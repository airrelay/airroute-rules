//! Read-only browsing of a build's complete private problem catalogue.
//!
//! The immutable manifest owns the list. The small live case projection only
//! supplies observation progress for a compatible fingerprint; it never owns
//! the catalogue and cannot turn a returned traceroute into a location fact.
use crate::{audit::AuditQuery, now, store::Store};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

const CATEGORY: &str = "CASE WHEN m.measurable=1 THEN 'measurable' WHEN m.kind='coverage-gap' THEN 'gaps' ELSE 'sources' END";
const PROGRESS: &str = "CASE WHEN m.measurable=0 THEN 'not-scheduled'
    WHEN live.key IS NULL THEN :missing_live
    WHEN (coalesce(t.running,0)>0 OR coalesce(t.failed,0)>0) AND EXISTS(SELECT 1 FROM runtime.job_cases l JOIN runtime.gp_remote g ON g.job_id=l.job_id WHERE l.case_key=live.key AND l.fp=live.fp AND l.revision=live.revision AND (g.state='unknown' OR (g.state='sending' AND g.remote_id=''))) THEN 'unconfirmed'
    WHEN (coalesce(t.running,0)>0 OR coalesce(t.failed,0)>0) AND EXISTS(SELECT 1 FROM runtime.job_cases l JOIN runtime.gp_remote g ON g.job_id=l.job_id WHERE l.case_key=live.key AND l.fp=live.fp AND l.revision=live.revision) THEN 'processing'
    WHEN coalesce(t.running,0)>0 THEN 'processing'
    WHEN coalesce(t.pending,0)>0 THEN 'queued'
    WHEN coalesce(t.failed,0)>0 THEN CASE
      WHEN EXISTS(SELECT 1 FROM runtime.job_cases l JOIN runtime.jobs j ON j.id=l.job_id WHERE l.case_key=live.key AND l.fp=live.fp AND l.revision=live.revision AND j.status='unknown' AND j.execution_count>=3 AND EXISTS(SELECT 1 FROM json_each(live.payload,'$.targets') target WHERE target.value=j.target)) THEN 'cooldown'
      ELSE 'unconfirmed' END
    WHEN coalesce(t.completed,0)>0 THEN CASE WHEN EXISTS(SELECT 1 FROM runtime.job_cases l JOIN runtime.jobs j ON j.id=l.job_id JOIN runtime.results r ON r.id=j.result_id WHERE l.case_key=live.key AND l.fp=live.fp AND l.revision=live.revision AND j.status='complete' AND j.round_seq>=l.required_round_seq AND EXISTS(SELECT 1 FROM json_each(live.payload,'$.targets') target WHERE target.value=j.target)) THEN 'returned' ELSE 'unconfirmed' END
    WHEN coalesce(json_array_length(live.payload,'$.targets'),0)=0 THEN 'awaiting-target'
    ELSE 'not-scheduled' END";

fn valid_build_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn empty(current: Option<&str>, p: &AuditQuery) -> Value {
    let mut value = json!({"build_id":null,"current_build_id":current,"release_hash":null,"built_at":null,"observation_cutoff":null,"historical":false,"available":false,"scope":{"unit":"issue","at":now(),"build_id":null}});
    if p.part != "summary" {
        value["items"] = json!([]);
    }
    if p.part != "items" {
        value["total"] = json!(0);
        value["states"] = json!({});
        value["categories"] = json!({});
        value["full_total"] = json!(0);
    }
    value
}

fn category_where(category: &str) -> &'static str {
    match category {
        "measurable" => "m.measurable=1",
        "sources" => "m.measurable=0 AND m.kind<>'coverage-gap'",
        "gaps" => "m.measurable=0 AND m.kind='coverage-gap'",
        _ => "1=1",
    }
}

fn base_query(category: &str) -> String {
    // A non-measurable page never reads online payloads or joins online jobs.
    // Its progress is a constant. Default measurable browsing uses the existing
    // partial index and touches at most the small actionable build subset.
    if matches!(category, "sources" | "gaps") {
        return format!(
            "SELECT m.key,m.fp,m.kind,m.subject,m.reason,m.measurable,{CATEGORY} AS category,'not-scheduled' AS progress,0 AS job_count,NULL AS live_targets,0 AS live_compatible FROM main.cases m WHERE {}",
            category_where(category)
        );
    }
    format!(
        "SELECT m.key,m.fp,m.kind,m.subject,m.reason,m.measurable,{CATEGORY} AS category,{PROGRESS} AS progress,coalesce(t.total,0) AS job_count,json_extract(live.payload,'$.targets') AS live_targets,live.key IS NOT NULL AS live_compatible
        FROM main.cases m LEFT JOIN runtime.cases live ON m.measurable=1 AND live.key=m.key AND live.fp=m.fp AND live.active=1
        LEFT JOIN runtime.task_job_totals t ON t.case_key=live.key AND t.fp=live.fp AND t.revision=live.revision WHERE {}",
        category_where(category)
    )
}

fn filters(p: &AuditQuery, search: &str) -> String {
    let mut filters = vec!["1=1"];
    if !p.case_key.is_empty() {
        filters.push("key=:case_key");
    }
    if !search.is_empty() {
        filters.push("(instr(lower(key),:q)>0 OR instr(lower(subject),:q)>0 OR instr(lower(reason),:q)>0 OR instr(lower(kind),:q)>0)");
    }
    if !p.state.is_empty() {
        filters.push("progress=:state");
    }
    filters.join(" AND ")
}

fn bindings<'a>(
    q: &rusqlite::Statement<'_>,
    p: &'a AuditQuery,
    search: &'a dyn rusqlite::ToSql,
    missing: &'a dyn rusqlite::ToSql,
) -> Result<Vec<(&'static str, &'a dyn rusqlite::ToSql)>> {
    let possible: [(&str, &dyn rusqlite::ToSql); 4] = [
        (":case_key", &p.case_key),
        (":q", search),
        (":state", &p.state),
        (":missing_live", missing),
    ];
    let mut selected = Vec::new();
    for (name, value) in possible {
        if q.parameter_index(name)?.is_some() {
            selected.push((name, value));
        }
    }
    Ok(selected)
}

fn basis(kind: &str, payload: &Value) -> &'static str {
    if kind == "coverage-gap" {
        "缺少可用依据，明确报告覆盖缺口"
    } else if kind == "domain-policy" {
        "按官方端点、规则范围和来源策略处理"
    } else if payload["publication"]
        .as_str()
        .is_some_and(|s| s.contains("deterministic geographic fallback"))
    {
        "按确定性来源策略输出；端点响应不用于判定地区"
    } else {
        "采用本轮固定的来源与适用观测；具体依据见详情"
    }
}

fn catalogue_counts(c: &Connection, summary: &Value) -> Result<BTreeMap<String, i64>> {
    let full: i64 = c.query_row("SELECT count(*) FROM main.cases", [], |r| r.get(0))?;
    let measurable = summary["geography"]["active_required_groups"].as_i64();
    let sources = summary["geography"]["non_measurable_location_gaps"]
        .as_i64()
        .zip(summary["domain_quarantines"].as_i64())
        .map(|(a, b)| a + b);
    let gaps = summary["geography"]["coverage_gap_groups"].as_i64();
    if let (Some(measurable), Some(sources), Some(gaps)) = (measurable, sources, gaps)
        && measurable + sources + gaps == full
    {
        return Ok(BTreeMap::from([
            ("measurable".into(), measurable),
            ("sources".into(), sources),
            ("gaps".into(), gaps),
        ]));
    }
    // Old / imported manifests may not have the matching build summary. Read
    // only catalogue columns, never parse the complete conflict JSON in Rust.
    Ok(c.prepare(&format!(
        "SELECT {CATEGORY},count(*) FROM main.cases m GROUP BY {CATEGORY}"
    ))?
    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
    .collect::<std::result::Result<BTreeMap<_, _>, _>>()?)
}

/// Lists immutable rule problems, optionally joined to compatible live progress.
/// No migration, task expansion, target update or result write happens here.
pub fn issues(store: &Store, data: &Path, p: &AuditQuery) -> Result<Value> {
    ensure!(
        matches!(p.part.as_str(), "" | "items" | "summary"),
        "invalid response part"
    );
    let category = if p.category.is_empty() {
        "measurable"
    } else {
        p.category.as_str()
    };
    ensure!(
        matches!(category, "all" | "measurable" | "sources" | "gaps"),
        "unknown problem category"
    );
    ensure!(
        p.q.len() <= 200 && p.case_key.len() <= 1024,
        "problem filter is too long"
    );
    ensure!(
        matches!(
            p.state.as_str(),
            "" | "awaiting-target"
                | "processing"
                | "queued"
                | "unconfirmed"
                | "cooldown"
                | "returned"
                | "not-scheduled"
                | "syncing"
                | "historical"
        ),
        "unknown problem progress"
    );
    let current = store.meta("current-build-id")?;
    let selected = if p.build_id.is_empty() {
        current.as_deref()
    } else {
        Some(p.build_id.as_str())
    };
    let Some(id) = selected else {
        return Ok(empty(None, p));
    };
    ensure!(valid_build_id(id), "invalid build id");
    let parent = data
        .join("internal-builds")
        .canonicalize()
        .context("this build has no retained private problem catalogue")?;
    let directory = parent
        .join(id)
        .canonicalize()
        .context("this build has no retained private problem catalogue")?;
    ensure!(
        directory.parent() == Some(parent.as_path()),
        "build catalogue is outside the private build directory"
    );
    let manifest = directory.join("manifest.sqlite3").canonicalize()?;
    ensure!(
        manifest.parent() == Some(directory.as_path()),
        "invalid private manifest location"
    );
    let binding: Value = crate::read_json(&directory.join("build.json"))?;
    ensure!(
        binding["build_id"] == id,
        "private problem catalogue belongs to another build"
    );
    let c = Connection::open_with_flags(
        manifest,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(2))?;
    c.execute(
        "ATTACH DATABASE ? AS runtime",
        [store.path.to_string_lossy().as_ref()],
    )?;
    c.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    let current_snapshot: Option<String> = c
        .query_row(
            "SELECT value FROM runtime.meta WHERE key='current-build-id'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let build: Option<(Option<String>, Option<i64>, Option<String>)> = c
        .query_row(
            "SELECT release,finished,summary FROM runtime.builds WHERE id=? AND status='complete'",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (release, built_at, summary) = build.context("completed build not found")?;
    ensure!(
        release.as_deref() == binding["release_hash"].as_str(),
        "problem catalogue release binding mismatch"
    );
    let summary: Value = summary
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or(Value::Null);
    let historical = current_snapshot.as_deref() != Some(id);
    let missing_live = if historical { "historical" } else { "syncing" }.to_string();
    let search = p.q.trim().to_lowercase();
    let mut value = json!({"build_id":id,"current_build_id":current_snapshot,"release_hash":release,"built_at":built_at,"observation_cutoff":summary["observation_cutoff"],"historical":historical,"available":true,"scope":{"unit":"issue","at":now(),"build_id":id,"category":category,"state":p.state,"q":p.q,"case_key":p.case_key}});
    let base = base_query(category);
    if p.part != "items" {
        let counts = catalogue_counts(&c, &summary)?;
        let full_total: i64 = counts.values().sum();
        let mut states = BTreeMap::<String, i64>::new();
        let mut categories = BTreeMap::<String, i64>::new();
        if search.is_empty() && p.case_key.is_empty() && matches!(category, "sources" | "gaps") {
            let n = if p.state.is_empty() || p.state == "not-scheduled" {
                *counts.get(category).unwrap_or(&0)
            } else {
                0
            };
            if n > 0 {
                states.insert("not-scheduled".into(), n);
                categories.insert(category.into(), n);
            }
        } else {
            // The all-category summary handles immutable, non-measurable rows
            // using their build counters; live joins run only on measurable rows.
            let summary_base = if category == "all" && search.is_empty() && p.case_key.is_empty() {
                for cat in ["sources", "gaps"] {
                    let n = *counts.get(cat).unwrap_or(&0);
                    if n > 0 && (p.state.is_empty() || p.state == "not-scheduled") {
                        categories.insert(cat.into(), n);
                        *states.entry("not-scheduled".into()).or_default() += n;
                    }
                }
                base_query("measurable")
            } else {
                base.clone()
            };
            let sql = format!(
                "WITH catalogue AS ({summary_base}) SELECT category,progress,count(*) FROM catalogue WHERE {} GROUP BY category,progress",
                filters(p, &search)
            );
            let mut q = c.prepare(&sql)?;
            let named = bindings(&q, p, &search, &missing_live)?;
            let mut rows = q.query(named.as_slice())?;
            while let Some(row) = rows.next()? {
                let cat: String = row.get(0)?;
                let state: String = row.get(1)?;
                let n: i64 = row.get(2)?;
                *categories.entry(cat).or_default() += n;
                *states.entry(state).or_default() += n;
            }
        }
        value["total"] = json!(states.values().sum::<i64>());
        value["states"] = json!(states);
        value["categories"] = json!(categories);
        value["full_total"] = json!(full_total);
    }
    if p.part != "summary" {
        let sql = format!(
            "WITH catalogue AS ({base}) SELECT key,fp,kind,subject,reason,measurable,category,progress,job_count,live_targets,live_compatible FROM catalogue WHERE {} ORDER BY key LIMIT :limit OFFSET :offset",
            filters(p, &search)
        );
        let mut q = c.prepare(&sql)?;
        let mut named = bindings(&q, p, &search, &missing_live)?;
        let limit = p.limit.clamp(1, 100) as i64;
        let offset = p.offset.min(i64::MAX as usize) as i64;
        named.push((":limit", &limit));
        named.push((":offset", &offset));
        let mut rows = q.query(named.as_slice())?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            let kind: String = row.get(2)?;
            // Only the requested page is decoded. This retains precise targets
            // and complete source detail without a second whole-catalogue copy.
            let payload_text: String =
                c.query_row("SELECT payload FROM main.cases WHERE key=?", [&key], |r| {
                    r.get(0)
                })?;
            let payload: Value = serde_json::from_str(&payload_text)?;
            let live_targets: Option<String> = row.get(9)?;
            let targets: Value = live_targets
                .map(|s| serde_json::from_str(&s))
                .transpose()?
                .unwrap_or_else(|| {
                    payload["targets"]
                        .as_array()
                        .map(|a| json!(a))
                        .unwrap_or(json!([]))
                });
            let mut item = json!({"key":key,"fingerprint":row.get::<_,String>(1)?,"kind":kind,"subject":row.get::<_,String>(3)?,"reason":row.get::<_,String>(4)?,"category":row.get::<_,String>(6)?,"rule_basis":basis(&kind,&payload),"progress":row.get::<_,String>(7)?,"targets":targets,"job_count":row.get::<_,i64>(8)?,"current":!historical,"live_compatible":row.get::<_,bool>(10)?});
            if !p.case_key.is_empty() {
                // Candidate selection can improve after a build. Expose that
                // compatible live provenance separately; the build payload is
                // still the immutable snapshot, including on historical pages.
                let live: Option<Option<String>> = if item["live_compatible"] == true {
                    c.query_row(
                        "SELECT json_extract(payload,'$.target_evidence') FROM runtime.cases WHERE key=? AND fp=? AND active=1",
                        rusqlite::params![item["key"].as_str(), item["fingerprint"].as_str()],
                        |r| r.get(0),
                    ).optional()?
                } else {
                    None
                };
                let (evidence, is_live) = match live {
                    Some(text) => (
                        text.map(|s| serde_json::from_str::<Value>(&s))
                            .transpose()?
                            .unwrap_or(json!({})),
                        true,
                    ),
                    None => (
                        payload.get("target_evidence").cloned().unwrap_or(json!({})),
                        false,
                    ),
                };
                item["target_evidence"] = evidence;
                item["target_evidence_is_live"] = json!(is_live);
                item["payload"] = payload;
            }
            items.push(item);
        }
        value["items"] = json!(items);
    }
    c.execute_batch("COMMIT;")?;
    Ok(value)
}
