//! Immutable build manifests, O(1) activation, and resumable bounded business-state synchronization.
use crate::{
    fingerprint, now,
    rules::Rule,
    store::{CaseInput, Store},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Instant,
};

// Force keyset access: the active/status index otherwise scans and sorts the
// entire active catalogue again for every small retirement page.
const CASE_REMOVALS_SQL: &str = "SELECT live.key FROM main.case_metadata live INDEXED BY sqlite_autoindex_case_metadata_1 LEFT JOIN incoming.cases wanted INDEXED BY case_measurable ON wanted.key=live.key AND wanted.measurable=1 WHERE live.active=1 AND live.kind NOT IN ('domain-observation','manual-ip','target-discovery') AND live.key>? AND wanted.key IS NULL ORDER BY live.key LIMIT ?";
#[derive(Debug)]
pub struct SnapshotChanged(pub String);
impl std::fmt::Display for SnapshotChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for SnapshotChanged {}
pub fn is_stale(e: &anyhow::Error) -> bool {
    e.downcast_ref::<SnapshotChanged>().is_some()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DomainInput {
    pub collection: String,
    pub rule: Rule,
}
fn meta(c: &Connection, k: &str) -> Result<Option<String>> {
    Ok(
        c.query_row("SELECT value FROM meta WHERE key=?", [k], |r| r.get(0))
            .optional()?,
    )
}
fn set_meta(c: &Connection, k: &str, v: &str) -> Result<()> {
    c.execute("INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE meta.value IS NOT excluded.value",params![k,v])?;
    Ok(())
}
fn execute<P: rusqlite::Params>(c: &Connection, sql: &str, p: P) -> rusqlite::Result<usize> {
    c.prepare_cached(sql)?.execute(p)
}
fn source_hash(c: &CaseInput) -> String {
    let mut p = c.payload.clone();
    if let Some(m) = p.as_object_mut() {
        m.remove("targets");
        m.remove("target_evidence");
    }
    fingerprint(&json!([c.fingerprint, c.kind, c.subject, c.reason, p]))
}

// Empty runtime selection is not an operator override of a newly frozen,
// qualified target. Nonempty selections keep their existing evidence/leases.
fn merge_target_payload(incoming: &Value, runtime: &Value, at: i64) -> Value {
    let mut payload = incoming.clone();
    let mut retained = Vec::new();
    let mut retained_evidence = serde_json::Map::new();
    for target in runtime["targets"].as_array().into_iter().flatten() {
        if let Some(target) = target.as_str()
            && crate::work::precise_target(incoming, target, "traceroute")
            && !retained.iter().any(|v| v == target)
        {
            retained.push(target.to_string());
            if let Some(row) = runtime["target_evidence"].get(target) {
                retained_evidence.insert(target.into(), row.clone());
            }
        }
    }
    if !retained.is_empty() {
        payload["targets"] = json!(retained);
        if retained_evidence.is_empty() {
            payload.as_object_mut().unwrap().remove("target_evidence");
        } else {
            payload["target_evidence"] = json!(retained_evidence);
        }
        return payload;
    }
    let mut targets = Vec::new();
    let mut evidence = serde_json::Map::new();
    for target in incoming["targets"].as_array().into_iter().flatten() {
        let Some(target) = target.as_str() else {
            continue;
        };
        let row = &incoming["target_evidence"][target];
        if !crate::work::precise_target(incoming, target, "traceroute")
            || !matches!(
                row["kind"].as_str(),
                Some("dns-answer" | "endpoint-response")
            )
            || !row["source"].as_str().is_some_and(|s| !s.is_empty())
            || !row["observed"]
                .as_i64()
                .is_some_and(|t| t > 0 && t <= at && t >= at.saturating_sub(7 * 86400))
            || !row["valid_until"].as_i64().is_some_and(|t| t > at)
            || row["ip"].as_str().is_some_and(|ip| ip != target)
        {
            continue;
        }
        if !evidence.contains_key(target) {
            targets.push(json!(target));
            evidence.insert(target.into(), row.clone());
        }
        if targets.len() == 3 {
            break;
        }
    }
    payload["targets"] = json!(targets);
    payload["target_evidence"] = Value::Object(evidence);
    payload
}

/// Retain up to three in-scope existing choices when ranges split or merge.
/// Recovery of old in-flight attempts is independent of this selection budget.
/// The batch-local cache reads each family once using primary-key ranges, never
/// sorting the family again for each child or copying old source payloads.
fn sampling_selection_on(
    c: &Connection,
    incoming: &Value,
    runtime: Value,
    families: &mut HashMap<String, Vec<Value>>,
) -> Result<Value> {
    if incoming["sample_plan"]["strategy"] != "bgp-bounded-v1" {
        return Ok(runtime);
    }
    let Some(parent) = incoming["sample_plan"]["parent_case_key"].as_str() else {
        return Ok(runtime);
    };
    let mut targets = Vec::<String>::new();
    let mut evidence = serde_json::Map::new();
    let mut retain = |selection: &Value| {
        for target in selection["targets"].as_array().into_iter().flatten() {
            if targets.len() == 3 {
                break;
            }
            if let Some(target) = target.as_str()
                && crate::work::precise_target(incoming, target, "traceroute")
                && !targets.iter().any(|v| v == target)
            {
                targets.push(target.into());
                if let Some(row) = selection["target_evidence"].get(target) {
                    evidence.insert(target.into(), row.clone());
                }
            }
        }
        targets.len() == 3
    };
    let filled = retain(&runtime);
    if !filled {
        if !families.contains_key(parent) {
            let mut selected = Vec::new();
            // Parent first preserves its previous choices. Separate exact/range
            // queries stream primary-key order without a temporary sort tree.
            let prefix = format!("{parent}:sample:");
            for (sql, first, last) in [
                (
                    "SELECT json_extract(payload,'$.targets'),json_extract(payload,'$.target_evidence') FROM cases WHERE key=?1 AND kind IN ('endpoint-reachability','anycast-validation') AND coalesce(json_array_length(payload,'$.targets'),0)>0",
                    parent.to_string(),
                    None,
                ),
                (
                    "SELECT json_extract(payload,'$.targets'),json_extract(payload,'$.target_evidence') FROM cases WHERE key>=?1 AND key<?2 AND kind IN ('endpoint-reachability','anycast-validation') AND coalesce(json_array_length(payload,'$.targets'),0)>0 ORDER BY key",
                    prefix.clone(),
                    Some(format!("{prefix}~")),
                ),
            ] {
                let mut query = c.prepare_cached(sql)?;
                let mut rows = if let Some(last) = last {
                    query.query(params![first, last])?
                } else {
                    query.query(params![first])?
                };
                while let Some(row) = rows.next()? {
                    let targets: Option<String> = row.get(0)?;
                    let provenance: Option<String> = row.get(1)?;
                    selected.push(json!({
                        "targets":targets.map(|s|serde_json::from_str::<Value>(&s)).transpose()?.unwrap_or(json!([])),
                        "target_evidence":provenance.map(|s|serde_json::from_str::<Value>(&s)).transpose()?.unwrap_or(Value::Null)
                    }));
                }
            }
            families.insert(parent.to_string(), selected);
        }
        for selection in &families[parent] {
            if retain(selection) {
                break;
            }
        }
    }
    Ok(json!({"targets":targets,"target_evidence":evidence}))
}

fn frozen_targets_improve(c: &Connection, manifest: &Connection, key: &str) -> Result<bool> {
    let incoming: Option<String> = manifest
        .prepare_cached("SELECT payload FROM cases WHERE key=? AND coalesce(json_array_length(payload,'$.targets'),0)>0")?
        .query_row([key], |r| r.get(0))
        .optional()?;
    let Some(incoming) = incoming else {
        return Ok(false);
    };
    let runtime: Option<String> = c
        .prepare_cached("SELECT payload FROM cases WHERE key=?")?
        .query_row([key], |r| r.get(0))
        .optional()?;
    let Some(runtime) = runtime else {
        return Ok(false);
    };
    let runtime: Value = serde_json::from_str(&runtime)?;
    if runtime["targets"].as_array().is_some_and(|a| !a.is_empty()) {
        return Ok(false);
    }
    let incoming = serde_json::from_str(&incoming)?;
    Ok(merge_target_payload(&incoming, &runtime, now())["targets"]
        .as_array()
        .is_some_and(|a| !a.is_empty()))
}

pub fn migrate(s: &Store) -> Result<()> {
    let c = s.connect()?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS build_case_sources(case_key TEXT PRIMARY KEY,source_hash TEXT NOT NULL);CREATE TABLE IF NOT EXISTS replan_cases(case_key TEXT PRIMARY KEY,queued_at INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS build_artifacts(build_id TEXT PRIMARY KEY,release_hash TEXT NOT NULL,path TEXT NOT NULL,base_build_id TEXT);")?;
    // Retain legacy tables and data. The first independent sync compares actual rows where a digest is missing.
    if meta(&c, "current-build-id")?.is_none() {
        let latest:Option<String>=c.query_row("SELECT id FROM builds WHERE status='complete' ORDER BY finished DESC,rowid DESC LIMIT 1",[],|r|r.get(0)).optional()?;
        if let Some(id) = latest {
            set_meta(&c, "current-build-id", &id)?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SyncState {
    build_id: String,
    phase: u8,
    cursor: String,
    #[serde(default)]
    stats: Stats,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Stats {
    new: usize,
    changed: usize,
    reused: usize,
    removed: usize,
    domain_changed: usize,
    domain_removed: usize,
    semantic_writes: u64,
    batches: usize,
}

/// Does not touch cases, jobs, domain discovery or their projections. No measurements or manual decisions are awaited.
pub fn activate(
    s: &Store,
    id: &str,
    release: &str,
    summary: &Value,
    artifact: &Path,
) -> Result<Value> {
    ensure!(
        artifact.join("manifest.sqlite3").is_file(),
        "build manifest missing"
    );
    let binding: Value = crate::read_json(&artifact.join("build.json"))?;
    ensure!(
        binding["build_id"] == id && binding["release_hash"] == release,
        "internal manifest belongs to another build or release"
    );
    let _guard = crate::build::export_guard(s)?;
    let mut c = s.connect()?;
    let wait = Instant::now();
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let wait_ms = wait.elapsed().as_secs_f64() * 1000.;
    let started = Instant::now();
    let current = meta(&tx, "current-build-id")?;
    if current.as_deref() == Some(id) {
        return Ok(
            json!({"activated":true,"semantic_writes":0,"sync_pending":meta(&tx,"build-sync-pending")?.is_some()}),
        );
    }
    let row: i64 = tx
        .query_row(
            "SELECT rowid FROM builds WHERE id=? AND status='running'",
            [id],
            |r| r.get(0),
        )
        .context("build is no longer running")?;
    if let Some(ref active) = current {
        let newer: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM builds WHERE id=? AND rowid>?)",
            params![active, row],
            |r| r.get(0),
        )?;
        if newer {
            return Err(SnapshotChanged("a newer build is already active".into()).into());
        }
    }
    let mut summary = summary.clone();
    summary["base_build_id"] = json!(current);
    summary["sync_pending"] = json!(true);
    summary["activation_lock_wait_ms"] = json!(wait_ms);
    summary["incremental"] = json!({"semantic_writes":0,"sync_pending":true});
    ensure!(tx.execute("UPDATE builds SET status='complete',finished=?,release=?,summary=?,error=NULL WHERE id=? AND status='running'",params![now(),release,summary.to_string(),id])?==1,"build is no longer running");
    tx.execute(
        "INSERT INTO build_artifacts VALUES(?,?,?,?)",
        params![id, release, artifact.to_string_lossy(), current],
    )?;
    if let Some(p) = crate::progress::snapshot(s, id) {
        tx.execute("INSERT INTO build_progress VALUES(?,?) ON CONFLICT(build_id) DO UPDATE SET snapshot=excluded.snapshot",params![id,serde_json::to_string(&p)?])?;
    }
    set_meta(&tx, "current-build-id", id)?;
    set_meta(&tx, "current-release", release)?;
    set_meta(
        &tx,
        "build-sync-pending",
        &serde_json::to_string(&SyncState {
            build_id: id.into(),
            ..Default::default()
        })?,
    )?;
    set_meta(
        &tx,
        "export-pending",
        &json!({"build_id":id,"release_hash":release}).to_string(),
    )?;
    tx.commit()?;
    let elapsed = started.elapsed().as_secs_f64() * 1000.;
    tracing::info!(
        build = id,
        lock_wait_ms = wait_ms,
        write_transaction_ms = elapsed,
        semantic_writes = 0,
        "build activated; business synchronization pending"
    );
    s.wake.notify_waiters();
    Ok(
        json!({"activated":true,"semantic_writes":0,"sync_pending":true,"lock_wait_ms":wait_ms,"activation_transaction_ms":elapsed}),
    )
}

fn open_manifest(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path.join("manifest.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?)
}

/// Dispatch alone must use the latest source snapshot while bounded case sync
/// is pending. Historical receipts and started attempts keep their own identity.
/// Callers recheck this under their short admission transaction.
pub(crate) fn current_case_payload_on(
    c: &Connection,
    key: &str,
    runtime: &Value,
) -> Result<Option<Value>> {
    if matches!(
        runtime["kind"].as_str(),
        Some("domain-observation" | "manual-ip")
    ) {
        return Ok(Some(runtime.clone()));
    }
    let binding: Option<(String, Option<String>, Option<String>)> = c
        .prepare_cached("SELECT pending.value,active.value,a.path FROM meta pending LEFT JOIN meta active ON active.key='current-build-id' LEFT JOIN build_artifacts a ON a.build_id=active.value WHERE pending.key='build-sync-pending'")?
        .query_row([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .optional()?;
    let Some((pending, current, path)) = binding else {
        return Ok(Some(runtime.clone()));
    };
    let pending: SyncState = serde_json::from_str(&pending)?;
    let Some(path) = path.filter(|_| current.as_deref() == Some(pending.build_id.as_str())) else {
        return Ok(None);
    };
    if !Path::new(&path).join("manifest.sqlite3").is_file() {
        return Ok(None);
    }
    let manifest = open_manifest(Path::new(&path))?;
    if runtime["kind"] == "target-discovery" {
        let mut payload = runtime.clone();
        let mut targets = Vec::new();
        let mut wanted =
            manifest.prepare_cached("SELECT EXISTS(SELECT 1 FROM domains WHERE host=?)")?;
        for target in runtime["targets"].as_array().into_iter().flatten() {
            if let Some(host) = target.as_str()
                && wanted.query_row([host], |r| r.get::<_, bool>(0))?
            {
                targets.push(target.clone());
            }
        }
        payload["targets"] = json!(targets);
        return Ok((!targets.is_empty()).then_some(payload));
    }
    let payload: Option<String> = manifest
        .prepare_cached("SELECT payload FROM cases WHERE key=? AND measurable=1")?
        .query_row([key], |r| r.get(0))
        .optional()?;
    payload
        .map(|body| {
            let payload: Value = serde_json::from_str(&body)?;
            Ok(merge_target_payload(&payload, runtime, now()))
        })
        .transpose()
}
struct ChangedCase {
    case: CaseInput,
    hash: String,
    ranges: Vec<(u8, String, String)>,
}
fn prepare_case(m: &Connection, key: &str, hash: String) -> Result<ChangedCase> {
    let (fp, kind, subject, reason, payload): (String, String, String, String, String) = m
        .query_row(
            "SELECT fp,kind,subject,reason,payload FROM cases WHERE key=?",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
    let ranges = {
        let mut q =
            m.prepare("SELECT family,start,end FROM ranges WHERE case_key=? ORDER BY start,end")?;
        q.query_map([key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<std::result::Result<_, _>>()?
    };
    let case = CaseInput {
        key: key.into(),
        fingerprint: fp,
        kind,
        subject,
        reason,
        payload: serde_json::from_str(&payload)?,
    };
    Ok(ChangedCase { case, hash, ranges })
}
/// Process at most `limit` manifest/actual-state rows. Every batch fences the latest build inside its writer transaction.
/// The cursor belongs to the latest build, not to an assumed previously synchronized build.
pub fn sync_current(s: &Store, limit: usize) -> Result<bool> {
    let limit = limit.clamp(1, 1024);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(s.path.with_extension("build-sync.lock"))?;
    let _guard = match crate::FileLock::try_new(lock) {
        Ok(g) => g,
        Err(std::fs::TryLockError::WouldBlock) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let c = s.connect()?;
    let Some(encoded) = meta(&c, "build-sync-pending")? else {
        return Ok(false);
    };
    let mut state: SyncState = serde_json::from_str(&encoded)?;
    if meta(&c, "current-build-id")?.as_deref() != Some(state.build_id.as_str()) {
        return Ok(true);
    }
    let path: String = c.query_row(
        "SELECT path FROM build_artifacts WHERE build_id=?",
        [&state.build_id],
        |r| r.get(0),
    )?;
    let manifest_path = Path::new(&path).join("manifest.sqlite3").canonicalize()?;
    let mut uri = reqwest::Url::from_file_path(manifest_path)
        .map_err(|_| anyhow::anyhow!("manifest path cannot be represented as a file URI"))?;
    uri.query_pairs_mut()
        .append_pair("mode", "ro")
        .append_pair("immutable", "1");
    // Compare two indexed datasets outside the writer, never probe/recompile one query per hostname.
    c.execute("ATTACH DATABASE ? AS incoming", [uri.as_str()])?;
    let m = open_manifest(Path::new(&path))?;
    let mut keys = Vec::new();
    let mut changed = Vec::new();
    let mut removed = Vec::new();
    let mut domains = Vec::new();
    let mut adopt = Vec::new();
    let mut daily_replans = Vec::new();
    let mut diff_query_vm_steps = 0u64;
    match state.phase {
        0 => {
            let mut q =
                m.prepare("SELECT key,source_hash FROM cases WHERE measurable=1 AND key>? ORDER BY key LIMIT ?")?;
            let rows = q
                .query_map(params![state.cursor, limit as i64], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            diff_query_vm_steps += q.get_status(rusqlite::StatementStatus::VmStep) as u64;
            for (key, hash) in rows {
                let existing:Option<(bool,String,Option<String>)>=c.prepare_cached("SELECT c.active,c.status,s.source_hash FROM cases c LEFT JOIN build_case_sources s ON s.case_key=c.key WHERE c.key=?")?.query_row([&key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
                if existing.as_ref().is_some_and(|(active, status, h)| {
                    *active && status != "decided" && h.as_deref() == Some(hash.as_str())
                }) {
                    if frozen_targets_improve(&c, &m, &key)? {
                        changed.push(prepare_case(&m, &key, hash)?);
                    } else {
                        state.stats.reused += 1;
                        if crate::work::needs_daily_replan_on(&c, &key, &state.build_id)? {
                            daily_replans.push(key.clone());
                        }
                    }
                } else if existing.as_ref().is_some_and(|(active, status, h)| {
                    *active && status != "decided" && h.is_none()
                }) {
                    let old: CaseInput = c
                        .prepare_cached(
                            "SELECT key,fp,kind,subject,reason,payload FROM cases WHERE key=?",
                        )?
                        .query_row([&key], |r| {
                            Ok(CaseInput {
                                key: r.get(0)?,
                                fingerprint: r.get(1)?,
                                kind: r.get(2)?,
                                subject: r.get(3)?,
                                reason: r.get(4)?,
                                payload: serde_json::from_str(&r.get::<_, String>(5)?)
                                    .unwrap_or(Value::Null),
                            })
                        })?;
                    if source_hash(&old) == hash && !frozen_targets_improve(&c, &m, &key)? {
                        adopt.push((key.clone(), hash));
                        state.stats.reused += 1;
                        if crate::work::needs_daily_replan_on(&c, &key, &state.build_id)? {
                            daily_replans.push(key.clone());
                        }
                    } else {
                        changed.push(prepare_case(&m, &key, hash)?);
                    }
                } else {
                    changed.push(prepare_case(&m, &key, hash)?);
                }
                keys.push(key);
            }
        }
        1 => {
            let mut q = c.prepare(CASE_REMOVALS_SQL)?;
            keys = q
                .query_map(params![state.cursor, limit as i64], |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            diff_query_vm_steps += q.get_status(rusqlite::StatementStatus::VmStep) as u64;
            removed = keys.clone();
        }
        2 => {
            let mut q = c.prepare("SELECT wanted.host,wanted.bucket FROM incoming.domains wanted LEFT JOIN main.discovery_domains live ON live.host=wanted.host WHERE wanted.host>? AND wanted.bucket IS NOT live.bucket ORDER BY wanted.host LIMIT ?")?;
            for row in q.query_map(params![state.cursor, limit as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
            })? {
                let (host, bucket) = row?;
                domains.push((host.clone(), bucket));
                keys.push(host);
            }
            diff_query_vm_steps += q.get_status(rusqlite::StatementStatus::VmStep) as u64;
        }
        3 => {
            let mut q = c.prepare("SELECT live.host FROM main.discovery_domains live LEFT JOIN incoming.domains wanted ON wanted.host=live.host WHERE live.host>? AND wanted.host IS NULL ORDER BY live.host LIMIT ?")?;
            keys = q
                .query_map(params![state.cursor, limit as i64], |r| {
                    r.get::<_, String>(0)
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            diff_query_vm_steps += q.get_status(rusqlite::StatementStatus::VmStep) as u64;
            removed = keys.clone();
        }
        _ => {}
    }
    let mut c = s.connect()?;
    c.set_prepared_statement_cache_capacity(24);
    let acquiring = Instant::now();
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let acquire_ms = acquiring.elapsed().as_secs_f64() * 1000.;
    let writing = Instant::now();
    let phase = state.phase;
    let scanned = keys.len();
    if meta(&tx, "current-build-id")?.as_deref() != Some(state.build_id.as_str())
        || meta(&tx, "build-sync-pending")?.as_deref() != Some(encoded.as_str())
    {
        return Ok(true);
    }
    let before = tx.total_changes();
    for key in daily_replans {
        if crate::work::needs_daily_replan_on(&tx, &key, &state.build_id)? {
            crate::work::mark_case_from_build(&tx, &key, &state.build_id)?;
        }
    }
    for (key, hash) in adopt {
        execute(
            &tx,
            "INSERT OR IGNORE INTO build_case_sources(case_key,source_hash) SELECT key,? FROM cases WHERE key=? AND active=1",
            params![hash, key],
        )?;
    }
    let mut sampling_families = HashMap::new();
    for change in changed {
        let item = change.case;
        type Current = (
            String,
            i64,
            bool,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let old:Option<Current>=tx.prepare_cached("SELECT c.fp,c.revision,c.active,c.status,json_extract(c.payload,'$.targets'),json_extract(c.payload,'$.target_evidence'),s.source_hash FROM cases c LEFT JOIN build_case_sources s ON s.case_key=c.key WHERE c.key=?")?.query_row([&item.key],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional()?;
        // Legacy rows without a digest are compared outside future syncs once this initial ownership digest is established.
        let semantic = old.as_ref().is_none_or(|o| o.0 != item.fingerprint || !o.2);
        let revision = old.as_ref().map_or(1, |o| o.1 + i64::from(semantic));
        let mut runtime = serde_json::Map::new();
        if let Some(o) = &old {
            if let Some(t) = &o.4 {
                runtime.insert("targets".into(), serde_json::from_str(t)?);
            }
            if let Some(e) = &o.5 {
                runtime.insert("target_evidence".into(), serde_json::from_str(e)?);
            }
        }
        let runtime = sampling_selection_on(
            &tx,
            &item.payload,
            Value::Object(runtime),
            &mut sampling_families,
        )?;
        let payload = merge_target_payload(&item.payload, &runtime, now());
        let target_upgrade = runtime["targets"].as_array().is_none_or(Vec::is_empty)
            && payload["targets"].as_array().is_some_and(|a| !a.is_empty());
        if old.as_ref().is_some_and(|o| {
            o.2 && o.3 != "decided" && o.6.as_deref() == Some(change.hash.as_str())
        }) && !target_upgrade
        {
            continue;
        }
        let mut observation = serde_json::Map::new();
        for key in [
            "kind",
            "targets",
            "regions",
            "observation_regions",
            "required_regions",
            "manual",
            "query_type",
            "query",
            "protocol",
            "max_hops",
            "required_asn",
            "excluded_asns",
            "family",
            "ranges",
        ] {
            if let Some(value) = payload.get(key) {
                observation.insert(key.into(), value.clone());
            }
        }
        if item.payload["family"].is_number() {
            let valid = observation
                .get("targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|v| {
                    v.as_str()
                        .and_then(|text| text.parse().ok())
                        .is_some_and(|ip| {
                            let (f, n) = crate::rules::addr_num(ip);
                            let n = format!("{n:032x}");
                            change.ranges.iter().any(|(family, start, end)| {
                                *family == f && start <= &n && &n <= end
                            })
                        })
                })
                .cloned()
                .collect::<Vec<_>>();
            observation.insert("targets".into(), json!(valid));
        }
        let fresh = item.payload["measurement_required"] != false
            && crate::work::has_current_observation(&tx, &Value::Object(observation))?;
        let sampling_needs_selection = payload["sample_plan"]["strategy"] == "bgp-bounded-v1"
            && payload["targets"].as_array().map_or(0, Vec::len) < 3;
        let status = if sampling_needs_selection {
            "blocked-target"
        } else if fresh {
            "evidence-ready"
        } else if target_upgrade {
            "needs-active"
        } else if !semantic && old.as_ref().is_some_and(|o| o.3 != "decided") {
            old.as_ref()
                .map(|o| o.3.as_str())
                .unwrap_or("blocked-target")
        } else if item.kind == "domain-policy" || item.payload["measurement_required"] == false {
            "needs-review"
        } else {
            "blocked-target"
        };
        execute(
            &tx,
            "INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,?,?,?,?,?,?,?,1,?) ON CONFLICT(key) DO UPDATE SET fp=excluded.fp,revision=excluded.revision,kind=excluded.kind,subject=excluded.subject,reason=excluded.reason,payload=excluded.payload,status=excluded.status,active=1,updated=excluded.updated",
            params![
                item.key,
                item.fingerprint,
                revision,
                item.kind,
                item.subject,
                item.reason,
                payload.to_string(),
                status,
                now()
            ],
        )?;
        execute(
            &tx,
            "INSERT INTO build_case_sources VALUES(?,?) ON CONFLICT(case_key) DO UPDATE SET source_hash=excluded.source_hash WHERE build_case_sources.source_hash IS NOT excluded.source_hash",
            params![item.key, change.hash],
        )?;
        if old.is_none() {
            state.stats.new += 1;
        } else {
            state.stats.changed += 1;
        }
        if semantic {
            execute(&tx, "DELETE FROM case_ranges WHERE case_key=?", [&item.key])?;
            for (f, start, end) in change.ranges {
                execute(
                    &tx,
                    "INSERT INTO case_ranges VALUES(?,?,?,?,?)",
                    params![item.key, item.fingerprint, f, start, end],
                )?;
            }
        }
        crate::work::mark_case_from_build(&tx, &item.key, &state.build_id)?;
        // Only the shared planner changes global jobs and demand-level projections.
    }
    if state.phase == 1 {
        for key in removed {
            state.stats.removed += execute(
                &tx,
                "UPDATE cases SET active=0,status='inactive',updated=? WHERE key=? AND active=1",
                params![now(), key],
            )?;
            crate::work::mark_case(&tx, &key)?;
        }
    } else if state.phase == 3 {
        for host in removed {
            state.stats.domain_removed +=
                execute(&tx, "DELETE FROM discovery_domains WHERE host=?", [host])?;
        }
    }
    for (host, bucket) in domains {
        state.stats.domain_changed += execute(
            &tx,
            "INSERT INTO discovery_domains VALUES(?,?) ON CONFLICT(host) DO UPDATE SET bucket=excluded.bucket WHERE discovery_domains.bucket IS NOT excluded.bucket",
            params![host, bucket],
        )?;
    }
    let semantic_writes = tx.total_changes() - before;
    state.stats.semantic_writes += semantic_writes;
    state.stats.batches += 1;
    if let Some(last) = keys.last() {
        state.cursor = last.clone();
    } else {
        state.phase += 1;
        state.cursor.clear();
    }
    let more = state.phase < 4;
    if more {
        set_meta(&tx, "build-sync-pending", &serde_json::to_string(&state)?)?;
    } else {
        set_meta(&tx, "last-build-sync", &serde_json::to_string(&state)?)?;
        tx.execute("UPDATE builds SET summary=json_set(coalesce(summary,'{}'),'$.sync_pending',json('false'),'$.incremental',json(?)) WHERE id=? AND status='complete'",params![serde_json::to_string(&state.stats)?,state.build_id])?;
        tx.execute("DELETE FROM meta WHERE key='build-sync-pending'", [])?;
        set_meta(&tx, "discovery-domain-index", "build-owned-v2")?;
    }
    tx.commit()?;
    tracing::debug!(build=%state.build_id,phase,candidates=scanned,diff_query_vm_steps,semantic_writes,acquire_ms,write_transaction_ms=writing.elapsed().as_secs_f64()*1000.,"build manifest synchronization batch");
    s.wake.notify_waiters();
    Ok(more)
}

/// Legacy fixture helper, not the production build path: explicitly activate then drain the independent synchronizer.
pub fn commit_compat(
    s: &Store,
    id: &str,
    release: &str,
    summary: &Value,
    cases: &[CaseInput],
    facts: &[(String, Rule, String)],
) -> Result<Value> {
    let domains = facts
        .iter()
        .map(|(collection, rule, _)| DomainInput {
            collection: collection.clone(),
            rule: rule.clone(),
        })
        .collect::<Vec<_>>();
    let base = s.meta("current-build-id")?;
    let path = write_internal(
        s.path.parent().context("database parent")?,
        id,
        base.as_deref(),
        release,
        cases,
        &domains,
        summary,
    )?;
    activate(s, id, release, summary, &path)?;
    while sync_current(s, 256)? {}
    let state: SyncState = serde_json::from_str(
        &s.meta("last-build-sync")?
            .context("build sync incomplete")?,
    )?;
    Ok(serde_json::to_value(state.stats)?)
}
/// One private candidate manifest. It is invisible to synchronization until
/// `activate` publishes its completed build/release binding.
pub(crate) struct InternalBuild {
    index: Connection,
    dir: tempfile::TempDir,
    parent: PathBuf,
    id: String,
}
impl InternalBuild {
    pub(crate) fn new(data: &Path, id: &str) -> Result<Self> {
        ensure!(
            !id.is_empty() && id.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
            "invalid internal build id"
        );
        let parent = data.join("internal-builds");
        std::fs::create_dir_all(&parent)?;
        let dir = tempfile::Builder::new()
            .prefix(".build-")
            .tempdir_in(&parent)?;
        let index = Connection::open(dir.path().join("manifest.sqlite3"))?;
        index.execute_batch("PRAGMA journal_mode=DELETE;CREATE TABLE cases(key TEXT PRIMARY KEY,fp TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,reason TEXT NOT NULL,payload TEXT NOT NULL,source_hash TEXT NOT NULL,measurable INTEGER NOT NULL);CREATE INDEX case_measurable ON cases(key,source_hash) WHERE measurable=1;CREATE INDEX case_audit_catalogue ON cases(measurable,kind,key,fp,subject);CREATE TABLE ranges(case_key TEXT NOT NULL,family INTEGER NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,PRIMARY KEY(case_key,start,end));CREATE TABLE domains(host TEXT PRIMARY KEY,bucket INTEGER NOT NULL);BEGIN;")?;
        Ok(Self {
            index,
            dir,
            parent,
            id: id.into(),
        })
    }
    pub(crate) fn add_case(&self, c: &CaseInput) -> Result<()> {
        let measurable = c.kind != "domain-policy" && c.payload["measurement_required"] != false;
        self.index
            .prepare_cached("INSERT INTO cases VALUES(?,?,?,?,?,?,?,?)")?
            .execute(params![
                c.key,
                c.fingerprint,
                c.kind,
                c.subject,
                c.reason,
                c.payload.to_string(),
                source_hash(c),
                measurable
            ])?;
        for r in c.payload["ranges"]
            .as_array()
            .filter(|_| measurable)
            .into_iter()
            .flatten()
        {
            let (f, start) = crate::rules::addr_num(r[0].as_str().context("range start")?.parse()?);
            let (ef, end) = crate::rules::addr_num(r[1].as_str().context("range end")?.parse()?);
            ensure!(f == ef && start <= end, "invalid disputed range");
            self.index
                .prepare_cached("INSERT INTO ranges VALUES(?,?,?,?)")?
                .execute(params![
                    c.key,
                    f,
                    format!("{start:032x}"),
                    format!("{end:032x}")
                ])?;
        }
        Ok(())
    }
    pub(crate) fn add_domains<'a>(
        &self,
        collection: &str,
        rules: impl IntoIterator<Item = &'a Rule>,
    ) -> Result<()> {
        let mut insert=self.index.prepare_cached("INSERT INTO domains VALUES(?,?) ON CONFLICT(host) DO UPDATE SET bucket=min(bucket,excluded.bucket)")?;
        for rule in rules {
            if matches!(rule.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") && rule.value.contains('.')
            {
                insert.execute(params![rule.value, i64::from(collection != "region/cn")])?;
            }
        }
        Ok(())
    }
    pub(crate) fn finish(
        self,
        base: Option<&str>,
        release: &str,
        domains: &[DomainInput],
        summary: &Value,
    ) -> Result<PathBuf> {
        for d in domains {
            self.add_domains(&d.collection, std::iter::once(&d.rule))?;
        }
        self.index.execute_batch("COMMIT;")?;
        let Self {
            index,
            dir,
            parent,
            id,
        } = self;
        drop(index);
        crate::atomic_write(
            &dir.path().join("build.json"),
            &serde_json::to_vec(
                &json!({"build_id":id,"base_build_id":base,"release_hash":release,"summary":summary}),
            )?,
        )?;
        sync_directory(dir.path())?;
        let dest = parent.join(id);
        std::fs::rename(dir.path(), &dest)?;
        sync_directory(&parent)?;
        Ok(dest)
    }
}

pub fn write_internal(
    data: &Path,
    id: &str,
    base: Option<&str>,
    release: &str,
    cases: &[CaseInput],
    domains: &[DomainInput],
    summary: &Value,
) -> Result<PathBuf> {
    let writer = InternalBuild::new(data, id)?;
    for c in cases {
        writer.add_case(c)?;
    }
    writer.finish(base, release, domains, summary)
}
pub(crate) fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn borrowed_domain_rows_keep_uncompacted_hosts_and_cn_bucket_precedence() {
        let directory = tempfile::tempdir().unwrap();
        let candidate = InternalBuild::new(directory.path(), "borrowed").unwrap();
        let parent = Rule::new("DOMAIN-SUFFIX", "example.com", &[]).unwrap();
        let child = Rule::new("DOMAIN", "exact.example.com", &[]).unwrap();
        let accepted: std::collections::BTreeSet<_> = [
            parent,
            child.clone(),
            Rule::new("IP-CIDR", "1.1.1.0/24", &["no-resolve"]).unwrap(),
            Rule::new("DOMAIN-WILDCARD", "*.ignored.example", &[]).unwrap(),
        ]
        .into();
        candidate.add_domains("provider/test", &accepted).unwrap();
        candidate.add_domains("region/cn", &accepted).unwrap();
        candidate.add_domains("category/test", &accepted).unwrap();
        candidate
            .add_domains(
                "provider/other",
                [&Rule::new("DOMAIN", "other.example", &[]).unwrap()],
            )
            .unwrap();
        assert!(
            accepted.contains(&child),
            "borrowed input must remain available for optimization"
        );
        assert!(
            !crate::rules::optimize(accepted).unwrap().contains(&child),
            "negative control: public compaction loses this exact discovery host"
        );
        let path = candidate
            .finish(Some("base"), "release", &[], &json!({"rules":1}))
            .unwrap();
        let c = Connection::open(path.join("manifest.sqlite3")).unwrap();
        let mut q = c
            .prepare("SELECT host,bucket FROM domains ORDER BY host")
            .unwrap();
        let actual = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            actual,
            vec![
                ("exact.example.com".into(), 0),
                ("example.com".into(), 0),
                ("other.example".into(), 1)
            ]
        );
        let binding: Value = crate::read_json(&path.join("build.json")).unwrap();
        assert_eq!(
            binding,
            json!({"build_id":"borrowed","base_build_id":"base","release_hash":"release","summary":{"rules":1}})
        );
    }
    #[test]
    fn streamed_private_manifest_keeps_complete_cases_and_never_publishes_a_partial_candidate() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let passive = CaseInput {
            key: "passive".into(),
            fingerprint: "fp".into(),
            kind: "geolocation".into(),
            subject: "1.1.1.0/24".into(),
            reason: "source disagreement retained".into(),
            payload: json!({"kind":"geolocation","ranges":[["1.1.1.0","1.1.1.255"]],"source_opinions":[{"iplocate_region":"us","dbip_region":"europe"}],"measurement_required":false}),
        };
        {
            let candidate = InternalBuild::new(directory.path(), "abandoned").unwrap();
            candidate.add_case(&passive).unwrap();
            assert!(store.meta("current-build-id").unwrap().is_none());
        }
        assert_eq!(
            std::fs::read_dir(directory.path().join("internal-builds"))
                .unwrap()
                .count(),
            0
        );
        let candidate = InternalBuild::new(directory.path(), "complete").unwrap();
        candidate.add_case(&passive).unwrap();
        let active = CaseInput {
            key: "active".into(),
            kind: "endpoint-reachability".into(),
            payload: json!({"kind":"endpoint-reachability","ranges":[["1.1.1.1","1.1.1.1"]],"measurement_required":true}),
            ..passive.clone()
        };
        candidate.add_case(&active).unwrap();
        let domains = ["example.com", "exact.example.com"].map(|host| DomainInput {
            collection: "region/cn".into(),
            rule: Rule::new("DOMAIN", host, &[]).unwrap(),
        });
        let path = candidate
            .finish(None, "release", &domains, &json!({"rules":1}))
            .unwrap();
        let c = Connection::open(path.join("manifest.sqlite3")).unwrap();
        assert_eq!(
            c.query_row::<String, _, _>("SELECT payload FROM cases WHERE key='passive'", [], |r| r
                .get(0))
                .unwrap(),
            passive.payload.to_string()
        );
        assert_eq!(
            c.query_row::<String, _, _>(
                "SELECT source_hash FROM cases WHERE key='passive'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            source_hash(&passive)
        );
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM cases", [], |r| r.get(0))
                .unwrap(),
            2
        );
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM ranges", [], |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM domains", [], |r| r.get(0))
                .unwrap(),
            2
        );
        assert!(store.meta("current-build-id").unwrap().is_none());
    }
    #[test]
    fn frozen_target_merge_keeps_selected_targets_and_rechecks_candidate_scope_and_clock() {
        let at = 1_000_000;
        let incoming = json!({"kind":"geolocation","family":4,"ranges":[["1.1.1.0","1.1.1.255"]],"targets":["1.1.1.1"],"target_evidence":{"1.1.1.1":{"kind":"dns-answer","source":"original-receipt","observed":at-10,"valid_until":at+100}}});
        for runtime in [json!({}), json!({"targets":[]})] {
            let merged = merge_target_payload(&incoming, &runtime, at);
            assert_eq!(merged["targets"], incoming["targets"]);
            assert_eq!(merged["target_evidence"], incoming["target_evidence"]);
        }
        let selected = json!({"targets":["1.1.1.2"],"target_evidence":{"1.1.1.2":{"source":"existing-selection"}}});
        let merged = merge_target_payload(&incoming, &selected, at);
        assert_eq!(merged["targets"], selected["targets"]);
        assert_eq!(merged["target_evidence"], selected["target_evidence"]);
        for invalid in [
            "expired",
            "future",
            "family",
            "range",
            "ip-mismatch",
            "unqualified",
        ] {
            let mut candidate = incoming.clone();
            match invalid {
                "expired" => candidate["target_evidence"]["1.1.1.1"]["valid_until"] = json!(at),
                "future" => candidate["target_evidence"]["1.1.1.1"]["observed"] = json!(at + 1),
                "family" => candidate["family"] = json!(6),
                "range" => candidate["ranges"] = json!([["1.0.0.0", "1.0.0.255"]]),
                "ip-mismatch" => candidate["target_evidence"]["1.1.1.1"]["ip"] = json!("1.1.1.2"),
                "unqualified" => {
                    candidate["target_evidence"]["1.1.1.1"]["kind"] = json!("untrusted")
                }
                _ => unreachable!(),
            }
            assert_eq!(
                merge_target_payload(&candidate, &json!({"targets":[]}), at)["targets"],
                json!([]),
                "{invalid}"
            );
        }
    }
    #[test]
    fn case_retirement_keyset_pages_do_not_rescan_unrelated_active_rows() {
        let mut c = Connection::open_in_memory().unwrap();
        c.execute_batch("CREATE TABLE case_metadata(key TEXT PRIMARY KEY,fp TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL);CREATE INDEX case_metadata_summary ON case_metadata(active,kind,status);CREATE INDEX case_metadata_status ON case_metadata(active,status);ATTACH DATABASE ':memory:' AS incoming;CREATE TABLE incoming.cases(key TEXT PRIMARY KEY,source_hash TEXT NOT NULL,measurable INTEGER NOT NULL);CREATE INDEX incoming.case_measurable ON cases(key,source_hash) WHERE measurable=1;").unwrap();
        let tx = c.transaction().unwrap();
        {
            let mut insert=tx.prepare("INSERT INTO case_metadata VALUES(?,'fp',1,'geolocation','','','blocked-target',1)").unwrap();
            for i in 0..20_000 {
                insert.execute([format!("old-{i:06}")]).unwrap();
            }
        }
        tx.commit().unwrap();
        fn page(c: &Connection, sql: &str, cursor: &str) -> (Vec<String>, i32) {
            let mut q = c.prepare(sql).unwrap();
            let rows = q
                .query_map(params![cursor, 128], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap();
            (rows, q.get_status(rusqlite::StatementStatus::VmStep))
        }
        let old = CASE_REMOVALS_SQL.replace(" INDEXED BY sqlite_autoindex_case_metadata_1", "");
        let (_, old_steps) = page(&c, &old, "old-000127");
        let mut largest = 0;
        for (cursor, expected) in [
            ("", "old-000000"),
            ("old-000127", "old-000128"),
            ("old-019743", "old-019744"),
        ] {
            let (rows, steps) = page(&c, CASE_REMOVALS_SQL, cursor);
            assert_eq!(rows.len(), 128);
            assert_eq!(rows[0], expected);
            assert!(
                steps < 12_000,
                "page VM work grew with the full catalogue: {steps}"
            );
            largest = largest.max(steps);
        }
        let mut explain = c
            .prepare(&format!("EXPLAIN QUERY PLAN {CASE_REMOVALS_SQL}"))
            .unwrap();
        let plan = explain
            .query_map(params!["old-000127", 128], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert!(
            plan.iter()
                .any(|p| p.contains("sqlite_autoindex_case_metadata_1") && p.contains("key>")),
            "{plan:?}"
        );
        assert!(!plan.iter().any(|p| p.contains("TEMP B-TREE")), "{plan:?}");
        assert!(
            old_steps > largest * 8,
            "negative control did not reproduce the expensive active-index plan: old={old_steps}, fixed={largest}"
        );
        eprintln!(
            "case retirement page: old_vm_steps={old_steps}, fixed_max_vm_steps={largest}, catalogue_rows=20000, page_rows=128"
        );
    }
}
