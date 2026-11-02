//! Read-only console views. A rule issue, shared job and execution attempt are
//! different counting units; no scheduler state is changed by these queries.
use crate::{hash, now, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{
    Connection, OpenFlags, OptionalExtension, params, params_from_iter, types::Value as Sql,
};
use serde::Deserialize;
use serde_json::{Value, json};

fn limit() -> usize {
    30
}
fn all() -> String {
    "all".into()
}
fn current() -> String {
    "current".into()
}
fn measurable() -> String {
    "measurable".into()
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "limit")]
    pub limit: usize,
    #[serde(default)]
    pub part: String,
    #[serde(default = "all")]
    pub purpose: String,
    #[serde(default = "current")]
    pub range: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub case_key: String,
    #[serde(default)]
    pub job_id: String,
    #[serde(default)]
    pub q: String,
    #[serde(default = "measurable")]
    pub category: String,
    #[serde(default)]
    pub build_id: String,
    #[serde(default)]
    pub after: Option<i64>,
    #[serde(default)]
    pub before: Option<i64>,
}
impl Default for AuditQuery {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 30,
            part: String::new(),
            purpose: all(),
            range: current(),
            state: String::new(),
            case_key: String::new(),
            job_id: String::new(),
            q: String::new(),
            category: measurable(),
            build_id: String::new(),
            after: None,
            before: None,
        }
    }
}
impl AuditQuery {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            ["", "items", "summary"].contains(&self.part.as_str()),
            "unknown audit response part"
        );
        ensure!(
            ["all", "business", "discovery"].contains(&self.purpose.as_str()),
            "unknown task purpose"
        );
        ensure!(
            ["current", "ended", "all"].contains(&self.range.as_str()),
            "unknown task range"
        );
        ensure!(
            self.q.len() <= 200 && self.case_key.len() <= 512 && self.job_id.len() <= 512,
            "audit filter too long"
        );
        ensure!(self.offset <= i64::MAX as usize, "audit offset too large");
        ensure!(
            self.after.zip(self.before).is_none_or(|(a, b)| a <= b),
            "invalid audit time range"
        );
        Ok(())
    }
}

fn read_connection(store: &Store) -> Result<Connection> {
    let c = Connection::open_with_flags(
        &store.path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(c)
}

// The same predicate drives classification and visibility. First-owner
// jobs.case_key / profile.purpose is deliberately not the current use of a job.
const CURRENT_LINK: &str = "c.active=1 AND c.status<>'decided' AND c.fp=l.fp AND c.revision=l.revision AND coalesce(json_extract(c.payload,'$.measurement_required'),1)<>0 AND EXISTS(SELECT 1 FROM json_each(c.payload,'$.targets') t WHERE t.value=j.target)";
fn business(current: bool) -> String {
    format!(
        "EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id AND c.kind<>'target-discovery' {})",
        if current {
            format!("AND {CURRENT_LINK}")
        } else {
            String::new()
        }
    )
}
fn discovery(current: bool) -> String {
    format!(
        "EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id AND c.kind='target-discovery' {})",
        if current {
            format!("AND {CURRENT_LINK}")
        } else {
            String::new()
        }
    )
}
fn current_link() -> String {
    format!(
        "EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id AND {CURRENT_LINK})"
    )
}

fn bind(values: &mut Vec<Sql>, value: impl Into<Sql>) -> String {
    values.push(value.into());
    format!("?{}", values.len())
}
fn case_filter(values: &mut Vec<Sql>, key: &str, alias: &str) -> String {
    let key = bind(values, key.to_owned());
    format!("EXISTS(SELECT 1 FROM job_cases k WHERE k.job_id={alias}.id AND k.case_key={key})")
}
fn common_filters(p: &AuditQuery, alias: &str, values: &mut Vec<Sql>) -> Vec<String> {
    let mut filters = Vec::new();
    if !p.case_key.is_empty() {
        filters.push(case_filter(values, &p.case_key, alias));
    }
    if !p.job_id.is_empty() {
        filters.push(format!("{alias}.id={}", bind(values, p.job_id.clone())));
    }
    if !p.q.is_empty() {
        let q = bind(
            values,
            format!(
                "%{}%",
                p.q.replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_")
            ),
        );
        filters.push(format!(
            "({alias}.target LIKE {q} ESCAPE '\\' OR {alias}.id LIKE {q} ESCAPE '\\')"
        ));
    }
    filters
}

fn task_base(p: &AuditQuery, values: &mut Vec<Sql>) -> String {
    let cb = business(true);
    let cd = discovery(true);
    let hb = business(false);
    let hd = discovery(false);
    let active = current_link();
    // Resolve selective association filters before inspecting jobs. A
    // correlated EXISTS outside an all-jobs driver otherwise scans the entire
    // history even when a problem has a single linked task.
    let (candidate, narrow) = if !p.job_id.is_empty() {
        (format!("SELECT {}", bind(values, p.job_id.clone())), true)
    } else if !p.case_key.is_empty() {
        (
            format!(
                "SELECT job_id FROM job_cases WHERE case_key={}",
                bind(values, p.case_key.clone())
            ),
            true,
        )
    } else if p.state == "unconfirmed" {
        ("SELECT id FROM jobs WHERE status='unknown' UNION SELECT job_id FROM gp_remote WHERE state='unknown' OR (state='sending' AND remote_id='')".into(), true)
    } else if p.purpose == "business" {
        // This is only a superset of business jobs. Keep the final current-use
        // classification below: a live discovery use can supersede an old
        // business link, and a deleted case must retain its legacy fallback.
        ("SELECT DISTINCT l.job_id FROM case_metadata m CROSS JOIN job_cases l ON l.case_key=m.key WHERE m.kind<>'target-discovery' UNION SELECT j.id FROM jobs j WHERE NOT EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id) AND coalesce(json_extract(j.profile,'$.purpose'),'')<>'discovery'".into(), true)
    } else {
        ((match p.range.as_str() {
            "current" => "SELECT id FROM jobs WHERE status IN ('pending','leased','unknown') UNION SELECT job_id FROM gp_remote",
            "ended" => "SELECT id FROM jobs WHERE status='complete'",
            _ => "SELECT id FROM jobs",
        }).into(), false)
    };
    let mut filters = common_filters(p, "j", values);
    if p.range == "current" {
        filters.push("(j.status IN ('pending','leased','unknown') OR g.job_id IS NOT NULL)".into());
        filters.push(format!(
            "({active} OR j.status='leased' OR g.job_id IS NOT NULL)"
        ));
        filters.push("(coalesce(json_extract(j.profile,'$.legacy_alias'),0)<>1 OR json_extract(j.profile,'$.logical_job')=1 OR j.status='leased' OR g.job_id IS NOT NULL)".into());
    } else if p.range == "ended" {
        filters.push("j.status='complete'".into());
    }
    let predicate = if filters.is_empty() {
        "1".into()
    } else {
        filters.join(" AND ")
    };
    // For a selective candidate, retain it as the outer loop instead of letting
    // ORDER BY choose a backwards scan of every job in audit_job_recent.
    let materialized = if narrow { "MATERIALIZED " } else { "" };
    let join = if narrow { "CROSS JOIN" } else { "JOIN" };
    format!("WITH candidate(id) AS {materialized}({candidate}), task_base AS (SELECT j.id,j.kind,j.target,j.region,j.status,j.not_before,j.created,j.attempt_seq,j.round_seq,j.execution_count,j.next_round_at,CASE WHEN j.status IN ('complete','obsolete') THEN coalesce(j.lease_node,(SELECT node FROM results WHERE id=j.result_id)) ELSE j.lease_node END lease_node,j.lease_until,j.result_id,g.remote_id,g.state AS remote_state,g.account,
        CASE WHEN {cb} THEN 1 WHEN {cd} THEN 0 WHEN {hb} THEN 1 WHEN {hd} THEN 0 ELSE coalesce(json_extract(j.profile,'$.purpose'),'')<>'discovery' END AS business,
        CASE WHEN {cd} THEN 1 WHEN NOT {active} AND {hd} THEN 1 ELSE 0 END AS discovery,
        CASE WHEN g.state='unknown' OR (g.state='sending' AND g.remote_id='') THEN 'unconfirmed'
          WHEN g.job_id IS NOT NULL THEN 'processing'
          WHEN j.status='leased' THEN 'processing'
          WHEN j.status='pending' THEN 'queued'
          WHEN j.status='unknown' AND j.execution_count>=3 THEN 'cooldown'
          WHEN j.status='unknown' THEN 'unconfirmed'
          WHEN j.status='complete' THEN 'ended' ELSE 'obsolete' END AS state,
        CASE WHEN g.state='unknown' THEN 'unknown' WHEN g.state='prepared' THEN 'prepared'
          WHEN g.state='sending' THEN 'sending' WHEN g.remote_id<>'' THEN 'remote'
          WHEN j.status='leased' AND EXISTS(SELECT 1 FROM lease_history h WHERE h.job_id=j.id AND h.attempt_seq=j.attempt_seq AND h.round_seq=j.round_seq AND h.started_at IS NOT NULL AND h.execution_refunded=0) THEN 'started'
          WHEN j.status='leased' THEN 'reserved' WHEN j.status='pending' AND j.not_before>{} THEN 'delayed'
          WHEN j.status='unknown' AND j.execution_count>=3 THEN 'cooldown'
          ELSE j.status END AS phase
        FROM candidate x {join} jobs j ON j.id=x.id LEFT JOIN gp_remote g ON g.job_id=j.id WHERE {predicate})", bind(values,now()))
}
fn view_filters(p: &AuditQuery, kind: &str, values: &mut Vec<Sql>) -> String {
    let mut f = Vec::new();
    match p.purpose.as_str() {
        "business" => f.push("business=1".into()),
        "discovery" => f.push("business=0 AND discovery=1".into()),
        _ => {}
    }
    if !p.state.is_empty() {
        f.push(format!("{kind}={}", bind(values, p.state.clone())));
    }
    if p.range == "ended" && kind == "state" {
        f.push("state='ended'".into());
    }
    if kind == "state" {
        if let Some(after) = p.after {
            f.push(format!("created>={}", bind(values, after)));
        }
        if let Some(before) = p.before {
            f.push(format!("created<={}", bind(values, before)));
        }
    }
    if f.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", f.join(" AND "))
    }
}
fn cases(c: &Connection, id: &str, target: &str) -> Result<(i64, Vec<Value>)> {
    let count = c
        .prepare_cached("SELECT count(*) FROM job_cases WHERE job_id=?")?
        .query_row([id], |r| r.get(0))?;
    let mut q=c.prepare_cached("SELECT l.case_key,c.subject,c.kind,c.fp=l.fp AND c.revision=l.revision AND c.active=1 AND c.status<>'decided' AND coalesce(json_extract(c.payload,'$.measurement_required'),1)<>0 AND EXISTS(SELECT 1 FROM json_each(c.payload,'$.targets') t WHERE t.value=?2) FROM job_cases l LEFT JOIN cases c ON c.key=l.case_key WHERE l.job_id=?1 ORDER BY l.case_key LIMIT 12")?;
    let rows=q.query_map(params![id,target],|r|Ok(json!({"key":r.get::<_,String>(0)?,"subject":r.get::<_,Option<String>>(1)?,"kind":r.get::<_,Option<String>>(2)?,"current":r.get::<_,Option<bool>>(3)?.unwrap_or(false)})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok((count, rows))
}
fn reason(state: &str, phase: &str, not_before: i64) -> String {
    match (state, phase) {
        ("unconfirmed", _) => "提交或旧执行状态尚未核实，保留原恢复记录".into(),
        ("cooldown", _) => "本轮三次执行机会已耗尽，等待需求重新满足续轮条件".into(),
        ("queued", "delayed") => format!("等待可执行时间 {not_before}，不等同于执行失败"),
        ("processing", "reserved") => "已预占容量，尚无执行开始记录".into(),
        ("processing", "started") => "已进入发送/执行边界，等待原尝试回传".into(),
        ("processing", "prepared") => "Globalping 已准备预留，尚未进入发送边界".into(),
        ("processing", "remote") => "已有远端 ID，继续按原 ID 回收".into(),
        ("ended", _) => "本轮任务结束；结果用途与新鲜度需分别查看".into(),
        ("obsolete", _) => "历史任务，已不属于当前有效工作".into(),
        _ => "等待符合能力的空闲执行方".into(),
    }
}
pub fn tasks(store: &Store, p: &AuditQuery) -> Result<Value> {
    p.validate()?;
    ensure!(
        [
            "",
            "queued",
            "processing",
            "unconfirmed",
            "cooldown",
            "ended",
            "obsolete"
        ]
        .contains(&p.state.as_str()),
        "unknown task state"
    );
    let mut c = read_connection(store)?;
    let tx = c.transaction()?;
    let mut values = Vec::new();
    let base = task_base(p, &mut values);
    let filter = view_filters(p, "state", &mut values);
    let mut out = json!({"scope":{"unit":"job","at":now(),"purpose":p.purpose,"range":p.range,"state":p.state,"case_key":p.case_key,"job_id":p.job_id,"q":p.q}});
    if p.part != "items" {
        let mut q = tx.prepare_cached(&format!(
            "{base} SELECT state,count(*) FROM task_base{filter} GROUP BY state"
        ))?;
        let mut states = serde_json::Map::new();
        let mut total = 0i64;
        for row in q.query_map(params_from_iter(&values), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (s, n) = row?;
            states.insert(s, json!(n));
            total += n;
        }
        out["total"] = json!(total);
        out["states"] = json!(states);
    }
    if p.part != "summary" {
        let count = bind(&mut values, p.limit.clamp(1, 100) as i64);
        let offset = bind(&mut values, p.offset as i64);
        let mut q=tx.prepare_cached(&format!("{base} SELECT id,kind,target,region,state,phase,not_before,created,attempt_seq,round_seq,execution_count,lease_node,remote_id,account,business,discovery,next_round_at FROM task_base{filter} ORDER BY created DESC,id LIMIT {count} OFFSET {offset}"))?;
        let mut items = Vec::new();
        for row in q.query_map(params_from_iter(&values),|r|{
            let node=r.get::<_,Option<String>>(11)?;let state=r.get::<_,String>(4)?;let phase=r.get::<_,String>(5)?;let at=r.get::<_,i64>(6)?;let b=r.get::<_,bool>(14)?;let d=r.get::<_,bool>(15)?;
            Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"target":r.get::<_,String>(2)?,"region":r.get::<_,String>(3)?,"reason":reason(&state,&phase,at),"state":state,"phase":phase,"not_before":at,"created":r.get::<_,i64>(7)?,"attempt_seq":r.get::<_,i64>(8)?,"round_seq":r.get::<_,i64>(9)?,"execution_count":r.get::<_,i64>(10)?,"executor":if node.as_deref().is_some_and(|n|n.starts_with("globalping:"))||r.get::<_,Option<String>>(13)?.is_some(){"globalping"}else if node.is_some(){"self"}else{"unassigned"},"node":node,"remote_id":r.get::<_,Option<String>>(12)?,"account":r.get::<_,Option<String>>(13)?,"purpose":if b{"business"}else{"discovery"},"purposes":([if b{Some("business")}else{None},if d{Some("discovery")}else{None}].into_iter().flatten().collect::<Vec<_>>()),"next_round_at":r.get::<_,Option<i64>>(16)?}))
        })? {
            let mut item=row?;let (count,linked)=cases(&tx,item["id"].as_str().unwrap_or(""),item["target"].as_str().unwrap_or(""))?;
            item["case_count"]=json!(count);item["cases"]=json!(linked);items.push(item);
        }
        out["items"] = json!(items);
    }
    tx.commit()?;
    Ok(out)
}

// A receipt has no persisted token hash. Matching attempt/round/node/fp must
// identify exactly one history row; ambiguous legacy rows remain visible but
// are never promoted to a precise execution count.
const RESULT_MATCH: &str = "r.job_id=h.job_id AND r.attempt_seq=h.attempt_seq AND r.round_seq=h.round_seq AND r.node=h.node AND r.fp=h.fp AND r.attempt_seq>0";
fn unique_history(alias: &str) -> String {
    format!(
        "(SELECT count(*) FROM lease_history matching WHERE matching.job_id={alias}.job_id AND matching.attempt_seq={alias}.attempt_seq AND matching.round_seq={alias}.round_seq AND matching.node={alias}.node AND matching.fp={alias}.fp)=1"
    )
}
fn branch_filter(p: &AuditQuery, values: &mut Vec<Sql>, created: &str, kind: &str) -> String {
    let mut conditions = Vec::new();
    if p.purpose == "business" {
        conditions.push("owner.business=1".into());
    }
    if p.purpose == "discovery" {
        conditions.push("owner.business=0 AND owner.discovery=1".into());
    }
    if !p.state.is_empty() {
        conditions.push(format!("({kind})={}", bind(values, p.state.clone())));
    }
    if let Some(at) = p.after {
        conditions.push(format!("{created}>={}", bind(values, at)));
    }
    if let Some(at) = p.before {
        conditions.push(format!("{created}<={}", bind(values, at)));
    }
    if conditions.is_empty() {
        "1".into()
    } else {
        conditions.join(" AND ")
    }
}
fn branch_limit(cap: Option<usize>, order: &str) -> String {
    cap.map(|n| format!(" ORDER BY {order} LIMIT {}", n.min(i64::MAX as usize)))
        .unwrap_or_default()
}
fn record_base(p: &AuditQuery, values: &mut Vec<Sql>, cap: Option<usize>) -> String {
    let cb = business(true);
    let cd = discovery(true);
    let hb = business(false);
    let hd = discovery(false);
    let active = current_link();
    let f = common_filters(p, "j", values);
    let where_jobs = if f.is_empty() {
        "1".into()
    } else {
        f.join(" AND ")
    };
    // A linked issue starts with its job IDs, not a correlated filter on the
    // complete job history. Retain the final filters for case/job intersections.
    // The business fallback still preserves genuinely unlinked legacy jobs.
    let (candidates, job_from) = if !p.case_key.is_empty() {
        let key = bind(values, p.case_key.clone());
        (
            format!(
                "case_candidates(id) AS MATERIALIZED (SELECT job_id FROM job_cases WHERE case_key={key}),"
            ),
            "case_candidates candidate CROSS JOIN jobs j ON j.id=candidate.id",
        )
    } else if p.purpose == "business" {
        ("business_candidates(id) AS MATERIALIZED (SELECT DISTINCT l.job_id FROM case_metadata m CROSS JOIN job_cases l ON l.case_key=m.key WHERE m.kind<>'target-discovery' UNION SELECT j.id FROM jobs j WHERE NOT EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id) AND coalesce(json_extract(j.profile,'$.purpose'),'')<>'discovery'),".to_string(),"business_candidates candidate JOIN jobs j ON j.id=candidate.id")
    } else {
        (String::new(), "jobs j")
    };
    let identity = unique_history("r");
    let at = bind(values, now());
    let history_kind="CASE WHEN r.id IS NOT NULL AND (r.execution_class='not-executed' OR h.result_class='not-executed') THEN 'not-executed'
        WHEN r.id IS NOT NULL AND h.execution_refunded=1 AND r.execution_class IN ('observation','target-failure') AND json_extract(r.evidence,'$.cache_hit')=1 THEN 'reused'
        WHEN r.id IS NOT NULL THEN 'returned' WHEN h.execution_refunded=1 THEN 'not-executed'
        WHEN g.state='unknown' OR (g.state='sending' AND g.remote_id='') THEN 'unconfirmed'
        WHEN g.job_id IS NOT NULL OR (j.status='leased' AND j.attempt_seq=h.attempt_seq AND j.round_seq=h.round_seq) THEN 'inflight'
        WHEN h.started_at IS NULL AND json_extract(h.lease_profile,'$.execution_reservation_schema')=1 THEN 'not-executed' ELSE 'unconfirmed' END";
    let remote_kind = "CASE WHEN g.state='unknown' OR (g.state='sending' AND g.remote_id='') THEN 'unconfirmed' ELSE 'inflight' END";
    let history_filter = branch_filter(p, values, "h.created", history_kind);
    let legacy_filter = branch_filter(p, values, "r.received", "'legacy-history'");
    let remote_filter = branch_filter(
        p,
        values,
        "coalesce(g.send_started_at,g.reserved_hour*3600)",
        remote_kind,
    );
    let h_limit = branch_limit(cap, "h.created DESC,h.job_id,h.token_hash");
    let l_limit = branch_limit(cap, "r.received DESC,r.job_id,r.id");
    // N history rows already establish a lower timestamp bound for the global
    // top N. Older legacy rows cannot enter that page. Keep ties and fall back
    // to the complete legacy scan when filtered history contains fewer rows.
    let legacy_bound = cap
        .map(|n| format!(" AND r.received>=coalesce((SELECT min(created) FROM history_records HAVING count(*)>={}),-9223372036854775808)", n.min(i64::MAX as usize)))
        .unwrap_or_default();
    let g_limit = branch_limit(
        cap,
        "coalesce(g.send_started_at,g.reserved_hour*3600) DESC,g.job_id",
    );
    let h_from = if p.purpose == "business" || !p.case_key.is_empty() || !p.job_id.is_empty() {
        "owned_jobs owner CROSS JOIN lease_history h ON h.job_id=owner.id JOIN jobs j ON j.id=h.job_id"
    } else {
        "lease_history h JOIN jobs j ON j.id=h.job_id JOIN owned_jobs owner ON owner.id=j.id"
    };
    let l_from = if p.purpose == "business" || !p.case_key.is_empty() || !p.job_id.is_empty() {
        "owned_jobs owner CROSS JOIN results r ON r.job_id=owner.id"
    } else {
        "results r JOIN owned_jobs owner ON owner.id=r.job_id"
    };
    format!("WITH {candidates} owned_jobs AS NOT MATERIALIZED (SELECT j.id,j.target,j.kind,j.region,CASE WHEN {cb} THEN 1 WHEN {cd} THEN 0 WHEN {hb} THEN 1 WHEN {hd} THEN 0 ELSE coalesce(json_extract(j.profile,'$.purpose'),'')<>'discovery' END business,CASE WHEN {cd} THEN 1 WHEN NOT {active} AND {hd} THEN 1 ELSE 0 END discovery FROM {job_from} WHERE {where_jobs}),
      history_records AS (SELECT h.job_id,h.token_hash identity,h.created,h.node,h.attempt_seq,h.round_seq,h.started_at,h.execution_refunded,r.id result_id,r.observed,r.received,r.outcome,coalesce(r.qualified,0) qualified,r.evidence_until valid_until,coalesce(r.accepted,0) accepted,1 identity_known,{history_kind} record_kind,coalesce(r.execution_class,h.result_class) execution_class,g.remote_id,g.state remote_state
        FROM {h_from} LEFT JOIN results r ON r.rowid=(SELECT r.rowid FROM results r WHERE {RESULT_MATCH} AND {identity} ORDER BY r.received,r.id LIMIT 1)
        LEFT JOIN gp_remote g ON g.job_id=h.job_id AND g.attempt_seq=h.attempt_seq AND coalesce(json_extract(g.lease,'$.profile.round_seq'),h.round_seq)=h.round_seq WHERE {history_filter}{h_limit}),
      legacy_records AS (SELECT r.job_id,'legacy:'||r.id,r.received,r.node,r.attempt_seq,r.round_seq,NULL,0,r.id,r.observed,r.received,r.outcome,r.qualified,r.evidence_until,r.accepted,0,'legacy-history' record_kind,r.execution_class,NULL,NULL FROM {l_from} WHERE (r.attempt_seq=0 OR NOT {identity}) AND {legacy_filter}{legacy_bound}{l_limit}),
      remote_records AS (SELECT g.job_id,'remote:'||g.job_id,coalesce(g.send_started_at,g.reserved_hour*3600),json_extract(g.lease,'$.profile.observer.id'),g.attempt_seq,coalesce(json_extract(g.lease,'$.profile.round_seq'),1),g.send_started_at,0,NULL,NULL,NULL,NULL,0,NULL,0,0,{remote_kind} record_kind,NULL,g.remote_id,g.state FROM gp_remote g JOIN owned_jobs owner ON owner.id=g.job_id WHERE NOT EXISTS(SELECT 1 FROM lease_history h WHERE h.job_id=g.job_id AND h.attempt_seq=g.attempt_seq) AND {remote_filter}{g_limit}),
      records AS (SELECT * FROM history_records UNION ALL SELECT * FROM legacy_records UNION ALL SELECT * FROM remote_records),
      record_base AS(SELECT r.*,j.target,j.kind,j.region,j.business,j.discovery,CASE WHEN r.valid_until IS NULL THEN NULL WHEN r.observed>0 AND r.observed<={at} AND r.valid_until>{at} THEN 1 ELSE 0 END fresh FROM records r JOIN owned_jobs j ON j.id=r.job_id)")
}
fn evidence_use(kind: &str, class: Option<&str>, qualified: bool) -> &'static str {
    if class == Some("not-executed") {
        return "未执行，不形成新的外部观测";
    }
    if class == Some("target-failure") {
        return "负观测：目标超时或拒绝，不直接证明地区";
    }
    if class == Some("executor-failure") {
        return "执行器故障，不能形成可复用证据";
    }
    match kind {
        "dns" if qualified => "DNS 答案或候选地址，不直接证明服务归属或 IP 地区",
        "traceroute" if qualified => "端点可达性与路径，不直接证明目标地区或整个前缀属性",
        _ => "保留回传材料；资格与具体事实用途需分别核查",
    }
}
pub fn records(store: &Store, p: &AuditQuery) -> Result<Value> {
    p.validate()?;
    ensure!(
        [
            "",
            "returned",
            "reused",
            "not-executed",
            "inflight",
            "unconfirmed",
            "legacy-history"
        ]
        .contains(&p.state.as_str()),
        "unknown execution record state"
    );
    let mut c = read_connection(store)?;
    let tx = c.transaction()?;
    let mut out = json!({"scope":{"unit":"attempt-record","at":now(),"purpose":p.purpose,"state":p.state,"case_key":p.case_key,"job_id":p.job_id,"q":p.q,"after":p.after,"before":p.before,"identity":"Only an unambiguous original attempt is counted as returned; legacy history stays separate."}});
    if p.part != "items" {
        let mut values = Vec::new();
        let base = record_base(p, &mut values, None);
        // The branches already enforce ownership, purpose, time and attempt
        // identity. Counts do not need the wide UNION row or its second job
        // join used to decorate list items. Project the classification first.
        let mut q = tx.prepare_cached(&format!(
            "{base} SELECT record_kind,count(*) FROM (SELECT record_kind FROM history_records UNION ALL SELECT record_kind FROM legacy_records UNION ALL SELECT record_kind FROM remote_records) GROUP BY record_kind"
        ))?;
        let mut states = serde_json::Map::new();
        let mut total = 0i64;
        for row in q.query_map(params_from_iter(&values), |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (s, n) = row?;
            states.insert(s, json!(n));
            total += n;
        }
        out["total"] = json!(total);
        out["states"] = json!(states);
    }
    if p.part != "summary" {
        let mut values = Vec::new();
        let cap = p.offset.saturating_add(p.limit.clamp(1, 100));
        let base = record_base(p, &mut values, Some(cap));
        let count = bind(&mut values, p.limit.clamp(1, 100) as i64);
        let offset = bind(&mut values, p.offset as i64);
        let sql = format!(
            "{base} SELECT job_id,identity,created,node,attempt_seq,round_seq,started_at,result_id,observed,received,outcome,qualified,valid_until,accepted,identity_known,record_kind,execution_class,remote_id,remote_state,target,kind,region,business,discovery,fresh FROM record_base ORDER BY created DESC,job_id,identity LIMIT {count} OFFSET {offset}"
        );
        let mut q = tx.prepare_cached(&sql)?;
        let mut items = Vec::new();
        for row in q.query_map(params_from_iter(&values),|r|{
            let job=r.get::<_,String>(0)?;let identity=r.get::<_,String>(1)?;let node=r.get::<_,Option<String>>(3)?;let kind=r.get::<_,String>(20)?;let class=r.get::<_,Option<String>>(16)?;let qualified=r.get::<_,bool>(11)?;
            Ok(json!({"id":hash(format!("{job}:{identity}")),"job_id":job,"created":r.get::<_,i64>(2)?,"node":node,"executor":if node.as_deref().is_some_and(|v|v.starts_with("globalping:")) || r.get::<_,Option<String>>(18)?.is_some(){"globalping"}else if node.is_some(){"self"}else{"unknown"},"attempt_seq":r.get::<_,i64>(4)?,"round_seq":r.get::<_,i64>(5)?,"started_at":r.get::<_,Option<i64>>(6)?,"result_id":r.get::<_,Option<String>>(7)?,"observed":r.get::<_,Option<i64>>(8)?,"received":r.get::<_,Option<i64>>(9)?,"outcome":r.get::<_,Option<String>>(10)?,"qualified":qualified,"valid_until":r.get::<_,Option<i64>>(12)?,"accepted":r.get::<_,bool>(13)?,"identity_known":r.get::<_,bool>(14)?,"record_kind":r.get::<_,String>(15)?,"execution_class":class,"remote_id":r.get::<_,Option<String>>(17)?,"remote_state":r.get::<_,Option<String>>(18)?,"target":r.get::<_,String>(19)?,"evidence_use":evidence_use(&kind,class.as_deref(),qualified),"kind":kind,"region":r.get::<_,String>(21)?,"purpose":if r.get::<_,bool>(22)?{"business"}else{"discovery"},"fresh":r.get::<_,Option<bool>>(24)?}))
        })? {
            let mut item=row?;let id=item["job_id"].as_str().unwrap_or("");let (count,linked)=cases(&tx,id,item["target"].as_str().unwrap_or(""))?;
            item["case_count"]=json!(count);item["cases"]=json!(linked);
            if !p.job_id.is_empty() && let Some(result)=item["result_id"].as_str() {
                let evidence:Option<String>=tx.prepare_cached("SELECT evidence FROM results WHERE id=?")?
                    .query_row([result],|r|r.get(0)).optional()?;
                item["result"]=evidence.and_then(|e|serde_json::from_str::<Value>(&e).ok()).unwrap_or(Value::Null);
            }
            items.push(item);
        }
        out["items"] = json!(items);
    }
    tx.commit()?;
    Ok(out)
}
