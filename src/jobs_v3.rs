//! Shared logical observations and short, fenced SQLite claims.
//! The old physical job IDs remain valid aliases so a migration cannot bypass
//! a leased attempt or a paid/uncertain remote creation.
use crate::{
    hash, now,
    store::{Lease, Node, Store},
};
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, OnceLock},
};

type CursorKey = (std::path::PathBuf, String, bool);
fn cursors() -> &'static Mutex<BTreeMap<CursorKey, (i64, String)>> {
    static CURSORS: OnceLock<Mutex<BTreeMap<CursorKey, (i64, String)>>> = OnceLock::new();
    CURSORS.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn save_cursor(s: &Store, node: &Node, uncovered: bool, time: i64, id: &str) {
    cursors().lock().expect("claim cursor lock").insert(
        (s.path.clone(), node.id.clone(), uncovered),
        (time, id.to_string()),
    );
}

fn scan_states() -> &'static Mutex<BTreeMap<CursorKey, bool>> {
    static STATES: OnceLock<Mutex<BTreeMap<CursorKey, bool>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}
pub fn uncovered_scan_complete(s: &Store, node: &Node) -> bool {
    scan_states()
        .lock()
        .expect("scan state lock")
        .get(&(s.path.clone(), node.id.clone(), true))
        .copied()
        .unwrap_or(false)
}

fn column(c: &Connection, table: &str, name: &str, declaration: &str) -> Result<()> {
    let columns = c
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if !columns.iter().any(|v| v == name) {
        c.execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {name} {declaration}"
        ))?;
    }
    Ok(())
}

pub fn migrate(s: &Store) -> Result<()> {
    let mut c = s.connect()?;
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (table, name, decl) in [
        ("jobs", "logical_key", "TEXT NOT NULL DEFAULT ''"),
        ("jobs", "demand_key", "TEXT NOT NULL DEFAULT ''"),
        ("jobs", "attempt_seq", "INTEGER NOT NULL DEFAULT 0"),
        ("jobs", "failure_count", "INTEGER NOT NULL DEFAULT 0"),
        ("jobs", "evidence_until", "INTEGER"),
        ("jobs", "execution_terminal", "INTEGER NOT NULL DEFAULT 0"),
        ("jobs", "round_seq", "INTEGER NOT NULL DEFAULT 1"),
        ("jobs", "execution_count", "INTEGER NOT NULL DEFAULT 0"),
        ("jobs", "next_round_at", "INTEGER"),
        ("jobs", "round_build_id", "TEXT"),
        ("results", "round_seq", "INTEGER NOT NULL DEFAULT 1"),
        ("results", "execution_class", "TEXT"),
        ("results", "observer_asn", "INTEGER"),
        ("lease_history", "round_seq", "INTEGER NOT NULL DEFAULT 1"),
        ("lease_history", "started_at", "INTEGER"),
        (
            "lease_history",
            "execution_refunded",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("lease_history", "execution_job_id", "TEXT"),
        ("lease_history", "result_class", "TEXT"),
        ("lease_history", "completed_at", "INTEGER"),
        ("lease_history", "observer_asn", "INTEGER"),
        (
            "nodes",
            "executor_cooldown_until",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("results", "attempt_seq", "INTEGER NOT NULL DEFAULT 0"),
        ("results", "qualified", "INTEGER NOT NULL DEFAULT 0"),
        ("results", "evidence_until", "INTEGER"),
        ("lease_history", "attempt_seq", "INTEGER NOT NULL DEFAULT 0"),
        ("lease_history", "lease_profile", "TEXT"),
    ] {
        column(&tx, table, name, decl)?;
    }
    tx.execute_batch("CREATE TABLE IF NOT EXISTS replan_cases(case_key TEXT PRIMARY KEY,queued_at INTEGER NOT NULL,build_id TEXT);
        CREATE TABLE IF NOT EXISTS job_cases(job_id TEXT NOT NULL,case_key TEXT NOT NULL,fp TEXT NOT NULL,revision INTEGER NOT NULL,required_round_seq INTEGER NOT NULL DEFAULT 1,PRIMARY KEY(job_id,case_key));
        CREATE INDEX IF NOT EXISTS job_cases_case ON job_cases(case_key,fp,revision,job_id);
        CREATE INDEX IF NOT EXISTS job_round_due ON jobs(next_round_at,id) WHERE next_round_at IS NOT NULL;
        CREATE INDEX IF NOT EXISTS lease_execution_round ON lease_history(execution_job_id,round_seq,completed_at,node);
        CREATE INDEX IF NOT EXISTS result_execution_round ON results(job_id,round_seq,execution_class);
        CREATE INDEX IF NOT EXISTS result_fusion_observed ON results(observed) WHERE qualified=1 AND outcome='ok';
        CREATE INDEX IF NOT EXISTS result_fusion_facts ON results(observed) WHERE (qualified=1 AND outcome='ok') OR execution_class='target-failure';
        CREATE INDEX IF NOT EXISTS job_target_method ON jobs(target,kind,logical_key);
        CREATE INDEX IF NOT EXISTS replan_case_queue ON replan_cases(queued_at,case_key);
        CREATE INDEX IF NOT EXISTS job_discovery_active ON jobs(status) WHERE status IN ('pending','leased') AND json_extract(profile,'$.purpose')='discovery' AND json_extract(profile,'$.logical_job')=1;
        CREATE INDEX IF NOT EXISTS job_active_target ON jobs(target,kind,status) WHERE status IN ('pending','leased');
        CREATE INDEX IF NOT EXISTS job_leased_node ON jobs(lease_node,kind,target) WHERE status='leased';
        CREATE INDEX IF NOT EXISTS job_logical_state ON jobs(logical_key,status);
        CREATE INDEX IF NOT EXISTS job_demand_state ON jobs(demand_key,status);
        CREATE INDEX IF NOT EXISTS job_pending_order ON jobs(not_before,id) WHERE status='pending';
        CREATE INDEX IF NOT EXISTS job_expired_lease ON jobs(lease_until,id) WHERE status='leased';
        CREATE INDEX IF NOT EXISTS job_evidence_due ON jobs(evidence_until,id) WHERE status='complete' AND kind='dns' AND evidence_until IS NOT NULL;
        CREATE INDEX IF NOT EXISTS job_canonical_dns_due ON jobs(evidence_until,id) WHERE status='complete' AND kind='dns' AND evidence_until IS NOT NULL AND json_extract(profile,'$.logical_job')=1;
        CREATE INDEX IF NOT EXISTS job_regular_dns_due ON jobs(evidence_until,id) WHERE status='complete' AND kind='dns' AND evidence_until IS NOT NULL AND json_extract(profile,'$.logical_job')=1 AND coalesce(json_extract(profile,'$.purpose'),'')<>'discovery';
        CREATE INDEX IF NOT EXISTS result_job_qualified ON results(job_id,qualified,observed);
        CREATE INDEX IF NOT EXISTS discovery_checks_due ON discovery_checks(kind,next_check,key);
        CREATE INDEX IF NOT EXISTS target_observations_expiry ON target_observations(valid_until);
        DROP TRIGGER IF EXISTS replan_case_insert_v3;
        DROP TRIGGER IF EXISTS replan_case_update_v3;")?;
    column(&tx, "replan_cases", "build_id", "TEXT")?;
    if !tx.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='shared-logical-jobs-v3')",
        [],
        |r| r.get(0),
    )? {
        // Backfill identities without replacing old IDs, tokens, leases or GP intents.
        let rows = {
            let mut q =
                tx.prepare("SELECT id,case_key,fp,target,kind,region,profile,attempts FROM jobs")?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (id, key, fp, target, kind, region, body, attempts) in rows {
            let profile: Value = serde_json::from_str(&body)?;
            let revision = profile["case_revision"].as_i64().unwrap_or(1);
            let canonical = crate::work::logical_profile(&profile);
            let required = canonical["region_required"].as_bool().unwrap_or(false);
            let scope = if required { region.as_str() } else { "any" };
            let logical =
                crate::work::logical_key((&key, &fp, revision), &target, &kind, scope, &canonical);
            let demand = crate::work::demand_key(&key, &target, &kind, scope, &canonical);
            let seq: i64 = tx
                .prepare_cached("SELECT count(*) FROM lease_history WHERE job_id=?")?
                .query_row([&id], |r| r.get(0))?;
            tx.prepare_cached("UPDATE jobs SET logical_key=?,demand_key=?,profile=CASE WHEN coalesce(json_extract(profile,'$.logical_job'),0)=1 THEN profile ELSE json_set(profile,'$.legacy_alias',1) END,attempt_seq=max(attempt_seq,?),failure_count=CASE WHEN status='complete' THEN 0 WHEN status='leased' THEN max(failure_count,max(0,?-1)) ELSE max(failure_count,?) END WHERE id=?")?.execute(params![logical,demand,seq,attempts.min(3),attempts.min(3),id])?;
        }
        tx.execute_batch("WITH numbered AS (SELECT job_id,token_hash,row_number() OVER(PARTITION BY job_id ORDER BY created,token_hash) seq FROM lease_history) UPDATE lease_history SET attempt_seq=(SELECT seq FROM numbered n WHERE n.job_id=lease_history.job_id AND n.token_hash=lease_history.token_hash) WHERE attempt_seq=0;")?;
        let holders = {
            let mut q = tx.prepare(
                "SELECT id,lease_token,attempt_seq FROM jobs WHERE lease_token IS NOT NULL",
            )?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (id, token, seq) in holders {
            tx.prepare_cached(
                "UPDATE lease_history SET attempt_seq=? WHERE job_id=? AND token_hash=?",
            )?
            .execute(params![seq, id, hash(token)])?;
        }
        // Only retire unsent old physical copies. In-flight aliases keep their exact namespace.
        tx.execute("UPDATE jobs SET status='obsolete' WHERE status='pending' AND coalesce(json_extract(profile,'$.logical_job'),0)<>1 AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id)",[])?;
        tx.execute(
            "INSERT OR IGNORE INTO replan_cases(case_key,queued_at) SELECT key,? FROM cases WHERE active=1",
            [now()],
        )?;
        tx.execute(
            "INSERT INTO meta VALUES('shared-logical-jobs-v3','complete')",
            [],
        )?;
    }
    if !tx.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='shared-observations-v4')",
        [],
        |r| r.get(0),
    )? {
        let rows = {
            let mut q = tx.prepare("SELECT id,case_key,fp,target,kind,region,profile FROM jobs")?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (id, key, fp, target, kind, region, body) in rows {
            let p: Value = serde_json::from_str(&body)?;
            let normalized = crate::work::logical_profile(&p);
            let view = if normalized["region_required"] == true {
                region.as_str()
            } else {
                "any"
            };
            let identity =
                crate::work::logical_key((&key, &fp, 1), &target, &kind, view, &normalized);
            tx.prepare_cached("UPDATE jobs SET logical_key=?,demand_key=?,profile=json_set(profile,'$.legacy_alias',1,'$.logical_job',0) WHERE id=?")?.execute(params![identity,identity,id])?;
            tx.prepare_cached("INSERT INTO job_cases(job_id,case_key,fp,revision,required_round_seq) VALUES(?,?,?,?,1) ON CONFLICT(job_id,case_key) DO NOTHING")?.execute(params![id,key,fp,p["case_revision"].as_i64().unwrap_or(1)])?;
        }
        let held = {
            let mut q=tx.prepare("SELECT id,case_key,fp,kind,target,region,profile,lease_token FROM jobs WHERE status='leased' AND lease_token IS NOT NULL AND json_extract(profile,'$.legacy_alias')=1")?;
            q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut owners = BTreeSet::new();
        for (old, key, source_fp, kind, target, region, body, token) in held {
            let p: Value = serde_json::from_str(&body)?;
            let mut profile = crate::work::logical_profile(&p);
            let view = if profile["region_required"] == true {
                region.as_str()
            } else {
                "any"
            };
            for field in [
                "observer_id",
                "self_only",
                "remote_only",
                "epoch",
                "case_revision",
            ] {
                profile.as_object_mut().unwrap().remove(field);
            }
            profile["logical_job"] = json!(true);
            profile["legacy_alias"] = json!(false);
            profile["observation_schema"] = json!(4);
            profile["scheduler"] = json!(2);
            let logical =
                crate::work::logical_key((&key, &source_fp, 1), &target, &kind, view, &profile);
            let owner = format!("job-{}", &logical[..32]);
            tx.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key) VALUES(?,?,?,?,?,?,?,'pending',?,?,?,?) ON CONFLICT(id) DO NOTHING",params![owner,key,logical,kind,target,view,profile.to_string(),now(),now(),logical,logical])?;
            tx.execute("INSERT INTO job_cases(job_id,case_key,fp,revision) VALUES(?,?,?,?) ON CONFLICT(job_id,case_key) DO NOTHING",params![owner,key,source_fp,p["case_revision"].as_i64().unwrap_or(1)])?;
            tx.execute("UPDATE lease_history SET started_at=coalesce(started_at,created),execution_job_id=?,round_seq=1 WHERE job_id=? AND token_hash=?",params![owner,old,hash(token)])?;
            owners.insert(owner);
        }
        for owner in owners {
            tx.execute("UPDATE jobs SET execution_count=(SELECT count(*) FROM lease_history h WHERE h.execution_job_id=jobs.id AND h.round_seq=jobs.round_seq AND h.started_at IS NOT NULL AND h.execution_refunded=0) WHERE id=?",[&owner])?;
            tx.execute("UPDATE jobs SET status='unknown',next_round_at=? WHERE id=? AND execution_count>=3",params![now()+86400,owner])?;
        }
        tx.execute("UPDATE jobs SET status='obsolete' WHERE status='pending' AND json_extract(profile,'$.legacy_alias')=1 AND coalesce(json_extract(profile,'$.logical_job'),0)<>1 AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id)",[])?;
        tx.execute("INSERT INTO replan_cases(case_key,queued_at) SELECT key,? FROM cases WHERE active=1 ON CONFLICT(case_key) DO NOTHING",[now()])?;
        tx.execute(
            "INSERT INTO meta VALUES('shared-observations-v4','complete')",
            [],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Shared by claims and console readiness; unresolved aliases are not ready work.
pub fn demand_available_sql(j: &str) -> String {
    format!(
        "NOT EXISTS(SELECT 1 FROM jobs old WHERE old.demand_key={j}.demand_key AND old.status='leased') AND NOT EXISTS(SELECT 1 FROM jobs old JOIN gp_remote g ON g.job_id=old.id WHERE old.demand_key={j}.demand_key) AND NOT EXISTS(SELECT 1 FROM jobs done WHERE done.id<>{j}.id AND done.logical_key={j}.logical_key AND done.status='complete' AND done.execution_terminal=1 AND (done.evidence_until IS NULL OR done.evidence_until>CAST(strftime('%s','now') AS INTEGER)))"
    )
}

pub fn lease(s: &Store, node: &Node, session: Option<&str>) -> Result<Option<Lease>> {
    lease_with_admission(s, node, session, |_, _| Ok(true))
}

/// A session worker owns this connection between calls. Transactions and
/// candidate statements end here before it returns to the asynchronous caller.
pub(crate) fn lease_on(
    s: &Store,
    c: &mut Connection,
    node: &Node,
    session: Option<&str>,
) -> Result<Option<Lease>> {
    lease_with_admission_preference_on(s, c, node, session, false, |_, _| Ok(true))
}

/// Candidate reads are outside the write transaction. Every predicate is checked
/// again in the claim transaction; external I/O belongs after this function.
pub fn lease_with_admission<F>(
    s: &Store,
    node: &Node,
    session: Option<&str>,
    admit: F,
) -> Result<Option<Lease>>
where
    F: FnMut(&Transaction<'_>, &Lease) -> Result<bool>,
{
    lease_with_admission_preference(s, node, session, false, admit)
}

pub fn lease_with_admission_preference<F>(
    s: &Store,
    node: &Node,
    session: Option<&str>,
    uncovered_only: bool,
    admit: F,
) -> Result<Option<Lease>>
where
    F: FnMut(&Transaction<'_>, &Lease) -> Result<bool>,
{
    let mut c = s.connect()?;
    lease_with_admission_preference_on(s, &mut c, node, session, uncovered_only, admit)
}

fn lease_with_admission_preference_on<F>(
    s: &Store,
    c: &mut Connection,
    node: &Node,
    session: Option<&str>,
    uncovered_only: bool,
    mut admit: F,
) -> Result<Option<Lease>>
where
    F: FnMut(&Transaction<'_>, &Lease) -> Result<bool>,
{
    let remote = node.id.starts_with("globalping:");
    let eligible = crate::work::eligibility_sql("j", "n");
    let available = demand_available_sql("j");
    let uncovered = if remote && uncovered_only {
        format!("AND {}", crate::work::uncovered_sql("j"))
    } else {
        String::new()
    };
    let base = format!(
        "FROM jobs j JOIN nodes n ON n.id=?1 WHERE j.status='pending' AND j.not_before<=?2 AND {eligible} {uncovered} AND {available} AND EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision,json_each(c.payload,'$.targets') target WHERE l.job_id=j.id AND l.required_round_seq<=j.round_seq AND c.active=1 AND c.status<>'decided' AND coalesce(json_extract(c.payload,'$.measurement_required'),1)<>0 AND target.value=j.target) AND NOT EXISTS(SELECT 1 FROM jobs busy WHERE busy.status='leased' AND busy.lease_node=n.id AND busy.kind=j.kind AND busy.target=j.target)"
    );
    let query = format!("SELECT j.id {base} AND j.id IN (SELECT value FROM json_each(?3))");
    let (mut cursor_time, mut cursor_id) = cursors()
        .lock()
        .expect("claim cursor lock")
        .get(&(s.path.clone(), node.id.clone(), uncovered_only))
        .cloned()
        .unwrap_or((i64::MIN, String::new()));
    let mut wrapped = false;
    if uncovered_only {
        scan_states()
            .lock()
            .expect("scan state lock")
            .insert((s.path.clone(), node.id.clone(), true), false);
    }
    // Bound raw queue scanning, retaining the cursor between calls. Eligibility
    // is checked before selecting claim counts, including beyond an ineligible head.
    for _ in 0..8 {
        let raw=c.prepare_cached("SELECT id,not_before FROM jobs INDEXED BY job_pending_order WHERE status='pending' AND not_before<=?1 AND (not_before>?2 OR (not_before=?2 AND id>?3)) ORDER BY not_before,id LIMIT 128")?.query_map(params![now(),cursor_time,cursor_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;
        if raw.is_empty() {
            if uncovered_only {
                scan_states()
                    .lock()
                    .expect("scan state lock")
                    .insert((s.path.clone(), node.id.clone(), true), true);
                save_cursor(s, node, true, i64::MIN, "");
                return Ok(None);
            }
            if !wrapped && cursor_time != i64::MIN {
                cursor_time = i64::MIN;
                cursor_id.clear();
                wrapped = true;
                continue;
            }
            save_cursor(s, node, uncovered_only, i64::MIN, "");
            return Ok(None);
        }
        let ids: Vec<&str> = raw.iter().map(|(id, _)| id.as_str()).collect();
        let eligible: BTreeSet<String> = c
            .prepare_cached(&query)?
            .query_map(params![node.id, now(), serde_json::to_string(&ids)?], |r| {
                r.get(0)
            })?
            .collect::<std::result::Result<_, _>>()?;
        for (id, order_time) in raw {
            cursor_time = order_time;
            cursor_id = id.clone();
            save_cursor(s, node, uncovered_only, cursor_time, &cursor_id);
            if !eligible.contains(&id) {
                continue;
            }
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if let Some(session) = session
                && !tx.prepare_cached("SELECT EXISTS(SELECT 1 FROM nodes WHERE id=? AND session_id=? AND connected=1 AND disabled=0)")?.query_row(params![node.id,session],|r|r.get::<_,bool>(0))? {
                return Ok(None);
            }
            let capacity:Option<(u32,u32,bool,String,u32)> = tx.prepare_cached("SELECT coalesce(concurrency_limit,10),coalesce(worker_capacity,1000),disabled<>0,region,asn FROM nodes WHERE id=?")?.query_row([&node.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
            let Some((limit, worker, disabled, actual_region, actual_asn)) = capacity else {
                return Ok(None);
            };
            if disabled {
                return Ok(None);
            }
            let active: u32 = tx
                .prepare_cached("SELECT count(*) FROM jobs WHERE status='leased' AND lease_node=?")?
                .query_row([&node.id], |r| r.get(0))?;
            if !remote && active >= limit.clamp(1, 1000).min(worker) {
                return Ok(None);
            }
            if remote {
                let active:u32=tx.prepare_cached("SELECT count(*) FROM jobs WHERE status='leased' AND lease_node LIKE 'globalping:%'")?.query_row([],|r|r.get(0))?;
                if active
                    >= crate::scheduler::policy_on(&tx)?
                        .globalping_concurrency
                        .min(16)
                {
                    return Ok(None);
                }
            }
            let check = format!(
                "SELECT j.case_key,j.fp,j.kind,j.target,j.profile,j.attempt_seq,j.not_before {base} AND j.id=?3"
            );
            let row: Option<(String, String, String, String, String, i64, i64)> = tx
                .prepare_cached(&check)?
                .query_row(params![node.id, now(), id], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })
                .optional()?;
            let Some((key, fp, kind, target, body, seq, _not_before)) = row else {
                continue;
            };
            if dispatch_case_links_on(&tx, &id)?.is_empty() {
                continue;
            }
            if crate::work::reuse_fresh_observation_on(&tx, &id, None)? {
                tx.commit()?;
                continue;
            }

            let mut profile: Value = serde_json::from_str(&body)?;
            profile["attempt_seq"] = json!(seq + 1);
            profile["execution_reservation_schema"] = json!(1);
            if let Some(session) = session {
                profile["worker_session"] = json!(session);
            }
            let round_seq: i64 = tx
                .prepare_cached("SELECT round_seq FROM jobs WHERE id=?")?
                .query_row([&id], |r| r.get(0))?;
            profile["round_seq"] = json!(round_seq);
            profile["epoch"] = json!(format!("round-{round_seq}"));
            profile["observer"] = json!({"id":node.id,"region":actual_region,"asn":actual_asn});
            profile["network_support"]=tx.prepare_cached("SELECT json_object('ipv4',coalesce(ipv4_supported,1),'ipv6',coalesce(ipv6_supported,0)) FROM nodes WHERE id=?")?.query_row([&node.id],|r|r.get::<_,String>(0)).map(|v|serde_json::from_str::<Value>(&v).unwrap_or(Value::Null))?;
            let token = uuid::Uuid::new_v4().to_string();
            let until = now() + 180;
            let lease = Lease {
                id: id.clone(),
                case_key: key,
                fingerprint: fp.clone(),
                kind,
                target,
                region: actual_region,
                token: token.clone(),
                until,
                profile,
            };
            tx.prepare_cached("UPDATE jobs SET status='leased',lease_node=?,lease_token=?,lease_until=?,attempt_seq=attempt_seq+1,attempts=attempts+1 WHERE id=? AND status='pending' AND attempt_seq=?")?.execute(params![node.id,token,until,id,seq])?;
            tx.prepare_cached("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,lease_profile,round_seq,execution_job_id) VALUES(?,?,?,?,?,?,?,?,?)")?.execute(params![id,hash(&token),node.id,fp,now(),seq+1,lease.profile.to_string(),round_seq,id])?;
            if !admit(&tx, &lease)? {
                return Ok(None);
            }
            tx.commit()?;
            return Ok(Some(lease));
        }
    }
    Ok(None)
}

/// Ordinary DNS has an autonomous freshness deadline. Discovery TTL only expires
/// evidence: its catalogue cursor selects later work before revisiting a host.
/// Trace renewals need an explicit fresh daily manifest.
pub fn expire_due(s: &Store) -> Result<usize> {
    expire_due_on(&mut s.connect()?)
}

pub(crate) fn expire_due_on(c: &mut Connection) -> Result<usize> {
    let dns = {
        let mut due = BTreeSet::new();
        // Purpose is not part of a shared job's identity. An older discovery
        // job may also serve manual DNS; start that exception from the small
        // indexed manual-demand set, never the expired discovery catalogue.
        for sql in [
            "SELECT evidence_until,id FROM jobs INDEXED BY job_regular_dns_due WHERE status='complete' AND kind='dns' AND evidence_until IS NOT NULL AND json_extract(profile,'$.logical_job')=1 AND coalesce(json_extract(profile,'$.purpose'),'')<>'discovery' AND evidence_until<=? AND EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision,json_each(c.payload,'$.targets') target WHERE l.job_id=jobs.id AND l.required_round_seq<=jobs.round_seq AND c.active=1 AND c.kind='domain-observation' AND c.status<>'decided' AND coalesce(json_extract(c.payload,'$.measurement_required'),1)<>0 AND target.value=jobs.target) ORDER BY evidence_until,id LIMIT 128",
            "SELECT DISTINCT j.evidence_until,j.id FROM case_metadata m INDEXED BY case_metadata_summary CROSS JOIN job_cases l INDEXED BY job_cases_case ON l.case_key=m.key AND l.fp=m.fp AND l.revision=m.revision CROSS JOIN jobs j ON j.id=l.job_id CROSS JOIN cases c ON c.key=m.key AND c.fp=m.fp AND c.revision=m.revision WHERE m.active=1 AND m.kind='domain-observation' AND c.active=1 AND c.status<>'decided' AND j.status='complete' AND j.kind='dns' AND json_extract(j.profile,'$.logical_job')=1 AND json_extract(j.profile,'$.purpose')='discovery' AND j.evidence_until IS NOT NULL AND j.evidence_until<=? AND l.required_round_seq<=j.round_seq AND coalesce(json_extract(c.payload,'$.measurement_required'),1)<>0 AND EXISTS(SELECT 1 FROM json_each(c.payload,'$.targets') target WHERE target.value=j.target) ORDER BY j.evidence_until,j.id LIMIT 128",
        ] {
            let mut q = c.prepare(sql)?;
            for row in q.query_map([now()], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })? {
                due.insert(row?);
            }
        }
        due.into_iter()
            .take(128)
            .map(|(_, id)| id)
            .collect::<Vec<_>>()
    };
    let leases = {
        let mut q=c.prepare("SELECT id FROM jobs INDEXED BY job_expired_lease WHERE status='leased' AND lease_until<? AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id) ORDER BY lease_until,id LIMIT 128")?;
        q.query_map([now()], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if dns.is_empty() && leases.is_empty() {
        return Ok(0);
    }
    let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut changed = 0;
    for id in dns {
        if reopen_dns_deadline_on(&tx, &id)? {
            changed += 1
        }
    }
    for id in leases {
        let current = current_case_links_on(&tx, &id)?;
        let row:(i64,bool,i64)=tx.query_row("SELECT execution_count,coalesce(json_extract(profile,'$.legacy_alias'),0)=1,attempt_seq FROM jobs WHERE id=?",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        let state = if current.is_empty() || row.1 {
            "obsolete"
        } else if row.0 >= 3 {
            "unknown"
        } else {
            "pending"
        };
        changed+=tx.execute("UPDATE jobs SET status=?,next_round_at=CASE WHEN ?='unknown' THEN coalesce(next_round_at,?) ELSE next_round_at END,not_before=?,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND status='leased' AND lease_until<? AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id)",params![state,state,now()+86400,now()+1,id,now()])?;
        for (key, _) in current {
            crate::work::mark_case(&tx, &key)?;
        }
    }
    tx.commit()?;
    Ok(changed)
}

fn reopen_dns_deadline_on(c: &Connection, job_id: &str) -> Result<bool> {
    // Recheck the actual demand under the writer, even if the first creator's
    // profile still says manual after its manual link was removed or changed.
    for (key, _) in current_case_links_on(c, job_id)? {
        if c.query_row(
            "SELECT kind='domain-observation' FROM cases WHERE key=?",
            [key],
            |r| r.get::<_, bool>(0),
        )? {
            return reopen_round_on(c, job_id, None, true);
        }
    }
    Ok(false)
}

pub fn reopen_round_on(
    c: &Connection,
    job_id: &str,
    fresh_build: Option<&str>,
    dns_deadline: bool,
) -> Result<bool> {
    type RenewalState = (
        String,
        String,
        Option<i64>,
        Option<i64>,
        Option<String>,
        i64,
    );
    let row:Option<RenewalState>=c.query_row("SELECT kind,status,evidence_until,next_round_at,round_build_id,execution_count FROM jobs WHERE id=? AND json_extract(profile,'$.logical_job')=1",[job_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((kind, state, expiry, cooldown, round_build, used)) = row else {
        return Ok(false);
    };
    let due = if dns_deadline {
        kind == "dns" && state == "complete" && expiry.is_some_and(|v| v <= now())
    } else {
        fresh_build.is_some_and(|build| round_build.as_deref() != Some(build))
            && ((state == "complete" && expiry.is_some_and(|v| v <= now()))
                || (state == "unknown" && used >= 3 && cooldown.is_some_and(|v| v <= now())))
    };
    if !due || cooldown.is_some_and(|v| v > now()) || current_case_links_on(c, job_id)?.is_empty() {
        return Ok(false);
    }
    let blocked:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM jobs j JOIN jobs old ON old.demand_key=j.demand_key WHERE j.id=? AND (old.status='leased' OR EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=old.id)))",[job_id],|r|r.get(0))?;
    if blocked {
        return Ok(false);
    }
    Ok(c.execute("UPDATE jobs SET status='pending',round_seq=round_seq+1,execution_count=0,failure_count=0,attempts=0,execution_terminal=0,next_round_at=NULL,evidence_until=NULL,result_id=NULL,lease_node=NULL,lease_token=NULL,lease_until=NULL,not_before=?,round_build_id=coalesce(?,round_build_id) WHERE id=?",params![now(),fresh_build,job_id])?==1)
}

/// One-time conservative evidence recheck after the authority country mapping
/// is configured. Old accepted/ok is authentication history, never a scope proof.
/// Candidates and JSON qualification are prepared before each short write batch.
pub fn requalify_legacy(s: &Store) -> Result<usize> {
    if s.meta("legacy-evidence-recheck-v3")?.is_some() {
        return Ok(0);
    }
    let Some(mapping) = s.meta("observation-country-regions")? else {
        return Ok(0);
    };
    let mapping: Value = serde_json::from_str(&mapping)?;
    let mut cursor = String::new();
    let mut total = 0;
    loop {
        let c = s.connect()?;
        // Native history without the original attempt scope cannot be qualified.
        // Filter it before transferring evidence bodies or filling each batch;
        // provider receipts still use their actual returned probe metadata.
        let rows = {
            let mut q=c.prepare("SELECT r.id,r.job_id,r.node,r.fp,r.observed,r.outcome,r.evidence,j.case_key,j.kind,j.target,j.region,j.profile,n.region,n.asn,n.capabilities,h.lease_profile FROM results r JOIN jobs j ON j.id=r.job_id JOIN nodes n ON n.id=r.node LEFT JOIN lease_history h ON h.job_id=r.job_id AND h.node=r.node AND h.fp=r.fp AND h.attempt_seq=r.attempt_seq AND r.attempt_seq>0 AND h.lease_profile IS NOT NULL WHERE r.id>? AND r.accepted=1 AND r.outcome='ok' AND r.qualified=0 AND coalesce(json_extract(j.profile,'$.logical_job'),0)<>1 AND (r.node LIKE 'globalping:%' OR h.lease_profile IS NOT NULL) ORDER BY r.id LIMIT 256")?;
            q.query_map([&cursor], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, String>(6)?,
                    r.get::<_, String>(7)?,
                    r.get::<_, String>(8)?,
                    r.get::<_, String>(9)?,
                    r.get::<_, String>(10)?,
                    r.get::<_, String>(11)?,
                    r.get::<_, String>(12)?,
                    r.get::<_, u32>(13)?,
                    r.get::<_, String>(14)?,
                    r.get::<_, Option<String>>(15)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        if rows.is_empty() {
            break;
        }
        let mut candidates = vec![];
        for (
            id,
            job,
            node,
            fp,
            at,
            outcome,
            body,
            key,
            kind,
            target,
            region,
            profile,
            node_region,
            asn,
            caps,
            historical_profile,
        ) in rows
        {
            cursor = id.clone();
            let profile = if let Some(history) = historical_profile {
                history
            } else if node.starts_with("globalping:") {
                profile
            } else {
                continue;
            };
            let mut profile: Value = serde_json::from_str(&profile)?;
            profile["observation_country_regions"] = mapping.clone();
            let lease = Lease {
                id: job.clone(),
                case_key: key,
                fingerprint: fp.clone(),
                kind,
                target,
                region,
                token: String::new(),
                until: 0,
                profile,
            };
            let node = Node {
                id: node.clone(),
                region: node_region,
                asn,
                capabilities: serde_json::from_str(&caps)?,
            };
            let result = crate::store::ProbeResult {
                id: id.clone(),
                job_id: job.clone(),
                fingerprint: fp,
                lease_token: String::new(),
                observed_at: at,
                outcome,
                evidence: serde_json::from_str(&body)?,
            };
            let q = crate::receipt::qualify(&lease, &node, &result);
            candidates.push((id, job, q));
        }
        let mut c = s.connect()?;
        let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for (id, job, q) in candidates {
            if q.execution_terminal {
                total += tx.execute(
                    "UPDATE results SET qualified=?,evidence_until=? WHERE id=? AND qualified=0",
                    params![q.qualified, q.evidence_until, id],
                )?;
                tx.execute("UPDATE jobs SET execution_terminal=1,failure_count=0,evidence_until=? WHERE id=? AND result_id=? AND status='complete'",params![q.evidence_until,job,id])?;
                tx.execute("INSERT INTO replan_cases(case_key,queued_at) SELECT case_key,? FROM jobs WHERE id=? ON CONFLICT(case_key) DO NOTHING",params![now(),job])?;
            }
        }
        tx.commit()?;
    }
    s.set_meta("legacy-evidence-recheck-v3", "complete")?;
    Ok(total)
}

/// Current source ownership is separate from the globally shared observation.
pub fn current_case_links_on(c: &Connection, job_id: &str) -> Result<Vec<(String, String)>> {
    case_links_on(c, job_id, false)
}

fn dispatch_case_links_on(c: &Connection, job_id: &str) -> Result<Vec<(String, String)>> {
    case_links_on(c, job_id, true)
}

fn case_links_on(c: &Connection, job_id: &str, dispatch: bool) -> Result<Vec<(String, String)>> {
    let row: Option<(String, String, i64, String, String)> = c
        .query_row(
            "SELECT target,kind,round_seq,region,profile FROM jobs WHERE id=?",
            [job_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((target, kind, round, region, profile)) = row else {
        return Ok(vec![]);
    };
    let profile: Value = serde_json::from_str(&profile)?;
    let view = if profile["region_required"] == true || profile["region_required"] == 1 {
        region.as_str()
    } else {
        "any"
    };
    let logical = crate::work::logical_key(("", "", 0), &target, &kind, view, &profile);
    let rows = {
        let mut q=c.prepare_cached("SELECT c.key,c.fp,c.payload FROM job_cases l JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision WHERE l.job_id=? AND l.required_round_seq<=? AND c.active=1 AND c.status<>'decided'")?;
        q.query_map(params![job_id, round], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut out = vec![];
    for (key, fp, body) in rows {
        let mut p: Value = serde_json::from_str(&body)?;
        if dispatch {
            let Some(current) = crate::build_delta::current_case_payload_on(c, &key, &p)? else {
                continue;
            };
            p = current;
        }
        let Ok(demands) = crate::work::observation_demands(&p) else {
            continue;
        };
        if demands.iter().any(|d| {
            crate::work::logical_key(("", "", 0), &d.target, d.kind, &d.region, &d.profile)
                == logical
        }) {
            out.push((key, fp));
        }
    }
    Ok(out)
}

/// Consume a real send opportunity exactly once per persisted attempt. The
/// caller holds the write transaction; preparation alone never calls this.
pub fn consume_execution_on(c: &Connection, lease: &Lease) -> Result<bool> {
    consume_execution_impl(c, lease, true)
}

/// Accounting for an authenticated report of work that already happened.
/// This is not send admission: reusable facts cannot undo an actual execution.
pub(crate) fn consume_reported_execution_on(c: &Connection, lease: &Lease) -> Result<bool> {
    consume_execution_impl(c, lease, false)
}
fn consume_execution_impl(c: &Connection, lease: &Lease, admitting_send: bool) -> Result<bool> {
    let attempt = lease.profile["attempt_seq"].as_i64().unwrap_or(0);
    let history:Option<(Option<i64>,bool,Option<String>,i64)>=c.query_row("SELECT started_at,execution_refunded,execution_job_id,round_seq FROM lease_history WHERE job_id=? AND token_hash=? AND fp=? AND attempt_seq=?",params![lease.id,hash(&lease.token),lease.fingerprint,attempt],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((started, refunded, owner, history_round)) = history else {
        return Ok(false);
    };
    if refunded {
        return Ok(false);
    }
    let links = if admitting_send && started.is_none() {
        dispatch_case_links_on(c, &lease.id)?
    } else {
        current_case_links_on(c, &lease.id)?
    };
    if links.is_empty() {
        return Ok(false);
    }
    let valid:bool=c.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=? AND fp=? AND status='leased' AND lease_token=? AND attempt_seq=? AND round_seq=? AND lease_until>=?)",params![lease.id,lease.fingerprint,lease.token,attempt,history_round,now()],|r|r.get(0))?;
    if !valid {
        return Ok(false);
    }
    if started.is_some() {
        return Ok(true);
    }
    if admitting_send && crate::work::reuse_fresh_observation_on(c, &lease.id, Some(&lease.token))?
    {
        return Ok(false);
    }
    let owner = owner.unwrap_or_else(|| lease.id.clone());
    let round = lease.profile["round_seq"].as_i64().unwrap_or(history_round);
    let changed=c.execute("UPDATE jobs SET execution_count=execution_count+1 WHERE id=? AND round_seq=? AND execution_count<3",params![owner,round])?;
    if changed == 0 {
        return Ok(false);
    }
    c.execute("UPDATE lease_history SET started_at=?,execution_job_id=?,round_seq=? WHERE job_id=? AND token_hash=? AND attempt_seq=? AND started_at IS NULL AND execution_refunded=0",params![now(),owner,round,lease.id,hash(&lease.token),attempt])?;
    Ok(true)
}

/// Proven non-execution is an irreversible disposition of this attempt. The
/// same token cannot be charged again; uncertain sends never call this.
pub fn refund_execution_on(c: &Connection, lease: &Lease) -> Result<bool> {
    let attempt = lease.profile["attempt_seq"].as_i64().unwrap_or(0);
    let row:Option<(Option<i64>,bool,Option<String>,i64)>=c.query_row("SELECT started_at,execution_refunded,execution_job_id,round_seq FROM lease_history WHERE job_id=? AND token_hash=? AND fp=? AND attempt_seq=?",params![lease.id,hash(&lease.token),lease.fingerprint,attempt],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((started, refunded, owner, round)) = row else {
        return Ok(false);
    };
    if refunded {
        return Ok(false);
    }
    c.execute("UPDATE lease_history SET execution_refunded=1 WHERE job_id=? AND token_hash=? AND attempt_seq=? AND execution_refunded=0",params![lease.id,hash(&lease.token),attempt])?;
    if started.is_some() {
        c.execute(
            "UPDATE jobs SET execution_count=max(0,execution_count-1) WHERE id=? AND round_seq=?",
            params![owner.unwrap_or_else(|| lease.id.clone()), round],
        )?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_manual_dns_deadline_rechecks_current_demand_inside_the_write_transaction() {
        for discovery_first in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let store = Store::open(dir.path()).unwrap();
            let mut c = store.connect().unwrap();
            let discovery = json!({"kind":"target-discovery","targets":["shared.example"]});
            let manual = json!({"kind":"domain-observation","manual":true,"targets":["shared.example"],"regions":["any"]});
            let order = if discovery_first {
                [("discovery", &discovery), ("manual", &manual)]
            } else {
                [("manual", &manual), ("discovery", &discovery)]
            };
            for (key, payload) in order {
                c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,?,'shared.example','race fixture',?,'needs-active',1,?)",params![key,payload["kind"].as_str().unwrap(),payload.to_string(),now()]).unwrap();
                crate::work::plan_on(&c, key, "fp", payload).unwrap();
            }
            c.execute("UPDATE jobs SET status='complete',evidence_until=0", [])
                .unwrap();
            let selected: String = c
                .query_row("SELECT id FROM jobs", [], |r| r.get(0))
                .unwrap();
            // The candidate was valid before entering the writer. An intervening
            // manual edit cannot rely on its still-live discovery link to renew it.
            let tx = c
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            tx.execute("UPDATE cases SET active=0 WHERE key='manual'", [])
                .unwrap();
            tx.execute_batch("SAVEPOINT old_deadline;").unwrap();
            assert!(
                reopen_round_on(&tx, &selected, None, true).unwrap(),
                "negative control: a discovery link alone let the old generic gate reopen"
            );
            tx.execute_batch("ROLLBACK TO old_deadline;RELEASE old_deadline;")
                .unwrap();
            assert!(!reopen_dns_deadline_on(&tx, &selected).unwrap());
            tx.execute("UPDATE cases SET active=1,payload=json_set(payload,'$.regions',json('[\"us\"]')) WHERE key='manual'",[]).unwrap();
            assert!(!reopen_dns_deadline_on(&tx, &selected).unwrap());
            tx.execute(
                "UPDATE cases SET payload=? WHERE key='manual'",
                [manual.to_string()],
            )
            .unwrap();
            assert!(reopen_dns_deadline_on(&tx, &selected).unwrap());
        }
    }
}
