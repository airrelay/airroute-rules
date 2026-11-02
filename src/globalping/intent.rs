//! The durable boundary between a refundable reservation and a possibly sent POST.
//! A missing remote id after `sending` is deliberately never retried automatically.
use super::{Account, limits};
use crate::{
    now,
    store::{Lease, Store},
};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

pub const ACTIVE_LIMIT: i64 = 16;

pub fn migrate(store: &Store) -> Result<()> {
    if store.meta("gp-intent-v1")?.is_some() {
        return Ok(());
    }
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if tx.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='gp-intent-v1')",
        [],
        |r| r.get(0),
    )? {
        return Ok(());
    }
    let columns = {
        let mut q = tx.prepare("PRAGMA table_info(gp_remote)")?;
        q.query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (name, definition) in [
        ("attempt_seq", "INTEGER NOT NULL DEFAULT 0"),
        ("state", "TEXT NOT NULL DEFAULT 'legacy'"),
        ("reserved_hour", "INTEGER NOT NULL DEFAULT 0"),
        ("reserved_cost", "INTEGER NOT NULL DEFAULT 1"),
        ("provider_reset_at", "INTEGER NOT NULL DEFAULT 0"),
        ("send_started_at", "INTEGER"),
        ("slot_active", "INTEGER NOT NULL DEFAULT 1"),
    ] {
        if !columns.iter().any(|n| n == name) {
            tx.execute(
                &format!("ALTER TABLE gp_remote ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    // Old rows were persisted immediately before POST; an empty id is not proof
    // that nothing was sent. Keep the original lease/token and original ledger.
    let legacy = {
        let mut q =
            tx.prepare("SELECT job_id,remote_id,lease FROM gp_remote WHERE state='legacy'")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let history_seq: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('lease_history') WHERE name='attempt_seq')",
        [],
        |r| r.get(0),
    )?;
    for (job, remote, text) in legacy {
        let mut value: serde_json::Value = serde_json::from_str(&text)?;
        let seq = if history_seq {
            let token = value["token"].as_str().unwrap_or("");
            tx.query_row(
                "SELECT attempt_seq FROM lease_history WHERE job_id=? AND token_hash=?",
                params![job, crate::hash(token)],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(value["profile"]["attempt_seq"].as_i64().unwrap_or(0))
        } else {
            value["profile"]["attempt_seq"].as_i64().unwrap_or(0)
        };
        value["profile"]["attempt_seq"] = seq.into();
        let hour = value["profile"]["globalping_reserved_hour"]
            .as_i64()
            .unwrap_or((value["until"].as_i64().unwrap_or(180) - 180) / 3600);
        let cost = value["profile"]["globalping_reserved_tests"]
            .as_i64()
            .unwrap_or(1);
        tx.execute("UPDATE gp_remote SET state=?,attempt_seq=?,lease=?,reserved_hour=?,reserved_cost=?,slot_active=? WHERE job_id=? AND state='legacy'",params![if remote.is_empty(){"unknown"}else{"submitted"},seq,value.to_string(),hour,cost,!remote.is_empty(),job])?;
    }

    tx.execute_batch("CREATE TABLE IF NOT EXISTS gp_send_clock(account TEXT PRIMARY KEY,last_started_ms INTEGER NOT NULL); CREATE INDEX IF NOT EXISTS gp_known_poll ON gp_remote(next_poll,job_id) WHERE remote_id<>''; CREATE INDEX IF NOT EXISTS gp_prepared_account ON gp_remote(account,state,job_id); CREATE INDEX IF NOT EXISTS gp_active_slots ON gp_remote(slot_active) WHERE slot_active=1;")?;
    tx.execute("INSERT INTO meta VALUES('gp-intent-v1','complete')", [])?;
    tx.commit()?;
    Ok(())
}

fn attempt(lease: &Lease) -> i64 {
    lease.profile["attempt_seq"].as_i64().unwrap_or(0)
}

/// Runs inside the very same transaction that claims this logical job.
pub fn prepare_on(c: &Connection, a: &Account, lease: &Lease, cost: u32, at: i64) -> Result<bool> {
    let count: i64 = c.query_row(
        "SELECT count(*) FROM gp_remote WHERE slot_active=1",
        [],
        |r| r.get(0),
    )?;
    if count >= ACTIVE_LIMIT
        || c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM gp_remote WHERE job_id=?)",
            [&lease.id],
            |r| r.get(0),
        )?
    {
        return Ok(false);
    }
    let Some(hour) = limits::reserve_on(c, &a.id, cost, at)? else {
        return Ok(false);
    };
    let reset = limits::cached(c, &a.id)?
        .context("missing reserved quota")?
        .reset_at;
    let reset = if reset == 0 { at + 3600 } else { reset };
    let mut saved = lease.clone();
    saved.profile["globalping_reserved_tests"] = cost.into();
    saved.profile["globalping_reserved_hour"] = hour.into();
    let inserted = c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,account_snapshot,attempt_seq,state,reserved_hour,reserved_cost,provider_reset_at,slot_active) VALUES(?,?,'',?,?,?,?,'prepared',?,?,?,1) ON CONFLICT(job_id) DO NOTHING", params![lease.id,a.id,serde_json::to_string(&saved)?,at,serde_json::to_string(a)?,attempt(lease),hour,cost,reset])?;
    // The caller rolls the transaction back on false; this must not leave a debit.
    Ok(inserted == 1)
}

pub fn prepared(store: &Store, account: &str) -> Result<Option<Lease>> {
    let value: Option<String> = store.connect()?.query_row("SELECT lease FROM gp_remote WHERE account=? AND state='prepared' ORDER BY next_poll,job_id LIMIT 1", [account], |r| r.get(0)).optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}

fn matches(c: &Connection, lease: &Lease, state: &str) -> Result<bool> {
    Ok(c.query_row("SELECT EXISTS(SELECT 1 FROM gp_remote WHERE job_id=? AND attempt_seq=? AND state=? AND json_extract(lease,'$.token')=?)", params![lease.id,attempt(lease),state,lease.token], |r| r.get(0))?)
}

fn cancel_prepared_on(c: &Connection, lease: &Lease, at: i64) -> Result<bool> {
    if !matches(c, lease, "prepared")? {
        return Ok(false);
    }
    let (account, hour, cost): (String, i64, u32) = c.query_row(
        "SELECT account,reserved_hour,reserved_cost FROM gp_remote WHERE job_id=?",
        [&lease.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    if c.execute("DELETE FROM gp_remote WHERE job_id=? AND attempt_seq=? AND state='prepared' AND json_extract(lease,'$.token')=?", params![lease.id,attempt(lease),lease.token])? == 0 { return Ok(false); }
    limits::refund_on_at(c, &account, hour, cost, at)?;
    let current = !crate::jobs_v3::current_case_links_on(c, &lease.id)?.is_empty();
    c.execute("UPDATE jobs SET status=?,not_before=?,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND attempt_seq=? AND lease_token=? AND status='leased'",params![if current{"pending"}else{"obsolete"},at,lease.id,attempt(lease),lease.token])?;
    Ok(true)
}

pub fn cancel_prepared(store: &Store, lease: &Lease) -> Result<bool> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let changed = cancel_prepared_on(&tx, lease, now())?;
    tx.commit()?;
    Ok(changed)
}

/// Called after a fresh /limits response and immediately before handing the POST
/// to the HTTP client. From this commit onward a crash is an uncertain delivery.
pub fn begin_send(store: &Store, a: &Account, lease: &Lease, at: i64) -> Result<bool> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !matches(&tx, lease, "prepared")? {
        return Ok(false);
    }
    let current:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=? AND fp=? AND lease_token=? AND attempt_seq=? AND status='leased')",params![lease.id,lease.fingerprint,lease.token,attempt(lease)],|r|r.get(0))?;
    let current = current && !crate::jobs_v3::current_case_links_on(&tx, &lease.id)?.is_empty();
    let override_config: Option<(String, bool)> = tx
        .query_row(
            "SELECT config,deleted FROM gp_accounts WHERE id=?",
            [&a.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let account_current = override_config
        .map(|(v, deleted)| {
            !deleted
                && serde_json::from_str::<Account>(&v).is_ok_and(|v| {
                    v.enabled
                        && v.credential_ref == a.credential_ref
                        && v.token_env == a.token_env
                        && v.regions == a.regions
                })
        })
        .unwrap_or(a.enabled);
    let eligible_sql = format!(
        "SELECT EXISTS(SELECT 1 FROM jobs j JOIN nodes n ON n.id=j.lease_node WHERE j.id=? AND {})",
        crate::work::eligibility_sql("j", "n")
    );
    let eligible: bool = tx.query_row(&eligible_sql, [&lease.id], |r| r.get(0))?;
    if !current || !account_current || !eligible {
        cancel_prepared_on(&tx, lease, at)?;
        tx.commit()?;
        return Ok(false);
    }
    let (hour, cost): (i64, u32) = tx.query_row(
        "SELECT reserved_hour,reserved_cost FROM gp_remote WHERE job_id=?",
        [&lease.id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let state = limits::cached(&tx, &a.id)?.context("quota snapshot missing before send")?;
    let reserved_reset: i64 = tx.query_row(
        "SELECT provider_reset_at FROM gp_remote WHERE job_id=?",
        [&lease.id],
        |r| r.get(0),
    )?;
    if hour != at / 3600 || (reserved_reset > 0 && reserved_reset <= at) {
        // Only this provably unsent reservation may move; uncertain old charges stay.
        if reserved_reset > at {
            limits::release_hold_on(&tx, &a.id, cost, at)?;
        }
        tx.execute(
            "UPDATE gp_account_usage SET used=max(0,used-?) WHERE account=? AND bucket=?",
            params![cost, a.id, hour],
        )?;
        let Some(new_hour) = limits::reserve_on(&tx, &a.id, cost, at)? else {
            return Ok(false);
        };
        tx.execute("UPDATE gp_remote SET reserved_hour=?,provider_reset_at=?,lease=json_set(lease,'$.profile.globalping_reserved_hour',?) WHERE job_id=? AND attempt_seq=? AND state='prepared' AND json_extract(lease,'$.token')=?", params![new_hour,if state.reset_at==0{at+3600}else{state.reset_at},new_hour,lease.id,attempt(lease),lease.token])?;
    }
    // Second-granularity UTC buckets are for metering, not the actual-start
    // clock: floor(seconds)+5 could otherwise admit two starts <5s apart.
    let actual_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis()
        .min(i64::MAX as u128) as i64;
    let start_ms = actual_ms.max(at.saturating_mul(1000));
    let previous: Option<i64> = tx
        .query_row(
            "SELECT last_started_ms FROM gp_send_clock WHERE account=?",
            [&a.id],
            |r| r.get(0),
        )
        .optional()?;
    if previous
        .is_some_and(|previous| start_ms.saturating_sub(previous) < limits::MINIMUM_INTERVAL * 1000)
    {
        return Ok(false);
    }
    // A durable prepared intent owns this still-unsent attempt across a quota
    // wait; renew its lease before consuming the real execution opportunity.
    tx.execute("UPDATE jobs SET lease_until=? WHERE id=? AND attempt_seq=? AND lease_token=? AND status='leased'",params![at+180,lease.id,attempt(lease),lease.token])?;
    if !crate::jobs_v3::consume_execution_on(&tx, lease)? {
        cancel_prepared_on(&tx, lease, at)?;
        tx.commit()?;
        return Ok(false);
    }
    if !limits::mark_send_on(&tx, &a.id, cost, at)? {
        return Ok(false);
    }
    let changed = tx.execute("UPDATE gp_remote SET state='sending',send_started_at=?,next_poll=?,slot_active=1 WHERE job_id=? AND attempt_seq=? AND state='prepared' AND json_extract(lease,'$.token')=?", params![at,at+60,lease.id,attempt(lease),lease.token])?;
    if changed == 1 {
        tx.execute("INSERT INTO gp_send_clock VALUES(?,?) ON CONFLICT(account) DO UPDATE SET last_started_ms=excluded.last_started_ms",params![a.id,start_ms])?;
    }
    tx.commit()?;
    Ok(changed == 1)
}

/// Run once when starting a controller/runtime, never on a concurrent send tick.
pub fn recover_interrupted_sends(store: &Store) -> Result<usize> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let changed = tx.execute(
        "UPDATE gp_remote SET state='unknown',slot_active=0 WHERE state='sending' AND remote_id=''",
        [],
    )?;
    tx.execute("UPDATE jobs SET status='unknown' WHERE status='leased' AND EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id AND g.attempt_seq=jobs.attempt_seq AND json_extract(g.lease,'$.token')=jobs.lease_token AND g.state='unknown' AND g.remote_id='')", [])?;
    tx.commit()?;
    Ok(changed)
}

pub fn unknown(store: &Store, lease: &Lease) -> Result<()> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if tx.execute("UPDATE gp_remote SET state='unknown',slot_active=0 WHERE job_id=? AND attempt_seq=? AND json_extract(lease,'$.token')=? AND state='sending' AND remote_id=''", params![lease.id,attempt(lease),lease.token])? > 0 {
        tx.execute("UPDATE jobs SET status='unknown' WHERE id=? AND attempt_seq=? AND lease_token=?", params![lease.id,attempt(lease),lease.token])?;
    }
    tx.commit()?;
    Ok(())
}

pub fn submitted(store: &Store, lease: &Lease, remote: &str) -> Result<bool> {
    Ok(store.connect()?.execute("UPDATE gp_remote SET remote_id=?,state='submitted',next_poll=?,slot_active=1 WHERE job_id=? AND attempt_seq=? AND json_extract(lease,'$.token')=? AND state='sending' AND remote_id=''", params![remote,now()+5,lease.id,attempt(lease),lease.token])? == 1)
}

pub fn poll_later(store: &Store, lease: &Lease, at: i64) -> Result<()> {
    store.connect()?.execute("UPDATE gp_remote SET next_poll=? WHERE job_id=? AND attempt_seq=? AND json_extract(lease,'$.token')=? AND remote_id<>''", params![at,lease.id,attempt(lease),lease.token])?;
    Ok(())
}

pub fn finish(store: &Store, lease: &Lease) -> Result<bool> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let remote:Option<String>=tx.query_row("DELETE FROM gp_remote WHERE job_id=? AND attempt_seq=? AND json_extract(lease,'$.token')=? AND remote_id<>'' RETURNING remote_id",params![lease.id,attempt(lease),lease.token],|r|r.get(0)).optional()?;
    let Some(remote) = remote else {
        return Ok(false);
    };
    // Historical collection must release the old execution slot immediately.
    // Normal ingestion already completed/requeued its attempt; never touch that
    // state, another attempt/token, or an unrelated historical result.
    let historical:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM results WHERE id=? AND job_id=? AND attempt_seq=? AND accepted=0)",params![format!("globalping-{remote}"),lease.id,attempt(lease)],|r|r.get(0))?;
    if historical || crate::jobs_v3::current_case_links_on(&tx, &lease.id)?.is_empty() {
        tx.execute("UPDATE jobs SET status='obsolete',lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND attempt_seq=? AND lease_token=? AND status='leased'",params![lease.id,attempt(lease),lease.token])?;
    }
    tx.commit()?;
    store.wake.notify_waiters();
    Ok(true)
}

pub fn reject(store: &Store, lease: &Lease, retry_at: i64, retry: bool) -> Result<bool> {
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if !matches(&tx, lease, "sending")? {
        return Ok(false);
    }
    let (id, hour, cost): (String, i64, u32) = tx.query_row(
        "SELECT account,reserved_hour,reserved_cost FROM gp_remote WHERE job_id=?",
        [&lease.id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let changed=tx.execute("DELETE FROM gp_remote WHERE job_id=? AND attempt_seq=? AND state='sending' AND json_extract(lease,'$.token')=?",params![lease.id,attempt(lease),lease.token])?;
    if changed > 0 {
        crate::jobs_v3::refund_execution_on(&tx, lease)?;
        limits::refund_on(&tx, &id, hour, cost)?;
        tx.execute("UPDATE jobs SET status=?,not_before=?,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND lease_token=?",params![if retry{"pending"}else{"unknown"},retry_at,lease.id,lease.token])?;
    }
    tx.commit()?;
    Ok(changed > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Node;
    use serde_json::json;

    fn setup() -> (tempfile::TempDir, Store, Account) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        migrate(&s).unwrap();
        let a = Account {
            id: "fixture".into(),
            enabled: true,
            regions: std::collections::BTreeMap::from([("us".into(), "US".into())]),
            ..Default::default()
        };
        quota(&s, &a, now(), 500);
        (d, s, a)
    }
    fn quota(s: &Store, a: &Account, at: i64, remaining: u32) {
        let value = json!({"scope":"user","limit":500,"remaining":remaining,"provider_remaining":remaining,"reset_at":at+7200,"checked_at":at,"valid_until":at+7200,"next_refresh_at":at+60,"last_error":null});
        s.connect().unwrap().execute("INSERT INTO observation_cache VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET result=excluded.result,valid_until=excluded.valid_until",params![format!("globalping-auto-limits:{}",a.id),at+7200,value.to_string()]).unwrap();
    }
    fn claim(s: &Store, a: &Account, target: &str, at: i64) -> Option<Lease> {
        s.enqueue_observation(target, &["us".into()], "local durable-intent fixture")
            .unwrap();
        let n = Node {
            id: format!("globalping:{}:us", a.id),
            region: "us".into(),
            asn: 0,
            capabilities: vec!["dns".into(), "traceroute".into()],
        };
        s.register_node(&n, &crate::hash("public-fixture")).unwrap();
        crate::jobs_v3::lease_with_admission(s, &n, None, |tx, l| prepare_on(tx, a, l, 1, at))
            .unwrap()
    }
    fn used(s: &Store, a: &Account, hour: i64) -> i64 {
        s.connect().unwrap().query_row("SELECT coalesce((SELECT used FROM gp_account_usage WHERE account=? AND bucket=?),0)",params![a.id,hour],|r|r.get(0)).unwrap()
    }
    #[test]
    fn prepared_is_refundable_but_send_boundary_crash_is_not_retried_or_refunded() {
        let (_d, s, a) = setup();
        let at = now();
        let lease = claim(&s, &a, "crash.example", at).unwrap();
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            0,
            "prepared is not an execution"
        );
        assert_eq!(used(&s, &a, at / 3600), 1);
        assert!(begin_send(&s, &a, &lease, at).unwrap());
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            1
        );
        assert_eq!(recover_interrupted_sends(&s).unwrap(), 1);
        assert_eq!(recover_interrupted_sends(&s).unwrap(), 0);
        assert!(!begin_send(&s, &a, &lease, at + 3601).unwrap());
        assert!(!reject(&s, &lease, at, true).unwrap());
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            1,
            "unknown cannot refund an execution"
        );
        assert_eq!(used(&s, &a, at / 3600), 1);
        let c = s.connect().unwrap();
        let state: (String, i64) = c
            .query_row(
                "SELECT state,slot_active FROM gp_remote WHERE job_id=?",
                [&lease.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("unknown".into(), 0));
        assert!(claim(&s, &a, "crash.example", at + 3601).is_none());
    }
    #[test]
    fn prepared_cross_hour_transfer_is_atomic_and_idempotent() {
        let (_d, s, a) = setup();
        let old = now();
        let next = (old / 3600 + 1) * 3600 + 1;
        let lease = claim(&s, &a, "transfer.example", old).unwrap();
        // Mimic a fresh provider snapshot withholding this unsent reservation.
        quota(&s, &a, next, 499);
        assert!(begin_send(&s, &a, &lease, next).unwrap());
        assert_eq!(used(&s, &a, old / 3600), 0);
        assert_eq!(used(&s, &a, next / 3600), 1);
        assert!(!begin_send(&s, &a, &lease, next + 1).unwrap());
        assert_eq!(used(&s, &a, next / 3600), 1);
    }
    #[test]
    fn exhausted_provider_window_rolls_back_old_prepared_reservation_transfer() {
        let (_d, s, a) = setup();
        let old = now();
        let next = (old / 3600 + 1) * 3600 + 1;
        let lease = claim(&s, &a, "exhausted.example", old).unwrap();
        quota(&s, &a, next, 0);
        s.connect()
            .unwrap()
            .execute(
                "INSERT INTO gp_account_usage VALUES(?,?,999999,0)",
                params![a.id, next / 3600],
            )
            .unwrap();
        assert!(!begin_send(&s, &a, &lease, next).unwrap());
        assert_eq!(used(&s, &a, old / 3600), 1);
        assert_eq!(used(&s, &a, next / 3600), 999999);
        assert_eq!(prepared(&s, &a.id).unwrap().unwrap().token, lease.token);
    }
    #[test]
    fn actual_send_uses_provider_balance_even_after_more_than_four_hundred_tests() {
        let (_d, s, a) = setup();
        let at = now();
        s.connect()
            .unwrap()
            .execute(
                "INSERT INTO gp_account_usage VALUES(?,?,999999,0)",
                params![a.id, at / 3600],
            )
            .unwrap();
        let lease = claim(&s, &a, "provider-balance.example", at).unwrap();
        assert!(begin_send(&s, &a, &lease, at).unwrap());
        assert_eq!(used(&s, &a, at / 3600), 1_000_000);
        assert!(
            !begin_send(&s, &a, &lease, at + 1).unwrap(),
            "a second call must not send the same intent again"
        );
    }
    #[test]
    fn claim_and_intent_share_sixteen_slots_and_noop_cannot_replace_an_old_intent() {
        let (_d, s, a) = setup();
        let at = now();
        let mut b = a.clone();
        b.id = "second-account".into();
        quota(&s, &b, at, 500);
        let mut held = vec![];
        for i in 0..16 {
            held.push(
                claim(
                    &s,
                    if i % 2 == 0 { &a } else { &b },
                    &format!("slot-{i}.example"),
                    at,
                )
                .unwrap(),
            );
        }
        assert!(claim(&s, &a, "slot-extra.example", at).is_none());
        assert!(claim(&s, &b, "slot-extra-b.example", at).is_none());
        assert_eq!(used(&s, &a, at / 3600), 8);
        assert_eq!(used(&s, &b, at / 3600), 8);
        let mut c = s.connect().unwrap();
        let tx = c.transaction().unwrap();
        assert!(!prepare_on(&tx, &a, &held[0], 1, at).unwrap());
        drop(tx);
        let state: String = c
            .query_row(
                "SELECT lease FROM gp_remote WHERE job_id=?",
                [&held[0].id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Lease>(&state).unwrap().token,
            held[0].token
        );
    }
    #[test]
    fn late_attempt_cannot_terminate_or_refund_a_new_intent() {
        let (_d, s, a) = setup();
        let at = now();
        let lease = claim(&s, &a, "fence.example", at).unwrap();
        assert!(begin_send(&s, &a, &lease, at).unwrap());
        let mut old = lease.clone();
        old.profile["attempt_seq"] = json!(0);
        old.token = "old-token".into();
        assert!(!submitted(&s, &old, "old-id").unwrap());
        assert!(!finish(&s, &old).unwrap());
        assert!(!reject(&s, &old, at, true).unwrap());
        assert!(submitted(&s, &lease, "known-id").unwrap());
        assert!(!finish(&s, &old).unwrap());
        assert!(finish(&s, &lease).unwrap());
        assert!(!finish(&s, &lease).unwrap());
        assert_eq!(used(&s, &a, at / 3600), 1);
    }
    #[test]
    fn closed_case_cancels_only_provably_unsent_work() {
        let (_d, s, a) = setup();
        let at = now();
        let lease = claim(&s, &a, "closed.example", at).unwrap();
        s.connect()
            .unwrap()
            .execute(
                "UPDATE cases SET status='decided' WHERE key=?",
                [&lease.case_key],
            )
            .unwrap();
        assert!(!begin_send(&s, &a, &lease, at).unwrap());
        assert_eq!(used(&s, &a, at / 3600), 0);
        assert!(prepared(&s, &a.id).unwrap().is_none());
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
    }
    #[test]
    fn definite_nonexecution_refunds_the_execution_charge_exactly_once() {
        let (_d, s, a) = setup();
        let at = now();
        let lease = claim(&s, &a, "not-executed.example", at).unwrap();
        assert!(begin_send(&s, &a, &lease, at).unwrap());
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            1
        );
        assert!(reject(&s, &lease, at, true).unwrap());
        assert!(!reject(&s, &lease, at, true).unwrap());
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(used(&s, &a, at / 3600), 0);
    }
    #[test]
    fn old_intent_keeps_id_token_and_existing_attempt_namespace_on_repeat_migration() {
        let (_d, s, a) = setup();
        let at = now();
        let lease = claim(&s, &a, "legacy-inflight.example", at).unwrap();
        let mut old = lease.clone();
        old.profile.as_object_mut().unwrap().remove("attempt_seq");
        let c = s.connect().unwrap();
        c.execute("UPDATE gp_remote SET state='legacy',remote_id='existing-id',attempt_seq=0,lease=? WHERE job_id=?",params![serde_json::to_string(&old).unwrap(),lease.id]).unwrap();
        c.execute("DELETE FROM meta WHERE key='gp-intent-v1'", [])
            .unwrap();
        migrate(&s).unwrap();
        let row: (String, String, i64) = c
            .query_row(
                "SELECT remote_id,lease,attempt_seq FROM gp_remote WHERE job_id=?",
                [&lease.id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        let saved: Lease = serde_json::from_str(&row.1).unwrap();
        assert_eq!(row.0, "existing-id");
        assert_eq!(saved.id, lease.id);
        assert_eq!(saved.token, lease.token);
        assert_eq!(row.2, lease.profile["attempt_seq"].as_i64().unwrap());
        let before = c.total_changes();
        migrate(&s).unwrap();
        assert_eq!(before, c.total_changes());
        assert_eq!(used(&s, &a, at / 3600), 1);
    }
    #[test]
    fn disabling_an_account_refunds_only_its_prepared_work_and_retains_known_id() {
        let (_d, s, a) = setup();
        let at = now();
        let sent = claim(&s, &a, "sent-before-disable.example", at).unwrap();
        let unsent = claim(&s, &a, "prepared-before-disable.example", at).unwrap();
        assert!(begin_send(&s, &a, &sent, at).unwrap());
        assert!(submitted(&s, &sent, "paid-existing-id").unwrap());
        let mut disabled = a.clone();
        disabled.enabled = false;
        s.connect()
            .unwrap()
            .execute(
                "INSERT INTO gp_accounts(id,config,deleted) VALUES(?,?,0)",
                params![a.id, serde_json::to_string(&disabled).unwrap()],
            )
            .unwrap();
        assert!(!begin_send(&s, &a, &unsent, at + 30).unwrap());
        let c = s.connect().unwrap();
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT count(*) FROM gp_remote WHERE state='prepared'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            c.query_row::<String, _, _>(
                "SELECT remote_id FROM gp_remote WHERE job_id=?",
                [&sent.id],
                |r| r.get(0)
            )
            .unwrap(),
            "paid-existing-id"
        );
        assert_eq!(used(&s, &a, at / 3600), 1);
    }
}
