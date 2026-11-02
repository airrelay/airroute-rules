//! Provider-authoritative free hourly allowance. Credits never increase admission.
use super::{Account, Config};
use crate::{now, store::Store};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, header::HeaderMap};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MINIMUM_INTERVAL: i64 = 5;
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub scope: String,
    pub limit: u32,
    pub remaining: u32,
    /// Raw provider balance before local reservations; old cached snapshots remain readable.
    #[serde(default)]
    pub provider_remaining: Option<u32>,
    pub reset_at: i64,
    pub checked_at: i64,
    pub valid_until: i64,
    pub next_refresh_at: i64,
    pub last_error: Option<String>,
}
fn key(id: &str) -> String {
    format!("globalping-auto-limits:{id}")
}
pub fn cached(c: &Connection, id: &str) -> Result<Option<State>> {
    let value: Option<String> = c
        .query_row(
            "SELECT result FROM observation_cache WHERE key=?",
            [key(id)],
            |r| r.get(0),
        )
        .optional()?;
    value
        .map(|v| serde_json::from_str(&v).map_err(Into::into))
        .transpose()
}
fn save(c: &Connection, id: &str, state: &State) -> Result<()> {
    c.execute("INSERT INTO observation_cache VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET valid_until=excluded.valid_until,result=excluded.result", params![key(id),state.valid_until,serde_json::to_string(state)?])?;
    Ok(())
}
pub fn invalidate(c: &Connection, id: &str) -> Result<()> {
    c.execute("DELETE FROM observation_cache WHERE key=?", [key(id)])?;
    Ok(())
}
pub fn pause(s: &Store, id: &str, seconds: i64) -> Result<()> {
    s.connect()?.execute("INSERT INTO gp_account_usage VALUES(?,?,0,?) ON CONFLICT(account,bucket) DO UPDATE SET blocked_until=max(blocked_until,excluded.blocked_until)",params![id,now()/3600,now()+seconds.clamp(1,86400)])?;
    Ok(())
}
pub fn blocked_until(c: &Connection, id: &str) -> Result<i64> {
    Ok(c.query_row(
        "SELECT coalesce(max(blocked_until),0) FROM gp_account_usage WHERE account=?",
        [id],
        |r| r.get(0),
    )?)
}
fn valid_at(state: &State, at: i64) -> bool {
    state.valid_until > at
        && state.last_error.is_none()
        && (state.reset_at == 0 || state.reset_at > at)
}
fn used_at(c: &Connection, id: &str, at: i64) -> Result<u32> {
    Ok(c.query_row(
        "SELECT coalesce((SELECT used FROM gp_account_usage WHERE account=? AND bucket=?),0)",
        params![id, at / 3600],
        |r| r.get::<_, i64>(0),
    )?
    .clamp(0, i64::from(u32::MAX)) as u32)
}
pub fn ready_at(c: &Connection, id: &str, cost: u32, at: i64) -> Result<bool> {
    Ok(cost > 0
        && blocked_until(c, id)? <= at
        && cached(c, id)?.is_some_and(|s| valid_at(&s, at) && s.remaining >= cost))
}
pub fn ready(c: &Connection, id: &str, cost: u32) -> Result<bool> {
    ready_at(c, id, cost, now())
}
// Only unconfirmed reservations must be withheld from a newly fetched provider
// balance. A known remote ID is already reflected in that authoritative balance.
fn held_at(c: &Connection, id: &str, at: i64) -> Result<u32> {
    let has_state: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('gp_remote') WHERE name='state')",
        [],
        |r| r.get(0),
    )?;
    if !has_state {
        return Ok(0);
    }
    Ok(c.query_row(
        "SELECT coalesce(sum(reserved_cost),0) FROM gp_remote WHERE account=? AND state IN ('prepared','sending','unknown') AND (provider_reset_at>? OR (provider_reset_at=0 AND reserved_hour=?))",
        params![id, at, at / 3600], |r| r.get::<_, i64>(0),
    )?.clamp(0, i64::from(u32::MAX)) as u32)
}
fn with_holds(c: &Connection, id: &str, mut state: State, at: i64) -> Result<State> {
    let raw = state.provider_remaining.unwrap_or(state.remaining);
    state.provider_remaining = Some(raw);
    state.remaining = raw.saturating_sub(held_at(c, id, at)?);
    Ok(state)
}
fn reset_time(reset: i64, limit: u32, remaining: u32) -> i64 {
    if reset == 0 && remaining == limit {
        0
    } else {
        now() + reset.max(1)
    }
}
fn parse(data: &Value) -> Result<State> {
    let v = &data["rateLimit"]["measurements"]["create"];
    let scope = v["type"]
        .as_str()
        .context("Globalping missing quota scope")?;
    ensure!(
        matches!(scope, "user" | "ip"),
        "unknown Globalping quota scope"
    );
    let limit = u32::try_from(
        v["limit"]
            .as_u64()
            .context("Globalping missing hourly limit")?,
    )?;
    ensure!(limit > 0, "invalid Globalping hourly limit");
    let remaining = u32::try_from(
        v["remaining"]
            .as_u64()
            .context("Globalping missing free balance")?,
    )?
    .min(limit);
    let reset = v["reset"]
        .as_i64()
        .context("Globalping missing reset interval")?;
    ensure!(
        (0..=86400).contains(&reset),
        "invalid Globalping reset interval"
    );
    Ok(State {
        scope: scope.into(),
        limit,
        remaining,
        provider_remaining: Some(remaining),
        reset_at: reset_time(reset, limit, remaining),
        checked_at: now(),
        valid_until: now() + 60,
        next_refresh_at: now() + 60,
        last_error: None,
    })
}
pub async fn refresh(
    s: &Store,
    config: &Config,
    a: &Account,
    client: &Client,
    token: &str,
    force: bool,
) -> Result<()> {
    if !force
        && cached(&s.connect()?, &a.id)?
            .is_some_and(|v| v.next_refresh_at > now() && (v.reset_at == 0 || v.reset_at > now()))
    {
        return Ok(());
    }
    let result: Result<State> = async {
        let response = client
            .get(format!("{}/limits", config.base_url.trim_end_matches('/')))
            .bearer_auth(token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            pause(s, &a.id, super::retry_after(response.headers()))?;
        }
        let data: Value = response.error_for_status()?.json().await?;
        parse(&data)
    }
    .await;
    match result {
        Ok(state) => {
            let c = s.connect()?;
            let state = with_holds(&c, &a.id, state, now())?;
            save(&c, &a.id, &state)?;
            Ok(())
        }
        Err(e) => {
            let mut state = cached(&s.connect()?, &a.id)?.unwrap_or_default();
            state.last_error = Some(e.to_string());
            state.valid_until = 0;
            state.next_refresh_at = now() + 60;
            save(&s.connect()?, &a.id, &state)?;
            Err(e)
        }
    }
}
/// Reserve inside the caller's claim/intent transaction. Reservation never
/// grants permission to send and does not start the actual-send spacing clock.
pub fn reserve_on(c: &Connection, id: &str, cost: u32, at: i64) -> Result<Option<i64>> {
    if !ready_at(c, id, cost, at)? {
        return Ok(None);
    }
    let mut state = cached(c, id)?.context("quota snapshot missing")?;
    if state.provider_remaining.is_none() {
        state.provider_remaining = Some(state.remaining);
    }
    state.remaining -= cost;
    save(c, id, &state)?;
    let hour = at / 3600;
    c.execute("INSERT INTO gp_account_usage VALUES(?,?,?,0) ON CONFLICT(account,bucket) DO UPDATE SET used=used+excluded.used", params![id,hour,cost])?;
    Ok(Some(hour))
}
/// Recheck immediately before entering the network-send boundary. The caller
/// holds the write transaction and its own reservation is already included.
pub fn mark_send_on(c: &Connection, id: &str, cost: u32, at: i64) -> Result<bool> {
    let Some(state) = cached(c, id)? else {
        return Ok(false);
    };
    let held = held_at(c, id, at)?;
    let raw = state.provider_remaining.unwrap_or(state.limit);
    let usable = if held >= cost {
        // Remove only this intent's own hold. Saturating remaining+cost would
        // incorrectly admit when other unknown intents already exhaust raw.
        raw.saturating_sub(held - cost)
    } else {
        // Compatibility callers may reserve without an intent row.
        state.remaining.saturating_add(cost).min(raw)
    };
    if cost == 0
        || !valid_at(&state, at)
        || blocked_until(c, id)? > at
        || usable < cost
        || used_at(c, id, at)? < cost
    {
        return Ok(false);
    }
    let window = if state.reset_at == 0 {
        3600
    } else {
        (state.reset_at - at).max(1)
    };
    let spacing = MINIMUM_INTERVAL.max(window * i64::from(cost) / i64::from(usable.max(1)));
    c.execute("INSERT INTO gp_account_usage VALUES(?,?,0,?) ON CONFLICT(account,bucket) DO UPDATE SET blocked_until=max(blocked_until,excluded.blocked_until)", params![id,at/3600,at+spacing])?;
    Ok(true)
}
// Compatibility convenience for callers that reserve and send in one step.
#[cfg(test)]
pub fn reserve(s: &Store, id: &str, cost: u32) -> Result<Option<i64>> {
    let mut c = s.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let at = now();
    let Some(hour) = reserve_on(&tx, id, cost, at)? else {
        return Ok(None);
    };
    if !mark_send_on(&tx, id, cost, at)? {
        return Ok(None);
    }
    tx.commit()?;
    Ok(Some(hour))
}
/// Caller must fence the intent before refunding; this operation alone is not
/// an idempotency key. Old-window local charges are kept separate from current
/// provider balances and never create new allowance after a reset.
/// Restore this prepared intent's hold before re-reserving it in a new local
/// hour. Caller must know the old hold is still included and fence the intent.
/// This does not refund ledger usage or authorize a network send.
pub fn release_hold_on(c: &Connection, id: &str, cost: u32, at: i64) -> Result<()> {
    if let Some(mut state) = cached(c, id)?
        && valid_at(&state, at)
    {
        state.remaining = state
            .remaining
            .saturating_add(cost)
            .min(state.provider_remaining.unwrap_or(state.limit));
        save(c, id, &state)?;
    }
    Ok(())
}
pub fn refund_on_at(c: &Connection, id: &str, hour: i64, cost: u32, at: i64) -> Result<()> {
    c.execute(
        "UPDATE gp_account_usage SET used=max(0,used-?) WHERE account=? AND bucket=?",
        params![cost, id, hour],
    )?;
    if hour == at / 3600
        && let Some(mut state) = cached(c, id)?
        && valid_at(&state, at)
    {
        state.remaining = state
            .remaining
            .saturating_add(cost)
            .min(state.provider_remaining.unwrap_or(state.limit));
        save(c, id, &state)?;
    }
    Ok(())
}
pub fn refund_on(c: &Connection, id: &str, hour: i64, cost: u32) -> Result<()> {
    refund_on_at(c, id, hour, cost, now())
}
#[cfg(test)]
pub fn refund(s: &Store, id: &str, hour: i64, cost: u32) -> Result<()> {
    let mut c = s.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    refund_on(&tx, id, hour, cost)?;
    tx.commit()?;
    Ok(())
}
#[cfg(test)]
pub fn observe_headers(s: &Store, id: &str, headers: &HeaderMap) -> Result<()> {
    observe_headers_from(s, id, headers, now())
}
/// An older asynchronous POST response must not overwrite a newer /limits
/// snapshot. Credit-consumption warnings are still processed independently.
pub fn observe_headers_from(
    s: &Store,
    id: &str,
    headers: &HeaderMap,
    request_started_at: i64,
) -> Result<()> {
    let num = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u32>().ok())
    };
    if let (Some(limit), Some(remaining), Some(reset)) = (
        num("x-ratelimit-limit"),
        num("x-ratelimit-remaining"),
        num("x-ratelimit-reset"),
    ) && cached(&s.connect()?, id)?.is_none_or(|state| state.checked_at <= request_started_at)
    {
        ensure!(
            limit > 0 && reset <= 86400,
            "invalid Globalping limit headers"
        );
        let mut state = cached(&s.connect()?, id)?.unwrap_or_default();
        state.limit = limit;
        state.remaining = remaining.min(limit);
        state.provider_remaining = Some(state.remaining);
        state.reset_at = reset_time(i64::from(reset), limit, remaining.min(limit));
        state.checked_at = now();
        state.valid_until = now() + 60;
        state.next_refresh_at = now() + 60;
        state.last_error = None;
        let c = s.connect()?;
        let state = with_holds(&c, id, state, now())?;
        save(&c, id, &state)?;
    }
    if num("x-credits-consumed").is_some_and(|v| v > 0) {
        let mut state = cached(&s.connect()?, id)?.unwrap_or_default();
        state.remaining = 0;
        state.last_error =
            Some("Provider consumed credits; new submissions paused until quota refresh".into());
        pause(s, id, (state.reset_at - now()).max(60))?;
        save(&s.connect()?, id, &state)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn state(limit: u32, remaining: u32) -> State {
        parse(&json!({"rateLimit":{"measurements":{"create":{"type":"user","limit":limit,"remaining":remaining,"reset":900}}},"credits":{"remaining":100000}})).unwrap()
    }
    #[test]
    fn zero_seconds_with_an_exhausted_window_triggers_a_near_term_refresh() {
        assert_eq!(reset_time(0, 500, 500), 0);
        let end = reset_time(0, 500, 0);
        assert!(end > now() && end <= now() + 1);
    }
    #[test]
    fn reservations_obey_provider_balance_and_ignore_local_audit_totals() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        save(&c, "one", &state(5, 5)).unwrap();
        save(&c, "two", &state(5, 5)).unwrap();
        c.execute(
            "INSERT INTO gp_account_usage VALUES('one',?,999999,0)",
            [now() / 3600],
        )
        .unwrap();
        assert!(reserve(&s, "one", 3).unwrap().is_some());
        assert_eq!(used_at(&c, "one", now()).unwrap(), 1_000_002);
        let next = blocked_until(&c, "one").unwrap();
        assert!(next >= now() + 5);
        c.execute(
            "UPDATE gp_account_usage SET blocked_until=0 WHERE account='one'",
            [],
        )
        .unwrap();
        assert!(reserve(&s, "one", 3).unwrap().is_none());
        assert!(reserve(&s, "two", 3).unwrap().is_some());
        assert_eq!(cached(&c, "one").unwrap().unwrap().remaining, 2);
    }
    #[test]
    fn refund_and_headers_calibrate_without_granting_balance_after_a_rejection() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        save(&c, "one", &state(5, 5)).unwrap();
        let hour = reserve(&s, "one", 1).unwrap().unwrap();
        refund(&s, "one", hour, 1).unwrap();
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-ratelimit-limit", "5"),
            ("x-ratelimit-remaining", "0"),
            ("x-ratelimit-reset", "20"),
        ] {
            h.insert(k, v.parse().unwrap());
        }
        observe_headers(&s, "one", &h).unwrap();
        assert_eq!(cached(&c, "one").unwrap().unwrap().remaining, 0);
        assert!(!ready(&c, "one", 1).unwrap());
        assert!(cached(&c, "one").unwrap().unwrap().reset_at <= now() + 20);
        // A stale snapshot must not turn into a fresh allowance at the local hour boundary.
        let mut stale = state(5, 5);
        stale.reset_at = now() - 1;
        save(&c, "one", &stale).unwrap();
        assert!(!ready(&c, "one", 1).unwrap());
    }
    fn state_at(at: i64, remaining: u32, reset_at: i64) -> State {
        State {
            scope: "user".into(),
            limit: 500,
            remaining,
            provider_remaining: Some(remaining),
            reset_at,
            checked_at: at,
            valid_until: at + 60,
            next_refresh_at: at + 60,
            last_error: None,
        }
    }
    #[test]
    fn delayed_post_headers_cannot_raise_a_newer_provider_balance_snapshot() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let mut newer = state_at(now(), 498, now() + 3600);
        newer.checked_at = now() + 10;
        save(&c, "one", &newer).unwrap();
        let mut h = HeaderMap::new();
        for (k, v) in [
            ("x-ratelimit-limit", "500"),
            ("x-ratelimit-remaining", "499"),
            ("x-ratelimit-reset", "3600"),
        ] {
            h.insert(k, v.parse().unwrap());
        }
        observe_headers_from(&s, "one", &h, now()).unwrap();
        assert_eq!(cached(&c, "one").unwrap().unwrap().remaining, 498);
    }
    #[test]
    fn provider_allowance_can_exceed_four_hundred_and_utc_rollover_grants_nothing() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200 + 3599;
        save(&c, "one", &state_at(at, 500, at + 3600)).unwrap();
        save(&c, "two", &state_at(at, 500, at + 3600)).unwrap();
        assert!(reserve_on(&c, "one", 400, at).unwrap().is_some());
        assert!(reserve_on(&c, "one", 100, at).unwrap().is_some());
        assert!(reserve_on(&c, "one", 1, at).unwrap().is_none());
        assert!(reserve_on(&c, "two", 500, at).unwrap().is_some());
        // A UTC audit boundary never replenishes the provider's free balance.
        save(&c, "one", &state_at(at + 1, 0, at + 3600)).unwrap();
        assert!(reserve_on(&c, "one", 1, at + 1).unwrap().is_none());
        assert_eq!(used_at(&c, "one", at).unwrap(), 500);
        assert_eq!(used_at(&c, "one", at + 1).unwrap(), 0);
        // Only a valid fresh provider balance authorizes further reservations.
        save(&c, "one", &state_at(at + 1, 50, at + 3600)).unwrap();
        assert!(reserve_on(&c, "one", 50, at + 1).unwrap().is_some());
        assert_eq!(
            blocked_until(&c, "one").unwrap(),
            0,
            "reservation is not send permission"
        );
    }
    #[test]
    fn send_spacing_is_actual_start_based_and_can_extend_beyond_five_seconds() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200;
        save(&c, "one", &state_at(at, 500, at + 100)).unwrap();
        reserve_on(&c, "one", 1, at).unwrap().unwrap();
        reserve_on(&c, "one", 1, at).unwrap().unwrap();
        assert!(mark_send_on(&c, "one", 1, at).unwrap());
        assert!(!mark_send_on(&c, "one", 1, at + 4).unwrap());
        assert!(mark_send_on(&c, "one", 1, at + 5).unwrap());
        save(&c, "two", &state_at(at, 2, at + 100)).unwrap();
        reserve_on(&c, "two", 1, at).unwrap().unwrap();
        assert!(mark_send_on(&c, "two", 1, at).unwrap());
        assert_eq!(blocked_until(&c, "two").unwrap(), at + 50);
    }
    #[test]
    fn final_send_checks_raw_provider_zero_even_with_an_existing_reservation() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200;
        save(&c, "one", &state_at(at, 500, at + 3600)).unwrap();
        reserve_on(&c, "one", 1, at).unwrap().unwrap();
        // Another client exhausted the provider's balance before this write.
        save(&c, "one", &state_at(at, 0, at + 3600)).unwrap();
        assert!(!mark_send_on(&c, "one", 1, at).unwrap());
        assert_eq!(used_at(&c, "one", at).unwrap(), 1);
    }
    #[test]
    fn old_bucket_refund_does_not_credit_a_new_provider_window() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200;
        save(&c, "one", &state_at(at, 100, at + 3600)).unwrap();
        reserve_on(&c, "one", 3, at).unwrap().unwrap();
        let next = at + 3600;
        save(&c, "one", &state_at(next, 2, next + 3600)).unwrap();
        refund_on_at(&c, "one", at / 3600, 3, next).unwrap();
        assert_eq!(cached(&c, "one").unwrap().unwrap().remaining, 2);
        assert_eq!(used_at(&c, "one", at).unwrap(), 0);
        assert!(reserve_on(&c, "one", 3, next).unwrap().is_none());
    }
    #[test]
    fn refresh_subtracts_only_unconfirmed_holds_in_their_own_window() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200;
        for (name, definition) in [
            ("state", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("reserved_cost", "INTEGER NOT NULL DEFAULT 1"),
            ("reserved_hour", "INTEGER NOT NULL DEFAULT 0"),
            ("provider_reset_at", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('gp_remote') WHERE name=?)",
                    [name],
                    |r| r.get(0),
                )
                .unwrap();
            if !exists {
                c.execute(
                    &format!("ALTER TABLE gp_remote ADD COLUMN {name} {definition}"),
                    [],
                )
                .unwrap();
            }
        }
        for (id, state, cost, end, hour) in [
            ("prepared", "prepared", 2, at + 3600, 2),
            ("uncertain", "unknown", 3, at + 3600, 2),
            ("known", "submitted", 7, at + 3600, 2),
            ("old", "unknown", 11, at - 1, 1),
        ] {
            c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state,reserved_cost,reserved_hour,provider_reset_at) VALUES(?,'one','remote','{}',0,?,?,?,?)",params![id,state,cost,hour,end]).unwrap();
        }
        let effective = with_holds(&c, "one", state_at(at, 10, at + 3600), at).unwrap();
        assert_eq!(effective.remaining, 5);
        assert_eq!(effective.provider_remaining, Some(10));
        let oversubscribed = with_holds(&c, "one", state_at(at, 1, at + 3600), at).unwrap();
        save(&c, "one", &oversubscribed).unwrap();
        c.execute(
            "INSERT INTO gp_account_usage VALUES('one',?,5,0)",
            [at / 3600],
        )
        .unwrap();
        assert!(
            !mark_send_on(&c, "one", 2, at).unwrap(),
            "other unknown holds cannot be released as our own balance"
        );
    }
    #[test]
    fn a_prepared_hold_can_move_utc_buckets_without_debiting_provider_twice() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = s.connect().unwrap();
        let at = 7200 + 3599;
        save(&c, "one", &state_at(at, 10, at + 3600)).unwrap();
        reserve_on(&c, "one", 2, at).unwrap().unwrap();
        // Fresh quota minus the old still-active provider-window reservation.
        let next = at + 1;
        let mut current = state_at(next, 10, at + 3600);
        current.remaining = 8;
        save(&c, "one", &current).unwrap();
        c.execute(
            "UPDATE gp_account_usage SET used=used-2 WHERE account='one' AND bucket=?",
            [at / 3600],
        )
        .unwrap();
        release_hold_on(&c, "one", 2, next).unwrap();
        reserve_on(&c, "one", 2, next).unwrap().unwrap();
        assert_eq!(cached(&c, "one").unwrap().unwrap().remaining, 8);
        assert_eq!(used_at(&c, "one", at).unwrap(), 0);
        assert_eq!(used_at(&c, "one", next).unwrap(), 2);
    }
    #[tokio::test]
    async fn idle_refresh_is_cached_but_pre_submission_queries_always_recheck_the_provider() {
        use axum::{Json, Router, routing::get};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let count = Arc::new(AtomicUsize::new(0));
        let next = count.clone();
        let app=Router::new().route("/limits",get(move||{let next=next.clone();async move{let n=next.fetch_add(1,Ordering::SeqCst);Json(json!({"rateLimit":{"measurements":{"create":{"type":"user","limit":7,"remaining":if n==0{7}else{0},"reset":20}}},"credits":{"remaining":10000}}))}}));
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            base_url: format!("http://{}", socket.local_addr().unwrap()),
            accounts: vec![],
        };
        let task = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let a = Account {
            id: "one".into(),
            ..Default::default()
        };
        let client = Client::new();
        refresh(&s, &config, &a, &client, "fixture", false)
            .await
            .unwrap();
        refresh(&s, &config, &a, &client, "fixture", false)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
        refresh(&s, &config, &a, &client, "fixture", true)
            .await
            .unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert!(
            !ready(&s.connect().unwrap(), "one", 1).unwrap(),
            "credits cannot substitute for free hourly balance"
        );
        task.abort();
    }
    #[tokio::test]
    async fn missing_limits_endpoint_fails_closed_and_exposes_the_query_error() {
        use axum::Router;
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            base_url: format!("http://{}", socket.local_addr().unwrap()),
            accounts: vec![],
        };
        let task = tokio::spawn(async move { axum::serve(socket, Router::new()).await.unwrap() });
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let a = Account {
            id: "one".into(),
            ..Default::default()
        };
        assert!(
            refresh(&s, &config, &a, &Client::new(), "fixture", true)
                .await
                .is_err()
        );
        assert!(!ready(&s.connect().unwrap(), "one", 1).unwrap());
        assert!(
            cached(&s.connect().unwrap(), "one")
                .unwrap()
                .unwrap()
                .last_error
                .is_some()
        );
        task.abort();
    }
}
