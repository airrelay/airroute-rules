use airroute_rules::{
    hash,
    measure::{self, ProbeConfig, ResolverConfig},
    now, server,
    store::{CaseInput, Node, ProbeResult, Store},
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tower::ServiceExt;

fn node(id: &str, region: &str, asn: u32) -> Node {
    Node {
        id: id.into(),
        region: region.into(),
        asn,
        capabilities: vec!["dns".into(), "traceroute".into()],
    }
}
fn case(fp: &str) -> CaseInput {
    CaseInput {
        key: "case-a".into(),
        fingerprint: fp.into(),
        kind: "geolocation".into(),
        subject: "1.1.1.0/24".into(),
        reason: "independent sources disagree".into(),
        payload: json!({"kind":"geolocation","family":4,"regions":["us","europe"],"ranges":[["1.1.1.0","1.1.1.255"]],"targets":[]}),
    }
}
fn commit(s: &Store, cases: &[CaseInput]) -> Value {
    let id = s.start_build().unwrap();
    s.commit_build(&id, "verified-release", &json!({}), cases, &[])
        .unwrap()
}
fn result(l: &airroute_rules::store::Lease) -> ProbeResult {
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: if l.kind == "dns" {
            json!({"kind":"dns","hostname":l.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":now(),"valid_until":now()+60,"records":[{"name":l.target,"type":"A","ttl":60,"data":"1.1.1.1"}]}]})
        } else {
            json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":l.target}]})
        },
    }
}
#[test]
fn unchanged_targets_and_source_changes_reuse_the_same_inflight_observation() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("v1");
    assert_eq!(commit(&s, std::slice::from_ref(&c))["new"], 1);
    let n = node("us-1", "us", 64501);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET connected=1,last_seen=?", [now()])
        .unwrap();
    assert!(s.lease(&n).unwrap().is_none());
    assert!(
        s.targets(&c.key, &c.fingerprint, &["8.8.8.8".into()])
            .is_err()
    );
    assert_eq!(
        s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
            .unwrap(),
        1
    );
    assert_eq!(commit(&s, std::slice::from_ref(&c))["reused"], 1);
    assert_eq!(
        s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
            .unwrap(),
        0
    );
    let lease = s.lease(&n).unwrap().unwrap();
    let r = result(&lease);
    commit(&s, &[case("v2")]);
    airroute_rules::work::refresh(&s).unwrap();
    assert_eq!(
        s.submit(&n.id, &r).unwrap()["accepted"],
        true,
        "the same precise target and method remain linked to the latest source scope"
    );
    assert_eq!(s.submit(&n.id, &r).unwrap()["duplicate"], true);
    let mut forged = r.clone();
    forged.id = uuid::Uuid::new_v4().to_string();
    forged.lease_token = "not-the-issued-attempt-token".into();
    assert!(s.submit(&n.id, &forged).is_err());
    assert_eq!(
        s.meta("current-release").unwrap().as_deref(),
        Some("verified-release")
    );
}

#[test]
fn a_changed_range_cannot_reuse_an_old_target_outside_the_new_scope() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let initial = case("before-range-change");
    commit(&s, std::slice::from_ref(&initial));
    s.targets(&initial.key, &initial.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let n = node("scope-fixture", "us", 64501);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    let old = s.lease(&n).unwrap().unwrap();
    let mut current = case("after-range-change");
    current.subject = "1.1.1.128/25".into();
    current.payload["ranges"] = json!([["1.1.1.128", "1.1.1.255"]]);
    commit(&s, &[current]);
    airroute_rules::work::refresh(&s).unwrap();
    let receipt = result(&old);
    assert_eq!(s.submit(&n.id, &receipt).unwrap()["historical_only"], true);
    assert_eq!(s.submit(&n.id, &receipt).unwrap()["duplicate"], true);
    assert!(
        !s.connect()
            .unwrap()
            .query_row::<bool, _, _>(
                "SELECT accepted FROM results WHERE id=? AND job_id=?",
                rusqlite::params![receipt.id, old.id],
                |r| r.get(0),
            )
            .unwrap(),
        "the authenticated late receipt remains historical even after its case link is removed"
    );
    assert!(
        airroute_rules::jobs_v3::current_case_links_on(&s.connect().unwrap(), &old.id)
            .unwrap()
            .is_empty(),
        "preserved target history is not a current observation requirement outside the new range"
    );
    assert!(
        s.lease(&n).unwrap().is_none(),
        "the old target cannot be dispatched again for the changed range"
    );
}
#[test]
fn single_observation_idempotence_and_expired_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    s.enqueue_observation("example.com", &["us".into()], "resolver comparison")
        .unwrap();
    let a = node("a", "us", 64501);
    let b = node("b", "us", 64501);
    let c = node("c", "us", 64502);
    for n in [&a, &b, &c] {
        s.register_node(n, "fixture-token-longer-than-24-characters")
            .unwrap();
    }
    let first = s.lease(&a).unwrap().unwrap();
    assert!(s.lease(&b).unwrap().is_none());
    assert!(s.lease(&a).unwrap().is_none());
    s.enqueue_observation("second.example", &["us".into()], "separate observation")
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,session_id='session-c' WHERE id=?",
            rusqlite::params![now(), c.id],
        )
        .unwrap();
    let other = s.lease_session(&c, "session-c").unwrap().unwrap();
    assert!(s.begin_execution(&c.id, "session-c", &other).unwrap());
    assert!(
        s.heartbeat(&c.id, "session-c", &other.id, &other.token)
            .unwrap()
    );
    assert_ne!(first.id, other.id);
    let r = result(&first);
    assert_eq!(s.submit(&a.id, &r).unwrap()["accepted"], true);
    let mut collision = r.clone();
    collision.outcome = "error".into();
    assert!(s.submit(&a.id, &collision).is_err());
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET lease_until=0 WHERE id=?", [&other.id])
        .unwrap();
    assert!(
        !s.heartbeat(&c.id, "session-c", &other.id, &other.token)
            .unwrap(),
        "a late heartbeat must not resurrect an expired attempt"
    );
    // The deadline worker owns expiry. Claiming remains a read/claim operation
    // and does not execute an implicit planner or timeout sweep.
    let expired_at = now();
    airroute_rules::jobs_v3::expire_due(&s).unwrap();
    let backoff: i64 = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT not_before FROM jobs WHERE id=?",
            [&other.id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(backoff > expired_at, "expiry must persist a retry backoff");
    // Keep the admission assertion independent of crossing a wall-clock second
    // while other integration tests are scheduled. The persisted value above
    // checks the real expiry policy; this fixture then controls the deadline.
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET not_before=? WHERE id=?",
            rusqlite::params![now() + 60, other.id],
        )
        .unwrap();
    assert!(
        s.lease(&c).unwrap().is_none(),
        "expired leases back off before another attempt"
    );
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET not_before=0 WHERE id=?", [&other.id])
        .unwrap();
    let replacement = node("replacement", "us", 64503);
    s.register_node(&replacement, "fixture-token-longer-than-24-characters")
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,session_id='replacement-session' WHERE id=?",
            rusqlite::params![now(), replacement.id],
        )
        .unwrap();
    let retry = s
        .lease_session(&replacement, "replacement-session")
        .unwrap()
        .unwrap();
    assert!(
        s.begin_execution(&replacement.id, "replacement-session", &retry)
            .unwrap()
    );
    assert_eq!(other.id, retry.id);
    assert!(
        retry.profile["attempt_seq"].as_i64().unwrap()
            > other.profile["attempt_seq"].as_i64().unwrap()
    );
    assert!(
        !s.heartbeat(&c.id, "session-c", &other.id, &other.token)
            .unwrap(),
        "an old executor heartbeat cannot extend the replacement lease"
    );
    assert!(
        s.heartbeat(
            &replacement.id,
            "replacement-session",
            &retry.id,
            &retry.token
        )
        .unwrap()
    );
    assert_eq!(
        s.submit(&c.id, &result(&other)).unwrap()["historical_only"],
        true
    );
    assert_eq!(
        s.submit(&replacement.id, &result(&retry)).unwrap()["accepted"],
        true
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT execution_count FROM jobs WHERE id=?",
                [&retry.id],
                |r| r.get(0)
            )
            .unwrap(),
        2,
        "dispatch acknowledgements and repeated/late receipts consume only their two actual executions"
    );
    // A repeated enqueue has no new jobs, and successful evidence is not replayed on every scheduler tick.
    let count: i64 = s
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))
        .unwrap();
    s.enqueue_observation("example.com", &["us".into()], "same semantic request")
        .unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        count
    );
    assert!(s.lease(&a).unwrap().is_none());
}
#[test]
fn revoked_node_and_failed_build_keep_current() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    commit(&s, &[case("v1")]);
    let id = s.start_build().unwrap();
    s.fail_build(&id, "required input missing").unwrap();
    assert_eq!(
        s.meta("current-release").unwrap().as_deref(),
        Some("verified-release")
    );
    let n = node("a", "us", 1);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    assert!(s.authenticate_node("a", "bad credential").is_err());
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET disabled=1", [])
        .unwrap();
    assert!(
        s.authenticate_node("a", "fixture-token-longer-than-24-characters")
            .is_err()
    );
}

#[test]
fn legacy_decisions_remain_history_while_manual_probe_refresh_is_separate() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("stable-semantic-fp");
    commit(&s, std::slice::from_ref(&c));
    s.connect().unwrap().execute(
        "INSERT INTO decisions(case_key,fp,action,reason,created,revision) VALUES(?,?,'region:us','legacy decision preserved as history',?,1)",
        rusqlite::params![c.key,c.fingerprint,now()],
    ).unwrap();
    assert_eq!(s.decisions().unwrap()[&c.key].1, "region:us");
    commit(&s, &[]);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM decisions", [], |r| r.get(0))
            .unwrap(),
        1
    );
    commit(&s, std::slice::from_ref(&c));
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM decisions", [], |r| r.get(0))
            .unwrap(),
        1
    );
    let key = s
        .enqueue_observation("fixture.example", &["us".into()], "first generation")
        .unwrap();
    let before: String = s
        .connect()
        .unwrap()
        .query_row("SELECT fp FROM cases WHERE key=?", [&key], |r| r.get(0))
        .unwrap();
    s.request_observation(
        "fixture.example",
        &["us".into()],
        "explicit temporary reprobe",
        true,
    )
    .unwrap();
    let after: String = s
        .connect()
        .unwrap()
        .query_row("SELECT fp FROM cases WHERE key=?", [&key], |r| r.get(0))
        .unwrap();
    assert_ne!(before, after);
    s.enqueue_observation(
        "fixture.example",
        &["us".into()],
        "reuse explicit generation",
    )
    .unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT fp FROM cases WHERE key=?", [&key], |r| r.get(0))
            .unwrap(),
        after
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM decisions", [], |r| r.get(0))
            .unwrap(),
        1,
        "temporary measurements never create location decisions"
    );
    let build = s.start_build().unwrap();
    airroute_rules::build::recover_abandoned(&s, temp.path()).unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM builds WHERE id=?", [build], |r| r
                .get(0))
            .unwrap(),
        "failed"
    );
}

#[test]
fn a_legacy_decision_insert_does_not_invalidate_a_frozen_build() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("v1");
    commit(&s, std::slice::from_ref(&c));
    let next = s.start_build().unwrap();
    let base = s.meta("current-build-id").unwrap();
    let artifact = airroute_rules::build_delta::write_internal(
        temp.path(),
        &next,
        base.as_deref(),
        "same-frozen-output",
        std::slice::from_ref(&c),
        &[],
        &json!({}),
    )
    .unwrap();
    s.connect().unwrap().execute("INSERT INTO decisions(case_key,fp,action,reason,created,revision) VALUES(?,?,'region:europe','imported historical decision',?,1)",rusqlite::params![c.key,c.fingerprint,now()]).unwrap();
    // Even an obsolete hint from an old controller cannot become a live output input.
    s.set_meta("rebuild-generation", "999").unwrap();
    airroute_rules::build_delta::activate(&s, &next, "same-frozen-output", &json!({}), &artifact)
        .unwrap();
    assert_eq!(
        s.meta("current-release").unwrap().as_deref(),
        Some("same-frozen-output")
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>(
                "SELECT action FROM decisions WHERE case_key=?",
                [&c.key],
                |r| r.get(0)
            )
            .unwrap(),
        "region:europe"
    );
}

#[test]
fn the_latest_manifest_reopens_legacy_decided_state_without_deleting_history() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("legacy-fixture");
    commit(&s, std::slice::from_ref(&c));
    let conn = s.connect().unwrap();
    conn.execute("INSERT INTO decisions(case_key,fp,action,reason,created,revision) VALUES(?,?,'region:us','legacy imported decision',?,1)",rusqlite::params![c.key,c.fingerprint,now()]).unwrap();
    conn.execute("UPDATE cases SET status='decided' WHERE key=?", [&c.key])
        .unwrap();
    commit(&s, std::slice::from_ref(&c));
    assert_ne!(
        conn.query_row::<String, _, _>("SELECT status FROM cases WHERE key=?", [&c.key], |r| r
            .get(0))
            .unwrap(),
        "decided"
    );
    assert_eq!(
        conn.query_row::<i64, _, _>("SELECT count(*) FROM decisions", [], |r| r.get(0))
            .unwrap(),
        1
    );
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let n = node("us-fixture", "us", 64501);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    assert!(
        s.lease(&n).unwrap().is_some(),
        "legacy history is not a live manual stop flag"
    );
}

#[test]
fn receipt_after_the_demand_is_withdrawn_is_only_trusted_history() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("withdrawn-fixture");
    commit(&s, std::slice::from_ref(&c));
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let n = node("us-fixture", "us", 64501);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    let lease = s.lease(&n).unwrap().unwrap();
    commit(&s, &[]);
    let r = result(&lease);
    assert_eq!(s.submit(&n.id, &r).unwrap()["historical_only"], true);
    assert_eq!(s.submit(&n.id, &r).unwrap()["duplicate"], true);
    assert_eq!(s.results(&c.key).unwrap()[0]["accepted"], false);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT active FROM cases WHERE key=?", [&c.key], |r| r
                .get(0))
            .unwrap(),
        0
    );
}

#[test]
fn retired_and_returning_source_scope_reuses_qualified_target_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let c = case("stable-fingerprint");
    let a = node("us-a", "us", 64501);
    let b = node("us-b", "us", 64502);
    for n in [&a, &b] {
        s.register_node(n, "fixture-token-longer-than-24-characters")
            .unwrap();
    }
    commit(&s, std::slice::from_ref(&c));
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let first = s.lease(&a).unwrap().unwrap();
    assert!(
        s.lease(&b).unwrap().is_none(),
        "one missing observation has no per-node copy"
    );
    assert_eq!(s.submit(&a.id, &result(&first)).unwrap()["qualified"], true);
    let jobs_before: i64 = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM jobs WHERE kind='traceroute' AND target='1.1.1.1'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    commit(&s, &[]);
    commit(&s, std::slice::from_ref(&c));
    airroute_rules::work::refresh(&s).unwrap();
    assert!(
        s.lease(&b).unwrap().is_none(),
        "an unchanged eligible target/method does not need a new observation merely because its source case returned"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM jobs WHERE kind='traceroute' AND target='1.1.1.1'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        jobs_before
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM results WHERE job_id=? AND qualified=1",
                [first.id],
                |r| r.get(0)
            )
            .unwrap(),
        1
    );
}

#[test]
fn audit_unsupported_jobs_do_not_hide_supported_work_behind_the_scan_limit() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    for octet in 0..26 {
        s.enqueue_observation(
            &format!("8.8.{octet}.1"),
            &["us".into()],
            "unrelated traceroute queue fixture",
        )
        .unwrap();
    }
    s.enqueue_observation(
        "supported.example",
        &["us".into()],
        "supported DNS queue fixture",
    )
    .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET not_before=CASE WHEN kind='traceroute' THEN 0 ELSE 1 END",
            [],
        )
        .unwrap();
    let mut n = node("dns-only", "us", 64501);
    n.capabilities = vec!["dns".into()];
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    let lease = s
        .lease(&n)
        .unwrap()
        .expect("supported work must remain reachable behind unsupported jobs");
    assert_eq!(lease.kind, "dns");
    assert_eq!(lease.target, "supported.example");
}

#[test]
fn uncertain_third_party_intent_blocks_the_same_demand_after_temporary_refresh() {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    s.enqueue_observation(
        "fixture.example",
        &["europe".into()],
        "uncertain send fixture",
    )
    .unwrap();
    let id: String = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT id FROM jobs WHERE target='fixture.example' AND region='europe'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET status='unknown' WHERE id=?", [&id])
        .unwrap();
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES(?,'fixture','','{}',0)",[&id]).unwrap();
    s.request_observation(
        "fixture.example",
        &["europe".into()],
        "explicit temporary refresh cannot bypass unknown",
        true,
    )
    .unwrap();
    let n = node("eu-fixture", "europe", 64501);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    assert!(
        s.lease(&n).unwrap().is_none(),
        "refresh cannot bypass an uncertain remote execution of the same target/method/view"
    );
    s.enqueue_observation(
        "unrelated.example",
        &["europe".into()],
        "independent work remains runnable",
    )
    .unwrap();
    assert_eq!(s.lease(&n).unwrap().unwrap().target, "unrelated.example");
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [&id], |r| r.get(0))
            .unwrap(),
        "unknown"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM gp_remote WHERE job_id=? AND remote_id=''",
                [id],
                |r| r.get(0)
            )
            .unwrap(),
        1
    );
}

fn app(temp: &std::path::Path) -> server::App {
    server::App {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        data: temp.into(),
        store: Store::open(temp).unwrap(),
        offline: true,
        admin_hash: hash("fixture-admin-token-with-enough-length"),
        gp: Default::default(),
        building: Arc::new(AtomicBool::new(false)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions: Arc::new(
            airroute_rules::console_session::ConsoleSessions::open(
                temp,
                &hash("fixture-admin-token-with-enough-length"),
            )
            .unwrap(),
        ),
        host: "127.0.0.1:8787".into(),
        probe_hub: Default::default(),
    }
}
#[tokio::test]
async fn console_node_activation_routes_are_authorized_reversible_and_validate_identity() {
    let temp = tempfile::tempdir().unwrap();
    let application = app(temp.path());
    let store = application.store.clone();
    let n = node("activation-route", "us", 64501);
    let key = hash("activation-fixture-key");
    store.register_node(&n, &key).unwrap();
    let router = server::router(application);
    for action in ["disable", "enable"] {
        let path = format!("/api/nodes/{}/{action}", n.id);
        let request = |authorized: bool| {
            let mut r = Request::builder().uri(&path).method("POST");
            if authorized {
                r = r.header(
                    "authorization",
                    "Bearer fixture-admin-token-with-enough-length",
                );
            }
            r.body(Body::empty()).unwrap()
        };
        assert_eq!(
            router
                .clone()
                .oneshot(request(false))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            router
                .clone()
                .oneshot(request(true))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            store.authenticate_node(&n.id, &key).is_ok(),
            action == "enable"
        );
    }
    for id in ["missing", "globalping:fixture:us"] {
        let r = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/nodes/{id}/enable"))
                    .method("POST")
                    .header(
                        "authorization",
                        "Bearer fixture-admin-token-with-enough-length",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
}

#[test]
fn audit_concurrent_observation_refreshes_commit_complete_plans() {
    let temp = tempfile::tempdir().unwrap();
    let application = app(temp.path());
    let geography: Value =
        airroute_rules::read_json(&application.root.join("config/geography.json")).unwrap();
    let regions: Vec<_> = geography["regions"]
        .as_array()
        .unwrap()
        .iter()
        .take(8)
        .map(|r| r["id"].clone())
        .collect();
    let router = server::router(application.clone());
    for trial in 0..4 {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = (0..2)
            .map(|_| {
                let router = router.clone();
                let barrier = barrier.clone();
                let body = json!({
                    "target":format!("refresh-{trial}.example"),
                    "regions":regions,
                    "reason":"concurrent refresh fixture",
                    "refresh":true
                });
                std::thread::spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    barrier.wait();
                    runtime.block_on(async {
                        let response = router
                            .oneshot(
                                Request::post("/api/observations")
                                    .header(
                                        "authorization",
                                        "Bearer fixture-admin-token-with-enough-length",
                                    )
                                    .header("content-type", "application/json")
                                    .body(Body::from(body.to_string()))
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        let status = response.status();
                        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                            .await
                            .unwrap();
                        (status, String::from_utf8(bytes.to_vec()).unwrap())
                    })
                })
            })
            .collect();
        for thread in threads {
            let (status, body) = thread.join().unwrap();
            assert_eq!(status, StatusCode::OK, "{body}");
        }
        let active_jobs: i64 = application
            .store
            .connect()
            .unwrap()
            .query_row(
                "SELECT count(*) FROM cases c JOIN job_cases l ON l.case_key=c.key AND l.fp=c.fp AND l.revision=c.revision JOIN jobs j ON j.id=l.job_id WHERE c.subject=? AND j.status='pending'",
                [format!("refresh-{trial}.example")],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active_jobs, regions.len() as i64);
    }
}

#[tokio::test]
async fn node_registration_generates_unique_ids_and_accepts_an_unknown_network() {
    let temp = tempfile::tempdir().unwrap();
    let application = app(temp.path());
    let store = application.store.clone();
    let router = server::router(application);
    let mut receipts = vec![];
    for _ in 0..2 {
        let request = Request::builder()
            .uri("/api/nodes")
            .method("POST")
            .header(
                "authorization",
                "Bearer fixture-admin-token-with-enough-length",
            )
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"name":"美国主节点","region":"us","capabilities":["dns","traceroute"]})
                    .to_string(),
            ))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let id = value["id"].as_str().unwrap();
        let token = value["token"].as_str().unwrap();
        assert!(id.starts_with("node-"));
        assert_eq!(id.len(), 37);
        assert_eq!(store.authenticate_node(id, token).unwrap().asn, 0);
        receipts.push(value);
    }
    assert_ne!(receipts[0]["id"], receipts[1]["id"]);
    let nodes = store.nodes().unwrap();
    assert_eq!(nodes.as_array().unwrap().len(), 2);
    assert!(
        nodes
            .as_array()
            .unwrap()
            .iter()
            .all(|n| n["name"] == "美国主节点")
    );
}
#[test]
fn old_node_registration_keeps_its_credentials_and_optional_name() {
    let temp = tempfile::tempdir().unwrap();
    let token = "fixture-token-longer-than-24-characters";
    let c = rusqlite::Connection::open(temp.path().join("control.sqlite3")).unwrap();
    c.execute_batch("CREATE TABLE nodes(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,region TEXT NOT NULL,asn INTEGER NOT NULL,capabilities TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0,last_seen INTEGER);").unwrap();
    c.execute("INSERT INTO nodes(id,token_hash,region,asn,capabilities) VALUES('old-node',?,'us',64501,'[\"dns\"]')",[hash(token)]).unwrap();
    drop(c);
    let store = Store::open(temp.path()).unwrap();
    let node = store.authenticate_node("old-node", token).unwrap();
    assert_eq!(store.nodes().unwrap()[0]["name"], "");
    store
        .register_named_node(&node, token, Some("现有美国节点"))
        .unwrap();
    store.register_node(&node, token).unwrap();
    assert_eq!(store.nodes().unwrap()[0]["name"], "现有美国节点");
    assert!(store.authenticate_node("old-node", token).is_ok());
}
#[tokio::test]
async fn console_auth_and_asset_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let router = server::router(app(temp.path()));
    let request = |path: &str| Request::builder().uri(path).body(Body::empty()).unwrap();
    assert_eq!(
        router
            .clone()
            .oneshot(request("/api/overview"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("/api/session"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router
            .clone()
            .oneshot(request("/assets/missing.js"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let r = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/conflicts")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r.headers().contains_key("content-security-policy"));
    let r = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/login")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"token":"fixture-admin-token-with-enough-length"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let cookie = r.headers()["set-cookie"].to_str().unwrap().to_string();
    assert!(cookie.contains("HttpOnly"));
    let session = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session.status(), StatusCode::OK);
    assert!(
        session.headers()["server-timing"]
            .to_str()
            .unwrap()
            .starts_with("app;dur=")
    );
    let body = axum::body::to_bytes(session.into_body(), 128)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"authenticated":true})
    );
    for path in [
        "/api/task-items?limit=30",
        "/api/task-summary",
        "/api/discovery-status",
    ] {
        assert_eq!(
            router
                .clone()
                .oneshot(request(path))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("cookie", &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    let r = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/overview")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = router
        .oneshot(
            Request::builder()
                .uri("/api/builds")
                .method("POST")
                .header("cookie", cookie)
                .header("origin", "https://attacker.invalid")
                .header("host", "127.0.0.1:8787")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn a_globalping_writer_wait_does_not_freeze_the_console_executor() {
    use std::sync::mpsc;
    use std::time::Duration;
    let temp = tempfile::tempdir().unwrap();
    let application = app(temp.path());
    let s = application.store.clone();
    let router = server::router(application);
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let released = Arc::new(AtomicBool::new(false));
    let flag = released.clone();
    let writer = std::thread::spawn(move || {
        let c = s.connect().unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(1));
        flag.store(true, Ordering::SeqCst);
        c.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let copy = router.clone();
    let tick = tokio::spawn(async move {
        copy.oneshot(
            Request::builder()
                .uri("/api/scheduler/tick")
                .method("POST")
                .header(
                    "authorization",
                    "Bearer fixture-admin-token-with-enough-length",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/session")
                .header(
                    "authorization",
                    "Bearer fixture-admin-token-with-enough-length",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !released.load(Ordering::SeqCst),
        "console must respond while the writer is still held"
    );
    release_tx.send(()).unwrap();
    assert_eq!(tick.await.unwrap().status(), StatusCode::OK);
    writer.join().unwrap();
}
#[tokio::test]
async fn dns_measurement_uses_ttl_cache_and_never_assigns_ownership() {
    use hickory_proto::{
        op::{Message, OpCode},
        rr::{
            Name, RData, Record,
            rdata::{A, CNAME},
        },
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    let fixture = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let q = Message::from_vec(&buf[..n]).unwrap();
            let mut r = Message::response(q.metadata.id, OpCode::Query);
            r.queries = q.queries.clone();
            r.answers.push(Record::from_rdata(
                q.queries[0].name().clone(),
                60,
                RData::CNAME(CNAME(
                    Name::from_ascii("tenant.shared-cdn.example.").unwrap(),
                )),
            ));
            r.answers.push(Record::from_rdata(
                Name::from_ascii("tenant.shared-cdn.example.").unwrap(),
                60,
                RData::A(A("1.1.1.1".parse().unwrap())),
            ));
            socket.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    s.enqueue_observation("fixture.example", &["us".into()], "DNS fixture")
        .unwrap();
    let n = node("fixture", "us", 64500);
    s.register_node(&n, "fixture-token-longer-than-24-characters")
        .unwrap();
    let lease = s.lease(&n).unwrap().unwrap();
    let config = ProbeConfig {
        controller: "http://127.0.0.1:8787".into(),
        id: n.id.clone(),
        token_env: "UNUSED_FIXTURE_TOKEN".into(),
        resolvers: vec![ResolverConfig {
            name: "fixture".into(),
            address: address.to_string(),
            transport: "udp".into(),
        }],
        allow_private_targets: false,
        tls: false,
        ca_cert: std::path::PathBuf::new(),
        server_name: airroute_rules::transport::SERVER_NAME.into(),
        data_dir: temp.path().into(),
    };
    let first = measure::domain(&config, &lease, &s).await.unwrap();
    let count = queries.load(Ordering::SeqCst);
    assert!(count >= 5);
    assert_eq!(first["resolvers"][0]["cache_hit"], false);
    let second = measure::domain(&config, &lease, &s).await.unwrap();
    assert_eq!(second["resolvers"][0]["cache_hit"], true);
    assert_eq!(queries.load(Ordering::SeqCst), count);
    assert!(s.decisions().unwrap().is_empty());
    let r = measure::execute(&config, &lease, &s).await;
    assert_eq!(r.outcome, "ok");
    assert_eq!(s.submit(&n.id, &r).unwrap()["accepted"], true);
    fixture.abort();
}

#[tokio::test]
async fn catalogue_and_download_hide_internal_china_even_in_an_old_release() {
    let temp = tempfile::tempdir().unwrap();
    let application = app(temp.path());
    let store = application.store.clone();
    let path = application.data.join("releases/old/region");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("cn-geo.list"), "IP-CIDR,1.2.3.0/24,no-resolve\n").unwrap();
    std::fs::write(path.join("cn.list"), "DOMAIN-SUFFIX,example.cn\n").unwrap();
    store.set_meta("current-release", "old").unwrap();
    let router = server::router(application);
    let request = |path: &str| {
        Request::builder()
            .uri(path)
            .header(
                "authorization",
                "Bearer fixture-admin-token-with-enough-length",
            )
            .body(Body::empty())
            .unwrap()
    };
    let r = router
        .clone()
        .oneshot(request("/api/catalogue"))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body = axum::body::to_bytes(r.into_body(), usize::MAX)
        .await
        .unwrap();
    let catalogue: Value = serde_json::from_slice(&body).unwrap();
    let rows = catalogue["items"].as_array().unwrap();
    assert_eq!(rows.len(), 376);
    assert_eq!(rows.iter().filter(|r| r["id"] == "region/cn").count(), 1);
    assert!(!rows.iter().any(|r| r["id"] == "region/cn-geo"));
    assert_eq!(
        router
            .clone()
            .oneshot(request("/api/rules/region/cn-geo.list"))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        router
            .oneshot(request("/api/rules/region/cn.list"))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
}
