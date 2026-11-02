use airroute_rules::{
    build_delta, hash, now,
    store::{CaseInput, Node, ProbeResult, Store},
    work,
};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

const PARENT: &str = "4:1.1.1.0/24:europe|us";

fn problem(key: &str, fp: &str, start: &str, end: &str, parent: Option<&str>) -> CaseInput {
    let mut payload = json!({
        "kind":"endpoint-reachability", "family":4,
        "ranges":[[start,end]], "targets":[], "regions":["europe","us"],
        "measurement_required":true, "repeat_on_build":false,
        "publication":"deterministic geographic fallback already emitted"
    });
    if let Some(parent) = parent {
        payload["sample_plan"] = json!({
            "strategy":"bgp-bounded-v1", "parent_case_key":parent,
            "targets_per_group":3, "allow_ipv4_candidates":true
        });
    }
    CaseInput {
        key: key.into(),
        fingerprint: fp.into(),
        kind: "endpoint-reachability".into(),
        subject: format!("{start}-{end}"),
        reason: "bounded sampling lifecycle fixture".into(),
        payload,
    }
}

fn child(suffix: &str, fp: &str, start: &str, end: &str) -> CaseInput {
    problem(
        &format!("{PARENT}:sample:{suffix}"),
        fp,
        start,
        end,
        Some(PARENT),
    )
}

fn activate(store: &Store, cases: &[CaseInput]) -> String {
    let id = store.start_build().unwrap();
    let base = store.meta("current-build-id").unwrap();
    let path = build_delta::write_internal(
        store.path.parent().unwrap(),
        &id,
        base.as_deref(),
        "sampling-fixture-release",
        cases,
        &[],
        &json!({"observation_cutoff":now()}),
    )
    .unwrap();
    assert_eq!(
        build_delta::activate(
            store,
            &id,
            "sampling-fixture-release",
            &json!({"observation_cutoff":now()}),
            &path,
        )
        .unwrap()["semantic_writes"],
        0
    );
    for _ in 0..1000 {
        if !build_delta::sync_current(store, 1).unwrap() {
            return id;
        }
    }
    panic!("bounded build synchronization did not finish");
}

fn payload(store: &Store, key: &str) -> Value {
    let body: String = store
        .connect()
        .unwrap()
        .query_row("SELECT payload FROM cases WHERE key=?", [key], |r| r.get(0))
        .unwrap();
    serde_json::from_str(&body).unwrap()
}

fn select(store: &Store, case: &CaseInput, targets: &[&str]) {
    store
        .targets(
            &case.key,
            &case.fingerprint,
            &targets.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
}

fn active(store: &Store, key: &str) -> bool {
    store
        .connect()
        .unwrap()
        .query_row("SELECT active FROM cases WHERE key=?", [key], |r| r.get(0))
        .unwrap()
}

#[test]
fn retired_parent_selections_are_inherited_only_inside_each_child_scope() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let old = problem(PARENT, "parent-v1", "1.1.1.0", "1.1.1.255", None);
    activate(&store, std::slice::from_ref(&old));
    select(&store, &old, &["1.1.1.10", "1.1.1.200"]);
    let mut old_payload = payload(&store, PARENT);
    old_payload["target_evidence"] = json!({
        "1.1.1.200":{"kind":"dns-answer","source":"original-receipt","observed":now()-30,"valid_until":now()+1000}
    });
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE cases SET payload=?,active=0,status='inactive' WHERE key=?",
            params![old_payload.to_string(), PARENT],
        )
        .unwrap();

    let low = child("low-stable", "low-v1", "1.1.1.0", "1.1.1.127");
    let high = child("high-stable", "high-v1", "1.1.1.128", "1.1.1.255");
    activate(&store, &[low.clone(), high.clone()]);
    let low_payload = payload(&store, &low.key);
    let high_payload = payload(&store, &high.key);
    assert_eq!(low_payload["targets"], json!(["1.1.1.10"]));
    assert_eq!(high_payload["targets"], json!(["1.1.1.200"]));
    assert!(low_payload["target_evidence"]["1.1.1.200"].is_null());
    assert_eq!(
        high_payload["target_evidence"]["1.1.1.200"],
        old_payload["target_evidence"]["1.1.1.200"]
    );
    assert!(!active(&store, PARENT));
}

#[test]
fn refinement_inherits_existing_siblings_without_requiring_the_original_parent_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let low = child("old-low", "old-low-v1", "1.1.1.0", "1.1.1.127");
    let high = child("old-high", "old-high-v1", "1.1.1.128", "1.1.1.255");
    activate(&store, &[low.clone(), high.clone()]);
    select(&store, &low, &["1.1.1.10"]);
    select(&store, &high, &["1.1.1.200"]);

    let a = child("new-a", "a-v1", "1.1.1.0", "1.1.1.63");
    let b = child("new-b", "b-v1", "1.1.1.64", "1.1.1.127");
    let c = child("new-c", "c-v1", "1.1.1.128", "1.1.1.191");
    let d = child("new-d", "d-v1", "1.1.1.192", "1.1.1.255");
    activate(&store, &[a.clone(), b.clone(), c.clone(), d.clone()]);
    assert_eq!(payload(&store, &a.key)["targets"], json!(["1.1.1.10"]));
    assert_eq!(payload(&store, &d.key)["targets"], json!(["1.1.1.200"]));
    assert_eq!(payload(&store, &b.key)["targets"], json!([]));
    assert_eq!(payload(&store, &c.key)["targets"], json!([]));
    assert!(!active(&store, &low.key));
    assert!(!active(&store, &high.key));
}

#[test]
fn a_changed_scope_drops_out_of_range_runtime_selections_and_their_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let wide = child("same-key", "wide-v1", "1.1.1.0", "1.1.1.255");
    activate(&store, std::slice::from_ref(&wide));
    select(&store, &wide, &["1.1.1.10", "1.1.1.200"]);
    let mut p = payload(&store, &wide.key);
    p["target_evidence"] =
        json!({"1.1.1.10":{"source":"keep-original"},"1.1.1.200":{"source":"outside-new-range"}});
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE cases SET payload=? WHERE key=?",
            params![p.to_string(), wide.key],
        )
        .unwrap();
    let narrow = child("same-key", "narrow-v2", "1.1.1.0", "1.1.1.127");
    activate(&store, std::slice::from_ref(&narrow));
    let actual = payload(&store, &narrow.key);
    assert_eq!(actual["targets"], json!(["1.1.1.10"]));
    assert_eq!(
        actual["target_evidence"]["1.1.1.10"],
        p["target_evidence"]["1.1.1.10"]
    );
    assert!(actual["target_evidence"]["1.1.1.200"].is_null());
}

fn node(store: &Store, id: &str) -> Node {
    let node = Node {
        id: id.into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, &hash("isolated-sampling-fixture"))
        .unwrap();
    store.connect().unwrap().execute(
        "UPDATE nodes SET connected=1,session_id='sampling-session',last_seen=?,ipv4_supported=1 WHERE id=?",
        params![now(),id],
    ).unwrap();
    node
}

#[test]
fn splitting_preserves_the_existing_job_attempt_budget_and_unknown_remote_fence() {
    for disposition in ["leased", "unknown", "exhausted"] {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        airroute_rules::globalping::initialize_intents(&store).unwrap();
        let executor = node(&store, "original-executor");
        let old = problem(PARENT, "parent-v1", "1.1.1.0", "1.1.1.255", None);
        activate(&store, std::slice::from_ref(&old));
        select(&store, &old, &["1.1.1.10"]);
        let lease = store
            .lease_session(&executor, "sampling-session")
            .unwrap()
            .unwrap();
        assert!(
            store
                .begin_execution(&executor.id, "sampling-session", &lease)
                .unwrap()
        );
        if disposition == "unknown" {
            store.connect().unwrap().execute(
                "INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,attempt_seq,state,reserved_hour,reserved_cost,slot_active) VALUES(?,'fixture-account','',?,0,?,'unknown',?,1,0)",
                params![lease.id,serde_json::to_string(&lease).unwrap(),lease.profile["attempt_seq"].as_i64().unwrap(),now()/3600],
            ).unwrap();
            store
                .connect()
                .unwrap()
                .execute("UPDATE jobs SET status='unknown' WHERE id=?", [&lease.id])
                .unwrap();
        } else if disposition == "exhausted" {
            store
                .connect()
                .unwrap()
                .execute(
                    "UPDATE jobs SET status='unknown',execution_count=3,next_round_at=? WHERE id=?",
                    params![now() + 86400, lease.id],
                )
                .unwrap();
        }
        let before: String = store.connect().unwrap().query_row(
            "SELECT json_array(id,status,execution_count,attempt_seq,round_seq,lease_token) FROM jobs WHERE id=?", [&lease.id], |r|r.get(0),
        ).unwrap();
        let remote: Option<String> = store.connect().unwrap().query_row(
            "SELECT json_array(account,remote_id,state,attempt_seq,reserved_hour,reserved_cost,lease) FROM gp_remote WHERE job_id=?", [&lease.id], |r|r.get(0),
        ).optional().unwrap();
        assert_eq!(remote.is_some(), disposition == "unknown");
        let new = child("new-scope", "new-v1", "1.1.1.0", "1.1.1.127");
        activate(&store, std::slice::from_ref(&new));
        assert!(
            payload(&store, &new.key)["targets"]
                .as_array()
                .unwrap()
                .contains(&json!("1.1.1.10"))
        );
        work::refresh(&store).unwrap();
        let c = store.connect().unwrap();
        let after: String = c.query_row(
            "SELECT json_array(id,status,execution_count,attempt_seq,round_seq,lease_token) FROM jobs WHERE id=?", [&lease.id], |r|r.get(0),
        ).unwrap();
        assert_eq!(before, after, "disposition={disposition}");
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT count(*) FROM jobs WHERE kind='traceroute' AND target='1.1.1.10'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            c.query_row::<String, _, _>(
                "SELECT job_id FROM job_cases WHERE case_key=? AND job_id=?",
                params![new.key, lease.id],
                |r| r.get(0)
            )
            .unwrap(),
            lease.id
        );
        let saved_remote: Option<String> = c.query_row("SELECT json_array(account,remote_id,state,attempt_seq,reserved_hour,reserved_cost,lease) FROM gp_remote WHERE job_id=?",[&lease.id],|r|r.get(0)).optional().unwrap();
        assert_eq!(remote, saved_remote);
        assert!(!active(&store, PARENT));
        let competing = node(&store, "competing-executor");
        assert!(
            airroute_rules::jobs_v3::lease_with_admission(
                &store,
                &competing,
                Some("sampling-session"),
                |_, candidate| Ok(candidate.target == "1.1.1.10"),
            )
            .unwrap()
            .is_none(),
            "disposition={disposition}: a split cannot dispatch the original target again"
        );
        if disposition == "leased" {
            let result = ProbeResult {
                id: "split-original-attempt-result".into(),
                job_id: lease.id.clone(),
                fingerprint: lease.fingerprint.clone(),
                lease_token: lease.token.clone(),
                observed_at: now(),
                outcome: "ok".into(),
                evidence: json!({"kind":"traceroute","target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target,"rtt_ms":1}]}),
            };
            let accepted = store.submit(&executor.id, &result).unwrap();
            assert_eq!(accepted["accepted"], true);
            assert_eq!(accepted["qualified"], true);
            assert_eq!(
                store.submit(&executor.id, &result).unwrap()["duplicate"],
                true
            );
            assert_eq!(
                c.query_row::<i64, _, _>(
                    "SELECT execution_count FROM jobs WHERE id=?",
                    [&lease.id],
                    |r| r.get(0)
                )
                .unwrap(),
                1
            );
            assert_eq!(
                c.query_row::<i64, _, _>(
                    "SELECT completed_tasks FROM executor_counters WHERE executor=?",
                    [&executor.id],
                    |r| r.get(0)
                )
                .unwrap(),
                1
            );
        }
    }
}

#[test]
fn merging_children_into_the_parent_preserves_unknown_attempt_and_accounting() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    airroute_rules::globalping::initialize_intents(&store).unwrap();
    let executor = node(&store, "old-child-executor");
    let low = child("old-low", "low-v1", "1.1.1.0", "1.1.1.127");
    let high = child("old-high", "high-v1", "1.1.1.128", "1.1.1.255");
    activate(&store, &[low.clone(), high.clone()]);
    select(&store, &low, &["1.1.1.10"]);
    // Claim the only selected target before creating the other child's work.
    // Admission callbacks reject a whole claim; they are not candidate filters.
    let lease = store
        .lease_session(&executor, "sampling-session")
        .unwrap()
        .unwrap();
    assert_eq!(lease.target, "1.1.1.10");
    assert!(
        store
            .begin_execution(&executor.id, "sampling-session", &lease)
            .unwrap()
    );
    select(&store, &high, &["1.1.1.200"]);

    // Fixture the durable possibly-sent boundary only; no provider request is made.
    let sent_at = now();
    let c = store.connect().unwrap();
    c.execute(
        "INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,attempt_seq,state,reserved_hour,reserved_cost,provider_reset_at,send_started_at,slot_active) VALUES(?,'fixture-account','',?,0,?,'unknown',?,3,?,?,0)",
        params![lease.id,serde_json::to_string(&lease).unwrap(),lease.profile["attempt_seq"].as_i64().unwrap(),sent_at/3600,sent_at+3600,sent_at],
    ).unwrap();
    c.execute("UPDATE jobs SET status='unknown' WHERE id=?", [&lease.id])
        .unwrap();
    c.execute(
        "INSERT INTO gp_account_usage VALUES('fixture-account',?,3,0)",
        [sent_at / 3600],
    )
    .unwrap();
    c.execute(
        "INSERT INTO gp_send_clock VALUES('fixture-account',?)",
        [sent_at * 1000],
    )
    .unwrap();
    let snapshot = || {
        let c = store.connect().unwrap();
        let job: String = c.query_row(
            "SELECT json_array(id,status,execution_count,failure_count,attempt_seq,round_seq,lease_token,logical_key,demand_key) FROM jobs WHERE id=?",
            [&lease.id], |r| r.get(0),
        ).unwrap();
        let remote: String = c.query_row(
            "SELECT json_array(account,remote_id,state,attempt_seq,reserved_hour,reserved_cost,provider_reset_at,send_started_at,slot_active,lease) FROM gp_remote WHERE job_id=?",
            [&lease.id], |r| r.get(0),
        ).unwrap();
        let history: String = c.query_row(
            "SELECT json_array(job_id,token_hash,node,fp,attempt_seq,round_seq,started_at,execution_refunded,execution_job_id,completed_at) FROM lease_history WHERE job_id=?",
            [&lease.id], |r| r.get(0),
        ).unwrap();
        let accounting: String = c.query_row(
            "SELECT json_array(u.account,u.bucket,u.used,u.blocked_until,s.last_started_ms) FROM gp_account_usage u JOIN gp_send_clock s ON s.account=u.account WHERE u.account='fixture-account'",
            [], |r| r.get(0),
        ).unwrap();
        (job, remote, history, accounting)
    };
    let before = snapshot();

    // A single homogeneous unit returns to the original parent key, including
    // when that parent row did not exist before the children were introduced.
    let merged = problem(PARENT, "merged-v2", "1.1.1.0", "1.1.1.255", Some(PARENT));
    activate(&store, std::slice::from_ref(&merged));
    let selected = payload(&store, PARENT);
    for target in ["1.1.1.10", "1.1.1.200"] {
        assert!(
            selected["targets"]
                .as_array()
                .unwrap()
                .contains(&json!(target))
        );
    }
    assert!(!active(&store, &low.key));
    assert!(!active(&store, &high.key));
    for _ in 0..3 {
        work::refresh(&store).unwrap();
    }
    assert_eq!(before, snapshot());
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT job_id FROM job_cases WHERE case_key=? AND job_id=?",
            params![PARENT, lease.id],
            |r| r.get(0)
        )
        .unwrap(),
        lease.id
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE kind='traceroute' AND target='1.1.1.10'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    let competing = node(&store, "merged-competing-executor");
    // Leave only this target due, so an unrelated claim cannot mask a duplicate.
    c.execute(
        "UPDATE jobs SET not_before=? WHERE status='pending' AND target<>'1.1.1.10'",
        [now() + 3600],
    )
    .unwrap();
    assert!(
        store
            .lease_session(&competing, "sampling-session")
            .unwrap()
            .is_none(),
        "merging cannot bypass an unknown submission by introducing a parent key"
    );
    assert_eq!(before, snapshot());
}

#[test]
fn unchanged_sampling_selections_survive_sync_refresh_and_reopen_without_semantic_writes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let new = child("stable", "stable-v1", "1.1.1.0", "1.1.1.255");
    activate(&store, std::slice::from_ref(&new));
    select(&store, &new, &["1.1.1.10", "1.1.1.120", "1.1.1.200"]);
    work::refresh(&store).unwrap();
    let before = payload(&store, &new.key);
    store.connect().unwrap().execute_batch("CREATE TABLE sampling_writes(object TEXT);CREATE TRIGGER sampling_case_write AFTER UPDATE ON cases BEGIN INSERT INTO sampling_writes VALUES('case');END;CREATE TRIGGER sampling_job_insert AFTER INSERT ON jobs BEGIN INSERT INTO sampling_writes VALUES('job');END;CREATE TRIGGER sampling_job_write AFTER UPDATE ON jobs BEGIN INSERT INTO sampling_writes VALUES('job');END;").unwrap();
    for _ in 0..3 {
        work::refresh(&store).unwrap();
    }
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    activate(&store, std::slice::from_ref(&new));
    for _ in 0..3 {
        work::refresh(&store).unwrap();
    }
    assert_eq!(before, payload(&store, &new.key));
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM sampling_writes", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        3
    );
}
