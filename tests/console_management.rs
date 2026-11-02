use airroute_rules::{
    globalping::{self, AccountInput, Config},
    now, publish, scheduler,
    store::{CaseInput, Node, ProbeResult, Store},
};
use serde_json::json;
use std::collections::BTreeMap;
fn node(id: &str) -> Node {
    Node {
        id: id.into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into(), "traceroute".into()],
    }
}
#[test]
fn node_disable_enable_preserves_identity_and_requeues_old_session_leases() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("recoverable");
    let key = airroute_rules::hash("same-node-fixture-key");
    s.register_named_node(&n, &key, Some("Existing probe"))
        .unwrap();
    s.update_node_settings(&n.id, "Existing probe", Some(7))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,session_id='old',last_seen=?",
            [now()],
        )
        .unwrap();
    s.enqueue_observation("fixture.example", &["us".into()], "enable fixture")
        .unwrap();
    let lease = s.lease_session(&n, "old").unwrap().unwrap();
    let hash_before: String = s
        .connect()
        .unwrap()
        .query_row("SELECT token_hash FROM nodes WHERE id=?", [&n.id], |r| {
            r.get(0)
        })
        .unwrap();
    s.set_node_enabled(&n.id, false).unwrap();
    assert!(s.authenticate_node(&n.id, &key).is_err());
    assert_eq!(s.nodes().unwrap()[0]["disabled"], true);
    assert_eq!(s.nodes().unwrap()[0]["connected"], false);
    assert!(s.lease_session(&n, "old").unwrap().is_none());
    s.set_node_enabled(&n.id, true).unwrap();
    assert!(s.authenticate_node(&n.id, &key).is_ok());
    let info = s.nodes().unwrap()[0].clone();
    assert_eq!(info["disabled"], false);
    assert_eq!(info["connected"], false);
    assert_eq!(info["name"], "Existing probe");
    assert_eq!(info["concurrency_limit"], 7);
    let late = ProbeResult {
        id: "disabled-late-receipt".into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({}),
    };
    assert_eq!(s.submit(&n.id, &late).unwrap()["historical_only"], true);
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,session_id='new',last_seen=?",
            [now()],
        )
        .unwrap();
    let resumed = s.lease_session(&n, "new").unwrap().unwrap();
    assert_eq!(resumed.id, lease.id);
    assert_ne!(resumed.token, lease.token);
    // Repeated enable requests must leave the new live session and lease intact.
    s.set_node_enabled(&n.id, true).unwrap();
    assert_eq!(s.nodes().unwrap()[0]["connected"], true);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>(
                "SELECT lease_token FROM jobs WHERE id=?",
                [resumed.id],
                |r| r.get(0)
            )
            .unwrap(),
        resumed.token
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT token_hash FROM nodes WHERE id=?", [&n.id], |r| r
                .get(0))
            .unwrap(),
        hash_before
    );
    assert!(s.set_node_enabled("missing", true).is_err());
    assert!(s.set_node_enabled("globalping:fixture:us", true).is_err());
}
#[test]
fn enabling_an_old_disabled_record_clears_its_stale_presence_and_lease() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("legacy-disabled");
    s.register_node(&n, &airroute_rules::hash("legacy-node-key"))
        .unwrap();
    s.enqueue_observation("legacy.example", &["us".into()], "legacy disable fixture")
        .unwrap();
    let lease = s.lease(&n).unwrap().unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET disabled=1,connected=1,session_id='stale'",
            [],
        )
        .unwrap();
    s.set_node_enabled(&n.id, true).unwrap();
    assert_eq!(s.nodes().unwrap()[0]["connected"], false);
    let state: (String, Option<String>) = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,lease_node FROM jobs WHERE id=?",
            [lease.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("pending".into(), None));
}
#[test]
fn node_settings_preserve_identity_credentials_and_independent_limits() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("editable");
    let token = airroute_rules::hash("settings-fixture");
    s.register_node(&n, &token).unwrap();
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 10);
    s.update_node_settings(&n.id, "Renamed node", Some(4))
        .unwrap();
    assert_eq!(s.nodes().unwrap()[0]["name"], "Renamed node");
    assert_eq!(s.nodes().unwrap()[0]["concurrency_limit"], 4);
    assert!(s.authenticate_node(&n.id, &token).is_ok());
    assert_eq!(
        Store::open(d.path())
            .unwrap()
            .node_concurrency(&n.id)
            .unwrap(),
        4
    );
    let policy = scheduler::Policy {
        per_node_concurrency: 12,
        ..Default::default()
    };
    scheduler::save_policy(&s, &policy, true).unwrap();
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 4);
    s.update_node_settings(&n.id, "Renamed node", None).unwrap();
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 10);
    for bad in [0, 1001] {
        assert!(s.update_node_settings(&n.id, "invalid", Some(bad)).is_err());
    }
    assert!(s.update_node_settings(&n.id, "bad\nname", None).is_err());
    assert!(s.update_node_settings("missing", "invalid", None).is_err());
    assert!(
        s.update_node_settings("globalping:fixture:us", "invalid", None)
            .is_err()
    );
    assert_eq!(s.nodes().unwrap()[0]["name"], "Renamed node");
}
#[test]
fn reset_revokes_the_old_key_requeues_lease_and_keeps_identity() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("old-id");
    s.register_named_node(&n, &airroute_rules::hash("old-test-key"), Some("US probe"))
        .unwrap();
    s.enqueue_observation("example.com", &["us".into()], "temporary fixture")
        .unwrap();
    let lease = s.lease(&n).unwrap().unwrap();
    let token = s.reset_node_token(&n.id).unwrap();
    assert!(
        s.authenticate_node(&n.id, &airroute_rules::hash("old-test-key"))
            .is_err()
    );
    assert!(s.authenticate_node(&n.id, &token).is_ok());
    assert_eq!(s.nodes().unwrap()[0]["name"], "US probe");
    let r = ProbeResult {
        id: "late".into(),
        job_id: lease.id,
        fingerprint: lease.fingerprint,
        lease_token: lease.token,
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({}),
    };
    assert_eq!(s.submit(&n.id, &r).unwrap()["historical_only"], true);
    assert!(s.lease(&n).unwrap().is_some());
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET disabled=1", [])
        .unwrap();
    let token = s.reset_node_token(&n.id).unwrap();
    assert!(
        s.authenticate_node(&n.id, &token).is_err(),
        "rotation cannot enable a disabled node"
    );
}
#[test]
fn build_plans_manual_ip_retry_and_concurrency_share_one_pool() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    scheduler::save_policy(
        &s,
        &scheduler::Policy {
            per_node_concurrency: 1,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let c = CaseInput {
        key: "geo".into(),
        fingerprint: "fp".into(),
        kind: "geolocation".into(),
        subject: "1.1.1.0/24".into(),
        reason: "fixture disagreement".into(),
        payload: json!({"kind":"geolocation","family":4,"ranges":[["1.1.1.0","1.1.1.255"]],"regions":["us"],"targets":[]}),
    };
    let b = s.start_build().unwrap();
    s.commit_build(&b, "abc", &json!({}), std::slice::from_ref(&c), &[])
        .unwrap();
    let plans = scheduler::tasks(&s, 0, 10, "").unwrap();
    assert_eq!(plans["items"][0]["source"], "build");
    assert_eq!(plans["items"][0]["state"], "awaiting-target");
    s.connect().unwrap().execute("INSERT INTO responsive_targets VALUES('1.1.1.1',4,'00000000000000000000000001010101',?,'fixture')",[now()]).unwrap();
    assert_eq!(scheduler::discover_targets(&s).unwrap(), 1);
    assert_eq!(scheduler::discover_targets(&s).unwrap(), 0);
    let key = s
        .request_observation("8.8.8.8", &["us".into()], "temporary IP fixture", false)
        .unwrap();
    assert!(key.starts_with("ip:"));
    assert_eq!(scheduler::tasks(&s, 0, 10, "manual").unwrap()["total"], 1);
    assert!(
        s.request_observation("127.0.0.1", &["us".into()], "private rejected", false)
            .is_err()
    );
    let n = node("a");
    s.register_node(&n, &airroute_rules::hash("fixture"))
        .unwrap();
    s.update_node_settings(&n.id, "a", Some(1)).unwrap();
    let l = s.lease(&n).unwrap().unwrap();
    assert!(s.lease(&n).unwrap().is_none());
    let r = ProbeResult {
        id: "failed".into(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint,
        lease_token: l.token,
        observed_at: now(),
        outcome: "error".into(),
        evidence: json!({}),
    };
    s.submit(&n.id, &r).unwrap();
    let due: i64 = s
        .connect()
        .unwrap()
        .query_row("SELECT not_before FROM jobs WHERE id=?", [l.id], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(due >= now() + 110, "failure backoff is persisted");
    let b = s.start_build().unwrap();
    assert_eq!(
        s.commit_build(&b, "abc", &json!({}), &[c], &[]).unwrap()["reused"],
        1
    );
    assert_eq!(
        scheduler::tasks(&s, 0, 10, "manual").unwrap()["total"],
        1,
        "build preserves manual measurements"
    );
}
fn input(id: Option<String>, token: Option<String>) -> AccountInput {
    AccountInput {
        id,
        name: "fixture account".into(),
        token,
        enabled: true,
        regions: BTreeMap::from([("us".into(), "US".into())]),
    }
}
#[test]
fn account_crud_hides_credentials_and_retains_inflight_snapshots() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let base = Config::default();
    let a = globalping::save_account(&s, &base, input(None, Some("fixture-only-token".into())))
        .unwrap();
    let id = a["id"].as_str().unwrap().to_string();
    let status = globalping::status(&s, &base).unwrap();
    assert_eq!(status["accounts"][0]["credential_configured"], true);
    assert!(!status.to_string().contains("fixture-only-token"));
    assert!(!status.to_string().contains("credential_ref"));
    let old = globalping::effective(&s, &base).unwrap().accounts[0].clone();
    let old_ref = old.credential_ref.clone().unwrap();
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,account_snapshot) VALUES('job',?,'remote','{}',0,?)",rusqlite::params![id,serde_json::to_string(&old).unwrap()]).unwrap();
    globalping::save_account(
        &s,
        &base,
        input(Some(id.clone()), Some("new-fixture-only-token".into())),
    )
    .unwrap();
    assert!(
        airroute_rules::secrets::read(d.path(), &old_ref).is_ok(),
        "old credentials survive until submitted work drains"
    );
    globalping::delete_account(&s, &base, &id).unwrap();
    assert_eq!(
        globalping::status(&s, &base).unwrap()["accounts"],
        json!([])
    );
    assert!(airroute_rules::secrets::read(d.path(), &old_ref).is_ok());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(d.path().join("credentials").join(old_ref))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
#[test]
fn github_settings_defaults_and_input_boundaries() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    publish::initialize(d.path(), &s).unwrap();
    let v = publish::status(&s).unwrap();
    assert_eq!(v["settings"]["repository"], "example/rules");
    assert_eq!(v["settings"]["branch"], "main");
    assert_eq!(v["settings"]["enabled"], false);
    assert_eq!(publish::enqueue_current(&s).unwrap(), 0);
    for branch in [
        "--upload-pack=x",
        "../main",
        "main:other",
        "refs/heads/x.lock",
        "x\ny",
    ] {
        let mut v = publish::settings(&s).unwrap();
        v.branch = branch.into();
        assert!(publish::save_settings(&s, &v).is_err());
    }
}

#[test]
fn passive_anycast_notes_stay_in_the_manifest_and_cannot_start_a_probe() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = CaseInput {
        key: "partial-anycast".into(),
        fingerprint: "fp".into(),
        kind: "anycast-review".into(),
        subject: "1.1.1.0/24".into(),
        reason: "scope includes partial anycast".into(),
        payload: json!({"family":4,"regions":["us"],"ranges":[["1.1.1.0","1.1.1.255"]],"targets":[],"measurement_required":false}),
    };
    let b = s.start_build().unwrap();
    s.commit_build(&b, "fixture", &json!({}), std::slice::from_ref(&c), &[])
        .unwrap();
    assert_eq!(scheduler::tasks(&s, 0, 10, "").unwrap()["total"], 0);
    let artifact: String = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT path FROM build_artifacts WHERE build_id=?",
            [&b],
            |r| r.get(0),
        )
        .unwrap();
    let manifest =
        rusqlite::Connection::open(std::path::Path::new(&artifact).join("manifest.sqlite3"))
            .unwrap();
    let (payload, measurable): (String, bool) = manifest
        .query_row(
            "SELECT payload,measurable FROM cases WHERE key=?",
            [&c.key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&payload).unwrap(),
        c.payload
    );
    assert!(!measurable);
    assert!(
        s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
            .is_err()
    );
    assert!(s.plan_case(&c.key, &c.fingerprint, &c.payload).is_err());
    assert_eq!(s.list("cases", 0, 10, "").unwrap()["total"], 0);
    assert_eq!(s.jobs(0, 10).unwrap()["total"], 0);
}
#[test]
fn account_updates_wait_for_an_active_scheduler_without_losing_credentials() {
    use std::{sync::mpsc, time::Duration};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let base = Config::default();
    let a = globalping::save_account(&s, &base, input(None, Some("fixture-only-token".into())))
        .unwrap();
    let id = a["id"].as_str().unwrap().to_string();
    let lock = std::fs::File::create(s.path.with_extension("globalping.lock")).unwrap();
    lock.lock().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let copied = s.clone();
    let copied_id = id.clone();
    let writer = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        done_tx
            .send(globalping::save_account(
                &copied,
                &Config::default(),
                input(Some(copied_id), None),
            ))
            .unwrap();
    });
    started_rx.recv().unwrap();
    assert!(
        done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "the scheduler lock must still serialize credential changes"
    );
    lock.unlock().unwrap();
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    writer.join().unwrap();
    assert_eq!(
        globalping::status(&s, &base).unwrap()["accounts"][0]["credential_configured"],
        true
    );
}
