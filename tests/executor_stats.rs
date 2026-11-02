use airroute_rules::{
    globalping::{self, Account, Config},
    now,
    store::{Lease, Node, ProbeResult, Store},
};
use serde_json::json;

fn node(store: &Store, id: &str, region: &str) -> Node {
    let node = Node {
        id: id.into(),
        region: region.into(),
        asn: 0,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, &airroute_rules::hash("fixture credentials"))
        .unwrap();
    node
}
fn lease(store: &Store, node: &Node, target: &str) -> Lease {
    store
        .enqueue_observation(
            target,
            std::slice::from_ref(&node.region),
            "statistics fixture",
        )
        .unwrap();
    store.lease(node).unwrap().unwrap()
}
fn receipt(lease: &Lease, id: &str, outcome: &str) -> ProbeResult {
    ProbeResult {
        id: id.into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: now() - 600,
        outcome: outcome.into(),
        evidence: if lease.profile["observer"]["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("globalping:"))
        {
            let country = if lease.region == "europe" { "DE" } else { "US" };
            json!({"measurement":{"type":"traceroute","target":lease.target,"measurementOptions":{"protocol":"ICMP"},"results":[{"probe":{"country":country,"asn":64500},"result":{"status":"finished","resolvedAddress":lease.target,"hops":[{"resolvedAddress":lease.target,"timings":[{"rtt":1.0}]}]}}]}})
        } else {
            json!({"kind":"traceroute","target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target}]})
        },
    }
}

#[test]
fn self_node_counts_unique_successes_and_live_leases_and_backfills_history() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "node-one", "us");
    let l = lease(&s, &n, "1.1.1.1");
    assert_eq!(s.nodes().unwrap()[0]["running_tasks"], 1);
    assert_eq!(s.nodes().unwrap()[0]["completed_tasks"], 0);
    assert!(s.nodes().unwrap()[0]["last_completed_at"].is_null());
    let r = receipt(&l, "success", "ok");
    let received = now();
    assert_eq!(s.submit(&n.id, &r).unwrap()["accepted"], true);
    assert_eq!(s.nodes().unwrap()[0]["completed_tasks"], 1);
    assert_eq!(s.nodes().unwrap()[0]["running_tasks"], 0);
    assert!(
        s.nodes().unwrap()[0]["last_completed_at"].as_i64().unwrap() >= received,
        "completion time is receipt acceptance, not the older observation time"
    );
    assert_eq!(s.submit(&n.id, &r).unwrap()["duplicate"], true);
    assert_eq!(
        s.submit(&n.id, &receipt(&l, "late", "ok")).unwrap()["historical_only"],
        true
    );
    assert_eq!(s.nodes().unwrap()[0]["completed_tasks"], 1);
    let failed = lease(&s, &n, "8.8.8.8");
    s.submit(&n.id, &receipt(&failed, "failure", "error"))
        .unwrap();
    assert_eq!(s.nodes().unwrap()[0]["completed_tasks"], 1);
    assert!(
        s.lease(&n).unwrap().is_none(),
        "an execution fault cools this observer"
    );
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET executor_cooldown_until=0 WHERE id=?",
            [&n.id],
        )
        .unwrap();
    let l = lease(&s, &n, "9.9.9.9");
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET lease_until=? WHERE id=?",
            rusqlite::params![now() - 1, l.id],
        )
        .unwrap();
    assert_eq!(s.nodes().unwrap()[0]["running_tasks"], 0);
    // Simulate the first upgrade from a database containing historical receipts.
    // Reopening a previously initialized store must not re-scan history every time.
    s.connect()
        .unwrap()
        .execute_batch("DELETE FROM executor_counters; DELETE FROM meta WHERE key='executor-counters-backfilled-v1';")
        .unwrap();
    drop(s);
    let s = Store::open(d.path()).unwrap();
    assert_eq!(s.nodes().unwrap()[0]["completed_tasks"], 1);
    assert_eq!(s.nodes().unwrap()[0]["running_tasks"], 0);
}

#[test]
fn globalping_aggregates_all_regions_per_account_without_prefix_or_group_leakage() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.set_meta(
        "observation-country-regions",
        &json!({"US":"us","DE":"europe"}).to_string(),
    )
    .unwrap();
    let us = node(&s, "globalping:acct_one:us", "us");
    let eu = node(&s, "globalping:acct_one:europe", "europe");
    let other = node(&s, "globalping:acct:us", "us");
    for (n, target, id) in [
        (&us, "1.1.1.1", "us-complete"),
        (&eu, "8.8.8.8", "eu-complete"),
        (&other, "9.9.9.9", "other-complete"),
    ] {
        let l = lease(&s, n, target);
        s.submit(&n.id, &receipt(&l, id, "ok")).unwrap();
    }
    let l = lease(&s, &us, "4.4.4.4");
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES(?,'acct_one','remote-active',?,?)",rusqlite::params![l.id,serde_json::to_string(&l).unwrap(),now()+30]).unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET lease_until=? WHERE id=?",
            rusqlite::params![now() - 1, l.id],
        )
        .unwrap();
    let config = Config {
        accounts: ["acct", "acct_one"]
            .map(|id| Account {
                id: id.into(),
                ..Account::default()
            })
            .into(),
        ..Config::default()
    };
    let rows = globalping::status(&s, &config).unwrap();
    let a = &rows["accounts"][0];
    let b = &rows["accounts"][1];
    assert_eq!(a["id"], "acct");
    assert_eq!(a["completed_tasks"], 1);
    assert_eq!(a["running_tasks"], 0);
    assert_eq!(b["completed_tasks"], 2);
    assert_eq!(b["running_tasks"], 1);
    assert!(!b["last_completed_at"].is_null());
    s.connect()
        .unwrap()
        .execute("UPDATE gp_remote SET remote_id=''", [])
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET status='unknown' WHERE id=?", [l.id])
        .unwrap();
    assert_eq!(
        globalping::status(&s, &config).unwrap()["accounts"][1]["running_tasks"],
        0,
        "uncertain creation is not a confirmed running measurement"
    );
    drop(s);
    let s = Store::open(d.path()).unwrap();
    assert_eq!(
        globalping::status(&s, &config).unwrap()["accounts"][1]["completed_tasks"],
        2
    );
}
