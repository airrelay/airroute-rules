use airroute_rules::{
    now,
    store::{Lease, Node, ProbeResult, Store},
};
use serde_json::json;

fn setup(store: &Store, id: &str, session: &str) -> Node {
    let node = Node {
        id: id.into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into(), "traceroute".into()],
    };
    store
        .register_node(&node, "dispatch-fixture-token-longer-than-24-characters")
        .unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,session_id=?,last_seen=? WHERE id=?",
            rusqlite::params![session, now(), id],
        )
        .unwrap();
    node
}
fn queue(store: &Store) {
    store
        .enqueue_observation("1.1.1.1", &["us".into()], "dispatch reservation fixture")
        .unwrap();
}
fn report(lease: &Lease) -> ProbeResult {
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target}]}),
    }
}
fn executions(store: &Store, id: &str) -> i64 {
    store
        .connect()
        .unwrap()
        .query_row("SELECT execution_count FROM jobs WHERE id=?", [id], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn a_started_lease_survives_disconnect_until_its_receipt_or_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let a = setup(&store, "a", "session-a");
    let b = setup(&store, "b", "session-b");
    queue(&store);
    let lease = store.lease_session(&a, "session-a").unwrap().unwrap();
    assert_eq!(
        executions(&store, &lease.id),
        0,
        "reservation is not execution"
    );
    assert!(store.begin_execution(&a.id, "session-a", &lease).unwrap());
    assert!(store.begin_execution(&a.id, "session-a", &lease).unwrap());
    assert_eq!(executions(&store, &lease.id), 1);
    store.set_node_enabled(&a.id, false).unwrap();
    assert!(
        store.lease_session(&b, "session-b").unwrap().is_none(),
        "uncertain local execution cannot be dispatched again immediately"
    );
    let row: (String, String) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,lease_token FROM jobs WHERE id=?",
            [&lease.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, ("leased".into(), lease.token.clone()));
    assert!(
        !store
            .heartbeat(&a.id, "session-a", &lease.id, &lease.token)
            .unwrap()
    );
    store.set_node_enabled(&a.id, true).unwrap();
    setup(&store, "a", "session-new");
    assert!(
        !store
            .heartbeat(&a.id, "session-a", &lease.id, &lease.token)
            .unwrap()
    );
    let result = report(&lease);
    assert_eq!(store.submit(&a.id, &result).unwrap()["accepted"], true);
    assert_eq!(store.submit(&a.id, &result).unwrap()["duplicate"], true);
    assert_eq!(executions(&store, &lease.id), 1);
    assert!(store.lease_session(&b, "session-b").unwrap().is_none());
}

#[test]
fn unsent_reservations_return_without_spending_an_execution() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let a = setup(&store, "a", "session-a");
    let b = setup(&store, "b", "session-b");
    queue(&store);
    let old = store.lease_session(&a, "session-a").unwrap().unwrap();
    store.set_node_enabled(&a.id, false).unwrap();
    let next = store.lease_session(&b, "session-b").unwrap().unwrap();
    assert_eq!(old.id, next.id);
    assert_ne!(old.token, next.token);
    assert_eq!(executions(&store, &next.id), 0);
    assert!(!store.begin_execution(&a.id, "session-a", &old).unwrap());
    assert!(store.begin_execution(&b.id, "session-b", &next).unwrap());
    assert_eq!(executions(&store, &next.id), 1);
}

#[test]
fn rotating_credentials_keeps_started_work_and_stale_heartbeats_cannot_add_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let a = setup(&store, "a", "session-a");
    store.update_node_settings(&a.id, "a", Some(1)).unwrap();
    queue(&store);
    let lease = store.lease_session(&a, "session-a").unwrap().unwrap();
    assert!(store.begin_execution(&a.id, "session-a", &lease).unwrap());
    store.reset_node_token(&a.id).unwrap();
    assert!(store.lease_session(&a, "session-a").unwrap().is_none());
    assert!(
        !store
            .heartbeat(&a.id, "wrong-session", &lease.id, &lease.token)
            .unwrap()
    );
    assert!(
        !store
            .heartbeat(&a.id, "session-a", &lease.id, &lease.token)
            .unwrap(),
        "credential rotation revokes the session immediately"
    );
    assert_eq!(executions(&store, &lease.id), 1);
}

#[test]
fn legacy_null_start_time_is_not_proof_that_a_lease_was_unsent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let a = setup(&store, "a", "session-a");
    queue(&store);
    let lease = store.lease_session(&a, "session-a").unwrap().unwrap();
    // Simulate an old controller: it dispatched without the new durable
    // start marker. Upgrade/reconnect must preserve this uncertainty.
    store.connect().unwrap().execute("UPDATE lease_history SET lease_profile=json_remove(lease_profile,'$.execution_reservation_schema'),started_at=NULL WHERE job_id=?", [&lease.id]).unwrap();
    store.set_node_enabled(&a.id, false).unwrap();
    let actual: (String, String, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,lease_token,lease_until FROM jobs WHERE id=?",
            [&lease.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(actual, ("leased".into(), lease.token, lease.until));
}
