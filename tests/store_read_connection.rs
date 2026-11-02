use airroute_rules::{
    hash,
    store::{Node, Store},
};
use rusqlite::params;

fn node(store: &Store) -> Node {
    let n = Node {
        id: "read-node".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&n, "old-read-fixture-credential-long-enough")
        .unwrap();
    n
}

#[test]
fn repeated_metadata_reads_and_clones_see_independent_commits_and_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let other = s.clone();
    assert_eq!(s.meta("first").unwrap(), None);
    let writer = s.connect().unwrap();
    writer
        .execute(
            "INSERT INTO meta(key,value) VALUES('first','one'),('second','two')",
            [],
        )
        .unwrap();
    assert_eq!(other.meta("first").unwrap().as_deref(), Some("one"));
    assert_eq!(s.meta("second").unwrap().as_deref(), Some("two"));
    assert_eq!(other.meta("missing").unwrap(), None);
    writer
        .execute("UPDATE meta SET value='updated' WHERE key='first'", [])
        .unwrap();
    assert_eq!(s.meta("first").unwrap().as_deref(), Some("updated"));
    writer
        .execute("DELETE FROM meta WHERE key='first'", [])
        .unwrap();
    assert_eq!(other.meta("first").unwrap(), None);
}

#[test]
fn authentication_and_capacity_do_not_cache_values_across_external_updates() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let n = node(&s);
    let other = s.clone();
    let old = "old-read-fixture-credential-long-enough";
    let new = "new-read-fixture-credential-long-enough";
    assert_eq!(s.authenticate_node(&n.id, old).unwrap().asn, 64501);
    assert_eq!(other.node_concurrency(&n.id).unwrap(), 10);
    let writer = s.connect().unwrap();
    writer.execute("UPDATE nodes SET token_hash=?,region='europe',asn=64502,capabilities='[\"dns\"]',concurrency_limit=37 WHERE id=?",params![hash(new),n.id]).unwrap();
    assert!(other.authenticate_node(&n.id, old).is_err());
    let actual = s.authenticate_node(&n.id, new).unwrap();
    assert_eq!(
        (actual.region, actual.asn, actual.capabilities),
        ("europe".into(), 64502, vec!["dns".to_string()])
    );
    assert_eq!(other.node_concurrency(&n.id).unwrap(), 37);
    writer
        .execute("UPDATE nodes SET disabled=1 WHERE id=?", [&n.id])
        .unwrap();
    assert!(s.authenticate_node(&n.id, new).is_err());
    writer
        .execute(
            "UPDATE nodes SET disabled=0,concurrency_limit=1 WHERE id=?",
            [&n.id],
        )
        .unwrap();
    assert!(other.authenticate_node(&n.id, new).is_ok());
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 1);
    let rotated = s.reset_node_token(&n.id).unwrap();
    assert!(other.authenticate_node(&n.id, new).is_err());
    assert!(other.authenticate_node(&n.id, &rotated).is_ok());
    writer
        .execute("DELETE FROM nodes WHERE id=?", [&n.id])
        .unwrap();
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 10);
    assert!(other.authenticate_node(&n.id, &rotated).is_err());
}

#[test]
fn completed_short_reads_do_not_pin_a_wal_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let reader = s.clone();
    s.set_meta("read-version", "0").unwrap();
    assert_eq!(reader.meta("read-version").unwrap().as_deref(), Some("0"));
    let mut writer = s.connect().unwrap();
    for n in 1..=12 {
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE meta SET value=? WHERE key='read-version'",
            [n.to_string()],
        )
        .unwrap();
        // A separate reader sees the committed version, never uncommitted data.
        assert_eq!(
            reader.meta("read-version").unwrap(),
            Some((n - 1).to_string())
        );
        tx.commit().unwrap();
        assert_eq!(s.meta("read-version").unwrap(), Some(n.to_string()));
    }
    let (busy, log, checkpointed): (i64, i64, i64) = writer
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(
        (busy, log, checkpointed),
        (0, 0, 0),
        "retained statements must not retain a read transaction"
    );
}

#[test]
fn a_public_path_change_cannot_reuse_the_other_database_reader() {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Store::open(a_dir.path()).unwrap();
    let b = Store::open(b_dir.path()).unwrap();
    a.set_meta("identity", "a").unwrap();
    b.set_meta("identity", "b").unwrap();
    let mut moved = a.clone();
    assert_eq!(moved.meta("identity").unwrap().as_deref(), Some("a"));
    moved.path = b.path.clone();
    assert_eq!(moved.meta("identity").unwrap().as_deref(), Some("b"));
    assert_eq!(a.meta("identity").unwrap().as_deref(), Some("a"));
    assert_eq!(moved.meta("identity").unwrap().as_deref(), Some("b"));
}
