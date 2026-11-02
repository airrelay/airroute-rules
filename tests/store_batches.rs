use airroute_rules::{
    network::NetworkSupport,
    now,
    store::{Lease, Node, Store},
};
use rusqlite::params;

fn fixture(count: u32) -> (tempfile::TempDir, Store, Node, Vec<Lease>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let node = Node {
        id: "batch-node".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, "batch-fixture-credentials-longer-than-24")
        .unwrap();
    store
        .update_node_settings(&node.id, "batch node", Some(count.max(1)))
        .unwrap();
    store.connect().unwrap().execute(
        "UPDATE nodes SET connected=1,session_id='current',last_seen=?,ipv4_supported=1,ipv6_supported=0 WHERE id=?",
        params![now()-60,node.id],
    ).unwrap();
    for n in 1..=count {
        store
            .enqueue_observation(&format!("1.1.1.{n}"), &["us".into()], "batch fixture")
            .unwrap();
    }
    let leases = (0..count)
        .map(|_| store.lease_session(&node, "current").unwrap().unwrap())
        .collect();
    (dir, store, node, leases)
}

fn identities(store: &Store) -> Vec<(String, i64, i64, Option<String>, String)> {
    store
        .connect()
        .unwrap()
        .prepare("SELECT id,attempt_seq,execution_count,lease_token,status FROM jobs ORDER BY id")
        .unwrap()
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn heartbeat_batch_renews_only_matching_live_leases_without_granting_capacity() {
    let (_dir, store, node, leases) = fixture(24);
    let at = now();
    let c = store.connect().unwrap();
    c.execute("UPDATE jobs SET lease_until=?", [at + 30])
        .unwrap();
    c.execute(
        "UPDATE jobs SET lease_until=? WHERE id=?",
        params![at - 1, leases[20].id],
    )
    .unwrap();
    c.execute(
        "UPDATE jobs SET lease_node='someone-else' WHERE id=?",
        [&leases[23].id],
    )
    .unwrap();
    let before = identities(&store);
    let mut active: Vec<_> = leases[..22]
        .iter()
        .map(|l| (l.id.clone(), l.token.clone()))
        .collect();
    active[21].1 = "wrong-token".into();
    // Lease 22 is omitted; lease 23 belongs to another executor.
    active.push((leases[23].id.clone(), leases[23].token.clone()));
    assert!(
        store
            .heartbeat_batch(
                &node.id,
                "current",
                &active,
                Some(&NetworkSupport {
                    ipv4: true,
                    ipv6: true
                })
            )
            .unwrap()
    );
    assert_eq!(identities(&store), before);
    for (i, lease) in leases.iter().enumerate() {
        let until: i64 = c
            .query_row(
                "SELECT lease_until FROM jobs WHERE id=?",
                [&lease.id],
                |r| r.get(0),
            )
            .unwrap();
        if i < 20 {
            assert!(
                until >= at + 180,
                "matching live lease {i} should be renewed"
            );
        } else {
            assert_eq!(
                until,
                if i == 20 { at - 1 } else { at + 30 },
                "expired, wrong, omitted or foreign lease {i} must not renew"
            );
        }
    }
    let row: (i64, bool, bool) = c
        .query_row(
            "SELECT last_seen,ipv4_supported,ipv6_supported FROM nodes WHERE id=?",
            [&node.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert!(row.0 >= at);
    assert_eq!((row.1, row.2), (true, true));
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM lease_history WHERE started_at IS NOT NULL",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn stale_or_empty_heartbeat_does_not_renew_unreported_work_or_overwrite_new_session() {
    let (_dir, store, node, leases) = fixture(1);
    let c = store.connect().unwrap();
    let until = now() + 30;
    c.execute("UPDATE jobs SET lease_until=?", [until]).unwrap();
    let active = vec![(leases[0].id.clone(), leases[0].token.clone())];
    assert!(
        !store
            .heartbeat_batch(
                &node.id,
                "old-session",
                &active,
                Some(&NetworkSupport {
                    ipv4: false,
                    ipv6: true
                })
            )
            .unwrap()
    );
    assert_eq!(
        c.query_row::<(bool, bool), _, _>(
            "SELECT ipv4_supported,ipv6_supported FROM nodes WHERE id=?",
            [&node.id],
            |r| Ok((r.get(0)?, r.get(1)?))
        )
        .unwrap(),
        (true, false)
    );
    assert!(
        store
            .heartbeat_batch(&node.id, "current", &[], None)
            .unwrap()
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT lease_until FROM jobs WHERE id=?",
            [&leases[0].id],
            |r| r.get(0)
        )
        .unwrap(),
        until
    );
    store.reset_node_token(&node.id).unwrap();
    assert!(
        !store
            .heartbeat_batch(
                &node.id,
                "current",
                &active,
                Some(&NetworkSupport {
                    ipv4: false,
                    ipv6: true
                })
            )
            .unwrap()
    );
}

#[test]
fn heartbeat_batch_rolls_back_node_and_earlier_lease_updates_on_failure() {
    let (_dir, store, node, leases) = fixture(2);
    let c = store.connect().unwrap();
    let at = now();
    c.execute("UPDATE jobs SET lease_until=?", [at + 30])
        .unwrap();
    let before: (i64, bool, bool) = c
        .query_row(
            "SELECT last_seen,ipv4_supported,ipv6_supported FROM nodes WHERE id=?",
            [&node.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    c.execute_batch(&format!("CREATE TRIGGER fail_batch BEFORE UPDATE OF lease_until ON jobs WHEN OLD.id='{}' BEGIN SELECT RAISE(ABORT,'injected batch failure'); END;",leases[1].id)).unwrap();
    let active = leases
        .iter()
        .map(|l| (l.id.clone(), l.token.clone()))
        .collect::<Vec<_>>();
    assert!(
        store
            .heartbeat_batch(
                &node.id,
                "current",
                &active,
                Some(&NetworkSupport {
                    ipv4: false,
                    ipv6: true
                })
            )
            .is_err()
    );
    assert_eq!(
        c.query_row::<(i64, bool, bool), _, _>(
            "SELECT last_seen,ipv4_supported,ipv6_supported FROM nodes WHERE id=?",
            [&node.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        )
        .unwrap(),
        before
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE lease_until<>?",
            [at + 30],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn send_admission_rechecks_reduced_capacity_and_returns_only_unsent_reservation() {
    let (_dir, store, node, leases) = fixture(2);
    assert!(
        store
            .begin_execution_with_capacity(&node.id, "current", &leases[0], 0)
            .unwrap()
    );
    store
        .update_node_settings(&node.id, "batch node", Some(1))
        .unwrap();
    assert!(
        !store
            .begin_execution_with_capacity(&node.id, "current", &leases[1], 1)
            .unwrap()
    );
    let c = store.connect().unwrap();
    let first: (String, Option<String>, i64) = c
        .query_row(
            "SELECT status,lease_token,execution_count FROM jobs WHERE id=?",
            [&leases[0].id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(first, ("leased".into(), Some(leases[0].token.clone()), 1));
    let second: (String, Option<String>, i64) = c
        .query_row(
            "SELECT status,lease_token,execution_count FROM jobs WHERE id=?",
            [&leases[1].id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(second, ("pending".into(), None, 0));
    // Once started, even a later over-capacity callback must retain its lease.
    assert!(
        !store
            .begin_execution_with_capacity(&node.id, "current", &leases[0], 1)
            .unwrap()
    );
    assert_eq!(
        c.query_row::<Option<String>, _, _>(
            "SELECT lease_token FROM jobs WHERE id=?",
            [&leases[0].id],
            |r| r.get(0)
        )
        .unwrap(),
        Some(leases[0].token.clone())
    );
}

#[test]
fn stale_send_callback_cannot_release_a_new_session_attempt() {
    let (_dir, store, node, leases) = fixture(1);
    let c = store.connect().unwrap();
    c.execute(
        "UPDATE nodes SET session_id='replacement' WHERE id=?",
        [&node.id],
    )
    .unwrap();
    assert!(
        !store
            .begin_execution_with_capacity(&node.id, "current", &leases[0], 0)
            .unwrap()
    );
    let replacement = store.lease_session(&node, "replacement").unwrap().unwrap();
    assert_ne!(replacement.token, leases[0].token);
    assert!(
        !store
            .begin_execution_with_capacity(&node.id, "current", &leases[0], 0)
            .unwrap()
    );
    assert_eq!(
        c.query_row::<Option<String>, _, _>(
            "SELECT lease_token FROM jobs WHERE id=?",
            [&replacement.id],
            |r| r.get(0)
        )
        .unwrap(),
        Some(replacement.token.clone())
    );
    assert!(
        store
            .begin_execution_with_capacity(&node.id, "replacement", &replacement, 0)
            .unwrap()
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT execution_count FROM jobs WHERE id=?",
            [&replacement.id],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}
