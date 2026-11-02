use airroute_rules::{
    hash, jobs_v3, now,
    store::{Lease, Node, ProbeResult, Store},
    work,
};
use rusqlite::params;
use serde_json::json;

fn fixture(hosts: &[&str]) -> (tempfile::TempDir, Store, Node) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let node = Node {
        id: "discovery-observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into()],
    };
    store.register_node(&node, &hash("fixture-token")).unwrap();
    let c = store.connect().unwrap();
    c.execute(
        "UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1,concurrency_limit=1 WHERE id=?",
        params![now(), node.id],
    )
    .unwrap();
    let payload = json!({"kind":"geolocation","family":4,"targets":[],"ranges":[["8.8.4.0","8.8.4.255"]],"measurement_required":true});
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('waiting-range','fp',1,'geolocation','8.8.4.0/24','target discovery fixture',?,'blocked-target',1,?)",params![payload.to_string(),now()]).unwrap();
    for host in hosts {
        c.execute("INSERT INTO discovery_domains VALUES(?,0)", [host])
            .unwrap();
    }
    (dir, store, node)
}

fn complete_expired_dns(store: &Store, node: &Node, ttl: i64) -> (Lease, i64) {
    let lease = jobs_v3::lease(store, node, None).unwrap().unwrap();
    let observed = now() - ttl - 2;
    let result = ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: observed,
        outcome: "ok".into(),
        evidence: json!({"kind":"dns","hostname":lease.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":observed+ttl,"records":[{"name":lease.target,"type":"A","ttl":ttl,"data":"1.1.1.1"}]}]}),
    };
    let ack = store.submit(&node.id, &result).unwrap();
    assert_eq!(ack["accepted"], true);
    assert_eq!(ack["execution_class"], "observation");
    assert_eq!(ack["execution_terminal"], true);
    assert_eq!(ack["qualified"], false);
    (lease, observed + ttl)
}

fn state(store: &Store, id: &str) -> (String, i64, i64, i64, Option<i64>) {
    store
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,round_seq,attempt_seq,execution_count,evidence_until FROM jobs WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
}

#[test]
fn zero_and_short_ttl_discovery_progress_without_autonomous_renewal() {
    for ttl in [0, 1] {
        let (_dir, store, node) = fixture(&["a.example", "b.example"]);
        work::refresh(&store).unwrap();
        let (first, expiry) = complete_expired_dns(&store, &node, ttl);
        assert_eq!(first.target, "a.example");
        assert_eq!(
            jobs_v3::expire_due(&store).unwrap(),
            0,
            "discovery TTL {ttl} must expire evidence without reopening work"
        );
        work::refresh(&store).unwrap();
        assert_eq!(
            state(&store, &first.id),
            ("complete".into(), 1, 1, 1, Some(expiry))
        );
        let next = jobs_v3::lease(&store, &node, None).unwrap().unwrap();
        assert_eq!(next.target, "b.example");
        assert_ne!(next.id, first.id);
    }
}

#[test]
fn selecting_an_expired_discovery_host_reopens_the_same_job_once() {
    let (_dir, store, node) = fixture(&["only.example"]);
    work::refresh(&store).unwrap();
    let (first, _) = complete_expired_dns(&store, &node, 0);
    assert_eq!(jobs_v3::expire_due(&store).unwrap(), 0);
    // The cursor wraps only after exhausting later catalogue entries. Its due
    // check selects this host again, rather than an evidence timer doing so.
    work::refresh(&store).unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(state(&store, &first.id), ("pending".into(), 2, 1, 0, None));
    let second = jobs_v3::lease(&store, &node, None).unwrap().unwrap();
    assert_eq!(second.id, first.id);
    assert_ne!(second.token, first.token);
    assert_eq!(second.profile["attempt_seq"], 2);
    assert_eq!(second.profile["round_seq"], 2);
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn a_selected_expired_discovery_host_keeps_unknown_remote_and_leased_alias_fences() {
    for alias_state in ["unknown", "leased"] {
        let (_dir, store, node) = fixture(&["only.example"]);
        work::refresh(&store).unwrap();
        let (first, expiry) = complete_expired_dns(&store, &node, 0);
        let c = store.connect().unwrap();
        c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key,lease_node,lease_token,lease_until) SELECT 'old-alias',case_key,fp,kind,target,region,json_set(profile,'$.legacy_alias',1,'$.logical_job',0),?,not_before,created,logical_key,demand_key,'old-node','old-token',? FROM jobs WHERE id=?",params![alias_state,now()+180,first.id]).unwrap();
        if alias_state == "unknown" {
            c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('old-alias','old-account','',?,0)",[serde_json::to_string(&first).unwrap()]).unwrap();
        }
        work::refresh(&store).unwrap();
        work::refresh(&store).unwrap();
        assert_eq!(
            state(&store, &first.id),
            ("complete".into(), 1, 1, 1, Some(expiry)),
            "{alias_state} must fence renewal without resetting its budget"
        );
        assert!(jobs_v3::lease(&store, &node, None).unwrap().is_none());
        if alias_state == "unknown" {
            assert_eq!(
                c.query_row::<i64, _, _>(
                    "SELECT count(*) FROM gp_remote WHERE job_id='old-alias' AND remote_id=''",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
                1
            );
        }
    }
}

#[test]
fn a_manual_any_view_keeps_ttl_renewal_when_it_shares_an_older_discovery_job() {
    for discovery_first in [true, false] {
        let (dir, store, node) = fixture(&["shared.example"]);
        if discovery_first {
            work::refresh(&store).unwrap();
        }
        let manual = store
            .enqueue_observation("shared.example", &["any".into()], "manual DNS fixture")
            .unwrap();
        let c = store.connect().unwrap();
        if !discovery_first {
            let payload = json!({"kind":"target-discovery","targets":["shared.example"]});
            c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('discover:shared.example','discovery-fp',1,'target-discovery','shared.example','shared discovery fixture',?,'needs-active',1,?)",params![payload.to_string(),now()]).unwrap();
            work::plan_on(&c, "discover:shared.example", "discovery-fp", &payload).unwrap();
        }
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM job_cases", [], |r| r.get(0))
                .unwrap(),
            2
        );
        let (shared, _) = complete_expired_dns(&store, &node, 1);
        assert_eq!(
            c.query_row::<String, _, _>(
                "SELECT json_extract(profile,'$.purpose') FROM jobs WHERE id=?",
                [&shared.id],
                |r| r.get(0)
            )
            .unwrap(),
            if discovery_first {
                "discovery"
            } else {
                "manual"
            }
        );
        drop(c);
        drop(store);
        // Existing mixed-purpose jobs work after reopen without rewriting their
        // profile or introducing another logical identity in a migration.
        let store = Store::open(dir.path()).unwrap();
        let c = store.connect().unwrap();
        c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES(?,'old-account','',?,0)",params![shared.id,serde_json::to_string(&shared).unwrap()]).unwrap();
        assert_eq!(jobs_v3::expire_due(&store).unwrap(), 0);
        assert_eq!(state(&store, &shared.id).0, "complete");
        c.execute("DELETE FROM gp_remote WHERE job_id=?", [&shared.id])
            .unwrap();
        assert_eq!(
            jobs_v3::expire_due(&store).unwrap(),
            1,
            "an actual manual demand must retain TTL renewal regardless of first creator"
        );
        assert_eq!(state(&store, &shared.id), ("pending".into(), 2, 1, 0, None));
        complete_expired_dns(&store, &node, 1);
        store
            .connect()
            .unwrap()
            .execute("UPDATE cases SET active=0 WHERE key=?", [manual])
            .unwrap();
        assert_eq!(jobs_v3::expire_due(&store).unwrap(), 0);
        assert_eq!(state(&store, &shared.id).0, "complete");
    }
}

#[test]
fn expired_discovery_history_does_not_fill_the_ordinary_dns_deadline_index() {
    let (_dir, store, _) = fixture(&[]);
    let mut c = store.connect().unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<1000) INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,evidence_until) SELECT 'history-'||i,'history','fp','dns','host-'||i||'.example','any','{\"logical_job\":true,\"purpose\":\"discovery\"}','complete',0,0,0 FROM n",[]).unwrap();
    let payload = json!({"kind":"domain-observation","manual":true,"targets":["manual.example"],"regions":["us"]});
    tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('ordinary','fp',1,'domain-observation','manual.example','ordinary TTL fixture',?,'needs-active',1,?)",params![payload.to_string(),now()]).unwrap();
    work::plan_on(&tx, "ordinary", "fp", &payload).unwrap();
    tx.execute(
        "UPDATE jobs SET status='complete',evidence_until=0 WHERE case_key='ordinary'",
        [],
    )
    .unwrap();
    tx.commit().unwrap();

    // Use the same partial-index predicate as autonomous DNS expiry. The old
    // discovery history contributes neither entries nor scan steps to it.
    let mut q = c.prepare("SELECT id FROM jobs INDEXED BY job_regular_dns_due WHERE status='complete' AND kind='dns' AND evidence_until IS NOT NULL AND json_extract(profile,'$.logical_job')=1 AND coalesce(json_extract(profile,'$.purpose'),'')<>'discovery' AND evidence_until<=? ORDER BY evidence_until,id LIMIT 128").unwrap();
    let due = q
        .query_map([now()], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(q.get_status(rusqlite::StatementStatus::FullscanStep), 0);
    assert!(q.get_status(rusqlite::StatementStatus::VmStep) < 100);
    drop(q);
    // More than a deadline page of jobs first created by manual demand may
    // outlive that demand while still linked to discovery. They must not
    // occupy the first page and starve the genuinely active manual job.
    let tx = c.transaction().unwrap();
    tx.execute("UPDATE jobs SET profile=json_set(profile,'$.purpose','manual') WHERE id IN (SELECT id FROM jobs WHERE id LIKE 'history-%' ORDER BY id LIMIT 140)",[]).unwrap();
    tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) SELECT 'history-discovery','fp',1,'target-discovery','history','removed manual demand fixture',json_object('kind','target-discovery','targets',json_group_array(target)),'needs-active',1,0 FROM jobs WHERE id LIKE 'history-%' AND json_extract(profile,'$.purpose')='manual'",[]).unwrap();
    tx.execute("INSERT INTO job_cases(job_id,case_key,fp,revision) SELECT id,'history-discovery','fp',1 FROM jobs WHERE id LIKE 'history-%' AND json_extract(profile,'$.purpose')='manual'",[]).unwrap();
    tx.commit().unwrap();
    assert_eq!(jobs_v3::expire_due(&store).unwrap(), 1);
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM jobs WHERE id LIKE 'history-%' AND status='complete' AND round_seq=1",[],|r|r.get(0)).unwrap(),1000);
}

#[test]
fn catalogue_revisit_reopens_a_manual_first_job_after_its_manual_demand_stops() {
    let (_dir, store, node) = fixture(&["shared.example"]);
    let manual = store
        .enqueue_observation("shared.example", &["any".into()], "manual first")
        .unwrap();
    let payload = json!({"kind":"target-discovery","targets":["shared.example"]});
    let c = store.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('discover:shared.example','initial',1,'target-discovery','shared.example','fixture',?,'needs-active',1,?)",params![payload.to_string(),now()]).unwrap();
    work::plan_on(&c, "discover:shared.example", "initial", &payload).unwrap();
    let (first, _) = complete_expired_dns(&store, &node, 0);
    c.execute("UPDATE cases SET active=0 WHERE key=?", [manual])
        .unwrap();
    assert_eq!(jobs_v3::expire_due(&store).unwrap(), 0);
    work::refresh(&store).unwrap();
    assert_eq!(state(&store, &first.id), ("pending".into(), 2, 1, 0, None));
    let next = store.lease(&node).unwrap().unwrap();
    assert_eq!(next.id, first.id);
    assert_ne!(next.token, first.token);
}

#[test]
fn completed_discovery_receipt_acknowledges_its_marker_without_replanning_unchanged_work() {
    let (_dir, store, node) = fixture(&["a.example", "b.example"]);
    work::refresh(&store).unwrap();
    let (first, _) = complete_expired_dns(&store, &node, 0);
    let c = store.connect().unwrap();
    assert!(
        c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM replan_cases WHERE case_key='discover:a.example')",
            [],
            |r| r.get(0)
        )
        .unwrap()
    );
    c.execute_batch("CREATE TABLE plan_attempts(n INTEGER); CREATE TRIGGER count_existing_discovery_plan BEFORE INSERT ON jobs WHEN NEW.target='a.example' BEGIN INSERT INTO plan_attempts VALUES(1); END;").unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM plan_attempts", [], |r| r.get(0))
            .unwrap(),
        0,
        "an unchanged completed discovery receipt must not prepare its logical job again"
    );
    assert!(
        !c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM replan_cases WHERE case_key='discover:a.example')",
            [],
            |r| r.get(0)
        )
        .unwrap()
    );
    assert_eq!(state(&store, &first.id).1, 1);
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE target='b.example' AND status='pending'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );

    // A missing link must still take the durable recovery path. Failed repair
    // rolls back its acknowledgement; the next pass can repair the same marker.
    c.execute("DELETE FROM job_cases WHERE job_id=?", [&first.id])
        .unwrap();
    work::mark_case(&c, "discover:a.example").unwrap();
    c.execute_batch("CREATE TRIGGER reject_recovered_link BEFORE INSERT ON job_cases WHEN NEW.case_key='discover:a.example' BEGIN SELECT RAISE(ABORT,'injected discovery repair failure'); END;").unwrap();
    assert!(
        work::refresh(&store)
            .unwrap_err()
            .to_string()
            .contains("injected discovery repair failure")
    );
    assert!(
        c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM replan_cases WHERE case_key='discover:a.example')",
            [],
            |r| r.get(0)
        )
        .unwrap()
    );
    c.execute_batch("DROP TRIGGER reject_recovered_link")
        .unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM job_cases WHERE job_id=? AND case_key='discover:a.example'",
            [first.id],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn catalogue_cursor_survives_restart_and_build_change_before_wrapping_to_old_hosts() {
    let (dir, store, node) = fixture(&["a.example", "b.example"]);
    store.set_meta("current-build-id", "first-build").unwrap();
    work::refresh(&store).unwrap();
    let (first, _) = complete_expired_dns(&store, &node, 1);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.set_meta("current-build-id", "next-build").unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(state(&store, &first.id).1, 1);
    let (second, _) = complete_expired_dns(&store, &node, 0);
    assert_eq!(second.target, "b.example");
    work::refresh(&store).unwrap();
    assert_eq!(state(&store, &first.id), ("pending".into(), 2, 1, 0, None));
    assert_eq!(state(&store, &second.id).1, 1);
    assert_eq!(
        store.meta("shared-dns-host-cursor").unwrap().as_deref(),
        Some("a.example")
    );
}

#[test]
fn each_catalogue_fill_is_bounded_even_when_live_capacity_is_larger() {
    let (_dir, store, node) = fixture(&[]);
    store
        .update_node_settings(&node.id, "large fixture", Some(1000))
        .unwrap();
    let mut c = store.connect().unwrap();
    let tx = c.transaction().unwrap();
    for n in 0..300 {
        tx.execute(
            "INSERT INTO discovery_domains VALUES(?,0)",
            [format!("host-{n:03}.example")],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    for expected in [128, 256, 300, 300] {
        work::refresh(&store).unwrap();
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
                .unwrap(),
            expected
        );
    }
    assert_eq!(
        store.meta("shared-dns-host-cursor").unwrap().as_deref(),
        Some("host-299.example")
    );
}

#[test]
fn fresh_shared_dns_reuse_keeps_original_expiry_and_rejects_another_method() {
    let (_dir, store, node) = fixture(&["shared.example"]);
    work::refresh(&store).unwrap();
    let lease = store.lease(&node).unwrap().unwrap();
    let observed = now();
    let result = ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: observed,
        outcome: "ok".into(),
        evidence: json!({"kind":"dns","hostname":lease.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":observed+60,"records":[{"name":lease.target,"type":"A","query_type":"A","ttl":60,"data":"1.1.1.1"}]}]}),
    };
    assert_eq!(store.submit(&node.id, &result).unwrap()["qualified"], true);
    let manual = store
        .enqueue_observation("shared.example", &["any".into()], "matching manual demand")
        .unwrap();
    let c = store.connect().unwrap();
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT job_id FROM job_cases WHERE case_key=?",
            [manual],
            |r| r.get(0)
        )
        .unwrap(),
        lease.id
    );
    assert_eq!(state(&store, &lease.id).4, Some(observed + 60));
    for (key, extra) in [
        ("other-type", json!({"query_type":"AAAA"})),
        ("other-transport", json!({"protocol":"tcp"})),
    ] {
        let mut payload = json!({"kind":"domain-observation","manual":true,"targets":["shared.example"],"regions":["any"]});
        payload
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'domain-observation','shared.example','method fixture',?,'needs-active',1,?)",params![key,payload.to_string(),now()]).unwrap();
        work::plan_on(&c, key, "fp", &payload).unwrap();
        let job: String = c
            .query_row(
                "SELECT job_id FROM job_cases WHERE case_key=?",
                [key],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(job, lease.id);
        assert_eq!(
            state(&store, &job).0,
            "pending",
            "wrong method evidence must not complete {key}"
        );
    }
    assert_eq!(state(&store, &lease.id).4, Some(observed + 60));
}

#[test]
fn shared_dns_exhaustion_needs_both_cooldown_and_a_fresh_build_to_reset_three_opportunities() {
    let (_dir, store, first_node) = fixture(&["shared.example"]);
    store.set_meta("current-build-id", "first-build").unwrap();
    work::refresh(&store).unwrap();
    let mut nodes = vec![first_node];
    for i in 1..4 {
        let node = Node {
            id: format!("executor-{i}"),
            region: "us".into(),
            asn: 64501 + i,
            capabilities: vec!["dns".into()],
        };
        store.register_node(&node, &hash("fixture-token")).unwrap();
        store
            .connect()
            .unwrap()
            .execute(
                "UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1 WHERE id=?",
                params![now(), node.id],
            )
            .unwrap();
        nodes.push(node);
    }
    let mut id = String::new();
    for node in &nodes[..3] {
        store
            .connect()
            .unwrap()
            .execute("UPDATE jobs SET not_before=0 WHERE status='pending'", [])
            .unwrap();
        let lease = store.lease(node).unwrap().unwrap();
        id = lease.id.clone();
        let result = ProbeResult {
            id: uuid::Uuid::new_v4().to_string(),
            job_id: lease.id,
            fingerprint: lease.fingerprint,
            lease_token: lease.token,
            observed_at: now(),
            outcome: "error".into(),
            evidence: json!({"error":"fixture resolver received no response"}),
        };
        assert_eq!(
            store.submit(&node.id, &result).unwrap()["execution_class"],
            "executor-failure"
        );
    }
    assert_eq!(state(&store, &id).0, "unknown");
    assert_eq!(state(&store, &id).3, 3);
    let manual = store
        .enqueue_observation("shared.example", &["any".into()], "same exhausted demand")
        .unwrap();
    assert!(store.lease(&nodes[3]).unwrap().is_none());
    store.set_meta("current-build-id", "next-build").unwrap();
    let c = store.connect().unwrap();
    work::mark_case_from_build(&c, &manual, "next-build").unwrap();
    work::refresh(&store).unwrap();
    assert_eq!((state(&store, &id).1, state(&store, &id).3), (1, 3));
    c.execute(
        "UPDATE jobs SET next_round_at=? WHERE id=?",
        params![now() - 1, id],
    )
    .unwrap();
    work::mark_case(&c, &manual).unwrap();
    work::refresh(&store).unwrap();
    assert_eq!((state(&store, &id).1, state(&store, &id).3), (1, 3));
    work::mark_case_from_build(&c, &manual, "next-build").unwrap();
    work::refresh(&store).unwrap();
    assert_eq!((state(&store, &id).1, state(&store, &id).3), (2, 0));
    assert_eq!(store.lease(&nodes[3]).unwrap().unwrap().id, id);
}
