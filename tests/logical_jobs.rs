use airroute_rules::{
    hash, now,
    store::{Node, Store},
    work,
};
use rusqlite::params;
use serde_json::json;
fn node(s: &Store, id: &str) -> Node {
    let n = Node {
        id: id.into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["dns".into(), "traceroute".into()],
    };
    s.register_node(&n, &hash("fixture")).unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1 WHERE id=?",
            params![now(), id],
        )
        .unwrap();
    n
}
fn case(s: &Store) {
    let p = json!({"kind":"geolocation","family":4,"targets":["1.1.1.1"],"regions":["us","europe"],"ranges":[["1.1.1.0","1.1.1.255"]]});
    let c = s.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('c','fp',1,'geolocation','x','legacy case',?,'needs-active',1,?)",params![p.to_string(),now()]).unwrap();
    work::plan_on(&c, "c", "fp", &p).unwrap();
    work::mark_case(&c, "c").unwrap();
}
#[test]
fn old_physical_lease_and_unknown_fence_the_shared_demand_even_after_source_change() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = node(&s, "old");
    let b = node(&s, "new");
    case(&s);
    let l = s.lease(&a).unwrap().unwrap();
    let c = s.connect().unwrap();
    let profile = json!({"scheduler":2,"case_revision":1,"purpose":"baseline","observer_id":"old","self_only":true,"preferred_regions":["us","europe"],"protocol":"icmp","max_hops":24});
    c.execute("UPDATE jobs SET id='legacy-physical-id',profile=?,logical_key='',demand_key='',attempt_seq=0 WHERE id=?",params![profile.to_string(),l.id]).unwrap();
    c.execute(
        "UPDATE job_cases SET job_id='legacy-physical-id' WHERE job_id=?",
        [&l.id],
    )
    .unwrap();
    c.execute(
        "UPDATE lease_history SET job_id='legacy-physical-id',attempt_seq=0 WHERE job_id=?",
        [&l.id],
    )
    .unwrap();
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('legacy-physical-id','old-account','',?,0)",[serde_json::to_string(&l).unwrap()]).unwrap();
    c.execute("DELETE FROM meta WHERE key='shared-logical-jobs-v3'", [])
        .unwrap();
    work::migrate(&s).unwrap();
    work::refresh(&s).unwrap();
    assert!(
        s.lease(&b).unwrap().is_none(),
        "a canonical ID must not bypass the old paid/leased alias"
    );
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT lease_token FROM jobs WHERE id='legacy-physical-id'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        l.token
    );
    let seq: i64 = c
        .query_row(
            "SELECT attempt_seq FROM jobs WHERE id='legacy-physical-id'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(seq > 0);
    assert_eq!(c.query_row::<i64,_,_>("SELECT attempt_seq FROM lease_history WHERE job_id='legacy-physical-id' AND token_hash=?",[hash(&l.token)],|r|r.get(0)).unwrap(),seq);
    c.execute(
        "UPDATE jobs SET status='unknown' WHERE id='legacy-physical-id'",
        [],
    )
    .unwrap();
    c.execute("UPDATE cases SET fp='changed',revision=2 WHERE key='c'", [])
        .unwrap();
    work::refresh(&s).unwrap();
    assert!(
        s.lease(&b).unwrap().is_none(),
        "refresh/source fingerprint must not bypass unknown intent"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote WHERE job_id='legacy-physical-id'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
}
#[test]
fn migration_can_repeat_without_rewriting_current_jobs_or_namespaces() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "a");
    case(&s);
    let l = s.lease(&n).unwrap().unwrap();
    let c = s.connect().unwrap();
    let before:String=c.query_row("SELECT json_array(id,profile,status,attempt_seq,lease_node,lease_token,lease_until,logical_key,demand_key) FROM jobs WHERE id=?",[&l.id],|r|r.get(0)).unwrap();
    for _ in 0..3 {
        work::migrate(&s).unwrap();
    }
    let after:String=c.query_row("SELECT json_array(id,profile,status,attempt_seq,lease_node,lease_token,lease_until,logical_key,demand_key) FROM jobs WHERE id=?",[&l.id],|r|r.get(0)).unwrap();
    assert_eq!(before, after);
}
#[test]
fn expired_closed_dns_rows_do_not_starve_live_expiry_behind_the_first_page() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "a");
    let mut c = s.connect().unwrap();
    let tx = c.transaction().unwrap();
    for i in 0..140 {
        let key = format!("d{i:03}");
        let p = json!({"kind":"domain-observation","manual":true,"targets":[format!("n{i}.example.org")],"regions":["us"]});
        tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'domain-observation','x','expiry fixture',?,'needs-active',1,?)",params![key,p.to_string(),now()]).unwrap();
        work::plan_on(&tx, &key, "fp", &p).unwrap();
        tx.execute("UPDATE jobs SET status='complete',execution_terminal=1,evidence_until=? WHERE case_key=?",params![now()-1000+i,key]).unwrap();
        if i < 139 {
            tx.execute("UPDATE cases SET status='decided' WHERE key=?", [key])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 1);
    let l = airroute_rules::jobs_v3::lease(&s, &n, None)
        .unwrap()
        .unwrap();
    assert_eq!(l.case_key, "d139");
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='pending'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn finished_old_alias_cannot_race_a_pending_canonical_copy() {
    use airroute_rules::store::ProbeResult;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = node(&s, "old");
    let b = node(&s, "new");
    case(&s);
    let l = s.lease(&a).unwrap().unwrap();
    let c = s.connect().unwrap();
    let profile = json!({"scheduler":2,"case_revision":1,"purpose":"baseline","observer_id":"old","self_only":true,"protocol":"icmp","max_hops":24});
    c.execute("UPDATE jobs SET id='legacy-inflight',profile=?,logical_key='',demand_key='',attempt_seq=0 WHERE id=?",params![profile.to_string(),l.id]).unwrap();
    c.execute(
        "UPDATE job_cases SET job_id='legacy-inflight' WHERE job_id=?",
        [&l.id],
    )
    .unwrap();
    c.execute(
        "UPDATE lease_history SET job_id='legacy-inflight',attempt_seq=0 WHERE job_id=?",
        [l.id],
    )
    .unwrap();
    c.execute("DELETE FROM meta WHERE key='shared-logical-jobs-v3'", [])
        .unwrap();
    work::migrate(&s).unwrap();
    work::refresh(&s).unwrap();
    let result = ProbeResult {
        id: "legacy-finished".into(),
        job_id: "legacy-inflight".into(),
        fingerprint: l.fingerprint,
        lease_token: l.token,
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target,"rtt_ms":1}]}),
    };
    assert_eq!(s.submit(&a.id, &result).unwrap()["qualified"], true);
    assert!(
        airroute_rules::jobs_v3::lease(&s, &b, None)
            .unwrap()
            .is_none(),
        "claim fence applies before planner consumes the completion event"
    );
    work::refresh(&s).unwrap();
    assert!(s.lease(&b).unwrap().is_none());
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='pending'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}
#[test]
fn legacy_ok_is_rechecked_and_a_previous_success_does_not_exhaust_failure_budget() {
    use airroute_rules::store::ProbeResult;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "old");
    case(&s);
    let l = s.lease(&n).unwrap().unwrap();
    let r = ProbeResult {
        id: "old-success".into(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target,"rtt_ms":1}]}),
    };
    s.submit(&n.id, &r).unwrap();
    let c = s.connect().unwrap();
    c.execute("UPDATE jobs SET profile=json_remove(profile,'$.logical_job'),execution_terminal=0,failure_count=3 WHERE id=?",[&l.id]).unwrap();
    c.execute("UPDATE results SET qualified=0 WHERE id='old-success'", [])
        .unwrap();
    s.set_meta("observation-country-regions", "{\"US\":\"us\"}")
        .unwrap();
    assert_eq!(airroute_rules::jobs_v3::requalify_legacy(&s).unwrap(), 1);
    assert_eq!(
        c.query_row::<(i64, i64), _, _>(
            "SELECT execution_terminal,failure_count FROM jobs WHERE id=?",
            [l.id],
            |r| Ok((r.get(0)?, r.get(1)?))
        )
        .unwrap(),
        (1, 0)
    );
    assert_eq!(
        airroute_rules::jobs_v3::requalify_legacy(&s).unwrap(),
        0,
        "requalification is rerunnable and preserves receipts"
    );
}
#[test]
fn legacy_local_evidence_without_attempt_scope_is_not_reconstructed_from_current_node() {
    use airroute_rules::store::ProbeResult;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "old");
    case(&s);
    let l = s.lease(&n).unwrap().unwrap();
    let r = ProbeResult {
        id: "missing-old-scope".into(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint,
        lease_token: l.token,
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target,"rtt_ms":1}]}),
    };
    s.submit(&n.id, &r).unwrap();
    let c = s.connect().unwrap();
    c.execute("UPDATE jobs SET profile=json_remove(profile,'$.logical_job'),execution_terminal=0 WHERE id=?",[&l.id]).unwrap();
    c.execute(
        "UPDATE results SET qualified=0 WHERE id='missing-old-scope'",
        [],
    )
    .unwrap();
    c.execute(
        "UPDATE lease_history SET lease_profile=NULL WHERE job_id=?",
        [&l.id],
    )
    .unwrap();
    c.execute(
        "UPDATE nodes SET region='europe',asn=64500 WHERE id='old'",
        [],
    )
    .unwrap();
    s.set_meta(
        "observation-country-regions",
        "{\"US\":\"us\",\"DE\":\"europe\"}",
    )
    .unwrap();
    assert_eq!(airroute_rules::jobs_v3::requalify_legacy(&s).unwrap(), 0);
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT qualified FROM results WHERE id='missing-old-scope'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT execution_terminal FROM jobs WHERE id=?",
            [l.id],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
}

#[test]
fn migrated_alias_history_exits_progress_but_leases_and_unknown_intents_remain_visible() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "observer");
    case(&s);
    let c = s.connect().unwrap();
    for (id, state) in [
        ("legacy-complete", "complete"),
        ("legacy-local", "leased"),
        ("legacy-remote", "unknown"),
    ] {
        c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key,lease_node,lease_token,lease_until) SELECT ?,case_key,fp,kind,target,region,json_remove(json_set(profile,'$.legacy_alias',1,'$.logical_job',0),'$.scheduler'),?,not_before,created,logical_key,demand_key,'observer','legacy-token',? FROM jobs WHERE json_extract(profile,'$.logical_job')=1 LIMIT 1",params![id,state,now()+180]).unwrap();
        c.execute("INSERT INTO job_cases(job_id,case_key,fp,revision,required_round_seq) SELECT ?,case_key,fp,revision,required_round_seq FROM job_cases WHERE case_key='c' LIMIT 1",[id]).unwrap();
    }
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('legacy-remote','old-account','','{}',0)",[]).unwrap();
    assert_eq!(
        c.query_row::<(i64, i64, i64), _, _>(
            "SELECT total,running,completed FROM task_job_totals WHERE case_key='c'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        )
        .unwrap(),
        (3, 1, 0),
        "canonical plus only two in-flight aliases, completed physical history is excluded"
    );
    c.execute(
        "UPDATE jobs SET status='complete' WHERE id='legacy-local'",
        [],
    )
    .unwrap();
    let items = airroute_rules::scheduler::task_items(&s, 0, 30, "").unwrap();
    assert_eq!(items["items"].as_array().unwrap().len(), 1);
    assert_eq!(items["items"][0]["blocking_reason"], "等待既有远端提交确认");
    assert!(s.lease(&n).unwrap().is_none());
    c.execute("DELETE FROM gp_remote WHERE job_id='legacy-remote'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<(i64, i64, i64), _, _>(
            "SELECT total,running,completed FROM task_job_totals WHERE case_key='c'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        )
        .unwrap(),
        (1, 0, 0)
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE json_extract(profile,'$.legacy_alias')=1",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        3,
        "history rows remain"
    );
    assert!(s.lease(&n).unwrap().is_some());
    let old = s.path.clone();
    drop(c);
    drop(s);
    let reopened = Store::open(old.parent().unwrap()).unwrap();
    assert_eq!(
        reopened
            .connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT total FROM task_job_totals WHERE case_key='c'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        1,
        "projection migration is idempotent"
    );
}

#[test]
fn dns_alias_expiries_do_not_reopen_or_starve_the_canonical_observation() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "observer");
    s.enqueue_observation(
        "fixture.example",
        &["us".into()],
        "canonical DNS expiry fixture",
    )
    .unwrap();
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET status='complete',execution_terminal=1,evidence_until=?",
        [now() - 1],
    )
    .unwrap();
    for i in 0..300 {
        c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key,evidence_until,execution_terminal) SELECT ?,case_key,fp,kind,target,region,json_set(profile,'$.legacy_alias',1,'$.logical_job',0),'complete',not_before,created,logical_key,demand_key,?,1 FROM jobs WHERE json_extract(profile,'$.logical_job')=1 LIMIT 1",params![format!("old-dns-{i}"),now()-1000]).unwrap();
    }
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 1);
    let l = s.lease(&n).unwrap().unwrap();
    assert_eq!(l.profile["logical_job"], true);
    assert!(airroute_rules::jobs_v3::expire_due(&s).unwrap() == 0);
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM jobs WHERE json_extract(profile,'$.legacy_alias')=1 AND status='complete'",[],|r|r.get(0)).unwrap(),300);
}

#[test]
fn an_expired_legacy_local_lease_is_retired_when_the_canonical_job_exists() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "observer");
    case(&s);
    let c = s.connect().unwrap();
    c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key,lease_node,lease_token,lease_until) SELECT 'old-inflight',case_key,fp,kind,target,region,json_set(profile,'$.legacy_alias',1,'$.logical_job',0),'leased',not_before,created,logical_key,demand_key,'observer','old-token',? FROM jobs WHERE json_extract(profile,'$.logical_job')=1 LIMIT 1",[now()-1]).unwrap();
    assert!(s.lease(&n).unwrap().is_none());
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 1);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id='old-inflight'", [], |r| r
            .get(0))
            .unwrap(),
        "obsolete"
    );
    assert!(s.lease(&n).unwrap().is_some());
}

#[test]
fn exhausted_round_needs_cooldown_and_a_fresh_daily_proof() {
    use airroute_rules::store::ProbeResult;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.set_meta("current-build-id", "build-one").unwrap();
    let nodes: Vec<_> = (0..3).map(|i| node(&s, &format!("n{i}"))).collect();
    case(&s);
    let mut id = String::new();
    for n in &nodes {
        s.connect()
            .unwrap()
            .execute("UPDATE jobs SET not_before=0 WHERE status='pending'", [])
            .unwrap();
        let lease = s.lease(n).unwrap().unwrap();
        id = lease.id.clone();
        let mut c = s.connect().unwrap();
        let tx = c.transaction().unwrap();
        assert!(airroute_rules::jobs_v3::consume_execution_on(&tx, &lease).unwrap());
        tx.commit().unwrap();
        let r = ProbeResult {
            id: uuid::Uuid::new_v4().to_string(),
            job_id: lease.id,
            fingerprint: lease.fingerprint,
            lease_token: lease.token,
            observed_at: now(),
            outcome: "error".into(),
            evidence: json!({"error":"fixture executor failed before usable response"}),
        };
        s.submit(&n.id, &r).unwrap();
    }
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id=?", [&id], |r| r
            .get(0))
            .unwrap(),
        3
    );
    s.set_meta("current-build-id", "build-two").unwrap();
    work::mark_case_from_build(&c, "c", "build-two").unwrap();
    work::refresh(&s).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT round_seq FROM jobs WHERE id=?", [&id], |r| r.get(0))
            .unwrap(),
        1,
        "fresh build alone cannot bypass 24h cooldown"
    );
    c.execute(
        "UPDATE jobs SET next_round_at=? WHERE id=?",
        params![now() - 1, id],
    )
    .unwrap();
    work::mark_case(&c, "c").unwrap();
    work::refresh(&s).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT round_seq FROM jobs WHERE id=?", [&id], |r| r.get(0))
            .unwrap(),
        1,
        "ordinary event cannot invent a new round"
    );
    work::mark_case_from_build(&c, "c", "build-two").unwrap();
    work::refresh(&s).unwrap();
    assert_eq!(
        c.query_row::<(i64, i64), _, _>(
            "SELECT round_seq,execution_count FROM jobs WHERE id=?",
            [&id],
            |r| Ok((r.get(0)?, r.get(1)?))
        )
        .unwrap(),
        (2, 0)
    );
    work::mark_case_from_build(&c, "c", "build-two").unwrap();
    work::refresh(&s).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT round_seq FROM jobs WHERE id=?", [id], |r| r.get(0))
            .unwrap(),
        2
    );
}

#[test]
fn legacy_recheck_skips_unscoped_native_history_but_keeps_scoped_native_and_provider_receipts() {
    use airroute_rules::store::ProbeResult;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let native = node(&s, "scoped-native");
    node(&s, "unscoped-native");
    node(&s, "globalping:legacy:us");
    case(&s);
    let l = s.lease(&native).unwrap().unwrap();
    let r = ProbeResult {
        id: "z-scoped-native".into(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token,
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target,"rtt_ms":1}]}),
    };
    s.submit(&native.id, &r).unwrap();
    let mut c = s.connect().unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("UPDATE jobs SET profile=json_remove(profile,'$.logical_job'),execution_terminal=0 WHERE id=?",[&l.id]).unwrap();
    tx.execute("UPDATE results SET qualified=0 WHERE id=?", [&r.id])
        .unwrap();
    // More than one page of large bodies with no original attempt scope. They
    // remain history and must not hide later native/provider candidates.
    for i in 0..300 {
        tx.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received) VALUES(?,?,'unscoped-native',?,?,'ok',?,1,?)",params![format!("a-unscoped-{i:03}"),l.id,l.fingerprint,now(),"untrusted history ".repeat(256),now()]).unwrap();
    }
    for (id, country) in [("z-provider-good", "US"), ("z-provider-wrong", "DE")] {
        let body = json!({"measurement":{"type":"traceroute","target":l.target,"measurementOptions":{"protocol":"ICMP"},"results":[{"probe":{"country":country,"asn":64500},"result":{"status":"finished","resolvedAddress":l.target,"hops":[{"resolvedAddress":l.target,"timings":[{"rtt":1.0}]}]}}]}});
        tx.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received) VALUES(?,?,'globalping:legacy:us',?,?,'ok',?,1,?)",params![id,l.id,l.fingerprint,now(),body.to_string(),now()]).unwrap();
    }
    // Require the actual US view; requested/virtual GP region is not proof.
    tx.execute(
        "UPDATE jobs SET region='us',profile=json_set(profile,'$.region_required',json('true')) WHERE id=?",
        [&l.id],
    )
    .unwrap();
    tx.commit().unwrap();
    s.set_meta(
        "observation-country-regions",
        "{\"US\":\"us\",\"DE\":\"europe\"}",
    )
    .unwrap();
    assert_eq!(airroute_rules::jobs_v3::requalify_legacy(&s).unwrap(), 2);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM results WHERE qualified=1", [], |r| r
            .get(0))
            .unwrap(),
        2
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT qualified FROM results WHERE id='z-provider-wrong'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
            .unwrap(),
        303
    );
    assert_eq!(airroute_rules::jobs_v3::requalify_legacy(&s).unwrap(), 0);
}

#[test]
fn dns_jobs_share_normalized_queries_but_separate_transport_and_observer_conditions() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = s.connect().unwrap();
    let methods = [
        json!({"query":{"type":"aaaa"},"protocol":"UDP"}),
        json!({"query_type":"AAAA","protocol":"udp"}),
        json!({"query_type":"A","protocol":"udp"}),
        json!({"query_type":"AAAA","protocol":"tcp"}),
        json!({"query_type":"AAAA","protocol":"udp","required_asn":64512}),
        json!({"query_type":"AAAA","protocol":"udp","excluded_asns":[64513,64512,64513]}),
        json!({"query_type":"AAAA","protocol":"udp","excluded_asns":[64512,64513]}),
    ];
    let mut ids = vec![];
    for (i, method) in methods.into_iter().enumerate() {
        let key = format!("query-{i}");
        let mut payload = json!({"kind":"domain-observation","manual":true,"targets":["query.example"],"regions":["any"]});
        payload
            .as_object_mut()
            .unwrap()
            .extend(method.as_object().unwrap().clone());
        c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'domain-observation','query.example','identity fixture',?,'needs-active',1,?)",params![key,payload.to_string(),now()]).unwrap();
        work::plan_on(&c, &key, "fp", &payload).unwrap();
        ids.push(
            c.query_row::<String, _, _>(
                "SELECT job_id FROM job_cases WHERE case_key=?",
                [key],
                |r| r.get(0),
            )
            .unwrap(),
        );
    }
    assert_eq!(
        ids[0], ids[1],
        "query spelling and type placement are not different observations"
    );
    for (i, id) in ids.iter().enumerate().take(6).skip(2) {
        assert_ne!(
            &ids[0], id,
            "method/observer condition {i} must remain isolated"
        );
    }
    assert_eq!(
        ids[5], ids[6],
        "excluded ASN order/duplicates do not change the condition"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        5
    );
}
