//! End-to-end scheduler contracts. The v2 filename is retained for callers;
//! default per-node baseline copies were deliberately replaced by shared jobs.
use airroute_rules::{
    hash, now,
    store::{Lease, Node, ProbeResult, Store},
    work,
};
use rusqlite::params;
use serde_json::{Value, json};
fn node(s: &Store, id: &str, region: &str, v6: bool, limit: u32) -> Node {
    let n = Node {
        id: id.into(),
        region: region.into(),
        asn: 64500,
        capabilities: vec!["dns".into(), "traceroute".into()],
    };
    s.register_node(&n, &hash("fixture-token")).unwrap();
    s.connect().unwrap().execute("UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1,ipv6_supported=?,worker_capacity=1000,concurrency_limit=? WHERE id=?",params![now(),v6,limit,id]).unwrap();
    n
}
fn demand(s: &Store, key: &str, p: Value) {
    let c = s.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,?,'fixture','fixture demand',?,'needs-active',1,?)",params![key,p["kind"].as_str().unwrap_or("geolocation"),p.to_string(),now()]).unwrap();
    if p["measurement_required"] != false {
        work::plan_on(&c, key, "fp", &p).unwrap();
        work::mark_case(&c, key).unwrap();
    }
}
fn trace(target: &str) -> Value {
    json!({"kind":"geolocation","family":4,"targets":[target],"regions":["us","europe"],"ranges":[["1.1.1.0","1.1.1.255"]]})
}
fn receipt(l: &Lease) -> ProbeResult {
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target,"rtt_ms":1.0}]}),
    }
}
fn jobs(s: &Store) -> i64 {
    s.connect()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM jobs WHERE status<>'obsolete'",
            [],
            |r| r.get(0),
        )
        .unwrap()
}
#[test]
fn nodes_compete_for_one_observation_without_default_region_or_node_copies() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let us = node(&s, "us", "us", false, 10);
    let eu = node(&s, "eu", "europe", false, 10);
    demand(&s, "c", trace("1.1.1.1"));
    work::refresh(&s).unwrap();
    assert_eq!(jobs(&s), 1);
    let a = s.lease(&us).unwrap().unwrap();
    assert!(s.lease(&eu).unwrap().is_none());
    let ack = s.submit(&us.id, &receipt(&a)).unwrap();
    assert_eq!(ack["qualified"], true);
    work::refresh(&s).unwrap();
    assert!(s.lease(&eu).unwrap().is_none());
    assert_eq!(jobs(&s), 1);
}
#[test]
fn only_explicit_observer_regions_generate_distinct_work() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let us = node(&s, "us", "us", false, 10);
    let gp = node(&s, "globalping:fixture:europe", "europe", false, 10);
    let mut p = trace("1.1.1.1");
    p["observation_regions"] = json!(["us", "europe"]);
    demand(&s, "c", p);
    assert_eq!(jobs(&s), 2);
    let a = s.lease(&us).unwrap().unwrap();
    let b = s.lease(&gp).unwrap().unwrap();
    assert_eq!(a.region, "us");
    assert_eq!(b.region, "europe");
}
#[test]
fn busy_owned_observer_is_not_uncovered_but_shared_fallback_remains_available() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let us = node(&s, "us", "us", false, 1);
    let gp = node(&s, "globalping:fixture:us", "us", false, 10);
    for i in 1..=3 {
        let mut p = trace(&format!("1.1.1.{i}"));
        p["observation_regions"] = json!(["us"]);
        demand(&s, &format!("c{i}"), p);
    }
    assert!(s.lease(&us).unwrap().is_some());
    assert!(
        airroute_rules::jobs_v3::lease_with_admission_preference(&s, &gp, None, true, |_, _| Ok(
            true
        ))
        .unwrap()
        .is_none()
    );
    assert!(airroute_rules::jobs_v3::uncovered_scan_complete(&s, &gp));
    assert!(s.lease(&gp).unwrap().is_some());
}
#[test]
fn new_node_does_not_reopen_an_already_observed_question() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let us = node(&s, "us", "us", false, 10);
    demand(&s, "c", trace("1.1.1.1"));
    let a = s.lease(&us).unwrap().unwrap();
    s.submit(&us.id, &receipt(&a)).unwrap();
    let de = node(&s, "de", "europe", true, 10);
    work::mark_node_change(&s, Some(&de.id)).unwrap();
    work::refresh(&s).unwrap();
    assert!(s.lease(&de).unwrap().is_none());
    assert_eq!(jobs(&s), 1);
}
#[test]
fn repeated_idle_refresh_writes_no_semantic_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let _n = node(&s, "us", "us", false, 10);
    demand(&s, "c", trace("1.1.1.1"));
    work::refresh(&s).unwrap();
    let c = s.connect().unwrap();
    c.execute_batch("CREATE TABLE writes(kind TEXT);CREATE TRIGGER observe_case AFTER UPDATE ON cases BEGIN INSERT INTO writes VALUES('case');END;CREATE TRIGGER observe_job AFTER UPDATE ON jobs BEGIN INSERT INTO writes VALUES('job');END;CREATE TRIGGER observe_request AFTER UPDATE ON work_requests BEGIN INSERT INTO writes VALUES('request');END;CREATE TRIGGER observe_domain AFTER UPDATE ON discovery_domains BEGIN INSERT INTO writes VALUES('domain');END;").unwrap();
    for _ in 0..8 {
        work::refresh(&s).unwrap();
    }
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM writes", [], |r| r.get(0))
            .unwrap(),
        0
    );
}
#[test]
fn ipv6_incapable_nodes_do_not_spend_attempts() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "v4", "us", false, 10);
    demand(
        &s,
        "v6",
        json!({"kind":"geolocation","family":6,"targets":["2001:4860::8888"],"regions":["cn-geo","us"],"ranges":[["2001:4860::","2001:4860:ffff:ffff:ffff:ffff:ffff:ffff"]]}),
    );
    assert!(s.lease(&n).unwrap().is_none());
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT sum(attempt_seq) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        0
    );
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET ipv6_supported=1 WHERE id='v4'", [])
        .unwrap();
    assert!(s.lease(&n).unwrap().is_some());
}
#[test]
fn bounded_queue_pages_progress_beyond_a_large_ineligible_head() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    let mut c = s.connect().unwrap();
    let tx = c.transaction().unwrap();
    for i in 0..1200 {
        let key = format!("cn-{i:04}");
        let p = json!({"kind":"domain-observation","manual":true,"targets":[format!("n{i}.example.org")],"regions":["cn-geo"]});
        tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'domain-observation','x','paging',?,'needs-active',1,?)",params![key,p.to_string(),now()]).unwrap();
        work::plan_on(&tx, &key, "fp", &p).unwrap();
    }
    tx.commit().unwrap();
    demand(
        &s,
        "last",
        json!({"kind":"domain-observation","manual":true,"targets":["last.example.org"],"regions":["us"]}),
    );
    // Put all incompatible candidates before the valid one regardless of hash ID.
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET not_before=0 WHERE case_key<>'last'", [])
        .unwrap();
    let mut result = None;
    for _ in 0..4 {
        if let Some(l) = airroute_rules::jobs_v3::lease(&s, &n, None).unwrap() {
            result = Some(l);
            break;
        }
    }
    assert_eq!(result.unwrap().case_key, "last");
}
#[test]
fn necessary_asn_is_filtered_before_claiming() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut n = node(&s, "us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["required_asn"] = json!(64501);
    demand(&s, "c", p);
    assert!(s.lease(&n).unwrap().is_none());
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET asn=64501 WHERE id='us'", [])
        .unwrap();
    n.asn = 64501;
    assert!(s.lease(&n).unwrap().is_some());
}
#[test]
fn a_new_source_range_cannot_schedule_preserved_out_of_range_targets() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["ranges"] = json!([["1.1.2.0", "1.1.2.255"]]);
    demand(&s, "c", p);
    assert_eq!(jobs(&s), 0);
    assert!(s.lease(&n).unwrap().is_none());
}
#[test]
fn empty_target_range_waits_without_fake_traceroute() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["targets"] = json!([]);
    demand(&s, "c", p);
    assert_eq!(jobs(&s), 0);
    assert!(s.lease(&n).unwrap().is_none());
}
#[test]
fn node_limit_is_independent_and_accepts_one_thousand() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 1000);
    for i in 0..70 {
        demand(
            &s,
            &format!("c{i}"),
            json!({"kind":"domain-observation","manual":true,"targets":[format!("n{i}.example.org")],"regions":["us"]}),
        );
    }
    let mut count = 0;
    while airroute_rules::jobs_v3::lease(&s, &n, None)
        .unwrap()
        .is_some()
    {
        count += 1;
    }
    assert_eq!(count, 70);
}
#[test]
fn admission_rejection_does_not_advance_attempt_identity_or_persist_a_lease() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    demand(&s, "c", trace("1.1.1.1"));
    assert!(
        airroute_rules::jobs_v3::lease_with_admission(&s, &n, None, |_, _| Ok(false))
            .unwrap()
            .is_none()
    );
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(attempt_seq) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM lease_history", [], |r| r.get(0))
            .unwrap(),
        0
    );
}
#[test]
fn globalping_positive_asn_is_a_request_constraint_not_its_virtual_as_zero() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let gp = node(&s, "globalping:fixture:europe", "europe", false, 10);
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET asn=0 WHERE id=?", [&gp.id])
        .unwrap();
    let mut p = trace("1.1.1.1");
    p["required_asn"] = json!(64500);
    p["observation_regions"] = json!(["europe"]);
    demand(&s, "c", p);
    let l = s
        .lease(&gp)
        .unwrap()
        .expect("actual ASN must be requested and checked on returned probe");
    assert_eq!(l.profile["required_asn"], 64500);
}
#[test]
fn excluded_only_asn_requirement_does_not_spend_on_unselectable_remote_probes() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let gp = node(&s, "globalping:fixture:us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["excluded_asns"] = json!([64500]);
    demand(&s, "c", p);
    assert!(s.lease(&gp).unwrap().is_none());
    let n = node(&s, "us", "us", false, 10);
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET asn=64501 WHERE id='us'", [])
        .unwrap();
    assert!(s.lease(&n).unwrap().is_some());
}
#[test]
fn public_claim_does_not_run_or_acknowledge_the_planner() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    demand(&s, "c", trace("1.1.1.1"));
    let c = s.connect().unwrap();
    let before: i64 = c
        .query_row(
            "SELECT count(*) FROM replan_cases WHERE case_key='c'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, 1);
    assert!(s.lease(&n).unwrap().is_some());
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM replan_cases WHERE case_key='c'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        before,
        "claim must not hide planning work or acknowledge a pending change"
    );
}
#[test]
fn replacing_targets_retires_only_unsent_old_work_and_expiry_cannot_reopen_removed_targets() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["targets"] = json!(["1.1.1.1", "1.1.1.2"]);
    demand(&s, "c", p);
    let old = s.lease(&n).unwrap().unwrap();
    let c = s.connect().unwrap();
    s.targets("c", "fp", &["1.1.1.3".into()]).unwrap();
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT j.target FROM job_cases l JOIN jobs j ON j.id=l.job_id JOIN cases c ON c.key=l.case_key,json_each(c.payload,'$.targets') t WHERE l.case_key='c' AND t.value=j.target",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "1.1.1.3"
    );
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [&old.id], |r| r
            .get(0))
            .unwrap(),
        "leased"
    );
    let next = s.lease(&n).unwrap().unwrap();
    assert_eq!(next.target, "1.1.1.3");
    c.execute(
        "UPDATE jobs SET lease_until=? WHERE id=?",
        params![now() - 1, old.id],
    )
    .unwrap();
    airroute_rules::jobs_v3::expire_due(&s).unwrap();
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [&old.id], |r| r
            .get(0))
            .unwrap(),
        "obsolete"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT failure_count FROM jobs WHERE id=?",
            [&old.id],
            |r| r.get(0)
        )
        .unwrap(),
        0,
        "cancellation does not consume an execution failure budget"
    );
    assert!(s.lease(&n).unwrap().is_none());
}

#[test]
fn current_method_and_view_are_rechecked_before_dispatch_even_without_source_revision_change() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "us", "us", false, 10);
    let mut p = trace("1.1.1.1");
    p["observation_regions"] = json!(["us"]);
    p["protocol"] = json!("ICMP");
    p["max_hops"] = json!(3);
    demand(&s, "c", p.clone());
    let lease = s.lease(&n).unwrap().unwrap();
    assert_eq!(lease.profile["protocol"], "icmp");
    assert_eq!(lease.profile["max_hops"], 3);
    let c = s.connect().unwrap();
    p["observation_regions"] = json!(["europe"]);
    c.execute("UPDATE cases SET payload=? WHERE key='c'", [p.to_string()])
        .unwrap();
    assert!(
        airroute_rules::jobs_v3::current_case_links_on(&c, &lease.id)
            .unwrap()
            .is_empty()
    );
    assert!(!airroute_rules::jobs_v3::consume_execution_on(&c, &lease).unwrap());
    p["observation_regions"] = json!(["us"]);
    p["max_hops"] = json!(4);
    c.execute("UPDATE cases SET payload=? WHERE key='c'", [p.to_string()])
        .unwrap();
    assert!(!airroute_rules::jobs_v3::consume_execution_on(&c, &lease).unwrap());
    c.execute("UPDATE jobs SET status='pending',lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=?",[&lease.id]).unwrap();
    assert!(
        s.lease(&n).unwrap().is_none(),
        "stale method must not leave a dispatchable job"
    );
}

#[test]
fn equivalent_dns_types_and_asn_sets_share_identity_but_distinct_types_do_not() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = json!({"kind":"domain-observation","manual":true,"targets":["EXAMPLE.org."],"regions":["us"],"query_type":"aaaa","excluded_asns":[64502,64501,64502]});
    let b = json!({"kind":"domain-observation","manual":true,"targets":["example.org"],"regions":["us"],"query":{"type":"AAAA"},"excluded_asns":[64501,64502]});
    demand(&s, "dns-a", a);
    demand(&s, "dns-b", b.clone());
    assert_eq!(jobs(&s), 1);
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM job_cases", [], |r| r.get(0))
            .unwrap(),
        2
    );
    let mut other = b;
    other["query"]["type"] = json!("A");
    demand(&s, "dns-c", other);
    assert_eq!(jobs(&s), 2);
    let node = node(&s, "us", "us", false, 10);
    let lease = s.lease(&node).unwrap().unwrap();
    assert!(matches!(
        lease.profile["query_type"].as_str(),
        Some("A" | "AAAA")
    ));
}

#[test]
fn unsupported_trace_protocol_is_rejected_instead_of_silently_changed() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut p = trace("1.1.1.1");
    p["protocol"] = json!("udp");
    let c = s.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('bad','fp',1,'geolocation','x','bad method',?,'needs-active',1,?)",params![p.to_string(),now()]).unwrap();
    assert!(
        work::plan_on(&c, "bad", "fp", &p)
            .unwrap_err()
            .to_string()
            .contains("unsupported traceroute protocol")
    );
    assert_eq!(jobs(&s), 0);
}

#[test]
fn partial_manifest_defers_stale_planning_but_not_expiry_claims_or_receipts() {
    use airroute_rules::{build_delta, store::CaseInput};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node(&s, "self", "us", false, 10);
    let mut c = s.connect().unwrap();
    c.execute(
        "UPDATE nodes SET capabilities='[\"traceroute\"]' WHERE id='self'",
        [],
    )
    .unwrap();
    let tx = c.transaction().unwrap();
    let old = json!({"kind":"geolocation","family":4,"targets":[],"ranges":[["1.1.1.0","1.1.1.255"]],"measurement_required":true});
    for i in 0..256 {
        let key = format!("old-{i:04}");
        tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'geolocation','old source range','old queued demand',?,'blocked-target',1,?)",params![key,old.to_string(),now()]).unwrap();
        work::mark_case(&tx, &key).unwrap();
    }
    let (_, address) = airroute_rules::rules::addr_num("1.1.1.1".parse().unwrap());
    tx.execute("INSERT INTO responsive_targets(ip,family,address,last_seen,result_id) VALUES('1.1.1.1',4,?,?,'public-fixture')",params![format!("{address:032x}"),now()]).unwrap();
    tx.commit().unwrap();
    demand(
        &s,
        "live-manual",
        json!({"kind":"manual-ip","manual":true,"targets":["8.8.8.8"],"regions":["us"]}),
    );
    demand(
        &s,
        "dns-expiry",
        json!({"kind":"domain-observation","manual":true,"targets":["ttl.example.org"],"regions":["us"]}),
    );
    c.execute(
        "UPDATE jobs SET status='complete',execution_terminal=1,evidence_until=? WHERE kind='dns'",
        [now() - 60],
    )
    .unwrap();
    c.execute_batch("CREATE TABLE stale_work(kind TEXT);CREATE TRIGGER stale_target AFTER UPDATE OF payload ON cases WHEN OLD.key LIKE 'old-%' AND json_array_length(OLD.payload,'$.targets')=0 AND json_array_length(NEW.payload,'$.targets')>0 BEGIN INSERT INTO stale_work VALUES('discovery');END;CREATE TRIGGER stale_plan AFTER INSERT ON job_cases WHEN NEW.case_key LIKE 'old-%' BEGIN INSERT INTO stale_work VALUES('planning');END;").unwrap();
    let build = s.start_build().unwrap();
    let empty: Vec<CaseInput> = vec![];
    let path = build_delta::write_internal(
        s.path.parent().unwrap(),
        &build,
        None,
        "empty-public",
        &empty,
        &[],
        &json!({}),
    )
    .unwrap();
    build_delta::activate(&s, &build, "empty-public", &json!({}), &path).unwrap();
    let queued: i64 = c
        .query_row("SELECT count(*) FROM replan_cases", [], |r| r.get(0))
        .unwrap();
    let started = std::time::Instant::now();
    work::refresh(&s).unwrap();
    let first_ms = started.elapsed().as_secs_f64() * 1000.;
    let waste: i64 = c
        .query_row("SELECT count(*) FROM stale_work", [], |r| r.get(0))
        .unwrap();
    eprintln!(
        "partial-manifest first refresh {first_ms:.3}ms; obsolete discovery/planning writes={waste}"
    );
    assert_eq!(
        waste, 0,
        "old queued cases must not discover targets or generate work before the latest manifest retires them"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM replan_cases", [], |r| r.get(0))
            .unwrap(),
        queued,
        "the durable markers are preserved during synchronization"
    );
    assert_eq!(
        c.query_row::<(String, i64), _, _>(
            "SELECT status,round_seq FROM jobs WHERE kind='dns'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?))
        )
        .unwrap(),
        ("pending".into(), 2),
        "DNS expiration still runs before the sequencing guard"
    );
    let lease = s.lease(&n).unwrap().unwrap();
    assert_eq!(lease.target, "8.8.8.8");
    assert_eq!(
        s.submit(&n.id, &receipt(&lease)).unwrap()["qualified"],
        true,
        "direct claim and receipt remain available"
    );
    let mut sync_rounds = 0;
    while s.meta("build-sync-pending").unwrap().is_some() {
        assert!(sync_rounds < 32);
        build_delta::sync_current(&s, 32).unwrap();
        work::refresh(&s).unwrap();
        sync_rounds += 1;
    }
    for _ in 0..8 {
        work::refresh(&s).unwrap();
    }
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM cases WHERE key LIKE 'old-%' AND active=1",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM stale_work", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM replan_cases", [], |r| r.get(0))
            .unwrap(),
        0,
        "markers are acknowledged against the latest post-manifest state"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM job_cases WHERE case_key LIKE 'old-%'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    eprintln!(
        "partial-manifest full convergence {:.3}ms; sync batches={sync_rounds}",
        started.elapsed().as_secs_f64() * 1000.
    );
}
