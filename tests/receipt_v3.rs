use airroute_rules::{
    now,
    receipt::{qualify, submit},
    store::{Lease, Node, ProbeResult, Store},
};
use serde_json::{Value, json};

fn node() -> Node {
    Node {
        id: "observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into(), "traceroute".into()],
    }
}
fn lease(kind: &str) -> Lease {
    Lease {
        id: "j".into(),
        case_key: "c".into(),
        fingerprint: "fp".into(),
        kind: kind.into(),
        target: if kind == "dns" {
            "fixture.example"
        } else {
            "1.1.1.1"
        }
        .into(),
        region: "us".into(),
        token: "token-one".into(),
        until: now() + 180,
        profile: json!({"case_revision":1,"region_required":true,"protocol":if kind=="dns"{Value::Null}else{json!("icmp")},"attempt_seq":1,"observer":{"id":"observer","region":"us","asn":64501}}),
    }
}
fn evidence(kind: &str) -> Value {
    if kind == "dns" {
        json!({"kind":"dns","hostname":"fixture.example","resolvers":[{"transport":"udp","response_received":true,"observed_at":now(),"valid_until":now()+60,"records":[{"name":"fixture.example","type":"A","ttl":60,"data":"1.1.1.1"}]}]})
    } else {
        json!({"kind":"traceroute","target":"1.1.1.1","protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":"1.1.1.1"}]})
    }
}
fn result(l: &Lease) -> ProbeResult {
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: evidence(&l.kind),
    }
}
fn fixture(kind: &str) -> (tempfile::TempDir, Store, Lease) {
    let temp = tempfile::tempdir().unwrap();
    let s = Store::open(temp.path()).unwrap();
    let n = node();
    s.register_node(&n, "fixture-token-longer-than-twenty-four")
        .unwrap();
    let mut l = lease(kind);
    l.profile["logical_job"] = json!(true);
    l.profile["scheduler"] = json!(2);
    l.profile["round_seq"] = json!(1);
    let c = s.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES('c','fp',1,'domain-observation','fixture','fixture',?,'needs-active',1,?)",rusqlite::params![json!({"kind":if kind=="dns"{"domain-observation"}else{"manual-ip"},"manual":true,"regions":["us"],"targets":[l.target]}).to_string(),now()]).unwrap();
    c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,attempts,lease_node,lease_token,lease_until,created,attempt_seq,failure_count,logical_key) VALUES('j','c','fp',?,?,?,?, 'leased',?,1,'observer','token-one',?,?,1,0,'logical')",rusqlite::params![l.kind,l.target,l.region,l.profile.to_string(),now(),now()+180,now()]).unwrap();
    c.execute(
        "INSERT INTO job_cases(job_id,case_key,fp,revision) VALUES('j','c','fp',1)",
        [],
    )
    .unwrap();
    c.execute("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,lease_profile) VALUES('j',?,'observer','fp',?,1,?)",rusqlite::params![airroute_rules::hash(&l.token),now(),l.profile.to_string()]).unwrap();
    (temp, s, l)
}

#[tokio::test]
async fn only_actionable_receipts_wake_dispatch_and_duplicates_do_not_write() {
    let (_t, s, l) = fixture("dns");
    let r = result(&l);
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(submit(&s, "observer", &r).unwrap()["accepted"], true);
    tokio::time::timeout(std::time::Duration::from_millis(100), notified)
        .await
        .expect("completion releases real capacity");

    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let before = s
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM results", [], |r| r.get::<_, i64>(0))
        .unwrap();
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(40), notified)
            .await
            .is_err()
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row("SELECT count(*) FROM results", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );

    // Authenticated old history with no usable evidence changes no executable
    // capacity and has no discovery or replan work to announce.
    let mut old = result(&l);
    old.outcome = "error".into();
    old.evidence = json!({"error":"old command failed"});
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(
        submit(&s, "observer", &old).unwrap()["historical_only"],
        true
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(40), notified)
            .await
            .is_err()
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row("SELECT count(*) FROM results", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before + 1
    );
}

#[tokio::test]
async fn late_qualified_receipt_wakes_a_durable_replan_without_completing_new_lease() {
    let (_t, s, l) = fixture("traceroute");
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET attempt_seq=2,lease_token='new-token'", [])
        .unwrap();
    let r = result(&l);
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(submit(&s, "observer", &r).unwrap()["historical_only"], true);
    tokio::time::timeout(std::time::Duration::from_millis(100), notified)
        .await
        .expect("new durable replan is actionable");
    let row: (String, i64, String, i64) = s.connect().unwrap().query_row("SELECT status,attempt_seq,lease_token,(SELECT count(*) FROM replan_cases WHERE case_key='c') FROM jobs WHERE id='j'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(row, ("leased".into(), 2, "new-token".into(), 1));
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(40), notified)
            .await
            .is_err()
    );
}

#[test]
fn native_dns_response_codes_do_not_turn_resolver_errors_or_alias_nxdomain_into_positive_evidence()
{
    let mut l = lease("dns");
    l.profile["query_type"] = json!("A");
    let mut r = result(&l);
    r.evidence["resolvers"][0]["records"] = json!([]);
    for code in [0, 3] {
        r.evidence["resolvers"][0]["rcodes"] =
            json!([{"name":l.target,"query_type":"A","code":code}]);
        let q = qualify(&l, &node(), &r);
        assert!(
            q.execution_terminal,
            "actual empty reply {code}: {}",
            q.reason
        );
        assert!(!q.qualified);
        assert_eq!(q.evidence_until, None);
        assert_eq!(q.class, airroute_rules::receipt::ResultClass::Observation);
    }
    for (code, label) in [(2, "SERVFAIL"), (5, "REFUSED")] {
        r.evidence["resolvers"][0]["rcodes"] =
            json!([{"name":l.target,"query_type":"A","code":code}]);
        let q = qualify(&l, &node(), &r);
        assert!(!q.execution_terminal, "{label}");
        assert_eq!(
            q.class,
            airroute_rules::receipt::ResultClass::ExecutorFailure
        );
        assert!(q.reason.contains("SERVFAIL or REFUSED"));
        assert_eq!(q.evidence_until, None);
    }
    r.evidence["resolvers"][0]["rcodes"] = json!([{"name":l.target,"query_type":"A","code":3}]);
    r.evidence["resolvers"][0]["records"] =
        json!([{"name":l.target,"query_type":"A","type":"CNAME","ttl":3600,"data":"gone.example"}]);
    let q = qualify(&l, &node(), &r);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(
        q.evidence_until, None,
        "NXDOMAIN CNAME TTL is not a positive address lifetime"
    );
    // Legacy string-only empty answers do not prove the requested actual type.
    r.evidence["resolvers"][0]["records"] = json!([]);
    r.evidence["resolvers"][0]["rcodes"] = json!(["Non-Existent Domain"]);
    assert!(!qualify(&l, &node(), &r).execution_terminal);
    l.profile["query_type"] = Value::Null;
    assert!(qualify(&l, &node(), &r).execution_terminal);
    r.evidence["resolvers"][0]["rcodes"] = json!(["Server Failure"]);
    assert!(!qualify(&l, &node(), &r).execution_terminal);
    // One failed auxiliary query does not erase an independently successful
    // address query from the same actual response collection.
    r.evidence["resolvers"][0]["rcodes"] = json!([
        {"name":l.target,"query_type":"A","code":0},
        {"name":l.target,"query_type":"AAAA","code":2}
    ]);
    r.evidence["resolvers"][0]["records"] = json!([
        {"name":l.target,"query_type":"A","type":"A","ttl":60,"data":"1.1.1.1"},
        {"name":l.target,"query_type":"AAAA","type":"AAAA","ttl":1,"data":"2606:4700:4700::1111"}
    ]);
    let q = qualify(&l, &node(), &r);
    assert!(q.qualified);
    assert_eq!(
        q.evidence_until,
        Some(r.observed_at + 60),
        "failed query cannot supply TTL"
    );
    r.evidence["resolvers"][0]["rcodes"] = json!([
        {"name":l.target,"query_type":"A","code":0},
        {"name":"alias.example","query_type":"A","code":2}
    ]);
    r.evidence["resolvers"][0]["records"] = json!([
        {"name":l.target,"query_name":l.target,"query_type":"A","type":"CNAME","ttl":60,"data":"alias.example"},
        {"name":"alias.example","query_name":l.target,"query_type":"A","type":"A","ttl":60,"data":"1.1.1.1"},
        {"name":"alias.example","query_name":"alias.example","query_type":"A","type":"A","ttl":1,"data":"8.8.8.8"}
    ]);
    let q = qualify(&l, &node(), &r);
    assert!(q.qualified);
    assert_eq!(
        q.evidence_until,
        Some(r.observed_at + 60),
        "same-type failed follow-up must not supply TTL"
    );
}

#[test]
fn qualified_mixed_dns_receipt_imports_only_its_successful_query_addresses() {
    let (_t, s, l) = fixture("dns");
    let mut r = result(&l);
    r.evidence["resolvers"][0]["rcodes"] = json!([
        {"name":l.target,"query_type":"A","code":0},
        {"name":l.target,"query_type":"AAAA","code":2}
    ]);
    r.evidence["resolvers"][0]["records"] = json!([
        {"name":l.target,"query_name":l.target,"query_type":"A","type":"A","ttl":60,"data":"1.1.1.1"},
        {"name":l.target,"query_name":l.target,"query_type":"AAAA","type":"AAAA","ttl":600,"data":"2606:4700:4700::1111"}
    ]);
    assert_eq!(submit(&s, "observer", &r).unwrap()["qualified"], true);
    let c = s.connect().unwrap();
    let ips: Vec<String> = c
        .prepare("SELECT ip FROM target_observations ORDER BY ip")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(ips, ["1.1.1.1"]);
    let saved: Value = serde_json::from_str(
        &c.query_row::<String, _, _>("SELECT evidence FROM results WHERE id=?", [&r.id], |r| {
            r.get(0)
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        saved, r.evidence,
        "filtering cannot rewrite original receipt history"
    );
}
#[test]
fn old_attempt_never_completes_new_attempt_and_duplicate_is_idempotent() {
    let (_t, s, l) = fixture("traceroute");
    let r = result(&l);
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET attempt_seq=2,lease_token='new-token'", [])
        .unwrap();
    let a = submit(&s, "observer", &r).unwrap();
    assert_eq!(a["historical_only"], true);
    assert_eq!(
        a["qualified"], true,
        "current demand state does not invalidate a trustworthy physical observation"
    );
    let scope: (bool, bool) = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT accepted,qualified FROM results WHERE id=?",
            [&r.id],
            |v| Ok((v.get(0)?, v.get(1)?)),
        )
        .unwrap();
    assert_eq!(scope, (false, true));
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
    let row: (String, i64) = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,attempt_seq FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?)),
        )
        .unwrap();
    assert_eq!(row, ("leased".into(), 2));
}
#[test]
fn accepted_once_counters_and_original_dns_expiry() {
    let (_t, s, l) = fixture("dns");
    let r = result(&l);
    let expiry = r.evidence["resolvers"][0]["valid_until"].as_i64().unwrap();
    assert_eq!(submit(&s, "observer", &r).unwrap()["qualified"], true);
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
    let(c,e,f,a):(i64,i64,i64,i64)=s.connect().unwrap().query_row("SELECT e.completed_tasks,j.evidence_until,j.failure_count,j.attempt_seq FROM executor_counters e,jobs j WHERE e.executor='observer'",[],|v|Ok((v.get(0)?,v.get(1)?,v.get(2)?,v.get(3)?))).unwrap();
    assert_eq!((c, e, f, a), (1, expiry, 0, 1));
}
#[test]
fn invalid_scope_fails_and_path_without_endpoint_is_terminal() {
    let (_t, s, l) = fixture("traceroute");
    s.connect()
        .unwrap()
        .execute("UPDATE lease_history SET lease_profile=json_set(lease_profile,'$.observer.region','europe') WHERE job_id='j'", [])
        .unwrap();
    let r = result(&l);
    let a = submit(&s, "observer", &r).unwrap();
    assert_eq!(a["qualified"], false);
    assert_eq!(a["execution_terminal"], false);
    let state: (String, i64) = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,failure_count FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, ("pending".into(), 1));
    let mut inconclusive = result(&l);
    inconclusive.evidence["reached"] = json!(false);
    inconclusive.evidence["hops"] = json!([{"hop":1,"ip":"9.9.9.9"}]);
    let q = qualify(&l, &node(), &inconclusive);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(
        q.evidence_until,
        Some(inconclusive.observed_at + airroute_rules::receipt::TRACE_NEGATIVE_TTL_SECONDS)
    );
}
#[test]
fn ttl_does_not_restart_on_a_late_result() {
    let l = lease("dns");
    let mut r = result(&l);
    r.observed_at = now() - 120;
    r.evidence["resolvers"][0]["observed_at"] = json!(r.observed_at);
    r.evidence["resolvers"][0]["valid_until"] = json!(r.observed_at + 60);
    let q = qualify(&l, &node(), &r);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.evidence_until, Some(r.observed_at + 60));
}
#[test]
fn actual_provider_probe_scope_and_method_are_required() {
    let mut l = lease("traceroute");
    l.profile["observation_country_regions"] = json!({"US":"us","DE":"europe"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    r.evidence = json!({"measurement":{"type":"traceroute","target":"1.1.1.1","measurementOptions":{"protocol":"ICMP"},"results":[{"probe":{"country":"DE","asn":64501},"result":{"status":"finished","resolvedAddress":"1.1.1.1","hops":[{"resolvedAddress":"1.1.1.1","timings":[{"rtt":1.0}]}]}}]}});
    assert!(!qualify(&l, &n, &r).execution_terminal);
    r.evidence["measurement"]["results"][0]["probe"]["country"] = json!("US");
    assert!(qualify(&l, &n, &r).qualified);
    r.evidence["measurement"]["measurementOptions"]["protocol"] = json!("UDP");
    assert!(!qualify(&l, &n, &r).qualified);
}
#[test]
fn three_failures_exhaust_current_chain_without_reusing_attempt_identity() {
    let (_t, s, l) = fixture("traceroute");
    for seq in 1..=3 {
        let token = format!("failure-{seq}");
        let mut l = l.clone();
        l.token = token.clone();
        let c = s.connect().unwrap();
        c.execute("UPDATE jobs SET status='leased',lease_node='observer',lease_token=?,lease_until=?,attempt_seq=? WHERE id='j'",rusqlite::params![token,now()+180,seq]).unwrap();
        c.execute("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,lease_profile) VALUES('j',?,'observer','fp',?,?,?)",rusqlite::params![airroute_rules::hash(&token),now(),seq,l.profile.to_string()]).unwrap();
        let mut r = result(&l);
        r.outcome = "error".into();
        r.evidence = json!({"error":"measurement timeout"});
        submit(&s, "observer", &r).unwrap();
        let (failures, attempt, state): (i64, i64, String) = c
            .query_row(
                "SELECT failure_count,attempt_seq,status FROM jobs WHERE id='j'",
                [],
                |v| Ok((v.get(0)?, v.get(1)?, v.get(2)?)),
            )
            .unwrap();
        assert_eq!((failures, attempt), (seq, seq));
        assert_eq!(state, if seq < 3 { "pending" } else { "unknown" });
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
                .get(0))
                .unwrap(),
            seq
        );
        if seq == 3 {
            assert!(
                c.query_row::<i64, _, _>("SELECT next_round_at FROM jobs WHERE id='j'", [], |v| v
                    .get(0))
                    .unwrap()
                    >= now() + 86390
            );
        }
    }
}

#[test]
fn expired_dns_reopens_same_logical_job_four_rounds_with_fresh_attempts() {
    let (_t, s, mut l) = fixture("dns");
    let n = node();
    for round in 1..=4 {
        let mut r = result(&l);
        // An answer can expire in transit. Its old clock must not become a
        // failure budget or a new cache lifetime when accepted now.
        r.observed_at = now() - 120;
        r.evidence["resolvers"][0]["observed_at"] = json!(r.observed_at);
        r.evidence["resolvers"][0]["valid_until"] = json!(r.observed_at + 60);
        let answer = submit(&s, &n.id, &r).unwrap();
        assert_eq!(answer["execution_terminal"], true);
        assert_eq!(answer["qualified"], false);
        let row: (i64, i64, String) = s
            .connect()
            .unwrap()
            .query_row(
                "SELECT failure_count,attempt_seq,status FROM jobs WHERE id='j'",
                [],
                |v| Ok((v.get(0)?, v.get(1)?, v.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (0, round, "complete".into()));
        let diagnostic: String=s.connect().unwrap().query_row("SELECT json_object('expiry',evidence_until,'profile',json(profile),'round',round_seq,'execution_count',execution_count,'workreq',(SELECT count(*) FROM work_requests),'meta',(SELECT json_object('fp',fp,'revision',revision,'status',status,'active',active) FROM case_metadata WHERE key='c')) FROM jobs WHERE id='j'",[],|v|v.get(0)).unwrap();
        assert_eq!(
            airroute_rules::jobs_v3::expire_due(&s).unwrap(),
            1,
            "round {round}; {diagnostic}"
        );
        let next = airroute_rules::jobs_v3::lease(&s, &n, None)
            .unwrap()
            .unwrap();
        assert_eq!(next.id, l.id);
        assert_ne!(next.token, l.token);
        assert_eq!(next.profile["attempt_seq"], round + 1);
        let mut late = r.clone();
        late.id = uuid::Uuid::new_v4().to_string();
        assert_eq!(submit(&s, &n.id, &late).unwrap()["historical_only"], true);
        l = next;
    }
    let rows: i64 = s
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM jobs", [], |v| v.get(0))
        .unwrap();
    assert_eq!(rows, 1);
}

#[test]
fn concluded_case_and_unknown_remote_block_dns_expiry_reopening() {
    let (_t, s, l) = fixture("dns");
    let mut r = result(&l);
    r.observed_at = now() - 120;
    r.evidence["resolvers"][0]["observed_at"] = json!(r.observed_at);
    r.evidence["resolvers"][0]["valid_until"] = json!(r.observed_at + 60);
    submit(&s, "observer", &r).unwrap();
    let c = s.connect().unwrap();
    c.execute("UPDATE cases SET status='decided' WHERE key='c'", [])
        .unwrap();
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 0);
    c.execute("UPDATE cases SET status='needs-active' WHERE key='c'", [])
        .unwrap();
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('j','fixture','',?,?)",rusqlite::params![serde_json::to_string(&l).unwrap(),now()]).unwrap();
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 0);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id='j'", [], |v| v.get(0))
            .unwrap(),
        "complete"
    );
}

#[test]
fn dns_missing_ttl_clock_and_unrelated_answers_are_not_positive_cache_entries() {
    let l = lease("dns");
    let n = node();
    let mut r = result(&l);
    r.evidence["resolvers"][0]["records"] =
        json!([{"name":"unrelated.example","type":"A","ttl":3600,"data":"1.1.1.1"}]);
    let q = qualify(&l, &n, &r);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.evidence_until, None);
    r.evidence = evidence("dns");
    r.evidence["resolvers"][0]
        .as_object_mut()
        .unwrap()
        .remove("observed_at");
    let q = qualify(&l, &n, &r);
    assert!(!q.qualified);
    assert_eq!(q.evidence_until, None);
    r.evidence = evidence("dns");
    r.evidence["resolvers"][0]["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("ttl");
    let q = qualify(&l, &n, &r);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.evidence_until, None);
}

#[test]
fn dns_cname_chain_bounds_expiry_and_ignores_unrelated_records() {
    let l = lease("dns");
    let n = node();
    let mut r = result(&l);
    let at = now();
    r.observed_at = at;
    r.evidence["resolvers"][0]["observed_at"] = json!(at);
    r.evidence["resolvers"][0]["valid_until"] = json!(at + 600);
    r.evidence["resolvers"][0]["records"] = json!([
        {"name":"fixture.example.","type":"CNAME","ttl":30,"data":"edge.example."},
        {"name":"edge.example.","type":"A","ttl":60,"data":"1.1.1.1"},
        {"name":"unrelated.example.","type":"A","ttl":1,"data":"8.8.8.8"}
    ]);
    let q = qualify(&l, &n, &r);
    assert!(q.qualified);
    assert_eq!(q.evidence_until, Some(at + 30));
}

#[test]
fn provider_dns_must_match_explicit_query_and_actual_transport() {
    let mut l = lease("dns");
    l.profile["protocol"] = json!("udp");
    l.profile["query"] = json!({"type":"AAAA"});
    l.profile["observation_country_regions"] = json!({"US":"us"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    r.evidence = json!({"measurement":{"type":"dns","target":l.target,"measurementOptions":{"protocol":"UDP","query":{"type":"AAAA"}},"results":[{"probe":{"country":"US","asn":64500},"result":{"status":"finished","statusCode":0,"answers":[{"name":l.target,"type":"AAAA","value":"2606:4700:4700::1111","ttl":60}]}}]}});
    assert!(qualify(&l, &n, &r).qualified);
    r.evidence["measurement"]["measurementOptions"]["query"]["type"] = json!("A");
    assert!(!qualify(&l, &n, &r).qualified);
    r.evidence["measurement"]["measurementOptions"]["query"]["type"] = json!("AAAA");
    r.evidence["measurement"]["measurementOptions"]["protocol"] = json!("TCP");
    assert!(!qualify(&l, &n, &r).qualified);
}

#[test]
fn removed_target_late_receipt_stays_history_even_when_the_case_fingerprint_is_unchanged() {
    let (_t, s, l) = fixture("traceroute");
    let c = s.connect().unwrap();
    // Target selection is runtime-owned and does not have to change the source
    // fingerprint. A leftover work request must not restore the old target.
    c.execute("UPDATE cases SET payload=json_set(payload,'$.targets',json('[\"8.8.8.8\"]')),status='needs-active' WHERE key='c'", []).unwrap();

    let r = result(&l);
    let answer = submit(&s, "observer", &r).unwrap();
    assert_eq!(answer["historical_only"], true);
    assert_eq!(
        answer["qualified"], true,
        "a trustworthy observation remains a fact for its exact old target"
    );
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM cases WHERE key='c'", [], |v| v.get(0))
            .unwrap(),
        "needs-active"
    );
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id='j'", [], |v| v.get(0))
            .unwrap(),
        "leased"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM executor_counters", [], |v| v.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM responsive_targets", [], |v| v.get(0))
            .unwrap(),
        0
    );
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
}

#[test]
fn local_attempt_uses_persisted_observer_not_changed_node_metadata() {
    let (_t, s, l) = fixture("traceroute");
    let c = s.connect().unwrap();
    c.execute("UPDATE lease_history SET lease_profile=json_set(lease_profile,'$.required_asn',64501) WHERE job_id='j'",[]).unwrap();
    c.execute(
        "UPDATE nodes SET region='europe',asn=64599 WHERE id='observer'",
        [],
    )
    .unwrap();
    let r = result(&l);
    assert_eq!(
        submit(&s, "observer", &r).unwrap()["qualified"],
        true,
        "the persisted US/64501 attempt is not relabelled Europe/64599"
    );

    let mut altered = l.clone();
    altered.profile["region_required"] = json!(true);
    altered.region = "europe".into();
    let mut current_node = node();
    current_node.region = "europe".into();
    current_node.asn = 64599;
    assert!(
        !qualify(&altered, &current_node, &r).qualified,
        "current node location cannot turn an old US observation into European evidence"
    );
}

#[test]
fn legacy_local_receipt_without_persisted_attempt_scope_is_history_only() {
    let (_t, s, l) = fixture("traceroute");
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE lease_history SET lease_profile=NULL WHERE job_id='j'",
        [],
    )
    .unwrap();
    let r = result(&l);
    let ack = submit(&s, "observer", &r).unwrap();
    assert_eq!(ack["historical_only"], true);
    assert_eq!(ack["qualified"], false);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM cases WHERE key='c'", [], |v| v.get(0))
            .unwrap(),
        "needs-active"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM executor_counters", [], |v| v.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn removed_dns_target_cannot_reopen_from_a_stale_work_request() {
    let (_t, s, l) = fixture("dns");
    let mut r = result(&l);
    r.observed_at = now() - 120;
    r.evidence["resolvers"][0]["observed_at"] = json!(r.observed_at);
    r.evidence["resolvers"][0]["valid_until"] = json!(r.observed_at + 60);
    assert_eq!(
        submit(&s, "observer", &r).unwrap()["execution_terminal"],
        true
    );
    let c = s.connect().unwrap();
    c.execute("INSERT INTO work_requests(case_key,fp,revision,target,kind,manual,regions,epoch) VALUES('c','fp',1,'fixture.example','dns',1,?,NULL)",[json!(["us"]).to_string()]).unwrap();
    // Simulate a legacy or interrupted edit that retained a stale derived row.
    c.execute(
        "UPDATE cases SET payload=json_set(payload,'$.targets',json('[]')) WHERE key='c'",
        [],
    )
    .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM work_requests WHERE target='fixture.example'",
            [],
            |v| v.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(airroute_rules::jobs_v3::expire_due(&s).unwrap(), 0);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id='j'", [], |v| v.get(0))
            .unwrap(),
        "complete"
    );
}

#[test]
fn structured_target_failure_is_an_observation_not_an_executor_fault() {
    let l = lease("traceroute");
    let mut r = result(&l);
    r.outcome = "error".into();
    r.evidence =
        json!({"kind":"traceroute","target":l.target,"protocol":"icmp","target_error":"timeout"});
    let q = qualify(&l, &node(), &r);
    assert_eq!(q.class, airroute_rules::receipt::ResultClass::TargetFailure);
    assert!(q.execution_terminal);
    assert!(
        !q.qualified,
        "a target timeout is not a geographic answer or positive endpoint response"
    );
    r.evidence = json!({"error":"connection timed out"});
    let q = qualify(&l, &node(), &r);
    assert_eq!(
        q.class,
        airroute_rules::receipt::ResultClass::ExecutorFailure
    );
    assert!(
        !q.execution_terminal,
        "an ambiguous error string does not invent target evidence"
    );
    r.outcome = "unsupported".into();
    assert_eq!(
        qualify(&l, &node(), &r).class,
        airroute_rules::receipt::ResultClass::NotExecuted
    );
}

#[test]
fn proven_not_executed_and_valid_cache_reuse_do_not_spend_network_attempts() {
    let (_t, s, l) = fixture("traceroute");
    let c = s.connect().unwrap();
    // Delivery conservatively started an opportunity. A verified cache answer
    // proves no new network measurement was performed by this attempt.
    assert!(airroute_rules::jobs_v3::consume_execution_on(&c, &l).unwrap());
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        1
    );
    let mut r = result(&l);
    r.observed_at = now() - 600;
    r.evidence["observed_at"] = json!(r.observed_at);
    r.evidence["cache_hit"] = json!(true);
    let ack = submit(&s, "observer", &r).unwrap();
    assert_eq!(ack["qualified"], true);
    assert_eq!(ack["cached_reuse"], true);
    assert_eq!(
        c.query_row::<(String, i64), _, _>(
            "SELECT status,execution_count FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?))
        )
        .unwrap(),
        ("complete".into(), 0)
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM executor_counters", [], |v| v.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT observed FROM results WHERE id=?", [&r.id], |v| v
            .get(0))
            .unwrap(),
        r.observed_at
    );
    assert_eq!(submit(&s, "observer", &r).unwrap()["duplicate"], true);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        0
    );

    let (_t, s, l) = fixture("traceroute");
    let c = s.connect().unwrap();
    assert!(airroute_rules::jobs_v3::consume_execution_on(&c, &l).unwrap());
    let mut r = result(&l);
    r.outcome = "unsupported".into();
    r.evidence =
        json!({"not_executed":true,"error":"required executable unavailable before measurement"});
    let ack = submit(&s, "observer", &r).unwrap();
    assert_eq!(ack["execution_class"], "not-executed");
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        0
    );
    assert!(
        c.query_row::<i64, _, _>(
            "SELECT executor_cooldown_until FROM nodes WHERE id='observer'",
            [],
            |v| v.get(0)
        )
        .unwrap()
            > now()
    );
}

fn install_next_attempt(store: &Store, original: &Lease, executor: &Node, seq: i64) -> Lease {
    store
        .register_node(executor, "fixture-registered-attempt-credentials")
        .unwrap();
    let mut lease = original.clone();
    lease.token = format!("fixture-attempt-{seq}");
    lease.profile["attempt_seq"] = json!(seq);
    lease.profile["observer"] =
        json!({"id":executor.id,"region":executor.region,"asn":executor.asn});
    let c = store.connect().unwrap();
    let round: i64 = c
        .query_row("SELECT round_seq FROM jobs WHERE id=?", [&lease.id], |v| {
            v.get(0)
        })
        .unwrap();
    lease.profile["round_seq"] = json!(round);
    c.execute("UPDATE jobs SET status='leased',attempt_seq=?,lease_node=?,lease_token=?,lease_until=? WHERE id=?",rusqlite::params![seq,executor.id,lease.token,now()+180,lease.id]).unwrap();
    c.execute("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,lease_profile,round_seq) VALUES(?,?,?,?,?,?,?,?)",rusqlite::params![lease.id,airroute_rules::hash(&lease.token),executor.id,lease.fingerprint,now(),seq,lease.profile.to_string(),round]).unwrap();
    lease
}

#[test]
fn two_matching_target_negatives_stop_after_one_other_observer_confirmation() {
    let (_t, s, l) = fixture("traceroute");
    let other = Node {
        id: "other-operator".into(),
        region: "us".into(),
        asn: 64502,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&other, "fixture-other-operator-credentials")
        .unwrap();
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE nodes SET connected=1,last_seen=? WHERE id=?",
        rusqlite::params![now(), other.id],
    )
    .unwrap();
    let mut first = result(&l);
    first.evidence["reached"] = json!(false);
    first.evidence["hops"] = json!([{"hop":1,"ip":"9.9.9.9"}]);
    let ack = submit(&s, "observer", &first).unwrap();
    assert_eq!(ack["execution_class"], "target-failure");
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id='j'", [], |v| v.get(0))
            .unwrap(),
        "pending"
    );
    let second_lease = install_next_attempt(&s, &l, &other, 2);
    let mut second = result(&second_lease);
    second.evidence["reached"] = json!(false);
    second.evidence["hops"] = json!([{"hop":1,"ip":"8.8.8.8"}]);
    let ack = submit(&s, &other.id, &second).unwrap();
    assert_eq!(
        ack["qualified"], false,
        "negative reachability is not target geography"
    );
    assert_eq!(
        c.query_row::<(String, i64), _, _>(
            "SELECT status,execution_count FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?))
        )
        .unwrap(),
        ("complete".into(), 2)
    );
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM lease_history WHERE result_class='target-failure' AND completed_at IS NOT NULL",[],|v|v.get(0)).unwrap(),2);
    assert!(
        airroute_rules::jobs_v3::lease(&s, &other, None)
            .unwrap()
            .is_none(),
        "two matching observations cannot mechanically demand a third"
    );
}

#[test]
fn self_and_provider_share_three_actual_opportunities_and_old_results_do_not_recharge() {
    let (_t, s, l) = fixture("traceroute");
    let mut first = result(&l);
    first.outcome = "error".into();
    first.evidence = json!({"error":"probe execution failed"});
    submit(&s, "observer", &first).unwrap();
    let gp = Node {
        id: "globalping:fixture:us".into(),
        region: "us".into(),
        asn: 0,
        capabilities: vec!["traceroute".into()],
    };
    let second_lease = install_next_attempt(&s, &l, &gp, 2);
    let mut second = result(&second_lease);
    second.outcome = "error".into();
    second.evidence = json!({"error":"provider returned no valid observation"});
    submit(&s, &gp.id, &second).unwrap();
    let last = Node {
        id: "last-self".into(),
        region: "us".into(),
        asn: 64503,
        capabilities: vec!["traceroute".into()],
    };
    let third_lease = install_next_attempt(&s, &l, &last, 3);
    let mut third = result(&third_lease);
    third.outcome = "error".into();
    third.evidence = json!({"error":"execution could not produce an observation"});
    submit(&s, &last.id, &third).unwrap();
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<(String, i64), _, _>(
            "SELECT status,execution_count FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?))
        )
        .unwrap(),
        ("unknown".into(), 3)
    );
    assert_eq!(submit(&s, &last.id, &third).unwrap()["duplicate"], true);
    let mut late = first;
    late.id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        submit(&s, "observer", &late).unwrap()["historical_only"],
        true
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        3
    );
    assert!(
        airroute_rules::jobs_v3::lease(&s, &last, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn trace_freshness_is_bound_to_original_observation_and_explicit_policy() {
    let mut l = lease("traceroute");
    l.profile["evidence_ttl_seconds"] = json!(120);
    l.profile["negative_evidence_ttl_seconds"] = json!(30);
    let mut r = result(&l);
    r.observed_at = now() - 60;
    let positive = qualify(&l, &node(), &r);
    assert!(positive.qualified);
    assert_eq!(positive.evidence_until, Some(r.observed_at + 120));
    r.evidence["cache_hit"] = json!(true);
    assert_eq!(
        qualify(&l, &node(), &r).evidence_until,
        positive.evidence_until
    );
    r.observed_at = now() - 121;
    assert!(!qualify(&l, &node(), &r).qualified);
    r.outcome = "error".into();
    r.evidence =
        json!({"kind":"traceroute","target":l.target,"protocol":"icmp","target_error":"refused"});
    let negative = qualify(&l, &node(), &r);
    assert_eq!(
        negative.class,
        airroute_rules::receipt::ResultClass::TargetFailure
    );
    assert_eq!(negative.evidence_until, Some(r.observed_at + 30));
    assert!(
        !negative.qualified,
        "a refusal never provides physical target location"
    );
}

#[test]
fn local_dns_observation_matches_explicit_transport_and_query_method() {
    let mut l = lease("dns");
    l.profile["protocol"] = json!("tcp");
    l.profile["query"] = json!({"type":"AAAA"});
    let mut r = result(&l);
    r.evidence["resolvers"][0]["records"][0]["query_type"] = json!("A");
    assert!(
        !qualify(&l, &node(), &r).execution_terminal,
        "UDP is not the requested TCP observation"
    );
    r.evidence["resolvers"][0]["transport"] = json!("tcp");
    assert!(
        !qualify(&l, &node(), &r).execution_terminal,
        "an A query does not satisfy an AAAA work item"
    );
    r.evidence["resolvers"][0]["records"] = json!([{"name":l.target,"type":"AAAA","query_type":"AAAA","ttl":60,"data":"2606:4700:4700::1111"}]);
    assert!(qualify(&l, &node(), &r).qualified);
    l.profile["protocol"] = json!("doh");
    r.evidence["resolvers"][0]["transport"] = json!("https");
    assert!(
        qualify(&l, &node(), &r).qualified,
        "documented HTTPS and DoH names describe the same transport"
    );
}

fn started_trace_then_expired(store: &Store, lease: &Lease) {
    let mut c = store.connect().unwrap();
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(airroute_rules::jobs_v3::consume_execution_on(&tx, lease).unwrap());
    tx.execute("UPDATE jobs SET lease_until=0 WHERE id=?", [&lease.id])
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(airroute_rules::jobs_v3::expire_due(store).unwrap(), 1);
    store
        .connect()
        .unwrap()
        .execute("UPDATE jobs SET not_before=0 WHERE id=?", [&lease.id])
        .unwrap();
}

#[test]
fn late_fresh_trace_before_claim_is_reused_without_another_reservation() {
    let (_t, s, l) = fixture("traceroute");
    started_trace_then_expired(&s, &l);
    let r = result(&l);
    let ack = submit(&s, "observer", &r).unwrap();
    assert_eq!(ack["accepted"], false);
    assert_eq!(ack["qualified"], true);
    assert!(
        airroute_rules::jobs_v3::lease(&s, &node(), None)
            .unwrap()
            .is_none(),
        "fresh trusted spool evidence must satisfy the demand before another claim"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
                .get(0))
            .unwrap(),
        1
    );
}

#[test]
fn late_fresh_trace_after_claim_blocks_send_without_completing_the_new_attempt() {
    let (_t, s, l) = fixture("traceroute");
    started_trace_then_expired(&s, &l);
    let next = airroute_rules::jobs_v3::lease(&s, &node(), None)
        .unwrap()
        .unwrap();
    assert_ne!(next.token, l.token);
    let ack = submit(&s, "observer", &result(&l)).unwrap();
    assert_eq!(ack["accepted"], false);
    let mut c = s.connect().unwrap();
    let reservation: (String, String) = c
        .query_row(
            "SELECT status,lease_token FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        reservation,
        ("leased".into(), next.token.clone()),
        "the old receipt cannot complete the newer attempt"
    );
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(
        !airroute_rules::jobs_v3::consume_execution_on(&tx, &next).unwrap(),
        "final send admission must recheck reusable evidence, not only queue state"
    );
    tx.commit().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        1
    );
    assert_eq!(c.query_row::<(Option<i64>,bool),_,_>("SELECT started_at,execution_refunded FROM lease_history WHERE job_id='j' AND token_hash=?",[airroute_rules::hash(&next.token)],|v|Ok((v.get(0)?,v.get(1)?))).unwrap(),(None,true));
}

#[test]
fn stale_or_wrong_method_spool_evidence_does_not_block_a_needed_send() {
    for stale in [false, true] {
        let (_t, s, l) = fixture("traceroute");
        started_trace_then_expired(&s, &l);
        let mut r = result(&l);
        if stale {
            r.observed_at = now() - airroute_rules::receipt::TRACE_POSITIVE_TTL_SECONDS - 1;
        } else {
            r.evidence["protocol"] = json!("udp");
        }
        assert_eq!(submit(&s, "observer", &r).unwrap()["qualified"], false);
        let next = airroute_rules::jobs_v3::lease(&s, &node(), None)
            .unwrap()
            .unwrap();
        let mut c = s.connect().unwrap();
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(airroute_rules::jobs_v3::consume_execution_on(&tx, &next).unwrap());
        tx.commit().unwrap();
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
                .get(0))
                .unwrap(),
            2
        );
    }
}

#[test]
fn an_already_executed_report_is_accounted_even_if_an_older_fact_arrived_first() {
    let (_t, s, l) = fixture("traceroute");
    started_trace_then_expired(&s, &l);
    let next = airroute_rules::jobs_v3::lease(&s, &node(), None)
        .unwrap()
        .unwrap();
    assert_eq!(
        submit(&s, "observer", &result(&l)).unwrap()["accepted"],
        false
    );
    // This authenticated report proves execution already happened (for example
    // an older controller had no durable start marker). It is not send admission.
    let new_report = result(&next);
    assert_eq!(
        submit(&s, "observer", &new_report).unwrap()["accepted"],
        true
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT execution_count FROM jobs WHERE id='j'", [], |v| v
                .get(0))
            .unwrap(),
        2
    );
}

#[test]
fn a_fresh_fact_from_a_different_view_does_not_replace_the_required_view() {
    let (_t, s, l) = fixture("traceroute");
    started_trace_then_expired(&s, &l);
    assert_eq!(
        submit(&s, "observer", &result(&l)).unwrap()["qualified"],
        true
    );
    s.enqueue_observation("1.1.1.1", &["europe".into()], "other required view fixture")
        .unwrap();
    let eu = Node {
        id: "eu-view".into(),
        region: "europe".into(),
        asn: 64502,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&eu, "fixture-europe-view-credentials")
        .unwrap();
    let next = airroute_rules::jobs_v3::lease(&s, &eu, None)
        .unwrap()
        .unwrap();
    assert_eq!(next.region, "europe");
    let mut c = s.connect().unwrap();
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(airroute_rules::jobs_v3::consume_execution_on(&tx, &next).unwrap());
    tx.commit().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT execution_count FROM jobs WHERE id=?",
            [&next.id],
            |v| v.get(0)
        )
        .unwrap(),
        1
    );
}

#[test]
fn a_fresh_a_answer_does_not_replace_a_required_aaaa_query() {
    let (_t, s, l) = fixture("dns");
    started_trace_then_expired(&s, &l);
    let mut old = result(&l);
    old.evidence["resolvers"][0]["records"][0]["query_type"] = json!("A");
    assert_eq!(submit(&s, "observer", &old).unwrap()["qualified"], true);
    let c = s.connect().unwrap();
    c.execute("UPDATE cases SET payload=json_set(payload,'$.query',json('{\"type\":\"AAAA\"}')) WHERE key='c'",[]).unwrap();
    let payload: String = c
        .query_row("SELECT payload FROM cases WHERE key='c'", [], |v| v.get(0))
        .unwrap();
    s.plan_case("c", "fp", &serde_json::from_str::<Value>(&payload).unwrap())
        .unwrap();
    let next = airroute_rules::jobs_v3::lease(&s, &node(), None)
        .unwrap()
        .unwrap();
    assert_eq!(next.profile["query_type"], "AAAA");
    let mut c = s.connect().unwrap();
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(airroute_rules::jobs_v3::consume_execution_on(&tx, &next).unwrap());
    tx.commit().unwrap();
}

#[test]
fn a_late_negative_counts_as_the_first_observation_not_a_third_confirmation() {
    let (_t, s, l) = fixture("traceroute");
    let b = Node {
        id: "negative-second".into(),
        region: "us".into(),
        asn: 64502,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&b, "fixture-negative-other-credentials")
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET connected=1,last_seen=?", [now()])
        .unwrap();
    started_trace_then_expired(&s, &l);
    let mut old = result(&l);
    old.evidence["reached"] = json!(false);
    old.evidence["hops"] = json!([{"hop":1,"ip":"9.9.9.9"}]);
    assert_eq!(submit(&s, "observer", &old).unwrap()["accepted"], false);
    let next = airroute_rules::jobs_v3::lease(&s, &b, None)
        .unwrap()
        .unwrap();
    let mut second = result(&next);
    second.evidence["reached"] = json!(false);
    second.evidence["hops"] = json!([{"hop":1,"ip":"8.8.8.8"}]);
    assert_eq!(
        submit(&s, &b.id, &second).unwrap()["execution_class"],
        "target-failure"
    );
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<(String, i64), _, _>(
            "SELECT status,execution_count FROM jobs WHERE id='j'",
            [],
            |v| Ok((v.get(0)?, v.get(1)?))
        )
        .unwrap(),
        ("complete".into(), 2),
        "the fresh late negative plus its independent confirmation are enough"
    );
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT result_class FROM lease_history WHERE job_id='j' AND attempt_seq=1",
            [],
            |v| v.get(0)
        )
        .unwrap(),
        "target-failure"
    );
}

#[test]
fn reusing_a_fact_never_extends_its_persisted_original_deadline() {
    let (_t, s, l) = fixture("traceroute");
    started_trace_then_expired(&s, &l);
    let r = result(&l);
    assert_eq!(submit(&s, "observer", &r).unwrap()["qualified"], true);
    let deadline = now() + 30;
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE results SET evidence_until=? WHERE id=?",
        rusqlite::params![deadline, r.id],
    )
    .unwrap();
    c.execute(
        "UPDATE jobs SET profile=json_set(profile,'$.evidence_ttl_seconds',200000) WHERE id='j'",
        [],
    )
    .unwrap();
    assert!(
        airroute_rules::jobs_v3::lease(&s, &node(), None)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT evidence_until FROM jobs WHERE id='j'", [], |v| v
            .get(0))
            .unwrap(),
        deadline
    );
}

#[test]
fn an_expired_or_wrong_view_negative_does_not_satisfy_fresh_confirmation() {
    for expired in [true, false] {
        let (_t, s, l) = fixture("traceroute");
        let b = Node {
            id: "fresh-negative-b".into(),
            region: "us".into(),
            asn: 64502,
            capabilities: vec!["traceroute".into()],
        };
        let third = Node {
            id: "fresh-negative-c".into(),
            region: "us".into(),
            asn: 64503,
            capabilities: vec!["traceroute".into()],
        };
        for n in [&b, &third] {
            s.register_node(n, "fixture-negative-scope-credentials")
                .unwrap();
        }
        s.connect()
            .unwrap()
            .execute("UPDATE nodes SET connected=1,last_seen=?", [now()])
            .unwrap();
        started_trace_then_expired(&s, &l);
        if !expired {
            // An old generic-view observation actually came from Europe. It
            // remains a valid negative fact, but not the newly required US view.
            s.connect().unwrap().execute("UPDATE lease_history SET lease_profile=json_set(lease_profile,'$.region_required',json('false'),'$.observer.region','europe') WHERE job_id='j' AND attempt_seq=1",[]).unwrap();
        }
        let mut old = result(&l);
        old.evidence["reached"] = json!(false);
        old.evidence["hops"] = json!([{"hop":1,"ip":"9.9.9.9"}]);
        if expired {
            old.observed_at = now() - airroute_rules::receipt::TRACE_NEGATIVE_TTL_SECONDS - 1;
        }
        assert_eq!(
            submit(&s, "observer", &old).unwrap()["execution_class"],
            "target-failure"
        );
        let next = airroute_rules::jobs_v3::lease(&s, &b, None)
            .unwrap()
            .unwrap();
        let mut current = result(&next);
        current.evidence["reached"] = json!(false);
        current.evidence["hops"] = json!([{"hop":1,"ip":"8.8.8.8"}]);
        submit(&s, &b.id, &current).unwrap();
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<String, _, _>("SELECT status FROM jobs WHERE id='j'", [], |v| v.get(0))
                .unwrap(),
            "pending",
            "only one fresh scope-compatible negative exists"
        );
    }
}

#[test]
fn actual_provider_dns_defaults_without_options_are_verified_from_dig_question_and_server() {
    let mut l = lease("dns");
    l.profile["observation_country_regions"] = json!({"US":"us","DE":"europe"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    r.observed_at = now() - 20;
    let raw = "; <<>> DiG 9 <<>> fixture.example A\n;; QUESTION SECTION:\n;fixture.example.\tIN\tA\n\n;; ANSWER SECTION:\nfixture.example. 60 IN A 1.1.1.1\n;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)\n";
    r.evidence = json!({"measurement_id":"actual-dns","measurement":{"id":"actual-dns","type":"dns","target":l.target,"createdAt":chrono::DateTime::from_timestamp(r.observed_at,0).unwrap().to_rfc3339(),"status":"finished","results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","statusCode":0,"answers":[{"name":"fixture.example.","type":"A","value":"1.1.1.1","ttl":60}],"rawOutput":raw}}]}});
    let q = qualify(&l, &n, &r);
    assert!(q.qualified, "{}", q.reason);
    assert_eq!(q.evidence_until, Some(r.observed_at + 60));
    // A default DNS demand does not invent a requirement to run A and AAAA.
    l.profile["query_type"] = json!("AAAA");
    assert!(!qualify(&l, &n, &r).qualified);
    l.profile["query_type"] = json!("A");
    assert!(qualify(&l, &n, &r).qualified);
    for raw in [
        raw.replace("fixture.example.\tIN", "other.example.\tIN"),
        raw.replace("(UDP)", "(TCP)"),
        raw.replace(";fixture.example.\tIN\tA", ";fixture.example.\tIN\tAAAA"),
        raw.replace(";; QUESTION SECTION:", ";; MISSING SECTION:"),
        raw.replace(";; SERVER:", ";; MISSING SERVER:"),
    ] {
        let mut wrong = r.clone();
        wrong.evidence["measurement"]["results"][0]["result"]["rawOutput"] = json!(raw);
        assert!(!qualify(&l, &n, &wrong).qualified);
    }
    let mut wrong = r.clone();
    wrong.evidence["measurement"]["measurementOptions"] =
        json!({"protocol":"TCP","query":{"type":"A"}});
    assert!(
        !qualify(&l, &n, &wrong).qualified,
        "structured echo must not hide a contradicting actual transport"
    );
    wrong.evidence["measurement"]["measurementOptions"] =
        json!({"protocol":"UDP","query":{"type":"AAAA"}});
    assert!(!qualify(&l, &n, &wrong).qualified);
    wrong = r.clone();
    wrong.evidence["measurement"]["results"][0]["probe"]["country"] = json!("DE");
    assert!(!qualify(&l, &n, &wrong).qualified);
    wrong = r.clone();
    wrong.evidence["measurement"]["results"][0]["probe"]["asn"] = json!(0);
    assert!(!qualify(&l, &n, &wrong).qualified);
    wrong = r.clone();
    wrong.evidence["measurement"]["results"][0]["result"]["answers"][0]["name"] =
        json!("unrelated.example");
    assert!(!qualify(&l, &n, &wrong).qualified);
}

#[test]
fn omitted_provider_options_decode_provider_defaults_without_copying_requested_methods() {
    let mut l = lease("dns");
    l.profile["observation_country_regions"] = json!({"US":"us"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    r.evidence = json!({"measurement":{"type":"dns","target":l.target,"results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","statusCode":0,"answers":[{"name":l.target,"type":"A","value":"1.1.1.1","ttl":60}]}}]}});
    assert!(qualify(&l, &n, &r).qualified);
    l.profile["protocol"] = json!("tcp");
    assert!(!qualify(&l, &n, &r).qualified);
    l.profile["protocol"] = Value::Null;
    l.profile["query_type"] = json!("AAAA");
    assert!(!qualify(&l, &n, &r).qualified);
    let mut l = lease("traceroute");
    l.profile["observation_country_regions"] = json!({"US":"us"});
    r = result(&l);
    r.evidence = json!({"measurement":{"type":"traceroute","target":l.target,"results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","resolvedAddress":l.target,"hops":[{"resolvedAddress":l.target,"timings":[{"rtt":1.0}]}]}}]}});
    assert!(qualify(&l, &n, &r).qualified);
    l.profile["protocol"] = json!("tcp");
    assert!(!qualify(&l, &n, &r).qualified);
    l.profile["protocol"] = json!("icmp");
    r.evidence["measurement"]["measurementOptions"] = json!({"protocol":"UDP"});
    r.evidence["measurement"]["results"][0]["result"]["protocol"] = json!("ICMP");
    assert!(!qualify(&l, &n, &r).qualified);
}

// One-off operator repair, deliberately outside the controller's runtime/API.
// Only the original recently received GP fact is reclassified. No job, token,
// execution opportunity, fee, remote intent, payload or observation clock changes.
fn recheck_recent_gp(s: &Store, since: i64) -> anyhow::Result<usize> {
    use anyhow::{Context, ensure};
    use rusqlite::params;
    ensure!(
        since > 0 && since <= now() && since >= now() - 86400,
        "explicit recent cutoff required (within one day)"
    );
    let c = s.connect()?;
    let rows = {
        let mut q=c.prepare("SELECT r.id,r.job_id,r.node,r.fp,r.observed,r.outcome,r.evidence,r.attempt_seq,r.round_seq,r.accepted,r.received,j.case_key,j.kind,j.target,j.region,h.token_hash,h.lease_profile FROM results r JOIN jobs j ON j.id=r.job_id JOIN lease_history h ON h.job_id=r.job_id AND h.node=r.node AND h.fp=r.fp AND h.attempt_seq=r.attempt_seq WHERE r.node LIKE 'globalping:%' AND r.received>=? AND r.outcome='ok' AND r.qualified=0 AND r.execution_class='executor-failure' AND r.attempt_seq>0 AND h.lease_profile IS NOT NULL AND (SELECT count(*) FROM lease_history same WHERE same.job_id=r.job_id AND same.node=r.node AND same.fp=r.fp AND same.attempt_seq=r.attempt_seq)=1 ORDER BY r.received,r.id LIMIT 1001")?;
        q.query_map([since], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
                r.get::<_, bool>(9)?,
                r.get::<_, i64>(10)?,
                r.get::<_, String>(11)?,
                r.get::<_, String>(12)?,
                r.get::<_, String>(13)?,
                r.get::<_, String>(14)?,
                r.get::<_, String>(15)?,
                r.get::<_, String>(16)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    ensure!(
        rows.len() <= 1000,
        "too many recent candidates; narrow explicit cutoff"
    );
    drop(c);
    let mut changed = 0;
    for batch in rows.chunks(32) {
        let mut checks = vec![];
        for (
            id,
            job,
            node,
            fp,
            observed,
            outcome,
            body,
            attempt,
            round,
            accepted,
            received,
            key,
            kind,
            target,
            region,
            token_hash,
            profile,
        ) in batch
        {
            let evidence: Value = serde_json::from_str(body)?;
            let Some(remote) = evidence["measurement"]["id"]
                .as_str()
                .filter(|v| !v.is_empty())
            else {
                continue;
            };
            if evidence["measurement_id"] != remote || *id != format!("globalping-{remote}") {
                continue;
            }
            let l = Lease {
                id: job.clone(),
                case_key: key.clone(),
                fingerprint: fp.clone(),
                kind: kind.clone(),
                target: target.clone(),
                region: region.clone(),
                token: String::new(),
                until: 0,
                profile: serde_json::from_str(profile)?,
            };
            ensure!(
                l.profile["attempt_seq"].as_i64() == Some(*attempt),
                "original attempt profile mismatch"
            );
            let n = Node {
                id: node.clone(),
                region: String::new(),
                asn: 0,
                capabilities: vec![kind.clone()],
            };
            let result = ProbeResult {
                id: id.clone(),
                job_id: job.clone(),
                fingerprint: fp.clone(),
                lease_token: String::new(),
                observed_at: *observed,
                outcome: outcome.clone(),
                evidence,
            };
            let qualification = airroute_rules::receipt::qualify_stored(s, &l, &n, &result)?;
            if qualification.execution_terminal {
                checks.push((
                    id,
                    job,
                    node,
                    fp,
                    body,
                    attempt,
                    round,
                    accepted,
                    received,
                    token_hash,
                    qualification,
                ));
            }
        }
        let mut c = s.connect()?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for (id, job, node, fp, body, attempt, round, accepted, received, token_hash, q) in checks {
            let updated=tx.execute("UPDATE results SET qualified=?,evidence_until=?,execution_class=?,observer_asn=? WHERE id=? AND job_id=? AND node=? AND fp=? AND evidence=? AND attempt_seq=? AND round_seq=? AND accepted=? AND received=? AND qualified=0 AND execution_class='executor-failure'",params![q.qualified,q.evidence_until,q.class.as_str(),q.observer_asn.and_then(|v| i64::try_from(v).ok()),id,job,node,fp,body,attempt,round,accepted,received])?;
            if updated == 0 {
                continue;
            }
            changed += updated;
            tx.execute("UPDATE lease_history SET result_class=?,completed_at=coalesce(completed_at,?),observer_asn=? WHERE job_id=? AND token_hash=? AND attempt_seq=? AND round_seq=? AND node=? AND fp=? AND (result_class IS NULL OR result_class='executor-failure')",params![q.class.as_str(),received,q.observer_asn.and_then(|v| i64::try_from(v).ok()),job,token_hash,attempt,round,node,fp])?;
            if *accepted {
                tx.execute("INSERT INTO executor_counters(executor,completed_tasks,last_completed_at) VALUES(?,1,?) ON CONFLICT(executor) DO UPDATE SET completed_tasks=completed_tasks+1,last_completed_at=max(coalesce(last_completed_at,0),excluded.last_completed_at)",params![node,received])?;
            }
            if q.qualified {
                tx.execute("INSERT INTO replan_cases(case_key,queued_at) SELECT l.case_key,? FROM jobs j JOIN job_cases l ON l.job_id=j.id JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision WHERE j.target=(SELECT target FROM jobs WHERE id=?) AND j.kind=(SELECT kind FROM jobs WHERE id=?) AND c.active=1 ON CONFLICT(case_key) DO NOTHING",params![now(),job,job])?;
            }
        }
        tx.commit().context("recent provider fact repair")?;
    }
    Ok(changed)
}

#[test]
#[ignore = "one-off authorized deployment repair; requires explicit data directory and recent cutoff"]
fn operator_recheck_recent_globalping_receipts() {
    let path = std::env::var("AIRROUTE_RECHECK_DATA").expect("explicit data path required");
    let since = std::env::var("AIRROUTE_RECHECK_SINCE")
        .expect("explicit cutoff required")
        .parse()
        .unwrap();
    let s = Store::open(std::path::Path::new(&path)).unwrap();
    let changed = recheck_recent_gp(&s, since).unwrap();
    println!("recent_globalping_facts_reclassified={changed}");
}

#[test]
fn recent_gp_recheck_is_idempotent_and_cannot_complete_a_new_attempt_or_refund_old_work() {
    for status_code in [0, 3] {
        let (_t, s, l) = fixture("dns");
        let gp = "globalping:fixture:us";
        s.set_meta("observation-country-regions", "{\"US\":\"us\"}")
            .unwrap();
        let c = s.connect().unwrap();
        c.execute("UPDATE lease_history SET node=?,lease_profile=json_set(lease_profile,'$.attempt_seq',1) WHERE job_id='j'",[gp]).unwrap();
        c.execute("UPDATE jobs SET attempt_seq=2,execution_count=2,failure_count=2,lease_token='new-token' WHERE id='j'",[]).unwrap();
        let at = now() - 120;
        let answers = if status_code == 0 {
            json!([{"name":l.target,"type":"A","value":"1.1.1.1","ttl":60}])
        } else {
            json!([{"name":l.target,"type":"CNAME","value":"missing.example.","ttl":60}])
        };
        let raw =
            ";; QUESTION SECTION:\n;fixture.example. IN A\n\n;; SERVER: 1.1.1.1#53(1.1.1.1)\n";
        let body=json!({"measurement_id":"repair","measurement":{"id":"repair","type":"dns","target":l.target,"results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","statusCode":status_code,"answers":answers,"rawOutput":raw}}]}}).to_string();
        c.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,attempt_seq,round_seq,qualified,execution_class) VALUES('globalping-repair','j',?,'fp',?,'ok',?,1,?,1,1,0,'executor-failure')",rusqlite::params![gp,at,body,now()]).unwrap();
        c.execute(
            "INSERT INTO gp_account_usage VALUES('fixture',?,2,0)",
            [now() / 3600],
        )
        .unwrap();
        let before:String=c.query_row("SELECT json_array(attempt_seq,lease_token,status,execution_count,failure_count,result_id) FROM jobs WHERE id='j'",[],|r|r.get(0)).unwrap();
        assert_eq!(recheck_recent_gp(&s, now() - 300).unwrap(), 1);
        assert_eq!(recheck_recent_gp(&s, now() - 300).unwrap(), 0);
        let after:String=c.query_row("SELECT json_array(attempt_seq,lease_token,status,execution_count,failure_count,result_id) FROM jobs WHERE id='j'",[],|r|r.get(0)).unwrap();
        assert_eq!(before, after);
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT used FROM gp_account_usage WHERE account='fixture'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            2
        );
        assert_eq!(c.query_row::<(bool,Option<i64>,String,String),_,_>("SELECT qualified,evidence_until,execution_class,evidence FROM results WHERE id='globalping-repair'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap(),(false,if status_code==0 {Some(at+60)} else {None},"observation".into(),body));
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT completed_tasks FROM executor_counters WHERE executor=?",
                [gp],
                |r| r.get(0)
            )
            .unwrap(),
            1
        );
        // A wrong-region fact remains rejected and is never upgraded by this tool.
        c.execute("UPDATE results SET id='globalping-wrong',evidence=json_set(evidence,'$.measurement.id','wrong','$.measurement_id','wrong','$.measurement.results[0].probe.country','DE'),execution_class='executor-failure'",[]).unwrap();
        assert_eq!(recheck_recent_gp(&s, now() - 300).unwrap(), 0);
    }
}

#[test]
fn legacy_dig_server_without_transport_accepts_only_standard_matching_server_addresses() {
    let mut l = lease("dns");
    l.profile["observation_country_regions"] = json!({"US":"us","DE":"europe"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    r.evidence = json!({"measurement":{"type":"dns","target":l.target,"results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","statusCode":0,"answers":[{"name":l.target,"type":"A","value":"1.1.1.1","ttl":60}]}}]}});
    let raw = |server: &str| {
        format!(
            ";; QUESTION SECTION:\n;fixture.example. IN A\n\n;; ANSWER SECTION:\nfixture.example. 60 IN A 1.1.1.1\n;; SERVER: {server}\n"
        )
    };
    // Official example also masks DNS resolver addresses literally:
    // https://github.com/jsdelivr/globalping-cli/blob/master/README.md#share-results-online
    for server in [
        "1.1.1.1#53(1.1.1.1)",
        "x.x.x.x#53(x.x.x.x)",
        "x.x.x.x#53(x.x.x.x) (UDP)",
        "192.0.2.53#53(192.0.2.53)",
        "2001:db8::53#53(2001:db8::53)",
        "1.1.1.1#53(1.1.1.1) (UDP)",
    ] {
        r.evidence["measurement"]["results"][0]["result"]["rawOutput"] = json!(raw(server));
        assert!(qualify(&l, &n, &r).qualified, "{server}");
    }
    for server in [
        "1.1.1.1#53(1.0.0.1)",
        "x.x.x.x#53(1.1.1.1)",
        "1.1.1.1#53(x.x.x.x)",
        "y.y.y.y#53(y.y.y.y)",
        "X.X.X.X#53(X.X.X.X)",
        "x.x.x.x#0(x.x.x.x)",
        "x.x.x.x#53(x.x.x.x) (TCP)",
        "x.x.x.x#53(x.x.x.x) (SCTP)",
        "1.1.1.1#0(1.1.1.1)",
        "1.1.1.1#65536(1.1.1.1)",
        "1.1.1.1(1.1.1.1)",
        "1.1.1.1#53(UDP)",
        "1.1.1.1#53(1.1.1.1) (SCTP)",
        "1.1.1.1#53(1.1.1.1) (TCP)",
        "1.1.1.1#53(1.1.1.1)\n;; SERVER: 1.1.1.1#53(1.1.1.1)",
    ] {
        r.evidence["measurement"]["results"][0]["result"]["rawOutput"] = json!(raw(server));
        assert!(!qualify(&l, &n, &r).qualified, "{server}");
    }
    r.evidence["measurement"]["results"][0]["result"]["rawOutput"] =
        json!(raw("1.1.1.1#53(1.1.1.1)"));
    l.profile["protocol"] = json!("TCP");
    assert!(
        !qualify(&l, &n, &r).qualified,
        "legacy omission cannot be filled from requested TCP"
    );
}

#[test]
fn provider_nxdomain_is_a_terminal_dns_observation_without_address_or_invented_ttl() {
    let mut l = lease("dns");
    l.profile["observation_country_regions"] = json!({"US":"us","DE":"europe"});
    let mut n = node();
    n.id = "globalping:fixture:us".into();
    let mut r = result(&l);
    let raw = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 10\n;; QUESTION SECTION:\n;fixture.example. IN A\n\n;; SERVER: 1.1.1.1#53(1.1.1.1)\n";
    r.evidence = json!({"measurement":{"type":"dns","target":l.target,"results":[{"probe":{"country":"US","asn":64501},"result":{"status":"finished","statusCode":3,"answers":[],"rawOutput":raw}}]}});
    let q = qualify(&l, &n, &r);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.class, airroute_rules::receipt::ResultClass::Observation);
    assert_eq!(q.evidence_until, None);
    let mut alias = r.clone();
    alias.evidence["measurement"]["results"][0]["result"]["answers"] =
        json!([{"name":l.target,"type":"CNAME","value":"missing.example.","ttl":60}]);
    alias.evidence["measurement"]["results"][0]["result"]["rawOutput"] = json!(raw.replace(
        ";; SERVER:",
        ";; ANSWER SECTION:\nfixture.example. 60 IN CNAME missing.example.\n\n;; SERVER:"
    ));
    let q = qualify(&l, &n, &alias);
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.class, airroute_rules::receipt::ResultClass::Observation);
    assert_eq!(
        q.evidence_until, None,
        "NXDOMAIN aliases do not manufacture a usable address or TTL"
    );
    for (kind, value) in [
        ("A", "1.1.1.1"),
        ("AAAA", "2606:4700:4700::1111"),
        ("RRSIG", "signature"),
        ("CNAME", ""),
    ] {
        let mut wrong = alias.clone();
        wrong.evidence["measurement"]["results"][0]["result"]["answers"] =
            json!([{"name":l.target,"type":kind,"value":value,"ttl":60}]);
        assert!(
            !qualify(&l, &n, &wrong).execution_terminal,
            "{kind}/{value}"
        );
    }
    for field in [
        "country",
        "asn",
        "target",
        "query",
        "transport",
        "server",
        "rcode",
    ] {
        let mut wrong = r.clone();
        match field {
            "country" => {
                wrong.evidence["measurement"]["results"][0]["probe"]["country"] = json!("DE")
            }
            "asn" => wrong.evidence["measurement"]["results"][0]["probe"]["asn"] = json!(0),
            "target" => wrong.evidence["measurement"]["target"] = json!("other.example"),
            "query" => {
                wrong.evidence["measurement"]["results"][0]["result"]["rawOutput"] =
                    json!(raw.replace("IN A", "IN AAAA"))
            }
            "transport" => {
                wrong.evidence["measurement"]["results"][0]["result"]["rawOutput"] =
                    json!(raw.replace("1.1.1.1#53(1.1.1.1)", "1.1.1.1#53(1.1.1.1) (TCP)"))
            }
            "server" => {
                wrong.evidence["measurement"]["results"][0]["result"]["rawOutput"] = Value::Null
            }
            "rcode" => {
                wrong.evidence["measurement"]["results"][0]["result"]["statusCode"] = json!(2)
            }
            _ => unreachable!(),
        }
        assert!(!qualify(&l, &n, &wrong).execution_terminal, "{field}");
    }
}
