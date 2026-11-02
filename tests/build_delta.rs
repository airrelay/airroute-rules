use airroute_rules::{
    build,
    build_delta::{self, DomainInput},
    now,
    progress::Reporter,
    rules::Rule,
    store::{CaseInput, Store},
};
use rusqlite::params;
use serde_json::{Value, json};
fn case(key: &str, fp: &str) -> CaseInput {
    CaseInput {
        key: key.into(),
        fingerprint: fp.into(),
        kind: "geolocation".into(),
        subject: "1.1.1.0/24".into(),
        reason: "independent geographic inputs need reachability evidence".into(),
        payload: json!({"kind":"geolocation","family":4,"regions":["us","europe"],"ranges":[["1.1.1.0","1.1.1.255"]],"targets":[],"measurement_required":true}),
    }
}
fn domain(host: &str) -> DomainInput {
    DomainInput {
        collection: "provider/fixture".into(),
        rule: Rule::new("DOMAIN", host, &[]).unwrap(),
    }
}
fn activate(s: &Store, cases: &[CaseInput], domains: &[DomainInput], release: &str) -> String {
    let id = s.start_build().unwrap();
    let base = s.meta("current-build-id").unwrap();
    let path = build_delta::write_internal(
        s.path.parent().unwrap(),
        &id,
        base.as_deref(),
        release,
        cases,
        domains,
        &json!({"observation_cutoff":now()}),
    )
    .unwrap();
    let result =
        build_delta::activate(s, &id, release, &json!({"observation_cutoff":now()}), &path)
            .unwrap();
    assert_eq!(result["semantic_writes"], 0);
    id
}
fn drain(s: &Store) -> Value {
    for _ in 0..10000 {
        if !build_delta::sync_current(s, 64).unwrap() {
            return serde_json::from_str(&s.meta("last-build-sync").unwrap().unwrap()).unwrap();
        }
    }
    panic!("synchronization did not converge")
}
fn audit(s: &Store) {
    s.connect().unwrap().execute_batch("CREATE TABLE writes(table_name TEXT,key TEXT);CREATE TRIGGER audit_case_i AFTER INSERT ON cases BEGIN INSERT INTO writes VALUES('cases',NEW.key);END;CREATE TRIGGER audit_case_u AFTER UPDATE ON cases BEGIN INSERT INTO writes VALUES('cases',NEW.key);END;CREATE TRIGGER audit_job_i AFTER INSERT ON jobs BEGIN INSERT INTO writes VALUES('jobs',NEW.id);END;CREATE TRIGGER audit_job_u AFTER UPDATE ON jobs BEGIN INSERT INTO writes VALUES('jobs',NEW.id);END;CREATE TRIGGER audit_domain_i AFTER INSERT ON discovery_domains BEGIN INSERT INTO writes VALUES('domains',NEW.host);END;CREATE TRIGGER audit_domain_u AFTER UPDATE ON discovery_domains BEGIN INSERT INTO writes VALUES('domains',NEW.host);END;CREATE TRIGGER audit_domain_d AFTER DELETE ON discovery_domains BEGIN INSERT INTO writes VALUES('domains',OLD.host);END;").unwrap();
}
fn count(s: &Store, table: &str) -> i64 {
    s.connect()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM writes WHERE table_name=?",
            [table],
            |r| r.get(0),
        )
        .unwrap()
}
fn clear(s: &Store) {
    s.connect()
        .unwrap()
        .execute("DELETE FROM writes", [])
        .unwrap();
}
#[test]
fn activation_is_constant_and_does_not_synchronize_any_business_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    audit(&s);
    let cases = (0..1024)
        .map(|i| case(&format!("case-{i:04}"), "v1"))
        .collect::<Vec<_>>();
    let id = activate(&s, &cases, &[domain("exact.example.com")], "same-release");
    for table in ["cases", "jobs", "domains"] {
        assert_eq!(count(&s, table), 0);
    }
    assert_eq!(s.meta("current-build-id").unwrap(), Some(id.clone()));
    assert!(s.meta("build-sync-pending").unwrap().is_some());
    assert!(build_delta::sync_current(&s, 32).unwrap());
    assert_eq!(count(&s, "cases"), 32);
    assert_eq!(count(&s, "jobs"), 0);
    let done = drain(&s);
    assert_eq!(done["build_id"], id);
    assert_eq!(done["stats"]["new"], 1024);
}
#[test]
fn zero_single_full_changes_touch_only_the_actual_source_differences() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut cases = (0..256)
        .map(|i| case(&format!("case-{i:04}"), "v1"))
        .collect::<Vec<_>>();
    let domains = [domain("example.com"), domain("exact.example.com")];
    activate(&s, &cases, &domains, "same-release");
    drain(&s);
    audit(&s);
    activate(&s, &cases, &domains, "same-release");
    let same = drain(&s);
    assert_eq!(same["stats"]["semantic_writes"], 0);
    for table in ["cases", "jobs", "domains"] {
        assert_eq!(count(&s, table), 0);
    }
    cases[79].reason = "a changed source advisory, not a different observation".into();
    activate(&s, &cases, &domains, "same-release");
    let one = drain(&s);
    assert_eq!(one["stats"]["changed"], 1);
    assert_eq!(count(&s, "cases"), 1);
    assert_eq!(count(&s, "jobs"), 0);
    assert_eq!(count(&s, "domains"), 0);
    clear(&s);
    for c in &mut cases {
        c.fingerprint = "v2".into();
    }
    activate(&s, &cases, &domains, "same-release");
    let all = drain(&s);
    assert_eq!(all["stats"]["changed"], 256);
    assert_eq!(count(&s, "cases"), 256);
    assert_eq!(count(&s, "jobs"), 0);
}
#[test]
fn interrupted_sync_resumes_and_a_newer_manifest_reconciles_actual_partial_state() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let old = (0..100)
        .map(|i| case(&format!("old-{i:03}"), "v1"))
        .collect::<Vec<_>>();
    let old_id = activate(&s, &old, &[domain("old.example")], "public-old");
    assert!(build_delta::sync_current(&s, 7).unwrap());
    drop(s);
    let s = Store::open(d.path()).unwrap();
    assert!(build_delta::sync_current(&s, 7).unwrap());
    let new = [case("new-case", "v2")];
    let new_id = activate(&s, &new, &[domain("new.example")], "public-new");
    let done = drain(&s);
    assert_eq!(done["build_id"], new_id);
    let active: Vec<String> = s
        .connect()
        .unwrap()
        .prepare("SELECT key FROM cases WHERE active=1 ORDER BY key")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(active, ["new-case"]);
    let old_path = d.path().join("internal-builds").join(&old_id);
    assert!(build_delta::activate(&s, &old_id, "public-old", &json!({}), &old_path).is_err());
    assert_eq!(
        s.meta("current-release").unwrap().as_deref(),
        Some("public-new")
    );
}
#[test]
fn targets_and_inflight_external_state_survive_syncing_a_changed_source() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("a", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "first");
    drain(&s);
    let changed = case("a", "v2");
    activate(&s, &[changed], &[], "next");
    let mut payload = c.payload;
    payload["targets"] = json!(["1.1.1.1"]);
    payload["target_evidence"] = json!({"1.1.1.1":{"source":"observed","observed":now()}});
    s.connect()
        .unwrap()
        .execute(
            "UPDATE cases SET payload=?,status='needs-active' WHERE key='a'",
            [payload.to_string()],
        )
        .unwrap();
    s.connect().unwrap().execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,attempts,lease_node,lease_token,lease_until,created) VALUES('old','a','v1','traceroute','1.1.1.1','us','{}','leased',0,1,'globalping:primary:us','original-token',?,0)",[now()+300]).unwrap();
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('old','primary','remote-123','{}',0)",[]).unwrap();
    drain(&s);
    let saved: String = s
        .connect()
        .unwrap()
        .query_row("SELECT payload FROM cases WHERE key='a'", [], |r| r.get(0))
        .unwrap();
    let saved: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved["targets"], payload["targets"]);
    assert_eq!(saved["target_evidence"], payload["target_evidence"]);
    let old:(String,String,String)=s.connect().unwrap().query_row("SELECT j.status,j.lease_token,g.remote_id FROM jobs j JOIN gp_remote g ON g.job_id=j.id WHERE j.id='old'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(
        old,
        (
            "leased".into(),
            "original-token".into(),
            "remote-123".into()
        )
    );
}
#[test]
fn old_manual_decision_is_history_and_never_an_activation_input() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("a", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "first");
    drain(&s);
    s.connect().unwrap().execute("INSERT INTO decisions(case_key,fp,action,reason,created,revision) VALUES('a','v1','region:europe','historical manual decision',?,1)",[now()]).unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE cases SET status='decided' WHERE key='a'", [])
        .unwrap();
    let id = activate(&s, &[c], &[], "unchanged-source-output");
    drain(&s);
    assert_eq!(s.meta("current-build-id").unwrap(), Some(id));
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM cases WHERE key='a'", [], |r| r.get(0))
            .unwrap(),
        "blocked-target"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM decisions", [], |r| r.get(0))
            .unwrap(),
        1
    );
}
#[test]
fn private_manifest_keeps_precise_domains_without_public_provenance() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let domains = [
        domain("exact.example.com"),
        DomainInput {
            collection: "region/cn".into(),
            rule: Rule::new("DOMAIN-SUFFIX", "example.com", &[]).unwrap(),
        },
    ];
    let a = activate(&s, &[case("a", "v1")], &domains, "same-public");
    drain(&s);
    let b = activate(&s, &[case("a", "v2")], &domains, "same-public");
    drain(&s);
    assert_ne!(a, b);
    let path = d.path().join("internal-builds").join(a);
    let manifest = rusqlite::Connection::open(path.join("manifest.sqlite3")).unwrap();
    assert_eq!(
        manifest
            .query_row::<i64, _, _>("SELECT count(*) FROM domains", [], |r| r.get(0))
            .unwrap(),
        2
    );
    assert!(
        !d.path()
            .join("releases/same-public/manifest.sqlite3")
            .exists()
    );
    assert!(
        manifest
            .query_row::<bool, _, _>(
                "SELECT EXISTS(SELECT 1 FROM domains WHERE host='exact.example.com')",
                [],
                |r| r.get(0)
            )
            .unwrap()
    );
    assert!(!path.join("domains.jsonl").exists());
    assert!(!path.join("conflicts.jsonl").exists());
}
#[test]
fn progress_contention_does_not_fail_the_build_and_terminal_snapshot_is_durable() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let id = s.start_build().unwrap();
    let mut writer = s.connect().unwrap();
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    let started = std::time::Instant::now();
    let p = Reporter::new(&s, &id).unwrap();
    p.phase(3, "geo", "writer busy", None, "").unwrap();
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    tx.rollback().unwrap();
    let internal =
        build_delta::write_internal(d.path(), &id, None, "done", &[], &[], &json!({})).unwrap();
    build_delta::activate(&s, &id, "done", &json!({}), &internal).unwrap();
    let saved: String = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT snapshot FROM build_progress WHERE build_id=?",
            [id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&saved).unwrap()["detail"],
        "writer busy"
    );
}
#[test]
fn export_recovers_directory_switch_without_binding_and_never_exports_old_build() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    let s = Store::open(&data).unwrap();
    let first = activate(&s, &[], &[], "old");
    for (name, text) in [("old", "old"), ("new", "new")] {
        let path = data.join("releases").join(name);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("fixture.list"), text).unwrap();
    }
    build::recover_export(&s, d.path(), &data).unwrap();
    let next = activate(&s, &[], &[], "new");
    build::export(&data.join("releases/new"), &d.path().join("dist")).unwrap();
    assert_eq!(s.meta("exported-build-id").unwrap(), Some(first.clone()));
    build::recover_export(&s, d.path(), &data).unwrap();
    assert_eq!(s.meta("exported-build-id").unwrap(), Some(next));
    assert!(s.meta("export-pending").unwrap().is_none());
    assert!(
        build::export_current(
            &s,
            &first,
            "old",
            &data.join("releases/old"),
            &d.path().join("dist")
        )
        .is_err()
    );
    assert_eq!(
        std::fs::read_to_string(d.path().join("dist/fixture.list")).unwrap(),
        "new"
    );
}
#[test]
fn legacy_same_source_bootstraps_hash_without_rewriting_case_or_facts() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("legacy", "v1");
    s.connect()
        .unwrap()
        .execute(
            "INSERT INTO cases VALUES(?,?,1,?,?,?,?, 'blocked-target',1,?)",
            params![
                c.key,
                c.fingerprint,
                c.kind,
                c.subject,
                c.reason,
                c.payload.to_string(),
                now()
            ],
        )
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "INSERT INTO facts VALUES('legacy','DOMAIN','legacy.example','old')",
            [],
        )
        .unwrap();
    audit(&s);
    activate(&s, &[c], &[], "new");
    drain(&s);
    assert_eq!(count(&s, "cases"), 0);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM facts", [], |r| r.get(0))
            .unwrap(),
        1
    );
    build_delta::migrate(&s).unwrap();
    assert_eq!(count(&s, "cases"), 0);
}

#[test]
fn nonmeasurable_location_gaps_remain_private_reports_without_online_probe_demands() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let measurable = case("a", "v1");
    activate(&s, std::slice::from_ref(&measurable), &[], "first");
    drain(&s);
    let mut passive = measurable;
    passive.payload["measurement_required"] = json!(false);
    let id = activate(&s, &[passive], &[], "same-output");
    drain(&s);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM cases WHERE active=1", [], |r| r
                .get(0))
            .unwrap(),
        0
    );
    let private = d.path().join("internal-builds").join(id);
    let m = rusqlite::Connection::open(private.join("manifest.sqlite3")).unwrap();
    assert!(m.query_row::<bool,_,_>("SELECT EXISTS(SELECT 1 FROM cases WHERE measurable=0 AND json_extract(payload,'$.measurement_required')=0)",[],|r|r.get(0)).unwrap());
    assert_eq!(
        m.query_row::<i64, _, _>("SELECT count(*) FROM ranges", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        m.query_row::<i64, _, _>("SELECT count(*) FROM cases", [], |r| r.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn observation_arriving_after_manifest_preparation_is_rechecked_before_reopening_work() {
    use airroute_rules::store::{Node, ProbeResult};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("a", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "first");
    drain(&s);
    let mut source = c.clone();
    source.reason = "changed advisory; concrete observation demand remains identical".into();
    activate(&s, &[source], &[], "next");
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let node = Node {
        id: "node-a".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&node, &airroute_rules::hash("fixture credential"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=? WHERE id=?",
            params![now(), node.id],
        )
        .unwrap();
    let lease = s.lease(&node).unwrap().unwrap();
    let result = ProbeResult {
        id: "fresh-result".into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":"1.1.1.1","protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":"1.1.1.1","rtt_ms":1.0}]}),
    };
    assert_eq!(s.submit(&node.id, &result).unwrap()["qualified"], true);
    let jobs: i64 = s
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))
        .unwrap();
    drain(&s);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM cases WHERE key='a'", [], |r| r.get(0))
            .unwrap(),
        "evidence-ready"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        jobs
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [lease.id], |r| r
                .get(0))
            .unwrap(),
        "complete"
    );
}

#[test]
fn unchanged_large_domain_catalogue_compares_in_constant_sync_batches() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let hosts = (0..1000)
        .map(|i| domain(&format!("host-{i:04}.example.com")))
        .collect::<Vec<_>>();
    activate(&s, &[], &hosts, "same-rules");
    drain(&s);
    audit(&s);
    activate(&s, &[], &hosts, "same-rules");
    let done = drain(&s);
    assert_eq!(
        done["stats"]["batches"], 4,
        "zero differences must not write one cursor transaction per 64 unchanged hosts"
    );
    assert_eq!(done["stats"]["semantic_writes"], 0);
    assert_eq!(count(&s, "domains"), 0);
    assert_eq!(count(&s, "cases"), 0);
    assert_eq!(count(&s, "jobs"), 0);
    clear(&s);
    let mut changed = hosts;
    changed[543].collection = "region/cn".into();
    activate(&s, &[], &changed, "same-rules");
    let one = drain(&s);
    assert_eq!(one["stats"]["domain_changed"], 1);
    assert!(one["stats"]["batches"].as_u64().unwrap() <= 5);
    assert_eq!(count(&s, "domains"), 1);
    clear(&s);
    changed.remove(123);
    activate(&s, &[], &changed, "same-rules");
    let removed = drain(&s);
    assert_eq!(removed["stats"]["domain_removed"], 1);
    assert!(removed["stats"]["batches"].as_u64().unwrap() <= 5);
    assert_eq!(count(&s, "domains"), 1);
}

fn online_node(s: &Store) -> airroute_rules::store::Node {
    let node = airroute_rules::store::Node {
        id: "manifest-fence-node".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&node, &airroute_rules::hash("isolated manifest fixture"))
        .unwrap();
    s.connect().unwrap().execute("UPDATE nodes SET connected=1,session_id='manifest-session',last_seen=?,ipv4_supported=1 WHERE id=?",params![now(),node.id]).unwrap();
    node
}

#[test]
fn manifest_fence_rejects_removed_queued_demands_before_case_sync() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("obsolete-case", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "old");
    drain(&s);
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let node = online_node(&s);
    activate(&s, &[], &[], "new");
    assert!(s.meta("build-sync-pending").unwrap().is_some());
    assert!(
        s.lease_session(&node, "manifest-session")
            .unwrap()
            .is_none(),
        "the latest immutable manifest already removed this unstarted demand"
    );
}

#[test]
fn manifest_fence_rechecks_unsent_reservations_at_execution_admission() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("obsolete-case", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "old");
    drain(&s);
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let node = online_node(&s);
    let lease = s.lease_session(&node, "manifest-session").unwrap().unwrap();
    activate(&s, &[], &[], "new");
    assert!(
        !s.begin_execution(&node.id, "manifest-session", &lease)
            .unwrap(),
        "a reservation is not authority to start obsolete work after activation"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT execution_count FROM jobs WHERE id=?",
                [lease.id],
                |r| r.get(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn manifest_fence_keeps_concrete_valid_demands_and_rejects_changed_requirements() {
    for scenario in ["same-demand", "outside-range", "method", "view", "passive"] {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = case("case", "v1");
        activate(&s, std::slice::from_ref(&c), &[], "old");
        drain(&s);
        s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
            .unwrap();
        let node = online_node(&s);
        let mut changed = c;
        changed.fingerprint = "v2".into();
        changed.reason = "latest source snapshot".into();
        match scenario {
            "outside-range" => changed.payload["ranges"] = json!([["1.0.0.0", "1.0.0.255"]]),
            "method" => changed.payload["max_hops"] = json!(12),
            "view" => changed.payload["observation_regions"] = json!(["europe"]),
            "passive" => changed.payload["measurement_required"] = json!(false),
            _ => {}
        }
        activate(&s, &[changed], &[], "new");
        assert_eq!(
            s.lease_session(&node, "manifest-session")
                .unwrap()
                .is_some(),
            scenario == "same-demand",
            "concrete observation validity, not the source fingerprint alone: {scenario}"
        );
    }
}

#[test]
fn manifest_fence_does_not_treat_missing_internal_source_as_dispatch_authority() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let c = case("case", "v1");
    activate(&s, std::slice::from_ref(&c), &[], "old");
    drain(&s);
    s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    let node = online_node(&s);
    let id = activate(&s, &[c], &[], "new");
    std::fs::remove_file(
        d.path()
            .join("internal-builds")
            .join(id)
            .join("manifest.sqlite3"),
    )
    .unwrap();
    assert!(
        s.lease_session(&node, "manifest-session")
            .unwrap()
            .is_none()
    );
}

#[test]
fn manifest_retirement_preserves_started_and_uncertain_paid_attempts() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = case("a", "v1");
    let b = case("b", "v1");
    activate(&s, &[a.clone(), b.clone()], &[], "old");
    drain(&s);
    s.targets(&a.key, &a.fingerprint, &["1.1.1.1".into()])
        .unwrap();
    s.targets(&b.key, &b.fingerprint, &["1.1.1.2".into()])
        .unwrap();
    let node = online_node(&s);
    let started = s.lease_session(&node, "manifest-session").unwrap().unwrap();
    assert!(
        s.begin_execution(&node.id, "manifest-session", &started)
            .unwrap()
    );
    let uncertain = s.lease_session(&node, "manifest-session").unwrap().unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET status='unknown',lease_node='globalping:fixture:us' WHERE id=?",
            [&uncertain.id],
        )
        .unwrap();
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES(?,'fixture','',?,0)",params![uncertain.id,serde_json::to_string(&uncertain).unwrap()]).unwrap();
    activate(&s, &[], &[], "new");
    assert!(
        s.begin_execution(&node.id, "manifest-session", &started)
            .unwrap()
    );
    drain(&s);
    airroute_rules::work::refresh(&s).unwrap();
    let actual: (String, String, i64) = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT status,lease_token,execution_count FROM jobs WHERE id=?",
            [&started.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(actual, ("leased".into(), started.token, 1));
    let actual: (String, String, String) = s.connect().unwrap().query_row("SELECT j.status,j.lease_token,g.remote_id FROM jobs j JOIN gp_remote g ON g.job_id=j.id WHERE j.id=?",[&uncertain.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(actual, ("unknown".into(), uncertain.token, String::new()));
}

#[test]
fn unchanged_snapshot_does_not_queue_current_evidence_or_a_cooling_attempt() {
    for cooling in [false, true] {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let c = case("stable-case", "stable-fingerprint");
        activate(&s, std::slice::from_ref(&c), &[], "same-public");
        drain(&s);
        s.targets(&c.key, &c.fingerprint, &["1.1.1.1".into()])
            .unwrap();
        let node = online_node(&s);
        let lease = s.lease_session(&node, "manifest-session").unwrap().unwrap();
        assert!(
            s.begin_execution(&node.id, "manifest-session", &lease)
                .unwrap()
        );
        let result = airroute_rules::store::ProbeResult {
            id: "current-evidence".into(),
            job_id: lease.id.clone(),
            fingerprint: lease.fingerprint,
            lease_token: lease.token,
            observed_at: now(),
            outcome: "ok".into(),
            evidence: json!({"kind":"traceroute","target":"1.1.1.1","protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":"1.1.1.1","rtt_ms":1.0}]}),
        };
        assert_eq!(s.submit(&node.id, &result).unwrap()["qualified"], true);
        airroute_rules::work::refresh(&s).unwrap();
        s.connect().unwrap().execute("UPDATE jobs SET status=?,evidence_until=?,execution_count=?,next_round_at=? WHERE id=?",params![if cooling{"unknown"}else{"complete"},now()+3600,if cooling{3}else{1},if cooling{Some(now()+3600)}else{None},lease.id]).unwrap();
        audit(&s);
        s.connect().unwrap().execute_batch("CREATE TRIGGER audit_replan_i AFTER INSERT ON replan_cases BEGIN INSERT INTO writes VALUES('replan',NEW.case_key);END;CREATE TRIGGER audit_replan_u AFTER UPDATE ON replan_cases BEGIN INSERT INTO writes VALUES('replan',NEW.case_key);END;").unwrap();
        activate(&s, &[c], &[], "same-public");
        let same = drain(&s);
        assert_eq!(same["stats"]["semantic_writes"], 0, "cooling={cooling}");
        for table in ["cases", "jobs", "replan"] {
            assert_eq!(count(&s, table), 0, "{table}, cooling={cooling}");
        }
    }
}

#[test]
fn manifest_fence_checks_pending_discovery_against_the_latest_domain_catalogue() {
    for retained in [true, false] {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let gap = case("gap", "v1");
        let domains = [domain("discovery.example")];
        activate(&s, std::slice::from_ref(&gap), &domains, "old");
        drain(&s);
        let payload =
            json!({"kind":"target-discovery","targets":["discovery.example"],"regions":[]});
        let c = s.connect().unwrap();
        c.execute("INSERT INTO cases VALUES('discover:discovery.example','discovery-fp',1,'target-discovery','discovery.example','isolated discovery fixture',?,'needs-active',1,?)",params![payload.to_string(),now()]).unwrap();
        airroute_rules::work::plan_on(&c, "discover:discovery.example", "discovery-fp", &payload)
            .unwrap();
        let mut node = online_node(&s);
        node.capabilities = vec!["dns".into()];
        s.register_node(&node, &airroute_rules::hash("isolated manifest fixture"))
            .unwrap();
        activate(&s, &[gap], if retained { &domains } else { &[] }, "new");
        assert_eq!(
            s.lease_session(&node, "manifest-session")
                .unwrap()
                .is_some(),
            retained,
            "retained={retained}"
        );
    }
}
