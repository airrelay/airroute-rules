use airroute_rules::{
    fusion, now,
    store::{CaseInput, Lease, Node, ProbeResult, Store},
    work,
};
use rusqlite::params;
use serde_json::{Value, json};

fn example() -> Value {
    serde_json::from_str(include_str!("fixtures/fusion_value.json")).unwrap()
}
fn case(repeat: bool) -> CaseInput {
    let e = example();
    let mut payload = json!({"kind":"endpoint-reachability","family":4,"ranges":[e["scope"]],"regions":e["source_regions"],"targets":[e["target"]],"measurement_required":true,"observation_goal":"endpoint-reachability"});
    let target = e["target"].as_str().unwrap();
    let observed = now() - 2;
    payload["target_evidence"] = json!({target:{"kind":"dns-answer","source":"explicit local DNS replay","observed":observed,"valid_until":observed+300}});
    if !repeat {
        payload["repeat_on_build"] = json!(false);
    }
    CaseInput {
        key: "real-cached-us-es-disagreement".into(),
        fingerprint: "same-exact-source-scope".into(),
        kind: "endpoint-reachability".into(),
        subject: "3.160.226.0/24".into(),
        reason: "A reachable endpoint does not establish location or Anycast".into(),
        payload,
    }
}
fn commit(s: &Store, c: &CaseInput) {
    let id = s.start_build().unwrap();
    s.commit_build(
        &id,
        "local-replay-release",
        &json!({}),
        std::slice::from_ref(c),
        &[],
    )
    .unwrap();
    work::refresh(s).unwrap();
}
fn node(s: &Store) -> Node {
    let n = Node {
        id: "local-replay-observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into(), "traceroute".into()],
    };
    s.register_node(&n, &airroute_rules::hash("local-replay-fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1 WHERE id=?",
            params![now(), n.id],
        )
        .unwrap();
    n
}
fn trace(s: &Store, n: &Node, l: &Lease) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let r = ProbeResult {
        id: id.clone(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now() - 2,
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"ip":l.target}]}),
    };
    assert_eq!(s.submit(&n.id, &r).unwrap()["qualified"], true);
    id
}
fn expire_trace(s: &Store, l: &Lease, result: &str) {
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET evidence_until=? WHERE id=?",
        params![now() - 1, l.id],
    )
    .unwrap();
    c.execute(
        "UPDATE results SET observed=?,evidence_until=? WHERE id=?",
        params![now() - 86401, now() - 1, result],
    )
    .unwrap();
}
fn state(s: &Store, id: &str) -> (String, i64, i64, i64) {
    s.connect()
        .unwrap()
        .query_row(
            "SELECT status,round_seq,attempt_seq,execution_count FROM jobs WHERE id=?",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

#[test]
fn geographic_disagreement_does_not_reopen_completed_reachability() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let n = node(&s);
    let c = case(false);
    commit(&s, &c);
    let l = s.lease(&n).unwrap().unwrap();
    assert_eq!(l.target, example()["target"]);
    let result = trace(&s, &n, &l);
    let done = state(&s, &l.id);
    assert_eq!(done.0, "complete");
    expire_trace(&s, &l, &result);
    commit(&s, &c);
    assert_eq!(
        state(&s, &l.id),
        done,
        "a daily build cannot retry a trace that cannot answer the geographic disagreement"
    );
    assert!(s.lease(&n).unwrap().is_none());
    let mut changed = c.clone();
    changed.fingerprint = "later-location-source-fingerprint".into();
    changed.reason =
        "Location sources changed; the same endpoint response still cannot answer country".into();
    commit(&s, &changed);
    assert_eq!(
        state(&s, &l.id),
        done,
        "source changes must not reopen an unrelated one-time target check"
    );
    assert!(s.lease(&n).unwrap().is_none());
    assert_eq!(
        fusion::choose_installed_region(Some("us"), Some("europe"))
            .unwrap()
            .0,
        "us"
    );
    assert!(fusion::capture(&s).unwrap().location_facts.is_empty());
}

#[test]
fn frozen_dns_candidate_unlocks_exact_target_without_becoming_a_location_fact() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let n = node(&s);
    let mut waiting = case(false);
    waiting.payload["targets"] = json!([]);
    commit(&s, &waiting);
    assert!(
        s.lease(&n).unwrap().is_none(),
        "an unresolved range is not a probe target"
    );
    let e = example();
    let host = e["dns_replay_hostname"].as_str().unwrap();
    s.enqueue_observation(
        host,
        &["us".into()],
        "explicit local replay of the existing DNS discovery path",
    )
    .unwrap();
    let dns = s.lease(&n).unwrap().unwrap();
    assert_eq!(dns.kind, "dns");
    let observed = now() - 2;
    let until = observed + 300;
    let receipt = ProbeResult {
        id: "local-dns-replay".into(),
        job_id: dns.id.clone(),
        fingerprint: dns.fingerprint.clone(),
        lease_token: dns.token.clone(),
        observed_at: observed,
        outcome: "ok".into(),
        evidence: json!({"kind":"dns","hostname":host,"resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":until,"records":[{"name":host,"type":"A","ttl":300,"data":e["target"]},{"name":"unrelated.invalid","type":"A","ttl":1,"data":"9.9.9.9"},{"name":host,"type":"A","ttl":300,"data":"10.0.0.1"}]}]}),
    };
    assert_eq!(s.submit(&n.id, &receipt).unwrap()["qualified"], true);
    let frozen = fusion::capture(&s).unwrap();
    assert_eq!(
        frozen.target_candidates.len(),
        1,
        "unrelated/private DNS addresses cannot become targets"
    );
    let ip = e["target"].as_str().unwrap().parse().unwrap();
    let candidate = &frozen.target_candidates[&ip];
    assert_eq!(candidate.kind, "dns-answer");
    assert_eq!(candidate.observed, observed);
    assert_eq!(candidate.valid_until, until);
    assert!(frozen.location_facts.is_empty());
    assert!(frozen.domain_facts.is_empty());
    assert_eq!(frozen.summary["qualified_target_candidates"], 1);
    let mut historical = receipt.clone();
    historical.id = "a-local-dns-replay".into();
    assert_eq!(
        s.submit(&n.id, &historical).unwrap()["historical_only"],
        true
    );
    let repeated = fusion::capture(&s).unwrap();
    assert_eq!(repeated.target_candidates.len(), 1);
    assert_eq!(
        repeated.target_candidates[&ip].source, "receipt:a-local-dns-replay:dns:0",
        "equal-clock receipts choose a deterministic source independent of insertion order"
    );
    assert_eq!(s.submit(&n.id, &receipt).unwrap()["duplicate"], true);
    assert_eq!(
        fusion::capture(&s).unwrap().target_candidates[&ip].valid_until,
        until,
        "retransmission cannot restart DNS TTL"
    );

    // The same persistent discovery pool is reused by the next manifest sync.
    // Only the precise address becomes executable; the /24 stays unresolved.
    commit(&s, &waiting);
    let l = s.lease(&n).unwrap().unwrap();
    assert_eq!(l.kind, "traceroute");
    assert_eq!(l.target, e["target"]);
    let payload: String = s
        .connect()
        .unwrap()
        .query_row(
            "SELECT payload FROM cases WHERE key=?",
            [&waiting.key],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["targets"],
        json!([e["target"]])
    );
    trace(&s, &n, &l);
    let after = fusion::capture(&s).unwrap();
    assert_eq!(after.target_candidates[&ip].kind, "endpoint-response");
    assert!(
        after.target_candidates[&ip].valid_until
            <= after
                .observations
                .iter()
                .find(|o| o.kind == "traceroute")
                .unwrap()
                .valid_until
    );
    assert!(after.location_facts.is_empty());
    assert!(after.domain_facts.is_empty());
    assert_eq!(
        fusion::choose_installed_region(Some("us"), Some("europe"))
            .unwrap()
            .0,
        "us"
    );
    assert!(s.lease(&n).unwrap().is_none());
    s.connect()
        .unwrap()
        .execute("UPDATE results SET evidence_until=?", [now() - 1])
        .unwrap();
    assert!(
        fusion::capture(&s).unwrap().target_candidates.is_empty(),
        "expired stored evidence cannot reappear as a fresh target candidate"
    );
}

#[test]
fn ordinary_requested_evidence_still_reopens_after_expiry_on_a_new_build() {
    let dir = tempfile::tempdir().unwrap();
    let s = Store::open(dir.path()).unwrap();
    let n = node(&s);
    let c = case(true);
    commit(&s, &c);
    let l = s.lease(&n).unwrap().unwrap();
    let result = trace(&s, &n, &l);
    expire_trace(&s, &l, &result);
    commit(&s, &c);
    let next = s.lease(&n).unwrap().unwrap();
    assert_eq!(next.id, l.id);
    assert_ne!(next.token, l.token);
    assert_eq!(next.profile["round_seq"], 2);
}

#[test]
fn frozen_dns_candidate_recovers_missing_postcommit_discovery_import() {
    for discovery_flag in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(dir.path()).unwrap();
        let n = node(&s);
        let mut waiting = case(false);
        waiting.payload["targets"] = json!([]);
        waiting.payload["requires_target_discovery"] = json!(discovery_flag);
        commit(&s, &waiting);
        let e = example();
        let host = e["dns_replay_hostname"].as_str().unwrap();
        s.enqueue_observation(
            host,
            &["us".into()],
            "local replay before a discovery import failure",
        )
        .unwrap();
        let l = s.lease(&n).unwrap().unwrap();
        let observed = now() - 2;
        let until = observed + 300;
        let r = ProbeResult {
            id: "persisted-dns-before-import-failure".into(),
            job_id: l.id.clone(),
            fingerprint: l.fingerprint.clone(),
            lease_token: l.token.clone(),
            observed_at: observed,
            outcome: "ok".into(),
            evidence: json!({"kind":"dns","hostname":host,"resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":until,"records":[{"name":host,"type":"A","ttl":300,"data":e["target"]}]}]}),
        };
        assert_eq!(s.submit(&n.id, &r).unwrap()["qualified"], true);
        // Results are committed before the optional discovery import. A restart can
        // therefore have this exact state, without a persistent discovery pool row.
        s.connect()
            .unwrap()
            .execute("DELETE FROM target_observations", [])
            .unwrap();
        let frozen = fusion::capture(&s).unwrap();
        let candidate = frozen.target_candidates.values().next().unwrap();
        let mut next = waiting.clone();
        next.payload["targets"] = json!([candidate.ip.to_string()]);
        next.payload["target_evidence"] = json!({candidate.ip.to_string():{"kind":candidate.kind,"source":candidate.source,"observed":candidate.observed,"valid_until":candidate.valid_until}});
        next.payload["requires_target_discovery"] = json!(false);
        commit(&s, &next);
        let ready = s.lease(&n).unwrap().expect(
        "the next manifest must apply its frozen DNS target even if background import was missed",
    );
        assert_eq!(ready.kind, "traceroute");
        assert_eq!(ready.target, e["target"]);
        assert_eq!(
            s.connect()
                .unwrap()
                .query_row::<i64, _, _>("SELECT count(*) FROM target_observations", [], |r| r
                    .get(0))
                .unwrap(),
            0,
            "the manifest path must not depend on replaying a mutable discovery import"
        );
    }
}
