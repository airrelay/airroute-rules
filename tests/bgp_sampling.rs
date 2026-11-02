use airroute_rules::{
    discovery::{self, Observation},
    now, sampling, scheduler,
    store::Store,
    work,
};
use rusqlite::params;
use serde_json::{Value, json};
use std::net::IpAddr;

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}
fn span(first: &str, last: &str) -> (u128, u128) {
    (
        airroute_rules::rules::addr_num(ip(first)).1,
        airroute_rules::rules::addr_num(ip(last)).1,
    )
}
fn addresses(rows: &[(IpAddr, Value)]) -> Vec<IpAddr> {
    rows.iter().map(|(ip, _)| *ip).collect()
}
fn selection(first: &str, last: &str) -> Vec<(IpAddr, Value)> {
    sampling::select_targets(4, &[span(first, last)], &[], &[], 3, true)
}

#[test]
fn fixed_ipv4_candidates_cover_three_strata_without_claiming_observations() {
    let ranges = [span("8.8.8.0", "8.8.8.255")];
    let candidates = selection("8.8.8.0", "8.8.8.255");
    assert_eq!(candidates.len(), 3);
    let mut strata = candidates
        .iter()
        .map(|(ip, evidence)| {
            assert_eq!(evidence["kind"], "sampled-candidate");
            assert_eq!(evidence["source"], "bgp-bounded-v1");
            assert!(evidence.get("observed").is_none());
            assert!(evidence.get("valid_until").is_none());
            let offset = airroute_rules::rules::addr_num(*ip).1 - ranges[0].0;
            if offset < 85 {
                0
            } else if offset < 170 {
                1
            } else {
                2
            }
        })
        .collect::<Vec<_>>();
    strata.sort();
    assert_eq!(strata, [0, 1, 2]);
    for _ in 0..4 {
        assert_eq!(selection("8.8.8.0", "8.8.8.255"), candidates);
    }
    assert_eq!(
        sampling::seed(
            4,
            &[span("8.8.8.128", "8.8.8.255"), span("8.8.8.0", "8.8.8.127")]
        ),
        sampling::seed(4, &ranges)
    );
    assert_ne!(
        sampling::seed(4, &[span("8.8.8.0", "8.8.8.127")]),
        sampling::seed(4, &ranges)
    );
}

#[test]
fn retained_choices_and_real_evidence_precede_sampled_fillers() {
    let ranges = [span("8.8.8.0", "8.8.8.255")];
    let manual = json!({"source":"operator-selected","note":"preserve"});
    let observed =
        json!({"kind":"dns-answer","source":"receipt:fixture","observed":20,"valid_until":40});
    let retained = [
        (ip("1.1.1.1"), Value::Null),
        (ip("8.8.8.5"), manual.clone()),
        (ip("8.8.8.5"), Value::Null),
    ];
    let selected = sampling::select_targets(
        4,
        &ranges,
        &retained,
        &[(ip("8.8.8.7"), observed.clone())],
        3,
        true,
    );
    assert_eq!(selected[0], (ip("8.8.8.5"), manual));
    assert_eq!(selected[1], (ip("8.8.8.7"), observed));
    assert_eq!(selected.len(), 3);
    assert_eq!(selected[2].1["kind"], "sampled-candidate");
}

#[test]
fn known_pool_is_spread_and_independent_of_input_order() {
    let ranges = [span("8.8.8.0", "8.8.8.255")];
    let mut known = [1, 2, 3, 126, 127, 128, 252, 253, 254]
        .map(|last| (ip(&format!("8.8.8.{last}")), json!({"kind":"dns-answer"})))
        .to_vec();
    let first = sampling::select_targets(4, &ranges, &[], &known, 3, false);
    assert_eq!(first.len(), 3);
    let values = addresses(&first);
    assert!(values.contains(&ip("8.8.8.1")));
    assert!(values.contains(&ip("8.8.8.127")));
    assert!(values.contains(&ip("8.8.8.254")));
    known.reverse();
    assert_eq!(
        sampling::select_targets(4, &ranges, &[], &known, 3, false),
        first
    );
}

#[test]
fn small_private_and_ipv6_scopes_remain_bounded() {
    assert_eq!(selection("8.8.8.8", "8.8.8.8").len(), 1);
    let small = selection("8.8.8.8", "8.8.8.9");
    assert_eq!(small.len(), 2);
    assert!(
        small
            .iter()
            .all(|(value, _)| [ip("8.8.8.8"), ip("8.8.8.9")].contains(value))
    );
    assert!(selection("10.0.0.0", "10.255.255.255").is_empty());
    assert!(sampling::select_targets(4, &[(0, u128::MAX)], &[], &[], 3, true).is_empty());
    let ranges = [span("2606:4700::", "2606:4700::ffff")];
    assert!(sampling::select_targets(6, &ranges, &[], &[], 3, true).is_empty());
    let known = [(ip("2606:4700::1111"), json!({"kind":"dns-answer"}))];
    assert_eq!(
        sampling::select_targets(6, &ranges, &[], &known, 3, true),
        known
    );
    assert!(sampling::select_targets(6, &[(0, u128::MAX)], &[], &[], 3, true).is_empty());
}

fn insert_case(
    store: &Store,
    key: &str,
    family: u8,
    first: &str,
    last: &str,
    bounded: bool,
    retained: &[&str],
) {
    let mut payload = json!({"kind":"endpoint-reachability","family":family,"ranges":[[first,last]],"regions":["us","europe"],"targets":retained,"measurement_required":true,"repeat_on_build":false});
    if bounded {
        payload["sample_plan"] = json!({"strategy":"bgp-bounded-v1","targets_per_group":3,"allow_ipv4_candidates":true,"parent_case_key":"old-parent"});
    }
    let c = store.connect().unwrap();
    c.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?1,'scope-fp',1,'endpoint-reachability',?2,'isolated fixture',?3,'blocked-target',1,?4)",params![key,first,payload.to_string(),now()]).unwrap();
    work::mark_case(&c, key).unwrap();
}
fn payload(store: &Store, key: &str) -> Value {
    let body: String = store
        .connect()
        .unwrap()
        .query_row("SELECT payload FROM cases WHERE key=?", [key], |r| r.get(0))
        .unwrap();
    serde_json::from_str(&body).unwrap()
}
fn jobs(store: &Store) -> Vec<(String, String)> {
    store
        .connect()
        .unwrap()
        .prepare("SELECT id,target FROM jobs ORDER BY id")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn runtime_candidates_fill_once_survive_restart_and_never_become_location_facts() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    insert_case(&store, "new", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    assert_eq!(scheduler::discover_case_targets(&store, "new").unwrap(), 3);
    let before = jobs(&store);
    let selected = payload(&store, "new");
    assert_eq!(selected["targets"].as_array().unwrap().len(), 3);
    assert!(
        selected["target_evidence"]
            .as_object()
            .unwrap()
            .values()
            .all(|e| e["kind"] == "sampled-candidate")
    );
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM target_observations", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(scheduler::discover_case_targets(&store, "new").unwrap(), 0);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(jobs(&store), before);
    assert_eq!(payload(&store, "new")["targets"], selected["targets"]);
    let snapshot = airroute_rules::fusion::capture(&store).unwrap();
    assert!(snapshot.location_facts.is_empty());
    assert!(snapshot.target_candidates.is_empty());
}

#[test]
fn legacy_and_ipv6_do_not_gain_random_candidates_and_known_ipv4_is_retained() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    insert_case(&store, "legacy", 4, "8.8.8.0", "8.8.8.255", false, &[]);
    insert_case(&store, "v6", 6, "2606:4700::", "2606:4700::ffff", true, &[]);
    assert_eq!(
        scheduler::discover_case_targets(&store, "legacy").unwrap(),
        0
    );
    assert_eq!(scheduler::discover_case_targets(&store, "v6").unwrap(), 0);
    assert!(jobs(&store).is_empty());
    let at = now();
    discovery::record(
        &store,
        &[Observation {
            ip: ip("8.8.8.20"),
            source: "fixture-known".into(),
            kind: "dns-answer",
            observed: at,
            valid_until: at + 120,
        }],
    )
    .unwrap();
    insert_case(&store, "new", 4, "8.8.8.0", "8.8.8.255", true, &["8.8.8.7"]);
    assert_eq!(scheduler::discover_case_targets(&store, "new").unwrap(), 3);
    let p = payload(&store, "new");
    assert!(p["targets"].as_array().unwrap().contains(&json!("8.8.8.7")));
    assert!(
        p["targets"]
            .as_array()
            .unwrap()
            .contains(&json!("8.8.8.20"))
    );
    assert_eq!(p["target_evidence"]["8.8.8.20"]["kind"], "dns-answer");
    assert_eq!(p["target_evidence"]["8.8.8.20"]["observed"], at);
}

#[test]
fn runtime_known_candidates_do_not_cluster_in_the_most_recent_first_window() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    insert_case(&store, "new", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    let at = now();
    let candidates = (1..=64)
        .chain([128, 250])
        .map(|last| Observation {
            ip: ip(&format!("8.8.8.{last}")),
            source: format!("fixture-known-{last}"),
            kind: "dns-answer",
            observed: at - i64::from(last > 64),
            valid_until: at + 120,
        })
        .collect::<Vec<_>>();
    discovery::record(&store, &candidates).unwrap();
    assert_eq!(scheduler::discover_case_targets(&store, "new").unwrap(), 3);
    let p = payload(&store, "new");
    assert_eq!(p["targets"], json!(["8.8.8.1", "8.8.8.128", "8.8.8.250"]));
    assert!(
        p["target_evidence"]
            .as_object()
            .unwrap()
            .values()
            .all(|e| e["kind"] == "dns-answer")
    );
}

#[test]
fn exhausted_samples_are_not_replaced_or_reopened_by_replanning_or_build_markers() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    insert_case(&store, "new", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    scheduler::discover_case_targets(&store, "new").unwrap();
    let before = jobs(&store);
    let c = store.connect().unwrap();
    c.execute(
        "UPDATE jobs SET status='unknown',execution_count=3,next_round_at=?",
        [now() - 1],
    )
    .unwrap();
    c.execute(
        "UPDATE cases SET status='blocked-target' WHERE key='new'",
        [],
    )
    .unwrap();
    assert_eq!(scheduler::discover_case_targets(&store, "new").unwrap(), 0);
    work::mark_case_from_build(&c, "new", "later-build").unwrap();
    work::refresh(&store).unwrap();
    assert_eq!(jobs(&store), before);
    assert!(!work::needs_daily_replan_on(&c, "new", "later-build").unwrap());
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='unknown' AND execution_count=3",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        3
    );
}

#[test]
fn identical_geometry_reuses_shared_jobs_and_preserves_unknown_provider_intent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    airroute_rules::globalping::initialize_intents(&store).unwrap();
    insert_case(&store, "first", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    scheduler::discover_case_targets(&store, "first").unwrap();
    let before = jobs(&store);
    let c = store.connect().unwrap();
    c.execute(
        "UPDATE jobs SET status='unknown',attempt_seq=7 WHERE id=?",
        [&before[0].0],
    )
    .unwrap();
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state,attempt_seq) VALUES(?,'fixture-account','','{}',0,'unknown',7)", [&before[0].0]).unwrap();
    insert_case(&store, "second", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    assert_eq!(
        scheduler::discover_case_targets(&store, "second").unwrap(),
        0
    );
    work::refresh(&store).unwrap();
    assert_eq!(jobs(&store), before);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM job_cases", [], |r| r.get(0))
            .unwrap(),
        6
    );
    assert_eq!(
        c.query_row::<(String, String, i64), _, _>(
            "SELECT account,state,attempt_seq FROM gp_remote WHERE job_id=?",
            [&before[0].0],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        )
        .unwrap(),
        ("fixture-account".into(), "unknown".into(), 7)
    );
}

#[test]
fn only_an_actual_qualified_reply_promotes_a_candidate_to_endpoint_evidence() {
    use airroute_rules::store::{Node, ProbeResult};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    insert_case(&store, "new", 4, "8.8.8.0", "8.8.8.255", true, &[]);
    scheduler::discover_case_targets(&store, "new").unwrap();
    let node = Node {
        id: "isolated-probe".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, "isolated-fixture-key-not-real-and-over-24")
        .unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,session_id='current',last_seen=? WHERE id=?",
            params![now(), node.id],
        )
        .unwrap();
    let lease = store.lease_session(&node, "current").unwrap().unwrap();
    assert_eq!(
        payload(&store, "new")["target_evidence"][&lease.target]["kind"],
        "sampled-candidate"
    );
    assert!(store.begin_execution(&node.id, "current", &lease).unwrap());
    let at = now();
    let result = ProbeResult {
        id: "actual-fixture-reply".into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: at,
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target,"rtt_ms":1}]}),
    };
    let ack = store.submit(&node.id, &result).unwrap();
    assert_eq!(ack["accepted"], true);
    assert_eq!(ack["qualified"], true);
    let observed: (String, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT kind,observed FROM target_observations WHERE ip=?",
            [&lease.target],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(observed, ("endpoint-response".into(), at));
    let facts = airroute_rules::fusion::capture(&store).unwrap();
    assert!(
        facts
            .target_candidates
            .contains_key(&lease.target.parse().unwrap())
    );
    assert!(facts.location_facts.is_empty());
    store.submit(&node.id, &result).unwrap();
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT completed_tasks FROM executor_counters WHERE executor=?",
                [&node.id],
                |r| r.get(0)
            )
            .unwrap(),
        1
    );
}
