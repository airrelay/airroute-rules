use airroute_rules::{
    discovery::{self, Config, Observation},
    measure::ResolverConfig,
    now, scheduler,
    store::{CaseInput, Node, ProbeResult, Store},
};
use axum::{
    Json, Router,
    extract::{OriginalUri, State},
    routing::get,
};
use hickory_proto::{
    op::{Message, OpCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME},
    },
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

fn case(key: &str, fp: &str, start: &str, end: &str) -> CaseInput {
    CaseInput {
        key: key.into(),
        fingerprint: fp.into(),
        kind: "geolocation".into(),
        subject: start.into(),
        reason: "source disagreement fixture".into(),
        payload: json!({"kind":"geolocation","family":4,"ranges":[[start,end]],"regions":["us"],"targets":[],"measurement_required":true}),
    }
}
fn commit(store: &Store, cases: &[CaseInput]) -> Value {
    let id = store.start_build().unwrap();
    store
        .commit_build(&id, "fixture-release", &json!({}), cases, &[])
        .unwrap()
}
fn observation(ip: &str, kind: &'static str, at: i64, until: i64) -> Observation {
    Observation {
        ip: ip.parse().unwrap(),
        source: format!("fixture:{ip}:{kind}"),
        kind,
        observed: at,
        valid_until: until,
    }
}
fn no_network() -> Config {
    Config {
        dns_per_tick: 0,
        atlas_results_per_tick: 0,
        ..Config::default()
    }
}

#[test]
fn cache_freshness_scope_and_kind_are_preserved_without_changing_adjudication() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let cases = [
        case("inside", "v1", "1.1.1.0", "1.1.1.63"),
        case("hole", "v1", "1.1.1.128", "1.1.1.191"),
        case("other", "v1", "8.8.8.0", "8.8.8.255"),
    ];
    commit(&store, &cases);
    let at = now();
    discovery::record(
        &store,
        &[
            observation("1.1.1.100", "endpoint-response", at, at + 600),
            observation("1.1.1.130", "dns-answer", at - 600, at - 1),
            observation("8.8.8.8", "dns-answer", at + 3600, at + 7200),
            observation("192.168.1.1", "endpoint-response", at, at + 600),
            observation("1.1.1.1", "dns-answer", at, at + 300),
        ],
    )
    .unwrap();
    assert_eq!(scheduler::discover_targets(&store).unwrap(), 1);
    let tasks = scheduler::tasks(&store, 0, 20, "").unwrap();
    assert_eq!(tasks["states"]["waiting-capability"], 1);
    assert_eq!(tasks["states"]["awaiting-target"], 2);
    let detail = scheduler::task_detail(&store, "inside").unwrap();
    assert_eq!(
        detail["payload"]["target_evidence"]["1.1.1.1"]["kind"],
        "dns-answer"
    );
    assert_eq!(detail["payload"]["targets"], json!(["1.1.1.1"]));
    let status: String = store
        .connect()
        .unwrap()
        .query_row("SELECT status FROM cases WHERE key='inside'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(status, "needs-active");
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(scheduler::discover_targets(&store).unwrap(), 0);
    let jobs_before: Vec<String> = scheduler::task_detail(&store, "inside").unwrap()["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().into())
        .collect();
    assert_eq!(commit(&store, &cases)["reused"], 3);
    assert_eq!(scheduler::discover_targets(&store).unwrap(), 0);
    let jobs_after: Vec<String> = scheduler::task_detail(&store, "inside").unwrap()["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].as_str().unwrap().into())
        .collect();
    assert_eq!(jobs_before, jobs_after);
    assert_eq!(
        scheduler::task_detail(&store, "inside").unwrap()["payload"]["target_evidence"]["1.1.1.1"]
            ["kind"],
        "dns-answer"
    );
}

#[test]
fn atlas_requires_a_destination_response_and_never_refreshes_source_time() {
    let at = now();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let value = json!([
        {"msm_id":42,"prb_id":1,"type":"ping","dst_addr":"1.1.1.1","timestamp":at,"result":[{"rtt":3.2}]},
        {"msm_id":42,"prb_id":2,"type":"ping","dst_addr":"8.8.8.8","timestamp":at,"result":[{"x":"*"}]},
        {"msm_id":42,"prb_id":3,"type":"traceroute","dst_addr":"9.9.9.9","timestamp":at,"result":[{"result":[{"from":"1.1.1.1","rtt":1.0}]}]},
        {"msm_id":43,"prb_id":4,"type":"ping","dst_addr":"4.4.4.4","timestamp":at,"result":[{"rtt":1}]},
        {"msm_id":42,"prb_id":5,"type":"ping","dst_addr":"2.2.2.2","timestamp":at-8*86400,"result":[{"rtt":1}]}
    ]);
    let observations = discovery::atlas_observations(&value, 42);
    assert_eq!(observations.len(), 2);
    assert_eq!(discovery::record(&store, &observations).unwrap(), 1);
    let before: (i64, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT observed,valid_until FROM target_observations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(discovery::record(&store, &observations).unwrap(), 0);
    let after: (i64, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT observed,valid_until FROM target_observations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(before, after);
    assert_eq!(before, (at, at + 7 * 86400));
    assert_eq!(
        discovery::atlas_observations(&json!({"1":[value[0].clone()]}), 42).len(),
        1
    );
}

#[tokio::test]
async fn dns_cname_ttl_candidates_flow_to_the_pool_and_restart_reuses_the_query_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    commit(&store, &[case("dns-case", "fp", "1.1.1.0", "1.1.1.255")]);
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO discovery_domains(host,bucket) VALUES('fixture.example',1)",
            [],
        )
        .unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    let fixture = tokio::spawn(async move {
        let mut bytes = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let q = Message::from_vec(&bytes[..n]).unwrap();
            let mut r = Message::response(q.metadata.id, OpCode::Query);
            r.queries = q.queries.clone();
            if q.queries[0].query_type() == RecordType::A {
                r.answers.push(Record::from_rdata(
                    q.queries[0].name().clone(),
                    30,
                    RData::CNAME(CNAME(Name::from_ascii("alias.example.").unwrap())),
                ));
                r.answers.push(Record::from_rdata(
                    Name::from_ascii("alias.example.").unwrap(),
                    600,
                    RData::A(A("1.1.1.1".parse().unwrap())),
                ));
                r.answers.push(Record::from_rdata(
                    Name::from_ascii("unrelated.example.").unwrap(),
                    600,
                    RData::A(A("8.8.8.8".parse().unwrap())),
                ));
            }
            socket.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let config = Config {
        dns_per_tick: 1,
        atlas_results_per_tick: 0,
        resolvers: vec![ResolverConfig {
            name: "fixture".into(),
            address,
            transport: "udp".into(),
        }],
        ..Config::default()
    };
    let report = discovery::tick(&store, &config).await.unwrap();
    assert_eq!(report["jobs_created"], 1);
    assert_eq!(queries.load(Ordering::SeqCst), 2);
    let (ttl, count): (i64, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT max(valid_until-observed),count(*) FROM target_observations",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((ttl, count), (30, 1));
    fixture.abort();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let report = discovery::tick(&store, &config).await.unwrap();
    assert_eq!(report["dns_hosts"], 0);
    assert_eq!(report["jobs_created"], 0);
}

#[tokio::test]
async fn accepted_receipts_are_imported_once_and_dns_never_becomes_response_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    commit(
        &store,
        &[case("receipt-case", "fp", "1.1.1.0", "1.1.1.255")],
    );
    let evidence = json!({"kind":"dns","hostname":"fixture.example","resolvers":[{"observed_at":now(),"valid_until":now()+300,"response_received":true,"transport":"udp","records":[{"name":"fixture.example","type":"A","data":"1.1.1.1","ttl":300}]}]});
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,qualified) VALUES('receipt','fixture','fixture','fp',?,'ok',?,1,?,1)",
            rusqlite::params![now(), evidence.to_string(), now()],
        )
        .unwrap();
    let report = discovery::tick(&store, &no_network()).await.unwrap();
    assert_eq!(report["jobs_created"], 1);
    let kind: String = store
        .connect()
        .unwrap()
        .query_row("SELECT kind FROM target_observations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(kind, "dns-answer");
    let report = discovery::tick(&store, &no_network()).await.unwrap();
    assert_eq!(report["observations_saved"], 0);
    assert_eq!(report["jobs_created"], 0);
    let stale = discovery::receipt_observations(
        "stale",
        now(),
        &json!({"resolvers":[{"observed_at":now(),"records":[{"type":"A","data":"8.8.8.8","ttl":30}]}]}),
    );
    assert_eq!(discovery::record(&store, &stale).unwrap(), 0);
    let gp = discovery::receipt_observations(
        "gp",
        now(),
        &json!({"measurement":{"type":"traceroute","results":[{"result":{"status":"finished","resolvedAddress":"9.9.9.9","hops":[{"resolvedAddress":"8.8.8.8","timings":[{"rtt":1}]}]}}]}}),
    );
    assert!(
        gp.is_empty(),
        "an intermediate router is not a reached target"
    );
}

#[tokio::test]
async fn a_qualified_late_receipt_recovers_candidate_import_after_a_failed_second_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    commit(&store, &[case("waiting", "fp", "1.1.1.0", "1.1.1.255")]);
    let node = Node {
        id: "late-observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into()],
    };
    store
        .register_node(&node, "local-late-fixture-credentials")
        .unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,ipv4_supported=1 WHERE id=?",
            rusqlite::params![now(), node.id],
        )
        .unwrap();
    store
        .enqueue_observation("late.example", &["us".into()], "late fixture")
        .unwrap();
    let lease = store.lease(&node).unwrap().unwrap();
    let observed = now();
    let result = ProbeResult {
        id: "late-qualified".into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint,
        lease_token: lease.token,
        observed_at: observed,
        outcome: "ok".into(),
        evidence: json!({"kind":"dns","hostname":"late.example","resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":observed+300,"records":[{"name":"late.example","type":"A","ttl":300,"data":"1.1.1.1"}]}]}),
    };
    let c = store.connect().unwrap();
    c.execute(
        "UPDATE jobs SET lease_until=? WHERE id=?",
        rusqlite::params![observed - 1, lease.id],
    )
    .unwrap();
    c.execute_batch("CREATE TRIGGER reject_candidate_import BEFORE INSERT ON target_observations BEGIN SELECT RAISE(ABORT,'injected candidate import failure'); END;").unwrap();
    let ack = store.submit(&node.id, &result).unwrap();
    assert_eq!(ack["accepted"], false);
    assert_eq!(ack["qualified"], true);
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM results WHERE id='late-qualified' AND accepted=0 AND qualified=1",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM target_observations", [], |r| r.get(0))
            .unwrap(),
        0
    );
    c.execute_batch("DROP TRIGGER reject_candidate_import")
        .unwrap();
    drop(c);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let report = discovery::tick(&store, &no_network()).await.unwrap();
    assert_eq!(
        report["observations_saved"], 1,
        "historical acceptance is independent of method-qualified candidate recovery"
    );
    let c = store.connect().unwrap();
    assert_eq!(c.query_row::<i64,_,_>("SELECT valid_until FROM target_observations WHERE source='receipt:late-qualified:dns:0'",[],|r|r.get(0)).unwrap(),observed+300);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM responsive_targets", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM discovery_receipts WHERE result_id='late-qualified'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        discovery::tick(&store, &no_network()).await.unwrap()["observations_saved"],
        0
    );
}

#[derive(Clone)]
struct AtlasFixture {
    calls: Arc<Mutex<Vec<String>>>,
    mode: u8,
}
async fn atlas_handler(
    State(s): State<AtlasFixture>,
    OriginalUri(uri): OriginalUri,
) -> (axum::http::StatusCode, axum::http::HeaderMap, Json<Value>) {
    use axum::http::{HeaderMap, StatusCode};
    s.calls.lock().unwrap().push(uri.to_string());
    if s.mode == 1 {
        let mut h = HeaderMap::new();
        h.insert("retry-after", "7200".parse().unwrap());
        return (StatusCode::TOO_MANY_REQUESTS, h, Json(json!({})));
    }
    let value = if uri.path() == "/measurements/" {
        if uri.query().unwrap_or("").contains("id__lt") {
            json!({"results":[]})
        } else {
            json!({"results":[{"id":42,"type":"ping","target_ip":"1.1.1.1"},{"id":41,"type":"ping","target_ip":"8.8.8.8"}]})
        }
    } else if uri.path() == "/measurements/42/" {
        json!({"id":42,"probes":[{"id":1}]})
    } else if uri.path() == "/measurements/42/latest/" {
        json!([{"msm_id":42,"prb_id":1,"type":"ping","dst_addr":"1.1.1.1","timestamp":now(),"result":[{"rtt":1}]}])
    } else {
        return (StatusCode::NOT_FOUND, HeaderMap::new(), Json(json!({})));
    };
    (StatusCode::OK, HeaderMap::new(), Json(value))
}
async fn atlas_server(mode: u8) -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let state = AtlasFixture {
        calls: Arc::new(Mutex::new(vec![])),
        mode,
    };
    let calls = state.calls.clone();
    let app = Router::new()
        .route("/measurements/", get(atlas_handler))
        .route("/measurements/42/", get(atlas_handler))
        .route("/measurements/42/latest/", get(atlas_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, calls, task)
}
#[tokio::test]
async fn public_catalog_uses_gets_only_and_persists_cursor_and_result_cache() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    commit(
        &store,
        &[
            case("atlas-case", "fp", "1.1.1.0", "1.1.1.255"),
            case("still-waiting", "fp", "9.9.9.0", "9.9.9.255"),
        ],
    );
    let (url, calls, server) = atlas_server(0).await;
    let config = Config {
        dns_per_tick: 0,
        atlas_base_url: url,
        atlas_page_size: 2,
        ..Config::default()
    };
    let first = discovery::tick(&store, &config).await.unwrap();
    assert_eq!(first["jobs_created"], 1);
    assert_eq!(first["atlas_measurements_queued"], 1);
    assert_eq!(
        store.meta("discovery-atlas-cursor").unwrap().as_deref(),
        Some("41")
    );
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    let second = discovery::tick(&store, &config).await.unwrap();
    assert_eq!(second["jobs_created"], 0);
    let urls = calls.lock().unwrap();
    assert_eq!(urls.len(), 4);
    assert!(urls.last().unwrap().contains("id__lt=41"));
    assert_eq!(
        urls.iter()
            .filter(|p| p.starts_with("/measurements/42/latest/"))
            .count(),
        1
    );
    server.abort();
}
#[tokio::test]
async fn atlas_rate_limit_backoff_survives_restart_and_does_not_block_dns_or_cached_planning() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    commit(&store, &[case("case", "fp", "1.1.1.0", "1.1.1.255")]);
    let (url, calls, server) = atlas_server(1).await;
    let config = Config {
        dns_per_tick: 0,
        atlas_base_url: url,
        ..Config::default()
    };
    let first = discovery::tick(&store, &config).await.unwrap();
    assert!(!first["errors"].as_array().unwrap().is_empty());
    let until = store
        .meta("discovery-atlas-after")
        .unwrap()
        .unwrap()
        .parse::<i64>()
        .unwrap();
    assert!(until >= now() + 7198);
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    discovery::record(
        &store,
        &[observation("1.1.1.1", "dns-answer", now(), now() + 300)],
    )
    .unwrap();
    let report = discovery::tick(&store, &config).await.unwrap();
    assert_eq!(report["jobs_created"], 1);
    assert_eq!(calls.lock().unwrap().len(), 1);
    server.abort();
}

#[test]
fn an_expired_receipt_never_becomes_a_fresh_responsive_target() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store
        .enqueue_observation("1.1.1.1", &["us".into()], "fixture measurement")
        .unwrap();
    let node = Node {
        id: "node".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, &airroute_rules::hash("fixture key"))
        .unwrap();
    let lease = store.lease(&node).unwrap().unwrap();
    let at = now() - 8 * 86400;
    let result = ProbeResult {
        id: "old-result".into(),
        job_id: lease.id,
        fingerprint: lease.fingerprint,
        lease_token: lease.token,
        observed_at: at,
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","protocol":"icmp","reached":true,"target":"1.1.1.1","hops":[{"ip":"1.1.1.1","rtt_ms":1.0}]}),
    };
    let ack = store.submit(&node.id, &result).unwrap();
    assert_eq!(ack["accepted"], true);
    assert_eq!(
        ack["qualified"], false,
        "original observation expiry is already past"
    );
    let saved: i64 = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT observed FROM results WHERE id='old-result'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(saved, at);
    assert_eq!(
        store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM responsive_targets", [], |r| r.get(0))
            .unwrap(),
        0
    );
    commit(&store, &[case("new-dispute", "fp", "1.1.1.0", "1.1.1.255")]);
    assert_eq!(scheduler::discover_targets(&store).unwrap(), 0);
}

#[test]
fn receipt_dns_candidates_follow_only_the_question_cname_chain() {
    let at = now();
    let candidates = discovery::receipt_observations(
        "chain",
        at,
        &json!({
            "kind":"dns", "hostname":"api.example", "resolvers":[{
                "observed_at":at,"valid_until":at+30,"records":[
                    {"name":"api.example.","type":"CNAME","data":"cdn.example.","ttl":30},
                    {"name":"cdn.example.","type":"A","data":"1.1.1.1","ttl":300},
                    {"name":"unrelated.example.","type":"A","data":"8.8.8.8","ttl":300}
                ]
            }]
        }),
    );
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].ip.to_string(), "1.1.1.1");
    assert_eq!(candidates[0].valid_until, at + 30);
}

#[test]
fn mixed_dns_candidates_use_only_successful_actual_query_contexts() {
    let at = now();
    let evidence = json!({"kind":"dns","hostname":"mixed.example","resolvers":[{"transport":"udp","response_received":true,"observed_at":at,"valid_until":at+300,"rcodes":[{"name":"mixed.example","query_type":"A","code":0},{"name":"mixed.example","query_type":"AAAA","code":2}],"records":[{"name":"mixed.example.","type":"A","query_name":"mixed.example","query_type":"A","data":"1.1.1.1","ttl":60},{"name":"mixed.example.","type":"AAAA","query_name":"mixed.example","query_type":"AAAA","data":"2606:4700:4700::1111","ttl":300}]}]});
    let observations = discovery::receipt_observations("mixed", at, &evidence);
    assert_eq!(
        observations.len(),
        1,
        "SERVFAIL records are history, never DNS candidates"
    );
    assert_eq!(observations[0].ip.to_string(), "1.1.1.1");
    assert_eq!(observations[0].valid_until, at + 60);
}

#[test]
fn cname_followup_rcodes_are_bound_to_the_actual_queried_name() {
    let at = now();
    let evidence = json!({"kind":"dns","hostname":"mixed.example","resolvers":[{"transport":"udp","response_received":true,"observed_at":at,"valid_until":at+300,"rcodes":[{"name":"mixed.example","query_type":"A","code":0},{"name":"alias.example","query_type":"A","code":2}],"records":[{"name":"mixed.example.","type":"CNAME","query_name":"mixed.example","query_type":"A","data":"alias.example.","ttl":60},{"name":"alias.example.","type":"A","query_name":"mixed.example","query_type":"A","data":"1.1.1.1","ttl":60},{"name":"alias.example.","type":"A","query_name":"alias.example","query_type":"A","data":"8.8.8.8","ttl":300}]}]});
    let observations = discovery::receipt_observations("alias-mixed", at, &evidence);
    assert_eq!(
        observations.len(),
        1,
        "a successful root question cannot authorize a failed same-type alias question"
    );
    assert_eq!(observations[0].ip.to_string(), "1.1.1.1");
    let mut legacy = evidence.clone();
    for record in legacy["resolvers"][0]["records"].as_array_mut().unwrap() {
        record.as_object_mut().unwrap().remove("query_name");
    }
    assert!(
        discovery::receipt_observations("ambiguous", at, &legacy).is_empty(),
        "legacy records without actual question names cannot resolve mixed success/failure for the same type"
    );
}
