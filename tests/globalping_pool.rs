use airroute_rules::store::Store;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
struct Mock {
    calls: Arc<Mutex<Vec<String>>>,
    deny: bool,
    measurements: Arc<Mutex<std::collections::BTreeMap<String, Value>>>,
}
async fn create(
    State(s): State<Mock>,
    h: HeaderMap,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    assert_eq!(body["limit"], 1);
    assert_eq!(body["type"], "dns");
    let auth = h["authorization"].to_str().unwrap().to_string();
    let mut calls = s.calls.lock().unwrap();
    calls.push(auth);
    let id = format!("fixture-{}", calls.len());
    if s.deny {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":"fixture quota exhausted"})),
        )
    } else {
        s.measurements.lock().unwrap().insert(id.clone(), body);
        (StatusCode::ACCEPTED, Json(json!({"id":id})))
    }
}
async fn limit_snapshot() -> Json<Value> {
    Json(
        json!({"rateLimit":{"measurements":{"create":{"type":"user","limit":500,"remaining":500,"reset":0}}}}),
    )
}
async fn poll(id: &str) -> Json<Value> {
    Json(
        json!({"id":id,"status":"finished","results":[{"probe":{"country":"US","asn":64500,"city":"fixture"},"result":{"status":"finished","answers":[{"type":"A","value":"1.1.1.1"}]}}]}),
    )
}
async fn fixture(deny: bool) -> (String, Mock, tokio::task::JoinHandle<()>) {
    let s = Mock {
        deny,
        ..Default::default()
    };
    let app = Router::new()
        .route("/v1/limits", get(limit_snapshot))
        .route("/v1/measurements", post(create))
        .route("/v1/measurements/{id}", get(|State(s):State<Mock>,Path(id):Path<String>|async move {
            let input=s.measurements.lock().unwrap().get(&id).cloned().unwrap();
            let country=if input["locations"][0]["magic"]=="DE"{"DE"}else{"US"};
            Json(json!({"id":id,"type":input["type"],"target":input["target"],"measurementOptions":input["measurementOptions"],"createdAt":chrono::Utc::now().to_rfc3339(),"status":"finished","results":[{"probe":{"country":country,"asn":64500},"result":{"status":"finished","statusCode":0,"answers":[{"name":input["target"],"type":"A","value":"1.1.1.1","ttl":60}]}}]}))
        }))
        .with_state(s.clone());
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1", socket.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    (url, s, task)
}
fn config(root: &std::path::Path, url: &str, same_group: bool) {
    std::fs::create_dir(root.join("config")).unwrap();
    std::fs::copy(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/geography.json"),
        root.join("config/geography.json"),
    )
    .unwrap();
    let text = format!(
        r#"
base_url = "{url}"
[quota_groups.a]
tests_per_hour = 10
tests_per_day = 20
minimum_interval_seconds = 0
[quota_groups.b]
tests_per_hour = 10
tests_per_day = 20
minimum_interval_seconds = 0
[[accounts]]
id = "one"
token_env = "GP_FIXTURE_ONE"
quota_group = "a"
enabled = true
[accounts.regions]
us = "US"
[[accounts]]
id = "two"
token_env = "GP_FIXTURE_TWO"
quota_group = "{}"
enabled = true
[accounts.regions]
europe = "DE"
"#,
        if same_group { "a" } else { "b" }
    );
    std::fs::write(root.join("config/globalping.toml"), text).unwrap();
}
async fn tick(root: &std::path::Path) {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_rules-control"))
        .arg("--root")
        .arg(root)
        .arg("tick")
        .env("GP_FIXTURE_ONE", "fixture-one")
        .env("GP_FIXTURE_TWO", "fixture-two")
        .output()
        .await
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
#[tokio::test]
async fn multiple_accounts_recover_remote_results_without_duplicate_creation() {
    let (url, mock, task) = fixture(false).await;
    let temp = tempfile::tempdir().unwrap();
    config(temp.path(), &url, false);
    let s = Store::open(&temp.path().join("data")).unwrap();
    s.enqueue_observation(
        "fixture.example",
        &["us".into(), "europe".into()],
        "local Globalping adapter fixture",
    )
    .unwrap();
    tick(temp.path()).await;
    let mut calls = mock.calls.lock().unwrap().clone();
    calls.sort();
    assert_eq!(calls, ["Bearer fixture-one", "Bearer fixture-two"]);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM gp_remote", [], |r| r.get(0))
            .unwrap(),
        2
    );
    s.connect()
        .unwrap()
        .execute("UPDATE gp_remote SET next_poll=0", [])
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET lease_until=0 WHERE status='leased'", [])
        .unwrap();
    // Account removal must stop new dispatch, while its persisted measurements drain.
    let base =
        airroute_rules::globalping::load(&temp.path().join("config/globalping.toml")).unwrap();
    airroute_rules::globalping::delete_account(&s, &base, "one").unwrap();
    tick(temp.path()).await;
    assert_eq!(mock.calls.lock().unwrap().len(), 2);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results WHERE accepted=1", [], |r| r
                .get(0))
            .unwrap(),
        2
    );
    task.abort();
}
#[tokio::test]
async fn globalping_competes_for_shared_work_when_no_uncovered_work_exists() {
    let (url, mock, task) = fixture(false).await;
    let temp = tempfile::tempdir().unwrap();
    config(temp.path(), &url, false);
    let s = Store::open(&temp.path().join("data")).unwrap();
    s.enqueue_observation("fixture.example", &["us".into()], "self preference fixture")
        .unwrap();
    let n = airroute_rules::store::Node {
        id: "self-us".into(),
        region: "us".into(),
        asn: 64510,
        capabilities: vec!["dns".into()],
    };
    s.register_node(&n, &airroute_rules::hash("public fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET last_seen=?,connected=1 WHERE id='self-us'",
            [airroute_rules::now()],
        )
        .unwrap();
    tick(temp.path()).await;
    assert_eq!(
        mock.calls.lock().unwrap().len(),
        1,
        "online owned capacity no longer excludes a Globalping fallback"
    );
    assert!(
        s.lease(&n).unwrap().is_none(),
        "one shared job is claimed once, not copied for each executor"
    );
    task.abort();
}
#[tokio::test]
async fn a_rate_limited_account_does_not_stop_an_independent_account() {
    let (url, mock, task) = fixture(true).await;
    let temp = tempfile::tempdir().unwrap();
    config(temp.path(), &url, true);
    let s = Store::open(&temp.path().join("data")).unwrap();
    s.enqueue_observation(
        "fixture.example",
        &["us".into(), "europe".into()],
        "local quota fixture",
    )
    .unwrap();
    tick(temp.path()).await;
    tick(temp.path()).await;
    let mut calls = mock.calls.lock().unwrap().clone();
    calls.sort();
    assert_eq!(calls, ["Bearer fixture-one", "Bearer fixture-two"]);
    task.abort();
}

fn local_account(store: &Store, enabled: bool) -> airroute_rules::globalping::Account {
    store
        .set_meta(
            "observation-country-regions",
            &json!({"US":"us","DE":"europe"}).to_string(),
        )
        .unwrap();
    airroute_rules::globalping::Account {
        id: "fixture".into(),
        name: "local fixture".into(),
        credential_ref: Some(
            airroute_rules::secrets::save(
                store.path.parent().unwrap(),
                &uuid::Uuid::nil().to_string(),
            )
            .unwrap(),
        ),
        enabled,
        regions: std::collections::BTreeMap::from([("us".into(), "US".into())]),
        ..Default::default()
    }
}

fn local_config(
    account: airroute_rules::globalping::Account,
    base_url: String,
) -> airroute_rules::globalping::Config {
    airroute_rules::globalping::Config {
        base_url,
        accounts: vec![account],
    }
}

// Change the authoritative demand and let the real planner create its new
// logical job. Keep the old row to exercise the dispatch-time stale-method fence.
fn require_asn_from_case(store: &Store, key: &str, asn: u32) -> String {
    let mut c = store.connect().unwrap();
    let tx = c.transaction().unwrap();
    let old: String = tx
        .query_row(
            "SELECT job_id FROM job_cases WHERE case_key=? ORDER BY job_id LIMIT 1",
            [key],
            |r| r.get(0),
        )
        .unwrap();
    let (fp, body): (String, String) = tx
        .query_row("SELECT fp,payload FROM cases WHERE key=?", [key], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    let mut payload: Value = serde_json::from_str(&body).unwrap();
    payload["required_asn"] = json!(asn);
    assert_eq!(
        tx.execute(
            "UPDATE cases SET payload=? WHERE key=? AND fp=?",
            rusqlite::params![payload.to_string(), key, fp]
        )
        .unwrap(),
        1
    );
    assert_eq!(
        airroute_rules::work::plan_on(&tx, key, &fp, &payload).unwrap(),
        1
    );
    tx.commit().unwrap();
    old
}
fn assert_stale_job_was_not_dispatched(store: &Store, id: &str) {
    let c = store.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM lease_history WHERE job_id=?",
            [id],
            |r| r.get(0)
        )
        .unwrap(),
        0,
        "an old job without the current necessary ASN must not be dispatched"
    );
    assert!(
        !c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM gp_remote WHERE job_id=?)",
            [id],
            |r| r.get(0)
        )
        .unwrap()
    );
}

fn pending_measurement(
    store: &Store,
    account: &airroute_rules::globalping::Account,
    region: &str,
    remote: &str,
    target: &str,
) -> String {
    store
        .enqueue_observation(target, &[region.into()], "local recovery fixture")
        .unwrap();
    let node = airroute_rules::store::Node {
        id: format!("globalping:{}:{region}", account.id),
        region: region.into(),
        asn: 0,
        capabilities: vec!["dns".into()],
    };
    store
        .register_node(&node, &uuid::Uuid::nil().to_string())
        .unwrap();
    let lease = store.lease(&node).unwrap().unwrap();
    store.connect().unwrap().execute(
        "INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,account_snapshot) VALUES(?1,?2,?3,?4,0,?5)",
        rusqlite::params![lease.id, account.id, remote, serde_json::to_string(&lease).unwrap(), serde_json::to_string(account).unwrap()],
    ).unwrap();
    lease.id
}

#[tokio::test]
async fn uncertain_creations_do_not_starve_confirmed_remote_results() {
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = polls.clone();
    let app = Router::new().route(
        "/measurements/{id}",
        get(move |Path(id): Path<String>| {
            let count = count.clone();
            async move {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                poll(&id).await
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let account = local_account(&store, false);
    for i in 0..16 {
        let job = pending_measurement(
            &store,
            &account,
            "us",
            "",
            &format!("uncertain-{i}.example"),
        );
        store
            .connect()
            .unwrap()
            .execute("UPDATE jobs SET status='unknown' WHERE id=?", [&job])
            .unwrap();
    }
    let confirmed = pending_measurement(&store, &account, "us", "confirmed", "confirmed.example");
    airroute_rules::globalping::tick(&store, &local_config(account, url))
        .await
        .unwrap();
    assert_eq!(
        polls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "existing paid work must still be recovered after uncertain submissions accumulate"
    );
    let remaining: i64 = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT count(*) FROM gp_remote WHERE remote_id=''",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        remaining, 16,
        "uncertain submissions must remain quarantined"
    );
    let accepted: bool = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM results WHERE job_id=? AND accepted=1)",
            [&confirmed],
            |r| r.get(0),
        )
        .unwrap();
    assert!(accepted);
    server.abort();
}

#[tokio::test]
async fn polling_429_blocks_new_hour_submissions_and_preserves_the_longest_pause() {
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count_posts = posts.clone();
    let count_polls = polls.clone();
    let app = Router::new()
        .route(
            "/measurements/{id}",
            get(move || {
                let count = count_polls.clone();
                async move {
                    let wait = if count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        "3600"
                    } else {
                        "60"
                    };
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [("retry-after", wait)],
                        Json(json!({"error":"local quota fixture"})),
                    )
                }
            }),
        )
        .route(
            "/measurements",
            post(move || {
                let count = count_posts.clone();
                async move {
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    (StatusCode::ACCEPTED, Json(json!({"id":"new-fixture"})))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path()).unwrap();
    let mut account = local_account(&store, true);
    pending_measurement(&store, &account, "us", "old-us", "prior-us.example");
    pending_measurement(
        &store,
        &account,
        "europe",
        "old-europe",
        "prior-europe.example",
    );
    account.regions.insert("europe".into(), "DE".into());
    account.regions.insert("southeast-asia".into(), "SG".into());
    store
        .enqueue_observation(
            "new-hour.example",
            &["southeast-asia".into()],
            "new local fixture",
        )
        .unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO gp_account_usage VALUES('fixture',?,1,0)",
            [airroute_rules::now() / 3600 - 1],
        )
        .unwrap();
    let started = airroute_rules::now();
    airroute_rules::globalping::tick(&store, &local_config(account, url))
        .await
        .unwrap();
    assert_eq!(
        posts.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "a polled 429 must pause the quota owner even before the first reservation of a new hour"
    );
    let (used, blocked): (i64, i64) = store
        .connect()
        .unwrap()
        .query_row(
            "SELECT used,blocked_until FROM gp_account_usage WHERE account='fixture' AND bucket=?",
            [started / 3600],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(used, 0);
    assert!(
        blocked >= started + 3600,
        "a later shorter retry delay must not shorten an existing pause"
    );
    server.abort();
}
#[tokio::test]
async fn ipv6_unavailable_requeues_without_spending_quota_or_reposting_an_accepted_measurement() {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = calls.clone();
    let app=Router::new().route("/limits",get(limit_snapshot)).route("/measurements",post(move |headers:HeaderMap,Json(body):Json<Value>|{
        let captured=captured.clone();async move {
            assert_eq!(body["target"],"2001:4860::8888");
            assert!(body["measurementOptions"].get("ipVersion").is_none(),"literal IP determines Globalping's family");
            captured.lock().unwrap().push(body);
            if headers["authorization"].to_str().unwrap().contains("unavailable") {(StatusCode::UNPROCESSABLE_ENTITY,Json(json!({"error":{"type":"no_probes_found","message":"No matching IPv6 probes"}})))}else{(StatusCode::ACCEPTED,Json(json!({"id":"accepted-v6","probesCount":1})))}
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut a = local_account(&s, true);
    a.id = "first".into();
    a.credential_ref =
        Some(airroute_rules::secrets::save(d.path(), "unavailable-fixture-token").unwrap());
    let mut b = local_account(&s, true);
    b.id = "second".into();
    let key = s
        .enqueue_observation("2001:4860::8888", &["us".into()], "v6 transport fixture")
        .unwrap();
    let mut config = airroute_rules::globalping::Config {
        base_url: url,
        accounts: vec![a],
    };
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
    config.accounts.push(b);
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT used FROM gp_account_usage WHERE account='first' AND bucket=?",
            [airroute_rules::now() / 3600],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT attempt_seq FROM jobs WHERE case_key=?",
            [key],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote WHERE remote_id='accepted-v6'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
    server.abort();
}
#[tokio::test]
async fn an_explicit_required_region_is_posted_and_collected_once_without_default_extra_views() {
    use airroute_rules::{
        now,
        store::{CaseInput, Node, ProbeResult},
        work,
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let app=Router::new().route("/limits",get(limit_snapshot)).route("/measurements",post(move |Json(body):Json<Value>|{let count=count.clone();async move {
        assert_eq!(body["type"],"traceroute");assert_eq!(body["locations"][0]["magic"],"DE");count.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
        (StatusCode::ACCEPTED,[("x-ratelimit-limit","500"),("x-ratelimit-remaining","499"),("x-ratelimit-reset","3600")],Json(json!({"id":"supplement","probesCount":1})))
    }})).route("/measurements/{id}",get(|Path(id):Path<String>|async move {Json(json!({"id":id,"type":"traceroute","target":"1.1.1.1","measurementOptions":{"protocol":"ICMP"},"status":"finished","results":[{"probe":{"country":"DE","asn":64501},"result":{"status":"finished","resolvedAddress":"1.1.1.1","hops":[{"resolvedAddress":"1.1.1.1","timings":[{"rtt":1.0}]}]}}]}))}));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut a = local_account(&s, true);
    a.regions = std::collections::BTreeMap::from([("europe".into(), "DE".into())]);
    let config = local_config(a, url);
    let n = Node {
        id: "self-us".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["traceroute".into()],
    };
    s.register_node(&n, &airroute_rules::hash("fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE nodes SET connected=1,last_seen=?", [now()])
        .unwrap();
    let c = CaseInput {
        key: "geo".into(),
        fingerprint: "fp".into(),
        kind: "geolocation".into(),
        subject: "1.1.1.0/24".into(),
        reason: "regional conflict".into(),
        payload: json!({"kind":"geolocation","family":4,"regions":["europe"],"targets":[],"ranges":[["1.1.1.0","1.1.1.255"]]}),
    };
    let b = s.start_build().unwrap();
    s.commit_build(&b, "fixture", &json!({}), &[c], &[])
        .unwrap();
    s.targets("geo", "fp", &["1.1.1.1".into()]).unwrap();
    let l = s.lease(&n).unwrap().unwrap();
    s.submit(
        &n.id,
        &ProbeResult {
            id: "self-result".into(),
            job_id: l.id,
            fingerprint: l.fingerprint,
            lease_token: l.token,
            observed_at: now(),
            outcome: "ok".into(),
            evidence: json!({"kind":"traceroute","protocol":"icmp","reached":true,"target":"1.1.1.1","hops":[{"ip":"1.1.1.1"}]}),
        },
    )
    .unwrap();
    s.connect()
        .unwrap()
        .execute("DELETE FROM meta WHERE key='work-refresh-at'", [])
        .unwrap();
    work::refresh(&s).unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an automatic case must not manufacture a second regional view"
    );
    s.enqueue_observation(
        "1.1.1.1",
        &["europe".into()],
        "explicit required regional observation",
    )
    .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        airroute_rules::globalping::status(&s, &config).unwrap()["accounts"][0]["limits"]["remaining"],
        499
    );
    s.connect()
        .unwrap()
        .execute("UPDATE gp_remote SET next_poll=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        airroute_rules::globalping::status(&s, &config).unwrap()["accounts"][0]["completed_tasks"],
        1
    );
    server.abort();
}

#[tokio::test]
async fn a_slow_create_response_does_not_stop_later_send_starts_for_the_same_account() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let starts = Arc::new(Mutex::new(Vec::<std::time::Instant>::new()));
    let replies = Arc::new(AtomicUsize::new(0));
    let captured = starts.clone();
    let finished = replies.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move || {
            let starts = captured.clone();
            let replies = finished.clone();
            async move {
                let id = {
                    let mut v = starts.lock().unwrap();
                    v.push(std::time::Instant::now());
                    v.len()
                };
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                replies.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::ACCEPTED,
                    Json(json!({"id":format!("slow-{id}")})),
                )
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    for host in ["one-slow.example", "two-slow.example"] {
        s.enqueue_observation(
            host,
            &["us".into()],
            "actual send-start concurrency fixture",
        )
        .unwrap();
    }
    let observed_start = std::time::Instant::now();
    let worker_store = s.clone();
    let worker =
        tokio::spawn(async move { airroute_rules::globalping::run(&worker_store, &config).await });
    let deadline = tokio::time::timeout(std::time::Duration::from_secs(12), async {
        while starts.lock().unwrap().len() < 2 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    if deadline.is_err() {
        let c = s.connect().unwrap();
        let jobs=c.prepare("SELECT json_object('target',target,'state',status,'attempt',attempt_seq,'executions',execution_count,'not_before',not_before) FROM jobs").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        let intents=c.prepare("SELECT json_object('state',state,'next_poll',next_poll,'send_started_at',send_started_at,'cost',reserved_cost) FROM gp_remote").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        let quota=c.prepare("SELECT json_object('used',used,'blocked_until',blocked_until) FROM gp_account_usage").unwrap().query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        let starts_ms: Vec<_> = starts
            .lock()
            .unwrap()
            .iter()
            .map(|v| v.duration_since(observed_start).as_millis())
            .collect();
        let stopped = worker.is_finished();
        worker.abort();
        server.abort();
        panic!(
            "second admission must not await the first 15-second response; starts_ms={starts_ms:?},worker_stopped={stopped},jobs={jobs:?},intents={intents:?},quota={quota:?}"
        );
    }
    let times = starts.lock().unwrap().clone();
    assert!(times[1].duration_since(times[0]) >= std::time::Duration::from_secs(5));
    assert_eq!(replies.load(Ordering::SeqCst), 0);
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote WHERE state='sending' AND remote_id=''",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        2
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        2
    );
    worker.abort();
    server.abort();
}

#[tokio::test]
async fn a_revoked_account_backoff_does_not_starve_other_known_remote_ids() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let bad = Arc::new(AtomicUsize::new(0));
    let good = Arc::new(AtomicUsize::new(0));
    let a = bad.clone();
    let b = good.clone();
    let app = Router::new().route(
        "/measurements/{id}",
        get(move |Path(id): Path<String>| {
            let bad = a.clone();
            let good = b.clone();
            async move {
                if id.starts_with("revoked-") {
                    bad.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error":"fixture revoked credential"})),
                    )
                } else {
                    good.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::OK, poll(&id).await)
                }
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, false);
    let mut b = local_account(&s, false);
    b.id = "other".into();
    for i in 0..20 {
        let job = pending_measurement(
            &s,
            &a,
            "us",
            &format!("revoked-{i:02}"),
            &format!("revoked-{i}.example"),
        );
        // Old installations can contain more than the new active admission cap;
        // these paid ids must drain even if their job state is already historical.
        s.connect()
            .unwrap()
            .execute("UPDATE jobs SET status='unknown' WHERE id=?", [job])
            .unwrap();
    }
    let good_job = pending_measurement(&s, &b, "us", "working-id", "working.example");
    let config = airroute_rules::globalping::Config {
        base_url: url,
        accounts: vec![a, b],
    };
    // Ensure deterministic oldest-first batch: first sixteen are the revoked account.
    s.connect()
        .unwrap()
        .execute(
            "UPDATE gp_remote SET next_poll=-10 WHERE account='fixture'",
            [],
        )
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(bad.load(Ordering::SeqCst), 16);
    assert_eq!(good.load(Ordering::SeqCst), 0);
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(
        bad.load(Ordering::SeqCst),
        16,
        "account-level pause covers the remaining revoked ids"
    );
    assert_eq!(good.load(Ordering::SeqCst), 1);
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote WHERE account='fixture'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        20,
        "revocation preserves recoverable paid ids"
    );
    assert!(
        !c.query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM gp_remote WHERE job_id=?)",
            [good_job],
            |r| r.get(0)
        )
        .unwrap()
    );
    server.abort();
}

#[tokio::test]
async fn a_provider_timeout_is_uncertain_and_manual_refresh_cannot_repost_it() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let posts = Arc::new(AtomicUsize::new(0));
    let count = posts.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                (
                    StatusCode::REQUEST_TIMEOUT,
                    Json(json!({"error":"delivery state unknown"})),
                )
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    let key = s
        .enqueue_observation(
            "timeout.example",
            &["us".into()],
            "uncertain timeout fixture",
        )
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let c = s.connect().unwrap();
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT state FROM gp_remote", [], |r| r.get(0))
            .unwrap(),
        "unknown"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    s.request_observation(
        "timeout.example",
        &["us".into()],
        "explicit refresh must not bypass unresolved intent",
        true,
    )
    .unwrap();
    c.execute("UPDATE gp_account_usage SET blocked_until=0", [])
        .unwrap();
    c.execute("UPDATE gp_send_clock SET last_started_ms=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote g JOIN jobs j ON j.id=g.job_id WHERE j.case_key=?",
            [key],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn a_required_asn_is_sent_as_an_actual_probe_filter_and_verified_on_return() {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = calls.clone();
    let app=Router::new().route("/limits",get(limit_snapshot)).route("/measurements",post(move|Json(body):Json<Value>|{
        let calls=captured.clone();async move {assert_eq!(body["locations"][0]["asn"],64510);calls.lock().unwrap().push(body);(StatusCode::ACCEPTED,Json(json!({"id":"required-asn"})))}
    })).route("/measurements/{id}",get(|Path(id):Path<String>|async move {Json(json!({"id":id,"type":"dns","target":"asn.example","measurementOptions":{"protocol":"UDP","query":{"type":"A"}},"status":"finished","results":[{"probe":{"country":"US","asn":64510},"result":{"status":"finished","statusCode":0,"answers":[{"name":"asn.example","type":"A","value":"1.1.1.1","ttl":60}]}}]}))}));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    let key = s
        .enqueue_observation(
            "asn.example",
            &["us".into()],
            "necessary ASN observation fixture",
        )
        .unwrap();
    let stale = require_asn_from_case(&s, &key, 64510);
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(
        calls.lock().unwrap().len(),
        1,
        "virtual ASN zero must not reject an expressible provider filter"
    );
    s.connect()
        .unwrap()
        .execute("UPDATE gp_remote SET next_poll=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results WHERE qualified=1", [], |r| r
                .get(0))
            .unwrap(),
        1
    );
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_stale_job_was_not_dispatched(&s, &stale);
    server.abort();
}

#[tokio::test]
async fn a_missing_required_asn_does_not_disable_other_probes_of_the_same_family() {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = calls.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move |Json(body): Json<Value>| {
            let calls = captured.clone();
            async move {
                let constrained = body["locations"][0]["asn"] == 64510;
                calls.lock().unwrap().push(body);
                if constrained {
                    (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(json!({"error":{"type":"no_probes_found"}})),
                    )
                } else {
                    (
                        StatusCode::ACCEPTED,
                        Json(json!({"id":"unconstrained-probe"})),
                    )
                }
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    let key = s
        .enqueue_observation(
            "missing-asn.example",
            &["us".into()],
            "necessary ASN missing fixture",
        )
        .unwrap();
    let stale = require_asn_from_case(&s, &key, 64510);
    let c = s.connect().unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM gp_unavailable", [], |r| r.get(0))
            .unwrap(),
        0,
        "missing one ASN is not missing every IPv4 probe in that region"
    );
    s.enqueue_observation(
        "plain.example",
        &["us".into()],
        "unrelated observation must remain eligible",
    )
    .unwrap();
    c.execute("UPDATE gp_account_usage SET blocked_until=0", [])
        .unwrap();
    c.execute("UPDATE gp_send_clock SET last_started_ms=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert!(calls.lock().unwrap()[1]["locations"][0]["asn"].is_null());
    assert_eq!(calls.lock().unwrap()[1]["target"], "plain.example");
    assert_stale_job_was_not_dispatched(&s, &stale);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn collecting_a_closed_case_releases_its_old_slot_without_refunding_or_touching_other_leases()
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let posts = Arc::new(AtomicUsize::new(0));
    let count = posts.clone();
    let app=Router::new().route("/limits",get(limit_snapshot)).route("/measurements",post(move|Json(body):Json<Value>|{
        let count=count.clone();async move {assert_eq!(body["target"],"next-available.example");count.fetch_add(1,Ordering::SeqCst);(StatusCode::ACCEPTED,Json(json!({"id":"next-available"})))}
    })).route("/measurements/{id}",get(|Path(id):Path<String>|async move {
        if id=="old-closed-0" {Json(json!({"id":id,"type":"dns","target":"closed-0.example","measurementOptions":{"protocol":"UDP","query":{"type":"A"}},"status":"finished","results":[{"probe":{"country":"US","asn":64510},"result":{"status":"finished","statusCode":0,"answers":[{"name":"closed-0.example","type":"A","value":"1.1.1.1","ttl":60}]}}]}))}
        else {Json(json!({"id":id,"status":"in-progress"}))}
    }));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a.clone(), url);
    let mut closed = String::new();
    for i in 0..16 {
        let job = pending_measurement(
            &s,
            &a,
            "us",
            &format!("old-closed-{i}"),
            &format!("closed-{i}.example"),
        );
        if i == 0 {
            closed = job;
        }
    }
    let c = s.connect().unwrap();
    c.execute(
        "INSERT INTO gp_account_usage VALUES(?,?,16,0)",
        rusqlite::params![a.id, airroute_rules::now() / 3600],
    )
    .unwrap();
    c.execute(
        "UPDATE cases SET active=0 WHERE key=(SELECT case_key FROM jobs WHERE id=?)",
        [&closed],
    )
    .unwrap();
    s.enqueue_observation(
        "next-available.example",
        &["us".into()],
        "new work waiting for released paid slot",
    )
    .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    // Poll and admission run independently: the released slot may be filled
    // during this round or the immediate next one, depending on the GET race.
    let newly_sent = posts.load(Ordering::SeqCst) as i64;
    assert!(newly_sent <= 1);
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [&closed], |r| r
            .get(0))
            .unwrap(),
        "obsolete"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='leased' AND lease_node LIKE 'globalping:%'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        15 + newly_sent
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        16 + newly_sent,
        "completed historical work was paid and must not be refunded"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM results WHERE job_id=? AND accepted=0",
            [&closed],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(
        posts.load(Ordering::SeqCst),
        1,
        "the slot is usable immediately without waiting for the old 180s lease timeout"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        17
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM gp_remote WHERE remote_id LIKE 'old-closed-%'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        15,
        "other attempts remain in flight"
    );
    server.abort();
}

#[tokio::test]
async fn every_region_is_checked_for_uncovered_work_before_shared_fallback() {
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = calls.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move |Json(body): Json<Value>| {
            let calls = captured.clone();
            async move {
                calls.lock().unwrap().push(body);
                (StatusCode::ACCEPTED, Json(json!({"id":"uncovered-first"})))
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut a = local_account(&s, true);
    a.regions = std::collections::BTreeMap::from([
        ("cn-geo".into(), "CN".into()),
        ("europe".into(), "DE".into()),
    ]);
    let config = local_config(a, url);
    let n = airroute_rules::store::Node {
        id: "self-cn".into(),
        region: "cn-geo".into(),
        asn: 64501,
        capabilities: vec!["dns".into()],
    };
    s.register_node(&n, &airroute_rules::hash("public-fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=? WHERE id=?",
            rusqlite::params![airroute_rules::now(), n.id],
        )
        .unwrap();
    s.enqueue_observation(
        "covered-first.example",
        &["cn-geo".into()],
        "first region has an owned observer",
    )
    .unwrap();
    s.enqueue_observation(
        "uncovered-later.example",
        &["europe".into()],
        "later region needs third-party coverage",
    )
    .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let submitted = calls.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0]["target"], "uncovered-later.example");
    assert_eq!(submitted[0]["locations"][0]["magic"], "DE");
    let owned = s.lease(&n).unwrap().unwrap();
    assert_eq!(owned.target, "covered-first.example");
    server.abort();
}

#[tokio::test]
async fn a_busy_owned_observer_does_not_prevent_globalping_from_filling_shared_backlog() {
    let (url, mock, server) = fixture(false).await;
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    let n = airroute_rules::store::Node {
        id: "busy-owned".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into()],
    };
    s.register_node(&n, &airroute_rules::hash("public-fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=?,concurrency_limit=1 WHERE id=?",
            rusqlite::params![airroute_rules::now(), n.id],
        )
        .unwrap();
    s.enqueue_observation(
        "owned-busy.example",
        &["us".into()],
        "occupy the one owned slot",
    )
    .unwrap();
    let busy = s.lease(&n).unwrap().unwrap();
    s.enqueue_observation(
        "shared-backlog.example",
        &["us".into()],
        "shared backlog can use free provider allowance",
    )
    .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    assert_eq!(
        mock.measurements.lock().unwrap().values().next().unwrap()["target"],
        "shared-backlog.example"
    );
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [busy.id], |r| r
            .get(0))
            .unwrap(),
        "leased"
    );
    assert!(s.lease(&n).unwrap().is_none());
    server.abort();
}

#[tokio::test]
async fn permission_rejection_refunds_the_execution_and_cools_only_the_bad_account() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = calls.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move |h: HeaderMap| {
            let calls = captured.clone();
            async move {
                let auth = h["authorization"].to_str().unwrap().to_string();
                calls.lock().unwrap().push(auth.clone());
                if auth.contains("rejected-fixture") {
                    (
                        StatusCode::FORBIDDEN,
                        [("retry-after", "1")],
                        Json(json!({"error":"insufficient measurement scope"})),
                    )
                } else {
                    (
                        StatusCode::ACCEPTED,
                        [("retry-after", "1")],
                        Json(json!({"id":"healthy-account"})),
                    )
                }
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut bad = local_account(&s, true);
    bad.id = "bad".into();
    bad.credential_ref =
        Some(airroute_rules::secrets::save(d.path(), "rejected-fixture-token").unwrap());
    let mut config = local_config(bad.clone(), url);
    s.enqueue_observation(
        "permission.example",
        &["us".into()],
        "permission rejection is not an execution",
    )
    .unwrap();
    let at = airroute_rules::now();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let c = s.connect().unwrap();
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(execution_count) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT sum(used) FROM gp_account_usage WHERE account='bad'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert!(
        c.query_row::<i64, _, _>(
            "SELECT max(blocked_until) FROM gp_account_usage WHERE account='bad'",
            [],
            |r| r.get(0)
        )
        .unwrap()
            >= at + 300
    );
    let mut good = local_account(&s, true);
    good.id = "good".into();
    config.accounts.push(good);
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let calls = calls.lock().unwrap().clone();
    assert_eq!(calls.len(), 2);
    assert!(calls[0].contains("rejected-fixture"));
    assert!(!calls[1].contains("rejected-fixture"));
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(execution_count) FROM jobs", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn incomplete_uncovered_scan_never_falls_back_to_a_deep_covered_prefix() {
    const COVERED: usize = 4097;
    let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = calls.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move |Json(body): Json<Value>| {
            let calls = captured.clone();
            async move {
                calls.lock().unwrap().push(body);
                (
                    StatusCode::ACCEPTED,
                    Json(json!({"id":"deep-uncovered-first"})),
                )
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, url);
    let n = airroute_rules::store::Node {
        id: "covered-prefix-owned".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["dns".into()],
    };
    s.register_node(&n, &airroute_rules::hash("public-fixture"))
        .unwrap();
    s.connect()
        .unwrap()
        .execute(
            "UPDATE nodes SET connected=1,last_seen=? WHERE id=?",
            rusqlite::params![airroute_rules::now(), n.id],
        )
        .unwrap();
    // Seed real planner inputs in one isolated setup transaction. Every case
    // has one exact host; only the final necessary ASN lacks an owned observer.
    let mut c = s.connect().unwrap();
    let tx = c.transaction().unwrap();
    for i in 0..=COVERED {
        let host = if i < COVERED {
            format!("deep-covered-{i:04}.example")
        } else {
            "deep-uncovered-asn.example".into()
        };
        let key = format!("deep-queue:{host}");
        let mut payload =
            json!({"kind":"domain-observation","targets":[host],"regions":["us"],"manual":true});
        if i == COVERED {
            payload["required_asn"] = json!(64510);
        }
        let fp = airroute_rules::fingerprint(&payload);
        tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,?,1,'domain-observation',?,'bounded deep-queue priority fixture',?,'needs-active',1,?)",rusqlite::params![key,fp,host,payload.to_string(),airroute_rules::now()]).unwrap();
        assert_eq!(
            airroute_rules::work::plan_on(&tx, &key, &fp, &payload).unwrap(),
            1
        );
    }
    let at = airroute_rules::now();
    tx.execute("UPDATE jobs SET not_before=CASE WHEN json_extract(profile,'$.required_asn')=64510 THEN ? ELSE ? END",rusqlite::params![at-50,at-100]).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='pending'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        (COVERED + 1) as i64
    );
    let mut found = false;
    // Each coordinator wake may advance a bounded scan with no measurement.
    // Returning None is not proof of absence until that scan reaches its end.
    for _ in 0..8 {
        airroute_rules::globalping::tick(&s, &config).await.unwrap();
        let sent = calls.lock().unwrap().clone();
        if !sent.is_empty() {
            assert_eq!(
                sent.len(),
                1,
                "the fixture allows only one measurement submission"
            );
            assert_eq!(
                sent[0]["target"], "deep-uncovered-asn.example",
                "an incomplete preferred scan must not be mistaken for no uncovered executable work"
            );
            assert_eq!(sent[0]["locations"][0]["asn"], 64510);
            found = true;
            break;
        }
    }
    assert!(
        found,
        "bounded coordinator scans must make progress to the uncovered tail"
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM jobs WHERE status='pending'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        COVERED as i64
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
}

// Persist a fully scoped, requalified old observation independently of the new
// demand. Its original source can be gone; its time and observer remain intact.
fn insert_late_trusted_trace(store: &Store, target: &str) {
    use airroute_rules::store::{Lease, Node, ProbeResult};
    let node = Node {
        id: "late-historical-observer".into(),
        region: "us".into(),
        asn: 64599,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, &airroute_rules::hash("public historical fixture"))
        .unwrap();
    let at = airroute_rules::now() - 30;
    let profile = json!({"protocol":"icmp","max_hops":24,"region_required":true,"observer":{"id":node.id,"region":"us","asn":64599}});
    let lease = Lease {
        id: "late-historical-job".into(),
        case_key: "removed-historical-source".into(),
        fingerprint: "old-source-fp".into(),
        kind: "traceroute".into(),
        target: target.into(),
        region: "us".into(),
        token: "old authenticated fixture attempt".into(),
        until: at + 180,
        profile: profile.clone(),
    };
    let result = ProbeResult {
        id: "late-trusted-trace".into(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: at,
        outcome: "ok".into(),
        evidence: json!({"kind":"traceroute","target":target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":target}]}),
    };
    let q = airroute_rules::receipt::qualify(&lease, &node, &result);
    assert!(q.qualified);
    assert_eq!(q.evidence_until, Some(at + 86400));
    let mut c = store.connect().unwrap();
    let tx = c.transaction().unwrap();
    tx.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,result_id,attempt_seq,execution_terminal,evidence_until,logical_key,demand_key) VALUES(?,?,?,?,?,?,?,'complete',?,?,?,1,1,?,'historical-alias','historical-alias')",rusqlite::params![lease.id,lease.case_key,lease.fingerprint,lease.kind,target,lease.region,profile.to_string(),at,at,result.id,q.evidence_until]).unwrap();
    tx.execute("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,lease_profile,started_at,completed_at,result_class,observer_asn) VALUES(?,?,?,?,?,1,?,?,?,'observation',64599)",rusqlite::params![lease.id,airroute_rules::hash(&lease.token),node.id,lease.fingerprint,at,profile.to_string(),at,at+1]).unwrap();
    tx.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,attempt_seq,qualified,evidence_until,execution_class,observer_asn) VALUES(?,?,?,?,?,'ok',?,0,?,1,1,?,'observation',64599)",rusqlite::params![result.id,lease.id,node.id,lease.fingerprint,at,result.evidence.to_string(),at+1,q.evidence_until]).unwrap();
    tx.execute(
        "INSERT INTO executor_counters(executor,completed_tasks,last_completed_at) VALUES(?,1,?)",
        rusqlite::params![node.id, at + 1],
    )
    .unwrap();
    tx.commit().unwrap();
}

#[tokio::test]
async fn a_fresh_fact_arriving_after_gp_preparation_cancels_only_the_unsent_reservation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let polls = Arc::new(AtomicUsize::new(0));
    let checked = polls.clone();
    let sender = Arc::new(AtomicUsize::new(0));
    let posts = sender.clone();
    let during = s.clone();
    let app = Router::new()
        .route(
            "/limits",
            get(move || {
                let n = checked.clone();
                let store = during.clone();
                async move {
                    if n.fetch_add(1, Ordering::SeqCst) == 1 {
                        let c = store.connect().unwrap();
                        assert_eq!(
                            c.query_row::<i64, _, _>(
                                "SELECT count(*) FROM gp_remote WHERE state='prepared'",
                                [],
                                |r| r.get(0)
                            )
                            .unwrap(),
                            1
                        );
                        assert_eq!(
                            c.query_row::<i64, _, _>(
                                "SELECT sum(execution_count) FROM jobs",
                                [],
                                |r| r.get(0)
                            )
                            .unwrap(),
                            0
                        );
                        insert_late_trusted_trace(&store, "1.1.1.1");
                    }
                    limit_snapshot().await
                }
            }),
        )
        .route(
            "/measurements",
            post(move || {
                let posts = posts.clone();
                async move {
                    posts.fetch_add(1, Ordering::SeqCst);
                    (
                        StatusCode::ACCEPTED,
                        Json(json!({"id":"must-not-be-created"})),
                    )
                }
            }),
        );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let config = local_config(a, url);
    s.enqueue_observation(
        "1.1.1.1",
        &["us".into()],
        "fresh evidence may arrive during quota preflight",
    )
    .unwrap();
    let c = s.connect().unwrap();
    let current: String = c
        .query_row("SELECT id FROM jobs", [], |r| r.get(0))
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(sender.load(Ordering::SeqCst), 0);
    let state: (String, Option<String>, i64, Option<i64>) = c
        .query_row(
            "SELECT status,result_id,execution_count,evidence_until FROM jobs WHERE id=?",
            [&current],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(state.0, "complete");
    assert_eq!(state.1.as_deref(), Some("late-trusted-trace"));
    assert_eq!(state.2, 0);
    let original_until: i64 = c
        .query_row(
            "SELECT evidence_until FROM results WHERE id='late-trusted-trace'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state.3, Some(original_until));
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM gp_remote", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT coalesce(sum(used),0) FROM gp_account_usage",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM results WHERE job_id=?",
            [&current],
            |r| r.get(0)
        )
        .unwrap(),
        0,
        "reuse references history, not a forged new execution receipt"
    );
    let history: (Option<i64>, bool, String) = c
        .query_row(
            "SELECT started_at,execution_refunded,result_class FROM lease_history WHERE job_id=?",
            [&current],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(history, (None, true, "not-executed".into()));
    assert_eq!(c.query_row::<i64,_,_>("SELECT coalesce(sum(completed_tasks),0) FROM executor_counters WHERE executor LIKE 'globalping:%'",[],|r|r.get(0)).unwrap(),0);
    server.abort();
}

#[tokio::test]
async fn late_fresh_facts_do_not_cancel_an_already_sent_or_unknown_gp_intent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let posts = Arc::new(AtomicUsize::new(0));
    let captured = posts.clone();
    let during = s.clone();
    let app = Router::new().route("/limits", get(limit_snapshot)).route(
        "/measurements",
        post(move || {
            let posts = captured.clone();
            let store = during.clone();
            async move {
                posts.fetch_add(1, Ordering::SeqCst);
                let c = store.connect().unwrap();
                let (state, saved): (String, String) = c
                    .query_row("SELECT state,lease FROM gp_remote", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .unwrap();
                assert_eq!(state, "sending");
                let lease: airroute_rules::store::Lease = serde_json::from_str(&saved).unwrap();
                insert_late_trusted_trace(&store, "1.1.1.1");
                let mut c = store.connect().unwrap();
                let tx = c.transaction().unwrap();
                assert!(
                    airroute_rules::jobs_v3::consume_execution_on(&tx, &lease).unwrap(),
                    "already-started admission is idempotent and does not reuse away the execution"
                );
                assert_eq!(
                    tx.query_row::<String, _, _>(
                        "SELECT status FROM jobs WHERE id=?",
                        [&lease.id],
                        |r| r.get(0)
                    )
                    .unwrap(),
                    "leased"
                );
                tx.commit().unwrap();
                (
                    StatusCode::REQUEST_TIMEOUT,
                    Json(json!({"error":"provider delivery outcome remains unknown"})),
                )
            }
        }),
    );
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", socket.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(socket, app).await.unwrap() });
    let config = local_config(a, url);
    let key = s
        .enqueue_observation(
            "1.1.1.1",
            &["us".into()],
            "late facts cannot settle an unknown delivery",
        )
        .unwrap();
    let c = s.connect().unwrap();
    let current: String = c
        .query_row("SELECT id FROM jobs", [], |r| r.get(0))
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let (fp, body): (String, String) = c
        .query_row("SELECT fp,payload FROM cases WHERE key=?", [&key], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    airroute_rules::work::plan_on(
        &c,
        &key,
        &fp,
        &serde_json::from_str::<Value>(&body).unwrap(),
    )
    .unwrap();
    c.execute("UPDATE gp_account_usage SET blocked_until=0", [])
        .unwrap();
    c.execute("UPDATE gp_send_clock SET last_started_ms=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(posts.load(Ordering::SeqCst), 1);
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT state FROM gp_remote WHERE job_id=?",
            [&current],
            |r| r.get(0)
        )
        .unwrap(),
        "unknown"
    );
    let state: (String, i64, Option<String>) = c
        .query_row(
            "SELECT status,execution_count,result_id FROM jobs WHERE id=?",
            [&current],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(state, ("unknown".into(), 1, None));
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        1
    );
    assert!(
        !c.query_row::<bool, _, _>(
            "SELECT execution_refunded FROM lease_history WHERE job_id=?",
            [&current],
            |r| r.get(0)
        )
        .unwrap()
    );
    server.abort();
}

#[tokio::test]
async fn wrong_remote_id_is_not_a_receipt_and_keeps_the_original_intent() {
    let app=Router::new().route("/measurements/{id}",get(||async{Json(json!({"id":"another-measurement","status":"finished","type":"dns","target":"wrong-id.example"}))}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, false);
    let job = pending_measurement(&s, &a, "us", "expected-measurement", "wrong-id.example");
    airroute_rules::globalping::tick(&s, &local_config(a, url))
        .await
        .unwrap();
    let c = s.connect().unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT remote_id FROM gp_remote WHERE job_id=?",
            [&job],
            |r| r.get(0)
        )
        .unwrap(),
        "expected-measurement"
    );
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM gp_remote", [], |r| r.get(0))
            .unwrap(),
        1
    );
    server.abort();
}

#[tokio::test]
async fn accepted_measurement_location_recovers_the_original_intent_without_an_id_body() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for reference in [
        "absolute",
        "root-relative",
        "path-relative",
        "unreadable-body",
    ] {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let a = local_account(&s, true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let remote = "Recovered_ID-1";
        let location = match reference {
            "root-relative" => format!("/v1/measurements/{remote}"),
            "path-relative" => format!("measurements/{remote}"),
            _ => format!("{base}/measurements/{remote}"),
        };
        let posts = Arc::new(AtomicUsize::new(0));
        let count = posts.clone();
        let saved = Arc::new(Mutex::new(None));
        let original = saved.clone();
        let store = s.clone();
        let app = Router::new()
            .route("/v1/limits", get(limit_snapshot))
            .route("/v1/measurements", post(move || {
                let count = count.clone(); let store = store.clone();
                let original = original.clone(); let location = location.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let identity: (String, i64, String) = store.connect().unwrap().query_row("SELECT job_id,attempt_seq,json_extract(lease,'$.token') FROM gp_remote WHERE state='sending'", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
                    *original.lock().unwrap() = Some(identity);
                    let body = if reference == "unreadable-body" { "{" } else { "{\"probesCount\":1}" };
                    (StatusCode::ACCEPTED, [("location", location), ("content-type", "application/json".into())], body)
                }
            }))
            .route("/v1/measurements/{id}", get(|Path(id): Path<String>| async move {
                Json(json!({"id":id,"type":"dns","target":"location-recovery.example","measurementOptions":{"protocol":"UDP","query":{"type":"A"}},"status":"finished","results":[{"probe":{"country":"US","asn":64500},"result":{"status":"finished","statusCode":0,"answers":[{"name":"location-recovery.example","type":"A","value":"1.1.1.1","ttl":60}]}}]}))
            }));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        s.enqueue_observation(
            "location-recovery.example",
            &["us".into()],
            "recover an accepted measurement from its official Location",
        )
        .unwrap();
        let config = local_config(a, base);
        airroute_rules::globalping::tick(&s, &config).await.unwrap();
        let c = s.connect().unwrap();
        let (job, attempt, lease_token) = saved.lock().unwrap().clone().unwrap();
        let persisted: (String, String, i64, String) = c.query_row("SELECT remote_id,state,attempt_seq,json_extract(lease,'$.token') FROM gp_remote WHERE job_id=?", [&job], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(
            persisted,
            (remote.into(), "submitted".into(), attempt, lease_token),
            "valid {reference} must retain the original paid attempt identity"
        );
        c.execute("UPDATE gp_remote SET next_poll=0 WHERE job_id=?", [&job])
            .unwrap();
        airroute_rules::globalping::tick(&s, &config).await.unwrap();
        assert_eq!(
            posts.load(Ordering::SeqCst),
            1,
            "recovering a Location must never send a replacement POST"
        );
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT count(*) FROM results WHERE job_id=? AND qualified=1",
                [&job],
                |r| r.get(0)
            )
            .unwrap(),
            1
        );
        assert_eq!(
            c.query_row::<i64, _, _>(
                "SELECT count(*) FROM gp_remote WHERE job_id=?",
                [&job],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        server.abort();
    }
}

#[tokio::test]
async fn invalid_measurement_locations_remain_unknown_and_keep_the_original_charge() {
    for location in [
        "https://other.example/v1/measurements/remote-id",
        "/v1/measurements/remote%2fid",
        "/v1/measurements/remote-id?query=1",
        "/v1/measurements/remote-id/extra",
    ] {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let a = local_account(&s, true);
        let app = Router::new()
            .route("/v1/limits", get(limit_snapshot))
            .route(
                "/v1/measurements",
                post(move || async move {
                    (
                        StatusCode::ACCEPTED,
                        [("location", location)],
                        Json(json!({"probesCount":1})),
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}/v1", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        s.enqueue_observation(
            "invalid-location.example",
            &["us".into()],
            "ambiguous provider locations must not become polling targets",
        )
        .unwrap();
        airroute_rules::globalping::tick(&s, &local_config(a, base))
            .await
            .unwrap();
        let c = s.connect().unwrap();
        let state: (String, String, i64, i64) = c
            .query_row(
                "SELECT state,remote_id,reserved_cost,slot_active FROM gp_remote",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(state, ("unknown".into(), "".into(), 1, 0), "{location}");
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
                .unwrap(),
            1
        );
        assert!(
            !c.query_row::<bool, _, _>("SELECT execution_refunded FROM lease_history", [], |r| r
                .get(0))
                .unwrap()
        );
        server.abort();
    }
}

#[tokio::test]
async fn a_lost_create_response_keeps_its_charge_without_freezing_unrelated_jobs() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/v1", listener.local_addr().unwrap());
    let posts = Arc::new(AtomicUsize::new(0));
    let count = posts.clone();
    let targets = Arc::new(Mutex::new(Vec::new()));
    let received = targets.clone();
    // Read the complete POST, then close without any response bytes. This is
    // uncertain delivery, not a definite HTTP rejection or a longer timeout.
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let n = stream.read(&mut buffer).await.unwrap();
                if n == 0 {
                    break None;
                }
                request.extend_from_slice(&buffer[..n]);
                if let Some(i) = request.windows(4).position(|v| v == b"\r\n\r\n") {
                    break Some(i + 4);
                }
                assert!(request.len() < 16384);
            };
            let Some(header_end) = header_end else {
                continue;
            };
            let header = String::from_utf8_lossy(&request[..header_end]).to_string();
            let size = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + size {
                let n = stream.read(&mut buffer).await.unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
            }
            let body = if header.starts_with("GET /v1/limits ") {
                json!({"rateLimit":{"measurements":{"create":{"type":"user","limit":500,"remaining":500,"reset":0}}}}).to_string()
            } else if header.starts_with("POST /v1/measurements ") {
                let input: Value =
                    serde_json::from_slice(&request[header_end..header_end + size]).unwrap();
                received
                    .lock()
                    .unwrap()
                    .push(input["target"].as_str().unwrap().to_string());
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    continue;
                }
                json!({"id":"unrelated-measurement","probesCount":1}).to_string()
            } else {
                panic!("unexpected fixture request");
            };
            let status = if header.starts_with("POST ") {
                "202 Accepted"
            } else {
                "200 OK"
            };
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let a = local_account(&s, true);
    let config = local_config(a, base);
    s.enqueue_observation(
        "lost-response.example",
        &["us".into()],
        "a lost response cannot authorize a second paid POST",
    )
    .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    let c = s.connect().unwrap();
    let original: (String, i64, String) = c.query_row("SELECT job_id,attempt_seq,json_extract(lease,'$.token') FROM gp_remote WHERE state='unknown' AND remote_id='' AND reserved_cost=1 AND slot_active=0", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    drop(c);
    let s = Store::open(d.path()).unwrap();
    s.enqueue_observation(
        "unrelated-response.example",
        &["us".into()],
        "unrelated work remains eligible after uncertain delivery",
    )
    .unwrap();
    let c = s.connect().unwrap();
    // Move only the fixture's actual-send clock and spacing past their window;
    // leave the original uncertain charge and execution ledger untouched.
    c.execute(
        "UPDATE gp_send_clock SET last_started_ms=last_started_ms-6000",
        [],
    )
    .unwrap();
    c.execute("UPDATE gp_account_usage SET blocked_until=0", [])
        .unwrap();
    airroute_rules::globalping::tick(&s, &config).await.unwrap();
    assert_eq!(posts.load(Ordering::SeqCst), 2);
    assert_eq!(
        *targets.lock().unwrap(),
        ["lost-response.example", "unrelated-response.example"]
    );
    let retained: (String, i64, String) = c.query_row("SELECT job_id,attempt_seq,json_extract(lease,'$.token') FROM gp_remote WHERE state='unknown' AND remote_id='' AND reserved_cost=1 AND slot_active=0", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
    assert_eq!(retained, original);
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(used) FROM gp_account_usage", [], |r| r.get(0))
            .unwrap(),
        2
    );
    assert!(
        !c.query_row::<bool, _, _>(
            "SELECT execution_refunded FROM lease_history WHERE job_id=? AND attempt_seq=?",
            rusqlite::params![original.0, original.1],
            |r| r.get(0)
        )
        .unwrap()
    );
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM gp_remote WHERE state='submitted' AND remote_id='unrelated-measurement'", [], |r|r.get(0)).unwrap(), 1);
    server.abort();
}
