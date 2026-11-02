use airroute_rules::{
    globalping, hash, now,
    server::{self, App},
    store::Store,
    transport,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tower::ServiceExt;

fn http_app(data: &std::path::Path) -> App {
    App {
        root: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        data: data.into(),
        store: Store::open(data).unwrap(),
        offline: true,
        admin_hash: hash("fixture administrator credential"),
        gp: globalping::Config::default(),
        building: Arc::new(AtomicBool::new(false)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions: Arc::new(
            airroute_rules::console_session::ConsoleSessions::open(
                data,
                &hash("fixture administrator credential"),
            )
            .unwrap(),
        ),
        host: "localhost".into(),
        probe_hub: transport::Hub::default(),
    }
}

#[tokio::test]
async fn removed_manual_decision_api_returns_404_and_preserves_imported_history() {
    let d = tempfile::tempdir().unwrap();
    let app = http_app(d.path());
    let s = app.store.clone();
    s.connect().unwrap().execute("INSERT INTO decisions(case_key,fp,action,reason,created,revision) VALUES('legacy','old-fp','region:us','preserved legacy history',?,1)",[now()]).unwrap();
    for path in ["/api/decision", "/api/retry-jobs"] {
        let response = server::router(app.clone()).oneshot(Request::post(path)
        .header("authorization","Bearer fixture administrator credential")
        .header("content-type","application/json")
        .body(Body::from(json!({"key":"legacy","fingerprint":"old-fp","action":"region:europe","reason":"this removed route must not mutate history"}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<(i64, String), _, _>("SELECT count(*),action FROM decisions", [], |r| Ok(
                (r.get(0)?, r.get(1)?)
            ))
            .unwrap(),
        (1, "region:us".into())
    );
    assert!(s.builds().unwrap().as_array().unwrap().is_empty());
    assert!(!app.build_requested.load(Ordering::SeqCst));
    assert!(!app.building.load(Ordering::SeqCst));
}

#[tokio::test]
async fn accepted_new_measurement_is_saved_without_requesting_an_immediate_build() {
    use airroute_rules::store::{Node, ProbeResult};
    let d = tempfile::tempdir().unwrap();
    let app = http_app(d.path());
    let s = app.store.clone();
    s.enqueue_observation(
        "fixed-input.example",
        &["us".into()],
        "next daily build fixture",
    )
    .unwrap();
    let node = Node {
        id: "fixture-observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into()],
    };
    s.register_node(&node, &hash("fixture observer credential"))
        .unwrap();
    let lease = s.lease(&node).unwrap().unwrap();
    let result = ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({"kind":"dns","hostname":lease.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":now(),"valid_until":now()+60,"records":[{"name":lease.target,"type":"A","ttl":60,"data":"1.1.1.1"}]}]}),
    };
    let ack = s.submit(&node.id, &result).unwrap();
    assert_eq!(ack["accepted"], true);
    assert_eq!(ack["qualified"], true);
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT count(*) FROM results WHERE id=?",
                [result.id],
                |r| r.get(0)
            )
            .unwrap(),
        1
    );
    assert!(
        s.builds().unwrap().as_array().unwrap().is_empty(),
        "new observations become input of a later daily build"
    );
    assert!(s.meta("rebuild-requested").unwrap().is_none());
    assert!(s.meta("rebuild-generation").unwrap().is_none());
    assert!(!app.build_requested.load(Ordering::SeqCst));
    assert!(!app.building.load(Ordering::SeqCst));
}

#[tokio::test]
async fn ip_library_download_is_authorized_exact_and_404_for_an_older_release() {
    let d = tempfile::tempdir().unwrap();
    let app = http_app(d.path());
    let s = app.store.clone();
    let release = d.path().join("releases/abc123");
    std::fs::create_dir_all(&release).unwrap();
    let expected = "family,start,end,region,anycast\n4,1.1.1.1,1.1.1.1,us,false\n6,2001:4860::1,2001:4860::2,europe,false\n";
    std::fs::write(release.join("ip-library.csv"), expected).unwrap();
    std::fs::write(release.join("private-evidence.json"), "internal only").unwrap();
    s.set_meta("current-release", "abc123").unwrap();
    let router = server::router(app);
    assert_eq!(
        router
            .clone()
            .oneshot(Request::get("/api/ip-library").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let request = || {
        Request::get("/api/ip-library")
            .header("authorization", "Bearer fixture administrator credential")
            .body(Body::empty())
            .unwrap()
    };
    let response = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/csv; charset=utf-8"
    );
    assert_eq!(
        response.headers()["content-disposition"],
        "attachment; filename=ip-library.csv"
    );
    assert_eq!(
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap()
            .as_ref(),
        expected.as_bytes()
    );
    std::fs::create_dir_all(d.path().join("releases/def456")).unwrap();
    s.set_meta("current-release", "def456").unwrap();
    assert_eq!(
        router.oneshot(request()).await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
}

#[test]
fn store_reopen_does_not_rewrite_unchanged_plan_projection_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.enqueue_observation(
        "1.1.1.1",
        &["us".into()],
        "stable plan reconciliation fixture",
    )
    .unwrap();
    s.connect().unwrap().execute_batch("CREATE TABLE plan_writes(n INTEGER);CREATE TRIGGER count_plan_writes AFTER UPDATE ON measurement_plans BEGIN INSERT INTO plan_writes VALUES(1);END;").unwrap();
    Store::open(d.path()).unwrap();
    Store::open(d.path()).unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM plan_writes", [], |r| r.get(0))
            .unwrap(),
        0,
        "even same-value UPDATEs must be absent"
    );
}

#[test]
fn store_reopen_keeps_lifetime_counts_without_rescanning_or_rewriting_them() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.connect()
        .unwrap()
        .execute(
            "INSERT INTO executor_counters VALUES('node-fixture',41,?)",
            [now()],
        )
        .unwrap();
    s.connect().unwrap().execute_batch("CREATE TABLE count_writes(n INTEGER);CREATE TRIGGER count_executor_updates AFTER UPDATE ON executor_counters BEGIN INSERT INTO count_writes VALUES(1);END;").unwrap();
    let reopened = Store::open(d.path()).unwrap();
    assert_eq!(
        reopened
            .connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT completed_tasks FROM executor_counters WHERE executor='node-fixture'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
        41
    );
    assert_eq!(
        reopened
            .connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM count_writes", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn concurrent_requests_while_a_build_is_running_coalesce_into_one_pending_flag() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let app = App {
        root: d.path().into(),
        data: d.path().into(),
        store,
        offline: true,
        admin_hash: hash("fixture administrator credential"),
        gp: globalping::Config::default(),
        building: Arc::new(AtomicBool::new(true)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions: Arc::new(
            airroute_rules::console_session::ConsoleSessions::open(
                d.path(),
                &hash("fixture administrator credential"),
            )
            .unwrap(),
        ),
        host: "localhost".into(),
        probe_hub: transport::Hub::default(),
    };
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let app = app.clone();
        requests.spawn(async move { server::launch_build(app) });
    }
    while let Some(result) = requests.join_next().await {
        assert!(!result.unwrap());
    }
    assert!(app.building.load(Ordering::SeqCst));
    assert!(app.build_requested.load(Ordering::SeqCst));
    assert!(
        app.store.builds().unwrap().as_array().unwrap().is_empty(),
        "busy requests must not launch independent build workers"
    );
}

#[test]
fn discovery_vacancy_reads_use_active_indexes() {
    let dir = tempfile::tempdir().unwrap();
    let s = airroute_rules::store::Store::open(dir.path()).unwrap();
    let c = s.connect().unwrap();
    for (sql, index) in [
        (
            "EXPLAIN QUERY PLAN SELECT count(*) FROM jobs INDEXED BY job_discovery_active WHERE status IN ('pending','leased') AND json_extract(profile,'$.purpose')='discovery' AND json_extract(profile,'$.logical_job')=1",
            "job_discovery_active",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT 1 FROM jobs WHERE target='example.com' AND kind='dns' AND status IN ('pending','leased')",
            "job_active_target",
        ),
    ] {
        let details = c
            .prepare(sql)
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" ");
        assert!(details.contains(index), "{details}");
    }
}

#[test]
fn cli_startup_reads_file_settings_but_controller_build_does_not_reinitialize_them() {
    use airroute_rules::{build, publish, store::Store};
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("workspace");
    std::fs::create_dir_all(root.join("config")).unwrap();
    std::fs::write(
        root.join("config/github.toml"),
        "enabled=false\nrepository='fixture/rules'\nbranch='main'\n",
    )
    .unwrap();
    let cli_data = d.path().join("cli");
    assert!(build::run(&root, &cli_data, true).is_err()); // No recipes: fail without activating output.
    let cli_store = Store::open(&cli_data).unwrap();
    assert_eq!(
        publish::settings(&cli_store).unwrap().repository,
        "fixture/rules"
    );
    let controller_data = d.path().join("controller");
    let controller_store = Store::open(&controller_data).unwrap();
    assert!(build::run_with_store(&root, &controller_data, true, &controller_store).is_err());
    assert!(controller_store.meta("github-settings").unwrap().is_none());
}
