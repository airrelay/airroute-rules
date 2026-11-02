use airroute_rules::{
    globalping, hash,
    server::{self, App},
    store::Store,
    transport,
};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::Value;
use std::sync::{Arc, atomic::AtomicBool};
use tower::ServiceExt;

fn app(data: &std::path::Path) -> App {
    let store = Store::open(data).unwrap();
    globalping::initialize_intents(&store).unwrap();
    App {
        root: env!("CARGO_MANIFEST_DIR").into(),
        data: data.into(),
        store,
        offline: true,
        admin_hash: hash("audit HTTP fixture credential"),
        gp: globalping::Config::default(),
        building: Arc::new(AtomicBool::new(false)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions: Arc::new(
            airroute_rules::console_session::ConsoleSessions::open(
                data,
                &hash("audit HTTP fixture credential"),
            )
            .unwrap(),
        ),
        host: "localhost".into(),
        probe_hub: transport::Hub::default(),
    }
}

async fn get(app: &App, path: &str, authorized: bool) -> (StatusCode, Value) {
    let mut request = Request::get(path);
    if authorized {
        request = request.header("authorization", "Bearer audit HTTP fixture credential");
    }
    let response = server::router(app.clone())
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn audit_routes_require_auth_and_keep_split_empty_reads_nonmutating() {
    let directory = tempfile::tempdir().unwrap();
    let app = app(directory.path());
    let snapshot = || {
        let c = app.store.connect().unwrap();
        [
            "cases",
            "jobs",
            "results",
            "lease_history",
            "builds",
            "gp_remote",
            "decisions",
        ]
        .map(|t| {
            c.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        })
    };
    let before = snapshot();
    for view in ["issues", "tasks", "records"] {
        let path = format!("/api/audit/{view}");
        assert_eq!(get(&app, &path, false).await.0, StatusCode::UNAUTHORIZED);
        let (status, combined) = get(&app, &path, true).await;
        assert_eq!(status, StatusCode::OK, "{view}: {combined}");
        assert_eq!(combined["total"], 0);
        assert_eq!(combined["items"].as_array().unwrap().len(), 0);
        for part in ["items", "summary"] {
            let (status, value) = get(&app, &format!("{path}?part={part}"), true).await;
            assert_eq!(status, StatusCode::OK, "{view}/{part}: {value}");
            if part == "items" {
                assert!(value["items"].is_array());
            } else {
                assert_eq!(value["total"], 0);
            }
        }
    }
    assert_eq!(
        snapshot(),
        before,
        "reading the merged UI must not create work or rewrite history"
    );
    assert_eq!(
        get(&app, "/api/task-items?limit=1", true).await.0,
        StatusCode::OK
    );
    assert_eq!(
        get(&app, "/api/conflicts?limit=1", true).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn malformed_audit_scopes_fail_instead_of_silently_showing_another_scope() {
    let directory = tempfile::tempdir().unwrap();
    let app = app(directory.path());
    for path in [
        "/api/audit/tasks?part=unexpected",
        "/api/audit/tasks?state=does-not-exist",
        "/api/audit/tasks?purpose=does-not-exist",
        "/api/audit/tasks?range=does-not-exist",
        "/api/audit/records?state=does-not-exist",
        "/api/audit/records?after=100&before=99",
        "/api/audit/issues?category=does-not-exist",
        "/api/audit/issues?build_id=..%2F..%2Foutside",
    ] {
        let (status, body) = get(&app, path, true).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}: {body}");
        assert!(body["error"].is_string());
    }
}
