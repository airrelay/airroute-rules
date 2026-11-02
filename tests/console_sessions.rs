//! HTTP-only session lifecycle checks with synthetic credentials and isolated data.
//! Cookie values are never printed; assertions expose only statuses/attributes.
use airroute_rules::{
    console_session::ConsoleSessions,
    globalping, hash,
    server::{self, App},
    store::Store,
    transport,
};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use serde_json::json;
use std::{
    path::Path,
    sync::{Arc, atomic::AtomicBool},
};
use tower::ServiceExt;

const ADMIN: &str = "synthetic-console-session-administrator";
const ROTATED: &str = "synthetic-rotated-console-administrator";
const HOST: &str = "console.invalid";

fn app(data: &Path, administrator: &str) -> App {
    let admin_hash = hash(administrator);
    let sessions = Arc::new(ConsoleSessions::open(data, &admin_hash).unwrap());
    App {
        root: env!("CARGO_MANIFEST_DIR").into(),
        data: data.into(),
        store: Store::open(data).unwrap(),
        offline: true,
        admin_hash,
        gp: globalping::Config::default(),
        building: Arc::new(AtomicBool::new(false)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions,
        host: HOST.into(),
        probe_hub: transport::Hub::default(),
    }
}

async fn request(
    app: &App,
    method: Method,
    path: &str,
    body: Body,
    headers: &[(&str, &str)],
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, HOST);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    server::router(app.clone())
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
}

async fn login(app: &App, token: &str, headers: &[(&str, &str)]) -> Response {
    let mut all = vec![("content-type", "application/json")];
    all.extend_from_slice(headers);
    request(
        app,
        Method::POST,
        "/api/login",
        Body::from(json!({"token":token}).to_string()),
        &all,
    )
    .await
}

fn cookie(response: &Response) -> String {
    assert_eq!(response.status(), StatusCode::OK);
    let header = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("successful login must set a cookie")
        .to_str()
        .unwrap();
    assert!(
        header.starts_with("ar_session="),
        "session cookie name changed"
    );
    assert!(
        header.split(';').any(|p| p.trim() == "HttpOnly"),
        "session must be HttpOnly"
    );
    assert!(
        header.split(';').any(|p| p.trim() == "SameSite=Strict"),
        "session must be SameSite Strict"
    );
    assert!(
        header.split(';').any(|p| p.trim() == "Path=/"),
        "session path must cover the console"
    );
    assert!(
        header.split(';').any(|p| p.trim() == "Max-Age=28800"),
        "session lifetime must remain eight hours"
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    header.split(';').next().unwrap().to_owned()
}

fn has_secure(response: &Response) -> bool {
    response
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|h| h.to_str().ok())
        .is_some_and(|h| h.split(';').any(|p| p.trim() == "Secure"))
}

async fn session_status(app: &App, cookie: &str) -> StatusCode {
    request(
        app,
        Method::GET,
        "/api/session",
        Body::empty(),
        &[("cookie", cookie)],
    )
    .await
    .status()
}

#[tokio::test]
async fn cookie_survives_controller_reconstruction_and_bearer_access_is_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let original = app(directory.path(), ADMIN);
    let response = login(&original, ADMIN, &[("origin", "http://console.invalid")]).await;
    let issued = cookie(&response);
    assert!(
        !has_secure(&response),
        "local HTTP login must remain usable"
    );
    assert_eq!(session_status(&original, &issued).await, StatusCode::OK);
    drop(original);
    let reopened = app(directory.path(), ADMIN);
    assert_eq!(
        session_status(&reopened, &issued).await,
        StatusCode::OK,
        "same-path restart must preserve a valid signed cookie"
    );
    let bearer = format!("Bearer {ADMIN}");
    assert_eq!(
        request(
            &reopened,
            Method::GET,
            "/api/session",
            Body::empty(),
            &[("authorization", &bearer)]
        )
        .await
        .status(),
        StatusCode::OK
    );
    let invalid = login(&reopened, "synthetic-invalid-password", &[]).await;
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    assert!(
        invalid.headers().get(header::SET_COOKIE).is_none(),
        "failed login must not issue a session"
    );
}

#[tokio::test]
async fn logout_revokes_the_cookie_immediately_and_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let original = app(directory.path(), ADMIN);
    let issued = cookie(&login(&original, ADMIN, &[]).await);
    let response = request(
        &original,
        Method::POST,
        "/api/logout",
        Body::empty(),
        &[("cookie", &issued)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cleared = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("logout must clear browser state")
        .to_str()
        .unwrap();
    assert!(
        cleared.starts_with("ar_session=;"),
        "logout must clear only the session cookie value"
    );
    assert!(
        cleared.split(';').any(|p| p.trim() == "Max-Age=0"),
        "logout must expire browser state"
    );
    assert_eq!(
        session_status(&original, &issued).await,
        StatusCode::UNAUTHORIZED
    );
    drop(original);
    let reopened = app(directory.path(), ADMIN);
    assert_eq!(
        session_status(&reopened, &issued).await,
        StatusCode::UNAUTHORIZED,
        "logout revocation must persist across reconstruction"
    );
}

#[tokio::test]
async fn administrator_rotation_invalidates_the_old_cookie_without_breaking_new_login() {
    let directory = tempfile::tempdir().unwrap();
    let original = app(directory.path(), ADMIN);
    let old = cookie(&login(&original, ADMIN, &[]).await);
    drop(original);
    let rotated = app(directory.path(), ROTATED);
    assert_eq!(
        session_status(&rotated, &old).await,
        StatusCode::UNAUTHORIZED
    );
    let new = cookie(&login(&rotated, ROTATED, &[]).await);
    assert_eq!(session_status(&rotated, &new).await, StatusCode::OK);
    let old_bearer = format!("Bearer {ADMIN}");
    assert_eq!(
        request(
            &rotated,
            Method::GET,
            "/api/session",
            Body::empty(),
            &[("authorization", &old_bearer)]
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn tampered_unsigned_oversized_and_old_opaque_cookies_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    let issued = cookie(&login(&application, ADMIN, &[]).await);
    let mut tampered = issued.clone().into_bytes();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'a' { b'b' } else { b'a' };
    let tampered = String::from_utf8(tampered).unwrap();
    let oversized = format!("ar_session={}", "x".repeat(16384));
    let legacy = format!("ar_session={}", "0123456789abcdef".repeat(4));
    for (label, value) in [
        ("tampered", tampered),
        ("unsigned", "ar_session=unsigned-payload".into()),
        ("oversized", oversized),
        ("old opaque", legacy),
    ] {
        assert_eq!(
            session_status(&application, &value).await,
            StatusCode::UNAUTHORIZED,
            "invalid cookie category: {label}"
        );
    }
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::OK,
        "bad cookies must not revoke a different valid session"
    );
}

#[tokio::test]
async fn console_cookie_never_authenticates_probe_routes_and_cross_origin_logout_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    let issued = cookie(&login(&application, ADMIN, &[]).await);
    for route in [
        "/api/probe/lease",
        "/api/probe/results",
        "/api/probe/heartbeat",
    ] {
        let response = request(
            &application,
            Method::POST,
            route,
            Body::from("{}"),
            &[("cookie", &issued), ("content-type", "application/json")],
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "probe route must require its own identity"
        );
    }
    let rejected = request(
        &application,
        Method::POST,
        "/api/logout",
        Body::empty(),
        &[("cookie", &issued), ("origin", "https://other.invalid")],
    )
    .await;
    assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
    assert!(rejected.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::OK,
        "rejected cross-origin logout must not mutate the session"
    );
}

#[tokio::test]
async fn https_origin_or_forwarded_protocol_sets_secure_on_login_and_logout() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    for headers in [
        vec![("origin", "https://console.invalid")],
        vec![("x-forwarded-proto", "https")],
    ] {
        let response = login(&application, ADMIN, &headers).await;
        let issued = cookie(&response);
        assert!(
            has_secure(&response),
            "HTTPS console session must be Secure"
        );
        let mut logout_headers = headers.clone();
        logout_headers.push(("cookie", &issued));
        let response = request(
            &application,
            Method::POST,
            "/api/logout",
            Body::empty(),
            &logout_headers,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            has_secure(&response),
            "HTTPS logout must clear the same Secure cookie scope"
        );
    }
}

#[tokio::test]
async fn failed_durable_logout_preserves_browser_state_and_can_be_retried() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    let issued = cookie(&login(&application, ADMIN, &[]).await);
    let target = directory.path().join("console-session-revocations.json");
    assert!(
        !target.exists(),
        "issuing a session should not write revocations"
    );
    // A directory is an unambiguous atomic-persist failure, including as root.
    std::fs::create_dir(&target).unwrap();
    let response = request(
        &application,
        Method::POST,
        "/api/logout",
        Body::empty(),
        &[("cookie", &issued)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "failed durable logout must not tell the browser it succeeded"
    );
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::OK,
        "failed persistence must not silently revoke memory-only state"
    );
    std::fs::remove_dir(target).unwrap();
    let retried = request(
        &application,
        Method::POST,
        "/api/logout",
        Body::empty(),
        &[("cookie", &issued)],
    )
    .await;
    assert_eq!(retried.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::UNAUTHORIZED
    );
    drop(application);
    assert_eq!(
        session_status(&app(directory.path(), ADMIN), &issued).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoked_cookie_can_retry_logout_and_persistence_after_reconstruction() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    let issued = cookie(&login(&application, ADMIN, &[]).await);
    let logout_headers = [("cookie", issued.as_str())];
    let logout = || {
        request(
            &application,
            Method::POST,
            "/api/logout",
            Body::empty(),
            &logout_headers,
        )
    };
    let first = logout().await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::UNAUTHORIZED
    );

    // A revoke can already be visible in memory while its final directory
    // durability step needs retrying. An already-revoked cookie must still
    // reach revoke, rather than being rejected by the ordinary API guard.
    let target = directory.path().join("console-session-revocations.json");
    let saved = directory.path().join("isolated-saved-revocations.json");
    std::fs::rename(&target, &saved).unwrap();
    std::fs::create_dir(&target).unwrap();
    let failed = logout().await;
    assert_eq!(
        failed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "revoked-cookie logout must reach its persistence retry"
    );
    assert!(failed.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        session_status(&application, &issued).await,
        StatusCode::UNAUTHORIZED,
        "other API access must remain revoked during the retry"
    );
    std::fs::remove_dir(&target).unwrap();
    std::fs::rename(&saved, &target).unwrap();
    let retried = logout().await;
    assert_eq!(retried.status(), StatusCode::NO_CONTENT);
    assert!(retried.headers().get(header::SET_COOKIE).is_some());
    drop(application);

    let reopened = app(directory.path(), ADMIN);
    assert_eq!(
        session_status(&reopened, &issued).await,
        StatusCode::UNAUTHORIZED
    );
    let repeated = request(
        &reopened,
        Method::POST,
        "/api/logout",
        Body::empty(),
        &[("cookie", &issued)],
    )
    .await;
    assert_eq!(
        repeated.status(),
        StatusCode::NO_CONTENT,
        "repeating a completed logout after restart is idempotent"
    );
    assert_eq!(
        session_status(&reopened, &issued).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_clears_absent_or_invalid_cookies_but_still_rejects_cross_origin_requests() {
    let directory = tempfile::tempdir().unwrap();
    let application = app(directory.path(), ADMIN);
    let other = cookie(&login(&application, ADMIN, &[]).await);
    for supplied in [
        None,
        Some("ar_session=invalid-signed-cookie"),
        Some("unrelated=fixture-value"),
    ] {
        let mut headers = Vec::new();
        if let Some(value) = supplied {
            headers.push(("cookie", value));
        }
        let cleared = request(
            &application,
            Method::POST,
            "/api/logout",
            Body::empty(),
            &headers,
        )
        .await;
        assert_eq!(cleared.status(), StatusCode::NO_CONTENT);
        let header = cleared
            .headers()
            .get(header::SET_COOKIE)
            .expect("logout must clear stale browser state")
            .to_str()
            .unwrap();
        assert!(header.starts_with("ar_session=;"));
        assert!(header.split(';').any(|p| p.trim() == "Max-Age=0"));
        assert_eq!(
            session_status(&application, &other).await,
            StatusCode::OK,
            "cleaning stale browser state must not revoke an unrelated session"
        );
        assert_eq!(
            session_status(&application, supplied.unwrap_or("")).await,
            StatusCode::UNAUTHORIZED
        );
        headers.push(("origin", "https://other.invalid"));
        let rejected = request(
            &application,
            Method::POST,
            "/api/logout",
            Body::empty(),
            &headers,
        )
        .await;
        assert_eq!(
            rejected.status(),
            StatusCode::FORBIDDEN,
            "logout exemption must remain after the Origin check"
        );
        assert!(rejected.headers().get(header::SET_COOKIE).is_none());
    }
}
