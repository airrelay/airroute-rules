use crate::{
    build,
    console_session::ConsoleSessions,
    globalping, hash, now, publish, scheduler,
    store::{Node, Store},
    transport,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

#[derive(rust_embed::Embed)]
#[folder = "web/console/dist/"]
#[exclude = "*.map"]
struct Console;

#[derive(Clone)]
pub struct App {
    pub root: PathBuf,
    pub data: PathBuf,
    pub store: Store,
    pub offline: bool,
    pub admin_hash: String,
    pub gp: globalping::Config,
    pub building: Arc<AtomicBool>,
    pub build_requested: Arc<AtomicBool>,
    pub sessions: Arc<ConsoleSessions>,
    pub host: String,
    pub probe_hub: transport::Hub,
}
#[derive(Debug)]
pub struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":format!("{:#}",self.0)})),
        )
            .into_response()
    }
}
type ApiResult = std::result::Result<Json<Value>, ApiError>;

async fn authenticate(State(app): State<App>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if request.method() != axum::http::Method::GET
        && request.method() != axum::http::Method::HEAD
        && let Some(origin) = request
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
    {
        let valid = reqwest::Url::parse(origin).is_ok_and(|u| {
            u.host_str().is_some()
                && u.authority()
                    == request
                        .headers()
                        .get(header::HOST)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
        });
        if !valid {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error":"cross-origin mutation rejected"})),
            )
                .into_response();
        }
    }
    // Logout must reach its own signature-checked, idempotent revoke even when
    // the cookie is already revoked and its durability step needs retrying.
    if path == "/api/login"
        || path == "/api/logout"
        || path == "/healthz"
        || !path.starts_with("/api/")
    {
        return next.run(request).await;
    }
    if path.starts_with("/api/probe/") {
        let node = request
            .headers()
            .get("x-node-id")
            .and_then(|s| s.to_str().ok())
            .unwrap_or("");
        let token = bearer(request.headers());
        let (s, id, key) = (app.store.clone(), node.to_string(), token.to_string());
        if !matches!(
            tokio::task::spawn_blocking(move || s.authenticate_node(&id, &key)).await,
            Ok(Ok(_))
        ) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"invalid node credentials"})),
            )
                .into_response();
        }
    } else {
        let auth = bearer(request.headers());
        let mut valid = !auth.is_empty() && crate::store::constant_eq(&app.admin_hash, &hash(auth));
        if !valid && let Some(cookie) = session_cookie(request.headers()) {
            valid = app.sessions.valid(cookie);
        }
        if !valid {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error":"login required"})),
            )
                .into_response();
        }
    }
    let started = std::time::Instant::now();
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("header"));
    response.headers_mut().insert(
        "server-timing",
        format!("app;dur={:.2}", started.elapsed().as_secs_f64() * 1000.0)
            .parse()
            .expect("duration header"),
    );
    response
}
fn bearer(h: &HeaderMap) -> &str {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
}
pub fn router(app: App) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async { Json(json!({"status":"ok","version":env!("CARGO_PKG_VERSION")})) }),
        )
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route(
            "/api/session",
            get(|| async { Json(json!({"authenticated":true})) }),
        )
        .route("/api/overview", get(overview))
        .route("/api/catalogue", get(catalogue))
        .route("/api/conflicts", get(conflicts))
        .route("/api/results", get(results))
        .route("/api/targets", post(targets))
        .route("/api/observations", post(observation))
        .route("/api/nodes", get(nodes).post(add_node))
        .route("/api/nodes/{id}/disable", post(disable_node))
        .route("/api/nodes/{id}/enable", post(enable_node))
        .route("/api/nodes/{id}/settings", post(update_node_settings))
        .route("/api/nodes/{id}/reset-token", post(reset_node))
        .route("/api/accounts", get(accounts).post(save_account))
        .route("/api/accounts/{id}/delete", post(delete_account))
        .route("/api/tasks", get(tasks))
        .route("/api/task-items", get(task_items))
        .route("/api/task-summary", get(task_summary))
        .route("/api/discovery-status", get(discovery_status))
        .route("/api/task", get(task_detail))
        .route("/api/audit/issues", get(audit_issues))
        .route("/api/audit/tasks", get(audit_tasks))
        .route("/api/audit/records", get(audit_records))
        .route("/api/probe-certificate", get(probe_certificate))
        .route("/api/transport", get(transport_status))
        .route("/api/github", get(github_status).post(github_settings))
        .route("/api/github/connect", post(github_connect))
        .route("/api/github/disconnect", post(github_disconnect))
        .route("/api/github/refresh", post(github_refresh))
        .route("/api/github/device", post(github_device))
        .route("/api/github/device/poll", post(github_poll))
        .route("/api/github/retry/{id}", post(github_retry))
        .route("/api/jobs", get(jobs))
        .route("/api/scheduler/tick", post(tick))
        .route("/api/builds", get(builds).post(start_build))
        .route("/api/rules/{kind}/{name}", get(download))
        .route("/api/ip-library", get(download_ip_library))
        .route("/api/probe/lease", post(retired_worker_api))
        .route("/api/probe/results", post(retired_worker_api))
        .route("/api/probe/heartbeat", post(retired_worker_api))
        .fallback(static_file)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(app.clone(), authenticate))
        .with_state(app)
}
#[derive(Deserialize)]
struct Login {
    token: String,
}
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("ar_session="))
}
fn session_cookie_header(headers: &HeaderMap, token: &str, max_age: u32) -> String {
    // The public HTTPS console is terminated by the existing reverse proxy.
    // Origin also covers ordinary browser login; HTTP development stays usable.
    let secure = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https")
        || headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| reqwest::Url::parse(v).ok())
            .is_some_and(|u| u.scheme() == "https");
    format!(
        "ar_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}
async fn login(State(app): State<App>, headers: HeaderMap, Json(input): Json<Login>) -> Response {
    if !crate::store::constant_eq(&app.admin_hash, &hash(input.token)) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"invalid admin token"})),
        )
            .into_response();
    }
    let token = match app.sessions.issue() {
        Ok(token) => token,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"unable to create session"})),
            )
                .into_response();
        }
    };
    let mut response = Json(json!({"authenticated":true})).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("header"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie_header(&headers, &token, 8 * 3600)
            .parse()
            .expect("cookie"),
    );
    response
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> Response {
    if let Some(cookie) = session_cookie(&headers) {
        let sessions = app.sessions.clone();
        let token = cookie.to_string();
        // Successful logout is durable before clearing the browser cookie.
        // No disk work runs on Tokio's request executor or on ordinary GETs.
        if !matches!(
            tokio::task::spawn_blocking(move || sessions.revoke(&token)).await,
            Ok(Ok(()))
        ) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"unable to revoke session; please retry logout"})),
            )
                .into_response();
        }
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().expect("header"));
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie_header(&headers, "", 0)
            .parse()
            .expect("cookie"),
    );
    response
}
async fn overview(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || app.store.overview()).await??,
    ))
}
async fn catalogue(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || catalogue_data(&app)).await??,
    ))
}
fn catalogue_data(app: &App) -> Result<Value> {
    let recipes = build::recipes(&app.root)?;
    let counts = app
        .store
        .builds()?
        .as_array()
        .and_then(|a| a.iter().find(|b| b["status"] == "complete"))
        .map(|v| v["summary"]["counts"].clone())
        .unwrap_or(json!({}));
    let sources: Value = crate::read_json(&app.root.join("config/sources.json"))?;
    let official: Value = crate::read_json(&app.root.join("config/endpoints.references.json"))?;
    Ok(
        json!({"items":recipes.iter().map(|r|json!({"id":r.id,"name":r.name,"type":r.kind,"scope":r.scope,"sources":r.sources,"members":r.members,"projected_members":r.projected_members,"count":counts[&r.id]})).collect::<Vec<_>>(),"sources":sources,"official_endpoints":official}),
    )
}
#[derive(Deserialize)]
struct Page {
    #[serde(default)]
    offset: usize,
    #[serde(default = "page_limit")]
    limit: usize,
    #[serde(default)]
    filter: String,
}
fn page_limit() -> usize {
    50
}
async fn conflicts(State(app): State<App>, Query(p): Query<Page>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || app.store.list("cases", p.offset, p.limit, &p.filter))
            .await??,
    ))
}
#[derive(Deserialize)]
struct Key {
    key: String,
}
async fn results(State(app): State<App>, Query(k): Query<Key>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || app.store.results(&k.key)).await??,
    ))
}
#[derive(Deserialize)]
struct Targets {
    key: String,
    fingerprint: String,
    targets: Vec<String>,
}
async fn targets(State(app): State<App>, Json(t): Json<Targets>) -> ApiResult {
    Ok(Json(
        json!({"new_jobs":tokio::task::spawn_blocking(move||app.store.targets(&t.key,&t.fingerprint,&t.targets)).await??}),
    ))
}
#[derive(Deserialize)]
struct Observation {
    target: String,
    regions: Vec<String>,
    reason: String,
    #[serde(default)]
    refresh: bool,
}
async fn observation(State(app): State<App>, Json(o): Json<Observation>) -> ApiResult {
    let regions: Value = crate::read_json(&app.root.join("config/geography.json"))?;
    if !o.regions.iter().all(|r| {
        regions["regions"]
            .as_array()
            .is_some_and(|a| a.iter().any(|a| a["id"] == r.as_str()))
    }) {
        return Err(anyhow::anyhow!("unknown observer region").into());
    }
    Ok(Json(
        json!({"key":tokio::task::spawn_blocking(move||app.store.request_observation(&o.target,&o.regions,&o.reason,o.refresh)).await??}),
    ))
}
async fn nodes(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || app.store.nodes()).await??,
    ))
}
#[derive(Deserialize)]
struct AddNode {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    region: String,
    #[serde(default)]
    asn: u32,
    capabilities: Vec<String>,
}
async fn add_node(State(app): State<App>, Json(n): Json<AddNode>) -> ApiResult {
    // Keep explicitly supplied legacy IDs working; new console registrations always generate one.
    let id =
        n.id.unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4().simple()));
    if id.starts_with("globalping:") || id.len() > 80 {
        return Err(anyhow::anyhow!("invalid reserved node id").into());
    }
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    tokio::task::spawn_blocking(move || -> Result<Value> {
        app.store.register_named_node(
            &Node {
                id: id.clone(),
                region: n.region,
                asn: n.asn,
                capabilities: n.capabilities,
            },
            &token,
            n.name.as_deref(),
        )?;
        Ok(json!({"id":id,"token":token,"shown_once":true}))
    })
    .await?
    .map(Json)
    .map_err(Into::into)
}
async fn disable_node(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    tokio::task::spawn_blocking(move || -> Result<()> {
        app.store.set_node_enabled(&id, false)?;
        app.probe_hub.disconnect(&id);
        Ok(())
    })
    .await??;
    Ok(Json(json!({"disabled":true})))
}
async fn enable_node(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    tokio::task::spawn_blocking(move || app.store.set_node_enabled(&id, true)).await??;
    Ok(Json(json!({"disabled":false})))
}
#[derive(Deserialize)]
struct NodeSettings {
    name: String,
    concurrency_limit: Option<u32>,
}
async fn update_node_settings(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(settings): Json<NodeSettings>,
) -> ApiResult {
    tokio::task::spawn_blocking(move || {
        app.store
            .update_node_settings(&id, &settings.name, settings.concurrency_limit)
    })
    .await??;
    Ok(Json(json!({"saved":true})))
}
async fn accounts(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || globalping::status(&app.store, &app.gp)).await??,
    ))
}
async fn reset_node(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    let display_id = id.clone();
    let token = tokio::task::spawn_blocking(move || -> Result<String> {
        let token = app.store.reset_node_token(&id)?;
        app.probe_hub.disconnect(&id);
        Ok(token)
    })
    .await??;
    Ok(Json(
        json!({"id":display_id,"token":token,"shown_once":true}),
    ))
}
async fn save_account(
    State(app): State<App>,
    Json(input): Json<globalping::AccountInput>,
) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || globalping::save_account(&app.store, &app.gp, input))
            .await??,
    ))
}
async fn delete_account(State(app): State<App>, Path(id): Path<String>) -> ApiResult {
    tokio::task::spawn_blocking(move || globalping::delete_account(&app.store, &app.gp, &id))
        .await??;
    Ok(Json(json!({"deleted":true})))
}
async fn tasks(State(app): State<App>, Query(p): Query<Page>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            scheduler::tasks(&app.store, p.offset, p.limit, &p.filter)
        })
        .await??,
    ))
}
async fn task_detail(State(app): State<App>, Query(k): Query<Key>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || scheduler::task_detail(&app.store, &k.key)).await??,
    ))
}
async fn task_items(State(app): State<App>, Query(p): Query<Page>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            scheduler::task_items(&app.store, p.offset, p.limit, &p.filter)
        })
        .await??,
    ))
}
async fn task_summary(State(app): State<App>, Query(p): Query<Page>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || scheduler::task_summary(&app.store, &p.filter))
            .await??,
    ))
}
async fn discovery_status(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || crate::discovery::status(&app.store)).await??,
    ))
}
async fn audit_issues(
    State(app): State<App>,
    Query(p): Query<crate::audit::AuditQuery>,
) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || crate::audit_issues::issues(&app.store, &app.data, &p))
            .await??,
    ))
}
async fn audit_tasks(
    State(app): State<App>,
    Query(p): Query<crate::audit::AuditQuery>,
) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || crate::audit::tasks(&app.store, &p)).await??,
    ))
}
async fn audit_records(
    State(app): State<App>,
    Query(p): Query<crate::audit::AuditQuery>,
) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || crate::audit::records(&app.store, &p)).await??,
    ))
}
async fn github_status(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || publish::status(&app.store)).await??,
    ))
}
async fn github_settings(State(app): State<App>, Json(s): Json<publish::Settings>) -> ApiResult {
    tokio::task::spawn_blocking(move || publish::save_settings(&app.store, &s)).await??;
    Ok(Json(json!({"saved":true})))
}
#[derive(Deserialize)]
struct GithubToken {
    token: String,
}
async fn github_connect(State(app): State<App>, Json(t): Json<GithubToken>) -> ApiResult {
    Ok(Json(
        blocking_io(move || async move {
            publish::connect(&app.store, &t.token, &publish::Endpoints::default()).await
        })
        .await?,
    ))
}
async fn github_disconnect(State(app): State<App>) -> ApiResult {
    tokio::task::spawn_blocking(move || publish::disconnect(&app.store)).await??;
    Ok(Json(json!({"disconnected":true})))
}
async fn github_refresh(State(app): State<App>) -> ApiResult {
    Ok(Json(
        blocking_io(move || async move {
            publish::renew_authorization(&app.store, &publish::Endpoints::default(), true).await
        })
        .await?,
    ))
}
async fn github_device(State(app): State<App>) -> ApiResult {
    Ok(Json(
        blocking_io(move || async move {
            publish::start_device(&app.store, &publish::Endpoints::default()).await
        })
        .await?,
    ))
}
async fn github_poll(State(app): State<App>) -> ApiResult {
    Ok(Json(
        blocking_io(move || async move {
            publish::poll_device(&app.store, &publish::Endpoints::default()).await
        })
        .await?,
    ))
}
async fn github_retry(State(app): State<App>, Path(id): Path<i64>) -> ApiResult {
    Ok(Json(
        json!({"queued":tokio::task::spawn_blocking(move||publish::retry(&app.store,id)).await??}),
    ))
}
async fn jobs(State(app): State<App>, Query(page): Query<Page>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || app.store.jobs(page.offset, page.limit)).await??,
    ))
}
async fn tick(State(app): State<App>) -> ApiResult {
    Ok(Json(globalping_tick(app).await?))
}
// This worker mixes provider I/O and synchronous SQLite transactions. Keep its
// lock waits on a blocking thread, outside the HTTP/QUIC network executor.
async fn globalping_tick(app: App) -> Result<Value> {
    blocking_io(move || async move { globalping::tick(&app.store, &app.gp).await }).await
}
async fn blocking_io<F, Fut, T>(task: F) -> Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T>>,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(task())
    })
    .await?
}
#[derive(Deserialize)]
struct BuildView {
    #[serde(default)]
    compact: bool,
}
async fn builds(State(app): State<App>, Query(view): Query<BuildView>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || {
            if view.compact {
                app.store.build_summaries()
            } else {
                app.store.builds()
            }
        })
        .await??,
    ))
}
pub fn launch_build(app: App) -> bool {
    app.build_requested.store(true, Ordering::SeqCst);
    if app.building.swap(true, Ordering::SeqCst) {
        return false;
    }
    tokio::spawn(async move {
        loop {
            // A boolean deliberately coalesces any number of requests during this build.
            app.build_requested.store(false, Ordering::SeqCst);
            let copy = app.clone();
            let result = tokio::task::spawn_blocking(move || {
                let _ = copy
                    .store
                    .set_meta("last-build-attempt", &now().to_string());
                build::run_with_store(&copy.root, &copy.data, copy.offline, &copy.store)
            })
            .await;
            if let Err(error) = result
                .as_ref()
                .map_err(|e| e.to_string())
                .and_then(|r| r.as_ref().map_err(|e| e.to_string()))
            {
                tracing::error!(%error, "scheduled build did not activate; current release retained");
                app.building.store(false, Ordering::SeqCst);
                break;
            }
            if app.build_requested.load(Ordering::SeqCst) {
                continue;
            }
            app.building.store(false, Ordering::SeqCst);
            // Close the handoff race with a request arriving immediately before release.
            if app.build_requested.load(Ordering::SeqCst)
                && !app.building.swap(true, Ordering::SeqCst)
            {
                continue;
            }
            break;
        }
    });
    true
}
async fn start_build(State(app): State<App>) -> Json<Value> {
    let started = launch_build(app);
    Json(json!({"started":started,"coalesced":!started}))
}
async fn download(
    State(app): State<App>,
    Path((kind, name)): Path<(String, String)>,
) -> std::result::Result<Response, ApiError> {
    if !(matches!(
        kind.as_str(),
        "region" | "category" | "provider" | "special"
    ) && name.ends_with(".list")
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.'))
    {
        return Err(anyhow::anyhow!("invalid rule path").into());
    }
    let id = format!("{kind}/{}", name.trim_end_matches(".list"));
    let location = tokio::task::spawn_blocking(move || -> Result<_> {
        if !build::recipes(&app.root)?.iter().any(|r| r.id == id) {
            return Ok(None);
        }
        let release = app
            .store
            .meta("current-release")?
            .context("no completed build")?;
        Ok(Some(
            app.data
                .join("releases")
                .join(release)
                .join(kind)
                .join(name),
        ))
    })
    .await??;
    let Some(file) = location else {
        return Ok((StatusCode::NOT_FOUND, "unknown rule collection").into_response());
    };
    let bytes = tokio::fs::read(file).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        bytes,
    )
        .into_response())
}
async fn download_ip_library(State(app): State<App>) -> std::result::Result<Response, ApiError> {
    let release = tokio::task::spawn_blocking(move || -> Result<_> {
        let release = app
            .store
            .meta("current-release")?
            .context("no completed build")?;
        anyhow::ensure!(
            release.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid release identity"
        );
        Ok(app
            .data
            .join("releases")
            .join(release)
            .join("ip-library.csv"))
    })
    .await??;
    match tokio::fs::read(release).await {
        Ok(bytes) => Ok((
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=ip-library.csv",
                ),
                (header::CACHE_CONTROL, "no-cache"),
            ],
            bytes,
        )
            .into_response()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((
            StatusCode::NOT_FOUND,
            "IP library is not available for this release",
        )
            .into_response()),
        Err(error) => Err(error.into()),
    }
}

async fn retired_worker_api() -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(json!({"error":"HTTP worker polling retired; use QUIC airroute-probe/1"})),
    )
}
async fn probe_certificate(State(app): State<App>) -> Result<Response, ApiError> {
    let bytes = tokio::fs::read(transport::certificate(&app.data)?).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/pkix-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=controller-cert.der",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn transport_status(State(app): State<App>) -> ApiResult {
    Ok(Json(
        tokio::task::spawn_blocking(move || -> Result<Value> {
            Ok(app
                .store
                .meta("probe-transport")?
                .map(|s| serde_json::from_str(&s))
                .transpose()?
                .unwrap_or(json!({"protocol":"QUIC","encoding":"CBOR","version":1})))
        })
        .await??,
    ))
}
async fn static_file(request: Request) -> Response {
    let path = request.uri().path().trim_start_matches('/');
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD
    ) {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }
    let file = if path.is_empty() { "index.html" } else { path };
    let asset = Console::get(file).or_else(|| {
        if !path.starts_with("assets/")
            && !path.contains('.')
            && request
                .headers()
                .get(header::ACCEPT)
                .and_then(|s| s.to_str().ok())
                .is_some_and(|s| s.contains("text/html"))
        {
            Console::get("index.html")
        } else {
            None
        }
    });
    let Some(asset) = asset else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let etag = format!("\"{}\"", hex::encode(asset.metadata.sha256_hash()));
    let mut response = if request
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        == Some(etag.as_str())
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Response::new(if request.method() == axum::http::Method::HEAD {
            Body::empty()
        } else {
            Body::from(asset.data.into_owned())
        })
    };
    let h = response.headers_mut();
    h.insert(header::ETAG, etag.parse().expect("ETag"));
    h.insert(
        header::CONTENT_TYPE,
        mime_guess::from_path(file)
            .first_or_octet_stream()
            .as_ref()
            .parse()
            .expect("mime"),
    );
    h.insert(
        header::CACHE_CONTROL,
        if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        }
        .parse()
        .expect("cache"),
    );
    h.insert(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'".parse().expect("CSP"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("header"),
    );
    response
}
pub async fn serve(
    root: PathBuf,
    data: PathBuf,
    bind: std::net::SocketAddr,
    offline: bool,
    interval_hours: u64,
    quic_bind: Option<std::net::SocketAddr>,
) -> Result<()> {
    let store = Store::open(&data)?;
    // Audit reads must also work on an empty/offline controller, before the
    // account worker or account page has performed the existing initialization.
    globalping::initialize_intents(&store)?;
    let discovery_config = crate::discovery::load(&root)?;
    scheduler::configure(&root, &store)?;
    crate::receipt::configure_country_regions(&store, &root)?;
    crate::jobs_v3::requalify_legacy(&store)?;
    if let Err(error) = build::recover_export(&store, &root, &data) {
        tracing::warn!(%error, "current export reconciliation deferred at startup");
    }
    publish::initialize(&root, &store)?;
    let quic_bind = quic_bind
        .unwrap_or_else(|| std::net::SocketAddr::new(bind.ip(), bind.port().saturating_add(1)));
    let quic = transport::Server::start(&data, store.clone(), quic_bind)?;
    store.set_meta("probe-transport",&json!({"protocol":"QUIC","encoding":"CBOR","version":transport::VERSION,"bind":quic.endpoint.local_addr()?.to_string(),"server_name":transport::SERVER_NAME,"heartbeat_seconds":10,"offline_after_seconds":35}).to_string())?;
    build::recover_abandoned(&store, &data)?;
    store.import_legacy(&root)?;
    let token = match std::env::var("AIRROUTE_ADMIN_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            let p = data.join("admin-token");
            if p.exists() {
                std::fs::read_to_string(p)?
            } else {
                let t = format!(
                    "{}{}",
                    uuid::Uuid::new_v4().simple(),
                    uuid::Uuid::new_v4().simple()
                );
                crate::atomic_write(&p, t.as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
                }
                t
            }
        }
    };
    ensure!(
        token.trim().len() >= 24,
        "admin token must contain at least 24 characters"
    );
    let admin_hash = hash(token.trim());
    let sessions = Arc::new(ConsoleSessions::open(&data, &admin_hash)?);
    let app = App {
        root: root.clone(),
        data: data.clone(),
        store,
        offline,
        admin_hash,
        gp: globalping::load(&root.join("config/globalping.toml"))?,
        building: Arc::new(AtomicBool::new(false)),
        build_requested: Arc::new(AtomicBool::new(false)),
        sessions,
        host: bind.to_string(),
        probe_hub: quic.hub.clone(),
    };
    let scheduler = app.clone();
    let discoverer = app.clone();
    tokio::spawn(async move {
        if discoverer.offline {
            let _ = discoverer.store.set_meta(
                "discovery-status",
                &json!({"enabled":false,"offline":true}).to_string(),
            );
            return;
        }
        loop {
            let (worker, config) = (discoverer.clone(), discovery_config.clone());
            let result = blocking_io(move || async move {
                tokio::time::timeout(
                    Duration::from_secs(180),
                    crate::discovery::tick(&worker.store, &config),
                )
                .await
                .context("passive discovery exceeded tick budget")?
            })
            .await;
            let error = result.err().map(|e| e.to_string());
            if let Some(error) = error {
                tracing::warn!(%error,"passive target discovery failed; measurements continue independently");
                let s = discoverer.store.clone();
                let enabled = discovery_config.enabled;
                let _ = tokio::task::spawn_blocking(move || {
                    s.set_meta(
                        "discovery-status",
                        &json!({"enabled":enabled,"updated":now(),"errors":[error]}).to_string(),
                    )
                })
                .await;
            }
            tokio::time::sleep(Duration::from_secs(discovery_config.interval_seconds)).await;
        }
    });
    let publisher = app.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let worker = publisher.clone();
            if let Err(e) = blocking_io(move || async move {
                publish::tick(&worker.root, &worker.data, &worker.store).await
            })
            .await
            {
                tracing::warn!(error=%e,"GitHub publication tick failed");
            }
        }
    });
    let planning = app.store.clone();
    tokio::spawn(async move {
        let mut drain = true;
        loop {
            if !drain {
                // Notifications are only wake hints. Due work is checked on a bounded timer.
                tokio::select! {
                    _ = planning.wake.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                }
            }
            let work_store = planning.clone();
            drain = match tokio::task::spawn_blocking(move || -> Result<bool> {
                let syncing = crate::build_delta::sync_current(&work_store, 128)?;
                crate::work::refresh(&work_store)?;
                Ok(syncing
                    || work_store.connect()?.query_row(
                        "SELECT EXISTS(SELECT 1 FROM replan_cases)",
                        [],
                        |r| r.get(0),
                    )?)
            })
            .await
            {
                Ok(Ok(pending)) => pending,
                Ok(Err(e)) => {
                    tracing::warn!(error=%e,"observation planning failed");
                    false
                }
                Err(e) => {
                    tracing::warn!(error=%e,"observation planning task failed");
                    false
                }
            };
            // A shared Notify permit can be consumed by another executor. Drain durable
            // markers directly so a migration backlog never waits 30s between batches.
            if drain {
                // Release the writer between small batches so receipts and
                // dispatch can acquire it while a full catalogue is syncing.
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    });
    let measurements = app.clone();
    let gp_stop = Arc::new(tokio::sync::Notify::new());
    let gp_shutdown = gp_stop.clone();
    // One long-lived runtime keeps account requests and result reaping independent.
    // Synchronous SQLite operations run on this bounded worker, away from QUIC/HTTP.
    let gp_worker = tokio::task::spawn_blocking(move || -> Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async move {
                tokio::select! {
                    result = globalping::run(&measurements.store, &measurements.gp) => result,
                    _ = gp_shutdown.notified() => Ok(()),
                }
            })
    });
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let check = scheduler.clone();
            let due_to_build = tokio::task::spawn_blocking(move || {
                let last = check.store.connect().ok().and_then(|c| {
                    c.query_row::<Option<i64>, _, _>(
                        "SELECT max(finished) FROM builds WHERE status='complete'",
                        [],
                        |r| r.get(0),
                    )
                    .ok()
                    .flatten()
                });
                if !check.building.load(Ordering::SeqCst) {
                    let _ = build::recover_abandoned(&check.store, &check.data);
                    if let Err(error) =
                        build::recover_export(&check.store, &check.root, &check.data)
                    {
                        tracing::warn!(%error, "current export reconciliation deferred");
                    }
                }
                // New observations are read on the next scheduled build. Only an
                // explicit build request may coalesce another run here.
                let pending = check.build_requested.load(Ordering::SeqCst);
                let due = interval_hours > 0
                    && last.is_none_or(|t| now() - t > interval_hours.clamp(1, 168) as i64 * 3600);
                let cooled = check
                    .store
                    .meta("last-build-attempt")
                    .ok()
                    .flatten()
                    .and_then(|s| s.parse::<i64>().ok())
                    .is_none_or(|t| now() - t >= 300);
                let running = check
                    .store
                    .connect()
                    .and_then(|c| {
                        c.query_row::<bool, _, _>(
                            "SELECT EXISTS(SELECT 1 FROM builds WHERE status='running')",
                            [],
                            |r| r.get(0),
                        )
                        .map_err(Into::into)
                    })
                    .unwrap_or(true);
                !running && cooled && (due || pending)
            })
            .await
            .unwrap_or(false);
            if due_to_build {
                launch_build(scheduler.clone());
            }
        }
    });
    tracing::info!(%bind,data=%data.display(),"controller ready; use data/admin-token or AIRROUTE_ADMIN_TOKEN to log in");
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let serving = axum::serve(listener, router(app))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    gp_stop.notify_one();
    if let Err(error) = gp_worker.await? {
        tracing::warn!(%error, "Globalping runtime stopped");
    }
    quic.shutdown().await;
    serving?;
    Ok(())
}
