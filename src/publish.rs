//! GitHub authorization and a durable, independently retryable publication queue.
use crate::{now, secrets, store::Store};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs::File, path::Path, time::Duration};
mod git;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub repository: String,
    pub branch: String,
    pub enabled: bool,
    pub client_id: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            repository: "example/rules".into(),
            branch: "main".into(),
            enabled: false,
            client_id: String::new(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Credential {
    reference: String,
    login: String,
    #[serde(default)]
    renewal: Option<Renewal>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Renewal {
    reference: String,
    client_id: String,
    expires_at: i64,
    refresh_expires_at: i64,
}
struct RenewalInput {
    token: String,
    client_id: String,
    expires_at: i64,
    refresh_expires_at: i64,
}
fn renewal_response(v: &Value, client_id: &str, issued: i64) -> Result<Option<RenewalInput>> {
    if v["expires_in"].is_null() && v["refresh_token"].is_null() {
        return Ok(None);
    }
    let lifetime = v["expires_in"]
        .as_i64()
        .context("missing OAuth token lifetime")?;
    let refresh_lifetime = v["refresh_token_expires_in"]
        .as_i64()
        .context("missing OAuth refresh lifetime")?;
    let token = v["refresh_token"]
        .as_str()
        .context("expiring OAuth token requires refresh token")?;
    ensure!(
        (1..=31_536_000).contains(&lifetime) && (1..=31_536_000).contains(&refresh_lifetime),
        "invalid OAuth token lifetime"
    );
    ensure!(!client_id.is_empty(), "missing OAuth client ID");
    ensure!(
        !token.trim().is_empty() && token.len() <= 8192 && !token.contains(['\n', '\r', '\0']),
        "invalid OAuth refresh token"
    );
    Ok(Some(RenewalInput {
        token: token.into(),
        client_id: client_id.into(),
        expires_at: issued + lifetime,
        refresh_expires_at: issued + refresh_lifetime,
    }))
}
fn remove_credential(data: &Path, c: &Credential) -> Result<()> {
    secrets::remove(data, &c.reference)?;
    if let Some(r) = &c.renewal {
        secrets::remove(data, &r.reference)?;
    }
    Ok(())
}
// Caller holds publish.lock. One metadata write installs both durable secret references.
fn save_credential(
    store: &Store,
    token: &str,
    login: &str,
    renewal: Option<&RenewalInput>,
) -> Result<()> {
    let data = store.path.parent().context("data directory")?;
    let old = credential(store)?;
    let reference = secrets::save(data, token)?;
    let refresh = renewal.map(|r| secrets::save(data, &r.token)).transpose();
    let refresh = match refresh {
        Ok(r) => r,
        Err(e) => {
            let _ = secrets::remove(data, &reference);
            return Err(e);
        }
    };
    let new = Credential {
        reference,
        login: login.into(),
        renewal: renewal.zip(refresh).map(|(r, reference)| Renewal {
            reference,
            client_id: r.client_id.clone(),
            expires_at: r.expires_at,
            refresh_expires_at: r.refresh_expires_at,
        }),
    };
    if let Err(e) = store.set_meta("github-credential", &serde_json::to_string(&new)?) {
        let _ = remove_credential(data, &new);
        return Err(e);
    }
    if let Some(old) = old
        && remove_credential(data, &old).is_err()
    {
        tracing::warn!("obsolete GitHub credential cleanup failed");
    }
    store.set_meta("github-refresh-after", "0")?;
    Ok(())
}
#[derive(Clone)]
pub struct Endpoints {
    pub api: String,
    pub oauth: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://api.github.com".into(),
            oauth: "https://github.com".into(),
        }
    }
}
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent("AirRoute-Rules/0.2")
        .timeout(Duration::from_secs(25))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
pub fn initialize(root: &Path, store: &Store) -> Result<()> {
    store.connect()?.execute_batch("CREATE TABLE IF NOT EXISTS publications(id INTEGER PRIMARY KEY,release TEXT NOT NULL,repository TEXT NOT NULL,branch TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,not_before INTEGER NOT NULL,created INTEGER NOT NULL,finished INTEGER,commit_sha TEXT,error TEXT,UNIQUE(release,repository,branch));")?;
    migrate_publications(store)?;
    if store.meta("github-settings")?.is_none() {
        let path = root.join("config/github.toml");
        let s: Settings = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)?
        } else {
            Settings::default()
        };
        save_settings(store, &s)?;
    }
    Ok(())
}
fn migrate_publications(store: &Store) -> Result<()> {
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let columns = {
        let mut q = tx.prepare("PRAGMA table_info(publications)")?;
        q.query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (name, definition) in [
        ("build_id", "TEXT"),
        ("base_sha", "TEXT"),
        ("push_state", "TEXT NOT NULL DEFAULT 'new'"),
        ("verified_remote_sha", "TEXT"),
    ] {
        if !columns.iter().any(|c| c == name) {
            tx.execute(
                &format!("ALTER TABLE publications ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    let migrated: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='publication-recovery-v2')",
        [],
        |r| r.get(0),
    )?;
    if !migrated {
        // The old worker did not save its commit before push. Preserve uncertainty;
        // absence of a SHA is not evidence that a previous POST/git push never ran.
        tx.execute("UPDATE publications SET status='unknown',push_state='unknown',error='legacy publication may have been sent without a durable commit; reconcile manually' WHERE commit_sha IS NULL AND (status='running' OR (status='retry' AND attempts>0))", [])?;
        tx.execute("INSERT INTO meta VALUES('publication-recovery-v2','1')", [])?;
    }
    tx.execute(
        "CREATE INDEX IF NOT EXISTS publication_pending ON publications(status,not_before,id)",
        [],
    )?;
    tx.commit()?;
    Ok(())
}
pub fn settings(store: &Store) -> Result<Settings> {
    Ok(store
        .meta("github-settings")?
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default())
}
fn validate(s: &Settings) -> Result<()> {
    let parts: Vec<_> = s.repository.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|s| !s.is_empty()
                && s.len() <= 100
                && *s != "."
                && *s != ".."
                && s.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))),
        "repository must be owner/repo"
    );
    ensure!(
        !s.branch.is_empty()
            && !s.branch.chars().any(char::is_control)
            && s.branch.len() <= 150
            && !s.branch.starts_with(['-', '/', '.'])
            && !s.branch.ends_with(['.', '/'])
            && !s.branch.ends_with(".lock")
            && !s
                .branch
                .contains([' ', '~', '^', ':', '?', '*', '[', '\\', '\0', '\n', '\r'])
            && !s.branch.contains("..")
            && !s.branch.contains("//")
            && !s.branch.contains("@{")
            && !s
                .branch
                .split('/')
                .any(|p| p.starts_with('.') || p.ends_with(".lock")),
        "invalid branch"
    );
    ensure!(
        s.client_id.len() <= 120
            && s.client_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_'),
        "invalid OAuth client ID"
    );
    Ok(())
}
pub fn save_settings(store: &Store, s: &Settings) -> Result<()> {
    validate(s)?;
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("publication in progress; change settings after it finishes")?;
    store.set_meta("github-settings", &serde_json::to_string(s)?)?;
    Ok(())
}
fn credential(store: &Store) -> Result<Option<Credential>> {
    Ok(store
        .meta("github-credential")?
        .filter(|s| !s.is_empty())
        .map(|s| serde_json::from_str(&s))
        .transpose()?)
}
pub fn status(store: &Store) -> Result<Value> {
    let conn = store.connect()?;
    let mut stmt=conn.prepare("SELECT id,release,repository,branch,status,attempts,not_before,created,finished,commit_sha,error,build_id,push_state,verified_remote_sha FROM publications ORDER BY id DESC LIMIT 30")?;
    let rows=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"release":r.get::<_,String>(1)?,"repository":r.get::<_,String>(2)?,"branch":r.get::<_,String>(3)?,"status":r.get::<_,String>(4)?,"attempts":r.get::<_,i64>(5)?,"not_before":r.get::<_,i64>(6)?,"created":r.get::<_,i64>(7)?,"finished":r.get::<_,Option<i64>>(8)?,"commit":r.get::<_,Option<String>>(9)?,"error":r.get::<_,Option<String>>(10)?,"build_id":r.get::<_,Option<String>>(11)?,"push_state":r.get::<_,String>(12)?,"verified_remote_sha":r.get::<_,Option<String>>(13)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    let c = credential(store)?;
    let device=store.meta("github-device")?.filter(|s|!s.is_empty()).and_then(|s|serde_json::from_str::<Value>(&s).ok()).filter(|d|d["expires"].as_i64().unwrap_or(0)>now()).map(|d|json!({"user_code":d["user_code"],"verification_uri":d["verification_uri"],"expires":d["expires"]}));
    Ok(
        json!({"settings":settings(store)?,"device_available":!settings(store)?.client_id.is_empty()||std::env::var("AIRROUTE_GITHUB_CLIENT_ID").is_ok_and(|s|!s.is_empty()),"connected":c.is_some(),"login":c.as_ref().map(|c|&c.login),"expires_at":c.as_ref().and_then(|c|c.renewal.as_ref().map(|r|r.expires_at)),"auto_refresh_available":c.as_ref().is_some_and(|c|c.renewal.is_some()),"health":store.meta("github-health")?.unwrap_or_else(||"not-connected".into()),"local_build_id":store.meta("current-build-id")?,"local_release":store.meta("current-release")?,"publications":rows,"device":device}),
    )
}
pub async fn connect(store: &Store, token: &str, ep: &Endpoints) -> Result<Value> {
    let attempt = begin_authorization(store)?;
    connect_inner(store, token, ep, None, Some(&attempt), None).await
}
fn begin_authorization(store: &Store) -> Result<String> {
    let attempt = uuid::Uuid::new_v4().to_string();
    {
        let _lock =
            crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
                .context("authorization or publication in progress; try again shortly")?;
        store.set_meta("github-auth-attempt", &attempt)?;
        store.set_meta("github-device", "")?;
    }
    Ok(attempt)
}
async fn connect_inner(
    store: &Store,
    token: &str,
    ep: &Endpoints,
    expected_device: Option<&str>,
    expected_attempt: Option<&str>,
    renewal: Option<RenewalInput>,
) -> Result<Value> {
    ensure!(
        !token.trim().is_empty() && !token.contains(['\n', '\r', '\0']) && token.len() <= 8192,
        "invalid GitHub token"
    );
    let r = client()?
        .get(format!("{}/user", ep.api))
        .bearer_auth(token.trim())
        .send()
        .await?;
    ensure!(
        r.status().is_success(),
        "GitHub authentication failed (HTTP {})",
        r.status().as_u16()
    );
    let v: Value = r.json().await?;
    let login = v["login"]
        .as_str()
        .context("GitHub returned no account")?
        .to_string();
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("publication in progress; try connecting again when it finishes")?;
    if let Some(expected) = expected_device {
        let current = store
            .meta("github-device")?
            .filter(|s| !s.is_empty())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        ensure!(
            current.as_ref().and_then(|v| v["device_code"].as_str()) == Some(expected),
            "GitHub authorization cancelled or replaced"
        );
    }
    if let Some(expected) = expected_attempt {
        ensure!(
            store.meta("github-auth-attempt")?.as_deref() == Some(expected),
            "GitHub authorization cancelled or replaced"
        );
    }
    save_credential(store, token, &login, renewal.as_ref())?;
    store.set_meta("github-device", "")?;
    store.set_meta("github-auth-attempt", "")?;
    let health = repository_health(store, ep, token)
        .await
        .unwrap_or_else(|_| "github-unavailable".into());
    store.set_meta("github-health", &health)?;
    Ok(json!({"connected":true,"login":login,"health":health}))
}
async fn repository_health(store: &Store, ep: &Endpoints, token: &str) -> Result<String> {
    let s = settings(store)?;
    let r = client()?
        .get(format!("{}/repos/{}", ep.api, s.repository))
        .bearer_auth(token)
        .send()
        .await?;
    Ok(match r.status().as_u16() {
        200 => "ready",
        404 => "waiting-for-repository",
        401 | 403 => "permission-required",
        _ => "github-unavailable",
    }
    .into())
}
pub fn disconnect(store: &Store) -> Result<()> {
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("publication in progress; disconnect after it finishes")?;
    let old = credential(store)?;
    store.set_meta("github-credential", "")?;
    store.set_meta("github-auth-attempt", "")?;
    store.set_meta("github-device", "")?;
    store.set_meta("github-health", "not-connected")?;
    if let Some(c) = old {
        remove_credential(store.path.parent().context("data directory")?, &c)?;
    }
    Ok(())
}
pub async fn start_device(store: &Store, ep: &Endpoints) -> Result<Value> {
    let s = settings(store)?;
    let client_id = std::env::var("AIRROUTE_GITHUB_CLIENT_ID").unwrap_or(s.client_id);
    ensure!(
        !client_id.is_empty(),
        "configure an OAuth App client ID with Device Flow enabled, or use a repository token"
    );
    let attempt = begin_authorization(store)?;
    let r = client()?
        .post(format!("{}/login/device/code", ep.oauth))
        .header("Accept", "application/json")
        .form(&[("client_id", client_id.as_str()), ("scope", "public_repo")])
        .send()
        .await?;
    ensure!(
        r.status().is_success(),
        "GitHub device authorization unavailable"
    );
    let v: Value = r.json().await?;
    let code = v["device_code"]
        .as_str()
        .context("GitHub refused device authorization; check the OAuth App Device Flow setting")?;
    let expires = now() + v["expires_in"].as_i64().unwrap_or(900).clamp(30, 1800);
    let interval = v["interval"].as_i64().unwrap_or(5).clamp(5, 60);
    let uri = v["verification_uri"]
        .as_str()
        .context("missing verification URL")?;
    ensure!(
        uri == "https://github.com/login/device" || ep.oauth.starts_with("http://127.0.0.1:"),
        "unexpected GitHub verification URL"
    );
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("authorization or publication in progress; try again shortly")?;
    ensure!(
        store.meta("github-auth-attempt")?.as_deref() == Some(attempt.as_str()),
        "GitHub authorization cancelled or replaced"
    );
    store.set_meta("github-device",&json!({"attempt":attempt,"client_id":client_id,"device_code":code,"user_code":v["user_code"],"verification_uri":uri,"expires":expires,"interval":interval,"next_poll":now()+interval}).to_string())?;
    Ok(json!({"user_code":v["user_code"],"verification_uri":uri,"expires":expires}))
}
fn update_device_if_current(store: &Store, expected: &Value, replacement: &str) -> Result<bool> {
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("authorization or publication in progress; try again shortly")?;
    let current = store
        .meta("github-device")?
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str::<Value>(&s).ok());
    if current.as_ref().is_some_and(|d| {
        d["device_code"] == expected["device_code"] && d["attempt"] == expected["attempt"]
    }) {
        store.set_meta("github-device", replacement)?;
        return Ok(true);
    }
    Ok(false)
}
pub async fn poll_device(store: &Store, ep: &Endpoints) -> Result<Value> {
    let _lock =
        match crate::FileLock::try_new(File::create(store.path.with_extension("device.lock"))?) {
            Ok(lock) => lock,
            Err(std::fs::TryLockError::WouldBlock) => return Ok(json!({"pending":true})),
            Err(error) => return Err(error.into()),
        };
    let mut d = {
        let mut conn = store.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key='github-device'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(raw) = raw.filter(|v| !v.is_empty()) else {
            return Ok(json!({"pending":false}));
        };
        let mut d: Value = serde_json::from_str(&raw)?;
        if d["expires"].as_i64().unwrap_or(0) <= now() {
            tx.execute("DELETE FROM meta WHERE key='github-device'", [])?;
            tx.commit()?;
            return Ok(json!({"expired":true}));
        }
        if d["next_poll"].as_i64().unwrap_or(0) > now() {
            return Ok(json!({"pending":true}));
        }
        d["next_poll"] = json!(now() + d["interval"].as_i64().unwrap_or(5));
        tx.execute(
            "UPDATE meta SET value=? WHERE key='github-device'",
            [d.to_string()],
        )?;
        tx.commit()?;
        drop(conn);
        d
    };
    let issued = now();
    let r = client()?
        .post(format!("{}/login/oauth/access_token", ep.oauth))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", d["client_id"].as_str().unwrap_or("")),
            ("device_code", d["device_code"].as_str().unwrap_or("")),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await?;
    ensure!(
        r.status().is_success(),
        "GitHub authorization polling unavailable"
    );
    let v: Value = r.json().await?;
    if let Some(token) = v["access_token"].as_str() {
        return connect_inner(
            store,
            token,
            ep,
            d["device_code"].as_str(),
            d["attempt"].as_str(),
            renewal_response(&v, d["client_id"].as_str().unwrap_or(""), issued)?,
        )
        .await;
    }
    match v["error"].as_str().unwrap_or("") {
        "authorization_pending" => {}
        "slow_down" => {
            let interval = d["interval"].as_i64().unwrap_or(5) + 5;
            d["interval"] = json!(interval);
            d["next_poll"] = json!(now() + interval);
            update_device_if_current(store, &d, &d.to_string())?;
        }
        _ => {
            if !update_device_if_current(store, &d, "")? {
                return Ok(json!({"cancelled":true}));
            }
            anyhow::bail!("GitHub authorization expired or was declined; start again");
        }
    }
    Ok(json!({"pending":true}))
}
pub fn enqueue_current(store: &Store) -> Result<usize> {
    let s = settings(store)?;
    if !s.enabled || credential(store)?.is_none() {
        return Ok(0);
    }
    if store.meta("current-release")?.is_none() {
        return Ok(0);
    }
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let build: Option<String> = tx
        .query_row(
            "SELECT value FROM meta WHERE key='current-build-id'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    // Re-read the pointer in the transaction: a completed build can race with this worker.
    let release: String = tx.query_row(
        "SELECT value FROM meta WHERE key='current-release'",
        [],
        |r| r.get(0),
    )?;
    tx.execute("UPDATE publications SET status='superseded' WHERE status IN ('queued','retry','waiting-repository') AND push_state IN ('new','prepared') AND (release<>? OR repository<>? OR branch<>?)",params![release,s.repository,s.branch])?;
    let queued = tx.execute("INSERT INTO publications(release,repository,branch,status,not_before,created,build_id) VALUES(?,?,?,'queued',?,?,?) ON CONFLICT(release,repository,branch) DO UPDATE SET status='queued',not_before=excluded.not_before,error=NULL,build_id=excluded.build_id WHERE publications.status='superseded' AND publications.push_state IN ('new','prepared')",params![release,s.repository,s.branch,now(),now(),build])?;
    tx.execute("UPDATE publications SET build_id=? WHERE release=? AND repository=? AND branch=? AND status IN ('queued','retry','waiting-repository') AND push_state IN ('new','prepared') AND build_id IS NOT ?",params![build,release,s.repository,s.branch,build])?;
    tx.commit()?;
    Ok(queued)
}
pub fn retry(store: &Store, id: i64) -> Result<usize> {
    // Unknown sends can be polled/reconciled, but never converted to a fresh send.
    Ok(store.connect()?.execute("UPDATE publications SET status=CASE WHEN push_state IN ('sending','unknown') THEN 'unknown' ELSE 'queued' END,not_before=?,error=NULL WHERE id=? AND status IN ('retry','waiting-repository','failed','unknown')",params![now(),id])?)
}
async fn refresh_locked(store: &Store, ep: &Endpoints, force: bool) -> Result<bool> {
    let Some(c) = credential(store)? else {
        return Ok(false);
    };
    let Some(renewal) = &c.renewal else {
        return Ok(false);
    };
    if !force && renewal.expires_at > now() + 120 {
        return Ok(false);
    }
    if renewal.refresh_expires_at <= now() {
        store.set_meta("github-health", "reauthorization-required")?;
        anyhow::bail!("GitHub refresh authorization expired; authorize again");
    }
    let data = store.path.parent().context("data directory")?;
    let refresh = secrets::read(data, &renewal.reference)?;
    let issued = now();
    let response = client()?
        .post(format!("{}/login/oauth/access_token", ep.oauth))
        .header("Accept", "application/json")
        .form(&[
            ("client_id", renewal.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
        ])
        .send()
        .await
        .context("GitHub token refresh request failed")?;
    ensure!(
        response.status().is_success(),
        "GitHub token refresh HTTP {}",
        response.status().as_u16()
    );
    let v: Value = response
        .json()
        .await
        .context("invalid GitHub refresh response")?;
    if matches!(
        v["error"].as_str(),
        Some("bad_refresh_token" | "incorrect_client_credentials" | "access_denied")
    ) {
        store.set_meta("github-health", "reauthorization-required")?;
        anyhow::bail!("GitHub refresh authorization rejected; authorize again");
    }
    let token = v["access_token"]
        .as_str()
        .context("GitHub did not return a refreshed access token")?;
    let next = renewal_response(&v, &renewal.client_id, issued)?
        .context("GitHub did not rotate the refresh token")?;
    if save_credential(store, token, &c.login, Some(&next)).is_err() {
        store.set_meta("github-health", "reauthorization-required")?;
        anyhow::bail!("cannot persist rotated GitHub credentials; authorize again");
    }
    store.set_meta("github-health", "ready")?;
    Ok(true)
}
pub async fn renew_authorization(store: &Store, ep: &Endpoints, force: bool) -> Result<Value> {
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)
        .context("publication or authorization in progress; try again shortly")?;
    let refreshed = refresh_locked(store, ep, force).await?;
    Ok(json!({"refreshed":refreshed}))
}
pub async fn tick(root: &Path, data: &Path, store: &Store) -> Result<Value> {
    let _lock =
        match crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?) {
            Ok(lock) => lock,
            Err(std::fs::TryLockError::WouldBlock) => return Ok(json!({"busy":true})),
            Err(error) => return Err(error.into()),
        };
    enqueue_current(store)?;
    let s = settings(store)?;
    if !s.enabled {
        return Ok(json!({"enabled":false}));
    }
    if credential(store)?.is_none() {
        return Ok(json!({"connected":false}));
    }
    let retry_at = store
        .meta("github-refresh-after")?
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    if retry_at > now() {
        return Ok(json!({"authorization_retry_at":retry_at}));
    }
    if let Err(error) = refresh_locked(store, &Endpoints::default(), false).await {
        let reauthorize =
            store.meta("github-health")?.as_deref() == Some("reauthorization-required");
        let retry_at = now() + if reauthorize { 86400 } else { 300 };
        store.set_meta("github-refresh-after", &retry_at.to_string())?;
        if !reauthorize {
            store.set_meta("github-health", "refresh-retry")?;
        }
        tracing::warn!(%error,"GitHub authorization refresh failed");
        return Ok(
            json!({"authorization_retry_at":retry_at,"reauthorization_required":reauthorize}),
        );
    }
    let c = credential(store)?.context("GitHub authorization unavailable")?;
    let row: Option<(i64, String)> = store.connect()?.query_row(
        "SELECT id,release FROM publications WHERE not_before<=? AND (status IN ('unknown','running') OR (repository=? AND branch=? AND status IN ('queued','retry','waiting-repository'))) ORDER BY CASE WHEN status IN ('unknown','running') THEN 0 ELSE 1 END,id DESC LIMIT 1",
        params![now(),s.repository,s.branch], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
    let Some((id, release)) = row else {
        return Ok(json!({"idle":true}));
    };
    let token = secrets::read(data, &c.reference)?;
    let state: String = store.connect()?.query_row(
        "SELECT push_state FROM publications WHERE id=?",
        [id],
        |r| r.get(0),
    )?;
    // A known prepared commit is immutable. Only new output needs validation and preparation.
    if state == "new" {
        let health = repository_health(store, &Endpoints::default(), &token).await?;
        store.set_meta("github-health", &health)?;
        if health != "ready" {
            store.connect()?.execute("UPDATE publications SET status='waiting-repository',not_before=?,error=? WHERE id=? AND push_state='new'", params![now()+300,health,id])?;
            return Ok(json!({"waiting_for_repository":true}));
        }
        let check_root = root.to_path_buf();
        let check_output = data.join("releases").join(&release);
        tokio::task::spawn_blocking(move || crate::build::validate(&check_output, &check_root))
            .await??;
    }
    let repository: String = store.connect()?.query_row(
        "SELECT repository FROM publications WHERE id=?",
        [id],
        |r| r.get(0),
    )?;
    process_publication(
        store,
        id,
        &data.join("releases").join(release),
        &format!("https://github.com/{repository}.git"),
        Some(&token),
    )
    .await
}

struct Publication {
    release: String,
    repository: String,
    branch: String,
    build: Option<String>,
    sha: Option<String>,
    base: Option<String>,
    state: String,
}
fn current_target(conn: &rusqlite::Connection, p: &Publication) -> Result<bool> {
    let value: String = conn.query_row(
        "SELECT value FROM meta WHERE key='github-settings'",
        [],
        |r| r.get(0),
    )?;
    let settings: Settings = serde_json::from_str(&value)?;
    let release: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='current-release'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let build: Option<String> = conn
        .query_row(
            "SELECT value FROM meta WHERE key='current-build-id'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    Ok(settings.enabled
        && settings.repository == p.repository
        && settings.branch == p.branch
        && release.as_deref() == Some(&p.release)
        && p.build.as_ref().is_none_or(|b| Some(b) == build.as_ref()))
}
fn published(store: &Store, id: i64, sha: &str, actual: &str) -> Result<Value> {
    store.connect()?.execute("UPDATE publications SET status='published',push_state='confirmed',finished=?,commit_sha=?,verified_remote_sha=?,error=NULL WHERE id=? AND commit_sha=?", params![now(),sha,actual,id,sha])?;
    Ok(json!({"published":true,"commit":sha,"verified_remote_sha":actual}))
}
fn pending_reconciliation(store: &Store, id: i64, error: &str) -> Result<Value> {
    store.connect()?.execute("UPDATE publications SET status='unknown',push_state='unknown',not_before=?,error=? WHERE id=? AND push_state IN ('sending','unknown')", params![now()+60,error.chars().take(1500).collect::<String>(),id])?;
    Ok(json!({"unknown":true,"reconciliation_pending":true}))
}
async fn process_publication(
    store: &Store,
    id: i64,
    output: &Path,
    remote: &str,
    token: Option<&str>,
) -> Result<Value> {
    let p = store.connect()?.query_row("SELECT release,repository,branch,build_id,commit_sha,base_sha,push_state FROM publications WHERE id=?", [id], |r| Ok(Publication {
        release:r.get(0)?, repository:r.get(1)?, branch:r.get(2)?, build:r.get(3)?, sha:r.get(4)?, base:r.get(5)?, state:r.get(6)?,
    }))?;
    validate(&Settings {
        repository: p.repository.clone(),
        branch: p.branch.clone(),
        ..Settings::default()
    })?;
    ensure!(
        !p.release.is_empty() && p.release.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid release ID"
    );
    let data = store.path.parent().context("data directory")?;
    let path = data.join("publication-git").join(id.to_string());
    if p.state == "new" {
        if !current_target(&store.connect()?, &p)? {
            store.connect()?.execute(
                "UPDATE publications SET status='superseded' WHERE id=? AND push_state='new'",
                [id],
            )?;
            return Ok(json!({"superseded":true}));
        }
        // No send exists yet; a crashed partial checkout may be rebuilt safely.
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
    }
    let git = git::Git::new(path, remote, &p.branch, token)?;
    let (base, sha) = if p.state == "new" {
        store.connect()?.execute("UPDATE publications SET status='running',attempts=attempts+1 WHERE id=? AND push_state='new'", [id])?;
        match git.prepare(output, &p.release).await {
            Ok((base, sha)) => {
                store.connect()?.execute("UPDATE publications SET push_state='prepared',commit_sha=?,base_sha=? WHERE id=? AND push_state='new'", params![sha,base,id])?;
                (base, sha)
            }
            Err(error) => {
                store.connect()?.execute("UPDATE publications SET status='retry',not_before=?,error=? WHERE id=? AND push_state='new'", params![now()+60,format!("{error:#}"),id])?;
                return Ok(json!({"retry_scheduled":true}));
            }
        }
    } else if let (Some(base), Some(sha)) = (&p.base, &p.sha) {
        (base.clone(), sha.clone())
    } else {
        // Legacy sending records without a saved SHA cannot be proven unsent.
        store.connect()?.execute(
            "UPDATE publications SET status='unknown',push_state='unknown',not_before=? WHERE id=?",
            params![now() + 300, id],
        )?;
        return Ok(json!({"unknown":true,"manual_reconciliation_required":true}));
    };
    let previous = match git.reconcile(&sha, &base).await {
        Ok(remote) => remote,
        Err(error) if matches!(p.state.as_str(), "sending" | "unknown") => {
            return pending_reconciliation(store, id, &format!("{error:#}"));
        }
        Err(error) => {
            store.connect()?.execute("UPDATE publications SET status='retry',not_before=?,error=? WHERE id=? AND push_state='prepared'", params![now()+60,format!("remote check failed before send: {error:#}"),id])?;
            return Ok(json!({"retry_scheduled":true}));
        }
    };
    match previous {
        git::Remote::Published(actual) => return published(store, id, &sha, &actual),
        git::Remote::Conflict(actual) => {
            let state = if matches!(p.state.as_str(), "sending" | "unknown") {
                "unknown"
            } else {
                "prepared"
            };
            store.connect()?.execute("UPDATE publications SET status=?,push_state=?,not_before=?,error=? WHERE id=?", params![if state=="unknown" {"unknown"} else {"failed"},state,now()+300,format!("remote ref conflict ({actual}); immutable commit retained, no rebase or automatic push"),id])?;
            return Ok(json!({"ref_conflict":true,"unknown":state=="unknown"}));
        }
        git::Remote::Base => {}
    }
    if matches!(p.state.as_str(), "sending" | "unknown") {
        return pending_reconciliation(
            store,
            id,
            "send outcome remains uncertain; remote is still at the prepared base; no automatic resend",
        );
    }
    {
        let mut conn = store.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if !current_target(&tx, &p)? {
            tx.execute(
                "UPDATE publications SET status='superseded' WHERE id=? AND push_state='prepared'",
                [id],
            )?;
            tx.commit()?;
            return Ok(json!({"superseded":true}));
        }
        let marked = tx.execute("UPDATE publications SET status='running',push_state='sending' WHERE id=? AND push_state='prepared' AND commit_sha=?", params![id,sha])?;
        ensure!(marked == 1, "publication send state changed");
        tx.commit()?;
    }
    let push = git.push(&sha).await;
    match git.reconcile(&sha, &base).await {
        Ok(git::Remote::Published(actual)) => published(store, id, &sha, &actual),
        Ok(git::Remote::Base)
            if push.as_ref().err().is_some_and(|e| {
                let message = format!("{e:#}");
                message.contains("[rejected]") || message.contains("[remote rejected]")
            }) =>
        {
            // A definitive rejection is retryable only as this same prepared commit.
            store.connect()?.execute("UPDATE publications SET status='failed',push_state='prepared',error=? WHERE id=? AND push_state='sending' AND commit_sha=?", params![push.err().map(|e|format!("{e:#}")),id,sha])?;
            Ok(json!({"rejected":true}))
        }
        Ok(_) => pending_reconciliation(
            store,
            id,
            "push not verified at remote; immutable commit retained without resend",
        ),
        Err(error) => {
            pending_reconciliation(store, id, &format!("push reconciliation failed: {error:#}"))
        }
    }
}

/// Isolated callers/tests can exercise the durable worker with a local bare remote.
/// The HTTP API never accepts an arbitrary repository URL.
pub async fn publish_queued_tree(
    store: &Store,
    id: i64,
    output: &Path,
    remote: &str,
    token: Option<&str>,
) -> Result<Value> {
    let _lock = crate::FileLock::try_new(File::create(store.path.with_extension("publish.lock"))?)?;
    process_publication(store, id, output, remote, token).await
}

// One-shot offline helper. The controller always uses the durable queue above.
pub async fn publish_tree(
    output: &Path,
    remote: &str,
    branch: &str,
    release: &str,
    token: Option<&str>,
) -> Result<String> {
    validate(&Settings {
        branch: branch.into(),
        ..Settings::default()
    })?;
    ensure!(
        !release.is_empty() && release.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid release ID"
    );
    let dir = tempfile::tempdir()?;
    let git = git::Git::new(dir.path().to_path_buf(), remote, branch, token)?;
    let (base, sha) = git.prepare(output, release).await?;
    match git.reconcile(&sha, &base).await? {
        git::Remote::Published(_) => return Ok(sha),
        git::Remote::Conflict(_) => anyhow::bail!("remote branch changed before publication"),
        git::Remote::Base => {}
    }
    git.push(&sha).await?;
    ensure!(
        matches!(git.reconcile(&sha, &base).await?, git::Remote::Published(_)),
        "remote branch changed after publication; reconcile before retry"
    );
    Ok(sha)
}
