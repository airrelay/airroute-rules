//! Provider-managed hourly quotas, persisted remote measurements and conservative retries.
mod intent;
mod limits;
use crate::{
    now,
    store::{Lease, Node, ProbeResult, Store},
};
use anyhow::{Context, Result, ensure};
use limits::pause;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, time::Duration};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub token_env: String,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub regions: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "base_url")]
    pub base_url: String,
    #[serde(default)]
    pub accounts: Vec<Account>,
}
fn base_url() -> String {
    "https://api.globalping.io/v1".into()
}
impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: base_url(),
            accounts: vec![],
        }
    }
}
pub fn load(path: &Path) -> Result<Config> {
    if path.exists() {
        let mut value: Value = toml::from_str(&std::fs::read_to_string(path)?)?;
        for a in value["accounts"].as_array_mut().into_iter().flatten() {
            upgrade_account(a)?;
        }
        value
            .as_object_mut()
            .context("Globalping config object")?
            .remove("quota_groups");
        let c: Config = serde_json::from_value(value)?;
        let url = reqwest::Url::parse(&c.base_url)?;
        ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && url.host_str().is_some_and(|h| h == "localhost"
                        || h.parse::<std::net::IpAddr>().is_ok_and(|i| i.is_loopback()))),
            "Globalping credentials require HTTPS outside local fixtures"
        );
        let mut ids = std::collections::BTreeSet::new();
        for a in &c.accounts {
            ensure!(ids.insert(&a.id), "duplicate Globalping account");
        }
        Ok(c)
    } else {
        Ok(Config::default())
    }
}
// Legacy settings are readable but no longer control admission.
fn upgrade_account(value: &mut Value) -> Result<Option<String>> {
    let key = value["quota_group"].as_str().map(str::to_string);
    let map = value.as_object_mut().context("account object")?;
    map.remove("quota_group");
    map.remove("quota");
    Ok(key)
}
fn migrate(store: &Store, base: &Config) -> Result<()> {
    if store.meta("globalping-account-quota-v1")?.is_some() {
        return Ok(());
    }
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if tx.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='globalping-account-quota-v1')",
        [],
        |r| r.get(0),
    )? {
        tx.commit()?;
        return Ok(());
    }
    let exists = |table: &str| -> Result<bool> {
        Ok(tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
            [table],
            |r| r.get(0),
        )?)
    };
    let mut accounts: BTreeMap<String, (Account, Option<String>)> = base
        .accounts
        .iter()
        .map(|a| (a.id.clone(), (a.clone(), None)))
        .collect();
    {
        let mut q = tx.prepare("SELECT id,config FROM gp_accounts")?;
        let rows = q
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (id, text) in rows {
            let mut v: Value = serde_json::from_str(&text)?;
            let key = upgrade_account(&mut v)?;
            let a: Account = serde_json::from_value(v)?;
            tx.execute(
                "UPDATE gp_accounts SET config=? WHERE id=?",
                params![serde_json::to_string(&a)?, id],
            )?;
            accounts.insert(id, (a, key));
        }
    }
    if exists("gp_usage")? {
        for (id, (_, key)) in &accounts {
            if let Some(key) = key {
                tx.execute("INSERT INTO gp_account_usage SELECT ?,bucket,used,blocked_until FROM gp_usage WHERE quota_group=? ON CONFLICT(account,bucket) DO UPDATE SET used=max(used,excluded.used),blocked_until=max(blocked_until,excluded.blocked_until)",params![id,key])?;
            } else {
                // File-only legacy accounts have no persisted owner mapping. Conservatively
                // carry old consumption to each one rather than grant a fresh budget.
                tx.execute("INSERT INTO gp_account_usage SELECT ?,bucket,sum(used),max(blocked_until) FROM gp_usage GROUP BY bucket ON CONFLICT(account,bucket) DO UPDATE SET used=max(used,excluded.used),blocked_until=max(blocked_until,excluded.blocked_until)",[id])?;
            }
        }
    }
    {
        let mut q=tx.prepare("SELECT job_id,account,account_snapshot FROM gp_remote WHERE account_snapshot IS NOT NULL")?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (job, _id, text) in rows {
            let mut v: Value = serde_json::from_str(&text)?;
            upgrade_account(&mut v)?;
            tx.execute(
                "UPDATE gp_remote SET account_snapshot=? WHERE job_id=?",
                params![serde_json::to_string(&v)?, job],
            )?;
        }
    }
    tx.execute_batch("DROP TABLE IF EXISTS gp_groups; DROP TABLE IF EXISTS gp_usage;")?;
    tx.execute(
        "INSERT INTO meta VALUES('globalping-account-quota-v1','complete')",
        [],
    )?;
    tx.commit()?;
    Ok(())
}
pub fn effective(store: &Store, base: &Config) -> Result<Config> {
    intent::migrate(store)?;
    migrate(store, base)?;
    migrate_test_usage(store)?;
    let mut c = base.clone();
    let conn = store.connect()?;
    let mut q = conn.prepare("SELECT id,config,deleted FROM gp_accounts")?;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, bool>(2)?,
        ))
    })? {
        let (id, config, deleted) = row?;
        c.accounts.retain(|a| a.id != id);
        if !deleted {
            c.accounts.push(serde_json::from_str(&config)?);
        }
    }
    c.accounts.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(c)
}
fn record_test_usage(
    conn: &rusqlite::Connection,
    account: &str,
    measurement: &str,
    data: &Value,
    fallback_time: i64,
    fallback_tests: u32,
) -> Result<()> {
    let created = data["createdAt"]
        .as_str()
        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
        .map(|v| v.timestamp())
        .unwrap_or(fallback_time);
    let tests = data["probesCount"]
        .as_u64()
        .or_else(|| {
            data["results"]
                .as_array()
                .filter(|v| !v.is_empty())
                .map(|v| v.len() as u64)
        })
        .unwrap_or(u64::from(fallback_tests))
        .min(500) as i64;
    conn.execute("INSERT INTO gp_test_usage VALUES(?,?,?,?) ON CONFLICT(account,measurement) DO UPDATE SET created=excluded.created,tests=excluded.tests",params![account,measurement,created,tests])?;
    Ok(())
}
fn migrate_test_usage(store: &Store) -> Result<()> {
    if store.meta("globalping-test-usage-v1")?.is_some() {
        return Ok(());
    }
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let done: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='globalping-test-usage-v1')",
        [],
        |r| r.get(0),
    )?;
    if !done {
        {
            let mut q=tx.prepare("SELECT node,observed,evidence FROM results WHERE node LIKE 'globalping:%' ORDER BY received,id")?;
            for r in q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })? {
                let (node, at, body) = r?;
                let v: Value = serde_json::from_str(&body)?;
                if let (Some(account), Some(id)) =
                    (node.split(':').nth(1), v["measurement_id"].as_str())
                {
                    record_test_usage(&tx, account, id, &v["measurement"], at, 1)?;
                }
            }
        }
        {
            let mut q =
                tx.prepare("SELECT account,remote_id,lease FROM gp_remote WHERE remote_id<>''")?;
            for r in q.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })? {
                let (account, id, body) = r?;
                let lease: Lease = serde_json::from_str(&body)?;
                tx.execute(
                    "INSERT OR IGNORE INTO gp_test_usage VALUES(?,?,?,?)",
                    params![
                        account,
                        id,
                        lease.until - 180,
                        lease.profile["globalping_reserved_tests"]
                            .as_u64()
                            .unwrap_or(1)
                            .min(500) as i64
                    ],
                )?;
            }
        }
        tx.execute(
            "INSERT INTO meta VALUES('globalping-test-usage-v1','complete')",
            [],
        )?;
    }
    tx.commit()?;
    Ok(())
}
fn token(store: &Store, a: &Account) -> Result<String> {
    if let Some(reference) = &a.credential_ref {
        return crate::secrets::read(store.path.parent().context("data directory")?, reference);
    }
    let value = std::env::var(&a.token_env).context("Globalping credential missing")?;
    ensure!(!value.trim().is_empty(), "Globalping credential missing");
    Ok(value)
}
#[derive(Deserialize)]
pub struct AccountInput {
    pub id: Option<String>,
    pub name: String,
    pub token: Option<String>,
    pub enabled: bool,
    pub regions: BTreeMap<String, String>,
}
pub fn save_account(store: &Store, base: &Config, input: AccountInput) -> Result<Value> {
    let _lock = crate::FileLock::blocking(std::fs::File::create(
        store.path.with_extension("globalping.lock"),
    )?)?;
    let c = effective(store, base)?;
    let id = input
        .id
        .unwrap_or_else(|| format!("gp-{}", uuid::Uuid::new_v4().simple()));
    let valid_id = |s: &str| {
        !s.is_empty()
            && s.len() <= 80
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    };
    ensure!(valid_id(&id), "invalid account ID");
    ensure!(
        input.name.trim().len() <= 160 && !input.name.chars().any(char::is_control),
        "invalid account name"
    );
    ensure!(
        input.regions.len() <= 16
            && input.regions.iter().all(|(k, v)| valid_id(k)
                && !v.is_empty()
                && v.len() <= 80
                && !v.chars().any(char::is_control)),
        "invalid Globalping location coverage"
    );
    let old = c.accounts.iter().find(|a| a.id == id);
    let mut a = Account {
        id: id.clone(),
        name: input.name.trim().into(),
        enabled: input.enabled,
        regions: input.regions,
        credential_ref: old.and_then(|a| a.credential_ref.clone()),
        token_env: old.map(|a| a.token_env.clone()).unwrap_or_default(),
    };
    let credential_changed = input.token.as_ref().is_some_and(|v| !v.trim().is_empty());
    if let Some(value) = input.token.filter(|s| !s.trim().is_empty()) {
        a.credential_ref = Some(crate::secrets::save(
            store.path.parent().context("data directory")?,
            &value,
        )?);
        a.token_env.clear();
    }
    ensure!(
        !a.enabled || (!a.regions.is_empty() && token(store, &a).is_ok()),
        "enabled accounts need a credential and observer coverage"
    );
    let mut conn = store.connect()?;
    let tx = conn.transaction()?;
    tx.execute("INSERT INTO gp_accounts VALUES(?,?,0) ON CONFLICT(id) DO UPDATE SET config=excluded.config,deleted=0",params![id,serde_json::to_string(&a)?])?;
    if credential_changed {
        limits::invalidate(&tx, &id)?;
        tx.execute(
            "UPDATE gp_account_usage SET blocked_until=0 WHERE account=?",
            [&id],
        )?;
    }
    tx.commit()?;
    if let Some(old) = old {
        cleanup_reference(store, base, old.credential_ref.as_deref())?;
    }
    Ok(json!({"saved":true,"id":id}))
}
pub fn delete_account(store: &Store, base: &Config, id: &str) -> Result<()> {
    let _lock = crate::FileLock::blocking(std::fs::File::create(
        store.path.with_extension("globalping.lock"),
    )?)?;
    let c = effective(store, base)?;
    let a = c
        .accounts
        .iter()
        .find(|a| a.id == id)
        .context("account not found")?;
    store.connect()?.execute(
        "INSERT INTO gp_accounts VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET deleted=1",
        params![id, serde_json::to_string(a)?],
    )?;
    cleanup_reference(store, base, a.credential_ref.as_deref())?;
    Ok(())
}
fn cleanup_reference(store: &Store, base: &Config, reference: Option<&str>) -> Result<()> {
    let Some(reference) = reference else {
        return Ok(());
    };
    let active = effective(store, base)?
        .accounts
        .iter()
        .any(|a| a.credential_ref.as_deref() == Some(reference));
    let pending:bool=store.connect()?.query_row("SELECT EXISTS(SELECT 1 FROM gp_remote WHERE json_extract(account_snapshot,'$.credential_ref')=?)",[reference],|r|r.get(0))?;
    if !active && !pending {
        crate::secrets::remove(store.path.parent().context("data directory")?, reference)?;
    }
    Ok(())
}
pub fn status(store: &Store, c: &Config) -> Result<Value> {
    let c = effective(store, c)?;
    let stats = store.executor_stats()?;
    let mut rows = vec![];
    let conn = store.connect()?;
    for a in &c.accounts {
        let prefix = format!("globalping:{}:", a.id);
        let mut stat = crate::store::ExecutorStats::default();
        for (_, v) in stats.iter().filter(|(id, _)| id.starts_with(&prefix)) {
            stat.completed_tasks += v.completed_tasks;
            stat.running_tasks += v.running_tasks;
            stat.last_completed_at = stat.last_completed_at.max(v.last_completed_at);
        }
        let used: Option<(u32, i64)> = conn
            .query_row(
                "SELECT used,blocked_until FROM gp_account_usage WHERE account=? AND bucket=?",
                params![a.id, now() / 3600],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let recent:i64=conn.query_row("SELECT coalesce(sum(tests),0) FROM gp_test_usage WHERE account=? AND created>? AND created<=?",params![a.id,now()-3600,now()],|r|r.get(0))?;
        let (prepared,submitted,unknown):(i64,i64,i64)=conn.query_row("SELECT coalesce(sum(state='prepared'),0),coalesce(sum(remote_id<>''),0),coalesce(sum(state='unknown' AND remote_id=''),0) FROM gp_remote WHERE account=?",[&a.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        rows.push(json!({"id":a.id,"name":a.name,"enabled":a.enabled,"credential_configured":token(store,a).is_ok(),"limits":limits::cached(&conn,&a.id)?,"minimum_interval_seconds":limits::MINIMUM_INTERVAL,"regions":a.regions,"hourly_usage_used":used.map(|u|u.0).unwrap_or(0),"prepared_tasks":prepared,"remote_pending_tasks":submitted,"uncertain_submissions":unknown,"recent_probe_tests":recent,"blocked_until":limits::blocked_until(&conn,&a.id)?,"completed_tasks":stat.completed_tasks,"running_tasks":stat.running_tasks,"last_completed_at":stat.last_completed_at}));
    }
    Ok(json!({"accounts":rows,"remote_enabled":c.accounts.iter().any(|a|a.enabled)}))
}
pub fn measurement_cost(request: &Value) -> Result<u32> {
    let locations = request["locations"]
        .as_array()
        .context("explicit location array required for budget accounting")?;
    ensure!(!locations.is_empty(), "measurement needs a location");
    let per_location = locations.iter().any(|v| !v["limit"].is_null());
    let valid = |v: &Value| -> Result<u32> {
        let n = v.as_u64().context("invalid probe limit")?;
        ensure!((1..=500).contains(&n), "invalid probe limit");
        Ok(n as u32)
    };
    let cost = if !request["limit"].is_null() {
        ensure!(
            !per_location,
            "global and per-location probe limits are mutually exclusive"
        );
        valid(&request["limit"])?
    } else if per_location {
        locations.iter().try_fold(0u32, |sum, v| -> Result<u32> {
            let n = if v["limit"].is_null() {
                1
            } else {
                valid(&v["limit"])?
            };
            sum.checked_add(n).context("probe budget overflow")
        })?
    } else {
        1
    };
    ensure!(cost <= 500, "measurement exceeds supported probe budget");
    Ok(cost)
}
/// Schema setup is safe on repeated opens. Recovery is only performed by `run`.
pub fn initialize_intents(store: &Store) -> Result<()> {
    intent::migrate(store)
}

type Events = Vec<Value>;

fn configured_coverage(store: &Store, config: &Config) -> Result<()> {
    let coverage: Vec<_> = config
        .accounts
        .iter()
        .filter(|a| a.enabled && token(store, a).is_ok())
        .flat_map(|a| a.regions.keys().map(|r| json!({"account":a.id,"region":r})))
        .collect();
    let value = json!(coverage).to_string();
    if store.meta("gp-coverage")?.as_deref() != Some(value.as_str()) {
        store.set_meta("gp-coverage", &value)?;
    }
    Ok(())
}

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("AirRoute-Rules/0.3 measurement-controller")
        .build()?)
}

/// A one-round adapter for CLI and isolated tests. Live controllers use `run`,
/// whose outstanding GET/POST responses never delay another admission round.
pub async fn tick(store: &Store, config: &Config) -> Result<Value> {
    initialize_intents(store)?;
    let config = effective(store, config)?;
    configured_coverage(store, &config)?;
    let client = client()?;
    let mut pending = tokio::task::JoinSet::new();
    launch_round(store, &config, &client, &mut pending)?;
    let mut events = vec![];
    while let Some(result) = pending.join_next().await {
        match result {
            Ok(Ok(v)) => events.extend(v),
            Ok(Err(e)) => events.push(json!({"status":"round-error","error":e.to_string()})),
            Err(e) => events.push(json!({"status":"worker-error","error":e.to_string()})),
        }
    }
    Ok(json!({"events":events}))
}

/// Runs on the controller's dedicated I/O runtime. Durable database admission
/// serializes send starts; responses remain independently awaitable.
pub async fn run(store: &Store, base: &Config) -> Result<()> {
    initialize_intents(store)?;
    intent::recover_interrupted_sends(store)?;
    let client = client()?;
    let mut pending = tokio::task::JoinSet::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=interval.tick()=>{
                match effective(store,base).and_then(|config| {
                    configured_coverage(store,&config)?;
                    launch_round(store,&config,&client,&mut pending)
                }) {
                    Ok(())=>{},
                    Err(error)=>tracing::warn!(%error,"Globalping admission round failed"),
                }
            },
            Some(done)=pending.join_next(),if !pending.is_empty()=>{
                match done {
                    Ok(Ok(_))=>{},
                    Ok(Err(error))=>tracing::warn!(%error,"Globalping worker failed; durable intent retained"),
                    Err(error)=>tracing::warn!(%error,"Globalping worker exited; durable intent retained"),
                }
            }
        }
    }
}

fn launch_round(
    store: &Store,
    config: &Config,
    client: &reqwest::Client,
    pending: &mut tokio::task::JoinSet<Result<Events>>,
) -> Result<()> {
    // Prepared means provably unsent; disabled/deleted/replaced credentials may
    // release that reservation. Known ids and uncertain sends remain recoverable.
    let unsent = {
        let c = store.connect()?;
        let mut q=c.prepare("SELECT account,lease FROM gp_remote WHERE state='prepared' ORDER BY next_poll,job_id LIMIT 16")?;
        q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (account, text) in unsent {
        let lease: Lease = serde_json::from_str(&text)?;
        if !config.accounts.iter().any(|a| {
            a.id == account
                && a.enabled
                && a.regions.contains_key(&lease.region)
                && token(store, a).is_ok()
        }) {
            intent::cancel_prepared(store, &lease)?;
        }
    }
    // LIMIT is a reaping batch size, not the active-creation slot count. Unknown
    // empty ids never enter this query and cannot starve recoverable ids.
    let rows = {
        let c = store.connect()?;
        let mut q=c.prepare("SELECT job_id,lease,account,remote_id,account_snapshot FROM gp_remote WHERE remote_id<>'' AND next_poll<=?1 AND NOT EXISTS(SELECT 1 FROM observation_cache backoff WHERE backoff.key='gp-poll-pause:'||gp_remote.account AND backoff.valid_until>?1) ORDER BY next_poll,job_id LIMIT 16")?;
        q.query_map([now()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (job, text, account, remote, snapshot) in rows {
        let lease: Lease = serde_json::from_str(&text)?;
        let c = store.connect()?;
        if c.execute("UPDATE gp_remote SET next_poll=? WHERE job_id=? AND remote_id=? AND next_poll<=? AND json_extract(lease,'$.token')=?",params![now()+30,job,remote,now(),lease.token])?==0 {continue;}
        let (store, config, client) = (store.clone(), config.clone(), client.clone());
        pending.spawn(async move {
            poll_one(store, config, client, lease, account, remote, snapshot).await
        });
    }
    for a in config.accounts.iter().filter(|a| a.enabled) {
        let (store, config, client, a) = (store.clone(), config.clone(), client.clone(), a.clone());
        pending.spawn(async move { admit_one(store, config, client, a).await });
    }
    Ok(())
}

fn pause_poll_account(store: &Store, account: &str, delay: i64) -> Result<()> {
    store.connect()?.execute("INSERT INTO observation_cache VALUES(?,?,'null') ON CONFLICT(key) DO UPDATE SET valid_until=max(valid_until,excluded.valid_until)",params![format!("gp-poll-pause:{account}"),now()+delay.clamp(1,86400)])?;
    Ok(())
}

async fn poll_one(
    store: Store,
    config: Config,
    client: reqwest::Client,
    lease: Lease,
    account: String,
    remote: String,
    snapshot: Option<String>,
) -> Result<Events> {
    let saved = snapshot
        .map(|s| serde_json::from_str::<Account>(&s))
        .transpose()?;
    let Some(a) = saved
        .as_ref()
        .or_else(|| config.accounts.iter().find(|a| a.id == account))
    else {
        intent::poll_later(&store, &lease, now() + 300)?;
        return Ok(vec![
            json!({"job":lease.id,"status":"account-missing; remote result retained"}),
        ]);
    };
    let Ok(secret) = token(&store, a) else {
        intent::poll_later(&store, &lease, now() + 300)?;
        pause_poll_account(&store, &account, 300)?;
        return Ok(vec![
            json!({"job":lease.id,"status":"credential-missing; remote result retained"}),
        ]);
    };
    store.connect()?.execute(
        "UPDATE jobs SET lease_until=? WHERE id=? AND lease_token=? AND status='leased'",
        params![now() + 180, lease.id, lease.token],
    )?;
    let response = match client
        .get(format!(
            "{}/measurements/{remote}",
            config.base_url.trim_end_matches('/')
        ))
        .bearer_auth(secret)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => {
            intent::poll_later(&store, &lease, now() + 60)?;
            return Ok(vec![json!({"job":lease.id,"status":"poll-network-error"})]);
        }
    };
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let delay = retry_after(response.headers());
        pause(&store, &a.id, delay)?;
        pause_poll_account(&store, &account, delay)?;
        intent::poll_later(&store, &lease, now() + delay.clamp(1, 86400))?;
        return Ok(vec![]);
    }
    if !response.status().is_success() {
        let status = response.status().as_u16();
        if matches!(status, 401 | 403) {
            pause_poll_account(&store, &account, 300)?;
        }
        intent::poll_later(&store, &lease, now() + 300)?;
        return Ok(vec![
            json!({"job":lease.id,"status":"poll-http-error","http_status":status}),
        ]);
    }
    let data: Value = match response.json().await {
        Ok(data) => data,
        Err(_) => {
            intent::poll_later(&store, &lease, now() + 60)?;
            return Ok(vec![]);
        }
    };
    if data["id"].as_str() != Some(remote.as_str()) {
        intent::poll_later(&store, &lease, now() + 60)?;
        return Ok(vec![
            json!({"job":lease.id,"status":"poll-id-mismatch; original intent retained"}),
        ]);
    }
    if data["status"] == "in-progress" {
        intent::poll_later(&store, &lease, now() + 5)?;
        return Ok(vec![]);
    }
    let ok = data["results"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["result"]["status"] == "finished"));
    // `ok` only reports command execution. Store qualification separately checks
    // actual probe region/ASN, target/method and evidence before satisfying work.
    let result = ProbeResult {
        id: format!("globalping-{remote}"),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: data["createdAt"]
            .as_str()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.timestamp())
            .unwrap_or(lease.until - 180),
        outcome: if ok { "ok" } else { "error" }.into(),
        evidence: json!({"provider":"globalping","measurement_id":remote,"attempt_seq":lease.profile["attempt_seq"],"quota":{"unit":"probe-test","reserved":lease.profile["globalping_reserved_tests"].as_u64().unwrap_or(1),"returned_probes":data["probesCount"].as_u64().unwrap_or(data["results"].as_array().map_or(0,|v|v.len()) as u64)},"measurement":data,"scope":"actual returned probe metadata; a finished command is not a geographic verdict"}),
    };
    record_test_usage(
        &store.connect()?,
        &a.id,
        &remote,
        &result.evidence["measurement"],
        result.observed_at,
        lease.profile["globalping_reserved_tests"]
            .as_u64()
            .unwrap_or(1) as u32,
    )?;
    let ack = store.submit(&format!("globalping:{}:{}", a.id, lease.region), &result)?;
    if ack["accepted"] == true && ack["duplicate"] != true {
        tracing::info!(account=%a.id,job=%lease.id,outcome=%result.outcome,"Globalping measurement completed");
    }
    intent::finish(&store, &lease)?;
    cleanup_reference(&store, &config, a.credential_ref.as_deref())?;
    Ok(vec![json!({"job":lease.id,"ack":ack})])
}

fn measurement_request(lease: &Lease, location: &str) -> Value {
    let options = if lease.kind == "dns" {
        json!({"query":{"type":lease.profile["query"]["type"].as_str().or_else(||lease.profile["query_type"].as_str()).unwrap_or("A")},"protocol":lease.profile["protocol"].as_str().unwrap_or("UDP").to_uppercase()})
    } else {
        json!({"protocol":lease.profile["protocol"].as_str().unwrap_or("ICMP").to_uppercase()})
    };
    let mut selection = json!({"magic":location});
    if let Some(asn) = lease.profile["required_asn"].as_u64().filter(|v| *v > 0) {
        selection["asn"] = asn.into();
        // The official filter special-cases world before applying other fields.
        if location.eq_ignore_ascii_case("world") {
            selection.as_object_mut().unwrap().remove("magic");
        }
    }
    json!({"type":lease.kind,"target":lease.target,"limit":1,"locations":[selection],"measurementOptions":options})
}

async fn admit_one(
    store: Store,
    config: Config,
    client: reqwest::Client,
    a: Account,
) -> Result<Events> {
    // Only serialize the pre-send section. Dropping this guard after begin_send
    // permits another send after its durable spacing expires while responses wait.
    let guard = match crate::FileLock::try_new(std::fs::File::create(
        store
            .path
            .with_extension(format!("gp-{}.lock", crate::hash(&a.id))),
    )?) {
        Ok(g) => g,
        Err(std::fs::TryLockError::WouldBlock) => return Ok(vec![]),
        Err(e) => return Err(e.into()),
    };
    let Ok(secret) = token(&store, &a) else {
        return Ok(vec![json!({"account":a.id,"status":"credential-missing"})]);
    };
    if let Err(error) = limits::refresh(&store, &config, &a, &client, &secret, false).await {
        return Ok(vec![
            json!({"account":a.id,"status":"quota-check-failed","error":error.to_string()}),
        ]);
    }
    if limits::cached(&store.connect()?, &a.id)?.is_none_or(|v| {
        v.last_error.is_some() || v.valid_until <= now() || (v.reset_at > 0 && v.reset_at <= now())
    }) {
        return Ok(vec![]);
    }
    let mut lease = intent::prepared(&store, &a.id)?;
    if lease.is_none() {
        // Empty/owned-only queues need no region-by-region claim passes. This
        // indexed readiness hint is only an optimization; claim rechecks truth.
        if !store.connect()?.query_row::<bool,_,_>("SELECT EXISTS(SELECT 1 FROM jobs WHERE status='pending' AND not_before<=? AND coalesce(json_extract(profile,'$.self_only'),0)=0 AND (coalesce(json_extract(profile,'$.legacy_alias'),0)=0 OR json_extract(profile,'$.logical_job')=1))",[now()],|r|r.get(0))? {
            return Ok(vec![]);
        }
        let regions: Vec<_> = a.regions.iter().collect();
        let cursor = store.meta(&format!("gp-region-cursor:{}", a.id))?;
        let start = cursor
            .as_ref()
            .and_then(|v| regions.iter().position(|(r, _)| *r == v))
            .map(|n| n + 1)
            .unwrap_or(0);
        // Search every eligible region for an uncovered necessary view before
        // allowing this account to compete for work owned nodes can also do.
        let mut preferred_scan_complete = true;
        'preference: for uncovered_only in [true, false] {
            if !uncovered_only && !preferred_scan_complete {
                // A bounded scan yielding is not proof that preferred work is
                // absent. The next coordinator wake resumes its own cursor.
                break;
            }
            for offset in 0..regions.len() {
                if !limits::ready(&store.connect()?, &a.id, 1)? {
                    break 'preference;
                }
                let (region, _) = regions[(start + offset) % regions.len()];
                let node = Node {
                    id: format!("globalping:{}:{region}", a.id),
                    region: region.clone(),
                    asn: 0,
                    capabilities: vec!["dns".into(), "traceroute".into()],
                };
                let exists: bool = store.connect()?.query_row(
                    "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?)",
                    [&node.id],
                    |r| r.get(0),
                )?;
                if !exists {
                    store.register_node(&node, &crate::hash(format!("virtual:{}", node.id)))?;
                }
                lease = crate::jobs_v3::lease_with_admission_preference(
                    &store,
                    &node,
                    None,
                    uncovered_only,
                    |tx, lease| intent::prepare_on(tx, &a, lease, 1, now()),
                )?;
                if lease.is_some() {
                    store.set_meta(&format!("gp-region-cursor:{}", a.id), region)?;
                    break 'preference;
                }
                if uncovered_only && !crate::jobs_v3::uncovered_scan_complete(&store, &node) {
                    preferred_scan_complete = false;
                }
            }
        }
    }
    let Some(lease) = lease else {
        return Ok(vec![]);
    };
    let Some(location) = a.regions.get(&lease.region) else {
        return Ok(vec![]);
    };
    let request = measurement_request(&lease, location);

    let cost = measurement_cost(&request)?;
    // A reservation is not permission to send. Re-fetch the authoritative balance
    // before the transactional final window/eligibility/interval check.
    if let Err(error) = limits::refresh(&store, &config, &a, &client, &secret, true).await {
        return Ok(vec![
            json!({"account":a.id,"status":"quota-check-failed","error":error.to_string()}),
        ]);
    }
    let send_started_at = now();
    if !intent::begin_send(&store, &a, &lease, send_started_at)? {
        return Ok(vec![]);
    }
    drop(guard);
    let response = client
        .post(format!(
            "{}/measurements",
            config.base_url.trim_end_matches('/')
        ))
        .bearer_auth(&secret)
        .json(&request)
        .send()
        .await;
    let mut events = vec![];
    match response {
        Ok(r) if r.status() == reqwest::StatusCode::ACCEPTED => {
            let headers = r.headers().clone();
            let data: Value = r.json().await.unwrap_or(Value::Null);
            let Some(remote) = created_measurement_id(&data, &headers, &config.base_url) else {
                intent::unknown(&store, &lease)?;
                return Ok(vec![
                    json!({"job":lease.id,"status":"uncertain-creation; missing remote ID"}),
                ]);
            };
            if intent::submitted(&store, &lease, &remote)? {
                record_test_usage(&store.connect()?, &a.id, &remote, &data, now(), cost)?;
                tracing::info!(account=%a.id,job=%lease.id,"Globalping measurement submitted");
            }
            if let Err(e) = limits::observe_headers_from(&store, &a.id, &headers, send_started_at) {
                limits::invalidate(&store.connect()?, &a.id)?;
                events.push(
                    json!({"account":a.id,"status":"quota-header-invalid","error":e.to_string()}),
                );
            }
            events.push(json!({"account":a.id,"job":lease.id,"remote_id":remote}));
        }
        Ok(r) => {
            let status = r.status();
            let wait = retry_after(r.headers());
            let wait = if matches!(status.as_u16(), 401 | 403) {
                wait.max(300)
            } else {
                wait
            };
            tracing::warn!(account=%a.id,job=%lease.id,http_status=status.as_u16(),retry_after_seconds=wait,"Globalping creation did not return an accepted measurement");
            if matches!(status.as_u16(), 401 | 403 | 429) {
                pause(&store, &a.id, wait)?;
            }
            let headers = r.headers().clone();
            if matches!(status.as_u16(), 400 | 401 | 403 | 422 | 429) {
                let detail = r.text().await.unwrap_or_default();
                let family_unavailable = status.as_u16() == 422
                    && (detail.contains("no_probes_found") || detail.contains("No matching IPv"));
                let asn_scoped = lease.profile["required_asn"]
                    .as_u64()
                    .is_some_and(|v| v > 0);
                if family_unavailable && !asn_scoped {
                    store.connect()?.execute("INSERT INTO gp_unavailable VALUES(?,?,?) ON CONFLICT(executor,family) DO UPDATE SET until=excluded.until",params![format!("globalping:{}:{}",a.id,lease.region),if lease.target.contains(':'){6}else{4},now()+300])?;
                }
                intent::reject(
                    &store,
                    &lease,
                    now()
                        + if matches!(status.as_u16(), 401 | 403 | 429) {
                            // Authentication/quota failure belongs to this
                            // account. Another healthy account may claim now.
                            0
                        } else if family_unavailable {
                            if asn_scoped { 300 } else { 0 }
                        } else {
                            wait
                        },
                    family_unavailable || matches!(status.as_u16(), 401 | 403 | 429),
                )?;
            } else {
                intent::unknown(&store, &lease)?;
            }
            if let Err(e) = limits::observe_headers_from(&store, &a.id, &headers, send_started_at) {
                limits::invalidate(&store.connect()?, &a.id)?;
                events.push(
                    json!({"account":a.id,"status":"quota-header-invalid","error":e.to_string()}),
                );
            }
            events.push(json!({"account":a.id,"job":lease.id,"status":status.as_u16()}));
        }
        Err(_) => {
            intent::unknown(&store, &lease)?;
            tracing::warn!(account=%a.id,job=%lease.id,"Globalping creation delivery is uncertain; original intent retained");
            events.push(json!({"job":lease.id,"status":"uncertain-creation"}));
        }
    }
    Ok(events)
}

fn created_measurement_id(
    data: &Value,
    headers: &reqwest::header::HeaderMap,
    base_url: &str,
) -> Option<String> {
    let valid_id = |id: &str| {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if let Some(id) = data["id"].as_str().filter(|id| valid_id(id)) {
        return Some(id.to_owned());
    }
    // The provider documents Location as the URL of this accepted measurement.
    // Recover only its ID; polling continues through our configured API origin.
    let mut values = headers.get_all(reqwest::header::LOCATION).iter();
    let reference = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || reference.trim() != reference
        || reference.chars().any(char::is_control)
        || reference.contains(['\\', '%', '?', '#'])
        || reference.split('/').any(|p| matches!(p, "." | ".."))
    {
        return None;
    }
    let create =
        reqwest::Url::parse(&format!("{}/measurements", base_url.trim_end_matches('/'))).ok()?;
    let location = create.join(reference).ok()?;
    if location.origin() != create.origin()
        || !location.username().is_empty()
        || location.password().is_some()
        || location.query().is_some()
        || location.fragment().is_some()
    {
        return None;
    }
    let prefix = format!("{}/", create.path());
    let id = location.path().strip_prefix(&prefix)?;
    valid_id(id).then(|| id.to_owned())
}

fn retry_after(headers: &reqwest::header::HeaderMap) -> i64 {
    headers
        .get("retry-after")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creation_location_rejects_ambiguous_origins_paths_and_ids() {
        let base = "https://api.globalping.io/v1";
        for location in [
            "https://other.example/v1/measurements/id",
            "http://api.globalping.io/v1/measurements/id",
            "https://user@api.globalping.io/v1/measurements/id",
            "/v1/measurements/id?option=1",
            "/v1/measurements/id#fragment",
            "/v1/measurements/%69d",
            "/v1/measurements/id/extra",
            "/v1/measurements/../id",
            "/v1/measurements/",
            "/measurements/id",
            "id",
            " /v1/measurements/id",
            "/v1/measurements/id\\extra",
            "/v1/measurements/i\td",
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(reqwest::header::LOCATION, location.parse().unwrap());
            assert_eq!(
                created_measurement_id(&json!({}), &headers, base),
                None,
                "{location}"
            );
        }
        let mut headers = reqwest::header::HeaderMap::new();
        headers.append(
            reqwest::header::LOCATION,
            "/v1/measurements/first".parse().unwrap(),
        );
        headers.append(
            reqwest::header::LOCATION,
            "/v1/measurements/second".parse().unwrap(),
        );
        assert_eq!(created_measurement_id(&json!({}), &headers, base), None);
    }
    #[test]
    fn recent_tests_count_actual_probes_in_a_rolling_hour_and_deduplicate_measurements() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        let conn = s.connect().unwrap();
        let data = json!({"measurement_id":"legacy-one","measurement":{"createdAt":chrono::DateTime::from_timestamp(now()-100,0).unwrap().to_rfc3339(),"probesCount":3}});
        // Even historical-only receipts represent tests that the provider actually ran.
        conn.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received) VALUES('legacy','job','globalping:fixture:us','fp',?,'error',?,0,?)",params![now()-100,data.to_string(),now()]).unwrap();
        let config = Config {
            accounts: vec![Account {
                id: "fixture".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            status(&s, &config).unwrap()["accounts"][0]["recent_probe_tests"],
            3
        );
        conn.execute(
            "INSERT INTO gp_account_usage VALUES('fixture',?,124,0)",
            [now() / 3600],
        )
        .unwrap();
        record_test_usage(
            &conn,
            "fixture",
            "legacy-one",
            &data["measurement"],
            now(),
            3,
        )
        .unwrap();
        record_test_usage(
            &conn,
            "fixture",
            "inflight",
            &json!({"probesCount":2}),
            now(),
            2,
        )
        .unwrap();
        record_test_usage(
            &conn,
            "fixture",
            "expired",
            &json!({"probesCount":5}),
            now() - 3601,
            5,
        )
        .unwrap();
        let v = status(&s, &config).unwrap();
        assert_eq!(v["accounts"][0]["hourly_usage_used"], 124);
        assert_eq!(v["accounts"][0]["recent_probe_tests"], 5);
        assert_eq!(v["accounts"][0]["completed_tasks"], 0);
    }
    #[test]
    fn cost_counts_probe_runs_not_location_candidates_or_http_requests() {
        let locations = json!([{"country":"US"},{"country":"DE"},{"country":"SG"}]);
        assert_eq!(
            measurement_cost(&json!({"locations":locations,"limit":2})).unwrap(),
            2
        );
        assert_eq!(
            measurement_cost(&json!({"locations":locations})).unwrap(),
            1
        );
        assert_eq!(measurement_cost(&json!({"locations":[{"country":"US","limit":2},{"country":"DE","limit":3},{"country":"SG"}]})).unwrap(),6);
        for invalid in [
            json!({"locations":locations,"limit":0}),
            json!({"locations":[{"limit":2}],"limit":1}),
            json!({"locations":[{"limit":500},{"limit":1}]}),
            json!({"locations":"previous-id"}),
        ] {
            assert!(measurement_cost(&invalid).is_err());
        }
    }
}
