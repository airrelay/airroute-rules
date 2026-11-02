//! Read-only target discovery. DNS candidates and endpoint-response evidence
//! remain distinct; neither is a geographic/ownership verdict.
use crate::{
    measure::{self, ResolverConfig},
    now,
    rules::addr_num,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use hickory_proto::{
    op::ResponseCode,
    rr::{RData, RecordType},
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeSet, net::IpAddr, path::Path, time::Duration};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct Config {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub dns_per_tick: usize,
    pub atlas_page_size: usize,
    pub atlas_results_per_tick: usize,
    pub atlas_base_url: String,
    pub resolvers: Vec<ResolverConfig>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 60,
            dns_per_tick: 16,
            atlas_page_size: 100,
            atlas_results_per_tick: 4,
            atlas_base_url: "https://atlas.ripe.net/api/v2".into(),
            resolvers: vec![
                ResolverConfig {
                    name: "cloudflare-doh".into(),
                    address: "https://cloudflare-dns.com/dns-query".into(),
                    transport: "https".into(),
                },
                ResolverConfig {
                    name: "google-doh".into(),
                    address: "https://dns.google/dns-query".into(),
                    transport: "https".into(),
                },
            ],
        }
    }
}
pub fn load(root: &Path) -> Result<Config> {
    let path = root.join("config/discovery.toml");
    let config: Config = if path.exists() {
        toml::from_str(&std::fs::read_to_string(path)?)?
    } else {
        Config::default()
    };
    ensure!(
        (30..=3600).contains(&config.interval_seconds)
            && config.dns_per_tick <= 64
            && (1..=250).contains(&config.atlas_page_size)
            && config.atlas_results_per_tick <= 16
            && config.resolvers.len() <= 4,
        "invalid passive discovery budget"
    );
    ensure!(
        config.dns_per_tick == 0 || !config.resolvers.is_empty(),
        "discovery DNS needs a resolver"
    );
    let url = reqwest::Url::parse(&config.atlas_base_url)?;
    ensure!(
        url.scheme() == "https"
            || url
                .host_str()
                .is_some_and(|h| h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())),
        "Atlas API requires HTTPS"
    );
    Ok(config)
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub ip: IpAddr,
    pub source: String,
    pub kind: &'static str,
    pub observed: i64,
    pub valid_until: i64,
}
/// Preserve source time. Re-reading a public result must never refresh its age.
pub fn record(store: &Store, observations: &[Observation]) -> Result<usize> {
    let mut conn = store.connect()?;
    let n = record_on(&mut conn, observations)?;
    if n > 0 {
        store.wake.notify_waiters();
    }
    Ok(n)
}

/// Receipt ingestion combines this change count with its own single wakeup.
/// The observations and their replan markers are still committed together.
pub(crate) fn record_on(
    conn: &mut rusqlite::Connection,
    observations: &[Observation],
) -> Result<usize> {
    let tx = conn.transaction()?;
    let mut n = 0;
    for o in observations {
        let max_age = match o.kind {
            "dns-answer" => 86400,
            "endpoint-response" => 7 * 86400,
            _ => continue,
        };
        if !measure::public_ip(o.ip)
            || o.observed > now() + 60
            || o.observed < now() - max_age
            || o.valid_until <= now()
            || o.valid_until <= o.observed
            || o.source.len() > 512
        {
            continue;
        }
        let (family, address) = addr_num(o.ip);
        let saved = tx.execute("INSERT INTO target_observations VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip,source) DO UPDATE SET kind=excluded.kind,observed=excluded.observed,valid_until=excluded.valid_until WHERE excluded.observed>target_observations.observed OR (excluded.observed=target_observations.observed AND excluded.valid_until<target_observations.valid_until)", params![o.ip.to_string(),o.source,o.kind,family,format!("{address:032x}"),o.observed,o.valid_until.min(o.observed+max_age)])?;
        n += saved;
        if saved > 0 {
            tx.execute("INSERT INTO replan_cases(case_key,queued_at) SELECT DISTINCT c.key,?1 FROM case_ranges r JOIN case_metadata c ON c.key=r.case_key AND c.fp=r.fp WHERE r.family=?2 AND r.start<=?3 AND r.end>=?3 AND c.active=1 AND c.status='blocked-target' ON CONFLICT(case_key) DO NOTHING", params![now(),family,format!("{address:032x}")])?;
        }
    }
    tx.commit()?;
    Ok(n)
}
fn disputed(store: &Store, ip: IpAddr) -> Result<bool> {
    let (f, n) = addr_num(ip);
    Ok(store.connect()?.query_row("SELECT EXISTS(SELECT 1 FROM case_ranges r JOIN cases c ON c.key=r.case_key AND c.fp=r.fp WHERE r.family=? AND r.start<=? AND r.end>=? AND c.active=1 AND c.status='blocked-target' AND coalesce(json_extract(c.payload,'$.measurement_required'),1)=1)", params![f,format!("{n:032x}"),format!("{n:032x}")], |r|r.get(0))?)
}
fn checked(store: &Store, kind: &str, key: &str, next: i64, error: Option<&str>) -> Result<()> {
    store.connect()?.execute("INSERT INTO discovery_checks VALUES(?,?,?,?,?) ON CONFLICT(kind,key) DO UPDATE SET checked=excluded.checked,next_check=excluded.next_check,error=excluded.error",params![kind,key,now(),next,error.map(|s|s.chars().take(240).collect::<String>())])?;
    Ok(())
}

fn answer_chain(host: Option<&str>, records: &[Value], data_key: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let Some(host) = host.and_then(|h| crate::rules::ascii_domain(h.trim_end_matches('.')).ok())
    else {
        return names;
    };
    names.insert(host);
    for _ in 0..8 {
        let mut added = false;
        for row in records {
            if row["type"] != "CNAME" {
                continue;
            }
            let Some(owner) = row["name"]
                .as_str()
                .map(|s| s.trim_end_matches('.').to_ascii_lowercase())
            else {
                continue;
            };
            if !names.contains(&owner) {
                continue;
            }
            if let Some(next) = row[data_key]
                .as_str()
                .and_then(|s| crate::rules::ascii_domain(s.trim_end_matches('.')).ok())
            {
                added |= names.insert(next);
            }
        }
        if !added {
            break;
        }
    }
    names
}
fn answer_owner_in_chain(row: &Value, names: &BTreeSet<String>) -> bool {
    row["name"]
        .as_str()
        .is_some_and(|s| names.contains(&s.trim_end_matches('.').to_ascii_lowercase()))
}
pub fn receipt_observations(id: &str, at: i64, evidence: &Value) -> Vec<Observation> {
    let mut out = vec![];
    let mut response = |value: &Value| {
        if let Some(ip) = value.as_str().and_then(|s| s.parse().ok()) {
            out.push(Observation {
                ip,
                source: format!("receipt:{id}"),
                kind: "endpoint-response",
                observed: at,
                valid_until: at.saturating_add(7 * 86400),
            });
        }
    };
    if evidence["reached"] == true {
        response(&evidence["target"]);
    }
    for tls in evidence["tls"].as_array().into_iter().flatten() {
        if tls["certificate_valid"] == true {
            response(&tls["ip"]);
        }
    }
    let measurement = &evidence["measurement"];
    for item in measurement["results"].as_array().into_iter().flatten() {
        let result = &item["result"];
        if result["status"] != "finished" {
            continue;
        }
        if measurement["type"] != "traceroute" {
            continue;
        }
        if let Some(ip) = result["resolvedAddress"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
        {
            let reached = result["hops"].as_array().is_some_and(|hops| {
                hops.iter().any(|hop| {
                    hop["resolvedAddress"]
                        .as_str()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        == Some(ip)
                        && hop["timings"].as_array().is_some_and(|times| {
                            times
                                .iter()
                                .any(|t| t["rtt"].as_f64().is_some_and(|v| v >= 0.0))
                        })
                })
            });
            if reached {
                response(&result["resolvedAddress"]);
            }
        }
    }
    // Old probe receipts lack absolute DNS expiry. Subtract the entire 120s
    // execution budget so importing them cannot restart a record's TTL.
    for (i, resolver) in evidence["resolvers"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        // One qualified query does not authorize records from another failed
        // question on this resolver (including a same-type CNAME follow-up).
        let records = measure::successful_dns_records(resolver, None);
        if records.is_empty() {
            continue;
        }
        let names = answer_chain(evidence["hostname"].as_str(), &records, "data");
        let ttl = records
            .iter()
            .filter(|r| answer_owner_in_chain(r, &names))
            .filter_map(|r| r["ttl"].as_u64())
            .min()
            .unwrap_or(0)
            .min(86400) as i64;
        let absolute = resolver["valid_until"].as_i64();
        let start = resolver["observed_at"]
            .as_i64()
            .unwrap_or(at)
            .min(at)
            .saturating_sub(if absolute.is_some() { 0 } else { 120 });
        for r in &records {
            if !matches!(r["type"].as_str(), Some("A" | "AAAA"))
                || !answer_owner_in_chain(r, &names)
            {
                continue;
            }
            if let Some(ip) = r["data"].as_str().and_then(|s| s.parse().ok()) {
                out.push(Observation {
                    ip,
                    source: format!("receipt:{id}:dns:{i}"),
                    kind: "dns-answer",
                    observed: start,
                    valid_until: absolute
                        .unwrap_or(start.saturating_add(ttl))
                        .min(start.saturating_add(ttl)),
                });
            }
        }
    }
    for (i, item) in measurement["results"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let r = &item["result"];
        if measurement["type"] != "dns" || r["status"] != "finished" || r["statusCode"] != 0 {
            continue;
        }
        let Some(records) = r["answers"].as_array() else {
            continue;
        };
        let names = answer_chain(measurement["target"].as_str(), records, "value");
        let ttl = records
            .iter()
            .filter(|r| answer_owner_in_chain(r, &names))
            .filter_map(|r| r["ttl"].as_u64())
            .min()
            .unwrap_or(0)
            .min(86400) as i64;
        for r in records {
            if !matches!(r["type"].as_str(), Some("A" | "AAAA"))
                || !answer_owner_in_chain(r, &names)
            {
                continue;
            }
            if let Some(ip) = r["value"].as_str().and_then(|s| s.parse().ok()) {
                out.push(Observation {
                    ip,
                    source: format!("receipt:{id}:gp-dns:{i}"),
                    kind: "dns-answer",
                    observed: at,
                    valid_until: at.saturating_add(ttl),
                });
            }
        }
    }
    out
}
fn import_receipts(store: &Store) -> Result<usize> {
    let conn = store.connect()?;
    // A late receipt can still prove a candidate. Its acceptance controls the
    // old job, not recovery of the independently qualified observation.
    let mut stmt = conn.prepare("SELECT r.id,r.observed,r.evidence FROM results r LEFT JOIN discovery_receipts d ON d.result_id=r.id WHERE r.qualified=1 AND r.outcome='ok' AND r.observed>? AND d.result_id IS NULL ORDER BY r.received,r.id LIMIT 128")?;
    let rows = stmt
        .query_map([now() - 7 * 86400], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut count = 0;
    for (id, at, evidence) in rows {
        let evidence: Value = serde_json::from_str(&evidence)?;
        count += record(store, &receipt_observations(&id, at, &evidence))?;
        conn.execute("INSERT OR IGNORE INTO discovery_receipts VALUES(?)", [id])?;
    }
    Ok(count)
}

async fn dns_host(store: &Store, config: &Config, host: &str) -> Result<usize> {
    checked(store, "dns", host, now() + 300, Some("in-progress"))?;
    let mut observations = vec![];
    let mut errors = vec![];
    let mut next = now() + 3600;
    let mut received = false;
    for resolver in &config.resolvers {
        for rr in [RecordType::A, RecordType::AAAA] {
            match measure::dns(resolver, host, rr).await {
                Ok(message) => {
                    let at = now();
                    if message.metadata.response_code != ResponseCode::NoError
                        && message.metadata.response_code != ResponseCode::NXDomain
                    {
                        errors.push("resolver error response".to_string());
                        continue;
                    }
                    received = true;
                    // Only A/AAAA belonging to the query's bounded CNAME chain.
                    let mut names = BTreeSet::from([host.to_string()]);
                    for _ in 0..8 {
                        let len = names.len();
                        for r in &message.answers {
                            let owner = r.name.to_ascii().trim_end_matches('.').to_lowercase();
                            if names.contains(&owner)
                                && let RData::CNAME(alias) = &r.data
                            {
                                names.insert(
                                    alias.0.to_ascii().trim_end_matches('.').to_lowercase(),
                                );
                            }
                        }
                        if len == names.len() {
                            break;
                        }
                    }
                    let ttl = message
                        .answers
                        .iter()
                        .filter(|r| {
                            names.contains(&r.name.to_ascii().trim_end_matches('.').to_lowercase())
                        })
                        .map(|r| r.ttl)
                        .min()
                        .unwrap_or(0)
                        .min(86400);
                    if ttl == 0 {
                        continue;
                    }
                    next = next.min(at + i64::from(ttl));
                    for r in message.answers {
                        if !names.contains(&r.name.to_ascii().trim_end_matches('.').to_lowercase())
                        {
                            continue;
                        }
                        let ip = match r.data {
                            RData::A(a) => IpAddr::V4(a.0),
                            RData::AAAA(a) => IpAddr::V6(a.0),
                            _ => continue,
                        };
                        observations.push(Observation {
                            ip,
                            source: format!("dns:{}:{host}", resolver.name),
                            kind: "dns-answer",
                            observed: at,
                            valid_until: at + i64::from(ttl),
                        });
                    }
                }
                Err(e) => errors.push(e.to_string()),
            }
        }
    }
    let n = record(store, &observations)?;
    checked(
        store,
        "dns",
        host,
        if received {
            next.max(now() + 60)
        } else {
            now() + 300
        },
        errors.first().map(String::as_str),
    )?;
    Ok(n)
}

async fn get(client: &reqwest::Client, url: reqwest::Url, store: &Store) -> Result<Value> {
    let mut response = client.get(url).send().await?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let wait = response
            .headers()
            .get("retry-after")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| {
                response
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| chrono::DateTime::parse_from_rfc2822(s).ok())
                    .map(|t| t.timestamp() - now())
            })
            .unwrap_or(900)
            .clamp(60, 86400);
        store.set_meta("discovery-atlas-after", &(now() + wait).to_string())?;
    }
    response = response.error_for_status()?;
    ensure!(
        response.content_length().unwrap_or(0) <= 2_000_000,
        "Atlas response too large"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len() + chunk.len() <= 2_000_000,
            "Atlas response too large"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}
/// Latest can be a result array or an object keyed by probe id, depending on API version.
pub fn atlas_observations(value: &Value, measurement: u64) -> Vec<Observation> {
    let rows: Vec<&Value> = if let Some(rows) = value.as_array() {
        rows.iter().collect()
    } else {
        value
            .as_object()
            .into_iter()
            .flat_map(|m| m.values())
            .filter_map(Value::as_array)
            .flatten()
            .collect()
    };
    rows.into_iter()
        .filter_map(|r| {
            if r["msm_id"].as_u64()? != measurement {
                return None;
            }
            let ip: IpAddr = r["dst_addr"].as_str()?.parse().ok()?;
            let at = r["timestamp"].as_i64()?;
            let reached = match r["type"].as_str()? {
                "ping" => r["result"].as_array().is_some_and(|rows| {
                    rows.iter().any(|v| {
                        v["rtt"]
                            .as_f64()
                            .is_some_and(|rtt| rtt.is_finite() && rtt >= 0.0)
                    })
                }),
                "traceroute" => r["result"].as_array().is_some_and(|hops| {
                    hops.iter()
                        .flat_map(|h| h["result"].as_array().into_iter().flatten())
                        .any(|hop| {
                            hop["from"].as_str().and_then(|v| v.parse::<IpAddr>().ok()) == Some(ip)
                                && hop["rtt"].as_f64().is_some_and(|v| v >= 0.0)
                                && hop["err"].is_null()
                        })
                }),
                _ => false,
            };
            reached.then(|| Observation {
                ip,
                source: format!("atlas:{measurement}:{}", r["prb_id"].as_u64().unwrap_or(0)),
                kind: "endpoint-response",
                observed: at,
                valid_until: at.saturating_add(7 * 86400),
            })
        })
        .collect()
}
async fn atlas_result(
    store: &Store,
    config: &Config,
    client: &reqwest::Client,
    id: u64,
) -> Result<usize> {
    checked(
        store,
        "atlas",
        &id.to_string(),
        now() + 300,
        Some("in-progress"),
    )?;
    let base = config.atlas_base_url.trim_end_matches('/');
    let mut url = reqwest::Url::parse(&format!("{base}/measurements/{id}/"))?;
    url.query_pairs_mut()
        .append_pair("fields", "id,target_ip,type,probes")
        .append_pair("optional_fields", "probes");
    let metadata = get(client, url, store).await?;
    ensure!(
        metadata["id"].as_u64() == Some(id),
        "Atlas measurement id mismatch"
    );
    let probes = metadata["probes"]
        .as_array()
        .context("Atlas probe list missing")?;
    let mut ids = BTreeSet::new();
    let sample = 8.min(probes.len());
    for i in 0..sample {
        let index = if sample == 1 {
            0
        } else {
            i * (probes.len() - 1) / (sample - 1)
        };
        if let Some(p) = probes[index]["id"].as_u64() {
            ids.insert(p);
        }
    }
    if ids.is_empty() {
        checked(store, "atlas", &id.to_string(), now() + 3600, None)?;
        return Ok(0);
    }
    let mut url = reqwest::Url::parse(&format!("{base}/measurements/{id}/latest/"))?;
    url.query_pairs_mut().append_pair(
        "probe_ids",
        &ids.iter().map(u64::to_string).collect::<Vec<_>>().join(","),
    );
    let result = get(client, url, store).await?;
    let observations = atlas_observations(&result, id);
    let fresh = observations
        .iter()
        .any(|o| o.valid_until > now() && o.observed <= now() + 60 && measure::public_ip(o.ip));
    let n = record(store, &observations)?;
    checked(
        store,
        "atlas",
        &id.to_string(),
        now() + if fresh { 86400 } else { 3600 },
        None,
    )?;
    Ok(n)
}
async fn atlas_catalog(store: &Store, config: &Config, client: &reqwest::Client) -> Result<usize> {
    let cursor = store
        .meta("discovery-atlas-cursor")?
        .and_then(|v| v.parse::<u64>().ok());
    let mut url = reqwest::Url::parse(&format!(
        "{}/measurements/",
        config.atlas_base_url.trim_end_matches('/')
    ))?;
    url.query_pairs_mut()
        .append_pair("status", "2")
        .append_pair("type", "ping")
        .append_pair("sort", "-id")
        .append_pair("page_size", &config.atlas_page_size.to_string())
        .append_pair("fields", "id,target_ip,type");
    if let Some(id) = cursor {
        url.query_pairs_mut().append_pair("id__lt", &id.to_string());
    }
    let value = get(client, url, store).await?;
    let rows = value["results"]
        .as_array()
        .context("Atlas catalog missing results")?;
    ensure!(
        rows.len() <= config.atlas_page_size,
        "Atlas catalog exceeded page budget"
    );
    if rows.is_empty() {
        store
            .connect()?
            .execute("DELETE FROM meta WHERE key='discovery-atlas-cursor'", [])?;
        store.set_meta(
            "discovery-atlas-catalog-after",
            &(now() + 86400).to_string(),
        )?;
        return Ok(0);
    }
    let mut lowest = u64::MAX;
    let mut seen = 0;
    let mut conn = store.connect()?;
    let tx = conn.transaction()?;
    for row in rows {
        let id = row["id"]
            .as_u64()
            .context("Atlas catalog missing measurement id")?;
        ensure!(
            cursor.is_none_or(|c| id < c),
            "Atlas ignored catalog cursor"
        );
        lowest = lowest.min(id);
        if let Some(ip) = row["target_ip"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
            && measure::public_ip(ip)
            && disputed(store, ip)?
        {
            seen += tx.execute(
                "INSERT OR IGNORE INTO discovery_checks VALUES('atlas',?,0,0,NULL)",
                [id.to_string()],
            )?;
        }
    }
    tx.execute("INSERT INTO meta VALUES('discovery-atlas-cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[lowest.to_string()])?;
    tx.commit()?;
    Ok(seen)
}

/// A bounded tick is restart-safe; scheduler/QUIC do not wait for its network I/O.
pub async fn tick(store: &Store, config: &Config) -> Result<Value> {
    if !config.enabled {
        return Ok(json!({"enabled":false}));
    }
    let _lock = match crate::FileLock::try_new(std::fs::File::create(
        store.path.with_extension("discovery.lock"),
    )?) {
        Ok(lock) => lock,
        Err(std::fs::TryLockError::WouldBlock) => return Ok(json!({"busy":true})),
        Err(e) => return Err(e.into()),
    };
    let mut errors = vec![];
    // Bounded indexed cleanup belongs to the background tick, not every receipt.
    store.connect()?.execute("DELETE FROM target_observations WHERE rowid IN (SELECT rowid FROM target_observations WHERE valid_until<=? ORDER BY valid_until LIMIT 256)", [now()])?;
    let mut imported = import_receipts(store)?;
    let waiting:bool=store.connect()?.query_row("SELECT EXISTS(SELECT 1 FROM cases WHERE active=1 AND status='blocked-target' AND json_extract(payload,'$.family') IN (4,6))",[],|r|r.get(0))?;
    if !waiting {
        let report = json!({"enabled":true,"updated":now(),"dns_hosts":0,"observations_saved":imported,"jobs_created":0,"idle":true,"errors":[]});
        store.set_meta("discovery-status", &report.to_string())?;
        return Ok(report);
    }
    let mut catalog = 0;
    let dns = {
        let conn = store.connect()?;
        let owned:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM nodes WHERE connected=1 AND disabled=0 AND id NOT LIKE 'globalping:%' AND last_seen>?)",[now()-120],|r|r.get(0))?;
        let mut names = vec![];
        if !owned {
            let start = store
                .meta("discovery-dns-bucket")?
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0)
                % 2;
            let mut pools = [Vec::new(), Vec::new()];
            for (bucket, pool) in pools.iter_mut().enumerate() {
                let mut q=conn.prepare("SELECT h.host FROM discovery_domains h LEFT JOIN discovery_checks d ON d.kind='dns' AND d.key=h.host WHERE h.bucket=? AND coalesce(d.next_check,0)<=? ORDER BY coalesce(d.checked,0),h.host LIMIT ?")?;
                *pool = q
                    .query_map(
                        params![bucket as i64, now(), config.dns_per_tick as i64],
                        |r| r.get::<_, String>(0),
                    )?
                    .collect::<std::result::Result<Vec<_>, _>>()?;
            }
            let mut indexes = [0usize; 2];
            for turn in 0..config.dns_per_tick {
                let preferred = (start + turn) % 2;
                let bucket = if indexes[preferred] < pools[preferred].len() {
                    preferred
                } else {
                    1 - preferred
                };
                let Some(host) = pools[bucket].get(indexes[bucket]) else {
                    break;
                };
                indexes[bucket] += 1;
                names.push(host.clone());
            }
            store.set_meta("discovery-dns-bucket", &(1 - start).to_string())?;
        }
        names
    };
    let mut workers: tokio::task::JoinSet<Result<usize>> = tokio::task::JoinSet::new();
    for host in &dns {
        if workers.len() >= 4 {
            match workers.join_next().await {
                Some(Ok(Ok(n))) => imported += n,
                Some(Ok(Err(e))) => errors.push(e.to_string()),
                Some(Err(e)) => errors.push(e.to_string()),
                _ => {}
            }
        }
        let (store, config, host) = (store.clone(), config.clone(), host.clone());
        workers.spawn(async move { dns_host(&store, &config, &host).await });
    }
    while let Some(result) = workers.join_next().await {
        match result {
            Ok(Ok(n)) => imported += n,
            Ok(Err(e)) => errors.push(e.to_string()),
            Err(e) => errors.push(e.to_string()),
        }
    }
    if config.atlas_results_per_tick > 0
        && store
            .meta("discovery-atlas-after")?
            .and_then(|v| v.parse::<i64>().ok())
            .is_none_or(|until| until <= now())
    {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(20))
            .user_agent("AirRoute-Rules/0.2 passive-target-discovery")
            .build()?;
        if store
            .meta("discovery-atlas-catalog-after")?
            .and_then(|v| v.parse::<i64>().ok())
            .is_none_or(|until| until <= now())
        {
            match atlas_catalog(store, config, &client).await {
                Ok(n) => catalog = n,
                Err(e) => {
                    errors.push(e.to_string());
                    store.set_meta("discovery-atlas-catalog-after", &(now() + 900).to_string())?;
                }
            }
        }
        let ids = {
            let conn = store.connect()?;
            let mut s = conn.prepare("SELECT key FROM discovery_checks WHERE kind='atlas' AND next_check<=? ORDER BY checked,key LIMIT ?")?;
            s.query_map(params![now(), config.atlas_results_per_tick as i64], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for key in ids {
            if store
                .meta("discovery-atlas-after")?
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|v| v > now())
            {
                break;
            }
            match atlas_result(store, config, &client, key.parse()?).await {
                Ok(n) => imported += n,
                Err(e) => {
                    checked(store, "atlas", &key, now() + 900, Some(&e.to_string()))?;
                    errors.push(e.to_string());
                }
            }
        }
    }
    let jobs = crate::scheduler::discover_targets(store)?;
    let report = json!({"enabled":true,"updated":now(),"dns_hosts":dns.len(),"atlas_measurements_queued":catalog,"observations_saved":imported,"jobs_created":jobs,"errors":errors});
    store.set_meta("discovery-status", &report.to_string())?;
    Ok(report)
}

pub fn status(store: &Store) -> Result<Value> {
    let conn = store.connect()?;
    let mut stmt = conn.prepare(
        "SELECT kind,count(DISTINCT ip) FROM target_observations WHERE valid_until>? GROUP BY kind",
    )?;
    let mut kinds = serde_json::Map::new();
    for r in stmt.query_map([now()], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })? {
        let (k, n) = r?;
        kinds.insert(k, json!(n));
    }
    let last = store
        .meta("discovery-status")?
        .map(|v| serde_json::from_str::<Value>(&v))
        .transpose()?;
    let errors: i64 = conn.query_row(
        "SELECT count(*) FROM discovery_checks WHERE error IS NOT NULL AND error<>'in-progress'",
        [],
        |r| r.get(0),
    )?;
    Ok(json!({"candidates":kinds,"last":last,"source_errors":errors}))
}
