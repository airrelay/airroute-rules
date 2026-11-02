use crate::{
    fingerprint, now,
    store::{Lease, ProbeResult, Store},
};
use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RData, RecordType},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolverConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "udp")]
    pub transport: String,
}
fn udp() -> String {
    "udp".into()
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub controller: String,
    pub id: String,
    pub token_env: String,
    #[serde(default)]
    pub resolvers: Vec<ResolverConfig>,
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default = "yes")]
    pub tls: bool,
    pub ca_cert: PathBuf,
    #[serde(default = "server_name")]
    pub server_name: String,
    #[serde(default = "spool_dir")]
    pub data_dir: PathBuf,
}
fn yes() -> bool {
    true
}
fn server_name() -> String {
    crate::transport::SERVER_NAME.into()
}
fn spool_dir() -> PathBuf {
    "probe-data".into()
}

pub(crate) fn dns_response_code(code: &Value) -> Option<u16> {
    if let Some(number) = code["code"].as_u64() {
        return u16::try_from(number).ok();
    }
    let text = code.as_str().or_else(|| code["response_code"].as_str())?;
    match text.to_ascii_lowercase().as_str() {
        "noerror" | "no error" => Some(0),
        "nxdomain" | "non-existent domain" => Some(3),
        "servfail" | "server failure" => Some(2),
        "refused" | "query refused" => Some(5),
        _ => None,
    }
}

/// A successful question only authorizes its own answer section. Record owner
/// names can differ after CNAMEs, so they cannot stand in for the queried name.
/// Keep old unambiguous receipts usable without inventing missing context.
pub(crate) fn successful_dns_records(resolver: &Value, expected: Option<&str>) -> Vec<Value> {
    if resolver["response_received"] == false {
        return vec![];
    }
    let Some(records) = resolver["records"].as_array() else {
        return vec![];
    };
    let codes = resolver["rcodes"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let errors = resolver["errors"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let all_success = codes.iter().all(|code| dns_response_code(code) == Some(0));
    records
        .iter()
        .filter(|record| {
            let kind = record["query_type"].as_str();
            if expected
                .is_some_and(|wanted| kind.is_none_or(|kind| !kind.eq_ignore_ascii_case(wanted)))
            {
                return false;
            }
            let question = record["query_name"].as_str();
            if question.is_none() && errors.is_empty() && (codes.is_empty() || all_success) {
                return true;
            }
            // An untyped failure cannot be assigned to another question safely.
            if codes.iter().any(|code| {
                code["query_type"].as_str().is_none() && dns_response_code(code) != Some(0)
            }) {
                return false;
            }
            let Some(kind) = kind else {
                return false;
            };
            if errors.iter().any(|error| {
                error["query_type"]
                    .as_str()
                    .is_none_or(|actual| actual.eq_ignore_ascii_case(kind))
                    && question.is_none_or(|name| {
                        error["name"].as_str().is_none_or(|actual| {
                            actual
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(name.trim_end_matches('.'))
                        })
                    })
            }) {
                return false;
            }
            let mut matched = false;
            for code in codes.iter().filter(|code| {
                code["query_type"]
                    .as_str()
                    .is_some_and(|actual| actual.eq_ignore_ascii_case(kind))
                    && question.is_none_or(|name| {
                        code["name"].as_str().is_some_and(|actual| {
                            actual
                                .trim_end_matches('.')
                                .eq_ignore_ascii_case(name.trim_end_matches('.'))
                        })
                    })
            }) {
                matched = true;
                if dns_response_code(code) != Some(0) {
                    return false;
                }
            }
            matched
        })
        .cloned()
        .collect()
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let n = u32::from(a);
            let block = [
                ("0.0.0.0/8"),
                ("10.0.0.0/8"),
                ("100.64.0.0/10"),
                ("127.0.0.0/8"),
                ("169.254.0.0/16"),
                ("172.16.0.0/12"),
                ("192.168.0.0/16"),
                ("192.0.0.0/24"),
                ("192.0.2.0/24"),
                ("198.18.0.0/15"),
                ("198.51.100.0/24"),
                ("203.0.113.0/24"),
                ("224.0.0.0/4"),
                ("240.0.0.0/4"),
            ];
            n != u32::MAX
                && !block.iter().any(|n| {
                    n.parse::<ipnet::IpNet>()
                        .expect("constant network")
                        .contains(&ip)
                })
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return public_ip(v4.into());
            }
            a.segments()[0] & 0xe000 == 0x2000
                && !"2001:db8::/32"
                    .parse::<ipnet::IpNet>()
                    .expect("constant network")
                    .contains(&ip)
        }
    }
}
fn system_resolver() -> Result<ResolverConfig> {
    let text = std::fs::read_to_string("/etc/resolv.conf")?;
    for l in text.lines() {
        let v: Vec<_> = l.split_whitespace().collect();
        if v.first() == Some(&"nameserver") && v.len() > 1 {
            let ip: IpAddr = v[1].parse()?;
            return Ok(ResolverConfig {
                name: "system".into(),
                address: SocketAddr::new(ip, 53).to_string(),
                transport: "udp".into(),
            });
        }
    }
    bail!("system resolver missing; configure an explicit resolver")
}
async fn tcp_dns(address: SocketAddr, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_u16(bytes.len().try_into()?).await?;
    stream.write_all(bytes).await?;
    let len = stream.read_u16().await?;
    let mut response = vec![0; len as usize];
    stream.read_exact(&mut response).await?;
    Ok(response)
}
pub(crate) async fn dns(
    resolver: &ResolverConfig,
    host: &str,
    kind: RecordType,
) -> Result<Message> {
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request
        .queries
        .push(Query::query(Name::from_ascii(format!("{host}."))?, kind));
    let bytes = request.to_vec()?;
    let run = async {
        let response = match resolver.transport.as_str() {
            "udp" => {
                let addr: SocketAddr = resolver.address.parse()?;
                let socket = UdpSocket::bind(if addr.ip().is_loopback() && addr.is_ipv4() {
                    "127.0.0.1:0"
                } else if addr.ip().is_loopback() {
                    "[::1]:0"
                } else if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                })
                .await
                .context("bind DNS UDP socket")?;
                socket
                    .connect(addr)
                    .await
                    .context("connect DNS UDP socket")?;
                socket.send(&bytes).await.context("send DNS UDP query")?;
                let mut buf = vec![0u8; 65535];
                let n = socket.recv(&mut buf).await?;
                buf.truncate(n);
                let response = Message::from_vec(&buf)?;
                if response.metadata.truncation {
                    tcp_dns(addr, &bytes).await?
                } else {
                    buf
                }
            }
            "tcp" => tcp_dns(resolver.address.parse()?, &bytes).await?,
            "https" => {
                let url = reqwest::Url::parse(&resolver.address)?;
                ensure!(url.scheme() == "https", "DoH requires HTTPS");
                let response = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(8))
                    .redirect(reqwest::redirect::Policy::none())
                    .build()?
                    .post(url)
                    .header("Content-Type", "application/dns-message")
                    .header("Accept", "application/dns-message")
                    .body(bytes.clone())
                    .send()
                    .await?
                    .error_for_status()?;
                ensure!(
                    response.content_length().unwrap_or(0) <= 65535,
                    "DNS response oversized"
                );
                let b = response.bytes().await?;
                ensure!(b.len() <= 65535, "DNS response oversized");
                b.to_vec()
            }
            _ => bail!("unsupported resolver transport"),
        };
        let response = Message::from_vec(&response)?;
        ensure!(
            response.metadata.id == request.metadata.id
                && response.metadata.message_type == MessageType::Response
                && response.queries == request.queries,
            "DNS transaction mismatch"
        );
        Ok::<_, anyhow::Error>(response)
    };
    tokio::time::timeout(Duration::from_secs(10), run).await?
}
fn dns_method(
    config: &ProbeConfig,
    lease: &Lease,
) -> Result<(Vec<ResolverConfig>, Vec<RecordType>)> {
    let mut resolvers = if config.resolvers.is_empty() {
        vec![system_resolver()?]
    } else {
        config.resolvers.clone()
    };
    ensure!(resolvers.len() <= 4, "at most four resolvers per node");
    if let Some(protocol) = lease.profile["protocol"].as_str() {
        let protocol = protocol.to_ascii_lowercase();
        let protocol = if protocol == "doh" {
            "https"
        } else {
            protocol.as_str()
        };
        ensure!(
            matches!(protocol, "udp" | "tcp" | "https"),
            "unsupported DNS transport"
        );
        resolvers.retain_mut(|resolver| {
            if matches!(protocol, "udp" | "tcp")
                && matches!(resolver.transport.as_str(), "udp" | "tcp")
            {
                resolver.transport = protocol.into();
            }
            resolver.transport == protocol
        });
        ensure!(
            !resolvers.is_empty(),
            "no configured resolver supports the requested DNS transport"
        );
    }
    let types = if let Some(kind) = lease.profile["query"]["type"]
        .as_str()
        .or_else(|| lease.profile["query_type"].as_str())
    {
        vec![
            kind.to_ascii_uppercase()
                .parse::<RecordType>()
                .context("unsupported DNS query type")?,
        ]
    } else {
        vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::HTTPS,
            RecordType::SVCB,
        ]
    };
    Ok((resolvers, types))
}
pub async fn domain(config: &ProbeConfig, lease: &Lease, cache: &Store) -> Result<Value> {
    let host = crate::rules::ascii_domain(&lease.target)?;
    ensure!(
        host.contains('.') && !host.contains('*'),
        "exact hostname required"
    );
    let (resolvers, types) = dns_method(config, lease)?;
    let query_types: Vec<String> = types.iter().map(ToString::to_string).collect();
    let mut observations = vec![];
    let mut addresses = BTreeSet::new();
    let mut success = false;
    for resolver in &resolvers {
        let key = fingerprint(&json!([
            "dns-answer-v3",
            config.id,
            lease.profile["observer"],
            lease.profile["epoch"],
            "adaptive-v2",
            host,
            resolver,
            query_types
        ]));
        if let Some(mut answer) = cache.cache_get(&key)? {
            answer["cache_hit"] = json!(true);
            // Older cache entries may contain aggregate addresses from a failed
            // auxiliary question. Reuse only the actual successful answer view.
            addresses.extend(
                successful_dns_records(&answer, None)
                    .iter()
                    .filter(|record| matches!(record["type"].as_str(), Some("A" | "AAAA")))
                    .filter_map(|record| record["data"].as_str()?.parse::<IpAddr>().ok()),
            );
            success |= answer["response_received"].as_bool().unwrap_or(false);
            observations.push(answer);
            continue;
        }
        let mut records = vec![];
        let mut errors = vec![];
        let mut ttl = u32::MAX;
        let mut valid_until = i64::MAX;
        let mut ads = vec![];
        let mut rcodes = vec![];
        let mut cacheable = true;
        let mut ips = BTreeSet::new();
        let mut responded = false;
        // Follow a bounded CNAME chain. CNAMEs are observations, never ownership edges.
        let mut pending = vec![host.clone()];
        let mut seen = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !seen.insert(name.clone()) || seen.len() > 8 {
                continue;
            }
            for &kind in &types {
                let start = Instant::now();
                match dns(resolver,&name,kind).await {
                    Ok(response)=>{let received_at=now();responded=true;cacheable &= response.metadata.response_code == hickory_proto::op::ResponseCode::NoError;rcodes.push(json!({"name":name,"query_type":kind.to_string(),"code":u16::from(response.metadata.response_code),"response_code":response.metadata.response_code.to_string(),"observed_at":received_at}));ads.push(response.metadata.authentic_data);
                        for r in &response.answers {records.push(json!({"name":r.name.to_ascii(),"type":r.record_type().to_string(),"ttl":r.ttl,"data":r.data.to_string(),"query_name":name,"query_type":kind.to_string(),"elapsed_ms":start.elapsed().as_millis()}));
                            if response.metadata.response_code != hickory_proto::op::ResponseCode::NoError {continue;}
                            ttl=ttl.min(r.ttl);valid_until=valid_until.min(received_at+r.ttl.min(86400) as i64);
                            match &r.data {RData::A(a)=>{ips.insert(IpAddr::V4(a.0));},RData::AAAA(a)=>{ips.insert(IpAddr::V6(a.0));},RData::CNAME(c)=>{let c=c.0.to_ascii().trim_end_matches('.').to_lowercase();if !seen.contains(&c){pending.push(c);}},_=>{}}
                        }
                    },Err(error)=>errors.push(json!({"query_type":kind.to_string(),"name":name,"error":format!("{error:#}")})),
                }
            }
        }
        let answer = json!({"resolver":resolver.name,"address":resolver.address,"transport":resolver.transport,"response_received":responded,"records":records,"addresses":ips,"rcodes":rcodes,"ad_flags":ads,"dnssec":"resolver-ad-observed; no independent chain validation","errors":errors,"cache_hit":false,"observed_at":now(),"valid_until":if valid_until==i64::MAX{now()}else{valid_until},"ttl":if ttl==u32::MAX{0}else{ttl}});
        if responded
            && cacheable
            && errors.is_empty()
            && ttl > 0
            && ttl < u32::MAX
            && valid_until > now()
        {
            cache.cache_put(&key, valid_until, &answer)?;
        }
        addresses.extend(ips);
        success |= responded;
        observations.push(answer);
    }
    ensure!(
        success,
        "all configured DNS observations failed: {}",
        serde_json::to_string(&observations)?
    );
    let mut tls = vec![];
    if config.tls {
        for ip in addresses
            .iter()
            .copied()
            .filter(|ip| {
                (config.allow_private_targets || public_ip(*ip))
                    && (if ip.is_ipv4() {
                        !matches!(lease.profile["network_support"]["ipv4"], Value::Bool(false))
                            && lease.profile["network_support"]["ipv4"] != 0
                    } else {
                        !matches!(lease.profile["network_support"]["ipv6"], Value::Bool(false))
                            && lease.profile["network_support"]["ipv6"] != 0
                    })
            })
            .take(3)
        {
            let start = Instant::now();
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(8))
                .resolve(&host, SocketAddr::new(ip, 443))
                .build()?;
            match client.head(format!("https://{host}/")).send().await{Ok(r)=>tls.push(json!({"ip":ip,"sni":host,"certificate_valid":true,"http_status":r.status().as_u16(),"elapsed_ms":start.elapsed().as_millis()})),Err(e)=>tls.push(json!({"ip":ip,"sni":host,"error":e.to_string()}))}
        }
    }
    Ok(
        json!({"kind":"dns","hostname":host,"resolvers":observations,"tls":tls,"private_answers":addresses.iter().filter(|ip|!public_ip(**ip)).collect::<Vec<_>>(),"interpretation":"DNS/CDN differences, NXDOMAIN, 403 or an unresponsive endpoint do not decide service ownership or geographic membership"}),
    )
}
async fn trace(config: &ProbeConfig, lease: &Lease) -> Result<Value> {
    let target: IpAddr = lease.target.parse()?;
    ensure!(
        config.allow_private_targets || public_ip(target),
        "non-public measurement target"
    );
    let max = lease.profile["max_hops"]
        .as_u64()
        .unwrap_or(24)
        .clamp(1, 24);
    let mut cmd = tokio::process::Command::new(if target.is_ipv6() && cfg!(target_os = "macos") {
        "traceroute6"
    } else {
        "traceroute"
    });
    cmd.kill_on_drop(true)
        .args(["-n", "-m", &max.to_string(), "-q", "1", "-w", "1"]);
    if !cfg!(target_os = "macos") {
        cmd.arg(if target.is_ipv4() { "-4" } else { "-6" });
    }
    if target.is_ipv4() || !cfg!(target_os = "macos") {
        cmd.arg("-I");
    }
    cmd.arg(target.to_string());
    let output = tokio::time::timeout(Duration::from_secs(40), cmd.output())
        .await
        .context("traceroute deadline")??;
    ensure!(
        output.stdout.len() + output.stderr.len() <= 128 * 1024,
        "trace output oversized"
    );
    ensure!(
        output.status.success(),
        "traceroute failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    let hops: Vec<_> = text
        .lines()
        .filter_map(|l| {
            let fields: Vec<_> = l.split_whitespace().collect();
            let hop = fields.first()?.parse::<u8>().ok()?;
            let ip = fields.iter().skip(1).find_map(|s| s.parse::<IpAddr>().ok());
            Some(json!({"hop":hop,"ip":ip,"raw":l}))
        })
        .collect();
    let reached = hops.iter().any(|r| r["ip"] == target.to_string());
    Ok(
        json!({"kind":"traceroute","target":target,"protocol":"icmp","reached":reached,"hops":hops,"raw":text,"scope":"one destination from one network at one time; not parent-prefix physical location"}),
    )
}
pub async fn execute(config: &ProbeConfig, lease: &Lease, cache: &Store) -> ProbeResult {
    // A rejected preflight is evidence of non-execution, not a failed network
    // measurement. The controller may return this opportunity to the round.
    let preflight = match lease.kind.as_str() {
        "dns" => crate::rules::ascii_domain(&lease.target)
            .and_then(|_| dns_method(config, lease).map(|_| ())),
        "traceroute" => lease
            .target
            .parse::<IpAddr>()
            .map_err(anyhow::Error::from)
            .and_then(|ip| {
                ensure!(
                    config.allow_private_targets || public_ip(ip),
                    "non-public measurement target"
                );
                Ok(())
            }),
        _ => Err(anyhow::anyhow!("unsupported task kind")),
    };
    if let Err(error) = preflight {
        return ProbeResult {
            id: uuid::Uuid::new_v4().to_string(),
            job_id: lease.id.clone(),
            fingerprint: lease.fingerprint.clone(),
            lease_token: lease.token.clone(),
            observed_at: now(),
            outcome: "unsupported".into(),
            evidence: json!({"kind":lease.kind,"target":lease.target,"not_executed":true,"error":error.to_string()}),
        };
    }
    let work = async {
        match lease.kind.as_str() {
            "dns" => domain(config, lease, cache).await,
            "traceroute" => {
                let key = fingerprint(&json!([
                    "trace-observation-v2",
                    config.id,
                    lease.target,
                    lease.profile["observer"],
                    lease.profile["epoch"],
                    lease.profile["protocol"],
                    lease.profile["max_hops"]
                ]));
                if let Some(mut value) = cache.cache_get(&key)? {
                    value["cache_hit"] = json!(true);
                    Ok(value)
                } else {
                    match trace(config, lease).await {
                        Ok(mut value) => {
                            value["observed_at"] = json!(now());
                            value["cache_hit"] = json!(false);
                            cache.cache_put(
                                &key,
                                now() + if value["reached"] == true { 86400 } else { 300 },
                                &value,
                            )?;
                            Ok(value)
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            _ => Err(anyhow::anyhow!("unsupported task kind")),
        }
    };
    let outcome = match tokio::time::timeout(Duration::from_secs(120), work).await {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("measurement exceeded 120 second budget")),
    };
    let (status, evidence) = match outcome {
        Ok(v) => ("ok", v),
        Err(e) => {
            let not_executed = lease.kind == "traceroute"
                && e.downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound);
            (
                "error",
                json!({"kind":lease.kind,"target":lease.target,"not_executed":not_executed,"error":format!("{e:#}")}),
            )
        }
    };
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: lease.id.clone(),
        fingerprint: lease.fingerprint.clone(),
        lease_token: lease.token.clone(),
        observed_at: evidence["observed_at"].as_i64().unwrap_or(now()),
        outcome: status.into(),
        evidence,
    }
}
pub async fn run(config: ProbeConfig, once: bool) -> Result<()> {
    crate::transport::run_agent(config, once).await
}

pub fn load(path: &Path) -> Result<ProbeConfig> {
    let mut config: ProbeConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if config.ca_cert.is_relative() {
        config.ca_cert = parent.join(&config.ca_cert);
    }
    if config.data_dir.is_relative() {
        config.data_dir = parent.join(&config.data_dir);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_records_require_their_actual_successful_question_context() {
        let mut resolver = json!({"response_received":true,"rcodes":[{"name":"root.example","query_type":"A","code":0}],"records":[{"name":"alias.example","query_name":"root.example","query_type":"A","type":"A","ttl":60,"data":"1.1.1.1"}]});
        assert_eq!(
            successful_dns_records(&resolver, Some("A")).len(),
            1,
            "answer owner can legally differ from the actual question"
        );
        resolver["records"][0]["query_name"] = json!("other.example");
        assert!(
            successful_dns_records(&resolver, None).is_empty(),
            "all-NoError cannot authorize a different actual question"
        );
        resolver["records"][0]["query_name"] = json!("root.example");
        resolver["errors"] =
            json!([{"name":"root.example","query_type":"A","error":"query timed out"}]);
        assert!(
            successful_dns_records(&resolver, None).is_empty(),
            "contradictory timeout context cannot provide addresses"
        );
        resolver["errors"] = json!([]);
        resolver["response_received"] = json!(false);
        assert!(successful_dns_records(&resolver, None).is_empty());
        let mut legacy =
            json!({"records":[{"name":"root.example","type":"A","ttl":60,"data":"1.1.1.1"}]});
        assert_eq!(successful_dns_records(&legacy, None).len(), 1);
        legacy["errors"] = json!([{"error":"old untyped query timed out"}]);
        assert!(
            successful_dns_records(&legacy, None).is_empty(),
            "missing legacy context cannot locate a failed question"
        );
    }

    #[test]
    fn public_targets() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "198.18.1.1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "fc00::1",
        ] {
            assert!(!public_ip(s.parse().unwrap()));
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }
    #[tokio::test]
    #[ignore = "requires native traceroute and raw-socket privileges"]
    async fn native_loopback_trace() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).unwrap();
        let config = ProbeConfig {
            controller: "http://127.0.0.1".into(),
            id: "native-fixture".into(),
            token_env: "UNUSED".into(),
            resolvers: vec![],
            allow_private_targets: true,
            tls: false,
            ca_cert: PathBuf::new(),
            server_name: crate::transport::SERVER_NAME.into(),
            data_dir: temp.path().into(),
        };
        let lease = Lease {
            id: "fixture".into(),
            case_key: "fixture".into(),
            fingerprint: "fixture".into(),
            kind: "traceroute".into(),
            target: "127.0.0.1".into(),
            region: "local-fixture".into(),
            token: "fixture".into(),
            until: now() + 180,
            profile: json!({"max_hops":3}),
        };
        let r = execute(&config, &lease, &store).await;
        assert_eq!(r.outcome, "ok", "{}", r.evidence);
        assert_eq!(r.evidence["reached"], true, "{}", r.evidence);
    }
}
