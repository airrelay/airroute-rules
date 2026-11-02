//! Attempt-fenced result ingestion. Measurements are evidence, never geographic votes.
use crate::measure::dns_response_code;
use crate::{
    hash, now,
    store::{Lease, Node, ProbeResult, Store},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::Path,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultClass {
    Observation,
    TargetFailure,
    ExecutorFailure,
    NotExecuted,
}
impl ResultClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::TargetFailure => "target-failure",
            Self::ExecutorFailure => "executor-failure",
            Self::NotExecuted => "not-executed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Qualification {
    pub qualified: bool,
    pub execution_terminal: bool,
    pub evidence_until: Option<i64>,
    pub reason: String,
    pub class: ResultClass,
    pub observer_asn: Option<u64>,
}
impl Qualification {
    fn invalid(reason: &str) -> Self {
        Self {
            qualified: false,
            execution_terminal: false,
            evidence_until: None,
            reason: reason.into(),
            class: ResultClass::ExecutorFailure,
            observer_asn: None,
        }
    }
    fn observed(qualified: bool, evidence_until: Option<i64>, reason: &str) -> Self {
        Self {
            qualified,
            execution_terminal: true,
            evidence_until,
            reason: reason.into(),
            class: ResultClass::Observation,
            observer_asn: None,
        }
    }
    fn target_failure(reason: &str) -> Self {
        let mut q = Self::observed(false, None, reason);
        q.class = ResultClass::TargetFailure;
        q
    }
    fn with_asn(mut self, asn: Option<u64>) -> Self {
        self.observer_asn = asn;
        self
    }
}

/// Store only a changed authority mapping. This maps observer locations, not target ownership.
pub fn configure_country_regions(store: &Store, root: &Path) -> Result<()> {
    let config: Value = crate::read_json(&root.join("config/geography.json"))?;
    let mut mapping = BTreeMap::<String, String>::new();
    for region in config["regions"]
        .as_array()
        .context("observation region mapping")?
    {
        let id = region["id"].as_str().context("region id")?;
        for country in region["codes"].as_array().context("region country codes")? {
            let code = country.as_str().context("country code")?.to_uppercase();
            ensure!(
                mapping.insert(code, id.into()).is_none(),
                "duplicate observer country mapping"
            );
        }
    }
    let encoded = serde_json::to_string(&mapping)?;
    if store.meta("observation-country-regions")?.as_deref() != Some(&encoded) {
        store.set_meta("observation-country-regions", &encoded)?;
    }
    Ok(())
}

fn same_target(a: &str, b: &str) -> bool {
    match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
        (Ok(a), Ok(b)) => a == b,
        (Err(_), Err(_)) => a
            .trim_end_matches('.')
            .eq_ignore_ascii_case(b.trim_end_matches('.')),
        _ => false,
    }
}
fn required_region(lease: &Lease) -> Option<&str> {
    if lease.profile["region_required"] == true && lease.region != "any" {
        Some(lease.region.as_str())
    } else {
        lease.profile["required_region"]
            .as_str()
            .filter(|s| *s != "any" && !s.is_empty())
    }
}
fn required_asn(lease: &Lease) -> Option<u64> {
    lease.profile["required_asn"].as_u64().filter(|v| *v > 0)
}
fn scope_matches(lease: &Lease, region: Option<&str>, asn: Option<u64>) -> bool {
    required_region(lease).is_none_or(|wanted| region == Some(wanted))
        && required_asn(lease).is_none_or(|wanted| asn == Some(wanted))
        && lease.profile["excluded_asns"]
            .as_array()
            .is_none_or(|excluded| {
                asn.is_none_or(|actual| !excluded.iter().any(|v| v.as_u64() == Some(actual)))
            })
}
fn trusted_start(value: &Value, fallback: i64) -> i64 {
    value["observed_at"]
        .as_i64()
        .unwrap_or(fallback)
        .min(fallback)
}
fn normalized_name(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}
fn dns_expiry(
    records: &[Value],
    host: &str,
    start: i64,
    absolute: Option<i64>,
    data_field: &str,
) -> Option<i64> {
    let mut names = BTreeSet::from([normalized_name(host)]);
    for _ in 0..8 {
        // Use the previous frontier, so one record-ordering cannot walk an
        // unbounded chain during a single pass.
        let previous = names.clone();
        let mut added = false;
        for record in records {
            if record["type"] != "CNAME" {
                continue;
            }
            let (Some(name), Some(target)) = (record["name"].as_str(), record[data_field].as_str())
            else {
                continue;
            };
            if previous.contains(&normalized_name(name))
                && crate::rules::ascii_domain(target.trim_end_matches('.')).is_ok()
            {
                added |= names.insert(normalized_name(target));
            }
        }
        if !added {
            break;
        }
    }
    records
        .iter()
        .filter(|record| {
            let (Some(name), Some(kind), Some(data)) = (
                record["name"].as_str(),
                record["type"].as_str(),
                record[data_field].as_str(),
            ) else {
                return false;
            };
            if !names.contains(&normalized_name(name)) {
                return false;
            }
            match kind {
                "A" => data.parse::<std::net::Ipv4Addr>().is_ok(),
                "AAAA" => data.parse::<std::net::Ipv6Addr>().is_ok(),
                "CNAME" => names.contains(&normalized_name(data)),
                "HTTPS" | "SVCB" => !data.is_empty(),
                _ => false,
            }
        })
        .filter_map(|v| v["ttl"].as_u64())
        .min()
        .map(|ttl| {
            let end = start.saturating_add(ttl.min(86400) as i64);
            absolute.map_or(end, |bound| end.min(bound))
        })
}

/// Defaults match the probe cache policy; explicit observation policy may
/// override them without turning expiration into a periodic trace generator.
pub const TRACE_POSITIVE_TTL_SECONDS: i64 = 86400;
pub const TRACE_NEGATIVE_TTL_SECONDS: i64 = 300;
fn trace_observation(lease: &Lease, r: &ProbeResult, reached: bool, reason: &str) -> Qualification {
    let field = if reached {
        "evidence_ttl_seconds"
    } else {
        "negative_evidence_ttl_seconds"
    };
    let ttl = lease.profile[field]
        .as_i64()
        .filter(|v| *v > 0)
        .unwrap_or(if reached {
            TRACE_POSITIVE_TTL_SECONDS
        } else {
            TRACE_NEGATIVE_TTL_SECONDS
        });
    let until = r.observed_at.saturating_add(ttl);
    let mut q = if reached {
        Qualification::observed(until > now(), Some(until), reason)
    } else {
        Qualification::target_failure(reason)
    };
    q.evidence_until = Some(until);
    q
}

/// Pure qualification; callers load runtime country mapping into the lease profile.
/// A valid trace without a destination response is terminal, but cannot satisfy positive-response evidence.
pub fn qualify(lease: &Lease, node: &Node, r: &ProbeResult) -> Qualification {
    let mut q = qualify_inner(lease, node, r);
    if !node.id.starts_with("globalping:") {
        q.observer_asn = lease.profile["observer"]["asn"].as_u64();
    }
    q
}
fn qualify_inner(lease: &Lease, node: &Node, r: &ProbeResult) -> Qualification {
    if r.outcome == "unsupported" || r.evidence["not_executed"] == true {
        let mut q = Qualification::invalid("execution did not start");
        q.class = ResultClass::NotExecuted;
        return q;
    }
    if r.outcome != "ok"
        && !matches!(
            r.evidence["target_error"].as_str(),
            Some("timeout" | "refused")
        )
    {
        return Qualification::invalid("executor did not return a valid observation");
    }
    if r.observed_at <= 0 || r.observed_at > now() + 60 {
        return Qualification::invalid("untrusted observation timestamp");
    }
    if node.id.starts_with("globalping:") {
        return qualify_globalping(lease, r);
    }
    let observer = &lease.profile["observer"];
    if observer["id"].as_str() != Some(node.id.as_str())
        || observer["region"].as_str().is_none_or(|v| v.is_empty())
        || observer["asn"].as_u64().is_none()
    {
        return Qualification::invalid("missing persisted attempt observer scope");
    }
    if !scope_matches(lease, observer["region"].as_str(), observer["asn"].as_u64()) {
        return Qualification::invalid("observer region or ASN does not satisfy this observation");
    }
    if r.evidence["kind"] != lease.kind {
        return Qualification::invalid("missing or mismatched measurement method");
    }
    match lease.kind.as_str() {
        "traceroute" => {
            if !r.evidence["target"]
                .as_str()
                .is_some_and(|s| same_target(s, &lease.target))
            {
                return Qualification::invalid("traceroute target mismatch");
            }
            let expected = lease.profile["protocol"].as_str().unwrap_or("icmp");
            if !r.evidence["protocol"]
                .as_str()
                .is_some_and(|s| s.eq_ignore_ascii_case(expected))
            {
                return Qualification::invalid("traceroute protocol mismatch");
            }
            if matches!(
                r.evidence["target_error"].as_str(),
                Some("timeout" | "refused")
            ) {
                return trace_observation(
                    lease,
                    r,
                    false,
                    "target timed out or refused the concrete measurement",
                );
            }
            let Some(hops) = r.evidence["hops"].as_array().filter(|h| !h.is_empty()) else {
                return Qualification::invalid("missing path observation");
            };
            let reached = hops.iter().any(|hop| {
                hop["ip"]
                    .as_str()
                    .is_some_and(|s| same_target(s, &lease.target))
            });
            if r.evidence["reached"] == true && !reached {
                return Qualification::invalid(
                    "destination response is not supported by path evidence",
                );
            }
            if reached {
                trace_observation(lease, r, true, "destination response observed")
            } else {
                trace_observation(
                    lease,
                    r,
                    false,
                    "path observed; destination did not respond",
                )
            }
        }
        "dns" => {
            if r.outcome != "ok" {
                return Qualification::invalid("DNS execution failed");
            }
            if !r.evidence["hostname"]
                .as_str()
                .is_some_and(|s| same_target(s, &lease.target))
            {
                return Qualification::invalid("DNS hostname mismatch");
            }
            let Some(resolvers) = r.evidence["resolvers"].as_array() else {
                return Qualification::invalid("missing resolver observations");
            };
            let mut responded = false;
            let mut expiry: Option<i64> = None;
            let mut response_error = None;
            for resolver in resolvers {
                if resolver["response_received"] != true {
                    continue;
                }
                let Some(transport) = resolver["transport"]
                    .as_str()
                    .filter(|v| matches!(*v, "udp" | "tcp" | "https" | "doh"))
                else {
                    continue;
                };
                if let Some(expected) = lease.profile["protocol"].as_str() {
                    let expected = expected.to_ascii_lowercase();
                    let same = transport.eq_ignore_ascii_case(&expected)
                        || (matches!(expected.as_str(), "https" | "doh")
                            && matches!(transport, "https" | "doh"));
                    if !same {
                        continue;
                    }
                }
                let expected_query = lease.profile["query"]["type"]
                    .as_str()
                    .or_else(|| lease.profile["query_type"].as_str());
                if let Some(expected) = expected_query {
                    let seen = resolver["rcodes"].as_array().is_some_and(|codes| {
                        codes.iter().any(|v| {
                            v["query_type"]
                                .as_str()
                                .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                        })
                    }) || resolver["records"].as_array().is_some_and(|records| {
                        records.iter().any(|v| {
                            v["query_type"]
                                .as_str()
                                .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                        })
                    });
                    if !seen {
                        continue;
                    }
                }
                let codes: Vec<_> = resolver["rcodes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|code| {
                        expected_query.is_none_or(|expected| {
                            code.is_string()
                                || code["query_type"]
                                    .as_str()
                                    .is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
                        })
                    })
                    .collect();
                if !codes.is_empty()
                    && !codes
                        .iter()
                        .any(|code| matches!(dns_response_code(code), Some(0 | 3)))
                {
                    response_error = Some(
                        if codes
                            .iter()
                            .any(|code| matches!(dns_response_code(code), Some(2 | 5)))
                        {
                            "DNS resolver returned SERVFAIL or REFUSED"
                        } else {
                            "DNS resolver returned an invalid or unsuccessful response code"
                        },
                    );
                    continue;
                }
                responded = true;
                {
                    let relevant = crate::measure::successful_dns_records(resolver, expected_query);
                    let start = trusted_start(resolver, r.observed_at);
                    if resolver["observed_at"].as_i64().is_none()
                        || resolver["valid_until"].as_i64().is_none()
                    {
                        continue;
                    }
                    if let Some(end) = dns_expiry(
                        &relevant,
                        &lease.target,
                        start,
                        resolver["valid_until"].as_i64(),
                        "data",
                    ) {
                        expiry = Some(expiry.map_or(end, |old| old.min(end)));
                    }
                }
            }
            if !responded {
                return Qualification::invalid(response_error.unwrap_or("no actual DNS response"));
            }
            Qualification::observed(
                expiry.is_some_and(|end| end > now()),
                expiry,
                "DNS response; expiry retains original observation time",
            )
        }
        _ => Qualification::invalid("unsupported measurement method"),
    }
}
// DiG reports the question actually sent and the transport actually used.
// Cross-check this actual output against the response's explicit/default method,
// never the requested profile or the address of an answer.
fn dig_dns_method(raw: &str) -> Option<(String, String, Option<String>)> {
    let mut question = None;
    let mut protocol = None;
    let mut server_seen = false;
    let mut in_question = false;
    for line in raw.lines().map(str::trim) {
        if line.eq_ignore_ascii_case(";; QUESTION SECTION:") {
            in_question = true;
            continue;
        }
        if line.starts_with(";;") {
            in_question = false;
        }
        if let Some(server) = line.strip_prefix(";; SERVER:") {
            if server_seen {
                return None;
            }
            server_seen = true;
            let server = server.trim();
            let address = if let Some((address, transport)) = server.rsplit_once(" (") {
                let transport = transport.strip_suffix(')')?.to_ascii_lowercase();
                if !matches!(transport.as_str(), "udp" | "tcp") {
                    return None;
                }
                protocol = Some(transport);
                address
            } else {
                // Older DiG ends after address#port(address). No explicit
                // transport is present; retain the provider's schema default.
                server
            };
            let (endpoint, echoed) = address.strip_suffix(')')?.rsplit_once('(')?;
            let (host, port) = endpoint.rsplit_once('#')?;
            // Globalping also masks the resolver address with this exact
            // literal in real DiG output. Both copies must match the mask.
            let matching_address = (host == "x.x.x.x" && echoed == "x.x.x.x")
                || host
                    .parse::<IpAddr>()
                    .ok()
                    .zip(echoed.parse::<IpAddr>().ok())
                    .is_some_and(|(host, echoed)| host == echoed);
            if !matching_address || port.parse::<u16>().ok()? == 0 {
                return None;
            }
        } else if in_question && !line.is_empty() {
            let fields: Vec<_> = line.strip_prefix(';')?.split_whitespace().collect();
            if fields.len() != 3 || !fields[1].eq_ignore_ascii_case("IN") || question.is_some() {
                return None;
            }
            let query = fields[2].to_ascii_uppercase();
            query.parse::<hickory_proto::rr::RecordType>().ok()?;
            question = Some((fields[0].to_string(), query));
        }
    }
    let (host, query) = question?;
    server_seen.then_some((host, query, protocol))
}
fn provider_dns_method(lease: &Lease, measurement: &Value, result: &Value) -> bool {
    let raw = match result["rawOutput"]
        .as_str()
        .filter(|v| !v.trim().is_empty())
    {
        Some(raw) => match dig_dns_method(raw) {
            Some(method) => Some(method),
            None => return false,
        },
        None => None,
    };
    if raw
        .as_ref()
        .is_some_and(|(host, _, _)| !same_target(host, &lease.target))
    {
        return false;
    }
    let protocol_fields = [
        &measurement["measurementOptions"]["protocol"],
        &result["protocol"],
    ];
    let query_fields = [
        &measurement["measurementOptions"]["query"]["type"],
        &result["query"]["type"],
    ];
    if protocol_fields
        .iter()
        .chain(query_fields.iter())
        .any(|v| !v.is_null() && !v.is_string())
    {
        return false;
    }
    // MeasurementResponse omits options equal to the provider's documented
    // defaults: DnsProtocol=UDP and DnsQueryType=A. Never fill actual values
    // from our requested profile.
    let protocol = protocol_fields
        .iter()
        .find_map(|v| v.as_str())
        .unwrap_or("udp");
    let query = query_fields.iter().find_map(|v| v.as_str()).unwrap_or("A");
    if !matches!(protocol.to_ascii_lowercase().as_str(), "udp" | "tcp") {
        return false;
    }
    if protocol_fields
        .iter()
        .filter_map(|v| v.as_str())
        .any(|v| !v.eq_ignore_ascii_case(protocol))
        || query_fields
            .iter()
            .filter_map(|v| v.as_str())
            .any(|v| !v.eq_ignore_ascii_case(query))
        || raw.as_ref().is_some_and(|(_, q, p)| {
            p.as_ref()
                .is_some_and(|p| !p.eq_ignore_ascii_case(protocol))
                || !q.eq_ignore_ascii_case(query)
        })
    {
        return false;
    }
    let expected_protocol = lease.profile["protocol"].as_str().unwrap_or("udp");
    let expected_query = lease.profile["query"]["type"]
        .as_str()
        .or_else(|| lease.profile["query_type"].as_str());
    protocol.eq_ignore_ascii_case(expected_protocol)
        && expected_query.is_none_or(|v| query.eq_ignore_ascii_case(v))
}

fn qualify_globalping(lease: &Lease, r: &ProbeResult) -> Qualification {
    let m = &r.evidence["measurement"];
    if m["type"] != lease.kind
        || !m["target"]
            .as_str()
            .is_some_and(|s| same_target(s, &lease.target))
    {
        return Qualification::invalid("missing or mismatched provider method/target");
    }
    let Some(items) = m["results"].as_array() else {
        return Qualification::invalid("missing actual probe results");
    };
    let mut inconclusive = None;
    for item in items {
        let probe = &item["probe"];
        let Some(country) = probe["country"].as_str().filter(|v| v.len() == 2) else {
            continue;
        };
        let country = country.to_uppercase();
        let region = lease.profile["observation_country_regions"][&country].as_str();
        // Missing mappings cannot turn a requested/virtual location into actual coverage.
        if region.is_none() {
            continue;
        }
        let asn = probe["asn"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= u32::MAX as u64);
        if asn.is_none() || !scope_matches(lease, region, asn) {
            continue;
        }
        let result = &item["result"];
        if result["status"] != "finished" {
            continue;
        }
        if lease.kind == "traceroute" {
            let expected = lease.profile["protocol"].as_str().unwrap_or("icmp");
            // The provider omits default options in MeasurementResponse;
            // TracerouteProtocol's documented response default is ICMP.
            let method = m["measurementOptions"]["protocol"]
                .as_str()
                .or_else(|| result["protocol"].as_str())
                .unwrap_or("ICMP");
            if [&m["measurementOptions"]["protocol"], &result["protocol"]]
                .iter()
                .any(|v| !v.is_null() && !v.is_string())
                || !method.eq_ignore_ascii_case(expected)
                || [&m["measurementOptions"]["protocol"], &result["protocol"]]
                    .iter()
                    .filter_map(|v| v.as_str())
                    .any(|v| !v.eq_ignore_ascii_case(method))
            {
                continue;
            }
            if !result["resolvedAddress"]
                .as_str()
                .is_some_and(|s| same_target(s, &lease.target))
            {
                continue;
            }
            let Some(hops) = result["hops"].as_array().filter(|h| !h.is_empty()) else {
                continue;
            };
            let reached = hops.iter().any(|hop| {
                hop["resolvedAddress"]
                    .as_str()
                    .is_some_and(|s| same_target(s, &lease.target))
                    && hop["timings"].as_array().is_some_and(|times| {
                        times
                            .iter()
                            .any(|t| t["rtt"].as_f64().is_some_and(|v| v >= 0.0))
                    })
            });
            let q = if reached {
                trace_observation(lease, r, true, "provider destination response observed")
            } else {
                trace_observation(
                    lease,
                    r,
                    false,
                    "provider path observed; destination did not respond",
                )
            }
            .with_asn(asn);
            if reached {
                return q;
            }
            inconclusive = Some(q);
        } else if lease.kind == "dns" {
            let Some(code) = result["statusCode"]
                .as_i64()
                .filter(|code| matches!(code, 0 | 3))
            else {
                continue;
            };
            if !provider_dns_method(lease, m, result) {
                continue;
            }
            if code == 3 {
                // An actual NXDOMAIN response completes this DNS observation,
                // just as a native resolver response without usable records does.
                // No address, geography or negative TTL is invented.
                let aliases_only = match result.get("answers") {
                    None | Some(Value::Null) => true,
                    Some(Value::Array(answers)) => answers.iter().all(|answer| {
                        answer["type"] == "CNAME"
                            && ["name", "value"].iter().all(|field| {
                                answer[*field]
                                    .as_str()
                                    .filter(|name| !name.is_empty())
                                    .is_some_and(|name| {
                                        name.parse::<hickory_proto::rr::Name>().is_ok()
                                    })
                            })
                    }),
                    _ => false,
                };
                if result["rawOutput"]
                    .as_str()
                    .and_then(dig_dns_method)
                    .is_none()
                    || !aliases_only
                {
                    continue;
                }
                return Qualification::observed(
                    false,
                    None,
                    "provider DNS NXDOMAIN response with actual question and observer scope",
                )
                .with_asn(asn);
            }
            let Some(answers) = result["answers"].as_array() else {
                continue;
            };
            let expiry = dns_expiry(answers, &lease.target, r.observed_at, None, "value");
            return Qualification::observed(
                expiry.is_some_and(|end| end > now()),
                expiry,
                "provider DNS response with actual observer scope",
            )
            .with_asn(asn);
        }
    }
    inconclusive.unwrap_or_else(|| {
        Qualification::invalid("no actual probe satisfies observer, method and target requirements")
    })
}

pub fn qualify_stored(
    store: &Store,
    lease: &Lease,
    node: &Node,
    r: &ProbeResult,
) -> Result<Qualification> {
    qualify_stored_on(&store.connect()?, lease, node, r)
}

fn qualify_stored_on(
    conn: &Connection,
    lease: &Lease,
    node: &Node,
    r: &ProbeResult,
) -> Result<Qualification> {
    if !node.id.starts_with("globalping:") {
        return Ok(qualify(lease, node, r));
    }
    let mut scoped = lease.clone();
    if let Some(mapping) = conn
        .prepare_cached("SELECT value FROM meta WHERE key='observation-country-regions'")?
        .query_row([], |r| r.get::<_, String>(0))
        .optional()?
    {
        scoped.profile["observation_country_regions"] = serde_json::from_str(&mapping)?;
    }
    Ok(qualify(&scoped, node, r))
}

pub(crate) fn has_other_observer_on(
    c: &rusqlite::Connection,
    lease: &Lease,
    current: &str,
) -> Result<bool> {
    let eligible = crate::work::eligibility_sql("j", "n");
    // Capability is independent of the remaining opportunity budget. A third
    // negative can still be insufficient; exhaustion must then keep its cooldown.
    let sql = format!(
        "WITH j(id,target,kind,region,profile,execution_count,round_seq) AS (SELECT ?1,?2,?3,?4,?5,0,coalesce((SELECT round_seq FROM jobs WHERE id=?1),1)) SELECT EXISTS(SELECT 1 FROM j JOIN nodes n ON n.id<>?6 WHERE {eligible} AND ((n.id NOT LIKE 'globalping:%' AND n.connected=1 AND n.last_seen>?7) OR (n.id LIKE 'globalping:%' AND EXISTS(SELECT 1 FROM gp_accounts a WHERE a.deleted=0 AND coalesce(json_extract(a.config,'$.enabled'),0)=1 AND substr(n.id,1,length(a.id)+12)='globalping:'||a.id||':'))))"
    );
    Ok(c.prepare_cached(&sql)?.query_row(
        params![
            lease.id,
            lease.target,
            lease.kind,
            lease.region,
            lease.profile.to_string(),
            current,
            now() - 120
        ],
        |v| v.get(0),
    )?)
}

/// Virtual GP account names are not independent observers. Use only actual
/// returned probe metadata; absent public probe IDs, collapse the same footprint.
pub(crate) fn negative_observer_key(lease: &Lease, node: &Node, r: &ProbeResult) -> Option<String> {
    if !node.id.starts_with("globalping:") {
        return lease.profile["observer"]["id"]
            .as_str()
            .map(|id| format!("self:{id}"));
    }
    for item in r.evidence["measurement"]["results"].as_array()? {
        let mut single = r.clone();
        single.evidence["measurement"]["results"] = json!([item]);
        let q = qualify(lease, node, &single);
        if q.class != ResultClass::TargetFailure || !q.execution_terminal {
            continue;
        }
        let p = &item["probe"];
        let country = p["country"].as_str()?.to_ascii_uppercase();
        let asn = p["asn"].as_u64()?;
        let city = p["city"].as_str().unwrap_or("").trim().to_ascii_lowercase();
        return Some(format!("gp:{country}:{asn}:{city}"));
    }
    None
}

pub fn submit(store: &Store, node_id: &str, r: &ProbeResult) -> Result<Value> {
    let mut conn = store.connect()?;
    submit_on(store, &mut conn, node_id, r)
}

/// One existing receipt worker owns this connection between calls. No SQLite
/// transaction survives the call or spans ACK/network I/O.
pub(crate) fn submit_on(
    store: &Store,
    conn: &mut rusqlite::Connection,
    node_id: &str,
    r: &ProbeResult,
) -> Result<Value> {
    ensure!(
        matches!(r.outcome.as_str(), "ok" | "error" | "unsupported"),
        "invalid outcome"
    );
    ensure!(
        r.observed_at > 0 && r.observed_at <= now() + 60,
        "invalid observation timestamp"
    );
    // Expensive parsing and qualification happen before acquiring the SQLite writer.
    let encoded = r.evidence.to_string();
    let candidate = {
        let (case_key, fp, kind, target, region, profile, until): (
            String,
            String,
            String,
            String,
            String,
            String,
            Option<i64>,
        ) = conn
            .prepare_cached(
                "SELECT case_key,fp,kind,target,region,profile,lease_until FROM jobs WHERE id=?",
            )?
            .query_row([&r.job_id], |v| {
                Ok((
                    v.get(0)?,
                    v.get(1)?,
                    v.get(2)?,
                    v.get(3)?,
                    v.get(4)?,
                    v.get(5)?,
                    v.get(6)?,
                ))
            })
            .context("unknown job")?;
        let (attempt, history_profile, round): (i64,Option<String>,i64) = conn.prepare_cached(
            "SELECT attempt_seq,lease_profile,round_seq FROM lease_history WHERE job_id=? AND token_hash=? AND node=? AND fp=?")?.query_row(
            params![r.job_id,hash(&r.lease_token),node_id,r.fingerprint],|v| Ok((v.get(0)?,v.get(1)?,v.get(2)?))).context("lease identity mismatch")?;
        if duplicate_on(conn, node_id, r, &encoded)? {
            return Ok(json!({"duplicate":true}));
        }
        let node = conn
            .prepare_cached("SELECT id,region,asn,capabilities FROM nodes WHERE id=?")?
            .query_row([node_id], |v| {
                let caps: String = v.get(3)?;
                Ok(Node {
                    id: v.get(0)?,
                    region: v.get(1)?,
                    asn: v.get(2)?,
                    capabilities: serde_json::from_str(&caps).unwrap_or_default(),
                })
            })
            .context("unknown executor")?;
        let has_history_scope = history_profile.is_some();
        let mut profile: Value = serde_json::from_str(&history_profile.unwrap_or(profile))?;
        profile["attempt_seq"] = json!(attempt);
        profile["round_seq"] = json!(round);
        if !node_id.starts_with("globalping:") && !has_history_scope {
            profile["observer"] = Value::Null;
        }
        let persisted_scope = node_id.starts_with("globalping:")
            || (has_history_scope
                && profile["observer"]["id"].as_str() == Some(node_id)
                && profile["observer"]["region"]
                    .as_str()
                    .is_some_and(|v| !v.is_empty())
                && profile["observer"]["asn"].as_u64().is_some());
        let lease = Lease {
            id: r.job_id.clone(),
            case_key,
            fingerprint: fp,
            kind,
            target,
            region,
            token: r.lease_token.clone(),
            until: until.unwrap_or(0),
            profile,
        };
        let qualification = qualify_stored_on(conn, &lease, &node, r)?;
        (lease, attempt, qualification, persisted_scope)
    };
    let (lease, attempt, qualification, persisted_scope) = candidate;
    let cached_reuse = !node_id.starts_with("globalping:")
        && r.evidence["cache_hit"] == true
        && qualification.execution_terminal
        && (qualification.qualified
            || (qualification.class == ResultClass::TargetFailure
                && qualification
                    .evidence_until
                    .is_some_and(|until| until > now())));
    let observer_asn = qualification
        .observer_asn
        .and_then(|value| i64::try_from(value).ok());
    let observations = if qualification.qualified && r.outcome == "ok" {
        crate::discovery::receipt_observations(&r.id, r.observed_at, &r.evidence)
    } else {
        Vec::new()
    };
    let retry_base = crate::scheduler::policy_on(conn)?.retry_base_seconds;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    // A second concurrent copy may have committed after the read check.
    if duplicate_on(&tx, node_id, r, &encoded)? {
        return Ok(json!({"duplicate":true}));
    }
    let mut wake_needed = false;
    let bound: bool = tx.prepare_cached(
        "SELECT EXISTS(SELECT 1 FROM jobs j WHERE j.id=?1 AND j.fp=?2 AND j.status='leased' AND j.lease_node=?3 AND j.lease_token=?4 AND j.attempt_seq=?5 AND j.lease_until>=?6)")?.query_row(
        params![r.job_id,r.fingerprint,node_id,r.lease_token,attempt,now()],|v|v.get(0))?;
    let links = if bound && persisted_scope {
        crate::jobs_v3::current_case_links_on(&tx, &r.job_id)?
    } else {
        Vec::new()
    };
    let mut current = bound && persisted_scope && !links.is_empty();
    if current {
        if qualification.class == ResultClass::NotExecuted || cached_reuse {
            crate::jobs_v3::refund_execution_on(&tx, &lease)?;
        } else {
            // The authenticated result can prove a send whose acknowledgement
            // was lost. Charging is fenced and idempotent for that exact attempt.
            current = crate::jobs_v3::consume_reported_execution_on(&tx, &lease)?;
        }
    }
    let round = lease.profile["round_seq"].as_i64().unwrap_or(1);
    tx.prepare_cached("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,attempt_seq,qualified,evidence_until,round_seq,execution_class,observer_asn) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")?.execute(
        params![r.id,r.job_id,node_id,r.fingerprint,r.observed_at,r.outcome,encoded,current,now(),attempt,qualification.qualified,qualification.evidence_until,round,qualification.class.as_str(),observer_asn])?;
    if qualification.execution_terminal && persisted_scope && !current {
        tx.prepare_cached("UPDATE lease_history SET result_class=?,completed_at=?,observer_asn=? WHERE job_id=? AND token_hash=? AND attempt_seq=? AND round_seq=? AND completed_at IS NULL")?.execute(params![qualification.class.as_str(),now(),observer_asn,lease.id,hash(&lease.token),attempt,round])?;
    }
    if qualification.qualified || qualification.class == ResultClass::TargetFailure {
        // A late observation can satisfy another current demand for this exact
        // target/method. Wake only those links; claim/send gates also recheck it
        // synchronously, so this durable notification is not the safety fence.
        wake_needed |= tx.prepare_cached("INSERT INTO replan_cases(case_key,queued_at) SELECT l.case_key,?3 FROM jobs j JOIN job_cases l ON l.job_id=j.id JOIN cases active ON active.key=l.case_key AND active.fp=l.fp AND active.revision=l.revision WHERE j.target=?1 AND j.kind=?2 AND j.status IN ('pending','leased','unknown') AND active.active=1 ON CONFLICT(case_key) DO NOTHING")?.execute(params![lease.target,lease.kind,now()])? > 0;
    }
    if current {
        // Completing/requeueing this live lease changes executable capacity.
        wake_needed = true;
        let (failures, owner, used): (i64,String,i64) = tx.prepare_cached(
            "SELECT j.failure_count,coalesce(h.execution_job_id,j.id),coalesce(owner.execution_count,j.execution_count) FROM jobs j JOIN lease_history h ON h.job_id=j.id AND h.token_hash=? LEFT JOIN jobs owner ON owner.id=h.execution_job_id WHERE j.id=?")?.query_row(
            params![hash(&lease.token),lease.id], |v| Ok((v.get(0)?,v.get(1)?,v.get(2)?)))?;
        let capability_failure = qualification.class == ResultClass::ExecutorFailure
            && r.evidence["error"].as_str().is_some_and(|e| {
                e.contains("Network is unreachable")
                    || e.contains("Network unreachable")
                    || e.contains("Address family not supported")
            });
        let terminal_observation = qualification.execution_terminal;
        let next_failures =
            if terminal_observation || qualification.class == ResultClass::NotExecuted {
                0
            } else {
                failures.saturating_add(1)
            };
        let negative_ready = if qualification.class == ResultClass::TargetFailure {
            crate::work::prior_negative_observation(
                &tx,
                &lease.target,
                &lease.kind,
                &lease.region,
                &lease.profile,
            )?
        } else {
            None
        };
        let needs_confirmation =
            qualification.class == ResultClass::TargetFailure && negative_ready.is_none();
        let demand_expiry = negative_ready
            .as_ref()
            .and_then(|(_, until)| *until)
            .or(qualification.evidence_until);
        let terminal = terminal_observation && !needs_confirmation;
        let exhausted = !terminal && qualification.class != ResultClass::NotExecuted && used >= 3;
        let state = if terminal {
            "complete"
        } else if exhausted {
            "unknown"
        } else {
            "pending"
        };
        let next = if terminal {
            now()
        } else {
            now()
                .saturating_add(retry_base.saturating_mul(1i64 << next_failures.min(8)))
                .saturating_add((r.job_id.bytes().map(u32::from).sum::<u32>() % 31) as i64)
        };
        tx.prepare_cached("UPDATE lease_history SET result_class=?,completed_at=?,observer_asn=? WHERE job_id=? AND token_hash=? AND attempt_seq=? AND round_seq=? AND completed_at IS NULL")?.execute(
            params![qualification.class.as_str(),now(),observer_asn,lease.id,hash(&lease.token),attempt,round])?;
        tx.prepare_cached("UPDATE jobs SET status=?,result_id=?,not_before=?,failure_count=?,attempts=?,evidence_until=?,execution_terminal=?,next_round_at=?,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND attempt_seq=? AND lease_token=?")?.execute(
            params![state,r.id,next,next_failures,next_failures,demand_expiry,terminal,if exhausted{Some(now()+86400)}else{None},r.job_id,attempt,r.lease_token])?;
        // A legacy in-flight ID may consume the canonical demand budget. Its
        // exhausted state must fence the canonical row as well as that old ID.
        if exhausted && owner != lease.id {
            tx.prepare_cached("UPDATE jobs SET status='unknown',next_round_at=?,failure_count=max(failure_count,?) WHERE id=? AND status='pending'")?.execute(params![now()+86400,next_failures,owner])?;
        }
        if terminal_observation && !cached_reuse {
            tx.prepare_cached("INSERT INTO executor_counters(executor,completed_tasks,last_completed_at) VALUES(?,1,?) ON CONFLICT(executor) DO UPDATE SET completed_tasks=completed_tasks+1,last_completed_at=max(coalesce(last_completed_at,0),excluded.last_completed_at)")?.execute(params![node_id,now()])?;
        }
        if matches!(
            qualification.class,
            ResultClass::ExecutorFailure | ResultClass::NotExecuted
        ) && !node_id.starts_with("globalping:")
        {
            tx.prepare_cached("UPDATE nodes SET executor_cooldown_until=max(coalesce(executor_cooldown_until,0),?) WHERE id=?")?.execute(params![now()+60,node_id])?;
        }
        if capability_failure {
            let column = if lease.target.contains(':') {
                "ipv6_supported"
            } else {
                "ipv4_supported"
            };
            tx.prepare_cached(&format!(
                "UPDATE nodes SET {column}=0,network_checked=? WHERE id=?"
            ))?
            .execute(params![now(), node_id])?;
        }
        for (case_key, case_fp) in &links {
            let state = if terminal_observation {
                "evidence-ready"
            } else {
                "needs-active"
            };
            tx.prepare_cached(
                "UPDATE cases SET status=? WHERE key=? AND fp=? AND active=1 AND status<>?",
            )?
            .execute(params![state, case_key, case_fp, state])?;
            tx.prepare_cached("INSERT INTO replan_cases(case_key,queued_at) VALUES(?,?) ON CONFLICT(case_key) DO NOTHING")?.execute(params![case_key,now()])?;
        }
        for observation in observations
            .iter()
            .filter(|o| o.kind == "endpoint-response" && crate::measure::public_ip(o.ip))
        {
            let (family, address) = crate::rules::addr_num(observation.ip);
            tx.prepare_cached("INSERT INTO responsive_targets(ip,family,address,last_seen,result_id) VALUES(?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen,result_id=excluded.result_id WHERE excluded.last_seen>responsive_targets.last_seen")?.execute(params![observation.ip.to_string(),family,format!("{address:032x}"),observation.observed,r.id])?;
        }
        if lease.profile["purpose"] == "discovery" {
            // No new TTL is invented on transport failure or receipt retransmission.
            let next_check = qualification
                .evidence_until
                .unwrap_or(if terminal_observation { i64::MAX } else { next });
            tx.prepare_cached("UPDATE discovery_checks SET next_check=?,error=? WHERE kind='shared-dns' AND key=?")?.execute(
                params![next_check,if terminal_observation {None} else {Some(qualification.reason.as_str())},lease.target])?;
        }
    }
    tx.commit()?;
    if !observations.is_empty() {
        match crate::discovery::record_on(conn, &observations) {
            Ok(changed) => wake_needed |= changed > 0,
            Err(error) => {
                tracing::warn!(%error, "receipt accepted; target discovery import deferred")
            }
        }
    }
    if wake_needed {
        store.wake.notify_waiters();
    }
    Ok(
        json!({"accepted":current,"historical_only":!current,"qualified":qualification.qualified,"execution_terminal":current && qualification.execution_terminal,"qualification":qualification.reason,"execution_class":qualification.class.as_str(),"cached_reuse":current && cached_reuse}),
    )
}

fn duplicate_on(
    conn: &rusqlite::Connection,
    node_id: &str,
    r: &ProbeResult,
    encoded: &str,
) -> Result<bool> {
    if let Some(old) = conn
        .prepare_cached("SELECT job_id,node,fp,evidence,observed,outcome FROM results WHERE id=?")?
        .query_row([&r.id], |v| {
            Ok((
                v.get::<_, String>(0)?,
                v.get::<_, String>(1)?,
                v.get::<_, String>(2)?,
                v.get::<_, String>(3)?,
                v.get::<_, i64>(4)?,
                v.get::<_, String>(5)?,
            ))
        })
        .optional()?
    {
        ensure!(
            old == (
                r.job_id.clone(),
                node_id.into(),
                r.fingerprint.clone(),
                encoded.to_owned(),
                r.observed_at,
                r.outcome.clone()
            ),
            "result id collision"
        );
        return Ok(true);
    }
    Ok(false)
}
