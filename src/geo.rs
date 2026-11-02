//! Deterministic geographic fusion, Anycast classification and useful missing observations.
//! BGP origins and path observations are never country votes.
use crate::{
    fingerprint,
    inputs::Inputs,
    read_json,
    rules::{Rule, addr_num, append_range, cidrs, ip_parts, ip_text, union},
    store::CaseInput,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Cursor, Read},
    net::IpAddr,
    path::Path,
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    prefix: String,
    origins: Vec<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Tag {
    Region(u8),
    NoLocationOpinion,
    NetworkRegion(u8),
    PartialAnycast,
    Flag,
    FactualRegion(u8),
    Route(Arc<Route>),
    Hints(Vec<u8>),
}
#[derive(Clone, Debug)]
struct Span {
    s: u128,
    e: u128,
    v: Tag,
}
fn coalesce(mut spans: Vec<Span>, validate: bool) -> Result<Vec<Span>> {
    spans.sort_unstable_by_key(|s| (s.s, s.e));
    for s in &spans {
        ensure!(s.s <= s.e, "reversed interval");
    }
    ensure!(
        !validate || spans.windows(2).all(|w| w[0].e < w[1].s),
        "overlap within one geographic source"
    );
    spans.dedup_by(|next, previous| {
        if previous.e.checked_add(1) == Some(next.s) && previous.v == next.v {
            previous.e = next.e;
            true
        } else {
            false
        }
    });
    spans.shrink_to_fit();
    Ok(spans)
}
fn range_tags(rows: Vec<(u128, u128)>) -> Vec<Span> {
    union(rows)
        .into_iter()
        .map(|(s, e)| Span { s, e, v: Tag::Flag })
        .collect()
}
fn region(
    code: &str,
    map: &BTreeMap<String, u8>,
    unknown: &BTreeSet<String>,
) -> Result<Option<u8>> {
    let code = code.trim().to_uppercase();
    if unknown.contains(&code) {
        return Ok(None);
    }
    Ok(Some(
        *map.get(&code)
            .with_context(|| format!("unmapped country {code}"))?,
    ))
}
type GeoProducts = [BTreeMap<u8, Vec<Span>>; 2];
const MAX_EXPANDED: u64 = 512 * 1024 * 1024;
fn geoip(
    iplocate: &[u8],
    dbip: &[u8],
    map: &BTreeMap<String, u8>,
    unknown: &BTreeSet<String>,
    progress: Option<&crate::progress::Reporter>,
) -> Result<(GeoProducts, Value)> {
    let mut products = [BTreeMap::<u8, Vec<Span>>::new(), BTreeMap::new()];
    let mut counts = [[0usize; 2]; 2];
    let mut unknown_counts = [[0usize; 2]; 2];
    // Release the expanded IPLocate CSV before expanding DB-IP. Shadowing
    // bindings below would otherwise retain both backing buffers to function end.
    {
        let mut archive = zip::ZipArchive::new(Cursor::new(iplocate))?;
        let names: Vec<_> = archive
            .file_names()
            .filter(|name| name.ends_with(".csv"))
            .map(str::to_string)
            .collect();
        ensure!(names.len() == 1, "expected one country CSV");
        let csv = archive.by_name(&names[0])?;
        ensure!(csv.size() <= MAX_EXPANDED, "country CSV oversized");
        let mut reader = csv::Reader::from_reader(csv.take(MAX_EXPANDED + 1));
        let headers = reader.headers()?.clone();
        let ni = headers
            .iter()
            .position(|s| s.trim_start_matches('\u{feff}') == "network")
            .context("IPLocate header network")?;
        let ci = headers
            .iter()
            .position(|s| s == "country_code")
            .context("IPLocate country_code")?;
        for row in reader.records() {
            let row = row?;
            let net: ipnet::IpNet = row[ni].parse()?;
            ensure!(net == net.trunc(), "noncanonical GeoIP network");
            let (f, s, e) = ip_parts(net);
            counts[0][usize::from(f == 6)] += 1;
            let completed = counts[0].iter().sum::<usize>();
            if completed % 100000 == 0
                && let Some(p) = progress
            {
                p.units(completed, None, "行地理记录", "解析 IPLocate 地址范围")?;
            }
            if let Some(r) = region(&row[ci], map, unknown)? {
                products[0].entry(f).or_default().push(Span {
                    s,
                    e,
                    v: Tag::Region(r),
                })
            } else {
                unknown_counts[0][usize::from(f == 6)] += 1;
                products[0].entry(f).or_default().push(Span {
                    s,
                    e,
                    v: Tag::NoLocationOpinion,
                });
            }
        }
        ensure!(
            reader.position().byte() <= MAX_EXPANDED,
            "country CSV oversized"
        );
    }
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(flate2::read::GzDecoder::new(dbip).take(MAX_EXPANDED + 1));
    for row in reader.records() {
        let row = row?;
        ensure!(row.len() == 3, "invalid DB-IP row");
        let (f, s) = addr_num(row[0].parse::<IpAddr>()?);
        let (g, e) = addr_num(row[1].parse::<IpAddr>()?);
        ensure!(f == g && s <= e, "invalid DB-IP range");
        counts[1][usize::from(f == 6)] += 1;
        let completed = counts.iter().flatten().sum::<usize>();
        if completed % 100000 == 0
            && let Some(p) = progress
        {
            p.units(completed, None, "行地理记录", "解析 DB-IP 地址范围")?;
        }
        if let Some(r) = region(&row[2], map, unknown)? {
            products[1].entry(f).or_default().push(Span {
                s,
                e,
                v: Tag::Region(r),
            })
        } else {
            unknown_counts[1][usize::from(f == 6)] += 1;
            products[1].entry(f).or_default().push(Span {
                s,
                e,
                v: Tag::NoLocationOpinion,
            });
        }
    }
    ensure!(
        reader.position().byte() <= MAX_EXPANDED,
        "gzip expansion oversized"
    );
    drop(reader);
    for (i, p) in products.iter_mut().enumerate() {
        for (family_index, family) in [4, 6].into_iter().enumerate() {
            ensure!(
                counts[i][family_index] >= 100000,
                "GeoIP source {i} IPv{family} input coverage collapsed"
            );
            let rows = p
                .get_mut(&family)
                .filter(|rows| !rows.is_empty())
                .with_context(|| format!("GeoIP source {i} IPv{family} has no address ranges"))?;
            *rows = coalesce(std::mem::take(rows), true)?;
        }
    }
    Ok((
        products,
        json!({"iplocate":{"4":counts[0][0],"6":counts[0][1]},"dbip":{"4":counts[1][0],"6":counts[1][1]},"no_location_opinion_rows":{"iplocate":{"4":unknown_counts[0][0],"6":unknown_counts[0][1]},"dbip":{"4":unknown_counts[1][0],"6":unknown_counts[1][1]}}}),
    ))
}
struct AnycastViews {
    high: Vec<Span>,
    suspected: Vec<Span>,
    partial: Vec<Span>,
    stats: Value,
}
fn anycast(data: &[u8], f: u8) -> Result<AnycastViews> {
    let mut reader =
        csv::Reader::from_reader(flate2::read::GzDecoder::new(data).take(MAX_EXPANDED + 1));
    let h = reader.headers()?.clone();
    let field = |s: &str| {
        h.iter()
            .position(|x| x.trim_start_matches('\u{feff}') == s)
            .with_context(|| format!("Anycast missing {s}"))
    };
    let pi = field("prefix")?;
    let ab = [
        field(&format!("AB_ICMPv{f}"))?,
        field(&format!("AB_TCPv{f}"))?,
        field(&format!("AB_DNSv{f}"))?,
    ];
    let gcd = [
        field(&format!("GCD_ICMPv{f}"))?,
        field(&format!("GCD_TCPv{f}"))?,
    ];
    let partial = h.iter().position(|s| s == "partial");
    let (mut high, mut suspected, mut partial_high) = (vec![], vec![], vec![]);
    let (mut count, mut wide) = (0, 0);
    for row in reader.records() {
        let row = row?;
        let net: ipnet::IpNet = row[pi].parse()?;
        let (family, s, e) = ip_parts(net);
        ensure!(family == f && net == net.trunc(), "invalid Anycast prefix");
        let is_wide = net.prefix_len() < if f == 4 { 24 } else { 48 };
        let number = |i: usize| {
            if row[i].is_empty() {
                Ok(0u32)
            } else {
                row[i].parse::<u32>()
            }
        };
        let ab = ab
            .iter()
            .map(|&i| number(i))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let gcd = gcd
            .iter()
            .map(|&i| number(i))
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        let p = partial
            .map(|i| row[i].trim().to_lowercase())
            .unwrap_or_default();
        ensure!(
            matches!(p.as_str(), "" | "true" | "false"),
            "invalid partial flag"
        );
        count += 1;
        wide += usize::from(is_wide);
        if (ab > 3 || gcd > 1) && p == "true" && !is_wide {
            partial_high.push((s, e));
        }
        if (ab > 3 || gcd > 1) && p != "true" && !is_wide {
            high.push((s, e))
        } else if ab > 1 || gcd > 1 || p == "true" {
            suspected.push((s, e))
        }
    }
    ensure!(
        reader.position().byte() <= MAX_EXPANDED,
        "gzip expansion oversized"
    );
    drop(reader);
    ensure!(
        count >= 1000 && high.len() >= 100,
        "Anycast coverage collapsed"
    );
    let stats = json!({"rows":count,"wide_candidates":wide,"high_nonpartial":high.len(),"suspected_or_partial":suspected.len(),"high_partial_narrow":partial_high.len()});
    Ok(AnycastViews {
        high: range_tags(high),
        suspected: range_tags(suspected),
        partial: range_tags(partial_high)
            .into_iter()
            .map(|r| Span {
                v: Tag::PartialAnycast,
                ..r
            })
            .collect(),
        stats,
    })
}
fn routes(data: &[u8], family: u8, peers: u64) -> Result<Vec<Span>> {
    let mut reader = BufReader::new(flate2::read::GzDecoder::new(data).take(MAX_EXPANDED + 1));
    let mut text = String::new();
    let mut expanded = 0;
    let mut networks: BTreeMap<(u128, u128, u8), BTreeSet<u32>> = BTreeMap::new();
    while reader.read_line(&mut text)? > 0 {
        expanded += text.len() as u64;
        ensure!(expanded <= MAX_EXPANDED, "gzip expansion oversized");
        let line = text.trim();
        if line.is_empty() || line.starts_with(['%', '#']) {
            text.clear();
            continue;
        }
        let v: Vec<_> = line.split_whitespace().collect();
        ensure!(v.len() >= 3, "invalid RIS record");
        let net: ipnet::IpNet = v[1].parse()?;
        let (f, s, e) = ip_parts(net);
        ensure!(f == family && net == net.trunc(), "invalid RIS network");
        if net.prefix_len() == 0 || v[2].parse::<u64>()? < peers {
            text.clear();
            continue;
        }
        let values = networks.entry((s, e, net.prefix_len())).or_default();
        for a in v[0]
            .replace(['{', '}'], "")
            .replace(';', ",")
            .split(',')
            .filter(|x| !x.is_empty())
        {
            let a = a.parse::<u32>()?;
            ensure!(a > 0, "invalid ASN");
            values.insert(a);
        }
        ensure!(!values.is_empty(), "empty origins");
        text.clear();
    }
    ensure!(
        networks.len() >= if family == 4 { 500000 } else { 100000 },
        "RIS coverage collapsed"
    );
    let mut rows: Vec<_> = networks
        .into_iter()
        .map(|((s, e, len), a)| Span {
            s,
            e,
            v: Tag::Route(Arc::new(Route {
                prefix: format!("{}/{len}", ip_text(family, s)),
                origins: a.into_iter().collect(),
            })),
        })
        .collect();
    rows.sort_unstable_by_key(|s| (s.s, std::cmp::Reverse(s.e)));
    // Flatten the CIDR tree to longest-prefix disjoint segments.
    let mut stack: Vec<(Option<u128>, u128, Tag)> = vec![];
    let mut out = vec![];
    fn pop(stack: &mut Vec<(Option<u128>, u128, Tag)>, out: &mut Vec<Span>) {
        let (cursor, end, v) = stack.pop().expect("nonempty stack");
        if let Some(s) = cursor
            && s <= end
        {
            out.push(Span { s, e: end, v })
        }
        if let Some(p) = stack.last_mut() {
            p.0 = match (p.0, end.checked_add(1)) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
        }
    }
    for row in rows {
        while stack.last().is_some_and(|p| p.1 < row.s) {
            pop(&mut stack, &mut out)
        }
        if let Some(p) = stack.last() {
            ensure!(row.e <= p.1, "non-nested RIS overlap");
            if let Some(s) = p.0
                && s < row.s
            {
                out.push(Span {
                    s,
                    e: row.s - 1,
                    v: p.2.clone(),
                });
            }
        }
        stack.push((Some(row.s), row.e, row.v));
    }
    while !stack.is_empty() {
        pop(&mut stack, &mut out)
    }
    coalesce(out, true)
}
fn feeds(
    data: &[u8],
    map: &BTreeMap<String, u8>,
    unknown: &BTreeSet<String>,
) -> Result<BTreeMap<u8, Vec<Span>>> {
    let mut events: BTreeMap<u8, Vec<(u128, u8, i32)>> = BTreeMap::new();
    let mut count = 0;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(data);
    for row in reader.records() {
        let row = row?;
        if row.is_empty() {
            continue;
        }
        ensure!(row.len() >= 2, "invalid geofeed");
        let net: ipnet::IpNet = row[0].trim().trim_start_matches('\u{feff}').parse()?;
        ensure!(net == net.trunc(), "noncanonical geofeed");
        count += 1;
        let (f, s, e) = ip_parts(net);
        if let Some(r) = region(&row[1], map, unknown)? {
            let v = events.entry(f).or_default();
            v.push((s, r, 1));
            if let Some(next) = e.checked_add(1) {
                v.push((next, r, -1))
            }
        }
    }
    ensure!(count >= 10000, "geofeed coverage collapsed");
    let mut out = BTreeMap::new();
    for (f, mut edges) in events {
        edges.sort_unstable();
        let mut values = BTreeMap::<u8, i32>::new();
        let mut prev = None;
        let mut rows = vec![];
        let mut i = 0;
        while i < edges.len() {
            let point = edges[i].0;
            if let Some(s) = prev
                && s < point
                && !values.is_empty()
            {
                rows.push(Span {
                    s,
                    e: point - 1,
                    v: Tag::Hints(values.keys().copied().collect()),
                })
            }
            while i < edges.len() && edges[i].0 == point {
                let (_, r, d) = edges[i];
                let v = values.entry(r).or_default();
                *v += d;
                ensure!(*v >= 0, "invalid geofeed events");
                if *v == 0 {
                    values.remove(&r);
                }
                i += 1;
            }
            prev = Some(point);
        }
        if let Some(s) = prev
            && !values.is_empty()
        {
            rows.push(Span {
                s,
                e: u128::MAX,
                v: Tag::Hints(values.keys().copied().collect()),
            })
        }
        out.insert(f, coalesce(rows, true)?);
    }
    Ok(out)
}
fn overlay(views: &[Vec<Span>], mut emit: impl FnMut(u128, u128, &[Option<Tag>])) {
    let mut indexes = vec![0; views.len()];
    let mut values = vec![None; views.len()];
    let mut end_edges = vec![false; views.len()];
    let mut point = None;
    loop {
        let next = views
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                v.get(indexes[i]).and_then(|r| {
                    if end_edges[i] {
                        r.e.checked_add(1)
                    } else {
                        Some(r.s)
                    }
                })
            })
            .min();
        if let Some(start) = point {
            let end = next.map(|n| n - 1).unwrap_or(u128::MAX);
            if start <= end
                && values.iter().any(|v| {
                    matches!(
                        v,
                        Some(
                            Tag::Region(_)
                                | Tag::NoLocationOpinion
                                | Tag::NetworkRegion(_)
                                | Tag::FactualRegion(_)
                        )
                    )
                })
            {
                emit(start, end, &values)
            }
        }
        let Some(p) = next else { break };
        for (i, view) in views.iter().enumerate() {
            while let Some(row) = view.get(indexes[i]) {
                let edge = if end_edges[i] {
                    row.e.checked_add(1)
                } else {
                    Some(row.s)
                };
                if edge != Some(p) {
                    break;
                }
                if end_edges[i] {
                    values[i] = None;
                    end_edges[i] = false;
                    indexes[i] += 1;
                } else {
                    values[i] = Some(row.v.clone());
                    end_edges[i] = true;
                }
            }
        }
        point = Some(p);
    }
}
// Operator lists are partial positive network claims, not independent location proofs.
// Their absence is unknown; they cannot override geolocation votes or suppress publication.
fn network_claim(data: &[u8], family: u8, region: u8) -> Result<(Vec<Span>, usize)> {
    let mut ranges = vec![];
    let mut count = 0;
    for line in std::str::from_utf8(data)?
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let net: ipnet::IpNet = line.parse()?;
        let (f, s, e) = ip_parts(net);
        ensure!(
            f == family && net == net.trunc(),
            "invalid network IP claim"
        );
        ranges.push((s, e));
        count += 1;
    }
    ensure!(count > 0, "empty network IP claim source");
    Ok((
        union(ranges)
            .into_iter()
            .map(|(s, e)| Span {
                s,
                e,
                v: Tag::NetworkRegion(region),
            })
            .collect(),
        count,
    ))
}
#[derive(Debug)]
struct ConflictGroup {
    route: Option<Arc<Route>>,
    subject: String,
    regions: Vec<String>,
    parts: Vec<Value>,
}
#[derive(Default)]
struct Partition {
    accepted: BTreeMap<String, Vec<(u128, u128)>>,
    cases: BTreeMap<String, ConflictGroup>,
    baseline: BTreeSet<String>,
    network_divergences: usize,
    network_only: usize,
    resolved: Vec<ResolvedRange>,
    observed_segments: usize,
    coverage_gaps: Vec<(u128, u128)>,
}
#[cfg(test)]
fn partition(f: u8, views: &[Vec<Span>], names: &[String], network_ids: &[String]) -> Partition {
    partition_with_facts(f, views, names, network_ids, None, &BTreeSet::new())
}
fn partition_with_facts(
    f: u8,
    views: &[Vec<Span>],
    names: &[String],
    network_ids: &[String],
    factual_index: Option<usize>,
    observed: &BTreeSet<u128>,
) -> Partition {
    let mut out = Partition::default();
    let mut last_resolved_end: Option<u128> = None;
    let mut unrouted: Vec<(u128, u128, Vec<String>, Vec<Value>)> = vec![];
    overlay(views, |s, e, v| {
        let opinion = |i: usize| match &v[i] {
            Some(Tag::Region(r)) => Some(names[*r as usize].clone()),
            _ => None,
        };
        let first = opinion(0);
        let second = opinion(1);
        // Match reusable actual-target observations for every object, including
        // agreements; their scope is reachability, never a location vote.
        let has_observation = observed.range(s..=e).next().is_some();
        out.observed_segments += usize::from(has_observation);
        let network: Vec<_> = network_ids
            .iter()
            .enumerate()
            .filter_map(|(i, id)| {
                match &v[6+i] {Some(Tag::NetworkRegion(r)) => Some(json!({"source_id":id,"region":names[*r as usize],"role":"network-advisory-not-location-vote"})),_ => None}
            })
            .collect();
        let candidates: Vec<_> = (0..2)
            .filter_map(opinion)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let route = match &v[4] {
            Some(Tag::Route(r)) => Some(r.clone()),
            _ => None,
        };
        let key = route
            .as_ref()
            .map(|r| format!("{f}:{}:{}", r.prefix, candidates.join("|")));
        if candidates.len() > 1
            && let Some(key) = &key
        {
            out.baseline.insert(key.clone());
        }
        // A factual target/prefix attestation is checked even when both datasets agree.
        let factual = factual_index.and_then(|i| match v.get(i) {
            Some(Some(Tag::FactualRegion(r))) => Some(names[*r as usize].clone()),
            _ => None,
        });
        let choice = factual
            .clone()
            .map(|r| (r, "qualified-target-location"))
            .or_else(|| {
                crate::fusion::choose_installed_region(first.as_deref(), second.as_deref())
            });
        if choice.is_none()
            && v[..2]
                .iter()
                .any(|value| matches!(value, Some(Tag::NoLocationOpinion)))
        {
            // Preserve the exact raw-source difference, including under an Anycast
            // flag. Unknown labels are not votes or a fabricated geographic region.
            append_range(&mut out.coverage_gaps, s, e);
        }
        if let Some((region, basis)) = choice {
            let record = ResolvedRange {
                family: f,
                start: ip_text(f, s),
                end: ip_text(f, e),
                region: region.clone(),
                basis,
                anycast: v[2].is_some(),
                confidence: if factual.is_some() {
                    "qualified-factual"
                } else if first.is_some() && first == second {
                    "source-agreement"
                } else {
                    "source-fallback"
                },
                sources: first
                    .as_ref()
                    .map(|_| "iplocate")
                    .into_iter()
                    .chain(second.as_ref().map(|_| "dbip"))
                    .chain(factual.as_ref().map(|_| "qualified-target-location"))
                    .collect(),
            };
            if let Some(last) = out.resolved.last_mut()
                && last_resolved_end.and_then(|end| end.checked_add(1)) == Some(s)
                && last.region == record.region
                && last.basis == record.basis
                && last.anycast == record.anycast
                && last.confidence == record.confidence
                && last.sources == record.sources
            {
                last.end = record.end;
            } else {
                out.resolved.push(record);
            }
            last_resolved_end = Some(e);
            if v[2].is_none() {
                append_range(out.accepted.entry(region).or_default(), s, e);
            }
        }
        if v[2].is_some() {
            return;
        }
        if !network.is_empty()
            && network
                .iter()
                .any(|n| !candidates.iter().any(|r| n["region"] == *r))
        {
            out.network_divergences += 1;
        }
        if candidates.is_empty() && !network.is_empty() {
            out.network_only += 1;
        }
        let partial_anycast = v.iter().any(|x| matches!(x, Some(Tag::PartialAnycast)));
        if factual.is_some() || (candidates.len() == 1 && !partial_anycast) {
            return;
        }
        // A sampled response is recorded at its exact target. It neither resolves
        // a geographic disagreement nor proves reachability of this whole interval.
        if candidates.is_empty() {
            return;
        }
        let mut feed = match &v[5] {
            Some(Tag::Hints(r)) => r
                .iter()
                .map(|r| names[*r as usize].clone())
                .collect::<Vec<_>>(),
            _ => vec![],
        };
        feed.sort();
        let origins = route
            .as_ref()
            .map(|r| r.origins.clone())
            .unwrap_or_default();
        // Only location opinions, routing and Anycast evidence define this signature.
        let mut signature = json!([first, second, origins, feed, v[3].is_some()]);
        if partial_anycast {
            signature
                .as_array_mut()
                .unwrap()
                .push(json!("high-partial-anycast"));
        }
        // Hints are retained for review but cannot create country conflicts or invalidate
        // unchanged geographical measurements. Only actual location opinions define candidates.
        let Some(route) = route else {
            if let Some(last) = unrouted.last_mut()
                && last.1.checked_add(1) == Some(s)
                && last.3.last().is_some_and(|p| p[2] == signature)
            {
                last.1 = e;
                last.3.push(json!([s, e, signature, network]));
            } else {
                unrouted.push((s, e, candidates, vec![json!([s, e, signature, network])]));
            }
            return;
        };
        let parts = &mut out
            .cases
            .entry(key.unwrap())
            .or_insert_with(|| ConflictGroup {
                subject: route.prefix.clone(),
                route: Some(route),
                regions: candidates,
                parts: vec![],
            })
            .parts;
        if let Some(last) = parts.last_mut()
            && number(&last[1]).and_then(|n| n.checked_add(1)) == Some(s)
            && last[2] == signature
            && last[3] == json!(network)
        {
            last[1] = json!(e);
        } else {
            parts.push(json!([s, e, signature, network]));
        }
    });
    // A missing route in this RIS view cannot silently discard a disagreement.
    for (s, e, regions, parts) in unrouted {
        let subject = format!("{}-{}", ip_text(f, s), ip_text(f, e));
        out.cases.insert(
            format!("{f}:unrouted:{subject}:{}", regions.join("|")),
            ConflictGroup {
                route: None,
                subject,
                regions,
                parts,
            },
        );
    }
    out
}
// Advisory boundary changes must not churn the location evidence cache.
fn fingerprint_parts(parts: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = vec![];
    for p in parts {
        let semantic = json!([p[2][0], p[2][1], p[2][4], p[2][5]]);
        if let Some(last) = out.last_mut()
            && number(&last[1]).and_then(|n| n.checked_add(1)) == number(&p[0])
            && last[2] == semantic
        {
            last[1] = p[1].clone();
        } else {
            out.push(json!([p[0], p[1], semantic]));
        }
    }
    out
}

fn needs_endpoint(part: &Value) -> bool {
    part[2][4] == true || part[2][5] == "high-partial-anycast"
}

// A network hint is not a new location opinion. Preserve the full source rows
// for review, but do not split sampling work merely because a hint changed.
fn sampling_signature(part: &Value) -> Value {
    let origins = part[2][2]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect::<BTreeSet<_>>();
    json!([
        part[2][0],
        part[2][1],
        origins,
        part[2][4] == true,
        part[2][5] == "high-partial-anycast"
    ])
}

fn range_subject(family: u8, start: u128, end: u128) -> String {
    let blocks = cidrs(family, start, end);
    if blocks.len() == 1 {
        blocks.into_iter().next().unwrap()
    } else {
        format!("{}-{}", ip_text(family, start), ip_text(family, end))
    }
}

/// Only executable endpoint work needs a homogeneous, continuous scope.
/// Unmeasurable source disagreements keep their compact catalogue grouping.
fn sampling_groups(
    family: u8,
    parent: &str,
    group: ConflictGroup,
) -> Result<Vec<(String, ConflictGroup)>> {
    if !group.parts.iter().any(needs_endpoint) {
        return Ok(vec![(parent.into(), group)]);
    }
    let ConflictGroup {
        route,
        subject,
        regions,
        parts,
    } = group;
    let mut passive = Vec::new();
    let mut units: Vec<Vec<Value>> = Vec::new();
    for part in parts {
        if !needs_endpoint(&part) {
            passive.push(part);
            continue;
        }
        if let Some(unit) = units.last_mut()
            && unit.last().is_some_and(|last| {
                number(&last[1]).and_then(|n| n.checked_add(1)) == number(&part[0])
                    && sampling_signature(last) == sampling_signature(&part)
            })
        {
            unit.push(part);
        } else {
            units.push(vec![part]);
        }
    }
    let keep_key = passive.is_empty() && units.len() == 1;
    let mut out = Vec::with_capacity(units.len() + usize::from(!passive.is_empty()));
    if !passive.is_empty() {
        out.push((
            parent.into(),
            ConflictGroup {
                route: route.clone(),
                subject,
                regions: regions.clone(),
                parts: passive,
            },
        ));
    }
    for parts in units {
        let first = parts.first().context("empty sampling unit")?;
        let start = number(&first[0]).context("sampling range start")?;
        let end = number(&parts.last().unwrap()[1]).context("sampling range end")?;
        let signature = fingerprint(&sampling_signature(first));
        let key = if keep_key {
            parent.into()
        } else {
            format!(
                "{parent}:sample:{}-{}:{}",
                ip_text(family, start),
                ip_text(family, end),
                &signature[..12]
            )
        };
        out.push((
            key,
            ConflictGroup {
                route: route.clone(),
                subject: range_subject(family, start, end),
                regions: regions.clone(),
                parts,
            },
        ));
    }
    Ok(out)
}

fn coverage_gap_cases(family: u8, ranges: &[(u128, u128)]) -> Vec<CaseInput> {
    ranges.iter().map(|(start,end)| {
        let start=ip_text(family,*start);let end=ip_text(family,*end);
        let payload=json!({"kind":"coverage-gap","family":family,"ranges":[[start,end]],"regions":[],"targets":[],"measurement_required":false,"requires_target_discovery":false,"missing_fact":"no mapped geolocation opinion or qualified target-location fact in known input scope","publication":"explicitly outside the mapped geolocation + qualified-fact union; no fabricated country","evidence_scope":"exact raw input range only; no route-only or whole-Internet expansion"});
        CaseInput{key:format!("coverage-gap:{family}:{start}-{end}"),fingerprint:fingerprint(&json!(["coverage-gap-v1",family,start,end])),kind:"coverage-gap".into(),subject:format!("{start}-{end}"),reason:"known input range has no usable target geolocation; coverage gap retained explicitly".into(),payload}
    }).collect()
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ResolvedRange {
    pub family: u8,
    pub start: String,
    pub end: String,
    pub region: String,
    pub basis: &'static str,
    pub anycast: bool,
    pub confidence: &'static str,
    pub sources: Vec<&'static str>,
}
pub struct GeoResult {
    /// Full mapped-source union, including an explicit geographic fallback for Anycast.
    pub resolved: Vec<ResolvedRange>,
    pub rules: BTreeMap<String, BTreeSet<Rule>>,
    pub cases: Vec<CaseInput>,
    pub report: Value,
}

fn exact_target_evidence(
    family: u8,
    ranges: &[(u128, u128)],
    facts: &crate::fusion::Snapshot,
) -> Result<(Vec<String>, BTreeMap<String, Value>)> {
    // Bound extra allocations even when a large range contains many DNS
    // candidates. The extremes and the midpoint neighbours provide a spread
    // without cloning the complete frozen candidate map.
    let mut known = BTreeMap::new();
    let valid = |(ip, observation): &(&IpAddr, &crate::discovery::Observation)| {
        observation.ip == **ip
            && crate::measure::public_ip(**ip)
            && matches!(observation.kind, "dns-answer" | "endpoint-response")
            && observation.observed > 0
            && observation.observed <= facts.observed_at
            && observation.valid_until > facts.observed_at
    };
    let mut remember = |row: Option<(&IpAddr, &crate::discovery::Observation)>| {
        if let Some((ip, observation)) = row {
            known.entry(*ip).or_insert_with(|| json!({"kind":observation.kind,"source":observation.source,"observed":observation.observed,"valid_until":observation.valid_until}));
        }
    };
    for &(start, end) in ranges {
        let first: IpAddr = ip_text(family, start).parse()?;
        let last: IpAddr = ip_text(family, end).parse()?;
        let middle: IpAddr = ip_text(family, start + (end - start) / 2).parse()?;
        remember(facts.target_candidates.range(first..=last).find(valid));
        remember(
            facts
                .target_candidates
                .range(first..=last)
                .rev()
                .find(valid),
        );
        remember(
            facts
                .target_candidates
                .range(first..=middle)
                .rev()
                .find(valid),
        );
        remember(facts.target_candidates.range(middle..=last).find(valid));
    }
    let mut selected = crate::sampling::select_targets(
        family,
        ranges,
        &[],
        &known.into_iter().collect::<Vec<_>>(),
        3,
        false,
    );
    selected.sort_unstable_by_key(|row| row.0);
    let mut targets = Vec::with_capacity(selected.len());
    let mut evidence = BTreeMap::new();
    for (ip, row) in selected {
        let target = ip.to_string();
        targets.push(target.clone());
        evidence.insert(target, row);
    }
    Ok((targets, evidence))
}
fn geographic_case(
    f: u8,
    key: String,
    parent: &str,
    group: ConflictGroup,
    facts: &crate::fusion::Snapshot,
) -> Result<CaseInput> {
    let ConflictGroup {
        route,
        subject,
        regions,
        parts,
    } = group;
    // Advisory-only changes do not invalidate location evidence or enqueue new probes.
    let fp = fingerprint(&json!([
        "missing-target-observation-v2",
        fingerprint_parts(&parts)
    ]));
    let mut spans = vec![];
    let mut origins = BTreeSet::new();
    let mut feed = BTreeSet::new();
    let mut suspect = false;
    for p in &parts {
        spans.push((
            number(&p[0]).context("IP start")?,
            number(&p[1]).context("IP end")?,
        ));
        if let Some(a) = p[2][2].as_array() {
            origins.extend(a.iter().filter_map(Value::as_u64));
        }
        if let Some(a) = p[2][3].as_array() {
            feed.extend(a.iter().filter_map(|s| s.as_str().map(str::to_string)));
        }
        suspect |= p[2][4].as_bool().unwrap_or(false);
    }
    let behavior_missing = suspect || parts.iter().any(|p| p[2][5] == "high-partial-anycast");
    let kind = if behavior_missing {
        "endpoint-reachability"
    } else {
        "geolocation"
    };
    let ranges = union(spans);
    let (targets, target_evidence) = if behavior_missing {
        exact_target_evidence(f, &ranges, facts)?
    } else {
        (Vec::new(), BTreeMap::new())
    };
    let mut payload = json!({"kind":kind,"family":f,"bgp_prefix":route.as_ref().map(|r| &r.prefix),"routing_visibility":if route.is_some() {"visible-in-selected-RIS-view"} else {"not-seen-in-selected-RIS-view"},"source_opinions":parts.iter().map(|p|json!({"range":[ip_text(f,number(&p[0]).unwrap()),ip_text(f,number(&p[1]).unwrap())],"iplocate_region":p[2][0],"dbip_region":p[2][1],"network_advisories":p[3]})).collect::<Vec<_>>(),"network_claim_sources":parts.iter().filter_map(|p|p[3].as_array()).flatten().map(|p|(p["source_id"].as_str().unwrap_or("").to_string(),p.clone())).collect::<BTreeMap<_,_>>(),"regions":regions,"ranges":ranges.iter().map(|(s,e)|[ip_text(f,*s),ip_text(f,*e)]).collect::<Vec<_>>(),"origin_asns":origins,"geofeed_regions":feed,"targets":targets,"target_evidence":target_evidence,"observation_goal":"endpoint-reachability","repeat_on_build":false,"measurement_required":behavior_missing,"requires_target_discovery":behavior_missing && targets.is_empty(),"missing_fact":if behavior_missing {"qualified location or Anycast classification; this probe only checks exact-target reachability"} else {"qualified target location; traceroute cannot answer country"},"purpose":"exact-target reachability only; not country or Anycast adjudication","publication":"deterministic geographic fallback already emitted","target_selection":"exact DNS or endpoint-response target only; never enumerate an IPv6 subnet","evidence_scope":"ranges above only; never infer whole parent prefix","geofeed_authority":"aggregate-advisory-only","sample_plan":{"targets_per_group":3,"goal":"exact-target reachability; not geographic ownership or Anycast classification","no_fixed_quorum":true}});
    if behavior_missing {
        payload["sample_plan"] = json!({
            "strategy":"bgp-bounded-v1",
            "targets_per_group":3,
            "parent_case_key":parent,
            "seed":crate::sampling::seed(f, &ranges),
            "allow_ipv4_candidates":true,
            "goal":"exact-target reachability; not geographic ownership or Anycast classification",
            "no_fixed_quorum":true
        });
        payload["target_selection"] = json!(
            "prefer known DNS or endpoint-response addresses; bounded stable IPv4 candidates may supplement this exact sampling range; never enumerate IPv6"
        );
    }
    Ok(CaseInput {
        key,
        fingerprint: fp,
        kind: kind.into(),
        subject,
        reason: if behavior_missing {
            "deterministic fallback published; exact-target reachability is outstanding, country and Anycast remain unproven"
        } else {
            "deterministic source fallback published; qualified target location fact is absent"
        }
        .into(),
        payload,
    })
}

pub fn reconcile(
    root: &Path,
    input: &mut Inputs,
    iplocate: &[u8],
    rule_data: &BTreeMap<String, Vec<u8>>,
) -> Result<GeoResult> {
    reconcile_with_facts(
        root,
        input,
        iplocate,
        rule_data,
        &crate::fusion::Snapshot::default(),
    )
}
pub fn reconcile_with_facts(
    root: &Path,
    input: &mut Inputs,
    iplocate: &[u8],
    rule_data: &BTreeMap<String, Vec<u8>>,
    facts: &crate::fusion::Snapshot,
) -> Result<GeoResult> {
    let mut cases = Vec::new();
    let mut result =
        reconcile_with_facts_into(root, input, iplocate, rule_data, facts, &mut |case| {
            cases.push(case);
            Ok(())
        })?;
    result.cases = cases;
    Ok(result)
}

pub(crate) fn reconcile_with_facts_into(
    root: &Path,
    input: &mut Inputs,
    iplocate: &[u8],
    rule_data: &BTreeMap<String, Vec<u8>>,
    facts: &crate::fusion::Snapshot,
    emit: &mut dyn FnMut(CaseInput) -> Result<()>,
) -> Result<GeoResult> {
    facts.validate()?;
    let config: Value = read_json(&root.join("config/geography.json"))?;
    let entries = config["regions"].as_array().context("regions")?;
    let names: Vec<String> = entries
        .iter()
        .map(|r| r["id"].as_str().unwrap_or("").into())
        .collect();
    let mut map = BTreeMap::new();
    for (i, r) in entries.iter().enumerate() {
        for cc in r["codes"].as_array().context("region codes")? {
            ensure!(
                map.insert(cc.as_str().context("country")?.to_string(), i as u8)
                    .is_none(),
                "country mapped twice"
            )
        }
    }
    let unknown: BTreeSet<_> = config["unknown_codes"]
        .as_array()
        .context("unknown country codes")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    ensure!(
        unknown.iter().all(|x| !map.contains_key(x)),
        "unknown region code mapped"
    );
    let mut data = BTreeMap::new();
    let progress = input.progress.clone();
    if let Some(p) = &progress {
        p.units(
            0,
            Some(config["sources"].as_object().context("geo sources")?.len()),
            "个地理来源",
            "读取地理、路由与 Anycast 来源",
        )?;
        p.flush()?;
    }
    for (name, source) in config["sources"].as_object().context("geo sources")? {
        tracing::info!(source = name, "load geography input");
        data.insert(name.clone(), input.mutable(name, source)?);
        if let Some(p) = &progress {
            p.advance(format!("已读取 {name}"))?;
        }
    }
    if let Some(p) = &progress {
        p.units(0, None, "行地理记录", "解析 IPLocate 与 DB-IP 地址范围")?;
        p.flush()?;
    }
    let dbip = data.remove("dbip").context("DB-IP input")?;
    let (mut products, counts) = geoip(iplocate, &dbip, &map, &unknown, progress.as_ref())?;
    drop(dbip);
    if let Some(p) = &progress {
        p.work("整理 geofeed 提示")?;
    }
    let geofeed = data.remove("geofeed").context("geofeed input")?;
    let mut hints = feeds(&geofeed, &map, &unknown)?;
    drop(geofeed);
    let mut rules = BTreeMap::<String, BTreeSet<Rule>>::new();
    for n in &names {
        rules.insert(n.clone(), BTreeSet::new());
    }
    rules.insert("anycast".into(), BTreeSet::new());
    let mut cases = BTreeMap::<(u8, String), ConflictGroup>::new();
    let mut network_counts = BTreeMap::new();
    let mut anycast_counts = BTreeMap::new();
    let mut network_divergences = 0usize;
    let mut network_only = 0usize;
    let mut observed_segments = 0usize;
    let mut coverage_gaps = BTreeMap::<u8, Vec<(u128, u128)>>::new();
    let ip_policy = crate::ip_policy::Policy::load(root)?;
    let mut baseline = BTreeSet::new();
    let mut deferred = BTreeMap::new();
    let mut resolved = Vec::new();
    let mut observed = BTreeMap::<u8, BTreeSet<u128>>::new();
    for observation in &facts.observations {
        if observation.kind == "traceroute"
            && observation.reached
            && observation.observed_at <= facts.observed_at
            && observation.valid_until > facts.observed_at
            && let Ok(ip) = observation.target.parse::<IpAddr>()
        {
            let (family, address) = addr_num(ip);
            observed.entry(family).or_default().insert(address);
        }
    }
    if let Some(p) = &progress {
        p.units(0, Some(2), "个地址族", "核查 IPv4 地址、路由与 Anycast")?;
        p.flush()?;
    }
    for f in [4u8, 6] {
        if let Some(p) = &progress {
            p.work(format!("对齐 IPv{f} 的多源地址区间、路由与 Anycast"))?;
            p.flush()?;
        }
        let anycast_input = data
            .remove(&format!("anycast{f}"))
            .context("Anycast input")?;
        let AnycastViews {
            high,
            suspected,
            partial,
            stats,
        } = anycast(&anycast_input, f)?;
        drop(anycast_input);
        anycast_counts.insert(f.to_string(), stats);
        let mut high: Vec<_> = high.into_iter().map(|r| (r.s, r.e)).collect();
        let cloudflare = data
            .remove(&format!("cloudflare{f}"))
            .context("official Anycast input")?;
        for line in std::str::from_utf8(&cloudflare)?
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let (g, s, e) = ip_parts(line.parse()?);
            ensure!(g == f, "official Anycast family");
            high.push((s, e));
        }
        drop(cloudflare);
        for prefix in config["official_anycast"]["prefixes"]
            .as_array()
            .context("official prefixes")?
        {
            let (g, s, e) = ip_parts(prefix.as_str().context("prefix")?.parse()?);
            if g == f {
                high.push((s, e));
            }
        }
        let high = range_tags(high);
        for span in &high {
            for c in cidrs(f, span.s, span.e) {
                rules.get_mut("anycast").unwrap().insert(Rule::new(
                    if f == 4 { "IP-CIDR" } else { "IP-CIDR6" },
                    &c,
                    &["no-resolve"],
                )?);
            }
        }
        let ris = data.remove(&format!("ris{f}")).context("RIS input")?;
        let route = routes(&ris, f, config["minimum_ris_peers"].as_u64().unwrap_or(10))?;
        drop(ris);
        let mut views = vec![
            products[0].remove(&f).unwrap_or_default(),
            products[1].remove(&f).unwrap_or_default(),
            high,
            suspected,
            route,
            hints.remove(&f).unwrap_or_default(),
        ];
        let mut network_ids = vec![];
        for claim in config["network_claims"]
            .as_array()
            .context("network claim sources")?
        {
            if claim["family"].as_u64() != Some(f.into()) {
                continue;
            }
            let source = claim["source_id"].as_str().context("network source id")?;
            ensure!(
                !network_ids.iter().any(|id| id == source),
                "duplicate network claim source"
            );
            let name = claim["region"].as_str().context("network claim region")?;
            let index = names
                .iter()
                .position(|n| n == name)
                .context("unknown network region")?;
            let (spans, count) = network_claim(
                rule_data.get(source).context("missing network IP source")?,
                f,
                index as u8,
            )?;
            network_counts.insert(source.to_string(), count);
            network_ids.push(source.to_string());
            views.push(spans);
        }
        views.push(partial);
        let factual_index = views.len();
        views.push(
            facts
                .location_spans(f, &map)?
                .into_iter()
                .map(|(s, e, r)| Span {
                    s,
                    e,
                    v: Tag::FactualRegion(r),
                })
                .collect(),
        );
        // Exclude non-public and protocol service space before generating either outputs or cases.
        for (i, view) in views.iter_mut().enumerate() {
            if !(2..6).contains(&i) {
                *view = view
                    .iter()
                    .flat_map(|r| {
                        crate::ip_policy::subtract(r.s, r.e, ip_policy.geographic(f))
                            .into_iter()
                            .map(|(s, e)| Span {
                                s,
                                e,
                                v: r.v.clone(),
                            })
                    })
                    .collect();
            }
        }
        let result = partition_with_facts(
            f,
            &views,
            &names,
            &network_ids,
            Some(factual_index),
            observed.get(&f).unwrap_or(&BTreeSet::new()),
        );
        coverage_gaps.insert(f, result.coverage_gaps);
        resolved.extend(result.resolved);
        network_divergences += result.network_divergences;
        network_only += result.network_only;
        observed_segments += result.observed_segments;
        baseline.extend(result.baseline);
        deferred.insert(
            f.to_string(),
            result.cases.values().filter(|c| c.route.is_none()).count(),
        );
        cases.extend(result.cases.into_iter().map(|(key, c)| ((f, key), c)));
        for (region, spans) in result.accepted {
            for (s, e) in spans {
                for c in cidrs(f, s, e) {
                    rules.get_mut(&region).unwrap().insert(Rule::new(
                        if f == 4 { "IP-CIDR" } else { "IP-CIDR6" },
                        &c,
                        &["no-resolve"],
                    )?);
                }
            }
        }
        tracing::info!(family = f, conflicts = cases.len(), "geography reconciled");
        if let Some(p) = &progress {
            p.advance(format!("IPv{f} 核查完成"))?;
        }
    }
    if let Some(p) = &progress {
        p.work("整理跨地区争议、来源指纹与统计")?;
        p.flush()?;
    }
    let mut per_region = BTreeMap::<String, usize>::new();
    let mut kind_counts = BTreeMap::<String, usize>::new();
    let mut coverage_gap_groups = 0;
    for (family, ranges) in &coverage_gaps {
        for case in coverage_gap_cases(*family, ranges) {
            coverage_gap_groups += 1;
            emit(case)?;
        }
    }
    if coverage_gap_groups > 0 {
        kind_counts.insert("coverage-gap".into(), coverage_gap_groups);
    }
    let mut active_required_groups = 0;
    let mut non_measurable_location_gaps = 0;
    let mut with_hint = 0;
    let routed_groups = cases
        .values()
        .filter(|c| c.route.is_some() && c.regions.len() > 1)
        .count();
    for ((f, parent), group) in cases {
        for (key, group) in sampling_groups(f, &parent, group)? {
            let case = geographic_case(f, key, &parent, group, facts)?;
            for region in case.payload["regions"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                *per_region.entry(region.to_string()).or_default() += 1;
            }
            with_hint += usize::from(
                case.payload["geofeed_regions"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
            );
            *kind_counts.entry(case.kind.clone()).or_default() += 1;
            let measurable = case.payload["measurement_required"] == true;
            active_required_groups += usize::from(measurable);
            non_measurable_location_gaps += usize::from(!measurable);
            emit(case)?;
        }
    }
    let active_kinds: BTreeMap<_, _> = kind_counts
        .iter()
        .filter(|(kind, _)| kind.as_str() == "endpoint-reachability")
        .collect();
    let report = json!({
        "geoip_rows":counts,
        "source_disagreement_route_groups":baseline.len(),
        "unresolved_route_groups":routed_groups,
        "network_claim_rows":network_counts,
        "network_advisory_divergence_segments":network_divergences,
        "network_only_unknown_segments":network_only,
        "active_required_groups":active_required_groups,
        "non_measurable_location_gaps":non_measurable_location_gaps,
        "coverage_gap_ranges":coverage_gaps.iter().map(|(family,ranges)|(family.to_string(),ranges.len())).collect::<BTreeMap<_,_>>(),
        "coverage_gap_groups":coverage_gap_groups,
        "anycast_input_rows":anycast_counts,
        "active_required_kinds":active_kinds,
        "case_kinds":kind_counts,
        "regions":per_region,
        "geofeed_hints":with_hint,
        "unrouted_missing_fact_groups":deferred,
        "passively_resolved_by_geofeed":0
    });
    let mut report = report;
    report["fusion"] = if facts.summary.is_object() {
        facts.summary.clone()
    } else {
        json!({})
    };
    report["fusion"]["qualified_target_location_facts"] = json!(
        facts
            .location_facts
            .iter()
            .filter(|f| f.observed_at > 0
                && f.observed_at <= facts.observed_at
                && f.valid_until > facts.observed_at
                && f.observed_at >= facts.observed_at.saturating_sub(7 * 86400))
            .count()
    );
    report["fusion"]["qualified_domain_owner_facts"] = json!(
        facts
            .domain_facts
            .iter()
            .filter(|f| f.observed_at > 0
                && f.observed_at <= facts.observed_at
                && f.valid_until > facts.observed_at
                && f.observed_at >= facts.observed_at.saturating_sub(7 * 86400))
            .count()
    );
    report["existing_observations_matched_segments"] = json!(observed_segments);
    report["coverage"] = json!({"contract":"mapped geolocation source and qualified fact union, excluding non-public/protocol space; not all allocated Internet addresses","resolved_segments":resolved.len(),"network_only_without_geolocation_segments":network_only,"true_gap_ranges":coverage_gaps.iter().map(|(family,ranges)|(family.to_string(),ranges.len())).collect::<BTreeMap<_,_>>(),"private_gap_manifest":"coverage-gap entries retain every unresolved raw-source address scope","missing_geolocation":"network classification, BGP and registration countries do not fill geolocation gaps"});
    Ok(GeoResult {
        resolved,
        rules,
        cases: Vec::new(),
        report,
    })
}

fn number(value: &Value) -> Option<u128> {
    value.as_number().and_then(|n| n.as_u128())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn geoip_fixture(codes: [Option<&str>; 2]) -> (Vec<u8>, Vec<u8>) {
        use std::io::Write;
        let mut iplocate = String::from("network,country_code\n");
        let mut dbip = String::new();
        for (index, code) in codes.into_iter().enumerate() {
            let Some(code) = code else { continue };
            for i in 0..100_000u128 {
                let ip: IpAddr = if index == 0 {
                    std::net::Ipv4Addr::from(0x0b000000 + i as u32).into()
                } else {
                    std::net::Ipv6Addr::from(0x26000000000000000000000000000000 + i).into()
                };
                iplocate += &format!("{ip}/{},{code}\n", if index == 0 { 32 } else { 128 });
                dbip += &format!("{ip},{ip},{code}\n");
            }
        }
        let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        zip.start_file("country.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(iplocate.as_bytes()).unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(dbip.as_bytes()).unwrap();
        (zip.finish().unwrap().into_inner(), gzip.finish().unwrap())
    }
    #[test]
    fn geoip_rejects_missing_address_families_in_each_source() {
        let complete = geoip_fixture([Some("US"), Some("US")]);
        let map = BTreeMap::from([("US".into(), 0)]);
        for family in 0..2 {
            let mut codes = [Some("US"), Some("US")];
            codes[family] = None;
            let incomplete = geoip_fixture(codes);
            for source in 0..2 {
                let inputs = if source == 0 {
                    (&incomplete.0, &complete.1)
                } else {
                    (&complete.0, &incomplete.1)
                };
                assert!(
                    geoip(inputs.0, inputs.1, &map, &BTreeSet::new(), None).is_err(),
                    "source {source} silently accepted missing address family {family}"
                );
            }
        }
    }
    #[test]
    fn geoip_retains_legitimate_unknown_opinions_without_fabricating_votes() {
        let complete = geoip_fixture([Some("US"), Some("US")]);
        let map = BTreeMap::from([("US".into(), 0)]);
        let unknown = BTreeSet::from(["ZZ".into()]);
        for family in 0..2 {
            let mut codes = [Some("US"), Some("US")];
            codes[family] = Some("ZZ");
            let unmapped = geoip_fixture(codes);
            for source in 0..2 {
                let inputs = if source == 0 {
                    (&unmapped.0, &complete.1)
                } else {
                    (&complete.0, &unmapped.1)
                };
                let (products, _) = geoip(inputs.0, inputs.1, &map, &unknown, None).unwrap();
                let address_family = if family == 0 { 4 } else { 6 };
                assert!(
                    products[source][&address_family]
                        .iter()
                        .all(|span| span.v == Tag::NoLocationOpinion)
                );
            }
        }
    }
    #[test]
    fn geoip_accepts_complete_dual_stack_sources() {
        let (iplocate, dbip) = geoip_fixture([Some("US"), Some("US")]);
        let map = BTreeMap::from([("US".into(), 0)]);
        let (products, _) = geoip(&iplocate, &dbip, &map, &BTreeSet::new(), None).unwrap();
        assert!(
            products
                .iter()
                .all(|p| p.contains_key(&4) && p.contains_key(&6))
        );
    }
    fn span(s: u128, e: u128, v: Tag) -> Span {
        Span { s, e, v }
    }
    fn names() -> Vec<String> {
        ["cn-geo", "us", "europe"].map(str::to_string).into()
    }
    fn fixture() -> Vec<Vec<Span>> {
        vec![vec![], vec![], vec![], vec![], vec![], vec![], vec![]]
    }
    fn sampling_part(start: u128, end: u128, origins: &[u32], suspect: bool) -> Value {
        json!([start, end, ["us", "europe", origins, [], suspect], []])
    }
    fn sampling_fixture(parts: Vec<Value>) -> ConflictGroup {
        ConflictGroup {
            route: Some(Arc::new(Route {
                prefix: "11.0.0.0/24".into(),
                origins: vec![64501],
            })),
            subject: "11.0.0.0/24".into(),
            regions: vec!["europe".into(), "us".into()],
            parts,
        }
    }
    #[test]
    fn bgp_sampling_separates_continuity_origin_location_and_anycast_boundaries() {
        let base = addr_num("11.0.0.0".parse().unwrap()).1;
        let parent = "4:11.0.0.0/24:europe|us";
        let mut advisory = sampling_part(base + 64, base + 95, &[64501], true);
        advisory[2][3] = json!(["cn-geo"]);
        advisory[3] = json!([{"source_id":"network-hint","region":"cn-geo"}]);
        let mut reverse = sampling_part(base + 160, base + 191, &[64501], true);
        reverse[2][0] = json!("europe");
        reverse[2][1] = json!("us");
        let mut origin = reverse.clone();
        origin[0] = json!(base + 192);
        origin[1] = json!(base + 223);
        origin[2][2] = json!([64502]);
        let mut partial = origin.clone();
        partial[0] = json!(base + 224);
        partial[1] = json!(base + 255);
        partial[2][4] = json!(false);
        partial[2]
            .as_array_mut()
            .unwrap()
            .push(json!("high-partial-anycast"));
        let units = sampling_groups(
            4,
            parent,
            sampling_fixture(vec![
                sampling_part(base, base + 31, &[64501], false),
                sampling_part(base + 32, base + 63, &[64501], true),
                advisory,
                sampling_part(base + 128, base + 159, &[64501], true),
                reverse,
                origin,
                partial,
            ]),
        )
        .unwrap();
        assert_eq!(units.len(), 6);
        assert_eq!(units[0].0, parent);
        assert!(units[0].1.parts.iter().all(|p| !needs_endpoint(p)));
        let ranges = units
            .iter()
            .skip(1)
            .map(|(_, g)| {
                (
                    number(&g.parts[0][0]).unwrap() - base,
                    number(&g.parts.last().unwrap()[1]).unwrap() - base,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            ranges,
            [(32, 95), (128, 159), (160, 191), (192, 223), (224, 255)]
        );
        for (key, group) in units.into_iter().skip(1) {
            assert!(key.starts_with(&format!("{parent}:sample:")));
            let case = geographic_case(4, key, parent, group, &crate::fusion::Snapshot::default())
                .unwrap();
            assert_eq!(case.kind, "endpoint-reachability");
            assert_eq!(case.payload["ranges"].as_array().unwrap().len(), 1);
            assert_eq!(case.payload["targets"], json!([]));
            assert_eq!(case.payload["sample_plan"]["parent_case_key"], parent);
            assert_eq!(case.payload["sample_plan"]["targets_per_group"], 3);
        }
    }
    #[test]
    fn bgp_sampling_preserves_single_keys_and_ignores_advisory_only_boundaries() {
        let base = addr_num("11.0.0.0".parse().unwrap()).1;
        let parent = "4:11.0.0.0/24:europe|us";
        let first = sampling_part(base, base + 127, &[64501], true);
        let mut second = sampling_part(base + 128, base + 255, &[64501], true);
        second[2][3] = json!(["us"]);
        second[3] = json!([{"source_id":"network-hint","region":"cn-geo"}]);
        let mut units = sampling_groups(4, parent, sampling_fixture(vec![first, second])).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].0, parent);
        let (key, group) = units.pop().unwrap();
        assert_eq!(group.subject, "11.0.0.0/24");
        let a =
            geographic_case(4, key, parent, group, &crate::fusion::Snapshot::default()).unwrap();
        let mut units = sampling_groups(
            4,
            parent,
            sampling_fixture(vec![sampling_part(base, base + 255, &[64501], true)]),
        )
        .unwrap();
        let (key, group) = units.pop().unwrap();
        let b = geographic_case(
            4,
            key,
            parent,
            group,
            &crate::fusion::Snapshot {
                observed_at: 12345,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(a.key, b.key);
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.payload["sample_plan"], b.payload["sample_plan"]);
        assert_eq!(
            a.payload["sample_plan"]["seed"],
            crate::sampling::seed(4, &[(base, base + 255)])
        );
        assert_eq!(a.payload["sample_plan"]["strategy"], "bgp-bounded-v1");
        assert_eq!(a.payload["sample_plan"]["allow_ipv4_candidates"], true);
        assert_eq!(a.payload["repeat_on_build"], false);

        let passive = sampling_fixture(vec![
            sampling_part(base, base + 31, &[64501], false),
            sampling_part(base + 128, base + 255, &[64501], false),
        ]);
        let mut groups = sampling_groups(4, parent, passive).unwrap();
        assert_eq!(groups.len(), 1);
        let (key, group) = groups.pop().unwrap();
        assert_eq!(key, parent);
        assert_eq!(group.parts.len(), 2);
        let passive =
            geographic_case(4, key, parent, group, &crate::fusion::Snapshot::default()).unwrap();
        assert_eq!(passive.kind, "geolocation");
        assert_eq!(passive.payload["measurement_required"], false);
        assert!(passive.payload["sample_plan"].get("strategy").is_none());
    }
    #[test]
    fn bgp_sampling_child_identity_and_seed_survive_advisory_replay() {
        let base = addr_num("11.0.0.0".parse().unwrap()).1;
        let parent = "4:11.0.0.0/24:europe|us";
        let parts = vec![
            sampling_part(base, base + 31, &[64501, 64502], true),
            sampling_part(base + 128, base + 255, &[64501, 64502], true),
        ];
        let mut changed = parts.clone();
        for p in &mut changed {
            p[2][2] = json!([64502, 64501, 64501]);
            p[2][3] = json!(["cn-geo"]);
            p[3] = json!([{"source_id":"changed-hint","region":"cn-geo"}]);
        }
        let cases = |parts| {
            sampling_groups(4, parent, sampling_fixture(parts))
                .unwrap()
                .into_iter()
                .map(|(key, group)| {
                    geographic_case(4, key, parent, group, &crate::fusion::Snapshot::default())
                        .unwrap()
                })
                .collect::<Vec<_>>()
        };
        let before = cases(parts.clone());
        let after = cases(changed);
        assert_eq!(before.len(), 2);
        for (a, b) in before.iter().zip(&after) {
            assert_eq!(a.key, b.key);
            assert_eq!(a.fingerprint, b.fingerprint);
            assert_eq!(
                a.payload["sample_plan"]["seed"],
                b.payload["sample_plan"]["seed"]
            );
        }
        let mut changed_origin = parts;
        changed_origin[0][2][2] = json!([64503]);
        let changed_origin = cases(changed_origin);
        assert_ne!(before[0].key, changed_origin[0].key);
        assert_eq!(before[1].key, changed_origin[1].key);
        assert_eq!(
            before[0].payload["sample_plan"]["seed"],
            changed_origin[0].payload["sample_plan"]["seed"]
        );
    }
    #[test]
    fn bgp_sampling_respects_more_specific_routes_and_disjoint_parent_remainders() {
        let base = addr_num("11.0.0.0".parse().unwrap()).1;
        let parent = Arc::new(Route {
            prefix: "11.0.0.0/23".into(),
            origins: vec![64501],
        });
        let child = Arc::new(Route {
            prefix: "11.0.0.128/25".into(),
            origins: vec![64502],
        });
        let mut v = fixture();
        v[0] = vec![span(base, base + 511, Tag::Region(1))];
        v[1] = vec![span(base, base + 511, Tag::Region(2))];
        v[3] = vec![span(base, base + 511, Tag::Flag)];
        v[4] = vec![
            span(base, base + 127, Tag::Route(parent.clone())),
            span(base + 128, base + 255, Tag::Route(child)),
            span(base + 256, base + 511, Tag::Route(parent)),
        ];
        let out = partition(4, &v, &names(), &[]);
        assert_eq!(out.accepted["us"], [(base, base + 511)]);
        assert_eq!(out.cases.len(), 2);
        let mut scopes = Vec::new();
        for (key, group) in out.cases {
            for (_, unit) in sampling_groups(4, &key, group).unwrap() {
                scopes.push((
                    number(&unit.parts[0][0]).unwrap(),
                    number(&unit.parts.last().unwrap()[1]).unwrap(),
                ));
            }
        }
        scopes.sort();
        assert_eq!(
            scopes,
            [
                (base, base + 127),
                (base + 128, base + 255),
                (base + 256, base + 511)
            ]
        );
    }
    #[test]
    fn bgp_sampling_frozen_targets_are_spread_real_and_scope_limited() {
        let base = addr_num("11.0.0.0".parse().unwrap()).1;
        let mut facts = crate::fusion::Snapshot {
            observed_at: 1000,
            ..Default::default()
        };
        for offset in [1, 2, 3, 128, 250, 251, 300] {
            let ip = std::net::Ipv4Addr::from((base + offset) as u32).into();
            facts.target_candidates.insert(
                ip,
                crate::discovery::Observation {
                    ip,
                    source: format!("retained-result-{offset}"),
                    kind: "dns-answer",
                    observed: 900,
                    valid_until: 1100,
                },
            );
        }
        let (targets, evidence) = exact_target_evidence(4, &[(base, base + 255)], &facts).unwrap();
        assert_eq!(targets.len(), 3);
        let positions = targets
            .iter()
            .map(|t| addr_num(t.parse().unwrap()).1 - base)
            .collect::<Vec<_>>();
        assert!(positions.iter().any(|p| *p < 64));
        assert!(positions.iter().any(|p| *p >= 192));
        assert!(positions.iter().all(|p| *p <= 255));
        assert!(evidence.values().all(|v| v["kind"] == "dns-answer"
            && v["observed"] == 900
            && v["valid_until"] == 1100));
        assert!(facts.location_facts.is_empty());
        assert_eq!(
            exact_target_evidence(4, &[(base + 512, base + 767)], &facts).unwrap(),
            (vec![], BTreeMap::new())
        );
        assert_eq!(
            exact_target_evidence(
                6,
                &[(
                    0x26000000000000000000000000000000,
                    0x2600000000000000000000000000ffff
                )],
                &facts
            )
            .unwrap(),
            (vec![], BTreeMap::new())
        );
    }
    #[test]
    fn cached_us_spain_suspected_anycast_keeps_fallback_and_target_scope() {
        let start = addr_num("3.160.224.0".parse().unwrap()).1;
        let end = addr_num("3.160.239.255".parse().unwrap()).1;
        let suspect = addr_num("3.160.226.0".parse().unwrap()).1;
        let mut views = fixture();
        views[0] = vec![span(start, start + 8191, Tag::Region(1))];
        views[1] = vec![span(start, end, Tag::Region(2))];
        views[3] = vec![span(suspect, suspect + 255, Tag::Flag)];
        let out = partition(4, &views, &names(), &[]);
        assert_eq!(out.accepted["us"], [(start, start + 8191)]);
        assert!(
            out.cases
                .values()
                .any(|group| group.parts.iter().any(|part| part[2][4] == true))
        );
        assert!(
            out.cases
                .values()
                .any(|group| group.parts.iter().all(|part| part[2][4] == false))
        );
        let mut facts = crate::fusion::Snapshot {
            observed_at: 1000,
            ..Default::default()
        };
        for address in ["3.160.226.1", "3.160.225.1", "3.160.226.2"] {
            let ip = address.parse().unwrap();
            facts.target_candidates.insert(
                ip,
                crate::discovery::Observation {
                    ip,
                    source: "explicit local DNS replay".into(),
                    kind: "dns-answer",
                    observed: 900,
                    valid_until: 1100,
                },
            );
        }
        let (targets, evidence) =
            exact_target_evidence(4, &[(suspect, suspect + 255)], &facts).unwrap();
        assert_eq!(targets, ["3.160.226.1", "3.160.226.2"]);
        assert_eq!(evidence.len(), 2);
        assert_eq!(out.resolved[0].basis, "location-source-priority");
    }
    #[test]
    fn network_advisories_do_not_outvote_location_or_generate_false_country_conflicts() {
        let mut v = fixture();
        v[0] = vec![span(0, 255, Tag::Region(1))];
        v[1] = vec![span(0, 255, Tag::Region(1))];
        v[6] = vec![span(64, 191, Tag::NetworkRegion(0))];
        let out = partition(4, &v, &names(), &["G/china.txt".into()]);
        assert_eq!(out.accepted["us"], [(0, 255)]);
        assert!(out.cases.is_empty());
        assert!(out.network_divergences > 0);
        v[0] = vec![span(0, 255, Tag::Region(0))];
        let disputed = partition(4, &v, &names(), &["G/china.txt".into()]);
        assert_eq!(disputed.accepted["cn-geo"], [(0, 255)]);
        assert_eq!(disputed.cases.len(), 1);
        let c = disputed.cases.values().next().unwrap();
        assert_eq!(c.regions, ["cn-geo", "us"]);
        assert!(c.route.is_none());
        assert_eq!(
            fingerprint_parts(&c.parts),
            vec![json!([0, 255, ["cn-geo", "us", false, null]])]
        );
    }
    #[test]
    fn network_only_is_unknown_and_anycast_still_wins_over_location_agreement() {
        let mut v = fixture();
        v[0] = vec![span(0, 15, Tag::Region(0))];
        v[6] = vec![span(8, 31, Tag::NetworkRegion(0))];
        v[2] = vec![span(12, 23, Tag::Flag)];
        let out = partition(4, &v, &names(), &["G/china.txt".into()]);
        assert_eq!(out.accepted["cn-geo"], [(0, 11)]);
        assert!(out.network_only > 0);
        assert!(out.cases.is_empty());
    }
    #[test]
    fn advisory_boundaries_preserve_fingerprints_but_keep_per_source_opinions() {
        let mut v = fixture();
        v[0] = vec![span(0, 255, Tag::Region(1))];
        v[1] = vec![span(0, 255, Tag::Region(2))];
        v[4] = vec![span(
            0,
            255,
            Tag::Route(Arc::new(Route {
                prefix: "0.0.0.0/24".into(),
                origins: vec![64501],
            })),
        )];
        let old = partition(4, &v[..6], &names(), &[]);
        v[6] = vec![span(128, 255, Tag::NetworkRegion(0))];
        let new = partition(4, &v, &names(), &["G/china.txt".into()]);
        let key = "4:0.0.0.0/24:europe|us";
        assert_eq!(new.cases.len(), 1);
        assert_eq!(
            fingerprint_parts(&new.cases[key].parts),
            fingerprint_parts(&old.cases[key].parts)
        );
        assert!(
            new.cases[key].parts.last().unwrap()[3]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["source_id"] == "G/china.txt")
        );
    }
    #[test]
    fn partial_anycast_does_not_withhold_deterministic_location_fallback() {
        let mut v = fixture();
        v[0] = vec![span(0, 31, Tag::Region(0))];
        v[1] = v[0].clone();
        v[3] = vec![span(8, 15, Tag::Flag)];
        v.push(vec![span(8, 15, Tag::PartialAnycast)]);
        let out = partition(4, &v, &names(), &["G/china.txt".into()]);
        assert_eq!(out.accepted["cn-geo"], [(0, 31)]);
        let c = out.cases.values().next().unwrap();
        assert_eq!(c.regions, ["cn-geo"]);
        assert_eq!(c.parts[0][2][5], "high-partial-anycast");
    }
    #[test]
    fn ipv6_maximum_and_equivalent_claim_splits_keep_the_same_scope() {
        let mut v = fixture();
        v[0] = vec![span(u128::MAX - 15, u128::MAX, Tag::Region(1))];
        v[1] = vec![span(u128::MAX - 15, u128::MAX, Tag::Region(0))];
        v[6] = network_claim(b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0/124\n", 6, 0)
            .unwrap()
            .0;
        let a = partition(6, &v, &names(), &["G/china6.txt".into()]);
        v[6]=network_claim(b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fff0/125\nffff:ffff:ffff:ffff:ffff:ffff:ffff:fff8/125\n",6,0).unwrap().0;
        let b = partition(6, &v, &names(), &["G/china6.txt".into()]);
        assert_eq!(a.accepted["us"], [(u128::MAX - 15, u128::MAX)]);
        assert_eq!(
            a.cases.keys().collect::<Vec<_>>(),
            b.cases.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            a.cases.values().next().unwrap().parts,
            b.cases.values().next().unwrap().parts
        );
        assert!(network_claim(b"1.2.3.4/24\n", 4, 0).is_err());
        assert!(network_claim(b"::/64\n", 4, 0).is_err());
        assert!(network_claim(b"# empty\n", 4, 0).is_err());
    }
    #[test]
    fn qualified_exact_fact_overrides_even_agreeing_sources_without_prefix_expansion() {
        let mut v = fixture();
        v[0] = vec![span(0, 255, Tag::Region(1))];
        v[1] = v[0].clone();
        let fact_index = v.len();
        v.push(vec![span(212, 212, Tag::FactualRegion(2))]);
        let out = partition_with_facts(
            4,
            &v,
            &names(),
            &["G/china.txt".into()],
            Some(fact_index),
            &BTreeSet::new(),
        );
        assert_eq!(out.accepted["us"], [(0, 211), (213, 255)]);
        assert_eq!(out.accepted["europe"], [(212, 212)]);
        assert!(out.cases.is_empty());
    }
    #[test]
    fn existing_actual_target_response_does_not_resolve_country_or_expand_to_range() {
        let mut v = fixture();
        v[0] = vec![span(0, 255, Tag::Region(1))];
        v[1] = vec![span(0, 255, Tag::Region(2))];
        let out = partition_with_facts(
            4,
            &v,
            &names(),
            &["G/china.txt".into()],
            None,
            &[212].into(),
        );
        assert_eq!(out.accepted["us"], [(0, 255)]);
        assert_eq!(out.cases.len(), 1);
        assert_eq!(out.observed_segments, 1);
        assert_eq!(out.resolved[0].basis, "location-source-priority");
    }
    #[test]
    fn full_library_keeps_anycast_fallback_and_reports_network_only_gap() {
        let mut v = fixture();
        v[0] = vec![span(0, 15, Tag::Region(1))];
        v[2] = vec![span(8, 15, Tag::Flag)];
        v[6] = vec![span(16, 31, Tag::NetworkRegion(0))];
        let out = partition(4, &v, &names(), &["G/china.txt".into()]);
        assert_eq!(out.accepted["us"], [(0, 7)]);
        assert_eq!(out.resolved.len(), 2);
        assert!(out.resolved[1].anycast);
        assert_eq!(out.network_only, 1);
    }
    #[test]
    fn unknown_raw_scopes_report_true_gap_difference_and_single_ip_fact_only() {
        let base = 0x0b000000u128;
        let mut views = fixture();
        views[0] = vec![span(base, base + 31, Tag::NoLocationOpinion)];
        views[1] = vec![
            span(base, base + 15, Tag::NoLocationOpinion),
            span(base + 16, base + 23, Tag::Region(1)),
            span(base + 24, base + 31, Tag::NoLocationOpinion),
        ];
        let original = partition(4, &views, &names(), &["G/china.txt".into()]);
        assert_eq!(original.accepted["us"], [(base + 16, base + 23)]);
        assert_eq!(
            original.coverage_gaps,
            [(base, base + 15), (base + 24, base + 31)]
        );
        let snapshot = crate::fusion::Snapshot {
            observed_at: 100,
            location_facts: vec![crate::fusion::LocationFact {
                scope: "11.0.0.4/32".parse().unwrap(),
                country_code: "DE".into(),
                authority: "controller-verified-scope".into(),
                method: crate::fusion::LocationMethod::TargetLocationAttestation,
                observed_at: 90,
                valid_until: 110,
            }],
            ..crate::fusion::Snapshot::default()
        };
        let facts = views.len();
        views.push(
            snapshot
                .location_spans(4, &BTreeMap::from([("DE".into(), 2)]))
                .unwrap()
                .into_iter()
                .map(|(s, e, region)| span(s, e, Tag::FactualRegion(region)))
                .collect(),
        );
        let fixed = partition_with_facts(
            4,
            &views,
            &names(),
            &["G/china.txt".into()],
            Some(facts),
            &BTreeSet::new(),
        );
        assert_eq!(fixed.accepted["us"], [(base + 16, base + 23)]);
        assert_eq!(fixed.accepted["europe"], [(base + 4, base + 4)]);
        assert_eq!(
            fixed.coverage_gaps,
            [
                (base, base + 3),
                (base + 5, base + 15),
                (base + 24, base + 31)
            ]
        );
        let gaps = coverage_gap_cases(4, &fixed.coverage_gaps);
        assert_eq!(gaps.len(), 3);
        assert_eq!(gaps[0].payload["ranges"], json!([["11.0.0.0", "11.0.0.3"]]));
        assert!(gaps.iter().all(|c| c.kind == "coverage-gap"
            && c.payload["measurement_required"] == false
            && c.payload["regions"] == json!([])));
        assert!(
            fixed
                .resolved
                .iter()
                .all(|r| r.region == "us" || r.region == "europe")
        );
    }
    #[test]
    fn unknown_scope_under_anycast_is_still_a_geographic_gap() {
        let mut views = fixture();
        views[0] = vec![span(100, 199, Tag::NoLocationOpinion)];
        views[1] = views[0].clone();
        views[2] = vec![span(100, 199, Tag::Flag)];
        let out = partition(4, &views, &names(), &["G/china.txt".into()]);
        assert_eq!(out.coverage_gaps, [(100, 199)]);
        assert!(out.accepted.is_empty());
        assert!(out.resolved.is_empty());
    }
    #[test]
    fn overlay_retains_end_and_holes() {
        let views = vec![
            vec![Span {
                s: 1,
                e: 5,
                v: Tag::Region(1),
            }],
            vec![Span {
                s: 3,
                e: 8,
                v: Tag::Region(2),
            }],
        ];
        let mut out = vec![];
        overlay(&views, |s, e, v| {
            out.push((s, e, v.iter().filter(|x| x.is_some()).count()))
        });
        assert_eq!(out, [(1, 2, 1), (3, 5, 2), (6, 8, 1)]);
    }
    #[test]
    fn invalid_source_overlap_fails() {
        assert!(
            coalesce(
                vec![
                    Span {
                        s: 0,
                        e: 10,
                        v: Tag::Region(1)
                    },
                    Span {
                        s: 10,
                        e: 20,
                        v: Tag::Region(1)
                    }
                ],
                true
            )
            .is_err()
        );
    }
}
