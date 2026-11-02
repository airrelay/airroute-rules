use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

pub const TYPES: &str = "DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD DOMAIN-WILDCARD DOMAIN-REGEX IP-CIDR IP-CIDR6 GEOIP IP-ASN SCRIPT SUBNET SRC-IP SRC-IP-CIDR SRC-IP-CIDR6 DST-PORT SRC-PORT IN-PORT NETWORK PROTOCOL PROCESS-NAME PROCESS-PATH PACKAGE-NAME USER-AGENT URL-REGEX HOSTNAME-TYPE MAC-ADDRESS DEVICE-NAME CELLULAR-RADIO";

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Rule {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub modifiers: Vec<String>,
}
impl Rule {
    pub fn new(kind: &str, value: &str, mods: &[&str]) -> Result<Self> {
        let mut kind = kind.trim().to_uppercase();
        let mut value = value.trim().to_string();
        ensure!(
            TYPES.split_whitespace().any(|x| x == kind),
            "unsupported type {kind}"
        );
        ensure!(
            !value.is_empty() && !value.contains([',', '\r', '\n']),
            "invalid {kind} payload"
        );
        let modifiers: Vec<_> = mods
            .iter()
            .map(|x| x.trim().to_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        ensure!(
            modifiers.iter().all(|m| m == "no-resolve"),
            "unknown rule modifier"
        );
        ensure!(
            modifiers.is_empty()
                || Self::ip_kind(&kind)
                || matches!(kind.as_str(), "IP-ASN" | "GEOIP"),
            "no-resolve on {kind}"
        );
        if Self::ip_kind(&kind) {
            let network = if value.contains('/') {
                value.clone()
            } else {
                let ip: IpAddr = value.parse()?;
                format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
            };
            let net: IpNet = network
                .parse()
                .with_context(|| format!("invalid network {value}"))?;
            kind = format!(
                "{}{}",
                if kind.starts_with("SRC-") { "SRC-" } else { "" },
                if net.addr().is_ipv4() {
                    "IP-CIDR"
                } else {
                    "IP-CIDR6"
                }
            );
            value = net.trunc().to_string();
        } else if kind == "DOMAIN-WILDCARD" {
            value = ascii_wildcard(value.trim_matches('.'))?;
        } else if matches!(kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") {
            value = ascii_domain(value.trim_matches('.'))?;
            ensure!(!value.contains('*'), "wildcard in literal domain rule");
        } else if kind == "DOMAIN-KEYWORD" {
            value = value.to_lowercase();
        } else if kind == "IP-ASN" {
            value = value.parse::<u32>()?.to_string();
        }
        if matches!(kind.as_str(), "DOMAIN-REGEX" | "URL-REGEX") {
            Regex::new(&value)?;
        }
        Ok(Self {
            kind,
            value,
            modifiers,
        })
    }
    pub fn ip_kind(k: &str) -> bool {
        matches!(k, "IP-CIDR" | "IP-CIDR6" | "SRC-IP-CIDR" | "SRC-IP-CIDR6")
    }
    pub fn line(&self) -> String {
        std::iter::once(self.kind.as_str())
            .chain(std::iter::once(self.value.as_str()))
            .chain(self.modifiers.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(",")
    }
    pub fn domain_match(&self, host: &str) -> bool {
        match self.kind.as_str() {
            "DOMAIN" => host == self.value,
            "DOMAIN-SUFFIX" => below(host, &self.value),
            "DOMAIN-KEYWORD" => host.contains(&self.value),
            "DOMAIN-REGEX" => Regex::new(&self.value).is_ok_and(|r| r.is_match(host)),
            "DOMAIN-WILDCARD" => wildcard_match(&self.value, host),
            _ => false,
        }
    }
}
// AirRoute treats a leading *.literal as a root-inclusive suffix. Other globs
// use byte-oriented * (zero or more) and ? (one), on normalized ASCII hosts.
fn wildcard_match(pattern: &str, host: &str) -> bool {
    if let Some(root) = pattern.strip_prefix("*.") {
        return below(host, root);
    }
    let (pattern, host) = (pattern.as_bytes(), host.as_bytes());
    let (mut p, mut h, mut star) = (0, 0, None);
    while h < host.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == host[h]) {
            p += 1;
            h += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, h));
            p += 1;
        } else if let Some((s, mut end)) = star {
            end += 1;
            star = Some((s, end));
            p = s + 1;
            h = end;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
fn ascii_wildcard(s: &str) -> Result<String> {
    // Mixed leading-* suffixes have inconsistent interpretations in older
    // AirRoute matcher paths. Fail closed rather than publish ambiguous rules.
    ensure!(
        !s.strip_prefix("*.")
            .is_some_and(|root| root.contains(['*', '?'])),
        "ambiguous leading wildcard suffix {s}"
    );
    let labels = s
        .split('.')
        .map(|label| {
            if label.contains(['*', '?']) {
                ensure!(
                    label.is_ascii()
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_*?".contains(&b)),
                    "invalid wildcard label"
                );
                Ok(label.to_ascii_lowercase())
            } else {
                ascii_domain(label)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let result = labels.join(".");
    ensure!(
        result.len() <= 253 && labels.iter().all(|l| !l.is_empty() && l.len() <= 63),
        "invalid wildcard domain"
    );
    Ok(result)
}
pub fn below(host: &str, root: &str) -> bool {
    host == root || host.strip_suffix(root).is_some_and(|p| p.ends_with('.'))
}
pub fn ascii_domain(s: &str) -> Result<String> {
    // URL's IDNA implementation, also used by reqwest; wildcard labels stay predicates.
    ensure!(
        !s.is_empty()
            && !s.chars().any(char::is_whitespace)
            && !s.contains(['/', ':', '@', '?', '#', '%', '\\']),
        "invalid domain {s}"
    );
    let labels = s
        .split('.')
        .map(|label| {
            if label.contains('*') {
                ensure!(label.is_ascii(), "non-ASCII wildcard label");
                return Ok(label.to_lowercase());
            }
            let url = reqwest::Url::parse(&format!("https://{label}.invalid"))?;
            Ok(url
                .host_str()
                .context("missing domain")?
                .trim_end_matches(".invalid")
                .to_lowercase())
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        labels.iter().all(|x| !x.is_empty() && x.len() <= 63) && s.len() <= 253,
        "invalid DNS label"
    );
    Ok(labels.join("."))
}
pub fn compatible_regex(s: &str) -> Result<String> {
    let mut out = String::new();
    let mut chars = s.chars();
    let mut class = false;
    while let Some(c) = chars.next() {
        if c == '\\' {
            let c = chars.next().context("trailing regex escape")?;
            if "DSW".contains(c) {
                ensure!(!class, "uppercase escape in class needs review");
                out.push_str(&format!("[^\\{}]", c.to_ascii_lowercase()));
            } else {
                ensure!(
                    !c.is_ascii_uppercase(),
                    "uppercase regex escape needs review"
                );
                out.push('\\');
                out.push(c);
            }
        } else {
            if c == '[' {
                class = true
            } else if c == ']' {
                class = false
            }
            out.push(c);
        }
    }
    fn up_to(atom: &str, n: usize) -> String {
        if n == 0 {
            return String::new();
        }
        if n == 1 {
            return format!("{atom}?");
        }
        let p = 1usize << (usize::BITS - 1 - n.leading_zeros());
        if n == 2 * p - 1 {
            let mut v = String::new();
            let mut k = p;
            while k > 1 {
                v += &format!("(?:{atom}{{{k}}})?");
                k /= 2;
            }
            v += &format!("{atom}?");
            v
        } else {
            format!(
                "(?:{}|{atom}{{{p}}}{})",
                up_to(atom, p - 1),
                up_to(atom, n - p)
            )
        }
    }
    let re = Regex::new(r"(\[[a-z0-9-]+\])\{(\d+),(\d+)\}")?;
    let mut err = false;
    out = re
        .replace_all(&out.to_lowercase(), |c: &regex::Captures| {
            let lo = c[2].parse::<usize>().unwrap_or(usize::MAX);
            let hi = c[3].parse::<usize>().unwrap_or(usize::MAX);
            if lo > hi || hi > 128 {
                err = true;
                return String::new();
            }
            format!("{}{{{lo}}}{}", &c[1], up_to(&c[1], hi - lo))
        })
        .into_owned();
    ensure!(
        !err && !out.contains(','),
        "regex not faithfully representable by AirRoute classical; review source"
    );
    Regex::new(&out)?;
    Ok(out)
}
pub fn classical(text: &str) -> Result<BTreeSet<Rule>> {
    let mut rules = BTreeSet::new();
    for line in text.trim_start_matches('\u{feff}').lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) || line.starts_with("//") {
            continue;
        }
        let (kind, rest) = line.split_once(',').context("malformed classical row")?;
        if kind.eq_ignore_ascii_case("DOMAIN-REGEX") {
            rules.insert(Rule::new(kind, &compatible_regex(rest)?, &[])?);
        } else {
            let v: Vec<_> = rest.split(',').collect();
            rules.insert(Rule::new(kind, v[0], &v[1..])?);
        }
    }
    ensure!(!rules.is_empty(), "empty classical source");
    Ok(rules)
}
#[derive(Clone)]
struct Tagged {
    rule: Rule,
    attrs: BTreeSet<String>,
}
pub struct Dlc {
    data: BTreeMap<String, String>,
    memo: BTreeMap<String, Vec<Tagged>>,
}
impl Dlc {
    pub fn new(mut data: BTreeMap<String, String>) -> Self {
        // DLC affiliations add a rule to the target list, not merely metadata on its owner.
        let mut affiliates = BTreeMap::<String, Vec<String>>::new();
        for text in data.values() {
            for line in text.lines() {
                let fields: Vec<_> = line
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .collect();
                if fields.is_empty() || fields[0].starts_with("include:") {
                    continue;
                }
                for target in fields.iter().skip(1).filter_map(|s| s.strip_prefix('&')) {
                    let entry = fields
                        .iter()
                        .copied()
                        .filter(|s| !s.starts_with('&'))
                        .collect::<Vec<_>>()
                        .join(" ");
                    affiliates
                        .entry(target.to_lowercase())
                        .or_default()
                        .push(entry);
                }
            }
        }
        for (name, rows) in affiliates {
            let text = data.entry(name).or_default();
            text.push('\n');
            text.push_str(&rows.join("\n"));
        }
        Self {
            data,
            memo: BTreeMap::new(),
        }
    }
    fn expand(&mut self, name: &str, stack: &mut Vec<String>) -> Result<Vec<Tagged>> {
        ensure!(
            !stack.iter().any(|s| s == name),
            "DLC include cycle {stack:?} -> {name}"
        );
        if let Some(r) = self.memo.get(name) {
            return Ok(r.clone());
        }
        let text = self
            .data
            .get(name)
            .with_context(|| format!("missing DLC include {name}"))?
            .clone();
        stack.push(name.into());
        let mut result = Vec::new();
        for line in text.lines() {
            let fields: Vec<_> = line
                .split('#')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .collect();
            if fields.is_empty() {
                continue;
            }
            ensure!(
                fields[1..].iter().all(|x| x.starts_with(['@', '&'])),
                "unknown DLC metadata"
            );
            let attrs: BTreeSet<_> = fields[1..]
                .iter()
                .filter_map(|x| x.strip_prefix('@').map(str::to_string))
                .collect();
            if let Some(child) = fields[0].strip_prefix("include:") {
                ensure!(
                    fields[1..].iter().all(|f| f.starts_with('@')),
                    "affiliations belong on domain entries, not include directives"
                );
                for row in self.expand(child, stack)? {
                    if attrs.iter().all(|a| {
                        if let Some(a) = a.strip_prefix('-') {
                            !row.attrs.contains(a)
                        } else {
                            row.attrs.contains(a)
                        }
                    }) {
                        result.push(row)
                    }
                }
            } else {
                let (k, v) = fields[0].split_once(':').unwrap_or(("domain", fields[0]));
                let k = match k {
                    "domain" => "DOMAIN-SUFFIX",
                    "full" => "DOMAIN",
                    "keyword" => "DOMAIN-KEYWORD",
                    "regexp" => "DOMAIN-REGEX",
                    _ => bail!("unknown DLC type {k}"),
                };
                result.push(Tagged {
                    rule: Rule::new(
                        k,
                        &if k == "DOMAIN-REGEX" {
                            compatible_regex(v)?
                        } else {
                            v.to_string()
                        },
                        &[],
                    )?,
                    attrs,
                });
            }
        }
        stack.pop();
        self.memo.insert(name.into(), result.clone());
        Ok(result)
    }
    pub fn select(&mut self, name: &str, selector: &str) -> Result<BTreeSet<Rule>> {
        let all = self.expand(name, &mut vec![])?;
        let wanted: BTreeSet<_> = selector.split(',').collect();
        let result: BTreeSet<_> = all
            .into_iter()
            .filter(|r| {
                selector == "all"
                    || if let Some(a) = selector.strip_prefix('@') {
                        r.attrs.contains(a)
                    } else {
                        wanted.contains(r.rule.value.as_str())
                    }
            })
            .map(|r| r.rule)
            .collect();
        ensure!(!result.is_empty(), "empty DLC selector {name}#{selector}");
        if selector != "all" && !selector.starts_with('@') {
            ensure!(
                result
                    .iter()
                    .map(|r| r.value.as_str())
                    .collect::<BTreeSet<_>>()
                    == wanted,
                "DLC selector disappeared {name}#{selector}"
            );
        }
        Ok(result)
    }
}
pub fn ip_parts(net: IpNet) -> (u8, u128, u128) {
    match net.trunc() {
        IpNet::V4(n) => (
            4,
            u32::from(n.network()) as u128,
            u32::from(n.broadcast()) as u128,
        ),
        IpNet::V6(n) => (6, u128::from(n.network()), u128::from(n.broadcast())),
    }
}
pub fn ip_text(family: u8, n: u128) -> String {
    if family == 4 {
        Ipv4Addr::from(n as u32).to_string()
    } else {
        Ipv6Addr::from(n).to_string()
    }
}
pub fn addr_num(addr: IpAddr) -> (u8, u128) {
    match addr {
        IpAddr::V4(a) => (4, u32::from(a) as u128),
        IpAddr::V6(a) => (6, u128::from(a)),
    }
}
pub fn append_range(rows: &mut Vec<(u128, u128)>, s: u128, e: u128) {
    if let Some(last) = rows.last_mut()
        && s <= last.1.saturating_add(1)
    {
        last.1 = last.1.max(e);
        return;
    }
    rows.push((s, e));
}
pub fn union(mut rows: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    rows.sort_unstable();
    let mut out = vec![];
    for (s, e) in rows {
        append_range(&mut out, s, e)
    }
    out
}
pub fn cidrs(family: u8, mut start: u128, end: u128) -> Vec<String> {
    let bits = if family == 4 { 32 } else { 128 };
    let mut out = vec![];
    loop {
        let mut host = start.trailing_zeros().min(bits);
        while host > 0
            && ((1u128.checked_shl(host).map(|x| x - 1).unwrap_or(u128::MAX)) > end - start)
        {
            host -= 1;
        }
        out.push(format!("{}/{}", ip_text(family, start), bits - host));
        if host == 128 {
            break;
        }
        let n = 1u128 << host;
        if end - start < n {
            break;
        }
        start += n;
    }
    out
}
// This is deliberately a sufficient containment proof, not a general regex or
// glob language solver. An unproven overlap always keeps both predicates.
struct Coverage<'a> {
    suffixes: BTreeMap<&'a str, &'a Rule>,
    keywords: Vec<&'a Rule>,
    wildcards: Vec<&'a Rule>,
}
impl<'a> Coverage<'a> {
    fn new(rows: &'a BTreeSet<Rule>) -> Self {
        let mut suffixes = BTreeMap::new();
        let mut keywords = vec![];
        let mut wildcards = vec![];
        for r in rows {
            match r.kind.as_str() {
                "DOMAIN-SUFFIX" => {
                    suffixes.insert(r.value.as_str(), r);
                }
                "DOMAIN-KEYWORD" => keywords.push(r),
                "DOMAIN-WILDCARD" => {
                    if let Some(root) = r.value.strip_prefix("*.")
                        && !root.contains(['*', '?'])
                    {
                        // Prefer the canonical suffix when both are present.
                        suffixes.entry(root).or_insert(r);
                    }
                    wildcards.push(r);
                }
                _ => {}
            }
        }
        Self {
            suffixes,
            keywords,
            wildcards,
        }
    }
    fn suffix_cover(&self, value: &str, target: &Rule) -> Option<&'a Rule> {
        let mut root = value;
        loop {
            if let Some(&r) = self.suffixes.get(root)
                && r != target
            {
                return Some(r);
            }
            root = root.split_once('.')?.1;
        }
    }
    fn covering(&self, target: &Rule) -> Option<&'a Rule> {
        if !target.kind.starts_with("DOMAIN") {
            return None;
        }
        if let Some(&r) = self
            .wildcards
            .iter()
            .find(|r| r.value == "*" && **r != target)
        {
            return Some(r);
        }
        match target.kind.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" => self
                .suffix_cover(&target.value, target)
                .or_else(|| {
                    self.keywords
                        .iter()
                        .copied()
                        .find(|r| target.value.contains(&r.value))
                })
                .or_else(|| {
                    (target.kind == "DOMAIN")
                        .then(|| {
                            self.wildcards
                                .iter()
                                .copied()
                                .find(|r| r.domain_match(&target.value))
                        })
                        .flatten()
                }),
            "DOMAIN-KEYWORD" => self
                .keywords
                .iter()
                .copied()
                .find(|r| *r != target && target.value.contains(&r.value)),
            "DOMAIN-WILDCARD" => {
                if let Some(root) = target.value.strip_prefix("*.") {
                    return self.suffix_cover(root, target).or_else(|| {
                        self.keywords
                            .iter()
                            .copied()
                            .find(|r| root.contains(&r.value))
                    });
                }
                // Every match contains every literal run, including across labels.
                self.keywords
                    .iter()
                    .copied()
                    .find(|r| {
                        target
                            .value
                            .split(['*', '?'])
                            .any(|part| part.contains(&r.value))
                    })
                    .or_else(|| {
                        let tail = target.value.rsplit(['*', '?']).next()?;
                        self.literal_tail_cover(tail, target)
                    })
            }
            "DOMAIN-REGEX" => {
                let tail = regex_literal_tail(&target.value)?;
                self.literal_tail_cover(&tail, target).or_else(|| {
                    self.keywords
                        .iter()
                        .copied()
                        .find(|r| tail.contains(&r.value))
                })
            }
            _ => None,
        }
    }
    fn literal_tail_cover(&self, tail: &str, target: &Rule) -> Option<&'a Rule> {
        // A literal suffix without its preceding dot could match badexample.com.
        let root = tail.split_once('.')?.1;
        self.suffix_cover(root, target)
    }
}
fn regex_literal_tail(pattern: &str) -> Option<String> {
    use regex_syntax::hir::{HirKind, Look};
    let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
    let HirKind::Concat(parts) = hir.kind() else {
        return None;
    };
    let (end, body) = parts.split_last()?;
    if !matches!(end.kind(), HirKind::Look(Look::End)) {
        return None;
    }
    let HirKind::Literal(literal) = body.last()?.kind() else {
        return None;
    };
    String::from_utf8(literal.0.to_vec()).ok()
}
type IpGroups = BTreeMap<(String, Vec<String>, u8), Vec<(u128, u128)>>;
fn ip_groups(rows: &BTreeSet<Rule>) -> Result<IpGroups> {
    let mut groups: IpGroups = BTreeMap::new();
    for r in rows.iter().filter(|r| Rule::ip_kind(&r.kind)) {
        let (f, s, e) = ip_parts(r.value.parse()?);
        groups
            .entry((r.kind.clone(), r.modifiers.clone(), f))
            .or_default()
            .push((s, e));
    }
    for ranges in groups.values_mut() {
        *ranges = union(std::mem::take(ranges));
    }
    Ok(groups)
}
/// Compare complete IP coverage by predicate kind, modifiers and address family.
/// Non-IP predicates are intentionally outside this borrowed comparison.
pub fn verify_ip_equivalent(before: &BTreeSet<Rule>, after: &BTreeSet<Rule>) -> Result<()> {
    ensure!(
        ip_groups(before)? == ip_groups(after)?,
        "optimization changed typed IP coverage"
    );
    Ok(())
}
/// Validate exact typed IP coverage and a retained containment witness for every
/// removed domain predicate. No sampling and no dependence on DNS/BGP lookups.
pub fn verify_equivalent(before: &BTreeSet<Rule>, after: &BTreeSet<Rule>) -> Result<()> {
    verify_ip_equivalent(before, after)?;
    ensure!(
        after
            .iter()
            .filter(|r| !Rule::ip_kind(&r.kind))
            .all(|r| before.contains(r)),
        "optimization introduced a predicate"
    );
    let coverage = Coverage::new(after);
    for r in before
        .iter()
        .filter(|r| !Rule::ip_kind(&r.kind) && !after.contains(r))
    {
        ensure!(
            coverage.covering(r).is_some(),
            "optimization lacks retained coverage witness: {}",
            r.line()
        );
    }
    Ok(())
}
pub fn optimize(rows: BTreeSet<Rule>) -> Result<BTreeSet<Rule>> {
    let coverage = Coverage::new(&rows);
    let mut out = BTreeSet::new();
    for r in &rows {
        if !Rule::ip_kind(&r.kind) && coverage.covering(r).is_none() {
            out.insert(r.clone());
        }
    }
    for ((kind, mods, f), ranges) in ip_groups(&rows)? {
        for (s, e) in ranges {
            for v in cidrs(f, s, e) {
                out.insert(Rule {
                    kind: kind.clone(),
                    value: v,
                    modifiers: mods.clone(),
                });
            }
        }
    }
    verify_equivalent(&rows, &out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dlc_affiliations_add_tagged_rules_to_target_and_include_filters() {
        let mut dlc = Dlc::new(BTreeMap::from([
            ("owner".into(), "example.org @tag &affiliate".into()),
            ("affiliate".into(), "own.example.net".into()),
            ("filtered".into(), "include:affiliate @tag".into()),
        ]));
        assert_eq!(dlc.select("affiliate", "all").unwrap().len(), 2);
        assert_eq!(
            dlc.select("filtered", "all")
                .unwrap()
                .iter()
                .map(|r| r.value.as_str())
                .collect::<Vec<_>>(),
            ["example.org"]
        );
    }
    #[test]
    fn typed_and_equivalent_collapse() {
        let rows = [
            Rule::new("DOMAIN-SUFFIX", "Example.com", &[]).unwrap(),
            Rule::new("DOMAIN", "a.example.com", &[]).unwrap(),
            Rule::new("IP-CIDR", "102.129.139.0/25", &["no-resolve"]).unwrap(),
            Rule::new("IP-CIDR", "102.129.139.128/25", &["no-resolve"]).unwrap(),
        ];
        let r = optimize(rows.into()).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r.iter().any(|r| r.value == "102.129.139.0/24"));
    }
    #[test]
    fn hole_must_survive() {
        let mut spans = vec![(0, 211), (213, 255)];
        let r = union(std::mem::take(&mut spans));
        assert_eq!(r.len(), 2);
        assert!(!cidrs(4, 213, 255).contains(&"0.0.0.0/24".into()));
    }
    #[test]
    fn full_ipv6_and_idna() {
        assert_eq!(cidrs(6, 0, u128::MAX), ["::/0"]);
        assert_eq!(ascii_domain("例子.中国").unwrap(), "xn--fsqu00a.xn--fiqs8s");
        assert!(
            Rule::new("DOMAIN-SUFFIX", "com", &[])
                .unwrap()
                .domain_match("example.com")
        );
        assert!(!below("badexample.com", "example.com"));
    }
    #[test]
    fn include_cycle() {
        let mut d = Dlc::new(BTreeMap::from([
            ("a".into(), "include:b".into()),
            ("b".into(), "include:a".into()),
        ]));
        assert!(d.select("a", "all").is_err());
    }
}
