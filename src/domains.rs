use crate::{
    build::Recipe,
    rules::{Rule, ascii_domain},
    store::CaseInput,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Mozilla PSL, including PRIVATE, exact, wildcard and exception rules.
pub struct Psl {
    exact: BTreeSet<String>,
    wildcard: BTreeSet<String>,
    exception: BTreeSet<String>,
}
impl Psl {
    pub fn parse(text: &str) -> Result<Self> {
        ensure!(
            text.contains("===END ICANN DOMAINS===")
                && text.contains("===BEGIN PRIVATE DOMAINS===")
                && text.contains("===END PRIVATE DOMAINS==="),
            "truncated public/private suffix list"
        );
        let mut p = Self {
            exact: BTreeSet::new(),
            wildcard: BTreeSet::new(),
            exception: BTreeSet::new(),
        };
        for l in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("//"))
        {
            if let Some(l) = l.strip_prefix('!') {
                p.exception.insert(ascii_domain(l)?);
            } else if let Some(l) = l.strip_prefix("*.") {
                p.wildcard.insert(ascii_domain(l)?);
            } else {
                p.exact.insert(ascii_domain(l)?);
            }
        }
        ensure!(p.exact.len() > 1000, "PSL coverage collapsed");
        Ok(p)
    }
    pub fn is_suffix(&self, domain: &str) -> bool {
        let parts: Vec<_> = domain.split('.').collect();
        let mut len = 1;
        for i in 0..parts.len() {
            let s = parts[i..].join(".");
            if self.exception.contains(&s) {
                return parts.len() == parts.len() - i - 1;
            }
            if self.exact.contains(&s) {
                len = len.max(parts.len() - i)
            }
            if i > 0 && self.wildcard.contains(&s) {
                len = len.max(parts.len() - i + 1)
            }
        }
        parts.len() == len
    }
}
pub struct DomainPolicy {
    pub config: Value,
    pub psl: Psl,
    pub cases: BTreeMap<String, CaseInput>,
    facts: crate::fusion::Snapshot,
    official: BTreeSet<(String, Rule)>,
}
impl DomainPolicy {
    pub fn new(config: Value, psl: Psl) -> Self {
        Self {
            config,
            psl,
            cases: BTreeMap::new(),
            facts: crate::fusion::Snapshot::default(),
            official: BTreeSet::new(),
        }
    }
    pub fn with_facts(config: Value, psl: Psl, facts: &crate::fusion::Snapshot) -> Self {
        let mut p = Self::new(config, psl);
        p.facts = crate::fusion::Snapshot {
            observed_at: facts.observed_at,
            domain_facts: facts.domain_facts.clone(),
            ..crate::fusion::Snapshot::default()
        };
        p
    }
    pub fn clean(
        &mut self,
        rows: BTreeSet<Rule>,
        recipe: &Recipe,
        claims: &BTreeMap<Rule, Vec<String>>,
    ) -> Result<BTreeSet<Rule>> {
        let mut result = BTreeSet::new();
        for row in rows {
            // Bind to the exact predicate and its contributing selectors, not unrelated
            // edits elsewhere in a large upstream file. Complete snapshots remain in build history.
            let official = claims
                .get(&row)
                .into_iter()
                .flatten()
                .any(|source| source.starts_with("O/"));
            if official {
                self.official.insert((recipe.id.clone(), row.clone()));
            }
            // A verified exact hostname owner applies only to that hostname. DNS/IP
            // observations cannot create these facts or authorize a whole suffix.
            if !official
                && matches!(row.kind.as_str(), "DOMAIN")
                && recipe.kind == "provider"
                && self
                    .facts
                    .domain_owner(&row.value)
                    .is_some_and(|owner| owner != recipe.id)
            {
                continue;
            }
            if recipe.exclude_payloads.contains(&row.value)
                || (!recipe.include_payloads.is_empty()
                    && !recipe.include_payloads.contains(&row.value))
            {
                continue;
            }
            let mut reason = None;
            if matches!(
                row.kind.as_str(),
                "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-WILDCARD" | "DOMAIN-REGEX" | "DOMAIN-KEYWORD"
            ) {
                // A negative child cannot be represented by deleting a literal positive row.
                if recipe.exclude_payloads.iter().any(|x| row.domain_match(x)) {
                    reason = Some(
                        "positive predicate covers an explicitly excluded child; cannot express suffix subtraction",
                    );
                }
                if row.kind == "DOMAIN-KEYWORD"
                    && recipe.kind != "special"
                    && !self.config["keyword_allowlist"][&recipe.id]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v == &row.value))
                {
                    reason = Some("unbounded hostname keyword is not dedicated service identity");
                }
                {
                    let namespace_allowed = self.config["namespace_scopes"][&recipe.id]["roots"]
                        .as_array()
                        .is_some_and(|roots| roots.iter().any(|r| r == &row.value));
                    let local = recipe.id == "special/lan"
                        && recipe.local_domain_allowlist.contains(&row.value);
                    if row.kind == "DOMAIN-SUFFIX"
                        && self.psl.is_suffix(&row.value)
                        && !namespace_allowed
                        && !local
                    {
                        reason = Some("public or private suffix crosses tenant boundary");
                    }
                    if recipe.kind != "special"
                        && !namespace_allowed
                        && self.config["shared_roots"]
                            .get(&row.value)
                            .is_some_and(|owners| {
                                !owners
                                    .as_array()
                                    .is_some_and(|o| o.iter().any(|o| o == &recipe.id))
                            })
                    {
                        reason =
                            Some("shared infrastructure root is not dedicated service membership");
                    }
                    if recipe.kind != "special"
                        && !namespace_allowed
                        && self.config["shared_endpoints"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|v| v == &row.value))
                    {
                        reason =
                            Some("shared dependency endpoint is not dedicated service identity");
                    }
                }
            }
            if let Some(reason) = reason {
                // Explicit reviewed endpoint declarations take precedence over generic
                // dependency heuristics, but never over invalid namespace boundaries.
                let unsafe_boundary =
                    reason.contains("suffix") || reason.contains("excluded child");
                if !official || unsafe_boundary {
                    continue;
                }
            }
            result.insert(row);
        }
        Ok(result)
    }
    /// Resolve explicit mutually exclusive products once, before categories inherit them.
    /// Official endpoints win, then independently verified exact owner facts, then the
    /// declared product order. Never turn unresolved ownership into traceroute work.
    pub fn resolve_exclusivity(
        &mut self,
        sets: &mut BTreeMap<String, BTreeSet<Rule>>,
        recipes: &BTreeMap<String, Recipe>,
    ) -> Result<()> {
        let groups = self.config["exclusive_membership_groups"]
            .as_array()
            .context("exclusive domain groups")?
            .clone();
        for group in groups {
            let members: Vec<String> = group
                .as_array()
                .context("exclusive group")?
                .iter()
                .map(|id| id.as_str().context("exclusive member").map(str::to_string))
                .collect::<Result<_>>()?;
            let mut candidates = Vec::new();
            for (order, id) in members.iter().enumerate() {
                ensure!(recipes.contains_key(id), "unknown exclusive recipe {id}");
                for rule in sets
                    .get(id)
                    .with_context(|| format!("unknown exclusive member {id}"))?
                {
                    if matches!(rule.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX") {
                        let rank = if self.official.contains(&(id.clone(), rule.clone())) {
                            0
                        } else if rule.kind == "DOMAIN"
                            && self.facts.domain_owner(&rule.value) == Some(id.as_str())
                        {
                            1
                        } else {
                            2
                        };
                        candidates.push((rank, order, id.clone(), rule.clone()));
                    }
                }
            }
            candidates.sort();
            let mut accepted = Vec::<(String, Rule)>::new();
            for (_, _, id, rule) in candidates {
                if accepted.iter().any(|(owner, other)| {
                    owner != &id
                        && (rule.domain_match(&other.value) || other.domain_match(&rule.value))
                }) {
                    sets.get_mut(&id).unwrap().remove(&rule);
                } else {
                    accepted.push((id, rule));
                }
            }
        }
        Ok(())
    }
    pub fn check_exclusivity(
        &mut self,
        sets: &BTreeMap<String, BTreeSet<Rule>>,
        recipes: &BTreeMap<String, Recipe>,
    ) -> Result<()> {
        self.resolve_exclusivity(&mut sets.clone(), recipes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn psl() -> Psl {
        Psl {
            exact: ["com", "co.uk", "github.io"].map(str::to_string).into(),
            wildcard: ["ck".into()].into(),
            exception: ["www.ck".into()].into(),
        }
    }
    #[test]
    fn explicit_endpoint_wins_exclusive_membership_without_manual_case() {
        let config = json!({"exclusive_membership_groups":[["provider/a","provider/b"]]});
        let mut p = DomainPolicy::new(config, psl());
        let a: Recipe =
            serde_json::from_value(json!({"id":"provider/a","name":"a","type":"provider"}))
                .unwrap();
        let b: Recipe =
            serde_json::from_value(json!({"id":"provider/b","name":"b","type":"provider"}))
                .unwrap();
        let rule = Rule::new("DOMAIN", "api.example.com", &[]).unwrap();
        let arows = p
            .clean([rule.clone()].into(), &a, &BTreeMap::new())
            .unwrap();
        let brows = p
            .clean(
                [rule.clone()].into(),
                &b,
                &BTreeMap::from([(rule.clone(), vec!["O/service#official".into()])]),
            )
            .unwrap();
        let mut sets = BTreeMap::from([(a.id.clone(), arows), (b.id.clone(), brows)]);
        let recipes = BTreeMap::from([(a.id.clone(), a), (b.id.clone(), b)]);
        p.resolve_exclusivity(&mut sets, &recipes).unwrap();
        assert!(sets["provider/a"].is_empty());
        assert_eq!(sets["provider/b"].len(), 1);
        assert!(p.cases.is_empty());
    }
    #[test]
    fn domain_owner_fact_is_exact_scope_and_dns_location_cannot_make_an_owner() {
        let snapshot = crate::fusion::Snapshot {
            observed_at: 100,
            domain_facts: vec![crate::fusion::DomainFact {
                hostname: "api.example.com".into(),
                collection: "provider/b".into(),
                authority: "verified-explicit-service".into(),
                observed_at: 90,
                valid_until: 110,
            }],
            ..crate::fusion::Snapshot::default()
        };
        let mut p =
            DomainPolicy::with_facts(json!({"exclusive_membership_groups":[]}), psl(), &snapshot);
        let a: Recipe =
            serde_json::from_value(json!({"id":"provider/a","name":"a","type":"provider"}))
                .unwrap();
        let out = p
            .clean(
                [
                    Rule::new("DOMAIN", "api.example.com", &[]).unwrap(),
                    Rule::new("DOMAIN", "other.example.com", &[]).unwrap(),
                ]
                .into(),
                &a,
                &BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(
            out.iter().map(|r| r.value.as_str()).collect::<Vec<_>>(),
            ["other.example.com"]
        );
        assert!(p.cases.is_empty());
    }
    #[test]
    fn tenant_boundaries() {
        let p = psl();
        assert!(p.is_suffix("github.io"));
        assert!(!p.is_suffix("tenant.github.io"));
        assert!(p.is_suffix("a.ck"));
        assert!(!p.is_suffix("www.ck"));
        assert!(!p.is_suffix("example.co.uk"));
    }
    #[test]
    fn suffix_minus_child_filters_unrepresentable_parent() {
        let mut p = DomainPolicy::new(json!({"wide_policy_sets":[],"shared_roots":{}}), psl());
        let recipe:Recipe=serde_json::from_value(json!({"id":"provider/test","name":"test","type":"provider","exclude_payloads":["unsafe.example.com"]})).unwrap();
        let rows = [
            Rule::new("DOMAIN-SUFFIX", "example.com", &[]).unwrap(),
            Rule::new("DOMAIN", "safe.example.org", &[]).unwrap(),
        ]
        .into();
        let out = p.clean(rows, &recipe, &BTreeMap::new()).unwrap();
        assert_eq!(out.len(), 1);
        assert!(p.cases.is_empty());
    }
    #[test]
    fn changed_excluded_child_does_not_create_manual_decision_state() {
        let mut p = DomainPolicy::new(json!({"shared_roots":{}}), psl());
        let mut recipe:Recipe=serde_json::from_value(json!({"id":"provider/test","name":"test","type":"provider","exclude_payloads":["one.example.com"]})).unwrap();
        let rule = Rule::new("DOMAIN-SUFFIX", "example.com", &[]).unwrap();
        p.clean([rule.clone()].into(), &recipe, &BTreeMap::new())
            .unwrap();
        assert!(p.cases.is_empty());
        recipe.exclude_payloads = ["two.example.com".into()].into();
        p.clean([rule].into(), &recipe, &BTreeMap::new()).unwrap();
        assert!(p.cases.is_empty());
    }
    #[test]
    fn shared_root_keeps_dedicated_tenant() {
        let mut p = DomainPolicy::new(json!({"shared_roots":{"auth0.com":[]}}), psl());
        let recipe: Recipe =
            serde_json::from_value(json!({"id":"provider/test","name":"test","type":"provider"}))
                .unwrap();
        let out = p
            .clean(
                [
                    Rule::new("DOMAIN-SUFFIX", "auth0.com", &[]).unwrap(),
                    Rule::new("DOMAIN-SUFFIX", "test.auth0.com", &[]).unwrap(),
                ]
                .into(),
                &recipe,
                &BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert!(out.iter().any(|r| r.value == "test.auth0.com"));
    }
    #[test]
    fn regional_suffixes_are_explicit_and_categories_cannot_inherit_supplier_exemptions() {
        let config = crate::read_json(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/domains.json"),
        )
        .unwrap();
        let mut suffixes = psl();
        suffixes.exact.extend(
            ["cn", "ms", "top", "in.th", "cloudfront.net", "vercel.app"].map(str::to_string),
        );
        let mut p = DomainPolicy::new(config, suffixes);
        let cn: Recipe =
            serde_json::from_value(json!({"id":"region/cn","type":"region","name":"CN"})).unwrap();
        let rows = ["cn", "ms", "top", "in.th"]
            .map(|s| Rule::new("DOMAIN-SUFFIX", s, &[]).unwrap())
            .into();
        let clean = p.clean(rows, &cn, &BTreeMap::new()).unwrap();
        assert_eq!(
            clean.iter().map(|r| r.value.as_str()).collect::<Vec<_>>(),
            ["cn"]
        );
        let category: Recipe = serde_json::from_value(
            json!({"id":"category/shopping-travel","type":"category","name":"shopping"}),
        )
        .unwrap();
        let root = Rule::new("DOMAIN-SUFFIX", "cloudfront.net", &[]).unwrap();
        assert!(
            p.clean(
                [root.clone()].into(),
                &category,
                &BTreeMap::from([(root, vec!["member:provider/amazon".into()])])
            )
            .unwrap()
            .is_empty()
        );
        let vercel: Recipe = serde_json::from_value(
            json!({"id":"provider/vercel","type":"provider","name":"Vercel"}),
        )
        .unwrap();
        assert_eq!(
            p.clean(
                [Rule::new("DOMAIN-SUFFIX", "vercel.app", &[]).unwrap()].into(),
                &vercel,
                &BTreeMap::new()
            )
            .unwrap()
            .len(),
            1
        );
    }
    #[test]
    fn identity_keywords_and_shared_dependencies_follow_explicit_purpose_boundaries() {
        let config = crate::read_json(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config/domains.json"),
        )
        .unwrap();
        let mut p = DomainPolicy::new(config, psl());
        let product: Recipe =
            serde_json::from_value(json!({"id":"provider/test","type":"provider","name":"test"}))
                .unwrap();
        let rules = [
            Rule::new("DOMAIN-KEYWORD", "colab", &[]).unwrap(),
            Rule::new("DOMAIN", "static.cloudflareinsights.com", &[]).unwrap(),
            Rule::new("DOMAIN", "dedicated.example.com", &[]).unwrap(),
        ]
        .into();
        let clean = p.clean(rules, &product, &BTreeMap::new()).unwrap();
        assert_eq!(clean.len(), 1);
        let purpose: Recipe = serde_json::from_value(
            json!({"id":"special/telemetry","type":"special","name":"telemetry"}),
        )
        .unwrap();
        assert_eq!(
            p.clean(
                [Rule::new("DOMAIN", "static.cloudflareinsights.com", &[]).unwrap()].into(),
                &purpose,
                &BTreeMap::new()
            )
            .unwrap()
            .len(),
            1
        );
    }
}
