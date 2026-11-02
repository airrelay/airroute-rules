//! Typed build inputs. Reachability/DNS observations are never target location or service ownership.
//! Positive location/owner facts require a controller-verified trusted importer; merely
//! deserializing receipt fields cannot qualify them and capture() never does so.
use crate::{now, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocationFact {
    /// Exact address or independently authorized prefix; never a sampled parent network.
    pub scope: ipnet::IpNet,
    pub country_code: String,
    pub authority: String,
    pub method: LocationMethod,
    pub observed_at: i64,
    pub valid_until: i64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocationMethod {
    /// The controller/importer has verified the operator's authority over the entire scope.
    OperatorAuthorizedGeofeed,
    /// An independently verified target-location attestation, not observer/path geolocation.
    TargetLocationAttestation,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainFact {
    /// Exact hostname. A tenant/host attestation does not authorize its parent suffix.
    pub hostname: String,
    pub collection: String,
    pub authority: String,
    pub observed_at: i64,
    pub valid_until: i64,
}
#[derive(Clone, Debug)]
pub struct Observation {
    pub target: String,
    pub kind: String,
    pub executor_id: String,
    pub protocol: Option<String>,
    pub query_types: BTreeSet<String>,
    pub execution_class: crate::receipt::ResultClass,
    pub observed_at: i64,
    pub valid_until: i64,
    pub reached: bool,
}
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub observed_at: i64,
    pub summary: Value,
    pub observations: Vec<Observation>,
    /// Qualified exact addresses with the original answer/observation clock.
    /// These can supply a probe target, never a location or service-owner vote.
    pub target_candidates: BTreeMap<std::net::IpAddr, crate::discovery::Observation>,
    pub location_facts: Vec<LocationFact>,
    pub domain_facts: Vec<DomainFact>,
}
fn current(observed: i64, until: i64, at: i64) -> bool {
    observed > 0
        && observed <= at
        && observed >= at.saturating_sub(7 * 86400)
        && until > at
        && until > observed
}
impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        for (ip, candidate) in &self.target_candidates {
            ensure!(
                *ip == candidate.ip,
                "target candidate has mismatched address scope"
            );
            ensure!(
                matches!(candidate.kind, "dns-answer" | "endpoint-response"),
                "unsupported target candidate evidence"
            );
            ensure!(
                candidate.observed > 0 && candidate.valid_until > candidate.observed,
                "invalid target candidate observation lifetime"
            );
        }
        for f in &self.location_facts {
            ensure!(f.scope == f.scope.trunc(), "noncanonical factual scope");
            ensure!(
                !f.authority.trim().is_empty(),
                "location fact has no verified authority"
            );
            ensure!(
                f.country_code.len() == 2 && f.country_code.bytes().all(|c| c.is_ascii_uppercase()),
                "invalid factual country code"
            );
            ensure!(
                f.observed_at > 0 && f.valid_until > f.observed_at,
                "invalid factual observation lifetime"
            );
        }
        for f in &self.domain_facts {
            ensure!(
                crate::rules::ascii_domain(&f.hostname)? == f.hostname,
                "noncanonical factual hostname"
            );
            ensure!(
                f.collection.starts_with("provider/") && !f.authority.trim().is_empty(),
                "invalid verified domain owner"
            );
            ensure!(
                f.observed_at > 0 && f.valid_until > f.observed_at,
                "invalid factual observation lifetime"
            );
        }
        Ok(())
    }
    pub fn domain_owner(&self, host: &str) -> Option<&str> {
        let owners: BTreeSet<_> = self
            .domain_facts
            .iter()
            .filter(|f| {
                f.hostname == host && current(f.observed_at, f.valid_until, self.observed_at)
            })
            .map(|f| f.collection.as_str())
            .collect();
        (owners.len() == 1).then(|| *owners.first().unwrap())
    }
    /// Prepartition the factual scopes once. Contradictory qualified facts abstain;
    /// source geolocation fusion remains deterministic for those intervals.
    pub fn location_spans(
        &self,
        family: u8,
        mapping: &BTreeMap<String, u8>,
    ) -> Result<Vec<(u128, u128, u8)>> {
        self.validate()?;
        let mut edges = BTreeMap::<u128, Vec<(usize, bool)>>::new();
        let mut facts = Vec::new();
        for fact in &self.location_facts {
            if !current(fact.observed_at, fact.valid_until, self.observed_at) {
                continue;
            }
            let (f, s, e) = crate::rules::ip_parts(fact.scope);
            if f != family {
                continue;
            }
            let Some(region) = mapping.get(&fact.country_code).copied() else {
                anyhow::bail!(
                    "qualified location country {} lacks a macroregion",
                    fact.country_code
                );
            };
            let i = facts.len();
            facts.push(region);
            edges.entry(s).or_default().push((i, true));
            if let Some(next) = e.checked_add(1) {
                edges.entry(next).or_default().push((i, false));
            }
        }
        let mut active = BTreeSet::new();
        let mut previous = None;
        let mut out = Vec::new();
        let mut emit = |s, e, active: &BTreeSet<usize>| {
            let regions: BTreeSet<_> = active.iter().map(|i| facts[*i]).collect();
            if regions.len() == 1 {
                out.push((s, e, *regions.first().unwrap()));
            }
        };
        for (point, changes) in edges {
            if let Some(s) = previous
                && s < point
            {
                emit(s, point - 1, &active);
            }
            for (i, add) in changes {
                if add {
                    active.insert(i);
                } else {
                    active.remove(&i);
                }
            }
            previous = Some(point);
        }
        if let Some(s) = previous {
            emit(s, u128::MAX, &active);
        }
        Ok(out)
    }
}

/// Hot path without vote-map allocations for the two independent installed products.
/// The generic owner-deduplicating function below supports additional same-type owners.
pub fn choose_installed_region(
    iplocate: Option<&str>,
    dbip: Option<&str>,
) -> Option<(String, &'static str)> {
    match (iplocate, dbip) {
        (Some(a), Some(b)) if a == b => Some((a.into(), "independent-location-majority")),
        (Some(a), Some(_)) => Some((a.into(), "location-source-priority")),
        (Some(a), None) | (None, Some(a)) => Some((a.into(), "independent-location-majority")),
        (None, None) => None,
    }
}

/// One owner gets at most one vote. Mirrors and duplicate products are not new owners;
/// contradictions within an owner abstain, and missing values never count as votes.
pub fn choose_region<'a>(
    votes: impl IntoIterator<Item = (&'a str, &'a str, u16)>,
) -> Option<(String, &'static str)> {
    let mut owners = BTreeMap::<&str, (BTreeSet<&str>, u16)>::new();
    for (owner, region, priority) in votes {
        let entry = owners
            .entry(owner)
            .or_insert_with(|| (BTreeSet::new(), priority));
        entry.0.insert(region);
        entry.1 = entry.1.min(priority);
    }
    let independent: Vec<_> = owners
        .iter()
        .filter(|(_, (regions, _))| regions.len() == 1)
        .map(|(owner, (regions, priority))| (*owner, *regions.first().unwrap(), *priority))
        .collect();
    let mut counts = BTreeMap::<&str, usize>::new();
    for (_, region, _) in &independent {
        *counts.entry(region).or_default() += 1;
    }
    if let Some((region, _)) = counts
        .iter()
        .find(|(_, count)| **count > independent.len() / 2)
    {
        return Some(((*region).into(), "independent-location-majority"));
    }
    independent
        .iter()
        .min_by_key(|(owner, _, priority)| (*priority, *owner))
        .map(|(_, region, _)| ((*region).into(), "location-source-priority"))
}

/// Snapshot controller-qualified positive and target-negative observations without mutating business state. Actual measurement
/// time bounds lifetime; retransmission and source-file downloads cannot refresh it.
/// Qualification describes evidence trust independently of whether an old attempt
/// is still allowed to complete its current queue job. Historical qualified receipts
/// remain reusable after source/case changes; accepted is execution accounting only.
/// Existing probes attest reachability/DNS only, so this deliberately does not invent
/// LocationFact or DomainFact records from observer country, RTT, BGP or DNS answers.
pub fn capture(store: &Store) -> Result<Snapshot> {
    let at = now();
    let conn = store.connect()?;
    let mut q=conn.prepare("SELECT j.target,j.kind,r.observed,r.evidence_until,r.evidence,r.node,r.execution_class,r.id FROM results r JOIN jobs j ON j.id=r.job_id WHERE ((r.qualified=1 AND r.outcome='ok') OR r.execution_class='target-failure') AND r.observed>? AND r.observed<=? AND (r.evidence_until IS NULL OR r.evidence_until>?)")?;
    let mut observations = Vec::new();
    let mut target_candidates = BTreeMap::<std::net::IpAddr, crate::discovery::Observation>::new();
    let mut legacy_expiry_defaults = 0usize;
    let mut negative_observations = 0usize;
    for row in q.query_map([at - 7 * 86400, at, at], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, Option<i64>>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, Option<String>>(6)?,
            r.get::<_, String>(7)?,
        ))
    })? {
        let (target, kind, observed_at, expiry, encoded, executor_id, execution_class, result_id) =
            row?;
        let negative = execution_class.as_deref() == Some("target-failure");
        let data: Value = serde_json::from_str(&encoded)?;
        let valid_until = expiry.unwrap_or_else(|| {
            legacy_expiry_defaults += usize::from(!negative);
            observed_at.saturating_add(if negative {
                crate::receipt::TRACE_NEGATIVE_TTL_SECONDS
            } else {
                7 * 86400
            })
        });
        if !current(observed_at, valid_until, at) {
            continue;
        }
        if !negative {
            for mut candidate in
                crate::discovery::receipt_observations(&result_id, observed_at, &data)
            {
                candidate.valid_until = candidate.valid_until.min(valid_until);
                if !crate::measure::public_ip(candidate.ip)
                    || !current(candidate.observed, candidate.valid_until, at)
                {
                    continue;
                }
                // One compact receipt per exact address. A direct endpoint response
                // outranks a DNS candidate; neither authorizes a surrounding prefix.
                let rank = |o: &crate::discovery::Observation| {
                    (o.kind == "endpoint-response", o.observed, o.valid_until)
                };
                match target_candidates.entry(candidate.ip) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(candidate);
                    }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if rank(&candidate) > rank(entry.get())
                            || (rank(&candidate) == rank(entry.get())
                                && candidate.source < entry.get().source)
                        {
                            entry.insert(candidate);
                        }
                    }
                }
            }
        }
        let reached = !negative
            && (data["reached"] == true
                || (kind == "traceroute"
                    && data["measurement"]["results"]
                        .as_array()
                        .is_some_and(|items| {
                            items.iter().any(|item| {
                                item["result"]["hops"].as_array().is_some_and(|hops| {
                                    hops.iter().any(|hop| {
                                        hop["resolvedAddress"].as_str() == Some(target.as_str())
                                            && hop["timings"].as_array().is_some_and(|times| {
                                                times.iter().any(|t| {
                                                    t["rtt"].as_f64().is_some_and(|rtt| rtt >= 0.0)
                                                })
                                            })
                                    })
                                })
                            })
                        })));
        let protocol = data["protocol"]
            .as_str()
            .or_else(|| data["measurement"]["measurementOptions"]["protocol"].as_str())
            .map(str::to_ascii_lowercase);
        let mut query_types = BTreeSet::new();
        if let Some(kind) = data["measurement"]["measurementOptions"]["query"]["type"].as_str() {
            query_types.insert(kind.to_ascii_uppercase());
        }
        for record in data["resolvers"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|r| r["records"].as_array().into_iter().flatten())
        {
            if let Some(kind) = record["query_type"].as_str() {
                query_types.insert(kind.to_ascii_uppercase());
            }
        }
        negative_observations += usize::from(negative);
        observations.push(Observation {
            target,
            kind,
            executor_id,
            protocol,
            query_types,
            execution_class: if negative {
                crate::receipt::ResultClass::TargetFailure
            } else {
                crate::receipt::ResultClass::Observation
            },
            observed_at,
            valid_until,
            reached,
        });
    }
    let count = observations.len();
    Ok(Snapshot {
        observed_at: at,
        summary: json!({"observation_cutoff":at,"qualified_observations":count-negative_observations,"negative_target_observations":negative_observations,"reusable_observations":count,"qualified_target_candidates":target_candidates.len(),"legacy_observations_using_7d_default":legacy_expiry_defaults,"qualified_target_location_facts":0,"qualified_domain_owner_facts":0,"location_gap":"existing DNS/traceroute receipts attest answers/reachability, not target country or service ownership"}),
        observations,
        target_candidates,
        ..Snapshot::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capture_reuses_actual_receipts_without_inventing_target_country() {
        use crate::store::{Node, ProbeResult};
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let node = Node {
            id: "fusion-observer".into(),
            region: "us".into(),
            asn: 64500,
            capabilities: vec!["traceroute".into()],
        };
        store
            .register_node(&node, &crate::hash("test-only"))
            .unwrap();
        for (i, age) in [(1, 60), (2, 60)] {
            let target = format!("1.1.1.{i}");
            store
                .enqueue_observation(&target, &["us".into()], "factual capture test")
                .unwrap();
            let lease = store.lease(&node).unwrap().unwrap();
            let receipt = ProbeResult {
                id: format!("capture-{i}"),
                job_id: lease.id.clone(),
                fingerprint: lease.fingerprint.clone(),
                lease_token: lease.token.clone(),
                observed_at: now() - age,
                outcome: "ok".into(),
                evidence: json!({"kind":"traceroute","target":target,"protocol":"icmp","reached":true,"hops":[{"ip":target}],"observer_country":"US","target_country":"TH"}),
            };
            assert_eq!(store.submit(&node.id, &receipt).unwrap()["qualified"], true);
            assert_eq!(store.submit(&node.id, &receipt).unwrap()["duplicate"], true);
        }
        // Model an old qualified legacy row retransmitted today: received time
        // never grants it a new lifetime.
        store
            .connect()
            .unwrap()
            .execute(
                "UPDATE results SET observed=?,evidence_until=NULL,received=? WHERE id='capture-2'",
                rusqlite::params![now() - 8 * 86400, now()],
            )
            .unwrap();
        let snapshot = capture(&store).unwrap();
        assert_eq!(snapshot.observations.len(), 1);
        assert_eq!(snapshot.observations[0].target, "1.1.1.1");
        assert!(snapshot.location_facts.is_empty());
        assert!(snapshot.domain_facts.is_empty());
        assert_eq!(
            snapshot.observations[0].valid_until,
            snapshot.observations[0].observed_at + 86400
        );
        store
            .connect()
            .unwrap()
            .execute(
                "UPDATE results SET evidence_until=NULL WHERE id='capture-1'",
                [],
            )
            .unwrap();
        let legacy = capture(&store).unwrap();
        assert_eq!(
            legacy.observations[0].valid_until,
            legacy.observations[0].observed_at + 7 * 86400
        );
        assert_eq!(legacy.summary["legacy_observations_using_7d_default"], 1);
    }
    #[test]
    fn qualified_late_receipt_survives_source_change_without_completing_new_scope() {
        use crate::store::{Node, ProbeResult};
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let node = Node {
            id: "historical-observer".into(),
            region: "us".into(),
            asn: 64500,
            capabilities: vec!["traceroute".into()],
        };
        store
            .register_node(&node, &crate::hash("fixture-only"))
            .unwrap();
        let case = store
            .enqueue_observation(
                "102.129.139.212",
                &["us".into()],
                "historical factual scope fixture",
            )
            .unwrap();
        let lease = store.lease(&node).unwrap().unwrap();
        store
            .connect()
            .unwrap()
            .execute(
                "UPDATE cases SET fp='changed-source',revision=revision+1 WHERE key=?",
                [&case],
            )
            .unwrap();
        let receipt = ProbeResult {
            id: "historical-trace".into(),
            job_id: lease.id.clone(),
            fingerprint: lease.fingerprint.clone(),
            lease_token: lease.token.clone(),
            observed_at: now() - 120,
            outcome: "ok".into(),
            evidence: json!({"kind":"traceroute","target":"102.129.139.212","protocol":"icmp","reached":true,"hops":[{"ip":"102.129.139.212"}],"observer_country":"US","target_country":"TH"}),
        };
        let ack = store.submit(&node.id, &receipt).unwrap();
        assert_eq!(ack["accepted"], false);
        assert_eq!(ack["qualified"], true);
        let before = store
            .connect()
            .unwrap()
            .query_row::<i64, _, _>(
                "SELECT received FROM results WHERE id=?",
                [&receipt.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(store.submit(&node.id, &receipt).unwrap()["duplicate"], true);
        let snapshot = capture(&store).unwrap();
        assert_eq!(snapshot.observations.len(), 1);
        assert_eq!(snapshot.observations[0].target, "102.129.139.212");
        assert_eq!(snapshot.observations[0].executor_id, node.id);
        assert_eq!(snapshot.observations[0].protocol.as_deref(), Some("icmp"));
        assert!(snapshot.observations[0].reached);
        assert_eq!(snapshot.observations[0].observed_at, receipt.observed_at);
        assert_eq!(
            snapshot.observations[0].valid_until,
            receipt.observed_at + 86400
        );
        assert!(snapshot.location_facts.is_empty());
        assert!(snapshot.domain_facts.is_empty());
        let conn = store.connect().unwrap();
        assert_ne!(
            conn.query_row::<String, _, _>(
                "SELECT status FROM jobs WHERE id=?",
                [&lease.id],
                |r| r.get(0)
            )
            .unwrap(),
            "complete"
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT received FROM results WHERE id=?",
                [&receipt.id],
                |r| r.get(0)
            )
            .unwrap(),
            before
        );
        assert_eq!(
            conn.query_row::<i64, _, _>(
                "SELECT count(*) FROM executor_counters WHERE completed_tasks>0",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
    }
    #[test]
    fn negative_target_fact_keeps_original_short_lifetime_and_never_votes_for_location() {
        use crate::store::{Node, ProbeResult};
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path()).unwrap();
        let node = Node {
            id: "negative-observer".into(),
            region: "us".into(),
            asn: 64500,
            capabilities: vec!["traceroute".into()],
        };
        store
            .register_node(&node, &crate::hash("fixture-only"))
            .unwrap();
        for (id, target, negative) in [
            ("target-negative", "1.1.1.1", true),
            ("executor-error", "2.2.2.2", false),
        ] {
            let case = store
                .enqueue_observation(target, &["us".into()], "negative factual capture fixture")
                .unwrap();
            let lease = store.lease(&node).unwrap().unwrap();
            store
                .connect()
                .unwrap()
                .execute(
                    "UPDATE cases SET fp='new-source',revision=revision+1 WHERE key=?",
                    [case],
                )
                .unwrap();
            let evidence = if negative {
                json!({"kind":"traceroute","target":target,"protocol":"icmp","target_error":"timeout","reached":false,"observer_country":"US","target_country":"TH"})
            } else {
                json!({"kind":"traceroute","target":target,"protocol":"icmp","error":"Network unreachable"})
            };
            let receipt = ProbeResult {
                id: id.into(),
                job_id: lease.id.clone(),
                fingerprint: lease.fingerprint.clone(),
                lease_token: lease.token.clone(),
                observed_at: now() - 120,
                outcome: "error".into(),
                evidence,
            };
            let ack = store.submit(&node.id, &receipt).unwrap();
            assert_eq!(ack["accepted"], false);
            assert_eq!(ack["qualified"], false);
            assert_eq!(
                ack["execution_class"],
                if negative {
                    "target-failure"
                } else {
                    "executor-failure"
                }
            );
            assert_eq!(store.submit(&node.id, &receipt).unwrap()["duplicate"], true);
        }
        let snapshot = capture(&store).unwrap();
        assert_eq!(snapshot.observations.len(), 1);
        let observation = &snapshot.observations[0];
        assert_eq!(observation.target, "1.1.1.1");
        assert!(!observation.reached);
        assert_eq!(
            observation.execution_class,
            crate::receipt::ResultClass::TargetFailure
        );
        assert_eq!(observation.valid_until, observation.observed_at + 300);
        assert_eq!(snapshot.summary["negative_target_observations"], 1);
        assert_eq!(snapshot.summary["qualified_observations"], 0);
        assert!(snapshot.target_candidates.is_empty());
        assert!(snapshot.location_facts.is_empty());
        assert!(snapshot.domain_facts.is_empty());
        assert_eq!(
            choose_installed_region(Some("us"), Some("southeast-asia"))
                .unwrap()
                .0,
            "us"
        );
        store
            .connect()
            .unwrap()
            .execute(
                "UPDATE results SET evidence_until=? WHERE id='target-negative'",
                [now() - 1],
            )
            .unwrap();
        assert!(capture(&store).unwrap().observations.is_empty());
    }
    #[test]
    fn majority_deduplicates_owners_and_fallback_is_stable() {
        assert_eq!(
            choose_region([("iplocate", "us", 0), ("dbip", "cn", 1)]),
            Some(("us".into(), "location-source-priority"))
        );
        assert_eq!(
            choose_region([("iplocate", "us", 0), ("dbip", "cn", 1), ("dbip", "cn", 1)])
                .unwrap()
                .0,
            "us"
        );
        assert_eq!(
            choose_region([("a", "us", 0), ("b", "cn", 1), ("c", "cn", 2)])
                .unwrap()
                .0,
            "cn"
        );
        assert!(choose_region([("a", "us", 0), ("a", "cn", 0)]).is_none());
    }
    #[test]
    fn location_scope_and_actual_observation_lifetime_are_preserved() {
        let mut snapshot = Snapshot {
            observed_at: 100,
            ..Snapshot::default()
        };
        snapshot.location_facts.push(LocationFact {
            scope: "102.129.139.212/32".parse().unwrap(),
            country_code: "TH".into(),
            authority: "verified-operator".into(),
            method: LocationMethod::TargetLocationAttestation,
            observed_at: 90,
            valid_until: 110,
        });
        let mapping = BTreeMap::from([("TH".into(), 1)]);
        let spans = snapshot.location_spans(4, &mapping).unwrap();
        assert_eq!(spans, [(0x66818bd4, 0x66818bd4, 1)]);
        snapshot.observed_at = 110;
        assert!(snapshot.location_spans(4, &mapping).unwrap().is_empty());
    }
    #[test]
    fn conflicting_facts_abstain_without_guessing_from_path() {
        let at = 100;
        let mut snapshot = Snapshot {
            observed_at: at,
            ..Snapshot::default()
        };
        for code in ["US", "TH"] {
            snapshot.location_facts.push(LocationFact {
                scope: "1.1.1.1/32".parse().unwrap(),
                country_code: code.into(),
                authority: code.into(),
                method: LocationMethod::TargetLocationAttestation,
                observed_at: 90,
                valid_until: 110,
            });
        }
        assert!(
            snapshot
                .location_spans(4, &BTreeMap::from([("US".into(), 0), ("TH".into(), 1)]))
                .unwrap()
                .is_empty()
        );
        assert!(serde_json::from_value::<LocationFact>(json!({"scope":"1.1.1.1/32","country_code":"TH","authority":"trace","method":"traceroute","observed_at":90,"valid_until":110})).is_err());
    }
}
