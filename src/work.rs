//! Demand-driven observation planning. One job is one missing observation;
//! executors compete for it rather than receiving copies of the same work.
use crate::{
    fingerprint, now,
    store::{Lease, Store},
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn scope_sql(j: &str, n: &str, owned: bool) -> String {
    format!(
        "(coalesce(json_extract({j}.profile,'$.observer_id'),'')='' OR json_extract({j}.profile,'$.observer_id')={n}.id) AND (coalesce(json_extract({j}.profile,'$.region_required'),0)=0 OR {j}.region={n}.region) AND ({n}.id LIKE 'globalping:%' OR coalesce(json_extract({j}.profile,'$.required_asn'),0)=0 OR json_extract({j}.profile,'$.required_asn')={n}.asn) AND ({n}.id LIKE 'globalping:%' OR NOT EXISTS(SELECT 1 FROM json_each({j}.profile,'$.excluded_asns') WHERE value={n}.asn)) AND (coalesce(json_extract({j}.profile,'$.self_only'),0)=0 OR {n}.id NOT LIKE 'globalping:%') {}",
        if owned {
            String::new()
        } else {
            format!(
                "AND (coalesce(json_extract({j}.profile,'$.remote_only'),0)=0 OR {n}.id LIKE 'globalping:%')"
            )
        }
    )
}
fn family_sql(j: &str, n: &str) -> String {
    format!(
        "CASE WHEN {j}.kind='dns' THEN coalesce({n}.ipv4_supported,1)=1 OR coalesce({n}.ipv6_supported,0)=1 WHEN instr({j}.target,':')>0 THEN coalesce({n}.ipv6_supported,0)=1 ELSE coalesce({n}.ipv4_supported,1)=1 END"
    )
}
pub fn eligibility_sql(j: &str, n: &str) -> String {
    let scope = scope_sql(j, n, false);
    let family = family_sql(j, n);
    let other_scope = scope_sql(j, "alternative", false);
    let other_family = family_sql(j, "alternative");
    let fault = format!(
        "NOT EXISTS(SELECT 1 FROM lease_history h WHERE h.execution_job_id={j}.id AND h.round_seq={j}.round_seq AND h.node={n}.id AND h.result_class IN ('executor-failure','not-executed'))"
    );
    let alternative = format!(
        "EXISTS(SELECT 1 FROM nodes alternative WHERE alternative.id<>{n}.id AND alternative.disabled=0 AND coalesce(alternative.executor_cooldown_until,0)<=CAST(strftime('%s','now') AS INTEGER) AND (alternative.id LIKE 'globalping:%' OR (alternative.connected=1 AND alternative.last_seen>CAST(strftime('%s','now') AS INTEGER)-120)) AND {j}.kind IN (SELECT value FROM json_each(alternative.capabilities)) AND {other_scope} AND (alternative.id LIKE 'globalping:%' OR ({other_family})) AND NOT EXISTS(SELECT 1 FROM lease_history failed WHERE failed.execution_job_id={j}.id AND failed.round_seq={j}.round_seq AND failed.node=alternative.id AND failed.result_class IN ('executor-failure','not-executed','target-failure')))"
    );
    let confirmation = format!(
        "(NOT EXISTS(SELECT 1 FROM lease_history previous WHERE previous.execution_job_id={j}.id AND previous.round_seq={j}.round_seq AND previous.node={n}.id AND previous.result_class='target-failure') OR NOT ({alternative}))"
    );
    let diverse = alternative.replace(
        "WHERE alternative.id<>",
        &format!("WHERE alternative.asn>0 AND alternative.asn<>{n}.asn AND alternative.id<>"),
    );
    let asn_preference = format!(
        "({n}.id LIKE 'globalping:%' OR NOT EXISTS(SELECT 1 FROM lease_history previous WHERE previous.execution_job_id={j}.id AND previous.round_seq={j}.round_seq AND previous.result_class='target-failure' AND previous.observer_asn={n}.asn) OR NOT ({diverse}))"
    );
    format!(
        "{n}.disabled=0 AND coalesce({n}.executor_cooldown_until,0)<=CAST(strftime('%s','now') AS INTEGER) AND {j}.execution_count<3 AND {fault} AND {confirmation} AND {asn_preference} AND (coalesce(json_extract({j}.profile,'$.legacy_alias'),0)=0 OR json_extract({j}.profile,'$.logical_job')=1) AND {j}.kind IN (SELECT value FROM json_each({n}.capabilities)) AND {scope} AND ({n}.id NOT LIKE 'globalping:%' OR coalesce(json_array_length({j}.profile,'$.excluded_asns'),0)=0 OR (coalesce(json_extract({j}.profile,'$.required_asn'),0)>0 AND NOT EXISTS(SELECT 1 FROM json_each({j}.profile,'$.excluded_asns') WHERE value=json_extract({j}.profile,'$.required_asn')))) AND ({n}.id NOT LIKE 'globalping:%' OR NOT EXISTS(SELECT 1 FROM gp_unavailable u WHERE u.executor={n}.id AND u.family=CASE WHEN instr({j}.target,':')>0 THEN 6 ELSE 4 END AND u.until>CAST(strftime('%s','now') AS INTEGER))) AND ({n}.id LIKE 'globalping:%' OR ({family}))"
    )
}
pub fn uncovered_sql(j: &str) -> String {
    let scope = scope_sql(j, "owned", true);
    let family = family_sql(j, "owned");
    format!(
        "NOT EXISTS(SELECT 1 FROM nodes owned WHERE owned.id NOT LIKE 'globalping:%' AND owned.connected=1 AND owned.disabled=0 AND owned.last_seen>CAST(strftime('%s','now') AS INTEGER)-120 AND coalesce(owned.executor_cooldown_until,0)<=CAST(strftime('%s','now') AS INTEGER) AND NOT EXISTS(SELECT 1 FROM lease_history h WHERE h.execution_job_id={j}.id AND h.round_seq={j}.round_seq AND h.node=owned.id AND h.result_class IN ('executor-failure','not-executed','target-failure')) AND {j}.kind IN (SELECT value FROM json_each(owned.capabilities)) AND {scope} AND ({family}))"
    )
}

/// Strip implementation-only executor copies while retaining true observation
/// constraints. Candidate ownership regions are never required vantage points.
pub fn logical_profile(profile: &Value) -> Value {
    let mut p = profile.clone();
    if let Some(m) = p.as_object_mut() {
        for k in [
            "observer",
            "network_support",
            "attempt_seq",
            "globalping_reserved_tests",
            "globalping_reserved_hour",
            "discovery_generation",
            "reason",
            "preferred_regions",
        ] {
            m.remove(k);
        }
        if matches!(
            m.get("purpose").and_then(Value::as_str),
            Some("baseline" | "seed" | "supplement")
        ) {
            for k in ["observer_id", "self_only", "remote_only", "region_required"] {
                m.remove(k);
            }
            m.insert("purpose".into(), json!("observation"));
        }
        if m.get("purpose").and_then(Value::as_str) == Some("discovery") {
            m.remove("observer_id");
            m.insert("self_only".into(), json!(true));
        }
        m.insert("scheduler".into(), json!(2));
        m.insert("logical_job".into(), json!(true));
    }
    p
}
pub fn logical_key(
    _identity: (&str, &str, i64),
    target: &str,
    kind: &str,
    region: &str,
    profile: &Value,
) -> String {
    let target = normalize_target(target);
    let profile = canonical_method(kind, profile);
    let protocol = profile["protocol"].as_str().or(if kind == "traceroute" {
        Some("icmp")
    } else {
        None
    });
    let max_hops =
        profile["max_hops"]
            .as_u64()
            .or(if kind == "traceroute" { Some(24) } else { None });
    fingerprint(&json!([
        "shared-observation-v4",
        target,
        kind,
        region,
        protocol,
        max_hops,
        profile["query"],
        profile["query_type"],
        profile["required_asn"],
        profile["excluded_asns"]
    ]))
}

fn canonical_method(kind: &str, profile: &Value) -> Value {
    let mut p = profile.clone();
    if let Some(protocol) = p["protocol"].as_str() {
        p["protocol"] = json!(protocol.to_ascii_lowercase());
    } else if kind == "traceroute" {
        p["protocol"] = json!("icmp");
    }
    if kind == "traceroute" && p["max_hops"].is_null() {
        p["max_hops"] = json!(24);
    }
    if let Some(query_type) = p["query"]["type"]
        .as_str()
        .or_else(|| p["query_type"].as_str())
    {
        let query_type = query_type.to_ascii_uppercase();
        p["query_type"] = json!(query_type);
        if p["query"].is_object() {
            p["query"].as_object_mut().unwrap().remove("type");
            if p["query"].as_object().unwrap().is_empty() {
                p.as_object_mut().unwrap().remove("query");
            }
        }
    }
    let excluded: BTreeSet<u64> = p["excluded_asns"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_u64)
        .collect();
    p["excluded_asns"] = json!(excluded);
    p
}

pub(crate) struct ObservationDemand {
    pub target: String,
    pub kind: &'static str,
    pub region: String,
    pub profile: Value,
}

/// The same pure derivation is used by planning and the final send fence. Source
/// fingerprints are not a substitute for checking current method/view settings.
pub(crate) fn observation_demands(payload: &Value) -> Result<Vec<ObservationDemand>> {
    if payload["measurement_required"] == false {
        return Ok(vec![]);
    }
    let discovery = payload["kind"] == "target-discovery";
    let manual = payload["manual"] == true
        || matches!(
            payload["kind"].as_str(),
            Some("domain-observation" | "manual-ip")
        );
    let kind = if payload["kind"] == "domain-observation" || discovery {
        "dns"
    } else {
        "traceroute"
    };
    let regions = if manual {
        payload["regions"].as_array()
    } else {
        payload["observation_regions"]
            .as_array()
            .or_else(|| payload["required_regions"].as_array())
    };
    let mut regions: BTreeSet<String> = regions
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .collect();
    if regions.is_empty() {
        regions.insert("any".into());
    }
    let mut profile = json!({"purpose":if discovery {"discovery"} else if manual {"manual"} else {"observation"}});
    for field in [
        "required_asn",
        "excluded_asns",
        "query",
        "query_type",
        "protocol",
        "max_hops",
    ] {
        if let Some(value) = payload.get(field) {
            profile[field] = value.clone();
        }
    }
    let profile = canonical_method(kind, &profile);
    if kind == "traceroute" {
        ensure!(
            profile["protocol"] == "icmp",
            "unsupported traceroute protocol; only ICMP is supported"
        );
        ensure!(
            profile["max_hops"]
                .as_u64()
                .is_some_and(|v| (1..=24).contains(&v)),
            "traceroute max_hops must be 1–24"
        );
    }
    let targets: BTreeSet<String> = payload["targets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|t| precise_target(payload, t, kind))
        .map(normalize_target)
        .collect();
    let mut out = vec![];
    for target in targets {
        for region in &regions {
            let mut profile = profile.clone();
            profile["region_required"] = json!(region != "any");
            out.push(ObservationDemand {
                target: target.clone(),
                kind,
                region: region.clone(),
                profile,
            });
        }
    }
    Ok(out)
}
pub fn demand_key(
    _case_key: &str,
    target: &str,
    kind: &str,
    region: &str,
    profile: &Value,
) -> String {
    logical_key(("", "", 0), target, kind, region, profile)
}
pub fn normalize_target(target: &str) -> String {
    target
        .parse::<std::net::IpAddr>()
        .map(|v| v.to_string())
        .unwrap_or_else(|_| target.trim_end_matches('.').to_ascii_lowercase())
}

fn add_job(
    c: &Connection,
    identity: (&str, &str, i64),
    target: &str,
    kind: &str,
    region: &str,
    mut profile: Value,
    fresh_build: Option<&str>,
) -> Result<(String, usize)> {
    let (key, source_fp, revision) = identity;
    let target = normalize_target(target);
    for field in [
        "observer_id",
        "self_only",
        "remote_only",
        "epoch",
        "case_revision",
    ] {
        profile.as_object_mut().unwrap().remove(field);
    }
    profile["scheduler"] = json!(2);
    profile["logical_job"] = json!(true);
    profile["observation_schema"] = json!(4);
    profile = canonical_method(kind, &profile);
    let logical = logical_key(identity, &target, kind, region, &profile);
    let id = format!("job-{}", &logical[..32]);
    let build: Option<String> = c
        .query_row(
            "SELECT value FROM meta WHERE key='current-build-id'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let inserted=c.prepare_cached("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,logical_key,demand_key,round_build_id) VALUES(?,?,?,?,?,?,?,'pending',?,?,?,?,?) ON CONFLICT(id) DO NOTHING")?.execute(params![id,key,logical,kind,target,region,profile.to_string(),now(),now(),logical,logical,build])?;
    c.prepare_cached("INSERT INTO job_cases(job_id,case_key,fp,revision,required_round_seq) VALUES(?,?,?,?,1) ON CONFLICT(job_id,case_key) DO UPDATE SET fp=excluded.fp,revision=excluded.revision WHERE job_cases.fp IS NOT excluded.fp OR job_cases.revision IS NOT excluded.revision")?.execute(params![id,key,source_fp,revision])?;
    // A case becoming active does not reset a shared execution budget or paid intent.
    c.prepare_cached("UPDATE jobs AS j SET status='pending',not_before=? WHERE id=? AND status='obsolete' AND execution_count<3 AND NOT EXISTS(SELECT 1 FROM jobs old JOIN gp_remote g ON g.job_id=old.id WHERE old.demand_key=j.demand_key)")?.execute(params![now(),id])?;
    if let Some((result, expiry)) = prior_observation(c, &target, kind, region, &profile)? {
        c.prepare_cached("UPDATE jobs SET status='complete',result_id=?,evidence_until=?,execution_terminal=1 WHERE id=? AND status IN ('pending','unknown','obsolete') AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id)")?.execute(params![result,expiry,id])?;
    } else if let Some(build) = fresh_build {
        crate::jobs_v3::reopen_round_on(c, &id, Some(build), false)?;
    }
    c.prepare_cached("UPDATE jobs AS old SET status='obsolete' WHERE logical_key=? AND id<>? AND status='pending' AND json_extract(profile,'$.legacy_alias')=1 AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=old.id)")?.execute(params![logical,id])?;
    Ok((id, inserted))
}

/// Scope/method-qualified reuse is independent of the old case/build. Candidate
/// evidence is bounded and revalidated from actual persisted observer metadata.
fn prior_observation(
    c: &Connection,
    target: &str,
    kind: &str,
    region: &str,
    profile: &Value,
) -> Result<Option<(String, Option<i64>)>> {
    prior_observation_inner(c, target, kind, region, profile, true)
}
pub(crate) fn prior_negative_observation(
    c: &Connection,
    target: &str,
    kind: &str,
    region: &str,
    profile: &Value,
) -> Result<Option<(String, Option<i64>)>> {
    prior_observation_inner(c, target, kind, region, profile, false)
}
fn prior_observation_inner(
    c: &Connection,
    target: &str,
    kind: &str,
    region: &str,
    profile: &Value,
    include_positive: bool,
) -> Result<Option<(String, Option<i64>)>> {
    let mapping: Option<String> = c
        .query_row(
            "SELECT value FROM meta WHERE key='observation-country-regions'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let rows = {
        let mut q=c.prepare_cached("SELECT r.id,r.job_id,r.node,r.fp,r.observed,r.outcome,r.evidence,r.evidence_until,h.lease_profile FROM jobs j JOIN results r ON r.job_id=j.id LEFT JOIN lease_history h ON h.job_id=r.job_id AND h.node=r.node AND h.attempt_seq=r.attempt_seq AND h.lease_profile IS NOT NULL WHERE j.target=? AND j.kind=? AND ((r.qualified=1 AND r.outcome='ok') OR r.execution_class='target-failure') AND (r.evidence_until IS NULL OR r.evidence_until>?) ORDER BY r.observed DESC,r.id LIMIT 128")?;
        q.query_map(params![target, kind, now()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, Option<i64>>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    struct Negative {
        id: String,
        until: i64,
        lease: Lease,
        observer: String,
    }
    let mut negative_keys = BTreeSet::new();
    let mut first_negative: Option<Negative> = None;
    for (id, job, node, fp, observed, outcome, body, expiry, history) in rows {
        let mut requested = profile.clone();
        if let Some(history) = history {
            let p: Value = serde_json::from_str(&history)?;
            requested["observer"] = p["observer"].clone();
        }
        if let Some(mapping) = mapping.as_deref() {
            requested["observation_country_regions"] = serde_json::from_str(mapping)?;
        }
        let observer = crate::store::Node {
            id: node.clone(),
            region: requested["observer"]["region"]
                .as_str()
                .unwrap_or("")
                .into(),
            asn: requested["observer"]["asn"].as_u64().unwrap_or(0) as u32,
            capabilities: vec![kind.into()],
        };
        let lease = Lease {
            id: job.clone(),
            case_key: String::new(),
            fingerprint: fp.clone(),
            kind: kind.into(),
            target: target.into(),
            region: region.into(),
            token: String::new(),
            until: 0,
            profile: requested,
        };
        let result = crate::store::ProbeResult {
            id: id.clone(),
            job_id: job,
            fingerprint: fp,
            lease_token: String::new(),
            observed_at: observed,
            outcome,
            evidence: serde_json::from_str(&body)?,
        };
        let q = crate::receipt::qualify(&lease, &observer, &result);
        let bound = match (q.evidence_until, expiry) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };
        if include_positive && q.qualified && bound.is_some_and(|until| until > now()) {
            return Ok(Some((id, bound)));
        }
        if q.class == crate::receipt::ResultClass::TargetFailure
            && q.execution_terminal
            && let Some(until) = bound.filter(|until| *until > now())
            && let Some(key) = crate::receipt::negative_observer_key(&lease, &observer, &result)
            && negative_keys.insert(key)
        {
            if let Some(first) = first_negative.as_ref() {
                return Ok(Some((id, Some(until.min(first.until)))));
            }
            first_negative = Some(Negative {
                id,
                until,
                lease,
                observer: node,
            });
        }
    }
    if let Some(first) = first_negative
        && !crate::receipt::has_other_observer_on(c, &first.lease, &first.observer)?
    {
        return Ok(Some((first.id, Some(first.until))));
    }
    Ok(None)
}

/// Reuse facts only at a pending demand or a provably unsent reservation.
/// This never finishes an already-started attempt or reconciles a GP intent.
pub(crate) fn reuse_fresh_observation_on(
    c: &Connection,
    job_id: &str,
    token: Option<&str>,
) -> Result<bool> {
    type ReusableJob = (String, String, String, String, String, i64, Option<String>);
    let row: Option<ReusableJob> = c
        .query_row(
            "SELECT target,kind,region,profile,status,attempt_seq,lease_token FROM jobs WHERE id=?",
            [job_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                ))
            },
        )
        .optional()?;
    let Some((target, kind, region, body, status, seq, current_token)) = row else {
        return Ok(false);
    };
    if crate::jobs_v3::current_case_links_on(c, job_id)?.is_empty() {
        return Ok(false);
    }
    if status == "leased" {
        if token.is_none() || token != current_token.as_deref() {
            return Ok(false);
        }
        let provably_unsent:bool=c.query_row(
            "SELECT EXISTS(SELECT 1 FROM lease_history WHERE job_id=? AND token_hash=? AND attempt_seq=? AND started_at IS NULL AND execution_refunded=0 AND json_extract(lease_profile,'$.execution_reservation_schema')=1)",
            params![job_id,crate::hash(token.unwrap()),seq],|r|r.get(0))?;
        if !provably_unsent {
            return Ok(false);
        }
    } else if status != "pending" {
        return Ok(false);
    }
    let remote: Option<(String, String)> = c
        .query_row(
            "SELECT remote_id,lease FROM gp_remote WHERE job_id=?",
            [job_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((remote_id, saved)) = remote {
        if token.is_none() || !remote_id.is_empty() {
            return Ok(false);
        }
        // A legacy empty ID is unknown, not proof of an unsent preparation.
        let state_column: bool = c.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('gp_remote') WHERE name='state')",
            [],
            |r| r.get(0),
        )?;
        if !state_column {
            return Ok(false);
        }
        let state: String = c.query_row(
            "SELECT state FROM gp_remote WHERE job_id=?",
            [job_id],
            |r| r.get(0),
        )?;
        let saved: Value = serde_json::from_str(&saved)?;
        if state != "prepared"
            || saved["token"].as_str() != token
            || saved["profile"]["attempt_seq"].as_i64() != Some(seq)
        {
            return Ok(false);
        }
    }
    let profile: Value = serde_json::from_str(&body)?;
    let Some((result, expiry)) = prior_observation(c, &target, &kind, &region, &profile)? else {
        return Ok(false);
    };
    if status == "leased" {
        // The attempt is cancelled as unexecuted; only the logical demand is
        // satisfied by a separately authenticated historical fact.
        c.execute("UPDATE lease_history SET execution_refunded=1,result_class='not-executed',completed_at=? WHERE job_id=? AND token_hash=? AND attempt_seq=? AND started_at IS NULL AND execution_refunded=0",params![now(),job_id,crate::hash(token.unwrap()),seq])?;
    }
    Ok(c.execute("UPDATE jobs SET status='complete',result_id=?,evidence_until=?,execution_terminal=1,failure_count=0,next_round_at=NULL,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=? AND status=? AND (? IS NULL OR lease_token=?)",params![result,expiry,job_id,status,token,token])?==1)
}

pub(crate) fn precise_target(payload: &Value, target: &str, kind: &str) -> bool {
    if kind == "dns" {
        return !target.is_empty() && !target.contains(['*', '/', ' ']);
    }
    let Ok(ip) = target.parse::<std::net::IpAddr>() else {
        return false;
    };
    if !crate::measure::public_ip(ip) {
        return false;
    }
    let (family, address) = crate::rules::addr_num(ip);
    if payload["family"]
        .as_u64()
        .is_some_and(|v| v != u64::from(family))
    {
        return false;
    }
    let ranges = payload["ranges"].as_array();
    if let Some(ranges) = ranges.filter(|r| !r.is_empty()) {
        return ranges.iter().any(|r|{
            let start=r[0].as_str().and_then(|s|s.parse().ok()).map(crate::rules::addr_num);
            let end=r[1].as_str().and_then(|s|s.parse().ok()).map(crate::rules::addr_num);
            matches!((start,end),(Some((f,s)),Some((g,e)))if f==family&&g==family&&s<=address&&address<=e)
        });
    }
    payload["manual"] == true || payload["kind"] == "manual-ip"
}

pub fn plan_on(c: &Connection, key: &str, fp: &str, payload: &Value) -> Result<usize> {
    plan_on_build(c, key, fp, payload, None)
}
fn plan_on_build(
    c: &Connection,
    key: &str,
    fp: &str,
    payload: &Value,
    fresh_build: Option<&str>,
) -> Result<usize> {
    let fresh_build = fresh_build.filter(|_| payload["repeat_on_build"] != false);
    ensure!(
        payload["measurement_required"] != false,
        "this case requires passive/manual review"
    );
    let revision: i64 = c
        .prepare_cached(
            "SELECT revision FROM cases WHERE key=? AND fp=? AND active=1 AND status<>'decided'",
        )?
        .query_row(params![key, fp], |r| r.get(0))?;
    let demands = observation_demands(payload)?;

    let old_jobs = {
        let mut q = c.prepare_cached("SELECT job_id FROM job_cases WHERE case_key=?")?;
        q.query_map([key], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut count = 0;
    let mut desired = vec![];
    for demand in demands {
        let (id, created) = add_job(
            c,
            (key, fp, revision),
            &demand.target,
            demand.kind,
            &demand.region,
            demand.profile,
            fresh_build,
        )?;
        desired.push(id);
        count += created;
    }
    c.prepare_cached(
        "DELETE FROM job_cases WHERE case_key=? AND job_id NOT IN (SELECT value FROM json_each(?)) AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.id=job_cases.job_id AND (j.status='leased' OR EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id)))",
    )?
    .execute(params![key, serde_json::to_string(&desired)?])?;
    for old in old_jobs {
        retire_unneeded_on(c, &old)?;
    }
    Ok(count)
}

pub fn migrate(s: &Store) -> Result<()> {
    crate::jobs_v3::migrate(s)
}
/// Executor capabilities only affect eligibility, never the logical job count.
/// Wake the loop to fill DNS discovery vacancies without expanding every case.
pub fn mark_node_change(s: &Store, _id: Option<&str>) -> Result<()> {
    s.wake.notify_waiters();
    Ok(())
}
pub fn mark_case(c: &Connection, key: &str) -> Result<()> {
    c.execute(
        "INSERT INTO replan_cases(case_key,queued_at) VALUES(?,?) ON CONFLICT(case_key) DO NOTHING",
        params![key, now()],
    )?;
    Ok(())
}

fn fill_discovery_on(c: &mut Connection) -> Result<usize> {
    if !c.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM case_metadata WHERE active=1 AND status='blocked-target')",
        [],
        |r| r.get(0),
    )? {
        return Ok(0);
    }
    let capacity:i64=c.query_row("SELECT coalesce(sum(min(coalesce(concurrency_limit,10),coalesce(worker_capacity,1000))),0) FROM nodes WHERE id NOT LIKE 'globalping:%' AND connected=1 AND disabled=0 AND last_seen>? AND (coalesce(ipv4_supported,1)=1 OR coalesce(ipv6_supported,0)=1) AND EXISTS(SELECT 1 FROM json_each(capabilities) WHERE value='dns')",[now()-120],|r|r.get(0))?;
    let discovery:i64=c.query_row("SELECT count(*) FROM jobs INDEXED BY job_discovery_active WHERE status IN ('pending','leased') AND json_extract(profile,'$.purpose')='discovery' AND json_extract(profile,'$.logical_job')=1",[],|r|r.get(0))?;
    let running:i64=c.query_row("SELECT count(*) FROM jobs WHERE status='leased' AND lease_node NOT LIKE 'globalping:%' AND coalesce(json_extract(profile,'$.purpose'),'')<>'discovery'",[],|r|r.get(0))?;
    let limit = (capacity - running - discovery).clamp(0, 128);
    if limit == 0 {
        return Ok(0);
    }
    let cursor: String = c
        .query_row(
            "SELECT value FROM meta WHERE key='shared-dns-host-cursor'",
            [],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let mut hosts = vec![];
    for after in [cursor.as_str(), ""] {
        let mut q=c.prepare_cached("SELECT h.host FROM discovery_domains h LEFT JOIN discovery_checks d ON d.kind='shared-dns' AND d.key=h.host WHERE h.host>? AND coalesce(d.next_check,0)<=? AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.target=h.host AND j.kind='dns' AND j.status IN ('pending','leased')) ORDER BY h.host LIMIT ?")?;
        hosts = q
            .query_map(params![after, now(), limit], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !hosts.is_empty() || cursor.is_empty() {
            break;
        }
    }
    if hosts.is_empty() {
        return Ok(0);
    }
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let mut count = 0;
    for host in &hosts {
        let key = format!("discover:{host}");
        let fp = fingerprint(&json!(["shared-target-discovery-v3", host]));
        let payload = json!({"kind":"target-discovery","targets":[host],"regions":[],"purpose":"find addresses in unresolved conflict ranges"});
        tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,?,1,'target-discovery',?,'accepted-domain DNS target discovery',?,'needs-active',1,?) ON CONFLICT(key) DO UPDATE SET fp=excluded.fp,revision=cases.revision+(cases.fp<>excluded.fp),active=1 WHERE cases.fp<>excluded.fp OR cases.active=0",params![key,fp,host,payload.to_string(),now()])?;
        count += plan_on(&tx, &key, &fp, &payload)?;
        // TTL expiry alone never puts discovery at the queue head again. Only
        // this due catalogue selection may reopen its existing logical job.
        let expired = {
            let mut q = tx.prepare_cached("SELECT j.id FROM job_cases l JOIN jobs j ON j.id=l.job_id WHERE l.case_key=? AND j.kind='dns' AND j.status='complete' AND json_extract(j.profile,'$.logical_job')=1 AND j.evidence_until<=?")?;
            q.query_map(params![key, now()], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for job in expired {
            count += usize::from(crate::jobs_v3::reopen_round_on(&tx, &job, None, true)?);
        }
        tx.execute("INSERT INTO discovery_checks(kind,key,checked,next_check,error) VALUES('shared-dns',?,?,?,NULL) ON CONFLICT(kind,key) DO UPDATE SET checked=excluded.checked,next_check=excluded.next_check,error=NULL",params![host,now(),now()+300])?;
    }
    tx.execute("INSERT INTO meta(key,value) VALUES('shared-dns-host-cursor',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[hosts.last().unwrap()])?;
    tx.commit()?;
    Ok(count)
}

// A prepared candidate is a read snapshot, not permission to acknowledge a
// change. The short write batch compares it with the transaction's current row.
struct Replan {
    key: String,
    fp: Option<String>,
    revision: Option<i64>,
    active: Option<bool>,
    status: Option<String>,
    body: Option<String>,
    queued: i64,
    build_id: Option<String>,
    payload: Value,
}

fn completed_discovery_on(c: &Connection, row: &Replan) -> Result<bool> {
    if row.payload["kind"] != "target-discovery" {
        return Ok(false);
    }
    let demands = observation_demands(&row.payload)?;
    if demands.is_empty() {
        return Ok(false);
    }
    for demand in demands {
        let logical = logical_key(
            ("", "", 0),
            &demand.target,
            demand.kind,
            &demand.region,
            &demand.profile,
        );
        if !c.query_row(
            "SELECT EXISTS(SELECT 1 FROM job_cases l JOIN jobs j ON j.id=l.job_id WHERE l.case_key=?1 AND l.fp=?2 AND l.revision=?3 AND j.logical_key=?4 AND json_extract(j.profile,'$.logical_job')=1 AND j.status='complete' AND l.required_round_seq<=j.round_seq)",
            params![row.key,row.fp,row.revision,logical], |r| r.get::<_,bool>(0),
        )? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prepare_replans_on(s: &Store, c: &mut Connection) -> Result<Vec<Replan>> {
    let rows = {
        let mut q=c.prepare("SELECT q.case_key,c.fp,c.revision,c.active,c.status,c.payload,q.queued_at,q.build_id FROM replan_cases q LEFT JOIN cases c ON c.key=q.case_key ORDER BY q.queued_at,q.case_key LIMIT 128")?;
        q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<bool>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, Option<String>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Option<String>>(7)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut ready = Vec::with_capacity(rows.len());
    for (key, fp, revision, active, status, body, queued, build_id) in rows {
        // Candidate lookup may update targets; all such work is outside the batch.
        if active == Some(true)
            && status.as_deref() == Some("blocked-target")
            && crate::scheduler::discover_case_targets(s, &key)? > 0
        {
            continue;
        }
        let payload = body
            .as_deref()
            .map(serde_json::from_str)
            .transpose()?
            .unwrap_or(Value::Null);
        ready.push(Replan {
            key,
            fp,
            revision,
            active,
            status,
            body,
            queued,
            build_id,
            payload,
        });
    }
    Ok(ready)
}
fn apply_replans_on(c: &mut Connection, candidates: &[Replan]) -> Result<()> {
    c.set_prepared_statement_cache_capacity(32);
    for batch in candidates.chunks(32) {
        let waiting = std::time::Instant::now();
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let acquired = std::time::Instant::now();
        {
            let mut current = tx.prepare_cached(
                "SELECT fp,revision,active,status,payload FROM cases WHERE key=?",
            )?;
            let mut retire=tx.prepare_cached("DELETE FROM job_cases WHERE case_key=? AND NOT EXISTS(SELECT 1 FROM cases c WHERE c.key=job_cases.case_key AND c.fp=job_cases.fp AND c.revision=job_cases.revision AND c.active=1 AND c.status<>'decided')")?;
            let mut acknowledge = tx.prepare_cached(
                "DELETE FROM replan_cases WHERE case_key=? AND queued_at=? AND build_id IS ?",
            )?;
            for row in batch {
                let actual: Option<(String, i64, bool, String, String)> = current
                    .query_row([&row.key], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                    })
                    .optional()?;
                let matches = match &actual {
                    Some((fp, revision, active, status, body)) => {
                        Some(fp) == row.fp.as_ref()
                            && Some(*revision) == row.revision
                            && Some(*active) == row.active
                            && Some(status) == row.status.as_ref()
                            && Some(body) == row.body.as_ref()
                    }
                    None => row.fp.is_none(),
                };
                if !matches {
                    continue;
                }
                if let Some(fp) = row.fp.as_deref()
                    && row.active == Some(true)
                    && row.status.as_deref() != Some("decided")
                    && row.payload["measurement_required"] != false
                {
                    let fresh = if let Some(build) = row.build_id.as_deref() {
                        let current_build: Option<String> = tx
                            .query_row(
                                "SELECT value FROM meta WHERE key='current-build-id'",
                                [],
                                |r| r.get(0),
                            )
                            .optional()?;
                        (current_build.as_deref() == Some(build)).then_some(build)
                    } else {
                        None
                    };
                    // A receipt changes the discovery case's display state,
                    // not its demand. Keep the durable marker/fallback, while
                    // avoiding full planning for an already complete identity.
                    if fresh.is_some() || !completed_discovery_on(&tx, row)? {
                        plan_on_build(&tx, &row.key, fp, &row.payload, fresh)?;
                    }
                }
                let former = {
                    let mut q =
                        tx.prepare_cached("SELECT job_id FROM job_cases WHERE case_key=?")?;
                    q.query_map([&row.key], |r| r.get::<_, String>(0))?
                        .collect::<std::result::Result<Vec<_>, _>>()?
                };
                retire.execute([&row.key])?;
                for job in former {
                    retire_unneeded_on(&tx, &job)?;
                }
                acknowledge.execute(params![row.key, row.queued, row.build_id])?;
            }
        }
        tx.commit()?;
        tracing::debug!(
            batch_len = batch.len(),
            acquire_ms = acquired.duration_since(waiting).as_secs_f64() * 1000.0,
            write_transaction_ms = acquired.elapsed().as_secs_f64() * 1000.0,
            "observation replan batch committed"
        );
    }
    Ok(())
}

/// Consume persisted changes in batches of at most 32 and indexed deadlines.
/// Idle rounds never expand the work_requests/history catalogue.
pub fn refresh(s: &Store) -> Result<()> {
    let mut c = s.connect()?;
    crate::jobs_v3::expire_due_on(&mut c)?;
    // The latest manifest may still retire queued cases. Do not discover or
    // plan those stale demands only to undo them in a later sync batch.
    // Existing leases, receipts and indexed DNS deadlines remain independent.
    if c.prepare_cached("SELECT EXISTS(SELECT 1 FROM meta WHERE key='build-sync-pending')")?
        .query_row([], |r| r.get::<_, bool>(0))?
    {
        return Ok(());
    }
    let candidates = prepare_replans_on(s, &mut c)?;
    apply_replans_on(&mut c, &candidates)?;
    fill_discovery_on(&mut c)?;
    if c.prepare_cached("SELECT EXISTS(SELECT 1 FROM replan_cases)")?
        .query_row([], |r| r.get::<_, bool>(0))?
    {
        s.wake.notify_one();
    }
    Ok(())
}

pub fn has_current_observation(c: &Connection, payload: &Value) -> Result<bool> {
    let demands = observation_demands(payload)?;
    if demands.is_empty() {
        return Ok(false);
    }
    for demand in demands {
        if prior_observation(
            c,
            &demand.target,
            demand.kind,
            &demand.region,
            &demand.profile,
        )?
        .is_none()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn retire_unneeded_on(c: &Connection, job_id: &str) -> Result<usize> {
    if !crate::jobs_v3::current_case_links_on(c, job_id)?.is_empty() {
        return Ok(0);
    }
    Ok(c.execute("UPDATE jobs AS j SET status='obsolete' WHERE id=? AND status='pending' AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id)",[job_id])?)
}

/// A daily source pass authorizes reconsideration; ordinary receipts and node
/// events never create this proof. The marker survives crashes and is fenced
/// against a newer daily build by the consumer.
pub fn mark_case_from_build(c: &Connection, key: &str, build_id: &str) -> Result<()> {
    c.execute("INSERT INTO replan_cases(case_key,queued_at,build_id) VALUES(?,?,?) ON CONFLICT(case_key) DO UPDATE SET build_id=excluded.build_id WHERE replan_cases.build_id IS NOT excluded.build_id",params![key,now(),build_id])?;
    Ok(())
}

/// Read only the current case's indexed logical observations. No global plan
/// expansion or automatic non-DNS expiry loop is introduced.
pub fn needs_daily_replan_on(c: &Connection, key: &str, build_id: &str) -> Result<bool> {
    if c.query_row(
        "SELECT coalesce(json_type(payload,'$.repeat_on_build'),'')='false' FROM cases WHERE key=?",
        [key],
        |r| r.get::<_, bool>(0),
    )
    .optional()?
    .unwrap_or(false)
    {
        return Ok(false);
    }
    let candidates = {
        let mut q=c.prepare_cached("SELECT j.id,j.target,j.kind,j.region,j.profile FROM job_cases l JOIN cases source ON source.key=l.case_key AND source.fp=l.fp AND source.revision=l.revision JOIN jobs j ON j.id=l.job_id WHERE l.case_key=?1 AND source.active=1 AND source.status<>'decided' AND json_extract(j.profile,'$.logical_job')=1 AND j.round_build_id IS NOT ?2 AND ((j.status='complete' AND j.evidence_until<=?3) OR (j.status='unknown' AND j.execution_count>=3 AND j.next_round_at<=?3)) AND (j.next_round_at IS NULL OR j.next_round_at<=?3)")?;
        q.query_map(params![key, build_id, now()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (job, target, kind, region, body) in candidates {
        if !crate::jobs_v3::current_case_links_on(c, &job)?
            .iter()
            .any(|(k, _)| k == key)
        {
            continue;
        }
        let p: Value = serde_json::from_str(&body)?;
        if prior_observation(c, &target, &kind, &region, &p)?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn insert(s: &Store, key: &str, target: &str) {
        let payload = json!({"kind":"geolocation","family":4,"targets":[target],"ranges":[["1.1.1.0","1.1.1.255"]],"regions":["us"]});
        s.connect().unwrap().execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,'geolocation','x','batch fixture',?,'needs-active',1,?)",params![key,payload.to_string(),now()]).unwrap();
        mark_case(&s.connect().unwrap(), key).unwrap();
    }
    #[test]
    fn stale_target_snapshot_does_not_acknowledge_a_new_change() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        insert(&s, "c", "1.1.1.1");
        let mut connection = s.connect().unwrap();
        let prepared = prepare_replans_on(&s, &mut connection).unwrap();
        s.targets("c", "fp", &["1.1.1.2".into()]).unwrap();
        apply_replans_on(&mut connection, &prepared).unwrap();
        let c = s.connect().unwrap();
        assert!(
            c.query_row::<bool, _, _>(
                "SELECT EXISTS(SELECT 1 FROM replan_cases WHERE case_key='c')",
                [],
                |r| r.get(0)
            )
            .unwrap()
        );
        assert_eq!(
            c.query_row::<String, _, _>(
                "SELECT target FROM jobs WHERE status='pending'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            "1.1.1.2"
        );
        refresh(&s).unwrap();
        assert!(
            !c.query_row::<bool, _, _>(
                "SELECT EXISTS(SELECT 1 FROM replan_cases WHERE case_key='c')",
                [],
                |r| r.get(0)
            )
            .unwrap()
        );
    }
    #[test]
    fn one_batch_failure_rolls_back_all_jobs_and_acknowledgements() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        insert(&s, "a", "1.1.1.1");
        insert(&s, "b", "1.1.1.2");
        let mut c = s.connect().unwrap();
        let prepared = prepare_replans_on(&s, &mut c).unwrap();
        c.execute_batch("CREATE TRIGGER fail_second_marker BEFORE DELETE ON replan_cases WHEN OLD.case_key='b' BEGIN SELECT RAISE(ABORT,'injected acknowledgement failure');END;").unwrap();
        let err = apply_replans_on(&mut c, &prepared).unwrap_err();
        assert!(err.to_string().contains("injected acknowledgement failure"));
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
                .unwrap(),
            0
        );
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM replan_cases", [], |r| r.get(0))
                .unwrap(),
            2
        );
        c.execute_batch("DROP TRIGGER fail_second_marker").unwrap();
        apply_replans_on(&mut c, &prepared).unwrap();
        assert_eq!(
            c.query_row::<i64, _, _>("SELECT count(*) FROM jobs", [], |r| r.get(0))
                .unwrap(),
            2
        );
    }
}
