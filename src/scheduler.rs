use crate::{now, rules::addr_num, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    // Read legacy settings without imposing a global or inherited owned-node cap.
    #[serde(skip_serializing)]
    pub per_node_concurrency: u32,
    #[serde(skip_serializing)]
    pub self_concurrency: u32,
    pub globalping_concurrency: u32,
    pub online_seconds: i64,
    pub retry_base_seconds: i64,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            per_node_concurrency: 10,
            self_concurrency: 64,
            globalping_concurrency: 16,
            online_seconds: 120,
            retry_base_seconds: 60,
        }
    }
}
pub fn configure(root: &Path, store: &Store) -> Result<()> {
    if let Some(value) = store.meta("scheduler-console-override")? {
        let p: Policy = serde_json::from_str(&value)?;
        return save_policy(store, &p, false);
    }
    let path = root.join("config/scheduler.toml");
    let p: Policy = if path.exists() {
        toml::from_str(&std::fs::read_to_string(path)?)?
    } else {
        Policy::default()
    };
    save_policy(store, &p, false)
}
pub fn save_policy(store: &Store, p: &Policy, console: bool) -> Result<()> {
    ensure!(
        (1..=1000).contains(&p.per_node_concurrency)
            && (1..=100000).contains(&p.self_concurrency)
            && (1..=64).contains(&p.globalping_concurrency)
            && (30..=600).contains(&p.online_seconds)
            && (1..=3600).contains(&p.retry_base_seconds),
        "invalid scheduler limits"
    );
    let value = serde_json::to_string(p)?;
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute("INSERT INTO meta VALUES('scheduler-policy',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [&value])?;
    if console {
        tx.execute("INSERT INTO meta VALUES('scheduler-console-override',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [&value])?;
    }
    tx.commit()?;
    store.wake.notify_waiters();
    Ok(())
}
pub fn policy(store: &Store) -> Result<Policy> {
    policy_on(&store.connect()?)
}
pub(crate) fn policy_on(conn: &Connection) -> Result<Policy> {
    Ok(conn
        .query_row(
            "SELECT value FROM meta WHERE key='scheduler-policy'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default())
}
pub fn discover_targets(store: &Store) -> Result<usize> {
    let c = store.connect()?;
    let keys = {
        let mut q=c.prepare("SELECT q.case_key FROM replan_cases q JOIN case_metadata c ON c.key=q.case_key WHERE c.active=1 AND c.status='blocked-target' ORDER BY q.queued_at,q.case_key LIMIT 64")?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut count = 0;
    for key in keys {
        count += discover_case_targets(store, &key)?;
    }
    Ok(count)
}

/// Look up candidates for one changed demand, never scan every blocked range.
pub fn discover_case_targets(store: &Store, key: &str) -> Result<usize> {
    let conn = store.connect()?;
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT fp,payload FROM cases WHERE key=? AND active=1 AND status='blocked-target'",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((fp, payload)) = row else {
        return Ok(0);
    };
    let mut count = 0;
    let p: Value = serde_json::from_str(&payload)?;
    let family = p["family"].as_u64().unwrap_or(0) as u8;
    let mut ranges = Vec::new();
    for range in p["ranges"].as_array().into_iter().flatten() {
        let (f, s) = addr_num(range[0].as_str().unwrap_or("").parse()?);
        let (g, e) = addr_num(range[1].as_str().unwrap_or("").parse()?);
        ensure!(f == family && g == family && s <= e, "invalid target range");
        ranges.push((s, e));
    }
    let ranges = crate::rules::union(ranges);
    // Only the new continuous endpoint units opt in. Legacy grouped cases may
    // contain separate ranges and keep their existing discovery-only behavior.
    let bounded = p["kind"] == "endpoint-reachability"
        && p["sample_plan"]["strategy"] == "bgp-bounded-v1"
        && ranges.len() == 1;
    let mut known = Vec::new();
    for (s, e) in &ranges {
        let windows = if bounded {
            if let Some(size) = e.checked_sub(*s).and_then(|v| v.checked_add(1)) {
                let slots = size.min(3);
                let cut = |i| *s + (size / slots) * i + (size % slots) * i / slots;
                (0..slots)
                    .map(|i| (cut(i), cut(i + 1) - 1))
                    .collect::<Vec<_>>()
            } else {
                vec![(*s, *e)]
            }
        } else {
            vec![(*s, *e)]
        };
        for (start, end) in windows {
            let mut q=conn.prepare_cached("SELECT ip,kind,source,observed,valid_until FROM (SELECT ip,'endpoint-response' kind,result_id source,last_seen observed,last_seen+604800 valid_until FROM responsive_targets WHERE family=?1 AND address>=?2 AND address<=?3 AND last_seen>?4-604800 AND last_seen<=?4+60 UNION ALL SELECT ip,kind,source,observed,valid_until FROM target_observations WHERE family=?1 AND address>=?2 AND address<=?3 AND valid_until>?4 AND observed<=?4+60) ORDER BY kind='endpoint-response' DESC,observed DESC,ip LIMIT 32")?;
            let rows = q.query_map(params![family,format!("{start:032x}"),format!("{end:032x}"),now()],|r|Ok((r.get::<_,String>(0)?,json!({"kind":r.get::<_,String>(1)?,"source":r.get::<_,String>(2)?,"observed":r.get::<_,i64>(3)?,"valid_until":r.get::<_,i64>(4)?}))))?.collect::<std::result::Result<Vec<_>,_>>()?;
            for (ip, receipt) in rows {
                if let Ok(ip) = ip.parse()
                    && crate::measure::public_ip(ip)
                    && !known.iter().any(|(old, _)| *old == ip)
                {
                    known.push((ip, receipt));
                }
                if !bounded && known.len() >= 3 {
                    break;
                }
            }
        }
        if !bounded && known.len() >= 3 {
            break;
        }
    }
    let selected = if bounded {
        let retained = p["targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|value| {
                let text = value.as_str()?;
                Some((text.parse().ok()?, p["target_evidence"][text].clone()))
            })
            .collect::<Vec<_>>();
        crate::sampling::select_targets(
            family,
            &ranges,
            &retained,
            &known,
            3,
            p["sample_plan"]["allow_ipv4_candidates"] == true,
        )
    } else {
        known
    };
    let mut targets = vec![];
    let mut evidence = serde_json::Map::new();
    for (ip, receipt) in selected {
        let ip = ip.to_string();
        if !evidence.contains_key(&ip) {
            targets.push(ip.clone());
            evidence.insert(ip, receipt);
        }
        if targets.len() == 3 {
            break;
        }
    }
    targets.sort();
    if !targets.is_empty() {
        match store.targets_with_evidence(key, &fp, &targets, &json!(evidence)) {
            Ok(n) => count += n,
            Err(error) => {
                let still_waiting:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM cases WHERE key=? AND fp=? AND active=1 AND status='blocked-target')",params![key,fp],|r|r.get(0))?;
                if still_waiting {
                    return Err(error);
                }
            }
        }
    }
    Ok(count)
}
// Aggregate the small executable queue once; never correlate six job lookups
// against every wide case payload. Fetch payloads only for the requested page.
const STATE: &str = "CASE WHEN c.active=0 THEN 'obsolete' WHEN c.status='decided' THEN 'decided' WHEN coalesce(s.running,0)>0 THEN 'running' WHEN coalesce(s.ready,0)>0 THEN CASE WHEN s.completed>0 THEN 'partial' ELSE 'queued' END WHEN coalesce(s.future,0)>0 THEN CASE WHEN s.completed>0 THEN 'partial' ELSE 'scheduled' END WHEN coalesce(s.pending,0)>0 THEN CASE WHEN s.completed>0 THEN 'partial' WHEN s.waiting_node>0 THEN 'waiting-node' ELSE 'waiting-capability' END WHEN coalesce(s.failed,0)>0 THEN CASE WHEN s.completed>0 THEN 'partial' ELSE 'failed' END WHEN coalesce(s.completed,0)>0 THEN 'complete' WHEN c.kind='domain-policy' OR c.status='needs-review' THEN 'needs-review' ELSE 'awaiting-target' END";
pub fn tasks(store: &Store, offset: usize, limit: usize, filter: &str) -> Result<Value> {
    query_tasks(store, offset, limit, filter, TaskView::Full)
}
pub fn task_items(store: &Store, offset: usize, limit: usize, filter: &str) -> Result<Value> {
    query_tasks(store, offset, limit, filter, TaskView::Items)
}
pub fn task_summary(store: &Store, filter: &str) -> Result<Value> {
    query_tasks(store, 0, 1, filter, TaskView::Summary)
}
#[derive(PartialEq)]
enum TaskView {
    Full,
    Items,
    Summary,
}
fn query_tasks(
    store: &Store,
    offset: usize,
    limit: usize,
    filter: &str,
    view: TaskView,
) -> Result<Value> {
    let mut conn = store.connect()?;
    let tx = conn.transaction()?;
    let eligible = crate::work::eligibility_sql("j", "n");
    let available = crate::jobs_v3::demand_available_sql("j");
    let ready = format!(
        "{available} AND EXISTS(SELECT 1 FROM nodes n WHERE {eligible} AND ((n.id NOT LIKE 'globalping:%' AND n.connected=1 AND n.last_seen>CAST(strftime('%s','now') AS INTEGER)-120) OR (n.id LIKE 'globalping:%' AND EXISTS(SELECT 1 FROM json_each(coalesce((SELECT value FROM meta WHERE key='gp-coverage'),'[]')) g WHERE 'globalping:'||json_extract(g.value,'$.account')||':'||json_extract(g.value,'$.region')=n.id))))"
    );
    tx.execute_batch("CREATE TEMP TABLE queue_job_states(case_key TEXT NOT NULL,fp TEXT NOT NULL,revision INTEGER NOT NULL,running INTEGER,ready INTEGER,future INTEGER,pending INTEGER,waiting_node INTEGER,failed INTEGER,completed INTEGER,total INTEGER,PRIMARY KEY(case_key,fp,revision)) WITHOUT ROWID;")?;
    let page_only = view == TaskView::Items && filter.is_empty();
    let (prefix, job_from, scope) = if page_only {
        (
            "latest_plans AS MATERIALIZED (SELECT p.case_key,p.fp FROM measurement_plans p INDEXED BY measurement_plan_recent CROSS JOIN case_metadata c ON c.key=p.case_key AND c.fp=p.fp ORDER BY p.created DESC,p.case_key LIMIT ?1 OFFSET ?2),",
            "latest_plans p CROSS JOIN job_cases l INDEXED BY job_cases_case JOIN jobs j ON j.id=l.job_id JOIN case_metadata current ON current.key=l.case_key AND current.fp=l.fp AND current.revision=l.revision",
            "l.case_key=p.case_key AND l.fp=p.fp AND ",
        )
    } else {
        (
            "",
            "job_cases l JOIN jobs j ON j.id=l.job_id JOIN case_metadata current ON current.key=l.case_key AND current.fp=l.fp AND current.revision=l.revision",
            "",
        )
    };
    tx.execute_batch("CREATE TEMP TABLE queue_pending(case_key TEXT NOT NULL,fp TEXT NOT NULL,revision INTEGER NOT NULL,ready INTEGER,future INTEGER,pending INTEGER,waiting_node INTEGER,PRIMARY KEY(case_key,fp,revision)) WITHOUT ROWID;")?;
    let aggregate = format!(
        "WITH {prefix} job_flags AS MATERIALIZED (SELECT l.case_key,l.fp,l.revision,j.profile,j.not_before,CASE WHEN j.not_before<=CAST(strftime('%s','now') AS INTEGER) AND {ready} THEN 1 ELSE 0 END ready,CASE WHEN json_extract(j.profile,'$.observer_id') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM nodes n WHERE n.id=json_extract(j.profile,'$.observer_id') AND n.connected=1 AND n.disabled=0 AND n.last_seen>CAST(strftime('%s','now') AS INTEGER)-120) THEN 1 ELSE 0 END waiting_node FROM {job_from} WHERE {scope}j.status='pending' AND (json_extract(j.profile,'$.scheduler')=2 OR EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id))) INSERT INTO queue_pending SELECT case_key,fp,revision,sum(ready),sum(not_before>CAST(strftime('%s','now') AS INTEGER)),count(*),sum(waiting_node) FROM job_flags GROUP BY case_key,fp,revision"
    );
    if page_only {
        tx.execute(
            &aggregate,
            params![limit.clamp(1, 100) as i64, offset as i64],
        )?;
    } else {
        tx.execute(&aggregate, [])?;
    }
    let totals_from = if page_only {
        "task_job_totals t JOIN latest_plans p ON p.case_key=t.case_key AND p.fp=t.fp"
    } else if view == TaskView::Summary {
        "task_job_totals t INDEXED BY task_job_pending"
    } else {
        "task_job_totals t"
    };
    let legacy_from = if page_only {
        "latest_plans p CROSS JOIN job_cases l INDEXED BY job_cases_case JOIN jobs j ON j.id=l.job_id JOIN gp_remote g ON g.job_id=j.id AND p.case_key=l.case_key AND p.fp=l.fp"
    } else {
        "gp_remote g JOIN jobs j ON j.id=g.job_id JOIN job_cases l ON l.job_id=j.id"
    };
    let totals_condition = if view == TaskView::Summary {
        "t.total>0 AND t.pending>0"
    } else {
        "t.total>0"
    };
    let totals = format!(
        "WITH {prefix} raw_totals AS (SELECT t.case_key,t.fp,t.revision,t.total,t.running,t.failed,t.completed FROM {totals_from} WHERE {totals_condition} UNION ALL SELECT l.case_key,l.fp,l.revision,count(*),sum(j.status='leased'),sum(j.status='unknown'),sum(j.status='complete') FROM {legacy_from} WHERE j.status<>'obsolete' AND coalesce(json_extract(j.profile,'$.scheduler'),0)<>2 AND coalesce(json_extract(j.profile,'$.legacy_alias'),0)<>1 GROUP BY l.case_key,l.fp,l.revision),totals AS (SELECT case_key,fp,revision,sum(total) total,sum(running) running,sum(failed) failed,sum(completed) completed FROM raw_totals GROUP BY case_key,fp,revision) INSERT INTO queue_job_states SELECT t.case_key,t.fp,t.revision,t.running,coalesce(p.ready,0),coalesce(p.future,0),coalesce(p.pending,0),coalesce(p.waiting_node,0),t.failed,t.completed,t.total FROM totals t LEFT JOIN queue_pending p ON p.case_key=t.case_key AND p.fp=t.fp AND p.revision=t.revision"
    );
    if page_only {
        tx.execute(&totals, params![limit.clamp(1, 100) as i64, offset as i64])?;
    } else {
        tx.execute(&totals, [])?;
    }
    let base = format!(
        "WITH task_states AS (SELECT c.key,c.fp,c.kind,c.subject,c.reason,p.source,p.created,coalesce(s.completed,0) completed,coalesce(s.total,0) total_jobs,CASE WHEN coalesce(s.pending,0)>0 AND coalesce(s.ready,0)=0 AND coalesce(s.future,0)=0 THEN CASE WHEN EXISTS(SELECT 1 FROM job_cases waiting_link JOIN jobs waiting ON waiting.id=waiting_link.job_id JOIN jobs held ON held.demand_key=waiting.demand_key JOIN gp_remote g ON g.job_id=held.id WHERE waiting_link.case_key=c.key AND waiting_link.fp=c.fp AND waiting.status='pending') THEN '等待既有远端提交确认' WHEN s.waiting_node>0 THEN '等待指定节点上线' ELSE '等待匹配的地址族、地区或执行能力' END ELSE '' END blocking_reason,CASE WHEN s.case_key IS NULL THEN d.state ELSE {STATE} END state FROM measurement_plans p JOIN case_metadata c ON c.key=p.case_key AND c.fp=p.fp JOIN task_defaults d ON d.case_key=c.key AND d.fp=c.fp AND d.revision=c.revision LEFT JOIN queue_job_states s ON s.case_key=c.key AND s.fp=c.fp AND s.revision=c.revision) "
    );
    let (filter, condition) = if let Some(value) = filter.strip_prefix("state:") {
        (value, " WHERE state=?1")
    } else if let Some(value) = filter.strip_prefix("source:") {
        (value, " WHERE source=?1")
    } else {
        (
            filter,
            " WHERE (?1='' OR state=?1 OR source=?1 OR subject LIKE '%'||?1||'%')",
        )
    };
    // Read the newest plans in index order so LIMIT applies before fetching case payloads.
    let page_index = if condition.starts_with(" WHERE source=") {
        "measurement_plan_source_recent"
    } else {
        "measurement_plan_recent"
    };
    let page_base = base.replace(
        "FROM measurement_plans p JOIN",
        &format!("FROM measurement_plans p INDEXED BY {page_index} CROSS JOIN"),
    );
    let mut output = json!({});
    if view != TaskView::Summary {
        let mut q=tx.prepare(&format!("{page_base} SELECT p.key,p.fp,p.kind,p.subject,c.payload,p.reason,p.source,p.created,p.state,p.completed,p.total_jobs,p.blocking_reason FROM (SELECT * FROM task_states{condition} ORDER BY created DESC,key LIMIT ? OFFSET ?) p JOIN cases c ON c.key=p.key AND c.fp=p.fp"))?;
        let items=q.query_map(params![filter,limit.clamp(1,100) as i64,offset as i64],|r|Ok(json!({"key":r.get::<_,String>(0)?,"fingerprint":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"subject":r.get::<_,String>(3)?,"payload":serde_json::from_str::<Value>(&r.get::<_,String>(4)?).unwrap_or(Value::Null),"reason":r.get::<_,String>(5)?,"source":r.get::<_,String>(6)?,"created":r.get::<_,i64>(7)?,"state":r.get::<_,String>(8)?,"completed":r.get::<_,i64>(9)?,"total_jobs":r.get::<_,i64>(10)?,"blocking_reason":r.get::<_,String>(11)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        output["items"] = json!(items);
    }
    if view == TaskView::Items {
        return Ok(output);
    }
    let mut counts = std::collections::BTreeMap::<String, i64>::new();
    let mut q = tx.prepare("SELECT state,sum(n) FROM task_default_counts GROUP BY state")?;
    for r in q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
        let (state, n) = r?;
        counts.insert(state, n);
    }
    let mut q=tx.prepare(&format!("SELECT d.state,{STATE},count(*) FROM queue_job_states s CROSS JOIN case_metadata c ON c.key=s.case_key AND c.fp=s.fp AND c.revision=s.revision CROSS JOIN task_defaults d ON d.case_key=c.key AND d.fp=c.fp AND d.revision=c.revision GROUP BY 1,2"))?;
    for r in q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)?,
        ))
    })? {
        let (default, actual, n) = r?;
        *counts.entry(default).or_default() -= n;
        *counts.entry(actual).or_default() += n;
    }
    let total: i64 = if condition.starts_with(" WHERE state=") {
        *counts.get(filter).unwrap_or(&0)
    } else if condition.starts_with(" WHERE source=") {
        tx.query_row(
            "SELECT coalesce(sum(n),0) FROM task_default_counts WHERE source=?",
            [filter],
            |r| r.get(0),
        )?
    } else if filter.is_empty() {
        counts.values().sum()
    } else {
        tx.query_row(
            &format!("{base} SELECT count(*) FROM task_states{condition}"),
            params![filter],
            |r| r.get(0),
        )?
    };
    let states: serde_json::Map<String, Value> = counts
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(state, n)| (state, json!(n)))
        .collect();
    output["total"] = json!(total);
    output["states"] = json!(states);
    if view == TaskView::Full {
        output["policy"] = json!(policy(store)?);
        output["discovery"] = crate::discovery::status(store)?;
    }
    Ok(output)
}
pub fn task_detail(store: &Store, key: &str) -> Result<Value> {
    let conn = store.connect()?;
    let mut q=conn.prepare("SELECT j.id,j.kind,j.target,j.region,j.status,j.not_before,j.attempts,j.lease_node,j.lease_until FROM job_cases l JOIN jobs j ON j.id=l.job_id JOIN cases current ON current.key=l.case_key AND current.fp=l.fp AND current.revision=l.revision WHERE l.case_key=? AND j.status<>'obsolete' ORDER BY j.created,j.id")?;
    let jobs=q.query_map([key],|r|{let node:Option<String>=r.get(7)?;Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"target":r.get::<_,String>(2)?,"region":r.get::<_,String>(3)?,"status":r.get::<_,String>(4)?,"not_before":r.get::<_,i64>(5)?,"attempts":r.get::<_,i64>(6)?,"executor":if node.as_deref().is_some_and(|n|n.starts_with("globalping:")){"globalping"}else if node.is_some(){"self"}else{"unassigned"},"node":node,"lease_until":r.get::<_,Option<i64>>(8)?}))})?.collect::<std::result::Result<Vec<_>,_>>()?;
    let payload: Option<String> = conn
        .query_row("SELECT payload FROM cases WHERE key=?", [key], |r| r.get(0))
        .optional()?;
    Ok(
        json!({"jobs":jobs,"results":store.results(key)?,"evidence_summary":evidence_summary(store,key)?,"payload":payload.and_then(|p|serde_json::from_str::<Value>(&p).ok())}),
    )
}

// Actual observer networks are evidence metadata, not lease eligibility or country votes.
fn evidence_summary(store: &Store, key: &str) -> Result<Value> {
    use std::collections::BTreeSet;
    let conn = store.connect()?;
    let mut q=conn.prepare("SELECT DISTINCT r.node,r.observed,r.evidence,j.target,j.kind,n.asn,n.region FROM job_cases l JOIN jobs j ON j.id=l.job_id CROSS JOIN results r INDEXED BY result_job JOIN cases current ON current.key=l.case_key AND current.fp=l.fp AND current.revision=l.revision LEFT JOIN nodes n ON n.id=r.node WHERE r.job_id=j.id AND l.case_key=? AND r.outcome='ok'")?;
    let mut observations = BTreeSet::new();
    let mut asns = BTreeSet::new();
    let mut locations = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    for row in q.query_map([key], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, Option<u32>>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    })? {
        let (node, at, body, target, kind, asn, region) = row?;
        let e: Value = serde_json::from_str(&body)?;
        if node.starts_with("globalping:") {
            for (i, r) in e["measurement"]["results"]
                .as_array()
                .into_iter()
                .flatten()
                .enumerate()
            {
                let identity = format!("{}:{i}", e["measurement_id"]);
                observations.insert(identity.clone());
                if let Some(asn) = r["probe"]["asn"].as_u64().filter(|n| *n > 0) {
                    asns.insert(asn);
                }
                if let Some(country) = r["probe"]["country"].as_str() {
                    locations.insert(country.to_string());
                }
                if crate::discovery::receipt_observations(
                    &identity,
                    at,
                    &json!({"measurement":{"results":[r]},"measurement_id":e["measurement_id"]}),
                )
                .iter()
                .any(|o| o.kind == "endpoint-response")
                {
                    endpoints.insert(identity);
                }
            }
        } else {
            let identity = format!("{node}:{kind}:{target}:{at}");
            observations.insert(identity.clone());
            if let Some(asn) = asn.filter(|n| *n > 0) {
                asns.insert(asn as u64);
            }
            if let Some(region) = region {
                locations.insert(region);
            }
            if e["reached"] == true
                || e["tls"]
                    .as_array()
                    .is_some_and(|v| v.iter().any(|t| t["certificate_valid"] == true))
            {
                endpoints.insert(identity);
            }
        }
    }
    Ok(
        json!({"observations":observations.len(),"distinct_asns":asns.len(),"asns":asns,"observer_locations":locations,"endpoint_responses":endpoints.len()}),
    )
}
