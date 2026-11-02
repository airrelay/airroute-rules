//! Opt-in same-host fixture measurements. These are not HTTP or production SLOs.
use airroute_rules::{
    now, scheduler,
    store::{Node, Store},
};
use serde_json::json;
use std::time::Instant;

fn distribution(mut milliseconds: Vec<f64>) -> serde_json::Value {
    milliseconds.sort_by(f64::total_cmp);
    let quantile = |p: f64| {
        milliseconds[((milliseconds.len() as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(milliseconds.len() - 1)]
    };
    json!({"samples":milliseconds.len(),"p50_ms":quantile(0.5),"p95_ms":quantile(0.95),"max_ms":milliseconds.last()})
}

// New controller: immutable activation is followed by independent bounded sync.
// The frozen historical test copy replaces only this helper with `false`, since
// that version already performed business-state synchronization inside build.
fn pipeline_sync_once(store: &Store) -> bool {
    airroute_rules::build_delta::sync_current(store, 128).unwrap()
}
fn pipeline_begin_execution(
    store: &Store,
    node: &Node,
    lease: &airroute_rules::store::Lease,
) -> bool {
    store
        .begin_execution(&node.id, "pipeline-session", lease)
        .unwrap()
}
fn pipeline_execution_counts(store: &Store) -> (Option<i64>, Option<i64>, i64) {
    let c = store.connect().unwrap();
    let count = |sql| c.query_row::<i64, _, _>(sql, [], |r| r.get(0)).unwrap();
    (
        Some(count("SELECT coalesce(sum(execution_count),0) FROM jobs")),
        Some(count(
            "SELECT count(*) FROM lease_history WHERE started_at IS NOT NULL",
        )),
        count("SELECT count(*) FROM results WHERE accepted=1 AND qualified=1"),
    )
}
fn pipeline_yield_ms() -> u64 {
    std::env::var("AIRROUTE_PIPELINE_YIELD_MS")
        .ok()
        .map(|s| s.parse().unwrap())
        .unwrap_or(0)
}
fn pipeline_pending(store: &Store) -> bool {
    store.meta("build-sync-pending").unwrap().is_some()
        || store
            .connect()
            .unwrap()
            .query_row::<bool, _, _>("SELECT EXISTS(SELECT 1 FROM replan_cases)", [], |r| {
                r.get(0)
            })
            .unwrap()
}
fn pipeline_drain(store: &Store) -> usize {
    let mut rounds = 0;
    let yield_ms = pipeline_yield_ms();
    while pipeline_pending(store) {
        pipeline_sync_once(store);
        airroute_rules::work::refresh(store).unwrap();
        rounds += 1;
        assert!(rounds < 100000, "durable pipeline work must converge");
        if yield_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(yield_ms));
        }
    }
    rounds
}

#[test]
#[ignore = "manual same-input full offline build + business sync + planning; see AIRROUTE_PIPELINE_* inputs"]
fn full_pipeline() {
    use airroute_rules::{build, hash, progress, store::ProbeResult};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            "airroute_rules=info,airroute_rules::build_delta=debug,airroute_rules::work=debug",
        )
        .with_writer(std::io::stderr)
        .try_init();
    let root = std::path::PathBuf::from(
        std::env::var("AIRROUTE_PIPELINE_ROOT").expect("frozen root required"),
    );
    let data = std::path::PathBuf::from(
        std::env::var("AIRROUTE_PIPELINE_DATA").expect("isolated SQLite backup required"),
    );
    assert!(
        data.join("control.sqlite3").is_file(),
        "seed with SQLite backup before execution"
    );
    assert!(root.join("config/discovery.toml").is_file());
    let discovery = std::fs::read_to_string(root.join("config/discovery.toml")).unwrap();
    assert!(
        discovery.contains("enabled = false"),
        "external discovery must be disabled"
    );
    assert!(
        !std::fs::read_to_string(root.join("config/globalping.toml"))
            .unwrap()
            .contains("enabled = true")
    );
    assert!(
        !std::fs::read_to_string(root.join("config/github.toml"))
            .unwrap()
            .contains("enabled = true")
    );
    let scenario = std::env::var("AIRROUTE_PIPELINE_SCENARIO").unwrap_or_else(|_| "zero".into());
    let setup_started = Instant::now();
    let store = Store::open(&data).unwrap();
    let startup_migration_seconds = setup_started.elapsed().as_secs_f64();
    airroute_rules::scheduler::configure(&root, &store).unwrap();
    airroute_rules::publish::initialize(&root, &store).unwrap();
    airroute_rules::receipt::configure_country_regions(&store, &root).unwrap();
    let startup_with_settings_seconds = setup_started.elapsed().as_secs_f64();
    let node = Node {
        id: "pipeline-observer".into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["traceroute".into()],
    };
    store
        .register_node(&node, &hash("public-isolated-pipeline-fixture-token"))
        .unwrap();
    store
        .update_node_settings(&node.id, "pipeline fixture", Some(10))
        .unwrap();
    let mut connection = store.connect().unwrap();
    if !connection
        .query_row::<bool, _, _>(
            "SELECT EXISTS(SELECT 1 FROM cases WHERE key='pipeline-manual-00000')",
            [],
            |r| r.get(0),
        )
        .unwrap()
    {
        let tx = connection.transaction().unwrap();
        for i in 0..5000 {
            let key = format!("pipeline-manual-{i:05}");
            let target = format!("11.0.{}.{}", i / 256, i % 256);
            let fp = hash(format!("pipeline-manual:{target}"));
            let payload = json!({"kind":"manual-ip","manual":true,"family":4,"ranges":[[target,target]],"targets":[target],"regions":["us"],"measurement_required":true,"epoch":"pipeline-fixed"});
            tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,?,1,'manual-ip',?,'isolated direct API traffic fixture',?,'needs-active',1,0)",rusqlite::params![key,fp,target,payload.to_string()]).unwrap();
            airroute_rules::work::plan_on(&tx, &key, &fp, &payload).unwrap();
        }
        tx.commit().unwrap();
    }
    connection.execute("UPDATE nodes SET connected=1,last_seen=?,session_id='pipeline-session',ipv4_supported=1,ipv6_supported=0,worker_capacity=1000 WHERE id=?",rusqlite::params![now(),node.id]).unwrap();
    // A first warm/migration run must build before retiring old demands. Do
    // not hide initial legacy processing in setup or do work the new manifest
    // will correctly retire. Steady scenarios clone an already drained warm DB.
    let setup_drain_rounds = if scenario == "warm" {
        0
    } else {
        pipeline_drain(&store)
    };
    assert_eq!(
        connection
            .query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
            .unwrap(),
        0,
        "each run must begin with the same empty observation input"
    );
    let mut synthetic_full_rows = 0;
    if scenario == "full" {
        // Deliberately stale *business projection*, not fake upstream countries.
        // Complete rule generation still runs from the fixed valid inputs. The
        // new policy may legitimately retire unmeasurable legacy cases instead
        // of recreating them; report that work-volume difference explicitly.
        let tx = connection.transaction().unwrap();
        synthetic_full_rows=tx.execute("UPDATE cases SET fp='pipeline-stale:'||fp,revision=revision+1,active=1 WHERE kind NOT IN ('domain-observation','manual-ip','target-discovery')",[]).unwrap();
        tx.execute("UPDATE case_ranges SET fp=(SELECT fp FROM cases c WHERE c.key=case_ranges.case_key) WHERE case_key IN (SELECT key FROM cases WHERE kind NOT IN ('domain-observation','manual-ip','target-discovery'))",[]).unwrap();
        tx.execute("UPDATE measurement_plans SET fp=(SELECT fp FROM cases c WHERE c.key=measurement_plans.case_key) WHERE case_key IN (SELECT key FROM cases WHERE kind NOT IN ('domain-observation','manual-ip','target-discovery'))",[]).unwrap();
        tx.execute("UPDATE build_case_sources SET source_hash=? WHERE case_key IN (SELECT key FROM cases WHERE kind NOT IN ('domain-observation','manual-ip','target-discovery'))",["0".repeat(64)]).unwrap();
        tx.commit().unwrap();
    }
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let initial_observations = connection
        .query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
        .unwrap();
    connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    drop(connection);
    if let Ok(marker) = std::env::var("AIRROUTE_PIPELINE_START_MARKER") {
        let marker = std::path::PathBuf::from(marker);
        assert!(!marker.exists(), "start marker must be unique to this run");
        std::fs::write(&marker, "ready\n").unwrap();
        let go = std::path::PathBuf::from(format!("{}.go", marker.display()));
        let wait = Instant::now();
        while !go.exists() {
            assert!(
                wait.elapsed().as_secs() < 120,
                "monitor did not release prepared fixture"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    let done = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(AtomicUsize::new(1));
    let traffic = if scenario != "warm" {
        let s = store.clone();
        let n = node.clone();
        let stop = done.clone();
        let current_phase = phase.clone();
        Some(std::thread::spawn(move || {
            let mut claims = Vec::<(usize, f64)>::new();
            let mut receipts = Vec::<(usize, f64)>::new();
            let mut reservations = Vec::<(usize, f64)>::new();
            let mut admissions = Vec::<(usize, f64)>::new();
            let mut empty = 0;
            // Both builds have frozen their observations before entering phase3.
            while !stop.load(Ordering::SeqCst) && current_phase.load(Ordering::SeqCst) == 1 {
                let id = s
                    .connect()
                    .unwrap()
                    .query_row::<String, _, _>(
                        "SELECT id FROM builds WHERE status='running' ORDER BY rowid DESC LIMIT 1",
                        [],
                        |r| r.get(0),
                    )
                    .ok();
                if id
                    .as_deref()
                    .and_then(|id| progress::snapshot(&s, id))
                    .is_some_and(|p| p.stage >= 3)
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let mut heartbeat = Instant::now();
            while !stop.load(Ordering::SeqCst) {
                if heartbeat.elapsed().as_secs() >= 5 {
                    s.connect()
                        .unwrap()
                        .execute(
                            "UPDATE nodes SET last_seen=? WHERE id=?",
                            rusqlite::params![now(), n.id],
                        )
                        .unwrap();
                    heartbeat = Instant::now();
                }
                let p = current_phase.load(Ordering::SeqCst);
                let started = Instant::now();
                let lease = s.lease_session(&n, "pipeline-session").unwrap();
                let elapsed = started.elapsed().as_secs_f64() * 1000.;
                if let Some(lease) = lease {
                    reservations.push((p, elapsed));
                    let admission_started = Instant::now();
                    assert!(
                        pipeline_begin_execution(&s, &n, &lease),
                        "qualified manual work must pass actual dispatch admission"
                    );
                    admissions.push((p, admission_started.elapsed().as_secs_f64() * 1000.));
                    claims.push((p, started.elapsed().as_secs_f64() * 1000.));
                    let result = ProbeResult {
                        id: uuid::Uuid::new_v4().to_string(),
                        job_id: lease.id.clone(),
                        fingerprint: lease.fingerprint.clone(),
                        lease_token: lease.token.clone(),
                        observed_at: now(),
                        outcome: "ok".into(),
                        evidence: json!({"kind":"traceroute","target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target}]}),
                    };
                    let started = Instant::now();
                    let ack = s.submit(&n.id, &result).unwrap();
                    receipts.push((
                        current_phase.load(Ordering::SeqCst),
                        started.elapsed().as_secs_f64() * 1000.,
                    ));
                    assert_eq!(
                        ack["accepted"], true,
                        "stress must exercise accepted receipts, not rejected no-ops"
                    );
                    assert_eq!(
                        ack["qualified"], true,
                        "trace fixture must meet actual observer/method/target qualification"
                    );
                } else {
                    empty += 1;
                }
                std::thread::sleep(std::time::Duration::from_millis(40));
            }
            (claims, receipts, empty, reservations, admissions)
        }))
    } else {
        None
    };
    let started = Instant::now();
    let output = build::run_with_store(&root, &data, true, &store).unwrap();
    if let Some(observations) = output.get("observations") {
        assert_eq!(
            observations["qualified_observations"], 0,
            "traffic must start after the fixed empty observation snapshot"
        );
    }
    let build_seconds = started.elapsed().as_secs_f64();
    phase.store(2, Ordering::SeqCst);
    let sync_rounds = pipeline_drain(&store);
    let first_drain_seconds = started.elapsed().as_secs_f64() - build_seconds;
    done.store(true, Ordering::SeqCst);
    let observations = traffic.map(|worker| worker.join().unwrap());
    let tail_rounds = pipeline_drain(&store);
    let elapsed_seconds = started.elapsed().as_secs_f64();
    let summarize = |items: Vec<(usize, f64)>| {
        let per_phase = |p| {
            let v = items
                .iter()
                .filter(|(phase, _)| *phase == p)
                .map(|(_, ms)| *ms)
                .collect::<Vec<_>>();
            if v.is_empty() {
                serde_json::Value::Null
            } else {
                distribution(v)
            }
        };
        let all = if items.is_empty() {
            serde_json::Value::Null
        } else {
            distribution(items.iter().map(|(_, ms)| *ms).collect())
        };
        json!({"all":all,"during_build":per_phase(1),"during_background_sync":per_phase(2)})
    };
    let (claims, receipts, empty, reservations, admissions) = observations.unwrap_or_default();
    if scenario != "warm" {
        assert!(
            claims.len() >= 10 && receipts.len() >= 10,
            "eligible backlog must actually exercise concurrent traffic"
        );
    }
    let final_db = store.connect().unwrap();
    let scalar = |sql| {
        final_db
            .query_row::<i64, _, _>(sql, [], |r| r.get(0))
            .unwrap()
    };
    let (actual_execution_count, started_attempts, qualified_results) =
        pipeline_execution_counts(&store);
    if let Some(count) = actual_execution_count {
        assert_eq!(
            count,
            receipts.len() as i64,
            "each simulated execution must consume exactly one real opportunity"
        );
    }
    if let Some(count) = started_attempts {
        assert_eq!(
            count,
            receipts.len() as i64,
            "receipts must follow actual send admission"
        );
    }
    assert_eq!(qualified_results, receipts.len() as i64);
    let report = json!({"scenario":scenario,"pipeline_yield_ms":pipeline_yield_ms(),"setup_seconds":setup_seconds,"startup_migration_seconds":startup_migration_seconds,"startup_with_settings_seconds":startup_with_settings_seconds,"setup_drain_rounds":setup_drain_rounds,"initial_observations":initial_observations,"synthetic_full_projection_rows":synthetic_full_rows,"build_seconds":build_seconds,"background_sync_and_planning_seconds":first_drain_seconds,"complete_pipeline_seconds":elapsed_seconds,"sync_rounds":sync_rounds,"tail_rounds":tail_rounds,"release":output["release"],"rules":output["rules"],"collections":output["targets"],"build_summary":output,"last_build_sync":store.meta("last-build-sync").unwrap().and_then(|s|serde_json::from_str::<serde_json::Value>(&s).ok()),"claim_scope":"lease_session plus actual begin_execution; reservation and send admission also reported separately; historical ce11 lease had no separate admission API","claim_ms":summarize(claims),"reservation_ms":summarize(reservations),"send_admission_ms":summarize(admissions),"receipt_ms":summarize(receipts),"empty_claims":empty,"final_counts":{"cases":scalar("SELECT count(*) FROM cases"),"active_build_owned_cases":scalar("SELECT count(*) FROM cases WHERE active=1 AND kind NOT IN ('domain-observation','manual-ip','target-discovery')"),"jobs":scalar("SELECT count(*) FROM jobs"),"results":scalar("SELECT count(*) FROM results"),"actual_execution_count":actual_execution_count,"started_attempts":started_attempts,"qualified_results":qualified_results,"replan_pending":scalar("SELECT count(*) FROM replan_cases")},"scope":"one-process real offline build + activation + complete business sync + queue planning; concurrent direct Store API with synthetic traceroute receipts, never network execution; setup and synthetic-stale projection preparation are reported separately","limitations":["new policy may emit more routing coverage and fewer useful measurement needs; work volumes are reported rather than called per-job speedup","direct Store API latency excludes QUIC/HTTP transport","remaining pending observation jobs are legitimate backlog; completion means durable manifest/replan markers are drained"]});
    if let Ok(path) = std::env::var("AIRROUTE_PERFORMANCE_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}

/// Real post-build data, sampled separately from build/synchronization time.
#[test]
#[ignore = "manual direct query measurements on an already drained isolated pipeline database"]
fn pipeline_queries() {
    let data = std::path::PathBuf::from(
        std::env::var("AIRROUTE_PIPELINE_DATA").expect("isolated backup required"),
    );
    assert!(data.join("control.sqlite3").is_file());
    let store = Store::open(&data).unwrap();
    let mut items = Vec::new();
    let mut summaries = Vec::new();
    let mut cases = Vec::new();
    scheduler::task_items(&store, 0, 30, "").unwrap();
    scheduler::task_summary(&store, "").unwrap();
    store.list("cases", 0, 30, "").unwrap();
    for _ in 0..25 {
        let at = Instant::now();
        scheduler::task_items(&store, 0, 30, "").unwrap();
        items.push(at.elapsed().as_secs_f64() * 1000.);
        let at = Instant::now();
        scheduler::task_summary(&store, "").unwrap();
        summaries.push(at.elapsed().as_secs_f64() * 1000.);
        let at = Instant::now();
        store.list("cases", 0, 30, "").unwrap();
        cases.push(at.elapsed().as_secs_f64() * 1000.);
    }
    let report = json!({"task_items":distribution(items),"task_summary":distribution(summaries),"conflict_items":distribution(cases),"scope":"25 warmed direct Store API list requests on real post-build isolated database; excludes HTTP/network; old/new workload cardinality differs by authorized policy"});
    if let Ok(path) = std::env::var("AIRROUTE_PERFORMANCE_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    eprintln!("{}", serde_json::to_string(&report).unwrap());
}
