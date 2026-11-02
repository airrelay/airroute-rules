use airroute_rules::{audit::AuditQuery, audit_issues, hash, now, store::Store};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};

fn open(data: &Path) -> Store {
    let store = Store::open(data).unwrap();
    // The server initializes durable GP columns before exposing console reads.
    airroute_rules::globalping::initialize_intents(&store).unwrap();
    store
}

fn row(key: &str, kind: &str, measurable: bool, targets: &[&str]) -> Value {
    json!({"key":key,"fp":"v1","kind":kind,"subject":format!("range-{key}"),"reason":"fixture source disagreement","measurable":measurable,"payload":{"kind":kind,"targets":targets,"measurement_required":measurable,"publication":"deterministic geographic fallback already emitted"}})
}

fn manifest(data: &Path, store: &Store, id: &str, rows: &[Value]) {
    let directory = data.join("internal-builds").join(id);
    std::fs::create_dir_all(&directory).unwrap();
    let mut c = Connection::open(directory.join("manifest.sqlite3")).unwrap();
    // Deliberately the old production schema, without the new covering index.
    c.execute_batch("CREATE TABLE cases(key TEXT PRIMARY KEY,fp TEXT NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,reason TEXT NOT NULL,payload TEXT NOT NULL,source_hash TEXT NOT NULL,measurable INTEGER NOT NULL);CREATE INDEX case_measurable ON cases(key,source_hash) WHERE measurable=1;").unwrap();
    let tx = c.transaction().unwrap();
    for row in rows {
        tx.execute(
            "INSERT INTO cases VALUES(?,?,?,?,?,?,?,?)",
            params![
                row["key"].as_str().unwrap(),
                row["fp"].as_str().unwrap(),
                row["kind"].as_str().unwrap(),
                row["subject"].as_str().unwrap(),
                row["reason"].as_str().unwrap(),
                row["payload"].to_string(),
                "source",
                row["measurable"].as_bool().unwrap()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let n_measurable = rows.iter().filter(|r| r["measurable"] == true).count();
    let gaps = rows.iter().filter(|r| r["kind"] == "coverage-gap").count();
    let domains = rows.iter().filter(|r| r["kind"] == "domain-policy").count();
    let summary = json!({"observation_cutoff":now()-60,"domain_quarantines":domains,"geography":{"active_required_groups":n_measurable,"non_measurable_location_gaps":rows.len()-n_measurable-gaps-domains,"coverage_gap_groups":gaps}});
    std::fs::write(
        directory.join("build.json"),
        json!({"build_id":id,"release_hash":format!("release-{id}"),"summary":summary}).to_string(),
    )
    .unwrap();
    store.connect().unwrap().execute("INSERT INTO builds(id,status,started,finished,release,summary) VALUES(?,'complete',?,?,?,?)",params![id,now()-120,now()-30,format!("release-{id}"),summary.to_string()]).unwrap();
    store.set_meta("current-build-id", id).unwrap();
}

fn online(store: &Store, row: &Value) {
    store
        .connect()
        .unwrap()
        .execute(
            "INSERT INTO cases VALUES(?,?,1,?,?,?,?,'needs-active',1,?)",
            params![
                row["key"].as_str().unwrap(),
                row["fp"].as_str().unwrap(),
                row["kind"].as_str().unwrap(),
                row["subject"].as_str().unwrap(),
                row["reason"].as_str().unwrap(),
                row["payload"].to_string(),
                now()
            ],
        )
        .unwrap();
}

fn job(store: &Store, id: &str, key: &str, status: &str, execution_count: i64) {
    let c = store.connect().unwrap();
    c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,execution_count) VALUES(?,?,'v1','traceroute','1.1.1.1','us','{\"logical_job\":true}',?,?,?,?)", params![id,key,status,now(),now(),execution_count]).unwrap();
    c.execute(
        "INSERT INTO job_cases VALUES(?,?,'v1',1,1)",
        params![id, key],
    )
    .unwrap();
    if status == "complete" {
        let result_id = format!("result-{id}");
        c.execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received) VALUES(?,?,'fixture','v1',?,'ok','{}',1,?)",params![result_id,id,now(),now()]).unwrap();
        c.execute(
            "UPDATE jobs SET result_id=? WHERE id=?",
            params![result_id, id],
        )
        .unwrap();
    }
}

#[test]
fn complete_manifest_is_not_the_online_task_subset_and_reads_do_not_write() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let rows = vec![
        row("waiting", "endpoint-reachability", true, &[]),
        row("returned", "endpoint-reachability", true, &["1.1.1.1"]),
        row("source", "geolocation", false, &[]),
        row("gap", "coverage-gap", false, &[]),
        row("domain", "domain-policy", false, &[]),
    ];
    manifest(d.path(), &s, "build-one", &rows);
    online(&s, &rows[0]);
    online(&s, &rows[1]);
    job(&s, "trace", "returned", "complete", 1);
    let path = d.path().join("internal-builds/build-one/manifest.sqlite3");
    let before = hash(std::fs::read(&path).unwrap());
    let query = AuditQuery {
        category: "all".into(),
        ..Default::default()
    };
    let all = audit_issues::issues(&s, d.path(), &query).unwrap();
    assert_eq!(all["full_total"], 5);
    assert_eq!(all["total"], 5);
    assert_eq!(
        all["categories"],
        json!({"measurable":2,"sources":2,"gaps":1})
    );
    assert_eq!(
        all["states"],
        json!({"awaiting-target":1,"returned":1,"not-scheduled":3})
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM cases", [], |r| r.get(0))
            .unwrap(),
        2
    );
    assert!(
        all["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("payload").is_none())
    );
    let detail = audit_issues::issues(
        &s,
        d.path(),
        &AuditQuery {
            category: "all".into(),
            case_key: "returned".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(detail["total"], 1);
    assert_eq!(detail["items"][0]["job_count"], 1);
    assert_eq!(detail["items"][0]["progress"], "returned");
    assert!(
        detail["items"][0]["rule_basis"]
            .as_str()
            .unwrap()
            .contains("不用于判定地区")
    );
    assert_eq!(detail["items"][0]["payload"], rows[1]["payload"]);
    assert_eq!(
        hash(std::fs::read(path).unwrap()),
        before,
        "browsing must not mutate an immutable manifest"
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
            .unwrap(),
        1
    );
}

#[test]
fn category_state_search_and_detail_use_the_same_scope() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let rows = vec![
        row("a", "endpoint-reachability", true, &[]),
        row("b", "endpoint-reachability", true, &["1.1.1.1"]),
        row("source", "geolocation", false, &[]),
        row("gap", "coverage-gap", false, &[]),
    ];
    manifest(d.path(), &s, "build-filter", &rows);
    online(&s, &rows[0]);
    online(&s, &rows[1]);
    job(&s, "pending", "b", "pending", 0);
    for category in ["all", "measurable", "sources", "gaps"] {
        for state in ["", "awaiting-target", "queued", "returned", "not-scheduled"] {
            let q = AuditQuery {
                category: category.into(),
                state: state.into(),
                ..Default::default()
            };
            let both = audit_issues::issues(&s, d.path(), &q).unwrap();
            let items = audit_issues::issues(
                &s,
                d.path(),
                &AuditQuery {
                    part: "items".into(),
                    ..q.clone()
                },
            )
            .unwrap();
            let summary = audit_issues::issues(
                &s,
                d.path(),
                &AuditQuery {
                    part: "summary".into(),
                    ..q.clone()
                },
            )
            .unwrap();
            assert_eq!(items["items"], both["items"]);
            assert_eq!(summary["total"], both["total"]);
            assert_eq!(summary["states"], both["states"]);
            assert_eq!(
                both["total"].as_u64().unwrap() as usize,
                both["items"].as_array().unwrap().len(),
                "{category}:{state}"
            );
            assert!(
                both["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|r| state.is_empty() || r["progress"] == state)
            );
        }
    }
    let source = audit_issues::issues(
        &s,
        d.path(),
        &AuditQuery {
            category: "sources".into(),
            q: "range-source".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(source["total"], 1);
    assert_eq!(source["states"], json!({"not-scheduled":1}));
    let not_found = audit_issues::issues(
        &s,
        d.path(),
        &AuditQuery {
            category: "all".into(),
            case_key: "not-found".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(not_found["total"], 0);
    assert!(not_found["items"].as_array().unwrap().is_empty());
}

#[test]
fn old_build_fingerprints_do_not_borrow_new_work_and_bound_builds_stay_selected() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let old = row("same-key", "endpoint-reachability", true, &["1.1.1.1"]);
    manifest(d.path(), &s, "older", std::slice::from_ref(&old));
    let mut new = old.clone();
    new["fp"] = json!("v2");
    manifest(d.path(), &s, "newer", std::slice::from_ref(&new));
    online(&s, &new);
    let old_page = audit_issues::issues(
        &s,
        d.path(),
        &AuditQuery {
            build_id: "older".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(old_page["build_id"], "older");
    assert_eq!(old_page["current_build_id"], "newer");
    assert_eq!(old_page["historical"], true);
    assert_eq!(old_page["items"][0]["fingerprint"], "v1");
    assert_eq!(old_page["items"][0]["progress"], "historical");
    assert_eq!(old_page["items"][0]["live_compatible"], false);
    assert_eq!(old_page["items"][0]["job_count"], 0);
    assert!(
        audit_issues::issues(
            &s,
            d.path(),
            &AuditQuery {
                build_id: "../newer".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn awaiting_target_cooldown_unknown_and_processing_are_distinct_problem_progress() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let rows = vec![
        row("cool", "endpoint-reachability", true, &["1.1.1.1"]),
        row("gp", "endpoint-reachability", true, &["1.1.1.1"]),
        row("busy", "endpoint-reachability", true, &["1.1.1.1"]),
    ];
    manifest(d.path(), &s, "states", &rows);
    for r in &rows {
        online(&s, r);
    }
    job(&s, "cool-job", "cool", "unknown", 3);
    job(&s, "gp-job", "gp", "unknown", 1);
    job(&s, "busy-job", "busy", "leased", 0);
    let c = s.connect().unwrap();
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state) VALUES('gp-job','account','','{}',0,'unknown')",[]).unwrap();
    let v = audit_issues::issues(&s, d.path(), &Default::default()).unwrap();
    assert_eq!(
        v["states"],
        json!({"cooldown":1,"unconfirmed":1,"processing":1})
    );
}

#[test]
fn empty_uninitialized_catalogue_is_a_clear_empty_state() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let v = audit_issues::issues(&s, d.path(), &Default::default()).unwrap();
    assert_eq!(v["available"], false);
    assert_eq!(v["build_id"], Value::Null);
    assert_eq!(v["total"], 0);
    assert!(v["items"].as_array().unwrap().is_empty());
}

#[test]
fn ended_without_a_retained_result_is_not_reported_as_a_returned_observation() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let entry = row("old-ended", "endpoint-reachability", true, &["1.1.1.1"]);
    manifest(d.path(), &s, "old-result", std::slice::from_ref(&entry));
    online(&s, &entry);
    job(&s, "old-job", "old-ended", "complete", 1);
    s.connect()
        .unwrap()
        .execute("DELETE FROM results", [])
        .unwrap();
    let page = audit_issues::issues(&s, d.path(), &Default::default()).unwrap();
    assert_eq!(page["items"][0]["job_count"], 1);
    assert_eq!(page["items"][0]["progress"], "unconfirmed");
    assert_eq!(page["states"], json!({"unconfirmed":1}));
}

#[test]
fn candidate_detail_keeps_live_sampling_separate_from_the_frozen_build_and_response_evidence() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    let mut frozen = row("candidate", "endpoint-reachability", true, &["1.0.0.1"]);
    frozen["payload"]["target_evidence"] = json!({"1.0.0.1":{"kind":"dns-answer","source":"fixture DNS","observed":now()-20,"valid_until":now()+300}});
    frozen["payload"]["sample_plan"] = json!({"strategy":"bgp-bounded-v1","targets_per_group":3,"allow_ipv4_candidates":true,"parent_case_key":"parent-range","seed":"stable-fixture"});
    manifest(
        d.path(),
        &s,
        "candidate-build",
        std::slice::from_ref(&frozen),
    );
    let mut runtime = frozen.clone();
    runtime["payload"]["targets"] = json!(["1.1.1.1"]);
    runtime["payload"]["target_evidence"] =
        json!({"1.1.1.1":{"kind":"sampled-candidate","source":"bgp-bounded-v1"}});
    online(&s, &runtime);
    let p = AuditQuery {
        case_key: "candidate".into(),
        build_id: "candidate-build".into(),
        ..Default::default()
    };
    let detail = audit_issues::issues(&s, d.path(), &p).unwrap();
    let item = &detail["items"][0];
    assert_eq!(item["targets"], json!(["1.1.1.1"]));
    assert_eq!(item["target_evidence_is_live"], true);
    assert_eq!(
        item["target_evidence"]["1.1.1.1"]["kind"],
        "sampled-candidate"
    );
    assert!(item["target_evidence"]["1.1.1.1"].get("observed").is_none());
    assert!(
        item["target_evidence"]["1.1.1.1"]
            .get("valid_until")
            .is_none()
    );
    assert_eq!(
        item["payload"], frozen["payload"],
        "current target selection must not rewrite the frozen build material"
    );
    let list = audit_issues::issues(
        &s,
        d.path(),
        &AuditQuery {
            part: "items".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(
        list["items"][0].get("target_evidence").is_none(),
        "full provenance belongs only to the selected detail"
    );
    assert!(list["items"][0].get("target_evidence_is_live").is_none());
    manifest(
        d.path(),
        &s,
        "candidate-new-build",
        std::slice::from_ref(&frozen),
    );
    let historical = audit_issues::issues(&s, d.path(), &p).unwrap();
    assert_eq!(historical["historical"], true);
    assert_eq!(historical["items"][0]["target_evidence_is_live"], true);
    assert_eq!(historical["items"][0]["payload"], frozen["payload"]);
    s.connect()
        .unwrap()
        .execute(
            "UPDATE cases SET fp='v2',revision=2 WHERE key='candidate'",
            [],
        )
        .unwrap();
    let incompatible = audit_issues::issues(&s, d.path(), &p).unwrap();
    assert_eq!(incompatible["items"][0]["target_evidence_is_live"], false);
    assert_eq!(
        incompatible["items"][0]["target_evidence"],
        frozen["payload"]["target_evidence"]
    );
    assert_eq!(
        incompatible["items"][0]["target_evidence"]["1.0.0.1"]["kind"],
        "dns-answer"
    );
}

#[test]
#[ignore = "147k old-schema catalogue workload; run explicitly to measure read cost"]
fn production_sized_immutable_catalogue_queries_remain_page_bounded() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path());
    manifest(d.path(), &s, "large", &[]);
    let path = d.path().join("internal-builds/large/manifest.sqlite3");
    let mut c = Connection::open(&path).unwrap();
    let tx = c.transaction().unwrap();
    {
        let mut insert = tx
            .prepare("INSERT INTO cases VALUES(?,? ,?,?,?,?,'source',?)")
            .unwrap();
        let padding = "x".repeat(2048);
        for i in 0..147225 {
            let measurable = i < 1712;
            insert
                .execute(params![
                    format!("case-{i:06}"),
                    "v1",
                    if measurable {
                        "endpoint-reachability"
                    } else if i < 147220 {
                        "geolocation"
                    } else {
                        "coverage-gap"
                    },
                    format!("fixture-{i}"),
                    "source disagreement",
                    json!({"targets":[],"padding":padding,"measurement_required":measurable})
                        .to_string(),
                    measurable
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    drop(c);
    for i in 0..1712 {
        let targets = if i < 71 { vec!["1.1.1.1"] } else { Vec::new() };
        online(
            &s,
            &row(
                &format!("case-{i:06}"),
                "endpoint-reachability",
                true,
                &targets,
            ),
        );
        if i < 71 {
            job(
                &s,
                &format!("completed-{i}"),
                &format!("case-{i:06}"),
                "complete",
                1,
            );
        }
    }
    let summary = json!({"domain_quarantines":0,"geography":{"active_required_groups":1712,"non_measurable_location_gaps":145508,"coverage_gap_groups":5}});
    s.connect()
        .unwrap()
        .execute(
            "UPDATE builds SET summary=? WHERE id='large'",
            [summary.to_string()],
        )
        .unwrap();
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    for (name, q) in [
        (
            "default-items",
            AuditQuery {
                part: "items".into(),
                ..Default::default()
            },
        ),
        (
            "default-summary",
            AuditQuery {
                part: "summary".into(),
                ..Default::default()
            },
        ),
        (
            "sources-items",
            AuditQuery {
                category: "sources".into(),
                part: "items".into(),
                ..Default::default()
            },
        ),
        (
            "sources-summary",
            AuditQuery {
                category: "sources".into(),
                part: "summary".into(),
                ..Default::default()
            },
        ),
        (
            "source-detail",
            AuditQuery {
                category: "all".into(),
                case_key: "case-090000".into(),
                ..Default::default()
            },
        ),
    ] {
        let start = Instant::now();
        let value = audit_issues::issues(&s, d.path(), &q).unwrap();
        eprintln!(
            "audit issue old-schema {name}: elapsed_ms={:.3} rows={} total={}",
            start.elapsed().as_secs_f64() * 1000.,
            value["items"].as_array().map_or(0, Vec::len),
            value["total"]
        );
        assert!(value["items"].as_array().is_none_or(|a| a.len() <= 30));
    }
    assert_eq!(before, std::fs::metadata(path).unwrap().modified().unwrap());
}
