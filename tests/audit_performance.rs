use airroute_rules::{
    audit::{self, AuditQuery},
    now,
    store::Store,
};
use rusqlite::params;
use serde_json::json;
use std::time::Instant;

#[test]
#[ignore = "explicit read-only query workload; synthetic history, no network execution"]
fn representative_audit_history_queries() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    airroute_rules::globalping::initialize_intents(&store).unwrap();
    let mut c = store.connect().unwrap();
    let case_records_only = std::env::var_os("AIRROUTE_AUDIT_CASE_RECORDS_ONLY").is_some();
    let profile_index_ab = std::env::var_os("AIRROUTE_AUDIT_PROFILE_INDEX_AB").is_some();
    if profile_index_ab {
        c.execute_batch("DROP INDEX IF EXISTS audit_job_profile_fallback")
            .unwrap();
    }
    let n = 100_000_i64;
    let base = if case_records_only {
        1_700_000_000
    } else {
        now() - n * 2
    };
    let evidence_until = if case_records_only {
        base + n + 3600
    } else {
        now() + 3600
    };
    let prep = Instant::now();
    let tx = c.transaction().unwrap();
    {
        let mut case=tx.prepare("INSERT INTO cases VALUES(?,'case-fp',1,?,?,'synthetic discovery',?,'needs-active',1,?)").unwrap();
        let mut job=tx.prepare("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,attempt_seq,round_seq,execution_count,result_id) VALUES(?,?,'job-fp','dns',?,'any',?, ?,0,?,1,1,1,?)").unwrap();
        let mut link = tx
            .prepare("INSERT INTO job_cases VALUES(?,?,'case-fp',1,1)")
            .unwrap();
        let mut history=tx.prepare("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,round_seq,started_at,result_class,completed_at,lease_profile) VALUES(?,?,'fixture-node','job-fp',?,?,1,?,'observation',?,?)").unwrap();
        let mut result=tx.prepare("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,attempt_seq,qualified,evidence_until,round_seq,execution_class) VALUES(?,?,'fixture-node','job-fp',?,'ok',?,1,?,?,1,?,1,'observation')").unwrap();
        let profile =
            json!({"logical_job":1,"purpose":"discovery","execution_reservation_schema":1})
                .to_string();
        let business_profile =
            json!({"logical_job":1,"purpose":"baseline","execution_reservation_schema":1})
                .to_string();
        let evidence = json!({"kind":"dns","padding":"x".repeat(256)}).to_string();
        for i in 0..n {
            let id = format!("job-{i:06}");
            let key = format!("case-{i:06}");
            let target = format!("host-{i}.example");
            let at = base + i;
            let payload = json!({"targets":[target],"padding":"x".repeat(256)}).to_string();
            case.execute(params![
                key,
                if i < 100 {
                    "domain-observation"
                } else {
                    "target-discovery"
                },
                target,
                payload,
                at
            ])
            .unwrap();
            let status = if i < n - 250 {
                "complete"
            } else if i % 5 == 0 {
                "leased"
            } else if i % 5 == 1 {
                "unknown"
            } else {
                "pending"
            };
            let r = format!("result-{i:06}-1");
            job.execute(params![
                id,
                key,
                target,
                if profile_index_ab && i < 100 {
                    &business_profile
                } else {
                    &profile
                },
                status,
                at,
                r
            ])
            .unwrap();
            link.execute(params![id, key]).unwrap();
            for attempt in 1..=if i < 20_000 { 2 } else { 1 } {
                let token = format!("token-{i}-{attempt}");
                let r = format!("result-{i:06}-{attempt}");
                history
                    .execute(params![id, token, at, attempt, at, at + 1, profile])
                    .unwrap();
                result
                    .execute(params![
                        r,
                        id,
                        at,
                        evidence,
                        at + 1,
                        attempt,
                        evidence_until
                    ])
                    .unwrap();
            }
        }
        if case_records_only {
            tx.execute("UPDATE cases SET payload=json_set(payload,'$.targets',json(?)) WHERE key='case-000001'",[json!(["host-1.example","host-2.example","host-90000.example"]).to_string()]).unwrap();
            tx.execute(
                "INSERT INTO job_cases VALUES('job-000002','case-000001','case-fp',1,1)",
                [],
            )
            .unwrap();
            tx.execute(
                "INSERT INTO job_cases VALUES('job-090000','case-000001','case-fp',1,1)",
                [],
            )
            .unwrap();
        }
    }
    tx.commit().unwrap();
    c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
    eprintln!(
        "synthetic fixture preparation: {:.3}s; jobs=100000; attempt/result rows=120000",
        prep.elapsed().as_secs_f64()
    );
    if profile_index_ab {
        let mut linked_ids = None;
        for join in ["JOIN", "CROSS JOIN"] {
            let sql = format!(
                "SELECT DISTINCT l.job_id FROM case_metadata m {join} job_cases l ON l.case_key=m.key WHERE m.kind<>'target-discovery' ORDER BY l.job_id"
            );
            let start = Instant::now();
            let ids = c
                .prepare(&sql)
                .unwrap()
                .query_map([], |r| r.get::<_, String>(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            assert_eq!(ids.len(), 100);
            if let Some(before) = &linked_ids {
                assert_eq!(before, &ids);
            } else {
                linked_ids = Some(ids);
            }
            let plan = c
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            eprintln!(
                "{}",
                json!({"business_link_driver":join,"ms":ms,"output_unchanged":true,"plan":plan})
            );
        }
        let queries = [
            (
                "business-all-items",
                false,
                AuditQuery {
                    part: "items".into(),
                    purpose: "business".into(),
                    range: "all".into(),
                    ..Default::default()
                },
            ),
            (
                "business-all-summary",
                false,
                AuditQuery {
                    part: "summary".into(),
                    purpose: "business".into(),
                    range: "all".into(),
                    ..Default::default()
                },
            ),
            (
                "business-record-summary",
                true,
                AuditQuery {
                    part: "summary".into(),
                    purpose: "business".into(),
                    ..Default::default()
                },
            ),
        ];
        let mut before = Vec::new();
        for phase in ["before", "after"] {
            if phase == "after" {
                let start = Instant::now();
                c.execute_batch("CREATE INDEX audit_job_profile_fallback ON jobs(id) WHERE coalesce(json_extract(profile,'$.purpose'),'')<>'discovery'").unwrap();
                let indexed:i64=c.query_row("SELECT count(*) FROM jobs INDEXED BY audit_job_profile_fallback WHERE coalesce(json_extract(profile,'$.purpose'),'')<>'discovery'",[],|r|r.get(0)).unwrap();
                assert_eq!(indexed, 100);
                let plan=c.prepare("EXPLAIN QUERY PLAN SELECT j.id FROM jobs j WHERE NOT EXISTS(SELECT 1 FROM job_cases l JOIN cases c ON c.key=l.case_key WHERE l.job_id=j.id) AND coalesce(json_extract(j.profile,'$.purpose'),'')<>'discovery'").unwrap().query_map([],|r|r.get::<_,String>(3)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
                assert!(
                    plan.iter()
                        .any(|p| p.contains("audit_job_profile_fallback"))
                );
                eprintln!(
                    "{}",
                    json!({"profile_partial_index_rows":indexed,"create_ms":start.elapsed().as_secs_f64()*1000.0,"plan":plan})
                );
            }
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            for (i, (name, records, p)) in queries.iter().enumerate() {
                let mut elapsed = Vec::new();
                for _ in 0..3 {
                    let start = Instant::now();
                    let mut value = if *records {
                        audit::records(&store, p)
                    } else {
                        audit::tasks(&store, p)
                    }
                    .unwrap();
                    elapsed.push(start.elapsed().as_secs_f64() * 1000.0);
                    value["scope"] = json!(null);
                    if phase == "before" {
                        if before.len() == i {
                            before.push(value);
                        } else {
                            assert_eq!(before[i], value);
                        }
                    } else {
                        assert_eq!(before[i], value);
                    }
                }
                elapsed.sort_by(f64::total_cmp);
                eprintln!(
                    "{}",
                    json!({"synthetic":true,"phase":phase,"query":name,"samples":3,"p50_ms":elapsed[1],"max_ms":elapsed[2],"output_unchanged":true,"writer_reserved":true})
                );
            }
            c.execute_batch("ROLLBACK").unwrap();
        }
        return;
    }
    let queries = [
        (
            "current-items",
            false,
            AuditQuery {
                part: "items".into(),
                ..Default::default()
            },
        ),
        (
            "current-summary",
            false,
            AuditQuery {
                part: "summary".into(),
                ..Default::default()
            },
        ),
        (
            "ended-items",
            false,
            AuditQuery {
                part: "items".into(),
                range: "ended".into(),
                ..Default::default()
            },
        ),
        (
            "ended-summary",
            false,
            AuditQuery {
                part: "summary".into(),
                range: "ended".into(),
                ..Default::default()
            },
        ),
        (
            "case-all-items",
            false,
            AuditQuery {
                part: "items".into(),
                range: "all".into(),
                case_key: "case-000001".into(),
                ..Default::default()
            },
        ),
        (
            "case-all-summary",
            false,
            AuditQuery {
                part: "summary".into(),
                range: "all".into(),
                case_key: "case-000001".into(),
                ..Default::default()
            },
        ),
        (
            "business-all-items",
            false,
            AuditQuery {
                part: "items".into(),
                range: "all".into(),
                purpose: "business".into(),
                ..Default::default()
            },
        ),
        (
            "business-all-summary",
            false,
            AuditQuery {
                part: "summary".into(),
                range: "all".into(),
                purpose: "business".into(),
                ..Default::default()
            },
        ),
        (
            "discovery-unconfirmed-items",
            false,
            AuditQuery {
                part: "items".into(),
                purpose: "discovery".into(),
                state: "unconfirmed".into(),
                ..Default::default()
            },
        ),
        (
            "discovery-unconfirmed-summary",
            false,
            AuditQuery {
                part: "summary".into(),
                purpose: "discovery".into(),
                state: "unconfirmed".into(),
                ..Default::default()
            },
        ),
        (
            "record-items",
            true,
            AuditQuery {
                part: "items".into(),
                ..Default::default()
            },
        ),
        (
            "record-summary",
            true,
            AuditQuery {
                part: "summary".into(),
                ..Default::default()
            },
        ),
        (
            "business-record-summary",
            true,
            AuditQuery {
                part: "summary".into(),
                purpose: "business".into(),
                ..Default::default()
            },
        ),
        (
            "case-record-items",
            true,
            AuditQuery {
                part: "items".into(),
                range: "all".into(),
                case_key: "case-000001".into(),
                ..Default::default()
            },
        ),
        (
            "case-record-summary",
            true,
            AuditQuery {
                part: "summary".into(),
                range: "all".into(),
                case_key: "case-000001".into(),
                ..Default::default()
            },
        ),
    ];
    // A reader must work while another connection owns the writer reservation.
    // Keeping this open also makes any accidental write in the new API fail.
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    for (name, records, p) in queries {
        if case_records_only && !name.starts_with("case-record-") {
            continue;
        }
        let mut ms = Vec::new();
        let mut output_sha256 = None;
        for _ in 0..5 {
            let started = Instant::now();
            let value = if records {
                audit::records(&store, &p)
            } else {
                audit::tasks(&store, &p)
            }
            .unwrap();
            ms.push(started.elapsed().as_secs_f64() * 1000.0);
            if case_records_only {
                let mut stable = value.clone();
                stable["scope"].as_object_mut().unwrap().remove("at");
                let digest = airroute_rules::fingerprint(&stable);
                if let Some(before) = &output_sha256 {
                    assert_eq!(before, &digest);
                } else {
                    output_sha256 = Some(digest);
                }
            }
            if name == "case-record-items" {
                assert_eq!(
                    value["items"].as_array().unwrap().len(),
                    if case_records_only { 5 } else { 2 }
                );
            } else if name == "case-record-summary" {
                assert_eq!(value["total"], if case_records_only { 5 } else { 2 });
            } else if name == "case-all-items" {
                assert_eq!(value["items"].as_array().unwrap().len(), 1);
            } else if p.part == "items" {
                assert_eq!(value["items"].as_array().unwrap().len(), 30);
            } else if name == "current-summary" {
                assert_eq!(value["total"], 250);
            } else if name == "ended-summary" {
                assert_eq!(value["total"], 99_750);
            } else if name == "record-summary" {
                assert_eq!(value["total"], 120_000);
            } else if name == "business-record-summary" {
                assert_eq!(value["total"], 200);
            } else if name == "case-all-summary" {
                assert_eq!(value["total"], 1);
            } else if name == "business-all-summary" {
                assert_eq!(value["total"], 100);
            } else if name == "discovery-unconfirmed-summary" {
                assert_eq!(value["total"], 50);
            }
        }
        ms.sort_by(f64::total_cmp);
        eprintln!(
            "{}",
            json!({"synthetic":true,"query":name,"samples":5,"p50_ms":ms[2],"p95_ms":ms[4],"read_only_with_writer_reserved":true,"fixed_epoch":case_records_only,"output_sha256_without_scope_at":output_sha256})
        );
    }
    c.execute_batch("ROLLBACK").unwrap();
}
