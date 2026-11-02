use airroute_rules::{
    audit::{self, AuditQuery},
    globalping, hash, now,
    store::Store,
};
use rusqlite::params;
use serde_json::{Value, json};

fn fixture() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    globalping::initialize_intents(&s).unwrap();
    (d, s)
}
fn case(s: &Store, key: &str, kind: &str, target: &str) {
    s.connect().unwrap().execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,'fp',1,?,?, 'fixture',?,'needs-active',1,?)",params![key,kind,key,json!({"targets":[target]}).to_string(),now()]).unwrap();
}
fn job(s: &Store, id: &str, key: &str, target: &str, status: &str) {
    let c = s.connect().unwrap();
    c.execute("INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created,round_seq,execution_count) VALUES(?,?,'fp','dns',?,'us',?, ?,?, ?,1,0)",params![id,key,target,json!({"logical_job":true,"purpose":"discovery"}).to_string(),status,now(),now()]).unwrap();
    link(s, id, key);
}
fn link(s: &Store, id: &str, key: &str) {
    s.connect().unwrap().execute("INSERT INTO job_cases(job_id,case_key,fp,revision,required_round_seq) VALUES(?,?,'fp',1,1)",params![id,key]).unwrap();
}
fn history(s: &Store, job: &str, token: &str, seq: i64, round: i64, started: bool) {
    s.connect().unwrap().execute("INSERT INTO lease_history(job_id,token_hash,node,fp,created,attempt_seq,round_seq,lease_profile,started_at,execution_job_id) VALUES(?,?,'node','fp',?,?,?, ?,?,?)",params![job,hash(token),now(),seq,round,json!({"execution_reservation_schema":1}).to_string(),if started{Some(now())}else{None},job]).unwrap();
}
fn receipt(s: &Store, id: &str, job: &str, seq: i64, round: i64, qualified: bool, until: i64) {
    s.connect().unwrap().execute("INSERT INTO results(id,job_id,node,fp,observed,outcome,evidence,accepted,received,attempt_seq,qualified,evidence_until,round_seq,execution_class) VALUES(?,?,'node','fp',?,'ok',?,1,?,?,?,?,?,'observation')",params![id,job,now(),json!({"answer":"fixture"}).to_string(),now(),seq,qualified,until,round]).unwrap();
}
fn total(v: &Value) -> i64 {
    v["total"].as_i64().unwrap()
}

#[test]
fn shared_job_counts_once_and_current_purposes_follow_valid_links() {
    let (_d, s) = fixture();
    case(&s, "discovery", "target-discovery", "example.com");
    case(&s, "manual", "domain-observation", "example.com");
    job(&s, "j", "discovery", "example.com", "pending");
    link(&s, "j", "manual");
    let all = audit::tasks(&s, &AuditQuery::default()).unwrap();
    assert_eq!(total(&all), 1);
    assert_eq!(all["items"][0]["case_count"], 2);
    assert_eq!(all["items"][0]["purpose"], "business");
    assert_eq!(
        all["items"][0]["purposes"],
        json!(["business", "discovery"])
    );
    assert_eq!(
        total(
            &audit::tasks(
                &s,
                &AuditQuery {
                    purpose: "discovery".into(),
                    ..Default::default()
                }
            )
            .unwrap()
        ),
        0
    );
    // The original owner's profile is unchanged, but the current live use changes.
    s.connect()
        .unwrap()
        .execute(
            "UPDATE cases SET fp='new-fp',revision=2 WHERE key='manual'",
            [],
        )
        .unwrap();
    let now = audit::tasks(&s, &AuditQuery::default()).unwrap();
    assert_eq!(now["items"][0]["purpose"], "discovery");
    assert_eq!(
        total(
            &audit::tasks(
                &s,
                &AuditQuery {
                    purpose: "business".into(),
                    ..Default::default()
                }
            )
            .unwrap()
        ),
        0
    );
}

#[test]
fn filters_and_counts_share_scope_and_split_unknown_cooldown_and_history() {
    let (_d, s) = fixture();
    for (id, status) in [
        ("queued", "pending"),
        ("cooldown", "unknown"),
        ("gp", "unknown"),
        ("old", "obsolete"),
        ("done", "complete"),
    ] {
        case(&s, id, "target-discovery", id);
        job(&s, id, id, id, status);
    }
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET execution_count=3,next_round_at=? WHERE id='cooldown'",
        [now() + 3600],
    )
    .unwrap();
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state) VALUES('gp','account','',?,0,'unknown')",[json!({"profile":{"round_seq":1}}).to_string()]).unwrap();
    let all = audit::tasks(&s, &AuditQuery::default()).unwrap();
    assert_eq!(total(&all), 3);
    assert_eq!(
        all["states"],
        json!({"queued":1,"cooldown":1,"unconfirmed":1})
    );
    for (state, key) in [
        ("queued", "queued"),
        ("cooldown", "cooldown"),
        ("unconfirmed", "gp"),
    ] {
        let p = AuditQuery {
            state: state.into(),
            case_key: key.into(),
            purpose: "discovery".into(),
            ..Default::default()
        };
        let full = audit::tasks(&s, &p).unwrap();
        assert_eq!(total(&full), 1);
        assert_eq!(full["items"][0]["state"], state);
        if state == "cooldown" {
            assert_eq!(full["items"][0]["phase"], "cooldown");
        }
        let summary = audit::tasks(
            &s,
            &AuditQuery {
                part: "summary".into(),
                ..p.clone()
            },
        )
        .unwrap();
        assert_eq!(summary["states"], full["states"]);
        assert!(summary.get("items").is_none());
        let items = audit::tasks(
            &s,
            &AuditQuery {
                part: "items".into(),
                ..p
            },
        )
        .unwrap();
        assert_eq!(items["items"], full["items"]);
        assert!(items.get("total").is_none());
    }
    assert_eq!(
        total(
            &audit::tasks(
                &s,
                &AuditQuery {
                    range: "ended".into(),
                    ..Default::default()
                }
            )
            .unwrap()
        ),
        1
    );
    assert_eq!(
        total(
            &audit::tasks(
                &s,
                &AuditQuery {
                    range: "all".into(),
                    state: "obsolete".into(),
                    ..Default::default()
                }
            )
            .unwrap()
        ),
        1
    );
    // Target disappearance hides an unstarted job, while a GP recovery survives.
    c.execute("UPDATE cases SET payload='{}'", []).unwrap();
    let view = audit::tasks(&s, &AuditQuery::default()).unwrap();
    assert_eq!(total(&view), 1);
    assert_eq!(view["items"][0]["id"], "gp");
}

#[test]
fn duplicate_receipts_and_late_rounds_keep_original_execution_identity() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "complete");
    history(&s, "j", "first", 1, 1, true);
    history(&s, "j", "second", 2, 2, true);
    receipt(&s, "first", "j", 1, 1, true, now() - 1);
    receipt(&s, "duplicate-transport-id", "j", 1, 1, true, now() - 1);
    receipt(&s, "new", "j", 2, 2, true, now() + 1000);
    let before = s
        .connect()
        .unwrap()
        .query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
        .unwrap();
    let v = audit::records(&s, &AuditQuery::default()).unwrap();
    assert_eq!(total(&v), 2);
    assert_eq!(v["states"]["returned"], 2);
    assert_eq!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["fresh"] == true)
            .count(),
        1
    );
    assert_eq!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["fresh"] == false)
            .count(),
        1
    );
    assert!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["qualified"] == true)
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results", [], |r| r.get(0))
            .unwrap(),
        before
    );
    let p = AuditQuery {
        part: "items".into(),
        job_id: "j".into(),
        case_key: "c".into(),
        ..Default::default()
    };
    let detail = audit::records(&s, &p).unwrap();
    assert!(detail["items"][0].get("result").is_some());
    assert_eq!(detail["items"][0]["case_count"], 1);
}

#[test]
fn ambiguous_legacy_results_are_visible_without_inventing_returned_executions() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "complete");
    history(&s, "j", "one", 1, 1, true);
    history(&s, "j", "other", 1, 1, true);
    receipt(&s, "r", "j", 1, 1, true, now() + 10);
    let v = audit::records(&s, &AuditQuery::default()).unwrap();
    assert!(v["states"].get("returned").is_none());
    assert_eq!(v["states"]["legacy-history"], 1);
    assert_eq!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["record_kind"] == "legacy-history")
            .unwrap()["identity_known"],
        false
    );
}

#[test]
fn reuse_and_unexecuted_claims_are_not_external_execution_records() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "complete");
    history(&s, "j", "reused", 1, 1, true);
    receipt(&s, "r", "j", 1, 1, true, now() + 10);
    history(&s, "j", "unsent", 2, 1, false);
    s.connect()
        .unwrap()
        .execute(
            "UPDATE lease_history SET execution_refunded=1 WHERE attempt_seq=1",
            [],
        )
        .unwrap();
    s.connect().unwrap().execute("UPDATE results SET evidence=json_set(evidence,'$.cache_hit',json('true')) WHERE id='r'",[]).unwrap();
    let v = audit::records(&s, &AuditQuery::default()).unwrap();
    assert_eq!(v["states"], json!({"reused":1,"not-executed":1}));
    let p = AuditQuery {
        state: "reused".into(),
        ..Default::default()
    };
    let filtered = audit::records(&s, &p).unwrap();
    assert_eq!(total(&filtered), 1);
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
}

#[test]
fn refunded_budget_does_not_by_itself_prove_cache_reuse() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "complete");
    history(&s, "j", "original", 1, 1, true);
    receipt(&s, "r", "j", 1, 1, true, now() + 10);
    s.connect()
        .unwrap()
        .execute("UPDATE lease_history SET execution_refunded=1", [])
        .unwrap();
    let v = audit::records(&s, &AuditQuery::default()).unwrap();
    assert_eq!(v["states"]["returned"], 1);
    assert!(v["states"].get("reused").is_none());
}

#[test]
fn orphan_remote_intent_remains_visible_and_keeps_original_remote_identity() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "unknown");
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state,attempt_seq,send_started_at) VALUES('j','account','',?,0,'unknown',4,?)",params![json!({"profile":{"round_seq":2}}).to_string(),now()]).unwrap();
    let v = audit::records(&s, &AuditQuery::default()).unwrap();
    assert_eq!(v["states"]["unconfirmed"], 1);
    assert_eq!(v["items"][0]["executor"], "globalping");
    assert_eq!(v["items"][0]["identity_known"], false);
    assert_eq!(v["items"][0]["attempt_seq"], 4);
    assert_eq!(v["items"][0]["round_seq"], 2);
}

#[test]
fn record_time_filter_uses_attempt_creation_without_rewriting_observed_time() {
    let (_d, s) = fixture();
    case(&s, "c", "domain-observation", "example.com");
    job(&s, "j", "c", "example.com", "complete");
    history(&s, "j", "attempt", 1, 1, true);
    receipt(&s, "r", "j", 1, 1, true, now() + 10);
    let old = now() - 3600;
    s.connect()
        .unwrap()
        .execute("UPDATE results SET observed=?", [old])
        .unwrap();
    let v = audit::records(
        &s,
        &AuditQuery {
            after: Some(now() - 100),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(total(&v), 1);
    assert_eq!(v["items"][0]["observed"], old);
    let v = audit::records(
        &s,
        &AuditQuery {
            before: Some(now() - 100),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(total(&v), 0);
}

#[test]
fn bounded_record_pages_match_the_complete_filtered_order_across_all_branches() {
    let (_d, s) = fixture();
    let base = now() - 1000;
    for i in 0..18 {
        let id = format!("job-{i:02}");
        let target = format!("host-{i:02}.example");
        case(
            &s,
            &id,
            if i % 4 == 0 {
                "target-discovery"
            } else {
                "domain-observation"
            },
            &target,
        );
        job(&s, &id, &id, &target, "complete");
        if i % 3 == 0 {
            receipt(&s, &format!("legacy-{i}"), &id, 0, 1, false, base + 3000);
            s.connect()
                .unwrap()
                .execute(
                    "UPDATE results SET received=? WHERE job_id=?",
                    params![base + i, id],
                )
                .unwrap();
        } else if i % 3 == 1 {
            history(&s, &id, &format!("token-{i}"), 1, 1, true);
            receipt(&s, &format!("known-{i}"), &id, 1, 1, true, base + 3000);
            s.connect()
                .unwrap()
                .execute(
                    "UPDATE lease_history SET created=? WHERE job_id=?",
                    params![base + i, id],
                )
                .unwrap();
        } else {
            s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state,attempt_seq,send_started_at) VALUES(?,'account','',?,0,'unknown',1,?)",params![id,json!({"profile":{"round_seq":1}}).to_string(),base+i]).unwrap();
        }
    }
    for p in [
        AuditQuery::default(),
        AuditQuery {
            purpose: "business".into(),
            ..Default::default()
        },
        AuditQuery {
            state: "returned".into(),
            ..Default::default()
        },
        AuditQuery {
            state: "legacy-history".into(),
            ..Default::default()
        },
        AuditQuery {
            after: Some(base + 4),
            before: Some(base + 15),
            ..Default::default()
        },
        AuditQuery {
            q: "host-1".into(),
            ..Default::default()
        },
    ] {
        let full = audit::records(
            &s,
            &AuditQuery {
                limit: 100,
                ..p.clone()
            },
        )
        .unwrap();
        let want = full["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].clone())
            .collect::<Vec<_>>();
        let mut got = Vec::new();
        for offset in (0..want.len() + 4).step_by(4) {
            let page = audit::records(
                &s,
                &AuditQuery {
                    part: "items".into(),
                    offset,
                    limit: 4,
                    ..p.clone()
                },
            )
            .unwrap();
            got.extend(
                page["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v["id"].clone()),
            );
        }
        assert_eq!(got, want, "filter {p:?}");
        assert_eq!(total(&full), want.len() as i64);
    }
}

#[test]
fn query_validation_rejects_unknown_filters_without_a_broad_scan() {
    let (_d, s) = fixture();
    assert!(
        audit::tasks(
            &s,
            &AuditQuery {
                state: "not-a-state".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        audit::tasks(
            &s,
            &AuditQuery {
                range: "recent".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        audit::records(
            &s,
            &AuditQuery {
                purpose: "typo".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        audit::records(
            &s,
            &AuditQuery {
                part: "invalid".into(),
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn deleted_case_does_not_hide_orphaned_business_job_or_execution_history() {
    let (_d, s) = fixture();
    case(&s, "deleted", "domain-observation", "old.example");
    job(&s, "historical", "deleted", "old.example", "complete");
    history(&s, "historical", "original", 1, 1, true);
    receipt(&s, "original-result", "historical", 1, 1, true, now() + 60);
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET profile=json_set(profile,'$.purpose','baseline') WHERE id='historical'",
        [],
    )
    .unwrap();
    c.execute("DELETE FROM cases WHERE key='deleted'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM job_cases WHERE job_id='historical'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM lease_history WHERE job_id='historical'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    let p = AuditQuery {
        range: "all".into(),
        ..Default::default()
    };
    let all_tasks = audit::tasks(&s, &p).unwrap();
    let business_tasks = audit::tasks(
        &s,
        &AuditQuery {
            purpose: "business".into(),
            ..p.clone()
        },
    )
    .unwrap();
    assert_eq!(total(&all_tasks), 1);
    assert_eq!(all_tasks["items"][0]["purpose"], "business");
    assert_eq!(business_tasks["items"], all_tasks["items"]);
    let all_records = audit::records(&s, &p).unwrap();
    let business_records = audit::records(
        &s,
        &AuditQuery {
            purpose: "business".into(),
            ..p
        },
    )
    .unwrap();
    assert_eq!(total(&all_records), 1);
    assert_eq!(total(&business_records), 1);
    assert_eq!(business_records["items"], all_records["items"]);
    assert_eq!(business_records["items"][0]["record_kind"], "returned");
    assert_eq!(business_records["items"][0]["cases"][0]["key"], "deleted");
    assert_eq!(business_records["items"][0]["cases"][0]["current"], false);
}

#[test]
fn record_page_legacy_bound_preserves_recent_ties_offsets_and_short_history() {
    let (_d, s) = fixture();
    let base = now() - 1000;
    for i in 0..12 {
        let id = format!("h-{i:02}");
        let host = format!("known-{i}.example");
        case(
            &s,
            &id,
            if i == 11 {
                "domain-observation"
            } else {
                "target-discovery"
            },
            &host,
        );
        job(&s, &id, &id, &host, "complete");
        history(&s, &id, &format!("token-{i}"), 1, 1, true);
        receipt(&s, &format!("result-{i}"), &id, 1, 1, true, now() + 1000);
        s.connect()
            .unwrap()
            .execute(
                "UPDATE lease_history SET created=? WHERE job_id=?",
                params![base + 100 - i, id],
            )
            .unwrap();
    }
    for (id, created, business) in [
        ("legacy-newest", base + 110, false),
        ("a-legacy-tie", base + 96, false),
        ("legacy-middle", base + 94, false),
        ("legacy-old", base + 1, false),
        ("legacy-business-new", base + 109, true),
        ("legacy-business-old", base + 1, true),
    ] {
        let host = format!("{id}.example");
        case(
            &s,
            id,
            if business {
                "domain-observation"
            } else {
                "target-discovery"
            },
            &host,
        );
        job(&s, id, id, &host, "complete");
        receipt(&s, &format!("result-{id}"), id, 0, 1, false, now() + 1000);
        s.connect()
            .unwrap()
            .execute(
                "UPDATE results SET received=? WHERE job_id=?",
                params![created, id],
            )
            .unwrap();
    }
    case(&s, "remote", "target-discovery", "remote.example");
    job(&s, "remote", "remote", "remote.example", "unknown");
    s.connect().unwrap().execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state,attempt_seq,send_started_at) VALUES('remote','fixture','',?,0,'unknown',1,?)",params![json!({"profile":{"round_seq":1}}).to_string(),base+98]).unwrap();
    for p in [
        AuditQuery::default(),
        AuditQuery {
            purpose: "business".into(),
            ..Default::default()
        },
        AuditQuery {
            state: "legacy-history".into(),
            ..Default::default()
        },
        AuditQuery {
            q: "legacy".into(),
            ..Default::default()
        },
        AuditQuery {
            after: Some(base + 99),
            ..Default::default()
        },
        AuditQuery {
            before: Some(base + 96),
            ..Default::default()
        },
    ] {
        // At limit 100 this fixture has fewer history rows than the cap, so
        // the oracle necessarily reads the complete legacy branch.
        let full = audit::records(
            &s,
            &AuditQuery {
                limit: 100,
                ..p.clone()
            },
        )
        .unwrap();
        let want = full["items"].as_array().unwrap();
        if p.purpose == "business" {
            assert_eq!(
                want.len(),
                3,
                "the old business legacy row must survive a history-short fallback"
            );
        }
        if p.q.is_empty()
            && p.state.is_empty()
            && p.purpose == "all"
            && p.after.is_none()
            && p.before.is_none()
        {
            assert_eq!(want.len(), 19);
            assert_eq!(want[0]["job_id"], "legacy-newest");
            let tie = want
                .iter()
                .position(|r| r["job_id"] == "a-legacy-tie")
                .unwrap();
            let known = want.iter().position(|r| r["job_id"] == "h-04").unwrap();
            assert!(
                tie < known,
                "equal-second legacy rows retain the global job/identity tie-break"
            );
        }
        for (offset, limit) in [(0, 1), (0, 4), (4, 4), (8, 4), (13, 4), (18, 4), (0, 8)] {
            let got = audit::records(
                &s,
                &AuditQuery {
                    part: "items".into(),
                    offset,
                    limit,
                    ..p.clone()
                },
            )
            .unwrap();
            let ids = got["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>();
            let expected = want
                .iter()
                .skip(offset)
                .take(limit)
                .map(|r| r["id"].clone())
                .collect::<Vec<_>>();
            assert_eq!(
                ids, expected,
                "filter={p:?}, offset={offset}, limit={limit}"
            );
        }
        let summary = audit::records(
            &s,
            &AuditQuery {
                part: "summary".into(),
                ..p.clone()
            },
        )
        .unwrap();
        assert_eq!(summary["states"], full["states"]);
        assert_eq!(total(&summary), want.len() as i64);
    }
}

#[test]
fn selective_task_candidates_preserve_scope_and_current_recovery_semantics() {
    let (_d, s) = fixture();
    case(&s, "aux", "target-discovery", "example.com");
    case(&s, "business", "domain-observation", "example.com");
    for (id, key, state) in [
        ("shared", "aux", "pending"),
        ("business-done", "business", "complete"),
        ("plain-unknown", "aux", "unknown"),
        ("cooldown", "aux", "unknown"),
        ("gp-obsolete", "aux", "obsolete"),
        ("gp-complete", "aux", "complete"),
        ("legacy", "aux", "pending"),
    ] {
        job(&s, id, key, "example.com", state);
    }
    link(&s, "shared", "business");
    case(&s, "deleted", "domain-observation", "old.example");
    job(&s, "orphan", "deleted", "old.example", "complete");
    case(&s, "inactive", "domain-observation", "inactive.example");
    job(&s, "inflight", "inactive", "inactive.example", "leased");
    case(
        &s,
        "without-target",
        "domain-observation",
        "missing.example",
    );
    job(
        &s,
        "unstarted",
        "without-target",
        "missing.example",
        "pending",
    );
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET profile=json_set(profile,'$.purpose','baseline') WHERE id='orphan'",
        [],
    )
    .unwrap();
    c.execute("DELETE FROM cases WHERE key='deleted'", [])
        .unwrap();
    c.execute("UPDATE cases SET active=0 WHERE key='inactive'", [])
        .unwrap();
    c.execute(
        "UPDATE cases SET payload='{}' WHERE key='without-target'",
        [],
    )
    .unwrap();
    c.execute("UPDATE jobs SET execution_count=3 WHERE id='cooldown'", [])
        .unwrap();
    c.execute("UPDATE jobs SET profile=json_set(json_remove(profile,'$.logical_job'),'$.legacy_alias',1) WHERE id='legacy'",[]).unwrap();
    for (id, state) in [("gp-obsolete", "unknown"), ("gp-complete", "sending")] {
        c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,state) VALUES(?,'fixture','',?,0,?)",params![id,json!({"profile":{"round_seq":1}}).to_string(),state]).unwrap();
    }
    for retired in [false, true] {
        if retired {
            c.execute("UPDATE cases SET active=0 WHERE key='business'", [])
                .unwrap();
        }
        for range in ["all", "current", "ended"] {
            let base = audit::tasks(
                &s,
                &AuditQuery {
                    limit: 100,
                    range: range.into(),
                    ..Default::default()
                },
            )
            .unwrap();
            for purpose in ["all", "business", "discovery"] {
                for state in [
                    "",
                    "queued",
                    "processing",
                    "unconfirmed",
                    "cooldown",
                    "ended",
                    "obsolete",
                ] {
                    let want = base["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|i| {
                            (purpose == "all"
                                || (purpose == "business" && i["purpose"] == "business")
                                || (purpose == "discovery"
                                    && i["purpose"] != "business"
                                    && i["purposes"]
                                        .as_array()
                                        .unwrap()
                                        .iter()
                                        .any(|p| p == "discovery")))
                                && (state.is_empty() || i["state"] == state)
                        })
                        .map(|i| i["id"].clone())
                        .collect::<Vec<_>>();
                    let p = AuditQuery {
                        limit: 100,
                        range: range.into(),
                        purpose: purpose.into(),
                        state: state.into(),
                        ..Default::default()
                    };
                    let actual = audit::tasks(&s, &p).unwrap();
                    let ids = actual["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i["id"].clone())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        ids, want,
                        "retired={retired} range={range} purpose={purpose} state={state}"
                    );
                    assert_eq!(total(&actual), want.len() as i64);
                }
            }
            for key in [
                "business",
                "aux",
                "deleted",
                "inactive",
                "without-target",
                "missing-key",
            ] {
                let want = base["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|i| {
                        i["cases"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|c| c["key"] == key)
                    })
                    .map(|i| i["id"].clone())
                    .collect::<Vec<_>>();
                let actual = audit::tasks(
                    &s,
                    &AuditQuery {
                        limit: 100,
                        range: range.into(),
                        case_key: key.into(),
                        ..Default::default()
                    },
                )
                .unwrap();
                assert_eq!(
                    actual["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i["id"].clone())
                        .collect::<Vec<_>>(),
                    want
                );
                assert_eq!(total(&actual), want.len() as i64);
            }
            for id in [
                "shared",
                "orphan",
                "gp-obsolete",
                "inflight",
                "legacy",
                "missing-id",
            ] {
                let want = base["items"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|i| i["id"] == id)
                    .map(|i| i["id"].clone())
                    .collect::<Vec<_>>();
                let actual = audit::tasks(
                    &s,
                    &AuditQuery {
                        limit: 100,
                        range: range.into(),
                        job_id: id.into(),
                        ..Default::default()
                    },
                )
                .unwrap();
                assert_eq!(
                    actual["items"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i["id"].clone())
                        .collect::<Vec<_>>(),
                    want
                );
                assert_eq!(total(&actual), want.len() as i64);
            }
        }
    }
}

#[test]
fn case_record_candidates_preserve_history_pages_summary_and_job_intersection() {
    let (_d, s) = fixture();
    let targets = ["100.42.112.2", "100.42.112.88", "100.42.112.226"];
    case(&s, "selected-case", "endpoint-reachability", targets[0]);
    s.connect().unwrap().execute("UPDATE cases SET payload=json_set(payload,'$.targets',json(?)) WHERE key='selected-case'",[json!(targets).to_string()]).unwrap();
    for (i, target) in targets.iter().enumerate() {
        let id = format!("selected-{i}");
        job(&s, &id, "selected-case", target, "complete");
        for seq in 1..=if i == 0 { 1 } else { 2 } {
            history(&s, &id, &format!("attempt-{i}-{seq}"), seq, 1, true);
            receipt(
                &s,
                &format!("receipt-{i}-{seq}"),
                &id,
                seq,
                1,
                i == 0,
                now() + 120,
            );
        }
    }
    let c = s.connect().unwrap();
    c.execute(
        "UPDATE jobs SET kind='traceroute' WHERE case_key='selected-case'",
        [],
    )
    .unwrap();
    c.execute("UPDATE results SET outcome='timeout',execution_class='target-failure',accepted=0 WHERE job_id IN ('selected-1','selected-2')",[]).unwrap();
    for i in 0..24 {
        let id = format!("unrelated-{i:02}");
        let target = format!("unrelated-{i}.example");
        case(&s, &id, "target-discovery", &target);
        job(&s, &id, &id, &target, "complete");
        history(&s, &id, &id, 1, 1, true);
        receipt(&s, &id, &id, 1, 1, true, now() + 120);
    }
    let p = AuditQuery {
        case_key: "selected-case".into(),
        range: "all".into(),
        limit: 100,
        ..Default::default()
    };
    let full = audit::records(&s, &p).unwrap();
    assert_eq!(total(&full), 5);
    assert_eq!(full["states"], json!({"returned":5}));
    let all = full["items"].as_array().unwrap();
    assert_eq!(all.iter().filter(|r| r["qualified"] == true).count(), 1);
    assert_eq!(
        all.iter()
            .filter(|r| r["execution_class"] == "target-failure")
            .count(),
        4
    );
    let expected = all.iter().map(|r| r["id"].clone()).collect::<Vec<_>>();
    let mut pages = Vec::new();
    for offset in [0, 2, 4, 6] {
        let page = audit::records(
            &s,
            &AuditQuery {
                part: "items".into(),
                offset,
                limit: 2,
                ..p.clone()
            },
        )
        .unwrap();
        pages.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["id"].clone()),
        );
    }
    assert_eq!(pages, expected);
    let summary = audit::records(
        &s,
        &AuditQuery {
            part: "summary".into(),
            ..p.clone()
        },
    )
    .unwrap();
    assert_eq!(summary["states"], full["states"]);
    assert_eq!(total(&summary), 5);
    let selected = audit::records(
        &s,
        &AuditQuery {
            job_id: "selected-1".into(),
            ..p.clone()
        },
    )
    .unwrap();
    assert_eq!(total(&selected), 2);
    assert!(
        selected["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["job_id"] == "selected-1")
    );
    assert_eq!(
        total(
            &audit::records(
                &s,
                &AuditQuery {
                    job_id: "unrelated-00".into(),
                    ..p.clone()
                }
            )
            .unwrap()
        ),
        0
    );
    assert_eq!(
        total(
            &audit::records(
                &s,
                &AuditQuery {
                    case_key: "missing-case".into(),
                    job_id: "selected-1".into(),
                    ..p.clone()
                }
            )
            .unwrap()
        ),
        0
    );
    assert_eq!(
        total(
            &audit::records(
                &s,
                &AuditQuery {
                    purpose: "business".into(),
                    ..p.clone()
                }
            )
            .unwrap()
        ),
        5
    );
    assert_eq!(
        total(
            &audit::records(
                &s,
                &AuditQuery {
                    purpose: "discovery".into(),
                    ..p.clone()
                }
            )
            .unwrap()
        ),
        0
    );
    c.execute(
        "UPDATE cases SET fp='later-version',revision=2,active=0 WHERE key='selected-case'",
        [],
    )
    .unwrap();
    let historical = audit::records(&s, &p).unwrap();
    assert_eq!(total(&historical), 5);
    assert!(
        historical["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["cases"][0]["current"] == false)
    );
}
