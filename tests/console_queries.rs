use airroute_rules::{scheduler, store::Store};
use serde_json::json;
use std::time::Instant;

#[test]
fn large_queue_pagination_filters_and_totals_share_the_same_state_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let conn = store.connect().unwrap();
    // A production-sized case catalogue, with executable state only on a small subset.
    conn.execute_batch("BEGIN;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<149999)
        INSERT INTO cases SELECT printf('case-%06d',i),'fp',1,'geolocation',printf('fixture-%d',i),'fixture disagreement',json_object('padding',printf('%01024d',i),'targets',json_array('1.1.1.1')),'needs-active',1,i FROM n;
        WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<5999)
        INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created)
        SELECT printf('job-%d',i),printf('case-%06d',i),'fp','traceroute','1.1.1.1','us',
          CASE WHEN i%6=4 THEN json_object('scheduler',2,'case_revision',1,'observer_id','offline') ELSE json_object('scheduler',2,'case_revision',1) END,
          CASE i%6 WHEN 0 THEN 'complete' WHEN 1 THEN 'unknown' WHEN 5 THEN 'leased' ELSE 'pending' END,
          CASE WHEN i%6=2 THEN 4102444800 ELSE 0 END,i FROM n;
        INSERT INTO job_cases SELECT id,case_key,'fp',1,1 FROM jobs;
        COMMIT;").unwrap();
    let start = Instant::now();
    let page = scheduler::tasks(&store, 0, 30, "").unwrap();
    eprintln!("150k cases / 6k jobs: tasks {:?}", start.elapsed());
    assert_eq!(page["total"], 150000);
    assert_eq!(page["items"].as_array().unwrap().len(), 30);
    assert_eq!(page["items"][0]["key"], "case-149999");
    assert_eq!(page["states"]["awaiting-target"], 144000);
    let start = Instant::now();
    assert_eq!(
        scheduler::task_items(&store, 0, 30, "").unwrap()["items"],
        page["items"]
    );
    eprintln!("150k cases / 6k jobs: page-only {:?}", start.elapsed());
    let start = Instant::now();
    let summary = scheduler::task_summary(&store, "").unwrap();
    eprintln!(
        "150k cases / 6k jobs: independent summary {:?}",
        start.elapsed()
    );
    assert_eq!(summary["total"], page["total"]);
    assert_eq!(summary["states"], page["states"]);
    let jobs_page = scheduler::tasks(&store, 144000, 30, "").unwrap();
    assert_eq!(
        scheduler::task_items(&store, 144000, 30, "").unwrap()["items"],
        jobs_page["items"],
        "page-only aggregation retains actual job states at a deep offset"
    );
    for state in [
        "complete",
        "failed",
        "scheduled",
        "waiting-capability",
        "waiting-node",
        "running",
    ] {
        assert_eq!(page["states"][state], 1000, "{state}");
        assert_eq!(
            scheduler::task_summary(&store, &format!("state:{state}")).unwrap()["total"],
            1000
        );
        let filtered = scheduler::tasks(&store, 990, 30, state).unwrap();
        assert_eq!(filtered["total"], 1000);
        assert_eq!(filtered["states"], page["states"]);
        assert_eq!(filtered["items"].as_array().unwrap().len(), 10);
        assert_eq!(
            scheduler::task_items(&store, 990, 30, state).unwrap()["items"],
            filtered["items"]
        );
        assert_eq!(
            scheduler::task_summary(&store, state).unwrap()["total"],
            filtered["total"]
        );
        assert!(
            filtered["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["state"] == state)
        );
    }
    conn.execute("UPDATE jobs SET status='complete' WHERE status='pending' AND id NOT IN (SELECT id FROM jobs WHERE status='pending' ORDER BY id LIMIT 10)",[]).unwrap();
    let start = Instant::now();
    let small_pending = scheduler::task_summary(&store, "").unwrap();
    eprintln!(
        "150k cases / 6k historical jobs / 10 pending: summary {:?}",
        start.elapsed()
    );
    assert_eq!(small_pending["total"], 150000);
    assert_eq!(small_pending["states"]["complete"], 3990);
    let start = Instant::now();
    let conflicts = store.list("cases", 0, 30, "").unwrap();
    eprintln!("150k cases: conflicts {:?}", start.elapsed());
    assert_eq!(conflicts["total"], 150000);
    assert_eq!(conflicts["items"][0]["key"], "case-149999");
    assert_eq!(
        store.list("cases", 0, 30, "kind:geolocation").unwrap(),
        conflicts
    );
    assert_eq!(
        store.list("cases", 0, 30, "status:needs-active").unwrap(),
        conflicts
    );
    assert_eq!(
        store.overview().unwrap()["cases"]["geolocation/needs-active"],
        150000
    );
}

#[test]
fn transactional_counters_follow_jobs_revisions_sources_and_rollbacks() {
    use rusqlite::types::Value as SqlValue;
    fn rows(c: &rusqlite::Connection, sql: &str) -> Vec<Vec<SqlValue>> {
        let mut q = c.prepare(sql).unwrap();
        let columns = q.column_count();
        q.query_map([], |r| (0..columns).map(|i| r.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
    }
    fn check(c: &rusqlite::Connection) {
        assert_eq!(
            rows(
                c,
                "SELECT case_key,fp,revision,total,pending,running,failed,completed FROM task_job_totals WHERE total>0 ORDER BY 1,2,3"
            ),
            rows(
                c,
                "SELECT l.case_key,l.fp,l.revision,count(*),sum(j.status='pending' OR (j.status='complete' AND j.round_seq<l.required_round_seq)),sum(j.status='leased'),sum(j.status='unknown'),sum(j.status='complete' AND j.round_seq>=l.required_round_seq) FROM job_cases l JOIN jobs j ON j.id=l.job_id JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision WHERE j.status<>'obsolete' AND c.active=1 AND c.status<>'decided' AND EXISTS(SELECT 1 FROM json_each(c.payload,'$.targets') selected WHERE selected.value=j.target) GROUP BY 1,2,3 ORDER BY 1,2,3"
            )
        );
        assert_eq!(
            rows(
                c,
                "SELECT source,state,n FROM task_default_counts WHERE n>0 ORDER BY 1,2"
            ),
            rows(
                c,
                "SELECT source,state,count(*) FROM task_defaults GROUP BY 1,2 ORDER BY 1,2"
            )
        );
        assert_eq!(
            rows(
                c,
                "SELECT kind,status,n FROM case_group_counts WHERE n>0 ORDER BY 1,2"
            ),
            rows(
                c,
                "SELECT kind,status,count(*) FROM case_metadata WHERE active=1 GROUP BY 1,2 ORDER BY 1,2"
            )
        );
        assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM task_job_totals WHERE total<0 OR pending<0 OR completed<0 OR failed<0 OR running<0",[],|r|r.get(0)).unwrap(),0);
    }
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let mut c = store.connect().unwrap();
    c.execute_batch("INSERT INTO cases VALUES('counter','fp',1,'geolocation','1.1.1.1','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,0);INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created) VALUES('counter-job','counter','observation-fp','traceroute','1.1.1.1','us','{\"scheduler\":2,\"logical_job\":1,\"observation_schema\":4}','pending',0,0);INSERT INTO job_cases VALUES('counter-job','counter','fp',1,1);").unwrap();
    for (status, state) in [
        ("pending", "waiting-capability"),
        ("leased", "running"),
        ("complete", "complete"),
        ("unknown", "failed"),
        ("obsolete", "awaiting-target"),
    ] {
        c.execute("UPDATE jobs SET status=?", [status]).unwrap();
        check(&c);
        assert_eq!(
            scheduler::task_summary(&store, &format!("state:{state}")).unwrap()["total"],
            1,
            "{status} should project as {state} through the case link"
        );
    }
    c.execute("UPDATE jobs SET status='pending'", []).unwrap();
    {
        let tx = c.transaction().unwrap();
        tx.execute("UPDATE jobs SET status='complete'", []).unwrap();
        assert_eq!(
            scheduler::task_summary(&store, "state:waiting-capability").unwrap()["total"],
            1
        );
        tx.rollback().unwrap();
    }
    check(&c);
    c.execute("UPDATE cases SET active=0", []).unwrap();
    assert_eq!(
        scheduler::task_summary(&store, "state:obsolete").unwrap()["total"],
        1
    );
    c.execute("UPDATE cases SET active=1,status='decided'", [])
        .unwrap();
    assert_eq!(
        scheduler::task_summary(&store, "state:decided").unwrap()["total"],
        1
    );
    c.execute(
        "UPDATE cases SET status='needs-active',fp='v2',revision=2,kind='manual-ip'",
        [],
    )
    .unwrap();
    assert_eq!(scheduler::task_summary(&store, "").unwrap()["total"], 1);
    assert_eq!(
        scheduler::task_summary(&store, "source:manual").unwrap()["total"],
        1
    );
    assert_eq!(
        scheduler::task_summary(&store, "source:build").unwrap()["total"],
        0
    );
    c.execute("UPDATE job_cases SET fp='v2',revision=2", [])
        .unwrap();
    c.execute("UPDATE jobs SET status='complete'", []).unwrap();
    check(&c);
    assert_eq!(
        scheduler::task_summary(&store, "state:complete").unwrap()["total"],
        1
    );
    c.execute("DELETE FROM meta WHERE key='task-read-model-links-v4'", [])
        .unwrap();
    let reopened = Store::open(d.path()).unwrap();
    check(&c);
    assert_eq!(
        scheduler::task_summary(&reopened, "state:complete").unwrap()["total"],
        1
    );
    c.execute("DELETE FROM jobs", []).unwrap();
    check(&c);
    assert_eq!(
        scheduler::task_summary(&store, "state:awaiting-target").unwrap()["total"],
        1
    );
    c.execute("DELETE FROM cases", []).unwrap();
    check(&c);
    assert_eq!(scheduler::task_summary(&store, "").unwrap()["total"], 0);
}

#[test]
fn shared_observation_projects_each_case_and_respects_the_required_round() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut c = store.connect().unwrap();
    c.execute_batch("INSERT INTO cases VALUES('a','case-a',1,'geolocation','a','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,1);
        INSERT INTO cases VALUES('b','case-b',1,'geolocation','b','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,2);
        INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created) VALUES('shared','a','observation-only','traceroute','1.1.1.1','any','{\"logical_job\":1,\"scheduler\":2,\"observation_schema\":4}','pending',0,0);
        INSERT INTO job_cases VALUES('shared','a','case-a',1,1),('shared','b','case-b',1,1);").unwrap();
    assert_eq!(scheduler::task_summary(&store, "").unwrap()["total"], 2);
    assert_eq!(
        scheduler::task_summary(&store, "state:waiting-capability").unwrap()["total"],
        2,
        "one pending observation must appear under both linked case fingerprints"
    );
    let page = scheduler::task_items(&store, 0, 30, "").unwrap();
    assert_eq!(page["items"].as_array().unwrap().len(), 2);
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["state"] == "waiting-capability")
    );
    c.execute("UPDATE jobs SET status='complete' WHERE id='shared'", [])
        .unwrap();
    assert_eq!(
        scheduler::task_summary(&store, "state:complete").unwrap()["total"],
        2
    );
    c.execute(
        "UPDATE job_cases SET required_round_seq=2 WHERE case_key='b'",
        [],
    )
    .unwrap();
    let totals: (i64, i64) = c
        .query_row(
            "SELECT pending,completed FROM task_job_totals WHERE case_key='b'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        totals,
        (1, 0),
        "an earlier round is not fresh evidence for a new request"
    );
    assert_eq!(
        scheduler::task_summary(&store, "state:complete").unwrap()["total"],
        1
    );
    {
        let tx = c.transaction().unwrap();
        tx.execute("UPDATE jobs SET round_seq=2,status='leased'", [])
            .unwrap();
        assert_eq!(
            tx.query_row::<i64, _, _>("SELECT sum(running) FROM task_job_totals", [], |r| r.get(0))
                .unwrap(),
            2
        );
        tx.rollback().unwrap();
    }
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT sum(running) FROM task_job_totals", [], |r| r.get(0))
            .unwrap(),
        0
    );
    c.execute("UPDATE jobs SET round_seq=2 WHERE id='shared'", [])
        .unwrap();
    assert_eq!(
        scheduler::task_summary(&store, "state:complete").unwrap()["total"],
        2
    );
    c.execute(
        "UPDATE cases SET payload='{\"targets\":[]}' WHERE key='a'",
        [],
    )
    .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT count(*) FROM task_job_totals WHERE case_key='a'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    c.execute("DELETE FROM job_cases WHERE case_key='b'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM task_job_totals", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn projection_updates_once_and_unchanged_source_and_heartbeats_do_not_write_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let c = store.connect().unwrap();
    c.execute_batch("INSERT INTO cases VALUES('a','case-fp',1,'geolocation','a','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,0);
        INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created) VALUES('j','a','observation-fp','traceroute','1.1.1.1','any','{\"scheduler\":2,\"logical_job\":1,\"observation_schema\":4}','pending',0,0);
        INSERT INTO job_cases VALUES('j','a','case-fp',1,1);
        CREATE TABLE projection_writes(name TEXT);").unwrap();
    for (table, name) in [
        ("case_metadata", "metadata"),
        ("measurement_plans", "plans"),
        ("task_defaults", "defaults"),
        ("task_job_totals", "totals"),
    ] {
        for action in ["INSERT", "UPDATE", "DELETE"] {
            c.execute_batch(&format!("CREATE TRIGGER audit_{table}_{action} AFTER {action} ON {table} BEGIN INSERT INTO projection_writes VALUES('{name}');END;")).unwrap();
        }
    }
    c.execute_batch(
        "UPDATE cases SET reason=reason,payload=payload,updated=updated+1;
        UPDATE cases SET payload=json_set(payload,'$.advisory','unchanged question');
        UPDATE jobs SET lease_until=12345;",
    )
    .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM projection_writes", [], |r| r.get(0))
            .unwrap(),
        0
    );
    c.execute("UPDATE jobs SET status='leased'", []).unwrap();
    let changed: Vec<(String, i64)> = c
        .prepare("SELECT name,count(*) FROM projection_writes GROUP BY name ORDER BY name")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(changed, vec![("defaults".into(), 1), ("totals".into(), 1)]);
    c.execute("DELETE FROM projection_writes", []).unwrap();
    c.execute("UPDATE cases SET reason='updated source explanation'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<String, _, _>(
            "SELECT group_concat(name) FROM projection_writes",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        "metadata"
    );
    c.execute("DELETE FROM projection_writes", []).unwrap();
    drop(Store::open(dir.path()).unwrap());
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM projection_writes", [], |r| r.get(0))
            .unwrap(),
        0,
        "opening an initialized store must not backfill projections again"
    );
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND (name LIKE 'task_measurement_plans_%' OR name LIKE 'task_case_metadata_%' OR name LIKE 'task_task_job_totals_%' OR name='case_metadata_update_v1')", [], |r|r.get(0)).unwrap(),0);
}

#[test]
fn legacy_remote_visibility_is_preserved_until_recovery_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let c = store.connect().unwrap();
    c.execute_batch("INSERT INTO cases VALUES('a','case-fp',1,'geolocation','a','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,0);
        INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created) VALUES('legacy','a','old-receipt-fp','traceroute','1.1.1.1','us','{\"scheduler\":2,\"legacy_alias\":1}','unknown',0,0);
        INSERT INTO job_cases VALUES('legacy','a','case-fp',1,1);").unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM task_job_totals", [], |r| r.get(0))
            .unwrap(),
        0
    );
    c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES('legacy','fixture','remote','{}',0)", []).unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT failed FROM task_job_totals WHERE case_key='a'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    c.execute("UPDATE jobs SET status='complete' WHERE id='legacy'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT completed FROM task_job_totals WHERE case_key='a'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    c.execute("DELETE FROM gp_remote WHERE job_id='legacy'", [])
        .unwrap();
    assert_eq!(
        c.query_row::<i64, _, _>("SELECT count(*) FROM task_job_totals", [], |r| r.get(0))
            .unwrap(),
        0
    );
}

#[test]
fn linked_projection_migration_repairs_legacy_rows_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let c = store.connect().unwrap();
    c.execute_batch("INSERT INTO cases VALUES('a','case-fp',1,'geolocation','current subject','fixture','{\"targets\":[\"1.1.1.1\"]}','needs-active',1,7);
        INSERT INTO jobs(id,case_key,fp,kind,target,region,profile,status,not_before,created) VALUES('j','a','observation-fp','traceroute','1.1.1.1','any','{\"scheduler\":2,\"logical_job\":1,\"observation_schema\":4}','complete',0,0);
        INSERT INTO job_cases VALUES('j','a','case-fp',1,1);").unwrap();
    let triggers: Vec<String> = c.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND (name LIKE 'case_projection_%_v4' OR name LIKE 'task_%_v4')").unwrap().query_map([],|r|r.get(0)).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    for name in triggers {
        c.execute_batch(&format!("DROP TRIGGER {name};")).unwrap();
    }
    c.execute_batch("DELETE FROM meta WHERE key='task-read-model-links-v4';
        UPDATE case_metadata SET fp='stale',subject='old subject';
        UPDATE measurement_plans SET fp='stale';
        DELETE FROM task_job_totals;
        CREATE TRIGGER case_metadata_update_v1 AFTER UPDATE ON cases BEGIN UPDATE case_metadata SET subject='obsolete trigger' WHERE key=NEW.key;END;").unwrap();
    let reopened = Store::open(dir.path()).unwrap();
    assert_eq!(
        c.query_row::<String, _, _>("SELECT subject FROM case_metadata WHERE key='a'", [], |r| r
            .get(0))
            .unwrap(),
        "current subject"
    );
    assert_eq!(
        scheduler::task_summary(&reopened, "state:complete").unwrap()["total"],
        1
    );
    assert_eq!(
        c.query_row::<i64, _, _>(
            "SELECT n FROM task_default_counts WHERE source='build' AND state='complete'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        1
    );
    assert_eq!(c.query_row::<i64,_,_>("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='case_metadata_update_v1'", [], |r|r.get(0)).unwrap(),0);
}

#[test]
fn compact_build_polling_retains_progress_and_counters_without_losing_details() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let id = store.start_build().unwrap();
    let summary = json!({"targets":376,"rules":1200000,"cn_domain_rules":100000,"domain_quarantines":7,"geography":{"regions":{"us":50},"active_required_groups":123,"raw_evidence":"large detail"},"incremental":{"new":2,"changed":3,"reused":4},"counts":{"region/cn":120000},"validation":{"details":"retained"}});
    store
        .commit_build(&id, "fixture-release", &summary, &[], &[])
        .unwrap();
    let full = store.builds().unwrap();
    let compact = store.build_summaries().unwrap();
    assert_eq!(compact[0]["id"], full[0]["id"]);
    assert_eq!(compact[0]["progress"], full[0]["progress"]);
    assert_eq!(compact[0]["summary"]["rules"], 1200000);
    assert_eq!(
        compact[0]["summary"]["geography"],
        json!({"regions":{"us":50},"active_required_groups":123})
    );
    assert_eq!(
        compact[0]["summary"]["incremental"],
        full[0]["summary"]["incremental"]
    );
    assert!(compact[0]["summary"].get("validation").is_none());
    assert_eq!(
        store.builds().unwrap()[0]["summary"]["validation"],
        summary["validation"]
    );
}
