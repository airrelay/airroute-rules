//! Compact, transactional console projections. Cases, links and jobs own their state.
use crate::store::Store;
use anyhow::Result;
pub(crate) const DEFAULT_STATE: &str = "CASE WHEN c.active=0 THEN 'obsolete' WHEN c.status='decided' THEN 'decided' WHEN coalesce(t.running,0)>0 THEN 'running' WHEN coalesce(t.pending,0)>0 THEN CASE WHEN t.completed>0 THEN 'partial' ELSE 'awaiting-target' END WHEN coalesce(t.failed,0)>0 THEN CASE WHEN t.completed>0 THEN 'partial' ELSE 'failed' END WHEN coalesce(t.completed,0)>0 THEN 'complete' WHEN c.kind='domain-policy' OR c.status='needs-review' THEN 'needs-review' ELSE 'awaiting-target' END";
const PLAN_SOURCE: &str = "CASE WHEN c.kind IN ('domain-observation','manual-ip') THEN 'manual' WHEN c.kind='target-discovery' THEN 'discovery' ELSE 'build' END";
const VISIBLE: &str = "j.status<>'obsolete' AND c.active=1 AND c.status<>'decided' AND (coalesce(json_extract(j.profile,'$.legacy_alias'),0)<>1 OR json_extract(j.profile,'$.logical_job')=1 OR j.status='leased' OR EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id)) AND EXISTS(SELECT 1 FROM json_each(c.payload,'$.targets') target WHERE target.value=j.target)";
const LINKS: &str = "job_cases l JOIN jobs j ON j.id=l.job_id JOIN cases c ON c.key=l.case_key AND c.fp=l.fp AND c.revision=l.revision";
fn totals(scope: &str) -> String {
    format!("DELETE FROM task_job_totals WHERE case_key IN ({scope}) AND NOT EXISTS(SELECT 1 FROM {LINKS} WHERE l.case_key=task_job_totals.case_key AND l.fp=task_job_totals.fp AND l.revision=task_job_totals.revision AND {VISIBLE});
        INSERT INTO task_job_totals SELECT l.case_key,l.fp,l.revision,count(*),sum(j.status='pending' OR (j.status='complete' AND j.round_seq<l.required_round_seq)),sum(j.status='leased'),sum(j.status='unknown'),sum(j.status='complete' AND j.round_seq>=l.required_round_seq) FROM {LINKS} WHERE l.case_key IN ({scope}) AND {VISIBLE} GROUP BY l.case_key,l.fp,l.revision
        ON CONFLICT(case_key,fp,revision) DO UPDATE SET total=excluded.total,pending=excluded.pending,running=excluded.running,failed=excluded.failed,completed=excluded.completed
        WHERE task_job_totals.total IS NOT excluded.total OR task_job_totals.pending IS NOT excluded.pending OR task_job_totals.running IS NOT excluded.running OR task_job_totals.failed IS NOT excluded.failed OR task_job_totals.completed IS NOT excluded.completed;")
}
fn defaults(scope: &str) -> String {
    format!("DELETE FROM task_defaults WHERE case_key IN ({scope}) AND NOT EXISTS(SELECT 1 FROM cases c WHERE c.key=task_defaults.case_key);
        INSERT INTO task_defaults SELECT c.key,c.fp,c.revision,p.source,{DEFAULT_STATE} FROM cases c JOIN measurement_plans p ON p.case_key=c.key AND p.fp=c.fp LEFT JOIN task_job_totals t ON t.case_key=c.key AND t.fp=c.fp AND t.revision=c.revision WHERE c.key IN ({scope})
        ON CONFLICT(case_key) DO UPDATE SET fp=excluded.fp,revision=excluded.revision,source=excluded.source,state=excluded.state
        WHERE task_defaults.fp IS NOT excluded.fp OR task_defaults.revision IS NOT excluded.revision OR task_defaults.source IS NOT excluded.source OR task_defaults.state IS NOT excluded.state;")
}
fn case_projection(scope: &str) -> String {
    format!("INSERT INTO case_metadata SELECT c.key,c.fp,c.revision,c.kind,c.subject,c.reason,c.status,c.active FROM cases c WHERE c.key IN ({scope})
        ON CONFLICT(key) DO UPDATE SET fp=excluded.fp,revision=excluded.revision,kind=excluded.kind,subject=excluded.subject,reason=excluded.reason,status=excluded.status,active=excluded.active
        WHERE case_metadata.fp IS NOT excluded.fp OR case_metadata.revision IS NOT excluded.revision OR case_metadata.kind IS NOT excluded.kind OR case_metadata.subject IS NOT excluded.subject OR case_metadata.reason IS NOT excluded.reason OR case_metadata.status IS NOT excluded.status OR case_metadata.active IS NOT excluded.active;
        INSERT INTO measurement_plans SELECT c.key,c.fp,{PLAN_SOURCE},c.updated FROM cases c WHERE c.key IN ({scope})
        ON CONFLICT(case_key) DO UPDATE SET fp=excluded.fp,source=excluded.source WHERE measurement_plans.fp IS NOT excluded.fp OR measurement_plans.source IS NOT excluded.source;
        {}{}",totals(scope),defaults(scope))
}
pub(crate) fn migrate(store: &Store) -> Result<()> {
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS task_defaults(case_key TEXT PRIMARY KEY,fp TEXT NOT NULL,revision INTEGER NOT NULL,source TEXT NOT NULL,state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS task_default_counts(source TEXT NOT NULL,state TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(source,state));
        CREATE TABLE IF NOT EXISTS case_group_counts(kind TEXT NOT NULL,status TEXT NOT NULL,n INTEGER NOT NULL,PRIMARY KEY(kind,status));
        CREATE TABLE IF NOT EXISTS task_job_totals(case_key TEXT NOT NULL,fp TEXT NOT NULL,revision INTEGER NOT NULL,total INTEGER NOT NULL,pending INTEGER NOT NULL,running INTEGER NOT NULL,failed INTEGER NOT NULL,completed INTEGER NOT NULL,PRIMARY KEY(case_key,fp,revision));
        CREATE INDEX IF NOT EXISTS task_job_pending ON task_job_totals(case_key,fp,revision) WHERE pending>0;")?;
    for name in [
        "case_metadata_insert",
        "case_metadata_update",
        "case_metadata_delete",
        "case_metadata_insert_v1",
        "case_metadata_update_v1",
        "case_metadata_delete_v1",
        "task_jobs_insert_v1",
        "task_jobs_update_v1",
        "task_jobs_delete_v1",
        "task_jobs_insert_v3",
        "task_jobs_update_v3",
        "task_jobs_delete_v3",
        "task_remote_insert_v3",
        "task_remote_delete_v3",
        "task_remote_move_v3",
    ] {
        tx.execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))?;
    }
    for table in ["measurement_plans", "case_metadata", "task_job_totals"] {
        for action in ["insert", "update", "delete"] {
            tx.execute_batch(&format!("DROP TRIGGER IF EXISTS task_{table}_{action}_v1;"))?;
        }
    }
    let initialized: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM meta WHERE key='task-read-model-links-v4')",
        [],
        |r| r.get(0),
    )?;
    if !initialized {
        // Rebuild once during migration, before installing leaf counter triggers.
        for name in [
            "task_count_insert_v1",
            "task_count_delete_v1",
            "task_count_update_v1",
            "case_count_insert_v1",
            "case_count_delete_v1",
            "case_count_update_v1",
        ] {
            tx.execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))?;
        }
        tx.execute_batch("DELETE FROM task_defaults;DELETE FROM task_default_counts;DELETE FROM task_job_totals;DELETE FROM case_group_counts;DELETE FROM case_metadata;
            DELETE FROM measurement_plans WHERE NOT EXISTS(SELECT 1 FROM cases c WHERE c.key=measurement_plans.case_key);")?;
        tx.execute_batch(&case_projection("SELECT key FROM cases"))?;
        tx.execute_batch("INSERT INTO case_group_counts SELECT kind,status,count(*) FROM case_metadata WHERE active=1 GROUP BY kind,status;
            INSERT INTO task_default_counts SELECT source,state,count(*) FROM task_defaults GROUP BY source,state;
            INSERT INTO meta VALUES('task-read-model-links-v4','complete');")?;
    }
    tx.execute_batch("CREATE TRIGGER IF NOT EXISTS task_count_insert_v1 AFTER INSERT ON task_defaults BEGIN
        INSERT INTO task_default_counts VALUES(NEW.source,NEW.state,1) ON CONFLICT(source,state) DO UPDATE SET n=n+1;END;
        CREATE TRIGGER IF NOT EXISTS task_count_delete_v1 AFTER DELETE ON task_defaults BEGIN
        UPDATE task_default_counts SET n=n-1 WHERE source=OLD.source AND state=OLD.state;END;
        CREATE TRIGGER IF NOT EXISTS task_count_update_v1 AFTER UPDATE ON task_defaults WHEN OLD.source IS NOT NEW.source OR OLD.state IS NOT NEW.state BEGIN
        UPDATE task_default_counts SET n=n-1 WHERE source=OLD.source AND state=OLD.state;
        INSERT INTO task_default_counts VALUES(NEW.source,NEW.state,1) ON CONFLICT(source,state) DO UPDATE SET n=n+1;END;")?;
    tx.execute_batch("CREATE TRIGGER IF NOT EXISTS case_count_insert_v1 AFTER INSERT ON case_metadata WHEN NEW.active=1 BEGIN
        INSERT INTO case_group_counts VALUES(NEW.kind,NEW.status,1) ON CONFLICT(kind,status) DO UPDATE SET n=n+1;END;
        CREATE TRIGGER IF NOT EXISTS case_count_delete_v1 AFTER DELETE ON case_metadata WHEN OLD.active=1 BEGIN
        UPDATE case_group_counts SET n=n-1 WHERE kind=OLD.kind AND status=OLD.status;END;
        CREATE TRIGGER IF NOT EXISTS case_count_update_v1 AFTER UPDATE ON case_metadata WHEN OLD.active IS NOT NEW.active OR OLD.kind IS NOT NEW.kind OR OLD.status IS NOT NEW.status BEGIN
        UPDATE case_group_counts SET n=n-1 WHERE OLD.active=1 AND kind=OLD.kind AND status=OLD.status;
        INSERT INTO case_group_counts SELECT NEW.kind,NEW.status,1 WHERE NEW.active=1 ON CONFLICT(kind,status) DO UPDATE SET n=n+1;END;")?;

    let case_sync = case_projection("SELECT NEW.key");
    let remove_old = "DELETE FROM task_defaults WHERE case_key=OLD.key AND OLD.key<>NEW.key;DELETE FROM measurement_plans WHERE case_key=OLD.key AND OLD.key<>NEW.key;DELETE FROM task_job_totals WHERE case_key=OLD.key AND OLD.key<>NEW.key;DELETE FROM case_metadata WHERE key=OLD.key AND OLD.key<>NEW.key;";
    tx.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS case_projection_insert_v4 AFTER INSERT ON cases BEGIN {case_sync} END;
        CREATE TRIGGER IF NOT EXISTS case_projection_update_v4 AFTER UPDATE ON cases WHEN OLD.key IS NOT NEW.key OR OLD.fp IS NOT NEW.fp OR OLD.revision IS NOT NEW.revision OR OLD.kind IS NOT NEW.kind OR OLD.subject IS NOT NEW.subject OR OLD.reason IS NOT NEW.reason OR OLD.status IS NOT NEW.status OR OLD.active IS NOT NEW.active OR OLD.payload IS NOT NEW.payload BEGIN {remove_old}{case_sync} END;
        CREATE TRIGGER IF NOT EXISTS case_projection_delete_v4 AFTER DELETE ON cases BEGIN DELETE FROM task_defaults WHERE case_key=OLD.key;DELETE FROM measurement_plans WHERE case_key=OLD.key;DELETE FROM task_job_totals WHERE case_key=OLD.key;DELETE FROM case_metadata WHERE key=OLD.key;END;"))?;
    let job_scope = "SELECT case_key FROM job_cases WHERE job_id=NEW.id";
    let job_sync = format!("{}{}", totals(job_scope), defaults(job_scope));
    let removed_scope = "SELECT case_key FROM job_cases WHERE job_id=OLD.id";
    let removed_sync = format!("{}{}", totals(removed_scope), defaults(removed_scope));
    tx.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS task_jobs_insert_v4 AFTER INSERT ON jobs BEGIN {job_sync} END;
        CREATE TRIGGER IF NOT EXISTS task_jobs_update_v4 AFTER UPDATE ON jobs WHEN OLD.status IS NOT NEW.status OR OLD.round_seq IS NOT NEW.round_seq OR OLD.target IS NOT NEW.target OR OLD.profile IS NOT NEW.profile BEGIN {job_sync} END;
        CREATE TRIGGER IF NOT EXISTS task_jobs_delete_v4 AFTER DELETE ON jobs BEGIN {removed_sync} END;"))?;
    let link_sync = format!(
        "{}{}",
        totals("SELECT NEW.case_key"),
        defaults("SELECT NEW.case_key")
    );
    let old_sync = format!(
        "{}{}",
        totals("SELECT OLD.case_key"),
        defaults("SELECT OLD.case_key")
    );
    let moved_scope = "SELECT OLD.case_key UNION SELECT NEW.case_key";
    let moved_sync = format!("{}{}", totals(moved_scope), defaults(moved_scope));
    tx.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS task_links_insert_v4 AFTER INSERT ON job_cases BEGIN {link_sync} END;
        CREATE TRIGGER IF NOT EXISTS task_links_update_v4 AFTER UPDATE ON job_cases WHEN OLD.job_id IS NOT NEW.job_id OR OLD.case_key IS NOT NEW.case_key OR OLD.fp IS NOT NEW.fp OR OLD.revision IS NOT NEW.revision OR OLD.required_round_seq IS NOT NEW.required_round_seq BEGIN {moved_sync} END;
        CREATE TRIGGER IF NOT EXISTS task_links_delete_v4 AFTER DELETE ON job_cases BEGIN {old_sync} END;"))?;
    // Only historical physical aliases depend on a remote intent for visibility.
    let alias = |prefix: &str| {
        format!(
            "EXISTS(SELECT 1 FROM jobs j WHERE j.id={prefix}.job_id AND json_extract(j.profile,'$.legacy_alias')=1 AND coalesce(json_extract(j.profile,'$.logical_job'),0)<>1 AND j.status<>'leased')"
        )
    };
    let remote_scope = "SELECT case_key FROM job_cases WHERE job_id=NEW.job_id";
    let remote_sync = format!("{}{}", totals(remote_scope), defaults(remote_scope));
    let remote_old_scope = "SELECT case_key FROM job_cases WHERE job_id=OLD.job_id";
    let remote_old_sync = format!("{}{}", totals(remote_old_scope), defaults(remote_old_scope));
    tx.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS task_remote_insert_v4 AFTER INSERT ON gp_remote WHEN {} BEGIN {remote_sync} END;
        CREATE TRIGGER IF NOT EXISTS task_remote_delete_v4 AFTER DELETE ON gp_remote WHEN {} BEGIN {remote_old_sync} END;",alias("NEW"),alias("OLD")))?;
    tx.commit()?;
    Ok(())
}
