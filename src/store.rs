use crate::{fingerprint, hash, now};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseInput {
    pub key: String,
    pub fingerprint: String,
    pub kind: String,
    pub subject: String,
    pub reason: String,
    pub payload: Value,
}
#[derive(Clone)]
pub struct Store {
    pub path: PathBuf,
    pub wake: std::sync::Arc<tokio::sync::Notify>,
    reader: Arc<Mutex<Option<ReadConnection>>>,
}
struct ReadConnection {
    path: PathBuf,
    connection: Connection,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct ExecutorStats {
    pub completed_tasks: i64,
    pub running_tasks: i64,
    pub last_completed_at: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub case_key: String,
    pub fingerprint: String,
    pub kind: String,
    pub target: String,
    pub region: String,
    pub token: String,
    pub until: i64,
    pub profile: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: String,
    pub job_id: String,
    pub fingerprint: String,
    pub lease_token: String,
    pub observed_at: i64,
    pub outcome: String,
    pub evidence: Value,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub region: String,
    pub asn: u32,
    pub capabilities: Vec<String>,
}
impl Store {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let store = Self {
            path: dir.join("control.sqlite3"),
            wake: shared_wake(&dir.join("control.sqlite3")),
            reader: Arc::new(Mutex::new(None)),
        };
        let conn = store.connect()?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cases(key TEXT PRIMARY KEY,fp TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,reason TEXT NOT NULL,payload TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,updated INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS cases_active_kind ON cases(active,kind,status);
        CREATE TABLE IF NOT EXISTS case_metadata(key TEXT PRIMARY KEY,fp TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,subject TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL,active INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS case_metadata_summary ON case_metadata(active,kind,status);
        CREATE INDEX IF NOT EXISTS case_metadata_status ON case_metadata(active,status);
        CREATE INDEX IF NOT EXISTS cases_recent ON cases(active,updated DESC,key) WHERE kind<>'target-discovery';
        CREATE INDEX IF NOT EXISTS cases_kind_recent ON cases(kind,updated DESC,key) WHERE active=1 AND kind<>'target-discovery';
        CREATE INDEX IF NOT EXISTS cases_status_recent ON cases(status,updated DESC,key) WHERE active=1 AND kind<>'target-discovery';
        DROP TRIGGER IF EXISTS case_metadata_insert;
        DROP TRIGGER IF EXISTS case_metadata_update;
        DROP TRIGGER IF EXISTS case_metadata_delete;
        CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY,case_key TEXT NOT NULL,fp TEXT NOT NULL,action TEXT NOT NULL,reason TEXT NOT NULL,created INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS decision_case ON decisions(case_key,fp,id);
        CREATE TABLE IF NOT EXISTS facts(collection TEXT NOT NULL,kind TEXT NOT NULL,value TEXT NOT NULL,fp TEXT NOT NULL,PRIMARY KEY(collection,kind,value));
        CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,region TEXT NOT NULL,asn INTEGER NOT NULL,capabilities TEXT NOT NULL,disabled INTEGER NOT NULL DEFAULT 0,last_seen INTEGER,name TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,case_key TEXT NOT NULL,fp TEXT NOT NULL,kind TEXT NOT NULL,target TEXT NOT NULL,region TEXT NOT NULL,profile TEXT NOT NULL,status TEXT NOT NULL,not_before INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,lease_node TEXT,lease_token TEXT,lease_until INTEGER,result_id TEXT,created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS job_schedule ON jobs(status,not_before,region);
        CREATE INDEX IF NOT EXISTS job_scope ON jobs(case_key,fp,target,region);
        CREATE TABLE IF NOT EXISTS results(id TEXT PRIMARY KEY,job_id TEXT NOT NULL,node TEXT NOT NULL,fp TEXT NOT NULL,observed INTEGER NOT NULL,outcome TEXT NOT NULL,evidence TEXT NOT NULL,accepted INTEGER NOT NULL,received INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS lease_history(job_id TEXT NOT NULL,token_hash TEXT NOT NULL,node TEXT NOT NULL,fp TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(job_id,token_hash));
        CREATE INDEX IF NOT EXISTS result_job ON results(job_id);
        CREATE INDEX IF NOT EXISTS result_completed_job ON results(job_id) WHERE accepted=1 AND outcome='ok';
        CREATE TABLE IF NOT EXISTS builds(id TEXT PRIMARY KEY,status TEXT NOT NULL,started INTEGER NOT NULL,finished INTEGER,release TEXT,summary TEXT,error TEXT);
        CREATE INDEX IF NOT EXISTS build_completed_at ON builds(status,finished DESC);
        CREATE TABLE IF NOT EXISTS build_progress(build_id TEXT PRIMARY KEY REFERENCES builds(id),snapshot TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS gp_account_usage(account TEXT NOT NULL,bucket INTEGER NOT NULL,used INTEGER NOT NULL,blocked_until INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(account,bucket));
        CREATE TABLE IF NOT EXISTS gp_unavailable(executor TEXT NOT NULL,family INTEGER NOT NULL,until INTEGER NOT NULL,PRIMARY KEY(executor,family));
        CREATE TABLE IF NOT EXISTS gp_test_usage(account TEXT NOT NULL,measurement TEXT NOT NULL,created INTEGER NOT NULL,tests INTEGER NOT NULL,PRIMARY KEY(account,measurement));
        CREATE INDEX IF NOT EXISTS gp_test_usage_recent ON gp_test_usage(account,created);
        CREATE TABLE IF NOT EXISTS gp_remote(job_id TEXT PRIMARY KEY,account TEXT NOT NULL,remote_id TEXT NOT NULL,lease TEXT NOT NULL,next_poll INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS observation_cache(key TEXT PRIMARY KEY,valid_until INTEGER NOT NULL,result TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS work_requests(case_key TEXT NOT NULL,fp TEXT NOT NULL,revision INTEGER NOT NULL,target TEXT NOT NULL,kind TEXT NOT NULL,manual INTEGER NOT NULL,regions TEXT NOT NULL,epoch TEXT,PRIMARY KEY(case_key,fp,target));
        CREATE TABLE IF NOT EXISTS discovery_domains(host TEXT PRIMARY KEY,bucket INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS discovery_domains_bucket ON discovery_domains(bucket,host);
        CREATE TABLE IF NOT EXISTS measurement_plans(case_key TEXT PRIMARY KEY,fp TEXT NOT NULL,source TEXT NOT NULL,created INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS measurement_plan_recent ON measurement_plans(created DESC,case_key);
        CREATE INDEX IF NOT EXISTS measurement_plan_source_recent ON measurement_plans(source,created DESC,case_key);
        CREATE TABLE IF NOT EXISTS case_ranges(case_key TEXT NOT NULL,fp TEXT NOT NULL,family INTEGER NOT NULL,start TEXT NOT NULL,end TEXT NOT NULL,PRIMARY KEY(case_key,fp,start,end));
        CREATE INDEX IF NOT EXISTS case_range_lookup ON case_ranges(family,start,end);
        CREATE TABLE IF NOT EXISTS responsive_targets(ip TEXT PRIMARY KEY,family INTEGER NOT NULL,address TEXT NOT NULL,last_seen INTEGER NOT NULL,result_id TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS responsive_target_address ON responsive_targets(family,address,last_seen);
        CREATE TABLE IF NOT EXISTS target_observations(ip TEXT NOT NULL,source TEXT NOT NULL,kind TEXT NOT NULL,family INTEGER NOT NULL,address TEXT NOT NULL,observed INTEGER NOT NULL,valid_until INTEGER NOT NULL,PRIMARY KEY(ip,source));
        CREATE INDEX IF NOT EXISTS target_observation_address ON target_observations(family,address,valid_until);
        CREATE INDEX IF NOT EXISTS target_observation_status ON target_observations(kind,ip,valid_until);
        CREATE INDEX IF NOT EXISTS target_observation_expiry ON target_observations(valid_until);
        CREATE TABLE IF NOT EXISTS discovery_checks(kind TEXT NOT NULL,key TEXT NOT NULL,checked INTEGER NOT NULL,next_check INTEGER NOT NULL,error TEXT,PRIMARY KEY(kind,key));
        CREATE TABLE IF NOT EXISTS discovery_receipts(result_id TEXT PRIMARY KEY);
        CREATE INDEX IF NOT EXISTS result_discovery ON results(accepted,observed);
        CREATE TABLE IF NOT EXISTS executor_counters(executor TEXT PRIMARY KEY,completed_tasks INTEGER NOT NULL,last_completed_at INTEGER);
        CREATE TABLE IF NOT EXISTS gp_accounts(id TEXT PRIMARY KEY,config TEXT NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
        PRAGMA user_version=2;")?;
        conn.execute("INSERT OR REPLACE INTO case_metadata SELECT key,fp,revision,kind,subject,reason,status,active FROM cases WHERE NOT EXISTS(SELECT 1 FROM meta WHERE key='case-metadata-v1')",[])?;
        conn.execute(
            "INSERT OR IGNORE INTO meta VALUES('case-metadata-v1','complete')",
            [],
        )?;
        let columns = conn
            .prepare("PRAGMA table_info(decisions)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !columns.iter().any(|c| c == "revision") {
            conn.execute(
                "ALTER TABLE decisions ADD COLUMN revision INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        let columns = conn
            .prepare("PRAGMA table_info(nodes)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !columns.iter().any(|c| c == "name") {
            conn.execute(
                "ALTER TABLE nodes ADD COLUMN name TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        let columns = conn
            .prepare("PRAGMA table_info(gp_remote)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !columns.iter().any(|c| c == "account_snapshot") {
            conn.execute("ALTER TABLE gp_remote ADD COLUMN account_snapshot TEXT", [])?;
        }
        let columns = conn
            .prepare("PRAGMA table_info(nodes)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if !columns.iter().any(|c| c == "connected") {
            conn.execute(
                "ALTER TABLE nodes ADD COLUMN connected INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !columns.iter().any(|c| c == "session_id") {
            conn.execute("ALTER TABLE nodes ADD COLUMN session_id TEXT", [])?;
        }
        if !columns.iter().any(|c| c == "concurrency_limit") {
            conn.execute(
                "ALTER TABLE nodes ADD COLUMN concurrency_limit INTEGER NOT NULL DEFAULT 10",
                [],
            )?;
        }
        let columns = conn
            .prepare("PRAGMA table_info(nodes)")?
            .query_map([], |r| r.get::<_, String>(1))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for column in [
            "ipv4_supported",
            "ipv6_supported",
            "network_checked",
            "worker_capacity",
        ] {
            if !columns.iter().any(|v| v == column) {
                conn.execute(
                    &format!("ALTER TABLE nodes ADD COLUMN {column} INTEGER"),
                    [],
                )?;
            }
        }
        conn.execute(
            "UPDATE nodes SET concurrency_limit=10 WHERE concurrency_limit IS NULL",
            [],
        )?;
        // Backfill/reconcile once on open, never scan historical receipts on UI polling.
        // MAX preserves lifetime counters if old receipts were archived externally.
        if conn.query_row::<bool, _, _>(
            "SELECT NOT EXISTS(SELECT 1 FROM meta WHERE key='executor-counters-backfilled-v1')",
            [],
            |r| r.get(0),
        )? {
            let tx = conn.unchecked_transaction()?;
            tx.execute("INSERT INTO executor_counters SELECT node,count(DISTINCT job_id),max(received) FROM results WHERE accepted=1 AND outcome='ok' GROUP BY node ON CONFLICT(executor) DO UPDATE SET completed_tasks=max(executor_counters.completed_tasks,excluded.completed_tasks),last_completed_at=max(executor_counters.last_completed_at,excluded.last_completed_at)",[])?;
            tx.execute(
                "INSERT OR IGNORE INTO meta VALUES('executor-counters-backfilled-v1','complete')",
                [],
            )?;
            tx.commit()?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&store.path, std::fs::Permissions::from_mode(0o600))?;
        }
        crate::build_delta::migrate(&store)?;
        crate::work::migrate(&store)?;
        crate::task_read_model::migrate(&store)?;
        // Read-only audit lists use the original jobs/attempt history. These
        // covering/order indexes avoid copying that history into another model.
        conn.execute_batch("CREATE INDEX IF NOT EXISTS audit_job_recent ON jobs(created DESC,id);
            CREATE INDEX IF NOT EXISTS audit_job_state_recent ON jobs(status,created DESC,id);
            CREATE INDEX IF NOT EXISTS audit_job_profile_fallback ON jobs(id) WHERE coalesce(json_extract(profile,'$.purpose'),'')<>'discovery';
            CREATE INDEX IF NOT EXISTS audit_attempt_recent ON lease_history(created DESC,job_id,token_hash);
            CREATE INDEX IF NOT EXISTS audit_attempt_identity ON lease_history(job_id,attempt_seq,round_seq,node,fp);
            CREATE INDEX IF NOT EXISTS audit_result_recent ON results(received DESC,id,job_id,attempt_seq,round_seq,node,fp);
            CREATE INDEX IF NOT EXISTS audit_result_attempt ON results(job_id,attempt_seq,round_seq,node,fp,received,id);")?;
        Ok(store)
    }
    pub fn connect(&self) -> Result<Connection> {
        let c = Connection::open(&self.path)?;
        c.busy_timeout(std::time::Duration::from_secs(15))?;
        c.execute_batch("PRAGMA foreign_keys=ON;")?;
        Ok(c)
    }
    // Only the three short, owned-result SELECTs below use this connection.
    // Clones share one schema/statement cache; no query value or read transaction
    // survives a call, so independent writers remain immediately visible.
    fn read<T>(&self, query: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let mut cached = self
            .reader
            .lock()
            .map_err(|_| anyhow::anyhow!("short read connection lock poisoned"))?;
        if cached.as_ref().is_none_or(|r| r.path != self.path) {
            let connection = Connection::open_with_flags(
                &self.path,
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )?;
            connection.busy_timeout(std::time::Duration::from_secs(15))?;
            *cached = Some(ReadConnection {
                path: self.path.clone(),
                connection,
            });
        }
        query(
            &cached
                .as_ref()
                .expect("read connection initialized")
                .connection,
        )
    }
    pub fn meta(&self, key: &str) -> Result<Option<String>> {
        self.read(|c| {
            Ok(c.prepare_cached("SELECT value FROM meta WHERE key=?")?
                .query_row([key], |r| r.get(0))
                .optional()?)
        })
    }
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.connect()?.execute(
            "INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
    pub fn import_legacy(&self, root: &Path) -> Result<usize> {
        if self.meta("legacy-import")?.is_some() {
            return Ok(0);
        }
        let path = root.join("state/geography.jsonl");
        if !path.exists() {
            return Ok(0);
        }
        let mut lines = BufReader::new(std::fs::File::open(path)?).lines();
        let header: Value = serde_json::from_str(&lines.next().context("empty state")??)?;
        ensure!(
            header["schema"] == 1 && header["policy"] == "regions-anycast-passive-v1",
            "unknown legacy state"
        );
        let mut conn = self.connect()?;
        let tx = conn.transaction()?;
        let mut n = 0;
        for line in lines {
            let row: Value = serde_json::from_str(&line?)?;
            let key = row["key"].as_str().context("legacy key")?;
            let fp = row["fingerprint"].as_str().context("legacy fingerprint")?;
            ensure!(fp.len() == 64, "invalid legacy fingerprint");
            let active = row["status"] == "needs-active";
            let mut payload = header["task_defaults"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            if let Some(task) = row["task"].as_object() {
                payload.extend(task.clone())
            }
            let p = Value::Object(payload);
            let kind = p["kind"].as_str().unwrap_or("geolocation");
            tx.execute(
                "INSERT OR IGNORE INTO cases VALUES(?,?,?,?,?,?,?,?,?,?)",
                params![
                    key,
                    fp,
                    row["revision"].as_i64().unwrap_or(1),
                    kind,
                    p["bgp_prefix"].as_str().unwrap_or(""),
                    "legacy unresolved evidence candidate",
                    p.to_string(),
                    if active { "blocked-target" } else { "inactive" },
                    i64::from(active),
                    now()
                ],
            )?;
            n += 1;
        }
        tx.execute(
            "INSERT INTO meta VALUES('legacy-import',?)",
            [n.to_string()],
        )?;
        tx.commit()?;
        Ok(n)
    }
    /// Read-only legacy history. These rows never influence generation or scheduling.
    pub fn decisions(&self) -> Result<BTreeMap<String, (String, String)>> {
        let conn = self.connect()?;
        let mut stmt = conn.prepare("SELECT d.case_key,d.fp,d.action FROM decisions d JOIN cases c ON c.key=d.case_key AND c.fp=d.fp AND c.revision=d.revision AND c.active=1 ORDER BY d.id")?;
        let mut out = BTreeMap::new();
        for row in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })? {
            let (k, fp, a) = row?;
            out.insert(k, (fp, a));
        }
        Ok(out)
    }
    pub fn commit_build(
        &self,
        id: &str,
        release: &str,
        summary: &Value,
        cases: &[CaseInput],
        facts: &[(String, crate::rules::Rule, String)],
    ) -> Result<Value> {
        crate::build_delta::commit_compat(self, id, release, summary, cases, facts)
    }
    pub fn start_build(&self) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.connect()?.execute(
            "INSERT INTO builds(id,status,started) VALUES(?,'running',?)",
            params![id, now()],
        )?;
        Ok(id)
    }
    pub fn write_build_progress(
        &self,
        id: &str,
        snapshot: &crate::progress::Snapshot,
    ) -> Result<usize> {
        Ok(self.connect()?.execute("INSERT INTO build_progress(build_id,snapshot) SELECT id,? FROM builds WHERE id=? AND status='running' ON CONFLICT(build_id) DO UPDATE SET snapshot=excluded.snapshot",params![serde_json::to_string(snapshot)?,id])?)
    }
    pub fn fail_build(&self, id: &str, error: &str) -> Result<()> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE builds SET status='failed',finished=?,error=? WHERE id=? AND status='running'",
            params![now(), error, id],
        )?;
        if let Some(snapshot) = crate::progress::snapshot(self, id) {
            tx.execute("INSERT INTO build_progress(build_id,snapshot) VALUES(?,?) ON CONFLICT(build_id) DO UPDATE SET snapshot=excluded.snapshot", params![id, serde_json::to_string(&snapshot)?])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn register_node(&self, node: &Node, token: &str) -> Result<()> {
        self.register_named_node(node, token, None)
    }
    pub fn register_named_node(&self, node: &Node, token: &str, name: Option<&str>) -> Result<()> {
        ensure!(
            token.len() >= 24,
            "node token must contain at least 24 characters"
        );
        ensure!(
            !node.id.is_empty() && !node.region.is_empty(),
            "invalid node identity"
        );
        let name = name.map(str::trim);
        ensure!(
            name.is_none_or(|s| s.chars().count() <= 80 && !s.chars().any(char::is_control)),
            "node name must contain at most 80 printable characters"
        );
        self.connect()?.execute("INSERT INTO nodes(id,token_hash,region,asn,capabilities,name,concurrency_limit) VALUES(?,?,?,?,?,?,10) ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash,region=excluded.region,asn=excluded.asn,capabilities=excluded.capabilities,disabled=0,name=CASE WHEN ? IS NULL THEN nodes.name ELSE excluded.name END",params![node.id,hash(token),node.region,node.asn,serde_json::to_string(&node.capabilities)?,name.unwrap_or(""),name])?;
        Ok(())
    }
    pub fn authenticate_node(&self, id: &str, token: &str) -> Result<Node> {
        ensure!(
            !id.starts_with("globalping:"),
            "internal measurement holder cannot authenticate as a remote node"
        );
        let n: Option<(String, String, u32, String)> = self.read(|c| {
            Ok(c.prepare_cached(
                "SELECT token_hash,region,asn,capabilities FROM nodes WHERE id=? AND disabled=0",
            )?
            .query_row([id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .optional()?)
        })?;
        let (h, region, asn, cap) = n.context("unknown or revoked node")?;
        ensure!(constant_eq(&h, &hash(token)), "invalid node credential");
        Ok(Node {
            id: id.into(),
            region,
            asn,
            capabilities: serde_json::from_str(&cap)?,
        })
    }
    pub fn update_node_settings(
        &self,
        id: &str,
        name: &str,
        concurrency: Option<u32>,
    ) -> Result<()> {
        let name = name.trim();
        ensure!(
            !id.starts_with("globalping:"),
            "internal executor is not an editable node"
        );
        ensure!(
            name.chars().count() <= 80 && !name.chars().any(char::is_control),
            "node name must contain at most 80 printable characters"
        );
        ensure!(
            concurrency.is_none_or(|n| (1..=1000).contains(&n)),
            "node concurrency must be 1–1000"
        );
        ensure!(
            self.connect()?.execute(
                "UPDATE nodes SET name=?,concurrency_limit=? WHERE id=?",
                params![name, concurrency.unwrap_or(10), id]
            )? == 1,
            "unknown node"
        );
        self.wake.notify_waiters();
        Ok(())
    }
    pub fn set_node_enabled(&self, id: &str, enabled: bool) -> Result<()> {
        ensure!(
            !id.starts_with("globalping:"),
            "cannot change an internal measurement holder"
        );
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let disabled: bool = tx
            .query_row("SELECT disabled FROM nodes WHERE id=?", [id], |r| r.get(0))
            .optional()?
            .context("unknown node")?;
        // Enabling an already active node must not reset its live QUIC session.
        if enabled && !disabled {
            return Ok(());
        }
        tx.execute(
            "UPDATE nodes SET disabled=?,connected=0,session_id=NULL WHERE id=?",
            params![!enabled, id],
        )?;
        // A started attempt may still be running or spooled on the worker.
        // Keep its token/deadline for recovery; only release proven-unsent work.
        release_unstarted_on(&tx, Some(id))?;
        tx.commit()?;
        self.wake.notify_waiters();
        Ok(())
    }
    pub fn node_concurrency(&self, id: &str) -> Result<u32> {
        self.read(|c| Self::node_concurrency_on(c, id))
    }
    pub(crate) fn node_concurrency_on(c: &Connection, id: &str) -> Result<u32> {
        let limit: Option<Option<u32>> = c
            .prepare_cached("SELECT concurrency_limit FROM nodes WHERE id=?")?
            .query_row([id], |r| r.get(0))
            .optional()?;
        Ok(limit.flatten().unwrap_or(10))
    }
    pub fn reset_node_token(&self, id: &str) -> Result<String> {
        ensure!(
            !id.starts_with("globalping:"),
            "cannot rotate an internal holder"
        );
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            tx.execute(
                "UPDATE nodes SET token_hash=?,connected=0,session_id=NULL WHERE id=?",
                params![hash(&token), id]
            )? == 1,
            "unknown node"
        );
        release_unstarted_on(&tx, Some(id))?;
        tx.commit()?;
        self.wake.notify_waiters();
        Ok(token)
    }
    pub fn targets(&self, key: &str, fp: &str, targets: &[String]) -> Result<usize> {
        self.targets_with_evidence(key, fp, targets, &Value::Null)
    }
    pub(crate) fn targets_with_evidence(
        &self,
        key: &str,
        fp: &str,
        targets: &[String],
        evidence: &Value,
    ) -> Result<usize> {
        ensure!(
            !targets.is_empty() && targets.len() <= 3,
            "choose 1–3 known-responsive targets"
        );
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let text: String = tx
            .query_row(
                "SELECT payload FROM cases WHERE key=? AND fp=? AND active=1 AND status<>'decided' AND (?=0 OR status='blocked-target')",
                params![key, fp, !evidence.is_null()],
                |r| r.get(0),
            )
            .context("measurement scope changed; refresh the dispute")?;
        let mut payload: Value = serde_json::from_str(&text)?;
        ensure!(
            payload["measurement_required"] != false,
            "this dispute has no supported active measurement"
        );
        let family = payload["family"]
            .as_u64()
            .context("target selection is only for address conflicts")? as u8;
        for target in targets {
            let (f, n) = crate::rules::addr_num(target.parse()?);
            ensure!(f == family, "target family mismatch");
            ensure!(
                payload["ranges"]
                    .as_array()
                    .context("ranges")?
                    .iter()
                    .any(|r| {
                        let a = r[0]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                            .map(crate::rules::addr_num);
                        let b = r[1]
                            .as_str()
                            .and_then(|s| s.parse().ok())
                            .map(crate::rules::addr_num);
                        a.zip(b).is_some_and(|((_, s), (_, e))| n >= s && n <= e)
                    }),
                "target outside disputed evidence scope"
            );
        }
        payload["targets"] = json!(targets);
        if !evidence.is_null() {
            payload["target_evidence"] = evidence.clone();
        }
        let changed = tx.execute(
            "UPDATE cases SET payload=?,status='needs-active' WHERE key=? AND fp=? AND (payload<>? OR status<>'needs-active')",
            params![payload.to_string(), key, fp, payload.to_string()],
        )?;
        if changed > 0 {
            crate::work::mark_case(&tx, key)?;
        }
        let count = Self::plan_case_on(&tx, key, fp, &payload)?;
        tx.commit()?;
        if count > 0 {
            self.wake.notify_waiters();
        }
        Ok(count)
    }
    pub fn plan_case(&self, key: &str, fp: &str, payload: &Value) -> Result<usize> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let count = Self::plan_case_on(&tx, key, fp, payload)?;
        tx.commit()?;
        if count > 0 {
            self.wake.notify_waiters();
        }
        Ok(count)
    }
    fn plan_case_on(conn: &Connection, key: &str, fp: &str, payload: &Value) -> Result<usize> {
        crate::work::plan_on(conn, key, fp, payload)
    }
    pub fn enqueue_observation(
        &self,
        target: &str,
        regions: &[String],
        reason: &str,
    ) -> Result<String> {
        self.request_observation(target, regions, reason, false)
    }
    pub fn request_observation(
        &self,
        target: &str,
        regions: &[String],
        reason: &str,
        refresh: bool,
    ) -> Result<String> {
        let ip = target.parse::<std::net::IpAddr>().ok();
        let target = if let Some(ip) = ip {
            ensure!(
                crate::measure::public_ip(ip),
                "temporary IP measurements require a public address"
            );
            ip.to_string()
        } else {
            crate::rules::ascii_domain(target)?
        };
        ensure!(
            ip.is_some() || (target.contains('.') && !target.contains('*')),
            "observation requires an exact hostname"
        );
        ensure!(
            !regions.is_empty() && regions.len() <= 8,
            "select measurement regions"
        );
        let key = format!("{}:{target}", if ip.is_some() { "ip" } else { "dns" });
        let regions: Vec<_> = regions
            .iter()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let kind = if ip.is_some() {
            "manual-ip"
        } else {
            "domain-observation"
        };
        let mut p = json!({"kind":kind,"targets":[target],"regions":regions,"profile":"dns-tls-v1","manual":true});
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if refresh {
            p["epoch"] = json!(uuid::Uuid::new_v4().to_string());
        } else if let Some(old) = tx
            .query_row::<String, _, _>("SELECT payload FROM cases WHERE key=?", [&key], |r| {
                r.get(0)
            })
            .optional()?
        {
            let old: Value = serde_json::from_str(&old)?;
            if !old["epoch"].is_null() {
                p["epoch"] = old["epoch"].clone();
            }
        }
        let fp = fingerprint(&p);
        let changed = tx.execute("INSERT INTO cases VALUES(?,?,1,?,?,?,?,'needs-active',1,?) ON CONFLICT(key) DO UPDATE SET active=1,status=CASE WHEN cases.fp=excluded.fp THEN cases.status ELSE 'needs-active' END,revision=cases.revision+CASE WHEN cases.fp=excluded.fp THEN 0 ELSE 1 END,fp=excluded.fp,payload=excluded.payload,reason=excluded.reason,updated=excluded.updated WHERE cases.active<>1 OR cases.fp<>excluded.fp OR cases.payload<>excluded.payload OR cases.reason<>excluded.reason",params![key,fp,kind,target,reason,p.to_string(),now()])?;
        if changed > 0 {
            crate::work::mark_case(&tx, &key)?;
        }
        let count = Self::plan_case_on(&tx, &key, &fp, &p)?;
        tx.commit()?;
        if count > 0 {
            self.wake.notify_waiters();
        }
        Ok(key)
    }
    pub fn lease(&self, node: &Node) -> Result<Option<Lease>> {
        self.lease_inner(node, None)
    }
    pub fn lease_session(&self, node: &Node, session: &str) -> Result<Option<Lease>> {
        self.lease_inner(node, Some(session))
    }
    /// The existing session claim worker owns this connection between calls;
    /// each claim still owns and completes its own transaction.
    pub(crate) fn lease_session_on(
        &self,
        c: &mut Connection,
        node: &Node,
        session: &str,
    ) -> Result<Option<Lease>> {
        crate::jobs_v3::lease_on(self, c, node, Some(session))
    }
    fn lease_inner(&self, node: &Node, session: Option<&str>) -> Result<Option<Lease>> {
        crate::jobs_v3::lease(self, node, session)
    }
    /// Convert a durable reservation into one execution opportunity immediately
    /// before dispatch. Heartbeat/free-slot reports never grant capacity.
    pub fn begin_execution(&self, node: &str, session: &str, lease: &Lease) -> Result<bool> {
        self.begin_execution_inner_on(&mut self.connect()?, node, session, lease, None)
    }

    /// The asynchronous claimant may finish after a live limit/session change.
    /// Recheck the actual send capacity in the same transaction as the attempt.
    pub fn begin_execution_with_capacity(
        &self,
        node: &str,
        session: &str,
        lease: &Lease,
        physical_inflight: u32,
    ) -> Result<bool> {
        self.begin_execution_with_capacity_on(
            &mut self.connect()?,
            node,
            session,
            lease,
            physical_inflight,
        )
    }

    pub(crate) fn begin_execution_with_capacity_on(
        &self,
        c: &mut Connection,
        node: &str,
        session: &str,
        lease: &Lease,
        physical_inflight: u32,
    ) -> Result<bool> {
        self.begin_execution_inner_on(c, node, session, lease, Some(physical_inflight))
    }

    fn begin_execution_inner_on(
        &self,
        c: &mut Connection,
        node: &str,
        session: &str,
        lease: &Lease,
        physical_inflight: Option<u32>,
    ) -> Result<bool> {
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let valid: bool = tx.prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM nodes n JOIN jobs j ON j.lease_node=n.id WHERE n.id=?1 AND n.session_id=?2 AND n.connected=1 AND n.disabled=0 AND j.id=?3 AND j.lease_token=?4 AND j.status='leased' AND (?5 IS NULL OR ?5<min(coalesce(n.concurrency_limit,10),coalesce(n.worker_capacity,1000))))",
        )?.query_row(
            params![node, session, lease.id, lease.token, physical_inflight], |r| r.get(0),
        )?;
        let started = valid && crate::jobs_v3::consume_execution_on(&tx, lease)?;
        if !started {
            // Only this exact, provably unsent reservation may be returned.
            // Started work (including old uncertain leases) retains its recovery
            // chain, and a new session/token cannot be changed by this callback.
            let needed = !crate::jobs_v3::current_case_links_on(&tx, &lease.id)?.is_empty();
            tx.prepare_cached("UPDATE jobs SET status=CASE WHEN ?1=0 THEN 'obsolete' WHEN execution_count>=3 THEN 'unknown' ELSE 'pending' END,not_before=?2,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=?3 AND fp=?4 AND lease_node=?5 AND lease_token=?6 AND attempt_seq=?7 AND status='leased' AND NOT EXISTS(SELECT 1 FROM gp_remote WHERE job_id=jobs.id) AND EXISTS(SELECT 1 FROM lease_history h WHERE h.job_id=jobs.id AND h.token_hash=?8 AND h.attempt_seq=jobs.attempt_seq AND h.started_at IS NULL AND json_extract(h.lease_profile,'$.execution_reservation_schema')=1)")?.execute(params![needed,now(),lease.id,lease.fingerprint,node,lease.token,lease.profile["attempt_seq"].as_i64().unwrap_or(0),hash(&lease.token)])?;
        }
        tx.commit()?;
        Ok(started)
    }

    /// Only the native transport's unsent guard may call this: it must still
    /// own proof that Task serialization/write has never been entered. A send
    /// error, partial write, timeout or lost acknowledgement is not such proof.
    pub(crate) fn release_unsent_execution(
        &self,
        node: &str,
        session: &str,
        lease: &Lease,
    ) -> Result<bool> {
        let attempt = lease.profile["attempt_seq"].as_i64().unwrap_or(0);
        let round = lease.profile["round_seq"].as_i64().unwrap_or(0);
        if node.starts_with("globalping:")
            || session.is_empty()
            || lease.profile["worker_session"].as_str() != Some(session)
            || attempt <= 0
            || round <= 0
        {
            return Ok(false);
        }
        let mut c = self.connect()?;
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Match the durable original session, not nodes.session_id: disconnect
        // may already have cleared it, or a replacement session may be online.
        let valid: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs j JOIN lease_history h ON h.job_id=j.id WHERE j.id=?1 AND j.fp=?2 AND j.lease_node=?3 AND j.lease_token=?4 AND j.attempt_seq=?5 AND j.round_seq=?6 AND j.status='leased' AND h.node=?3 AND h.token_hash=?7 AND h.fp=?2 AND h.attempt_seq=?5 AND h.round_seq=?6 AND h.started_at IS NOT NULL AND h.completed_at IS NULL AND h.execution_refunded=0 AND json_extract(h.lease_profile,'$.execution_reservation_schema')=1 AND json_extract(h.lease_profile,'$.worker_session')=?8 AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id) AND EXISTS(SELECT 1 FROM jobs owner WHERE owner.id=coalesce(h.execution_job_id,j.id) AND owner.round_seq=?6 AND owner.execution_count>0))",
            params![lease.id,lease.fingerprint,node,lease.token,attempt,round,hash(&lease.token),session],
            |r| r.get(0),
        )?;
        if !valid {
            return Ok(false);
        }
        let needed = !crate::jobs_v3::current_case_links_on(&tx, &lease.id)?.is_empty();
        ensure!(
            crate::jobs_v3::refund_execution_on(&tx, lease)?,
            "unsent execution changed during cleanup"
        );
        let changed = tx.execute(
            "UPDATE jobs SET status=CASE WHEN ?1 THEN 'pending' ELSE 'obsolete' END,not_before=?2,lease_node=NULL,lease_token=NULL,lease_until=NULL WHERE id=?3 AND fp=?4 AND lease_node=?5 AND lease_token=?6 AND attempt_seq=?7 AND round_seq=?8 AND status='leased'",
            params![needed,now(),lease.id,lease.fingerprint,node,lease.token,attempt,round],
        )?;
        ensure!(changed == 1, "unsent lease changed during cleanup");
        tx.commit()?;
        self.wake.notify_waiters();
        Ok(true)
    }

    pub fn heartbeat(&self, node: &str, session: &str, job: &str, token: &str) -> Result<bool> {
        let n=self.connect()?.execute("UPDATE jobs SET lease_until=max(lease_until,?) WHERE id=? AND lease_node=? AND lease_token=? AND status='leased' AND lease_until>=? AND EXISTS(SELECT 1 FROM nodes WHERE id=? AND connected=1 AND disabled=0 AND session_id=?)",params![now()+180,job,node,token,now(),node,session])?;
        Ok(n == 1)
    }

    /// Persist one authenticated heartbeat using one connection and writer
    /// transaction, rather than reopening the schema for every active lease.
    pub fn heartbeat_batch(
        &self,
        node: &str,
        session: &str,
        active: &[(String, String)],
        network: Option<&crate::network::NetworkSupport>,
    ) -> Result<bool> {
        self.heartbeat_batch_on(&mut self.connect()?, node, session, active, network)
    }

    pub(crate) fn heartbeat_batch_on(
        &self,
        c: &mut Connection,
        node: &str,
        session: &str,
        active: &[(String, String)],
        network: Option<&crate::network::NetworkSupport>,
    ) -> Result<bool> {
        ensure!(active.len() <= 1000, "too many active worker leases");
        let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<(Option<bool>, Option<bool>)> = tx
            .prepare_cached("SELECT ipv4_supported,ipv6_supported FROM nodes WHERE id=? AND session_id=? AND connected=1 AND disabled=0")?
            .query_row(
                params![node, session],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((ipv4, ipv6)) = previous else {
            return Ok(false);
        };
        let at = now();
        if let Some(network) = network {
            tx.prepare_cached(
                "UPDATE nodes SET last_seen=max(coalesce(last_seen,0),?1),ipv4_supported=?2,ipv6_supported=?3,network_checked=?1 WHERE id=?4 AND session_id=?5",
            )?.execute(
                params![at, network.ipv4, network.ipv6, node, session],
            )?;
        } else {
            tx.prepare_cached(
                "UPDATE nodes SET last_seen=max(coalesce(last_seen,0),?) WHERE id=? AND session_id=?",
            )?.execute(
                params![at, node, session],
            )?;
        }
        {
            let until = at + 180;
            let mut statement = tx.prepare_cached("UPDATE jobs SET lease_until=?1 WHERE id=?2 AND lease_node=?3 AND lease_token=?4 AND status='leased' AND lease_until>=?5 AND lease_until<?1")?;
            for (job, token) in active {
                statement.execute(params![until, job, node, token, at])?;
            }
        }
        tx.commit()?;
        if network.is_some_and(|n| ipv4 != Some(n.ipv4) || ipv6 != Some(n.ipv6)) {
            self.wake.notify_waiters();
        }
        Ok(true)
    }
    pub fn eligible_self_observer(&self, lease: &Lease) -> Result<bool> {
        let c = self.connect()?;
        let profile = serde_json::to_string(&lease.profile)?;
        let query = format!(
            "WITH j AS (SELECT ?1 target,?2 kind,?3 profile,?4 region) SELECT EXISTS(SELECT 1 FROM nodes n,j WHERE n.id NOT LIKE 'globalping:%' AND n.connected=1 AND n.disabled=0 AND n.last_seen>?5 AND {})",
            crate::work::eligibility_sql("j", "n")
        );
        Ok(c.query_row(
            &query,
            params![lease.target, lease.kind, profile, lease.region, now() - 120],
            |r| r.get(0),
        )?)
    }
    pub fn jobs(&self, offset: usize, limit: usize) -> Result<Value> {
        let conn = self.connect()?;
        let total: i64 = conn.query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))?;
        let mut stmt=conn.prepare("SELECT id,case_key,fp,kind,target,region,status,not_before,attempts,lease_node,lease_until FROM jobs ORDER BY created DESC,id LIMIT ? OFFSET ?")?;
        let rows=stmt.query_map(params![limit.clamp(1,100) as i64,offset as i64],|r|Ok(json!({"id":r.get::<_,String>(0)?,"case_key":r.get::<_,String>(1)?,"fingerprint":r.get::<_,String>(2)?,"kind":r.get::<_,String>(3)?,"target":r.get::<_,String>(4)?,"region":r.get::<_,String>(5)?,"status":r.get::<_,String>(6)?,"not_before":r.get::<_,i64>(7)?,"attempts":r.get::<_,i64>(8)?,"lease_node":r.get::<_,Option<String>>(9)?,"lease_until":r.get::<_,Option<i64>>(10)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!({"items":rows,"total":total}))
    }
    pub fn submit(&self, node: &str, r: &ProbeResult) -> Result<Value> {
        crate::receipt::submit(self, node, r)
    }
    pub fn list(&self, what: &str, offset: usize, limit: usize, filter: &str) -> Result<Value> {
        let conn = self.connect()?;
        let limit = limit.clamp(1, 100);
        ensure!(what == "cases", "unknown collection");
        let (filter, predicate, index) = if let Some(v) = filter.strip_prefix("kind:") {
            (v, "kind=?1", "cases_kind_recent")
        } else if let Some(v) = filter.strip_prefix("status:") {
            (v, "status=?1", "cases_status_recent")
        } else {
            (
                filter,
                "(?1='' OR kind=?1 OR status=?1 OR subject LIKE '%'||?1||'%')",
                "cases_recent",
            )
        };
        let count = format!(
            "SELECT count(*) FROM case_metadata WHERE active=1 AND kind<>'target-discovery' AND {predicate}"
        );
        let total: i64 = conn.query_row(&count, [filter], |r| r.get(0))?;
        let query = format!(
            "SELECT key,fp,revision,kind,subject,reason,payload,status,updated FROM cases INDEXED BY {index} WHERE active=1 AND kind<>'target-discovery' AND {predicate} ORDER BY updated DESC,key LIMIT ?2 OFFSET ?3"
        );
        let mut stmt = conn.prepare(&query)?;
        let rows=stmt.query_map(params![filter,limit as i64,offset as i64],|r|Ok(json!({"key":r.get::<_,String>(0)?,"fingerprint":r.get::<_,String>(1)?,"revision":r.get::<_,i64>(2)?,"kind":r.get::<_,String>(3)?,"subject":r.get::<_,String>(4)?,"reason":r.get::<_,String>(5)?,"payload":serde_json::from_str::<Value>(&r.get::<_,String>(6)?).unwrap_or(Value::Null),"status":r.get::<_,String>(7)?,"updated":r.get::<_,i64>(8)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!({"total":total,"items":rows}))
    }
    pub fn overview(&self) -> Result<Value> {
        let conn = self.connect()?;
        let mut groups = BTreeMap::new();
        let mut stmt = conn.prepare("SELECT kind,status,n FROM case_group_counts WHERE n>0")?;
        for r in stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })? {
            let (k, s, n) = r?;
            groups.insert(format!("{k}/{s}"), n);
        }
        let mut jobs = BTreeMap::new();
        let mut stmt = conn.prepare("SELECT status,count(*) FROM jobs GROUP BY status")?;
        for r in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (k, n) = r?;
            jobs.insert(k, n);
        }
        let facts: i64 =
            conn.query_row("SELECT count(*) FROM discovery_domains", [], |r| r.get(0))?;
        Ok(
            json!({"cases":groups,"jobs":jobs,"domain_facts":facts,"current_release":self.meta("current-release")?,"nodes":self.nodes()?,"builds":self.build_summaries()?}),
        )
    }
    pub fn nodes(&self) -> Result<Value> {
        let c = self.connect()?;
        let stats = self.executor_stats()?;
        let default_limit = 10;
        let mut s = c.prepare(
            "SELECT id,region,asn,capabilities,disabled,last_seen,name,connected,concurrency_limit,ipv4_supported,ipv6_supported,network_checked FROM nodes WHERE id NOT LIKE 'globalping:%' ORDER BY id",
        )?;
        let rows=s.query_map([],|r|{let id:String=r.get(0)?;let stat=stats.get(&id).cloned().unwrap_or_default();let limit:Option<u32>=r.get(8)?;Ok(json!({"id":id,"region":r.get::<_,String>(1)?,"asn":r.get::<_,u32>(2)?,"capabilities":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"disabled":r.get::<_,bool>(4)?,"last_seen":r.get::<_,Option<i64>>(5)?,"name":r.get::<_,String>(6)?,"connected":r.get::<_,bool>(7)?,"concurrency_limit":limit,"effective_concurrency":limit.unwrap_or(default_limit),"ipv4_supported":r.get::<_,Option<bool>>(9)?,"ipv6_supported":r.get::<_,Option<bool>>(10)?,"network_checked":r.get::<_,Option<i64>>(11)?,"completed_tasks":stat.completed_tasks,"running_tasks":stat.running_tasks,"last_completed_at":stat.last_completed_at}))})?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!(rows))
    }
    pub fn executor_stats(&self) -> Result<BTreeMap<String, ExecutorStats>> {
        let conn = self.connect()?;
        let mut stats = BTreeMap::new();
        let mut q = conn
            .prepare("SELECT executor,completed_tasks,last_completed_at FROM executor_counters")?;
        for r in q.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                ExecutorStats {
                    completed_tasks: r.get(1)?,
                    running_tasks: 0,
                    last_completed_at: r.get(2)?,
                },
            ))
        })? {
            let (id, v) = r?;
            stats.insert(id, v);
        }
        let mut q=conn.prepare("SELECT j.lease_node,count(*) FROM jobs j WHERE j.lease_node IS NOT NULL AND j.status IN ('leased','unknown') AND ((j.status='leased' AND j.lease_until>=?) OR EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=j.id AND g.remote_id<>'')) GROUP BY j.lease_node")?;
        for r in q.query_map([now()], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })? {
            let (id, n) = r?;
            stats.entry(id).or_default().running_tasks = n;
        }
        Ok(stats)
    }
    pub fn builds(&self) -> Result<Value> {
        self.read_builds(false)
    }
    /// Project before transferring or deserializing wide internal build summaries.
    pub fn build_summaries(&self) -> Result<Value> {
        self.read_builds(true)
    }
    fn read_builds(&self, compact: bool) -> Result<Value> {
        let conn = self.connect()?;
        let summary = if compact {
            "CASE WHEN json_valid(b.summary) THEN json_object('targets',json_extract(b.summary,'$.targets'),'rules',json_extract(b.summary,'$.rules'),'cn_domain_rules',json_extract(b.summary,'$.cn_domain_rules'),'domain_quarantines',json_extract(b.summary,'$.domain_quarantines'),'incremental',json_extract(b.summary,'$.incremental'),'geography',json_object('regions',json_extract(b.summary,'$.geography.regions'),'active_required_groups',json_extract(b.summary,'$.geography.active_required_groups'))) END"
        } else {
            "b.summary"
        };
        let mut statement = conn.prepare(&format!("SELECT b.id,b.status,b.started,b.finished,b.release,{summary},b.error,p.snapshot FROM builds b LEFT JOIN build_progress p ON p.build_id=b.id ORDER BY b.started DESC,b.rowid DESC LIMIT 30"))?;
        let rows = statement.query_map([], |r| Ok(json!({
            "id":r.get::<_,String>(0)?,"status":r.get::<_,String>(1)?,"started":r.get::<_,i64>(2)?,
            "finished":r.get::<_,Option<i64>>(3)?,"release":r.get::<_,Option<String>>(4)?,
            "summary":r.get::<_,Option<String>>(5)?.and_then(|s|serde_json::from_str::<Value>(&s).ok()),
            "error":r.get::<_,Option<String>>(6)?,"progress":r.get::<_,Option<String>>(7)?.and_then(|s|serde_json::from_str::<Value>(&s).ok())
        })))?.collect::<std::result::Result<Vec<_>,_>>()?;
        let mut value = json!(rows);
        crate::progress::overlay(self, &mut value);
        Ok(value)
    }
    pub fn cache_get(&self, key: &str) -> Result<Option<Value>> {
        let text: Option<String> = self
            .connect()?
            .query_row(
                "SELECT result FROM observation_cache WHERE key=? AND valid_until>?",
                params![key, now()],
                |r| r.get(0),
            )
            .optional()?;
        text.map(|s| serde_json::from_str(&s).map_err(Into::into))
            .transpose()
    }
    pub fn cache_put(&self, key: &str, until: i64, result: &Value) -> Result<()> {
        self.connect()?.execute("INSERT INTO observation_cache VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET valid_until=excluded.valid_until,result=excluded.result",params![key,until,result.to_string()])?;
        Ok(())
    }
    pub fn results(&self, key: &str) -> Result<Value> {
        let c = self.connect()?;
        let mut s=c.prepare("SELECT r.id,r.node,r.observed,r.outcome,r.evidence,r.accepted,r.fp FROM job_cases l JOIN jobs j ON j.id=l.job_id JOIN results r INDEXED BY result_job ON r.job_id=j.id WHERE l.case_key=? ORDER BY r.received DESC LIMIT 100")?;
        let rows=s.query_map([key],|r|Ok(json!({"id":r.get::<_,String>(0)?,"node":r.get::<_,String>(1)?,"observed_at":r.get::<_,i64>(2)?,"outcome":r.get::<_,String>(3)?,"evidence":serde_json::from_str::<Value>(&r.get::<_,String>(4)?).unwrap_or(Value::Null),"accepted":r.get::<_,bool>(5)?,"fingerprint":r.get::<_,String>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!(rows))
    }
}
/// A lost connection is not proof that a dispatched measurement did not run.
/// Unsent reservations can be returned immediately; started attempts retain
/// their original lease for bounded recovery and cannot run concurrently again.
pub(crate) fn release_unstarted_on(c: &Connection, node: Option<&str>) -> Result<usize> {
    Ok(c.execute("UPDATE jobs SET status=CASE WHEN json_extract(profile,'$.legacy_alias')=1 AND coalesce(json_extract(profile,'$.logical_job'),0)<>1 THEN 'obsolete' WHEN execution_count>=3 THEN 'unknown' ELSE 'pending' END,lease_node=NULL,lease_token=NULL,lease_until=NULL,not_before=? WHERE status='leased' AND lease_node NOT LIKE 'globalping:%' AND (? IS NULL OR lease_node=?) AND NOT EXISTS(SELECT 1 FROM gp_remote g WHERE g.job_id=jobs.id) AND EXISTS(SELECT 1 FROM lease_history h WHERE h.job_id=jobs.id AND h.attempt_seq=jobs.attempt_seq AND json_extract(h.lease_profile,'$.execution_reservation_schema')=1) AND NOT EXISTS(SELECT 1 FROM lease_history h WHERE h.job_id=jobs.id AND h.attempt_seq=jobs.attempt_seq AND h.started_at IS NOT NULL AND h.execution_refunded=0)",params![now(),node,node])?)
}

pub fn constant_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |x, (a, b)| x | (a ^ b)) == 0
}

fn shared_wake(path: &Path) -> std::sync::Arc<tokio::sync::Notify> {
    use std::sync::{Arc, Mutex, OnceLock, Weak};
    static QUEUES: OnceLock<Mutex<BTreeMap<PathBuf, Weak<tokio::sync::Notify>>>> = OnceLock::new();
    let mut queues = QUEUES
        .get_or_init(Default::default)
        .lock()
        .expect("queue notifications");
    queues.retain(|_, v| v.strong_count() > 0);
    let key = path
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.join("control.sqlite3"))
        .unwrap_or_else(|| path.to_path_buf());
    if let Some(queue) = queues.get(&key).and_then(Weak::upgrade) {
        return queue;
    }
    let queue = Arc::new(tokio::sync::Notify::new());
    queues.insert(key, Arc::downgrade(&queue));
    queue
}

#[cfg(test)]
mod read_connection_tests {
    use super::*;

    #[test]
    fn short_reader_is_shared_and_physically_read_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let clone = store.clone();
        assert!(Arc::ptr_eq(&store.reader, &clone.reader));
        store.meta("missing").unwrap();
        let cache = store.reader.lock().unwrap();
        let connection = &cache.as_ref().unwrap().connection;
        assert!(connection.is_readonly("main").unwrap());
        assert!(connection.is_autocommit());
        assert!(
            connection
                .execute("INSERT INTO meta VALUES('read-only-must-fail','value')", [])
                .is_err()
        );
    }
}

#[cfg(test)]
mod session_connection_tests {
    use super::*;

    fn fixture(count: u32) -> (tempfile::TempDir, Store, Node) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let node = Node {
            id: "connection-fixture".into(),
            region: "us".into(),
            asn: 64501,
            capabilities: vec!["traceroute".into()],
        };
        store
            .register_node(&node, "connection-fixture-token-long-enough")
            .unwrap();
        store
            .update_node_settings(&node.id, "connection fixture", Some(count))
            .unwrap();
        store.connect().unwrap().execute(
            "UPDATE nodes SET connected=1,session_id='current',last_seen=?,ipv4_supported=1,ipv6_supported=0,worker_capacity=1000 WHERE id=?",
            params![now(), node.id],
        ).unwrap();
        for n in 1..=count {
            store
                .enqueue_observation(&format!("1.1.1.{n}"), &["us".into()], "connection fixture")
                .unwrap();
        }
        (dir, store, node)
    }

    #[test]
    fn reused_session_connection_sees_new_capacity_and_revocation_without_pinning_a_snapshot() {
        let (_dir, store, node) = fixture(2);
        let mut c = store.connect().unwrap();
        let first = store
            .lease_session_on(&mut c, &node, "current")
            .unwrap()
            .unwrap();
        let second = store
            .lease_session_on(&mut c, &node, "current")
            .unwrap()
            .unwrap();
        assert!(c.is_autocommit());
        assert!(
            store
                .begin_execution_with_capacity_on(&mut c, &node.id, "current", &first, 0)
                .unwrap()
        );
        assert!(c.is_autocommit());
        let writer = store.connect().unwrap();
        writer
            .execute(
                "UPDATE nodes SET concurrency_limit=1 WHERE id=?",
                [&node.id],
            )
            .unwrap();
        assert_eq!(Store::node_concurrency_on(&c, &node.id).unwrap(), 1);
        assert!(
            !store
                .begin_execution_with_capacity_on(&mut c, &node.id, "current", &second, 1)
                .unwrap()
        );
        assert!(c.is_autocommit());
        let state: (String, i64) = writer
            .query_row(
                "SELECT status,execution_count FROM jobs WHERE id=?",
                [&second.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("pending".into(), 0));

        let active = vec![(first.id.clone(), first.token.clone())];
        assert!(
            store
                .heartbeat_batch_on(&mut c, &node.id, "current", &active, None)
                .unwrap()
        );
        writer
            .execute(
                "UPDATE nodes SET session_id='replacement',disabled=1,last_seen=1 WHERE id=?",
                [&node.id],
            )
            .unwrap();
        assert!(
            !store
                .heartbeat_batch_on(&mut c, &node.id, "current", &active, None)
                .unwrap()
        );
        assert!(c.is_autocommit());
        assert_eq!(
            writer
                .query_row::<i64, _, _>("SELECT last_seen FROM nodes WHERE id=?", [&node.id], |r| r
                    .get(0))
                .unwrap(),
            1
        );
        // Cached statements have completed; the persistent connection holds no
        // old read snapshot and does not obstruct a checkpoint.
        assert_eq!(
            writer
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, i64>(2)?
                )))
                .unwrap(),
            (0, 0, 0)
        );
    }

    #[test]
    fn reused_heartbeat_connection_recovers_after_an_atomic_batch_failure() {
        let (_dir, store, node) = fixture(2);
        let mut c = store.connect().unwrap();
        let leases: Vec<_> = (0..2)
            .map(|_| {
                store
                    .lease_session_on(&mut c, &node, "current")
                    .unwrap()
                    .unwrap()
            })
            .collect();
        let active: Vec<_> = leases
            .iter()
            .map(|l| (l.id.clone(), l.token.clone()))
            .collect();
        let writer = store.connect().unwrap();
        let deadline = now() + 30;
        writer.execute("UPDATE nodes SET last_seen=1", []).unwrap();
        writer
            .execute("UPDATE jobs SET lease_until=?", [deadline])
            .unwrap();
        writer.execute_batch(&format!(
            "CREATE TRIGGER reject_second_heartbeat BEFORE UPDATE OF lease_until ON jobs WHEN NEW.id='{}' BEGIN SELECT RAISE(ABORT,'injected heartbeat failure'); END",
            leases[1].id,
        )).unwrap();
        assert!(
            store
                .heartbeat_batch_on(&mut c, &node.id, "current", &active, None)
                .is_err()
        );
        assert!(c.is_autocommit());
        assert_eq!(
            writer
                .query_row::<i64, _, _>("SELECT last_seen FROM nodes WHERE id=?", [&node.id], |r| r
                    .get(0))
                .unwrap(),
            1
        );
        assert_eq!(
            writer
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM jobs WHERE lease_until=?",
                    [deadline],
                    |r| r.get(0)
                )
                .unwrap(),
            2
        );
        writer
            .execute_batch("DROP TRIGGER reject_second_heartbeat")
            .unwrap();
        assert!(
            store
                .heartbeat_batch_on(&mut c, &node.id, "current", &active, None)
                .unwrap()
        );
        assert!(c.is_autocommit());
    }

    #[test]
    fn proven_unsent_attempt_is_refunded_once_after_disconnect_without_rewinding_identity() {
        let (_dir, store, node) = fixture(1);
        let lease = store.lease_session(&node, "current").unwrap().unwrap();
        assert_eq!(lease.profile["worker_session"], "current");
        assert!(store.begin_execution(&node.id, "current", &lease).unwrap());
        let c = store.connect().unwrap();
        // The old session is no longer current when its dropped start worker
        // returns. A replacement session must not make the proof unusable.
        c.execute(
            "UPDATE nodes SET connected=1,session_id='replacement' WHERE id=?",
            [&node.id],
        )
        .unwrap();
        assert!(
            store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
        let state: (String, i64, i64, i64, Option<String>) = c.query_row("SELECT status,execution_count,attempt_seq,failure_count,lease_token FROM jobs WHERE id=?", [&lease.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        assert_eq!(state, ("pending".into(), 0, 1, 0, None));
        assert!(
            c.query_row::<bool, _, _>(
                "SELECT execution_refunded FROM lease_history WHERE job_id=?",
                [&lease.id],
                |r| r.get(0)
            )
            .unwrap()
        );
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
        let next = store.lease_session(&node, "replacement").unwrap().unwrap();
        assert_eq!(next.profile["attempt_seq"], 2);
        assert!(
            store
                .begin_execution(&node.id, "replacement", &next)
                .unwrap()
        );
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
        let current: (i64, String) = c
            .query_row(
                "SELECT execution_count,lease_token FROM jobs WHERE id=?",
                [&next.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(current, (1, next.token));
    }

    #[test]
    fn unsent_cleanup_rejects_wrong_history_completed_remote_and_legacy_attempts() {
        let (_dir, store, node) = fixture(1);
        let lease = store.lease_session(&node, "current").unwrap().unwrap();
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap(),
            "unstarted work is handled by the reservation cleanup"
        );
        assert!(store.begin_execution(&node.id, "current", &lease).unwrap());
        let mut changed = lease.clone();
        changed.profile["worker_session"] = json!("forged-session");
        assert!(
            !store
                .release_unsent_execution(&node.id, "forged-session", &changed)
                .unwrap()
        );
        for variant in ["token", "fingerprint", "attempt", "round"] {
            let mut changed = lease.clone();
            match variant {
                "token" => changed.token.push_str("-different"),
                "fingerprint" => changed.fingerprint.push_str("-different"),
                "attempt" => changed.profile["attempt_seq"] = json!(2),
                "round" => changed.profile["round_seq"] = json!(2),
                _ => unreachable!(),
            }
            assert!(
                !store
                    .release_unsent_execution(&node.id, "current", &changed)
                    .unwrap(),
                "{variant}"
            );
        }
        assert!(
            !store
                .release_unsent_execution("another-node", "current", &lease)
                .unwrap()
        );
        let c = store.connect().unwrap();
        c.execute(
            "UPDATE lease_history SET completed_at=? WHERE job_id=?",
            params![now(), lease.id],
        )
        .unwrap();
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
        c.execute(
            "UPDATE lease_history SET completed_at=NULL WHERE job_id=?",
            [&lease.id],
        )
        .unwrap();
        c.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll) VALUES(?,'fixture','known-id',?,0)", params![lease.id,serde_json::to_string(&lease).unwrap()]).unwrap();
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
        c.execute("DELETE FROM gp_remote WHERE job_id=?", [&lease.id])
            .unwrap();
        c.execute("UPDATE lease_history SET lease_profile=json_remove(lease_profile,'$.worker_session') WHERE job_id=?", [&lease.id]).unwrap();
        assert!(
            !store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap(),
            "old uncertain history must not acquire new proof"
        );
        let state: (i64, String, bool) = c.query_row("SELECT j.execution_count,j.lease_token,h.execution_refunded FROM jobs j JOIN lease_history h ON h.job_id=j.id WHERE j.id=?", [&lease.id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(state, (1, lease.token, false));
    }

    #[test]
    fn unsent_cleanup_rolls_back_the_refund_if_releasing_the_lease_fails() {
        let (_dir, store, node) = fixture(1);
        let lease = store.lease_session(&node, "current").unwrap().unwrap();
        assert!(store.begin_execution(&node.id, "current", &lease).unwrap());
        let c = store.connect().unwrap();
        c.execute_batch("CREATE TRIGGER reject_unsent_release BEFORE UPDATE OF lease_token ON jobs BEGIN SELECT RAISE(ABORT,'injected unsent release failure'); END").unwrap();
        assert!(
            store
                .release_unsent_execution(&node.id, "current", &lease)
                .is_err()
        );
        let state: (i64, String, bool) = c.query_row("SELECT j.execution_count,j.lease_token,h.execution_refunded FROM jobs j JOIN lease_history h ON h.job_id=j.id WHERE j.id=?", [&lease.id], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(state, (1, lease.token.clone(), false));
        c.execute_batch("DROP TRIGGER reject_unsent_release")
            .unwrap();
        assert!(
            store
                .release_unsent_execution(&node.id, "current", &lease)
                .unwrap()
        );
    }

    #[test]
    #[ignore = "fixed local SQL workload; run explicitly with --nocapture"]
    fn fixed_session_sql_workload() {
        use std::time::Instant;
        let (_dir, base, node) = fixture(20);
        let leases: Vec<_> = (0..20)
            .map(|_| base.lease_session(&node, "current").unwrap().unwrap())
            .collect();
        assert!(
            base.begin_execution_with_capacity(&node.id, "current", &leases[0], 0)
                .unwrap()
        );
        let active: Vec<_> = leases
            .iter()
            .map(|l| (l.id.clone(), l.token.clone()))
            .collect();
        base.connect()
            .unwrap()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        const LOOPS: usize = 500;
        for reused in [false, true, true, false] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::copy(&base.path, dir.path().join("control.sqlite3")).unwrap();
            let store = Store::open(dir.path()).unwrap();
            let mut claim = store.connect().unwrap();
            let mut heartbeat = store.connect().unwrap();
            let start = Instant::now();
            for _ in 0..LOOPS {
                if reused {
                    assert_eq!(Store::node_concurrency_on(&claim, &node.id).unwrap(), 20);
                    assert!(
                        store
                            .lease_session_on(&mut claim, &node, "current")
                            .unwrap()
                            .is_none()
                    );
                    assert!(
                        store
                            .begin_execution_with_capacity_on(
                                &mut claim, &node.id, "current", &leases[0], 0
                            )
                            .unwrap()
                    );
                    assert!(
                        store
                            .heartbeat_batch_on(&mut heartbeat, &node.id, "current", &active, None)
                            .unwrap()
                    );
                } else {
                    assert_eq!(store.node_concurrency(&node.id).unwrap(), 20);
                    assert!(store.lease_session(&node, "current").unwrap().is_none());
                    assert!(
                        store
                            .begin_execution_with_capacity(&node.id, "current", &leases[0], 0)
                            .unwrap()
                    );
                    assert!(
                        store
                            .heartbeat_batch(&node.id, "current", &active, None)
                            .unwrap()
                    );
                }
            }
            assert!(claim.is_autocommit() && heartbeat.is_autocommit());
            println!(
                "session_sql reuse={reused} loops={LOOPS} elapsed_ms={:.3} session_connections={}",
                start.elapsed().as_secs_f64() * 1000.0,
                if reused { 2 } else { 3 * LOOPS }
            );
        }
    }
}
