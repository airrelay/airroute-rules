//! Durable build observations, independent of rule contents and release identity.
use crate::{now, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, Instant},
};
type Registry = BTreeMap<(std::path::PathBuf, String), Weak<Mutex<State>>>;
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}
pub fn snapshot(store: &Store, id: &str) -> Option<Snapshot> {
    let state = registry()
        .lock()
        .ok()?
        .get(&(store.path.clone(), id.into()))?
        .upgrade()?;
    state.lock().ok().map(|s| s.snapshot.clone())
}
/// Only running rows may use volatile progress. Terminal rows always use the committed snapshot.
pub fn overlay(store: &Store, rows: &mut serde_json::Value) {
    if let Some(rows) = rows.as_array_mut() {
        for row in rows {
            if row["status"] == "running"
                && let Some(id) = row["id"].as_str()
                && let Some(s) = snapshot(store, id)
            {
                row["progress"] = serde_json::to_value(s).unwrap_or_default();
            }
        }
    }
}
pub const STAGES: usize = 7;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub stage: usize,
    pub stages: usize,
    pub label: String,
    pub detail: String,
    pub completed: usize,
    pub total: Option<usize>,
    pub unit: String,
    pub bytes_received: Option<u64>,
    pub bytes_total: Option<u64>,
    pub updated: i64,
}
struct State {
    snapshot: Snapshot,
    last: Instant,
    phase_started: Instant,
}
#[derive(Clone)]
pub struct Reporter {
    store: Store,
    id: String,
    state: Arc<Mutex<State>>,
}
impl Reporter {
    pub fn new(store: &Store, id: &str) -> Result<Self> {
        let snapshot = Snapshot {
            stage: 1,
            stages: STAGES,
            label: "准备构建".into(),
            detail: "读取构建配方与缓存设置".into(),
            completed: 0,
            total: None,
            unit: String::new(),
            bytes_received: None,
            bytes_total: None,
            updated: now(),
        };
        let report = Self {
            store: store.clone(),
            id: id.into(),
            state: Arc::new(Mutex::new(State {
                snapshot,
                last: Instant::now(),
                phase_started: Instant::now(),
            })),
        };
        {
            let mut registry = registry().lock().expect("build progress registry");
            registry.retain(|_, state| state.strong_count() > 0);
            registry.insert(
                (store.path.clone(), id.into()),
                Arc::downgrade(&report.state),
            );
        }
        report.flush()?;
        Ok(report)
    }
    fn update(&self, force: bool, f: impl FnOnce(&mut Snapshot)) -> Result<()> {
        let mut state = self.state.lock().expect("build progress");
        let previous_stage = state.snapshot.stage;
        f(&mut state.snapshot);
        if state.snapshot.stage != previous_stage {
            tracing::info!(build=%self.id, stage=previous_stage,
                elapsed_ms=state.phase_started.elapsed().as_secs_f64()*1000.,
                "build phase completed");
            state.phase_started = Instant::now();
        }
        state.snapshot.updated = now();
        if force || state.last.elapsed() >= Duration::from_secs(1) {
            // Progress is telemetry, never a reason to abandon a valid rule build.
            // Do not spend the normal writer timeout waiting for an unrelated receipt.
            let persist = (|| -> Result<()> {
                let c = self.store.connect()?;
                c.busy_timeout(Duration::ZERO)?;
                c.execute("INSERT INTO build_progress(build_id,snapshot) SELECT id,? FROM builds WHERE id=? AND status='running' ON CONFLICT(build_id) DO UPDATE SET snapshot=excluded.snapshot",rusqlite::params![serde_json::to_string(&state.snapshot)?,self.id])?;
                Ok(())
            })();
            if let Err(error) = persist {
                tracing::debug!(build=%self.id,%error,"progress persistence deferred");
            }
            state.last = Instant::now();
        }
        Ok(())
    }
    pub fn phase(
        &self,
        stage: usize,
        label: &str,
        detail: &str,
        total: Option<usize>,
        unit: &str,
    ) -> Result<()> {
        ensure!((1..=STAGES).contains(&stage), "invalid build phase");
        self.update(true, |s| {
            *s = Snapshot {
                stage,
                stages: STAGES,
                label: label.into(),
                detail: detail.into(),
                completed: 0,
                total,
                unit: unit.into(),
                bytes_received: None,
                bytes_total: None,
                updated: now(),
            }
        })
    }
    pub fn work(&self, detail: impl Into<String>) -> Result<()> {
        self.update(false, |s| {
            s.detail = detail.into();
            s.bytes_received = None;
            s.bytes_total = None;
        })
    }
    pub fn units(
        &self,
        completed: usize,
        total: Option<usize>,
        unit: &str,
        detail: impl Into<String>,
    ) -> Result<()> {
        self.update(false, |s| {
            s.completed = completed;
            s.total = total;
            s.unit = unit.into();
            s.detail = detail.into();
            s.bytes_received = None;
            s.bytes_total = None;
        })
    }
    pub fn advance(&self, detail: impl Into<String>) -> Result<()> {
        self.update(false, |s| {
            s.completed += 1;
            s.detail = detail.into();
            s.bytes_received = None;
            s.bytes_total = None;
        })
    }
    pub fn receiving(&self, item: &str, received: u64, total: Option<u64>) -> Result<()> {
        self.update(false, |s| {
            s.detail = format!("下载 {item}");
            s.bytes_received = Some(received);
            s.bytes_total = total;
        })
    }
    /// Monotonic phase timing is independent of best-effort SQLite telemetry.
    pub fn finish_timing(&self) {
        let state = self.state.lock().expect("build progress");
        tracing::info!(build=%self.id, stage=state.snapshot.stage,
            elapsed_ms=state.phase_started.elapsed().as_secs_f64()*1000.,
            "build phase completed");
    }
    pub fn flush(&self) -> Result<()> {
        self.update(true, |_| {})
    }
}
