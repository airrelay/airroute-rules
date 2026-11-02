pub mod audit;
pub mod audit_issues;
pub mod build;
pub mod console_session;
pub mod discovery;
pub mod domains;
pub mod fusion;
pub mod geo;
pub mod globalping;
pub mod inputs;
pub mod ip_policy;
pub mod measure;
pub mod progress;
pub mod publish;
pub mod rules;
pub mod sampling;
pub mod scheduler;
pub mod secrets;
pub mod server;
pub mod store;
mod task_read_model;
pub mod transport;

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn hash(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}
pub fn fingerprint(data: &impl Serialize) -> String {
    hash(serde_json::to_vec(data).expect("serializable fingerprint"))
}
pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    use anyhow::Context;
    serde_json::from_slice(&std::fs::read(path).with_context(|| path.display().to_string())?)
        .with_context(|| format!("parse {}", path.display()))
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

// Closing only our descriptor can leave flock held by a descriptor inherited by
// a concurrently spawned child. Explicitly unlock the shared description first.
pub(crate) struct FileLock(std::fs::File);
impl FileLock {
    pub(crate) fn blocking(file: std::fs::File) -> std::io::Result<Self> {
        file.lock()?;
        Ok(Self(file))
    }
    pub(crate) fn try_new(file: std::fs::File) -> Result<Self, std::fs::TryLockError> {
        file.try_lock()?;
        Ok(Self(file))
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

#[cfg(all(test, unix))]
mod lock_tests {
    use super::*;
    #[test]
    fn dropping_the_guard_unlocks_even_while_an_inherited_descriptor_is_alive() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let owned = std::fs::File::open(file.path()).unwrap();
        let inherited = owned.try_clone().unwrap();
        let guard = FileLock::try_new(owned).unwrap();
        assert!(FileLock::try_new(std::fs::File::open(file.path()).unwrap()).is_err());
        drop(guard);
        let reacquired = FileLock::try_new(std::fs::File::open(file.path()).unwrap()).unwrap();
        drop(inherited);
        drop(reacquired);
    }
}

pub mod work;

pub mod network;

pub mod build_delta;
pub mod jobs_v3;
pub mod receipt;
