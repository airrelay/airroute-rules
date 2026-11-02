//! Controller-owned credentials, never part of rule exports or API responses.
use anyhow::{Result, ensure};
use std::path::{Path, PathBuf};
pub fn directory(data: &Path) -> Result<PathBuf> {
    let dir = data.join("credentials");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}
pub fn save(data: &Path, value: &str) -> Result<String> {
    ensure!(
        !value.trim().is_empty() && value.len() <= 8192 && !value.contains(['\n', '\r', '\0']),
        "invalid credential"
    );
    let id = uuid::Uuid::new_v4().simple().to_string();
    let path = directory(data)?.join(&id);
    crate::atomic_write(&path, value.trim().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(id)
}
pub fn read(data: &Path, id: &str) -> Result<String> {
    ensure!(
        id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid credential reference"
    );
    Ok(std::fs::read_to_string(directory(data)?.join(id))?)
}
pub fn remove(data: &Path, id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid credential reference"
    );
    let path = directory(data)?.join(id);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
