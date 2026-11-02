//! Fixed console sessions. Only logout revocations are persisted; verification is local.
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::RwLock,
};
use uuid::Uuid;

const TTL: i64 = 8 * 3600;
const HEADER: &[u8] = br#"{"alg":"HS256","typ":"JWT"}"#;
const MAX_TOKEN: usize = 1024;
const MAX_REVOCATION_FILE: u64 = 4 * 1024 * 1024;
const REVOCATION_FILE: &str = "console-session-revocations.json";
const KEY_FILE: &str = "console-session-key";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claims {
    iss: String,
    aud: String,
    sub: String,
    iat: i64,
    exp: i64,
    jti: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocations {
    version: u8,
    revoked: Vec<Revocation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Revocation {
    digest: String,
    exp: i64,
}

pub struct ConsoleSessions {
    key: hmac::Key,
    path: PathBuf,
    revoked: RwLock<BTreeMap<String, i64>>,
}

impl ConsoleSessions {
    pub fn open(data: &Path, admin_hash: &str) -> Result<Self> {
        Self::open_at(data, admin_hash, crate::now())
    }

    fn open_at(data: &Path, admin_hash: &str, now: i64) -> Result<Self> {
        ensure!(!admin_hash.is_empty(), "console credential is empty");
        fs::create_dir_all(data).context("create console session directory")?;
        let path = data.join(REVOCATION_FILE);
        let (revoked, pruned) = read_revocations(&path, now)?;
        // Independent OS entropy prevents an administrator password from becoming
        // an offline JWT guessing oracle. Bind it to the current credential too.
        let master = session_key(data)?;
        let mut derivation = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &master));
        derivation.update(b"airroute-rules/console-session/HS256/v1\0");
        derivation.update(admin_hash.as_bytes());
        let derived_key = derivation.sign();
        let sessions = Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, derived_key.as_ref()),
            path,
            revoked: RwLock::new(revoked),
        };
        if pruned {
            let map = sessions
                .revoked
                .read()
                .map_err(|_| anyhow!("console revocations lock poisoned"))?;
            let mut installed = false;
            sessions.persist(&map, &mut installed)?;
        }
        Ok(sessions)
    }

    pub fn issue(&self) -> Result<String> {
        self.issue_at(crate::now())
    }

    fn issue_at(&self, now: i64) -> Result<String> {
        ensure!(now > 0, "invalid console session time");
        let claims = Claims {
            iss: "airroute-rules".into(),
            aud: "airroute-console".into(),
            sub: "admin".into(),
            iat: now,
            exp: now
                .checked_add(TTL)
                .context("console session time overflow")?,
            jti: Uuid::new_v4().to_string(),
        };
        self.sign(&claims)
    }

    fn sign(&self, claims: &Claims) -> Result<String> {
        let body = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(HEADER),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
        );
        let signature = hmac::sign(&self.key, body.as_bytes());
        Ok(format!(
            "{body}.{}",
            URL_SAFE_NO_PAD.encode(signature.as_ref())
        ))
    }

    pub fn valid(&self, token: &str) -> bool {
        self.valid_at(token, crate::now())
    }

    fn valid_at(&self, token: &str, now: i64) -> bool {
        let Some(claims) = self.verified(token, now) else {
            return false;
        };
        let Ok(revoked) = self.revoked.read() else {
            return false;
        };
        !revoked.contains_key(&jti_digest(&claims.jti))
    }

    fn verified(&self, token: &str, now: i64) -> Option<Claims> {
        if token.len() > MAX_TOKEN || !token.is_ascii() {
            return None;
        }
        let mut segments = token.split('.');
        let header = segments.next()?;
        let payload = segments.next()?;
        let signature = segments.next()?;
        if segments.next().is_some()
            || header != URL_SAFE_NO_PAD.encode(HEADER)
            || payload.is_empty()
            || payload.len() > 768
            || signature.len() != 43
        {
            return None;
        }
        let signature_bytes = URL_SAFE_NO_PAD.decode(signature).ok()?;
        if signature_bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature {
            return None;
        }
        let signed_len = header.len() + 1 + payload.len();
        hmac::verify(&self.key, &token.as_bytes()[..signed_len], &signature_bytes).ok()?;
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
        let claims: Claims = serde_json::from_slice(&payload_bytes).ok()?;
        // This console emits one representation, so reject alternate encodings and fields.
        if URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).ok()?) != payload
            || claims.iss != "airroute-rules"
            || claims.aud != "airroute-console"
            || claims.sub != "admin"
            || claims.iat <= 0
            || claims.iat > now
            || claims.exp <= now
            || claims.exp.checked_sub(claims.iat) != Some(TTL)
        {
            return None;
        }
        let id = Uuid::parse_str(&claims.jti).ok()?;
        if id.get_version_num() != 4
            || id.get_variant() != uuid::Variant::RFC4122
            || id.to_string() != claims.jti
        {
            return None;
        }
        Some(claims)
    }

    /// A failed durable logout is reported to the caller so it can retain the cookie.
    pub fn revoke(&self, token: &str) -> Result<()> {
        self.revoke_at(token, crate::now())
    }

    fn revoke_at(&self, token: &str, now: i64) -> Result<()> {
        // An expired, old-credential, or invalid cookie is already unusable.
        let Some(claims) = self.verified(token, now) else {
            return Ok(());
        };
        let mut revoked = self
            .revoked
            .write()
            .map_err(|_| anyhow!("console revocations lock poisoned"))?;
        let mut next = revoked.clone();
        next.retain(|_, exp| *exp > now);
        next.insert(jti_digest(&claims.jti), claims.exp);
        let mut installed = false;
        let result = self.persist(&next, &mut installed);
        // After rename, reflect the visible file even if directory fsync failed.
        // Still return that failure; a retry must perform durability checks again.
        if result.is_ok() || installed {
            *revoked = next;
        }
        result
    }

    fn persist(&self, revoked: &BTreeMap<String, i64>, installed: &mut bool) -> Result<()> {
        let contents = Revocations {
            version: 1,
            revoked: revoked
                .iter()
                .map(|(digest, exp)| Revocation {
                    digest: digest.clone(),
                    exp: *exp,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&contents)?;
        ensure!(
            bytes.len() as u64 <= MAX_REVOCATION_FILE,
            "console revocations file too large"
        );
        let directory = self
            .path
            .parent()
            .context("console revocations directory missing")?;
        let mut file = tempfile::NamedTempFile::new_in(directory)
            .context("create console revocations temporary file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(&bytes)
            .context("write console revocations")?;
        file.as_file()
            .sync_all()
            .context("sync console revocations")?;
        file.persist(&self.path)
            .context("install console revocations")?;
        *installed = true;
        #[cfg(unix)]
        File::open(directory)?
            .sync_all()
            .context("sync console revocations directory")?;
        Ok(())
    }
}

fn jti_digest(jti: &str) -> String {
    let mut hash = digest::Context::new(&digest::SHA256);
    hash.update(b"airroute-rules/console-session/revoked-jti/v1\0");
    hash.update(jti.as_bytes());
    hex::encode(hash.finish())
}

fn session_key(data: &Path) -> Result<[u8; 32]> {
    let path = data.join(KEY_FILE);
    match fs::symlink_metadata(&path) {
        Ok(_) => return read_session_key(&path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("read console session key metadata"),
    }
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("console session randomness unavailable"))?;
    let mut file = tempfile::NamedTempFile::new_in(data).context("create console session key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(&bytes)
        .context("write console session key")?;
    file.as_file()
        .sync_all()
        .context("sync console session key")?;
    match file.persist_noclobber(&path) {
        Ok(_) => {
            #[cfg(unix)]
            File::open(data)?
                .sync_all()
                .context("sync console session key directory")?;
            Ok(bytes)
        }
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            read_session_key(&path)
        }
        Err(error) => Err(error).context("install console session key"),
    }
}

fn read_session_key(path: &Path) -> Result<[u8; 32]> {
    let metadata = fs::symlink_metadata(path).context("read console session key metadata")?;
    ensure!(
        metadata.is_file() && metadata.len() == 32,
        "invalid console session key file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "console session key must have mode 0600"
        );
    }
    let mut file = File::open(path).context("open console session key")?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)
        .context("read console session key")?;
    let mut excess = [0u8; 1];
    ensure!(
        file.read(&mut excess)? == 0,
        "invalid console session key length"
    );
    Ok(bytes)
}

fn read_revocations(path: &Path, now: i64) -> Result<(BTreeMap<String, i64>, bool)> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((BTreeMap::new(), false));
        }
        Err(error) => return Err(error).context("read console revocations metadata"),
    };
    ensure!(
        metadata.is_file(),
        "console revocations is not a regular file"
    );
    ensure!(
        metadata.len() <= MAX_REVOCATION_FILE,
        "console revocations file too large"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o777 == 0o600,
            "console revocations must have mode 0600"
        );
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_REVOCATION_FILE + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_REVOCATION_FILE,
        "console revocations file too large"
    );
    let contents: Revocations =
        serde_json::from_slice(&bytes).context("parse console revocations")?;
    ensure!(
        contents.version == 1,
        "unsupported console revocations version"
    );
    let mut revoked = BTreeMap::new();
    let mut pruned = false;
    let mut seen = std::collections::BTreeSet::new();
    for entry in contents.revoked {
        ensure!(
            entry.digest.len() == 64
                && entry
                    .digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && entry.exp > 0
                && seen.insert(entry.digest.clone()),
            "invalid console revocation entry"
        );
        if entry.exp > now {
            revoked.insert(entry.digest, entry.exp);
        } else {
            pruned = true;
        }
    }
    Ok((revoked, pruned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const TIME: i64 = 1_800_000_000;

    fn fixture() -> (tempfile::TempDir, ConsoleSessions) {
        // Synthetic fixture material only; no stored or real administrator credential.
        let directory = tempfile::tempdir().unwrap();
        let sessions = ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).unwrap();
        (directory, sessions)
    }

    fn fixture_hash() -> String {
        crate::hash(b"console-session synthetic unit-test material")
    }

    fn raw_signed(sessions: &ConsoleSessions, header: &[u8], payload: &[u8]) -> String {
        let body = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let signature = hmac::sign(&sessions.key, body.as_bytes());
        format!("{body}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }

    #[test]
    fn sessions_survive_restart_but_not_credential_change() {
        let (directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        assert!(!directory.path().join(REVOCATION_FILE).exists());
        assert!(sessions.valid_at(&cookie, TIME));
        let reopened =
            ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME + 1).unwrap();
        assert!(reopened.valid_at(&cookie, TIME + 1));
        let changed = ConsoleSessions::open_at(
            directory.path(),
            &crate::hash(b"different synthetic unit-test material"),
            TIME + 1,
        )
        .unwrap();
        assert!(!changed.valid_at(&cookie, TIME + 1));
        let second = sessions.issue_at(TIME).unwrap();
        let first_id = sessions.verified(&cookie, TIME).unwrap().jti;
        let second_id = sessions.verified(&second, TIME).unwrap().jti;
        assert!(first_id != second_id);
        let (_other_directory, other_sessions) = fixture();
        assert!(!other_sessions.valid_at(&cookie, TIME));
    }

    #[test]
    fn logout_is_durable_and_contains_only_digests_and_expirations() {
        let (directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        let other = sessions.issue_at(TIME).unwrap();
        let id = sessions.verified(&cookie, TIME).unwrap().jti;
        sessions.revoke_at(&cookie, TIME).unwrap();
        assert!(!sessions.valid_at(&cookie, TIME));
        assert!(sessions.valid_at(&other, TIME));
        let bytes = fs::read(directory.path().join(REVOCATION_FILE)).unwrap();
        let contents: Revocations = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(contents.revoked.len(), 1);
        assert_eq!(contents.revoked[0].digest, jti_digest(&id));
        assert_eq!(contents.revoked[0].exp, TIME + TTL);
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains(&cookie));
        assert!(!text.contains(&id));
        assert!(!text.contains(&fixture_hash()));
        let reopened =
            ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME + 1).unwrap();
        assert!(!reopened.valid_at(&cookie, TIME + 1));
        assert!(reopened.valid_at(&other, TIME + 1));
        // Repeated logout remains harmless and rechecks durability.
        reopened.revoke_at(&cookie, TIME + 1).unwrap();
    }

    #[test]
    fn time_signature_shape_and_fixed_claims_are_strict() {
        let (_directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        assert!(sessions.valid_at(&cookie, TIME + TTL - 1));
        assert!(!sessions.valid_at(&cookie, TIME + TTL));
        assert!(!sessions.valid_at(&cookie, TIME - 1));
        assert!(!sessions.valid_at(&format!("{cookie}.extra"), TIME));
        assert!(!sessions.valid_at(&"x".repeat(MAX_TOKEN + 1), TIME));
        let mut damaged = cookie.as_bytes().to_vec();
        let last = damaged.last_mut().unwrap();
        *last = if *last == b'A' { b'B' } else { b'A' };
        assert!(!sessions.valid_at(std::str::from_utf8(&damaged).unwrap(), TIME));
        let claims = sessions.verified(&cookie, TIME).unwrap();
        let payload = serde_json::to_vec(&claims).unwrap();
        assert!(!sessions.valid_at(
            &raw_signed(&sessions, br#"{"alg":"none","typ":"JWT"}"#, &payload),
            TIME
        ));
        assert!(!sessions.valid_at(
            &raw_signed(&sessions, br#"{"typ":"JWT","alg":"HS256"}"#, &payload),
            TIME
        ));
        for field in ["iss", "aud", "sub", "jti"] {
            let mut altered: Claims = serde_json::from_slice(&payload).unwrap();
            match field {
                "iss" => altered.iss = "incorrect".into(),
                "aud" => altered.aud = "incorrect".into(),
                "sub" => altered.sub = "incorrect".into(),
                "jti" => altered.jti = Uuid::nil().to_string(),
                _ => unreachable!(),
            }
            assert!(!sessions.valid_at(&sessions.sign(&altered).unwrap(), TIME));
        }
        let mut wrong_ttl = claims;
        wrong_ttl.exp += 1;
        assert!(!sessions.valid_at(&sessions.sign(&wrong_ttl).unwrap(), TIME));
        assert!(!sessions.valid_at(&sessions.issue_at(TIME + 1).unwrap(), TIME));
        assert!(sessions.issue_at(i64::MAX).is_err());
    }

    #[test]
    fn noncanonical_and_unknown_fields_are_rejected_even_with_valid_mac() {
        let (_directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        let claims = sessions.verified(&cookie, TIME).unwrap();
        let payload = serde_json::to_vec(&claims).unwrap();
        let mut spaced = b" ".to_vec();
        spaced.extend(&payload);
        assert!(!sessions.valid_at(&raw_signed(&sessions, HEADER, &spaced), TIME));
        let mut duplicate = payload[..payload.len() - 1].to_vec();
        duplicate.extend(br#", "iss":"airroute-rules"}"#);
        assert!(!sessions.valid_at(&raw_signed(&sessions, HEADER, &duplicate), TIME));
        let mut unknown = payload[..payload.len() - 1].to_vec();
        unknown.extend(br#", "role":"admin"}"#);
        assert!(!sessions.valid_at(&raw_signed(&sessions, HEADER, &unknown), TIME));
        let mut segments: Vec<_> = cookie.split('.').map(str::to_owned).collect();
        segments[1].push('=');
        assert!(!sessions.valid_at(&segments.join("."), TIME));
        // The last base64url digit has two unused bits. Alternate padding bits are invalid.
        let mut signature = segments[2].as_bytes().to_vec();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let position = alphabet
            .iter()
            .position(|b| *b == *signature.last().unwrap())
            .unwrap();
        *signature.last_mut().unwrap() = alphabet[position | 1];
        let original: Vec<_> = cookie.split('.').collect();
        let alternate = format!(
            "{}.{}.{}",
            original[0],
            original[1],
            std::str::from_utf8(&signature).unwrap()
        );
        assert!(!sessions.valid_at(&alternate, TIME));
    }

    #[test]
    fn simultaneous_logouts_do_not_lose_revocations() {
        let (directory, sessions) = fixture();
        let sessions = Arc::new(sessions);
        let cookies: Vec<_> = (0..16).map(|_| sessions.issue_at(TIME).unwrap()).collect();
        let handles: Vec<_> = cookies
            .iter()
            .map(|cookie| {
                let sessions = Arc::clone(&sessions);
                let cookie = cookie.clone();
                std::thread::spawn(move || sessions.revoke_at(&cookie, TIME).unwrap())
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let reopened =
            ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME + 1).unwrap();
        for cookie in cookies {
            assert!(!reopened.valid_at(&cookie, TIME + 1));
        }
        assert_eq!(reopened.revoked.read().unwrap().len(), 16);
    }

    #[test]
    fn failed_persistence_is_not_a_successful_logout() {
        let (directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        let destination = directory.path().join(REVOCATION_FILE);
        fs::create_dir(&destination).unwrap();
        assert!(sessions.revoke_at(&cookie, TIME).is_err());
        assert!(sessions.valid_at(&cookie, TIME));
        assert!(sessions.revoked.read().unwrap().is_empty());
        fs::remove_dir(destination).unwrap();
        sessions.revoke_at(&cookie, TIME).unwrap();
        assert!(!sessions.valid_at(&cookie, TIME));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn startup_rejects_corruption_and_prunes_expired_entries() {
        let (directory, sessions) = fixture();
        let old = sessions.issue_at(TIME).unwrap();
        sessions.revoke_at(&old, TIME).unwrap();
        let reopened =
            ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME + TTL).unwrap();
        assert!(reopened.revoked.read().unwrap().is_empty());
        let path = directory.path().join(REVOCATION_FILE);
        let pruned: Revocations = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(pruned.revoked.is_empty());
        fs::write(&path, b"not json").unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
        fs::write(&path, br#"{"version":2,"revoked":[]}"#).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
        let entry = Revocation {
            digest: "a".repeat(64),
            exp: TIME + TTL,
        };
        let duplicate = Revocations {
            version: 1,
            revoked: vec![
                Revocation {
                    digest: entry.digest.clone(),
                    exp: entry.exp,
                },
                entry,
            ],
        };
        fs::write(path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn revocation_file_is_private_and_links_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (directory, sessions) = fixture();
        let cookie = sessions.issue_at(TIME).unwrap();
        sessions.revoke_at(&cookie, TIME).unwrap();
        let master = directory.path().join(KEY_FILE);
        assert_eq!(
            fs::metadata(&master).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let path = directory.path().join(REVOCATION_FILE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
        fs::remove_file(&path).unwrap();
        let linked = directory.path().join("linked.json");
        fs::write(&linked, br#"{"version":1,"revoked":[]}"#).unwrap();
        fs::set_permissions(&linked, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&linked, path).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
    }

    #[test]
    fn damaged_master_is_rejected_without_replacement() {
        let (directory, _sessions) = fixture();
        let path = directory.path().join(KEY_FILE);
        fs::write(&path, []).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn public_or_linked_master_is_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (directory, _sessions) = fixture();
        let path = directory.path().join(KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
        let target = directory.path().join("original-key");
        fs::rename(&path, &target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert!(ConsoleSessions::open_at(directory.path(), &fixture_hash(), TIME).is_err());
    }
}
