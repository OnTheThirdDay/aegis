//! App updates offered by the gateway (ADR-0017).
//!
//! A gateway carries the client builds of its own release. Each comes with
//! a statement signed by the release workflow's Ed25519 key: platform,
//! version, file name and SHA-256. A device asks its gateway on the same
//! device-authenticated path as renewal, and accepts an update only when the
//! signature verifies against [`RELEASE_KEY`], the platform is its own and
//! the version is newer than its own. A gateway can therefore offer only
//! builds the release workflow signed, never an older one. Apps offer the
//! update; they never install it on their own.

use crate::{http, rejected, DeviceDir, JoinError};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// The release workflow's update-signing public key (Ed25519, raw, base64).
/// Its private key is the `AEGIS_UPDATE_SIGNING_KEY` repository secret.
pub const RELEASE_KEY: &str = "WZYVPxlTsjLmdqyu8ejnyMaV6SYbdAAZVZxKfuTdsow=";

/// What a statement's signature covers starts with this line.
const STATEMENT: &str = "aegisborne-update/1";
/// Download piece size: what one device request returns.
pub const CHUNK: u64 = 1024 * 1024;
/// No client build is larger.
pub const MAX_SIZE: u64 = 200 * 1024 * 1024;

/// One signed client build, as the gateway describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update {
    pub platform: String,
    pub version: String,
    pub file: String,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
    /// Ed25519 over [`Update::statement`], base64.
    pub signature: String,
}

impl Update {
    /// The exact bytes the release workflow signs.
    pub fn statement(&self) -> String {
        format!(
            "{STATEMENT}\nplatform={}\nversion={}\nfile={}\nsize={}\nsha256={}\n",
            self.platform, self.version, self.file, self.size, self.sha256
        )
    }

    /// Signed by the key whose public half is `key` (base64).
    pub fn verify_with(&self, key: &str) -> Result<(), JoinError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let key = b64
            .decode(key)
            .map_err(|_| JoinError::Untrusted("update key"))?;
        let signature = b64
            .decode(self.signature.trim())
            .map_err(|_| JoinError::Untrusted("update signature is malformed"))?;
        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
            .verify(self.statement().as_bytes(), &signature)
            .map_err(|_| JoinError::Untrusted("update signature does not verify"))
    }

    /// Signed by the release workflow, for `platform`, newer than `current`,
    /// and well formed.
    pub fn acceptable(&self, platform: &str, current: &str) -> Result<(), JoinError> {
        self.verify_with(RELEASE_KEY)?;
        if self.platform != platform {
            return Err(JoinError::Untrusted("update is for another platform"));
        }
        if !newer(&self.version, current) {
            return Err(JoinError::Untrusted("update is not newer"));
        }
        let name_ok = !self.file.is_empty()
            && self.file.len() <= 128
            && !self.file.starts_with('.')
            && self
                .file
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        let hash_ok = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !name_ok || !hash_ok || self.size == 0 || self.size > MAX_SIZE {
            return Err(JoinError::Untrusted("update description is malformed"));
        }
        Ok(())
    }
}

/// `X.Y.Z` as numbers; a pre-release (`-…`) sorts before its release.
fn parse_version(v: &str) -> Option<([u64; 3], bool)> {
    let (core, pre) = match v.trim().split_once('-') {
        Some((c, _)) => (c, true),
        None => (v.trim(), false),
    };
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    let out = [parts.next()??, parts.next()??, parts.next()??];
    parts.next().is_none().then_some((out, pre))
}

/// Whether `candidate` is a later version than `current`.
pub fn newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some((a, a_pre)), Some((b, b_pre))) => a > b || (a == b && b_pre && !a_pre),
        _ => false,
    }
}

/// This build's platform as releases name it, if it updates from its
/// gateway (iOS updates are installed from the gateway too, as an Ad Hoc
/// build; see ADR-0017).
pub fn platform() -> Option<&'static str> {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("windows-x86_64")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x86_64")
    } else if cfg!(target_os = "macos") {
        Some("macos")
    } else if cfg!(all(target_os = "android", target_arch = "aarch64")) {
        Some("android-arm64")
    } else if cfg!(all(target_os = "android", target_arch = "x86_64")) {
        // Emulators and some Chromebooks; releases ship ARM64 only.
        Some("android-x86_64")
    } else if cfg!(target_os = "ios") {
        Some("ios")
    } else {
        None
    }
}

fn request(dir: &DeviceDir) -> Result<(String, http::Edge, String), JoinError> {
    let device = dir.load()?;
    let cert = dir.read("cert.pem")?;
    let outer = if device.outer_server_name.is_some() {
        Some(dir.read("outer-ca.pem")?)
    } else {
        None
    };
    Ok((device.renew_url(), device.edge(outer), cert))
}

/// Ask the gateway for a build newer than `current` for `platform`. `None`
/// when it has none (or nothing acceptable: a gateway can't make a device
/// take a build the release workflow didn't sign).
pub async fn check(
    dir: &DeviceDir,
    platform: &str,
    current: &str,
) -> Result<Option<Update>, JoinError> {
    let (url, edge, cert) = request(dir)?;
    let body = json!({"certificate_pem": cert, "update_query": {"platform": platform}});
    let (status, bytes) = http::post_json(&url, &edge, &body).await?;
    if status != 200 {
        return Err(rejected(status, &bytes));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| JoinError::Untrusted("malformed response"))?;
    if response["update"].is_null() {
        return Ok(None);
    }
    let update: Update = serde_json::from_value(response["update"].clone())
        .map_err(|_| JoinError::Untrusted("malformed update"))?;
    Ok(update.acceptable(platform, current).ok().map(|()| update))
}

/// Download `update` to `dest`, in pieces, checking its size and SHA-256.
/// A partial download (`dest` + `.part`) is resumed. `dest` exists only
/// once the whole file matched.
pub async fn download(
    dir: &DeviceDir,
    update: &Update,
    dest: &Path,
    progress: impl Fn(u64, u64),
) -> Result<(), JoinError> {
    let (url, edge, cert) = request(dir)?;
    let part = dest.with_extension("part");
    let io = |e: std::io::Error| JoinError::Storage(format!("{}: {}", part.display(), e.kind()));
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    if let Ok(existing) = tokio::fs::read(&part).await {
        if (existing.len() as u64) <= update.size {
            hasher.update(&existing);
            offset = existing.len() as u64;
        }
    }
    let mut file = if offset > 0 {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(&part)
            .await
            .map_err(io)?
    } else {
        tokio::fs::File::create(&part).await.map_err(io)?
    };
    while offset < update.size {
        let body = json!({
            "certificate_pem": cert,
            "update_download": {"file": update.file, "offset": offset},
        });
        let (status, bytes) =
            http::post_json_up_to(&url, &edge, &body, CHUNK as usize + 64 * 1024).await?;
        if status != 200 {
            return Err(rejected(status, &bytes));
        }
        let expected = (update.size - offset).min(CHUNK);
        if bytes.len() as u64 != expected {
            return Err(JoinError::Untrusted("update download is the wrong size"));
        }
        hasher.update(&bytes);
        file.write_all(&bytes).await.map_err(io)?;
        offset += expected;
        progress(offset, update.size);
    }
    file.flush().await.map_err(io)?;
    drop(file);
    if hex::encode(hasher.finalize()) != update.sha256 {
        let _ = tokio::fs::remove_file(&part).await;
        return Err(JoinError::Untrusted(
            "the downloaded update doesn't match its signature",
        ));
    }
    tokio::fs::rename(&part, dest).await.map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Signed with `openssl pkeyutl -sign -rawin` and a throwaway key, as
    /// the release workflow signs (.github/scripts/sign-updates.sh).
    const TEST_KEY: &str = "2rVsVxGp8kk7pEomqVqQCrK+Ql5R8WKOL5O/Ss5UI+E=";
    fn signed() -> Update {
        Update {
            platform: "windows-x86_64".into(),
            version: "1.2.0".into(),
            file: "aegis-client-windows-x86_64.exe".into(),
            size: 5,
            sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824".into(),
            signature: "aLc0ZGkZanLmaWBGp88atmLL1wVCvoZYJUYEfwFRVmxKzxcG5H2pK/Z9J42zDZS8BZwPE70MmtpoJKRYPoykAw==".into(),
        }
    }

    #[test]
    fn signatures_from_the_release_workflow_verify() {
        signed().verify_with(TEST_KEY).expect("verifies");
        // Any change to what was signed breaks it.
        for change in [
            |u: &mut Update| u.version = "1.3.0".into(),
            |u: &mut Update| u.platform = "linux-x86_64".into(),
            |u: &mut Update| u.file = "other.exe".into(),
            |u: &mut Update| u.size = 6,
            |u: &mut Update| u.sha256 = "0".repeat(64),
        ] {
            let mut u = signed();
            change(&mut u);
            assert!(u.verify_with(TEST_KEY).is_err());
        }
        // Another key (the real release key) doesn't accept it.
        assert!(signed().acceptable("windows-x86_64", "1.0.0").is_err());
    }

    #[test]
    fn versions_only_move_forward() {
        assert!(newer("1.0.1", "1.0.0"));
        assert!(newer("1.10.0", "1.9.9"));
        assert!(newer("2.0.0", "1.99.99"));
        assert!(newer("1.0.0", "1.0.0-rc.1"));
        assert!(!newer("1.0.0", "1.0.0"));
        assert!(!newer("1.0.0-rc.2", "1.0.0"));
        assert!(!newer("0.9.9", "1.0.0"));
        assert!(!newer("1.0", "0.9.0"));
        assert!(!newer("1.0.0.1", "1.0.0"));
        assert!(!newer("x.y.z", "1.0.0"));
    }
}
