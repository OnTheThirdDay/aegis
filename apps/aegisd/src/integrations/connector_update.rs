//! Keeps the Cloudflare connector current: finds cloudflared's latest
//! release on GitHub and installs it into the data volume.
//!
//! * The SHA-256 comes from the checksum list Cloudflare publishes in the
//!   release notes; when GitHub also lists an asset digest, both must agree.
//! * Only `https://github.com/cloudflare/cloudflared/releases/download/…`
//!   URLs are fetched, at most [`connector::MAX_BINARY`] bytes.
//! * The download must report its own version (`cloudflared --version`)
//!   before its manifest is written; the manifest write is the switch, so a
//!   failed or partial update leaves the running build in place.

use super::connector::{self, Build, Store};
use serde_json::Value;
use std::time::Duration;

const LATEST: &str = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest";
const DOWNLOADS: &str = "https://github.com/cloudflare/cloudflared/releases/download/";

/// A release's binary for this machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    pub build: Build,
    pub url: String,
}

/// The release asset name for this machine's architecture.
pub fn asset() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("cloudflared-linux-amd64"),
        "aarch64" => Some("cloudflared-linux-arm64"),
        _ => None,
    }
}

/// Read a GitHub release object (`/releases/latest`).
pub fn parse_release(release: &Value, asset: &str) -> Result<Release, String> {
    let version = release["tag_name"].as_str().unwrap_or_default().to_owned();
    if connector::version_key(&version).is_none() {
        return Err(format!("unexpected cloudflared release tag {version:?}"));
    }
    let body = release["body"].as_str().unwrap_or_default();
    let sha256 = body
        .lines()
        .filter_map(|line| line.trim().strip_prefix(asset)?.strip_prefix(':'))
        .map(|rest| rest.trim().to_ascii_lowercase())
        .find(|sum| sum.len() == 64)
        .ok_or_else(|| format!("cloudflared {version} lists no SHA-256 for {asset}"))?;
    let build = Build { version, sha256 };
    build.check()?;
    let listed = release["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == asset)
        .ok_or_else(|| format!("cloudflared {} has no {asset} download", build.version))?;
    if let Some(digest) = listed["digest"].as_str() {
        if digest != format!("sha256:{}", build.sha256) {
            return Err(format!(
                "{asset}: GitHub's digest differs from the release notes"
            ));
        }
    }
    let url = listed["browser_download_url"].as_str().unwrap_or_default();
    if !url.starts_with(&format!("{DOWNLOADS}{}/", build.version)) {
        return Err(format!("unexpected download address for {asset}"));
    }
    Ok(Release {
        url: url.to_owned(),
        build,
    })
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .user_agent(concat!("aegisnet/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))
}

/// cloudflared's latest release for this machine.
pub async fn latest() -> Result<Release, String> {
    let asset =
        asset().ok_or_else(|| format!("no cloudflared build for {}", std::env::consts::ARCH))?;
    let response = client()?
        .get(LATEST)
        .header("accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| "could not reach api.github.com".to_owned())?;
    if !response.status().is_success() {
        return Err(format!("api.github.com answered {}", response.status()));
    }
    let release: Value = response
        .json()
        .await
        .map_err(|_| "malformed release information from GitHub".to_owned())?;
    parse_release(&release, asset)
}

/// Download, verify and install `release`; afterwards it is the store's
/// newest build. Older downloads stay until [`prune`].
pub async fn install(store: &Store, release: &Release) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let dir = store.updates();
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e.kind()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let mut response = client()?
        .get(&release.url)
        .send()
        .await
        .map_err(|_| "could not download cloudflared from github.com".to_owned())?;
    if !response.status().is_success() {
        return Err(format!("github.com answered {}", response.status()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "the cloudflared download was interrupted".to_owned())?
    {
        if (bytes.len() + chunk.len()) as u64 > connector::MAX_BINARY {
            return Err("the cloudflared download is too large".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    if hex::encode(Sha256::digest(&bytes)) != release.build.sha256 {
        return Err("the cloudflared download does not match its published SHA-256".into());
    }
    let target = store.update_binary(&release.build.version);
    let part = target.with_extension("part");
    write_file(&part, &bytes, 0o755)?;
    if let Err(e) = reports_version(&part, &release.build.version).await {
        let _ = std::fs::remove_file(&part);
        return Err(e);
    }
    std::fs::rename(&part, &target).map_err(|e| format!("installing cloudflared: {}", e.kind()))?;
    let manifest = serde_json::to_vec(&release.build).map_err(|e| e.to_string())?;
    let next = store.update_manifest().with_extension("next");
    write_file(&next, &manifest, 0o600)?;
    std::fs::rename(&next, store.update_manifest())
        .map_err(|e| format!("installing cloudflared: {}", e.kind()))?;
    Ok(())
}

/// Delete downloaded builds other than `keep`.
pub fn prune(store: &Store, keep: &str) {
    let Ok(entries) = std::fs::read_dir(store.updates()) else {
        return;
    };
    let keep = format!("cloudflared-{keep}");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("cloudflared-") && name != keep {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn write_file(path: &std::path::Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let result = opts.open(path).and_then(|mut f| {
        f.write_all(bytes)?;
        f.sync_all()
    });
    result.map_err(|e| format!("{}: {}", path.display(), e.kind()))
}

/// The binary runs here and says it is `version`.
async fn reports_version(path: &std::path::Path, version: &str) -> Result<(), String> {
    let run = tokio::process::Command::new(path)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(20), run)
        .await
        .map_err(|_| "the downloaded cloudflared did not answer".to_owned())?
        .map_err(|e| format!("the downloaded cloudflared does not run here: {}", e.kind()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !text.contains(&format!("version {version} "))
        && !text.trim_end().ends_with(&format!("version {version}"))
    {
        return Err(format!(
            "the downloaded cloudflared does not report version {version}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn release(sum: &str) -> Value {
        json!({
            "tag_name": "2026.10.4",
            "body": format!(" \n### SHA256 Checksums:\n```\ncloudflared-linux-amd64.deb: {}\ncloudflared-linux-amd64: {sum}\ncloudflared-linux-arm64: {}\n```\n", "1".repeat(64), "2".repeat(64)),
            "assets": [
                {"name": "cloudflared-linux-amd64.deb", "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/2026.10.4/cloudflared-linux-amd64.deb"},
                {"name": "cloudflared-linux-amd64", "digest": format!("sha256:{sum}"), "browser_download_url": "https://github.com/cloudflare/cloudflared/releases/download/2026.10.4/cloudflared-linux-amd64"},
            ],
        })
    }

    #[test]
    fn releases_are_read_from_the_published_checksums() {
        let sum = "a".repeat(64);
        let r = parse_release(&release(&sum), "cloudflared-linux-amd64").expect("release");
        assert_eq!(
            r.build,
            Build {
                version: "2026.10.4".into(),
                sha256: sum.clone()
            }
        );
        assert!(r.url.ends_with("/2026.10.4/cloudflared-linux-amd64"));
        // Listed in the notes but not downloadable.
        assert!(parse_release(&release(&sum), "cloudflared-linux-arm64").is_err());

        let mut v = release(&sum);
        v["assets"][1]["digest"] = json!(format!("sha256:{}", "b".repeat(64)));
        assert!(
            parse_release(&v, "cloudflared-linux-amd64").is_err(),
            "digests disagree"
        );
        let mut v = release(&sum);
        v["assets"][1]["browser_download_url"] =
            json!("https://example.com/cloudflared-linux-amd64");
        assert!(
            parse_release(&v, "cloudflared-linux-amd64").is_err(),
            "foreign download"
        );
        let mut v = release(&sum);
        v["tag_name"] = json!("latest; rm -rf /");
        assert!(
            parse_release(&v, "cloudflared-linux-amd64").is_err(),
            "odd tag"
        );
        let mut v = release(&sum);
        v["body"] = json!("no checksums");
        assert!(
            parse_release(&v, "cloudflared-linux-amd64").is_err(),
            "unverifiable"
        );
    }

    /// Needs internet access: `cargo test -p aegisd -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn installs_the_latest_release() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = Store::new(tmp.path());
        let release = latest().await.expect("latest release");
        install(&store, &release).await.expect("install");
        let installed = store.downloaded().expect("verified");
        assert_eq!(installed.build, release.build);
        std::fs::write(store.updates().join("cloudflared-2000.1.0"), b"old").expect("old");
        prune(&store, &release.build.version);
        assert!(!store.updates().join("cloudflared-2000.1.0").exists());
        assert!(store.downloaded().is_ok(), "the current build stays");
    }
}
