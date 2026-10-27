//! Supervised Cloudflare connector (`cloudflared`) for the embedded tunnel.
//!
//! * Two builds can be present: the one bundled in the image and a newer
//!   one downloaded by the updater (`connector_update`) into the data
//!   volume. Each comes with a manifest (version and SHA-256 from
//!   Cloudflare's release notes); the newest whose binary matches its
//!   manifest runs, checked again before every start.
//! * The tunnel token is read from an owner-only file (`--token-file`), never
//!   from arguments or the environment.
//! * Output is discarded (privacy default); health comes from the
//!   connector's loopback `/ready` endpoint.
//! * The child runs with this process's unprivileged identity and is
//!   restarted with backoff while the integration is enabled. It never
//!   updates itself (`--no-autoupdate`): the image is read-only.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const METRICS: &str = "127.0.0.1:20241";
/// Larger than any cloudflared release (about 40 MB).
pub const MAX_BINARY: u64 = 200 * 1024 * 1024;

/// A cloudflared release and the SHA-256 of its binary for this machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Build {
    pub version: String,
    pub sha256: String,
}

impl Build {
    pub fn check(&self) -> Result<(), String> {
        if version_key(&self.version).is_none() {
            return Err(format!("unexpected cloudflared version {:?}", self.version));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err("malformed cloudflared digest".into());
        }
        Ok(())
    }
}

/// `YYYY.M.P` as numbers, for ordering releases.
pub fn version_key(v: &str) -> Option<(u32, u32, u32)> {
    let mut parts = v.split('.');
    let year = parts.next()?;
    let key = (
        year.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    (year.len() == 4 && parts.next().is_none()).then_some(key)
}

/// A binary that matched its manifest.
#[derive(Clone, Debug)]
pub struct Binary {
    pub path: PathBuf,
    pub build: Build,
    /// Shipped in the image (rather than downloaded by the updater).
    pub bundled: bool,
}

/// Where the connector's builds live.
#[derive(Clone, Debug)]
pub struct Store {
    bundled_binary: PathBuf,
    bundled_manifest: PathBuf,
    /// Downloaded builds: `cloudflared-<version>` plus `cloudflared.json`.
    updates: PathBuf,
}

impl Store {
    /// The image's build (`AEGIS_CLOUDFLARED`, `AEGIS_CLOUDFLARED_MANIFEST`
    /// override the paths) and downloads under `data_dir/cloudflared`.
    pub fn new(data_dir: &Path) -> Self {
        let env = |name: &str, default: &str| {
            std::env::var_os(name).map_or_else(|| PathBuf::from(default), PathBuf::from)
        };
        Store {
            bundled_binary: env("AEGIS_CLOUDFLARED", "/usr/local/bin/cloudflared"),
            bundled_manifest: env(
                "AEGIS_CLOUDFLARED_MANIFEST",
                "/usr/share/aegisnet/cloudflared.json",
            ),
            updates: data_dir.join("cloudflared"),
        }
    }

    pub fn updates(&self) -> &Path {
        &self.updates
    }

    pub fn update_manifest(&self) -> PathBuf {
        self.updates.join("cloudflared.json")
    }

    pub fn update_binary(&self, version: &str) -> PathBuf {
        self.updates.join(format!("cloudflared-{version}"))
    }

    pub fn bundled(&self) -> Result<Binary, String> {
        let build = read_manifest(&self.bundled_manifest)
            .map_err(|e| format!("the bundled cloudflared has no valid manifest ({e})"))?;
        verify(&self.bundled_binary, &build)?;
        Ok(Binary {
            path: self.bundled_binary.clone(),
            build,
            bundled: true,
        })
    }

    pub fn downloaded(&self) -> Result<Binary, String> {
        let build = read_manifest(&self.update_manifest())?;
        let path = self.update_binary(&build.version);
        verify(&path, &build)?;
        Ok(Binary {
            path,
            build,
            bundled: false,
        })
    }

    /// The newest build that verifies. `Err` explains why the integration
    /// is unavailable on this installation.
    pub fn best(&self) -> Result<Binary, String> {
        match (self.bundled(), self.downloaded()) {
            (Ok(b), Ok(d)) => Ok(if newer(&d.build.version, &b.build.version) {
                d
            } else {
                b
            }),
            (Ok(b), Err(_)) => Ok(b),
            (Err(_), Ok(d)) => Ok(d),
            (Err(e), Err(_)) => Err(e),
        }
    }
}

/// Whether release `a` is newer than `b`.
pub fn newer(a: &str, b: &str) -> bool {
    match (version_key(a), version_key(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

fn read_manifest(path: &Path) -> Result<Build, String> {
    let text =
        std::fs::read_to_string(path).map_err(|_| format!("{} is missing", path.display()))?;
    let build: Build =
        serde_json::from_str(&text).map_err(|_| format!("{} is malformed", path.display()))?;
    build.check()?;
    Ok(build)
}

/// The binary at `path` is a regular file with the build's digest.
pub fn verify(path: &Path, build: &Build) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::metadata(path).map_err(|_| {
        format!(
            "cloudflared {} is not installed at {}",
            build.version,
            path.display()
        )
    })?;
    if !meta.is_file() || meta.len() > MAX_BINARY {
        return Err("cloudflared binary is not a regular file".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "cloudflared binary is unreadable".to_owned())?;
    if hex::encode(Sha256::digest(&bytes)) != build.sha256 {
        return Err(format!(
            "cloudflared binary does not match the {} digest",
            build.version
        ));
    }
    Ok(())
}

pub struct Connector {
    store: Store,
    token_file: PathBuf,
    /// The build started last.
    current: Mutex<Option<Build>>,
    desired: AtomicBool,
    running: Arc<AtomicBool>,
    ready: AtomicBool,
    child: Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>,
    supervisor: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Connector {
    pub fn new(store: Store, token_file: PathBuf) -> Self {
        Connector {
            store,
            token_file,
            current: Mutex::new(None),
            desired: AtomicBool::new(false),
            running: Arc::new(AtomicBool::new(false)),
            ready: AtomicBool::new(false),
            child: Arc::new(tokio::sync::Mutex::new(None)),
            supervisor: Mutex::new(None),
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The build running (or started last), if any.
    pub fn current(&self) -> Option<Build> {
        self.current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn enabled(&self) -> bool {
        self.desired.load(Ordering::SeqCst)
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Last sampled edge connectivity (for status displays).
    pub fn last_ready(&self) -> bool {
        self.running() && self.ready.load(Ordering::SeqCst)
    }

    /// Start (or restart) supervision with the newest verified build.
    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        let binary = self.store.best()?;
        if !self.token_file.is_file() {
            return Err("connector token missing".into());
        }
        self.stop().await;
        self.desired.store(true, Ordering::SeqCst);
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(binary.build.clone());
        let me = Arc::clone(self);
        let handle = tokio::spawn(async move { me.supervise(binary.path).await });
        *self.supervisor.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }

    async fn supervise(self: Arc<Self>, binary: PathBuf) {
        let mut backoff = Duration::from_secs(1);
        while self.desired.load(Ordering::SeqCst) {
            let spawned = tokio::process::Command::new(&binary)
                .args([
                    "tunnel",
                    "--no-autoupdate",
                    "--loglevel",
                    "error",
                    "--metrics",
                    METRICS,
                    "run",
                    "--token-file",
                ])
                .arg(&self.token_file)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn();
            let started = std::time::Instant::now();
            match spawned {
                Ok(child) => {
                    self.running.store(true, Ordering::SeqCst);
                    *self.child.lock().await = Some(child);
                    let mut ticks = 0u32;
                    loop {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        ticks = ticks.wrapping_add(1);
                        if ticks.is_multiple_of(10) {
                            self.ready.store(self.ready().await, Ordering::SeqCst);
                        }
                        let mut guard = self.child.lock().await;
                        match guard.as_mut() {
                            Some(c) => match c.try_wait() {
                                Ok(None) => continue,
                                _ => {
                                    *guard = None;
                                    break;
                                }
                            },
                            None => break,
                        }
                    }
                    self.running.store(false, Ordering::SeqCst);
                    self.ready.store(false, Ordering::SeqCst);
                }
                Err(_) => self.running.store(false, Ordering::SeqCst),
            }
            if !self.desired.load(Ordering::SeqCst) {
                break;
            }
            if started.elapsed() > Duration::from_secs(120) {
                backoff = Duration::from_secs(1);
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }

    pub async fn stop(&self) {
        self.desired.store(false, Ordering::SeqCst);
        if let Some(mut c) = self.child.lock().await.take() {
            let _ = c.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(5), c.wait()).await;
        }
        let handle = self
            .supervisor
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(h) = handle {
            h.abort();
        }
        self.running.store(false, Ordering::SeqCst);
    }

    /// Whether the connector reports an established edge connection.
    pub async fn ready(&self) -> bool {
        if !self.running() {
            return false;
        }
        let ready = self.probe_ready().await;
        self.ready.store(ready, Ordering::SeqCst);
        ready
    }

    async fn probe_ready(&self) -> bool {
        let probe = async {
            let mut s = tokio::net::TcpStream::connect(METRICS).await.ok()?;
            s.write_all(b"GET /ready HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .await
                .ok()?;
            let mut buf = Vec::new();
            let _ = (&mut s).take(4096).read_to_end(&mut buf).await;
            Some(buf.starts_with(b"HTTP/1.1 200"))
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(3), probe).await,
            Ok(Some(true))
        )
    }

    /// Wait until ready or the deadline passes.
    pub async fn wait_ready(&self, deadline: Duration) -> bool {
        let end = tokio::time::Instant::now() + deadline;
        while tokio::time::Instant::now() < end {
            if self.ready().await {
                return true;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn put(dir: &Path, name: &str, version: &str, body: &[u8]) -> Build {
        let build = Build {
            version: version.into(),
            sha256: hex::encode(Sha256::digest(body)),
        };
        std::fs::write(dir.join(name), body).expect("binary");
        build
    }

    fn manifest(path: &Path, build: &Build) {
        std::fs::write(path, serde_json::to_vec(build).expect("json")).expect("manifest");
    }

    #[test]
    fn versions_order_numerically() {
        assert_eq!(version_key("2026.10.4"), Some((2026, 10, 4)));
        assert!(newer("2026.10.10", "2026.10.9"));
        assert!(newer("2027.1.0", "2026.12.31"));
        assert!(!newer("2026.10.4", "2026.10.4"));
        for bad in [
            "latest",
            "2026.10",
            "2026.10.4.1",
            "26.10.4",
            "2026.x.1",
            "",
        ] {
            assert_eq!(version_key(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_newest_verified_build_runs() {
        let tmp = tempfile::tempdir().expect("tmp");
        let store = Store {
            bundled_binary: tmp.path().join("bundled"),
            bundled_manifest: tmp.path().join("bundled.json"),
            updates: tmp.path().join("updates"),
        };
        assert!(store.best().is_err(), "nothing installed");
        let bundled = put(tmp.path(), "bundled", "2026.10.0", b"old");
        manifest(&store.bundled_manifest, &bundled);
        assert_eq!(store.best().expect("bundled").build, bundled);

        std::fs::create_dir_all(store.updates()).expect("dir");
        let name = "cloudflared-2026.10.4";
        let update = put(store.updates(), name, "2026.10.4", b"new");
        manifest(&store.update_manifest(), &update);
        let best = store.best().expect("update");
        assert_eq!((best.build, best.bundled), (update.clone(), false));

        // A tampered download is skipped.
        std::fs::write(store.update_binary("2026.10.4"), b"evil").expect("tamper");
        assert_eq!(store.best().expect("fallback").build, bundled);
        // An older download never replaces a newer image.
        let older = put(
            store.updates(),
            "cloudflared-2026.9.0",
            "2026.9.0",
            b"older",
        );
        manifest(&store.update_manifest(), &older);
        assert_eq!(store.best().expect("bundled again").build, bundled);
        // Neither verifies: the reason is the image's.
        std::fs::write(&store.bundled_binary, b"evil").expect("tamper");
        std::fs::write(store.update_binary("2026.9.0"), b"evil").expect("tamper");
        assert!(store.best().expect_err("none").contains("2026.10.0"));
    }
}
