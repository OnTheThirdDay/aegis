//! Supervised Cloudflare connector (`cloudflared`) for the embedded tunnel.
//!
//! * The binary is bundled in the image and verified against pinned SHA-256
//!   digests before every start; a mismatch disables the integration.
//! * The tunnel token is read from an owner-only file (`--token-file`), never
//!   from arguments or the environment.
//! * Output is discarded (privacy default); health comes from the
//!   connector's loopback `/ready` endpoint.
//! * The child runs with this process's unprivileged identity and is
//!   restarted with backoff while the integration is enabled.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Pinned connector release (published 2026-10-05; checksums from the
/// release notes, verified at image build and again before each start).
pub const CLOUDFLARED_VERSION: &str = "2026.10.0";
pub const CLOUDFLARED_SHA256: &[(&str, &str)] = &[
    (
        "x86_64",
        "d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db",
    ),
    (
        "aarch64",
        "e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08",
    ),
];
const METRICS: &str = "127.0.0.1:20241";

pub struct Connector {
    binary: PathBuf,
    token_file: PathBuf,
    desired: AtomicBool,
    running: Arc<AtomicBool>,
    ready: AtomicBool,
    child: Arc<tokio::sync::Mutex<Option<tokio::process::Child>>>,
    supervisor: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

pub fn default_binary() -> PathBuf {
    std::env::var_os("AEGIS_CLOUDFLARED")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/local/bin/cloudflared"))
}

/// Check the bundled binary. `Err` explains why the integration is
/// unavailable on this installation.
pub fn verify_binary(path: &Path) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    let meta = std::fs::metadata(path).map_err(|_| {
        format!(
            "cloudflared {CLOUDFLARED_VERSION} is not installed at {}",
            path.display()
        )
    })?;
    if !meta.is_file() || meta.len() > 200 * 1024 * 1024 {
        return Err("cloudflared binary is not a regular file".into());
    }
    let bytes = std::fs::read(path).map_err(|_| "cloudflared binary is unreadable".to_owned())?;
    let digest = hex::encode(Sha256::digest(&bytes));
    let expected = CLOUDFLARED_SHA256
        .iter()
        .find(|(arch, _)| *arch == std::env::consts::ARCH)
        .map(|(_, d)| *d)
        .ok_or_else(|| format!("no pinned cloudflared build for {}", std::env::consts::ARCH))?;
    if digest != expected {
        return Err(format!(
            "cloudflared binary does not match the pinned {CLOUDFLARED_VERSION} digest"
        ));
    }
    Ok(())
}

impl Connector {
    pub fn new(binary: PathBuf, token_file: PathBuf) -> Self {
        Connector {
            binary,
            token_file,
            desired: AtomicBool::new(false),
            running: Arc::new(AtomicBool::new(false)),
            ready: AtomicBool::new(false),
            child: Arc::new(tokio::sync::Mutex::new(None)),
            supervisor: Mutex::new(None),
        }
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

    /// Start (or restart) supervision. Verifies the binary first.
    pub async fn start(self: &Arc<Self>) -> Result<(), String> {
        verify_binary(&self.binary)?;
        if !self.token_file.is_file() {
            return Err("connector token missing".into());
        }
        self.stop().await;
        self.desired.store(true, Ordering::SeqCst);
        let me = Arc::clone(self);
        let handle = tokio::spawn(async move { me.supervise().await });
        *self.supervisor.lock().unwrap_or_else(|e| e.into_inner()) = Some(handle);
        Ok(())
    }

    async fn supervise(self: Arc<Self>) {
        let mut backoff = Duration::from_secs(1);
        while self.desired.load(Ordering::SeqCst) {
            let spawned = tokio::process::Command::new(&self.binary)
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
