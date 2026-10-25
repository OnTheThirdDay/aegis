//! Background engine: owns the tokio runtime, the enrolled device profile
//! and the running client node. The UI only sends [`Command`]s and reads
//! the shared [`Snapshot`].

use crate::settings::Settings;
use crate::sysproxy;
use aegis_join::{DeviceDir, Ports};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotEnrolled,
    Enrolling,
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub status: Status,
    pub device_name: Option<String>,
    pub server: Option<String>,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub certificate_expires_at: Option<i64>,
    pub connected_since: Option<Instant>,
    pub error: Option<String>,
    pub info: Option<String>,
    pub system_proxy_active: bool,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            status: Status::NotEnrolled,
            device_name: None,
            server: None,
            socks: None,
            http: None,
            bytes_up: 0,
            bytes_down: 0,
            certificate_expires_at: None,
            connected_since: None,
            error: None,
            info: None,
            system_proxy_active: false,
        }
    }
}

pub enum Command {
    Enroll(String),
    Connect,
    Disconnect,
    Forget,
    SaveSettings(Settings),
    Shutdown(std::sync::mpsc::Sender<()>),
}

pub struct Engine {
    tx: mpsc::UnboundedSender<Command>,
    pub state: Arc<Mutex<Snapshot>>,
    _runtime: tokio::runtime::Runtime,
}

fn host_of(url: &str) -> String {
    url.strip_prefix("wss://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_owned()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Engine {
    pub fn start(
        dir: PathBuf,
        settings: Settings,
        repaint: Box<dyn Fn() + Send + Sync>,
    ) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let state = Arc::new(Mutex::new(Snapshot::default()));
        let (tx, rx) = mpsc::unbounded_channel();
        let worker = Worker {
            device: DeviceDir::new(dir),
            settings,
            state: Arc::clone(&state),
            node: None,
            repaint,
            proxy_saved: None,
        };
        runtime.spawn(worker.run(rx));
        Ok(Engine {
            tx,
            state,
            _runtime: runtime,
        })
    }

    pub fn send(&self, c: Command) {
        let _ = self.tx.send(c);
    }

    pub fn snapshot(&self) -> Snapshot {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Disconnect and restore system settings before the process exits.
    pub fn shutdown(&self) {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        self.send(Command::Shutdown(done_tx));
        let _ = done_rx.recv_timeout(Duration::from_secs(5));
    }
}

struct Worker {
    device: DeviceDir,
    settings: Settings,
    state: Arc<Mutex<Snapshot>>,
    node: Option<aegis_node::NodeRuntime>,
    repaint: Box<dyn Fn() + Send + Sync>,
    proxy_saved: Option<sysproxy::Saved>,
}

impl Worker {
    fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
        (self.repaint)();
    }

    fn load_device(&self) {
        match self.device.load() {
            Ok(d) => {
                let exp = self.device.certificate_expires_at().ok();
                self.update(|s| {
                    s.device_name = Some(d.name.clone());
                    s.server = Some(host_of(&d.url));
                    s.certificate_expires_at = exp;
                    if s.status == Status::NotEnrolled || s.status == Status::Enrolling {
                        s.status = Status::Disconnected;
                    }
                });
            }
            Err(_) => self.update(|s| {
                *s = Snapshot {
                    error: s.error.take(),
                    ..Snapshot::default()
                };
            }),
        }
    }

    async fn run(mut self, mut rx: mpsc::UnboundedReceiver<Command>) {
        // A crash while the system proxy pointed at us would leave the
        // machine without working web access: undo it first.
        if let Some(saved) = self.settings.proxy_saved.take() {
            let _ = sysproxy::restore(&saved);
            let _ = self.settings.save();
        }
        self.load_device();
        if self.settings.auto_connect && self.device.load().is_ok() {
            self.connect().await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut checks = 0u32;
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        Command::Enroll(code) => self.enroll(code).await,
                        Command::Connect => self.connect().await,
                        Command::Disconnect => self.disconnect().await,
                        Command::Forget => {
                            self.disconnect().await;
                            match self.device.forget() {
                                Ok(()) => self.update(|s| s.info = Some("Server removed from this device.".into())),
                                Err(e) => self.update(|s| s.error = Some(e.to_string())),
                            }
                            self.load_device();
                        }
                        Command::SaveSettings(next) => {
                            let reconnect = self.node.is_some()
                                && (next.socks_port != self.settings.socks_port
                                    || next.http_port != self.settings.http_port
                                    || next.system_proxy != self.settings.system_proxy);
                            self.settings = Settings { proxy_saved: self.settings.proxy_saved.clone(), ..next };
                            if let Err(e) = self.settings.save() {
                                self.update(|s| s.error = Some(format!("Could not save settings: {e}")));
                            }
                            if reconnect {
                                self.disconnect().await;
                                self.connect().await;
                            }
                        }
                        Command::Shutdown(done) => {
                            self.disconnect().await;
                            let _ = done.send(());
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    checks = checks.wrapping_add(1);
                    self.refresh(checks.is_multiple_of(15)).await;
                }
            }
        }
    }

    async fn enroll(&mut self, code: String) {
        self.update(|s| {
            s.status = Status::Enrolling;
            s.error = None;
            s.info = None;
        });
        let result = async {
            let invite = aegis_join::parse_invite(&code)?;
            aegis_join::enroll(&invite, &self.device).await
        }
        .await;
        match result {
            Ok(d) => {
                self.update(|s| {
                    s.status = Status::Disconnected;
                    s.info = Some(format!("Joined {} as \"{}\".", host_of(&d.url), d.name));
                });
                self.load_device();
                self.connect().await;
            }
            Err(e) => self.update(|s| {
                s.status = Status::NotEnrolled;
                s.error = Some(e.to_string());
            }),
        }
    }

    async fn connect(&mut self) {
        if self.node.is_some() {
            return;
        }
        self.update(|s| {
            s.status = Status::Connecting;
            s.error = None;
        });
        // Renew ahead of expiry; a failure is fine while the current
        // certificate is still valid.
        match aegis_join::renew_if_due(&self.device, false).await {
            Ok(true) => self.update(|s| s.info = Some("Device certificate renewed.".into())),
            Ok(false) => {}
            Err(e) => {
                let expired = self
                    .device
                    .certificate_expires_at()
                    .is_ok_and(|exp| exp <= now());
                if expired {
                    self.update(|s| {
                        s.status = Status::Disconnected;
                        s.error = Some(format!(
                            "This device's certificate expired and could not be renewed ({e}). Ask for a new invitation."
                        ));
                    });
                    return;
                }
            }
        }
        let ports = Ports {
            socks: self.settings.socks_port,
            http: self.settings.http_port,
        };
        let cfg = match aegis_join::client_config(&self.device, ports) {
            Ok(c) => c,
            Err(e) => {
                self.update(|s| {
                    s.status = Status::Disconnected;
                    s.error = Some(e.to_string());
                });
                return;
            }
        };
        // The client keeps no durable state: start from the profile.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(self.device.root.join(format!("state.db{suffix}")));
        }
        let started = aegis_node::start(aegis_node::StartOptions {
            config: cfg,
            store_path: self.device.store(),
            failpoints: None,
        })
        .await;
        let node = match started {
            Ok(n) => n,
            Err(e) => {
                let msg = match e {
                    aegis_node::StartError::Bind(_) => format!(
                        "A local port is already in use (SOCKS {} / HTTP {}). Close the other program or change the ports in Settings.",
                        ports.socks, ports.http
                    ),
                    aegis_node::StartError::Identity(_) => {
                        "The device identity could not be loaded. Remove the server and join again with a new invitation.".into()
                    }
                    other => format!("Could not start: {other}"),
                };
                self.update(|s| {
                    s.status = Status::Disconnected;
                    s.error = Some(msg);
                });
                return;
            }
        };
        let socks = node.bound_addr("socks");
        let http = node.bound_addr("http");
        self.node = Some(node);
        self.update(|s| {
            s.socks = socks;
            s.http = http;
        });
        if self.settings.system_proxy {
            if let Some(h) = http {
                match sysproxy::enable(h.port()) {
                    Ok(saved) => {
                        self.settings.proxy_saved = Some(saved.clone());
                        let _ = self.settings.save();
                        self.proxy_saved = Some(saved);
                        self.update(|s| s.system_proxy_active = true);
                    }
                    Err(e) => self.update(|s| s.error = Some(format!("System proxy: {e}"))),
                }
            }
        }
        self.refresh(true).await;
    }

    async fn disconnect(&mut self) {
        if let Some(saved) = self.proxy_saved.take() {
            let _ = sysproxy::restore(&saved);
            self.settings.proxy_saved = None;
            let _ = self.settings.save();
        }
        if let Some(node) = self.node.take() {
            node.shutdown(Duration::from_secs(1)).await;
        }
        let enrolled = self.device.load().is_ok();
        self.update(|s| {
            s.status = if enrolled {
                Status::Disconnected
            } else {
                Status::NotEnrolled
            };
            s.socks = None;
            s.http = None;
            s.connected_since = None;
            s.system_proxy_active = false;
            s.error = None;
        });
    }

    /// Refresh counters; with `probe`, verify the gateway end to end.
    async fn refresh(&mut self, probe: bool) {
        let Some(node) = &self.node else { return };
        let gauges = node.ctx.gauges();
        let m = node.ctx.metrics.snapshot(gauges);
        let live = gauges.sessions_active > 0;
        let mut verified = None;
        if probe || !live {
            if let Some(socks) = node.bound_addr("socks") {
                verified = Some(verify(socks).await);
            }
        }
        self.update(|s| {
            s.bytes_up = m.transport_bytes_up;
            s.bytes_down = m.transport_bytes_down;
            match verified {
                Some(Ok(())) => {
                    if s.status != Status::Connected {
                        s.connected_since = Some(Instant::now());
                    }
                    s.status = Status::Connected;
                    s.error = None;
                }
                Some(Err(e)) => {
                    s.status = Status::Connecting;
                    s.connected_since = None;
                    s.error = Some(e);
                }
                None => {}
            }
        });
    }
}

/// Open a stream to `localhost:9` through the tunnel: the gateway must
/// refuse it by policy (SOCKS reply 2), which proves the authenticated
/// session works without contacting any third party.
async fn verify(socks: SocketAddr) -> Result<(), String> {
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(socks).await.ok()?;
        s.write_all(&[5, 1, 0]).await.ok()?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.ok()?;
        let host = b"localhost";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&9u16.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.ok()?;
        Some(head[1])
    };
    match tokio::time::timeout(Duration::from_secs(15), attempt).await {
        Ok(Some(2)) => Ok(()),
        Ok(Some(_)) | Ok(None) | Err(_) => Err(
            "Cannot reach the server yet — retrying. Check the network, or ask the administrator whether this device was removed.".into(),
        ),
    }
}
