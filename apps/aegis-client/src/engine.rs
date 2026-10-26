//! Background engine: owns the tokio runtime, the enrolled device profile
//! and the running client node. The UI only sends [`Command`]s and reads
//! the shared [`Snapshot`].

use crate::settings::Settings;
use crate::sysproxy;
use aegis_join::{DeviceDir, JoinError, Ports};
use aegis_telemetry::report::{Report, Role};
use aegis_telemetry::{DiagnosticSink, Severity};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
    /// Outcome of the last diagnostics send/save: (success, message).
    pub diag_message: Option<(bool, String)>,
    pub diag_sending: bool,
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
            diag_message: None,
            diag_sending: false,
        }
    }
}

pub enum Command {
    Enroll(String),
    Connect,
    Disconnect,
    Forget,
    SaveSettings(Settings),
    /// Start an on-demand diagnostics recording for this many minutes.
    DiagStart(u64),
    /// Stop recording; with `true`, send the report to the server.
    DiagStop(bool),
    DiagSend,
    DiagSave,
    DiagDiscard,
    Shutdown(std::sync::mpsc::Sender<()>),
}

pub struct Engine {
    tx: mpsc::UnboundedSender<Command>,
    pub state: Arc<Mutex<Snapshot>>,
    /// On-demand diagnostics: off unless the user starts it, memory only,
    /// stops by itself. Survives reconnects.
    pub diag: Arc<DiagnosticSink>,
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
        let diag = Arc::new(DiagnosticSink::new());
        let worker = Worker {
            data_dir: dir.clone(),
            diag: Arc::clone(&diag),
            diag_was_recording: false,
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
            diag,
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
    data_dir: PathBuf,
    diag: Arc<DiagnosticSink>,
    /// Send the report automatically when a recording ends by itself.
    diag_was_recording: bool,
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
                        Command::DiagStart(minutes) => self.diag_start(minutes),
                        Command::DiagStop(send) => {
                            self.diag.stop();
                            self.diag_was_recording = false;
                            if send {
                                self.diag_send().await;
                            }
                        }
                        Command::DiagSend => self.diag_send().await,
                        Command::DiagSave => self.diag_save(),
                        Command::DiagDiscard => {
                            self.diag.discard();
                            self.diag_was_recording = false;
                            self.update(|s| s.diag_message = None);
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
                    let recording = self.diag.is_recording();
                    if self.diag_was_recording && !recording {
                        // The recording ran out: hand it to the server.
                        self.diag_was_recording = false;
                        self.diag_send().await;
                    }
                    self.diag_was_recording = recording;
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
                self.diag.note(
                    Severity::Warn,
                    "client.renew.failed",
                    &[("error", &e.to_string())],
                );
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
        self.diag.note(Severity::Info, "client.connect", &[]);
        if let Some(node) = self.follow_endpoint(ports).await {
            self.install(node).await;
            return;
        }
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
        let node = match self.start_node(cfg).await {
            Ok(n) => n,
            Err(e) => {
                self.diag.note(
                    Severity::Error,
                    "client.start.failed",
                    &[("error", &e.to_string())],
                );
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
        self.install(node).await;
    }

    async fn start_node(
        &self,
        config: aegis_config::NodeConfig,
    ) -> Result<aegis_node::NodeRuntime, aegis_node::StartError> {
        // The client keeps no durable state: start from the profile.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(self.device.root.join(format!("state.db{suffix}")));
        }
        aegis_node::start_with_diagnostics(
            aegis_node::StartOptions {
                config,
                store_path: self.device.store(),
                failpoints: None,
            },
            Arc::clone(&self.diag),
        )
        .await
    }

    /// Follow a changed server address: ask the gateway for its current
    /// endpoint and, if it differs, try it. It is kept only when the
    /// gateway's pinned identity answers there (the end-to-end check), so a
    /// tampered answer can't redirect the device; otherwise the stored
    /// address is used as before. Returns the running node on success.
    async fn follow_endpoint(&mut self, ports: Ports) -> Option<aegis_node::NodeRuntime> {
        let endpoint = match aegis_join::fetch_endpoint(&self.device).await {
            Ok(Some(e)) => e,
            Ok(None) => return None,
            Err(e) => {
                self.diag.note(
                    Severity::Info,
                    "client.endpoint.unchecked",
                    &[("error", &e.to_string())],
                );
                return None;
            }
        };
        self.diag.note(
            Severity::Info,
            "client.endpoint.changed",
            &[("url", &endpoint.url)],
        );
        let cfg = aegis_join::client_config_for(&self.device, ports, Some(&endpoint)).ok()?;
        let node = self.start_node(cfg).await.ok()?;
        let verified = match node.bound_addr("socks") {
            Some(socks) => verify(socks).await.is_ok(),
            None => false,
        };
        if verified {
            if let Ok(device) = aegis_join::adopt_endpoint(&self.device, &endpoint) {
                let host = host_of(&device.url);
                self.update(|s| {
                    s.server = Some(host.clone());
                    s.info = Some(format!("The server's address changed; now using {host}."));
                });
                return Some(node);
            }
        }
        self.diag.note(
            Severity::Warn,
            "client.endpoint.rejected",
            &[("url", &endpoint.url)],
        );
        node.shutdown(Duration::from_secs(1)).await;
        None
    }

    /// Take over a started node: proxies, optional system proxy, status.
    async fn install(&mut self, node: aegis_node::NodeRuntime) {
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
        if self.node.is_some() {
            self.diag.note(Severity::Info, "client.disconnect", &[]);
        }
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
                let result = verify(socks).await;
                match &result {
                    Ok(()) => self.diag.count("client.check.ok"),
                    // A note also counts towards the per-kind total.
                    Err(_) => self.diag.note(Severity::Warn, "client.check.failed", &[]),
                }
                verified = Some(result);
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

impl Worker {
    fn diag_start(&mut self, minutes: u64) {
        match self
            .diag
            .start(Duration::from_secs(minutes.saturating_mul(60)))
        {
            Ok(()) => {
                self.diag_was_recording = true;
                let ports = format!(
                    "socks {} http {}",
                    self.settings.socks_port, self.settings.http_port
                );
                self.diag.note(
                    Severity::Info,
                    "client.info",
                    &[
                        ("version", env!("CARGO_PKG_VERSION")),
                        ("os", std::env::consts::OS),
                        ("arch", std::env::consts::ARCH),
                        ("connected", if self.node.is_some() { "yes" } else { "no" }),
                        ("ports", &ports),
                        (
                            "system_proxy",
                            if self.settings.system_proxy {
                                "on"
                            } else {
                                "off"
                            },
                        ),
                    ],
                );
                self.update(|s| s.diag_message = None);
            }
            Err(e) => self.update(|s| s.diag_message = Some((false, e.to_string()))),
        }
    }

    fn report(&self) -> Option<Report> {
        let recording = self.diag.recording()?;
        Some(Report {
            role: Role::Client,
            name: self
                .device
                .load()
                .map(|d| d.name)
                .unwrap_or_else(|_| "unenrolled device".into()),
            version: env!("CARGO_PKG_VERSION").into(),
            recording,
        })
    }

    async fn diag_send(&mut self) {
        let Some(mut report) = self.report() else {
            return;
        };
        if self.device.load().is_err() {
            self.update(|s| {
                s.diag_message = Some((
                    false,
                    "This device hasn't joined a server; use Save to file instead.".into(),
                ))
            });
            return;
        }
        self.update(|s| {
            s.diag_sending = true;
            s.diag_message = None;
        });
        // Leave headroom under the gateway's limit for base64 and JSON.
        let gz = report.to_gzip(900 * 1024);
        let result = aegis_join::upload_diagnostics(&self.device, &gz).await;
        let message = match result {
            Ok(()) => (
                true,
                "Report sent. Your administrator can now see it under Diagnostics.".to_owned(),
            ),
            Err(JoinError::Rejected { status: 409, .. }) => (
                false,
                "Diagnostics are off on the server. Ask your administrator to start them in the console (Diagnostics), then press Send again.".to_owned(),
            ),
            Err(JoinError::Network(_)) => (
                false,
                "Could not reach the server to send the report. Press Save to file and give the file to your administrator.".to_owned(),
            ),
            Err(e) => (false, format!("Could not send the report: {e}")),
        };
        self.update(|s| {
            s.diag_sending = false;
            s.diag_message = Some(message);
        });
    }

    fn diag_save(&mut self) {
        let Some(report) = self.report() else {
            return;
        };
        let path = self
            .data_dir
            .join(format!("aegisnet-diagnostics-{}.otlp.json", now()));
        let body = serde_json::to_vec_pretty(&report.to_otlp()).unwrap_or_default();
        let message = match std::fs::write(&path, body) {
            Ok(()) => (true, format!("Saved to {}", path.display())),
            Err(e) => (false, format!("Could not save the report: {e}")),
        };
        self.update(|s| s.diag_message = Some(message));
    }
}

/// The end-to-end check, with the message the window shows on failure.
async fn verify(socks: SocketAddr) -> Result<(), String> {
    if aegis_join::verify_tunnel(socks).await {
        Ok(())
    } else {
        Err("Cannot reach the server yet — retrying. Check the network, or ask the administrator whether this device was removed.".into())
    }
}
