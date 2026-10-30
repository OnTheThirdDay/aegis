//! Background engine: owns the tokio runtime, the joined servers (one
//! device profile each) and the running client node, connected to the
//! selected server. The UI only sends [`Command`]s and reads
//! the shared [`Snapshot`].

use crate::settings::Settings;
use crate::sysproxy;
use aegis_join::{DeviceDir, JoinError, Ports, Servers};
use aegis_telemetry::report::{Report, Role};
use aegis_telemetry::{DiagnosticSink, Severity};
use aegis_vpn::client::{HelperState, Session};
use aegis_vpn::proto::Counters;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How often a connected client checks whether its certificate is due for
/// renewal (renewal itself starts 10 days before expiry).
const RENEWAL_CHECK: Duration = Duration::from_secs(6 * 3600);
/// How often a connected app asks its server for a newer version.
const UPDATE_CHECK: Duration = Duration::from_secs(6 * 3600);
/// A changed server address that couldn't be verified from this network is
/// tried again after this long (each try can take ~15 s before falling back).
const ENDPOINT_RETRY: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    NotEnrolled,
    Disconnected,
    Connecting,
    Connected,
}

/// A joined server, as listed in the window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerEntry {
    pub id: String,
    pub server: String,
    pub device_name: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub status: Status,
    /// Every joined server, oldest first, and the one in use.
    pub servers: Vec<ServerEntry>,
    pub selected: Option<String>,
    /// An invitation is being redeemed.
    pub joining: bool,
    pub device_name: Option<String>,
    pub server: Option<String>,
    pub socks: Option<SocketAddr>,
    pub http: Option<SocketAddr>,
    pub bytes_up: u64,
    pub bytes_down: u64,
    /// What carries the tunnel: `quic` or `websocket`.
    pub transport: Option<&'static str>,
    pub certificate_expires_at: Option<i64>,
    pub connected_since: Option<Instant>,
    pub error: Option<String>,
    pub info: Option<String>,
    pub system_proxy_active: bool,
    /// The system VPN's helper, whether the VPN is up, and its counters.
    pub vpn_helper: HelperState,
    pub vpn_active: bool,
    pub vpn_counters: Counters,
    /// Installing or removing the helper (waiting for the administrator).
    pub vpn_busy: bool,
    /// Outcome of the last helper install/removal: (success, message).
    pub vpn_message: Option<(bool, String)>,
    /// Outcome of the last diagnostics send/save: (success, message).
    pub diag_message: Option<(bool, String)>,
    pub diag_sending: bool,
    /// A newer version of this app that the server offers.
    pub update: UpdateState,
}

/// A newer version of this app, offered by the server (ADR-0017). The app
/// never installs it by itself.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum UpdateState {
    #[default]
    None,
    Available(String),
    Downloading {
        version: String,
        done: u64,
        total: u64,
    },
    /// In place; restarting starts it.
    Ready {
        version: String,
        start: PathBuf,
    },
    Failed {
        version: String,
        message: String,
    },
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            status: Status::NotEnrolled,
            servers: Vec::new(),
            selected: None,
            joining: false,
            device_name: None,
            server: None,
            socks: None,
            http: None,
            bytes_up: 0,
            bytes_down: 0,
            transport: None,
            certificate_expires_at: None,
            connected_since: None,
            error: None,
            info: None,
            system_proxy_active: false,
            vpn_helper: HelperState::Unsupported,
            vpn_active: false,
            vpn_counters: Counters::default(),
            vpn_busy: false,
            vpn_message: None,
            diag_message: None,
            diag_sending: false,
            update: UpdateState::None,
        }
    }
}

pub enum Command {
    /// Join another server with an invitation, then connect to it.
    Enroll(String),
    /// Use this server; reconnects if connected to another.
    Select(String),
    Connect,
    Disconnect,
    /// Remove a server from this device.
    Forget(String),
    SaveSettings(Settings),
    /// Install or update the system VPN's helper (administrator prompt).
    InstallVpnHelper,
    /// Release a kill switch that blocks traffic after the VPN stopped.
    Unblock,
    RemoveVpnHelper,
    /// Start an on-demand diagnostics recording for this many minutes.
    DiagStart(u64),
    /// Stop recording; with `true`, send the report to the server.
    DiagStop(bool),
    DiagSend,
    DiagSave,
    DiagDiscard,
    /// Download the offered update and put it in this app's place.
    InstallUpdate,
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
        let servers = Servers::open(&dir).map_err(|e| e.to_string())?;
        let worker = Worker {
            data_dir: dir,
            diag: Arc::clone(&diag),
            diag_was_recording: false,
            servers,
            device: None,
            settings,
            state: Arc::clone(&state),
            node: None,
            repaint: Arc::from(repaint),
            proxy_saved: None,
            vpn: None,
            endpoint_failed: None,
            offer: None,
            update_checked: None,
            update_job: None,
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
    servers: Servers,
    /// The selected server's profile.
    device: Option<DeviceDir>,
    settings: Settings,
    state: Arc<Mutex<Snapshot>>,
    node: Option<aegis_node::NodeRuntime>,
    repaint: Arc<dyn Fn() + Send + Sync>,
    proxy_saved: Option<sysproxy::Saved>,
    /// The system VPN, while it runs.
    vpn: Option<Session>,
    /// A changed server address that failed its check here, and when: it
    /// isn't tried again on every reconnect (see ENDPOINT_RETRY).
    endpoint_failed: Option<(String, Instant)>,
    /// The update the server offers, checked and signed (ADR-0017).
    offer: Option<aegis_join::update::Update>,
    update_checked: Option<Instant>,
    /// Downloading and installing an update: a task of its own, so that
    /// Disconnect and Shutdown are handled meanwhile (Shutdown cancels it).
    update_job: Option<tokio::task::JoinHandle<()>>,
}

impl Worker {
    fn update(&self, f: impl FnOnce(&mut Snapshot)) {
        f(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()));
        (self.repaint)();
    }

    /// Read the joined servers and the selection into the snapshot.
    fn load_servers(&mut self) {
        let entries: Vec<ServerEntry> = self
            .servers
            .list()
            .iter()
            .map(|s| ServerEntry {
                id: s.id.clone(),
                server: s.host(),
                device_name: s.device.name.clone(),
            })
            .collect();
        let selected = self.servers.selected();
        self.device = selected.as_ref().map(|s| s.dir.clone());
        match selected {
            Some(sel) => {
                let exp = sel.dir.certificate_expires_at().ok();
                self.update(|s| {
                    s.servers = entries;
                    s.selected = Some(sel.id.clone());
                    s.device_name = Some(sel.device.name.clone());
                    s.server = Some(sel.host());
                    s.certificate_expires_at = exp;
                    if s.status == Status::NotEnrolled {
                        s.status = Status::Disconnected;
                    }
                });
            }
            None => self.update(|s| {
                *s = Snapshot {
                    error: s.error.take(),
                    info: s.info.take(),
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
        self.load_servers();
        self.check_helper().await;
        if self.settings.auto_connect && self.device.is_some() {
            self.connect().await;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(2));
        let mut checks = 0u32;
        let mut renewal_checked = Instant::now();
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    match cmd {
                        Command::Enroll(code) => self.enroll(code).await,
                        Command::Select(id) => self.select(id).await,
                        Command::Connect => self.connect().await,
                        Command::Disconnect => self.disconnect().await,
                        Command::Forget(id) => self.forget(id).await,
                        Command::SaveSettings(next) => {
                            let reconnect = self.node.is_some()
                                && (next.socks_port != self.settings.socks_port
                                    || next.http_port != self.settings.http_port
                                    || next.system_proxy != self.settings.system_proxy
                                    || next.system_vpn != self.settings.system_vpn
                                    || next.kill_switch != self.settings.kill_switch);
                            self.settings = Settings { proxy_saved: self.settings.proxy_saved.clone(), ..next };
                            if let Err(e) = self.settings.save() {
                                self.update(|s| s.error = Some(format!("Could not save settings: {e}")));
                            }
                            if reconnect {
                                self.disconnect().await;
                                self.connect().await;
                            }
                        }
                        Command::InstallVpnHelper => self.install_helper().await,
                        Command::Unblock => {
                            if let Err(e) = aegis_vpn::client::release().await {
                                self.update(|s| s.error = Some(e));
                            }
                            self.check_helper().await;
                        }
                        Command::RemoveVpnHelper => self.remove_helper().await,
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
                        Command::InstallUpdate => self.install_update().await,
                        Command::Shutdown(done) => {
                            if let Some(job) = self.update_job.take() {
                                job.abort();
                            }
                            self.disconnect().await;
                            let _ = done.send(());
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    checks = checks.wrapping_add(1);
                    self.refresh(checks.is_multiple_of(15)).await;
                    // A device left connected for weeks never passes through
                    // connect(): renew in the background too.
                    if self.node.is_some() && renewal_checked.elapsed() >= RENEWAL_CHECK {
                        renewal_checked = Instant::now();
                        self.renew_connected().await;
                    }
                    // Once connected, then every few hours.
                    if self.node.is_some()
                        && self.update_checked.is_none_or(|t| t.elapsed() >= UPDATE_CHECK)
                    {
                        self.update_checked = Some(Instant::now());
                        self.check_update().await;
                    }
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
            s.joining = true;
            s.error = None;
            s.info = None;
        });
        let result = match aegis_join::parse_invite(&code) {
            Ok(invite) => self.servers.join(&invite).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(server) => {
                // One connection at a time: leave the previous server.
                self.disconnect().await;
                self.endpoint_failed = None;
                self.update(|s| {
                    s.joining = false;
                    s.info = Some(format!(
                        "Joined {} as \"{}\".",
                        server.host(),
                        server.device.name
                    ));
                });
                self.load_servers();
                self.connect().await;
            }
            Err(e) => self.update(|s| {
                s.joining = false;
                s.error = Some(e.to_string());
            }),
        }
    }

    async fn select(&mut self, id: String) {
        if self.servers.selected().is_some_and(|s| s.id == id) {
            return;
        }
        let reconnect = self.node.is_some();
        self.disconnect().await;
        match self.servers.select(&id) {
            Ok(_) => {
                self.endpoint_failed = None;
                self.update(|s| s.info = None);
                self.load_servers();
                if reconnect {
                    self.connect().await;
                }
            }
            Err(e) => self.update(|s| s.error = Some(e.to_string())),
        }
    }

    async fn forget(&mut self, id: String) {
        if self.servers.selected().is_some_and(|s| s.id == id) {
            self.disconnect().await;
        }
        match self.servers.remove(&id) {
            Ok(()) => self.update(|s| s.info = Some("Server removed from this device.".into())),
            Err(e) => self.update(|s| s.error = Some(e.to_string())),
        }
        self.load_servers();
    }

    async fn connect(&mut self) {
        if self.node.is_some() {
            return;
        }
        let Some(device) = self.device.clone() else {
            return;
        };
        self.update(|s| {
            s.status = Status::Connecting;
            s.error = None;
        });
        // Renew ahead of expiry; a failure is fine while the current
        // certificate is still valid.
        match aegis_join::renew_if_due(&device, false).await {
            Ok(true) => self.update(|s| s.info = Some("Device certificate renewed.".into())),
            Ok(false) => {}
            Err(e) => {
                self.diag.note(
                    Severity::Warn,
                    "client.renew.failed",
                    &[("error", &e.to_string())],
                );
                let expired = device
                    .certificate_expires_at()
                    .is_ok_and(|exp| exp <= now());
                if expired {
                    self.update(|s| {
                        s.status = Status::Disconnected;
                        s.error = Some(format!(
                            "This device's certificate expired and could not be renewed ({e}). If it expired over 90 days ago or the device was removed, ask for a new invitation."
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
        if let Some(node) = self.follow_endpoint(&device, ports).await {
            self.install(node).await;
            return;
        }
        let cfg = match aegis_join::client_config(&device, ports) {
            Ok(c) => c,
            Err(e) => {
                self.update(|s| {
                    s.status = Status::Disconnected;
                    s.error = Some(e.to_string());
                });
                return;
            }
        };
        let node = match self.start_node(&device, cfg).await {
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
        device: &DeviceDir,
        config: aegis_config::NodeConfig,
    ) -> Result<aegis_node::NodeRuntime, aegis_node::StartError> {
        // The client keeps no durable state: start from the profile.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(device.root.join(format!("state.db{suffix}")));
        }
        aegis_node::start_with_diagnostics(
            aegis_node::StartOptions {
                config,
                store_path: device.store(),
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
    async fn follow_endpoint(
        &mut self,
        device: &DeviceDir,
        ports: Ports,
    ) -> Option<aegis_node::NodeRuntime> {
        let endpoint = match aegis_join::fetch_endpoint(device).await {
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
        if self
            .endpoint_failed
            .as_ref()
            .is_some_and(|(url, at)| *url == endpoint.url && at.elapsed() < ENDPOINT_RETRY)
        {
            return None;
        }
        self.diag.note(
            Severity::Info,
            "client.endpoint.changed",
            &[("url", &endpoint.url)],
        );
        let cfg = aegis_join::client_config_for(device, ports, Some(&endpoint)).ok()?;
        let node = self.start_node(device, cfg).await.ok()?;
        let verified = match node.bound_addr("socks") {
            Some(socks) => verify(socks).await.is_ok(),
            None => false,
        };
        if verified {
            if let Ok(adopted) = aegis_join::adopt_endpoint(device, &endpoint) {
                let host = host_of(&adopted.url);
                self.update(|s| {
                    s.server = Some(host.clone());
                    s.info = Some(format!("The server's address changed; now using {host}."));
                });
                self.endpoint_failed = None;
                self.load_servers();
                return Some(node);
            }
        }
        self.diag.note(
            Severity::Warn,
            "client.endpoint.rejected",
            &[("url", &endpoint.url)],
        );
        self.endpoint_failed = Some((endpoint.url.clone(), Instant::now()));
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
        if self.settings.system_vpn {
            if let Some(socks) = socks {
                self.start_vpn(socks.port()).await;
            }
        }
        self.refresh(true).await;
    }

    /// Bring the system VPN up for the running node; on failure the
    /// connection stays up for apps that use the proxy.
    async fn start_vpn(&mut self, socks_port: u16) {
        if !aegis_vpn::supported() || self.vpn.is_some() {
            return;
        }
        let bypass = self
            .device
            .as_ref()
            .and_then(|d| d.load().ok())
            .map(|d| bypass_hosts(&d))
            .unwrap_or_default();
        match Session::start(socks_port, bypass, self.settings.kill_switch).await {
            Ok(session) => {
                self.vpn = Some(session);
                self.diag.note(Severity::Info, "client.vpn.started", &[]);
                self.update(|s| {
                    s.vpn_active = true;
                    s.vpn_counters = Counters::default();
                    if let HelperState::Ready { blocked, .. } = &mut s.vpn_helper {
                        *blocked = false;
                    }
                });
            }
            Err(e) => {
                self.diag
                    .note(Severity::Warn, "client.vpn.failed", &[("error", &e)]);
                self.update(|s| {
                    s.vpn_active = false;
                    s.error = Some(format!("System VPN: {e}"));
                });
            }
        }
    }

    async fn stop_vpn(&mut self) {
        if let Some(session) = self.vpn.take() {
            session.stop().await;
            self.diag.note(Severity::Info, "client.vpn.stopped", &[]);
        }
        self.update(|s| s.vpn_active = false);
    }

    async fn check_helper(&mut self) {
        let state = aegis_vpn::client::state().await;
        self.update(|s| s.vpn_helper = state);
    }

    async fn install_helper(&mut self) {
        self.update(|s| {
            s.vpn_busy = true;
            s.vpn_message = None;
        });
        // An update replaces the running helper, which ends the VPN.
        let had_vpn = self.vpn.is_some();
        self.stop_vpn().await;
        let result = aegis_vpn::client::install().await;
        self.check_helper().await;
        let message = match &result {
            Ok(()) => (true, "VPN helper installed.".to_owned()),
            Err(e) => (false, e.clone()),
        };
        self.update(|s| {
            s.vpn_busy = false;
            s.vpn_message = Some(message);
        });
        let socks = self.node.as_ref().and_then(|n| n.bound_addr("socks"));
        if let Some(socks) = socks {
            if self.settings.system_vpn && (had_vpn || result.is_ok()) {
                self.start_vpn(socks.port()).await;
            }
        }
    }

    async fn remove_helper(&mut self) {
        self.update(|s| {
            s.vpn_busy = true;
            s.vpn_message = None;
        });
        self.stop_vpn().await;
        let result = aegis_vpn::client::uninstall().await;
        self.check_helper().await;
        let message = match result {
            Ok(()) => (true, "VPN helper removed.".to_owned()),
            Err(e) => (false, e),
        };
        self.update(|s| {
            s.vpn_busy = false;
            s.vpn_message = Some(message);
        });
    }

    async fn disconnect(&mut self) {
        if self.node.is_some() {
            self.diag.note(Severity::Info, "client.disconnect", &[]);
        }
        // Release the system's traffic before the proxy it goes to stops.
        self.stop_vpn().await;
        if let Some(saved) = self.proxy_saved.take() {
            let _ = sysproxy::restore(&saved);
            self.settings.proxy_saved = None;
            let _ = self.settings.save();
        }
        if let Some(node) = self.node.take() {
            node.shutdown(Duration::from_secs(1)).await;
        }
        let enrolled = self.device.is_some();
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

    /// Renew a due certificate while connected and switch the running node
    /// to it; established sessions keep going.
    async fn renew_connected(&mut self) {
        let Some(device) = self.device.clone() else {
            return;
        };
        match aegis_join::renew_if_due(&device, false).await {
            Ok(true) => {
                if let Some(node) = &self.node {
                    if let Err(e) = node.ctx.reload_certificates() {
                        self.diag.note(
                            Severity::Warn,
                            "client.renew.reload_failed",
                            &[("error", &e)],
                        );
                    }
                }
                let exp = device.certificate_expires_at().ok();
                self.update(|s| s.certificate_expires_at = exp);
                self.diag.note(Severity::Info, "client.renew.ok", &[]);
            }
            Ok(false) => {}
            Err(e) => self.diag.note(
                Severity::Warn,
                "client.renew.failed",
                &[("error", &e.to_string())],
            ),
        }
    }

    /// Refresh counters; with `probe`, verify the gateway end to end.
    async fn refresh(&mut self, probe: bool) {
        let vpn = match &mut self.vpn {
            Some(session) => Some(session.status().await),
            None => None,
        };
        if let Some(vpn) = vpn {
            match vpn {
                Ok((true, counters)) => self.update(|s| s.vpn_counters = counters),
                Ok((false, _)) | Err(_) => {
                    self.vpn = None;
                    self.diag.note(Severity::Warn, "client.vpn.lost", &[]);
                    self.check_helper().await;
                    self.update(|s| {
                        s.vpn_active = false;
                        s.error = Some(
                            "The system VPN stopped. Disconnect and connect again to restart it."
                                .into(),
                        );
                    });
                }
            }
        }
        let Some(node) = &self.node else { return };
        let gauges = node.ctx.gauges();
        let m = node.ctx.metrics.snapshot(gauges);
        let transport = node.ctx.tunnel_transport();
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
            s.transport = transport;
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
                        ("system_vpn", if self.vpn.is_some() { "on" } else { "off" }),
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
                .as_ref()
                .and_then(|d| d.load().ok())
                .map(|d| d.name)
                .unwrap_or_else(|| "unenrolled device".into()),
            version: env!("CARGO_PKG_VERSION").into(),
            recording,
        })
    }

    /// Ask the server for a newer version of this app; offer it if it is
    /// signed by the release workflow (aegis_join checks).
    async fn check_update(&mut self) {
        let (Some(platform), Some(device)) = (aegis_join::update::platform(), self.device.clone())
        else {
            return;
        };
        let busy = matches!(
            self.state.lock().unwrap_or_else(|e| e.into_inner()).update,
            UpdateState::Downloading { .. } | UpdateState::Ready { .. }
        );
        if busy {
            return;
        }
        match aegis_join::update::check(&device, platform, env!("CARGO_PKG_VERSION")).await {
            Ok(Some(offer)) => {
                let version = offer.version.clone();
                self.offer = Some(offer);
                self.update(|s| s.update = UpdateState::Available(version));
            }
            Ok(None) => {}
            Err(e) => self.diag.note(
                Severity::Info,
                "client.update.check_failed",
                &[("error", &e.to_string())],
            ),
        }
    }

    async fn install_update(&mut self) {
        if self.update_job.as_ref().is_some_and(|j| !j.is_finished()) {
            return;
        }
        let (Some(offer), Some(device)) = (self.offer.clone(), self.device.clone()) else {
            return;
        };
        let version = offer.version.clone();
        let failed = {
            let version = version.clone();
            move |message: String| UpdateState::Failed {
                version: version.clone(),
                message,
            }
        };
        let folder = self.data_dir.join("update");
        if let Err(e) = std::fs::create_dir_all(&folder) {
            self.update(|s| s.update = failed(format!("{}: {e}", folder.display())));
            return;
        }
        let dest = folder.join(&offer.file);
        let _ = std::fs::remove_file(&dest);
        self.update(|s| {
            s.update = UpdateState::Downloading {
                version: version.clone(),
                done: 0,
                total: offer.size,
            }
        });
        let (state, repaint) = (Arc::clone(&self.state), Arc::clone(&self.repaint));
        self.update_job = Some(tokio::spawn(async move {
            let set = |next: UpdateState| {
                state.lock().unwrap_or_else(|e| e.into_inner()).update = next;
                repaint();
            };
            let downloaded = aegis_join::update::download(&device, &offer, &dest, |done, total| {
                if let UpdateState::Downloading {
                    done: d, total: t, ..
                } = &mut state.lock().unwrap_or_else(|e| e.into_inner()).update
                {
                    (*d, *t) = (done, total);
                }
                repaint();
            })
            .await;
            if let Err(e) = downloaded {
                set(failed(format!("Could not download the update: {e}")));
                return;
            }
            let installed = tokio::task::spawn_blocking(move || crate::selfupdate::install(&dest))
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            set(match installed {
                Ok(start) => UpdateState::Ready {
                    version: version.clone(),
                    start,
                },
                Err(e) => failed(e),
            });
        }));
    }

    async fn diag_send(&mut self) {
        let Some(mut report) = self.report() else {
            return;
        };
        let Some(device) = self.device.clone() else {
            self.update(|s| {
                s.diag_message = Some((
                    false,
                    "This device hasn't joined a server; use Save to file instead.".into(),
                ))
            });
            return;
        };
        self.update(|s| {
            s.diag_sending = true;
            s.diag_message = None;
        });
        // Leave headroom under the gateway's limit for base64 and JSON.
        let gz = report.to_gzip(900 * 1024);
        let result = aegis_join::upload_diagnostics(&device, &gz).await;
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
            .join(format!("aegisborne-diagnostics-{}.otlp.json", now()));
        let body = serde_json::to_vec_pretty(&report.to_otlp()).unwrap_or_default();
        let message = match std::fs::write(&path, body) {
            Ok(()) => (true, format!("Saved to {}", path.display())),
            Err(e) => (false, format!("Could not save the report: {e}")),
        };
        self.update(|s| s.diag_message = Some(message));
    }
}

/// The host of `url` or of a `host:port`, without the port (an IPv6
/// literal keeps its brackets, which the helper refuses).
fn host_only(s: &str) -> String {
    let rest = s.split_once("://").map_or(s, |(_, r)| r);
    let hostport = rest.split(['/', '?']).next().unwrap_or(rest);
    if hostport.starts_with('[') {
        return hostport.split(']').next().unwrap_or(hostport).to_owned() + "]";
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host.to_owned(),
        _ => hostport.to_owned(),
    }
}

/// Where this device connects to its server outside the VPN: the tunnel,
/// enrollment/renewal and direct QUIC addresses.
fn bypass_hosts(device: &aegis_join::Device) -> Vec<String> {
    let mut hosts: Vec<String> = [
        Some(&device.url),
        Some(&device.enroll_url),
        device.quic.as_ref(),
    ]
    .into_iter()
    .flatten()
    .map(|s| host_only(s))
    .filter(|h| aegis_vpn::proto::valid_bypass(h))
    .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The end-to-end check, with the message the window shows on failure.
async fn verify(socks: SocketAddr) -> Result<(), String> {
    if aegis_join::verify_tunnel(socks).await {
        Ok(())
    } else {
        Err("Cannot reach the server yet — retrying. Check the network, or ask the administrator whether this device was removed.".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_server_s_hosts_stay_off_the_vpn() {
        assert_eq!(host_only("wss://gw.example.com:8443/agp"), "gw.example.com");
        assert_eq!(host_only("https://gw.example.com/enroll"), "gw.example.com");
        assert_eq!(host_only("203.0.113.9:8444"), "203.0.113.9");
        assert_eq!(host_only("[2001:db8::1]:8444"), "[2001:db8::1]");
        let device = aegis_join::Device {
            name: "laptop".into(),
            url: "wss://gw.example.com/agp".into(),
            enroll_url: "https://gw.example.com/enroll".into(),
            server_name: "gw".into(),
            outer_server_name: None,
            device_ca_sha256: String::new(),
            enrolled_at: 0,
            quic: Some("203.0.113.9:8444".into()),
        };
        assert_eq!(bypass_hosts(&device), vec!["203.0.113.9", "gw.example.com"]);
    }
}
