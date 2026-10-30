//! Mobile client core.
//!
//! The app (Flutter UI, platform VPN service) calls a small JSON API: join
//! servers with invitations, list and select them, connect to the selected
//! one with a VPN interface descriptor, disconnect, and poll status. Every
//! call takes the app's data folder; each server's profile lives under it
//! (`aegis_join::Servers`). Underneath it is the desktop
//! client's stack: `aegis-join` for enrollment and renewal, the client node
//! (local SOCKS proxy, AGP tunnel to the gateway), plus the VPN packet path
//! that feeds captured connections into that proxy.
//!
//! Every function returns a JSON object with `"ok": true` and its fields, or
//! `"ok": false` and an `"error"` message for the user.
//!
//! On-demand diagnostics (`diag`) record what the connection does while the
//! user reproduces a problem, for the administrator.
//!
//! Unsafe code is denied, not forbidden (ADR-0011): only the platform
//! boundary allows it, item by item (`fd`, `android`).
#![deny(unsafe_code)]

#[cfg(unix)]
mod fd;

#[cfg(target_os = "android")]
mod android;

#[cfg(any(target_vendor = "apple", test))]
pub mod ffi;

pub mod diag;

use aegis_join::update::Update;
use aegis_join::{DeviceDir, JoinError, Ports, Servers};
use aegis_telemetry::{DiagnosticSink, Severity};
use aegis_tun::{dns, packet, routes};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use tokio::sync::watch;

/// How often a connected device checks whether its certificate is due for
/// renewal (renewal itself starts 10 days before expiry).
const RENEWAL_CHECK: Duration = Duration::from_secs(6 * 3600);
/// Status refresh while connected; every `PROBE_EVERY` refreshes (and
/// whenever no session is up) the tunnel is checked end to end.
const TICK: Duration = Duration::from_secs(2);
const PROBE_EVERY: u32 = 15;
/// How long an answer to "is there a newer app?" is reused.
const UPDATE_CHECK: Duration = Duration::from_secs(6 * 3600);
/// While recording diagnostics, the VPN's counters are noted every this
/// many status refreshes (a minute).
const STATS_EVERY: u32 = 30;

/// What the app shows.
#[derive(Clone, Default)]
struct Snapshot {
    state: State,
    error: Option<String>,
    info: Option<String>,
    /// The server of the current (or last) connection: id and address.
    server_id: Option<String>,
    server: Option<String>,
    connected_since: Option<u64>,
    bytes_up: u64,
    bytes_down: u64,
    /// What carries the tunnel: `quic` or `websocket`.
    transport: Option<&'static str>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum State {
    #[default]
    Disconnected,
    Connecting,
    Connected,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Disconnected => "disconnected",
            State::Connecting => "connecting",
            State::Connected => "connected",
        }
    }
}

struct Running {
    server_id: String,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

struct Client {
    rt: Runtime,
    snapshot: Arc<Mutex<Snapshot>>,
    stats: Mutex<Arc<packet::Stats>>,
    running: Mutex<Option<Running>>,
    /// The last update check: when, and the signed build offered (ADR-0017).
    offer: Mutex<Option<(Instant, Option<Update>)>>,
    /// An update download in progress: bytes done and total.
    progress: Arc<Mutex<Option<(u64, u64)>>>,
    diag: diag::Diag,
    /// The gateway's names and their real addresses, looked up before the
    /// VPN took over DNS ([`prepare_tunnel`]).
    pins: Mutex<Vec<(String, Vec<Ipv4Addr>)>>,
}

fn client() -> Result<&'static Client, String> {
    static CLIENT: OnceLock<Result<Client, String>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("aegis")
                .enable_all()
                .build()
                .map_err(|e| format!("runtime: {e}"))?;
            Ok(Client {
                rt,
                snapshot: Arc::default(),
                stats: Mutex::default(),
                running: Mutex::default(),
                offer: Mutex::default(),
                progress: Arc::default(),
                diag: diag::Diag::default(),
                pins: Mutex::default(),
            })
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn ok(mut v: Value) -> Value {
    v["ok"] = json!(true);
    v
}

fn fail(error: impl std::fmt::Display) -> Value {
    json!({"ok": false, "error": error.to_string()})
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?']).next().unwrap_or(rest).to_owned()
}

fn server_json(s: &aegis_join::Server) -> Value {
    json!({
        "id": s.id,
        "name": s.device.name,
        "server": s.host(),
        "certificate_expires_at": s.dir.certificate_expires_at().ok(),
    })
}

/// Join another server with an invitation code (`aegis1:…`) and select it.
/// Blocking.
pub fn enroll(dir: &str, code: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let result = c.rt.block_on(async {
        let invite = aegis_join::parse_invite(code)?;
        Servers::open(dir)?.join(&invite).await
    });
    match result {
        Ok(s) => ok(server_json(&s)),
        Err(e) => fail(e),
    }
}

/// The joined servers, oldest first, and the selected one's id.
pub fn servers(dir: &str) -> Value {
    match Servers::open(dir) {
        Ok(servers) => {
            let list: Vec<Value> = servers.list().iter().map(server_json).collect();
            ok(json!({
                "servers": list,
                "selected": servers.selected().map(|s| s.id),
            }))
        }
        Err(e) => fail(e),
    }
}

/// Make `id` the server the next connection uses.
pub fn select(dir: &str, id: &str) -> Value {
    match Servers::open(dir).and_then(|s| s.select(id)) {
        Ok(s) => ok(server_json(&s)),
        Err(e) => fail(e),
    }
}

/// Remove a server and its identity from this phone, disconnecting first
/// if it is the one connected.
pub fn forget(dir: &str, id: &str) -> Value {
    let connected = client()
        .ok()
        .is_some_and(|c| lock(&c.running).as_ref().is_some_and(|r| r.server_id == id));
    if connected {
        let _ = stop();
    }
    match Servers::open(dir).and_then(|s| s.remove(id)) {
        Ok(()) => ok(json!({})),
        Err(e) => fail(e),
    }
}

/// How the platform should set up the VPN interface.
pub fn vpn_config() -> Value {
    let v4: Vec<Value> = routes::ipv4()
        .into_iter()
        .map(|(ip, len)| json!({"address": ip.to_string(), "prefix": len}))
        .collect();
    let v6: Vec<Value> = routes::IPV6
        .iter()
        .map(|(ip, len)| json!({"address": ip, "prefix": len}))
        .collect();
    ok(json!({
        "mtu": packet::MTU,
        "address": "172.19.0.1",
        "prefix": 30,
        "address6": "fdfe:dcba:9876::1",
        "prefix6": 126,
        "dns": dns::SERVER.to_string(),
        "routes": v4,
        "routes6": v6,
    }))
}

/// Connect, carrying the VPN interface `fd` (ownership passes to Rust; it
/// is closed on disconnect). Returns at once; progress shows in [`status`].
#[cfg(unix)]
pub fn start(dir: &str, fd: i32) -> Value {
    start_device(dir, fd, false)
}

/// Before the VPN takes over DNS (iOS: before the tunnel's settings apply):
/// look up the selected gateway's names, so the VPN answers them with their
/// real addresses. Everything else gets the VPN's own addresses, and the
/// extension's lookups go through it too, so without this the gateway's
/// name would point back into the tunnel and the connection would never
/// come up. Blocking; best effort (the count of names pinned).
pub fn prepare_tunnel(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let server = match Servers::open(dir).map(|s| s.selected()) {
        Ok(Some(s)) => s,
        Ok(None) => return fail("Join a server first."),
        Err(e) => return fail(e),
    };
    let pins = c.rt.block_on(gateway_pins(&server.dir));
    let n = pins.len();
    *lock(&c.pins) = pins;
    ok(json!({ "pinned": n }))
}

/// The gateway's names (connection, enrollment and renewal, QUIC) with
/// their real IPv4 addresses. Addresses of the VPN's pool are stale
/// answers from an earlier connection and are skipped.
async fn gateway_pins(dir: &DeviceDir) -> Vec<(String, Vec<Ipv4Addr>)> {
    let Ok(d) = dir.load() else {
        return Vec::new();
    };
    let mut hosts = vec![diag::host_port(&d.url).0, diag::host_port(&d.enroll_url).0];
    hosts.extend(d.quic.as_deref().map(|q| diag::host_port(q).0));
    hosts.sort();
    hosts.dedup();
    let mut pins = Vec::new();
    for host in hosts {
        if host.is_empty() || host.parse::<IpAddr>().is_ok() {
            continue;
        }
        let lookup = tokio::time::timeout(
            Duration::from_secs(10),
            tokio::net::lookup_host((host.clone(), 0)),
        )
        .await;
        let mut found: Vec<Ipv4Addr> = match lookup {
            Ok(Ok(addrs)) => addrs
                .filter_map(|a| match a.ip() {
                    IpAddr::V4(ip) if !dns::FakeDns::in_pool(ip) => Some(ip),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        found.dedup();
        found.truncate(8);
        if !found.is_empty() {
            pins.push((host, found));
        }
    }
    pins
}

/// [`start`] on the iOS packet tunnel's utun interface, which this process
/// finds itself (the system doesn't hand its descriptor over).
#[cfg(target_vendor = "apple")]
pub fn start_tunnel(dir: &str) -> Value {
    match fd::find_utun() {
        Some(fd) => start_device(dir, fd, true),
        None => fail("The VPN interface was not found."),
    }
}

#[cfg(unix)]
fn start_device(dir: &str, fd: i32, utun: bool) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    // Registering the descriptor needs the runtime's reactor.
    let device = {
        let _rt = c.rt.enter();
        if utun {
            fd::TunDevice::utun(fd)
        } else {
            fd::TunDevice::new(fd)
        }
    };
    match device {
        Ok(device) => start_with(dir, device),
        Err(e) => fail(format!("VPN interface: {e}")),
    }
}

/// Connect to the selected server with any packet device (the VPN
/// interface, or a test double).
pub fn start_with<D>(dir: &str, device: D) -> Value
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let server = match Servers::open(dir).map(|s| s.selected()) {
        Ok(Some(s)) => s,
        Ok(None) => return fail("Join a server first."),
        Err(e) => return fail(e),
    };
    let _ = stop();
    let (stop_tx, stop_rx) = watch::channel(false);
    let stats = Arc::new(packet::Stats::default());
    *lock(&c.stats) = Arc::clone(&stats);
    let mut names = dns::FakeDns::default();
    for (host, addrs) in lock(&c.pins).iter() {
        names.pin(host, addrs.clone());
    }
    {
        let mut s = lock(&c.snapshot);
        *s = Snapshot {
            state: State::Connecting,
            server_id: Some(server.id.clone()),
            server: Some(server.host()),
            ..Snapshot::default()
        };
    }
    let task = c.rt.spawn(session(
        server.dir,
        device,
        Arc::clone(&c.snapshot),
        stats,
        names,
        Arc::clone(&c.diag.sink),
        stop_rx,
    ));
    *lock(&c.running) = Some(Running {
        server_id: server.id,
        stop: stop_tx,
        task,
    });
    ok(json!({}))
}

/// Disconnect (no-op when not connected). Blocks until the node stopped.
pub fn stop() -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let running = lock(&c.running).take();
    if let Some(r) = running {
        let _ = r.stop.send(true);
        let _ =
            c.rt.block_on(async { tokio::time::timeout(Duration::from_secs(5), r.task).await });
    }
    let mut s = lock(&c.snapshot);
    s.state = State::Disconnected;
    s.connected_since = None;
    ok(json!({}))
}

/// Ask the selected server for a newer version of this app (blocking; the
/// answer is reused for a few hours). `{"version": "1.2.0"}` when one signed
/// by the release workflow is offered, else `{"version": null}`. On iOS the
/// offer carries `install`, the link iOS installs it from.
pub fn check_update(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let Some(platform) = aegis_join::update::platform() else {
        return ok(json!({"version": null}));
    };
    if platform == "ios" {
        return check_ios_update(c, dir);
    }
    let cached = lock(&c.offer)
        .as_ref()
        .filter(|(at, _)| at.elapsed() < UPDATE_CHECK)
        .map(|(_, offer)| offer.clone());
    let offer = match cached {
        Some(offer) => offer,
        None => {
            let server = match Servers::open(dir).map(|s| s.selected()) {
                Ok(Some(s)) => s,
                Ok(None) => return ok(json!({"version": null})),
                Err(e) => return fail(e),
            };
            let checked = c.rt.block_on(aegis_join::update::check(
                &server.dir,
                platform,
                env!("CARGO_PKG_VERSION"),
            ));
            match checked {
                Ok(offer) => {
                    *lock(&c.offer) = Some((Instant::now(), offer.clone()));
                    offer
                }
                Err(e) => return fail(e),
            }
        }
    };
    ok(json!({"version": offer.map(|o| o.version), "current": env!("CARGO_PKG_VERSION")}))
}

/// [`check_update`] on iOS: a fresh install link each time (they last an
/// hour), so nothing is cached.
fn check_ios_update(c: &Client, dir: &str) -> Value {
    let server = match Servers::open(dir).map(|s| s.selected()) {
        Ok(Some(s)) => s,
        Ok(None) => return ok(json!({"version": null})),
        Err(e) => return fail(e),
    };
    match c.rt.block_on(aegis_join::update::check_ios(
        &server.dir,
        env!("CARGO_PKG_VERSION"),
    )) {
        Ok(offer) => ok(json!({
            "version": offer.as_ref().map(|o| o.version.clone()),
            "install": offer.map(|o| o.install),
            "current": env!("CARGO_PKG_VERSION"),
        })),
        Err(e) => fail(e),
    }
}

/// Download the offered update into the folder `into` (blocking), checking
/// it against its signed description. Returns the file's `path`; progress
/// shows in [`status`] meanwhile.
pub fn download_update(dir: &str, into: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let Some(offer) = lock(&c.offer).as_ref().and_then(|(_, o)| o.clone()) else {
        return fail("No update is offered.");
    };
    let server = match Servers::open(dir).map(|s| s.selected()) {
        Ok(Some(s)) => s,
        Ok(None) => return fail("Join a server first."),
        Err(e) => return fail(e),
    };
    if let Err(e) = std::fs::create_dir_all(into) {
        return fail(format!("{into}: {e}"));
    }
    let dest = std::path::Path::new(into).join(&offer.file);
    let _ = std::fs::remove_file(&dest);
    let progress = Arc::clone(&c.progress);
    *lock(&progress) = Some((0, offer.size));
    let result = c.rt.block_on(aegis_join::update::download(
        &server.dir,
        &offer,
        &dest,
        |done, total| *lock(&progress) = Some((done, total)),
    ));
    *lock(&progress) = None;
    match result {
        Ok(()) => ok(json!({"path": dest.to_string_lossy(), "version": offer.version})),
        Err(e) => fail(format!("Could not download the update: {e}")),
    }
}

/// Connection state and counters.
pub fn status() -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let s = lock(&c.snapshot).clone();
    let stats = Arc::clone(&lock(&c.stats));
    let downloading = *lock(&c.progress);
    ok(json!({
        "state": s.state.as_str(),
        "error": s.error,
        "info": s.info,
        "server_id": s.server_id,
        "server": s.server,
        "connected_since": s.connected_since,
        "bytes_up": s.bytes_up,
        "bytes_down": s.bytes_down,
        "transport": s.transport,
        "connections": stats.tcp_open.load(Ordering::Relaxed),
        "connections_total": stats.tcp_total.load(Ordering::Relaxed),
        "connections_failed": stats.tcp_failed.load(Ordering::Relaxed),
        "udp_flows": stats.udp_open.load(Ordering::Relaxed),
        "udp_flows_total": stats.udp_total.load(Ordering::Relaxed),
        "udp_flows_failed": stats.udp_failed.load(Ordering::Relaxed),
        "dns_queries": stats.dns_queries.load(Ordering::Relaxed),
        "dropped": stats.dropped.load(Ordering::Relaxed),
        "update_done": downloading.map(|(d, _)| d),
        "update_total": downloading.map(|(_, t)| t),
    }))
}

fn update(snapshot: &Mutex<Snapshot>, f: impl FnOnce(&mut Snapshot)) {
    f(&mut lock(snapshot));
}

/// One connection: renew if due, start the client node (following a
/// changed server address), run the packet path, keep status current and
/// renew in the background until stopped.
async fn session<D>(
    dir: DeviceDir,
    device: D,
    snapshot: Arc<Mutex<Snapshot>>,
    stats: Arc<packet::Stats>,
    names: dns::FakeDns,
    diag: Arc<DiagnosticSink>,
    mut stop: watch::Receiver<bool>,
) where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let fail_with = |e: String| {
        update(&snapshot, |s| {
            s.state = State::Disconnected;
            s.error = Some(e);
        })
    };
    diag.note(Severity::Info, "client.connect", &[]);
    if let Err(e) = aegis_join::renew_if_due(&dir, false).await {
        diag.note(
            Severity::Warn,
            "client.renew.failed",
            &[("error", &e.to_string())],
        );
        let expired = dir
            .certificate_expires_at()
            .is_ok_and(|exp| exp <= now() as i64);
        if expired {
            return fail_with(format!(
                "This device's certificate expired and could not be renewed ({e}). If it expired over 90 days ago or the device was removed, ask for a new invitation."
            ));
        }
    }
    let node = match start_node(&dir, &snapshot, &diag).await {
        Ok(n) => n,
        Err(e) => {
            diag.note(Severity::Error, "client.start.failed", &[("error", &e)]);
            diag::reach(&dir, &diag).await;
            return fail_with(e);
        }
    };
    let Some(socks) = node.bound_addr("socks") else {
        node.shutdown(Duration::from_secs(1)).await;
        return fail_with("the local proxy did not start".into());
    };
    let packets = tokio::spawn(packet::run(
        device,
        socks,
        names,
        Arc::clone(&stats),
        stop.clone(),
    ));
    let mut tick = tokio::time::interval(TICK);
    let mut ticks = 0u32;
    let mut renewal_checked = Instant::now();
    // The last health check's outcome: a failure after a pass (or the
    // first one) checks the gateway's address too.
    let mut last_check = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.wait_for(|s| *s) => break,
        }
        if packets.is_finished() {
            diag.note(
                Severity::Warn,
                "client.platform",
                &[("error", "the VPN interface closed")],
            );
            update(&snapshot, |s| {
                s.error = Some("The VPN interface closed.".into())
            });
            break;
        }
        ticks = ticks.wrapping_add(1);
        let gauges = node.ctx.gauges();
        let m = node.ctx.metrics.snapshot(gauges);
        let transport = node.ctx.tunnel_transport();
        let probe = ticks % PROBE_EVERY == 1 || gauges.sessions_active == 0;
        let verified = if probe {
            Some(aegis_join::verify_tunnel(socks).await)
        } else {
            None
        };
        match verified {
            Some(true) => diag.count("client.check.ok"),
            Some(false) => {
                diag.note(Severity::Warn, "client.check.failed", &[]);
                if last_check != Some(false) {
                    diag::reach(&dir, &diag).await;
                }
            }
            None => {}
        }
        if verified.is_some() {
            last_check = verified;
        }
        if ticks.is_multiple_of(STATS_EVERY) && diag.is_recording() {
            let n = |a: &std::sync::atomic::AtomicU64| a.load(Ordering::Relaxed).to_string();
            diag.note(
                Severity::Info,
                "client.vpn.stats",
                &[
                    ("tcp_open", &n(&stats.tcp_open)),
                    ("tcp_total", &n(&stats.tcp_total)),
                    ("tcp_failed", &n(&stats.tcp_failed)),
                    ("udp_total", &n(&stats.udp_total)),
                    ("udp_failed", &n(&stats.udp_failed)),
                    ("dns_queries", &n(&stats.dns_queries)),
                    ("dropped", &n(&stats.dropped)),
                    ("transport", transport.unwrap_or("none")),
                ],
            );
        }
        update(&snapshot, |s| {
            s.bytes_up = m.transport_bytes_up;
            s.bytes_down = m.transport_bytes_down;
            s.transport = transport;
            match verified {
                Some(true) => {
                    if s.state != State::Connected {
                        s.connected_since = Some(now());
                    }
                    s.state = State::Connected;
                    s.error = None;
                }
                Some(false) => {
                    s.state = State::Connecting;
                    s.connected_since = None;
                    s.error = Some("Cannot reach the server yet — retrying. Check the network, or ask the administrator whether this device was removed.".into());
                }
                None => {}
            }
        });
        if renewal_checked.elapsed() >= RENEWAL_CHECK {
            renewal_checked = Instant::now();
            match aegis_join::renew_if_due(&dir, false).await {
                Ok(true) => {
                    let _ = node.ctx.reload_certificates();
                }
                Ok(false) => {}
                Err(e) => diag.note(
                    Severity::Warn,
                    "client.renew.failed",
                    &[("error", &e.to_string())],
                ),
            }
        }
    }
    diag.note(Severity::Info, "client.disconnect", &[]);
    packets.abort();
    node.shutdown(Duration::from_secs(1)).await;
    update(&snapshot, |s| {
        s.state = State::Disconnected;
        s.connected_since = None;
    });
}

/// iOS ends a VPN extension that uses more than about 50 MB, so there the
/// client's buffers stay well below it (ADR-0018). The session window is
/// the desktop's (8 MB): it bounds the sum of all connections' windows, and
/// with 4 MB about 20 connections that stopped reading (a browser's slow or
/// abandoned page loads) left no room for any new one, the tunnel's health
/// check included. Within the configuration rules: the window holds two
/// stream buffers, and window plus one stream buffer fit the peer budget.
fn within_memory_limit(core: &mut aegis_config::CoreConfig, small: bool) {
    if small {
        core.process_buffer_budget_bytes = 24 * 1024 * 1024;
        core.peer_buffer_budget_bytes = 20 * 1024 * 1024;
        core.stream_buffer_budget_bytes = 256 * 1024;
        core.session_window_bytes = 8 * 1024 * 1024;
    }
}

/// Start the client node on ephemeral local ports, first trying a changed
/// server address the gateway reports (kept only if the pinned gateway
/// answers there).
async fn start_node(
    dir: &DeviceDir,
    snapshot: &Mutex<Snapshot>,
    diag: &Arc<DiagnosticSink>,
) -> Result<aegis_node::NodeRuntime, String> {
    let ports = Ports { socks: 0, http: 0 };
    let start = |mut cfg: aegis_config::NodeConfig| async {
        within_memory_limit(&mut cfg.core, cfg!(target_os = "ios"));
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(dir.root.join(format!("state.db{suffix}")));
        }
        aegis_node::start_with_diagnostics(
            aegis_node::StartOptions {
                config: cfg,
                store_path: dir.store(),
                failpoints: None,
            },
            Arc::clone(diag),
        )
        .await
    };
    let endpoint = match aegis_join::fetch_endpoint(dir).await {
        Ok(e) => e,
        Err(e) => {
            diag.note(
                Severity::Info,
                "client.endpoint.unchecked",
                &[("error", &e.to_string())],
            );
            None
        }
    };
    if let Some(endpoint) = endpoint {
        diag.note(
            Severity::Info,
            "client.endpoint.changed",
            &[("url", &endpoint.url)],
        );
        if let Ok(cfg) = aegis_join::client_config_for(dir, ports, Some(&endpoint)) {
            if let Ok(trial) = start(cfg).await {
                let verified = match trial.bound_addr("socks") {
                    Some(socks) => aegis_join::verify_tunnel(socks).await,
                    None => false,
                };
                if verified {
                    if let Ok(d) = aegis_join::adopt_endpoint(dir, &endpoint) {
                        let host = host_of(&d.url);
                        update(snapshot, |s| {
                            s.info =
                                Some(format!("The server's address changed; now using {host}."));
                            s.server = Some(host);
                        });
                        return Ok(trial);
                    }
                }
                diag.note(
                    Severity::Warn,
                    "client.endpoint.rejected",
                    &[("url", &endpoint.url)],
                );
                trial.shutdown(Duration::from_secs(1)).await;
            }
        }
    }
    let cfg = aegis_join::client_config(dir, ports).map_err(|e: JoinError| e.to_string())?;
    let server = dir.load().ok().map(|d| host_of(&d.url));
    update(snapshot, |s| s.server = server);
    start(cfg).await.map_err(|e| match e {
        aegis_node::StartError::Identity(_) => {
            "This device's identity could not be loaded. Remove the server and join again.".into()
        }
        other => format!("Could not start: {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_vpn_config() {
        assert_eq!(
            host_of("wss://gw.example.test:8443/agp"),
            "gw.example.test:8443"
        );
        assert_eq!(host_of("wss://gw.example.test/agp"), "gw.example.test");
        let v = vpn_config();
        assert_eq!(v["ok"], true);
        assert_eq!(v["dns"], "198.18.0.1");
        assert!(v["routes"].as_array().is_some_and(|r| r.len() > 5));
    }

    #[test]
    fn the_ios_limits_keep_the_configuration_rules() {
        let mut c = aegis_config::CoreConfig::default();
        within_memory_limit(&mut c, true);
        let mib = 1024 * 1024;
        assert!((4 * mib..=1024 * mib).contains(&c.process_buffer_budget_bytes));
        assert!(c.peer_buffer_budget_bytes <= c.process_buffer_budget_bytes);
        assert!((16 * 1024..=mib as u32).contains(&c.stream_buffer_budget_bytes));
        assert!(c.session_window_bytes >= 2 * c.stream_buffer_budget_bytes);
        assert!(
            u64::from(c.session_window_bytes) + u64::from(c.stream_buffer_budget_bytes)
                <= c.peer_buffer_budget_bytes
        );
        let mut unchanged = aegis_config::CoreConfig::default();
        within_memory_limit(&mut unchanged, false);
        assert_eq!(unchanged, aegis_config::CoreConfig::default());
    }

    #[test]
    fn no_servers_until_one_is_joined() {
        let dir = std::env::temp_dir().join(format!("aegis-mobile-test-{}", std::process::id()));
        let dir = dir.to_str().expect("utf-8");
        let v = servers(dir);
        assert_eq!(v["ok"], true);
        assert_eq!(v["servers"], json!([]));
        assert_eq!(v["selected"], Value::Null);
        assert_eq!(select(dir, "0123456789abcdef")["ok"], false);
        assert_eq!(start_with(dir, tokio::io::duplex(64).0)["ok"], false);
        let s = status();
        assert_eq!(s["state"], "disconnected");
        let _ = std::fs::remove_dir_all(dir);
    }
}
