//! The helper's core, the same on every platform.
//!
//! Starting the VPN, in order:
//! 1. resolve the gateway's names (before the system resolver points at
//!    the VPN) and keep those addresses off the VPN with host routes
//!    through the current uplink;
//! 2. create the VPN interface with the captured routes;
//! 3. point the system resolver at the VPN's fake-IP DNS;
//! 4. run the packet path into the client node's local SOCKS proxy.
//!
//! Every change outside the interface itself (host routes, saved resolver
//! settings) is written to a journal first, so a helper that stopped
//! abruptly undoes it when it starts again. While the VPN runs, the host
//! routes follow the uplink when the network changes.
//!
//! Kill switch (when the app asks for it): while the VPN runs, traffic may
//! leave only through it, to local networks and to the server. When the VPN
//! ends unexpectedly (the app crashed, the helper died) the block stays,
//! now letting DNS out so the app can reconnect, until the app connects
//! again or the user unblocks; a deliberate stop releases it. The block
//! outlives the helper (it is recorded in its own file) but not a restart
//! of the computer.

use crate::proto::{self, Counters, Reply, Request};
use aegis_tun::dns::FakeDns;
use aegis_tun::{packet, routes};
use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often the uplink is checked while the VPN runs.
const UPLINK_CHECK: Duration = Duration::from_secs(3);
/// At most this many addresses kept per bypassed name.
const MAX_ADDRS: usize = 16;

/// Where traffic leaves this computer outside the VPN: the interface and,
/// unless the link is point-to-point, the next hop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uplink {
    pub gateway: Option<IpAddr>,
    pub if_index: u32,
}

/// A route that keeps one address off the VPN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoute {
    pub dest: Ipv4Addr,
    pub via: Uplink,
}

/// Resolver settings to restore: (network service, its servers), empty
/// where the platform keeps the VPN's resolver on the interface itself.
pub type DnsSaved = Vec<(String, Vec<String>)>;

/// The VPN interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tun {
    pub index: u32,
    pub name: String,
}

/// What the helper needs from the operating system.
pub trait System: Send + Sync + 'static {
    type Device: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The uplink that reaches `ip` now (asked before the VPN is up).
    fn uplink_for(&self, ip: Ipv4Addr) -> io::Result<Option<Uplink>>;
    /// The default routes outside the VPN interface, best first.
    fn default_routes(&self, tun_index: u32) -> io::Result<Vec<Uplink>>;
    fn add_route(&self, route: &HostRoute) -> io::Result<()>;
    fn delete_route(&self, route: &HostRoute) -> io::Result<()>;
    /// Create the VPN interface with its addresses and the captured routes
    /// (which go away with it). Returns the packet device and the
    /// interface; dropping the device removes the interface.
    fn open_tun(&self) -> io::Result<(Self::Device, Tun)>;
    /// The resolver settings [`set_dns`](Self::set_dns) would change (what
    /// to restore afterwards). Changes nothing.
    fn read_dns(&self) -> io::Result<DnsSaved>;
    /// Point the resolver of the services in `saved` (from
    /// [`read_dns`](Self::read_dns)) at the VPN. On failure nothing is
    /// left changed.
    fn set_dns(&self, saved: &DnsSaved) -> io::Result<()>;
    fn restore_dns(&self, saved: &DnsSaved) -> io::Result<()>;
    fn flush_dns_cache(&self);
    /// Kill switch: outbound traffic may leave only through `tun` (while
    /// the VPN is up), to loopback, local networks and `allow` (the
    /// server), and to DNS servers while `tun` is `None`. Replaces an
    /// earlier block and outlives the helper (not a restart of the
    /// computer). `token`: what the earlier call returned.
    fn block(
        &self,
        tun: Option<&Tun>,
        allow: &[Ipv4Addr],
        token: Option<String>,
    ) -> io::Result<Option<String>>;
    fn unblock(&self, token: Option<&str>) -> io::Result<()>;
    /// Whether a block is in place (one that survived the helper).
    fn blocking(&self) -> bool;
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Journal {
    routes: Vec<HostRoute>,
    dns: DnsSaved,
}

struct JournalFile {
    path: PathBuf,
    state: Mutex<Journal>,
}

impl JournalFile {
    fn update(&self, f: impl FnOnce(&mut Journal)) {
        let mut j = lock(&self.state);
        f(&mut j);
        if let Ok(text) = serde_json::to_vec(&*j) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }

    fn clear(&self) {
        self.keep(Journal::default());
    }

    /// Replace the journal with `left` (what could not be undone yet).
    fn keep(&self, left: Journal) {
        if left == Journal::default() {
            *lock(&self.state) = left;
            let _ = std::fs::remove_file(&self.path);
        } else {
            self.update(|j| *j = left);
        }
    }
}

/// Undo `j` as far as possible; returns what could not be undone (kept in
/// the journal and tried again, so a passing failure doesn't leave the
/// system changed for good).
fn undo_journal<S: System>(sys: &S, j: Journal) -> Journal {
    let dns = if !j.dns.is_empty() && sys.restore_dns(&j.dns).is_err() {
        j.dns
    } else {
        Vec::new()
    };
    let routes = j
        .routes
        .into_iter()
        .filter(|r| match sys.delete_route(r) {
            Ok(()) => false,
            Err(e) => e.kind() != io::ErrorKind::NotFound,
        })
        .collect();
    Journal { routes, dns }
}

/// The kill switch's state, kept in its own file while it is on.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Kill {
    allow: Vec<Ipv4Addr>,
    token: Option<String>,
}

fn save_kill(path: &std::path::Path, kill: Option<&Kill>) {
    match kill.and_then(|k| serde_json::to_vec(k).ok()) {
        Some(text) => {
            let tmp = path.with_extension("tmp");
            if std::fs::write(&tmp, text).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
        None => {
            let _ = std::fs::remove_file(path);
        }
    }
}

struct Active {
    owner: u64,
    kill_switch: bool,
    stop: watch::Sender<bool>,
    packets: JoinHandle<()>,
    watcher: JoinHandle<()>,
    routes: Arc<Mutex<Vec<HostRoute>>>,
    dns: DnsSaved,
    stats: Arc<packet::Stats>,
}

impl Active {
    fn counters(&self) -> Counters {
        let s = &self.stats;
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Counters {
            tcp_open: get(&s.tcp_open),
            tcp_total: get(&s.tcp_total),
            tcp_failed: get(&s.tcp_failed),
            udp_open: get(&s.udp_open),
            udp_total: get(&s.udp_total),
            udp_failed: get(&s.udp_failed),
            dns_queries: get(&s.dns_queries),
            dropped: get(&s.dropped),
        }
    }
}

/// The helper: serves control connections; at most one VPN at a time.
pub struct Helper<S: System> {
    sys: Arc<S>,
    journal: Arc<JournalFile>,
    active: tokio::sync::Mutex<Option<Active>>,
    /// Lock order: `active`, then `kill`.
    kill: tokio::sync::Mutex<Option<Kill>>,
    kill_path: PathBuf,
    connections: AtomicU64,
}

impl<S: System> Helper<S> {
    /// First undo whatever a helper that stopped abruptly left behind
    /// (recorded in the journal at `journal`), keeping a kill switch that
    /// is still blocking.
    pub fn new(sys: S, journal: PathBuf) -> Arc<Self> {
        let sys = Arc::new(sys);
        let left: Option<Journal> = std::fs::read(&journal)
            .ok()
            .and_then(|t| serde_json::from_slice(&t).ok());
        let left = match left {
            Some(left) => {
                let left = undo_journal(&*sys, left);
                sys.flush_dns_cache();
                left
            }
            None => Journal::default(),
        };
        let journal = JournalFile {
            path: journal,
            state: Mutex::default(),
        };
        journal.keep(left);
        let kill_path = journal.path.with_extension("kill.json");
        let left: Option<Kill> = std::fs::read(&kill_path)
            .ok()
            .and_then(|t| serde_json::from_slice(&t).ok());
        let kill = match left {
            // The VPN that had it on is gone: keep blocking, with DNS let
            // out so the app can reconnect.
            Some(k) if sys.blocking() => match sys.block(None, &k.allow, k.token.clone()) {
                Ok(token) => Some(Kill { token, ..k }),
                Err(_) => Some(k),
            },
            // Gone with a restart of the computer.
            _ => None,
        };
        save_kill(&kill_path, kill.as_ref());
        Arc::new(Helper {
            sys,
            journal: Arc::new(journal),
            active: tokio::sync::Mutex::new(None),
            kill: tokio::sync::Mutex::new(kill),
            kill_path,
            connections: AtomicU64::new(0),
        })
    }

    /// Run a blocking system call off the async threads.
    async fn on_sys<T: Send + 'static>(
        &self,
        f: impl FnOnce(&S) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let sys = Arc::clone(&self.sys);
        tokio::task::spawn_blocking(move || f(&sys))
            .await
            .map_err(io::Error::other)?
    }

    /// Turn the kill switch on, or move it to `tun` (`None`: the VPN is
    /// down; DNS is let out).
    async fn block(&self, tun: Option<Tun>, allow: Option<Vec<Ipv4Addr>>) -> io::Result<()> {
        let mut kill = self.kill.lock().await;
        let previous = kill.clone().unwrap_or_default();
        let allow = allow.unwrap_or(previous.allow);
        let (a, t) = (allow.clone(), previous.token);
        let token = self
            .on_sys(move |sys| sys.block(tun.as_ref(), &a, t))
            .await?;
        *kill = Some(Kill { allow, token });
        save_kill(&self.kill_path, kill.as_ref());
        Ok(())
    }

    /// Release the kill switch. On failure it stays recorded (and reported
    /// as blocking), so releasing can be tried again, also after a restart
    /// of the helper.
    async fn unblock(&self) -> io::Result<()> {
        let mut kill = self.kill.lock().await;
        if let Some(k) = kill.clone() {
            self.on_sys(move |sys| sys.unblock(k.token.as_deref()))
                .await?;
            *kill = None;
            save_kill(&self.kill_path, None);
        }
        Ok(())
    }

    /// Serve one control connection until it closes; the VPN it started
    /// stops with it.
    pub async fn handle<C>(self: Arc<Self>, conn: C)
    where
        C: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let id = self.connections.fetch_add(1, Ordering::Relaxed) + 1;
        let (r, mut w) = tokio::io::split(conn);
        let mut r = BufReader::new(r);
        loop {
            let request = match proto::read::<_, Request>(&mut r).await {
                Ok(Some(request)) => request,
                Ok(None) => break,
                Err(e) => {
                    let _ = proto::write(&mut w, &Reply::error(e.to_string())).await;
                    break;
                }
            };
            let reply = self.request(id, request).await;
            if proto::write(&mut w, &reply).await.is_err() {
                break;
            }
        }
        // Without a Stop first: the app crashed or was killed.
        self.stop_owned(id, false).await;
    }

    /// Take the VPN down and release the kill switch (the helper is being
    /// stopped: removed, updated, or the computer is shutting down).
    pub async fn shutdown(&self) {
        let active = self.active.lock().await.take();
        if let Some(a) = active {
            self.teardown(a).await;
        }
        let _ = self.unblock().await;
    }

    async fn request(&self, id: u64, request: Request) -> Reply {
        match request {
            Request::Hello => {
                let running = self.active.lock().await.is_some();
                let blocked = !running && self.kill.lock().await.is_some();
                Reply {
                    version: Some(env!("CARGO_PKG_VERSION").into()),
                    protocol: Some(proto::PROTOCOL),
                    blocked: Some(blocked),
                    ..Reply::default()
                }
            }
            Request::Start {
                socks_port,
                bypass,
                kill_switch,
            } => match self.start(id, socks_port, bypass, kill_switch).await {
                Ok(()) => Reply {
                    running: Some(true),
                    ..Reply::default()
                },
                Err(e) => Reply::error(e),
            },
            Request::Status => {
                let active = self.active.lock().await;
                match active.as_ref() {
                    Some(a) if a.owner == id => Reply {
                        running: Some(!a.packets.is_finished()),
                        counters: Some(a.counters()),
                        ..Reply::default()
                    },
                    _ => Reply {
                        running: Some(false),
                        ..Reply::default()
                    },
                }
            }
            Request::Stop => {
                self.stop_owned(id, true).await;
                Reply {
                    running: Some(false),
                    ..Reply::default()
                }
            }
            Request::Release => {
                // Only a kill switch left blocking after the VPN ended.
                if self.active.lock().await.is_none() {
                    if let Err(e) = self.unblock().await {
                        return Reply {
                            blocked: Some(true),
                            ..Reply::error(format!("Could not release the kill switch: {e}"))
                        };
                    }
                }
                Reply {
                    blocked: Some(false),
                    ..Reply::default()
                }
            }
        }
    }

    /// Stop the VPN connection `id` started. A deliberate stop releases the
    /// kill switch; otherwise it keeps blocking, VPN or not.
    async fn stop_owned(&self, id: u64, deliberate: bool) {
        let mut active = self.active.lock().await;
        if !active.as_ref().is_some_and(|a| a.owner == id) {
            return;
        }
        let Some(a) = active.take() else { return };
        let kill_switch = a.kill_switch;
        self.teardown(a).await;
        if deliberate {
            let _ = self.unblock().await;
        } else if kill_switch {
            let _ = self.block(None, None).await;
        }
    }

    async fn start(
        &self,
        owner: u64,
        socks_port: u16,
        bypass: Vec<String>,
        kill_switch: bool,
    ) -> Result<(), String> {
        if socks_port == 0 {
            return Err("invalid proxy port".into());
        }
        if bypass.len() > proto::MAX_BYPASS || !bypass.iter().all(|h| proto::valid_bypass(h)) {
            return Err("invalid server address".into());
        }
        let mut active = self.active.lock().await;
        // A newer start replaces the VPN (an app that restarted before its
        // old connection was noticed closing).
        if let Some(a) = active.take() {
            self.teardown(a).await;
        }
        let mut dns = FakeDns::default();
        let mut addrs = Vec::new();
        for host in &bypass {
            let found = resolve(host).await?;
            if host.parse::<Ipv4Addr>().is_err() {
                dns.pin(host, found.clone());
            }
            addrs.extend(found);
        }
        addrs.sort();
        addrs.dedup();
        let server = addrs.clone();
        // Local addresses aren't captured and need no route of their own.
        addrs.retain(|ip| routes::captured(*ip));
        let sys = Arc::clone(&self.sys);
        let journal = Arc::clone(&self.journal);
        let (device, tun, added, saved) =
            tokio::task::spawn_blocking(move || setup(&*sys, &journal, &addrs))
                .await
                .map_err(|e| e.to_string())??;
        let tun_index = tun.index;
        let (stop, stop_rx) = watch::channel(false);
        let stats = Arc::new(packet::Stats::default());
        let proxy = SocketAddr::from((Ipv4Addr::LOCALHOST, socks_port));
        let packets = tokio::spawn(packet::run(
            device,
            proxy,
            dns,
            Arc::clone(&stats),
            stop_rx.clone(),
        ));
        let routes = Arc::new(Mutex::new(added));
        let watcher = tokio::spawn(follow_uplink(
            Arc::clone(&self.sys),
            Arc::clone(&self.journal),
            Arc::clone(&routes),
            tun_index,
            stop_rx,
        ));
        *active = Some(Active {
            owner,
            kill_switch,
            stop,
            packets,
            watcher,
            routes,
            dns: saved,
            stats,
        });
        let armed = if kill_switch {
            self.block(Some(tun), Some(server)).await
        } else {
            self.unblock().await
        };
        if let Err(e) = armed {
            if let Some(a) = active.take() {
                self.teardown(a).await;
            }
            return Err(format!("Could not turn on the kill switch: {e}"));
        }
        Ok(())
    }

    async fn teardown(&self, a: Active) {
        let _ = a.stop.send(true);
        a.watcher.abort();
        let _ = a.watcher.await;
        // The packet path ends on the stop signal; the interface and its
        // routes go with the device it owns.
        let mut packets = a.packets;
        if tokio::time::timeout(Duration::from_secs(3), &mut packets)
            .await
            .is_err()
        {
            packets.abort();
            let _ = packets.await;
        }
        let sys = Arc::clone(&self.sys);
        let journal = Arc::clone(&self.journal);
        let routes = std::mem::take(&mut *lock(&a.routes));
        let dns = a.dns;
        let _ = tokio::task::spawn_blocking(move || {
            // With what an earlier helper could not undo yet.
            let mut all = std::mem::take(&mut *lock(&journal.state));
            all.routes.retain(|r| !routes.contains(r));
            all.routes.extend(routes);
            if !dns.is_empty() {
                all.dns = dns;
            }
            journal.keep(undo_journal(&*sys, all));
            sys.flush_dns_cache();
        })
        .await;
    }
}

/// The IPv4 addresses of `host` (a name or an IPv4 address).
async fn resolve(host: &str) -> Result<Vec<Ipv4Addr>, String> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(vec![ip]);
    }
    let found: Vec<Ipv4Addr> = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| format!("Could not look up {host}: {e}"))?
        .filter_map(|a| match a.ip() {
            // A pool address is a stale answer of an earlier VPN.
            IpAddr::V4(ip) if !FakeDns::in_pool(ip) => Some(ip),
            _ => None,
        })
        .take(MAX_ADDRS)
        .collect();
    if found.is_empty() {
        Err(format!("Could not look up {host}: no IPv4 address."))
    } else {
        Ok(found)
    }
}

type Setup<D> = (D, Tun, Vec<HostRoute>, DnsSaved);

/// Host routes, the interface, the resolver; undone in reverse on failure.
fn setup<S: System>(
    sys: &S,
    journal: &JournalFile,
    addrs: &[Ipv4Addr],
) -> Result<Setup<S::Device>, String> {
    let undo = |added: &[HostRoute]| {
        for r in added {
            let _ = sys.delete_route(r);
        }
        journal.clear();
    };
    let mut added = Vec::new();
    if let Some(first) = addrs.first() {
        let uplink = sys
            .uplink_for(*first)
            .map_err(|e| format!("Could not read the routing table: {e}"))?
            .ok_or("This computer has no network connection.")?;
        for dest in addrs {
            let route = HostRoute {
                dest: *dest,
                via: uplink,
            };
            journal.update(|j| j.routes.push(route));
            if let Err(e) = sys.add_route(&route) {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    // Someone else's route: leave it alone.
                    journal.update(|j| j.routes.retain(|r| *r != route));
                    continue;
                }
                undo(&added);
                return Err(format!("Could not add a route for {dest}: {e}"));
            }
            added.push(route);
        }
    }
    let (device, tun) = match sys.open_tun() {
        Ok(t) => t,
        Err(e) => {
            undo(&added);
            return Err(format!("Could not create the VPN interface: {e}"));
        }
    };
    // What to restore is journaled before anything changes: a crash in
    // between leaves a record to restore from. Settings an earlier helper
    // could not restore yet are the originals (the current ones are ours).
    let earlier = lock(&journal.state).dns.clone();
    let saved = if earlier.is_empty() {
        match sys.read_dns() {
            Ok(saved) => saved,
            Err(e) => {
                drop(device);
                undo(&added);
                return Err(format!("Could not read the system's DNS: {e}"));
            }
        }
    } else {
        earlier
    };
    journal.update(|j| j.dns = saved.clone());
    if let Err(e) = sys.set_dns(&saved) {
        drop(device);
        undo(&added);
        return Err(format!("Could not set the system's DNS: {e}"));
    }
    sys.flush_dns_cache();
    Ok((device, tun, added, saved))
}

/// Keep the host routes on the current uplink while the VPN runs.
async fn follow_uplink<S: System>(
    sys: Arc<S>,
    journal: Arc<JournalFile>,
    routes: Arc<Mutex<Vec<HostRoute>>>,
    tun_index: u32,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(UPLINK_CHECK) => {}
            _ = stop.wait_for(|s| *s) => return,
        }
        if lock(&routes).is_empty() {
            return;
        }
        let (sys, journal, routes) = (Arc::clone(&sys), Arc::clone(&journal), Arc::clone(&routes));
        let _ = tokio::task::spawn_blocking(move || {
            move_routes(&*sys, &journal, &routes, tun_index);
        })
        .await;
    }
}

fn move_routes<S: System>(
    sys: &S,
    journal: &JournalFile,
    routes: &Mutex<Vec<HostRoute>>,
    tun_index: u32,
) {
    let Ok(candidates) = sys.default_routes(tun_index) else {
        return;
    };
    let mut routes = lock(routes);
    if routes.iter().all(|r| candidates.contains(&r.via)) {
        return;
    }
    // Offline: keep the routes until a network comes back.
    let Some(next) = candidates.first().copied() else {
        return;
    };
    // A route is recorded on the new uplink only once it is there; one that
    // failed stays on the old one and is tried again next time.
    for r in routes.iter_mut().filter(|r| !candidates.contains(&r.via)) {
        let moved = HostRoute { via: next, ..*r };
        let added = match sys.add_route(&moved) {
            Ok(()) => true,
            Err(e) => e.kind() == io::ErrorKind::AlreadyExists,
        };
        if added {
            let _ = sys.delete_route(r);
            *r = moved;
        }
    }
    let now = routes.clone();
    journal.update(|j| j.routes = now);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    #[derive(Default)]
    struct FakeState {
        routes: Vec<HostRoute>,
        defaults: Vec<Uplink>,
        dns_set: bool,
        tuns_opened: u32,
        /// The far ends of the devices handed out (kept open).
        peers: Vec<DuplexStream>,
        fail_tun: bool,
        /// The next this many calls fail (a passing OS error).
        fail_restore: u32,
        fail_add: u32,
        fail_unblock: u32,
        /// The kill switch: (through the VPN interface, allowed addresses).
        block: Option<(bool, Vec<Ipv4Addr>)>,
    }

    /// Whether the call counted down by `n` fails this time.
    fn failing(n: &mut u32) -> bool {
        let fail = *n > 0;
        *n = n.saturating_sub(1);
        fail
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<FakeState>>);

    const WIFI: Uplink = Uplink {
        gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        if_index: 7,
    };
    const ETHERNET: Uplink = Uplink {
        gateway: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        if_index: 3,
    };

    impl System for Fake {
        type Device = DuplexStream;
        fn uplink_for(&self, _ip: Ipv4Addr) -> io::Result<Option<Uplink>> {
            Ok(lock(&self.0).defaults.first().copied())
        }
        fn default_routes(&self, _tun: u32) -> io::Result<Vec<Uplink>> {
            Ok(lock(&self.0).defaults.clone())
        }
        fn add_route(&self, r: &HostRoute) -> io::Result<()> {
            let mut s = lock(&self.0);
            if failing(&mut s.fail_add) {
                return Err(io::Error::other("busy"));
            }
            s.routes.push(*r);
            Ok(())
        }
        fn delete_route(&self, r: &HostRoute) -> io::Result<()> {
            lock(&self.0).routes.retain(|x| x != r);
            Ok(())
        }
        fn open_tun(&self) -> io::Result<(DuplexStream, Tun)> {
            let mut s = lock(&self.0);
            if s.fail_tun {
                return Err(io::Error::other("no driver"));
            }
            let (a, b) = tokio::io::duplex(1 << 16);
            s.peers.push(b);
            s.tuns_opened += 1;
            Ok((
                a,
                Tun {
                    index: 99,
                    name: "utun9".into(),
                },
            ))
        }
        fn read_dns(&self) -> io::Result<DnsSaved> {
            Ok(vec![("Wi-Fi".into(), vec!["192.168.1.1".into()])])
        }
        fn set_dns(&self, _saved: &DnsSaved) -> io::Result<()> {
            lock(&self.0).dns_set = true;
            Ok(())
        }
        fn restore_dns(&self, saved: &DnsSaved) -> io::Result<()> {
            assert_eq!(saved[0].0, "Wi-Fi");
            let mut s = lock(&self.0);
            if failing(&mut s.fail_restore) {
                return Err(io::Error::other("busy"));
            }
            s.dns_set = false;
            Ok(())
        }
        fn flush_dns_cache(&self) {}
        fn block(
            &self,
            tun: Option<&Tun>,
            allow: &[Ipv4Addr],
            token: Option<String>,
        ) -> io::Result<Option<String>> {
            lock(&self.0).block = Some((tun.is_some(), allow.to_vec()));
            Ok(token.or(Some("token".into())))
        }
        fn unblock(&self, token: Option<&str>) -> io::Result<()> {
            assert_eq!(token, Some("token"));
            let mut s = lock(&self.0);
            if failing(&mut s.fail_unblock) {
                return Err(io::Error::other("busy"));
            }
            s.block = None;
            Ok(())
        }
        fn blocking(&self) -> bool {
            lock(&self.0).block.is_some()
        }
    }

    fn journal_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-vpn-test-{}-{name}.json", std::process::id()))
    }

    async fn ask(
        w: &mut (impl AsyncWrite + Unpin),
        r: &mut (impl tokio::io::AsyncBufRead + Unpin),
        request: &Request,
    ) -> Reply {
        proto::write(w, request).await.expect("write");
        proto::read(r).await.expect("read").expect("reply")
    }

    #[tokio::test]
    async fn the_vpn_lives_as_long_as_its_connection() {
        let fake = Fake::default();
        lock(&fake.0).defaults = vec![WIFI];
        let path = journal_path("lifetime");
        let helper = Helper::new(fake.clone(), path.clone());
        let (app, conn) = tokio::io::duplex(1 << 16);
        let served = tokio::spawn(Arc::clone(&helper).handle(conn));
        let (r, mut w) = tokio::io::split(app);
        let mut r = BufReader::new(r);
        let hello = ask(&mut w, &mut r, &Request::Hello).await;
        assert_eq!(hello.protocol, Some(proto::PROTOCOL));
        let start = Request::Start {
            socks_port: 1080,
            // A public gateway address gets a host route; a LAN one doesn't.
            bypass: vec!["203.0.113.9".into(), "192.168.4.31".into()],
            kill_switch: false,
        };
        let reply = ask(&mut w, &mut r, &start).await;
        assert_eq!(reply.error, None);
        {
            let s = lock(&fake.0);
            assert_eq!(
                s.routes,
                vec![HostRoute {
                    dest: Ipv4Addr::new(203, 0, 113, 9),
                    via: WIFI
                }]
            );
            assert!(s.dns_set);
            assert_eq!(s.tuns_opened, 1);
        }
        let journal: Journal =
            serde_json::from_slice(&std::fs::read(&path).expect("journal")).expect("json");
        assert_eq!(journal.routes.len(), 1, "recorded before anything else");
        assert_eq!(journal.dns.len(), 1);
        let status = ask(&mut w, &mut r, &Request::Status).await;
        assert_eq!(status.running, Some(true));
        assert_eq!(status.counters, Some(Counters::default()));
        // The app goes away: everything is undone.
        drop((r, w));
        served.await.expect("served");
        let s = lock(&fake.0);
        assert!(s.routes.is_empty());
        assert!(!s.dns_set);
        assert!(!path.exists(), "journal cleared");
    }

    #[tokio::test]
    async fn host_routes_follow_the_uplink() {
        let fake = Fake::default();
        lock(&fake.0).defaults = vec![WIFI];
        let journal = JournalFile {
            path: journal_path("uplink"),
            state: Mutex::default(),
        };
        let route = HostRoute {
            dest: Ipv4Addr::new(203, 0, 113, 9),
            via: WIFI,
        };
        fake.add_route(&route).expect("add");
        let routes = Mutex::new(vec![route]);
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, WIFI, "unchanged network");
        lock(&fake.0).defaults = vec![];
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, WIFI, "offline: kept");
        lock(&fake.0).defaults = vec![ETHERNET, WIFI];
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, WIFI, "still there: kept");
        lock(&fake.0).defaults = vec![ETHERNET];
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, ETHERNET, "moved");
        assert_eq!(lock(&fake.0).routes, vec![lock(&routes)[0]]);
        journal.clear();
    }

    #[tokio::test]
    async fn a_failed_start_and_a_crash_leave_nothing_behind() {
        let fake = Fake::default();
        {
            let mut s = lock(&fake.0);
            s.defaults = vec![WIFI];
            s.fail_tun = true;
        }
        let path = journal_path("failed");
        let helper = Helper::new(fake.clone(), path.clone());
        let err = helper
            .start(1, 1080, vec!["203.0.113.9".into()], true)
            .await
            .expect_err("no driver");
        assert!(err.contains("VPN interface"), "{err}");
        assert!(lock(&fake.0).routes.is_empty());
        assert!(!path.exists());

        // A helper that died mid-session left a route and the resolver set.
        let left = HostRoute {
            dest: Ipv4Addr::new(203, 0, 113, 9),
            via: WIFI,
        };
        {
            let mut s = lock(&fake.0);
            s.routes.push(left);
            s.dns_set = true;
        }
        let journal = Journal {
            routes: vec![left],
            dns: vec![("Wi-Fi".into(), vec![])],
        };
        std::fs::write(&path, serde_json::to_vec(&journal).expect("json")).expect("write");
        let _helper = Helper::new(fake.clone(), path.clone());
        let s = lock(&fake.0);
        assert!(s.routes.is_empty());
        assert!(!s.dns_set);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn the_kill_switch_holds_until_released_or_stopped_deliberately() {
        let fake = Fake::default();
        lock(&fake.0).defaults = vec![WIFI];
        let path = journal_path("kill");
        let kill_path = path.with_extension("kill.json");
        let helper = Helper::new(fake.clone(), path.clone());
        let server = vec![Ipv4Addr::new(203, 0, 113, 9)];
        let start = Request::Start {
            socks_port: 1080,
            bypass: vec!["203.0.113.9".into()],
            kill_switch: true,
        };

        // Armed with the VPN; a deliberate stop releases it.
        let (app, conn) = tokio::io::duplex(1 << 16);
        let served = tokio::spawn(Arc::clone(&helper).handle(conn));
        let (r, mut w) = tokio::io::split(app);
        let mut r = BufReader::new(r);
        assert_eq!(ask(&mut w, &mut r, &start).await.error, None);
        assert_eq!(lock(&fake.0).block, Some((true, server.clone())));
        assert!(kill_path.exists(), "recorded");
        ask(&mut w, &mut r, &Request::Stop).await;
        assert_eq!(lock(&fake.0).block, None);
        assert!(!kill_path.exists());

        // The app goes away without a Stop: the block stays, VPN or not.
        assert_eq!(ask(&mut w, &mut r, &start).await.error, None);
        drop((r, w));
        served.await.expect("served");
        assert_eq!(lock(&fake.0).block, Some((false, server.clone())));
        assert!(lock(&fake.0).routes.is_empty(), "the VPN itself is gone");

        // A new helper (after a crash) keeps it, and says so.
        let helper = Helper::new(fake.clone(), path.clone());
        assert_eq!(lock(&fake.0).block, Some((false, server.clone())));
        let (app, conn) = tokio::io::duplex(1 << 16);
        let served = tokio::spawn(Arc::clone(&helper).handle(conn));
        let (r, mut w) = tokio::io::split(app);
        let mut r = BufReader::new(r);
        assert_eq!(
            ask(&mut w, &mut r, &Request::Hello).await.blocked,
            Some(true)
        );
        // The user unblocks.
        ask(&mut w, &mut r, &Request::Release).await;
        assert_eq!(lock(&fake.0).block, None);
        assert_eq!(
            ask(&mut w, &mut r, &Request::Hello).await.blocked,
            Some(false)
        );
        drop((r, w));
        served.await.expect("served");
        assert_eq!(lock(&fake.0).block, None, "nothing was running");

        // After a restart of the computer the block is gone: forgotten.
        save_kill(&kill_path, Some(&Kill::default()));
        let _helper = Helper::new(fake.clone(), path.clone());
        assert!(!kill_path.exists());
        assert_eq!(lock(&fake.0).block, None);
    }

    #[tokio::test]
    async fn bad_requests_are_refused() {
        let helper = Helper::new(Fake::default(), journal_path("bad"));
        assert!(helper.start(1, 0, vec![], false).await.is_err());
        assert!(helper
            .start(1, 1080, vec!["a;b".into()], false)
            .await
            .is_err());
        assert!(helper
            .start(1, 1080, vec!["x".into(); 9], false)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn cleanup_that_failed_is_tried_again() {
        let fake = Fake::default();
        let path = journal_path("retry");
        let left = HostRoute {
            dest: Ipv4Addr::new(203, 0, 113, 9),
            via: WIFI,
        };
        {
            let mut s = lock(&fake.0);
            s.routes.push(left);
            s.dns_set = true;
            s.fail_restore = 1;
        }
        let journal = Journal {
            routes: vec![left],
            dns: vec![("Wi-Fi".into(), vec![])],
        };
        std::fs::write(&path, serde_json::to_vec(&journal).expect("json")).expect("write");
        // The resolver could not be restored: that part stays journaled.
        drop(Helper::new(fake.clone(), path.clone()));
        assert!(lock(&fake.0).dns_set);
        let kept: Journal =
            serde_json::from_slice(&std::fs::read(&path).expect("journal")).expect("json");
        assert_eq!(kept.dns.len(), 1);
        assert!(kept.routes.is_empty(), "the route was removed");
        // The next helper restores it.
        drop(Helper::new(fake.clone(), path.clone()));
        assert!(!lock(&fake.0).dns_set);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn a_failed_release_keeps_the_kill_switch_known() {
        let fake = Fake::default();
        let path = journal_path("release");
        let helper = Helper::new(fake.clone(), path.clone());
        helper.block(None, Some(vec![])).await.expect("block");
        lock(&fake.0).fail_unblock = 1;
        let reply = helper.request(1, Request::Release).await;
        assert!(reply.error.is_some());
        assert_eq!(reply.blocked, Some(true));
        assert!(lock(&fake.0).block.is_some());
        assert!(path.with_extension("kill.json").exists(), "still recorded");
        let reply = helper.request(1, Request::Release).await;
        assert_eq!(reply.error, None);
        assert_eq!(reply.blocked, Some(false));
        assert!(lock(&fake.0).block.is_none());
        assert!(!path.with_extension("kill.json").exists());
    }

    #[tokio::test]
    async fn a_route_that_failed_to_move_is_moved_later() {
        let fake = Fake::default();
        lock(&fake.0).defaults = vec![WIFI];
        let journal = JournalFile {
            path: journal_path("move-retry"),
            state: Mutex::default(),
        };
        let route = HostRoute {
            dest: Ipv4Addr::new(203, 0, 113, 9),
            via: WIFI,
        };
        fake.add_route(&route).expect("add");
        let routes = Mutex::new(vec![route]);
        {
            let mut s = lock(&fake.0);
            s.defaults = vec![ETHERNET];
            s.fail_add = 1;
        }
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, WIFI, "not moved yet");
        move_routes(&fake, &journal, &routes, 99);
        assert_eq!(lock(&routes)[0].via, ETHERNET, "moved on the next check");
        assert_eq!(lock(&fake.0).routes, vec![lock(&routes)[0]]);
        journal.clear();
    }
}
