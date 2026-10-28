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
    /// interface index; dropping the device removes the interface.
    fn open_tun(&self) -> io::Result<(Self::Device, u32)>;
    /// Point the system resolver at the VPN; returns what to restore.
    /// On failure nothing is left changed.
    fn set_dns(&self) -> io::Result<DnsSaved>;
    fn restore_dns(&self, saved: &DnsSaved) -> io::Result<()>;
    fn flush_dns_cache(&self);
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
        *lock(&self.state) = Journal::default();
        let _ = std::fs::remove_file(&self.path);
    }
}

struct Active {
    owner: u64,
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
    connections: AtomicU64,
}

impl<S: System> Helper<S> {
    /// First undo whatever a helper that stopped abruptly left behind
    /// (recorded in the journal at `journal`).
    pub fn new(sys: S, journal: PathBuf) -> Arc<Self> {
        let sys = Arc::new(sys);
        let left: Option<Journal> = std::fs::read(&journal)
            .ok()
            .and_then(|t| serde_json::from_slice(&t).ok());
        if let Some(left) = left {
            if !left.dns.is_empty() {
                let _ = sys.restore_dns(&left.dns);
            }
            for r in &left.routes {
                let _ = sys.delete_route(r);
            }
            sys.flush_dns_cache();
        }
        let _ = std::fs::remove_file(&journal);
        Arc::new(Helper {
            sys,
            journal: Arc::new(JournalFile {
                path: journal,
                state: Mutex::default(),
            }),
            active: tokio::sync::Mutex::new(None),
            connections: AtomicU64::new(0),
        })
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
        self.stop_owned(id).await;
    }

    /// Take the VPN down (the helper is stopping).
    pub async fn shutdown(&self) {
        let active = self.active.lock().await.take();
        if let Some(a) = active {
            self.teardown(a).await;
        }
    }

    async fn request(&self, id: u64, request: Request) -> Reply {
        match request {
            Request::Hello => Reply {
                version: Some(env!("CARGO_PKG_VERSION").into()),
                protocol: Some(proto::PROTOCOL),
                ..Reply::default()
            },
            Request::Start { socks_port, bypass } => match self.start(id, socks_port, bypass).await
            {
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
                self.stop_owned(id).await;
                Reply {
                    running: Some(false),
                    ..Reply::default()
                }
            }
        }
    }

    async fn stop_owned(&self, id: u64) {
        let mut active = self.active.lock().await;
        if active.as_ref().is_some_and(|a| a.owner == id) {
            if let Some(a) = active.take() {
                self.teardown(a).await;
            }
        }
    }

    async fn start(&self, owner: u64, socks_port: u16, bypass: Vec<String>) -> Result<(), String> {
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
        // Local addresses aren't captured and need no route of their own.
        addrs.retain(|ip| routes::captured(*ip));
        let sys = Arc::clone(&self.sys);
        let journal = Arc::clone(&self.journal);
        let (device, tun_index, added, saved) =
            tokio::task::spawn_blocking(move || setup(&*sys, &journal, &addrs))
                .await
                .map_err(|e| e.to_string())??;
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
            stop,
            packets,
            watcher,
            routes,
            dns: saved,
            stats,
        });
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
            if !dns.is_empty() {
                let _ = sys.restore_dns(&dns);
            }
            for r in &routes {
                let _ = sys.delete_route(r);
            }
            journal.clear();
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

type Setup<D> = (D, u32, Vec<HostRoute>, DnsSaved);

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
    let (device, tun_index) = match sys.open_tun() {
        Ok(t) => t,
        Err(e) => {
            undo(&added);
            return Err(format!("Could not create the VPN interface: {e}"));
        }
    };
    let saved = match sys.set_dns() {
        Ok(saved) => saved,
        Err(e) => {
            drop(device);
            undo(&added);
            return Err(format!("Could not set the system's DNS: {e}"));
        }
    };
    journal.update(|j| j.dns = saved.clone());
    sys.flush_dns_cache();
    Ok((device, tun_index, added, saved))
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
    let Some(current) = routes.first().map(|r| r.via) else {
        return;
    };
    if candidates.contains(&current) {
        return;
    }
    // Offline: keep the routes until a network comes back.
    let Some(next) = candidates.first().copied() else {
        return;
    };
    for r in routes.iter_mut() {
        let _ = sys.delete_route(r);
        r.via = next;
        let _ = sys.add_route(r);
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
            lock(&self.0).routes.push(*r);
            Ok(())
        }
        fn delete_route(&self, r: &HostRoute) -> io::Result<()> {
            lock(&self.0).routes.retain(|x| x != r);
            Ok(())
        }
        fn open_tun(&self) -> io::Result<(DuplexStream, u32)> {
            let mut s = lock(&self.0);
            if s.fail_tun {
                return Err(io::Error::other("no driver"));
            }
            let (a, b) = tokio::io::duplex(1 << 16);
            s.peers.push(b);
            s.tuns_opened += 1;
            Ok((a, 99))
        }
        fn set_dns(&self) -> io::Result<DnsSaved> {
            lock(&self.0).dns_set = true;
            Ok(vec![("Wi-Fi".into(), vec!["192.168.1.1".into()])])
        }
        fn restore_dns(&self, saved: &DnsSaved) -> io::Result<()> {
            assert_eq!(saved[0].0, "Wi-Fi");
            lock(&self.0).dns_set = false;
            Ok(())
        }
        fn flush_dns_cache(&self) {}
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
            .start(1, 1080, vec!["203.0.113.9".into()])
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
    async fn bad_requests_are_refused() {
        let helper = Helper::new(Fake::default(), journal_path("bad"));
        assert!(helper.start(1, 0, vec![]).await.is_err());
        assert!(helper.start(1, 1080, vec!["a;b".into()]).await.is_err());
        assert!(helper.start(1, 1080, vec!["x".into(); 9]).await.is_err());
    }
}
