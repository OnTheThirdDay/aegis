//! The VPN packet path: a userspace TCP/IP stack over the VPN interface.
//!
//! * TCP connections are opened through the client node's local SOCKS proxy:
//!   by name for fake-DNS addresses, by address otherwise. The node then
//!   carries them through the gateway exactly like desktop traffic.
//! * DNS (UDP port 53, whatever server an app asks) is answered locally by
//!   [`FakeDns`].
//! * Other UDP and ICMP are dropped: the tunnel carries TCP only for now.
//!   Browsers fall back from QUIC to TCP.

use crate::dns::FakeDns;
use crate::socks::{self, Target};
use ipstack::{IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

/// Interface MTU (set the same on the VPN interface).
pub const MTU: u16 = 1500;

/// Counters of the packet path.
#[derive(Default)]
pub struct Stats {
    pub tcp_open: AtomicU64,
    pub tcp_total: AtomicU64,
    pub tcp_failed: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dropped: AtomicU64,
}

/// Run the packet path on `device` until `stop` turns true or the device
/// closes. Connections in flight end with it.
pub async fn run<D>(
    device: D,
    proxy: SocketAddr,
    stats: Arc<Stats>,
    mut stop: watch::Receiver<bool>,
) where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut config = IpStackConfig::default();
    let _ = config.mtu(MTU);
    config.udp_timeout(Duration::from_secs(30));
    let mut stack = IpStack::new(config, device);
    let dns = Arc::new(Mutex::new(FakeDns::default()));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        let stream = tokio::select! {
            s = stack.accept() => match s {
                Ok(s) => s,
                Err(_) => break,
            },
            _ = stop.wait_for(|s| *s) => break,
        };
        // Reap finished connection tasks as we go.
        while tasks.try_join_next().is_some() {}
        match stream {
            IpStackStream::Tcp(tcp) => {
                let Some(target) = target_of(&dns, tcp.peer_addr()) else {
                    // A pool address we no longer (or never) handed out.
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                tasks.spawn(relay(tcp, proxy, target, Arc::clone(&stats)));
            }
            IpStackStream::Udp(udp) if udp.peer_addr().port() == 53 => {
                tasks.spawn(serve_dns(udp, Arc::clone(&dns), Arc::clone(&stats)));
            }
            _ => {
                stats.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    tasks.abort_all();
}

fn target_of(dns: &Mutex<FakeDns>, dst: SocketAddr) -> Option<Target> {
    match dst.ip() {
        IpAddr::V4(ip) if FakeDns::in_pool(ip) => {
            let dns = dns.lock().unwrap_or_else(|e| e.into_inner());
            dns.name_of(ip)
                .map(|name| Target::Name(name.to_owned(), dst.port()))
        }
        _ => Some(Target::Addr(dst)),
    }
}

async fn relay(mut tcp: IpStackTcpStream, proxy: SocketAddr, target: Target, stats: Arc<Stats>) {
    stats.tcp_total.fetch_add(1, Ordering::Relaxed);
    let mut upstream = match socks::connect(proxy, &target).await {
        Ok(s) => s,
        Err(_) => {
            stats.tcp_failed.fetch_add(1, Ordering::Relaxed);
            // Dropping the stream resets the app's connection.
            return;
        }
    };
    stats.tcp_open.fetch_add(1, Ordering::Relaxed);
    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut upstream).await;
    let _ = upstream.shutdown().await;
    let _ = tcp.shutdown().await;
    stats.tcp_open.fetch_sub(1, Ordering::Relaxed);
}

async fn serve_dns(mut udp: IpStackUdpStream, dns: Arc<Mutex<FakeDns>>, stats: Arc<Stats>) {
    let mut buf = vec![0u8; 1500];
    // One flow per (app socket, server); it ends after the UDP timeout.
    while let Ok(n) = udp.read(&mut buf).await {
        if n == 0 {
            break;
        }
        stats.dns_queries.fetch_add(1, Ordering::Relaxed);
        let answer = dns
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .answer(&buf[..n]);
        if let Some(a) = answer {
            if udp.write_all(&a).await.is_err() {
                break;
            }
        }
    }
}
