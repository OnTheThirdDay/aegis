//! The VPN packet path: a userspace TCP/IP stack over the VPN interface.
//!
//! * TCP connections are opened through the client node's local SOCKS proxy:
//!   by name for fake-DNS addresses, by address otherwise. The node then
//!   carries them through the gateway exactly like desktop traffic.
//! * DNS (UDP port 53, whatever server an app asks) is answered locally by
//!   [`FakeDns`].
//! * Other UDP flows (QUIC, calls, games) go through the local proxy's UDP
//!   ASSOCIATE, one association per flow, and from there through the
//!   gateway as AGP UDP flows. A gateway without UDP support refuses them;
//!   apps then fall back as they would on a network that blocks UDP.
//! * ICMP is dropped.

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

/// A UDP flow (one app socket and destination) ends after this long
/// without a packet. QUIC keepalives come well within it.
const UDP_TIMEOUT: Duration = Duration::from_secs(60);

/// Counters of the packet path.
#[derive(Default)]
pub struct Stats {
    pub tcp_open: AtomicU64,
    pub tcp_total: AtomicU64,
    pub tcp_failed: AtomicU64,
    pub udp_open: AtomicU64,
    pub udp_total: AtomicU64,
    pub udp_failed: AtomicU64,
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
    config.udp_timeout(UDP_TIMEOUT);
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
            IpStackStream::Udp(udp) => {
                let Some(target) = target_of(&dns, udp.peer_addr()) else {
                    stats.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                tasks.spawn(relay_udp(udp, proxy, target, Arc::clone(&stats)));
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

/// One UDP flow through its own association with the local proxy, until
/// the app's flow times out or the association ends.
async fn relay_udp(
    mut udp: IpStackUdpStream,
    proxy: SocketAddr,
    target: Target,
    stats: Arc<Stats>,
) {
    stats.udp_total.fetch_add(1, Ordering::Relaxed);
    let Ok(socks::UdpAssociation {
        mut control,
        socket,
    }) = socks::udp_associate(proxy).await
    else {
        stats.udp_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    stats.udp_open.fetch_add(1, Ordering::Relaxed);
    let mut from_app = vec![0u8; usize::from(MTU)];
    let mut from_proxy = vec![0u8; 64 * 1024];
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            r = udp.read(&mut from_app) => match r {
                Ok(n) if n > 0 => {
                    if let Ok(framed) = socks::encode_udp(&target, &from_app[..n]) {
                        // A datagram the relay can't take is lost, as UDP allows.
                        let _ = socket.send(&framed).await;
                    }
                }
                _ => break,
            },
            r = socket.recv(&mut from_proxy) => match r {
                Ok(n) => {
                    if let Some(data) = socks::decode_udp(&from_proxy[..n]) {
                        if udp.write_all(data).await.is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            },
            // The proxy closes the control connection when it stops.
            r = control.read(&mut probe) => match r {
                Ok(n) if n > 0 => {}
                _ => break,
            },
        }
    }
    stats.udp_open.fetch_sub(1, Ordering::Relaxed);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::net::{TcpListener, UdpSocket};

    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for pair in bytes.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// An IPv4/UDP packet as an app would send it into the VPN interface.
    fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let total = 20 + udp_len;
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&src.ip().octets());
        p.extend_from_slice(&dst.ip().octets());
        let sum = checksum(&p);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p.extend_from_slice(&src.port().to_be_bytes());
        p.extend_from_slice(&dst.port().to_be_bytes());
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        // UDP checksum over the pseudo-header, header and data.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.ip().octets());
        pseudo.extend_from_slice(&dst.ip().octets());
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&p[20..26]);
        pseudo.extend_from_slice(&[0, 0]);
        pseudo.extend_from_slice(payload);
        let sum = match checksum(&pseudo) {
            0 => 0xffff,
            s => s,
        };
        p.extend_from_slice(&sum.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    /// A local "proxy" that grants UDP ASSOCIATE and echoes every datagram
    /// (header included) back; it reports each target it was asked for.
    async fn echo_proxy() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (seen_tx, seen) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = listener.accept().await else {
                    return;
                };
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let mut hello = [0u8; 3];
                    c.read_exact(&mut hello).await.expect("hello");
                    c.write_all(&[5, 0]).await.expect("method");
                    let mut req = [0u8; 10];
                    c.read_exact(&mut req).await.expect("request");
                    assert_eq!(req[1], 3, "UDP ASSOCIATE");
                    let relay = UdpSocket::bind("127.0.0.1:0").await.expect("relay");
                    let port = relay.local_addr().expect("addr").port();
                    let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                    reply.extend_from_slice(&port.to_be_bytes());
                    c.write_all(&reply).await.expect("reply");
                    let mut buf = vec![0u8; 65536];
                    let mut probe = [0u8; 1];
                    loop {
                        tokio::select! {
                            r = relay.recv_from(&mut buf) => {
                                let (n, from) = r.expect("recv");
                                let _ = seen_tx.send(buf[..n].to_vec());
                                relay.send_to(&buf[..n], from).await.expect("echo");
                            }
                            _ = c.read(&mut probe) => return,
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn udp_flows_go_through_the_proxy_and_back() {
        let (proxy, mut seen) = echo_proxy().await;
        let (device, mut net) = tokio::io::duplex(1 << 16);
        let stats = Arc::new(Stats::default());
        let (stop_tx, stop) = watch::channel(false);
        let path = tokio::spawn(run(device, proxy, Arc::clone(&stats), stop));
        let app = SocketAddrV4::new(Ipv4Addr::new(172, 19, 0, 1), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 443);
        net.write_all(&udp_packet(app, server, b"quic initial"))
            .await
            .expect("packet in");
        let framed = tokio::time::timeout(Duration::from_secs(5), seen.recv())
            .await
            .expect("reached the proxy")
            .expect("datagram");
        // Addressed to the app's destination, as an IPv4 SOCKS target.
        assert_eq!(&framed[..4], &[0, 0, 0, 1]);
        assert_eq!(&framed[4..8], &[203, 0, 113, 9]);
        assert_eq!(&framed[8..10], &443u16.to_be_bytes());
        assert_eq!(&framed[10..], b"quic initial");
        // The echo comes back to the app as a UDP packet from the server.
        let mut buf = vec![0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(5), net.read(&mut buf))
            .await
            .expect("packet out")
            .expect("read");
        let packet = &buf[..n];
        assert_eq!(packet[9], 17, "UDP");
        assert_eq!(&packet[12..16], &[203, 0, 113, 9], "from the server");
        assert_eq!(&packet[16..20], &[172, 19, 0, 1], "to the app");
        assert!(packet.ends_with(b"quic initial"));
        assert_eq!(stats.udp_total.load(Ordering::Relaxed), 1);
        assert_eq!(stats.udp_open.load(Ordering::Relaxed), 1);
        let _ = stop_tx.send(true);
        let _ = path.await;
    }
}
