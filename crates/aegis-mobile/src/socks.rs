//! Minimal SOCKS5 client for the hop from the VPN path into the client
//! node's local proxy (no authentication; CONNECT and UDP ASSOCIATE).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Where a captured connection goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A name the gateway resolves.
    Name(String, u16),
    Addr(SocketAddr),
}

/// SOCKS5 address and port of `target`.
fn put_target(out: &mut Vec<u8>, target: &Target) -> io::Result<()> {
    let port = match target {
        Target::Name(name, port) => {
            let len = u8::try_from(name.len()).map_err(|_| io::Error::other("name too long"))?;
            out.push(3);
            out.push(len);
            out.extend_from_slice(name.as_bytes());
            *port
        }
        Target::Addr(SocketAddr::V4(a)) => {
            out.push(1);
            out.extend_from_slice(&a.ip().octets());
            a.port()
        }
        Target::Addr(SocketAddr::V6(a)) => {
            out.push(4);
            out.extend_from_slice(&a.ip().octets());
            a.port()
        }
    };
    out.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

/// Send `cmd` for `target` and read the reply: the proxy's bound address.
async fn request(
    proxy: SocketAddr,
    cmd: u8,
    target: &Target,
) -> io::Result<(TcpStream, SocketAddr)> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true)?;
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(io::Error::other("SOCKS method refused"));
    }
    let mut req = vec![5, cmd, 0];
    put_target(&mut req, target)?;
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(io::Error::other("not a SOCKS5 reply"));
    }
    if head[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("refused through the tunnel (SOCKS reply {})", head[1]),
        ));
    }
    let ip = match head[3] {
        1 => {
            let mut o = [0u8; 4];
            s.read_exact(&mut o).await?;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        4 => {
            let mut o = [0u8; 16];
            s.read_exact(&mut o).await?;
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return Err(io::Error::other("bad SOCKS address type")),
    };
    let port = s.read_u16().await?;
    Ok((s, SocketAddr::new(ip, port)))
}

/// Open `target` through the SOCKS5 proxy at `proxy`.
pub async fn connect(proxy: SocketAddr, target: &Target) -> io::Result<TcpStream> {
    request(proxy, 1, target).await.map(|(s, _)| s)
}

/// A UDP association with the proxy. It lasts while `control` is open;
/// `socket` is connected to the proxy's relay.
pub struct UdpAssociation {
    pub control: TcpStream,
    pub socket: UdpSocket,
}

/// Ask the proxy at `proxy` to relay UDP.
pub async fn udp_associate(proxy: SocketAddr) -> io::Result<UdpAssociation> {
    let any = Target::Addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let (control, mut relay) = request(proxy, 3, &any).await?;
    if relay.ip().is_unspecified() {
        relay.set_ip(proxy.ip());
    }
    let socket = UdpSocket::bind(SocketAddr::new(proxy.ip(), 0)).await?;
    socket.connect(relay).await?;
    Ok(UdpAssociation { control, socket })
}

/// One datagram for `target`, framed for the proxy's relay.
pub fn encode_udp(target: &Target, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + 22);
    out.extend_from_slice(&[0, 0, 0]);
    put_target(&mut out, target)?;
    out.extend_from_slice(data);
    Ok(out)
}

/// The data of a datagram from the proxy's relay (`None` if malformed or a
/// fragment).
pub fn decode_udp(packet: &[u8]) -> Option<&[u8]> {
    let (head, rest) = packet.split_first_chunk::<4>()?;
    if head[..3] != [0, 0, 0] {
        return None;
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => usize::from(*rest.first()?) + 1 + 2,
        _ => return None,
    };
    rest.get(skip..)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connect_by_name_and_refusal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            for rep in [0u8, 2] {
                let (mut c, _) = listener.accept().await.expect("accept");
                let mut hello = [0u8; 3];
                c.read_exact(&mut hello).await.expect("hello");
                assert_eq!(hello, [5, 1, 0]);
                c.write_all(&[5, 0]).await.expect("method");
                let mut head = [0u8; 5];
                c.read_exact(&mut head).await.expect("head");
                assert_eq!(&head[..4], &[5, 1, 0, 3]);
                let mut name = vec![0u8; usize::from(head[4]) + 2];
                c.read_exact(&mut name).await.expect("name");
                assert_eq!(&name[..name.len() - 2], b"example.com");
                assert_eq!(&name[name.len() - 2..], &443u16.to_be_bytes());
                c.write_all(&[5, rep, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("reply");
                if rep == 0 {
                    c.write_all(b"hi").await.expect("data");
                }
            }
        });
        let target = Target::Name("example.com".into(), 443);
        let mut s = connect(proxy, &target).await.expect("connected");
        let mut hi = [0u8; 2];
        s.read_exact(&mut hi).await.expect("data");
        assert_eq!(&hi, b"hi");
        let refused = connect(proxy, &target).await.expect_err("refused");
        assert_eq!(refused.kind(), io::ErrorKind::ConnectionRefused);
        server.await.expect("server");
    }

    #[test]
    fn udp_framing() {
        let name = Target::Name("example.com".into(), 443);
        let framed = encode_udp(&name, b"quic").expect("encode");
        assert_eq!(&framed[..5], &[0, 0, 0, 3, 11]);
        assert_eq!(decode_udp(&framed), Some(&b"quic"[..]));
        let v6 = Target::Addr("[2001:db8::1]:53".parse().expect("addr"));
        let framed = encode_udp(&v6, b"dns").expect("encode");
        assert_eq!(framed.len(), 4 + 16 + 2 + 3);
        assert_eq!(decode_udp(&framed), Some(&b"dns"[..]));
        let mut fragment = framed.clone();
        fragment[2] = 1;
        assert_eq!(decode_udp(&fragment), None);
        assert_eq!(decode_udp(&[0, 0, 0, 1, 1]), None);
    }
}
