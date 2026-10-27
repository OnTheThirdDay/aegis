//! Minimal SOCKS5 client for the hop from the VPN path into the client
//! node's local proxy (no authentication, CONNECT only).

use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Where a captured connection goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A name the gateway resolves.
    Name(String, u16),
    Addr(SocketAddr),
}

/// Open `target` through the SOCKS5 proxy at `proxy`.
pub async fn connect(proxy: SocketAddr, target: &Target) -> io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy).await?;
    s.set_nodelay(true)?;
    s.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(io::Error::other("SOCKS method refused"));
    }
    let mut req = vec![5, 1, 0];
    let port = match target {
        Target::Name(name, port) => {
            let len = u8::try_from(name.len()).map_err(|_| io::Error::other("name too long"))?;
            req.push(3);
            req.push(len);
            req.extend_from_slice(name.as_bytes());
            *port
        }
        Target::Addr(SocketAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.ip().octets());
            a.port()
        }
        Target::Addr(SocketAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.ip().octets());
            a.port()
        }
    };
    req.extend_from_slice(&port.to_be_bytes());
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
    // Skip the bound address.
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => usize::from(s.read_u8().await?) + 2,
        _ => return Err(io::Error::other("bad SOCKS address type")),
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await?;
    Ok(s)
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
}
