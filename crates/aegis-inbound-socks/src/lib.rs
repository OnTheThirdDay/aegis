//! SOCKS5 inbound (FR-001): CONNECT only, IPv4/IPv6/domain, optional
//! username/password authentication. The caller performs admission and dials
//! between [`handshake`] and the reply; success is only sent once the
//! destination is connected.
#![forbid(unsafe_code)]

use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_contracts::destination::normalize_domain;
use aegis_contracts::reason::OpenFailure;
use aegis_contracts::{Destination, Host};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    module_id: "aegis.inbound.socks5",
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client, Role::Gateway],
    operating_systems: &[
        OsFamily::Linux,
        OsFamily::Windows,
        OsFamily::Macos,
        OsFamily::Android,
        OsFamily::Ios,
    ],
    provides: &[Capability::ByteStream, Capability::HalfClose],
    requires: &[],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 1,
        read_buffer_bytes: 1024,
        write_buffer_bytes: 1024,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

const VER: u8 = 0x05;
const METHOD_NONE: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_REJECT: u8 = 0xFF;
const CMD_CONNECT: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

impl Reply {
    pub fn for_failure(f: OpenFailure) -> Reply {
        match f {
            OpenFailure::Denied | OpenFailure::Unauthorized => Reply::NotAllowed,
            OpenFailure::DnsFailure | OpenFailure::Unreachable => Reply::HostUnreachable,
            OpenFailure::Refused => Reply::ConnectionRefused,
            OpenFailure::Timeout => Reply::TtlExpired,
            OpenFailure::Unsupported => Reply::AddressTypeNotSupported,
            OpenFailure::Quota | OpenFailure::Unavailable | OpenFailure::Internal => {
                Reply::GeneralFailure
            }
        }
    }
}

#[derive(Clone)]
pub struct Credentials {
    pub username: Vec<u8>,
    pub password: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

#[derive(Clone, Debug)]
pub struct SocksConfig {
    pub credentials: Option<Credentials>,
    pub handshake_timeout: Duration,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SocksError {
    Io(std::io::ErrorKind),
    Timeout,
    BadVersion,
    NoAcceptableMethod,
    AuthFailed,
    /// A failure reply has already been sent to the client.
    Rejected(Reply),
}

impl std::fmt::Display for SocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "socks5: {self:?}")
    }
}

impl std::error::Error for SocksError {}

impl From<std::io::Error> for SocksError {
    fn from(e: std::io::Error) -> Self {
        SocksError::Io(e.kind())
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Negotiate method, authenticate and parse the CONNECT request.
pub async fn handshake<S>(stream: &mut S, cfg: &SocksConfig) -> Result<Destination, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(cfg.handshake_timeout, handshake_inner(stream, cfg))
        .await
        .map_err(|_| SocksError::Timeout)?
}

async fn handshake_inner<S>(s: &mut S, cfg: &SocksConfig) -> Result<Destination, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != VER {
        return Err(SocksError::BadVersion);
    }
    let n = hdr[1] as usize;
    if n == 0 {
        s.write_all(&[VER, METHOD_REJECT]).await?;
        return Err(SocksError::NoAcceptableMethod);
    }
    let mut methods = vec![0u8; n];
    s.read_exact(&mut methods).await?;
    let wanted = if cfg.credentials.is_some() {
        METHOD_USERPASS
    } else {
        METHOD_NONE
    };
    if !methods.contains(&wanted) {
        s.write_all(&[VER, METHOD_REJECT]).await?;
        return Err(SocksError::NoAcceptableMethod);
    }
    s.write_all(&[VER, wanted]).await?;
    if let Some(creds) = &cfg.credentials {
        // RFC 1929 sub-negotiation.
        let mut v = [0u8; 2];
        s.read_exact(&mut v).await?;
        if v[0] != 0x01 {
            s.write_all(&[0x01, 0x01]).await?;
            return Err(SocksError::AuthFailed);
        }
        let mut user = vec![0u8; v[1] as usize];
        s.read_exact(&mut user).await?;
        let plen = s.read_u8().await? as usize;
        let mut pass = vec![0u8; plen];
        s.read_exact(&mut pass).await?;
        let ok = ct_eq(&user, &creds.username) & ct_eq(&pass, &creds.password);
        if !ok {
            s.write_all(&[0x01, 0x01]).await?;
            return Err(SocksError::AuthFailed);
        }
        s.write_all(&[0x01, 0x00]).await?;
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    if req[0] != VER {
        return Err(SocksError::BadVersion);
    }
    let cmd = req[1];
    let host = match req[3] {
        0x01 => {
            let mut o = [0u8; 4];
            s.read_exact(&mut o).await?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(o)))
        }
        0x04 => {
            let mut o = [0u8; 16];
            s.read_exact(&mut o).await?;
            Host::Ip(aegis_contracts::destination::canonical_ip(IpAddr::V6(
                Ipv6Addr::from(o),
            )))
        }
        0x03 => {
            let len = s.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            s.read_exact(&mut name).await?;
            let _port = s.read_u16().await?;
            let parsed = std::str::from_utf8(&name)
                .ok()
                .and_then(|n| normalize_domain(n).ok());
            match parsed {
                Some(d) => {
                    if cmd != CMD_CONNECT {
                        return reject(s, Reply::CommandNotSupported).await;
                    }
                    if req[2] != 0 {
                        return reject(s, Reply::GeneralFailure).await;
                    }
                    return finish(s, Host::Domain(d), _port).await;
                }
                None => return reject(s, Reply::HostUnreachable).await,
            }
        }
        _ => return reject(s, Reply::AddressTypeNotSupported).await,
    };
    let port = s.read_u16().await?;
    if cmd != CMD_CONNECT {
        return reject(s, Reply::CommandNotSupported).await;
    }
    if req[2] != 0 {
        return reject(s, Reply::GeneralFailure).await;
    }
    finish(s, host, port).await
}

async fn finish<S>(s: &mut S, host: Host, port: u16) -> Result<Destination, SocksError>
where
    S: AsyncWrite + Unpin,
{
    match Destination::new(host, port) {
        Ok(d) => Ok(d),
        Err(_) => reject(s, Reply::GeneralFailure).await,
    }
}

async fn reject<S, T>(s: &mut S, reply: Reply) -> Result<T, SocksError>
where
    S: AsyncWrite + Unpin,
{
    send_reply(s, reply, None).await?;
    Err(SocksError::Rejected(reply))
}

/// Send the final reply. `bound` is reported for success when known.
pub async fn send_reply<S>(
    s: &mut S,
    reply: Reply,
    bound: Option<SocketAddr>,
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut out = vec![VER, reply as u8, 0x00];
    match bound {
        Some(SocketAddr::V6(a)) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Some(SocketAddr::V4(a)) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        None => out.extend_from_slice(&[0x01, 0, 0, 0, 0, 0, 0]),
    }
    s.write_all(&out).await?;
    s.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(creds: Option<(&str, &str)>) -> SocksConfig {
        SocksConfig {
            credentials: creds.map(|(u, p)| Credentials {
                username: u.as_bytes().to_vec(),
                password: p.as_bytes().to_vec(),
            }),
            handshake_timeout: Duration::from_secs(2),
        }
    }

    async fn run(input: Vec<u8>, c: SocksConfig) -> (Result<Destination, SocksError>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move { handshake(&mut server, &c).await });
        client.write_all(&input).await.expect("write");
        let res = srv.await.expect("join");
        drop(client.shutdown().await);
        let mut out = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_millis(200), client.read_to_end(&mut out)).await;
        (res, out)
    }

    #[tokio::test]
    async fn tc_n01_connect_variants() {
        let (r, out) = run(
            vec![5, 1, 0, 5, 1, 0, 1, 93, 184, 216, 34, 0, 80],
            cfg(None),
        )
        .await;
        assert_eq!(r.expect("v4").to_string(), "93.184.216.34:80");
        assert_eq!(&out[..2], &[5, 0]);
        let mut v6 = vec![5, 1, 0, 5, 1, 0, 4];
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().expect("v6").octets());
        v6.extend_from_slice(&[1, 187]);
        assert_eq!(
            run(v6, cfg(None)).await.0.expect("v6").to_string(),
            "[2001:db8::1]:443"
        );
        let mut dom = vec![5, 1, 0, 5, 1, 0, 3, 11];
        dom.extend_from_slice(b"Example.COM");
        dom.extend_from_slice(&[0, 80]);
        assert_eq!(
            run(dom, cfg(None)).await.0.expect("domain").to_string(),
            "example.com:80"
        );
    }

    #[tokio::test]
    async fn tc_n01_unsupported_and_malformed() {
        let (r, out) = run(vec![5, 1, 0, 5, 2, 0, 1, 1, 2, 3, 4, 0, 80], cfg(None)).await;
        assert_eq!(r, Err(SocksError::Rejected(Reply::CommandNotSupported)));
        assert_eq!(out[3], 7);
        let (r, _) = run(vec![5, 1, 0, 5, 1, 0, 9], cfg(None)).await;
        assert_eq!(r, Err(SocksError::Rejected(Reply::AddressTypeNotSupported)));
        let (r, _) = run(vec![4, 1, 0, 80], cfg(None)).await;
        assert_eq!(r, Err(SocksError::BadVersion));
        let (r, _) = run(vec![5, 1, 0, 5, 1, 0, 1, 1, 2, 3, 4, 0, 0], cfg(None)).await;
        assert_eq!(
            r,
            Err(SocksError::Rejected(Reply::GeneralFailure)),
            "port 0"
        );
        let mut bad = vec![5, 1, 0, 5, 1, 0, 3, 5];
        bad.extend_from_slice(b"a b.c");
        bad.extend_from_slice(&[0, 80]);
        assert_eq!(
            run(bad, cfg(None)).await.0,
            Err(SocksError::Rejected(Reply::HostUnreachable))
        );
    }

    #[tokio::test]
    async fn tc_n01_authentication() {
        let mut ok = vec![5, 1, 2, 1, 4];
        ok.extend_from_slice(b"user");
        ok.push(4);
        ok.extend_from_slice(b"pass");
        ok.extend_from_slice(&[5, 1, 0, 1, 1, 1, 1, 1, 0, 80]);
        assert!(run(ok, cfg(Some(("user", "pass")))).await.0.is_ok());
        let mut bad = vec![5, 1, 2, 1, 4];
        bad.extend_from_slice(b"user");
        bad.push(4);
        bad.extend_from_slice(b"nope");
        assert_eq!(
            run(bad, cfg(Some(("user", "pass")))).await.0,
            Err(SocksError::AuthFailed)
        );
        // Client offering only no-auth when auth is required.
        let (r, out) = run(vec![5, 1, 0], cfg(Some(("user", "pass")))).await;
        assert_eq!(r, Err(SocksError::NoAcceptableMethod));
        assert_eq!(out, vec![5, 0xFF]);
    }
}
