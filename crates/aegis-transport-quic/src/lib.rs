//! QUIC transport: a direct UDP path between a device and its gateway.
//!
//! One QUIC connection per device session:
//! * The QUIC handshake *is* the mutual TLS 1.3 handshake, with the same
//!   device and gateway certificates, CA pinning, revocation and policy as
//!   the inner TLS of the WebSocket path (the caller passes those rustls
//!   configs; only the ALPN changes). No 0-RTT, no resumption.
//! * The AGP session runs on the one bidirectional stream the client opens
//!   ([`QuicStream`]).
//! * UDP flows travel as QUIC datagrams (RFC 9221): unreliable and
//!   unordered, so a lost datagram never holds up anything else.
//!
//! The QUIC port is reached directly (not through an HTTP proxy or CDN);
//! clients fall back to WebSocket where it can't be reached.
#![forbid(unsafe_code)]

use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use bytes::Bytes;
use rustls_pki_types::CertificateDer;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use quinn::{Connection, Endpoint, Incoming};

/// ALPN of an AGP session over QUIC.
pub const ALPN_AGP_QUIC: &[u8] = b"agp-quic/1";

pub const DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    module_id: "aegis.transport.quic",
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
    provides: &[
        Capability::ByteStream,
        Capability::Ordered,
        Capability::HalfClose,
        Capability::Datagram,
    ],
    requires: &[],
    budget: ResourceBudget {
        max_open_streams: 1,
        max_sockets: 1,
        read_buffer_bytes: 1024 * 1024,
        write_buffer_bytes: 1024 * 1024,
        timers: 2,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

/// Connection-level limits shared by both ends.
#[derive(Clone, Debug)]
pub struct Limits {
    /// The connection closes after this long without any packet.
    pub idle_timeout: Duration,
    /// Keepalive PING interval: keeps NAT bindings open on idle tunnels.
    pub keepalive: Duration,
    /// Bytes of received datagrams QUIC buffers before dropping new ones.
    pub datagram_receive_buffer: usize,
    /// Bytes of datagrams waiting to be sent before the oldest are dropped.
    pub datagram_send_buffer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            idle_timeout: Duration::from_secs(60),
            keepalive: Duration::from_secs(15),
            datagram_receive_buffer: 1024 * 1024,
            datagram_send_buffer: 1024 * 1024,
        }
    }
}

#[derive(Debug)]
pub enum QuicError {
    Config(String),
    Resolve(std::io::Error),
    Bind(std::io::Error),
    Connect(String),
    Timeout,
    /// The peer's certificate is missing or unusable.
    Identity,
}

impl fmt::Display for QuicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuicError::Config(e) => write!(f, "QUIC configuration error: {e}"),
            QuicError::Resolve(e) => write!(f, "could not resolve the QUIC address: {e}"),
            QuicError::Bind(e) => write!(f, "could not open a UDP socket: {e}"),
            QuicError::Connect(e) => write!(f, "QUIC connection failed: {e}"),
            QuicError::Timeout => f.write_str("QUIC connect timed out"),
            QuicError::Identity => f.write_str("QUIC peer certificate missing"),
        }
    }
}

impl std::error::Error for QuicError {}

fn transport(limits: &Limits, server: bool) -> Result<Arc<quinn::TransportConfig>, QuicError> {
    let mut t = quinn::TransportConfig::default();
    let idle = quinn::IdleTimeout::try_from(limits.idle_timeout)
        .map_err(|e| QuicError::Config(e.to_string()))?;
    t.max_idle_timeout(Some(idle));
    t.keep_alive_interval(Some(limits.keepalive));
    t.datagram_receive_buffer_size(Some(limits.datagram_receive_buffer));
    t.datagram_send_buffer_size(limits.datagram_send_buffer);
    // One session stream per connection, opened by the client; the gateway
    // accepts no further streams and opens none.
    let peer_streams: u32 = if server { 1 } else { 0 };
    t.max_concurrent_bidi_streams(peer_streams.into());
    t.max_concurrent_uni_streams(0u32.into());
    Ok(Arc::new(t))
}

/// Bind the gateway's QUIC endpoint. `tls` is the gateway's mTLS server
/// config (mandatory, verified client certificates); its ALPN is replaced.
pub fn server(
    bind: SocketAddr,
    tls: &rustls::ServerConfig,
    limits: &Limits,
) -> Result<Endpoint, QuicError> {
    Endpoint::server(server_config(tls, limits)?, bind).map_err(QuicError::Bind)
}

fn server_config(
    tls: &rustls::ServerConfig,
    limits: &Limits,
) -> Result<quinn::ServerConfig, QuicError> {
    let mut tls = tls.clone();
    tls.alpn_protocols = vec![ALPN_AGP_QUIC.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls))
        .map_err(|e| QuicError::Config(e.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(transport(limits, true)?);
    // Phones change networks: let a connection follow its client.
    config.migration(true);
    Ok(config)
}

/// Replace the server's TLS identity (certificate renewal); connections
/// already open keep theirs.
pub fn reload(
    endpoint: &Endpoint,
    tls: &rustls::ServerConfig,
    limits: &Limits,
) -> Result<(), QuicError> {
    endpoint.set_server_config(Some(server_config(tls, limits)?));
    Ok(())
}

/// The certificate the peer presented in the handshake (verified by the
/// TLS config's verifier before the connection completed).
pub fn peer_certificate(conn: &Connection) -> Option<CertificateDer<'static>> {
    conn.peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?
        .into_iter()
        .next()
}

/// Gateway side: wait for the client's session stream.
pub async fn accept_stream(conn: &Connection, timeout: Duration) -> Result<QuicStream, QuicError> {
    let (send, recv) = tokio::time::timeout(timeout, conn.accept_bi())
        .await
        .map_err(|_| QuicError::Timeout)?
        .map_err(|e| QuicError::Connect(e.to_string()))?;
    Ok(QuicStream { send, recv })
}

/// How a client reaches a gateway over QUIC.
#[derive(Clone)]
pub struct ClientConfig {
    /// `host:port` (or `[v6]:port`) of the gateway's QUIC listener.
    pub address: String,
    /// The gateway's certificate name (as for the inner TLS).
    pub server_name: String,
    /// The device's mTLS client config; its ALPN is replaced.
    pub tls: Arc<rustls::ClientConfig>,
    pub connect_timeout: Duration,
    pub limits: Limits,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("address", &self.address)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// Connect to a gateway and open the session stream. Each resolved
/// address is tried in turn (at most four), within `connect_timeout` overall.
pub async fn connect(cfg: &ClientConfig) -> Result<(Connection, QuicStream), QuicError> {
    let mut tls = (*cfg.tls).clone();
    tls.alpn_protocols = vec![ALPN_AGP_QUIC.to_vec()];
    tls.enable_early_data = false;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| QuicError::Config(e.to_string()))?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(transport(&cfg.limits, false)?);
    let attempt = async {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(cfg.address.as_str())
            .await
            .map_err(QuicError::Resolve)?
            .take(4)
            .collect();
        let mut last = QuicError::Connect("no address".into());
        for addr in addrs {
            match connect_to(addr, &cfg.server_name, client.clone()).await {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    };
    tokio::time::timeout(cfg.connect_timeout, attempt)
        .await
        .map_err(|_| QuicError::Timeout)?
}

async fn connect_to(
    addr: SocketAddr,
    server_name: &str,
    config: quinn::ClientConfig,
) -> Result<(Connection, QuicStream), QuicError> {
    let local: SocketAddr = if addr.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let mut endpoint = Endpoint::client(local).map_err(QuicError::Bind)?;
    endpoint.set_default_client_config(config);
    let conn = endpoint
        .connect(addr, server_name)
        .map_err(|e| QuicError::Connect(e.to_string()))?
        .await
        .map_err(|e| QuicError::Connect(e.to_string()))?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| QuicError::Connect(e.to_string()))?;
    Ok((conn, QuicStream { send, recv }))
}

/// Send one datagram on the connection; `false` when it was not sent
/// (too large for the path now, datagrams unsupported, or the connection
/// is gone). QUIC drops the oldest queued datagrams when its buffer fills.
pub fn send_datagram(conn: &Connection, datagram: Bytes) -> bool {
    conn.send_datagram(datagram).is_ok()
}

/// Largest datagram the connection can send now, if any.
pub fn max_datagram(conn: &Connection) -> Option<usize> {
    conn.max_datagram_size()
}

/// The session stream: an ordered byte duplex. Shutdown finishes the send
/// side; dropping it resets both.
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), cx)
    }
}
