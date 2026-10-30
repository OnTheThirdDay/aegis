//! WebSocket transport (03 §4).
//!
//! The outer WebSocket carries inner TLS bytes as binary messages. Message
//! boundaries are invisible to TLS/AGP: this adapter exposes an ordered byte
//! duplex. The upgrade itself grants nothing — inner mTLS must complete before
//! any proxy command is honored. Origin is never used for authentication;
//! by default requests carrying an `Origin` header (i.e. browsers) are refused.
//!
//! Padding: the client asks for padded framing with [`PADDING_HEADER`]; a
//! gateway that supports it answers with the same header, and only then do
//! both ends pad (see [`WsDuplex`]). Older clients and gateways ignore it.
#![forbid(unsafe_code)]

mod duplex;

pub use duplex::WsDuplex;

use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::ServerName;
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

pub const DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    module_id: "aegis.transport.websocket",
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
        Capability::HttpReverseProxyCompatible,
        Capability::OuterTls,
    ],
    requires: &[],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 1,
        read_buffer_bytes: 64 * 1024,
        write_buffer_bytes: 64 * 1024,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

#[derive(Debug)]
pub enum WsError {
    InvalidUrl(&'static str),
    Connect(std::io::Error),
    Timeout,
    Tls(std::io::Error),
    Handshake(String),
    Config(String),
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WsError::InvalidUrl(w) => write!(f, "invalid WebSocket URL: {w}"),
            WsError::Connect(e) => write!(f, "TCP connect failed: {e}"),
            WsError::Timeout => f.write_str("WebSocket connect/handshake timed out"),
            WsError::Tls(e) => write!(f, "outer TLS failed: {e}"),
            WsError::Handshake(e) => write!(f, "WebSocket handshake failed: {e}"),
            WsError::Config(e) => write!(f, "transport configuration error: {e}"),
        }
    }
}

impl std::error::Error for WsError {}

/// Upgrade header announcing padded framing, in the request and its answer.
pub const PADDING_HEADER: &str = "aegis-framing";
const PADDING_VERSION: &str = "padded-1";

fn ws_config(max_message: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message))
        .accept_unmasked_frames(false)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WsServerConfig {
    pub path: String,
    pub handshake_timeout: Duration,
    pub max_message_bytes: usize,
    /// Allowed `Origin` values. Empty = refuse any request carrying Origin.
    pub allowed_origins: Vec<String>,
}

impl Default for WsServerConfig {
    fn default() -> Self {
        WsServerConfig {
            path: "/agp".into(),
            handshake_timeout: Duration::from_secs(10),
            max_message_bytes: 128 * 1024,
            allowed_origins: Vec::new(),
        }
    }
}

fn reject(status: StatusCode) -> ErrorResponse {
    let mut r = ErrorResponse::new(None);
    *r.status_mut() = status;
    r
}

/// Perform the server-side upgrade on an accepted connection.
pub async fn accept<S>(stream: S, cfg: &WsServerConfig) -> Result<WsDuplex<S>, WsError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = cfg.path.clone();
    let origins = cfg.allowed_origins.clone();
    let padded = Arc::new(AtomicBool::new(false));
    let agreed = Arc::clone(&padded);
    // The callback signature (and its large error type) is tungstenite's.
    #[allow(clippy::result_large_err)]
    let callback = move |req: &Request, mut resp: Response| -> Result<Response, ErrorResponse> {
        if req.uri().path() != path {
            return Err(reject(StatusCode::NOT_FOUND));
        }
        if req.uri().query().is_some() {
            return Err(reject(StatusCode::BAD_REQUEST));
        }
        if let Some(origin) = req.headers().get("origin") {
            let allowed = origin
                .to_str()
                .map(|o| origins.iter().any(|a| a == o))
                .unwrap_or(false);
            if !allowed {
                return Err(reject(StatusCode::FORBIDDEN));
            }
        }
        if req
            .headers()
            .get(PADDING_HEADER)
            .is_some_and(|v| v == PADDING_VERSION)
        {
            resp.headers_mut()
                .insert(PADDING_HEADER, HeaderValue::from_static(PADDING_VERSION));
            agreed.store(true, Ordering::Relaxed);
        }
        Ok(resp)
    };
    let fut = tokio_tungstenite::accept_hdr_async_with_config(
        stream,
        callback,
        Some(ws_config(cfg.max_message_bytes)),
    );
    let ws = tokio::time::timeout(cfg.handshake_timeout, fut)
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(|e| WsError::Handshake(e.to_string()))?;
    Ok(WsDuplex::new(ws, padded.load(Ordering::Relaxed)))
}

/// A stream whose first bytes were already read (e.g. to route a request by
/// path); they are replayed before the rest of the underlying stream.
pub struct Prefixed<S> {
    prefix: Vec<u8>,
    pos: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Prefixed {
            prefix,
            pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WsClientConfig {
    /// `wss://host[:port]/path` (or `ws://` for an explicitly acknowledged
    /// loopback/trusted-hop deployment; inner mTLS still applies).
    pub url: String,
    /// Extra trust anchor for the outer TLS hop (PEM). Public roots are used
    /// otherwise.
    pub outer_ca_pem: Option<String>,
    /// Verify the outer certificate against this name instead of the URL
    /// host. With it, `outer_ca_pem` is the only trust anchor: a pinned
    /// private outer CA never widens to public roots.
    pub outer_server_name: Option<String>,
    /// Connect to these addresses (in order) instead of resolving the URL
    /// host; TLS and the WebSocket Host still use the URL host.
    pub connect_addresses: Vec<std::net::SocketAddr>,
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub max_message_bytes: usize,
}

pub struct ParsedUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

pub fn parse_url(url: &str) -> Result<ParsedUrl, WsError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| WsError::InvalidUrl("unparseable"))?;
    let tls = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => return Err(WsError::InvalidUrl("scheme must be ws or wss")),
    };
    if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
        return Err(WsError::InvalidUrl("credentials in URL are not allowed"));
    }
    let host = uri.host().ok_or(WsError::InvalidUrl("missing host"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
        .to_owned();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
    let path = uri
        .path_and_query()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "/".into());
    Ok(ParsedUrl {
        tls,
        host,
        port,
        path,
    })
}

/// Outer connection: plain TCP or TLS over TCP.
pub enum OuterStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for OuterStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OuterStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            OuterStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for OuterStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            OuterStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            OuterStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OuterStream::Plain(s) => Pin::new(s).poll_flush(cx),
            OuterStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            OuterStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            OuterStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

fn outer_tls_config(
    extra_ca: Option<&str>,
    pinned_only: bool,
) -> Result<Arc<rustls::ClientConfig>, WsError> {
    let mut roots = rustls::RootCertStore::empty();
    if pinned_only {
        if extra_ca.is_none() {
            return Err(WsError::Config(
                "outer_server_name requires a pinned outer CA".into(),
            ));
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if let Some(pem) = extra_ca {
        for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|_| WsError::Config("invalid outer CA PEM".into()))?;
            roots
                .add(cert)
                .map_err(|e| WsError::Config(e.to_string()))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| WsError::Config(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Outer early data never carries enrollment/auth/proxy operations.
    config.enable_early_data = false;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// How long one of several addresses is tried before the next.
const PER_ADDRESS: Duration = Duration::from_secs(3);

/// Connect to `host:port`, trying its addresses in turn, IPv6 and IPv4
/// alternating. Each but the last gets a few seconds at most, so an
/// address this network can't reach (IPv6 where it doesn't work) doesn't
/// use up all of `limit` before the next is tried.
pub async fn connect_host(host: &str, port: u16, limit: Duration) -> std::io::Result<TcpStream> {
    use std::io::{Error, ErrorKind};
    let deadline = tokio::time::Instant::now() + limit;
    let found = tokio::time::timeout(limit, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "name lookup timed out"))??;
    let (v6, v4): (Vec<_>, Vec<_>) = found.partition(std::net::SocketAddr::is_ipv6);
    let mut addrs = Vec::new();
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => addrs.extend(x.into_iter().chain(y)),
        }
    }
    let mut last = Error::new(ErrorKind::NotFound, "no address");
    for (i, addr) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        let try_for = if i + 1 < addrs.len() {
            left.min(PER_ADDRESS)
        } else {
            left
        };
        match tokio::time::timeout(try_for, TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::new(ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

pub async fn connect(cfg: &WsClientConfig) -> Result<WsDuplex<OuterStream>, WsError> {
    let url = parse_url(&cfg.url)?;
    let tcp = if cfg.connect_addresses.is_empty() {
        connect_host(&url.host, url.port, cfg.connect_timeout)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::TimedOut => WsError::Timeout,
                _ => WsError::Connect(e),
            })?
    } else {
        let mut last = WsError::Timeout;
        let mut connected = None;
        for addr in &cfg.connect_addresses {
            match tokio::time::timeout(cfg.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    connected = Some(s);
                    break;
                }
                Ok(Err(e)) => last = WsError::Connect(e),
                Err(_) => last = WsError::Timeout,
            }
        }
        connected.ok_or(last)?
    };
    let _ = tcp.set_nodelay(true);
    let outer = if url.tls {
        let config =
            outer_tls_config(cfg.outer_ca_pem.as_deref(), cfg.outer_server_name.is_some())?;
        let name = ServerName::try_from(
            cfg.outer_server_name
                .clone()
                .unwrap_or_else(|| url.host.clone()),
        )
        .map_err(|_| WsError::InvalidUrl("invalid TLS server name"))?;
        let tls = tokio::time::timeout(
            cfg.handshake_timeout,
            tokio_rustls::TlsConnector::from(config).connect(name, tcp),
        )
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(WsError::Tls)?;
        OuterStream::Tls(Box::new(tls))
    } else {
        OuterStream::Plain(tcp)
    };
    let mut request = cfg
        .url
        .as_str()
        .into_client_request()
        .map_err(|e| WsError::Handshake(e.to_string()))?;
    request
        .headers_mut()
        .insert(PADDING_HEADER, HeaderValue::from_static(PADDING_VERSION));
    let fut = tokio_tungstenite::client_async_with_config(
        request,
        outer,
        Some(ws_config(cfg.max_message_bytes)),
    );
    let (ws, resp) = tokio::time::timeout(cfg.handshake_timeout, fut)
        .await
        .map_err(|_| WsError::Timeout)?
        .map_err(|e| WsError::Handshake(e.to_string()))?;
    let padded = resp
        .headers()
        .get(PADDING_HEADER)
        .is_some_and(|v| v == PADDING_VERSION);
    Ok(WsDuplex::new(ws, padded))
}
