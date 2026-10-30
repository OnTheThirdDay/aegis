//! Minimal HTTPS/1.1 JSON POST for enrollment. Deliberately tiny: one
//! request per connection, bounded response, no redirects, no proxies, no
//! cookies. TLS is verified against the invitation's pinned edge CA and name
//! (private edge) or the public web PKI (public edge).

use crate::JoinError;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_RESPONSE: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Edge {
    pub outer_server_name: Option<String>,
    pub outer_ca_pem: Option<String>,
}

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Target, JoinError> {
    let rest = url
        .strip_prefix("https://")
        .ok_or(JoinError::InvalidInvite("enrollment URL must be https"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || path.contains(['\r', '\n', ' ']) {
        return Err(JoinError::InvalidInvite("malformed enrollment URL"));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, tail) = v6
            .split_once(']')
            .ok_or(JoinError::InvalidInvite("malformed enrollment URL"))?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p
                .parse()
                .map_err(|_| JoinError::InvalidInvite("bad port"))?,
            None => 443,
        };
        (h.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h.to_owned(),
                p.parse()
                    .map_err(|_| JoinError::InvalidInvite("bad port"))?,
            ),
            None => (authority.to_owned(), 443),
        }
    };
    if host.is_empty() {
        return Err(JoinError::InvalidInvite("malformed enrollment URL"));
    }
    Ok(Target {
        host,
        port,
        path: path.to_owned(),
    })
}

fn tls_config(edge: &Edge) -> Result<Arc<rustls::ClientConfig>, JoinError> {
    let mut roots = rustls::RootCertStore::empty();
    match &edge.outer_ca_pem {
        Some(pem) => {
            for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
                let cert = cert.map_err(|_| JoinError::InvalidInvite("bad edge certificate"))?;
                roots
                    .add(cert)
                    .map_err(|_| JoinError::InvalidInvite("bad edge certificate"))?;
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    let mut config = rustls::ClientConfig::builder_with_provider(aegis_identity::tls::provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| JoinError::Network("TLS unavailable".into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// POST `body` as JSON; returns `(status, body)`.
pub async fn post_json(url: &str, edge: &Edge, body: &Value) -> Result<(u16, Vec<u8>), JoinError> {
    post_json_up_to(url, edge, body, MAX_RESPONSE).await
}

/// How long connecting to the gateway may take, and one of its addresses.
const CONNECT_LIMIT: Duration = Duration::from_secs(15);
const PER_ADDRESS: Duration = Duration::from_secs(3);

/// Connect to `host:port`, trying its addresses in turn, IPv6 and IPv4
/// alternating. Each but the last gets a few seconds at most, so an
/// address this network can't reach (IPv6 where it doesn't work) doesn't
/// use up all of `limit` before the next is tried.
/// (As `aegis_transport_ws::connect_host`, which this crate doesn't use.)
async fn connect_host(
    host: &str,
    port: u16,
    limit: Duration,
) -> std::io::Result<tokio::net::TcpStream> {
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
        match tokio::time::timeout(try_for, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::new(ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

/// [`post_json`] accepting a response of up to `max` bytes (update
/// downloads come in larger pieces).
pub async fn post_json_up_to(
    url: &str,
    edge: &Edge,
    body: &Value,
    max: usize,
) -> Result<(u16, Vec<u8>), JoinError> {
    let target = parse(url)?;
    let name = edge
        .outer_server_name
        .clone()
        .unwrap_or_else(|| target.host.clone());
    let server_name =
        ServerName::try_from(name).map_err(|_| JoinError::InvalidInvite("invalid server name"))?;
    let config = tls_config(edge)?;
    let payload = body.to_string();
    let host_header = if target.host.contains(':') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let host_header = if target.port == 443 {
        host_header
    } else {
        format!("{host_header}:{}", target.port)
    };
    let exchange = async {
        let tcp = connect_host(&target.host, target.port, CONNECT_LIMIT)
            .await
            .map_err(|e| JoinError::Network(e.kind().to_string()))?;
        let mut tls = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, tcp)
            .await
            .map_err(|e| JoinError::Network(format!("TLS: {e}")))?;
        let request = format!(
            "POST {} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: aegis-join/{}\r\n\r\n",
            target.path,
            payload.len(),
            env!("CARGO_PKG_VERSION"),
        );
        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| JoinError::Network(e.kind().to_string()))?;
        tls.write_all(payload.as_bytes())
            .await
            .map_err(|e| JoinError::Network(e.kind().to_string()))?;
        tls.flush()
            .await
            .map_err(|e| JoinError::Network(e.kind().to_string()))?;
        let mut response = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    response.extend_from_slice(&chunk[..n]);
                    if response.len() > max {
                        return Err(JoinError::Network("response too large".into()));
                    }
                    if complete(&response) {
                        break;
                    }
                }
                // Peers that close without TLS close_notify still delivered
                // a complete, length-delimited response.
                Err(_) if complete(&response) => break,
                Err(e) => return Err(JoinError::Network(e.kind().to_string())),
            }
        }
        split(&response)
    };
    tokio::time::timeout(TIMEOUT, exchange)
        .await
        .map_err(|_| JoinError::Network("timed out".into()))?
}

fn head_len(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn content_length(head: &[u8]) -> Option<usize> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(head).ok()?;
    resp.headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .and_then(|v| v.trim().parse().ok())
}

fn complete(bytes: &[u8]) -> bool {
    match head_len(bytes) {
        Some(h) => content_length(&bytes[..h]).is_some_and(|l| bytes.len() >= h + l),
        None => false,
    }
}

fn split(bytes: &[u8]) -> Result<(u16, Vec<u8>), JoinError> {
    let head = head_len(bytes).ok_or(JoinError::Network("malformed response".into()))?;
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    resp.parse(&bytes[..head])
        .map_err(|_| JoinError::Network("malformed response".into()))?;
    let status = resp
        .code
        .ok_or(JoinError::Network("malformed response".into()))?;
    let mut body = bytes[head..].to_vec();
    if let Some(l) = content_length(&bytes[..head]) {
        body.truncate(l);
    }
    Ok((status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_with_ports_and_ipv6() {
        let t = parse("https://192.0.2.1:8444/enroll").expect("v4");
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("192.0.2.1", 8444, "/enroll")
        );
        let t = parse("https://[2001:db8::1]/enroll").expect("v6");
        assert_eq!((t.host.as_str(), t.port), ("2001:db8::1", 443));
        assert!(parse("http://x/enroll").is_err());
        assert!(parse("https://user@x/enroll").is_err());
    }
}
