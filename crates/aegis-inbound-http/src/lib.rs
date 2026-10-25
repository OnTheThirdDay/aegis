//! HTTP proxy inbound (FR-002).
//!
//! * `CONNECT authority-form HTTP/1.x` tunnels any TCP protocol (HTTPS).
//! * Absolute-form requests for `http://` URLs (`GET http://host/path`) are
//!   forwarded as one origin-form request per connection, so a system proxy
//!   setting also works for plain-HTTP sites. The forwarded head is rebuilt
//!   from parsed fields (hop-by-hop and proxy headers removed,
//!   `Connection: close` added); bodies need an exact `Content-Length`;
//!   chunked uploads are refused (411) to avoid request-smuggling ambiguity.
//!
//! The request head is capped (size and header count) before parsing, and
//! duplicate credentials or framing headers are refused. For CONNECT, `200`
//! is sent only after the destination connected.
#![forbid(unsafe_code)]

use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_contracts::reason::OpenFailure;
use aegis_contracts::Destination;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use std::time::Duration;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    module_id: "aegis.inbound.http_connect",
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client, Role::Gateway],
    operating_systems: &[OsFamily::Linux, OsFamily::Windows, OsFamily::Macos],
    provides: &[Capability::ByteStream, Capability::HalfClose],
    requires: &[],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 1,
        read_buffer_bytes: 8192,
        write_buffer_bytes: 512,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

pub const MAX_HEAD_BYTES: usize = 8 * 1024;
pub const MAX_HEADERS: usize = 64;

#[derive(Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

#[derive(Clone, Debug)]
pub struct HttpConnectConfig {
    pub credentials: Option<Credentials>,
    pub handshake_timeout: Duration,
}

/// A request rejection; the status has been sent when returned from
/// [`read_request`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    BadRequest,
    LengthRequired,
    MethodNotAllowed,
    ProxyAuthRequired,
    HeadersTooLarge,
    Timeout,
    Closed,
}

impl Rejection {
    fn status(self) -> Option<(u16, &'static str)> {
        match self {
            Rejection::BadRequest => Some((400, "Bad Request")),
            Rejection::LengthRequired => Some((411, "Length Required")),
            Rejection::MethodNotAllowed => Some((405, "Method Not Allowed")),
            Rejection::ProxyAuthRequired => Some((407, "Proxy Authentication Required")),
            Rejection::HeadersTooLarge => Some((431, "Request Header Fields Too Large")),
            Rejection::Timeout => Some((408, "Request Timeout")),
            Rejection::Closed => None,
        }
    }
}

pub fn status_for(f: OpenFailure) -> (u16, &'static str) {
    match f {
        OpenFailure::Denied | OpenFailure::Unauthorized => (403, "Forbidden"),
        OpenFailure::DnsFailure | OpenFailure::Refused | OpenFailure::Unreachable => {
            (502, "Bad Gateway")
        }
        OpenFailure::Timeout => (504, "Gateway Timeout"),
        OpenFailure::Quota | OpenFailure::Unavailable => (503, "Service Unavailable"),
        OpenFailure::Unsupported => (400, "Bad Request"),
        OpenFailure::Internal => (500, "Internal Server Error"),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// Largest request body forwarded for a plain-HTTP request.
pub const MAX_FORWARD_BODY: u64 = 64 * 1024 * 1024;

/// A plain-HTTP request to forward to `dest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub dest: Destination,
    /// Rebuilt origin-form request head (ends with CRLF CRLF).
    pub head: Bytes,
    /// Exact request body length to forward after the head.
    pub body_len: u64,
    /// WebSocket-style upgrade: relay both directions after the head.
    pub upgrade: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Connect(Destination),
    Forward(Forward),
}

fn check_auth(auth_values: &[&[u8]], creds: Option<&Credentials>) -> Result<(), Rejection> {
    if auth_values.len() > 1 {
        return Err(Rejection::BadRequest);
    }
    if let Some(creds) = creds {
        let Some(value) = auth_values.first() else {
            return Err(Rejection::ProxyAuthRequired);
        };
        let value = std::str::from_utf8(value).map_err(|_| Rejection::ProxyAuthRequired)?;
        let encoded = value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
            .ok_or(Rejection::ProxyAuthRequired)?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .map_err(|_| Rejection::ProxyAuthRequired)?;
        let expected = format!("{}:{}", creds.username, creds.password);
        if !ct_eq(&decoded, expected.as_bytes()) {
            return Err(Rejection::ProxyAuthRequired);
        }
    }
    Ok(())
}

/// Split `http://authority/path?query` into a destination and origin-form
/// target. Userinfo and non-`http` schemes are refused.
fn absolute_target(target: &str) -> Result<(Destination, String, String), Rejection> {
    let scheme_end = target.find("://").ok_or(Rejection::BadRequest)?;
    if !target[..scheme_end].eq_ignore_ascii_case("http") {
        return Err(Rejection::BadRequest);
    }
    let rest = &target[scheme_end + 3..];
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(split);
    if authority.is_empty() || authority.contains('@') || path.contains('#') {
        return Err(Rejection::BadRequest);
    }
    let has_port = match authority.rfind(']') {
        Some(close) => authority[close..].contains(':'),
        None => authority.contains(':'),
    };
    let with_port = if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let dest = Destination::parse_authority(&with_port).map_err(|_| Rejection::BadRequest)?;
    let path = if path.is_empty() {
        "/".to_owned()
    } else if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    Ok((dest, path, authority.to_owned()))
}

/// Parse a complete request head (CONNECT or absolute-form `http://`).
/// Pure, for tests and fuzzing.
pub fn parse_request(head: &[u8], creds: Option<&Credentials>) -> Result<Request, Rejection> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(Rejection::BadRequest),
        Err(httparse::Error::TooManyHeaders) => return Err(Rejection::HeadersTooLarge),
        Err(_) => return Err(Rejection::BadRequest),
    }
    let method = req.method.ok_or(Rejection::BadRequest)?;
    if method == "CONNECT" {
        return parse_head(head, creds).map(Request::Connect);
    }
    if !matches!(
        method,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS"
    ) {
        return Err(Rejection::MethodNotAllowed);
    }
    if !matches!(req.version, Some(0) | Some(1)) {
        return Err(Rejection::BadRequest);
    }
    let target = req.path.ok_or(Rejection::BadRequest)?;
    let (dest, path, authority) = absolute_target(target)?;
    let mut auth_values = Vec::new();
    let mut lengths = Vec::new();
    let mut connection_tokens = Vec::new();
    let mut has_host = false;
    let mut upgrade_value = None;
    let mut kept = Vec::new();
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        match name.as_str() {
            "transfer-encoding" => return Err(Rejection::LengthRequired),
            "content-length" => lengths.push(h.value),
            "proxy-authorization" => auth_values.push(h.value),
            "connection" | "proxy-connection" => {
                if let Ok(v) = std::str::from_utf8(h.value) {
                    connection_tokens.extend(v.split(',').map(|t| t.trim().to_ascii_lowercase()));
                }
            }
            "keep-alive" | "te" | "trailer" => {}
            "upgrade" => upgrade_value = Some(h.value),
            "host" => {
                if has_host {
                    return Err(Rejection::BadRequest);
                }
                has_host = true;
                kept.push(h);
            }
            _ => kept.push(h),
        }
    }
    check_auth(&auth_values, creds)?;
    let body_len = match lengths.as_slice() {
        [] => 0,
        [v] => std::str::from_utf8(v)
            .ok()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|n| *n <= MAX_FORWARD_BODY)
            .ok_or(Rejection::BadRequest)?,
        _ => return Err(Rejection::BadRequest),
    };
    let upgrade = upgrade_value.is_some() && connection_tokens.iter().any(|t| t == "upgrade");
    let mut out = BytesMut::with_capacity(head.len() + 32);
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    if !has_host {
        out.extend_from_slice(b"Host: ");
        out.extend_from_slice(authority.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    for h in kept {
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    if body_len > 0 {
        out.extend_from_slice(format!("Content-Length: {body_len}\r\n").as_bytes());
    }
    match (upgrade, upgrade_value) {
        (true, Some(u)) => {
            out.extend_from_slice(b"Upgrade: ");
            out.extend_from_slice(u);
            out.extend_from_slice(b"\r\nConnection: Upgrade\r\n");
        }
        _ => out.extend_from_slice(b"Connection: close\r\n"),
    }
    out.extend_from_slice(b"\r\n");
    Ok(Request::Forward(Forward {
        dest,
        head: out.freeze(),
        body_len,
        upgrade,
    }))
}

/// Parse a complete CONNECT request head. Pure, for tests and fuzzing.
pub fn parse_head(head: &[u8], creds: Option<&Credentials>) -> Result<Destination, Rejection> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Err(Rejection::BadRequest),
        Err(httparse::Error::TooManyHeaders) => return Err(Rejection::HeadersTooLarge),
        Err(_) => return Err(Rejection::BadRequest),
    }
    if req.method != Some("CONNECT") {
        return Err(Rejection::MethodNotAllowed);
    }
    if !matches!(req.version, Some(0) | Some(1)) {
        return Err(Rejection::BadRequest);
    }
    let target = req.path.ok_or(Rejection::BadRequest)?;
    if target.contains('/') || target.contains('@') {
        return Err(Rejection::BadRequest);
    }
    let dest = Destination::parse_authority(target).map_err(|_| Rejection::BadRequest)?;
    let mut auth_values = Vec::new();
    for h in req.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        match name.as_str() {
            "transfer-encoding" => return Err(Rejection::BadRequest),
            "content-length" => {
                if h.value.iter().any(|b| *b != b'0') || h.value.is_empty() {
                    return Err(Rejection::BadRequest);
                }
            }
            "proxy-authorization" => auth_values.push(h.value),
            _ => {}
        }
    }
    check_auth(&auth_values, creds)?;
    Ok(dest)
}

/// Read and validate a CONNECT or plain-HTTP request head; on rejection the
/// error status is written before returning. Returns the request and any
/// bytes the client sent after the head.
pub async fn read_any<S>(s: &mut S, cfg: &HttpConnectConfig) -> Result<(Request, Bytes), Rejection>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let res = tokio::time::timeout(cfg.handshake_timeout, read_head(s)).await;
    let outcome = match res {
        Err(_) => Err(Rejection::Timeout),
        Ok(Err(r)) => Err(r),
        Ok(Ok((head, rest))) => parse_request(&head, cfg.credentials.as_ref()).map(|r| (r, rest)),
    };
    if let Err(r) = outcome {
        reject(s, r).await;
        return Err(r);
    }
    outcome
}

async fn reject<S: AsyncWrite + Unpin>(s: &mut S, r: Rejection) {
    if let Some((code, reason)) = r.status() {
        let extra = if r == Rejection::ProxyAuthRequired {
            "Proxy-Authenticate: Basic realm=\"aegis\"\r\n"
        } else {
            ""
        };
        let resp = format!(
            "HTTP/1.1 {code} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n"
        );
        let _ = s.write_all(resp.as_bytes()).await;
        let _ = s.flush().await;
    }
}

/// Read and validate the request head; on rejection the error status is
/// written before returning. Returns the destination and any bytes the
/// client sent after the head.
pub async fn read_request<S>(
    s: &mut S,
    cfg: &HttpConnectConfig,
) -> Result<(Destination, Bytes), Rejection>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let res = tokio::time::timeout(cfg.handshake_timeout, read_head(s)).await;
    let outcome = match res {
        Err(_) => Err(Rejection::Timeout),
        Ok(Err(r)) => Err(r),
        Ok(Ok((head, rest))) => parse_head(&head, cfg.credentials.as_ref()).map(|d| (d, rest)),
    };
    if let Err(r) = outcome {
        if let Some((code, reason)) = r.status() {
            let extra = if r == Rejection::ProxyAuthRequired {
                "Proxy-Authenticate: Basic realm=\"aegis\"\r\n"
            } else {
                ""
            };
            let resp = format!(
                "HTTP/1.1 {code} {reason}\r\n{extra}Connection: close\r\nContent-Length: 0\r\n\r\n"
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.flush().await;
        }
        return Err(r);
    }
    outcome
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<(Bytes, Bytes), Rejection> {
    let mut buf = BytesMut::with_capacity(1024);
    loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = buf.split_to(pos + 4).freeze();
            return Ok((head, buf.freeze()));
        }
        if buf.len() >= MAX_HEAD_BYTES {
            return Err(Rejection::HeadersTooLarge);
        }
        let mut chunk = [0u8; 1024];
        let want = (MAX_HEAD_BYTES - buf.len()).min(chunk.len());
        let n = s
            .read(&mut chunk[..want])
            .await
            .map_err(|_| Rejection::Closed)?;
        if n == 0 {
            return Err(Rejection::Closed);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

pub async fn respond_established<S: AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<()> {
    s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    s.flush().await
}

pub async fn respond_failure<S: AsyncWrite + Unpin>(
    s: &mut S,
    f: OpenFailure,
) -> std::io::Result<()> {
    let (code, reason) = status_for(f);
    let resp =
        format!("HTTP/1.1 {code} {reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
    s.write_all(resp.as_bytes()).await?;
    s.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> Credentials {
        Credentials {
            username: "u".into(),
            password: "p".into(),
        }
    }

    #[test]
    fn absolute_form_is_rebuilt_without_proxy_or_hop_headers() {
        let r = parse_request(
            b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dTpw\r\nAccept: */*\r\n\r\n",
            Some(&creds()),
        )
        .expect("forward");
        let Request::Forward(f) = r else {
            unreachable!("forward expected")
        };
        assert_eq!(f.dest.to_string(), "example.com:80");
        let head = String::from_utf8(f.head.to_vec()).expect("utf8");
        assert!(head.starts_with("GET /a?b=1 HTTP/1.1\r\n"), "{head}");
        assert!(head.contains("Accept: */*\r\n") && head.ends_with("Connection: close\r\n\r\n"));
        assert!(!head.to_ascii_lowercase().contains("proxy-"), "{head}");
        assert_eq!((f.body_len, f.upgrade), (0, false));
        let r = parse_request(
            b"POST http://[2001:db8::1]:8080 HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            None,
        )
        .expect("v6");
        let Request::Forward(f) = r else {
            unreachable!("forward expected")
        };
        assert_eq!(f.body_len, 5);
        assert!(String::from_utf8_lossy(&f.head)
            .starts_with("POST / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n"));
    }

    #[test]
    fn absolute_form_smuggling_and_auth_are_refused() {
        let bad: &[&[u8]] = &[
            b"GET http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nContent-Length: +1\r\n\r\n",
            b"GET http://u:p@example.com/ HTTP/1.1\r\n\r\n",
            b"GET https://example.com/ HTTP/1.1\r\n\r\n",
            b"GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            b"TRACE http://example.com/ HTTP/1.1\r\n\r\n",
        ];
        for req in bad {
            assert!(
                parse_request(req, None).is_err(),
                "{}",
                String::from_utf8_lossy(req)
            );
        }
        assert_eq!(
            parse_request(b"GET http://example.com/ HTTP/1.1\r\n\r\n", Some(&creds())),
            Err(Rejection::ProxyAuthRequired)
        );
        assert!(matches!(
            parse_request(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n", None),
            Ok(Request::Connect(_))
        ));
    }

    #[test]
    fn tc_n02_valid_requests() {
        let d = parse_head(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
            None,
        )
        .expect("ok");
        assert_eq!(d.to_string(), "example.com:443");
        let d = parse_head(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n", None).expect("v6");
        assert_eq!(d.port, 8443);
        let auth = format!(
            "CONNECT a.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            base64::engine::general_purpose::STANDARD.encode("u:p")
        );
        assert!(parse_head(auth.as_bytes(), Some(&creds())).is_ok());
    }

    #[test]
    fn tc_n02_adversarial_requests() {
        let cases: &[(&[u8], Rejection)] = &[
            (
                b"GET http://a.com/ HTTP/1.1\r\n\r\n",
                Rejection::MethodNotAllowed,
            ),
            (
                b"connect a.com:443 HTTP/1.1\r\n\r\n",
                Rejection::MethodNotAllowed,
            ),
            (
                b"CONNECT http://a.com:443 HTTP/1.1\r\n\r\n",
                Rejection::BadRequest,
            ),
            (b"CONNECT a.com HTTP/1.1\r\n\r\n", Rejection::BadRequest),
            (
                b"CONNECT 2001:db8::1:443 HTTP/1.1\r\n\r\n",
                Rejection::BadRequest,
            ),
            (
                b"CONNECT user@a.com:443 HTTP/1.1\r\n\r\n",
                Rejection::BadRequest,
            ),
            (
                b"CONNECT a.com:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                Rejection::BadRequest,
            ),
            (
                b"CONNECT a.com:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
                Rejection::BadRequest,
            ),
            (b"CONNECT a.com:443 HTTP/2.0\r\n\r\n", Rejection::BadRequest),
            (
                b"CONNECT a.com:99999 HTTP/1.1\r\n\r\n",
                Rejection::BadRequest,
            ),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                parse_head(raw, None),
                Err(*expected),
                "{}",
                String::from_utf8_lossy(raw)
            );
        }
        let many: String = (0..80).map(|i| format!("X-{i}: v\r\n")).collect();
        let req = format!("CONNECT a.com:443 HTTP/1.1\r\n{many}\r\n");
        assert_eq!(
            parse_head(req.as_bytes(), None),
            Err(Rejection::HeadersTooLarge)
        );
    }

    #[test]
    fn tc_n02_authentication_required() {
        let c = creds();
        assert_eq!(
            parse_head(b"CONNECT a.com:443 HTTP/1.1\r\n\r\n", Some(&c)),
            Err(Rejection::ProxyAuthRequired)
        );
        let wrong = format!(
            "CONNECT a.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {}\r\n\r\n",
            base64::engine::general_purpose::STANDARD.encode("u:x")
        );
        assert_eq!(
            parse_head(wrong.as_bytes(), Some(&c)),
            Err(Rejection::ProxyAuthRequired)
        );
        let dup = "CONNECT a.com:443 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nProxy-Authorization: Basic dTpw\r\n\r\n";
        assert_eq!(
            parse_head(dup.as_bytes(), Some(&c)),
            Err(Rejection::BadRequest)
        );
    }

    #[tokio::test]
    async fn oversized_head_rejected_with_431() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let cfg = HttpConnectConfig {
            credentials: None,
            handshake_timeout: Duration::from_secs(2),
        };
        let srv =
            tokio::spawn(async move { read_request(&mut server, &cfg).await.map(|(d, _)| d) });
        let mut big = b"CONNECT a.com:443 HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', 10_000));
        let _ = client.write_all(&big).await;
        assert_eq!(srv.await.expect("join"), Err(Rejection::HeadersTooLarge));
        let mut out = vec![0u8; 64];
        let n = client.read(&mut out).await.expect("read");
        assert!(String::from_utf8_lossy(&out[..n]).starts_with("HTTP/1.1 431"));
    }

    #[tokio::test]
    async fn leftover_bytes_preserved() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let cfg = HttpConnectConfig {
            credentials: None,
            handshake_timeout: Duration::from_secs(2),
        };
        let srv = tokio::spawn(async move { read_request(&mut server, &cfg).await });
        client
            .write_all(b"CONNECT a.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01")
            .await
            .expect("w");
        let (d, rest) = srv.await.expect("join").expect("ok");
        assert_eq!(d.port, 443);
        assert_eq!(&rest[..], b"\x16\x03\x01");
    }
}
