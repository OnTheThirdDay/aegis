//! HTTP CONNECT inbound (FR-002).
//!
//! Only `CONNECT authority-form HTTP/1.x` is accepted. The request head is
//! capped (size and header count) before parsing; bodies, `Transfer-Encoding`
//! and duplicate credentials are refused so there is no request-smuggling
//! ambiguity. `200` is sent only after the destination connected.
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

/// Parse a complete request head. Pure, for tests and fuzzing.
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
    Ok(dest)
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
