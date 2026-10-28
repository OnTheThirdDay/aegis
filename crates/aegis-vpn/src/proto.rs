//! The control channel between the app and the helper: one JSON object per
//! line each way, a reply for every request.
//!
//! The VPN lives as long as the connection that started it: when the app
//! disconnects, exits or crashes, the helper takes the VPN down.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bumped when a request or reply changes incompatibly; the app then asks
/// for the helper to be updated.
pub const PROTOCOL: u32 = 1;

/// Longest line accepted either way.
const MAX_LINE: u64 = 16 * 1024;
/// At most this many names (or addresses) kept off the VPN.
pub const MAX_BYPASS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Hello,
    /// Capture this computer's traffic into the client node's local SOCKS
    /// proxy at `127.0.0.1:socks_port`. `bypass`: the gateway's host names
    /// or IPv4 addresses, which must stay reachable outside the VPN.
    Start {
        socks_port: u16,
        bypass: Vec<String>,
    },
    Status,
    Stop,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    pub tcp_open: u64,
    pub tcp_total: u64,
    pub tcp_failed: u64,
    pub udp_open: u64,
    pub udp_total: u64,
    pub udp_failed: u64,
    pub dns_queries: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    /// Whether this connection's VPN is up (status).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<Counters>,
}

impl Reply {
    pub fn error(e: impl Into<String>) -> Reply {
        Reply {
            error: Some(e.into()),
            ..Reply::default()
        }
    }
}

/// A host the helper may keep off the VPN: a DNS name or an IPv4 address.
pub fn valid_bypass(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Read one message; `None` at the end of the stream.
pub async fn read<R, T>(r: &mut R) -> io::Result<Option<T>>
where
    R: AsyncBufRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut line = Vec::new();
    let n = r.take(MAX_LINE).read_until(b'\n', &mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "message too long or cut short",
        ));
    }
    serde_json::from_slice(&line)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub async fn write<W, T>(w: &mut W, message: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut line = serde_json::to_vec(message).map_err(io::Error::other)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn messages_round_trip_one_per_line() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (_, mut w) = tokio::io::split(a);
        let (r, _) = tokio::io::split(b);
        let mut r = BufReader::new(r);
        let start = Request::Start {
            socks_port: 1080,
            bypass: vec!["gw.example.com".into()],
        };
        write(&mut w, &start).await.expect("write");
        write(&mut w, &Request::Stop).await.expect("write");
        assert_eq!(read::<_, Request>(&mut r).await.expect("read"), Some(start));
        assert_eq!(
            read::<_, Request>(&mut r).await.expect("read"),
            Some(Request::Stop)
        );
        drop(w);
        assert_eq!(read::<_, Request>(&mut r).await.expect("eof"), None);
    }

    #[tokio::test]
    async fn oversized_and_malformed_lines_are_refused() {
        let long = vec![b'x'; 20_000];
        let mut r = BufReader::new(&long[..]);
        assert!(read::<_, Request>(&mut r).await.is_err());
        let mut r = BufReader::new(&b"{\"op\":\"format_disk\"}\n"[..]);
        assert!(read::<_, Request>(&mut r).await.is_err());
    }

    #[test]
    fn bypass_hosts() {
        assert!(valid_bypass("gw.example.com"));
        assert!(valid_bypass("203.0.113.9"));
        for bad in ["", "a b", "x;rm", "[::1]", "a/b"] {
            assert!(!valid_bypass(bad), "{bad:?}");
        }
    }
}
