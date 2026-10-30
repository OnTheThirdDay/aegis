//! Fresh addresses for the gateway while the VPN runs (iOS).
//!
//! On iOS the tunnel answers every lookup, the extension's own too, so the
//! gateway's addresses are looked up once before it starts and pinned
//! (`prepare_tunnel`). When the network stops carrying traffic to those
//! addresses (a Cloudflare edge address slowed or blocked by one ISP),
//! reconnecting to them keeps failing; Android, whose own lookups bypass
//! the VPN, gets other addresses on its next lookup. This asks public
//! resolvers directly (the extension's sockets bypass the tunnel) for
//! current addresses. A wrong answer can't redirect the device: the outer
//! TLS and the gateway's pinned identity are checked on every connection.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

/// Asked together; the first useful answers win. Inside mainland China
/// (Alibaba, DNSPod) and outside it (Cloudflare). Not Google's: blocked
/// in mainland China.
const RESOLVERS: [Ipv4Addr; 3] = [
    Ipv4Addr::new(223, 5, 5, 5),
    Ipv4Addr::new(119, 29, 29, 29),
    Ipv4Addr::new(1, 1, 1, 1),
];
const TIMEOUT: Duration = Duration::from_secs(4);
/// Addresses kept per name.
pub(crate) const MAX_ADDRS: usize = 8;

/// The IPv4 addresses public resolvers give for `host` (empty when none
/// answered in time), first answers first.
pub(crate) async fn lookup(host: &str) -> Vec<Ipv4Addr> {
    let Some(query) = query(rand::random(), host) else {
        return Vec::new();
    };
    let mut asks = tokio::task::JoinSet::new();
    for resolver in RESOLVERS {
        let query = query.clone();
        asks.spawn(async move {
            tokio::time::timeout(TIMEOUT, ask(resolver, &query))
                .await
                .ok()
                .flatten()
                .unwrap_or_default()
        });
    }
    let mut found: Vec<Ipv4Addr> = Vec::new();
    while let Some(answer) = asks.join_next().await {
        for ip in answer.unwrap_or_default() {
            if !found.contains(&ip) && found.len() < MAX_ADDRS {
                found.push(ip);
            }
        }
        // Two resolvers agreeing (or a full list) is enough.
        if found.len() >= 2 {
            asks.abort_all();
            break;
        }
    }
    found
}

async fn ask(resolver: Ipv4Addr, query: &[u8]) -> Option<Vec<Ipv4Addr>> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .await
        .ok()?;
    socket.connect((resolver, 53)).await.ok()?;
    socket.send(query).await.ok()?;
    let mut buf = [0u8; 1500];
    loop {
        let n = socket.recv(&mut buf).await.ok()?;
        if let Some(ips) = answers(query, &buf[..n]) {
            return Some(ips);
        }
    }
}

/// A standard recursive `A` query for `host`.
fn query(id: u16, host: &str) -> Option<Vec<u8>> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]);
    Some(q)
}

/// The `A` records of `response` to `query`; `None` when it isn't the
/// answer to it (another ID or question, or malformed).
fn answers(query: &[u8], r: &[u8]) -> Option<Vec<Ipv4Addr>> {
    if r.len() < 12 || r[0..2] != query[0..2] || r[2] & 0x80 == 0 {
        return None;
    }
    // The question must be ours (case aside).
    let question = query.get(12..)?;
    if !r
        .get(12..12 + question.len())?
        .eq_ignore_ascii_case(question)
    {
        return None;
    }
    if u16::from_be_bytes([r[4], r[5]]) != 1 || r[3] & 0x0F != 0 {
        return Some(Vec::new());
    }
    let count = u16::from_be_bytes([r[6], r[7]]);
    let mut pos = 12 + question.len();
    let mut ips = Vec::new();
    for _ in 0..count {
        pos = skip_name(r, pos)?;
        let head = r.get(pos..pos + 10)?;
        let (rtype, class) = (
            u16::from_be_bytes([head[0], head[1]]),
            u16::from_be_bytes([head[2], head[3]]),
        );
        let len = usize::from(u16::from_be_bytes([head[8], head[9]]));
        let data = r.get(pos + 10..pos + 10 + len)?;
        if rtype == 1 && class == 1 && len == 4 {
            ips.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        pos += 10 + len;
    }
    Some(ips)
}

/// The position after the (possibly compressed) name at `pos`.
fn skip_name(r: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *r.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xC0 == 0xC0 => return Some(pos + 2),
            l if l <= 63 => pos += 1 + usize::from(l),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response to `q` with a CNAME and two A records.
    fn response(q: &[u8]) -> Vec<u8> {
        let mut r = q.to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 3;
        // CNAME (name by pointer), then the alias' two addresses.
        r.extend_from_slice(&[
            0xC0, 0x0C, 0, 5, 0, 1, 0, 0, 0, 60, 0, 4, 1, b'x', 0xC0, 0x0C,
        ]);
        for ip in [[104, 21, 1, 1], [172, 67, 2, 2]] {
            r.extend_from_slice(&[1, b'x', 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            r.extend_from_slice(&ip);
        }
        r
    }

    #[test]
    fn answers_are_read_from_responses_to_the_query() {
        let q = query(0x4242, "gw.example.test").expect("query");
        assert_eq!(
            answers(&q, &response(&q)),
            Some(vec![
                Ipv4Addr::new(104, 21, 1, 1),
                Ipv4Addr::new(172, 67, 2, 2)
            ])
        );
        // Another ID, or another question: not ours.
        let other = query(0x4243, "gw.example.test").expect("query");
        assert_eq!(answers(&q, &response(&other)), None);
        let other = query(0x4242, "gx.example.test").expect("query");
        assert_eq!(answers(&q, &response(&other)), None);
        // Truncated: nothing, not a panic.
        let r = response(&q);
        assert_eq!(answers(&q, &r[..r.len() - 3]), None);
        assert!(query(1, "bad..name").is_none());
    }
}
