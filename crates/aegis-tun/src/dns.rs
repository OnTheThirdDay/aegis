//! Fake-IP DNS for the VPN path.
//!
//! Apps resolve names before connecting, but the gateway is the resolver
//! (`remote_required`): the device must never look names up itself. So the
//! VPN answers every `A` query with an address from a reserved pool and
//! remembers which name it stands for; a connection to that address is
//! opened through the tunnel *by name*. `AAAA` and other types get an empty
//! answer, which keeps apps on the IPv4 addresses this pool hands out.
//!
//! A few names can be pinned to their real addresses instead
//! ([`FakeDns::pin`]): on a desktop the client node itself resolves the
//! gateway through the system resolver, which the VPN answers, and must
//! reach the real gateway, whose addresses stay off the VPN.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// The pool: 198.18.0.0/15 (benchmarking range, never a real destination).
const POOL_BASE: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const POOL_SIZE: u32 = 1 << 17;
/// The VPN's DNS server address (inside the pool, never handed out).
pub const SERVER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
/// First address handed out (after the network and server addresses).
const FIRST: u32 = 2;
/// Answer TTL: short enough that a recycled address is rarely still cached.
const TTL: u32 = 120;

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Name ⇄ pool address mapping. Addresses are handed out in turn; once the
/// pool wraps, the oldest mapping is reused.
pub struct FakeDns {
    by_name: HashMap<String, Ipv4Addr>,
    by_ip: HashMap<Ipv4Addr, String>,
    next: u32,
    pinned: HashMap<String, Vec<Ipv4Addr>>,
}

impl Default for FakeDns {
    fn default() -> Self {
        FakeDns {
            by_name: HashMap::new(),
            by_ip: HashMap::new(),
            next: FIRST,
            pinned: HashMap::new(),
        }
    }
}

impl FakeDns {
    /// Whether `ip` is in the pool (a connection to it must be by name).
    pub fn in_pool(ip: Ipv4Addr) -> bool {
        u32::from(ip).wrapping_sub(POOL_BASE) < POOL_SIZE
    }

    /// The name a pool address stands for.
    pub fn name_of(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }

    /// The pool address for `name`, assigning one if needed.
    pub fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(name) {
            return *ip;
        }
        let ip = Ipv4Addr::from(POOL_BASE + self.next);
        self.next = if self.next + 1 >= POOL_SIZE {
            FIRST
        } else {
            self.next + 1
        };
        if let Some(old) = self.by_ip.insert(ip, name.to_owned()) {
            self.by_name.remove(&old);
        }
        self.by_name.insert(name.to_owned(), ip);
        ip
    }

    /// Answer `name` with these real addresses from now on (an empty list
    /// gives an empty answer).
    pub fn pin(&mut self, name: &str, addrs: Vec<Ipv4Addr>) {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        self.pinned.insert(name, addrs);
    }

    /// Answer one DNS query packet (UDP payload). `None` for packets that
    /// aren't a single standard query, which are dropped.
    pub fn answer(&mut self, query: &[u8]) -> Option<Vec<u8>> {
        let q = Question::parse(query)?;
        let ips = if q.qtype != TYPE_A || q.qclass != CLASS_IN {
            Vec::new()
        } else if let Some(real) = self.pinned.get(&q.name) {
            real.clone()
        } else {
            vec![self.address_for(&q.name)]
        };
        Some(q.response(query, &ips))
    }
}

/// The question of a standard query.
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    /// End of the question section in the packet.
    end: usize,
}

impl Question {
    fn parse(p: &[u8]) -> Option<Question> {
        if p.len() < 12 {
            return None;
        }
        let flags = u16::from_be_bytes([p[2], p[3]]);
        let qdcount = u16::from_be_bytes([p[4], p[5]]);
        // A query (QR = 0), opcode QUERY, exactly one question.
        if flags & 0x8000 != 0 || (flags >> 11) & 0xF != 0 || qdcount != 1 {
            return None;
        }
        let mut pos = 12;
        let mut labels: Vec<String> = Vec::new();
        loop {
            let len = usize::from(*p.get(pos)?);
            pos += 1;
            if len == 0 {
                break;
            }
            // No compression in a question; labels are at most 63 bytes.
            if len > 63 {
                return None;
            }
            let label = p.get(pos..pos + len)?;
            if !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
            {
                return None;
            }
            labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
            pos += len;
        }
        let name = labels.join(".");
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        let qtype = u16::from_be_bytes([*p.get(pos)?, *p.get(pos + 1)?]);
        let qclass = u16::from_be_bytes([*p.get(pos + 2)?, *p.get(pos + 3)?]);
        Some(Question {
            name,
            qtype,
            qclass,
            end: pos + 4,
        })
    }

    /// The response: the query's ID, RD and question, and an `A` record
    /// for each of `ips` (at most 16).
    fn response(&self, query: &[u8], ips: &[Ipv4Addr]) -> Vec<u8> {
        let ips = &ips[..ips.len().min(16)];
        let mut r = Vec::with_capacity(self.end + 16 * ips.len());
        r.extend_from_slice(&query[0..2]);
        let rd = query[2] & 0x01;
        // QR, RD copied, RA; NOERROR.
        r.extend_from_slice(&[0x80 | rd, 0x80]);
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&(ips.len() as u16).to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        r.extend_from_slice(&query[12..self.end]);
        for ip in ips {
            // Name: pointer to the question's name at offset 12.
            r.extend_from_slice(&[0xC0, 0x0C]);
            r.extend_from_slice(&TYPE_A.to_be_bytes());
            r.extend_from_slice(&CLASS_IN.to_be_bytes());
            r.extend_from_slice(&TTL.to_be_bytes());
            r.extend_from_slice(&4u16.to_be_bytes());
            r.extend_from_slice(&ip.octets());
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[test]
    fn a_queries_get_stable_pool_addresses() {
        let mut dns = FakeDns::default();
        let r = dns
            .answer(&query(0x1234, "Example.COM", 1))
            .expect("answer");
        assert_eq!(&r[0..2], &[0x12, 0x34]);
        assert_eq!(r[2] & 0x80, 0x80, "a response");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "one answer");
        let ip = Ipv4Addr::new(
            r[r.len() - 4],
            r[r.len() - 3],
            r[r.len() - 2],
            r[r.len() - 1],
        );
        assert!(FakeDns::in_pool(ip));
        assert_ne!(ip, SERVER);
        assert_eq!(dns.name_of(ip), Some("example.com"));
        let again = dns.answer(&query(1, "example.com", 1)).expect("answer");
        assert_eq!(
            &again[again.len() - 4..],
            &ip.octets(),
            "same name, same address"
        );
        assert!(!FakeDns::in_pool(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(FakeDns::in_pool(Ipv4Addr::new(198, 19, 255, 255)));
    }

    #[test]
    fn other_types_get_an_empty_answer() {
        let mut dns = FakeDns::default();
        for qtype in [28u16, 65, 16] {
            let r = dns.answer(&query(7, "example.com", qtype)).expect("answer");
            assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "type {qtype}");
            assert_eq!(r[3] & 0x0F, 0, "NOERROR");
        }
        assert!(dns.by_name.is_empty());
    }

    #[test]
    fn pinned_names_get_their_real_addresses() {
        let mut dns = FakeDns::default();
        let real = vec![Ipv4Addr::new(104, 16, 1, 1), Ipv4Addr::new(104, 16, 2, 2)];
        dns.pin("GW.Example.com.", real);
        let r = dns.answer(&query(9, "gw.example.com", 1)).expect("answer");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 2, "two answers");
        assert_eq!(&r[r.len() - 4..], &[104, 16, 2, 2]);
        assert_eq!(&r[r.len() - 20..r.len() - 16], &[104, 16, 1, 1]);
        assert!(dns.by_name.is_empty(), "no pool address used");
        let r = dns.answer(&query(9, "gw.example.com", 28)).expect("answer");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "no AAAA");
    }

    #[test]
    fn malformed_packets_are_dropped() {
        let mut dns = FakeDns::default();
        assert!(dns.answer(&[0; 5]).is_none());
        let mut response = query(1, "example.com", 1);
        response[2] |= 0x80;
        assert!(dns.answer(&response).is_none(), "not a query");
        let mut truncated = query(1, "example.com", 1);
        truncated.truncate(20);
        assert!(dns.answer(&truncated).is_none());
        assert!(dns.answer(&query(1, "bad name", 1)).is_none());
        let mut pointer = query(1, "x", 1);
        pointer[12] = 0xC0;
        assert!(
            dns.answer(&pointer).is_none(),
            "no compression in a question"
        );
    }

    #[test]
    fn the_pool_wraps_and_forgets_the_oldest() {
        let mut dns = FakeDns::default();
        let first = dns.address_for("first.example");
        for i in 0..(POOL_SIZE - FIRST) {
            dns.address_for(&format!("n{i}.example"));
        }
        assert_eq!(dns.name_of(first), Some("n131069.example"), "reused");
        assert!(!dns.by_name.contains_key("first.example"));
        assert_eq!(dns.by_name.len(), dns.by_ip.len());
    }
}
