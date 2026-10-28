//! Which destinations the VPN captures.
//!
//! Everything public goes through the gateway. Local networks (Wi-Fi
//! printers, a home router, other VPNs' carrier-grade ranges) stay direct:
//! the gateway couldn't reach them anyway. Android's `excludeRoute` needs
//! API 33, so the captured set is computed as the complement.

use std::net::Ipv4Addr;

/// Ranges that stay off the VPN.
const LOCAL: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

/// IPv6: global unicast only (link-local, unique-local and multicast stay
/// direct). Nothing is answered with IPv6 addresses, so this mostly keeps
/// IPv6 literals from leaking past the VPN.
pub const IPV6: &[(&str, u8)] = &[("2000::", 3)];

fn contains((net, len): (u32, u8), (other, other_len): (u32, u8)) -> bool {
    len <= other_len && (len == 0 || (net ^ other) >> (32 - len) == 0)
}

/// Whether the VPN captures traffic to `ip` (it isn't local).
pub fn captured(ip: Ipv4Addr) -> bool {
    let ip = (u32::from(ip), 32);
    !LOCAL.iter().any(|(n, l)| contains((u32::from(*n), *l), ip))
}

/// The IPv4 routes to add: 0.0.0.0/0 minus [`LOCAL`], as CIDRs.
pub fn ipv4() -> Vec<(Ipv4Addr, u8)> {
    let local: Vec<(u32, u8)> = LOCAL.iter().map(|(n, l)| (u32::from(*n), *l)).collect();
    let mut out = Vec::new();
    let mut todo = vec![(0u32, 0u8)];
    while let Some(net) = todo.pop() {
        if local.iter().any(|l| contains(*l, net)) {
            continue;
        }
        if !local.iter().any(|l| contains(net, *l)) {
            out.push((Ipv4Addr::from(net.0), net.1));
            continue;
        }
        // Partly local: split in halves.
        let len = net.1 + 1;
        todo.push((net.0 | (1 << (32 - len)), len));
        todo.push((net.0, len));
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn covered(ip: Ipv4Addr) -> bool {
        ipv4()
            .iter()
            .any(|(n, l)| contains((u32::from(*n), *l), (u32::from(ip), 32)))
    }

    #[test]
    fn public_addresses_are_captured_and_local_ones_are_not() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "198.18.0.1",
            "198.19.3.4",
            "203.0.113.9",
            "100.128.0.1",
            "172.32.0.1",
        ] {
            assert!(covered(ip.parse().expect("ip")), "{ip}");
        }
        for ip in [
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "0.1.2.3",
        ] {
            assert!(!covered(ip.parse().expect("ip")), "{ip}");
        }
        assert!(captured(Ipv4Addr::new(104, 16, 1, 1)));
        assert!(!captured(Ipv4Addr::new(192, 168, 4, 31)));
        let routes = ipv4();
        assert!(routes.len() < 64, "a compact set: {}", routes.len());
        // No overlaps.
        for (i, a) in routes.iter().enumerate() {
            for b in &routes[i + 1..] {
                let (a, b) = ((u32::from(a.0), a.1), (u32::from(b.0), b.1));
                assert!(!contains(a, b) && !contains(b, a));
            }
        }
    }
}
