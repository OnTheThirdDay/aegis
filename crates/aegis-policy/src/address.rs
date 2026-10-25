//! Destination address classification for SSRF/egress protection.
//!
//! IPv6 forms that embed an IPv4 address (mapped, NAT64 well-known prefix,
//! 6to4) are classified by the embedded address so that
//! `::ffff:169.254.169.254` cannot bypass a metadata deny.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    Public,
    Loopback,
    /// RFC 1918 / unique-local.
    Private,
    /// RFC 6598 shared address space.
    SharedCgnat,
    LinkLocal,
    /// Cloud instance metadata endpoints.
    Metadata,
    Multicast,
    Unspecified,
    Broadcast,
    Documentation,
    /// Benchmarking, reserved, deprecated or otherwise non-routable.
    Reserved,
}

impl AddressClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Public => "public",
            AddressClass::Loopback => "loopback",
            AddressClass::Private => "private",
            AddressClass::SharedCgnat => "shared_cgnat",
            AddressClass::LinkLocal => "link_local",
            AddressClass::Metadata => "metadata",
            AddressClass::Multicast => "multicast",
            AddressClass::Unspecified => "unspecified",
            AddressClass::Broadcast => "broadcast",
            AddressClass::Documentation => "documentation",
            AddressClass::Reserved => "reserved",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressPolicy {
    /// Only globally routable unicast destinations (default).
    #[serde(rename = "deny-private-and-metadata")]
    DenyPrivateAndMetadata,
    /// Additionally permit RFC 1918/ULA and CGNAT ranges. Loopback, link-local
    /// and metadata endpoints remain denied.
    #[serde(rename = "allow-private")]
    AllowPrivate,
}

impl AddressPolicy {
    pub fn permits(self, ip: IpAddr) -> Result<(), AddressClass> {
        let class = classify(ip);
        let ok = match self {
            AddressPolicy::DenyPrivateAndMetadata => class == AddressClass::Public,
            AddressPolicy::AllowPrivate => matches!(
                class,
                AddressClass::Public | AddressClass::Private | AddressClass::SharedCgnat
            ),
        };
        if ok {
            Ok(())
        } else {
            Err(class)
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AddressPolicy::DenyPrivateAndMetadata => "deny-private-and-metadata",
            AddressPolicy::AllowPrivate => "allow-private",
        }
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(Ipv4Addr::from(net)) & mask)
}

pub fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    use AddressClass::*;
    if ip == Ipv4Addr::new(169, 254, 169, 254) || ip == Ipv4Addr::new(169, 254, 170, 2) {
        return Metadata;
    }
    if ip.is_unspecified() || in_v4(ip, [0, 0, 0, 0], 8) {
        return Unspecified;
    }
    if ip.is_broadcast() {
        return Broadcast;
    }
    if ip.is_loopback() {
        return Loopback;
    }
    if ip.is_link_local() {
        return LinkLocal;
    }
    if ip.is_private() {
        return Private;
    }
    if in_v4(ip, [100, 64, 0, 0], 10) {
        return SharedCgnat;
    }
    if ip.is_multicast() {
        return Multicast;
    }
    if in_v4(ip, [192, 0, 2, 0], 24)
        || in_v4(ip, [198, 51, 100, 0], 24)
        || in_v4(ip, [203, 0, 113, 0], 24)
    {
        return Documentation;
    }
    if in_v4(ip, [198, 18, 0, 0], 15)       // benchmarking
        || in_v4(ip, [240, 0, 0, 0], 4)      // reserved
        || in_v4(ip, [192, 0, 0, 0], 24)     // IETF protocol assignments
        || in_v4(ip, [192, 88, 99, 0], 24)
    // deprecated 6to4 relay anycast
    {
        return Reserved;
    }
    Public
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(ip) & mask) == (u128::from(net) & mask)
}

const fn v6(segs: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(
        segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
    )
}

pub fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    use AddressClass::*;
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4);
    }
    if ip.is_unspecified() {
        return Unspecified;
    }
    if ip.is_loopback() {
        return Loopback;
    }
    // NAT64 well-known prefix: classify the embedded IPv4 address.
    if in_v6(ip, v6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0]), 96) {
        let o = ip.octets();
        return classify_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 6to4: embedded IPv4 in bits 16..48.
    if in_v6(ip, v6([0x2002, 0, 0, 0, 0, 0, 0, 0]), 16) {
        let o = ip.octets();
        let inner = classify_v4(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
        return if inner == Public { Public } else { inner };
    }
    if ip == v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]) {
        return Metadata; // AWS IMDS IPv6
    }
    if in_v6(ip, v6([0xfe80, 0, 0, 0, 0, 0, 0, 0]), 10) {
        return LinkLocal;
    }
    if in_v6(ip, v6([0xfc00, 0, 0, 0, 0, 0, 0, 0]), 7) {
        return Private;
    }
    if in_v6(ip, v6([0xff00, 0, 0, 0, 0, 0, 0, 0]), 8) {
        return Multicast;
    }
    if in_v6(ip, v6([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0]), 32)
        || in_v6(ip, v6([0x3fff, 0, 0, 0, 0, 0, 0, 0]), 20)
    {
        return Documentation;
    }
    // IPv4-compatible (deprecated), Teredo, ORCHID, discard-only, site-local.
    if in_v6(ip, v6([0, 0, 0, 0, 0, 0, 0, 0]), 96)
        || in_v6(ip, v6([0x2001, 0, 0, 0, 0, 0, 0, 0]), 32)
        || in_v6(ip, v6([0x2001, 0x0010, 0, 0, 0, 0, 0, 0]), 28)
        || in_v6(ip, v6([0x2001, 0x0020, 0, 0, 0, 0, 0, 0]), 28)
        || in_v6(ip, v6([0x0100, 0, 0, 0, 0, 0, 0, 0]), 64)
        || in_v6(ip, v6([0xfec0, 0, 0, 0, 0, 0, 0, 0]), 10)
    {
        return Reserved;
    }
    // Only 2000::/3 is global unicast.
    if !in_v6(ip, v6([0x2000, 0, 0, 0, 0, 0, 0, 0]), 3) {
        return Reserved;
    }
    Public
}

pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> AddressClass {
        classify(s.parse().expect("ip"))
    }

    #[test]
    fn tc_n03_ssrf_classes() {
        assert_eq!(c("8.8.8.8"), AddressClass::Public);
        assert_eq!(c("2606:4700::1111"), AddressClass::Public);
        assert_eq!(c("127.0.0.1"), AddressClass::Loopback);
        assert_eq!(c("127.255.0.9"), AddressClass::Loopback);
        assert_eq!(c("::1"), AddressClass::Loopback);
        assert_eq!(c("10.1.2.3"), AddressClass::Private);
        assert_eq!(c("172.16.0.1"), AddressClass::Private);
        assert_eq!(c("192.168.1.1"), AddressClass::Private);
        assert_eq!(c("fd12::1"), AddressClass::Private);
        assert_eq!(c("100.64.0.1"), AddressClass::SharedCgnat);
        assert_eq!(c("169.254.169.254"), AddressClass::Metadata);
        assert_eq!(c("fd00:ec2::254"), AddressClass::Metadata);
        assert_eq!(c("169.254.1.1"), AddressClass::LinkLocal);
        assert_eq!(c("fe80::1"), AddressClass::LinkLocal);
        assert_eq!(c("0.0.0.0"), AddressClass::Unspecified);
        assert_eq!(c("0.1.2.3"), AddressClass::Unspecified);
        assert_eq!(c("::"), AddressClass::Unspecified);
        assert_eq!(c("255.255.255.255"), AddressClass::Broadcast);
        assert_eq!(c("224.0.0.1"), AddressClass::Multicast);
        assert_eq!(c("ff02::1"), AddressClass::Multicast);
        assert_eq!(c("192.0.2.1"), AddressClass::Documentation);
        assert_eq!(c("2001:db8::1"), AddressClass::Documentation);
        assert_eq!(c("198.18.0.1"), AddressClass::Reserved);
        assert_eq!(c("240.0.0.1"), AddressClass::Reserved);
    }

    #[test]
    fn tc_n03_embedded_ipv4_forms_cannot_bypass() {
        assert_eq!(c("::ffff:169.254.169.254"), AddressClass::Metadata);
        assert_eq!(c("::ffff:127.0.0.1"), AddressClass::Loopback);
        assert_eq!(c("64:ff9b::a9fe:a9fe"), AddressClass::Metadata);
        assert_eq!(c("64:ff9b::7f00:1"), AddressClass::Loopback);
        assert_eq!(c("64:ff9b::808:808"), AddressClass::Public);
        assert_eq!(c("2002:7f00:0001::1"), AddressClass::Loopback);
        assert_eq!(c("2002:0a00:0001::1"), AddressClass::Private);
        assert_eq!(c("::127.0.0.1"), AddressClass::Reserved, "IPv4-compatible");
        assert_eq!(c("2001::1"), AddressClass::Reserved, "Teredo");
    }

    #[test]
    fn policies() {
        let deny = AddressPolicy::DenyPrivateAndMetadata;
        let allow = AddressPolicy::AllowPrivate;
        assert!(deny.permits("1.1.1.1".parse().expect("ip")).is_ok());
        assert_eq!(
            deny.permits("10.0.0.1".parse().expect("ip")),
            Err(AddressClass::Private)
        );
        assert!(allow.permits("10.0.0.1".parse().expect("ip")).is_ok());
        assert!(allow.permits("127.0.0.1".parse().expect("ip")).is_err());
        assert!(allow
            .permits("169.254.169.254".parse().expect("ip"))
            .is_err());
    }
}
