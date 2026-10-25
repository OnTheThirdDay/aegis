//! Bounded destination representation shared by inbounds, policy and AGP.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

pub const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Host {
    Ip(IpAddr),
    /// Normalized: lowercase ASCII (A-label form), no trailing dot.
    Domain(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Destination {
    pub host: Host,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationError {
    Empty,
    TooLong,
    InvalidCharacter,
    InvalidLabel,
    NonAscii,
    ZeroPort,
}

impl fmt::Display for DestinationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            DestinationError::Empty => "empty host",
            DestinationError::TooLong => "host too long",
            DestinationError::InvalidCharacter => "invalid character in host",
            DestinationError::InvalidLabel => "invalid domain label",
            DestinationError::NonAscii => "non-ASCII host; supply IDNA A-labels",
            DestinationError::ZeroPort => "port 0 is not a valid destination",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DestinationError {}

/// Normalize and validate a domain name. Non-ASCII input is rejected rather
/// than guessed: callers must supply IDNA A-labels (`xn--`).
pub fn normalize_domain(input: &str) -> Result<String, DestinationError> {
    let trimmed = input.strip_suffix('.').unwrap_or(input);
    if trimmed.is_empty() {
        return Err(DestinationError::Empty);
    }
    if trimmed.len() > MAX_DOMAIN_LEN {
        return Err(DestinationError::TooLong);
    }
    if !trimmed.is_ascii() {
        return Err(DestinationError::NonAscii);
    }
    let lower = trimmed.to_ascii_lowercase();
    for label in lower.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(DestinationError::InvalidLabel);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DestinationError::InvalidLabel);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(DestinationError::InvalidCharacter);
        }
    }
    Ok(lower)
}

impl Host {
    /// Parse a host token: IP literal (v6 may be bracketed) or domain name.
    pub fn parse(input: &str) -> Result<Host, DestinationError> {
        let unbracketed = input
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(input);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Host::Ip(canonical_ip(ip)));
        }
        if unbracketed.len() != input.len() {
            // Brackets around something that is not an IPv6 literal.
            return Err(DestinationError::InvalidCharacter);
        }
        let name = normalize_domain(input)?;
        // "1.2.3.4." is an IP literal in disguise: one canonical form only.
        if let Ok(ip) = name.parse::<IpAddr>() {
            return Ok(Host::Ip(canonical_ip(ip)));
        }
        // A numeric last label ("127.1", "0x7f.1") is read as IPv4 by some
        // resolvers and by the URL standard; never treat it as a name.
        let last = name.rsplit('.').next().unwrap_or_default();
        let hex = last
            .strip_prefix("0x")
            .is_some_and(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
        if last.bytes().all(|b| b.is_ascii_digit()) || hex {
            return Err(DestinationError::InvalidLabel);
        }
        Ok(Host::Domain(name))
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Host::Domain(_))
    }
}

/// Collapse IPv4-mapped IPv6 into IPv4 so policy sees one canonical form.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

impl Destination {
    pub fn new(host: Host, port: u16) -> Result<Self, DestinationError> {
        if port == 0 {
            return Err(DestinationError::ZeroPort);
        }
        Ok(Destination { host, port })
    }

    /// Parse `host:port` / `[v6]:port` authority form.
    pub fn parse_authority(input: &str) -> Result<Self, DestinationError> {
        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let end = rest.find(']').ok_or(DestinationError::InvalidCharacter)?;
            let host = &input[..end + 2];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .ok_or(DestinationError::InvalidCharacter)?;
            (host, port)
        } else {
            let idx = input.rfind(':').ok_or(DestinationError::InvalidCharacter)?;
            let host = &input[..idx];
            if host.contains(':') {
                // Unbracketed IPv6 with port is ambiguous.
                return Err(DestinationError::InvalidCharacter);
            }
            (host, &input[idx + 1..])
        };
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DestinationError::InvalidCharacter);
        }
        let port: u16 = port
            .parse()
            .map_err(|_| DestinationError::InvalidCharacter)?;
        Destination::new(Host::parse(host)?, port)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]"),
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Domain(d) => f.write_str(d),
        }
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalization() {
        assert_eq!(
            normalize_domain("Example.COM.").as_deref(),
            Ok("example.com")
        );
        assert_eq!(normalize_domain(""), Err(DestinationError::Empty));
        assert_eq!(
            normalize_domain("bad..label"),
            Err(DestinationError::InvalidLabel)
        );
        assert_eq!(
            normalize_domain("-x.com"),
            Err(DestinationError::InvalidLabel)
        );
        assert_eq!(
            normalize_domain("bücher.de"),
            Err(DestinationError::NonAscii)
        );
        assert_eq!(
            normalize_domain("a b.com"),
            Err(DestinationError::InvalidCharacter)
        );
        assert!(normalize_domain(&"a.".repeat(130)).is_err());
    }

    #[test]
    fn numeric_names_are_ips_or_rejected() {
        let d = Destination::parse_authority("0.3.3.3.:2").expect("trailing-dot IPv4");
        assert_eq!(d.host, Host::Ip("0.3.3.3".parse().expect("ip")));
        assert_eq!(Destination::parse_authority(&d.to_string()), Ok(d));
        for bad in ["127.1:80", "0x7f.1:80", "example.123:80", "1.2.3.4.5:80"] {
            assert!(Destination::parse_authority(bad).is_err(), "{bad}");
        }
        assert!(Destination::parse_authority("123.example:80").is_ok());
    }

    #[test]
    fn authority_parsing() {
        let d = Destination::parse_authority("[2001:db8::1]:443").expect("v6");
        assert_eq!(d.port, 443);
        assert!(matches!(d.host, Host::Ip(IpAddr::V6(_))));
        let d = Destination::parse_authority("Example.org:80").expect("domain");
        assert_eq!(d.host, Host::Domain("example.org".into()));
        assert!(Destination::parse_authority("2001:db8::1:443").is_err());
        assert!(Destination::parse_authority("example.org:0").is_err());
        assert!(Destination::parse_authority("example.org:65536").is_err());
        assert!(Destination::parse_authority("example.org").is_err());
        assert!(Destination::parse_authority("[example.org]:80").is_err());
    }

    #[test]
    fn mapped_addresses_canonicalize() {
        let d = Destination::parse_authority("[::ffff:127.0.0.1]:80").expect("mapped");
        assert_eq!(d.host, Host::Ip("127.0.0.1".parse().expect("ip")));
    }
}
