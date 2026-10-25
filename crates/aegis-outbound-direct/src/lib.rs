//! Policy-restricted direct TCP egress (D-003).
//!
//! Resolution happens once under the admitted DNS policy; every candidate
//! address is passed through the caller's policy check (egress ACL, CIDR deny
//! rules, IPv6 policy) and only validated addresses are dialed. There is no
//! second, unchecked resolution, which closes DNS-rebinding gaps.
#![forbid(unsafe_code)]

use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_contracts::reason::OpenFailure;
use aegis_contracts::route::RouteDecision;
use aegis_contracts::{Destination, Host};
use aegis_dns::{DnsError, Resolver};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;

pub const DESCRIPTOR: ModuleDescriptor = ModuleDescriptor {
    module_id: "aegis.outbound.direct",
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client, Role::Gateway],
    operating_systems: &[OsFamily::Linux, OsFamily::Windows, OsFamily::Macos],
    provides: &[
        Capability::ByteStream,
        Capability::HalfClose,
        Capability::EgressAcl,
    ],
    requires: &[],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 1,
        read_buffer_bytes: 0,
        write_buffer_bytes: 0,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

/// Maximum addresses attempted per dial.
pub const MAX_ATTEMPTS: usize = 4;

#[derive(Debug)]
pub enum DialError {
    /// Policy rejected the destination (pre- or post-resolution).
    Denied(RouteDecision),
    /// Literal address of a disabled family or similar local refusal.
    Unsupported,
    Dns(DnsError),
    Refused,
    Unreachable,
    Timeout,
}

impl DialError {
    pub fn as_open_failure(&self) -> OpenFailure {
        match self {
            DialError::Denied(_) => OpenFailure::Denied,
            DialError::Unsupported => OpenFailure::Unsupported,
            DialError::Dns(_) => OpenFailure::DnsFailure,
            DialError::Refused => OpenFailure::Refused,
            DialError::Unreachable => OpenFailure::Unreachable,
            DialError::Timeout => OpenFailure::Timeout,
        }
    }
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_open_failure().as_str())
    }
}

impl std::error::Error for DialError {}

pub struct DirectDialer {
    resolver: Option<Arc<Resolver>>,
    connect_timeout: Duration,
}

fn classify_io(e: &io::Error) -> DialError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => DialError::Refused,
        io::ErrorKind::TimedOut => DialError::Timeout,
        _ => DialError::Unreachable,
    }
}

impl DirectDialer {
    /// `resolver = None` means this dialer must never resolve names (e.g. a
    /// client in `remote_required` mode); domain destinations then fail.
    pub fn new(resolver: Option<Arc<Resolver>>, connect_timeout: Duration) -> Self {
        DirectDialer {
            resolver,
            connect_timeout,
        }
    }

    /// Resolve (if needed), validate every address with `check`, then dial
    /// validated addresses in order. Returns the stream and the dialed peer.
    pub async fn dial<F>(
        &self,
        dest: &Destination,
        check: F,
    ) -> Result<(TcpStream, SocketAddr), DialError>
    where
        F: Fn(IpAddr) -> Result<(), RouteDecision>,
    {
        let candidates: Vec<IpAddr> = match &dest.host {
            Host::Ip(ip) => {
                check(*ip).map_err(DialError::Denied)?;
                vec![*ip]
            }
            Host::Domain(name) => {
                let resolver = self.resolver.as_ref().ok_or(DialError::Unsupported)?;
                let addrs = resolver.resolve(name).await.map_err(DialError::Dns)?;
                let mut allowed = Vec::new();
                let mut first_denial = None;
                for ip in addrs {
                    match check(ip) {
                        Ok(()) => allowed.push(ip),
                        Err(d) => {
                            first_denial.get_or_insert(d);
                        }
                    }
                }
                if allowed.is_empty() {
                    return Err(match first_denial {
                        Some(d) => DialError::Denied(d),
                        None => DialError::Dns(DnsError::NotFound),
                    });
                }
                allowed
            }
        };
        let mut last = DialError::Unreachable;
        for ip in candidates.into_iter().take(MAX_ATTEMPTS) {
            let addr = SocketAddr::new(ip, dest.port);
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok((stream, addr));
                }
                Ok(Err(e)) => last = classify_io(&e),
                Err(_) => last = DialError::Timeout,
            }
        }
        Err(last)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use aegis_contracts::route::RuleClass;
    use tokio::net::TcpListener;

    fn deny_loopback(ip: IpAddr) -> Result<(), RouteDecision> {
        if ip.is_loopback() {
            Err(RouteDecision::deny(None, RuleClass::Privacy))
        } else {
            Ok(())
        }
    }

    #[tokio::test]
    async fn literal_checked_before_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let dialer = DirectDialer::new(None, Duration::from_secs(1));
        let dest = Destination::parse_authority(&format!("127.0.0.1:{port}")).expect("dest");
        let err = dialer.dial(&dest, deny_loopback).await.expect_err("denied");
        assert!(matches!(err, DialError::Denied(_)));
        let ok = dialer.dial(&dest, |_| Ok(())).await;
        assert!(ok.is_ok());
    }

    #[tokio::test]
    async fn domain_resolving_to_denied_address_is_denied() {
        // localhost resolves to loopback: SSRF via DNS must be refused.
        let resolver = Arc::new(Resolver::system(Duration::from_secs(2), true));
        let dialer = DirectDialer::new(Some(resolver), Duration::from_secs(1));
        let dest = Destination::parse_authority("localhost:80").expect("dest");
        match dialer.dial(&dest, deny_loopback).await {
            Err(DialError::Denied(_)) | Err(DialError::Dns(_)) => {}
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn names_never_resolved_without_resolver() {
        let dialer = DirectDialer::new(None, Duration::from_secs(1));
        let dest = Destination::parse_authority("example.com:80").expect("dest");
        assert!(matches!(
            dialer.dial(&dest, |_| Ok(())).await,
            Err(DialError::Unsupported)
        ));
    }

    #[tokio::test]
    async fn refused_is_reported() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let dialer = DirectDialer::new(None, Duration::from_secs(1));
        let dest = Destination::parse_authority(&format!("127.0.0.1:{port}")).expect("dest");
        assert!(matches!(
            dialer.dial(&dest, |_| Ok(())).await,
            Err(DialError::Refused)
        ));
    }
}
