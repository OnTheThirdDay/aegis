//! Resolver selection with explicit provenance (03 §7, D-004).
//!
//! A resolver is always explicitly chosen by configuration:
//! * `System`: the host's configured resolver (getaddrinfo) — only valid
//!   where the operator declared it to be the egress resolver;
//! * `Explicit`: only the listed nameservers (UDP with TCP fallback on
//!   truncation), no hosts file, no system configuration.
//!
//! There is no fallback between them: a failure of the designated resolver
//! is a DNS failure, never a retry through another path. Errors are coarse
//! and never carry the queried name.
#![forbid(unsafe_code)]

use aegis_contracts::destination::canonical_ip;
use hickory_resolver::config::{
    LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Upper bound on addresses considered per name.
pub const MAX_ADDRESSES: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    Timeout,
    NotFound,
    /// Any other resolver failure (no detail is exposed).
    Failure,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DnsError::Timeout => "dns timeout",
            DnsError::NotFound => "dns name not found",
            DnsError::Failure => "dns failure",
        })
    }
}

impl std::error::Error for DnsError {}

enum Inner {
    System,
    Explicit(Box<TokioResolver>),
}

pub struct Resolver {
    inner: Inner,
    timeout: Duration,
    allow_ipv6: bool,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("kind", &self.kind())
            .field("allow_ipv6", &self.allow_ipv6)
            .finish()
    }
}

impl Resolver {
    pub fn system(timeout: Duration, allow_ipv6: bool) -> Self {
        Resolver {
            inner: Inner::System,
            timeout,
            allow_ipv6,
        }
    }

    /// Only the given nameservers (UDP with TCP fallback on truncation).
    /// No system configuration and no hosts file are consulted.
    pub fn explicit(
        nameservers: &[SocketAddr],
        timeout: Duration,
        allow_ipv6: bool,
    ) -> Result<Self, DnsError> {
        let mut servers = Vec::with_capacity(nameservers.len());
        for ns in nameservers {
            let mut server = NameServerConfig::udp_and_tcp(ns.ip());
            for conn in &mut server.connections {
                conn.port = ns.port();
            }
            server.trust_negative_responses = true;
            servers.push(server);
        }
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ndots = 0;
        opts.ip_strategy = if allow_ipv6 {
            LookupIpStrategy::Ipv4AndIpv6
        } else {
            LookupIpStrategy::Ipv4Only
        };
        opts.cache_size = 256;
        opts.try_tcp_on_error = true;
        let resolver = TokioResolver::builder_with_config(
            ResolverConfig::from_name_servers(servers),
            TokioRuntimeProvider::default(),
        )
        .with_options(opts)
        .build()
        .map_err(|_| DnsError::Failure)?;
        Ok(Resolver {
            inner: Inner::Explicit(Box::new(resolver)),
            timeout,
            allow_ipv6,
        })
    }

    pub fn kind(&self) -> &'static str {
        match self.inner {
            Inner::System => "system_explicit",
            Inner::Explicit(_) => "gateway",
        }
    }

    pub fn allows_ipv6(&self) -> bool {
        self.allow_ipv6
    }

    /// Resolve a normalized domain to at most [`MAX_ADDRESSES`] canonical
    /// addresses, honoring the IPv6 policy.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let fqdn = format!("{}.", domain.trim_end_matches('.'));
        let addrs: Vec<IpAddr> = match &self.inner {
            Inner::System => {
                let fut = tokio::net::lookup_host((domain, 0u16));
                let iter = tokio::time::timeout(self.timeout, fut)
                    .await
                    .map_err(|_| DnsError::Timeout)?
                    .map_err(|_| DnsError::NotFound)?;
                iter.map(|sa| sa.ip()).collect()
            }
            Inner::Explicit(r) => {
                let fut = r.lookup_ip(fqdn.as_str());
                let lookup = tokio::time::timeout(self.timeout * 3, fut)
                    .await
                    .map_err(|_| DnsError::Timeout)?
                    .map_err(|e| match e {
                        _ if e.is_no_records_found() => DnsError::NotFound,
                        NetError::Timeout => DnsError::Timeout,
                        _ => DnsError::Failure,
                    })?;
                lookup.iter().collect()
            }
        };
        let mut out = Vec::new();
        for ip in addrs.into_iter().map(canonical_ip) {
            if ip.is_ipv6() && !self.allow_ipv6 {
                continue;
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
            if out.len() >= MAX_ADDRESSES {
                break;
            }
        }
        if out.is_empty() {
            return Err(DnsError::NotFound);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn explicit_resolver_never_falls_back() {
        // A resolver pointed at a closed local port must fail, not consult
        // the system resolver. (`localhost` is answered locally per RFC 6761
        // and is rejected by egress policy instead.)
        let r = Resolver::explicit(
            &["127.0.0.1:9".parse().expect("addr")],
            Duration::from_millis(200),
            true,
        )
        .expect("resolver builds");
        let res = r.resolve("www.example.org").await;
        assert!(res.is_err(), "got {res:?}");
    }

    #[tokio::test]
    async fn system_resolver_respects_ipv6_policy() {
        let r = Resolver::system(Duration::from_secs(2), false);
        if let Ok(addrs) = r.resolve("localhost").await {
            assert!(addrs.iter().all(|a| a.is_ipv4()));
        }
    }
}
