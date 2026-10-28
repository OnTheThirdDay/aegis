//! Admission-to-dial path shared by gateway OPENs and client direct routes.

use crate::NodeContext;
use aegis_config::{Ipv6Policy, OutboundKind};
use aegis_contracts::reason::OpenFailure;
use aegis_contracts::route::{RouteDecision, RuleClass};
use aegis_contracts::Destination;
use aegis_core::{AdmitError, Admitted};
use aegis_outbound_direct::DirectDialer;
use aegis_policy::{AddressPolicy, DecisionInput};
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

pub fn admit_failure(e: &AdmitError) -> OpenFailure {
    match e {
        AdmitError::Closed | AdmitError::NoPolicy => OpenFailure::Unavailable,
        AdmitError::Revoked | AdmitError::Expired | AdmitError::Unauthorized => {
            OpenFailure::Unauthorized
        }
        AdmitError::Denied(_) => OpenFailure::Denied,
    }
}

/// The admitted direct outbound's egress rules: every address is checked
/// against CIDR deny rules, the outbound's egress policy and IPv6 policy.
struct Egress<'a> {
    admitted: &'a Admitted,
    policy: AddressPolicy,
    allow_v6: bool,
    input: DecisionInput<'a>,
}

impl<'a> Egress<'a> {
    fn new(
        admitted: &'a Admitted,
        dest: &'a Destination,
        inbound: &'a str,
        node_id: Option<&'a str>,
    ) -> Result<Self, OpenFailure> {
        let compiled = &admitted.bundle.compiled;
        let outbound_id = admitted
            .decision
            .outbound
            .as_deref()
            .ok_or(OpenFailure::Internal)?;
        let ob = compiled
            .outbound(outbound_id)
            .ok_or(OpenFailure::Internal)?;
        if ob.kind != OutboundKind::DirectTcp {
            return Err(OpenFailure::Internal);
        }
        Ok(Egress {
            admitted,
            policy: compiled
                .outbound_policies
                .get(outbound_id)
                .copied()
                .unwrap_or(AddressPolicy::DenyPrivateAndMetadata),
            allow_v6: compiled.config.dns.ipv6_policy != Ipv6Policy::Block,
            input: DecisionInput {
                destination: dest,
                inbound,
                node_id,
            },
        })
    }

    fn check(&self, ip: std::net::IpAddr) -> Result<(), RouteDecision> {
        let ip = aegis_contracts::destination::canonical_ip(ip);
        if ip.is_ipv6() && !self.allow_v6 {
            return Err(RouteDecision::deny(None, RuleClass::Privacy));
        }
        self.admitted
            .bundle
            .compiled
            .router
            .check_resolved(&self.input, ip)?;
        self.policy
            .permits(ip)
            .map_err(|_| RouteDecision::deny(None, RuleClass::Privacy))
    }

    /// A dialer resolving under the admitted DNS policy.
    fn dialer(&self, ctx: &NodeContext, timeout: Duration) -> DirectDialer {
        let config = &self.admitted.bundle.compiled.config;
        let connect_timeout =
            Duration::from_millis(u64::from(config.core.connect_timeout_ms)).min(timeout);
        DirectDialer::new(ctx.resolver_for(config), connect_timeout)
    }
}

/// Dial a direct_tcp outbound selected by an admitted decision. DNS runs
/// under the admitted revision's policy; every address is revalidated
/// against CIDR deny rules, the outbound's egress policy and IPv6 policy.
pub async fn dial_direct(
    ctx: &NodeContext,
    admitted: &Admitted,
    dest: &Destination,
    inbound: &str,
    node_id: Option<&str>,
    timeout: Duration,
) -> Result<TcpStream, OpenFailure> {
    let egress = Egress::new(admitted, dest, inbound, node_id)?;
    let dialer = egress.dialer(ctx, timeout);
    match tokio::time::timeout(timeout, dialer.dial(dest, |ip| egress.check(ip))).await {
        Ok(Ok((stream, _peer))) => Ok(stream),
        Ok(Err(e)) => Err(e.as_open_failure()),
        Err(_) => Err(OpenFailure::Timeout),
    }
}

/// A UDP socket for a direct outbound, connected to the one address that
/// passed the same checks as [`dial_direct`].
pub async fn bind_direct_udp(
    ctx: &NodeContext,
    admitted: &Admitted,
    dest: &Destination,
    inbound: &str,
    node_id: Option<&str>,
    timeout: Duration,
) -> Result<UdpSocket, OpenFailure> {
    let egress = Egress::new(admitted, dest, inbound, node_id)?;
    let dialer = egress.dialer(ctx, timeout);
    match tokio::time::timeout(timeout, dialer.bind_udp(dest, |ip| egress.check(ip))).await {
        Ok(Ok((socket, _peer))) => Ok(socket),
        Ok(Err(e)) => Err(e.as_open_failure()),
        Err(_) => Err(OpenFailure::Timeout),
    }
}
