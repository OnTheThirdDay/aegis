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
use tokio::net::TcpStream;

pub fn admit_failure(e: &AdmitError) -> OpenFailure {
    match e {
        AdmitError::Closed | AdmitError::NoPolicy => OpenFailure::Unavailable,
        AdmitError::Revoked | AdmitError::Expired | AdmitError::Unauthorized => {
            OpenFailure::Unauthorized
        }
        AdmitError::Denied(_) => OpenFailure::Denied,
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
    let policy = compiled
        .outbound_policies
        .get(outbound_id)
        .copied()
        .unwrap_or(AddressPolicy::DenyPrivateAndMetadata);
    let allow_v6 = compiled.config.dns.ipv6_policy != Ipv6Policy::Block;
    let resolver = ctx.resolver_for(&compiled.config);
    let router = &compiled.router;
    let input = DecisionInput {
        destination: dest,
        inbound,
        node_id,
    };
    let check = |ip: std::net::IpAddr| -> Result<(), RouteDecision> {
        let ip = aegis_contracts::destination::canonical_ip(ip);
        if ip.is_ipv6() && !allow_v6 {
            return Err(RouteDecision::deny(None, RuleClass::Privacy));
        }
        router.check_resolved(&input, ip)?;
        policy
            .permits(ip)
            .map_err(|_| RouteDecision::deny(None, RuleClass::Privacy))
    };
    let connect_timeout =
        Duration::from_millis(u64::from(compiled.config.core.connect_timeout_ms)).min(timeout);
    let dialer = DirectDialer::new(resolver, connect_timeout);
    match tokio::time::timeout(timeout, dialer.dial(dest, check)).await {
        Ok(Ok((stream, _peer))) => Ok(stream),
        Ok(Err(e)) => Err(e.as_open_failure()),
        Err(_) => Err(OpenFailure::Timeout),
    }
}
