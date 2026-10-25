//! Human-readable security diff and restart-required detection.
//!
//! Routing/ACL changes affect **future admissions only**: streams admitted
//! under an earlier revision keep it until they close. Listener, identity
//! and budget changes cannot be applied by a snapshot pointer swap and are
//! reported as restart-required before commitment.

use crate::types::*;
use serde::Serialize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Diff {
    pub security: Vec<String>,
    pub restart_required: Vec<String>,
    /// Changes that can never be applied through a profile.
    pub forbidden: Vec<String>,
}

fn rule_summary(r: &RuleConfig) -> String {
    format!(
        "{} -> {}",
        serde_json::to_string(&r.action)
            .unwrap_or_default()
            .trim_matches('"'),
        r.outbound.as_deref().unwrap_or("-")
    )
}

pub fn security_diff(old: Option<&NodeConfig>, new: &NodeConfig) -> Diff {
    let mut d = Diff::default();
    let Some(old) = old else {
        d.security
            .push("initial activation: all policy is new".into());
        return d;
    };
    if old.node_id != new.node_id {
        d.forbidden
            .push("node_id cannot change through a profile".into());
    }
    if old.role != new.role {
        d.forbidden
            .push("role cannot change through a profile".into());
    }
    const FUTURE: &str = "(applies to future admissions; admitted streams keep their revision)";
    if old.routing.default_action != new.routing.default_action
        || old.routing.default_outbound != new.routing.default_outbound
    {
        d.security.push(format!(
            "routing default: {:?}/{:?} -> {:?}/{:?} {FUTURE}",
            old.routing.default_action,
            old.routing.default_outbound,
            new.routing.default_action,
            new.routing.default_outbound
        ));
    }
    for r in &new.routing.rules {
        match old.routing.rules.iter().find(|o| o.id == r.id) {
            None => d.security.push(format!(
                "rule added: {} ({}) {FUTURE}",
                r.id,
                rule_summary(r)
            )),
            Some(o) if o != r => d.security.push(format!(
                "rule changed: {} ({} => {}) {FUTURE}",
                r.id,
                rule_summary(o),
                rule_summary(r)
            )),
            _ => {}
        }
    }
    for o in &old.routing.rules {
        if !new.routing.rules.iter().any(|r| r.id == o.id) {
            d.security.push(format!(
                "rule removed: {} ({}) {FUTURE}",
                o.id,
                rule_summary(o)
            ));
        }
    }
    for ob in &new.outbounds {
        match old.outbounds.iter().find(|o| o.id == ob.id) {
            None => d
                .security
                .push(format!("outbound added: {} ({})", ob.id, ob.kind.as_str())),
            Some(o) => {
                if o.restricted_address_policy != ob.restricted_address_policy {
                    d.security.push(format!(
                        "outbound {} egress policy: {:?} -> {:?} {FUTURE}",
                        ob.id, o.restricted_address_policy, ob.restricted_address_policy
                    ));
                }
                if o.url != ob.url || o.server_name != ob.server_name || o.outer_ca != ob.outer_ca {
                    d.security.push(format!(
                        "outbound {} tunnel endpoint changed (new sessions only)",
                        ob.id
                    ));
                }
            }
        }
    }
    for o in &old.outbounds {
        if !new.outbounds.iter().any(|n| n.id == o.id) {
            d.security.push(format!("outbound removed: {}", o.id));
        }
    }
    if old.dns != new.dns {
        d.security.push(format!(
            "dns: mode {} -> {}, ipv6 {:?} -> {:?}, resolver {:?} -> {:?}",
            old.dns.mode.as_str(),
            new.dns.mode.as_str(),
            old.dns.ipv6_policy,
            new.dns.ipv6_policy,
            old.dns.resolver,
            new.dns.resolver
        ));
    }
    if old.system_vpn != new.system_vpn {
        d.security.push("system_vpn policy changed".into());
    }
    // Restart-required (not applicable by pointer swap).
    if old.inbounds != new.inbounds {
        d.restart_required.push("inbound listeners changed".into());
    }
    if old.management != new.management || old.ui != new.ui {
        d.restart_required
            .push("management/ui listener settings changed".into());
    }
    if old.identity != new.identity || old.secrets != new.secrets {
        d.restart_required
            .push("identity material references changed".into());
        d.security
            .push("identity/trust material references changed".into());
    }
    if old.core != new.core {
        d.restart_required
            .push("core budgets/timeouts changed".into());
    }
    d
}
