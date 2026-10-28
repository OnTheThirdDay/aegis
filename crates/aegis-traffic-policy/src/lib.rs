//! System-VPN policy (10 §2, §7).
//!
//! This crate validates the typed `system_vpn` profile section against the
//! JSON-schema rules *and* the semantic rules the schema cannot express
//! (mode conflicts, rule ambiguity, capability gates), and evaluates
//! synthetic flows for the non-executing preview API.
//!
//! It does not capture traffic or touch the OS. Native capture, app identity
//! and the persistent kill switch are M3/M4 platform adapters; until they
//! exist every mode reports `unsupported` and enabling System-VPN fails
//! validation.
#![forbid(unsafe_code)]

use aegis_contracts::capability::OsFamily;
use aegis_contracts::vpn::{Attribution, FlowAction, IpProtocol, VpnMode};
use aegis_policy::address::{classify, AddressClass};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;

pub const MAX_APP_REFS: usize = 256;
pub const MAX_RULES: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitch {
    Strict,
    ProtectedFlows,
    Off,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelOrBlock {
    Tunnel,
    Block,
}

impl From<TunnelOrBlock> for FlowAction {
    fn from(v: TunnelOrBlock) -> Self {
        match v {
            TunnelOrBlock::Tunnel => FlowAction::Tunnel,
            TunnelOrBlock::Block => FlowAction::Block,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectOrBlock {
    Direct,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockOnly {
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    Strict,
    ScopedSplit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnDns {
    pub mode: DnsMode,
    pub intercept_udp_53: bool,
    pub intercept_tcp_53: bool,
    pub fallback_to_physical_resolver: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnHost {
    pub helper: Option<String>,
    pub require_os_policy_reconciliation: Option<bool>,
    pub owned_state_journal: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnMatch {
    pub app_refs: Option<Vec<String>>,
    pub cidrs: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    pub protocols: Option<Vec<IpProtocol>>,
    pub ports: Option<Vec<u16>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VpnRule {
    pub id: String,
    pub priority: u16,
    pub action: FlowAction,
    #[serde(rename = "match")]
    pub matcher: VpnMatch,
}

/// Typed `system_vpn` profile section (schemas/system-vpn.schema.json).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemVpnConfig {
    pub enabled: bool,
    pub mode: Option<VpnMode>,
    pub kill_switch: Option<KillSwitch>,
    #[serde(default)]
    pub app_refs: Vec<String>,
    pub nonselected_action: Option<DirectOrBlock>,
    #[serde(default)]
    pub direct_bypass_authorized: bool,
    pub unknown_app_action: Option<TunnelOrBlock>,
    pub unknown_domain_action: Option<TunnelOrBlock>,
    pub unsupported_protocol_action: Option<BlockOnly>,
    pub ipv4_policy: Option<TunnelOrBlock>,
    pub ipv6_policy: Option<TunnelOrBlock>,
    #[serde(default)]
    pub lan_bypass: bool,
    pub dns: Option<VpnDns>,
    pub host: Option<VpnHost>,
    #[serde(default)]
    pub rules: Vec<VpnRule>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    Unsupported,
    Experimental,
    Beta,
    Ga,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModeCapability {
    pub mode: VpnMode,
    pub support: Support,
    pub identity_enforcement: bool,
    pub explanation: String,
}

/// Observed host capabilities. Built by `aegis-platform` from real probes;
/// never inferred from the compile target alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostCapabilities {
    pub platform: OsFamily,
    pub modes: Vec<ModeCapability>,
    pub tcp: bool,
    pub udp: bool,
    pub dns_capture: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub native_kill_switch: bool,
}

impl HostCapabilities {
    pub fn mode(&self, mode: VpnMode) -> Option<&ModeCapability> {
        self.modes.iter().find(|m| m.mode == mode)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlowDecision {
    pub action: FlowAction,
    pub reason_code: String,
    pub enforcement_possible: bool,
    pub warning: Option<String>,
}

/// Synthetic flow for preview; never dialed or exported.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyntheticFlow {
    pub app_ref: Option<String>,
    pub protocol: IpProtocol,
    pub remote_address: String,
    pub remote_port: u16,
    pub verified_domain: Option<String>,
    #[serde(default)]
    pub app_attribution: Attribution,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    rule: VpnRule,
    cidrs: Vec<IpNet>,
    domains: Vec<String>,
    order: usize,
}

#[derive(Clone, Debug)]
pub struct CompiledVpnPolicy {
    cfg: SystemVpnConfig,
    rules: Vec<CompiledRule>,
}

fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_app_ref(r: &str) -> bool {
    r.starts_with("os-app-ref:") && r.len() <= 256 && r.len() > "os-app-ref:".len()
}

fn sets_disjoint<T: Eq + std::hash::Hash>(a: &Option<Vec<T>>, b: &Option<Vec<T>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => {
            let sa: HashSet<&T> = a.iter().collect();
            !b.iter().any(|x| sa.contains(x))
        }
        _ => false,
    }
}

fn is_catch_all(m: &VpnMatch) -> bool {
    m.app_refs.is_none()
        && m.cidrs.is_none()
        && m.domains.is_none()
        && m.ports.is_none()
        && m.protocols.as_ref().is_some_and(|p| {
            [IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Other]
                .iter()
                .all(|x| p.contains(x))
        })
}

impl SystemVpnConfig {
    /// Structural + semantic validation independent of the host.
    pub fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        if self.kill_switch == Some(KillSwitch::Off) && self.enabled {
            e.push("kill_switch=off is only allowed with enabled=false".into());
        }
        if self.app_refs.len() > MAX_APP_REFS {
            e.push("too many app_refs".into());
        }
        let mut seen = HashSet::new();
        for r in &self.app_refs {
            if !valid_app_ref(r) {
                e.push(format!(
                    "app_ref {r:?} must be an opaque os-app-ref: identifier"
                ));
            }
            if !seen.insert(r) {
                e.push(format!("duplicate app_ref {r:?}"));
            }
        }
        if self.lan_bypass && !self.direct_bypass_authorized {
            e.push("lan_bypass requires direct_bypass_authorized=true".into());
        }
        if self.nonselected_action == Some(DirectOrBlock::Direct) && !self.direct_bypass_authorized
        {
            e.push("nonselected_action=direct requires direct_bypass_authorized=true".into());
        }
        if let Some(dns) = &self.dns {
            if dns.fallback_to_physical_resolver {
                e.push("dns.fallback_to_physical_resolver must be false".into());
            }
        }
        if let Some(host) = &self.host {
            if host.require_os_policy_reconciliation == Some(false) {
                e.push("host.require_os_policy_reconciliation must be true".into());
            }
            if host
                .helper
                .as_deref()
                .is_some_and(|h| h != "native_scoped_helper")
            {
                e.push("host.helper must be native_scoped_helper".into());
            }
            if host
                .owned_state_journal
                .as_deref()
                .is_some_and(|j| j != "platform-default")
            {
                e.push("host.owned_state_journal must be platform-default".into());
            }
        }
        if self.rules.len() > MAX_RULES {
            e.push("too many rules".into());
        }
        let mut ids = HashSet::new();
        for r in &self.rules {
            if !valid_rule_id(&r.id) {
                e.push(format!("rule id {:?} invalid", r.id));
            }
            if !ids.insert(&r.id) {
                e.push(format!("duplicate rule id {}", r.id));
            }
            let m = &r.matcher;
            if *m == VpnMatch::default() {
                e.push(format!(
                    "rule {}: match must have at least one criterion",
                    r.id
                ));
            }
            let empty_list = [
                m.app_refs.as_ref().map(Vec::len),
                m.cidrs.as_ref().map(Vec::len),
                m.domains.as_ref().map(Vec::len),
                m.protocols.as_ref().map(Vec::len),
                m.ports.as_ref().map(Vec::len),
            ]
            .contains(&Some(0));
            if empty_list {
                e.push(format!("rule {}: match lists must not be empty", r.id));
            }
            if let Some(refs) = &m.app_refs {
                if refs.iter().any(|x| !valid_app_ref(x)) {
                    e.push(format!("rule {}: invalid app_ref", r.id));
                }
            }
            if let Some(cidrs) = &m.cidrs {
                if cidrs.len() > 64 || cidrs.iter().any(|c| c.parse::<IpNet>().is_err()) {
                    e.push(format!("rule {}: invalid cidr", r.id));
                }
            }
            if let Some(domains) = &m.domains {
                if domains.len() > 64
                    || domains.iter().any(|d| {
                        aegis_contracts::destination::normalize_domain(
                            d.strip_prefix("*.").unwrap_or(d),
                        )
                        .is_err()
                    })
                {
                    e.push(format!("rule {}: invalid domain", r.id));
                }
            }
            if m.ports.as_ref().is_some_and(|p| p.contains(&0)) {
                e.push(format!("rule {}: port 0 invalid", r.id));
            }
            if r.action == FlowAction::Direct && !self.direct_bypass_authorized {
                e.push(format!(
                    "rule {}: direct action requires direct_bypass_authorized=true",
                    r.id
                ));
            }
        }
        // Full-table ambiguity check: equal priority, different action and
        // not provably disjoint has no defined precedence.
        for (i, a) in self.rules.iter().enumerate() {
            for b in &self.rules[i + 1..] {
                if a.priority != b.priority || a.action == b.action {
                    continue;
                }
                let disjoint = sets_disjoint(&a.matcher.protocols, &b.matcher.protocols)
                    || sets_disjoint(&a.matcher.ports, &b.matcher.ports)
                    || sets_disjoint(&a.matcher.app_refs, &b.matcher.app_refs);
                if !disjoint {
                    e.push(format!(
                        "rules {} and {} overlap at priority {} with different actions",
                        a.id, b.id, a.priority
                    ));
                }
            }
        }
        if !self.enabled {
            return e;
        }
        // enabled => required fields (schema allOf[0]).
        for (present, name) in [
            (self.mode.is_some(), "mode"),
            (self.kill_switch.is_some(), "kill_switch"),
            (self.unknown_app_action.is_some(), "unknown_app_action"),
            (
                self.unknown_domain_action.is_some(),
                "unknown_domain_action",
            ),
            (
                self.unsupported_protocol_action.is_some(),
                "unsupported_protocol_action",
            ),
            (self.ipv4_policy.is_some(), "ipv4_policy"),
            (self.ipv6_policy.is_some(), "ipv6_policy"),
            (self.dns.is_some(), "dns"),
            (self.host.is_some(), "host"),
        ] {
            if !present {
                e.push(format!("{name} is required when system_vpn.enabled=true"));
            }
        }
        match self.mode {
            Some(VpnMode::Global) => {
                if !self.app_refs.is_empty() {
                    e.push("global mode must not list app_refs".into());
                }
            }
            Some(VpnMode::IncludeApps) => {
                if self.app_refs.is_empty() {
                    e.push("include_apps requires at least one app_ref".into());
                }
                if self.nonselected_action.is_none() {
                    e.push("include_apps requires an explicit nonselected_action".into());
                }
                if self.nonselected_action == Some(DirectOrBlock::Direct)
                    && self.kill_switch == Some(KillSwitch::Strict)
                {
                    e.push(
                        "include_apps with direct nonselected apps cannot be enforced under a strict kill switch".into(),
                    );
                }
            }
            Some(VpnMode::ExcludeApps) => {
                if self.app_refs.is_empty() {
                    e.push("exclude_apps requires at least one app_ref".into());
                }
                if !self.direct_bypass_authorized {
                    e.push("exclude_apps requires direct_bypass_authorized=true".into());
                }
                if self.kill_switch == Some(KillSwitch::Strict) {
                    e.push("exclude_apps direct exceptions cannot be enforced under a strict kill switch".into());
                }
            }
            Some(VpnMode::Rule) => {
                if self.rules.is_empty() {
                    e.push("rule mode requires rules".into());
                } else if !self.rules.iter().any(|r| is_catch_all(&r.matcher)) {
                    e.push("rule mode requires an explicit default rule matching protocols [tcp, udp, other]".into());
                }
            }
            None => {}
        }
        e
    }

    /// Host-dependent gate: can this profile be enforced here?
    pub fn check_capabilities(&self, caps: &HostCapabilities) -> Vec<String> {
        let mut e = Vec::new();
        if !self.enabled {
            return e;
        }
        let Some(mode) = self.mode else { return e };
        match caps.mode(mode) {
            Some(m) if m.support != Support::Unsupported => {
                let uses_apps = !self.app_refs.is_empty()
                    || self.rules.iter().any(|r| r.matcher.app_refs.is_some());
                if uses_apps && !m.identity_enforcement {
                    e.push(format!(
                        "{}: OS-verified application identity is not enforceable on this host",
                        mode.as_str()
                    ));
                }
            }
            Some(m) => e.push(format!(
                "{} unsupported on this host: {}",
                mode.as_str(),
                m.explanation
            )),
            None => e.push(format!("{} unsupported on this host", mode.as_str())),
        }
        if !caps.native_kill_switch {
            e.push("no persistent native kill switch is available on this host".into());
        }
        if self.ipv6_policy == Some(TunnelOrBlock::Tunnel) && !caps.ipv6 {
            e.push("ipv6_policy=tunnel requires verified IPv6 tunnel capability; use block".into());
        }
        let udp_tunnel = self.rules.iter().any(|r| {
            r.action == FlowAction::Tunnel
                && r.matcher
                    .protocols
                    .as_ref()
                    .is_some_and(|p| p.contains(&IpProtocol::Udp))
        });
        if (udp_tunnel || mode == VpnMode::Global) && !caps.udp {
            e.push("this host can't capture UDP; System-VPN beta requires TCP+UDP".into());
        }
        if self
            .dns
            .as_ref()
            .is_some_and(|d| d.intercept_udp_53 || d.intercept_tcp_53)
            && !caps.dns_capture
        {
            e.push("DNS interception is not available on this host".into());
        }
        e
    }

    pub fn compile(&self) -> Result<CompiledVpnPolicy, Vec<String>> {
        let errors = self.validate();
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut rules: Vec<CompiledRule> = self
            .rules
            .iter()
            .enumerate()
            .map(|(order, r)| CompiledRule {
                cidrs: r
                    .matcher
                    .cidrs
                    .iter()
                    .flatten()
                    .filter_map(|c| c.parse().ok())
                    .collect(),
                domains: r
                    .matcher
                    .domains
                    .iter()
                    .flatten()
                    .map(|d| d.to_ascii_lowercase())
                    .collect(),
                rule: r.clone(),
                order,
            })
            .collect();
        rules.sort_by_key(|r| (r.rule.priority, r.order));
        Ok(CompiledVpnPolicy {
            cfg: self.clone(),
            rules,
        })
    }
}

fn decision(action: FlowAction, reason: &str, enforcement_possible: bool) -> FlowDecision {
    let warning = match action {
        FlowAction::Direct => Some(
            "client direct bypass exposes this device's local egress; simulated decision, not proof of OS enforcement".into(),
        ),
        _ => Some("simulated decision; not proof of OS enforcement".into()),
    };
    FlowDecision {
        action,
        reason_code: reason.chars().take(80).collect(),
        enforcement_possible,
        warning,
    }
}

enum RuleMatch {
    Yes,
    No,
    /// Would require domain evidence the flow lacks.
    MissingDomain,
}

impl CompiledVpnPolicy {
    pub fn config(&self) -> &SystemVpnConfig {
        &self.cfg
    }

    fn rule_matches(r: &CompiledRule, flow: &SyntheticFlow, ip: IpAddr) -> RuleMatch {
        let m = &r.rule.matcher;
        if let Some(p) = &m.protocols {
            if !p.contains(&flow.protocol) {
                return RuleMatch::No;
            }
        }
        if let Some(ports) = &m.ports {
            if !ports.contains(&flow.remote_port) {
                return RuleMatch::No;
            }
        }
        if !r.cidrs.is_empty() && !r.cidrs.iter().any(|n| n.contains(&ip)) {
            return RuleMatch::No;
        }
        if let Some(refs) = &m.app_refs {
            let trusted = matches!(
                flow.app_attribution,
                Attribution::Verified | Attribution::Scoped
            );
            if !trusted || !flow.app_ref.as_ref().is_some_and(|a| refs.contains(a)) {
                return RuleMatch::No;
            }
        }
        if !r.domains.is_empty() {
            let Some(d) = &flow.verified_domain else {
                return RuleMatch::MissingDomain;
            };
            let d = d.to_ascii_lowercase();
            let hit = r.domains.iter().any(|pat| match pat.strip_prefix("*.") {
                Some(sfx) => d.ends_with(&format!(".{sfx}")),
                None => *pat == d,
            });
            if !hit {
                return RuleMatch::No;
            }
        }
        RuleMatch::Yes
    }

    fn authorize_direct(&self, reason: &str, possible: bool) -> FlowDecision {
        if self.cfg.direct_bypass_authorized {
            decision(FlowAction::Direct, reason, possible)
        } else {
            decision(FlowAction::Block, "direct_not_authorized", possible)
        }
    }

    /// Evaluate one synthetic flow in the mandatory order of 10 §2.
    pub fn evaluate(&self, flow: &SyntheticFlow, caps: &HostCapabilities) -> FlowDecision {
        let cfg = &self.cfg;
        if !cfg.enabled {
            return decision(FlowAction::Block, "system_vpn_disabled", false);
        }
        let Some(mode) = cfg.mode else {
            return decision(FlowAction::Block, "mode_missing", false);
        };
        let possible = caps
            .mode(mode)
            .is_some_and(|m| m.support != Support::Unsupported)
            && caps.native_kill_switch;
        let Ok(ip) = flow.remote_address.parse::<IpAddr>() else {
            return decision(FlowAction::Block, "invalid_synthetic_address", possible);
        };
        let ip = aegis_contracts::destination::canonical_ip(ip);
        // 1. Mandatory block rules always win.
        for r in self
            .rules
            .iter()
            .filter(|r| r.rule.action == FlowAction::Block)
        {
            if matches!(Self::rule_matches(r, flow, ip), RuleMatch::Yes) {
                return decision(
                    FlowAction::Block,
                    &format!("explicit_block:{}", r.rule.id),
                    possible,
                );
            }
        }
        // 2. Unsupported protocols / families are blocked, never bypassed.
        if flow.protocol == IpProtocol::Other {
            return decision(FlowAction::Block, "unsupported_protocol", possible);
        }
        if flow.protocol == IpProtocol::Udp && !caps.udp {
            return decision(FlowAction::Block, "udp_unsupported", possible);
        }
        let family = match ip {
            IpAddr::V4(_) => cfg.ipv4_policy,
            IpAddr::V6(_) => cfg.ipv6_policy,
        };
        if family != Some(TunnelOrBlock::Tunnel) {
            return decision(
                FlowAction::Block,
                if ip.is_ipv6() {
                    "ipv6_blocked"
                } else {
                    "ipv4_blocked"
                },
                possible,
            );
        }
        // 3. Explicit LAN bypass.
        if cfg.lan_bypass
            && matches!(
                classify(ip),
                AddressClass::Private | AddressClass::LinkLocal
            )
        {
            return self.authorize_direct("lan_bypass", possible);
        }
        let trusted = matches!(
            flow.app_attribution,
            Attribution::Verified | Attribution::Scoped
        );
        let in_list = flow
            .app_ref
            .as_ref()
            .is_some_and(|a| cfg.app_refs.contains(a));
        // 4. Mode.
        match mode {
            VpnMode::Global => decision(FlowAction::Tunnel, "global_mode", possible),
            VpnMode::IncludeApps => {
                if !trusted {
                    return decision(FlowAction::Block, "attribution_required", possible);
                }
                if in_list {
                    return decision(FlowAction::Tunnel, "selected_app", possible);
                }
                match cfg.nonselected_action {
                    Some(DirectOrBlock::Direct) => {
                        self.authorize_direct("nonselected_app", possible)
                    }
                    _ => decision(FlowAction::Block, "nonselected_app", possible),
                }
            }
            VpnMode::ExcludeApps => {
                // Only a verified identity may inherit an exclusion.
                if flow.app_attribution == Attribution::Verified && in_list {
                    return self.authorize_direct("excluded_app", possible);
                }
                if trusted {
                    return decision(FlowAction::Tunnel, "not_excluded", possible);
                }
                let action = cfg.unknown_app_action.unwrap_or(TunnelOrBlock::Block);
                decision(action.into(), "unknown_app", possible)
            }
            VpnMode::Rule => {
                let mut missing_domain = false;
                for r in self
                    .rules
                    .iter()
                    .filter(|r| r.rule.action != FlowAction::Block)
                {
                    match Self::rule_matches(r, flow, ip) {
                        RuleMatch::Yes => {
                            if missing_domain {
                                let action =
                                    cfg.unknown_domain_action.unwrap_or(TunnelOrBlock::Block);
                                return decision(action.into(), "unknown_domain", possible);
                            }
                            let reason = format!("rule_match:{}", r.rule.id);
                            return match r.rule.action {
                                FlowAction::Direct => self.authorize_direct(&reason, possible),
                                a => decision(a, &reason, possible),
                            };
                        }
                        RuleMatch::MissingDomain => missing_domain = true,
                        RuleMatch::No => {}
                    }
                }
                // Validation guarantees a catch-all; this is unreachable for
                // compiled policies but stays fail-closed.
                decision(FlowAction::Block, "no_rule_matched", possible)
            }
        }
    }
}

#[cfg(test)]
mod tests;
