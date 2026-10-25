//! Route decision types shared by the policy engine and inbounds.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    /// Forward via the named outbound (gateway egress or client tunnel).
    Proxy,
    /// Local direct egress (client-side only; explicit opt-in).
    Direct,
    Deny,
}

impl RouteAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RouteAction::Proxy => "proxy",
            RouteAction::Direct => "direct",
            RouteAction::Deny => "deny",
        }
    }
}

/// Finite rule classes, matching `aegis.rule.class`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleClass {
    ExplicitDeny,
    Privacy,
    Identity,
    Domain,
    Cidr,
    Default,
    Other,
}

impl RuleClass {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleClass::ExplicitDeny => "explicit_deny",
            RuleClass::Privacy => "privacy",
            RuleClass::Identity => "identity",
            RuleClass::Domain => "domain",
            RuleClass::Cidr => "cidr",
            RuleClass::Default => "default",
            RuleClass::Other => "other",
        }
    }
}

/// One explainable decision. `rule_id` is a privacy-safe operator label; it is
/// local-only and never an exported metric dimension.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub outbound: Option<String>,
    pub rule_id: Option<String>,
    pub rule_class: RuleClass,
}

impl RouteDecision {
    pub fn deny(rule_id: Option<String>, rule_class: RuleClass) -> Self {
        RouteDecision {
            action: RouteAction::Deny,
            outbound: None,
            rule_id,
            rule_class,
        }
    }
}
