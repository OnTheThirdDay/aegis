//! Immutable compiled routing table with deterministic precedence.

use crate::address::{AddressClass, AddressPolicy};
use aegis_contracts::destination::normalize_domain;
use aegis_contracts::route::{RouteAction, RouteDecision, RuleClass};
use aegis_contracts::{Destination, Host};
use ipnet::IpNet;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;

pub const MAX_RULES: usize = 4096;
const MAX_LIST: usize = 1024;

/// Rule criteria. All specified criteria must match (AND); within a list any
/// element may match (OR). An empty matcher is rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Matcher {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub cidrs: Vec<IpNet>,
    pub ports: Vec<u16>,
    pub inbounds: Vec<String>,
    pub nodes: Vec<String>,
    /// Restrict to globally routable destinations (checked again after DNS).
    pub public_destination: bool,
}

impl Matcher {
    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.cidrs.is_empty()
            && self.ports.is_empty()
            && self.inbounds.is_empty()
            && self.nodes.is_empty()
            && !self.public_destination
    }

    fn has_name_criteria(&self) -> bool {
        !self.domains.is_empty() || !self.domain_suffixes.is_empty()
    }

    /// Canonical key used for duplicate/conflict detection.
    fn canonical(&self) -> String {
        let mut d = self.domains.clone();
        d.sort();
        let mut s = self.domain_suffixes.clone();
        s.sort();
        let mut c: Vec<String> = self.cidrs.iter().map(|n| n.trunc().to_string()).collect();
        c.sort();
        let mut p = self.ports.clone();
        p.sort_unstable();
        let mut i = self.inbounds.clone();
        i.sort();
        let mut n = self.nodes.clone();
        n.sort();
        format!(
            "{d:?}|{s:?}|{c:?}|{p:?}|{i:?}|{n:?}|{}",
            self.public_destination
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RuleSpec {
    pub id: String,
    /// Lower value wins among equally specific matches.
    pub priority: u32,
    pub action: RouteAction,
    pub outbound: Option<String>,
    pub matcher: Matcher,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError {
    pub rule_id: Option<String>,
    pub message: String,
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.rule_id {
            Some(id) => write!(f, "rule {id}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

fn err(rule: Option<&str>, message: impl Into<String>) -> CompileError {
    CompileError {
        rule_id: rule.map(str::to_owned),
        message: message.into(),
    }
}

/// Inputs for one decision. `node_id` is the authenticated peer (gateway) or
/// `None` for local inbounds.
#[derive(Clone, Copy, Debug)]
pub struct DecisionInput<'a> {
    pub destination: &'a Destination,
    pub inbound: &'a str,
    pub node_id: Option<&'a str>,
}

#[derive(Clone, Debug)]
struct CompiledRule {
    spec: RuleSpec,
    class: RuleClass,
}

#[derive(Clone, Debug)]
pub struct Router {
    rules: Vec<CompiledRule>,
    deny_rules: Vec<usize>,
    allow_exact: HashMap<String, Vec<usize>>,
    allow_suffix: HashMap<String, Vec<usize>>,
    allow_unnamed: Vec<usize>,
    default_action: RouteAction,
    default_outbound: Option<String>,
    address_policy: AddressPolicy,
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainAction {
    Proxy,
    Direct,
    Deny,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Explanation {
    pub action: ExplainAction,
    pub rule_id: Option<String>,
    pub reason: String,
}

fn normalize_suffix(s: &str) -> Option<String> {
    let trimmed = s
        .strip_prefix("*.")
        .or_else(|| s.strip_prefix('.'))
        .unwrap_or(s);
    normalize_domain(trimmed).ok()
}

fn rule_class(m: &Matcher) -> RuleClass {
    if m.has_name_criteria() {
        RuleClass::Domain
    } else if !m.cidrs.is_empty() {
        RuleClass::Cidr
    } else if !m.nodes.is_empty() {
        RuleClass::Identity
    } else if !m.ports.is_empty() || !m.inbounds.is_empty() {
        RuleClass::Other
    } else {
        RuleClass::Privacy
    }
}

const EXACT_DOMAIN: u32 = 4_000;

/// Specificity of a matching domain suffix (longer is more specific).
fn suffix_specificity(suffix: &str) -> u32 {
    3_000 + suffix.len() as u32
}

/// How specific `m`'s match on `input` is, judged by the element that
/// matched: the exact name, else the longest suffix that matches, else the
/// longest CIDR containing the address. Judging by a rule's longest element
/// instead would let a broad entry (`com`, `0.0.0.0/0`) ride on a narrow one
/// listed beside it and outrank a more specific rule. Only called for rules
/// that match.
fn match_specificity(m: &Matcher, input: &DecisionInput<'_>, resolved: Option<IpAddr>) -> u32 {
    if m.has_name_criteria() {
        let Host::Domain(d) = &input.destination.host else {
            return 0;
        };
        if m.domains.iter().any(|x| x == d) {
            return EXACT_DOMAIN;
        }
        return m
            .domain_suffixes
            .iter()
            .filter(|s| d == *s || d.ends_with(&format!(".{s}")))
            .map(|s| suffix_specificity(s))
            .max()
            .unwrap_or(0);
    }
    if !m.cidrs.is_empty() {
        let ip = match &input.destination.host {
            Host::Ip(ip) => Some(*ip),
            Host::Domain(_) => resolved,
        };
        let longest = ip.and_then(|ip| {
            m.cidrs
                .iter()
                .filter(|n| n.contains(&ip))
                .map(|n| u32::from(n.prefix_len()))
                .max()
        });
        return 2_000 + longest.unwrap_or(0);
    }
    if !m.nodes.is_empty() {
        1_500
    } else if !m.ports.is_empty() || !m.inbounds.is_empty() {
        1_000
    } else {
        100
    }
}

impl Router {
    /// Compile and validate. Returns every error found, not just the first.
    pub fn compile(
        rules: Vec<RuleSpec>,
        default_action: RouteAction,
        default_outbound: Option<String>,
        address_policy: AddressPolicy,
        known_outbounds: &HashSet<String>,
    ) -> Result<Router, Vec<CompileError>> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        if rules.len() > MAX_RULES {
            errors.push(err(None, format!("too many rules (max {MAX_RULES})")));
        }
        match default_action {
            RouteAction::Deny => {}
            RouteAction::Proxy | RouteAction::Direct => match &default_outbound {
                Some(o) if known_outbounds.contains(o) => {}
                Some(o) => errors.push(err(None, format!("default outbound {o:?} does not exist"))),
                None => errors.push(err(None, "default action requires default_outbound")),
            },
        }
        let mut ids = HashSet::new();
        let mut canon: HashMap<String, (String, RouteAction, Option<String>)> = HashMap::new();
        let mut compiled = Vec::with_capacity(rules.len());
        for mut r in rules {
            let id = r.id.clone();
            if id.is_empty()
                || id.len() > 128
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                errors.push(err(
                    Some(&id),
                    "rule id must be 1-128 chars of [A-Za-z0-9_-]",
                ));
            }
            if !ids.insert(id.clone()) {
                errors.push(err(Some(&id), "duplicate rule id"));
            }
            if r.matcher.is_empty() {
                errors.push(err(
                    Some(&id),
                    "empty matcher matches everything; use the default action",
                ));
            }
            let lists = [
                r.matcher.domains.len(),
                r.matcher.domain_suffixes.len(),
                r.matcher.cidrs.len(),
                r.matcher.ports.len(),
                r.matcher.inbounds.len(),
                r.matcher.nodes.len(),
            ];
            if lists.iter().any(|l| *l > MAX_LIST) {
                errors.push(err(Some(&id), "matcher list too long"));
            }
            let mut domains = Vec::new();
            for d in &r.matcher.domains {
                match normalize_domain(d) {
                    Ok(n) => domains.push(n),
                    Err(e) => errors.push(err(Some(&id), format!("invalid domain {d:?}: {e}"))),
                }
            }
            r.matcher.domains = domains;
            let mut suffixes = Vec::new();
            for s in &r.matcher.domain_suffixes {
                match normalize_suffix(s) {
                    Some(n) => suffixes.push(n),
                    None => errors.push(err(Some(&id), format!("invalid domain suffix {s:?}"))),
                }
            }
            r.matcher.domain_suffixes = suffixes;
            if r.matcher.ports.contains(&0) {
                errors.push(err(Some(&id), "port 0 is invalid"));
            }
            match r.action {
                RouteAction::Deny => {
                    if r.outbound.is_some() {
                        errors.push(err(Some(&id), "deny rules must not name an outbound"));
                    }
                }
                RouteAction::Proxy | RouteAction::Direct => match &r.outbound {
                    Some(o) if known_outbounds.contains(o) => {}
                    Some(o) => {
                        errors.push(err(Some(&id), format!("outbound {o:?} does not exist")))
                    }
                    None => errors.push(err(Some(&id), "allow rules require an outbound")),
                },
            }
            let key = r.matcher.canonical();
            if let Some((other, action, outbound)) = canon.get(&key) {
                if *action != r.action || *outbound != r.outbound {
                    errors.push(err(
                        Some(&id),
                        format!("conflicts with rule {other}: identical match, different outcome"),
                    ));
                } else {
                    warnings.push(format!("rule {id} duplicates rule {other}"));
                }
            } else {
                canon.insert(key, (id.clone(), r.action, r.outbound.clone()));
            }
            let class = if r.action == RouteAction::Deny {
                RuleClass::ExplicitDeny
            } else {
                rule_class(&r.matcher)
            };
            compiled.push(CompiledRule { spec: r, class });
        }
        // Equal specificity + equal priority + shared exact domain with
        // different outcome has no defined precedence: reject.
        type Key<'a> = (&'a str, u32, u32);
        type Outcome<'a> = (&'a str, RouteAction, &'a Option<String>);
        let mut by_domain: HashMap<Key<'_>, Outcome<'_>> = HashMap::new();
        for c in compiled
            .iter()
            .filter(|c| c.spec.action != RouteAction::Deny)
        {
            let m = &c.spec.matcher;
            let names = m
                .domains
                .iter()
                .map(|d| (d, EXACT_DOMAIN))
                .chain(m.domain_suffixes.iter().map(|s| (s, suffix_specificity(s))));
            for (d, specificity) in names {
                let k = (d.as_str(), specificity, c.spec.priority);
                if let Some((other, action, outbound)) = by_domain.get(&k) {
                    if *action != c.spec.action || **outbound != c.spec.outbound {
                        errors.push(err(
                            Some(&c.spec.id),
                            format!("ambiguous with rule {other} for {d}: set distinct priorities"),
                        ));
                    }
                } else {
                    by_domain.insert(k, (&c.spec.id, c.spec.action, &c.spec.outbound));
                }
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let mut router = Router {
            rules: compiled,
            deny_rules: Vec::new(),
            allow_exact: HashMap::new(),
            allow_suffix: HashMap::new(),
            allow_unnamed: Vec::new(),
            default_action,
            default_outbound,
            address_policy,
            warnings,
        };
        for (i, r) in router.rules.iter().enumerate() {
            if r.spec.action == RouteAction::Deny {
                router.deny_rules.push(i);
                continue;
            }
            let m = &r.spec.matcher;
            if !m.has_name_criteria() {
                router.allow_unnamed.push(i);
            }
            for d in &m.domains {
                router.allow_exact.entry(d.clone()).or_default().push(i);
            }
            for s in &m.domain_suffixes {
                router.allow_suffix.entry(s.clone()).or_default().push(i);
            }
        }
        Ok(router)
    }

    pub fn address_policy(&self) -> AddressPolicy {
        self.address_policy
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Does `m` match? `resolved` carries an address for post-resolution
    /// checks; CIDR criteria cannot match a domain without one.
    fn matches(m: &Matcher, input: &DecisionInput<'_>, resolved: Option<IpAddr>) -> bool {
        if !m.ports.is_empty() && !m.ports.contains(&input.destination.port) {
            return false;
        }
        if !m.inbounds.is_empty() && !m.inbounds.iter().any(|i| i == input.inbound) {
            return false;
        }
        if !m.nodes.is_empty()
            && !input
                .node_id
                .is_some_and(|n| m.nodes.iter().any(|x| x == n))
        {
            return false;
        }
        let ip = match &input.destination.host {
            Host::Ip(ip) => Some(*ip),
            Host::Domain(_) => resolved,
        };
        if m.has_name_criteria() {
            let Host::Domain(d) = &input.destination.host else {
                return false;
            };
            let exact = m.domains.iter().any(|x| x == d);
            let suffix = m
                .domain_suffixes
                .iter()
                .any(|s| d == s || d.ends_with(&format!(".{s}")));
            if !exact && !suffix {
                return false;
            }
        }
        if !m.cidrs.is_empty() {
            match ip {
                Some(ip) => {
                    if !m.cidrs.iter().any(|n| n.contains(&ip)) {
                        return false;
                    }
                }
                // A name-scoped rule provisionally satisfies its CIDR
                // constraint before resolution; check_resolved re-verifies
                // every dialed address against this same rule. CIDR-only
                // rules never match an unresolved name.
                None if m.has_name_criteria() => {}
                None => return false,
            }
        }
        if m.public_destination {
            if let Some(ip) = ip {
                if crate::address::classify(ip) != AddressClass::Public {
                    return false;
                }
            }
        }
        true
    }

    fn candidate_allow_rules(&self, dest: &Destination) -> Vec<usize> {
        let mut out = self.allow_unnamed.clone();
        if let Host::Domain(d) = &dest.host {
            if let Some(v) = self.allow_exact.get(d) {
                out.extend_from_slice(v);
            }
            let mut rest = d.as_str();
            loop {
                if let Some(v) = self.allow_suffix.get(rest) {
                    out.extend_from_slice(v);
                }
                match rest.find('.') {
                    Some(i) => rest = &rest[i + 1..],
                    None => break,
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn best_allow(&self, input: &DecisionInput<'_>) -> Option<&CompiledRule> {
        self.candidate_allow_rules(input.destination)
            .into_iter()
            .map(|i| &self.rules[i])
            .filter(|r| Self::matches(&r.spec.matcher, input, None))
            .map(|r| (match_specificity(&r.spec.matcher, input, None), r))
            .min_by(|(sa, a), (sb, b)| sb.cmp(sa).then(a.spec.priority.cmp(&b.spec.priority)))
            .map(|(_, r)| r)
    }

    fn default_decision(&self) -> RouteDecision {
        RouteDecision {
            action: self.default_action,
            outbound: match self.default_action {
                RouteAction::Deny => None,
                _ => self.default_outbound.clone(),
            },
            rule_id: None,
            rule_class: RuleClass::Default,
        }
    }

    /// Pre-resolution decision for a new logical stream.
    pub fn decide(&self, input: &DecisionInput<'_>) -> RouteDecision {
        for &i in &self.deny_rules {
            let r = &self.rules[i];
            if Self::matches(&r.spec.matcher, input, None) {
                return RouteDecision::deny(Some(r.spec.id.clone()), RuleClass::ExplicitDeny);
            }
        }
        if let Host::Ip(ip) = input.destination.host {
            if self.address_policy.permits(ip).is_err() {
                return RouteDecision::deny(None, RuleClass::Privacy);
            }
        }
        match self.best_allow(input) {
            Some(r) => RouteDecision {
                action: r.spec.action,
                outbound: r.spec.outbound.clone(),
                rule_id: Some(r.spec.id.clone()),
                rule_class: r.class,
            },
            None => self.default_decision(),
        }
    }

    /// Post-resolution check of one candidate address for a domain
    /// destination. Every dialed address must pass this.
    pub fn check_resolved(
        &self,
        input: &DecisionInput<'_>,
        ip: IpAddr,
    ) -> Result<(), RouteDecision> {
        let ip = aegis_contracts::destination::canonical_ip(ip);
        if self.address_policy.permits(ip).is_err() {
            return Err(RouteDecision::deny(None, RuleClass::Privacy));
        }
        for &i in &self.deny_rules {
            let r = &self.rules[i];
            if Self::matches(&r.spec.matcher, input, Some(ip)) {
                return Err(RouteDecision::deny(
                    Some(r.spec.id.clone()),
                    RuleClass::ExplicitDeny,
                ));
            }
        }
        // DNS must not broaden the rule that authorized admission. In
        // particular, an unresolved name only provisionally satisfies a
        // public_destination constraint, even when another rule/outbound
        // permits private addresses. Do not fall back to a different allow
        // rule (and potentially a different outbound) after resolution.
        if let Some(r) = self.best_allow(input) {
            if !Self::matches(&r.spec.matcher, input, Some(ip)) {
                return Err(RouteDecision::deny(Some(r.spec.id.clone()), r.class));
            }
        } else if self.default_action == RouteAction::Deny {
            return Err(self.default_decision());
        }
        Ok(())
    }

    /// Synthetic, non-networking explanation. A domain destination whose
    /// outcome could still be changed by a CIDR deny rule is indeterminate:
    /// the answer depends on DNS input we do not have, so we never guess.
    pub fn explain(&self, input: &DecisionInput<'_>) -> Explanation {
        let d = self.decide(input);
        let action = match d.action {
            RouteAction::Proxy => ExplainAction::Proxy,
            RouteAction::Direct => ExplainAction::Direct,
            RouteAction::Deny => ExplainAction::Deny,
        };
        let mut reason = match (&d.rule_id, d.rule_class) {
            (Some(id), class) => format!("matched {} rule {id}", class.as_str()),
            (None, RuleClass::Privacy) => format!(
                "destination address class denied by egress policy {}",
                self.address_policy.as_str()
            ),
            (None, _) => "no rule matched; secure default applied".to_owned(),
        };
        if d.action != RouteAction::Deny && input.destination.host.is_domain() {
            let cidr_denies = self.deny_rules.iter().any(|&i| {
                let m = &self.rules[i].spec.matcher;
                !m.cidrs.is_empty() && !m.has_name_criteria()
            });
            if cidr_denies {
                return Explanation {
                    action: ExplainAction::Indeterminate,
                    rule_id: d.rule_id,
                    reason: format!("{reason}; CIDR deny rules apply after DNS resolution, which explain does not perform"),
                };
            }
            reason.push_str(&format!(
                "; every resolved address must also pass egress policy {}",
                self.address_policy.as_str()
            ));
        }
        Explanation {
            action,
            rule_id: d.rule_id,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outbounds() -> HashSet<String> {
        ["egress".to_string(), "alt".to_string()]
            .into_iter()
            .collect()
    }

    fn rule(id: &str, action: RouteAction, m: Matcher) -> RuleSpec {
        RuleSpec {
            id: id.into(),
            priority: 1000,
            action,
            outbound: (action != RouteAction::Deny).then(|| "egress".to_string()),
            matcher: m,
        }
    }

    fn dest(s: &str) -> Destination {
        Destination::parse_authority(s).expect("dest")
    }

    fn input(d: &Destination) -> DecisionInput<'_> {
        DecisionInput {
            destination: d,
            inbound: "ws",
            node_id: Some("client-1"),
        }
    }

    fn compile(rules: Vec<RuleSpec>, default: RouteAction) -> Router {
        Router::compile(
            rules,
            default,
            Some("egress".into()),
            AddressPolicy::DenyPrivateAndMetadata,
            &outbounds(),
        )
        .expect("compile")
    }

    #[test]
    fn precedence_deny_then_privacy_then_specific_then_default() {
        let r = compile(
            vec![
                rule(
                    "deny-bad",
                    RouteAction::Deny,
                    Matcher {
                        domain_suffixes: vec!["bad.example".into()],
                        ..Default::default()
                    },
                ),
                rule(
                    "public",
                    RouteAction::Proxy,
                    Matcher {
                        public_destination: true,
                        ..Default::default()
                    },
                ),
                rule(
                    "special",
                    RouteAction::Proxy,
                    Matcher {
                        domains: vec!["x.bad.example".into()],
                        ..Default::default()
                    },
                ),
            ],
            RouteAction::Deny,
        );
        let d = dest("x.bad.example:443");
        assert_eq!(
            r.decide(&input(&d)).action,
            RouteAction::Deny,
            "explicit deny beats more specific allow"
        );
        let d = dest("10.0.0.5:80");
        let dec = r.decide(&input(&d));
        assert_eq!(
            (dec.action, dec.rule_class),
            (RouteAction::Deny, RuleClass::Privacy)
        );
        let d = dest("good.example:443");
        assert_eq!(r.decide(&input(&d)).rule_id.as_deref(), Some("public"));
        let d = dest("1.1.1.1:443");
        assert_eq!(r.decide(&input(&d)).action, RouteAction::Proxy);
    }

    #[test]
    fn a_broad_entry_does_not_borrow_a_narrow_entrys_rank() {
        // A direct rule listing a broad suffix beside a long, unrelated one
        // must not outrank a proxy rule for the destination's own domain.
        let mut direct = rule(
            "direct-mixed",
            RouteAction::Direct,
            Matcher {
                domain_suffixes: vec!["com".into(), "a-very-long-unrelated-suffix.org".into()],
                ..Default::default()
            },
        );
        direct.outbound = Some("alt".into());
        let proxy = rule(
            "proxy-example",
            RouteAction::Proxy,
            Matcher {
                domain_suffixes: vec!["example.com".into()],
                ..Default::default()
            },
        );
        let r = compile(vec![direct.clone(), proxy.clone()], RouteAction::Deny);
        let d = dest("www.example.com:443");
        let dec = r.decide(&input(&d));
        assert_eq!(dec.rule_id.as_deref(), Some("proxy-example"));
        assert_eq!(dec.action, RouteAction::Proxy);
        // An exact name listed beside a suffix ranks only for that name.
        let mut direct = rule(
            "direct-exact-and-suffix",
            RouteAction::Direct,
            Matcher {
                domains: vec!["other.net".into()],
                domain_suffixes: vec!["com".into()],
                ..Default::default()
            },
        );
        direct.outbound = Some("alt".into());
        let r = compile(vec![direct, proxy], RouteAction::Deny);
        assert_eq!(
            r.decide(&input(&d)).rule_id.as_deref(),
            Some("proxy-example")
        );
        // CIDRs: a /8 listed beside an unrelated /32 ranks as a /8.
        let mut direct = rule(
            "direct-cidrs",
            RouteAction::Direct,
            Matcher {
                cidrs: vec![
                    "8.0.0.0/8".parse().expect("net"),
                    "9.9.9.9/32".parse().expect("net"),
                ],
                ..Default::default()
            },
        );
        direct.outbound = Some("alt".into());
        let proxy = rule(
            "proxy-net",
            RouteAction::Proxy,
            Matcher {
                cidrs: vec!["8.8.8.0/24".parse().expect("net")],
                ..Default::default()
            },
        );
        let r = compile(vec![direct, proxy], RouteAction::Deny);
        let d = dest("8.8.8.8:443");
        assert_eq!(r.decide(&input(&d)).rule_id.as_deref(), Some("proxy-net"));
        let d = dest("9.9.9.9:443");
        assert_eq!(
            r.decide(&input(&d)).rule_id.as_deref(),
            Some("direct-cidrs")
        );
    }

    #[test]
    fn most_specific_wins_then_priority() {
        let mut a = rule(
            "suffix",
            RouteAction::Proxy,
            Matcher {
                domain_suffixes: vec!["example.com".into()],
                ..Default::default()
            },
        );
        a.outbound = Some("alt".into());
        let b = rule(
            "exact",
            RouteAction::Proxy,
            Matcher {
                domains: vec!["api.example.com".into()],
                ..Default::default()
            },
        );
        let r = compile(vec![a, b], RouteAction::Deny);
        let d = dest("api.example.com:443");
        assert_eq!(r.decide(&input(&d)).rule_id.as_deref(), Some("exact"));
        let d = dest("www.example.com:443");
        assert_eq!(r.decide(&input(&d)).outbound.as_deref(), Some("alt"));
        let d = dest("example.com:443");
        assert_eq!(r.decide(&input(&d)).rule_id.as_deref(), Some("suffix"));
        let d = dest("notexample.com:443");
        assert_eq!(r.decide(&input(&d)).action, RouteAction::Deny);
    }

    #[test]
    fn name_scoped_cidr_is_provisional_until_resolution() {
        let r = Router::compile(
            vec![
                rule(
                    "lan-cidr",
                    RouteAction::Proxy,
                    Matcher {
                        cidrs: vec!["10.0.0.0/8".parse().expect("net")],
                        ..Default::default()
                    },
                ),
                rule(
                    "nas",
                    RouteAction::Proxy,
                    Matcher {
                        domains: vec!["nas.lan.test".into()],
                        cidrs: vec!["10.0.0.5/32".parse().expect("net")],
                        ..Default::default()
                    },
                ),
            ],
            RouteAction::Deny,
            Some("egress".into()),
            AddressPolicy::AllowPrivate,
            &outbounds(),
        )
        .expect("compile");
        let d = dest("nas.lan.test:443");
        assert_eq!(r.decide(&input(&d)).rule_id.as_deref(), Some("nas"));
        assert!(r
            .check_resolved(&input(&d), "10.0.0.5".parse().expect("ip"))
            .is_ok());
        assert!(
            r.check_resolved(&input(&d), "10.0.0.6".parse().expect("ip"))
                .is_err(),
            "resolution outside the rule's CIDR fails closed"
        );
        let d = dest("other.lan.test:443");
        assert_eq!(
            r.decide(&input(&d)).action,
            RouteAction::Deny,
            "CIDR-only rules never authorize an unresolved name"
        );
    }

    #[test]
    fn node_scoped_rules() {
        let r = compile(
            vec![rule(
                "only-c2",
                RouteAction::Proxy,
                Matcher {
                    nodes: vec!["client-2".into()],
                    ..Default::default()
                },
            )],
            RouteAction::Deny,
        );
        let d = dest("1.1.1.1:443");
        assert_eq!(r.decide(&input(&d)).action, RouteAction::Deny);
        let i = DecisionInput {
            node_id: Some("client-2"),
            ..input(&d)
        };
        assert_eq!(r.decide(&i).action, RouteAction::Proxy);
    }

    #[test]
    fn tc_n03_resolved_address_revalidation() {
        let r = compile(
            vec![
                rule(
                    "public",
                    RouteAction::Proxy,
                    Matcher {
                        public_destination: true,
                        ..Default::default()
                    },
                ),
                rule(
                    "deny-net",
                    RouteAction::Deny,
                    Matcher {
                        cidrs: vec!["203.0.113.0/24".parse().expect("net")],
                        ..Default::default()
                    },
                ),
            ],
            RouteAction::Deny,
        );
        let d = dest("rebind.example:80");
        let i = input(&d);
        assert_eq!(r.decide(&i).action, RouteAction::Proxy);
        assert!(r
            .check_resolved(&i, "93.184.216.34".parse().expect("ip"))
            .is_ok());
        assert!(r
            .check_resolved(&i, "127.0.0.1".parse().expect("ip"))
            .is_err());
        assert!(r
            .check_resolved(&i, "::ffff:169.254.169.254".parse().expect("ip"))
            .is_err());
        assert!(r
            .check_resolved(&i, "203.0.113.9".parse().expect("ip"))
            .is_err());
        assert_eq!(r.explain(&i).action, ExplainAction::Indeterminate);
    }

    #[test]
    fn public_rule_is_revalidated_with_private_egress_enabled() {
        let router = Router::compile(
            vec![
                rule(
                    "public",
                    RouteAction::Proxy,
                    Matcher {
                        public_destination: true,
                        ..Default::default()
                    },
                ),
                rule(
                    "private-ip",
                    RouteAction::Proxy,
                    Matcher {
                        cidrs: vec!["10.0.0.0/8".parse().expect("net")],
                        ..Default::default()
                    },
                ),
                rule(
                    "private-name",
                    RouteAction::Proxy,
                    Matcher {
                        domains: vec!["internal.example".into()],
                        ..Default::default()
                    },
                ),
            ],
            RouteAction::Deny,
            None,
            AddressPolicy::AllowPrivate,
            &outbounds(),
        )
        .expect("router");
        for name in ["rebind.example", "10.250.0.1"] {
            let destination = Destination {
                host: Host::Domain(name.into()),
                port: 443,
            };
            let request = input(&destination);
            assert_eq!(router.decide(&request).rule_id.as_deref(), Some("public"));
            assert!(router
                .check_resolved(&request, "93.184.216.34".parse().expect("ip"))
                .is_ok());
            for private in ["10.250.0.1", "192.168.1.1", "fd00::1", "::ffff:10.250.0.1"] {
                assert!(
                    router
                        .check_resolved(&request, private.parse().expect("ip"))
                        .is_err(),
                    "public rule must reject {name} resolving to {private}"
                );
            }
        }
        // An explicit private exception remains usable when it was the
        // actual admission rule, rather than a post-DNS fallback.
        for destination in [dest("internal.example:443"), dest("10.250.0.1:443")] {
            assert!(router
                .check_resolved(&input(&destination), "10.250.0.1".parse().expect("ip"))
                .is_ok());
        }
    }

    #[test]
    fn conflicts_and_validation_errors() {
        let a = rule(
            "a",
            RouteAction::Proxy,
            Matcher {
                domains: vec!["x.com".into()],
                ..Default::default()
            },
        );
        let b = rule(
            "b",
            RouteAction::Deny,
            Matcher {
                domains: vec!["X.com".into()],
                ..Default::default()
            },
        );
        let res = Router::compile(
            vec![a, b],
            RouteAction::Deny,
            None,
            AddressPolicy::DenyPrivateAndMetadata,
            &outbounds(),
        );
        assert!(
            res.is_err(),
            "identical match with different outcomes conflicts"
        );

        let mut c = rule(
            "c",
            RouteAction::Proxy,
            Matcher {
                domains: vec!["y.com".into()],
                ..Default::default()
            },
        );
        let mut d = rule(
            "d",
            RouteAction::Proxy,
            Matcher {
                domains: vec!["y.com".into()],
                ports: vec![443],
                ..Default::default()
            },
        );
        d.outbound = Some("alt".into());
        c.priority = 10;
        d.priority = 10;
        let res = Router::compile(
            vec![c, d],
            RouteAction::Deny,
            None,
            AddressPolicy::DenyPrivateAndMetadata,
            &outbounds(),
        );
        assert!(
            res.is_err(),
            "same specificity/priority/domain, different outcome is ambiguous"
        );

        let empty = rule("e", RouteAction::Proxy, Matcher::default());
        let missing = RuleSpec {
            outbound: Some("nope".into()),
            ..rule(
                "m",
                RouteAction::Proxy,
                Matcher {
                    ports: vec![1],
                    ..Default::default()
                },
            )
        };
        let errs = Router::compile(
            vec![empty, missing],
            RouteAction::Proxy,
            None,
            AddressPolicy::DenyPrivateAndMetadata,
            &outbounds(),
        )
        .expect_err("errors");
        assert_eq!(errs.len(), 3, "{errs:?}");
    }
}
