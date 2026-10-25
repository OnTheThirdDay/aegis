//! TC-N04: >1000 rules, deterministic precedence and stable decisions.

use aegis_contracts::route::RouteAction;
use aegis_contracts::Destination;
use aegis_policy::{AddressPolicy, DecisionInput, Matcher, Router, RuleSpec};
use proptest::prelude::*;
use std::collections::HashSet;

fn outbounds() -> HashSet<String> {
    (0..4).map(|i| format!("out{i}")).collect()
}

fn big_table() -> Vec<RuleSpec> {
    let mut rules = Vec::new();
    for i in 0..600u32 {
        rules.push(RuleSpec {
            id: format!("exact-{i}"),
            priority: 1000,
            action: RouteAction::Proxy,
            outbound: Some(format!("out{}", i % 4)),
            matcher: Matcher {
                domains: vec![format!("host{i}.svc{}.example", i % 50)],
                ..Default::default()
            },
        });
    }
    for i in 0..50u32 {
        rules.push(RuleSpec {
            id: format!("suffix-{i}"),
            priority: 1000,
            action: RouteAction::Proxy,
            outbound: Some("out0".into()),
            matcher: Matcher {
                domain_suffixes: vec![format!("svc{i}.example")],
                ..Default::default()
            },
        });
    }
    for i in 0..300u32 {
        rules.push(RuleSpec {
            id: format!("cidr-{i}"),
            priority: 1000,
            action: RouteAction::Proxy,
            outbound: Some("out1".into()),
            matcher: Matcher {
                cidrs: vec![format!("{}.{}.0.0/16", 20 + i / 256, i % 256)
                    .parse()
                    .expect("net")],
                ..Default::default()
            },
        });
    }
    for i in 0..100u32 {
        rules.push(RuleSpec {
            id: format!("deny-{i}"),
            priority: 1000,
            action: RouteAction::Deny,
            outbound: None,
            matcher: Matcher {
                domains: vec![format!("blocked{i}.example")],
                ..Default::default()
            },
        });
    }
    rules
}

fn router() -> Router {
    Router::compile(
        big_table(),
        RouteAction::Deny,
        None,
        AddressPolicy::DenyPrivateAndMetadata,
        &outbounds(),
    )
    .expect("compile 1050 rules")
}

fn decide(r: &Router, d: &str) -> (RouteAction, Option<String>, Option<String>) {
    let dest = Destination::parse_authority(d).expect("dest");
    let dec = r.decide(&DecisionInput {
        destination: &dest,
        inbound: "ws",
        node_id: Some("n"),
    });
    (dec.action, dec.outbound, dec.rule_id)
}

#[test]
fn golden_decisions() {
    let r = router();
    assert!(r.rule_count() > 1000);
    let cases = [
        (
            "host7.svc7.example:443",
            RouteAction::Proxy,
            Some("out3"),
            Some("exact-7"),
        ),
        (
            "other.svc7.example:443",
            RouteAction::Proxy,
            Some("out0"),
            Some("suffix-7"),
        ),
        (
            "svc49.example:80",
            RouteAction::Proxy,
            Some("out0"),
            Some("suffix-49"),
        ),
        (
            "blocked3.example:443",
            RouteAction::Deny,
            None,
            Some("deny-3"),
        ),
        (
            "20.5.1.1:443",
            RouteAction::Proxy,
            Some("out1"),
            Some("cidr-5"),
        ),
        (
            "21.0.9.9:443",
            RouteAction::Proxy,
            Some("out1"),
            Some("cidr-256"),
        ),
        ("unknown.test:443", RouteAction::Deny, None, None),
        ("10.0.0.1:443", RouteAction::Deny, None, None),
    ];
    for (d, action, out, rule) in cases {
        let got = decide(&r, d);
        assert_eq!(
            got,
            (action, out.map(String::from), rule.map(String::from)),
            "decision for {d}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// Determinism: compiling the same table in any order yields identical
    /// decisions (precedence never depends on declaration order).
    #[test]
    fn order_independent(seed in any::<u64>(), host in 0u32..700, svc in 0u32..60) {
        let mut shuffled = big_table();
        let n = shuffled.len();
        let mut s = seed;
        for i in (1..n).rev() {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            shuffled.swap(i, (s % (i as u64 + 1)) as usize);
        }
        let a = router();
        let b = Router::compile(shuffled, RouteAction::Deny, None, AddressPolicy::DenyPrivateAndMetadata, &outbounds()).expect("compile");
        let d = format!("host{host}.svc{svc}.example:443");
        prop_assert_eq!(decide(&a, &d), decide(&b, &d));
    }
}
