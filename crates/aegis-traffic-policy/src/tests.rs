//! Synthetic decision-matrix tests for 07 TC-V02/TC-V03/TC-V04 policy logic.
//! These exercise the compiler/evaluator only; native-host TC-V evidence
//! remains BLOCKED until platform adapters exist.

use super::*;

fn caps_all() -> HostCapabilities {
    HostCapabilities {
        platform: OsFamily::Linux,
        modes: VpnMode::ALL
            .iter()
            .map(|m| ModeCapability {
                mode: *m,
                support: Support::Experimental,
                identity_enforcement: true,
                explanation: String::new(),
            })
            .collect(),
        tcp: true,
        udp: true,
        dns_capture: true,
        ipv4: true,
        ipv6: true,
        native_kill_switch: true,
    }
}

fn base(mode: VpnMode) -> SystemVpnConfig {
    SystemVpnConfig {
        enabled: true,
        mode: Some(mode),
        kill_switch: Some(KillSwitch::ProtectedFlows),
        unknown_app_action: Some(TunnelOrBlock::Block),
        unknown_domain_action: Some(TunnelOrBlock::Block),
        unsupported_protocol_action: Some(BlockOnly::Block),
        ipv4_policy: Some(TunnelOrBlock::Tunnel),
        ipv6_policy: Some(TunnelOrBlock::Block),
        dns: Some(VpnDns {
            mode: DnsMode::Strict,
            intercept_udp_53: true,
            intercept_tcp_53: true,
            fallback_to_physical_resolver: false,
        }),
        host: Some(VpnHost {
            helper: Some("native_scoped_helper".into()),
            require_os_policy_reconciliation: Some(true),
            owned_state_journal: Some("platform-default".into()),
        }),
        ..Default::default()
    }
}

fn flow(app: Option<&str>, attr: Attribution, addr: &str) -> SyntheticFlow {
    SyntheticFlow {
        app_ref: app.map(String::from),
        protocol: IpProtocol::Tcp,
        remote_address: addr.into(),
        remote_port: 443,
        verified_domain: None,
        app_attribution: attr,
    }
}

const SEL: &str = "os-app-ref:selected";
const OTHER: &str = "os-app-ref:other";

fn eval(cfg: &SystemVpnConfig, f: &SyntheticFlow) -> FlowAction {
    cfg.compile()
        .expect("valid")
        .evaluate(f, &caps_all())
        .action
}

#[test]
fn tc_v02_global_mode() {
    let cfg = base(VpnMode::Global);
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Verified, "1.1.1.1")),
        FlowAction::Tunnel
    );
    assert_eq!(
        eval(&cfg, &flow(None, Attribution::Unknown, "1.1.1.1")),
        FlowAction::Tunnel
    );
    assert_eq!(
        eval(&cfg, &flow(None, Attribution::Unknown, "2606:4700::1")),
        FlowAction::Block,
        "ipv6 block"
    );
}

#[test]
fn tc_v02_include_apps_mode() {
    let mut cfg = base(VpnMode::IncludeApps);
    cfg.app_refs = vec![SEL.into()];
    cfg.nonselected_action = Some(DirectOrBlock::Direct);
    cfg.direct_bypass_authorized = true;
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Verified, "1.1.1.1")),
        FlowAction::Tunnel
    );
    assert_eq!(
        eval(&cfg, &flow(Some(OTHER), Attribution::Verified, "1.1.1.1")),
        FlowAction::Direct
    );
    assert_eq!(
        eval(&cfg, &flow(None, Attribution::Unknown, "1.1.1.1")),
        FlowAction::Block
    );
    // Selected helper loses attribution: blocked, never direct.
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Ambiguous, "1.1.1.1")),
        FlowAction::Block
    );
    cfg.nonselected_action = Some(DirectOrBlock::Block);
    assert_eq!(
        eval(&cfg, &flow(Some(OTHER), Attribution::Verified, "1.1.1.1")),
        FlowAction::Block
    );
}

#[test]
fn tc_v02_tc_v04_exclude_apps_requires_verified_identity() {
    let mut cfg = base(VpnMode::ExcludeApps);
    cfg.app_refs = vec![SEL.into()];
    cfg.direct_bypass_authorized = true;
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Verified, "1.1.1.1")),
        FlowAction::Direct
    );
    assert_eq!(
        eval(&cfg, &flow(Some(OTHER), Attribution::Verified, "1.1.1.1")),
        FlowAction::Tunnel
    );
    // Same name/ref but not verified (stale PID, spoofed name): no exclusion.
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Unknown, "1.1.1.1")),
        FlowAction::Block
    );
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Scoped, "1.1.1.1")),
        FlowAction::Tunnel
    );
    cfg.unknown_app_action = Some(TunnelOrBlock::Tunnel);
    assert_eq!(
        eval(&cfg, &flow(Some(SEL), Attribution::Ambiguous, "1.1.1.1")),
        FlowAction::Tunnel
    );
}

fn rule(id: &str, prio: u16, action: FlowAction, m: VpnMatch) -> VpnRule {
    VpnRule {
        id: id.into(),
        priority: prio,
        action,
        matcher: m,
    }
}

fn catch_all(action: FlowAction) -> VpnRule {
    rule(
        "default",
        u16::MAX,
        action,
        VpnMatch {
            protocols: Some(vec![IpProtocol::Tcp, IpProtocol::Udp, IpProtocol::Other]),
            ..Default::default()
        },
    )
}

#[test]
fn tc_v03_rule_mode_precedence_and_domain_evidence() {
    let mut cfg = base(VpnMode::Rule);
    cfg.direct_bypass_authorized = true;
    cfg.rules = vec![
        rule(
            "lan-direct",
            10,
            FlowAction::Direct,
            VpnMatch {
                cidrs: Some(vec!["192.168.0.0/16".into()]),
                ..Default::default()
            },
        ),
        rule(
            "stream-direct",
            20,
            FlowAction::Direct,
            VpnMatch {
                domains: Some(vec!["*.video.example".into()]),
                ..Default::default()
            },
        ),
        rule(
            "block-smb",
            5,
            FlowAction::Block,
            VpnMatch {
                ports: Some(vec![445]),
                ..Default::default()
            },
        ),
        catch_all(FlowAction::Tunnel),
    ];
    let c = cfg.compile().expect("valid");
    let caps = caps_all();
    assert_eq!(
        c.evaluate(&flow(None, Attribution::Unknown, "192.168.1.5"), &caps)
            .action,
        FlowAction::Direct
    );
    let mut f = flow(None, Attribution::Unknown, "8.8.8.8");
    f.remote_port = 445;
    assert_eq!(
        c.evaluate(&f, &caps).action,
        FlowAction::Block,
        "block beats later rules"
    );
    let mut f = flow(None, Attribution::Unknown, "93.184.216.34");
    f.verified_domain = Some("cdn.video.example".into());
    assert_eq!(c.evaluate(&f, &caps).action, FlowAction::Direct);
    // Missing domain evidence: the domain rule cannot match, explicit
    // unknown_domain_action applies rather than a guess.
    let f = flow(None, Attribution::Unknown, "93.184.216.34");
    let d = c.evaluate(&f, &caps);
    assert_eq!(
        (d.action, d.reason_code.as_str()),
        (FlowAction::Block, "unknown_domain")
    );
}

#[test]
fn validation_mirrors_schema_and_semantics() {
    // enabled requires fields
    let cfg = SystemVpnConfig {
        enabled: true,
        ..Default::default()
    };
    assert!(cfg.validate().len() >= 9);
    // include_apps needs explicit nonselected_action
    let mut cfg = base(VpnMode::IncludeApps);
    cfg.app_refs = vec![SEL.into()];
    assert!(cfg
        .validate()
        .iter()
        .any(|e| e.contains("nonselected_action")));
    // direct needs authorization
    cfg.nonselected_action = Some(DirectOrBlock::Direct);
    assert!(cfg
        .validate()
        .iter()
        .any(|e| e.contains("direct_bypass_authorized")));
    // strict lockdown conflicts with direct nonselected
    cfg.direct_bypass_authorized = true;
    cfg.kill_switch = Some(KillSwitch::Strict);
    assert!(cfg
        .validate()
        .iter()
        .any(|e| e.contains("strict kill switch")));
    // global with app refs
    let mut cfg = base(VpnMode::Global);
    cfg.app_refs = vec![SEL.into()];
    assert!(!cfg.validate().is_empty());
    // bare names are not identities
    let mut cfg = base(VpnMode::ExcludeApps);
    cfg.app_refs = vec!["chrome.exe".into()];
    cfg.direct_bypass_authorized = true;
    assert!(cfg.validate().iter().any(|e| e.contains("os-app-ref")));
    // rule mode needs explicit default
    let mut cfg = base(VpnMode::Rule);
    cfg.rules = vec![rule(
        "r",
        1,
        FlowAction::Tunnel,
        VpnMatch {
            ports: Some(vec![443]),
            ..Default::default()
        },
    )];
    assert!(cfg
        .validate()
        .iter()
        .any(|e| e.contains("explicit default rule")));
    // kill switch off only when disabled
    let mut cfg = base(VpnMode::Global);
    cfg.kill_switch = Some(KillSwitch::Off);
    assert!(!cfg.validate().is_empty());
    // physical resolver fallback forbidden
    let mut cfg = base(VpnMode::Global);
    if let Some(d) = cfg.dns.as_mut() {
        d.fallback_to_physical_resolver = true;
    }
    assert!(!cfg.validate().is_empty());
}

#[test]
fn ambiguous_rules_rejected() {
    let mut cfg = base(VpnMode::Rule);
    cfg.rules = vec![
        rule(
            "a",
            10,
            FlowAction::Tunnel,
            VpnMatch {
                ports: Some(vec![443]),
                ..Default::default()
            },
        ),
        rule(
            "b",
            10,
            FlowAction::Block,
            VpnMatch {
                cidrs: Some(vec!["1.0.0.0/8".into()]),
                ..Default::default()
            },
        ),
        catch_all(FlowAction::Tunnel),
    ];
    assert!(cfg.validate().iter().any(|e| e.contains("overlap")));
    // Provably disjoint (different protocols) at the same priority is fine.
    cfg.rules[0].matcher.protocols = Some(vec![IpProtocol::Tcp]);
    cfg.rules[1].matcher.protocols = Some(vec![IpProtocol::Udp]);
    assert!(cfg.validate().is_empty(), "{:?}", cfg.validate());
}

#[test]
fn tc_v05_capability_gate_rejects_unsupported_host() {
    let mut caps = caps_all();
    for m in &mut caps.modes {
        m.support = Support::Unsupported;
        m.explanation = "no native adapter".into();
    }
    caps.native_kill_switch = false;
    let cfg = base(VpnMode::Global);
    let errs = cfg.check_capabilities(&caps);
    assert!(errs.iter().any(|e| e.contains("unsupported")));
    assert!(errs.iter().any(|e| e.contains("kill switch")));
    let d = cfg
        .compile()
        .expect("valid")
        .evaluate(&flow(None, Attribution::Unknown, "1.1.1.1"), &caps);
    assert!(!d.enforcement_possible);
    // Identity-dependent modes on whole-device-only capture.
    let mut caps = caps_all();
    for m in &mut caps.modes {
        m.identity_enforcement = false;
    }
    let mut cfg = base(VpnMode::ExcludeApps);
    cfg.app_refs = vec![SEL.into()];
    cfg.direct_bypass_authorized = true;
    assert!(cfg
        .check_capabilities(&caps)
        .iter()
        .any(|e| e.contains("identity")));
}

#[test]
fn unsupported_udp_never_bypasses() {
    let mut caps = caps_all();
    caps.udp = false;
    let cfg = base(VpnMode::Global);
    let mut f = flow(None, Attribution::Verified, "1.1.1.1");
    f.protocol = IpProtocol::Udp;
    assert_eq!(
        cfg.compile().expect("ok").evaluate(&f, &caps).action,
        FlowAction::Block
    );
}
