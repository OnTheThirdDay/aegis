//! TC-U02, TC-P11 and 07 §5 configuration rejections.

use aegis_config::{
    compile, config_digest, parse_json, parse_toml, security_diff, to_json, Environment, ModuleIds,
};
use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_platform::{host_vpn_capabilities, Registry};

fn d(
    id: &'static str,
    provides: &'static [Capability],
    requires: &'static [Capability],
    roles: &'static [Role],
) -> ModuleDescriptor {
    ModuleDescriptor {
        module_id: id,
        module_version: "0.1.0",
        api_version: 1,
        roles,
        operating_systems: &[OsFamily::Linux, OsFamily::Windows, OsFamily::Macos],
        provides,
        requires,
        budget: ResourceBudget::default(),
        maturity: Maturity::Experimental,
        conformance_hash: "",
    }
}

fn registry() -> Registry {
    use Capability::*;
    let both: &'static [Role] = &[Role::Client, Role::Gateway];
    let mut r = Registry::new(OsFamily::Linux);
    r.register(d(
        ModuleIds::WEBSOCKET,
        &[ByteStream, Ordered, HalfClose, HttpReverseProxyCompatible],
        &[],
        both,
    ))
    .expect("ws");
    r.register(d(ModuleIds::MTLS, &[InnerMutualTls], &[ByteStream], both))
        .expect("mtls");
    r.register(d(
        ModuleIds::SESSION,
        &[ConnectionMultiplexing, ByteStream, HalfClose],
        &[InnerMutualTls],
        both,
    ))
    .expect("session");
    r.register(d(ModuleIds::SOCKS5, &[ByteStream], &[], both))
        .expect("socks");
    r.register(d(ModuleIds::HTTP_CONNECT, &[ByteStream], &[], both))
        .expect("http");
    r.register(d(ModuleIds::DIRECT, &[ByteStream, EgressAcl], &[], both))
        .expect("direct");
    r.register(d(
        ModuleIds::TUNNEL,
        &[ByteStream],
        &[ConnectionMultiplexing, InnerMutualTls],
        &[Role::Client],
    ))
    .expect("tunnel");
    r
}

fn check(text: &str) -> Result<aegis_config::CompiledConfig, Vec<String>> {
    let cfg = parse_toml(text).map_err(|e| vec![e.to_string()])?;
    let reg = registry();
    let host = host_vpn_capabilities(OsFamily::Linux);
    compile(
        &cfg,
        &Environment {
            registry: &reg,
            host_vpn: &host,
        },
    )
}

const GATEWAY: &str = r#"
schema_version = "0.1"
node_id = "pi-gateway-01"
role = "gateway"

[core]
max_sessions = 128

[management]
bind = "127.0.0.1:9080"
config_store = "/var/lib/aegisnet/state.db"

[identity]
peer_auth = "mutual_tls_1_3"
server_identity = "secret://identity/server-cert"
server_private_key = "secret://identity/server-key"
trusted_client_ca = "secret://identity/client-ca"

[[inbounds]]
id = "ingress-ws"
kind = "websocket"
bind = "127.0.0.1:18080"

[[outbounds]]
id = "public-egress"
kind = "direct_tcp"
restricted_address_policy = "deny-private-and-metadata"

[routing]
default_outbound = "public-egress"
default_action = "deny"

[[routing.rules]]
id = "authorized-users-public-egress"
match = "authenticated-and-public-destination"
action = "proxy"
outbound = "public-egress"

[dns]
mode = "remote_required"
fallback_to_system_resolver = false
ipv6_policy = "follow-routing-policy"
resolver = "system"
"#;

const CLIENT: &str = r#"
schema_version = "0.1"
node_id = "laptop-1"
role = "client"

[management]
bind = "127.0.0.1:9081"
config_store = "/tmp/client.db"

[identity]
peer_auth = "mutual_tls_1_3"
client_identity = "secret://identity/client-cert"
client_private_key = "secret://identity/client-key"
trusted_server_ca = "secret://identity/server-ca"

[[inbounds]]
id = "local-socks"
kind = "socks5"
bind = "127.0.0.1:1080"

[[outbounds]]
id = "tunnel"
kind = "agp_tunnel"
url = "wss://gateway.example.org/agp"
server_name = "gateway.aegis.internal"

[routing]
default_outbound = "tunnel"
default_action = "proxy"

[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
"#;

fn with(base: &str, find: &str, replace: &str) -> String {
    assert!(base.contains(find), "fixture missing {find:?}");
    base.replacen(find, replace, 1)
}

fn assert_rejected(text: &str, needle: &str) {
    let errs = check(text).expect_err("must be rejected");
    assert!(
        errs.iter().any(|e| e.contains(needle)),
        "expected an error containing {needle:?}, got {errs:#?}"
    );
}

#[test]
fn valid_gateway_and_client_compile() {
    let g = check(GATEWAY).expect("gateway valid");
    assert_eq!(g.digest.len(), 64);
    let c = check(CLIENT).expect("client valid");
    assert_ne!(g.digest, c.digest);
}

#[test]
fn spec_example_requires_explicit_resolver() {
    let spec = include_str!("../../../aegis-spec/examples/config.toml");
    assert_rejected(spec, "dns.resolver must be set explicitly");
}

#[test]
fn tc_u02_equivalent_inputs_same_digest() {
    let a = parse_toml(GATEWAY).expect("toml");
    let json = to_json(&a);
    let b = parse_json(&json).expect("json");
    assert_eq!(config_digest(&a), config_digest(&b));
    // Reordered/whitespace-different TOML with explicit defaults.
    let reordered = with(
        GATEWAY,
        "[core]\nmax_sessions = 128",
        "[core]\nmax_streams_per_session = 64\nmax_sessions   =   128",
    );
    let c = parse_toml(&reordered).expect("toml");
    assert_eq!(config_digest(&a), config_digest(&c));
}

#[test]
fn tc_u02_unknown_fields_rejected() {
    let text = with(GATEWAY, "[core]", "[core]\nsecret_backdoor = true");
    assert!(parse_toml(&text).is_err());
    let text = with(GATEWAY, "[dns]", "[dns]\nfallback_to_doh = true");
    assert!(parse_toml(&text).is_err());
}

#[test]
fn disabled_tls_verification_rejected() {
    assert_rejected(
        &with(
            GATEWAY,
            "peer_auth = \"mutual_tls_1_3\"",
            "peer_auth = \"mutual_tls_1_3\"\nverify_peer = false",
        ),
        "verify_peer=false",
    );
    assert_rejected(
        &with(
            CLIENT,
            "server_name = \"gateway.aegis.internal\"",
            "server_name = \"gateway.aegis.internal\"\nskip_certificate_verification = true",
        ),
        "certificate verification cannot be disabled",
    );
    assert!(parse_toml(&with(GATEWAY, "\"mutual_tls_1_3\"", "\"none\"")).is_err());
}

#[test]
fn public_management_and_open_proxy_rejected() {
    assert_rejected(
        &with(
            GATEWAY,
            "bind = \"127.0.0.1:9080\"",
            "bind = \"0.0.0.0:9080\"",
        ),
        "management.bind must be loopback",
    );
    assert_rejected(
        &with(
            GATEWAY,
            "config_store",
            "remote_access_enabled = true\nconfig_store",
        ),
        "remote_access_enabled",
    );
    assert_rejected(
        &with(
            CLIENT,
            "bind = \"127.0.0.1:1080\"",
            "bind = \"0.0.0.0:1080\"",
        ),
        "open proxy",
    );
}

#[test]
fn dns_leak_paths_rejected() {
    assert_rejected(
        &with(
            GATEWAY,
            "fallback_to_system_resolver = false",
            "fallback_to_system_resolver = true",
        ),
        "fallback_to_system_resolver",
    );
    assert_rejected(
        &with(
            CLIENT,
            "ipv6_policy = \"follow-routing-policy\"",
            "ipv6_policy = \"follow-routing-policy\"\nresolver = \"system\"",
        ),
        "unintended local resolver",
    );
    assert_rejected(
        &with(GATEWAY, "mode = \"remote_required\"", "mode = \"per_rule\""),
        "per_rule",
    );
}

#[test]
fn telemetry_cannot_be_enabled_by_profile() {
    let t = format!("{GATEWAY}\n[telemetry]\notlp_export_enabled = true\n");
    assert_rejected(&t, "otlp_export_enabled");
    let t = format!("{GATEWAY}\n[telemetry]\nprofile = \"coarse_export\"\n");
    assert_rejected(&t, "telemetry.profile");
    let t = format!("{GATEWAY}\n[telemetry]\nlogs_to_console = true\n");
    assert_rejected(&t, "logs_to_console");
}

#[test]
fn insecure_transport_rejected() {
    let t = format!("{GATEWAY}\n[transport]\nallow_insecure_fallback = true\n");
    assert_rejected(&t, "allow_insecure_fallback");
    assert_rejected(
        &with(
            CLIENT,
            "wss://gateway.example.org/agp",
            "ws://gateway.example.org/agp",
        ),
        "insecure_outer_transport_acknowledged",
    );
    assert_rejected(
        &with(
            CLIENT,
            "wss://gateway.example.org/agp",
            "wss://user:pw@gateway.example.org/agp",
        ),
        "without credentials",
    );
}

#[test]
fn tc_p11_invalid_or_looping_policy_rejected() {
    // Route loop: the tunnel points back at our own listener.
    let looping = with(
        CLIENT,
        "wss://gateway.example.org/agp",
        "ws://127.0.0.1:1080/agp",
    );
    assert_rejected(&looping, "route loop");
    // Unknown outbound.
    assert_rejected(
        &with(
            GATEWAY,
            "outbound = \"public-egress\"\n",
            "outbound = \"nowhere\"\n",
        ),
        "does not exist",
    );
    // Gateway cannot use client-direct semantics.
    assert_rejected(
        &with(GATEWAY, "action = \"proxy\"", "action = \"direct\""),
        "not valid for a Gateway",
    );
    // Conflicting identical rules.
    let conflict = format!(
        "{GATEWAY}\n[[routing.rules]]\nid = \"deny-same\"\nmatch = \"authenticated-and-public-destination\"\naction = \"deny\"\n"
    );
    assert_rejected(&conflict, "conflicts with rule");
}

#[test]
fn system_vpn_gated_by_host_capabilities() {
    let text = format!(
        r#"{CLIENT}
[system_vpn]
enabled = true
mode = "global"
kill_switch = "protected_flows"
unknown_app_action = "block"
unknown_domain_action = "block"
unsupported_protocol_action = "block"
ipv4_policy = "tunnel"
ipv6_policy = "block"
[system_vpn.dns]
mode = "strict"
intercept_udp_53 = true
intercept_tcp_53 = true
fallback_to_physical_resolver = false
[system_vpn.host]
helper = "native_scoped_helper"
require_os_policy_reconciliation = true
owned_state_journal = "platform-default"
"#
    );
    assert_rejected(&text, "unsupported on this host");
    // Disabled section is accepted (default for existing installs).
    let disabled = format!("{CLIENT}\n[system_vpn]\nenabled = false\n");
    assert!(check(&disabled).is_ok());
}

#[test]
fn security_diff_reports_restart_and_future_admission() {
    let a = parse_toml(GATEWAY).expect("a");
    let b = parse_toml(&with(
        GATEWAY,
        "bind = \"127.0.0.1:18080\"",
        "bind = \"127.0.0.1:18081\"",
    ))
    .expect("b");
    let diff = security_diff(Some(&a), &b);
    assert!(diff.restart_required.iter().any(|s| s.contains("inbound")));
    let c = parse_toml(&with(
        GATEWAY,
        "default_action = \"deny\"",
        "default_action = \"proxy\"",
    ))
    .expect("c");
    let diff = security_diff(Some(&a), &c);
    assert!(diff
        .security
        .iter()
        .any(|s| s.contains("future admissions")));
    assert!(diff.restart_required.is_empty());
    let e = parse_toml(&with(
        GATEWAY,
        "node_id = \"pi-gateway-01\"",
        "node_id = \"other\"",
    ))
    .expect("e");
    assert!(!security_diff(Some(&a), &e).forbidden.is_empty());
}
