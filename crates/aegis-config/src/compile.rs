//! Validation and compilation into an immutable snapshot (02 §5 steps 1–6).

use crate::secret;
use crate::types::*;
use crate::{config_digest, SUPPORTED_SCHEMA_VERSIONS};
use aegis_contracts::capability::Capability;
use aegis_contracts::route::RouteAction;
use aegis_contracts::Role;
use aegis_platform::Registry;
use aegis_policy::{AddressPolicy, Matcher, Router, RuleSpec};
use aegis_traffic_policy::{CompiledVpnPolicy, HostCapabilities};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

/// Registry IDs of the built-in (T0) modules a profile can reference.
pub struct ModuleIds;

impl ModuleIds {
    pub const WEBSOCKET: &'static str = "aegis.transport.websocket";
    pub const SESSION: &'static str = "aegis.session.agp";
    pub const MTLS: &'static str = "aegis.identity.mtls";
    pub const SOCKS5: &'static str = "aegis.inbound.socks5";
    pub const HTTP_CONNECT: &'static str = "aegis.inbound.http_connect";
    pub const DIRECT: &'static str = "aegis.outbound.direct";
    pub const TUNNEL: &'static str = "aegis.outbound.agp_tunnel";
    pub const QUIC: &'static str = "aegis.transport.quic";
}

/// `host:port` (or `[v6]:port`) with a nonzero port and a valid host.
pub fn quic_address(addr: &str) -> Option<(String, u16)> {
    if let Ok(a) = addr.parse::<SocketAddr>() {
        return (a.port() != 0 && !a.ip().is_unspecified()).then(|| (a.ip().to_string(), a.port()));
    }
    let (host, port) = addr.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|p| *p != 0)?;
    let host = aegis_contracts::destination::normalize_domain(host).ok()?;
    Some((host, port))
}

/// The installed capability environment a profile is validated against.
pub struct Environment<'a> {
    pub registry: &'a Registry,
    pub host_vpn: &'a HostCapabilities,
}

/// Immutable compiled snapshot. Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct CompiledConfig {
    pub config: NodeConfig,
    pub digest: String,
    pub router: Router,
    pub vpn: Option<CompiledVpnPolicy>,
    pub warnings: Vec<String>,
    /// Effective egress policy per direct outbound.
    pub outbound_policies: HashMap<String, AddressPolicy>,
}

impl CompiledConfig {
    pub fn outbound(&self, id: &str) -> Option<&OutboundConfig> {
        self.config.outbounds.iter().find(|o| o.id == id)
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_loopback_bind(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

struct Ctx {
    errors: Vec<String>,
    warnings: Vec<String>,
}

impl Ctx {
    fn err(&mut self, m: impl Into<String>) {
        self.errors.push(m.into());
    }
    fn warn(&mut self, m: impl Into<String>) {
        self.warnings.push(m.into());
    }
    fn secret(&mut self, field: &str, v: &Option<String>, required: bool) {
        match v {
            Some(r) => {
                if let Err(e) = secret::parse_ref(r) {
                    self.err(format!("{field}: {e}"));
                }
            }
            None if required => self.err(format!("{field} is required")),
            None => {}
        }
    }
}

fn check_core(c: &CoreConfig, ctx: &mut Ctx) {
    let mib = 1024 * 1024;
    if !(1..=600).contains(&c.shutdown_grace_seconds) {
        ctx.err("core.shutdown_grace_seconds must be 1..=600");
    }
    if !(1..=65_535).contains(&c.max_sessions) {
        ctx.err("core.max_sessions must be 1..=65535");
    }
    if !(1..=4096).contains(&c.max_streams_per_session) {
        ctx.err("core.max_streams_per_session must be 1..=4096");
    }
    if !(4 * mib..=1024 * mib).contains(&c.process_buffer_budget_bytes) {
        ctx.err("core.process_buffer_budget_bytes must be 4 MiB..=1 GiB");
    }
    if c.peer_buffer_budget_bytes > c.process_buffer_budget_bytes {
        ctx.err("core.peer_buffer_budget_bytes must not exceed the process budget");
    }
    if !(16 * 1024..=4 * mib as u32).contains(&c.stream_buffer_budget_bytes) {
        ctx.err("core.stream_buffer_budget_bytes must be 16 KiB..=4 MiB");
    }
    if c.session_window_bytes < 2 * c.stream_buffer_budget_bytes
        || c.session_window_bytes > aegis_contracts_max_window()
    {
        ctx.err("core.session_window_bytes must be >= 2x stream buffer and < 2^31");
    }
    if u64::from(c.session_window_bytes) + u64::from(c.stream_buffer_budget_bytes)
        > c.peer_buffer_budget_bytes
    {
        ctx.err("core.session_window_bytes plus one stream TX buffer must fit the peer budget");
    }
    if !(8192..=65_536).contains(&c.max_frame_payload_bytes) {
        ctx.err("core.max_frame_payload_bytes must be 8192..=65536 (AGP/1 cap)");
    }
    if !c.fail_closed {
        ctx.err(
            "core.fail_closed=false is not supported: failures never fall back to weaker policy",
        );
    }
    for (name, v, max) in [
        ("connect_timeout_ms", c.connect_timeout_ms, 120_000),
        (
            "tls_handshake_timeout_ms",
            c.tls_handshake_timeout_ms,
            60_000,
        ),
        ("open_timeout_ms", c.open_timeout_ms, 120_000),
        (
            "inbound_handshake_timeout_ms",
            c.inbound_handshake_timeout_ms,
            60_000,
        ),
    ] {
        if v < 100 || v > max {
            ctx.err(format!("core.{name} must be 100..={max}"));
        }
    }
    if !(10..=86_400).contains(&c.idle_timeout_seconds) {
        ctx.err("core.idle_timeout_seconds must be 10..=86400");
    }
    if !(5..=300).contains(&c.keepalive_interval_seconds) {
        ctx.err("core.keepalive_interval_seconds must be 5..=300");
    }
}

fn aegis_contracts_max_window() -> u32 {
    (1u32 << 31) - 1
}

/// Minimal `ws(s)://host[:port]/path` parse for validation (the transport
/// crate re-parses strictly at runtime).
fn tunnel_host_port(url: &str) -> Option<(bool, String, u16)> {
    let (tls, rest) = match url.strip_prefix("wss://") {
        Some(r) => (true, r),
        None => (false, url.strip_prefix("ws://")?),
    };
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let end = v6.find(']')?;
        let host = &v6[..end];
        let port = v6[end + 1..]
            .strip_prefix(':')
            .map(|p| p.parse().ok())
            .unwrap_or(Some(if tls { 443 } else { 80 }))?;
        (host.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().ok()?),
            None => (authority.to_owned(), if tls { 443 } else { 80 }),
        }
    };
    Some((tls, host.to_ascii_lowercase(), port))
}

fn host_is_loopback(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

fn to_matcher(id: &str, m: &MatchConfig, ctx: &mut Ctx) -> Matcher {
    match m {
        MatchConfig::Preset(p) if p == PRESET_AUTHENTICATED_PUBLIC => Matcher {
            public_destination: true,
            ..Default::default()
        },
        MatchConfig::Preset(p) => {
            ctx.err(format!("rule {id}: unknown match preset {p:?}"));
            Matcher::default()
        }
        MatchConfig::Table(t) => {
            let mut cidrs = Vec::new();
            for c in &t.cidrs {
                match c.parse() {
                    Ok(n) => cidrs.push(n),
                    Err(_) => ctx.err(format!("rule {id}: invalid cidr {c:?}")),
                }
            }
            Matcher {
                domains: t.domains.clone(),
                domain_suffixes: t.domain_suffixes.clone(),
                cidrs,
                ports: t.ports.clone(),
                inbounds: t.inbounds.clone(),
                nodes: t.nodes.clone(),
                public_destination: t.public_destination,
            }
        }
    }
}

/// Validate `cfg` against `env` and build the immutable snapshot. Returns
/// every error found.
pub fn compile(cfg: &NodeConfig, env: &Environment<'_>) -> Result<CompiledConfig, Vec<String>> {
    let mut ctx = Ctx {
        errors: Vec::new(),
        warnings: Vec::new(),
    };
    let role = cfg.role;
    let reg = env.registry;

    if !SUPPORTED_SCHEMA_VERSIONS.contains(&cfg.schema_version.as_str()) {
        ctx.err(format!(
            "unsupported schema_version {:?}",
            cfg.schema_version
        ));
    }
    if !valid_id(&cfg.node_id) {
        ctx.err("node_id must be 1-64 chars of [A-Za-z0-9._-]");
    }
    check_core(&cfg.core, &mut ctx);

    // Management plane: loopback by default. A non-loopback console needs
    // both an explicit opt-in and HTTPS (ADR-0007).
    let mgmt = &cfg.management;
    if mgmt.enabled {
        match mgmt.bind.parse::<SocketAddr>() {
            Ok(a) if is_loopback_bind(&a) => {}
            Ok(_) if mgmt.remote_access_enabled && mgmt.tls.is_some() => {}
            Ok(_) => ctx.err("management.bind must be loopback unless remote_access_enabled=true and management.tls is configured"),
            Err(_) => ctx.err("management.bind is not a valid socket address"),
        }
        if mgmt.remote_access_enabled && mgmt.tls.is_none() {
            ctx.err("management.remote_access_enabled=true requires management.tls");
        }
        if let Some(tls) = &mgmt.tls {
            if let Err(e) = secret::parse_ref(tls) {
                ctx.err(format!("management.tls: {e}"));
            }
        }
        if mgmt.config_store.is_empty() {
            ctx.err("management.config_store is required");
        }
    }
    if let Some(ui) = &cfg.ui {
        if ui.enabled && (!mgmt.enabled || ui.bind != mgmt.bind) {
            ctx.err(
                "ui.bind must equal management.bind; the UI is served by the management listener",
            );
        }
    }

    // Identity material: references only, never inline values.
    let id = &cfg.identity;
    if cfg.schema_version == "0.2" && !id.require_enrollment {
        ctx.err("schema 0.2 requires identity.require_enrollment=true");
    }
    if id
        .legacy_identity_until
        .is_some_and(|t| !(0..=1_800_662_400).contains(&t))
    {
        ctx.err("identity.legacy_identity_until must not exceed 2027-01-23 UTC");
    }
    if !id.require_enrollment {
        ctx.warn("legacy CA authorization is deprecated and ends 2027-01-23 UTC; migrate to schema 0.2 and register existing devices");
    }
    if id.verify_peer == Some(false) {
        ctx.err(
            "identity.verify_peer=false: disabling peer certificate verification is never allowed",
        );
    }
    match role {
        Role::Gateway => {
            ctx.secret(
                "identity.server_identity",
                &id.server_identity,
                id.material_bundle.is_none(),
            );
            ctx.secret(
                "identity.server_private_key",
                &id.server_private_key,
                id.material_bundle.is_none(),
            );
            ctx.secret("identity.trusted_client_ca", &id.trusted_client_ca, true);
            ctx.secret("identity.ca_certificate", &id.ca_certificate, false);
            ctx.secret("identity.ca_private_key", &id.ca_private_key, false);
            if id.ca_certificate.is_some() != id.ca_private_key.is_some() {
                ctx.err("identity.ca_certificate and identity.ca_private_key must be set together");
            }
            if id.client_identity.is_some()
                || id.client_private_key.is_some()
                || id.trusted_server_ca.is_some()
            {
                ctx.err("client identity fields are not valid on a gateway");
            }
        }
        Role::Client => {
            ctx.secret(
                "identity.client_identity",
                &id.client_identity,
                id.material_bundle.is_none(),
            );
            ctx.secret(
                "identity.client_private_key",
                &id.client_private_key,
                id.material_bundle.is_none(),
            );
            ctx.secret("identity.trusted_server_ca", &id.trusted_server_ca, true);
            if id.server_identity.is_some()
                || id.server_private_key.is_some()
                || id.trusted_client_ca.is_some()
                || id.ca_private_key.is_some()
            {
                ctx.err("gateway identity fields are not valid on a client");
            }
        }
    }
    ctx.secret("identity.material_bundle", &id.material_bundle, false);
    ctx.secret("identity.issuer_bundle", &id.issuer_bundle, false);
    if id.material_bundle.is_some()
        && (id.server_identity.is_some()
            || id.server_private_key.is_some()
            || id.client_identity.is_some()
            || id.client_private_key.is_some())
    {
        ctx.err("identity material bundle and individual leaf references are mutually exclusive");
    }
    if id.issuer_bundle.is_some()
        && (role != Role::Gateway || id.ca_certificate.is_some() || id.ca_private_key.is_some())
    {
        ctx.err(
            "issuer bundle is gateway-only and cannot be combined with legacy issuer references",
        );
    }
    if id.node_certificate_days.is_some_and(|d| d == 0 || d > 90) {
        ctx.err("identity.node_certificate_days must be 1..=90");
    }
    for m in [ModuleIds::MTLS, ModuleIds::SESSION] {
        if let Err(e) = reg.check(m, role) {
            ctx.err(e.to_string());
        }
    }

    // Inbounds.
    let mut ids = HashSet::new();
    // (UDP?, address): a QUIC listener may share a port number with TCP.
    let mut binds: HashSet<(bool, SocketAddr)> = HashSet::new();
    let mut ws_count = 0;
    let mut local_count = 0;
    for ib in &cfg.inbounds {
        if let Some(tls) = &ib.outer_tls {
            if ib.kind != InboundKind::Websocket {
                ctx.err("outer_tls requires websocket ingress");
            }
            if secret::parse_ref(&tls.bundle).is_err()
                || aegis_contracts::destination::normalize_domain(&tls.server_name).as_ref()
                    != Ok(&tls.server_name)
            {
                ctx.err("invalid outer TLS bundle or server DNS name");
            }
            if tls
                .trusted_ca
                .as_ref()
                .is_some_and(|ca| secret::parse_ref(ca).is_err())
            {
                ctx.err("invalid outer TLS trust reference");
            }
        }
        if !valid_id(&ib.id) || !ids.insert(ib.id.clone()) {
            ctx.err(format!("inbound id {:?} is invalid or duplicated", ib.id));
        }
        let bind = match ib.bind.parse::<SocketAddr>() {
            Ok(a) => Some(a),
            Err(_) => {
                ctx.err(format!("inbound {}: bind is not a socket address", ib.id));
                None
            }
        };
        if let Some(b) = bind.filter(|b| b.port() != 0) {
            if !binds.insert((ib.kind == InboundKind::Quic, b)) {
                ctx.err(format!("inbound {}: bind address used twice", ib.id));
            }
        }
        let module = match ib.kind {
            InboundKind::Websocket => ModuleIds::WEBSOCKET,
            InboundKind::Socks5 => ModuleIds::SOCKS5,
            InboundKind::HttpConnect => ModuleIds::HTTP_CONNECT,
            InboundKind::Quic => ModuleIds::QUIC,
        };
        if let Err(e) = reg.check(module, role) {
            ctx.err(format!("inbound {}: {e}", ib.id));
        }
        if let Err(e) = reg.require_capability(module, Capability::ByteStream) {
            ctx.err(format!("inbound {}: {e}", ib.id));
        }
        match ib.kind {
            InboundKind::Websocket => {
                ws_count += 1;
                if role != Role::Gateway {
                    ctx.err(format!(
                        "inbound {}: websocket ingress is a gateway inbound",
                        ib.id
                    ));
                }
                if !ib.path.starts_with('/') || ib.path.len() > 128 || ib.path.contains('?') {
                    ctx.err(format!(
                        "inbound {}: path must be an absolute path without query",
                        ib.id
                    ));
                }
                if !(1..=1024).contains(&ib.max_pending_handshakes) {
                    ctx.err(format!(
                        "inbound {}: max_pending_handshakes must be 1..=1024",
                        ib.id
                    ));
                }
                if !(16_384..=1_048_576).contains(&ib.max_frame_bytes) {
                    ctx.err(format!(
                        "inbound {}: max_frame_bytes must be 16 KiB..=1 MiB",
                        ib.id
                    ));
                }
                if ib.auth.is_some() {
                    ctx.err(format!("inbound {}: websocket peers authenticate with inner mTLS, not inbound auth", ib.id));
                }
                if bind.is_some_and(|b| !is_loopback_bind(&b)) {
                    ctx.warn(format!(
                        "inbound {}: websocket listener is not loopback; expose it only on a trusted bridge or behind the edge",
                        ib.id
                    ));
                }
            }
            InboundKind::Quic => {
                if role != Role::Gateway {
                    ctx.err(format!(
                        "inbound {}: quic ingress is a gateway inbound",
                        ib.id
                    ));
                }
                if !(1..=1024).contains(&ib.max_pending_handshakes) {
                    ctx.err(format!(
                        "inbound {}: max_pending_handshakes must be 1..=1024",
                        ib.id
                    ));
                }
                if ib.auth.is_some() || !ib.allowed_origins.is_empty() {
                    ctx.err(format!(
                        "inbound {}: quic peers authenticate with mutual TLS; auth and allowed_origins don't apply",
                        ib.id
                    ));
                }
            }
            InboundKind::Socks5 | InboundKind::HttpConnect => {
                local_count += 1;
                if let Some(auth) = &ib.auth {
                    if auth.username.is_empty() || auth.username.len() > 255 {
                        ctx.err(format!(
                            "inbound {}: auth.username must be 1..=255 bytes",
                            ib.id
                        ));
                    }
                    if let Err(e) = secret::parse_ref(&auth.password) {
                        ctx.err(format!("inbound {}: auth.password: {e}", ib.id));
                    }
                }
                if bind.is_some_and(|b| !is_loopback_bind(&b)) && ib.auth.is_none() {
                    ctx.err(format!(
                        "inbound {}: non-loopback proxy listener without authentication would be an open proxy",
                        ib.id
                    ));
                }
                if !ib.allowed_origins.is_empty() {
                    ctx.err(format!(
                        "inbound {}: allowed_origins applies only to websocket",
                        ib.id
                    ));
                }
            }
        }
    }
    if role == Role::Gateway && ws_count == 0 {
        ctx.err("a gateway requires at least one websocket inbound");
    }
    if role == Role::Client && local_count == 0 {
        ctx.err("a client requires at least one socks5 or http_connect inbound");
    }

    // Outbounds.
    let mut out_ids = HashSet::new();
    let mut kinds: HashMap<String, OutboundKind> = HashMap::new();
    let mut policies: HashMap<String, AddressPolicy> = HashMap::new();
    for ob in &cfg.outbounds {
        if !valid_id(&ob.id) || !out_ids.insert(ob.id.clone()) {
            ctx.err(format!("outbound id {:?} is invalid or duplicated", ob.id));
        }
        kinds.insert(ob.id.clone(), ob.kind);
        if ob.skip_certificate_verification == Some(true) {
            ctx.err(format!(
                "outbound {}: certificate verification cannot be disabled",
                ob.id
            ));
        }
        let module = match ob.kind {
            OutboundKind::DirectTcp => ModuleIds::DIRECT,
            OutboundKind::AgpTunnel => ModuleIds::TUNNEL,
        };
        if let Err(e) = reg.check(module, role) {
            ctx.err(format!("outbound {}: {e}", ob.id));
        }
        match ob.kind {
            OutboundKind::DirectTcp => {
                if ob.url.is_some()
                    || ob.server_name.is_some()
                    || ob.outer_ca.is_some()
                    || ob.quic.is_some()
                {
                    ctx.err(format!(
                        "outbound {}: url/server_name/outer_ca/quic apply only to agp_tunnel",
                        ob.id
                    ));
                }
                if role == Role::Client && cfg.dns.mode != DnsMode::LocalExplicit {
                    ctx.err(format!(
                        "outbound {}: client direct egress needs local resolution; set dns.mode=local_explicit with an explicit resolver",
                        ob.id
                    ));
                }
                let policy = ob
                    .restricted_address_policy
                    .unwrap_or(AddressPolicy::DenyPrivateAndMetadata);
                if policy == AddressPolicy::AllowPrivate {
                    ctx.warn(format!(
                        "outbound {}: allow-private permits RFC 1918/ULA/CGNAT destinations",
                        ob.id
                    ));
                }
                policies.insert(ob.id.clone(), policy);
            }
            OutboundKind::AgpTunnel => {
                if ob.restricted_address_policy.is_some() {
                    ctx.err(format!(
                        "outbound {}: egress policy is enforced by the gateway, not the tunnel",
                        ob.id
                    ));
                }
                match ob.url.as_deref().and_then(tunnel_host_port) {
                    Some((tls, host, port)) => {
                        if !tls && !host_is_loopback(&host) && !ob.insecure_outer_transport_acknowledged {
                            ctx.err(format!(
                                "outbound {}: ws:// to a non-loopback host requires insecure_outer_transport_acknowledged=true (inner mTLS still applies)",
                                ob.id
                            ));
                        }
                        for ib in &cfg.inbounds {
                            if let Ok(b) = ib.bind.parse::<SocketAddr>() {
                                let same_host = host_is_loopback(&host) && b.ip().is_loopback()
                                    || host.parse::<IpAddr>().ok() == Some(b.ip());
                                if same_host && b.port() == port {
                                    ctx.err(format!("outbound {}: route loop back into inbound {}", ob.id, ib.id));
                                }
                            }
                        }
                    }
                    None => ctx.err(format!("outbound {}: url must be ws:// or wss://host[:port]/path without credentials", ob.id)),
                }
                if let Some(q) = &ob.quic {
                    if quic_address(q).is_none() {
                        ctx.err(format!(
                            "outbound {}: quic must be host:port (or [v6]:port)",
                            ob.id
                        ));
                    }
                    if let Err(e) = reg.check(ModuleIds::QUIC, role) {
                        ctx.err(format!("outbound {}: {e}", ob.id));
                    }
                }
                match &ob.server_name {
                    Some(n) if aegis_contracts::destination::normalize_domain(n).is_ok() => {}
                    _ => ctx.err(format!(
                        "outbound {}: server_name (inner TLS name) is required",
                        ob.id
                    )),
                }
                ctx.secret(
                    &format!("outbound {}: outer_ca", ob.id),
                    &ob.outer_ca,
                    false,
                );
                if let Some(name) = &ob.outer_server_name {
                    if ob.outer_ca.is_none() {
                        ctx.err(format!(
                            "outbound {}: outer_server_name requires outer_ca (a pinned outer trust anchor)",
                            ob.id
                        ));
                    }
                    if aegis_contracts::destination::normalize_domain(name).as_ref() != Ok(name) {
                        ctx.err(format!(
                            "outbound {}: outer_server_name must be a canonical DNS name",
                            ob.id
                        ));
                    }
                }
                if ob.connect_addresses.len() > 8
                    || ob
                        .connect_addresses
                        .iter()
                        .any(|a| crate::connect_address(a, 443).is_none())
                {
                    ctx.err(format!(
                        "outbound {}: connect_addresses must be at most 8 IP addresses (ip, ip:port or [v6]:port)",
                        ob.id
                    ));
                }
                if let Err(e) = reg.require_capability(ModuleIds::WEBSOCKET, Capability::ByteStream)
                {
                    ctx.err(format!("outbound {}: {e}", ob.id));
                }
            }
        }
    }

    // DNS: no unintended resolver fallback, ever.
    let dns = &cfg.dns;
    if dns.fallback_to_system_resolver {
        ctx.err("dns.fallback_to_system_resolver=true is forbidden: sensitive DNS is never retried through the system resolver");
    }
    if dns.mode == DnsMode::PerRule {
        ctx.err("dns.mode=per_rule (split DNS) is an M3/M4 feature not available in this build");
    }
    if !(100..=30_000).contains(&dns.timeout_ms) {
        ctx.err("dns.timeout_ms must be 100..=30000");
    }
    let resolver_needed = role == Role::Gateway || dns.mode == DnsMode::LocalExplicit;
    match (resolver_needed, dns.resolver) {
        (true, None) => ctx.err("dns.resolver must be set explicitly (\"system\" or \"explicit\" with nameservers) before activation"),
        (false, Some(_)) => ctx.err("dns.resolver is not used by a client in remote_required mode; remove it to avoid an unintended local resolver"),
        _ => {}
    }
    if dns.resolver == Some(ResolverKind::Explicit) {
        if dns.nameservers.is_empty() || dns.nameservers.len() > 8 {
            ctx.err("dns.nameservers must list 1..=8 resolvers for resolver=explicit");
        }
        for ns in &dns.nameservers {
            if ns.parse::<SocketAddr>().is_err() && ns.parse::<IpAddr>().is_err() {
                ctx.err(format!("dns.nameservers entry {ns:?} is not an IP[:port]"));
            }
        }
    } else if !dns.nameservers.is_empty() {
        ctx.err("dns.nameservers requires resolver=explicit");
    }

    // Telemetry: profiles can never enable export or diagnostics (05 §7, 11 §3).
    let t = &cfg.telemetry;
    if t.otlp_export_enabled {
        ctx.err("telemetry.otlp_export_enabled cannot be set by a profile; use the authenticated /telemetry/settings workflow");
    }
    if t.profile != TelemetryProfile::Off {
        ctx.err("telemetry.profile must be \"off\" in profiles; coarse_export and local_diagnostic require separate authorized actions");
    }
    if t.logs_to_console {
        ctx.err("telemetry.logs_to_console=true is not allowed: no routine console event logs");
    }
    if t.sensitive_diagnostics_enabled {
        ctx.err("telemetry.sensitive_diagnostics_enabled cannot be enabled by a profile");
    }
    if t.semantic_conventions_version != "1.44.0" {
        ctx.warn("telemetry.semantic_conventions_version differs from the pinned 1.44.0 registry");
    }

    // Transport flags: no insecure fallback, unimplemented transports refused.
    let tr = &cfg.transport;
    if tr.allow_insecure_fallback {
        ctx.err("transport.allow_insecure_fallback=true is forbidden");
    }
    if tr.h2_experimental || tr.preferred == TransportPreference::Http2 {
        ctx.err("HTTP/2 transport is not available in this build (C-005 experimental track)");
    }
    if tr.sse_experimental {
        ctx.err("SSE+POST transport is research-only and not available");
    }
    if let Some(cf) = &cfg.cloudflare {
        if let Some(origin) = &cf.origin_bind {
            let matches = cfg
                .inbounds
                .iter()
                .any(|i| i.kind == InboundKind::Websocket && &i.bind == origin);
            if !matches {
                ctx.warn("cloudflare.origin_bind does not match any websocket inbound bind");
            }
        }
        if role != Role::Gateway && cf.mode != CloudflareMode::None {
            ctx.err("cloudflare deployment settings apply to gateways");
        }
    }

    // Routing.
    let router_policy = match role {
        Role::Gateway => {
            if policies.values().any(|p| *p == AddressPolicy::AllowPrivate) {
                AddressPolicy::AllowPrivate
            } else {
                AddressPolicy::DenyPrivateAndMetadata
            }
        }
        // Clients defer egress restrictions to the gateway; loopback,
        // link-local and metadata literals are still refused locally.
        Role::Client => AddressPolicy::AllowPrivate,
    };
    if let Some(o) = &cfg.routing.default_outbound {
        if !out_ids.contains(o) {
            ctx.err(format!("routing.default_outbound {o:?} does not exist"));
        }
    }
    let check_action =
        |action: RouteAction, outbound: &Option<String>, what: &str, ctx: &mut Ctx| {
            if action == RouteAction::Deny {
                return;
            }
            let Some(o) = outbound else { return };
            let Some(kind) = kinds.get(o) else { return };
            let ok = matches!(
                (role, action, kind),
                (Role::Gateway, RouteAction::Proxy, OutboundKind::DirectTcp)
                    | (Role::Client, RouteAction::Proxy, OutboundKind::AgpTunnel)
                    | (Role::Client, RouteAction::Direct, OutboundKind::DirectTcp)
            );
            if !ok {
                ctx.err(format!(
                    "{what}: action {} via {} outbound {o} is not valid for a {role:?}",
                    action.as_str(),
                    kind.as_str()
                ));
            }
        };
    let default_action: RouteAction = cfg.routing.default_action.into();
    check_action(
        default_action,
        &cfg.routing.default_outbound,
        "routing default",
        &mut ctx,
    );
    let mut specs = Vec::new();
    for r in &cfg.routing.rules {
        let action: RouteAction = r.action.into();
        check_action(action, &r.outbound, &format!("rule {}", r.id), &mut ctx);
        let matcher = to_matcher(&r.id, &r.matcher, &mut ctx);
        for ib in &matcher.inbounds {
            if !ids.contains(ib) {
                ctx.err(format!("rule {}: unknown inbound {ib}", r.id));
            }
        }
        specs.push(RuleSpec {
            id: r.id.clone(),
            priority: r.priority.unwrap_or(1000),
            action,
            outbound: r.outbound.clone(),
            matcher,
        });
    }
    let router = match Router::compile(
        specs,
        default_action,
        cfg.routing.default_outbound.clone(),
        router_policy,
        &out_ids,
    ) {
        Ok(r) => {
            ctx.warnings.extend(r.warnings.iter().cloned());
            Some(r)
        }
        Err(errs) => {
            ctx.errors
                .extend(errs.into_iter().map(|e| format!("routing: {e}")));
            None
        }
    };

    // System-VPN section.
    let mut vpn = None;
    if let Some(sv) = &cfg.system_vpn {
        if sv.enabled && role == Role::Gateway {
            ctx.err("system_vpn cannot be enabled on a gateway profile");
        }
        ctx.errors.extend(
            sv.validate()
                .into_iter()
                .map(|e| format!("system_vpn: {e}")),
        );
        ctx.errors.extend(
            sv.check_capabilities(env.host_vpn)
                .into_iter()
                .map(|e| format!("system_vpn: {e}")),
        );
        if let Ok(c) = sv.compile() {
            vpn = Some(c);
        }
    }

    if !ctx.errors.is_empty() {
        return Err(ctx.errors);
    }
    let Some(router) = router else {
        return Err(vec!["routing failed to compile".into()]);
    };
    Ok(CompiledConfig {
        digest: config_digest(cfg),
        config: cfg.clone(),
        router,
        vpn,
        warnings: ctx.warnings,
        outbound_policies: policies,
    })
}
