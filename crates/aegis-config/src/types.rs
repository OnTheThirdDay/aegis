//! Typed configuration schema `0.1`. Every struct rejects unknown fields.

use aegis_contracts::route::RouteAction;
use aegis_contracts::Role;
use aegis_policy::AddressPolicy;
use aegis_traffic_policy::SystemVpnConfig;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub schema_version: String,
    /// Operator label; never emitted as a metric label.
    pub node_id: String,
    pub role: Role,
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub management: ManagementConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
    pub identity: IdentityConfig,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    pub routing: RoutingConfig,
    pub dns: DnsConfig,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub transport: TransportConfig,
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
    #[serde(default)]
    pub ui: Option<UiConfig>,
    #[serde(default)]
    pub system_vpn: Option<SystemVpnConfig>,
}

fn d_true() -> bool {
    true
}
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CoreConfig {
    pub shutdown_grace_seconds: u32,
    pub max_sessions: u32,
    pub max_streams_per_session: u32,
    pub process_buffer_budget_bytes: u64,
    pub peer_buffer_budget_bytes: u64,
    pub stream_buffer_budget_bytes: u32,
    pub session_window_bytes: u32,
    pub max_frame_payload_bytes: u32,
    pub fail_closed: bool,
    pub connect_timeout_ms: u32,
    pub tls_handshake_timeout_ms: u32,
    pub open_timeout_ms: u32,
    pub idle_timeout_seconds: u32,
    pub keepalive_interval_seconds: u32,
    pub inbound_handshake_timeout_ms: u32,
}

impl Default for CoreConfig {
    fn default() -> Self {
        CoreConfig {
            shutdown_grace_seconds: 15,
            max_sessions: 128,
            // Streams start with a 16 KiB window that grows (up to
            // stream_buffer_budget_bytes) only while busy, inside the 8 MiB
            // session window less one full stream window as the working
            // share: ~500 concurrent connections, idle ones nearly free.
            // The peer budget covers the session window plus each stream's
            // initial transmit reservation, with room to grow.
            max_streams_per_session: 512,
            process_buffer_budget_bytes: 256 * 1024 * 1024,
            peer_buffer_budget_bytes: 24 * 1024 * 1024,
            stream_buffer_budget_bytes: 256 * 1024,
            session_window_bytes: 8 * 1024 * 1024,
            max_frame_payload_bytes: 16 * 1024,
            fail_closed: true,
            connect_timeout_ms: 10_000,
            tls_handshake_timeout_ms: 10_000,
            open_timeout_ms: 15_000,
            idle_timeout_seconds: 300,
            keepalive_interval_seconds: 30,
            inbound_handshake_timeout_ms: 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementAuth {
    LocalOwner,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ManagementConfig {
    pub enabled: bool,
    pub bind: String,
    pub remote_access_enabled: bool,
    pub authentication: ManagementAuth,
    pub config_store: String,
    /// Local privileged IPC socket (Unix). Defaults next to the store.
    pub ipc_socket: Option<String>,
    /// Additional Host header values accepted (beyond the bind address and
    /// `localhost:<port>`).
    pub allowed_hosts: Vec<String>,
    /// HTTPS for the console: `secret://` reference to a JSON bundle
    /// `{"certificate": "secret://..", "private_key": "secret://.."}`.
    /// Required for any non-loopback bind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<String>,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        ManagementConfig {
            enabled: true,
            bind: "127.0.0.1:9080".into(),
            remote_access_enabled: false,
            authentication: ManagementAuth::LocalOwner,
            config_store: "/var/lib/aegisnet/state.db".into(),
            ipc_socket: None,
            allowed_hosts: Vec::new(),
            tls: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecretsConfig {
    pub dir: String,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        SecretsConfig {
            dir: "/run/secrets/aegisnet".into(),
        }
    }
}

/// Inner peer authentication. Serialized as `mutual_tls_1_3` (custom serde
/// below, since `rename_all` cannot produce that spelling).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerAuth {
    MutualTls13,
}

impl PeerAuth {
    pub fn as_str(self) -> &'static str {
        "mutual_tls_1_3"
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(with = "peer_auth_str")]
    pub peer_auth: PeerAuth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub material_bundle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_bundle: Option<String>,
    // Gateway material.
    pub server_identity: Option<String>,
    pub server_private_key: Option<String>,
    pub trusted_client_ca: Option<String>,
    /// Local CA used to sign enrollment CSRs (gateway only, optional).
    pub ca_certificate: Option<String>,
    pub ca_private_key: Option<String>,
    // Client material.
    pub client_identity: Option<String>,
    pub client_private_key: Option<String>,
    pub trusted_server_ca: Option<String>,
    /// Explicitly disabling peer verification is always rejected; the field
    /// exists so such a profile fails loudly instead of being ignored.
    pub verify_peer: Option<bool>,
    pub node_certificate_days: Option<u32>,
    /// Explicit migration: v0.1 keeps legacy CA authorization until cutoff;
    /// new v0.2 deployments require registry authorization.
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_enrollment: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub legacy_identity_until: Option<i64>,
}

mod peer_auth_str {
    use super::PeerAuth;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(_: &PeerAuth, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("mutual_tls_1_3")
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<PeerAuth, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "mutual_tls_1_3" => Ok(PeerAuth::MutualTls13),
            _ => Err(serde::de::Error::custom("peer_auth must be mutual_tls_1_3")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundKind {
    Websocket,
    Socks5,
    HttpConnect,
}

impl InboundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InboundKind::Websocket => "websocket",
            InboundKind::Socks5 => "socks5",
            InboundKind::HttpConnect => "http_connect",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundAuth {
    pub username: String,
    /// `secret://` reference to the password file.
    pub password: String,
}

fn d_pending() -> u32 {
    32
}
fn d_frame() -> u32 {
    65_536
}
fn d_path() -> String {
    "/agp".into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InboundConfig {
    pub id: String,
    pub kind: InboundKind,
    pub bind: String,
    #[serde(default = "d_pending")]
    pub max_pending_handshakes: u32,
    #[serde(default = "d_frame")]
    pub max_frame_bytes: u32,
    /// WebSocket upgrade path.
    #[serde(default = "d_path")]
    pub path: String,
    #[serde(default)]
    pub auth: Option<InboundAuth>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Optional native public/direct TLS, outside the mandatory inner mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer_tls: Option<OuterTlsConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OuterTlsConfig {
    pub bundle: String,
    pub server_name: String,
    pub trusted_ca: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundKind {
    DirectTcp,
    AgpTunnel,
}

impl OutboundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OutboundKind::DirectTcp => "direct_tcp",
            OutboundKind::AgpTunnel => "agp_tunnel",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    pub id: String,
    pub kind: OutboundKind,
    /// direct_tcp: egress address policy.
    #[serde(default)]
    pub restricted_address_policy: Option<AddressPolicy>,
    /// agp_tunnel: `wss://host/path` of the gateway WebSocket entry.
    #[serde(default)]
    pub url: Option<String>,
    /// agp_tunnel: expected inner TLS server name of the gateway.
    #[serde(default)]
    pub server_name: Option<String>,
    /// agp_tunnel: extra outer-TLS trust anchor (secret:// reference).
    #[serde(default)]
    pub outer_ca: Option<String>,
    /// agp_tunnel: verify the outer certificate against this name instead of
    /// the URL host. Requires `outer_ca`, which then becomes the only outer
    /// trust anchor (public roots are not consulted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outer_server_name: Option<String>,
    /// agp_tunnel: connect to these IP addresses (`ip`, `ip:port` or
    /// `[v6]:port`; the URL's port when omitted) instead of resolving the URL
    /// host, like `curl --resolve`. TLS verification and the WebSocket Host
    /// still use the URL host. At most 8.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub connect_addresses: Vec<String>,
    /// agp_tunnel: acknowledge a plaintext `ws://` outer hop to a non-loopback
    /// host (inner mTLS still protects data). Never implied.
    #[serde(default)]
    pub insecure_outer_transport_acknowledged: bool,
    /// Always rejected when true.
    #[serde(default)]
    pub skip_certificate_verification: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default)]
    pub default_outbound: Option<String>,
    pub default_action: RouteActionConfig,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteActionConfig {
    Proxy,
    Direct,
    Deny,
}

impl From<RouteActionConfig> for RouteAction {
    fn from(a: RouteActionConfig) -> Self {
        match a {
            RouteActionConfig::Proxy => RouteAction::Proxy,
            RouteActionConfig::Direct => RouteAction::Direct,
            RouteActionConfig::Deny => RouteAction::Deny,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    pub id: String,
    #[serde(rename = "match")]
    pub matcher: MatchConfig,
    pub action: RouteActionConfig,
    #[serde(default)]
    pub outbound: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
}

/// Either a named preset or a structured matcher.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MatchConfig {
    Preset(String),
    Table(MatchTable),
}

pub const PRESET_AUTHENTICATED_PUBLIC: &str = "authenticated-and-public-destination";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MatchTable {
    pub domains: Vec<String>,
    pub domain_suffixes: Vec<String>,
    pub cidrs: Vec<String>,
    pub ports: Vec<u16>,
    pub inbounds: Vec<String>,
    pub nodes: Vec<String>,
    pub public_destination: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsMode {
    /// Clients never resolve; names travel to the gateway, which resolves
    /// through its explicitly configured resolver only.
    RemoteRequired,
    /// Local resolution through an explicitly configured resolver.
    LocalExplicit,
    /// Split rules (M3/M4; rejected by this build).
    PerRule,
}

impl DnsMode {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsMode::RemoteRequired => "remote_required",
            DnsMode::LocalExplicit => "local_explicit",
            DnsMode::PerRule => "per_rule",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ipv6Policy {
    /// Keep AAAA results; each address still passes routing/egress policy.
    FollowRoutingPolicy,
    /// Never use IPv6 destinations.
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverKind {
    /// The host's configured resolver (getaddrinfo), explicitly chosen.
    System,
    /// Only the listed nameservers.
    Explicit,
}

fn d_dns_timeout() -> u32 {
    5_000
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    pub mode: DnsMode,
    #[serde(default)]
    pub fallback_to_system_resolver: bool,
    pub ipv6_policy: Ipv6Policy,
    #[serde(default)]
    pub resolver: Option<ResolverKind>,
    #[serde(default)]
    pub nameservers: Vec<String>,
    #[serde(default = "d_dns_timeout")]
    pub timeout_ms: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryProfile {
    Off,
    CoarseExport,
    LocalDiagnostic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub otlp_export_enabled: bool,
    pub logs_to_console: bool,
    #[serde(default = "d_true")]
    pub local_metrics_enabled: bool,
    pub sensitive_diagnostics_enabled: bool,
    pub profile: TelemetryProfile,
    pub semantic_conventions_version: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        TelemetryConfig {
            enabled: false,
            otlp_export_enabled: false,
            logs_to_console: false,
            local_metrics_enabled: true,
            sensitive_diagnostics_enabled: false,
            profile: TelemetryProfile::Off,
            semantic_conventions_version: "1.44.0".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPreference {
    Websocket,
    Http2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TransportConfig {
    pub preferred: TransportPreference,
    pub h2_experimental: bool,
    pub sse_experimental: bool,
    pub allow_insecure_fallback: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            preferred: TransportPreference::Websocket,
            h2_experimental: false,
            sse_experimental: false,
            allow_insecure_fallback: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareMode {
    ExternalTunnel,
    ProxiedWebsocket,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareConfig {
    pub mode: CloudflareMode,
    #[serde(default)]
    pub origin_bind: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiConfig {
    pub enabled: bool,
    pub bind: String,
}
