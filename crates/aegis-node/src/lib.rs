//! Node composition root.
//!
//! Wires the transport, inbound and outbound modules to the transport-
//! agnostic core: listeners are bound from the active (recovered) revision,
//! every new logical stream goes through the admission gate, and identities
//! are loaded from `secret://` references at start.
#![forbid(unsafe_code)]

mod client;
mod egress;
mod gateway;
pub mod modules;
pub mod relay;
mod sessions;

pub use sessions::SessionRegistry;

use aegis_buffer::Budget;
use aegis_config::{secret, DnsMode, InboundKind, Ipv6Policy, NodeConfig, ResolverKind};
use aegis_contracts::capability::OsFamily;
use aegis_contracts::observability::{Observability, PoolClass};
use aegis_contracts::reason::ResetReason;
use aegis_contracts::state::AgentState;
use aegis_contracts::Role;
use aegis_core::{
    AdmissionGate, AgentCell, CapabilityEnv, Coordinator, FailPoints, NoFailPoints, RecoveryOutcome,
};
use aegis_dns::Resolver;
use aegis_identity::pki::CaBundle;
use aegis_identity::{IdentitySnapshot, IdentityStore};
use aegis_session::SessionConfig;
use aegis_storage::Store;
use aegis_telemetry::{CoreGauges, DiagnosticSink, LocalMetrics};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Stable, secret-free startup failure codes (the only console output a
/// node produces; 11 §3 rule 2).
#[derive(Debug)]
pub enum StartError {
    ConfigInvalid(Vec<String>),
    Storage(String),
    Identity(String),
    Bind(String),
    Recovery(String),
}

impl StartError {
    pub fn code(&self) -> &'static str {
        match self {
            StartError::ConfigInvalid(_) => "E_CONFIG_INVALID",
            StartError::Storage(_) => "E_STORAGE",
            StartError::Identity(_) => "E_IDENTITY",
            StartError::Bind(_) => "E_BIND",
            StartError::Recovery(_) => "E_RECOVERY",
        }
    }
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::ConfigInvalid(e) => write!(f, "{}: {}", self.code(), e.join("; ")),
            StartError::Storage(e)
            | StartError::Identity(e)
            | StartError::Bind(e)
            | StartError::Recovery(e) => {
                write!(f, "{}: {e}", self.code())
            }
        }
    }
}

impl std::error::Error for StartError {}

/// Identity material loaded from secrets.
pub(crate) struct LoadedIdentity {
    pub server_tls: Option<Arc<rustls::ServerConfig>>,
    pub client_tls: Option<Arc<rustls::ClientConfig>>,
    pub ca: Option<CaBundle>,
}

pub struct NodeContext {
    pub node_id: String,
    pub role: Role,
    pub coord: Arc<Coordinator>,
    pub gate: Arc<AdmissionGate>,
    pub metrics: Arc<LocalMetrics>,
    pub diagnostics: Arc<DiagnosticSink>,
    pub budget: Arc<Budget>,
    pub streams_active: Arc<AtomicU64>,
    pub sessions: Arc<SessionRegistry>,
    pub secrets_dir: PathBuf,
    /// The configuration listeners and identities were started from.
    pub startup: NodeConfig,
    /// Local CA used to sign enrollment CSRs (gateway only).
    pub ca: Option<CaBundle>,
    pub(crate) identity: LoadedIdentity,
    pub(crate) tunnels: HashMap<String, Arc<client::Tunnel>>,
    resolver_cache: Mutex<Option<(String, Arc<Resolver>)>>,
    shutdown: watch::Sender<bool>,
}

impl NodeContext {
    pub fn obs(&self) -> &dyn Observability {
        self.metrics.as_ref()
    }

    /// Authoritative gauges for local status and coarse export.
    pub fn gauges(&self) -> CoreGauges {
        CoreGauges {
            sessions_active: self.sessions.count() as u64
                + self.tunnels.values().filter(|t| t.connected()).count() as u64,
            streams_active: self.streams_active.load(Ordering::Relaxed),
            buffer_receive: self.budget.class_used(PoolClass::Receive),
            buffer_transmit: self.budget.class_used(PoolClass::Transmit),
            buffer_control: self.budget.class_used(PoolClass::Control),
            buffer_total: self.budget.used(),
        }
    }

    pub(crate) fn session_config(&self) -> SessionConfig {
        let c = &self.startup.core;
        SessionConfig {
            node_id: self.node_id.clone(),
            max_streams: c.max_streams_per_session,
            stream_window: c.stream_buffer_budget_bytes,
            session_window: c.session_window_bytes,
            max_frame_payload: c.max_frame_payload_bytes,
            stream_tx_buffer: c.stream_buffer_budget_bytes,
            handshake_timeout: Duration::from_millis(u64::from(c.tls_handshake_timeout_ms)),
            keepalive_interval: Duration::from_secs(u64::from(c.keepalive_interval_seconds)),
            keepalive_timeout: Duration::from_secs(u64::from(c.keepalive_interval_seconds).max(10)),
            ..SessionConfig::default()
        }
    }

    /// Resolver for a bundle's DNS policy; `None` when this node must never
    /// resolve locally (client in `remote_required`).
    pub(crate) fn resolver_for(&self, cfg: &NodeConfig) -> Option<Arc<Resolver>> {
        let dns = &cfg.dns;
        let needed = cfg.role == Role::Gateway || dns.mode == DnsMode::LocalExplicit;
        if !needed {
            return None;
        }
        let key = serde_json_key(dns);
        let mut cache = self
            .resolver_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((k, r)) = cache.as_ref() {
            if *k == key {
                return Some(Arc::clone(r));
            }
        }
        let timeout = Duration::from_millis(u64::from(dns.timeout_ms));
        let allow_v6 = dns.ipv6_policy != Ipv6Policy::Block;
        let resolver = match dns.resolver {
            Some(ResolverKind::System) => Resolver::system(timeout, allow_v6),
            Some(ResolverKind::Explicit) => {
                let servers: Vec<SocketAddr> = dns
                    .nameservers
                    .iter()
                    .filter_map(|s| {
                        s.parse::<SocketAddr>().ok().or_else(|| {
                            s.parse::<std::net::IpAddr>()
                                .ok()
                                .map(|ip| SocketAddr::new(ip, 53))
                        })
                    })
                    .collect();
                // A resolver that cannot be built yields none: domain dials
                // then fail closed rather than fall back to another path.
                Resolver::explicit(&servers, timeout, allow_v6).ok()?
            }
            None => return None,
        };
        let r = Arc::new(resolver);
        *cache = Some((key, Arc::clone(&r)));
        Some(r)
    }

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }
}

fn serde_json_key(dns: &aegis_config::DnsConfig) -> String {
    format!(
        "{:?}|{:?}|{:?}|{:?}|{}",
        dns.mode, dns.ipv6_policy, dns.resolver, dns.nameservers, dns.timeout_ms
    )
}

fn read_secret(dir: &Path, field: &str, r: &Option<String>) -> Result<String, StartError> {
    let r = r
        .as_ref()
        .ok_or_else(|| StartError::Identity(format!("{field} is not configured")))?;
    secret::read(dir, r).map_err(|e| StartError::Identity(format!("{field}: {e}")))
}

fn load_identity(
    cfg: &NodeConfig,
    dir: &Path,
    store: Arc<IdentityStore>,
) -> Result<LoadedIdentity, StartError> {
    let id = &cfg.identity;
    let ie = |e: aegis_identity::IdentityError| StartError::Identity(e.to_string());
    match cfg.role {
        Role::Gateway => {
            let cert = read_secret(dir, "identity.server_identity", &id.server_identity)?;
            let key = read_secret(dir, "identity.server_private_key", &id.server_private_key)?;
            let ca = read_secret(dir, "identity.trusted_client_ca", &id.trusted_client_ca)?;
            let server_tls = aegis_identity::server_config(&cert, &key, &ca, store).map_err(ie)?;
            let ca_bundle = match (&id.ca_certificate, &id.ca_private_key) {
                (Some(_), Some(_)) => Some(CaBundle {
                    cert_pem: read_secret(dir, "identity.ca_certificate", &id.ca_certificate)?,
                    key_pem: read_secret(dir, "identity.ca_private_key", &id.ca_private_key)?,
                }),
                _ => None,
            };
            Ok(LoadedIdentity {
                server_tls: Some(server_tls),
                client_tls: None,
                ca: ca_bundle,
            })
        }
        Role::Client => {
            let cert = read_secret(dir, "identity.client_identity", &id.client_identity)?;
            let key = read_secret(dir, "identity.client_private_key", &id.client_private_key)?;
            let ca = read_secret(dir, "identity.trusted_server_ca", &id.trusted_server_ca)?;
            Ok(LoadedIdentity {
                server_tls: None,
                client_tls: Some(aegis_identity::client_config(&cert, &key, &ca).map_err(ie)?),
                ca: None,
            })
        }
    }
}

pub struct StartOptions {
    pub config: NodeConfig,
    pub store_path: PathBuf,
    pub failpoints: Option<Arc<dyn FailPoints>>,
}

pub struct NodeRuntime {
    pub ctx: Arc<NodeContext>,
    /// Actual bound addresses per inbound id (binds may use port 0).
    pub bound: Vec<(String, SocketAddr)>,
    pub recovery: RecoveryOutcome,
    tasks: Vec<JoinHandle<()>>,
}

impl NodeRuntime {
    pub fn bound_addr(&self, inbound_id: &str) -> Option<SocketAddr> {
        self.bound
            .iter()
            .find(|(i, _)| i == inbound_id)
            .map(|(_, a)| *a)
    }

    /// Graceful stop: close admission, GOAWAY sessions, drain up to `grace`,
    /// then close everything.
    pub async fn shutdown(self, grace: Duration) {
        let ctx = &self.ctx;
        ctx.coord.agent().transition(AgentState::Draining);
        ctx.gate.set_admission(false);
        let _ = ctx.shutdown.send(true);
        ctx.sessions.goaway_all();
        let deadline = tokio::time::Instant::now() + grace;
        while ctx.streams_active.load(Ordering::Relaxed) > 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ctx.sessions.close_all(ResetReason::Shutdown);
        for t in &self.tasks {
            t.abort();
        }
        ctx.coord.agent().transition(AgentState::Stopped);
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> T + Send + 'static,
) -> Result<T, StartError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| StartError::Recovery(e.to_string()))
}

/// Start a node: open the store, recover (or import the file config on
/// first start), load identities, bind listeners from the active revision.
pub async fn start(opts: StartOptions) -> Result<NodeRuntime, StartError> {
    let file_cfg = opts.config;
    let os = OsFamily::current();
    let env = Arc::new(CapabilityEnv::new(
        modules::registry(os),
        aegis_platform::host_vpn_capabilities(os),
    ));
    // Validate the file up front so a bad file fails fast with its errors.
    env.compile(&file_cfg).map_err(StartError::ConfigInvalid)?;
    let store =
        Arc::new(Store::open(&opts.store_path).map_err(|e| StartError::Storage(e.to_string()))?);
    let identity_store = IdentityStore::new(IdentitySnapshot::default());
    let gate = AdmissionGate::new(Arc::clone(&identity_store));
    let agent = Arc::new(AgentCell::default());
    let diagnostics = Arc::new(DiagnosticSink::new());
    let metrics = Arc::new(LocalMetrics::new(Some(Arc::clone(&diagnostics))));
    let coord = Arc::new(Coordinator::new(
        Arc::clone(&store),
        Arc::clone(&gate),
        Arc::clone(&env),
        Arc::clone(&agent),
        file_cfg.node_id.clone(),
        file_cfg.role,
        opts.failpoints.unwrap_or_else(|| Arc::new(NoFailPoints)),
        metrics.clone() as Arc<dyn Observability>,
    ));
    let c = Arc::clone(&coord);
    let mut recovery = blocking(move || c.recover())
        .await?
        .map_err(|e| StartError::Recovery(e.to_string()))?;
    if recovery == RecoveryOutcome::Fresh {
        let c = Arc::clone(&coord);
        let cfg = file_cfg.clone();
        let job = blocking(move || c.import_initial(&cfg))
            .await?
            .map_err(|e| match e {
                aegis_core::CoordinatorError::Invalid(errs) => StartError::ConfigInvalid(errs),
                other => StartError::Recovery(other.to_string()),
            })?;
        if job.status != "succeeded" {
            return Err(StartError::Recovery(format!(
                "initial activation {}",
                job.safe_error_code.unwrap_or_else(|| job.status.clone())
            )));
        }
        recovery = RecoveryOutcome::Restored {
            revision_id: job.result_revision_id.unwrap_or_default(),
        };
    }
    // Listeners and identities come from the active revision.
    let active = gate
        .current()
        .map(|b| b.compiled.config.clone())
        .unwrap_or_else(|| file_cfg.clone());
    if active.node_id != file_cfg.node_id || active.role != file_cfg.role {
        return Err(StartError::ConfigInvalid(vec![
            "stored state belongs to a different node".into(),
        ]));
    }
    let secrets_dir = PathBuf::from(&active.secrets.dir);
    let identity = load_identity(&active, &secrets_dir, Arc::clone(&identity_store))?;
    let budget = Budget::root(active.core.process_buffer_budget_bytes);
    let (shutdown, _) = watch::channel(false);
    let sessions = Arc::new(SessionRegistry::default());
    let mut tunnels = HashMap::new();
    if active.role == Role::Client {
        for ob in &active.outbounds {
            if ob.kind == aegis_config::OutboundKind::AgpTunnel {
                let t = client::Tunnel::new(
                    ob,
                    &active,
                    &secrets_dir,
                    &identity,
                    &budget,
                    metrics.clone(),
                )
                .map_err(StartError::Identity)?;
                tunnels.insert(ob.id.clone(), Arc::new(t));
            }
        }
    }
    let ca = identity.ca.clone();
    let ctx = Arc::new(NodeContext {
        node_id: active.node_id.clone(),
        role: active.role,
        coord: Arc::clone(&coord),
        gate,
        metrics,
        diagnostics,
        budget,
        streams_active: Arc::new(AtomicU64::new(0)),
        sessions: Arc::clone(&sessions),
        secrets_dir,
        startup: active.clone(),
        ca,
        identity,
        tunnels,
        resolver_cache: Mutex::new(None),
        shutdown,
    });
    {
        let sessions = Arc::clone(&sessions);
        coord.set_on_revoke(Arc::new(move |fps| {
            sessions.close_fingerprints(fps, ResetReason::PolicyRevoked)
        }));
    }
    let mut bound = Vec::new();
    let mut tasks = Vec::new();
    for ib in &active.inbounds {
        let listener = tokio::net::TcpListener::bind(&ib.bind)
            .await
            .map_err(|e| StartError::Bind(format!("inbound {}: {}", ib.id, e.kind())))?;
        let addr = listener
            .local_addr()
            .map_err(|e| StartError::Bind(e.to_string()))?;
        bound.push((ib.id.clone(), addr));
        let task = match ib.kind {
            InboundKind::Websocket => {
                tokio::spawn(gateway::serve(Arc::clone(&ctx), ib.clone(), listener))
            }
            InboundKind::Socks5 => {
                let creds = client::socks_credentials(ib, &ctx.secrets_dir)
                    .map_err(StartError::Identity)?;
                tokio::spawn(client::serve_socks(
                    Arc::clone(&ctx),
                    ib.clone(),
                    listener,
                    creds,
                ))
            }
            InboundKind::HttpConnect => {
                let creds =
                    client::http_credentials(ib, &ctx.secrets_dir).map_err(StartError::Identity)?;
                tokio::spawn(client::serve_http(
                    Arc::clone(&ctx),
                    ib.clone(),
                    listener,
                    creds,
                ))
            }
        };
        tasks.push(task);
    }
    Ok(NodeRuntime {
        ctx,
        bound,
        recovery,
        tasks,
    })
}

/// Validate a configuration against this build's installed capabilities
/// without touching the network, the store or any secret.
pub fn validate_offline(cfg: &NodeConfig) -> Result<aegis_config::CompiledConfig, Vec<String>> {
    let os = OsFamily::current();
    CapabilityEnv::new(
        modules::registry(os),
        aegis_platform::host_vpn_capabilities(os),
    )
    .compile(cfg)
}

pub(crate) fn now_unix() -> i64 {
    aegis_storage::now_unix()
}
