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
mod outer_tls;
mod quic;
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
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::{watch, Semaphore};
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

/// Plain HTTP requests the gateway's public edge answers besides the
/// WebSocket upgrade (device enrollment and self-renewal). The handler is
/// installed by the composition root; without one the edge only upgrades.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeRequest {
    Enroll,
    Renew,
}

/// A device request's reply: status, content type, body.
pub type EdgeFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = (u16, &'static str, Vec<u8>)> + Send>>;
pub type EdgeHook = Arc<dyn Fn(EdgeRequest, Vec<u8>) -> EdgeFuture + Send + Sync>;

/// A byte stream handed over by the edge.
pub trait EdgeIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> EdgeIo for T {}

/// Serves a whole HTTP connection whose first request targets `/portal`
/// (the user portal), installed by the composition root. The request bytes
/// already read are replayed at the start of the stream.
pub type PortalHook = Arc<
    dyn Fn(Box<dyn EdgeIo>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Identity material loaded from secrets.
#[derive(Clone)]
pub(crate) struct LoadedIdentity {
    pub server_tls: Option<Arc<rustls::ServerConfig>>,
    pub client_tls: Option<Arc<rustls::ClientConfig>>,
    pub ca: Option<CaBundle>,
    pub trust_digest: String,
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
    pub(crate) identity: RwLock<LoadedIdentity>,
    pub(crate) outer_tls: HashMap<String, Arc<outer_tls::ReloadingTls>>,
    pub(crate) tunnels: Mutex<HashMap<String, Arc<client::Tunnel>>>,
    /// Tunnels replaced by a configuration or certificate change. Their
    /// sessions carry streams that were open at the time; shutdown closes
    /// them too.
    retired_tunnels: Mutex<Vec<std::sync::Weak<client::Tunnel>>>,
    tunnel_update: tokio::sync::Mutex<()>,
    /// Every accepted connection and admitted stream, so shutdown can stop
    /// them all (direct relays have no session to close).
    connections: Mutex<tokio::task::JoinSet<()>>,
    /// QUIC listeners, whose TLS configuration follows certificate reloads.
    quic_endpoints: Mutex<Vec<aegis_transport_quic::Endpoint>>,
    /// Process-wide reservations include authenticated AGP handshakes.
    session_slots: Arc<Semaphore>,
    resolver_cache: Mutex<Option<(String, Arc<Resolver>)>>,
    shutdown: watch::Sender<bool>,
    pub(crate) edge_hook: std::sync::OnceLock<EdgeHook>,
    pub(crate) portal_hook: std::sync::OnceLock<PortalHook>,
}

impl NodeContext {
    /// Install the enrollment/renewal handler for the public edge (once).
    pub fn set_edge_hook(&self, hook: EdgeHook) {
        let _ = self.edge_hook.set(hook);
    }

    /// Install the user-portal handler for `/portal` on the public edge.
    pub fn set_portal_hook(&self, hook: PortalHook) {
        let _ = self.portal_hook.set(hook);
    }

    /// Validate replacements before publishing TLS state. Existing sessions
    /// keep established TLS; future client sessions use the replacement.
    pub fn reload_certificates(&self) -> Result<(), String> {
        let cfg = self
            .gate
            .current()
            .ok_or("configuration_unavailable")?
            .compiled
            .config
            .clone();
        let loaded = load_identity(
            &cfg,
            &self.secrets_dir,
            Arc::clone(self.gate.identity_store()),
        )
        .map_err(|_| "replacement_identity_rejected")?;
        if let Some(tls) = &loaded.server_tls {
            let limits = quic_limits(&cfg);
            for endpoint in self
                .quic_endpoints
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
            {
                aegis_transport_quic::reload(endpoint, tls, &limits)
                    .map_err(|_| "replacement_identity_rejected")?;
            }
        }
        let mut identity = self.identity.write().unwrap_or_else(|e| e.into_inner());
        if identity.trust_digest != loaded.trust_digest {
            self.sessions.close_all(ResetReason::PolicyRevoked);
        }
        *identity = loaded;
        let replaced: Vec<_> = self
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .map(|(_, t)| t)
            .collect();
        self.retire(replaced);
        Ok(())
    }
    pub fn current_ca(&self) -> Option<CaBundle> {
        self.identity
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .ca
            .clone()
    }
    pub fn obs(&self) -> &dyn Observability {
        self.metrics.as_ref()
    }

    /// Authoritative gauges for local status and coarse export.
    pub fn gauges(&self) -> CoreGauges {
        CoreGauges {
            sessions_active: self.sessions.count() as u64
                + self
                    .tunnels
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .filter(|t| t.connected())
                    .count() as u64,
            streams_active: self.streams_active.load(Ordering::Relaxed),
            buffer_receive: self.budget.class_used(PoolClass::Receive),
            buffer_transmit: self.budget.class_used(PoolClass::Transmit),
            buffer_control: self.budget.class_used(PoolClass::Control),
            buffer_total: self.budget.used(),
        }
    }

    /// What carries the client's tunnel now: `quic`, `websocket`, or
    /// `None` while it isn't connected.
    pub fn tunnel_transport(&self) -> Option<&'static str> {
        self.tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .find_map(|t| t.transport())
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
            datagrams: true,
            ..SessionConfig::default()
        }
    }

    /// Select a tunnel from the admitted outbound, never just its ID. Build
    /// replacements off the async workers and retain existing streams on
    /// their old session until they finish. Identity/budget changes still
    /// use the startup values until the documented restart.
    pub(crate) async fn tunnel_for(
        &self,
        outbound: &aegis_config::OutboundConfig,
        cfg: &NodeConfig,
    ) -> Result<Arc<client::Tunnel>, aegis_contracts::reason::OpenFailure> {
        let cached = || {
            self.tunnels
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&outbound.id)
                .filter(|t| t.matches(outbound))
                .cloned()
        };
        if let Some(t) = cached() {
            return Ok(t);
        }
        let _update = self.tunnel_update.lock().await;
        if let Some(t) = cached() {
            return Ok(t);
        }
        let ob = outbound.clone();
        let startup = self.startup.clone();
        let secrets = self.secrets_dir.clone();
        let identity = self
            .identity
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let budget = Arc::clone(&self.budget);
        let metrics = Arc::clone(&self.metrics);
        let tunnel = tokio::task::spawn_blocking(move || {
            client::Tunnel::new(&ob, &startup, &secrets, &identity, &budget, metrics)
        })
        .await
        .map_err(|_| aegis_contracts::reason::OpenFailure::Unavailable)?
        .map_err(|_| aegis_contracts::reason::OpenFailure::Unavailable)?;
        let tunnel = Arc::new(tunnel);
        let mut replaced = Vec::new();
        {
            let mut cache = self.tunnels.lock().unwrap_or_else(|e| e.into_inner());
            cache.retain(|id, t| {
                let keep = cfg
                    .outbounds
                    .iter()
                    .any(|ob| ob.id == *id && ob.kind == aegis_config::OutboundKind::AgpTunnel);
                if !keep {
                    replaced.push(Arc::clone(t));
                }
                keep
            });
            if let Some(old) = cache.insert(outbound.id.clone(), Arc::clone(&tunnel)) {
                replaced.push(old);
            }
        }
        self.retire(replaced);
        Ok(tunnel)
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

    /// Run one connection's (or stream's) task where shutdown can stop it.
    pub(crate) fn spawn_connection<F>(&self, task: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut set = self.connections.lock().unwrap_or_else(|e| e.into_inner());
        while set.try_join_next().is_some() {}
        set.spawn(task);
    }

    /// Keep a replaced tunnel within reach of shutdown.
    fn retire(&self, tunnels: impl IntoIterator<Item = Arc<client::Tunnel>>) {
        let mut retired = self
            .retired_tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        retired.retain(|t| t.strong_count() > 0);
        retired.extend(tunnels.into_iter().map(|t| Arc::downgrade(&t)));
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
    let material = |cert: &Option<String>,
                    key: &Option<String>,
                    bundle: &Option<String>|
     -> Result<(String, String), StartError> {
        if let Some(bundle) = bundle {
            let text = secret::read(dir, bundle)
                .map_err(|_| StartError::Identity("identity bundle unavailable".into()))?;
            let manifest: outer_tls::Bundle = serde_json::from_str(&text)
                .map_err(|_| StartError::Identity("identity bundle invalid".into()))?;
            Ok((
                secret::read(dir, &manifest.certificate)
                    .map_err(|_| StartError::Identity("certificate unavailable".into()))?,
                secret::read(dir, &manifest.private_key)
                    .map_err(|_| StartError::Identity("key unavailable".into()))?,
            ))
        } else {
            Ok((
                read_secret(dir, "identity.certificate", cert)?,
                read_secret(dir, "identity.private_key", key)?,
            ))
        }
    };
    let validate_leaf = |cert: &str| -> Result<(), StartError> {
        let certs = aegis_identity::tls::parse_certs(cert).map_err(ie)?;
        let peer = aegis_identity::PeerIdentity::from_der(certs[0].as_ref()).map_err(ie)?;
        if peer.node_id != cfg.node_id
            || peer.role != Some(cfg.role)
            || peer.is_expired_at(now_unix())
        {
            return Err(StartError::Identity(
                "local certificate identity or validity rejected".into(),
            ));
        }
        Ok(())
    };
    match cfg.role {
        Role::Gateway => {
            let (cert, key) = material(
                &id.server_identity,
                &id.server_private_key,
                &id.material_bundle,
            )?;
            validate_leaf(&cert)?;
            let ca = read_secret(dir, "identity.trusted_client_ca", &id.trusted_client_ca)?;
            let server_tls = aegis_identity::server_config(&cert, &key, &ca, store).map_err(ie)?;
            let ca_bundle = if id.issuer_bundle.is_some() {
                let (cert_pem, key_pem) = material(&None, &None, &id.issuer_bundle)?;
                Some(CaBundle { cert_pem, key_pem })
            } else {
                match (&id.ca_certificate, &id.ca_private_key) {
                    (Some(_), Some(_)) => Some(CaBundle {
                        cert_pem: read_secret(dir, "identity.ca_certificate", &id.ca_certificate)?,
                        key_pem: read_secret(dir, "identity.ca_private_key", &id.ca_private_key)?,
                    }),
                    _ => None,
                }
            };
            if let Some(ca) = &ca_bundle {
                aegis_identity::pki::validate_issuer(ca).map_err(ie)?;
            }
            Ok(LoadedIdentity {
                server_tls: Some(server_tls),
                client_tls: None,
                ca: ca_bundle,
                trust_digest: aegis_storage::sha256_hex(ca.as_bytes()),
            })
        }
        Role::Client => {
            let (cert, key) = material(
                &id.client_identity,
                &id.client_private_key,
                &id.material_bundle,
            )?;
            validate_leaf(&cert)?;
            let ca = read_secret(dir, "identity.trusted_server_ca", &id.trusted_server_ca)?;
            Ok(LoadedIdentity {
                server_tls: None,
                client_tls: Some(aegis_identity::client_config(&cert, &key, &ca).map_err(ie)?),
                ca: None,
                trust_digest: aegis_storage::sha256_hex(ca.as_bytes()),
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
        // Client side: outbound tunnels drain and close like inbound sessions.
        let tunnels: Vec<Arc<client::Tunnel>> = ctx
            .tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for t in &tunnels {
            t.goaway().await;
        }
        let deadline = tokio::time::Instant::now() + grace;
        while ctx.streams_active.load(Ordering::Relaxed) > 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ctx.sessions.close_all(ResetReason::Shutdown);
        let retired: Vec<_> = ctx
            .retired_tunnels
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .filter_map(|t| t.upgrade())
            .collect();
        for t in tunnels.iter().chain(&retired) {
            t.close(ResetReason::Shutdown).await;
        }
        for t in &self.tasks {
            t.abort();
        }
        // Wait until the aborted tasks are gone, so their listeners are
        // closed (and the ports free) when shutdown returns.
        for t in self.tasks {
            let _ = t.await;
        }
        // Then stop every connection still running (direct relays, streams
        // of replaced tunnels): nothing forwards once shutdown returns.
        let mut connections =
            std::mem::take(&mut *ctx.connections.lock().unwrap_or_else(|e| e.into_inner()));
        connections.shutdown().await;
        // QUIC listeners: quinn closes the UDP socket once its last handle
        // is gone and its driver notices, so wait (bounded) until the port
        // can be bound again: it is free when shutdown returns, as for TCP.
        let endpoints =
            std::mem::take(&mut *ctx.quic_endpoints.lock().unwrap_or_else(|e| e.into_inner()));
        let addrs: Vec<SocketAddr> = endpoints
            .iter()
            .filter_map(|e| e.local_addr().ok())
            .collect();
        for e in &endpoints {
            e.close(0u32.into(), b"shutdown");
            let _ = tokio::time::timeout(Duration::from_secs(1), e.wait_idle()).await;
        }
        drop(endpoints);
        for addr in addrs {
            for _ in 0..100 {
                if std::net::UdpSocket::bind(addr).is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
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
    start_with_diagnostics(opts, Arc::new(DiagnosticSink::new())).await
}

/// [`start`] with a caller-owned diagnostics recorder, so a recording can
/// span several node lifetimes (the client app reconnecting).
pub async fn start_with_diagnostics(
    opts: StartOptions,
    diagnostics: Arc<DiagnosticSink>,
) -> Result<NodeRuntime, StartError> {
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
    let mut outer_tls = HashMap::new();
    for inbound in &active.inbounds {
        if let Some(settings) = &inbound.outer_tls {
            outer_tls.insert(
                inbound.id.clone(),
                outer_tls::ReloadingTls::new(secrets_dir.clone(), settings.clone())
                    .map_err(StartError::Identity)?,
            );
        }
    }
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
        identity: RwLock::new(identity),
        outer_tls,
        tunnels: Mutex::new(tunnels),
        retired_tunnels: Mutex::new(Vec::new()),
        tunnel_update: tokio::sync::Mutex::new(()),
        connections: Mutex::new(tokio::task::JoinSet::new()),
        quic_endpoints: Mutex::new(Vec::new()),
        session_slots: Arc::new(Semaphore::new(active.core.max_sessions as usize)),
        resolver_cache: Mutex::new(None),
        shutdown,
        edge_hook: std::sync::OnceLock::new(),
        portal_hook: std::sync::OnceLock::new(),
    });
    {
        let sessions = Arc::clone(&sessions);
        coord.set_on_revoke(Arc::new(move |fps| {
            sessions.close_fingerprints(fps, ResetReason::PolicyRevoked)
        }));
    }
    // Bind every listener and read every credential before serving any:
    // a startup that fails part way must leave nothing listening.
    enum Serve {
        Websocket(tokio::net::TcpListener),
        Socks(
            tokio::net::TcpListener,
            Option<aegis_inbound_socks::Credentials>,
        ),
        Http(
            tokio::net::TcpListener,
            Option<aegis_inbound_http::Credentials>,
        ),
        Quic(aegis_transport_quic::Endpoint),
    }
    let mut ready = Vec::new();
    for ib in &active.inbounds {
        if ib.kind == InboundKind::Quic {
            let bind = ib
                .bind
                .parse()
                .map_err(|_| StartError::Bind(format!("inbound {}: bind", ib.id)))?;
            let tls = ctx
                .identity
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .server_tls
                .clone()
                .ok_or_else(|| StartError::Identity("quic needs the gateway identity".into()))?;
            let endpoint = aegis_transport_quic::server(bind, &tls, &quic_limits(&active))
                .map_err(|e| StartError::Bind(format!("inbound {}: {e}", ib.id)))?;
            let addr = endpoint
                .local_addr()
                .map_err(|e| StartError::Bind(e.to_string()))?;
            ready.push((ib, addr, Serve::Quic(endpoint)));
            continue;
        }
        enum Creds {
            None,
            Socks(Option<aegis_inbound_socks::Credentials>),
            Http(Option<aegis_inbound_http::Credentials>),
        }
        let creds = match ib.kind {
            InboundKind::Websocket | InboundKind::Quic => Creds::None,
            InboundKind::Socks5 => Creds::Socks(
                client::socks_credentials(ib, &ctx.secrets_dir).map_err(StartError::Identity)?,
            ),
            InboundKind::HttpConnect => Creds::Http(
                client::http_credentials(ib, &ctx.secrets_dir).map_err(StartError::Identity)?,
            ),
        };
        let listener = tokio::net::TcpListener::bind(&ib.bind)
            .await
            .map_err(|e| StartError::Bind(format!("inbound {}: {}", ib.id, e.kind())))?;
        let addr = listener
            .local_addr()
            .map_err(|e| StartError::Bind(e.to_string()))?;
        let serve = match creds {
            Creds::None => Serve::Websocket(listener),
            Creds::Socks(c) => Serve::Socks(listener, c),
            Creds::Http(c) => Serve::Http(listener, c),
        };
        ready.push((ib, addr, serve));
    }
    let mut bound = Vec::new();
    let mut tasks = Vec::new();
    for (ib, addr, serve) in ready {
        bound.push((ib.id.clone(), addr));
        let ctx = Arc::clone(&ctx);
        tasks.push(match serve {
            Serve::Websocket(l) => tokio::spawn(gateway::serve(ctx, ib.clone(), l)),
            Serve::Socks(l, creds) => tokio::spawn(client::serve_socks(ctx, ib.clone(), l, creds)),
            Serve::Http(l, creds) => tokio::spawn(client::serve_http(ctx, ib.clone(), l, creds)),
            Serve::Quic(endpoint) => {
                ctx.quic_endpoints
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(endpoint.clone());
                tokio::spawn(gateway::serve_quic(ctx, ib.clone(), endpoint))
            }
        });
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

/// QUIC connection limits from the node's core settings.
pub(crate) fn quic_limits(cfg: &NodeConfig) -> aegis_transport_quic::Limits {
    let keepalive = u64::from(cfg.core.keepalive_interval_seconds).clamp(5, 15);
    aegis_transport_quic::Limits {
        keepalive: Duration::from_secs(keepalive),
        idle_timeout: Duration::from_secs(keepalive * 4),
        ..aegis_transport_quic::Limits::default()
    }
}

pub(crate) fn now_unix() -> i64 {
    aegis_storage::now_unix()
}

#[cfg(test)]
mod capacity_tests {
    /// Browsers open connections in bursts; the default limits must leave
    /// ample room on one session, within the per-peer budget (session window
    /// plus each stream's initial transmit reservation).
    #[test]
    fn default_session_carries_a_browser() {
        let core = aegis_config::CoreConfig::default();
        let cfg = aegis_session::SessionConfig {
            max_streams: core.max_streams_per_session,
            stream_window: core.stream_buffer_budget_bytes,
            session_window: core.session_window_bytes,
            stream_tx_buffer: core.stream_buffer_budget_bytes,
            ..aegis_session::SessionConfig::default()
        };
        let streams = cfg.effective_max_streams(core.session_window_bytes);
        assert!(
            streams >= 400,
            "only {streams} concurrent connections per session"
        );
        // UDP flows' datagram buffers come out of the same peer budget.
        let needed = u64::from(core.session_window_bytes)
            + u64::from(streams) * u64::from(cfg.initial_stream_window)
            + u64::from(cfg.datagram_recv_buffer)
            + u64::from(cfg.datagram_send_buffer);
        assert!(
            needed <= core.peer_buffer_budget_bytes,
            "peer budget too small: {needed}"
        );
        assert!(core.peer_buffer_budget_bytes <= core.process_buffer_budget_bytes);
    }
}
