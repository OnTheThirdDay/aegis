//! Local management plane (04).
//!
//! * Loopback-only REST API at `/api/v1` implementing
//!   `schemas/management.openapi.yaml`, plus the static admin UI.
//! * Owner bootstrap via a one-use local token, Argon2id passwords, cookie
//!   sessions with CSRF tokens, short-lived bearer tokens minted over local
//!   IPC, server-side RBAC on every operation.
//! * Strong ETags (`If-Match`, 428/412), `Idempotency-Key` for async jobs,
//!   RFC 9457 problem details, bounded cursor pagination.
//! * No permissive CORS; Host and Origin allowlists; strict CSP.
//!
//! This crate depends on the core/config facades, never on data-plane
//! internals (A-002).
#![forbid(unsafe_code)]

mod auth;
pub mod console;
mod cursor;
mod handlers;
mod http_util;
pub mod ipc;
mod ui;

pub use auth::{hash_password, Permission, Principal, ROLE_OWNER};
pub use handlers::edge::{edge_enroll, edge_renew};

use aegis_core::Coordinator;
use aegis_identity::pki::CaBundle;
use aegis_telemetry::{CoarseExporter, CoreGauges, DiagnosticSink, LocalMetrics};
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub type GaugeFn = Arc<dyn Fn() -> CoreGauges + Send + Sync>;
pub type ReloadFn = Arc<dyn Fn() -> Result<(), String> + Send + Sync>;
pub type IntegrationFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<serde_json::Value, (u16, String)>> + Send>,
>;

pub struct ManagementContext {
    pub coord: Arc<Coordinator>,
    pub metrics: Arc<LocalMetrics>,
    pub gauges: GaugeFn,
    pub diagnostics: Arc<DiagnosticSink>,
    /// Device diagnostic reports received while diagnostics are on.
    pub device_reports: aegis_telemetry::ReportStore,
    /// Local CA for enrollment (gateway only).
    pub ca: Option<CaBundle>,
    pub secrets_dir: PathBuf,
    /// Listener address; Host/Origin allowlists derive from it.
    pub bind: SocketAddr,
    pub extra_allowed_hosts: Vec<String>,
    pub(crate) auth: auth::AuthState,
    pub(crate) cursor_key: [u8; 32],
    pub(crate) exporter: Mutex<Option<CoarseExporter>>,
    pub provisioning: aegis_provision::Controller,
    pub provision_executor: Mutex<Option<Arc<dyn aegis_provision::Executor>>>,
    pub certificate_reload: Mutex<Option<ReloadFn>>,
    /// Appliance data directory (ADR-0007); `None` for hand-configured nodes.
    data_dir: Mutex<Option<PathBuf>>,
    /// HTTPS console reachable beyond loopback: Host may be any address the
    /// operator uses, and Origin must then equal `https://<Host>`.
    remote_console: AtomicBool,
    /// Installed with `--tunnel-only`: the device port is not reachable from
    /// the network, so devices can only use Cloudflare Tunnel.
    tunnel_only: AtomicBool,
    pub(crate) console_tls: Mutex<Option<Arc<console::ConsoleTls>>>,
    /// Appliance services (integrations, certificate lifecycle) installed by
    /// the composition root; absent on hand-configured nodes.
    pub appliance: Mutex<Option<Arc<dyn ApplianceServices>>>,
    /// Directory of client app builds offered to signed-in users.
    pub downloads_dir: Mutex<Option<PathBuf>>,
    pub(crate) download_digests: Mutex<std::collections::HashMap<String, (u64, String)>>,
}

/// Hooks the composition root (aegisd) provides in appliance mode. The
/// management crate never gains data-plane or host authority itself.
pub trait ApplianceServices: Send + Sync {
    /// Secret-free status of integrations and runtime pieces for the console.
    fn status(&self) -> serde_json::Value;
    /// Re-issue web certificates for changed public addresses and reload.
    fn set_public_addresses(
        &self,
        names: &[String],
        ips: &[std::net::IpAddr],
    ) -> Result<(), String>;
    /// Integration requests (Cloudflare, ACME) routed by integration id.
    fn integration(
        &self,
        id: &str,
        action: &str,
        actor: &str,
        body: serde_json::Value,
    ) -> IntegrationFuture;
    /// Device CA custody (blocking): `export-root-key`, `remove-root-key`,
    /// `restore-root-key`, `renew-issuer`. Callers check the permission and,
    /// for an export, the password.
    fn device_ca(
        &self,
        _action: &str,
        _actor: &str,
        _body: serde_json::Value,
    ) -> Result<serde_json::Value, (u16, String)> {
        Err((404, "unsupported".into()))
    }
}

impl ManagementContext {
    pub(crate) fn enrollment_ca(&self) -> Result<Option<CaBundle>, http_util::ApiError> {
        if let Some(bundle) = self.coord.gate().current() {
            if let Some(reference) = &bundle.compiled.config.identity.issuer_bundle {
                let read = |r: &str| {
                    aegis_config::secret::read(&self.secrets_dir, r)
                        .map_err(|_| http_util::ApiError::conflict("enrollment_ca_unavailable"))
                };
                let manifest: serde_json::Value = serde_json::from_str(&read(reference)?)
                    .map_err(|_| http_util::ApiError::conflict("issuer_manifest_invalid"))?;
                let ca = CaBundle {
                    cert_pem: read(manifest["certificate"].as_str().ok_or_else(|| {
                        http_util::ApiError::conflict("issuer_manifest_invalid")
                    })?)?,
                    key_pem: read(manifest["private_key"].as_str().ok_or_else(|| {
                        http_util::ApiError::conflict("issuer_manifest_invalid")
                    })?)?,
                };
                aegis_identity::pki::validate_issuer(&ca)
                    .map_err(|_| http_util::ApiError::conflict("issuer_rejected"))?;
                return Ok(Some(ca));
            }
        }
        Ok(self.ca.clone())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coord: Arc<Coordinator>,
        metrics: Arc<LocalMetrics>,
        gauges: GaugeFn,
        diagnostics: Arc<DiagnosticSink>,
        ca: Option<CaBundle>,
        secrets_dir: PathBuf,
        bind: SocketAddr,
        extra_allowed_hosts: Vec<String>,
    ) -> Arc<Self> {
        let mut cursor_key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cursor_key);
        let ctx = Arc::new(ManagementContext {
            provisioning: aegis_provision::Controller::new(Arc::clone(coord.store())),
            provision_executor: Mutex::new(None),
            certificate_reload: Mutex::new(None),
            data_dir: Mutex::new(None),
            remote_console: AtomicBool::new(false),
            tunnel_only: AtomicBool::new(false),
            console_tls: Mutex::new(None),
            appliance: Mutex::new(None),
            downloads_dir: Mutex::new(None),
            download_digests: Mutex::new(std::collections::HashMap::new()),
            coord,
            metrics,
            gauges,
            diagnostics,
            device_reports: aegis_telemetry::ReportStore::default(),
            ca,
            secrets_dir,
            bind,
            extra_allowed_hosts,
            auth: auth::AuthState::default(),
            cursor_key,
            exporter: Mutex::new(None),
        });
        // Re-apply persisted, previously approved export settings. Export
        // is never enabled implicitly.
        handlers::telemetry::apply_persisted(&ctx);
        ctx
    }

    pub fn set_data_dir(&self, dir: PathBuf) {
        *self.data_dir.lock().unwrap_or_else(|e| e.into_inner()) = Some(dir);
    }

    pub fn data_dir(&self) -> Option<PathBuf> {
        self.data_dir
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_tunnel_only(&self, on: bool) {
        self.tunnel_only.store(on, Ordering::Relaxed);
    }

    pub fn tunnel_only(&self) -> bool {
        self.tunnel_only.load(Ordering::Relaxed)
    }

    pub(crate) fn remote_console(&self) -> bool {
        self.remote_console.load(Ordering::Relaxed)
    }

    pub fn appliance(&self) -> Option<Arc<dyn ApplianceServices>> {
        self.appliance
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn console_fingerprint(&self) -> Option<String> {
        self.console_tls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|t| t.fingerprint())
    }

    /// Reload the console certificate after a replacement was written.
    pub fn reload_console_tls(&self) -> Result<(), String> {
        match self
            .console_tls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            Some(t) => t.reload(),
            None => Ok(()),
        }
    }

    /// Hosts accepted in `Host` (and `Origin` as `http://<host>`).
    pub(crate) fn allowed_hosts(&self) -> Vec<String> {
        let port = self.bind.port();
        let mut hosts = vec![
            format!("127.0.0.1:{port}"),
            format!("localhost:{port}"),
            format!("[::1]:{port}"),
            match self.bind {
                SocketAddr::V4(a) => format!("{}:{port}", a.ip()),
                SocketAddr::V6(a) => format!("[{}]:{port}", a.ip()),
            },
        ];
        hosts.extend(self.extra_allowed_hosts.iter().cloned());
        hosts.sort();
        hosts.dedup();
        hosts
    }
}

/// Build the router (API + UI) with all guards applied.
pub fn router(ctx: Arc<ManagementContext>) -> Router {
    handlers::routes(Arc::clone(&ctx))
        .merge(ui::routes())
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&ctx),
            http_util::guard,
        ))
        .with_state(ctx)
}

/// Serve HTTPS on an already-bound listener until `shutdown` resolves.
pub async fn serve_tls(
    ctx: Arc<ManagementContext>,
    listener: tokio::net::TcpListener,
    tls: Arc<console::ConsoleTls>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    if !ctx.bind.ip().is_loopback() {
        ctx.remote_console.store(true, Ordering::Relaxed);
    }
    *ctx.console_tls.lock().unwrap_or_else(|e| e.into_inner()) = Some(Arc::clone(&tls));
    let listener = console::tls_listener(listener, tls)?;
    axum::serve(listener, router(ctx))
        .with_graceful_shutdown(shutdown)
        .await
}

/// Serve on an already-bound listener until `shutdown` resolves.
pub async fn serve(
    ctx: Arc<ManagementContext>,
    listener: tokio::net::TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, router(ctx))
        .with_graceful_shutdown(shutdown)
        .await
}

#[cfg(test)]
mod test_support {
    use super::*;
    use aegis_contracts::capability::OsFamily;
    use aegis_contracts::observability::NoopObservability;
    use aegis_contracts::Role;
    use aegis_core::{AdmissionGate, AgentCell, CapabilityEnv, NoFailPoints};
    use aegis_identity::{IdentitySnapshot, IdentityStore};
    use aegis_storage::Store;

    pub fn context(store: Arc<Store>) -> Arc<ManagementContext> {
        let os = OsFamily::current();
        let coord = Arc::new(Coordinator::new(
            store,
            AdmissionGate::new(IdentityStore::new(IdentitySnapshot::default())),
            Arc::new(CapabilityEnv::new(
                aegis_platform::Registry::new(os),
                aegis_platform::host_vpn_capabilities(os),
            )),
            Arc::new(AgentCell::default()),
            "management-test".into(),
            Role::Gateway,
            Arc::new(NoFailPoints),
            Arc::new(NoopObservability),
        ));
        ManagementContext::new(
            coord,
            Arc::new(LocalMetrics::new(None)),
            Arc::new(CoreGauges::default),
            Arc::new(DiagnosticSink::new()),
            None,
            PathBuf::new(),
            "127.0.0.1:9080".parse().expect("bind"),
            Vec::new(),
        )
    }

    pub fn insert_owner(store: &Store) {
        store
            .tx(|c| {
                aegis_storage::insert_principal(
                    c,
                    &aegis_storage::PrincipalRow {
                        id: "test-owner".into(),
                        username: "owner".into(),
                        password_hash: "unused".into(),
                        status: "active".into(),
                        roles: vec![ROLE_OWNER.into()],
                    },
                )
            })
            .expect("insert owner");
    }
}
