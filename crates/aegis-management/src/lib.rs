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
mod cursor;
mod handlers;
mod http_util;
pub mod ipc;
mod ui;

pub use auth::{Permission, Principal, ROLE_OWNER};

use aegis_core::Coordinator;
use aegis_identity::pki::CaBundle;
use aegis_telemetry::{CoarseExporter, CoreGauges, DiagnosticSink, LocalMetrics};
use axum::Router;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub type GaugeFn = Arc<dyn Fn() -> CoreGauges + Send + Sync>;

pub struct ManagementContext {
    pub coord: Arc<Coordinator>,
    pub metrics: Arc<LocalMetrics>,
    pub gauges: GaugeFn,
    pub diagnostics: Arc<DiagnosticSink>,
    /// Local CA for enrollment (gateway only).
    pub ca: Option<CaBundle>,
    pub secrets_dir: PathBuf,
    /// Listener address; Host/Origin allowlists derive from it.
    pub bind: SocketAddr,
    pub extra_allowed_hosts: Vec<String>,
    pub(crate) auth: auth::AuthState,
    pub(crate) cursor_key: [u8; 32],
    pub(crate) exporter: Mutex<Option<CoarseExporter>>,
}

impl ManagementContext {
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
            coord,
            metrics,
            gauges,
            diagnostics,
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
