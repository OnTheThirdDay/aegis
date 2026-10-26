//! `aegisd` composition root as a library, shared by the binary and the
//! appliance integration tests.
//!
//! Appliance mode (ADR-0007): an empty `--data-dir` is initialized into a
//! complete gateway with an HTTPS web console; see [`appliance`].
#![forbid(unsafe_code)]

pub mod appliance;
pub mod integrations;
pub mod services;

use aegis_management::ManagementContext;
use aegis_node::{start, EdgeRequest, NodeRuntime, StartOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Seed configurations may be TOML or the JSON form the provisioning
/// controller generates.
pub fn parse_config(text: &str) -> Result<aegis_config::NodeConfig, aegis_config::ConfigError> {
    if text.trim_start().starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| aegis_config::ConfigError::Parse(e.to_string()))?;
        aegis_config::parse_json(&v)
    } else {
        aegis_config::parse_toml(text)
    }
}

pub struct Running {
    pub node: NodeRuntime,
    pub mgmt: Option<Arc<ManagementContext>>,
    pub appliance: Option<Arc<services::Appliance>>,
    /// Bound console address (management listener).
    pub console: Option<SocketAddr>,
    stop_tx: tokio::sync::watch::Sender<bool>,
}

impl Running {
    /// Stop the console, then drain the data plane for up to the configured
    /// grace period.
    pub async fn shutdown(self) {
        let _ = self.stop_tx.send(true);
        if let Some(app) = &self.appliance {
            app.integrations.stop().await;
        }
        let grace = u64::from(self.node.ctx.startup.core.shutdown_grace_seconds);
        self.node.shutdown(Duration::from_secs(grace)).await;
    }
}

/// Start the node, its management console and (for an appliance data
/// directory) the appliance services. Errors are stable startup codes.
pub async fn launch(
    cfg: aegis_config::NodeConfig,
    store_path: PathBuf,
    appliance_dir: Option<PathBuf>,
) -> Result<Running, &'static str> {
    let node = start(StartOptions {
        config: cfg,
        store_path,
        failpoints: None,
    })
    .await
    .map_err(|e| e.code())?;
    let ctx = Arc::clone(&node.ctx);
    // The file only locates/seeds the store. Once recovered, every
    // listener and shutdown setting comes from the active revision.
    let cfg = ctx.startup.clone();
    let gauges_ctx = Arc::clone(&ctx);
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut running = Running {
        node,
        mgmt: None,
        appliance: None,
        console: None,
        stop_tx,
    };
    if !cfg.management.enabled {
        return Ok(running);
    }
    let bind: SocketAddr = cfg
        .management
        .bind
        .parse()
        .map_err(|_| "E_CONFIG_INVALID")?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| "E_BIND")?;
    let bound = listener.local_addr().map_err(|_| "E_BIND")?;
    let m = ManagementContext::new(
        Arc::clone(&ctx.coord),
        Arc::clone(&ctx.metrics),
        Arc::new(move || gauges_ctx.gauges()),
        Arc::clone(&ctx.diagnostics),
        ctx.ca.clone(),
        ctx.secrets_dir.clone(),
        bound,
        cfg.management.allowed_hosts.clone(),
    );
    // Set by the installer for --tunnel-only (devices via Cloudflare only).
    m.set_tunnel_only(std::env::var("AEGIS_TUNNEL_ONLY").is_ok_and(|v| v == "1"));
    let reload_ctx = Arc::clone(&ctx);
    *m.certificate_reload
        .lock()
        .unwrap_or_else(|e| e.into_inner()) =
        Some(Arc::new(move || reload_ctx.reload_certificates()));
    if let Some(dir) = &appliance_dir {
        m.set_data_dir(dir.clone());
    }
    let downloads = std::env::var_os("AEGIS_DOWNLOADS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/share/aegisnet/clients"));
    if downloads.is_dir() {
        *m.downloads_dir.lock().unwrap_or_else(|e| e.into_inner()) = Some(downloads);
    }
    let mut rx = stop_rx.clone();
    let stop = async move {
        let _ = rx.wait_for(|s| *s).await;
    };
    match &cfg.management.tls {
        Some(bundle) => {
            let tls = aegis_management::console::ConsoleTls::load(
                ctx.secrets_dir.clone(),
                bundle.clone(),
            )
            .map_err(|_| "E_CONSOLE_TLS")?;
            tokio::spawn(aegis_management::serve_tls(
                Arc::clone(&m),
                listener,
                tls,
                stop,
            ));
        }
        None => {
            tokio::spawn(aegis_management::serve(Arc::clone(&m), listener, stop));
        }
    }
    if cfg.role == aegis_contracts::Role::Gateway {
        // Devices enroll and renew through the public edge, so the console
        // never has to be reachable from the internet.
        let mc = Arc::clone(&m);
        ctx.set_edge_hook(Arc::new(move |request, body| {
            let mc = Arc::clone(&mc);
            Box::pin(async move {
                match request {
                    EdgeRequest::Enroll => aegis_management::edge_enroll(mc, body).await,
                    EdgeRequest::Renew => aegis_management::edge_renew(mc, body).await,
                }
            })
        }));
    }
    if let (Some(dir), aegis_contracts::Role::Gateway) = (&appliance_dir, cfg.role) {
        let app =
            services::Appliance::new(dir.clone(), Arc::clone(ctx.coord.store()), Arc::clone(&ctx))
                .map_err(|_| "E_APPLIANCE")?;
        app.attach(&m);
        *m.appliance.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(app.clone() as Arc<dyn aegis_management::ApplianceServices>);
        app.integrations.resume();
        tokio::spawn(services::maintenance_loop(Arc::clone(&app)));
        tokio::spawn(services::diagnostics_loop(Arc::clone(&app)));
        running.appliance = Some(app);
    }
    running.console = Some(bound);
    running.mgmt = Some(m);
    Ok(running)
}
