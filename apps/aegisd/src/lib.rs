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
    console_task: Option<tokio::task::JoinHandle<()>>,
    stop_tx: tokio::sync::watch::Sender<bool>,
}

impl Running {
    /// Stop the console, then drain the data plane for up to the configured
    /// grace period.
    pub async fn shutdown(self) {
        let _ = self.stop_tx.send(true);
        // Wait for the console to close its listener (bounded: open
        // keep-alive connections are cut after 5 s).
        if let Some(task) = self.console_task {
            let abort = task.abort_handle();
            if tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .is_err()
            {
                abort.abort();
            }
        }
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
    let seed = StartOptions {
        config: cfg.clone(),
        store_path: store_path.clone(),
        failpoints: None,
    };
    let mut node = start(seed).await.map_err(|e| e.code())?;
    // Listeners and session limits are read at start: after upgrading the
    // stored profile, start again (once; nothing is connected yet).
    let mut upgraded = false;
    if appliance_dir.is_some() {
        for (name, plan) in PROFILE_UPGRADES {
            upgraded |= upgrade_profile(&node.ctx.coord, name, *plan).await;
        }
    }
    if upgraded {
        node.shutdown(Duration::from_secs(1)).await;
        node = start(StartOptions {
            config: cfg,
            store_path,
            failpoints: None,
        })
        .await
        .map_err(|e| e.code())?;
    }
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
        console_task: None,
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
    let m2 = Arc::clone(&m);
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
            running.console_task = Some(tokio::spawn(async move {
                let _ = aegis_management::serve_tls(Arc::clone(&m2), listener, tls, stop).await;
            }));
        }
        None => {
            running.console_task = Some(tokio::spawn(async move {
                let _ = aegis_management::serve(Arc::clone(&m2), listener, stop).await;
            }));
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
        // Users sign in to the self-service portal on the same public edge.
        let portal = aegis_management::portal::Server::new(Arc::clone(&m));
        ctx.set_portal_hook(Arc::new(move |io| {
            Box::pin(portal.clone().serve_connection(io))
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

/// Limits stored by appliances set up before 0.2: a 2 MiB session window
/// with fixed 64 KiB streams allows only 31 concurrent connections per
/// device, which a browser exhausts, so pages stall until old connections
/// close.
const LEGACY_SESSION_LIMITS: [(&str, u64); 5] = [
    ("max_streams_per_session", 64),
    ("stream_buffer_budget_bytes", 64 * 1024),
    ("session_window_bytes", 2 * 1024 * 1024),
    ("peer_buffer_budget_bytes", 8 * 1024 * 1024),
    ("process_buffer_budget_bytes", 32 * 1024 * 1024),
];

/// Changes appliances set up by older versions get once: each plan returns
/// a merge patch for the active profile, or `None` when it doesn't apply.
type UpgradePlan = fn(&serde_json::Value) -> Option<serde_json::Value>;
const PROFILE_UPGRADES: &[(&str, UpgradePlan)] = &[
    ("session-limits-upgrade", session_limits_plan),
    ("quic-inbound-upgrade", quic_inbound_plan),
];

/// Session limits to the current defaults, only while all of them still
/// hold the legacy values (anything an operator changed is left alone).
fn session_limits_plan(spec: &serde_json::Value) -> Option<serde_json::Value> {
    let legacy = LEGACY_SESSION_LIMITS
        .iter()
        .all(|(k, v)| spec["core"][*k].as_u64() == Some(*v));
    if !legacy {
        return None;
    }
    let d = aegis_config::CoreConfig::default();
    Some(serde_json::json!({"core": {
        "max_streams_per_session": d.max_streams_per_session,
        "stream_buffer_budget_bytes": d.stream_buffer_budget_bytes,
        "session_window_bytes": d.session_window_bytes,
        "peer_buffer_budget_bytes": d.peer_buffer_budget_bytes,
        "process_buffer_budget_bytes": d.process_buffer_budget_bytes,
    }}))
}

/// A QUIC listener on the device port number, for profiles from before
/// QUIC existed. It is reachable only once the installer publishes the UDP
/// port, and used only once an administrator turns QUIC on.
fn quic_inbound_plan(spec: &serde_json::Value) -> Option<serde_json::Value> {
    let inbounds = spec["inbounds"].as_array()?;
    if inbounds.iter().any(|i| i["kind"] == "quic") {
        return None;
    }
    let edge = inbounds.iter().find(|i| i["id"] == "edge")?;
    let port = edge["bind"]
        .as_str()?
        .parse::<std::net::SocketAddr>()
        .ok()?
        .port();
    let mut next = inbounds.clone();
    next.push(serde_json::json!({
        "id": "quic",
        "kind": "quic",
        "bind": format!("0.0.0.0:{port}"),
    }));
    Some(serde_json::json!({ "inbounds": next }))
}

/// Apply one upgrade plan to the active profile. Returns whether a new
/// revision was activated; it applies from the next start.
async fn upgrade_profile(
    coord: &Arc<aegis_core::Coordinator>,
    name: &'static str,
    plan: UpgradePlan,
) -> bool {
    let coord = Arc::clone(coord);
    tokio::task::spawn_blocking(move || -> Option<bool> {
        let runtime = coord.health().runtime_revision_id?;
        let profile = coord
            .store()
            .read(|c| aegis_storage::list_profiles(c, None, 100))
            .ok()?
            .into_iter()
            .find(|p| p.active_revision_id.as_deref() == Some(runtime.as_str()))?;
        let revision = coord
            .store()
            .read(|c| aegis_storage::get_revision(c, &runtime))
            .ok()?;
        let spec: serde_json::Value = serde_json::from_str(&revision.spec_json).ok()?;
        let Some(patch) = plan(&spec) else {
            return Some(false);
        };
        let patched = coord
            .patch_profile(None, &profile.id, &profile.etag(), None, Some(&patch))
            .ok()?;
        let report = coord
            .validate(
                None,
                &patched.id,
                &patched.etag(),
                &patched.desired_revision_id,
            )
            .ok()?;
        if !report.valid {
            return Some(false);
        }
        let req = aegis_core::ActivateRequest {
            actor_id: None,
            profile_id: patched.id.clone(),
            if_match: patched.etag(),
            idempotency_key: format!("{name}-{}", report.target_revision_id),
            target_revision_id: report.target_revision_id.clone(),
            config_digest: report.config_digest.clone(),
            validation_id: report.validation_id.clone(),
        };
        let job = coord
            .submit_activation(&req, &format!("/api/v1/profiles/{}/activate", patched.id))
            .ok()?;
        let job = coord.run_job(&job.id).ok()?;
        Some(job.status == "succeeded")
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_profiles_get_a_quic_listener_on_the_device_port_once() {
        let spec = serde_json::json!({"inbounds": [
            {"id": "edge", "kind": "websocket", "bind": "0.0.0.0:8444"},
            {"id": "tunnel-origin", "kind": "websocket", "bind": "127.0.0.1:18080"},
        ]});
        let patch = quic_inbound_plan(&spec).expect("planned");
        let inbounds = patch["inbounds"].as_array().expect("inbounds");
        assert_eq!(inbounds.len(), 3, "existing inbounds are kept");
        assert_eq!(inbounds[2]["kind"], "quic");
        assert_eq!(inbounds[2]["bind"], "0.0.0.0:8444");
        // Already there: nothing to do.
        assert!(quic_inbound_plan(&patch).is_none());
        // No edge to take the port from: left alone.
        assert!(quic_inbound_plan(&serde_json::json!({"inbounds": []})).is_none());
    }
}
