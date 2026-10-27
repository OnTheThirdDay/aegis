//! Cloudflare Tunnel, fully driven from the console (SPEC-12 §7, ADR-0007).
//!
//! The durable saga (`aegis_provision::Controller`) and the Cloudflare API
//! adapter are shared with the CLI/Compose path; this module supplies the
//! embedded host provisioner (bundled connector supervised in-process) and
//! the end-to-end probe.
//!
//! Credentials: the API token lives in memory for one operation and is
//! zeroized afterwards, unless the owner explicitly asks to keep it (for
//! DNS-validated certificate renewals), in which case it is stored in an
//! owner-only secret file. The connector token is written to an owner-only
//! file read by `cloudflared --token-file`.

use super::connector::{self, Connector};
use super::{probe, ActionResult};
use crate::appliance;
use crate::services::Appliance;
use aegis_provision::cloudflare::Cloudflare;
use aegis_provision::{
    Controller, DesiredDeployment, Error, HostKind, HostProvisioner, Mode, Plan, PlanState, Probe,
    StepFuture, Verification,
};
use aegis_storage as db;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use zeroize::Zeroizing;

pub const ID: &str = "cloudflare";
/// Plans are owned by the appliance; the console user is audited separately.
const PLAN_ACTOR: &str = "appliance";
const TOKEN_FILE: &str = "cloudflared-token";
pub const API_TOKEN_FILE: &str = "cloudflare-api-token";

#[derive(Default, Clone)]
struct Live {
    busy: bool,
    step: Option<String>,
}

pub struct CloudflareIntegration {
    app: Weak<Appliance>,
    pub connector: Arc<Connector>,
    live: Mutex<Live>,
    unavailable: Option<String>,
}

fn err(status: u16, code: impl Into<String>) -> (u16, String) {
    (status, code.into())
}

fn provider_error(e: Error) -> (u16, String) {
    let status = match e.0 {
        "cloudflare_insufficient_permissions" | "invalid_cloudflare_token" => 403,
        "cloudflare_rate_limited_retry_later" => 429,
        "cloudflare_network_or_tls_failure" | "cloudflare_temporarily_unavailable" => 502,
        _ => 409,
    };
    (status, explain(e.0))
}

/// Version of the tunnel routes AegisNet writes; 2 adds the user portal.
const ROUTES_VERSION: u64 = 2;

/// Human-readable, secret-free explanation of a provider/saga error code.
pub fn explain(code: &str) -> String {
    let text = match code {
        "cloudflare_insufficient_permissions" => "Cloudflare rejected the token or it lacks a required permission (Account · Cloudflare Tunnel · Edit, Zone · DNS · Edit, Zone · Zone · Read)",
        "invalid_cloudflare_token" => "That does not look like a Cloudflare API token",
        "cloudflare_rate_limited_retry_later" => "Cloudflare is rate limiting requests; try again in a minute",
        "cloudflare_network_or_tls_failure" => "Could not reach api.cloudflare.com from the server",
        "cloudflare_temporarily_unavailable" => "Cloudflare's API is temporarily unavailable",
        "dns_record_not_owned" => "A DNS record for this name already exists and was not created by AegisNet; choose another name or remove it yourself",
        "hostname_outside_free_edge_certificate_scope" => "Use the domain itself or a single-level subdomain (Cloudflare's free certificate covers *.domain only)",
        "cloudflare_zone_account_mismatch" => "The domain is not active in that Cloudflare account",
        "tunnel_create_outcome_unknown_requires_ownership_review" => "A tunnel with this AegisNet name already exists; remove it in Cloudflare or disconnect first",
        "tunnel_ingress_drift_requires_review" => "The tunnel's routes were changed outside AegisNet",
        "cloudflare_connector_not_healthy" => "The connector did not report healthy to Cloudflare in time",
        "connector_not_ready" => "The connector could not connect to Cloudflare from this server (outbound UDP 7844 or TCP 443 may be blocked)",
        "data_path_not_verified" => "The end-to-end test through Cloudflare failed",
        "data_path_unverified_from_host" => "Active, but not verified from this server: Cloudflare reports the tunnel, its route and DNS record healthy, yet this server could not connect to its own public address to test it. Devices elsewhere are not affected; connect a device to confirm",
        _ => code,
    };
    if text == code {
        code.replace('_', " ")
    } else {
        format!("{text} ({code})")
    }
}

impl CloudflareIntegration {
    pub fn new(app: Weak<Appliance>, dir: &std::path::Path) -> Self {
        let binary = connector::default_binary();
        let unavailable = connector::verify_binary(&binary).err();
        CloudflareIntegration {
            app,
            connector: Arc::new(Connector::new(binary, dir.join("secrets").join(TOKEN_FILE))),
            live: Mutex::new(Live::default()),
            unavailable,
        }
    }

    fn app(&self) -> Result<Arc<Appliance>, (u16, String)> {
        self.app
            .upgrade()
            .ok_or_else(|| err(503, "appliance_unavailable"))
    }

    fn controller(app: &Appliance) -> Controller {
        Controller::new(Arc::clone(&app.store))
    }

    fn record(app: &Appliance) -> Option<db::IntegrationRow> {
        app.store
            .read(|c| db::get_integration(c, ID))
            .ok()
            .flatten()
    }

    fn save(app: &Appliance, enabled: bool, settings: &Value, status: &Value) {
        let _ = app
            .store
            .tx(|c| db::put_integration(c, ID, enabled, settings, status).map(|_| ()));
    }

    fn set_live(&self, busy: bool, step: Option<&str>) {
        let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
        l.busy = busy;
        l.step = step.map(str::to_owned);
    }

    fn token_from(body: &Value, app: &Appliance) -> Result<Zeroizing<String>, (u16, String)> {
        match body["token"]
            .as_str()
            .map(str::trim)
            .filter(|t| !t.is_empty())
        {
            Some(t) => Ok(Zeroizing::new(t.to_owned())),
            None => app
                .secrets
                .read(API_TOKEN_FILE)
                .map(|t| Zeroizing::new(t.trim().to_owned()))
                .map_err(|_| err(400, "Paste the Cloudflare API token")),
        }
    }

    pub fn status(&self) -> Value {
        let base = json!({
            "id": ID,
            "name": "Cloudflare Tunnel",
            "description": "Reach this gateway from anywhere through your Cloudflare domain — AegisNet creates the tunnel, DNS record and connector. No port forwarding needed.",
            "available": self.unavailable.is_none(),
            "unavailable_reason": self.unavailable,
        });
        let Some(app) = self.app.upgrade() else {
            return base;
        };
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let row = Self::record(&app);
        let mut v = base;
        let settings = row
            .as_ref()
            .map(|r| r.settings.clone())
            .unwrap_or(Value::Null);
        let status = row
            .as_ref()
            .map(|r| r.status.clone())
            .unwrap_or(Value::Null);
        v["enabled"] = json!(row.as_ref().is_some_and(|r| r.enabled));
        v["state"] = status["state"]
            .as_str()
            .map_or(json!("inactive"), |s| json!(s));
        if live.busy {
            v["state"] = json!(status["state"].as_str().unwrap_or("applying"));
            v["step"] = json!(live.step);
        }
        v["error"] = status["error"].clone();
        v["warning"] = status["warning"].clone();
        // Set up before the user portal existed: its routes still lack /portal
        // until re-verified with the token ("Test again").
        v["portal_routes"] = json!(settings["routes"].as_u64() >= Some(ROUTES_VERSION));
        v["hostname"] = settings["hostname"].clone();
        v["plan_id"] = settings["plan_id"].clone();
        if let Some(h) = settings["hostname"].as_str() {
            // The device port the administrator chose (one of Cloudflare's).
            let port = app
                .store
                .read(|c| db::get_setting(c, "connection"))
                .ok()
                .flatten()
                .filter(|c| c["mode"] == "cloudflare")
                .and_then(|c| c["public_port"].as_u64())
                .filter(|p| *p != 443);
            v["public_url"] = json!(match port {
                Some(p) => format!("wss://{h}:{p}/agp"),
                None => format!("wss://{h}/agp"),
            });
        }
        v["token_stored"] = json!(app.secrets.read(API_TOKEN_FILE).is_ok());
        v["connector"] = json!({
            "running": self.connector.running(),
            "ready": self.connector.last_ready(),
            "version": connector::CLOUDFLARED_VERSION,
        });
        v
    }

    /// Restart the connector after a reboot when the tunnel is active.
    pub fn resume(&self) {
        let Some(app) = self.app.upgrade() else {
            return;
        };
        let active = Self::record(&app).is_some_and(|r| r.enabled && r.status["state"] == "active");
        if active && self.unavailable.is_none() {
            let c = Arc::clone(&self.connector);
            tokio::spawn(async move {
                let _ = c.start().await;
            });
        }
    }

    pub async fn ready(&self) -> bool {
        self.connector.ready().await
    }

    pub async fn zones(&self, body: Value) -> ActionResult {
        let app = self.app()?;
        let token = Self::token_from(&body, &app)?;
        let cf = Cloudflare::new(token).map_err(provider_error)?;
        let zones = cf.zones().await.map_err(provider_error)?;
        Ok(json!({ "zones": zones }))
    }

    fn deployment_id(app: &Appliance, fresh: bool) -> Result<String, (u16, String)> {
        let existing = app
            .store
            .read(|c| db::get_setting(c, "cloudflare_deployment_id"))
            .ok()
            .flatten()
            .and_then(|v| v.as_str().map(str::to_owned));
        match existing {
            Some(id) if !fresh => Ok(id),
            _ => {
                let id = db::new_id();
                app.store
                    .tx(|c| db::put_setting(c, "cloudflare_deployment_id", &json!(id)))
                    .map_err(|_| err(503, "storage_unavailable"))?;
                Ok(id)
            }
        }
    }

    pub async fn plan(&self, actor: &str, body: Value) -> ActionResult {
        if let Some(reason) = &self.unavailable {
            return Err(err(409, reason.clone()));
        }
        let app = self.app()?;
        let hostname = body["hostname"]
            .as_str()
            .map(|h| h.trim().to_ascii_lowercase())
            .ok_or_else(|| err(400, "hostname required"))?;
        let zone_id = body["zone_id"].as_str().unwrap_or_default().to_owned();
        let token = Self::token_from(&body, &app)?;
        let cf = Cloudflare::new(token).map_err(provider_error)?;
        // Resolve the account from the zone rather than trusting the client.
        let zones = cf.zones().await.map_err(provider_error)?;
        let zone = zones
            .iter()
            .find(|z| z["id"] == zone_id.as_str())
            .ok_or_else(|| err(404, "That domain is not visible to this token"))?;
        let account_id = zone["account_id"].as_str().unwrap_or_default().to_owned();
        let ctrl = Self::controller(&app);
        // A previous, not-removed deployment must be disconnected first; a
        // never-applied plan may be replaced.
        let previous =
            Self::record(&app).and_then(|r| r.settings["plan_id"].as_str().map(str::to_owned));
        let mut fresh = false;
        if let Some(pid) = &previous {
            if let Ok(p) = ctrl.get(pid, PLAN_ACTOR) {
                match p.state {
                    PlanState::Removed => fresh = true,
                    PlanState::Validated => {}
                    _ if p.desired.hostname.as_deref() == Some(hostname.as_str())
                        && p.desired.zone_id.as_deref() == Some(zone_id.as_str()) => {}
                    _ => {
                        return Err(err(
                            409,
                            "A Cloudflare tunnel from an earlier setup still exists; disconnect it first",
                        ))
                    }
                }
            }
        }
        let tunnel_port = app
            .node
            .startup
            .inbounds
            .iter()
            .find(|i| i.id == "tunnel-origin")
            .and_then(|i| i.bind.parse::<std::net::SocketAddr>().ok())
            .map(|a| a.port())
            .ok_or_else(|| err(409, "this installation has no tunnel origin listener"))?;
        let tunnel_port = if tunnel_port == 0 {
            appliance::TUNNEL_PORT
        } else {
            tunnel_port
        };
        let http_url = body["verify_http_url"]
            .as_str()
            .unwrap_or("http://example.com/")
            .to_owned();
        let https_url = body["verify_https_url"]
            .as_str()
            .unwrap_or("https://example.com/")
            .to_owned();
        let desired = DesiredDeployment {
            schema_version: 1,
            deployment_id: Self::deployment_id(&app, fresh)?,
            mode: Mode::CloudflareTunnel,
            host: HostKind::Embedded,
            origin_service: Some(format!("http://127.0.0.1:{tunnel_port}")),
            node_id: app.node.node_id.clone(),
            inner_server_name: appliance::INNER_SERVER_NAME.into(),
            hostname: Some(hostname.clone()),
            account_id: Some(account_id),
            zone_id: Some(zone_id),
            gateway_image: String::new(),
            connector_image: None,
            nameservers: app.node.startup.dns.nameservers.clone(),
            verification_http_url: http_url,
            verification_https_url: https_url,
            acme: None,
            outer_trust_ca: None,
            nginx_image: None,
        };
        let plan = ctrl
            .plan(desired, PLAN_ACTOR, None)
            .map_err(|e| err(400, explain(e.0)))?;
        // Read-only provider checks now, so conflicts surface before apply.
        aegis_provision::InfrastructureProvider::validate(&cf, &plan)
            .await
            .map_err(provider_error)?;
        Self::save(
            &app,
            Self::record(&app).is_some_and(|r| r.enabled),
            &json!({"plan_id": plan.id, "hostname": hostname, "zone": zone["name"], "planned_by": actor}),
            &json!({"state": "planned"}),
        );
        let reused = plan.inventory.tunnel_id.is_some();
        Ok(json!({
            "plan_id": plan.id,
            "changes": [
                if reused { format!("Reuse the AegisNet tunnel aegis-{} (owned by this server)", plan.desired.deployment_id) }
                else { format!("Create a Cloudflare Tunnel named aegis-{}", plan.desired.deployment_id) },
                format!("Route https://{hostname}/agp, /enroll and /renew to this gateway only (the console is never published)"),
                format!("Create a proxied DNS record {hostname} → <tunnel>.cfargotunnel.com, labelled as AegisNet-owned"),
                format!("Run the bundled connector (cloudflared {}) inside this server", connector::CLOUDFLARED_VERSION),
                "Verify end to end: a test device connects through Cloudflare with mutual TLS and loads the verification sites".to_owned(),
                "Point new device invitations at the Cloudflare address".to_owned(),
            ],
            "warnings": [
                "Cloudflare terminates the outer HTTPS; device traffic inside stays end-to-end encrypted and authenticated.",
                "Cloudflare hides this server's address from devices; it does not change the server's own outgoing IP address.",
                "Cloudflare's terms apply to traffic through the tunnel; the Free plan is not unlimited for every use.",
            ],
        }))
    }

    /// Start applying a plan in the background; progress via status().
    pub async fn apply(self: &Arc<Self>, actor: &str, body: Value) -> ActionResult {
        if let Some(reason) = &self.unavailable {
            return Err(err(409, reason.clone()));
        }
        let app = self.app()?;
        let token = Self::token_from(&body, &app)?;
        let plan_id = body["plan_id"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| {
                Self::record(&app).and_then(|r| r.settings["plan_id"].as_str().map(str::to_owned))
            })
            .ok_or_else(|| err(400, "preview the changes first"))?;
        let ctrl = Self::controller(&app);
        let plan = ctrl
            .get(&plan_id, PLAN_ACTOR)
            .map_err(|_| err(404, "plan not found; preview again"))?;
        {
            let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
            if l.busy {
                return Err(err(409, "an operation is already running"));
            }
            l.busy = true;
            l.step = Some("starting".into());
        }
        let cf = Cloudflare::new(Zeroizing::new(token.to_string())).map_err(|e| {
            self.set_live(false, None);
            provider_error(e)
        })?;
        if body["store_token"] == true {
            let _ = app.secrets.put(API_TOKEN_FILE, &token, true);
        }
        let settings = Self::record(&app).map(|r| r.settings).unwrap_or(json!({}));
        Self::save(&app, true, &settings, &json!({"state": "applying"}));
        let _ = app.store.tx(|c| {
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: Some(actor),
                    action: "integration.cloudflare.apply",
                    target_type: "deployment",
                    target_id: Some(&plan.id),
                    decision: "allowed",
                    revision_digest: Some(&plan.digest),
                    metadata: json!({}),
                },
            )
        });
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let host = EmbeddedHost {
                app: Arc::clone(&app),
                connector: Arc::clone(&me.connector),
            };
            let detail = Arc::new(Mutex::new(None));
            let probe = EmbeddedProbe {
                app: Arc::clone(&app),
                detail: Arc::clone(&detail),
            };
            let progress = {
                let me = Arc::clone(&me);
                let app = Arc::clone(&app);
                let id = plan.id.clone();
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_millis(700)).await;
                        if let Ok(p) = Controller::new(Arc::clone(&app.store)).get(&id, PLAN_ACTOR)
                        {
                            me.set_live(true, Some(&p.step));
                        }
                    }
                })
            };
            let result = ctrl
                .apply(&plan.id, PLAN_ACTOR, &plan.etag(), None, &cf, &host, &probe)
                .await;
            progress.abort();
            drop(cf);
            let mut settings = Self::record(&app).map(|r| r.settings).unwrap_or(json!({}));
            if result.is_ok()
                || matches!(&result, Err(e) if e.0 == aegis_provision::DATA_PATH_UNVERIFIED_FROM_HOST)
            {
                // Verification brought the tunnel's routes up to date,
                // including the user portal (ROUTES_VERSION).
                settings["routes"] = json!(ROUTES_VERSION);
            }
            let warning = |code: &str| {
                let mut message = explain(code);
                if let Some(d) = detail.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    message.push_str(". ");
                    message.push_str(&d);
                }
                message
            };
            match result {
                Ok(p) if p.inventory.verified => {
                    switch_connection(&app, p.desired.hostname.as_deref());
                    Self::save(&app, true, &settings, &json!({"state": "active"}));
                }
                Ok(p) => {
                    switch_connection(&app, p.desired.hostname.as_deref());
                    let w = warning(aegis_provision::DATA_PATH_UNVERIFIED_FROM_HOST);
                    Self::save(
                        &app,
                        true,
                        &settings,
                        &json!({"state": "active", "warning": w}),
                    );
                }
                // A re-test of an active plan that again can't reach the
                // endpoint from here: stays active, with the reason.
                Err(e) if e.0 == aegis_provision::DATA_PATH_UNVERIFIED_FROM_HOST => {
                    if let Some(h) = Self::record(&app)
                        .and_then(|r| r.settings["hostname"].as_str().map(str::to_owned))
                    {
                        switch_connection(&app, Some(&h));
                    }
                    let w = warning(e.0);
                    Self::save(
                        &app,
                        true,
                        &settings,
                        &json!({"state": "active", "warning": w}),
                    );
                }
                Err(e) => {
                    let message = warning(e.0);
                    // Keep a connector that is up so a retry can reuse it;
                    // stop it only if the connector itself was the problem.
                    if !me.connector.ready().await {
                        me.connector.stop().await;
                    }
                    Self::save(
                        &app,
                        true,
                        &settings,
                        &json!({"state": "failed", "error": message}),
                    );
                }
            }
            me.set_live(false, None);
        });
        Ok(json!({"started": true, "plan_id": plan_id}))
    }

    pub async fn disable(self: &Arc<Self>, actor: &str, body: Value) -> ActionResult {
        let app = self.app()?;
        let token = Self::token_from(&body, &app)?;
        let plan_id = Self::record(&app)
            .and_then(|r| r.settings["plan_id"].as_str().map(str::to_owned))
            .ok_or_else(|| err(404, "Cloudflare is not set up"))?;
        let ctrl = Self::controller(&app);
        let plan = ctrl
            .get(&plan_id, PLAN_ACTOR)
            .map_err(|_| err(404, "Cloudflare is not set up"))?;
        let cf = Cloudflare::new(token).map_err(provider_error)?;
        let host = EmbeddedHost {
            app: Arc::clone(&app),
            connector: Arc::clone(&self.connector),
        };
        // Keeping the DNS record requires keeping the tunnel it points at.
        let keep = body["keep_dns"] == true;
        self.set_live(true, Some("removing"));
        let result = ctrl
            .uninstall(&plan.id, PLAN_ACTOR, &plan.etag(), &cf, &host, keep, keep)
            .await;
        self.set_live(false, None);
        let settings = Self::record(&app).map(|r| r.settings).unwrap_or(json!({}));
        let _ = app.store.tx(|c| {
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: Some(actor),
                    action: "integration.cloudflare.disable",
                    target_type: "deployment",
                    target_id: Some(&plan.id),
                    decision: if result.is_ok() { "allowed" } else { "failed" },
                    revision_digest: None,
                    metadata: json!({"keep_dns": keep}),
                },
            )
        });
        match result {
            Ok(_) => {
                restore_direct(&app);
                Self::save(&app, false, &settings, &json!({"state": "inactive"}));
                Ok(json!({"removed": true}))
            }
            Err(e) => {
                Self::save(
                    &app,
                    true,
                    &settings,
                    &json!({"state": "recovery_required", "error": explain(e.0)}),
                );
                Err(provider_error(e))
            }
        }
    }

    pub async fn restart(&self) -> ActionResult {
        let app = self.app()?;
        let active = Self::record(&app).is_some_and(|r| r.status["state"] == "active");
        if !active {
            return Err(err(409, "Cloudflare is not active"));
        }
        self.connector.start().await.map_err(|e| err(409, e))?;
        Ok(json!({"restarted": true}))
    }
}

/// Point invitations at the tunnel, remembering the direct settings.
fn switch_connection(app: &Appliance, hostname: Option<&str>) {
    let Some(host) = hostname else { return };
    let _ = app.store.tx(|c| {
        let mut port = 443;
        if let Some(current) = db::get_setting(c, "connection")? {
            if current["mode"].as_str().is_none_or(|m| m == "direct") {
                db::put_setting(c, "direct_connection", &current)?;
            }
            // A retry or route update keeps the port the administrator chose.
            if current["mode"] == "cloudflare" && current["public_host"] == host {
                port = current["public_port"].as_u64().unwrap_or(443);
            }
        }
        db::put_setting(
            c,
            "connection",
            &json!({"mode": "cloudflare", "public_host": host, "public_port": port, "outer_trust": "public"}),
        )
    });
}

fn restore_direct(app: &Appliance) {
    let _ = app.store.tx(|c| {
        let direct = db::get_setting(c, "direct_connection")?
            .unwrap_or_else(|| json!({"mode": "direct", "outer_trust": "pinned"}));
        db::put_setting(c, "connection", &direct)
    });
}

/// Embedded host provisioner: owner-only token file + supervised connector.
struct EmbeddedHost {
    app: Arc<Appliance>,
    connector: Arc<Connector>,
}

impl HostProvisioner for EmbeddedHost {
    fn apply<'a>(&'a self, _plan: &'a Plan, token: Option<&'a str>) -> StepFuture<'a, ()> {
        Box::pin(async move {
            let token = token.ok_or(Error("connector_token_missing"))?;
            self.app
                .secrets
                .put(TOKEN_FILE, token, true)
                .map_err(|_| Error("connector_token_write_failed"))?;
            self.connector
                .start()
                .await
                .map_err(|_| Error("connector_unavailable"))?;
            if !self.connector.wait_ready(Duration::from_secs(90)).await {
                return Err(Error("connector_not_ready"));
            }
            Ok(())
        })
    }

    fn verify<'a>(&'a self, _plan: &'a Plan) -> StepFuture<'a, String> {
        Box::pin(async move {
            if !self.connector.ready().await {
                return Err(Error("connector_not_ready"));
            }
            let health = self.app.node.coord.health();
            if !health.admission_enabled {
                return Err(Error("gateway_admission_closed"));
            }
            Ok(health
                .runtime_revision_id
                .unwrap_or_else(|| "embedded".into()))
        })
    }

    fn remove<'a>(&'a self, _plan: &'a Plan) -> StepFuture<'a, ()> {
        Box::pin(async move {
            self.connector.stop().await;
            let _ = std::fs::remove_file(self.app.secrets.root().join(TOKEN_FILE));
            Ok(())
        })
    }
}

struct EmbeddedProbe {
    app: Arc<Appliance>,
    /// Secret-free detail of the last probe failure, for the console.
    detail: Arc<Mutex<Option<String>>>,
}

impl Probe for EmbeddedProbe {
    fn verify<'a>(&'a self, plan: &'a Plan) -> StepFuture<'a, Verification> {
        Box::pin(async move {
            probe::run(
                &self.app,
                &plan.desired.endpoint(),
                &plan.desired.verification_http_url,
                &plan.desired.verification_https_url,
            )
            .await
            .map_err(|e| {
                *self.detail.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some(e.detail().to_owned());
                match e {
                    probe::ProbeFailure::Unreachable(_) => {
                        Error(aegis_provision::DATA_PATH_UNVERIFIED_FROM_HOST)
                    }
                    probe::ProbeFailure::Failed(_) => Error("data_path_not_verified"),
                }
            })?;
            // Each flag was demonstrated by the probe above: the session
            // crossed public DNS, the edge, the connector and inner mTLS,
            // and both verification sites loaded through SOCKS.
            Ok(Verification {
                provider_objects: true,
                connector: true,
                public_dns: true,
                wss: true,
                inner_mtls: true,
                socks_http: true,
                socks_https: true,
            })
        })
    }
}
