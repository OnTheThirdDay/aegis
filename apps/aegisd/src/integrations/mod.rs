//! Built-in integrations ("plugins" in the console). Each is reviewed,
//! first-party code with a fixed action set; no external code is loaded.

pub mod acme;
pub mod cloudflare;
pub mod connector;
pub mod connector_update;
pub mod probe;

use crate::services::Appliance;
use serde_json::{json, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock, Weak};

pub type ActionResult = Result<Value, (u16, String)>;
pub type ActionFuture = Pin<Box<dyn Future<Output = ActionResult> + Send>>;

pub struct Integrations {
    app: Weak<Appliance>,
    cloudflare: OnceLock<Arc<cloudflare::CloudflareIntegration>>,
    acme: Arc<acme::AcmeIntegration>,
}

impl Integrations {
    pub fn new(app: Weak<Appliance>) -> Self {
        Integrations {
            acme: Arc::new(acme::AcmeIntegration::new(app.clone())),
            cloudflare: OnceLock::new(),
            app,
        }
    }

    /// Created lazily: it needs the appliance's data directory.
    fn cloudflare(&self) -> Option<Arc<cloudflare::CloudflareIntegration>> {
        if let Some(c) = self.cloudflare.get() {
            return Some(Arc::clone(c));
        }
        let app = self.app.upgrade()?;
        let c = Arc::new(cloudflare::CloudflareIntegration::new(
            self.app.clone(),
            &app.dir,
        ));
        Some(Arc::clone(self.cloudflare.get_or_init(|| c)))
    }

    /// Restart integrations that were active before a restart.
    pub fn resume(&self) {
        if let Some(cf) = self.cloudflare() {
            cf.resume();
        }
    }

    /// Stop supervised helpers (connector processes) on shutdown.
    pub async fn stop(&self) {
        if let Some(cf) = self.cloudflare.get() {
            cf.connector.stop().await;
        }
    }

    /// Periodic work: certificate renewal, connector updates.
    pub async fn maintain(&self) {
        self.acme.renew_if_due().await;
        if let Some(cf) = self.cloudflare() {
            cf.update_if_due().await;
        }
    }

    pub fn status(&self) -> Value {
        let telemetry = json!({
            "id": "otel",
            "name": "OpenTelemetry export",
            "description": "Coarse, allowlisted metrics to an OTLP/HTTP collector after an explicit preview and consent. Off by default; configure it through the telemetry API.",
            "enabled": false,
            "state": "off",
        });
        let mut list = Vec::new();
        if let Some(cf) = self.cloudflare() {
            list.push(cf.status());
        }
        list.push(self.acme.status());
        list.push(telemetry);
        Value::Array(list)
    }

    pub fn dispatch(&self, id: &str, action: &str, actor: &str, body: Value) -> ActionFuture {
        let cf = self.cloudflare();
        let acme = Arc::clone(&self.acme);
        let (id, action, actor) = (id.to_owned(), action.to_owned(), actor.to_owned());
        Box::pin(async move {
            match (id.as_str(), action.as_str()) {
                ("cloudflare", a) => {
                    let cf = cf.ok_or((503, "appliance_unavailable".to_owned()))?;
                    match a {
                        "zones" => cf.zones(body).await,
                        "plan" => cf.plan(&actor, body).await,
                        "apply" => cf.apply(&actor, body).await,
                        "disable" => cf.disable(&actor, body).await,
                        "restart" => cf.restart().await,
                        "update-connector" => cf.update_connector(&actor).await,
                        "connector-auto-update" => cf.set_auto_update(&actor, &body),
                        _ => Err((404, format!("unknown action {a}"))),
                    }
                }
                ("acme", "issue") => acme.issue(&actor, body).await,
                ("acme", "renew") => acme.renew(&actor).await,
                ("acme", "disable") => acme.disable(&actor).await,
                _ => Err((404, format!("unknown integration action {id}/{action}"))),
            }
        })
    }
}
