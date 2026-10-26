//! Appliance runtime services (ADR-0007): certificate lifecycle for the
//! appliance's own identities and the built-in integrations. Everything here
//! runs inside the unprivileged gateway process; nothing gains host
//! authority.

use crate::appliance::{self, manifest_certificate};
use aegis_management::{ApplianceServices, ManagementContext};
use aegis_node::NodeContext;
use aegis_provision::secrets::SecretStore;
use aegis_storage::Store;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

/// Renew the 30-day gateway identity with 10 days left.
const GATEWAY_RENEW_BEFORE: i64 = 10 * 86_400;
/// Renew web certificates (397 days) with 30 days left.
const WEB_RENEW_BEFORE: i64 = 30 * 86_400;
/// Rotate the online issuer (1 year) with 60 days left, if the root is here.
const ISSUER_RENEW_BEFORE: i64 = 60 * 86_400;

pub struct Appliance {
    pub dir: PathBuf,
    pub secrets: SecretStore,
    pub store: Arc<Store>,
    pub node: Arc<NodeContext>,
    mgmt: OnceLock<Weak<ManagementContext>>,
    pub integrations: crate::integrations::Integrations,
}

pub fn now_unix() -> i64 {
    aegis_storage::now_unix()
}

fn expiry(pem: &str) -> Option<i64> {
    let certs = aegis_identity::tls::parse_certs(pem).ok()?;
    aegis_identity::tls::certificate_expiry(certs[0].as_ref()).ok()
}

impl Appliance {
    pub fn new(
        dir: PathBuf,
        store: Arc<Store>,
        node: Arc<NodeContext>,
    ) -> Result<Arc<Self>, String> {
        let secrets = SecretStore::open(dir.join("secrets")).map_err(|e| e.0.to_owned())?;
        Ok(Arc::new_cyclic(|weak: &Weak<Appliance>| Appliance {
            integrations: crate::integrations::Integrations::new(weak.clone()),
            dir,
            secrets,
            store,
            node,
            mgmt: OnceLock::new(),
        }))
    }

    pub fn attach(&self, mgmt: &Arc<ManagementContext>) {
        let _ = self.mgmt.set(Arc::downgrade(mgmt));
    }

    pub fn mgmt(&self) -> Option<Arc<ManagementContext>> {
        self.mgmt.get().and_then(Weak::upgrade)
    }

    fn certificate_status(&self) -> Value {
        let at =
            |manifest: &str| manifest_certificate(&self.secrets, manifest).and_then(|p| expiry(&p));
        let issuer = appliance::load_issuer(&self.secrets)
            .ok()
            .and_then(|i| expiry(&i.cert_pem));
        json!({
            "gateway_identity_expires_at": at("gateway-identity.json").map(aegis_core::rfc3339),
            "edge_expires_at": at("edge-tls.json").map(aegis_core::rfc3339),
            "console_expires_at": at("console-tls.json").map(aegis_core::rfc3339),
            "issuer_expires_at": issuer.map(aegis_core::rfc3339),
            "root_key_on_host": self.secrets.root().join("device-root-key.pem").exists(),
        })
    }

    fn reissue_web(&self, names: &[String], ips: &[IpAddr]) -> Result<(), String> {
        let web = appliance::load_web_ca(&self.secrets)?;
        appliance::issue_console(&self.secrets, &web, names, ips)?;
        appliance::issue_edge(&self.secrets, &web, names, ips)?;
        if let Some(m) = self.mgmt() {
            m.reload_console_tls()?;
        }
        // The edge listener re-reads its manifest on the next handshake.
        Ok(())
    }

    /// One maintenance pass; returns what was renewed (for tests/audit).
    pub fn maintain(&self) -> Vec<&'static str> {
        let mut done = Vec::new();
        let now = now_unix();
        let mut issuer = appliance::load_issuer(&self.secrets).ok();
        if issuer
            .as_ref()
            .and_then(|i| expiry(&i.cert_pem))
            .is_some_and(|e| e - now < ISSUER_RENEW_BEFORE)
        {
            if let Ok(next) = appliance::rotate_issuer(&self.secrets) {
                issuer = Some(next);
                done.push("issuer");
            }
        }
        let gateway_due = manifest_certificate(&self.secrets, "gateway-identity.json")
            .and_then(|p| expiry(&p))
            .is_none_or(|e| e - now < GATEWAY_RENEW_BEFORE);
        if gateway_due || done.contains(&"issuer") {
            if let Some(i) = &issuer {
                if appliance::issue_gateway_identity(&self.secrets, i).is_ok()
                    && self.node.reload_certificates().is_ok()
                {
                    done.push("gateway_identity");
                }
            }
        }
        let web_due = ["edge-tls.json", "console-tls.json"].iter().any(|m| {
            manifest_certificate(&self.secrets, m)
                .and_then(|p| expiry(&p))
                .is_none_or(|e| e - now < WEB_RENEW_BEFORE)
        });
        if web_due {
            let (names, ips) = appliance::web_names(&self.store);
            if self.reissue_web(&names, &ips).is_ok() {
                done.push("web");
            }
        }
        if !done.is_empty() {
            let _ = self.store.tx(|c| {
                aegis_storage::append_audit(
                    c,
                    aegis_storage::AuditInsert {
                        actor_id: None,
                        action: "appliance.certificates_renewed",
                        target_type: "system",
                        target_id: None,
                        decision: "allowed",
                        revision_digest: None,
                        metadata: json!({ "renewed": done }),
                    },
                )
            });
        }
        done
    }
}

impl ApplianceServices for Appliance {
    fn status(&self) -> Value {
        json!({
            "certificates": self.certificate_status(),
            "integrations": self.integrations.status(),
            "listeners": self.node.startup.inbounds.iter().map(|i| json!({"id": i.id, "bind": i.bind})).collect::<Vec<_>>(),
        })
    }

    fn set_public_addresses(&self, names: &[String], ips: &[IpAddr]) -> Result<(), String> {
        let (mut all_names, mut all_ips) = appliance::web_names(&self.store);
        let mut added = false;
        for n in names {
            if !all_names.contains(n) {
                all_names.push(n.clone());
                added = true;
            }
        }
        for i in ips {
            if !all_ips.contains(i) {
                all_ips.push(*i);
                added = true;
            }
        }
        // Re-issuing for an address already covered would only invalidate
        // the fingerprint the operator verified.
        if !added {
            return Ok(());
        }
        all_names.truncate(6);
        all_ips.truncate(6);
        appliance::set_web_names(&self.store, &all_names, &all_ips)?;
        self.reissue_web(&all_names, &all_ips)
    }

    fn integration(
        &self,
        id: &str,
        action: &str,
        actor: &str,
        body: Value,
    ) -> aegis_management::IntegrationFuture {
        self.integrations.dispatch(id, action, actor, body)
    }
}

/// Periodic certificate maintenance (first pass shortly after start).
/// While an on-demand diagnostics recording runs, note integrations that
/// are failing (for example a Cloudflare connector that is down), so the
/// analysis can point at them. Idle otherwise.
pub async fn diagnostics_loop(app: Arc<Appliance>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tick.tick().await;
        let diagnostics = &app.node.diagnostics;
        if !diagnostics.is_recording() {
            continue;
        }
        let status = app.integrations.status();
        for i in status.as_array().into_iter().flatten() {
            if i["enabled"] != true {
                continue;
            }
            let id = i["id"].as_str().unwrap_or("integration");
            let state = i["state"].as_str().unwrap_or("");
            let connector_down = i["state"] == "active"
                && i["connector"].is_object()
                && (i["connector"]["running"] != true || i["connector"]["ready"] == false);
            if state == "failed" || connector_down {
                let error = i["error"].as_str().unwrap_or(if connector_down {
                    "connector not running or not ready"
                } else {
                    ""
                });
                diagnostics.note(
                    aegis_telemetry::Severity::Error,
                    "integration.failed",
                    &[("integration", id), ("state", state), ("error", error)],
                );
            } else {
                diagnostics.count("integration.ok");
            }
        }
    }
}

pub async fn maintenance_loop(app: Arc<Appliance>) {
    let mut wait = Duration::from_secs(30);
    loop {
        tokio::time::sleep(wait).await;
        let a = Arc::clone(&app);
        let _ = tokio::task::spawn_blocking(move || a.maintain()).await;
        app.integrations.maintain().await;
        wait = Duration::from_secs(6 * 3600);
    }
}
