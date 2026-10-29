//! Public server certificate via ACME (Let's Encrypt), SPEC-12 §8.
//!
//! * HTTP-01: a challenge responder listens on the HTTP port only while an
//!   order is pending and answers nothing but `/.well-known/acme-challenge/`.
//! * DNS-01: an AegisBorne-labelled TXT record is created through the
//!   Cloudflare API and deleted afterwards (by id).
//! * The issued certificate is validated (chain, name, key) before it is
//!   published as an SNI alternate on the edge listener; the private edge
//!   certificate stays the default so devices pinned to it keep working.
//! * Renewal runs automatically with 30 days left; a failed renewal keeps
//!   the still-valid certificate.
//!
//! For tests against a private ACME server (e.g. Pebble), set
//! `AEGIS_ACME_DIRECTORY`, `AEGIS_ACME_CA_FILE` (API TLS trust) and
//! `AEGIS_ACME_TRUST_FILE` (issued-certificate trust); production uses the
//! Let's Encrypt directories and public roots only.

use super::ActionResult;
use crate::services::Appliance;
use aegis_provision::cloudflare::Cloudflare;
use aegis_storage as db;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType,
    HttpClient, Identifier, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

pub const ID: &str = "acme";
const RENEW_BEFORE: i64 = 30 * 86_400;
const TEST_CA: &str = "acme-test-ca.pem";

fn err(status: u16, code: impl Into<String>) -> (u16, String) {
    (status, code.into())
}

/// instant-acme HTTP client over reqwest (rustls, no proxies, no redirects).
struct Http(reqwest::Client);

impl HttpClient for Http {
    fn request(
        &self,
        req: http::Request<BodyWrapper<bytes::Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, mut body) = req.into_parts();
            let mut bytes = Vec::new();
            while let Some(frame) =
                std::future::poll_fn(|cx| http_body::Body::poll_frame(Pin::new(&mut body), cx))
                    .await
            {
                // The body type is infallible; trailers carry no data.
                let Ok(frame) = frame;
                if let Ok(chunk) = frame.into_data() {
                    bytes.extend_from_slice(&chunk);
                }
            }
            let mut builder = client.request(parts.method, parts.uri.to_string());
            for (k, v) in parts.headers.iter() {
                builder = builder.header(k, v);
            }
            let resp = builder
                .body(bytes)
                .send()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let mut out = http::Response::builder().status(resp.status().as_u16());
            for (k, v) in resp.headers().iter() {
                out = out.header(k, v);
            }
            let data = resp
                .bytes()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let (parts, _) = out
                .body(())
                .map_err(instant_acme::Error::Http)?
                .into_parts();
            Ok(BytesResponse {
                parts,
                body: Box::new(data),
            })
        })
    }
}

fn test_ca() -> Option<String> {
    std::env::var("AEGIS_ACME_CA_FILE")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
}

/// Trust anchor for the *issued* certificate on a private test CA (Pebble
/// issues from a per-run root that differs from its API certificate).
fn issued_trust() -> Option<String> {
    std::env::var("AEGIS_ACME_TRUST_FILE")
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
}

fn http_client() -> Result<reqwest::Client, (u16, String)> {
    let mut b = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    if let Some(pem) = test_ca() {
        let cert = reqwest::Certificate::from_pem(pem.as_bytes())
            .map_err(|_| err(500, "invalid AEGIS_ACME_CA_FILE"))?;
        b = b.tls_built_in_root_certs(false).add_root_certificate(cert);
    }
    b.build().map_err(|_| err(500, "acme_client_unavailable"))
}

fn directory(staging: bool) -> String {
    std::env::var("AEGIS_ACME_DIRECTORY").unwrap_or_else(|_| {
        if staging {
            LetsEncrypt::Staging.url().to_owned()
        } else {
            LetsEncrypt::Production.url().to_owned()
        }
    })
}

fn http_port() -> u16 {
    std::env::var("AEGIS_HTTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Settings {
    hostname: String,
    email: String,
    challenge: String,
    staging: bool,
    public_port: u16,
}

#[derive(Default, Clone)]
struct Live {
    busy: bool,
    step: Option<String>,
}

pub struct AcmeIntegration {
    app: Weak<Appliance>,
    live: Mutex<Live>,
    tokens: Arc<Mutex<HashMap<String, String>>>,
}

impl AcmeIntegration {
    pub fn new(app: Weak<Appliance>) -> Self {
        AcmeIntegration {
            app,
            live: Mutex::new(Live::default()),
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn app(&self) -> Result<Arc<Appliance>, (u16, String)> {
        self.app
            .upgrade()
            .ok_or_else(|| err(503, "appliance_unavailable"))
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

    fn step(&self, step: Option<&str>) {
        let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
        l.busy = step.is_some();
        l.step = step.map(str::to_owned);
    }

    pub fn status(&self) -> Value {
        let mut v = json!({
            "id": ID,
            "name": "Let's Encrypt certificate",
            "description": "Publicly trusted certificate for a DNS name pointing at this server, renewed automatically. Uses HTTP validation (port 80) or DNS validation through Cloudflare.",
        });
        let Some(app) = self.app.upgrade() else {
            return v;
        };
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner()).clone();
        if let Some(row) = Self::record(&app) {
            v["enabled"] = json!(row.enabled);
            v["state"] = row.status["state"].clone();
            v["error"] = row.status["error"].clone();
            v["expires_at"] = row.status["expires_at"].clone();
            v["hostname"] = row.settings["hostname"].clone();
            v["staging"] = row.settings["staging"].clone();
            v["challenge"] = row.settings["challenge"].clone();
        } else {
            v["state"] = json!("inactive");
        }
        if live.busy {
            v["state"] = json!("issuing");
            v["step"] = json!(live.step);
        }
        v
    }

    fn validate(body: &Value) -> Result<Settings, (u16, String)> {
        let hostname = body["hostname"]
            .as_str()
            .map(|h| h.trim().to_ascii_lowercase())
            .unwrap_or_default();
        if aegis_contracts::destination::normalize_domain(&hostname).as_deref()
            != Ok(hostname.as_str())
            || hostname.parse::<std::net::IpAddr>().is_ok()
            || !hostname.contains('.')
        {
            return Err(err(400, "Enter a public DNS name such as vpn.example.com"));
        }
        let email = body["email"].as_str().unwrap_or_default().trim().to_owned();
        if email.len() > 254
            || !email.contains('@')
            || email.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(err(400, "Enter a valid contact email address"));
        }
        if body["terms_accepted"] != true {
            return Err(err(
                400,
                "The Let's Encrypt Subscriber Agreement must be accepted",
            ));
        }
        let challenge = match body["challenge"].as_str() {
            Some("http-01") => "http-01",
            Some("dns-01-cloudflare") => "dns-01-cloudflare",
            _ => return Err(err(400, "Choose HTTP or DNS validation")),
        };
        let public_port = body["public_port"]
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .unwrap_or(443);
        Ok(Settings {
            hostname,
            email,
            challenge: challenge.into(),
            staging: body["staging"] == true,
            public_port,
        })
    }

    pub async fn issue(self: &Arc<Self>, actor: &str, body: Value) -> ActionResult {
        let app = self.app()?;
        let settings = Self::validate(&body)?;
        let token = if settings.challenge == "dns-01-cloudflare" {
            let t = body["token"]
                .as_str()
                .map(str::trim)
                .filter(|t| !t.is_empty())
                .map(|t| Zeroizing::new(t.to_owned()))
                .or_else(|| {
                    app.secrets
                        .read(super::cloudflare::API_TOKEN_FILE)
                        .ok()
                        .map(|t| Zeroizing::new(t.trim().to_owned()))
                })
                .ok_or_else(|| err(400, "DNS validation needs a Cloudflare API token"))?;
            // Renewals need it again: keep it owner-only on this server.
            app.secrets
                .put(super::cloudflare::API_TOKEN_FILE, &t, true)
                .map_err(|_| err(503, "could not store the token"))?;
            Some(t)
        } else {
            None
        };
        self.start(&app, actor, settings, token)
    }

    fn start(
        self: &Arc<Self>,
        app: &Arc<Appliance>,
        actor: &str,
        settings: Settings,
        token: Option<Zeroizing<String>>,
    ) -> ActionResult {
        {
            let mut l = self.live.lock().unwrap_or_else(|e| e.into_inner());
            if l.busy {
                return Err(err(409, "a certificate request is already running"));
            }
            l.busy = true;
            l.step = Some("starting".into());
        }
        let settings_json = serde_json::to_value(&settings).unwrap_or(Value::Null);
        let previous = Self::record(app);
        Self::save(
            app,
            previous.as_ref().is_some_and(|r| r.enabled),
            &settings_json,
            &previous
                .as_ref()
                .map(|r| r.status.clone())
                .unwrap_or_else(|| json!({"state": "inactive"})),
        );
        let _ = app.store.tx(|c| {
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: Some(actor),
                    action: "integration.acme.issue",
                    target_type: "certificate",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"challenge": settings.challenge, "staging": settings.staging}),
                },
            )
        });
        let me = Arc::clone(self);
        let app = Arc::clone(app);
        tokio::spawn(async move {
            let result = me.order(&app, &settings, token.as_ref()).await;
            me.tokens.lock().unwrap_or_else(|e| e.into_inner()).clear();
            let settings_json = serde_json::to_value(&settings).unwrap_or(Value::Null);
            match result {
                Ok(expires) => {
                    switch_connection(&app, &settings);
                    Self::save(
                        &app,
                        true,
                        &settings_json,
                        &json!({"state": "active", "expires_at": aegis_core::rfc3339(expires)}),
                    );
                }
                Err(e) => {
                    // A failed renewal keeps the active, still-valid certificate.
                    let prev = Self::record(&app);
                    let was_active = prev.as_ref().is_some_and(|r| r.status["state"] == "active");
                    let mut status = prev.map(|r| r.status).unwrap_or_else(|| json!({}));
                    status["state"] = json!(if was_active { "active" } else { "failed" });
                    status["error"] = json!(e);
                    Self::save(&app, was_active, &settings_json, &status);
                }
            }
            me.step(None);
        });
        Ok(json!({"started": true}))
    }

    async fn order(
        &self,
        app: &Arc<Appliance>,
        s: &Settings,
        token: Option<&Zeroizing<String>>,
    ) -> Result<i64, String> {
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            let text: String = e.to_string().chars().take(300).collect();
            format!("{what}: {text}")
        };
        self.step(Some("account"));
        let account = self.account(app, s).await?;
        self.step(Some("order"));
        let ids = [Identifier::Dns(s.hostname.clone())];
        let mut order = account
            .new_order(&NewOrder::new(&ids))
            .await
            .map_err(|e| fail("order", &e))?;
        let mut cleanup: Vec<(String, String)> = Vec::new();
        let cf = match (s.challenge.as_str(), token) {
            ("dns-01-cloudflare", Some(t)) => Some(
                Cloudflare::new(Zeroizing::new(t.to_string()))
                    .map_err(|e| super::cloudflare::explain(e.0))?,
            ),
            _ => None,
        };
        let responder = if s.challenge == "http-01" {
            Some(
                start_responder(Arc::clone(&self.tokens))
                    .await
                    .map_err(|e| format!("HTTP validation port {}: {e}", http_port()))?,
            )
        } else {
            None
        };
        let prepared: Result<(), String> = async {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authz = result.map_err(|e| fail("authorization", &e))?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => return Err(format!("authorization {other:?}")),
                }
                let kind = if cf.is_some() {
                    ChallengeType::Dns01
                } else {
                    ChallengeType::Http01
                };
                let mut challenge = authz
                    .challenge(kind)
                    .ok_or_else(|| "the CA offered no usable challenge".to_owned())?;
                let key_auth = challenge.key_authorization();
                if let Some(cf) = &cf {
                    self.step(Some("dns_record"));
                    let (zone, _) = cf
                        .zone_for(&s.hostname)
                        .await
                        .map_err(|e| super::cloudflare::explain(e.0))?;
                    let id = cf
                        .create_txt(
                            &zone,
                            &format!("_acme-challenge.{}", s.hostname),
                            &key_auth.dns_value(),
                            "aegis-acme",
                        )
                        .await
                        .map_err(|e| super::cloudflare::explain(e.0))?;
                    cleanup.push((zone, id));
                    // Give Cloudflare's authoritative servers a moment.
                    tokio::time::sleep(Duration::from_secs(15)).await;
                } else {
                    self.tokens
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(challenge.token.clone(), key_auth.as_str().to_owned());
                }
                self.step(Some("validating"));
                challenge
                    .set_ready()
                    .await
                    .map_err(|e| fail("challenge", &e))?;
            }
            Ok(())
        }
        .await;
        let validated = match prepared {
            Ok(()) => order
                .poll_ready(&RetryPolicy::default().timeout(Duration::from_secs(180)))
                .await
                .map_err(|e| fail("validation", &e)),
            Err(e) => Err(e),
        };
        if let Some(r) = responder {
            r.abort();
        }
        if let Some(cf) = &cf {
            for (zone, id) in &cleanup {
                let _ = cf.delete_record(zone, id).await;
            }
        }
        match validated? {
            OrderStatus::Ready => {}
            other => {
                return Err(match s.challenge.as_str() {
                    "http-01" => format!("validation failed ({other:?}): the CA could not fetch http://{}/.well-known/acme-challenge/… — forward TCP port 80 to this server's HTTP port", s.hostname),
                    _ => format!("validation failed ({other:?}): the TXT record was not visible to the CA"),
                })
            }
        }
        self.step(Some("finalizing"));
        let (key, csr) = aegis_identity::pki::server_key_and_csr(&s.hostname)
            .map_err(|_| "key generation failed".to_owned())?;
        let key = Zeroizing::new(key);
        order
            .finalize_csr(&csr)
            .await
            .map_err(|e| fail("finalize", &e))?;
        let chain = order
            .poll_certificate(&RetryPolicy::default().timeout(Duration::from_secs(90)))
            .await
            .map_err(|e| fail("certificate", &e))?;
        self.step(Some("activating"));
        activate(app, &s.hostname, &chain, &key)
    }

    async fn account(&self, app: &Arc<Appliance>, s: &Settings) -> Result<Account, String> {
        let file = if s.staging {
            "acme-account-staging.json"
        } else {
            "acme-account.json"
        };
        let builder = || {
            Account::builder_with_http(Box::new(Http(
                http_client().map_err(|e| e.1).unwrap_or_default(),
            )))
        };
        if let Ok(text) = app.secrets.read(file) {
            if let Ok(creds) = serde_json::from_str::<AccountCredentials>(&text) {
                if let Ok(a) = builder().from_credentials(creds).await {
                    return Ok(a);
                }
            }
        }
        let contact = format!("mailto:{}", s.email);
        let (account, creds) = builder()
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                directory(s.staging),
                None,
            )
            .await
            .map_err(|e| {
                format!(
                    "account: {}",
                    e.to_string().chars().take(300).collect::<String>()
                )
            })?;
        let text = serde_json::to_string(&creds).map_err(|_| "account serialization".to_owned())?;
        app.secrets
            .put(file, &text, true)
            .map_err(|_| "could not store ACME account".to_owned())?;
        Ok(account)
    }

    pub async fn renew(self: &Arc<Self>, actor: &str) -> ActionResult {
        let app = self.app()?;
        let row = Self::record(&app).ok_or_else(|| err(404, "no certificate configured"))?;
        let settings: Settings = serde_json::from_value(row.settings)
            .map_err(|_| err(409, "certificate settings missing"))?;
        let token = if settings.challenge == "dns-01-cloudflare" {
            Some(
                app.secrets
                    .read(super::cloudflare::API_TOKEN_FILE)
                    .map(|t| Zeroizing::new(t.trim().to_owned()))
                    .map_err(|_| err(409, "the stored Cloudflare token is missing"))?,
            )
        } else {
            None
        };
        self.start(&app, actor, settings, token)
    }

    /// Called by the maintenance loop.
    pub async fn renew_if_due(self: &Arc<Self>) {
        let Some(app) = self.app.upgrade() else {
            return;
        };
        let Some(row) = Self::record(&app) else {
            return;
        };
        if !row.enabled || row.status["state"] != "active" {
            return;
        }
        let due = row.status["expires_at"]
            .as_str()
            .and_then(|s| {
                time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
            })
            .is_none_or(|t| t.unix_timestamp() - db::now_unix() < RENEW_BEFORE);
        if due {
            let _ = self.renew("system").await;
        }
    }

    pub async fn disable(&self, actor: &str) -> ActionResult {
        let app = self.app()?;
        set_alternates(&app, Vec::new()).map_err(|e| err(503, e))?;
        restore_direct(&app);
        let settings = Self::record(&app).map(|r| r.settings).unwrap_or(json!({}));
        Self::save(&app, false, &settings, &json!({"state": "inactive"}));
        let _ = app.store.tx(|c| {
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: Some(actor),
                    action: "integration.acme.disable",
                    target_type: "certificate",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        });
        Ok(json!({"disabled": true}))
    }
}

/// Validate and publish the certificate as the edge's SNI alternate.
fn activate(app: &Appliance, hostname: &str, chain: &str, key: &str) -> Result<i64, String> {
    let custom = issued_trust();
    if let Some(ca) = &custom {
        app.secrets
            .put(TEST_CA, ca, true)
            .map_err(|_| "could not store test CA".to_owned())?;
    }
    aegis_identity::tls::certified_key(chain, key, hostname, custom.as_deref())
        .map_err(|_| "the issued certificate failed validation".to_owned())?;
    let certs =
        aegis_identity::tls::parse_certs(chain).map_err(|_| "bad certificate".to_owned())?;
    let expires = aegis_identity::tls::certificate_expiry(certs[0].as_ref())
        .map_err(|_| "bad certificate".to_owned())?;
    let generation = &db::sha256_hex(chain.as_bytes())[..16];
    let cert_file = format!("acme-{generation}.pem");
    let key_file = format!("acme-{generation}.key");
    app.secrets
        .put(&cert_file, chain, true)
        .map_err(|_| "could not store certificate".to_owned())?;
    app.secrets
        .put(&key_file, key, true)
        .map_err(|_| "could not store key".to_owned())?;
    let mut alt = json!({
        "certificate": format!("secret://{cert_file}"),
        "private_key": format!("secret://{key_file}"),
        "server_name": hostname,
    });
    if custom.is_some() {
        alt["trusted_ca"] = json!(format!("secret://{TEST_CA}"));
    }
    set_alternates(app, vec![alt])?;
    Ok(expires)
}

/// Rewrite the edge manifest's SNI alternates atomically, removing files of
/// replaced alternates afterwards.
fn set_alternates(app: &Appliance, alternates: Vec<Value>) -> Result<(), String> {
    let _lock = crate::appliance::MANIFEST_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let text = app
        .secrets
        .read("edge-tls.json")
        .map_err(|_| "edge manifest unavailable".to_owned())?;
    let mut manifest: Value =
        serde_json::from_str(&text).map_err(|_| "edge manifest invalid".to_owned())?;
    let old = manifest["alternates"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    manifest["alternates"] = json!(alternates);
    app.secrets
        .put("edge-tls.json", &manifest.to_string(), true)
        .map_err(|_| "could not update edge manifest".to_owned())?;
    let keep: Vec<&str> = alternates
        .iter()
        .flat_map(|a| [a["certificate"].as_str(), a["private_key"].as_str()])
        .flatten()
        .collect();
    for a in &old {
        for field in ["certificate", "private_key"] {
            if let Some(r) = a[field].as_str() {
                if !keep.contains(&r) {
                    if let Some(name) = r.strip_prefix("secret://").filter(|n| !n.contains('/')) {
                        let _ = std::fs::remove_file(app.secrets.root().join(name));
                    }
                }
            }
        }
    }
    Ok(())
}

fn switch_connection(app: &Appliance, s: &Settings) {
    let _ = app.store.tx(|c| {
        if let Some(current) = db::get_setting(c, "connection")? {
            if current["mode"].as_str().is_none_or(|m| m == "direct") {
                db::put_setting(c, "direct_connection", &current)?;
            }
            if current["mode"] == "cloudflare" {
                // Cloudflare stays the device path; the certificate only
                // serves direct clients using the public name.
                return Ok(());
            }
        }
        db::put_setting(
            c,
            "connection",
            &json!({"mode": "acme", "public_host": s.hostname, "public_port": s.public_port, "outer_trust": "public"}),
        )
    });
}

fn restore_direct(app: &Appliance) {
    let _ = app.store.tx(|c| {
        let current = db::get_setting(c, "connection")?;
        if current.as_ref().is_some_and(|v| v["mode"] == "acme") {
            let direct = db::get_setting(c, "direct_connection")?
                .unwrap_or_else(|| json!({"mode": "direct", "outer_trust": "pinned"}));
            db::put_setting(c, "connection", &direct)?;
        }
        Ok(())
    });
}

/// Minimal HTTP-01 responder, alive only during an order.
async fn start_responder(
    tokens: Arc<Mutex<HashMap<String, String>>>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", http_port()))
        .await
        .map_err(|e| e.kind().to_string())?;
    Ok(tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                continue;
            };
            let tokens = Arc::clone(&tokens);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let n = match tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await
                {
                    Ok(Ok(n)) => n,
                    _ => return,
                };
                let head = String::from_utf8_lossy(&buf[..n]);
                let path = head.split_whitespace().nth(1).unwrap_or("");
                let answer = path
                    .strip_prefix("/.well-known/acme-challenge/")
                    .and_then(|t| {
                        tokens
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .get(t)
                            .cloned()
                    });
                let resp = match answer {
                    Some(body) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    ),
                    None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                };
                let _ = s.write_all(resp.as_bytes()).await;
                let _ = s.shutdown().await;
            });
        }
    }))
}
