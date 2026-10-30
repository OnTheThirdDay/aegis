//! The iPhone app (ADR-0019): Ad Hoc builds signed for the iPhones
//! registered on the Apple team, shared by every gateway.
//!
//! - The release workflow publishes the signed app encrypted
//!   (`aegis-client-ios.ipa.enc`, AES-256-GCM) on the repository's latest
//!   GitHub release; registering an iPhone re-signs it in place. Only
//!   gateways given the key can read it, so the profile inside, which lists
//!   every registered iPhone, stays private.
//! - This gateway fetches it with its GitHub token, decrypts it and serves
//!   it to its users' portal (`ios/app.ipa`).
//! - Users ask from the portal to register their iPhone; an administrator
//!   approves the request here, which starts the repository's `ios-device`
//!   workflow (repository dispatch). Neither the Apple key nor the signing
//!   certificate is on the gateway.
//! - A gateway that can't reach GitHub (its downloads are blocked in places)
//!   can reach it through another gateway: it joins that gateway as a device,
//!   with an invitation from it, and its GitHub requests go through a client
//!   of its own (a local HTTP proxy into the tunnel). Nothing else of its
//!   traffic changes.

use crate::services::Appliance;
use aegis_storage::now_unix;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

pub const ID: &str = "ios";
/// Where the decrypted app is kept, relative to the appliance directory
/// (the management API streams it from there).
pub const APP_FILE: &str = "ios/app.ipa";
const TOKEN: &str = "ios-github-token";
const KEY: &str = "ios-app-key";
const ASSET: &str = "aegis-client-ios.ipa.enc";
/// File format: magic, 12-byte nonce, ciphertext with its tag.
const MAGIC: &[u8] = b"AEGISIPA1";
const AAD: &[u8] = b"aegisborne-ipa/1";
const MAX_BYTES: u64 = 400 * 1024 * 1024;
/// Requests kept (pending, approved or failed).
const MAX_REQUESTS: usize = 500;
/// GitHub's API, while the console waits (under the gateway's 30-second
/// idle limit): reading the latest release, starting the workflow.
const API_TIMEOUT: Duration = Duration::from_secs(20);

fn err(status: u16, code: impl Into<String>) -> (u16, String) {
    (status, code.into())
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Settings {
    /// `owner/name` of the repository whose releases carry the app.
    repository: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Fetched {
    version: String,
    asset_id: u64,
    updated_at: String,
    fetched_at: i64,
    size: u64,
}

/// A user's request to register an iPhone.
#[derive(Clone, Serialize, Deserialize)]
struct Request {
    id: String,
    user: String,
    username: String,
    name: String,
    udid: String,
    product: String,
    ios: String,
    requested_at: i64,
    /// `pending`, `approved` (sent to GitHub) or `failed`.
    state: String,
    message: Option<String>,
}

pub struct IosIntegration {
    app: Weak<Appliance>,
    dir: PathBuf,
    /// Serialises changes to the files in `dir`.
    files: Mutex<()>,
    last_error: Mutex<Option<String>>,
    /// A fetch runs in the background; one at a time.
    fetching: AtomicBool,
    /// The client into the other gateway GitHub is reached through, while
    /// it runs.
    upstream: tokio::sync::Mutex<Option<aegis_node::NodeRuntime>>,
}

/// `host[:port]` of a URL.
fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    rest.split(['/', '?']).next().unwrap_or(rest).to_owned()
}

/// An iPhone UDID: 40 hex digits (older models) or `XXXXXXXX-XXXXXXXXXXXXXXXX`.
pub fn valid_udid(udid: &str) -> bool {
    let hex = |s: &str| s.bytes().all(|b| b.is_ascii_hexdigit());
    match udid.split_once('-') {
        None => udid.len() == 40 && hex(udid),
        Some((a, b)) => a.len() == 8 && b.len() == 16 && hex(a) && hex(b),
    }
}

fn valid_repository(r: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    };
    matches!(r.split_once('/'), Some((o, n)) if ok(o) && ok(n) && !n.contains('/'))
}

/// Decrypt a downloaded `.ipa.enc` with the 32-byte key.
pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let rest = data
        .strip_prefix(MAGIC)
        .ok_or("not an encrypted iPhone app")?;
    if rest.len() < 12 + 16 {
        return Err("the file is too short");
    }
    let (nonce, sealed) = rest.split_at(12);
    let key = UnboundKey::new(&AES_256_GCM, key).map_err(|_| "the key must be 32 bytes")?;
    let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| "bad nonce")?;
    let mut buf = sealed.to_vec();
    let plain = LessSafeKey::new(key)
        .open_in_place(nonce, Aad::from(AAD), &mut buf)
        .map_err(|_| "it doesn't decrypt with this key")?;
    Ok(plain.to_vec())
}

impl IosIntegration {
    pub fn new(app: Weak<Appliance>, appliance_dir: &Path) -> Self {
        let dir = appliance_dir.join("ios");
        let _ = std::fs::create_dir_all(&dir);
        IosIntegration {
            app,
            dir,
            files: Mutex::new(()),
            last_error: Mutex::new(None),
            fetching: AtomicBool::new(false),
            upstream: tokio::sync::Mutex::new(None),
        }
    }

    fn load<T: for<'de> Deserialize<'de> + Default>(&self, name: &str) -> T {
        std::fs::read(self.dir.join(name))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save<T: Serialize>(&self, name: &str, value: &T) -> Result<(), (u16, String)> {
        let path = self.dir.join(name);
        let tmp = path.with_extension("tmp");
        let text = serde_json::to_vec_pretty(value).map_err(|_| err(500, "serialize"))?;
        std::fs::write(&tmp, text)
            .and_then(|()| std::fs::rename(&tmp, &path))
            .map_err(|e| err(500, format!("{}: {}", path.display(), e.kind())))
    }

    fn secret(&self, name: &str) -> Option<String> {
        let app = self.app.upgrade()?;
        app.secrets
            .read(name)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    fn requests(&self) -> Vec<Request> {
        self.load::<Option<Vec<Request>>>("requests.json")
            .unwrap_or_default()
    }

    fn set_error(&self, e: Option<String>) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = e;
    }

    fn audit(&self, actor: &str, action: &'static str, metadata: Value) {
        if let Some(app) = self.app.upgrade() {
            app.audit(actor, action, metadata);
        }
    }

    pub fn status(&self) -> Value {
        let settings: Settings = self.load("settings.json");
        let fetched: Option<Fetched> = self.load("fetched.json");
        let configured = settings.repository.is_some()
            && self.secret(TOKEN).is_some()
            && self.secret(KEY).is_some();
        let error = self
            .last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let app_ready = fetched.is_some() && self.dir.join("app.ipa").is_file();
        json!({
            "id": ID,
            "name": "iPhone app",
            "description": "Ad Hoc builds of the iPhone app for registered iPhones: users register their iPhone in the portal, you approve it here, and they install the app from the portal.",
            "enabled": configured,
            "state": if !configured { "off" } else if error.is_some() { "error" } else if app_ready { "active" } else { "pending" },
            "fetching": self.fetching.load(Ordering::Relaxed),
            "repository": settings.repository,
            "via": self.upstream_dir().load().ok().map(|d| json!({
                "server": host_of(&d.url),
                "name": d.name,
                "certificate_expires_at": self.upstream_dir().certificate_expires_at().ok(),
            })),
            "has_token": self.secret(TOKEN).is_some(),
            "has_key": self.secret(KEY).is_some(),
            "app": if app_ready { serde_json::to_value(&fetched).unwrap_or(Value::Null) } else { Value::Null },
            "error": error,
            "requests": self.requests(),
        })
    }

    /// `{repository?, via?, token?, key?}`: the repository whose releases
    /// carry the app; `via`, an invitation from another gateway to reach
    /// GitHub through ("" to stop); a GitHub token that can read its
    /// releases and start its workflows; and the app's decryption key
    /// (base64, 32 bytes). Then fetches the app in the background.
    pub async fn configure(
        self: &Arc<Self>,
        actor: &str,
        body: Value,
    ) -> Result<Value, (u16, String)> {
        let app = self
            .app
            .upgrade()
            .ok_or_else(|| err(503, "appliance_unavailable"))?;
        {
            let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
            let mut settings: Settings = self.load("settings.json");
            if let Some(r) = body.get("repository").and_then(Value::as_str) {
                let r = r.trim();
                if !valid_repository(r) {
                    return Err(err(400, "the repository must look like owner/name"));
                }
                settings.repository = Some(r.to_owned());
            }
            self.save("settings.json", &settings)?;
        }
        if let Some(code) = body.get("via").and_then(Value::as_str) {
            self.set_via(code.trim()).await?;
        }
        if let Some(t) = body.get("token").and_then(Value::as_str).map(str::trim) {
            if t.is_empty() || t.len() > 512 || !t.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(err(400, "the token looks wrong"));
            }
            app.secrets.put(TOKEN, t, true).map_err(|e| err(500, e.0))?;
        }
        if let Some(k) = body.get("key").and_then(Value::as_str).map(str::trim) {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(k)
                .map_err(|_| err(400, "the key must be base64"))?;
            if raw.len() != 32 {
                return Err(err(400, "the key must be 32 bytes (base64)"));
            }
            app.secrets.put(KEY, k, true).map_err(|e| err(500, e.0))?;
        }
        self.audit(actor, "ios.configured", json!({}));
        self.set_error(None);
        let started = self.start_fetch();
        Ok(json!({ "fetching": started, "status": self.status() }))
    }

    /// Fetch in the background (the console never waits on GitHub, which can
    /// be slow or blocked). False when one is already running.
    pub fn start_fetch(self: &Arc<Self>) -> bool {
        if self.fetching.swap(true, Ordering::AcqRel) {
            return false;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let _ = me.fetch_now().await;
            me.fetching.store(false, Ordering::Release);
        });
        true
    }

    fn upstream_dir(&self) -> aegis_join::DeviceDir {
        aegis_join::DeviceDir::new(self.dir.join("upstream"))
    }

    /// Join another gateway (an invitation from it) to reach GitHub through,
    /// replacing any earlier one; "" stops using one.
    async fn set_via(&self, code: &str) -> Result<(), (u16, String)> {
        if let Some(node) = self.upstream.lock().await.take() {
            node.shutdown(Duration::from_secs(1)).await;
        }
        let dir = self.dir.join("upstream");
        let _ = std::fs::remove_dir_all(&dir);
        if code.is_empty() {
            return Ok(());
        }
        let invite = aegis_join::parse_invite(code).map_err(|e| err(400, e.to_string()))?;
        // Under the gateway's 30-second idle limit for the console.
        tokio::time::timeout(
            API_TIMEOUT,
            aegis_join::enroll(&invite, &aegis_join::DeviceDir::new(&dir)),
        )
        .await
        .map_err(|_| err(502, "the other gateway didn't answer in time"))?
        .map_err(|e| err(502, format!("joining the other gateway: {e}")))?;
        Ok(())
    }

    /// The local HTTP proxy into the other gateway, when one is set
    /// (starting its client the first time).
    async fn via(&self) -> Result<Option<String>, (u16, String)> {
        let dir = self.upstream_dir();
        if dir.load().is_err() {
            return Ok(None);
        }
        let mut node = self.upstream.lock().await;
        if node.is_none() {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(dir.root.join(format!("state.db{suffix}")));
            }
            let config = aegis_join::client_config(&dir, aegis_join::Ports { socks: 0, http: 0 })
                .map_err(|e| err(409, format!("the other gateway: {e}")))?;
            let started = aegis_node::start(aegis_node::StartOptions {
                config,
                store_path: dir.store(),
                failpoints: None,
            })
            .await
            .map_err(|e| err(502, format!("the other gateway: {e}")))?;
            *node = Some(started);
        }
        let addr = node
            .as_ref()
            .and_then(|n| n.bound_addr("http"))
            .ok_or_else(|| err(500, "the client into the other gateway has no proxy"))?;
        Ok(Some(format!("http://{addr}")))
    }

    /// Keep the device identity at the other gateway renewed.
    async fn renew_via(&self) {
        let dir = self.upstream_dir();
        if dir.load().is_ok() && matches!(aegis_join::renew_if_due(&dir, false).await, Ok(true)) {
            if let Some(node) = self.upstream.lock().await.as_ref() {
                let _ = node.ctx.reload_certificates();
            }
        }
    }

    /// For GitHub: through the other gateway, when one is set.
    async fn client(&self) -> Result<reqwest::Client, (u16, String)> {
        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("aegisborne/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(600));
        if let Some(proxy) = self.via().await? {
            builder =
                builder.proxy(reqwest::Proxy::all(&proxy).map_err(|e| err(500, e.to_string()))?);
        }
        builder
            .build()
            .map_err(|e| err(500, format!("HTTP client: {e}")))
    }

    fn github(&self) -> Result<(String, String), (u16, String)> {
        let settings: Settings = self.load("settings.json");
        let repo = settings
            .repository
            .ok_or_else(|| err(409, "set the repository first"))?;
        let token = self
            .secret(TOKEN)
            .ok_or_else(|| err(409, "set the GitHub token first"))?;
        Ok((repo, token))
    }

    /// Fetch the latest release's app when it changed (new release, or
    /// re-signed for a new iPhone). Quiet when not configured.
    pub async fn poll(self: &Arc<Self>) {
        self.renew_via().await;
        if self.github().is_ok() && self.secret(KEY).is_some() {
            self.start_fetch();
        }
    }

    /// "Check GitHub now": starts a fetch; the status shows the outcome.
    pub fn fetch(self: &Arc<Self>) -> Result<Value, (u16, String)> {
        self.github()?;
        let started = self.start_fetch();
        Ok(json!({ "fetching": true, "started": started }))
    }

    async fn fetch_now(&self) -> Result<Value, (u16, String)> {
        let result = self.fetch_inner().await;
        self.set_error(result.as_ref().err().map(|e| e.1.clone()));
        result
    }

    async fn fetch_inner(&self) -> Result<Value, (u16, String)> {
        let (repo, token) = self.github()?;
        let key = self
            .secret(KEY)
            .ok_or_else(|| err(409, "set the app key first"))?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| err(409, "the stored app key is not base64"))?;
        let client = self.client().await?;
        let body = client
            .get(format!(
                "https://api.github.com/repos/{repo}/releases/latest"
            ))
            .timeout(API_TIMEOUT)
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| err(502, format!("GitHub: {e}")))?
            .error_for_status()
            .map_err(|e| err(502, format!("GitHub: {e}")))?
            .bytes()
            .await
            .map_err(|e| err(502, format!("GitHub: {e}")))?;
        let release: Value =
            serde_json::from_slice(&body).map_err(|_| err(502, "GitHub: unexpected answer"))?;
        let tag = release["tag_name"].as_str().unwrap_or("");
        let Some(asset) = release["assets"]
            .as_array()
            .and_then(|a| a.iter().find(|x| x["name"] == ASSET))
        else {
            return Err(err(404, format!("release {tag} has no iPhone app yet")));
        };
        let id = asset["id"].as_u64().unwrap_or(0);
        let updated_at = asset["updated_at"].as_str().unwrap_or("").to_owned();
        let known: Option<Fetched> = self.load("fetched.json");
        let ipa = self.dir.join("app.ipa");
        if let Some(k) = &known {
            if k.asset_id == id && k.updated_at == updated_at && ipa.is_file() {
                return Ok(json!({ "version": k.version, "changed": false }));
            }
        }
        let size = asset["size"].as_u64().unwrap_or(0);
        if size > MAX_BYTES {
            return Err(err(502, "the app on GitHub is too large"));
        }
        let mut response = client
            .get(format!(
                "https://api.github.com/repos/{repo}/releases/assets/{id}"
            ))
            .bearer_auth(&token)
            .header("Accept", "application/octet-stream")
            .send()
            .await
            .map_err(|e| err(502, format!("download: {e}")))?
            .error_for_status()
            .map_err(|e| err(502, format!("download: {e}")))?;
        let mut data = Vec::with_capacity(size as usize);
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| err(502, format!("download: {e}")))?
        {
            if (data.len() + chunk.len()) as u64 > MAX_BYTES {
                return Err(err(502, "the app on GitHub is too large"));
            }
            data.extend_from_slice(&chunk);
        }
        let plain = tokio::task::spawn_blocking(move || decrypt(&key, &data))
            .await
            .map_err(|_| err(500, "decrypt"))?
            .map_err(|e| err(409, format!("The app {e}.")))?;
        let version = tag.trim_start_matches('v').to_owned();
        let fetched = Fetched {
            version: version.clone(),
            asset_id: id,
            updated_at,
            fetched_at: now_unix(),
            size: plain.len() as u64,
        };
        let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = self.dir.join("app.ipa.part");
        std::fs::write(&tmp, &plain)
            .and_then(|()| std::fs::rename(&tmp, &ipa))
            .map_err(|e| err(500, format!("{}: {}", ipa.display(), e.kind())))?;
        self.save("fetched.json", &Some(fetched))?;
        Ok(json!({ "version": version, "changed": true }))
    }

    /// From the portal: a user asks to register an iPhone (its UDID read by
    /// the registration profile). Asking again for the same iPhone keeps
    /// one request.
    pub fn request(&self, actor: &str, body: &Value) -> Result<Value, (u16, String)> {
        let s = |k: &str, max: usize| -> String {
            body.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(max)
                .collect()
        };
        let udid = s("udid", 64);
        if !valid_udid(&udid) {
            return Err(err(400, "not an iPhone UDID"));
        }
        let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let mut list = self.requests();
        if let Some(r) = list
            .iter()
            .find(|r| r.udid.eq_ignore_ascii_case(&udid) && r.state != "failed")
        {
            return Ok(json!({ "id": r.id, "state": r.state }));
        }
        list.retain(|r| !r.udid.eq_ignore_ascii_case(&udid));
        if list.len() >= MAX_REQUESTS {
            return Err(err(409, "too many iPhone requests"));
        }
        let name = match s("name", 60) {
            n if n.trim().is_empty() => "iPhone".to_owned(),
            n => n,
        };
        let r = Request {
            id: aegis_storage::new_id(),
            user: actor.to_owned(),
            username: s("username", 64),
            name,
            udid,
            product: s("product", 32),
            ios: s("ios", 16),
            requested_at: now_unix(),
            state: "pending".into(),
            message: None,
        };
        let out = json!({ "id": r.id, "state": r.state });
        list.push(r);
        self.save("requests.json", &Some(list))?;
        drop(_guard);
        self.audit(actor, "ios.device_requested", json!({}));
        Ok(out)
    }

    /// The signed-in user's requests (portal).
    pub fn mine(&self, actor: &str) -> Value {
        let list: Vec<Value> = self
            .requests()
            .into_iter()
            .filter(|r| r.user == actor)
            .map(|r| json!({"id": r.id, "name": r.name, "product": r.product, "state": r.state, "requested_at": r.requested_at}))
            .collect();
        let fetched: Option<Fetched> = self.load("fetched.json");
        let available = fetched.filter(|_| self.dir.join("app.ipa").is_file());
        let settings: Settings = self.load("settings.json");
        json!({
            // Set up on this gateway (the portal shows the iPhone app only then).
            "enabled": settings.repository.is_some() && self.secret(TOKEN).is_some(),
            "requests": list,
            "app": available.map(|f| json!({"version": f.version, "size": f.size})),
        })
    }

    /// Approve: start the repository's `ios-device` workflow, which registers
    /// the iPhone with Apple and re-signs the app for it.
    pub async fn approve(&self, actor: &str, body: &Value) -> Result<Value, (u16, String)> {
        let id = body
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let request = self
            .requests()
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| err(404, "no such request"))?;
        let (repo, token) = self.github()?;
        let response = self
            .client()
            .await?
            .post(format!("https://api.github.com/repos/{repo}/dispatches"))
            .timeout(API_TIMEOUT)
            .bearer_auth(&token)
            .header("Accept", "application/vnd.github+json")
            .header("Content-Type", "application/json")
            .body(
                json!({
                    "event_type": "ios-device",
                    "client_payload": {"name": request.name, "udid": request.udid},
                })
                .to_string(),
            )
            .send()
            .await
            .map_err(|e| err(502, format!("Could not reach GitHub ({e}). If this server can't reach it directly, reach it through another gateway.")))?;
        let ok = response.status().is_success();
        let message = if ok {
            "Sent to GitHub: the iPhone is registered and the app re-signed within a few minutes."
                .to_owned()
        } else {
            format!(
                "GitHub refused to start the workflow ({}). The token needs Contents: read and write on {repo}.",
                response.status()
            )
        };
        {
            let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
            let mut list = self.requests();
            if let Some(r) = list.iter_mut().find(|r| r.id == id) {
                r.state = if ok { "approved" } else { "failed" }.into();
                r.message = Some(message.clone());
            }
            self.save("requests.json", &Some(list))?;
        }
        self.audit(actor, "ios.device_approved", json!({ "sent": ok }));
        if ok {
            Ok(json!({ "message": message }))
        } else {
            Err(err(502, message))
        }
    }

    pub fn reject(&self, actor: &str, body: &Value) -> Result<Value, (u16, String)> {
        let id = body.get("id").and_then(Value::as_str).unwrap_or("");
        let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
        let mut list = self.requests();
        let before = list.len();
        list.retain(|r| r.id != id);
        if list.len() == before {
            return Err(err(404, "no such request"));
        }
        self.save("requests.json", &Some(list))?;
        drop(_guard);
        self.audit(actor, "ios.device_rejected", json!({}));
        Ok(json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udids_and_repositories() {
        assert!(valid_udid("447c2b96bb63020799bbd2c659a98af8edf3b525"));
        assert!(valid_udid("00008030-001A35E40C3A802E"));
        assert!(!valid_udid("00008030-001A35E40C3A802"));
        assert!(!valid_udid("not-a-udid"));
        assert!(!valid_udid(""));
        assert!(valid_repository("OnTheThirdDay/aegis"));
        assert!(!valid_repository("aegis"));
        assert!(!valid_repository("a/b/c"));
        assert!(!valid_repository("a/../b"));
    }

    #[test]
    fn the_app_decrypts_only_with_its_key() {
        use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut sealed = b"the app".to_vec();
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).expect("key"))
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(AAD),
                &mut sealed,
            )
            .expect("seal");
        let file = [MAGIC, &nonce, &sealed].concat();
        assert_eq!(decrypt(&key, &file).expect("decrypt"), b"the app");
        assert!(decrypt(&[8u8; 32], &file).is_err());
        assert!(decrypt(&key, &file[1..]).is_err());
        // As the release workflow encrypts it (.github/scripts/ios-ipa-crypt.py).
        let python = hex::decode("4145474953495041310909090909090909090909094ae4e0f19e92b841d01bbf508984c9e746ff5c2de414345acfb016a6c239").expect("hex");
        assert_eq!(decrypt(&key, &python).expect("decrypt"), b"made by python");
    }
}
