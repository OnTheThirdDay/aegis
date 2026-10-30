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
//! - An approved iPhone is "ready to install" once the app on this gateway
//!   was signed for it: its UDID is in the provisioning profiles inside.
//!   While one is being prepared, the gateway checks GitHub every minute
//!   instead of every 10.
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
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
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
/// How often the app is checked for on GitHub, and how often while an
/// approved iPhone is being prepared (registered and re-signed for).
const POLL_EVERY: i64 = 600;
pub const POLL_PREPARING: Duration = Duration::from_secs(60);
/// How long preparing an iPhone may take before it shows as delayed.
const PREPARING: i64 = 30 * 60;

fn err(status: u16, code: impl Into<String>) -> (u16, String) {
    (status, code.into())
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Settings {
    /// `owner/name` of the repository whose releases carry the app.
    repository: Option<String>,
    /// Approve users' iPhones as soon as they register, up to
    /// `auto_per_user` approved iPhones each; beyond that they wait.
    #[serde(default)]
    auto_approve: bool,
    #[serde(default)]
    auto_per_user: Option<u32>,
}

/// iPhones a user gets approved automatically, unless set otherwise.
const AUTO_PER_USER: u32 = 2;

impl Settings {
    fn per_user(&self) -> u32 {
        self.auto_per_user.unwrap_or(AUTO_PER_USER)
    }
}

/// Whether `user`'s new request may be approved automatically: below the
/// number of iPhones each user gets without the administrator. Requests
/// still being approved automatically count too, so that several sent at
/// once can't all pass before the first is approved.
fn auto_allowed(requests: &[Request], user: &str, limit: u32) -> bool {
    let taken = requests
        .iter()
        .filter(|r| r.user == user && (r.state == "approved" || (r.state == "pending" && r.auto)))
        .count();
    taken < limit as usize
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Fetched {
    version: String,
    asset_id: u64,
    updated_at: String,
    fetched_at: i64,
    size: u64,
    /// The iPhones (UDIDs, upper case) the app installs on; None when they
    /// couldn't be read.
    #[serde(default)]
    devices: Option<Vec<String>>,
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
    #[serde(default)]
    approved_at: Option<i64>,
    /// Being approved automatically: counts toward the user's automatic
    /// iPhones while GitHub is asked (see [`auto_allowed`]).
    #[serde(default)]
    auto: bool,
}

/// Where an iPhone stands: `pending`, `failed`, `ready` (the app here
/// installs on it), `preparing` (approved, being registered and re-signed
/// for), `delayed` (still not in the app after a while) or `approved`
/// (when the app's iPhones are unknown).
fn stage(r: &Request, devices: Option<&[String]>, now: i64) -> &'static str {
    match (r.state.as_str(), devices) {
        ("approved", None) => "approved",
        ("approved", Some(d)) if d.iter().any(|u| u.eq_ignore_ascii_case(&r.udid)) => "ready",
        ("approved", Some(_)) if now - r.approved_at.unwrap_or(r.requested_at) < PREPARING => {
            "preparing"
        }
        ("approved", Some(_)) => "delayed",
        ("failed", _) => "failed",
        _ => "pending",
    }
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
    /// When `poll` last checked on its regular schedule.
    last_poll: AtomicI64,
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

const BAD_ZIP: &str = "the app isn't a readable zip file";

/// The files in a zip (an `.ipa`) whose names `want` picks, uncompressed.
fn zip_files(zip: &[u8], want: impl Fn(&str) -> bool) -> Result<Vec<Vec<u8>>, &'static str> {
    let u16_at = |i: usize| {
        zip.get(i..i + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
            .ok_or(BAD_ZIP)
    };
    let u32_at = |i: usize| {
        zip.get(i..i + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
            .ok_or(BAD_ZIP)
    };
    // The end of the central directory: 22 bytes and a comment (< 64 KiB).
    let from = zip.len().saturating_sub(22 + 0xffff);
    let end = (from..zip.len().saturating_sub(21))
        .rev()
        .find(|&i| u32_at(i) == Ok(0x0605_4b50))
        .ok_or(BAD_ZIP)?;
    let mut at = u32_at(end + 16)?;
    let mut out = Vec::new();
    for _ in 0..u16_at(end + 10)? {
        if u32_at(at)? != 0x0201_4b50 {
            return Err(BAD_ZIP);
        }
        let (method, compressed, size) = (u16_at(at + 10)?, u32_at(at + 20)?, u32_at(at + 24)?);
        let name_len = u16_at(at + 28)?;
        let local = u32_at(at + 42)?;
        let name = zip.get(at + 46..at + 46 + name_len).ok_or(BAD_ZIP)?;
        at += 46 + name_len + u16_at(at + 30)? + u16_at(at + 32)?;
        if !want(&String::from_utf8_lossy(name)) {
            continue;
        }
        if size > 16 << 20 || u32_at(local)? != 0x0403_4b50 {
            return Err(BAD_ZIP);
        }
        let start = local + 30 + u16_at(local + 26)? + u16_at(local + 28)?;
        let data = zip.get(start..start + compressed).ok_or(BAD_ZIP)?;
        out.push(match method {
            0 => data.to_vec(),
            8 => {
                let mut plain = Vec::with_capacity(size);
                flate2::read::DeflateDecoder::new(data)
                    .take(size as u64)
                    .read_to_end(&mut plain)
                    .map_err(|_| BAD_ZIP)?;
                plain
            }
            _ => return Err(BAD_ZIP),
        });
    }
    Ok(out)
}

/// The UDIDs (upper case) a provisioning profile lists: it's a signed
/// plist, readable as text.
fn profile_devices(profile: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(profile);
    let Some((list, _)) = text
        .split_once("<key>ProvisionedDevices</key>")
        .and_then(|(_, rest)| rest.split_once("</array>"))
    else {
        return Vec::new();
    };
    list.split("<string>")
        .skip(1)
        .filter_map(|s| s.split_once("</string>"))
        .map(|(u, _)| u.trim().to_ascii_uppercase())
        .collect()
}

/// The iPhones an Ad Hoc app installs on: those in every provisioning
/// profile inside it (the app's and its extension's).
pub fn provisioned_devices(ipa: &[u8]) -> Result<Vec<String>, &'static str> {
    let profiles = zip_files(ipa, |name| name.ends_with("/embedded.mobileprovision"))?;
    let mut profiles = profiles.iter().map(|p| profile_devices(p));
    let first = profiles
        .next()
        .ok_or("no provisioning profile in the app")?;
    Ok(profiles.fold(first, |common, devices| {
        common.into_iter().filter(|d| devices.contains(d)).collect()
    }))
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
            last_poll: AtomicI64::new(0),
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

    /// Requests as JSON, each with its `stage`.
    fn staged(&self, requests: Vec<Request>, fetched: Option<&Fetched>) -> Vec<Value> {
        let devices = fetched
            .filter(|_| self.dir.join("app.ipa").is_file())
            .and_then(|f| f.devices.as_deref());
        let now = now_unix();
        requests
            .into_iter()
            .map(|r| {
                let stage = stage(&r, devices, now);
                let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
                v["stage"] = stage.into();
                v
            })
            .collect()
    }

    /// Whether an approved iPhone is being prepared (so GitHub is checked
    /// more often).
    fn preparing(&self) -> bool {
        let fetched: Option<Fetched> = self.load("fetched.json");
        self.staged(self.requests(), fetched.as_ref())
            .iter()
            .any(|r| r["stage"] == "preparing")
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
            "auto_approve": settings.auto_approve,
            "auto_per_user": settings.per_user(),
            "via": self.upstream_dir().load().ok().map(|d| json!({
                "server": host_of(&d.url),
                "name": d.name,
                "certificate_expires_at": self.upstream_dir().certificate_expires_at().ok(),
            })),
            "has_token": self.secret(TOKEN).is_some(),
            "has_key": self.secret(KEY).is_some(),
            "app": fetched.as_ref().filter(|_| app_ready).map(|f| json!({
                "version": f.version,
                "updated_at": f.updated_at,
                "fetched_at": f.fetched_at,
                "size": f.size,
            })),
            "error": error,
            "requests": self.staged(self.requests(), fetched.as_ref()),
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
            if let Some(on) = body.get("auto_approve").and_then(Value::as_bool) {
                settings.auto_approve = on;
            }
            if let Some(n) = body.get("auto_per_user").and_then(Value::as_u64) {
                if !(1..=10).contains(&n) {
                    return Err(err(400, "iPhones per user: 1 to 10"));
                }
                settings.auto_per_user = Some(n as u32);
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
    /// replacing any earlier one; "" stops using one. The earlier one stays
    /// until the new one joined: a mistyped or expired invitation, or an
    /// unreachable gateway, leaves the working setup as it was.
    async fn set_via(&self, code: &str) -> Result<(), (u16, String)> {
        let dir = self.dir.join("upstream");
        if code.is_empty() {
            if let Some(node) = self.upstream.lock().await.take() {
                node.shutdown(Duration::from_secs(1)).await;
            }
            let _ = std::fs::remove_dir_all(&dir);
            return Ok(());
        }
        let invite = aegis_join::parse_invite(code).map_err(|e| err(400, e.to_string()))?;
        let next = self.dir.join("upstream.next");
        let _ = std::fs::remove_dir_all(&next);
        // Under the gateway's 30-second idle limit for the console.
        let joined = tokio::time::timeout(
            API_TIMEOUT,
            aegis_join::enroll(&invite, &aegis_join::DeviceDir::new(&next)),
        )
        .await
        .map_err(|_| err(502, "the other gateway didn't answer in time"))
        .and_then(|r| r.map_err(|e| err(502, format!("joining the other gateway: {e}"))));
        if let Err(e) = joined {
            let _ = std::fs::remove_dir_all(&next);
            return Err(e);
        }
        let mut node = self.upstream.lock().await;
        if let Some(old) = node.take() {
            old.shutdown(Duration::from_secs(1)).await;
        }
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::rename(&next, &dir)
            .map_err(|e| err(500, format!("keeping the new identity: {e}")))?;
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
    /// re-signed for a new iPhone). Quiet when not configured. Called every
    /// `POLL_PREPARING`; checks every `POLL_EVERY` unless an iPhone is being
    /// prepared.
    pub async fn poll(self: &Arc<Self>) {
        let now = now_unix();
        if now - self.last_poll.load(Ordering::Relaxed) >= POLL_EVERY {
            self.last_poll.store(now, Ordering::Relaxed);
            self.renew_via().await;
        } else if !self.preparing() {
            return;
        }
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
                if k.devices.is_none() {
                    let path = ipa.clone();
                    let devices = tokio::task::spawn_blocking(move || {
                        provisioned_devices(&std::fs::read(path).ok()?).ok()
                    })
                    .await
                    .ok()
                    .flatten();
                    if devices.is_some() {
                        let _guard = self.files.lock().unwrap_or_else(|e| e.into_inner());
                        let fetched = Fetched {
                            devices,
                            ..k.clone()
                        };
                        self.save("fetched.json", &Some(fetched))?;
                    }
                }
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
        let (plain, devices) = tokio::task::spawn_blocking(move || {
            decrypt(&key, &data).map(|plain| {
                let devices = provisioned_devices(&plain).ok();
                (plain, devices)
            })
        })
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
            devices,
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
    pub fn request(self: &Arc<Self>, actor: &str, body: &Value) -> Result<Value, (u16, String)> {
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
            approved_at: None,
            auto: false,
        };
        let settings: Settings = self.load("settings.json");
        let auto = settings.auto_approve && auto_allowed(&list, actor, settings.per_user());
        // Reserved under the same lock that checked the limit.
        let r = Request { auto, ..r };
        let id = r.id.clone();
        list.push(r);
        self.save("requests.json", &Some(list))?;
        drop(_guard);
        self.audit(actor, "ios.device_requested", json!({ "auto": auto }));
        if auto {
            // Approved in the background: the request answers iOS at once.
            let (me, actor, request) = (Arc::clone(self), actor.to_owned(), json!({ "id": id }));
            tokio::spawn(async move {
                let _ = me.approve(&actor, &request).await;
            });
        }
        Ok(json!({ "id": id, "state": "pending", "auto": auto }))
    }

    /// The signed-in user's requests (portal).
    pub fn mine(&self, actor: &str) -> Value {
        let fetched: Option<Fetched> = self.load("fetched.json");
        let mine = self
            .requests()
            .into_iter()
            .filter(|r| r.user == actor)
            .collect();
        let list: Vec<Value> = self
            .staged(mine, fetched.as_ref())
            .into_iter()
            .map(|r| json!({"id": r["id"], "name": r["name"], "product": r["product"], "state": r["state"], "stage": r["stage"], "requested_at": r["requested_at"]}))
            .collect();
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
                r.approved_at = ok.then(now_unix);
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
    fn automatic_approval_stops_at_the_limit() {
        let r = |user: &str, state: &str| Request {
            id: "x".into(),
            user: user.into(),
            username: String::new(),
            name: String::new(),
            udid: String::new(),
            product: String::new(),
            ios: String::new(),
            requested_at: 0,
            state: state.into(),
            message: None,
            approved_at: None,
            auto: false,
        };
        let list = vec![
            r("alice", "approved"),
            r("alice", "pending"),
            r("bob", "approved"),
        ];
        assert!(
            auto_allowed(&list, "alice", 2),
            "one approved, a second is fine"
        );
        assert!(!auto_allowed(
            &[r("alice", "approved"), r("alice", "approved")],
            "alice",
            2
        ));
        assert!(auto_allowed(&list, "carol", 2));
        assert!(!auto_allowed(&list, "bob", 1));
        // Requests being approved automatically hold their place.
        let mut reserved = r("carol", "pending");
        reserved.auto = true;
        let list = vec![reserved.clone(), reserved];
        assert!(!auto_allowed(&list, "carol", 2));
        assert!(auto_allowed(&list, "carol", 3));
    }

    #[test]
    fn the_app_lists_the_iphones_it_installs_on() {
        // Made by Python's zipfile: the app's profile (compressed) lists two
        // iPhones, the extension's (stored) one of them.
        let ipa = include_bytes!("testdata/profiles.ipa");
        assert_eq!(
            provisioned_devices(ipa).expect("profiles"),
            ["447C2B96BB63020799BBD2C659A98AF8EDF3B525"]
        );
        assert!(provisioned_devices(b"not a zip").is_err());
        assert!(provisioned_devices(&ipa[..ipa.len() - 30]).is_err());
    }

    #[test]
    fn an_approved_iphone_is_ready_once_the_app_has_it() {
        let mut r = Request {
            id: "x".into(),
            user: "alice".into(),
            username: String::new(),
            name: String::new(),
            udid: "447c2b96bb63020799bbd2c659a98af8edf3b525".into(),
            product: String::new(),
            ios: String::new(),
            requested_at: 0,
            state: "pending".into(),
            message: None,
            approved_at: None,
            auto: false,
        };
        let has = vec!["447C2B96BB63020799BBD2C659A98AF8EDF3B525".to_owned()];
        assert_eq!(stage(&r, Some(&has), 100), "pending");
        r.state = "approved".into();
        r.approved_at = Some(100);
        assert_eq!(stage(&r, Some(&[]), 200), "preparing");
        assert_eq!(stage(&r, Some(&[]), 100 + PREPARING), "delayed");
        assert_eq!(stage(&r, Some(&has), 200), "ready");
        assert_eq!(stage(&r, None, 200), "approved");
    }

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
