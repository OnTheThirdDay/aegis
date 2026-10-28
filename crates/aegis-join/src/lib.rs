//! Device side of "join a gateway": import an invitation code, enroll with a
//! locally generated key, renew with the same key before expiry, and build
//! the client profile the node runs.
//!
//! Trust model:
//! * The invitation pins the device trust anchor (SHA-256 of the root) and,
//!   for a private edge, the edge CA and the name its certificate carries.
//! * Enrollment runs over TLS verified against that pin (or public roots for
//!   a publicly certified edge), so the one-use token is never sent in clear.
//! * The returned chain must end in the pinned anchor and carry our key.
//! * The private key never leaves the device directory.
#![forbid(unsafe_code)]

mod http;

use aegis_identity::pki;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const INVITE_PREFIX: &str = "aegis1:";
/// Renew when less than this remains (certificates last 30 days).
pub const RENEW_BEFORE_SECONDS: i64 = 10 * 86_400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinError {
    InvalidInvite(&'static str),
    InviteExpired,
    Network(String),
    Rejected { status: u16, code: String },
    Untrusted(&'static str),
    Storage(String),
    NotEnrolled,
}

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoinError::InvalidInvite(why) => write!(f, "invalid invitation code: {why}"),
            JoinError::InviteExpired => {
                f.write_str("the invitation has expired; ask for a new one")
            }
            JoinError::Network(e) => write!(f, "could not reach the server: {e}"),
            JoinError::Rejected { status, code } => {
                write!(f, "the server rejected the request ({status}): {code}")
            }
            JoinError::Untrusted(why) => write!(f, "server response failed verification: {why}"),
            JoinError::Storage(e) => write!(f, "could not save device files: {e}"),
            JoinError::NotEnrolled => f.write_str("this device is not enrolled"),
        }
    }
}

impl std::error::Error for JoinError {}

/// Decoded invitation. Nothing in it is a long-term secret; the token is
/// one-use, name-bound and expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub v: u32,
    pub name: String,
    pub token: String,
    pub expires_at: i64,
    pub url: String,
    pub enroll_url: String,
    pub server_name: String,
    #[serde(default)]
    pub outer_server_name: Option<String>,
    #[serde(default)]
    pub outer_ca_pem: Option<String>,
    pub device_ca_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<String>,
}

impl Invite {
    pub fn endpoint(&self) -> Endpoint {
        Endpoint {
            url: self.url.clone(),
            enroll_url: self.enroll_url.clone(),
            server_name: self.server_name.clone(),
            outer_server_name: self.outer_server_name.clone(),
            outer_ca_pem: self.outer_ca_pem.clone(),
            device_ca_sha256: self.device_ca_sha256.clone(),
            quic: self.quic.clone(),
        }
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Where and how a device reaches its gateway: the non-secret part of an
/// invitation, which the gateway also serves to enrolled devices so they
/// can follow address changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub url: String,
    pub enroll_url: String,
    pub server_name: String,
    #[serde(default)]
    pub outer_server_name: Option<String>,
    #[serde(default)]
    pub outer_ca_pem: Option<String>,
    pub device_ca_sha256: String,
    /// `host:port` of the gateway's direct QUIC (UDP) listener, when the
    /// administrator turned it on. Tried first; `url` stays the fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<String>,
}

impl Endpoint {
    fn check(&self) -> Result<(), &'static str> {
        if self.device_ca_sha256.len() != 64
            || !self.device_ca_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !self.url.starts_with("wss://")
            || !self.enroll_url.starts_with("https://")
            || self.url.len() > 2048
            || self.enroll_url.len() > 2048
            || aegis_contracts::destination::normalize_domain(&self.server_name).as_ref()
                != Ok(&self.server_name)
        {
            return Err("missing or malformed fields");
        }
        if self.outer_server_name.is_some() != self.outer_ca_pem.is_some() {
            return Err("incomplete edge trust");
        }
        if self
            .quic
            .as_deref()
            .is_some_and(|q| q.len() > 300 || aegis_config::quic_address(q).is_none())
        {
            return Err("malformed QUIC address");
        }
        if let Some(ca) = &self.outer_ca_pem {
            aegis_identity::tls::parse_certs(ca).map_err(|_| "bad edge certificate")?;
        }
        Ok(())
    }
}

/// Parse and validate an invitation code (whitespace tolerant).
pub fn parse_invite(code: &str) -> Result<Invite, JoinError> {
    // Pasted text and some shells add a byte-order mark or zero-width
    // characters; none can occur inside a valid code.
    let compact: String = code
        .chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(c, '\u{feff}' | '\u{200b}'..='\u{200d}' | '\u{2060}')
        })
        .collect();
    let body = compact
        .strip_prefix(INVITE_PREFIX)
        .ok_or(JoinError::InvalidInvite("it must start with aegis1:"))?;
    if body.len() > 16 * 1024 {
        return Err(JoinError::InvalidInvite("too long"));
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| JoinError::InvalidInvite("not valid base64url"))?;
    let invite: Invite = serde_json::from_slice(&bytes)
        .map_err(|_| JoinError::InvalidInvite("unexpected contents"))?;
    if invite.v != 1 {
        return Err(JoinError::InvalidInvite("unsupported version"));
    }
    if !aegis_identity::valid_node_id(&invite.name)
        || invite.token.is_empty()
        || invite.token.len() > 256
    {
        return Err(JoinError::InvalidInvite("missing or malformed fields"));
    }
    invite
        .endpoint()
        .check()
        .map_err(JoinError::InvalidInvite)?;
    if invite.expires_at <= now() {
        return Err(JoinError::InviteExpired);
    }
    Ok(invite)
}

/// Persistent, non-secret description of an enrolled device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub name: String,
    pub url: String,
    pub enroll_url: String,
    pub server_name: String,
    #[serde(default)]
    pub outer_server_name: Option<String>,
    pub device_ca_sha256: String,
    pub enrolled_at: i64,
    /// The gateway's direct QUIC address, when it offers one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quic: Option<String>,
}

impl Device {
    pub fn renew_url(&self) -> String {
        match self.enroll_url.strip_suffix("/enroll") {
            Some(base) => format!("{base}/renew"),
            None => self.enroll_url.clone(),
        }
    }

    fn edge(&self, outer_ca: Option<String>) -> http::Edge {
        http::Edge {
            outer_server_name: self.outer_server_name.clone(),
            outer_ca_pem: outer_ca,
        }
    }
}

/// On-disk layout of one device profile.
#[derive(Clone, Debug)]
pub struct DeviceDir {
    pub root: PathBuf,
}

impl DeviceDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        DeviceDir { root: root.into() }
    }
    pub fn secrets(&self) -> PathBuf {
        self.root.join("secrets")
    }
    fn identity(&self) -> PathBuf {
        self.secrets().join("identity")
    }
    pub fn device_file(&self) -> PathBuf {
        self.root.join("device.json")
    }
    pub fn store(&self) -> PathBuf {
        self.root.join("state.db")
    }

    pub fn load(&self) -> Result<Device, JoinError> {
        let text =
            std::fs::read_to_string(self.device_file()).map_err(|_| JoinError::NotEnrolled)?;
        serde_json::from_str(&text).map_err(|_| JoinError::NotEnrolled)
    }

    fn read(&self, name: &str) -> Result<String, JoinError> {
        std::fs::read_to_string(self.identity().join(name))
            .map_err(|e| JoinError::Storage(format!("{name}: {}", e.kind())))
    }

    /// Certificate expiry (unix seconds) of the current device certificate.
    pub fn certificate_expires_at(&self) -> Result<i64, JoinError> {
        let cert = self.read("cert.pem")?;
        let certs = aegis_identity::tls::parse_certs(&cert)
            .map_err(|_| JoinError::Storage("certificate unreadable".into()))?;
        aegis_identity::tls::certificate_expiry(certs[0].as_ref())
            .map_err(|_| JoinError::Storage("certificate unreadable".into()))
    }

    /// Remove every file of this profile (forget the device locally).
    pub fn forget(&self) -> Result<(), JoinError> {
        for p in [self.device_file(), self.store()] {
            let _ = std::fs::remove_file(p);
        }
        for suffix in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(self.root.join(format!("state.db{suffix}")));
        }
        match std::fs::remove_dir_all(self.secrets()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(JoinError::Storage(e.kind().to_string())),
        }
    }
}

/// Every server this device joined, one profile each, and which one the
/// client connects to (one at a time). Layout under `root`:
///
/// * `servers/<id>/`: a [`DeviceDir`];
/// * `servers/selected`: the selected id.
///
/// The id is derived from the gateway's device CA and the device name, so
/// joining the same gateway under the same name twice is refused. A single
/// profile kept directly in `root` by earlier versions is moved in on open.
#[derive(Clone, Debug)]
pub struct Servers {
    root: PathBuf,
}

/// One joined server.
#[derive(Clone, Debug)]
pub struct Server {
    pub id: String,
    pub device: Device,
    pub dir: DeviceDir,
}

impl Server {
    /// The gateway's address as shown to the user (`host[:port]`).
    pub fn host(&self) -> String {
        let rest = self
            .device
            .url
            .split_once("://")
            .map_or(self.device.url.as_str(), |(_, r)| r);
        rest.split(['/', '?']).next().unwrap_or(rest).to_owned()
    }
}

fn server_id(device_ca_sha256: &str, name: &str) -> String {
    sha256_hex(format!("{}/{name}", device_ca_sha256.to_ascii_lowercase()).as_bytes())[..16]
        .to_owned()
}

fn valid_server_id(id: &str) -> bool {
    id.len() == 16 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Servers {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, JoinError> {
        let servers = Servers { root: root.into() };
        servers.migrate()?;
        Ok(servers)
    }

    fn base(&self) -> PathBuf {
        self.root.join("servers")
    }

    fn selection(&self) -> PathBuf {
        self.base().join("selected")
    }

    /// Move a profile from directly in `root` (one server per device) into
    /// `servers/<id>/`, unchanged.
    fn migrate(&self) -> Result<(), JoinError> {
        let legacy = DeviceDir::new(&self.root);
        let Ok(device) = legacy.load() else {
            return Ok(());
        };
        let id = server_id(&device.device_ca_sha256, &device.name);
        let target = DeviceDir::new(self.base().join(&id));
        if target.device_file().exists() {
            return Err(JoinError::Storage(format!(
                "{} holds two copies of the same server",
                self.root.display()
            )));
        }
        private_dir(&self.base())?;
        private_dir(&target.root)?;
        let moved = |from: PathBuf, to: PathBuf| match std::fs::rename(&from, to) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(JoinError::Storage(format!(
                "moving {}: {}",
                from.display(),
                e.kind()
            ))),
        };
        moved(legacy.secrets(), target.secrets())?;
        // The device file last: until it moves, the old layout is complete.
        moved(legacy.device_file(), target.device_file())?;
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(self.root.join(format!("state.db{suffix}")));
        }
        if self.selected().is_none() {
            self.select(&id)?;
        }
        Ok(())
    }

    /// Joined servers, oldest first.
    pub fn list(&self) -> Vec<Server> {
        let Ok(entries) = std::fs::read_dir(self.base()) else {
            return Vec::new();
        };
        let mut out: Vec<Server> = entries
            .filter_map(Result::ok)
            .filter_map(|e| self.get(e.file_name().to_str()?))
            .collect();
        out.sort_by(|a, b| (a.device.enrolled_at, &a.id).cmp(&(b.device.enrolled_at, &b.id)));
        out
    }

    pub fn get(&self, id: &str) -> Option<Server> {
        if !valid_server_id(id) {
            return None;
        }
        let dir = DeviceDir::new(self.base().join(id));
        let device = dir.load().ok()?;
        Some(Server {
            id: id.to_owned(),
            device,
            dir,
        })
    }

    /// The server to connect to: the one chosen last, else the oldest.
    pub fn selected(&self) -> Option<Server> {
        std::fs::read_to_string(self.selection())
            .ok()
            .and_then(|id| self.get(id.trim()))
            .or_else(|| self.list().into_iter().next())
    }

    pub fn select(&self, id: &str) -> Result<Server, JoinError> {
        let server = self.get(id).ok_or(JoinError::NotEnrolled)?;
        private_dir(&self.base())?;
        write_private(&self.selection(), id)?;
        Ok(server)
    }

    /// Join another server with an invitation and select it.
    pub async fn join(&self, invite: &Invite) -> Result<Server, JoinError> {
        let id = server_id(&invite.device_ca_sha256, &invite.name);
        if let Some(existing) = self.get(&id) {
            return Err(JoinError::Storage(format!(
                "this device already joined {} as \"{}\"; remove it first to join again",
                existing.host(),
                existing.device.name
            )));
        }
        private_dir(&self.base())?;
        let dir = DeviceDir::new(self.base().join(&id));
        enroll(invite, &dir).await?;
        self.select(&id)
    }

    /// Forget a server: its identity and files are deleted from this device.
    pub fn remove(&self, id: &str) -> Result<(), JoinError> {
        if !valid_server_id(id) {
            return Err(JoinError::NotEnrolled);
        }
        let dir = DeviceDir::new(self.base().join(id));
        dir.forget()?;
        match std::fs::remove_dir_all(&dir.root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(JoinError::Storage(e.kind().to_string())),
        }
        let selected = std::fs::read_to_string(self.selection()).unwrap_or_default();
        if selected.trim() == id {
            let _ = std::fs::remove_file(self.selection());
        }
        Ok(())
    }
}

fn private_dir(path: &Path) -> Result<(), JoinError> {
    std::fs::create_dir_all(path).map_err(|e| JoinError::Storage(e.kind().to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| JoinError::Storage(e.kind().to_string()))?;
    }
    Ok(())
}

/// Atomic owner-only write.
fn write_private(path: &Path, value: &str) -> Result<(), JoinError> {
    use std::io::Write;
    let tmp = path.with_extension("tmp-write");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        JoinError::Storage(e.kind().to_string())
    })
}

/// Verify an issued chain: it ends in the pinned anchor, chains to it as a
/// client certificate, and carries our key. Returns `(chain, anchor)`.
fn verify_issued(
    response: &Value,
    pin: &str,
    key_pem: &str,
    name: &str,
) -> Result<(String, String), JoinError> {
    let chain = response["certificate_pem"]
        .as_str()
        .ok_or(JoinError::Untrusted("no certificate"))?;
    let anchor = response["trust_anchor_pem"]
        .as_str()
        .ok_or(JoinError::Untrusted("no trust anchor"))?;
    let anchor_der =
        aegis_identity::tls::parse_certs(anchor).map_err(|_| JoinError::Untrusted("bad anchor"))?;
    if !sha256_hex(anchor_der[anchor_der.len() - 1].as_ref()).eq_ignore_ascii_case(pin) {
        return Err(JoinError::Untrusted(
            "server trust anchor does not match the invitation",
        ));
    }
    let peer = aegis_identity::tls::validate_client_certificate(chain, anchor)
        .map_err(|_| JoinError::Untrusted("certificate does not chain to the anchor"))?;
    let leaf = aegis_identity::tls::parse_certs(chain)
        .map_err(|_| JoinError::Untrusted("bad certificate"))?;
    if peer.node_id != name || !pki::certificate_matches_key(leaf[0].as_ref(), key_pem) {
        return Err(JoinError::Untrusted(
            "certificate is not for this device key",
        ));
    }
    Ok((chain.to_owned(), anchor.to_owned()))
}

fn rejected(status: u16, body: &[u8]) -> JoinError {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let code = v["detail"]
        .as_str()
        .or_else(|| v["aegis_error_code"].as_str())
        .unwrap_or("request failed")
        .chars()
        .take(200)
        .collect();
    JoinError::Rejected { status, code }
}

/// Enroll this device with an invitation. Writes the device profile into
/// `dir` (which must not already hold an enrolled device).
pub async fn enroll(invite: &Invite, dir: &DeviceDir) -> Result<Device, JoinError> {
    if dir.device_file().exists() {
        return Err(JoinError::Storage(
            "a device is already enrolled here; remove it first".into(),
        ));
    }
    let (key, csr) = pki::generate_key_and_csr(&invite.name)
        .map_err(|_| JoinError::Storage("key generation failed".into()))?;
    let edge = http::Edge {
        outer_server_name: invite.outer_server_name.clone(),
        outer_ca_pem: invite.outer_ca_pem.clone(),
    };
    let body = json!({"token": invite.token, "node_name": invite.name, "csr_pem": csr});
    let (status, bytes) = http::post_json(&invite.enroll_url, &edge, &body).await?;
    if status != 201 {
        return Err(rejected(status, &bytes));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| JoinError::Untrusted("malformed response"))?;
    let (chain, anchor) = verify_issued(&response, &invite.device_ca_sha256, &key, &invite.name)?;
    private_dir(&dir.root)?;
    private_dir(&dir.secrets())?;
    private_dir(&dir.identity())?;
    write_private(&dir.identity().join("key.pem"), &key)?;
    write_private(&dir.identity().join("cert.pem"), &chain)?;
    write_private(&dir.identity().join("ca.pem"), &anchor)?;
    if let Some(ca) = &invite.outer_ca_pem {
        write_private(&dir.identity().join("outer-ca.pem"), ca)?;
    }
    let device = Device {
        name: invite.name.clone(),
        url: invite.url.clone(),
        enroll_url: invite.enroll_url.clone(),
        server_name: invite.server_name.clone(),
        outer_server_name: invite.outer_server_name.clone(),
        device_ca_sha256: invite.device_ca_sha256.clone(),
        enrolled_at: now(),
        quic: invite.quic.clone(),
    };
    let text = serde_json::to_string_pretty(&device)
        .map_err(|_| JoinError::Storage("serialize".into()))?;
    write_private(&dir.device_file(), &text)?;
    Ok(device)
}

/// Renew the device certificate with the same key when it is due (or when
/// `force`). Returns whether a new certificate was installed.
pub async fn renew_if_due(dir: &DeviceDir, force: bool) -> Result<bool, JoinError> {
    let device = dir.load()?;
    if !force && dir.certificate_expires_at()? - now() > RENEW_BEFORE_SECONDS {
        return Ok(false);
    }
    let key = dir.read("key.pem")?;
    let cert = dir.read("cert.pem")?;
    let outer = if device.outer_server_name.is_some() {
        Some(dir.read("outer-ca.pem")?)
    } else {
        None
    };
    let csr = pki::csr_for_key(&key, &device.name)
        .map_err(|_| JoinError::Storage("CSR generation failed".into()))?;
    let body = json!({"certificate_pem": cert, "csr_pem": csr});
    let (status, bytes) = http::post_json(&device.renew_url(), &device.edge(outer), &body).await?;
    if status != 200 {
        return Err(rejected(status, &bytes));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| JoinError::Untrusted("malformed response"))?;
    let (chain, anchor) = verify_issued(&response, &device.device_ca_sha256, &key, &device.name)?;
    write_private(&dir.identity().join("cert.pem"), &chain)?;
    write_private(&dir.identity().join("ca.pem"), &anchor)?;
    Ok(true)
}

/// Send a gzipped diagnostic report (OTLP/JSON) to the gateway this device
/// joined. It travels on the device-authenticated `/renew` edge endpoint,
/// signed with the device key; the gateway only accepts it while an
/// administrator has diagnostics turned on.
pub async fn upload_diagnostics(dir: &DeviceDir, report_gz: &[u8]) -> Result<(), JoinError> {
    let device = dir.load()?;
    let key = dir.read("key.pem")?;
    let cert = dir.read("cert.pem")?;
    let outer = if device.outer_server_name.is_some() {
        Some(dir.read("outer-ca.pem")?)
    } else {
        None
    };
    let signed_at = now();
    let signature = pki::sign_with_key(&key, &pki::diagnostic_upload_message(signed_at, report_gz))
        .map_err(|_| JoinError::Storage("could not sign the report".into()))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let body = json!({
        "certificate_pem": cert,
        "diagnostic_report_gz": b64.encode(report_gz),
        "signed_at": signed_at,
        "signature": b64.encode(signature),
    });
    let (status, bytes) = http::post_json(&device.renew_url(), &device.edge(outer), &body).await?;
    if status != 200 {
        return Err(rejected(status, &bytes));
    }
    Ok(())
}

/// Ask the gateway for its current endpoint. Returns `Some` only when it
/// differs from what this device stores; the caller must verify the new
/// endpoint works (the gateway's pinned identity) before [`adopt_endpoint`].
/// An endpoint for a different device CA is refused outright.
pub async fn fetch_endpoint(dir: &DeviceDir) -> Result<Option<Endpoint>, JoinError> {
    let device = dir.load()?;
    let cert = dir.read("cert.pem")?;
    let outer = if device.outer_server_name.is_some() {
        Some(dir.read("outer-ca.pem")?)
    } else {
        None
    };
    let body = json!({"certificate_pem": cert, "endpoint_query": true});
    let (status, bytes) =
        http::post_json(&device.renew_url(), &device.edge(outer.clone()), &body).await?;
    if status != 200 {
        return Err(rejected(status, &bytes));
    }
    let response: Value =
        serde_json::from_slice(&bytes).map_err(|_| JoinError::Untrusted("malformed response"))?;
    let endpoint: Endpoint = serde_json::from_value(response["endpoint"].clone())
        .map_err(|_| JoinError::Untrusted("malformed endpoint"))?;
    endpoint.check().map_err(JoinError::Untrusted)?;
    if endpoint.device_ca_sha256 != device.device_ca_sha256 {
        return Err(JoinError::Untrusted(
            "endpoint belongs to a different gateway",
        ));
    }
    let same = endpoint.url == device.url
        && endpoint.enroll_url == device.enroll_url
        && endpoint.server_name == device.server_name
        && endpoint.outer_server_name == device.outer_server_name
        && endpoint.outer_ca_pem.as_deref().map(str::trim) == outer.as_deref().map(str::trim)
        && endpoint.quic == device.quic;
    Ok((!same).then_some(endpoint))
}

/// Store `endpoint` as this device's way to reach the gateway.
pub fn adopt_endpoint(dir: &DeviceDir, endpoint: &Endpoint) -> Result<Device, JoinError> {
    endpoint.check().map_err(JoinError::Untrusted)?;
    let mut device = dir.load()?;
    if endpoint.device_ca_sha256 != device.device_ca_sha256 {
        return Err(JoinError::Untrusted(
            "endpoint belongs to a different gateway",
        ));
    }
    let outer = dir.identity().join("outer-ca.pem");
    match &endpoint.outer_ca_pem {
        Some(ca) => write_private(&outer, ca)?,
        None => {
            let _ = std::fs::remove_file(&outer);
        }
    }
    // The staged copy stays: the verified trial node keeps running with it
    // and reads it again whenever it rebuilds its tunnel (e.g. after a
    // certificate renewal). The next trial overwrites it.
    device.url = endpoint.url.clone();
    device.enroll_url = endpoint.enroll_url.clone();
    device.server_name = endpoint.server_name.clone();
    device.outer_server_name = endpoint.outer_server_name.clone();
    device.quic = endpoint.quic.clone();
    let text = serde_json::to_string_pretty(&device)
        .map_err(|_| JoinError::Storage("serialize".into()))?;
    write_private(&dir.device_file(), &text)?;
    Ok(device)
}

/// End-to-end check of a running client: open a stream to `localhost:9`
/// through its SOCKS5 proxy. The gateway must refuse it *by policy* (SOCKS
/// reply 2), which only happens after the pinned inner mTLS handshake and
/// registry admission succeeded, without contacting any third party.
pub async fn verify_tunnel(socks: std::net::SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(socks).await.ok()?;
        s.write_all(&[5, 1, 0]).await.ok()?;
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.ok()?;
        let host = b"localhost";
        let mut req = vec![5, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&9u16.to_be_bytes());
        s.write_all(&req).await.ok()?;
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.ok()?;
        Some(head[1])
    };
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(15), attempt).await,
        Ok(Some(2))
    )
}

/// Edge CA of an endpoint being tried, before it is adopted.
const STAGED_OUTER_CA: &str = "outer-ca.next.pem";

/// Local proxy listeners of the client profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    pub socks: u16,
    pub http: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports {
            socks: 1080,
            http: 8080,
        }
    }
}

/// Build the client node configuration for an enrolled device. Destination
/// names are always resolved by the gateway (`remote_required`).
pub fn client_config(dir: &DeviceDir, ports: Ports) -> Result<aegis_config::NodeConfig, JoinError> {
    client_config_for(dir, ports, None)
}

/// The client profile, reaching the gateway through `trial` instead of the
/// stored endpoint (to verify a changed endpoint before adopting it).
pub fn client_config_for(
    dir: &DeviceDir,
    ports: Ports,
    trial: Option<&Endpoint>,
) -> Result<aegis_config::NodeConfig, JoinError> {
    let device = dir.load()?;
    let path = |p: PathBuf| p.display().to_string();
    let quic = match trial {
        Some(e) => e.quic.clone(),
        None => device.quic.clone(),
    };
    let (url, server_name, outer) = match trial {
        Some(e) => {
            let outer = match (&e.outer_server_name, &e.outer_ca_pem) {
                (Some(name), Some(ca)) => {
                    write_private(&dir.identity().join(STAGED_OUTER_CA), ca)?;
                    Some((name.clone(), format!("secret://identity/{STAGED_OUTER_CA}")))
                }
                _ => None,
            };
            (e.url.clone(), e.server_name.clone(), outer)
        }
        None => (
            device.url.clone(),
            device.server_name.clone(),
            device
                .outer_server_name
                .clone()
                .map(|n| (n, "secret://identity/outer-ca.pem".to_owned())),
        ),
    };
    let mut outbound = json!({
        "id": "gateway",
        "kind": "agp_tunnel",
        "url": url,
        "server_name": server_name,
    });
    if let Some((name, ca)) = outer {
        outbound["outer_ca"] = json!(ca);
        outbound["outer_server_name"] = json!(name);
    }
    if let Some(q) = quic {
        outbound["quic"] = json!(q);
    }
    let cfg = json!({
        "schema_version": "0.2",
        "node_id": device.name,
        "role": "client",
        "management": {"enabled": false, "config_store": path(dir.store())},
        "secrets": {"dir": path(dir.secrets())},
        "identity": {
            "peer_auth": "mutual_tls_1_3",
            "client_identity": "secret://identity/cert.pem",
            "client_private_key": "secret://identity/key.pem",
            "trusted_server_ca": "secret://identity/ca.pem",
            "require_enrollment": true,
            "legacy_identity_until": 0
        },
        "inbounds": [
            {"id": "socks", "kind": "socks5", "bind": format!("127.0.0.1:{}", ports.socks)},
            {"id": "http", "kind": "http_connect", "bind": format!("127.0.0.1:{}", ports.http)}
        ],
        "outbounds": [outbound],
        "routing": {"default_action": "proxy", "default_outbound": "gateway"},
        "dns": {"mode": "remote_required", "ipv6_policy": "follow-routing-policy"}
    });
    aegis_config::parse_json(&cfg).map_err(|e| JoinError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(v: &Value) -> String {
        format!(
            "{INVITE_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string())
        )
    }

    fn sample() -> Value {
        json!({
            "v": 1, "name": "laptop", "token": "t", "expires_at": now() + 600,
            "url": "wss://gw.example.test/agp", "enroll_url": "https://gw.example.test/enroll",
            "server_name": "gateway.aegis.internal",
            "outer_server_name": null, "outer_ca_pem": null,
            "device_ca_sha256": "a".repeat(64),
        })
    }

    #[test]
    fn invite_codes_are_validated() {
        let ok = parse_invite(&format!("  {}\n", code(&sample()))).expect("valid");
        assert_eq!(ok.name, "laptop");
        let mut v = sample();
        v["expires_at"] = json!(1);
        assert_eq!(parse_invite(&code(&v)), Err(JoinError::InviteExpired));
        let mut v = sample();
        v["url"] = json!("ws://gw.example.test/agp");
        assert!(parse_invite(&code(&v)).is_err(), "plaintext edge refused");
        let mut v = sample();
        v["outer_server_name"] = json!("edge.aegis.internal");
        assert!(parse_invite(&code(&v)).is_err(), "pin without CA refused");
        assert!(parse_invite("hello").is_err());
    }

    /// A profile as `enroll` leaves it, without the network.
    fn fake_profile(dir: &DeviceDir, ca: &str, name: &str, enrolled_at: i64) {
        private_dir(&dir.identity()).expect("dirs");
        write_private(&dir.identity().join("key.pem"), "key").expect("key");
        let device = Device {
            name: name.into(),
            url: format!("wss://{name}.example.test/agp"),
            enroll_url: format!("https://{name}.example.test/enroll"),
            server_name: "gateway.aegis.internal".into(),
            outer_server_name: None,
            device_ca_sha256: ca.into(),
            enrolled_at,
            quic: None,
        };
        write_private(
            &dir.device_file(),
            &serde_json::to_string(&device).expect("json"),
        )
        .expect("device");
    }

    fn temp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("aegis-join-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a_single_profile_moves_into_the_server_list() {
        let root = temp("migrate");
        fake_profile(&DeviceDir::new(&root), &"a".repeat(64), "laptop", 1);
        std::fs::write(root.join("settings.json"), "{}").expect("settings");
        std::fs::write(root.join("state.db"), "x").expect("state");
        let servers = Servers::open(&root).expect("open");
        let list = servers.list();
        assert_eq!(list.len(), 1);
        let s = &list[0];
        assert_eq!(s.device.name, "laptop");
        assert_eq!(s.host(), "laptop.example.test");
        assert_eq!(
            std::fs::read_to_string(s.dir.identity().join("key.pem")).expect("key"),
            "key"
        );
        assert_eq!(servers.selected().expect("selected").id, s.id);
        assert!(!root.join("device.json").exists() && !root.join("secrets").exists());
        assert!(!root.join("state.db").exists());
        assert!(root.join("settings.json").exists(), "other files stay");
        // Opening again changes nothing.
        assert_eq!(Servers::open(&root).expect("reopen").list().len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn servers_are_listed_selected_and_removed() {
        let root = temp("list");
        let servers = Servers::open(&root).expect("open");
        assert!(servers.list().is_empty() && servers.selected().is_none());
        let (a, b) = (
            server_id(&"a".repeat(64), "phone"),
            server_id(&"b".repeat(64), "phone"),
        );
        assert_ne!(a, b, "same name on two gateways");
        fake_profile(
            &DeviceDir::new(servers.base().join(&b)),
            &"b".repeat(64),
            "phone",
            20,
        );
        fake_profile(
            &DeviceDir::new(servers.base().join(&a)),
            &"a".repeat(64),
            "phone",
            10,
        );
        // An unfinished join and a stray name are not servers.
        std::fs::create_dir_all(servers.base().join(server_id("c", "x"))).expect("partial");
        std::fs::create_dir_all(servers.base().join("..evil")).expect("stray");
        let ids: Vec<String> = servers.list().into_iter().map(|s| s.id).collect();
        assert_eq!(ids, [a.clone(), b.clone()], "oldest first");
        assert_eq!(
            servers.selected().expect("default").id,
            a,
            "oldest by default"
        );
        servers.select(&b).expect("select");
        assert_eq!(servers.selected().expect("chosen").id, b);
        assert!(servers.select("../../etc").is_err());
        assert!(servers.get("../x").is_none());
        servers.remove(&b).expect("remove");
        assert!(!servers.base().join(&b).exists());
        assert_eq!(servers.selected().expect("fallback").id, a);
        servers.remove(&a).expect("remove");
        assert!(servers.selected().is_none());
        let _ = std::fs::remove_dir_all(&root);
    }
}
