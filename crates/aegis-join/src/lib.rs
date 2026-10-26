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
        && endpoint.outer_ca_pem.as_deref().map(str::trim) == outer.as_deref().map(str::trim);
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
}
