//! Appliance mode (ADR-0007): `aegisd --data-dir DIR` on an empty directory
//! initializes a complete, secure-by-default gateway with no hand-written
//! configuration:
//!
//! * a device PKI (root + online issuer) for inner mTLS enrollment;
//! * a separate web CA for the HTTPS console and the outer (edge) listener,
//!   so web certificates can never authenticate as an AegisNet gateway;
//! * the owner account `admin` with a random password that must be changed
//!   at first sign-in. The password is written once to
//!   `DIR/initial-admin-password` (0600) and removed after it is changed;
//!   it is never printed to logs.
//!
//! The seed `config.toml` is written last; a crashed initialization is
//! detected by the `.aegis-init` marker and restarted from scratch.

use aegis_contracts::Role;
use aegis_identity::pki::{self, CaBundle};
use aegis_provision::secrets::SecretStore;
use aegis_storage::{self as db, Store};
use rand::Rng;
use serde_json::json;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const GATEWAY_NODE_ID: &str = "aegis-gateway";
pub const INNER_SERVER_NAME: &str = "gateway.aegis.internal";
pub const EDGE_SERVER_NAME: &str = "edge.aegis.internal";
pub const CONSOLE_PORT: u16 = 8443;
pub const EDGE_PORT: u16 = 8444;
/// Container-loopback origin port for the embedded Cloudflare connector.
pub const TUNNEL_PORT: u16 = 18080;
pub const INITIAL_PASSWORD_FILE: &str = "initial-admin-password";
const MARKER: &str = ".aegis-init";
const ISSUER_LIFETIME: Duration = Duration::from_secs(365 * 24 * 3600);
const WEB_LIFETIME: Duration = Duration::from_secs(397 * 24 * 3600);

/// Operator hints supplied by the installer (environment), all optional.
#[derive(Clone, Debug, Default)]
pub struct InitOptions {
    /// Addresses clients and browsers use to reach this host
    /// (`AEGIS_PUBLIC_ADDRESSES`, comma separated IPs and/or DNS names).
    pub public_addresses: Vec<String>,
    /// Host port mapped to the edge listener (`AEGIS_PUBLIC_PORT`).
    pub public_port: Option<u16>,
    /// Bind the console to loopback only (`AEGIS_CONSOLE_LOOPBACK=1`).
    pub console_loopback: bool,
    /// Bind the device edge to loopback only (`AEGIS_EDGE_LOOPBACK=1`):
    /// devices arrive through the Cloudflare Tunnel, nothing listens publicly.
    pub edge_loopback: bool,
    /// Listener ports (`AEGIS_CONSOLE_PORT`, `AEGIS_EDGE_PORT`,
    /// `AEGIS_TUNNEL_PORT`); `None` selects the defaults.
    pub console_port: Option<u16>,
    pub edge_port: Option<u16>,
    pub tunnel_port: Option<u16>,
}

impl InitOptions {
    pub fn from_env() -> Self {
        let public_addresses = std::env::var("AEGIS_PUBLIC_ADDRESSES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .take(8)
            .collect();
        InitOptions {
            public_addresses,
            public_port: std::env::var("AEGIS_PUBLIC_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .filter(|p| *p != 0),
            console_loopback: std::env::var("AEGIS_CONSOLE_LOOPBACK").is_ok_and(|v| v == "1"),
            edge_loopback: std::env::var("AEGIS_EDGE_LOOPBACK").is_ok_and(|v| v == "1"),
            console_port: env_port("AEGIS_CONSOLE_PORT"),
            edge_port: env_port("AEGIS_EDGE_PORT"),
            tunnel_port: env_port("AEGIS_TUNNEL_PORT"),
        }
    }

    fn split(&self) -> (Vec<String>, Vec<IpAddr>) {
        let mut names = Vec::new();
        let mut ips = Vec::new();
        for a in &self.public_addresses {
            if let Ok(ip) = a.parse::<IpAddr>() {
                if !ip.is_unspecified() && !ips.contains(&ip) {
                    ips.push(ip);
                }
            } else if aegis_contracts::destination::normalize_domain(a).as_deref() == Ok(a)
                && !names.contains(a)
            {
                names.push(a.clone());
            }
        }
        (names, ips)
    }
}

fn env_port(name: &str) -> Option<u16> {
    std::env::var(name).ok().and_then(|p| p.parse().ok())
}

pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.toml")
}

/// Generate a readable random password: 4 groups of 5 from an unambiguous
/// 55-symbol alphabet (~115 bits).
pub fn random_password() -> String {
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rngs::OsRng;
    (0..4)
        .map(|_| {
            (0..5)
                .map(|_| char::from(ALPHABET[rng.gen_range(0..ALPHABET.len())]))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn err(code: &'static str) -> String {
    code.to_owned()
}

fn check_empty(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    let marker = dir.join(MARKER).exists();
    for entry in std::fs::read_dir(dir).map_err(|_| err("E_DATA_DIR_UNREADABLE"))? {
        let entry = entry.map_err(|_| err("E_DATA_DIR_UNREADABLE"))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "lost+found" || name == MARKER {
            continue;
        }
        if !marker {
            return Err(err("E_DATA_DIR_NOT_EMPTY"));
        }
    }
    if marker {
        // A previous initialization crashed before publishing config.toml.
        // Nothing generated by it was ever used; start over.
        for entry in std::fs::read_dir(dir).map_err(|_| err("E_DATA_DIR_UNREADABLE"))? {
            let entry = entry.map_err(|_| err("E_DATA_DIR_UNREADABLE"))?;
            let name = entry.file_name();
            if name == "lost+found" || name == MARKER {
                continue;
            }
            let path = entry.path();
            let meta =
                std::fs::symlink_metadata(&path).map_err(|_| err("E_DATA_DIR_UNREADABLE"))?;
            let removed = if meta.is_dir() && !meta.file_type().is_symlink() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.map_err(|_| err("E_DATA_DIR_CLEANUP"))?;
        }
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|_| err("E_DATA_DIR_CREATE"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| err("E_DATA_DIR_PERMISSIONS"))?;
    }
    Ok(())
}

fn put(store: &SecretStore, name: &str, value: &str) -> Result<(), String> {
    store
        .put(name, value, true)
        .map_err(|_| err("E_SECRET_WRITE"))
}

fn bundle(cert: &str, key: &str) -> String {
    json!({"certificate": format!("secret://{cert}"), "private_key": format!("secret://{key}")})
        .to_string()
}

/// Publish a certificate/key pair crash-safely: write generation-named
/// files, then atomically replace the manifest that references them, then
/// remove the previous generation. An interruption leaves the old, still
/// consistent pair active.
pub fn publish_pair(
    secrets: &SecretStore,
    manifest: &str,
    prefix: &str,
    cert: &str,
    key: &str,
) -> Result<(), String> {
    let generation = &aegis_storage::sha256_hex(cert.as_bytes())[..16];
    let cert_file = format!("{prefix}-{generation}.pem");
    let key_file = format!("{prefix}-{generation}.key");
    let previous: Option<serde_json::Value> = secrets
        .read(manifest)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok());
    put(secrets, &cert_file, cert)?;
    put(secrets, &key_file, key)?;
    put(secrets, manifest, &bundle(&cert_file, &key_file))?;
    if let Some(prev) = previous {
        for field in ["certificate", "private_key"] {
            if let Some(name) = prev[field]
                .as_str()
                .and_then(|r| r.strip_prefix("secret://"))
            {
                if name != cert_file && name != key_file && !name.contains('/') {
                    let _ = std::fs::remove_file(secrets.root().join(name));
                }
            }
        }
    }
    Ok(())
}

/// Read the certificate PEM a manifest currently references.
pub fn manifest_certificate(secrets: &SecretStore, manifest: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(&secrets.read(manifest).ok()?).ok()?;
    let name = v["certificate"].as_str()?.strip_prefix("secret://")?;
    secrets.read(name).ok().map(|s| s.to_string())
}

/// Issue the edge (outer TLS) certificate for the configured public names.
pub fn issue_edge(
    secrets: &SecretStore,
    web: &CaBundle,
    names: &[String],
    ips: &[IpAddr],
) -> Result<(), String> {
    let mut dns = vec![EDGE_SERVER_NAME.to_owned(), "localhost".to_owned()];
    dns.extend(
        names
            .iter()
            .filter(|n| !dns.contains(n))
            .cloned()
            .collect::<Vec<_>>(),
    );
    let mut addrs = vec![IpAddr::from([127, 0, 0, 1])];
    addrs.extend(
        ips.iter()
            .filter(|i| !addrs.contains(i))
            .copied()
            .collect::<Vec<_>>(),
    );
    let (cert, key) = pki::issue_web_server(web, &dns, &addrs, WEB_LIFETIME)
        .map_err(|_| err("E_EDGE_CERTIFICATE"))?;
    publish_pair(
        secrets,
        "edge-tls.json",
        "edge",
        &format!("{cert}{}", web.cert_pem),
        &key,
    )
}

/// Issue the console certificate (web CA) for the configured public names.
pub fn issue_console(
    secrets: &SecretStore,
    web: &CaBundle,
    names: &[String],
    ips: &[IpAddr],
) -> Result<(), String> {
    let mut dns = vec!["aegis.local".to_owned(), "localhost".to_owned()];
    dns.extend(
        names
            .iter()
            .filter(|n| !dns.contains(n))
            .cloned()
            .collect::<Vec<_>>(),
    );
    let mut addrs = vec![IpAddr::from([127, 0, 0, 1])];
    addrs.extend(
        ips.iter()
            .filter(|i| !addrs.contains(i))
            .copied()
            .collect::<Vec<_>>(),
    );
    let (cert, key) = pki::issue_web_server(web, &dns, &addrs, WEB_LIFETIME)
        .map_err(|_| err("E_CONSOLE_CERTIFICATE"))?;
    publish_pair(
        secrets,
        "console-tls.json",
        "console",
        &format!("{cert}{}", web.cert_pem),
        &key,
    )
}

/// Issue (or re-issue) the gateway's inner mTLS identity from the issuer.
pub fn issue_gateway_identity(secrets: &SecretStore, issuer: &CaBundle) -> Result<(), String> {
    let (cert, key) = pki::issue_direct(
        issuer,
        GATEWAY_NODE_ID,
        Role::Gateway,
        &[INNER_SERVER_NAME.into()],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| err("E_GATEWAY_IDENTITY"))?;
    // The issuer chain holds issuer + root; serve leaf + issuer + root.
    publish_pair(
        secrets,
        "gateway-identity.json",
        "gateway",
        &format!("{cert}{}", issuer.cert_pem),
        &key,
    )
}

/// Load the online device issuer (certificate chain + key) via its manifest.
pub fn load_issuer(secrets: &SecretStore) -> Result<CaBundle, String> {
    let v: serde_json::Value = secrets
        .read("issuer.json")
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .ok_or_else(|| err("E_ISSUER_UNAVAILABLE"))?;
    let read = |field: &str| -> Result<String, String> {
        let name = v[field]
            .as_str()
            .and_then(|r| r.strip_prefix("secret://"))
            .ok_or_else(|| err("E_ISSUER_UNAVAILABLE"))?;
        secrets
            .read(name)
            .map(|s| s.to_string())
            .map_err(|_| err("E_ISSUER_UNAVAILABLE"))
    };
    Ok(CaBundle {
        cert_pem: read("certificate")?,
        key_pem: read("private_key")?,
    })
}

/// The device root's private key, when it is kept on this host.
pub const ROOT_KEY: &str = "device-root-key.pem";

/// Whether `key_pem` is the private key of this gateway's device root.
pub fn is_root_key(secrets: &SecretStore, key_pem: &str) -> bool {
    let Ok(root) = secrets.read("device-root.pem") else {
        return false;
    };
    aegis_identity::tls::parse_certs(&root)
        .ok()
        .and_then(|c| c.first().cloned())
        .is_some_and(|der| pki::certificate_matches_key(der.as_ref(), key_pem))
}

/// Rotate the online issuer from the root kept on this host (lab mode).
/// Devices trust the root, so existing enrollments stay valid.
pub fn rotate_issuer(secrets: &SecretStore) -> Result<CaBundle, String> {
    let key_pem = secrets
        .read(ROOT_KEY)
        .map_err(|_| err("E_ROOT_KEY_NOT_ON_HOST"))?
        .to_string();
    rotate_issuer_with(secrets, &key_pem)
}

/// Rotate the online issuer with the root key supplied by the operator (the
/// key kept offline); the key is used in memory only, never stored.
pub fn rotate_issuer_with(secrets: &SecretStore, root_key_pem: &str) -> Result<CaBundle, String> {
    if !is_root_key(secrets, root_key_pem) {
        return Err(err("E_NOT_ROOT_KEY"));
    }
    let root = CaBundle {
        cert_pem: secrets
            .read("device-root.pem")
            .map_err(|_| err("E_ROOT_UNAVAILABLE"))?
            .to_string(),
        key_pem: root_key_pem.to_owned(),
    };
    let issuer = pki::generate_intermediate(&root, "AegisNet device issuer", ISSUER_LIFETIME)
        .map_err(|_| err("E_ISSUER_GENERATION"))?;
    let chain = format!("{}{}", issuer.cert_pem, root.cert_pem);
    publish_pair(
        secrets,
        "issuer.json",
        "device-issuer",
        &chain,
        &issuer.key_pem,
    )?;
    Ok(CaBundle {
        cert_pem: chain,
        key_pem: issuer.key_pem,
    })
}

pub fn load_web_ca(secrets: &SecretStore) -> Result<CaBundle, String> {
    Ok(CaBundle {
        cert_pem: secrets
            .read("web-ca.pem")
            .map_err(|_| err("E_WEB_CA_UNAVAILABLE"))?
            .to_string(),
        key_pem: secrets
            .read("web-ca-key.pem")
            .map_err(|_| err("E_WEB_CA_UNAVAILABLE"))?
            .to_string(),
    })
}

fn seed_config(dir: &Path, opts: &InitOptions) -> String {
    let console_port = opts.console_port.unwrap_or(CONSOLE_PORT);
    let edge_port = opts.edge_port.unwrap_or(EDGE_PORT);
    let tunnel_port = opts.tunnel_port.unwrap_or(TUNNEL_PORT);
    let console_bind = if opts.console_loopback {
        format!("127.0.0.1:{console_port}")
    } else {
        format!("0.0.0.0:{console_port}")
    };
    let edge_host = if opts.edge_loopback {
        "127.0.0.1"
    } else {
        "0.0.0.0"
    };
    let toml_str = |p: &Path| p.display().to_string().replace('\\', "/");
    format!(
        r#"# Generated by aegisd appliance initialization. After first start the
# SQLite store is authoritative: change settings in the web console, not here.
schema_version = "0.2"
node_id = "{GATEWAY_NODE_ID}"
role = "gateway"

[management]
bind = "{console_bind}"
remote_access_enabled = {remote}
tls = "secret://console-tls.json"
config_store = "{store}"

[secrets]
dir = "{secrets}"

[identity]
peer_auth = "mutual_tls_1_3"
material_bundle = "secret://gateway-identity.json"
trusted_client_ca = "secret://device-root.pem"
issuer_bundle = "secret://issuer.json"
require_enrollment = true
legacy_identity_until = 0

[[inbounds]]
id = "edge"
kind = "websocket"
bind = "{edge_host}:{edge_port}"
path = "/agp"
outer_tls = {{ bundle = "secret://edge-tls.json", server_name = "{EDGE_SERVER_NAME}", trusted_ca = "secret://web-ca.pem" }}

[[inbounds]]
id = "tunnel-origin"
kind = "websocket"
bind = "127.0.0.1:{tunnel_port}"
path = "/agp"

[[outbounds]]
id = "egress"
kind = "direct_tcp"
restricted_address_policy = "deny-private-and-metadata"

[routing]
default_action = "deny"

[[routing.rules]]
id = "authenticated-public"
match = "authenticated-and-public-destination"
action = "proxy"
outbound = "egress"

[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
resolver = "explicit"
nameservers = ["1.1.1.1:53", "9.9.9.9:53"]
"#,
        remote = !opts.console_loopback,
        store = toml_str(&dir.join("state.db")),
        secrets = toml_str(&dir.join("secrets")),
    )
}

/// Remember the web certificate names so renewals keep them.
fn db_store_web_names(dir: &Path, names: &[String], ips: &[IpAddr]) -> Result<(), String> {
    let store = Store::open(dir.join("state.db")).map_err(|_| err("E_STORAGE"))?;
    store
        .tx(|c| db::put_setting(c, "web_names", &json!({"names": names, "ips": ips})))
        .map_err(|_| err("E_STORAGE"))
}

pub fn web_names(store: &Store) -> (Vec<String>, Vec<IpAddr>) {
    let v = store
        .read(|c| db::get_setting(c, "web_names"))
        .ok()
        .flatten()
        .unwrap_or_default();
    let names = serde_json::from_value(v["names"].clone()).unwrap_or_default();
    let ips = serde_json::from_value(v["ips"].clone()).unwrap_or_default();
    (names, ips)
}

pub fn set_web_names(store: &Store, names: &[String], ips: &[IpAddr]) -> Result<(), String> {
    store
        .tx(|c| db::put_setting(c, "web_names", &json!({"names": names, "ips": ips})))
        .map_err(|_| err("E_STORAGE"))
}

/// Initialize an empty data directory. Returns the seed configuration path.
pub fn init(dir: &Path, opts: &InitOptions) -> Result<PathBuf, String> {
    check_empty(dir)?;
    private_dir(dir)?;
    std::fs::write(dir.join(MARKER), b"").map_err(|_| err("E_DATA_DIR_WRITE"))?;
    let secrets = SecretStore::open(dir.join("secrets")).map_err(|_| err("E_SECRET_STORE"))?;

    // Device PKI: root (lab mode: kept on this host, exportable/removable
    // from the console) and a path-length-zero online issuer.
    let root =
        pki::generate_offline_root("AegisNet device root").map_err(|_| err("E_ROOT_GENERATION"))?;
    let issuer = pki::generate_intermediate(&root, "AegisNet device issuer", ISSUER_LIFETIME)
        .map_err(|_| err("E_ISSUER_GENERATION"))?;
    put(&secrets, "device-root.pem", &root.cert_pem)?;
    put(&secrets, ROOT_KEY, &root.key_pem)?;
    let chain = format!("{}{}", issuer.cert_pem, root.cert_pem);
    publish_pair(
        &secrets,
        "issuer.json",
        "device-issuer",
        &chain,
        &issuer.key_pem,
    )?;
    let online_issuer = CaBundle {
        cert_pem: chain,
        key_pem: issuer.key_pem.clone(),
    };
    issue_gateway_identity(&secrets, &online_issuer)?;

    // Web PKI for the console and the outer listener.
    let web = pki::generate_ca("AegisNet web CA", pki::DEFAULT_CA_VALIDITY)
        .map_err(|_| err("E_WEB_CA_GENERATION"))?;
    put(&secrets, "web-ca.pem", &web.cert_pem)?;
    put(&secrets, "web-ca-key.pem", &web.key_pem)?;
    let (names, ips) = opts.split();
    issue_console(&secrets, &web, &names, &ips)?;
    issue_edge(&secrets, &web, &names, &ips)?;

    // Owner account with a forced password change.
    let password = random_password();
    let hash = aegis_management::hash_password(&password).map_err(|_| err("E_PASSWORD_HASH"))?;
    let store = Store::open(dir.join("state.db")).map_err(|_| err("E_STORAGE"))?;
    let connection = json!({
        "mode": "direct",
        "public_host": opts.public_addresses.first(),
        "public_port": opts.public_port.unwrap_or(443),
    });
    store
        .tx(|c| {
            let id = db::new_id();
            db::insert_principal(
                c,
                &db::PrincipalRow {
                    id: id.clone(),
                    username: "admin".into(),
                    password_hash: hash.clone(),
                    status: "active".into(),
                    roles: vec![aegis_management::ROLE_OWNER.into()],
                },
            )?;
            db::set_password(c, &id, &hash, true)?;
            db::put_setting(c, "connection", &connection)?;
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: None,
                    action: "appliance.initialized",
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        })
        .map_err(|_| err("E_STORAGE"))?;
    drop(store);
    db_store_web_names(dir, &names, &ips)?;
    let files = SecretStore::open(dir).map_err(|_| err("E_DATA_DIR_WRITE"))?;
    put(&files, INITIAL_PASSWORD_FILE, &format!("{password}\n"))?;
    put(&files, "config.toml", &seed_config(dir, opts))?;
    std::fs::remove_file(dir.join(MARKER)).map_err(|_| err("E_DATA_DIR_WRITE"))?;
    Ok(config_path(dir))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn init_produces_valid_config_owner_and_separate_web_trust() {
        let dir = tempfile::tempdir().expect("tmp");
        let root = dir.path().join("data");
        let opts = InitOptions {
            public_addresses: vec!["192.0.2.10".into(), "gw.example.test".into()],
            public_port: Some(443),
            ..Default::default()
        };
        let path = init(&root, &opts).expect("init");
        let cfg = aegis_config::parse_toml(&std::fs::read_to_string(&path).expect("read"))
            .expect("parse");
        aegis_node::validate_offline(&cfg).expect("seed validates");
        let edge = cfg.inbounds.iter().find(|i| i.id == "edge").expect("edge");
        assert!(edge.bind.starts_with("0.0.0.0:"), "direct by default");
        let tunnel_only = seed_config(
            &root,
            &InitOptions {
                edge_loopback: true,
                ..Default::default()
            },
        );
        assert!(
            tunnel_only.contains("bind = \"127.0.0.1:8444\""),
            "{tunnel_only}"
        );
        let password = std::fs::read_to_string(root.join(INITIAL_PASSWORD_FILE)).expect("pw");
        assert_eq!(password.trim().len(), 23);
        let store = Store::open(root.join("state.db")).expect("store");
        let owner = store
            .read(|c| db::get_principal_by_username(c, "admin"))
            .expect("read")
            .expect("owner");
        assert!(store
            .read(|c| db::must_change_password(c, &owner.id))
            .expect("flag"));
        // A web certificate must not verify as a device identity.
        let secrets = SecretStore::open(root.join("secrets")).expect("secrets");
        let device_root = secrets.read("device-root.pem").expect("root");
        let edge = manifest_certificate(&secrets, "edge-tls.json").expect("edge");
        assert!(aegis_identity::tls::validate_client_certificate(&edge, &device_root).is_err());
        // Second init refuses a populated directory.
        assert_eq!(
            init(&root, &opts).expect_err("populated"),
            "E_DATA_DIR_NOT_EMPTY"
        );
    }

    #[test]
    fn crashed_init_is_restarted_but_foreign_data_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        std::fs::write(dir.path().join("user-file"), b"x").expect("w");
        assert_eq!(
            init(dir.path(), &InitOptions::default()).expect_err("foreign"),
            "E_DATA_DIR_NOT_EMPTY"
        );
        let crashed = dir.path().join("crashed");
        std::fs::create_dir_all(crashed.join("secrets")).expect("mk");
        std::fs::write(crashed.join(MARKER), b"").expect("marker");
        std::fs::write(crashed.join("secrets/partial"), b"x").expect("partial");
        init(&crashed, &InitOptions::default()).expect("restart");
        assert!(!crashed.join("secrets/partial").exists());
    }

    #[test]
    fn passwords_are_random_and_well_formed() {
        let a = random_password();
        assert_ne!(a, random_password());
        assert_eq!(a.split('-').count(), 4);
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_alphanumeric()));
    }
}
