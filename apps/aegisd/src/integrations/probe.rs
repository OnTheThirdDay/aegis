//! End-to-end data-path probe for provisioning (SPEC-12 §7.2.7): an
//! in-process client with a dedicated, registered probe identity connects to
//! the public endpoint exactly like a device (public DNS, edge TLS,
//! connector, origin, inner mTLS), then:
//!
//! 1. opens a stream to `localhost:9`, which the gateway must refuse by
//!    policy — proving the authenticated AGP session reaches the gateway;
//! 2. fetches the operator's HTTP and HTTPS verification URLs through SOCKS
//!    with remote DNS (the HTTPS certificate is verified normally).

use crate::appliance;
use crate::services::Appliance;
use aegis_contracts::Role;
use aegis_identity::pki;
use aegis_provision::secrets::SecretStore;
use aegis_storage as db;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const PROBE_NODE: &str = "aegis-probe";

fn probe_store(app: &Appliance) -> Result<SecretStore, String> {
    SecretStore::open(app.dir.join("secrets/probe")).map_err(|e| e.0.to_owned())
}

/// Issue (or renew) the probe's client identity and register it so the
/// gateway admits it like any enrolled device.
pub fn ensure_identity(app: &Appliance) -> Result<(), String> {
    let store = probe_store(app)?;
    let fresh = store
        .read("cert.pem")
        .ok()
        .and_then(|c| {
            let certs = aegis_identity::tls::parse_certs(&c).ok()?;
            aegis_identity::tls::certificate_expiry(certs[0].as_ref()).ok()
        })
        .is_some_and(|exp| exp - db::now_unix() > 7 * 86_400);
    let registered = app
        .store
        .read(|c| db::get_node_by_name(c, PROBE_NODE))
        .map_err(|_| "storage_unavailable".to_owned())?;
    if fresh && registered.as_ref().is_some_and(|n| n.status == "active") {
        return Ok(());
    }
    let issuer = appliance::load_issuer(&app.secrets)?;
    let (key, csr) =
        pki::generate_key_and_csr(PROBE_NODE).map_err(|_| "probe_identity_failed".to_owned())?;
    let cert = pki::sign_csr(
        &issuer,
        &csr,
        PROBE_NODE,
        Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| "probe_identity_failed".to_owned())?;
    let chain = format!("{cert}{}", issuer.cert_pem);
    let der =
        aegis_identity::tls::parse_certs(&cert).map_err(|_| "probe_identity_failed".to_owned())?;
    let peer = aegis_identity::tls::PeerIdentity::from_der(der[0].as_ref())
        .map_err(|_| "probe_identity_failed".to_owned())?;
    let anchor = app
        .secrets
        .read("device-root.pem")
        .map_err(|_| "device_root_unavailable".to_owned())?;
    store
        .put("key.pem", &key, true)
        .map_err(|e| e.0.to_owned())?;
    store
        .put("cert.pem", &chain, true)
        .map_err(|e| e.0.to_owned())?;
    store
        .put("ca.pem", &anchor, true)
        .map_err(|e| e.0.to_owned())?;
    app.store
        .tx(|c| {
            let node_id = match db::get_node_by_name(c, PROBE_NODE)? {
                Some(n) if n.status != "revoked" => {
                    db::rotate_node_certificate(
                        c,
                        &n.id,
                        &peer.fingerprint_hex(),
                        &peer.serial_hex,
                        peer.not_after,
                    )?;
                    n.id
                }
                Some(_) => return Err(db::StoreError::Conflict("probe identity revoked".into())),
                None => {
                    let id = db::new_id();
                    db::insert_node(
                        c,
                        &db::NodeRow {
                            id: id.clone(),
                            name: PROBE_NODE.into(),
                            role: "client".into(),
                            cert_fingerprint: Some(peer.fingerprint_hex()),
                            cert_serial: Some(peer.serial_hex.clone()),
                            status: "active".into(),
                            generation: 1,
                            not_after: Some(peer.not_after),
                            created_at: db::now_unix(),
                        },
                    )?;
                    id
                }
            };
            db::insert_identity(
                c,
                &peer.fingerprint_hex(),
                &node_id,
                &peer.serial_hex,
                peer.not_before,
                peer.not_after,
            )?;
            db::bump_epoch(c)?;
            db::append_audit(
                c,
                db::AuditInsert {
                    actor_id: None,
                    action: "provision.probe_identity",
                    target_type: "node",
                    target_id: Some(&node_id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        })
        .map_err(|_| "probe_registration_failed".to_owned())?;
    app.node
        .coord
        .refresh_identities()
        .map_err(|_| "probe_registration_failed".to_owned())?;
    Ok(())
}

fn probe_config(app: &Appliance, url: &str) -> Result<aegis_config::NodeConfig, String> {
    let dir = app.dir.join("secrets/probe");
    let cfg = json!({
        "schema_version": "0.2",
        "node_id": PROBE_NODE,
        "role": "client",
        "management": {"enabled": false, "config_store": app.dir.join("probe-state.db").display().to_string()},
        "secrets": {"dir": dir.display().to_string()},
        "identity": {
            "peer_auth": "mutual_tls_1_3",
            "client_identity": "secret://cert.pem",
            "client_private_key": "secret://key.pem",
            "trusted_server_ca": "secret://ca.pem",
            "require_enrollment": true,
            "legacy_identity_until": 0
        },
        "inbounds": [{"id": "probe-socks", "kind": "socks5", "bind": "127.0.0.1:0"}],
        "outbounds": [{"id": "gateway", "kind": "agp_tunnel", "url": url, "server_name": appliance::INNER_SERVER_NAME}],
        "routing": {"default_action": "proxy", "default_outbound": "gateway"},
        "dns": {"mode": "remote_required", "ipv6_policy": "follow-routing-policy"}
    });
    aegis_config::parse_json(&cfg).map_err(|_| "probe_config_invalid".to_owned())
}

/// SOCKS5 CONNECT by name; returns the reply code (0 = success).
async fn socks(proxy: SocketAddr, host: &str, port: u16) -> Result<(u8, TcpStream), String> {
    let io = |_| "probe_socks_io".to_owned();
    let mut s = TcpStream::connect(proxy).await.map_err(io)?;
    s.write_all(&[5, 1, 0]).await.map_err(io)?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.map_err(io)?;
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(io)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(io)?;
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(io)?;
            usize::from(l[0]) + 2
        }
        _ => 0,
    };
    let mut skip = vec![0u8; rest];
    if head[1] == 0 {
        s.read_exact(&mut skip).await.map_err(io)?;
    }
    Ok((head[1], s))
}

struct Url {
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str, scheme: &str, default_port: u16) -> Result<Url, String> {
    let rest = url
        .strip_prefix(&format!("{scheme}://"))
        .ok_or("invalid_probe_url")?;
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') && !h.contains(':') => {
            (h.to_owned(), p.parse().map_err(|_| "invalid_probe_url")?)
        }
        _ => (auth.to_owned(), default_port),
    };
    if host.is_empty() || host.len() > 253 {
        return Err("invalid_probe_url".into());
    }
    Ok(Url {
        host,
        port,
        path: path.to_owned(),
    })
}

async fn http_status<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    host: &str,
    path: &str,
) -> Result<u16, String> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: aegis-probe\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|_| "probe_http_io".to_owned())?;
    let mut buf = [0u8; 64];
    let n = s
        .read(&mut buf)
        .await
        .map_err(|_| "probe_http_io".to_owned())?;
    let line = String::from_utf8_lossy(&buf[..n]);
    line.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| "probe_http_malformed".to_owned())
}

async fn check(proxy: SocketAddr, http_url: &str, https_url: &str) -> Result<(), String> {
    let u = parse_url(http_url, "http", 80)?;
    let (code, s) = socks(proxy, &u.host, u.port).await?;
    if code != 0 {
        return Err(format!("probe_http_refused_{code}"));
    }
    let status = http_status(s, &u.host, &u.path).await?;
    if !(200..400).contains(&status) {
        return Err(format!("probe_http_status_{status}"));
    }
    let u = parse_url(https_url, "https", 443)?;
    let (code, s) = socks(proxy, &u.host, u.port).await?;
    if code != 0 {
        return Err(format!("probe_https_refused_{code}"));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(aegis_identity::tls::provider())
        .with_safe_default_protocol_versions()
        .map_err(|_| "probe_tls".to_owned())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(u.host.clone())
        .map_err(|_| "invalid_probe_url".to_owned())?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, s)
        .await
        .map_err(|_| "probe_https_certificate_or_tls_failed".to_owned())?;
    let status = http_status(tls, &u.host, &u.path).await?;
    if !(200..400).contains(&status) {
        return Err(format!("probe_https_status_{status}"));
    }
    Ok(())
}

/// Run the probe against `wss://<hostname>/agp`, retrying while public DNS
/// and the edge converge (up to ~2 minutes).
pub async fn run(
    app: &Appliance,
    url: &str,
    http_url: &str,
    https_url: &str,
) -> Result<(), String> {
    let a = app;
    ensure_identity(a)?;
    let _ = std::fs::remove_file(app.dir.join("probe-state.db"));
    let node = aegis_node::start(aegis_node::StartOptions {
        config: probe_config(app, url)?,
        store_path: app.dir.join("probe-state.db"),
        failpoints: None,
    })
    .await
    .map_err(|_| "probe_client_start_failed".to_owned())?;
    let proxy = node
        .bound_addr("probe-socks")
        .ok_or("probe_socks_unavailable")?;
    let mut last = "probe_not_started".to_owned();
    let mut ok = false;
    for _ in 0..24 {
        match tokio::time::timeout(Duration::from_secs(20), socks(proxy, "localhost", 9)).await {
            // 0x02: refused by gateway policy => authenticated session works.
            Ok(Ok((2, _))) => {
                ok = true;
                break;
            }
            Ok(Ok((code, _))) => last = format!("probe_session_reply_{code}"),
            Ok(Err(e)) => last = e,
            Err(_) => last = "probe_timeout".into(),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    let result = if ok {
        tokio::time::timeout(Duration::from_secs(60), check(proxy, http_url, https_url))
            .await
            .unwrap_or_else(|_| Err("probe_timeout".into()))
    } else {
        Err(last)
    };
    node.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_file(app.dir.join("probe-state.db"));
    result
}
