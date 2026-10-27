//! End-to-end data-path probe for provisioning (SPEC-12 §7.2.7): an
//! in-process client with a dedicated, registered probe identity connects to
//! the public endpoint exactly like a device (public DNS, edge TLS,
//! connector, origin, inner mTLS), then:
//!
//! 1. opens a stream to `localhost:9`, which the gateway must refuse by
//!    policy — proving the authenticated AGP session reaches the gateway;
//! 2. fetches the operator's HTTP and HTTPS verification URLs through SOCKS
//!    with remote DNS (the HTTPS certificate is verified normally).
//!
//! The public hostname is looked up at the zone's own nameservers and the
//! probe connects to those addresses (TLS and Host still use the name):
//! resolvers, this server's or public ones, may still cache "no such name"
//! from before the record existed, which says nothing about devices.

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

/// Why the data path could not be verified.
#[derive(Debug)]
pub enum ProbeFailure {
    /// Nothing answered when this server connected to the public endpoint
    /// (TCP refused or timed out): its own route to the edge is blocked,
    /// which says nothing about devices elsewhere.
    Unreachable(String),
    /// Anything else: missing DNS, an HTTP error from the edge, TLS or
    /// session failures, verification sites unreachable.
    Failed(String),
}

impl ProbeFailure {
    pub fn detail(&self) -> &str {
        match self {
            ProbeFailure::Unreachable(d) | ProbeFailure::Failed(d) => d,
        }
    }
}

const PUBLIC_RESOLVERS: [&str; 4] = ["1.1.1.1:53", "8.8.8.8:53", "1.0.0.1:53", "8.8.4.4:53"];

fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("wss://")?;
    let auth = rest.split('/').next()?;
    let host = match auth.rsplit_once(':') {
        Some((h, p)) if p.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => auth,
    };
    (!host.is_empty()).then_some(host)
}

/// Addresses of `host` as devices will see them, waiting up to two minutes
/// while a new record appears. Asked of the zone's own nameservers, which
/// answer as soon as the record exists: public resolvers keep "no such name"
/// for the zone's negative TTL (30 minutes on Cloudflare) if anything looked
/// the name up before setup created it. Public DNS is the fallback when the
/// nameservers can't be reached from here, and this server's resolver when
/// neither can (UDP 53 blocked).
async fn resolve_public(host: &str) -> Result<Vec<String>, ProbeFailure> {
    let public: Vec<SocketAddr> = PUBLIC_RESOLVERS
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let authoritative = zone_nameservers(host, &public).await;
    let system = aegis_dns::Resolver::system(Duration::from_secs(4), true);
    let mut last = String::new();
    for _ in 0..24 {
        if !authoritative.is_empty() {
            match lookup(&authoritative, host).await {
                Ok(ips) => return Ok(ips),
                Err(aegis_dns::DnsError::NotFound) => {
                    last = format!("the zone's nameservers have no record for {host}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                // Not reachable from here: ask public DNS instead.
                Err(_) => {}
            }
        }
        match lookup(&public, host).await {
            Ok(ips) => return Ok(ips),
            Err(aegis_dns::DnsError::Timeout) => {
                // Public resolvers unreachable from here: use this server's.
                if let Ok(ips) = system.resolve(host).await {
                    if !ips.is_empty() {
                        return Ok(Vec::new());
                    }
                }
                last = format!("{host} does not resolve (public DNS unreachable from this server, and its own resolver has no answer)");
            }
            Err(e) => last = format!("public DNS: {host}: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    Err(ProbeFailure::Failed(format!(
        "{last}; check that the DNS record exists in Cloudflare"
    )))
}

/// One lookup through a fresh resolver: a reused one would answer from its
/// own cache of the last "no such name".
async fn lookup(servers: &[SocketAddr], host: &str) -> Result<Vec<String>, aegis_dns::DnsError> {
    let resolver = aegis_dns::Resolver::explicit(servers, Duration::from_secs(4), true)?;
    Ok(resolver
        .resolve(host)
        .await?
        .iter()
        .map(ToString::to_string)
        .collect())
}

/// Addresses of the nameservers for the zone holding `host`: the NS records
/// of its closest parent that has them, per public DNS. The zone existed
/// long before setup added the record, so no negative answer is cached for
/// these names. Empty when they can't be found.
async fn zone_nameservers(host: &str, public: &[SocketAddr]) -> Vec<SocketAddr> {
    let Ok(resolver) = aegis_dns::Resolver::explicit(public, Duration::from_secs(4), true) else {
        return Vec::new();
    };
    let mut name = host;
    while let Some((_, parent)) = name.split_once('.') {
        // A top-level domain's servers only refer onward.
        if !parent.contains('.') {
            break;
        }
        name = parent;
        let Ok(servers) = resolver.nameservers(name).await else {
            continue;
        };
        let mut addresses = Vec::new();
        for server in servers {
            if let Ok(ips) = resolver.resolve(&server).await {
                addresses.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, 53)));
            }
        }
        return addresses;
    }
    Vec::new()
}

fn probe_config(
    app: &Appliance,
    url: &str,
    connect_addresses: &[String],
) -> Result<aegis_config::NodeConfig, String> {
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
        "outbounds": [{"id": "gateway", "kind": "agp_tunnel", "url": url, "server_name": appliance::INNER_SERVER_NAME, "connect_addresses": connect_addresses}],
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

/// Why the probe's connection attempts failed, from its diagnostics notes.
/// Unreachable only when every attempt failed before anything answered.
fn connect_failure(
    sink: &aegis_telemetry::DiagnosticSink,
    host: &str,
    fallback: String,
) -> ProbeFailure {
    let records = sink.recording().map(|r| r.records).unwrap_or_default();
    let failures: Vec<_> = records
        .iter()
        .filter(|r| r.code == "client.connect.failed")
        .collect();
    let Some(last) = failures.last() else {
        return ProbeFailure::Failed(fallback);
    };
    let stage = last.attr("stage").unwrap_or("connect");
    let kind = last.attr("kind").unwrap_or("");
    let error = last.attr("error").unwrap_or("");
    let detail = match (stage, kind) {
        ("websocket", "http") => format!(
            "Cloudflare answered {host} with an error instead of reaching the gateway: {error}"
        ),
        ("websocket", "tls") => format!("TLS to {host} failed: {error}"),
        ("websocket", _) => format!("this server could not connect to {host}: {error}"),
        ("tls", _) => format!("the gateway's inner TLS check failed: {error}"),
        _ => format!("the gateway refused the test session: {error}"),
    };
    let unreachable = failures.iter().all(|r| {
        r.attr("stage") == Some("websocket")
            && matches!(r.attr("kind"), Some("connect" | "timeout"))
    });
    if unreachable {
        ProbeFailure::Unreachable(detail)
    } else {
        ProbeFailure::Failed(detail)
    }
}

/// Run the probe against `wss://<hostname>/agp`, retrying while public DNS
/// and the edge converge (up to ~2 minutes each).
pub async fn run(
    app: &Appliance,
    url: &str,
    http_url: &str,
    https_url: &str,
) -> Result<(), ProbeFailure> {
    let failed = ProbeFailure::Failed;
    ensure_identity(app).map_err(failed)?;
    let host = url_host(url).ok_or_else(|| ProbeFailure::Failed("invalid_probe_url".into()))?;
    let addresses = resolve_public(host).await?;
    let _ = std::fs::remove_file(app.dir.join("probe-state.db"));
    // The probe's own recorder: why each attempt failed (never exported).
    let sink = Arc::new(aegis_telemetry::DiagnosticSink::new());
    let _ = sink.start(Duration::from_secs(15 * 60));
    let node = aegis_node::start_with_diagnostics(
        aegis_node::StartOptions {
            config: probe_config(app, url, &addresses).map_err(failed)?,
            store_path: app.dir.join("probe-state.db"),
            failpoints: None,
        },
        Arc::clone(&sink),
    )
    .await
    .map_err(|_| ProbeFailure::Failed("probe_client_start_failed".into()))?;
    let proxy = node
        .bound_addr("probe-socks")
        .ok_or_else(|| ProbeFailure::Failed("probe_socks_unavailable".into()))?;
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
            .map_err(ProbeFailure::Failed)
    } else {
        Err(connect_failure(&sink, host, last))
    };
    node.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_file(app.dir.join("probe-state.db"));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_telemetry::{DiagnosticSink, Severity};

    fn sink(notes: &[(&str, &str, &str)]) -> DiagnosticSink {
        let s = DiagnosticSink::new();
        s.start(Duration::from_secs(60)).expect("start");
        for (stage, kind, error) in notes {
            s.note(
                Severity::Warn,
                "client.connect.failed",
                &[("stage", stage), ("kind", kind), ("error", error)],
            );
        }
        s
    }

    /// Needs internet access: `cargo test -p aegisd -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn zone_nameservers_answer_for_a_host() {
        let public: Vec<SocketAddr> = PUBLIC_RESOLVERS
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let servers = zone_nameservers("www.example.com", &public).await;
        assert!(!servers.is_empty());
        assert!(!lookup(&servers, "www.example.com")
            .await
            .expect("answer")
            .is_empty());
        assert_eq!(
            lookup(&servers, "aegis-no-such-name.example.com").await,
            Err(aegis_dns::DnsError::NotFound)
        );
        // Nothing to find above a top-level domain.
        assert!(zone_nameservers("example", &public).await.is_empty());
    }

    #[test]
    fn host_of_probe_url() {
        assert_eq!(
            url_host("wss://aegis.example.com/agp"),
            Some("aegis.example.com")
        );
        assert_eq!(
            url_host("wss://aegis.example.com:8443/agp"),
            Some("aegis.example.com")
        );
        assert_eq!(url_host("https://x/agp"), None);
    }

    #[test]
    fn only_unanswered_connections_count_as_unreachable() {
        let host = "aegis.example.com";
        let s = sink(&[
            ("websocket", "timeout", "timed out"),
            ("websocket", "connect", "refused"),
        ]);
        let f = connect_failure(&s, host, String::new());
        assert!(matches!(f, ProbeFailure::Unreachable(_)), "{f:?}");
        assert!(
            f.detail()
                .contains("could not connect to aegis.example.com"),
            "{f:?}"
        );
        // An HTTP error from the edge is a real problem, not this host's route.
        let s = sink(&[
            ("websocket", "connect", "refused"),
            ("websocket", "http", "HTTP error: 530"),
        ]);
        let f = connect_failure(&s, host, String::new());
        assert!(matches!(f, ProbeFailure::Failed(_)), "{f:?}");
        assert!(f.detail().contains("530"), "{f:?}");
        let s = sink(&[("tls", "inner", "invalid peer certificate")]);
        assert!(matches!(
            connect_failure(&s, host, String::new()),
            ProbeFailure::Failed(_)
        ));
        // Nothing recorded: the generic reason, as a hard failure.
        let s = sink(&[]);
        let f = connect_failure(&s, host, "probe_timeout".into());
        assert!(matches!(&f, ProbeFailure::Failed(d) if d == "probe_timeout"));
    }
}
