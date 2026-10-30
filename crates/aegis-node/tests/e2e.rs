#![allow(clippy::panic)]
//! End-to-end: client SOCKS5/HTTP CONNECT → WS → inner mTLS → AGP →
//! gateway admission → restricted egress. Covers TC-N01, TC-N02, TC-N03,
//! TC-N05 (direct path), TC-P08, TC-P09 and TC-P18 at system level.

use aegis_config::parse_toml;
use aegis_contracts::Role;
use aegis_core::ActivateRequest;
use aegis_identity::pki::{self, CaBundle, DEFAULT_NODE_VALIDITY};
use aegis_identity::tls::{parse_certs, PeerIdentity};
use aegis_node::{start, NodeRuntime, StartOptions};
use aegis_storage as db;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A non-loopback local address (no packets are sent). Loopback targets are
/// denied by egress policy, so the echo target needs a LAN address.
fn lan_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

async fn echo_server(ip: IpAddr) -> SocketAddr {
    let l = TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .expect("bind echo");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    addr
}

fn write(dir: &Path, rel: &str, content: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    std::fs::write(&p, content).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
}

struct Pki {
    ca: CaBundle,
    client_fp: [u8; 32],
}

fn provision(secrets: &Path) -> Pki {
    let ca = pki::generate_ca("e2e-ca", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let (gw_cert, gw_key) = pki::issue_direct(
        &ca,
        "gw-1",
        Role::Gateway,
        &["gateway.aegis.internal".into()],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("gw");
    let (client_key, csr) = pki::generate_key_and_csr("laptop-1").expect("csr");
    let client_cert = pki::sign_csr(
        &ca,
        &csr,
        "laptop-1",
        Role::Client,
        &[],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("sign");
    for (rel, content) in [
        ("identity/server-cert", gw_cert.as_str()),
        ("identity/server-key", gw_key.as_str()),
        ("identity/client-ca", ca.cert_pem.as_str()),
        ("identity/server-ca", ca.cert_pem.as_str()),
        ("identity/client-cert", client_cert.as_str()),
        ("identity/client-key", client_key.as_str()),
        ("identity/ca-cert", ca.cert_pem.as_str()),
        ("identity/ca-key", ca.key_pem.as_str()),
        ("socks-password", "s3cret\n"),
    ] {
        write(secrets, rel, content);
    }
    let fp = PeerIdentity::from_der(parse_certs(&client_cert).expect("c")[0].as_ref())
        .expect("peer")
        .fingerprint;
    Pki { ca, client_fp: fp }
}

fn gateway_toml(dir: &Path, allow_net: &str) -> String {
    format!(
        r#"
schema_version = "0.1"
node_id = "gw-1"
role = "gateway"
[management]
enabled = false
config_store = "{store}"
[secrets]
dir = "{secrets}"
[identity]
peer_auth = "mutual_tls_1_3"
server_identity = "secret://identity/server-cert"
server_private_key = "secret://identity/server-key"
trusted_client_ca = "secret://identity/client-ca"
ca_certificate = "secret://identity/ca-cert"
ca_private_key = "secret://identity/ca-key"
[[inbounds]]
id = "ingress-ws"
kind = "websocket"
bind = "127.0.0.1:0"
[[outbounds]]
id = "egress"
kind = "direct_tcp"
restricted_address_policy = "allow-private"
[routing]
default_outbound = "egress"
default_action = "deny"
[[routing.rules]]
id = "public"
match = "authenticated-and-public-destination"
action = "proxy"
outbound = "egress"
[[routing.rules]]
id = "lab-net"
match = {{ cidrs = ["{allow_net}"] }}
action = "proxy"
outbound = "egress"
[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
resolver = "system"
"#,
        store = dir.join("gw.db").display(),
        secrets = dir.join("secrets").display(),
    )
}

fn client_toml(dir: &Path, secrets: &Path, gw: SocketAddr) -> String {
    format!(
        r#"
schema_version = "0.1"
node_id = "laptop-1"
role = "client"
[management]
enabled = false
config_store = "{store}"
[secrets]
dir = "{secrets}"
[identity]
peer_auth = "mutual_tls_1_3"
client_identity = "secret://identity/client-cert"
client_private_key = "secret://identity/client-key"
trusted_server_ca = "secret://identity/server-ca"
[[inbounds]]
id = "socks"
kind = "socks5"
bind = "127.0.0.1:0"
[[inbounds]]
id = "socks-auth"
kind = "socks5"
bind = "127.0.0.1:0"
auth = {{ username = "alice", password = "secret://socks-password" }}
[[inbounds]]
id = "http"
kind = "http_connect"
bind = "127.0.0.1:0"
[[outbounds]]
id = "tunnel"
kind = "agp_tunnel"
url = "ws://{gw}/agp"
server_name = "gateway.aegis.internal"
[routing]
default_outbound = "tunnel"
default_action = "proxy"
[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
"#,
        store = dir.join("client.db").display(),
        secrets = secrets.display(),
        gw = gw,
    )
}

struct Env {
    _dir: tempfile::TempDir,
    gw: NodeRuntime,
    client: NodeRuntime,
    echo: SocketAddr,
    pki: Pki,
}

async fn setup() -> Option<Env> {
    let Some(ip) = lan_ip() else {
        eprintln!("BLOCKED: no non-loopback interface for an egress-permitted echo target");
        return None;
    };
    let echo = echo_server(ip).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    let pki = provision(&secrets);
    let gw_cfg = parse_toml(&gateway_toml(dir.path(), &format!("{ip}/32"))).expect("gw cfg");
    let gw = start(StartOptions {
        config: gw_cfg,
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gateway start");
    let gw_addr = gw.bound_addr("ingress-ws").expect("ws addr");
    let client_cfg = parse_toml(&client_toml(dir.path(), &secrets, gw_addr)).expect("client cfg");
    let client = start(StartOptions {
        config: client_cfg,
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client start");
    Some(Env {
        _dir: dir,
        gw,
        client,
        echo,
        pki,
    })
}

/// SOCKS5 CONNECT (no auth). Returns the stream and the reply code.
async fn socks_connect(
    proxy: SocketAddr,
    target: &str,
    auth: Option<(&str, &str)>,
) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.expect("connect proxy");
    match auth {
        None => {
            s.write_all(&[5, 1, 0]).await.expect("greet");
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await.expect("method");
            assert_eq!(r, [5, 0]);
        }
        Some((u, p)) => {
            s.write_all(&[5, 1, 2]).await.expect("greet");
            let mut r = [0u8; 2];
            s.read_exact(&mut r).await.expect("method");
            assert_eq!(r, [5, 2]);
            let mut a = vec![1, u.len() as u8];
            a.extend_from_slice(u.as_bytes());
            a.push(p.len() as u8);
            a.extend_from_slice(p.as_bytes());
            s.write_all(&a).await.expect("auth");
            s.read_exact(&mut r).await.expect("auth reply");
            if r[1] != 0 {
                return (s, 0xFF);
            }
        }
    }
    let (host, port) = target.rsplit_once(':').expect("target");
    let port: u16 = port.parse().expect("port");
    let mut req = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.expect("request");
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.expect("reply");
    let rest = match head[3] {
        1 => 6,
        4 => 18,
        _ => 6,
    };
    let mut skip = vec![0u8; rest];
    s.read_exact(&mut skip).await.expect("bound addr");
    (s, head[1])
}

async fn echo_roundtrip(mut s: TcpStream, size: usize) {
    let mut data = vec![0u8; size];
    rand::thread_rng().fill_bytes(&mut data);
    let expected = Sha256::digest(&data);
    let (mut r, mut w) = s.split();
    let send = async {
        w.write_all(&data).await.expect("write");
        w.shutdown().await.expect("half close");
    };
    let mut got = Vec::new();
    let recv = r.read_to_end(&mut got);
    let (_, res) = tokio::join!(send, recv);
    res.expect("read");
    assert_eq!(got.len(), size);
    assert_eq!(Sha256::digest(&got), expected, "byte-exact transfer");
}

async fn controlled_dns(ip: std::net::Ipv4Addr) -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("DNS bind");
    let address = socket.local_addr().expect("DNS address");
    tokio::spawn(async move {
        let mut bytes = [0u8; 512];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut bytes).await else {
                return;
            };
            if n < 17 {
                continue;
            }
            let mut end = 12usize;
            while end < n && bytes[end] != 0 {
                end += 1 + usize::from(bytes[end]);
            }
            if end + 5 > n {
                continue;
            }
            let qtype = u16::from_be_bytes([bytes[end + 1], bytes[end + 2]]);
            let answer = qtype == 1;
            let mut response = bytes[..2].to_vec();
            response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, u8::from(answer), 0, 0, 0, 0]);
            response.extend_from_slice(&bytes[12..end + 5]);
            if answer {
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4]);
                response.extend_from_slice(&ip.octets());
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    address
}
async fn site_response<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut stream: T) {
    let mut bytes = [0u8; 4096];
    let _ = stream.read(&mut bytes).await;
    let body = b"aegis-http-https-fixture";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;
}
async fn site(ip: IpAddr, tls: Option<std::sync::Arc<rustls::ServerConfig>>) -> SocketAddr {
    let listener = TcpListener::bind((ip, 0)).await.expect("site bind");
    let address = listener.local_addr().expect("site address");
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let tls = tls.clone();
            tokio::spawn(async move {
                if let Some(tls) = tls {
                    if let Ok(stream) = tokio_rustls::TlsAcceptor::from(tls).accept(stream).await {
                        site_response(stream).await;
                    }
                } else {
                    site_response(stream).await;
                }
            });
        }
    });
    address
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks_hostname_http_https_across_tls_terminating_edge_requires_registered_mtls() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let Some(IpAddr::V4(ip)) = lan_ip() else {
            eprintln!("BLOCKED: controlled egress requires IPv4 LAN interface");
            return;
        };
        let directory = tempfile::tempdir().expect("temp");
        let root = directory.path();
        let secrets = root.join("secrets");
        let identity = provision(&secrets);
        let dns = controlled_dns(ip).await;
        let web_ca =
            pki::generate_ca("web site test CA", pki::DEFAULT_CA_VALIDITY).expect("web CA");
        let (site_cert, site_key) = pki::issue_direct(
            &web_ca,
            "website",
            Role::Gateway,
            &["site.example.test".into()],
            DEFAULT_NODE_VALIDITY,
        )
        .expect("web cert");
        let site_tls = aegis_identity::tls::public_server_config(
            &site_cert,
            &site_key,
            "site.example.test",
            Some(&web_ca.cert_pem),
        )
        .expect("target TLS");
        let http = site(IpAddr::V4(ip), None).await;
        let https = site(IpAddr::V4(ip), Some(site_tls)).await;
        let mut gateway =
            parse_toml(&gateway_toml(root, &format!("{ip}/32"))).expect("gateway config");
        gateway.schema_version = "0.2".into();
        gateway.identity.require_enrollment = true;
        gateway.identity.legacy_identity_until = Some(0);
        gateway.dns.resolver = Some(aegis_config::ResolverKind::Explicit);
        gateway.dns.nameservers = vec![dns.to_string()];
        gateway.dns.ipv6_policy = aegis_config::Ipv6Policy::Block;
        // The fixture site lives on the LAN: a CIDR-only rule cannot authorize
        // an unresolved name, so scope the private range to the hostname.
        gateway.routing.rules.push(aegis_config::RuleConfig {
            id: "lab-site".into(),
            matcher: aegis_config::MatchConfig::Table(aegis_config::MatchTable {
                domains: vec!["site.example.test".into()],
                cidrs: vec![format!("{ip}/32")],
                ..Default::default()
            }),
            action: aegis_config::RouteActionConfig::Proxy,
            outbound: Some("egress".into()),
            priority: None,
        });
        let store = db::Store::open(root.join("gw.db")).expect("store");
        let cert = std::fs::read_to_string(secrets.join("identity/client-cert")).expect("cert");
        let peer =
            PeerIdentity::from_der(parse_certs(&cert).expect("PEM")[0].as_ref()).expect("peer");
        let node_id = db::new_id();
        store
            .tx(|c| {
                db::insert_node(
                    c,
                    &db::NodeRow {
                        id: node_id.clone(),
                        name: peer.node_id.clone(),
                        role: "client".into(),
                        cert_fingerprint: Some(peer.fingerprint_hex()),
                        cert_serial: Some(peer.serial_hex.clone()),
                        status: "active".into(),
                        generation: 1,
                        not_after: Some(peer.not_after),
                        created_at: db::now_unix(),
                    },
                )?;
                db::insert_identity(
                    c,
                    &peer.fingerprint_hex(),
                    &node_id,
                    &peer.serial_hex,
                    peer.not_before,
                    peer.not_after,
                )
            })
            .expect("enroll before starting");
        drop(store);
        let gateway = start(StartOptions {
            config: gateway,
            store_path: root.join("gw.db"),
            failpoints: None,
        })
        .await
        .expect("gateway");
        let address = gateway.bound_addr("ingress-ws").expect("WS");
        let edge_ca =
            pki::generate_ca("independent edge CA", pki::DEFAULT_CA_VALIDITY).expect("edge CA");
        let (edge_cert, edge_key) = pki::issue_direct(
            &edge_ca,
            "edge",
            Role::Gateway,
            &["localhost".into()],
            DEFAULT_NODE_VALIDITY,
        )
        .expect("edge cert");
        let tls = aegis_identity::tls::public_server_config(
            &edge_cert,
            &edge_key,
            "localhost",
            Some(&edge_ca.cert_pem),
        )
        .expect("edge TLS");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("edge bind");
        let edge = listener.local_addr().expect("edge address");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let tls = std::sync::Arc::clone(&tls);
                tokio::spawn(async move {
                    if let Ok(mut incoming) =
                        tokio_rustls::TlsAcceptor::from(tls).accept(stream).await
                    {
                        if let Ok(mut origin) = TcpStream::connect(address).await {
                            let _ = tokio::io::copy_bidirectional(&mut incoming, &mut origin).await;
                        }
                    }
                });
            }
        });
        write(&secrets, "edge-ca.pem", &edge_ca.cert_pem);
        let mut client_cfg =
            parse_toml(&client_toml(root, &secrets, address)).expect("client config");
        client_cfg.schema_version = "0.2".into();
        client_cfg.identity.require_enrollment = true;
        client_cfg.identity.legacy_identity_until = Some(0);
        client_cfg.outbounds[0].url = Some(format!("wss://localhost:{}/agp", edge.port()));
        client_cfg.outbounds[0].outer_ca = Some("secret://edge-ca.pem".into());
        let client = start(StartOptions {
            config: client_cfg.clone(),
            store_path: root.join("client.db"),
            failpoints: None,
        })
        .await
        .expect("client");
        let socks = client.bound_addr("socks").expect("SOCKS");
        assert!(
            client_cfg.dns.resolver.is_none(),
            "no client destination resolver is configured"
        );
        let (mut plain, code) =
            socks_connect(socks, &format!("site.example.test:{}", http.port()), None).await;
        assert_eq!(code, 0, "gateway alone resolves controlled hostname");
        plain
            .write_all(b"GET / HTTP/1.1\r\nHost: site.example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("HTTP request");
        let mut response = String::new();
        plain
            .read_to_string(&mut response)
            .await
            .expect("HTTP response");
        assert!(response.ends_with("aegis-http-https-fixture"));
        let (stream, code) =
            socks_connect(socks, &format!("site.example.test:{}", https.port()), None).await;
        assert_eq!(code, 0);
        let tls = rustls::ClientConfig::builder_with_provider(aegis_identity::tls::provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("versions")
            .with_root_certificates(
                aegis_identity::tls::root_store(&web_ca.cert_pem).expect("target roots"),
            )
            .with_no_client_auth();
        let mut stream = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls))
            .connect("site.example.test".try_into().expect("SNI"), stream)
            .await
            .expect("end-to-end destination HTTPS");
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: site.example.test\r\nConnection: close\r\n\r\n")
            .await
            .expect("HTTPS request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("HTTPS response");
        assert!(response.ends_with("aegis-http-https-fixture"));
        // Same trusted CA + correct role/URI is insufficient without enrollment.
        let rogue_dir = root.join("rogue");
        let (rogue_cert, rogue_key) = pki::issue_direct(
            &identity.ca,
            "rogue",
            Role::Client,
            &[],
            DEFAULT_NODE_VALIDITY,
        )
        .expect("rogue CA-issued identity");
        for (file, value) in [
            ("identity/client-cert", rogue_cert.as_str()),
            ("identity/client-key", rogue_key.as_str()),
            ("identity/server-ca", identity.ca.cert_pem.as_str()),
            ("edge-ca.pem", edge_ca.cert_pem.as_str()),
            ("socks-password", "s3cret\n"),
        ] {
            write(&rogue_dir, file, value);
        }
        let mut rogue = client_cfg;
        rogue.node_id = "rogue".into();
        rogue.secrets.dir = rogue_dir.to_string_lossy().into_owned();
        let rogue = start(StartOptions {
            config: rogue,
            store_path: root.join("rogue.db"),
            failpoints: None,
        })
        .await
        .expect("local rogue process");
        let (_, code) = socks_connect(
            rogue.bound_addr("socks").expect("rogue SOCKS"),
            &format!("site.example.test:{}", http.port()),
            None,
        )
        .await;
        assert_ne!(code, 0, "edge cannot replace device authorization");
        rogue.shutdown(Duration::from_secs(1)).await;
        client.shutdown(Duration::from_secs(1)).await;
        gateway.shutdown(Duration::from_secs(1)).await;
    })
    .await
    .expect("bounded e2e deadline");
}

/// Origin that records each request it receives (head + body) and answers
/// once, then closes.
async fn recording_origin(ip: IpAddr) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind((ip, 0)).await.expect("origin bind");
    let address = listener.local_addr().expect("origin address");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let Ok(n) = s.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= end + 4 + len {
                            break;
                        }
                    }
                }
                // Give a misbehaving proxy time to push extra bytes.
                tokio::time::sleep(Duration::from_millis(200)).await;
                let mut extra = [0u8; 1024];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_millis(50), s.read(&mut extra)).await
                {
                    got.extend_from_slice(&extra[..n]);
                }
                log.lock()
                    .expect("log")
                    .push(String::from_utf8_lossy(&got).to_string());
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    (address, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn plain_http_forwarding_through_the_tunnel() {
    let Some(env) = setup().await else { return };
    let ip = env.echo.ip();
    let (origin, seen) = recording_origin(ip).await;
    let http = env.client.bound_addr("http").expect("http inbound");
    // A keep-alive client pipelines a second request for another path: it
    // must never reach the origin through the first request's stream.
    let mut s = TcpStream::connect(http).await.expect("proxy");
    s.write_all(
        format!(
            "GET http://{origin}/one?x=1 HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\nGET http://{origin}/two HTTP/1.1\r\nHost: {origin}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .expect("request");
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut response))
        .await
        .expect("bounded")
        .expect("response");
    assert!(
        response.starts_with("HTTP/1.1 200 OK") && response.ends_with("ok"),
        "{response}"
    );
    // POST body is forwarded exactly.
    let mut s = TcpStream::connect(http).await.expect("proxy");
    s.write_all(format!("POST http://{origin}/form HTTP/1.1\r\nHost: {origin}\r\nContent-Length: 5\r\n\r\nhello").as_bytes())
        .await
        .expect("post");
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut response))
        .await
        .expect("bounded")
        .expect("response");
    assert!(response.ends_with("ok"));
    // Plain-HTTP requests still obey gateway egress policy.
    let mut s = TcpStream::connect(http).await.expect("proxy");
    s.write_all(b"GET http://169.254.169.254/latest HTTP/1.1\r\n\r\n")
        .await
        .expect("w");
    let mut response = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut response)).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    let seen = seen.lock().expect("log").clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    let get = &seen[0];
    assert!(get.starts_with("GET /one?x=1 HTTP/1.1\r\n"), "{get}");
    assert!(get.contains("Connection: close\r\n") && get.contains("Accept: */*\r\n"));
    assert!(!get.to_ascii_lowercase().contains("proxy-"), "{get}");
    assert!(
        !get.contains("/two"),
        "pipelined request leaked to the origin: {get}"
    );
    assert!(seen[1].starts_with("POST /form HTTP/1.1\r\n") && seen[1].ends_with("\r\n\r\nhello"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_socks_http_policy_and_identity() {
    let Some(env) = setup().await else { return };
    let socks = env.client.bound_addr("socks").expect("socks");
    let echo = env.echo.to_string();

    // TC-N01/TC-N05: byte-exact bidirectional transfer with half-close.
    let (s, code) = socks_connect(socks, &echo, None).await;
    assert_eq!(code, 0, "SOCKS CONNECT through the tunnel");
    echo_roundtrip(s, 2 * 1024 * 1024 + 3).await;

    // Concurrent streams share one session.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let echo = echo.clone();
        handles.push(tokio::spawn(async move {
            let (s, code) = socks_connect(socks, &echo, None).await;
            assert_eq!(code, 0);
            echo_roundtrip(s, 64 * 1024).await;
        }));
    }
    for h in handles {
        h.await.expect("stream");
    }
    assert_eq!(env.gw.ctx.sessions.count(), 1, "one multiplexed session");

    // Authenticated SOCKS inbound.
    let auth = env.client.bound_addr("socks-auth").expect("socks-auth");
    let (_, code) = socks_connect(auth, &echo, Some(("alice", "wrong"))).await;
    assert_eq!(code, 0xFF);
    let (s, code) = socks_connect(auth, &echo, Some(("alice", "s3cret"))).await;
    assert_eq!(code, 0);
    echo_roundtrip(s, 1024).await;

    // TC-N02: HTTP CONNECT.
    let http = env.client.bound_addr("http").expect("http");
    let mut h = TcpStream::connect(http).await.expect("http");
    h.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .expect("w");
    let mut buf = [0u8; 39];
    h.read_exact(&mut buf).await.expect("status");
    assert!(
        buf.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&buf)
    );
    echo_roundtrip(h, 4096).await;

    // TC-N03: SSRF — loopback literal and a name resolving to loopback are
    // denied by gateway egress policy (SOCKS 0x02 = not allowed).
    let gw_ws = env.gw.bound_addr("ingress-ws").expect("ws");
    let (_, code) = socks_connect(socks, &gw_ws.to_string(), None).await;
    assert_eq!(code, 2, "loopback literal denied");
    let (_, code) = socks_connect(socks, &format!("localhost:{}", gw_ws.port()), None).await;
    assert_eq!(
        code, 2,
        "DNS-resolved loopback denied (rebinding/SSRF guard)"
    );
    let (_, code) = socks_connect(socks, "169.254.169.254:80", None).await;
    assert_eq!(code, 2, "metadata endpoint denied");

    // TC-P18: tighten gateway policy; the next OPEN on the SAME session is
    // denied under the new revision.
    let coord = &env.gw.ctx.coord;
    let profile = coord
        .store()
        .read(|c| db::list_profiles(c, None, 10))
        .expect("p")
        .remove(0);
    let p = coord
        .patch_profile(Some("owner"), &profile.id, &profile.etag(), None, Some(&json!({"routing": {"rules": [
            {"id": "public", "match": "authenticated-and-public-destination", "action": "proxy", "outbound": "egress"}
        ]}})))
        .expect("patch");
    let report = coord
        .validate(
            Some("owner"),
            &profile.id,
            &p.etag(),
            &p.desired_revision_id,
        )
        .expect("validate");
    assert!(report.valid, "{:?}", report.errors);
    let job = coord
        .submit_activation(
            &ActivateRequest {
                actor_id: Some("owner".into()),
                profile_id: profile.id.clone(),
                if_match: p.etag(),
                idempotency_key: "e2e-tighten-0001".into(),
                target_revision_id: report.target_revision_id,
                config_digest: report.config_digest,
                validation_id: report.validation_id,
            },
            "/e2e",
        )
        .expect("submit");
    assert_eq!(coord.run_job(&job.id).expect("run").status, "succeeded");
    let (_, code) = socks_connect(socks, &echo, None).await;
    assert_eq!(code, 2, "tightened ACL applies to the next OPEN");
    // The same private address encoded as a hostname must not bypass the
    // public-only rule after resolution, even though egress allows private.
    let mut named = TcpStream::connect(socks).await.expect("proxy");
    named.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0u8; 2];
    named.read_exact(&mut method).await.expect("method");
    assert_eq!(method, [5, 0]);
    let name = env.echo.ip().to_string();
    let mut request = vec![5, 1, 0, 3, name.len() as u8];
    request.extend_from_slice(name.as_bytes());
    request.extend_from_slice(&env.echo.port().to_be_bytes());
    named.write_all(&request).await.expect("connect");
    let mut reply = [0u8; 10];
    named.read_exact(&mut reply).await.expect("reply");
    assert_eq!(
        reply[1], 2,
        "domain encoding must retain the public constraint"
    );
    assert_eq!(
        env.gw.ctx.sessions.count(),
        1,
        "same authenticated session reused"
    );

    // TC-P09: revoke the client identity; its session is closed and the
    // reconnect handshake is refused.
    let node_id = db::new_id();
    coord
        .store()
        .tx(|c| {
            db::insert_node(
                c,
                &db::NodeRow {
                    id: node_id.clone(),
                    name: "laptop-1".into(),
                    role: "client".into(),
                    cert_fingerprint: Some(hex_encode(&env.pki.client_fp)),
                    cert_serial: Some("00".into()),
                    status: "active".into(),
                    generation: 1,
                    not_after: None,
                    created_at: db::now_unix(),
                },
            )?;
            db::insert_identity(
                c,
                &hex_encode(&env.pki.client_fp),
                &node_id,
                "00",
                0,
                i64::MAX,
            )
        })
        .expect("register node");
    let node = coord
        .store()
        .read(|c| db::get_node(c, &node_id))
        .expect("node");
    let rj = coord
        .submit_revoke(
            Some("owner"),
            &node_id,
            &node.etag(),
            "e2e-revoke-00001",
            "/r",
        )
        .expect("revoke");
    assert_eq!(coord.run_revoke(&rj.id).expect("run").status, "succeeded");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        env.gw.ctx.sessions.count(),
        0,
        "revoked identity's session closed"
    );
    let (_, code) = socks_connect(socks, "93.184.216.34:443", None).await;
    assert_ne!(code, 0, "revoked client cannot re-authenticate");
    let _ = env.pki.ca.cert_pem.len();
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tc_p08_client_from_foreign_ca_cannot_connect() {
    let Some(ip) = lan_ip() else { return };
    let echo = echo_server(ip).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    provision(&secrets);
    // Replace the client identity with one from an unrelated CA.
    let rogue = pki::generate_ca("rogue", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let (cert, key) =
        pki::issue_direct(&rogue, "laptop-1", Role::Client, &[], DEFAULT_NODE_VALIDITY)
            .expect("rogue");
    write(&secrets, "identity/client-cert", &cert);
    write(&secrets, "identity/client-key", &key);
    let gw = start(StartOptions {
        config: parse_toml(&gateway_toml(dir.path(), &format!("{ip}/32"))).expect("cfg"),
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gw");
    let client = start(StartOptions {
        config: parse_toml(&client_toml(
            dir.path(),
            &secrets,
            gw.bound_addr("ingress-ws").expect("ws"),
        ))
        .expect("cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client");
    let (_, code) = socks_connect(
        client.bound_addr("socks").expect("socks"),
        &echo.to_string(),
        None,
    )
    .await;
    assert_ne!(code, 0, "rejected before any proxy command");
    assert_eq!(gw.ctx.sessions.count(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_restores_active_revision_and_serves() {
    let Some(ip) = lan_ip() else { return };
    let echo = echo_server(ip).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    provision(&secrets);
    let cfg = parse_toml(&gateway_toml(dir.path(), &format!("{ip}/32"))).expect("cfg");
    let gw = start(StartOptions {
        config: cfg.clone(),
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gw");
    let rev = gw.ctx.gate.current_revision();
    gw.shutdown(Duration::from_millis(100)).await;
    let gw = start(StartOptions {
        config: cfg,
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gw restart");
    assert!(matches!(
        gw.recovery,
        aegis_core::RecoveryOutcome::Restored { .. }
    ));
    assert_eq!(
        gw.ctx.gate.current_revision(),
        rev,
        "state persisted across restart"
    );
    let client = start(StartOptions {
        config: parse_toml(&client_toml(
            dir.path(),
            &secrets,
            gw.bound_addr("ingress-ws").expect("ws"),
        ))
        .expect("cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client");
    let (s, code) = socks_connect(
        client.bound_addr("socks").expect("socks"),
        &echo.to_string(),
        None,
    )
    .await;
    assert_eq!(code, 0);
    echo_roundtrip(s, 10_000).await;
}

fn activate_patch(node: &NodeRuntime, patch: serde_json::Value) {
    let coord = &node.ctx.coord;
    let original = coord
        .store()
        .read(|c| db::list_profiles(c, None, 10))
        .expect("profiles")
        .remove(0);
    let profile = coord
        .patch_profile(None, &original.id, &original.etag(), None, Some(&patch))
        .expect("patch");
    let report = coord
        .validate(
            None,
            &profile.id,
            &profile.etag(),
            &profile.desired_revision_id,
        )
        .expect("validate");
    assert!(report.valid, "{:?}", report.errors);
    let job = coord
        .submit_activation(
            &ActivateRequest {
                actor_id: None,
                profile_id: profile.id.clone(),
                if_match: profile.etag(),
                idempotency_key: db::new_id(),
                target_revision_id: report.target_revision_id,
                config_digest: report.config_digest,
                validation_id: report.validation_id,
            },
            "/test",
        )
        .expect("submit");
    assert_eq!(
        coord.run_job(&job.id).expect("activate").status,
        "succeeded"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tunnel_updates_use_new_endpoint_and_preserve_admitted_streams() {
    let Some(env) = setup().await else { return };
    let socks = env.client.bound_addr("socks").expect("socks");
    let (old_stream, code) = socks_connect(socks, &env.echo.to_string(), None).await;
    assert_eq!(code, 0);
    let second_dir = tempfile::tempdir().expect("tmp");
    let mut config = parse_toml(&gateway_toml(
        second_dir.path(),
        &format!("{}/32", env.echo.ip()),
    ))
    .expect("config");
    config.secrets = env.gw.ctx.startup.secrets.clone();
    let second = start(StartOptions {
        config,
        store_path: second_dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("second gateway");
    let mut outbounds = serde_json::to_value(&env.client.ctx.startup.outbounds).expect("outbounds");
    outbounds[0]["url"] = json!(format!(
        "ws://{}/agp",
        second.bound_addr("ingress-ws").expect("ws")
    ));
    activate_patch(&env.client, json!({"outbounds": outbounds}));
    let (new_stream, code) = socks_connect(socks, &env.echo.to_string(), None).await;
    assert_eq!(code, 0);
    assert_eq!(
        second.ctx.sessions.count(),
        1,
        "new admission must use the replacement gateway"
    );
    echo_roundtrip(old_stream, 4096).await;
    echo_roundtrip(new_stream, 4096).await;

    // Changing the TLS name must never reuse an already-authenticated session.
    outbounds[0]["server_name"] = json!("wrong-gateway.example");
    activate_patch(&env.client, json!({"outbounds": outbounds}));
    let (_, code) = socks_connect(socks, &env.echo.to_string(), None).await;
    assert_ne!(
        code, 0,
        "changed TLS name must be verified on a new session"
    );

    // Failed preparation must not silently fall back to the cached tunnel.
    outbounds[0]["server_name"] = json!("gateway.aegis.internal");
    outbounds[0]["outer_ca"] = json!("secret://missing-ca");
    activate_patch(&env.client, json!({"outbounds": outbounds}));
    let (_, code) = socks_connect(socks, &env.echo.to_string(), None).await;
    assert_ne!(code, 0, "unreadable replacement trust anchor fails closed");

    // A newly added outbound also becomes usable without restarting.
    outbounds[0]["outer_ca"] = serde_json::Value::Null;
    outbounds[0]["id"] = json!("replacement");
    activate_patch(
        &env.client,
        json!({"outbounds": outbounds, "routing": {"default_outbound": "replacement"}}),
    );
    let (stream, code) = socks_connect(socks, &env.echo.to_string(), None).await;
    assert_eq!(code, 0);
    echo_roundtrip(stream, 1024).await;
    env.client.shutdown(Duration::from_millis(100)).await;
    env.gw.shutdown(Duration::from_millis(100)).await;
    second.shutdown(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_limits_cover_pending_agp_and_live_sessions() {
    use aegis_buffer::Budget;
    use aegis_session::{client_handshake, SessionConfig};
    use aegis_transport_ws::WsClientConfig;
    use std::sync::Arc;
    // Exercise the pending limit separately from the global session limit.
    for (pending, sessions) in [(1, 2), (2, 1)] {
        let dir = tempfile::tempdir().expect("tmp");
        let secrets = dir.path().join("secrets");
        provision(&secrets);
        let mut config = parse_toml(&gateway_toml(dir.path(), "10.0.0.1/32")).expect("config");
        config.core.max_sessions = sessions;
        config.inbounds[0].max_pending_handshakes = pending;
        let gw = start(StartOptions {
            config,
            store_path: dir.path().join("gw.db"),
            failpoints: None,
        })
        .await
        .expect("gateway");
        let ws_config = WsClientConfig {
            url: format!("ws://{}/agp", gw.bound_addr("ingress-ws").expect("ws")),
            outer_ca_pem: None,
            outer_server_name: None,
            connect_addresses: Vec::new(),
            connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            max_message_bytes: 128 * 1024,
        };
        let tls_config = aegis_identity::client_config(
            &std::fs::read_to_string(secrets.join("identity/client-cert")).expect("cert"),
            &std::fs::read_to_string(secrets.join("identity/client-key")).expect("key"),
            &std::fs::read_to_string(secrets.join("identity/server-ca")).expect("ca"),
        )
        .expect("TLS config");
        let connect = || async {
            let ws = aegis_transport_ws::connect(&ws_config)
                .await
                .map_err(|e| e.to_string())?;
            let (tls, _) = aegis_identity::tls::connect(
                tls_config.clone(),
                "gateway.aegis.internal",
                ws,
                Duration::from_secs(2),
            )
            .await
            .map_err(|e| e.to_string())?;
            client_handshake(
                tls,
                SessionConfig {
                    node_id: "laptop-1".into(),
                    ..Default::default()
                },
                Budget::root(8 * 1024 * 1024),
                Arc::new(aegis_contracts::observability::NoopObservability),
            )
            .await
            .map_err(|e| e.to_string())
        };
        let ws = aegis_transport_ws::connect(&ws_config).await.expect("ws");
        let (tls, _) = aegis_identity::tls::connect(
            tls_config.clone(),
            "gateway.aegis.internal",
            ws,
            Duration::from_secs(2),
        )
        .await
        .expect("TLS");
        // Complete TLS while leaving HELLO pending. Neither quota may be
        // released just because certificate authentication finished.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(connect().await.is_err(), "pending AGP must reserve quota");
        let first = client_handshake(
            tls,
            SessionConfig {
                node_id: "laptop-1".into(),
                ..Default::default()
            },
            Budget::root(8 * 1024 * 1024),
            Arc::new(aegis_contracts::observability::NoopObservability),
        )
        .await
        .expect("AGP");
        tokio::time::timeout(Duration::from_secs(2), async {
            while gw.ctx.sessions.count() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("registered");
        let second = connect().await;
        if sessions == 1 {
            assert!(second.is_err(), "live session consumes the only slot");
        } else {
            assert!(second.is_ok(), "completed AGP releases the pending permit");
        }
        drop(second);
        drop(first);
        tokio::time::timeout(Duration::from_secs(3), async {
            while gw.ctx.sessions.count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("slots released");
        // The session leaves the registry a moment before its connection task
        // ends and gives its slots back, so a replacement may need a retry.
        let replacement = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match connect().await {
                    Ok(session) => break session,
                    Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
                }
            }
        })
        .await
        .expect("reusable quota after close");
        drop(replacement);
        gw.shutdown(Duration::from_millis(100)).await;
    }
}

async fn read_request_head(s: &mut TcpStream) {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut b = [0u8];
        s.read_exact(&mut b).await.expect("head");
        head.push(b[0]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_forward_relays_100_continue_before_the_body() {
    let Some(env) = setup().await else { return };
    let origin = TcpListener::bind(SocketAddr::new(env.echo.ip(), 0))
        .await
        .expect("origin");
    let target = origin.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.expect("accept");
        read_request_head(&mut s).await;
        s.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .expect("100");
        let mut b = [0u8];
        s.read_exact(&mut b).await.expect("body");
        s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("200");
    });
    let mut client = TcpStream::connect(env.client.bound_addr("http").expect("http"))
        .await
        .expect("proxy");
    client
        .write_all(format!("POST http://{target}/ HTTP/1.1\r\nHost: {target}\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n").as_bytes())
        .await
        .expect("request");
    let mut interim = [0u8; 25];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut interim))
        .await
        .expect("100 Continue forwarded before the body")
        .expect("read");
    assert!(interim[..n].starts_with(b"HTTP/1.1 100"));
    client.write_all(b"x").await.expect("body");
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("bounded")
        .expect("response");
    assert!(String::from_utf8_lossy(&rest).contains("200 OK"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_forward_answers_a_client_that_half_closes() {
    let Some(env) = setup().await else { return };
    let origin = TcpListener::bind(SocketAddr::new(env.echo.ip(), 0))
        .await
        .expect("origin");
    let target = origin.local_addr().expect("addr");
    tokio::spawn(async move {
        let (mut s, _) = origin.accept().await.expect("accept");
        read_request_head(&mut s).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = s
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await;
    });
    let mut client = TcpStream::connect(env.client.bound_addr("http").expect("http"))
        .await
        .expect("proxy");
    client
        .write_all(format!("GET http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .expect("request");
    client.shutdown().await.expect("half-close");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .expect("bounded")
        .expect("response");
    assert!(response.ends_with(b"OK"), "{response:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_shutdown_closes_existing_tunnel_streams() {
    let Some(env) = setup().await else { return };
    let (mut s, reply) = socks_connect(
        env.client.bound_addr("socks").expect("socks"),
        &env.echo.to_string(),
        None,
    )
    .await;
    assert_eq!(reply, 0);
    s.write_all(b"before").await.expect("write");
    let mut b = [0u8; 6];
    s.read_exact(&mut b).await.expect("echo");
    env.client.shutdown(Duration::ZERO).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let forwarded = async {
        s.write_all(b"after!").await?;
        s.read_exact(&mut b).await?;
        Ok::<_, std::io::Error>(b)
    };
    let result = tokio::time::timeout(Duration::from_secs(2), forwarded).await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "client still forwards through its tunnel after shutdown: {result:?}"
    );
}

/// A UDP echo on `ip`: every datagram goes back to its sender.
async fn udp_echo_server(ip: IpAddr) -> SocketAddr {
    let s = tokio::net::UdpSocket::bind(SocketAddr::new(ip, 0))
        .await
        .expect("bind udp echo");
    let addr = s.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// SOCKS5 UDP ASSOCIATE: the control connection and the relay address.
async fn socks_udp_associate(proxy: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut s = TcpStream::connect(proxy).await.expect("connect proxy");
    s.write_all(&[5, 1, 0]).await.expect("greet");
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.expect("method");
    assert_eq!(r, [5, 0]);
    s.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.expect("reply");
    assert_eq!(&reply[..4], &[5, 0, 0, 1], "associate refused");
    let ip = std::net::Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let port = u16::from_be_bytes([reply[8], reply[9]]);
    (s, SocketAddr::new(IpAddr::V4(ip), port))
}

async fn udp_exchange(
    socket: &tokio::net::UdpSocket,
    relay: SocketAddr,
    dest: &aegis_contracts::Destination,
    data: &[u8],
) -> Option<Vec<u8>> {
    socket
        .send_to(&aegis_inbound_socks::encode_udp(dest, data), relay)
        .await
        .expect("send");
    let mut buf = vec![0u8; 65536];
    let n = tokio::time::timeout(Duration::from_millis(1500), socket.recv(&mut buf))
        .await
        .ok()?
        .expect("recv");
    let (from, payload) = aegis_inbound_socks::parse_udp(&buf[..n]).expect("socks udp header");
    assert_eq!(&from, dest, "reply names its source");
    Some(payload.to_vec())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tc_n07_udp_through_socks_associate_and_the_tunnel() {
    let Some(env) = setup().await else { return };
    let echo = udp_echo_server(env.echo.ip()).await;
    let (control, relay) =
        socks_udp_associate(env.client.bound_addr("socks").expect("socks")).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let dest = aegis_contracts::Destination::parse_authority(&echo.to_string()).expect("dest");
    for size in [1usize, 512, 1400, 8000] {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
        let back = udp_exchange(&socket, relay, &dest, &data)
            .await
            .expect("echoed through the gateway");
        assert_eq!(back, data, "{size}-byte datagram");
    }
    // Gateway policy still applies: loopback isn't an allowed egress.
    let denied_echo = udp_echo_server(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).await;
    let denied =
        aegis_contracts::Destination::parse_authority(&denied_echo.to_string()).expect("dest");
    assert!(
        udp_exchange(&socket, relay, &denied, b"x").await.is_none(),
        "denied destination answered"
    );
    // Datagrams from another host port are ignored.
    let stranger = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    assert!(udp_exchange(&stranger, relay, &dest, b"x").await.is_none());
    // Closing the control connection ends the association and its flows.
    drop(control);
    tokio::time::timeout(Duration::from_secs(5), async {
        while env.gw.ctx.gauges().streams_active > 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("gateway flows closed");
    assert!(udp_exchange(&socket, relay, &dest, b"x").await.is_none());
}

/// A client whose routes go direct (no gateway), listening on `socks_bind`
/// and `http_bind`.
fn direct_client_toml(dir: &Path, secrets: &Path, socks_bind: &str, http_bind: &str) -> String {
    format!(
        r#"
schema_version = "0.1"
node_id = "laptop-1"
role = "client"
[management]
enabled = false
config_store = "{store}"
[secrets]
dir = "{secrets}"
[identity]
peer_auth = "mutual_tls_1_3"
client_identity = "secret://identity/client-cert"
client_private_key = "secret://identity/client-key"
trusted_server_ca = "secret://identity/server-ca"
[[inbounds]]
id = "socks"
kind = "socks5"
bind = "{socks_bind}"
[[inbounds]]
id = "http"
kind = "http_connect"
bind = "{http_bind}"
[[outbounds]]
id = "direct"
kind = "direct_tcp"
restricted_address_policy = "allow-private"
[routing]
default_outbound = "direct"
default_action = "direct"
[dns]
mode = "local_explicit"
ipv6_policy = "follow-routing-policy"
resolver = "system"
"#,
        store = dir.join("direct-client.db").display(),
        secrets = secrets.display(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_stops_direct_relays_before_returning() {
    let Some(ip) = lan_ip() else {
        eprintln!("BLOCKED: no non-loopback interface");
        return;
    };
    let echo = echo_server(ip).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    provision(&secrets);
    let cfg = parse_toml(&direct_client_toml(
        dir.path(),
        &secrets,
        "127.0.0.1:0",
        "127.0.0.1:0",
    ))
    .expect("cfg");
    let client = start(StartOptions {
        config: cfg,
        store_path: dir.path().join("direct-client.db"),
        failpoints: None,
    })
    .await
    .expect("start");
    let (mut s, reply) = socks_connect(
        client.bound_addr("socks").expect("socks"),
        &echo.to_string(),
        None,
    )
    .await;
    assert_eq!(reply, 0);
    s.write_all(b"before").await.expect("write");
    let mut b = [0u8; 6];
    s.read_exact(&mut b).await.expect("echo");
    client.shutdown(Duration::ZERO).await;
    // No waiting: once shutdown returned, the relay is gone.
    let forwarded = async {
        s.write_all(b"after!").await?;
        s.read_exact(&mut b).await?;
        Ok::<_, std::io::Error>(b)
    };
    let result = tokio::time::timeout(Duration::from_secs(2), forwarded).await;
    assert!(
        !matches!(result, Ok(Ok(_))),
        "direct relay still forwards after shutdown: {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_start_leaves_no_listener_behind() {
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    provision(&secrets);
    let free = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
    let free_port = free.local_addr().expect("addr").port();
    drop(free);
    let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy");
    let taken_port = taken.local_addr().expect("addr").port();
    let cfg = parse_toml(&direct_client_toml(
        dir.path(),
        &secrets,
        &format!("127.0.0.1:{free_port}"),
        &format!("127.0.0.1:{taken_port}"),
    ))
    .expect("cfg");
    let err = start(StartOptions {
        config: cfg,
        store_path: dir.path().join("direct-client.db"),
        failpoints: None,
    })
    .await
    .err()
    .expect("second bind fails");
    assert_eq!(err.code(), "E_BIND");
    assert!(
        TcpStream::connect(("127.0.0.1", free_port)).await.is_err(),
        "the first inbound is still listening"
    );
    drop(taken);
}

/// A gateway with a QUIC listener next to its WebSocket one, and a client
/// told about it (or about `quic_override`, e.g. a port nobody answers).
async fn setup_quic(quic_override: Option<String>) -> Option<Env> {
    let Some(ip) = lan_ip() else {
        eprintln!("BLOCKED: no non-loopback interface for an egress-permitted echo target");
        return None;
    };
    let echo = echo_server(ip).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    let pki = provision(&secrets);
    let gw_toml = format!(
        "{}\n[[inbounds]]\nid = \"ingress-quic\"\nkind = \"quic\"\nbind = \"127.0.0.1:0\"\n",
        gateway_toml(dir.path(), &format!("{ip}/32"))
    );
    let gw = start(StartOptions {
        config: parse_toml(&gw_toml).expect("gw cfg"),
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gateway start");
    let quic = quic_override.unwrap_or_else(|| {
        gw.bound_addr("ingress-quic")
            .expect("quic addr")
            .to_string()
    });
    let client_toml = client_toml(
        dir.path(),
        &secrets,
        gw.bound_addr("ingress-ws").expect("ws addr"),
    )
    .replace(
        "server_name = \"gateway.aegis.internal\"",
        &format!("server_name = \"gateway.aegis.internal\"\nquic = \"{quic}\""),
    );
    let client = start(StartOptions {
        config: parse_toml(&client_toml).expect("client cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client start");
    Some(Env {
        _dir: dir,
        gw,
        client,
        echo,
        pki,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_and_udp_run_over_direct_quic() {
    let Some(env) = setup_quic(None).await else {
        return;
    };
    let proxy = env.client.bound_addr("socks").expect("socks");
    let (s, reply) = socks_connect(proxy, &env.echo.to_string(), None).await;
    assert_eq!(reply, 0);
    echo_roundtrip(s, 256 * 1024).await;
    assert_eq!(env.client.ctx.tunnel_transport(), Some("quic"));
    let udp_echo = udp_echo_server(env.echo.ip()).await;
    let (_control, relay) = socks_udp_associate(proxy).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let dest = aegis_contracts::Destination::parse_authority(&udp_echo.to_string()).expect("dest");
    // Small datagrams ride QUIC datagrams; large ones the session stream.
    for size in [1usize, 500, 1100, 8000] {
        let data: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
        let back = udp_exchange(&socket, relay, &dest, &data)
            .await
            .expect("echoed over QUIC");
        assert_eq!(back, data, "{size}-byte datagram");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_quic_port_falls_back_to_websocket() {
    // A UDP port nobody serves QUIC on.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = silent.local_addr().expect("addr").to_string();
    let Some(env) = setup_quic(Some(addr)).await else {
        return;
    };
    let proxy = env.client.bound_addr("socks").expect("socks");
    let started = std::time::Instant::now();
    let (s, reply) = socks_connect(proxy, &env.echo.to_string(), None).await;
    assert_eq!(reply, 0);
    echo_roundtrip(s, 4096).await;
    assert_eq!(env.client.ctx.tunnel_transport(), Some("websocket"));
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "fallback took {:?}",
        started.elapsed()
    );
    drop(silent);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_waiting_for_its_flows_stays_within_the_buffer_budget() {
    // A gateway that accepts connections and never answers: every flow
    // waits to open while the app keeps sending.
    let stalled = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let gw = stalled.local_addr().expect("addr");
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = stalled.accept().await {
            held.push(s);
        }
    });
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    let _pki = provision(&secrets);
    let limit: u64 = 4 * 1024 * 1024;
    let toml = format!(
        "{}\n[core]\nprocess_buffer_budget_bytes = {limit}\npeer_buffer_budget_bytes = {limit}\nsession_window_bytes = 2097152\n",
        client_toml(dir.path(), &secrets, gw)
    );
    let client = start(StartOptions {
        config: parse_toml(&toml).expect("client cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client start");
    let (_control, relay) = socks_udp_associate(client.bound_addr("socks").expect("socks")).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let payload = vec![5u8; 60_000];
    let mut peak = 0;
    for round in 0..32u16 {
        for d in 0..16u8 {
            let dest = aegis_contracts::Destination::parse_authority(&format!(
                "93.184.216.{}:{}",
                d + 1,
                4000 + round % 2
            ))
            .expect("dest");
            let _ = socket
                .send_to(&aegis_inbound_socks::encode_udp(&dest, &payload), relay)
                .await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        peak = peak.max(client.ctx.budget.used());
    }
    // Queued datagrams are charged against the budget, and capped by it.
    assert!(peak > 0, "waiting datagrams are accounted for");
    assert!(peak <= limit, "used {peak} of {limit}");
    client.shutdown(Duration::from_secs(1)).await;
}

/// A server that sends `size` bytes to every connection, then closes.
async fn download_server(ip: IpAddr, size: usize) -> SocketAddr {
    let l = TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .expect("bind download");
    let addr = l.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let chunk = vec![7u8; 64 * 1024];
                let mut left = size;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if s.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                }
                let _ = s.shutdown().await;
            });
        }
    });
    addr
}

/// `count` connections that start downloading and stop reading (a browser's
/// slow or abandoned page loads), then a fresh connection that must still
/// work within `deadline`. `core` overrides the client's buffer settings.
async fn stalled_downloads_leave_room(
    core: &str,
    count: usize,
    deadline: Duration,
) -> Result<(), String> {
    let Some(ip) = lan_ip() else {
        return Ok(());
    };
    let echo = echo_server(ip).await;
    let download = download_server(ip, 4 * 1024 * 1024).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    let _pki = provision(&secrets);
    let gw_cfg = parse_toml(&gateway_toml(dir.path(), &format!("{ip}/32"))).expect("gw cfg");
    let gw = start(StartOptions {
        config: gw_cfg,
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gateway start");
    let gw_addr = gw.bound_addr("ingress-ws").expect("ws addr");
    let toml = format!(
        "{}\n[core]\n{core}\n",
        client_toml(dir.path(), &secrets, gw_addr)
    );
    let client = start(StartOptions {
        config: parse_toml(&toml).expect("client cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client start");
    let proxy = client.bound_addr("socks").expect("socks");
    let mut held = Vec::new();
    for _ in 0..count {
        let (mut s, code) = socks_connect(proxy, &download.to_string(), None).await;
        if code != 0 {
            return Err(format!("download {} refused: {code}", held.len()));
        }
        // Read a little, then stop reading.
        let mut first = [0u8; 4096];
        let _ = s.read(&mut first).await;
        held.push(s);
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let used = client.ctx.budget.used();
    let probe = async {
        let (s, code) = socks_connect(proxy, &echo.to_string(), None).await;
        if code != 0 {
            return Err(format!("probe refused: {code}"));
        }
        echo_roundtrip(s, 1024).await;
        Ok(())
    };
    let result = match tokio::time::timeout(deadline, probe).await {
        Ok(r) => r,
        Err(_) => Err(format!("a new connection stalled (budget used {used})")),
    };
    drop(held);
    client.shutdown(Duration::from_secs(1)).await;
    gw.shutdown(Duration::from_secs(1)).await;
    result
}

/// As the iPhone build runs (crates/aegis-mobile, within_memory_limit).
const IPHONE_CORE: &str = "process_buffer_budget_bytes = 25165824\npeer_buffer_budget_bytes = 20971520\nstream_buffer_budget_bytes = 262144\nsession_window_bytes = 8388608";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_downloads_leave_the_tunnel_usable() {
    // With a 4 MB window the iPhone refused every new connection after 21
    // stalled ones (1.1.6): its health check failed and pages stopped.
    let default = stalled_downloads_leave_room("", 24, Duration::from_secs(10)).await;
    let iphone = stalled_downloads_leave_room(IPHONE_CORE, 24, Duration::from_secs(10)).await;
    assert!(
        default.is_ok() && iphone.is_ok(),
        "default: {default:?}; iphone: {iphone:?}"
    );
}

/// Many short-lived downloads, each closed after a little reading (a
/// browser's churn), then a fresh connection that must still work.
async fn churned_downloads_leave_room(core: &str, rounds: usize) -> Result<(), String> {
    let Some(ip) = lan_ip() else {
        return Ok(());
    };
    let echo = echo_server(ip).await;
    let download = download_server(ip, 4 * 1024 * 1024).await;
    let dir = tempfile::tempdir().expect("tmp");
    let secrets = dir.path().join("secrets");
    let _pki = provision(&secrets);
    let gw_cfg = parse_toml(&gateway_toml(dir.path(), &format!("{ip}/32"))).expect("gw cfg");
    let gw = start(StartOptions {
        config: gw_cfg,
        store_path: dir.path().join("gw.db"),
        failpoints: None,
    })
    .await
    .expect("gateway start");
    let gw_addr = gw.bound_addr("ingress-ws").expect("ws addr");
    let toml = format!(
        "{}\n[core]\n{core}\n",
        client_toml(dir.path(), &secrets, gw_addr)
    );
    let client = start(StartOptions {
        config: parse_toml(&toml).expect("client cfg"),
        store_path: dir.path().join("client.db"),
        failpoints: None,
    })
    .await
    .expect("client start");
    let proxy = client.bound_addr("socks").expect("socks");
    let mut result = Ok(());
    'rounds: for round in 0..rounds {
        let mut batch = Vec::new();
        for _ in 0..8 {
            let (s, code) = socks_connect(proxy, &download.to_string(), None).await;
            if code != 0 {
                result = Err(format!("round {round}: download refused ({code})"));
                break 'rounds;
            }
            batch.push(s);
        }
        for s in &mut batch {
            let mut buf = vec![0u8; 256 * 1024];
            let _ = tokio::time::timeout(Duration::from_millis(200), s.read(&mut buf)).await;
        }
        drop(batch);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    if result.is_ok() {
        let probe = async {
            let (s, code) = socks_connect(proxy, &echo.to_string(), None).await;
            if code != 0 {
                return Err(format!("probe refused: {code}"));
            }
            echo_roundtrip(s, 1024).await;
            Ok(())
        };
        result = match tokio::time::timeout(Duration::from_secs(10), probe).await {
            Ok(r) => r,
            Err(_) => Err("a new connection stalled".into()),
        };
    }
    client.shutdown(Duration::from_secs(1)).await;
    gw.shutdown(Duration::from_secs(1)).await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_downloads_give_their_windows_back() {
    let iphone = churned_downloads_leave_room(IPHONE_CORE, 40).await;
    assert!(iphone.is_ok(), "iphone: {iphone:?}");
}
