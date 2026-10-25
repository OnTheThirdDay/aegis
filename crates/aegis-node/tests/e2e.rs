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
    std::fs::write(p, content).expect("write");
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
