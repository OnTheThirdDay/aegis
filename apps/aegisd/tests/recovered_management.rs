#![cfg(unix)]
//! Exercise the actual daemon after a stored revision has diverged from
//! its seed file. Management must use the same recovered revision as ingress.

use aegis_contracts::Role;
use aegis_core::ActivateRequest;
use aegis_identity::pki;
use aegis_node::{start, StartOptions};
use aegis_storage as db;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_address() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("reserve port")
        .local_addr()
        .expect("local address")
}

async fn prepare(dir: &Path, seed_enabled: bool, patch: Value) -> (SocketAddr, SocketAddr) {
    let ingress = unused_address();
    let management = unused_address();
    let ca = pki::generate_ca("management-test", pki::DEFAULT_CA_VALIDITY).expect("CA");
    let (cert, key) = pki::issue_direct(
        &ca,
        "test-gateway",
        Role::Gateway,
        &["gateway.test".into()],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .expect("gateway certificate");
    for (name, value) in [
        ("ca.pem", ca.cert_pem),
        ("cert.pem", cert),
        ("key.pem", key),
    ] {
        std::fs::write(dir.join(name), value).expect("identity fixture");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600))
                .expect("mode");
        }
    }
    let text = format!(
        r#"
schema_version = "0.1"
node_id = "test-gateway"
role = "gateway"
[management]
enabled = {seed_enabled}
bind = "{management}"
config_store = "{dir}/state.db"
ipc_socket = "{dir}/seed.sock"
allowed_hosts = ["seed.example"]
[secrets]
dir = "{dir}"
[identity]
peer_auth = "mutual_tls_1_3"
server_identity = "secret://cert.pem"
server_private_key = "secret://key.pem"
trusted_client_ca = "secret://ca.pem"
[[inbounds]]
id = "ws"
kind = "websocket"
bind = "{ingress}"
[[outbounds]]
id = "egress"
kind = "direct_tcp"
[routing]
default_action = "deny"
default_outbound = "egress"
[dns]
mode = "remote_required"
resolver = "system"
ipv6_policy = "follow-routing-policy"
"#,
        dir = dir.display()
    );
    std::fs::write(dir.join("config.toml"), &text).expect("seed config");
    let node = start(StartOptions {
        config: aegis_config::parse_toml(&text).expect("config"),
        store_path: dir.join("state.db"),
        failpoints: None,
    })
    .await
    .expect("initial node");
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
                idempotency_key: "management-restart-test".into(),
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
    node.shutdown(Duration::from_millis(100)).await;
    (ingress, management)
}

fn daemon(dir: &Path) -> Daemon {
    Daemon(
        Command::new(env!("CARGO_BIN_EXE_aegisd"))
            .arg("--config")
            .arg(dir.join("config.toml"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn daemon"),
    )
}

async fn wait_for_listener(child: &mut Daemon, addr: SocketAddr) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(
                child.0.try_wait().expect("child status").is_none(),
                "daemon exited"
            );
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("listener ready");
}

#[tokio::test]
async fn disabled_management_stays_disabled_after_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (ingress, management) =
        prepare(dir.path(), true, json!({"management": {"enabled": false}})).await;
    let mut child = daemon(dir.path());
    wait_for_listener(&mut child, ingress).await;
    // Give the daemon a scheduling turn after data ingress binds, then
    // require that management remains absent throughout the interval.
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            TcpStream::connect(management).await.is_err(),
            "seed HTTP listener revived"
        );
        assert!(
            !dir.path().join("seed.sock").exists(),
            "seed IPC listener revived"
        );
    }
}

async fn http_status(addr: SocketAddr, host: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.expect("HTTP connection");
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .expect("request");
    let mut response = String::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_string(&mut response))
        .await
        .expect("response deadline")
        .expect("response");
    response.lines().next().expect("status line").to_owned()
}

#[tokio::test]
async fn recovered_management_uses_active_bind_hosts_and_ipc_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let active_bind = unused_address();
    let active_socket = dir.path().join("active.sock");
    let (ingress, seed_bind) = prepare(
        dir.path(),
        false,
        json!({"management": {
            "enabled": true, "bind": active_bind.to_string(),
            "allowed_hosts": ["active.example"], "ipc_socket": active_socket,
        }}),
    )
    .await;
    let mut child = daemon(dir.path());
    wait_for_listener(&mut child, ingress).await;
    wait_for_listener(&mut child, active_bind).await;
    assert!(TcpStream::connect(seed_bind).await.is_err());
    assert!(http_status(active_bind, "active.example")
        .await
        .starts_with("HTTP/1.1 200"));
    let rejected = http_status(active_bind, "seed.example").await;
    assert!(rejected.starts_with("HTTP/1.1 400"), "{rejected}");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !active_socket.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("active IPC ready");
    assert!(!dir.path().join("seed.sock").exists());
}
