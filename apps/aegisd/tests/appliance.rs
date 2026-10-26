//! Appliance end-to-end (ADR-0007): initialize an empty data directory, sign
//! in to the HTTPS console with the generated password, complete the forced
//! password change, invite a device, enroll it through the TLS edge with the
//! invitation's pins, open a tunnel session, renew with the same key and
//! revoke it. Runs fully in-process on loopback.
#![cfg(unix)]

use aegisd::appliance::{self, InitOptions};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port")
}

struct Console {
    http: reqwest::Client,
    base: String,
    cookie: Option<String>,
    csrf: Option<String>,
}

impl Console {
    fn new(addr: SocketAddr, web_ca: &str) -> Self {
        let http = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(web_ca.as_bytes()).expect("ca"))
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .expect("client");
        Console {
            http,
            base: format!("https://127.0.0.1:{}", addr.port()),
            cookie: None,
            csrf: None,
        }
    }

    async fn call(
        &mut self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut req = self
            .http
            .request(method.clone(), format!("{}/api/v1{path}", self.base));
        if let Some(c) = &self.cookie {
            req = req.header("cookie", format!("aegis_session={c}"));
        }
        if method != reqwest::Method::GET {
            if let Some(t) = &self.csrf {
                req = req.header("x-csrf-token", t);
            }
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req.send().await.expect("console reachable over TLS");
        let status = resp.status().as_u16();
        if let Some(set) = resp
            .headers()
            .get("set-cookie")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(v) = set
                .split(';')
                .next()
                .and_then(|kv| kv.strip_prefix("aegis_session="))
            {
                self.cookie = Some(v.to_owned());
            }
        }
        let value: Value = resp.json().await.unwrap_or(Value::Null);
        if let Some(t) = value["csrf_token"].as_str() {
            self.csrf = Some(t.to_owned());
        }
        (status, value)
    }
}

async fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> u8 {
    let mut s = TcpStream::connect(proxy).await.expect("socks");
    s.write_all(&[5, 1, 0]).await.expect("greet");
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.expect("method");
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.expect("connect");
    let mut head = [0u8; 4];
    match tokio::time::timeout(Duration::from_secs(15), s.read_exact(&mut head)).await {
        Ok(Ok(_)) => head[1],
        _ => 0xEE,
    }
}

async fn start_client(dir: &Path) -> aegis_node::NodeRuntime {
    start_client_via(dir, None).await
}

async fn start_client_via(
    dir: &Path,
    trial: Option<&aegis_join::Endpoint>,
) -> aegis_node::NodeRuntime {
    let device = aegis_join::DeviceDir::new(dir);
    let _ = std::fs::remove_file(device.store());
    let cfg =
        aegis_join::client_config_for(&device, aegis_join::Ports { socks: 0, http: 0 }, trial)
            .expect("client config");
    aegis_node::start(aegis_node::StartOptions {
        config: cfg,
        store_path: device.store(),
        failpoints: None,
    })
    .await
    .expect("client start")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn appliance_console_invite_enroll_tunnel_renew_revoke() {
    tokio::time::timeout(Duration::from_secs(90), async {
        let tmp = tempfile::tempdir().expect("tmp");
        let data = tmp.path().join("data");
        let (console_port, edge_port) = (free_port(), free_port());
        let opts = InitOptions {
            public_addresses: vec!["127.0.0.1".into()],
            public_port: Some(edge_port),
            console_loopback: true,
            // Tunnel-only exposure: the device edge listens on loopback.
            edge_loopback: true,
            console_port: Some(console_port),
            edge_port: Some(edge_port),
            tunnel_port: Some(0),
        };
        let path = appliance::init(&data, &opts).expect("init");
        let cfg = aegisd::parse_config(&std::fs::read_to_string(path).expect("cfg")).expect("parse");
        let store = std::path::PathBuf::from(&cfg.management.config_store);
        let running = aegisd::launch(cfg, store, Some(data.clone())).await.expect("launch");
        let password = std::fs::read_to_string(data.join(appliance::INITIAL_PASSWORD_FILE))
            .expect("initial password")
            .trim()
            .to_owned();
        let web_ca = std::fs::read_to_string(data.join("secrets/web-ca.pem")).expect("web ca");
        let mut c = Console::new(running.console.expect("console"), &web_ca);

        // Plain HTTP on the console port is redirected, never served.
        let mut plain = TcpStream::connect(("127.0.0.1", console_port)).await.expect("plain");
        plain
            .write_all(format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{console_port}\r\n\r\n").as_bytes())
            .await
            .expect("write");
        let mut text = String::new();
        let _ = plain.read_to_string(&mut text).await;
        assert!(text.starts_with("HTTP/1.1 308"), "{text}");
        assert!(text.contains(&format!("Location: https://127.0.0.1:{console_port}/")));

        let (s, _) = c.call(reqwest::Method::GET, "/auth/me", None).await;
        assert_eq!(s, 401);
        let (s, v) = c
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": "wrong-password-x"})))
            .await;
        assert_eq!(s, 401, "{v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": password})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["password_change_required"], true);
        let (s, _) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(s, 403, "restricted session before the forced change");
        let restricted = c.cookie.clone();
        let (s, v) = c
            .call(reqwest::Method::POST, "/auth/password", Some(json!({"current_password": password, "new_password": "short"})))
            .await;
        assert_eq!(s, 400, "{v}");
        let (s, v) = c
            .call(
                reqwest::Method::POST,
                "/auth/password",
                Some(json!({"current_password": password, "new_password": "a much better passphrase"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["password_change_required"], false);
        assert!(
            !data.join(appliance::INITIAL_PASSWORD_FILE).exists(),
            "one-time password file removed"
        );
        assert_ne!(c.cookie, restricted, "session rotated");
        let (s, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["checklist"]["owner_password_changed"], true);

        // Server address -> invitation code.
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/connection", Some(json!({"public_host": "127.0.0.1", "public_port": edge_port})))
            .await;
        assert_eq!(s, 200, "{v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "laptop"})))
            .await;
        assert_eq!(s, 201, "{v}");
        let code = v["code"].as_str().expect("code").to_owned();
        let invite = aegis_join::parse_invite(&code).expect("invite parses");
        assert_eq!(invite.outer_server_name.as_deref(), Some("edge.aegis.internal"));

        // Enroll through the TLS edge (not the console).
        let dev_dir = tmp.path().join("device");
        let device_dir = aegis_join::DeviceDir::new(&dev_dir);
        aegis_join::enroll(&invite, &device_dir).await.expect("enroll");
        let again = aegis_join::enroll(&invite, &aegis_join::DeviceDir::new(tmp.path().join("replay"))).await;
        assert!(
            matches!(again, Err(aegis_join::JoinError::Rejected { status: 401, .. })),
            "one-use invitation: {again:?}"
        );
        let (s, v) = c.call(reqwest::Method::GET, "/devices", None).await;
        assert_eq!(s, 200);
        assert_eq!(v["items"][0]["name"], "laptop");

        // Tunnel session: a loopback destination is refused *by the gateway
        // policy* (0x02), which proves inner mTLS + registry admission.
        let client = start_client(&dev_dir).await;
        let socks = client.bound_addr("socks").expect("socks");
        assert_eq!(socks_connect(socks, "localhost", 9).await, 2);
        client.shutdown(Duration::from_secs(1)).await;

        // Same-key renewal through the edge.
        let before = device_dir.certificate_expires_at().expect("expiry");
        assert!(aegis_join::renew_if_due(&device_dir, true).await.expect("renew"));
        assert!(device_dir.certificate_expires_at().expect("expiry") >= before);
        let client = start_client(&dev_dir).await;
        let socks = client.bound_addr("socks").expect("socks");
        assert_eq!(socks_connect(socks, "localhost", 9).await, 2, "renewed identity admitted");

        // On-demand diagnostics: a device report is refused while the
        // gateway's diagnostics are off, accepted (signed with the device
        // key, through the edge) once an administrator starts a recording,
        // attributed by the registry and explained by the analysis.
        let sink = aegis_telemetry::DiagnosticSink::new();
        sink.start(Duration::from_secs(60)).expect("start");
        sink.note(
            aegis_telemetry::Severity::Warn,
            "client.connect.failed",
            &[("stage", "tls"), ("error", "invalid peer certificate: UnknownIssuer")],
        );
        let mut report = aegis_telemetry::Report {
            role: aegis_telemetry::report::Role::Client,
            name: "claims-another-name".into(),
            version: "test".into(),
            recording: sink.recording().expect("recording"),
        };
        let gz = report.to_gzip(900 * 1024);
        let refused = aegis_join::upload_diagnostics(&device_dir, &gz).await;
        assert!(
            matches!(refused, Err(aegis_join::JoinError::Rejected { status: 409, .. })),
            "upload while off must be refused: {refused:?}"
        );
        let (s, v) = c
            .call(reqwest::Method::POST, "/diagnostics/start", Some(json!({"minutes": 61})))
            .await;
        assert_eq!(s, 400, "{v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/diagnostics/start", Some(json!({"minutes": 5})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["gateway"]["state"], "recording");
        aegis_join::upload_diagnostics(&device_dir, &gz)
            .await
            .expect("signed upload accepted");
        let (_, v) = c.call(reqwest::Method::GET, "/diagnostics", None).await;
        assert_eq!(v["devices"][0]["name"], "laptop", "the registry names the sender");
        let (s, v) = c
            .call(reqwest::Method::GET, "/diagnostics/analysis", None)
            .await;
        assert_eq!(s, 200, "{v}");
        let ids: Vec<&str> = v["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .filter_map(|f| f["id"].as_str())
            .collect();
        assert!(ids.contains(&"device_tls_failed"), "{v}");
        let (s, v) = c.call(reqwest::Method::GET, "/diagnostics/otlp", None).await;
        assert_eq!(s, 200);
        assert_eq!(v["resourceLogs"].as_array().map(Vec::len), Some(2), "gateway + device");
        let (_, v) = c.call(reqwest::Method::POST, "/diagnostics/stop", None).await;
        assert_eq!(v["gateway"]["state"], "stopped");
        let (_, v) = c.call(reqwest::Method::POST, "/diagnostics/discard", None).await;
        assert_eq!(v["gateway"]["state"], "off");
        assert_eq!(v["devices"].as_array().map(Vec::len), Some(0));

        // Address change: the device learns the gateway's new endpoint on
        // connect and adopts it only after the pinned gateway answers there.
        assert_eq!(aegis_join::fetch_endpoint(&device_dir).await.expect("query"), None, "unchanged");
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/connection", Some(json!({"public_host": "localhost", "public_port": edge_port})))
            .await;
        assert_eq!(s, 200, "{v}");
        let moved = aegis_join::fetch_endpoint(&device_dir)
            .await
            .expect("query")
            .expect("endpoint changed");
        assert!(moved.url.starts_with("wss://localhost:"), "{moved:?}");
        // A bogus endpoint (nothing listening) fails the end-to-end check.
        let mut bogus = moved.clone();
        bogus.url = format!("wss://127.0.0.1:{}/agp", free_port());
        let trial = start_client_via(&dev_dir, Some(&bogus)).await;
        assert!(!aegis_join::verify_tunnel(trial.bound_addr("socks").expect("socks")).await);
        trial.shutdown(Duration::from_secs(1)).await;
        // The real one passes and is adopted.
        let trial = start_client_via(&dev_dir, Some(&moved)).await;
        assert!(aegis_join::verify_tunnel(trial.bound_addr("socks").expect("socks")).await);
        trial.shutdown(Duration::from_secs(1)).await;
        let device = aegis_join::adopt_endpoint(&device_dir, &moved).expect("adopt");
        assert_eq!(device.url, moved.url);
        assert_eq!(aegis_join::fetch_endpoint(&device_dir).await.expect("query"), None, "now current");
        let mut foreign = moved.clone();
        foreign.device_ca_sha256 = "0".repeat(64);
        assert!(aegis_join::adopt_endpoint(&device_dir, &foreign).is_err(), "other gateway refused");
        client.shutdown(Duration::from_secs(1)).await;
        let client = start_client(&dev_dir).await;
        let socks = client.bound_addr("socks").expect("socks");
        assert_eq!(socks_connect(socks, "localhost", 9).await, 2, "connects via the new address");

        // Offline device root: export (password re-checked), remove with
        // proof of possession, renew the issuer with the offline key (not
        // stored), and devices keep enrolling/renewing/connecting.
        let export = |password: &str| {
            c.http
                .post(format!("{}/api/v1/system/device-ca/export-root-key", c.base))
                .header("cookie", format!("aegis_session={}", c.cookie.clone().expect("cookie")))
                .header("x-csrf-token", c.csrf.clone().expect("csrf"))
                .json(&json!({ "password": password }))
                .send()
        };
        assert_eq!(export("wrong password!").await.expect("export").status().as_u16(), 403);
        let resp = export("a much better passphrase").await.expect("export");
        assert_eq!(resp.status().as_u16(), 200);
        let root_key = resp.text().await.expect("pem");
        assert!(root_key.contains("PRIVATE KEY"));
        let (s, v) = c
            .call(reqwest::Method::POST, "/system/device-ca/remove-root-key", Some(json!({"key_pem": "not a key"})))
            .await;
        assert_eq!(s, 400, "removal needs the real key: {v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/system/device-ca/remove-root-key", Some(json!({"key_pem": root_key})))
            .await;
        assert_eq!(s, 200, "{v}");
        let (_, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(v["runtime"]["certificates"]["root_key_on_host"], false, "{v}");
        let (s, _) = c
            .call(reqwest::Method::POST, "/system/device-ca/renew-issuer", Some(json!({})))
            .await;
        assert_eq!(s, 400, "offline root: renewal needs the key file");
        let (s, v) = c
            .call(reqwest::Method::POST, "/system/device-ca/renew-issuer", Some(json!({"key_pem": root_key})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert!(v["issuer_expires_at"].is_string(), "{v}");
        let (_, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(v["runtime"]["certificates"]["root_key_on_host"], false, "key not stored by renewal");
        assert!(aegis_join::renew_if_due(&device_dir, true).await.expect("renew from the new issuer"));
        client.shutdown(Duration::from_secs(1)).await;
        let client = start_client(&dev_dir).await;
        let socks = client.bound_addr("socks").expect("socks");
        assert_eq!(socks_connect(socks, "localhost", 9).await, 2, "new issuer and gateway identity admitted");
        let (s, v) = c
            .call(reqwest::Method::POST, "/system/device-ca/restore-root-key", Some(json!({"key_pem": root_key})))
            .await;
        assert_eq!(s, 200, "{v}");
        let (_, v) = c.call(reqwest::Method::GET, "/audit?limit=20", None).await;
        let actions: Vec<&str> = v["items"].as_array().expect("audit").iter().filter_map(|a| a["action"].as_str()).collect();
        for a in ["pki.root_key_exported", "pki.root_key_removed", "pki.issuer_renewed", "pki.root_key_restored"] {
            assert!(actions.contains(&a), "audited {a}: {actions:?}");
        }

        // Revoke: new sessions/streams are refused.
        let (_, v) = c.call(reqwest::Method::GET, "/devices", None).await;
        let id = v["items"][0]["id"].as_str().expect("id").to_owned();
        let etag = v["items"][0]["etag"].as_str().expect("etag").to_owned();
        let resp = c
            .http
            .post(format!("{}/api/v1/devices/{id}/revoke", c.base))
            .header("cookie", format!("aegis_session={}", c.cookie.clone().expect("cookie")))
            .header("x-csrf-token", c.csrf.clone().expect("csrf"))
            .header("if-match", etag)
            .header("idempotency-key", "revoke-laptop-0001")
            .send()
            .await
            .expect("revoke");
        assert_eq!(resp.status().as_u16(), 202);
        let mut revoked = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if socks_connect(socks, "localhost", 9).await != 2 {
                revoked = true;
                break;
            }
        }
        assert!(revoked, "revoked device can no longer open streams");
        assert!(
            aegis_join::renew_if_due(&device_dir, true).await.is_err(),
            "revoked device cannot renew"
        );
        client.shutdown(Duration::from_secs(1)).await;
        running.shutdown().await;
    })
    .await
    .expect("bounded appliance e2e");
}

/// Start an appliance whose stored configuration carries `core` (TOML).
async fn launch_with_core(data: &Path, core: &str) -> aegisd::Running {
    let opts = InitOptions {
        public_addresses: vec!["127.0.0.1".into()],
        console_loopback: true,
        console_port: Some(free_port()),
        edge_port: Some(free_port()),
        tunnel_port: Some(0),
        ..Default::default()
    };
    let path = if data.join("config.toml").exists() {
        data.join("config.toml")
    } else {
        let p = appliance::init(data, &opts).expect("init");
        let mut text = std::fs::read_to_string(&p).expect("cfg");
        text.push_str(core);
        std::fs::write(&p, text).expect("write");
        p
    };
    let cfg = aegisd::parse_config(&std::fs::read_to_string(path).expect("cfg")).expect("parse");
    let store = std::path::PathBuf::from(&cfg.management.config_store);
    aegisd::launch(cfg, store, Some(data.to_path_buf()))
        .await
        .expect("launch")
}

fn revisions(data: &Path) -> i64 {
    let store = aegis_storage::Store::open(data.join("state.db")).expect("store");
    store
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get::<_, i64>(0))?))
        .expect("count")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn legacy_session_limits_are_upgraded_once_and_operator_values_kept() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let tmp = tempfile::tempdir().expect("tmp");
        // Pre-0.2 defaults: 31 concurrent connections per device.
        let legacy = "\n[core]\nmax_streams_per_session = 64\nstream_buffer_budget_bytes = 65536\nsession_window_bytes = 2097152\npeer_buffer_budget_bytes = 8388608\nprocess_buffer_budget_bytes = 33554432\n";
        let data = tmp.path().join("legacy");
        let running = launch_with_core(&data, legacy).await;
        let core = &running.node.ctx.startup.core;
        assert_eq!(core.max_streams_per_session, 512, "upgraded and restarted");
        assert_eq!(core.stream_buffer_budget_bytes, 256 * 1024);
        assert_eq!(core.session_window_bytes, 8 * 1024 * 1024);
        let after = revisions(&data);
        running.shutdown().await;
        let running = launch_with_core(&data, "").await;
        assert_eq!(running.node.ctx.startup.core.max_streams_per_session, 512);
        assert_eq!(revisions(&data), after, "no second upgrade");
        running.shutdown().await;

        // An operator's own limits are not touched.
        let custom = "\n[core]\nmax_streams_per_session = 64\nsession_window_bytes = 4194304\npeer_buffer_budget_bytes = 8388608\nprocess_buffer_budget_bytes = 33554432\n";
        let data = tmp.path().join("custom");
        let running = launch_with_core(&data, custom).await;
        assert_eq!(running.node.ctx.startup.core.max_streams_per_session, 64);
        assert_eq!(running.node.ctx.startup.core.session_window_bytes, 4 * 1024 * 1024);
        running.shutdown().await;
    })
    .await
    .expect("bounded");
}
