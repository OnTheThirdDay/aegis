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

/// These tests start gateways on ports picked by [`free_port`]: run in
/// parallel, two of them could pick the same port between its release and
/// the gateway binding it. One gateway test at a time.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;
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
        // Administrators see whose device it is.
        let (s, v) = c.call(reqwest::Method::GET, "/devices?scope=all", None).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["items"][0]["owner"]["username"], "admin", "{v}");

        // The iPhone app (ADR-0019): not set up, so the portal offers it to
        // nobody; a registration profile's link still records an iPhone
        // for approval, once.
        let (s, v) = c.call(reqwest::Method::GET, "/ios", None).await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["enabled"], false, "{v}");
        let session = format!("aegis_session={}", c.cookie.clone().expect("session"));
        let profile = c
            .http
            .get(format!("{}/api/v1/ios/register.mobileconfig", c.base))
            .header("cookie", &session)
            .send()
            .await
            .expect("profile");
        assert_eq!(profile.status(), 200);
        assert_eq!(profile.headers()["content-type"], "application/x-apple-aspen-config");
        let text = profile.text().await.expect("profile text");
        assert!(text.contains("<string>Profile Service</string>"));
        let callback = text
            .split("<string>")
            .find(|s| s.contains("/api/v1/ios/udid/"))
            .and_then(|s| s.split("</string>").next())
            .expect("callback link");
        let token = callback.rsplit('/').next().expect("token").to_owned();
        // What iOS posts back: a plist inside a signature.
        let mut posted = b"\x30\x80signed".to_vec();
        posted.extend_from_slice(
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>DEVICE_NAME</key><string>Test iPhone</string><key>PRODUCT</key><string>iPhone15,2</string><key>UDID</key><string>00008030-001A35E40C3A802E</string><key>VERSION</key><string>22A3354</string></dict></plist>"#,
        );
        let ios = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(web_ca.as_bytes()).expect("ca"))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let back = |r: reqwest::Response| {
            assert_eq!(r.status(), 301);
            r.headers()["location"].to_str().expect("location").to_owned()
        };
        let first = ios
            .post(format!("{}/api/v1/ios/udid/{token}", c.base))
            .body(posted.clone())
            .send()
            .await
            .expect("callback");
        assert!(back(first).ends_with("#ios-registered"));
        let again = ios
            .post(format!("{}/api/v1/ios/udid/{token}", c.base))
            .body(posted)
            .send()
            .await
            .expect("callback");
        assert!(back(again).ends_with("#ios-expired"), "a link registers once");
        let (s, v) = c.call(reqwest::Method::GET, "/integrations", None).await;
        assert_eq!(s, 200, "{v}");
        let iphone = v["integrations"]
            .as_array()
            .and_then(|l| l.iter().find(|i| i["id"] == "ios"))
            .expect("iPhone app integration")
            .clone();
        assert_eq!(iphone["state"], "off");
        let request = &iphone["requests"][0];
        assert_eq!(request["udid"], "00008030-001A35E40C3A802E");
        assert_eq!(request["name"], "Test iPhone");
        assert_eq!(request["username"], "admin");
        assert_eq!(request["state"], "pending");
        // Approving needs GitHub settings; removing works.
        let id = request["id"].clone();
        let (s, _) = c
            .call(reqwest::Method::POST, "/integrations/ios/approve", Some(json!({"id": id})))
            .await;
        assert_eq!(s, 409, "not set up: nothing is sent");
        let (s, v) = c
            .call(reqwest::Method::POST, "/integrations/ios/reject", Some(json!({"id": id})))
            .await;
        assert_eq!(s, 200, "{v}");
        let (_, v) = c.call(reqwest::Method::GET, "/ios", None).await;
        assert_eq!(v["requests"], json!([]), "{v}");
        // Reaching GitHub through another gateway: joining it with one of
        // its invitations (here this gateway's own), then stopping again.
        let (s, v) = c
            .call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "gw-upstream", "expires_in_hours": 1})))
            .await;
        assert_eq!(s, 201, "{v}");
        let code = v["code"].as_str().expect("code").to_owned();
        let (s, v) = c
            .call(reqwest::Method::POST, "/integrations/ios/configure", Some(json!({"via": code})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["status"]["via"]["name"], "gw-upstream", "{v}");
        assert!(v["status"]["via"]["server"].as_str().is_some_and(|s| s.starts_with("127.0.0.1")), "{v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/integrations/ios/configure", Some(json!({"via": ""})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert!(v["status"]["via"].is_null(), "{v}");

        // App updates: the gateway offers only builds with a signed
        // description next to them, and serves them to enrolled devices in
        // pieces; the device resumes a partial download and checks the hash.
        let downloads = tmp.path().join("downloads");
        std::fs::create_dir_all(&downloads).expect("downloads");
        let chunk = aegis_join::update::CHUNK;
        let build: Vec<u8> = (0..chunk * 2 + 123).map(|i| (i % 251) as u8).collect();
        let sha = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(&build))
        };
        std::fs::write(downloads.join("aegis-client-linux-x86_64"), &build).expect("build");
        std::fs::write(downloads.join("aegis-client-windows-x86_64.exe"), b"unsigned").expect("unsigned");
        let offered = aegis_join::update::Update {
            platform: "linux-x86_64".into(),
            version: "9.9.9".into(),
            file: "aegis-client-linux-x86_64".into(),
            size: build.len() as u64,
            sha256: sha,
            signature: "c2lnbmVk".into(),
        };
        std::fs::write(
            downloads.join("aegis-client-linux-x86_64.update"),
            serde_json::to_vec(&offered).expect("json"),
        )
        .expect("update");
        let mgmt = running.mgmt.as_ref().expect("management");
        *mgmt.downloads_dir.lock().expect("lock") = Some(downloads.clone());
        // Not signed by the release key: the device ignores the offer.
        assert_eq!(
            aegis_join::update::check(&device_dir, "linux-x86_64", "1.0.0").await.expect("check"),
            None
        );
        // An iPhone asks the same way; this gateway serves no iPhone app.
        assert_eq!(
            aegis_join::update::check_ios(&device_dir, "1.0.0").await.expect("check ios"),
            None
        );
        // Nothing for a platform without a signed build.
        let dest = tmp.path().join("update.bin");
        let mut unsigned = offered.clone();
        unsigned.file = "aegis-client-windows-x86_64.exe".into();
        unsigned.size = 8;
        assert!(
            aegis_join::update::download(&device_dir, &unsigned, &dest, |_, _| {}).await.is_err(),
            "only signed builds are served"
        );
        // A partial download resumes.
        std::fs::write(dest.with_extension("part"), &build[..chunk as usize]).expect("part");
        let pieces = std::sync::atomic::AtomicU32::new(0);
        aegis_join::update::download(&device_dir, &offered, &dest, |_, _| {
            pieces.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        })
        .await
        .expect("download");
        assert_eq!(std::fs::read(&dest).expect("downloaded"), build);
        assert_eq!(pieces.into_inner(), 2, "resumed after the first piece");
        // A build that doesn't match its description is discarded.
        let mut wrong = offered.clone();
        wrong.sha256 = "0".repeat(64);
        let _ = std::fs::remove_file(&dest);
        assert!(aegis_join::update::download(&device_dir, &wrong, &dest, |_, _| {}).await.is_err());
        assert!(!dest.exists() && !dest.with_extension("part").exists());
        let (s, v) = c.call(reqwest::Method::GET, "/system/downloads", None).await;
        assert_eq!(s, 200, "{v}");
        assert!(
            v["items"].as_array().expect("items").iter().all(|i| !i["name"].as_str().unwrap_or("").ends_with(".update")),
            "descriptions aren't listed as downloads: {v}"
        );

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

        // User portal on the public edge: end users sign in and manage their
        // own devices; administrators and everything else are refused.
        let (s, v) = c
            .call(reqwest::Method::POST, "/users", Some(json!({"username": "alice", "roles": ["user"]})))
            .await;
        assert_eq!(s, 201, "{v}");
        let alice_pw = v["temporary_password"].as_str().expect("temporary password").to_owned();
        let mut portal = Console::new(SocketAddr::from(([127, 0, 0, 1], edge_port)), &web_ca);
        portal.base = format!("https://127.0.0.1:{edge_port}/portal");
        let page = portal.http.get(format!("{}/", portal.base)).send().await.expect("portal page");
        assert_eq!(page.status().as_u16(), 200);
        assert!(page.text().await.expect("html").contains("src=\"/portal/app.js\""));
        let (s, v) = portal
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": "a much better passphrase"})))
            .await;
        assert_eq!(s, 403, "administrators without 2FA are refused on the portal: {v}");
        assert_eq!(v["aegis_error_code"], "two_factor_setup_required");
        let (s, v) = portal
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "alice", "password": alice_pw})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["password_change_required"], true);
        let (s, v) = portal
            .call(
                reqwest::Method::POST,
                "/auth/password",
                Some(json!({"current_password": alice_pw, "new_password": "alice's own passphrase"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        let (s, v) = portal.call(reqwest::Method::GET, "/devices", None).await;
        assert_eq!(s, 200, "{v}");
        let (s, v) = portal
            .call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "alice-phone"})))
            .await;
        assert_eq!(s, 201, "users invite their own devices on the portal: {v}");
        assert!(v["code"].as_str().is_some_and(|c| c.starts_with("aegis1:")));
        let (s, v) = portal.call(reqwest::Method::GET, "/system/downloads", None).await;
        assert_eq!(s, 200, "{v}");
        let (s, _) = portal.call(reqwest::Method::GET, "/users", None).await;
        assert_eq!(s, 404, "console routes don't exist on the portal");
        let (s, _) = portal.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(s, 404);
        let resp = portal
            .http
            .get(format!("{}/api/v1/devices", portal.base))
            .header("authorization", "Bearer anything")
            .send()
            .await
            .expect("token request");
        assert_eq!(resp.status().as_u16(), 403, "API tokens are refused on the portal");
        let resp = portal
            .http
            .get(format!("{}/", portal.base))
            .header("host", "evil.example")
            .send()
            .await
            .expect("foreign host");
        assert_eq!(resp.status().as_u16(), 400);
        // The console shows the portal and can switch it off.
        let (_, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(v["portal"]["enabled"], true, "{v}");
        assert!(v["portal"]["url"].as_str().is_some_and(|u| u.ends_with("/portal/")), "{v}");
        let (s, _) = c
            .call(reqwest::Method::PUT, "/system/portal", Some(json!({"enabled": false})))
            .await;
        assert_eq!(s, 200);
        let page = portal.http.get(format!("{}/", portal.base)).send().await.expect("portal off");
        assert_eq!(page.status().as_u16(), 404);
        let (s, _) = c
            .call(reqwest::Method::PUT, "/system/portal", Some(json!({"enabled": true})))
            .await;
        assert_eq!(s, 200);
        // A public port of the administrator's choice (port forwarding).
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/portal", Some(json!({"public_port": 9443})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert!(v["url"].as_str().is_some_and(|u| u.ends_with(":9443/portal/")), "{v}");
        assert_eq!((v["enabled"].clone(), v["public_port"].clone()), (json!(true), json!(9443)), "{v}");
        let host = reqwest::Url::parse(&portal.base).expect("url").host_str().expect("host").to_owned();
        let page = portal
            .http
            .get(format!("{}/", portal.base))
            .header("host", format!("{host}:9443"))
            .send()
            .await
            .expect("forwarded port");
        assert_eq!(page.status().as_u16(), 200, "the forwarded port's Host is accepted");
        for bad in [json!(0), json!(70000), json!("9443"), json!({})] {
            let (s, _) = c
                .call(reqwest::Method::PUT, "/system/portal", Some(json!({"public_port": bad})))
                .await;
            assert_eq!(s, 400, "{bad}");
        }
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/portal", Some(json!({"public_port": null})))
            .await;
        assert_eq!(s, 200);
        assert!(!v["url"].as_str().is_some_and(|u| u.contains(":9443")), "cleared: {v}");
        assert_eq!(v["enabled"], true, "the other field stays");

        // Administrators with 2FA get the whole console on the portal.
        let (s, v) = c.call(reqwest::Method::POST, "/auth/2fa/setup", None).await;
        assert_eq!(s, 200, "{v}");
        let secret = aegis_management::totp::base32_decode(v["secret"].as_str().expect("secret")).expect("base32");
        assert!(v["uri"].as_str().is_some_and(|u| u.starts_with("otpauth://totp/AegisBorne:admin?")));
        assert!(v["qr"].as_array().is_some_and(|rows| rows.len() >= 21));
        let now = aegis_management::totp::step_of(aegis_storage::now_unix());
        let code = |step: i64| format!("{:06}", aegis_management::totp::code_at(&secret, step as u64));
        let (s, v) = c
            .call(reqwest::Method::POST, "/auth/2fa/enable", Some(json!({"code": "000000"})))
            .await;
        assert!(s == 400 || code(now) == "000000", "a wrong code doesn't enable 2FA: {v}");
        let (s, v) = c
            .call(reqwest::Method::POST, "/auth/2fa/enable", Some(json!({"code": code(now)})))
            .await;
        assert_eq!(s, 200, "{v}");
        let recovery: Vec<String> = v["recovery_codes"]
            .as_array()
            .expect("recovery codes")
            .iter()
            .filter_map(|c| c.as_str().map(str::to_owned))
            .collect();
        assert_eq!(recovery.len(), 10);
        let mut admin = Console::new(SocketAddr::from(([127, 0, 0, 1], edge_port)), &web_ca);
        admin.base = format!("https://127.0.0.1:{edge_port}/portal");
        let login = |code: Option<String>| {
            let mut body = json!({"username": "admin", "password": "a much better passphrase"});
            if let Some(c) = code {
                body["code"] = json!(c);
            }
            body
        };
        let (s, v) = admin.call(reqwest::Method::POST, "/auth/login", Some(login(None))).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["aegis_error_code"], "two_factor_required");
        let (s, v) = admin
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some("123456".into()))))
            .await;
        assert!(s == 401 || code(now + 1) == "123456", "wrong code refused: {v}");
        // The next step's code (the enabling code's step is already spent).
        let (s, v) = admin
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some(code(now + 1)))))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["mfa_session"], true);
        let (s, v) = admin.call(reqwest::Method::GET, "/users", None).await;
        assert_eq!(s, 200, "the whole console with 2FA: {v}");
        let (s, _) = admin.call(reqwest::Method::GET, "/diagnostics", None).await;
        assert_eq!(s, 200);
        let (s, _) = admin
            .call(reqwest::Method::POST, "/system/device-ca/export-root-key", Some(json!({"password": "a much better passphrase"})))
            .await;
        assert_eq!(s, 404, "exporting the root key stays local-only");
        let (s, _) = admin
            .call(reqwest::Method::POST, "/system/device-ca/export%2Droot-key", Some(json!({"password": "a much better passphrase"})))
            .await;
        assert_eq!(s, 404, "an encoded path doesn't get past the rule");
        let mut again = Console::new(SocketAddr::from(([127, 0, 0, 1], edge_port)), &web_ca);
        again.base = admin.base.clone();
        let (s, _) = again
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some(code(now + 1)))))
            .await;
        assert_eq!(s, 401, "a code works once");
        let (s, v) = again
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some(recovery[0].clone()))))
            .await;
        assert_eq!(s, 200, "recovery code: {v}");
        let mut third = Console::new(SocketAddr::from(([127, 0, 0, 1], edge_port)), &web_ca);
        third.base = admin.base.clone();
        let (s, _) = third
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some(recovery[0].clone()))))
            .await;
        assert_eq!(s, 401, "a recovery code works once");
        // The local console asks for the code too once 2FA is on.
        let mut local = Console::new(running.console.expect("console"), &web_ca);
        let (s, v) = local.call(reqwest::Method::POST, "/auth/login", Some(login(None))).await;
        assert_eq!(s, 401, "{v}");
        assert_eq!(v["aegis_error_code"], "two_factor_required");
        let (s, v) = local
            .call(reqwest::Method::POST, "/auth/login", Some(login(Some(recovery[1].clone()))))
            .await;
        assert_eq!(s, 200, "{v}");
        // Owners can reset a lost authenticator.
        let (_, v) = c.call(reqwest::Method::GET, "/users", None).await;
        assert!(v["items"].as_array().expect("users").iter().any(|u| u["username"] == "admin" && u["two_factor"] == true));

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
        // The laptop (other devices joined above, e.g. a gateway's own).
        let laptop = v["items"]
            .as_array()
            .and_then(|l| l.iter().find(|d| d["name"] == "laptop"))
            .expect("laptop device")
            .clone();
        let id = laptop["id"].as_str().expect("id").to_owned();
        let etag = laptop["etag"].as_str().expect("etag").to_owned();
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
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let tmp = tempfile::tempdir().expect("tmp");
        // Pre-0.2 defaults: 31 concurrent connections per device.
        let legacy = "\n[core]\nmax_streams_per_session = 64\nstream_buffer_budget_bytes = 65536\nsession_window_bytes = 2097152\npeer_buffer_budget_bytes = 8388608\nprocess_buffer_budget_bytes = 33554432\n";
        let data = tmp.path().join("legacy");
        let running = launch_with_core(&data, legacy).await;
        let core = &running.node.ctx.startup.core;
        assert_eq!(core.max_streams_per_session, 512, "upgraded and restarted");
        assert_eq!(core.stream_buffer_budget_bytes, 2 * 1024 * 1024);
        assert_eq!(core.session_window_bytes, 10 * 1024 * 1024);
        let after = revisions(&data);
        running.shutdown().await;
        let running = launch_with_core(&data, "").await;
        assert_eq!(running.node.ctx.startup.core.max_streams_per_session, 512);
        assert_eq!(revisions(&data), after, "no second upgrade");
        running.shutdown().await;

        // 1.1.9's defaults: the windows grow to today's (ADR-0009).
        let windows = "\n[core]\nstream_buffer_budget_bytes = 262144\nsession_window_bytes = 8388608\n";
        let data = tmp.path().join("windows");
        let running = launch_with_core(&data, windows).await;
        let core = &running.node.ctx.startup.core;
        assert_eq!(core.stream_buffer_budget_bytes, 2 * 1024 * 1024);
        assert_eq!(core.session_window_bytes, 10 * 1024 * 1024);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cloudflare_device_port_is_one_of_cloudflares() {
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let tmp = tempfile::tempdir().expect("tmp");
        let data = tmp.path().join("cf");
        let running = launch_with_core(&data, "").await;
        // As the Cloudflare integration leaves it once the tunnel is active.
        let store = aegis_storage::Store::open(data.join("state.db")).expect("store");
        store
            .tx(|c| {
                aegis_storage::put_setting(
                    c,
                    "connection",
                    &json!({"mode": "cloudflare", "public_host": "gw.example.com", "public_port": 443, "outer_trust": "public"}),
                )
            })
            .expect("connection");
        let password = std::fs::read_to_string(data.join(appliance::INITIAL_PASSWORD_FILE))
            .expect("initial password")
            .trim()
            .to_owned();
        let web_ca = std::fs::read_to_string(data.join("secrets/web-ca.pem")).expect("web ca");
        let mut c = Console::new(running.console.expect("console"), &web_ca);
        let (s, _) = c
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": password})))
            .await;
        assert_eq!(s, 200);
        let (s, v) = c
            .call(
                reqwest::Method::POST,
                "/auth/password",
                Some(json!({"current_password": password, "new_password": "a much better passphrase"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");

        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/connection", Some(json!({"public_port": 9443})))
            .await;
        assert_eq!(s, 400, "not a Cloudflare port: {v}");
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/connection", Some(json!({"public_host": "evil.example", "public_port": 8443})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["connection"]["public_host"], "gw.example.com", "the tunnel's hostname stays");
        assert_eq!(v["connection"]["public_port"], 8443);
        // Invitations and the portal use it.
        let (s, v) = c.call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "phone"}))).await;
        assert_eq!(s, 201, "{v}");
        let invite = aegis_join::parse_invite(v["code"].as_str().expect("code")).expect("invite");
        assert_eq!(invite.url, "wss://gw.example.com:8443/agp");
        assert_eq!(invite.enroll_url, "https://gw.example.com:8443/enroll");
        let (_, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(v["portal"]["url"], "https://gw.example.com:8443/portal/", "{v}");
        running.shutdown().await;
    })
    .await
    .expect("bounded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quic_is_offered_to_devices_only_once_turned_on_and_complete() {
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let tmp = tempfile::tempdir().expect("tmp");
        let data = tmp.path().join("quic");
        let running = launch_with_core(&data, "").await;
        assert!(
            running
                .node
                .ctx
                .startup
                .inbounds
                .iter()
                .any(|i| i.kind == aegis_config::InboundKind::Quic),
            "the seed listens for QUIC"
        );
        let store = aegis_storage::Store::open(data.join("state.db")).expect("store");
        store
            .tx(|c| {
                aegis_storage::put_setting(
                    c,
                    "connection",
                    &json!({"mode": "cloudflare", "public_host": "gw.example.com", "public_port": 443, "outer_trust": "public"}),
                )
            })
            .expect("connection");
        let password = std::fs::read_to_string(data.join(appliance::INITIAL_PASSWORD_FILE))
            .expect("initial password")
            .trim()
            .to_owned();
        let web_ca = std::fs::read_to_string(data.join("secrets/web-ca.pem")).expect("web ca");
        let mut c = Console::new(running.console.expect("console"), &web_ca);
        let (s, _) = c
            .call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": password})))
            .await;
        assert_eq!(s, 200);
        let (s, v) = c
            .call(
                reqwest::Method::POST,
                "/auth/password",
                Some(json!({"current_password": password, "new_password": "a much better passphrase"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        let invite_quic = |v: &Value| {
            aegis_join::parse_invite(v["code"].as_str().expect("code"))
                .expect("invite")
                .quic
        };
        // Off by default.
        let (_, v) = c.call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "a"}))).await;
        assert_eq!(invite_quic(&v), None);
        // On, but through Cloudflare the server's own address is missing.
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/quic", Some(json!({"enabled": true})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["address"], Value::Null);
        assert!(v["warning"].is_string());
        let (_, v) = c.call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "b"}))).await;
        assert_eq!(invite_quic(&v), None, "incomplete: not offered");
        let (s, _) = c
            .call(reqwest::Method::PUT, "/system/quic", Some(json!({"host": "not a host!"})))
            .await;
        assert_eq!(s, 400);
        let (s, v) = c
            .call(reqwest::Method::PUT, "/system/quic", Some(json!({"host": "203.0.113.7", "port": 8444})))
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["address"], "203.0.113.7:8444");
        let (_, v) = c.call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "c"}))).await;
        assert_eq!(invite_quic(&v).as_deref(), Some("203.0.113.7:8444"));
        let (_, v) = c.call(reqwest::Method::GET, "/system/info", None).await;
        assert_eq!(v["quic"]["enabled"], true);
        // Off again: not offered.
        c.call(reqwest::Method::PUT, "/system/quic", Some(json!({"enabled": false})))
            .await;
        let (_, v) = c.call(reqwest::Method::POST, "/devices/invite", Some(json!({"name": "d"}))).await;
        assert_eq!(invite_quic(&v), None);
        running.shutdown().await;
    })
    .await
    .expect("bounded");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn console_upgrades_go_through_the_updater_files() {
    let _one_at_a_time = ONE_AT_A_TIME.lock().await;
    tokio::time::timeout(Duration::from_secs(60), async {
        let tmp = tempfile::tempdir().expect("tmp");
        let data = tmp.path().join("updates");
        let running = launch_with_core(&data, "").await;
        let password = std::fs::read_to_string(data.join(appliance::INITIAL_PASSWORD_FILE))
            .expect("initial password")
            .trim()
            .to_owned();
        let web_ca = std::fs::read_to_string(data.join("secrets/web-ca.pem")).expect("web ca");
        let mut c = Console::new(running.console.expect("console"), &web_ca);
        c.call(reqwest::Method::POST, "/auth/login", Some(json!({"username": "admin", "password": password})))
            .await;
        let (s, v) = c
            .call(
                reqwest::Method::POST,
                "/auth/password",
                Some(json!({"current_password": password, "new_password": "a much better passphrase"})),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        // No updater yet: nothing to ask.
        let (s, v) = c.call(reqwest::Method::GET, "/system/updates", None).await;
        assert_eq!(s, 200);
        assert_eq!(v["updater"], false);
        assert_eq!(v["running"], env!("CARGO_PKG_VERSION"));
        let (s, _) = c
            .call(reqwest::Method::POST, "/system/updates", Some(json!({"action": "check"})))
            .await;
        assert_eq!(s, 409, "refused without an updater");
        // An updater reporting in.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();
        aegis_updater::files::write_status(
            &data,
            &json!({"heartbeat": now, "source": "local", "running": "0.7.0", "available": "0.8.0", "state": "idle"}),
        )
        .expect("status");
        let (_, v) = c.call(reqwest::Method::GET, "/system/updates", None).await;
        assert_eq!(v["updater"], true);
        assert_eq!(v["available"], "0.8.0");
        assert_eq!(v["source"], "local");
        let (s, _) = c
            .call(reqwest::Method::POST, "/system/updates", Some(json!({"action": "upgrade", "version": "latest"})))
            .await;
        assert_eq!(s, 400, "only a release version");
        let (s, _) = c
            .call(reqwest::Method::POST, "/system/updates", Some(json!({"action": "upgrade", "version": "0.8.0"})))
            .await;
        assert_eq!(s, 202);
        assert_eq!(
            aegis_updater::files::take_request(&data),
            Some(aegis_updater::files::Request::Upgrade(Some(aegis_updater::version::Version(0, 8, 0))))
        );
        let (s, v) = c
            .call(reqwest::Method::POST, "/system/updates", Some(json!({"auto": true})))
            .await;
        assert_eq!(s, 202);
        assert_eq!(v["auto"], true);
        assert!(aegis_updater::files::auto(&data));
        running.shutdown().await;
    })
    .await
    .expect("bounded");
}
