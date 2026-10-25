//! `aegisctl` — local administration CLI.
//!
//! * `validate <config.toml>`: offline validation against this build.
//! * `pki ...`: local CA, direct issuance (bootstrap) and node CSRs.
//! * IPC commands (`health`, `bootstrap-token`, `token`, `activation ...`,
//!   `diagnostic ...`, `metrics`) talk to `aegisd` over its owner-only Unix
//!   socket.
//! * `api ...` / `activate` / `enroll-redeem` call the loopback REST API.
#![forbid(unsafe_code)]

use aegis_contracts::Role;
use aegis_identity::pki;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: aegisctl <command> [options]

offline:
  validate <config.toml>
  pki init-ca --out DIR [--name NAME]
  pki issue --ca DIR --node-id ID --role gateway|client [--server-name NAME]... --out DIR [--days N]
  pki csr --node-id ID --out DIR

local IPC (owner-only socket; --socket PATH, default /var/lib/aegisnet/aegisd.sock):
  health | metrics | bootstrap-token
  bootstrap-owner --username NAME            (password on stdin; mints + claims the one-use token)
  token [--scopes a,b,...] [--ttl SECONDS]
  activation inspect
  activation reconcile OPERATION_ID
  activation supersede --pending OP --expected-runtime REV|null --epoch N --revision REV --digest HEX --reason TEXT
  diagnostic start [--minutes N] | diagnostic status | diagnostic stop

REST API (--api URL default http://127.0.0.1:9080, --token or $AEGIS_TOKEN):
  api METHOD PATH [--data JSON] [--if-match ETAG] [--idempotency-key KEY]
  activate PROFILE_ID
  enroll-redeem --invite TOKEN --name NODE --csr FILE [--server-name NAME]... --out DIR";

fn die(msg: impl AsRef<str>) -> ExitCode {
    eprintln!("aegisctl: {}", msg.as_ref());
    ExitCode::FAILURE
}

struct Opts {
    positional: Vec<String>,
    flags: Vec<(String, String)>,
}

impl Opts {
    fn parse(args: &[String]) -> Opts {
        let mut positional = Vec::new();
        let mut flags = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if let Some(name) = args[i].strip_prefix("--") {
                let value = args.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
                if value.is_some() {
                    i += 1;
                }
                flags.push((name.to_owned(), value.unwrap_or_default()));
            } else {
                positional.push(args[i].clone());
            }
            i += 1;
        }
        Opts { positional, flags }
    }

    fn get(&self, k: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }

    fn all(&self, k: &str) -> Vec<String> {
        self.flags
            .iter()
            .filter(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn req(&self, k: &str) -> Result<&str, String> {
        self.get(k)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("--{k} is required"))
    }
}

fn write_file(path: &Path, content: &str, secret: bool) -> Result<(), String> {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, content).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = secret;
    Ok(())
}

fn print(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
}

fn cmd_validate(o: &Opts) -> Result<bool, String> {
    let path = o.positional.get(1).ok_or("validate needs a config path")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let cfg = match aegis_config::parse_toml(&text) {
        Ok(c) => c,
        Err(e) => {
            print(&json!({"valid": false, "errors": [e.to_string()]}));
            return Ok(false);
        }
    };
    match aegis_node::validate_offline(&cfg) {
        Ok(c) => {
            print(&json!({"valid": true, "config_digest": c.digest, "warnings": c.warnings}));
            Ok(true)
        }
        Err(errors) => {
            print(&json!({"valid": false, "errors": errors}));
            Ok(false)
        }
    }
}

fn load_ca(dir: &Path) -> Result<pki::CaBundle, String> {
    Ok(pki::CaBundle {
        cert_pem: std::fs::read_to_string(dir.join("ca.pem"))
            .map_err(|e| format!("ca.pem: {e}"))?,
        key_pem: std::fs::read_to_string(dir.join("ca-key.pem"))
            .map_err(|e| format!("ca-key.pem: {e}"))?,
    })
}

fn cmd_pki(o: &Opts) -> Result<(), String> {
    match o.positional.get(1).map(String::as_str) {
        Some("init-ca") => {
            let out = PathBuf::from(o.req("out")?);
            if out.join("ca-key.pem").exists() {
                return Err("refusing to overwrite an existing CA key".into());
            }
            let ca = pki::generate_ca(
                o.get("name").unwrap_or("aegisnet-local-ca"),
                pki::DEFAULT_CA_VALIDITY,
            )
            .map_err(|e| e.to_string())?;
            write_file(&out.join("ca.pem"), &ca.cert_pem, false)?;
            write_file(&out.join("ca-key.pem"), &ca.key_pem, true)?;
            print(
                &json!({"ca_certificate": out.join("ca.pem"), "ca_private_key": out.join("ca-key.pem")}),
            );
            Ok(())
        }
        Some("issue") => {
            let ca = load_ca(Path::new(o.req("ca")?))?;
            let role = match o.req("role")? {
                "gateway" => Role::Gateway,
                "client" => Role::Client,
                _ => return Err("--role must be gateway or client".into()),
            };
            let days: u64 = o
                .get("days")
                .unwrap_or("30")
                .parse()
                .map_err(|_| "--days must be a number")?;
            let names = o.all("server-name");
            let (cert, key) = pki::issue_direct(
                &ca,
                o.req("node-id")?,
                role,
                &names,
                Duration::from_secs(days * 86_400),
            )
            .map_err(|e| e.to_string())?;
            let out = PathBuf::from(o.req("out")?);
            write_file(&out.join("cert.pem"), &cert, false)?;
            write_file(&out.join("key.pem"), &key, true)?;
            print(
                &json!({"certificate": out.join("cert.pem"), "private_key": out.join("key.pem")}),
            );
            Ok(())
        }
        Some("csr") => {
            let (key, csr) =
                pki::generate_key_and_csr(o.req("node-id")?).map_err(|e| e.to_string())?;
            let out = PathBuf::from(o.req("out")?);
            write_file(&out.join("key.pem"), &key, true)?;
            write_file(&out.join("csr.pem"), &csr, false)?;
            print(&json!({"private_key": out.join("key.pem"), "csr": out.join("csr.pem")}));
            Ok(())
        }
        _ => Err("pki subcommand must be init-ca, issue or csr".into()),
    }
}

#[cfg(unix)]
fn ipc(o: &Opts, req: Value) -> Result<Value, String> {
    use std::os::unix::net::UnixStream;
    let path = o.get("socket").unwrap_or("/var/lib/aegisnet/aegisd.sock");
    let mut s = UnixStream::connect(path).map_err(|e| format!("{path}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    let mut body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    body.push(b'\n');
    s.write_all(&body).map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).map_err(|e| e.to_string())?;
    serde_json::from_str(out.trim()).map_err(|e| e.to_string())
}

#[cfg(not(unix))]
fn ipc(_o: &Opts, _req: Value) -> Result<Value, String> {
    Err("local IPC is only available on Unix in this build".into())
}

fn ipc_print(o: &Opts, req: Value) -> Result<bool, String> {
    let resp = ipc(o, req)?;
    let ok = resp.get("ok").and_then(Value::as_bool).unwrap_or(false);
    print(
        resp.get(if ok { "result" } else { "error" })
            .unwrap_or(&resp),
    );
    Ok(ok)
}

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Minimal HTTP/1.1 client for the loopback management API.
fn http(
    o: &Opts,
    method: &str,
    path: &str,
    body: Option<&Value>,
    extra: &[(&str, String)],
    auth: bool,
) -> Result<HttpResponse, String> {
    let base = o.get("api").unwrap_or("http://127.0.0.1:9080");
    let authority = base
        .strip_prefix("http://")
        .ok_or("--api must be an http:// loopback URL (remote management requires TLS, not provided by this build)")?
        .trim_end_matches('/');
    let mut stream =
        std::net::TcpStream::connect(authority).map_err(|e| format!("{authority}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    let payload = body
        .map(|b| serde_json::to_vec(b).unwrap_or_default())
        .unwrap_or_default();
    let mut req = format!("{method} /api/v1{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n");
    if auth {
        let token = o
            .get("token")
            .map(str::to_owned)
            .or_else(|| std::env::var("AEGIS_TOKEN").ok())
            .ok_or("--token or AEGIS_TOKEN is required (mint one with `aegisctl token`)")?;
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (k, v) in extra {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if body.is_some() {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            payload.len()
        ));
    }
    req.push_str("\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.write_all(&payload).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (head, rest) = text
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP response")?;
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("malformed status line")?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.contains("chunked"));
    let body_text = if chunked {
        dechunk(rest)
    } else {
        rest.to_owned()
    };
    let body = serde_json::from_str(&body_text).unwrap_or(Value::Null);
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn dechunk(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some((size, tail)) = rest.split_once("\r\n") {
        let Ok(n) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if n == 0 || tail.len() < n {
            break;
        }
        out.push_str(&tail[..n]);
        rest = tail[n..].trim_start_matches("\r\n");
    }
    out
}

fn idem_key() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cmd_api(o: &Opts) -> Result<bool, String> {
    let method = o
        .positional
        .get(1)
        .ok_or("api needs METHOD PATH")?
        .to_ascii_uppercase();
    let path = o.positional.get(2).ok_or("api needs METHOD PATH")?;
    let body = match o.get("data") {
        Some(d) => Some(serde_json::from_str::<Value>(d).map_err(|e| format!("--data: {e}"))?),
        None => None,
    };
    let mut extra = Vec::new();
    if let Some(e) = o.get("if-match") {
        extra.push(("If-Match", e.to_owned()));
    }
    if let Some(k) = o.get("idempotency-key") {
        extra.push(("Idempotency-Key", k.to_owned()));
    }
    let r = http(o, &method, path, body.as_ref(), &extra, true)?;
    if let Some(etag) = r.header("etag") {
        eprintln!("ETag: {etag}");
    }
    print(&r.body);
    Ok(r.status < 400)
}

/// Validate the profile's desired revision, activate it and poll the job.
fn cmd_activate(o: &Opts) -> Result<bool, String> {
    let id = o.positional.get(1).ok_or("activate needs PROFILE_ID")?;
    let p = http(o, "GET", &format!("/profiles/{id}"), None, &[], true)?;
    if p.status != 200 {
        print(&p.body);
        return Ok(false);
    }
    let etag = p.header("etag").ok_or("missing ETag")?.to_owned();
    let rev = p.body["desired_revision_id"]
        .as_str()
        .ok_or("missing desired revision")?
        .to_owned();
    let v = http(
        o,
        "POST",
        &format!("/profiles/{id}/validate"),
        Some(&json!({"target_revision_id": rev})),
        &[("If-Match", etag.clone())],
        true,
    )?;
    if v.body["valid"] != true {
        print(&v.body);
        return Ok(false);
    }
    eprintln!("security diff:");
    for line in v.body["security_diff"].as_array().into_iter().flatten() {
        eprintln!("  - {}", line.as_str().unwrap_or(""));
    }
    let body = json!({
        "target_revision_id": v.body["target_revision_id"],
        "config_digest": v.body["config_digest"],
        "validation_id": v.body["validation_id"],
    });
    let a = http(
        o,
        "POST",
        &format!("/profiles/{id}/activate"),
        Some(&body),
        &[("If-Match", etag), ("Idempotency-Key", idem_key())],
        true,
    )?;
    if a.status != 202 {
        print(&a.body);
        return Ok(false);
    }
    let job = a.body["id"].as_str().ok_or("missing job id")?.to_owned();
    for _ in 0..120 {
        let j = http(o, "GET", &format!("/jobs/{job}"), None, &[], true)?;
        match j.body["status"].as_str() {
            Some("pending" | "running") => std::thread::sleep(Duration::from_millis(500)),
            _ => {
                print(&j.body);
                return Ok(j.body["status"] == "succeeded");
            }
        }
    }
    Err("job did not finish in time".into())
}

fn cmd_redeem(o: &Opts) -> Result<bool, String> {
    let csr = std::fs::read_to_string(o.req("csr")?).map_err(|e| e.to_string())?;
    let body = json!({
        "token": o.req("invite")?,
        "node_name": o.req("name")?,
        "csr_pem": csr,
        "server_names": o.all("server-name"),
    });
    let r = http(
        o,
        "POST",
        "/nodes/enrollment/redeem",
        Some(&body),
        &[],
        false,
    )?;
    if r.status != 201 {
        print(&r.body);
        return Ok(false);
    }
    let out = PathBuf::from(o.req("out")?);
    write_file(
        &out.join("cert.pem"),
        r.body["certificate_pem"].as_str().unwrap_or(""),
        false,
    )?;
    write_file(
        &out.join("ca.pem"),
        r.body["ca_certificate_pem"].as_str().unwrap_or(""),
        false,
    )?;
    print(
        &json!({"node_id": r.body["node_id"], "certificate": out.join("cert.pem"), "ca_certificate": out.join("ca.pem"), "expires_at": r.body["expires_at"]}),
    );
    Ok(true)
}

/// Headless owner bootstrap: mint the one-use token over local IPC and claim
/// it via the API. The password is read from stdin (never argv/env).
fn cmd_bootstrap_owner(o: &Opts) -> Result<bool, String> {
    let username = o.req("username")?.to_owned();
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|e| e.to_string())?;
    let password = password.trim_end_matches(['\r', '\n']).to_owned();
    if password.chars().count() < 12 {
        return Err("owner password (stdin) must be at least 12 characters".into());
    }
    let resp = ipc(o, json!({"cmd": "bootstrap_token"}))?;
    let token = resp["result"]["bootstrap_token"]
        .as_str()
        .ok_or_else(|| resp["error"].as_str().unwrap_or("bootstrap token unavailable").to_owned())?
        .to_owned();
    let body = json!({"bootstrap_token": token, "owner_username": username, "owner_password": password});
    let r = http(o, "POST", "/bootstrap/claim", Some(&body), &[], false)?;
    print(&r.body);
    Ok(r.status == 201)
}

fn run(args: &[String]) -> Result<bool, String> {
    let o = Opts::parse(args);
    if o.positional.is_empty() && o.get("version").is_some() {
        println!("aegisctl {}", env!("CARGO_PKG_VERSION"));
        return Ok(true);
    }
    let cmd = o.positional.first().map(String::as_str).unwrap_or("");
    match cmd {
        "bootstrap-owner" => cmd_bootstrap_owner(&o),
        "validate" => cmd_validate(&o),
        "pki" => cmd_pki(&o).map(|_| true),
        "health" => ipc_print(&o, json!({"cmd": "health"})),
        "metrics" => ipc_print(&o, json!({"cmd": "metrics"})),
        "bootstrap-token" => ipc_print(&o, json!({"cmd": "bootstrap_token"})),
        "token" => {
            let mut req = json!({"cmd": "token_create"});
            if let Some(s) = o.get("scopes") {
                req["scopes"] = json!(s
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>());
            }
            if let Some(t) = o.get("ttl") {
                req["ttl_seconds"] =
                    json!(t.parse::<u64>().map_err(|_| "--ttl must be a number")?);
            }
            ipc_print(&o, req)
        }
        "activation" => match o.positional.get(1).map(String::as_str) {
            Some("inspect") => ipc_print(&o, json!({"cmd": "activation_inspect"})),
            Some("reconcile") => {
                let op = o.positional.get(2).ok_or("reconcile needs OPERATION_ID")?;
                ipc_print(
                    &o,
                    json!({"cmd": "activation_reconcile", "operation_id": op}),
                )
            }
            Some("supersede") => {
                let expected = o.req("expected-runtime")?;
                ipc_print(
                    &o,
                    json!({
                        "cmd": "activation_supersede",
                        "pending_operation_id": o.req("pending")?,
                        "expected_runtime_revision_id": if expected == "null" { Value::Null } else { json!(expected) },
                        "expected_security_epoch": o.req("epoch")?.parse::<i64>().map_err(|_| "--epoch must be a number")?,
                        "recovery_revision_id": o.req("revision")?,
                        "recovery_config_digest": o.req("digest")?,
                        "reason": o.req("reason")?,
                    }),
                )
            }
            _ => Err("activation subcommand must be inspect, reconcile or supersede".into()),
        },
        "diagnostic" => match o.positional.get(1).map(String::as_str) {
            Some("start") => {
                let minutes: u64 = o
                    .get("minutes")
                    .unwrap_or("5")
                    .parse()
                    .map_err(|_| "--minutes must be a number")?;
                ipc_print(&o, json!({"cmd": "diagnostic_start", "minutes": minutes}))
            }
            Some("status") => ipc_print(&o, json!({"cmd": "diagnostic_status"})),
            Some("stop") => ipc_print(&o, json!({"cmd": "diagnostic_stop"})),
            _ => Err("diagnostic subcommand must be start, status or stop".into()),
        },
        "api" => cmd_api(&o),
        "activate" => cmd_activate(&o),
        "enroll-redeem" => cmd_redeem(&o),
        "--version" | "version" => {
            println!("aegisctl {}", env!("CARGO_PKG_VERSION"));
            Ok(true)
        }
        _ => {
            println!("{USAGE}");
            Ok(cmd == "help" || cmd == "--help")
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => die(e),
    }
}
