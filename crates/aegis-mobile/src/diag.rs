//! On-demand diagnostics on the phone (ADR-0008): the desktop client's
//! recorder, sent to the gateway signed with the device's key. Off unless
//! the user starts it, memory only, at most 5 MB, stops by itself; when the
//! time runs out the report is sent. The last send's outcome is also kept
//! in the data folder, so the iOS app can show it after the tunnel
//! extension (which records there) has ended.
//!
//! A phone that needs diagnosing often can't reach its gateway, so the
//! report can't be sent either: it can be saved to a file instead (iOS
//! does that by itself when the extension's send fails), shared from the
//! phone and imported in the console. A recording also checks the
//! gateway's address from the phone (name lookup, TCP connection), when it
//! starts and whenever connecting fails.

use crate::{client, fail, lock, now, ok, Client};
use aegis_join::{DeviceDir, JoinError, Servers};
use aegis_telemetry::report::{Report, Role};
use aegis_telemetry::{DiagnosticSink, Severity};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The last send's outcome, in the data folder.
const RESULT_FILE: &str = "diagnostics-result.json";
/// How long that outcome is shown.
const RESULT_KEPT: u64 = 3600;
/// Under the gateway's limit, with room for base64 and JSON.
const MAX_UPLOAD: usize = 900 * 1024;

#[derive(Default)]
pub(crate) struct Diag {
    pub(crate) sink: Arc<DiagnosticSink>,
    /// Changes with every start, stop and discard: a recording's watcher
    /// sends it when its time runs out only if nothing else happened.
    generation: AtomicU64,
    /// Recorded and not sent yet.
    unsent: AtomicBool,
    sending: AtomicBool,
}

fn next(d: &Diag) -> u64 {
    d.generation.fetch_add(1, Ordering::SeqCst) + 1
}

/// Start recording for `minutes` (1 to 60), replacing an earlier recording.
/// `about` describes the phone (model, system version).
pub fn start(dir: &str, minutes: u64, about: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let d = &c.diag;
    if let Err(e) = d
        .sink
        .start(Duration::from_secs(minutes.saturating_mul(60)))
    {
        return fail(e);
    }
    let generation = next(d);
    d.unsent.store(true, Ordering::SeqCst);
    let _ = std::fs::remove_file(Path::new(dir).join(RESULT_FILE));
    let s = lock(&c.snapshot).clone();
    d.sink.note(
        Severity::Info,
        "client.info",
        &[
            ("version", env!("CARGO_PKG_VERSION")),
            ("os", std::env::consts::OS),
            ("arch", std::env::consts::ARCH),
            ("device", about),
            ("state", s.state.as_str()),
            ("transport", s.transport.unwrap_or("none")),
            ("server", s.server.as_deref().unwrap_or("")),
        ],
    );
    if let Ok(Some(server)) = Servers::open(dir).map(|s| s.selected()) {
        c.rt.spawn(async move { reach(&server.dir, &c.diag.sink).await });
    }
    // Send by itself when the time runs out.
    let dir = dir.to_owned();
    c.rt.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            if c.diag.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            if !c.diag.sink.status().active {
                break;
            }
        }
        send(c, &dir).await;
    });
    ok(json!({}))
}

/// Stop recording; with `send`, send the report (blocks).
pub fn stop(dir: &str, send_it: bool) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    c.diag.sink.stop();
    next(&c.diag);
    if send_it {
        send_now(dir)
    } else {
        ok(json!({}))
    }
}

/// Send what was recorded to the selected server (blocks). `sent` says
/// whether it arrived; `message` is for the user either way.
pub fn send_now(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let (sent, message) = c.rt.block_on(send(c, dir));
    ok(json!({"sent": sent, "message": message}))
}

/// The tunnel is ending (iOS: the extension, and the recording with it):
/// stop a recording that wasn't sent, save it to a file for the app to
/// share, then send it (the file goes once it arrived). Saving first keeps
/// it if the system ends the process mid-send. Blocks.
pub fn finish(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    if !c.diag.unsent.load(Ordering::SeqCst) || c.diag.sink.status().state == "off" {
        return ok(json!({}));
    }
    c.diag
        .sink
        .note(Severity::Info, "client.tunnel.ending", &[]);
    c.diag.sink.stop();
    next(&c.diag);
    let saved = save(dir);
    let sent = send_now(dir);
    if sent["sent"] == true {
        let _ = std::fs::remove_dir_all(Path::new(dir).join("diagnostics"));
    } else if let Some(file) = saved["path"].as_str() {
        let path = Path::new(dir).join(RESULT_FILE);
        if let Some(mut result) = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        {
            result["file"] = json!(file);
            let _ = std::fs::write(&path, result.to_string());
        }
    }
    sent
}

/// Write what was recorded to a gzipped OTLP/JSON file (the console imports
/// it) under `dir/diagnostics`, replacing an earlier one; returns its `path`.
pub fn save(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let Some(recording) = c.diag.sink.recording() else {
        return fail("Nothing was recorded.");
    };
    let name = Servers::open(dir)
        .ok()
        .and_then(|s| s.selected())
        .map(|s| s.device.name.clone())
        .unwrap_or_else(|| "phone".into());
    let mut report = Report {
        role: Role::Client,
        name,
        version: env!("CARGO_PKG_VERSION").into(),
        recording,
    };
    let folder = Path::new(dir).join("diagnostics");
    let _ = std::fs::remove_dir_all(&folder);
    let path: PathBuf = folder.join(format!("aegisborne-diagnostics-{}.otlp.json.gz", now()));
    let written = std::fs::create_dir_all(&folder)
        .and_then(|()| std::fs::write(&path, report.to_gzip(usize::MAX)));
    match written {
        Ok(()) => ok(json!({"path": path.to_string_lossy()})),
        Err(e) => fail(format!("Could not save the report: {e}")),
    }
}

pub fn discard(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    c.diag.sink.discard();
    next(&c.diag);
    c.diag.unsent.store(false, Ordering::SeqCst);
    let _ = std::fs::remove_file(Path::new(dir).join(RESULT_FILE));
    let _ = std::fs::remove_dir_all(Path::new(dir).join("diagnostics"));
    ok(json!({}))
}

/// Record something the platform side saw (the VPN interface refused, the
/// system stopping the VPN). A no-op unless recording.
pub fn note(text: &str) -> Value {
    if let Ok(c) = client() {
        c.diag
            .sink
            .note(Severity::Warn, "client.platform", &[("error", text)]);
    }
    ok(json!({}))
}

/// `state` (`off`, `recording` or `stopped`), the time left, how many
/// events, whether a send is running, and the last send's outcome
/// (`result`: `{sent, message, at}`) from the last hour.
pub fn status(dir: &str) -> Value {
    let c = match client() {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let s = c.diag.sink.status();
    let result = std::fs::read(Path::new(dir).join(RESULT_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .filter(|r| {
            r["at"]
                .as_u64()
                .is_some_and(|at| now().saturating_sub(at) < RESULT_KEPT)
        });
    ok(json!({
        "state": s.state,
        "remaining_seconds": s.remaining_seconds,
        "events": s.events,
        "sending": c.diag.sending.load(Ordering::SeqCst),
        "result": result,
    }))
}

/// Check the gateway's address from the phone: look its name up, then open
/// a TCP connection to the port. Tells a blocked or altered name lookup
/// from a blocked port from a gateway that answers. A no-op unless
/// recording.
pub(crate) async fn reach(dir: &DeviceDir, sink: &DiagnosticSink) {
    if !sink.status().active {
        return;
    }
    let Ok(device) = dir.load() else {
        return;
    };
    let (host, port) = host_port(&device.url);
    let started = Instant::now();
    let ms = |t: Instant| t.elapsed().as_millis().to_string();
    let lookup = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await;
    let addresses: Vec<std::net::SocketAddr> = match lookup {
        Ok(Ok(a)) => a.collect(),
        Ok(Err(e)) => {
            let e = e.to_string();
            let attrs = [
                ("host", host.as_str()),
                ("result", "failed"),
                ("error", e.as_str()),
            ];
            return sink.note(Severity::Warn, "client.reach.dns", &attrs);
        }
        Err(_) => {
            let attrs = [
                ("host", host.as_str()),
                ("result", "failed"),
                ("error", "timed out"),
            ];
            return sink.note(Severity::Warn, "client.reach.dns", &attrs);
        }
    };
    let mut ips: Vec<String> = addresses.iter().map(|a| a.ip().to_string()).collect();
    ips.dedup();
    ips.truncate(4);
    let (ips, took) = (ips.join(", "), ms(started));
    sink.note(
        Severity::Info,
        "client.reach.dns",
        &[
            ("host", &host),
            ("result", "ok"),
            ("addresses", &ips),
            ("ms", &took),
        ],
    );
    let Some(first) = addresses.first().copied() else {
        return;
    };
    let started = Instant::now();
    let connected = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(first),
    )
    .await;
    let (address, took) = (first.to_string(), ms(started));
    let (severity, result, error) = match connected {
        Ok(Ok(_)) => (Severity::Info, "ok", String::new()),
        Ok(Err(e)) => (Severity::Warn, "failed", e.to_string()),
        Err(_) => (Severity::Warn, "failed", "timed out".to_owned()),
    };
    sink.note(
        severity,
        "client.reach.tcp",
        &[
            ("address", &address),
            ("result", result),
            ("error", &error),
            ("ms", &took),
        ],
    );
}

/// Host and port of a `wss://host[:port]/…` address (443 by default).
pub(crate) fn host_port(url: &str) -> (String, u16) {
    let authority = crate::host_of(url);
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => match v6.split_once("]:") {
            Some((h, p)) => (h, Some(p)),
            None => (v6.trim_end_matches(']'), None),
        },
        None => match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority.as_str(), None),
        },
    };
    (
        host.to_owned(),
        port.and_then(|p| p.parse().ok()).unwrap_or(443),
    )
}

async fn send(c: &'static Client, dir: &str) -> (bool, String) {
    c.diag.sending.store(true, Ordering::SeqCst);
    let (sent, message) = upload(c, dir).await;
    c.diag.sending.store(false, Ordering::SeqCst);
    if sent {
        c.diag.unsent.store(false, Ordering::SeqCst);
    }
    let result = json!({"sent": sent, "message": message, "at": now()});
    let _ = std::fs::write(Path::new(dir).join(RESULT_FILE), result.to_string());
    (sent, message)
}

async fn upload(c: &Client, dir: &str) -> (bool, String) {
    let Some(recording) = c.diag.sink.recording() else {
        return (false, "Nothing was recorded.".into());
    };
    let server = match Servers::open(dir).map(|s| s.selected()) {
        Ok(Some(s)) => s,
        _ => return (false, "Join a server first.".into()),
    };
    let mut report = Report {
        role: Role::Client,
        name: server.device.name.clone(),
        version: env!("CARGO_PKG_VERSION").into(),
        recording,
    };
    let gz = report.to_gzip(MAX_UPLOAD);
    match aegis_join::upload_diagnostics(&server.dir, &gz).await {
        Ok(()) => (
            true,
            "Report sent. Your administrator can now see it under Diagnostics.".into(),
        ),
        Err(JoinError::Rejected { status: 409, .. }) => (
            false,
            "Diagnostics are off on the server. Ask your administrator to start them in the console (Diagnostics), then send again.".into(),
        ),
        Err(JoinError::Network(_)) => (
            false,
            "Could not reach the server to send the report. Send again when the phone is online.".into(),
        ),
        Err(e) => (false, format!("Could not send the report: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_addresses_split_into_host_and_port() {
        assert_eq!(
            host_port("wss://gw.example.test/agp"),
            ("gw.example.test".into(), 443)
        );
        assert_eq!(
            host_port("wss://gw.example.test:8443/agp"),
            ("gw.example.test".into(), 8443)
        );
        assert_eq!(
            host_port("wss://[2001:db8::1]:9443/agp"),
            ("2001:db8::1".into(), 9443)
        );
        assert_eq!(
            host_port("wss://[2001:db8::1]/agp"),
            ("2001:db8::1".into(), 443)
        );
    }
}
