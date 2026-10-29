//! Appliance console endpoints: setup status, server address, web CA
//! download and built-in integrations ("plugins"). Integration work runs in
//! the composition root behind [`crate::ApplianceServices`]; this module
//! only authenticates, authorizes, validates and audits.

use super::devices::{connection, valid_public_host, Connection};
use super::{blocking, Ctx};
use crate::auth::Permission;
use crate::http_util::{json, read_json, ApiError, ApiResult};
use aegis_storage::{self as db, AuditInsert};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use http::{header, HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

/// Setup checklist and runtime summary for the dashboard.
pub async fn info(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    if p.password_change_required() {
        return Err(ApiError::forbidden().detail("password change required"));
    }
    let c = ctx.clone();
    let (conn, owners_pending, devices) = blocking(move || {
        let conn = connection(&c)?;
        let store = c.coord.store();
        let pending = store.read_as(|c| -> Result<i64, ApiError> {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM principals p JOIN principal_roles r ON r.principal_id = p.id WHERE r.role = 'owner' AND p.must_change_password = 1",
                [],
                |r| r.get(0),
            ).map_err(db::StoreError::from)?)
        })?;
        let devices = store.read_as(|c| -> Result<i64, ApiError> {
            Ok(c.query_row(
                "SELECT COUNT(*) FROM nodes WHERE role = 'client' AND status IN ('active','rotating')",
                [],
                |r| r.get(0),
            ).map_err(db::StoreError::from)?)
        })?;
        Ok((conn, pending, devices))
    })
    .await?;
    let appliance = ctx.appliance();
    Ok(json(
        StatusCode::OK,
        &json!({
            "version": env!("CARGO_PKG_VERSION"),
            "appliance": appliance.is_some(),
            "tunnel_only": ctx.tunnel_only(),
            "portal": crate::portal::status_json(&ctx),
            "quic": super::devices::quic_status_json(&ctx),
            "console_certificate_sha256": ctx.console_fingerprint(),
            "connection": conn,
            "checklist": {
                "owner_password_changed": owners_pending == 0,
                "server_address_set": conn.public_host.is_some()
                    && (!ctx.tunnel_only() || conn.mode.as_deref() == Some("cloudflare")),
                "devices_enrolled": devices,
            },
            "runtime": appliance.map(|a| a.status()).unwrap_or(Value::Null),
            "health": ctx.coord.health(),
        }),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionBody {
    #[serde(default)]
    public_host: Option<String>,
    public_port: u16,
}

/// Set the address devices use to reach this server in direct mode, or,
/// with Cloudflare Tunnel, the port (one of Cloudflare's HTTPS ports).
/// Enrolled devices follow the change on their next connection.
pub async fn put_connection(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PUT)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ConnectionBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if connection(&ctx)?.mode.as_deref() == Some("cloudflare") {
        return put_cloudflare_port(&ctx, &p.id, b.public_port).await;
    }
    let Some(public_host) = b.public_host else {
        return Err(ApiError::bad_request("invalid_public_address")
            .detail("enter an IP address or DNS name and a port"));
    };
    if ctx.tunnel_only() {
        return Err(ApiError::conflict("tunnel_only").detail(
            "this gateway was installed with --tunnel-only, so its device port is not reachable from the network; use Cloudflare Tunnel (or reinstall with --direct)",
        ));
    }
    let host = public_host.trim().to_ascii_lowercase();
    if !valid_public_host(&host) || b.public_port == 0 {
        return Err(ApiError::bad_request("invalid_public_address")
            .detail("enter an IP address or DNS name and a port"));
    }
    let c = ctx.clone();
    let actor = p.id.clone();
    let h = host.clone();
    let updated = blocking(move || {
        let mut conn = connection(&c)?;
        if conn.mode.as_deref().is_some_and(|m| m != "direct") {
            return Err(ApiError::conflict("integration_controls_address").detail(
                "a Cloudflare or public-certificate integration manages the device address; disable it first",
            ));
        }
        conn = Connection {
            mode: Some("direct".into()),
            public_host: Some(h.clone()),
            public_port: Some(b.public_port),
            outer_trust: Some("pinned".into()),
            inner_server_name: conn.inner_server_name,
        };
        let value = serde_json::to_value(&conn).map_err(|_| ApiError::unavailable())?;
        c.coord.store().tx(|tx| {
            db::put_setting(tx, "connection", &value)?;
            db::append_audit(
                tx,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: "system.connection_updated",
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        })?;
        Ok(conn)
    })
    .await?;
    if let Some(a) = ctx.appliance() {
        let (names, ips): (Vec<String>, Vec<std::net::IpAddr>) =
            match host.parse::<std::net::IpAddr>() {
                Ok(ip) => (vec![], vec![ip]),
                Err(_) => (vec![host.clone()], vec![]),
            };
        let a2 = a.clone();
        blocking(move || {
            a2.set_public_addresses(&names, &ips)
                .map_err(|_| ApiError::conflict("certificate_reissue_failed"))
        })
        .await?;
    }
    Ok(json(StatusCode::OK, &json!({"connection": updated}), &[]))
}

/// With Cloudflare Tunnel the hostname belongs to the integration; only the
/// port devices use can change, among the ports Cloudflare proxies.
async fn put_cloudflare_port(ctx: &Ctx, actor: &str, port: u16) -> ApiResult {
    if !crate::portal::CLOUDFLARE_HTTPS_PORTS.contains(&port) {
        return Err(ApiError::bad_request("invalid_public_port").detail(format!(
            "through Cloudflare Tunnel devices can use Cloudflare's HTTPS ports only: {}",
            crate::portal::CLOUDFLARE_HTTPS_PORTS
                .map(|p| p.to_string())
                .join(", ")
        )));
    }
    let (c, actor) = (ctx.clone(), actor.to_owned());
    let updated = blocking(move || {
        let mut conn = connection(&c)?;
        conn.public_port = Some(port);
        let value = serde_json::to_value(&conn).map_err(|_| ApiError::unavailable())?;
        c.coord.store().tx(|tx| {
            db::put_setting(tx, "connection", &value)?;
            db::append_audit(
                tx,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: "system.connection_updated",
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"public_port": port}),
                },
            )
        })?;
        Ok(conn)
    })
    .await?;
    Ok(json(StatusCode::OK, &json!({"connection": updated}), &[]))
}

/// The local web CA certificate (public), so browsers and clients can trust
/// the console and edge without warnings.
pub async fn web_ca(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    if p.password_change_required() {
        return Err(ApiError::forbidden().detail("password change required"));
    }
    let pem = aegis_config::secret::read(&ctx.secrets_dir, "secret://web-ca.pem")
        .map_err(|_| ApiError::not_found())?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"aegisborne-web-ca.pem\"",
            ),
        ],
        pem,
    )
        .into_response())
}

pub async fn integrations(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::ProvisionRead)?;
    let status = ctx.appliance().map(|a| a.status()).unwrap_or(Value::Null);
    Ok(json(
        StatusCode::OK,
        &json!({
            "appliance": !status.is_null(),
            "integrations": status.get("integrations").cloned().unwrap_or(json!([])),
            "third_party_plugins": "Every integration is built in and reviewed. Third-party plugins are not supported, so no external code ever runs inside the gateway.",
        }),
        &[],
    ))
}

pub async fn integration_action(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path((id, action)): Path<(String, String)>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProviderConfigure)?;
    if !id.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        || !action.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        || id.len() > 32
        || action.len() > 32
    {
        return Err(ApiError::not_found());
    }
    let v = read_json(&headers, body, &["application/json"]).await?;
    let appliance = ctx
        .appliance()
        .ok_or_else(|| ApiError::conflict("appliance_mode_required"))?;
    match appliance.integration(&id, &action, &p.id, v).await {
        Ok(v) => Ok(json(StatusCode::OK, &v, &[])),
        Err((status, code)) => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
            Err(ApiError::new(status, "integration_failed").detail(code))
        }
    }
}

/// Configure the user portal: `{"enabled": bool}` switches it on or off,
/// `{"public_port": port|null}` sets (or clears) the port in its address.
/// Either or both; the other stays as it was.
pub async fn put_portal(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PUT)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let on = match v.get("enabled") {
        None => None,
        Some(e) => Some(e.as_bool().ok_or_else(|| {
            ApiError::bad_request("invalid_body").detail("enabled must be true or false")
        })?),
    };
    // Outer None: unchanged; Some(None): cleared.
    let port = match v.get("public_port") {
        None => None,
        Some(Value::Null) => Some(None),
        Some(n) => {
            let port = n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n != 0)
                .ok_or_else(|| {
                    ApiError::bad_request("invalid_body")
                        .detail("public_port must be a port number (1-65535)")
                })?;
            if let Some(why) = crate::portal::port_problem(&ctx, port) {
                return Err(ApiError::bad_request("invalid_portal_port").detail(why));
            }
            Some(Some(port))
        }
    };
    if on.is_none() && port.is_none() {
        return Err(ApiError::bad_request("invalid_body").detail("set enabled or public_port"));
    }
    let mut setting = crate::portal::setting(&ctx);
    if !setting.is_object() {
        setting = json!({});
    }
    if let Some(on) = on {
        setting["enabled"] = json!(on);
    }
    if let Some(port) = port {
        setting["public_port"] = json!(port);
    }
    let (c, actor) = (ctx.clone(), p.id.clone());
    blocking(move || {
        c.coord.store().tx(|tx| {
            db::put_setting(tx, "portal", &setting)?;
            let audit = |action, metadata| AuditInsert {
                actor_id: Some(&actor),
                action,
                target_type: "system",
                target_id: None,
                decision: "allowed",
                revision_digest: None,
                metadata,
            };
            if let Some(on) = on {
                let action = if on {
                    "portal.enabled"
                } else {
                    "portal.disabled"
                };
                db::append_audit(tx, audit(action, json!({})))?;
            }
            if let Some(port) = port {
                db::append_audit(
                    tx,
                    audit("portal.public_port", json!({"public_port": port})),
                )?;
            }
            Ok(())
        })?;
        Ok(())
    })
    .await?;
    Ok(json(StatusCode::OK, &crate::portal::status_json(&ctx), &[]))
}

/// Configure direct QUIC: `{"enabled": bool, "host": name|null, "port":
/// port|null}`, any of them; the rest stays. Devices learn the address the
/// next time they connect (they fetch their endpoint) and fall back to the
/// usual address when QUIC can't reach the server.
pub async fn put_quic(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PUT)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let obj = v
        .as_object()
        .filter(|o| {
            !o.is_empty()
                && o.keys()
                    .all(|k| ["enabled", "host", "port"].contains(&k.as_str()))
        })
        .ok_or_else(|| ApiError::bad_request("invalid_body").detail("set enabled, host or port"))?;
    let mut setting = super::devices::quic_setting(&ctx);
    if let Some(e) = obj.get("enabled") {
        let on = e.as_bool().ok_or_else(|| {
            ApiError::bad_request("invalid_body").detail("enabled must be true or false")
        })?;
        setting["enabled"] = json!(on);
    }
    match obj.get("host") {
        None => {}
        Some(Value::Null) => setting["host"] = Value::Null,
        Some(h) => {
            let h = h.as_str().map(str::trim).unwrap_or("").to_ascii_lowercase();
            if !super::devices::valid_public_host(&h) {
                return Err(ApiError::bad_request("invalid_host")
                    .detail("enter the server's public IP address or DNS name"));
            }
            setting["host"] = json!(h);
        }
    }
    match obj.get("port") {
        None => {}
        Some(Value::Null) => setting["port"] = Value::Null,
        Some(n) => {
            let port = n
                .as_u64()
                .and_then(|n| u16::try_from(n).ok())
                .filter(|n| *n != 0)
                .ok_or_else(|| {
                    ApiError::bad_request("invalid_body").detail("port must be 1-65535")
                })?;
            setting["port"] = json!(port);
        }
    }
    let (c, actor, audit_meta) = (ctx.clone(), p.id.clone(), setting.clone());
    blocking(move || {
        c.coord.store().tx(|tx| {
            db::put_setting(tx, "quic", &setting)?;
            db::append_audit(
                tx,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: "quic.updated",
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: audit_meta,
                },
            )
        })?;
        Ok(())
    })
    .await?;
    Ok(json(
        StatusCode::OK,
        &super::devices::quic_status_json(&ctx),
        &[],
    ))
}

/// The updater counts as present while its heartbeat is this fresh.
const UPDATER_STALE_SECS: u64 = 120;

/// Version and upgrades as the console shows them: this gateway's version,
/// what the updater container last found, and the automatic setting.
fn updates_json(ctx: &crate::ManagementContext) -> Value {
    let Some(data) = ctx.data_dir() else {
        return json!({"running": env!("CARGO_PKG_VERSION"), "updater": false});
    };
    let status = aegis_updater::files::status(&data).unwrap_or(Value::Null);
    let fresh = status["heartbeat"]
        .as_u64()
        .is_some_and(|t| db::now_unix().max(0) as u64 <= t + UPDATER_STALE_SECS);
    json!({
        "running": env!("CARGO_PKG_VERSION"),
        "updater": fresh,
        "source": status["source"],
        "available": status["available"],
        "checked_at": status["checked_at"],
        "state": status["state"],
        "message": status["message"],
        "finished_at": status["finished_at"],
        "auto": aegis_updater::files::auto(&data),
    })
}

/// `GET /api/v1/system/updates`.
pub async fn updates(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::SystemConfigure)?;
    Ok(json(StatusCode::OK, &updates_json(&ctx), &[]))
}

/// `POST /api/v1/system/updates`: `{"action": "check"}`, `{"action":
/// "upgrade", "version": "X.Y.Z"}` (or no version: the newest available),
/// or `{"auto": bool}`. Requests go to the updater container through the
/// data volume; the gateway itself never touches Docker.
pub async fn post_updates(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    use aegis_updater::files::{self, Request};
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let data = ctx
        .data_dir()
        .ok_or_else(|| ApiError::conflict("not_an_appliance"))?;
    let (action, metadata) = if let Some(on) = v.get("auto") {
        let on = on.as_bool().ok_or_else(|| {
            ApiError::bad_request("invalid_body").detail("auto must be true or false")
        })?;
        files::set_auto(&data, on).map_err(|_| ApiError::unavailable())?;
        ("system.auto_upgrade", json!({ "auto": on }))
    } else {
        if updates_json(&ctx)["updater"] != json!(true) {
            return Err(ApiError::conflict("updater_missing").detail(
                "the updater isn't running on this server: upgrade once with the newest install.sh, which sets it up",
            ));
        }
        let request = match v["action"].as_str() {
            Some("check") => Request::Check,
            Some("upgrade") => match &v["version"] {
                Value::Null => Request::Upgrade(None),
                Value::String(s) => Request::Upgrade(Some(
                    aegis_updater::version::Version::parse(s).ok_or_else(|| {
                        ApiError::bad_request("invalid_version")
                            .detail("version must look like 1.2.3")
                    })?,
                )),
                _ => return Err(ApiError::bad_request("invalid_version")),
            },
            _ => {
                return Err(ApiError::bad_request("invalid_body")
                    .detail("set action (check or upgrade) or auto"))
            }
        };
        files::write_request(&data, &request).map_err(|_| ApiError::unavailable())?;
        let action = match request {
            Request::Check => "system.update_check",
            Request::Upgrade(_) => "system.upgrade_requested",
        };
        (action, json!({ "version": v["version"] }))
    };
    let (c, actor) = (ctx.clone(), p.id.clone());
    blocking(move || {
        c.coord.store().tx(|tx| {
            db::append_audit(
                tx,
                AuditInsert {
                    actor_id: Some(&actor),
                    action,
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata,
                },
            )
        })?;
        Ok(())
    })
    .await?;
    Ok(json(StatusCode::ACCEPTED, &updates_json(&ctx), &[]))
}

/// Device CA custody: take the root key offline, renew the issuer with it,
/// or put it back (owner only). Exporting the key needs the password again.
pub async fn device_ca(
    State(ctx): State<Ctx>,
    portal: Option<axum::Extension<crate::portal::PortalRequest>>,
    headers: HeaderMap,
    Path(action): Path<String>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::SystemConfigure)?;
    if !matches!(
        action.as_str(),
        "export-root-key" | "remove-root-key" | "restore-root-key" | "renew-issuer"
    ) {
        return Err(ApiError::not_found());
    }
    // The root key never leaves through the public address, however the
    // path was spelled (the portal guard sees it still percent-encoded).
    if portal.is_some() && action == "export-root-key" {
        return Err(ApiError::not_found());
    }
    let v = read_json(&headers, body, &["application/json"]).await?;
    let appliance = ctx
        .appliance()
        .ok_or_else(|| ApiError::conflict("appliance_mode_required"))?;
    let (c, actor) = (ctx.clone(), p.id.clone());
    let export = action == "export-root-key";
    let portal = portal.is_some();
    let out = blocking(move || {
        if export {
            let password = v.get("password").and_then(Value::as_str).unwrap_or("");
            c.confirm_password(&actor, password, portal)?;
        }
        appliance
            .device_ca(&action, &actor, v)
            .map_err(|(status, detail)| {
                let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST);
                ApiError::new(status, "device_ca_failed").detail(detail)
            })
    })
    .await?;
    if export {
        let pem = out["key_pem"].as_str().unwrap_or("").to_owned();
        return Ok((
            [
                (header::CONTENT_TYPE, "application/x-pem-file"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"aegisborne-device-root-key.pem\"",
                ),
                (header::CACHE_CONTROL, "no-store"),
            ],
            pem,
        )
            .into_response());
    }
    Ok(json(StatusCode::OK, &out, &[]))
}

const MAX_DOWNLOAD_BYTES: u64 = 200 * 1024 * 1024;

fn download_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn download_label(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    if n.starts_with("aegisnet-update") {
        // The last update of the old Android app: it moves a phone's
        // servers to AegisBorne.
        return "AegisNet update for Android (moves an AegisNet phone to AegisBorne)".into();
    }
    let os = if n.contains("android") || n.ends_with(".apk") {
        "Android"
    } else if n.contains("windows") || n.ends_with(".exe") {
        "Windows"
    } else if n.contains("macos") || n.contains("darwin") {
        "macOS"
    } else if n.contains("linux") {
        "Linux"
    } else {
        return name.to_owned();
    };
    let arch = if n.contains("arm64") || n.contains("aarch64") {
        " (ARM64)"
    } else if n.contains("x86_64") || n.contains("x64") || n.contains("amd64") {
        " (x64)"
    } else {
        ""
    };
    format!("AegisBorne client for {os}{arch}")
}

fn downloads_dir(ctx: &crate::ManagementContext) -> Option<std::path::PathBuf> {
    ctx.downloads_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Client builds offered for download (empty when none are bundled).
pub async fn downloads(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    if p.password_change_required() {
        return Err(ApiError::forbidden().detail("password change required"));
    }
    let c = ctx.clone();
    let items = blocking(move || {
        let Some(dir) = downloads_dir(&c) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            // FILE.update: the signed description of an app update (ADR-0017).
            if !download_name_ok(&name)
                || name.ends_with(".update")
                || !meta.is_file()
                || meta.len() > MAX_DOWNLOAD_BYTES
            {
                continue;
            }
            let cached = c
                .download_digests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&name)
                .filter(|(size, _)| *size == meta.len())
                .map(|(_, d)| d.clone());
            let digest = match cached {
                Some(d) => d,
                None => {
                    let Ok(d) = file_sha256(&entry.path()) else {
                        continue;
                    };
                    c.download_digests
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(name.clone(), (meta.len(), d.clone()));
                    d
                }
            };
            out.push(json!({
                "name": name,
                "label": download_label(&name),
                "size": meta.len(),
                "sha256": digest,
            }));
        }
        out.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        Ok(out)
    })
    .await?;
    Ok(json(StatusCode::OK, &json!({ "items": items }), &[]))
}

pub async fn download_file(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    if p.password_change_required() || !download_name_ok(&name) {
        return Err(ApiError::not_found());
    }
    let dir = downloads_dir(&ctx).ok_or_else(ApiError::not_found)?;
    let path = dir.join(&name);
    let meta = tokio::fs::symlink_metadata(&path)
        .await
        .map_err(|_| ApiError::not_found())?;
    if !meta.is_file() || meta.len() > MAX_DOWNLOAD_BYTES {
        return Err(ApiError::not_found());
    }
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError::not_found())?;
    let len = file
        .metadata()
        .await
        .map_err(|_| ApiError::not_found())?
        .len();
    if len > MAX_DOWNLOAD_BYTES {
        return Err(ApiError::not_found());
    }
    let disposition = format!("attachment; filename=\"{name}\"");
    // Streamed from disk: a download holds one chunk, not the whole file.
    let mut resp = axum::response::Response::new(axum::body::Body::new(FileBody::new(file, len)));
    let h = resp.headers_mut();
    // Phones offer to install an APK only with its own media type.
    let content_type = if name.ends_with(".apk") {
        "application/vnd.android.package-archive"
    } else {
        "application/octet-stream"
    };
    h.insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static(content_type),
    );
    if let Ok(v) = http::HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// SHA-256 of a file, read in chunks.
fn file_sha256(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::Digest;
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; FILE_CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }
        hasher.update(&buf[..n]);
    }
}

const FILE_CHUNK: usize = 64 * 1024;

/// A response body read from a file of known length, one chunk at a time.
struct FileBody {
    file: tokio::fs::File,
    remaining: u64,
    buf: Box<[u8]>,
}

impl FileBody {
    fn new(file: tokio::fs::File, len: u64) -> Self {
        FileBody {
            file,
            remaining: len,
            buf: vec![0u8; FILE_CHUNK].into_boxed_slice(),
        }
    }
}

impl hyper::body::Body for FileBody {
    type Data = axum::body::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        use tokio::io::AsyncRead;
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(None);
        }
        let want = this
            .buf
            .len()
            .min(usize::try_from(this.remaining).unwrap_or(usize::MAX));
        let mut rb = tokio::io::ReadBuf::new(&mut this.buf[..want]);
        match std::pin::Pin::new(&mut this.file).poll_read(cx, &mut rb) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    // The file shrank under us: end with an error, not a
                    // short body that looks complete.
                    return Poll::Ready(Some(Err(std::io::ErrorKind::UnexpectedEof.into())));
                }
                this.remaining -= n as u64;
                let data = axum::body::Bytes::copy_from_slice(rb.filled());
                Poll::Ready(Some(Ok(hyper::body::Frame::data(data))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(self.remaining)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn downloads_stream_in_chunks_and_hash_incrementally() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("aegis-client-linux-x86_64");
        let data: Vec<u8> = (0..(3 * FILE_CHUNK + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&path, &data).expect("write");
        assert_eq!(file_sha256(&path).expect("hash"), db::sha256_hex(&data));
        let file = tokio::fs::File::open(&path).await.expect("open");
        let mut body = FileBody::new(file, data.len() as u64);
        assert_eq!(
            hyper::body::Body::size_hint(&body).exact(),
            Some(data.len() as u64)
        );
        let mut got = Vec::new();
        let mut frames = 0;
        while let Some(frame) = std::future::poll_fn(|cx| {
            hyper::body::Body::poll_frame(std::pin::Pin::new(&mut body), cx)
        })
        .await
        {
            let chunk = frame.expect("frame").into_data().expect("data");
            assert!(chunk.len() <= FILE_CHUNK);
            got.extend_from_slice(&chunk);
            frames += 1;
        }
        assert_eq!(got, data);
        assert_eq!(frames, 4);
    }

    #[test]
    fn download_labels() {
        assert_eq!(
            download_label("aegis-client-android-arm64.apk"),
            "AegisBorne client for Android (ARM64)"
        );
        assert_eq!(
            download_label("aegis-client-windows-x86_64.exe"),
            "AegisBorne client for Windows (x64)"
        );
        assert!(download_label("aegisnet-update-android-arm64.apk").starts_with("AegisNet update"));
        assert_eq!(download_label("notes.txt"), "notes.txt");
        assert!(download_name_ok("aegis-client-android-arm64.apk"));
    }
}
