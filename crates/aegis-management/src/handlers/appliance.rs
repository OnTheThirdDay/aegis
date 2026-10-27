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
    public_host: String,
    public_port: u16,
}

/// Set the address devices use to reach this server in direct mode.
pub async fn put_connection(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PUT)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ConnectionBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if ctx.tunnel_only() {
        return Err(ApiError::conflict("tunnel_only").detail(
            "this gateway was installed with --tunnel-only, so its device port is not reachable from the network; use Cloudflare Tunnel (or reinstall with --direct)",
        ));
    }
    let host = b.public_host.trim().to_ascii_lowercase();
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
                "attachment; filename=\"aegisnet-web-ca.pem\"",
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

/// Switch the user portal on or off (`{"enabled": bool}`).
pub async fn put_portal(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PUT)?;
    p.require(Permission::SystemConfigure)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let on = v
        .get("enabled")
        .and_then(Value::as_bool)
        .ok_or_else(|| ApiError::bad_request("invalid_body"))?;
    let (c, actor) = (ctx.clone(), p.id.clone());
    blocking(move || {
        c.coord.store().tx(|tx| {
            db::put_setting(tx, "portal", &json!({"enabled": on}))?;
            db::append_audit(
                tx,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: if on {
                        "portal.enabled"
                    } else {
                        "portal.disabled"
                    },
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        })?;
        Ok(())
    })
    .await?;
    Ok(json(StatusCode::OK, &crate::portal::status_json(&ctx), &[]))
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
                    "attachment; filename=\"aegisnet-device-root-key.pem\"",
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
    format!("AegisNet client for {os}{arch}")
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
            if !download_name_ok(&name) || !meta.is_file() || meta.len() > MAX_DOWNLOAD_BYTES {
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
                    let Ok(bytes) = std::fs::read(entry.path()) else {
                        continue;
                    };
                    let d = db::sha256_hex(&bytes);
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
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| ApiError::not_found())?;
    let disposition = format!("attachment; filename=\"{name}\"");
    let mut resp = axum::response::Response::new(axum::body::Body::from(bytes));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_labels() {
        assert_eq!(
            download_label("aegis-client-android-arm64.apk"),
            "AegisNet client for Android (ARM64)"
        );
        assert_eq!(
            download_label("aegis-client-windows-x86_64.exe"),
            "AegisNet client for Windows (x64)"
        );
        assert_eq!(download_label("notes.txt"), "notes.txt");
        assert!(download_name_ok("aegis-client-android-arm64.apk"));
    }
}
