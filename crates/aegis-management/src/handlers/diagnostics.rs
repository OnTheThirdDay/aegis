//! On-demand diagnostics (ADR-0008): start and stop the gateway's
//! recording, collect device reports, export everything as OTLP/JSON logs
//! and explain what went wrong.
//!
//! Nothing records until an administrator starts it; recording stops by
//! itself after at most an hour and everything is held in memory only
//! (capped), then dropped. Devices can send their own report while the
//! gateway's diagnostics are on.

use super::edge::{authenticate_device, device_trust_anchor};
use super::{blocking, Ctx};
use crate::auth::{Permission, Principal};
use crate::http_util::{json, read_json, ApiError, ApiResult};
use crate::ManagementContext;
use aegis_storage::{self as db, AuditInsert};
use aegis_telemetry::analyze::analyze;
use aegis_telemetry::diagnostic::{MAX_BYTES, MAX_DURATION, RETAIN_AFTER};
use aegis_telemetry::report::{self, Report, Role};
use axum::body::Body;
use axum::extract::State;
use axum::response::IntoResponse;
use base64::Engine;
use http::{header, HeaderMap, Method, StatusCode};
use serde_json::{json, Value};
use std::time::Duration;

/// Largest report file the console imports.
const MAX_IMPORT: usize = 16 * 1024 * 1024;
/// Largest compressed report a device uploads (fits the edge body limit
/// after base64).
pub const MAX_UPLOAD_GZ: usize = 1024 * 1024;
/// Allowed clock difference for a device's signature time.
const SIGNATURE_SKEW: i64 = 600;

fn gateway_report(ctx: &ManagementContext) -> Option<Report> {
    ctx.diagnostics.recording().map(|recording| Report {
        role: Role::Gateway,
        name: "gateway".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        recording,
    })
}

fn device_reports(ctx: &ManagementContext) -> Vec<Report> {
    ctx.device_reports
        .list()
        .into_iter()
        .map(|h| h.report)
        .collect()
}

async fn audit(
    ctx: &Ctx,
    p: &Principal,
    action: &'static str,
    metadata: Value,
) -> Result<(), ApiError> {
    let c = ctx.clone();
    let actor = p.id.clone();
    blocking(move || {
        c.coord.store().tx(|conn| {
            db::append_audit(
                conn,
                AuditInsert {
                    actor_id: Some(&actor),
                    action,
                    target_type: "diagnostics",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata,
                },
            )
        })?;
        Ok(())
    })
    .await
}

fn status_json(ctx: &ManagementContext) -> Value {
    let devices: Vec<Value> = ctx
        .device_reports
        .list()
        .iter()
        .map(|h| {
            json!({
                "name": h.report.name,
                "version": h.report.version,
                "received_unix": h.received_unix_ms / 1000,
                "started_unix": h.report.recording.started_unix_ms / 1000,
                "ended_unix": h.report.recording.ended_unix_ms / 1000,
                "events": h.report.recording.records.len(),
                "dropped": h.report.recording.dropped,
            })
        })
        .collect();
    json!({
        "gateway": ctx.diagnostics.status(),
        "devices": devices,
        "limits": {
            "max_minutes": MAX_DURATION.as_secs() / 60,
            "retain_minutes": RETAIN_AFTER.as_secs() / 60,
            "max_bytes": MAX_BYTES,
        },
    })
}

pub async fn status(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::DiagnosticsExplain)?;
    Ok(json(StatusCode::OK, &status_json(&ctx), &[]))
}

pub async fn start(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DiagnosticsExplain)?;
    let b = read_json(&headers, body, &["application/json"]).await?;
    let max = MAX_DURATION.as_secs() / 60;
    let minutes = b
        .get("minutes")
        .and_then(Value::as_u64)
        .filter(|m| (1..=max).contains(m))
        .ok_or_else(|| {
            ApiError::bad_request("invalid_minutes").detail(format!("minutes must be 1..={max}"))
        })?;
    ctx.diagnostics
        .start(Duration::from_secs(minutes * 60))
        .map_err(|e| ApiError::bad_request("invalid_minutes").detail(e))?;
    // Reports from an earlier recording would not line up with this one.
    ctx.device_reports.clear();
    audit(&ctx, &p, "diagnostics.started", json!({"minutes": minutes})).await?;
    Ok(json(StatusCode::OK, &status_json(&ctx), &[]))
}

pub async fn stop(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DiagnosticsExplain)?;
    ctx.diagnostics.stop();
    audit(&ctx, &p, "diagnostics.stopped", json!({})).await?;
    Ok(json(StatusCode::OK, &status_json(&ctx), &[]))
}

pub async fn discard(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DiagnosticsExplain)?;
    ctx.diagnostics.discard();
    ctx.device_reports.clear();
    audit(&ctx, &p, "diagnostics.discarded", json!({})).await?;
    Ok(json(StatusCode::OK, &status_json(&ctx), &[]))
}

pub async fn analysis(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::DiagnosticsExplain)?;
    let gateway = gateway_report(&ctx);
    let devices = device_reports(&ctx);
    Ok(json(
        StatusCode::OK,
        &analyze(gateway.as_ref(), &devices),
        &[],
    ))
}

/// Everything held, as one OTLP/JSON logs document.
pub async fn otlp(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::DiagnosticsExplain)?;
    let mut all: Vec<Report> = gateway_report(&ctx).into_iter().collect();
    all.extend(device_reports(&ctx));
    if all.is_empty() {
        return Err(ApiError::not_found().detail("nothing has been recorded"));
    }
    let body = report::to_otlp(&all).to_string();
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"aegisnet-diagnostics.otlp.json\"",
            ),
        ],
        body,
    )
        .into_response())
}

/// Import a report file a device saved (plain or gzipped OTLP/JSON), for
/// devices that could not reach the gateway to send it.
pub async fn import(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DiagnosticsExplain)?;
    let bytes = axum::body::to_bytes(body, MAX_IMPORT)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))?;
    let reports = tokio::task::spawn_blocking(move || {
        if bytes.starts_with(&[0x1f, 0x8b]) {
            Report::from_gzip(&bytes)
        } else {
            serde_json::from_slice::<Value>(&bytes)
                .map_err(|_| "the file is not JSON")
                .and_then(|doc| Report::from_otlp(&doc))
        }
    })
    .await
    .map_err(|_| ApiError::unavailable())?
    .map_err(|e| ApiError::bad_request("invalid_report").detail(e))?;
    let mut names = Vec::new();
    for r in reports.into_iter().filter(|r| r.role == Role::Client) {
        names.push(r.name.clone());
        ctx.device_reports.put(r);
    }
    if names.is_empty() {
        return Err(
            ApiError::bad_request("invalid_report").detail("the file holds no device report")
        );
    }
    audit(
        &ctx,
        &p,
        "diagnostics.imported",
        json!({"devices": names.len()}),
    )
    .await?;
    Ok(json(StatusCode::OK, &status_json(&ctx), &[]))
}

/// A device's signed report, from the public edge (`POST /renew` with
/// `diagnostic_report_gz`).
pub(crate) async fn device_report(ctx: &Ctx, body: Value) -> Result<Value, ApiError> {
    let permit = ctx.auth.enrollment_permit()?;
    if ctx.diagnostics.status().state == "off" {
        return Err(ApiError::conflict("diagnostics_not_enabled").detail(
            "diagnostics are off on the server; ask the administrator to start them, then send again",
        ));
    }
    let field = |k: &str| body.get(k).and_then(Value::as_str).unwrap_or("");
    let b64 = base64::engine::general_purpose::STANDARD;
    let certificate_pem = field("certificate_pem").to_owned();
    let gz = b64
        .decode(field("diagnostic_report_gz"))
        .map_err(|_| ApiError::bad_request("invalid_body"))?;
    let signature = b64
        .decode(field("signature"))
        .map_err(|_| ApiError::bad_request("invalid_body"))?;
    let signed_at = body
        .get("signed_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| ApiError::bad_request("invalid_body"))?;
    if certificate_pem.len() > 16 * 1024 || gz.len() > MAX_UPLOAD_GZ || signature.len() > 512 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    if (signed_at - db::now_unix()).abs() > SIGNATURE_SKEW {
        return Err(ApiError::unauthenticated()
            .detail("the device clock is more than 10 minutes off; correct it and send again"));
    }
    let anchor = device_trust_anchor(ctx)?;
    let c = ctx.clone();
    let count = blocking(move || {
        let _permit = permit;
        let device = authenticate_device(&c, &anchor, &certificate_pem, 0)?;
        let message = aegis_identity::pki::diagnostic_upload_message(signed_at, &gz);
        if !aegis_identity::pki::verify_with_certificate(&device.der, &message, &signature) {
            return Err(ApiError::unauthenticated().detail("report signature invalid"));
        }
        let reports = Report::from_gzip(&gz)
            .map_err(|e| ApiError::bad_request("invalid_report").detail(e))?;
        let mut report = reports
            .into_iter()
            .find(|r| r.role == Role::Client)
            .ok_or_else(|| ApiError::bad_request("invalid_report"))?;
        // The registry, not the report, says who sent it.
        report.name = device.name;
        let count = report.recording.records.len();
        c.device_reports.put(report);
        Ok(count)
    })
    .await?;
    Ok(json!({"accepted": true, "records": count}))
}
