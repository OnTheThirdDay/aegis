//! Telemetry settings: export is off by default and requires
//! `telemetry:configure`, If-Match, a valid endpoint/service name and an
//! acknowledged preview of the exact serialized payload shape.

use super::{blocking, Ctx};
use crate::auth::Permission;
use crate::http_util::{if_match, json, read_json, ApiError, ApiResult};
use crate::ManagementContext;
use aegis_config::secret;
use aegis_storage::{self as db, AuditInsert};
use aegis_telemetry::export::preview as build_preview;
use aegis_telemetry::{CoarseExporter, TelemetrySettings};
use axum::body::Body;
use axum::extract::{Query, State};
use http::{header, HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

pub const EXPORT_INTERVAL: Duration = Duration::from_secs(60);

fn etag(gen: i64) -> String {
    format!("\"t{gen}\"")
}

fn load(ctx: &ManagementContext) -> Result<(i64, TelemetrySettings), ApiError> {
    match ctx.coord.store().read(db::get_telemetry_settings)? {
        Some((g, j)) => Ok((
            g,
            serde_json::from_str(&j).map_err(|_| ApiError::unavailable())?,
        )),
        None => Ok((0, TelemetrySettings::default())),
    }
}

/// Start or stop the exporter to match settings. Credentials are read from
/// their secret reference at this point only.
fn apply(ctx: &ManagementContext, s: &TelemetrySettings) {
    let mut slot = ctx.exporter.lock().unwrap_or_else(|e| e.into_inner());
    *slot = None;
    if !s.export_enabled || s.validate().is_err() {
        return;
    }
    let (Some(url), Some(name)) = (s.collector_url.clone(), s.service_name.clone()) else {
        return;
    };
    let credential = s
        .credential_ref
        .as_ref()
        .and_then(|r| secret::read(&ctx.secrets_dir, r).ok());
    let gauges = Arc::clone(&ctx.gauges);
    if let Ok(e) = CoarseExporter::spawn(
        url,
        name,
        credential,
        Arc::clone(&ctx.metrics),
        gauges,
        EXPORT_INTERVAL,
    ) {
        *slot = Some(e);
    }
}

pub fn apply_persisted(ctx: &ManagementContext) {
    if let Ok((_, s)) = load(ctx) {
        if tokio::runtime::Handle::try_current().is_ok() {
            apply(ctx, &s);
        }
    }
}

pub async fn get_settings(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::TelemetryConfigure)?;
    let (g, s) = load(&ctx)?;
    Ok(json(StatusCode::OK, &s, &[(header::ETAG, etag(g))]))
}

pub async fn patch_settings(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PATCH)?;
    p.require(Permission::TelemetryConfigure)?;
    let tag = if_match(&headers)?;
    let patch = read_json(
        &headers,
        body,
        &["application/merge-patch+json", "application/json"],
    )
    .await?;
    let (g, current) = load(&ctx)?;
    if tag != etag(g) {
        return Err(ApiError::precondition_failed());
    }
    let next = current
        .apply_patch(&patch)
        .map_err(|e| ApiError::unprocessable(&[e.to_string()]))?;
    // Enabling (or redirecting) export requires acknowledging the preview of
    // exactly what will be sent.
    let export_changed = next.export_enabled
        && (!current.export_enabled
            || current.collector_url != next.collector_url
            || current.service_name != next.service_name);
    if export_changed {
        let name = next.service_name.clone().unwrap_or_default();
        let (_, digest) = build_preview(&name, &ctx.metrics, (ctx.gauges)())
            .map_err(|e| ApiError::unprocessable(&[e]))?;
        let ack = headers
            .get("x-aegis-export-preview-digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if ack != digest {
            return Err(ApiError::conflict("preview_required").detail(
                "GET /api/v1/telemetry/preview, review the payload, and resend with X-Aegis-Export-Preview-Digest",
            ));
        }
    }
    let actor = p.id.clone();
    let json_s = serde_json::to_string(&next).map_err(|_| ApiError::unavailable())?;
    let c = ctx.clone();
    let exported = next.export_enabled;
    let gen = blocking(move || {
        c.coord
            .store()
            .tx(|c| {
                let gen = db::put_telemetry_settings(c, g, &json_s, Some(&actor))?;
                db::append_audit(
                    c,
                    AuditInsert {
                        actor_id: Some(&actor),
                        action: "telemetry.settings_changed",
                        target_type: "telemetry",
                        target_id: None,
                        decision: "allowed",
                        revision_digest: None,
                        metadata: json!({"export_enabled": exported}),
                    },
                )?;
                Ok(gen)
            })
            .map_err(|e| match e {
                db::StoreError::Conflict(_) => ApiError::precondition_failed(),
                other => ApiError::from(other),
            })
    })
    .await?;
    apply(&ctx, &next);
    Ok(json(StatusCode::OK, &next, &[(header::ETAG, etag(gen))]))
}

#[derive(Deserialize)]
pub struct PreviewQuery {
    service_name: String,
}

/// The complete serialized OTLP payload that would be exported now, and the
/// digest of its shape that must be acknowledged to enable export.
pub async fn preview(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<PreviewQuery>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::TelemetryConfigure)?;
    let (payload, digest) = build_preview(&q.service_name, &ctx.metrics, (ctx.gauges)())
        .map_err(|e| ApiError::unprocessable(&[e]))?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "payload": payload,
            "preview_digest": digest,
            "warning": "Exported counts and timing can still reveal service characteristics; collectors are not trusted to redact.",
        }),
        &[],
    ))
}
