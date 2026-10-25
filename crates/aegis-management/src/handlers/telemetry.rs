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

fn revision_binding(ctx: &ManagementContext) -> serde_json::Value {
    let bundle = ctx.coord.gate().current();
    json!({"consent_schema":2,"profile_id":bundle.as_ref().map(|b|&b.profile_id),"revision_id":bundle.as_ref().map(|b|&b.revision_id),"config_digest":bundle.as_ref().map(|b|&b.digest)})
}
fn saved_binding(ctx: &ManagementContext) -> Option<serde_json::Value> {
    ctx.coord
        .store()
        .read(|c| {
            Ok(c.query_row(
                "SELECT consent_json FROM telemetry_settings WHERE id=1",
                [],
                |r| r.get::<_, Option<String>>(0),
            )?)
        })
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Consent covers the destination and complete versioned schema, independent
/// of changing sample values/timestamps. Actor, settings generation and active
/// configuration prevent replay across principals or revisions.
fn consent_digest(
    ctx: &ManagementContext,
    s: &TelemetrySettings,
    generation: i64,
    actor: &str,
) -> Result<String, ApiError> {
    let name = s
        .service_name
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("service_name_required"))?;
    let url = aegis_telemetry::settings::canonical_collector_url(
        s.collector_url
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("collector_url_required"))?,
    )
    .map_err(|e| ApiError::unprocessable(&[e]))?;
    let (_, shape) = build_preview(name, &ctx.metrics, (ctx.gauges)())
        .map_err(|e| ApiError::unprocessable(&[e]))?;
    let bundle = ctx.coord.gate().current();
    Ok(aegis_config::digest_value(&json!({
        "consent_schema": 2, "collector_url": url, "export_profile": s.export_profile,
        "credential_ref": s.credential_ref, "privacy_mode": s.privacy_mode,
        "resource_detection_mode": s.resource_detection_mode, "payload_schema_digest": shape,
        "settings_generation": generation, "actor_id": actor,
        "profile_id": bundle.as_ref().map(|b| &b.profile_id),
        "revision_id": bundle.as_ref().map(|b| &b.revision_id),
        "config_digest": bundle.as_ref().map(|b| &b.digest),
    })))
}

/// Start or stop the exporter to match settings. Credentials are read from
/// their secret reference at this point only.
fn apply(ctx: &ManagementContext, slot: &mut Option<CoarseExporter>, s: &TelemetrySettings) {
    *slot = None;
    if !s.export_enabled || s.validate().is_err() {
        return;
    }
    let Some(binding) = saved_binding(ctx).filter(|b| *b == revision_binding(ctx)) else {
        return;
    };
    let (Some(url), Some(name)) = (s.collector_url.clone(), s.service_name.clone()) else {
        return;
    };
    let credential = match &s.credential_ref {
        Some(r) => match secret::read(&ctx.secrets_dir, r) {
            Ok(c) => Some(c),
            Err(_) => return,
        },
        None => None,
    };
    let gauges = Arc::clone(&ctx.gauges);
    let gate = Arc::clone(ctx.coord.gate());
    let expected_revision = binding["revision_id"].as_str().map(str::to_owned);
    if let Ok(e) = CoarseExporter::spawn_guarded(
        url,
        name,
        credential,
        Arc::clone(&ctx.metrics),
        gauges,
        EXPORT_INTERVAL,
        Arc::new(move || gate.current_revision() == expected_revision),
    ) {
        *slot = Some(e);
    }
}

pub fn apply_persisted(ctx: &ManagementContext) {
    // Keep startup recovery in the same order as a settings commit: exporter
    // lock, then store. A stale startup snapshot must not replace newer state.
    let mut slot = ctx.exporter.lock().unwrap_or_else(|e| e.into_inner());
    if let Ok((_, s)) = load(ctx) {
        if tokio::runtime::Handle::try_current().is_ok() {
            apply(ctx, &mut slot, &s);
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
            || current.service_name != next.service_name
            || current.credential_ref != next.credential_ref
            || current.export_profile != next.export_profile
            || current.privacy_mode != next.privacy_mode
            || saved_binding(&ctx).as_ref() != Some(&revision_binding(&ctx)));
    if export_changed {
        let digest = consent_digest(&ctx, &next, g, &p.id)?;
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
    let apply_settings = next.clone();
    let consent = if next.export_enabled {
        Some(revision_binding(&ctx).to_string())
    } else {
        None
    };
    let gen = blocking(move || {
        // Serialize durable commits and runtime application as one operation.
        // This blocking job runs to completion even if the HTTP caller drops
        // its future; there is no post-await action that can publish old state.
        let mut slot = c.exporter.lock().unwrap_or_else(|e| e.into_inner());
        let gen = c
            .coord
            .store()
            .tx(|c| {
                let gen = db::put_telemetry_settings(c, g, &json_s, Some(&actor))?;
                c.execute(
                    "UPDATE telemetry_settings SET consent_json=?1 WHERE id=1",
                    [&consent],
                )?;
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
            })?;
        apply(&c, &mut slot, &apply_settings);
        Ok(gen)
    })
    .await?;
    Ok(json(StatusCode::OK, &next, &[(header::ETAG, etag(gen))]))
}

#[derive(Deserialize)]
pub struct PreviewQuery {
    service_name: String,
    collector_url: Option<String>,
    credential_ref: Option<String>,
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
    let (payload, _) = build_preview(&q.service_name, &ctx.metrics, (ctx.gauges)())
        .map_err(|e| ApiError::unprocessable(&[e]))?;
    let (generation, mut settings) = load(&ctx)?;
    settings.service_name = Some(q.service_name);
    settings.collector_url = q.collector_url.or(settings.collector_url);
    settings.credential_ref = q.credential_ref.or(settings.credential_ref);
    settings.export_profile = aegis_telemetry::settings::ExportProfile::CoarseExport;
    let digest = consent_digest(&ctx, &settings, generation, &p.id)?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "payload": payload,
            "preview_digest": digest,
            "consent_schema": 2,
            "collector_url": settings.collector_url,
            "warning": "Exported counts and timing can still reveal service characteristics; collectors are not trusted to redact.",
        }),
        &[],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{context, insert_owner};
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    #[tokio::test]
    async fn delayed_enable_response_cannot_restart_disabled_export() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let ctx = context(Arc::clone(&store));
        insert_owner(&store);
        let (token, _) = ctx
            .mint_bearer(None, Duration::from_secs(60))
            .expect("bearer");
        let approved = TelemetrySettings::default().apply_patch(&json!({"service_name":"network-runtime", "collector_url":"https://127.0.0.1:9/v1/metrics", "export_profile":"coarse_export"})).expect("settings");
        let digest = consent_digest(&ctx, &approved, 0, "test-owner").expect("preview");
        let headers = |generation| {
            let mut h = HeaderMap::new();
            h.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("token"),
            );
            h.insert(header::IF_MATCH, etag(generation).parse().expect("etag"));
            h.insert(
                header::CONTENT_TYPE,
                "application/json".parse().expect("type"),
            );
            h.insert(
                "x-aegis-export-preview-digest",
                digest.parse().expect("digest"),
            );
            h
        };
        let enable = json!({
            "export_enabled": true, "export_profile": "coarse_export",
            "collector_url": "https://127.0.0.1:9/v1/metrics", "service_name": "network-runtime"
        });
        let mut pending = Box::pin(patch_settings(
            State(Arc::clone(&ctx)),
            headers(0),
            Body::from(enable.to_string()),
        ));
        poll_fn(|cx| {
            // Force the blocking job to remain pending during this poll,
            // independent of how quickly the worker thread is scheduled.
            let _slot = ctx.exporter.lock().expect("exporter");
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        // Leave the first HTTP future unpolled after its blocking job commits.
        // A subsequent generation must remain authoritative even when that
        // older future resumes (or gets cancelled).
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if store
                    .read(db::get_telemetry_settings)
                    .expect("settings")
                    .is_some()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("enable commit");
        let disabled = patch_settings(
            State(Arc::clone(&ctx)),
            headers(1),
            Body::from(r#"{"export_enabled":false}"#),
        )
        .await
        .expect("disable");
        assert_eq!(disabled.status(), StatusCode::OK);
        assert!(ctx.exporter.lock().expect("exporter").is_none());
        assert_eq!(
            pending.await.expect("enable response").status(),
            StatusCode::OK
        );
        assert!(
            ctx.exporter.lock().expect("exporter").is_none(),
            "older request must never restore export"
        );
        let (generation, settings) = load(&ctx).expect("settings");
        assert_eq!(generation, 2);
        assert!(!settings.export_enabled);
        let restarted = context(Arc::clone(&store));
        assert!(restarted.exporter.lock().expect("exporter").is_none());
    }

    #[tokio::test]
    async fn cancelled_settings_request_still_applies_committed_state() {
        let store = Arc::new(db::Store::open_in_memory().expect("store"));
        let enabled = TelemetrySettings::default()
            .apply_patch(&json!({
                "export_enabled": true, "export_profile": "coarse_export",
                "collector_url": "https://127.0.0.1:9/v1/metrics", "service_name": "network-runtime"
            }))
            .expect("settings");
        store
            .tx(|c| {
                let generation=db::put_telemetry_settings(
                    c,
                    0,
                    &serde_json::to_string(&enabled).expect("json"),
                    None,
                )?;
                c.execute("UPDATE telemetry_settings SET consent_json=?1 WHERE id=1",[json!({"consent_schema":2,"profile_id":null,"revision_id":null,"config_digest":null}).to_string()])?;
                Ok(generation)
            })
            .expect("persist");
        let ctx = context(Arc::clone(&store));
        assert!(
            ctx.exporter.lock().expect("exporter").is_some(),
            "approved startup setting applied"
        );
        insert_owner(&store);
        let (token, _) = ctx
            .mint_bearer(None, Duration::from_secs(60))
            .expect("bearer");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("token"),
        );
        headers.insert(header::IF_MATCH, etag(1).parse().expect("etag"));
        headers.insert(
            header::CONTENT_TYPE,
            "application/json".parse().expect("type"),
        );
        let mut pending = Box::pin(patch_settings(
            State(Arc::clone(&ctx)),
            headers,
            Body::from(r#"{"export_enabled":false}"#),
        ));
        poll_fn(|cx| {
            let _slot = ctx.exporter.lock().expect("exporter");
            assert!(pending.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(pending);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ctx.exporter.lock().expect("exporter").is_none() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("committed disable applied after cancellation");
        let (generation, settings) = load(&ctx).expect("settings");
        assert_eq!(generation, 2);
        assert!(!settings.export_enabled);
        apply_persisted(&ctx);
        assert!(ctx.exporter.lock().expect("exporter").is_none());
    }
}
