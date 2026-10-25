use super::{blocking, next_cursor, Ctx, Page};
use crate::auth::Permission;
use crate::http_util::{json, ApiResult};
use aegis_core::rfc3339;
use aegis_storage as db;
use axum::extract::{Query, State};
use http::{HeaderMap, Method, StatusCode};
use serde_json::json;

pub async fn health(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    ctx.authenticate(&headers, &Method::GET)?;
    let c = ctx.clone();
    let h = blocking(move || Ok(c.coord.health())).await?;
    let status = match h.status.as_str() {
        "starting" => "starting",
        "ready" => "ready",
        "degraded" => "degraded",
        "draining" | "stopped" => "draining",
        _ => "unavailable",
    };
    Ok(json(
        StatusCode::OK,
        &json!({
            "status": status,
            "version": h.version,
            "admission_enabled": h.admission_enabled,
            "runtime_revision_id": h.runtime_revision_id,
            "applied_revision_id": h.applied_revision_id,
            "pending_operation_id": h.pending_operation_id,
            "updated_at": h.updated_at,
        }),
        &[],
    ))
}

/// Authenticated in-memory counters (`local_metrics_enabled`); not OTel.
pub async fn metrics(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::TelemetryRead)?;
    let snapshot = ctx.metrics.snapshot((ctx.gauges)());
    let restart = ctx.coord.health().restart_required;
    Ok(json(
        StatusCode::OK,
        &json!({"metrics": snapshot, "restart_required": restart}),
        &[],
    ))
}

pub async fn capabilities(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    ctx.authenticate(&headers, &Method::GET)?;
    let env = ctx.coord.env();
    let mut modules = env.registry.views();
    modules.truncate(256);
    Ok(json(
        StatusCode::OK,
        &json!({
            "capability_digest": env.digest,
            "security_epoch": ctx.coord.gate().security_epoch().to_string(),
            "modules": modules,
        }),
        &[],
    ))
}

pub async fn audit(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::AuditRead)?;
    let limit = page.limit()?;
    let before = page.position(&ctx, "audit", &p)?.and_then(|v| v.as_i64());
    let c = ctx.clone();
    let rows =
        blocking(move || Ok(c.coord.store().read(|c| db::list_audit(c, before, limit))?)).await?;
    let full = rows.len() as u32 == limit;
    let last = rows.last().map(|r| json!(r.seq));
    let items: Vec<_> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "timestamp": rfc3339(r.occurred_at),
                "action": r.action,
                "decision": r.decision,
                "actor_id": r.actor_id.as_ref().filter(|a| uuid::Uuid::parse_str(a).is_ok()),
                "target_type": r.target_type,
                "target_id": r.target_id.as_ref().filter(|t| uuid::Uuid::parse_str(t).is_ok()),
                "revision_digest": r.revision_digest,
            })
        })
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({"items": items, "next_cursor": next_cursor(&ctx, "audit", &p, full, last)}),
        &[],
    ))
}
