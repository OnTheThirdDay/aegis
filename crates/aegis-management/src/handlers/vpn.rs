//! Read-only System-VPN surface (04 §6, 10 §8). Reports the real installed
//! capability (all modes unsupported in this build), never a desired state,
//! and never mutates OS routing.

use super::{blocking, Ctx, Page};
use crate::auth::Permission;
use crate::http_util::{json, read_json, valid_uuid, ApiError, ApiResult};
use aegis_config::parse_json;
use aegis_core::rfc3339;
use aegis_storage as db;
use aegis_traffic_policy::SyntheticFlow;
use axum::body::Body;
use axum::extract::{Query, State};
use http::{HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};

pub async fn capabilities(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::NetworkRead)?;
    let caps = &ctx.coord.env().host_vpn;
    Ok(json(
        StatusCode::OK,
        &json!({
            "platform": caps.platform.as_str(),
            "modes": caps.modes,
            "tcp": caps.tcp,
            "udp": caps.udp,
            "dns_capture": caps.dns_capture,
            "ipv4": caps.ipv4,
            "ipv6": caps.ipv6,
            "native_kill_switch": caps.native_kill_switch,
            "permission_state": "unavailable",
            "helper_state": "missing",
            "observed_at": rfc3339(db::now_unix()),
        }),
        &[],
    ))
}

pub async fn status(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::NetworkRead)?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "enabled": false,
            "status": "unavailable",
            "mode": null,
            "kill_switch": "unavailable",
            "os_policy_generation": null,
            "runtime_policy_generation": null,
            "reconcile_state": "unavailable",
            "reason": "no native System-VPN adapter or privileged helper is installed on this host",
        }),
        &[],
    ))
}

/// No OS-verified app identity provider exists in this build: the list is
/// empty rather than fabricated from process names.
pub async fn apps(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::NetworkAppsRead)?;
    page.limit()?;
    if page.cursor.is_some() {
        return Err(ApiError::bad_request("invalid_cursor"));
    }
    Ok(json(
        StatusCode::OK,
        &json!({"items": [], "next_cursor": null}),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewBody {
    revision_id: String,
    target_node_id: String,
    flows: Vec<SyntheticFlow>,
}

/// Non-executing synthetic decisions for an immutable revision.
pub async fn preview(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProfilesRead)?;
    p.require(Permission::DiagnosticsExplain)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: PreviewBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    valid_uuid(&b.revision_id)?;
    uuid::Uuid::parse_str(&b.target_node_id).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.flows.is_empty() || b.flows.len() > 20 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    if b.flows
        .iter()
        .any(|f| f.remote_port == 0 || f.remote_address.is_empty() || f.remote_address.len() > 255)
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let rev = ctx
        .coord
        .store()
        .read(|c| db::get_revision(c, &b.revision_id))?;
    let spec: Value = serde_json::from_str(&rev.spec_json).map_err(|_| ApiError::unavailable())?;
    let c = ctx.clone();
    let decisions = blocking(move || {
        let cfg = parse_json(&spec).map_err(|e| ApiError::unprocessable(&[e.to_string()]))?;
        let section = cfg.system_vpn.ok_or_else(|| {
            ApiError::unprocessable(&["revision has no system_vpn section".into()])
        })?;
        let policy = section.compile().map_err(|e| ApiError::unprocessable(&e))?;
        let caps = &c.coord.env().host_vpn;
        Ok(b.flows
            .iter()
            .map(|f| policy.evaluate(f, caps))
            .collect::<Vec<_>>())
    })
    .await?;
    Ok(json(
        StatusCode::OK,
        &json!({
            "revision_id": b.revision_id,
            "config_digest": rev.digest,
            "target_node_id": b.target_node_id,
            "capability_digest": ctx.coord.env().digest,
            "simulated": true,
            "decisions": decisions,
        }),
        &[],
    ))
}
