use super::{blocking, job_json, next_cursor, Ctx, Page};
use crate::auth::{Permission, Principal};
use crate::http_util::{
    idempotency_key, if_match, json, read_json, valid_uuid, ApiError, ApiResult,
};
use aegis_config::parse_json;
use aegis_contracts::Destination;
use aegis_core::{rfc3339, ActivateRequest};
use aegis_policy::{DecisionInput, ExplainAction};
use aegis_storage::{self as db, JobRow};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use http::{header, HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

fn profile_json(p: &db::ProfileRow, desired: &db::RevisionRow) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "specification": serde_json::from_str::<Value>(&desired.spec_json).unwrap_or(Value::Null),
        "desired_revision_id": p.desired_revision_id,
        "active_revision_id": p.active_revision_id,
        "config_digest": desired.digest,
    })
}

fn revision_json(r: &db::RevisionRow, with_spec: bool) -> Value {
    let mut v = json!({
        "id": r.id,
        "profile_id": r.profile_id,
        "parent_id": r.parent_id,
        "config_digest": r.digest,
        "state": r.state,
        "created_at": rfc3339(r.created_at),
    });
    if with_spec {
        v["specification"] = serde_json::from_str::<Value>(&r.spec_json).unwrap_or(Value::Null);
    }
    v
}

fn profile_response(ctx: &Ctx, status: StatusCode, id: &str) -> ApiResult {
    let (p, rev) = ctx.coord.store().read(|c| {
        let p = db::get_profile(c, id)?;
        let r = db::get_revision(c, &p.desired_revision_id)?;
        Ok((p, r))
    })?;
    Ok(json(
        status,
        &profile_json(&p, &rev),
        &[(header::ETAG, p.etag())],
    ))
}

pub async fn list(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::ProfilesRead)?;
    let limit = page.limit()?;
    let after = page
        .position(&ctx, "profiles", &p)?
        .and_then(|v| Some((v.get(0)?.as_i64()?, v.get(1)?.as_str()?.to_owned())));
    let c = ctx.clone();
    let rows = blocking(move || {
        Ok(c.coord
            .store()
            .read(|c| db::list_profiles(c, after, limit))?)
    })
    .await?;
    let full = rows.len() as u32 == limit;
    let last = rows.last().map(|r| json!([r.created_at, r.id]));
    let items: Vec<Value> = rows
        .iter()
        .map(|r| json!({"id": r.id, "name": r.name, "desired_revision_id": r.desired_revision_id, "active_revision_id": r.active_revision_id}))
        .collect();
    Ok(json(
        StatusCode::OK,
        &json!({"items": items, "next_cursor": next_cursor(&ctx, "profiles", &p, full, last)}),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileInput {
    name: String,
    specification: serde_json::Map<String, Value>,
}

pub async fn create(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProfilesWrite)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let input: ProfileInput =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let profile = blocking(move || {
        Ok(c.coord.create_profile(
            Some(&actor),
            &input.name,
            &Value::Object(input.specification),
        )?)
    })
    .await?;
    profile_response(&ctx, StatusCode::CREATED, &profile.id)
}

pub async fn get_one(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::ProfilesRead)?;
    valid_uuid(&id)?;
    profile_response(&ctx, StatusCode::OK, &id)
}

pub async fn patch(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PATCH)?;
    p.require(Permission::ProfilesWrite)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let v = read_json(
        &headers,
        body,
        &["application/merge-patch+json", "application/json"],
    )
    .await?;
    let obj = v
        .as_object()
        .ok_or_else(|| ApiError::bad_request("invalid_body"))?;
    if obj.is_empty() || obj.keys().any(|k| k != "name" && k != "specification") {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let name = match obj.get("name") {
        Some(Value::String(s)) => Some(s.clone()),
        None => None,
        _ => return Err(ApiError::bad_request("invalid_body")),
    };
    let spec = match obj.get("specification") {
        Some(s @ Value::Object(_)) => Some(s.clone()),
        None => None,
        _ => return Err(ApiError::bad_request("invalid_body")),
    };
    let c = ctx.clone();
    let actor = p.id.clone();
    let id2 = id.clone();
    blocking(move || {
        Ok(c.coord
            .patch_profile(Some(&actor), &id2, &etag, name.as_deref(), spec.as_ref())?)
    })
    .await?;
    profile_response(&ctx, StatusCode::OK, &id)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateBody {
    target_revision_id: String,
}

pub async fn validate(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProfilesRead)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ValidateBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    valid_uuid(&b.target_revision_id).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let report = blocking(move || {
        Ok(c.coord
            .validate(Some(&actor), &id, &etag, &b.target_revision_id)?)
    })
    .await?;
    Ok(json(StatusCode::OK, &report, &[]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateBody {
    target_revision_id: String,
    config_digest: String,
    validation_id: String,
}

fn accepted(job: &JobRow) -> axum::response::Response {
    json(
        StatusCode::ACCEPTED,
        &job_json(job),
        &[
            (header::LOCATION, format!("/api/v1/jobs/{}", job.id)),
            (header::RETRY_AFTER, "1".into()),
        ],
    )
}

pub async fn activate(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProfilesActivate)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ActivateBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.config_digest.len() != 64
        || !b
            .config_digest
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let req = ActivateRequest {
        actor_id: Some(p.id.clone()),
        profile_id: id.clone(),
        if_match: etag,
        idempotency_key: key,
        target_revision_id: b.target_revision_id,
        config_digest: b.config_digest,
        validation_id: b.validation_id,
    };
    let c = ctx.clone();
    let path = format!("/api/v1/profiles/{id}/activate");
    let job = blocking(move || Ok(c.coord.submit_activation(&req, &path)?)).await?;
    spawn_job(&ctx, &job);
    Ok(accepted(&job))
}

pub fn spawn_job(ctx: &Ctx, job: &JobRow) {
    if job.status != "pending" {
        return;
    }
    let coord = Arc::clone(&ctx.coord);
    let id = job.id.clone();
    let kind = job.kind.clone();
    tokio::task::spawn_blocking(move || {
        let _ = if kind == "node_revoke" {
            coord.run_revoke(&id)
        } else {
            coord.run_job(&id)
        };
    });
}

pub async fn revisions(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::ProfilesRead)?;
    valid_uuid(&id)?;
    let limit = page.limit()?;
    let kind = format!("revisions:{id}");
    let before = page.position(&ctx, &kind, &p)?.and_then(|v| v.as_i64());
    let c = ctx.clone();
    let id2 = id.clone();
    let rows = blocking(move || {
        Ok(c.coord.store().read(|c| {
            db::get_profile(c, &id2)?;
            db::list_revisions(c, &id2, before, limit)
        })?)
    })
    .await?;
    let full = rows.len() as u32 == limit;
    let last = rows.last().map(|r| json!(r.seq));
    let items: Vec<Value> = rows.iter().map(|r| revision_json(r, false)).collect();
    Ok(json(
        StatusCode::OK,
        &json!({"items": items, "next_cursor": next_cursor(&ctx, &kind, &p, full, last)}),
        &[],
    ))
}

pub async fn revision(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::ProfilesRead)?;
    valid_uuid(&id)?;
    let r = ctx.coord.store().read(|c| db::get_revision(c, &id))?;
    Ok(json(StatusCode::OK, &revision_json(&r, true), &[]))
}

pub async fn restore(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::ProfilesActivate)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let path = format!("/api/v1/revisions/{id}/restore");
    let job = blocking(move || {
        Ok(c.coord
            .submit_restore(Some(&actor), &id, &etag, &key, &path)?)
    })
    .await?;
    spawn_job(&ctx, &job);
    Ok(accepted(&job))
}

/// Object-scoped job polling: knowledge of a UUID grants nothing.
fn may_read_job(p: &Principal, j: &JobRow) -> bool {
    j.actor_id.as_deref() == Some(p.id.as_str())
        || match j.target_type.as_str() {
            "profile" => p.has(Permission::ProfilesRead),
            "node" => p.has(Permission::NodesRead),
            _ => false,
        }
}

pub async fn job(State(ctx): State<Ctx>, headers: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    valid_uuid(&id)?;
    let j = ctx.coord.store().read(|c| db::get_job(c, &id))?;
    if !may_read_job(&p, &j) {
        return Err(ApiError::not_found());
    }
    let retry = matches!(j.status.as_str(), "pending" | "running" | "reconciling");
    let headers = if retry {
        vec![(header::RETRY_AFTER, "1".to_string())]
    } else {
        vec![]
    };
    Ok(json(StatusCode::OK, &job_json(&j), &headers))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainBody {
    profile_id: String,
    revision_id: String,
    destination_host: String,
    destination_port: u16,
    protocol: String,
}

/// Synthetic exact-revision route explanation; never dials or resolves.
pub async fn explain(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DiagnosticsExplain)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ExplainBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    valid_uuid(&b.profile_id)?;
    valid_uuid(&b.revision_id)?;
    if b.destination_port == 0 || b.destination_host.is_empty() || b.destination_host.len() > 253 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let rev = ctx
        .coord
        .store()
        .read(|c| db::get_revision(c, &b.revision_id))?;
    if rev.profile_id != b.profile_id {
        return Err(ApiError::not_found());
    }
    let respond = |action: &str, rule: Option<String>, reason: String| {
        json(
            StatusCode::OK,
            &json!({"revision_id": b.revision_id, "action": action, "rule_id": rule, "reason": reason}),
            &[],
        )
    };
    if b.protocol == "udp" {
        return Ok(respond(
            "deny",
            None,
            "UDP (DATAGRAM) is not supported in this build; UDP flows are not forwarded".into(),
        ));
    }
    if b.protocol != "tcp" {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let Ok(host) = aegis_contracts::Host::parse(&b.destination_host) else {
        return Ok(respond(
            "indeterminate",
            None,
            "destination is not a valid IP literal or A-label domain".into(),
        ));
    };
    let dest = Destination {
        host,
        port: b.destination_port,
    };
    let c = ctx.clone();
    let spec_json = rev.spec_json.clone();
    let compiled = blocking(move || {
        let v: Value = serde_json::from_str(&spec_json).map_err(|_| ApiError::unavailable())?;
        let cfg = parse_json(&v).map_err(|e| ApiError::unprocessable(&[e.to_string()]))?;
        c.coord
            .env()
            .compile(&cfg)
            .map_err(|e| ApiError::unprocessable(&e))
    })
    .await?;
    let inbound = compiled
        .config
        .inbounds
        .first()
        .map(|i| i.id.clone())
        .unwrap_or_default();
    let node_scoped =
        compiled.config.routing.rules.iter().any(
            |r| matches!(&r.matcher, aegis_config::MatchConfig::Table(t) if !t.nodes.is_empty()),
        );
    let e = compiled.router.explain(&DecisionInput {
        destination: &dest,
        inbound: &inbound,
        node_id: None,
    });
    if node_scoped && e.action != ExplainAction::Deny {
        return Ok(respond(
            "indeterminate",
            e.rule_id,
            format!(
                "{}; node-scoped rules need an authenticated identity that explain does not have",
                e.reason
            ),
        ));
    }
    let action = match e.action {
        ExplainAction::Proxy => "proxy",
        ExplainAction::Direct => "direct",
        ExplainAction::Deny => "deny",
        ExplainAction::Indeterminate => "indeterminate",
    };
    Ok(respond(action, e.rule_id, e.reason))
}
