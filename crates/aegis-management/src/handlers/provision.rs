use super::{blocking, Ctx};
use crate::{
    auth::Permission,
    http_util::{idempotency_key, if_match, json, read_json, ApiError, ApiResult},
};
use axum::{
    body::Body,
    extract::{Path, State},
};
use http::{header, HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

fn error(e: aegis_provision::Error) -> ApiError {
    match e.0 {
        "stale_provision_plan" | "stale_config_revision" => ApiError::precondition_failed(),
        "plan_not_found" => ApiError::not_found(),
        _ => ApiError::conflict(e.0),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    desired: aegis_provision::DesiredDeployment,
    expected_revision: Option<String>,
}
pub async fn plan(State(ctx): State<Ctx>, h: HeaderMap, body: Body) -> ApiResult {
    let actor = ctx.authenticate(&h, &Method::POST)?;
    actor.require(Permission::ProvisionWrite)?;
    let value = read_json(&h, body, &["application/json"]).await?;
    let request: PlanRequest = serde_json::from_value(value)
        .map_err(|_| ApiError::bad_request("invalid_provision_plan"))?;
    request
        .desired
        .validate()
        .map_err(|e| ApiError::unprocessable(&[e.to_string()]))?;
    let plan = ctx
        .provisioning
        .plan(request.desired, &actor.id, request.expected_revision)
        .map_err(error)?;
    Ok(json(
        StatusCode::CREATED,
        &plan,
        &[(header::ETAG, plan.etag())],
    ))
}
pub async fn list(State(ctx): State<Ctx>, h: HeaderMap) -> ApiResult {
    let actor = ctx.authenticate(&h, &Method::GET)?;
    actor.require(Permission::ProvisionRead)?;
    let plans = ctx.provisioning.list(&actor.id).map_err(error)?;
    Ok(json(
        StatusCode::OK,
        &json!({"items":plans,"next_cursor":null}),
        &[],
    ))
}
pub async fn get(State(ctx): State<Ctx>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let actor = ctx.authenticate(&h, &Method::GET)?;
    actor.require(Permission::ProvisionRead)?;
    let plan = ctx.provisioning.get(&id, &actor.id).map_err(error)?;
    Ok(json(StatusCode::OK, &plan, &[(header::ETAG, plan.etag())]))
}
pub async fn apply(State(ctx): State<Ctx>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let actor = ctx.authenticate(&h, &Method::POST)?;
    actor.require(Permission::ProvisionWrite)?;
    let etag = if_match(&h)?;
    let key = idempotency_key(&h)?;
    let executor=ctx.provision_executor.lock().unwrap_or_else(|e|e.into_inner()).clone()
        .ok_or_else(||ApiError::conflict("host_controller_required").detail("run aegisctl setup serve on the authorized host; gateway management has no Docker authority"))?;
    let plan = ctx.provisioning.get(&id, &actor.id).map_err(error)?;
    let path = format!("/api/v1/provision/plans/{id}/apply");
    let hash = aegis_storage::sha256_hex(key.as_bytes());
    let request = aegis_config::digest_value(&json!({"plan":id,"etag":etag}));
    let replay = ctx
        .coord
        .store()
        .read(|c| aegis_storage::get_idempotency(c, &actor.id, "POST", &path, &hash))?;
    if let Some(previous) = replay {
        if previous.request_digest != request {
            return Err(ApiError::conflict("idempotency_conflict"));
        }
        return Ok(json(
            StatusCode::ACCEPTED,
            &plan,
            &[(header::LOCATION, format!("/api/v1/provision/plans/{id}"))],
        ));
    }
    if plan.etag() != etag {
        return Err(ApiError::precondition_failed());
    }
    let c = ctx.clone();
    let actor_id = actor.id.clone();
    let plan_id = id.clone();
    blocking(move || {
        c.coord.store().tx(|c| {
            aegis_storage::insert_idempotency(
                c,
                &actor_id,
                "POST",
                &path,
                &hash,
                &request,
                &plan_id,
                aegis_storage::now_unix() + 86400,
            )
        })?;
        Ok(())
    })
    .await?;
    let task = ctx.clone();
    tokio::spawn(async move {
        let _ = executor
            .apply(&task.provisioning, &id, &actor.id, &etag)
            .await;
    });
    Ok(json(
        StatusCode::ACCEPTED,
        &plan,
        &[(
            header::LOCATION,
            format!("/api/v1/provision/plans/{}", plan.id),
        )],
    ))
}
pub async fn recover(State(ctx): State<Ctx>, h: HeaderMap, Path(id): Path<String>) -> ApiResult {
    let actor = ctx.authenticate(&h, &Method::POST)?;
    actor.require(Permission::ProvisionWrite)?;
    let etag = if_match(&h)?;
    let plan = ctx
        .provisioning
        .recover(&id, &actor.id, &etag)
        .map_err(error)?;
    Ok(json(StatusCode::OK, &plan, &[(header::ETAG, plan.etag())]))
}
