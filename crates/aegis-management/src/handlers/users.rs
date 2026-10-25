//! Account administration (owner only). Temporary passwords are returned
//! exactly once and must be changed at first sign-in.

use super::{blocking, Ctx};
use crate::auth::Permission;
use crate::http_util::{json, read_json, valid_uuid, ApiError, ApiResult};
use aegis_core::rfc3339;
use aegis_storage as db;
use axum::body::Body;
use axum::extract::{Path, State};
use http::{HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

pub async fn list(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::UsersManage)?;
    let c = ctx.clone();
    let rows = blocking(move || Ok(c.coord.store().read(db::list_principals)?)).await?;
    let items: Vec<_> = rows
        .iter()
        .map(|u| {
            json!({
                "id": u.id,
                "username": u.username,
                "status": u.status,
                "roles": u.roles,
                "password_change_required": u.must_change_password,
                "created_at": rfc3339(u.created_at),
            })
        })
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items }), &[]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    username: String,
    roles: Vec<String>,
}

pub async fn create(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::UsersManage)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: CreateBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let (id, password) = blocking(move || c.create_user(&actor, &b.username, &b.roles)).await?;
    Ok(json(
        StatusCode::CREATED,
        &json!({"id": id, "temporary_password": password}),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateBody {
    roles: Option<Vec<String>>,
    status: Option<String>,
}

pub async fn update(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::PATCH)?;
    p.require(Permission::UsersManage)?;
    valid_uuid(&id)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: UpdateBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let actor = p.id.clone();
    blocking(move || c.update_user(&actor, &id, b.roles.as_deref(), b.status.as_deref())).await?;
    Ok(json(StatusCode::OK, &json!({"updated": true}), &[]))
}

pub async fn reset_password(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::UsersManage)?;
    valid_uuid(&id)?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let password = blocking(move || c.reset_password(&actor, &id)).await?;
    Ok(json(
        StatusCode::OK,
        &json!({"temporary_password": password}),
        &[],
    ))
}
