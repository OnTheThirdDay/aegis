use super::Ctx;
use crate::auth::Principal;
use crate::http_util::{json, read_json, ApiError, ApiResult};
use crate::ManagementContext;
use aegis_core::rfc3339;
use aegis_storage as db;
use axum::body::Body;
use axum::extract::State;
use http::{header, HeaderMap, Method, StatusCode};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginBody {
    username: String,
    password: String,
}

pub async fn login(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: LoginBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.username.is_empty()
        || b.username.len() > 100
        || b.password.is_empty()
        || b.password.len() > 1024
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let c = ctx.clone();
    let (token, p) = super::blocking(move || c.login(&b.username, &b.password)).await?;
    session_response(&ctx, &token, &p).await
}

async fn session_response(ctx: &Ctx, token: &str, p: &Principal) -> ApiResult {
    let cookie = ManagementContext::session_cookie(token, crate::auth::SESSION_TTL.as_secs());
    let body = principal_json(ctx, p).await?;
    Ok(json(StatusCode::OK, &body, &[(header::SET_COOKIE, cookie)]))
}

async fn principal_json(ctx: &Ctx, p: &Principal) -> Result<serde_json::Value, ApiError> {
    let c = ctx.clone();
    let id = p.id.clone();
    let row =
        super::blocking(move || Ok(c.coord.store().read(|c| db::get_principal(c, &id))?)).await?;
    Ok(json!({
        "principal_id": p.id,
        "username": row.username,
        "roles": row.roles,
        "scopes": p.scopes,
        "expires_at": rfc3339(p.expires_at),
        "csrf_token": p.csrf_token,
        "password_change_required": p.password_change_required(),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current_password: String,
    new_password: String,
}

/// Change the caller's own password (also completes a forced change).
pub async fn change_password(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    if p.kind != crate::auth::CredentialKind::Cookie {
        return Err(ApiError::forbidden().detail("sign in interactively to change a password"));
    }
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: PasswordBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.current_password.len() > 1024 || b.new_password.len() > 1024 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let c = ctx.clone();
    let id = p.id.clone();
    let (token, next) =
        super::blocking(move || c.change_password(&id, &b.current_password, &b.new_password))
            .await?;
    session_response(&ctx, &token, &next).await
}

pub async fn logout(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    ctx.authenticate(&headers, &Method::POST)?;
    ctx.logout(&headers);
    let mut resp = axum::response::Response::new(Body::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    if let Ok(v) = ManagementContext::session_cookie("", 0).parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(resp)
}

pub async fn me(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    let body = principal_json(&ctx, &p).await?;
    Ok(json(StatusCode::OK, &body, &[]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimBody {
    bootstrap_token: String,
    owner_username: String,
    owner_password: String,
}

pub async fn bootstrap_claim(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: ClaimBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.bootstrap_token.is_empty() || b.bootstrap_token.len() > 256 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let permit = ctx.begin_bootstrap_claim()?;
    let c = ctx.clone();
    let id = super::blocking(move || {
        c.claim_bootstrap_admitted(
            &b.bootstrap_token,
            &b.owner_username,
            &b.owner_password,
            permit,
        )
    })
    .await?;
    Ok(json(StatusCode::CREATED, &json!({"principal_id": id}), &[]))
}
