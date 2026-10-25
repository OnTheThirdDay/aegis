use super::Ctx;
use crate::http_util::{json, read_json, ApiError, ApiResult};
use crate::ManagementContext;
use aegis_core::rfc3339;
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
    let cookie = ManagementContext::session_cookie(&token, crate::auth::SESSION_TTL.as_secs());
    Ok(json(
        StatusCode::OK,
        &json!({
            "principal_id": p.id,
            "scopes": p.scopes,
            "expires_at": rfc3339(p.expires_at),
            "csrf_token": p.csrf_token,
        }),
        &[(header::SET_COOKIE, cookie)],
    ))
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
    Ok(json(
        StatusCode::OK,
        &json!({
            "principal_id": p.id,
            "scopes": p.scopes,
            "expires_at": rfc3339(p.expires_at),
            "csrf_token": p.csrf_token,
        }),
        &[],
    ))
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
    let c = ctx.clone();
    let id = super::blocking(move || {
        c.claim_bootstrap(&b.bootstrap_token, &b.owner_username, &b.owner_password)
    })
    .await?;
    Ok(json(StatusCode::CREATED, &json!({"principal_id": id}), &[]))
}
