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
    /// Authenticator code or recovery code, when the account uses 2FA.
    #[serde(default)]
    code: Option<String>,
}

pub async fn login(
    State(ctx): State<Ctx>,
    portal: Option<axum::Extension<crate::portal::PortalRequest>>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: LoginBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.username.is_empty()
        || b.username.len() > 100
        || b.password.is_empty()
        || b.password.len() > 1024
        || b.code.as_ref().is_some_and(|c| c.len() > 64)
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let c = ctx.clone();
    let through_portal = portal.is_some();
    let (token, p) = super::blocking(move || {
        c.login(&b.username, &b.password, through_portal, b.code.as_deref())
    })
    .await?;
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
    let (row, two_factor) = super::blocking(move || {
        Ok(c.coord
            .store()
            .read(|c| Ok((db::get_principal(c, &id)?, db::two_factor_enabled(c, &id)?)))?)
    })
    .await?;
    Ok(json!({
        "principal_id": p.id,
        "username": row.username,
        "roles": row.roles,
        "scopes": p.scopes,
        "expires_at": rfc3339(p.expires_at),
        "csrf_token": p.csrf_token,
        "password_change_required": p.password_change_required(),
        "two_factor": two_factor,
        "mfa_session": p.mfa,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current_password: String,
    new_password: String,
}

/// Change the caller's own password (also completes a forced change).
pub async fn change_password(
    State(ctx): State<Ctx>,
    portal: Option<axum::Extension<crate::portal::PortalRequest>>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
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
    let (mfa, portal) = (p.mfa, portal.is_some());
    let (token, next) = super::blocking(move || {
        c.change_password(&id, &b.current_password, &b.new_password, mfa, portal)
    })
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

// ---------------------------------------------------------------- two-factor

/// A signed-in, interactive (cookie) caller with a normal session.
fn interactive(ctx: &Ctx, headers: &HeaderMap, method: &Method) -> Result<Principal, ApiError> {
    let p = ctx.authenticate(headers, method)?;
    if p.kind != crate::auth::CredentialKind::Cookie {
        return Err(ApiError::forbidden()
            .detail("sign in interactively to manage two-factor authentication"));
    }
    if p.password_change_required() {
        return Err(ApiError::forbidden().detail("password change required"));
    }
    Ok(p)
}

async fn audit_2fa(
    ctx: &Ctx,
    actor: &str,
    target: &str,
    action: &'static str,
) -> Result<(), ApiError> {
    let (c, actor, target) = (ctx.clone(), actor.to_owned(), target.to_owned());
    super::blocking(move || {
        c.coord.store().tx(|tx| {
            db::append_audit(
                tx,
                db::AuditInsert {
                    actor_id: Some(&actor),
                    action,
                    target_type: "principal",
                    target_id: Some(&target),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({}),
                },
            )
        })?;
        Ok(())
    })
    .await
}

/// `GET /api/v1/auth/2fa`: whether 2FA is on, and recovery codes left.
pub async fn two_factor_status(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = interactive(&ctx, &headers, &Method::GET)?;
    let c = ctx.clone();
    let (on, left) = super::blocking(move || {
        Ok(c.coord.store().read(|tx| {
            Ok((
                db::two_factor_enabled(tx, &p.id)?,
                db::recovery_codes_left(tx, &p.id)?,
            ))
        })?)
    })
    .await?;
    Ok(json(
        StatusCode::OK,
        &json!({"enabled": on, "recovery_codes_left": left}),
        &[],
    ))
}

/// `POST /api/v1/auth/2fa/setup`: a new secret to scan, pending until
/// confirmed with a code.
pub async fn two_factor_setup(State(ctx): State<Ctx>, headers: HeaderMap) -> ApiResult {
    let p = interactive(&ctx, &headers, &Method::POST)?;
    let c = ctx.clone();
    let id = p.id.clone();
    let body = super::blocking(move || {
        let (row, on) = c.coord.store().read(|tx| {
            Ok((
                db::get_principal(tx, &id)?,
                db::two_factor_enabled(tx, &id)?,
            ))
        })?;
        if on {
            return Err(ApiError::conflict("two_factor_already_enabled")
                .detail("turn two-factor authentication off first to set up a new authenticator"));
        }
        let secret = crate::totp::new_secret();
        crate::totp::store(&c, &id, true, &secret)?;
        let uri = crate::totp::uri(&row.username, &secret);
        Ok(json!({
            "secret": crate::totp::base32(&secret),
            "uri": uri,
            "qr": crate::totp::qr_rows(&uri),
        }))
    })
    .await?;
    Ok(json(StatusCode::OK, &body, &[]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeBody {
    code: String,
}

/// `POST /api/v1/auth/2fa/enable`: confirm the pending secret with a code;
/// returns the recovery codes, shown once.
pub async fn two_factor_enable(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let p = interactive(&ctx, &headers, &Method::POST)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: CodeBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let id = p.id.clone();
    let codes = super::blocking(move || {
        let secret = crate::totp::load(&c, &id, true).ok_or_else(|| {
            ApiError::conflict("two_factor_not_set_up").detail("start the setup again")
        })?;
        let step = crate::totp::verify(&secret, &b.code, db::now_unix()).ok_or_else(|| {
            ApiError::bad_request("invalid_two_factor_code")
                .detail("that code doesn't match: check the device clock and try the current code")
        })?;
        let codes = crate::totp::new_recovery_codes();
        let hashes: Vec<String> = codes
            .iter()
            .map(|c| crate::totp::recovery_hash(c))
            .collect();
        crate::totp::activate(&c, &id)?;
        c.coord.store().tx(|tx| {
            db::enable_two_factor(tx, &id, &hashes)?;
            // The confirming code counts as used.
            db::advance_totp_step(tx, &id, step)?;
            Ok(())
        })?;
        Ok(codes)
    })
    .await?;
    audit_2fa(&ctx, &p.id, &p.id, "auth.2fa_enabled").await?;
    Ok(json(
        StatusCode::OK,
        &json!({"enabled": true, "recovery_codes": codes}),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisableBody {
    password: String,
    code: String,
}

/// `POST /api/v1/auth/2fa/disable`: needs the password and a current code.
pub async fn two_factor_disable(
    State(ctx): State<Ctx>,
    portal: Option<axum::Extension<crate::portal::PortalRequest>>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let p = interactive(&ctx, &headers, &Method::POST)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: DisableBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let c = ctx.clone();
    let (id, portal) = (p.id.clone(), portal.is_some());
    super::blocking(move || {
        c.confirm_password(&id, &b.password, portal)?;
        c.check_second_factor(&id, &b.code)?;
        c.coord.store().tx(|tx| db::disable_two_factor(tx, &id))?;
        crate::totp::remove(&c, &id, false);
        crate::totp::remove(&c, &id, true);
        Ok(())
    })
    .await?;
    audit_2fa(&ctx, &p.id, &p.id, "auth.2fa_disabled").await?;
    Ok(json(StatusCode::OK, &json!({"enabled": false}), &[]))
}

/// `POST /api/v1/users/{id}/reset-2fa` (owners): turn 2FA off for an account
/// whose authenticator was lost; they can set it up again.
pub async fn two_factor_reset(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(crate::auth::Permission::UsersManage)?;
    crate::http_util::valid_uuid(&id)?;
    let c = ctx.clone();
    let target = id.clone();
    super::blocking(move || {
        c.coord
            .store()
            .tx(|tx| db::disable_two_factor(tx, &target))?;
        crate::totp::remove(&c, &target, false);
        crate::totp::remove(&c, &target, true);
        c.purge_sessions(&target);
        Ok(())
    })
    .await?;
    audit_2fa(&ctx, &p.id, &id, "auth.2fa_reset").await?;
    Ok(json(StatusCode::OK, &json!({"enabled": false}), &[]))
}
