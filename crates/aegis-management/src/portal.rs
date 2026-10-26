//! User portal (ADR-0010): the self-service part of the console, served on
//! the gateway's public edge under `/portal` (through the Cloudflare tunnel
//! when one is set up), so users can sign in, manage their own devices and
//! download the client app while the console itself stays private.
//!
//! * Only self-service routes are reachable (an allowlist below); everything
//!   else answers 404, whatever the session.
//! * Administrators (any role beyond `user`) may sign in only with two-factor
//!   authentication; such a session gets the whole console here (minus a few
//!   local-only actions), so SSH is optional. Without 2FA they are refused,
//!   after the password check, so the portal reveals nothing about who is one.
//! * Cookie sessions only: `Authorization` headers (API tokens) are refused.
//! * The Host must be the gateway's public device address; cross-origin
//!   requests are refused.
//! * Sign-in has its own rate limiter, so traffic on the portal can never
//!   lock an administrator out of the console.
//! * Bounded concurrency; idle connections close after a short timeout.

use crate::handlers::devices::connection;
use crate::http_util::{finish, ApiError};
use crate::ManagementContext;
use aegis_storage as db;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Router;
use http::{header, Method};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Marks a request that arrived through the portal.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PortalRequest;

/// Portal connections served at once.
pub const MAX_CONNECTIONS: usize = 64;
/// An idle keep-alive connection closes after this long.
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);

/// The routes a portal user needs, nothing else.
fn allowed(method: &Method, path: &str) -> bool {
    if *method == Method::GET {
        matches!(
            path,
            "/" | "/app.js"
                | "/style.css"
                | "/api/v1/auth/me"
                | "/api/v1/auth/2fa"
                | "/api/v1/devices"
                | "/api/v1/system/downloads"
        ) || path.starts_with("/downloads/")
    } else if *method == Method::POST {
        matches!(
            path,
            "/api/v1/auth/login"
                | "/api/v1/auth/logout"
                | "/api/v1/auth/password"
                | "/api/v1/auth/2fa/setup"
                | "/api/v1/auth/2fa/enable"
                | "/api/v1/auth/2fa/disable"
                | "/api/v1/devices/invite"
        ) || (path.starts_with("/api/v1/devices/") && path.ends_with("/revoke"))
    } else {
        false
    }
}

/// Console actions never offered on the public address, even to an
/// administrator signed in with 2FA: taking the device root key off the server.
fn local_only(method: &Method, path: &str) -> bool {
    *method == Method::POST && path == "/api/v1/system/device-ca/export-root-key"
}

/// Whether the portal is switched on (default: on).
pub fn enabled(ctx: &ManagementContext) -> bool {
    ctx.coord
        .store()
        .read(|c| db::get_setting(c, "portal"))
        .ok()
        .flatten()
        .and_then(|v| v["enabled"].as_bool())
        .unwrap_or(true)
}

/// The portal's address for users, once devices have a public address.
pub fn url(ctx: &ManagementContext) -> Option<String> {
    let conn = connection(ctx).ok()?;
    let host = conn.public_host?;
    Some(match conn.public_port {
        Some(port) if port != 443 && conn.mode.as_deref() != Some("cloudflare") => {
            format!("https://{host}:{port}/portal/")
        }
        _ => format!("https://{host}/portal/"),
    })
}

fn host_without_port(h: &str) -> &str {
    if h.starts_with('[') {
        h.split(']').next().map_or(h, |x| x.trim_start_matches('['))
    } else {
        h.rsplit_once(':')
            .filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit()))
            .map_or(h, |(n, _)| n)
    }
}

async fn guard(
    State(ctx): State<Arc<ManagementContext>>,
    mut req: Request,
    next: Next,
) -> Response {
    let not_found = || finish(ApiError::not_found().into_response(), true);
    if !enabled(&ctx) {
        return not_found();
    }
    if !allowed(req.method(), req.uri().path()) {
        // Beyond self-service: only an administrator whose session was
        // opened with a second factor (the handlers still authenticate).
        let admin_2fa = ctx
            .peek_session(req.headers())
            .is_some_and(|(scopes, mfa)| mfa && ManagementContext::administrative(&scopes));
        if !admin_2fa || local_only(req.method(), req.uri().path()) {
            return not_found();
        }
    }
    if req.headers().contains_key(header::AUTHORIZATION) {
        return finish(
            ApiError::forbidden()
                .detail("the portal accepts browser sessions only")
                .into_response(),
            true,
        );
    }
    let public = connection(&ctx).ok().and_then(|c| c.public_host);
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    let host_ok = match (&host, &public) {
        (Some(h), Some(p)) => host_without_port(h).eq_ignore_ascii_case(p),
        _ => false,
    };
    if !host_ok {
        return finish(
            ApiError::bad_request("host_not_allowed").into_response(),
            true,
        );
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let expected = format!("https://{}", host.as_deref().unwrap_or(""));
        if !origin
            .to_str()
            .is_ok_and(|o| o.eq_ignore_ascii_case(&expected))
        {
            return finish(
                ApiError::forbidden()
                    .detail("origin not allowed")
                    .into_response(),
                true,
            );
        }
    }
    let is_api = req.uri().path().starts_with("/api/");
    req.extensions_mut().insert(PortalRequest);
    finish(next.run(req).await, is_api)
}

/// The portal's routes, mounted under `/portal`.
pub fn router(ctx: Arc<ManagementContext>) -> Router {
    let inner = crate::handlers::routes(Arc::clone(&ctx))
        .merge(crate::ui::portal_routes())
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&ctx),
            guard,
        ))
        .with_state(ctx);
    Router::new().nest_service("/portal", inner)
}

/// Serve one HTTP/1.1 connection handed over by the gateway's edge (its
/// path starts with `/portal`). Returns when the connection closes.
pub async fn serve_connection<I>(ctx: Arc<ManagementContext>, mut io: I)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(_slot) = Arc::clone(&ctx.portal_slots).try_acquire_owned() else {
        let _ = io
            .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    };
    let service = hyper_util::service::TowerToHyperService::new(router(ctx));
    let _ = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .serve_connection(hyper_util::rt::TokioIo::new(io), service)
        .await;
}

/// `GET/PUT /api/v1/system/portal` (console): show or switch the portal.
pub(crate) fn status_json(ctx: &ManagementContext) -> serde_json::Value {
    serde_json::json!({
        "enabled": enabled(ctx),
        "url": url(ctx),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_self_service_routes() {
        assert!(allowed(&Method::GET, "/"));
        assert!(allowed(&Method::POST, "/api/v1/auth/login"));
        assert!(allowed(&Method::POST, "/api/v1/devices/0b0e/revoke"));
        assert!(allowed(
            &Method::GET,
            "/downloads/aegis-client-windows-x86_64.exe"
        ));
        for (m, p) in [
            (Method::GET, "/api/v1/users"),
            (Method::GET, "/api/v1/system/info"),
            (Method::POST, "/api/v1/users"),
            (Method::GET, "/api/v1/diagnostics"),
            (Method::POST, "/api/v1/system/device-ca/export-root-key"),
            (Method::PUT, "/api/v1/system/connection"),
            (Method::GET, "/api/v1/audit"),
            (Method::DELETE, "/api/v1/devices/x/revoke"),
        ] {
            assert!(!allowed(&m, p), "{m} {p}");
        }
    }

    #[test]
    fn host_ports_are_ignored() {
        assert_eq!(host_without_port("aegis.example.com"), "aegis.example.com");
        assert_eq!(host_without_port("203.0.113.7:8444"), "203.0.113.7");
        assert_eq!(host_without_port("[2001:db8::1]:8444"), "2001:db8::1");
    }
}
