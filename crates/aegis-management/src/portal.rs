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
/// A connection whose request head hasn't arrived closes after this long.
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
/// Compared decoded; the handler refuses portal requests for it as well.
fn local_only(method: &Method, path: &str) -> bool {
    *method == Method::POST
        && percent_decode(path).as_deref() == Some("/api/v1/system/device-ca/export-root-key")
}

/// Percent-decode a URI path; `None` when the result isn't UTF-8.
fn percent_decode(path: &str) -> Option<String> {
    let b = path.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).copied().and_then(hex),
            b.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, _, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// The HTTPS ports Cloudflare's proxy listens on; a tunnel hostname answers
/// on each of them.
pub const CLOUDFLARE_HTTPS_PORTS: [u16; 6] = [443, 2053, 2083, 2087, 2096, 8443];

/// The `portal` setting: `{"enabled": bool, "public_port": port|null}`.
pub(crate) fn setting(ctx: &ManagementContext) -> serde_json::Value {
    ctx.coord
        .store()
        .read(|c| db::get_setting(c, "portal"))
        .ok()
        .flatten()
        .unwrap_or_else(|| serde_json::json!({}))
}

/// Whether the portal is switched on (default: on).
pub fn enabled(ctx: &ManagementContext) -> bool {
    setting(ctx)["enabled"].as_bool().unwrap_or(true)
}

/// The port users type when the administrator set one: the portal is
/// still served by the device listener, reached through port forwarding
/// or one of Cloudflare's other HTTPS ports.
pub fn public_port(ctx: &ManagementContext) -> Option<u16> {
    setting(ctx)["public_port"]
        .as_u64()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
}

/// The portal's address for users, once devices have a public address.
pub fn url(ctx: &ManagementContext) -> Option<String> {
    let conn = connection(ctx).ok()?;
    Some(portal_url(
        &conn.public_host?,
        public_port(ctx).or(conn.public_port),
    ))
}

fn portal_url(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        Some(port) if port != 443 => format!("https://{host}:{port}/portal/"),
        _ => format!("https://{host}/portal/"),
    }
}

/// Why `port` can't reach the portal with the current connection, if so.
pub(crate) fn port_problem(ctx: &ManagementContext, port: u16) -> Option<String> {
    let cloudflare = connection(ctx)
        .ok()
        .is_some_and(|c| c.mode.as_deref() == Some("cloudflare"));
    (cloudflare && !CLOUDFLARE_HTTPS_PORTS.contains(&port)).then(|| {
        format!(
            "Through Cloudflare Tunnel the portal answers only on Cloudflare's HTTPS ports: {}",
            CLOUDFLARE_HTTPS_PORTS.map(|p| p.to_string()).join(", ")
        )
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

/// Serves the connections the gateway's edge hands over (their first path
/// starts with `/portal`). The router is built once.
#[derive(Clone)]
pub struct Server {
    ctx: Arc<ManagementContext>,
    router: Router,
}

impl Server {
    pub fn new(ctx: Arc<ManagementContext>) -> Server {
        Server {
            router: router(Arc::clone(&ctx)),
            ctx,
        }
    }

    /// Serve one request on a handed-over HTTP/1.1 connection, then close
    /// it. The edge routes a connection by its first request, so keeping it
    /// alive would let a proxy that pools connections (cloudflared) send a
    /// device's `/renew` or `/agp` here, where it would get a 404.
    pub async fn serve_connection<I>(self, mut io: I)
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Ok(_slot) = Arc::clone(&self.ctx.portal_slots).try_acquire_owned() else {
            let _ = io
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return;
        };
        let service = hyper_util::service::TowerToHyperService::new(self.router);
        let _ = hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .keep_alive(false)
            .serve_connection(hyper_util::rt::TokioIo::new(io), service)
            .await;
    }
}

/// `GET/PUT /api/v1/system/portal` (console): show or switch the portal.
pub(crate) fn status_json(ctx: &ManagementContext) -> serde_json::Value {
    let port = public_port(ctx);
    serde_json::json!({
        "enabled": enabled(ctx),
        "url": url(ctx),
        "public_port": port,
        // A port set before switching to Cloudflare Tunnel may not work there.
        "warning": port.and_then(|p| port_problem(ctx, p)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_addresses_carry_the_port_users_type() {
        assert_eq!(
            portal_url("gw.example.com", None),
            "https://gw.example.com/portal/"
        );
        assert_eq!(
            portal_url("gw.example.com", Some(443)),
            "https://gw.example.com/portal/"
        );
        assert_eq!(
            portal_url("gw.example.com", Some(8443)),
            "https://gw.example.com:8443/portal/"
        );
        assert_eq!(
            portal_url("2001:db8::1", Some(9443)),
            "https://[2001:db8::1]:9443/portal/"
        );
    }

    #[test]
    fn root_key_export_is_local_only_however_spelled() {
        for p in [
            "/api/v1/system/device-ca/export-root-key",
            "/api/v1/system/device-ca/export%2Droot-key",
            "/api/v1/system/device-ca/%65xport-root-key",
            "/api/v1/system/device%2Dca/export%2droot%2Dkey",
        ] {
            assert!(local_only(&Method::POST, p), "{p}");
        }
        assert!(!local_only(
            &Method::POST,
            "/api/v1/system/device-ca/renew-issuer"
        ));
        assert_eq!(percent_decode("/a%2"), Some("/a%2".into()));
        assert_eq!(percent_decode("/%ff"), None);
    }

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
