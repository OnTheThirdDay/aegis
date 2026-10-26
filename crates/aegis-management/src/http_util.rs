//! HTTP plumbing: RFC 9457 problems, request guards, body/precondition
//! parsing and security headers.

use crate::ManagementContext;
use aegis_core::CoordinatorError;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

pub const MAX_BODY: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub aegis_error_code: String,
    pub correlation_id: String,
}

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub detail: Option<String>,
    pub extra: Vec<(header::HeaderName, HeaderValue)>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        ApiError {
            status,
            code,
            detail: None,
            extra: Vec::new(),
        }
    }

    /// Replace the machine-readable error code (keeps the status).
    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = code;
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        let d: String = d.into();
        self.detail = Some(d.chars().take(2048).collect());
        self
    }

    pub fn bad_request(code: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code)
    }
    pub fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated")
    }
    pub fn forbidden() -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden")
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }
    pub fn conflict(code: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code)
    }
    pub fn unprocessable(errors: &[String]) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_configuration")
            .detail(errors.join("; "))
    }
    pub fn precondition_required() -> Self {
        Self::new(StatusCode::PRECONDITION_REQUIRED, "precondition_required")
    }
    pub fn precondition_failed() -> Self {
        Self::new(StatusCode::PRECONDITION_FAILED, "stale_etag")
    }
    pub fn unavailable() -> Self {
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
    }
}

fn title(status: StatusCode) -> &'static str {
    status.canonical_reason().unwrap_or("Error")
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let p = Problem {
            kind: format!("https://aegisnet.invalid/problems/{}", self.code),
            title: title(self.status).into(),
            status: self.status.as_u16(),
            detail: self.detail,
            aegis_error_code: self.code.into(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
        };
        let mut resp = Response::new(Body::from(serde_json::to_vec(&p).unwrap_or_default()));
        *resp.status_mut() = self.status;
        let h = resp.headers_mut();
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        for (k, v) in self.extra {
            h.insert(k, v);
        }
        resp
    }
}

impl From<CoordinatorError> for ApiError {
    fn from(e: CoordinatorError) -> Self {
        match e {
            CoordinatorError::NotFound => ApiError::not_found(),
            CoordinatorError::PreconditionFailed => ApiError::precondition_failed(),
            CoordinatorError::Conflict(c) => ApiError::conflict("conflict").detail(c),
            CoordinatorError::Invalid(errs) => ApiError::unprocessable(&errs),
            CoordinatorError::Storage(_) | CoordinatorError::Crashed => ApiError::unavailable(),
        }
    }
}

impl From<aegis_storage::StoreError> for ApiError {
    fn from(e: aegis_storage::StoreError) -> Self {
        match e {
            aegis_storage::StoreError::NotFound => ApiError::not_found(),
            aegis_storage::StoreError::Conflict(_) => ApiError::conflict("conflict"),
            _ => ApiError::unavailable(),
        }
    }
}

pub type ApiResult = Result<Response, ApiError>;

/// JSON response with extra headers.
pub fn json(
    status: StatusCode,
    v: &impl Serialize,
    headers: &[(header::HeaderName, String)],
) -> Response {
    let mut resp = Response::new(Body::from(serde_json::to_vec(v).unwrap_or_default()));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (k, v) in headers {
        if let Ok(v) = HeaderValue::from_str(v) {
            h.insert(k.clone(), v);
        }
    }
    resp
}

/// Read a body with the 1 MiB cap and parse it as JSON with an accepted
/// content type.
pub async fn read_json(
    headers: &HeaderMap,
    body: Body,
    allowed: &[&str],
) -> Result<Value, ApiError> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_default();
    if !allowed.contains(&ct.as_str()) {
        return Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let bytes = axum::body::to_bytes(body, MAX_BODY)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::bad_request("malformed_json"))
}

/// Exactly one strong quoted ETag; wildcard and weak validators rejected.
pub fn if_match(headers: &HeaderMap) -> Result<String, ApiError> {
    let v = headers
        .get(header::IF_MATCH)
        .ok_or_else(ApiError::precondition_required)?
        .to_str()
        .map_err(|_| ApiError::bad_request("invalid_if_match"))?
        .trim();
    let inner = v
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| ApiError::bad_request("invalid_if_match"))?;
    if inner.is_empty()
        || v.len() > 130
        || !inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::bad_request("invalid_if_match"));
    }
    Ok(v.to_owned())
}

pub fn idempotency_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let v = headers
        .get("idempotency-key")
        .ok_or_else(ApiError::precondition_required)?
        .to_str()
        .map_err(|_| ApiError::bad_request("invalid_idempotency_key"))?;
    if !(16..=128).contains(&v.len())
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(ApiError::bad_request("invalid_idempotency_key"));
    }
    Ok(v.to_owned())
}

pub fn valid_uuid(s: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(s)
        .map(|_| ())
        .map_err(|_| ApiError::not_found())
}

/// Request guard + response security headers for every route.
pub async fn guard(
    State(ctx): State<Arc<ManagementContext>>,
    req: Request,
    next: Next,
) -> Response {
    let allowed = ctx.allowed_hosts();
    let remote = ctx.remote_console();
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned);
    // A loopback console only answers its own names (DNS-rebinding guard).
    // A remote console is HTTPS-only: the name the operator typed is
    // accepted, and cross-origin requests are refused below.
    let host_ok = host.as_deref().is_some_and(|h| {
        if remote {
            valid_host_header(h)
        } else {
            allowed.iter().any(|a| a.eq_ignore_ascii_case(h))
        }
    });
    if !host_ok {
        return finish(
            ApiError::bad_request("host_not_allowed").into_response(),
            true,
        );
    }
    if let Some(origin) = req.headers().get(header::ORIGIN) {
        let ok = origin.to_str().ok().is_some_and(|o| {
            if remote {
                host.as_deref()
                    .is_some_and(|h| o.eq_ignore_ascii_case(&format!("https://{h}")))
            } else {
                o.strip_prefix("http://")
                    .or_else(|| o.strip_prefix("https://"))
                    .is_some_and(|o| allowed.iter().any(|a| a.eq_ignore_ascii_case(o)))
            }
        });
        if !ok {
            return finish(
                ApiError::forbidden()
                    .detail("origin not allowed")
                    .into_response(),
                true,
            );
        }
    }
    if req.method() == Method::OPTIONS {
        // No CORS: preflights are refused.
        return finish(
            ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed").into_response(),
            true,
        );
    }
    let is_api = req.uri().path().starts_with("/api/");
    let resp = next.run(req).await;
    finish(resp, is_api)
}

fn valid_host_header(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 255
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

pub(crate) fn finish(mut resp: Response, no_store: bool) -> Response {
    let h = resp.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    );
    set(h, "x-frame-options", "DENY");
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(h, "strict-transport-security", "max-age=31536000");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    );
    if no_store {
        set(h, "cache-control", "no-store");
    }
    resp
}
