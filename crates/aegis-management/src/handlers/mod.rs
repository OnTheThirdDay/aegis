//! `/api/v1` routes.

mod auth;
mod nodes;
mod profiles;
mod system;
pub mod telemetry;
mod vpn;

use crate::auth::Principal;
use crate::http_util::{ApiError, MAX_BODY};
use crate::ManagementContext;
use aegis_core::rfc3339;
use aegis_storage::JobRow;
use axum::routing::{get, post};
use axum::Router;
use serde_json::{json, Value};
use std::sync::Arc;

pub type Ctx = Arc<ManagementContext>;

pub fn routes(_ctx: Ctx) -> Router<Ctx> {
    Router::new()
        .route("/api/v1/auth/login", post(auth::login))
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/auth/me", get(auth::me))
        .route("/api/v1/bootstrap/claim", post(auth::bootstrap_claim))
        .route("/api/v1/system/health", get(system::health))
        .route("/api/v1/system/metrics", get(system::metrics))
        .route("/api/v1/capabilities", get(system::capabilities))
        .route("/api/v1/nodes", get(nodes::list))
        .route("/api/v1/nodes/enrollment", post(nodes::create_enrollment))
        .route(
            "/api/v1/nodes/enrollment/redeem",
            post(nodes::redeem_enrollment),
        )
        .route("/api/v1/nodes/{id}", get(nodes::get_one))
        .route("/api/v1/nodes/{id}/revoke", post(nodes::revoke))
        .route(
            "/api/v1/profiles",
            get(profiles::list).post(profiles::create),
        )
        .route(
            "/api/v1/profiles/{id}",
            get(profiles::get_one).patch(profiles::patch),
        )
        .route("/api/v1/profiles/{id}/validate", post(profiles::validate))
        .route("/api/v1/profiles/{id}/activate", post(profiles::activate))
        .route("/api/v1/profiles/{id}/revisions", get(profiles::revisions))
        .route("/api/v1/revisions/{id}", get(profiles::revision))
        .route("/api/v1/revisions/{id}/restore", post(profiles::restore))
        .route("/api/v1/jobs/{id}", get(profiles::job))
        .route("/api/v1/diagnostics/explain", post(profiles::explain))
        .route(
            "/api/v1/telemetry/settings",
            get(telemetry::get_settings).patch(telemetry::patch_settings),
        )
        .route("/api/v1/telemetry/preview", get(telemetry::preview))
        .route("/api/v1/audit", get(system::audit))
        .route("/api/v1/network/vpn/capabilities", get(vpn::capabilities))
        .route("/api/v1/network/vpn/status", get(vpn::status))
        .route("/api/v1/network/apps", get(vpn::apps))
        .route("/api/v1/network/policy/preview", post(vpn::preview))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
}

/// Run blocking store/coordinator work off the async runtime.
pub async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| ApiError::unavailable())?
}

#[derive(serde::Deserialize)]
pub struct Page {
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

impl Page {
    pub fn limit(&self) -> Result<u32, ApiError> {
        match self.limit {
            None => Ok(25),
            Some(l) if (1..=100).contains(&l) => Ok(l),
            Some(_) => Err(ApiError::bad_request("invalid_limit")),
        }
    }

    pub fn position(
        &self,
        ctx: &ManagementContext,
        kind: &str,
        p: &Principal,
    ) -> Result<Option<Value>, ApiError> {
        match &self.cursor {
            None => Ok(None),
            Some(c) => crate::cursor::decode(&ctx.cursor_key, kind, &p.id, c)
                .map(Some)
                .ok_or_else(|| ApiError::bad_request("invalid_cursor")),
        }
    }
}

pub fn next_cursor(
    ctx: &ManagementContext,
    kind: &str,
    p: &Principal,
    full: bool,
    pos: Option<Value>,
) -> Value {
    match (full, pos) {
        (true, Some(pos)) => {
            Value::String(crate::cursor::encode(&ctx.cursor_key, kind, &p.id, pos))
        }
        _ => Value::Null,
    }
}

/// OpenAPI `Job` representation.
pub fn job_json(j: &JobRow) -> Value {
    let mut v = json!({
        "id": j.id,
        "kind": j.kind,
        "status": j.status,
        "target_type": j.target_type,
        "target_id": j.target_id,
        "commit_state": j.commit_state,
        "created_at": rfc3339(j.created_at),
        "deadline_at": rfc3339(j.deadline_at),
        "safe_error_code": j.safe_error_code,
    });
    let o = v.as_object_mut().expect("object");
    if j.target_type == "profile" {
        if let Some(r) = &j.target_revision_id {
            o.insert("target_revision_id".into(), json!(r));
        }
        if let Some(d) = &j.config_digest {
            o.insert("config_digest".into(), json!(d));
        }
        if let Some(e) = &j.expected_profile_etag {
            o.insert("expected_profile_etag".into(), json!(e));
        }
        o.insert(
            "expected_active_revision_id".into(),
            json!(j.expected_active_revision_id),
        );
        o.insert("result_revision_id".into(), json!(j.result_revision_id));
    }
    if let Some(e) = &j.expected_node_etag {
        o.insert("expected_node_etag".into(), json!(e));
    }
    if let Some(s) = &j.superseded_by {
        o.insert("superseded_by".into(), json!(s));
    }
    v
}
