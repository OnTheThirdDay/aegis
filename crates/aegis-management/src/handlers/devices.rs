//! Self-service devices: any account with `devices:self` can invite (enroll)
//! its own devices, list them and revoke them. Owners and operators with
//! node permissions see every device.
//!
//! An invitation is a single code (`aegis1:<base64url JSON>`) the client app
//! imports. It carries the gateway endpoint, the inner and outer trust pins
//! and a one-use, name-bound enrollment token; nothing in it is a long-term
//! secret. The private key is generated on the device.

use super::profiles::spawn_job;
use super::{blocking, job_json, Ctx};
use crate::auth::{Permission, Principal};
use crate::http_util::{
    idempotency_key, if_match, json, read_json, valid_uuid, ApiError, ApiResult,
};
use crate::ManagementContext;
use aegis_core::rfc3339;
use aegis_storage::{self as db, AuditInsert};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use base64::Engine;
use http::{header, HeaderMap, Method, StatusCode};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};

pub const INVITE_PREFIX: &str = "aegis1:";
pub const DEFAULT_INNER_SERVER_NAME: &str = "gateway.aegis.internal";
pub const DEFAULT_EDGE_SERVER_NAME: &str = "edge.aegis.internal";

/// How devices reach this gateway; maintained by the console and by
/// integrations (Cloudflare, ACME) when they become active.
#[derive(Clone, Debug, Default, Deserialize, serde::Serialize)]
pub struct Connection {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub public_host: Option<String>,
    #[serde(default)]
    pub public_port: Option<u16>,
    /// `pinned` (local web CA) or `public` (publicly trusted edge).
    #[serde(default)]
    pub outer_trust: Option<String>,
    #[serde(default)]
    pub inner_server_name: Option<String>,
}

pub fn connection(ctx: &ManagementContext) -> Result<Connection, ApiError> {
    let v = ctx
        .coord
        .store()
        .read(|c| db::get_setting(c, "connection"))?;
    Ok(v.and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default())
}

fn can_see_all(p: &Principal) -> bool {
    p.has(Permission::NodesRead)
}

fn device_json(n: &db::NodeRow) -> Value {
    let mut v = super::nodes::node_json(n);
    v["etag"] = json!(n.etag());
    v
}

#[derive(Deserialize)]
pub struct ListQuery {
    scope: Option<String>,
}

pub async fn list(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    if !p.has(Permission::DevicesSelf) && !can_see_all(&p) {
        return Err(ApiError::forbidden());
    }
    let all = q.scope.as_deref() == Some("all");
    if all && !can_see_all(&p) {
        return Err(ApiError::forbidden());
    }
    let c = ctx.clone();
    let me = p.id.clone();
    let rows = blocking(move || {
        Ok(c.coord.store().read(|c| {
            if all {
                db::list_nodes(c, None, 100)
            } else {
                db::list_owned_nodes(c, &me)
            }
        })?)
    })
    .await?;
    let items: Vec<Value> = rows
        .iter()
        .filter(|n| n.role == "client")
        .map(device_json)
        .collect();
    Ok(json(StatusCode::OK, &json!({ "items": items }), &[]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteBody {
    name: String,
    expires_in_hours: Option<i64>,
}

/// Validated host for a device endpoint: an IP literal or canonical DNS name.
pub fn valid_public_host(h: &str) -> bool {
    h.parse::<std::net::IpAddr>()
        .is_ok_and(|ip| !ip.is_unspecified())
        || aegis_contracts::destination::normalize_domain(h).as_deref() == Ok(h)
}

fn endpoint(host: &str, port: u16, path: &str, scheme: &str) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == 443 {
        format!("{scheme}://{host}{path}")
    } else {
        format!("{scheme}://{host}:{port}{path}")
    }
}

/// How devices reach and trust this gateway right now: the non-secret part
/// of an invitation. Devices fetch it on connect to follow address changes.
pub(crate) fn current_endpoint(ctx: &ManagementContext) -> Result<Value, ApiError> {
    let conn = connection(ctx)?;
    if ctx.tunnel_only() && conn.mode.as_deref() != Some("cloudflare") {
        return Err(ApiError::conflict("tunnel_not_ready").detail(
            "this gateway accepts devices only through Cloudflare Tunnel; finish setting it up under Connectivity first, and invitations will point at the tunnel's hostname",
        ));
    }
    let host = conn
        .public_host
        .clone()
        .filter(|h| valid_public_host(h))
        .ok_or_else(|| {
            ApiError::conflict("public_address_required").detail(
                "an administrator must set the server address (Settings) before devices can be invited",
            )
        })?;
    let port = conn.public_port.unwrap_or(443);
    let anchor = super::edge::device_trust_anchor(ctx)?;
    let anchor_der = aegis_identity::tls::parse_certs(&anchor)
        .map_err(|_| ApiError::conflict("device_trust_unavailable"))?;
    let device_ca_sha256 = db::sha256_hex(anchor_der[anchor_der.len() - 1].as_ref());
    let public = conn.outer_trust.as_deref() == Some("public");
    let (outer_server_name, outer_ca_pem) = if public {
        (Value::Null, Value::Null)
    } else {
        let ca = aegis_config::secret::read(&ctx.secrets_dir, "secret://web-ca.pem")
            .map_err(|_| ApiError::conflict("edge_trust_unavailable"))?;
        (json!(DEFAULT_EDGE_SERVER_NAME), json!(ca))
    };
    Ok(json!({
        "url": endpoint(&host, port, "/agp", "wss"),
        "enroll_url": endpoint(&host, port, "/enroll", "https"),
        "server_name": conn.inner_server_name.as_deref().unwrap_or(DEFAULT_INNER_SERVER_NAME),
        "outer_server_name": outer_server_name,
        "outer_ca_pem": outer_ca_pem,
        "device_ca_sha256": device_ca_sha256,
    }))
}

pub(crate) fn invite_code(
    ctx: &ManagementContext,
    name: &str,
    token: &str,
    expires: i64,
) -> Result<(String, Value), ApiError> {
    let mut invite = current_endpoint(ctx)?;
    invite["v"] = json!(1);
    invite["name"] = json!(name);
    invite["token"] = json!(token);
    invite["expires_at"] = json!(expires);
    let code = format!(
        "{INVITE_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invite.to_string())
    );
    Ok((code, invite))
}

pub async fn invite(State(ctx): State<Ctx>, headers: HeaderMap, body: Body) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::DevicesSelf)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: InviteBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if !aegis_identity::valid_node_id(&b.name) {
        return Err(ApiError::bad_request("invalid_device_name")
            .detail("use 1-64 letters, digits, '.', '_' or '-'"));
    }
    let hours = b.expires_in_hours.unwrap_or(24);
    if !(1..=72).contains(&hours) {
        return Err(ApiError::bad_request("invalid_expiry"));
    }
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let verifier = db::sha256_hex(token.as_bytes());
    let expires = db::now_unix() + hours * 3600;
    // Build first: a missing server address must not burn a token row.
    let (code, invite) = invite_code(&ctx, &b.name, &token, expires)?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let name = b.name.clone();
    blocking(move || {
        c.coord.store().tx(|c| {
            if db::get_node_by_name(c, &name)?.is_some() {
                return Err(db::StoreError::Conflict("node name exists".into()));
            }
            let pending: i64 = c.query_row(
                "SELECT COUNT(*) FROM enrollment_tokens WHERE node_name = ?1 AND used_at IS NULL AND expires_at > ?2",
                (&name, db::now_unix()),
                |r| r.get(0),
            ).map_err(db::StoreError::from)?;
            if pending > 0 {
                return Err(db::StoreError::Conflict("invitation pending".into()));
            }
            db::insert_enrollment_token(c, &db::new_id(), &verifier, "client", expires, Some(&actor))?;
            c.execute(
                "UPDATE enrollment_tokens SET node_name=?1,server_names_json='[]' WHERE verifier_hash=?2",
                (&name, &verifier),
            ).map_err(db::StoreError::from)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: "device.invited",
                    target_type: "node",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"expires_in_hours": hours}),
                },
            )
        })
        .map_err(|e| match e {
            db::StoreError::Conflict(_) => ApiError::conflict("device_name_in_use")
                .detail("a device or pending invitation already uses this name"),
            other => ApiError::from(other),
        })
    })
    .await?;
    Ok(json(
        StatusCode::CREATED,
        &json!({
            "code": code,
            "name": invite["name"],
            "url": invite["url"],
            "expires_at": rfc3339(expires),
        }),
        &[],
    ))
}

/// Revoke one of the caller's own devices (or any, with identity:revoke).
pub async fn revoke(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let c = ctx.clone();
    let node = id.clone();
    let owner = blocking(move || Ok(c.coord.store().read(|c| db::node_owner(c, &node))?)).await?;
    let mine = owner.as_deref() == Some(p.id.as_str()) && p.has(Permission::DevicesSelf);
    if !mine && !p.has(Permission::IdentityRevoke) {
        return Err(ApiError::forbidden());
    }
    let c = ctx.clone();
    let actor = p.id.clone();
    let path = format!("/api/v1/devices/{id}/revoke");
    let job = blocking(move || {
        Ok(c.coord
            .submit_revoke(Some(&actor), &id, &etag, &key, &path)?)
    })
    .await?;
    spawn_job(&ctx, &job);
    Ok(json(
        StatusCode::ACCEPTED,
        &job_json(&job),
        &[
            (header::LOCATION, format!("/api/v1/jobs/{}", job.id)),
            (header::RETRY_AFTER, "1".into()),
        ],
    ))
}
