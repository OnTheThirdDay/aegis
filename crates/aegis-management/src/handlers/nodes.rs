use super::profiles::spawn_job;
use super::{blocking, job_json, next_cursor, Ctx, Page};
use crate::auth::Permission;
use crate::http_util::{
    idempotency_key, if_match, json, read_json, valid_uuid, ApiError, ApiResult,
};
use aegis_contracts::Role;
use aegis_core::rfc3339;
use aegis_identity::pki;
use aegis_identity::tls::{parse_certs, PeerIdentity};
use aegis_storage::{self as db, AuditInsert};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use base64::Engine;
use http::{header, HeaderMap, Method, StatusCode};
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

fn node_json(n: &db::NodeRow) -> Value {
    let status = match n.status.as_str() {
        "active" | "pending" | "rotating" | "revoked" | "offline" => n.status.as_str(),
        _ => "pending",
    };
    json!({"id": n.id, "name": n.name, "status": status})
}

pub async fn list(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Query(page): Query<Page>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::NodesRead)?;
    let limit = page.limit()?;
    let after = page
        .position(&ctx, "nodes", &p)?
        .and_then(|v| Some((v.get(0)?.as_i64()?, v.get(1)?.as_str()?.to_owned())));
    let c = ctx.clone();
    let rows =
        blocking(move || Ok(c.coord.store().read(|c| db::list_nodes(c, after, limit))?)).await?;
    let full = rows.len() as u32 == limit;
    let last = rows.last().map(|r| json!([r.created_at, r.id]));
    let items: Vec<Value> = rows.iter().map(node_json).collect();
    Ok(json(
        StatusCode::OK,
        &json!({"items": items, "next_cursor": next_cursor(&ctx, "nodes", &p, full, last)}),
        &[],
    ))
}

pub async fn get_one(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::GET)?;
    p.require(Permission::NodesRead)?;
    valid_uuid(&id)?;
    let n = ctx.coord.store().read(|c| db::get_node(c, &id))?;
    Ok(json(
        StatusCode::OK,
        &node_json(&n),
        &[(header::ETAG, n.etag())],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollBody {
    role: String,
    expires_in_seconds: Option<i64>,
}

/// One-use invitation: the token appears only in this response; only its
/// verifier hash is stored. A lost response is not retried; the invitation
/// simply expires.
pub async fn create_enrollment(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::NodesWrite)?;
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: EnrollBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let role = match b.role.as_str() {
        "agent" => "client",
        "gateway" => "gateway",
        _ => return Err(ApiError::bad_request("invalid_role")),
    };
    let ttl = b.expires_in_seconds.unwrap_or(600);
    if !(60..=3600).contains(&ttl) {
        return Err(ApiError::bad_request("invalid_expiry"));
    }
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let verifier = db::sha256_hex(token.as_bytes());
    let expires = db::now_unix() + ttl;
    let c = ctx.clone();
    let actor = p.id.clone();
    let role_s = role.to_owned();
    blocking(move || {
        Ok(c.coord.store().tx(|c| {
            db::insert_enrollment_token(
                c,
                &db::new_id(),
                &verifier,
                &role_s,
                expires,
                Some(&actor),
            )?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: Some(&actor),
                    action: "node.enrollment_created",
                    target_type: "node",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"role": role_s, "expires_in_seconds": ttl}),
                },
            )
        })?)
    })
    .await?;
    Ok(json(
        StatusCode::CREATED,
        &json!({"token": token, "expires_at": rfc3339(expires)}),
        &[],
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemBody {
    token: String,
    node_name: String,
    csr_pem: String,
    #[serde(default)]
    server_names: Vec<String>,
}

/// Redeem an invitation with a locally generated CSR. The private key never
/// reaches this service; subject, role, EKU and lifetime are set by the CA.
pub async fn redeem_enrollment(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: RedeemBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.token.is_empty()
        || b.token.len() > 256
        || !aegis_identity::valid_node_id(&b.node_name)
        || b.csr_pem.len() > 16 * 1024
        || b.server_names.len() > 8
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let Some(ca) = ctx.ca.clone() else {
        return Err(ApiError::conflict("enrollment_ca_unavailable")
            .detail("this node has no local enrollment CA configured"));
    };
    let c = ctx.clone();
    let out = blocking(move || {
        let store = c.coord.store();
        let verifier = db::sha256_hex(b.token.as_bytes());
        if store
            .read(|c| db::get_node_by_name(c, &b.node_name))?
            .is_some()
        {
            return Err(ApiError::conflict("node_name_exists"));
        }
        // Consume first (atomic, one-use) so a failing CSR still burns it.
        let role = store
            .tx(|c| db::consume_enrollment_token(c, &verifier, db::now_unix()))?
            .ok_or_else(|| {
                ApiError::unauthenticated().detail("invalid, used or expired invitation")
            })?;
        let role_e = if role == "gateway" {
            Role::Gateway
        } else {
            Role::Client
        };
        if role_e == Role::Gateway && b.server_names.is_empty() {
            return Err(ApiError::bad_request("server_names_required"));
        }
        let cert = pki::sign_csr(
            &ca,
            &b.csr_pem,
            &b.node_name,
            role_e,
            &b.server_names,
            pki::DEFAULT_NODE_VALIDITY,
        )
        .map_err(|_| ApiError::bad_request("invalid_csr"))?;
        let der = parse_certs(&cert).map_err(|_| ApiError::unavailable())?;
        let peer = PeerIdentity::from_der(der[0].as_ref()).map_err(|_| ApiError::unavailable())?;
        let node_id = db::new_id();
        store.tx(|c| {
            db::insert_node(
                c,
                &db::NodeRow {
                    id: node_id.clone(),
                    name: b.node_name.clone(),
                    role: role.clone(),
                    cert_fingerprint: Some(peer.fingerprint_hex()),
                    cert_serial: Some(peer.serial_hex.clone()),
                    status: "active".into(),
                    generation: 1,
                    not_after: Some(peer.not_after),
                    created_at: db::now_unix(),
                },
            )?;
            db::insert_identity(
                c,
                &peer.fingerprint_hex(),
                &node_id,
                &peer.serial_hex,
                peer.not_before,
                peer.not_after,
            )?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: None,
                    action: "node.enroll",
                    target_type: "node",
                    target_id: Some(&node_id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"role": role}),
                },
            )
        })?;
        Ok(json!({
            "node_id": node_id,
            "certificate_pem": cert,
            "ca_certificate_pem": ca.cert_pem,
            "expires_at": rfc3339(peer.not_after),
        }))
    })
    .await?;
    let _ = Duration::from_secs(0);
    Ok(json(StatusCode::CREATED, &out, &[]))
}

pub async fn revoke(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult {
    let p = ctx.authenticate(&headers, &Method::POST)?;
    p.require(Permission::IdentityRevoke)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let c = ctx.clone();
    let actor = p.id.clone();
    let path = format!("/api/v1/nodes/{id}/revoke");
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
