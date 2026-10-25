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

pub(crate) fn node_json(n: &db::NodeRow) -> Value {
    let status = match n.status.as_str() {
        "active" | "pending" | "rotating" | "revoked" | "offline" => n.status.as_str(),
        _ => "pending",
    };
    json!({
        "id": n.id,
        "name": n.name,
        "status": status,
        "role": n.role,
        "created_at": rfc3339(n.created_at),
        "certificate_expires_at": n.not_after.map(rfc3339),
    })
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
    node_name: Option<String>,
    #[serde(default)]
    server_names: Vec<String>,
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
    if b.node_name
        .as_ref()
        .is_some_and(|n| !aegis_identity::valid_node_id(n))
        || b.server_names.len() > 8
        || b.server_names
            .iter()
            .any(|n| aegis_contracts::destination::normalize_domain(n).as_ref() != Ok(n))
        || (role == "client" && !b.server_names.is_empty())
    {
        return Err(ApiError::bad_request("invalid_identity_binding"));
    }
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
            c.execute("UPDATE enrollment_tokens SET node_name=?1,server_names_json=?2 WHERE verifier_hash=?3",
                (b.node_name.as_deref(), json!(b.server_names).to_string(), &verifier))?;
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

/// Redeem an invitation with a locally generated CSR. The private key never
/// reaches this service; subject, role, EKU and lifetime are set by the CA.
pub async fn redeem_enrollment(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult {
    // A pre-migration, unbound invitation requires an authenticated owner
    // approval. New bound invitations are themselves a scoped credential.
    let owner_approved = ctx
        .authenticate(&headers, &Method::POST)
        .ok()
        .is_some_and(|p| p.has(Permission::NodesWrite));
    let v = read_json(&headers, body, &["application/json"]).await?;
    let b: super::edge::RedeemBody =
        serde_json::from_value(v).map_err(|_| ApiError::bad_request("invalid_body"))?;
    let out = super::edge::redeem(&ctx, b, owner_approved).await?;
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    csr_pem: String,
    #[serde(default)]
    server_names: Vec<String>,
}

/// Owner-approved CSR rekey with an overlap window. Old valid certificates
/// remain enrolled until their expiry; revocation always removes all of them.
pub async fn renew(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Body,
) -> ApiResult {
    let principal = ctx.authenticate(&headers, &Method::POST)?;
    principal.require(Permission::NodesWrite)?;
    valid_uuid(&id)?;
    let etag = if_match(&headers)?;
    let key = idempotency_key(&headers)?;
    let value = read_json(&headers, body, &["application/json"]).await?;
    let b: RenewBody =
        serde_json::from_value(value).map_err(|_| ApiError::bad_request("invalid_renewal"))?;
    if b.csr_pem.len() > 16384 || b.server_names.len() > 8 {
        return Err(ApiError::bad_request("invalid_renewal"));
    }
    let ca = ctx
        .enrollment_ca()?
        .ok_or_else(|| ApiError::conflict("enrollment_ca_unavailable"))?;
    let digest = aegis_config::digest_value(
        &json!({"node":id,"etag":etag,"csr_digest":db::sha256_hex(b.csr_pem.as_bytes()),"server_names":b.server_names}),
    );
    let actor = principal.id;
    let key_hash = db::sha256_hex(key.as_bytes());
    let response=blocking(move|| {
        let cached=ctx.coord.store().read(|c| {
            use db::OptionalExtension;
            Ok(c.query_row("SELECT request_digest,response_json FROM certificate_renewals WHERE actor_id=?1 AND node_id=?2 AND key_hash=?3",(&actor,&id,&key_hash),|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))).optional()?)
        })?;
        if let Some((old,response))=cached {
            if old!=digest{return Err(ApiError::conflict("idempotency_conflict"));}
            return serde_json::from_str(&response).map_err(|_|ApiError::unavailable());
        }
        let node=ctx.coord.store().read(|c|db::get_node(c,&id))?;
        if node.etag()!=etag{return Err(ApiError::precondition_failed());}
        if node.status!="active" && node.status!="rotating"{return Err(ApiError::conflict("identity_not_active"));}
        let role=if node.role=="client"{Role::Client}else{Role::Gateway};
        if role==Role::Client && !b.server_names.is_empty(){return Err(ApiError::bad_request("client_cannot_claim_dns_names"));}
        let certificate=pki::sign_csr(&ca,&b.csr_pem,&node.name,role,&b.server_names,pki::DEFAULT_NODE_VALIDITY).map_err(|_|ApiError::bad_request("invalid_csr"))?;
        let certs=parse_certs(&certificate).map_err(|_|ApiError::unavailable())?;
        let peer=PeerIdentity::from_der(certs[0].as_ref()).map_err(|_|ApiError::unavailable())?;
        let response=json!({"node_id":id,"certificate_pem":format!("{certificate}{}",ca.cert_pem),"ca_certificate_pem":ca.cert_pem,"expires_at":rfc3339(peer.not_after),"identity_version":1,"old_certificate_policy":"enrolled until expiry or node revocation"});
        ctx.coord.store().tx(|c| {
            let current=db::get_node(c,&id)?;
            if current.etag()!=etag{return Err(db::StoreError::Conflict("stale_node".into()));}
            db::rotate_node_certificate(c,&id,&peer.fingerprint_hex(),&peer.serial_hex,peer.not_after)?;
            db::insert_identity(c,&peer.fingerprint_hex(),&id,&peer.serial_hex,peer.not_before,peer.not_after)?;
            db::bump_epoch(c)?;
            c.execute("INSERT INTO certificate_renewals(actor_id,node_id,key_hash,request_digest,response_json) VALUES (?1,?2,?3,?4,?5)",(&actor,&id,&key_hash,&digest,response.to_string()))?;
            db::append_audit(c,AuditInsert{actor_id:Some(&actor),action:"identity.renew",target_type:"node",target_id:Some(&id),decision:"allowed",revision_digest:None,metadata:json!({"identity_version":1})})?;
            Ok(())
        }).map_err(|e|match e{db::StoreError::Conflict(_)=>ApiError::precondition_failed(),other=>ApiError::from(other)})?;
        ctx.coord.refresh_identities().map_err(|_|ApiError::unavailable())?;
        Ok(response)
    }).await?;
    Ok(json(StatusCode::OK, &response, &[]))
}
