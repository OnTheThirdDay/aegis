//! Device enrollment and self-renewal, shared by the management API and the
//! public data-plane edge (`POST /enroll`, `POST /renew` on the WebSocket
//! listener). The edge path is what lets a device enroll through Cloudflare
//! or a public address while the console itself stays private.
//!
//! Both operations are CSR-only (private keys never leave the device), rate
//! limited by the same enrollment limiter, and audited without secrets.

use super::{blocking, Ctx};
use crate::http_util::ApiError;
use crate::ManagementContext;
use aegis_contracts::Role;
use aegis_core::rfc3339;
use aegis_identity::pki;
use aegis_identity::tls::{parse_certs, PeerIdentity};
use aegis_storage::{self as db, AuditInsert, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RedeemBody {
    pub token: String,
    pub node_name: String,
    pub csr_pem: String,
    #[serde(default)]
    pub server_names: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewBody {
    certificate_pem: String,
    csr_pem: String,
}

/// PEM of the device trust anchor clients must pin for the inner hop.
pub(crate) fn device_trust_anchor(ctx: &ManagementContext) -> Result<String, ApiError> {
    let bundle = ctx
        .coord
        .gate()
        .current()
        .ok_or_else(ApiError::unavailable)?;
    let reference = bundle
        .compiled
        .config
        .identity
        .trusted_client_ca
        .clone()
        .ok_or_else(|| ApiError::conflict("device_trust_unavailable"))?;
    aegis_config::secret::read(&ctx.secrets_dir, &reference)
        .map_err(|_| ApiError::conflict("device_trust_unavailable"))
}

/// Redeem a one-use invitation with a locally generated CSR.
pub(crate) async fn redeem(
    ctx: &Ctx,
    b: RedeemBody,
    owner_approved: bool,
) -> Result<Value, ApiError> {
    let permit = ctx.auth.enrollment_permit()?;
    if b.token.is_empty()
        || b.token.len() > 256
        || !aegis_identity::valid_node_id(&b.node_name)
        || b.csr_pem.len() > 16 * 1024
        || b.server_names.len() > 8
    {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let Some(ca) = ctx.enrollment_ca()? else {
        return Err(ApiError::conflict("enrollment_ca_unavailable")
            .detail("this node has no local enrollment CA configured"));
    };
    let anchor = device_trust_anchor(ctx).ok();
    let c = ctx.clone();
    blocking(move || {
        let _permit = permit;
        let store = c.coord.store();
        let verifier = db::sha256_hex(b.token.as_bytes());
        let binding = store.read(|conn| {
            Ok(conn.query_row("SELECT node_name,server_names_json FROM enrollment_tokens WHERE verifier_hash=?1 AND used_at IS NULL AND expires_at>?2",
                (&verifier, db::now_unix()), |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?))).optional()?)
        })?.ok_or_else(|| ApiError::unauthenticated().detail("invalid, used or expired invitation"))?;
        if let Some(name) = binding.0 {
            let names: Vec<String> = serde_json::from_str(&binding.1).map_err(|_| ApiError::unavailable())?;
            if name != b.node_name || names != b.server_names {
                return Err(ApiError::forbidden().detail("invitation identity binding mismatch"));
            }
        } else if !owner_approved {
            return Err(ApiError::forbidden().detail("unbound legacy invitations require owner approval"));
        }
        if store
            .read(|c| db::get_node_by_name(c, &b.node_name))?
            .is_some()
        {
            return Err(ApiError::conflict("node_name_exists"));
        }
        let owner = store.read(|c| db::enrollment_token_creator(c, &verifier))?;
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
            // Repeat the name check in the transaction: concurrent redeemers
            // cannot replace one another's device binding.
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
            db::set_node_owner(c, &node_id, owner.as_deref())?;
            db::insert_identity(
                c,
                &peer.fingerprint_hex(),
                &node_id,
                &peer.serial_hex,
                peer.not_before,
                peer.not_after,
            )?;
            db::bump_epoch(c)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: owner.as_deref(),
                    action: "node.enroll",
                    target_type: "node",
                    target_id: Some(&node_id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: json!({"role": role}),
                },
            )
        })?;
        c.coord.refresh_identities().map_err(|_| ApiError::unavailable())?;
        Ok(json!({
            "node_id": node_id,
            "certificate_pem": format!("{cert}{}",ca.cert_pem),
            "ca_certificate_pem": ca.cert_pem,
            "trust_anchor_pem": anchor,
            "expires_at": rfc3339(peer.not_after),
        }))
    })
    .await
}

/// Renew an enrolled, unexpired, unrevoked device certificate. The CSR must
/// reuse the enrolled key (proof of possession); the new certificate keeps
/// the device's name, role and owner. Old certificates stay valid until
/// they expire or the device is revoked.
pub(crate) async fn renew_self(ctx: &Ctx, body: Value) -> Result<Value, ApiError> {
    let permit = ctx.auth.enrollment_permit()?;
    let b: RenewBody =
        serde_json::from_value(body).map_err(|_| ApiError::bad_request("invalid_body"))?;
    if b.certificate_pem.len() > 16 * 1024 || b.csr_pem.len() > 16 * 1024 {
        return Err(ApiError::bad_request("invalid_body"));
    }
    let ca = ctx
        .enrollment_ca()?
        .ok_or_else(|| ApiError::conflict("enrollment_ca_unavailable"))?;
    let anchor = device_trust_anchor(ctx)?;
    let c = ctx.clone();
    blocking(move || {
        let _permit = permit;
        // Authenticate the presented certificate exactly as the data plane
        // would: chain to the device trust anchor, then registry lookup.
        let peer = aegis_identity::tls::validate_client_certificate(&b.certificate_pem, &anchor)
            .map_err(|_| ApiError::unauthenticated().detail("certificate not trusted"))?;
        let der = parse_certs(&b.certificate_pem).map_err(|_| ApiError::bad_request("invalid_certificate"))?;
        let store = c.coord.store();
        let fp = peer.fingerprint_hex();
        let row = store.read(|conn| {
            Ok(conn.query_row(
                "SELECT n.id, n.name, n.role, n.status, i.not_after FROM trusted_identities i JOIN nodes n ON n.id = i.node_id WHERE i.fingerprint = ?1 AND i.status = 'active'",
                [&fp],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)),
            ).optional()?)
        })?;
        let Some((node_id, name, role, status, not_after)) = row else {
            return Err(ApiError::unauthenticated().detail("device is not enrolled or was revoked"));
        };
        if status != "active" && status != "rotating" || not_after <= db::now_unix() || name != peer.node_id {
            return Err(ApiError::unauthenticated().detail("device is not enrolled or was revoked"));
        }
        if role != "client" {
            return Err(ApiError::forbidden().detail("only client devices renew here"));
        }
        let cert = pki::sign_renewal_csr(&ca, &b.csr_pem, der[0].as_ref(), &name, Role::Client, &[], pki::DEFAULT_NODE_VALIDITY)
            .map_err(|_| ApiError::bad_request("invalid_csr"))?;
        let new = parse_certs(&cert).map_err(|_| ApiError::unavailable())?;
        let next = PeerIdentity::from_der(new[0].as_ref()).map_err(|_| ApiError::unavailable())?;
        store.tx(|c| {
            db::rotate_node_certificate(c, &node_id, &next.fingerprint_hex(), &next.serial_hex, next.not_after)?;
            db::insert_identity(c, &next.fingerprint_hex(), &node_id, &next.serial_hex, next.not_before, next.not_after)?;
            db::bump_epoch(c)?;
            db::append_audit(c, AuditInsert {
                actor_id: None,
                action: "identity.self_renew",
                target_type: "node",
                target_id: Some(&node_id),
                decision: "allowed",
                revision_digest: None,
                metadata: json!({}),
            })
        })?;
        c.coord.refresh_identities().map_err(|_| ApiError::unavailable())?;
        Ok(json!({
            "node_id": node_id,
            "certificate_pem": format!("{cert}{}", ca.cert_pem),
            "trust_anchor_pem": anchor,
            "expires_at": rfc3339(next.not_after),
        }))
    })
    .await
}

fn respond(result: Result<Value, ApiError>, ok: u16) -> (u16, Vec<u8>) {
    match result {
        Ok(v) => (ok, serde_json::to_vec(&v).unwrap_or_default()),
        Err(e) => (
            e.status.as_u16(),
            serde_json::to_vec(&json!({
                "aegis_error_code": e.code,
                "detail": e.detail,
            }))
            .unwrap_or_default(),
        ),
    }
}

/// Data-plane edge entry: `POST /enroll` with a JSON [`RedeemBody`].
pub async fn edge_enroll(ctx: Arc<ManagementContext>, body: Vec<u8>) -> (u16, Vec<u8>) {
    let parsed = serde_json::from_slice::<RedeemBody>(&body)
        .map_err(|_| ApiError::bad_request("invalid_body"));
    let result = match parsed {
        Ok(b) => redeem(&ctx, b, false).await,
        Err(e) => Err(e),
    };
    respond(result, 201)
}

/// Data-plane edge entry: `POST /renew` with certificate + same-key CSR.
pub async fn edge_renew(ctx: Arc<ManagementContext>, body: Vec<u8>) -> (u16, Vec<u8>) {
    let result = match serde_json::from_slice::<Value>(&body) {
        Ok(v) => renew_self(&ctx, v).await,
        Err(_) => Err(ApiError::bad_request("invalid_body")),
    };
    respond(result, 200)
}
