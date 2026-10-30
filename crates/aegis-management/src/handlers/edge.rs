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
            .is_some_and(|n| n.status != "revoked")
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
            // cannot replace one another's device binding. A revoked
            // device's record gives up its name.
            if !db::release_revoked_name(c, &b.node_name)? {
                return Err(db::StoreError::Conflict("node name exists".into()));
            }
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

/// How long after expiry a device may still renew: a laptop that stayed
/// offline past its certificate's lifetime reconnects without a new
/// invitation, as long as it still holds its key and wasn't revoked.
pub(crate) const RENEW_GRACE_SECONDS: i64 = 90 * 86_400;

/// Renew an enrolled, unrevoked device certificate that is unexpired or
/// expired within [`RENEW_GRACE_SECONDS`]. The CSR must reuse the enrolled
/// key (proof of possession); the new certificate keeps the device's name,
/// role and owner. Old certificates stay valid until they expire or the
/// device is revoked.
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
        let device = authenticate_device(&c, &anchor, &b.certificate_pem, RENEW_GRACE_SECONDS)?;
        let expired_for = (db::now_unix() - device.not_after).max(0);
        let (node_id, name, der) = (device.node_id, device.name, device.der);
        let store = c.coord.store();
        let cert = pki::sign_renewal_csr(
            &ca,
            &b.csr_pem,
            &der,
            &name,
            Role::Client,
            &[],
            pki::DEFAULT_NODE_VALIDITY,
        )
        .map_err(|_| ApiError::bad_request("invalid_csr"))?;
        let new = parse_certs(&cert).map_err(|_| ApiError::unavailable())?;
        let next = PeerIdentity::from_der(new[0].as_ref()).map_err(|_| ApiError::unavailable())?;
        store.tx(|c| {
            db::rotate_node_certificate(
                c,
                &node_id,
                &next.fingerprint_hex(),
                &next.serial_hex,
                next.not_after,
            )?;
            db::insert_identity(
                c,
                &next.fingerprint_hex(),
                &node_id,
                &next.serial_hex,
                next.not_before,
                next.not_after,
            )?;
            db::bump_epoch(c)?;
            db::append_audit(
                c,
                AuditInsert {
                    actor_id: None,
                    action: "identity.self_renew",
                    target_type: "node",
                    target_id: Some(&node_id),
                    decision: "allowed",
                    revision_digest: None,
                    metadata: if expired_for > 0 {
                        json!({"expired_for_seconds": expired_for})
                    } else {
                        json!({})
                    },
                },
            )
        })?;
        c.coord
            .refresh_identities()
            .map_err(|_| ApiError::unavailable())?;
        Ok(json!({
            "node_id": node_id,
            "certificate_pem": format!("{cert}{}", ca.cert_pem),
            "trust_anchor_pem": anchor,
            "expires_at": rfc3339(next.not_after),
        }))
    })
    .await
}

/// A client device authenticated by its certificate.
pub(crate) struct Device {
    pub node_id: String,
    pub name: String,
    /// Leaf certificate DER.
    pub der: Vec<u8>,
    /// Unix seconds.
    pub not_after: i64,
}

/// Authenticate a presented device certificate exactly as the data plane
/// would: chain to the device trust anchor, then registry lookup. Blocking.
///
/// `grace` seconds after expiry, the certificate is still accepted, checked
/// as of its last valid second (only for renewal; 0 everywhere else).
pub(crate) fn authenticate_device(
    ctx: &ManagementContext,
    anchor: &str,
    certificate_pem: &str,
    grace: i64,
) -> Result<Device, ApiError> {
    let untrusted = || ApiError::unauthenticated().detail("certificate not trusted");
    let now = db::now_unix();
    let peer = match aegis_identity::tls::validate_client_certificate(certificate_pem, anchor) {
        Ok(peer) => peer,
        Err(_) if grace > 0 => {
            // Expired within the grace period: validate the chain as of the
            // certificate's last valid second instead.
            let der = parse_certs(certificate_pem).map_err(|_| untrusted())?;
            let leaf = PeerIdentity::from_der(der[0].as_ref()).map_err(|_| untrusted())?;
            let at = grace_validation_time(leaf.not_after, now, grace).ok_or_else(untrusted)?;
            aegis_identity::tls::validate_client_certificate_at(certificate_pem, anchor, at)
                .map_err(|_| untrusted())?
        }
        Err(_) => return Err(untrusted()),
    };
    let der =
        parse_certs(certificate_pem).map_err(|_| ApiError::bad_request("invalid_certificate"))?;
    let fp = peer.fingerprint_hex();
    let row = ctx.coord.store().read(|conn| {
        Ok(conn.query_row(
            "SELECT n.id, n.name, n.role, n.status, i.not_after FROM trusted_identities i JOIN nodes n ON n.id = i.node_id WHERE i.fingerprint = ?1 AND i.status = 'active'",
            [&fp],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, i64>(4)?)),
        ).optional()?)
    })?;
    let Some((node_id, name, role, status, not_after)) = row else {
        return Err(ApiError::unauthenticated().detail("device is not enrolled or was revoked"));
    };
    if status != "active" && status != "rotating"
        || not_after.saturating_add(grace) <= now
        || name != peer.node_id
    {
        return Err(ApiError::unauthenticated().detail("device is not enrolled or was revoked"));
    }
    if role != "client" {
        return Err(ApiError::forbidden().detail("only client devices renew here"));
    }
    Ok(Device {
        node_id,
        name,
        der: der[0].as_ref().to_vec(),
        not_after: peer.not_after,
    })
}

/// For a certificate that expired at `not_after`, `grace` seconds or less
/// before `now`: the time to validate its chain at (its last valid second).
fn grace_validation_time(not_after: i64, now: i64, grace: i64) -> Option<i64> {
    (not_after < now && now - not_after <= grace).then(|| not_after - 1)
}

/// Note a failed edge request in a running diagnostics recording.
fn note_failure(ctx: &ManagementContext, request: &str, result: &Result<Value, ApiError>) {
    if let Err(e) = result {
        if ctx.diagnostics.is_recording() {
            let error = match &e.detail {
                Some(d) => format!("{}: {d}", e.code),
                None => e.code.to_string(),
            };
            ctx.diagnostics.note(
                aegis_telemetry::Severity::Warn,
                "edge.failed",
                &[("request", request), ("error", &error)],
            );
        }
    }
}

const JSON: &str = "application/json";

/// An edge reply: status, content type, body.
pub type EdgeReply = (u16, &'static str, Vec<u8>);

fn respond(result: Result<Value, ApiError>, ok: u16) -> EdgeReply {
    match result {
        Ok(v) => (ok, JSON, serde_json::to_vec(&v).unwrap_or_default()),
        Err(e) => failed(&e),
    }
}

fn failed(e: &ApiError) -> EdgeReply {
    (
        e.status.as_u16(),
        JSON,
        serde_json::to_vec(&json!({
            "aegis_error_code": e.code,
            "detail": e.detail,
        }))
        .unwrap_or_default(),
    )
}

/// Data-plane edge entry: `POST /enroll` with a JSON [`RedeemBody`].
pub async fn edge_enroll(ctx: Arc<ManagementContext>, body: Vec<u8>) -> EdgeReply {
    let parsed = serde_json::from_slice::<RedeemBody>(&body)
        .map_err(|_| ApiError::bad_request("invalid_body"));
    let result = match parsed {
        Ok(b) => redeem(&ctx, b, false).await,
        Err(e) => Err(e),
    };
    note_failure(&ctx, "enroll", &result);
    respond(result, 201)
}

/// The gateway's current device endpoint, for an enrolled device
/// (`endpoint_query`). Not secret, so only the certificate is checked and
/// the enrollment rate limit is not spent: every device asks on connect.
/// Devices adopt a changed endpoint only after the gateway's pinned inner
/// identity verifies there, so a tampered answer can't redirect them.
async fn endpoint_query(ctx: &Ctx, body: Value) -> Result<Value, ApiError> {
    let certificate_pem = body
        .get("certificate_pem")
        .and_then(Value::as_str)
        .filter(|p| p.len() <= 16 * 1024)
        .ok_or_else(|| ApiError::bad_request("invalid_body"))?
        .to_owned();
    let anchor = device_trust_anchor(ctx)?;
    let c = ctx.clone();
    blocking(move || {
        authenticate_device(&c, &anchor, &certificate_pem, 0)?;
        Ok(json!({ "endpoint": super::devices::current_endpoint(&c)? }))
    })
    .await
}

/// Download piece size; devices ask for exactly this much at a time
/// (`aegis_join::update::CHUNK`).
const UPDATE_CHUNK: u64 = 1024 * 1024;

/// The client builds this gateway offers as app updates: those with a
/// description signed by the release workflow next to them (`FILE.update`,
/// ADR-0017). Devices check the signature; the gateway only serves them.
fn signed_builds(ctx: &ManagementContext) -> Vec<(Value, std::path::PathBuf)> {
    let dir = ctx
        .downloads_dir
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let Some(entries) = dir.as_ref().and_then(|d| std::fs::read_dir(d).ok()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("update") {
            continue;
        }
        let Some(v) = std::fs::metadata(&path)
            .ok()
            .filter(|m| m.is_file() && m.len() <= 4096)
            .and_then(|_| std::fs::read(&path).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        else {
            continue;
        };
        let build = path.with_extension("");
        let same_file = build.file_name().and_then(|n| n.to_str()) == v["file"].as_str();
        let size_ok = std::fs::symlink_metadata(&build)
            .is_ok_and(|m| m.is_file() && Some(m.len()) == v["size"].as_u64());
        if same_file && size_ok {
            out.push((v, build));
        }
    }
    out
}

/// `X.Y.Z` for picking the latest of several builds for one platform; a
/// release sorts after its pre-releases.
fn version_key(v: &Value) -> (Vec<u64>, bool) {
    let s = v["version"].as_str().unwrap_or("");
    let (core, release) = match s.split_once('-') {
        Some((c, _)) => (c, false),
        None => (s, true),
    };
    (
        core.split('.').map(|p| p.parse().unwrap_or(0)).collect(),
        release,
    )
}

fn device_certificate(body: &Value) -> Result<String, ApiError> {
    body.get("certificate_pem")
        .and_then(Value::as_str)
        .filter(|p| p.len() <= 16 * 1024)
        .map(str::to_owned)
        .ok_or_else(|| ApiError::bad_request("invalid_body"))
}

/// The latest app build for the device's platform (`update_query`), or
/// null. Like the endpoint query: not secret, certificate checked, no rate
/// limit spent. For `ios`, also the iPhone app this gateway serves, with an
/// install link (`ios`): iOS updates install like the first install.
async fn update_query(ctx: &Ctx, body: Value) -> Result<Value, ApiError> {
    let certificate_pem = device_certificate(&body)?;
    let platform = body["update_query"]["platform"]
        .as_str()
        .filter(|p| !p.is_empty() && p.len() <= 32)
        .ok_or_else(|| ApiError::bad_request("invalid_body"))?
        .to_owned();
    let anchor = device_trust_anchor(ctx)?;
    let c = ctx.clone();
    let ios = platform == "ios";
    let (latest, device) = blocking(move || {
        let device = authenticate_device(&c, &anchor, &certificate_pem, 0)?;
        let latest = signed_builds(&c)
            .into_iter()
            .map(|(v, _)| v)
            .filter(|v| v["platform"].as_str() == Some(platform.as_str()))
            .max_by_key(version_key);
        Ok((latest, device.node_id))
    })
    .await?;
    let offer = if ios {
        super::ios::device_offer(ctx, &device).await
    } else {
        None
    };
    Ok(json!({ "update": latest, "ios": offer }))
}

/// One piece of a signed app build (`update_download`: file and offset).
async fn update_download(ctx: &Ctx, body: Value) -> Result<Vec<u8>, ApiError> {
    use std::io::{Read, Seek};
    let certificate_pem = device_certificate(&body)?;
    let request = &body["update_download"];
    let (Some(file), Some(offset)) = (request["file"].as_str(), request["offset"].as_u64()) else {
        return Err(ApiError::bad_request("invalid_body"));
    };
    let file = file.to_owned();
    let anchor = device_trust_anchor(ctx)?;
    let c = ctx.clone();
    blocking(move || {
        authenticate_device(&c, &anchor, &certificate_pem, 0)?;
        let (v, path) = signed_builds(&c)
            .into_iter()
            .find(|(v, _)| v["file"].as_str() == Some(file.as_str()))
            .ok_or_else(|| ApiError::bad_request("unknown_update"))?;
        let size = v["size"].as_u64().unwrap_or(0);
        if offset >= size {
            return Err(ApiError::bad_request("invalid_offset"));
        }
        let mut piece = vec![0u8; (size - offset).min(UPDATE_CHUNK) as usize];
        let mut f =
            std::fs::File::open(&path).map_err(|_| ApiError::bad_request("unknown_update"))?;
        f.seek(std::io::SeekFrom::Start(offset))
            .and_then(|_| f.read_exact(&mut piece))
            .map_err(|_| ApiError::bad_request("unknown_update"))?;
        Ok(piece)
    })
    .await
}

/// Data-plane edge entry for device-authenticated requests on `POST /renew`:
/// certificate + same-key CSR (renewal), a signed diagnostic report
/// (`diagnostic_report_gz`), an endpoint query (`endpoint_query`), or an app
/// update query or download (`update_query`, `update_download`). They share
/// this path so existing tunnel ingress rules keep matching.
pub async fn edge_renew(ctx: Arc<ManagementContext>, body: Vec<u8>) -> EdgeReply {
    let parsed = serde_json::from_slice::<Value>(&body);
    if let Ok(v) = &parsed {
        if v.get("update_download").is_some() {
            return match update_download(&ctx, v.clone()).await {
                Ok(piece) => (200, "application/octet-stream", piece),
                Err(e) => {
                    let reply = failed(&e);
                    note_failure(&ctx, "update_download", &Err::<Value, _>(e));
                    reply
                }
            };
        }
    }
    let (request, result) = match parsed {
        Ok(v) if v.get("update_query").is_some() => ("update_query", update_query(&ctx, v).await),
        Ok(v) if v.get("diagnostic_report_gz").is_some() => (
            "diagnostic_report",
            super::diagnostics::device_report(&ctx, v).await,
        ),
        Ok(v) if v.get("endpoint_query").is_some() => {
            ("endpoint_query", endpoint_query(&ctx, v).await)
        }
        Ok(v) => ("renew", renew_self(&ctx, v).await),
        Err(_) => ("renew", Err(ApiError::bad_request("invalid_body"))),
    };
    note_failure(&ctx, request, &result);
    respond(result, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_renewal_window() {
        let day = 86_400;
        let exp = 1_000 * day;
        assert_eq!(
            grace_validation_time(exp, exp - 1, RENEW_GRACE_SECONDS),
            None,
            "not expired"
        );
        assert_eq!(
            grace_validation_time(exp, exp + 30 * day, RENEW_GRACE_SECONDS),
            Some(exp - 1)
        );
        assert_eq!(
            grace_validation_time(exp, exp + RENEW_GRACE_SECONDS, RENEW_GRACE_SECONDS),
            Some(exp - 1)
        );
        assert_eq!(
            grace_validation_time(exp, exp + RENEW_GRACE_SECONDS + 1, RENEW_GRACE_SECONDS),
            None,
            "too late"
        );
        assert_eq!(
            grace_validation_time(exp, exp + 1, 0),
            None,
            "no grace elsewhere"
        );
    }
}
