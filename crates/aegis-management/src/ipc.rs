//! Local privileged IPC commands (04 §5 "Local recovery").
//!
//! These are never exposed over HTTP. The daemon serves them on a Unix
//! socket restricted to the service user and authenticates the peer's OS
//! credentials before calling [`handle`]. Requests and responses are single
//! JSON objects.

use crate::ManagementContext;
use aegis_core::{RecoveryOutcome, SupersedeRequest};
use serde_json::{json, Value};
use std::time::Duration;

pub const MAX_REQUEST: usize = 64 * 1024;

fn ok(v: Value) -> Value {
    json!({"ok": true, "result": v})
}

fn err(msg: impl Into<String>) -> Value {
    json!({"ok": false, "error": msg.into()})
}

fn outcome(o: RecoveryOutcome) -> Value {
    match o {
        RecoveryOutcome::Fresh => json!({"outcome": "fresh"}),
        RecoveryOutcome::Restored { revision_id } => {
            json!({"outcome": "restored", "revision_id": revision_id})
        }
        RecoveryOutcome::Reconciled {
            operation_id,
            revision_id,
        } => {
            json!({"outcome": "reconciled", "operation_id": operation_id, "revision_id": revision_id})
        }
        RecoveryOutcome::Blocked {
            operation_id,
            reason,
        } => {
            json!({"outcome": "blocked", "operation_id": operation_id, "reason": reason})
        }
    }
}

fn s<'a>(req: &'a Value, k: &str) -> Option<&'a str> {
    req.get(k).and_then(Value::as_str)
}

/// Dispatch one authenticated local command (blocking).
pub fn handle(ctx: &ManagementContext, req: &Value) -> Value {
    let Some(cmd) = s(req, "cmd") else {
        return err("missing cmd");
    };
    match cmd {
        "config_inspect" => match ctx.coord.gate().current() {
            Some(bundle) => ok(
                json!({"revision_id":bundle.revision_id,"digest":bundle.digest,"specification":aegis_config::to_json(&bundle.compiled.config)}),
            ),
            None => err("no_active_configuration"),
        },
        "certificate_reload" => {
            let reload = ctx
                .certificate_reload
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            match reload.map(|f| f()) {
                Some(Ok(())) => ok(
                    json!({"reloaded":true,"existing_sessions":"retain established TLS; revocation affects all"}),
                ),
                Some(Err(_)) => err("replacement_identity_rejected"),
                None => err("certificate_reload_unavailable"),
            }
        }
        "config_apply" => config_apply(ctx, req),
        "identity_register" => identity_register(ctx, req),
        "health" => ok(serde_json::to_value(ctx.coord.health()).unwrap_or(Value::Null)),
        "bootstrap_token" => match ctx.create_bootstrap_token() {
            Ok((token, expires)) => {
                ok(json!({"bootstrap_token": token, "expires_at": aegis_core::rfc3339(expires)}))
            }
            Err(e) => err(e),
        },
        "token_create" => {
            let scopes = req.get("scopes").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            });
            let ttl = req
                .get("ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(900);
            match ctx.mint_bearer(scopes, Duration::from_secs(ttl)) {
                Ok((token, expires)) => {
                    ok(json!({"token": token, "expires_at": aegis_core::rfc3339(expires)}))
                }
                Err(e) => err(e),
            }
        }
        "activation_inspect" => match ctx.coord.inspect() {
            Ok(v) => ok(v),
            Err(e) => err(e.to_string()),
        },
        "activation_reconcile" => match s(req, "operation_id") {
            Some(op) => match ctx.coord.reconcile(op) {
                Ok(o) => ok(outcome(o)),
                Err(e) => err(e.to_string()),
            },
            None => err("operation_id required"),
        },
        "activation_supersede" => {
            let (Some(pending), Some(rev), Some(digest), Some(reason), Some(epoch)) = (
                s(req, "pending_operation_id"),
                s(req, "recovery_revision_id"),
                s(req, "recovery_config_digest"),
                s(req, "reason"),
                req.get("expected_security_epoch").and_then(Value::as_i64),
            ) else {
                return err("pending_operation_id, expected_runtime_revision_id, expected_security_epoch, recovery_revision_id, recovery_config_digest and reason are required");
            };
            let expected_runtime = match req.get("expected_runtime_revision_id") {
                Some(Value::String(r)) => Some(r.clone()),
                Some(Value::Null) => None,
                _ => return err("expected_runtime_revision_id must be a string or null"),
            };
            let owner = ctx
                .coord
                .store()
                .read(|c| {
                    Ok(c.query_row(
                        "SELECT principal_id FROM principal_roles WHERE role = 'owner' LIMIT 1",
                        [],
                        |r| r.get::<_, String>(0),
                    )
                    .ok())
                })
                .ok()
                .flatten();
            let r = SupersedeRequest {
                actor_id: owner,
                pending_operation_id: pending.into(),
                expected_runtime_revision_id: expected_runtime,
                expected_security_epoch: epoch,
                recovery_revision_id: rev.into(),
                recovery_config_digest: digest.into(),
                reason: reason.into(),
            };
            match ctx.coord.supersede(&r) {
                Ok(job) => ok(
                    json!({"job_id": job.id, "status": job.status, "operation_id": job.operation_id}),
                ),
                Err(e) => err(e.to_string()),
            }
        }
        "diagnostic_start" => {
            let minutes = req.get("minutes").and_then(Value::as_u64).unwrap_or(5);
            match ctx
                .diagnostics
                .start(Duration::from_secs(minutes.saturating_mul(60)))
            {
                Ok(()) => {
                    ctx.device_reports.clear();
                    ok(json!({"active": true, "minutes": minutes}))
                }
                Err(e) => err(e),
            }
        }
        "diagnostic_status" => {
            ok(serde_json::to_value(ctx.diagnostics.status()).unwrap_or(Value::Null))
        }
        "diagnostic_stop" => {
            ctx.diagnostics.stop();
            ok(serde_json::to_value(ctx.diagnostics.status()).unwrap_or(Value::Null))
        }
        "diagnostic_discard" => {
            ctx.diagnostics.discard();
            ctx.device_reports.clear();
            ok(json!({"state": "off"}))
        }
        "metrics" => {
            ok(serde_json::to_value(ctx.metrics.snapshot((ctx.gauges)())).unwrap_or(Value::Null))
        }
        _ => err("unknown cmd"),
    }
}

fn config_apply(ctx: &ManagementContext, req: &Value) -> Value {
    let Some(spec) = req.get("specification") else {
        return err("specification required");
    };
    let Ok(cfg) = aegis_config::parse_json(spec) else {
        return err("invalid_configuration");
    };
    let Some(active) = ctx.coord.gate().current() else {
        return err("no_active_configuration");
    };
    let digest = aegis_config::config_digest(&cfg);
    if digest == active.digest {
        return ok(json!({"applied":true,"revision_id":active.revision_id}));
    }
    if req["expected_revision"].as_str() != Some(active.revision_id.as_str()) {
        return err("stale_config_revision");
    }
    if !aegis_config::security_diff(Some(&active.compiled.config), &cfg)
        .restart_required
        .is_empty()
    {
        return err("restart_required");
    }
    let result = (|| {
        let profile = ctx
            .coord
            .store()
            .read(|c| aegis_storage::get_profile(c, &active.profile_id))?;
        let p = ctx
            .coord
            .patch_profile(None, &profile.id, &profile.etag(), None, Some(spec))?;
        let validation = ctx
            .coord
            .validate(None, &p.id, &p.etag(), &p.desired_revision_id)?;
        if !validation.valid {
            return Err(aegis_core::CoordinatorError::Invalid(validation.errors));
        }
        let key = s(req, "operation_key").ok_or(aegis_core::CoordinatorError::Conflict(
            "operation_key required",
        ))?;
        let job = ctx.coord.submit_activation(
            &aegis_core::ActivateRequest {
                actor_id: None,
                profile_id: p.id.clone(),
                if_match: p.etag(),
                idempotency_key: key.into(),
                target_revision_id: p.desired_revision_id,
                config_digest: validation.config_digest,
                validation_id: validation.validation_id,
            },
            &format!("/local/profiles/{}/activate", p.id),
        )?;
        ctx.coord.run_job(&job.id)
    })();
    match result {
        Ok(job) => ok(
            json!({"applied":job.status=="succeeded","job_id":job.id,"revision_id":job.result_revision_id}),
        ),
        Err(_) => err("configuration_activation_failed"),
    }
}

/// Authenticated local forwarding to the same REST router. This makes every
/// management API usable through Docker exec on Mac without publishing an
/// admin port or adding a privileged management network bridge.
pub async fn dispatch(ctx: std::sync::Arc<ManagementContext>, req: Value) -> Value {
    if s(&req, "cmd") != Some("api") {
        return tokio::task::spawn_blocking(move || handle(&ctx, &req))
            .await
            .unwrap_or_else(|_| err("internal"));
    }
    use tower::ServiceExt;
    let Some(path) = s(&req, "path").filter(|p| p.starts_with("/api/v1/") && p.len() <= 2048)
    else {
        return err("invalid_api_path");
    };
    let method = s(&req, "method").unwrap_or("GET");
    let mut request = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", format!("127.0.0.1:{}", ctx.bind.port()))
        .header("content-type", "application/json");
    if !matches!(
        path,
        "/api/v1/bootstrap/claim" | "/api/v1/nodes/enrollment/redeem" | "/api/v1/auth/login"
    ) {
        let token = match ctx.mint_bearer(None, Duration::from_secs(60)) {
            Ok((token, _)) => token,
            Err(_) => return err("owner_bootstrap_required"),
        };
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(headers) = req["headers"].as_object() {
        for name in [
            "if-match",
            "idempotency-key",
            "x-aegis-export-preview-digest",
        ] {
            if let Some(value) = headers.get(name).and_then(Value::as_str) {
                request = request.header(name, value);
            }
        }
    }
    let body = req
        .get("body")
        .filter(|v| !v.is_null())
        .map(Value::to_string)
        .unwrap_or_default();
    let Ok(request) = request.body(axum::body::Body::from(body)) else {
        return err("invalid_api_request");
    };
    let response = match crate::router(ctx).oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let status = response.status().as_u16();
    let headers: serde_json::Map<String, Value> = response
        .headers()
        .iter()
        .filter(|(k, _)| matches!(k.as_str(), "etag" | "location" | "retry-after"))
        .filter_map(|(k, v)| Some((k.as_str().into(), json!(v.to_str().ok()?))))
        .collect();
    let Ok(bytes) = axum::body::to_bytes(response.into_body(), 1024 * 1024).await else {
        return err("api_response_limit");
    };
    ok(
        json!({"status":status,"headers":headers,"body":serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null)}),
    )
}

#[cfg(unix)]
pub async fn serve(
    ctx: std::sync::Arc<ManagementContext>,
    path: std::path::PathBuf,
) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() {
            return Err(std::io::Error::other("IPC path is not an owned socket"));
        }
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "IPC is already serving",
            ));
        }
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(&path)?.uid();
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let Ok(permit) = std::sync::Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        if !stream.peer_cred().is_ok_and(|p| p.uid() == owner) {
            continue;
        }
        let ctx = std::sync::Arc::clone(&ctx);
        tokio::spawn(async move {
            let _permit = permit;
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..n]);
                    if bytes.len() > MAX_REQUEST {
                        return Err(std::io::Error::other("request limit"));
                    }
                    if bytes.contains(&b'\n') {
                        break;
                    }
                }
                Ok(bytes)
            })
            .await;
            let Ok(Ok(bytes)) = result else {
                return;
            };
            let Ok(req) = serde_json::from_slice(bytes.trim_ascii()) else {
                return;
            };
            let response = dispatch(ctx, req).await;
            let Ok(mut bytes) = serde_json::to_vec(&response) else {
                return;
            };
            bytes.push(b'\n');
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&bytes)).await;
        });
    }
}

fn identity_register(ctx: &ManagementContext, req: &Value) -> Value {
    let Some(cert) = s(req, "certificate_pem") else {
        return err("certificate_required");
    };
    if cert.len() > 64 * 1024 {
        return err("certificate_too_large");
    }
    let result = (|| -> Result<_, String> {
        let bundle = ctx
            .coord
            .gate()
            .current()
            .ok_or("configuration_unavailable")?;
        let ca = bundle
            .compiled
            .config
            .identity
            .trusted_client_ca
            .as_ref()
            .ok_or("client_ca_unavailable")?;
        let ca = aegis_config::secret::read(&ctx.secrets_dir, ca)
            .map_err(|_| "client_ca_unavailable")?;
        let peer = aegis_identity::tls::validate_client_certificate(cert, &ca)
            .map_err(|_| "invalid_device_certificate")?;
        let node_id = ctx
            .coord
            .store()
            .tx(|c| {
                if let Some(existing) = aegis_storage::get_node_by_name(c, &peer.node_id)? {
                    if existing.status != "active" || existing.role != "client" {
                        return Err(aegis_storage::StoreError::Conflict(
                            "identity_requires_approved_renewal".into(),
                        ));
                    }
                    if existing.cert_fingerprint.as_deref() != Some(peer.fingerprint_hex().as_str())
                    {
                        if req["replace"] != true {
                            return Err(aegis_storage::StoreError::Conflict(
                                "identity_requires_approved_renewal".into(),
                            ));
                        }
                        aegis_storage::rotate_node_certificate(
                            c,
                            &existing.id,
                            &peer.fingerprint_hex(),
                            &peer.serial_hex,
                            peer.not_after,
                        )?;
                        aegis_storage::insert_identity(
                            c,
                            &peer.fingerprint_hex(),
                            &existing.id,
                            &peer.serial_hex,
                            peer.not_before,
                            peer.not_after,
                        )?;
                        aegis_storage::bump_epoch(c)?;
                        aegis_storage::append_audit(
                            c,
                            aegis_storage::AuditInsert {
                                actor_id: None,
                                action: "identity.local_renew",
                                target_type: "node",
                                target_id: Some(&existing.id),
                                decision: "allowed",
                                revision_digest: None,
                                metadata: json!({"identity_version":1}),
                            },
                        )?;
                    }
                    return Ok(existing.id);
                }
                let id = aegis_storage::new_id();
                aegis_storage::insert_node(
                    c,
                    &aegis_storage::NodeRow {
                        id: id.clone(),
                        name: peer.node_id.clone(),
                        role: "client".into(),
                        cert_fingerprint: Some(peer.fingerprint_hex()),
                        cert_serial: Some(peer.serial_hex.clone()),
                        status: "active".into(),
                        generation: 1,
                        not_after: Some(peer.not_after),
                        created_at: aegis_storage::now_unix(),
                    },
                )?;
                aegis_storage::insert_identity(
                    c,
                    &peer.fingerprint_hex(),
                    &id,
                    &peer.serial_hex,
                    peer.not_before,
                    peer.not_after,
                )?;
                aegis_storage::bump_epoch(c)?;
                aegis_storage::append_audit(
                    c,
                    aegis_storage::AuditInsert {
                        actor_id: None,
                        action: "identity.local_register",
                        target_type: "node",
                        target_id: Some(&id),
                        decision: "allowed",
                        revision_digest: None,
                        metadata: json!({"identity_version":if peer.san_identity{1}else{0}}),
                    },
                )?;
                Ok(id)
            })
            .map_err(|_| "identity_registration_conflict")?;
        ctx.coord
            .refresh_identities()
            .map_err(|_| "identity_publication_failed")?;
        Ok(json!({"node_id":node_id,"expires_at":aegis_core::rfc3339(peer.not_after)}))
    })();
    match result {
        Ok(v) => ok(v),
        Err(code) => err(code),
    }
}
