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
                Ok(()) => ok(json!({"active": true, "minutes": minutes})),
                Err(e) => err(e),
            }
        }
        "diagnostic_status" => {
            ok(serde_json::to_value(ctx.diagnostics.status()).unwrap_or(Value::Null))
        }
        "diagnostic_stop" => {
            ctx.diagnostics.stop();
            ok(json!({"active": false}))
        }
        "metrics" => {
            ok(serde_json::to_value(ctx.metrics.snapshot((ctx.gauges)())).unwrap_or(Value::Null))
        }
        _ => err("unknown cmd"),
    }
}
