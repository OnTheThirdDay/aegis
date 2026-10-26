//! Forward-only, checksummed migrations.

use crate::{Result, StoreError};
use rusqlite::Connection;
use sha2::{Digest, Sha256};

const MIGRATIONS: &[(i64, &str)] = &[
    (
        1,
        r#"
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE principal_roles (
    principal_id TEXT NOT NULL REFERENCES principals(id),
    role TEXT NOT NULL,
    PRIMARY KEY (principal_id, role)
);
CREATE TABLE bootstrap_tokens (
    id TEXT PRIMARY KEY,
    verifier_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);
CREATE TABLE security_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL
);
INSERT INTO security_state (id, epoch) VALUES (1, 1);
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    cert_fingerprint TEXT,
    cert_serial TEXT,
    status TEXT NOT NULL,
    generation INTEGER NOT NULL,
    not_after INTEGER,
    created_at INTEGER NOT NULL
);
CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    verifier_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL,
    used_at INTEGER,
    created_by TEXT
);
CREATE TABLE trusted_identities (
    fingerprint TEXT PRIMARY KEY,
    node_id TEXT NOT NULL REFERENCES nodes(id),
    serial TEXT NOT NULL,
    status TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    revoked_at INTEGER,
    revoked_epoch INTEGER
);
CREATE TABLE profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    desired_revision_id TEXT NOT NULL,
    active_revision_id TEXT,
    generation INTEGER NOT NULL,
    owner_id TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE revisions (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    parent_id TEXT,
    spec_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    actor_id TEXT,
    created_at INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    state TEXT NOT NULL
);
CREATE INDEX revisions_by_profile ON revisions (profile_id, seq DESC);
CREATE TABLE validation_reports (
    id TEXT PRIMARY KEY,
    profile_id TEXT NOT NULL,
    target_revision_id TEXT NOT NULL,
    config_digest TEXT NOT NULL,
    profile_etag TEXT NOT NULL,
    capability_digest TEXT NOT NULL,
    security_epoch INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    valid INTEGER NOT NULL,
    actor_id TEXT,
    report_json TEXT NOT NULL
);
CREATE TABLE jobs (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    actor_id TEXT,
    status TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    target_revision_id TEXT,
    config_digest TEXT,
    validation_id TEXT,
    expected_profile_etag TEXT,
    expected_active_revision_id TEXT,
    expected_node_etag TEXT,
    commit_state TEXT NOT NULL,
    operation_id TEXT,
    deadline_at INTEGER NOT NULL,
    result_revision_id TEXT,
    superseded_by TEXT,
    safe_error_code TEXT,
    created_at INTEGER NOT NULL
);
CREATE TABLE activation_intents (
    operation_id TEXT PRIMARY KEY,
    job_id TEXT,
    profile_id TEXT NOT NULL,
    target_revision_id TEXT NOT NULL,
    expected_active_revision_id TEXT,
    config_digest TEXT NOT NULL,
    security_epoch INTEGER NOT NULL,
    commit_state TEXT NOT NULL,
    committed_at INTEGER NOT NULL,
    applied_at INTEGER,
    superseded_by TEXT,
    reason TEXT
);
CREATE TABLE runtime_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    applied_revision_id TEXT,
    applied_profile_id TEXT,
    applied_operation_id TEXT
);
INSERT INTO runtime_state (id) VALUES (1);
CREATE TABLE idempotency_records (
    actor_id TEXT NOT NULL,
    method TEXT NOT NULL,
    canonical_path TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    job_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (actor_id, method, canonical_path, key_hash)
);
CREATE TABLE telemetry_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    generation INTEGER NOT NULL,
    settings_json TEXT NOT NULL,
    actor_id TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    occurred_at INTEGER NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    decision TEXT NOT NULL,
    revision_digest TEXT,
    safe_metadata_json TEXT NOT NULL
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"#,
    ),
    (
        2,
        r#"
ALTER TABLE enrollment_tokens ADD COLUMN node_name TEXT;
ALTER TABLE enrollment_tokens ADD COLUMN server_names_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE telemetry_settings ADD COLUMN consent_json TEXT;
CREATE TABLE provision_plans (
 id TEXT PRIMARY KEY, digest TEXT NOT NULL, actor_id TEXT NOT NULL,
 desired_json TEXT NOT NULL, expected_revision TEXT, state TEXT NOT NULL,
 generation INTEGER NOT NULL DEFAULT 1, step TEXT NOT NULL DEFAULT 'planned',
 inventory_json TEXT NOT NULL DEFAULT '{}', error_code TEXT,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX provision_single_apply ON provision_plans((1))
 WHERE state IN ('applying','verifying','compensating');
CREATE TABLE provision_events (
 seq INTEGER PRIMARY KEY AUTOINCREMENT, plan_id TEXT NOT NULL REFERENCES provision_plans(id),
 state TEXT NOT NULL, step TEXT NOT NULL, occurred_at INTEGER NOT NULL, code TEXT
);
CREATE TABLE provider_credentials (
 provider TEXT PRIMARY KEY, secret_ref TEXT NOT NULL, fingerprint TEXT NOT NULL,
 generation INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
-- Shape-only pre-SPEC-12 consent cannot authorize an export after upgrade.
UPDATE telemetry_settings SET generation=generation+1,
 settings_json=json_set(settings_json,'$.export_enabled',json('false'),'$.export_profile','off')
 WHERE json_extract(settings_json,'$.export_enabled')=1;
CREATE TABLE certificate_renewals (
 actor_id TEXT NOT NULL, node_id TEXT NOT NULL, key_hash TEXT NOT NULL,
 request_digest TEXT NOT NULL, response_json TEXT NOT NULL,
 PRIMARY KEY(actor_id,node_id,key_hash)
);
"#,
    ),
    (
        3,
        r#"
ALTER TABLE principals ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN owner_principal_id TEXT;
CREATE TABLE app_settings (
 key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE integrations (
 id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
 settings_json TEXT NOT NULL DEFAULT '{}', status_json TEXT NOT NULL DEFAULT '{}',
 generation INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL
);
"#,
    ),
    (
        4,
        r#"
ALTER TABLE principals ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE principals ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
CREATE TABLE totp_recovery (
 principal_id TEXT NOT NULL, code_hash TEXT NOT NULL, used_at INTEGER,
 PRIMARY KEY(principal_id, code_hash)
);
"#,
    ),
];

fn checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

pub fn run(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (id INTEGER PRIMARY KEY, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL);",
    )?;
    let latest_known = MIGRATIONS.last().map(|m| m.0).unwrap_or(0);
    let applied_max: i64 = conn.query_row(
        "SELECT COALESCE(MAX(id), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    if applied_max > latest_known {
        // Database written by a newer binary: refuse (downgrade blocked).
        return Err(StoreError::Corrupt(format!(
            "schema version {applied_max} is newer than this binary supports ({latest_known})"
        )));
    }
    for (id, sql) in MIGRATIONS {
        let existing: Option<String> = conn
            .query_row(
                "SELECT checksum FROM schema_migrations WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .ok();
        match existing {
            Some(c) if c == checksum(sql) => continue,
            Some(_) => {
                return Err(StoreError::Corrupt(format!(
                    "migration {id} checksum mismatch"
                )));
            }
            None => {
                let tx = conn.unchecked_transaction()?;
                tx.execute_batch(sql)?;
                tx.execute(
                    "INSERT INTO schema_migrations (id, checksum, applied_at) VALUES (?1, ?2, strftime('%s','now'))",
                    rusqlite::params![id, checksum(sql)],
                )?;
                tx.commit()?;
            }
        }
    }
    Ok(())
}
