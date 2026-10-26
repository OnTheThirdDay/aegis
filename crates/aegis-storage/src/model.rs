//! Typed rows and statement helpers. Every function takes a `&Connection`
//! (a `Transaction` derefs to one) so callers compose them atomically.

use crate::{Result, StoreError};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Hex SHA-256, used for token verifiers and idempotency keys.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ---------------------------------------------------------------------------
// Profiles & revisions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProfileRow {
    pub id: String,
    pub name: String,
    pub desired_revision_id: String,
    pub active_revision_id: Option<String>,
    pub generation: i64,
    pub owner_id: Option<String>,
    pub created_at: i64,
}

impl ProfileRow {
    /// Strong ETag over the profile representation (name, desired and
    /// active revisions, generation). Quoted, `[A-Za-z0-9_-]`.
    pub fn etag(&self) -> String {
        let material = format!(
            "{}|{}|{}|{}|{}",
            self.id,
            self.name,
            self.desired_revision_id,
            self.active_revision_id.as_deref().unwrap_or("-"),
            self.generation
        );
        format!("\"p{}\"", &sha256_hex(material.as_bytes())[..32])
    }
}

fn profile_row(r: &Row<'_>) -> rusqlite::Result<ProfileRow> {
    Ok(ProfileRow {
        id: r.get(0)?,
        name: r.get(1)?,
        desired_revision_id: r.get(2)?,
        active_revision_id: r.get(3)?,
        generation: r.get(4)?,
        owner_id: r.get(5)?,
        created_at: r.get(6)?,
    })
}

const PROFILE_COLS: &str =
    "id, name, desired_revision_id, active_revision_id, generation, owner_id, created_at";

pub fn insert_profile(c: &Connection, p: &ProfileRow) -> Result<()> {
    c.execute(
        "INSERT INTO profiles (id, name, desired_revision_id, active_revision_id, generation, owner_id, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![p.id, p.name, p.desired_revision_id, p.active_revision_id, p.generation, p.owner_id, p.created_at],
    )?;
    Ok(())
}

pub fn get_profile(c: &Connection, id: &str) -> Result<ProfileRow> {
    Ok(c.query_row(
        &format!("SELECT {PROFILE_COLS} FROM profiles WHERE id = ?1"),
        [id],
        profile_row,
    )?)
}

/// Profiles ordered by (created_at, id), starting after the cursor key.
pub fn list_profiles(
    c: &Connection,
    after: Option<(i64, String)>,
    limit: u32,
) -> Result<Vec<ProfileRow>> {
    let (ts, id) = after.unwrap_or((i64::MIN, String::new()));
    let mut stmt = c.prepare(&format!(
        "SELECT {PROFILE_COLS} FROM profiles WHERE (created_at > ?1) OR (created_at = ?1 AND id > ?2) ORDER BY created_at, id LIMIT ?3"
    ))?;
    let rows = stmt.query_map(params![ts, id, limit], profile_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// CAS update of name/desired revision on the expected generation.
pub fn update_profile_desired(
    c: &Connection,
    id: &str,
    name: &str,
    desired: &str,
    expected_generation: i64,
) -> Result<i64> {
    let n = c.execute(
        "UPDATE profiles SET name = ?1, desired_revision_id = ?2, generation = generation + 1 WHERE id = ?3 AND generation = ?4",
        params![name, desired, id, expected_generation],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict("profile generation changed".into()));
    }
    Ok(expected_generation + 1)
}

pub fn set_profile_active(c: &Connection, id: &str, active: &str) -> Result<()> {
    c.execute(
        "UPDATE profiles SET active_revision_id = ?1, generation = generation + 1 WHERE id = ?2",
        params![active, id],
    )?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevisionRow {
    pub id: String,
    pub profile_id: String,
    pub parent_id: Option<String>,
    pub spec_json: String,
    pub digest: String,
    pub actor_id: Option<String>,
    pub created_at: i64,
    pub seq: i64,
    pub state: String,
}

fn revision_row(r: &Row<'_>) -> rusqlite::Result<RevisionRow> {
    Ok(RevisionRow {
        id: r.get(0)?,
        profile_id: r.get(1)?,
        parent_id: r.get(2)?,
        spec_json: r.get(3)?,
        digest: r.get(4)?,
        actor_id: r.get(5)?,
        created_at: r.get(6)?,
        seq: r.get(7)?,
        state: r.get(8)?,
    })
}

const REVISION_COLS: &str =
    "id, profile_id, parent_id, spec_json, digest, actor_id, created_at, seq, state";

pub fn next_revision_seq(c: &Connection, profile_id: &str) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM revisions WHERE profile_id = ?1",
        [profile_id],
        |r| r.get(0),
    )?)
}

pub fn insert_revision(c: &Connection, r: &RevisionRow) -> Result<()> {
    c.execute(
        "INSERT INTO revisions (id, profile_id, parent_id, spec_json, digest, actor_id, created_at, seq, state) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![r.id, r.profile_id, r.parent_id, r.spec_json, r.digest, r.actor_id, r.created_at, r.seq, r.state],
    )?;
    Ok(())
}

pub fn get_revision(c: &Connection, id: &str) -> Result<RevisionRow> {
    Ok(c.query_row(
        &format!("SELECT {REVISION_COLS} FROM revisions WHERE id = ?1"),
        [id],
        revision_row,
    )?)
}

/// Newest first, before the cursor sequence.
pub fn list_revisions(
    c: &Connection,
    profile_id: &str,
    before_seq: Option<i64>,
    limit: u32,
) -> Result<Vec<RevisionRow>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {REVISION_COLS} FROM revisions WHERE profile_id = ?1 AND seq < ?2 ORDER BY seq DESC LIMIT ?3"
    ))?;
    let rows = stmt.query_map(
        params![profile_id, before_seq.unwrap_or(i64::MAX), limit],
        revision_row,
    )?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn set_revision_state(c: &Connection, id: &str, state: &str) -> Result<()> {
    c.execute(
        "UPDATE revisions SET state = ?1 WHERE id = ?2",
        params![state, id],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Validation reports
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ValidationRow {
    pub id: String,
    pub profile_id: String,
    pub target_revision_id: String,
    pub config_digest: String,
    pub profile_etag: String,
    pub capability_digest: String,
    pub security_epoch: i64,
    pub expires_at: i64,
    pub valid: bool,
    pub actor_id: Option<String>,
    pub report_json: String,
}

pub fn insert_validation(c: &Connection, v: &ValidationRow) -> Result<()> {
    c.execute(
        "INSERT INTO validation_reports (id, profile_id, target_revision_id, config_digest, profile_etag, capability_digest, security_epoch, expires_at, valid, actor_id, report_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![v.id, v.profile_id, v.target_revision_id, v.config_digest, v.profile_etag, v.capability_digest, v.security_epoch, v.expires_at, v.valid, v.actor_id, v.report_json],
    )?;
    Ok(())
}

pub fn get_validation(c: &Connection, id: &str) -> Result<ValidationRow> {
    Ok(c.query_row(
        "SELECT id, profile_id, target_revision_id, config_digest, profile_etag, capability_digest, security_epoch, expires_at, valid, actor_id, report_json FROM validation_reports WHERE id = ?1",
        [id],
        |r| {
            Ok(ValidationRow {
                id: r.get(0)?,
                profile_id: r.get(1)?,
                target_revision_id: r.get(2)?,
                config_digest: r.get(3)?,
                profile_etag: r.get(4)?,
                capability_digest: r.get(5)?,
                security_epoch: r.get(6)?,
                expires_at: r.get(7)?,
                valid: r.get(8)?,
                actor_id: r.get(9)?,
                report_json: r.get(10)?,
            })
        },
    )?)
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct JobRow {
    pub id: String,
    pub kind: String,
    pub actor_id: Option<String>,
    pub status: String,
    pub target_type: String,
    pub target_id: String,
    pub target_revision_id: Option<String>,
    pub config_digest: Option<String>,
    pub validation_id: Option<String>,
    pub expected_profile_etag: Option<String>,
    pub expected_active_revision_id: Option<String>,
    pub expected_node_etag: Option<String>,
    pub commit_state: String,
    pub operation_id: Option<String>,
    pub deadline_at: i64,
    pub result_revision_id: Option<String>,
    pub superseded_by: Option<String>,
    pub safe_error_code: Option<String>,
    pub created_at: i64,
}

const JOB_COLS: &str = "id, kind, actor_id, status, target_type, target_id, target_revision_id, config_digest, validation_id, expected_profile_etag, expected_active_revision_id, expected_node_etag, commit_state, operation_id, deadline_at, result_revision_id, superseded_by, safe_error_code, created_at";

fn job_row(r: &Row<'_>) -> rusqlite::Result<JobRow> {
    Ok(JobRow {
        id: r.get(0)?,
        kind: r.get(1)?,
        actor_id: r.get(2)?,
        status: r.get(3)?,
        target_type: r.get(4)?,
        target_id: r.get(5)?,
        target_revision_id: r.get(6)?,
        config_digest: r.get(7)?,
        validation_id: r.get(8)?,
        expected_profile_etag: r.get(9)?,
        expected_active_revision_id: r.get(10)?,
        expected_node_etag: r.get(11)?,
        commit_state: r.get(12)?,
        operation_id: r.get(13)?,
        deadline_at: r.get(14)?,
        result_revision_id: r.get(15)?,
        superseded_by: r.get(16)?,
        safe_error_code: r.get(17)?,
        created_at: r.get(18)?,
    })
}

pub fn insert_job(c: &Connection, j: &JobRow) -> Result<()> {
    c.execute(
        &format!("INSERT INTO jobs ({JOB_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)"),
        params![
            j.id, j.kind, j.actor_id, j.status, j.target_type, j.target_id, j.target_revision_id, j.config_digest,
            j.validation_id, j.expected_profile_etag, j.expected_active_revision_id, j.expected_node_etag,
            j.commit_state, j.operation_id, j.deadline_at, j.result_revision_id, j.superseded_by, j.safe_error_code,
            j.created_at
        ],
    )?;
    Ok(())
}

pub fn get_job(c: &Connection, id: &str) -> Result<JobRow> {
    Ok(c.query_row(
        &format!("SELECT {JOB_COLS} FROM jobs WHERE id = ?1"),
        [id],
        job_row,
    )?)
}

pub fn update_job(c: &Connection, j: &JobRow) -> Result<()> {
    c.execute(
        "UPDATE jobs SET status = ?2, commit_state = ?3, operation_id = ?4, result_revision_id = ?5, superseded_by = ?6, safe_error_code = ?7 WHERE id = ?1",
        params![j.id, j.status, j.commit_state, j.operation_id, j.result_revision_id, j.superseded_by, j.safe_error_code],
    )?;
    Ok(())
}

/// Jobs not yet durably committed when the process stopped.
pub fn interrupted_uncommitted_jobs(c: &Connection) -> Result<Vec<JobRow>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {JOB_COLS} FROM jobs WHERE status IN ('pending','running') AND commit_state = 'uncommitted'"
    ))?;
    let rows = stmt.query_map([], job_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_job_by_operation(c: &Connection, op: &str) -> Result<Option<JobRow>> {
    Ok(c.query_row(
        &format!("SELECT {JOB_COLS} FROM jobs WHERE operation_id = ?1"),
        [op],
        job_row,
    )
    .optional()?)
}

// ---------------------------------------------------------------------------
// Activation intents & runtime state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IntentRow {
    pub operation_id: String,
    pub job_id: Option<String>,
    pub profile_id: String,
    pub target_revision_id: String,
    pub expected_active_revision_id: Option<String>,
    pub config_digest: String,
    pub security_epoch: i64,
    pub commit_state: String,
    pub committed_at: i64,
    pub applied_at: Option<i64>,
    pub superseded_by: Option<String>,
    pub reason: Option<String>,
}

const INTENT_COLS: &str = "operation_id, job_id, profile_id, target_revision_id, expected_active_revision_id, config_digest, security_epoch, commit_state, committed_at, applied_at, superseded_by, reason";

fn intent_row(r: &Row<'_>) -> rusqlite::Result<IntentRow> {
    Ok(IntentRow {
        operation_id: r.get(0)?,
        job_id: r.get(1)?,
        profile_id: r.get(2)?,
        target_revision_id: r.get(3)?,
        expected_active_revision_id: r.get(4)?,
        config_digest: r.get(5)?,
        security_epoch: r.get(6)?,
        commit_state: r.get(7)?,
        committed_at: r.get(8)?,
        applied_at: r.get(9)?,
        superseded_by: r.get(10)?,
        reason: r.get(11)?,
    })
}

pub fn insert_intent(c: &Connection, i: &IntentRow) -> Result<()> {
    c.execute(
        &format!("INSERT INTO activation_intents ({INTENT_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)"),
        params![
            i.operation_id, i.job_id, i.profile_id, i.target_revision_id, i.expected_active_revision_id,
            i.config_digest, i.security_epoch, i.commit_state, i.committed_at, i.applied_at, i.superseded_by, i.reason
        ],
    )?;
    Ok(())
}

pub fn get_intent(c: &Connection, op: &str) -> Result<IntentRow> {
    Ok(c.query_row(
        &format!("SELECT {INTENT_COLS} FROM activation_intents WHERE operation_id = ?1"),
        [op],
        intent_row,
    )?)
}

/// The latest committed intent that is neither applied nor superseded.
pub fn unresolved_intent(c: &Connection) -> Result<Option<IntentRow>> {
    Ok(c.query_row(
        &format!(
            "SELECT {INTENT_COLS} FROM activation_intents WHERE commit_state = 'committed' ORDER BY committed_at DESC, rowid DESC LIMIT 1"
        ),
        [],
        intent_row,
    )
    .optional()?)
}

pub fn mark_intent_applied(c: &Connection, op: &str, at: i64) -> Result<()> {
    let n = c.execute(
        "UPDATE activation_intents SET commit_state = 'applied', applied_at = ?2 WHERE operation_id = ?1 AND commit_state IN ('committed','applied')",
        params![op, at],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict(
            "intent is not in a committed state".into(),
        ));
    }
    Ok(())
}

pub fn mark_intent_superseded(c: &Connection, op: &str, by: &str, reason: &str) -> Result<()> {
    let n = c.execute(
        "UPDATE activation_intents SET commit_state = 'superseded', superseded_by = ?2, reason = ?3 WHERE operation_id = ?1 AND commit_state = 'committed'",
        params![op, by, reason],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict("intent is not unresolved".into()));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RuntimeStateRow {
    pub applied_revision_id: Option<String>,
    pub applied_profile_id: Option<String>,
    pub applied_operation_id: Option<String>,
}

pub fn get_runtime_state(c: &Connection) -> Result<RuntimeStateRow> {
    Ok(c.query_row(
        "SELECT applied_revision_id, applied_profile_id, applied_operation_id FROM runtime_state WHERE id = 1",
        [],
        |r| {
            Ok(RuntimeStateRow {
                applied_revision_id: r.get(0)?,
                applied_profile_id: r.get(1)?,
                applied_operation_id: r.get(2)?,
            })
        },
    )?)
}

pub fn set_runtime_applied(c: &Connection, rev: &str, profile: &str, op: &str) -> Result<()> {
    c.execute(
        "UPDATE runtime_state SET applied_revision_id = ?1, applied_profile_id = ?2, applied_operation_id = ?3 WHERE id = 1",
        params![rev, profile, op],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdempotencyRow {
    pub request_digest: String,
    pub job_id: String,
}

pub fn get_idempotency(
    c: &Connection,
    actor: &str,
    method: &str,
    path: &str,
    key_hash: &str,
) -> Result<Option<IdempotencyRow>> {
    Ok(c.query_row(
        "SELECT request_digest, job_id FROM idempotency_records WHERE actor_id = ?1 AND method = ?2 AND canonical_path = ?3 AND key_hash = ?4",
        params![actor, method, path, key_hash],
        |r| Ok(IdempotencyRow { request_digest: r.get(0)?, job_id: r.get(1)? }),
    )
    .optional()?)
}

#[allow(clippy::too_many_arguments)]
pub fn insert_idempotency(
    c: &Connection,
    actor: &str,
    method: &str,
    path: &str,
    key_hash: &str,
    digest: &str,
    job: &str,
    expires: i64,
) -> Result<()> {
    c.execute(
        "INSERT INTO idempotency_records (actor_id, method, canonical_path, key_hash, request_digest, job_id, expires_at) VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![actor, method, path, key_hash, digest, job, expires],
    )?;
    Ok(())
}

/// Evict expired keys, but never for pending/running/committed jobs.
pub fn prune_idempotency(c: &Connection, now: i64) -> Result<usize> {
    Ok(c.execute(
        "DELETE FROM idempotency_records WHERE expires_at < ?1 AND job_id IN (SELECT id FROM jobs WHERE status IN ('succeeded','failed','cancelled','superseded'))",
        [now],
    )?)
}

// ---------------------------------------------------------------------------
// Security epoch, nodes, identities, enrollment
// ---------------------------------------------------------------------------

pub fn get_epoch(c: &Connection) -> Result<i64> {
    Ok(
        c.query_row("SELECT epoch FROM security_state WHERE id = 1", [], |r| {
            r.get(0)
        })?,
    )
}

pub fn bump_epoch(c: &Connection) -> Result<i64> {
    c.execute(
        "UPDATE security_state SET epoch = epoch + 1 WHERE id = 1",
        [],
    )?;
    get_epoch(c)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeRow {
    pub id: String,
    pub name: String,
    pub role: String,
    pub cert_fingerprint: Option<String>,
    pub cert_serial: Option<String>,
    pub status: String,
    pub generation: i64,
    pub not_after: Option<i64>,
    pub created_at: i64,
}

impl NodeRow {
    pub fn etag(&self) -> String {
        let material = format!(
            "{}|{}|{}|{}",
            self.id,
            self.status,
            self.generation,
            self.cert_fingerprint.as_deref().unwrap_or("-")
        );
        format!("\"n{}\"", &sha256_hex(material.as_bytes())[..32])
    }
}

const NODE_COLS: &str =
    "id, name, role, cert_fingerprint, cert_serial, status, generation, not_after, created_at";

fn node_row(r: &Row<'_>) -> rusqlite::Result<NodeRow> {
    Ok(NodeRow {
        id: r.get(0)?,
        name: r.get(1)?,
        role: r.get(2)?,
        cert_fingerprint: r.get(3)?,
        cert_serial: r.get(4)?,
        status: r.get(5)?,
        generation: r.get(6)?,
        not_after: r.get(7)?,
        created_at: r.get(8)?,
    })
}

pub fn insert_node(c: &Connection, n: &NodeRow) -> Result<()> {
    c.execute(
        &format!("INSERT INTO nodes ({NODE_COLS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"),
        params![
            n.id,
            n.name,
            n.role,
            n.cert_fingerprint,
            n.cert_serial,
            n.status,
            n.generation,
            n.not_after,
            n.created_at
        ],
    )?;
    Ok(())
}

pub fn get_node(c: &Connection, id: &str) -> Result<NodeRow> {
    Ok(c.query_row(
        &format!("SELECT {NODE_COLS} FROM nodes WHERE id = ?1"),
        [id],
        node_row,
    )?)
}

pub fn get_node_by_name(c: &Connection, name: &str) -> Result<Option<NodeRow>> {
    Ok(c.query_row(
        &format!("SELECT {NODE_COLS} FROM nodes WHERE name = ?1"),
        [name],
        node_row,
    )
    .optional()?)
}

pub fn list_nodes(
    c: &Connection,
    after: Option<(i64, String)>,
    limit: u32,
) -> Result<Vec<NodeRow>> {
    let (ts, id) = after.unwrap_or((i64::MIN, String::new()));
    let mut stmt = c.prepare(&format!(
        "SELECT {NODE_COLS} FROM nodes WHERE (created_at > ?1) OR (created_at = ?1 AND id > ?2) ORDER BY created_at, id LIMIT ?3"
    ))?;
    let rows = stmt.query_map(params![ts, id, limit], node_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Re-enrollment of an existing node name (certificate rotation).
pub fn rotate_node_certificate(
    c: &Connection,
    id: &str,
    fingerprint: &str,
    serial: &str,
    not_after: i64,
) -> Result<()> {
    c.execute(
        "UPDATE nodes SET cert_fingerprint = ?2, cert_serial = ?3, not_after = ?4, status = 'active', generation = generation + 1 WHERE id = ?1 AND status != 'revoked'",
        params![id, fingerprint, serial, not_after],
    )?;
    Ok(())
}

pub fn set_node_status(
    c: &Connection,
    id: &str,
    status: &str,
    expected_generation: i64,
) -> Result<()> {
    let n = c.execute(
        "UPDATE nodes SET status = ?2, generation = generation + 1 WHERE id = ?1 AND generation = ?3",
        params![id, status, expected_generation],
    )?;
    if n != 1 {
        return Err(StoreError::Conflict("node generation changed".into()));
    }
    Ok(())
}

pub fn insert_identity(
    c: &Connection,
    fp: &str,
    node_id: &str,
    serial: &str,
    nb: i64,
    na: i64,
) -> Result<()> {
    c.execute(
        "INSERT INTO trusted_identities (fingerprint, node_id, serial, status, not_before, not_after) VALUES (?1,?2,?3,'active',?4,?5)",
        params![fp, node_id, serial, nb, na],
    )?;
    Ok(())
}

/// Revoke every identity of a node at `epoch`. Returns fingerprints.
pub fn revoke_node_identities(c: &Connection, node_id: &str, epoch: i64) -> Result<Vec<String>> {
    c.execute(
        "UPDATE trusted_identities SET status = 'revoked', revoked_at = ?2, revoked_epoch = ?3 WHERE node_id = ?1 AND status != 'revoked'",
        params![node_id, now_unix(), epoch],
    )?;
    let mut stmt = c.prepare(
        "SELECT fingerprint FROM trusted_identities WHERE node_id = ?1 AND status = 'revoked'",
    )?;
    let rows = stmt.query_map([node_id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn revoked_fingerprints(c: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        c.prepare("SELECT fingerprint FROM trusted_identities WHERE status = 'revoked'")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn active_identity_bindings(c: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut stmt = c.prepare("SELECT i.fingerprint,n.name,n.role FROM trusted_identities i JOIN nodes n ON n.id=i.node_id WHERE i.status='active' AND n.status IN ('active','rotating')")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn insert_enrollment_token(
    c: &Connection,
    id: &str,
    verifier: &str,
    role: &str,
    expires: i64,
    created_by: Option<&str>,
) -> Result<()> {
    c.execute(
        "INSERT INTO enrollment_tokens (id, verifier_hash, role, expires_at, max_uses, created_by) VALUES (?1,?2,?3,?4,1,?5)",
        params![id, verifier, role, expires, created_by],
    )?;
    Ok(())
}

/// Atomically consume a one-use enrollment token; returns its role.
pub fn consume_enrollment_token(
    c: &Connection,
    verifier: &str,
    now: i64,
) -> Result<Option<String>> {
    let role: Option<String> = c
        .query_row(
            "SELECT role FROM enrollment_tokens WHERE verifier_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![verifier, now],
            |r| r.get(0),
        )
        .optional()?;
    if role.is_some() {
        let n = c.execute(
            "UPDATE enrollment_tokens SET used_at = ?2 WHERE verifier_hash = ?1 AND used_at IS NULL",
            params![verifier, now],
        )?;
        if n != 1 {
            return Ok(None);
        }
    }
    Ok(role)
}

// ---------------------------------------------------------------------------
// Principals & bootstrap
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRow {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub status: String,
    pub roles: Vec<String>,
}

pub fn owner_exists(c: &Connection) -> Result<bool> {
    let n: i64 = c.query_row(
        "SELECT COUNT(*) FROM principal_roles WHERE role = 'owner'",
        [],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

pub fn insert_principal(c: &Connection, p: &PrincipalRow) -> Result<()> {
    c.execute(
        "INSERT INTO principals (id, username, password_hash, status, created_at) VALUES (?1,?2,?3,?4,?5)",
        params![p.id, p.username, p.password_hash, p.status, now_unix()],
    )?;
    for role in &p.roles {
        c.execute(
            "INSERT INTO principal_roles (principal_id, role) VALUES (?1, ?2)",
            params![p.id, role],
        )?;
    }
    Ok(())
}

fn roles_of(c: &Connection, id: &str) -> Result<Vec<String>> {
    let mut stmt =
        c.prepare("SELECT role FROM principal_roles WHERE principal_id = ?1 ORDER BY role")?;
    let rows = stmt.query_map([id], |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

pub fn get_principal_by_username(c: &Connection, username: &str) -> Result<Option<PrincipalRow>> {
    let row = c
        .query_row(
            "SELECT id, username, password_hash, status FROM principals WHERE username = ?1",
            [username],
            |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    match row {
        Some((id, username, password_hash, status)) => {
            let roles = roles_of(c, &id)?;
            Ok(Some(PrincipalRow {
                id,
                username,
                password_hash,
                status,
                roles,
            }))
        }
        None => Ok(None),
    }
}

pub fn get_principal(c: &Connection, id: &str) -> Result<PrincipalRow> {
    let (id, username, password_hash, status) = c.query_row(
        "SELECT id, username, password_hash, status FROM principals WHERE id = ?1",
        [id],
        |r| Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let roles = roles_of(c, &id)?;
    Ok(PrincipalRow {
        id,
        username,
        password_hash,
        status,
        roles,
    })
}

/// Summary row for user administration (never includes the password hash).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PrincipalSummary {
    pub id: String,
    pub username: String,
    pub status: String,
    pub roles: Vec<String>,
    pub must_change_password: bool,
    pub two_factor: bool,
    pub created_at: i64,
}

pub fn list_principals(c: &Connection) -> Result<Vec<PrincipalSummary>> {
    let mut stmt = c.prepare(
        "SELECT id, username, status, must_change_password, created_at, totp_enabled FROM principals ORDER BY created_at, id LIMIT 500",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(id, username, status, must, created_at, totp)| {
            Ok(PrincipalSummary {
                roles: roles_of(c, &id)?,
                id,
                username,
                status,
                must_change_password: must != 0,
                two_factor: totp != 0,
                created_at,
            })
        })
        .collect()
}

/// Whether the principal signs in with a second factor (TOTP). The shared
/// secret itself is kept in the secret store, never in this database.
pub fn two_factor_enabled(c: &Connection, id: &str) -> Result<bool> {
    let v: i64 = c.query_row(
        "SELECT totp_enabled FROM principals WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    Ok(v != 0)
}

/// Turn the second factor on with fresh recovery codes (hashes only).
pub fn enable_two_factor(c: &Connection, id: &str, recovery_hashes: &[String]) -> Result<()> {
    let n = c.execute(
        "UPDATE principals SET totp_enabled = 1, totp_last_step = 0 WHERE id = ?1",
        [id],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound);
    }
    c.execute("DELETE FROM totp_recovery WHERE principal_id = ?1", [id])?;
    for h in recovery_hashes {
        c.execute(
            "INSERT INTO totp_recovery (principal_id, code_hash, used_at) VALUES (?1, ?2, NULL)",
            params![id, h],
        )?;
    }
    Ok(())
}

pub fn disable_two_factor(c: &Connection, id: &str) -> Result<()> {
    c.execute(
        "UPDATE principals SET totp_enabled = 0, totp_last_step = 0 WHERE id = ?1",
        [id],
    )?;
    c.execute("DELETE FROM totp_recovery WHERE principal_id = ?1", [id])?;
    Ok(())
}

/// Record a used code's time step; false if that step (or a later one)
/// was already used, which makes each code single-use.
pub fn advance_totp_step(c: &Connection, id: &str, step: i64) -> Result<bool> {
    let n = c.execute(
        "UPDATE principals SET totp_last_step = ?2 WHERE id = ?1 AND totp_enabled = 1 AND totp_last_step < ?2",
        params![id, step],
    )?;
    Ok(n == 1)
}

/// Spend a recovery code (by hash); false if unknown or already used.
pub fn use_recovery_code(c: &Connection, id: &str, code_hash: &str) -> Result<bool> {
    let n = c.execute(
        "UPDATE totp_recovery SET used_at = ?3 WHERE principal_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
        params![id, code_hash, now_unix()],
    )?;
    Ok(n == 1)
}

pub fn recovery_codes_left(c: &Connection, id: &str) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM totp_recovery WHERE principal_id = ?1 AND used_at IS NULL",
        [id],
        |r| r.get(0),
    )?)
}

pub fn must_change_password(c: &Connection, id: &str) -> Result<bool> {
    let v: i64 = c.query_row(
        "SELECT must_change_password FROM principals WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?;
    Ok(v != 0)
}

/// Replace a password hash; `must_change` forces a change at next sign-in.
pub fn set_password(c: &Connection, id: &str, hash: &str, must_change: bool) -> Result<()> {
    let n = c.execute(
        "UPDATE principals SET password_hash = ?2, must_change_password = ?3 WHERE id = ?1",
        params![id, hash, i64::from(must_change)],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

pub fn set_principal_status(c: &Connection, id: &str, status: &str) -> Result<()> {
    let n = c.execute(
        "UPDATE principals SET status = ?2 WHERE id = ?1",
        params![id, status],
    )?;
    if n != 1 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

pub fn set_principal_roles(c: &Connection, id: &str, roles: &[String]) -> Result<()> {
    c.execute("DELETE FROM principal_roles WHERE principal_id = ?1", [id])?;
    for role in roles {
        c.execute(
            "INSERT INTO principal_roles (principal_id, role) VALUES (?1, ?2)",
            params![id, role],
        )?;
    }
    Ok(())
}

pub fn count_active_owners(c: &Connection) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM principals p JOIN principal_roles r ON r.principal_id = p.id WHERE r.role = 'owner' AND p.status = 'active'",
        [],
        |r| r.get(0),
    )?)
}

// ---------------------------------------------------------------------------
// Appliance settings and integrations
// ---------------------------------------------------------------------------

pub fn get_setting(c: &Connection, key: &str) -> Result<Option<serde_json::Value>> {
    let v: Option<String> = c
        .query_row(
            "SELECT value_json FROM app_settings WHERE key = ?1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    v.map(|s| serde_json::from_str(&s).map_err(|_| StoreError::Corrupt("setting".into())))
        .transpose()
}

pub fn put_setting(c: &Connection, key: &str, value: &serde_json::Value) -> Result<()> {
    c.execute(
        "INSERT INTO app_settings (key, value_json, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
        params![key, value.to_string(), now_unix()],
    )?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct IntegrationRow {
    pub id: String,
    pub enabled: bool,
    pub settings: serde_json::Value,
    pub status: serde_json::Value,
    pub generation: i64,
    pub updated_at: i64,
}

pub fn get_integration(c: &Connection, id: &str) -> Result<Option<IntegrationRow>> {
    let row = c
        .query_row(
            "SELECT enabled, settings_json, status_json, generation, updated_at FROM integrations WHERE id = ?1",
            [id],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    row.map(|(enabled, settings, status, generation, updated_at)| {
        Ok(IntegrationRow {
            id: id.to_owned(),
            enabled: enabled != 0,
            settings: serde_json::from_str(&settings)
                .map_err(|_| StoreError::Corrupt("integration".into()))?,
            status: serde_json::from_str(&status)
                .map_err(|_| StoreError::Corrupt("integration".into()))?,
            generation,
            updated_at,
        })
    })
    .transpose()
}

/// Upsert an integration record; returns the new generation.
pub fn put_integration(
    c: &Connection,
    id: &str,
    enabled: bool,
    settings: &serde_json::Value,
    status: &serde_json::Value,
) -> Result<i64> {
    c.execute(
        "INSERT INTO integrations (id, enabled, settings_json, status_json, generation, updated_at) VALUES (?1, ?2, ?3, ?4, 1, ?5)
         ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled, settings_json = excluded.settings_json,
           status_json = excluded.status_json, generation = integrations.generation + 1, updated_at = excluded.updated_at",
        params![id, i64::from(enabled), settings.to_string(), status.to_string(), now_unix()],
    )?;
    Ok(c.query_row(
        "SELECT generation FROM integrations WHERE id = ?1",
        [id],
        |r| r.get(0),
    )?)
}

/// Record which principal owns an enrolled device.
pub fn set_node_owner(c: &Connection, node_id: &str, principal: Option<&str>) -> Result<()> {
    c.execute(
        "UPDATE nodes SET owner_principal_id = ?2 WHERE id = ?1",
        params![node_id, principal],
    )?;
    Ok(())
}

pub fn node_owner(c: &Connection, node_id: &str) -> Result<Option<String>> {
    Ok(c.query_row(
        "SELECT owner_principal_id FROM nodes WHERE id = ?1",
        [node_id],
        |r| r.get(0),
    )?)
}

/// Devices enrolled through invitations created by `owner` (newest first).
pub fn list_owned_nodes(c: &Connection, owner: &str) -> Result<Vec<NodeRow>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {NODE_COLS} FROM nodes WHERE owner_principal_id = ?1 ORDER BY created_at DESC, id LIMIT 200"
    ))?;
    let rows = stmt.query_map([owner], node_row)?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Enrollment token creator (the device's future owner).
pub fn enrollment_token_creator(c: &Connection, verifier: &str) -> Result<Option<String>> {
    Ok(c.query_row(
        "SELECT created_by FROM enrollment_tokens WHERE verifier_hash = ?1",
        [verifier],
        |r| r.get::<_, Option<String>>(0),
    )
    .optional()?
    .flatten())
}

pub fn insert_bootstrap_token(c: &Connection, verifier: &str, expires: i64) -> Result<()> {
    c.execute(
        "INSERT INTO bootstrap_tokens (id, verifier_hash, expires_at) VALUES (?1, ?2, ?3)",
        params![new_id(), verifier, expires],
    )?;
    Ok(())
}

/// Consume a bootstrap token atomically; false if unknown, used or expired.
pub fn consume_bootstrap_token(c: &Connection, verifier: &str, now: i64) -> Result<bool> {
    let n = c.execute(
        "UPDATE bootstrap_tokens SET used_at = ?2 WHERE verifier_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
        params![verifier, now],
    )?;
    Ok(n == 1)
}

// ---------------------------------------------------------------------------
// Telemetry settings
// ---------------------------------------------------------------------------

pub fn get_telemetry_settings(c: &Connection) -> Result<Option<(i64, String)>> {
    Ok(c.query_row(
        "SELECT generation, settings_json FROM telemetry_settings WHERE id = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()?)
}

/// CAS write on generation (0 = no row yet).
pub fn put_telemetry_settings(
    c: &Connection,
    expected_generation: i64,
    json: &str,
    actor: Option<&str>,
) -> Result<i64> {
    let next = expected_generation + 1;
    let n = if expected_generation == 0 {
        c.execute(
            "INSERT OR IGNORE INTO telemetry_settings (id, generation, settings_json, actor_id, updated_at) VALUES (1, 1, ?1, ?2, ?3)",
            params![json, actor, now_unix()],
        )?
    } else {
        c.execute(
            "UPDATE telemetry_settings SET generation = ?1, settings_json = ?2, actor_id = ?3, updated_at = ?4 WHERE id = 1 AND generation = ?5",
            params![next, json, actor, now_unix(), expected_generation],
        )?
    };
    if n != 1 {
        return Err(StoreError::Conflict("telemetry settings changed".into()));
    }
    Ok(next)
}

// ---------------------------------------------------------------------------
// Audit (append-only)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditRow {
    pub seq: i64,
    pub id: String,
    pub occurred_at: i64,
    pub actor_id: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<String>,
    pub decision: String,
    pub revision_digest: Option<String>,
    pub safe_metadata_json: String,
}

pub struct AuditInsert<'a> {
    pub actor_id: Option<&'a str>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: Option<&'a str>,
    pub decision: &'a str,
    pub revision_digest: Option<&'a str>,
    pub metadata: serde_json::Value,
}

pub fn append_audit(c: &Connection, a: AuditInsert<'_>) -> Result<String> {
    let id = new_id();
    c.execute(
        "INSERT INTO audit_events (id, occurred_at, actor_id, action, target_type, target_id, decision, revision_digest, safe_metadata_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![id, now_unix(), a.actor_id, a.action, a.target_type, a.target_id, a.decision, a.revision_digest, a.metadata.to_string()],
    )?;
    Ok(id)
}

/// Newest first, before the cursor sequence.
pub fn list_audit(c: &Connection, before_seq: Option<i64>, limit: u32) -> Result<Vec<AuditRow>> {
    let mut stmt = c.prepare(
        "SELECT seq, id, occurred_at, actor_id, action, target_type, target_id, decision, revision_digest, safe_metadata_json FROM audit_events WHERE seq < ?1 ORDER BY seq DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![before_seq.unwrap_or(i64::MAX), limit], |r| {
        Ok(AuditRow {
            seq: r.get(0)?,
            id: r.get(1)?,
            occurred_at: r.get(2)?,
            actor_id: r.get(3)?,
            action: r.get(4)?,
            target_type: r.get(5)?,
            target_id: r.get(6)?,
            decision: r.get(7)?,
            revision_digest: r.get(8)?,
            safe_metadata_json: r.get(9)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn audit_is_append_only() {
        let s = Store::open_in_memory().expect("store");
        s.tx(|c| {
            append_audit(
                c,
                AuditInsert {
                    actor_id: None,
                    action: "test",
                    target_type: "system",
                    target_id: None,
                    decision: "allowed",
                    revision_digest: None,
                    metadata: serde_json::json!({}),
                },
            )
        })
        .expect("append");
        let upd = s.tx(|c| Ok(c.execute("UPDATE audit_events SET action = 'x'", [])?));
        assert!(upd.is_err());
        let del = s.tx(|c| Ok(c.execute("DELETE FROM audit_events", [])?));
        assert!(del.is_err());
        assert_eq!(s.read(|c| list_audit(c, None, 10)).expect("list").len(), 1);
    }

    #[test]
    fn one_use_tokens() {
        let s = Store::open_in_memory().expect("store");
        let now = now_unix();
        s.tx(|c| insert_enrollment_token(c, "t1", "v1", "client", now + 60, None))
            .expect("ins");
        assert_eq!(
            s.tx(|c| consume_enrollment_token(c, "v1", now))
                .expect("c1")
                .as_deref(),
            Some("client")
        );
        assert_eq!(
            s.tx(|c| consume_enrollment_token(c, "v1", now))
                .expect("c2"),
            None,
            "reuse rejected"
        );
        s.tx(|c| insert_enrollment_token(c, "t2", "v2", "client", now - 1, None))
            .expect("ins");
        assert_eq!(
            s.tx(|c| consume_enrollment_token(c, "v2", now))
                .expect("c3"),
            None,
            "expired rejected"
        );
        s.tx(|c| insert_bootstrap_token(c, "b", now + 60))
            .expect("b");
        assert!(s.tx(|c| consume_bootstrap_token(c, "b", now)).expect("b1"));
        assert!(!s.tx(|c| consume_bootstrap_token(c, "b", now)).expect("b2"));
    }

    #[test]
    fn failed_transaction_leaves_no_partial_state() {
        let s = Store::open_in_memory().expect("store");
        let res: Result<()> = s.tx(|c| {
            bump_epoch(c)?;
            Err(StoreError::Unavailable("injected".into()))
        });
        assert!(res.is_err());
        assert_eq!(s.read(get_epoch).expect("epoch"), 1, "rolled back");
    }

    #[test]
    fn telemetry_settings_cas() {
        let s = Store::open_in_memory().expect("store");
        assert_eq!(
            s.tx(|c| put_telemetry_settings(c, 0, "{}", None))
                .expect("g1"),
            1
        );
        assert!(s.tx(|c| put_telemetry_settings(c, 0, "{}", None)).is_err());
        assert_eq!(
            s.tx(|c| put_telemetry_settings(c, 1, "{\"a\":1}", None))
                .expect("g2"),
            2
        );
        assert!(
            s.tx(|c| put_telemetry_settings(c, 1, "{}", None)).is_err(),
            "stale write"
        );
    }
}
