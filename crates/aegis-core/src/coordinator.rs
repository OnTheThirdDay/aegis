//! Single-writer activation coordinator (02 §5, 04 §5, B-005).
//!
//! Protocol for every activation:
//! 1. prepare the pinned revision into a detached compiled bundle (no
//!    traffic effect);
//! 2. under the writer lock, recheck the bound validation, profile ETag,
//!    expected active revision and absence of an unresolved intent;
//! 3. durably commit revision state + activation intent + job binding +
//!    audit (`committed`) in one SQLite transaction;
//! 4. CAS-publish the bundle through the admission gate (linearization);
//! 5. durably record `applied` and complete the job.
//!
//! Failure before (3) is a rejection with no visible effect. Failure after
//! (3) is never reported as a no-op: the job becomes `reconciling`, new
//! admission closes, and restart/reconcile/supersede resolves it.

use crate::agent::AgentCell;
use crate::gate::{AdmissionGate, RuntimeBundle};
use crate::rfc3339;
use aegis_config::{
    compile, parse_json, security_diff, to_json, CompiledConfig, Environment, NodeConfig,
};
use aegis_contracts::observability::{Event, Observability, OperationResult};
use aegis_contracts::state::{AgentState, RevisionState};
use aegis_contracts::Role;
use aegis_identity::IdentitySnapshot;
use aegis_platform::Registry;
use aegis_storage::{self as db, AuditInsert, JobRow, Store, StoreError};
use aegis_traffic_policy::HostCapabilities;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub const VALIDATION_TTL_SECONDS: i64 = 300;
pub const JOB_DEADLINE_SECONDS: i64 = 120;
pub const IDEMPOTENCY_RETENTION_SECONDS: i64 = 24 * 3600;

/// Installed capability environment profiles are validated against.
pub struct CapabilityEnv {
    pub registry: Registry,
    pub host_vpn: HostCapabilities,
    pub digest: String,
}

impl CapabilityEnv {
    pub fn new(registry: Registry, host_vpn: HostCapabilities) -> Self {
        let digest = registry.capability_digest(&host_vpn);
        CapabilityEnv {
            registry,
            host_vpn,
            digest,
        }
    }

    pub fn compile(&self, cfg: &NodeConfig) -> Result<CompiledConfig, Vec<String>> {
        compile(
            cfg,
            &Environment {
                registry: &self.registry,
                host_vpn: &self.host_vpn,
            },
        )
    }
}

/// Fault-injection points for crash-cut tests (TC-C01/TC-C02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailPoint {
    Prepare,
    CommitTx,
    AfterCommit,
    Publish,
    AfterPublish,
    AppliedTx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailAction {
    Continue,
    /// The step fails (I/O error, CAS mismatch...).
    Fail,
    /// Simulate the process dying at this point: stop immediately with no
    /// further persistence.
    Crash,
}

pub trait FailPoints: Send + Sync {
    fn check(&self, point: FailPoint) -> FailAction;
}

pub struct NoFailPoints;

impl FailPoints for NoFailPoints {
    fn check(&self, _: FailPoint) -> FailAction {
        FailAction::Continue
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoordinatorError {
    NotFound,
    PreconditionFailed,
    Conflict(&'static str),
    Invalid(Vec<String>),
    Storage(String),
    /// Simulated process death (tests only).
    Crashed,
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoordinatorError::NotFound => f.write_str("not found"),
            CoordinatorError::PreconditionFailed => f.write_str("stale precondition"),
            CoordinatorError::Conflict(c) => write!(f, "conflict: {c}"),
            CoordinatorError::Invalid(e) => write!(f, "invalid configuration: {}", e.join("; ")),
            CoordinatorError::Storage(e) => write!(f, "storage unavailable: {e}"),
            CoordinatorError::Crashed => f.write_str("simulated crash"),
        }
    }
}

impl std::error::Error for CoordinatorError {}

impl From<StoreError> for CoordinatorError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => CoordinatorError::NotFound,
            StoreError::Conflict(_) => CoordinatorError::Conflict("concurrent modification"),
            other => CoordinatorError::Storage(other.to_string()),
        }
    }
}

type CResult<T> = Result<T, CoordinatorError>;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ValidationReport {
    pub validation_id: String,
    pub profile_id: String,
    pub target_revision_id: String,
    pub config_digest: String,
    pub profile_etag: String,
    pub capability_digest: String,
    pub security_epoch: String,
    pub expires_at: String,
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub security_diff: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ActivateRequest {
    pub actor_id: Option<String>,
    pub profile_id: String,
    pub if_match: String,
    pub idempotency_key: String,
    pub target_revision_id: String,
    pub config_digest: String,
    pub validation_id: String,
}

#[derive(Clone, Debug)]
pub struct SupersedeRequest {
    pub actor_id: Option<String>,
    pub pending_operation_id: String,
    pub expected_runtime_revision_id: Option<String>,
    pub expected_security_epoch: i64,
    pub recovery_revision_id: String,
    pub recovery_config_digest: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub admission_enabled: bool,
    pub runtime_revision_id: Option<String>,
    pub applied_revision_id: Option<String>,
    pub pending_operation_id: Option<String>,
    pub updated_at: String,
    pub restart_required: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No configuration was ever applied.
    Fresh,
    /// The last durably applied revision is live again.
    Restored { revision_id: String },
    /// A committed-but-unapplied intent was completed.
    Reconciled {
        operation_id: String,
        revision_id: String,
    },
    /// A committed intent could not be completed; admission stays closed
    /// until an explicit supersede.
    Blocked {
        operation_id: String,
        reason: String,
    },
}

/// Callback that terminates sessions of newly revoked identities.
pub type RevokeHook = Arc<dyn Fn(&[[u8; 32]]) + Send + Sync>;

pub struct Coordinator {
    store: Arc<Store>,
    gate: Arc<AdmissionGate>,
    env: Arc<CapabilityEnv>,
    agent: Arc<AgentCell>,
    node_id: String,
    role: Role,
    writer: Mutex<()>,
    failpoints: Arc<dyn FailPoints>,
    obs: Arc<dyn Observability>,
    restart_required: Mutex<Vec<String>>,
    on_revoke: Mutex<Option<RevokeHook>>,
}

#[allow(clippy::too_many_arguments)]
fn audit(
    c: &db::Connection,
    actor: Option<&str>,
    action: &str,
    target_type: &str,
    target_id: Option<&str>,
    decision: &str,
    digest: Option<&str>,
    meta: Value,
) -> db::Result<String> {
    db::append_audit(
        c,
        AuditInsert {
            actor_id: actor,
            action,
            target_type,
            target_id,
            decision,
            revision_digest: digest,
            metadata: meta,
        },
    )
}

fn parse_fingerprint(hex_fp: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_fp).ok()?;
    bytes.try_into().ok()
}

impl Coordinator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: Arc<Store>,
        gate: Arc<AdmissionGate>,
        env: Arc<CapabilityEnv>,
        agent: Arc<AgentCell>,
        node_id: String,
        role: Role,
        failpoints: Arc<dyn FailPoints>,
        obs: Arc<dyn Observability>,
    ) -> Self {
        Coordinator {
            store,
            gate,
            env,
            agent,
            node_id,
            role,
            writer: Mutex::new(()),
            failpoints,
            obs,
            restart_required: Mutex::new(Vec::new()),
            on_revoke: Mutex::new(None),
        }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    pub fn gate(&self) -> &Arc<AdmissionGate> {
        &self.gate
    }

    pub fn env(&self) -> &Arc<CapabilityEnv> {
        &self.env
    }

    pub fn agent(&self) -> &Arc<AgentCell> {
        &self.agent
    }

    /// Callback used to terminate sessions of revoked identities.
    pub fn set_on_revoke(&self, f: RevokeHook) {
        *self.on_revoke.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    /// Publish current durable device bindings under the admission writer gate.
    /// No store access occurs on handshakes or OPEN admission.
    pub fn refresh_identities(&self) -> CResult<()> {
        let _writer = self.lock_writer();
        self.refresh_identities_locked()
    }

    fn refresh_identities_locked(&self) -> CResult<()> {
        let (epoch, revoked, bindings) = self.store.read(|c| {
            Ok((
                db::get_epoch(c)?,
                db::revoked_fingerprints(c)?,
                db::active_identity_bindings(c)?,
            ))
        })?;
        let mut snapshot = IdentitySnapshot::new(
            epoch as u64,
            revoked.iter().filter_map(|f| parse_fingerprint(f)),
        );
        if let Some(bundle) = self.gate.current() {
            let id = &bundle.compiled.config.identity;
            let cutoff = id.legacy_identity_until.unwrap_or(1_800_662_400);
            if id.require_enrollment {
                let entries = bindings.into_iter().filter_map(|(fp, name, role)| {
                    Some((
                        parse_fingerprint(&fp)?,
                        name,
                        match role.as_str() {
                            "client" => Role::Client,
                            "gateway" => Role::Gateway,
                            _ => return None,
                        },
                    ))
                });
                snapshot = snapshot.with_registry(entries, cutoff);
            } else {
                snapshot = snapshot.with_legacy_deadline(cutoff);
            }
        }
        self.gate.publish_identity(snapshot);
        Ok(())
    }

    fn lock_writer(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writer.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn fail(&self, p: FailPoint) -> FailAction {
        self.failpoints.check(p)
    }

    /// Parse, normalize and check node binding of a profile specification.
    fn typed_spec(&self, spec: &Value) -> CResult<(NodeConfig, Value, String)> {
        let cfg = parse_json(spec).map_err(|e| CoordinatorError::Invalid(vec![e.to_string()]))?;
        if cfg.node_id != self.node_id || cfg.role != self.role {
            return Err(CoordinatorError::Invalid(vec![
                "profile node_id/role must match this node".into(),
            ]));
        }
        let normalized = to_json(&cfg);
        let digest = aegis_config::digest_value(&normalized);
        Ok((cfg, normalized, digest))
    }

    fn compile_revision(&self, rev: &db::RevisionRow) -> CResult<CompiledConfig> {
        let spec: Value = serde_json::from_str(&rev.spec_json)
            .map_err(|e| CoordinatorError::Invalid(vec![e.to_string()]))?;
        let cfg = parse_json(&spec).map_err(|e| CoordinatorError::Invalid(vec![e.to_string()]))?;
        let compiled = self.env.compile(&cfg).map_err(CoordinatorError::Invalid)?;
        if compiled.digest != rev.digest {
            return Err(CoordinatorError::Invalid(vec![
                "revision digest mismatch".into()
            ]));
        }
        Ok(compiled)
    }

    // -----------------------------------------------------------------
    // Profiles and revisions
    // -----------------------------------------------------------------

    pub fn create_profile(
        &self,
        actor: Option<&str>,
        name: &str,
        spec: &Value,
    ) -> CResult<db::ProfileRow> {
        if name.is_empty() || name.len() > 100 {
            return Err(CoordinatorError::Invalid(vec![
                "name must be 1..=100 characters".into(),
            ]));
        }
        let (_cfg, normalized, digest) = self.typed_spec(spec)?;
        let now = db::now_unix();
        let profile_id = db::new_id();
        let rev = db::RevisionRow {
            id: db::new_id(),
            profile_id: profile_id.clone(),
            parent_id: None,
            spec_json: normalized.to_string(),
            digest: digest.clone(),
            actor_id: actor.map(str::to_owned),
            created_at: now,
            seq: 1,
            state: RevisionState::Draft.as_str().into(),
        };
        let profile = db::ProfileRow {
            id: profile_id.clone(),
            name: name.to_owned(),
            desired_revision_id: rev.id.clone(),
            active_revision_id: None,
            generation: 1,
            owner_id: actor.map(str::to_owned),
            created_at: now,
        };
        let _w = self.lock_writer();
        self.store.tx(|c| {
            db::insert_revision(c, &rev)?;
            db::insert_profile(c, &profile)?;
            audit(
                c,
                actor,
                "profile.create",
                "profile",
                Some(&profile_id),
                "allowed",
                Some(&digest),
                json!({"revision_id": rev.id}),
            )?;
            Ok(())
        })?;
        Ok(profile)
    }

    /// Apply a JSON merge patch to name/specification and create a new
    /// immutable desired revision. Does not validate or publish it.
    pub fn patch_profile(
        &self,
        actor: Option<&str>,
        id: &str,
        if_match: &str,
        name: Option<&str>,
        spec_patch: Option<&Value>,
    ) -> CResult<db::ProfileRow> {
        let _w = self.lock_writer();
        let profile = self.store.read(|c| db::get_profile(c, id))?;
        if profile.etag() != if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        let desired = self
            .store
            .read(|c| db::get_revision(c, &profile.desired_revision_id))?;
        let mut spec: Value = serde_json::from_str(&desired.spec_json)
            .map_err(|e| CoordinatorError::Storage(e.to_string()))?;
        if let Some(p) = spec_patch {
            merge_patch(&mut spec, p);
        }
        let (_cfg, normalized, digest) = self.typed_spec(&spec)?;
        let new_name = name.unwrap_or(&profile.name).to_owned();
        if new_name.is_empty() || new_name.len() > 100 {
            return Err(CoordinatorError::Invalid(vec![
                "name must be 1..=100 characters".into(),
            ]));
        }
        let now = db::now_unix();
        let rev_id = db::new_id();
        self.store.tx(|c| {
            let seq = db::next_revision_seq(c, id)?;
            db::insert_revision(
                c,
                &db::RevisionRow {
                    id: rev_id.clone(),
                    profile_id: id.to_owned(),
                    parent_id: Some(desired.id.clone()),
                    spec_json: normalized.to_string(),
                    digest: digest.clone(),
                    actor_id: actor.map(str::to_owned),
                    created_at: now,
                    seq,
                    state: RevisionState::Draft.as_str().into(),
                },
            )?;
            db::update_profile_desired(c, id, &new_name, &rev_id, profile.generation)?;
            audit(
                c,
                actor,
                "profile.patch",
                "profile",
                Some(id),
                "allowed",
                Some(&digest),
                json!({"revision_id": rev_id}),
            )?;
            Ok(())
        })?;
        Ok(self.store.read(|c| db::get_profile(c, id))?)
    }

    // -----------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------

    pub fn validate(
        &self,
        actor: Option<&str>,
        profile_id: &str,
        if_match: &str,
        target_revision_id: &str,
    ) -> CResult<ValidationReport> {
        let profile = self.store.read(|c| db::get_profile(c, profile_id))?;
        if profile.etag() != if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        if profile.desired_revision_id != target_revision_id {
            return Err(CoordinatorError::Conflict(
                "target_revision_id is not the profile's desired revision",
            ));
        }
        let rev = self
            .store
            .read(|c| db::get_revision(c, target_revision_id))?;
        let epoch = self.store.read(db::get_epoch)?;
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut diff_lines = Vec::new();
        match serde_json::from_str::<Value>(&rev.spec_json)
            .map_err(|e| vec![e.to_string()])
            .and_then(|v| parse_json(&v).map_err(|e| vec![e.to_string()]))
        {
            Ok(cfg) => {
                match self.env.compile(&cfg) {
                    Ok(c) => warnings.extend(c.warnings),
                    Err(e) => errors.extend(e),
                }
                let current = self.gate.current();
                let diff = security_diff(current.as_ref().map(|b| &b.compiled.config), &cfg);
                errors.extend(diff.forbidden.iter().cloned());
                diff_lines.extend(diff.security.iter().cloned());
                diff_lines.extend(
                    diff.restart_required
                        .iter()
                        .map(|r| format!("restart required: {r}")),
                );
            }
            Err(e) => errors.extend(e),
        }
        errors.truncate(100);
        warnings.truncate(100);
        diff_lines.truncate(100);
        let valid = errors.is_empty();
        let now = db::now_unix();
        let report = ValidationReport {
            validation_id: db::new_id(),
            profile_id: profile_id.to_owned(),
            target_revision_id: target_revision_id.to_owned(),
            config_digest: rev.digest.clone(),
            profile_etag: profile.etag(),
            capability_digest: self.env.digest.clone(),
            security_epoch: epoch.to_string(),
            expires_at: rfc3339(now + VALIDATION_TTL_SECONDS),
            valid,
            errors,
            warnings,
            security_diff: diff_lines,
        };
        let row = db::ValidationRow {
            id: report.validation_id.clone(),
            profile_id: profile_id.to_owned(),
            target_revision_id: target_revision_id.to_owned(),
            config_digest: rev.digest.clone(),
            profile_etag: report.profile_etag.clone(),
            capability_digest: report.capability_digest.clone(),
            security_epoch: epoch,
            expires_at: now + VALIDATION_TTL_SECONDS,
            valid,
            actor_id: actor.map(str::to_owned),
            report_json: serde_json::to_string(&report).unwrap_or_default(),
        };
        self.store.tx(|c| {
            db::insert_validation(c, &row)?;
            if valid && rev.state == RevisionState::Draft.as_str() {
                db::set_revision_state(c, &rev.id, RevisionState::Validated.as_str())?;
            }
            audit(
                c,
                actor,
                "profile.validate",
                "profile",
                Some(profile_id),
                if valid { "allowed" } else { "denied" },
                Some(&rev.digest),
                json!({"validation_id": row.id}),
            )?;
            Ok(())
        })?;
        Ok(report)
    }

    /// Check a stored validation report still authorizes this activation.
    fn check_validation(
        &self,
        c: &db::Connection,
        validation_id: &str,
        profile: &db::ProfileRow,
        expected_etag: &str,
        revision_id: &str,
        digest: &str,
    ) -> CResult<()> {
        let v = db::get_validation(c, validation_id)
            .map_err(|_| CoordinatorError::Conflict("unknown validation_id"))?;
        let epoch = db::get_epoch(c)?;
        let ok = v.valid
            && v.profile_id == profile.id
            && v.target_revision_id == revision_id
            && v.config_digest == digest
            && v.profile_etag == expected_etag
            && v.capability_digest == self.env.digest
            && v.security_epoch == epoch
            && v.expires_at > db::now_unix();
        if ok {
            Ok(())
        } else {
            Err(CoordinatorError::Conflict(
                "validation report does not authorize this activation; validate again",
            ))
        }
    }

    // -----------------------------------------------------------------
    // Activation
    // -----------------------------------------------------------------

    fn request_digest(req: &ActivateRequest, kind: &str) -> String {
        db::sha256_hex(
            json!({
                "kind": kind,
                "profile": req.profile_id,
                "if_match": req.if_match,
                "target_revision_id": req.target_revision_id,
                "config_digest": req.config_digest,
                "validation_id": req.validation_id,
            })
            .to_string()
            .as_bytes(),
        )
    }

    /// Accept an activation job (202). Idempotent per actor/method/path/key.
    pub fn submit_activation(
        &self,
        req: &ActivateRequest,
        canonical_path: &str,
    ) -> CResult<JobRow> {
        self.submit_profile_job(req, canonical_path, "profile_activate")
    }

    fn submit_profile_job(
        &self,
        req: &ActivateRequest,
        canonical_path: &str,
        kind: &str,
    ) -> CResult<JobRow> {
        let actor = req.actor_id.clone().unwrap_or_else(|| "system".into());
        let key_hash = db::sha256_hex(req.idempotency_key.as_bytes());
        let digest = Self::request_digest(req, kind);
        let _w = self.lock_writer();
        if let Some(existing) = self
            .store
            .read(|c| db::get_idempotency(c, &actor, "POST", canonical_path, &key_hash))?
        {
            if existing.request_digest != digest {
                return Err(CoordinatorError::Conflict(
                    "idempotency key reused with different input",
                ));
            }
            return Ok(self.store.read(|c| db::get_job(c, &existing.job_id))?);
        }
        let profile = self.store.read(|c| db::get_profile(c, &req.profile_id))?;
        if profile.etag() != req.if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        if self.store.read(db::unresolved_intent)?.is_some() {
            return Err(CoordinatorError::Conflict(
                "a committed activation is unresolved; reconcile or supersede first",
            ));
        }
        let rev = self
            .store
            .read(|c| db::get_revision(c, &req.target_revision_id))?;
        if rev.profile_id != profile.id || rev.digest != req.config_digest {
            return Err(CoordinatorError::Conflict(
                "target revision/digest mismatch",
            ));
        }
        self.store.read_as(|c| {
            self.check_validation(
                c,
                &req.validation_id,
                &profile,
                &req.if_match,
                &rev.id,
                &rev.digest,
            )
        })?;
        let runtime = self.store.read(db::get_runtime_state)?;
        let now = db::now_unix();
        let job = JobRow {
            id: db::new_id(),
            kind: kind.into(),
            actor_id: req.actor_id.clone(),
            status: "pending".into(),
            target_type: "profile".into(),
            target_id: profile.id.clone(),
            target_revision_id: Some(rev.id.clone()),
            config_digest: Some(rev.digest.clone()),
            validation_id: Some(req.validation_id.clone()),
            expected_profile_etag: Some(req.if_match.clone()),
            expected_active_revision_id: runtime.applied_revision_id,
            expected_node_etag: None,
            commit_state: "uncommitted".into(),
            operation_id: None,
            deadline_at: now + JOB_DEADLINE_SECONDS,
            result_revision_id: None,
            superseded_by: None,
            safe_error_code: None,
            created_at: now,
        };
        self.store.tx(|c| {
            db::insert_job(c, &job)?;
            db::insert_idempotency(
                c,
                &actor,
                "POST",
                canonical_path,
                &key_hash,
                &digest,
                &job.id,
                now + IDEMPOTENCY_RETENTION_SECONDS,
            )?;
            audit(
                c,
                req.actor_id.as_deref(),
                &format!("{kind}.accepted"),
                "profile",
                Some(&profile.id),
                "allowed",
                Some(&rev.digest),
                json!({"job_id": job.id}),
            )?;
            Ok(())
        })?;
        Ok(job)
    }

    fn fail_job(&self, job: &mut JobRow, code: &str, revision_rejected: bool) {
        job.status = "failed".into();
        job.commit_state = "uncommitted".into();
        job.safe_error_code = Some(code.into());
        let _ = self.store.tx(|c| {
            db::update_job(c, job)?;
            if revision_rejected {
                if let Some(r) = &job.target_revision_id {
                    let rev = db::get_revision(c, r)?;
                    if matches!(rev.state.as_str(), "draft" | "validated" | "prepared") {
                        db::set_revision_state(c, r, RevisionState::Rejected.as_str())?;
                    }
                }
            }
            audit(
                c,
                job.actor_id.as_deref(),
                "activation.rejected",
                "profile",
                Some(&job.target_id),
                "error",
                job.config_digest.as_deref(),
                json!({"job_id": job.id, "code": code}),
            )?;
            Ok(())
        });
        self.obs.record(Event::ConfigActivation {
            result: OperationResult::Error,
        });
    }

    fn enter_reconciling(&self, job: &mut JobRow, code: &str) {
        self.gate.set_admission(false);
        self.agent.transition(AgentState::Degraded {
            admission_allowed: false,
        });
        job.status = "reconciling".into();
        job.commit_state = "committed".into();
        job.safe_error_code = Some(code.into());
        let _ = self.store.tx(|c| db::update_job(c, job));
    }

    /// Execute an accepted job to completion. Runs on a blocking thread.
    pub fn run_job(&self, job_id: &str) -> CResult<JobRow> {
        let mut job = self.store.read(|c| db::get_job(c, job_id))?;
        if job.status != "pending" {
            return Ok(job);
        }
        job.status = "running".into();
        self.store.tx(|c| db::update_job(c, &job))?;
        let Some(rev_id) = job.target_revision_id.clone() else {
            self.fail_job(&mut job, "invalid_job", false);
            return Ok(job);
        };
        // 1. Prepare a detached bundle.
        let rev = self.store.read(|c| db::get_revision(c, &rev_id))?;
        match self.fail(FailPoint::Prepare) {
            FailAction::Continue => {}
            FailAction::Fail => {
                self.fail_job(&mut job, "prepare_failed", false);
                return Ok(job);
            }
            FailAction::Crash => return Err(CoordinatorError::Crashed),
        }
        let compiled = match self.compile_revision(&rev) {
            Ok(c) => Arc::new(c),
            Err(_) => {
                self.fail_job(&mut job, "validation_failed", true);
                return Ok(job);
            }
        };
        let restart = {
            let current = self.gate.current();
            security_diff(
                current.as_ref().map(|b| &b.compiled.config),
                &compiled.config,
            )
            .restart_required
        };
        // 2. Recheck under the single-writer lock.
        let _w = self.lock_writer();
        let recheck = self.store.read_as(|c| -> CResult<()> {
            let profile = db::get_profile(c, &job.target_id)?;
            let expected_etag = job.expected_profile_etag.clone().unwrap_or_default();
            if profile.etag() != expected_etag {
                return Err(CoordinatorError::Conflict(
                    "profile changed since acceptance",
                ));
            }
            let runtime = db::get_runtime_state(c)?;
            if runtime.applied_revision_id != job.expected_active_revision_id {
                return Err(CoordinatorError::Conflict(
                    "active revision changed since acceptance",
                ));
            }
            if db::unresolved_intent(c)?.is_some() {
                return Err(CoordinatorError::Conflict(
                    "unresolved committed activation",
                ));
            }
            if let Some(v) = &job.validation_id {
                self.check_validation(c, v, &profile, &expected_etag, &rev.id, &rev.digest)?;
            }
            Ok(())
        });
        if let Err(e) = recheck {
            let code = match e {
                CoordinatorError::Storage(_) => "storage_unavailable",
                _ => "stale",
            };
            self.fail_job(&mut job, code, false);
            return Ok(job);
        }
        // 3. Durable commit of the activation intent.
        let op_id = db::new_id();
        let epoch = self.store.read(db::get_epoch)?;
        let fp = self.fail(FailPoint::CommitTx);
        if fp == FailAction::Crash {
            return Err(CoordinatorError::Crashed);
        }
        let commit = self.store.tx(|c| {
            db::insert_intent(
                c,
                &db::IntentRow {
                    operation_id: op_id.clone(),
                    job_id: Some(job.id.clone()),
                    profile_id: job.target_id.clone(),
                    target_revision_id: rev.id.clone(),
                    expected_active_revision_id: job.expected_active_revision_id.clone(),
                    config_digest: rev.digest.clone(),
                    security_epoch: epoch,
                    commit_state: "committed".into(),
                    committed_at: db::now_unix(),
                    applied_at: None,
                    superseded_by: None,
                    reason: None,
                },
            )?;
            db::set_revision_state(c, &rev.id, RevisionState::Committed.as_str())?;
            let mut committed = job.clone();
            committed.commit_state = "committed".into();
            committed.operation_id = Some(op_id.clone());
            db::update_job(c, &committed)?;
            audit(
                c,
                job.actor_id.as_deref(),
                "activation.committed",
                "profile",
                Some(&job.target_id),
                "committed",
                Some(&rev.digest),
                json!({"job_id": job.id, "operation_id": op_id}),
            )?;
            if fp == FailAction::Fail {
                // Injected I/O failure inside the transaction: rolls back.
                return Err(StoreError::Unavailable("injected commit failure".into()));
            }
            Ok(())
        });
        if commit.is_err() {
            self.fail_job(&mut job, "storage_unavailable", false);
            return Ok(job);
        }
        job.commit_state = "committed".into();
        job.operation_id = Some(op_id.clone());
        if self.fail(FailPoint::AfterCommit) == FailAction::Crash {
            return Err(CoordinatorError::Crashed);
        }
        // 4. Publish (linearization point).
        let expected = self.gate.current_revision();
        let bundle = Arc::new(RuntimeBundle {
            revision_id: rev.id.clone(),
            profile_id: job.target_id.clone(),
            operation_id: op_id.clone(),
            digest: rev.digest.clone(),
            compiled,
        });
        let published = match self.fail(FailPoint::Publish) {
            FailAction::Crash => return Err(CoordinatorError::Crashed),
            FailAction::Fail => false,
            FailAction::Continue => self.gate.publish(expected.as_deref(), bundle).is_ok(),
        };
        if !published {
            self.enter_reconciling(&mut job, "publication_failed");
            return Ok(job);
        }
        if self.fail(FailPoint::AfterPublish) == FailAction::Crash {
            return Err(CoordinatorError::Crashed);
        }
        // 5. Durable applied record.
        match self.complete_applied(&mut job, &op_id) {
            Ok(()) => {
                *self
                    .restart_required
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = restart;
                Ok(job)
            }
            Err(CoordinatorError::Crashed) => Err(CoordinatorError::Crashed),
            Err(_) => {
                // Published but not durably recorded: hold new admissions
                // until durable/runtime agreement is restored.
                self.enter_reconciling(&mut job, "applied_record_failed");
                Ok(job)
            }
        }
    }

    /// Persist the applied result for `op_id` and reopen admission.
    fn complete_applied(&self, job: &mut JobRow, op_id: &str) -> CResult<()> {
        let fp = self.fail(FailPoint::AppliedTx);
        if fp == FailAction::Crash {
            return Err(CoordinatorError::Crashed);
        }
        let intent = self.store.read(|c| db::get_intent(c, op_id))?;
        self.store.tx(|c| {
            let profile = db::get_profile(c, &intent.profile_id)?;
            let previous = db::get_runtime_state(c)?.applied_revision_id;
            db::mark_intent_applied(c, op_id, db::now_unix())?;
            db::set_runtime_applied(c, &intent.target_revision_id, &intent.profile_id, op_id)?;
            if profile.active_revision_id.as_deref() != Some(intent.target_revision_id.as_str()) {
                db::set_profile_active(c, &intent.profile_id, &intent.target_revision_id)?;
            }
            db::set_revision_state(
                c,
                &intent.target_revision_id,
                RevisionState::Active.as_str(),
            )?;
            if let Some(prev) = previous.filter(|p| *p != intent.target_revision_id) {
                db::set_revision_state(c, &prev, RevisionState::Superseded.as_str())?;
            }
            job.status = "succeeded".into();
            job.commit_state = "applied".into();
            job.result_revision_id = Some(intent.target_revision_id.clone());
            job.safe_error_code = None;
            db::update_job(c, job)?;
            audit(
                c,
                job.actor_id.as_deref(),
                "activation.applied",
                "profile",
                Some(&intent.profile_id),
                "applied",
                Some(&intent.config_digest),
                json!({"job_id": job.id, "operation_id": op_id}),
            )?;
            if fp == FailAction::Fail {
                return Err(StoreError::Unavailable(
                    "injected applied-record failure".into(),
                ));
            }
            Ok(())
        })?;
        self.refresh_identities_locked()?;
        self.gate.set_admission(true);
        self.agent.transition(AgentState::Ready);
        self.obs.record(Event::ConfigActivation {
            result: OperationResult::Ok,
        });
        Ok(())
    }

    // -----------------------------------------------------------------
    // Restore
    // -----------------------------------------------------------------

    /// Copy a historical revision into a new revision and activate it through
    /// the same commit protocol. `if_match` is the owning profile's ETag.
    pub fn submit_restore(
        &self,
        actor: Option<&str>,
        source_revision_id: &str,
        if_match: &str,
        idempotency_key: &str,
        canonical_path: &str,
    ) -> CResult<JobRow> {
        let source = self
            .store
            .read(|c| db::get_revision(c, source_revision_id))?;
        let profile = self
            .store
            .read(|c| db::get_profile(c, &source.profile_id))?;
        if profile.etag() != if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        let actor_key = actor.unwrap_or("system").to_owned();
        let key_hash = db::sha256_hex(idempotency_key.as_bytes());
        let digest = db::sha256_hex(
            json!({"kind": "revision_restore", "source": source_revision_id, "if_match": if_match})
                .to_string()
                .as_bytes(),
        );
        {
            let _w = self.lock_writer();
            if let Some(existing) = self
                .store
                .read(|c| db::get_idempotency(c, &actor_key, "POST", canonical_path, &key_hash))?
            {
                if existing.request_digest != digest {
                    return Err(CoordinatorError::Conflict(
                        "idempotency key reused with different input",
                    ));
                }
                return Ok(self.store.read(|c| db::get_job(c, &existing.job_id))?);
            }
        }
        // Stage a new revision (desired/active references are unchanged at
        // acceptance), validate it against the *current* environment.
        let spec: Value = serde_json::from_str(&source.spec_json)
            .map_err(|e| CoordinatorError::Storage(e.to_string()))?;
        let (cfg, normalized, rdigest) = self.typed_spec(&spec)?;
        if let Err(errs) = self.env.compile(&cfg) {
            return Err(CoordinatorError::Invalid(errs));
        }
        let new_rev = db::new_id();
        let now = db::now_unix();
        let _w = self.lock_writer();
        let profile = self
            .store
            .read(|c| db::get_profile(c, &source.profile_id))?;
        if profile.etag() != if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        if self.store.read(db::unresolved_intent)?.is_some() {
            return Err(CoordinatorError::Conflict(
                "a committed activation is unresolved; reconcile or supersede first",
            ));
        }
        let runtime = self.store.read(db::get_runtime_state)?;
        let job = JobRow {
            id: db::new_id(),
            kind: "revision_restore".into(),
            actor_id: actor.map(str::to_owned),
            status: "pending".into(),
            target_type: "profile".into(),
            target_id: profile.id.clone(),
            target_revision_id: Some(new_rev.clone()),
            config_digest: Some(rdigest.clone()),
            validation_id: None,
            expected_profile_etag: Some(if_match.to_owned()),
            expected_active_revision_id: runtime.applied_revision_id,
            expected_node_etag: None,
            commit_state: "uncommitted".into(),
            operation_id: None,
            deadline_at: now + JOB_DEADLINE_SECONDS,
            result_revision_id: None,
            superseded_by: None,
            safe_error_code: None,
            created_at: now,
        };
        self.store.tx(|c| {
            let seq = db::next_revision_seq(c, &profile.id)?;
            db::insert_revision(
                c,
                &db::RevisionRow {
                    id: new_rev.clone(),
                    profile_id: profile.id.clone(),
                    parent_id: Some(source.id.clone()),
                    spec_json: normalized.to_string(),
                    digest: rdigest.clone(),
                    actor_id: actor.map(str::to_owned),
                    created_at: now,
                    seq,
                    state: RevisionState::Validated.as_str().into(),
                },
            )?;
            db::insert_job(c, &job)?;
            db::insert_idempotency(
                c,
                &actor_key,
                "POST",
                canonical_path,
                &key_hash,
                &digest,
                &job.id,
                now + IDEMPOTENCY_RETENTION_SECONDS,
            )?;
            audit(
                c,
                actor,
                "revision_restore.accepted",
                "profile",
                Some(&profile.id),
                "allowed",
                Some(&rdigest),
                json!({"job_id": job.id, "source_revision_id": source.id}),
            )?;
            Ok(())
        })?;
        Ok(job)
    }

    // -----------------------------------------------------------------
    // Startup recovery, reconcile, supersede
    // -----------------------------------------------------------------

    /// Restore runtime state after a (re)start. External admission stays
    /// closed until the durable record and runtime agree.
    pub fn recover(&self) -> CResult<RecoveryOutcome> {
        self.gate.set_admission(false);
        let _w = self.lock_writer();
        // Revocations are reloaded first; a restore never resurrects them.
        let epoch = self.store.read(db::get_epoch)?;
        let revoked: Vec<[u8; 32]> = self
            .store
            .read(db::revoked_fingerprints)?
            .iter()
            .filter_map(|f| parse_fingerprint(f))
            .collect();
        self.gate
            .publish_identity(IdentitySnapshot::new(epoch as u64, revoked));
        // Pre-commit jobs interrupted by the stop are rejections.
        let interrupted = self.store.read(db::interrupted_uncommitted_jobs)?;
        for mut j in interrupted {
            self.fail_job(&mut j, "interrupted", false);
        }
        if let Some(intent) = self.store.read(db::unresolved_intent)? {
            return Ok(self.reconcile_intent(&intent));
        }
        let runtime = self.store.read(db::get_runtime_state)?;
        let Some(rev_id) = runtime.applied_revision_id else {
            return Ok(RecoveryOutcome::Fresh);
        };
        let rev = self.store.read(|c| db::get_revision(c, &rev_id))?;
        match self.compile_revision(&rev) {
            Ok(compiled) => {
                let bundle = Arc::new(RuntimeBundle {
                    revision_id: rev.id.clone(),
                    profile_id: rev.profile_id.clone(),
                    operation_id: runtime.applied_operation_id.unwrap_or_default(),
                    digest: rev.digest.clone(),
                    compiled: Arc::new(compiled),
                });
                let expected = self.gate.current_revision();
                if self.gate.publish(expected.as_deref(), bundle).is_err() {
                    self.agent.transition(AgentState::Degraded {
                        admission_allowed: false,
                    });
                    return Ok(RecoveryOutcome::Blocked {
                        operation_id: String::new(),
                        reason: "publication failed".into(),
                    });
                }
                self.refresh_identities_locked()?;
                self.gate.set_admission(true);
                self.agent.transition(AgentState::Ready);
                Ok(RecoveryOutcome::Restored {
                    revision_id: rev.id,
                })
            }
            Err(e) => {
                self.agent.transition(AgentState::Degraded {
                    admission_allowed: false,
                });
                Ok(RecoveryOutcome::Blocked {
                    operation_id: String::new(),
                    reason: format!("last applied revision no longer valid here: {e}"),
                })
            }
        }
    }

    /// Complete a committed intent idempotently (writer lock held).
    fn reconcile_intent(&self, intent: &db::IntentRow) -> RecoveryOutcome {
        let blocked = |reason: String| {
            self.gate.set_admission(false);
            self.agent.transition(AgentState::Degraded {
                admission_allowed: false,
            });
            RecoveryOutcome::Blocked {
                operation_id: intent.operation_id.clone(),
                reason,
            }
        };
        let rev = match self
            .store
            .read(|c| db::get_revision(c, &intent.target_revision_id))
        {
            Ok(r) => r,
            Err(e) => return blocked(e.to_string()),
        };
        if rev.digest != intent.config_digest {
            return blocked("intent digest does not match revision".into());
        }
        let current = self.gate.current_revision();
        if current.as_deref() != Some(rev.id.as_str()) {
            let compiled = match self.compile_revision(&rev) {
                Ok(c) => Arc::new(c),
                Err(e) => return blocked(format!("cannot safely prepare committed revision: {e}")),
            };
            let bundle = Arc::new(RuntimeBundle {
                revision_id: rev.id.clone(),
                profile_id: intent.profile_id.clone(),
                operation_id: intent.operation_id.clone(),
                digest: rev.digest.clone(),
                compiled,
            });
            if self.gate.publish(current.as_deref(), bundle).is_err() {
                return blocked("publication CAS mismatch".into());
            }
        }
        let mut job = match intent
            .job_id
            .as_ref()
            .and_then(|j| self.store.read(|c| db::get_job(c, j)).ok())
        {
            Some(j) => j,
            None => JobRow {
                id: db::new_id(),
                kind: "profile_activate".into(),
                status: "reconciling".into(),
                target_type: "profile".into(),
                target_id: intent.profile_id.clone(),
                commit_state: "committed".into(),
                ..Default::default()
            },
        };
        match self.complete_applied(&mut job, &intent.operation_id) {
            Ok(()) => RecoveryOutcome::Reconciled {
                operation_id: intent.operation_id.clone(),
                revision_id: rev.id,
            },
            Err(e) => blocked(format!("applied record failed: {e}")),
        }
    }

    /// Local privileged `activation reconcile`: retry the same pinned
    /// operation.
    pub fn reconcile(&self, operation_id: &str) -> CResult<RecoveryOutcome> {
        let _w = self.lock_writer();
        let intent = self
            .store
            .read(db::unresolved_intent)?
            .ok_or(CoordinatorError::Conflict(
                "no unresolved committed activation",
            ))?;
        if intent.operation_id != operation_id {
            return Err(CoordinatorError::Conflict(
                "operation is not the unresolved intent",
            ));
        }
        Ok(self.reconcile_intent(&intent))
    }

    /// Local privileged `activation inspect`.
    pub fn inspect(&self) -> CResult<Value> {
        let intent = self.store.read(db::unresolved_intent)?;
        let epoch = self.store.read(db::get_epoch)?;
        Ok(json!({
            "pending_operation_id": intent.as_ref().map(|i| &i.operation_id),
            "durable_target_revision_id": intent.as_ref().map(|i| &i.target_revision_id),
            "durable_target_digest": intent.as_ref().map(|i| &i.config_digest),
            "actual_runtime_revision_id": self.gate.current_revision(),
            "security_epoch": epoch,
            "admission_enabled": self.gate.admission_enabled(),
        }))
    }

    /// Local privileged `activation supersede`: atomically link the pending
    /// intent to a new committed intent for an explicit recovery revision.
    pub fn supersede(&self, req: &SupersedeRequest) -> CResult<JobRow> {
        if req.reason.trim().is_empty() || req.reason.len() > 512 {
            return Err(CoordinatorError::Invalid(vec![
                "a reason (1..=512 chars) is required".into(),
            ]));
        }
        let _w = self.lock_writer();
        let pending = self
            .store
            .read(db::unresolved_intent)?
            .ok_or(CoordinatorError::Conflict(
                "no unresolved committed activation",
            ))?;
        if pending.operation_id != req.pending_operation_id {
            return Err(CoordinatorError::Conflict(
                "pending operation id does not match",
            ));
        }
        if self.gate.current_revision() != req.expected_runtime_revision_id {
            return Err(CoordinatorError::Conflict(
                "actual runtime revision differs from expectation",
            ));
        }
        let epoch = self.store.read(db::get_epoch)?;
        if epoch != req.expected_security_epoch {
            return Err(CoordinatorError::Conflict(
                "security epoch differs from expectation",
            ));
        }
        let rev = self
            .store
            .read(|c| db::get_revision(c, &req.recovery_revision_id))?;
        if rev.digest != req.recovery_config_digest {
            return Err(CoordinatorError::Conflict("recovery digest mismatch"));
        }
        let compiled = Arc::new(self.compile_revision(&rev)?);
        let new_op = db::new_id();
        let now = db::now_unix();
        let mut job = JobRow {
            id: db::new_id(),
            kind: "profile_activate".into(),
            actor_id: req.actor_id.clone(),
            status: "running".into(),
            target_type: "profile".into(),
            target_id: rev.profile_id.clone(),
            target_revision_id: Some(rev.id.clone()),
            config_digest: Some(rev.digest.clone()),
            validation_id: None,
            expected_profile_etag: None,
            expected_active_revision_id: req.expected_runtime_revision_id.clone(),
            expected_node_etag: None,
            commit_state: "committed".into(),
            operation_id: Some(new_op.clone()),
            deadline_at: now + JOB_DEADLINE_SECONDS,
            result_revision_id: None,
            superseded_by: None,
            safe_error_code: None,
            created_at: now,
        };
        self.store.tx(|c| {
            db::insert_job(c, &job)?;
            db::insert_intent(
                c,
                &db::IntentRow {
                    operation_id: new_op.clone(),
                    job_id: Some(job.id.clone()),
                    profile_id: rev.profile_id.clone(),
                    target_revision_id: rev.id.clone(),
                    expected_active_revision_id: req.expected_runtime_revision_id.clone(),
                    config_digest: rev.digest.clone(),
                    security_epoch: epoch,
                    commit_state: "committed".into(),
                    committed_at: now,
                    applied_at: None,
                    superseded_by: None,
                    reason: None,
                },
            )?;
            db::mark_intent_superseded(c, &pending.operation_id, &new_op, &req.reason)?;
            if let Some(old_job_id) = &pending.job_id {
                if let Ok(mut old) = db::get_job(c, old_job_id) {
                    old.status = "superseded".into();
                    old.commit_state = "superseded".into();
                    old.superseded_by = Some(new_op.clone());
                    db::update_job(c, &old)?;
                }
            }
            db::set_revision_state(c, &pending.target_revision_id, RevisionState::Superseded.as_str())?;
            audit(
                c,
                req.actor_id.as_deref(),
                "activation.supersede",
                "profile",
                Some(&rev.profile_id),
                "superseded",
                Some(&rev.digest),
                json!({"superseded_operation_id": pending.operation_id, "operation_id": new_op, "reason": req.reason}),
            )?;
            Ok(())
        })?;
        let expected = self.gate.current_revision();
        let bundle = Arc::new(RuntimeBundle {
            revision_id: rev.id.clone(),
            profile_id: rev.profile_id.clone(),
            operation_id: new_op.clone(),
            digest: rev.digest.clone(),
            compiled,
        });
        if self.gate.publish(expected.as_deref(), bundle).is_err() {
            self.enter_reconciling(&mut job, "publication_failed");
            return Ok(job);
        }
        if self.complete_applied(&mut job, &new_op).is_err() {
            self.enter_reconciling(&mut job, "applied_record_failed");
        }
        Ok(job)
    }

    // -----------------------------------------------------------------
    // Revocation
    // -----------------------------------------------------------------

    /// Accept a node revocation job bound to the node ETag.
    pub fn submit_revoke(
        &self,
        actor: Option<&str>,
        node_id: &str,
        if_match: &str,
        idempotency_key: &str,
        canonical_path: &str,
    ) -> CResult<JobRow> {
        let actor_key = actor.unwrap_or("system").to_owned();
        let key_hash = db::sha256_hex(idempotency_key.as_bytes());
        let digest = db::sha256_hex(
            json!({"kind": "node_revoke", "node": node_id, "if_match": if_match})
                .to_string()
                .as_bytes(),
        );
        let _w = self.lock_writer();
        if let Some(existing) = self
            .store
            .read(|c| db::get_idempotency(c, &actor_key, "POST", canonical_path, &key_hash))?
        {
            if existing.request_digest != digest {
                return Err(CoordinatorError::Conflict(
                    "idempotency key reused with different input",
                ));
            }
            return Ok(self.store.read(|c| db::get_job(c, &existing.job_id))?);
        }
        let node = self.store.read(|c| db::get_node(c, node_id))?;
        if node.etag() != if_match {
            return Err(CoordinatorError::PreconditionFailed);
        }
        if node.status == "revoked" {
            return Err(CoordinatorError::Conflict("node already revoked"));
        }
        let now = db::now_unix();
        let job = JobRow {
            id: db::new_id(),
            kind: "node_revoke".into(),
            actor_id: actor.map(str::to_owned),
            status: "pending".into(),
            target_type: "node".into(),
            target_id: node_id.to_owned(),
            expected_node_etag: Some(if_match.to_owned()),
            commit_state: "uncommitted".into(),
            deadline_at: now + JOB_DEADLINE_SECONDS,
            created_at: now,
            ..Default::default()
        };
        self.store.tx(|c| {
            db::insert_job(c, &job)?;
            db::insert_idempotency(
                c,
                &actor_key,
                "POST",
                canonical_path,
                &key_hash,
                &digest,
                &job.id,
                now + IDEMPOTENCY_RETENTION_SECONDS,
            )?;
            audit(
                c,
                actor,
                "node_revoke.accepted",
                "node",
                Some(node_id),
                "allowed",
                None,
                json!({"job_id": job.id}),
            )?;
            Ok(())
        })?;
        Ok(job)
    }

    /// Execute a revocation: durably bump the security epoch, then publish
    /// the new identity snapshot and terminate the node's sessions.
    pub fn run_revoke(&self, job_id: &str) -> CResult<JobRow> {
        let mut job = self.store.read(|c| db::get_job(c, job_id))?;
        if job.status != "pending" {
            return Ok(job);
        }
        let _w = self.lock_writer();
        let node = self.store.read(|c| db::get_node(c, &job.target_id))?;
        if Some(node.etag()) != job.expected_node_etag {
            job.status = "failed".into();
            job.safe_error_code = Some("stale".into());
            self.store.tx(|c| db::update_job(c, &job))?;
            return Ok(job);
        }
        let mut fingerprints = Vec::new();
        let epoch = self.store.tx(|c| {
            let epoch = db::bump_epoch(c)?;
            db::set_node_status(c, &node.id, "revoked", node.generation)?;
            fingerprints = db::revoke_node_identities(c, &node.id, epoch)?;
            job.status = "succeeded".into();
            job.commit_state = "applied".into();
            db::update_job(c, &job)?;
            audit(
                c,
                job.actor_id.as_deref(),
                "node.revoke",
                "node",
                Some(&node.id),
                "applied",
                None,
                json!({"job_id": job.id, "security_epoch": epoch}),
            )?;
            Ok(epoch)
        })?;
        let fps: Vec<[u8; 32]> = fingerprints
            .iter()
            .filter_map(|f| parse_fingerprint(f))
            .collect();
        // Durable state is authoritative; fold in the in-memory set too so a
        // store read failure can never shrink the revocation list.
        let mut all: Vec<[u8; 32]> = self
            .store
            .read(db::revoked_fingerprints)
            .unwrap_or_default()
            .iter()
            .filter_map(|f| parse_fingerprint(f))
            .collect();
        all.extend(fps.iter().copied());
        let previous = self.gate.identity_store().current();
        self.gate
            .publish_identity(previous.with_revoked_at(epoch as u64, all));
        if let Some(cb) = self
            .on_revoke
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            cb(&fps);
        }
        Ok(job)
    }

    // -----------------------------------------------------------------
    // Bootstrap import & health
    // -----------------------------------------------------------------

    /// First start with an empty store: import the configuration file as the
    /// initial profile and activate it through the normal protocol.
    pub fn import_initial(&self, cfg: &NodeConfig) -> CResult<JobRow> {
        let spec = to_json(cfg);
        let profile = self.create_profile(None, "default", &spec)?;
        let report = self.validate(
            None,
            &profile.id,
            &profile.etag(),
            &profile.desired_revision_id,
        )?;
        if !report.valid {
            return Err(CoordinatorError::Invalid(report.errors));
        }
        let req = ActivateRequest {
            actor_id: None,
            profile_id: profile.id.clone(),
            if_match: profile.etag(),
            idempotency_key: format!("bootstrap-import-{}", profile.id),
            target_revision_id: report.target_revision_id.clone(),
            config_digest: report.config_digest.clone(),
            validation_id: report.validation_id.clone(),
        };
        let job =
            self.submit_activation(&req, &format!("/api/v1/profiles/{}/activate", profile.id))?;
        self.run_job(&job.id)
    }

    pub fn health(&self) -> Health {
        let state = self.agent.get();
        let (applied, pending) = match (
            self.store.read(db::get_runtime_state),
            self.store.read(db::unresolved_intent),
        ) {
            (Ok(r), Ok(i)) => (r.applied_revision_id, i.map(|i| i.operation_id)),
            // Control-store loss does not stop forwarding; report unknowns.
            _ => (None, None),
        };
        Health {
            status: state.name().into(),
            version: env!("CARGO_PKG_VERSION").into(),
            admission_enabled: self.gate.admission_enabled(),
            runtime_revision_id: self.gate.current_revision(),
            applied_revision_id: applied,
            pending_operation_id: pending,
            updated_at: rfc3339(db::now_unix()),
            restart_required: self
                .restart_required
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
        }
    }
}

/// RFC 7396 JSON merge patch.
pub fn merge_patch(target: &mut Value, patch: &Value) {
    if let Value::Object(p) = patch {
        if !target.is_object() {
            *target = Value::Object(serde_json::Map::new());
        }
        if let Value::Object(t) = target {
            for (k, v) in p {
                if v.is_null() {
                    t.remove(k);
                } else {
                    merge_patch(t.entry(k.clone()).or_insert(Value::Null), v);
                }
            }
        }
    } else {
        *target = patch.clone();
    }
}
