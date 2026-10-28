#![allow(clippy::panic)]
//! Durable activation, crash cuts and recovery: TC-C01..TC-C05, TC-A03,
//! TC-A04, TC-P18 (gate level).

use aegis_config::{parse_toml, to_json, ModuleIds};
use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_contracts::observability::NoopObservability;
use aegis_contracts::Destination;
use aegis_core::{
    ActivateRequest, AdmissionGate, AdmitError, AgentCell, CapabilityEnv, Coordinator,
    CoordinatorError, FailAction, FailPoint, FailPoints, NoFailPoints, RecoveryOutcome,
    SupersedeRequest,
};
use aegis_identity::{IdentitySnapshot, IdentityStore, PeerIdentity};
use aegis_platform::{host_vpn_capabilities, Registry};
use aegis_policy::DecisionInput;
use aegis_storage::{self as db, Store};
use serde_json::json;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

const GATEWAY: &str = r#"
schema_version = "0.1"
node_id = "gw-1"
role = "gateway"
[identity]
peer_auth = "mutual_tls_1_3"
server_identity = "secret://identity/server-cert"
server_private_key = "secret://identity/server-key"
trusted_client_ca = "secret://identity/client-ca"
[[inbounds]]
id = "ws"
kind = "websocket"
bind = "127.0.0.1:18080"
[[outbounds]]
id = "egress"
kind = "direct_tcp"
[routing]
default_outbound = "egress"
default_action = "deny"
[[routing.rules]]
id = "public"
match = "authenticated-and-public-destination"
action = "proxy"
outbound = "egress"
[dns]
mode = "remote_required"
ipv6_policy = "follow-routing-policy"
resolver = "system"
"#;

fn d(
    id: &'static str,
    provides: &'static [Capability],
    requires: &'static [Capability],
) -> ModuleDescriptor {
    ModuleDescriptor {
        module_id: id,
        module_version: "0.1.0",
        api_version: 1,
        roles: &[Role::Client, Role::Gateway],
        operating_systems: &[OsFamily::Linux, OsFamily::Windows, OsFamily::Macos],
        provides,
        requires,
        budget: ResourceBudget::default(),
        maturity: Maturity::Experimental,
        conformance_hash: "",
    }
}

fn env() -> Arc<CapabilityEnv> {
    use Capability::*;
    let mut r = Registry::new(OsFamily::Linux);
    for m in [
        d(ModuleIds::WEBSOCKET, &[ByteStream], &[]),
        d(ModuleIds::MTLS, &[InnerMutualTls], &[ByteStream]),
        d(
            ModuleIds::SESSION,
            &[ConnectionMultiplexing],
            &[InnerMutualTls],
        ),
        d(ModuleIds::SOCKS5, &[ByteStream], &[]),
        d(ModuleIds::HTTP_CONNECT, &[ByteStream], &[]),
        d(ModuleIds::DIRECT, &[ByteStream, EgressAcl], &[]),
        d(ModuleIds::TUNNEL, &[ByteStream], &[ConnectionMultiplexing]),
    ] {
        r.register(m).expect("register");
    }
    Arc::new(CapabilityEnv::new(
        r,
        host_vpn_capabilities(OsFamily::Linux),
    ))
}

#[derive(Default)]
struct Faults(Mutex<HashMap<FailPoint, FailAction>>);

impl Faults {
    fn arm(&self, p: FailPoint, a: FailAction) {
        self.0.lock().expect("lock").insert(p, a);
    }
}

impl FailPoints for Faults {
    fn check(&self, p: FailPoint) -> FailAction {
        self.0
            .lock()
            .expect("lock")
            .remove(&p)
            .unwrap_or(FailAction::Continue)
    }
}

struct Node {
    coord: Arc<Coordinator>,
    gate: Arc<AdmissionGate>,
}

fn boot(path: &Path, faults: Arc<dyn FailPoints>) -> Node {
    let store = Arc::new(Store::open(path).expect("store"));
    let gate = AdmissionGate::new(IdentityStore::new(IdentitySnapshot::default()));
    let coord = Arc::new(Coordinator::new(
        store,
        Arc::clone(&gate),
        env(),
        Arc::new(AgentCell::default()),
        "gw-1".into(),
        Role::Gateway,
        faults,
        Arc::new(NoopObservability),
    ));
    Node { coord, gate }
}

fn initial(node: &Node) -> db::ProfileRow {
    assert_eq!(
        node.coord.recover().expect("recover"),
        RecoveryOutcome::Fresh
    );
    let cfg = parse_toml(GATEWAY).expect("cfg");
    let job = node.coord.import_initial(&cfg).expect("import");
    assert_eq!(job.status, "succeeded", "{job:?}");
    let p = node
        .coord
        .store()
        .read(|c| db::list_profiles(c, None, 10))
        .expect("list");
    p.into_iter().next().expect("profile")
}

/// Patch the profile (default action flip), validate, submit. Returns
/// (job id, target revision id).
fn stage_change(
    node: &Node,
    profile_id: &str,
    default_action: &str,
    key: &str,
) -> (String, String) {
    stage_patch(
        node,
        profile_id,
        &json!({"routing": {"default_action": default_action}}),
        key,
    )
}

/// Merge-patch the profile, validate, submit.
fn stage_patch(
    node: &Node,
    profile_id: &str,
    patch: &serde_json::Value,
    key: &str,
) -> (String, String) {
    let p = node
        .coord
        .store()
        .read(|c| db::get_profile(c, profile_id))
        .expect("p");
    let p = node
        .coord
        .patch_profile(None, profile_id, &p.etag(), None, Some(patch))
        .expect("patch");
    let report = node
        .coord
        .validate(None, profile_id, &p.etag(), &p.desired_revision_id)
        .expect("validate");
    assert!(report.valid, "{:?}", report.errors);
    let job = node
        .coord
        .submit_activation(
            &ActivateRequest {
                actor_id: Some("owner".into()),
                profile_id: profile_id.into(),
                if_match: p.etag(),
                idempotency_key: key.into(),
                target_revision_id: report.target_revision_id.clone(),
                config_digest: report.config_digest.clone(),
                validation_id: report.validation_id,
            },
            &format!("/api/v1/profiles/{profile_id}/activate"),
        )
        .expect("submit");
    (job.id, report.target_revision_id)
}

fn tmpdb() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("state.db");
    (dir, path)
}

#[test]
fn happy_path_activation() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    assert!(node.gate.admission_enabled());
    let (job, rev) = stage_change(&node, &profile.id, "proxy", "key-000000000001");
    let done = node.coord.run_job(&job).expect("run");
    assert_eq!(
        (done.status.as_str(), done.commit_state.as_str()),
        ("succeeded", "applied")
    );
    assert_eq!(node.gate.current_revision().as_deref(), Some(rev.as_str()));
    let h = node.coord.health();
    assert_eq!(h.applied_revision_id.as_deref(), Some(rev.as_str()));
    assert!(h.pending_operation_id.is_none());
    let audit = node
        .coord
        .store()
        .read(|c| db::list_audit(c, None, 100))
        .expect("audit");
    assert!(audit
        .iter()
        .any(|a| a.action == "activation.committed" && a.decision == "committed"));
    assert!(audit
        .iter()
        .any(|a| a.action == "activation.applied" && a.decision == "applied"));
}

#[test]
fn a_later_activation_keeps_an_outstanding_restart_requirement() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    assert!(node.coord.health().restart_required.is_empty());
    let run = |job: &str| {
        let done = node.coord.run_job(job).expect("run");
        assert_eq!(done.status, "succeeded", "{done:?}");
    };
    let (job, _) = stage_patch(
        &node,
        &profile.id,
        &json!({"core": {"idle_timeout_seconds": 301}}),
        "key-restart-0001",
    );
    run(&job);
    let core = vec!["core budgets/timeouts changed".to_string()];
    assert_eq!(node.coord.health().restart_required, core);
    // A routing-only change doesn't apply the core change: still pending.
    let (job, _) = stage_change(&node, &profile.id, "proxy", "key-restart-0002");
    run(&job);
    assert_eq!(node.coord.health().restart_required, core);
    // Reverting it leaves nothing to restart for.
    let (job, _) = stage_patch(
        &node,
        &profile.id,
        &json!({"core": {"idle_timeout_seconds": 300}}),
        "key-restart-0003",
    );
    run(&job);
    assert!(node.coord.health().restart_required.is_empty());
}

#[test]
fn tc_c01_pre_commit_failures_leave_live_policy_unchanged() {
    for point in [FailPoint::Prepare, FailPoint::CommitTx] {
        let (_d, path) = tmpdb();
        let faults = Arc::new(Faults::default());
        let node = boot(&path, faults.clone());
        let profile = initial(&node);
        let before = node.gate.current_revision();
        let (job, rev) = stage_change(&node, &profile.id, "proxy", "key-000000000002");
        faults.arm(point, FailAction::Fail);
        let done = node.coord.run_job(&job).expect("run");
        assert_eq!(
            (done.status.as_str(), done.commit_state.as_str()),
            ("failed", "uncommitted"),
            "{point:?}"
        );
        assert_eq!(
            node.gate.current_revision(),
            before,
            "{point:?}: live snapshot unchanged"
        );
        assert!(node.gate.admission_enabled());
        assert!(node
            .coord
            .store()
            .read(db::unresolved_intent)
            .expect("intent")
            .is_none());
        let r = node
            .coord
            .store()
            .read(|c| db::get_revision(c, &rev))
            .expect("rev");
        assert_ne!(r.state, "committed");
    }
}

#[test]
fn tc_c02_crash_cuts_reconcile_exact_committed_revision() {
    for point in [
        FailPoint::AfterCommit,
        FailPoint::Publish,
        FailPoint::AfterPublish,
        FailPoint::AppliedTx,
    ] {
        let (_d, path) = tmpdb();
        let faults = Arc::new(Faults::default());
        let node = boot(&path, faults.clone());
        let profile = initial(&node);
        let (job, rev) = stage_change(&node, &profile.id, "proxy", "key-000000000003");
        // A newer draft after the commit must not be selected by recovery.
        faults.arm(point, FailAction::Crash);
        assert_eq!(
            node.coord.run_job(&job),
            Err(CoordinatorError::Crashed),
            "{point:?}"
        );
        drop(node);
        let restarted = boot(&path, Arc::new(NoFailPoints));
        assert!(
            !restarted.gate.admission_enabled(),
            "admission closed before recovery"
        );
        match restarted.coord.recover().expect("recover") {
            RecoveryOutcome::Reconciled { revision_id, .. } => {
                assert_eq!(revision_id, rev, "{point:?}")
            }
            other => panic!("{point:?}: expected reconcile, got {other:?}"),
        }
        assert_eq!(
            restarted.gate.current_revision().as_deref(),
            Some(rev.as_str())
        );
        assert!(restarted.gate.admission_enabled());
        let j = restarted
            .coord
            .store()
            .read(|c| db::get_job(c, &job))
            .expect("job");
        assert_eq!(
            (j.status.as_str(), j.commit_state.as_str()),
            ("succeeded", "applied"),
            "{point:?}"
        );
    }
}

#[test]
fn tc_c02_crash_before_commit_restores_previous_revision() {
    for point in [FailPoint::Prepare, FailPoint::CommitTx] {
        let (_d, path) = tmpdb();
        let faults = Arc::new(Faults::default());
        let node = boot(&path, faults.clone());
        let profile = initial(&node);
        let old = node.gate.current_revision();
        let (job, _rev) = stage_change(&node, &profile.id, "proxy", "key-000000000004");
        faults.arm(point, FailAction::Crash);
        assert_eq!(node.coord.run_job(&job), Err(CoordinatorError::Crashed));
        drop(node);
        let restarted = boot(&path, Arc::new(NoFailPoints));
        assert!(matches!(
            restarted.coord.recover().expect("recover"),
            RecoveryOutcome::Restored { .. }
        ));
        assert_eq!(restarted.gate.current_revision(), old);
        let j = restarted
            .coord
            .store()
            .read(|c| db::get_job(c, &job))
            .expect("job");
        assert_eq!(
            (j.status.as_str(), j.safe_error_code.as_deref()),
            ("failed", Some("interrupted"))
        );
    }
}

#[test]
fn tc_c02_publication_failure_reconciles_and_blocks_new_activation() {
    let (_d, path) = tmpdb();
    let faults = Arc::new(Faults::default());
    let node = boot(&path, faults.clone());
    let profile = initial(&node);
    let (job, rev) = stage_change(&node, &profile.id, "proxy", "key-000000000005");
    faults.arm(FailPoint::Publish, FailAction::Fail);
    let done = node.coord.run_job(&job).expect("run");
    assert_eq!(
        (done.status.as_str(), done.commit_state.as_str()),
        ("reconciling", "committed")
    );
    assert!(!node.gate.admission_enabled(), "new admission held");
    // Unresolved commit blocks normal activation.
    let p = node
        .coord
        .store()
        .read(|c| db::get_profile(c, &profile.id))
        .expect("p");
    let p = node
        .coord
        .patch_profile(None, &profile.id, &p.etag(), Some("renamed"), None)
        .expect("patch");
    let report = node
        .coord
        .validate(None, &profile.id, &p.etag(), &p.desired_revision_id)
        .expect("v");
    let res = node.coord.submit_activation(
        &ActivateRequest {
            actor_id: None,
            profile_id: profile.id.clone(),
            if_match: p.etag(),
            idempotency_key: "key-000000000006".into(),
            target_revision_id: report.target_revision_id,
            config_digest: report.config_digest,
            validation_id: report.validation_id,
        },
        "/x",
    );
    assert!(matches!(res, Err(CoordinatorError::Conflict(_))));
    let op = done.operation_id.expect("op");
    assert!(matches!(
        node.coord.reconcile("wrong-op"),
        Err(CoordinatorError::Conflict(_))
    ));
    assert!(matches!(
        node.coord.reconcile(&op).expect("reconcile"),
        RecoveryOutcome::Reconciled { .. }
    ));
    assert_eq!(node.gate.current_revision().as_deref(), Some(rev.as_str()));
    assert!(node.gate.admission_enabled());
}

#[test]
fn tc_c02_applied_record_failure_holds_admission_until_agreement() {
    let (_d, path) = tmpdb();
    let faults = Arc::new(Faults::default());
    let node = boot(&path, faults.clone());
    let profile = initial(&node);
    let (job, rev) = stage_change(&node, &profile.id, "proxy", "key-000000000007");
    faults.arm(FailPoint::AppliedTx, FailAction::Fail);
    let done = node.coord.run_job(&job).expect("run");
    assert_eq!(done.status, "reconciling");
    assert_eq!(
        node.gate.current_revision().as_deref(),
        Some(rev.as_str()),
        "new snapshot stays live"
    );
    assert!(!node.gate.admission_enabled());
    let h = node.coord.health();
    assert_ne!(
        h.applied_revision_id.as_deref(),
        Some(rev.as_str()),
        "UI sees durable vs runtime disagreement"
    );
    assert_eq!(h.runtime_revision_id.as_deref(), Some(rev.as_str()));
    node.coord
        .reconcile(&done.operation_id.expect("op"))
        .expect("reconcile");
    assert!(node.gate.admission_enabled());
    assert_eq!(
        node.coord.health().applied_revision_id.as_deref(),
        Some(rev.as_str())
    );
}

#[test]
fn tc_c05_supersede_checks_expectations_and_links_chain() {
    let (_d, path) = tmpdb();
    let faults = Arc::new(Faults::default());
    let node = boot(&path, faults.clone());
    let profile = initial(&node);
    let original = node.gate.current_revision().expect("rev");
    let original_digest = node
        .coord
        .store()
        .read(|c| db::get_revision(c, &original))
        .expect("r")
        .digest;
    let (job, _rev) = stage_change(&node, &profile.id, "proxy", "key-000000000008");
    faults.arm(FailPoint::Publish, FailAction::Fail);
    let pending = node
        .coord
        .run_job(&job)
        .expect("run")
        .operation_id
        .expect("op");
    let epoch = node.coord.store().read(db::get_epoch).expect("epoch");
    let mut req = SupersedeRequest {
        actor_id: Some("local-owner".into()),
        pending_operation_id: pending.clone(),
        expected_runtime_revision_id: Some(original.clone()),
        expected_security_epoch: epoch + 1, // stale
        recovery_revision_id: original.clone(),
        recovery_config_digest: original_digest,
        reason: "operator rollback".into(),
    };
    assert!(matches!(
        node.coord.supersede(&req),
        Err(CoordinatorError::Conflict(_))
    ));
    assert!(
        node.coord
            .store()
            .read(db::unresolved_intent)
            .expect("i")
            .is_some(),
        "stale supersede changes nothing"
    );
    req.expected_security_epoch = epoch;
    let new_job = node.coord.supersede(&req).expect("supersede");
    assert_eq!(new_job.status, "succeeded");
    assert!(node.gate.admission_enabled());
    let old = node
        .coord
        .store()
        .read(|c| db::get_intent(c, &pending))
        .expect("old");
    assert_eq!(old.commit_state, "superseded");
    assert_eq!(old.superseded_by, new_job.operation_id);
    let old_job = node
        .coord
        .store()
        .read(|c| db::get_job(c, &job))
        .expect("old job");
    assert_eq!(old_job.status, "superseded");
}

#[test]
fn tc_a03_validation_binding_and_idempotency() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    let p = node
        .coord
        .store()
        .read(|c| db::get_profile(c, &profile.id))
        .expect("p");
    let p = node
        .coord
        .patch_profile(
            None,
            &profile.id,
            &p.etag(),
            None,
            Some(&json!({"routing": {"default_action": "proxy"}})),
        )
        .expect("patch");
    let report = node
        .coord
        .validate(None, &profile.id, &p.etag(), &p.desired_revision_id)
        .expect("v");
    // Edit after validation: the old ETag/report no longer authorize.
    let p2 = node
        .coord
        .patch_profile(None, &profile.id, &p.etag(), Some("edited"), None)
        .expect("patch2");
    let req = ActivateRequest {
        actor_id: Some("owner".into()),
        profile_id: profile.id.clone(),
        if_match: p.etag(),
        idempotency_key: "key-000000000009".into(),
        target_revision_id: report.target_revision_id.clone(),
        config_digest: report.config_digest.clone(),
        validation_id: report.validation_id.clone(),
    };
    assert_eq!(
        node.coord.submit_activation(&req, "/a"),
        Err(CoordinatorError::PreconditionFailed)
    );
    let req2 = ActivateRequest {
        if_match: p2.etag(),
        ..req.clone()
    };
    assert!(matches!(
        node.coord.submit_activation(&req2, "/a"),
        Err(CoordinatorError::Conflict(_))
    ));
    // Fresh validation, then idempotent retries.
    let report = node
        .coord
        .validate(None, &profile.id, &p2.etag(), &p2.desired_revision_id)
        .expect("v2");
    let ok = ActivateRequest {
        if_match: p2.etag(),
        target_revision_id: report.target_revision_id.clone(),
        config_digest: report.config_digest.clone(),
        validation_id: report.validation_id.clone(),
        idempotency_key: "key-00000000000a".into(),
        ..req
    };
    let j1 = node.coord.submit_activation(&ok, "/a").expect("j1");
    let j2 = node.coord.submit_activation(&ok, "/a").expect("j2");
    assert_eq!(j1.id, j2.id, "lost response recovered by the same key");
    let different = ActivateRequest {
        config_digest: "0".repeat(64),
        ..ok.clone()
    };
    assert!(matches!(
        node.coord.submit_activation(&different, "/a"),
        Err(CoordinatorError::Conflict(_))
    ));
    assert_eq!(node.coord.run_job(&j1.id).expect("run").status, "succeeded");
    // Re-running the job has no second effect.
    assert_eq!(
        node.coord.run_job(&j1.id).expect("rerun").status,
        "succeeded"
    );
}

#[test]
fn tc_a04_stale_restore_rejected() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    let first = node.gate.current_revision().expect("first");
    let p_before = node
        .coord
        .store()
        .read(|c| db::get_profile(c, &profile.id))
        .expect("p");
    let (job, _) = stage_change(&node, &profile.id, "proxy", "key-00000000000b");
    node.coord.run_job(&job).expect("run");
    // Restore with the pre-change profile ETag must fail.
    assert_eq!(
        node.coord
            .submit_restore(None, &first, &p_before.etag(), "key-00000000000c", "/r"),
        Err(CoordinatorError::PreconditionFailed)
    );
    let p_now = node
        .coord
        .store()
        .read(|c| db::get_profile(c, &profile.id))
        .expect("p");
    let r = node
        .coord
        .submit_restore(None, &first, &p_now.etag(), "key-00000000000d", "/r")
        .expect("restore");
    let done = node.coord.run_job(&r.id).expect("run");
    assert_eq!(done.status, "succeeded");
    let new_rev = node.gate.current_revision().expect("rev");
    assert_ne!(new_rev, first, "restore creates a new revision");
    let digest = |id: &str| {
        node.coord
            .store()
            .read(|c| db::get_revision(c, id))
            .expect("r")
            .digest
    };
    assert_eq!(digest(&new_rev), digest(&first));
}

fn peer(fp: u8) -> PeerIdentity {
    PeerIdentity {
        san_identity: true,
        node_id: "client-1".into(),
        role: Some(Role::Client),
        fingerprint: [fp; 32],
        serial_hex: "01".into(),
        not_before: 0,
        not_after: i64::MAX,
    }
}

#[test]
fn tc_p18_tightened_policy_and_revocation_apply_to_next_open() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    let dest = Destination::parse_authority("93.184.216.34:443").expect("dest");
    let input = DecisionInput {
        destination: &dest,
        inbound: "ws",
        node_id: Some("client-1"),
    };
    let p = peer(7);
    let admitted = node
        .gate
        .admit(Some(&p), &input, 1)
        .expect("admitted under rev1");
    let rev1 = admitted.bundle.revision_id.clone();
    // Tighten: remove the allow rule (default deny remains).
    let prof = node
        .coord
        .store()
        .read(|c| db::get_profile(c, &profile.id))
        .expect("p");
    let prof = node
        .coord
        .patch_profile(
            None,
            &profile.id,
            &prof.etag(),
            None,
            Some(&json!({"routing": {"rules": []}})),
        )
        .expect("patch");
    let report = node
        .coord
        .validate(None, &profile.id, &prof.etag(), &prof.desired_revision_id)
        .expect("v");
    assert!(report
        .security_diff
        .iter()
        .any(|l| l.contains("rule removed")));
    let job = node
        .coord
        .submit_activation(
            &ActivateRequest {
                actor_id: None,
                profile_id: profile.id.clone(),
                if_match: prof.etag(),
                idempotency_key: "key-00000000000e".into(),
                target_revision_id: report.target_revision_id,
                config_digest: report.config_digest,
                validation_id: report.validation_id,
            },
            "/a",
        )
        .expect("submit");
    node.coord.run_job(&job.id).expect("run");
    // Next OPEN on the same (logical) session uses the new policy...
    assert!(matches!(
        node.gate.admit(Some(&p), &input, 1),
        Err(AdmitError::Denied(_))
    ));
    // ...while the already-admitted stream keeps its revision.
    assert_eq!(admitted.bundle.revision_id, rev1);
    // Revocation rejects new admissions regardless of policy.
    let snap = node
        .gate
        .identity_store()
        .current()
        .with_revoked([[7u8; 32]]);
    node.gate.publish_identity(snap);
    assert_eq!(
        node.gate.admit(Some(&p), &input, 1).map(|_| ()),
        Err(AdmitError::Revoked)
    );
    // Expired credentials are rejected even without revocation.
    let mut expired = peer(8);
    expired.not_after = 10;
    assert_eq!(
        node.gate.admit(Some(&expired), &input, 11).map(|_| ()),
        Err(AdmitError::Expired)
    );
}

#[test]
fn tc_c03_readers_see_complete_revisions_during_activations() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let profile = initial(&node);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut readers = Vec::new();
    for _ in 0..100 {
        let gate = Arc::clone(&node.gate);
        let stop = Arc::clone(&stop);
        readers.push(std::thread::spawn(move || {
            let dest = Destination::parse_authority("93.184.216.34:443").expect("dest");
            let mut seen = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let input = DecisionInput {
                    destination: &dest,
                    inbound: "ws",
                    node_id: Some("c"),
                };
                match gate.admit(None, &input, 1) {
                    Ok(a) => {
                        // Bundle is internally consistent: digest matches its config.
                        assert_eq!(a.bundle.digest, a.bundle.compiled.digest);
                        seen += 1;
                    }
                    Err(AdmitError::Closed | AdmitError::Denied(_)) => {}
                    Err(e) => panic!("unexpected {e:?}"),
                }
            }
            seen
        }));
    }
    for i in 0..6 {
        let action = if i % 2 == 0 { "proxy" } else { "deny" };
        let (job, rev) = stage_change(&node, &profile.id, action, &format!("key-race-{i:010}"));
        assert_eq!(node.coord.run_job(&job).expect("run").status, "succeeded");
        assert_eq!(node.gate.current_revision().as_deref(), Some(rev.as_str()));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let total: u32 = readers.into_iter().map(|h| h.join().expect("reader")).sum();
    assert!(total > 0);
}

#[test]
fn tc_c04_restart_restores_revocations_and_last_applied() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let _profile = initial(&node);
    let rev = node.gate.current_revision();
    // Enroll + revoke a node directly in the store, then publish via job.
    let node_id = db::new_id();
    node.coord
        .store()
        .tx(|c| {
            db::insert_node(
                c,
                &db::NodeRow {
                    id: node_id.clone(),
                    name: "client-1".into(),
                    role: "client".into(),
                    cert_fingerprint: Some(hex::encode([9u8; 32])),
                    cert_serial: Some("01".into()),
                    status: "active".into(),
                    generation: 1,
                    not_after: Some(i64::MAX),
                    created_at: db::now_unix(),
                },
            )?;
            db::insert_identity(c, &hex::encode([9u8; 32]), &node_id, "01", 0, i64::MAX)
        })
        .expect("enroll");
    let n = node
        .coord
        .store()
        .read(|c| db::get_node(c, &node_id))
        .expect("node");
    let job = node
        .coord
        .submit_revoke(Some("owner"), &node_id, &n.etag(), "key-00000000000f", "/n")
        .expect("revoke");
    assert_eq!(
        node.coord.run_revoke(&job.id).expect("run").status,
        "succeeded"
    );
    assert!(node.gate.identity_store().current().is_revoked(&[9u8; 32]));
    let epoch = node.gate.security_epoch();
    drop(node);
    let restarted = boot(&path, Arc::new(NoFailPoints));
    assert!(matches!(
        restarted.coord.recover().expect("recover"),
        RecoveryOutcome::Restored { .. }
    ));
    assert_eq!(restarted.gate.current_revision(), rev);
    assert!(
        restarted
            .gate
            .identity_store()
            .current()
            .is_revoked(&[9u8; 32]),
        "restart cannot resurrect revoked identities"
    );
    assert_eq!(restarted.gate.security_epoch(), epoch);
}

#[test]
fn profiles_for_other_nodes_rejected() {
    let (_d, path) = tmpdb();
    let node = boot(&path, Arc::new(NoFailPoints));
    let mut spec = to_json(&parse_toml(GATEWAY).expect("cfg"));
    spec["node_id"] = json!("someone-else");
    assert!(matches!(
        node.coord.create_profile(None, "x", &spec),
        Err(CoordinatorError::Invalid(_))
    ));
}
