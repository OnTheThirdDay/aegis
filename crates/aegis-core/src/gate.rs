//! The new-stream admission gate (02 §5 step 10).
//!
//! Every new logical stream — including an OPEN on a long-lived AGP
//! session — is admitted here against the *current* published policy bundle
//! and identity/revocation snapshot. Publication swaps the bundle under the
//! write lock with a compare-and-swap on the expected revision; that swap is
//! the runtime linearization point. Nothing in either critical section
//! performs I/O, awaits, or calls module code.

use aegis_config::CompiledConfig;
use aegis_contracts::route::{RouteAction, RouteDecision};
use aegis_identity::{IdentitySnapshot, IdentityStore, PeerIdentity};
use aegis_policy::DecisionInput;
use std::sync::{Arc, RwLock};

/// An immutable published policy bundle.
#[derive(Debug)]
pub struct RuntimeBundle {
    pub revision_id: String,
    pub profile_id: String,
    pub operation_id: String,
    pub digest: String,
    pub compiled: Arc<CompiledConfig>,
}

#[derive(Debug)]
struct GateState {
    bundle: Option<Arc<RuntimeBundle>>,
    admission_enabled: bool,
}

#[derive(Debug)]
pub struct AdmissionGate {
    state: RwLock<GateState>,
    identity: Arc<IdentityStore>,
}

/// A successful admission. The stream keeps this bundle (its admitted
/// revision) until it closes.
#[derive(Clone, Debug)]
pub struct Admitted {
    pub bundle: Arc<RuntimeBundle>,
    pub security_epoch: u64,
    pub decision: RouteDecision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// Admission closed (starting, reconciling, degraded or draining).
    Closed,
    /// No policy has been published yet.
    NoPolicy,
    Revoked,
    Expired,
    Unauthorized,
    Denied(RouteDecision),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasMismatch {
    pub expected: Option<String>,
    pub actual: Option<String>,
}

impl AdmissionGate {
    pub fn new(identity: Arc<IdentityStore>) -> Arc<Self> {
        Arc::new(AdmissionGate {
            state: RwLock::new(GateState {
                bundle: None,
                admission_enabled: false,
            }),
            identity,
        })
    }

    pub fn identity_store(&self) -> &Arc<IdentityStore> {
        &self.identity
    }

    /// Admit one new logical stream.
    pub fn admit(
        &self,
        peer: Option<&PeerIdentity>,
        input: &DecisionInput<'_>,
        now_unix: i64,
    ) -> Result<Admitted, AdmitError> {
        let st = self.state.read().unwrap_or_else(|e| e.into_inner());
        if !st.admission_enabled {
            return Err(AdmitError::Closed);
        }
        let bundle = st.bundle.clone().ok_or(AdmitError::NoPolicy)?;
        // Read under the gate lock: identity publication also takes the
        // write lock, so admission and revocation are totally ordered.
        let ident = self.identity.current();
        if let Some(p) = peer {
            if ident.is_revoked(&p.fingerprint) {
                return Err(AdmitError::Revoked);
            }
            if p.is_expired_at(now_unix) {
                return Err(AdmitError::Expired);
            }
            if !ident.authorizes(p, now_unix) {
                return Err(AdmitError::Unauthorized);
            }
        }
        let decision = bundle.compiled.router.decide(input);
        if decision.action == RouteAction::Deny {
            return Err(AdmitError::Denied(decision));
        }
        Ok(Admitted {
            bundle,
            security_epoch: ident.epoch,
            decision,
        })
    }

    /// CAS-publish a prepared bundle. Fails without effect if the current
    /// revision is not `expected`.
    pub fn publish(
        &self,
        expected: Option<&str>,
        bundle: Arc<RuntimeBundle>,
    ) -> Result<(), CasMismatch> {
        let mut st = self.state.write().unwrap_or_else(|e| e.into_inner());
        let actual = st.bundle.as_ref().map(|b| b.revision_id.as_str());
        if actual != expected {
            return Err(CasMismatch {
                expected: expected.map(str::to_owned),
                actual: actual.map(str::to_owned),
            });
        }
        st.bundle = Some(bundle);
        Ok(())
    }

    /// Publish a new identity/revocation snapshot (epochs never regress).
    pub fn publish_identity(&self, snapshot: IdentitySnapshot) -> bool {
        let _st = self.state.write().unwrap_or_else(|e| e.into_inner());
        self.identity.publish(snapshot)
    }

    pub fn set_admission(&self, enabled: bool) {
        self.state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .admission_enabled = enabled;
    }

    pub fn admission_enabled(&self) -> bool {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .admission_enabled
    }

    pub fn current(&self) -> Option<Arc<RuntimeBundle>> {
        self.state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .bundle
            .clone()
    }

    pub fn current_revision(&self) -> Option<String> {
        self.current().map(|b| b.revision_id.clone())
    }

    pub fn security_epoch(&self) -> u64 {
        self.identity.current().epoch
    }
}
