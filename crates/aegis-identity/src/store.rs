//! Published identity/revocation snapshot.
//!
//! Revocations are enforced locally from this in-memory snapshot: no data
//! path database query, and loss of the controller cannot invent new
//! revocation information. Publication bumps the security epoch; rollback of
//! routing configuration can never roll it back.

use crate::tls::PeerIdentity;
use aegis_contracts::Role;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentitySnapshot {
    /// Monotonic security epoch.
    pub epoch: u64,
    revoked: HashSet<[u8; 32]>,
    enrolled: Option<HashMap<[u8; 32], (String, Role)>>,
    legacy_until: Option<i64>,
}

impl IdentitySnapshot {
    pub fn new(epoch: u64, revoked: impl IntoIterator<Item = [u8; 32]>) -> Self {
        IdentitySnapshot {
            epoch,
            revoked: revoked.into_iter().collect(),
            enrolled: None,
            legacy_until: None,
        }
    }

    pub fn is_revoked(&self, fingerprint: &[u8; 32]) -> bool {
        self.revoked.contains(fingerprint)
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    pub fn with_registry(
        mut self,
        entries: impl IntoIterator<Item = ([u8; 32], String, Role)>,
        legacy_until: i64,
    ) -> Self {
        self.enrolled = Some(
            entries
                .into_iter()
                .map(|(fp, name, role)| (fp, (name, role)))
                .collect(),
        );
        self.legacy_until = Some(legacy_until);
        self
    }

    pub fn with_legacy_deadline(mut self, until: i64) -> Self {
        self.legacy_until = Some(until);
        self
    }

    pub fn authorizes(&self, peer: &PeerIdentity, now: i64) -> bool {
        !self.is_revoked(&peer.fingerprint)
            && !peer.is_expired_at(now)
            && (self.enrolled.is_some() || self.legacy_until.is_none_or(|until| now < until))
            && (peer.san_identity || self.legacy_until.is_none_or(|until| now < until))
            && self.enrolled.as_ref().is_none_or(|registry| {
                registry
                    .get(&peer.fingerprint)
                    .is_some_and(|(name, role)| name == &peer.node_id && Some(*role) == peer.role)
            })
    }

    /// A new snapshot with additional revocations at a durably assigned
    /// epoch (never lower than the current one).
    pub fn with_revoked_at(
        &self,
        epoch: u64,
        fingerprints: impl IntoIterator<Item = [u8; 32]>,
    ) -> Self {
        let mut revoked = self.revoked.clone();
        revoked.extend(fingerprints);
        let mut next = self.clone();
        next.epoch = epoch.max(self.epoch);
        next.revoked = revoked;
        next
    }

    /// A new snapshot with additional revocations and the next epoch.
    pub fn with_revoked(&self, fingerprints: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut revoked = self.revoked.clone();
        revoked.extend(fingerprints);
        let mut next = self.clone();
        next.epoch += 1;
        next.revoked = revoked;
        next
    }
}

/// Shared holder read by the TLS verifier at handshake time and by the
/// admission gate on every OPEN.
#[derive(Debug, Default)]
pub struct IdentityStore {
    current: RwLock<Arc<IdentitySnapshot>>,
}

impl IdentityStore {
    pub fn new(snapshot: IdentitySnapshot) -> Arc<Self> {
        Arc::new(IdentityStore {
            current: RwLock::new(Arc::new(snapshot)),
        })
    }

    pub fn current(&self) -> Arc<IdentitySnapshot> {
        Arc::clone(&self.current.read().unwrap_or_else(|e| e.into_inner()))
    }

    /// Replace the snapshot. Epochs never move backwards.
    pub fn publish(&self, snapshot: IdentitySnapshot) -> bool {
        let mut cur = self.current.write().unwrap_or_else(|e| e.into_inner());
        if snapshot.epoch < cur.epoch {
            return false;
        }
        *cur = Arc::new(snapshot);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epochs_are_monotonic() {
        let store = IdentityStore::new(IdentitySnapshot::new(3, []));
        let next = store.current().with_revoked([[1u8; 32]]);
        assert_eq!(next.epoch, 4);
        assert!(store.publish(next));
        assert!(store.current().is_revoked(&[1u8; 32]));
        assert!(
            !store.publish(IdentitySnapshot::new(2, [])),
            "rollback refused"
        );
        assert!(store.current().is_revoked(&[1u8; 32]));
    }
}
