//! Published identity/revocation snapshot.
//!
//! Revocations are enforced locally from this in-memory snapshot: no data
//! path database query, and loss of the controller cannot invent new
//! revocation information. Publication bumps the security epoch; rollback of
//! routing configuration can never roll it back.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentitySnapshot {
    /// Monotonic security epoch.
    pub epoch: u64,
    revoked: HashSet<[u8; 32]>,
}

impl IdentitySnapshot {
    pub fn new(epoch: u64, revoked: impl IntoIterator<Item = [u8; 32]>) -> Self {
        IdentitySnapshot {
            epoch,
            revoked: revoked.into_iter().collect(),
        }
    }

    pub fn is_revoked(&self, fingerprint: &[u8; 32]) -> bool {
        self.revoked.contains(fingerprint)
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
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
        IdentitySnapshot {
            epoch: epoch.max(self.epoch),
            revoked,
        }
    }

    /// A new snapshot with additional revocations and the next epoch.
    pub fn with_revoked(&self, fingerprints: impl IntoIterator<Item = [u8; 32]>) -> Self {
        let mut revoked = self.revoked.clone();
        revoked.extend(fingerprints);
        IdentitySnapshot {
            epoch: self.epoch + 1,
            revoked,
        }
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
