//! Registry of live gateway sessions, keyed for revocation enforcement.

use aegis_contracts::reason::ResetReason;
use aegis_session::Session;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

type Entry = ([u8; 32], Arc<Session>);

#[derive(Default)]
pub struct SessionRegistry {
    inner: Mutex<HashMap<u64, Entry>>,
    next: AtomicU64,
}

impl SessionRegistry {
    pub fn insert(&self, fingerprint: [u8; 32], s: Arc<Session>) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, (fingerprint, s));
        id
    }

    pub fn remove(&self, id: u64) {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
    }

    pub fn count(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// High-risk revocation default: close every session of the identity,
    /// resetting its admitted streams.
    pub fn close_fingerprints(&self, fps: &[[u8; 32]], reason: ResetReason) {
        let targets: Vec<Arc<Session>> = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|(fp, _)| fps.contains(fp))
            .map(|(_, s)| Arc::clone(s))
            .collect();
        for s in targets {
            s.close(reason);
        }
    }

    pub fn goaway_all(&self) {
        for (_, s) in self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
        {
            s.goaway();
        }
    }

    pub fn close_all(&self, reason: ResetReason) {
        let all: Vec<Arc<Session>> = self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|(_, s)| Arc::clone(s))
            .collect();
        for s in all {
            s.close(reason);
        }
    }
}
