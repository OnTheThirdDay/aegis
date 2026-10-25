//! `local_diagnostic` (11 §2): an explicitly authorized, expiring, in-memory
//! ring of coded events. Never persisted (a restart or crash leaves it
//! disabled), never exported, and records no destinations, identities,
//! stream IDs or payload.

use aegis_contracts::observability::{Event, OperationResult};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_DURATION: Duration = Duration::from_secs(15 * 60);
pub const MAX_EVENTS: usize = 2048;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiagnosticEvent {
    /// Seconds since the session started.
    pub t: u64,
    pub code: &'static str,
}

#[derive(Debug)]
struct Active {
    started: Instant,
    expires: Instant,
    started_unix: u64,
    events: VecDeque<DiagnosticEvent>,
}

#[derive(Debug, Default)]
pub struct DiagnosticSink {
    state: Mutex<Option<Active>>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DiagnosticStatus {
    pub active: bool,
    pub started_unix: Option<u64>,
    pub remaining_seconds: Option<u64>,
    pub events: Vec<DiagnosticEvent>,
}

fn code(event: &Event) -> &'static str {
    match event {
        Event::SessionOpened => "session.opened",
        Event::SessionClosed => "session.closed",
        Event::StreamOpened => "stream.opened",
        Event::StreamClosed { result, .. } => match result {
            OperationResult::Ok => "stream.closed.ok",
            OperationResult::Cancelled => "stream.closed.cancelled",
            OperationResult::Denied => "flow.rejected",
            OperationResult::Timeout => "stream.closed.timeout",
            OperationResult::Error => "stream.closed.error",
        },
        Event::StreamOpenDuration { .. } => "stream.open.measured",
        Event::TransportBytes { .. } => "transport.io",
        Event::TransportReconnect { .. } => "transport.reconnect",
        Event::HandshakeDuration { .. } => "handshake.measured",
        Event::RouteDecision { .. } => "policy.decision",
        Event::ResourceThrottle { .. } => "resource.throttle",
        Event::ConfigActivation { .. } => "config.activation",
        Event::AuthFailure { .. } => "auth.failure",
    }
}

impl DiagnosticSink {
    pub fn new() -> Self {
        DiagnosticSink::default()
    }

    /// Start (or restart) a session. Callers must have verified local
    /// privileged authorization; durations above 15 minutes are refused.
    pub fn start(&self, duration: Duration) -> Result<(), &'static str> {
        if duration.is_zero() || duration > MAX_DURATION {
            return Err("diagnostic duration must be 1s..=15min");
        }
        let now = Instant::now();
        let unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(Active {
            started: now,
            expires: now + duration,
            started_unix: unix,
            events: VecDeque::new(),
        });
        Ok(())
    }

    /// Stop and securely discard collected events.
    pub fn stop(&self) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn expire(slot: &mut Option<Active>) {
        if slot.as_ref().is_some_and(|a| Instant::now() >= a.expires) {
            *slot = None;
        }
    }

    pub fn record(&self, event: Event) {
        // Skip high-volume byte accounting entirely.
        if matches!(event, Event::TransportBytes { .. }) {
            return;
        }
        let Ok(mut slot) = self.state.try_lock() else {
            return; // never block the data path
        };
        Self::expire(&mut slot);
        if let Some(a) = slot.as_mut() {
            if a.events.len() >= MAX_EVENTS {
                a.events.pop_front();
            }
            a.events.push_back(DiagnosticEvent {
                t: a.started.elapsed().as_secs(),
                code: code(&event),
            });
        }
    }

    pub fn status(&self) -> DiagnosticStatus {
        let mut slot = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::expire(&mut slot);
        match slot.as_ref() {
            Some(a) => DiagnosticStatus {
                active: true,
                started_unix: Some(a.started_unix),
                remaining_seconds: Some(
                    a.expires
                        .saturating_duration_since(Instant::now())
                        .as_secs(),
                ),
                events: a.events.iter().cloned().collect(),
            },
            None => DiagnosticStatus {
                active: false,
                started_unix: None,
                remaining_seconds: None,
                events: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_priv05_duration_bounds_and_expiry() {
        let d = DiagnosticSink::new();
        assert!(d.start(Duration::from_secs(16 * 60)).is_err());
        assert!(d.start(Duration::ZERO).is_err());
        d.record(Event::SessionOpened);
        assert!(!d.status().active, "nothing recorded while inactive");
        d.start(Duration::from_millis(50)).expect("start");
        d.record(Event::SessionOpened);
        assert_eq!(d.status().events.len(), 1);
        std::thread::sleep(Duration::from_millis(80));
        assert!(!d.status().active, "expires automatically");
        // A fresh sink (process restart) is always inactive.
        assert!(!DiagnosticSink::new().status().active);
    }
}
