//! Lifecycle core: the admission gate, the single-writer activation
//! coordinator and supervision helpers.
//!
//! This crate is transport-agnostic (A-002): it knows compiled policy,
//! identities and the management store, never WebSocket/SOCKS/TLS code.
#![forbid(unsafe_code)]

pub mod agent;
pub mod coordinator;
pub mod gate;
pub mod supervisor;

pub use agent::AgentCell;
pub use coordinator::{
    ActivateRequest, CapabilityEnv, Coordinator, CoordinatorError, FailAction, FailPoint,
    FailPoints, Health, NoFailPoints, RecoveryOutcome, SupersedeRequest, ValidationReport,
};
pub use gate::{AdmissionGate, AdmitError, Admitted, RuntimeBundle};
pub use supervisor::{Backoff, CircuitBreaker};

/// RFC 3339 UTC timestamp for API output.
pub fn rfc3339(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".into())
}
