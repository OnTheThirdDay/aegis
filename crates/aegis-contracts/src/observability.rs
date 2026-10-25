//! The data plane's only observability dependency (05 §1).
//!
//! Events are typed, finite and carry no destinations, identities or free-form
//! strings. Implementations MUST NOT block or perform I/O on the caller's
//! thread; the default is a no-op.

use crate::reason::ReasonGroup;
use crate::route::{RouteAction, RuleClass};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolClass {
    Receive,
    Transmit,
    Control,
    Handshake,
    Telemetry,
}

impl PoolClass {
    pub const ALL: [PoolClass; 5] = [
        PoolClass::Receive,
        PoolClass::Transmit,
        PoolClass::Control,
        PoolClass::Handshake,
        PoolClass::Telemetry,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            PoolClass::Receive => "receive",
            PoolClass::Transmit => "transmit",
            PoolClass::Control => "control",
            PoolClass::Handshake => "handshake",
            PoolClass::Telemetry => "telemetry",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Up,
    Down,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationResult {
    Ok,
    Error,
    Cancelled,
    Denied,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Event {
    SessionOpened,
    SessionClosed,
    StreamOpened,
    StreamClosed {
        result: OperationResult,
        reason: ReasonGroup,
    },
    StreamOpenDuration {
        seconds: f64,
        result: OperationResult,
    },
    TransportBytes {
        direction: Direction,
        bytes: u64,
    },
    TransportReconnect {
        reason: ReasonGroup,
    },
    HandshakeDuration {
        seconds: f64,
        result: OperationResult,
    },
    RouteDecision {
        action: RouteAction,
        class: RuleClass,
    },
    ResourceThrottle {
        reason: ReasonGroup,
    },
    ConfigActivation {
        result: OperationResult,
    },
    AuthFailure {
        reason: ReasonGroup,
    },
}

pub trait Observability: Send + Sync {
    fn record(&self, event: Event);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopObservability;

impl Observability for NoopObservability {
    #[inline]
    fn record(&self, _event: Event) {}
}
