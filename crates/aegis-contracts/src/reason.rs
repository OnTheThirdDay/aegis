//! Deterministic low-cardinality failure codes (03 §3: "deterministic,
//! low-cardinality error; no raw DNS error or hostnames").

use serde::{Deserialize, Serialize};

/// Finite reason groups, matching `aegis.reason.group` in the telemetry catalog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonGroup {
    Auth,
    Policy,
    Dns,
    Tls,
    Timeout,
    Transport,
    Quota,
    Platform,
    Internal,
    Cancelled,
    Shutdown,
    Other,
}

impl ReasonGroup {
    pub const ALL: [ReasonGroup; 12] = [
        ReasonGroup::Auth,
        ReasonGroup::Policy,
        ReasonGroup::Dns,
        ReasonGroup::Tls,
        ReasonGroup::Timeout,
        ReasonGroup::Transport,
        ReasonGroup::Quota,
        ReasonGroup::Platform,
        ReasonGroup::Internal,
        ReasonGroup::Cancelled,
        ReasonGroup::Shutdown,
        ReasonGroup::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReasonGroup::Auth => "auth",
            ReasonGroup::Policy => "policy",
            ReasonGroup::Dns => "dns",
            ReasonGroup::Tls => "tls",
            ReasonGroup::Timeout => "timeout",
            ReasonGroup::Transport => "transport",
            ReasonGroup::Quota => "quota",
            ReasonGroup::Platform => "platform",
            ReasonGroup::Internal => "internal",
            ReasonGroup::Cancelled => "cancelled",
            ReasonGroup::Shutdown => "shutdown",
            ReasonGroup::Other => "other",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// OPEN_ACK result code. 0 is success; everything else is a denial/failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenFailure {
    /// Policy/ACL denied the destination.
    Denied = 1,
    /// Identity revoked, expired or not authorized.
    Unauthorized = 2,
    /// DNS resolution failed (no detail is transmitted).
    DnsFailure = 3,
    /// Destination refused the TCP connection.
    Refused = 4,
    /// Destination unreachable / no route.
    Unreachable = 5,
    /// Dial timed out.
    Timeout = 6,
    /// Stream/session/resource quota exceeded.
    Quota = 7,
    /// Admission closed (degraded/reconciling or draining).
    Unavailable = 8,
    /// Unsupported network or malformed request.
    Unsupported = 9,
    Internal = 10,
}

impl OpenFailure {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => OpenFailure::Denied,
            2 => OpenFailure::Unauthorized,
            3 => OpenFailure::DnsFailure,
            4 => OpenFailure::Refused,
            5 => OpenFailure::Unreachable,
            6 => OpenFailure::Timeout,
            7 => OpenFailure::Quota,
            8 => OpenFailure::Unavailable,
            9 => OpenFailure::Unsupported,
            10 => OpenFailure::Internal,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn group(self) -> ReasonGroup {
        match self {
            OpenFailure::Denied => ReasonGroup::Policy,
            OpenFailure::Unauthorized => ReasonGroup::Auth,
            OpenFailure::DnsFailure => ReasonGroup::Dns,
            OpenFailure::Refused | OpenFailure::Unreachable => ReasonGroup::Transport,
            OpenFailure::Timeout => ReasonGroup::Timeout,
            OpenFailure::Quota => ReasonGroup::Quota,
            OpenFailure::Unavailable => ReasonGroup::Shutdown,
            OpenFailure::Unsupported => ReasonGroup::Policy,
            OpenFailure::Internal => ReasonGroup::Internal,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OpenFailure::Denied => "denied",
            OpenFailure::Unauthorized => "unauthorized",
            OpenFailure::DnsFailure => "dns_failure",
            OpenFailure::Refused => "refused",
            OpenFailure::Unreachable => "unreachable",
            OpenFailure::Timeout => "timeout",
            OpenFailure::Quota => "quota",
            OpenFailure::Unavailable => "unavailable",
            OpenFailure::Unsupported => "unsupported",
            OpenFailure::Internal => "internal",
        }
    }
}

/// Enumerated RESET reasons carried in the RESET payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetReason {
    Cancelled = 1,
    DestinationReset = 2,
    Timeout = 3,
    PolicyRevoked = 4,
    ResourceLimit = 5,
    ProtocolError = 6,
    Shutdown = 7,
    Internal = 8,
}

impl ResetReason {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => ResetReason::Cancelled,
            2 => ResetReason::DestinationReset,
            3 => ResetReason::Timeout,
            4 => ResetReason::PolicyRevoked,
            5 => ResetReason::ResourceLimit,
            6 => ResetReason::ProtocolError,
            7 => ResetReason::Shutdown,
            8 => ResetReason::Internal,
            _ => return None,
        })
    }

    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn group(self) -> ReasonGroup {
        match self {
            ResetReason::Cancelled => ReasonGroup::Cancelled,
            ResetReason::DestinationReset => ReasonGroup::Transport,
            ResetReason::Timeout => ReasonGroup::Timeout,
            ResetReason::PolicyRevoked => ReasonGroup::Auth,
            ResetReason::ResourceLimit => ReasonGroup::Quota,
            ResetReason::ProtocolError => ReasonGroup::Transport,
            ResetReason::Shutdown => ReasonGroup::Shutdown,
            ResetReason::Internal => ReasonGroup::Internal,
        }
    }
}
