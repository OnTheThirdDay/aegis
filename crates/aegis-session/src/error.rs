use aegis_agp::ProtocolError;
use aegis_contracts::reason::{OpenFailure, ReasonGroup, ResetReason};
use std::fmt;

/// Why a session ended. Cloneable so every stream can observe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    Protocol(ProtocolError),
    Io(std::io::ErrorKind),
    HandshakeTimeout,
    KeepaliveTimeout,
    /// The transport could not write and flush a batch within the keepalive deadline.
    WriteTimeout,
    ResetDrainTimeout,
    /// Peer HELLO identity does not match the authenticated certificate.
    IdentityMismatch,
    /// Could not reserve receive capacity for a new session.
    Budget,
    /// Locally requested close.
    Closed(ResetReason),
    /// Peer closed the transport.
    PeerClosed,
    ControlOverload,
}

impl SessionError {
    pub fn reason_group(&self) -> ReasonGroup {
        match self {
            SessionError::Protocol(_) | SessionError::ControlOverload => ReasonGroup::Transport,
            SessionError::Io(_) | SessionError::PeerClosed => ReasonGroup::Transport,
            SessionError::HandshakeTimeout
            | SessionError::KeepaliveTimeout
            | SessionError::WriteTimeout
            | SessionError::ResetDrainTimeout => ReasonGroup::Timeout,
            SessionError::IdentityMismatch => ReasonGroup::Auth,
            SessionError::Budget => ReasonGroup::Quota,
            SessionError::Closed(r) => r.group(),
        }
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Protocol(e) => write!(f, "protocol error: {e}"),
            SessionError::Io(k) => write!(f, "transport I/O error: {k:?}"),
            SessionError::HandshakeTimeout => f.write_str("handshake timed out"),
            SessionError::KeepaliveTimeout => f.write_str("keepalive timed out"),
            SessionError::WriteTimeout => f.write_str("transport write timed out"),
            SessionError::ResetDrainTimeout => f.write_str("peer failed to acknowledge reset"),
            SessionError::IdentityMismatch => {
                f.write_str("HELLO node_id does not match peer certificate")
            }
            SessionError::Budget => f.write_str("insufficient buffer budget for session"),
            SessionError::Closed(r) => write!(f, "session closed locally ({r:?})"),
            SessionError::PeerClosed => f.write_str("peer closed the session"),
            SessionError::ControlOverload => f.write_str("control frame overload"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ProtocolError> for SessionError {
    fn from(e: ProtocolError) -> Self {
        SessionError::Protocol(e)
    }
}

/// Failure to open a logical stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Remote denied or failed the OPEN with a deterministic code.
    Rejected(OpenFailure),
    Timeout,
    /// Local stream/budget limit reached.
    Quota,
    /// Stream IDs exhausted; a new session is required.
    IdsExhausted,
    /// Peer sent GOAWAY; open a new session.
    GoingAway,
    Session(SessionError),
}

impl OpenError {
    pub fn as_open_failure(&self) -> OpenFailure {
        match self {
            OpenError::Rejected(f) => *f,
            OpenError::Timeout => OpenFailure::Timeout,
            OpenError::Quota => OpenFailure::Quota,
            OpenError::IdsExhausted | OpenError::GoingAway => OpenFailure::Unavailable,
            OpenError::Session(_) => OpenFailure::Unavailable,
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::Rejected(r) => write!(f, "open rejected: {}", r.as_str()),
            OpenError::Timeout => f.write_str("open timed out"),
            OpenError::Quota => f.write_str("stream quota exceeded"),
            OpenError::IdsExhausted => f.write_str("stream ids exhausted"),
            OpenError::GoingAway => f.write_str("session is going away"),
            OpenError::Session(e) => write!(f, "session failed: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}
