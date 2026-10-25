//! Core state machines (02 §6). Every transition is checked; illegal
//! transitions return an error instead of panicking.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IllegalTransition {
    pub from: &'static str,
    pub to: &'static str,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal transition {} -> {}", self.from, self.to)
    }
}

impl std::error::Error for IllegalTransition {}

/// Agent lifecycle. `Degraded` records whether new admission is allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum AgentState {
    Starting,
    Ready,
    Degraded { admission_allowed: bool },
    Draining,
    Stopped,
}

impl AgentState {
    pub fn name(&self) -> &'static str {
        match self {
            AgentState::Starting => "starting",
            AgentState::Ready => "ready",
            AgentState::Degraded { .. } => "degraded",
            AgentState::Draining => "draining",
            AgentState::Stopped => "stopped",
        }
    }

    pub fn admission_allowed(&self) -> bool {
        match self {
            AgentState::Ready => true,
            AgentState::Degraded { admission_allowed } => *admission_allowed,
            _ => false,
        }
    }

    pub fn transition(self, to: AgentState) -> Result<AgentState, IllegalTransition> {
        use AgentState::*;
        let ok = matches!(
            (self, to),
            (Starting, Ready)
                | (Starting, Degraded { .. })
                | (Ready, Degraded { .. })
                | (Degraded { .. }, Ready)
                | (Degraded { .. }, Degraded { .. })
                | (Ready, Draining)
                | (Degraded { .. }, Draining)
                | (Starting, Draining)
                | (Draining, Stopped)
        );
        if ok {
            Ok(to)
        } else {
            Err(IllegalTransition {
                from: self.name(),
                to: to.name(),
            })
        }
    }
}

/// Logical stream lifecycle. A reset is terminal and never becomes success.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Idle,
    Opening,
    Established,
    LocalHalfClosed,
    RemoteHalfClosed,
    Closed,
    Reset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    SendOpen,
    OpenAcked,
    OpenFailed,
    LocalHalfClose,
    RemoteHalfClose,
    Reset,
}

impl StreamState {
    pub fn name(self) -> &'static str {
        match self {
            StreamState::Idle => "idle",
            StreamState::Opening => "opening",
            StreamState::Established => "established",
            StreamState::LocalHalfClosed => "local_half_closed",
            StreamState::RemoteHalfClosed => "remote_half_closed",
            StreamState::Closed => "closed",
            StreamState::Reset => "reset",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, StreamState::Closed | StreamState::Reset)
    }

    pub fn can_send_data(self) -> bool {
        matches!(
            self,
            StreamState::Established | StreamState::RemoteHalfClosed
        )
    }

    pub fn can_receive_data(self) -> bool {
        matches!(
            self,
            StreamState::Established | StreamState::LocalHalfClosed
        )
    }

    pub fn apply(self, event: StreamEvent) -> Result<StreamState, IllegalTransition> {
        use StreamEvent as E;
        use StreamState as S;
        let next = match (self, event) {
            (S::Idle, E::SendOpen) => S::Opening,
            (S::Opening, E::OpenAcked) => S::Established,
            (S::Opening, E::OpenFailed) => S::Reset,
            (S::Established, E::LocalHalfClose) => S::LocalHalfClosed,
            (S::Established, E::RemoteHalfClose) => S::RemoteHalfClosed,
            (S::LocalHalfClosed, E::RemoteHalfClose) => S::Closed,
            (S::RemoteHalfClosed, E::LocalHalfClose) => S::Closed,
            (s, E::Reset) if !s.is_terminal() => S::Reset,
            (from, _) => {
                return Err(IllegalTransition {
                    from: from.name(),
                    to: "invalid",
                })
            }
        };
        Ok(next)
    }
}

/// Configuration revision lifecycle (02 §6, 04 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevisionState {
    Draft,
    Validated,
    Prepared,
    Committed,
    Active,
    Superseded,
    Rejected,
}

impl RevisionState {
    pub fn as_str(self) -> &'static str {
        match self {
            RevisionState::Draft => "draft",
            RevisionState::Validated => "validated",
            RevisionState::Prepared => "prepared",
            RevisionState::Committed => "committed",
            RevisionState::Active => "active",
            RevisionState::Superseded => "superseded",
            RevisionState::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "draft" => RevisionState::Draft,
            "validated" => RevisionState::Validated,
            "prepared" => RevisionState::Prepared,
            "committed" => RevisionState::Committed,
            "active" => RevisionState::Active,
            "superseded" => RevisionState::Superseded,
            "rejected" => RevisionState::Rejected,
            _ => return None,
        })
    }

    /// Only failures before `Committed` may enter `Rejected`; a committed
    /// revision is reconciled, never rewritten to rejected.
    pub fn transition(self, to: RevisionState) -> Result<RevisionState, IllegalTransition> {
        use RevisionState::*;
        let ok = matches!(
            (self, to),
            (Draft, Validated)
                | (Validated, Prepared)
                | (Draft, Prepared)
                | (Prepared, Committed)
                | (Validated, Committed)
                | (Draft, Committed)
                | (Committed, Active)
                | (Active, Superseded)
                | (Committed, Superseded)
                | (Draft, Rejected)
                | (Validated, Rejected)
                | (Prepared, Rejected)
        );
        if ok {
            Ok(to)
        } else {
            Err(IllegalTransition {
                from: self.as_str(),
                to: to.as_str(),
            })
        }
    }
}

/// Node enrollment lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentState {
    Unenrolled,
    PendingApproval,
    Active,
    Rotating,
    Revoked,
}

impl EnrollmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            EnrollmentState::Unenrolled => "unenrolled",
            EnrollmentState::PendingApproval => "pending",
            EnrollmentState::Active => "active",
            EnrollmentState::Rotating => "rotating",
            EnrollmentState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "unenrolled" => EnrollmentState::Unenrolled,
            "pending" => EnrollmentState::PendingApproval,
            "active" => EnrollmentState::Active,
            "rotating" => EnrollmentState::Rotating,
            "revoked" => EnrollmentState::Revoked,
            _ => return None,
        })
    }

    pub fn transition(self, to: EnrollmentState) -> Result<EnrollmentState, IllegalTransition> {
        use EnrollmentState::*;
        let ok = matches!(
            (self, to),
            (Unenrolled, PendingApproval)
                | (Unenrolled, Active)
                | (PendingApproval, Active)
                | (Active, Rotating)
                | (Rotating, Active)
                | (Active, Revoked)
                | (Rotating, Revoked)
                | (PendingApproval, Revoked)
        );
        if ok {
            Ok(to)
        } else {
            Err(IllegalTransition {
                from: self.as_str(),
                to: to.as_str(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_transitions() {
        let s = AgentState::Starting;
        let s = s.transition(AgentState::Ready).expect("ready");
        assert!(s.admission_allowed());
        let s = s
            .transition(AgentState::Degraded {
                admission_allowed: false,
            })
            .expect("degraded");
        assert!(!s.admission_allowed());
        let s = s.transition(AgentState::Draining).expect("draining");
        assert!(s.transition(AgentState::Ready).is_err());
        let s = s.transition(AgentState::Stopped).expect("stopped");
        assert!(s.transition(AgentState::Starting).is_err());
    }

    #[test]
    fn stream_transitions() {
        use StreamEvent as E;
        let s = StreamState::Idle.apply(E::SendOpen).expect("open");
        assert!(
            s.apply(E::LocalHalfClose).is_err(),
            "no half-close before ack"
        );
        let s = s.apply(E::OpenAcked).expect("ack");
        let s = s.apply(E::LocalHalfClose).expect("lhc");
        assert!(!s.can_send_data());
        assert!(s.can_receive_data());
        let s = s.apply(E::RemoteHalfClose).expect("closed");
        assert_eq!(s, StreamState::Closed);
        assert!(
            s.apply(E::Reset).is_err(),
            "reset after close is not a transition"
        );
        let r = StreamState::Established.apply(E::Reset).expect("reset");
        assert!(
            r.apply(E::OpenAcked).is_err(),
            "reset never becomes success"
        );
    }

    #[test]
    fn revision_transitions() {
        use RevisionState::*;
        assert!(Committed.transition(Rejected).is_err());
        assert!(Active.transition(Superseded).is_ok());
        assert!(Draft.transition(Active).is_err());
    }

    #[test]
    fn enrollment_transitions() {
        use EnrollmentState::*;
        assert!(
            Revoked.transition(Active).is_err(),
            "revocation is permanent"
        );
        assert!(Active
            .transition(Rotating)
            .and_then(|s| s.transition(Active))
            .is_ok());
    }
}
