//! Shared agent lifecycle state.

use aegis_contracts::state::AgentState;
use std::sync::Mutex;

#[derive(Debug)]
pub struct AgentCell {
    state: Mutex<AgentState>,
}

impl Default for AgentCell {
    fn default() -> Self {
        AgentCell {
            state: Mutex::new(AgentState::Starting),
        }
    }
}

impl AgentCell {
    pub fn get(&self) -> AgentState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply a checked transition; returns false (and leaves the state
    /// unchanged) if it is illegal.
    pub fn transition(&self, to: AgentState) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match s.transition(to) {
            Ok(next) => {
                *s = next;
                true
            }
            Err(_) => false,
        }
    }
}
