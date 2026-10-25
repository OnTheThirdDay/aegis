//! Routing and egress policy (03 §8, D-003, D-005).
//!
//! Evaluation order for every new logical stream:
//! 1. explicit deny rules;
//! 2. mandatory destination restrictions (egress address policy);
//! 3. node/user permissions (rules scoped to authenticated nodes);
//! 4. most-specific matching allow rule;
//! 5. secure default.
//!
//! Domain destinations are re-checked after resolution: every selected
//! address must pass the address policy and CIDR deny rules before dialing.
#![forbid(unsafe_code)]

pub mod address;
pub mod router;

pub use address::{classify, AddressClass, AddressPolicy};
pub use router::{
    CompileError, DecisionInput, ExplainAction, Explanation, Matcher, Router, RuleSpec,
};
