//! Platform-neutral contracts shared by every AegisBorne module.
//!
//! This crate deliberately depends only on `serde` (A-002): no async runtime,
//! no HTTP stack and no management types. Everything here is either plain data
//! or a synchronous trait.
#![forbid(unsafe_code)]

pub mod capability;
pub mod destination;
pub mod observability;
pub mod reason;
pub mod route;
pub mod state;
pub mod vpn;

pub use capability::{Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role};
pub use destination::{Destination, DestinationError, Host};
pub use observability::{Event, NoopObservability, Observability};
pub use reason::{OpenFailure, ReasonGroup, ResetReason};
pub use route::{RouteAction, RouteDecision, RuleClass};
