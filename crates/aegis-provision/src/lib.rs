//! SPEC-12: control-plane-only provisioning. No data-plane dependency and no
//! host authority unless an operator explicitly constructs the local adapter.
#![forbid(unsafe_code)]

pub mod certificate;
pub mod cloudflare;
pub mod host;
pub mod nginx;
mod saga;
pub mod secrets;
pub mod trust;
mod types;
pub use saga::{Controller, Executor, HostProvisioner, InfrastructureProvider, Probe, StepFuture};
pub use types::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<aegis_storage::StoreError> for Error {
    fn from(_: aegis_storage::StoreError) -> Self {
        Self("provision_storage_unavailable")
    }
}
pub type Result<T> = std::result::Result<T, Error>;
