//! Console-driven upgrades of the gateway container.
//!
//! The gateway runs unprivileged and has no access to Docker. A second,
//! small container from the same image (`aegisctl updater`) holds the
//! Docker socket instead. It has no network listener; the two talk only
//! through files in the shared data volume ([`files`]):
//!
//! * the console writes a request (`check`, or `upgrade` to a release
//!   version) and the automatic-upgrade setting;
//! * the updater writes its status: the running and available versions,
//!   what it is doing, how the last attempt ended.
//!
//! An upgrade recreates the gateway container with the new image and the
//! same settings, waits for its health check and rolls back to the previous
//! container when it doesn't become healthy. Only release images of the one
//! repository the updater was started for are ever run.
#![forbid(unsafe_code)]

#[cfg(unix)]
pub mod docker;
pub mod files;
#[cfg(unix)]
mod run;
pub mod version;

#[cfg(unix)]
pub use run::{run, Options, Source};
