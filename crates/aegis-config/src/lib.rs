//! Typed configuration (02 §5).
//!
//! Configuration is never executed directly. [`parse_toml`]/[`parse_json`]
//! produce a typed [`NodeConfig`] (unknown fields rejected everywhere),
//! [`compile`] validates it against the installed capability environment and
//! produces an immutable [`CompiledConfig`] with a canonical SHA-256 digest.
//! Secrets are only ever `secret://` references; values are resolved at
//! runtime preparation, never into the digest or stored revisions.
#![forbid(unsafe_code)]

mod canonical;
mod compile;
mod diff;
pub mod secret;
mod types;

pub use canonical::{canonical_json, digest_value};
pub use compile::{compile, quic_address, CompiledConfig, Environment, ModuleIds};
pub use diff::{security_diff, Diff};
pub use types::*;

use std::fmt;

/// Maximum accepted configuration document size (before decoding).
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;
pub const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["0.1", "0.2"];

/// Explicit, offline dry-run migration. The caller publishes the returned
/// profile through the existing revision coordinator; seed edits have no effect
/// on initialized stores. Keep the source revision for a compensating restore.
pub fn migrate_v02(cfg: &NodeConfig) -> (NodeConfig, Vec<String>) {
    let mut next = cfg.clone();
    next.schema_version = "0.2".into();
    next.identity.require_enrollment = true;
    next.identity.legacy_identity_until = Some(1_800_662_400); // 2027-01-23 UTC
    (next, vec![
        "Register every existing client certificate before activation; unregistered CA certificates lose access.".into(),
        "Legacy CN/OU identities expire at the fixed migration deadline; renew to URI SAN first.".into(),
        "Existing SQLite state is authoritative; activate this as a new revision. DNS endpoints and inner names are preserved.".into(),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    TooLarge,
    Parse(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::TooLarge => write!(f, "configuration exceeds {MAX_CONFIG_BYTES} bytes"),
            ConfigError::Parse(e) => write!(f, "configuration parse error: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Parse one `connect_addresses` entry (`ip`, `ip:port` or `[v6]:port`),
/// using `default_port` when none is given. Unspecified addresses and port 0
/// are refused.
pub fn connect_address(entry: &str, default_port: u16) -> Option<std::net::SocketAddr> {
    let addr = entry.parse::<std::net::SocketAddr>().ok().or_else(|| {
        entry
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| std::net::SocketAddr::new(ip, default_port))
    })?;
    (!addr.ip().is_unspecified() && addr.port() != 0).then_some(addr)
}

pub fn parse_toml(text: &str) -> Result<NodeConfig, ConfigError> {
    if text.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    toml::from_str(text).map_err(|e| ConfigError::Parse(e.message().to_owned()))
}

pub fn parse_json(value: &serde_json::Value) -> Result<NodeConfig, ConfigError> {
    let size = serde_json::to_vec(value)
        .map(|v| v.len())
        .unwrap_or(usize::MAX);
    if size > MAX_CONFIG_BYTES {
        return Err(ConfigError::TooLarge);
    }
    serde_json::from_value(value.clone()).map_err(|e| ConfigError::Parse(e.to_string()))
}

/// Typed, defaults-applied JSON form used for storage and digests.
pub fn to_json(cfg: &NodeConfig) -> serde_json::Value {
    serde_json::to_value(cfg).unwrap_or(serde_json::Value::Null)
}

/// SHA-256 (lowercase hex) over RFC 8785-style canonical JSON of the typed,
/// normalized configuration.
pub fn config_digest(cfg: &NodeConfig) -> String {
    digest_value(&to_json(cfg))
}
