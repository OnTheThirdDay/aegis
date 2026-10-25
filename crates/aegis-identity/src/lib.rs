//! Node identity and the inner mutual-TLS channel (03 §1, OQ-01).
//!
//! OQ-01 decision for this build: a **local CA** per personal install. Node
//! private keys are generated on the node; the CA signs a CSR presented with a
//! one-use invitation. Node certificates are short-lived, carry the node ID in
//! the subject CN and the role in the subject OU, and are restricted by EKU
//! (gateway = serverAuth, client = clientAuth).
//!
//! Inner TLS is TLS 1.3 only, with session resumption, tickets and 0-RTT
//! disabled: every AGP session performs a full mutual handshake against the
//! current revocation snapshot.
#![forbid(unsafe_code)]

pub mod pki;
pub mod store;
pub mod tls;

pub use store::{IdentitySnapshot, IdentityStore};
pub use tls::{client_config, server_config, PeerIdentity, ALPN_AGP1};

use std::fmt;

#[derive(Debug)]
pub enum IdentityError {
    Pem(&'static str),
    Certificate(String),
    Tls(rustls::Error),
    InvalidNodeId,
    Generation(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::Pem(what) => write!(f, "invalid PEM: {what}"),
            IdentityError::Certificate(e) => write!(f, "certificate error: {e}"),
            IdentityError::Tls(e) => write!(f, "TLS configuration error: {e}"),
            IdentityError::InvalidNodeId => f.write_str("invalid node id"),
            IdentityError::Generation(e) => write!(f, "key/certificate generation failed: {e}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<rustls::Error> for IdentityError {
    fn from(e: rustls::Error) -> Self {
        IdentityError::Tls(e)
    }
}

impl From<rcgen::Error> for IdentityError {
    fn from(e: rcgen::Error) -> Self {
        IdentityError::Generation(e.to_string())
    }
}

/// Node IDs: 1–64 chars of `[A-Za-z0-9._-]` (same rule as AGP HELLO).
pub fn valid_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
