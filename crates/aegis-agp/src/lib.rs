//! AGP/1 — the AegisBorne inner protocol (03 §3). Not V2Ray compatible.
//!
//! Layering: `Transport duplex → TLS 1.3 mTLS → AGP framing → streams`.
//! This crate only encodes/decodes; session semantics live in `aegis-session`.
//!
//! Every length is checked against the negotiated cap *before* any payload
//! buffer is allocated, and every control message uses a strict, deterministic
//! binary layout that rejects trailing bytes and unknown values.
#![forbid(unsafe_code)]

mod control;
mod frame;

pub use control::{
    decode_reset, decode_window_update, encode_reset, encode_window_update, Feature, GoAway, Hello,
    Network, OpenAck, OpenRequest, CRITICAL_FEATURE_BIT, FEATURE_DATAGRAM, FEATURE_DATAGRAM_PATH,
    MAX_FEATURES, MAX_HELLO_LEN, MAX_NODE_ID_LEN, MAX_OPEN_TIMEOUT_MS,
};
pub use frame::{
    encode_frame, encode_header, Decoder, Frame, FrameType, Header, FLAG_RESET_ACK, HEADER_LEN,
    MAGIC, MAX_FRAME_LEN, MAX_PAYLOAD, MAX_WINDOW, MIN_ADVERTISED_PAYLOAD, VERSION_MAJOR,
};

use std::fmt;

/// A protocol violation. Any of these terminates the session; none is ever
/// converted into a successful transfer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    BadMagic,
    UnsupportedVersion(u8),
    UnknownFrameType(u8),
    /// A frame type this build doesn't accept (none at present).
    UnsupportedFrameType(FrameType),
    ReservedFlags {
        frame_type: FrameType,
        flags: u16,
    },
    PayloadTooLarge {
        length: u32,
        cap: u32,
    },
    BadLength {
        frame_type: FrameType,
        length: u32,
    },
    BadStreamId {
        frame_type: FrameType,
        stream_id: u32,
    },
    Malformed(&'static str),
    UnknownCriticalFeature(u16),
    /// Session-level semantic violation detected above the codec.
    Violation(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::BadMagic => f.write_str("bad frame magic"),
            ProtocolError::UnsupportedVersion(v) => write!(f, "unsupported protocol version {v}"),
            ProtocolError::UnknownFrameType(t) => write!(f, "unknown frame type {t}"),
            ProtocolError::UnsupportedFrameType(t) => write!(f, "unsupported frame type {t:?}"),
            ProtocolError::ReservedFlags { frame_type, flags } => {
                write!(f, "reserved flags {flags:#06x} on {frame_type:?}")
            }
            ProtocolError::PayloadTooLarge { length, cap } => {
                write!(f, "payload length {length} exceeds cap {cap}")
            }
            ProtocolError::BadLength { frame_type, length } => {
                write!(f, "invalid length {length} for {frame_type:?}")
            }
            ProtocolError::BadStreamId {
                frame_type,
                stream_id,
            } => write!(f, "invalid stream id {stream_id} for {frame_type:?}"),
            ProtocolError::Malformed(what) => write!(f, "malformed payload: {what}"),
            ProtocolError::UnknownCriticalFeature(id) => {
                write!(f, "unknown critical feature {id:#06x}")
            }
            ProtocolError::Violation(what) => write!(f, "protocol violation: {what}"),
        }
    }
}

impl std::error::Error for ProtocolError {}
