//! AGP/1 session multiplexer (03 §3, C-003).
//!
//! One authenticated session carries many logical streams. Key properties:
//!
//! * **Credit is backed by reservation.** The receive session window is
//!   reserved from the peer/process [`aegis_buffer::Budget`] before it is
//!   advertised, and the invariant
//!   `buffered + outstanding_credit + pending_grant == reserved`
//!   holds at all times.
//! * **The parser never waits on a stream.** DATA within advertised credit is
//!   pushed into reserved storage; over-window DATA is a protocol error.
//! * **Control progresses under DATA saturation.** Control frames
//!   (WINDOW_UPDATE, RESET, OPEN_ACK, PONG, GOAWAY) are written before DATA,
//!   from a bounded queue.
//! * **Fair scheduling.** Streams with sendable data are served round-robin
//!   with a one-frame quantum.
//! * **No resumption.** Losing the transport fails all streams; reconnecting
//!   creates a new session and new streams.
//! * **UDP flows lose, never block.** When both sides agree (feature
//!   0x0001), a stream can be a UDP flow carrying whole DATAGRAMs. They
//!   use no credit; bounded, reserved queues drop instead of waiting.
#![forbid(unsafe_code)]

mod config;
mod datagram;
mod error;
mod mux;
mod stream;

pub use config::SessionConfig;
pub use datagram::{DatagramFlow, DatagramPath};
pub use error::{OpenError, SessionError};
pub use mux::{
    client_handshake, server_handshake, Incoming, IncomingOpen, PeerInfo, Session, SessionStats,
};
pub use stream::MuxStream;
