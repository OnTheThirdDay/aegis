use aegis_agp::{MAX_PAYLOAD, MAX_WINDOW, MIN_ADVERTISED_PAYLOAD};
use std::time::Duration;

/// Per-session parameters. Defaults follow 02 §7 and must be re-benchmarked
/// on Pi hardware before being treated as tuned values.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// This endpoint's node identity, bound to its mTLS certificate.
    pub node_id: String,
    /// Upper bound on concurrent streams (incl. closing records) we accept.
    pub max_streams: u32,
    /// Per-stream receive window we advertise (16 KiB – 1 MiB).
    pub stream_window: u32,
    /// Session receive window we try to reserve and advertise.
    pub session_window: u32,
    /// Largest payload we accept per frame (8 KiB – 64 KiB).
    pub max_frame_payload: u32,
    /// Per-stream transmit buffer ceiling.
    pub stream_tx_buffer: u32,
    /// Bounded control queue (frames).
    pub control_queue_frames: usize,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_timeout: Duration,
    pub reset_drain_timeout: Duration,
    /// Peer PING/PONG frames tolerated per second (burst = 2x).
    pub peer_ping_rate: u32,
    /// Bounded queue of OPENs awaiting the gateway's admission decision.
    pub incoming_queue: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            node_id: "node".into(),
            max_streams: 64,
            stream_window: 64 * 1024,
            session_window: 2 * 1024 * 1024,
            max_frame_payload: 16 * 1024,
            stream_tx_buffer: 64 * 1024,
            control_queue_frames: 4096,
            handshake_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(20),
            reset_drain_timeout: Duration::from_secs(10),
            peer_ping_rate: 10,
            incoming_queue: 64,
        }
    }
}

impl SessionConfig {
    /// Validate ranges; returns a human-readable reason on failure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(16 * 1024..=1024 * 1024).contains(&self.stream_window) {
            return Err("stream_window must be 16 KiB..=1 MiB");
        }
        if self.session_window < self.stream_window || self.session_window > MAX_WINDOW {
            return Err("session_window must be >= stream_window and < 2^31");
        }
        if !(MIN_ADVERTISED_PAYLOAD..=MAX_PAYLOAD).contains(&self.max_frame_payload) {
            return Err("max_frame_payload must be 8 KiB..=64 KiB");
        }
        if self.max_streams == 0 {
            return Err("max_streams must be positive");
        }
        if !(1024..=1024 * 1024).contains(&self.stream_tx_buffer) {
            return Err("stream_tx_buffer must be 1 KiB..=1 MiB");
        }
        if self.control_queue_frames < 16 {
            return Err("control_queue_frames too small");
        }
        Ok(())
    }

    /// Streams that can be admitted while still reserving one full stream
    /// window as a working share for runnable streams: a stalled stream can
    /// hold at most `stream_window` of the session budget (03 §3).
    pub fn effective_max_streams(&self, reserved_session_window: u32) -> u32 {
        let fit = (reserved_session_window / self.stream_window).saturating_sub(1);
        self.max_streams.min(fit.max(1))
    }
}
