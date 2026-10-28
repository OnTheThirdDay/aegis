use aegis_agp::{MAX_PAYLOAD, MAX_WINDOW, MIN_ADVERTISED_PAYLOAD};
use std::time::Duration;

/// Per-session parameters. Defaults follow 02 §7 and must be re-benchmarked
/// on Pi hardware before being treated as tuned values.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// This endpoint's node identity, bound to its mTLS certificate.
    pub node_id: String,
    pub expected_peer_node_id: Option<String>,
    /// Upper bound on concurrent streams (incl. closing records) we accept.
    pub max_streams: u32,
    /// Largest receive window one stream can grow to: the per-stream RX
    /// quota (16 KiB – 1 MiB).
    pub stream_window: u32,
    /// Receive window a new stream starts with (advertised in HELLO). It
    /// grows towards `stream_window` while the stream's sender is limited
    /// by our credit, so idle streams stay cheap (1 KiB – `stream_window`).
    pub initial_stream_window: u32,
    /// Session receive window we try to reserve and advertise.
    pub session_window: u32,
    /// Largest payload we accept per frame (8 KiB – 64 KiB).
    pub max_frame_payload: u32,
    /// Per-stream transmit buffer ceiling; reserved in steps as data is
    /// written, starting at `initial_stream_window`.
    pub stream_tx_buffer: u32,
    /// Bounded control queue (frames).
    pub control_queue_frames: usize,
    pub handshake_timeout: Duration,
    pub keepalive_interval: Duration,
    /// Deadline for both a keepalive response and a transport write/flush.
    pub keepalive_timeout: Duration,
    pub reset_drain_timeout: Duration,
    /// Peer PING/PONG frames tolerated per second (burst = 2x).
    pub peer_ping_rate: u32,
    /// Bounded queue of OPENs awaiting the gateway's admission decision.
    pub incoming_queue: usize,
    /// Offer (client) or accept (gateway) UDP flows: feature 0x0001,
    /// DATAGRAM frames. Used only when both sides agree and the buffers
    /// below can be reserved.
    pub datagrams: bool,
    /// Received datagrams one flow holds for its reader; newer ones are
    /// dropped while it is full (UDP semantics: loss, never backpressure).
    pub datagram_queue: usize,
    /// Bytes of received datagrams held across all flows of the session.
    pub datagram_recv_buffer: u32,
    /// Bytes of datagrams waiting to be written; beyond it new ones are
    /// dropped instead of queueing behind a slow transport.
    pub datagram_send_buffer: u32,
    /// The transport's own unreliable datagrams (QUIC), used for UDP flows
    /// when both sides have one (feature 0x0002). Datagrams too large for
    /// it still go in the session.
    pub datagram_path: Option<std::sync::Arc<dyn crate::DatagramPath>>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            node_id: "node".into(),
            expected_peer_node_id: None,
            max_streams: 512,
            stream_window: 256 * 1024,
            initial_stream_window: 16 * 1024,
            session_window: 8 * 1024 * 1024,
            max_frame_payload: 16 * 1024,
            stream_tx_buffer: 256 * 1024,
            control_queue_frames: 4096,
            handshake_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(20),
            reset_drain_timeout: Duration::from_secs(10),
            peer_ping_rate: 10,
            incoming_queue: 64,
            datagrams: false,
            datagram_queue: 64,
            datagram_recv_buffer: 512 * 1024,
            datagram_send_buffer: 256 * 1024,
            datagram_path: None,
        }
    }
}

impl SessionConfig {
    /// Validate ranges; returns a human-readable reason on failure.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(16 * 1024..=1024 * 1024).contains(&self.stream_window) {
            return Err("stream_window must be 16 KiB..=1 MiB");
        }
        if !(1024..=self.stream_window).contains(&self.initial_stream_window) {
            return Err("initial_stream_window must be 1 KiB..=stream_window");
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
        if self.datagrams
            && (self.datagram_queue == 0
                || self.datagram_recv_buffer < MAX_PAYLOAD
                || self.datagram_send_buffer < MAX_PAYLOAD)
        {
            return Err("datagram buffers must each hold one largest frame");
        }
        Ok(())
    }

    /// Streams that can be admitted, each with its initial window, while one
    /// full stream window stays free as the working share for runnable
    /// streams (03 §3): the sum of all stream windows never exceeds
    /// `reserved - stream_window`, so stalled streams cannot take the whole
    /// receive budget. Windows only grow inside that same bound.
    pub fn effective_max_streams(&self, reserved_session_window: u32) -> u32 {
        let fit = reserved_session_window.saturating_sub(self.stream_window)
            / self.initial_stream_window.max(1);
        self.max_streams.min(fit.max(1))
    }

    /// Budget for the sum of all stream windows (see
    /// [`effective_max_streams`](Self::effective_max_streams)).
    pub fn stream_windows_budget(&self, reserved_session_window: u64) -> u64 {
        reserved_session_window.saturating_sub(u64::from(self.stream_window))
    }
}
