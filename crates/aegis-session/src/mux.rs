//! Session engine: handshake, shared state, reader/writer/timer tasks.

use crate::config::SessionConfig;
use crate::error::{OpenError, SessionError};
use crate::stream::MuxStream;
use aegis_agp::{
    decode_reset, decode_window_update, encode_frame, encode_reset, encode_window_update, Decoder,
    Frame, FrameType, GoAway, Hello, OpenAck, OpenRequest, ProtocolError, FLAG_RESET_ACK,
    MAX_WINDOW, VERSION_MAJOR,
};
use aegis_buffer::{Budget, Reservation};
use aegis_contracts::observability::{Event, Observability, PoolClass};
use aegis_contracts::reason::{OpenFailure, ResetReason};
use aegis_contracts::state::StreamState;
use aegis_contracts::Destination;
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Waker;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch, Notify};
use tokio::time::Instant;

/// Largest batch the writer assembles before issuing one transport write.
const WRITE_BATCH: usize = 64 * 1024;
const TIMER_TICK: Duration = Duration::from_millis(250);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    pub node_id: String,
    pub max_streams: u32,
    pub stream_window: u32,
    pub session_window: u32,
    pub max_frame_payload: u32,
    pub features: Vec<u16>,
}

/// Point-in-time accounting snapshot (for health and invariant tests).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStats {
    pub streams: usize,
    pub recv_reserved: u64,
    /// Backing storage for receive rings, bounded by `recv_reserved`.
    pub recv_allocated: u64,
    pub recv_outstanding: u64,
    pub recv_buffered: u64,
    pub recv_pending_grant: u64,
    pub send_session_credit: u64,
    pub control_queued: usize,
    pub closed: bool,
}

#[derive(Debug)]
pub(crate) enum ResetPhase {
    None,
    /// We sent a RESET request; the peer may still have DATA in flight.
    AwaitingPeer {
        deadline: Instant,
    },
}

/// One fixed allocation per stream, independent of peer DATA fragmentation.
/// The session's receive reservation and stream-count limit cover these rings
/// before any stream credit is advertised.
#[derive(Debug)]
pub(crate) struct ReceiveBuffer {
    bytes: Box<[u8]>,
    start: usize,
    len: usize,
}

impl ReceiveBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: vec![0; capacity].into_boxed_slice(),
            start: 0,
            len: 0,
        }
    }

    fn capacity(&self) -> usize {
        self.bytes.len()
    }

    fn append(&mut self, data: &[u8]) -> bool {
        if data.len() > self.capacity() - self.len {
            return false;
        }
        let end = (self.start + self.len) % self.capacity();
        let first = data.len().min(self.capacity() - end);
        self.bytes[end..end + first].copy_from_slice(&data[..first]);
        self.bytes[..data.len() - first].copy_from_slice(&data[first..]);
        self.len += data.len();
        true
    }

    pub fn read_into(&mut self, out: &mut ReadBuf<'_>) -> usize {
        let n = self.len.min(out.remaining());
        let first = n.min(self.capacity() - self.start);
        out.put_slice(&self.bytes[self.start..self.start + first]);
        out.put_slice(&self.bytes[..n - first]);
        self.start = (self.start + n) % self.capacity();
        self.len -= n;
        n
    }

    fn clear(&mut self) {
        self.start = 0;
        self.len = 0;
    }
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub state: StreamState,
    pub rx: ReceiveBuffer,
    pub rx_buffered: u32,
    pub rx_outstanding: u32,
    pub pending_grant: u32,
    pub remote_fin: bool,
    pub tx: BytesMut,
    pub tx_cap: usize,
    pub send_credit: u64,
    pub fin_requested: bool,
    pub fin_sent: bool,
    pub in_ready: bool,
    pub reset: ResetPhase,
    pub reset_reason: Option<ResetReason>,
    pub read_waker: Option<Waker>,
    pub write_waker: Option<Waker>,
    pub open_waiter: Option<oneshot::Sender<OpenAck>>,
    pub handle_alive: bool,
    _tx_reservation: Reservation,
}

impl Entry {
    fn new(
        state: StreamState,
        rx_window: u32,
        send_credit: u32,
        tx_cap: usize,
        reservation: Reservation,
    ) -> Self {
        Entry {
            state,
            rx: ReceiveBuffer::new(rx_window as usize),
            rx_buffered: 0,
            rx_outstanding: rx_window,
            pending_grant: 0,
            remote_fin: false,
            tx: BytesMut::new(),
            tx_cap,
            send_credit: u64::from(send_credit),
            fin_requested: false,
            fin_sent: false,
            in_ready: false,
            reset: ResetPhase::None,
            reset_reason: None,
            read_waker: None,
            write_waker: None,
            open_waiter: None,
            handle_alive: true,
            _tx_reservation: reservation,
        }
    }

    fn wake_all(&mut self) {
        if let Some(w) = self.read_waker.take() {
            w.wake();
        }
        if let Some(w) = self.write_waker.take() {
            w.wake();
        }
    }

    /// Removable once no handle refers to it and no peer DATA can still
    /// arrive for it.
    fn removable(&self) -> bool {
        !self.handle_alive
            && match self.state {
                StreamState::Closed => true,
                StreamState::Reset => matches!(self.reset, ResetPhase::None),
                _ => false,
            }
    }
}

pub(crate) struct State {
    pub streams: HashMap<u32, Entry>,
    pub ready: VecDeque<u32>,
    pub control: VecDeque<Frame>,
    pub send_session_credit: u64,
    pub recv_reserved: u64,
    pub recv_outstanding: u64,
    pub recv_buffered: u64,
    pub recv_pending_grant: u64,
    /// Next client stream ID to allocate (client role); `None` = exhausted.
    pub next_local_id: Option<u32>,
    /// Highest client stream ID seen (server role); 0 = none yet.
    pub last_peer_id: u32,
    pub goaway_sent: bool,
    pub goaway_received: Option<u32>,
    pub closed: Option<SessionError>,
    pub final_frame: Option<Frame>,
    pub owner_dropped: bool,
    pub last_rx: Instant,
    pub ping_outstanding: Option<Instant>,
    pub ping_counter: u64,
    pub incoming_tx: Option<mpsc::Sender<IncomingOpen>>,
    _rx_reservation: Reservation,
    _control_reservation: Reservation,
}

pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub writer: Notify,
    pub closed_tx: watch::Sender<bool>,
    pub cfg: SessionConfig,
    pub peer: PeerInfo,
    pub is_client: bool,
    pub budget: Arc<Budget>,
    pub local_max_streams: u32,
    pub obs: Arc<dyn Observability>,
}

impl Shared {
    pub fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn send_frame_cap(&self) -> usize {
        self.peer.max_frame_payload.min(self.cfg.max_frame_payload) as usize
    }

    fn stream_grant_threshold(&self) -> u32 {
        (self.cfg.stream_window / 4).max(1)
    }

    fn session_grant_threshold(st: &State) -> u64 {
        (st.recv_reserved / 8).max(1)
    }

    /// Is `id` a client-initiated ID that was previously opened in this
    /// session? Used to ignore late frames for closed streams while still
    /// rejecting frames for never-opened IDs.
    fn previously_valid(&self, st: &State, id: u32) -> bool {
        if id & 1 == 0 {
            return false;
        }
        if self.is_client {
            match st.next_local_id {
                Some(next) => id < next,
                None => true,
            }
        } else {
            st.last_peer_id != 0 && id <= st.last_peer_id
        }
    }

    pub fn push_control(&self, st: &mut State, frame: Frame) -> Result<(), SessionError> {
        if st.control.len() >= self.cfg.control_queue_frames {
            return Err(SessionError::ControlOverload);
        }
        st.control.push_back(frame);
        Ok(())
    }

    fn maybe_grant_session(&self, st: &mut State, force: bool) -> Result<(), SessionError> {
        let threshold = Self::session_grant_threshold(st);
        if st.recv_pending_grant > 0 && (force || st.recv_pending_grant >= threshold) {
            let amount = st.recv_pending_grant.min(u64::from(MAX_WINDOW));
            // Keep credit + buffered within the reservation (checked).
            debug_assert!(st.recv_outstanding + amount + st.recv_buffered <= st.recv_reserved);
            let payload = encode_window_update(amount as u32)?;
            self.push_control(st, Frame::new(FrameType::WindowUpdate, 0, payload))?;
            st.recv_outstanding += amount;
            st.recv_pending_grant -= amount;
        }
        Ok(())
    }

    /// Account for bytes the application consumed from stream `id`.
    pub fn on_consumed(&self, st: &mut State, id: u32, n: u32) -> Result<(), SessionError> {
        st.recv_buffered -= u64::from(n);
        st.recv_pending_grant += u64::from(n);
        let threshold = self.stream_grant_threshold();
        let mut grant = None;
        if let Some(e) = st.streams.get_mut(&id) {
            e.rx_buffered -= n;
            if !e.remote_fin {
                e.pending_grant += n;
                if e.pending_grant >= threshold {
                    grant = Some(e.pending_grant);
                    e.rx_outstanding += e.pending_grant;
                    e.pending_grant = 0;
                }
            }
        }
        if let Some(amount) = grant {
            let payload = encode_window_update(amount)?;
            self.push_control(st, Frame::new(FrameType::WindowUpdate, id, payload))?;
        }
        self.maybe_grant_session(st, false)?;
        self.writer.notify_one();
        Ok(())
    }

    /// Drop buffered receive data for a stream; the capacity backs session
    /// credit again but stream credit is not replenished.
    fn discard_rx(&self, st: &mut State, id: u32) {
        let mut freed = 0u64;
        if let Some(e) = st.streams.get_mut(&id) {
            freed = u64::from(e.rx_buffered);
            e.rx.clear();
            e.rx_buffered = 0;
        }
        st.recv_buffered -= freed;
        st.recv_pending_grant += freed;
    }

    /// Request a reset of stream `id` (RESET with ACK flag clear).
    pub fn local_reset(
        &self,
        st: &mut State,
        id: u32,
        reason: ResetReason,
    ) -> Result<(), SessionError> {
        let Some(e) = st.streams.get_mut(&id) else {
            return Ok(());
        };
        if e.state.is_terminal() {
            return Ok(());
        }
        e.state = StreamState::Reset;
        e.reset_reason = Some(reason);
        e.tx.clear();
        e.fin_requested = false;
        e.reset = ResetPhase::AwaitingPeer {
            deadline: Instant::now() + self.cfg.reset_drain_timeout,
        };
        e.wake_all();
        self.discard_rx(st, id);
        st.ready.retain(|r| *r != id);
        self.push_control(st, Frame::new(FrameType::Reset, id, encode_reset(reason)))?;
        self.maybe_grant_session(st, false)?;
        self.writer.notify_one();
        Ok(())
    }

    /// Remove an entry, returning any buffered receive capacity.
    pub fn remove_entry(&self, st: &mut State, id: u32) {
        self.discard_rx(st, id);
        st.streams.remove(&id);
        st.ready.retain(|r| *r != id);
        if st.owner_dropped && st.streams.is_empty() && st.closed.is_none() {
            self.fail(st, SessionError::Closed(ResetReason::Shutdown));
        }
    }

    pub fn try_remove(&self, st: &mut State, id: u32) {
        if st.streams.get(&id).is_some_and(Entry::removable) {
            self.remove_entry(st, id);
        }
    }

    /// Terminate the session. Idempotent; wakes every waiter.
    pub fn fail(&self, st: &mut State, err: SessionError) {
        if st.closed.is_some() {
            return;
        }
        let reason = match &err {
            SessionError::Protocol(_) | SessionError::ControlOverload => {
                Some(ResetReason::ProtocolError)
            }
            SessionError::Closed(r) => Some(*r),
            SessionError::ResetDrainTimeout
            | SessionError::KeepaliveTimeout
            | SessionError::WriteTimeout => Some(ResetReason::Timeout),
            _ => None,
        };
        if let Some(reason) = reason {
            let last = if self.is_client { 0 } else { st.last_peer_id };
            st.final_frame = Some(Frame::new(
                FrameType::GoAway,
                0,
                GoAway {
                    last_stream_id: last,
                    reason,
                }
                .encode(),
            ));
        }
        st.closed = Some(err);
        for e in st.streams.values_mut() {
            e.open_waiter = None;
            e.wake_all();
        }
        st.ready.clear();
        st.incoming_tx = None;
        self.closed_tx.send_replace(true);
        self.writer.notify_one();
        self.obs.record(Event::SessionClosed);
    }
}

/// A live AGP session. Dropping the handle closes the session once all of its
/// streams are gone.
pub struct Session {
    pub(crate) shared: Arc<Shared>,
}

impl Session {
    pub fn peer(&self) -> &PeerInfo {
        &self.shared.peer
    }

    /// Open a logical stream (client role). Succeeds only once the gateway
    /// reports a connected destination.
    pub async fn open(
        &self,
        destination: Destination,
        timeout: Duration,
    ) -> Result<MuxStream, OpenError> {
        let shared = &self.shared;
        if !shared.is_client {
            return Err(OpenError::Rejected(OpenFailure::Unsupported));
        }
        let timeout_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, aegis_agp::MAX_OPEN_TIMEOUT_MS);
        let payload = OpenRequest {
            network: aegis_agp::Network::Tcp,
            destination,
            timeout_ms,
        }
        .encode()
        .map_err(|_| OpenError::Rejected(OpenFailure::Unsupported))?;
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut st = shared.lock();
            if let Some(e) = &st.closed {
                return Err(OpenError::Session(e.clone()));
            }
            if st.goaway_received.is_some() || st.goaway_sent {
                return Err(OpenError::GoingAway);
            }
            let limit = shared.peer.max_streams.min(shared.local_max_streams);
            if st.streams.len() as u32 >= limit {
                return Err(OpenError::Quota);
            }
            let id = st.next_local_id.ok_or(OpenError::IdsExhausted)?;
            let reservation = shared
                .budget
                .try_reserve(u64::from(shared.cfg.stream_tx_buffer), PoolClass::Transmit)
                .map_err(|_| OpenError::Quota)?;
            st.next_local_id = id.checked_add(2);
            let mut entry = Entry::new(
                StreamState::Opening,
                shared.cfg.stream_window,
                shared.peer.stream_window,
                shared.cfg.stream_tx_buffer as usize,
                reservation,
            );
            entry.open_waiter = Some(tx);
            st.streams.insert(id, entry);
            if let Err(e) = shared.push_control(&mut st, Frame::new(FrameType::Open, id, payload)) {
                shared.fail(&mut st, e.clone());
                return Err(OpenError::Session(e));
            }
            shared.writer.notify_one();
            id
        };
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(timeout, rx).await;
        let elapsed = started.elapsed().as_secs_f64();
        let result = match outcome {
            Ok(Ok(OpenAck::Success)) => Ok(MuxStream::new(Arc::clone(shared), id)),
            Ok(Ok(OpenAck::Failure(f))) => Err(OpenError::Rejected(f)),
            Ok(Err(_)) => {
                let st = shared.lock();
                Err(OpenError::Session(
                    st.closed.clone().unwrap_or(SessionError::PeerClosed),
                ))
            }
            Err(_) => {
                let mut st = shared.lock();
                if let Some(e) = st.streams.get_mut(&id) {
                    e.open_waiter = None;
                    e.handle_alive = false;
                }
                if let Err(e) = shared.local_reset(&mut st, id, ResetReason::Timeout) {
                    shared.fail(&mut st, e);
                }
                shared.try_remove(&mut st, id);
                Err(OpenError::Timeout)
            }
        };
        use aegis_contracts::observability::OperationResult;
        let res = match &result {
            Ok(_) => OperationResult::Ok,
            Err(OpenError::Timeout) => OperationResult::Timeout,
            Err(OpenError::Rejected(OpenFailure::Denied | OpenFailure::Unauthorized)) => {
                OperationResult::Denied
            }
            Err(_) => OperationResult::Error,
        };
        shared.obs.record(Event::StreamOpenDuration {
            seconds: elapsed,
            result: res,
        });
        result
    }

    /// Forbid new streams; existing streams drain normally.
    pub fn goaway(&self) {
        let shared = &self.shared;
        let mut st = shared.lock();
        if st.goaway_sent || st.closed.is_some() {
            return;
        }
        st.goaway_sent = true;
        let last = if shared.is_client { 0 } else { st.last_peer_id };
        let frame = Frame::new(
            FrameType::GoAway,
            0,
            GoAway {
                last_stream_id: last,
                reason: ResetReason::Shutdown,
            }
            .encode(),
        );
        if let Err(e) = shared.push_control(&mut st, frame) {
            shared.fail(&mut st, e);
        }
        shared.writer.notify_one();
    }

    /// Close immediately; all streams fail.
    pub fn close(&self, reason: ResetReason) {
        let mut st = self.shared.lock();
        self.shared.fail(&mut st, SessionError::Closed(reason));
    }

    pub fn is_closed(&self) -> bool {
        self.shared.lock().closed.is_some()
    }

    pub fn close_reason(&self) -> Option<SessionError> {
        self.shared.lock().closed.clone()
    }

    pub fn stream_count(&self) -> usize {
        self.shared.lock().streams.len()
    }

    /// Resolves when the session has terminated.
    pub async fn closed(&self) {
        let mut rx = self.shared.closed_tx.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }

    pub fn stats(&self) -> SessionStats {
        let st = self.shared.lock();
        SessionStats {
            streams: st.streams.len(),
            recv_reserved: st.recv_reserved,
            recv_allocated: st.streams.values().map(|e| e.rx.capacity() as u64).sum(),
            recv_outstanding: st.recv_outstanding,
            recv_buffered: st.recv_buffered,
            recv_pending_grant: st.recv_pending_grant,
            send_session_credit: st.send_session_credit,
            control_queued: st.control.len(),
            closed: st.closed.is_some(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut st = self.shared.lock();
        st.owner_dropped = true;
        if st.streams.is_empty() {
            self.shared
                .fail(&mut st, SessionError::Closed(ResetReason::Shutdown));
        }
    }
}

/// Stream of OPEN requests awaiting an admission decision (server role).
pub struct Incoming {
    rx: mpsc::Receiver<IncomingOpen>,
}

impl Incoming {
    pub async fn next(&mut self) -> Option<IncomingOpen> {
        self.rx.recv().await
    }
}

/// One pending OPEN. Must be accepted (after the destination is connected)
/// or rejected; dropping it rejects with `Internal`.
pub struct IncomingOpen {
    shared: Arc<Shared>,
    stream_id: u32,
    request: OpenRequest,
    responded: bool,
}

impl std::fmt::Debug for IncomingOpen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncomingOpen")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl IncomingOpen {
    pub fn stream_id(&self) -> u32 {
        self.stream_id
    }

    pub fn request(&self) -> &OpenRequest {
        &self.request
    }

    /// Send OPEN_ACK success. Call only after the destination connected.
    pub fn accept(mut self) -> Result<MuxStream, SessionError> {
        self.responded = true;
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        if let Some(e) = &st.closed {
            return Err(e.clone());
        }
        let opening = st
            .streams
            .get(&self.stream_id)
            .is_some_and(|e| e.state == StreamState::Opening);
        if !opening {
            // The client reset the stream while we were dialing.
            if let Some(e) = st.streams.get_mut(&self.stream_id) {
                e.handle_alive = false;
            }
            shared.try_remove(&mut st, self.stream_id);
            return Err(SessionError::Closed(ResetReason::Cancelled));
        }
        if let Some(e) = st.streams.get_mut(&self.stream_id) {
            e.state = StreamState::Established;
        }
        let frame = Frame::new(
            FrameType::OpenAck,
            self.stream_id,
            OpenAck::Success.encode(),
        );
        if let Err(e) = shared.push_control(&mut st, frame) {
            shared.fail(&mut st, e.clone());
            return Err(e);
        }
        shared.writer.notify_one();
        drop(st);
        Ok(MuxStream::new(shared, self.stream_id))
    }

    pub fn reject(mut self, failure: OpenFailure) {
        self.responded = true;
        reject_inner(&self.shared, self.stream_id, failure);
    }
}

fn reject_inner(shared: &Shared, id: u32, failure: OpenFailure) {
    let mut st = shared.lock();
    if st.closed.is_some() {
        return;
    }
    let opening = st
        .streams
        .get(&id)
        .is_some_and(|e| e.state == StreamState::Opening);
    if opening {
        st.streams.remove(&id);
        let frame = Frame::new(FrameType::OpenAck, id, OpenAck::Failure(failure).encode());
        if let Err(e) = shared.push_control(&mut st, frame) {
            shared.fail(&mut st, e);
        }
        shared.writer.notify_one();
    } else {
        if let Some(e) = st.streams.get_mut(&id) {
            e.handle_alive = false;
        }
        shared.try_remove(&mut st, id);
    }
}

impl Drop for IncomingOpen {
    fn drop(&mut self) {
        if !self.responded {
            reject_inner(&self.shared, self.stream_id, OpenFailure::Internal);
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

fn reserve(
    budget: &Arc<Budget>,
    cfg: &SessionConfig,
) -> Result<(Reservation, Reservation), SessionError> {
    let min = u64::from(cfg.stream_window) * 2;
    let rx = budget
        .try_reserve_range(min, u64::from(cfg.session_window), PoolClass::Receive)
        .map_err(|_| SessionError::Budget)?;
    let control_bytes = u64::from(cfg.max_frame_payload)
        + aegis_agp::HEADER_LEN as u64
        + (cfg.control_queue_frames as u64) * 32;
    let ctl = budget
        .try_reserve(control_bytes, PoolClass::Control)
        .map_err(|_| SessionError::Budget)?;
    Ok((rx, ctl))
}

async fn write_frame<T: AsyncWrite + Unpin>(io: &mut T, frame: &Frame) -> Result<(), SessionError> {
    let mut buf = BytesMut::new();
    encode_frame(&mut buf, frame)?;
    io.write_all(&buf)
        .await
        .map_err(|e| SessionError::Io(e.kind()))?;
    io.flush().await.map_err(|e| SessionError::Io(e.kind()))
}

async fn read_frame<T: AsyncRead + Unpin>(
    io: &mut T,
    decoder: &mut Decoder,
    buf: &mut BytesMut,
) -> Result<Frame, SessionError> {
    loop {
        if let Some(f) = decoder.decode(buf)? {
            return Ok(f);
        }
        let want = decoder.bytes_needed(buf.len()).max(4096);
        buf.reserve(want);
        let n = io
            .read_buf(buf)
            .await
            .map_err(|e| SessionError::Io(e.kind()))?;
        if n == 0 {
            return Err(SessionError::PeerClosed);
        }
    }
}

fn local_hello(cfg: &SessionConfig, window: u32, max_streams: u32) -> Hello {
    Hello {
        protocol_min: VERSION_MAJOR,
        protocol_max: VERSION_MAJOR,
        node_id: cfg.node_id.clone(),
        max_streams,
        initial_stream_window: cfg.stream_window,
        initial_session_window: window,
        max_frame_payload: cfg.max_frame_payload,
        features: Vec::new(),
    }
}

fn peer_info(h: &Hello) -> PeerInfo {
    PeerInfo {
        node_id: h.node_id.clone(),
        max_streams: h.max_streams,
        stream_window: h.initial_stream_window,
        session_window: h.initial_session_window,
        max_frame_payload: h.max_frame_payload,
        features: h.features.clone(),
    }
}

/// Client side: send HELLO, await HELLO_ACK. `io` is the authenticated inner
/// TLS stream; no OPEN/DATA is possible before this returns.
pub async fn client_handshake<T>(
    mut io: T,
    cfg: SessionConfig,
    budget: Arc<Budget>,
    obs: Arc<dyn Observability>,
) -> Result<Session, SessionError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    cfg.validate()
        .map_err(|_| SessionError::Protocol(ProtocolError::Violation("invalid session config")))?;
    let (rx_res, ctl_res) = reserve(&budget, &cfg)?;
    let window = rx_res.bytes() as u32;
    let max_streams = cfg.effective_max_streams(window);
    let hello = local_hello(&cfg, window, max_streams);
    let timeout = cfg.handshake_timeout;
    let mut decoder = Decoder::new(cfg.max_frame_payload);
    let mut buf = BytesMut::new();
    let ack = tokio::time::timeout(timeout, async {
        write_frame(&mut io, &Frame::new(FrameType::Hello, 0, hello.encode()?)).await?;
        let frame = read_frame(&mut io, &mut decoder, &mut buf).await?;
        if frame.frame_type != FrameType::HelloAck {
            return Err(SessionError::Protocol(ProtocolError::Violation(
                "expected HELLO_ACK",
            )));
        }
        let ack = Hello::decode(frame.payload)?;
        if cfg
            .expected_peer_node_id
            .as_ref()
            .is_some_and(|expected| expected != &ack.node_id)
        {
            return Err(SessionError::Protocol(ProtocolError::Violation(
                "HELLO_ACK identity mismatch",
            )));
        }
        if ack.protocol_min != VERSION_MAJOR || ack.protocol_max != VERSION_MAJOR {
            return Err(SessionError::Protocol(ProtocolError::UnsupportedVersion(
                ack.protocol_max,
            )));
        }
        if !ack.features.iter().all(|f| hello.features.contains(f)) {
            return Err(SessionError::Protocol(ProtocolError::Violation(
                "HELLO_ACK selected unoffered feature",
            )));
        }
        Ok(ack)
    })
    .await
    .map_err(|_| SessionError::HandshakeTimeout)??;
    let peer = peer_info(&ack);
    let (session, _) = start(
        io,
        decoder,
        buf,
        cfg,
        peer,
        true,
        budget,
        obs,
        rx_res,
        ctl_res,
        max_streams,
    );
    Ok(session)
}

/// Server side: await HELLO, verify the node identity matches the mTLS peer,
/// reserve receive capacity, reply HELLO_ACK.
pub async fn server_handshake<T>(
    mut io: T,
    cfg: SessionConfig,
    budget: Arc<Budget>,
    obs: Arc<dyn Observability>,
    authenticated_node_id: &str,
) -> Result<(Session, Incoming), SessionError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    cfg.validate()
        .map_err(|_| SessionError::Protocol(ProtocolError::Violation("invalid session config")))?;
    let timeout = cfg.handshake_timeout;
    let mut decoder = Decoder::new(cfg.max_frame_payload);
    let mut buf = BytesMut::new();
    let hello = tokio::time::timeout(timeout, async {
        let frame = read_frame(&mut io, &mut decoder, &mut buf).await?;
        if frame.frame_type != FrameType::Hello {
            return Err(SessionError::Protocol(ProtocolError::Violation(
                "expected HELLO",
            )));
        }
        Ok(Hello::decode(frame.payload)?)
    })
    .await
    .map_err(|_| SessionError::HandshakeTimeout)??;
    if hello.node_id != authenticated_node_id {
        return Err(SessionError::IdentityMismatch);
    }
    let (version, features) = hello.negotiate(&[])?;
    let (rx_res, ctl_res) = reserve(&budget, &cfg)?;
    let window = rx_res.bytes() as u32;
    let max_streams = cfg.effective_max_streams(window);
    let mut ack = local_hello(&cfg, window, max_streams);
    ack.protocol_min = version;
    ack.protocol_max = version;
    ack.features = features;
    tokio::time::timeout(
        timeout,
        write_frame(&mut io, &Frame::new(FrameType::HelloAck, 0, ack.encode()?)),
    )
    .await
    .map_err(|_| SessionError::HandshakeTimeout)??;
    let peer = peer_info(&hello);
    let (session, incoming) = start(
        io,
        decoder,
        buf,
        cfg,
        peer,
        false,
        budget,
        obs,
        rx_res,
        ctl_res,
        max_streams,
    );
    Ok((session, incoming.expect("server role always has incoming")))
}

#[allow(clippy::too_many_arguments)]
fn start<T>(
    io: T,
    decoder: Decoder,
    leftover: BytesMut,
    cfg: SessionConfig,
    peer: PeerInfo,
    is_client: bool,
    budget: Arc<Budget>,
    obs: Arc<dyn Observability>,
    rx_res: Reservation,
    ctl_res: Reservation,
    local_max_streams: u32,
) -> (Session, Option<Incoming>)
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (incoming_tx, incoming) = if is_client {
        (None, None)
    } else {
        let (tx, rx) = mpsc::channel(cfg.incoming_queue.max(1));
        (Some(tx), Some(Incoming { rx }))
    };
    let reserved = rx_res.bytes();
    let state = State {
        streams: HashMap::new(),
        ready: VecDeque::new(),
        control: VecDeque::new(),
        send_session_credit: u64::from(peer.session_window),
        recv_reserved: reserved,
        recv_outstanding: reserved,
        recv_buffered: 0,
        recv_pending_grant: 0,
        next_local_id: Some(1),
        last_peer_id: 0,
        goaway_sent: false,
        goaway_received: None,
        closed: None,
        final_frame: None,
        owner_dropped: false,
        last_rx: Instant::now(),
        ping_outstanding: None,
        ping_counter: 0,
        incoming_tx,
        _rx_reservation: rx_res,
        _control_reservation: ctl_res,
    };
    let (closed_tx, _) = watch::channel(false);
    let shared = Arc::new(Shared {
        state: Mutex::new(state),
        writer: Notify::new(),
        closed_tx,
        cfg,
        peer,
        is_client,
        budget,
        local_max_streams,
        obs,
    });
    shared.obs.record(Event::SessionOpened);
    let (rd, wr) = tokio::io::split(io);
    tokio::spawn(reader_task(Arc::clone(&shared), rd, decoder, leftover));
    tokio::spawn(writer_task(Arc::clone(&shared), wr));
    tokio::spawn(timer_task(Arc::clone(&shared)));
    (Session { shared }, incoming)
}

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

struct PingLimiter {
    tokens: f64,
    rate: f64,
    burst: f64,
    last: Instant,
}

impl PingLimiter {
    fn new(rate: u32) -> Self {
        let rate = f64::from(rate.max(1));
        PingLimiter {
            tokens: rate * 2.0,
            rate,
            burst: rate * 2.0,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn reader_task<R: AsyncRead + Unpin>(
    shared: Arc<Shared>,
    mut rd: R,
    mut decoder: Decoder,
    mut buf: BytesMut,
) {
    let mut closed_rx = shared.closed_tx.subscribe();
    let mut limiter = PingLimiter::new(shared.cfg.peer_ping_rate);
    loop {
        // Drain every complete frame already buffered.
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(frame)) => {
                    let mut st = shared.lock();
                    if st.closed.is_some() {
                        return;
                    }
                    st.last_rx = Instant::now();
                    st.ping_outstanding = None;
                    if let Err(e) = handle_frame(&shared, &mut st, frame, &mut limiter) {
                        shared.fail(&mut st, e);
                        return;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    let mut st = shared.lock();
                    shared.fail(&mut st, SessionError::Protocol(e));
                    return;
                }
            }
        }
        let want = decoder.bytes_needed(buf.len()).max(8192);
        buf.reserve(want);
        let read = tokio::select! {
            r = rd.read_buf(&mut buf) => r,
            _ = closed_rx.wait_for(|c| *c) => return,
        };
        match read {
            Ok(0) => {
                let mut st = shared.lock();
                shared.fail(&mut st, SessionError::PeerClosed);
                return;
            }
            Ok(n) => {
                shared.obs.record(Event::TransportBytes {
                    direction: aegis_contracts::observability::Direction::Down,
                    bytes: n as u64,
                });
            }
            Err(e) => {
                let mut st = shared.lock();
                shared.fail(&mut st, SessionError::Io(e.kind()));
                return;
            }
        }
    }
}

fn violation(what: &'static str) -> SessionError {
    SessionError::Protocol(ProtocolError::Violation(what))
}

fn handle_frame(
    shared: &Arc<Shared>,
    st: &mut State,
    frame: Frame,
    limiter: &mut PingLimiter,
) -> Result<(), SessionError> {
    let id = frame.stream_id;
    match frame.frame_type {
        FrameType::Hello | FrameType::HelloAck => Err(violation("duplicate handshake")),
        FrameType::Datagram => Err(violation("datagram not negotiated")),
        FrameType::Open => on_open(shared, st, id, frame.payload),
        FrameType::OpenAck => on_open_ack(shared, st, id, &frame.payload),
        FrameType::Data => on_data(shared, st, id, frame.payload),
        FrameType::HalfClose => on_half_close(shared, st, id),
        FrameType::Reset => on_reset(shared, st, id, frame.flags, &frame.payload),
        FrameType::WindowUpdate => on_window_update(shared, st, id, &frame.payload),
        FrameType::Ping => {
            if !limiter.allow() {
                return Err(SessionError::ControlOverload);
            }
            shared.push_control(st, Frame::new(FrameType::Pong, 0, frame.payload))?;
            shared.writer.notify_one();
            Ok(())
        }
        FrameType::Pong => {
            if !limiter.allow() {
                return Err(SessionError::ControlOverload);
            }
            Ok(())
        }
        FrameType::GoAway => {
            let g = GoAway::decode(frame.payload)?;
            st.goaway_received = Some(g.last_stream_id);
            if shared.is_client {
                // Streams the gateway never processed fail as unavailable.
                let unprocessed: Vec<u32> = st
                    .streams
                    .iter()
                    .filter(|(sid, e)| **sid > g.last_stream_id && e.state == StreamState::Opening)
                    .map(|(sid, _)| *sid)
                    .collect();
                for sid in unprocessed {
                    if let Some(mut e) = st.streams.remove(&sid) {
                        if let Some(w) = e.open_waiter.take() {
                            let _ = w.send(OpenAck::Failure(OpenFailure::Unavailable));
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

fn on_open(
    shared: &Arc<Shared>,
    st: &mut State,
    id: u32,
    payload: Bytes,
) -> Result<(), SessionError> {
    if shared.is_client {
        return Err(violation("gateway-initiated streams are not enabled"));
    }
    let expected = if st.last_peer_id == 0 {
        1
    } else {
        st.last_peer_id.wrapping_add(2)
    };
    if id != expected || id & 1 == 0 || (st.last_peer_id != 0 && id <= st.last_peer_id) {
        return Err(violation("stream id not monotonic by 2"));
    }
    st.last_peer_id = id;
    let request = OpenRequest::decode(payload)?;
    let reject = |st: &mut State, f: OpenFailure| -> Result<(), SessionError> {
        shared.push_control(
            st,
            Frame::new(FrameType::OpenAck, id, OpenAck::Failure(f).encode()),
        )?;
        shared.writer.notify_one();
        Ok(())
    };
    if st.goaway_sent {
        return reject(st, OpenFailure::Unavailable);
    }
    if st.streams.len() as u32 >= shared.local_max_streams {
        shared.obs.record(Event::ResourceThrottle {
            reason: aegis_contracts::ReasonGroup::Quota,
        });
        return reject(st, OpenFailure::Quota);
    }
    let Ok(reservation) = shared
        .budget
        .try_reserve(u64::from(shared.cfg.stream_tx_buffer), PoolClass::Transmit)
    else {
        shared.obs.record(Event::ResourceThrottle {
            reason: aegis_contracts::ReasonGroup::Quota,
        });
        return reject(st, OpenFailure::Quota);
    };
    let Some(tx) = st.incoming_tx.clone() else {
        return reject(st, OpenFailure::Unavailable);
    };
    let entry = Entry::new(
        StreamState::Opening,
        shared.cfg.stream_window,
        shared.peer.stream_window,
        shared.cfg.stream_tx_buffer as usize,
        reservation,
    );
    st.streams.insert(id, entry);
    let incoming = IncomingOpen {
        shared: Arc::clone(shared),
        stream_id: id,
        request,
        responded: false,
    };
    match tx.try_send(incoming) {
        Ok(()) => Ok(()),
        Err(err) => {
            let mut back = match err {
                mpsc::error::TrySendError::Full(v) | mpsc::error::TrySendError::Closed(v) => v,
            };
            // We hold the state lock: suppress Drop's re-entrant rejection
            // and reject inline instead.
            back.responded = true;
            st.streams.remove(&id);
            reject(st, OpenFailure::Quota)
        }
    }
}

fn on_open_ack(
    shared: &Arc<Shared>,
    st: &mut State,
    id: u32,
    payload: &[u8],
) -> Result<(), SessionError> {
    if !shared.is_client {
        return Err(violation("OPEN_ACK sent to gateway"));
    }
    let ack = OpenAck::decode(payload)?;
    let Some(e) = st.streams.get_mut(&id) else {
        return Err(violation("OPEN_ACK for unknown stream"));
    };
    match e.state {
        StreamState::Opening => {}
        // We reset it (e.g. timeout) before the ACK arrived; the RESET
        // exchange completes the stream.
        StreamState::Reset => return Ok(()),
        _ => return Err(violation("duplicate OPEN_ACK")),
    }
    match ack {
        OpenAck::Success => {
            e.state = StreamState::Established;
            let waiter = e.open_waiter.take();
            let delivered = waiter.is_some_and(|w| w.send(OpenAck::Success).is_ok());
            if !delivered {
                // Opener gave up; abort the now-established stream.
                e.handle_alive = false;
                shared.local_reset(st, id, ResetReason::Cancelled)?;
            }
        }
        OpenAck::Failure(f) => {
            let waiter = e.open_waiter.take();
            st.streams.remove(&id);
            if let Some(w) = waiter {
                let _ = w.send(OpenAck::Failure(f));
            }
            if st.owner_dropped && st.streams.is_empty() {
                shared.fail(st, SessionError::Closed(ResetReason::Shutdown));
            }
        }
    }
    Ok(())
}

fn on_data(
    shared: &Arc<Shared>,
    st: &mut State,
    id: u32,
    payload: Bytes,
) -> Result<(), SessionError> {
    let n = payload.len() as u32;
    let Some(e) = st.streams.get_mut(&id) else {
        return Err(violation("DATA for unknown or closed stream"));
    };
    if n > e.rx_outstanding || u64::from(n) > st.recv_outstanding {
        return Err(violation("DATA exceeds advertised credit"));
    }
    let discarding = matches!(e.reset, ResetPhase::AwaitingPeer { .. });
    if !discarding && !e.state.can_receive_data() {
        return Err(violation("DATA in invalid stream state"));
    }
    if e.remote_fin {
        return Err(violation("DATA after HALF_CLOSE"));
    }
    e.rx_outstanding -= n;
    st.recv_outstanding -= u64::from(n);
    if discarding {
        // Charged and discarded; capacity immediately backs session credit.
        st.recv_pending_grant += u64::from(n);
        shared.maybe_grant_session(st, false)?;
        shared.writer.notify_one();
        return Ok(());
    }
    if !e.rx.append(&payload) {
        return Err(violation("DATA exceeds receive buffer capacity"));
    }
    e.rx_buffered += n;
    if let Some(w) = e.read_waker.take() {
        w.wake();
    }
    st.recv_buffered += u64::from(n);
    Ok(())
}

fn on_half_close(shared: &Arc<Shared>, st: &mut State, id: u32) -> Result<(), SessionError> {
    let Some(e) = st.streams.get_mut(&id) else {
        return Err(violation("HALF_CLOSE for unknown stream"));
    };
    if matches!(e.reset, ResetPhase::AwaitingPeer { .. }) {
        // Crossed our RESET; ignore, the RESET exchange finishes the stream.
        return Ok(());
    }
    if e.remote_fin || !e.state.can_receive_data() {
        return Err(violation("invalid HALF_CLOSE direction"));
    }
    e.remote_fin = true;
    e.state = e
        .state
        .apply(aegis_contracts::state::StreamEvent::RemoteHalfClose)
        .map_err(|_| violation("invalid HALF_CLOSE transition"))?;
    // No more stream credit is needed for a finished direction.
    e.pending_grant = 0;
    if let Some(w) = e.read_waker.take() {
        w.wake();
    }
    shared.try_remove(st, id);
    Ok(())
}

fn on_reset(
    shared: &Arc<Shared>,
    st: &mut State,
    id: u32,
    flags: u16,
    payload: &[u8],
) -> Result<(), SessionError> {
    let reason = decode_reset(payload)?;
    let is_ack = flags & FLAG_RESET_ACK != 0;
    let Some(e) = st.streams.get_mut(&id) else {
        if !shared.previously_valid(st, id) {
            return Err(violation("RESET for never-opened stream"));
        }
        if !is_ack {
            // Late reset of a stream we already finished: still acknowledge.
            shared.push_control(
                st,
                Frame::new(FrameType::Reset, id, encode_reset(reason)).with_flags(FLAG_RESET_ACK),
            )?;
            shared.writer.notify_one();
        }
        return Ok(());
    };
    let awaiting = matches!(e.reset, ResetPhase::AwaitingPeer { .. });
    if is_ack {
        if !awaiting {
            return Err(violation("unsolicited RESET ACK"));
        }
        // Boundary established: no further peer DATA can arrive.
        e.reset = ResetPhase::None;
        shared.try_remove(st, id);
        return Ok(());
    }
    // Reset request from the peer.
    let waiter = e.open_waiter.take();
    e.state = StreamState::Reset;
    if e.reset_reason.is_none() {
        e.reset_reason = Some(reason);
    }
    e.reset = ResetPhase::None;
    e.tx.clear();
    e.fin_requested = false;
    e.wake_all();
    if let Some(w) = waiter {
        let _ = w.send(OpenAck::Failure(OpenFailure::Unavailable));
    }
    shared.discard_rx(st, id);
    st.ready.retain(|r| *r != id);
    // Acknowledge after any DATA already serialized; unsent DATA was dropped.
    shared.push_control(
        st,
        Frame::new(FrameType::Reset, id, encode_reset(reason)).with_flags(FLAG_RESET_ACK),
    )?;
    shared.maybe_grant_session(st, false)?;
    shared.writer.notify_one();
    shared.try_remove(st, id);
    Ok(())
}

fn on_window_update(
    shared: &Arc<Shared>,
    st: &mut State,
    id: u32,
    payload: &[u8],
) -> Result<(), SessionError> {
    let inc = u64::from(decode_window_update(payload)?);
    if id == 0 {
        let next = st.send_session_credit + inc;
        if next > u64::from(MAX_WINDOW) {
            return Err(violation("session window overflow"));
        }
        st.send_session_credit = next;
        shared.writer.notify_one();
        return Ok(());
    }
    let Some(e) = st.streams.get_mut(&id) else {
        if shared.previously_valid(st, id) {
            return Ok(()); // late update for a closed stream
        }
        return Err(violation("WINDOW_UPDATE for never-opened stream"));
    };
    let next = e.send_credit + inc;
    if next > u64::from(MAX_WINDOW) {
        return Err(violation("stream window overflow"));
    }
    e.send_credit = next;
    if !e.in_ready && (!e.tx.is_empty() || (e.fin_requested && !e.fin_sent)) {
        e.in_ready = true;
        st.ready.push_back(id);
    }
    shared.writer.notify_one();
    Ok(())
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

/// Assemble one batch: all queued control frames first, then DATA from ready
/// streams round-robin with a one-frame quantum.
fn assemble_batch(shared: &Shared, st: &mut State, out: &mut BytesMut) -> Result<(), SessionError> {
    while let Some(frame) = st.control.pop_front() {
        encode_frame(out, &frame)?;
        if out.len() >= WRITE_BATCH {
            return Ok(());
        }
    }
    if st.closed.is_some() {
        return Ok(());
    }
    let cap = shared.send_frame_cap();
    let mut visited = 0usize;
    let rounds = st.ready.len();
    while out.len() < WRITE_BATCH && visited < rounds.max(1) * 4 {
        let Some(id) = st.ready.pop_front() else {
            break;
        };
        visited += 1;
        let session_credit = st.send_session_credit;
        let Some(e) = st.streams.get_mut(&id) else {
            continue;
        };
        e.in_ready = false;
        if e.state.can_send_data() && !e.tx.is_empty() {
            let n = (e.tx.len() as u64)
                .min(e.send_credit)
                .min(session_credit)
                .min(cap as u64) as usize;
            if n == 0 {
                if e.send_credit > 0 && session_credit == 0 {
                    // Blocked on session credit: keep its place.
                    e.in_ready = true;
                    st.ready.push_front(id);
                    break;
                }
                // Blocked on stream credit: parked until WINDOW_UPDATE.
                continue;
            }
            let chunk = e.tx.split_to(n).freeze();
            e.send_credit -= n as u64;
            st.send_session_credit -= n as u64;
            encode_frame(out, &Frame::new(FrameType::Data, id, chunk))?;
            if let Some(w) = e.write_waker.take() {
                w.wake();
            }
        }
        if e.tx.is_empty() && e.fin_requested && !e.fin_sent && e.state.can_send_data() {
            encode_frame(out, &Frame::new(FrameType::HalfClose, id, Bytes::new()))?;
            e.fin_sent = true;
            e.state = e
                .state
                .apply(aegis_contracts::state::StreamEvent::LocalHalfClose)
                .unwrap_or(StreamState::Reset);
            if let Some(w) = e.write_waker.take() {
                w.wake();
            }
            let id_done = id;
            shared.try_remove(st, id_done);
            continue;
        }
        if !e.tx.is_empty() && e.send_credit > 0 && !e.in_ready {
            e.in_ready = true;
            st.ready.push_back(id);
        }
    }
    Ok(())
}

async fn writer_task<W: AsyncWrite + Unpin>(shared: Arc<Shared>, mut wr: W) {
    let mut out = BytesMut::with_capacity(WRITE_BATCH + aegis_agp::MAX_FRAME_LEN);
    let mut closed_rx = shared.closed_tx.subscribe();
    loop {
        out.clear();
        let finished = {
            let mut st = shared.lock();
            if let Err(e) = assemble_batch(&shared, &mut st, &mut out) {
                shared.fail(&mut st, e);
            }
            if st.closed.is_some() {
                if let Some(f) = st.final_frame.take() {
                    let _ = encode_frame(&mut out, &f);
                }
                true
            } else {
                false
            }
        };
        if finished {
            // A final GOAWAY is best-effort. Bound the entire operation,
            // including its write/flush, rather than just shutdown.
            let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
                wr.write_all(&out).await?;
                wr.flush().await?;
                wr.shutdown().await
            })
            .await;
            return;
        }
        if !out.is_empty() {
            let res = tokio::select! {
                // Preserve a complete ready write before observing closure.
                // If it stalls, cancellation drops the transport immediately:
                // appending GOAWAY after a partially written frame is unsafe.
                biased;
                r = tokio::time::timeout(shared.cfg.keepalive_timeout, async {
                    wr.write_all(&out).await?;
                    wr.flush().await
                }) => r,
                _ = closed_rx.wait_for(|c| *c) => return,
            };
            match res {
                Ok(Ok(())) => shared.obs.record(Event::TransportBytes {
                    direction: aegis_contracts::observability::Direction::Up,
                    bytes: out.len() as u64,
                }),
                Ok(Err(e)) => {
                    let mut st = shared.lock();
                    shared.fail(&mut st, SessionError::Io(e.kind()));
                    return;
                }
                Err(_) => {
                    let mut st = shared.lock();
                    shared.fail(&mut st, SessionError::WriteTimeout);
                    return;
                }
            }
        }
        if out.is_empty() {
            shared.writer.notified().await;
        }
    }
}

// ---------------------------------------------------------------------------
// Timers: keepalive and reset-drain deadlines
// ---------------------------------------------------------------------------

async fn timer_task(shared: Arc<Shared>) {
    let mut closed_rx = shared.closed_tx.subscribe();
    let mut tick = tokio::time::interval(TIMER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = closed_rx.wait_for(|c| *c) => return,
        }
        let mut st = shared.lock();
        if st.closed.is_some() {
            return;
        }
        let now = Instant::now();
        let expired = st
            .streams
            .values()
            .any(|e| matches!(e.reset, ResetPhase::AwaitingPeer { deadline } if deadline <= now));
        if expired {
            shared.fail(&mut st, SessionError::ResetDrainTimeout);
            return;
        }
        if let Some(sent) = st.ping_outstanding {
            if now.duration_since(sent) >= shared.cfg.keepalive_timeout {
                shared.fail(&mut st, SessionError::KeepaliveTimeout);
                return;
            }
        } else if now.duration_since(st.last_rx) >= shared.cfg.keepalive_interval {
            st.ping_counter += 1;
            let payload = Bytes::copy_from_slice(&st.ping_counter.to_be_bytes());
            if let Err(e) = shared.push_control(&mut st, Frame::new(FrameType::Ping, 0, payload)) {
                shared.fail(&mut st, e);
                return;
            }
            st.ping_outstanding = Some(now);
            shared.writer.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_streams_reserve_working_share() {
        let cfg = SessionConfig::default();
        assert_eq!(cfg.effective_max_streams(2 * 1024 * 1024), 31);
        assert_eq!(cfg.effective_max_streams(128 * 1024), 1);
        let small = SessionConfig {
            max_streams: 4,
            ..SessionConfig::default()
        };
        assert_eq!(small.effective_max_streams(2 * 1024 * 1024), 4);
    }
}
