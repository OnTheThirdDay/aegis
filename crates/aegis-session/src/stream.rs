//! Logical stream handle.
//!
//! Semantics (documented per 02 §4 for `BoxedDuplexStream`):
//! * `poll_write` copies into a bounded per-stream TX buffer; it returns
//!   `Pending` when the buffer is full (backpressure from peer credit).
//! * `poll_flush` completes when every byte has been serialized to the
//!   ordered transport (not when the peer has read it).
//! * `poll_shutdown` sends HALF_CLOSE after all buffered data and completes
//!   once it is serialized; reading may continue (TCP write shutdown).
//! * Dropping a stream that is not fully closed sends RESET (cancellation),
//!   which is never reported as success to the peer.
//! * A peer RESET surfaces as `ConnectionReset` on both read and write.

use crate::mux::Shared;
use aegis_contracts::reason::ResetReason;
use aegis_contracts::state::StreamState;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct MuxStream {
    shared: Arc<Shared>,
    id: u32,
    /// Reason sent if this handle is dropped before the stream fully closed.
    drop_reason: ResetReason,
}

impl std::fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MuxStream").field("id", &self.id).finish()
    }
}

pub(crate) fn reset_err(reason: Option<ResetReason>) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionReset,
        format!("stream reset ({reason:?})"),
    )
}

pub(crate) fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, "session closed")
}

impl MuxStream {
    pub(crate) fn new(shared: Arc<Shared>, id: u32) -> Self {
        MuxStream {
            shared,
            id,
            drop_reason: ResetReason::Cancelled,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Abort the stream with an explicit reason (RESET request). Has no
    /// effect on a stream that already closed cleanly.
    pub fn reset(mut self, reason: ResetReason) {
        self.drop_reason = reason;
        let mut st = self.shared.lock();
        if let Some(e) = st.streams.get_mut(&self.id) {
            if !e.state.is_terminal() {
                // Force the non-graceful path in Drop.
                e.fin_requested = false;
            }
        }
    }

    /// Current state (for diagnostics and tests).
    pub fn state(&self) -> Option<StreamState> {
        self.shared.lock().streams.get(&self.id).map(|e| e.state)
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let this = self.get_mut();
        let shared = Arc::clone(&this.shared);
        let mut st = shared.lock();
        let closed = st.closed.is_some();
        let Some(e) = st.streams.get_mut(&this.id) else {
            return Poll::Ready(Err(reset_err(None)));
        };
        if e.state == StreamState::Reset {
            return Poll::Ready(Err(reset_err(e.reset_reason)));
        }
        let n = e.rx.read_into(buf);
        if n > 0 {
            if let Err(err) = shared.on_consumed(&mut st, this.id, n as u32) {
                shared.fail(&mut st, err);
            }
            return Poll::Ready(Ok(()));
        }
        if e.remote_fin {
            return Poll::Ready(Ok(())); // EOF
        }
        if closed {
            return Poll::Ready(Err(closed_err()));
        }
        e.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let shared = Arc::clone(&this.shared);
        let mut st = shared.lock();
        if st.closed.is_some() {
            return Poll::Ready(Err(closed_err()));
        }
        let Some(e) = st.streams.get_mut(&this.id) else {
            return Poll::Ready(Err(reset_err(None)));
        };
        if e.state == StreamState::Reset {
            return Poll::Ready(Err(reset_err(e.reset_reason)));
        }
        if e.fin_requested || !e.state.can_send_data() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "write after shutdown",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Reserve transmit memory as it is needed, up to the cap; the
        // initial reservation always leaves room, so writes progress.
        let want = (e.tx.len() + buf.len()).min(e.tx_cap) as u64;
        let held = e.tx_reservation.bytes();
        if want > held {
            let _ = e.tx_reservation.try_grow(want - held);
        }
        let space = (e.tx_reservation.bytes() as usize)
            .min(e.tx_cap)
            .saturating_sub(e.tx.len());
        if space == 0 {
            e.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(buf.len());
        e.tx.extend_from_slice(&buf[..n]);
        if !e.in_ready && e.send_credit > 0 {
            e.in_ready = true;
            st.ready.push_back(this.id);
        }
        shared.writer.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut st = this.shared.lock();
        let closed = st.closed.is_some();
        let Some(e) = st.streams.get_mut(&this.id) else {
            return Poll::Ready(Err(reset_err(None)));
        };
        if e.state == StreamState::Reset {
            return Poll::Ready(Err(reset_err(e.reset_reason)));
        }
        if e.tx.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if closed {
            return Poll::Ready(Err(closed_err()));
        }
        e.write_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let shared = Arc::clone(&this.shared);
        let mut st = shared.lock();
        let closed = st.closed.is_some();
        let Some(e) = st.streams.get_mut(&this.id) else {
            return Poll::Ready(Err(reset_err(None)));
        };
        if e.state == StreamState::Reset {
            return Poll::Ready(Err(reset_err(e.reset_reason)));
        }
        if e.fin_sent {
            return Poll::Ready(Ok(()));
        }
        if closed {
            return Poll::Ready(Err(closed_err()));
        }
        if !e.state.can_send_data() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "stream not open",
            )));
        }
        e.fin_requested = true;
        e.write_waker = Some(cx.waker().clone());
        if !e.in_ready {
            e.in_ready = true;
            st.ready.push_back(this.id);
        }
        shared.writer.notify_one();
        Poll::Pending
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        let Some(e) = st.streams.get_mut(&self.id) else {
            return;
        };
        e.handle_alive = false;
        e.read_waker = None;
        e.write_waker = None;
        let graceful = match e.state {
            StreamState::Closed | StreamState::Reset => true,
            // Our FIN is queued behind data and the peer already finished:
            // let the writer deliver it, then the entry is removed.
            StreamState::RemoteHalfClosed => e.fin_requested,
            _ => false,
        };
        if !graceful && st.closed.is_none() {
            if let Err(err) = shared.local_reset(&mut st, self.id, self.drop_reason) {
                shared.fail(&mut st, err);
            }
        }
        shared.try_remove(&mut st, self.id);
        if st.closed.is_some() {
            shared.remove_entry(&mut st, self.id);
        }
    }
}
