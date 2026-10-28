//! UDP flow handle (feature 0x0001).
//!
//! A flow carries whole datagrams to and from one destination:
//! * [`DatagramFlow::send`] queues one datagram for the writer, or drops it
//!   when the session's datagram send buffer is full (UDP semantics: loss,
//!   never backpressure on the sender);
//! * [`DatagramFlow::recv`] yields received datagrams in arrival order; a
//!   reader that falls behind loses the newest ones;
//! * a flow has no half-close: dropping the handle (or [`reset`]) sends
//!   RESET, and a peer RESET surfaces as `ConnectionReset`.
//!
//! [`reset`]: DatagramFlow::reset

use crate::mux::Shared;
use crate::stream::{closed_err, reset_err};
use aegis_contracts::reason::ResetReason;
use aegis_contracts::state::StreamState;
use bytes::Bytes;
use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct DatagramFlow {
    shared: Arc<Shared>,
    id: u32,
    /// Reason sent when this handle is dropped.
    drop_reason: ResetReason,
}

impl std::fmt::Debug for DatagramFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramFlow")
            .field("id", &self.id)
            .finish()
    }
}

impl DatagramFlow {
    pub(crate) fn new(shared: Arc<Shared>, id: u32) -> Self {
        DatagramFlow {
            shared,
            id,
            drop_reason: ResetReason::Cancelled,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    /// Largest datagram this flow carries (the negotiated frame cap).
    pub fn max_datagram(&self) -> usize {
        self.shared.send_frame_cap()
    }

    /// Queue one datagram. `Ok(false)` means it was dropped: empty, or the
    /// send buffer is full. Larger than [`max_datagram`](Self::max_datagram)
    /// is an `InvalidInput` error; a closed flow or session is an error too.
    pub fn send(&self, datagram: &[u8]) -> io::Result<bool> {
        let shared = &self.shared;
        let mut st = shared.lock();
        let st = &mut *st;
        if st.closed.is_some() {
            return Err(closed_err());
        }
        let Some(e) = st.streams.get(&self.id) else {
            return Err(reset_err(None));
        };
        if e.state == StreamState::Reset {
            return Err(reset_err(e.reset_reason));
        }
        if datagram.len() > shared.send_frame_cap() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "datagram larger than the tunnel carries",
            ));
        }
        if datagram.is_empty()
            || st.dgram_tx_bytes + datagram.len() > shared.cfg.datagram_send_buffer as usize
        {
            st.dgram_dropped += 1;
            return Ok(false);
        }
        st.dgram_tx_bytes += datagram.len();
        st.dgram_tx
            .push_back((self.id, Bytes::copy_from_slice(datagram)));
        shared.writer.notify_one();
        Ok(true)
    }

    /// The next datagram from the destination.
    pub async fn recv(&self) -> io::Result<Bytes> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
        let mut st = self.shared.lock();
        let st = &mut *st;
        let closed = st.closed.is_some();
        let Some(e) = st.streams.get_mut(&self.id) else {
            return Poll::Ready(Err(reset_err(None)));
        };
        if let Some(d) = e.datagrams.pop_front() {
            st.dgram_rx_bytes -= d.len();
            return Poll::Ready(Ok(d));
        }
        if e.state == StreamState::Reset {
            return Poll::Ready(Err(reset_err(e.reset_reason)));
        }
        if closed {
            return Poll::Ready(Err(closed_err()));
        }
        e.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// End the flow with an explicit reason (RESET request).
    pub fn reset(mut self, reason: ResetReason) {
        self.drop_reason = reason;
    }
}

impl Drop for DatagramFlow {
    fn drop(&mut self) {
        let shared = Arc::clone(&self.shared);
        let mut st = shared.lock();
        let Some(e) = st.streams.get_mut(&self.id) else {
            return;
        };
        e.handle_alive = false;
        e.read_waker = None;
        // A flow only ends by RESET; one already reset needs nothing more.
        if !e.state.is_terminal() && st.closed.is_none() {
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
