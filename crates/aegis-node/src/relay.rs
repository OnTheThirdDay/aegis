//! Bidirectional relay with half-close propagation, idle timeout and an
//! authoritative active-stream gauge.

use aegis_contracts::observability::{Event, Observability, OperationResult};
use aegis_contracts::reason::{ReasonGroup, ResetReason};
use aegis_session::MuxStream;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// Either side of a relay.
pub enum Upstream {
    Tcp(TcpStream),
    Mux(MuxStream),
}

impl AsyncRead for Upstream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Upstream::Mux(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Upstream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Upstream::Mux(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Upstream::Mux(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Upstream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Upstream::Mux(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Wrapper recording the last time any byte moved.
struct Tracked<'a, S> {
    inner: &'a mut S,
    last: &'a AtomicU64,
    epoch: Instant,
}

impl<S> Tracked<'_, S> {
    fn touch(&self) {
        self.last
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            this.touch();
        }
        r
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if matches!(r, Poll::Ready(Ok(n)) if n > 0) {
            this.touch();
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

/// RAII active-stream counter: the gauge is authoritative, not
/// reconstructed from events.
pub struct ActiveGuard(Arc<AtomicU64>);

impl ActiveGuard {
    pub fn new(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        ActiveGuard(Arc::clone(counter))
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOutcome {
    Completed,
    IdleTimeout,
    Error(io::ErrorKind),
}

/// Relay until both directions finish (half-close aware), an error occurs,
/// or the connection is idle for `idle`.
pub async fn relay<A, B>(a: &mut A, b: &mut B, idle: Duration) -> RelayOutcome
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let last = AtomicU64::new(0);
    let epoch = Instant::now();
    let mut ta = Tracked {
        inner: a,
        last: &last,
        epoch,
    };
    let mut tb = Tracked {
        inner: b,
        last: &last,
        epoch,
    };
    let watchdog = async {
        let tick = (idle / 4).max(Duration::from_millis(50));
        loop {
            tokio::time::sleep(tick).await;
            let since =
                (epoch.elapsed().as_millis() as u64).saturating_sub(last.load(Ordering::Relaxed));
            if since >= idle.as_millis() as u64 {
                return;
            }
        }
    };
    tokio::select! {
        r = tokio::io::copy_bidirectional(&mut ta, &mut tb) => match r {
            Ok(_) => RelayOutcome::Completed,
            Err(e) => RelayOutcome::Error(e.kind()),
        },
        _ = watchdog => RelayOutcome::IdleTimeout,
    }
}

/// Finish a relayed logical stream: on failure the AGP side is reset with a
/// specific reason (never reported as clean success); record the outcome.
pub fn finish_mux(mux: MuxStream, outcome: RelayOutcome, obs: &dyn Observability) {
    let (result, reason) = match outcome {
        RelayOutcome::Completed => (OperationResult::Ok, ReasonGroup::Other),
        RelayOutcome::IdleTimeout => {
            mux.reset(ResetReason::Timeout);
            (OperationResult::Timeout, ReasonGroup::Timeout)
        }
        RelayOutcome::Error(_) => {
            mux.reset(ResetReason::DestinationReset);
            (OperationResult::Error, ReasonGroup::Transport)
        }
    };
    obs.record(Event::StreamClosed { result, reason });
}
