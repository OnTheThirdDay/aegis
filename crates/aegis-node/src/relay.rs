//! Bidirectional relay with half-close propagation, idle timeout and an
//! authoritative active-stream gauge; and the datagram relay of UDP flows.

use aegis_contracts::observability::{Event, Observability, OperationResult};
use aegis_contracts::reason::{ReasonGroup, ResetReason};
use aegis_session::{DatagramFlow, MuxStream};
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

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

/// How long a UDP flow lives without a datagram in either direction. UDP has
/// no close; QUIC and other UDP protocols send keepalives well within this.
pub const UDP_IDLE: Duration = Duration::from_secs(120);

/// Room for the largest UDP datagram.
const UDP_BUFFER: usize = 64 * 1024;

/// The far end of a UDP flow: the tunnel, or a direct socket.
pub enum DatagramUpstream {
    Flow(DatagramFlow),
    Socket(UdpSocket),
}

impl DatagramUpstream {
    /// Send one datagram. Loss (a full queue, no route) is not an error;
    /// a flow that ended is.
    pub async fn send(&self, datagram: &[u8]) -> io::Result<()> {
        match self {
            DatagramUpstream::Flow(f) => f.send(datagram).map(|_| ()),
            DatagramUpstream::Socket(s) => {
                let _ = s.send(datagram).await;
                Ok(())
            }
        }
    }

    /// The next datagram from the destination.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Bytes> {
        match self {
            DatagramUpstream::Flow(f) => f.recv().await,
            DatagramUpstream::Socket(s) => loop {
                match s.recv(buf).await {
                    Ok(n) => return Ok(Bytes::copy_from_slice(&buf[..n])),
                    // An ICMP error reported on the connected socket: the
                    // destination dropped a datagram, nothing more.
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                    Err(e) => return Err(e),
                }
            },
        }
    }
}

/// Relay a gateway UDP flow and its egress socket until the flow ends, the
/// socket fails, or nothing moved for `idle`.
pub async fn relay_datagrams(
    flow: &DatagramFlow,
    socket: &UdpSocket,
    idle: Duration,
) -> RelayOutcome {
    let mut buf = vec![0u8; UDP_BUFFER];
    let mut deadline = tokio::time::Instant::now() + idle;
    loop {
        tokio::select! {
            d = flow.recv() => match d {
                Ok(d) => {
                    deadline = tokio::time::Instant::now() + idle;
                    // A send that fails (no route) loses the datagram.
                    let _ = socket.send(&d).await;
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                    return RelayOutcome::Completed
                }
                Err(e) => return RelayOutcome::Error(e.kind()),
            },
            r = socket.recv(&mut buf) => match r {
                Ok(n) => {
                    deadline = tokio::time::Instant::now() + idle;
                    // Larger than the tunnel carries: dropped, like any
                    // datagram a path can't fit.
                    if n <= flow.max_datagram() {
                        if let Err(e) = flow.send(&buf[..n]) {
                            return RelayOutcome::Error(e.kind());
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
                Err(e) => return RelayOutcome::Error(e.kind()),
            },
            _ = tokio::time::sleep_until(deadline) => return RelayOutcome::IdleTimeout,
        }
    }
}

/// Finish a UDP flow like [`finish_mux`]: idle flows end with a timeout
/// RESET, failed ones with a destination RESET.
pub fn finish_flow(flow: DatagramFlow, outcome: RelayOutcome, obs: &dyn Observability) {
    let (result, reason) = match outcome {
        RelayOutcome::Completed => (OperationResult::Ok, ReasonGroup::Other),
        RelayOutcome::IdleTimeout => {
            flow.reset(ResetReason::Timeout);
            (OperationResult::Timeout, ReasonGroup::Timeout)
        }
        RelayOutcome::Error(_) => {
            flow.reset(ResetReason::DestinationReset);
            (OperationResult::Error, ReasonGroup::Transport)
        }
    };
    obs.record(Event::StreamClosed { result, reason });
}
