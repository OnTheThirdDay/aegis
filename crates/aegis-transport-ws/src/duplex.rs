//! Byte-duplex view of a WebSocket.
//!
//! * Reads: binary message payloads concatenated in order. Text messages are
//!   a protocol error. Control frames are handled by tungstenite.
//! * Writes: each `poll_write` becomes one binary message (≤ 64 KiB).
//! * Flush: flushes the WebSocket sink. Shutdown: sends a Close frame.
//! * Cancellation: dropping the duplex drops the TCP connection.

use bytes::{Buf, Bytes};
use futures_util::{Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{Error as WsProtoError, Message};
use tokio_tungstenite::WebSocketStream;

const MAX_WRITE_MESSAGE: usize = 64 * 1024;

pub struct WsDuplex<S> {
    inner: WebSocketStream<S>,
    pending: Bytes,
    eof: bool,
}

impl<S> WsDuplex<S> {
    pub(crate) fn new(inner: WebSocketStream<S>) -> Self {
        WsDuplex {
            inner,
            pending: Bytes::new(),
            eof: false,
        }
    }
}

fn to_io(e: WsProtoError) -> io::Error {
    match e {
        WsProtoError::Io(e) => e,
        WsProtoError::ConnectionClosed | WsProtoError::AlreadyClosed => {
            io::Error::new(io::ErrorKind::BrokenPipe, "websocket closed")
        }
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

impl<S> AsyncRead for WsDuplex<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut this.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(data))) => this.pending = data,
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text message on binary transport",
                    )))
                }
                Some(Ok(Message::Close(_))) | None => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(WsProtoError::ConnectionClosed)) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(Err(e)) => return Poll::Ready(Err(to_io(e))),
            }
        }
    }
}

impl<S> AsyncWrite for WsDuplex<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(to_io)?;
        let n = buf.len().min(MAX_WRITE_MESSAGE);
        Pin::new(&mut this.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(&buf[..n])))
            .map_err(to_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(to_io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(Pin::new(&mut self.get_mut().inner).poll_close(cx)) {
            Ok(()) | Err(WsProtoError::ConnectionClosed) | Err(WsProtoError::AlreadyClosed) => {
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(to_io(e))),
        }
    }
}
