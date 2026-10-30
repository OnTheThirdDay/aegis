//! Byte-duplex view of a WebSocket.
//!
//! * Reads: binary message payloads concatenated in order. Text messages are
//!   a protocol error. Control frames are handled by tungstenite.
//! * Writes: each `poll_write` becomes one binary message (≤ 64 KiB).
//! * Flush: flushes the WebSocket sink. Shutdown: sends a Close frame.
//! * Cancellation: dropping the duplex drops the TCP connection.
//!
//! Padded framing (when both ends announced it in the upgrade): every
//! message is `[u16 payload length][payload][padding]`. The first writes of
//! a connection, which carry the inner TLS handshake, are split into
//! random-sized pieces and padded by random amounts, so their sizes no
//! longer match a TLS handshake's (the TLS-in-TLS pattern). Messages with
//! an empty payload are padding only.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{Sink, Stream};
use rand::Rng;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::{Error as WsProtoError, Message};
use tokio_tungstenite::WebSocketStream;

const MAX_WRITE_MESSAGE: usize = 64 * 1024;

/// Writes shaped at the start of a padded connection: the inner TLS
/// handshake and the session's opening frames, in either direction.
const SHAPED_WRITES: u32 = 16;
/// Payload of a shaped write, at most (larger writes are split).
const SHAPED_PIECE: std::ops::RangeInclusive<usize> = 200..=1400;
/// Padding added to a shaped write.
const SHAPED_PAD: std::ops::RangeInclusive<usize> = 32..=1024;
/// Payload of a padded message: what its length prefix can say.
const MAX_PADDED_PAYLOAD: usize = MAX_WRITE_MESSAGE - 2;

pub struct WsDuplex<S> {
    inner: WebSocketStream<S>,
    pending: Bytes,
    eof: bool,
    /// Padded framing: shaped writes left. `None`: plain messages.
    shaped: Option<u32>,
}

impl<S> WsDuplex<S> {
    pub(crate) fn new(inner: WebSocketStream<S>, padded: bool) -> Self {
        WsDuplex {
            inner,
            pending: Bytes::new(),
            eof: false,
            shaped: padded.then_some(SHAPED_WRITES),
        }
    }

    /// Whether both ends use padded framing.
    pub fn is_padded(&self) -> bool {
        self.shaped.is_some()
    }
}

/// The payload of a padded message (empty for padding only).
fn unpad(mut data: Bytes) -> io::Result<Bytes> {
    if data.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "padded message without a length",
        ));
    }
    let n = usize::from(data.get_u16());
    if n > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "padded message shorter than its length",
        ));
    }
    Ok(data.split_to(n))
}

/// One padded message carrying `payload`, with `pad` bytes of padding.
fn padded(payload: &[u8], pad: usize) -> Bytes {
    let mut m = BytesMut::with_capacity(2 + payload.len() + pad);
    m.put_u16(u16::try_from(payload.len()).unwrap_or(u16::MAX));
    m.put_slice(payload);
    m.put_bytes(0, pad);
    m.freeze()
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
                Some(Ok(Message::Binary(data))) => {
                    this.pending = match this.shaped {
                        Some(_) => unpad(data)?,
                        None => data,
                    }
                }
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
        let (n, message) = match this.shaped.as_mut() {
            None => {
                let n = buf.len().min(MAX_WRITE_MESSAGE);
                (n, Bytes::copy_from_slice(&buf[..n]))
            }
            Some(0) => {
                let n = buf.len().min(MAX_PADDED_PAYLOAD);
                (n, padded(&buf[..n], 0))
            }
            Some(left) => {
                *left -= 1;
                let mut rng = rand::thread_rng();
                let n = buf.len().min(rng.gen_range(SHAPED_PIECE));
                (n, padded(&buf[..n], rng.gen_range(SHAPED_PAD)))
            }
        };
        Pin::new(&mut this.inner)
            .start_send(Message::Binary(message))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padded_messages_carry_their_payload() {
        let m = padded(b"hello", 100);
        assert_eq!(m.len(), 107);
        assert_eq!(&unpad(m).expect("unpad")[..], b"hello");
        assert!(unpad(padded(b"", 50)).expect("unpad").is_empty());
        assert!(unpad(Bytes::from_static(&[0])).is_err());
        assert!(unpad(Bytes::from_static(&[0, 9, 1, 2])).is_err());
    }
}
