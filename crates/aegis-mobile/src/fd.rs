//! The VPN interface's file descriptor as an async packet device: each read
//! returns one IP packet, each write sends one.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TunDevice {
    fd: AsyncFd<File>,
}

impl TunDevice {
    /// Take ownership of `fd` (closed when the device is dropped). Call it
    /// inside the Tokio runtime.
    ///
    /// The caller must pass a valid descriptor it no longer uses (Android:
    /// `ParcelFileDescriptor.detachFd()`).
    #[allow(unsafe_code)]
    pub fn new(fd: RawFd) -> io::Result<TunDevice> {
        if fd < 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        // SAFETY: the caller hands over a valid, otherwise unused descriptor;
        // the File becomes its only owner.
        let file = unsafe { File::from_raw_fd(fd) };
        // SAFETY: fcntl on a descriptor we own, with standard flags.
        let ok = unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the File owns the descriptor, which stays open and the same
        // until the AsyncFd (and with it the File) is dropped.
        let fd = unsafe { AsyncFd::register(file) }.map_err(io::Error::from)?;
        Ok(TunDevice { fd })
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            match guard.try_io(|f| f.get_ref().read(buf.initialize_unfilled())) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|f| f.get_ref().write(buf)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
