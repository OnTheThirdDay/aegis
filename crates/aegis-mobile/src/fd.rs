//! The VPN interface's file descriptor as an async packet device: each read
//! returns one IP packet, each write sends one.
//!
//! Android's descriptor carries bare packets. Apple's utun (the iOS packet
//! tunnel's interface) puts a 4-byte address family in front of each one,
//! which [`TunDevice::utun`] removes and adds.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TunDevice {
    fd: AsyncFd<File>,
    /// utun: each packet is preceded by its address family (4 bytes, big
    /// endian).
    framed: bool,
}

/// The utun header's address families (Darwin's AF_INET, AF_INET6).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const HEADER: usize = 4;

impl TunDevice {
    /// Take ownership of `fd` (closed when the device is dropped). Call it
    /// inside the Tokio runtime.
    ///
    /// The caller must pass a valid descriptor it no longer uses (Android:
    /// `ParcelFileDescriptor.detachFd()`).
    pub fn new(fd: RawFd) -> io::Result<TunDevice> {
        Self::open(fd, false)
    }

    /// A utun descriptor (Apple), whose packets carry an address family.
    /// The same ownership rules as [`TunDevice::new`] apply.
    pub fn utun(fd: RawFd) -> io::Result<TunDevice> {
        Self::open(fd, true)
    }

    #[allow(unsafe_code)]
    fn open(fd: RawFd, framed: bool) -> io::Result<TunDevice> {
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
        Ok(TunDevice { fd, framed })
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
            if self.framed {
                let mut packet = vec![0u8; buf.remaining() + HEADER];
                match guard.try_io(|f| f.get_ref().read(&mut packet)) {
                    Ok(Ok(n)) if n > HEADER => {
                        buf.put_slice(&packet[HEADER..n]);
                        return Poll::Ready(Ok(()));
                    }
                    // A header alone carries nothing: read the next one.
                    Ok(Ok(n)) if n > 0 => continue,
                    Ok(Ok(_)) => return Poll::Ready(Ok(())),
                    Ok(Err(e)) => return Poll::Ready(Err(e)),
                    Err(_would_block) => continue,
                }
            }
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
        let framed = self.framed.then(|| frame(buf));
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            let written = match &framed {
                Some(packet) => guard.try_io(|f| {
                    f.get_ref()
                        .write(packet)
                        .map(|n| n.saturating_sub(HEADER).min(buf.len()))
                }),
                None => guard.try_io(|f| f.get_ref().write(buf)),
            };
            match written {
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

/// `packet` behind the utun header for its IP version.
fn frame(packet: &[u8]) -> Vec<u8> {
    let family = match packet.first().map(|b| b >> 4) {
        Some(6) => AF_INET6,
        _ => AF_INET,
    };
    let mut out = Vec::with_capacity(packet.len() + HEADER);
    out.extend_from_slice(&[0, 0, 0, family]);
    out.extend_from_slice(packet);
    out
}

/// The packet tunnel's utun descriptor in this process (iOS: the system
/// opened it for the extension and doesn't hand it over). A utun control
/// socket answers `UTUN_OPT_IFNAME` with its interface name.
#[cfg(target_vendor = "apple")]
#[allow(unsafe_code)]
pub fn find_utun() -> Option<RawFd> {
    // <sys/kern_control.h>, <net/if_utun.h>
    const SYSPROTO_CONTROL: libc::c_int = 2;
    const UTUN_OPT_IFNAME: libc::c_int = 2;
    (0..1024).find(|&fd| {
        let mut name = [0u8; 32];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: getsockopt writes at most `len` bytes into `name`, which
        // outlives the call; an fd that isn't a utun socket only fails.
        let ok = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr().cast(),
                &mut len,
            )
        } == 0;
        ok && name.starts_with(b"utun")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn utun_headers_name_the_ip_version() {
        assert_eq!(frame(&[0x45, 1, 2])[..4], [0, 0, 0, AF_INET]);
        assert_eq!(frame(&[0x60, 1, 2])[..4], [0, 0, 0, AF_INET6]);
        assert_eq!(&frame(&[0x45, 1, 2])[4..], &[0x45, 1, 2]);
    }

    #[tokio::test]
    async fn a_utun_device_strips_and_adds_the_header() {
        use std::os::fd::IntoRawFd;
        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair().expect("pair");
        let mut dev = TunDevice::utun(ours.into_raw_fd()).expect("device");
        theirs.send(&[0, 0, 0, AF_INET, 0x45, 9, 9]).expect("send");
        let mut buf = [0u8; 64];
        let n = dev.read(&mut buf).await.expect("read");
        assert_eq!(&buf[..n], &[0x45, 9, 9]);
        dev.write_all(&[0x60, 7]).await.expect("write");
        let mut got = [0u8; 64];
        let n = theirs.recv(&mut got).expect("recv");
        assert_eq!(&got[..n], &[0, 0, 0, AF_INET6, 0x60, 7]);
    }
}
