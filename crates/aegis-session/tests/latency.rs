#![allow(clippy::panic)]
//! Throughput of one stream over a long, slow link (a phone in China
//! reaching its gateway through Cloudflare: ~430 ms round trip), on tokio's
//! test clock.

use aegis_buffer::Budget;
use aegis_contracts::observability::NoopObservability;
use aegis_contracts::{Destination, Observability};
use aegis_session::{client_handshake, server_handshake, SessionConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::time::Instant;

fn obs() -> Arc<dyn Observability> {
    Arc::new(NoopObservability)
}

/// Copy `r` to `w`, delivering each piece `delay` after it was read, and no
/// faster than `rate` bytes per second (a queue builds up behind it).
async fn forward<R, W>(mut r: R, mut w: W, delay: Duration, rate: u64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((at, data)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if w.write_all(&data).await.is_err() {
                return;
            }
        }
    });
    let mut buf = vec![0u8; 16 * 1024];
    let mut free_at = Instant::now();
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let now = Instant::now();
        let start = free_at.max(now);
        free_at = start + Duration::from_secs_f64(n as f64 / rate as f64);
        if tx.send((free_at + delay, buf[..n].to_vec())).is_err() {
            return;
        }
    }
}

/// Two ends of a link with `delay` each way and `rate` bytes/s each way.
fn link(delay: Duration, rate: u64) -> (DuplexStream, DuplexStream) {
    let (a, a_far) = tokio::io::duplex(1 << 20);
    let (b, b_far) = tokio::io::duplex(1 << 20);
    let (ar, aw) = tokio::io::split(a_far);
    let (br, bw) = tokio::io::split(b_far);
    tokio::spawn(forward(ar, bw, delay, rate));
    tokio::spawn(forward(br, aw, delay, rate));
    (a, b)
}

/// Seconds (test clock) to move `bytes` over one stream: from the gateway
/// to the client (a download), or the other way (`upload`).
async fn transfer(
    client_cfg: SessionConfig,
    gateway_cfg: SessionConfig,
    bytes: usize,
    upload: bool,
) -> f64 {
    let (a, b) = link(Duration::from_millis(215), 4 * 1024 * 1024);
    let budget = Budget::root(256 * 1024 * 1024);
    let gb = Arc::clone(&budget);
    let gateway =
        tokio::spawn(async move { server_handshake(b, gateway_cfg, gb, obs(), "client-1").await });
    let client = client_handshake(a, client_cfg, budget, obs())
        .await
        .expect("client handshake");
    let (_gateway, mut incoming) = gateway.await.expect("join").expect("gateway handshake");
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let Some(open) = incoming.next().await else {
            return;
        };
        let mut stream = open.accept().expect("accept");
        if upload {
            let _ = done_tx.send(read_all(&mut stream).await);
        } else {
            let _ = stream.write_all(&vec![7u8; bytes]).await;
            let _ = stream.shutdown().await;
            // Dropping a stream before the peer read it all resets it.
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let dest = Destination::parse_authority("example.com:443").expect("dest");
    let mut stream = client
        .open(dest, Duration::from_secs(30))
        .await
        .expect("open");
    let start = Instant::now();
    let got = if upload {
        stream.write_all(&vec![7u8; bytes]).await.expect("write");
        stream.shutdown().await.expect("shutdown");
        done_rx.await.expect("received")
    } else {
        read_all(&mut stream).await
    };
    assert_eq!(got, bytes);
    start.elapsed().as_secs_f64()
}

async fn read_all<R: AsyncRead + Unpin>(r: &mut R) -> usize {
    let mut got = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf).await.expect("read");
        if n == 0 {
            return got;
        }
        got += n;
    }
}

fn cfg(node: &str, window_kib: u32) -> SessionConfig {
    SessionConfig {
        node_id: node.into(),
        stream_window: window_kib * 1024,
        stream_tx_buffer: window_kib.min(1024) * 1024,
        ..SessionConfig::default()
    }
}

const MIB: usize = 1024 * 1024;

/// A connection's window used to grow only when the receiver saw its credit
/// nearly used up, which on a long round trip (data in flight looks like
/// unused credit) never happened: it stayed near 64 KiB, 0.15 MB/s. Timed
/// by its round trip, it reaches the quota.
#[tokio::test(start_paused = true)]
async fn one_download_over_a_long_round_trip_reaches_its_window() {
    let secs = transfer(cfg("client-1", 2048), cfg("gw-1", 2048), 32 * MIB, false).await;
    // The 2 MiB window allows ~4.8 MB/s at 430 ms; the link 4 MB/s.
    assert!(secs < 14.0, "32 MiB took {secs:.1} s");
}

/// Windows are the receiver's: a gateway with a small window of its own
/// (256 KiB, as before 1.1.10) still sends as fast as the client takes.
#[tokio::test(start_paused = true)]
async fn the_gateways_own_window_doesnt_limit_downloads() {
    let old = SessionConfig {
        node_id: "gw-1".into(),
        ..SessionConfig::default()
    };
    let secs = transfer(cfg("client-1", 2048), old, 32 * MIB, false).await;
    assert!(secs < 14.0, "32 MiB took {secs:.1} s");
}

#[tokio::test(start_paused = true)]
async fn one_upload_over_a_long_round_trip_reaches_its_window() {
    let secs = transfer(cfg("client-1", 2048), cfg("gw-1", 2048), 32 * MIB, true).await;
    assert!(secs < 14.0, "32 MiB took {secs:.1} s");
}

/// iPhone settings (1 MiB): about half the speed, still several times the
/// old one.
#[tokio::test(start_paused = true)]
async fn a_one_mib_window_carries_about_two_mb_per_second() {
    let secs = transfer(cfg("client-1", 1024), cfg("gw-1", 2048), 32 * MIB, false).await;
    assert!(secs < 22.0, "32 MiB took {secs:.1} s");
}
