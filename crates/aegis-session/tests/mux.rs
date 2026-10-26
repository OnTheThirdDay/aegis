#![allow(clippy::panic)]
//! Multiplexer conformance tests (03 §3, 07 TC-P04..TC-P20).

use aegis_agp::{
    encode_frame, encode_window_update, Decoder, Frame, FrameType, Hello, Network, OpenAck,
    OpenRequest, FLAG_RESET_ACK,
};
use aegis_buffer::Budget;
use aegis_contracts::observability::NoopObservability;
use aegis_contracts::reason::{OpenFailure, ResetReason};
use aegis_contracts::{Destination, Observability};
use aegis_session::{
    client_handshake, server_handshake, Incoming, OpenError, Session, SessionConfig, SessionError,
};
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

fn obs() -> Arc<dyn Observability> {
    Arc::new(NoopObservability)
}

fn dest() -> Destination {
    Destination::parse_authority("example.com:443").expect("dest")
}

fn cfg(node: &str) -> SessionConfig {
    SessionConfig {
        node_id: node.into(),
        ..SessionConfig::default()
    }
}

async fn pair_with(
    client_cfg: SessionConfig,
    server_cfg: SessionConfig,
    budget: Arc<Budget>,
) -> (Session, Session, Incoming) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let sb = Arc::clone(&budget);
    let server =
        tokio::spawn(async move { server_handshake(b, server_cfg, sb, obs(), "client-1").await });
    let client = client_handshake(a, client_cfg, budget, obs())
        .await
        .expect("client handshake");
    let (server, incoming) = server.await.expect("join").expect("server handshake");
    (client, server, incoming)
}

async fn pair() -> (Session, Session, Incoming) {
    pair_with(cfg("client-1"), cfg("gw-1"), Budget::root(64 * 1024 * 1024)).await
}

/// Accept every OPEN and echo bytes back, half-closing on EOF.
fn spawn_echo(mut incoming: Incoming) {
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            let stream = open.accept().expect("accept");
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(stream);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
}

#[tokio::test]
async fn byte_exact_bidirectional_transfer() {
    let (client, _server, incoming) = pair().await;
    spawn_echo(incoming);
    let stream = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    let mut payload = vec![0u8; 3 * 1024 * 1024 + 17];
    rand::thread_rng().fill_bytes(&mut payload);
    let (mut r, mut w) = tokio::io::split(stream);
    let to_send = payload.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&to_send).await.expect("write");
        w.shutdown().await.expect("shutdown");
        w
    });
    let mut echoed = Vec::new();
    r.read_to_end(&mut echoed).await.expect("read");
    let _w = writer.await.expect("join");
    assert_eq!(echoed.len(), payload.len());
    assert!(echoed == payload, "payload mismatch");
}

#[tokio::test]
async fn tc_p05_half_close_then_reply() {
    let (client, _server, mut incoming) = pair().await;
    tokio::spawn(async move {
        let open = incoming.next().await.expect("open");
        let mut s = open.accept().expect("accept");
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.expect("server read to EOF");
        assert_eq!(got, b"request");
        s.write_all(b"response after client FIN")
            .await
            .expect("write");
        s.shutdown().await.expect("shutdown");
    });
    let mut s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    s.write_all(b"request").await.expect("write");
    s.shutdown().await.expect("half close");
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).await.expect("read after own FIN");
    assert_eq!(reply, b"response after client FIN");
    drop(s);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(client.stream_count(), 0, "fully closed stream released");
}

#[tokio::test]
async fn tc_p17_open_rejected_is_never_success() {
    let (client, _server, mut incoming) = pair().await;
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            open.reject(OpenFailure::Denied);
        }
    });
    let err = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect_err("denied");
    assert_eq!(err, OpenError::Rejected(OpenFailure::Denied));
    assert_eq!(client.stream_count(), 0);
    // Dropping an IncomingOpen without a decision rejects it as internal.
    let (client, _server, mut incoming) = pair().await;
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            drop(open);
        }
    });
    let err = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect_err("dropped");
    assert_eq!(err, OpenError::Rejected(OpenFailure::Internal));
}

#[tokio::test]
async fn tc_p06_remote_reset_terminates_stream() {
    let (client, _server, mut incoming) = pair().await;
    tokio::spawn(async move {
        let open = incoming.next().await.expect("open");
        let mut s = open.accept().expect("accept");
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.expect("read");
        s.reset(ResetReason::DestinationReset);
    });
    let mut s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    s.write_all(b"data").await.expect("write");
    let mut buf = [0u8; 16];
    let err = loop {
        match s.read(&mut buf).await {
            Ok(0) => panic!("reset must not look like EOF"),
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    let werr = s
        .write_all(&[0u8; 100_000])
        .await
        .expect_err("write after reset");
    assert_eq!(werr.kind(), std::io::ErrorKind::ConnectionReset);
}

#[tokio::test]
async fn tc_p13_slow_reader_does_not_starve_other_streams() {
    let budget = Budget::root(64 * 1024 * 1024);
    let (client, _server, mut incoming) =
        pair_with(cfg("client-1"), cfg("gw-1"), Arc::clone(&budget)).await;
    // Stream 1: server floods, client never reads. Stream 3: echo.
    tokio::spawn(async move {
        let first = incoming
            .next()
            .await
            .expect("first")
            .accept()
            .expect("accept");
        tokio::spawn(async move {
            let mut s = first;
            let chunk = vec![7u8; 16 * 1024];
            loop {
                if s.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        while let Some(open) = incoming.next().await {
            let s = open.accept().expect("accept");
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(s);
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    let stalled = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open stalled");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let stats = client.stats();
    assert!(
        stats.recv_buffered <= 64 * 1024,
        "stalled stream bounded by its window: {stats:?}"
    );
    assert_eq!(
        stats.recv_buffered + stats.recv_outstanding + stats.recv_pending_grant,
        stats.recv_reserved,
        "credit is backed by reservation"
    );
    for i in 0..20 {
        let mut s = client
            .open(dest(), Duration::from_secs(5))
            .await
            .expect("open healthy");
        let msg = format!("interactive {i}");
        s.write_all(msg.as_bytes()).await.expect("write");
        s.shutdown().await.expect("fin");
        let mut back = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut back))
            .await
            .expect("healthy stream progresses")
            .expect("read");
        assert_eq!(back, msg.as_bytes());
    }
    drop(stalled);
}

#[tokio::test]
async fn tc_p10_window_exhaustion_applies_backpressure() {
    let (client, _server, mut incoming) = pair().await;
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let s = incoming
            .next()
            .await
            .expect("open")
            .accept()
            .expect("accept");
        // Never read: the client writer must block, not buffer unboundedly.
        let _ = done_rx.await;
        drop(s);
    });
    let mut s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    let big = vec![1u8; 4 * 1024 * 1024];
    let res = tokio::time::timeout(Duration::from_millis(500), s.write_all(&big)).await;
    assert!(
        res.is_err(),
        "write must block once credit + tx buffer are exhausted"
    );
    let _ = done_tx.send(());
}

#[tokio::test]
async fn tc_p20_open_reset_churn_returns_to_baseline() {
    let budget = Budget::root(64 * 1024 * 1024);
    let (client, server, incoming) =
        pair_with(cfg("client-1"), cfg("gw-1"), Arc::clone(&budget)).await;
    spawn_echo(incoming);
    let baseline = budget.used();
    for i in 0..1000u32 {
        let mut s = client
            .open(dest(), Duration::from_secs(5))
            .await
            .expect("open");
        if i % 3 == 0 {
            s.write_all(b"x").await.expect("write");
        }
        if i % 2 == 0 {
            s.reset(ResetReason::Cancelled);
        } else {
            drop(s);
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client.stream_count() == 0 && server.stream_count() == 0 && budget.used() == baseline
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("streams and reservations return to baseline");
    let st = client.stats();
    assert_eq!(
        st.recv_buffered + st.recv_outstanding + st.recv_pending_grant,
        st.recv_reserved
    );
}

#[tokio::test]
async fn goaway_forbids_new_streams_but_existing_continue() {
    let (client, server, incoming) = pair().await;
    spawn_echo(incoming);
    let mut s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    server.goaway();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        client
            .open(dest(), Duration::from_secs(1))
            .await
            .expect_err("goaway"),
        OpenError::GoingAway
    );
    s.write_all(b"still here").await.expect("write");
    s.shutdown().await.expect("fin");
    let mut back = Vec::new();
    s.read_to_end(&mut back).await.expect("read");
    assert_eq!(back, b"still here");
}

#[tokio::test]
async fn tc_p07_transport_loss_fails_streams_explicitly() {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let budget = Budget::root(64 * 1024 * 1024);
    let sb = Arc::clone(&budget);
    let server =
        tokio::spawn(async move { server_handshake(b, cfg("gw-1"), sb, obs(), "client-1").await });
    let client = client_handshake(a, cfg("client-1"), budget, obs())
        .await
        .expect("client");
    let (server, incoming) = server.await.expect("join").expect("server");
    spawn_echo(incoming);
    let mut s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    server.close(ResetReason::Shutdown);
    let mut buf = [0u8; 8];
    let res = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("no hang");
    assert!(
        res.is_err(),
        "existing stream fails explicitly, not EOF success"
    );
    client.closed().await;
    assert!(matches!(
        client.open(dest(), Duration::from_secs(1)).await,
        Err(OpenError::Session(_))
    ));
}

#[tokio::test]
async fn tc_p04_quota_bounded_under_open_flood() {
    let small = SessionConfig {
        max_streams: 8,
        ..cfg("gw-1")
    };
    let budget = Budget::root(64 * 1024 * 1024);
    let (client, _server, mut incoming) =
        pair_with(cfg("client-1"), small, Arc::clone(&budget)).await;
    // Accept but hold every stream open.
    let held = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let h2 = Arc::clone(&held);
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            h2.lock().await.push(open.accept().expect("accept"));
        }
    });
    let mut ok = Vec::new();
    for _ in 0..8 {
        ok.push(
            client
                .open(dest(), Duration::from_secs(5))
                .await
                .expect("within limit"),
        );
    }
    // A full session waits for a free slot no longer than the open's own
    // timeout, then refuses; nothing beyond the limit is ever admitted.
    let mut quota = 0;
    for _ in 0..300 {
        match client.open(dest(), Duration::from_millis(5)).await {
            Ok(s) => ok.push(s),
            Err(OpenError::Quota) | Err(OpenError::Rejected(OpenFailure::Quota)) => quota += 1,
            Err(e) => panic!("unexpected {e:?}"),
        }
    }
    assert_eq!(ok.len(), 8);
    assert_eq!(quota, 300);
    // Both sessions' receive windows plus small per-stream reservations.
    let bound = 2 * u64::from(cfg("x").session_window) + 2 * 1024 * 1024;
    assert!(budget.used() < bound, "bounded memory: {}", budget.used());
}

#[tokio::test]
async fn full_session_open_waits_for_a_free_slot() {
    let small = SessionConfig {
        max_streams: 4,
        ..cfg("gw-1")
    };
    let (client, _server, incoming) =
        pair_with(cfg("client-1"), small, Budget::root(64 * 1024 * 1024)).await;
    // Like a gateway: each stream ends when the device closes it.
    spawn_echo(incoming);
    let mut open = Vec::new();
    for _ in 0..4 {
        open.push(
            client
                .open(dest(), Duration::from_secs(5))
                .await
                .expect("within limit"),
        );
    }
    // Free one slot shortly; the next open waits for it instead of failing.
    let first = open.remove(0);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(first);
    });
    let started = std::time::Instant::now();
    let fifth = client.open(dest(), Duration::from_secs(5)).await;
    assert!(fifth.is_ok(), "waited for a slot: {:?}", fifth.err());
    assert!(started.elapsed() >= Duration::from_millis(150));
}

#[tokio::test]
async fn session_rejected_when_budget_exhausted() {
    let budget = Budget::root(64 * 1024); // smaller than 2 stream windows
    let (a, b) = tokio::io::duplex(64 * 1024);
    let sb = Arc::clone(&budget);
    tokio::spawn(async move {
        let _ = client_handshake(a, cfg("client-1"), Budget::root(64 * 1024 * 1024), obs()).await;
    });
    let res = server_handshake(b, cfg("gw-1"), sb, obs(), "client-1").await;
    assert!(matches!(res, Err(SessionError::Budget)));
    assert_eq!(budget.used(), 0);
}

// ---------------------------------------------------------------------------
// Raw adversarial peer
// ---------------------------------------------------------------------------

struct Raw {
    io: DuplexStream,
    dec: Decoder,
    buf: BytesMut,
}

impl Raw {
    async fn send(&mut self, f: Frame) {
        let mut b = BytesMut::new();
        // Deliberately bypass the production encoder to inject invalid peer
        // controls. The production encoder now rejects these malformed values.
        aegis_agp::encode_header(
            &mut b,
            f.frame_type,
            f.flags,
            f.stream_id,
            f.payload.len() as u32,
        );
        b.extend_from_slice(&f.payload);
        let _ = self.io.write_all(&b).await;
    }

    async fn recv(&mut self) -> Option<Frame> {
        recv_frame(&mut self.io, &mut self.dec, &mut self.buf).await
    }

    /// Next frame that is not a keepalive/credit frame.
    async fn recv_significant(&mut self) -> Option<Frame> {
        loop {
            let f = self.recv().await?;
            if !matches!(f.frame_type, FrameType::WindowUpdate | FrameType::Ping) {
                return Some(f);
            }
        }
    }
}

async fn recv_frame<T: AsyncRead + Unpin>(
    io: &mut T,
    dec: &mut Decoder,
    buf: &mut BytesMut,
) -> Option<Frame> {
    loop {
        if let Ok(Some(f)) = dec.decode(buf) {
            return Some(f);
        }
        buf.reserve(8192);
        match tokio::time::timeout(Duration::from_secs(3), io.read_buf(buf)).await {
            Ok(Ok(n)) if n > 0 => {}
            _ => return None,
        }
    }
}

fn hello(node: &str) -> Hello {
    Hello {
        protocol_min: 1,
        protocol_max: 1,
        node_id: node.into(),
        max_streams: 16,
        initial_stream_window: 65_536,
        initial_session_window: 1 << 20,
        max_frame_payload: 16_384,
        features: vec![],
    }
}

async fn raw_against_server(server_cfg: SessionConfig) -> (Raw, Session, Incoming) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(async move {
        server_handshake(b, server_cfg, Budget::root(64 << 20), obs(), "client-1").await
    });
    let mut raw = Raw {
        io: a,
        dec: Decoder::new(65_536),
        buf: BytesMut::new(),
    };
    raw.send(Frame::new(
        FrameType::Hello,
        0,
        hello("client-1").encode().expect("hello"),
    ))
    .await;
    let ack = raw.recv().await.expect("hello ack");
    assert_eq!(ack.frame_type, FrameType::HelloAck);
    let (session, incoming) = server.await.expect("join").expect("server");
    (raw, session, incoming)
}

fn open_frame(id: u32) -> Frame {
    Frame::new(
        FrameType::Open,
        id,
        OpenRequest {
            network: Network::Tcp,
            destination: dest(),
            timeout_ms: 5000,
        }
        .encode()
        .expect("open"),
    )
}

async fn expect_protocol_close(session: &Session, raw: &mut Raw) {
    tokio::time::timeout(Duration::from_secs(3), session.closed())
        .await
        .expect("session must terminate");
    assert!(
        matches!(session.close_reason(), Some(SessionError::Protocol(_))),
        "got {:?}",
        session.close_reason()
    );
    // Server sends GOAWAY before closing the transport.
    let mut saw_goaway = false;
    while let Some(f) = raw.recv().await {
        if f.frame_type == FrameType::GoAway {
            saw_goaway = true;
        }
    }
    assert!(saw_goaway);
}

#[tokio::test]
async fn tc_p17_data_before_open_ack_is_protocol_error() {
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    let _pending = incoming.next().await.expect("queued open");
    raw.send(Frame::new(FrameType::Data, 1, Bytes::from_static(b"early")))
        .await;
    expect_protocol_close(&session, &mut raw).await;
}

#[tokio::test]
async fn tc_p14_over_window_data_is_protocol_error() {
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    let s = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let ack = raw.recv_significant().await.expect("ack");
    assert_eq!(OpenAck::decode(&ack.payload), Ok(OpenAck::Success));
    // Window is 64 KiB: send 4 x 16 KiB (ok) then one more byte (violation).
    for _ in 0..4 {
        raw.send(Frame::new(
            FrameType::Data,
            1,
            Bytes::from(vec![0u8; 16_384]),
        ))
        .await;
    }
    raw.send(Frame::new(FrameType::Data, 1, Bytes::from_static(b"!")))
        .await;
    expect_protocol_close(&session, &mut raw).await;
    drop(s);
}

#[tokio::test]
async fn tc_p14_window_update_arithmetic() {
    for payload in [vec![0u8, 0, 0, 0], vec![0x7f, 0xff, 0xff, 0xff]] {
        let (mut raw, session, _incoming) = raw_against_server(cfg("gw-1")).await;
        // Zero increment rejected by codec; 2^31-1 overflows the existing credit.
        raw.send(Frame::new(FrameType::WindowUpdate, 0, Bytes::from(payload)))
            .await;
        expect_protocol_close(&session, &mut raw).await;
    }
    // Update for a never-opened stream.
    let (mut raw, session, _incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(Frame::new(
        FrameType::WindowUpdate,
        5,
        encode_window_update(10).expect("wu"),
    ))
    .await;
    expect_protocol_close(&session, &mut raw).await;
}

#[tokio::test]
async fn tc_p16_stream_ids_must_increase_by_two() {
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    incoming
        .next()
        .await
        .expect("open 1")
        .reject(OpenFailure::Denied);
    let ack = raw.recv_significant().await.expect("ack");
    assert_eq!(
        OpenAck::decode(&ack.payload),
        Ok(OpenAck::Failure(OpenFailure::Denied))
    );
    // A denied OPEN still consumes its ID: reusing 1 is a violation.
    raw.send(open_frame(1)).await;
    expect_protocol_close(&session, &mut raw).await;

    let (mut raw, session, _incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(5)).await; // skipped 1 and 3
    expect_protocol_close(&session, &mut raw).await;

    let (mut raw, session, _incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(2)).await; // even IDs are reserved
    expect_protocol_close(&session, &mut raw).await;
}

#[tokio::test]
async fn tc_p15_reset_ack_rules() {
    // Unsolicited ACK for a live stream is a violation.
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    let s = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let _ = raw.recv_significant().await;
    raw.send(
        Frame::new(
            FrameType::Reset,
            1,
            aegis_agp::encode_reset(ResetReason::Cancelled),
        )
        .with_flags(FLAG_RESET_ACK),
    )
    .await;
    expect_protocol_close(&session, &mut raw).await;
    drop(s);

    // Peer RESET request is acknowledged exactly once; DATA after it is illegal.
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    let s = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let _ = raw.recv_significant().await;
    raw.send(Frame::new(
        FrameType::Reset,
        1,
        aegis_agp::encode_reset(ResetReason::Cancelled),
    ))
    .await;
    let ack = raw.recv_significant().await.expect("reset ack");
    assert_eq!(ack.frame_type, FrameType::Reset);
    assert_eq!(ack.flags, FLAG_RESET_ACK);
    raw.send(Frame::new(FrameType::Data, 1, Bytes::from_static(b"late")))
        .await;
    expect_protocol_close(&session, &mut raw).await;
    drop(s);
}

#[tokio::test]
async fn tc_p15_local_reset_discards_in_flight_data_until_ack() {
    let (mut raw, session, mut incoming) = raw_against_server(cfg("gw-1")).await;
    raw.send(open_frame(1)).await;
    let s = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let _ = raw.recv_significant().await;
    s.reset(ResetReason::Cancelled);
    let req = raw.recv_significant().await.expect("reset request");
    assert_eq!((req.frame_type, req.flags), (FrameType::Reset, 0));
    // DATA crossing our RESET (within old credit) is charged and discarded.
    raw.send(Frame::new(FrameType::Data, 1, Bytes::from(vec![0u8; 1000])))
        .await;
    raw.send(
        Frame::new(
            FrameType::Reset,
            1,
            aegis_agp::encode_reset(ResetReason::Cancelled),
        )
        .with_flags(FLAG_RESET_ACK),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!session.is_closed());
    assert_eq!(
        session.stream_count(),
        0,
        "closing record released after ACK"
    );
    let st = session.stats();
    assert_eq!(st.recv_buffered, 0);
    assert_eq!(
        st.recv_buffered + st.recv_outstanding + st.recv_pending_grant,
        st.recv_reserved
    );
}

#[tokio::test]
async fn tc_p15_missing_reset_ack_times_out_session() {
    let server_cfg = SessionConfig {
        reset_drain_timeout: Duration::from_millis(300),
        ..cfg("gw-1")
    };
    let (mut raw, session, mut incoming) = raw_against_server(server_cfg).await;
    raw.send(open_frame(1)).await;
    let s = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let _ = raw.recv_significant().await;
    s.reset(ResetReason::Cancelled);
    tokio::time::timeout(Duration::from_secs(3), session.closed())
        .await
        .expect("drain deadline enforced");
    assert_eq!(
        session.close_reason(),
        Some(SessionError::ResetDrainTimeout)
    );
}

#[tokio::test]
async fn hello_identity_must_match_certificate() {
    let (mut a, b) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        server_handshake(b, cfg("gw-1"), Budget::root(64 << 20), obs(), "client-1").await
    });
    let mut wire = BytesMut::new();
    encode_frame(
        &mut wire,
        &Frame::new(
            FrameType::Hello,
            0,
            hello("someone-else").encode().expect("h"),
        ),
    )
    .expect("encode");
    a.write_all(&wire).await.expect("write");
    let res = server.await.expect("join");
    assert!(matches!(res, Err(SessionError::IdentityMismatch)));
}

#[tokio::test]
async fn open_before_hello_is_rejected() {
    let (mut a, b) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        server_handshake(b, cfg("gw-1"), Budget::root(64 << 20), obs(), "client-1").await
    });
    let mut wire = BytesMut::new();
    encode_frame(&mut wire, &open_frame(1)).expect("encode");
    a.write_all(&wire).await.expect("write");
    assert!(matches!(
        server.await.expect("join"),
        Err(SessionError::Protocol(_))
    ));
}

#[tokio::test]
async fn ping_flood_terminates_session() {
    let (mut raw, session, _incoming) = raw_against_server(cfg("gw-1")).await;
    for i in 0..200u64 {
        raw.send(Frame::new(
            FrameType::Ping,
            0,
            Bytes::copy_from_slice(&i.to_be_bytes()),
        ))
        .await;
    }
    tokio::time::timeout(Duration::from_secs(3), session.closed())
        .await
        .expect("flood terminates session");
    assert_eq!(session.close_reason(), Some(SessionError::ControlOverload));
}

#[tokio::test]
async fn fragmented_data_stays_within_reserved_receive_storage() {
    // A non-power-of-two window catches containers that round capacity up.
    let window = 65_537;
    // Starts at its full window, so the whole window can arrive at once.
    let config = SessionConfig {
        stream_window: window,
        initial_stream_window: window,
        ..cfg("gw-1")
    };
    let (mut raw, session, mut incoming) = raw_against_server(config).await;
    raw.send(open_frame(1)).await;
    let mut stream = incoming
        .next()
        .await
        .expect("open")
        .accept()
        .expect("accept");
    let _ = raw.recv_significant().await.expect("ack");
    // Receive storage is allocated as data arrives, never up front.
    assert_eq!(session.stats().recv_allocated, 0);

    let mut batch = BytesMut::new();
    for _ in 0..1024 {
        encode_frame(
            &mut batch,
            &Frame::new(FrameType::Data, 1, Bytes::from_static(b"a")),
        )
        .expect("encode");
    }
    for _ in 0..64 {
        raw.io.write_all(&batch).await.expect("tiny frames");
    }
    raw.send(Frame::new(FrameType::Data, 1, Bytes::from_static(b"a")))
        .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        while session.stats().recv_buffered != u64::from(window) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("all frames consumed");
    let allocated = session.stats().recv_allocated;
    assert_eq!(
        allocated,
        u64::from(window),
        "exactly the window, not rounded up"
    );
    assert!(allocated <= session.stats().recv_reserved);

    // Consume enough to grant more credit, then refill across the ring boundary.
    let mut first = vec![0; 32_769];
    stream.read_exact(&mut first).await.expect("read prefix");
    assert!(first.iter().all(|&b| b == b'a'));
    for size in [16_384, 16_384, 1] {
        raw.send(Frame::new(
            FrameType::Data,
            1,
            Bytes::from(vec![b'b'; size]),
        ))
        .await;
    }
    let mut rest = vec![0; window as usize];
    stream
        .read_exact(&mut rest)
        .await
        .expect("read wrapped buffer");
    assert!(rest[..32_768].iter().all(|&b| b == b'a'));
    assert!(rest[32_768..].iter().all(|&b| b == b'b'));
    // Drained: the storage is released again.
    assert_eq!(session.stats().recv_allocated, 0);
    assert_eq!(session.stats().recv_buffered, 0);
}

#[derive(Default)]
struct WriteGate {
    // 0 = normal, 1 = blocked write, 2 = blocked flush, 3 = blocked shutdown.
    mode: AtomicUsize,
    allowance: AtomicUsize,
    blocked: tokio::sync::Notify,
    dropped: AtomicBool,
}

struct GatedTransport {
    io: DuplexStream,
    gate: Arc<WriteGate>,
}

impl Drop for GatedTransport {
    fn drop(&mut self) {
        self.gate.dropped.store(true, Ordering::SeqCst);
    }
}

impl AsyncRead for GatedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for GatedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.gate.mode.load(Ordering::SeqCst) == 1 {
            let allowance = self.gate.allowance.load(Ordering::SeqCst);
            if allowance == 0 {
                self.gate.blocked.notify_one();
                return Poll::Pending;
            }
            let result = Pin::new(&mut self.io).poll_write(cx, &buf[..buf.len().min(allowance)]);
            if let Poll::Ready(Ok(n)) = result {
                self.gate.allowance.fetch_sub(n, Ordering::SeqCst);
            }
            result
        } else {
            Pin::new(&mut self.io).poll_write(cx, buf)
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.gate.mode.load(Ordering::SeqCst) == 2 {
            self.gate.blocked.notify_one();
            Poll::Pending
        } else {
            Pin::new(&mut self.io).poll_flush(cx)
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.gate.mode.load(Ordering::SeqCst) == 3 {
            self.gate.blocked.notify_one();
            Poll::Pending
        } else {
            Pin::new(&mut self.io).poll_shutdown(cx)
        }
    }
}

async fn gated_server(
    config: SessionConfig,
) -> (Raw, Session, Incoming, Arc<Budget>, Arc<WriteGate>) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let gate = Arc::new(WriteGate::default());
    let transport = GatedTransport {
        io: b,
        gate: Arc::clone(&gate),
    };
    let budget = Budget::root(8 * 1024 * 1024);
    let server_budget = Arc::clone(&budget);
    let server = tokio::spawn(async move {
        server_handshake(transport, config, server_budget, obs(), "client-1").await
    });
    let mut raw = Raw {
        io: a,
        dec: Decoder::new(65_536),
        buf: BytesMut::new(),
    };
    raw.send(Frame::new(
        FrameType::Hello,
        0,
        hello("client-1").encode().expect("hello"),
    ))
    .await;
    let _ = raw.recv().await.expect("ack");
    let (session, incoming) = server.await.expect("join").expect("handshake");
    (raw, session, incoming, budget, gate)
}

async fn released(budget: &Budget, gate: &WriteGate) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while budget.used() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("closed session must release reservations");
    assert!(
        gate.dropped.load(Ordering::SeqCst),
        "transport dropped while peer remains connected"
    );
}

#[tokio::test(start_paused = true)]
async fn close_cancels_blocked_write_and_flush_without_appending_goaway() {
    for mode in [1, 2] {
        let (mut raw, session, incoming, budget, gate) = gated_server(cfg("gw-1")).await;
        gate.allowance.store(5, Ordering::SeqCst);
        gate.mode.store(mode, Ordering::SeqCst);
        raw.send(Frame::new(
            FrameType::Ping,
            0,
            Bytes::from_static(b"12345678"),
        ))
        .await;
        tokio::time::timeout(Duration::from_secs(1), gate.blocked.notified())
            .await
            .expect("writer blocked");
        session.close(ResetReason::PolicyRevoked);
        drop(incoming);
        drop(session);
        released(&budget, &gate).await;
        let mut wire = Vec::new();
        raw.io.read_to_end(&mut wire).await.expect("EOF");
        if mode == 1 {
            assert_eq!(wire.len(), 5, "no GOAWAY may follow an incomplete frame");
        } else {
            let mut wire = BytesMut::from(wire.as_slice());
            assert_eq!(
                raw.dec
                    .decode(&mut wire)
                    .expect("decode")
                    .expect("pong")
                    .frame_type,
                FrameType::Pong
            );
            assert!(
                wire.is_empty(),
                "no further writes after cancelling a flush"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn incoming_keepalives_do_not_extend_a_blocked_write_deadline() {
    let config = SessionConfig {
        keepalive_timeout: Duration::from_millis(100),
        ..cfg("gw-1")
    };
    let (mut raw, session, incoming, budget, gate) = gated_server(config).await;
    gate.mode.store(1, Ordering::SeqCst);
    raw.send(Frame::new(
        FrameType::Ping,
        0,
        Bytes::from_static(b"12345678"),
    ))
    .await;
    gate.blocked.notified().await;
    for _ in 0..2 {
        tokio::time::sleep(Duration::from_millis(40)).await;
        raw.send(Frame::new(
            FrameType::Ping,
            0,
            Bytes::from_static(b"12345678"),
        ))
        .await;
    }
    tokio::time::timeout(Duration::from_millis(50), session.closed())
        .await
        .expect("write deadline enforced");
    assert_eq!(session.close_reason(), Some(SessionError::WriteTimeout));
    drop(incoming);
    drop(session);
    released(&budget, &gate).await;
    drop(raw);
}

#[tokio::test(start_paused = true)]
async fn final_write_flush_and_shutdown_have_a_deadline() {
    for mode in [1, 2, 3] {
        let (_raw, session, incoming, budget, gate) = gated_server(cfg("gw-1")).await;
        gate.mode.store(mode, Ordering::SeqCst);
        session.close(ResetReason::Shutdown);
        drop(incoming);
        drop(session);
        released(&budget, &gate).await;
    }
}

#[tokio::test]
async fn open_retries_while_the_peer_still_counts_a_released_stream() {
    let small = SessionConfig {
        max_streams: 2,
        ..cfg("gw-1")
    };
    let (client, _server, mut incoming) =
        pair_with(cfg("client-1"), small, Budget::root(64 * 1024 * 1024)).await;
    // The gateway side keeps its handles until told to let go, like a relay
    // that is still closing its connection to the destination.
    let held = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let h2 = Arc::clone(&held);
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            h2.lock().await.push(open.accept().expect("accept"));
        }
    });
    let a = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("first");
    let _b = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("second");
    drop(a); // released here; the gateway still holds its side
    tokio::time::sleep(Duration::from_millis(100)).await;
    let release = Arc::clone(&held);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        release.lock().await.remove(0);
    });
    let started = std::time::Instant::now();
    let third = client.open(dest(), Duration::from_secs(5)).await;
    assert!(
        third.is_ok(),
        "retried until the gateway freed the slot: {:?}",
        third.err()
    );
    assert!(started.elapsed() >= Duration::from_millis(200));
}

#[tokio::test]
async fn hundreds_of_idle_streams_fit_and_busy_ones_grow() {
    let (client, server, incoming) = pair_with(
        cfg("client-1"),
        cfg("gw-1"),
        Budget::root(256 * 1024 * 1024),
    )
    .await;
    spawn_echo(incoming);
    // A browser's worth of mostly idle connections on one default session.
    let mut idle = Vec::new();
    for i in 0..400 {
        let s = client
            .open(dest(), Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("stream {i}: {e:?}"));
        idle.push(s);
    }
    let stats = client.stats();
    assert_eq!(
        stats.recv_allocated, 0,
        "idle streams hold no receive storage"
    );
    assert!(stats.stream_windows <= 400 * 16 * 1024);
    // One busy stream alongside them: its window grows past the initial
    // 16 KiB, and the transfer is byte-exact.
    let s = client
        .open(dest(), Duration::from_secs(5))
        .await
        .expect("busy");
    let (mut r, mut w) = tokio::io::split(s);
    let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&data).await.expect("write");
        w.shutdown().await.expect("shutdown");
    });
    // Read in chunks, watching the busy stream's window while it flows.
    let mut got = Vec::with_capacity(expected.len());
    let mut buf = vec![0u8; 64 * 1024];
    let mut peak = 0;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let n = r.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            peak = peak.max(client.stats().stream_windows);
        }
    })
    .await
    .expect("transfer finishes");
    writer.await.expect("join");
    assert_eq!(got, expected);
    assert!(
        peak > 401 * 16 * 1024,
        "a busy stream's window grows: peak {peak}"
    );
    let _ = server;
    drop(idle);
}
