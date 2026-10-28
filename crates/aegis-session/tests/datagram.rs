#![allow(clippy::panic)]
//! UDP flows (feature 0x0001, DATAGRAM frames): negotiation, boundaries,
//! loss instead of backpressure, RESET, and peer violations (TC-N07).

use aegis_agp::{
    encode_header, Decoder, Frame, FrameType, Hello, Network, OpenAck, OpenRequest,
    FEATURE_DATAGRAM,
};
use aegis_buffer::Budget;
use aegis_contracts::observability::NoopObservability;
use aegis_contracts::reason::OpenFailure;
use aegis_contracts::{Destination, Observability};
use aegis_session::{
    client_handshake, server_handshake, Incoming, OpenError, Session, SessionConfig, SessionError,
};
use bytes::{Bytes, BytesMut};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn obs() -> Arc<dyn Observability> {
    Arc::new(NoopObservability)
}

fn dest() -> Destination {
    Destination::parse_authority("192.0.2.7:443").expect("dest")
}

fn cfg(node: &str, datagrams: bool) -> SessionConfig {
    SessionConfig {
        node_id: node.into(),
        datagrams,
        ..SessionConfig::default()
    }
}

async fn pair_with(
    client_cfg: SessionConfig,
    server_cfg: SessionConfig,
    server_budget: Arc<Budget>,
) -> (Session, Session, Incoming) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(async move {
        server_handshake(b, server_cfg, server_budget, obs(), "client-1").await
    });
    let client = client_handshake(a, client_cfg, Budget::root(64 << 20), obs())
        .await
        .expect("client handshake");
    let (server, incoming) = server.await.expect("join").expect("server handshake");
    (client, server, incoming)
}

async fn pair(client: bool, server: bool) -> (Session, Session, Incoming) {
    pair_with(
        cfg("client-1", client),
        cfg("gw-1", server),
        Budget::root(64 << 20),
    )
    .await
}

/// Accept every UDP flow and send each datagram back.
fn spawn_echo(mut incoming: Incoming) {
    tokio::spawn(async move {
        while let Some(open) = incoming.next().await {
            assert_eq!(open.request().network, Network::Udp);
            let flow = open.accept_datagram().expect("accept");
            tokio::spawn(async move {
                while let Ok(d) = flow.recv().await {
                    let _ = flow.send(&d);
                }
            });
        }
    });
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), f)
        .await
        .expect("timed out")
}

#[tokio::test]
async fn tc_n07_datagrams_keep_their_boundaries() {
    let (client, _server, incoming) = pair(true, true).await;
    assert!(client.datagrams());
    spawn_echo(incoming);
    let flow = client
        .open_datagram(dest(), Duration::from_secs(5))
        .await
        .expect("open flow");
    assert_eq!(flow.max_datagram(), 16 * 1024);
    let sizes = [1usize, 7, 1200, 1500, 16 * 1024];
    for (i, n) in sizes.iter().enumerate() {
        let d: Vec<u8> = (0..*n).map(|b| (b + i) as u8).collect();
        assert!(flow.send(&d).expect("send"));
        let back = within(flow.recv()).await.expect("echo");
        assert_eq!(back.as_ref(), d.as_slice(), "datagram {i} ({n} bytes)");
    }
    // Empty datagrams can't be framed: dropped, not an error.
    assert!(!flow.send(&[]).expect("empty"));
    let too_big = vec![0u8; 16 * 1024 + 1];
    assert_eq!(
        flow.send(&too_big).expect_err("oversize").kind(),
        std::io::ErrorKind::InvalidInput
    );
    // A byte stream still works on the same session.
    drop(flow);
    within(async {
        while client.stream_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

#[tokio::test]
async fn udp_needs_both_sides() {
    for (c, s) in [(true, false), (false, true), (false, false)] {
        let (client, server, _incoming) = pair(c, s).await;
        assert!(!client.datagrams(), "client {c} server {s}");
        assert!(!server.datagrams());
        assert_eq!(
            client
                .open_datagram(dest(), Duration::from_secs(1))
                .await
                .expect_err("no udp"),
            OpenError::Rejected(OpenFailure::Unsupported)
        );
    }
}

#[tokio::test]
async fn udp_is_left_out_when_its_buffers_dont_fit() {
    let server_cfg = cfg("gw-1", true);
    // Room for the streams' receive window, not for the datagram buffers.
    let tight = u64::from(server_cfg.session_window) + 64 * 1024;
    let (client, _server, incoming) =
        pair_with(cfg("client-1", true), server_cfg, Budget::root(tight)).await;
    assert!(!client.datagrams());
    drop(incoming);
}

#[tokio::test]
async fn a_slow_reader_loses_datagrams_instead_of_stalling() {
    let (client, _server, mut incoming) = pair(true, true).await;
    let opened = tokio::spawn(async move {
        let flow = incoming
            .next()
            .await
            .expect("open")
            .accept_datagram()
            .expect("accept");
        for i in 0..200u32 {
            flow.send(&i.to_be_bytes()).expect("send");
        }
        (flow, incoming)
    });
    let flow = client
        .open_datagram(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    let (_server_flow, _incoming) = opened.await.expect("join");
    // Let everything arrive while nobody reads.
    within(async {
        while client.stats().datagram_recv_queued < 64 * 4 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stats = client.stats();
    assert_eq!(stats.datagram_recv_queued, 64 * 4, "one flow keeps 64");
    assert_eq!(stats.datagrams_dropped, 200 - 64);
    // The oldest are kept, in order.
    for i in 0..64u32 {
        assert_eq!(
            within(flow.recv()).await.expect("queued").as_ref(),
            i.to_be_bytes()
        );
    }
    assert_eq!(client.stats().datagram_recv_queued, 0);
}

#[tokio::test]
async fn reset_ends_the_flow_on_both_sides() {
    let (client, server, mut incoming) = pair(true, true).await;
    let accepted = tokio::spawn(async move {
        let open = incoming.next().await.expect("open");
        (open.accept_datagram().expect("accept"), incoming)
    });
    let flow = client
        .open_datagram(dest(), Duration::from_secs(5))
        .await
        .expect("open");
    let (server_flow, _incoming) = accepted.await.expect("join");
    server_flow.reset(aegis_contracts::reason::ResetReason::Timeout);
    let err = within(flow.recv()).await.expect_err("reset");
    assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    assert_eq!(
        flow.send(b"x").expect_err("reset").kind(),
        std::io::ErrorKind::ConnectionReset
    );
    drop(flow);
    within(async {
        while client.stream_count() + server.stream_count() > 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// A raw peer that breaks the rules.
// ---------------------------------------------------------------------------

struct Raw {
    io: DuplexStream,
    dec: Decoder,
    buf: BytesMut,
}

impl Raw {
    async fn send(&mut self, f: Frame) {
        let mut b = BytesMut::new();
        encode_header(
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
        loop {
            if let Ok(Some(f)) = self.dec.decode(&mut self.buf) {
                return Some(f);
            }
            self.buf.reserve(8192);
            match tokio::time::timeout(Duration::from_secs(3), self.io.read_buf(&mut self.buf))
                .await
            {
                Ok(Ok(n)) if n > 0 => {}
                _ => return None,
            }
        }
    }

    async fn recv_significant(&mut self) -> Option<Frame> {
        loop {
            let f = self.recv().await?;
            if !matches!(f.frame_type, FrameType::WindowUpdate | FrameType::Ping) {
                return Some(f);
            }
        }
    }
}

/// A raw client offering `features` to a gateway that accepts UDP.
async fn raw_client(features: Vec<u16>) -> (Raw, Session, Incoming) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(async move {
        server_handshake(
            b,
            cfg("gw-1", true),
            Budget::root(64 << 20),
            obs(),
            "client-1",
        )
        .await
    });
    let mut raw = Raw {
        io: a,
        dec: Decoder::new(65_536),
        buf: BytesMut::new(),
    };
    let hello = Hello {
        protocol_min: 1,
        protocol_max: 1,
        node_id: "client-1".into(),
        max_streams: 16,
        initial_stream_window: 65_536,
        initial_session_window: 1 << 20,
        max_frame_payload: 16_384,
        features,
    };
    raw.send(Frame::new(
        FrameType::Hello,
        0,
        hello.encode().expect("hello"),
    ))
    .await;
    let ack = raw.recv().await.expect("hello ack");
    let ack = Hello::decode(ack.payload).expect("ack");
    let (session, incoming) = server.await.expect("join").expect("server");
    assert_eq!(session.datagrams(), ack.features == [FEATURE_DATAGRAM]);
    (raw, session, incoming)
}

fn open(id: u32, network: Network) -> Frame {
    Frame::new(
        FrameType::Open,
        id,
        OpenRequest {
            network,
            destination: dest(),
            timeout_ms: 5000,
        }
        .encode()
        .expect("open"),
    )
}

fn datagram(id: u32) -> Frame {
    Frame::new(FrameType::Datagram, id, Bytes::from_static(b"udp"))
}

async fn expect_protocol_close(session: &Session) {
    within(session.closed()).await;
    assert!(
        matches!(session.close_reason(), Some(SessionError::Protocol(_))),
        "got {:?}",
        session.close_reason()
    );
}

#[tokio::test]
async fn datagram_without_negotiation_fails_the_session() {
    let (mut raw, session, mut incoming) = raw_client(vec![]).await;
    raw.send(open(1, Network::Tcp)).await;
    let _s = incoming.next().await.expect("open").accept().expect("tcp");
    raw.send(datagram(1)).await;
    expect_protocol_close(&session).await;
}

#[tokio::test]
async fn udp_open_without_negotiation_is_refused_alone() {
    let (mut raw, session, _incoming) = raw_client(vec![]).await;
    raw.send(open(1, Network::Udp)).await;
    let ack = raw.recv_significant().await.expect("ack");
    assert_eq!(ack.frame_type, FrameType::OpenAck);
    assert_eq!(
        OpenAck::decode(&ack.payload),
        Ok(OpenAck::Failure(OpenFailure::Unsupported))
    );
    assert!(!session.is_closed(), "only the stream is refused");
}

#[tokio::test]
async fn datagram_on_a_byte_stream_fails_the_session() {
    let (mut raw, session, mut incoming) = raw_client(vec![FEATURE_DATAGRAM]).await;
    raw.send(open(1, Network::Tcp)).await;
    let _s = incoming.next().await.expect("open").accept().expect("tcp");
    raw.send(datagram(1)).await;
    expect_protocol_close(&session).await;
}

#[tokio::test]
async fn datagram_before_the_flow_opened_fails_the_session() {
    let (mut raw, session, mut incoming) = raw_client(vec![FEATURE_DATAGRAM]).await;
    raw.send(open(1, Network::Udp)).await;
    let _pending = incoming.next().await.expect("queued open");
    raw.send(datagram(1)).await;
    expect_protocol_close(&session).await;
}

#[tokio::test]
async fn byte_stream_frames_on_a_flow_fail_the_session() {
    for bad in [
        Frame::new(FrameType::Data, 1, Bytes::from_static(b"x")),
        Frame::new(FrameType::HalfClose, 1, Bytes::new()),
        Frame::new(
            FrameType::WindowUpdate,
            1,
            Bytes::copy_from_slice(&1u32.to_be_bytes()),
        ),
    ] {
        let (mut raw, session, mut incoming) = raw_client(vec![FEATURE_DATAGRAM]).await;
        raw.send(open(1, Network::Udp)).await;
        let _flow = incoming
            .next()
            .await
            .expect("open")
            .accept_datagram()
            .expect("udp");
        raw.send(bad.clone()).await;
        expect_protocol_close(&session).await;
    }
}

#[tokio::test]
async fn accepting_with_the_wrong_kind_refuses_the_stream() {
    let (mut raw, session, mut incoming) = raw_client(vec![FEATURE_DATAGRAM]).await;
    raw.send(open(1, Network::Udp)).await;
    let open = incoming.next().await.expect("open");
    assert!(open.accept().is_err());
    let ack = raw.recv_significant().await.expect("ack");
    assert_eq!(
        OpenAck::decode(&ack.payload),
        Ok(OpenAck::Failure(OpenFailure::Internal))
    );
    assert!(!session.is_closed());
}

#[tokio::test]
async fn a_late_datagram_after_reset_is_ignored() {
    let (mut raw, session, mut incoming) = raw_client(vec![FEATURE_DATAGRAM]).await;
    raw.send(open(1, Network::Udp)).await;
    let flow = incoming
        .next()
        .await
        .expect("open")
        .accept_datagram()
        .expect("udp");
    let ack = raw.recv_significant().await.expect("ack");
    assert_eq!(OpenAck::decode(&ack.payload), Ok(OpenAck::Success));
    raw.send(datagram(1)).await;
    assert_eq!(
        within(flow.recv()).await.expect("datagram").as_ref(),
        b"udp"
    );
    drop(flow);
    let reset = raw.recv_significant().await.expect("reset");
    assert_eq!(reset.frame_type, FrameType::Reset);
    // Crossing the RESET: dropped, not a violation.
    raw.send(datagram(1)).await;
    raw.send(reset.with_flags(aegis_agp::FLAG_RESET_ACK)).await;
    raw.send(datagram(1)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!session.is_closed(), "{:?}", session.close_reason());
    assert_eq!(session.stream_count(), 0);
}
