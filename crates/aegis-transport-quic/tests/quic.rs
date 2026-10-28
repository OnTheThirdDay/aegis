//! A real QUIC handshake with device certificates: the session stream,
//! datagrams, and refusal of a client the gateway doesn't trust.

use aegis_contracts::Role;
use aegis_identity::pki::{self, DEFAULT_CA_VALIDITY, DEFAULT_NODE_VALIDITY};
use aegis_identity::tls::{client_config, server_config, PeerIdentity};
use aegis_identity::{IdentitySnapshot, IdentityStore};
use aegis_transport_quic as quic;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Identities {
    server: rustls::ServerConfig,
    client: Arc<rustls::ClientConfig>,
    foreign_client: Arc<rustls::ClientConfig>,
}

fn identities() -> Identities {
    let ca = pki::generate_ca("test-ca", DEFAULT_CA_VALIDITY).expect("ca");
    let (gw_cert, gw_key) = pki::issue_direct(
        &ca,
        "gw-1",
        Role::Gateway,
        &["gateway.aegis.internal".into()],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("gateway");
    let client = |ca: &pki::CaBundle| {
        let (key, csr) = pki::generate_key_and_csr("phone-1").expect("csr");
        let cert = pki::sign_csr(
            ca,
            &csr,
            "phone-1",
            Role::Client,
            &[],
            DEFAULT_NODE_VALIDITY,
        )
        .expect("sign");
        (cert, key)
    };
    let (c_cert, c_key) = client(&ca);
    let foreign = pki::generate_ca("other-ca", DEFAULT_CA_VALIDITY).expect("ca");
    let (f_cert, f_key) = client(&foreign);
    let store = IdentityStore::new(IdentitySnapshot::default());
    Identities {
        server: (*server_config(&gw_cert, &gw_key, &ca.cert_pem, store).expect("server")).clone(),
        client: client_config(&c_cert, &c_key, &ca.cert_pem).expect("client"),
        foreign_client: client_config(&f_cert, &f_key, &ca.cert_pem).expect("client"),
    }
}

fn client_cfg(addr: std::net::SocketAddr, tls: Arc<rustls::ClientConfig>) -> quic::ClientConfig {
    quic::ClientConfig {
        address: addr.to_string(),
        server_name: "gateway.aegis.internal".into(),
        tls,
        connect_timeout: Duration::from_secs(5),
        limits: quic::Limits::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_stream_and_datagrams_over_mutual_tls() {
    let ids = identities();
    let endpoint = quic::server(
        "127.0.0.1:0".parse().expect("addr"),
        &ids.server,
        &quic::Limits::default(),
    )
    .expect("server");
    let addr = endpoint.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let conn = endpoint
            .accept()
            .await
            .expect("incoming")
            .await
            .expect("handshake");
        let peer = PeerIdentity::from_der(quic::peer_certificate(&conn).expect("cert").as_ref())
            .expect("identity");
        assert_eq!(peer.node_id, "phone-1");
        let mut stream = quic::accept_stream(&conn, Duration::from_secs(5))
            .await
            .expect("stream");
        let mut hello = [0u8; 5];
        stream.read_exact(&mut hello).await.expect("read");
        stream.write_all(&hello).await.expect("echo");
        let d = conn.read_datagram().await.expect("datagram");
        assert!(quic::send_datagram(&conn, d));
        // Keep the connection until the client is done.
        let _ = conn.closed().await;
    });
    let (conn, mut stream) = quic::connect(&client_cfg(addr, ids.client))
        .await
        .expect("connect");
    let gateway = PeerIdentity::from_der(quic::peer_certificate(&conn).expect("cert").as_ref())
        .expect("gateway");
    aegis_identity::tls::check_gateway(&gateway).expect("gateway policy");
    stream.write_all(b"hello").await.expect("write");
    let mut back = [0u8; 5];
    stream.read_exact(&mut back).await.expect("echo");
    assert_eq!(&back, b"hello");
    let max = quic::max_datagram(&conn).expect("datagrams negotiated");
    assert!(max >= 1100, "datagram size {max}");
    assert!(quic::send_datagram(
        &conn,
        Bytes::from_static(b"udp payload")
    ));
    let echoed = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("in time")
        .expect("datagram");
    assert_eq!(echoed.as_ref(), b"udp payload");
    conn.close(0u32.into(), b"done");
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_from_another_ca_is_refused() {
    let ids = identities();
    let endpoint = quic::server(
        "127.0.0.1:0".parse().expect("addr"),
        &ids.server,
        &quic::Limits::default(),
    )
    .expect("server");
    let addr = endpoint.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
    });
    let result = quic::connect(&client_cfg(addr, ids.foreign_client)).await;
    // Either the handshake fails, or the stream dies on first use.
    if let Ok((_conn, mut stream)) = result {
        let _ = stream.write_all(b"x").await;
        let mut b = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut b)).await;
        assert!(
            !matches!(read, Ok(Ok(1))),
            "untrusted client got data through"
        );
    }
}
