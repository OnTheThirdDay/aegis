use aegis_transport_ws::{accept, connect, parse_url, WsClientConfig, WsServerConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn client(url: String) -> WsClientConfig {
    WsClientConfig {
        url,
        outer_ca_pem: None,
        connect_timeout: Duration::from_secs(5),
        handshake_timeout: Duration::from_secs(5),
        max_message_bytes: 128 * 1024,
    }
}

async fn echo_server(cfg: WsServerConfig) -> (u16, tokio::task::JoinHandle<Result<(), String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
        let ws = accept(tcp, &cfg).await.map_err(|e| e.to_string())?;
        let (mut r, mut w) = tokio::io::split(ws);
        tokio::io::copy(&mut r, &mut w)
            .await
            .map_err(|e| e.to_string())?;
        w.shutdown().await.map_err(|e| e.to_string())?;
        Ok(())
    });
    (port, task)
}

#[tokio::test]
async fn ordered_bytes_survive_message_framing() {
    let (port, server) = echo_server(WsServerConfig::default()).await;
    let ws = connect(&client(format!("ws://127.0.0.1:{port}/agp")))
        .await
        .expect("connect");
    let (mut r, mut w) = tokio::io::split(ws);
    let data: Vec<u8> = (0..1_000_003u32).map(|i| (i % 251) as u8).collect();
    let expected = data.clone();
    let writer = tokio::spawn(async move {
        for chunk in data.chunks(7919) {
            w.write_all(chunk).await.expect("write");
        }
        w.shutdown().await.expect("close");
    });
    let mut got = Vec::new();
    r.read_to_end(&mut got).await.expect("read");
    writer.await.expect("join");
    assert_eq!(got, expected);
    server.await.expect("join").expect("server ok");
}

#[tokio::test]
async fn wrong_path_is_refused() {
    let (port, server) = echo_server(WsServerConfig::default()).await;
    let res = connect(&client(format!("ws://127.0.0.1:{port}/other"))).await;
    assert!(res.is_err());
    assert!(server.await.expect("join").is_err());
}

#[test]
fn url_validation() {
    assert!(parse_url("https://x/agp").is_err());
    assert!(parse_url("wss://user:pw@x/agp").is_err());
    let u = parse_url("wss://gw.example.org/agp").expect("ok");
    assert!(u.tls);
    assert_eq!(u.port, 443);
    let u = parse_url("ws://[::1]:8080/agp").expect("ok");
    assert_eq!(u.host, "::1");
    assert_eq!(u.port, 8080);
}
