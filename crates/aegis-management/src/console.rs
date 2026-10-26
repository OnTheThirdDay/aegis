//! HTTPS console listener (ADR-0007).
//!
//! The console is served over TLS whenever it is reachable beyond loopback.
//! Handshakes run in bounded background tasks with a deadline so a slow or
//! idle peer can never stall the accept loop. A plaintext request on the
//! console port receives a redirect to `https://` and is closed; no API is
//! ever answered without TLS.

use aegis_config::secret;
use rustls::ServerConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::server::TlsStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 64;

#[derive(serde::Deserialize)]
struct Bundle {
    certificate: String,
    private_key: String,
    #[serde(default)]
    #[allow(dead_code)]
    server_name: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    trusted_ca: Option<String>,
}

/// Reloadable console certificate. A rejected replacement keeps the
/// previous configuration.
pub struct ConsoleTls {
    dir: PathBuf,
    bundle: String,
    current: RwLock<Arc<ServerConfig>>,
    fingerprint: RwLock<String>,
}

fn build(dir: &std::path::Path, bundle: &str) -> Result<(Arc<ServerConfig>, String), String> {
    let text = secret::read(dir, bundle).map_err(|_| "console_tls_bundle_unavailable")?;
    let b: Bundle = serde_json::from_str(&text).map_err(|_| "console_tls_bundle_invalid")?;
    let cert = secret::read(dir, &b.certificate).map_err(|_| "console_certificate_unavailable")?;
    let key = secret::read(dir, &b.private_key).map_err(|_| "console_key_unavailable")?;
    let certs =
        aegis_identity::tls::parse_certs(&cert).map_err(|_| "console_certificate_invalid")?;
    let fingerprint = aegis_storage::sha256_hex(certs[0].as_ref());
    let key = aegis_identity::tls::parse_key(&key).map_err(|_| "console_key_invalid")?;
    let mut config = ServerConfig::builder_with_provider(aegis_identity::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "console_tls_unavailable")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| "console_certificate_key_mismatch")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.max_early_data_size = 0;
    Ok((Arc::new(config), fingerprint))
}

impl ConsoleTls {
    pub fn load(dir: PathBuf, bundle: String) -> Result<Arc<Self>, String> {
        let (config, fingerprint) = build(&dir, &bundle)?;
        Ok(Arc::new(ConsoleTls {
            dir,
            bundle,
            current: RwLock::new(config),
            fingerprint: RwLock::new(fingerprint),
        }))
    }

    /// Validate and publish a replaced certificate for new connections.
    pub fn reload(&self) -> Result<(), String> {
        let (config, fingerprint) = build(&self.dir, &self.bundle)?;
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = config;
        *self.fingerprint.write().unwrap_or_else(|e| e.into_inner()) = fingerprint;
        Ok(())
    }

    /// SHA-256 of the leaf certificate, shown to operators so the first
    /// browser warning can be verified out of band.
    pub fn fingerprint(&self) -> String {
        self.fingerprint
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.current.read().unwrap_or_else(|e| e.into_inner()))
    }
}

/// `axum::serve` listener yielding completed TLS streams.
pub struct TlsListener {
    rx: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The acceptor task ended (listener failure); park forever so
            // graceful shutdown remains the only exit.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Reply to a plaintext request with a redirect to the HTTPS origin.
async fn redirect_plaintext(mut tcp: TcpStream, port: u16) {
    let mut head = [0u8; 4096];
    let mut n = 0;
    while n < head.len() {
        match tcp.read(&mut head[n..]).await {
            Ok(0) | Err(_) => return,
            Ok(m) => n += m,
        }
        if head[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head[..n]);
    let host = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("host")
                .then(|| v.trim().to_owned())
        })
        .filter(|h| {
            !h.is_empty()
                && h.len() <= 255
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
        });
    let response = match host {
        Some(h) => {
            // The plaintext request reached the TLS port, so the port the
            // browser used (behind any port mapping) is the HTTPS port.
            let target = if h.starts_with('[') {
                if h.contains("]:") {
                    h.clone()
                } else {
                    format!("{h}:{port}")
                }
            } else if h.contains(':') {
                h.clone()
            } else {
                format!("{h}:{port}")
            };
            format!(
                "HTTP/1.1 308 Permanent Redirect\r\nLocation: https://{target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        }
        None => {
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
        }
    };
    let _ = tcp.write_all(response.as_bytes()).await;
    let _ = tcp.shutdown().await;
}

pub fn tls_listener(listener: TcpListener, tls: Arc<ConsoleTls>) -> std::io::Result<TlsListener> {
    let local = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(MAX_PENDING_HANDSHAKES);
    let slots = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    tokio::spawn(async move {
        loop {
            // Stop (closing the listening socket) once the server side is
            // gone, i.e. the console shut down.
            let accepted = tokio::select! {
                _ = tx.closed() => break,
                r = listener.accept() => r,
            };
            let (tcp, peer) = match accepted {
                Ok(c) => c,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                // Saturated with pending handshakes: shed the newcomer.
                drop(tcp);
                continue;
            };
            let tx = tx.clone();
            let config = tls.config();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = tcp.set_nodelay(true);
                let mut first = [0u8; 1];
                let peeked = tokio::time::timeout(HANDSHAKE_TIMEOUT, tcp.peek(&mut first)).await;
                if !matches!(peeked, Ok(Ok(1))) {
                    return;
                }
                if first[0] != 0x16 {
                    let _ = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        redirect_plaintext(tcp, local.port()),
                    )
                    .await;
                    return;
                }
                let acceptor = tokio_rustls::TlsAcceptor::from(config);
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await
                {
                    let _ = tx.send((stream, peer)).await;
                }
            });
        }
    });
    Ok(TlsListener { rx, local })
}
