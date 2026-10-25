//! Gateway ingress: WebSocket → inner mTLS → AGP session → per-OPEN
//! admission against the current policy → restricted dial → relay.

use crate::egress::{admit_failure, dial_direct};
use crate::relay::{finish_mux, relay, ActiveGuard};
use crate::{now_unix, NodeContext};
use aegis_config::InboundConfig;
use aegis_contracts::observability::{Event, OperationResult};
use aegis_contracts::reason::{OpenFailure, ReasonGroup};
use aegis_core::Admitted;
use aegis_identity::tls::{self, PeerIdentity};
use aegis_policy::DecisionInput;
use aegis_session::{server_handshake, IncomingOpen};
use aegis_transport_ws::WsServerConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

trait Duplex: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Duplex for T {}

const EDGE_MAX_HEAD: usize = 8 * 1024;
const EDGE_MAX_BODY: usize = 32 * 1024;

/// Read the HTTP request head. `POST /enroll` and `POST /renew` are answered
/// here and the connection closed (`None`); anything else is replayed into
/// the WebSocket upgrade unchanged.
async fn route_edge(
    mut io: Box<dyn Duplex>,
    ws_path: &str,
    hook: crate::EdgeHook,
) -> Option<Box<dyn Duplex>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() >= EDGE_MAX_HEAD {
            return None;
        }
        let mut chunk = [0u8; 2048];
        let n = io.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(
        req.parse(&buf[..head_end]),
        Ok(httparse::Status::Complete(_))
    ) {
        return None;
    }
    let route = match (req.method, req.path) {
        (Some("POST"), Some("/enroll")) => crate::EdgeRequest::Enroll,
        (Some("POST"), Some("/renew")) => crate::EdgeRequest::Renew,
        (_, Some(p)) if p == ws_path || p.starts_with(&format!("{ws_path}?")) => {
            return Some(Box::new(aegis_transport_ws::Prefixed::new(buf, io)));
        }
        _ => {
            let _ = io
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return None;
        }
    };
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    let length = header("content-length").and_then(|v| v.parse::<usize>().ok());
    // Reverse proxies (e.g. a Cloudflare tunnel) may forward the body
    // chunked; accept exactly `chunked`, never both framings.
    let chunked = match header("transfer-encoding") {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("chunked") && length.is_none() => true,
        Some(_) => return None,
    };
    let mut body = buf[head_end..].to_vec();
    if chunked {
        body = read_chunked(&mut io, body).await?;
    } else {
        let Some(length) = length.filter(|l| *l <= EDGE_MAX_BODY) else {
            let _ = io
                .write_all(b"HTTP/1.1 411 Length Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return None;
        };
        if body.len() > length {
            return None;
        }
        while body.len() < length {
            let mut chunk = vec![0u8; (length - body.len()).min(4096)];
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    let (status, payload) = hook(route, body).await;
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        409 => "Conflict",
        429 => "Too Many Requests",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    let _ = io.write_all(head.as_bytes()).await;
    let _ = io.write_all(&payload).await;
    let _ = io.shutdown().await;
    None
}

/// Decode a chunked body (bounded by `EDGE_MAX_BODY`); trailers ignored.
async fn read_chunked(io: &mut Box<dyn Duplex>, mut raw: Vec<u8>) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // Ensure a full size line is buffered.
        let line_end = loop {
            if let Some(i) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + i;
            }
            if raw.len() > EDGE_MAX_BODY * 2 {
                return None;
            }
            let mut chunk = [0u8; 4096];
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&chunk[..n]);
        };
        let size_text = std::str::from_utf8(&raw[pos..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        if out.len() + size > EDGE_MAX_BODY {
            return None;
        }
        while raw.len() < pos + size + 2 {
            let mut chunk = [0u8; 4096];
            let n = io.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            raw.extend_from_slice(&chunk[..n]);
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        if &raw[pos + size..pos + size + 2] != b"\r\n" {
            return None;
        }
        pos += size + 2;
    }
}

pub async fn serve(ctx: Arc<NodeContext>, inbound: InboundConfig, listener: TcpListener) {
    let pending = Arc::new(Semaphore::new(inbound.max_pending_handshakes as usize));
    let ws_cfg = WsServerConfig {
        path: inbound.path.clone(),
        handshake_timeout: Duration::from_millis(u64::from(
            ctx.startup.core.inbound_handshake_timeout_ms,
        )),
        max_message_bytes: inbound.max_frame_bytes as usize,
        allowed_origins: inbound.allowed_origins.clone(),
    };
    let inbound = Arc::new(inbound);
    let mut shutdown = ctx.shutdown_signal();
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.wait_for(|s| *s) => return,
        };
        let Ok((tcp, _peer_addr)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        // Bounded pending handshakes: excess connections are dropped
        // immediately rather than queued.
        let Ok(permit) = Arc::clone(&pending).try_acquire_owned() else {
            ctx.obs().record(Event::ResourceThrottle {
                reason: ReasonGroup::Quota,
            });
            drop(tcp);
            continue;
        };
        let ctx = Arc::clone(&ctx);
        let ws_cfg = ws_cfg.clone();
        let inbound = Arc::clone(&inbound);
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            handle_connection(ctx, inbound, ws_cfg, tcp, permit).await;
        });
    }
}

async fn handle_connection(
    ctx: Arc<NodeContext>,
    inbound: Arc<InboundConfig>,
    ws_cfg: WsServerConfig,
    tcp: TcpStream,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let started = Instant::now();
    let io: Box<dyn Duplex> = if let Some(reload) = ctx.outer_tls.get(&inbound.id).cloned() {
        let Ok(Ok(config)) = tokio::task::spawn_blocking(move || reload.load()).await else {
            return;
        };
        let handshake = tokio_rustls::TlsAcceptor::from(config).accept(tcp);
        let Ok(Ok(tls)) = tokio::time::timeout(
            Duration::from_millis(u64::from(ctx.startup.core.tls_handshake_timeout_ms)),
            handshake,
        )
        .await
        else {
            return;
        };
        Box::new(tls)
    } else {
        Box::new(tcp)
    };
    let io: Box<dyn Duplex> = match ctx.edge_hook.get().cloned() {
        Some(hook) => {
            let deadline =
                Duration::from_millis(u64::from(ctx.startup.core.inbound_handshake_timeout_ms));
            match tokio::time::timeout(deadline, route_edge(io, &ws_cfg.path, hook)).await {
                Ok(Some(io)) => io,
                _ => return,
            }
        }
        None => io,
    };
    let Ok(ws) = aegis_transport_ws::accept(io, &ws_cfg).await else {
        return;
    };
    let Some(server_tls) = ctx
        .identity
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .server_tls
        .clone()
    else {
        return;
    };
    let tls_timeout = Duration::from_millis(u64::from(ctx.startup.core.tls_handshake_timeout_ms));
    let (tls_stream, peer) = match tls::accept(server_tls, ws, tls_timeout).await {
        Ok(v) => v,
        Err(_) => {
            ctx.obs().record(Event::AuthFailure {
                reason: ReasonGroup::Tls,
            });
            ctx.obs().record(Event::HandshakeDuration {
                seconds: started.elapsed().as_secs_f64(),
                result: OperationResult::Denied,
            });
            return;
        }
    };
    ctx.obs().record(Event::HandshakeDuration {
        seconds: started.elapsed().as_secs_f64(),
        result: OperationResult::Ok,
    });
    // Reserve atomically before AGP negotiation. A count followed by an
    // await and later insertion allows concurrent handshakes past the cap.
    let Ok(_session_slot) = Arc::clone(&ctx.session_slots).try_acquire_owned() else {
        ctx.obs().record(Event::ResourceThrottle {
            reason: ReasonGroup::Quota,
        });
        return;
    };
    let budget = ctx.budget.child(ctx.startup.core.peer_buffer_budget_bytes);
    let obs: Arc<dyn aegis_contracts::Observability> = ctx.metrics.clone();
    let (session, mut incoming) = match server_handshake(
        tls_stream,
        ctx.session_config(),
        budget,
        obs,
        &peer.node_id,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            ctx.obs().record(Event::AuthFailure {
                reason: e.reason_group(),
            });
            return;
        }
    };
    let session = Arc::new(session);
    let reg_id = ctx.sessions.insert(peer.fingerprint, Arc::clone(&session));
    // The pending quota covers the entire WS + mTLS + AGP handshake.
    drop(permit);
    let peer = Arc::new(peer);
    let inbound_id: Arc<str> = Arc::from(inbound.id.as_str());
    loop {
        tokio::select! {
            next = incoming.next() => match next {
                Some(open) => {
                    let ctx = Arc::clone(&ctx);
                    let peer = Arc::clone(&peer);
                    let inbound_id = Arc::clone(&inbound_id);
                    tokio::spawn(async move { handle_open(ctx, peer, inbound_id, open).await });
                }
                None => break,
            },
            _ = session.closed() => break,
        }
    }
    ctx.sessions.remove(reg_id);
}

/// One logical stream. The session's earlier admissions grant nothing:
/// identity, revocation and policy are checked again right here.
async fn handle_open(
    ctx: Arc<NodeContext>,
    peer: Arc<PeerIdentity>,
    inbound_id: Arc<str>,
    open: IncomingOpen,
) {
    let dest = open.request().destination.clone();
    let input = DecisionInput {
        destination: &dest,
        inbound: &inbound_id,
        node_id: Some(&peer.node_id),
    };
    let admitted: Admitted = match ctx.gate.admit(Some(&peer), &input, now_unix()) {
        Ok(a) => a,
        Err(e) => {
            if let aegis_core::AdmitError::Denied(d) = &e {
                ctx.obs().record(Event::RouteDecision {
                    action: d.action,
                    class: d.rule_class,
                });
            }
            let f = admit_failure(&e);
            ctx.obs().record(Event::StreamClosed {
                result: OperationResult::Denied,
                reason: f.group(),
            });
            open.reject(f);
            return;
        }
    };
    ctx.obs().record(Event::RouteDecision {
        action: admitted.decision.action,
        class: admitted.decision.rule_class,
    });
    let timeout = Duration::from_millis(u64::from(open.request().timeout_ms));
    let started = Instant::now();
    let tcp = match dial_direct(
        &ctx,
        &admitted,
        &dest,
        &inbound_id,
        Some(&peer.node_id),
        timeout,
    )
    .await
    {
        Ok(s) => s,
        Err(f) => {
            ctx.obs().record(Event::StreamOpenDuration {
                seconds: started.elapsed().as_secs_f64(),
                result: if f == OpenFailure::Denied {
                    OperationResult::Denied
                } else {
                    OperationResult::Error
                },
            });
            ctx.obs().record(Event::StreamClosed {
                result: OperationResult::Error,
                reason: f.group(),
            });
            open.reject(f);
            return;
        }
    };
    // OPEN_ACK success only now that the destination is connected.
    let Ok(mut mux) = open.accept() else {
        return;
    };
    ctx.obs().record(Event::StreamOpened);
    let _active = ActiveGuard::new(&ctx.streams_active);
    let mut tcp = tcp;
    let idle = Duration::from_secs(u64::from(
        admitted.bundle.compiled.config.core.idle_timeout_seconds,
    ));
    let outcome = relay(&mut mux, &mut tcp, idle).await;
    finish_mux(mux, outcome, ctx.obs());
}
