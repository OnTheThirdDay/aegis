//! Gateway ingress: WebSocket → inner mTLS → AGP session → per-OPEN
//! admission against the current policy → restricted dial → relay.

use crate::egress::{admit_failure, bind_direct_udp, dial_direct};
use crate::relay::{finish_flow, finish_mux, relay, relay_datagrams, ActiveGuard, UDP_IDLE};
use crate::{now_unix, NodeContext};
use aegis_agp::Network;
use aegis_config::InboundConfig;
use aegis_contracts::observability::{Event, OperationResult};
use aegis_contracts::reason::{OpenFailure, ReasonGroup};
use aegis_core::Admitted;
use aegis_identity::tls::{self, PeerIdentity};
use aegis_policy::DecisionInput;
use aegis_session::{server_handshake, IncomingOpen};
use aegis_telemetry::Severity;
use aegis_transport_ws::WsServerConfig;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::EdgeIo as Duplex;

const EDGE_MAX_HEAD: usize = 8 * 1024;
/// Room for a device's compressed diagnostic report (sent on `/renew`); the
/// pending-handshake cap and the handshake deadline bound what this costs.
const EDGE_MAX_BODY: usize = 2 * 1024 * 1024;

/// What the edge does with a connection after reading its first request.
enum EdgeRoute {
    /// Continue with the WebSocket upgrade (head replayed).
    Upgrade(Box<dyn Duplex>),
    /// Hand the connection to the user portal (head replayed).
    Portal(Box<dyn Duplex>),
    /// Answered (or refused) and closed.
    Done,
}

fn is_portal_path(p: &str) -> bool {
    p == "/portal" || p.starts_with("/portal/") || p.starts_with("/portal?")
}

/// Read the HTTP request head. `POST /enroll` and `POST /renew` are answered
/// here and the connection closed; `/portal` goes to the user portal (when
/// installed); anything else is replayed into the WebSocket upgrade.
async fn route_edge(
    mut io: Box<dyn Duplex>,
    ws_path: &str,
    hook: crate::EdgeHook,
    portal: bool,
) -> EdgeRoute {
    match route_edge_inner(&mut io, ws_path, hook, portal).await {
        Some(Replay::Upgrade(buf)) => {
            EdgeRoute::Upgrade(Box::new(aegis_transport_ws::Prefixed::new(buf, io)))
        }
        Some(Replay::Portal(buf)) => {
            EdgeRoute::Portal(Box::new(aegis_transport_ws::Prefixed::new(buf, io)))
        }
        None => EdgeRoute::Done,
    }
}

enum Replay {
    Upgrade(Vec<u8>),
    Portal(Vec<u8>),
}

async fn route_edge_inner(
    io: &mut Box<dyn Duplex>,
    ws_path: &str,
    hook: crate::EdgeHook,
    portal: bool,
) -> Option<Replay> {
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
            return Some(Replay::Upgrade(buf));
        }
        (_, Some(p)) if portal && is_portal_path(p) => {
            return Some(Replay::Portal(buf));
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
    let length = match header("content-length") {
        None => None,
        Some(v) => match v.parse::<usize>() {
            Ok(l) => Some(l),
            Err(_) => {
                refuse(io, "400 Bad Request").await;
                return None;
            }
        },
    };
    // Proxies such as Cloudflare's forward a body with Content-Length, as
    // chunked, or with both headers. Chunked takes precedence (RFC 9112
    // 6.3); this connection serves one request and then closes, so a
    // conflicting length can't desynchronize a following request.
    let chunked = match header("transfer-encoding") {
        None => false,
        Some(v) if v.eq_ignore_ascii_case("chunked") => true,
        Some(_) => {
            refuse(io, "501 Not Implemented").await;
            return None;
        }
    };
    let mut body = buf[head_end..].to_vec();
    if chunked {
        body = match read_chunked(io, body).await {
            Ok(b) => b,
            Err(BodyError::TooLarge) => {
                refuse(io, "413 Content Too Large").await;
                return None;
            }
            Err(BodyError::Malformed) => {
                refuse(io, "400 Bad Request").await;
                return None;
            }
            Err(BodyError::Closed) => return None,
        };
    } else {
        let Some(length) = length else {
            refuse(io, "411 Length Required").await;
            return None;
        };
        if length > EDGE_MAX_BODY {
            refuse(io, "413 Content Too Large").await;
            return None;
        }
        if body.len() > length {
            refuse(io, "400 Bad Request").await;
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

/// Answer a refused edge request and close: a proxy in front (Cloudflare)
/// then relays a meaningful status instead of a bare 502.
async fn refuse(io: &mut Box<dyn Duplex>, status: &str) {
    use tokio::io::AsyncWriteExt;
    let head = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = io.write_all(head.as_bytes()).await;
    let _ = io.shutdown().await;
}

/// Read more of a request body into `raw`.
async fn fill(io: &mut Box<dyn Duplex>, raw: &mut Vec<u8>) -> Result<(), BodyError> {
    use tokio::io::AsyncReadExt;
    let mut chunk = [0u8; 4096];
    let n = io.read(&mut chunk).await.map_err(|_| BodyError::Closed)?;
    if n == 0 {
        return Err(BodyError::Closed);
    }
    raw.extend_from_slice(&chunk[..n]);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum BodyError {
    TooLarge,
    Malformed,
    Closed,
}

/// Decode a chunked body (bounded by `EDGE_MAX_BODY`); trailers ignored.
async fn read_chunked(io: &mut Box<dyn Duplex>, mut raw: Vec<u8>) -> Result<Vec<u8>, BodyError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // Ensure a full size line is buffered.
        let line_end = loop {
            if let Some(i) = raw[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + i;
            }
            if raw.len() > EDGE_MAX_BODY * 2 {
                return Err(BodyError::TooLarge);
            }
            fill(io, &mut raw).await?;
        };
        let size_text =
            std::str::from_utf8(&raw[pos..line_end]).map_err(|_| BodyError::Malformed)?;
        let size = size_text
            .split(';')
            .next()
            .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
            .ok_or(BodyError::Malformed)?;
        pos = line_end + 2;
        if size == 0 {
            return Ok(out);
        }
        // Bound the size before arithmetic: a huge hex size must not overflow.
        if size > EDGE_MAX_BODY - out.len() {
            return Err(BodyError::TooLarge);
        }
        while raw.len() < pos + size + 2 {
            fill(io, &mut raw).await?;
        }
        out.extend_from_slice(&raw[pos..pos + size]);
        if &raw[pos + size..pos + size + 2] != b"\r\n" {
            return Err(BodyError::Malformed);
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
        ctx.diagnostics.count("gateway.accepted");
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
            let portal = ctx.portal_hook.get().cloned();
            let routed = tokio::time::timeout(
                deadline,
                route_edge(io, &ws_cfg.path, hook, portal.is_some()),
            )
            .await;
            match routed {
                Ok(EdgeRoute::Upgrade(io)) => io,
                Ok(EdgeRoute::Portal(io)) => {
                    // A web session, not a tunnel: no handshake slot, and its
                    // own limits (the portal bounds connections and idle time).
                    drop(permit);
                    if let Some(serve) = portal {
                        serve(io).await;
                    }
                    return;
                }
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
        Err(e) => {
            if ctx.diagnostics.is_recording() {
                ctx.diagnostics.note(
                    Severity::Warn,
                    "gateway.tls.rejected",
                    &[("error", &e.to_string())],
                );
            }
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
            if ctx.diagnostics.is_recording() {
                ctx.diagnostics.note(
                    Severity::Warn,
                    "gateway.session.rejected",
                    &[
                        ("reason", e.reason_group().as_str()),
                        ("error", &e.to_string()),
                    ],
                );
            }
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
    if open.request().network == Network::Udp {
        return handle_udp(ctx, &peer, &inbound_id, &admitted, open, timeout).await;
    }
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

/// One admitted UDP flow: a socket connected to the checked destination
/// address, then datagrams both ways until the flow ends or idles out.
async fn handle_udp(
    ctx: Arc<NodeContext>,
    peer: &PeerIdentity,
    inbound_id: &str,
    admitted: &Admitted,
    open: IncomingOpen,
    timeout: Duration,
) {
    let dest = open.request().destination.clone();
    let started = Instant::now();
    let socket = match bind_direct_udp(
        &ctx,
        admitted,
        &dest,
        inbound_id,
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
    let Ok(flow) = open.accept_datagram() else {
        return;
    };
    ctx.obs().record(Event::StreamOpened);
    let _active = ActiveGuard::new(&ctx.streams_active);
    let outcome = relay_datagrams(&flow, &socket, UDP_IDLE).await;
    finish_flow(flow, outcome, ctx.obs());
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn chunked(raw: &[u8]) -> Option<Vec<u8>> {
        chunked_result(raw).await.ok()
    }

    async fn chunked_result(raw: &[u8]) -> Result<Vec<u8>, BodyError> {
        let (io, _peer) = tokio::io::duplex(64);
        let mut io: Box<dyn Duplex> = Box::new(io);
        read_chunked(&mut io, raw.to_vec()).await
    }

    /// One request through the edge router; returns the response text and
    /// the body the hook received.
    async fn edge(request: &str) -> (String, Option<Vec<u8>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (server, mut client) = tokio::io::duplex(1 << 20);
        let seen = Arc::new(std::sync::Mutex::new(None));
        let s2 = Arc::clone(&seen);
        let hook: crate::EdgeHook = Arc::new(move |_req, body| {
            *s2.lock().expect("lock") = Some(body);
            Box::pin(async { (200, b"{}".to_vec()) })
        });
        let route = tokio::spawn(async move {
            let io: Box<dyn Duplex> = Box::new(server);
            let _ = route_edge(io, "/agp", hook, false).await;
        });
        client.write_all(request.as_bytes()).await.expect("write");
        // A malformed request must not wait forever for more input.
        client.shutdown().await.expect("shutdown");
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        route.await.expect("join");
        let body = seen.lock().expect("lock").take();
        (String::from_utf8_lossy(&out).into_owned(), body)
    }

    #[tokio::test]
    async fn proxied_framings_are_accepted_and_refusals_answered() {
        // Both headers, as a proxy may forward: chunked wins.
        let (resp, body) = edge(
            "POST /renew HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n\
             3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(body.as_deref(), Some(&b"abcde"[..]));
        // Plain length.
        let (resp, body) =
            edge("POST /renew HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nxyz").await;
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        assert_eq!(body.as_deref(), Some(&b"xyz"[..]));
        // Refusals are answered, never a silent close (a proxy's 502).
        let big = format!(
            "POST /renew HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            EDGE_MAX_BODY + 1
        );
        let (resp, body) = edge(&big).await;
        assert!(resp.starts_with("HTTP/1.1 413"), "{resp}");
        assert!(body.is_none());
        let (resp, _) = edge("POST /renew HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 411"), "{resp}");
        let (resp, _) =
            edge("POST /renew HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n").await;
        assert!(resp.starts_with("HTTP/1.1 501"), "{resp}");
        let (resp, _) =
            edge("POST /renew HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n")
                .await;
        assert!(resp.starts_with("HTTP/1.1 400"), "{resp}");
    }

    #[tokio::test]
    async fn chunked_bodies_decode_and_hostile_sizes_are_refused() {
        assert_eq!(
            chunked(b"3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\n\r\n").await,
            Some(b"abcde".to_vec())
        );
        // Unauthenticated input: an enormous chunk size must neither panic
        // (overflow) nor slip past the body limit.
        assert_eq!(chunked(b"1\r\nx\r\nffffffffffffffff\r\n").await, None);
        assert_eq!(
            chunked(format!("{:x}\r\n", EDGE_MAX_BODY + 1).as_bytes()).await,
            None
        );
        assert_eq!(chunked(b"zz\r\n").await, None);
        assert_eq!(
            chunked(b"3\r\nabcXX").await,
            None,
            "missing CRLF after data"
        );
        // Each refusal has its reason (answered as 413 / 400).
        assert_eq!(
            chunked_result(format!("{:x}\r\n", EDGE_MAX_BODY + 1).as_bytes()).await,
            Err(BodyError::TooLarge)
        );
        assert_eq!(chunked_result(b"zz\r\n").await, Err(BodyError::Malformed));
    }
}
