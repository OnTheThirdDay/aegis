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
    let Ok(ws) = aegis_transport_ws::accept(tcp, &ws_cfg).await else {
        return;
    };
    let Some(server_tls) = ctx.identity.server_tls.clone() else {
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
    drop(permit);
    ctx.obs().record(Event::HandshakeDuration {
        seconds: started.elapsed().as_secs_f64(),
        result: OperationResult::Ok,
    });
    if ctx.sessions.count() as u32 >= ctx.startup.core.max_sessions {
        ctx.obs().record(Event::ResourceThrottle {
            reason: ReasonGroup::Quota,
        });
        return;
    }
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
