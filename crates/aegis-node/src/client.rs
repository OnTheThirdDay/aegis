//! Client side: local SOCKS5/HTTP CONNECT inbounds, admission, and the AGP
//! tunnel outbound (one multiplexed session per gateway, reconnected with
//! bounded backoff; never a silent direct fallback).

use crate::egress::{admit_failure, dial_direct};
use crate::relay::{finish_mux, relay, ActiveGuard, RelayOutcome, Upstream};
use crate::{now_unix, LoadedIdentity, NodeContext};
use aegis_buffer::Budget;
use aegis_config::{secret, InboundConfig, NodeConfig, OutboundConfig, OutboundKind};
use aegis_contracts::observability::{Event, Observability, OperationResult};
use aegis_contracts::reason::{OpenFailure, ReasonGroup};
use aegis_contracts::Destination;
use aegis_core::{Backoff, CircuitBreaker};
use aegis_identity::tls;
use aegis_inbound_http::HttpConnectConfig;
use aegis_inbound_socks::{Reply, SocksConfig};
use aegis_policy::DecisionInput;
use aegis_session::{client_handshake, MuxStream, OpenError, Session, SessionConfig};
use aegis_telemetry::LocalMetrics;
use aegis_transport_ws::WsClientConfig;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

struct TunnelState {
    session: Option<Arc<Session>>,
    backoff: Backoff,
    breaker: CircuitBreaker,
    next_attempt: Option<Instant>,
}

pub struct Tunnel {
    ws: WsClientConfig,
    server_name: String,
    tls: Arc<rustls::ClientConfig>,
    session_cfg: SessionConfig,
    tls_timeout: Duration,
    budget: Arc<Budget>,
    peer_budget: u64,
    obs: Arc<LocalMetrics>,
    state: tokio::sync::Mutex<TunnelState>,
    connected: std::sync::atomic::AtomicBool,
}

impl Tunnel {
    pub fn new(
        ob: &OutboundConfig,
        cfg: &NodeConfig,
        secrets_dir: &Path,
        identity: &LoadedIdentity,
        budget: &Arc<Budget>,
        obs: Arc<LocalMetrics>,
    ) -> Result<Tunnel, String> {
        let outer_ca_pem = match &ob.outer_ca {
            Some(r) => Some(secret::read(secrets_dir, r).map_err(|e| e.to_string())?),
            None => None,
        };
        let tls = identity
            .client_tls
            .clone()
            .ok_or_else(|| "client identity not loaded".to_string())?;
        let c = &cfg.core;
        Ok(Tunnel {
            ws: WsClientConfig {
                url: ob.url.clone().unwrap_or_default(),
                outer_ca_pem,
                connect_timeout: Duration::from_millis(u64::from(c.connect_timeout_ms)),
                handshake_timeout: Duration::from_millis(u64::from(c.tls_handshake_timeout_ms)),
                max_message_bytes: 128 * 1024,
            },
            server_name: ob.server_name.clone().unwrap_or_default(),
            tls,
            session_cfg: SessionConfig {
                node_id: cfg.node_id.clone(),
                max_streams: c.max_streams_per_session,
                stream_window: c.stream_buffer_budget_bytes,
                session_window: c.session_window_bytes,
                max_frame_payload: c.max_frame_payload_bytes,
                stream_tx_buffer: c.stream_buffer_budget_bytes,
                handshake_timeout: Duration::from_millis(u64::from(c.tls_handshake_timeout_ms)),
                keepalive_interval: Duration::from_secs(u64::from(c.keepalive_interval_seconds)),
                ..SessionConfig::default()
            },
            tls_timeout: Duration::from_millis(u64::from(c.tls_handshake_timeout_ms)),
            budget: Arc::clone(budget),
            peer_budget: c.peer_buffer_budget_bytes,
            obs,
            state: tokio::sync::Mutex::new(TunnelState {
                session: None,
                backoff: Backoff::new(Duration::from_millis(250), Duration::from_secs(30)),
                breaker: CircuitBreaker::new(8, Duration::from_secs(60), Duration::from_secs(30)),
                next_attempt: None,
            }),
            connected: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    async fn connect_once(&self) -> Result<Session, ReasonGroup> {
        let started = Instant::now();
        let ws = aegis_transport_ws::connect(&self.ws)
            .await
            .map_err(|_| ReasonGroup::Transport)?;
        let (tls_stream, _gateway) = tls::connect(
            Arc::clone(&self.tls),
            &self.server_name,
            ws,
            self.tls_timeout,
        )
        .await
        .map_err(|_| ReasonGroup::Tls)?;
        let obs: Arc<dyn Observability> = self.obs.clone();
        let session = client_handshake(
            tls_stream,
            self.session_cfg.clone(),
            self.budget.child(self.peer_budget),
            obs,
        )
        .await
        .map_err(|e| e.reason_group())?;
        self.obs.record(Event::HandshakeDuration {
            seconds: started.elapsed().as_secs_f64(),
            result: OperationResult::Ok,
        });
        Ok(session)
    }

    async fn session(&self) -> Result<Arc<Session>, OpenFailure> {
        let mut st = self.state.lock().await;
        if let Some(s) = &st.session {
            if !s.is_closed() {
                return Ok(Arc::clone(s));
            }
        }
        st.session = None;
        self.connected
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if !st.breaker.allow() || st.next_attempt.is_some_and(|t| Instant::now() < t) {
            return Err(OpenFailure::Unavailable);
        }
        match self.connect_once().await {
            Ok(s) => {
                let s = Arc::new(s);
                st.backoff.reset();
                st.breaker.record_success();
                st.next_attempt = None;
                st.session = Some(Arc::clone(&s));
                self.connected
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                Ok(s)
            }
            Err(reason) => {
                st.breaker.record_failure();
                st.next_attempt = Some(Instant::now() + st.backoff.next_delay());
                self.obs.record(Event::TransportReconnect { reason });
                Err(OpenFailure::Unavailable)
            }
        }
    }

    async fn forget(&self, s: &Arc<Session>) {
        let mut st = self.state.lock().await;
        if st.session.as_ref().is_some_and(|cur| Arc::ptr_eq(cur, s)) {
            st.session = None;
            self.connected
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Open a logical stream. Retries on a fresh session only when the
    /// gateway provably did not process the OPEN (GOAWAY / ID exhaustion);
    /// an OPEN with unknown outcome is never replayed.
    pub async fn open(
        &self,
        dest: &Destination,
        timeout: Duration,
    ) -> Result<MuxStream, OpenFailure> {
        for _ in 0..2 {
            let s = self.session().await?;
            match s.open(dest.clone(), timeout).await {
                Ok(m) => return Ok(m),
                Err(OpenError::GoingAway | OpenError::IdsExhausted) => {
                    self.forget(&s).await;
                    continue;
                }
                Err(OpenError::Session(_)) => {
                    self.forget(&s).await;
                    return Err(OpenFailure::Unavailable);
                }
                Err(e) => return Err(e.as_open_failure()),
            }
        }
        Err(OpenFailure::Unavailable)
    }
}

/// Admit a local connection and connect its upstream.
async fn route(
    ctx: &NodeContext,
    dest: &Destination,
    inbound: &str,
) -> Result<Upstream, OpenFailure> {
    let input = DecisionInput {
        destination: dest,
        inbound,
        node_id: None,
    };
    let admitted = match ctx.gate.admit(None, &input, now_unix()) {
        Ok(a) => a,
        Err(e) => {
            if let aegis_core::AdmitError::Denied(d) = &e {
                ctx.obs().record(Event::RouteDecision {
                    action: d.action,
                    class: d.rule_class,
                });
            }
            return Err(admit_failure(&e));
        }
    };
    ctx.obs().record(Event::RouteDecision {
        action: admitted.decision.action,
        class: admitted.decision.rule_class,
    });
    let outbound = admitted
        .decision
        .outbound
        .clone()
        .ok_or(OpenFailure::Internal)?;
    let ob = admitted
        .bundle
        .compiled
        .outbound(&outbound)
        .ok_or(OpenFailure::Internal)?;
    let timeout = Duration::from_millis(u64::from(
        admitted.bundle.compiled.config.core.open_timeout_ms,
    ));
    match ob.kind {
        OutboundKind::AgpTunnel => {
            let tunnel = ctx.tunnels.get(&outbound).ok_or(OpenFailure::Unavailable)?;
            tunnel.open(dest, timeout).await.map(Upstream::Mux)
        }
        OutboundKind::DirectTcp => dial_direct(ctx, &admitted, dest, inbound, None, timeout)
            .await
            .map(Upstream::Tcp),
    }
}

async fn run_relay(ctx: &NodeContext, mut local: TcpStream, mut upstream: Upstream) {
    ctx.obs().record(Event::StreamOpened);
    let _active = ActiveGuard::new(&ctx.streams_active);
    let idle = Duration::from_secs(u64::from(ctx.startup.core.idle_timeout_seconds));
    let outcome = relay(&mut local, &mut upstream, idle).await;
    match upstream {
        Upstream::Mux(m) => finish_mux(m, outcome, ctx.obs()),
        Upstream::Tcp(_) => {
            let result = match outcome {
                RelayOutcome::Completed => OperationResult::Ok,
                RelayOutcome::IdleTimeout => OperationResult::Timeout,
                RelayOutcome::Error(_) => OperationResult::Error,
            };
            ctx.obs().record(Event::StreamClosed {
                result,
                reason: ReasonGroup::Other,
            });
        }
    }
}

pub fn socks_credentials(
    ib: &InboundConfig,
    dir: &Path,
) -> Result<Option<aegis_inbound_socks::Credentials>, String> {
    match &ib.auth {
        Some(a) => {
            let pw = secret::read(dir, &a.password).map_err(|e| e.to_string())?;
            Ok(Some(aegis_inbound_socks::Credentials {
                username: a.username.as_bytes().to_vec(),
                password: pw.trim_end_matches(['\r', '\n']).as_bytes().to_vec(),
            }))
        }
        None => Ok(None),
    }
}

pub fn http_credentials(
    ib: &InboundConfig,
    dir: &Path,
) -> Result<Option<aegis_inbound_http::Credentials>, String> {
    match &ib.auth {
        Some(a) => {
            let pw = secret::read(dir, &a.password).map_err(|e| e.to_string())?;
            Ok(Some(aegis_inbound_http::Credentials {
                username: a.username.clone(),
                password: pw.trim_end_matches(['\r', '\n']).to_owned(),
            }))
        }
        None => Ok(None),
    }
}

pub async fn serve_socks(
    ctx: Arc<NodeContext>,
    inbound: InboundConfig,
    listener: TcpListener,
    credentials: Option<aegis_inbound_socks::Credentials>,
) {
    let cfg = Arc::new(SocksConfig {
        credentials,
        handshake_timeout: Duration::from_millis(u64::from(
            ctx.startup.core.inbound_handshake_timeout_ms,
        )),
    });
    let id: Arc<str> = Arc::from(inbound.id.as_str());
    let mut shutdown = ctx.shutdown_signal();
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.wait_for(|s| *s) => return,
        };
        let Ok((mut tcp, _)) = accepted else { continue };
        let ctx = Arc::clone(&ctx);
        let cfg = Arc::clone(&cfg);
        let id = Arc::clone(&id);
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let Ok(dest) = aegis_inbound_socks::handshake(&mut tcp, &cfg).await else {
                return;
            };
            match route(&ctx, &dest, &id).await {
                Ok(up) => {
                    let bound = match &up {
                        Upstream::Tcp(s) => s.local_addr().ok(),
                        Upstream::Mux(_) => None,
                    };
                    if aegis_inbound_socks::send_reply(&mut tcp, Reply::Succeeded, bound)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    run_relay(&ctx, tcp, up).await;
                }
                Err(f) => {
                    ctx.obs().record(Event::StreamClosed {
                        result: OperationResult::Denied,
                        reason: f.group(),
                    });
                    let _ = aegis_inbound_socks::send_reply(&mut tcp, Reply::for_failure(f), None)
                        .await;
                }
            }
        });
    }
}

pub async fn serve_http(
    ctx: Arc<NodeContext>,
    inbound: InboundConfig,
    listener: TcpListener,
    credentials: Option<aegis_inbound_http::Credentials>,
) {
    let cfg = Arc::new(HttpConnectConfig {
        credentials,
        handshake_timeout: Duration::from_millis(u64::from(
            ctx.startup.core.inbound_handshake_timeout_ms,
        )),
    });
    let id: Arc<str> = Arc::from(inbound.id.as_str());
    let mut shutdown = ctx.shutdown_signal();
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.wait_for(|s| *s) => return,
        };
        let Ok((mut tcp, _)) = accepted else { continue };
        let ctx = Arc::clone(&ctx);
        let cfg = Arc::clone(&cfg);
        let id = Arc::clone(&id);
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let Ok((dest, leftover)) = aegis_inbound_http::read_request(&mut tcp, &cfg).await
            else {
                return;
            };
            match route(&ctx, &dest, &id).await {
                Ok(mut up) => {
                    if aegis_inbound_http::respond_established(&mut tcp)
                        .await
                        .is_err()
                    {
                        return;
                    }
                    if !leftover.is_empty() && up.write_all(&leftover).await.is_err() {
                        return;
                    }
                    run_relay(&ctx, tcp, up).await;
                }
                Err(f) => {
                    ctx.obs().record(Event::StreamClosed {
                        result: OperationResult::Denied,
                        reason: f.group(),
                    });
                    let _ = aegis_inbound_http::respond_failure(&mut tcp, f).await;
                }
            }
        });
    }
}
