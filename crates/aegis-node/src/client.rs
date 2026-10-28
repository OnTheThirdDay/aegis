//! Client side: local SOCKS5/HTTP CONNECT inbounds, admission, and the AGP
//! tunnel outbound (one multiplexed session per gateway, reconnected with
//! bounded backoff; never a silent direct fallback).

use crate::egress::{admit_failure, bind_direct_udp, dial_direct};
use crate::relay::{
    finish_flow, finish_mux, relay, ActiveGuard, DatagramUpstream, RelayOutcome, Upstream, UDP_IDLE,
};
use crate::{now_unix, LoadedIdentity, NodeContext};
use aegis_buffer::Budget;
use aegis_config::{secret, InboundConfig, NodeConfig, OutboundConfig, OutboundKind};
use aegis_contracts::observability::{Event, Observability, OperationResult};
use aegis_contracts::reason::{OpenFailure, ReasonGroup, ResetReason};
use aegis_contracts::Destination;
use aegis_core::{Backoff, CircuitBreaker};
use aegis_identity::tls;
use aegis_inbound_http::HttpConnectConfig;
use aegis_inbound_socks::{Command, Reply, SocksConfig};
use aegis_policy::DecisionInput;
use aegis_session::{client_handshake, DatagramFlow, MuxStream, OpenError, Session, SessionConfig};
use aegis_telemetry::{LocalMetrics, Severity};
use aegis_transport_ws::WsClientConfig;
use std::net::SocketAddr;
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
    outbound: OutboundConfig,
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
            outbound: ob.clone(),
            ws: WsClientConfig {
                url: ob.url.clone().unwrap_or_default(),
                outer_ca_pem,
                outer_server_name: ob.outer_server_name.clone(),
                connect_addresses: {
                    let port = aegis_transport_ws::parse_url(ob.url.as_deref().unwrap_or(""))
                        .map(|u| u.port)
                        .unwrap_or(443);
                    ob.connect_addresses
                        .iter()
                        .filter_map(|a| aegis_config::connect_address(a, port))
                        .collect()
                },
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
                datagrams: true,
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

    /// Stop new streams on the current session (graceful shutdown).
    pub(crate) async fn goaway(&self) {
        if let Some(s) = &self.state.lock().await.session {
            s.goaway();
        }
    }

    /// Close the current session; its streams fail immediately.
    pub(crate) async fn close(&self, reason: ResetReason) {
        let mut st = self.state.lock().await;
        if let Some(s) = st.session.take() {
            s.close(reason);
        }
        self.connected
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn connected(&self) -> bool {
        self.connected.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn matches(&self, outbound: &OutboundConfig) -> bool {
        &self.outbound == outbound
    }

    /// Note why an attempt failed for on-demand diagnostics (a no-op unless
    /// a recording is running).
    /// `kind` refines the WebSocket stage: `connect`/`timeout` (nothing
    /// answered), `tls`, `http` (an HTTP status instead of an upgrade).
    fn note_failure(
        &self,
        stage: &str,
        kind: &str,
        reason: ReasonGroup,
        error: &dyn std::fmt::Display,
    ) {
        if let Some(d) = self.obs.diagnostics().filter(|d| d.is_recording()) {
            d.note(
                Severity::Warn,
                "client.connect.failed",
                &[
                    ("stage", stage),
                    ("kind", kind),
                    ("reason", reason.as_str()),
                    ("error", &error.to_string()),
                ],
            );
        }
    }

    async fn connect_once(&self) -> Result<Session, ReasonGroup> {
        let started = Instant::now();
        let ws = aegis_transport_ws::connect(&self.ws).await.map_err(|e| {
            let kind = match &e {
                aegis_transport_ws::WsError::Connect(_) => "connect",
                aegis_transport_ws::WsError::Timeout => "timeout",
                aegis_transport_ws::WsError::Tls(_) => "tls",
                aegis_transport_ws::WsError::Handshake(_) => "http",
                _ => "config",
            };
            self.note_failure("websocket", kind, ReasonGroup::Transport, &e);
            ReasonGroup::Transport
        })?;
        let (tls_stream, gateway) = tls::connect(
            Arc::clone(&self.tls),
            &self.server_name,
            ws,
            self.tls_timeout,
        )
        .await
        .map_err(|e| {
            self.note_failure("tls", "inner", ReasonGroup::Tls, &e);
            ReasonGroup::Tls
        })?;
        let obs: Arc<dyn Observability> = self.obs.clone();
        let mut session_cfg = self.session_cfg.clone();
        session_cfg.expected_peer_node_id = Some(gateway.node_id);
        let session = client_handshake(
            tls_stream,
            session_cfg,
            self.budget.child(self.peer_budget),
            obs,
        )
        .await
        .map_err(|e| {
            self.note_failure("session", "agp", e.reason_group(), &e);
            e.reason_group()
        })?;
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

    /// Open a UDP flow, with the same retry rule as [`open`](Self::open).
    /// A gateway without UDP support refuses it as unsupported.
    pub async fn open_datagram(
        &self,
        dest: &Destination,
        timeout: Duration,
    ) -> Result<DatagramFlow, OpenFailure> {
        for _ in 0..2 {
            let s = self.session().await?;
            match s.open_datagram(dest.clone(), timeout).await {
                Ok(f) => return Ok(f),
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
    let (admitted, ob, timeout) = admit(ctx, dest, inbound)?;
    match ob.kind {
        OutboundKind::AgpTunnel => {
            let tunnel = ctx
                .tunnel_for(&ob, &admitted.bundle.compiled.config)
                .await?;
            tunnel.open(dest, timeout).await.map(Upstream::Mux)
        }
        OutboundKind::DirectTcp => dial_direct(ctx, &admitted, dest, inbound, None, timeout)
            .await
            .map(Upstream::Tcp),
    }
}

/// Admit a local UDP flow and open its upstream: a tunnel flow, or for a
/// direct route a socket under the same egress checks as a direct dial.
async fn route_udp(
    ctx: &NodeContext,
    dest: &Destination,
    inbound: &str,
) -> Result<DatagramUpstream, OpenFailure> {
    let (admitted, ob, timeout) = admit(ctx, dest, inbound)?;
    match ob.kind {
        OutboundKind::AgpTunnel => {
            let tunnel = ctx
                .tunnel_for(&ob, &admitted.bundle.compiled.config)
                .await?;
            tunnel
                .open_datagram(dest, timeout)
                .await
                .map(DatagramUpstream::Flow)
        }
        OutboundKind::DirectTcp => bind_direct_udp(ctx, &admitted, dest, inbound, None, timeout)
            .await
            .map(DatagramUpstream::Socket),
    }
}

/// Admission of a local connection or flow: the decision, its outbound and
/// the open timeout.
fn admit(
    ctx: &NodeContext,
    dest: &Destination,
    inbound: &str,
) -> Result<(aegis_core::Admitted, OutboundConfig, Duration), OpenFailure> {
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
        .ok_or(OpenFailure::Internal)?
        .clone();
    let timeout = Duration::from_millis(u64::from(
        admitted.bundle.compiled.config.core.open_timeout_ms,
    ));
    Ok((admitted, ob, timeout))
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

/// Forward one plain-HTTP request. The rebuilt head and exactly the declared
/// body go upstream while the response streams back concurrently (so an
/// origin's `100 Continue` reaches a client waiting for it). After the body,
/// further client bytes are discarded, so a reused client connection can
/// never send a second request to this destination; a client that
/// half-closes after its request still receives the whole response.
/// Upgrades relay both directions.
async fn run_forward(
    ctx: &NodeContext,
    mut local: TcpStream,
    mut upstream: Upstream,
    request: aegis_inbound_http::Forward,
    leftover: bytes::Bytes,
) {
    use tokio::io::AsyncReadExt;
    ctx.obs().record(Event::StreamOpened);
    let _active = ActiveGuard::new(&ctx.streams_active);
    let idle = Duration::from_secs(u64::from(ctx.startup.core.idle_timeout_seconds));
    let timed_out = || std::io::Error::from(std::io::ErrorKind::TimedOut);
    let outcome: std::io::Result<Option<RelayOutcome>> = async {
        if request.upgrade {
            upstream.write_all(&request.head).await?;
            upstream.write_all(&leftover).await?;
            upstream.flush().await?;
            return Ok(Some(relay(&mut local, &mut upstream, idle).await));
        }
        let (mut local_read, mut local_write) = local.split();
        let (mut up_read, mut up_write) = tokio::io::split(&mut upstream);
        let upload = async {
            up_write.write_all(&request.head).await?;
            let first = leftover
                .len()
                .min(usize::try_from(request.body_len).unwrap_or(usize::MAX));
            up_write.write_all(&leftover[..first]).await?;
            let mut remaining = request.body_len - first as u64;
            let mut buf = vec![0u8; 16 * 1024];
            while remaining > 0 {
                let want = buf
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let n = tokio::time::timeout(idle, local_read.read(&mut buf[..want]))
                    .await
                    .map_err(|_| timed_out())??;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                up_write.write_all(&buf[..n]).await?;
                remaining -= n as u64;
            }
            up_write.flush().await?;
            // Anything after the declared body is never forwarded.
            while local_read.read(&mut buf).await? != 0 {}
            Ok::<_, std::io::Error>(())
        };
        let download = async {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = tokio::time::timeout(idle, up_read.read(&mut buf))
                    .await
                    .map_err(|_| timed_out())??;
                if n == 0 {
                    break;
                }
                local_write.write_all(&buf[..n]).await?;
            }
            local_write.flush().await?;
            Ok::<_, std::io::Error>(())
        };
        tokio::pin!(upload, download);
        let mut uploaded = false;
        loop {
            tokio::select! {
                r = &mut download => return r.map(|_| None),
                r = &mut upload, if !uploaded => match r {
                    // The client finished (or half-closed): keep streaming
                    // the response until the origin closes.
                    Ok(()) => uploaded = true,
                    Err(e) => return Err(e),
                },
            }
        }
    }
    .await;
    let outcome = match outcome {
        Ok(Some(relayed)) => relayed,
        Ok(None) => RelayOutcome::Completed,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => RelayOutcome::IdleTimeout,
        Err(e) => RelayOutcome::Error(e.kind()),
    };
    match upstream {
        Upstream::Mux(m) => finish_mux(m, outcome, ctx.obs()),
        Upstream::Tcp(_) => ctx.obs().record(Event::StreamClosed {
            result: match outcome {
                RelayOutcome::Completed => OperationResult::Ok,
                RelayOutcome::IdleTimeout => OperationResult::Timeout,
                RelayOutcome::Error(_) => OperationResult::Error,
            },
            reason: ReasonGroup::Other,
        }),
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
        Arc::clone(&ctx).spawn_connection(async move {
            let _ = tcp.set_nodelay(true);
            let dest = match aegis_inbound_socks::handshake(&mut tcp, &cfg).await {
                Ok(Command::Connect(dest)) => dest,
                Ok(Command::UdpAssociate { from_port }) => {
                    udp_associate(ctx, tcp, id, from_port).await;
                    return;
                }
                Err(_) => return,
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

/// UDP flows one association carries at once; datagrams to further
/// destinations are dropped until one ends.
const ASSOCIATION_FLOWS: usize = 64;
/// Datagrams waiting for a flow (its upstream may still be opening).
const FLOW_QUEUE: usize = 32;

/// A SOCKS5 UDP association: a relay socket on the address the client
/// reached us on, accepting datagrams only from the client's host (and the
/// port it named, if any). Each destination becomes its own admitted flow
/// (a tunnel UDP flow or a direct socket); the association, and with it
/// every flow, ends when the client closes the control connection.
async fn udp_associate(
    ctx: Arc<NodeContext>,
    mut control: TcpStream,
    inbound: Arc<str>,
    from_port: Option<u16>,
) {
    use std::collections::HashMap;
    use tokio::io::AsyncReadExt;
    let (Ok(local), Ok(client)) = (control.local_addr(), control.peer_addr()) else {
        return;
    };
    let relay = match tokio::net::UdpSocket::bind((local.ip(), 0)).await {
        Ok(s) => Arc::new(s),
        Err(_) => {
            let _ =
                aegis_inbound_socks::send_reply(&mut control, Reply::GeneralFailure, None).await;
            return;
        }
    };
    let bound = relay.local_addr().ok();
    if aegis_inbound_socks::send_reply(&mut control, Reply::Succeeded, bound)
        .await
        .is_err()
    {
        return;
    }
    // Replies go to wherever the client's first datagram came from.
    let mut peer: Option<SocketAddr> = None;
    let mut flows: HashMap<Destination, tokio::sync::mpsc::Sender<bytes::Bytes>> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut probe = [0u8; 1];
    let mut shutdown = ctx.shutdown_signal();
    loop {
        let (n, from) = tokio::select! {
            r = relay.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(_) => continue,
            },
            // The client closes the control connection to end the
            // association (and anything it sends on it is ignored).
            r = control.read(&mut probe) => match r {
                Ok(n) if n > 0 => continue,
                _ => break,
            },
            _ = shutdown.wait_for(|s| *s) => break,
        };
        if from.ip() != client.ip() || from_port.is_some_and(|p| p != from.port()) {
            continue;
        }
        if *peer.get_or_insert(from) != from {
            continue;
        }
        let Some((dest, data)) = aegis_inbound_socks::parse_udp(&buf[..n]) else {
            continue;
        };
        let data = bytes::Bytes::copy_from_slice(data);
        if let Some(tx) = flows.get(&dest) {
            match tx.try_send(data) {
                Ok(()) => continue,
                // Full: this datagram is lost, as UDP allows.
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => continue,
                // The flow ended (idle or refused): start a new one below.
                Err(tokio::sync::mpsc::error::TrySendError::Closed(data)) => {
                    flows.remove(&dest);
                    if let Some(tx) = start_flow(&ctx, &inbound, &relay, from, &dest, &mut flows) {
                        let _ = tx.try_send(data);
                    }
                }
            }
        } else {
            flows.retain(|_, tx| !tx.is_closed());
            if let Some(tx) = start_flow(&ctx, &inbound, &relay, from, &dest, &mut flows) {
                let _ = tx.try_send(data);
            }
        }
    }
}

/// Start the flow task for `dest` in an association, unless it is full.
fn start_flow(
    ctx: &Arc<NodeContext>,
    inbound: &Arc<str>,
    relay: &Arc<tokio::net::UdpSocket>,
    client: SocketAddr,
    dest: &Destination,
    flows: &mut std::collections::HashMap<Destination, tokio::sync::mpsc::Sender<bytes::Bytes>>,
) -> Option<tokio::sync::mpsc::Sender<bytes::Bytes>> {
    if flows.len() >= ASSOCIATION_FLOWS {
        return None;
    }
    let (tx, rx) = tokio::sync::mpsc::channel(FLOW_QUEUE);
    flows.insert(dest.clone(), tx.clone());
    ctx.spawn_connection(udp_flow(
        Arc::clone(ctx),
        Arc::clone(inbound),
        Arc::clone(relay),
        client,
        dest.clone(),
        rx,
    ));
    Some(tx)
}

/// One destination of an association: admit and open the upstream, then
/// carry datagrams both ways until the association drops it or it idles.
async fn udp_flow(
    ctx: Arc<NodeContext>,
    inbound: Arc<str>,
    relay: Arc<tokio::net::UdpSocket>,
    client: SocketAddr,
    dest: Destination,
    mut rx: tokio::sync::mpsc::Receiver<bytes::Bytes>,
) {
    let upstream = match route_udp(&ctx, &dest, &inbound).await {
        Ok(u) => u,
        Err(f) => {
            ctx.obs().record(Event::StreamClosed {
                result: OperationResult::Denied,
                reason: f.group(),
            });
            return;
        }
    };
    ctx.obs().record(Event::StreamOpened);
    let _active = ActiveGuard::new(&ctx.streams_active);
    let mut buf = vec![0u8; 64 * 1024];
    let mut deadline = tokio::time::Instant::now() + UDP_IDLE;
    let outcome = loop {
        tokio::select! {
            d = rx.recv() => match d {
                Some(d) => {
                    deadline = tokio::time::Instant::now() + UDP_IDLE;
                    if let Err(e) = upstream.send(&d).await {
                        break RelayOutcome::Error(e.kind());
                    }
                }
                None => break RelayOutcome::Completed,
            },
            r = upstream.recv(&mut buf) => match r {
                Ok(d) => {
                    deadline = tokio::time::Instant::now() + UDP_IDLE;
                    let _ = relay
                        .send_to(&aegis_inbound_socks::encode_udp(&dest, &d), client)
                        .await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    break RelayOutcome::Completed
                }
                Err(e) => break RelayOutcome::Error(e.kind()),
            },
            _ = tokio::time::sleep_until(deadline) => break RelayOutcome::IdleTimeout,
        }
    };
    match upstream {
        DatagramUpstream::Flow(f) => finish_flow(f, outcome, ctx.obs()),
        DatagramUpstream::Socket(_) => ctx.obs().record(Event::StreamClosed {
            result: match outcome {
                RelayOutcome::Completed => OperationResult::Ok,
                RelayOutcome::IdleTimeout => OperationResult::Timeout,
                RelayOutcome::Error(_) => OperationResult::Error,
            },
            reason: ReasonGroup::Other,
        }),
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
        Arc::clone(&ctx).spawn_connection(async move {
            let _ = tcp.set_nodelay(true);
            let Ok((request, leftover)) = aegis_inbound_http::read_any(&mut tcp, &cfg).await else {
                return;
            };
            let dest = match request {
                aegis_inbound_http::Request::Connect(d) => d,
                aegis_inbound_http::Request::Forward(f) => {
                    match route(&ctx, &f.dest, &id).await {
                        Ok(up) => run_forward(&ctx, tcp, up, f, leftover).await,
                        Err(e) => {
                            ctx.obs().record(Event::StreamClosed {
                                result: OperationResult::Denied,
                                reason: e.group(),
                            });
                            let _ = aegis_inbound_http::respond_failure(&mut tcp, e).await;
                        }
                    }
                    return;
                }
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
