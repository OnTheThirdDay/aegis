//! Glue between a QUIC connection and the AGP session it carries: the
//! session sends small UDP-flow datagrams as QUIC datagrams ([`Path`]), and
//! a reader task hands received ones back to it.

use crate::NodeContext;
use aegis_session::{DatagramPath, Session};
use aegis_transport_quic::Connection;
use bytes::Bytes;
use std::sync::Arc;

/// A QUIC connection as the session's datagram path.
#[derive(Debug)]
pub(crate) struct Path(pub Connection);

impl DatagramPath for Path {
    fn max_packet(&self) -> Option<usize> {
        aegis_transport_quic::max_datagram(&self.0)
    }

    fn send(&self, packet: Bytes) -> bool {
        aegis_transport_quic::send_datagram(&self.0, packet)
    }
}

/// Deliver the connection's datagrams to `session` until either ends.
pub(crate) fn spawn_datagram_reader(ctx: &NodeContext, conn: Connection, session: &Arc<Session>) {
    ctx.spawn_connection(datagram_reader(conn, session));
}

/// The reader task: it holds the session weakly, so it never keeps an idle
/// session open, and closes the connection when the session ends.
pub(crate) fn datagram_reader(
    conn: Connection,
    session: &Arc<Session>,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let weak = Arc::downgrade(session);
    let mut closed = session.closed_signal();
    async move {
        loop {
            tokio::select! {
                d = conn.read_datagram() => match d {
                    Ok(d) => match weak.upgrade() {
                        Some(s) => s.deliver_datagram(d),
                        None => break,
                    },
                    Err(_) => break,
                },
                _ = closed.wait_for(|c| *c) => break,
            }
        }
        conn.close(0u32.into(), b"session closed");
    }
}
