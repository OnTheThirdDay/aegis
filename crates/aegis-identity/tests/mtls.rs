#![allow(clippy::panic)]
//! Inner mTLS acceptance: TC-P08, TC-P09 (handshake side), TC-P19.

use aegis_contracts::Role;
use aegis_identity::pki::{self, CaBundle, DEFAULT_NODE_VALIDITY};
use aegis_identity::tls::{self, HandshakeError, PeerIdentity};
use aegis_identity::{IdentitySnapshot, IdentityStore};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    ca: CaBundle,
    gw_cert: String,
    gw_key: String,
    client_cert: String,
    client_key: String,
}

fn fixture() -> Fixture {
    let ca = pki::generate_ca("test-ca", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let (gw_cert, gw_key) = pki::issue_direct(
        &ca,
        "gw-1",
        Role::Gateway,
        &["gateway.aegis.internal".into()],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("gw cert");
    // Client: key + CSR generated "on the client", CA signs the CSR.
    let (client_key, csr) = pki::generate_key_and_csr("client-1").expect("csr");
    let client_cert = pki::sign_csr(
        &ca,
        &csr,
        "client-1",
        Role::Client,
        &[],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("sign");
    Fixture {
        ca,
        gw_cert,
        gw_key,
        client_cert,
        client_key,
    }
}

async fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> (
    Result<PeerIdentity, HandshakeError>,
    Result<PeerIdentity, HandshakeError>,
) {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let srv = tokio::spawn(async move {
        match tls::accept(server, b, Duration::from_secs(5)).await {
            Ok((mut s, peer)) => {
                let mut buf = [0u8; 4];
                let _ = s.read_exact(&mut buf).await;
                let _ = s.write_all(&buf).await;
                let _ = s.flush().await;
                Ok(peer)
            }
            Err(e) => Err(e),
        }
    });
    let cli = match tls::connect(client, name, a, Duration::from_secs(5)).await {
        Ok((mut c, peer)) => {
            // In TLS 1.3 the server verifies the client certificate after the
            // client considers the handshake done; rejection shows up here.
            let mut buf = [0u8; 4];
            let echoed = async {
                c.write_all(b"ping").await?;
                c.read_exact(&mut buf).await?;
                Ok::<_, std::io::Error>(())
            }
            .await;
            match echoed {
                Ok(()) => {
                    assert_eq!(&buf, b"ping");
                    Ok(peer)
                }
                Err(e) => Err(HandshakeError::Tls(e)),
            }
        }
        Err(e) => Err(e),
    };
    (srv.await.expect("join"), cli)
}

#[tokio::test]
async fn mutual_tls_binds_identities() {
    let f = fixture();
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, store).expect("server");
    let client = tls::client_config(&f.client_cert, &f.client_key, &f.ca.cert_pem).expect("client");
    let (srv, cli) = handshake(server, client, "gateway.aegis.internal").await;
    let client_seen_by_server = srv.expect("server side ok");
    assert_eq!(client_seen_by_server.node_id, "client-1");
    assert_eq!(client_seen_by_server.role, Some(Role::Client));
    let gw_seen_by_client = cli.expect("client side ok");
    assert_eq!(gw_seen_by_client.node_id, "gw-1");
    assert_eq!(gw_seen_by_client.role, Some(Role::Gateway));
}

#[tokio::test]
async fn tc_p08_foreign_ca_client_rejected() {
    let f = fixture();
    let other = pki::generate_ca("other-ca", pki::DEFAULT_CA_VALIDITY).expect("ca2");
    let (rogue_cert, rogue_key) =
        pki::issue_direct(&other, "client-1", Role::Client, &[], DEFAULT_NODE_VALIDITY)
            .expect("rogue");
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, store).expect("server");
    let client = tls::client_config(&rogue_cert, &rogue_key, &f.ca.cert_pem).expect("client");
    let (srv, _cli) = handshake(server, client, "gateway.aegis.internal").await;
    assert!(
        srv.is_err(),
        "impersonating client with foreign CA must fail"
    );
}

#[tokio::test]
async fn tc_p08_server_impersonation_rejected() {
    let f = fixture();
    let other = pki::generate_ca("evil-ca", pki::DEFAULT_CA_VALIDITY).expect("ca2");
    let (evil_cert, evil_key) = pki::issue_direct(
        &other,
        "gw-1",
        Role::Gateway,
        &["gateway.aegis.internal".into()],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("evil");
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&evil_cert, &evil_key, &f.ca.cert_pem, store).expect("server");
    let client = tls::client_config(&f.client_cert, &f.client_key, &f.ca.cert_pem).expect("client");
    let (_srv, cli) = handshake(server, client, "gateway.aegis.internal").await;
    assert!(
        cli.is_err(),
        "client must reject a gateway from an untrusted CA"
    );
}

#[tokio::test]
async fn wrong_server_name_rejected() {
    let f = fixture();
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, store).expect("server");
    let client = tls::client_config(&f.client_cert, &f.client_key, &f.ca.cert_pem).expect("client");
    let (_srv, cli) = handshake(server, client, "other.example").await;
    assert!(cli.is_err());
}

#[tokio::test]
async fn role_separation_enforced_by_eku() {
    let f = fixture();
    // A gateway certificate cannot authenticate as a client.
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, store).expect("server");
    let client = tls::client_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem).expect("client");
    let (srv, _cli) = handshake(server, client, "gateway.aegis.internal").await;
    assert!(srv.is_err());
}

#[tokio::test]
async fn tc_p09_revoked_client_rejected_on_new_handshake() {
    let f = fixture();
    let fp = PeerIdentity::from_der(tls::parse_certs(&f.client_cert).expect("certs")[0].as_ref())
        .expect("peer")
        .fingerprint;
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, Arc::clone(&store))
        .expect("server");
    let client = tls::client_config(&f.client_cert, &f.client_key, &f.ca.cert_pem).expect("client");
    let (srv, _) = handshake(
        Arc::clone(&server),
        Arc::clone(&client),
        "gateway.aegis.internal",
    )
    .await;
    assert!(srv.is_ok());
    store.publish(store.current().with_revoked([fp]));
    let (srv, _) = handshake(server, client, "gateway.aegis.internal").await;
    assert!(
        srv.is_err(),
        "revoked identity must fail the next handshake"
    );
}

#[test]
fn tc_p19_resumption_and_early_data_disabled() {
    let f = fixture();
    let store = IdentityStore::new(IdentitySnapshot::default());
    let server = tls::server_config(&f.gw_cert, &f.gw_key, &f.ca.cert_pem, store).expect("server");
    assert_eq!(server.send_tls13_tickets, 0);
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.session_storage.can_cache());
    let client = tls::client_config(&f.client_cert, &f.client_key, &f.ca.cert_pem).expect("client");
    assert!(!client.enable_early_data);
}

#[test]
fn issuance_limits() {
    let ca = pki::generate_ca("ca", pki::DEFAULT_CA_VALIDITY).expect("ca");
    assert!(pki::issue_direct(&ca, "bad id", Role::Client, &[], DEFAULT_NODE_VALIDITY).is_err());
    assert!(pki::issue_direct(
        &ca,
        "ok",
        Role::Client,
        &[],
        Duration::from_secs(365 * 24 * 3600)
    )
    .is_err());
    // CSR subject is ignored: the CA decides the node id and role.
    let (_k, csr) = pki::generate_key_and_csr("requested-name").expect("csr");
    let cert = pki::sign_csr(
        &ca,
        &csr,
        "assigned-name",
        Role::Client,
        &[],
        DEFAULT_NODE_VALIDITY,
    )
    .expect("sign");
    let peer = PeerIdentity::from_der(tls::parse_certs(&cert).expect("c")[0].as_ref()).expect("p");
    assert_eq!(peer.node_id, "assigned-name");
}
