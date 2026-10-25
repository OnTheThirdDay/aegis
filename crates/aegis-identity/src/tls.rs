//! Inner mTLS 1.3 configuration.

use crate::pki::{role_ou, MAX_NODE_VALIDITY};
use crate::store::IdentityStore;
use crate::{valid_node_id, IdentityError};
use aegis_contracts::Role;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::Resumption;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::{Error as PemError, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore,
    ServerConfig, SignatureScheme,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// ALPN for the inner channel; distinct from any outer HTTP ALPN.
pub const ALPN_AGP1: &[u8] = b"agp/1";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn parse_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, IdentityError> {
    let certs: Result<Vec<_>, _> = CertificateDer::pem_slice_iter(pem.as_bytes()).collect();
    let certs = certs.map_err(|_| IdentityError::Pem("certificate"))?;
    if certs.is_empty() {
        return Err(IdentityError::Pem("no certificate found"));
    }
    Ok(certs)
}

pub fn parse_key(pem: &str) -> Result<PrivateKeyDer<'static>, IdentityError> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(|e| match e {
        PemError::NoItemsFound => IdentityError::Pem("no private key found"),
        _ => IdentityError::Pem("private key"),
    })
}

pub fn root_store(ca_pem: &str) -> Result<RootCertStore, IdentityError> {
    validate_ca_certificates(ca_pem)?;
    let mut roots = RootCertStore::empty();
    for cert in parse_certs(ca_pem)? {
        roots
            .add(cert)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    }
    Ok(roots)
}

pub fn validate_ca_certificates(pem: &str) -> Result<(), IdentityError> {
    let certs = parse_certs(pem)?;
    if certs.len() > 16 {
        return Err(IdentityError::Pem("too many trust anchors"));
    }
    for der in certs {
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref())
            .map_err(|_| IdentityError::Pem("CA"))?;
        if !cert.is_ca() || !cert.validity().is_valid() {
            return Err(IdentityError::Certificate(
                "invalid or expired CA trust anchor".into(),
            ));
        }
    }
    Ok(())
}

pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

pub fn certificate_expiry(der: &[u8]) -> Result<i64, IdentityError> {
    let (rest, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|_| IdentityError::Pem("certificate"))?;
    if !rest.is_empty() {
        return Err(IdentityError::Pem("trailing certificate bytes"));
    }
    Ok(cert.validity().not_after.timestamp())
}

/// Public/direct TLS is independent from device PKI. Validate the staged
/// server chain, DNS SAN, EKU, expiry and key match before publishing it.
pub fn public_server_config(
    cert_pem: &str,
    key_pem: &str,
    server_name: &str,
    custom_ca: Option<&str>,
) -> Result<Arc<ServerConfig>, IdentityError> {
    use rustls::client::danger::ServerCertVerifier;
    let certs = parse_certs(cert_pem)?;
    let roots = match custom_ca {
        Some(pem) => root_store(pem)?,
        None => RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    };
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .map_err(|_| IdentityError::Certificate("server verifier unavailable".into()))?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| IdentityError::Certificate("invalid server DNS name".into()))?;
    verifier.verify_server_cert(&certs[0], &certs[1..], &name, &[], UnixTime::now())?;
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, parse_key(key_pem)?)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// A validated outer certificate for SNI-based selection: exactly the checks
/// of [`public_server_config`] (chain, name, expiry, key match), returned as
/// a signing key instead of a whole server configuration.
pub fn certified_key(
    cert_pem: &str,
    key_pem: &str,
    server_name: &str,
    custom_ca: Option<&str>,
) -> Result<Arc<rustls::sign::CertifiedKey>, IdentityError> {
    public_server_config(cert_pem, key_pem, server_name, custom_ca)?;
    let certs = parse_certs(cert_pem)?;
    let key = provider()
        .key_provider
        .load_private_key(parse_key(key_pem)?)
        .map_err(|_| IdentityError::Certificate("unsupported private key".into()))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(certs, key)))
}

/// Outer server configuration choosing its certificate by SNI, with the same
/// protocol policy as [`public_server_config`].
pub fn sni_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> Result<Arc<ServerConfig>, IdentityError> {
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Validate imported/offline enrollment before placing it in the registry.
/// No private device key is accepted by the gateway.
pub fn validate_client_certificate(
    cert_pem: &str,
    ca_pem: &str,
) -> Result<PeerIdentity, IdentityError> {
    let certs = parse_certs(cert_pem)?;
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(root_store(ca_pem)?), provider())
            .build()
            .map_err(|_| IdentityError::Certificate("client verifier unavailable".into()))?;
    verifier.verify_client_cert(&certs[0], &certs[1..], UnixTime::now())?;
    let peer = PeerIdentity::from_der(certs[0].as_ref())?;
    if peer.role != Some(Role::Client)
        || peer.not_after - peer.not_before > MAX_NODE_VALIDITY.as_secs() as i64 + 600
    {
        return Err(IdentityError::Certificate(
            "device certificate policy rejected".into(),
        ));
    }
    Ok(peer)
}

/// Authenticated identity of the remote endpoint, extracted after the TLS
/// handshake completes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdentity {
    pub node_id: String,
    pub role: Option<Role>,
    pub fingerprint: [u8; 32],
    pub serial_hex: String,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    /// Version 1 URI SAN; false only for explicitly bounded legacy migration.
    pub san_identity: bool,
}

impl PeerIdentity {
    pub fn from_der(der: &[u8]) -> Result<PeerIdentity, IdentityError> {
        if der.len() > 64 * 1024 {
            return Err(IdentityError::Pem("leaf certificate too large"));
        }
        let (remaining, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| IdentityError::Certificate(e.to_string()))?;
        if !remaining.is_empty() {
            return Err(IdentityError::Certificate(
                "trailing certificate data".into(),
            ));
        }
        let subject = cert.subject();
        if subject.iter_common_name().count() != 1
            || subject.iter_organizational_unit().count() != 1
        {
            return Err(IdentityError::Certificate(
                "ambiguous subject identity".into(),
            ));
        }
        let node_id = subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .ok_or_else(|| IdentityError::Certificate("missing CN".into()))?
            .to_owned();
        if !valid_node_id(&node_id) {
            return Err(IdentityError::InvalidNodeId);
        }
        let role = subject
            .iter_organizational_unit()
            .next()
            .and_then(|ou| ou.as_str().ok())
            .and_then(|ou| match ou {
                "gateway" => Some(Role::Gateway),
                "client" => Some(Role::Client),
                _ => None,
            });
        let mut identities = Vec::new();
        if let Some(san) = cert
            .subject_alternative_name()
            .map_err(|_| IdentityError::Certificate("ambiguous SAN extension".into()))?
        {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if uri.starts_with("urn:aegis:") {
                        identities.push(*uri);
                    }
                }
            }
        }
        let san_identity = !identities.is_empty();
        if san_identity
            && (identities.len() != 1
                || role.is_none()
                || identities[0]
                    != crate::pki::node_uri(&node_id, role.ok_or(IdentityError::InvalidNodeId)?))
        {
            return Err(IdentityError::Certificate(
                "invalid or ambiguous node URI SAN".into(),
            ));
        }
        let validity = cert.validity();
        Ok(PeerIdentity {
            node_id,
            role,
            fingerprint: fingerprint(der),
            serial_hex: hex::encode(cert.raw_serial()),
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
            san_identity,
        })
    }

    pub fn fingerprint_hex(&self) -> String {
        hex::encode(self.fingerprint)
    }

    pub fn is_expired_at(&self, unix_now: i64) -> bool {
        unix_now >= self.not_after || unix_now < self.not_before
    }

    pub fn from_connection(conn: &rustls::CommonState) -> Result<PeerIdentity, IdentityError> {
        let certs = conn
            .peer_certificates()
            .ok_or_else(|| IdentityError::Certificate("no peer certificate".into()))?;
        let leaf = certs
            .first()
            .ok_or_else(|| IdentityError::Certificate("empty peer chain".into()))?;
        PeerIdentity::from_der(leaf.as_ref())
    }
}

/// Client verifier: WebPKI chain validation against the configured client CA,
/// then local policy: role OU must be `client`, validity span must not exceed
/// the maximum node lifetime, and the certificate must not be revoked in the
/// current snapshot.
#[derive(Debug)]
struct PolicyClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    store: Arc<IdentityStore>,
}

impl ClientCertVerifier for PolicyClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let peer = PeerIdentity::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if peer.role != Some(Role::Client) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        if peer.not_after - peer.not_before > MAX_NODE_VALIDITY.as_secs() as i64 + 600 {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        let snapshot = self.store.current();
        if snapshot.is_revoked(&peer.fingerprint) {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Revoked));
        }
        if !snapshot.authorizes(&peer, now.as_secs() as i64) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Gateway-side inner TLS: TLS 1.3 only, mandatory client certificates, no
/// session storage, no tickets, no early data.
pub fn server_config(
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: &str,
    store: Arc<IdentityStore>,
) -> Result<Arc<ServerConfig>, IdentityError> {
    let provider = provider();
    let roots = Arc::new(root_store(client_ca_pem)?);
    let inner = WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(&provider))
        .build()
        .map_err(|e| IdentityError::Certificate(e.to_string()))?;
    let verifier = Arc::new(PolicyClientVerifier { inner, store });
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(parse_certs(cert_pem)?, parse_key(key_pem)?)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![ALPN_AGP1.to_vec()];
    Ok(Arc::new(config))
}

/// Client-side inner TLS: TLS 1.3 only, explicit server CA (no public roots,
/// no TOFU), client certificate, resumption and early data disabled.
pub fn client_config(
    cert_pem: &str,
    key_pem: &str,
    server_ca_pem: &str,
) -> Result<Arc<ClientConfig>, IdentityError> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store(server_ca_pem)?)
        .with_client_auth_cert(parse_certs(cert_pem)?, parse_key(key_pem)?)?;
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.alpn_protocols = vec![ALPN_AGP1.to_vec()];
    Ok(Arc::new(config))
}

#[derive(Debug)]
pub enum HandshakeError {
    Timeout,
    Tls(std::io::Error),
    Identity(IdentityError),
    /// Peer certificate role is not the expected one.
    WrongRole,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Timeout => f.write_str("TLS handshake timed out"),
            HandshakeError::Tls(e) => write!(f, "TLS handshake failed: {e}"),
            HandshakeError::Identity(e) => write!(f, "peer identity invalid: {e}"),
            HandshakeError::WrongRole => f.write_str("peer certificate has the wrong role"),
        }
    }
}

impl std::error::Error for HandshakeError {}

pub type ServerTls<T> = tokio_rustls::server::TlsStream<T>;
pub type ClientTls<T> = tokio_rustls::client::TlsStream<T>;

/// Accept the inner TLS handshake; nothing is read as a proxy command until
/// this completes successfully.
pub async fn accept<T>(
    config: Arc<ServerConfig>,
    io: T,
    timeout: Duration,
) -> Result<(ServerTls<T>, PeerIdentity), HandshakeError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let tls = tokio::time::timeout(timeout, TlsAcceptor::from(config).accept(io))
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(HandshakeError::Tls)?;
    let peer = PeerIdentity::from_connection(tls.get_ref().1).map_err(HandshakeError::Identity)?;
    if peer.role != Some(Role::Client) {
        return Err(HandshakeError::WrongRole);
    }
    Ok((tls, peer))
}

pub async fn connect<T>(
    config: Arc<ClientConfig>,
    server_name: &str,
    io: T,
    timeout: Duration,
) -> Result<(ClientTls<T>, PeerIdentity), HandshakeError>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let name = ServerName::try_from(server_name.to_owned()).map_err(|_| {
        HandshakeError::Identity(IdentityError::Certificate("invalid server name".into()))
    })?;
    let tls = tokio::time::timeout(timeout, TlsConnector::from(config).connect(name, io))
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(HandshakeError::Tls)?;
    let peer = PeerIdentity::from_connection(tls.get_ref().1).map_err(HandshakeError::Identity)?;
    if peer.role != Some(Role::Gateway) {
        return Err(HandshakeError::WrongRole);
    }
    if peer.not_after - peer.not_before > MAX_NODE_VALIDITY.as_secs() as i64 + 600
        || (!peer.san_identity && UnixTime::now().as_secs() >= 1_800_662_400)
    {
        return Err(HandshakeError::Identity(IdentityError::Certificate(
            "gateway identity policy rejected".into(),
        )));
    }
    Ok((tls, peer))
}

/// For diagnostics: the OU string a role is encoded with.
pub fn expected_ou(role: Role) -> &'static str {
    role_ou(role)
}
