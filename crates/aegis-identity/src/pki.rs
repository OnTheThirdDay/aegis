//! Local CA operations: CA generation, node key/CSR generation and signing.

use crate::{valid_node_id, IdentityError};
use aegis_contracts::Role;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use std::time::Duration;
use time::OffsetDateTime;

/// Default node certificate lifetime ("short-lived"); renewal re-enrolls.
pub const DEFAULT_NODE_VALIDITY: Duration = Duration::from_secs(30 * 24 * 3600);
/// Peers presenting certificates valid for longer than this are rejected.
pub const MAX_NODE_VALIDITY: Duration = Duration::from_secs(90 * 24 * 3600);
pub const DEFAULT_CA_VALIDITY: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// PEM-encoded CA certificate and private key. The key is secret material.
#[derive(Clone)]
pub struct CaBundle {
    pub cert_pem: String,
    pub key_pem: String,
}

impl std::fmt::Debug for CaBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaBundle")
            .field("key_pem", &"<redacted>")
            .finish_non_exhaustive()
    }
}

pub fn role_ou(role: Role) -> &'static str {
    match role {
        Role::Gateway => "gateway",
        Role::Client => "client",
    }
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f; // positive
    bytes[0] |= 0x01; // non-zero leading byte
    SerialNumber::from_slice(&bytes)
}

fn validity(params: &mut CertificateParams, lifetime: Duration) {
    let now = OffsetDateTime::now_utc();
    // Small backdate tolerates clock skew between CA and peers.
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::seconds(lifetime.as_secs() as i64);
}

pub fn generate_ca(common_name: &str, lifetime: Duration) -> Result<CaBundle, IdentityError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "AegisNet local CA");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.serial_number = Some(random_serial());
    validity(&mut params, lifetime);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok(CaBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Generate a node private key locally and a CSR naming the node.
/// Returns `(key_pem, csr_pem)`; the key never leaves the node.
pub fn generate_key_and_csr(node_id: &str) -> Result<(String, String), IdentityError> {
    if !valid_node_id(node_id) {
        return Err(IdentityError::InvalidNodeId);
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_id);
    params.distinguished_name = dn;
    let key = KeyPair::generate()?;
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.pem()?))
}

fn node_params(
    node_id: &str,
    role: Role,
    server_names: &[String],
    lifetime: Duration,
) -> Result<CertificateParams, IdentityError> {
    if !valid_node_id(node_id) {
        return Err(IdentityError::InvalidNodeId);
    }
    if lifetime > MAX_NODE_VALIDITY {
        return Err(IdentityError::Certificate(
            "requested lifetime exceeds maximum node validity".into(),
        ));
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_id);
    dn.push(DnType::OrganizationalUnitName, role_ou(role));
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![match role {
        Role::Gateway => ExtendedKeyUsagePurpose::ServerAuth,
        Role::Client => ExtendedKeyUsagePurpose::ClientAuth,
    }];
    if role == Role::Gateway {
        for name in server_names {
            let san = name
                .clone()
                .try_into()
                .map_err(|_| IdentityError::Certificate("invalid server name".into()))?;
            params.subject_alt_names.push(SanType::DnsName(san));
        }
    }
    params.serial_number = Some(random_serial());
    params.use_authority_key_identifier_extension = true;
    validity(&mut params, lifetime);
    Ok(params)
}

/// Issuer built from the stored CA certificate itself, so issued certificates
/// carry the CA's exact subject and key identifier.
fn load_ca(ca: &CaBundle) -> Result<Issuer<'static, KeyPair>, IdentityError> {
    let key = KeyPair::from_pem(&ca.key_pem)?;
    Ok(Issuer::from_ca_cert_pem(&ca.cert_pem, key)?)
}

/// Sign a node CSR. Only the CSR's public key is used: subject, role, SANs,
/// EKU and lifetime are set by the CA, never taken from the request.
pub fn sign_csr(
    ca: &CaBundle,
    csr_pem: &str,
    node_id: &str,
    role: Role,
    server_names: &[String],
    lifetime: Duration,
) -> Result<String, IdentityError> {
    if csr_pem.len() > 16 * 1024 {
        return Err(IdentityError::Pem("CSR too large"));
    }
    let issuer = load_ca(ca)?;
    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    csr.params = node_params(node_id, role, server_names, lifetime)?;
    let cert = csr.signed_by(&issuer)?;
    Ok(cert.pem())
}

/// Convenience for bootstrap/testing: generate a key and certificate in one
/// step on the CA host. Prefer CSR enrollment for remote nodes.
pub fn issue_direct(
    ca: &CaBundle,
    node_id: &str,
    role: Role,
    server_names: &[String],
    lifetime: Duration,
) -> Result<(String, String), IdentityError> {
    let issuer = load_ca(ca)?;
    let params = node_params(node_id, role, server_names, lifetime)?;
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &issuer)?;
    Ok((cert.pem(), key.serialize_pem()))
}
