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
pub const NODE_URI_PREFIX: &str = "urn:aegis:node:v1:";

pub fn node_uri(node_id: &str, role: Role) -> String {
    format!("{NODE_URI_PREFIX}{}:{node_id}", role_ou(role))
}

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

/// Fresh key and DER CSR for a public (ACME) server certificate.
pub fn server_key_and_csr(hostname: &str) -> Result<(String, Vec<u8>), IdentityError> {
    let normalized = aegis_contracts::destination::normalize_domain(hostname)
        .map_err(|_| IdentityError::Certificate("invalid server name".into()))?;
    if normalized != hostname {
        return Err(IdentityError::Certificate(
            "server name must be canonical DNS".into(),
        ));
    }
    let params = CertificateParams::new(vec![hostname.to_owned()])?;
    let key = KeyPair::generate()?;
    let csr = params.serialize_request(&key)?;
    Ok((key.serialize_pem(), csr.der().to_vec()))
}

/// CSR for an already-provisioned device key (same-key renewal).
pub fn csr_for_key(key_pem: &str, node_id: &str) -> Result<String, IdentityError> {
    if !valid_node_id(node_id) {
        return Err(IdentityError::InvalidNodeId);
    }
    let key = KeyPair::from_pem(key_pem)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, node_id);
    params.distinguished_name = dn;
    Ok(params.serialize_request(&key)?.pem()?)
}

/// Whether a certificate carries the public key of `key_pem`.
pub fn certificate_matches_key(cert_der: &[u8], key_pem: &str) -> bool {
    let Ok(key) = KeyPair::from_pem(key_pem) else {
        return false;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) else {
        return false;
    };
    rcgen::PublicKeyData::der_bytes(&key) == cert.public_key().subject_public_key.data.as_ref()
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
    if lifetime.is_zero() || lifetime > MAX_NODE_VALIDITY {
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
    params.subject_alt_names.push(SanType::URI(
        node_uri(node_id, role)
            .try_into()
            .map_err(|_| IdentityError::InvalidNodeId)?,
    ));
    if role == Role::Gateway {
        if server_names.is_empty() || server_names.len() > 8 {
            return Err(IdentityError::Certificate(
                "gateway requires 1..=8 DNS SANs".into(),
            ));
        }
        for name in server_names {
            let normalized = aegis_contracts::destination::normalize_domain(name)
                .map_err(|_| IdentityError::Certificate("invalid server name".into()))?;
            if normalized != *name || name.contains('*') {
                return Err(IdentityError::Certificate(
                    "server name must be canonical DNS".into(),
                ));
            }
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
    validate_issuer(ca)?;
    let key = KeyPair::from_pem(&ca.key_pem)?;
    Ok(Issuer::from_ca_cert_pem(&ca.cert_pem, key)?)
}

pub fn validate_issuer(ca: &CaBundle) -> Result<(), IdentityError> {
    let certs = crate::tls::parse_certs(&ca.cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|_| IdentityError::Pem("issuer"))?;
    let key = KeyPair::from_pem(&ca.key_pem)?;
    if !cert.validity().is_valid()
        || !cert.is_ca()
        || rcgen::PublicKeyData::subject_public_key_info(&key) != cert.public_key().raw
    {
        return Err(IdentityError::Certificate(
            "issuer validity, CA constraint or key mismatch".into(),
        ));
    }
    Ok(())
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
    // Accept public-key requests, never requests for CA/role/SAN authority.
    // Subjects are assigned by the approved invitation, for compatibility.
    if !csr.params.subject_alt_names.is_empty()
        || !csr.params.extended_key_usages.is_empty()
        || !csr.params.custom_extensions.is_empty()
        || !csr.params.key_usages.is_empty()
        || matches!(csr.params.is_ca, IsCa::Ca(_))
    {
        return Err(IdentityError::Certificate(
            "forbidden CSR attributes".into(),
        ));
    }
    csr.params = node_params(node_id, role, server_names, lifetime)?;
    let cert = csr.signed_by(&issuer)?;
    Ok(cert.pem())
}

/// Renew an enrolled device without rekeying: the CSR must carry exactly the
/// public key of the device's current certificate. Its (verified) signature
/// is therefore proof of possession of the enrolled private key.
pub fn sign_renewal_csr(
    ca: &CaBundle,
    csr_pem: &str,
    current_cert_der: &[u8],
    node_id: &str,
    role: Role,
    server_names: &[String],
    lifetime: Duration,
) -> Result<String, IdentityError> {
    if csr_pem.len() > 16 * 1024 {
        return Err(IdentityError::Pem("CSR too large"));
    }
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let (_, current) = x509_parser::parse_x509_certificate(current_cert_der)
        .map_err(|_| IdentityError::Pem("certificate"))?;
    if rcgen::PublicKeyData::der_bytes(&csr.public_key)
        != current.public_key().subject_public_key.data.as_ref()
    {
        return Err(IdentityError::Certificate(
            "renewal CSR key does not match the enrolled certificate".into(),
        ));
    }
    sign_csr(ca, csr_pem, node_id, role, server_names, lifetime)
}

/// Offline root plus a path-length-zero issuer. Only the intermediate key is
/// needed by an online enrollment signer. Append the root certificate to the
/// issued chain when distributing it to devices.
pub fn generate_intermediate(
    root: &CaBundle,
    name: &str,
    lifetime: Duration,
) -> Result<CaBundle, IdentityError> {
    if lifetime.is_zero() || lifetime > Duration::from_secs(365 * 24 * 3600) {
        return Err(IdentityError::Certificate(
            "issuer lifetime must be <= 1 year".into(),
        ));
    }
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial());
    params.use_authority_key_identifier_extension = true;
    validity(&mut params, lifetime);
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &load_ca(root)?)?;
    Ok(CaBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Root for hardened installations; unlike the legacy lab CA it can sign one
/// intermediate. Existing lab CA constraints are deliberately unchanged.
pub fn generate_offline_root(name: &str) -> Result<CaBundle, IdentityError> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial());
    validity(&mut params, DEFAULT_CA_VALIDITY);
    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok(CaBundle {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Ceiling for console/edge web server certificates (CA/Browser Forum limit).
pub const MAX_WEB_VALIDITY: Duration = Duration::from_secs(397 * 24 * 3600);

/// TLS server certificate for the HTTPS console or the outer (edge) listener.
/// Issue it from a dedicated web CA, never the device CA: it carries no node
/// identity URI and must not be able to authenticate as an AegisNet gateway.
pub fn issue_web_server(
    ca: &CaBundle,
    dns_names: &[String],
    ips: &[std::net::IpAddr],
    lifetime: Duration,
) -> Result<(String, String), IdentityError> {
    if lifetime.is_zero() || lifetime > MAX_WEB_VALIDITY {
        return Err(IdentityError::Certificate(
            "web certificate lifetime exceeds 397 days".into(),
        ));
    }
    if dns_names.is_empty() || dns_names.len() + ips.len() > 16 {
        return Err(IdentityError::Certificate(
            "web certificate needs 1..=16 subject alternative names".into(),
        ));
    }
    let issuer = load_ca(ca)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, dns_names[0].as_str());
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    for name in dns_names {
        let normalized = aegis_contracts::destination::normalize_domain(name)
            .map_err(|_| IdentityError::Certificate("invalid server name".into()))?;
        if normalized != *name {
            return Err(IdentityError::Certificate(
                "server name must be canonical DNS".into(),
            ));
        }
        params.subject_alt_names.push(SanType::DnsName(
            name.clone()
                .try_into()
                .map_err(|_| IdentityError::Certificate("invalid server name".into()))?,
        ));
    }
    for ip in ips {
        params.subject_alt_names.push(SanType::IpAddress(*ip));
    }
    params.serial_number = Some(random_serial());
    params.use_authority_key_identifier_extension = true;
    validity(&mut params, lifetime);
    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, &issuer)?;
    Ok((cert.pem(), key.serialize_pem()))
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
