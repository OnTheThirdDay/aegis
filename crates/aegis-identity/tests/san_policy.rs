use aegis_contracts::Role;
use aegis_identity::{pki, tls, IdentitySnapshot};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

fn legacy(ca: &pki::CaBundle, uris: &[&str]) -> String {
    let mut p = CertificateParams::new(Vec::<String>::new()).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "legacy-device");
    dn.push(DnType::OrganizationalUnitName, "client");
    p.distinguished_name = dn;
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    p.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    p.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    for uri in uris {
        p.subject_alt_names
            .push(SanType::URI((*uri).try_into().expect("URI")));
    }
    let issuer =
        Issuer::from_ca_cert_pem(&ca.cert_pem, KeyPair::from_pem(&ca.key_pem).expect("key"))
            .expect("issuer");
    p.signed_by(&KeyPair::generate().expect("node key"), &issuer)
        .expect("certificate")
        .pem()
}
fn peer(pem: &str) -> tls::PeerIdentity {
    tls::PeerIdentity::from_der(tls::parse_certs(pem).expect("PEM")[0].as_ref()).expect("identity")
}

#[test]
fn new_issuance_has_versioned_uri_and_registry_binds_name_role_and_fingerprint() {
    let ca = pki::generate_ca("lab", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let (cert, _) = pki::issue_direct(
        &ca,
        "device-1",
        Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .expect("issue");
    let p = peer(&cert);
    assert!(p.san_identity);
    assert_eq!(p.node_id, "device-1");
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let deny = IdentitySnapshot::new(1, []).with_registry([], 0);
    assert!(!deny.authorizes(&p, now));
    let allow = IdentitySnapshot::new(2, [])
        .with_registry([(p.fingerprint, p.node_id.clone(), Role::Client)], 0);
    assert!(allow.authorizes(&p, now));
    assert!(!allow.authorizes(&p, p.not_after));
    assert!(!allow.with_revoked([p.fingerprint]).authorizes(&p, now));
    let wrong_role = IdentitySnapshot::new(2, [])
        .with_registry([(p.fingerprint, p.node_id.clone(), Role::Gateway)], 0);
    assert!(!wrong_role.authorizes(&p, now));
    let mut claimed = p.clone();
    claimed.node_id = "another-device".into();
    assert!(!allow.authorizes(&claimed, now));
    let mut copied = p;
    copied.fingerprint = [0; 32];
    assert!(!allow.authorizes(&copied, now));
}
#[test]
fn legacy_enrolled_records_work_only_during_bounded_overlap() {
    let ca = pki::generate_ca("lab", pki::DEFAULT_CA_VALIDITY).expect("ca");
    let p = peer(&legacy(&ca, &[]));
    assert!(!p.san_identity);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let snapshot = IdentitySnapshot::new(1, [])
        .with_registry([(p.fingerprint, p.node_id.clone(), Role::Client)], now + 10);
    assert!(snapshot.authorizes(&p, now));
    assert!(!snapshot.authorizes(&p, now + 10));
    assert!(!IdentitySnapshot::new(1, [])
        .with_registry([], now + 10)
        .authorizes(&p, now));
    // The same stable record can authorize a replacement SAN certificate.
    let (_, csr) = pki::generate_key_and_csr("legacy-device").expect("local CSR");
    let cert = pki::sign_csr(
        &ca,
        &csr,
        "legacy-device",
        Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .expect("migrate");
    let renewed = peer(&cert);
    assert!(renewed.san_identity);
    assert_eq!(renewed.node_id, p.node_id);
    assert!(IdentitySnapshot::new(2, [])
        .with_registry(
            [(renewed.fingerprint, renewed.node_id.clone(), Role::Client)],
            0
        )
        .authorizes(&renewed, now));
}
#[test]
fn ambiguous_wrong_role_and_invalid_version_sans_fail_closed() {
    let ca = pki::generate_ca("lab", pki::DEFAULT_CA_VALIDITY).expect("ca");
    for uris in [
        vec![
            "urn:aegis:node:v1:client:legacy-device",
            "urn:aegis:node:v1:client:legacy-device",
        ],
        vec!["urn:aegis:node:v1:gateway:legacy-device"],
        vec!["urn:aegis:node:v2:client:legacy-device"],
        vec!["urn:aegis:node:v1:client:legacy%2Ddevice"],
    ] {
        let cert = legacy(&ca, &uris);
        let der = tls::parse_certs(&cert).expect("parse");
        assert!(tls::PeerIdentity::from_der(der[0].as_ref()).is_err());
    }
}
#[test]
fn offline_root_intermediate_chain_and_forbidden_csr_extensions() {
    let root = pki::generate_offline_root("offline root").expect("root");
    let issuer = pki::generate_intermediate(
        &root,
        "restricted issuer",
        std::time::Duration::from_secs(365 * 86400),
    )
    .expect("issuer");
    let (_, csr) = pki::generate_key_and_csr("device").expect("local CSR");
    let cert = pki::sign_csr(
        &issuer,
        &csr,
        "device",
        Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .expect("sign");
    tls::validate_client_certificate(&format!("{cert}{}", issuer.cert_pem), &root.cert_pem)
        .expect("offline chain validates");
    assert!(!issuer.key_pem.contains(&root.key_pem));
    let mut request =
        CertificateParams::new(vec!["forbidden.example.test".into()]).expect("params");
    request.is_ca = IsCa::ExplicitNoCa;
    let csr = request
        .serialize_request(&KeyPair::generate().expect("key"))
        .expect("CSR")
        .pem()
        .expect("PEM");
    assert!(pki::sign_csr(
        &issuer,
        &csr,
        "device",
        Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY
    )
    .is_err());
}
