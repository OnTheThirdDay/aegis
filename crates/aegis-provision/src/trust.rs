//! Explicit local trust rotation with overlapping anchors and a durable journal.
//! Root keys are never needed by these operations; import a restricted issuer
//! produced on the offline signer. No routing rollback resurrects revocations.
use crate::{host, secrets::SecretStore, Error, Result};
use aegis_identity::pki::{self, CaBundle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rotation {
    pub schema_version: u32,
    pub phase: String,
    pub old_digest: String,
    pub new_digest: String,
    pub retire_after: i64,
}

pub fn read_bundle(store: &SecretStore, manifest: &str) -> Result<CaBundle> {
    let value: Value = serde_json::from_str(&store.read(manifest)?)
        .map_err(|_| Error("invalid_identity_manifest"))?;
    let read = |field: &str| -> Result<_> {
        let reference = value[field]
            .as_str()
            .ok_or(Error("invalid_identity_manifest"))?;
        store.read(
            aegis_config::secret::parse_ref(reference)
                .map_err(|_| Error("invalid_identity_manifest"))?,
        )
    };
    Ok(CaBundle {
        cert_pem: read("certificate")?.to_string(),
        key_pem: read("private_key")?.to_string(),
    })
}

fn publish_bundle(store: &SecretStore, manifest: &str, cert: &str, key: &str) -> Result<()> {
    let fp = aegis_storage::sha256_hex(cert.as_bytes());
    let certificate = format!("identity-{}.pem", &fp[..16]);
    let private_key = format!("identity-{}.key", &fp[..16]);
    for (name, value) in [(&certificate, cert), (&private_key, key)] {
        if !store.root().join(name).exists() {
            store.put(name, value, false)?;
        } else if store.read(name)?.as_str() != value {
            return Err(Error("identity_generation_conflict"));
        }
    }
    store.put(manifest,&json!({"certificate":format!("secret://{certificate}"),"private_key":format!("secret://{private_key}")}).to_string(),true)
}

pub fn stage(root: &Path, new_ca: &str) -> Result<Rotation> {
    aegis_identity::tls::validate_ca_certificates(new_ca)
        .map_err(|_| Error("new_trust_anchor_rejected"))?;
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    let host = SecretStore::open(root.join("host-secrets"))?;
    let old = runtime.read("root.pem")?;
    if old.as_str() == new_ca {
        return Err(Error("trust_anchor_already_active"));
    }
    if host.root().join("trust-rotation.json").exists() {
        let previous = status(root)?;
        if previous.phase != "retired" {
            return Err(Error("trust_rotation_already_pending"));
        }
    }
    let rotation = Rotation {
        schema_version: 1,
        phase: "staging".into(),
        old_digest: aegis_storage::sha256_hex(old.as_bytes()),
        new_digest: aegis_storage::sha256_hex(new_ca.as_bytes()),
        retire_after: aegis_storage::now_unix() + pki::MAX_NODE_VALIDITY.as_secs() as i64 + 600,
    };
    host.put("trust-old.pem", &old, true)?;
    host.put("trust-new.pem", new_ca, true)?;
    host.put(
        "trust-rotation.json",
        &serde_json::to_string(&rotation).map_err(|_| Error("invalid_rotation"))?,
        true,
    )?;
    finish_stage(root)
}

/// Recover the same journaled staging intent after a crash, without guessing
/// which roots were previously approved.
pub fn finish_stage(root: &Path) -> Result<Rotation> {
    let host = SecretStore::open(root.join("host-secrets"))?;
    let mut rotation = status(root)?;
    if rotation.phase != "staging" && rotation.phase != "overlap" {
        return Err(Error("trust_rotation_not_staging"));
    }
    let old = host.read("trust-old.pem")?;
    let new = host.read("trust-new.pem")?;
    if aegis_storage::sha256_hex(old.as_bytes()) != rotation.old_digest
        || aegis_storage::sha256_hex(new.as_bytes()) != rotation.new_digest
    {
        return Err(Error("trust_journal_integrity_failure"));
    }
    let anchors = format!("{}{}", old.as_str(), new.as_str());
    SecretStore::open(root.join("runtime-secrets"))?.put("root.pem", &anchors, true)?;
    SecretStore::open(root.join("probe-secrets"))?.put("root.pem", &anchors, true)?;
    host::runtime_permissions(root)?;
    rotation.phase = "overlap".into();
    host.put(
        "trust-rotation.json",
        &serde_json::to_string(&rotation).map_err(|_| Error("invalid_rotation"))?,
        true,
    )?;
    Ok(rotation)
}

pub fn import_issuer(root: &Path, issuer: CaBundle) -> Result<()> {
    pki::validate_issuer(&issuer).map_err(|_| Error("new_issuer_rejected"))?;
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    // Prove the issuer chains to the explicitly staged trust anchors, not just
    // that its subject says CA. This key is never a device's key.
    let (_, csr) = pki::generate_key_and_csr("issuer-validation")
        .map_err(|_| Error("issuer_validation_failed"))?;
    let cert = pki::sign_csr(
        &issuer,
        &csr,
        "issuer-validation",
        aegis_contracts::Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("issuer_validation_failed"))?;
    aegis_identity::tls::validate_client_certificate(
        &format!("{cert}{}", issuer.cert_pem),
        &runtime.read("root.pem")?,
    )
    .map_err(|_| Error("issuer_not_in_staged_trust"))?;
    publish_bundle(&runtime, "issuer.json", &issuer.cert_pem, &issuer.key_pem)?;
    host::runtime_permissions(root)
}

pub fn renew_local(root: &Path) -> Result<()> {
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    let issuer = read_bundle(&runtime, "issuer.json")?;
    let host = host::LocalDocker::open(root)?;
    let manifest = host.bootstrap_manifest();
    let (key, csr) = pki::generate_key_and_csr(&manifest.node_id)
        .map_err(|_| Error("local_key_rollover_failed"))?;
    let leaf = pki::sign_csr(
        &issuer,
        &csr,
        &manifest.node_id,
        aegis_contracts::Role::Gateway,
        std::slice::from_ref(&manifest.inner_server_name),
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("local_renewal_failed"))?;
    let chain = format!("{leaf}{}", issuer.cert_pem);
    aegis_identity::tls::public_server_config(
        &chain,
        &key,
        &manifest.inner_server_name,
        Some(&runtime.read("root.pem")?),
    )
    .map_err(|_| Error("replacement_identity_rejected"))?;
    publish_bundle(&runtime, "gateway-identity.json", &chain, &key)?;
    let probe = SecretStore::open(root.join("probe-secrets"))?;
    let probe_id = format!("probe-{}", &manifest.deployment_id[..8]);
    let (key, csr) =
        pki::generate_key_and_csr(&probe_id).map_err(|_| Error("local_key_rollover_failed"))?;
    let cert = pki::sign_csr(
        &issuer,
        &csr,
        &probe_id,
        aegis_contracts::Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("local_renewal_failed"))?;
    publish_bundle(
        &probe,
        "probe-identity.json",
        &format!("{cert}{}", issuer.cert_pem),
        &key,
    )?;
    host::runtime_permissions(root)
}

pub fn local_status(root: &Path) -> Result<Value> {
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    let current = read_bundle(&runtime, "gateway-identity.json")?;
    let certs = aegis_identity::tls::parse_certs(&current.cert_pem)
        .map_err(|_| Error("invalid_local_certificate"))?;
    let expires = aegis_identity::tls::certificate_expiry(certs[0].as_ref())
        .map_err(|_| Error("invalid_local_certificate"))?;
    Ok(
        json!({"expires_at":expires,"renew_before":expires-7*86400,"expired":aegis_storage::now_unix()>=expires,"identity_version":1}),
    )
}
pub fn status(root: &Path) -> Result<Rotation> {
    serde_json::from_str(
        &SecretStore::open(root.join("host-secrets"))?.read("trust-rotation.json")?,
    )
    .map_err(|_| Error("invalid_trust_journal"))
}
pub fn retire(root: &Path) -> Result<Rotation> {
    retire_at(root, aegis_storage::now_unix())
}
fn retire_at(root: &Path, now: i64) -> Result<Rotation> {
    let mut rotation = status(root)?;
    if now < rotation.retire_after {
        return Err(Error("trust_overlap_window_not_elapsed"));
    }
    let host = SecretStore::open(root.join("host-secrets"))?;
    let new = host.read("trust-new.pem")?;
    aegis_identity::tls::validate_ca_certificates(&new)
        .map_err(|_| Error("new_trust_anchor_expired"))?;
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    let issuer = read_bundle(&runtime, "issuer.json")?;
    // Refuse retirement while the active issuer/leaf still needs the old root.
    let (_, csr) = pki::generate_key_and_csr("retirement-validation")
        .map_err(|_| Error("issuer_validation_failed"))?;
    let leaf = pki::sign_csr(
        &issuer,
        &csr,
        "retirement-validation",
        aegis_contracts::Role::Client,
        &[],
        pki::DEFAULT_NODE_VALIDITY,
    )
    .map_err(|_| Error("issuer_validation_failed"))?;
    aegis_identity::tls::validate_client_certificate(&format!("{leaf}{}", issuer.cert_pem), &new)
        .map_err(|_| Error("issuer_still_requires_old_root"))?;
    let gateway = read_bundle(&runtime, "gateway-identity.json")?;
    let b = host::LocalDocker::open(root)?;
    aegis_identity::tls::public_server_config(
        &gateway.cert_pem,
        &gateway.key_pem,
        &b.bootstrap_manifest().inner_server_name,
        Some(&new),
    )
    .map_err(|_| Error("gateway_still_requires_old_root"))?;
    rotation.phase = "retiring".into();
    host.put(
        "trust-rotation.json",
        &serde_json::to_string(&rotation).map_err(|_| Error("invalid_rotation"))?,
        true,
    )?;
    runtime.put("root.pem", &new, true)?;
    SecretStore::open(root.join("probe-secrets"))?.put("root.pem", &new, true)?;
    host::runtime_permissions(root)?;
    rotation.phase = "retired".into();
    host.put(
        "trust-rotation.json",
        &serde_json::to_string(&rotation).map_err(|_| Error("invalid_rotation"))?,
        true,
    )?;
    Ok(rotation)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn root_stays_off_container_and_trust_rotation_is_staged_recoverable_and_bounded() {
        let temp = tempfile::tempdir().expect("temp");
        let root = temp.path();
        let initial =
            host::bootstrap(root, "gateway", "gateway.aegis.internal").expect("bootstrap");
        assert_eq!(
            host::bootstrap(root, "gateway", "gateway.aegis.internal")
                .expect("idempotent")
                .deployment_id,
            initial.deployment_id
        );
        let runtime = SecretStore::open(root.join("runtime-secrets")).expect("runtime");
        let private = SecretStore::open(root.join("host-secrets")).expect("host");
        let root_key = private.read("root-key.pem").expect("offline root");
        for entry in std::fs::read_dir(runtime.root()).expect("runtime files") {
            let content = std::fs::read_to_string(entry.expect("file").path()).expect("read");
            assert!(!content.contains(root_key.as_str()));
        }
        let old = runtime.read("root.pem").expect("old root");
        let next = pki::generate_offline_root("new offline root").expect("new root");
        let rotation = stage(root, &next.cert_pem).expect("overlap");
        let anchors = runtime.read("root.pem").expect("anchors");
        assert!(anchors.contains(old.as_str()) && anchors.contains(&next.cert_pem));
        assert!(
            stage(root, &next.cert_pem).is_err(),
            "cannot overwrite pending rotation"
        );
        assert_eq!(
            retire(root).expect_err("bounded overlap").0,
            "trust_overlap_window_not_elapsed"
        );
        assert_eq!(
            finish_stage(root).expect("reconcile stage").phase,
            "overlap"
        );
        assert!(
            retire_at(root, rotation.retire_after).is_err(),
            "old issuer prevents retirement"
        );
        let issuer = pki::generate_intermediate(
            &next,
            "new issuer",
            std::time::Duration::from_secs(365 * 86400),
        )
        .expect("issuer");
        import_issuer(
            root,
            CaBundle {
                cert_pem: format!("{}{}", issuer.cert_pem, next.cert_pem),
                key_pem: issuer.key_pem,
            },
        )
        .expect("approved issuer");
        assert!(
            retire_at(root, rotation.retire_after).is_err(),
            "old gateway leaf prevents retirement"
        );
        renew_local(root).expect("renew/rekey both local devices");
        assert_eq!(
            retire_at(root, rotation.retire_after)
                .expect("retire old trust")
                .phase,
            "retired"
        );
        assert_eq!(
            runtime.read("root.pem").expect("new-only trust").as_str(),
            next.cert_pem
        );
        assert!(!local_status(root).expect("status")["expired"]
            .as_bool()
            .expect("expired"));
    }
}
