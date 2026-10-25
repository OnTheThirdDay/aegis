//! Validated immutable certificate generations and an atomically replaced
//! manifest. ACME credentials live on the host, outside gateway/NGINX mounts.
use crate::{secrets::SecretStore, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeSettings {
    pub hostname: String,
    pub contact_email: String,
    pub challenge: Challenge,
    pub staging: bool,
    pub image: String,
    pub terms_accepted: bool,
    pub http_public_port_approved: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Challenge {
    Dns01Cloudflare,
    Http01,
}
impl AcmeSettings {
    pub fn validate(&self) -> Result<()> {
        if aegis_contracts::destination::normalize_domain(&self.hostname).as_ref()
            != Ok(&self.hostname)
            || self.contact_email.len() > 254
            || !self.contact_email.contains('@')
            || self
                .contact_email
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
            || !crate::pinned_image(&self.image)
            || !self.image.starts_with("goacme/lego:v4.26.0@sha256:")
            || !self.terms_accepted
        {
            return Err(Error("invalid_acme_settings_or_terms_not_accepted"));
        }
        if self.challenge == Challenge::Http01 && !self.http_public_port_approved {
            return Err(Error(
                "http01_requires_public_port_80_approval_and_reachability",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CertificateStatus {
    pub generation: String,
    pub expires_at: i64,
    pub renew_before: i64,
    pub manifest: String,
}

pub fn activate_public(
    store: &SecretStore,
    cert: &str,
    key: &str,
    name: &str,
    custom_ca: Option<&str>,
) -> Result<CertificateStatus> {
    // Complete chain/name/expiry/key validation occurs before any active file
    // changes. Private staging trust must be explicitly supplied.
    aegis_identity::tls::public_server_config(cert, key, name, custom_ca)
        .map_err(|_| Error("replacement_certificate_invalid"))?;
    let certs = aegis_identity::tls::parse_certs(cert)
        .map_err(|_| Error("replacement_certificate_invalid"))?;
    let expires = aegis_identity::tls::certificate_expiry(certs[0].as_ref())
        .map_err(|_| Error("replacement_certificate_invalid"))?;
    let generation = aegis_storage::sha256_hex(certs[0].as_ref());
    let cert_file = format!("public-{}.pem", &generation[..16]);
    let key_file = format!("public-{}.key", &generation[..16]);
    for (file, value) in [(&cert_file, cert), (&key_file, key)] {
        match store.read(file) {
            Ok(existing) if existing.as_str() == value => {}
            Ok(_) => return Err(Error("certificate_generation_conflict")),
            Err(_) if store.root().join(file).exists() => {
                return Err(Error("certificate_generation_not_owned"))
            }
            Err(_) => store.put(file, value, false)?,
        }
    }
    store.put("public-tls.json",&json!({"certificate":format!("secret://{cert_file}"),"private_key":format!("secret://{key_file}")}).to_string(),true)?;
    Ok(CertificateStatus {
        generation,
        expires_at: expires,
        renew_before: expires - 7 * 86400,
        manifest: "secret://public-tls.json".into(),
    })
}

pub fn public_status(store: &SecretStore) -> Result<CertificateStatus> {
    let manifest = store.read("public-tls.json")?;
    let refs: serde_json::Value =
        serde_json::from_str(&manifest).map_err(|_| Error("invalid_certificate_manifest"))?;
    let cert_ref = refs["certificate"]
        .as_str()
        .ok_or(Error("invalid_certificate_manifest"))?;
    let name = aegis_config::secret::parse_ref(cert_ref)
        .map_err(|_| Error("invalid_certificate_manifest"))?;
    let cert = store.read(name)?;
    let certs =
        aegis_identity::tls::parse_certs(&cert).map_err(|_| Error("invalid_certificate"))?;
    let expires = aegis_identity::tls::certificate_expiry(certs[0].as_ref())
        .map_err(|_| Error("invalid_certificate"))?;
    Ok(CertificateStatus {
        generation: aegis_storage::sha256_hex(certs[0].as_ref()),
        expires_at: expires,
        renew_before: expires - 7 * 86400,
        manifest: "secret://public-tls.json".into(),
    })
}

/// Restricted official lego container adapter. DNS-01 is Cloudflare-only in
/// this release. HTTP-01 uses a dedicated, explicitly approved port-80 mapping.
pub async fn acme(root: &Path, settings: &AcmeSettings, renew: bool) -> Result<CertificateStatus> {
    settings.validate()?;
    let root = std::fs::canonicalize(root).map_err(|_| Error("setup_bootstrap_required"))?;
    let work = SecretStore::open(root.join("acme-state"))?;
    let bootstrap = crate::host::LocalDocker::open(&root)?;
    let b = bootstrap.bootstrap_manifest();
    let mut args: Vec<String> = vec![
        "run",
        "--rm",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--pids-limit=64",
        "--memory=128m",
        "--log-driver=none",
        "--user",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.push(format!("{}:{}", b.runtime_uid, b.runtime_gid));
    args.extend([
        "--mount".into(),
        format!("type=bind,source={},target=/lego", work.root().display()),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,size=16m".into(),
    ]);
    // Explicitly root-run installers transfer only this newly-owned directory.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{chown, MetadataExt};
        if std::fs::metadata(&root)
            .map_err(|_| Error("host_directory_unavailable"))?
            .uid()
            == 0
        {
            chown(work.root(), Some(b.runtime_uid), Some(b.runtime_gid))
                .map_err(|_| Error("acme_state_permissions"))?;
        }
    }
    if settings.challenge == Challenge::Dns01Cloudflare {
        let host_secrets = SecretStore::open(root.join("host-secrets"))?;
        let _ = host_secrets.read("acme-dns-token")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{chown, MetadataExt};
            if std::fs::metadata(&root)
                .map_err(|_| Error("host_directory_unavailable"))?
                .uid()
                == 0
            {
                chown(
                    host_secrets.root().join("acme-dns-token"),
                    Some(b.runtime_uid),
                    Some(b.runtime_gid),
                )
                .map_err(|_| Error("acme_token_permissions"))?;
            }
        }
        args.extend([
            "--mount".into(),
            format!(
                "type=bind,source={},target=/run/secrets/dns-token,readonly",
                host_secrets.root().join("acme-dns-token").display()
            ),
            "--env".into(),
            "CF_DNS_API_TOKEN_FILE=/run/secrets/dns-token".into(),
            "--env".into(),
            "CF_ZONE_API_TOKEN_FILE=/run/secrets/dns-token".into(),
        ]);
    } else {
        args.extend(["--publish".into(), "80:8080".into()]);
    }
    args.push(settings.image.clone());
    args.extend([
        "--path".into(),
        "/lego".into(),
        "--server".into(),
        if settings.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory".into()
        } else {
            "https://acme-v02.api.letsencrypt.org/directory".into()
        },
        "--email".into(),
        settings.contact_email.clone(),
        "--domains".into(),
        settings.hostname.clone(),
        "--accept-tos".into(),
    ]);
    match settings.challenge {
        Challenge::Dns01Cloudflare => args.extend(["--dns".into(), "cloudflare".into()]),
        Challenge::Http01 => args.extend(["--http".into(), "--http.port".into(), ":8080".into()]),
    }
    if renew {
        args.extend(["renew".into(), "--days".into(), "30".into()]);
    } else {
        args.push("run".into());
    }
    crate::host::command(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        None,
        Duration::from_secs(300),
    )
    .await?;
    let cert_dir = root.join("acme-state/certificates");
    let cert_path = cert_dir.join(format!("{}.crt", settings.hostname));
    let key_path = cert_dir.join(format!("{}.key", settings.hostname));
    for file in [&cert_path, &key_path] {
        let meta =
            std::fs::symlink_metadata(file).map_err(|_| Error("acme_certificate_not_written"))?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 1024 * 1024 {
            return Err(Error("acme_artifact_invalid"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| Error("acme_artifact_permissions"))?;
        }
    }
    let issued = SecretStore::open(&cert_dir)?;
    let cert = issued.read(&format!("{}.crt", settings.hostname))?;
    let key = issued.read(&format!("{}.key", settings.hostname))?;
    // Staging roots are deliberately not public trust anchors. Preserve issued
    // artifacts, but require an explicit staging trust anchor for activation.
    let staging_ca = if settings.staging {
        Some(SecretStore::open(root.join("host-secrets"))?.read("acme-staging-ca.pem")?)
    } else {
        None
    };
    let runtime = SecretStore::open(root.join("runtime-secrets"))?;
    if let Some(ca) = &staging_ca {
        runtime.put("outer-ca.pem", ca, true)?;
    }
    let status = activate_public(
        &runtime,
        &cert,
        &key,
        &settings.hostname,
        staging_ca.as_deref().map(String::as_str),
    )?;
    crate::host::runtime_permissions(&root)?;
    SecretStore::open(root.join("host-secrets"))?.put(
        "acme-settings.json",
        &serde_json::to_string(settings).map_err(|_| Error("invalid_acme_settings"))?,
        true,
    )?;
    Ok(status)
}

pub fn renewal_settings(root: &Path) -> Result<AcmeSettings> {
    let text = SecretStore::open(root.join("host-secrets"))?.read("acme-settings.json")?;
    serde_json::from_str(&text).map_err(|_| Error("invalid_acme_settings"))
}

pub fn staging_ca_path(root: &Path) -> PathBuf {
    root.join("host-secrets/acme-staging-ca.pem")
}
