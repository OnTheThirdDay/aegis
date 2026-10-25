//! Reload one atomic manifest for new outer handshakes. Existing connections
//! keep their Arc. Invalid replacements retain a still-valid previous config.
//!
//! A manifest can carry SNI alternates: e.g. the appliance keeps its private
//! edge certificate as the default (devices pinned to it keep working) and
//! adds a public ACME certificate selected when clients ask for its name.
use aegis_config::{secret, OuterTlsConfig};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub certificate: String,
    pub private_key: String,
    /// Name the certificate must be valid for, together with `trusted_ca`.
    /// Lets a replacement for a new public hostname (ACME) hot-swap without a
    /// configuration revision. When set, the bundle's own `trusted_ca`
    /// (absent = public roots) replaces the inbound's; when absent, the
    /// inbound's `server_name` and `trusted_ca` apply.
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub trusted_ca: Option<String>,
    /// Additional certificates served when the client's SNI names them.
    #[serde(default)]
    pub alternates: Vec<Alternate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alternate {
    pub certificate: String,
    pub private_key: String,
    pub server_name: String,
    /// `secret://` trust anchor; absent = public web PKI.
    #[serde(default)]
    pub trusted_ca: Option<String>,
}

#[derive(Debug)]
struct SniResolver {
    default: Arc<CertifiedKey>,
    by_name: Vec<(String, Arc<CertifiedKey>)>,
}

impl ResolvesServerCert for SniResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(sni) = hello.server_name() {
            if let Some((_, key)) = self
                .by_name
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(sni))
            {
                return Some(Arc::clone(key));
            }
        }
        Some(Arc::clone(&self.default))
    }
}

struct Current {
    tls: Arc<rustls::ServerConfig>,
    expires: i64,
    digest: String,
}
pub struct ReloadingTls {
    dir: PathBuf,
    settings: OuterTlsConfig,
    current: Mutex<Option<Current>>,
}
impl ReloadingTls {
    pub fn new(dir: PathBuf, settings: OuterTlsConfig) -> Result<Arc<Self>, String> {
        let this = Arc::new(Self {
            dir,
            settings,
            current: Mutex::new(None),
        });
        this.load()?;
        Ok(this)
    }

    fn read_ca(&self, reference: Option<&String>) -> Result<Option<String>, &'static str> {
        reference
            .map(|ca| secret::read(&self.dir, ca))
            .transpose()
            .map_err(|_| "outer_trust_unavailable")
    }

    pub fn load(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut current = self.current.lock().unwrap_or_else(|e| e.into_inner());
        let now = crate::now_unix();
        let staged = (|| {
            let text = secret::read(&self.dir, &self.settings.bundle)
                .map_err(|_| "outer_bundle_unavailable")?;
            if text.len() > 8192 {
                return Err("outer_bundle_too_large");
            }
            let b: Bundle = serde_json::from_str(&text).map_err(|_| "outer_bundle_invalid")?;
            if b.alternates.len() > 4 {
                return Err("outer_bundle_invalid");
            }
            let cert = secret::read(&self.dir, &b.certificate)
                .map_err(|_| "outer_certificate_unavailable")?;
            let key =
                secret::read(&self.dir, &b.private_key).map_err(|_| "outer_key_unavailable")?;
            let (name, ca_ref) = match &b.server_name {
                Some(name) => (name.as_str(), b.trusted_ca.as_ref()),
                None => (
                    self.settings.server_name.as_str(),
                    self.settings.trusted_ca.as_ref(),
                ),
            };
            let ca = self.read_ca(ca_ref)?;
            let mut alternates = Vec::new();
            for alt in &b.alternates {
                alternates.push((
                    alt.server_name.clone(),
                    secret::read(&self.dir, &alt.certificate)
                        .map_err(|_| "outer_certificate_unavailable")?,
                    secret::read(&self.dir, &alt.private_key)
                        .map_err(|_| "outer_key_unavailable")?,
                    self.read_ca(alt.trusted_ca.as_ref())?,
                ));
            }
            let digest = aegis_storage::sha256_hex(
                format!("{cert}{key}{ca:?}{name}{alternates:?}").as_bytes(),
            );
            if current
                .as_ref()
                .is_some_and(|c| c.digest == digest && now < c.expires)
            {
                return Ok(None);
            }
            let rejected = |_| "outer_certificate_rejected";
            let expiry = |pem: &str| -> Result<i64, &'static str> {
                let certs = aegis_identity::tls::parse_certs(pem).map_err(rejected)?;
                aegis_identity::tls::certificate_expiry(certs[0].as_ref()).map_err(rejected)
            };
            let default = aegis_identity::tls::certified_key(&cert, &key, name, ca.as_deref())
                .map_err(rejected)?;
            let mut expires = expiry(&cert)?;
            let mut by_name = Vec::new();
            for (alt_name, alt_cert, alt_key, alt_ca) in &alternates {
                // An invalid alternate never takes the default down with it.
                if let Ok(k) = aegis_identity::tls::certified_key(
                    alt_cert,
                    alt_key,
                    alt_name,
                    alt_ca.as_deref(),
                ) {
                    expires = expires.min(expiry(alt_cert)?);
                    by_name.push((alt_name.clone(), k));
                }
            }
            let tls =
                aegis_identity::tls::sni_server_config(Arc::new(SniResolver { default, by_name }))
                    .map_err(rejected)?;
            Ok::<_, &str>(Some(Current {
                tls,
                expires,
                digest,
            }))
        })();
        match staged {
            Ok(Some(new)) => *current = Some(new),
            Ok(None) => {}
            Err(code) if current.as_ref().is_none_or(|c| now >= c.expires) => {
                return Err(code.into())
            }
            Err(_) => {}
        }
        current
            .as_ref()
            .map(|c| Arc::clone(&c.tls))
            .ok_or_else(|| "outer_tls_unavailable".into())
    }
}
