use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    LocalPrivate,
    CloudflareTunnel,
    DirectPublic,
}

/// Where the gateway and connector run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    /// Host-side controller drives Docker Compose (pinned images).
    #[default]
    Compose,
    /// Appliance: the gateway supervises the bundled, digest-verified
    /// connector itself; no host or Docker authority is involved.
    Embedded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredDeployment {
    pub schema_version: u32,
    /// Stable UUID owned by this local installer, not an arbitrary Compose name.
    pub deployment_id: String,
    pub mode: Mode,
    pub node_id: String,
    pub inner_server_name: String,
    pub hostname: Option<String>,
    pub account_id: Option<String>,
    pub zone_id: Option<String>,
    #[serde(default)]
    pub host: HostKind,
    /// Tunnel origin for the connector (embedded: container loopback).
    #[serde(default)]
    pub origin_service: Option<String>,
    /// Immutable image references required; no tag-only production execution.
    #[serde(default)]
    pub gateway_image: String,
    pub connector_image: Option<String>,
    pub nameservers: Vec<String>,
    /// Operator-selected probes; no default calls to third-party test services.
    pub verification_http_url: String,
    pub verification_https_url: String,
    #[serde(default)]
    pub acme: Option<crate::certificate::AcmeSettings>,
    #[serde(default)]
    pub outer_trust_ca: Option<String>,
    #[serde(default)]
    pub nginx_image: Option<String>,
}

pub fn pinned_image(image: &str) -> bool {
    image.split_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && name.len() <= 200
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"./:_-".contains(&b))
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

pub fn provider_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn tunnel_id(id: &str) -> bool {
    uuid_shape(id)
}
pub fn uuid_shape(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit() && !b.is_ascii_uppercase()
            }
        })
}

impl DesiredDeployment {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || !uuid_shape(&self.deployment_id)
            || !aegis_identity::valid_node_id(&self.node_id)
            || aegis_contracts::destination::normalize_domain(&self.inner_server_name).as_ref()
                != Ok(&self.inner_server_name)
        {
            return Err(Error("invalid_deployment"));
        }
        match self.host {
            HostKind::Compose => {
                if !pinned_image(&self.gateway_image) || self.origin_service.is_some() {
                    return Err(Error("invalid_deployment"));
                }
            }
            HostKind::Embedded => {
                let loopback_origin = self
                    .origin_service
                    .as_deref()
                    .and_then(|s| s.strip_prefix("http://127.0.0.1:"))
                    .and_then(|p| p.parse::<u16>().ok())
                    .is_some_and(|p| p != 0);
                if !self.gateway_image.is_empty()
                    || self.connector_image.is_some()
                    || self.nginx_image.is_some()
                    || self.acme.is_some()
                    || !loopback_origin
                {
                    return Err(Error("invalid_embedded_deployment"));
                }
            }
        }
        if self.nameservers.is_empty()
            || self.nameservers.len() > 4
            || self.nameservers.iter().any(|s| {
                s.parse::<std::net::SocketAddr>().map_or(true, |a| {
                    a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast()
                })
            })
        {
            return Err(Error("explicit_nameservers_required"));
        }
        for (url, scheme) in [
            (&self.verification_http_url, "http"),
            (&self.verification_https_url, "https"),
        ] {
            let url = reqwest::Url::parse(url).map_err(|_| Error("invalid_probe_url"))?;
            if url.scheme() != scheme
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err(Error("invalid_probe_url"));
            }
        }
        if self.mode == Mode::CloudflareTunnel {
            let host = self.hostname.as_ref().ok_or(Error("hostname_required"))?;
            let connector_ok = match self.host {
                HostKind::Compose => self.connector_image.as_deref().is_some_and(|image| {
                    pinned_image(image) && image.starts_with("cloudflare/cloudflared:")
                }),
                HostKind::Embedded => self.connector_image.is_none(),
            };
            if aegis_contracts::destination::normalize_domain(host).as_ref() != Ok(host)
                || !self.account_id.as_deref().is_some_and(provider_id)
                || !self.zone_id.as_deref().is_some_and(provider_id)
                || !connector_ok
            {
                return Err(Error("invalid_cloudflare_deployment"));
            }
        } else if self.account_id.is_some()
            || self.zone_id.is_some()
            || self.connector_image.is_some()
            || (self.mode == Mode::LocalPrivate && self.hostname.is_some())
        {
            return Err(Error("unexpected_provider_configuration"));
        }
        if self.mode == Mode::DirectPublic {
            let host = self.hostname.as_ref().ok_or(Error("hostname_required"))?;
            if aegis_contracts::destination::normalize_domain(host).as_ref() != Ok(host) {
                return Err(Error("invalid_hostname"));
            }
        }
        if let Some(acme) = &self.acme {
            acme.validate()?;
            if self.mode != Mode::DirectPublic
                || Some(acme.hostname.as_str()) != self.hostname.as_deref()
            {
                return Err(Error("acme_requires_direct_public_hostname"));
            }
        }
        if self.nginx_image.as_deref().is_some_and(|image| {
            self.mode != Mode::DirectPublic || !pinned_image(image) || !image.starts_with("nginx:")
        }) {
            return Err(Error(
                "nginx_requires_explicit_direct_public_selection_and_pin",
            ));
        }
        if self
            .outer_trust_ca
            .as_ref()
            .is_some_and(|ca| aegis_config::secret::parse_ref(ca).is_err())
        {
            return Err(Error("invalid_outer_trust_reference"));
        }
        Ok(())
    }

    pub fn endpoint(&self) -> String {
        match self.mode {
            Mode::CloudflareTunnel => {
                format!("wss://{}/agp", self.hostname.as_deref().unwrap_or_default())
            }
            Mode::LocalPrivate => "ws://127.0.0.1:18080/agp".into(),
            Mode::DirectPublic => {
                format!("wss://{}/agp", self.hostname.as_deref().unwrap_or_default())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    Validated,
    Applying,
    Verifying,
    Active,
    Failed,
    RecoveryRequired,
    Compensating,
    Removed,
}
impl PlanState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::Applying => "applying",
            Self::Verifying => "verifying",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::RecoveryRequired => "recovery_required",
            Self::Compensating => "compensating",
            Self::Removed => "removed",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Inventory {
    pub tunnel_id: Option<String>,
    pub dns_id: Option<String>,
    pub created_tunnel: bool,
    pub created_dns: bool,
    pub host_applied: bool,
    pub verified: bool,
    pub config_revision: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub digest: String,
    pub actor_id: String,
    pub desired: DesiredDeployment,
    pub expected_revision: Option<String>,
    pub state: PlanState,
    pub generation: i64,
    pub step: String,
    pub inventory: Inventory,
    pub error_code: Option<String>,
}
impl Plan {
    pub fn etag(&self) -> String {
        format!("\"provision-{}-{}\"", self.id, self.generation)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verification {
    pub provider_objects: bool,
    pub connector: bool,
    pub public_dns: bool,
    pub wss: bool,
    pub inner_mtls: bool,
    pub socks_http: bool,
    pub socks_https: bool,
}
impl Verification {
    pub fn complete(&self) -> bool {
        self.provider_objects
            && self.connector
            && self.public_dns
            && self.wss
            && self.inner_mtls
            && self.socks_http
            && self.socks_https
    }
}
