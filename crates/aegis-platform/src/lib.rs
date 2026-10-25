//! Capability registry and host probing.
//!
//! The registry holds the T0 built-in module descriptors supplied by the
//! composition root. Configuration validation asks it whether every component
//! a profile names exists, supports this OS and role, and has its required
//! capabilities provided. The capability digest binds validation reports to
//! the exact installed environment.
#![forbid(unsafe_code)]

use aegis_contracts::capability::{Capability, Maturity, ModuleDescriptor, OsFamily, Role};
use aegis_contracts::vpn::VpnMode;
use aegis_traffic_policy::{HostCapabilities, ModeCapability, Support};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Registry {
    modules: BTreeMap<&'static str, ModuleDescriptor>,
    os: OsFamily,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryError {
    UnknownModule(String),
    UnsupportedOs {
        module: String,
        os: OsFamily,
    },
    UnsupportedRole {
        module: String,
        role: Role,
    },
    MissingCapability {
        module: String,
        capability: Capability,
    },
    Duplicate(String),
    TooManyModules,
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::UnknownModule(m) => write!(f, "module {m} is not installed"),
            RegistryError::UnsupportedOs { module, os } => {
                write!(f, "module {module} does not support {}", os.as_str())
            }
            RegistryError::UnsupportedRole { module, role } => {
                write!(f, "module {module} does not support role {role:?}")
            }
            RegistryError::MissingCapability { module, capability } => write!(
                f,
                "module {module} requires capability {} which no installed module provides",
                capability.as_str()
            ),
            RegistryError::Duplicate(m) => write!(f, "module {m} registered twice"),
            RegistryError::TooManyModules => {
                f.write_str("capability registry limited to 256 modules")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

/// API representation (OpenAPI `ModuleCapability`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ModuleCapabilityView {
    pub id: String,
    pub version: String,
    pub maturity: Maturity,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
}

impl Registry {
    pub fn new(os: OsFamily) -> Self {
        Registry {
            modules: BTreeMap::new(),
            os,
        }
    }

    pub fn register(&mut self, d: ModuleDescriptor) -> Result<(), RegistryError> {
        if self.modules.len() >= 256 {
            return Err(RegistryError::TooManyModules);
        }
        if self.modules.contains_key(d.module_id) {
            return Err(RegistryError::Duplicate(d.module_id.into()));
        }
        self.modules.insert(d.module_id, d);
        Ok(())
    }

    pub fn os(&self) -> OsFamily {
        self.os
    }

    pub fn get(&self, id: &str) -> Option<&ModuleDescriptor> {
        self.modules.get(id)
    }

    fn provided(&self, cap: Capability) -> bool {
        self.modules.values().any(|m| m.provides.contains(&cap))
    }

    /// Check that `module_id` can run here in `role`, with every required
    /// capability provided by some installed module.
    pub fn check(&self, module_id: &str, role: Role) -> Result<&ModuleDescriptor, RegistryError> {
        let m = self
            .modules
            .get(module_id)
            .ok_or_else(|| RegistryError::UnknownModule(module_id.into()))?;
        if !m.supports_os(self.os) {
            return Err(RegistryError::UnsupportedOs {
                module: module_id.into(),
                os: self.os,
            });
        }
        if !m.supports_role(role) {
            return Err(RegistryError::UnsupportedRole {
                module: module_id.into(),
                role,
            });
        }
        for cap in m.requires {
            if !self.provided(*cap) {
                return Err(RegistryError::MissingCapability {
                    module: module_id.into(),
                    capability: *cap,
                });
            }
        }
        Ok(m)
    }

    /// Require that `module_id` provides `cap` (e.g. a byte-stream inbound
    /// must not be wired to a datagram-only transport).
    pub fn require_capability(
        &self,
        module_id: &str,
        cap: Capability,
    ) -> Result<(), RegistryError> {
        let m = self
            .modules
            .get(module_id)
            .ok_or_else(|| RegistryError::UnknownModule(module_id.into()))?;
        if m.provides.contains(&cap) {
            Ok(())
        } else {
            Err(RegistryError::MissingCapability {
                module: module_id.into(),
                capability: cap,
            })
        }
    }

    pub fn views(&self) -> Vec<ModuleCapabilityView> {
        self.modules
            .values()
            .map(|m| ModuleCapabilityView {
                id: m.module_id.into(),
                version: m.module_version.into(),
                maturity: m.maturity,
                provides: m.provides.iter().map(|c| c.as_str().to_owned()).collect(),
                requires: m.requires.iter().map(|c| c.as_str().to_owned()).collect(),
            })
            .collect()
    }

    /// SHA-256 over the canonical JSON of installed modules, OS and host
    /// System-VPN capabilities.
    pub fn capability_digest(&self, host: &HostCapabilities) -> String {
        #[derive(Serialize)]
        struct Canon<'a> {
            os: &'a str,
            modules: &'a [ModuleCapabilityView],
            host: &'a HostCapabilities,
        }
        let views = self.views();
        let json = serde_json::to_vec(&Canon {
            os: self.os.as_str(),
            modules: &views,
            host,
        })
        .unwrap_or_default();
        hex::encode(Sha256::digest(&json))
    }
}

/// Observed System-VPN capabilities for this host.
///
/// No native capture adapter, app-identity provider or privileged
/// route/DNS/filter helper is implemented in this build, so every mode is
/// reported unsupported with an actionable reason. Availability is never
/// inferred from the compile target.
pub fn host_vpn_capabilities(os: OsFamily) -> HostCapabilities {
    let reason = match os {
        OsFamily::Linux => "Linux TUN/nftables capture, UID/cgroup identity and the privileged helper are M3 work and not installed",
        OsFamily::Windows => "Windows TUN + WFP attribution/redirect adapters are M3 work and not installed",
        OsFamily::Macos => "macOS Network Extension adapter is not installed; per-app support is entitlement dependent",
        OsFamily::Android => "Android VpnService shell is M4 work and not installed",
        OsFamily::Ios => "iOS Packet Tunnel shell is M4 work; per-app requires MDM-managed deployment",
        OsFamily::Other => "no System-VPN adapter exists for this platform",
    };
    HostCapabilities {
        platform: os,
        modes: VpnMode::ALL
            .iter()
            .map(|m| ModeCapability {
                mode: *m,
                support: Support::Unsupported,
                identity_enforcement: false,
                explanation: reason.into(),
            })
            .collect(),
        tcp: false,
        udp: false,
        dns_capture: false,
        ipv4: false,
        ipv6: false,
        native_kill_switch: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_contracts::capability::ResourceBudget;

    const TRANSPORT: ModuleDescriptor = ModuleDescriptor {
        module_id: "t.ws",
        module_version: "1",
        api_version: 1,
        roles: &[Role::Client, Role::Gateway],
        operating_systems: &[OsFamily::Linux],
        provides: &[Capability::ByteStream, Capability::Ordered],
        requires: &[],
        budget: ResourceBudget {
            max_open_streams: 0,
            max_sockets: 1,
            read_buffer_bytes: 0,
            write_buffer_bytes: 0,
            timers: 0,
        },
        maturity: Maturity::Experimental,
        conformance_hash: "",
    };
    const MUX: ModuleDescriptor = ModuleDescriptor {
        module_id: "s.mux",
        requires: &[Capability::ByteStream, Capability::InnerMutualTls],
        provides: &[Capability::ConnectionMultiplexing],
        ..TRANSPORT
    };
    const DGRAM: ModuleDescriptor = ModuleDescriptor {
        module_id: "t.udp",
        provides: &[Capability::Datagram],
        operating_systems: &[OsFamily::Windows],
        ..TRANSPORT
    };

    #[test]
    fn tc_u_capability_checks() {
        let mut r = Registry::new(OsFamily::Linux);
        r.register(TRANSPORT).expect("t");
        r.register(MUX).expect("m");
        r.register(DGRAM).expect("d");
        assert!(matches!(
            r.register(TRANSPORT),
            Err(RegistryError::Duplicate(_))
        ));
        // Required E2E TLS missing.
        assert!(matches!(
            r.check("s.mux", Role::Client),
            Err(RegistryError::MissingCapability {
                capability: Capability::InnerMutualTls,
                ..
            })
        ));
        // Unsupported OS.
        assert!(matches!(
            r.check("t.udp", Role::Client),
            Err(RegistryError::UnsupportedOs { .. })
        ));
        // Stream consumer cannot use a datagram-only module.
        assert!(r
            .require_capability("t.udp", Capability::ByteStream)
            .is_err());
        assert!(r.require_capability("t.ws", Capability::ByteStream).is_ok());
        assert!(matches!(
            r.check("nope", Role::Client),
            Err(RegistryError::UnknownModule(_))
        ));
    }

    #[test]
    fn digest_tracks_environment() {
        let mut a = Registry::new(OsFamily::Linux);
        a.register(TRANSPORT).expect("t");
        let host = host_vpn_capabilities(OsFamily::Linux);
        let d1 = a.capability_digest(&host);
        a.register(MUX).expect("m");
        assert_ne!(d1, a.capability_digest(&host));
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn vpn_modes_reported_unsupported() {
        let caps = host_vpn_capabilities(OsFamily::current());
        assert_eq!(caps.modes.len(), 4);
        assert!(caps
            .modes
            .iter()
            .all(|m| m.support == Support::Unsupported && !m.explanation.is_empty()));
        assert!(!caps.native_kill_switch);
    }
}
