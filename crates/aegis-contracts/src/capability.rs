//! Module capability descriptors (02 §4).

use serde::{Deserialize, Serialize};

/// Capabilities a module may provide or require. Registry-controlled; adding a
/// variant is a contract change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ByteStream,
    Datagram,
    IpPacket,
    TcpFlowAdapter,
    DnsMessage,
    AppIdentityVerified,
    HostVpnPolicy,
    KillSwitchEnforced,
    ConnectionMultiplexing,
    Ordered,
    HalfClose,
    ServerStream,
    HttpReverseProxyCompatible,
    InnerMutualTls,
    OuterTls,
    EgressAcl,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::ByteStream => "ByteStream",
            Capability::Datagram => "Datagram",
            Capability::IpPacket => "IpPacket",
            Capability::TcpFlowAdapter => "TcpFlowAdapter",
            Capability::DnsMessage => "DnsMessage",
            Capability::AppIdentityVerified => "AppIdentityVerified",
            Capability::HostVpnPolicy => "HostVpnPolicy",
            Capability::KillSwitchEnforced => "KillSwitchEnforced",
            Capability::ConnectionMultiplexing => "ConnectionMultiplexing",
            Capability::Ordered => "Ordered",
            Capability::HalfClose => "HalfClose",
            Capability::ServerStream => "ServerStream",
            Capability::HttpReverseProxyCompatible => "HttpReverseProxyCompatible",
            Capability::InnerMutualTls => "InnerMutualTls",
            Capability::OuterTls => "OuterTls",
            Capability::EgressAcl => "EgressAcl",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Maturity {
    Experimental,
    Beta,
    Ga,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Client,
    Gateway,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Linux,
    Windows,
    Macos,
    Android,
    Ios,
    Other,
}

impl OsFamily {
    pub fn current() -> Self {
        if cfg!(target_os = "android") {
            OsFamily::Android
        } else if cfg!(target_os = "linux") {
            OsFamily::Linux
        } else if cfg!(target_os = "windows") {
            OsFamily::Windows
        } else if cfg!(target_os = "macos") {
            OsFamily::Macos
        } else if cfg!(target_os = "ios") {
            OsFamily::Ios
        } else {
            OsFamily::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OsFamily::Linux => "linux",
            OsFamily::Windows => "windows",
            OsFamily::Macos => "macos",
            OsFamily::Android => "android",
            OsFamily::Ios => "ios",
            OsFamily::Other => "other",
        }
    }
}

/// Declared resource ceilings for a module. These are ceilings, not promises.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceBudget {
    pub max_open_streams: u32,
    pub max_sockets: u32,
    pub read_buffer_bytes: u32,
    pub write_buffer_bytes: u32,
    pub timers: u32,
}

/// Static module declaration. `module_id` is registry controlled and is the
/// only identity; display names are not identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModuleDescriptor {
    pub module_id: &'static str,
    pub module_version: &'static str,
    pub api_version: u16,
    pub roles: &'static [Role],
    pub operating_systems: &'static [OsFamily],
    pub provides: &'static [Capability],
    pub requires: &'static [Capability],
    pub budget: ResourceBudget,
    pub maturity: Maturity,
    /// Hash of the conformance suite the module was qualified against; empty
    /// means "not qualified" and is reported as such.
    pub conformance_hash: &'static str,
}

impl ModuleDescriptor {
    pub fn supports_os(&self, os: OsFamily) -> bool {
        self.operating_systems.contains(&os)
    }

    pub fn supports_role(&self, role: Role) -> bool {
        self.roles.contains(&role)
    }
}
