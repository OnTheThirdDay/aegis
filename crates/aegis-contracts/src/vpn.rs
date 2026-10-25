//! System-VPN contract enums (10 §3). Platform adapters are M3/M4 work; only
//! the platform-neutral vocabulary lives here.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnMode {
    Global,
    IncludeApps,
    ExcludeApps,
    Rule,
}

impl VpnMode {
    pub const ALL: [VpnMode; 4] = [
        VpnMode::Global,
        VpnMode::IncludeApps,
        VpnMode::ExcludeApps,
        VpnMode::Rule,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VpnMode::Global => "global",
            VpnMode::IncludeApps => "include_apps",
            VpnMode::ExcludeApps => "exclude_apps",
            VpnMode::Rule => "rule",
        }
    }
}

/// Client-side flow action. `Direct` is a local physical-network bypass and is
/// never the gateway's `direct_tcp` egress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowAction {
    Tunnel,
    Direct,
    Block,
}

impl FlowAction {
    pub fn as_str(self) -> &'static str {
        match self {
            FlowAction::Tunnel => "tunnel",
            FlowAction::Direct => "direct",
            FlowAction::Block => "block",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Attribution {
    Verified,
    Scoped,
    #[default]
    Unknown,
    Ambiguous,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpProtocol {
    Tcp,
    Udp,
    Other,
}

impl IpProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            IpProtocol::Tcp => "tcp",
            IpProtocol::Udp => "udp",
            IpProtocol::Other => "other",
        }
    }
}
