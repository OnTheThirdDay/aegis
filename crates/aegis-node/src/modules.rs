//! T0 built-in module registry for this build.

use aegis_config::ModuleIds;
use aegis_contracts::capability::{
    Capability, Maturity, ModuleDescriptor, OsFamily, ResourceBudget, Role,
};
use aegis_platform::Registry;

/// Portable modules: plain Rust over TCP/TLS, also used by the mobile
/// client core (crates/aegis-mobile).
const PORTABLE: &[OsFamily] = &[
    OsFamily::Linux,
    OsFamily::Windows,
    OsFamily::Macos,
    OsFamily::Android,
    OsFamily::Ios,
];

pub const SESSION: ModuleDescriptor = ModuleDescriptor {
    module_id: ModuleIds::SESSION,
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client, Role::Gateway],
    operating_systems: PORTABLE,
    provides: &[
        Capability::ConnectionMultiplexing,
        Capability::ByteStream,
        Capability::Ordered,
        Capability::HalfClose,
        Capability::ServerStream,
    ],
    requires: &[Capability::ByteStream, Capability::InnerMutualTls],
    budget: ResourceBudget {
        max_open_streams: 4096,
        max_sockets: 0,
        read_buffer_bytes: 2 * 1024 * 1024,
        write_buffer_bytes: 64 * 1024,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

pub const MTLS: ModuleDescriptor = ModuleDescriptor {
    module_id: ModuleIds::MTLS,
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client, Role::Gateway],
    operating_systems: PORTABLE,
    provides: &[Capability::InnerMutualTls],
    requires: &[Capability::ByteStream],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 0,
        read_buffer_bytes: 32 * 1024,
        write_buffer_bytes: 32 * 1024,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

pub const TUNNEL: ModuleDescriptor = ModuleDescriptor {
    module_id: ModuleIds::TUNNEL,
    module_version: env!("CARGO_PKG_VERSION"),
    api_version: 1,
    roles: &[Role::Client],
    operating_systems: PORTABLE,
    provides: &[Capability::ByteStream, Capability::HalfClose],
    requires: &[
        Capability::ConnectionMultiplexing,
        Capability::InnerMutualTls,
        Capability::HttpReverseProxyCompatible,
    ],
    budget: ResourceBudget {
        max_open_streams: 0,
        max_sockets: 1,
        read_buffer_bytes: 0,
        write_buffer_bytes: 0,
        timers: 1,
    },
    maturity: Maturity::Experimental,
    conformance_hash: "",
};

pub fn registry(os: OsFamily) -> Registry {
    let mut r = Registry::new(os);
    for d in [
        aegis_transport_ws::DESCRIPTOR,
        aegis_transport_quic::DESCRIPTOR,
        aegis_inbound_socks::DESCRIPTOR,
        aegis_inbound_http::DESCRIPTOR,
        aegis_outbound_direct::DESCRIPTOR,
        SESSION,
        MTLS,
        TUNNEL,
    ] {
        // Built-in IDs are unique by construction.
        let _ = r.register(d);
    }
    r
}
