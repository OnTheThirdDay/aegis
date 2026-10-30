//! Windows Filtering Platform filters, in sublayers of our own (a block
//! there applies whatever other sublayers permit).
//!
//! * DNS leak protection: Windows may send a lookup to every adapter's DNS
//!   server at once, so the router or ISP would see the names and could
//!   answer first. While the VPN runs, DNS (port 53, UDP and TCP, IPv4 and
//!   IPv6) may leave only through the VPN's adapter, or go to this computer
//!   itself. These filters live in a dynamic session: Windows deletes them
//!   when it closes, including when the helper crashes.
//! * Kill switch: everything outbound is blocked but the VPN's adapter,
//!   loopback, local networks and the server's addresses (and DNS, while
//!   the VPN is down, so the app can reconnect). These filters are not
//!   dynamic: they outlive the helper until removed, and a restart of the
//!   computer clears them (they aren't persistent).

use std::io;
use std::net::Ipv4Addr;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0,
    FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_UINT16, FWP_UINT32, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const DNS_SUBLAYER: GUID = GUID::from_u128(0x6165_6769_736e_6574_2d64_6e73_0000_0001);
const KILL_SUBLAYER: GUID = GUID::from_u128(0x6165_6769_736e_6574_2d6b_696c_0000_0001);
/// Kill switch filters have fixed keys (this + 1, + 2, ...) so they can be
/// found and removed by a later helper.
const KILL_FILTER: u128 = 0x6165_6769_736e_6574_2d6b_6966_0000_0000;
const MAX_KILL_FILTERS: u128 = 16;

/// Local networks: reachable with the kill switch on.
const LAN_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];
/// Link-local, unique-local, multicast.
const LAN_V6: &[([u8; 16], u8)] = &[
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Windows Filtering Platform: {what} failed (0x{code:08x})"
        )))
    }
}

/// An open filter engine session (closed on drop).
struct Engine {
    handle: usize,
    name: Vec<u16>,
}

impl Drop for Engine {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
        unsafe {
            FwpmEngineClose0(self.handle as HANDLE);
        }
    }
}

impl Engine {
    /// A dynamic session's objects go away when it closes.
    #[allow(unsafe_code)]
    fn open(dynamic: bool, name: &str) -> io::Result<Engine> {
        let mut name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut session = FWPM_SESSION0 {
            flags: if dynamic {
                FWPM_SESSION_FLAG_DYNAMIC
            } else {
                0
            },
            ..Default::default()
        };
        session.displayData.name = name.as_mut_ptr();
        let mut handle: HANDLE = null_mut();
        // SAFETY: `session` lives across the call; `handle` receives a
        // handle the Engine owns from here on.
        check(
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) },
            "opening the filter engine",
        )?;
        Ok(Engine {
            handle: handle as usize,
            name,
        })
    }

    fn handle(&self) -> HANDLE {
        self.handle as HANDLE
    }

    /// Run `f` in a transaction: all of it applies, or none.
    #[allow(unsafe_code)]
    fn transaction(&mut self, f: impl FnOnce(&mut Engine) -> io::Result<()>) -> io::Result<()> {
        // SAFETY: an open engine handle.
        check(
            unsafe { FwpmTransactionBegin0(self.handle(), 0) },
            "starting a transaction",
        )?;
        if let Err(e) = f(self) {
            // SAFETY: a transaction is open on this handle.
            unsafe {
                FwpmTransactionAbort0(self.handle());
            }
            return Err(e);
        }
        // SAFETY: a transaction is open on this handle.
        check(
            unsafe { FwpmTransactionCommit0(self.handle()) },
            "committing the filters",
        )
    }

    #[allow(unsafe_code)]
    fn add_sublayer(&mut self, key: GUID, weight: u16) -> io::Result<()> {
        let mut sublayer = FWPM_SUBLAYER0 {
            subLayerKey: key,
            weight,
            ..Default::default()
        };
        sublayer.displayData.name = self.name.as_mut_ptr();
        // SAFETY: `sublayer` and its name live across the call.
        check(
            unsafe { FwpmSubLayerAdd0(self.handle(), &sublayer, null_mut()) },
            "adding a sublayer",
        )
    }

    /// Add a filter (conditions on the same field match any of them,
    /// different fields all of them); a higher `weight` wins within the
    /// sublayer.
    #[allow(unsafe_code)]
    fn add_filter(
        &mut self,
        key: Option<GUID>,
        sublayer: GUID,
        layer: GUID,
        weight: u8,
        action: FWP_ACTION_TYPE,
        conditions: &mut [FWPM_FILTER_CONDITION0],
    ) -> io::Result<()> {
        let mut filter = FWPM_FILTER0 {
            filterKey: key.unwrap_or(GUID::from_u128(0)),
            layerKey: layer,
            subLayerKey: sublayer,
            numFilterConditions: conditions.len() as u32,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            ..Default::default()
        };
        filter.displayData.name = self.name.as_mut_ptr();
        filter.weight.r#type = FWP_UINT8;
        filter.weight.Anonymous.uint8 = weight;
        filter.action.r#type = action;
        // SAFETY: `filter` and what it points to (the conditions and the
        // values they point to, the name) live across the call; WFP copies
        // them.
        check(
            unsafe { FwpmFilterAdd0(self.handle(), &filter, null_mut(), null_mut()) },
            "adding a filter",
        )
    }
}

fn condition(field: GUID, match_type: i32) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        ..Default::default()
    }
}

fn remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_PORT, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT16;
    c.conditionValue.Anonymous.uint16 = port;
    c
}

fn interface(index: u32) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_INTERFACE_INDEX, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = index;
    c
}

fn loopback() -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_FLAGS, FWP_MATCH_FLAGS_ALL_SET);
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    c
}

fn remote_v4(ip: Ipv4Addr) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = u32::from(ip);
    c
}

/// `net` must outlive the filter's addition.
fn remote_v4_net(net: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V4_ADDR_MASK;
    c.conditionValue.Anonymous.v4AddrMask = net;
    c
}

fn remote_v6_net(net: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    let mut c = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, FWP_MATCH_EQUAL);
    c.conditionValue.r#type = FWP_V6_ADDR_MASK;
    c.conditionValue.Anonymous.v6AddrMask = net;
    c
}

const LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
];

/// DNS leak protection, until the guard is dropped.
pub struct DnsGuard(#[allow(dead_code)] Engine);

/// Block DNS everywhere but through the interface `tun_index` and loopback.
pub fn block_dns_outside(tun_index: u32) -> io::Result<DnsGuard> {
    let mut engine = Engine::open(true, "AegisBorne VPN: DNS only through the VPN")?;
    engine.transaction(|e| {
        e.add_sublayer(DNS_SUBLAYER, u16::MAX)?;
        for layer in LAYERS {
            e.add_filter(
                None,
                DNS_SUBLAYER,
                layer,
                1,
                FWP_ACTION_BLOCK,
                &mut [remote_port(53)],
            )?;
            let permit = [interface(tun_index), loopback()];
            for c in permit {
                e.add_filter(None, DNS_SUBLAYER, layer, 10, FWP_ACTION_PERMIT, &mut [c])?;
            }
        }
        Ok(())
    })?;
    Ok(DnsGuard(engine))
}

/// Remove the kill switch's filters and sublayer, if present (in the
/// caller's transaction).
#[allow(unsafe_code)]
fn delete_kill_switch(e: &mut Engine) {
    for n in 1..=MAX_KILL_FILTERS {
        let key = GUID::from_u128(KILL_FILTER + n);
        // SAFETY: an open engine handle and a key that lives across the
        // call. Missing filters fail harmlessly.
        unsafe {
            FwpmFilterDeleteByKey0(e.handle(), &key);
        }
    }
    // SAFETY: as above.
    unsafe {
        FwpmSubLayerDeleteByKey0(e.handle(), &KILL_SUBLAYER);
    }
}

/// Turn the kill switch on (replacing an earlier one): outbound traffic
/// may only go through the VPN interface `tun` (when up), to loopback,
/// local networks and `allow`, and to DNS servers while `tun` is `None`.
pub fn kill_switch(tun: Option<u32>, allow: &[Ipv4Addr]) -> io::Result<()> {
    let mut engine = Engine::open(false, "AegisBorne VPN: kill switch")?;
    engine.transaction(|e| {
        delete_kill_switch(e);
        e.add_sublayer(KILL_SUBLAYER, u16::MAX - 1)?;
        let mut n = 0;
        let mut key = || {
            n += 1;
            Some(GUID::from_u128(KILL_FILTER + n))
        };
        let mut lan_v4: Vec<FWP_V4_ADDR_AND_MASK> = LAN_V4
            .iter()
            .map(|(ip, len)| FWP_V4_ADDR_AND_MASK {
                addr: u32::from(*ip),
                mask: u32::MAX.checked_shl(32 - u32::from(*len)).unwrap_or(0),
            })
            .collect();
        let mut lan_v6: Vec<FWP_V6_ADDR_AND_MASK> = LAN_V6
            .iter()
            .map(|(addr, len)| FWP_V6_ADDR_AND_MASK {
                addr: *addr,
                prefixLength: *len,
            })
            .collect();
        let permit = |e: &mut Engine, key, layer, conditions: &mut [FWPM_FILTER_CONDITION0]| {
            e.add_filter(key, KILL_SUBLAYER, layer, 10, FWP_ACTION_PERMIT, conditions)
        };
        for (layer, v6) in [(LAYERS[0], false), (LAYERS[1], true)] {
            if let Some(index) = tun {
                permit(e, key(), layer, &mut [interface(index)])?;
            }
            permit(e, key(), layer, &mut [loopback()])?;
            let mut lan: Vec<FWPM_FILTER_CONDITION0> = if v6 {
                lan_v6.iter_mut().map(remote_v6_net).collect()
            } else {
                lan_v4.iter_mut().map(remote_v4_net).collect()
            };
            permit(e, key(), layer, &mut lan)?;
            if !v6 && !allow.is_empty() {
                let mut server: Vec<FWPM_FILTER_CONDITION0> =
                    allow.iter().map(|ip| remote_v4(*ip)).collect();
                permit(e, key(), layer, &mut server)?;
            }
            if tun.is_none() {
                permit(e, key(), layer, &mut [remote_port(53)])?;
            }
            e.add_filter(key(), KILL_SUBLAYER, layer, 0, FWP_ACTION_BLOCK, &mut [])?;
        }
        Ok(())
    })
}

/// Turn the kill switch off (nothing to do when it is off).
pub fn remove_kill_switch() -> io::Result<()> {
    let mut engine = Engine::open(false, "AegisBorne VPN: kill switch")?;
    engine.transaction(|e| {
        delete_kill_switch(e);
        Ok(())
    })
}

/// Whether the kill switch's filters are in place.
#[allow(unsafe_code)]
pub fn kill_switch_present() -> bool {
    let Ok(engine) = Engine::open(false, "AegisBorne VPN: kill switch") else {
        return false;
    };
    let mut sublayer: *mut FWPM_SUBLAYER0 = null_mut();
    // SAFETY: an open engine handle; on success WFP allocates `sublayer`,
    // freed right after.
    let found =
        unsafe { FwpmSubLayerGetByKey0(engine.handle(), &KILL_SUBLAYER, &mut sublayer) } == 0;
    if !sublayer.is_null() {
        // SAFETY: memory WFP allocated above.
        unsafe {
            FwpmFreeMemory0(std::ptr::from_mut(&mut sublayer).cast());
        }
    }
    found
}
