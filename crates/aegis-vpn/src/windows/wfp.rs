//! DNS leak protection (Windows Filtering Platform).
//!
//! Windows may send a lookup to every adapter's DNS server at once, so the
//! router or ISP would see the names and could answer first. While the VPN
//! runs, DNS (port 53, UDP and TCP, IPv4 and IPv6) may leave only through
//! the VPN's adapter, or go to this computer itself (loopback).
//!
//! The filters live in a dynamic WFP session: Windows deletes them when
//! the session closes, which includes the helper exiting or crashing, so
//! nothing can be left blocking DNS.

use std::io;
use std::ptr::{null, null_mut};
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_CONDITION_FLAGS,
    FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_FILTER0,
    FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
    FWP_ACTION_TYPE, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_UINT16, FWP_UINT32, FWP_UINT8,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

/// Our sublayer: its block filter applies whatever other sublayers permit.
const SUBLAYER: GUID = GUID::from_u128(0x6165_6769_736e_6574_2d64_6e73_0000_0001);

/// The open session; closing it removes every filter it added.
pub struct DnsGuard(usize);

impl Drop for DnsGuard {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: the handle came from FwpmEngineOpen0 and is closed once.
        unsafe {
            FwpmEngineClose0(self.0 as HANDLE);
        }
    }
}

fn check(code: u32, what: &str) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Windows Filtering Platform: {what} failed (0x{code:08x})"
        )))
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn remote_port(port: u16) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    c.conditionValue.r#type = FWP_UINT16;
    c.conditionValue.Anonymous.uint16 = port;
    c
}

fn interface(index: u32) -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_INTERFACE_INDEX,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    };
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = index;
    c
}

fn loopback() -> FWPM_FILTER_CONDITION0 {
    let mut c = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_FLAGS,
        matchType: FWP_MATCH_FLAGS_ALL_SET,
        ..Default::default()
    };
    c.conditionValue.r#type = FWP_UINT32;
    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    c
}

/// Add one filter to our sublayer: a higher `weight` wins within it.
#[allow(unsafe_code)]
fn add_filter(
    engine: HANDLE,
    name: &mut [u16],
    layer: GUID,
    weight: u8,
    action: FWP_ACTION_TYPE,
    mut condition: FWPM_FILTER_CONDITION0,
) -> io::Result<()> {
    let mut filter = FWPM_FILTER0 {
        layerKey: layer,
        subLayerKey: SUBLAYER,
        numFilterConditions: 1,
        filterCondition: &mut condition,
        ..Default::default()
    };
    filter.displayData.name = name.as_mut_ptr();
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = weight;
    filter.action.r#type = action;
    // SAFETY: `filter` and what it points to (the condition, the name) live
    // across the call; WFP copies them.
    check(
        unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) },
        "adding a filter",
    )
}

#[allow(unsafe_code)]
fn add_all(engine: HANDLE, tun_index: u32, name: &mut [u16]) -> io::Result<()> {
    let mut sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER,
        weight: u16::MAX,
        ..Default::default()
    };
    sublayer.displayData.name = name.as_mut_ptr();
    // SAFETY: `sublayer` and its name live across the call.
    check(
        unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) },
        "adding the sublayer",
    )?;
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    ] {
        add_filter(engine, name, layer, 1, FWP_ACTION_BLOCK, remote_port(53))?;
        add_filter(
            engine,
            name,
            layer,
            10,
            FWP_ACTION_PERMIT,
            interface(tun_index),
        )?;
        add_filter(engine, name, layer, 10, FWP_ACTION_PERMIT, loopback())?;
    }
    Ok(())
}

/// Block DNS everywhere but through the interface `tun_index` and loopback,
/// until the guard is dropped.
#[allow(unsafe_code)]
pub fn block_dns_outside(tun_index: u32) -> io::Result<DnsGuard> {
    let mut name = wide("AegisNet VPN: DNS only through the VPN");
    let mut session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    session.displayData.name = name.as_mut_ptr();
    let mut engine: HANDLE = null_mut();
    // SAFETY: `session` lives across the call; `engine` receives a handle
    // owned by the guard from here on.
    check(
        unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) },
        "opening the filter engine",
    )?;
    let guard = DnsGuard(engine as usize);
    // SAFETY: `engine` is the open handle above.
    check(
        unsafe { FwpmTransactionBegin0(engine, 0) },
        "starting a transaction",
    )?;
    if let Err(e) = add_all(engine, tun_index, &mut name) {
        // SAFETY: a transaction is open on `engine`.
        unsafe {
            FwpmTransactionAbort0(engine);
        }
        return Err(e);
    }
    // SAFETY: a transaction is open on `engine`.
    check(
        unsafe { FwpmTransactionCommit0(engine) },
        "committing the filters",
    )?;
    Ok(guard)
}
