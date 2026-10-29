//! Windows: Wintun adapter, routes through the IP helper API, a service
//! running as LocalSystem, a named pipe only the installing user and
//! administrators can open.

pub mod install;
pub mod pipe;
pub mod service;
pub mod wfp;

use crate::device::Packets;
use crate::helper::{DnsSaved, HostRoute, System, Tun, Uplink};
use aegis_tun::{dns, packet, routes};
use route_manager::{Route, RouteManager};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

pub const SERVICE: &str = "AegisBorneVPN";
const ADAPTER: &str = "AegisBorne";
/// A fixed adapter identity: Windows keeps recognising the same network
/// instead of adding "AegisBorne 2", "AegisBorne 3"...
const ADAPTER_GUID: u128 = 0x6165_6769_736e_6574_2d76_706e_0000_0001;
/// Run a console program without flashing a window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `%ProgramFiles%\AegisBorne`: the helper, Wintun and the journal. Only
/// administrators can write there.
pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    base.join("AegisBorne")
}

pub fn hidden(program: &str) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

/// A SID as Windows prints it (`S-1-5-21-…`), nothing else.
pub fn valid_sid(sid: &str) -> bool {
    sid.len() <= 184
        && sid.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'-')
        })
}

/// The SID of the user running this process.
pub fn current_sid() -> Result<String, String> {
    let out = hidden("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .map_err(|e| e.to_string())?;
    // "computer\user","S-1-5-21-…"
    let text = String::from_utf8_lossy(&out.stdout);
    let sid = text
        .trim()
        .rsplit(',')
        .next()
        .unwrap_or("")
        .trim_matches('"');
    if valid_sid(sid) {
        Ok(sid.to_owned())
    } else {
        Err("could not determine the current user".into())
    }
}

pub struct Windows {
    pub wintun: PathBuf,
}

fn uplink_of(route: &Route) -> Option<Uplink> {
    Some(Uplink {
        gateway: route.gateway().filter(|g| !g.is_unspecified()),
        if_index: route.if_index()?,
    })
}

fn route_of(r: &HostRoute) -> Route {
    let route = Route::new(IpAddr::V4(r.dest), 32).with_if_index(r.via.if_index);
    match r.via.gateway {
        Some(g) => route.with_gateway(g),
        None => route,
    }
}

impl System for Windows {
    type Device = Packets;

    fn uplink_for(&self, ip: Ipv4Addr) -> io::Result<Option<Uplink>> {
        Ok(RouteManager::new()?
            .find_route(&IpAddr::V4(ip))?
            .as_ref()
            .and_then(uplink_of))
    }

    fn default_routes(&self, tun_index: u32) -> io::Result<Vec<Uplink>> {
        let mut defaults: Vec<Route> = RouteManager::new()?
            .list()?
            .into_iter()
            .filter(|r| {
                r.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    && r.prefix() == 0
                    && r.if_index() != Some(tun_index)
            })
            .collect();
        defaults.sort_by_key(|r| r.metric().unwrap_or(u32::MAX));
        Ok(defaults.iter().filter_map(uplink_of).collect())
    }

    fn add_route(&self, r: &HostRoute) -> io::Result<()> {
        RouteManager::new()?.add(&route_of(r))
    }

    fn delete_route(&self, r: &HostRoute) -> io::Result<()> {
        RouteManager::new()?.delete(&route_of(r))
    }

    fn open_tun(&self) -> io::Result<(Packets, Tun)> {
        let wintun = self.wintun.to_string_lossy().into_owned();
        let build = || {
            tun_rs::DeviceBuilder::new()
                .name(ADAPTER)
                .description("AegisBorne VPN")
                .device_guid(ADAPTER_GUID)
                .wintun_file(wintun.clone())
                .ipv4(Ipv4Addr::new(172, 19, 0, 1), 30u8, None)
                .ipv6(Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126u8)
                .mtu(packet::MTU)
                // Ahead of the physical adapters, for DNS too.
                .metric(1)
                .build_async()
        };
        // The previous session's adapter may still be closing.
        let mut tries = 0;
        let dev = loop {
            match build() {
                Ok(dev) => break dev,
                Err(e) if tries >= 10 => return Err(e),
                Err(_) => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(300));
                }
            }
        };
        let index = dev.if_index()?;
        dev.set_dns_servers(&[IpAddr::V4(dns::SERVER)])?;
        let mut manager = RouteManager::new()?;
        for (net, len) in routes::ipv4() {
            manager.add(&Route::new(IpAddr::V4(net), len).with_if_index(index))?;
        }
        for (net, len) in routes::IPV6 {
            let net: Ipv6Addr = net.parse().map_err(io::Error::other)?;
            manager.add(&Route::new(IpAddr::V6(net), *len).with_if_index(index))?;
        }
        // Lookups may leave only through the VPN while it runs.
        let dns_guard = wfp::block_dns_outside(index)?;
        Ok((
            Packets {
                device: dev,
                _keep: Some(Box::new(dns_guard)),
            },
            Tun {
                index,
                name: ADAPTER.into(),
            },
        ))
    }

    /// The VPN's resolver is set on its own adapter, which is ahead of the
    /// others, and DNS through any other adapter is blocked (`wfp`).
    fn set_dns(&self) -> io::Result<DnsSaved> {
        Ok(Vec::new())
    }

    fn restore_dns(&self, _saved: &DnsSaved) -> io::Result<()> {
        Ok(())
    }

    fn flush_dns_cache(&self) {
        let _ = hidden("ipconfig").arg("/flushdns").output();
    }

    fn block(
        &self,
        tun: Option<&Tun>,
        allow: &[Ipv4Addr],
        _token: Option<String>,
    ) -> io::Result<Option<String>> {
        wfp::kill_switch(tun.map(|t| t.index), allow).map(|()| None)
    }

    fn unblock(&self, _token: Option<&str>) -> io::Result<()> {
        wfp::remove_kill_switch()
    }

    fn blocking(&self) -> bool {
        wfp::kill_switch_present()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids() {
        assert!(valid_sid("S-1-5-21-1004336348-1177238915-682003330-512"));
        assert!(valid_sid("S-1-5-18"));
        for bad in ["", "S-1-", "S-1-5)(A;;GA;;;WD", "s-1-5-18", "S-1-5-18 "] {
            assert!(!valid_sid(bad), "{bad:?}");
        }
    }
}
