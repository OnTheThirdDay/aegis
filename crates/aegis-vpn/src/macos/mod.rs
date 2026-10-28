//! macOS: a utun interface, routes through the routing socket, the
//! resolver set with `networksetup` (and restored), a launch daemon
//! running as root, a Unix socket that serves only the installing user and
//! root.

pub mod daemon;
pub mod install;

use crate::device::Packets;
use crate::helper::{DnsSaved, HostRoute, System, Uplink};
use aegis_tun::{dns, packet, routes};
use route_manager::{Route, RouteManager};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

pub const SOCKET: &str = "/var/run/aegisnet-vpn.sock";
pub const LABEL: &str = "net.aegisnet.vpn";
/// The utun interface's own and peer addresses.
const LOCAL: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 1);
const PEER: Ipv4Addr = Ipv4Addr::new(172, 19, 0, 2);

/// The numeric ID of the user running this process.
pub fn current_uid() -> Result<String, String> {
    let out = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()) {
        Ok(uid)
    } else {
        Err("could not determine the current user".into())
    }
}

pub struct MacOs;

fn uplink_of(route: &Route) -> Option<Uplink> {
    Some(Uplink {
        gateway: route.gateway().filter(|g| !g.is_unspecified()),
        if_index: route.if_index()?,
    })
}

fn route_of(r: &HostRoute) -> Route {
    let route = Route::new(IpAddr::V4(r.dest), 32);
    match r.via.gateway {
        Some(g) => route.with_gateway(g),
        None => route.with_if_index(r.via.if_index),
    }
}

fn networksetup(args: &[&str]) -> io::Result<String> {
    let out = Command::new("/usr/sbin/networksetup").args(args).output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
    }
}

/// The network services (Wi-Fi, Ethernet, ...); disabled ones are skipped.
fn services() -> io::Result<Vec<String>> {
    let text = networksetup(&["-listallnetworkservices"])?;
    Ok(text
        .lines()
        // The first line explains the asterisk that marks disabled ones.
        .skip(1)
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_owned)
        .collect())
}

/// A service's manually set DNS servers (empty: from DHCP).
fn dns_servers(service: &str) -> io::Result<Vec<String>> {
    let text = networksetup(&["-getdnsservers", service])?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| l.parse::<IpAddr>().is_ok())
        .map(str::to_owned)
        .collect())
}

fn set_dns_servers(service: &str, servers: &[String]) -> io::Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    networksetup(&args).map(|_| ())
}

impl System for MacOs {
    type Device = Packets;

    fn uplink_for(&self, _ip: Ipv4Addr) -> io::Result<Option<Uplink>> {
        Ok(self.default_routes(0)?.into_iter().next())
    }

    fn default_routes(&self, tun_index: u32) -> io::Result<Vec<Uplink>> {
        Ok(RouteManager::new()?
            .list()?
            .iter()
            .filter(|r| {
                r.destination() == IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                    && r.prefix() == 0
                    && !r.if_scope()
                    && r.if_index() != Some(tun_index)
            })
            .filter_map(uplink_of)
            .collect())
    }

    fn add_route(&self, r: &HostRoute) -> io::Result<()> {
        RouteManager::new()?.add(&route_of(r))
    }

    fn delete_route(&self, r: &HostRoute) -> io::Result<()> {
        RouteManager::new()?.delete(&route_of(r))
    }

    fn open_tun(&self) -> io::Result<(Packets, u32)> {
        let dev = tun_rs::DeviceBuilder::new()
            .ipv4(LOCAL, 30u8, Some(PEER))
            .ipv6(Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126u8)
            .mtu(packet::MTU)
            .build_async()?;
        let index = dev.if_index()?;
        let mut manager = RouteManager::new()?;
        for (net, len) in routes::ipv4() {
            manager.add(&Route::new(IpAddr::V4(net), len).with_gateway(IpAddr::V4(PEER)))?;
        }
        for (net, len) in routes::IPV6 {
            let net: Ipv6Addr = net.parse().map_err(io::Error::other)?;
            manager.add(&Route::new(IpAddr::V6(net), *len).with_if_index(index))?;
        }
        Ok((
            Packets {
                device: dev,
                _keep: None,
            },
            index,
        ))
    }

    fn set_dns(&self) -> io::Result<DnsSaved> {
        let ours = vec![dns::SERVER.to_string()];
        let mut saved: DnsSaved = Vec::new();
        for service in services()? {
            let result = dns_servers(&service)
                .and_then(|old| set_dns_servers(&service, &ours).map(|()| old));
            match result {
                Ok(old) => saved.push((service, old)),
                Err(e) => {
                    let _ = self.restore_dns(&saved);
                    return Err(e);
                }
            }
        }
        Ok(saved)
    }

    fn restore_dns(&self, saved: &DnsSaved) -> io::Result<()> {
        let mut result = Ok(());
        for (service, servers) in saved {
            if let Err(e) = set_dns_servers(service, servers) {
                result = Err(e);
            }
        }
        result
    }

    fn flush_dns_cache(&self) {
        let _ = Command::new("/usr/bin/dscacheutil")
            .arg("-flushcache")
            .output();
        let _ = Command::new("/usr/bin/killall")
            .args(["-HUP", "mDNSResponder"])
            .output();
    }
}
