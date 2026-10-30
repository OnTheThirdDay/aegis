//! macOS: a utun interface, routes through the routing socket, the
//! resolver set with `networksetup` (and restored), the kill switch as pf
//! rules, a launch daemon running as root, a Unix socket that serves only
//! the installing user and root.

pub mod daemon;
pub mod install;

use crate::device::Packets;
use crate::helper::{DnsSaved, HostRoute, System, Tun, Uplink};
use aegis_tun::{dns, packet, routes};
use route_manager::{Route, RouteManager};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::{Command, Stdio};

pub const SOCKET: &str = "/var/run/aegisborne-vpn.sock";
pub const LABEL: &str = "borne.aegis.vpn";
/// The kill switch's pf anchor: the stock `/etc/pf.conf` evaluates every
/// anchor under `com.apple/`, so nothing else on the system changes.
pub const ANCHOR: &str = "com.apple/aegisborne";
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

    fn open_tun(&self) -> io::Result<(Packets, Tun)> {
        let dev = tun_rs::DeviceBuilder::new()
            .ipv4(LOCAL, 30u8, Some(PEER))
            .ipv6(Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126u8)
            .mtu(packet::MTU)
            .build_async()?;
        let index = dev.if_index()?;
        let name = dev.name()?;
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
            Tun { index, name },
        ))
    }

    fn read_dns(&self) -> io::Result<DnsSaved> {
        services()?
            .into_iter()
            .map(|service| dns_servers(&service).map(|old| (service, old)))
            .collect()
    }

    fn set_dns(&self, saved: &DnsSaved) -> io::Result<()> {
        let ours = vec![dns::SERVER.to_string()];
        for (i, (service, _)) in saved.iter().enumerate() {
            if let Err(e) = set_dns_servers(service, &ours) {
                let _ = self.restore_dns(&saved[..i].to_vec());
                return Err(e);
            }
        }
        Ok(())
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

    fn block(
        &self,
        tun: Option<&Tun>,
        allow: &[Ipv4Addr],
        token: Option<String>,
    ) -> io::Result<Option<String>> {
        pfctl(&["-a", ANCHOR, "-f", "-"], Some(&kill_rules(tun, allow)?))?;
        if token.is_some() {
            return Ok(token);
        }
        // Enable pf with a reference of our own, released by `-X`.
        let out = pfctl(&["-E"], None)?;
        Ok(out
            .lines()
            .find_map(|l| l.strip_prefix("Token : "))
            .map(|t| t.trim().to_owned()))
    }

    fn unblock(&self, token: Option<&str>) -> io::Result<()> {
        pfctl(&["-a", ANCHOR, "-F", "all"], None)?;
        if let Some(token) = token {
            let _ = pfctl(&["-X", token], None);
        }
        Ok(())
    }

    fn blocking(&self) -> bool {
        pfctl(&["-a", ANCHOR, "-s", "rules"], None).is_ok_and(|rules| !rules.trim().is_empty())
    }
}

/// Run pfctl; its stdout and stderr together.
pub fn pfctl(args: &[&str], input: Option<&str>) -> io::Result<String> {
    let mut child = Command::new("/sbin/pfctl")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
        stdin.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(io::Error::other(text.trim().to_owned()))
    }
}

/// The kill switch as pf rules: outbound traffic only through the VPN
/// interface, to loopback, local networks and the server, and to DNS
/// servers while the VPN is down.
fn kill_rules(tun: Option<&Tun>, allow: &[Ipv4Addr]) -> io::Result<String> {
    let mut rules = String::from("pass out quick on lo0 all\n");
    if let Some(tun) = tun {
        if tun.name.is_empty() || !tun.name.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(io::Error::other("unexpected interface name"));
        }
        rules += &format!("pass out quick on {} all\n", tun.name);
    }
    rules += "pass out quick inet to { 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 }\n";
    rules += "pass out quick inet6 to { fe80::/10, fc00::/7, ff00::/8 }\n";
    if !allow.is_empty() {
        let list: Vec<String> = allow.iter().map(Ipv4Addr::to_string).collect();
        rules += &format!("pass out quick inet to {{ {} }}\n", list.join(", "));
    }
    if tun.is_none() {
        rules += "pass out quick proto { udp tcp } to any port 53\n";
    }
    rules += "block drop out quick all\n";
    Ok(rules)
}
