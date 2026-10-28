//! The VPN packet path, shared by the phone (Android `VpnService`) and the
//! desktop system VPN (Wintun, utun).
//!
//! The platform hands over a packet device (one IP packet per read and per
//! write); [`packet::run`] terminates TCP and UDP in userspace and opens
//! each flow through the client node's local SOCKS proxy, answering DNS
//! itself with [`dns::FakeDns`]. [`routes`] is the set of destinations the
//! VPN captures.
#![forbid(unsafe_code)]

pub mod dns;
pub mod packet;
pub mod routes;
pub mod socks;
