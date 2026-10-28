//! Desktop system VPN (ADR-0015): every app's traffic, not only the apps
//! that use the local proxy, goes through the client node.
//!
//! Capturing traffic needs administrator rights, the app doesn't. So a
//! small helper runs privileged: a Windows service (Wintun) or a macOS
//! launch daemon (utun), installed once from the app with one prompt. It
//! owns the VPN interface, routes and DNS and feeds the captured packets
//! into the client node's local SOCKS proxy, through the packet path the
//! phone uses ([`aegis_tun`]). The app controls it over a local channel
//! only the installing user (and administrators) can open; the VPN lives
//! as long as the app's connection.
//!
//! The helper is the app's own executable, copied to a protected location
//! and started with `--vpn-service` (Windows) or `--vpn-daemon` (macOS):
//! the app calls [`dispatch`] first thing in `main`.
#![deny(unsafe_code)]

pub mod client;
pub mod helper;
pub mod proto;

#[cfg(any(windows, target_os = "macos"))]
mod device;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// Whether this platform has a system VPN.
pub fn supported() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// Value of `--name value` in `args`.
fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// When the process was started as the helper or its installer, do that
/// and return the exit code; `None` for a normal start of the app.
pub fn dispatch(args: &[String]) -> Option<i32> {
    let command = args.get(1)?.as_str();
    if !matches!(
        command,
        "--vpn-service" | "--vpn-daemon" | "--vpn-install" | "--vpn-uninstall"
    ) {
        return None;
    }
    let allow = arg(args, "--allow").unwrap_or_default();
    let report = arg(args, "--report").map(std::path::PathBuf::from);
    let result: Result<(), String> = match command {
        #[cfg(windows)]
        "--vpn-service" => windows::service::run(allow),
        #[cfg(target_os = "macos")]
        "--vpn-daemon" => macos::daemon::run(allow),
        #[cfg(windows)]
        "--vpn-install" => windows::install::install(allow),
        #[cfg(windows)]
        "--vpn-uninstall" => windows::install::uninstall(),
        #[cfg(target_os = "macos")]
        "--vpn-install" => macos::install::install(allow),
        #[cfg(target_os = "macos")]
        "--vpn-uninstall" => macos::install::uninstall(),
        _ => {
            let _ = allow;
            Err("The system VPN isn't available on this platform.".into())
        }
    };
    // The installer runs elevated, without a window: the app reads the
    // outcome from the report file it named.
    if let Some(report) = report {
        let _ = std::fs::write(report, result.as_ref().err().map_or("", String::as_str));
    }
    Some(if result.is_ok() { 0 } else { 1 })
}
