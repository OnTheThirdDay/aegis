//! Installing and removing the launch daemon (run as root, by the app's
//! own executable started with `--vpn-install` / `--vpn-uninstall`).

use super::{LABEL, SOCKET};
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::Duration;

const BINARY: &str = "/Library/PrivilegedHelperTools/borne.aegis.vpn";
const PLIST: &str = "/Library/LaunchDaemons/borne.aegis.vpn.plist";

/// The helper as versions from before the rename to AegisBorne installed it.
const OLD_LABEL: &str = "net.aegisnet.vpn";
const OLD_FILES: [&str; 3] = [
    "/Library/LaunchDaemons/net.aegisnet.vpn.plist",
    "/Library/PrivilegedHelperTools/net.aegisnet.vpn",
    "/var/run/aegisnet-vpn.sock",
];
const OLD_ANCHOR: &str = "com.apple/aegisnet";
const OLD_STATE_DIR: &str = "/Library/Application Support/AegisNet";

/// Remove the helper of a version from before the rename. Its journal moves
/// to the new state folder first, so the new helper undoes what the old one
/// left behind. Like any update of the helper, this releases its kill
/// switch.
fn remove_previous() {
    let _ = launchctl(&["bootout", &format!("system/{OLD_LABEL}")]);
    let _ = super::pfctl(&["-a", OLD_ANCHOR, "-F", "all"], None);
    for path in OLD_FILES {
        let _ = std::fs::remove_file(path);
    }
    let old = std::path::Path::new(OLD_STATE_DIR);
    if !old.is_dir() {
        return;
    }
    let new = std::path::Path::new(super::daemon::STATE_DIR);
    let (from, to) = (old.join("vpn-journal.json"), new.join("vpn-journal.json"));
    if from.exists() && !to.exists() && std::fs::create_dir_all(new).is_ok() {
        let _ = std::fs::set_permissions(new, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::rename(&from, &to);
    }
    let _ = std::fs::remove_dir_all(old);
}

fn launchctl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

fn plist(uid: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{BINARY}</string>
    <string>--vpn-daemon</string>
    <string>--allow</string>
    <string>{uid}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#
    )
}

/// Install (or update) the helper for the user `uid`, and start it.
pub fn install(uid: &str) -> Result<(), String> {
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid user".into());
    }
    remove_previous();
    let target = format!("system/{LABEL}");
    let _ = launchctl(&["bootout", &target]);
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    std::fs::create_dir_all("/Library/PrivilegedHelperTools").map_err(|e| e.to_string())?;
    // Copied in place, then renamed: root-owned, writable by root only.
    let tmp = format!("{BINARY}.new");
    std::fs::copy(&me, &tmp).map_err(|e| format!("Could not copy the helper: {e}"))?;
    std::os::unix::fs::chown(&tmp, Some(0), Some(0)).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, BINARY).map_err(|e| e.to_string())?;
    std::fs::write(PLIST, plist(uid)).map_err(|e| e.to_string())?;
    std::os::unix::fs::chown(PLIST, Some(0), Some(0)).map_err(|e| e.to_string())?;
    std::fs::set_permissions(PLIST, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| e.to_string())?;
    // launchd may still be letting go of the previous instance.
    let mut tries = 0;
    loop {
        match launchctl(&["bootstrap", "system", PLIST]) {
            Ok(()) => return Ok(()),
            Err(_) if tries < 10 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(500));
            }
            Err(e) => return Err(format!("Could not start the helper: {e}")),
        }
    }
}

/// Stop and remove the helper.
pub fn uninstall() -> Result<(), String> {
    remove_previous();
    let _ = launchctl(&["bootout", &format!("system/{LABEL}")]);
    // A kill switch the helper left blocking goes with it.
    let _ = super::pfctl(&["-a", super::ANCHOR, "-F", "all"], None);
    for path in [PLIST, BINARY, SOCKET] {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("Could not remove {path}: {e}"));
            }
            _ => {}
        }
    }
    Ok(())
}
