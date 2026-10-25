//! Operating-system proxy setting (Windows: per-user WinINet settings used
//! by Edge, Chrome and most apps). The previous values are returned so they
//! can be restored exactly on disconnect, exit, or the next start after a
//! crash. Other platforms report the manual setting instead.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub bypass: Option<String>,
}

pub fn supported() -> bool {
    cfg!(windows)
}

#[cfg(windows)]
mod imp {
    use super::Saved;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    /// Run reg.exe without flashing a console window.
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn reg(args: &[&str]) -> Result<String, String> {
        let out = Command::new("reg")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }
    }

    fn query(name: &str) -> Option<String> {
        let out = reg(&["query", KEY, "/v", name]).ok()?;
        out.lines().find_map(|l| {
            let mut parts = l.split_whitespace();
            if parts.next()? != name {
                return None;
            }
            let _kind = parts.next()?;
            Some(parts.collect::<Vec<_>>().join(" "))
        })
    }

    fn set(name: &str, kind: &str, value: &str) -> Result<(), String> {
        reg(&["add", KEY, "/v", name, "/t", kind, "/d", value, "/f"]).map(|_| ())
    }

    fn delete(name: &str) {
        let _ = reg(&["delete", KEY, "/v", name, "/f"]);
    }

    pub fn enable(http_port: u16) -> Result<Saved, String> {
        let saved = Saved {
            enable: query("ProxyEnable")
                .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok()),
            server: query("ProxyServer"),
            bypass: query("ProxyOverride"),
        };
        set("ProxyServer", "REG_SZ", &format!("127.0.0.1:{http_port}"))?;
        set(
            "ProxyOverride",
            "REG_SZ",
            "<local>;localhost;127.*;10.*;192.168.*",
        )?;
        set("ProxyEnable", "REG_DWORD", "1")?;
        Ok(saved)
    }

    pub fn restore(saved: &Saved) -> Result<(), String> {
        match &saved.server {
            Some(v) => set("ProxyServer", "REG_SZ", v)?,
            None => delete("ProxyServer"),
        }
        match &saved.bypass {
            Some(v) => set("ProxyOverride", "REG_SZ", v)?,
            None => delete("ProxyOverride"),
        }
        set(
            "ProxyEnable",
            "REG_DWORD",
            &saved.enable.unwrap_or(0).to_string(),
        )
    }
}

#[cfg(not(windows))]
mod imp {
    use super::Saved;

    pub fn enable(http_port: u16) -> Result<Saved, String> {
        Err(format!(
            "set your system or browser proxy to HTTP 127.0.0.1:{http_port} manually on this platform"
        ))
    }

    pub fn restore(_saved: &Saved) -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{enable, restore};
