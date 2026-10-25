//! Portable data location and user settings.
//!
//! The app is portable: it keeps everything in `AegisNet-data` next to the
//! executable when that folder is writable (USB stick, Downloads), and falls
//! back to the per-user application data folder otherwise. `AEGIS_CLIENT_DATA`
//! overrides both.

use crate::sysproxy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub socks_port: u16,
    pub http_port: u16,
    /// Point the OS proxy at the local HTTP proxy while connected.
    pub system_proxy: bool,
    pub auto_connect: bool,
    /// Previous OS proxy values, kept while ours are applied so a crash can
    /// be undone at the next start.
    pub proxy_saved: Option<sysproxy::Saved>,
    #[serde(skip)]
    pub path: PathBuf,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            socks_port: 1080,
            http_port: 8080,
            system_proxy: false,
            auto_connect: false,
            proxy_saved: None,
            path: PathBuf::new(),
        }
    }
}

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        let path = dir.join("settings.json");
        let mut s: Settings = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        s.path = path;
        s
    }

    pub fn save(&self) -> std::io::Result<()> {
        let text = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, &self.path)
    }
}

fn writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write-test");
    let ok = std::fs::write(&probe, b"x").is_ok();
    let _ = std::fs::remove_file(probe);
    ok
}

/// Resolve (and create) the data directory.
pub fn data_dir() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("AEGIS_CLIENT_DATA") {
        let p = PathBuf::from(p);
        return if writable(&p) {
            Ok(p)
        } else {
            Err(format!("{} is not writable", p.display()))
        };
    }
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
    {
        let portable = exe_dir.join("AegisNet-data");
        if writable(&portable) {
            return Ok(portable);
        }
    }
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
    };
    let dir = base.ok_or("no home directory")?.join("AegisNet");
    if writable(&dir) {
        Ok(dir)
    } else {
        Err(format!("{} is not writable", dir.display()))
    }
}
