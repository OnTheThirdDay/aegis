//! Replacing this app with a newer build its server offered (ADR-0017).
//!
//! The build was downloaded and checked by `aegis_join::update`: signed by
//! the release workflow, for this platform, newer than this version, and
//! matching its SHA-256. Here it only takes this app's place, which the
//! user starts from the window; the app then restarts.
//!
//! * Windows, Linux: the executable is swapped in its folder (the running
//!   one is renamed aside first, which both allow), so the portable data
//!   folder next to it stays.
//! * macOS: the app bundle is replaced by the one in the disk image.

use std::path::{Path, PathBuf};

/// Where the previous executable is set aside on Windows and Linux.
fn aside(exe: &Path) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".old");
    exe.with_file_name(name)
}

/// Remove what an earlier update left behind.
pub fn cleanup() {
    if cfg!(target_os = "macos") {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(aside(&exe));
    }
}

/// The app bundle this executable runs from (macOS).
#[cfg(target_os = "macos")]
fn bundle(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.ends_with("MacOS") && contents.ends_with("Contents")).then(|| app.to_path_buf())
}

/// Put the downloaded build in this app's place. Returns what to start.
pub fn install(downloaded: &Path) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    install_for(&exe, downloaded)
}

#[cfg(not(target_os = "macos"))]
fn install_for(exe: &Path, downloaded: &Path) -> Result<PathBuf, String> {
    let mut staged = exe.file_name().unwrap_or_default().to_os_string();
    staged.push(".new");
    let staged = exe.with_file_name(staged);
    let cant = |e: std::io::Error| {
        format!(
            "Could not update the app in {} ({e}). Download the new version from your server's page instead.",
            exe.parent().map(|p| p.display().to_string()).unwrap_or_default()
        )
    };
    std::fs::copy(downloaded, &staged).map_err(cant)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755)).map_err(cant)?;
    }
    let old = aside(exe);
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old).map_err(cant)?;
    if let Err(e) = std::fs::rename(&staged, exe) {
        let _ = std::fs::rename(&old, exe);
        return Err(cant(e));
    }
    let _ = std::fs::remove_file(downloaded);
    Ok(exe.to_path_buf())
}

#[cfg(target_os = "macos")]
fn install_for(exe: &Path, downloaded: &Path) -> Result<PathBuf, String> {
    use std::process::Command;
    let current = bundle(exe).ok_or("This app isn't running from an app bundle; download the new version from your server's page instead.")?;
    let folder = current.parent().ok_or("no folder")?.to_path_buf();
    let mount = std::env::temp_dir().join(format!("aegisborne-update-{}", std::process::id()));
    std::fs::create_dir_all(&mount).map_err(|e| e.to_string())?;
    let attached = Command::new("/usr/bin/hdiutil")
        .args([
            "attach",
            "-nobrowse",
            "-readonly",
            "-noautoopen",
            "-mountpoint",
        ])
        .arg(&mount)
        .arg(downloaded)
        .output()
        .map_err(|e| e.to_string())?;
    if !attached.status.success() {
        return Err(format!(
            "Could not open the update: {}",
            String::from_utf8_lossy(&attached.stderr).trim()
        ));
    }
    let result = (|| {
        let source = mount.join("AegisBorne.app");
        if !source.is_dir() {
            return Err("The update has no AegisBorne.app.".to_owned());
        }
        // A bundle from before the rename (AegisNet.app) takes the new name.
        let target = folder.join("AegisBorne.app");
        let staged = folder.join(".AegisBorne.app.new");
        let _ = std::fs::remove_dir_all(&staged);
        let copied = Command::new("/usr/bin/ditto")
            .arg(&source)
            .arg(&staged)
            .status()
            .map_err(|e| e.to_string())?;
        if !copied.success() {
            let _ = std::fs::remove_dir_all(&staged);
            return Err(format!(
                "Could not copy the update into {}. Download the new version from your server's page instead.",
                folder.display()
            ));
        }
        let old = folder.join(".AegisBorne.app.old");
        let _ = std::fs::remove_dir_all(&old);
        std::fs::rename(&current, &old).map_err(|e| e.to_string())?;
        if let Err(e) = std::fs::rename(&staged, &target) {
            let _ = std::fs::rename(&old, &current);
            return Err(e.to_string());
        }
        let _ = std::fs::remove_dir_all(&old);
        Ok(target)
    })();
    let _ = Command::new("/usr/bin/hdiutil")
        .args(["detach", "-quiet"])
        .arg(&mount)
        .status();
    let _ = std::fs::remove_dir(&mount);
    if result.is_ok() {
        let _ = std::fs::remove_file(downloaded);
    }
    result
}

/// Start the updated app (the caller exits right after).
pub fn relaunch(started: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("/usr/bin/open")
        .arg("-n")
        .arg(started)
        .spawn();
    #[cfg(not(target_os = "macos"))]
    let spawned = std::process::Command::new(started).spawn();
    spawned.map(|_| ()).map_err(|e| e.to_string())
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn the_executable_is_swapped_in_place() {
        let dir = std::env::temp_dir().join(format!("aegis-selfupdate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let exe = dir.join("aegis-client.exe");
        let downloaded = dir.join("download.bin");
        std::fs::write(&exe, b"old").expect("exe");
        std::fs::write(&downloaded, b"new").expect("download");
        assert_eq!(install_for(&exe, &downloaded).expect("install"), exe);
        assert_eq!(std::fs::read(&exe).expect("read"), b"new");
        assert_eq!(std::fs::read(aside(&exe)).expect("aside"), b"old");
        assert!(!downloaded.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
