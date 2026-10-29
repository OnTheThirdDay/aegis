//! Installing and removing the service (run elevated, by the app's own
//! executable started with `--vpn-install` / `--vpn-uninstall`).

use super::{install_dir, valid_sid, SERVICE};
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};
use windows_service::service::{
    Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

#[cfg(has_wintun)]
const WINTUN: Option<(&[u8], &[u8])> = Some((
    include_bytes!(concat!(env!("OUT_DIR"), "/wintun.dll")),
    include_bytes!(concat!(env!("OUT_DIR"), "/wintun-LICENSE.txt")),
));
#[cfg(not(has_wintun))]
const WINTUN: Option<(&[u8], &[u8])> = None;

const EXE: &str = "aegisborne-vpn.exe";
/// What the app consists of besides the helper, and the journal of changes
/// to undo after a crash (with the kill switch's record).
const FILES: [&str; 4] = [
    "wintun.dll",
    "wintun-LICENSE.txt",
    "vpn-journal.json",
    "vpn-journal.kill.json",
];

/// The helper as versions from before the rename to AegisBorne installed it.
const OLD_SERVICE: &str = "AegisNetVPN";
const OLD_DIR: &str = "AegisNet";
const OLD_EXE: &str = "aegisnet-vpn.exe";

fn manager() -> Result<ServiceManager, String> {
    ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("Could not open the service manager: {e}"))
}

fn wait_for(service: &Service, state: ServiceState) {
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        match service.query_status() {
            Ok(s) if s.current_state == state => return,
            Ok(_) => std::thread::sleep(Duration::from_millis(200)),
            Err(_) => return,
        }
    }
}

/// Retry a file operation while a just-stopped process lets go of it.
fn retry(mut f: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    let mut tries = 0;
    loop {
        match f() {
            Err(_) if tries < 25 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(200));
            }
            other => return other,
        }
    }
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if std::fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(());
    }
    retry(|| std::fs::write(path, bytes))
}

/// Remove the helper of a version from before the rename. Its journal moves
/// to `dir` first, so the new helper undoes what the old one left behind.
/// Like any update of the helper, this releases its kill switch.
fn remove_previous(manager: &ServiceManager, dir: &Path) {
    if let Ok(service) = manager.open_service(
        OLD_SERVICE,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        let _ = service.stop();
        wait_for(&service, ServiceState::Stopped);
        let _ = service.delete();
    }
    let Some(old) = dir.parent().map(|p| p.join(OLD_DIR)) else {
        return;
    };
    if !old.is_dir() {
        return;
    }
    // Same filter keys as this version's.
    let _ = super::wfp::remove_kill_switch();
    let (from, to) = (old.join("vpn-journal.json"), dir.join("vpn-journal.json"));
    if from.exists() && !to.exists() {
        let _ = retry(|| std::fs::rename(&from, &to));
    }
    for name in std::iter::once(OLD_EXE).chain(FILES) {
        let path = old.join(name);
        if path.exists() {
            let _ = retry(|| std::fs::remove_file(&path));
        }
    }
    let _ = std::fs::remove_dir(&old);
}

/// Install (or update) the helper for the user `sid`, and start it.
pub fn install(sid: &str) -> Result<(), String> {
    if !valid_sid(sid) {
        return Err("invalid user".into());
    }
    let (wintun, license) = WINTUN.ok_or(
        "This build of AegisBorne doesn't include the Wintun driver; download the release build to use the system VPN.",
    )?;
    let manager = manager()?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::DELETE;
    let existing = manager.open_service(SERVICE, access).ok();
    if let Some(service) = &existing {
        let _ = service.stop();
        wait_for(service, ServiceState::Stopped);
    }
    let dir = install_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    remove_previous(&manager, &dir);
    let exe = dir.join(EXE);
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    retry(|| std::fs::copy(&me, &exe).map(|_| ()))
        .map_err(|e| format!("Could not copy the helper: {e}"))?;
    write_if_changed(&dir.join("wintun.dll"), wintun)
        .map_err(|e| format!("Could not write Wintun: {e}"))?;
    let _ = write_if_changed(&dir.join("wintun-LICENSE.txt"), license);
    let info = ServiceInfo {
        name: OsString::from(SERVICE),
        display_name: OsString::from("AegisBorne VPN helper"),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["--vpn-service".into(), "--allow".into(), sid.into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = match existing {
        Some(service) => {
            service
                .change_config(&info)
                .map_err(|e| format!("Could not update the service: {e}"))?;
            service
        }
        None => manager
            .create_service(&info, access)
            .map_err(|e| format!("Could not create the service: {e}"))?,
    };
    let _ = service.set_description(
        "Runs the AegisBorne system VPN for the AegisBorne app. Remove it from the app's settings.",
    );
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    let _ = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    });
    service
        .start::<&str>(&[])
        .map_err(|e| format!("Could not start the service: {e}"))?;
    wait_for(&service, ServiceState::Running);
    Ok(())
}

/// Stop and remove the helper and its files.
pub fn uninstall() -> Result<(), String> {
    let manager = manager()?;
    if let Ok(service) = manager.open_service(
        SERVICE,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        let _ = service.stop();
        wait_for(&service, ServiceState::Stopped);
        service
            .delete()
            .map_err(|e| format!("Could not remove the service: {e}"))?;
    }
    let dir = install_dir();
    remove_previous(&manager, &dir);
    // A kill switch the helper left blocking goes with it.
    let _ = super::wfp::remove_kill_switch();
    for name in std::iter::once(EXE).chain(FILES) {
        let path = dir.join(name);
        if path.exists() {
            retry(|| std::fs::remove_file(&path))
                .map_err(|e| format!("Could not remove {}: {e}", path.display()))?;
        }
    }
    let _ = std::fs::remove_dir(&dir);
    Ok(())
}
