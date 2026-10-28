//! The service: started by the service control manager as LocalSystem,
//! it serves the control pipe until stopped, then takes the VPN down.

use super::{install_dir, pipe, Windows, SERVICE};
use crate::helper::Helper;
use std::ffi::OsString;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

/// The user allowed to control the helper (from the service's arguments).
static ALLOWED: OnceLock<String> = OnceLock::new();

#[allow(unsafe_code)]
mod entry {
    // The generated entry point converts the arguments the service control
    // manager passes.
    windows_service::define_windows_service!(ffi_service_main, service_main);

    fn service_main(arguments: Vec<std::ffi::OsString>) {
        super::service_main(arguments);
    }

    pub(super) fn dispatch() -> windows_service::Result<()> {
        windows_service::service_dispatcher::start(super::SERVICE, ffi_service_main)
    }
}

/// Hand the process to the service control manager (returns when the
/// service stopped).
pub fn run(allow: &str) -> Result<(), String> {
    let _ = ALLOWED.set(allow.to_owned());
    entry::dispatch().map_err(|e| e.to_string())
}

fn status(state: ServiceState, code: u32) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let (stop_tx, stop) = watch::channel(false);
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(handle) = service_control_handler::register(SERVICE, handler) else {
        return;
    };
    let _ = handle.set_service_status(status(ServiceState::Running, 0));
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|rt| rt.block_on(serve(stop)));
    let _ = handle.set_service_status(status(
        ServiceState::Stopped,
        if result.is_ok() { 0 } else { 1 },
    ));
}

async fn serve(mut stop: watch::Receiver<bool>) -> Result<(), String> {
    let allowed = ALLOWED.get().map(String::as_str).unwrap_or_default();
    let descriptor = pipe::Descriptor::new(allowed).map_err(|e| e.to_string())?;
    let dir = install_dir();
    let helper = Helper::new(
        Windows {
            wintun: dir.join("wintun.dll"),
        },
        dir.join("vpn-journal.json"),
    );
    let mut server = pipe::create(&descriptor, true).map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            connected = server.connect() => {
                let next = pipe::create(&descriptor, false).map_err(|e| e.to_string())?;
                let conn = std::mem::replace(&mut server, next);
                if connected.is_ok() {
                    tokio::spawn(Arc::clone(&helper).handle(conn));
                }
            }
            _ = stop.wait_for(|s| *s) => break,
        }
    }
    helper.shutdown().await;
    Ok(())
}
