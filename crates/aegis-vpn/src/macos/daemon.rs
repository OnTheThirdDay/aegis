//! The launch daemon: runs as root, serves the control socket until
//! launchd stops it, then takes the VPN down.

use super::{MacOs, SOCKET};
use crate::helper::Helper;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};

/// Journal and other state, readable by root only.
const STATE_DIR: &str = "/Library/Application Support/AegisNet";

pub fn run(allow: &str) -> Result<(), String> {
    let allowed: u32 = allow.parse().map_err(|_| "invalid user".to_owned())?;
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(serve(allowed))
}

async fn serve(allowed: u32) -> Result<(), String> {
    let dir = Path::new(STATE_DIR);
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    let helper = Helper::new(MacOs, dir.join("vpn-journal.json"));
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET).map_err(|e| e.to_string())?;
    // Anyone may connect; only root and the installing user are served.
    let _ = std::fs::set_permissions(SOCKET, std::fs::Permissions::from_mode(0o666));
    let mut term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let uid = stream.peer_cred().map(|c| c.uid()).ok();
                if matches!(uid, Some(u) if u == 0 || u == allowed) {
                    tokio::spawn(Arc::clone(&helper).handle(stream));
                }
            }
            _ = term.recv() => break,
        }
    }
    helper.shutdown().await;
    let _ = std::fs::remove_file(SOCKET);
    Ok(())
}
