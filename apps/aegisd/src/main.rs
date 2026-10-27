//! `aegisd` — AegisNet service.
//!
//! Privacy defaults (11 §3): no routine stdout/stderr logs. The only console
//! output is a short, secret-free fatal startup code (plus one secret-free
//! line when an appliance data directory is first initialized); use
//! `aegisctl validate <config>` for configuration details and the
//! authenticated local API/IPC for status.
//!
//! Appliance mode: `aegisd --data-dir DIR` initializes an empty directory
//! into a complete gateway with an HTTPS web console (ADR-0007).
#![forbid(unsafe_code)]

#[cfg(unix)]
use aegis_management::ManagementContext;
use aegisd::{appliance, parse_config};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::Arc;

struct Args {
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    store: Option<PathBuf>,
    check: bool,
}

fn parse_args() -> Result<Args, &'static str> {
    let mut args = Args {
        config: None,
        data_dir: std::env::var_os("AEGIS_DATA_DIR").map(PathBuf::from),
        store: None,
        check: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" | "-c" => {
                args.config = Some(it.next().ok_or("--config needs a path")?.into())
            }
            "--data-dir" => {
                args.data_dir = Some(it.next().ok_or("--data-dir needs a path")?.into())
            }
            "--store" => args.store = Some(it.next().ok_or("--store needs a path")?.into()),
            "--check" => args.check = true,
            "--version" => {
                println!("aegisd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("usage: aegisd [--data-dir DIR | --config PATH] [--store PATH] [--check] [--version]");
                std::process::exit(0);
            }
            _ => return Err("unknown argument"),
        }
    }
    Ok(args)
}

fn fatal(code: &str) -> ExitCode {
    eprintln!("aegisd: {code}");
    ExitCode::FAILURE
}

#[cfg(unix)]
async fn serve_ipc(ctx: Arc<ManagementContext>, path: PathBuf) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    // We created the socket, so its owner is our effective uid.
    let owner_uid = std::fs::metadata(&path)?.uid();
    loop {
        let (mut stream, _) = listener.accept().await?;
        // OS-local peer authentication: only our own uid may issue
        // privileged commands.
        let authorized = stream
            .peer_cred()
            .map(|c| c.uid() == owner_uid)
            .unwrap_or(false);
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
            if !authorized {
                let _ = stream
                    .write_all(b"{\"ok\":false,\"error\":\"unauthorized peer\"}\n")
                    .await;
                return;
            }
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let Ok(n) = stream.read(&mut chunk).await else {
                    return;
                };
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > aegis_management::ipc::MAX_REQUEST {
                    return;
                }
                if buf.contains(&b'\n') {
                    break;
                }
            }
            let req: serde_json::Value = match serde_json::from_slice(buf.trim_ascii()) {
                Ok(v) => v,
                Err(_) => serde_json::json!({}),
            };
            let resp = aegis_management::ipc::dispatch(ctx, req).await;
            let mut out = serde_json::to_vec(&resp).unwrap_or_default();
            out.push(b'\n');
            let _ = stream.write_all(&out).await;
        });
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
fn default_ipc_path(store: &Path) -> PathBuf {
    store
        .parent()
        .map(|p| p.join("aegisd.sock"))
        .unwrap_or_else(|| PathBuf::from("aegisd.sock"))
}

fn main() -> ExitCode {
    let Ok(args) = parse_args() else {
        return fatal("E_USAGE");
    };
    let appliance_dir = if args.config.is_none() {
        args.data_dir.clone()
    } else {
        None
    };
    let config_path = match (&args.config, &appliance_dir) {
        (Some(c), _) => c.clone(),
        (None, Some(dir)) => {
            let path = appliance::config_path(dir);
            if !path.exists() {
                if args.check {
                    return fatal("E_CONFIG_UNREADABLE");
                }
                let opts = appliance::InitOptions::from_env();
                if let Err(code) = appliance::init(dir, &opts) {
                    return fatal(&code);
                }
                // Secret-free notice; the password stays in a 0600 file.
                eprintln!(
                    "aegisd: initialized {}; console https://<this-host>:{}; read the one-time admin password with `aegisctl initial-password`",
                    dir.display(),
                    opts.console_port.unwrap_or(appliance::CONSOLE_PORT)
                );
            }
            path
        }
        (None, None) => PathBuf::from("/etc/aegisnet/config.toml"),
    };
    let Ok(text) = std::fs::read_to_string(&config_path) else {
        return fatal("E_CONFIG_UNREADABLE");
    };
    let Ok(cfg) = parse_config(&text) else {
        return fatal("E_CONFIG_INVALID");
    };
    if args.check {
        return match aegis_node::validate_offline(&cfg) {
            Ok(_) => ExitCode::SUCCESS,
            Err(_) => fatal("E_CONFIG_INVALID"),
        };
    }
    let store_path = args
        .store
        .clone()
        .unwrap_or_else(|| PathBuf::from(&cfg.management.config_store));
    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        return fatal("E_RUNTIME");
    };
    rt.block_on(async move {
        let running = match aegisd::launch(cfg, store_path.clone(), appliance_dir).await {
            Ok(r) => r,
            Err(code) => return fatal(code),
        };
        #[cfg(unix)]
        if let Some(m) = &running.mgmt {
            let path = running
                .node
                .ctx
                .startup
                .management
                .ipc_socket
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| default_ipc_path(&store_path));
            tokio::spawn(serve_ipc(Arc::clone(m), path));
        }
        shutdown_signal().await;
        running.shutdown().await;
        ExitCode::SUCCESS
    })
}
