//! `aegisd` — AegisNet service.
//!
//! Privacy defaults (11 §3): no routine stdout/stderr logs. The only console
//! output is a short, secret-free fatal startup code; use
//! `aegisctl validate <config>` for configuration details and the
//! authenticated local API/IPC for status.
#![forbid(unsafe_code)]

use aegis_management::ManagementContext;
use aegis_node::{start, StartOptions};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

struct Args {
    config: PathBuf,
    store: Option<PathBuf>,
    check: bool,
}

fn parse_args() -> Result<Args, &'static str> {
    let mut args = Args {
        config: PathBuf::from("/etc/aegisnet/config.toml"),
        store: None,
        check: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" | "-c" => args.config = it.next().ok_or("--config needs a path")?.into(),
            "--store" => args.store = Some(it.next().ok_or("--store needs a path")?.into()),
            "--check" => args.check = true,
            "--version" => {
                println!("aegisd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--help" | "-h" => {
                println!("usage: aegisd [--config PATH] [--store PATH] [--check] [--version]");
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
            let resp =
                tokio::task::spawn_blocking(move || aegis_management::ipc::handle(&ctx, &req))
                    .await
                    .unwrap_or_else(|_| serde_json::json!({"ok": false, "error": "internal"}));
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
    let Ok(text) = std::fs::read_to_string(&args.config) else {
        return fatal("E_CONFIG_UNREADABLE");
    };
    let Ok(cfg) = aegis_config::parse_toml(&text) else {
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
        let node = match start(StartOptions {
            config: cfg.clone(),
            store_path: store_path.clone(),
            failpoints: None,
        })
        .await
        {
            Ok(n) => n,
            Err(e) => return fatal(e.code()),
        };
        let ctx = Arc::clone(&node.ctx);
        let gauges_ctx = Arc::clone(&ctx);
        let mut mgmt_ctx = None;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        if cfg.management.enabled {
            let Ok(bind) = cfg.management.bind.parse() else {
                return fatal("E_CONFIG_INVALID");
            };
            let listener = match tokio::net::TcpListener::bind(bind).await {
                Ok(l) => l,
                Err(_) => return fatal("E_BIND"),
            };
            let m = ManagementContext::new(
                Arc::clone(&ctx.coord),
                Arc::clone(&ctx.metrics),
                Arc::new(move || gauges_ctx.gauges()),
                Arc::clone(&ctx.diagnostics),
                ctx.ca.clone(),
                ctx.secrets_dir.clone(),
                bind,
                cfg.management.allowed_hosts.clone(),
            );
            let mut rx = stop_rx.clone();
            tokio::spawn(aegis_management::serve(
                Arc::clone(&m),
                listener,
                async move {
                    let _ = rx.wait_for(|s| *s).await;
                },
            ));
            mgmt_ctx = Some(m);
        }
        #[cfg(unix)]
        if let Some(m) = &mgmt_ctx {
            let path = cfg
                .management
                .ipc_socket
                .clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| default_ipc_path(&store_path));
            tokio::spawn(serve_ipc(Arc::clone(m), path));
        }
        let _ = &mgmt_ctx;
        shutdown_signal().await;
        let _ = stop_tx.send(true);
        node.shutdown(Duration::from_secs(u64::from(
            cfg.core.shutdown_grace_seconds,
        )))
        .await;
        ExitCode::SUCCESS
    })
}
