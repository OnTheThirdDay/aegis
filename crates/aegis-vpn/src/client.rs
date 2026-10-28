//! The app's side: is the helper installed, install or remove it (one
//! administrator prompt), and run the VPN while a [`Session`] is open.

use crate::proto::{self, Counters, Reply, Request};
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadHalf, WriteHalf};

/// The helper as the app sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperState {
    /// No system VPN on this platform.
    Unsupported,
    /// Not installed (or not running).
    NotInstalled,
    /// Installed, but too old for this app: install again to update.
    Outdated { version: String },
    /// Ready; `current` when it is this app's version; `blocked` when the
    /// kill switch blocks traffic because the VPN ended unexpectedly.
    Ready {
        version: String,
        current: bool,
        blocked: bool,
    },
}

trait Conn: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Conn for T {}

type Stream = Box<dyn Conn>;

async fn connect() -> std::io::Result<Stream> {
    #[cfg(windows)]
    {
        Ok(Box::new(crate::windows::pipe::connect().await?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(
            tokio::net::UnixStream::connect(crate::macos::SOCKET).await?,
        ))
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

struct Channel {
    r: BufReader<ReadHalf<Stream>>,
    w: WriteHalf<Stream>,
}

impl Channel {
    async fn open() -> Result<Channel, String> {
        let stream = connect().await.map_err(|_| {
            "The VPN helper isn't running. Install it again from Settings.".to_owned()
        })?;
        let (r, w) = tokio::io::split(stream);
        Ok(Channel {
            r: BufReader::new(r),
            w,
        })
    }

    async fn ask(&mut self, request: &Request) -> Result<Reply, String> {
        let lost = |_| "Lost the connection to the VPN helper.".to_owned();
        proto::write(&mut self.w, request).await.map_err(lost)?;
        let reply: Reply = proto::read(&mut self.r)
            .await
            .map_err(lost)?
            .ok_or("The VPN helper closed the connection.")?;
        match reply.error {
            Some(e) => Err(e),
            None => Ok(reply),
        }
    }
}

pub async fn state() -> HelperState {
    if !crate::supported() {
        return HelperState::Unsupported;
    }
    let Ok(mut channel) = Channel::open().await else {
        return HelperState::NotInstalled;
    };
    match channel.ask(&Request::Hello).await {
        Ok(Reply {
            version: Some(version),
            protocol: Some(proto::PROTOCOL),
            blocked,
            ..
        }) => {
            let current = version == env!("CARGO_PKG_VERSION");
            HelperState::Ready {
                version,
                current,
                blocked: blocked.unwrap_or(false),
            }
        }
        Ok(reply) => HelperState::Outdated {
            version: reply.version.unwrap_or_default(),
        },
        Err(_) => HelperState::NotInstalled,
    }
}

/// The VPN, up while this lives (or until [`Session::stop`]); the helper
/// also takes it down if the app exits or crashes.
pub struct Session {
    channel: Channel,
}

impl Session {
    /// Capture this computer's traffic into the local SOCKS proxy at
    /// `127.0.0.1:socks_port`, keeping `bypass` (the server's host names or
    /// addresses) outside. With `kill_switch`, nothing else gets out, and
    /// that stays so if the VPN ends without [`Session::stop`].
    pub async fn start(
        socks_port: u16,
        bypass: Vec<String>,
        kill_switch: bool,
    ) -> Result<Session, String> {
        let mut channel = Channel::open().await?;
        channel
            .ask(&Request::Start {
                socks_port,
                bypass,
                kill_switch,
            })
            .await?;
        Ok(Session { channel })
    }

    /// Whether the VPN still runs, and its counters.
    pub async fn status(&mut self) -> Result<(bool, Counters), String> {
        let reply = self.channel.ask(&Request::Status).await?;
        Ok((
            reply.running.unwrap_or(false),
            reply.counters.unwrap_or_default(),
        ))
    }

    pub async fn stop(mut self) {
        let _ = self.channel.ask(&Request::Stop).await;
    }
}

/// Release a kill switch left blocking after the VPN ended unexpectedly.
pub async fn release() -> Result<(), String> {
    Channel::open()
        .await?
        .ask(&Request::Release)
        .await
        .map(|_| ())
}

/// Install or update the helper for the current user. Asks for
/// administrator rights; blocks until done.
pub async fn install() -> Result<(), String> {
    let user = current_user()?;
    elevated(vec!["--vpn-install".into(), "--allow".into(), user]).await
}

/// Remove the helper. Asks for administrator rights.
pub async fn uninstall() -> Result<(), String> {
    elevated(vec!["--vpn-uninstall".into()]).await
}

fn current_user() -> Result<String, String> {
    #[cfg(windows)]
    {
        crate::windows::current_sid()
    }
    #[cfg(target_os = "macos")]
    {
        crate::macos::current_uid()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Err("The system VPN isn't available on this platform.".into())
    }
}

/// Run this executable with `args` as administrator, and the outcome.
async fn elevated(args: Vec<String>) -> Result<(), String> {
    let report = std::env::temp_dir().join(format!("aegisnet-vpn-{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&report);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let report_arg = report.to_string_lossy().into_owned();
    let result = tokio::task::spawn_blocking(move || run_elevated(&exe, &args, &report_arg))
        .await
        .map_err(|e| e.to_string())?;
    let message = std::fs::read_to_string(&report).unwrap_or_default();
    let _ = std::fs::remove_file(&report);
    match result {
        Elevated::Cancelled => Err("Cancelled.".into()),
        // The installer's own explanation, when it gave one.
        _ if !message.is_empty() => Err(message),
        Elevated::Done => Ok(()),
        Elevated::Failed(e) => Err(e),
    }
}

#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
enum Elevated {
    Done,
    Cancelled,
    Failed(String),
}

#[cfg(windows)]
fn run_elevated(exe: &std::path::Path, args: &[String], report: &str) -> Elevated {
    // Start-Process joins its arguments with spaces: quote each one (none
    // contains a double quote: SIDs, flags, a path).
    let mut list: Vec<String> = args.iter().map(|a| format!("\"{a}\"")).collect();
    list.push("--report".into());
    list.push(format!("\"{report}\""));
    let single = |s: &str| format!("'{}'", s.replace('\'', "''"));
    let script = format!(
        "try {{ $p = Start-Process -FilePath {} -ArgumentList {} -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop; exit $p.ExitCode }} catch {{ exit 1223 }}",
        single(&exe.to_string_lossy()),
        single(&list.join(" ")),
    );
    match crate::windows::hidden("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
    {
        Ok(out) => match out.status.code() {
            Some(0) => Elevated::Done,
            Some(1223) => Elevated::Cancelled,
            _ => Elevated::Failed("The administrator step failed.".into()),
        },
        Err(e) => Elevated::Failed(e.to_string()),
    }
}

#[cfg(target_os = "macos")]
fn run_elevated(exe: &std::path::Path, args: &[String], report: &str) -> Elevated {
    let sh = |s: &str| format!("'{}'", s.replace('\'', r"'\''"));
    let mut words = vec![sh(&exe.to_string_lossy())];
    words.extend(args.iter().map(|a| sh(a)));
    words.push("--report".into());
    words.push(sh(report));
    let command = words.join(" ");
    let script = format!(
        "do shell script \"{}\" with administrator privileges",
        command.replace('\\', "\\\\").replace('"', "\\\"")
    );
    match std::process::Command::new("osascript")
        .args(["-e", &script])
        .output()
    {
        Ok(out) if out.status.success() => Elevated::Done,
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("-128") {
                Elevated::Cancelled
            } else {
                Elevated::Failed(err.trim().to_owned())
            }
        }
        Err(e) => Elevated::Failed(e.to_string()),
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn run_elevated(_exe: &std::path::Path, _args: &[String], _report: &str) -> Elevated {
    Elevated::Failed("The system VPN isn't available on this platform.".into())
}
