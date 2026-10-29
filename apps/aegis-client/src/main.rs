//! AegisBorne portable client: paste an invitation, connect, browse.
//!
//! * Several servers can be joined; one is connected at a time.
//! * No installation and no administrator rights: data lives next to the
//!   executable (or in the user's app-data folder).
//! * The device key is generated here and never leaves this device.
//! * Local proxies: SOCKS5 and HTTP on 127.0.0.1; optionally set as the
//!   Windows system proxy while connected (restored afterwards).
//! * Optionally a system VPN for every app (Windows, macOS): a helper
//!   installed once with administrator rights (`aegis-vpn`). The same
//!   executable is that helper when started with its arguments.
//! * No logs are written; errors are shown in the window only. For support,
//!   Troubleshooting records connection events on demand: in memory, at
//!   most an hour, then sent to the server or saved to a file.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

mod engine;
mod selfupdate;
mod settings;
mod sysproxy;

use eframe::egui::{self, Color32, RichText};
use engine::{Command, Engine, Status, UpdateState};
use settings::Settings;
use std::path::PathBuf;
use std::time::Duration;

const GREEN: Color32 = Color32::from_rgb(46, 160, 67);
const AMBER: Color32 = Color32::from_rgb(210, 153, 34);
const RED: Color32 = Color32::from_rgb(218, 54, 51);
const BLUE: Color32 = Color32::from_rgb(56, 125, 230);

struct App {
    engine: Engine,
    data_dir: PathBuf,
    invite: String,
    settings: Settings,
    edited: Settings,
    confirm_forget: bool,
    paste_error: Option<String>,
    /// Open "Add a server" (an invitation arrived while already joined).
    open_add: bool,
    /// To clear the invitation once a join succeeds.
    was_joining: bool,
    diag_minutes: u64,
}

fn fmt_bytes(n: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut x = n as f64;
    let mut i = 0;
    while x >= 1024.0 && i < units.len() - 1 {
        x /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{x:.1} {}", units[i])
    }
}

fn fmt_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else if s < 86_400 {
        format!("{}h {}m", s / 3600, (s % 3600) / 60)
    } else {
        format!("{}d {}h", s / 86_400, (s % 86_400) / 3600)
    }
}

fn server_of(url: &str) -> String {
    url.strip_prefix("wss://")
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .to_owned()
}

fn expires_in(at: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    fmt_duration(Duration::from_secs(u64::try_from(at - now).unwrap_or(0)))
}

fn days_left(exp: i64) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (exp - now) / 86_400
}

impl App {
    fn new(
        cc: &eframe::CreationContext<'_>,
        data_dir: PathBuf,
        initial_invite: Option<String>,
    ) -> Self {
        let settings = Settings::load(&data_dir);
        let ctx = cc.egui_ctx.clone();
        let engine = Engine::start(
            data_dir.clone(),
            settings.clone(),
            Box::new(move || ctx.request_repaint()),
        )
        .unwrap_or_else(|e| {
            // Without a runtime nothing works; show the reason and exit.
            eprintln!("aegis-client: {e}");
            std::process::exit(1);
        });
        let mut app = App {
            engine,
            data_dir,
            invite: String::new(),
            edited: settings.clone(),
            settings,
            confirm_forget: false,
            paste_error: None,
            open_add: false,
            was_joining: false,
            diag_minutes: 15,
        };
        if let Some(code) = initial_invite {
            app.invite = code;
            app.open_add = true;
        }
        app
    }

    fn status_line(&self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        let (text, color) = match s.status {
            Status::NotEnrolled if s.joining => ("Joining...".to_owned(), AMBER),
            Status::NotEnrolled => ("Not set up".to_owned(), Color32::GRAY),
            Status::Disconnected => ("Disconnected".to_owned(), Color32::GRAY),
            Status::Connecting => ("Connecting...".to_owned(), AMBER),
            Status::Connected => (
                match s.connected_since {
                    Some(t) => format!("Connected · {}", fmt_duration(t.elapsed())),
                    None => "Connected".to_owned(),
                },
                GREEN,
            ),
        };
        ui.horizontal(|ui| {
            // Painted, not a glyph: the bundled fonts have no bullet circle.
            let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 6.0, color);
            ui.label(RichText::new(text).size(18.0).strong());
        });
    }

    fn join_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        if s.servers.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("Add a server").size(16.0).strong());
        }
        ui.label("Paste the invitation code you received (it starts with aegis1:), or drop a .aegis file on this window.");
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .id_salt("invite")
            .max_height(96.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.invite)
                        .desired_rows(4)
                        .desired_width(f32::INFINITY)
                        .hint_text("aegis1:...")
                        .font(egui::TextStyle::Monospace),
                );
            });
        ui.horizontal(|ui| {
            if ui
                .button("Paste")
                .on_hover_text("Paste the invitation from the clipboard")
                .clicked()
            {
                match arboard::Clipboard::new().and_then(|mut c| c.get_text()) {
                    Ok(text) => {
                        self.invite = text.trim().to_owned();
                        self.paste_error = None;
                    }
                    Err(_) => {
                        self.paste_error = Some(
                            "The clipboard has no text. Copy the invitation code first.".into(),
                        )
                    }
                }
            }
            if !self.invite.is_empty() && ui.button("Clear").clicked() {
                self.invite.clear();
                self.paste_error = None;
            }
        });
        if let Some(e) = &self.paste_error {
            ui.label(RichText::new(e).color(RED));
        }
        ui.add_space(6.0);
        let parsed = if self.invite.trim().is_empty() {
            None
        } else {
            Some(aegis_join::parse_invite(&self.invite))
        };
        match &parsed {
            Some(Ok(inv)) => {
                ui.label(
                    RichText::new(format!(
                        "Valid invitation for \"{}\" on {} (expires in {})",
                        inv.name,
                        server_of(&inv.url),
                        expires_in(inv.expires_at)
                    ))
                    .color(GREEN),
                );
            }
            Some(Err(e)) => {
                ui.label(RichText::new(e.to_string()).color(RED));
            }
            None => {}
        }
        let busy = s.joining;
        let ready = matches!(parsed, Some(Ok(_))) && !busy;
        if ui
            .add_enabled(
                ready,
                egui::Button::new(
                    RichText::new(if busy {
                        "Joining..."
                    } else {
                        "Join and connect"
                    })
                    .size(16.0),
                )
                .min_size(egui::vec2(180.0, 34.0)),
            )
            .clicked()
        {
            self.engine
                .send(Command::Enroll(self.invite.trim().to_owned()));
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Get an invitation from your server's web console: Devices > Invite a device. The code can be used once; this device creates its own key.").small().weak());
    }

    fn connected_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        egui::Grid::new("device")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Server").weak());
                if s.servers.len() > 1 {
                    let label =
                        |e: &engine::ServerEntry| format!("{} ({})", e.server, e.device_name);
                    let current = s
                        .servers
                        .iter()
                        .find(|e| Some(&e.id) == s.selected.as_ref())
                        .map(label)
                        .unwrap_or_default();
                    egui::ComboBox::from_id_salt("server")
                        .selected_text(current)
                        .show_ui(ui, |ui| {
                            for e in &s.servers {
                                let chosen = Some(&e.id) == s.selected.as_ref();
                                if ui.selectable_label(chosen, label(e)).clicked() && !chosen {
                                    self.confirm_forget = false;
                                    self.engine.send(Command::Select(e.id.clone()));
                                }
                            }
                        })
                        .response
                        .on_hover_text("Connect to another joined server (one at a time)");
                } else {
                    ui.label(s.server.as_deref().unwrap_or("—"));
                }
                ui.end_row();
                ui.label(RichText::new("This device").weak());
                ui.label(s.device_name.as_deref().unwrap_or("—"));
                ui.end_row();
                if let Some(exp) = s.certificate_expires_at {
                    ui.label(RichText::new("Certificate").weak());
                    ui.label(format!(
                        "{} days left (renews automatically)",
                        days_left(exp).max(0)
                    ));
                    ui.end_row();
                }
            });
        ui.add_space(12.0);
        let running = matches!(s.status, Status::Connected | Status::Connecting);
        let (label, color) = if running {
            ("Disconnect", RED)
        } else {
            ("Connect", BLUE)
        };
        let button = egui::Button::new(RichText::new(label).size(18.0).color(Color32::WHITE))
            .fill(color)
            .min_size(egui::vec2(ui.available_width(), 44.0));
        if ui.add(button).clicked() {
            self.engine.send(if running {
                Command::Disconnect
            } else {
                Command::Connect
            });
        }
        if running {
            ui.add_space(12.0);
            ui.group(|ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new("Use these proxy settings in your apps").strong());
                for (name, addr) in [("SOCKS5", s.socks), ("HTTP", s.http)] {
                    if let Some(a) = addr {
                        ui.horizontal(|ui| {
                            ui.label(format!("{name}:"));
                            ui.monospace(a.to_string());
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(a.to_string());
                            }
                        });
                    }
                }
                if s.vpn_active {
                    ui.label(RichText::new("System VPN is on: every app on this computer goes through AegisBorne.").color(GREEN));
                    let c = &s.vpn_counters;
                    ui.label(RichText::new(format!(
                        "{} connections open ({} in total) · {} UDP flows · {} DNS lookups",
                        c.tcp_open, c.tcp_total, c.udp_open, c.dns_queries
                    )).small().weak());
                } else if s.system_proxy_active {
                    ui.label(RichText::new("Windows system proxy is set: Edge, Chrome and most apps use it.").color(GREEN));
                } else {
                    ui.label(RichText::new("Firefox: Settings > Network Settings > Manual proxy > SOCKS Host 127.0.0.1, port above, SOCKS v5, and tick \"Proxy DNS when using SOCKS v5\".").small().weak());
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Sent {}", fmt_bytes(s.bytes_up))).weak());
                    ui.label(RichText::new(format!("Received {}", fmt_bytes(s.bytes_down))).weak());
                    if let Some(t) = s.transport {
                        let via = if t == "quic" { "via QUIC (UDP)" } else { "via WebSocket (TCP)" };
                        ui.label(RichText::new(via).weak());
                    }
                });
            });
        }
        ui.add_space(8.0);
        let open = std::mem::take(&mut self.open_add).then_some(true);
        egui::CollapsingHeader::new("Add a server")
            .open(open)
            .show(ui, |ui| self.join_view(ui, s));
    }

    fn diagnostics_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot, enrolled: bool) {
        let st = self.engine.diag.status();
        ui.add_space(8.0);
        egui::CollapsingHeader::new("Troubleshooting")
            .default_open(st.state != "off")
            .show(ui, |ui| {
                match st.state {
                    "recording" => {
                        ui.horizontal(|ui| {
                            let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
                            ui.painter().circle_filled(rect.center(), 5.0, RED);
                            ui.label(RichText::new(format!(
                                "Recording · {} left · {} events",
                                fmt_duration(Duration::from_secs(st.remaining_seconds.unwrap_or(0))),
                                st.events
                            )).strong());
                        });
                        ui.label(RichText::new("Reproduce the problem now (open the sites or apps that fail). Recording stops by itself and the report is then sent to the server.").small().weak());
                        ui.horizontal(|ui| {
                            if enrolled && ui.button("Stop and send").clicked() {
                                self.engine.send(Command::DiagStop(true));
                            }
                            if ui.button("Stop").clicked() {
                                self.engine.send(Command::DiagStop(false));
                            }
                        });
                    }
                    "stopped" => {
                        ui.label(format!(
                            "Recording finished · {} events (kept in memory for up to an hour)",
                            st.events
                        ));
                        ui.horizontal(|ui| {
                            if enrolled && ui.add_enabled(!s.diag_sending, egui::Button::new(if s.diag_sending { "Sending..." } else { "Send to server" })).clicked() {
                                self.engine.send(Command::DiagSend);
                            }
                            if ui.button("Save to file").clicked() {
                                self.engine.send(Command::DiagSave);
                            }
                            if ui.button("Discard").clicked() {
                                self.engine.send(Command::DiagDiscard);
                            }
                        });
                    }
                    _ => {
                        ui.label("Something not working? Record what happens while you reproduce it, so your administrator can see what went wrong.");
                        ui.horizontal(|ui| {
                            ui.label("Record for");
                            egui::ComboBox::from_id_salt("diag_minutes")
                                .selected_text(format!("{} minutes", self.diag_minutes))
                                .show_ui(ui, |ui| {
                                    for m in [5u64, 15, 30, 60] {
                                        ui.selectable_value(&mut self.diag_minutes, m, format!("{m} minutes"));
                                    }
                                });
                            if ui.button("Start recording").clicked() {
                                self.engine.send(Command::DiagStart(self.diag_minutes));
                            }
                        });
                        ui.label(RichText::new("Records connection events and error messages only, never the sites you visit or your traffic. Kept in memory (at most 5 MB), not written to disk, and switched off automatically. Ask your administrator to start diagnostics on the server too.").small().weak());
                    }
                }
                if let Some((ok, msg)) = &s.diag_message {
                    ui.label(RichText::new(msg).color(if *ok { GREEN } else { RED }));
                }
            });
    }

    fn settings_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        ui.add_space(8.0);
        egui::CollapsingHeader::new("Settings")
            .default_open(false)
            .show(ui, |ui| {
                egui::Grid::new("settings").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                    ui.label("SOCKS5 port");
                    ui.add(egui::DragValue::new(&mut self.edited.socks_port).range(1024..=65535));
                    ui.end_row();
                    ui.label("HTTP proxy port");
                    ui.add(egui::DragValue::new(&mut self.edited.http_port).range(1024..=65535));
                    ui.end_row();
                });
                if sysproxy::supported() {
                    ui.checkbox(&mut self.edited.system_proxy, "Set as the Windows system proxy while connected");
                }
                if aegis_vpn::supported() {
                    ui.checkbox(&mut self.edited.system_vpn, "System VPN: send every app's traffic through AegisBorne while connected");
                    ui.add_enabled(
                        self.edited.system_vpn,
                        egui::Checkbox::new(&mut self.edited.kill_switch, "Kill switch: block internet access if the system VPN stops unexpectedly"),
                    )
                    .on_hover_text("Disconnecting or quitting turns it off. If the app or the VPN stops unexpectedly, only your local network and your server stay reachable until you connect again or unblock. Restarting the computer always clears it.");
                }
                ui.checkbox(&mut self.edited.auto_connect, "Connect automatically when the app starts");
                let changed = self.edited != self.settings;
                ui.horizontal(|ui| {
                    if ui.add_enabled(changed, egui::Button::new("Save")).clicked() {
                        if self.edited.socks_port == self.edited.http_port {
                            self.edited.http_port = self.edited.socks_port.saturating_add(1);
                        }
                        self.settings = self.edited.clone();
                        self.engine.send(Command::SaveSettings(self.edited.clone()));
                    }
                    if ui.add_enabled(changed, egui::Button::new("Undo")).clicked() {
                        self.edited = self.settings.clone();
                    }
                });
                if aegis_vpn::supported() {
                    self.vpn_helper_view(ui, s);
                }
                if let (Some(id), Some(server)) = (&s.selected, &s.server) {
                    ui.separator();
                    if self.confirm_forget {
                        ui.label(RichText::new(format!("Remove {server} from this device? You will need a new invitation to join it again.")).color(RED));
                        ui.horizontal(|ui| {
                            if ui.button("Remove").clicked() {
                                self.engine.send(Command::Forget(id.clone()));
                                self.confirm_forget = false;
                            }
                            if ui.button("Cancel").clicked() {
                                self.confirm_forget = false;
                            }
                        });
                    } else if ui.button("Remove this server...").clicked() {
                        self.confirm_forget = true;
                    }
                }
                ui.separator();
                ui.label(RichText::new(format!("Data folder: {}", self.data_dir.display())).small().weak());
                ui.label(RichText::new(format!("AegisBorne client {}", env!("CARGO_PKG_VERSION"))).small().weak());
            });
    }
}

impl App {
    fn vpn_helper_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        use aegis_vpn::client::HelperState;
        ui.separator();
        ui.label(RichText::new("System VPN helper").strong());
        if s.vpn_busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for administrator approval...");
            });
            return;
        }
        let (text, install, remove) = match &s.vpn_helper {
            HelperState::Unsupported => return,
            HelperState::NotInstalled => (
                "The system VPN needs a small helper, installed once. Installing asks for administrator rights.".to_owned(),
                Some("Install VPN helper"),
                false,
            ),
            HelperState::Outdated { version } => (
                format!("The installed helper ({version}) is too old for this app; update it to use the system VPN."),
                Some("Update VPN helper"),
                true,
            ),
            HelperState::Ready {
                version,
                current: false,
                ..
            } => (
                format!("Installed (version {version}); this app can update it."),
                Some("Update VPN helper"),
                true,
            ),
            HelperState::Ready { .. } => ("Installed.".to_owned(), None, true),
        };
        ui.label(RichText::new(text).small());
        ui.horizontal(|ui| {
            if let Some(label) = install {
                if ui.button(label).clicked() {
                    self.engine.send(Command::InstallVpnHelper);
                }
            }
            if remove && ui.button("Remove VPN helper").clicked() {
                self.engine.send(Command::RemoveVpnHelper);
            }
        });
        if let Some((ok, msg)) = &s.vpn_message {
            ui.label(RichText::new(msg).color(if *ok { GREEN } else { RED }));
        }
    }
}

impl App {
    /// A newer version from the server: offered, never installed unasked.
    fn update_view(&mut self, ui: &mut egui::Ui, s: &engine::Snapshot) {
        let current = env!("CARGO_PKG_VERSION");
        match &s.update {
            UpdateState::None => {}
            UpdateState::Available(version) => {
                ui.group(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "AegisBorne {version} is available (you have {current})."
                        ))
                        .color(BLUE),
                    );
                    if ui.button("Update").clicked() {
                        self.engine.send(Command::InstallUpdate);
                    }
                });
            }
            UpdateState::Downloading {
                version,
                done,
                total,
            } => {
                ui.group(|ui| {
                    ui.label(format!("Downloading AegisBorne {version}…"));
                    let part = if *total > 0 {
                        *done as f32 / *total as f32
                    } else {
                        0.0
                    };
                    ui.add(egui::ProgressBar::new(part).show_percentage());
                });
            }
            UpdateState::Ready { version, start } => {
                ui.group(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "AegisBorne {version} is installed. Restart the app to use it."
                        ))
                        .color(GREEN),
                    );
                    if ui.button("Restart now").clicked() {
                        // Disconnects and restores system settings first.
                        self.engine.shutdown();
                        match selfupdate::relaunch(start) {
                            Ok(()) => std::process::exit(0),
                            Err(e) => {
                                self.paste_error = Some(format!(
                                    "Could not restart: {e}. Start the app again yourself."
                                ))
                            }
                        }
                    }
                });
            }
            UpdateState::Failed { version, message } => {
                ui.group(|ui| {
                    ui.label(
                        RichText::new(format!("Updating to {version} failed: {message}"))
                            .color(RED),
                    );
                    if ui.button("Try again").clicked() {
                        self.engine.send(Command::InstallUpdate);
                    }
                });
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let s = self.engine.snapshot();
        // Accept dropped .aegis invitation files.
        let dropped: Vec<_> = ui.ctx().input(|i| i.raw.dropped_files.clone());
        for f in dropped {
            if let Ok(text) = std::fs::read_to_string(f.path()) {
                self.invite = text.trim().to_owned();
                self.open_add = true;
            }
        }
        if self.was_joining && !s.joining && s.error.is_none() {
            self.invite.clear();
            self.open_add = false;
        }
        self.was_joining = s.joining;
        if ui.ctx().input(|i| i.viewport().close_requested()) {
            self.engine.shutdown();
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("AegisBorne").size(22.0).strong());
            ui.separator();
            self.status_line(ui, &s);
            if let Some(e) = &s.error {
                ui.label(RichText::new(e).color(RED));
            } else if let Some(i) = &s.info {
                ui.label(RichText::new(i).color(GREEN));
            }
            self.update_view(ui, &s);
            let blocked = matches!(
                s.vpn_helper,
                aegis_vpn::client::HelperState::Ready { blocked: true, .. }
            );
            if blocked && !s.vpn_active {
                ui.group(|ui| {
                    ui.label(RichText::new("The system VPN stopped unexpectedly, so the kill switch is blocking this computer's internet access. Your local network and your server are still reachable.").color(RED));
                    ui.horizontal(|ui| {
                        if s.status == Status::Disconnected && ui.button("Connect").clicked() {
                            self.engine.send(Command::Connect);
                        }
                        if ui.button("Unblock internet").clicked() {
                            self.engine.send(Command::Unblock);
                        }
                    });
                });
            }
            ui.add_space(6.0);
            egui::ScrollArea::vertical().show(ui, |ui| {
                let enrolled = !s.servers.is_empty();
                if enrolled {
                    self.connected_view(ui, &s);
                } else {
                    self.join_view(ui, &s);
                }
                self.diagnostics_view(ui, &s, enrolled);
                self.settings_view(ui, &s);
            });
        });
        // Keep counters and the uptime fresh while connected.
        if matches!(s.status, Status::Connected | Status::Connecting)
            || s.joining
            || s.vpn_busy
            || matches!(s.update, UpdateState::Downloading { .. })
            || self.engine.diag.is_recording()
        {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
    }
}

fn main() -> eframe::Result {
    // Started as the system VPN's helper or its installer.
    let args: Vec<String> = std::env::args().collect();
    if let Some(code) = aegis_vpn::dispatch(&args) {
        std::process::exit(code);
    }
    selfupdate::cleanup();
    let data_dir = match settings::data_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("aegis-client: no writable data folder: {e}");
            std::process::exit(1);
        }
    };
    // `aegis-client path/to/device.aegis` (file association / drag on icon).
    let initial_invite = std::env::args()
        .nth(1)
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| t.trim().to_owned())
        .filter(|t| t.starts_with("aegis1:"));
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("AegisBorne")
            .with_inner_size([420.0, 560.0])
            .with_min_inner_size([360.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "AegisBorne",
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, data_dir, initial_invite)))),
    )
}
