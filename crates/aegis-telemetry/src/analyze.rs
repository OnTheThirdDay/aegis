//! Explain a problem from diagnostic reports: correlate what a device saw
//! with what its gateway saw over the same time and turn it into findings
//! with a suggested fix. Rule based and deterministic; every finding names
//! the evidence it rests on.

use crate::diagnostic::{Record, Severity};
use crate::report::{Report, Role};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    /// Stable identifier, for tests and documentation.
    pub id: &'static str,
    pub title: String,
    pub detail: String,
    /// What to do about it.
    pub action: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub gateway_recorded: bool,
    pub devices: Vec<String>,
}

/// Records and counts of one side, with helpers.
struct Side<'a> {
    name: &'a str,
    records: Vec<&'a Record>,
    counts: &'a BTreeMap<String, u64>,
    window: (u64, u64),
}

impl<'a> Side<'a> {
    fn new(r: &'a Report) -> Self {
        Side {
            name: &r.name,
            records: r.recording.records.iter().collect(),
            counts: &r.recording.counts,
            window: (r.recording.started_unix_ms, r.recording.ended_unix_ms),
        }
    }

    fn count(&self, code: &str) -> u64 {
        self.counts.get(code).copied().unwrap_or(0)
    }

    fn matching(&self, code: &str, key: &str, value: &str) -> Vec<&'a Record> {
        self.records
            .iter()
            .copied()
            .filter(|r| r.code == code && r.attr(key) == Some(value))
            .collect()
    }

    fn total(records: &[&Record]) -> u64 {
        records.iter().map(|r| r.repeat).sum()
    }

    /// The most frequent `error` attribute among `records`.
    fn top_error(records: &[&Record]) -> Option<String> {
        let mut by: BTreeMap<&str, u64> = BTreeMap::new();
        for r in records {
            if let Some(e) = r.attr("error") {
                *by.entry(e).or_default() += r.repeat;
            }
        }
        by.into_iter()
            .max_by_key(|(_, n)| *n)
            .map(|(e, _)| e.to_owned())
    }

    fn overlaps(&self, other: &Side) -> bool {
        self.window.0 <= other.window.1 && other.window.0 <= self.window.1
    }
}

fn finding(
    severity: Severity,
    id: &'static str,
    title: impl Into<String>,
    detail: impl Into<String>,
    action: impl Into<String>,
    evidence: Vec<String>,
) -> Finding {
    Finding {
        severity,
        id,
        title: title.into(),
        detail: detail.into(),
        action: action.into(),
        evidence,
    }
}

fn with_error(base: String, error: Option<String>) -> String {
    match error {
        Some(e) => format!("{base} The error was: \"{e}\"."),
        None => base,
    }
}

/// Stream failures by reason, from the device's or the gateway's view.
fn stream_failures(side: &Side) -> BTreeMap<String, u64> {
    let mut by = BTreeMap::new();
    for r in side.records.iter().filter(|r| r.code == "stream.closed") {
        if let (Some(result), Some(reason)) = (r.attr("result"), r.attr("reason")) {
            if result != "ok" && result != "cancelled" {
                *by.entry(reason.to_owned()).or_default() += r.repeat;
            }
        }
    }
    by
}

fn analyze_device(c: &Side, gw: Option<&Side>, out: &mut Vec<Finding>) {
    let who = format!("device \"{}\"", c.name);
    if let Some(g) = gw {
        if !c.overlaps(g) {
            out.push(finding(
                Severity::Info,
                "windows_do_not_overlap",
                format!("The recordings of {who} and the gateway don't overlap in time"),
                "The device and the gateway were recording at different times, so their events can't be compared.",
                "Start diagnostics on the gateway first, then on the device, and reproduce the problem while both are recording.",
                vec![],
            ));
        }
    }
    let gw_tls_rejects = gw
        .map(|g| {
            g.records
                .iter()
                .copied()
                .filter(|r| r.code == "gateway.tls.rejected")
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let gw_sessions = gw.map(|g| g.count("session.opened")).unwrap_or(0);

    // The phone app's own check of the gateway's address: the name lookup,
    // then a plain TCP connection to the port.
    let dns_failed = c.matching("client.reach.dns", "result", "failed");
    let tcp_failed = c.matching("client.reach.tcp", "result", "failed");
    if let Some(r) = dns_failed.first() {
        let host = r.attr("host").unwrap_or("the server");
        out.push(finding(
            Severity::Error,
            "gateway_name_not_resolved",
            format!("{who} can't look up the gateway's address"),
            with_error(format!("Looking up {host} failed on the device."), Side::top_error(&dns_failed)),
            "Check that the server address in the invitation still exists in DNS (with Cloudflare, that its record is still there). If it does, the device's network blocks or filters the lookup: try another network, for example mobile data instead of Wi-Fi.",
            vec![format!("{}× client.reach.dns result=failed", Side::total(&dns_failed))],
        ));
    } else if let Some(r) = tcp_failed.first() {
        let address = r.attr("address").unwrap_or("the server's address");
        let resolved = c
            .matching("client.reach.dns", "result", "ok")
            .first()
            .and_then(|d| d.attr("addresses"))
            .map(|a| format!(" The name resolved to {a}."))
            .unwrap_or_default();
        out.push(finding(
            Severity::Error,
            "gateway_port_unreachable",
            format!("{who} can't open a connection to the gateway's address"),
            with_error(format!("Connecting to {address} failed on the device.{resolved}"), Side::top_error(&tcp_failed)),
            "Check that the address is your server's (or Cloudflare's, with Cloudflare Tunnel) and that the port is open in the server's or cloud provider's firewall. If the address looks wrong (127.0.0.1, 0.0.0.0, or one that is neither yours nor Cloudflare's), the device's network is altering DNS answers: try another network.",
            vec![format!("{}× client.reach.tcp result=failed", Side::total(&tcp_failed))],
        ));
    }

    // What the phone's VPN layer reported (the system refused the VPN,
    // the interface closed).
    let platform: Vec<&Record> = c
        .records
        .iter()
        .copied()
        .filter(|r| r.code == "client.platform")
        .collect();
    if !platform.is_empty() {
        out.push(finding(
            Severity::Warn,
            "device_vpn_problem",
            format!("{who} reported a problem with its VPN"),
            with_error(format!("{} problem(s) from the phone's VPN.", Side::total(&platform)), Side::top_error(&platform)),
            "The phone's system refused or ended the VPN. Check that the app may create a VPN (Android: Settings → Network → VPN; iOS: Settings → VPN), that no other VPN app took over, and that battery saving doesn't stop the app.",
            vec![format!("{}× client.platform", Side::total(&platform))],
        ));
    }

    // Connection attempts that failed, by stage.
    let ws = c.matching("client.connect.failed", "stage", "websocket");
    let tls = c.matching("client.connect.failed", "stage", "tls");
    let session = c.matching("client.connect.failed", "stage", "session");

    if !ws.is_empty() {
        let n = Side::total(&ws);
        let err = Side::top_error(&ws);
        let reached =
            gw.is_some_and(|g| g.count("gateway.accepted") > 0 || g.count("handshake") > 0);
        let (title, action) = if gw.is_some() && !reached {
            (
                format!("{who} can't reach the gateway"),
                "Nothing arrived at the gateway while the device was failing, so the connection is lost on the way. Check: the address and port in the invitation still point at this server; the device port is open in the server's or cloud provider's firewall; with Cloudflare Tunnel, Connectivity shows the tunnel as active; the device's own network (captive portal, proxy, firewall) allows the connection.",
            )
        } else {
            (
                format!("{who} can't open the connection to the gateway"),
                "Check the server address and port, the firewall, and (with Cloudflare Tunnel) the tunnel status under Connectivity. An HTTP status in the error (403, 404, 502, 530) means something between the device and the gateway answered instead.",
            )
        };
        out.push(finding(
            Severity::Error,
            "device_cannot_reach_gateway",
            title,
            with_error(
                format!("{n} connection attempt(s) failed before any secure session started."),
                err,
            ),
            action,
            vec![format!("{n}× client.connect.failed stage=websocket")],
        ));
    }

    if !tls.is_empty() {
        let n = Side::total(&tls);
        let err = Side::top_error(&tls);
        if !gw_tls_rejects.is_empty() {
            let gerr = Side::top_error(&gw_tls_rejects);
            out.push(finding(
                Severity::Error,
                "gateway_rejected_device_certificate",
                format!("The gateway rejected the certificate of {who}"),
                with_error(
                    with_error(format!("{n} attempt(s) failed in the device's TLS handshake, and the gateway refused {} device certificate(s) at the same time.", Side::total(&gw_tls_rejects)), err),
                    gerr,
                ),
                "The device was probably removed, or its certificate expired. Check Devices in the console; if the device is gone or expired, create a new invitation and join again from the device.",
                vec![
                    format!("{n}× client.connect.failed stage=tls (device)"),
                    format!("{}× gateway.tls.rejected (gateway)", Side::total(&gw_tls_rejects)),
                ],
            ));
        } else {
            out.push(finding(
                Severity::Error,
                "device_tls_failed",
                format!("{who} doesn't trust the gateway (TLS failed)"),
                with_error(format!("{n} attempt(s) reached a server but the secure handshake failed on the device."), err),
                "The gateway's identity no longer matches the invitation the device joined with. That happens when the server was reinstalled with its data deleted, or when something on the network intercepts TLS. Create a new invitation and join again; if it keeps failing on one network only, that network is intercepting the connection.",
                vec![format!("{n}× client.connect.failed stage=tls")],
            ));
        }
    }

    let auth_rejects = gw
        .map(|g| {
            g.records
                .iter()
                .filter(|r| {
                    r.code == "gateway.session.rejected"
                        || (r.code == "auth.failure" && r.attr("reason") == Some("auth"))
                })
                .map(|r| r.repeat)
                .sum::<u64>()
        })
        .unwrap_or(0);
    if !session.is_empty() || auth_rejects > 0 {
        let n = Side::total(&session);
        out.push(finding(
            Severity::Error,
            "device_not_authorized",
            format!("The gateway did not authorize {who}"),
            with_error(
                format!("The secure connection was set up, but the session was refused ({n} on the device, {auth_rejects} on the gateway)."),
                Side::top_error(&session),
            ),
            "The device may have been revoked or its role changed. Check Devices in the console and invite it again if needed.",
            vec![format!("{n}× client.connect.failed stage=session"), format!("{auth_rejects}× session/auth rejections (gateway)")],
        ));
    }

    let renew = c
        .records
        .iter()
        .copied()
        .filter(|r| r.code == "client.renew.failed")
        .collect::<Vec<_>>();
    if !renew.is_empty() {
        out.push(finding(
            Severity::Warn,
            "certificate_renewal_failed",
            format!("{who} could not renew its certificate"),
            with_error("The device keeps working until its certificate expires, then it needs a new invitation.".into(), Side::top_error(&renew)),
            "Connect the device once while the gateway is reachable so it renews automatically. If it was removed in Devices, invite it again.",
            vec![format!("{}× client.renew.failed", Side::total(&renew))],
        ));
    }

    let start = c
        .records
        .iter()
        .copied()
        .filter(|r| r.code == "client.start.failed")
        .collect::<Vec<_>>();
    if !start.is_empty() {
        out.push(finding(
            Severity::Error,
            "client_failed_to_start",
            format!("The app on {who} could not start its local proxy"),
            with_error(String::new(), Side::top_error(&start)).trim().to_owned(),
            "If a port is in use, close the other program or change the ports in the app's Settings.",
            vec![format!("{}× client.start.failed", Side::total(&start))],
        ));
    }

    // Streams: what happened to the connections the apps on the device made.
    let failures = stream_failures(c);
    // The app's own health check is refused by policy on purpose.
    let checks = c.count("client.check.ok") + c.count("client.check.failed");
    let explain = |reason: &str| -> Option<(&'static str, Severity, &'static str, &'static str)> {
        Some(match reason {
            "dns" => ("destinations_not_resolved", Severity::Warn, "The gateway couldn't resolve some destination names", "Check the gateway host's DNS settings (for Docker, the DNS the container uses). Names that don't exist also show up here."),
            "timeout" => ("destinations_timed_out", Severity::Warn, "Connections to some destinations timed out at the gateway", "The destinations were slow or unreachable from the gateway's network. Check the gateway's outbound connectivity and its firewall for outbound traffic."),
            "transport" => ("destinations_unreachable", Severity::Warn, "The gateway couldn't connect to some destinations", "The destination refused the connection or had no route from the gateway's network. Check the gateway's outbound network."),
            "policy" => ("blocked_by_policy", Severity::Info, "Some connections were blocked by policy", "That is the gateway's routing policy at work. If the blocked sites should be allowed, review the active profile's rules."),
            "quota" => ("gateway_limits_hit", Severity::Warn, "Some connections hit the gateway's connection limits", "Too many simultaneous connections for the configured limits; reduce parallel downloads or raise the limits in the profile."),
            "auth" => ("streams_unauthorized", Severity::Error, "The gateway refused connections from this device as unauthorized", "Check that the device is still active in Devices; invite it again if not."),
            _ => return None,
        })
    };
    for (reason, mut n) in failures {
        if reason == "policy" {
            n = n.saturating_sub(checks);
        }
        if n == 0 {
            continue;
        }
        if let Some((id, sev, title, action)) = explain(&reason) {
            out.push(finding(
                sev,
                id,
                format!("{title} ({who})"),
                format!("{n} connection(s) from the device ended with reason \"{reason}\"."),
                action,
                vec![format!("{n}× stream.closed reason={reason}")],
            ));
        }
    }

    let ok = c.count("client.check.ok");
    let failed = c.count("client.check.failed");
    if failed > 0 && ok > 0 {
        out.push(finding(
            Severity::Warn,
            "connection_unstable",
            format!("The connection of {who} was unstable"),
            format!("{ok} health check(s) passed and {failed} failed during the recording, with {} reconnect(s).", c.count("transport.reconnect")),
            "Intermittent drops usually come from the device's network (Wi-Fi, mobile data, sleep). If many devices drop at the same time, check the gateway host's network and, with Cloudflare Tunnel, the connector status.",
            vec![format!("{ok}× client.check.ok, {failed}× client.check.failed")],
        ));
    }
    if gw.is_some() && gw_sessions == 0 && ok > 0 {
        out.push(finding(
            Severity::Info,
            "no_gateway_sessions",
            format!("{who} was connected, but the gateway recorded no new session"),
            "The device's session was probably opened before the gateway started recording; that is normal.",
            "To see the session start on both sides, disconnect and reconnect the device while both are recording.",
            vec![],
        ));
    }
}

/// Analyze one gateway recording (if any) together with device reports.
pub fn analyze(gateway: Option<&Report>, devices: &[Report]) -> Analysis {
    let mut out = Vec::new();
    let gw = gateway.filter(|g| g.role == Role::Gateway).map(Side::new);
    let clients: Vec<&Report> = devices.iter().filter(|d| d.role == Role::Client).collect();
    if let Some(g) = &gw {
        let activation = g.matching("config.activation", "result", "error");
        if !activation.is_empty() {
            out.push(finding(
                Severity::Error,
                "config_activation_failed",
                "The gateway failed to activate a configuration",
                format!(
                    "{} activation(s) failed during the recording.",
                    Side::total(&activation)
                ),
                "Check Profiles in the console for the failed revision and its validation errors.",
                vec!["config.activation result=error".into()],
            ));
        }
        let throttles = g.count("resource.throttle");
        if throttles > 0 {
            out.push(finding(
                Severity::Warn,
                "gateway_overloaded",
                "The gateway turned connections away under load",
                format!("{throttles} connection(s) or session(s) were refused because a limit was reached."),
                "Check the host's CPU and memory, and the session/stream limits in the active profile.",
                vec![format!("{throttles}× resource.throttle")],
            ));
        }
        let edge = g
            .records
            .iter()
            .copied()
            .filter(|r| r.code == "edge.failed")
            .collect::<Vec<_>>();
        if !edge.is_empty() {
            out.push(finding(
                Severity::Warn,
                "edge_requests_failed",
                "Enrollment or renewal requests failed at the gateway",
                with_error(format!("{} request(s) failed.", Side::total(&edge)), Side::top_error(&edge)),
                "Expired or already-used invitations fail here: create a new invitation. Removed devices can't renew.",
                vec![format!("{}× edge.failed", Side::total(&edge))],
            ));
        }
        let connector = g
            .records
            .iter()
            .copied()
            .filter(|r| r.code == "integration.failed")
            .collect::<Vec<_>>();
        if !connector.is_empty() {
            out.push(finding(
                Severity::Error,
                "integration_failed",
                "A connectivity integration (Cloudflare Tunnel or certificate) was failing",
                with_error(String::new(), Side::top_error(&connector)).trim().to_owned(),
                "Open Connectivity in the console for the full status, fix the cause, then press Retry setup.",
                vec![format!("{}× integration.failed", Side::total(&connector))],
            ));
        }
        if clients.is_empty() {
            let rejects = g.count("gateway.tls.rejected");
            if rejects > 0 {
                out.push(finding(
                    Severity::Warn,
                    "gateway_rejected_certificates",
                    "The gateway rejected device certificates",
                    with_error(
                        format!("{rejects} connection(s) presented a certificate the gateway does not accept."),
                        Side::top_error(&g.records.iter().copied().filter(|r| r.code == "gateway.tls.rejected").collect::<Vec<_>>()),
                    ),
                    "A removed or expired device keeps retrying. Re-invite it if it should have access; otherwise remove the app from that device.",
                    vec![format!("{rejects}× gateway.tls.rejected")],
                ));
            }
        }
    }
    for c in &clients {
        analyze_device(&Side::new(c), gw.as_ref(), &mut out);
    }
    if gw.is_none() {
        out.push(finding(
            Severity::Info,
            "gateway_not_recorded",
            "The gateway has no recording",
            "Only the device side can be analyzed, so causes on the server can't be confirmed or ruled out.",
            "Start diagnostics under Diagnostics in the console, then reproduce the problem again.",
            vec![],
        ));
    }
    if clients.is_empty() {
        out.push(finding(
            Severity::Info,
            "no_device_report",
            "No device has sent a report",
            "Problems seen only on a device (it can't connect, pages don't load) need the device's own recording.",
            "On the device, open the AegisBorne app, Troubleshooting > Start recording, reproduce the problem, then press Stop and send. A device that can't reach the server can Save to file instead; import that file here.",
            vec![],
        ));
    }
    let problems = out.iter().any(|f| f.severity >= Severity::Warn);
    if !problems && (gw.is_some() || !clients.is_empty()) {
        out.push(finding(
            Severity::Info,
            "no_problems_found",
            "No problems found",
            "Nothing in the recordings points to a failure.",
            "If the problem didn't happen while recording, start a new recording and reproduce it.",
            vec![],
        ));
    }
    out.sort_by_key(|f| std::cmp::Reverse(f.severity));
    Analysis {
        findings: out,
        gateway_recorded: gw.is_some(),
        devices: clients.iter().map(|c| c.name.clone()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::Recording;

    fn rec(code: &str, attrs: &[(&str, &str)], repeat: u64) -> Record {
        Record {
            time_unix_ms: 1_500,
            severity: Severity::Warn,
            code: code.into(),
            attrs: attrs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            repeat,
        }
    }

    fn report(role: Role, records: Vec<Record>, counts: &[(&str, u64)]) -> Report {
        Report {
            role,
            name: if role == Role::Gateway {
                "gateway"
            } else {
                "laptop"
            }
            .into(),
            version: "0".into(),
            recording: Recording {
                started_unix_ms: 1_000,
                ended_unix_ms: 9_000,
                records,
                counts: counts.iter().map(|(k, n)| ((*k).into(), *n)).collect(),
                dropped: 0,
            },
        }
    }

    fn ids(a: &Analysis) -> Vec<&'static str> {
        a.findings.iter().map(|f| f.id).collect()
    }

    #[test]
    fn unreachable_gateway_is_explained() {
        let c = report(
            Role::Client,
            vec![rec(
                "client.connect.failed",
                &[("stage", "websocket"), ("error", "connection refused")],
                4,
            )],
            &[("client.connect.failed", 4)],
        );
        let g = report(Role::Gateway, vec![], &[]);
        let a = analyze(Some(&g), &[c]);
        assert_eq!(a.findings[0].id, "device_cannot_reach_gateway");
        assert!(a.findings[0].title.contains("can't reach"));
        assert!(a.findings[0].detail.contains("connection refused"));
    }

    #[test]
    fn the_phones_own_reachability_check_is_explained() {
        let phone = |records| report(Role::Client, records, &[]);
        let a = analyze(
            None,
            &[phone(vec![rec(
                "client.reach.dns",
                &[
                    ("host", "gw.example.test"),
                    ("result", "failed"),
                    ("error", "no such host"),
                ],
                1,
            )])],
        );
        assert!(ids(&a).contains(&"gateway_name_not_resolved"));
        assert!(a.findings.iter().any(|f| f.detail.contains("no such host")));
        let a = analyze(
            None,
            &[phone(vec![
                rec(
                    "client.reach.dns",
                    &[
                        ("host", "gw.example.test"),
                        ("result", "ok"),
                        ("addresses", "127.0.0.1"),
                    ],
                    1,
                ),
                rec(
                    "client.reach.tcp",
                    &[
                        ("address", "127.0.0.1:443"),
                        ("result", "failed"),
                        ("error", "refused"),
                    ],
                    1,
                ),
            ])],
        );
        let f = a
            .findings
            .iter()
            .find(|f| f.id == "gateway_port_unreachable")
            .expect("finding");
        assert!(f.detail.contains("resolved to 127.0.0.1"));
        let a = analyze(
            None,
            &[phone(vec![rec(
                "client.platform",
                &[("error", "VPN not allowed")],
                1,
            )])],
        );
        assert!(ids(&a).contains(&"device_vpn_problem"));
    }

    #[test]
    fn revoked_device_is_correlated_across_sides() {
        let c = report(
            Role::Client,
            vec![rec(
                "client.connect.failed",
                &[("stage", "tls"), ("error", "alert")],
                3,
            )],
            &[],
        );
        let g = report(
            Role::Gateway,
            vec![rec(
                "gateway.tls.rejected",
                &[("error", "certificate revoked")],
                3,
            )],
            &[("gateway.tls.rejected", 3)],
        );
        let a = analyze(Some(&g), &[c]);
        assert!(ids(&a).contains(&"gateway_rejected_device_certificate"));
        assert!(!ids(&a).contains(&"device_tls_failed"));
    }

    #[test]
    fn health_checks_are_not_reported_as_policy_blocks() {
        let c = report(
            Role::Client,
            vec![rec(
                "stream.closed",
                &[("result", "denied"), ("reason", "policy")],
                5,
            )],
            &[("client.check.ok", 5)],
        );
        let g = report(Role::Gateway, vec![], &[("session.opened", 1)]);
        let a = analyze(Some(&g), &[c]);
        assert_eq!(ids(&a), vec!["no_problems_found"]);
    }

    #[test]
    fn missing_sides_are_called_out() {
        let a = analyze(None, &[]);
        assert!(ids(&a).contains(&"gateway_not_recorded"));
        assert!(ids(&a).contains(&"no_device_report"));
        assert!(!ids(&a).contains(&"no_problems_found"));
        let dns = report(
            Role::Client,
            vec![rec(
                "stream.closed",
                &[("result", "error"), ("reason", "dns")],
                2,
            )],
            &[],
        );
        let a = analyze(None, &[dns]);
        assert!(ids(&a).contains(&"destinations_not_resolved"));
    }
}
