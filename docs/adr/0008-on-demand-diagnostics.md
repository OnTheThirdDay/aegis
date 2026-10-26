# ADR-0008 — On-demand diagnostics with device reports

Status: accepted (owner direction, 2026-10-26). Supersedes the `local_diagnostic` limits in ADR-0005 (at most 15 minutes, local IPC only, never exported).

## Context

The owner asked for diagnostics that:

- record only while an administrator (on the server) or a user (on the device) turns them on;
- turn themselves off after a while;
- cap their storage, deleting the oldest records first, so they can't fill a disk;
- let the administrator work out what went wrong from both sides together.

Until now the gateway had an IPC-only, 15-minute, coded event ring. Devices had nothing. Nothing explained the events.

## Decisions

1. **Off by default, time-boxed.**
   - Each side records only after an explicit start: the console's **Diagnostics** page (`diagnostics:explain`, owner and operator) or `aegisctl diagnostic start` on the gateway; **Troubleshooting** in the client app on a device.
   - A recording lasts 1–60 minutes and stops by itself. The recorded data is then kept for 60 minutes for review and dropped.
   - A process restart always comes back off.
2. **Memory only, size-capped.**
   - Nothing is written to disk by the recorder.
   - Each recording holds at most **5 MiB** of records; the oldest are deleted first.
   - Identical consecutive records within a minute collapse into a repeat count.
   - A per-kind counter survives deletion, so totals stay right.
   - The gateway holds at most 16 device reports and 16 MiB of them in total, also dropped after 60 minutes.
3. **What is recorded.**
   - **Core events:** finite codes and reason groups, as before (session opened/closed, stream failures by reason, reconnects, handshakes, throttling, configuration activation, authentication failures). Byte accounting and routine successes are only counted.
   - **Component notes:** a bounded error message (at most 300 characters, at most 8 attributes). Examples: why a device's connection attempt failed and at which stage (WebSocket, TLS, session); why the gateway rejected a TLS handshake or session; failed enroll/renew requests; failing integrations (Cloudflare connector down).
   - **Never recorded:** destinations, visited sites, payload, stream IDs.
   - Error messages may contain the server's own address. That is why recording needs an explicit action on each side.
4. **OpenTelemetry format.**
   - Reports are OTLP/JSON logs (`resourceLogs`). The resource carries `service.name`, `service.version`, `aegis.role`, `aegis.name` and the recording window. Each log record has `event.name`, severity and `aegis.*` attributes.
   - A trailing `diagnostic.summary` record carries the counts.
   - The console exports everything held as one file, which loads into any OTLP-compatible tool. This is a download by an authenticated administrator, not a background exporter; the coarse-metrics export of ADR-0004 is unchanged.
5. **Device → gateway upload.**
   - The device gzips its report (at most 900 KiB compressed, trimming the oldest records), then signs `aegis-diagnostic-report-v1\n<unix time>\n<sha256 of payload>` with its device key.
   - It posts the report, signature and certificate to the existing `/renew` edge endpoint. The body shape selects the handler, so Cloudflare tunnel ingress rules are unchanged and no drift appears on upgrade.
   - The gateway:
     - authenticates the certificate exactly like renewal (chain to the device anchor, active registry entry);
     - verifies the signature and a ±10-minute clock window;
     - inflates with a 16 MiB bound;
     - names the report after the **registry** entry, not the report's own claim.
   - Uploads are rate limited with enrollment and accepted **only while the gateway's diagnostics are on** (recording or held). Otherwise the device is told to ask the administrator.
   - The edge body limit rose from 32 KiB to 2 MiB to fit an upload. The pending-handshake cap and the 10 s edge deadline still bound its cost.
   - A device that can't reach the gateway saves the same file locally, and the administrator imports it in the console.
6. **Analysis.**
   - A deterministic, rule-based analyzer correlates the gateway recording with device reports over the same window.
   - It produces findings, each with severity, explanation, suggested fix and evidence. Examples:
     - a device can't reach the gateway (nothing arrived at the gateway);
     - the gateway rejected the device's certificate (both sides agree);
     - the device doesn't trust the gateway (server reinstalled or TLS interception);
     - destinations not resolved, timing out or unreachable from the gateway;
     - blocked by policy, excluding the client's own health checks;
     - gateway limits hit;
     - a configuration activation failed;
     - an integration failing;
     - an unstable connection;
     - recordings that don't overlap.
   - It also says when a side is missing, and "No problems found" when nothing points to a failure.

## Consequences

- Operators get a guided flow: start on the server, start on the device, reproduce, read the findings.
- A recording can hold error strings. Mitigations: explicit opt-in on each side, the time box, memory-only storage, the size cap, retention, audit entries (`diagnostics.started`, `.stopped`, `.discarded`, `.imported`), and the `diagnostics:explain` permission.
- `aegisctl diagnostic stop` now keeps the data for review; `aegisctl diagnostic discard` drops it.
