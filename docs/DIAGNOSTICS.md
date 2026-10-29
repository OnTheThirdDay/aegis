# Diagnosing problems

When a device can't connect, or sites don't load through AegisBorne, record what the gateway and the device see while the problem happens. The console then explains what went wrong and what to do.

Diagnostics are **off** until someone turns them on, and they turn themselves off again. Nothing is written to disk.

## Steps

**On the server (administrator):**

1. Open the console → **Diagnostics**.
2. Choose how long to record (5–60 minutes) and press **Start recording**.

**On the device (its user):**

3. Open the AegisBorne app → **Troubleshooting**.
4. Choose a duration and press **Start recording**.
5. Reproduce the problem: connect, open the sites or apps that fail.
6. Press **Stop and send**. If you don't, the app sends the report by itself when its recording ends.

**Back in the console:**

7. Read the **Analysis**. Each finding says what happened, what to do, and which recorded events it is based on.

**If the device can't reach the server at all,** it can't send its report. Press **Save to file** in the app instead. The file lands in the app's data folder, and the app shows the full path. Send the file to the administrator, who imports it under **Diagnostics → Device reports → Import report file**.

## What is recorded and for how long

| | |
|---|---|
| **Recorded** | Connection events: sessions opened or closed, failed connections and their reason (DNS, timeout, policy, …), reconnects, TLS and authentication failures, failing integrations such as a stopped Cloudflare connector. Short error messages, for example `invalid peer certificate: UnknownIssuer`. |
| **Never recorded** | Which sites or addresses are visited, traffic content, stream IDs. |
| **Duration** | Recording stops by itself after the chosen time, at most 60 minutes. |
| **Storage** | In memory only, never on disk. At most 5 MB per recording: when that is reached, the oldest events are deleted first. Repeated identical events are stored once with a count. The gateway keeps at most 16 device reports, 16 MB in total. |
| **Retention** | After recording stops, the data is kept for 60 minutes for review, then dropped. **Discard everything** in the console, or **Discard** in the app, drops it immediately. Restarting the gateway or the app always drops it. |
| **Who can see it** | Accounts with the owner or operator role. Starting, stopping, discarding and importing are recorded in the audit log. |

**Uploads from devices:**

- A device can send its report only while the gateway's diagnostics are on.
- The report is signed with the device's own key and checked against the device list. A removed device can't send one.
- The report is filed under the device's registered name.

## Exporting to other tools

**Download as OpenTelemetry logs** saves everything held as one OTLP/JSON file (`resourceLogs`): the gateway's recording plus every device report. It can be loaded into any tool that reads OTLP logs, for example an OpenTelemetry Collector with the `otlpjsonfile` receiver. Each record carries:

- **Event:** `event.name`, a severity, and `aegis.*` attributes.
- **Resource:** `aegis.role` (`gateway` or `client`) and `aegis.name` tell the sources apart.

## Command line and API

**On the gateway host, through the local admin socket:**

```sh
docker exec aegis aegisctl diagnostic start --minutes 15
docker exec aegis aegisctl diagnostic status
docker exec aegis aegisctl diagnostic stop       # stop recording, keep the data for review
docker exec aegis aegisctl diagnostic discard    # drop everything
```

**REST** (permission `diagnostics:explain`):

| Method and path | Does |
|---|---|
| `GET /api/v1/diagnostics` | status of the gateway recording and the device reports held |
| `POST /api/v1/diagnostics/start` `{"minutes": N}` | start a recording (1–60 minutes); drops earlier device reports |
| `POST /api/v1/diagnostics/stop` | stop recording, keep the data |
| `POST /api/v1/diagnostics/discard` | drop everything |
| `GET /api/v1/diagnostics/analysis` | findings |
| `GET /api/v1/diagnostics/otlp` | everything held, as OTLP/JSON logs |
| `POST /api/v1/diagnostics/devices` | import a saved device report (JSON or gzip, up to 16 MB) |

Design and security reasoning: [ADR-0008](adr/0008-on-demand-diagnostics.md).
