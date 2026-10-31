# ADR-0009 — Adaptive stream windows

Status: accepted (2026-10-26), amended 2026-10-31 (growth on long round trips, larger quotas).

## Context

Each AGP session reserved a full receive window per stream: a 64 KiB ring allocated at open, and 64 KiB of transmit reservation. Concurrency was then capped so all of those windows fit in the session reservation, plus one working share: with a 2 MiB session window that was **31 streams**.

A browser opens connections in bursts. A device recording showed 684 opens in 37 seconds, of which 560 were refused as `quota`. The applications retried immediately, which kept the session full, and browsing stalled for seconds at a time.

## Decision

Concurrency no longer requires fully allocated windows, as 03 §3 allows: "configured stream concurrency is not a guarantee of that many fully allocated windows".

**Starting and growing windows**

- A stream starts with a small receive window (`initial_stream_window`, 16 KiB, advertised in HELLO).
- On each credit replenishment, the receiver doubles the window when the sender is limited by it: less than half the window is still outstanding when the replenishment is due. Growth stops at the per-stream quota (`stream_window`, 256 KiB).

**Bounds that are kept**

- **Memory:** session credit still bounds everything buffered (`buffered + outstanding ≤ reserved`).
- **Working share:** the sum of all stream windows is kept at or below `reserved - stream_window`. Admission and growth both stop there, so stalled streams can never take the whole receive budget. At least one full stream window always remains for runnable streams.

**Lazy allocation**

- **Receive rings** are allocated as data arrives, sized to what is buffered (never beyond the stream's window), and released when drained.
- **Transmit reservations** start at the initial window and grow as the application writes, up to `stream_tx_buffer`. They shrink back once the buffer drains. The initial reservation always leaves room, so writes always progress.

**Opens wait for capacity**

- An open on a full session waits up to 10 s (bounded by its own timeout) for a slot, instead of failing at once.
- A peer `quota` refusal is retried within the same wait. The peer may still count a stream the opener already released while its side closes.

**Defaults**

- `max_streams_per_session` 512; with an 8 MiB session window, about 496 effective streams.
- `stream_buffer_budget_bytes` 256 KiB, the per-stream maximum.
- `peer_buffer_budget_bytes` 24 MiB; `process_buffer_budget_bytes` 256 MiB.
- Gateways that still carry the old stored defaults are upgraded once at start (`aegisd`), then restart in-process. Values an operator changed are left alone.

## Compatibility

The wire format is unchanged. Windows were always receiver-chosen: a peer honors the advertised initial window and later `WINDOW_UPDATE`s. Mixed old and new peers interoperate; the effective limit is the smaller side's.

## Consequences

- **Idle connections** cost about 16 KiB of window accounting and no buffer memory.
- **Bulk streams** reach 256 KiB windows, four times the old fixed 64 KiB, which helps high-latency paths.
- **Peaks:** under many simultaneous bulk streams, growth is limited by the working-share bound. Individual streams then stay smaller, but nothing stalls or exceeds the reservation.

## Amendment: growth on long round trips (1.1.10)

**What went wrong**

- Measured from Beijing through Cloudflare to a gateway in Los Angeles: the round trip is about 430 ms, and up to about 0.9 s under load.
- Each connection carried at most about 0.3 MB/s, while eight together carried 1.9 MB/s. Raising the per-stream quota changed nothing.
- The cause was the growth rule. The receiver counts credit as outstanding until data arrives against it, and on a long round trip most of the window is always data in flight. So "less than half outstanding" almost never held, and windows stayed near 64 KiB.
- A simulated 430 ms link reproduces it: one 8 MiB download took 56 s (0.15 MB/s) whatever the quota.

**The rule now**

- Each session keeps a smoothed round-trip time from PING/PONG.
  - It pings only while streams receive data, at most once every 5 s, and its keepalive pings count too. Idle sessions send nothing extra.
  - Every peer answers PING, so this needs no protocol change.
- Each stream counts the bytes consumed since the start of an epoch.
  - When a whole window is consumed within two round trips, the sender is limited by the window. The window grows fourfold (up to the quota, within the working share) and a new epoch starts.
  - When two round trips pass first, a new epoch starts without growth.
- The old rule still applies too. It works on short links and before the first sample.
- **Growth may take at most three quarters of the working share** (the sum of growth beyond initial windows). The last quarter stays for new streams.
  - Idle streams at their initial window don't count against it, so a browser's hundreds of idle connections don't keep a busy one from growing.
  - Without this, a few downloads that grew to 2 MiB and then stopped reading took the whole share. New connections were refused after 13 of them, the tunnel's health check included. `stalled_downloads_leave_the_tunnel_usable` holds it for the default and iPhone settings.

**Quotas**

- `stream_buffer_budget_bytes` defaults to **2 MiB** (allowed: 16 KiB to 4 MiB). One connection then carries about 2–4 MB/s over a 0.5–1 s round trip.
  - The session window still bounds everything received. A bigger quota only lets one busy connection use more of it.
  - The session window grows from 8 MiB to **10 MiB**, so the working share (10 − 2 MiB) still holds all 512 connections at 16 KiB. With 8 MiB it would hold 384.
  - The peer budget (24 MiB) still covers the session window plus every connection's initial transmit reservation.
- iPhones use **1 MiB** (ADR-0018).
- The per-stream transmit buffer stays at most 1 MiB (`MAX_STREAM_TX_BUFFER`). Data leaves it as soon as credit allows, so a larger one would only hold more for a peer that stopped reading.
- Gateways whose profile still holds the old defaults (256 KiB and 8 MiB) get the new ones once at start (`stream-window-upgrade`). Values an operator chose stay.

**Compatibility**

- A window is the receiver's. A new app downloads fast from any gateway, and a new gateway receives uploads fast from any app.
- Old apps and gateways keep their own (slow) growth for what they receive.

**Measured on the simulated link (430 ms, 4 MB/s):** one download, before and after.

| Size | Before | 1 MiB quota | 2 MiB quota |
|---|---|---|---|
| 2 MiB | 0.15 MB/s | 0.87 MB/s | 0.87 MB/s |
| 8 MiB | 0.15 MB/s | 1.56 MB/s | 2.05 MB/s |
| 32 MiB | 0.15 MB/s | 1.95 MB/s | 3.11 MB/s |

Tests in `crates/aegis-session/tests/latency.rs` hold these for downloads, uploads, a gateway with a small window, and the iPhone's quota.

**Measured for real:** a client with this change, from a Beijing server through Cloudflare to a 1.1.9 gateway in Los Angeles. One 8 MB download each run; the round trip was 0.45–0.8 s.

| Quota | Speed (MB/s) | Window reached |
|---|---|---|
| 256 KiB | 0.21, 0.23 | 256 KiB |
| 1 MiB | 0.50, 0.28 | 1 MiB |
| 2 MiB | 0.55, 0.64, 0.25, 0.47 | 2 MiB |
| 4 MiB | 0.61, 0.38 | 2–3 MiB |

- The path across the border is noisy, so single runs vary. 2 MiB is typically 2–3× the old speed; 4 MiB brought nothing reliable beyond it.
- Through the same gateway from Australia (0.17 s round trip), one download ran at 2.3–5.7 MB/s.
