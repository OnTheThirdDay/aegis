# ADR-0009 — Adaptive stream windows

Status: accepted (2026-10-26).

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
