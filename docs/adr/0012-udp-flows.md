# ADR-0012 — UDP flows (C-006)

Status: accepted (owner direction, 2026-10-28).

## Context

AGP carried TCP only. On phones that meant calls, games and QUIC didn't go through the VPN (browsers fell back to TCP), and desktop apps couldn't send UDP through the local proxy. The design reserved a DATAGRAM frame for this (03 §3, FR-015).

## Decision

**Protocol: an optional feature, not a new version**

- Feature `0x0001` (optional) in HELLO/HELLO_ACK enables UDP flows. Peers without it never see the new frames: a client only opens a flow on a session that selected it, so old gateways and old clients keep working, TCP only.
- A UDP flow is an ordinary stream opened with OPEN network 2, carrying DATAGRAM frames (one whole datagram each). It reuses stream IDs, OPEN_ACK codes, RESET, GOAWAY, and, most importantly, **per-OPEN admission**: identity, revocation and the routing policy are checked for each flow exactly as for a TCP stream. The wire contract is in `docs/protocol/AGP-1.0.md`.
- **One flow per destination** ("connected" UDP). The gateway resolves once, checks every address against the same egress rules as a TCP dial, and connects a UDP socket to the first permitted one. That socket neither sends anywhere else nor accepts datagrams from anyone else, so a flow can't be turned into an open relay or reach a denied address through replies.

**Loss instead of backpressure**

- Datagrams use no stream or session credit. Bounded buffers (per session 512 KiB received, 256 KiB to send; 64 datagrams per flow) are reserved from the peer budget when the feature is selected. When they are full, new datagrams are dropped and counted. Nothing waits, so UDP can't hold up the session's control frames or TCP streams.
- The writer sends control frames first, then datagrams for at most half of each write batch, then DATA round-robin.
- UDP rides the same ordered transport (TLS over WebSocket), so flows of one session still share head-of-line delays on a lossy link. That is acceptable for QUIC, voice and games at this scale; it is recorded, not hidden (TC-N07 asks to measure it).
- Flows end by RESET. Gateways close a flow after 120 s without a datagram.

**Clients**

- **Local proxy:** SOCKS5 UDP ASSOCIATE (RFC 1928 §7, no fragmentation). The relay socket listens on the address the client reached, accepts datagrams only from the client's IP (and the port it named), and lives as long as the control connection. Each destination becomes its own admitted flow, at most 64 per association. Direct routes get a direct UDP socket under the same egress checks.
- **Android:** the VPN path sends every non-DNS UDP flow (one app socket and destination) through its own UDP association with the local proxy. Names from the fake-IP DNS go to the gateway as names, as for TCP. DNS itself stays local (fake-IP).
- The HTTP proxy and the Windows system proxy remain TCP only, as HTTP proxies are.

## Consequences

- QUIC (HTTP/3), voice and video calls, and games work through the phone VPN and through SOCKS5 clients that support UDP. A gateway on an older version refuses nothing: the client simply doesn't open flows, and apps fall back as on a network that blocks UDP.
- The gateway gains UDP egress. It follows the routing rules and egress address policy like TCP (private, loopback and metadata ranges stay denied unless allowed).
- Tests: protocol vectors (`open_udp`, `datagram` and malformed ones), session tests for negotiation, boundaries, drops, RESET and peer violations (`aegis-session/tests/datagram.rs`), an end-to-end SOCKS5 UDP ASSOCIATE run through a gateway (`e2e.rs`), and the Android packet path from raw IP packets through the proxy and back.
- Not done: SOCKS5 UDP fragmentation (dropped), UDP for the managed desktop System-VPN modes (M3; the plain desktop system VPN of ADR-0015 carries UDP), and a measurement of head-of-line effects under loss.
