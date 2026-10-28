# ADR-0013 — Direct QUIC transport

Status: accepted (owner direction, 2026-10-28).

## Context

UDP flows (ADR-0012) ride the WebSocket tunnel, which is TCP: a packet lost on the tunnel leg holds up every flow behind it until TCP resends it. For games and calls that shows up as freezes of 100–300 ms on lossy links (mobile data, busy Wi-Fi). The owner runs gateways on VPSs (Hong Kong, Beijing, Los Angeles) and at home (Sydney) and wants UDP to stay UDP end to end where possible.

Cloudflare can't carry it: its edge ends QUIC from browsers and talks TCP to origins, and Tunnel carries only HTTP/WebSocket. A UDP path must reach the gateway directly.

## Decision

**Transport**

- A device connects to the gateway over QUIC (quinn, rustls/ring) on a UDP port. The QUIC handshake *is* the mutual TLS 1.3 handshake: same device and gateway certificates, CA pinning, revocation and policy as the WebSocket path's inner TLS, ALPN `agp-quic/1`, no 0-RTT or resumption. No second TLS layer runs inside.
- The AGP session runs unchanged on the one bidirectional stream the client opens (TCP streams, control). The gateway accepts no other streams.
- UDP flows' datagrams travel as QUIC datagrams (RFC 9221) when both sides agree on AGP feature `0x0002`: packet = flow ID (u32) + payload. They are never retransmitted or ordered behind anything. A datagram too large for the path's current QUIC datagram size (apps' own 1,200–1,500-byte QUIC packets often are) falls back to the in-session DATAGRAM frame, so nothing breaks; it just doesn't gain.
- QUIC datagrams that don't belong to an open flow are dropped, never a session error: they may race the stream.
- Keepalives every 15 s keep NAT bindings; connections follow a client that changes address (phones moving between networks).

**QUIC first, WebSocket fallback**

- A device with a QUIC address tries it first (3 s), and on failure uses the usual WebSocket address (direct or Cloudflare) and stays there for 2 minutes before trying QUIC again. Networks that block UDP keep working.
- The apps show which transport carries the tunnel.

**Opt-in on the appliance**

- Every appliance listens for QUIC inside the container, on the device port number (UDP 8444 in the container; added to older profiles by a one-time upgrade). It is reachable only when the installer publishes the UDP port: `install.sh --quic` (remembered on upgrades; `--no-quic` undoes it).
- Devices learn the QUIC address only after an administrator turns it on (Connectivity → Direct QUIC). With direct connections it defaults to the device address and port. With Cloudflare Tunnel the server's own address and UDP port must be entered, which exposes that address to devices.
- The address travels in invitations and in the endpoint devices fetch on every connect, so devices already joined pick it up without a new invitation.

## Consequences

- Where devices can reach the gateway's UDP port, app UDP is UDP end to end and the tunnel connects faster (one handshake instead of TCP + TLS + WebSocket + TLS). TCP streams inside still share one ordered QUIC stream, so their head-of-line behaviour is like before; per-stream QUIC streams would be a larger change of the session layer.
- The gateway gains a UDP listener when published. Unauthenticated clients can't get past the handshake (mandatory client certificates); pending handshakes are bounded like the WebSocket edge's.
- Tests: the transport (`aegis-transport-quic/tests`), the session's datagram path (`aegis-session/tests/datagram.rs`), end to end over QUIC and the fallback (`aegis-node/tests/e2e.rs`), the console setting and invitations (`aegisd/tests/appliance.rs`).
- Not done: path MTU tuning beyond quinn's discovery, loss protection (sending game packets twice), choosing among several gateways by latency, and native capture on desktops (planned phases).
