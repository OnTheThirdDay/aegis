# ADR-0005 — M1/M2 implementation decisions

- Status: Proposed (implementation-time decisions; security owner sign-off pending)
- Date: 2026-10-25
- Scope: decisions taken while implementing the M1 core and the M2 management subset, where the specification left an open question or an unspecified detail.

Each item names the spec reference it resolves, the choice, and what would trigger a revisit.

## 1. OQ-01 — Inner identity PKI

**Choice:** one local CA per installation (ECDSA P-256 via `rcgen`/`ring`).

- Node keys are generated on the node (`aegisctl pki csr`). The CA signs CSRs presented with a one-use invitation (`POST /api/v1/nodes/enrollment` → `/nodes/enrollment/redeem`). Only the CSR's public key is used. Subject, role, EKU and lifetime are set by the CA.
- Identity encoding: subject CN = node ID, subject OU = role (`gateway`/`client`). EKU separates the roles (`serverAuth` for gateways, `clientAuth` for clients), so a certificate cannot act in the other role.
- Node certificates default to 30 days. Peers whose validity span exceeds 90 days are rejected.
- Revocation is by certificate SHA-256 fingerprint in a monotonic security epoch. It is checked by the TLS verifier at handshake time and again by the admission gate on every OPEN. Revoking a node closes its live sessions (the high-risk default).
- Rotation means enrolling a new node name, then revoking the old one. Re-enrolling an existing name is refused, because an invitation is not bound to a name.

**Revisit:** a fleet/managed CA, name-bound invitations, CA rotation (M2 E-005 managed UX).

## 2. OQ-02 — AGP control-message codec

**Choice:** hand-written fixed binary layouts, with no CBOR or protobuf dependency.

- Every decoder consumes the whole payload, rejects trailing bytes, out-of-range values and non-canonical forms (uppercase domains, IPv4-mapped IPv6, unsorted feature lists). Each message has exactly one valid encoding, and the fuzz target `agp_control` asserts the re-encoding round trip.
- Feature IDs with bit `0x8000` set are *critical*. An unknown critical feature rejects the session. AGP/1.0 defines no features.
- Zero-length DATA is a protocol error.
- OPEN payload: `network u8 | atyp u8 | addr | port u16 | timeout_ms u32` (timeout 1..=120000).
- GOAWAY payload: `last_stream_id u32 | reason u8`.

**Revisit:** before the AGP freeze, if extensibility needs outgrow the fixed layouts.

## 3. Flow control parameters

- Session receive windows are reserved from the per-peer budget before they are advertised. The invariant `buffered + outstanding + pending_grant == reserved` is asserted in tests.
- Effective stream concurrency is capped at `session_window / stream_window − 1`. This keeps one full stream window as a working share, so stalled streams cannot exhaust session credit (03 §3: reduce concurrency rather than promise fairness).
- Each stream's TX buffer (default 64 KiB) is reserved when the stream opens. OPENs fail with `quota` when the budget is exhausted.

## 4. Configuration schema additions

The spec's illustrative config deliberately leaves the client tunnel endpoint undefined. This build adds:

- outbound `kind = "agp_tunnel"` with `url` (`wss://`, or `ws://` only to loopback or with `insecure_outer_transport_acknowledged = true`), `server_name` (the inner TLS name) and an optional `outer_ca`;
- `dns.resolver = "system" | "explicit"` plus `nameservers`. Gateways must declare one explicitly, because the spec example "is not a complete profile". A client in `remote_required` mode must not declare one;
- `[secrets] dir` for `secret://` resolution (files);
- `identity.ca_certificate` / `ca_private_key` to enable API enrollment on a gateway;
- `identity.verify_peer` and `outbound.skip_certificate_verification` exist only so that a profile disabling verification fails loudly.

Route actions are role-checked:

- gateway `proxy` must target a `direct_tcp` outbound;
- client `proxy` must target an `agp_tunnel` outbound;
- client `direct` must target a `direct_tcp` outbound, and requires `dns.mode = local_explicit`.

## 5. Profiles and listeners

- A profile is the full typed node configuration. The TOML file seeds the first profile on an empty store, which is then activated through the normal durable protocol (audited with a null actor).
- Listener, identity, budget and management changes are reported as `restart_required` in the validation diff and the health payload. They are never applied by a pointer swap. `node_id`/`role` changes are forbidden.

## 6. Management API additions beyond the OpenAPI draft

- `POST /api/v1/nodes/enrollment/redeem`: authorization is the invitation token itself (one-use, hashed, short-lived, loopback listener only).
- `GET /api/v1/telemetry/preview?service_name=…`: returns the exact serialized OTLP payload and a *shape digest*. `PATCH /telemetry/settings` that enables or redirects export must echo that digest in `X-Aegis-Export-Preview-Digest`, otherwise it gets `409 preview_required`. This implements the spec's mandatory payload preview (11 §3 rule 8).
- `GET /api/v1/system/metrics`: the authenticated in-memory counter snapshot (`local_metrics_enabled`); not OTel.
- `/network/policy/preview` requires `target_node_id` to be a UUID and echoes it. This build is single-node, so there is no registry of node UUIDs to check it against.

## 7. OQ-04 / OQ-05 / OQ-06

- **Admin auth:** local owner with Argon2id password, created by a local one-use bootstrap token. The token is minted only over the owner-only Unix socket while no owner exists. Cookie sessions carry CSRF tokens. Short-lived scoped bearer tokens are minted over IPC for the CLI. Sessions are in memory, so a restart signs everyone out.
- **Storage:** `rusqlite` with bundled SQLite, WAL and `synchronous=FULL`. The audit table is append-only, enforced by triggers.
- **UI:** dependency-free JavaScript checked with `// @ts-check` + JSDoc types, served from the binary under a strict CSP. A TypeScript build step was deferred to avoid a Node toolchain in the release path. The UI is English only; Chinese localization is pending.

## 8. Telemetry

- No OTel SDK is linked. `coarse_export` is a hand-written OTLP/HTTP-JSON encoder for exactly the four catalog metrics, with exhaustive pre-serialization allowlisting. The scope name and SDK name are truthful but not product-identifying (`runtime.coarse`, `coarse-otlp-json`).
- `local_diagnostic` is an in-memory ring of coded events (no destinations), at most 15 minutes, started only over local IPC. It is never persisted, so any restart disables it. *Superseded by [ADR-0008](0008-on-demand-diagnostics.md): up to 60 minutes, console and device toggles, size cap, OTLP/JSON export.*

## 9. Explicit non-implementations

The following are **not implemented**, and the runtime refuses or reports them as unsupported:

- HTTP/2 and SSE transports;
- DATAGRAM / general UDP;
- `dns.mode = per_rule`;
- remote (TLS) management;
- all System-VPN native adapters (capture, app identity, privileged helper, kill switch). Every mode reports `unsupported` and enabling `system_vpn` fails validation.

The four-mode policy compiler and the synthetic preview *are* implemented.
