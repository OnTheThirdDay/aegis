# AegisNet

AegisNet is a security-first modular proxy engine written in Rust. It implements the design package in [`aegis-spec/`](aegis-spec/README.md) (v0.3-draft) from its M1 core MVP up to a subset of M2 management.

> **Status: prototype.** This build is not production-qualified.
>
> - Development tests pass; release gates have not run: Pi 4B hardware, real Cloudflare paths, soak, signed artifacts and independent review are all outstanding.
> - System-VPN (M3/M4) native enforcement is **not implemented**. It is reported as `unsupported`.
>
> See [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) for the per-test-ID matrix.

## What works

- **Data path:** SOCKS5 and HTTP CONNECT on the client → WebSocket (`wss://`, works behind a TLS-terminating edge) → **inner mutual TLS 1.3** (no resumption, tickets or 0-RTT) → **AGP/1** multiplexed streams → gateway → policy-restricted TCP egress.
- **Per-OPEN admission:** every new logical stream, including one on a long-lived session, is checked against the *current* policy and the current revocation snapshot. Revoking a node closes its live sessions.
- **Bounded resources:**
  - receive credit is reserved before it is advertised;
  - control frames keep flowing while DATA is saturated;
  - streams are scheduled fairly;
  - the RESET/ACK drain protocol is enforced;
  - per-stream, per-peer and per-process budgets apply.
- **Egress safety:**
  - an SSRF-safe address policy (loopback, link-local, metadata and private ranges, including IPv4-embedded IPv6 forms);
  - each address is resolved once, every candidate is validated, and only validated addresses are dialed;
  - DNS has no implicit fallback;
  - routing is deterministic and explainable (1,000+ rule golden tests).
- **Crash-consistent configuration:**
  - durable activation intent in SQLite, then CAS publication at the admission gate, then a durable applied record;
  - recovery, `reconcile` and audited `supersede` run over a local IPC socket that only the owning user can use.
- **Management:**
  - loopback REST API following the OpenAPI draft;
  - one-use local bootstrap, Argon2id passwords, cookie sessions with CSRF tokens, scoped bearer tokens for the CLI;
  - ETag/`If-Match`, `Idempotency-Key`, RBAC, RFC 9457 errors;
  - append-only audit log;
  - a minimal admin UI (status, validate/diff/activate, enroll/revoke, audit).
- **Identity:** local CA, CSR enrollment with one-use invitations (the private key never leaves the node), short-lived certificates, EKU-separated roles.
- **Privacy by default:**
  - no OTel SDK, no exporter, no resource detectors and no console logs: the daemon writes **zero bytes** to stdout/stderr in normal operation;
  - bounded in-memory counters are available only to authenticated callers;
  - opt-in export of four allowlisted coarse metrics requires acknowledging a payload preview;
  - local diagnostics run for at most 15 minutes and are never exported.

## Layout

```
crates/
  aegis-contracts        platform-neutral types (no async runtime)
  aegis-buffer           hierarchical RAII budgets
  aegis-agp              AGP/1 codec (strict, length-checked before allocation)
  aegis-session          multiplexer: credit, fairness, half-close, RESET drain
  aegis-identity         local CA, CSR signing, mTLS 1.3 configs, revocation store
  aegis-transport-ws     WebSocket byte-duplex adapter
  aegis-inbound-socks    SOCKS5 (RFC 1928/1929)
  aegis-inbound-http     HTTP CONNECT
  aegis-dns              explicit resolvers, no fallback
  aegis-outbound-direct  policy-restricted dialer
  aegis-policy           route compiler + egress address policy
  aegis-traffic-policy   System-VPN four-mode compiler/evaluator (preview only)
  aegis-config           typed schema, validation, canonical digest, security diff
  aegis-platform         capability registry, host capability probing
  aegis-telemetry        local counters, coarse OTLP export, local diagnostics
  aegis-storage          SQLite revisions/intents/jobs/audit
  aegis-core             admission gate, activation coordinator, supervision
  aegis-node             composition root (gateway + client runtimes)
  aegis-management       REST API, auth/RBAC/CSRF, IPC handlers
apps/  aegisd · aegisctl · aegis-ui (static assets)
xtask/ architecture/unsafe policy checks
fuzz/  cargo-fuzz targets (AGP, config, HTTP head, destinations)
deploy/ Dockerfile (rootless), systemd unit, runnable example configs
docs/  status matrix, ADR-0005, dependency intake, operations
```

## Build and test

```sh
cargo build --locked --workspace
cargo test --locked --workspace           # 153 tests
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo run -p xtask -- arch-check          # crate-graph rules + forbid(unsafe_code)
cargo +nightly fuzz run agp_decoder       # requires cargo-fuzz
```

The end-to-end test (`crates/aegis-node/tests/e2e.rs`) needs a non-loopback network interface for its egress target, because loopback destinations are correctly denied. Without one it reports itself as `BLOCKED` and skips.

## Quickstart

See [docs/OPERATIONS.md](docs/OPERATIONS.md). In short:

```sh
aegisctl validate deploy/examples/gateway.toml
aegisd --config gateway.toml &
aegisctl --socket /var/lib/aegisnet/aegisd.sock bootstrap-token   # then claim the owner in the UI
```

## Decisions and deviations

Where the spec left questions open (PKI, AGP control codec, client tunnel config, auth, UI stack), the choices are recorded in [docs/adr/0005-m1-implementation-decisions.md](docs/adr/0005-m1-implementation-decisions.md). They include the few management endpoints added beyond the OpenAPI draft: enrollment redeem, telemetry preview and the local metrics snapshot.

## Not promised

AegisNet does not promise:

- undetectable traffic;
- unrestricted or free CDN capacity;
- egress anonymity;
- seamless TCP recovery across transport loss;
- protection against a privileged host operator.
