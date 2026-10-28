# Implementation status and test traceability

Evidence base: developer runs on WSL2 Ubuntu 22.04 x86_64, Rust 1.97.1, 2026-10-25.

- `cargo test --workspace`: 153 tests, all passing. The concurrency-sensitive suites (session, node, core, management) also passed 15 consecutive loops with no failures.
- `cargo clippy --workspace --all-targets -D warnings`: clean.
- `xtask arch-check`: clean, including its self-test.
- A binary smoke test also passed (two `aegisd` processes plus `aegisctl` and `curl`).

These are **development results, not release-gate evidence** (07 §14). None of the following has been done:

- signed artifacts;
- a Pi 4B run;
- a Cloudflare path;
- a soak test;
- an independent review.

Status legend:

- **PASS (dev):** the assertions are executed locally by an automated test.
- **PARTIAL:** some of the required assertions are covered; the gap is stated.
- **BLOCKED:** needs hardware, credentials or infrastructure that is not available here.
- **NOT IMPL:** the feature does not exist in this build. It is refused at validation or runtime, never silently enabled.

## Work packages (09)

| WP | Status | Where / notes |
|---|---|---|
| S-001 spike | BLOCKED | No Pi or Cloudflare access. The production path was exercised locally instead (`aegis-node/tests/e2e.rs`). |
| A-001 workspace | PASS (dev) | `Cargo.toml`, `rust-toolchain.toml` pinned to 1.97.1, `Cargo.lock`. Feature flags are not yet split per role. |
| A-002 architecture rules | PASS (dev) | `xtask arch-check`: 32 rules plus the `forbid(unsafe_code)` policy, and a self-test that injects a forbidden edge. |
| A-003 dependency intake | PARTIAL | `docs/DEPENDENCIES.md`, `deny.toml`. The review sign-off is pending, and no approval-metadata gate exists. |
| A-004 packaging | PARTIAL | `deploy/Dockerfile` (rootless, uid 10001), `deploy/systemd/aegisd.service`. Not built or run; base image digests are not pinned. |
| A-005 CI | PARTIAL | `.github/workflows/ci.yml`. It has not been run; action SHAs are not pinned; lab and protected environments are not provisioned. |
| B-001 state machines | PASS (dev) | `aegis-contracts::state` (agent, stream, revision, enrollment). |
| B-002 supervisor | PASS (dev) | `aegis-core::supervisor` (bounded jittered backoff, circuit breaker); used by the client tunnel reconnect. |
| B-003 budgets | PASS (dev) | `aegis-buffer`, plus the credit reservation invariant in `aegis-session`. |
| B-004 capability registry | PASS (dev) | `aegis-platform::Registry`; `aegis-node::modules`. |
| B-005 commit/publication/recovery | PASS (dev) | `aegis-core::{gate,coordinator}`; local IPC inspect, reconcile and supersede. |
| C-001 AGP codec | PASS (dev) | `aegis-agp`. Property tests and fuzz targets exist; the fuzzers have **not been run** (no nightly toolchain). |
| C-002 inner mTLS | PASS (dev) | `aegis-identity`. TLS 1.3 only; tickets, resumption and early data disabled. |
| C-003 multiplexer | PASS (dev) | `aegis-session`. |
| C-004 WebSocket | PARTIAL | `aegis-transport-ws`. Direct path tested; local reverse proxy and Cloudflare paths are BLOCKED. |
| C-005 HTTP/2 | NOT IMPL | Rejected by validation. |
| QUIC transport | PASS (dev) | Direct QUIC with mTLS in the handshake, AGP on one stream, UDP flows as QUIC datagrams, WebSocket fallback ([ADR-0013](adr/0013-direct-quic.md)); `aegis-transport-quic/tests`, `e2e.rs` (QUIC and fallback). Not measured on lossy or real mobile paths. |
| C-006 DATAGRAM / UDP | PASS (dev) | Optional feature 0x0001: UDP flows with DATAGRAM frames, bounded reserved buffers that drop instead of blocking ([ADR-0012](adr/0012-udp-flows.md)); `aegis-session/tests/datagram.rs`, vectors, `e2e.rs` SOCKS5 UDP ASSOCIATE. Head-of-line effects under loss are not measured. |
| D-001 SOCKS5 | PASS (dev) | `aegis-inbound-socks`: CONNECT and UDP ASSOCIATE (no fragmentation). |
| D-002 HTTP CONNECT | PASS (dev) | `aegis-inbound-http`. |
| D-003 gateway egress | PASS (dev) | `aegis-policy::address`, `aegis-outbound-direct`. Per-user/network rate quotas are not implemented. |
| D-004 DNS | PASS (dev) for M1 | `aegis-dns`: explicit resolvers, no fallback, IPv6 policy. Split DNS (M3/M4) is NOT IMPL. |
| D-005 route engine | PASS (dev) | `aegis-policy::router`. |
| D-006 – D-010 System-VPN native | NOT IMPL / BLOCKED | See the TC-V rows. Policy compilation (part of D-009) is implemented. |
| E-001 SQLite store | PASS (dev) | `aegis-storage`. Encrypted backups are NOT IMPL. |
| E-002 auth/bootstrap | PASS (dev) | `aegis-management::auth`. MFA/passkeys (P1) are NOT IMPL. |
| E-003 REST API | PARTIAL | All OpenAPI paths are implemented. There is no generated client and no automated OpenAPI schema-fixture validation. |
| E-004 web console | PARTIAL | `apps/aegis-ui`: status, validate/diff/activate, enroll/revoke and audit. No browser automation; English only. |
| E-005 enrollment | PASS (dev) for M1 | CSR enrollment with one-use invitations. Managed CA rotation is NOT IMPL. |
| E-006 native shells | NOT IMPL | |
| F-001 / F-002 telemetry | PARTIAL | Noop default, local counters, coarse OTLP/JSON export. Not tested against a stock Collector. |
| F-003 SemConv gate | PARTIAL | The catalog mirror is checked against the spec YAML; the allowlist is enforced pre-serialization. |
| F-004 diagnostics | PARTIAL | Explain API and local diagnostic ring. Support-bundle export is NOT IMPL. |
| F-005 benchmarks | BLOCKED | |
| G-001 – G-005 release readiness | BLOCKED / NOT IMPL | |
| H-001 – H-003 host privacy | PASS (dev) | See the TC-PRIV rows. |

## Acceptance cases (07, 11)

### Protocol

| ID | Status | Evidence |
|---|---|---|
| TC-P01 | PASS (dev) | `aegis-agp/tests/roundtrip.rs` (payload sizes 1..65536, chunked streams, property cases). |
| TC-P02 / TC-P03 | PASS (dev) | `aegis-agp/src/frame.rs` tests. |
| TC-P04 | PASS (dev) | `mux.rs::tc_p04_quota_bounded_under_open_flood` (2,000 OPENs, memory bounded). |
| TC-P05 / TC-P06 / TC-P07 | PASS (dev) | `aegis-session/tests/mux.rs`. |
| TC-P08 / TC-P09 | PASS (dev) | `aegis-identity/tests/mtls.rs`; `aegis-node/tests/e2e.rs` (revocation closes the live session; re-authentication is refused). |
| TC-P10 / TC-P13 / TC-P14 / TC-P15 / TC-P16 / TC-P17 | PASS (dev) | `aegis-session/tests/mux.rs`, including raw adversarial-peer cases. |
| TC-P11 | PASS (dev) | `aegis-config/tests/compile.rs` (loop, conflict and unknown-outbound cases). |
| TC-P12 | PARTIAL | The data plane has no runtime dependency on management (A-002) and restart restores the last applied revision. A 24 h controller outage is not exercised. |
| TC-P18 | PASS (dev) | Gate level (`aegis-core/tests/activation.rs`) and system level on the same AGP session (`e2e.rs`). |
| TC-P19 | PASS (dev) | `mtls.rs::tc_p19_resumption_and_early_data_disabled`. |
| TC-P20 | PARTIAL | 1,000 seeded open/reset/drop cycles return to the baseline. The spec requires 10,000 events plus timer/handle accounting. |

### Unit-level gates and crash consistency

| ID | Status | Evidence |
|---|---|---|
| TC-U01 | PASS (dev) | `xtask arch-check --self-test`. Feature-matrix builds are not covered. |
| TC-U02 | PASS (dev) | Unknown fields rejected; TOML/JSON produce the same digest; cyclic routes rejected. |
| TC-U03 | PARTIAL | Property tests pass. The fuzz targets compile but were not run, and no corpus budget has been applied. |
| TC-U04 | PASS (dev) | Supervisor tests. |
| TC-C01 / TC-C02 | PASS (dev) | Fault injection at every cut, plus a simulated crash followed by reopening the same DB file. A real process kill (SIGKILL) is not exercised. |
| TC-C03 | PASS (dev) | 100 reader threads against alternating activations. |
| TC-C04 | PARTIAL | Revocations survive restart. SQLite corruption and unavailability while serving are not exercised. |
| TC-C05 | PASS (dev) | Supersede with stale-expectation rejection and chain linkage; restart-required reported in the diff. |

### Management API

| ID | Status | Evidence |
|---|---|---|
| TC-A01 | PARTIAL | Positive and negative request tests. There is no OpenAPI meta-schema or generated-client validation. |
| TC-A02 | PASS (dev) | Bootstrap reuse and expiry, lockout, CSRF, Host/Origin/CORS checks (`aegis-management/tests/api.rs`). |
| TC-A03 / TC-A04 | PASS (dev) | `activation.rs`, `api.rs`. |
| TC-A05 | PASS (dev) | Scoped bearer tokens, job object scope, cursor binding. Multi-user roles beyond the owner are not exercised. |
| TC-A06 | BLOCKED | No browser automation. |

### Network paths

| ID | Status | Evidence |
|---|---|---|
| TC-N01 / TC-N02 / TC-N03 | PASS (dev) | Inbound unit tests plus `e2e.rs` (SSRF via literal, via DNS-resolved loopback, and via the metadata IP). |
| TC-N04 | PASS (dev) | `aegis-policy/tests/golden.rs` (1,050 rules, order independence). |
| TC-N05 | PARTIAL | Direct WebSocket path, byte-exact transfers, restart persistence. Cloudflare proxied, Tunnel and OCI paths are BLOCKED. |
| TC-N06 | NOT IMPL | |
| TC-N07 | PARTIAL | Boundaries up to the frame cap, bounded queues and counted drops, RESET, negotiation and peer violations (`aegis-session/tests/datagram.rs`); UDP through a gateway end to end (`e2e.rs`). No loss/reorder simulation or head-of-line measurement yet. |

### Observability

| ID | Status | Evidence |
|---|---|---|
| TC-O01 | PARTIAL | Destinations never enter metrics or diagnostics by construction. There is no support-bundle test. |
| TC-O02 | PASS (dev) | 100k events produce bounded series (`local.rs`). |
| TC-O03 | PARTIAL | Unreachable-collector behavior is tested. There is no stock-Collector interop test. |
| TC-O04 | PARTIAL | Active gauges come from RAII counters, not events. There is no saturation test. |

### Host privacy (11)

| ID | Status | Evidence |
|---|---|---|
| TC-PRIV01 | PARTIAL | With default settings no exporter exists. No packet capture under load was performed. |
| TC-PRIV02 | PASS (dev) | Smoke test: 0 bytes on stdout/stderr from both daemons across a full session. |
| TC-PRIV03 / TC-PRIV04 | PASS (dev) | `export.rs`: serialized-payload term scan, fuzzed attributes, exact metric and resource set. |
| TC-PRIV05 | PASS (dev) | `diagnostic.rs`: duration bound and expiry; a restart always starts disabled. |
| TC-PRIV06 | PASS (dev) | `api.rs`: permission, ETag and preview digest required; a profile cannot enable export. |
| TC-PRIV07 | PASS (doc) | The limitations against a privileged host adversary are documented in this file and the README. |
| TC-PRIV08 | PASS (dev) | The unreachable collector drops telemetry with bounded counts; forwarding is unaffected. |

### System VPN

| ID | Status | Evidence |
|---|---|---|
| TC-V01, TC-V05 – TC-V12 | BLOCKED | No native capture, app identity, helper or kill switch exists. |
| TC-V02 – TC-V04 | PARTIAL | Synthetic policy logic only (`aegis-traffic-policy` tests). Native evidence is BLOCKED. |
| TC-V13 | PASS (dev) | `api.rs::tc_v13_vpn_surface_is_read_only_and_honest`. |
| TC-V14 | PARTIAL | `coarse_export` contains only the 4 metrics. No 100k-flow capture test (there is no capture). |
| TC-V15 | PARTIAL | The rootless Dockerfile needs no TUN or NET_ADMIN. Not built or run. |

### Release, security and benchmarks

| ID | Status |
|---|---|
| TC-R01 – TC-R05, TC-S01 – TC-S03, TC-B01 – TC-B03 | BLOCKED (no artifacts, signing, scanners, lab or soak run) |

## Honest limitations (TC-PRIV07 and 01 §6)

- Metadata minimization does **not** protect against a privileged host operator. Root or a hypervisor can observe the process, its sockets, routes and memory, including runtime keys.
- A TLS-terminating edge such as Cloudflare sees outer connection metadata and volume. Inner mTLS protects only content.
- Existing TCP streams do not survive a transport loss. Reconnects create new sessions and new streams; OPENs whose outcome is unknown are never replayed.
- No claim is made of undetectability, unlimited Free-plan capacity, or egress anonymity.
