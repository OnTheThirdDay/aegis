# SPEC-12 acceptance matrix (evidence-backed)

Date: 2026-10-25. Environment:
- build and test: WSL Ubuntu 22.04, Rust 1.97.1;
- gateway: MacBook Pro 2016 (Intel), macOS 12.7.6, Docker Desktop;
- client: Windows 11.

Evidence levels:
- **U**: unit or property test;
- **I**: in-process integration test (real TLS and sockets on loopback);
- **L**: live run on the Mac/Windows lab;
- **X**: verified against the real external service.

Gates, all passing in this run:
- `cargo clippy --workspace --all-targets -D warnings`;
- `cargo test --workspace`: 202 tests in 62 suites, 0 failures;
- `cargo audit --deny warnings`: 457 crates, no advisories.

| Exit criterion (§14.2) | Implementation | Evidence | Result | Remaining risk |
|---|---|---|---|---|
| **A-D1** SAN identity, registry authorization, legacy migration, renew/revoke/rotation | URI SAN `urn:aegis:node:v1`, fingerprint-bound registry, bounded legacy window; same-key self-renewal at the edge; issuer rotation from root (appliance) | `san_policy.rs` (4, U/I); `appliance_console_invite_enroll_tunnel_renew_revoke` (I); live revoke of a connected Windows GUI device (L) | Pass | Rotation with an *offline* root is CLI-only |
| **A-D2** AGP wire spec, golden vectors, negative/fuzz | `docs/protocol/AGP-1.0.md`, `agp-1.0-vectors.json`, strict codec | `golden.rs`, `roundtrip.rs` (U); 5 fuzz targets (not run in this session) | Pass (fuzz run outstanding) | Fuzz campaign duration |
| **A-D3** tunnel URL vs inner name, explicit DNS, no fallback, migration | typed `agp_tunnel` (`url`, `server_name`, new `outer_server_name` + pinned `outer_ca`), explicit resolver, `aegisctl config migrate` | `compile.rs` DNS-leak tests, `explicit_resolver_never_falls_back` (U); SOCKS hostname e2e across a TLS-terminating edge (I) | Pass | DoH/DoT not implemented (not claimed) |
| **A-D4** enrollment redeem, telemetry preview binding, local metrics auth | API routes kept; edge `/enroll` shares the implementation; consent bound to destination digest | `enrollment_redeem_is_one_use`, `tc_priv06_*`, `tc_a05_*` (I); live one-use replay rejection (L) | Pass | — |
| **B** Cloudflare Free: one plan + one apply, no click-ops, pinned connector, idempotent reapply, owned-only cleanup | Saga + Cloudflare adapter (shared); embedded host provisioner with supervised digest-checked `cloudflared`; console wizard | adapter mock contract tests (create/reuse/conflict/ambiguous/cleanup, I); connector digest verification inside the image (L, "available": true) | **Partly verified**: implemented, but not run against a live account | The owner's Cloudflare account is reachable, but creating DNS records needs explicit approval |
| **C** Local CA usable; ACME issues/renews/validates/reloads; inner auth retained | Appliance local PKI; instant-acme HTTP-01/DNS-01; SNI alternate on the edge | ACME via HTTP-01 against **Pebble 2.10.1** on the Mac: issued, validated, served for its SNI name while the private certificate stayed the default; disable reverted (L) | Pass (Pebble) | Let's Encrypt staging/production and DNS-01 were not run live |
| **D** Fresh Mac Docker install, controlled locally, no hand editing; Linux Compose/native | `deploy/install.sh` (Docker default, `--native` systemd), `Dockerfile.prebuilt`, `build-bundle.sh` | Mac: bundle → healthy gateway in 18.7 s, URL/password/fingerprint printed; in-place upgrade kept the data (L) | Mac Docker: pass. Linux native: **not tested** | Native unit hardening untested on a real distro |
| **D (Nginx)** optional adapter | existing Compose-path adapter (`aegis-provision::nginx`) | config unit test (U) | Unchanged; not exercised live | Not needed by the appliance (native TLS) |
| **E** SOCKS5 HTTP and HTTPS with remote DNS through the gateway; exit IP | client SOCKS5/HTTP; new plain-HTTP forwarding | Windows → Mac: SOCKS5h HTTPS 200 (0.20 s), HTTP 200; HTTP proxy GET 200; CONNECT TLS 1.3, egress `202.128.112.177`; 10 MB at ≈9.6 MB/s via the GUI client (L); pipelining isolation test (I) | Pass | — |
| **F** Security and consistency preserved | Remote console only with TLS + opt-in; HSTS; Origin = Host; edge routes only device paths; no new privileges | live CSP/HSTS/cross-origin 403/redirect checks (L); `public_management_and_open_proxy_rejected` (U); container: read-only, `cap-drop ALL`, uid 10001 | Pass (console exposure deliberately changed, see ADR-0007) | Password guessing against a LAN console (mitigated by rate limiting) |

## Spec deviations (documented)

- **UI.** SPEC-12 §11.3 deferred UI work. The owner later required a full web console and a GUI client; both are built, and ADR-0007 records the change.
- **Console exposure.** SPEC-12 §0.5/§10.3 forbade a non-loopback management listener. Per ADR-0007 the console is reachable on the LAN, **HTTPS-only** and opt-in by configuration, and the installer enables it. It is never published through Cloudflare.
