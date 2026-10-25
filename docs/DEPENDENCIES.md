# Dependency intake record (06 §1)

**Status: candidate set; nothing here is approved.** Section 06 requires each dependency to record:

- maintainer org and release verification;
- license;
- direct and transitive count;
- unsafe footprint;
- advisories and their disposition;
- feature flags;
- incident process;
- update owner;
- reason needed;
- alternatives considered;
- review date.

Only the columns that could be established while implementing are filled in below. Everything marked *pending* blocks a release until a reviewer completes it.

Exact versions are locked in `Cargo.lock`. Run `cargo deny check` and `cargo tree -e normal` to refresh counts.

| Crate (line) | Purpose | Features enabled | Alternatives considered | Review |
|---|---|---|---|---|
| tokio 1.54 (locked 1.54.1) | async runtime | net, io-util, time, sync, rt, macros, signal (per crate, minimal) | async-std (less maintained) | pending |
| rustls 0.23.46 + ring 0.17 | inner mTLS 1.3, outer TLS | `ring`, `std`, `logging`; no aws-lc (avoids cmake/nasm on Pi builds) | aws-lc-rs provider (FIPS path) | pending |
| tokio-rustls 0.26.4 | async TLS | `ring` | — | pending |
| rcgen 0.14 | local CA, CSR signing (via `Issuer` built from the stored CA cert) | crypto, pem, ring, x509-parser | openssl (C dependency) | pending |
| x509-parser 0.18 | peer CN/OU/validity extraction | default | webpki internals (not public API) | pending |
| rustls-pki-types 1.12+ | PEM parsing (`PemObject`) | `std` | rustls-pemfile (unmaintained, RUSTSEC-2025-0134; removed 2026-10-25) | pending |
| webpki-roots 1.0 | outer-TLS public roots | — | rustls-native-certs (host store varies) | pending |
| tokio-tungstenite 0.30 | WebSocket transport | `handshake` only; TLS done separately | hyper upgrade + custom framing | pending |
| hickory-resolver 0.26.1+ (locked 0.26.3) | explicit-nameserver DNS | `tokio`; hosts file disabled; no system-conf | getaddrinfo only (no explicit servers) | pending; 0.24 had RUSTSEC-2026-0119 (fixed by upgrade) |
| rusqlite 0.41 (bundled SQLite) | management store | `bundled` | sled/redb (WAL/SQL maturity) | pending; SQLite C provenance must be reviewed (OQ-05) |
| axum 0.8 / http 1 | local management API | http1, json, tokio, query | hyper directly | pending |
| argon2 0.5 | owner password hashing (Argon2id) | default | scrypt, bcrypt | pending |
| reqwest 0.12 | opt-in OTLP export only | rustls-tls-webpki-roots; https_only, no proxy, no redirects | hyper-util client | pending |
| serde / serde_json / toml 0.8 | typed config & API | toml `parse` only | — | pending |
| sha2, hex, base64, subtle, rand 0.8, uuid, time, ipnet, httparse, bytes, futures-util | utilities | minimal | — | pending |
| proptest (dev) | property tests | default | quickcheck | pending |
| libfuzzer-sys (fuzz only) | fuzzing | — | — | pending |

## First-party unsafe code

None. Every first-party crate declares `#![forbid(unsafe_code)]`, enforced by `cargo run -p xtask -- arch-check`.

## Advisory review — 2026-10-25

`cargo audit` 0.22.2 (advisory DB of 1,352 entries) was run against the workspace lockfile and `fuzz/Cargo.lock`.

| Finding | Before | Disposition |
|---|---|---|
| RUSTSEC-2026-0119: hickory-proto CPU exhaustion via O(n²) name compression | hickory 0.24.4 | **Fixed** by upgrading hickory-resolver to 0.26.x |
| RUSTSEC-2025-0134: rustls-pemfile unmaintained | 2.2.0 | **Removed**; PEM parsing moved to `rustls-pki-types` `PemObject` |

After the changes, `cargo audit --deny warnings` passes for both lockfiles: no vulnerabilities, no unmaintained or yanked crates. The CI job `audit` runs the same commands on every PR and push, and nightly so that newly published advisories are caught.

`tokio` and `rustls` were already on their latest releases (1.54.1 and 0.23.46), so no change was needed. Upgrades made as maintenance with no known advisory: tokio-tungstenite 0.24 → 0.30, x509-parser 0.16 → 0.18 (with rcgen 0.13 → 0.14), rusqlite 0.32 → 0.41 and webpki-roots 0.26 → 1.0.

## Known gaps

- `cargo deny` (licenses, bans, sources) has not been run in this environment.
- No SBOM, signatures or provenance are produced yet (G-002).
- **Duplicate versions:** the upgraded crates pull newer RustCrypto/rand lines transitively (sha2/digest 0.11, rand 0.10, base64 0.23) alongside the 0.10/0.8/0.22 lines that first-party code uses directly. Aligning first-party code to the newer lines would remove the duplicates. It is a follow-up because `rand` 0.10 changes its API.
- `toml` 0.8 remains pinned below the current 1.x line and needs a "stay or upgrade" decision.
