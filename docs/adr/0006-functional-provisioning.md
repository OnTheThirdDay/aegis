# ADR-0006 — SPEC-12 implementation boundaries

Status: implementation in progress; independent review pending. Date: 2026-10-25.

The existing Rust implementation has WS + inner TLS 1.3, bounded AGP,
SOCKS5/CONNECT, explicit resolver selection, SQLite activation and owner-local
management. It has no provider controller, native outer TLS listener or host
installer. Enrollment signs CSRs but admission checks only revocation; CN/OU
identities and telemetry shape-only consent need migration.

SPEC-12 supersedes ADR-0005's provisional identity/codec/provisioning choices.
Keep the handwritten AGP/1 layout and existing crate boundaries. New identity
issuance uses `urn:aegis:node:v1:<role>:<node-id>` plus legacy CN/OU and gateway
DNS SANs. Authorization binds active registry entries to certificate fingerprints.
The 0.1 profile remains readable; a versioned, explicit migration enables strict
registry/SAN policy. No routing rollback reverses revocation.

Three independent trust planes are public edge/direct TLS, connector-to-origin,
and device-to-gateway inner mTLS. Public certificates never authorize devices.
An offline root/restricted intermediate can issue identities without placing a
root key in the public gateway. Device keys are generated locally.

Provisioning is a SQLite-backed saga, not a distributed transaction. Persist
intent before each effect, reconcile unknown outcomes by owned IDs, and verify
the actual authenticated data path before ACTIVE. Keep provider tokens and host
authority outside the data plane. Host execution is a fixed local allowlist;
no Docker socket in gateway containers, shell snippets, or arbitrary commands.
Existing initialized stores are changed through revision activation, never seed
file edits. Remote resources require ownership evidence before update/deletion.

Native Rust outer TLS is preferred; Nginx is optional and never required for
Tunnel mode. Validate staged certificate/configuration replacements before
publication. A failed replacement preserves the previous valid state.

No UI redesign. CLI and local authenticated API share typed provisioning logic.
Default telemetry stays off. External provider and platform evidence is distinct
from local contract tests; the operator confirmed live credentials unavailable.
Track every SPEC-12 exit criterion in docs/SPEC12_ACCEPTANCE.md. Re-review on new
provider endpoints, parser dependencies, privilege grants or identity cutover.
