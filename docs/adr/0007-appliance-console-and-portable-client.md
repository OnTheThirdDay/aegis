# ADR-0007 — Appliance mode, HTTPS web console, built-in integrations, portable client

Status: accepted (owner direction, 2026-10-25). Supersedes parts of SPEC-12 as noted.

## Context

The owner asked for setup without CLI or file editing:

- one command installs the server (Docker or native; later narrowed to Docker only, with the installer shipped inside the public image so the repository can be private);
- the server generates a random admin password;
- the admin opens a browser at the server, signs in, changes the password and configures everything there, including Cloudflare and "plugins";
- end users get their own pages;
- the client is a portable GUI app.

SPEC-12 §0.2/§11.3 had deferred UI work and §0.5/§10.3 forbade a non-loopback management listener. The owner's later instruction takes precedence for these points; the security invariants of SPEC-12 §0.5 still apply.

## Decisions

1. **Appliance mode.** `aegisd --data-dir DIR` on an empty directory generates everything at first start:
   - **Device PKI:** a root plus a one-year, pathlen-0 online issuer.
   - **Web CA:** a *separate* CA for the console and edge certificates. Web certificates carry no node URI and cannot authenticate as a gateway; a test asserts this.
   - **Gateway inner identity.**
   - **Seed configuration:** a `0.2` seed with enrollment required and legacy identities off.
   - **Owner account:** `admin` with a random 115-bit password, flagged for a forced change.

   `config.toml` is written last. A `.aegis-init` marker makes a crashed initialization restartable, and initialization refuses foreign, non-empty directories. Certificate and key pairs are replaced crash-safely: generation-named files first, then an atomic manifest swap. A maintenance loop renews:
   - the gateway identity with 10 days left;
   - web certificates with 30 days left;
   - the issuer with 60 days left, while the root key is on the host (lab mode).
2. **One-time password handling.** The password is written once to `DIR/initial-admin-password` (0600). It is never logged: the daemon prints only a secret-free notice. The installer reads it with `aegisctl initial-password`. Until it is changed, the session's only scope is `self:password`. Changing it ends all of that principal's sessions and deletes the file.
3. **Remote console = HTTPS only.** A non-loopback `management.bind` requires `remote_access_enabled = true` **and** `management.tls`; configuration validation enforces this.
   - The console is served over rustls (TLS 1.2/1.3, no 0-RTT).
   - Handshakes run in bounded tasks with a 10 s deadline. Plaintext requests receive only a 308 redirect to HTTPS.
   - **Host and Origin rules differ by binding:**
     - remote console: any syntactically valid `Host` is accepted, but `Origin` must equal `https://<Host>`;
     - loopback console: the existing allowlist still applies, as protection against DNS rebinding.
   - HSTS is set. Cookies are `Secure; HttpOnly; SameSite=Strict`; mutations still require the CSRF header.
   - `--local-console` (`AEGIS_CONSOLE_LOOPBACK=1`) keeps the console on loopback only.
   - **The console is never published through Cloudflare:** tunnel ingress routes only the device paths and, since ADR-0010, the restricted user portal: `^/(agp|enroll|renew|portal(/.*)?)$`.
4. **Edge enrollment.** Devices enroll and renew through the public data-plane listener (`POST /enroll`, `POST /renew`), so the console need not be reachable from the internet.
   - Both endpoints share one implementation and one rate limiter with the API endpoint.
   - Bodies are bounded at 32 KiB; chunked bodies are accepted for proxies.
   - Renewal is **same-key**: the CSR must carry the enrolled public key. rcgen verifies the CSR signature, which proves possession of that key. Revoked or expired devices cannot renew.
5. **Invitation codes.** Codes have the form `aegis1:` + base64url JSON. They carry:
   - the endpoint;
   - the inner server name;
   - the SHA-256 pin of the device root;
   - for a private edge, the edge CA and the name it must present (`edge.aegis.internal`, the client option `outer_server_name`). With `outer_server_name`, the pinned CA is the only trust anchor; public roots are not consulted.
   - a one-use, name-bound token valid for 1–72 hours.

   No long-term secret is in the code. The device generates its key locally and verifies that the returned chain ends in the pinned root and carries its own key.
6. **Users.** A `user` role holds only `devices:self`: it can invite, list and revoke its own devices. Owners manage users with temporary passwords that must be changed at first sign-in. The last active owner can be neither demoted nor disabled.
7. **Built-in integrations instead of plugins.** No third-party code runs.
   - **Cloudflare Tunnel:**
     - It reuses the SPEC-12 saga and API adapter, with an *embedded* host provisioner.
     - The bundled `cloudflared` 2026.10.0 is digest-checked at image build and again before every start. It runs as a supervised child with `--token-file` (owner-only file) and its output discarded.
     - The API token is held in memory for one operation unless the owner opts to store it (owner-only file), which DNS-validated renewals need.
     - The tunnel origin is a container-loopback WebSocket inbound.
     - ACTIVE requires an end-to-end probe through the public hostname:
       - a registered probe identity crosses public DNS, the edge, the connector and inner mTLS;
       - a stream to `localhost:9` must be refused by gateway policy;
       - the operator's HTTP and HTTPS verification sites must load through SOCKS.
   - **ACME:** instant-acme 0.8.5 with ring, over our existing reqwest/rustls client (no extra TLS stack).
     - HTTP-01 uses a responder that listens only during an order.
     - DNS-01 uses AegisNet-labelled TXT records via Cloudflare, deleted by id afterwards.
     - The certificate is published as an **SNI alternate** on the edge. The private edge certificate stays the default, so already-enrolled devices keep working; a failed renewal keeps the valid certificate.
   - **OTel** remains the existing consent-bound exporter.
8. **HTTP forward proxy.** The client's HTTP inbound also forwards absolute-form `http://` requests, so an OS system proxy works for plain-HTTP sites.
   - The head is rebuilt from parsed fields, with `Connection: close` and proxy/hop-by-hop headers removed.
   - The body length must be exact; chunked uploads get 411.
   - After the declared body, client bytes are discarded, so a reused keep-alive connection can never send a second request to the first origin.
9. **Portable client.** `aegis-client` is an eframe/glow GUI: one executable, no installer, no admin rights.
   - **Data:** stored in `AegisNet-data` next to the exe, falling back to the app-data folder.
   - **Privacy:** no logs are written.
   - **Windows system proxy:** set via `reg.exe` with no console window. The previous values are saved and restored on disconnect, on exit, and at the next start after a crash.
   - **Shared code:** the GUI and `aegisctl join/connect/renew` share `aegis-join`.

## Consequences and limits

- **Exposed console.** The console listens on the LAN by default; the residual risk is password guessing. Mitigations: Argon2id hashing, per-user lockout and a global rate limit, and the forced password change.
  - The console certificate is self-issued, so the browser warns until the web CA is installed or replaced. The installer prints the SHA-256 fingerprint for out-of-band checking.
- **Root key custody.** The device root key starts on the appliance host, so the issuer renews by itself.
  - The owner can take it offline from the console (Account → Device certificate authority). Export needs the password again; removal needs the key file back as proof.
  - With the root key offline, the issuer is renewed in the console with the key file. The key is used in memory and not stored. The console warns 60 days before expiry.
  - All steps are audited (`pki.root_key_exported`, `pki.root_key_removed`, `pki.issuer_renewed`, `pki.root_key_restored`).
- **Platforms.** The GUI client is built for Windows (cross-compiled with mingw) and Linux. macOS needs a native build. The Windows system-proxy toggle is implemented but has not been exercised on a real desktop.
- **Cloudflare evidence.**
  - Adapter: mock contract tests only.
  - Embedded live flow: not yet run against a real account. The account owner must authorize DNS changes.
