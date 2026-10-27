# ADR-0010 — User portal on the public edge

Status: accepted (owner direction, 2026-10-26).

## Context

Recommended public installs (`--tunnel-only`) keep the console on the server's loopback interface, reachable only through SSH. End users with the `user` role could then not sign in at all. They could not invite or remove their own devices, and with a private repository they could not download the client app either.

## Decision

The self-service part of the console is served on the gateway's public edge at `/portal/`, the same address devices use (`/agp`, `/enroll`, `/renew`). With Cloudflare Tunnel it is reached through the tunnel, so nothing new is opened on the server.

The administrator may set the public port in the portal's address (owner direction, 2026-10-27). The portal stays on the device listener; only the address changes. This fits port forwarding, and Cloudflare's other HTTPS ports (2053, 2083, 2087, 2096, 8443). With Cloudflare, a port outside that list is refused.

The device port with Cloudflare Tunnel can also be any of those ports, not just 443; the hostname stays the integration's. Enrolled devices adopt the new address through endpoint following, which verifies the gateway's pinned identity there first. The portal address follows the device port unless set separately. A retried setup keeps the chosen port.

**Restrictions**

- **Allowlist.** Only these routes exist on the portal; everything else answers 404, whatever the session:
  - the pages;
  - sign-in, sign-out, the current session and password change;
  - the user's devices: list, invite, revoke;
  - client downloads.
- **Administrators only with 2FA.** An account with any role beyond `user` can sign in only with two-factor authentication. Without it, sign-in is refused after the password check, so the portal does not reveal which accounts are administrators; refusals are audited. A session opened with a second factor gets the **whole console** on the portal (owner decision, 2026-10-26), so SSH is optional. The exception is exporting the device root key, which stays local-only. The allowlist above applies to everyone else.
- **Two-factor authentication** (TOTP, RFC 6238: HMAC-SHA1, 6 digits, 30 s, ±1 step):
  - Set up under Account by scanning a QR code, then confirmed with a code. It is optional on the local console, but once on, every sign-in asks for a code.
  - Each code works once (the last used time step is recorded).
  - Ten single-use recovery codes are stored as hashes.
  - The shared secret is kept in the secret directory, never in the database.
  - Owners can reset a lost authenticator for an account; that ends its sessions.
  - Code failures count against the same sign-in limits as passwords.
- **Browser sessions only.** `Authorization` headers (API tokens) are refused. Sessions are the usual `Secure; HttpOnly; SameSite=Strict` cookies with CSRF tokens.
- **Host and origin.** The `Host` must be the gateway's public device address, and cross-origin requests are refused.
- **Separate sign-in limits.** Portal sign-in has its own rate limiter (global and per user), so traffic on the portal can never lock an administrator out of the console.

**Serving**

- **Connection handling.** The edge reads the first request line. A `/portal` path hands the whole connection to the portal: outside the tunnel-handshake deadline, holding no handshake slot.
- **One request per connection.** The edge routes a connection by its first request, so a portal connection closes after its response. Otherwise a proxy that pools connections (cloudflared) could send a device's `/renew` or `/agp` on it and get the portal's 404.
- **Limits.** At most 64 concurrent portal connections; a request head must arrive within 20 s.
- **Switch.** On by default; owners can switch it off on the Users page (`PUT /api/v1/system/portal`, audited).

**Cloudflare routes**

- New tunnels route `^/(agp|enroll|renew|portal(/.*)?)$`.
- A tunnel whose routes are exactly AegisNet's earlier set is recognised as its own: setup and re-verification update it, rather than reporting drift. Anything else is still drift.
- Existing active tunnels are updated when re-verified with the token; the console offers **Update routes for the user portal**.

## Consequences

- Users have a browser self-service path behind `--tunnel-only`, and the client app is downloadable without GitHub.
- The admin console stays private, and an administrator session or token is never accepted on the public path.
- The portal adds a public sign-in surface. It is limited to user accounts and bounded, and it can be switched off. For stricter setups, Cloudflare Access can be placed in front of the `/portal` path in the Cloudflare dashboard.
