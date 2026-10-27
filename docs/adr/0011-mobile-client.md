# ADR-0011 — Mobile client (Android first)

Status: accepted (owner direction, 2026-10-27).

## Context

Users want the gateway on their phones. A local proxy, as on desktop, is of little use there: most apps ignore proxy settings. A phone client must capture traffic as a VPN.

## Decision

**Stack**

- **Flutter UI, shared by Android and iOS** (owner choice). It covers joining, connecting, status and removing the server.
- **A Rust core** (`crates/aegis-mobile`) reuses the desktop client: `aegis-join` for enrollment, renewal and following address changes, and the client node for the local SOCKS proxy and the AGP tunnel. The app calls it through a small JSON-in/JSON-out API.
- **Platform glue:**
  - On Android, a Kotlin `VpnService` and `MainActivity` that serves the Flutter method channel `aegisnet/client`. Kotlin calls the core over JNI.
  - On iOS (later), a Swift packet tunnel calls the same core through a C ABI.

**Packet path (VPN mode, owner choice)**

- The VPN interface's descriptor goes to the core, where a userspace TCP/IP stack (`ipstack`) terminates connections.
- **TCP** is opened through the client node's local SOCKS proxy. Each connection then takes exactly the desktop data path: mutual TLS, AGP and gateway policy.
- **DNS is fake-IP.** Every `A` query (UDP port 53, whatever server an app asks) is answered from 198.18.0.0/15, and a connection to one of those addresses is opened *by name*. The gateway therefore resolves every name, as `remote_required` demands. `AAAA`, HTTPS/SVCB and other record types get an empty answer, which keeps apps on IPv4.
- **Other UDP and ICMP are dropped.** AGP carries TCP only. Browsers fall back from QUIC to TCP; calls, games and DNS-over-QUIC don't work until UDP support lands.
- **Routes:**
  - All public IPv4 goes through the VPN, plus IPv6 global unicast (2000::/3) so that IPv6 literals can't leak.
  - Local ranges stay direct: RFC 1918, link-local, CGNAT 100.64/10, loopback and multicast. The routes are computed as a complement, because `excludeRoute` needs API 33.
  - The app excludes itself from the VPN, so its own connection to the gateway goes direct.
- **Renewal** works as on desktop. The core checks every 6 hours and reloads the certificate without dropping sessions; grace renewal (ADR-0007) applies.

**Android specifics**

- Application ID `net.aegis.app` (owner choice; also the iOS bundle ID); minSdk 26 (Android 8).
- Builds for arm64-v8a (phones) and x86_64 (emulator); NDK r28 links with 16 KB page alignment.
- Foreground service type `systemExempted` (VPN apps); always-on VPN is supported.
- Invitations can be pasted or shared to the app from another app.

**Several servers (desktop and phone)**

- A device can join several servers and connects to one at a time. Android runs a single VPN per app, and one proxy keeps desktop settings simple.
- `aegis_join::Servers` keeps one profile per server under `servers/<id>/`, plus the selected id. The id hashes the gateway's device CA and the device name, so joining the same server under the same name twice is refused.
- A profile from the single-server layout moves into the list unchanged the first time the app starts.
- Switching servers while connected disconnects and connects to the new one. Removing the connected server disconnects first.

**Distribution (owner choice: sideload)**

- The release workflow builds `aegis-client-android-arm64.apk`. It ships in the GitHub release and in the image's downloads, offered under **Devices → Client apps** and on the user portal with the APK media type.
- Release APKs are signed with a key kept in repository secrets (see RELEASING.md). Without it, a build is signed with a throwaway key and later builds won't install over it.
- Google Play can come later. It needs its own VPN declarations and review.

**Unsafe code**

- The workspace forbids unsafe code. The mobile crate is the one exception, recorded in `xtask` (`UNSAFE_BOUNDARY`): JNI exports need `#[no_mangle]`, and the VPN descriptor needs `from_raw_fd` and `fcntl`.
- The crate denies unsafe code and allows it per item in `fd.rs` and `android.rs` only, each with a SAFETY comment.

## Consequences

- Phones get a real VPN with the gateway's identity pinning, policy and renewal unchanged. The packet path is new code, covered by host unit tests: fake DNS, routes and the SOCKS hop. End to end it was verified on an Android 15 emulator with 16 KB pages: enrollment, VPN consent, `nc` and Chrome (HTTPS) through a local gateway, and disconnect.
- UDP applications don't work through the VPN yet.
- iOS needs a Network Extension target (packet tunnel) and an Apple developer account for signing. The Rust core and Flutter UI carry over.
