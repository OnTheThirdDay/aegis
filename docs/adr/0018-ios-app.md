# ADR-0018 — iOS app

Status: accepted (owner direction, 2026-10-30). In progress: it builds in CI; it has not run on an iPhone yet.

## Context

ADR-0011 planned iOS on the same Flutter UI and Rust core as Android. On iOS a VPN must run in a separate process, a Network Extension packet tunnel. The app and the extension share files only through an App Group container.

The owner has a paid Apple developer account (individual) and no Mac. Distribution to friends is Ad Hoc ([ADR-0019](0019-iphone-app-distribution.md)).

## Decision

**Two targets, one Rust core**

- **Runner (the app):**
  - The Flutter UI.
  - The `aegisborne/client` channel (`AegisChannel.swift`), with the same calls and JSON as on Android.
  - Joining, listing, selecting and removing servers call the Rust core directly on the App Group folder (`group.borne.aegis.app`, then `aegis/`).
- **AegisTunnel (the extension, `borne.aegis.app.tunnel`):**
  - `PacketTunnelProvider.swift` sets up the interface from the core's `vpn_config`: the same addresses, routes (everything but local networks), fake-IP DNS for every domain, and MTU as Android.
  - The core then runs the connection on it: renewal, the client node, the packet path.
  - The extension's own traffic to the gateway doesn't go through the tunnel, as excluding the app does on Android.
  - Its name lookups do, though: iOS resolves for it through the system resolver, which the tunnel's DNS settings send to the VPN's fake-IP DNS. So before applying the settings, the extension looks up the gateway's names (connection, enrollment and renewal, QUIC) through the normal network (`aegis_prepare_tunnel`), and the VPN's DNS answers those names with the real addresses, as the desktop VPN pins them. Without it the gateway's name resolved into the tunnel and the connection never came up (1.1.6).
  - iPhones sold in mainland China ask whether an app may use the network the first time it uses Apple's networking; the core's own sockets never ask and fail until it's allowed. The app makes one such request at launch, and a failed join points to the setting.
- **Connect and disconnect:** the app saves a `NETunnelProviderManager` configuration (iOS asks the user the first time) and starts or stops the tunnel.
- **Status:** while the tunnel runs, the app asks the extension with a provider message (`status`), which answers with the core's status JSON.
- **Unexpected stops:** when the core disconnects by itself (an expired certificate, a removed device), the extension ends the tunnel with that error, and the app shows it from `fetchLastDisconnectError`. That needs iOS 16, now the minimum.
- **Removing the connected server:** the app stops the tunnel first.

**The core on iOS**

- **C interface:** `ffi.rs` exposes the core to Swift as JSON strings in and out, with `aegis_free` for results. The header and module map are in `ios/AegisCore/include`.
  - `scripts/build-rust-ios.sh` builds a static library per target (`aarch64-apple-ios`, `aarch64-apple-ios-sim`) and packs them as `ios/AegisCore.xcframework`, which both targets link.
- **The tunnel's descriptor:**
  - iOS doesn't hand the packet tunnel's descriptor over.
  - The core finds the utun socket in its own process: the one that answers `UTUN_OPT_IFNAME` with a `utun` name.
  - utun puts a 4-byte address family in front of each packet, which `TunDevice::utun` removes and adds. Packets don't cross between Swift and Rust.
- **Memory:** iOS ends a packet tunnel that uses more than about 50 MB, so on iOS the client's buffer budgets are smaller:
  - process 16 MiB, peer 12 MiB;
  - stream 256 KiB, session window 4 MiB;
  - within the configuration rules, which a test checks.
- **Unsafe code:** the crate's unsafe boundary (ADR-0011) gains `ffi.rs` (exported C functions, strings from Swift) and the utun lookup (`getsockopt`), each item with a SAFETY comment.

**The Xcode project:** edited by a script rather than Xcode, since there's no Mac. It adds:
- the extension target, embedded in the app;
- its Info.plist;
- the entitlements on both targets: the `packet-tunnel-provider` network extension and the App Group;
- the xcframework and NetworkExtension, linked into both.

**Not on iOS yet:**
- sharing an invitation into the app (it needs a share extension; pasting works);
- app updates (Ad Hoc, ADR-0017);
- the move from the old Android app, which doesn't apply.

The channel answers these as not implemented, and the UI treats that as "nothing to show".

**CI:** a macOS job builds the Rust core for iOS and runs `flutter build ios --no-codesign` on every code push, so the app compiles and links without an Apple account.

## Consequences

- One UI and one core on Android and iOS. The iOS-specific code is two Swift files.
- **Signing (Ad Hoc):**
  - Release builds sign manually with an Apple Distribution certificate and an Ad Hoc profile per target ("AegisBorne Ad Hoc App" and "AegisBorne Ad Hoc Tunnel").
  - The release workflow recreates both profiles through the App Store Connect API on every build, so each build includes every registered iPhone, and exports `aegis-client-ios.ipa` (`ios/ExportOptions.plist`).
  - Debug builds keep automatic signing.
  - The secrets are listed in RELEASING.md.
- **Not yet verified**, all on a real iPhone:
  - the VPN connecting;
  - the extension staying under the memory limit during a large download;
  - DNS, UDP and switching networks.

  The simulator can't run packet tunnels.
