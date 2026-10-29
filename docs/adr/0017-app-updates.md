# ADR-0017 — App updates from the gateway

Status: accepted (owner direction, 2026-10-30).

## Context

Gateways upgrade from the console (ADR-0014). Until now the apps didn't update at all: users downloaded new builds from the console, the portal or GitHub.

Every component shares the workspace version, and a gateway image already carries the client builds of its own release (`/usr/share/aegisnet/clients`).

The Windows and macOS apps aren't signed by a certificate authority, so nothing on those systems checks where a replacement comes from. Android installs an update only over an app signed with the same key.

## Decision

**Offer, never install unasked (owner choice)**

- A connected app asks its server whether it has a newer build: after connecting, then every 6 hours. The phone app also asks when it opens or resumes, reusing the answer for 6 hours.
- If it has one, the app shows "AegisBorne X is available" with an **Update** button.
- Nothing is downloaded or installed until the user presses it.

**Signed by the release workflow**

- The `AEGIS_UPDATE_SIGNING_KEY` secret is an Ed25519 key that belongs to this project, not a certificate authority.
- When a release builds its image, `.github/scripts/sign-updates.sh` writes `FILE.update` next to each client build. It holds platform, version, file name, size and SHA-256, and a signature over the statement `aegisborne-update/1` followed by those fields, one `key=value` line each.
- The apps carry the public key (`RELEASE_KEY`, `aegis-join` `update.rs`). An app accepts an offer only when:
  - the signature verifies;
  - the platform is its own;
  - the version is newer than its own (a release sorts after its pre-releases).
- A hacked or misconfigured gateway can therefore offer only builds the release workflow signed, and never an older one.
- Staging images reuse the release's version number, so their builds are never signed or offered.
- A Rust test checks that OpenSSL's signatures (as CI makes them) verify in the app.

**Carried by the gateway**

- Devices ask on the device-authenticated `POST /renew` path, like the endpoint query: the certificate is checked, no rate limit is spent, and existing Cloudflare tunnel routes keep matching.
  - `update_query` returns the latest signed build for the device's platform, or null.
  - `update_download` returns 1 MiB of a signed build at an offset, as `application/octet-stream`. The edge hook now carries a content type.
- Only builds with a description are served, and only when the file's size matches it.
- The device writes pieces to `FILE.part` and resumes it. It compares the SHA-256 before the file takes its final name, and discards a mismatch.
- Descriptions aren't listed among the console's downloads.

**Installing, once the user asked**

- **Windows, Linux:**
  - The downloaded executable is copied next to the running one. The running one is renamed to `NAME.old`, which both systems allow, and the new one takes its name.
  - The app offers **Restart now**: it disconnects, restores system settings and starts the new executable.
  - `NAME.old` is removed at the next start, and the portable data folder stays.
  - A folder the user can't write gets a message pointing to the server's download page.
- **macOS:**
  - The disk image is attached read-only and its `AegisBorne.app` copied next to the running bundle, then swapped in.
  - A bundle still named `AegisNet.app` (ADR-0016) becomes `AegisBorne.app`.
  - Then **Restart now**, as on Windows and Linux.
- **Android:**
  - The Rust core downloads and checks the APK.
  - The app hands it to Android's package installer, as the move to AegisBorne does. The user allows installs from AegisBorne once, then confirms.
  - Android itself refuses an APK not signed with the release key.
  - The old app (AegisNet) never offers updates; it moves to AegisBorne instead.
- **The desktop VPN helper:** after an update the app shows **Update VPN helper** when the installed helper is older, as before.

**iOS (owner choice: Ad Hoc IPA, when the iOS app exists)**

- The platform name `ios` and the file name `aegis-client-ios.ipa` are reserved, and the signing script signs such a build.
- iOS installs Ad Hoc builds only through `itms-services://` with a manifest. The system downloads the IPA itself, over HTTPS with a publicly trusted certificate, and can't present a device certificate.
- So the iOS app will need a short-lived download link from the gateway. The gateway's edge needs a public certificate, which Cloudflare and ACME setups have; a private CA won't do.
- Each iPhone must also be registered in the Ad Hoc provisioning profile, and a new phone needs a new build.
- The iOS app checks the offer's signature and version exactly as the others do.

## Consequences

- Users update apps in one tap from the version their server runs, and nothing changes without their action.
- An update can't come from anyone but the release workflow, even through a compromised server. A leaked signing key is as serious as a leaked Android key. Replacing it needs app releases carrying the new public key, installed by hand once.
- A release that changes only the gateway still offers the apps its new version number. That's harmless: the same code with a new number.
- Tests:
  - signatures made by OpenSSL verify, and any changed field breaks them;
  - versions only move forward;
  - through a real gateway (`apps/aegisd/tests/appliance.rs`):
    - an offer not signed by the release key is ignored;
    - unsigned builds aren't served;
    - a partial download resumes;
    - a build that doesn't match its hash is discarded;
    - descriptions stay out of the download list;
  - the executable swap (Windows and Linux);
  - the phone's update card is shown only with an offer, installs only when pressed, and never appears in the old app.
- Verified on an Android 15 emulator against a local gateway:
  - an app signed with the release key was offered a newer build, signed with the real update key;
  - it downloaded the build in pieces and asked for install permission;
  - Android updated it in place, keeping its joined server and identity.
- **Not yet exercised:** a real release signed in CI and the desktop swap on a real Windows PC or Mac. The macOS code builds only in the release workflow.
