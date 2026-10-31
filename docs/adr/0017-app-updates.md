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
- **Phones (1.1.8):** the answer to an update check is reused for 15 minutes, for the server that gave it only; a download comes from the server that offered it.
- **Desktop (1.1.8):** downloading and installing runs as a task of its own, so Disconnect and Shutdown are handled meanwhile; shutting down cancels it.

**Unchanged apps keep their build (1.1.9, owner direction)**

- Apps compare version numbers, and every release gives every build a new one. So a release that changed only the gateway or one app used to offer every device the same app again under a new number. Android users downloaded it for nothing.
- Now the release workflow's `plan` job compares each app's build inputs with the previous release (`.github/scripts/unchanged-apps.py`). The inputs are:
  - the app's workspace crates and every workspace crate they depend on, and files their sources include;
  - `Cargo.toml`, `Cargo.lock` and `rust-toolchain.toml`, with the workspace version left out;
  - the app's job in `release.yml`, without scheduling lines and comments;
  - the app's other sources: `apps/aegis-mobile` except `ios/` for Android, and `macos-dmg.sh` for macOS.
- An app with the same inputs, whose builds the previous release has, isn't rebuilt. Its files are carried into the new release and image and signed as the version they are. Android, desktop (Linux and Windows together) and macOS are decided separately.
- Each release lists every file's version in a `BUILDS` asset, so a build carried twice keeps its first version. Releases before 1.1.9 have no `BUILDS`; their files are their own version.
- The release notes name the carried apps.
- iOS is always rebuilt. Gateways up to 1.1.8 label the iPhone app with the release's version, not the app's, so a carried app would be offered again and again.
- Counting too much only rebuilds an app. Anything that changes a build must be among the inputs: a build step outside the app's job, for example, would be missed.

**iOS (owner choice: Ad Hoc IPA, when the iOS app exists)**

- The platform name `ios` and the file name `aegis-client-ios.ipa` are reserved, and the signing script signs such a build.
- iOS installs Ad Hoc builds only through `itms-services://` with a manifest. The system downloads the IPA itself, over HTTPS with a publicly trusted certificate, and can't present a device certificate.
- So the iOS app will need a short-lived download link from the gateway. The gateway's edge needs a public certificate, which Cloudflare and ACME setups have; a private CA won't do.
- Each iPhone must also be registered in the Ad Hoc provisioning profile, and a new phone needs a new build.
- As built (1.1.5, ADR-0019): there is no signed `.update` description for iOS. iOS verifies Apple's signature itself, and the build is the one every gateway fetches for the iPhone app integration. The gateway answers the iPhone's `update_query` with that app's version and a device-bound install link; the app checks the version is newer and the link is an `itms-services` manifest over HTTPS. Since 1.1.8 the link is given only to a request signed with the device key (`ios_offer_message`): a device certificate is not secret, and the link downloads the app. Apps up to 1.1.7 don't sign, so they install 1.1.8 from the portal.

## Consequences

- Users update apps in one tap from the version their server runs, and nothing changes without their action.
- An update can't come from anyone but the release workflow, even through a compromised server. A leaked signing key is as serious as a leaked Android key. Replacing it needs app releases carrying the new public key, installed by hand once.
- A release offers an app only when its build inputs changed (1.1.9). A carried app reports its own, older version, for example in its about screen, while the gateway runs the new one.
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
