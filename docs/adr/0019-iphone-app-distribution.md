# ADR-0019 — Distributing the iPhone app (Ad Hoc, several gateways)

Status: accepted (owner direction, 2026-10-30).

## Context

The iPhone app (ADR-0018) goes to the owner's friends as an Ad Hoc build: it installs only on iPhones registered on the Apple team (up to 100 a year), whose UDIDs its provisioning profile lists. The owner runs several gateways, all with the same Apple team, so one signed app per version serves every gateway.

Without help, adding a friend meant reading the UDID with a third-party site, registering it by hand, rebuilding, and sending a file that iOS won't install from a chat or Safari anyway. iOS installs Ad Hoc apps only through an `itms-services://` link to a manifest, over HTTPS with a publicly trusted certificate.

## Decision

**One signed app for all gateways, published encrypted**

- The release workflow builds the app and publishes it only as `aegis-client-ios.ipa.enc` on the GitHub release.
- The format is AES-256-GCM: `AEGISIPA1`, a 12-byte nonce, then ciphertext and tag, with `aegisborne-ipa/1` as associated data. The key is `AEGIS_IOS_APP_KEY`.
- The profile inside an Ad Hoc build lists every registered UDID. Encrypted, the friends' device identifiers stay private even while the repository is public; only gateways given the key can read the app.
- The release's iOS job needs the key and never publishes the plain build.

**Adding an iPhone re-signs; it doesn't rebuild**

- The `ios-device` workflow, started by a gateway (repository dispatch) or by hand:
  1. registers the iPhone through the App Store Connect API;
  2. downloads the latest release's app and decrypts it;
  3. swaps in fresh Ad Hoc profiles for the app and its tunnel, listing every registered iPhone;
  4. re-signs it with `rcodesign` (pinned, on Linux, nested code first, entitlements kept), then encrypts it and replaces the release asset.
- It takes about a minute. The Apple key and the signing certificate stay in GitHub secrets, never on a gateway.

**Each gateway (`integrations/ios.rs`, console: Integrations → iPhone app)**

- **Settings:** the repository, a GitHub token (fine-grained, that repository only, Contents read and write) and the app key. The token and key go in the gateway's secret store.
- **Fetching:** every 10 minutes, and on demand, the gateway checks the latest release's asset. When it changed (a new release or a re-signed build), it downloads it, decrypts it and keeps it as `ios/app.ipa`.
- **Requests:** users' iPhone requests, which the administrator approves (this starts the workflow) or removes. Up to 500 are kept; the same iPhone keeps one request.

**The user portal (Devices → iPhone app; `handlers/ios.rs`)**

- **Register this iPhone:**
  - A registration profile (`register.mobileconfig`, Apple's "Profile Service") whose link carries a one-time token, tied to the user, valid 30 minutes.
  - iOS posts the iPhone's UDID, model, iOS version and name back to that link. The gateway reads them from the plist inside the signed post and records a request.
  - Safari returns to the portal, which says the request is waiting for approval.
- **Install:**
  - An `itms-services://` link to a manifest. iOS fetches the manifest and the app itself, without the user's session, so both links carry a token valid for an hour.
  - The links use the portal's public address, which needs a publicly trusted certificate (Cloudflare Tunnel or Let's Encrypt).
- **Portal routes:** these are its only additions. The token-carrying routes need no session; everything else needs a signed-in user.

## Consequences

- **Adding a friend:**
  1. The friend presses Register in the portal.
  2. The administrator presses Approve in that gateway's console.
  3. Within minutes every gateway serves an app that installs on that iPhone, and the friend presses Install.
- **Removed or replaced iPhones** still use one of the 100 yearly slots until the membership year renews.
- **A gateway's GitHub token** can read the repository's releases and start its workflows. Anyone with the token could register an iPhone (using a slot), but not obtain the Apple key or certificate.
- **The app key decrypts the app and nothing else.** Rotating it means a new secret, a new release, and the new key on each gateway.
- **Tests:**
  - decryption of the workflow's format (a Python-made vector), with a wrong key refused;
  - reading the UDID from what iOS posts;
  - install link encoding;
  - UDID and repository validation.

  The `ios-device` workflow, `rcodesign`'s re-signing and installing on a real iPhone haven't run yet; they need the first signed release and a friend's iPhone.
