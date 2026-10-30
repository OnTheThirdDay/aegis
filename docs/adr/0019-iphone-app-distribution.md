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
- **Fetching:** every 10 minutes, and on demand, the gateway checks the latest release's asset. When it changed (a new release or a re-signed build), it downloads it, decrypts it and keeps it as `ios/app.ipa`. Fetching always runs in the background: the console never waits on GitHub, which can be slow or blocked, and calls to GitHub's API that the console does wait on (approving) give up after 20 seconds.
- **Ready to install:** after each fetch the gateway reads which iPhones the app installs on (the UDIDs in the provisioning profiles inside it, the app's and its extension's). An approved iPhone shows as **ready to install** once it's among them; until then it's **preparing**, and after 30 minutes **delayed** (the workflow likely failed). While an iPhone is preparing, the gateway checks GitHub every minute instead of every 10.
- **Through another gateway (optional):** a gateway that can't reach GitHub directly (GitHub's downloads are blocked in places, such as mainland China) reaches it through one of the owner's other gateways.
  - It joins that gateway as a device, with an invitation created there (pasted under **Reach GitHub through another gateway**).
  - Its GitHub requests then go through a built-in client: a local HTTP proxy into the tunnel, started when first needed. Nothing else of its traffic changes.
  - Its device identity there renews like any device's, and appears on that gateway's Devices page, where it can be revoked. **Stop using it** removes it from this side.
  - Friends' iPhones never contact GitHub either way: they reach only their gateway.
- **Requests:** users' iPhone requests, which the administrator approves (this starts the workflow) or removes. Up to 500 are kept; the same iPhone keeps one request.
- **Automatic approval (optional, per gateway):** an iPhone is approved as soon as it registers, while its user has fewer than N approved iPhones (2 unless set, 1–10). Beyond that, requests wait for the administrator. This guards the team's 100 iPhones a year against anyone who can sign in to the portal.

**The user portal (Devices → iPhone app; `handlers/ios.rs`)**

- **Register this iPhone:**
  - A registration profile (`register.mobileconfig`, Apple's "Profile Service") whose link carries a one-time token, tied to the user, valid 30 minutes.
  - iOS posts the iPhone's UDID, model, iOS version and name back to that link. The gateway reads them from the plist inside the signed post and records a request.
  - Safari returns to the portal, which shows the iPhone's progress: waiting for approval, preparing the app, ready to install. The card updates by itself every 30 seconds while the iPhone waits, and Install is the main button once it's ready.
- **Install:**
  - An `itms-services://` link to a manifest. iOS fetches the manifest and the app itself, without the user's session, so both links carry a token valid for an hour.
  - The links use the portal's public address, which needs a publicly trusted certificate (Cloudflare Tunnel or Let's Encrypt).
- **Older iPhones:** the portal's pages work in Safari on iOS 12 (the iPhone 6's last): a `replaceChildren` fallback, no `?.`, a clipboard fallback. Registering works there too; the app itself needs iOS 16.
- **Portal routes:** these are its only additions. The token-carrying routes need no session; everything else needs a signed-in user.

## Consequences

- **Adding a friend:**
  1. The friend presses Register in the portal.
  2. The administrator presses Approve in that gateway's console.
  3. Within minutes every gateway serves an app that installs on that iPhone. The friend's portal shows **ready to install**, and they press Install.
- **Removed or replaced iPhones** still use one of the 100 yearly slots until the membership year renews.
- **A gateway's GitHub token** can read the repository's releases and start its workflows. Anyone with the token could register an iPhone (using a slot), but not obtain the Apple key or certificate.
- **The app key decrypts the app and nothing else.** Rotating it means a new secret, a new release, and the new key on each gateway.
- **Tests:**
  - decryption of the workflow's format (a Python-made vector), with a wrong key refused;
  - reading the UDID from what iOS posts;
  - install link encoding;
  - UDID and repository validation.

  The `ios-device` workflow, `rcodesign`'s re-signing and installing on a real iPhone haven't run yet; they need the first signed release and a friend's iPhone.
