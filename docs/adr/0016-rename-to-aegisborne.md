# ADR-0016 — Rename to AegisBorne

Status: accepted (owner direction, 2026-10-29).

## Context

The product was called AegisNet, and its Android app had the ID `net.aegis.app`. The owner renamed both: everything people see becomes **AegisBorne**, and the phone app's ID becomes `borne.aegis.app` (also the iOS bundle ID).

Some names live on machines that are already installed, where changing them breaks something:

- A phone's identity sits in the old app's private storage. On Android a new app ID is a separate app, which can't read it.
- The desktop client keeps its data in a folder named after the product.
- The desktop VPN helpers have a named service, socket and folder.
- On a gateway, console upgrades are performed by the updater from the old image (`aegis-updater`, `clone_config`). It recreates the container with the old mounts and the old `AEGIS_*` environment, so a new image can't move its own data folder.

## Decision

**Renamed**

- Every user-facing text: the desktop client, admin console, user portal, both phone apps, installer messages and docs.
- The macOS app: `AegisBorne.app`, bundle ID `borne.aegis.client`.
- Downloaded file names (`aegisborne-web-ca.pem`, `aegisborne-device-root-key.pem`, `aegisborne-diagnostics*.otlp.json`), the API's problem type URI, and the HTTP user agent.
- The flutter channel (`aegisborne/client`).
- Names given to things created from now on: certificate subjects of new gateways and offline roots, and the two-factor issuer of new enrollments. Existing certificates and authenticator entries keep "AegisNet". This is cosmetic: nothing matches on these names.

**Renamed, with a move from the old name**

- **Desktop data:** `AegisNet-data` next to the executable, or `AegisNet` in the user's application data folder, is renamed to the AegisBorne name the first time the new client starts (only when the new folder doesn't exist yet).
- **Windows VPN helper:** now service `AegisBorneVPN`, pipe `aegisborne-vpn`, folder `%ProgramFiles%\AegisBorne`.
  - The app doesn't find the old helper under these names, so it offers **Install VPN helper**.
  - Installing (one administrator prompt) stops and deletes the old `AegisNetVPN` service and removes `%ProgramFiles%\AegisNet`.
  - The old helper's journal moves across first, so the new helper undoes any routes or DNS changes the old one left behind.
  - Like any update of the helper, this releases the kill switch. Its filter keys are unchanged, so the new code removes them.
- **macOS VPN helper:** now launch daemon `borne.aegis.vpn`, socket `/var/run/aegisborne-vpn.sock`, pf anchor `com.apple/aegisborne`. Installing works the same way: it unloads `net.aegisnet.vpn`, clears the old anchor, moves the journal and removes the old files.
- **Android:** one codebase, two Gradle flavors.
  - `borne` is AegisBorne (`borne.aegis.app`).
  - `legacy` is the last update of the old app ID (`net.aegis.app`, still named AegisNet). It carries the AegisBorne APK.
  - The legacy update asks the user to **Move to AegisBorne**. It installs the bundled APK with Android's package installer: the user allows "install unknown apps" once, then confirms the install.
  - On first start with no servers, AegisBorne takes every server (profile and identity, not per-connection state) from the old app through a content provider. It then offers to uninstall the old app, and the old app shows "Moved to AegisBorne". Since 1.1.8 the old app says so only once AegisBorne confirmed it keeps every server (a second provider call, `imported`): a failed import leaves the old app's servers and state as they were, and AegisBorne tries again when opened again. Uninstalling the old app deletes its copy of the identities, so it must not be offered before.
  - The phone keeps its device identities, so nothing is joined again and the console shows no new device.
- **Security of the hand-over**
  - The provider is guarded by a signature-level permission, `borne.aegis.app.permission.MIGRATE`. Only an app signed with our release key can hold it.
  - It also checks the caller's package name and signature.
  - AegisBorne checks that the provider belongs to `net.aegis.app` signed with the same key before using what it returns.
  - The identities move from one app's private storage to the other's and never leave the phone.
- **Release outputs:** the release workflow builds AegisBorne as `aegis-client-android-arm64.apk`. With the signing key present, it also builds the legacy update as `aegisnet-update-android-arm64.apk`, which installs over AegisNet only when signed with the same key. The gateway's download list labels it as the AegisNet update.

**Kept**

- The gateway's paths inside its container (`/var/lib/aegisnet`, `/etc/aegisnet`, `/usr/share/aegisnet`, `/run/secrets/aegisnet`) and its system user `aegisnet`. Upgrades keep the old mounts and environment (see Context), so renaming them would mean supporting both locations for good, with a gateway's data at stake. They are internal names, seen only by operators.
- The published command `docker run … cat /usr/share/aegisnet/install.sh` keeps working.
- Internal names that already say "Aegis": the crates, `aegisd`, `aegisctl`, the `ghcr.io/onthethirdday/aegis` image, AGP.
- Release file names (`aegis-client-*`).
- Cloudflare resources are marked `aegis:<id>`, so a gateway still recognises the tunnels and records it created.

## Consequences

- AegisNet phones move with two installs, the update and then AegisBorne from inside it, plus two confirmations, and keep their identities.
  - Verified on an Android 15 emulator with a phone joined under 0.1.1 (signed with the release key):
    - the update installed over it;
    - AegisBorne was installed from inside it;
    - AegisBorne imported the server and connected to the gateway as the same device;
    - the old app was uninstalled from AegisBorne.
  - A caller without the permission (the adb shell) was refused.
- A phone that installs AegisBorne without updating AegisNet first is told to install the AegisNet update, or can join with a new invitation.
- Desktop users install the VPN helper once more after updating.
- The legacy flavor and the import can be removed once AegisNet phones are gone.
