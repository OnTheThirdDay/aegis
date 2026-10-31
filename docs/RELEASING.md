# Branches, releases and installs

## Branch flow

```
work branch ──PR──► staging ──release PR──► main
     ┊                 ┊                       │
     ┊ (manual)        ┊ (manual)              ▼ (automatic, new version only)
     ▼                 ▼                       tag vX.Y.Z + GitHub Release
  :test-<branch>    :staging                   + ghcr.io/onthethirdday/aegis:X.Y.Z / :latest
```

Test images are built only when you ask for one: a full build takes about 30 minutes and uses Actions minutes, so merging doesn't build anything by itself.

**Making a change:**

1. Create a branch, for example `feature/x` or `fix/y`, commit and push. CI runs (one check job), and a pull request into `staging` opens automatically.
2. Merge it into `staging`. CI checks it again. Several changes can collect on `staging` before you test.
3. **To test on a server:** run **Actions → Release → Run workflow**, choose the `staging` branch, and wait for the run to finish. It publishes `ghcr.io/onthethirdday/aegis:staging`. Install it on a test gateway with the installer from that image:
   ```sh
   docker run --rm --pull always --entrypoint cat \
     ghcr.io/onthethirdday/aegis:staging /usr/share/aegisnet/install.sh > install.sh
   sudo sh install.sh --name aegis-test
   ```
   The same run on a work branch builds `:test-<branch>` (for example `:test-feature-x`) instead, to try a change before merging it.
4. Once `staging` passes CI, a **Release to main** pull request opens, or is updated if one is already open.
5. Merge it with **Create a merge commit**.

**Publishing a release:** run **Actions → Version bump → Run workflow**, choosing patch, minor or major, or typing an exact version.

1. The workflow commits the new version on `release/vX.Y.Z` and opens a pull request into `staging`.
2. Merge it, then merge the release pull request into `main`.
3. `release.yml` sees an untagged version on `main` and does the rest:
   - creates tag `vX.Y.Z`;
   - builds the gateway for amd64 and arm64, plus the client apps for Windows, macOS (arm64 and x86_64), Linux, Android and iPhone;
   - carries an app unchanged since the previous release instead of rebuilding it, so devices aren't offered it again (ADR-0017). The release notes name the carried apps, and the `BUILDS` asset gives each file's version;
   - pushes the multi-arch image (with build provenance and an SBOM);
   - publishes the GitHub Release.

   Versions are never edited by hand on `main`. Merging to `main` without a version bump updates `main` but publishes nothing.

## Workflows

| Workflow | Trigger | Does |
|---|---|---|
| [ci.yml](../.github/workflows/ci.yml) `check` | code pushes to any branch except `main` | one cached Linux job: fmt, clippy, architecture rules, tests and a Windows compile check; on `staging` also cargo-deny and cargo-audit |
| ci.yml `weekly` | Sundays, or manual (choose seconds per fuzz target) | fuzz targets (3 minutes each) and the large property-test budget |
| ci.yml `branch-policy` | pull requests into `main` | fails if the pull request doesn't come from `staging` |
| [pull-requests.yml](../.github/workflows/pull-requests.yml) | branch pushes, and successful `ci` runs on `staging` | opens the pull request into `staging` and the release pull request into `main` |
| [version.yml](../.github/workflows/version.yml) | manual | version bump: `release/vX.Y.Z` branch plus a pull request into `staging` |
| [release.yml](../.github/workflows/release.yml) | push to `main`; manual runs | on `main` with a new version: tag, image with all clients including macOS, and GitHub Release. Manual run on `staging`: the `:staging` test image; on a work branch: `:test-<branch>` (Linux and Windows clients) |
| release.yml main gate (in `plan`) | push to `main` | fails unless `main`'s exact file tree already exists as a commit on `staging` |
| release.yml `sync-staging` | push to `main` | fast-forwards `staging` to `main` after a release |

**Actions minutes.** The repository is private, so CI uses the free plan's 2,000 minutes a month. Windows minutes count double, macOS minutes 10×, and every job rounds up to whole minutes. The workflows are sized for that:

| Event | Runs | About |
|---|---|---|
| Push to a work branch that changes code | `check` | 10 minutes (20 with a cold cache) |
| Push that only changes documentation (`*.md`, `docs/`) | nothing (just opening the pull request) | 1 minute |
| Merge into `staging` | `check` with dependency gates | 12 minutes |
| Test image (manual run on `staging` or a branch) | Linux builds, Windows client, image | 25 minutes |
| Release to `main` | Linux builds, macOS clients (one job, 10×), image, GitHub Release | 200 minutes, mostly macOS |
| Weekly fuzzing | `weekly` | 25 minutes |

Every job has a time limit (5 to 60 minutes), so a hang fails quickly instead of running for GitHub's default 6 hours. Usage so far: Settings → Billing and plans → Usage.

macOS is compiled only for releases (one universal `AegisBorne.app` in `aegis-client-macos.dmg`, `.github/scripts/macos-dmg.sh`), so a macOS-only build problem shows up when releasing (the release then fails before anything is published). Every push does lint the system VPN helper (`aegis-vpn`) for macOS and Windows, since it is pure Rust; to check the whole client earlier, run `cargo check -p aegis-client` on a Mac.

**Quirks to know:**

- Pushes and pull requests made with `GITHUB_TOKEN` don't trigger other workflows. That's why `PR_TOKEN` exists, and why the `sync-staging` push doesn't republish staging.
- `workflow_run` triggers, which open the release pull request, only work from the copy of the workflow on `main`.

## One-time repository setup

- **Secret `PR_TOKEN`:** a fine-grained personal access token for this repository only, with:
  - **Contents: Read and write**, so version-bump branches run CI;
  - **Pull requests: Read and write**.

  Without it the built-in token is used. Then turn on Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests", and approve CI on bot pull requests by hand. Note the expiry date somewhere.
- **Image package:** after the first publish, go to Packages → `aegis` → Package settings → change visibility to **Public**. Servers can then pull it, and the installer inside it, without `docker login`. This works while the repository itself is private. If the package stays private, run `docker login ghcr.io` on each server.
- **Android signing key:** phones install an update only over an APK signed with the same key, so create the key once and keep a backup outside GitHub. If it's lost, every phone must uninstall and join again.

  ```sh
  openssl rand -base64 24 | tr -d '\r\n' > password.txt
  openssl req -x509 -newkey rsa:4096 -sha256 -days 10950 -nodes \
    -keyout key.pem -out cert.pem -subj "/CN=AegisBorne"
  openssl pkcs12 -export -inkey key.pem -in cert.pem -name aegis \
    -out aegis-android.p12 -passout file:password.txt
  rm key.pem
  base64 -w0 aegis-android.p12   # paste the output into AEGIS_ANDROID_KEYSTORE_B64
  ```

  Add these repository secrets: `AEGIS_ANDROID_KEYSTORE_B64`, `AEGIS_ANDROID_KEY_ALIAS` (`aegis`), and the contents of `password.txt` as both `AEGIS_ANDROID_KEYSTORE_PASSWORD` and `AEGIS_ANDROID_KEY_PASSWORD` (a PKCS#12 file has one password). Without them, builds still succeed but warn: each APK is signed with a throwaway key and won't install over the previous one.

  With the key, a release also builds `aegisnet-update-android-arm64.apk`: the last update of the old Android app (AegisNet, `net.aegis.app`). It installs over AegisNet, carries AegisBorne and moves the phone's servers to it ([ADR-0016](adr/0016-rename-to-aegisborne.md)). Without the key it is skipped, since it couldn't install over AegisNet.
- **Update-signing key:** releases sign their client builds so the apps accept them as updates from a gateway ([ADR-0017](adr/0017-app-updates.md)). The apps carry the public key (`RELEASE_KEY` in `crates/aegis-join/src/update.rs`); keep the private key with a backup outside GitHub. If it's lost, a new key needs app releases carrying its public key, installed by hand once.

  ```sh
  openssl genpkey -algorithm ed25519 -out update-signing-key.pem
  openssl pkey -in update-signing-key.pem -pubout -outform DER | tail -c 32 | base64   # RELEASE_KEY
  ```

  Add the repository secret `AEGIS_UPDATE_SIGNING_KEY` with the contents of `update-signing-key.pem`. Without it, releases still build but warn, and their apps aren't offered as updates.
- **iOS (Ad Hoc, ADR-0018):** an Apple Developer Program team (`2ANDRZ4DY3`, in the Xcode project and `ios/ExportOptions.plist`) with:
  - the App IDs `borne.aegis.app` and `borne.aegis.app.tunnel`, both with Network Extensions and App Groups (`group.borne.aegis.app`);
  - an App Store Connect API key with the Admin role;
  - an Apple Distribution certificate (made through that key; its private key never leaves the machine that made it);
  - at least one registered iPhone.

  Repository secrets:

  | Secret | Value |
  |---|---|
  | `APPLE_API_KEY_ID` | the key's id |
  | `APPLE_API_ISSUER_ID` | the issuer id (App Store Connect → Users and Access → Integrations) |
  | `APPLE_API_KEY_P8` | the contents of `AuthKey_<id>.p8` |
  | `APPLE_DIST_P12_B64` | `base64 -w0 distribution.p12` |
  | `APPLE_DIST_P12_PASSWORD` | the `.p12` password |
  | `AEGIS_IOS_APP_KEY` | 32 random bytes, base64 (`head -c 32 /dev/urandom \| base64`): the app is published only encrypted with it ([ADR-0019](adr/0019-iphone-app-distribution.md)) |

  Each build makes fresh Ad Hoc profiles (`.github/scripts/ios-profiles.py`) listing every registered iPhone, and the release's `aegis-client-ios.ipa` installs on those only. Register a friend's iPhone with its UDID (on the iPhone, Safari → udid.tech) in the developer portal (Devices → +) or with the same key: `ios-profiles.py add-device NAME UDID`. The next build includes it. Without the secrets, or with no iPhone registered, the iOS job reports why and the rest of the release goes ahead.

  Friends' iPhones are normally added from the gateways ([ADR-0019](adr/0019-iphone-app-distribution.md)): in each gateway's console, **Integrations → iPhone app**, enter the repository, a fine-grained GitHub token for this repository only (Contents: read and write) and the `AEGIS_IOS_APP_KEY`. Users then press **Register this iPhone** in the portal, you approve it in the console, and the `ios-device` workflow registers the iPhone and re-signs the current app; every gateway fetches it within 10 minutes. The same workflow can be run by hand (Actions → iOS device) with a name and UDID.
- **Local hook:** run `git config core.hooksPath .githooks` once per clone. It blocks direct pushes to `main` and `staging`; `--no-verify` overrides it deliberately.
- **Branch protection:** rulesets need a paid plan for private repositories. Until then, the main gate in release.yml, `branch-policy` and the hook enforce the flow. With rulesets available:
  - **`main`:** block force pushes and deletion; require a pull request with merge commits only; require the `branch-policy` check.
  - **`staging`:** the same, requiring the `check` job.

## Installing a release (servers)

Servers need only the public image; the repository can stay private. Each image carries `install.sh`, stamped with its own tag:

```sh
docker run --rm --pull always --entrypoint cat \
  ghcr.io/onthethirdday/aegis /usr/share/aegisnet/install.sh > install.sh
sudo sh install.sh            # add --tunnel-only on a public server
```

- **Which image it installs:** the copy from `:latest` or `:X.Y.Z` installs that release; the copy from `:staging` installs `:staging`.
  - `--version vX.Y.Z` selects another release.
  - `--image REF` runs any image.
- **Provenance:** the image carries buildx provenance and an SBOM (`docker buildx imagetools inspect ghcr.io/onthethirdday/aegis:X.Y.Z --format '{{json .Provenance}}'`). GitHub artifact attestations are not used, because they need a public repository on the free plan.
- **Upgrading:** fetch `install.sh` again as above and run it (with `--name` if used). Data and settings are kept; settings are read back from the running instance.
- **The GitHub Release** (visible to repository members) holds the client apps and `SHA256SUMS`. The apps are also in the image, served by the console under Devices → Client apps.
- **Offline or development installs** without the registry:
  ```sh
  sh deploy/build-bundle.sh DIR
  sudo sh DIR/aegisborne-gateway/install.sh --from DIR/aegisborne-gateway
  ```

The full server guide (first-time setup, servers that already run nginx or v2ray, console access on a public server, upgrades) is [INSTALL.md](INSTALL.md).
