# Branches, releases and installs

## Branch flow

```
work branch ──PR──► staging ──release PR──► main
                       │                       │
                       ▼                       ▼
        ghcr.io/onthethirdday/aegis:staging    tag vX.Y.Z + GitHub Release
                                               + ghcr.io/onthethirdday/aegis:X.Y.Z / :latest
```

**Making a change:**

1. Create a branch, for example `feature/x` or `fix/y`, commit and push. CI runs, and a pull request into `staging` opens automatically.
2. Merge it into `staging`. CI runs again and the staging image is published.
3. Test the staging image on a lab gateway:
   ```sh
   sudo sh install.sh --image ghcr.io/onthethirdday/aegis:staging
   ```
4. Once `staging` passes CI, a **Release to main** pull request opens, or is updated if one is already open.
5. Merge it with **Create a merge commit**.

**Publishing a release:** run **Actions → Version bump → Run workflow**, choosing patch, minor or major, or typing an exact version.

1. The workflow commits the new version on `release/vX.Y.Z` and opens a pull request into `staging`.
2. Merge it, then merge the release pull request into `main`.
3. `release.yml` sees an untagged version on `main` and does the rest:
   - creates tag `vX.Y.Z`;
   - builds the gateway for amd64 and arm64, plus the client apps for Windows, macOS (arm64 and x86_64) and Linux;
   - pushes the multi-arch image;
   - attests build provenance;
   - publishes the GitHub Release.

   Versions are never edited by hand on `main`. Merging to `main` without a version bump updates `main` but publishes nothing.

## Workflows

| Workflow | Trigger | Does |
|---|---|---|
| [ci.yml](../.github/workflows/ci.yml) | every push, nightly, manual | fmt, clippy, tests, arch rules, aarch64 cross-build, Windows/macOS checks, cargo-deny, cargo-audit and fuzz smoke tests, aggregated into `required` |
| ci.yml `branch-policy` | pull requests | fails if a pull request into `main` doesn't come from `staging` |
| ci.yml `main-gate` | push to `main` | fails unless `main`'s exact file tree already exists as a commit on `staging` |
| ci.yml `sync-staging` | push to `main` | fast-forwards `staging` to `main` after a release |
| [pull-requests.yml](../.github/workflows/pull-requests.yml) | branch pushes, and successful `ci` runs on `staging` | opens the pull request into `staging` and the release pull request into `main` |
| [version.yml](../.github/workflows/version.yml) | manual | version bump: `release/vX.Y.Z` branch plus a pull request into `staging` |
| [release.yml](../.github/workflows/release.yml) | push to `staging` or `main`, manual | staging image, or (on `main` with a new version) tag, image and GitHub Release |

**Quirks to know:**

- Pushes and pull requests made with `GITHUB_TOKEN` don't trigger other workflows. That's why `PR_TOKEN` exists, and why the `sync-staging` push doesn't republish staging.
- `workflow_run` triggers, which open the release pull request, only work from the copy of the workflow on `main`.

## One-time repository setup

- **Secret `PR_TOKEN`:** a fine-grained personal access token for this repository only, with:
  - **Contents: Read and write**, so version-bump branches run CI;
  - **Pull requests: Read and write**.

  Without it the built-in token is used. Then turn on Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests", and approve CI on bot pull requests by hand. Note the expiry date somewhere.
- **Image package:** after the first publish, go to Packages → `aegis` → Package settings → change visibility to **Public**. Servers can then pull it without `docker login`. If the package stays private, run `docker login ghcr.io` on each server.
- **Local hook:** run `git config core.hooksPath .githooks` once per clone. It blocks direct pushes to `main` and `staging`; `--no-verify` overrides it deliberately.
- **Branch protection:** rulesets need a paid plan for private repositories. Until then, `main-gate`, `branch-policy` and the hook enforce the flow. With rulesets available:
  - **`main`:** block force pushes and deletion; require a pull request with merge commits only; require the `required`, `branch-policy` and `main-gate` checks.
  - **`staging`:** the same, requiring only `required`.

## Installing a release (servers)

```sh
curl -fsSLO https://github.com/OnTheThirdDay/aegis/releases/latest/download/install.sh
sudo sh install.sh            # Docker. Add --native for a systemd service (Linux)
```

- **Image pinning:** the release copy of `install.sh` pins that release's image **by digest**.
  - `--version vX.Y.Z` selects another release.
  - `--image REF` runs any image, for example `:staging`.
  - `--native` downloads `aegisnet-gateway-linux-<arch>.tar.gz` and checks it against `SHA256SUMS` before installing.
- **Verifying downloads:** `gh attestation verify <file> -R OnTheThirdDay/aegis`, or for the image `gh attestation verify oci://ghcr.io/onthethirdday/aegis:X.Y.Z -R OnTheThirdDay/aegis`.
- **Upgrading:** run the newer `install.sh` with the same options. Data is kept.
- **Offline or development installs** without GitHub:
  ```sh
  sh deploy/build-bundle.sh DIR
  sudo sh DIR/aegisnet-gateway/install.sh --from DIR/aegisnet-gateway
  ```

The full server guide (first-time setup, servers that already run nginx or v2ray, console access on a public server, upgrades) is [INSTALL.md](INSTALL.md).
