# ADR-0014 — Upgrades from the console

Status: accepted (owner direction, 2026-10-28).

## Context

Upgrading a gateway meant SSH, fetching `install.sh` and running it. The owner runs several gateways (Hong Kong, Beijing, Los Angeles, Sydney) and wants an upgrade button. The gateway container is unprivileged, read-only and has no access to Docker; replacing a container needs the Docker daemon, and anything that can talk to it is root-equivalent on the host.

## Decision

- **A separate updater container** from the same image (`aegisctl updater`) holds the Docker socket. The internet-facing gateway never gets it. The updater has no network (`--network none`; the daemon does the pulling), no listener, no capabilities except reading/writing the gateway's files (`DAC_OVERRIDE`, `CHOWN`), and is limited to 64 MiB and 64 processes. `install.sh` starts it next to the gateway (`<name>-updater`).
- **Files, not an API, between them.** The console writes `updates/request.json` (`check`, or `upgrade` to a release version) and `updates/settings.json` (automatic upgrades) in the data volume; the updater writes `updates/status.json` (running and available versions, state, outcome, heartbeat). A request carries nothing but a plain `X.Y.Z`; the updater runs only release images of the one repository it was started for, and checks that an image's version label matches its tag.
- **Upgrade = recreate with the same settings.** The gateway container is stopped, renamed `<name>-previous`, and recreated from the new image with the same host configuration (ports, volume, limits, security options, restart policy), command and `AEGIS_*` environment. If it doesn't report healthy within 3 minutes (its image health check), it is removed and the previous container renamed back and started. Only upgrades are accepted, never downgrades.
- **The updater updates itself** after a successful upgrade: it starts `<name>-updater-next` from the new image, which removes the old updater and takes its name.
- **Where releases come from** (`install.sh --updates`, remembered): `registry` (default) pulls `latest` every 6 hours and tags it with its version; `local` only uses release images already on the machine, for servers fed by another one (Beijing from Hong Kong); `off` runs no updater.
- **Automatic upgrades** are off by default; when on, a newer release found by a check is installed.

## Consequences

- After one more manual upgrade (which creates the updater), every later upgrade is a button, or automatic. Data and settings are kept as with `install.sh`; devices reconnect by themselves; console sessions end with the restart.
- A changed container setting that a future release needs (a new published port, for example) is not applied by the updater, which copies the old settings: such a release says so in its notes, and `install.sh` applies it.
- The updater is root-equivalent through the socket, as any Docker management tool is. It is kept out of reach: no network, no listener, and a request format that can't name an image or a command.
- Tests: the Docker API client's parsing, request validation, and the upgrade logic against a fake engine (install, rollback on an unhealthy release, registry and offline sources, refusal of missing, mislabelled and older releases); the console API end to end (`aegisd/tests/appliance.rs`). Not exercised against a real Docker daemon here.
