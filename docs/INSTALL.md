# Installing, setting up and upgrading an AegisNet server

This guide is for anyone setting up a gateway on a new server. Normal use takes the steps in order:

1. **Prepare the server**: install Docker.
2. **Install** with one command, chosen by where the server is and how devices will reach it.
3. **Open the admin console**: directly on a home network, through SSH for a server on the internet.
4. **Finish setup in the browser**: set the admin password, choose how devices connect, invite devices.

Upgrades and removal are covered at the end.

---

## 1. Prepare the server

**Supported:**

- Linux (Ubuntu 22.04+, Debian 12+) on x86-64 (amd64) or ARM64.
- macOS with Docker Desktop (Intel or Apple silicon).

You need a user with `sudo`. Check the architecture with `uname -m`: it should print `x86_64` or `aarch64`/`arm64`.

**Install Docker if it isn't there** (Linux):

```sh
docker --version || curl -fsSL https://get.docker.com | sudo sh
```

On macOS, install Docker Desktop and make sure it's running. Enable *Start Docker Desktop when you sign in*, so the gateway comes back after a reboot.

**Ports:** you don't need to check them. The installer uses these defaults and, when one is already taken (for example by nginx in a v2ray + nginx setup), picks a free one instead and shows it in its summary. Existing v2ray, nginx and cloudflared services are never modified.

| Port | Used by AegisNet for | If taken | Option to set it |
|---|---|---|---|
| 8443 | the HTTPS web console | 8453, 8463, 9443 | `--console-port N` |
| 443 | devices connecting directly | 8444, 8454, 9444 | `--port N` |
| 80 | Let's Encrypt HTTP validation (only during issuance) | not used | `--http-port N` (`0` = don't use) |

## 2. Install

Get the installer. It ships inside the gateway's public Docker image, so this needs only Docker, no GitHub account:

```sh
docker run --rm --pull always --entrypoint cat \
  ghcr.io/onthethirdday/aegis /usr/share/aegisnet/install.sh > install.sh
```

Then run **one** of the three commands below, chosen by where the server is and how devices will reach it. Nginx, v2ray or anything else already on the server doesn't change the choice: the installer avoids ports that are taken.

### Server on the internet, devices use Cloudflare Tunnel (recommended)

```sh
sudo sh install.sh --tunnel-only
```

- Nothing on the server becomes reachable from the internet, not even during setup.
- You open the admin console through SSH (step 3) and create the Cloudflare Tunnel there (step 4, option A).
- Devices then connect through Cloudflare. The server's IP stays hidden and no firewall port needs opening.

### Server on the internet, devices connect straight to it (no Cloudflare)

```sh
sudo sh install.sh --local-console --address <public-ip-or-hostname>
```

- You open the admin console through SSH (step 3).
- Devices connect to the server's device port. Open that port (printed by the installer) in your cloud provider's firewall, and choose option B in step 4.
- `--address` goes into the server's certificates. On cloud servers, give the public IP or hostname: the server itself usually only knows its private address.

### Server at home or on your local network

```sh
sudo sh install.sh
```

- The admin console opens directly in a browser on your network: `https://<server-address>:<console-port>`.
- Devices on the same network can connect directly. For access from outside, use option A in step 4 (Cloudflare Tunnel), or forward the device port on your router.

**Variations (add to any command above):**

- **`--name NAME`**: a second, separate instance on the same server (its own container and data).
- **`--version vX.Y.Z`**: a specific release instead of the newest.
- **`--console-port N`, `--port N`, `--http-port N`**: choose the ports yourself instead of letting the installer pick.

You never need to repeat these options: upgrades read them back from the running gateway.

The installer checks Docker, pulls the release image (pinned to an exact digest), starts it hardened and waits until it is healthy. It then prints:

- **the ports it chose** and whether each is reachable from the network or from the server only;
- **the console address,** or for a server on the internet the SSH command to use instead (see step 3);
- **the one-time admin password:** `admin` / `xxxxx-xxxxx-xxxxx-xxxxx`;
- **the console certificate's SHA-256 fingerprint.**

Keep that output. If you lose the password before using it:

```sh
docker exec aegis aegisctl initial-password
```

## 3. Open the admin console

**Server on the internet** (installed with `--tunnel-only` or `--local-console`): the console listens only on the server itself. You reach it through SSH, the same connection you used to run the installer, so no other port is needed.

1. On **your own computer**, open a terminal (PowerShell on Windows has `ssh` built in) and run the command below. Use the console port the installer printed, here 8453:
   ```sh
   ssh -L 8453:127.0.0.1:8453 <user>@<server-ip>
   ```
   Sign in as usual and keep that window open.
2. In the browser **on your computer**, open **https://localhost:8453**.

The browser's traffic goes to your own computer, through the encrypted SSH connection to the server, and to the console there. It doesn't go through Cloudflare (the tunnel only carries device traffic), and the console port is never reachable from the internet. Use the same SSH command whenever you need the console later. PuTTY can do the same: Connection → SSH → Tunnels, source port `8453`, destination `127.0.0.1:8453`.

**Server at home or on your local network:** open `https://<server-address>:<console-port>` in a browser on your network, for example `https://192.168.1.20:8443`.

**The first time, the browser warns** that the certificate isn't trusted. That's expected: the server made its own certificate. Compare the fingerprint the installer printed with the certificate's fingerprint in the browser (click the warning, then view the certificate), then continue. To get rid of the warning permanently, download the web CA under **Account → Trust this console** and install it on your computer.

> **Want the console public anyway?** Install it as for a home server instead, then allow the console port only from your own IP in the cloud provider's firewall. On Docker hosts, **`ufw` does not filter Docker-published ports**, so use the provider's firewall (or `--local-console`). A fully public console still works: it is HTTPS-only, rate-limits sign-in attempts and forces a password change. Use a long passphrase.

## 4. First-time setup in the browser

1. **Sign in** as `admin` with the one-time password. You must choose your own password (12+ characters) before anything else.
2. **Overview** shows a checklist; follow it.
3. **Connectivity: choose how devices reach the server.** Use one of these:

   **Option A: Cloudflare Tunnel** (recommended for public servers; works whether or not Cloudflare is already in use)

   1. Create a Cloudflare API token at dash.cloudflare.com → My Profile → API Tokens → Create Token → Custom token:
      - permissions **Account · Cloudflare Tunnel · Edit**, **Zone · DNS · Edit** and **Zone · Zone · Read**;
      - limited to your account and the one domain.
   2. In Connectivity → Cloudflare Tunnel, paste the token and press **Continue**. Pick the domain, enter a subdomain nobody uses yet (for example `aegis`), press **Preview changes**, then **Create tunnel and connect**.
   3. After about a minute the status becomes **active**. Devices then connect to `wss://<subdomain>.<domain>/agp`. No inbound port needs to be open, and port 443/8444 can stay closed in the firewall.

   AegisNet creates its *own* tunnel and one DNS record labelled as AegisNet's. Existing tunnels (for example v2ray's) and DNS records are not touched. The token is used once and not stored unless you tick "Remember the token".

   **Option B: direct connection** (LAN, or a public server without Cloudflare)

   1. Enter the server's address (IP or DNS name) and the device port the installer printed (443 unless it was taken), then press **Use this address**.
   2. For a public server, open that TCP port in the cloud provider's firewall or security group.

   Devices trust the server through the invitation, so no public certificate is needed.

   **Option C: Let's Encrypt certificate** (optional, with a public DNS name pointing at the server)

   - **HTTP validation** needs port 80 forwarded to the server, so it isn't available with `--http-port 0`.
   - **DNS validation** works through the Cloudflare API instead, so it does not need port 80.
   - The certificate renews automatically. Devices invited earlier keep working.

4. **Users** (optional): add people with the role **User**. They get a one-time password, sign in to the same console, and can invite and remove only their own devices.
5. **Devices → Invite a device**: enter a device name and press **Create invitation**. Send the code (or the downloaded `.aegis` file) to the device's owner.

## 5. Connect a device

1. Download the client app from the console (**Devices → Client apps**). It is portable: no installation and no admin rights needed.
   - macOS builds are unsigned: the first time, right-click → Open, or run `xattr -d com.apple.quarantine aegis-client-macos-*`.
2. Open it, press **Paste** (or drop the `.aegis` file on the window), then **Join and connect**.
3. Point apps at the local proxy:
   - **SOCKS5:** `127.0.0.1:1080`. In Firefox, also tick "Proxy DNS when using SOCKS v5".
   - **HTTP:** `127.0.0.1:8080`.
   - **Windows:** Settings → *Set as the Windows system proxy* does this for most apps.

Headless machines: `aegisctl join --dir DIR < invite.aegis`, then `aegisctl connect --dir DIR`.

**If the server's address changes later** (a new hostname, or a switch from a direct address to Cloudflare Tunnel), devices pick up the new address the next time they connect, as long as the old address still reaches the server at that moment. Keep the old address working until devices have connected once. A device adopts the new address only after it has verified, through its pinned connection, that the same gateway answers there. Devices that were offline for the whole changeover need a new invitation.

## 6. Upgrade

Get the installer from the newest image (`--pull always` makes Docker fetch the newest one) and run it:

```sh
docker run --rm --pull always --entrypoint cat \
  ghcr.io/onthethirdday/aegis /usr/share/aegisnet/install.sh > install.sh
```

```sh
sudo sh install.sh                  # add --name NAME if you installed with one
```

The installer reads the current settings from the running gateway (ports, addresses, whether the console and device port are local only), prints them, and keeps them. To change one, pass just that option, for example `--port 8444`; `--public-console` undoes `--local-console`, `--direct` undoes `--tunnel-only`, and `--fresh` ignores the old settings.

What the upgrade keeps and changes:

- **Kept:** all data, including the admin password, users, devices, certificates and the Cloudflare tunnel. They live in the Docker volume `aegis-data`. The console certificate stays the same, so the browser does not warn again.
- **Changed:** only the program. Devices reconnect automatically within seconds.

The settings live in the gateway's container. After `--uninstall` they are gone; data is kept, but a reinstall starts from the defaults again unless you pass the options.

**If an upgrade fails to start** (usually a port another service took in the meantime), the gateway is stopped but no data is lost. Run the installer again with the port options it needs.

**Other upgrade targets:**

- **A specific version:** `sudo sh install.sh --version vX.Y.Z`.
- **The pre-release test build:** `sudo sh install.sh --image ghcr.io/onthethirdday/aegis:staging`. Use this only on test servers. The image is not remembered: the next plain upgrade goes back to the release.

## Optional: keep the device root key offline

Device certificates are signed by a one-year *issuer*, which is signed by the gateway's *root*. Devices trust the root. By default the root key is stored on the server, so the issuer renews by itself.

For stronger protection, take the root key off the server. Then someone who breaks into the server can't create a new root. The cost is renewing the issuer yourself once a year.

In the console, open **Account → Device certificate authority**:

1. **Download the root key.** Your password is asked again. Store the file offline, for example on a USB stick kept somewhere safe, or in a password manager.
2. **Choose the downloaded file and press Remove the key from this server.** Choosing the file proves you saved the right key before it is deleted.
3. **Once a year**, when the console warns that the device issuer expires within 60 days, choose the key file there and press **Renew the device issuer**. The key is used once and not stored. Devices keep working throughout.

**Put the key back on this server** returns to automatic renewal. Keep a backup of the key file: if it is lost while offline, the issuer can't be renewed, and every device needs a new invitation after it expires.

## 7. Remove

```sh
sudo sh install.sh --uninstall            # keeps the data (Docker volume aegis-data)
sudo sh install.sh --uninstall --purge    # also deletes all data, keys and settings
```

Removing AegisNet does not delete its Cloudflare tunnel. To remove the tunnel and its DNS record, disconnect it in **Connectivity** before uninstalling.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `could not start the container (port … in use?)` | Another service holds the port: re-run with `--port`/`--console-port` (see step 1) |
| `could not pull ghcr.io/…` | No internet from the server, or a wrong `--version` |
| Browser can't reach the console | Server on the internet: use the SSH command from step 3 and browse to `https://localhost:<port>`. Home server: check the console port the installer printed |
| Cloudflare status `failed` | The error text says why (missing token permission, existing DNS name, connector blocked). Fix it, paste the token and press **Retry setup**; nothing is duplicated |
| Client says "Cannot reach the server" | Check the device port is open (direct mode), the Cloudflare status (tunnel mode), or whether the device was removed in **Devices** |
| Anything else, or the cause isn't clear | Record it: console **Diagnostics** plus **Troubleshooting** in the client app, then read the analysis. See [DIAGNOSTICS.md](DIAGNOSTICS.md) |
| Logs | `docker logs aegis`. The gateway keeps no logs by design; status is in the console, and diagnostics record on demand (see above) |
