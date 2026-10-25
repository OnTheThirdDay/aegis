# Installing, setting up and upgrading an AegisNet server

This guide is for anyone setting up a gateway on a new server. Normal use takes the steps in order:

1. **Prepare the server**: install Docker and check which ports are free.
2. **Install** with one command, adding options if the server already runs nginx, v2ray or Cloudflare.
3. **Finish setup in the browser**: set the admin password, choose how devices connect, invite devices.

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

**Check which ports are already taken:**

```sh
sudo ss -ltnp | grep -E ':(80|443|8443)\b'        # Linux
sudo lsof -nP -iTCP -sTCP:LISTEN | grep -E ':(80|443|8443) '   # macOS
```

| Port | Used by AegisNet for | Option to change it |
|---|---|---|
| 8443 | the HTTPS web console | `--console-port N` |
| 443 | devices connecting to the gateway | `--port N` |
| 80 | Let's Encrypt HTTP validation (only during issuance) | `--http-port N` (`0` = don't use) |

**If nginx (or another web server) already uses 80 and 443**, as it does with a typical v2ray + nginx setup, use `--port 8444 --http-port 0` in step 2. AegisNet then leaves both ports alone. Existing v2ray, nginx and cloudflared services are never modified.

## 2. Install

Download the installer from the latest release:

```sh
curl -fsSLO https://github.com/OnTheThirdDay/aegis/releases/latest/download/install.sh
```

Pick the line that matches your server. **Write down the command you used**, because upgrades must repeat the same options.

| Situation | Command |
|---|---|
| Home or LAN server, ports 80/443 free | `sudo sh install.sh` |
| Public server (VPS), ports free | `sudo sh install.sh --local-console --address <public-ip>` |
| Public server already running nginx/v2ray | `sudo sh install.sh --port 8444 --http-port 0 --local-console --address <public-ip>` |
| Linux without Docker | add `--native` to any line above (systemd service; not yet tested on a real distribution) |

**Options:**

- **`--address`**: the public IP or DNS name people use to reach this server. It goes into the server's certificates. On cloud VMs the network card usually only knows a private address, so give the public one here; you can list several separated by commas.
- **`--local-console`**: the admin console is reachable only from the server itself; see step 3.
- **`--name NAME`**: run a second, separate instance (its own container and data).
- **`--version vX.Y.Z`**: install a specific release instead of the newest.

The installer checks Docker, pulls the release image (pinned to an exact digest), starts it hardened and waits until it is healthy. It then prints:

- **the console address:** with `--local-console`, the SSH command to use instead (see step 3);
- **the one-time admin password:** `admin` / `xxxxx-xxxxx-xxxxx-xxxxx`;
- **the console certificate's SHA-256 fingerprint.**

Keep that output. If you lose the password before using it:

```sh
docker exec aegis aegisctl initial-password                           # Docker
sudo aegisctl initial-password --data-dir /var/lib/aegis              # --native
```

## 3. Open the admin console

**Server installed without `--local-console`** (home/LAN): open `https://<server-address>:8443` in a browser.

**Server installed with `--local-console`** (recommended for public servers): the console only listens on the server itself. Reach it through SSH from your computer:

```sh
ssh -L 8443:127.0.0.1:8443 <user>@<server>
```

Keep that session open and browse to **https://localhost:8443**. The console is never exposed to the internet this way.

**The first time, the browser warns** that the certificate isn't trusted. That's expected: the server made its own certificate. Compare the fingerprint the installer printed with the certificate's fingerprint in the browser (click the warning, then view the certificate), then continue. To get rid of the warning permanently, download the web CA under **Account → Trust this console** and install it on your computer.

> **Want the console public anyway?** Install without `--local-console`, then allow TCP 8443 only from your own IP in the cloud provider's firewall. On Docker hosts, **`ufw` does not filter Docker-published ports**, so use the provider's firewall (or `--local-console`). A fully public console still works: it is HTTPS-only, rate-limits sign-in attempts and forces a password change. Use a long passphrase.

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

   1. Enter the server's address (IP or DNS name) and the device port (443, or 8444 if you used `--port 8444`), then press **Use this address**.
   2. For a public server, open that TCP port in the cloud provider's firewall or security group.

   Devices trust the server through the invitation, so no public certificate is needed.

   **Option C: Let's Encrypt certificate** (optional, with a public DNS name pointing at the server)

   - **HTTP validation** needs port 80 forwarded to the server, so it isn't available with `--http-port 0`.
   - **DNS validation** works through the Cloudflare API instead, so it does not need port 80.
   - The certificate renews automatically. Devices invited earlier keep working.

4. **Users** (optional): add people with the role **User**. They get a one-time password, sign in to the same console, and can invite and remove only their own devices.
5. **Devices → Invite a device**: enter a device name and press **Create invitation**. Send the code (or the downloaded `.aegis` file) to the device's owner.

## 5. Connect a device

1. Download the client app from the console (**Devices → Client apps**) or from the [latest release](https://github.com/OnTheThirdDay/aegis/releases/latest). It is portable: no installation and no admin rights needed.
   - macOS builds are unsigned: the first time, right-click → Open, or run `xattr -d com.apple.quarantine aegis-client-macos-*`.
2. Open it, press **Paste** (or drop the `.aegis` file on the window), then **Join and connect**.
3. Point apps at the local proxy:
   - **SOCKS5:** `127.0.0.1:1080`. In Firefox, also tick "Proxy DNS when using SOCKS v5".
   - **HTTP:** `127.0.0.1:8080`.
   - **Windows:** Settings → *Set as the Windows system proxy* does this for most apps.

Headless machines: `aegisctl join --dir DIR < invite.aegis`, then `aegisctl connect --dir DIR`.

## 6. Upgrade

Download the newest installer and run it **with the same options you installed with**:

```sh
curl -fsSLO https://github.com/OnTheThirdDay/aegis/releases/latest/download/install.sh
sudo sh install.sh <same options as the original install>
```

What the upgrade keeps and changes:

- **Kept:** all data, including the admin password, users, devices, certificates and the Cloudflare tunnel. They live in the Docker volume `aegis-data` (or `/var/lib/aegis` with `--native`). The console certificate stays the same, so the browser does not warn again.
- **Changed:** only the program. Devices reconnect automatically within seconds.

**Forgot the original options?** Read them from the running gateway *before* upgrading:

```sh
docker port aegis      # e.g. 8443/tcp -> 127.0.0.1:8443 means --local-console;
                       #      8444/tcp -> 0.0.0.0:8444 means --port 8444;
                       #      no 8080/tcp line means --http-port 0
docker inspect aegis --format '{{range .Config.Env}}{{println .}}{{end}}' | grep AEGIS_PUBLIC
                       # AEGIS_PUBLIC_ADDRESSES = your --address
```

With `--native`: `systemctl cat aegis | grep AEGIS_`.

**If an upgrade fails to start** (usually a port mismatch, for example forgetting `--port 8444` next to nginx), the gateway is stopped but no data is lost. Run the installer again with the correct options.

**Other upgrade targets:**

- **A specific version:** `sudo sh install.sh --version vX.Y.Z <options>`.
- **The pre-release test build:** `sudo sh install.sh --image ghcr.io/onthethirdday/aegis:staging <options>`. Use this only on test servers.

## 7. Remove

```sh
sudo sh install.sh --uninstall            # keeps the data (Docker volume aegis-data)
sudo sh install.sh --uninstall --purge    # also deletes all data, keys and settings
```

Add `--native` if it was installed with `--native`. Removing AegisNet does not delete its Cloudflare tunnel. To remove the tunnel and its DNS record, disconnect it in **Connectivity** before uninstalling.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `could not start the container (port … in use?)` | Another service holds the port: re-run with `--port`/`--console-port` (see step 1) |
| `could not pull ghcr.io/…` | No internet from the server, or a wrong `--version` |
| Browser can't reach the console | With `--local-console`, use the SSH command. Otherwise, check the provider's firewall for TCP 8443 |
| Cloudflare status `failed` | The error text says why (missing token permission, existing DNS name, connector blocked). Fix it, paste the token and press **Retry setup**; nothing is duplicated |
| Client says "Cannot reach the server" | Check the device port is open (direct mode), the Cloudflare status (tunnel mode), or whether the device was removed in **Devices** |
| Logs | `docker logs aegis`. The gateway logs almost nothing by design; status is in the console |
