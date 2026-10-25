# Operations quickstart

> **Most installations should use the appliance:** `sh install.sh`, then the web console. See the README's Quick start and [ADR-0007](adr/0007-appliance-console-and-portable-client.md).
>
> Appliance operations:
>
> - **Recover the one-time password:** `docker exec aegis aegisctl initial-password`.
> - **Check the console certificate:** `docker exec aegis aegisctl console-fingerprint`.
> - **Upgrade:** download the newest `install.sh` from the latest release and run it with the same options. Data in the `aegis-data` volume is kept. See [RELEASING.md](RELEASING.md).
> - **Remove:** `sh install.sh --uninstall`, plus `--purge` to delete all data.
> - **Ports** (container → default host port):
>   - 8443 → 8443: HTTPS console;
>   - 8444 → 443: device edge (`/agp`, `/enroll`, `/renew`);
>   - 8080 → 80: ACME HTTP-01, only while a certificate is being issued.
>
>
> ### Install next to existing services
>
> On a server that already runs nginx, v2ray or Cloudflare, keep AegisNet off their ports and reach its console privately:
>
> ```sh
> sudo sh install.sh --port 8444 --http-port 0 --local-console --address <public-ip-or-name>
> ssh -L 8443:127.0.0.1:8443 <user>@<server>     # then open https://localhost:8443
> ```
>
> - `--port 8444` and `--http-port 0` leave 80 and 443 to nginx.
> - `--local-console` binds the console to the server's loopback, so it's never reachable from the internet.
> - On cloud VMs, `--address` should be the *public* IP or DNS name.
>
> **Making devices reachable:**
>
> - **With Cloudflare** (recommended): use Cloudflare Tunnel in the console. No inbound port is needed, and existing tunnels and DNS records are untouched.
> - **Without Cloudflare:** open TCP 8444 in the provider's firewall and enter the public address under Connectivity.
>
> **Firewall caveat:** `ufw` rules do not filter ports published by Docker. Restrict the console with `--local-console` or the cloud provider's firewall instead.
>
> The rest of this document covers hand-configured (non-appliance) nodes.

This walks through a gateway and a client on Linux. Paths follow `deploy/examples/`. All administrative surfaces are loopback-only.

## 1. Build

```sh
cargo build --locked --release -p aegisd -p aegisctl
install -m 0755 target/release/aegisd target/release/aegisctl /usr/local/bin/
```

## 2. Gateway identity (on the gateway host)

```sh
install -d -m 0700 /etc/aegisnet/secrets/identity
aegisctl pki init-ca --out /etc/aegisnet/secrets/identity        # ca.pem, ca-key.pem (0600)
aegisctl pki issue --ca /etc/aegisnet/secrets/identity \
  --node-id pi-gateway-01 --role gateway \
  --server-name gateway.aegis.internal --out /tmp/gw
mv /tmp/gw/cert.pem /etc/aegisnet/secrets/identity/server-cert.pem
mv /tmp/gw/key.pem  /etc/aegisnet/secrets/identity/server-key.pem
```

If the gateway host is not fully trusted, keep `ca-key.pem` elsewhere and enroll offline (11 §5).

## 3. Start and bootstrap

```sh
cp deploy/examples/gateway.toml /etc/aegisnet/config.toml
aegisctl validate /etc/aegisnet/config.toml
systemctl enable --now aegisd          # deploy/systemd/aegisd.service
aegisctl --socket /var/lib/aegisnet/aegisd.sock bootstrap-token
```

Open `http://127.0.0.1:9080/` on the gateway (use an SSH tunnel for remote access). Use the token under **First-time setup**, then sign in. The token is single-use and expires after 15 minutes.

The daemon writes nothing to the console. If it fails to start it prints only a code such as `aegisd: E_CONFIG_INVALID`; run `aegisctl validate` for the details.

## 4. Enroll a client

On the gateway, using a CLI token:

```sh
export AEGIS_TOKEN=$(aegisctl --socket /var/lib/aegisnet/aegisd.sock token --ttl 600 | jq -r .token)
aegisctl api POST /nodes/enrollment --data '{"role":"agent"}'     # prints a one-use invite
```

On the client, the private key never leaves the client:

```sh
aegisctl pki csr --node-id laptop-1 --out /etc/aegisnet-client/secrets/identity
```

Copy `csr.pem` to the gateway, then on the gateway:

```sh
aegisctl enroll-redeem --invite <INVITE> --name laptop-1 --csr csr.pem --out ./laptop-1
```

Copy `laptop-1/cert.pem` and `laptop-1/ca.pem` back into the client's `secrets/identity/`.

## 5. Edge

Point cloudflared (or a local reverse proxy) at `http://127.0.0.1:18080`. On the client, set `url = "wss://<your-hostname>/agp"` in `client.toml` and start `aegisd --config client.toml`. Then:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.org/
```

Cloudflare Free is a compatibility target, not a capacity guarantee. Comply with the service terms.

## 6. Where the live configuration comes from

The TOML file seeds an **empty** store only. On first start it is imported as the profile `default` and activated through the normal durable protocol. From then on, the stored active revision is authoritative. Editing the file afterwards has no effect: make changes through the API or console as described below. The file is still validated at startup, so a broken file fails fast.

## 7. Change policy safely

Edit the profile in the console, or with `aegisctl api PATCH /profiles/<id> ...`. Then run:

```sh
aegisctl activate <profile-id>
```

This validates the exact revision, prints the security diff, activates it and polls the job.

- Routing and ACL changes apply to new streams, including new streams on existing sessions. Streams that were already admitted keep their revision.
- Listener, identity and budget changes are reported as `restart_required`.

## 8. Recovery

If health shows `pending_operation_id` (a committed activation that has not yet been applied), new admissions are held. Use:

```sh
aegisctl activation inspect
aegisctl activation reconcile <operation-id>
aegisctl activation supersede --pending <op> --expected-runtime <rev|null> \
  --epoch <n> --revision <recovery-rev> --digest <hex> --reason "..."
```

A supersede operation never revives revoked identities.

## 9. Telemetry

Telemetry is off by default. To opt in to the four coarse metrics:

1. `GET /api/v1/telemetry/preview?service_name=<truthful-name>` and review the payload.
2. `PATCH /api/v1/telemetry/settings` with the current `If-Match` and the header `X-Aegis-Export-Preview-Digest: <digest>`.

Only `https://` collectors are accepted.

Local diagnostics:

```sh
aegisctl diagnostic start --minutes 10
```

This is limited to 15 minutes, held in memory only, and never exported.
