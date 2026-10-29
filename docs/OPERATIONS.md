# Operations quickstart

> **Most installations should use the appliance.** Installing, first-time setup (including servers that already run nginx, v2ray or Cloudflare), upgrading and removal are covered step by step in [INSTALL.md](INSTALL.md).
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
aegisctl pki csr --node-id laptop-1 --out /etc/aegisborne-client/secrets/identity
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

On-demand diagnostics:

```sh
aegisctl diagnostic start --minutes 15     # or console → Diagnostics
```

- **Limits:** a recording lasts at most 60 minutes and stops by itself. It is held in memory only, capped at 5 MiB with the oldest records deleted first, and dropped 60 minutes after it ends.
- **Devices:** devices can send their own signed report while it is on.
- **Analysis and export:** the console explains the findings and exports everything as OTLP/JSON logs.

See [DIAGNOSTICS.md](DIAGNOSTICS.md).
