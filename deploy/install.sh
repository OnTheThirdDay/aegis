#!/bin/sh
# AegisNet gateway installer.
#
#   curl -fsSLO https://github.com/OnTheThirdDay/aegis/releases/latest/download/install.sh
#   sudo sh install.sh [options]
#
# Docker (default): pulls the release image (pinned by digest in release
# builds) and runs it hardened. --native (Linux/systemd): downloads the
# release binaries, verifies SHA256SUMS and installs a hardened service.
# Then open the printed console URL and finish setup in the browser.
#
# Upgrading: run the newest install.sh again (with --name / --native if the
# instance was installed with them). Ports, addresses and console exposure
# are read back from the running instance; options given now override them.
#
# Options:
#   --console-port N   host port of the HTTPS console        (default 8443)
#   --port N           host port devices connect to           (default 443)
#   --http-port N      host port for Let's Encrypt HTTP-01    (default 80; 0 = none)
#   --address A[,B]    public IP/DNS names for certificates   (default: detected)
#   --local-console    console on this machine only (reach it with ssh -L)
#   --public-console   undo --local-console on an upgrade
#   --fresh            ignore the existing instance's settings; use defaults
#   --name NAME        container / service name               (default aegis)
#   --version vX.Y.Z   release to install                     (default: this installer's)
#   --image REF        Docker image to run instead of the release image
#   --from DIR         offline: use binaries from DIR/bin/<arch>/ (deploy/build-bundle.sh)
#   --native           install as a Linux systemd service instead of Docker
#   --uninstall        remove the container/service (keeps data unless --purge)
#   --purge            with --uninstall: also delete all gateway data
set -eu

# Stamped by the release workflow; unstamped copies use the latest release.
REPO="OnTheThirdDay/aegis"
RELEASE="@VERSION@"
RELEASE_IMAGE="@IMAGE@"

NAME=aegis
# Empty = not given: taken from the existing instance, else the default.
CONSOLE_PORT=""
EDGE_PORT=""
HTTP_PORT=""
ADDRESSES=""
LOCAL_CONSOLE=""
FRESH=0
MODE=docker
UNINSTALL=0
PURGE=0
IMAGE=""
FROM=""
VERSION=""

die() { printf 'install: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --console-port) CONSOLE_PORT=${2:?}; shift 2 ;;
    --port) EDGE_PORT=${2:?}; shift 2 ;;
    --http-port) HTTP_PORT=${2:?}; shift 2 ;;
    --address) ADDRESSES=${2:?}; shift 2 ;;
    --local-console) LOCAL_CONSOLE=1; shift ;;
    --public-console) LOCAL_CONSOLE=0; shift ;;
    --fresh) FRESH=1; shift ;;
    --name) NAME=${2:?}; shift 2 ;;
    --version) VERSION=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --from) FROM=${2:?}; shift 2 ;;
    --native) MODE=native; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,31p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

case "$NAME" in *[!A-Za-z0-9_.-]*|"") die "invalid --name" ;; esac

# ---------------------------------------------------------------- settings of an existing instance

RECALLED=0

recall_docker() {
  command -v docker >/dev/null 2>&1 || return 0
  docker inspect "$NAME" >/dev/null 2>&1 || return 0
  # "8443/tcp=127.0.0.1:8453 8444/tcp=:8454 ..." (container port=host ip:port)
  ports=$(docker inspect -f '{{range $p, $b := .HostConfig.PortBindings}}{{$p}}={{range $b}}{{.HostIp}}:{{.HostPort}}{{end}} {{end}}' "$NAME" 2>/dev/null) || return 0
  http_seen=0
  for entry in $ports; do
    key=${entry%%=*}; val=${entry#*=}
    host_port=${val##*:}; host_ip=${val%:*}
    case "$key" in
      8443/tcp)
        if [ -z "$CONSOLE_PORT" ]; then CONSOLE_PORT=$host_port; fi
        if [ -z "$LOCAL_CONSOLE" ]; then
          if [ "$host_ip" = 127.0.0.1 ]; then LOCAL_CONSOLE=1; else LOCAL_CONSOLE=0; fi
        fi ;;
      8444/tcp) if [ -z "$EDGE_PORT" ]; then EDGE_PORT=$host_port; fi ;;
      8080/tcp) http_seen=1; if [ -z "$HTTP_PORT" ]; then HTTP_PORT=$host_port; fi ;;
    esac
  done
  if [ -z "$HTTP_PORT" ] && [ "$http_seen" = 0 ]; then HTTP_PORT=0; fi
  if [ -z "$ADDRESSES" ]; then
    ADDRESSES=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" 2>/dev/null \
      | sed -n 's/^AEGIS_PUBLIC_ADDRESSES=//p' | head -n 1)
  fi
  RECALLED=1
}

recall_native() {
  unit=/etc/systemd/system/$NAME.service
  [ -f "$unit" ] || return 0
  env_of() { sed -n "s/^Environment=$1=//p" "$unit" | head -n 1; }
  if [ -z "$CONSOLE_PORT" ]; then CONSOLE_PORT=$(env_of AEGIS_CONSOLE_PORT); fi
  if [ -z "$EDGE_PORT" ]; then EDGE_PORT=$(env_of AEGIS_EDGE_PORT); fi
  if [ -z "$HTTP_PORT" ]; then HTTP_PORT=$(env_of AEGIS_HTTP_PORT); fi
  if [ -z "$ADDRESSES" ]; then ADDRESSES=$(env_of AEGIS_PUBLIC_ADDRESSES); fi
  if [ -z "$LOCAL_CONSOLE" ]; then LOCAL_CONSOLE=$(env_of AEGIS_CONSOLE_LOOPBACK); fi
  RECALLED=1
}

if [ "$UNINSTALL" = 0 ] && [ "$FRESH" = 0 ]; then
  if [ "$MODE" = native ]; then recall_native; else recall_docker; fi
fi
[ -n "$CONSOLE_PORT" ] || CONSOLE_PORT=8443
[ -n "$EDGE_PORT" ] || EDGE_PORT=443
[ -n "$HTTP_PORT" ] || HTTP_PORT=80
[ -n "$LOCAL_CONSOLE" ] || LOCAL_CONSOLE=0
if [ "$RECALLED" = 1 ]; then
  console_where="reachable from the network"; [ "$LOCAL_CONSOLE" = 1 ] && console_where="this machine only"
  say "Upgrading $NAME with its current settings (options given now override them; --fresh ignores them):"
  say "  console port $CONSOLE_PORT ($console_where), device port $EDGE_PORT, HTTP validation port $HTTP_PORT (0 = none)"
  [ -n "$ADDRESSES" ] && say "  addresses $ADDRESSES"
fi

for p in "$CONSOLE_PORT" "$EDGE_PORT" "$HTTP_PORT"; do
  case "$p" in *[!0-9]*|"") die "ports must be numbers" ;; esac
done
case "$RELEASE" in @*) RELEASE="" ;; esac
case "$RELEASE_IMAGE" in @*) RELEASE_IMAGE="" ;; esac
[ -z "$VERSION" ] && VERSION=$RELEASE
case "$VERSION" in ""|latest|v[0-9]*) ;; *) die "--version must look like v1.2.3" ;; esac
LOWER_REPO=$(printf '%s' "$REPO" | tr 'A-Z' 'a-z')

release_url() { # file
  if [ -n "$VERSION" ] && [ "$VERSION" != latest ]; then
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$1"
  else
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$1"
  fi
}

fetch() { # url dest
  if command -v curl >/dev/null 2>&1; then curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then wget -q --https-only -O "$2" "$1"
  else die "curl or wget is required"; fi
}

host_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "unsupported CPU architecture $(uname -m)" ;;
  esac
}

detect_addresses() {
  if [ -n "$ADDRESSES" ]; then printf '%s' "$ADDRESSES"; return; fi
  found=""
  case "$(uname -s)" in
    Darwin)
      for ifc in en0 en1 en2; do
        ip=$(ipconfig getifaddr "$ifc" 2>/dev/null || true)
        [ -n "$ip" ] && found="$found${found:+,}$ip"
      done ;;
    *)
      for ip in $(hostname -I 2>/dev/null || true); do
        case "$ip" in 127.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|*:*) ;; *) found="$found${found:+,}$ip" ;; esac
      done ;;
  esac
  host=$(hostname 2>/dev/null | tr 'A-Z' 'a-z' || true)
  case "$host" in *.*) found="$found${found:+,}$host" ;; "") ;; *) found="$found${found:+,}$host.local" ;; esac
  printf '%s' "$found"
}

print_summary() { # password fingerprint addresses
  say ""
  say "  AegisNet gateway is running."
  say ""
  if [ "$LOCAL_CONSOLE" = 1 ]; then
    say "  The console listens on this machine only. From your computer run:"
    say "      ssh -L $CONSOLE_PORT:127.0.0.1:$CONSOLE_PORT <user>@<this-server>"
    say "  and open  https://localhost:$CONSOLE_PORT"
  else
    say "  Open the web console in a browser:"
    shown=0
    OLDIFS=$IFS; IFS=,
    for a in $3; do [ -n "$a" ] && { say "      https://$a:$CONSOLE_PORT"; shown=1; }; done
    IFS=$OLDIFS
    [ "$shown" = 0 ] && say "      https://<this-server>:$CONSOLE_PORT"
  fi
  say ""
  say "  Sign in as:   admin"
  if [ -n "$1" ]; then
    say "  Password:     $1      (one-time; you must change it at first sign-in)"
  else
    say "  Password:     already changed (existing installation)"
  fi
  say ""
  say "  The browser warns about the certificate the first time; this server made"
  say "  its own. Check its SHA-256 fingerprint matches:"
  say "      $2"
  say ""
  say "  Devices connect to TCP port $EDGE_PORT. For access from the internet, open that"
  say "  port in your firewall, or set up Cloudflare Tunnel in the console (no open ports)."
  say ""
}

wait_healthy() { # command...
  i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -gt 90 ] && return 1
    sleep 1
  done
}

# ---------------------------------------------------------------- docker

docker_install() {
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it (Linux: curl -fsSL https://get.docker.com | sudo sh) or use --native"
  docker info >/dev/null 2>&1 || die "Docker is not running (or this user may not use it: try sudo)"
  if [ "$UNINSTALL" = 1 ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ "$PURGE" = 1 ]; then docker volume rm "$NAME-data" >/dev/null 2>&1 || true; say "Removed $NAME and its data."
    else say "Removed $NAME (data kept in Docker volume $NAME-data)."; fi
    return
  fi
  if [ -n "$FROM" ]; then
    [ -f "$FROM/Dockerfile" ] || die "--from: $FROM/Dockerfile missing"
    IMAGE=${IMAGE:-aegisnet/gateway:local}
    say "Building $IMAGE from $FROM…"
    docker build -q --build-arg TARGETARCH="$(host_arch)" -t "$IMAGE" "$FROM" >/dev/null
  else
    if [ -z "$IMAGE" ]; then
      if [ -n "$RELEASE_IMAGE" ] && { [ -z "$VERSION" ] || [ "$VERSION" = "$RELEASE" ]; }; then
        IMAGE=$RELEASE_IMAGE
      elif [ -n "$VERSION" ] && [ "$VERSION" != latest ]; then
        IMAGE="ghcr.io/$LOWER_REPO:${VERSION#v}"
      else
        IMAGE="ghcr.io/$LOWER_REPO:latest"
      fi
    fi
    say "Pulling $IMAGE…"
    docker pull -q "$IMAGE" >/dev/null || die "could not pull $IMAGE (is the package public, or run: docker login ghcr.io)"
  fi
  docker volume create "$NAME-data" >/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  addrs=$(detect_addresses)
  console_bind="0.0.0.0"; [ "$LOCAL_CONSOLE" = 1 ] && console_bind="127.0.0.1"
  err=$(mktemp)
  run() { # extra publish flags
    # shellcheck disable=SC2086
    docker run -d --name "$NAME" --restart unless-stopped \
      --read-only --cap-drop ALL --security-opt no-new-privileges \
      --pids-limit 256 --memory 512m --tmpfs /tmp:rw,noexec,nosuid,size=16m \
      -v "$NAME-data:/var/lib/aegisnet" \
      -e AEGIS_PUBLIC_ADDRESSES="$addrs" -e AEGIS_PUBLIC_PORT="$EDGE_PORT" \
      -p "$console_bind:$CONSOLE_PORT:8443" -p "$EDGE_PORT:8444" $1 \
      "$IMAGE" >/dev/null 2>"$err"
  }
  extra=""; [ "$HTTP_PORT" != 0 ] && extra="-p $HTTP_PORT:8080"
  if ! run "$extra"; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ -n "$extra" ] && grep -qiE 'port is already allocated|address already in use' "$err"; then
      say "Port $HTTP_PORT is in use; continuing without Let's Encrypt HTTP validation (DNS validation still works)."
      run "" || { cat "$err" >&2; rm -f "$err"; die "could not start the container"; }
    else
      cat "$err" >&2; rm -f "$err"
      die "could not start the container (port $CONSOLE_PORT or $EDGE_PORT in use? try --console-port / --port)"
    fi
  fi
  rm -f "$err"
  say "Waiting for the gateway to start…"
  wait_healthy docker exec "$NAME" aegisctl health || { docker logs --tail 20 "$NAME" >&2 || true; die "the gateway did not become healthy"; }
  password=$(docker exec "$NAME" aegisctl initial-password 2>/dev/null || true)
  fingerprint=$(docker exec "$NAME" aegisctl console-fingerprint 2>/dev/null || echo unknown)
  print_summary "$password" "$fingerprint" "$addrs"
  name_opt=""; [ "$NAME" = aegis ] || name_opt=" --name $NAME"
  say "  Manage:  docker logs $NAME | docker restart $NAME | sh install.sh$name_opt --uninstall"
  say "  Upgrade: run the newest install.sh again; data and settings are kept."
  say ""
}

# ---------------------------------------------------------------- native

write_unit() { # unit data addresses
  console_loopback=0; [ "$LOCAL_CONSOLE" = 1 ] && console_loopback=1
  cat > "$1" <<UNIT
# AegisNet appliance (native), written by install.sh --native.
[Unit]
Description=AegisNet gateway (appliance)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegisnet
Group=aegisnet
Environment=AEGIS_DATA_DIR=$2
Environment=AEGIS_CONSOLE_PORT=$CONSOLE_PORT
Environment=AEGIS_EDGE_PORT=$EDGE_PORT
Environment=AEGIS_PUBLIC_PORT=$EDGE_PORT
Environment=AEGIS_HTTP_PORT=$HTTP_PORT
Environment=AEGIS_PUBLIC_ADDRESSES=$3
Environment=AEGIS_CONSOLE_LOOPBACK=$console_loopback
Environment=AEGIS_DOWNLOADS_DIR=/usr/local/share/aegisnet/clients
ExecStart=/usr/local/bin/aegisd --data-dir $2
StateDirectory=$NAME
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
RestartSec=2s
TimeoutStopSec=30s
LimitNOFILE=65536
# Binding ports below 1024 needs only this capability; nothing else is granted.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ReadWritePaths=$2
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RemoveIPC=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @mount

[Install]
WantedBy=multi-user.target
UNIT
}

native_install() {
  [ "$(uname -s)" = Linux ] || die "--native supports Linux (systemd) only; use Docker on macOS"
  [ "$(id -u)" = 0 ] || die "--native needs root: sudo sh install.sh --native"
  command -v systemctl >/dev/null 2>&1 || die "systemd is required for --native"
  unit=/etc/systemd/system/$NAME.service
  data=/var/lib/$NAME
  if [ "$UNINSTALL" = 1 ]; then
    systemctl disable --now "$NAME" >/dev/null 2>&1 || true
    rm -f "$unit"; systemctl daemon-reload
    if [ "$PURGE" = 1 ]; then rm -rf "$data"; say "Removed $NAME and its data."; else say "Removed $NAME (data kept in $data)."; fi
    return
  fi
  arch=$(host_arch)
  work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
  if [ -n "$FROM" ]; then
    src="$FROM/bin/$arch"
    [ -x "$src/aegisd" ] || die "--from: $src/aegisd missing"
    clients="$FROM/clients"
  else
    tag=${VERSION:-latest}
    pkg="aegisnet-gateway-linux-$arch.tar.gz"
    say "Downloading AegisNet ($tag, $arch)…"
    fetch "$(release_url "$pkg")" "$work/$pkg"
    fetch "$(release_url SHA256SUMS)" "$work/SHA256SUMS"
    ( cd "$work" && grep " $pkg\$" SHA256SUMS | sha256sum -c - >/dev/null ) || die "checksum verification failed for $pkg"
    tar -xzf "$work/$pkg" -C "$work"
    src="$work/aegisnet-gateway/bin"
    clients="$work/aegisnet-gateway/clients"
  fi
  id aegisnet >/dev/null 2>&1 || useradd --system --home-dir "$data" --shell /usr/sbin/nologin aegisnet
  install -m 0755 "$src/aegisd" "$src/aegisctl" /usr/local/bin/
  [ -f "$src/cloudflared" ] && install -m 0755 "$src/cloudflared" /usr/local/bin/cloudflared
  install -d -m 0755 /usr/local/share/aegisnet/clients
  if [ -d "$clients" ]; then cp -f "$clients"/* /usr/local/share/aegisnet/clients/ 2>/dev/null || true; fi
  addrs=$(detect_addresses)
  write_unit "$unit" "$data" "$addrs"
  systemctl daemon-reload
  systemctl enable "$NAME" >/dev/null 2>&1
  systemctl restart "$NAME"
  say "Waiting for the gateway to start…"
  wait_healthy /usr/local/bin/aegisctl --socket "$data/aegisd.sock" health \
    || { journalctl -u "$NAME" -n 20 --no-pager >&2 || true; die "the gateway did not become healthy"; }
  password=$(/usr/local/bin/aegisctl initial-password --data-dir "$data" 2>/dev/null || true)
  fingerprint=$(/usr/local/bin/aegisctl console-fingerprint --data-dir "$data" 2>/dev/null || echo unknown)
  print_summary "$password" "$fingerprint" "$addrs"
  name_opt=""; [ "$NAME" = aegis ] || name_opt=" --name $NAME"
  say "  Manage:  systemctl status $NAME | sudo sh install.sh --native$name_opt --uninstall"
  say "  Upgrade: run the newest install.sh --native again; data and settings are kept."
  say ""
}

if [ "$MODE" = native ]; then native_install; else docker_install; fi
