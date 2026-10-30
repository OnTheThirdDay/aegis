#!/bin/sh
# AegisBorne gateway installer (Docker). It ships inside the gateway image, so
# everything comes from the public registry; no GitHub access is needed:
#
#   docker run --rm --pull always --entrypoint cat \
#     ghcr.io/onthethirdday/aegis /usr/share/aegisnet/install.sh > install.sh
#   sudo sh install.sh [options]
#
# The copy from an image installs that image's release (the :staging image's
# copy installs :staging). Then open the console it prints and finish setup
# in the browser.
#
# Public servers: --tunnel-only exposes nothing to the internet. The console
# listens on this machine only (reach it with ssh -L) and devices arrive
# through the Cloudflare Tunnel you set up in the console.
#
# Ports that are not given and already in use (nginx, v2ray, ...) are
# replaced by free ones automatically; the summary shows which.
#
# Upgrading: fetch install.sh again as above and run it (with --name if the
# instance was installed with one). Ports, addresses and exposure are read
# back from the running instance; options given now override them.
#
# Options:
#   --tunnel-only      nothing public: console and device port on this machine
#                      only, no HTTP-01 port; devices use Cloudflare Tunnel
#   --direct           undo --tunnel-only on an upgrade
#   --quic             also publish UDP on the device port number, for direct
#                      QUIC (turn it on in the console under Connectivity)
#   --no-quic          undo --quic on an upgrade
#   --updates SOURCE   upgrades from the console: registry (default: newest
#                      release from ghcr.io), local (only images copied to this
#                      server, e.g. by another server), or off (no updater)
#   --console-port N   host port of the HTTPS console        (default 8443)
#   --port N           host port devices connect to           (default 443)
#   --http-port N      host port for Let's Encrypt HTTP-01    (default 80; 0 = none)
#   --address A[,B]    public IP/DNS names for certificates   (default: detected)
#   --local-console    console on this machine only (reach it with ssh -L)
#   --public-console   undo --local-console on an upgrade
#   --fresh            ignore the existing instance's settings; use defaults
#   --name NAME        container name                         (default aegis)
#   --version vX.Y.Z   release to install (default: this installer's)
#   --image REF        Docker image to run instead of the release image
#   --from DIR         offline: build the image from DIR (deploy/build-bundle.sh)
#   --uninstall        remove the container (keeps data unless --purge)
#   --purge            with --uninstall: also delete all gateway data
set -eu
# Keep the code ASCII (comments may not be): macOS runs this with bash 3.2,
# which under sudo (C locale) reads a byte of a non-ASCII character after
# "$NAME" as part of the variable name ("NAME?: unbound variable").

# Stamped when the image is built: the image this copy installs by default.
# Unstamped copies (from the source tree) use :latest.
REPO="OnTheThirdDay/aegis"
RELEASE_IMAGE="@IMAGE@"

NAME=aegis
# Empty = not given: taken from the existing instance, else the default.
CONSOLE_PORT=""
EDGE_PORT=""
HTTP_PORT=""
ADDRESSES=""
LOCAL_CONSOLE=""
TUNNEL_ONLY=""
QUIC=""
UPDATES=""
FRESH=0
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
    --tunnel-only) TUNNEL_ONLY=1; shift ;;
    --direct) TUNNEL_ONLY=0; shift ;;
    --quic) QUIC=1; shift ;;
    --no-quic) QUIC=0; shift ;;
    --updates) UPDATES=${2:?}; shift 2 ;;
    --fresh) FRESH=1; shift ;;
    --name) NAME=${2:?}; shift 2 ;;
    --version) VERSION=${2:?}; shift 2 ;;
    --image) IMAGE=${2:?}; shift 2 ;;
    --from) FROM=${2:?}; shift 2 ;;
    --native) die "--native is no longer supported; AegisBorne installs with Docker" ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,40p' "$0" 2>/dev/null || true; exit 0 ;;
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
      8444/tcp)
        if [ -z "$EDGE_PORT" ]; then EDGE_PORT=$host_port; fi
        if [ -z "$TUNNEL_ONLY" ]; then
          if [ "$host_ip" = 127.0.0.1 ]; then TUNNEL_ONLY=1; else TUNNEL_ONLY=0; fi
        fi ;;
      8080/tcp) http_seen=1; if [ -z "$HTTP_PORT" ]; then HTTP_PORT=$host_port; fi ;;
      8444/udp) if [ -z "$QUIC" ]; then QUIC=1; fi ;;
    esac
  done
  if [ -z "$HTTP_PORT" ] && [ "$http_seen" = 0 ]; then HTTP_PORT=0; fi
  if [ -z "$ADDRESSES" ]; then
    ADDRESSES=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" 2>/dev/null \
      | sed -n 's/^AEGIS_PUBLIC_ADDRESSES=//p' | head -n 1)
  fi
  if [ -z "$UPDATES" ]; then
    UPDATES=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" 2>/dev/null \
      | sed -n 's/^AEGIS_UPDATES=//p' | head -n 1)
  fi
  RECALLED=1
}

# The updater: a second container from the same image that upgrades the
# gateway when asked from the console. It holds the Docker socket (which is
# root-equivalent on this machine) and so has no network listener; it only
# reads requests from, and reports to, files in the data volume. It runs as
# root to use the socket, with no capabilities except reading and writing
# the gateway's files (DAC_OVERRIDE) and giving its own back to it (CHOWN).
start_updater() {
  docker rm -f "$NAME-updater" "$NAME-updater-next" >/dev/null 2>&1 || true
  [ "$UPDATES" = off ] && return 0
  sock=/var/run/docker.sock
  [ -S "$sock" ] || { say "No Docker socket at $sock: upgrades from the console are off."; return 0; }
  if ! docker run -d --name "$NAME-updater" --restart unless-stopped \
      --read-only --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN \
      --security-opt no-new-privileges --pids-limit 64 --memory 64m \
      --no-healthcheck --network none --user 0:0 \
      -v "$sock:/var/run/docker.sock" -v "$NAME-data:/var/lib/aegisnet" \
      --entrypoint /usr/local/bin/aegisctl "$IMAGE" \
      updater --container "$NAME" --repository "ghcr.io/$LOWER_REPO" --source "$UPDATES" >/dev/null 2>&1; then
    say "Could not start the updater; upgrades from the console are off (the gateway runs normally)."
  fi
}

instance_exists() {
  command -v docker >/dev/null 2>&1 && docker inspect "$NAME" >/dev/null 2>&1
}

# Whether something on this machine already listens on TCP port $1. Without
# a tool to ask, assume free (the start then fails with a clear message).
port_busy() {
  if command -v ss >/dev/null 2>&1; then
    ss -Hltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -an 2>/dev/null | grep -i listen | awk '{print $4}' | grep -qE "[:.]$1\$"
  else
    return 1
  fi
}

# Whether image reference $1 ends in a release version tag (:1.2.3).
is_release_tag() {
  tag=${1##*:}
  case "$1" in *:*) ;; *) return 1 ;; esac
  case "$tag" in
    *[!0-9.]*|.*|*.|*..*) return 1 ;;
  esac
  case "$tag" in
    *.*.*.*) return 1 ;;
    *.*.*) return 0 ;;
  esac
  return 1
}

# First free port of the candidates (the first one when none is free).
pick_port() {
  for candidate in "$@"; do
    if ! port_busy "$candidate"; then printf '%s' "$candidate"; return; fi
  done
  printf '%s' "$1"
}

if [ "$UNINSTALL" = 0 ] && [ "$FRESH" = 0 ]; then recall_docker; fi
[ -n "$TUNNEL_ONLY" ] || TUNNEL_ONLY=0
[ -n "$QUIC" ] || QUIC=0
[ -n "$UPDATES" ] || UPDATES=registry
case "$UPDATES" in registry|local|off) ;; *) die "--updates must be registry, local or off" ;; esac
if [ "$TUNNEL_ONLY" = 1 ]; then
  # Nothing public: the console needs ssh -L, and HTTP-01 can't reach us.
  [ -n "$LOCAL_CONSOLE" ] || LOCAL_CONSOLE=1
  [ -n "$HTTP_PORT" ] || HTTP_PORT=0
fi
[ -n "$LOCAL_CONSOLE" ] || LOCAL_CONSOLE=0
# Defaults, skipping ports another service already uses. Not on an upgrade
# or reinstall of this instance: its own ports would look taken.
auto=0
if [ "$UNINSTALL" = 0 ] && ! instance_exists; then auto=1; fi
if [ -z "$CONSOLE_PORT" ]; then
  if [ "$auto" = 1 ]; then CONSOLE_PORT=$(pick_port 8443 8453 8463 9443); else CONSOLE_PORT=8443; fi
fi
if [ -z "$EDGE_PORT" ]; then
  if [ "$auto" = 1 ]; then EDGE_PORT=$(pick_port 443 8444 8454 9444); else EDGE_PORT=443; fi
fi
if [ -z "$HTTP_PORT" ]; then
  HTTP_PORT=80
  if [ "$auto" = 1 ] && port_busy 80; then
    HTTP_PORT=0
    say "Port 80 is in use; Let's Encrypt HTTP validation is off (DNS validation still works)."
  fi
fi
describe_settings() {
  console_where="reachable from the network"; [ "$LOCAL_CONSOLE" = 1 ] && console_where="this machine only"
  devices_where="all addresses"; [ "$TUNNEL_ONLY" = 1 ] && devices_where="this machine only; devices use Cloudflare Tunnel"
  say "  console port $CONSOLE_PORT ($console_where); device port $EDGE_PORT ($devices_where); HTTP validation port $HTTP_PORT (0 = none)"
  if [ "$QUIC" = 1 ]; then say "  direct QUIC: UDP port $EDGE_PORT (published)"; fi
  if [ -n "$ADDRESSES" ]; then say "  addresses $ADDRESSES"; fi
}
if [ "$UNINSTALL" = 0 ]; then
  if [ "$RECALLED" = 1 ]; then
    say "Upgrading $NAME with its current settings (options given now override them; --fresh ignores them):"
  else
    say "Installing $NAME with:"
  fi
  describe_settings
fi

for p in "$CONSOLE_PORT" "$EDGE_PORT" "$HTTP_PORT"; do
  case "$p" in *[!0-9]*|"") die "ports must be numbers" ;; esac
done
case "$RELEASE_IMAGE" in @*) RELEASE_IMAGE="" ;; esac
case "$VERSION" in ""|latest|v[0-9]*) ;; *) die "--version must look like v1.2.3" ;; esac
LOWER_REPO=$(printf '%s' "$REPO" | tr 'A-Z' 'a-z')

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
  say "  AegisBorne gateway is running."
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
  if [ "$TUNNEL_ONLY" = 1 ] && [ "$QUIC" = 1 ]; then
    say "  TCP stays on this machine: devices connect through Cloudflare Tunnel (set it"
    say "  up in the console under Connectivity), and use direct QUIC where UDP gets through."
  elif [ "$TUNNEL_ONLY" = 1 ]; then
    say "  Nothing on this server is reachable from the internet. Devices connect through"
    say "  Cloudflare Tunnel: set it up in the console under Connectivity."
  else
    say "  Devices connect to TCP port $EDGE_PORT. For access from the internet, open that"
    say "  port in your firewall, or set up Cloudflare Tunnel in the console (no open ports;"
    say "  install with --tunnel-only to keep this port off the network)."
  fi
  if [ "$QUIC" = 1 ]; then
    say "  Direct QUIC: UDP port $EDGE_PORT is open to the internet. Allow it in this"
    say "  server's firewall (and the cloud provider's security group, or forward it on"
    say "  your router at home), then turn QUIC on in the console under Connectivity."
    say "  Devices fall back to the tunnel where UDP is blocked."
  fi
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
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it (Linux: curl -fsSL https://get.docker.com | sudo sh)"
  docker info >/dev/null 2>&1 || die "Docker is not running (or this user may not use it: try sudo)"
  if [ "$UNINSTALL" = 1 ]; then
    docker rm -f "$NAME" "$NAME-updater" "$NAME-updater-next" >/dev/null 2>&1 || true
    if [ "$PURGE" = 1 ]; then docker volume rm "$NAME-data" >/dev/null 2>&1 || true; say "Removed $NAME and its data."
    else say "Removed $NAME (data kept in Docker volume $NAME-data)."; fi
    return
  fi
  if [ -n "$FROM" ]; then
    [ -f "$FROM/Dockerfile" ] || die "--from: $FROM/Dockerfile missing"
    IMAGE=${IMAGE:-aegisborne/gateway:local}
    say "Building $IMAGE from $FROM..."
    docker build -q --build-arg TARGETARCH="$(host_arch)" -t "$IMAGE" "$FROM" >/dev/null
  else
    if [ -z "$IMAGE" ]; then
      if [ -n "$VERSION" ] && [ "$VERSION" != latest ]; then
        IMAGE="ghcr.io/$LOWER_REPO:${VERSION#v}"
      elif [ -z "$VERSION" ] && [ -n "$RELEASE_IMAGE" ]; then
        IMAGE=$RELEASE_IMAGE
      else
        IMAGE="ghcr.io/$LOWER_REPO:latest"
      fi
    fi
    # A release tag (X.Y.Z) never changes, so one already on this machine
    # (pulled before, or copied here from another server) is used without
    # asking the registry. Moving tags (latest, staging) are pulled; if the
    # registry can't be reached, a copy already here is used.
    if is_release_tag "$IMAGE" && docker image inspect "$IMAGE" >/dev/null 2>&1; then
      say "Using $IMAGE (already on this machine)."
    else
      say "Pulling $IMAGE..."
      if ! docker pull -q "$IMAGE" >/dev/null; then
        docker image inspect "$IMAGE" >/dev/null 2>&1 \
          || die "could not pull $IMAGE (no internet, a wrong --version, or a private image: docker login ghcr.io)"
        say "Could not reach the registry; using the copy of $IMAGE already on this machine."
      fi
    fi
  fi
  docker volume create "$NAME-data" >/dev/null
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  addrs=$(detect_addresses)
  console_bind="0.0.0.0"; [ "$LOCAL_CONSOLE" = 1 ] && console_bind="127.0.0.1"
  edge_bind="0.0.0.0"; [ "$TUNNEL_ONLY" = 1 ] && edge_bind="127.0.0.1"
  err=$(mktemp)
  run() { # extra publish flags
    # shellcheck disable=SC2086
    docker run -d --name "$NAME" --restart unless-stopped \
      --read-only --cap-drop ALL --security-opt no-new-privileges \
      --pids-limit 256 --memory 512m --tmpfs /tmp:rw,noexec,nosuid,size=16m \
      -v "$NAME-data:/var/lib/aegisnet" \
      -e AEGIS_PUBLIC_ADDRESSES="$addrs" -e AEGIS_PUBLIC_PORT="$EDGE_PORT" \
      -e AEGIS_TUNNEL_ONLY="$TUNNEL_ONLY" -e AEGIS_UPDATES="$UPDATES" \
      -p "$console_bind:$CONSOLE_PORT:8443" -p "$edge_bind:$EDGE_PORT:8444" $1 \
      "$IMAGE" >/dev/null 2>"$err"
  }
  # Direct QUIC is reached on UDP even when TCP stays local (--tunnel-only):
  # Cloudflare can't carry it.
  quic_publish=""; [ "$QUIC" = 1 ] && quic_publish="-p 0.0.0.0:$EDGE_PORT:8444/udp"
  extra="$quic_publish"; [ "$HTTP_PORT" != 0 ] && extra="$extra -p $HTTP_PORT:8080"
  if ! run "$extra"; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [ -n "$extra" ] && grep -qiE 'port is already allocated|address already in use' "$err"; then
      say "Port $HTTP_PORT is in use; continuing without Let's Encrypt HTTP validation (DNS validation still works)."
      run "$quic_publish" || { cat "$err" >&2; rm -f "$err"; die "could not start the container"; }
    else
      cat "$err" >&2; rm -f "$err"
      die "could not start the container (port $CONSOLE_PORT or $EDGE_PORT in use? try --console-port / --port)"
    fi
  fi
  rm -f "$err"
  say "Waiting for the gateway to start..."
  wait_healthy docker exec "$NAME" aegisctl health || { docker logs --tail 20 "$NAME" >&2 || true; die "the gateway did not become healthy"; }
  start_updater
  password=$(docker exec "$NAME" aegisctl initial-password 2>/dev/null || true)
  fingerprint=$(docker exec "$NAME" aegisctl console-fingerprint 2>/dev/null || echo unknown)
  print_summary "$password" "$fingerprint" "$addrs"
  name_opt=""; [ "$NAME" = aegis ] || name_opt=" --name $NAME"
  say "  Manage:  docker logs $NAME | docker restart $NAME | sh install.sh$name_opt --uninstall"
  say "  Upgrade: fetch install.sh from the newest image again and run it; data and"
  say "           settings are kept."
  say ""
}

docker_install
