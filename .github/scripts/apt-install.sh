#!/usr/bin/env bash
# Install Ubuntu packages on a hosted runner without hanging silently:
#   bash .github/scripts/apt-install.sh PACKAGE...
#
# * Downloads time out and retry; the package database lock (another apt or
#   unattended-upgrades on a fresh runner) is waited for 3 minutes at most.
# * Each command is limited, timestamped and shows its output.
# * The man-page index isn't rebuilt (minutes, silently, on hosted runners).
# * Runners download from Azure's Ubuntu mirror, which sometimes stops
#   delivering; then the install is retried from archive.ubuntu.com.
# * On failure the apt/dpkg processes still running and apt's log are
#   printed, so a hang says where it was.
set -uo pipefail

apt=(sudo DEBIAN_FRONTEND=noninteractive apt-get
  -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
  -o DPkg::Lock::Timeout=180)
sudo rm -f /var/lib/man-db/auto-update

# run SECONDS COMMAND...
run() {
  local limit=$1
  shift
  echo "::group::$(date -u +%T) $*"
  timeout "${APT_STEP_TIMEOUT:-$limit}" "$@"
  local rc=$?
  echo "$(date -u +%T) exit $rc"
  echo "::endgroup::"
  return "$rc"
}

install() {
  run 120 "${apt[@]}" update && run "$1" "${apt[@]}" install -y "${@:2}"
}

if install 180 "$@"; then
  exit 0
fi
echo "::warning::The runner's package mirror didn't deliver; retrying from archive.ubuntu.com"
for f in /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list; do
  [ -f "$f" ] && sudo sed -i \
    -e 's#mirror+file:/etc/apt/apt-mirrors.txt#http://archive.ubuntu.com/ubuntu/#g' \
    -e 's#http://azure.archive.ubuntu.com/ubuntu#http://archive.ubuntu.com/ubuntu#g' "$f"
done
if install 300 "$@"; then
  exit 0
fi
echo "::error::apt-get did not finish installing $*"
echo "Still running:"
ps -eo pid,etime,cmd | grep -E '[a]pt|[d]pkg|[u]nattended' || echo "(no apt or dpkg processes)"
echo "Last lines of /var/log/apt/term.log:"
sudo tail -n 40 /var/log/apt/term.log 2>/dev/null || true
exit 1
