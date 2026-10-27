#!/usr/bin/env bash
# Install Ubuntu packages on a hosted runner without hanging silently:
#   bash .github/scripts/apt-install.sh PACKAGE...
#
# * Downloads time out and retry; the package database lock (another apt or
#   unattended-upgrades on a fresh runner) is waited for 3 minutes at most.
# * Each command is limited, timestamped and shows its output.
# * The man-page index isn't rebuilt (minutes, silently, on hosted runners).
# * On failure the apt/dpkg processes still running and apt's log are
#   printed, so a hang says where it was.
set -uo pipefail

apt=(sudo DEBIAN_FRONTEND=noninteractive apt-get
  -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30
  -o DPkg::Lock::Timeout=180)
sudo rm -f /var/lib/man-db/auto-update

run() {
  echo "::group::$(date -u +%T) $*"
  timeout "${APT_STEP_TIMEOUT:-300}" "$@"
  local rc=$?
  echo "$(date -u +%T) exit $rc"
  echo "::endgroup::"
  return "$rc"
}

if run "${apt[@]}" update && run "${apt[@]}" install -y "$@"; then
  exit 0
fi
echo "::error::apt-get did not finish installing $*"
echo "Still running:"
ps -eo pid,etime,cmd | grep -E '[a]pt|[d]pkg|[u]nattended' || echo "(no apt or dpkg processes)"
echo "Last lines of /var/log/apt/term.log:"
sudo tail -n 40 /var/log/apt/term.log 2>/dev/null || true
exit 1
