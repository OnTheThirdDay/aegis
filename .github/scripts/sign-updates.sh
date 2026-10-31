#!/usr/bin/env bash
# Sign the client builds in DIR as app updates (ADR-0017): for each one,
# write FILE.update with its platform, version, size, SHA-256 and an Ed25519
# signature over the statement the apps verify (aegis-join update.rs).
#
#   sign-updates.sh DIR VERSION [BUILDS]
#   BUILDS  optional "FILE VERSION" lines for builds carried from an earlier
#           release, which are signed as the version they are
#   AEGIS_UPDATE_SIGNING_KEY  the private key (PEM, PKCS#8)
set -euo pipefail

dir=$1
release_version=$2
builds=${3:-}
[ -n "${AEGIS_UPDATE_SIGNING_KEY:-}" ] || { echo "AEGIS_UPDATE_SIGNING_KEY is not set" >&2; exit 1; }
key=$(mktemp)
trap 'rm -f "$key" "$key.statement"' EXIT
printf '%s\n' "$AEGIS_UPDATE_SIGNING_KEY" > "$key"

platform_of() {
  case "$1" in
    aegis-client-windows-x86_64.exe) echo windows-x86_64 ;;
    aegis-client-linux-x86_64) echo linux-x86_64 ;;
    aegis-client-macos.dmg) echo macos ;;
    aegis-client-android-arm64.apk) echo android-arm64 ;;
    aegis-client-android-x86_64.apk) echo android-x86_64 ;;
    aegis-client-ios.ipa) echo ios ;;
  esac
}

signed=0
for path in "$dir"/*; do
  file=$(basename "$path")
  platform=$(platform_of "$file")
  [ -n "$platform" ] || continue
  version=$release_version
  if [ -n "$builds" ] && [ -f "$builds" ]; then
    carried=$(awk -v f="$file" '$1 == f { print $2 }' "$builds")
    version=${carried:-$release_version}
  fi
  size=$(stat -c %s "$path")
  sha=$(sha256sum "$path" | cut -d' ' -f1)
  printf 'aegisborne-update/1\nplatform=%s\nversion=%s\nfile=%s\nsize=%s\nsha256=%s\n' \
    "$platform" "$version" "$file" "$size" "$sha" > "$key.statement"
  signature=$(openssl pkeyutl -sign -inkey "$key" -rawin -in "$key.statement" | base64 -w0)
  printf '{"platform":"%s","version":"%s","file":"%s","size":%s,"sha256":"%s","signature":"%s"}\n' \
    "$platform" "$version" "$file" "$size" "$sha" "$signature" > "$path.update"
  echo "signed $file ($platform $version)"
  signed=$((signed + 1))
done
[ "$signed" -gt 0 ] || { echo "no client builds to sign in $dir" >&2; exit 1; }
