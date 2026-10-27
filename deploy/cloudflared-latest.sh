#!/bin/sh
# Fetch cloudflared for the gateway image: the latest release (or
# $CLOUDFLARED_VERSION), checked against the SHA-256 Cloudflare publishes in
# the release notes and, when GitHub lists one, the asset digest.
#
#   sh deploy/cloudflared-latest.sh <amd64|arm64> OUT_DIR
#
# Writes OUT_DIR/cloudflared and OUT_DIR/cloudflared.json
# ({"version": ..., "sha256": ...}); the image installs both and aegisd
# verifies the binary against the manifest before every start.
# Needs curl and python3. GITHUB_TOKEN, if set, raises the API rate limit.
set -eu

ARCH=$1
OUT=$2
case "$ARCH" in
  amd64 | arm64) ;;
  *) echo "unsupported architecture $ARCH" >&2; exit 1 ;;
esac
ASSET="cloudflared-linux-$ARCH"
API=https://api.github.com/repos/cloudflare/cloudflared/releases
if [ -n "${CLOUDFLARED_VERSION:-}" ]; then
  URL="$API/tags/$CLOUDFLARED_VERSION"
else
  URL="$API/latest"
fi
mkdir -p "$OUT"
META="$OUT/.release.json"
set -- -fsSL --retry 3 -H "Accept: application/vnd.github+json"
[ -n "${GITHUB_TOKEN:-}" ] && set -- "$@" -H "Authorization: Bearer $GITHUB_TOKEN"
curl "$@" -o "$META" "$URL"

# version, download URL and expected digest, or a failure.
INFO=$(python3 -I - "$META" "$ASSET" <<'EOF'
import json, re, sys
release = json.load(open(sys.argv[1]))
asset = sys.argv[2]
version = release.get("tag_name", "")
if not re.fullmatch(r"\d{4}\.\d{1,2}\.\d{1,3}", version):
    sys.exit(f"unexpected cloudflared release tag {version!r}")
found = re.search(rf"^{re.escape(asset)}:\s*([0-9a-f]{{64}})\s*$", release.get("body") or "", re.M)
if not found:
    sys.exit(f"release {version} lists no SHA-256 for {asset}")
sha = found.group(1)
url = None
for a in release.get("assets", []):
    if a.get("name") == asset:
        url = a.get("browser_download_url", "")
        digest = a.get("digest")
        if digest and digest != f"sha256:{sha}":
            sys.exit(f"{asset}: GitHub's digest differs from the release notes")
prefix = f"https://github.com/cloudflare/cloudflared/releases/download/{version}/"
if not url or not url.startswith(prefix):
    sys.exit(f"release {version} has no {asset} download")
print(version, url, sha)
EOF
)
rm -f "$META"
set -- $INFO
VERSION=$1 DOWNLOAD=$2 SHA=$3

curl -fsSL --retry 3 -o "$OUT/cloudflared.part" "$DOWNLOAD"
echo "$SHA  $OUT/cloudflared.part" | sha256sum -c - >/dev/null
chmod 0755 "$OUT/cloudflared.part"
mv "$OUT/cloudflared.part" "$OUT/cloudflared"
printf '{"version":"%s","sha256":"%s"}\n' "$VERSION" "$SHA" > "$OUT/cloudflared.json"
echo "cloudflared $VERSION ($ARCH) $SHA"
