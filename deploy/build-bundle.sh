#!/bin/sh
# Offline / development build of the gateway (releases are built by
# .github/workflows/release.yml). Run on Linux/WSL from the repository:
#
#   sh deploy/build-bundle.sh [OUT_DIR]
#   sudo sh OUT_DIR/aegisnet-gateway/install.sh --from OUT_DIR/aegisnet-gateway [--native]
#
# Produces OUT_DIR/aegisnet-gateway/ with the same layout as the release
# packages and image context: bin/<arch>/{aegisd,aegisctl,cloudflared},
# clients/, Dockerfile and install.sh. cloudflared is checked against the
# pinned SHA-256 before it is included.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$REPO/dist"}
TARGET_DIR=${CARGO_TARGET_DIR:-"$REPO/target"}
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/Cargo.toml" | head -1)
CFD_VERSION=2026.10.0
case "$(uname -m)" in
  x86_64) ARCH=amd64; CFD_SHA=d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db ;;
  aarch64) ARCH=arm64; CFD_SHA=e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08 ;;
  *) echo "unsupported build architecture" >&2; exit 1 ;;
esac
DEST="$OUT/aegisnet-gateway"

cd "$REPO"
cargo build --locked --release -p aegisd -p aegisctl
rm -rf "$DEST"
mkdir -p "$DEST/bin/$ARCH" "$DEST/clients"
cp "$TARGET_DIR/release/aegisd" "$TARGET_DIR/release/aegisctl" "$DEST/bin/$ARCH/"

CACHE="$OUT/.cache"
mkdir -p "$CACHE"
CFD="$CACHE/cloudflared-linux-$ARCH-$CFD_VERSION"
if [ ! -f "$CFD" ]; then
  curl -fsSL -o "$CFD.part" "https://github.com/cloudflare/cloudflared/releases/download/$CFD_VERSION/cloudflared-linux-$ARCH"
  mv "$CFD.part" "$CFD"
fi
echo "$CFD_SHA  $CFD" | sha256sum -c -
install -m 0755 "$CFD" "$DEST/bin/$ARCH/cloudflared"

if rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-gnu \
   && command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc \
  CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
  AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
  CFLAGS_x86_64_pc_windows_gnu="-D_WIN32_WINNT=0x0A00 -DWINVER=0x0A00" \
    cargo build --locked --release --target x86_64-pc-windows-gnu -p aegis-client
  cp "$TARGET_DIR/x86_64-pc-windows-gnu/release/aegis-client.exe" \
     "$DEST/clients/aegis-client-windows-x86_64.exe"
else
  echo "note: Windows client not built (add the x86_64-pc-windows-gnu target and mingw-w64)" >&2
fi

cp deploy/install.sh "$DEST/install.sh"
cp deploy/Dockerfile.prebuilt "$DEST/Dockerfile"
echo "built: $DEST (version $VERSION, $ARCH)"
