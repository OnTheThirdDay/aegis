#!/bin/sh
# Offline / development build of the gateway (releases are built by
# .github/workflows/release.yml). Run on Linux/WSL from the repository:
#
#   sh deploy/build-bundle.sh [OUT_DIR]
#   sudo sh OUT_DIR/aegisborne-gateway/install.sh --from OUT_DIR/aegisborne-gateway
#
# Produces OUT_DIR/aegisborne-gateway/ with the same layout as the release
# image context: bin/<arch>/{aegisd,aegisctl,cloudflared}, clients/,
# Dockerfile and install.sh; the installer builds the image from it.
# cloudflared is the latest release (or $CLOUDFLARED_VERSION), checked
# against Cloudflare's published SHA-256 (deploy/cloudflared-latest.sh).
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$REPO/dist"}
TARGET_DIR=${CARGO_TARGET_DIR:-"$REPO/target"}
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$REPO/Cargo.toml" | head -1)
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "unsupported build architecture" >&2; exit 1 ;;
esac
DEST="$OUT/aegisborne-gateway"

cd "$REPO"
cargo build --locked --release -p aegisd -p aegisctl
rm -rf "$DEST"
mkdir -p "$DEST/bin/$ARCH" "$DEST/clients"
cp "$TARGET_DIR/release/aegisd" "$TARGET_DIR/release/aegisctl" "$DEST/bin/$ARCH/"

sh "$REPO/deploy/cloudflared-latest.sh" "$ARCH" "$DEST/bin/$ARCH"

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
