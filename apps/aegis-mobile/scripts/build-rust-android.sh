#!/usr/bin/env bash
# Build the mobile Rust core (crates/aegis-mobile) for Android and place it
# where Gradle packages it: android/app/src/main/jniLibs/<abi>/.
#
#   ANDROID_NDK_HOME  NDK root (default: ~/android/android-ndk-r28c)
#   ABIS              space-separated subset of "arm64-v8a x86_64"
#   PROFILE           release (default) or debug
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="$(cd "$here/../.." && pwd)"
ndk="${ANDROID_NDK_HOME:-$HOME/android/android-ndk-r28c}"
api=26
profile="${PROFILE:-release}"
abis="${ABIS:-arm64-v8a x86_64}"

case "$(uname -s)" in
  Linux) host=linux-x86_64 ;;
  Darwin) host=darwin-x86_64 ;;
  *) echo "unsupported build host" >&2; exit 1 ;;
esac
bin="$ndk/toolchains/llvm/prebuilt/$host/bin"
[ -x "$bin/llvm-ar" ] || { echo "NDK not found at $ndk (set ANDROID_NDK_HOME)" >&2; exit 1; }

for abi in $abis; do
  case "$abi" in
    arm64-v8a) target=aarch64-linux-android ;;
    x86_64) target=x86_64-linux-android ;;
    *) echo "unknown ABI $abi" >&2; exit 1 ;;
  esac
  env_target="$(echo "$target" | tr 'a-z-' 'A-Z_')"
  cc="$bin/$target$api-clang"
  # NDK r28 links with 16 KB page alignment (required from Android 15).
  export "CC_${target//-/_}=$cc" "AR_${target//-/_}=$bin/llvm-ar" \
    "CARGO_TARGET_${env_target}_LINKER=$cc"
  flags=(--locked -p aegis-mobile --target "$target")
  [ "$profile" = release ] && flags+=(--release)
  (cd "$repo" && cargo build "${flags[@]}")
  out="${CARGO_TARGET_DIR:-$repo/target}/$target/$profile/libaegis_mobile.so"
  mkdir -p "$here/android/app/src/main/jniLibs/$abi"
  cp "$out" "$here/android/app/src/main/jniLibs/$abi/libaegis_mobile.so"
  echo "$abi: $(du -h "$out" | cut -f1)"
done
