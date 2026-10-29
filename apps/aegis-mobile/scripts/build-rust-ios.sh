#!/usr/bin/env bash
# Build the mobile Rust core (crates/aegis-mobile) for iOS as a static
# library and package it as ios/AegisCore.xcframework, which the app and its
# packet tunnel link (macOS with Xcode).
#
#   TARGETS  space-separated subset of "aarch64-apple-ios aarch64-apple-ios-sim"
#   PROFILE  release (default) or debug
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
repo="$(cd "$here/../.." && pwd)"
profile="${PROFILE:-release}"
targets="${TARGETS:-aarch64-apple-ios aarch64-apple-ios-sim}"
# The app's minimum (ios/Flutter/AppFrameworkInfo.plist, the project).
export IPHONEOS_DEPLOYMENT_TARGET=16.0

args=()
for target in $targets; do
  flags=(--locked -p aegis-mobile --target "$target" --crate-type staticlib)
  [ "$profile" = release ] && flags+=(--release)
  (cd "$repo" && cargo rustc "${flags[@]}")
  lib="${CARGO_TARGET_DIR:-$repo/target}/$target/$profile/libaegis_mobile.a"
  echo "$target: $(du -h "$lib" | cut -f1)"
  args+=(-library "$lib" -headers "$here/ios/AegisCore/include")
done
out="$here/ios/AegisCore.xcframework"
rm -rf "$out"
xcodebuild -create-xcframework "${args[@]}" -output "$out" >/dev/null
echo "wrote $out"
