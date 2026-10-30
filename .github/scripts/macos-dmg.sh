#!/usr/bin/env bash
# Package the macOS client as AegisBorne.app (universal binary, ad-hoc signed;
# no Apple Developer ID) in a disk image with a link to /Applications.
#
# Usage: macos-dmg.sh VERSION ARM64_BINARY X86_64_BINARY OUTPUT.dmg
set -euo pipefail

version=$1
arm64=$2
x86_64=$3
output=$4

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root="$work/root"
app="$root/AegisBorne.app"
mkdir -p "$app/Contents/MacOS"

lipo -create -output "$app/Contents/MacOS/aegis-client" "$arm64" "$x86_64"
chmod 0755 "$app/Contents/MacOS/aegis-client"

cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>en</string>
  <key>CFBundleDisplayName</key><string>AegisBorne</string>
  <key>CFBundleExecutable</key><string>aegis-client</string>
  <key>CFBundleIdentifier</key><string>borne.aegis.client</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>AegisBorne</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${version}</string>
  <key>CFBundleVersion</key><string>${version}</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLIST

# Ad-hoc signature: enough for Apple silicon; Gatekeeper still asks once
# (System Settings > Privacy & Security > Open Anyway).
codesign --force --sign - "$app"
codesign --verify "$app"

ln -s /Applications "$root/Applications"
hdiutil create -quiet -volname AegisBorne -srcfolder "$root" -ov -format UDZO "$output"
