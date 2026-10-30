# AegisBorne mobile app

Flutter UI over the Rust core in `crates/aegis-mobile` ([ADR-0011](../../docs/adr/0011-mobile-client.md)), on Android and iOS ([ADR-0018](../../docs/adr/0018-ios-app.md)).

## Build (Android)

1. Rust core, from WSL or Linux with the NDK (r28c by default at `~/android/android-ndk-r28c`, or set `ANDROID_NDK_HOME`):

   ```sh
   bash apps/aegis-mobile/scripts/build-rust-android.sh            # arm64-v8a + x86_64
   ABIS=x86_64 bash apps/aegis-mobile/scripts/build-rust-android.sh # emulator only
   ```

   This places `libaegis_mobile.so` under `android/app/src/main/jniLibs/`.
2. App, with Flutter, the Android SDK and Java 17:

   ```sh
   cd apps/aegis-mobile
   flutter build apk --release --flavor borne --split-per-abi --target-platform android-arm64
   ```

   Every Android build names a flavor (`flutter run --flavor borne` too):
   - `borne`: AegisBorne, `borne.aegis.app`.
   - `legacy`: the last update of the old app ID, AegisNet (`net.aegis.app`). It carries AegisBorne at `android/app/src/legacy/assets/aegisborne.apk` (copied in by the release workflow, not committed), installs it and hands its servers over. See `Migration.kt` and [ADR-0016](../../docs/adr/0016-rename-to-aegisborne.md).

   Release signing reads `android/key.properties` (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`) or the `AEGIS_ANDROID_*` environment variables; otherwise the debug key is used.

## Build (iOS)

On macOS with Xcode and Rust (`rustup target add aarch64-apple-ios aarch64-apple-ios-sim`):

```sh
bash apps/aegis-mobile/scripts/build-rust-ios.sh   # ios/AegisCore.xcframework
cd apps/aegis-mobile
flutter build ios --release --no-codesign
```

Signed builds need the App IDs `borne.aegis.app` and `borne.aegis.app.tunnel` with the Network Extension capability and the App Group `group.borne.aegis.app` ([ADR-0018](../../docs/adr/0018-ios-app.md)).

## Layout

- `lib/`: the UI (`main.dart`) and the method channel `aegisborne/client` (`client.dart`).
- `android/app/src/main/kotlin/net/aegis/app/`:
  - `MainActivity`: the channel and VPN consent;
  - `AegisVpnService`: the VPN interface and foreground service;
  - `Native`: the JNI bindings;
  - `Migration`, `MigrationProvider`: moving from the old app to AegisBorne;
  - `Installer`: installing APKs (AegisBorne from the old app, app updates).
- `ios/Runner/AegisChannel.swift`: the channel on iOS, and starting the tunnel.
- `ios/AegisTunnel/PacketTunnelProvider.swift`: the VPN (packet tunnel extension).
- `ios/AegisCore/include/`: the Rust core's C interface.
