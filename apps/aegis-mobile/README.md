# AegisNet mobile app

Flutter UI over the Rust core in `crates/aegis-mobile` ([ADR-0011](../../docs/adr/0011-mobile-client.md)). Android first; iOS later on the same core.

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
   flutter build apk --release --split-per-abi --target-platform android-arm64
   ```

   Release signing reads `android/key.properties` (`storeFile`, `storePassword`, `keyAlias`, `keyPassword`) or the `AEGIS_ANDROID_*` environment variables; otherwise the debug key is used.

## Layout

- `lib/`: the UI (`main.dart`) and the method channel `aegisnet/client` (`client.dart`).
- `android/app/src/main/kotlin/net/aegis/app/`:
  - `MainActivity`: the channel and VPN consent;
  - `AegisVpnService`: the VPN interface and foreground service;
  - `Native`: the JNI bindings.
