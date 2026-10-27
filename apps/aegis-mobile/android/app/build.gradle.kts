import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing: android/key.properties (local) or AEGIS_ANDROID_* (CI).
// Without either, release builds are signed with the debug key.
val keyProperties = Properties().apply {
    val f = rootProject.file("key.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}
fun signing(name: String, env: String): String? =
    keyProperties.getProperty(name) ?: System.getenv(env)

android {
    namespace = "net.aegis.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "net.aegis.app"
        minSdk = 26
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        // The ABIs the Rust core is built for (scripts/build-rust-android.sh).
        // Split builds choose theirs with --target-platform instead.
        if (!project.hasProperty("split-per-abi")) {
            ndk {
                abiFilters += listOf("arm64-v8a", "x86_64")
            }
        }
    }

    signingConfigs {
        val store = signing("storeFile", "AEGIS_ANDROID_KEYSTORE")
        if (store != null) {
            create("release") {
                storeFile = file(store)
                storePassword = signing("storePassword", "AEGIS_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = signing("keyAlias", "AEGIS_ANDROID_KEY_ALIAS")
                keyPassword = signing("keyPassword", "AEGIS_ANDROID_KEY_PASSWORD")
            }
        }
    }

    // Compressed native libraries: a smaller download for sideloading.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}
