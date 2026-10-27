package net.aegis.app

import android.content.Context
import java.io.File

/**
 * The Rust core (crates/aegis-mobile). Every call returns a JSON object:
 * `{"ok": true, ...}` or `{"ok": false, "error": "..."}`. `enroll`, `forget`
 * and `stop` block (network, shutdown): call them off the main thread.
 */
object Native {
    init {
        System.loadLibrary("aegis_mobile")
    }

    /** Where the device identity and client state live (app-private). */
    fun dir(context: Context): String = File(context.filesDir, "aegis").absolutePath

    external fun enroll(dir: String, code: String): String
    external fun device(dir: String): String
    external fun forget(dir: String): String
    external fun vpnConfig(): String
    /** Takes ownership of [fd] (a detached VPN interface descriptor). */
    external fun start(dir: String, fd: Int): String
    external fun stop(): String
    external fun status(): String
}
