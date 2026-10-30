package borne.aegis.app

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

    /** Where each joined server's identity and client state live (app-private). */
    fun dir(context: Context): String = File(context.filesDir, "aegis").absolutePath

    /** Join another server and select it. */
    external fun enroll(dir: String, code: String): String
    /** `{"servers": [{id, name, server, certificate_expires_at}], "selected": id}` */
    external fun servers(dir: String): String
    /** The server the next connection uses. */
    external fun select(dir: String, id: String): String
    external fun forget(dir: String, id: String): String
    external fun vpnConfig(): String
    /** Connects to the selected server; takes ownership of [fd] (a detached VPN interface descriptor). */
    external fun start(dir: String, fd: Int): String
    external fun stop(): String
    external fun status(): String
    /** `{"version": v | null}`: a newer app the server offers (cached for hours). Blocks. */
    external fun checkUpdate(dir: String): String
    /** Download the offered update into [into]; `{"path"}`. Blocks. */
    external fun downloadUpdate(dir: String, into: String): String

    // On-demand diagnostics (crates/aegis-mobile/src/diag.rs).
    /** Record for 1-60 minutes; [about] describes the phone. */
    external fun diagStart(dir: String, minutes: Int, about: String): String
    /** Stop; with [send], send the report (blocks). */
    external fun diagStop(dir: String, send: Boolean): String
    /** `{"sent", "message"}`. Blocks. */
    external fun diagSend(dir: String): String
    /** Save the report to share; `{"path"}`. */
    external fun diagSave(dir: String): String
    external fun diagDiscard(dir: String): String
    /** Record a problem seen here (no-op unless recording). */
    external fun diagNote(text: String): String
    /** `{state, remaining_seconds, events, sending, result}` */
    external fun diagStatus(dir: String): String
}
