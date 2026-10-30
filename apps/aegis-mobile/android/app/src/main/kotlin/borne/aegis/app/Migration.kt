package borne.aegis.app

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import org.json.JSONObject
import java.io.File

/**
 * Moving from the old app (AegisNet, `net.aegis.app`) to AegisBorne
 * (`borne.aegis.app`). Both are built from this code (Gradle flavors
 * `legacy` and `borne`) and signed with the same key. The old app carries
 * the AegisBorne APK and installs it; AegisBorne then takes the old app's
 * servers (profiles and identities) through [MigrationProvider], once, and
 * connects as the same devices.
 *
 * Only an app signed with our key can ask for the servers (a signature
 * permission, checked again on both sides), and the identities never leave
 * the phone.
 */
object Migration {
    const val LEGACY = "net.aegis.app"
    const val BORNE = "borne.aegis.app"
    const val AUTHORITY = "net.aegis.app.migration"
    const val PERMISSION = "borne.aegis.app.permission.MIGRATE"
    const val EXPORT = "export"
    /** AegisBorne confirms that it keeps every exported server. */
    const val IMPORTED = "imported"

    /** The AegisBorne APK inside the legacy build (added by CI). */
    private const val BUNDLED_APK = "aegisborne.apk"
    /** As `aegis_join` names server folders. */
    private val SERVER_ID = Regex("[0-9a-f]{16}")

    fun isLegacy(context: Context) = context.packageName == LEGACY

    fun installed(context: Context, pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }

    /** Installed and signed with the same key as this app. */
    fun trusted(context: Context, pkg: String): Boolean =
        installed(context, pkg) &&
            context.packageManager.checkSignatures(context.packageName, pkg) == PackageManager.SIGNATURE_MATCH

    /** Set in the old app once AegisBorne confirmed it keeps its servers. */
    private fun movedFlag(context: Context) = File(context.filesDir, "moved-to-aegisborne")

    /** Set in AegisBorne once it took the old app's servers (never again). */
    private fun importedFlag(context: Context) = File(context.filesDir, "imported-from-aegisnet")

    /** For the UI: which app this is and how far the move got. */
    fun state(context: Context): String = JSONObject()
        .put("ok", true)
        .put("legacy", isLegacy(context))
        .put("moved", isLegacy(context) && movedFlag(context).exists())
        .put("other_installed", installed(context, if (isLegacy(context)) BORNE else LEGACY))
        .toString()

    // ---- the old app: hand the servers over ----

    /** Every file of every joined server, except per-connection state. */
    fun export(context: Context): Bundle {
        val dir = File(Native.dir(context))
        // Opening the list first moves a single-server profile into it.
        Native.servers(dir.path)
        val paths = ArrayList<String>()
        val out = Bundle()
        dir.walkTopDown()
            .filter { it.isFile && !it.name.startsWith("state.db") }
            .forEach { f ->
                val rel = f.relativeTo(dir).invariantSeparatorsPath
                paths += rel
                out.putByteArray(rel, f.readBytes())
            }
        out.putStringArrayList("files", paths)
        return out
    }

    /**
     * AegisBorne holds the servers now ([IMPORTED]): only then does the old
     * app say they moved and offer to uninstall itself, which deletes its
     * copy of the identities.
     */
    fun confirmMoved(context: Context) {
        movedFlag(context).writeText("")
    }

    /**
     * Install the bundled AegisBorne, or open it if it is installed. Returns
     * null when the system took over, or a message for the user.
     */
    fun installBorne(context: Context): String? {
        if (installed(context, BORNE)) {
            val open = context.packageManager.getLaunchIntentForPackage(BORNE)
                ?: return "AegisBorne is installed; open it from the home screen."
            context.startActivity(open)
            return null
        }
        val apk = try {
            context.assets.open(BUNDLED_APK)
        } catch (_: java.io.IOException) {
            return "This build doesn't include AegisBorne. Download it from your server instead."
        }
        return Installer.install(context, apk, BORNE, "AegisNet")
    }

    // ---- AegisBorne: take the servers ----

    /**
     * Take the old app's servers into [dir], once: only servers not already
     * here, and its selection if this app has none. Returns
     * `{"ok", "imported": n, "legacy": "absent"|"outdated"|"untrusted"|"done"|"ok"}`.
     */
    fun import(context: Context): String {
        val result = JSONObject().put("ok", true).put("imported", 0)
        val legacy = when {
            importedFlag(context).exists() -> "done"
            !installed(context, LEGACY) -> "absent"
            !trusted(context, LEGACY) -> "untrusted"
            context.packageManager.resolveContentProvider(AUTHORITY, 0)?.packageName != LEGACY -> "outdated"
            else -> "ok"
        }
        result.put("legacy", legacy)
        if (legacy != "ok") return result.toString()
        val files = try {
            context.contentResolver.call(Uri.parse("content://$AUTHORITY"), EXPORT, null, null)
        } catch (e: SecurityException) {
            return result.put("legacy", "untrusted").toString()
        } ?: return result.put("legacy", "outdated").toString()
        val dir = File(Native.dir(context))
        val n = try {
            importFiles(dir, files)
        } catch (e: java.io.IOException) {
            // Nothing is confirmed: the old app keeps its servers, and
            // opening AegisBorne again tries again.
            return JSONObject().put("ok", false).put("error", "Could not take the servers over: ${e.message}").toString()
        }
        if (!holdsAll(dir, files)) {
            return JSONObject().put("ok", false).put("error", "Could not take every server over; open AegisBorne again to retry.").toString()
        }
        importedFlag(context).writeText("")
        try {
            context.contentResolver.call(Uri.parse("content://$AUTHORITY"), IMPORTED, null, null)
        } catch (_: Exception) {
            // An old app that doesn't ask for this confirmation.
        }
        return result.put("imported", n).toString()
    }

    /** Every server in the export is in [dir] now. */
    private fun holdsAll(dir: File, files: Bundle): Boolean =
        (files.getStringArrayList("files") ?: arrayListOf())
            .mapNotNull { p -> p.split('/').takeIf { it.size >= 3 && it[0] == "servers" }?.get(1) }
            .filter { SERVER_ID.matches(it) }
            .all { File(dir, "servers/$it").isDirectory }

    private fun importFiles(dir: File, files: Bundle): Int {
        val paths = files.getStringArrayList("files") ?: return 0
        val byServer = paths
            .mapNotNull { p -> p.split('/').takeIf { it.size >= 3 && it[0] == "servers" }?.let { it[1] to p } }
            .groupBy({ it.first }, { it.second })
            .filterKeys { SERVER_ID.matches(it) && !File(dir, "servers/$it").exists() }
        val staging = File(dir, ".import")
        staging.deleteRecursively()
        var added = 0
        for ((id, list) in byServer) {
            val tmp = File(staging, id)
            for (p in list) {
                val rel = p.removePrefix("servers/$id/")
                if (rel.split('/').any { it.isEmpty() || it == "." || it == ".." }) continue
                val bytes = files.getByteArray(p) ?: continue
                val f = File(tmp, rel)
                f.parentFile?.mkdirs()
                f.writeBytes(bytes)
            }
            val target = File(dir, "servers/$id")
            target.parentFile?.mkdirs()
            if (!tmp.renameTo(target)) throw java.io.IOException("could not keep server $id")
            added++
        }
        staging.deleteRecursively()
        val selected = files.getByteArray("servers/selected")?.toString(Charsets.UTF_8)?.trim()
        val mine = File(dir, "servers/selected")
        if (selected != null && SERVER_ID.matches(selected) && !mine.exists() && File(dir, "servers/$selected").exists()) {
            mine.writeText(selected)
        }
        return added
    }

    /** Ask Android to uninstall the old app (the user confirms). */
    fun uninstallLegacy(context: Context) {
        context.startActivity(
            Intent(Intent.ACTION_DELETE, Uri.parse("package:$LEGACY")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }
}
