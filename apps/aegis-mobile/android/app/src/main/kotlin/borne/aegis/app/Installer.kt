package borne.aegis.app

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.net.Uri
import android.provider.Settings
import java.io.InputStream

/**
 * Installs an APK with Android's package installer: AegisBorne from the old
 * app ([Migration]), or an update of this app that the server offered and
 * the Rust core checked (ADR-0017). Android asks the user to confirm, and
 * installs an update only when it is signed with the same key.
 */
object Installer {
    const val ACTION_STATUS = "borne.aegis.app.INSTALL_STATUS"

    /**
     * Null when this app may install apps; otherwise opens the setting that
     * allows it and returns a message for the user.
     */
    fun permissionNeeded(context: Context, appName: String): String? {
        if (context.packageManager.canRequestPackageInstalls()) return null
        context.startActivity(
            Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        return "Allow $appName to install apps, then press the button again."
    }

    /**
     * Install [apk] as [pkg]. Returns null when Android took over (it shows
     * its confirmation), or a message for the user.
     */
    fun install(context: Context, apk: InputStream, pkg: String, appName: String): String? {
        permissionNeeded(context, appName)?.let {
            apk.close()
            return it
        }
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
        params.setAppPackageName(pkg)
        val id = installer.createSession(params)
        installer.openSession(id).use { session ->
            apk.use { input ->
                session.openWrite("app", 0, -1).use { output ->
                    input.copyTo(output)
                    session.fsync(output)
                }
            }
            // The result comes back to MainActivity, which shows the
            // system's confirmation when it asks for one.
            val status = Intent(context, MainActivity::class.java).setAction(ACTION_STATUS)
            val pending = PendingIntent.getActivity(
                context, id, status,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
            )
            session.commit(pending.intentSender)
        }
        return null
    }
}
