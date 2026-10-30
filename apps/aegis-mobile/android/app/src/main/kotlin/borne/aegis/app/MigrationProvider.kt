package borne.aegis.app

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.PackageManager
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/**
 * In the old app only (legacy flavor): hands every joined server to
 * AegisBorne ([Migration]). Answers nothing but [Migration.EXPORT] and
 * [Migration.IMPORTED], and only to AegisBorne signed with this app's key.
 */
class MigrationProvider : ContentProvider() {
    override fun onCreate() = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        val context = context ?: return null
        val caller = callingPackage
        if ((method != Migration.EXPORT && method != Migration.IMPORTED) ||
            caller != Migration.BORNE ||
            context.checkCallingPermission(Migration.PERMISSION) != PackageManager.PERMISSION_GRANTED ||
            !Migration.trusted(context, caller)
        ) {
            throw SecurityException("not allowed")
        }
        if (method == Migration.IMPORTED) {
            Migration.confirmMoved(context)
            return Bundle()
        }
        return Migration.export(context)
    }

    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
}
