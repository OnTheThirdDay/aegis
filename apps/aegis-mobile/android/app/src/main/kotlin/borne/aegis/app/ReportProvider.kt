package borne.aegis.app

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File

/**
 * Shares a saved diagnostics report with the app the user picks (a chat
 * or mail app), for a phone that can't reach its server to send it. Not
 * exported: readers get access to the one file through the share intent's
 * read grant. Serves only files in the core's report folder.
 */
class ReportProvider : ContentProvider() {
    companion object {
        /** The core saves reports here (crates/aegis-mobile, diag::save). */
        fun folder(context: Context) = File(Native.dir(context), "diagnostics")

        /** The manifest names it after the app (the old app may be installed too). */
        fun uri(context: Context, file: File): Uri =
            Uri.parse("content://${context.packageName}.reports/${Uri.encode(file.name)}")
    }

    override fun onCreate() = true

    private fun file(uri: Uri): File? {
        val context = context ?: return null
        val name = uri.lastPathSegment ?: return null
        val folder = folder(context)
        val f = File(folder, name)
        return f.takeIf { it.parentFile == folder && it.isFile }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        if (mode != "r") throw SecurityException("read only")
        val f = file(uri) ?: return null
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY)
    }

    /** Name and size, which chat apps show. */
    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?,
    ): Cursor? {
        val f = file(uri) ?: return null
        val cursor = MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE))
        cursor.addRow(arrayOf<Any>(f.name, f.length()))
        return cursor
    }

    override fun getType(uri: Uri) = "application/gzip"
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = 0
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = 0
}
