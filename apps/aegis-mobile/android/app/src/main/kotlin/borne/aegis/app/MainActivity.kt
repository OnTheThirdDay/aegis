package borne.aegis.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * Hosts the Flutter UI and answers its calls on the `aegisborne/client`
 * channel. Results are the Rust core's JSON strings.
 */
class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "aegisborne/client"
        private const val VPN_CONSENT = 1
    }

    private val worker = Executors.newSingleThreadExecutor()
    private var consent: MethodChannel.Result? = null
    private var sharedText: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        takeShared(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeShared(intent)
    }

    private fun takeShared(intent: Intent?) {
        when (intent?.action) {
            Intent.ACTION_SEND -> sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            Installer.ACTION_STATUS -> installStatus(intent)
        }
    }

    /** Installing AegisBorne: show the system's confirmation when asked. */
    private fun installStatus(intent: Intent) {
        if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, 0) == PackageInstaller.STATUS_PENDING_USER_ACTION) {
            @Suppress("DEPRECATION")
            val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
            startActivity(confirm)
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            val dir = Native.dir(this)
            when (call.method) {
                "servers" -> result.success(Native.servers(dir))
                "select" -> result.success(Native.select(dir, call.argument<String>("id") ?: ""))
                "status" -> result.success(status())
                "enroll" -> background(result) { Native.enroll(dir, call.argument<String>("code") ?: "") }
                // The core disconnects first when this is the connected server.
                "forget" -> background(result) { Native.forget(dir, call.argument<String>("id") ?: "") }
                "connect" -> connect(result)
                "disconnect" -> {
                    stopService()
                    result.success(JSONObject().put("ok", true).toString())
                }
                "sharedText" -> {
                    result.success(sharedText)
                    sharedText = null
                }
                // Moving from AegisNet to AegisBorne (Migration.kt).
                "migration" -> result.success(Migration.state(this))
                "importLegacy" -> background(result) { Migration.import(this) }
                "installBorne" -> {
                    val message = try {
                        Migration.installBorne(this)
                    } catch (e: Exception) {
                        e.message ?: e.toString()
                    }
                    val out = JSONObject().put("ok", true)
                    if (message != null) out.put("message", message)
                    result.success(out.toString())
                }
                // App updates the server offers (ADR-0017).
                "checkUpdate" -> background(result) { Native.checkUpdate(dir) }
                "installUpdate" -> background(result) { installUpdate(dir) }
                // On-demand diagnostics.
                "diagStatus" -> result.success(Native.diagStatus(dir))
                "diagStart" -> result.success(Native.diagStart(dir, call.argument<Int>("minutes") ?: 15, about()))
                "diagStop" -> background(result) { Native.diagStop(dir, call.argument<Boolean>("send") ?: false) }
                "diagSend" -> background(result) { Native.diagSend(dir) }
                "diagDiscard" -> result.success(Native.diagDiscard(dir))
                "diagShare" -> result.success(shareReport(dir))
                "uninstallLegacy" -> {
                    Migration.uninstallLegacy(this)
                    result.success(JSONObject().put("ok", true).toString())
                }
                else -> result.notImplemented()
            }
        }
    }

    /** The phone, for diagnostics: maker, model and Android version. */
    private fun about() = "${Build.MANUFACTURER} ${Build.MODEL}, Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"

    /** Save the recorded report and offer it to another app (chat, mail). */
    private fun shareReport(dir: String): String {
        val saved = JSONObject(Native.diagSave(dir))
        if (!saved.optBoolean("ok")) return saved.toString()
        val file = java.io.File(saved.getString("path"))
        val send = Intent(Intent.ACTION_SEND)
            .setType("application/gzip")
            .putExtra(Intent.EXTRA_STREAM, ReportProvider.uri(this, file))
            .putExtra(Intent.EXTRA_SUBJECT, "AegisBorne diagnostics")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        startActivity(Intent.createChooser(send, getString(R.string.app_name)))
        return JSONObject().put("ok", true).toString()
    }

    /** The core's status, plus a failure from before the core took over. */
    private fun status(): String {
        val s = JSONObject(Native.status())
        val early = AegisVpnService.lastError
        if (s.optString("state") == "disconnected" && s.isNull("error") && early != null) {
            s.put("error", early)
        }
        return s.toString()
    }

    /** Download the offered update (the core checks it), then install it. */
    private fun installUpdate(dir: String): String {
        // Ask for the permission first, not after the download.
        Installer.permissionNeeded(this, getString(R.string.app_name))?.let {
            return JSONObject().put("ok", true).put("message", it).toString()
        }
        val got = JSONObject(Native.downloadUpdate(dir, java.io.File(cacheDir, "update").path))
        if (!got.optBoolean("ok")) return got.toString()
        val file = java.io.File(got.getString("path"))
        val message = Installer.install(this, file.inputStream(), packageName, getString(R.string.app_name))
        file.delete()
        val out = JSONObject().put("ok", true)
        if (message != null) out.put("message", message)
        return out.toString()
    }

    private fun background(result: MethodChannel.Result, f: () -> String) {
        worker.execute {
            val out = try {
                f()
            } catch (e: Exception) {
                JSONObject().put("ok", false).put("error", e.message ?: e.toString()).toString()
            }
            runOnUiThread { result.success(out) }
        }
    }

    private fun connect(result: MethodChannel.Result) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            // The connection notification; the VPN works without it.
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 2)
        }
        val ask = VpnService.prepare(this)
        if (ask == null) {
            startVpn(result)
        } else {
            consent?.success(JSONObject().put("ok", false).put("error", "cancelled").toString())
            consent = result
            @Suppress("DEPRECATION")
            startActivityForResult(ask, VPN_CONSENT)
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_CONSENT) return
        val result = consent ?: return
        consent = null
        if (resultCode == RESULT_OK) {
            startVpn(result)
        } else {
            Native.diagNote("the user or the system didn't allow the VPN")
            result.success(
                JSONObject().put("ok", false)
                    .put("error", "Android didn't allow the VPN connection.").toString()
            )
        }
    }

    private fun startVpn(result: MethodChannel.Result) {
        AegisVpnService.lastError = null
        startForegroundService(Intent(this, AegisVpnService::class.java).setAction(AegisVpnService.ACTION_CONNECT))
        result.success(JSONObject().put("ok", true).toString())
    }

    private fun stopService() {
        startService(Intent(this, AegisVpnService::class.java).setAction(AegisVpnService.ACTION_DISCONNECT))
    }
}
