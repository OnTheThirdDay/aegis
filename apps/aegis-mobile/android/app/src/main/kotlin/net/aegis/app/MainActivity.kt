package net.aegis.app

import android.Manifest
import android.content.Intent
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
 * Hosts the Flutter UI and answers its calls on the `aegisnet/client`
 * channel. Results are the Rust core's JSON strings.
 */
class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "aegisnet/client"
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
        if (intent?.action == Intent.ACTION_SEND) {
            sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
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
                else -> result.notImplemented()
            }
        }
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
