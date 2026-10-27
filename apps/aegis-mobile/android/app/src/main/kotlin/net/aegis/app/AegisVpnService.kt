package net.aegis.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.json.JSONObject
import java.util.concurrent.Executors

/**
 * The VPN: sets up the interface from the Rust core's settings, hands its
 * descriptor to the core, and stays in the foreground while connected. The
 * app itself is excluded, so its own connection to the gateway goes direct.
 */
class AegisVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "net.aegis.app.CONNECT"
        const val ACTION_DISCONNECT = "net.aegis.app.DISCONNECT"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION = 1
        private const val WATCH_MS = 2000L

        /** Why the last connect attempt failed before the core took over. */
        @Volatile
        var lastError: String? = null
    }

    private val worker = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var running = false
    private var shown: String? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        // ACTION_CONNECT, or the system starting an always-on VPN.
        connect()
        return START_STICKY
    }

    private fun connect() {
        lastError = null
        foreground(getString(R.string.vpn_connecting))
        running = true
        worker.execute {
            val error = try {
                establish()
            } catch (e: Exception) {
                e.message ?: e.toString()
            }
            if (error != null) {
                lastError = error
                main.post { finish() }
            } else {
                main.post { watch() }
            }
        }
    }

    /** Build the interface and start the core; returns an error or null. */
    private fun establish(): String? {
        val cfg = JSONObject(Native.vpnConfig())
        val b = Builder()
            .setSession(getString(R.string.app_name))
            .setMtu(cfg.getInt("mtu"))
            .addAddress(cfg.getString("address"), cfg.getInt("prefix"))
            .addAddress(cfg.getString("address6"), cfg.getInt("prefix6"))
            .addDnsServer(cfg.getString("dns"))
        for (key in listOf("routes", "routes6")) {
            val routes = cfg.getJSONArray(key)
            for (i in 0 until routes.length()) {
                val r = routes.getJSONObject(i)
                b.addRoute(r.getString("address"), r.getInt("prefix"))
            }
        }
        try {
            b.addDisallowedApplication(packageName)
        } catch (_: PackageManager.NameNotFoundException) {
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) b.setMetered(false)
        val pfd = b.establish() ?: return getString(R.string.vpn_not_allowed)
        val result = JSONObject(Native.start(Native.dir(this), pfd.detachFd()))
        return if (result.optBoolean("ok")) null else result.optString("error")
    }

    /** Keep the notification current; stop when the core disconnected. */
    private fun watch() {
        if (!running) return
        val s = JSONObject(Native.status())
        when (s.optString("state")) {
            "disconnected" -> {
                lastError = s.optString("error").ifEmpty { null }
                finish()
                return
            }
            "connected" -> foreground(getString(R.string.vpn_connected, s.optString("server")))
            else -> foreground(getString(R.string.vpn_connecting))
        }
        main.postDelayed({ watch() }, WATCH_MS)
    }

    private fun disconnect() {
        running = false
        worker.execute {
            Native.stop()
            main.post { finish() }
        }
    }

    private fun finish() {
        running = false
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // Another VPN took over, or the user revoked it in system settings.
        disconnect()
    }

    override fun onDestroy() {
        running = false
        worker.execute { Native.stop() }
        worker.shutdown()
        super.onDestroy()
    }

    private fun foreground(text: String) {
        if (text == shown) return
        shown = text
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, getString(R.string.vpn_channel), NotificationManager.IMPORTANCE_LOW)
        )
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, AegisVpnService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE
        )
        val n = Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.disconnect), stop).build())
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        } else {
            startForeground(NOTIFICATION, n)
        }
    }
}
