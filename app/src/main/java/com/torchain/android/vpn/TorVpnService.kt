package com.torchain.android.vpn

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.torchain.android.R
import com.torchain.android.ui.MainActivity
import com.torchain.android.util.Logger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.IOException

class TorVpnService : VpnService() {

    private var tunFd: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.i("vpn", "TorVpnService start")
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        try {
            val builder = Builder()
                .setSession(getString(R.string.app_name))
                .addAddress(VPN_ADDRESS, 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(VPN_DNS)
                .setMtu(1500)
                .setBlocking(false)
                .allowFamily(android.system.OsConstants.AF_INET)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            val pi = PendingIntent.getActivity(
                this, 0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE
            )
            builder.setConfigureIntent(pi)

            tunFd = builder.establish()
                ?: throw IOException("VpnService.establish() returned null (user revoked?)")
            running = true
            Logger.i("vpn", "TUN established, MTU 1500, routes 0.0.0.0/0 via $VPN_ADDRESS")
        } catch (e: Exception) {
            Logger.e("vpn", "startVpn failed", e)
            stopSelf()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        running = false
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        scope.cancel()
        Logger.i("vpn", "TorVpnService destroyed")
    }

    override fun onRevoke() {
        Logger.w("vpn", "VPN revoked")
        running = false
        try { tunFd?.close() } catch (_: Exception) {}
        stopSelf()
    }

    companion object {
        private const val VPN_ADDRESS = "10.211.211.2"
        private const val VPN_DNS = "10.211.211.1"
    }
}
