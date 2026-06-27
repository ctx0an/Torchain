package com.torchain.android.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.torchain.android.R
import com.torchain.android.TorchainApp
import com.torchain.android.data.Config
import com.torchain.android.data.TorState
import com.torchain.android.data.TorStatus
import com.torchain.android.tor.TorController
import com.torchain.android.ui.MainActivity
import com.torchain.android.util.Logger
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class TorService : LifecycleService() {

    private lateinit var tor: TorController
    private var statusJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        tor = TorController(this)
        startForeground(NOTIF_ID, buildNotification("Torchain starting..."))
        statusJob = lifecycleScope.launch {
            tor.status.collectLatest { s ->
                updateNotification(s)
                broadcastState(s)
            }
        }
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent); return null
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_START -> startTor()
            ACTION_STOP  -> stopTor()
            ACTION_ROTATE -> lifecycleScope.launch { tor.rotateIdentity() }
            ACTION_PANIC -> lifecycleScope.launch { tor.panic() }
        }
        return START_STICKY
    }

    private fun startTor() {
        lifecycleScope.launch {
            val config = Config.flow(this@TorService).first()
            val ok = tor.start(config)
            if (ok) {
                val vpnIntent = Intent(this@TorService, com.torchain.android.vpn.TorVpnService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(vpnIntent)
                else startService(vpnIntent)
            }
        }
    }

    private fun stopTor() {
        lifecycleScope.launch {
            try {
                stopService(Intent(this@TorService, com.torchain.android.vpn.TorVpnService::class.java))
            } catch (e: Exception) { Logger.w("TorService", "stop vpn failed", e) }
            tor.stop()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun updateNotification(s: TorStatus) {
        val msg = when (val st = s.state) {
            is TorState.Stopped -> "Stopped"
            is TorState.Starting -> "Starting..."
            is TorState.Bootstrapping -> "Bootstrap ${st.progress}% - ${st.tag}"
            is TorState.Running -> "Running - exit ${s.exitIp.ifEmpty { "..." }}"
            is TorState.Stopping -> "Stopping..."
            is TorState.Error -> "Error: ${st.message.take(80)}"
        }
        val nm = getSystemService(NotificationManager::class.java) ?: return
        nm.notify(NOTIF_ID, buildNotification(msg))
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, TorService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this, TorchainApp.CHANNEL_TOR)
            .setSmallIcon(R.drawable.ic_torchain)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(0, "Stop", stopIntent)
            .build()
    }

    private fun broadcastState(s: TorStatus) {
        val intent = Intent(ACTION_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATE, s.state::class.java.simpleName)
            putExtra(EXTRA_PID, s.pid)
            putExtra(EXTRA_SOCKS, s.socksPort)
            putExtra(EXTRA_CONTROL, s.controlPort)
            putExtra(EXTRA_EXIT_IP, s.exitIp)
            putExtra(EXTRA_MESSAGE, s.message)
            val st = s.state
            if (st is TorState.Bootstrapping) {
                putExtra(EXTRA_PROGRESS, st.progress)
                putExtra(EXTRA_TAG, st.tag)
            }
        }
        androidx.localbroadcastmanager.content.LocalBroadcastManager
            .getInstance(this).sendBroadcast(intent)
    }

    override fun onDestroy() {
        statusJob?.cancel()
        lifecycleScope.launch { tor.stop() }
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.torchain.android.START"
        const val ACTION_STOP = "com.torchain.android.STOP"
        const val ACTION_ROTATE = "com.torchain.android.ROTATE"
        const val ACTION_PANIC = "com.torchain.android.PANIC"
        const val ACTION_STATUS = "com.torchain.android.STATUS"
        const val EXTRA_STATE = "state"
        const val EXTRA_PID = "pid"
        const val EXTRA_SOCKS = "socks"
        const val EXTRA_CONTROL = "control"
        const val EXTRA_EXIT_IP = "exit_ip"
        const val EXTRA_MESSAGE = "message"
        const val EXTRA_PROGRESS = "progress"
        const val EXTRA_TAG = "tag"
        const val NOTIF_ID = 1

        fun start(ctx: Context) {
            val i = Intent(ctx, TorService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) ctx.startForegroundService(i)
            else ctx.startService(i)
        }
        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, TorService::class.java).setAction(ACTION_STOP))
        }
        fun rotate(ctx: Context) {
            ctx.startService(Intent(ctx, TorService::class.java).setAction(ACTION_ROTATE))
        }
        fun panic(ctx: Context) {
            ctx.startService(Intent(ctx, TorService::class.java).setAction(ACTION_PANIC))
        }
    }
}
