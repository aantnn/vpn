package ru.valishin.vpn

import android.Manifest
import android.app.Service

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.os.Debug
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.annotation.RequiresPermission
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer


import java.net.InetAddress

class MyVpnService : VpnService() {
    external fun runRustVpnLoop(fd: Int)
    external fun initRust()
    external fun requestRustShutdown()

    private var logger= initRust()
    private var vpnInterface: ParcelFileDescriptor? = null
        private var vpnJob: Job? = null
            private val channelId = "vpn_service_channel"

            override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
                if (intent?.action == "ACTION_STOP") {
                    stopVpn()
                    return START_NOT_STICKY
                }

                // Check if we are already doing work
                if (isRunning) {
                    return START_STICKY
                }

                isRunning = true
                startForeground(1001, createNotification())

                vpnJob = CoroutineScope(Dispatchers.IO).launch {
                    try {
                        runVpnEngine()
                    } finally {
                        // Reset flag if engine stops
                        isRunning = false
                    }
                }

                return START_STICKY
            }

            @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
            private suspend fun runVpnEngine() {
                try {
                    val builder = Builder()
                    // 1. Basic Config
                    builder.setSession("MyVPN")
                    builder.addAddress("10.10.0.2", 24)
                    builder.addRoute("10.10.0.0", 24)
                    builder.addDnsServer("8.8.8.8")


                    // 2. The OpenVPN "Stability" Trick:
                    // Instead of just calling allowBypass(), we explicitly exclude the app packages
                    // that should NOT be part of the tunnel (including the debugger).
                    try {
                        builder.addDisallowedApplication(packageName) // Your app (Debugger traffic)
                        builder.addDisallowedApplication("com.android.shell") // ADB
                    } catch (e: Exception) {
                        // Fallback for older devices or missing packages
                    }

                    // 3. Essential for ping replies and local connectivity
                    builder.allowBypass()

                    // 4. Critical: Link the VPN to the actual physical network
                    // This matches the logic at line 1179 in the OpenVPN source
                    val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                        val activeNetwork = cm.activeNetwork
                        if (activeNetwork != null) {
                            builder.setUnderlyingNetworks(arrayOf(activeNetwork))
                        }
                    }

                    vpnInterface = builder.establish()
                    val fd = vpnInterface!!.fd

                    Log.d("VPN", "Handing FD $fd over to Rust...")

                    // 3. Call Rust (This is a blocking call as per your Rust block_on)
                    // Since this is a suspend function, run it in a proper dispatcher
                    withContext(Dispatchers.IO) {
                        Debug.waitForDebugger()
                        runRustVpnLoop(fd)
                    }

                } catch (e: Exception) {
                    Log.e("VPN", "Error in Rust VPN engine", e)
                } finally {
                    if (isRunning) {
                        stopVpn()
                    }
                }
            }

            private fun createNotification(): Notification {
                // Create Notification Channel for API 26+
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    val channel = NotificationChannel(channelId, "VPN Status", NotificationManager.IMPORTANCE_LOW)
                    getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
                }

                val stopIntent = Intent(this, MyVpnService::class.java).apply { action = "ACTION_STOP" }
                val pendingStop = PendingIntent.getService(this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE)

                return NotificationCompat.Builder(this, channelId)
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setContentTitle("VPN is Active")
                .setContentText("Connected in a separate process.")
                .setOngoing(true)
                .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pendingStop)
                .build()
            }

            private fun stopVpn() {
                isRunning = false
                requestRustShutdown()
                vpnJob?.cancel()
                vpnInterface?.close()
                vpnInterface = null
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()

            }

            override fun onDestroy() {
                if (isRunning) {
                    stopVpn()
                }
                super.onDestroy()
            }
    companion object {
        // Used to load the 'vpn' library on application startup.
        init {
            //try {
                // 1 = enabled, 0 = disabled, "full" = more detail
                //Os.setenv("RUST_BACKTRACE", "full", true)
                //Os.setenv("RUST_LIB_BACKTRACE", "full", true)
           // } catch (e: Exception) {
                //e.printStackTrace()
            //}
            System.loadLibrary("vpn")
        }
        var isRunning = false
            private set
    }
}
