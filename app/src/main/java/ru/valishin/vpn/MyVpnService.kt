package ru.valishin.vpn

import android.Manifest
import android.app.Service

import android.app.*
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkRequest
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
    external fun runRustVpnLoop(fd: Int): Any?
    external fun initRust(): Any?
    external fun requestRustShutdown(): Any?
    external fun reconnectRustTunnel(fd: Int): Any?
    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnJob: Job? = null
    private val channelId = "vpn_service_channel"
    // Store reference to network callbacks so we can unregister them later
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    // currentNetwork is the underlying/default network used by the tunnel
    private var currentNetwork: android.net.Network? = null
    // cached copy of whatever the system considers the active/default network

            override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
                Log.d("VPN_APP", "onStartCommand: PID=${android.os.Process.myPid()}")
                if (intent?.action == null || intent?.action == "ACTION_START" ) {
                    Log.d("VPN_APP", "onStartCommand: action=${intent?.action}")
                    try {
                        Log.d("VPN_APP", "onStartCommand: Calling initRust()")
                        initRust()
                        Log.d("VPN_APP", "onStartCommand: initRust() completed successfully")
                    } catch (e: Exception) {
                        Log.e("VPN_APP", "Failed to init Rust", e)
                    }
                }
                else if (intent?.action == "ACTION_STOP") {
                    Log.d("VPN_APP", "onStartCommand: ACTION_STOP received, calling stopVpn()")
                    stopVpn()
                    return START_NOT_STICKY
                }

                // Check if we are already doing work
                if (isRunning) {
                    Log.d("VPN_APP", "onStartCommand: Already running, returning START_STICKY")
                    return START_STICKY
                }

                Log.d("VPN_APP", "onStartCommand: Starting VPN engine coroutine")
                isRunning = true
                startForeground(1001, createNotification())

                vpnJob = CoroutineScope(Dispatchers.IO).launch {
                    try {
                        Log.d("VPN_APP", "Coroutine: calling runVpnEngine()")
                        runVpnEngine()
                    } finally {
                        Log.d("VPN_APP", "Coroutine: VpnEngine stopped, resetting isRunning flag")
                        isRunning = false
                    }
                }

                Log.d("VPN_APP", "onStartCommand: Returning START_STICKY")
                return START_STICKY
            }

            @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
            private suspend fun runVpnEngine() {
                try {
                    Log.d("VPN_APP", "runVpnEngine: Establishing initial tunnel...")
                    // Initial Setup
                    val fd1 = establishTunnel() ?: run {
                        Log.e("VPN_APP", "runVpnEngine: establishTunnel() returned null. Aborting.")
                        return
                    }
                    val fd = fd1.fd
                    Log.d("VPN_APP", "runVpnEngine: Handing Initial FD $fd over to Rust...")

                    Log.d("VPN_APP", "runVpnEngine: Registering Network Listener...")
                    // Register Network Listener to automatically reconnect when routing changes
                    registerNetworkListener()

                    Log.d("VPN_APP", "runVpnEngine: Switching context to IO to call runRustVpnLoop()...")
                    // Call Rust (This is a blocking call as per your Rust block_on)
                    // Since this is a suspend function, run it in a proper dispatcher
                    withContext(Dispatchers.IO) {
                        Log.d("VPN_APP", "runVpnEngine: Waiting for debugger (commented natively). Executing JNI loop.")
                        Debug.waitForDebugger()
                        val latestFd = vpnInterface?.fd ?: fd
                        Log.d("VPN_APP", "runVpnEngine: Debugger wait over. Actually launching JNI loop with FD $latestFd (was originally $fd)")
                        runRustVpnLoop(latestFd)
                        Log.d("VPN_APP", "runVpnEngine: runRustVpnLoop(fd) RETURNED. Loop finished.")
                    }

                } catch (e: Exception) {
                    Log.e("VPN_APP", "Error in Rust VPN engine", e)
                } finally {
                    Log.d("VPN_APP", "runVpnEngine: Finally block executing, isRunning=$isRunning")
                    if (isRunning) {
                        stopVpn()
                    }
                }
            }


    private fun establishTunnel(): ParcelFileDescriptor? {
                Log.d("VPN_APP", "establishTunnel: Start execution")
                try {
                    val builder = Builder()
                    Log.d("VPN_APP", "establishTunnel: Builder created, configuring IPs and routes")
                    builder.setSession("MyVPN")
                    builder.addAddress("10.10.0.2", 24)
                    builder.addRoute("10.10.0.0", 24)
                    builder.addDnsServer("8.8.8.8")

                    try {
                        Log.d("VPN_APP", "establishTunnel: Disallowing current package & ADB")
                        builder.addDisallowedApplication(packageName)
                        builder.addDisallowedApplication("com.android.shell")
                    } catch (e: Exception) {
                        Log.w("VPN_APP", "establishTunnel: Failed to disallow application", e)
                    }
                    builder.allowBypass()

                    val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                        val activeNetwork = cm.activeNetwork
                        if (activeNetwork != null) {
                            Log.d("VPN_APP", "establishTunnel: Found active underlying network: $activeNetwork")
                            builder.setUnderlyingNetworks(arrayOf(activeNetwork))
                            currentNetwork = activeNetwork
                        } else {
                            Log.w("VPN_APP", "establishTunnel: Active network is NULL. Tunnel may lack outbound connectivity.")
                        }
                    }

                    Log.d("VPN_APP", "establishTunnel: Calling builder.establish()...")
                    val newVpnInterface = builder.establish()
                    if (newVpnInterface != null) {

                        return newVpnInterface
                    } else {
                        Log.e("VPN_APP", "establishTunnel: builder.establish() returned null! Missing VPN permissions or system blocked it?")
                    }
                } catch (e: Exception) {
                    Log.e("VPN_APP", "Error establishing new tunnel", e)
                }
                Log.d("VPN_APP", "establishTunnel: Returning null due to failure.")
                return null
            }


    private fun registerNetworkListener() {
                Log.d("VPN_APP", "registerNetworkListener: Registering explicit NetworkRequest for Wi-Fi and Cellular")
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

                // Build a specific request for non-VPN internet networks
                val request = NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build()

                networkCallback = object : ConnectivityManager.NetworkCallback() {
                    @RequiresPermission(Manifest.permission.ACCESS_NETWORK_STATE)
                    override fun onAvailable(network: android.net.Network) {

                        // only consider the network if it's currently the cached default
                        Log.d("VPN_APP", "NetworkCallback.onAvailable() triggered for network: $network")
                        if (network == currentNetwork) {
                            Log.d("VPN_APP", "=> NetworkCallback: Network $network is already the active tunnel network, ignoring explicit reconnect.")
                            return
                        }

                        Log.d("VPN_APP", "=> NetworkCallback: Network genuinely changed. Triggering reconnect sequence...")
                        currentNetwork = network

                        // We must rebuild the tunnel routes for the new network and pass the fd to Rust
                        Log.d("VPN_APP", "=> NetworkCallback: Calling establishTunnel()...")
                        val newVpnInterface = establishTunnel()
                        val newFd = newVpnInterface?.fd
                        if (newFd != null) {
                            Log.d("VPN_APP", "=> NetworkCallback: establishTunnel SUCCESS. Handing new FD ($newFd) to Rust via reconnectRustTunnel()...")
                            reconnectRustTunnel(newFd)
                            val oldVpnInterface = vpnInterface
                            vpnInterface = newVpnInterface // Update the current interface

                            if (oldVpnInterface != null) {
                                Log.d("VPN_APP", "establishTunnel: Closing previously open VPN Interface natively (FD: ${oldVpnInterface.fd})")
                                oldVpnInterface.close() // Close the old one after updating
                            }
                            Log.d("VPN_APP", "=> NetworkCallback: reconnectRustTunnel execution completed.")
                        } else {
                            Log.e("VPN_APP", "=> NetworkCallback: Failed to get new FD during network change.")
                        }
                    }

                    override fun onLost(network: android.net.Network) {
                        Log.w("VPN_APP", "NetworkCallback.onLost() triggered for network: $network")
                        if (network == currentNetwork) {
                            Log.w("VPN_APP", "=> NetworkCallback: Primary active network disappeared! Tunnel is effectively frozen.")
                            currentNetwork = null
                            Log.d("VPN_APP", "=> NetworkCallback: Network genuinely changed. Triggering reconnect sequence...")
                            Log.d("VPN_APP", "=> NetworkCallback: Calling establishTunnel()...")
                            val newVpnInterface = establishTunnel()
                            val newFd = newVpnInterface?.fd
                            if (newFd != null) {
                                Log.d("VPN_APP", "=> NetworkCallback: establishTunnel SUCCESS. Handing new FD ($newFd) to Rust via reconnectRustTunnel()...")
                                reconnectRustTunnel(newFd)
                                Log.d("VPN_APP", "establishTunnel: successfully established. Got new Interface! FD: $newFd")

                                val oldVpnInterface = vpnInterface
                                vpnInterface = newVpnInterface // Update the current interface

                                if (oldVpnInterface != null) {
                                    Log.d("VPN_APP", "establishTunnel: Closing previously open VPN Interface natively (FD: ${oldVpnInterface.fd})")
                                    oldVpnInterface.close() // Close the old one after updating
                                }
                                Log.d("VPN_APP", "=> NetworkCallback: reconnectRustTunnel execution completed.")
                            } else {
                                Log.e("VPN_APP", "=> NetworkCallback: Failed to get new FD during network change.")
                            }

                        }
                    }
                }

                try {
                    cm.registerNetworkCallback(request, networkCallback!!)
                    Log.d("VPN_APP", "registerNetworkListener: Success.")
                } catch (e: Exception) {
                    Log.e("VPN_APP", "registerNetworkListener: Exception during registration", e)
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

                // Unregister our network observers to prevent leaks
                val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                networkCallback?.let {
                    try {
                        cm.unregisterNetworkCallback(it)
                    } catch (e: Exception) {
                        Log.e("VPN", "Failed to unregister network callback", e)
                    }
                }
                networkCallback = null
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