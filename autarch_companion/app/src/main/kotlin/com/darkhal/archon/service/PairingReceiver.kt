package com.darkhal.archon.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.RemoteInput
import com.darkhal.archon.R
import com.darkhal.archon.server.ArchonClient

/**
 * Handles the pairing code entered via notification inline reply.
 *
 * Flow (like Shizuku):
 * 1. User taps "START PAIRING" in Setup
 * 2. App shows notification with text input for pairing code
 * 3. User opens Developer Options > Wireless Debugging > Pair with code
 * 4. User pulls down notification shade and enters the 6-digit code
 * 5. This receiver auto-detects port, pairs, connects, starts ArchonServer
 */
class PairingReceiver : BroadcastReceiver() {

    companion object {
        private const val TAG = "PairingReceiver"
        const val ACTION_PAIR = "com.darkhal.archon.ACTION_PAIR"
        const val KEY_PAIRING_CODE = "pairing_code"
        const val NOTIFICATION_ID = 42
        const val CHANNEL_ID = "archon_pairing"

        /**
         * Show the pairing notification with inline text input.
         */
        fun showPairingNotification(context: Context) {
            createChannel(context)

            val replyIntent = Intent(ACTION_PAIR).apply {
                setPackage(context.packageName)
            }
            val replyPending = PendingIntent.getBroadcast(
                context, 0, replyIntent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
            )

            val remoteInput = RemoteInput.Builder(KEY_PAIRING_CODE)
                .setLabel("6-digit pairing code")
                .build()

            val action = NotificationCompat.Action.Builder(
                R.drawable.ic_archon,
                "Enter pairing code",
                replyPending
            )
                .addRemoteInput(remoteInput)
                .build()

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_archon)
                .setContentTitle("Archon — Wireless Debugging Pairing")
                .setContentText("Open Settings > Developer Options > Wireless Debugging > Pair with code")
                .setStyle(NotificationCompat.BigTextStyle()
                    .bigText("1. Open Settings > Developer Options\n" +
                            "2. Enable Wireless Debugging\n" +
                            "3. Tap 'Pair with pairing code'\n" +
                            "4. Enter the 6-digit code below"))
                .addAction(action)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(false)
                .build()

            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(NOTIFICATION_ID, notification)
        }

        /**
         * Update the notification with a status message (no input).
         */
        fun updateNotification(context: Context, message: String, ongoing: Boolean = false) {
            createChannel(context)

            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_archon)
                .setContentTitle("Archon Pairing")
                .setContentText(message)
                .setOngoing(ongoing)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(!ongoing)
                .build()

            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(NOTIFICATION_ID, notification)
        }

        /**
         * Dismiss the pairing notification.
         */
        fun dismissNotification(context: Context) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.cancel(NOTIFICATION_ID)
        }

        private fun createChannel(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    "Wireless Debugging Pairing",
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = "Used for entering the wireless debugging pairing code"
                }
                val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                nm.createNotificationChannel(channel)
            }
        }
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION_PAIR) return

        val remoteInput = RemoteInput.getResultsFromIntent(intent)
        val code = remoteInput?.getCharSequence(KEY_PAIRING_CODE)?.toString()?.trim()

        if (code.isNullOrEmpty()) {
            updateNotification(context, "No code entered — try again")
            showPairingNotification(context)
            return
        }

        Log.i(TAG, "Received pairing code: $code")
        updateNotification(context, "Pairing with code $code...", ongoing = true)

        // Run pairing in background thread
        Thread {
            try {
                // Auto-detect pairing port
                Log.i(TAG, "Discovering pairing port...")
                val port = LocalAdbClient.discoverPairingPort(context)
                if (port == null) {
                    Log.w(TAG, "Could not find pairing port")
                    updateNotification(context, "Failed: no pairing port found. Is the Pair dialog still open?")
                    Thread.sleep(3000)
                    showPairingNotification(context)
                    return@Thread
                }

                Log.i(TAG, "Found pairing port: $port, pairing...")
                updateNotification(context, "Found port $port, pairing...", ongoing = true)

                val success = LocalAdbClient.pair(context, "127.0.0.1", port, code)
                if (!success) {
                    Log.w(TAG, "Pairing failed")
                    updateNotification(context, "Pairing failed — wrong code or port changed. Try again.")
                    Thread.sleep(3000)
                    showPairingNotification(context)
                    return@Thread
                }

                Log.i(TAG, "Paired! Waiting for connect service...")
                updateNotification(context, "Paired! Waiting for ADB connect service...", ongoing = true)

                // Wait for wireless debugging to register the connect service after pairing
                Thread.sleep(2000)

                // Try to discover and connect with retries
                var connectSuccess = false
                for (attempt in 1..3) {
                    Log.i(TAG, "Connect attempt $attempt/3...")
                    updateNotification(context, "Connecting (attempt $attempt/3)...", ongoing = true)

                    val connectPort = LocalAdbClient.discoverConnectPort(context, timeoutSec = 8)
                    if (connectPort != null) {
                        Log.i(TAG, "Found connect port: $connectPort")
                        connectSuccess = LocalAdbClient.connect(context, "127.0.0.1", connectPort)
                        if (connectSuccess) {
                            Log.i(TAG, "Connected on port $connectPort")
                            break
                        }
                        Log.w(TAG, "Connect failed on port $connectPort")
                    } else {
                        Log.w(TAG, "mDNS connect discovery failed (attempt $attempt)")
                    }

                    if (attempt < 3) Thread.sleep(2000)
                }

                if (!connectSuccess) {
                    Log.w(TAG, "All connect attempts failed")
                    updateNotification(context, "Paired but connect failed. Open Setup tab and tap START SERVER.", ongoing = false)
                    return@Thread
                }

                // Try to start ArchonServer
                updateNotification(context, "Connected! Starting Archon Server...", ongoing = true)
                val result = ArchonClient.startServer(context)

                val msg = if (result.success) {
                    "Paired + connected + Archon Server running!"
                } else {
                    "Paired + connected! Server: ${result.message}"
                }

                Log.i(TAG, msg)
                updateNotification(context, msg, ongoing = false)

            } catch (e: Exception) {
                Log.e(TAG, "Pairing error", e)
                updateNotification(context, "Error: ${e.message}")
            }
        }.start()
    }
}
