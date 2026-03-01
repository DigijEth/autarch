package com.darkhal.archon.module

import android.content.Context
import android.util.Log
import com.darkhal.archon.service.LocalAdbClient
import com.darkhal.archon.util.PrefsManager
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID

/**
 * Reverse Shell module — connects back to the AUTARCH server for remote device management.
 *
 * SAFETY GATES:
 * 1. Disabled by default — must be explicitly enabled
 * 2. Three warning prompts before enabling (enforced in UI)
 * 3. Kill switch — disconnect at any time from app or by force-stopping
 * 4. Audit log — all commands logged at /data/local/tmp/archon_shell.log
 * 5. Auto-timeout — connection drops after configurable time (default 30 min)
 * 6. Server verification — only connects to configured AUTARCH server IP
 * 7. Token auth — random token per session
 *
 * The shell process (ArchonShell.java) runs via app_process at UID 2000,
 * same as ArchonServer. It connects OUTBOUND to AUTARCH's RevShellListener.
 */
class ReverseShellModule : ArchonModule {

    override val id = "revshell"
    override val name = "Reverse Shell"
    override val description = "Remote shell connection to AUTARCH server for device investigation"
    override val version = "1.0"

    companion object {
        private const val TAG = "ReverseShellModule"
        private const val PREFS_NAME = "archon_revshell"
        private const val KEY_ENABLED = "revshell_enabled"
        private const val KEY_WARNING_ACCEPTED = "revshell_warnings_accepted"
        private const val KEY_PORT = "revshell_port"
        private const val KEY_TIMEOUT = "revshell_timeout_min"
        private const val KEY_SESSION_TOKEN = "revshell_session_token"
        private const val DEFAULT_PORT = 17322
        private const val DEFAULT_TIMEOUT = 30 // minutes
        private const val SHELL_PROCESS_NAME = "archon_shell"

        // Warning messages shown before enabling (UI enforces showing all 3)
        val WARNINGS = listOf(
            "This enables a reverse shell connection to your AUTARCH server. " +
                "This gives remote shell access (UID 2000) to this device.",
            "Only enable this on devices YOU own. Never enable on someone else's device. " +
                "This is a defensive tool for investigating threats on your own phone.",
            "The reverse shell will connect to your configured AUTARCH server. " +
                "You can disable it at any time from this screen or by force-stopping the app."
        )
    }

    override fun getActions(): List<ModuleAction> = listOf(
        ModuleAction("enable", "Enable", "Accept warnings and enable reverse shell", privilegeRequired = false),
        ModuleAction("disable", "Disable", "Disable reverse shell and kill active connections", privilegeRequired = false),
        ModuleAction("connect", "Connect", "Start reverse shell to AUTARCH server"),
        ModuleAction("disconnect", "Disconnect", "Stop active reverse shell"),
        ModuleAction("status", "Status", "Check connection status", privilegeRequired = false),
    )

    override fun executeAction(actionId: String, context: Context): ModuleResult {
        return when (actionId) {
            "enable" -> enable(context)
            "disable" -> disable(context)
            "connect" -> connect(context)
            "disconnect" -> disconnect(context)
            "status" -> status(context)
            else -> ModuleResult(false, "Unknown action: $actionId")
        }
    }

    override fun getStatus(context: Context): ModuleStatus {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val enabled = prefs.getBoolean(KEY_ENABLED, false)
        val connected = isShellRunning()

        val summary = when {
            connected -> "Connected to AUTARCH"
            enabled -> "Enabled — not connected"
            else -> "Disabled"
        }

        return ModuleStatus(
            active = connected,
            summary = summary,
            details = mapOf(
                "enabled" to enabled.toString(),
                "connected" to connected.toString(),
                "port" to prefs.getInt(KEY_PORT, DEFAULT_PORT).toString(),
                "timeout" to "${prefs.getInt(KEY_TIMEOUT, DEFAULT_TIMEOUT)} min"
            )
        )
    }

    // ── Actions ─────────────────────────────────────────────────────

    private fun enable(context: Context): ModuleResult {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Check if warnings were accepted (UI sets this after showing all 3)
        if (!prefs.getBoolean(KEY_WARNING_ACCEPTED, false)) {
            return ModuleResult(
                false,
                "Warnings not accepted. Use the UI to enable — all 3 safety warnings must be acknowledged.",
                WARNINGS
            )
        }

        prefs.edit().putBoolean(KEY_ENABLED, true).apply()
        Log.i(TAG, "Reverse shell ENABLED")
        return ModuleResult(true, "Reverse shell enabled. Use 'connect' to start a session.")
    }

    private fun disable(context: Context): ModuleResult {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Kill any active shell first
        if (isShellRunning()) {
            killShell()
        }

        prefs.edit()
            .putBoolean(KEY_ENABLED, false)
            .putBoolean(KEY_WARNING_ACCEPTED, false)
            .remove(KEY_SESSION_TOKEN)
            .apply()

        Log.i(TAG, "Reverse shell DISABLED")
        return ModuleResult(true, "Reverse shell disabled. All connections terminated.")
    }

    private fun connect(context: Context): ModuleResult {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        if (!prefs.getBoolean(KEY_ENABLED, false)) {
            return ModuleResult(false, "Reverse shell is disabled. Enable it first.")
        }

        if (isShellRunning()) {
            return ModuleResult(false, "Shell is already connected. Disconnect first.")
        }

        // Get server IP from main prefs
        val serverIp = PrefsManager.getServerIp(context)
        if (serverIp.isEmpty()) {
            return ModuleResult(false, "No AUTARCH server IP configured. Set it in Settings.")
        }

        val port = prefs.getInt(KEY_PORT, DEFAULT_PORT)
        val timeout = prefs.getInt(KEY_TIMEOUT, DEFAULT_TIMEOUT)

        // Generate session token
        val token = UUID.randomUUID().toString().replace("-", "").take(32)
        prefs.edit().putString(KEY_SESSION_TOKEN, token).apply()

        // Get APK path for app_process bootstrap
        val apkPath = context.applicationInfo.sourceDir
        if (apkPath.isNullOrEmpty()) {
            return ModuleResult(false, "Could not determine APK path")
        }

        // Build bootstrap command (no --nice-name — causes abort on GrapheneOS/some ROMs)
        val bootstrapCmd = buildString {
            append("TMPDIR=/data/local/tmp ")
            append("CLASSPATH='$apkPath' ")
            append("/system/bin/app_process /system/bin ")
            append("com.darkhal.archon.server.ArchonShell ")
            append("$serverIp $port $token $timeout")
        }

        val fullCmd = "nohup sh -c \"$bootstrapCmd\" >> /data/local/tmp/archon_shell.log 2>&1 & echo started"

        Log.i(TAG, "Starting reverse shell to $serverIp:$port (timeout: ${timeout}m)")

        // Execute via LocalAdbClient (same as ArchonServer bootstrap)
        val result = if (LocalAdbClient.isConnected()) {
            LocalAdbClient.execute(fullCmd)
        } else {
            return ModuleResult(false, "No ADB connection — pair via Wireless Debugging first")
        }

        if (result.exitCode != 0 && !result.stdout.contains("started")) {
            return ModuleResult(false, "Failed to start shell: ${result.stderr}")
        }

        // Wait briefly for connection to establish
        Thread.sleep(2000)

        return if (isShellRunning()) {
            ModuleResult(true, "Connected to $serverIp:$port (timeout: ${timeout}m)")
        } else {
            ModuleResult(false, "Shell process started but may not have connected yet. Check server logs.")
        }
    }

    private fun disconnect(context: Context): ModuleResult {
        if (!isShellRunning()) {
            return ModuleResult(true, "No active shell connection")
        }

        killShell()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().remove(KEY_SESSION_TOKEN).apply()

        Thread.sleep(500)
        return if (!isShellRunning()) {
            ModuleResult(true, "Shell disconnected")
        } else {
            ModuleResult(false, "Shell process may still be running — try force-stopping the app")
        }
    }

    private fun status(context: Context): ModuleResult {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val enabled = prefs.getBoolean(KEY_ENABLED, false)
        val connected = isShellRunning()
        val serverIp = PrefsManager.getServerIp(context)
        val port = prefs.getInt(KEY_PORT, DEFAULT_PORT)
        val timeout = prefs.getInt(KEY_TIMEOUT, DEFAULT_TIMEOUT)

        val details = mutableListOf<String>()
        details.add("Enabled: $enabled")
        details.add("Connected: $connected")
        details.add("Server: $serverIp:$port")
        details.add("Timeout: ${timeout} minutes")

        if (connected) {
            // Try to read the log tail
            val logTail = try {
                val p = Runtime.getRuntime().exec(arrayOf("sh", "-c", "tail -5 /data/local/tmp/archon_shell.log 2>/dev/null"))
                p.inputStream.bufferedReader().readText().trim()
            } catch (e: Exception) { "" }
            if (logTail.isNotEmpty()) {
                details.add("--- Recent log ---")
                details.add(logTail)
            }
        }

        return ModuleResult(
            success = true,
            output = if (connected) "Connected to $serverIp:$port" else if (enabled) "Enabled — not connected" else "Disabled",
            details = details
        )
    }

    // ── Internal ────────────────────────────────────────────────────

    private fun isShellRunning(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", "pgrep -f $SHELL_PROCESS_NAME"))
            val output = process.inputStream.bufferedReader().readText().trim()
            process.waitFor()
            output.isNotEmpty()
        } catch (e: Exception) {
            false
        }
    }

    private fun killShell() {
        try {
            Runtime.getRuntime().exec(arrayOf("sh", "-c", "pkill -f $SHELL_PROCESS_NAME"))
            Log.i(TAG, "Killed reverse shell process")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to kill shell", e)
        }
    }
}
