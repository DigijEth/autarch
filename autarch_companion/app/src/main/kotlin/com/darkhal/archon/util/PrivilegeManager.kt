package com.darkhal.archon.util

import android.content.Context
import android.util.Log
import com.darkhal.archon.server.ArchonClient
import com.darkhal.archon.service.LocalAdbClient
import java.net.HttpURLConnection
import java.net.URL

/**
 * Central privilege escalation chain manager.
 * Tries methods in order: ROOT → ARCHON_SERVER → LOCAL_ADB → SERVER_ADB → NONE
 *
 * ARCHON_SERVER is our own privileged process running at UID 2000 (shell level),
 * started via app_process through an ADB connection. It replaces Shizuku entirely.
 */
object PrivilegeManager {

    private const val TAG = "PrivilegeManager"

    enum class Method(val label: String) {
        ROOT("Root (su)"),
        ARCHON_SERVER("Archon Server"),
        LOCAL_ADB("Wireless ADB"),
        SERVER_ADB("Server ADB"),
        NONE("No privileges")
    }

    private var cachedMethod: Method? = null
    private var serverIp: String = ""
    private var serverPort: Int = 8181
    private var appContext: Context? = null

    /**
     * Initialize with app context and server connection info.
     */
    fun init(context: Context, serverIp: String = "", serverPort: Int = 8181) {
        appContext = context.applicationContext
        this.serverIp = serverIp
        this.serverPort = serverPort
        cachedMethod = null
    }

    /**
     * Update the AUTARCH server connection info.
     */
    fun setServerConnection(ip: String, port: Int) {
        serverIp = ip
        serverPort = port
        if (cachedMethod == Method.SERVER_ADB || cachedMethod == Method.NONE) {
            cachedMethod = null
        }
    }

    /**
     * Determine the best available privilege method.
     */
    fun getAvailableMethod(): Method {
        cachedMethod?.let { return it }

        val method = when {
            checkRoot() -> Method.ROOT
            checkArchonServer() -> Method.ARCHON_SERVER
            checkLocalAdb() -> Method.LOCAL_ADB
            checkServerAdb() -> Method.SERVER_ADB
            else -> Method.NONE
        }

        cachedMethod = method
        Log.i(TAG, "Available method: ${method.name}")
        return method
    }

    /**
     * Force a re-check of available methods.
     */
    fun refreshMethod(): Method {
        cachedMethod = null
        return getAvailableMethod()
    }

    fun isReady(): Boolean = getAvailableMethod() != Method.NONE

    /**
     * Execute a command via the best available method.
     */
    fun execute(command: String): ShellResult {
        return when (getAvailableMethod()) {
            Method.ROOT -> executeViaRoot(command)
            Method.ARCHON_SERVER -> executeViaArchonServer(command)
            Method.LOCAL_ADB -> executeViaLocalAdb(command)
            Method.SERVER_ADB -> executeViaServer(command)
            Method.NONE -> ShellResult("", "No privilege method available — run Setup first", -1)
        }
    }

    fun getStatusDescription(): String {
        return when (getAvailableMethod()) {
            Method.ROOT -> "Connected via root shell"
            Method.ARCHON_SERVER -> "Connected via Archon Server (UID 2000)"
            Method.LOCAL_ADB -> "Connected via Wireless ADB"
            Method.SERVER_ADB -> "Connected via AUTARCH server ($serverIp)"
            Method.NONE -> "No privilege access — run Setup"
        }
    }

    // ── Method checks ─────────────────────────────────────────────

    private fun checkRoot(): Boolean {
        return ShellExecutor.isRootAvailable()
    }

    private fun checkArchonServer(): Boolean {
        val ctx = appContext ?: return false
        return ArchonClient.isServerRunning(ctx)
    }

    private fun checkLocalAdb(): Boolean {
        return LocalAdbClient.isConnected()
    }

    private fun checkServerAdb(): Boolean {
        if (serverIp.isEmpty()) return false
        return try {
            val url = URL("https://$serverIp:$serverPort/hardware/status")
            val conn = url.openConnection() as HttpURLConnection
            SslHelper.trustSelfSigned(conn)
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            conn.requestMethod = "GET"
            val code = conn.responseCode
            conn.disconnect()
            code in 200..399
        } catch (e: Exception) {
            false
        }
    }

    // ── Execution backends ────────────────────────────────────────

    private fun executeViaRoot(command: String): ShellResult {
        return ShellExecutor.executeAsRoot(command)
    }

    private fun executeViaArchonServer(command: String): ShellResult {
        val ctx = appContext ?: return ShellResult("", "No app context", -1)
        return ArchonClient.execute(ctx, command)
    }

    private fun executeViaLocalAdb(command: String): ShellResult {
        return LocalAdbClient.execute(command)
    }

    private fun executeViaServer(command: String): ShellResult {
        if (serverIp.isEmpty()) {
            return ShellResult("", "Server not configured", -1)
        }

        return try {
            val url = URL("https://$serverIp:$serverPort/hardware/adb/shell")
            val conn = url.openConnection() as HttpURLConnection
            SslHelper.trustSelfSigned(conn)
            conn.connectTimeout = 5000
            conn.readTimeout = 15000
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true

            val payload = """{"serial":"any","command":"$command"}"""
            conn.outputStream.write(payload.toByteArray())

            val responseCode = conn.responseCode
            val response = if (responseCode in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $responseCode"
            }
            conn.disconnect()

            if (responseCode in 200..299) {
                val stdout = extractJsonField(response, "stdout") ?: response
                val stderr = extractJsonField(response, "stderr") ?: ""
                val exitCode = extractJsonField(response, "exit_code")?.toIntOrNull() ?: 0
                ShellResult(stdout, stderr, exitCode)
            } else {
                ShellResult("", "Server HTTP $responseCode: $response", -1)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Server execute failed", e)
            ShellResult("", "Server error: ${e.message}", -1)
        }
    }

    private fun extractJsonField(json: String, field: String): String? {
        val pattern = """"$field"\s*:\s*"([^"]*?)"""".toRegex()
        val match = pattern.find(json)
        return match?.groupValues?.get(1)
    }
}
