package com.darkhal.archon.server

import android.content.Context
import android.util.Log
import com.darkhal.archon.service.LocalAdbClient
import com.darkhal.archon.util.AuthManager
import com.darkhal.archon.util.PrefsManager
import com.darkhal.archon.util.ShellResult
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.net.InetSocketAddress
import java.net.Socket
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Client for the Archon privileged server process.
 *
 * Handles:
 * - Bootstrapping the server via ADB (app_process command)
 * - TCP socket communication with JSON protocol
 * - Token-based authentication
 * - Server lifecycle management
 */
object ArchonClient {

    private const val TAG = "ArchonClient"
    private const val DEFAULT_PORT = 17321
    private const val PREFS_NAME = "archon_server"
    private const val KEY_TOKEN = "server_token"
    private const val KEY_PORT = "server_port"
    private const val CONNECT_TIMEOUT = 3000
    private const val READ_TIMEOUT = 30000

    private val serverRunning = AtomicBoolean(false)
    private var serverPid: Int = -1

    /**
     * Check if the Archon server is running and responding.
     */
    fun isServerRunning(context: Context): Boolean {
        val token = getToken(context) ?: return false
        val port = getPort(context)
        return try {
            val result = sendCommand(token, port, "__ping__")
            val alive = result.exitCode == 0 && result.stdout == "pong"
            serverRunning.set(alive)
            alive
        } catch (e: Exception) {
            serverRunning.set(false)
            false
        }
    }

    /**
     * Get server info (UID, PID, uptime) if running.
     */
    fun getServerInfo(context: Context): String? {
        val token = getToken(context) ?: return null
        val port = getPort(context)
        return try {
            val result = sendCommand(token, port, "__info__")
            if (result.exitCode == 0) result.stdout else null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Start the Archon server via ADB.
     *
     * Bootstrap flow:
     * 1. Get APK path from context
     * 2. Generate random auth token
     * 3. Build app_process command
     * 4. Execute via LocalAdbClient or AUTARCH server ADB
     * 5. Wait for server to start
     * 6. Verify connection
     */
    /**
     * Check if any ArchonServer is alive on the port (no auth needed).
     */
    fun isServerAlive(): Boolean {
        return try {
            val result = sendCommand("", DEFAULT_PORT, "__alive__", 3)
            result.exitCode == 0 && result.stdout == "alive"
        } catch (e: Exception) {
            false
        }
    }

    fun startServer(context: Context): StartResult {
        // Check if a server is already running (possibly started from web UI)
        if (isServerAlive()) {
            Log.i(TAG, "Server already alive on port $DEFAULT_PORT")
            // If we also have a valid token, verify full auth
            if (isServerRunning(context)) {
                val info = getServerInfo(context) ?: "running"
                return StartResult(true, "Server already running: $info")
            }
            // Server alive but we don't have the right token
            return StartResult(false, "Server running but token mismatch — stop it first (web UI or: adb shell pkill -f ArchonServer)")
        }

        // Generate new token for this session
        val token = UUID.randomUUID().toString().replace("-", "").take(32)
        val port = DEFAULT_PORT

        // Save token and port
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_TOKEN, token)
            .putInt(KEY_PORT, port)
            .apply()

        // Get APK path
        val apkPath = context.applicationInfo.sourceDir
        if (apkPath.isNullOrEmpty()) {
            return StartResult(false, "Could not determine APK path")
        }

        // Build the bootstrap command (modeled after Shizuku's ServiceStarter pattern)
        // TMPDIR is needed so dalvik-cache can be created by shell user
        val bootstrapCmd = buildString {
            append("TMPDIR=/data/local/tmp ")
            append("CLASSPATH='$apkPath' ")
            append("/system/bin/app_process /system/bin ")
            append("com.darkhal.archon.server.ArchonServer ")
            append("$token $port")
        }

        // Wrap in nohup + background so it survives ADB disconnect
        val fullCmd = "nohup sh -c \"$bootstrapCmd\" > /data/local/tmp/archon_server.log 2>&1 & echo started"

        Log.i(TAG, "Bootstrap command: $bootstrapCmd")

        // Try to execute — LocalAdbClient first, then AUTARCH server USB ADB
        val adbResult = if (LocalAdbClient.isConnected()) {
            Log.i(TAG, "Starting server via LocalAdbClient")
            val r = LocalAdbClient.execute(fullCmd)
            Log.i(TAG, "LocalAdb result: exit=${r.exitCode} stdout=${r.stdout.take(200)} stderr=${r.stderr.take(200)}")
            r
        } else {
            Log.i(TAG, "LocalAdb not connected, trying AUTARCH server USB ADB")
            val httpResult = startServerViaHttp(context, apkPath, token, port)
            if (httpResult != null) {
                Log.i(TAG, "HTTP bootstrap result: exit=${httpResult.exitCode} stdout=${httpResult.stdout.take(200)} stderr=${httpResult.stderr.take(200)}")
                httpResult
            } else {
                Log.e(TAG, "Both ADB methods failed — no connection available")
                return StartResult(false, "No ADB connection — connect phone via USB to AUTARCH, or use Wireless Debugging")
            }
        }

        if (adbResult.exitCode != 0 && !adbResult.stdout.contains("started")) {
            Log.e(TAG, "Bootstrap command failed: exit=${adbResult.exitCode} stdout=${adbResult.stdout} stderr=${adbResult.stderr}")
            return StartResult(false, "ADB command failed (exit ${adbResult.exitCode}): ${adbResult.stderr.ifEmpty { adbResult.stdout }}")
        }

        // Wait for server to come up
        Log.i(TAG, "Waiting for server to start...")
        for (i in 1..10) {
            Thread.sleep(500)
            if (isServerRunning(context)) {
                val info = getServerInfo(context) ?: "running"
                Log.i(TAG, "Server started: $info")
                return StartResult(true, "Server running: $info")
            }
        }

        return StartResult(false, "Server did not start within 5s — check /data/local/tmp/archon_server.log")
    }

    /**
     * Execute a shell command via the Archon server.
     */
    fun execute(context: Context, command: String, timeoutSec: Int = 30): ShellResult {
        val token = getToken(context)
            ?: return ShellResult("", "No server token — start server first", -1)
        val port = getPort(context)

        return try {
            sendCommand(token, port, command, timeoutSec)
        } catch (e: Exception) {
            Log.e(TAG, "Execute failed", e)
            serverRunning.set(false)
            ShellResult("", "Server communication error: ${e.message}", -1)
        }
    }

    /**
     * Stop the Archon server.
     */
    fun stopServer(context: Context): Boolean {
        val token = getToken(context) ?: return false
        val port = getPort(context)
        return try {
            sendCommand(token, port, "__shutdown__")
            serverRunning.set(false)
            Log.i(TAG, "Server shutdown requested")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Stop failed", e)
            false
        }
    }

    /**
     * Generate the bootstrap command string (for display/manual use).
     */
    fun getBootstrapCommand(context: Context): String {
        val token = getToken(context) ?: "TOKEN"
        val port = getPort(context)
        val apkPath = context.applicationInfo.sourceDir ?: "/data/app/.../base.apk"
        return "TMPDIR=/data/local/tmp CLASSPATH='$apkPath' /system/bin/app_process /system/bin " +
            "com.darkhal.archon.server.ArchonServer $token $port"
    }

    // ── Internal ────────────────────────────────────────────────────

    private fun getToken(context: Context): String? {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_TOKEN, null)
    }

    private fun getPort(context: Context): Int {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getInt(KEY_PORT, DEFAULT_PORT)
    }

    private fun sendCommand(token: String, port: Int, cmd: String, timeoutSec: Int = 30): ShellResult {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT)
            socket.soTimeout = (timeoutSec + 5) * 1000

            val writer = PrintWriter(OutputStreamWriter(socket.getOutputStream()), true)
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))

            // Build JSON request
            val request = """{"token":"${escapeJson(token)}","cmd":"${escapeJson(cmd)}","timeout":$timeoutSec}"""
            writer.println(request)

            // Read JSON response
            val response = reader.readLine()
                ?: return ShellResult("", "No response from server", -1)

            return parseResponse(response)
        } finally {
            try { socket.close() } catch (e: Exception) { /* ignore */ }
        }
    }

    private fun parseResponse(json: String): ShellResult {
        val stdout = extractJsonString(json, "stdout") ?: ""
        val stderr = extractJsonString(json, "stderr") ?: ""
        val exitCode = extractJsonInt(json, "exit_code", -1)
        return ShellResult(stdout, stderr, exitCode)
    }

    private fun extractJsonString(json: String, key: String): String? {
        val search = "\"$key\""
        var idx = json.indexOf(search)
        if (idx < 0) return null

        idx = json.indexOf(':', idx + search.length)
        if (idx < 0) return null
        idx++

        while (idx < json.length && json[idx] == ' ') idx++
        if (idx >= json.length || json[idx] != '"') return null
        idx++

        val sb = StringBuilder()
        while (idx < json.length) {
            val c = json[idx]
            if (c == '\\' && idx + 1 < json.length) {
                when (json[idx + 1]) {
                    '"' -> sb.append('"')
                    '\\' -> sb.append('\\')
                    'n' -> sb.append('\n')
                    'r' -> sb.append('\r')
                    't' -> sb.append('\t')
                    else -> sb.append(json[idx + 1])
                }
                idx += 2
            } else if (c == '"') {
                break
            } else {
                sb.append(c)
                idx++
            }
        }
        return sb.toString()
    }

    private fun extractJsonInt(json: String, key: String, default: Int): Int {
        val search = "\"$key\""
        var idx = json.indexOf(search)
        if (idx < 0) return default

        idx = json.indexOf(':', idx + search.length)
        if (idx < 0) return default
        idx++

        while (idx < json.length && json[idx] == ' ') idx++

        val sb = StringBuilder()
        while (idx < json.length && (json[idx].isDigit() || json[idx] == '-')) {
            sb.append(json[idx])
            idx++
        }
        return sb.toString().toIntOrNull() ?: default
    }

    /**
     * Bootstrap ArchonServer via AUTARCH server's USB ADB connection.
     * Uses the /hardware/archon/bootstrap endpoint which auto-discovers the device.
     */
    private fun startServerViaHttp(context: Context, apkPath: String, token: String, port: Int): ShellResult? {
        val serverIp = PrefsManager.getServerIp(context)
        val serverPort = PrefsManager.getWebPort(context)
        if (serverIp.isEmpty()) return null

        return try {
            val url = java.net.URL("https://$serverIp:$serverPort/hardware/archon/bootstrap")
            val conn = url.openConnection() as java.net.HttpURLConnection
            com.darkhal.archon.util.SslHelper.trustSelfSigned(conn)
            conn.connectTimeout = 5000
            conn.readTimeout = 15000
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true

            val payload = """{"apk_path":"${escapeJson(apkPath)}","token":"${escapeJson(token)}","port":$port}"""
            Log.i(TAG, "Bootstrap via HTTP: $serverIp:$serverPort")
            conn.outputStream.write(payload.toByteArray())

            val code = conn.responseCode
            val body = if (code in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $code"
            }
            conn.disconnect()

            Log.i(TAG, "Bootstrap HTTP response: $code - $body")

            if (code in 200..299) {
                val stdout = extractJsonString(body, "stdout") ?: body
                val stderr = extractJsonString(body, "stderr") ?: ""
                val exitCode = extractJsonInt(body, "exit_code", 0)
                ShellResult(stdout, stderr, exitCode)
            } else {
                Log.w(TAG, "Bootstrap returned HTTP $code: $body")
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Bootstrap failed: ${e.message}")
            null
        }
    }

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
    }

    data class StartResult(val success: Boolean, val message: String)
}
