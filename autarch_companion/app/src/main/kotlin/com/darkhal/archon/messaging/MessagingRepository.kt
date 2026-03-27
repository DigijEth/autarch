package com.darkhal.archon.messaging

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.ContactsContract
import android.provider.Telephony
import android.telephony.SmsManager
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Data access layer for SMS/MMS/RCS messages using Android ContentResolver.
 *
 * Most write operations require the app to be the default SMS handler.
 * Use ShizukuManager or RoleManager to acquire that role first.
 */
class MessagingRepository(private val context: Context) {

    companion object {
        private const val TAG = "MessagingRepo"

        // SMS message types
        const val MESSAGE_TYPE_RECEIVED = 1
        const val MESSAGE_TYPE_SENT = 2
        const val MESSAGE_TYPE_DRAFT = 3
        const val MESSAGE_TYPE_OUTBOX = 4
        const val MESSAGE_TYPE_FAILED = 5
        const val MESSAGE_TYPE_QUEUED = 6

        // Content URIs
        val URI_SMS: Uri = Uri.parse("content://sms/")
        val URI_MMS: Uri = Uri.parse("content://mms/")
        val URI_SMS_CONVERSATIONS: Uri = Uri.parse("content://sms/conversations/")
        val URI_MMS_SMS_CONVERSATIONS: Uri = Uri.parse("content://mms-sms/conversations/")
        val URI_MMS_SMS_COMPLETE: Uri = Uri.parse("content://mms-sms/complete-conversations/")

        // RCS content provider (Google Messages)
        val URI_RCS_MESSAGES: Uri = Uri.parse("content://im/messages")
        val URI_RCS_THREADS: Uri = Uri.parse("content://im/threads")
    }

    // ── Data classes ───────────────────────────────────────────────

    data class Conversation(
        val threadId: Long,
        val address: String,
        val snippet: String,
        val date: Long,
        val messageCount: Int,
        val unreadCount: Int,
        val contactName: String?
    )

    data class Message(
        val id: Long,
        val threadId: Long,
        val address: String,
        val body: String,
        val date: Long,
        val type: Int,
        val read: Boolean,
        val status: Int,
        val isRcs: Boolean,
        val isMms: Boolean,
        val contactName: String?
    )

    // ── Read operations ────────────────────────────────────────────

    /**
     * Get all conversations from the combined SMS+MMS threads provider.
     * Falls back to SMS-only conversations if the combined provider is not available.
     */
    fun getConversations(): List<Conversation> {
        val conversations = mutableListOf<Conversation>()
        val threadMap = mutableMapOf<Long, Conversation>()

        try {
            // Query all SMS messages grouped by thread_id
            val cursor = context.contentResolver.query(
                URI_SMS,
                arrayOf("_id", "thread_id", "address", "body", "date", "read", "type"),
                null, null, "date DESC"
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val threadId = it.getLongSafe("thread_id")
                    if (threadId <= 0) continue

                    val existing = threadMap[threadId]
                    if (existing != null) {
                        // Update counts
                        val unread = if (!it.getBoolSafe("read")) 1 else 0
                        threadMap[threadId] = existing.copy(
                            messageCount = existing.messageCount + 1,
                            unreadCount = existing.unreadCount + unread
                        )
                    } else {
                        val address = it.getStringSafe("address")
                        val read = it.getBoolSafe("read")
                        threadMap[threadId] = Conversation(
                            threadId = threadId,
                            address = address,
                            snippet = it.getStringSafe("body"),
                            date = it.getLongSafe("date"),
                            messageCount = 1,
                            unreadCount = if (!read) 1 else 0,
                            contactName = getContactName(address)
                        )
                    }
                }
            }

            conversations.addAll(threadMap.values)
            conversations.sortByDescending { it.date }

        } catch (e: SecurityException) {
            Log.e(TAG, "No SMS read permission", e)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get conversations", e)
        }

        return conversations
    }

    /**
     * Get all messages in a specific thread, ordered by date ascending (oldest first).
     */
    fun getMessages(threadId: Long): List<Message> {
        val messages = mutableListOf<Message>()

        try {
            val cursor = context.contentResolver.query(
                URI_SMS,
                arrayOf("_id", "thread_id", "address", "body", "date", "type", "read", "status"),
                "thread_id = ?",
                arrayOf(threadId.toString()),
                "date ASC"
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val address = it.getStringSafe("address")
                    messages.add(Message(
                        id = it.getLongSafe("_id"),
                        threadId = it.getLongSafe("thread_id"),
                        address = address,
                        body = it.getStringSafe("body"),
                        date = it.getLongSafe("date"),
                        type = it.getIntSafe("type"),
                        read = it.getBoolSafe("read"),
                        status = it.getIntSafe("status"),
                        isRcs = false,
                        isMms = false,
                        contactName = getContactName(address)
                    ))
                }
            }

            // Also try to load MMS messages for this thread
            loadMmsForThread(threadId, messages)

            // Sort combined list by date
            messages.sortBy { it.date }

        } catch (e: SecurityException) {
            Log.e(TAG, "No SMS read permission", e)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get messages for thread $threadId", e)
        }

        return messages
    }

    /**
     * Get a single message by ID.
     */
    fun getMessage(id: Long): Message? {
        try {
            val cursor = context.contentResolver.query(
                URI_SMS,
                arrayOf("_id", "thread_id", "address", "body", "date", "type", "read", "status"),
                "_id = ?",
                arrayOf(id.toString()),
                null
            )

            cursor?.use {
                if (it.moveToFirst()) {
                    val address = it.getStringSafe("address")
                    return Message(
                        id = it.getLongSafe("_id"),
                        threadId = it.getLongSafe("thread_id"),
                        address = address,
                        body = it.getStringSafe("body"),
                        date = it.getLongSafe("date"),
                        type = it.getIntSafe("type"),
                        read = it.getBoolSafe("read"),
                        status = it.getIntSafe("status"),
                        isRcs = false,
                        isMms = false,
                        contactName = getContactName(address)
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get message $id", e)
        }
        return null
    }

    /**
     * Full-text search across all SMS message bodies.
     */
    fun searchMessages(query: String): List<Message> {
        val messages = mutableListOf<Message>()
        if (query.isBlank()) return messages

        try {
            val cursor = context.contentResolver.query(
                URI_SMS,
                arrayOf("_id", "thread_id", "address", "body", "date", "type", "read", "status"),
                "body LIKE ?",
                arrayOf("%$query%"),
                "date DESC"
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val address = it.getStringSafe("address")
                    messages.add(Message(
                        id = it.getLongSafe("_id"),
                        threadId = it.getLongSafe("thread_id"),
                        address = address,
                        body = it.getStringSafe("body"),
                        date = it.getLongSafe("date"),
                        type = it.getIntSafe("type"),
                        read = it.getBoolSafe("read"),
                        status = it.getIntSafe("status"),
                        isRcs = false,
                        isMms = false,
                        contactName = getContactName(address)
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Search failed for '$query'", e)
        }

        return messages
    }

    /**
     * Lookup contact display name by phone number.
     */
    fun getContactName(address: String): String? {
        if (address.isBlank()) return null

        try {
            val uri = Uri.withAppendedPath(
                ContactsContract.PhoneLookup.CONTENT_FILTER_URI,
                Uri.encode(address)
            )
            val cursor = context.contentResolver.query(
                uri,
                arrayOf(ContactsContract.PhoneLookup.DISPLAY_NAME),
                null, null, null
            )

            cursor?.use {
                if (it.moveToFirst()) {
                    val idx = it.getColumnIndex(ContactsContract.PhoneLookup.DISPLAY_NAME)
                    if (idx >= 0) return it.getString(idx)
                }
            }
        } catch (e: Exception) {
            // Contact lookup can fail for short codes, etc.
            Log.d(TAG, "Contact lookup failed for $address: ${e.message}")
        }
        return null
    }

    // ── Write operations (requires default SMS app role) ──────────

    /**
     * Send an SMS message via SmsManager.
     * Returns true if the message was submitted to the system for sending.
     */
    fun sendSms(address: String, body: String): Boolean {
        return try {
            val smsManager = context.getSystemService(SmsManager::class.java)
            if (body.length > 160) {
                val parts = smsManager.divideMessage(body)
                smsManager.sendMultipartTextMessage(address, null, parts, null, null)
            } else {
                smsManager.sendTextMessage(address, null, body, null, null)
            }
            // Also insert into sent box
            insertSms(address, body, MESSAGE_TYPE_SENT, System.currentTimeMillis(), true)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send SMS to $address", e)
            false
        }
    }

    /**
     * Insert an SMS record into the content provider.
     * Requires default SMS app role for writing.
     *
     * @param type 1=received, 2=sent, 3=draft, 4=outbox, 5=failed, 6=queued
     * @return the row ID of the inserted message, or -1 on failure
     */
    fun insertSms(address: String, body: String, type: Int, date: Long, read: Boolean): Long {
        return try {
            val values = ContentValues().apply {
                put("address", address)
                put("body", body)
                put("type", type)
                put("date", date)
                put("read", if (read) 1 else 0)
                put("seen", 1)
            }

            val uri = context.contentResolver.insert(URI_SMS, values)
            if (uri != null) {
                val id = uri.lastPathSegment?.toLongOrNull() ?: -1L
                Log.i(TAG, "Inserted SMS id=$id type=$type addr=$address")
                id
            } else {
                Log.w(TAG, "SMS insert returned null URI — app may not be default SMS handler")
                -1L
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "No write permission — must be default SMS app", e)
            -1L
        } catch (e: Exception) {
            Log.e(TAG, "Failed to insert SMS", e)
            -1L
        }
    }

    /**
     * Update an existing SMS message's fields.
     */
    fun updateMessage(id: Long, body: String?, type: Int?, date: Long?, read: Boolean?): Boolean {
        return try {
            val values = ContentValues()
            body?.let { values.put("body", it) }
            type?.let { values.put("type", it) }
            date?.let { values.put("date", it) }
            read?.let { values.put("read", if (it) 1 else 0) }

            if (values.size() == 0) return false

            val count = context.contentResolver.update(
                Uri.parse("content://sms/$id"),
                values, null, null
            )
            Log.i(TAG, "Updated SMS id=$id, rows=$count")
            count > 0
        } catch (e: SecurityException) {
            Log.e(TAG, "No write permission for update", e)
            false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update message $id", e)
            false
        }
    }

    /**
     * Delete a single SMS message by ID.
     */
    fun deleteMessage(id: Long): Boolean {
        return try {
            val count = context.contentResolver.delete(
                Uri.parse("content://sms/$id"), null, null
            )
            Log.i(TAG, "Deleted SMS id=$id, rows=$count")
            count > 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete message $id", e)
            false
        }
    }

    /**
     * Delete all messages in a conversation thread.
     */
    fun deleteConversation(threadId: Long): Boolean {
        return try {
            val count = context.contentResolver.delete(
                URI_SMS, "thread_id = ?", arrayOf(threadId.toString())
            )
            Log.i(TAG, "Deleted conversation thread=$threadId, rows=$count")
            count > 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to delete conversation $threadId", e)
            false
        }
    }

    /**
     * Mark all messages in a thread as read.
     */
    fun markAsRead(threadId: Long): Boolean {
        return try {
            val values = ContentValues().apply {
                put("read", 1)
                put("seen", 1)
            }
            val count = context.contentResolver.update(
                URI_SMS, values,
                "thread_id = ? AND read = 0",
                arrayOf(threadId.toString())
            )
            Log.i(TAG, "Marked $count messages as read in thread $threadId")
            count >= 0
        } catch (e: Exception) {
            Log.e(TAG, "Failed to mark thread $threadId as read", e)
            false
        }
    }

    // ── Spoofing / Forging ─────────────────────────────────────────

    /**
     * Insert a forged message with arbitrary sender, body, timestamp, and direction.
     * This creates a message that appears to come from the given address
     * at the given time, regardless of whether it was actually received.
     *
     * Requires default SMS app role.
     *
     * @param type MESSAGE_TYPE_RECEIVED (1) to fake incoming, MESSAGE_TYPE_SENT (2) to fake outgoing
     * @return the row ID of the forged message, or -1 on failure
     */
    fun forgeMessage(
        address: String,
        body: String,
        type: Int,
        date: Long,
        contactName: String? = null,
        read: Boolean = true
    ): Long {
        return try {
            val values = ContentValues().apply {
                put("address", address)
                put("body", body)
                put("type", type)
                put("date", date)
                put("read", if (read) 1 else 0)
                put("seen", 1)
                // Set status to complete for sent messages
                if (type == MESSAGE_TYPE_SENT) {
                    put("status", Telephony.Sms.STATUS_COMPLETE)
                }
                // person field links to contacts — we leave it null for forged messages
                // unless we want to explicitly associate with a contact
                contactName?.let { put("person", 0) }
            }

            val uri = context.contentResolver.insert(URI_SMS, values)
            if (uri != null) {
                val id = uri.lastPathSegment?.toLongOrNull() ?: -1L
                Log.i(TAG, "Forged SMS id=$id type=$type addr=$address date=$date")
                id
            } else {
                Log.w(TAG, "Forge insert returned null — not default SMS app?")
                -1L
            }
        } catch (e: SecurityException) {
            Log.e(TAG, "Forge failed — no write permission", e)
            -1L
        } catch (e: Exception) {
            Log.e(TAG, "Forge failed", e)
            -1L
        }
    }

    /**
     * Create an entire fake conversation by inserting multiple messages.
     *
     * @param messages list of (body, type) pairs where type is 1=received, 2=sent
     * @return the thread ID of the created conversation, or -1 on failure
     */
    fun forgeConversation(address: String, messages: List<Pair<String, Int>>): Long {
        if (messages.isEmpty()) return -1L

        // Insert messages with increasing timestamps, 1-5 minutes apart
        var timestamp = System.currentTimeMillis() - (messages.size * 180_000L) // Start N*3min ago
        var threadId = -1L

        for ((body, type) in messages) {
            val id = forgeMessage(address, body, type, timestamp, read = true)
            if (id < 0) {
                Log.e(TAG, "Failed to forge message in conversation")
                return -1L
            }

            // Get the thread ID from the first inserted message
            if (threadId < 0) {
                val msg = getMessage(id)
                threadId = msg?.threadId ?: -1L
            }

            // Advance 1-5 minutes
            timestamp += (60_000L + (Math.random() * 240_000L).toLong())
        }

        Log.i(TAG, "Forged conversation: addr=$address, msgs=${messages.size}, thread=$threadId")
        return threadId
    }

    // ── Export / Backup ────────────────────────────────────────────

    /**
     * Export a conversation to SMS Backup & Restore compatible XML format.
     */
    fun exportConversation(threadId: Long, format: String = "xml"): String {
        val messages = getMessages(threadId)
        if (messages.isEmpty()) return ""

        return when (format.lowercase()) {
            "xml" -> exportToXml(messages)
            "csv" -> exportToCsv(messages)
            else -> exportToXml(messages)
        }
    }

    /**
     * Export all SMS messages to the specified format.
     */
    fun exportAllMessages(format: String = "xml"): String {
        val allMessages = mutableListOf<Message>()

        try {
            val cursor = context.contentResolver.query(
                URI_SMS,
                arrayOf("_id", "thread_id", "address", "body", "date", "type", "read", "status"),
                null, null, "date ASC"
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val address = it.getStringSafe("address")
                    allMessages.add(Message(
                        id = it.getLongSafe("_id"),
                        threadId = it.getLongSafe("thread_id"),
                        address = address,
                        body = it.getStringSafe("body"),
                        date = it.getLongSafe("date"),
                        type = it.getIntSafe("type"),
                        read = it.getBoolSafe("read"),
                        status = it.getIntSafe("status"),
                        isRcs = false,
                        isMms = false,
                        contactName = getContactName(address)
                    ))
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to export all messages", e)
            return "<!-- Export error: ${e.message} -->"
        }

        return when (format.lowercase()) {
            "xml" -> exportToXml(allMessages)
            "csv" -> exportToCsv(allMessages)
            else -> exportToXml(allMessages)
        }
    }

    private fun exportToXml(messages: List<Message>): String {
        val sb = StringBuilder()
        sb.appendLine("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>")
        sb.appendLine("<?xml-stylesheet type=\"text/xsl\" href=\"sms.xsl\"?>")
        sb.appendLine("<smses count=\"${messages.size}\">")

        val dateFormat = SimpleDateFormat("MMM dd, yyyy hh:mm:ss a", Locale.US)

        for (msg in messages) {
            val typeStr = when (msg.type) {
                MESSAGE_TYPE_RECEIVED -> "1"
                MESSAGE_TYPE_SENT -> "2"
                MESSAGE_TYPE_DRAFT -> "3"
                else -> msg.type.toString()
            }
            val readableDate = dateFormat.format(Date(msg.date))
            val escapedBody = escapeXml(msg.body)
            val escapedAddr = escapeXml(msg.address)
            val contactStr = escapeXml(msg.contactName ?: "(Unknown)")

            sb.appendLine("  <sms protocol=\"0\" address=\"$escapedAddr\" " +
                    "date=\"${msg.date}\" type=\"$typeStr\" " +
                    "subject=\"null\" body=\"$escapedBody\" " +
                    "toa=\"null\" sc_toa=\"null\" service_center=\"null\" " +
                    "read=\"${if (msg.read) "1" else "0"}\" status=\"${msg.status}\" " +
                    "locked=\"0\" date_sent=\"0\" " +
                    "readable_date=\"$readableDate\" " +
                    "contact_name=\"$contactStr\" />")
        }

        sb.appendLine("</smses>")
        return sb.toString()
    }

    private fun exportToCsv(messages: List<Message>): String {
        val sb = StringBuilder()
        sb.appendLine("id,thread_id,address,contact_name,body,date,type,read,status")

        for (msg in messages) {
            val escapedBody = escapeCsv(msg.body)
            val contact = escapeCsv(msg.contactName ?: "")
            sb.appendLine("${msg.id},${msg.threadId},\"${msg.address}\",\"$contact\"," +
                    "\"$escapedBody\",${msg.date},${msg.type},${if (msg.read) 1 else 0},${msg.status}")
        }

        return sb.toString()
    }

    // ── RCS operations ─────────────────────────────────────────────

    /**
     * Attempt to read RCS messages from Google Messages' content provider.
     * This requires Shizuku or root access since the provider is protected.
     * Falls back gracefully if not accessible.
     */
    fun getRcsMessages(threadId: Long): List<Message> {
        val messages = mutableListOf<Message>()

        try {
            val cursor = context.contentResolver.query(
                URI_RCS_MESSAGES,
                null,
                "thread_id = ?",
                arrayOf(threadId.toString()),
                "date ASC"
            )

            cursor?.use {
                val cols = it.columnNames.toList()
                while (it.moveToNext()) {
                    val address = if (cols.contains("address")) it.getStringSafe("address") else ""
                    val body = if (cols.contains("body")) it.getStringSafe("body")
                    else if (cols.contains("text")) it.getStringSafe("text") else ""
                    val date = if (cols.contains("date")) it.getLongSafe("date") else 0L
                    val type = if (cols.contains("type")) it.getIntSafe("type") else 1

                    messages.add(Message(
                        id = it.getLongSafe("_id"),
                        threadId = threadId,
                        address = address,
                        body = body,
                        date = date,
                        type = type,
                        read = true,
                        status = 0,
                        isRcs = true,
                        isMms = false,
                        contactName = getContactName(address)
                    ))
                }
            }
        } catch (e: SecurityException) {
            Log.w(TAG, "Cannot access RCS provider — requires Shizuku or root: ${e.message}")
        } catch (e: Exception) {
            Log.w(TAG, "RCS read failed (provider may not exist): ${e.message}")
        }

        return messages
    }

    /**
     * Check if RCS is available on this device.
     * Looks for Google Messages as the RCS provider.
     */
    fun isRcsAvailable(): Boolean {
        return try {
            // Check if Google Messages is installed and is RCS-capable
            val pm = context.packageManager
            val info = pm.getPackageInfo("com.google.android.apps.messaging", 0)
            if (info == null) return false

            // Try to query the RCS provider
            val cursor = context.contentResolver.query(
                URI_RCS_THREADS, null, null, null, null
            )
            val available = cursor != null
            cursor?.close()
            available
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check RCS capabilities for a given address.
     * Returns a map of feature flags (e.g., "chat" -> true, "ft" -> true for file transfer).
     */
    fun getRcsCapabilities(address: String): Map<String, Boolean> {
        val caps = mutableMapOf<String, Boolean>()

        try {
            // Try to query RCS capabilities via the carrier messaging service
            // This is a best-effort check — may not work on all carriers
            val cursor = context.contentResolver.query(
                Uri.parse("content://im/capabilities"),
                null,
                "address = ?",
                arrayOf(address),
                null
            )

            cursor?.use {
                if (it.moveToFirst()) {
                    val cols = it.columnNames
                    for (col in cols) {
                        val idx = it.getColumnIndex(col)
                        if (idx >= 0) {
                            try {
                                caps[col] = it.getInt(idx) > 0
                            } catch (e: Exception) {
                                caps[col] = it.getString(idx)?.isNotEmpty() == true
                            }
                        }
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "RCS capabilities check failed for $address: ${e.message}")
        }

        return caps
    }

    // ── Bulk operations ────────────────────────────────────────────

    /**
     * Insert multiple messages in batch.
     * Returns the number of successfully inserted messages.
     */
    fun bulkInsert(messages: List<Message>): Int {
        var count = 0
        for (msg in messages) {
            val id = insertSms(msg.address, msg.body, msg.type, msg.date, msg.read)
            if (id >= 0) count++
        }
        Log.i(TAG, "Bulk insert: $count/${messages.size} succeeded")
        return count
    }

    /**
     * Delete multiple messages by ID.
     * Returns the number of successfully deleted messages.
     */
    fun bulkDelete(ids: List<Long>): Int {
        var count = 0
        for (id in ids) {
            if (deleteMessage(id)) count++
        }
        Log.i(TAG, "Bulk delete: $count/${ids.size} succeeded")
        return count
    }

    /**
     * Delete all messages in a conversation (alias for deleteConversation).
     * Returns the number of deleted rows.
     */
    fun clearConversation(threadId: Long): Int {
        return try {
            val count = context.contentResolver.delete(
                URI_SMS, "thread_id = ?", arrayOf(threadId.toString())
            )
            Log.i(TAG, "Cleared conversation $threadId: $count messages")
            count
        } catch (e: Exception) {
            Log.e(TAG, "Failed to clear conversation $threadId", e)
            0
        }
    }

    // ── MMS helpers ────────────────────────────────────────────────

    /**
     * Load MMS messages for a thread and add them to the list.
     */
    private fun loadMmsForThread(threadId: Long, messages: MutableList<Message>) {
        try {
            val cursor = context.contentResolver.query(
                URI_MMS,
                arrayOf("_id", "thread_id", "date", "read", "msg_box"),
                "thread_id = ?",
                arrayOf(threadId.toString()),
                "date ASC"
            )

            cursor?.use {
                while (it.moveToNext()) {
                    val mmsId = it.getLongSafe("_id")
                    val mmsDate = it.getLongSafe("date") * 1000L // MMS dates are in seconds
                    val msgBox = it.getIntSafe("msg_box")
                    val type = if (msgBox == 1) MESSAGE_TYPE_RECEIVED else MESSAGE_TYPE_SENT

                    // Get MMS text part
                    val body = getMmsTextPart(mmsId)
                    // Get MMS address
                    val address = getMmsAddress(mmsId)

                    messages.add(Message(
                        id = mmsId,
                        threadId = threadId,
                        address = address,
                        body = body ?: "[MMS]",
                        date = mmsDate,
                        type = type,
                        read = it.getBoolSafe("read"),
                        status = 0,
                        isRcs = false,
                        isMms = true,
                        contactName = getContactName(address)
                    ))
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "MMS load for thread $threadId failed: ${e.message}")
        }
    }

    /**
     * Get the text body of an MMS message from its parts.
     */
    private fun getMmsTextPart(mmsId: Long): String? {
        try {
            val cursor = context.contentResolver.query(
                Uri.parse("content://mms/$mmsId/part"),
                arrayOf("_id", "ct", "text"),
                "ct = 'text/plain'",
                null, null
            )

            cursor?.use {
                if (it.moveToFirst()) {
                    val textIdx = it.getColumnIndex("text")
                    if (textIdx >= 0) return it.getString(textIdx)
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Failed to get MMS text part for $mmsId: ${e.message}")
        }
        return null
    }

    /**
     * Get the sender/recipient address of an MMS message.
     */
    private fun getMmsAddress(mmsId: Long): String {
        try {
            val cursor = context.contentResolver.query(
                Uri.parse("content://mms/$mmsId/addr"),
                arrayOf("address", "type"),
                "type = 137", // PduHeaders.FROM
                null, null
            )

            cursor?.use {
                if (it.moveToFirst()) {
                    val addrIdx = it.getColumnIndex("address")
                    if (addrIdx >= 0) {
                        val addr = it.getString(addrIdx)
                        if (!addr.isNullOrBlank() && addr != "insert-address-token") {
                            return addr
                        }
                    }
                }
            }

            // Fallback: try recipient address (type 151 = TO)
            val cursor2 = context.contentResolver.query(
                Uri.parse("content://mms/$mmsId/addr"),
                arrayOf("address", "type"),
                "type = 151",
                null, null
            )

            cursor2?.use {
                if (it.moveToFirst()) {
                    val addrIdx = it.getColumnIndex("address")
                    if (addrIdx >= 0) {
                        val addr = it.getString(addrIdx)
                        if (!addr.isNullOrBlank()) return addr
                    }
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "Failed to get MMS address for $mmsId: ${e.message}")
        }
        return ""
    }

    // ── Utility ────────────────────────────────────────────────────

    private fun escapeXml(text: String): String {
        return text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&apos;")
            .replace("\n", "&#10;")
    }

    private fun escapeCsv(text: String): String {
        return text.replace("\"", "\"\"")
    }

    // Cursor extension helpers
    private fun Cursor.getStringSafe(column: String): String {
        val idx = getColumnIndex(column)
        return if (idx >= 0) getString(idx) ?: "" else ""
    }

    private fun Cursor.getLongSafe(column: String): Long {
        val idx = getColumnIndex(column)
        return if (idx >= 0) getLong(idx) else 0L
    }

    private fun Cursor.getIntSafe(column: String): Int {
        val idx = getColumnIndex(column)
        return if (idx >= 0) getInt(idx) else 0
    }

    private fun Cursor.getBoolSafe(column: String): Boolean {
        return getIntSafe(column) != 0
    }
}
