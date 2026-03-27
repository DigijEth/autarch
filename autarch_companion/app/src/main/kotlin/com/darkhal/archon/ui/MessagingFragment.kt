package com.darkhal.archon.ui

import android.app.DatePickerDialog
import android.app.TimePickerDialog
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.darkhal.archon.R
import com.darkhal.archon.messaging.ConversationAdapter
import com.darkhal.archon.messaging.MessageAdapter
import com.darkhal.archon.messaging.MessagingModule
import com.darkhal.archon.messaging.MessagingRepository
import com.darkhal.archon.messaging.ShizukuManager
import com.darkhal.archon.module.ModuleManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.card.MaterialCardView
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.textfield.TextInputEditText
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale

/**
 * SMS/RCS Messaging tab — full messaging UI with conversation list and thread view.
 *
 * Two views:
 * 1. Conversation list — shows all threads with contact, snippet, date, unread count
 * 2. Message thread — shows messages as chat bubbles with input bar
 *
 * Features:
 * - Search across all messages
 * - Set/restore default SMS app
 * - Export conversations (XML/CSV)
 * - Forge messages with arbitrary sender/timestamp
 * - Edit/delete messages via long-press context menu
 * - Shizuku status indicator
 */
class MessagingFragment : Fragment() {

    // Views — Conversation list
    private lateinit var conversationListContainer: View
    private lateinit var recyclerConversations: RecyclerView
    private lateinit var emptyState: TextView
    private lateinit var shizukuDot: View
    private lateinit var btnSearch: MaterialButton
    private lateinit var btnDefaultSms: MaterialButton
    private lateinit var btnTools: MaterialButton
    private lateinit var searchBar: View
    private lateinit var inputSearch: TextInputEditText
    private lateinit var btnSearchGo: MaterialButton
    private lateinit var btnSearchClose: MaterialButton
    private lateinit var fabNewMessage: FloatingActionButton

    // Views — Thread
    private lateinit var threadViewContainer: View
    private lateinit var recyclerMessages: RecyclerView
    private lateinit var threadContactName: TextView
    private lateinit var threadAddress: TextView
    private lateinit var btnBack: MaterialButton
    private lateinit var btnThreadExport: MaterialButton
    private lateinit var inputMessage: TextInputEditText
    private lateinit var btnSend: MaterialButton

    // Views — Output log
    private lateinit var outputLogCard: MaterialCardView
    private lateinit var outputLog: TextView
    private lateinit var btnCloseLog: MaterialButton

    // Data
    private lateinit var repo: MessagingRepository
    private lateinit var shizuku: ShizukuManager
    private lateinit var conversationAdapter: ConversationAdapter
    private lateinit var messageAdapter: MessageAdapter
    private val handler = Handler(Looper.getMainLooper())

    // State
    private var currentThreadId: Long = -1
    private var currentAddress: String = ""
    private var isDefaultSms: Boolean = false

    // Forge dialog state
    private var forgeCalendar: Calendar = Calendar.getInstance()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_messaging, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        repo = MessagingRepository(requireContext())
        shizuku = ShizukuManager(requireContext())

        bindViews(view)
        setupConversationList()
        setupThreadView()
        setupSearch()
        setupToolbar()
        setupOutputLog()

        // Load conversations
        loadConversations()

        // Check Shizuku status
        refreshShizukuStatus()
    }

    // ── View binding ───────────────────────────────────────────────

    private fun bindViews(view: View) {
        // Conversation list
        conversationListContainer = view.findViewById(R.id.conversation_list_container)
        recyclerConversations = view.findViewById(R.id.recycler_conversations)
        emptyState = view.findViewById(R.id.empty_state)
        shizukuDot = view.findViewById(R.id.shizuku_status_dot)
        btnSearch = view.findViewById(R.id.btn_search)
        btnDefaultSms = view.findViewById(R.id.btn_default_sms)
        btnTools = view.findViewById(R.id.btn_tools)
        searchBar = view.findViewById(R.id.search_bar)
        inputSearch = view.findViewById(R.id.input_search)
        btnSearchGo = view.findViewById(R.id.btn_search_go)
        btnSearchClose = view.findViewById(R.id.btn_search_close)
        fabNewMessage = view.findViewById(R.id.fab_new_message)

        // Thread view
        threadViewContainer = view.findViewById(R.id.thread_view_container)
        recyclerMessages = view.findViewById(R.id.recycler_messages)
        threadContactName = view.findViewById(R.id.thread_contact_name)
        threadAddress = view.findViewById(R.id.thread_address)
        btnBack = view.findViewById(R.id.btn_back)
        btnThreadExport = view.findViewById(R.id.btn_thread_export)
        inputMessage = view.findViewById(R.id.input_message)
        btnSend = view.findViewById(R.id.btn_send)

        // Output log
        outputLogCard = view.findViewById(R.id.output_log_card)
        outputLog = view.findViewById(R.id.messaging_output_log)
        btnCloseLog = view.findViewById(R.id.btn_close_log)
    }

    // ── Conversation list ──────────────────────────────────────────

    private fun setupConversationList() {
        conversationAdapter = ConversationAdapter(mutableListOf()) { conversation ->
            openThread(conversation)
        }

        recyclerConversations.apply {
            layoutManager = LinearLayoutManager(requireContext())
            adapter = conversationAdapter
        }

        fabNewMessage.setOnClickListener {
            showForgeMessageDialog()
        }
    }

    private fun loadConversations() {
        Thread {
            val conversations = repo.getConversations()
            handler.post {
                conversationAdapter.updateData(conversations)
                if (conversations.isEmpty()) {
                    emptyState.visibility = View.VISIBLE
                    recyclerConversations.visibility = View.GONE
                } else {
                    emptyState.visibility = View.GONE
                    recyclerConversations.visibility = View.VISIBLE
                }
            }
        }.start()
    }

    // ── Thread view ────────────────────────────────────────────────

    private fun setupThreadView() {
        messageAdapter = MessageAdapter(mutableListOf()) { message ->
            showMessageContextMenu(message)
        }

        recyclerMessages.apply {
            layoutManager = LinearLayoutManager(requireContext()).apply {
                stackFromEnd = true
            }
            adapter = messageAdapter
        }

        btnBack.setOnClickListener {
            closeThread()
        }

        btnSend.setOnClickListener {
            sendMessage()
        }

        btnThreadExport.setOnClickListener {
            exportCurrentThread()
        }
    }

    private fun openThread(conversation: MessagingRepository.Conversation) {
        currentThreadId = conversation.threadId
        currentAddress = conversation.address

        val displayName = conversation.contactName ?: conversation.address
        threadContactName.text = displayName
        threadAddress.text = if (conversation.contactName != null) conversation.address else ""

        // Mark as read
        Thread {
            repo.markAsRead(conversation.threadId)
        }.start()

        // Load messages
        loadMessages(conversation.threadId)

        // Switch views
        conversationListContainer.visibility = View.GONE
        threadViewContainer.visibility = View.VISIBLE
    }

    private fun closeThread() {
        currentThreadId = -1
        currentAddress = ""

        threadViewContainer.visibility = View.GONE
        conversationListContainer.visibility = View.VISIBLE

        // Refresh conversations to update unread counts
        loadConversations()
    }

    private fun loadMessages(threadId: Long) {
        Thread {
            val messages = repo.getMessages(threadId)
            handler.post {
                messageAdapter.updateData(messages)
                // Scroll to bottom
                if (messages.isNotEmpty()) {
                    recyclerMessages.scrollToPosition(messages.size - 1)
                }
            }
        }.start()
    }

    private fun sendMessage() {
        val body = inputMessage.text?.toString()?.trim() ?: return
        if (body.isEmpty()) return

        inputMessage.setText("")

        Thread {
            val success = repo.sendSms(currentAddress, body)
            handler.post {
                if (success) {
                    // Reload messages to show the sent message
                    loadMessages(currentThreadId)
                } else {
                    // If we can't send (not default SMS), try forge as sent
                    val id = repo.forgeMessage(
                        currentAddress, body,
                        MessagingRepository.MESSAGE_TYPE_SENT,
                        System.currentTimeMillis(), read = true
                    )
                    if (id >= 0) {
                        loadMessages(currentThreadId)
                        appendLog("Message inserted (forge mode — not actually sent)")
                    } else {
                        appendLog("Failed to send/insert — need default SMS app role")
                        Toast.makeText(requireContext(),
                            "Cannot send — set as default SMS app first",
                            Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }.start()
    }

    private fun exportCurrentThread() {
        if (currentThreadId < 0) return

        Thread {
            val result = ModuleManager.executeAction("messaging", "export_thread:$currentThreadId", requireContext())
            handler.post {
                appendLog(result.output)
                for (detail in result.details) {
                    appendLog("  $detail")
                }
                showOutputLog()
            }
        }.start()
    }

    // ── Search ─────────────────────────────────────────────────────

    private fun setupSearch() {
        btnSearch.setOnClickListener {
            if (searchBar.visibility == View.VISIBLE) {
                searchBar.visibility = View.GONE
            } else {
                searchBar.visibility = View.VISIBLE
                inputSearch.requestFocus()
            }
        }

        btnSearchGo.setOnClickListener {
            val query = inputSearch.text?.toString()?.trim() ?: ""
            if (query.isNotEmpty()) {
                performSearch(query)
            }
        }

        btnSearchClose.setOnClickListener {
            searchBar.visibility = View.GONE
            inputSearch.setText("")
            loadConversations()
        }
    }

    private fun performSearch(query: String) {
        Thread {
            val results = repo.searchMessages(query)
            handler.post {
                if (results.isEmpty()) {
                    appendLog("No results for '$query'")
                    showOutputLog()
                } else {
                    // Group results by thread and show as conversations
                    val threadGroups = results.groupBy { it.threadId }
                    val conversations = threadGroups.map { (threadId, msgs) ->
                        val first = msgs.first()
                        MessagingRepository.Conversation(
                            threadId = threadId,
                            address = first.address,
                            snippet = "[${msgs.size} matches] ${first.body.take(40)}",
                            date = first.date,
                            messageCount = msgs.size,
                            unreadCount = 0,
                            contactName = first.contactName
                        )
                    }.sortedByDescending { it.date }

                    conversationAdapter.updateData(conversations)
                    emptyState.visibility = View.GONE
                    recyclerConversations.visibility = View.VISIBLE
                    appendLog("Found ${results.size} messages in ${conversations.size} threads")
                }
            }
        }.start()
    }

    // ── Toolbar actions ────────────────────────────────────────────

    private fun setupToolbar() {
        btnDefaultSms.setOnClickListener {
            toggleDefaultSms()
        }

        btnTools.setOnClickListener { anchor ->
            showToolsMenu(anchor)
        }
    }

    private fun toggleDefaultSms() {
        Thread {
            if (!isDefaultSms) {
                val result = ModuleManager.executeAction("messaging", "become_default", requireContext())
                handler.post {
                    if (result.success) {
                        isDefaultSms = true
                        btnDefaultSms.text = getString(R.string.messaging_restore_default)
                        appendLog("Archon is now default SMS app")
                    } else {
                        appendLog("Failed: ${result.output}")
                    }
                    showOutputLog()
                }
            } else {
                val result = ModuleManager.executeAction("messaging", "restore_default", requireContext())
                handler.post {
                    if (result.success) {
                        isDefaultSms = false
                        btnDefaultSms.text = getString(R.string.messaging_become_default)
                        appendLog("Default SMS app restored")
                    } else {
                        appendLog("Failed: ${result.output}")
                    }
                    showOutputLog()
                }
            }
        }.start()
    }

    private fun showToolsMenu(anchor: View) {
        val popup = PopupMenu(requireContext(), anchor)
        popup.menu.add(0, 1, 0, "Export All Messages")
        popup.menu.add(0, 2, 1, "Forge Message")
        popup.menu.add(0, 3, 2, "Forge Conversation")
        popup.menu.add(0, 4, 3, "RCS Status")
        popup.menu.add(0, 5, 4, "Shizuku Status")
        popup.menu.add(0, 6, 5, "Intercept Mode ON")
        popup.menu.add(0, 7, 6, "Intercept Mode OFF")

        popup.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                1 -> executeModuleAction("export_all")
                2 -> showForgeMessageDialog()
                3 -> showForgeConversationDialog()
                4 -> executeModuleAction("rcs_status")
                5 -> executeModuleAction("shizuku_status")
                6 -> executeModuleAction("intercept_mode:on")
                7 -> executeModuleAction("intercept_mode:off")
            }
            true
        }

        popup.show()
    }

    private fun executeModuleAction(actionId: String) {
        appendLog("Running: $actionId...")
        showOutputLog()

        Thread {
            val result = ModuleManager.executeAction("messaging", actionId, requireContext())
            handler.post {
                appendLog(result.output)
                for (detail in result.details.take(20)) {
                    appendLog("  $detail")
                }
            }
        }.start()
    }

    // ── Shizuku status ─────────────────────────────────────────────

    private fun refreshShizukuStatus() {
        Thread {
            val ready = shizuku.isReady()
            handler.post {
                setStatusDot(shizukuDot, ready)
            }
        }.start()
    }

    private fun setStatusDot(dot: View, online: Boolean) {
        val drawable = GradientDrawable()
        drawable.shape = GradientDrawable.OVAL
        drawable.setColor(if (online) Color.parseColor("#00FF41") else Color.parseColor("#666666"))
        dot.background = drawable
    }

    // ── Message context menu (long-press) ──────────────────────────

    private fun showMessageContextMenu(message: MessagingRepository.Message) {
        val items = arrayOf(
            "Copy",
            "Edit Body",
            "Delete",
            "Change Timestamp",
            "Spoof Read Status",
            "Forward (Forge)"
        )

        AlertDialog.Builder(requireContext())
            .setTitle("Message Options")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> copyMessage(message)
                    1 -> editMessageBody(message)
                    2 -> deleteMessage(message)
                    3 -> changeTimestamp(message)
                    4 -> spoofReadStatus(message)
                    5 -> forwardAsForge(message)
                }
            }
            .show()
    }

    private fun copyMessage(message: MessagingRepository.Message) {
        val clipboard = requireContext().getSystemService(android.content.ClipboardManager::class.java)
        val clip = android.content.ClipData.newPlainText("sms", message.body)
        clipboard?.setPrimaryClip(clip)
        Toast.makeText(requireContext(), "Copied to clipboard", Toast.LENGTH_SHORT).show()
    }

    private fun editMessageBody(message: MessagingRepository.Message) {
        val input = TextInputEditText(requireContext()).apply {
            setText(message.body)
            setTextColor(resources.getColor(R.color.text_primary, null))
            setBackgroundColor(resources.getColor(R.color.surface_dark, null))
            setPadding(32, 24, 32, 24)
        }

        AlertDialog.Builder(requireContext())
            .setTitle("Edit Message Body")
            .setView(input)
            .setPositiveButton("Save") { _, _ ->
                val newBody = input.text?.toString() ?: return@setPositiveButton
                Thread {
                    val success = repo.updateMessage(message.id, body = newBody, type = null, date = null, read = null)
                    handler.post {
                        if (success) {
                            appendLog("Updated message ${message.id}")
                            loadMessages(currentThreadId)
                        } else {
                            appendLog("Failed to update — need default SMS app role")
                        }
                        showOutputLog()
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun deleteMessage(message: MessagingRepository.Message) {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete Message")
            .setMessage("Delete this message permanently?\n\n\"${message.body.take(60)}\"")
            .setPositiveButton("Delete") { _, _ ->
                Thread {
                    val success = repo.deleteMessage(message.id)
                    handler.post {
                        if (success) {
                            appendLog("Deleted message ${message.id}")
                            loadMessages(currentThreadId)
                        } else {
                            appendLog("Failed to delete — need default SMS app role")
                        }
                        showOutputLog()
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun changeTimestamp(message: MessagingRepository.Message) {
        val cal = Calendar.getInstance()
        cal.timeInMillis = message.date

        DatePickerDialog(requireContext(), { _, year, month, day ->
            TimePickerDialog(requireContext(), { _, hour, minute ->
                cal.set(year, month, day, hour, minute)
                val newDate = cal.timeInMillis

                Thread {
                    val success = repo.updateMessage(message.id, body = null, type = null, date = newDate, read = null)
                    handler.post {
                        if (success) {
                            val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US)
                            appendLog("Changed timestamp to ${fmt.format(Date(newDate))}")
                            loadMessages(currentThreadId)
                        } else {
                            appendLog("Failed to change timestamp")
                        }
                        showOutputLog()
                    }
                }.start()
            }, cal.get(Calendar.HOUR_OF_DAY), cal.get(Calendar.MINUTE), true).show()
        }, cal.get(Calendar.YEAR), cal.get(Calendar.MONTH), cal.get(Calendar.DAY_OF_MONTH)).show()
    }

    private fun spoofReadStatus(message: MessagingRepository.Message) {
        val items = arrayOf("Mark as Read", "Mark as Unread")
        AlertDialog.Builder(requireContext())
            .setTitle("Read Status")
            .setItems(items) { _, which ->
                val newRead = which == 0
                Thread {
                    val success = repo.updateMessage(message.id, body = null, type = null, date = null, read = newRead)
                    handler.post {
                        if (success) {
                            appendLog("Set read=${newRead} for message ${message.id}")
                            loadMessages(currentThreadId)
                        } else {
                            appendLog("Failed to update read status")
                        }
                        showOutputLog()
                    }
                }.start()
            }
            .show()
    }

    private fun forwardAsForge(message: MessagingRepository.Message) {
        // Pre-fill the forge dialog with this message's body
        showForgeMessageDialog(prefillBody = message.body)
    }

    // ── Forge dialogs ──────────────────────────────────────────────

    private fun showForgeMessageDialog(prefillBody: String? = null) {
        val dialogView = LayoutInflater.from(requireContext())
            .inflate(R.layout.dialog_forge_message, null)

        val forgeAddress = dialogView.findViewById<TextInputEditText>(R.id.forge_address)
        val forgeContactName = dialogView.findViewById<TextInputEditText>(R.id.forge_contact_name)
        val forgeBody = dialogView.findViewById<TextInputEditText>(R.id.forge_body)
        val forgeTypeReceived = dialogView.findViewById<MaterialButton>(R.id.forge_type_received)
        val forgeTypeSent = dialogView.findViewById<MaterialButton>(R.id.forge_type_sent)
        val forgePickDate = dialogView.findViewById<MaterialButton>(R.id.forge_pick_date)
        val forgePickTime = dialogView.findViewById<MaterialButton>(R.id.forge_pick_time)
        val forgeReadStatus = dialogView.findViewById<CheckBox>(R.id.forge_read_status)

        prefillBody?.let { forgeBody.setText(it) }

        // If we're in a thread, prefill the address
        if (currentAddress.isNotEmpty()) {
            forgeAddress.setText(currentAddress)
        }

        // Direction toggle
        var selectedType = MessagingRepository.MESSAGE_TYPE_RECEIVED
        forgeTypeReceived.setOnClickListener {
            selectedType = MessagingRepository.MESSAGE_TYPE_RECEIVED
            forgeTypeReceived.tag = "selected"
            forgeTypeSent.tag = null
        }
        forgeTypeSent.setOnClickListener {
            selectedType = MessagingRepository.MESSAGE_TYPE_SENT
            forgeTypeSent.tag = "selected"
            forgeTypeReceived.tag = null
        }

        // Date/time pickers
        forgeCalendar = Calendar.getInstance()
        val dateFormat = SimpleDateFormat("MMM dd, yyyy", Locale.US)
        val timeFormat = SimpleDateFormat("HH:mm", Locale.US)
        forgePickDate.text = dateFormat.format(forgeCalendar.time)
        forgePickTime.text = timeFormat.format(forgeCalendar.time)

        forgePickDate.setOnClickListener {
            DatePickerDialog(requireContext(), { _, year, month, day ->
                forgeCalendar.set(Calendar.YEAR, year)
                forgeCalendar.set(Calendar.MONTH, month)
                forgeCalendar.set(Calendar.DAY_OF_MONTH, day)
                forgePickDate.text = dateFormat.format(forgeCalendar.time)
            }, forgeCalendar.get(Calendar.YEAR), forgeCalendar.get(Calendar.MONTH),
                forgeCalendar.get(Calendar.DAY_OF_MONTH)).show()
        }

        forgePickTime.setOnClickListener {
            TimePickerDialog(requireContext(), { _, hour, minute ->
                forgeCalendar.set(Calendar.HOUR_OF_DAY, hour)
                forgeCalendar.set(Calendar.MINUTE, minute)
                forgePickTime.text = timeFormat.format(forgeCalendar.time)
            }, forgeCalendar.get(Calendar.HOUR_OF_DAY), forgeCalendar.get(Calendar.MINUTE), true).show()
        }

        AlertDialog.Builder(requireContext())
            .setView(dialogView)
            .setPositiveButton("Forge") { _, _ ->
                val address = forgeAddress.text?.toString()?.trim() ?: ""
                val contactName = forgeContactName.text?.toString()?.trim()
                val body = forgeBody.text?.toString()?.trim() ?: ""
                val read = forgeReadStatus.isChecked
                val date = forgeCalendar.timeInMillis

                if (address.isEmpty() || body.isEmpty()) {
                    Toast.makeText(requireContext(), "Address and body required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }

                Thread {
                    val id = repo.forgeMessage(
                        address = address,
                        body = body,
                        type = selectedType,
                        date = date,
                        contactName = contactName,
                        read = read
                    )
                    handler.post {
                        if (id >= 0) {
                            val direction = if (selectedType == 1) "received" else "sent"
                            appendLog("Forged $direction message id=$id to $address")
                            showOutputLog()

                            // Refresh view
                            if (currentThreadId > 0) {
                                loadMessages(currentThreadId)
                            } else {
                                loadConversations()
                            }
                        } else {
                            appendLog("Forge failed — need default SMS app role")
                            showOutputLog()
                        }
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showForgeConversationDialog() {
        val input = TextInputEditText(requireContext()).apply {
            hint = "Phone number (e.g. +15551234567)"
            setTextColor(resources.getColor(R.color.text_primary, null))
            setHintTextColor(resources.getColor(R.color.text_muted, null))
            setBackgroundColor(resources.getColor(R.color.surface_dark, null))
            setPadding(32, 24, 32, 24)
            inputType = android.text.InputType.TYPE_CLASS_PHONE
        }

        AlertDialog.Builder(requireContext())
            .setTitle("Forge Conversation")
            .setMessage("Create a fake conversation with back-and-forth messages from this number:")
            .setView(input)
            .setPositiveButton("Forge") { _, _ ->
                val address = input.text?.toString()?.trim() ?: ""
                if (address.isEmpty()) {
                    Toast.makeText(requireContext(), "Phone number required", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                executeModuleAction("forge_conversation:$address")
                // Refresh after a short delay for the inserts to complete
                handler.postDelayed({ loadConversations() }, 2000)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ── Output log ─────────────────────────────────────────────────

    private fun setupOutputLog() {
        btnCloseLog.setOnClickListener {
            outputLogCard.visibility = View.GONE
        }
    }

    private fun showOutputLog() {
        outputLogCard.visibility = View.VISIBLE
    }

    private fun appendLog(msg: String) {
        val current = outputLog.text.toString()
        val lines = current.split("\n").takeLast(30)
        outputLog.text = (lines + "> $msg").joinToString("\n")
    }
}
