package com.darkhal.archon.messaging

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.darkhal.archon.R
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * RecyclerView adapter for the conversation list view.
 * Shows each conversation with contact avatar, name/number, snippet, date, and unread badge.
 */
class ConversationAdapter(
    private val conversations: MutableList<MessagingRepository.Conversation>,
    private val onClick: (MessagingRepository.Conversation) -> Unit
) : RecyclerView.Adapter<ConversationAdapter.ViewHolder>() {

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val avatarText: TextView = itemView.findViewById(R.id.avatar_text)
        val avatarBg: View = itemView.findViewById(R.id.avatar_bg)
        val contactName: TextView = itemView.findViewById(R.id.contact_name)
        val snippet: TextView = itemView.findViewById(R.id.message_snippet)
        val dateText: TextView = itemView.findViewById(R.id.conversation_date)
        val unreadBadge: TextView = itemView.findViewById(R.id.unread_badge)

        init {
            itemView.setOnClickListener {
                val pos = adapterPosition
                if (pos != RecyclerView.NO_POSITION) {
                    onClick(conversations[pos])
                }
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_conversation, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val conv = conversations[position]

        // Avatar — first letter of contact name or number
        val displayName = conv.contactName ?: conv.address
        val initial = displayName.firstOrNull()?.uppercase() ?: "#"
        holder.avatarText.text = initial

        // Avatar background color — deterministic based on address
        val avatarDrawable = GradientDrawable()
        avatarDrawable.shape = GradientDrawable.OVAL
        avatarDrawable.setColor(getAvatarColor(conv.address))
        holder.avatarBg.background = avatarDrawable

        // Contact name / phone number
        holder.contactName.text = displayName

        // Snippet (most recent message)
        holder.snippet.text = conv.snippet

        // Date
        holder.dateText.text = formatConversationDate(conv.date)

        // Unread badge
        if (conv.unreadCount > 0) {
            holder.unreadBadge.visibility = View.VISIBLE
            holder.unreadBadge.text = if (conv.unreadCount > 99) "99+" else conv.unreadCount.toString()
        } else {
            holder.unreadBadge.visibility = View.GONE
        }
    }

    override fun getItemCount(): Int = conversations.size

    fun updateData(newConversations: List<MessagingRepository.Conversation>) {
        conversations.clear()
        conversations.addAll(newConversations)
        notifyDataSetChanged()
    }

    /**
     * Format date for conversation list display.
     * Today: show time (3:45 PM), This week: show day (Mon), Older: show date (12/25).
     */
    private fun formatConversationDate(timestamp: Long): String {
        if (timestamp <= 0) return ""

        val now = System.currentTimeMillis()
        val diff = now - timestamp
        val date = Date(timestamp)

        val today = Calendar.getInstance()
        today.set(Calendar.HOUR_OF_DAY, 0)
        today.set(Calendar.MINUTE, 0)
        today.set(Calendar.SECOND, 0)
        today.set(Calendar.MILLISECOND, 0)

        return when {
            timestamp >= today.timeInMillis -> {
                // Today — show time
                SimpleDateFormat("h:mm a", Locale.US).format(date)
            }
            diff < TimeUnit.DAYS.toMillis(7) -> {
                // This week — show day name
                SimpleDateFormat("EEE", Locale.US).format(date)
            }
            diff < TimeUnit.DAYS.toMillis(365) -> {
                // This year — show month/day
                SimpleDateFormat("MMM d", Locale.US).format(date)
            }
            else -> {
                // Older — show full date
                SimpleDateFormat("M/d/yy", Locale.US).format(date)
            }
        }
    }

    /**
     * Generate a deterministic color for a contact's avatar based on their address.
     */
    private fun getAvatarColor(address: String): Int {
        val colors = intArrayOf(
            Color.parseColor("#E91E63"),  // Pink
            Color.parseColor("#9C27B0"),  // Purple
            Color.parseColor("#673AB7"),  // Deep Purple
            Color.parseColor("#3F51B5"),  // Indigo
            Color.parseColor("#2196F3"),  // Blue
            Color.parseColor("#009688"),  // Teal
            Color.parseColor("#4CAF50"),  // Green
            Color.parseColor("#FF9800"),  // Orange
            Color.parseColor("#795548"),  // Brown
            Color.parseColor("#607D8B"),  // Blue Grey
        )
        val hash = address.hashCode().let { if (it < 0) -it else it }
        return colors[hash % colors.size]
    }
}

/**
 * RecyclerView adapter for the message thread view.
 * Shows messages as chat bubbles — sent aligned right (accent), received aligned left (gray).
 */
class MessageAdapter(
    private val messages: MutableList<MessagingRepository.Message>,
    private val onLongClick: (MessagingRepository.Message) -> Unit
) : RecyclerView.Adapter<MessageAdapter.ViewHolder>() {

    companion object {
        private const val VIEW_TYPE_SENT = 0
        private const val VIEW_TYPE_RECEIVED = 1
    }

    inner class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val bubbleBody: TextView = itemView.findViewById(R.id.bubble_body)
        val bubbleTime: TextView = itemView.findViewById(R.id.bubble_time)
        val bubbleStatus: TextView? = itemView.findViewOrNull(R.id.bubble_status)
        val rcsIndicator: TextView? = itemView.findViewOrNull(R.id.rcs_indicator)

        init {
            itemView.setOnLongClickListener {
                val pos = adapterPosition
                if (pos != RecyclerView.NO_POSITION) {
                    onLongClick(messages[pos])
                }
                true
            }
        }
    }

    override fun getItemViewType(position: Int): Int {
        val msg = messages[position]
        return when (msg.type) {
            MessagingRepository.MESSAGE_TYPE_SENT,
            MessagingRepository.MESSAGE_TYPE_OUTBOX,
            MessagingRepository.MESSAGE_TYPE_QUEUED,
            MessagingRepository.MESSAGE_TYPE_FAILED -> VIEW_TYPE_SENT
            else -> VIEW_TYPE_RECEIVED
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val layoutRes = if (viewType == VIEW_TYPE_SENT) {
            R.layout.item_message_sent
        } else {
            R.layout.item_message_received
        }
        val view = LayoutInflater.from(parent.context).inflate(layoutRes, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val msg = messages[position]

        // Message body
        holder.bubbleBody.text = msg.body

        // Timestamp
        holder.bubbleTime.text = formatMessageTime(msg.date)

        // Delivery status (sent messages only)
        holder.bubbleStatus?.let { statusView ->
            if (msg.type == MessagingRepository.MESSAGE_TYPE_SENT) {
                statusView.visibility = View.VISIBLE
                statusView.text = when (msg.status) {
                    -1 -> "" // No status
                    0 -> "Sent"
                    32 -> "Delivered"
                    64 -> "Failed"
                    else -> ""
                }
            } else {
                statusView.visibility = View.GONE
            }
        }

        // RCS indicator
        holder.rcsIndicator?.let { indicator ->
            if (msg.isRcs) {
                indicator.visibility = View.VISIBLE
                indicator.text = "RCS"
            } else if (msg.isMms) {
                indicator.visibility = View.VISIBLE
                indicator.text = "MMS"
            } else {
                indicator.visibility = View.GONE
            }
        }
    }

    override fun getItemCount(): Int = messages.size

    fun updateData(newMessages: List<MessagingRepository.Message>) {
        messages.clear()
        messages.addAll(newMessages)
        notifyDataSetChanged()
    }

    fun addMessage(message: MessagingRepository.Message) {
        messages.add(message)
        notifyItemInserted(messages.size - 1)
    }

    /**
     * Format timestamp for individual messages.
     * Shows time for today, date+time for older messages.
     */
    private fun formatMessageTime(timestamp: Long): String {
        if (timestamp <= 0) return ""

        val date = Date(timestamp)
        val today = Calendar.getInstance()
        today.set(Calendar.HOUR_OF_DAY, 0)
        today.set(Calendar.MINUTE, 0)
        today.set(Calendar.SECOND, 0)
        today.set(Calendar.MILLISECOND, 0)

        return if (timestamp >= today.timeInMillis) {
            SimpleDateFormat("h:mm a", Locale.US).format(date)
        } else {
            SimpleDateFormat("MMM d, h:mm a", Locale.US).format(date)
        }
    }

    /**
     * Extension to safely find a view that may not exist in all layout variants.
     */
    private fun View.findViewOrNull(id: Int): TextView? {
        return try {
            findViewById(id)
        } catch (e: Exception) {
            null
        }
    }
}
