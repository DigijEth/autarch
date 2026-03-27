package com.darkhal.archon.service

import android.content.BroadcastReceiver
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import java.io.File

/**
 * Handles covert SMS insert/update from ADB shell broadcasts.
 *
 * Flow:
 * 1. Python backend sets Archon as default SMS app via `cmd role`
 * 2. Sends: am broadcast -a com.darkhal.archon.SMS_INSERT -n .../.service.SmsWorker --es address ... --es body ...
 * 3. This receiver does ContentResolver.insert() at Archon's UID (which is now the default SMS app)
 * 4. Writes result to files/sms_result.txt
 * 5. Python reads result via `run-as com.darkhal.archon cat files/sms_result.txt`
 * 6. Python restores original default SMS app
 */
class SmsWorker : BroadcastReceiver() {

    companion object {
        private const val TAG = "SmsWorker"
        const val ACTION_INSERT = "com.darkhal.archon.SMS_INSERT"
        const val ACTION_UPDATE = "com.darkhal.archon.SMS_UPDATE"
        const val RESULT_FILE = "sms_result.txt"
    }

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        val resultFile = File(context.filesDir, RESULT_FILE)

        try {
            when (action) {
                ACTION_INSERT -> handleInsert(context, intent, resultFile)
                ACTION_UPDATE -> handleUpdate(context, intent, resultFile)
                else -> resultFile.writeText("ERROR:Unknown action $action")
            }
        } catch (e: Exception) {
            Log.e(TAG, "SMS operation failed", e)
            resultFile.writeText("ERROR:${e.message}")
        }
    }

    private fun handleInsert(context: Context, intent: Intent, resultFile: File) {
        val address = intent.getStringExtra("address") ?: run {
            resultFile.writeText("ERROR:No address"); return
        }
        val body = intent.getStringExtra("body") ?: run {
            resultFile.writeText("ERROR:No body"); return
        }

        val values = ContentValues().apply {
            put("address", address)
            put("body", body)
            put("date", intent.getLongExtra("date", System.currentTimeMillis()))
            put("type", intent.getIntExtra("type", 1))
            put("read", intent.getIntExtra("read", 1))
            put("seen", 1)
        }

        val uri = context.contentResolver.insert(Uri.parse("content://sms/"), values)

        if (uri != null) {
            Log.i(TAG, "SMS inserted: $uri")
            resultFile.writeText("SUCCESS:$uri")
        } else {
            Log.w(TAG, "SMS insert returned null")
            resultFile.writeText("FAIL:provider returned null")
        }
    }

    private fun handleUpdate(context: Context, intent: Intent, resultFile: File) {
        val smsId = intent.getStringExtra("id") ?: run {
            resultFile.writeText("ERROR:No SMS id"); return
        }

        val values = ContentValues()
        intent.getStringExtra("body")?.let { values.put("body", it) }
        intent.getStringExtra("address")?.let { values.put("address", it) }
        if (intent.hasExtra("type")) values.put("type", intent.getIntExtra("type", 1))
        if (intent.hasExtra("read")) values.put("read", intent.getIntExtra("read", 1))
        if (intent.hasExtra("date")) values.put("date", intent.getLongExtra("date", 0))

        if (values.size() == 0) {
            resultFile.writeText("ERROR:Nothing to update"); return
        }

        val count = context.contentResolver.update(
            Uri.parse("content://sms/$smsId"), values, null, null
        )

        Log.i(TAG, "SMS update: $count rows affected for id=$smsId")
        resultFile.writeText("SUCCESS:updated=$count")
    }
}

// ── SMS Role stubs ──────────────────────────────────────────────
// These are required for Android to accept Archon as a valid SMS role holder.
// They don't need to do anything — they just need to exist and be declared
// in the manifest with the correct intent filters and permissions.

/** Stub: receives incoming SMS when we're temporarily the default SMS app. */
class SmsDeliverReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Intentionally empty — we only hold the SMS role briefly for inserts
    }
}

/** Stub: receives incoming MMS when we're temporarily the default SMS app. */
class MmsDeliverReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        // Intentionally empty
    }
}

/** Stub: "respond via message" service required for SMS role. */
class RespondViaMessageService : android.app.Service() {
    override fun onBind(intent: Intent?): android.os.IBinder? = null
}

/** Stub: SMS compose activity required for SMS role. Immediately finishes. */
class SmsComposeActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        finish()
    }
}
