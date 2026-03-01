package com.darkhal.archon.ui

import android.content.Context
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.darkhal.archon.R
import com.darkhal.archon.module.ModuleManager
import com.darkhal.archon.module.ReverseShellModule
import com.darkhal.archon.server.ArchonClient
import com.darkhal.archon.util.PrivilegeManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText

class ModulesFragment : Fragment() {

    private lateinit var serverStatusDot: View
    private lateinit var serverStatusText: TextView
    private lateinit var archonStatusDot: View
    private lateinit var archonInfoText: TextView
    private lateinit var archonUidText: TextView
    private lateinit var inputArchonCmd: TextInputEditText
    private lateinit var shieldStatusDot: View
    private lateinit var shieldStatusText: TextView
    private lateinit var honeypotStatusDot: View
    private lateinit var honeypotStatusText: TextView
    private lateinit var revshellStatusDot: View
    private lateinit var revshellStatusText: TextView
    private lateinit var outputLog: TextView

    private val handler = Handler(Looper.getMainLooper())

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_modules, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Bind views
        serverStatusDot = view.findViewById(R.id.server_status_dot)
        serverStatusText = view.findViewById(R.id.server_status_text)
        archonStatusDot = view.findViewById(R.id.archon_status_dot)
        archonInfoText = view.findViewById(R.id.archon_info_text)
        archonUidText = view.findViewById(R.id.archon_uid_text)
        inputArchonCmd = view.findViewById(R.id.input_archon_cmd)
        shieldStatusDot = view.findViewById(R.id.shield_status_dot)
        shieldStatusText = view.findViewById(R.id.shield_status_text)
        honeypotStatusDot = view.findViewById(R.id.honeypot_status_dot)
        honeypotStatusText = view.findViewById(R.id.honeypot_status_text)
        revshellStatusDot = view.findViewById(R.id.revshell_status_dot)
        revshellStatusText = view.findViewById(R.id.revshell_status_text)
        outputLog = view.findViewById(R.id.modules_output_log)

        // Archon Server buttons
        view.findViewById<MaterialButton>(R.id.btn_archon_run).setOnClickListener {
            val cmd = inputArchonCmd.text?.toString()?.trim() ?: ""
            if (cmd.isEmpty()) {
                appendLog("Enter a command to run")
                return@setOnClickListener
            }
            runArchonCommand(cmd)
        }

        view.findViewById<MaterialButton>(R.id.btn_archon_info).setOnClickListener {
            appendLog("Querying server info...")
            Thread {
                val info = ArchonClient.getServerInfo(requireContext())
                handler.post {
                    if (info != null) {
                        appendLog("Archon: $info")
                        archonInfoText.text = "Info: $info"
                    } else {
                        appendLog("Archon Server not running")
                        archonInfoText.text = "Status: not running"
                    }
                }
            }.start()
        }

        view.findViewById<MaterialButton>(R.id.btn_archon_ping).setOnClickListener {
            Thread {
                val running = ArchonClient.isServerRunning(requireContext())
                handler.post {
                    setStatusDot(archonStatusDot, running)
                    appendLog(if (running) "Archon: pong" else "Archon: no response")
                }
            }.start()
        }

        view.findViewById<MaterialButton>(R.id.btn_archon_packages).setOnClickListener {
            runArchonCommand("pm list packages -3")
        }

        // Shield buttons
        view.findViewById<MaterialButton>(R.id.btn_shield_full_scan).setOnClickListener {
            runModuleAction("shield", "full_scan", "Full Scan")
        }
        view.findViewById<MaterialButton>(R.id.btn_shield_scan_packages).setOnClickListener {
            runModuleAction("shield", "scan_packages", "Package Scan")
        }
        view.findViewById<MaterialButton>(R.id.btn_shield_scan_admins).setOnClickListener {
            runModuleAction("shield", "scan_device_admins", "Device Admin Scan")
        }
        view.findViewById<MaterialButton>(R.id.btn_shield_scan_certs).setOnClickListener {
            runModuleAction("shield", "scan_certificates", "Certificate Scan")
        }
        view.findViewById<MaterialButton>(R.id.btn_shield_scan_network).setOnClickListener {
            runModuleAction("shield", "scan_network", "Network Scan")
        }

        // Honeypot buttons
        view.findViewById<MaterialButton>(R.id.btn_honeypot_harden).setOnClickListener {
            runModuleAction("honeypot", "harden_all", "Harden All")
        }
        view.findViewById<MaterialButton>(R.id.btn_honeypot_reset_ad).setOnClickListener {
            runModuleAction("honeypot", "reset_ad_id", "Reset Ad ID")
        }
        view.findViewById<MaterialButton>(R.id.btn_honeypot_dns).setOnClickListener {
            runModuleAction("honeypot", "set_private_dns", "Private DNS")
        }
        view.findViewById<MaterialButton>(R.id.btn_honeypot_restrict).setOnClickListener {
            runModuleAction("honeypot", "restrict_trackers", "Restrict Trackers")
        }
        view.findViewById<MaterialButton>(R.id.btn_honeypot_revoke).setOnClickListener {
            runModuleAction("honeypot", "revoke_tracker_perms", "Revoke Tracker Perms")
        }

        // Reverse Shell buttons
        view.findViewById<MaterialButton>(R.id.btn_revshell_enable).setOnClickListener {
            showRevshellWarnings(0)
        }
        view.findViewById<MaterialButton>(R.id.btn_revshell_disable).setOnClickListener {
            runModuleAction("revshell", "disable", "Disable")
        }
        view.findViewById<MaterialButton>(R.id.btn_revshell_connect).setOnClickListener {
            runModuleAction("revshell", "connect", "Connect")
        }
        view.findViewById<MaterialButton>(R.id.btn_revshell_disconnect).setOnClickListener {
            runModuleAction("revshell", "disconnect", "Disconnect")
        }
        view.findViewById<MaterialButton>(R.id.btn_revshell_status).setOnClickListener {
            runModuleAction("revshell", "status", "Status")
        }

        // Initialize status
        refreshStatus()
    }

    private fun refreshStatus() {
        Thread {
            val method = PrivilegeManager.getAvailableMethod()
            val archonRunning = ArchonClient.isServerRunning(requireContext())
            val serverInfo = if (archonRunning) {
                ArchonClient.getServerInfo(requireContext()) ?: "running"
            } else {
                null
            }

            val shieldStatus = ModuleManager.get("shield")?.getStatus(requireContext())
            val honeypotStatus = ModuleManager.get("honeypot")?.getStatus(requireContext())
            val revshellStatus = ModuleManager.get("revshell")?.getStatus(requireContext())

            handler.post {
                // Server status
                val serverActive = method != PrivilegeManager.Method.NONE
                setStatusDot(serverStatusDot, serverActive)
                serverStatusText.text = when (method) {
                    PrivilegeManager.Method.ROOT -> "Privilege: Root (su)"
                    PrivilegeManager.Method.ARCHON_SERVER -> "Privilege: Archon Server"
                    PrivilegeManager.Method.LOCAL_ADB -> "Privilege: Wireless ADB"
                    PrivilegeManager.Method.SERVER_ADB -> "Privilege: AUTARCH Remote"
                    PrivilegeManager.Method.NONE -> "Privilege: none — run Setup first"
                }

                // Archon Server status
                setStatusDot(archonStatusDot, archonRunning)
                archonInfoText.text = if (archonRunning) {
                    "Status: Running ($serverInfo)"
                } else {
                    "Status: Not running — start in Setup tab"
                }

                // Module status
                setStatusDot(shieldStatusDot, shieldStatus?.active == true)
                shieldStatusText.text = "Last: ${shieldStatus?.summary ?: "no scan run"}"

                setStatusDot(honeypotStatusDot, honeypotStatus?.active == true)
                honeypotStatusText.text = "Status: ${honeypotStatus?.summary ?: "idle"}"

                setStatusDot(revshellStatusDot, revshellStatus?.active == true)
                revshellStatusText.text = "Status: ${revshellStatus?.summary ?: "Disabled"}"

                appendLog("Privilege: ${method.label}")
                if (archonRunning) appendLog("Archon Server: active")
            }
        }.start()
    }

    private fun runArchonCommand(command: String) {
        appendLog("$ $command")

        Thread {
            val method = PrivilegeManager.getAvailableMethod()
            if (method == PrivilegeManager.Method.NONE) {
                handler.post { appendLog("Error: No privilege method — run Setup first") }
                return@Thread
            }

            val result = PrivilegeManager.execute(command)
            handler.post {
                if (result.stdout.isNotEmpty()) {
                    // Show up to 30 lines
                    val lines = result.stdout.split("\n").take(30)
                    for (line in lines) {
                        appendLog(line)
                    }
                    if (result.stdout.split("\n").size > 30) {
                        appendLog("... (${result.stdout.split("\n").size - 30} more lines)")
                    }
                }
                if (result.stderr.isNotEmpty()) {
                    appendLog("ERR: ${result.stderr}")
                }
                if (result.exitCode != 0) {
                    appendLog("exit: ${result.exitCode}")
                }
            }
        }.start()
    }

    private fun runModuleAction(moduleId: String, actionId: String, label: String) {
        appendLog("Running: $label...")

        Thread {
            val result = ModuleManager.executeAction(moduleId, actionId, requireContext())

            handler.post {
                appendLog("$label: ${result.output}")
                for (detail in result.details.take(20)) {
                    appendLog("  $detail")
                }

                // Update module status after action
                when (moduleId) {
                    "shield" -> shieldStatusText.text = "Last: ${result.output}"
                    "honeypot" -> honeypotStatusText.text = "Status: ${result.output}"
                    "revshell" -> revshellStatusText.text = "Status: ${result.output}"
                }
            }
        }.start()
    }

    private fun setStatusDot(dot: View, online: Boolean) {
        val drawable = GradientDrawable()
        drawable.shape = GradientDrawable.OVAL
        drawable.setColor(if (online) Color.parseColor("#00FF41") else Color.parseColor("#666666"))
        dot.background = drawable
    }

    private fun appendLog(msg: String) {
        val current = outputLog.text.toString()
        val lines = current.split("\n").takeLast(30)
        outputLog.text = (lines + "> $msg").joinToString("\n")
    }

    /**
     * Show reverse shell safety warnings one at a time.
     * After all 3 are accepted, set the warning flag and run the enable action.
     */
    private fun showRevshellWarnings(index: Int) {
        val warnings = ReverseShellModule.WARNINGS
        if (index >= warnings.size) {
            // All warnings accepted — set the prefs flag and enable
            val prefs = requireContext().getSharedPreferences("archon_revshell", Context.MODE_PRIVATE)
            prefs.edit().putBoolean("revshell_warnings_accepted", true).apply()
            appendLog("All warnings accepted")
            runModuleAction("revshell", "enable", "Enable")
            return
        }

        AlertDialog.Builder(requireContext())
            .setTitle("Warning ${index + 1} of ${warnings.size}")
            .setMessage(warnings[index])
            .setPositiveButton("I Understand") { _, _ ->
                showRevshellWarnings(index + 1)
            }
            .setNegativeButton("Cancel") { _, _ ->
                appendLog("Reverse shell enable cancelled at warning ${index + 1}")
            }
            .setCancelable(false)
            .show()
    }
}
