package com.darkhal.archon.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.darkhal.archon.R
import com.darkhal.archon.server.ArchonClient
import com.darkhal.archon.service.LocalAdbClient
import com.darkhal.archon.service.PairingReceiver
import com.darkhal.archon.util.PrefsManager
import com.darkhal.archon.util.PrivilegeManager
import com.darkhal.archon.util.ShellExecutor
import com.google.android.material.button.MaterialButton

class SetupFragment : Fragment() {

    private lateinit var privilegeStatusDot: View
    private lateinit var privilegeStatusText: TextView
    private lateinit var btnStartPairing: MaterialButton
    private lateinit var localAdbStatus: TextView
    private lateinit var archonServerStatusDot: View
    private lateinit var archonServerStatus: TextView
    private lateinit var btnStartArchonServer: MaterialButton
    private lateinit var btnStopArchonServer: MaterialButton
    private lateinit var btnShowCommand: MaterialButton
    private lateinit var serverAdbStatus: TextView
    private lateinit var btnBootstrapUsb: MaterialButton
    private lateinit var rootStatus: TextView
    private lateinit var btnCheckRoot: MaterialButton
    private lateinit var btnRootExploit: MaterialButton
    private lateinit var outputLog: TextView

    private val handler = Handler(Looper.getMainLooper())

    // Notification permission request (Android 13+)
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            startPairingNotification()
        } else {
            appendLog("Notification permission denied — cannot show pairing notification")
            appendLog("Grant notification permission in app settings")
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_setup, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Bind views
        privilegeStatusDot = view.findViewById(R.id.privilege_status_dot)
        privilegeStatusText = view.findViewById(R.id.privilege_status_text)
        btnStartPairing = view.findViewById(R.id.btn_start_pairing)
        localAdbStatus = view.findViewById(R.id.local_adb_status)
        archonServerStatusDot = view.findViewById(R.id.archon_server_status_dot)
        archonServerStatus = view.findViewById(R.id.archon_server_status)
        btnStartArchonServer = view.findViewById(R.id.btn_start_archon_server)
        btnStopArchonServer = view.findViewById(R.id.btn_stop_archon_server)
        btnShowCommand = view.findViewById(R.id.btn_show_command)
        serverAdbStatus = view.findViewById(R.id.server_adb_status)
        btnBootstrapUsb = view.findViewById(R.id.btn_bootstrap_usb)
        rootStatus = view.findViewById(R.id.root_status)
        btnCheckRoot = view.findViewById(R.id.btn_check_root)
        btnRootExploit = view.findViewById(R.id.btn_root_exploit)
        outputLog = view.findViewById(R.id.setup_output_log)

        setupListeners()
        initializeStatus()
    }

    private fun setupListeners() {
        // ── Wireless Debugging (Shizuku-style notification) ──
        btnStartPairing.setOnClickListener {
            // Check notification permission for Android 13+
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (ContextCompat.checkSelfPermission(
                        requireContext(), Manifest.permission.POST_NOTIFICATIONS
                    ) != PackageManager.PERMISSION_GRANTED
                ) {
                    notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    return@setOnClickListener
                }
            }
            startPairingNotification()
        }

        // ── Archon Server ──
        btnStartArchonServer.setOnClickListener {
            btnStartArchonServer.isEnabled = false
            appendLog("Starting Archon Server...")

            Thread {
                val result = ArchonClient.startServer(requireContext())
                handler.post {
                    btnStartArchonServer.isEnabled = true
                    appendLog(result.message)
                    updateArchonServerStatus()
                    if (result.success) {
                        PrivilegeManager.refreshMethod()
                        updatePrivilegeStatus()
                    }
                }
            }.start()
        }

        btnStopArchonServer.setOnClickListener {
            appendLog("Stopping Archon Server...")
            Thread {
                val stopped = ArchonClient.stopServer(requireContext())
                handler.post {
                    appendLog(if (stopped) "Server stopped" else "Failed to stop server")
                    updateArchonServerStatus()
                    PrivilegeManager.refreshMethod()
                    updatePrivilegeStatus()
                }
            }.start()
        }

        btnShowCommand.setOnClickListener {
            val cmd = ArchonClient.getBootstrapCommand(requireContext())
            appendLog("ADB command to start Archon Server:")
            appendLog("adb shell \"$cmd\"")

            // Copy to clipboard
            val clipboard = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(ClipData.newPlainText("Archon Bootstrap", "adb shell \"$cmd\""))
            Toast.makeText(requireContext(), "Command copied to clipboard", Toast.LENGTH_SHORT).show()
        }

        // ── USB via AUTARCH ──
        btnBootstrapUsb.setOnClickListener {
            val serverIp = PrefsManager.getServerIp(requireContext())
            val serverPort = PrefsManager.getWebPort(requireContext())

            if (serverIp.isEmpty()) {
                appendLog("Server not configured — set IP in Settings tab or use SCAN on Dashboard")
                return@setOnClickListener
            }

            btnBootstrapUsb.isEnabled = false
            appendLog("Bootstrapping via AUTARCH USB ADB ($serverIp:$serverPort)...")

            Thread {
                val result = ArchonClient.startServer(requireContext())
                handler.post {
                    btnBootstrapUsb.isEnabled = true
                    appendLog(result.message)
                    if (result.success) {
                        updateArchonServerStatus()
                        PrivilegeManager.refreshMethod()
                        updatePrivilegeStatus()
                    }
                }
            }.start()
        }

        // ── Root ──
        btnCheckRoot.setOnClickListener {
            appendLog("Checking root access...")
            Thread {
                val hasRoot = ShellExecutor.isRootAvailable()
                handler.post {
                    rootStatus.text = if (hasRoot) "Status: rooted" else "Status: not rooted"
                    appendLog(if (hasRoot) "Root access available" else "Device is not rooted")
                    if (hasRoot) {
                        PrivilegeManager.refreshMethod()
                        updatePrivilegeStatus()
                    }
                }
            }.start()
        }

        btnRootExploit.setOnClickListener {
            val serverIp = PrefsManager.getServerIp(requireContext())
            val serverPort = PrefsManager.getWebPort(requireContext())
            if (serverIp.isEmpty()) {
                appendLog("Server not configured — set IP in Settings tab")
                return@setOnClickListener
            }
            val url = "https://$serverIp:$serverPort/android-exploit"
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                appendLog("Opened exploit page in browser")
            } catch (e: Exception) {
                appendLog("Could not open browser: ${e.message}")
            }
        }
    }

    private fun startPairingNotification() {
        appendLog("Showing pairing notification...")
        appendLog("Now open Developer Options > Wireless Debugging > Pair with code")
        appendLog("Enter the 6-digit code in the notification")
        PairingReceiver.showPairingNotification(requireContext())
        localAdbStatus.text = "Status: waiting for pairing code in notification..."
    }

    private fun initializeStatus() {
        appendLog("Checking available privilege methods...")

        val ctx = requireContext()
        PrivilegeManager.init(
            ctx,
            PrefsManager.getServerIp(ctx),
            PrefsManager.getWebPort(ctx)
        )

        Thread {
            val hasRoot = ShellExecutor.isRootAvailable()
            val method = PrivilegeManager.refreshMethod()

            handler.post {
                rootStatus.text = if (hasRoot) "Status: rooted" else "Status: not rooted"
                localAdbStatus.text = "Status: ${LocalAdbClient.getStatusString(requireContext())}"

                val serverIp = PrefsManager.getServerIp(ctx)
                serverAdbStatus.text = if (serverIp.isNotEmpty()) {
                    "Server: $serverIp:${PrefsManager.getWebPort(ctx)}"
                } else {
                    "Server: not configured — set IP in Settings or SCAN on Dashboard"
                }

                updateArchonServerStatus()
                updatePrivilegeStatus()
                appendLog("Best method: ${method.label}")
            }
        }.start()
    }

    private fun updatePrivilegeStatus() {
        val method = PrivilegeManager.getAvailableMethod()
        val isReady = method != PrivilegeManager.Method.NONE

        setStatusDot(privilegeStatusDot, isReady)
        privilegeStatusText.text = "Privilege: ${method.label}"
    }

    private fun updateArchonServerStatus() {
        Thread {
            val running = ArchonClient.isServerRunning(requireContext())
            val info = if (running) ArchonClient.getServerInfo(requireContext()) else null

            handler.post {
                setStatusDot(archonServerStatusDot, running)
                archonServerStatus.text = if (running) {
                    "Status: Running ($info)"
                } else {
                    "Status: Not running"
                }
                btnStopArchonServer.isEnabled = running
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
        val lines = current.split("\n").takeLast(25)
        outputLog.text = (lines + "> $msg").joinToString("\n")
    }
}
