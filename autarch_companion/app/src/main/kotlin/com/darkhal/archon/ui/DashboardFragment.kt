package com.darkhal.archon.ui

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.darkhal.archon.R
import com.darkhal.archon.service.DiscoveryManager
import com.darkhal.archon.util.PrefsManager
import com.darkhal.archon.util.PrivilegeManager
import com.darkhal.archon.util.ShellExecutor
import com.darkhal.archon.util.SslHelper
import com.google.android.material.button.MaterialButton
import java.net.HttpURLConnection
import java.net.URL

class DashboardFragment : Fragment() {

    private lateinit var privilegeStatusDot: View
    private lateinit var privilegeStatusText: TextView
    private lateinit var serverStatusDot: View
    private lateinit var serverStatusText: TextView
    private lateinit var wgStatusDot: View
    private lateinit var wgStatusText: TextView
    private lateinit var outputLog: TextView

    // Discovery
    private lateinit var discoveryStatusDot: View
    private lateinit var discoveryStatusText: TextView
    private lateinit var discoveryMethodText: TextView
    private lateinit var btnDiscover: MaterialButton
    private var discoveryManager: DiscoveryManager? = null

    private val handler = Handler(Looper.getMainLooper())

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_dashboard, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        // Bind views
        privilegeStatusDot = view.findViewById(R.id.privilege_status_dot)
        privilegeStatusText = view.findViewById(R.id.privilege_status_text)
        serverStatusDot = view.findViewById(R.id.server_status_dot)
        serverStatusText = view.findViewById(R.id.server_status_text)
        wgStatusDot = view.findViewById(R.id.wg_status_dot)
        wgStatusText = view.findViewById(R.id.wg_status_text)
        outputLog = view.findViewById(R.id.output_log)

        // Discovery views
        discoveryStatusDot = view.findViewById(R.id.discovery_status_dot)
        discoveryStatusText = view.findViewById(R.id.discovery_status_text)
        discoveryMethodText = view.findViewById(R.id.discovery_method_text)
        btnDiscover = view.findViewById(R.id.btn_discover)

        setupDiscovery()

        // Initialize PrivilegeManager and check available methods
        val ctx = requireContext()
        PrivilegeManager.init(ctx, PrefsManager.getServerIp(ctx), PrefsManager.getWebPort(ctx))

        Thread {
            val method = PrivilegeManager.getAvailableMethod()
            handler.post {
                val hasPrivilege = method != PrivilegeManager.Method.NONE
                setStatusDot(privilegeStatusDot, hasPrivilege)
                privilegeStatusText.text = "Privilege: ${method.label}"
                appendLog("Privilege: ${method.label}")
                refreshServerStatus()
            }
        }.start()

        // Auto-discover server on launch
        startDiscovery()
    }

    private fun refreshServerStatus() {
        Thread {
            val serverIp = PrefsManager.getServerIp(requireContext())
            val webPort = PrefsManager.getWebPort(requireContext())

            // Check WireGuard tunnel
            val wgResult = ShellExecutor.execute("ip addr show wg0 2>/dev/null")
            val wgUp = wgResult.exitCode == 0 && wgResult.stdout.contains("inet ")

            // Check if AUTARCH server is reachable
            val serverReachable = if (serverIp.isNotEmpty()) {
                probeServer(serverIp, webPort)
            } else {
                false
            }

            handler.post {
                // WireGuard
                setStatusDot(wgStatusDot, wgUp)
                wgStatusText.text = if (wgUp) "WireGuard: connected" else "WireGuard: not active"

                // Server
                if (serverIp.isEmpty()) {
                    setStatusDot(serverStatusDot, false)
                    serverStatusText.text = "Server: not configured — tap SCAN or set in Settings"
                } else if (serverReachable) {
                    setStatusDot(serverStatusDot, true)
                    serverStatusText.text = "Server: $serverIp:$webPort (connected)"
                } else {
                    setStatusDot(serverStatusDot, false)
                    serverStatusText.text = "Server: $serverIp:$webPort (unreachable)"
                }
            }
        }.start()
    }

    private fun probeServer(ip: String, port: Int): Boolean {
        return try {
            val url = URL("https://$ip:$port/")
            val conn = url.openConnection() as HttpURLConnection
            SslHelper.trustSelfSigned(conn)
            conn.connectTimeout = 3000
            conn.readTimeout = 3000
            conn.requestMethod = "GET"
            conn.instanceFollowRedirects = true
            val code = conn.responseCode
            conn.disconnect()
            code in 200..399
        } catch (e: Exception) {
            false
        }
    }

    private fun setStatusDot(dot: View, online: Boolean) {
        val drawable = GradientDrawable()
        drawable.shape = GradientDrawable.OVAL
        drawable.setColor(if (online) Color.parseColor("#00FF41") else Color.parseColor("#666666"))
        dot.background = drawable
    }

    private fun appendLog(msg: String) {
        val current = outputLog.text.toString()
        val lines = current.split("\n").takeLast(20)
        outputLog.text = (lines + "> $msg").joinToString("\n")
    }

    // ── Discovery ────────────────────────────────────────────────

    private fun setupDiscovery() {
        discoveryManager = DiscoveryManager(requireContext())
        discoveryManager?.listener = object : DiscoveryManager.Listener {
            override fun onServerFound(server: DiscoveryManager.DiscoveredServer) {
                val method = when (server.method) {
                    DiscoveryManager.ConnectionMethod.MDNS -> "LAN (mDNS)"
                    DiscoveryManager.ConnectionMethod.WIFI_DIRECT -> "Wi-Fi Direct"
                    DiscoveryManager.ConnectionMethod.BLUETOOTH -> "Bluetooth"
                }
                setStatusDot(discoveryStatusDot, true)
                discoveryStatusText.text = "Found: ${server.hostname}"
                discoveryMethodText.text = "via $method"
                appendLog("Discovered AUTARCH via $method")

                if (server.ip.isNotEmpty() && server.port > 0) {
                    PrefsManager.setServerIp(requireContext(), server.ip)
                    PrefsManager.setWebPort(requireContext(), server.port)
                    appendLog("Auto-configured: ${server.ip}:${server.port}")
                    // Update PrivilegeManager with new server info
                    PrivilegeManager.setServerConnection(server.ip, server.port)
                    refreshServerStatus()
                }
            }

            override fun onDiscoveryStarted(method: DiscoveryManager.ConnectionMethod) {
                appendLog("Scanning: ${method.name}...")
            }

            override fun onDiscoveryStopped(method: DiscoveryManager.ConnectionMethod) {
                if (discoveryManager?.getDiscoveredServers()?.isEmpty() == true) {
                    appendLog("No mDNS/BT response — trying HTTP probe...")
                    probeLocalSubnet()
                }
                btnDiscover.isEnabled = true
                btnDiscover.text = "SCAN"
            }

            override fun onDiscoveryError(method: DiscoveryManager.ConnectionMethod, error: String) {
                appendLog("${method.name}: $error")
            }
        }

        btnDiscover.setOnClickListener {
            startDiscovery()
        }
    }

    private fun startDiscovery() {
        setStatusDot(discoveryStatusDot, false)
        discoveryStatusText.text = "Scanning network..."
        discoveryMethodText.text = "mDNS / Wi-Fi Direct / Bluetooth / HTTP"
        btnDiscover.isEnabled = false
        btnDiscover.text = "SCANNING..."
        discoveryManager?.startDiscovery()
    }

    private fun probeLocalSubnet() {
        Thread {
            val port = PrefsManager.getWebPort(requireContext())

            val routeResult = ShellExecutor.execute("ip route show default 2>/dev/null")
            val gateway = routeResult.stdout.split(" ").let { parts ->
                val idx = parts.indexOf("via")
                if (idx >= 0 && idx + 1 < parts.size) parts[idx + 1] else null
            }

            if (gateway == null) {
                handler.post {
                    discoveryStatusText.text = "No AUTARCH server found"
                    discoveryMethodText.text = "Set server IP in Settings tab"
                }
                return@Thread
            }

            val base = gateway.substringBeforeLast(".") + "."
            appendLogOnUi("Probing ${base}x on port $port...")

            val candidates = mutableListOf<String>()
            candidates.add(gateway)
            for (i in 1..30) {
                val ip = "$base$i"
                if (ip != gateway) candidates.add(ip)
            }
            candidates.addAll(listOf("${base}100", "${base}200", "${base}254"))

            val savedIp = PrefsManager.getServerIp(requireContext())
            if (savedIp.isNotEmpty() && !savedIp.startsWith("10.1.0.")) {
                candidates.add(0, savedIp)
            }

            for (ip in candidates) {
                if (probeServer(ip, port)) {
                    handler.post {
                        PrefsManager.setServerIp(requireContext(), ip)
                        setStatusDot(discoveryStatusDot, true)
                        discoveryStatusText.text = "Found: AUTARCH"
                        discoveryMethodText.text = "via HTTP probe ($ip)"
                        appendLog("Found AUTARCH at $ip:$port (HTTP)")
                        PrivilegeManager.setServerConnection(ip, port)
                        refreshServerStatus()
                    }
                    return@Thread
                }
            }

            handler.post {
                discoveryStatusText.text = "No AUTARCH server found"
                discoveryMethodText.text = "Set server IP in Settings tab"
                appendLog("HTTP probe: no server found on $base* :$port")
            }
        }.start()
    }

    private fun appendLogOnUi(msg: String) {
        handler.post { appendLog(msg) }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        discoveryManager?.stopDiscovery()
    }
}
