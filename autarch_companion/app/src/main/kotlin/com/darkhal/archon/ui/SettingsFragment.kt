package com.darkhal.archon.ui

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.fragment.app.Fragment
import com.darkhal.archon.LoginActivity
import com.darkhal.archon.R
import com.darkhal.archon.service.DiscoveryManager
import com.darkhal.archon.util.AuthManager
import com.darkhal.archon.util.PrefsManager
import com.darkhal.archon.util.ShellExecutor
import com.darkhal.archon.util.SslHelper
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText

class SettingsFragment : Fragment() {

    private lateinit var inputServerIp: TextInputEditText
    private lateinit var inputWebPort: TextInputEditText
    private lateinit var inputAdbPort: TextInputEditText
    private lateinit var inputUsbipPort: TextInputEditText
    private lateinit var switchAutoRestart: MaterialSwitch
    private lateinit var statusText: TextView

    private val handler = Handler(Looper.getMainLooper())

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_settings, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        inputServerIp = view.findViewById(R.id.input_server_ip)
        inputWebPort = view.findViewById(R.id.input_web_port)
        inputAdbPort = view.findViewById(R.id.input_adb_port)
        inputUsbipPort = view.findViewById(R.id.input_usbip_port)
        switchAutoRestart = view.findViewById(R.id.switch_settings_auto_restart)
        statusText = view.findViewById(R.id.settings_status)

        loadSettings()

        view.findViewById<MaterialButton>(R.id.btn_save_settings).setOnClickListener {
            saveSettings()
        }

        view.findViewById<MaterialButton>(R.id.btn_auto_detect).setOnClickListener {
            autoDetectServer(it as MaterialButton)
        }

        view.findViewById<MaterialButton>(R.id.btn_test_connection).setOnClickListener {
            testConnection()
        }

        view.findViewById<MaterialButton>(R.id.btn_logout).setOnClickListener {
            AuthManager.logout(requireContext())
            val intent = android.content.Intent(requireContext(), LoginActivity::class.java)
            intent.flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK or android.content.Intent.FLAG_ACTIVITY_CLEAR_TASK
            startActivity(intent)
        }
    }

    private fun loadSettings() {
        val ctx = requireContext()
        inputServerIp.setText(PrefsManager.getServerIp(ctx))
        inputWebPort.setText(PrefsManager.getWebPort(ctx).toString())
        inputAdbPort.setText(PrefsManager.getAdbPort(ctx).toString())
        inputUsbipPort.setText(PrefsManager.getUsbIpPort(ctx).toString())
        switchAutoRestart.isChecked = PrefsManager.isAutoRestartAdb(ctx)
    }

    private fun saveSettings() {
        val ctx = requireContext()

        val serverIp = inputServerIp.text.toString().trim()
        val webPort = inputWebPort.text.toString().trim().toIntOrNull() ?: 8181
        val adbPort = inputAdbPort.text.toString().trim().toIntOrNull() ?: 5555
        val usbipPort = inputUsbipPort.text.toString().trim().toIntOrNull() ?: 3240

        if (serverIp.isEmpty()) {
            statusText.text = "Error: Server IP cannot be empty"
            return
        }

        // Validate IP format (IPv4 or hostname)
        if (!isValidIpOrHostname(serverIp)) {
            statusText.text = "Error: Invalid IP address or hostname"
            return
        }

        // Validate port ranges
        if (webPort < 1 || webPort > 65535) {
            statusText.text = "Error: Web port must be 1-65535"
            return
        }
        if (adbPort < 1 || adbPort > 65535) {
            statusText.text = "Error: ADB port must be 1-65535"
            return
        }

        PrefsManager.setServerIp(ctx, serverIp)
        PrefsManager.setWebPort(ctx, webPort)
        PrefsManager.setAdbPort(ctx, adbPort)
        PrefsManager.setUsbIpPort(ctx, usbipPort)
        PrefsManager.setAutoRestartAdb(ctx, switchAutoRestart.isChecked)

        statusText.text = "Settings saved"
        Toast.makeText(ctx, "Settings saved", Toast.LENGTH_SHORT).show()
    }

    private fun isValidIpOrHostname(input: String): Boolean {
        // IPv4 pattern
        val ipv4 = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
        val match = ipv4.matchEntire(input)
        if (match != null) {
            return match.groupValues.drop(1).all {
                val n = it.toIntOrNull() ?: return false
                n in 0..255
            }
        }
        // Hostname pattern (alphanumeric, dots, hyphens)
        val hostname = Regex("""^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$""")
        return hostname.matches(input)
    }

    private fun autoDetectServer(btn: MaterialButton) {
        statusText.text = "Scanning for AUTARCH server..."
        btn.isEnabled = false
        btn.text = "SCANNING..."

        val discovery = DiscoveryManager(requireContext())
        discovery.listener = object : DiscoveryManager.Listener {
            override fun onServerFound(server: DiscoveryManager.DiscoveredServer) {
                discovery.stopDiscovery()

                val method = when (server.method) {
                    DiscoveryManager.ConnectionMethod.MDNS -> "LAN (mDNS)"
                    DiscoveryManager.ConnectionMethod.WIFI_DIRECT -> "Wi-Fi Direct"
                    DiscoveryManager.ConnectionMethod.BLUETOOTH -> "Bluetooth"
                }

                if (server.ip.isNotEmpty()) {
                    inputServerIp.setText(server.ip)
                }
                if (server.port > 0) {
                    inputWebPort.setText(server.port.toString())
                }

                statusText.text = "Found ${server.hostname} via $method\nIP: ${server.ip}  Port: ${server.port}"
                btn.isEnabled = true
                btn.text = "AUTO-DETECT SERVER"
            }

            override fun onDiscoveryStarted(method: DiscoveryManager.ConnectionMethod) {}

            override fun onDiscoveryStopped(method: DiscoveryManager.ConnectionMethod) {
                if (discovery.getDiscoveredServers().isEmpty()) {
                    handler.post {
                        statusText.text = "No AUTARCH server found on network.\nCheck that the server is running and on the same network."
                        btn.isEnabled = true
                        btn.text = "AUTO-DETECT SERVER"
                    }
                }
            }

            override fun onDiscoveryError(method: DiscoveryManager.ConnectionMethod, error: String) {}
        }
        discovery.startDiscovery()
    }

    private fun testConnection() {
        val serverIp = inputServerIp.text.toString().trim()
        val webPort = inputWebPort.text.toString().trim().toIntOrNull() ?: 8181

        if (serverIp.isEmpty()) {
            statusText.text = "Error: Enter a server IP first"
            return
        }

        if (!isValidIpOrHostname(serverIp)) {
            statusText.text = "Error: Invalid IP address"
            return
        }

        statusText.text = "Testing connection to $serverIp..."

        Thread {
            // Ping test
            val pingResult = ShellExecutor.execute("ping -c 1 -W 3 $serverIp")
            val pingOk = pingResult.exitCode == 0

            // HTTPS test — probe root endpoint
            val httpOk = try {
                val url = java.net.URL("https://$serverIp:$webPort/")
                val conn = url.openConnection() as java.net.HttpURLConnection
                SslHelper.trustSelfSigned(conn)
                conn.connectTimeout = 5000
                conn.readTimeout = 5000
                conn.requestMethod = "GET"
                val code = conn.responseCode
                conn.disconnect()
                code in 200..399
            } catch (e: Exception) {
                false
            }

            handler.post {
                val status = StringBuilder()
                status.append("Ping: ${if (pingOk) "OK" else "FAILED"}\n")
                status.append("HTTPS ($webPort): ${if (httpOk) "OK" else "FAILED"}")
                if (!pingOk && !httpOk) {
                    status.append("\n\nServer unreachable. Check WireGuard tunnel and IP.")
                } else if (pingOk && !httpOk) {
                    status.append("\n\nHost reachable but web UI not responding on port $webPort.")
                }
                statusText.text = status.toString()
            }
        }.start()
    }
}
