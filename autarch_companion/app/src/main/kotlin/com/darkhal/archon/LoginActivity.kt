package com.darkhal.archon

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.darkhal.archon.service.DiscoveryManager
import com.darkhal.archon.util.AuthManager
import com.darkhal.archon.util.PrefsManager
import com.google.android.material.button.MaterialButton
import com.google.android.material.textfield.TextInputEditText

class LoginActivity : AppCompatActivity() {

    private lateinit var inputServerIp: TextInputEditText
    private lateinit var inputPort: TextInputEditText
    private lateinit var inputUsername: TextInputEditText
    private lateinit var inputPassword: TextInputEditText
    private lateinit var statusText: TextView
    private lateinit var btnLogin: MaterialButton
    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // If already logged in, skip to main
        if (AuthManager.isLoggedIn(this)) {
            // Quick session check in background, but go to main immediately
            startMain()
            return
        }

        setContentView(R.layout.activity_login)

        inputServerIp = findViewById(R.id.input_login_server_ip)
        inputPort = findViewById(R.id.input_login_port)
        inputUsername = findViewById(R.id.input_login_username)
        inputPassword = findViewById(R.id.input_login_password)
        statusText = findViewById(R.id.login_status)
        btnLogin = findViewById(R.id.btn_login)

        // Pre-fill from saved settings
        val savedIp = PrefsManager.getServerIp(this)
        if (savedIp.isNotEmpty()) {
            inputServerIp.setText(savedIp)
        }
        inputPort.setText(PrefsManager.getWebPort(this).toString())

        val savedUser = AuthManager.getUsername(this)
        if (savedUser.isNotEmpty()) {
            inputUsername.setText(savedUser)
        }

        btnLogin.setOnClickListener { doLogin() }

        findViewById<MaterialButton>(R.id.btn_login_detect).setOnClickListener {
            autoDetect(it as MaterialButton)
        }

        findViewById<MaterialButton>(R.id.btn_login_skip).setOnClickListener {
            startMain()
        }
    }

    private fun doLogin() {
        val serverIp = inputServerIp.text.toString().trim()
        val port = inputPort.text.toString().trim().toIntOrNull() ?: 8181
        val username = inputUsername.text.toString().trim()
        val password = inputPassword.text.toString().trim()

        if (serverIp.isEmpty()) {
            statusText.text = "Enter server IP or tap AUTO-DETECT"
            return
        }
        if (username.isEmpty() || password.isEmpty()) {
            statusText.text = "Enter username and password"
            return
        }

        // Save server settings
        PrefsManager.setServerIp(this, serverIp)
        PrefsManager.setWebPort(this, port)

        btnLogin.isEnabled = false
        btnLogin.text = "LOGGING IN..."
        statusText.text = "Connecting to $serverIp:$port..."

        Thread {
            val result = AuthManager.login(this@LoginActivity, username, password)

            handler.post {
                btnLogin.isEnabled = true
                btnLogin.text = "LOGIN"

                if (result.success) {
                    Toast.makeText(this@LoginActivity, "Logged in", Toast.LENGTH_SHORT).show()
                    startMain()
                } else {
                    statusText.text = result.message
                }
            }
        }.start()
    }

    private fun autoDetect(btn: MaterialButton) {
        btn.isEnabled = false
        btn.text = "SCANNING..."
        statusText.text = "Scanning for AUTARCH server..."

        val discovery = DiscoveryManager(this)
        discovery.listener = object : DiscoveryManager.Listener {
            override fun onServerFound(server: DiscoveryManager.DiscoveredServer) {
                discovery.stopDiscovery()
                handler.post {
                    if (server.ip.isNotEmpty()) {
                        inputServerIp.setText(server.ip)
                    }
                    if (server.port > 0) {
                        inputPort.setText(server.port.toString())
                    }
                    statusText.text = "Found ${server.hostname} at ${server.ip}:${server.port}"
                    btn.isEnabled = true
                    btn.text = "AUTO-DETECT"
                }
            }

            override fun onDiscoveryStarted(method: DiscoveryManager.ConnectionMethod) {}

            override fun onDiscoveryStopped(method: DiscoveryManager.ConnectionMethod) {
                handler.post {
                    if (discovery.getDiscoveredServers().isEmpty()) {
                        statusText.text = "No AUTARCH server found on network"
                    }
                    btn.isEnabled = true
                    btn.text = "AUTO-DETECT"
                }
            }

            override fun onDiscoveryError(method: DiscoveryManager.ConnectionMethod, error: String) {}
        }
        discovery.startDiscovery()
    }

    private fun startMain() {
        startActivity(Intent(this, MainActivity::class.java))
        finish()
    }
}
