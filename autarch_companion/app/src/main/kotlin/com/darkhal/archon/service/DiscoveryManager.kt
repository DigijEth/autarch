package com.darkhal.archon.service

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pDeviceList
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.os.Handler
import android.os.Looper
import android.util.Log

/**
 * Discovers AUTARCH servers on the network using three methods (priority order):
 *
 * 1. **mDNS/NSD** — discovers _autarch._tcp.local. on LAN (fastest, most reliable)
 * 2. **Wi-Fi Direct** — discovers AUTARCH peers when no shared LAN exists
 * 3. **Bluetooth** — discovers AUTARCH BT advertisement (fallback, requires BT enabled + paired)
 *
 * Usage:
 *   val discovery = DiscoveryManager(context)
 *   discovery.listener = object : DiscoveryManager.Listener { ... }
 *   discovery.startDiscovery()
 *   // ... later ...
 *   discovery.stopDiscovery()
 */
class DiscoveryManager(private val context: Context) {

    companion object {
        private const val TAG = "ArchonDiscovery"
        private const val MDNS_SERVICE_TYPE = "_autarch._tcp."
        private const val BT_TARGET_NAME = "AUTARCH"
        private const val WIFIDIRECT_TARGET_NAME = "AUTARCH"
        private const val DISCOVERY_TIMEOUT_MS = 15000L
    }

    // ── Result Data ─────────────────────────────────────────────────

    data class DiscoveredServer(
        val ip: String,
        val port: Int,
        val hostname: String,
        val method: ConnectionMethod,
        val extras: Map<String, String> = emptyMap()
    )

    enum class ConnectionMethod {
        MDNS,          // Found via mDNS on local network
        WIFI_DIRECT,   // Found via Wi-Fi Direct
        BLUETOOTH      // Found via Bluetooth
    }

    // ── Listener ────────────────────────────────────────────────────

    interface Listener {
        fun onServerFound(server: DiscoveredServer)
        fun onDiscoveryStarted(method: ConnectionMethod)
        fun onDiscoveryStopped(method: ConnectionMethod)
        fun onDiscoveryError(method: ConnectionMethod, error: String)
    }

    var listener: Listener? = null
    private val handler = Handler(Looper.getMainLooper())

    // ── State ───────────────────────────────────────────────────────

    private var mdnsRunning = false
    private var wifiDirectRunning = false
    private var bluetoothRunning = false

    private var nsdManager: NsdManager? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private var wifiP2pManager: WifiP2pManager? = null
    private var wifiP2pChannel: WifiP2pManager.Channel? = null
    private var bluetoothAdapter: BluetoothAdapter? = null

    private val discoveredServers = mutableListOf<DiscoveredServer>()

    // ── Public API ──────────────────────────────────────────────────

    /**
     * Start all available discovery methods in priority order.
     * Results arrive via the [Listener] callback.
     */
    fun startDiscovery() {
        discoveredServers.clear()
        startMdnsDiscovery()
        startWifiDirectDiscovery()
        startBluetoothDiscovery()

        // Auto-stop after timeout
        handler.postDelayed({ stopDiscovery() }, DISCOVERY_TIMEOUT_MS)
    }

    /**
     * Stop all discovery methods.
     */
    fun stopDiscovery() {
        stopMdnsDiscovery()
        stopWifiDirectDiscovery()
        stopBluetoothDiscovery()
    }

    /**
     * Get all servers found so far.
     */
    fun getDiscoveredServers(): List<DiscoveredServer> {
        return discoveredServers.toList()
    }

    /**
     * Get the best server (highest priority method).
     */
    fun getBestServer(): DiscoveredServer? {
        return discoveredServers.minByOrNull { it.method.ordinal }
    }

    // ── mDNS / NSD ─────────────────────────────────────────────────

    private fun startMdnsDiscovery() {
        if (mdnsRunning) return

        try {
            nsdManager = context.getSystemService(Context.NSD_SERVICE) as? NsdManager
            if (nsdManager == null) {
                notifyError(ConnectionMethod.MDNS, "NSD service not available")
                return
            }

            discoveryListener = object : NsdManager.DiscoveryListener {
                override fun onDiscoveryStarted(serviceType: String) {
                    Log.d(TAG, "mDNS discovery started")
                    mdnsRunning = true
                    handler.post { listener?.onDiscoveryStarted(ConnectionMethod.MDNS) }
                }

                override fun onServiceFound(serviceInfo: NsdServiceInfo) {
                    Log.d(TAG, "mDNS service found: ${serviceInfo.serviceName}")
                    // Resolve to get IP and port
                    nsdManager?.resolveService(serviceInfo, object : NsdManager.ResolveListener {
                        override fun onResolveFailed(info: NsdServiceInfo, errorCode: Int) {
                            Log.w(TAG, "mDNS resolve failed: $errorCode")
                        }

                        override fun onServiceResolved(info: NsdServiceInfo) {
                            val host = info.host?.hostAddress ?: return
                            val port = info.port
                            val hostname = info.attributes["hostname"]
                                ?.let { String(it) } ?: info.serviceName

                            val server = DiscoveredServer(
                                ip = host,
                                port = port,
                                hostname = hostname,
                                method = ConnectionMethod.MDNS,
                                extras = info.attributes.mapValues { String(it.value ?: byteArrayOf()) }
                            )
                            discoveredServers.add(server)
                            handler.post { listener?.onServerFound(server) }
                            Log.i(TAG, "mDNS: found AUTARCH at $host:$port")
                        }
                    })
                }

                override fun onServiceLost(serviceInfo: NsdServiceInfo) {
                    Log.d(TAG, "mDNS service lost: ${serviceInfo.serviceName}")
                }

                override fun onDiscoveryStopped(serviceType: String) {
                    mdnsRunning = false
                    handler.post { listener?.onDiscoveryStopped(ConnectionMethod.MDNS) }
                }

                override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
                    mdnsRunning = false
                    notifyError(ConnectionMethod.MDNS, "Start failed (code $errorCode)")
                }

                override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {
                    Log.w(TAG, "mDNS stop failed: $errorCode")
                }
            }

            nsdManager?.discoverServices(MDNS_SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discoveryListener)

        } catch (e: Exception) {
            notifyError(ConnectionMethod.MDNS, e.message ?: "Unknown error")
        }
    }

    private fun stopMdnsDiscovery() {
        if (!mdnsRunning) return
        try {
            discoveryListener?.let { nsdManager?.stopServiceDiscovery(it) }
        } catch (e: Exception) {
            Log.w(TAG, "mDNS stop error: ${e.message}")
        }
        mdnsRunning = false
    }

    // ── Wi-Fi Direct ────────────────────────────────────────────────

    private val wifiP2pReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> {
                    // Peers list changed, request updated list
                    wifiP2pManager?.requestPeers(wifiP2pChannel) { peers ->
                        handleWifiDirectPeers(peers)
                    }
                }
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                    wifiP2pManager?.requestConnectionInfo(wifiP2pChannel) { info ->
                        handleWifiDirectConnection(info)
                    }
                }
            }
        }
    }

    private fun startWifiDirectDiscovery() {
        if (wifiDirectRunning) return

        try {
            wifiP2pManager = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
            if (wifiP2pManager == null) {
                notifyError(ConnectionMethod.WIFI_DIRECT, "Wi-Fi Direct not available")
                return
            }

            wifiP2pChannel = wifiP2pManager?.initialize(context, Looper.getMainLooper(), null)

            // Register receiver for Wi-Fi Direct events
            val intentFilter = IntentFilter().apply {
                addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
                addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
                addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
            }
            context.registerReceiver(wifiP2pReceiver, intentFilter)

            wifiP2pManager?.discoverPeers(wifiP2pChannel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {
                    wifiDirectRunning = true
                    handler.post { listener?.onDiscoveryStarted(ConnectionMethod.WIFI_DIRECT) }
                    Log.d(TAG, "Wi-Fi Direct discovery started")
                }

                override fun onFailure(reason: Int) {
                    val msg = when (reason) {
                        WifiP2pManager.P2P_UNSUPPORTED -> "P2P unsupported"
                        WifiP2pManager.BUSY -> "System busy"
                        WifiP2pManager.ERROR -> "Internal error"
                        else -> "Unknown error ($reason)"
                    }
                    notifyError(ConnectionMethod.WIFI_DIRECT, msg)
                }
            })

        } catch (e: Exception) {
            notifyError(ConnectionMethod.WIFI_DIRECT, e.message ?: "Unknown error")
        }
    }

    private fun handleWifiDirectPeers(peers: WifiP2pDeviceList) {
        for (device in peers.deviceList) {
            if (device.deviceName.contains(WIFIDIRECT_TARGET_NAME, ignoreCase = true)) {
                Log.i(TAG, "Wi-Fi Direct: found AUTARCH peer: ${device.deviceName} (${device.deviceAddress})")
                // Found an AUTARCH device — connect to get IP
                connectWifiDirect(device)
            }
        }
    }

    private fun connectWifiDirect(device: WifiP2pDevice) {
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
        }
        wifiP2pManager?.connect(wifiP2pChannel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() {
                Log.d(TAG, "Wi-Fi Direct: connecting to ${device.deviceName}")
            }

            override fun onFailure(reason: Int) {
                Log.w(TAG, "Wi-Fi Direct: connect failed ($reason)")
            }
        })
    }

    private fun handleWifiDirectConnection(info: WifiP2pInfo) {
        if (info.groupFormed) {
            val ownerAddress = info.groupOwnerAddress?.hostAddress ?: return
            // The group owner is the AUTARCH server
            val server = DiscoveredServer(
                ip = ownerAddress,
                port = 8181, // Default — will be refined via mDNS or API call
                hostname = "AUTARCH (Wi-Fi Direct)",
                method = ConnectionMethod.WIFI_DIRECT
            )
            discoveredServers.add(server)
            handler.post { listener?.onServerFound(server) }
            Log.i(TAG, "Wi-Fi Direct: AUTARCH at $ownerAddress")
        }
    }

    private fun stopWifiDirectDiscovery() {
        if (!wifiDirectRunning) return
        try {
            wifiP2pManager?.stopPeerDiscovery(wifiP2pChannel, null)
            context.unregisterReceiver(wifiP2pReceiver)
        } catch (e: Exception) {
            Log.w(TAG, "Wi-Fi Direct stop error: ${e.message}")
        }
        wifiDirectRunning = false
    }

    // ── Bluetooth ───────────────────────────────────────────────────

    private val btReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                BluetoothDevice.ACTION_FOUND -> {
                    val device = intent.getParcelableExtra<BluetoothDevice>(
                        BluetoothDevice.EXTRA_DEVICE
                    ) ?: return

                    val name = try { device.name } catch (e: SecurityException) { null }
                    if (name != null && name.contains(BT_TARGET_NAME, ignoreCase = true)) {
                        Log.i(TAG, "Bluetooth: found AUTARCH device: $name (${device.address})")

                        val server = DiscoveredServer(
                            ip = "", // BT doesn't give IP directly — use for pairing flow
                            port = 0,
                            hostname = name,
                            method = ConnectionMethod.BLUETOOTH,
                            extras = mapOf(
                                "bt_address" to device.address,
                                "bt_name" to name
                            )
                        )
                        discoveredServers.add(server)
                        handler.post { listener?.onServerFound(server) }
                    }
                }
                BluetoothAdapter.ACTION_DISCOVERY_FINISHED -> {
                    bluetoothRunning = false
                    handler.post { listener?.onDiscoveryStopped(ConnectionMethod.BLUETOOTH) }
                }
            }
        }
    }

    private fun startBluetoothDiscovery() {
        if (bluetoothRunning) return

        try {
            val btManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            bluetoothAdapter = btManager?.adapter

            if (bluetoothAdapter == null || bluetoothAdapter?.isEnabled != true) {
                notifyError(ConnectionMethod.BLUETOOTH, "Bluetooth not available or disabled")
                return
            }

            val intentFilter = IntentFilter().apply {
                addAction(BluetoothDevice.ACTION_FOUND)
                addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED)
            }
            context.registerReceiver(btReceiver, intentFilter)

            val started = try {
                bluetoothAdapter?.startDiscovery() == true
            } catch (e: SecurityException) {
                notifyError(ConnectionMethod.BLUETOOTH, "Bluetooth permission denied")
                return
            }

            if (started) {
                bluetoothRunning = true
                handler.post { listener?.onDiscoveryStarted(ConnectionMethod.BLUETOOTH) }
                Log.d(TAG, "Bluetooth discovery started")
            } else {
                notifyError(ConnectionMethod.BLUETOOTH, "Failed to start BT discovery")
            }

        } catch (e: Exception) {
            notifyError(ConnectionMethod.BLUETOOTH, e.message ?: "Unknown error")
        }
    }

    private fun stopBluetoothDiscovery() {
        if (!bluetoothRunning) return
        try {
            bluetoothAdapter?.cancelDiscovery()
            context.unregisterReceiver(btReceiver)
        } catch (e: Exception) {
            Log.w(TAG, "Bluetooth stop error: ${e.message}")
        }
        bluetoothRunning = false
    }

    // ── Helpers ─────────────────────────────────────────────────────

    private fun notifyError(method: ConnectionMethod, error: String) {
        Log.e(TAG, "${method.name}: $error")
        handler.post { listener?.onDiscoveryError(method, error) }
    }
}
