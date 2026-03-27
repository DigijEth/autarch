package com.darkhal.archon.service

import com.darkhal.archon.util.PrivilegeManager
import com.darkhal.archon.util.ShellExecutor
import com.darkhal.archon.util.ShellResult

data class UsbDevice(
    val busId: String,
    val description: String
)

object UsbIpManager {

    private const val USBIPD_PROCESS = "usbipd"

    /**
     * Start USB/IP daemon to export this device's USB gadget over the network.
     */
    fun startExport(): ShellResult {
        return PrivilegeManager.execute("usbipd -D")
    }

    /**
     * Stop the USB/IP daemon.
     */
    fun stopExport(): ShellResult {
        return PrivilegeManager.execute("killall $USBIPD_PROCESS")
    }

    /**
     * Check if usbipd is currently running.
     */
    fun isExporting(): Boolean {
        val result = ShellExecutor.execute("pidof $USBIPD_PROCESS")
        return result.exitCode == 0 && result.stdout.isNotEmpty()
    }

    /**
     * Check if the usbip binary is available on this device.
     */
    fun isAvailable(): Boolean {
        val result = ShellExecutor.execute("which usbip || which usbipd")
        return result.exitCode == 0 && result.stdout.isNotEmpty()
    }

    /**
     * List local USB devices that can be exported.
     */
    fun listLocalDevices(): List<UsbDevice> {
        val result = PrivilegeManager.execute("usbip list -l")
        if (result.exitCode != 0) return emptyList()

        val devices = mutableListOf<UsbDevice>()
        val lines = result.stdout.lines()

        for (line in lines) {
            val match = Regex("""busid\s+(\S+)\s+\(([^)]+)\)""").find(line)
            if (match != null) {
                val busId = match.groupValues[1]
                val desc = match.groupValues[2]
                devices.add(UsbDevice(busId, desc))
            }
        }

        return devices
    }

    /**
     * Bind a local USB device for export.
     */
    fun bindDevice(busId: String): ShellResult {
        return PrivilegeManager.execute("usbip bind -b $busId")
    }

    /**
     * Unbind a local USB device from export.
     */
    fun unbindDevice(busId: String): ShellResult {
        return PrivilegeManager.execute("usbip unbind -b $busId")
    }

    /**
     * Get combined USB/IP status.
     */
    fun getStatus(): Map<String, Any> {
        val available = isAvailable()
        val exporting = if (available) isExporting() else false
        val devices = if (available) listLocalDevices() else emptyList()

        return mapOf(
            "available" to available,
            "exporting" to exporting,
            "device_count" to devices.size,
            "devices" to devices.map { mapOf("bus_id" to it.busId, "description" to it.description) }
        )
    }
}
