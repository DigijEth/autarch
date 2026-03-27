package com.darkhal.archon.service

import com.darkhal.archon.util.PrivilegeManager
import com.darkhal.archon.util.ShellExecutor
import com.darkhal.archon.util.ShellResult

object AdbManager {

    private const val ADBD_PROCESS = "adbd"

    /**
     * Enable ADB over TCP/IP on the specified port.
     * Uses the best available privilege method.
     */
    fun enableTcpMode(port: Int = 5555): ShellResult {
        return PrivilegeManager.execute(
            "setprop service.adb.tcp.port $port && stop adbd && start adbd"
        )
    }

    /**
     * Disable ADB TCP/IP mode, reverting to USB-only.
     */
    fun disableTcpMode(): ShellResult {
        return PrivilegeManager.execute(
            "setprop service.adb.tcp.port -1 && stop adbd && start adbd"
        )
    }

    /**
     * Kill the ADB daemon.
     */
    fun killServer(): ShellResult {
        return PrivilegeManager.execute("stop adbd")
    }

    /**
     * Restart the ADB daemon (stop then start).
     */
    fun restartServer(): ShellResult {
        return PrivilegeManager.execute("stop adbd && start adbd")
    }

    /**
     * Check if the ADB daemon process is currently running.
     */
    fun isRunning(): Boolean {
        val result = ShellExecutor.execute("pidof $ADBD_PROCESS")
        return result.exitCode == 0 && result.stdout.isNotEmpty()
    }

    /**
     * Get the current ADB mode: "tcp" with port number, or "usb".
     */
    fun getMode(): String {
        val result = ShellExecutor.execute("getprop service.adb.tcp.port")
        val port = result.stdout.trim()
        return if (port.isNotEmpty() && port != "-1" && port != "0") {
            "tcp:$port"
        } else {
            "usb"
        }
    }

    /**
     * Get a combined status map for display.
     */
    fun getStatus(): Map<String, Any> {
        val running = isRunning()
        val mode = getMode()
        return mapOf(
            "running" to running,
            "mode" to mode,
            "tcp_enabled" to mode.startsWith("tcp")
        )
    }
}
