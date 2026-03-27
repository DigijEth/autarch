package com.darkhal.archon.util

import android.content.Context
import android.content.SharedPreferences

object PrefsManager {

    private const val PREFS_NAME = "archon_prefs"

    private const val KEY_SERVER_IP = "server_ip"
    private const val KEY_WEB_PORT = "web_port"
    private const val KEY_ADB_PORT = "adb_port"
    private const val KEY_USBIP_PORT = "usbip_port"
    private const val KEY_AUTO_RESTART_ADB = "auto_restart_adb"
    private const val KEY_BBS_ADDRESS = "bbs_address"

    private const val DEFAULT_SERVER_IP = ""
    private const val DEFAULT_WEB_PORT = 8181
    private const val DEFAULT_ADB_PORT = 5555
    private const val DEFAULT_USBIP_PORT = 3240
    private const val DEFAULT_BBS_ADDRESS = ""

    private fun prefs(context: Context): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun getServerIp(context: Context): String {
        return prefs(context).getString(KEY_SERVER_IP, DEFAULT_SERVER_IP) ?: DEFAULT_SERVER_IP
    }

    fun setServerIp(context: Context, ip: String) {
        prefs(context).edit().putString(KEY_SERVER_IP, ip).apply()
    }

    fun getWebPort(context: Context): Int {
        return prefs(context).getInt(KEY_WEB_PORT, DEFAULT_WEB_PORT)
    }

    fun setWebPort(context: Context, port: Int) {
        prefs(context).edit().putInt(KEY_WEB_PORT, port).apply()
    }

    fun getAdbPort(context: Context): Int {
        return prefs(context).getInt(KEY_ADB_PORT, DEFAULT_ADB_PORT)
    }

    fun setAdbPort(context: Context, port: Int) {
        prefs(context).edit().putInt(KEY_ADB_PORT, port).apply()
    }

    fun getUsbIpPort(context: Context): Int {
        return prefs(context).getInt(KEY_USBIP_PORT, DEFAULT_USBIP_PORT)
    }

    fun setUsbIpPort(context: Context, port: Int) {
        prefs(context).edit().putInt(KEY_USBIP_PORT, port).apply()
    }

    fun isAutoRestartAdb(context: Context): Boolean {
        return prefs(context).getBoolean(KEY_AUTO_RESTART_ADB, true)
    }

    fun setAutoRestartAdb(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO_RESTART_ADB, enabled).apply()
    }

    fun getBbsAddress(context: Context): String {
        return prefs(context).getString(KEY_BBS_ADDRESS, DEFAULT_BBS_ADDRESS) ?: DEFAULT_BBS_ADDRESS
    }

    fun setBbsAddress(context: Context, address: String) {
        prefs(context).edit().putString(KEY_BBS_ADDRESS, address).apply()
    }

    fun getAutarchBaseUrl(context: Context): String {
        val ip = getServerIp(context)
        val port = getWebPort(context)
        return "https://$ip:$port"
    }
}
