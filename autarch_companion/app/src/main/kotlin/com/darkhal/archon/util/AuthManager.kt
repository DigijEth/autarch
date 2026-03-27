package com.darkhal.archon.util

import android.content.Context
import android.util.Log
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpURLConnection
import java.net.URL

/**
 * Manages authentication with the AUTARCH web server.
 *
 * Handles login via JSON API, cookie storage, and attaching
 * the session cookie to all outbound HTTP requests.
 */
object AuthManager {

    private const val TAG = "AuthManager"
    private const val PREFS_NAME = "archon_auth"
    private const val KEY_USERNAME = "username"
    private const val KEY_PASSWORD = "password"
    private const val KEY_SESSION_COOKIE = "session_cookie"
    private const val KEY_LOGGED_IN = "logged_in"

    @Volatile
    private var sessionCookie: String? = null

    /**
     * Log in to the AUTARCH web server.
     * Returns true on success. Stores the session cookie.
     */
    fun login(context: Context, username: String, password: String): LoginResult {
        val baseUrl = PrefsManager.getAutarchBaseUrl(context)
        if (baseUrl.contains("://:" ) || baseUrl.endsWith("://")) {
            return LoginResult(false, "No server IP configured")
        }

        return try {
            val url = URL("$baseUrl/api/login")
            val conn = url.openConnection() as HttpURLConnection
            SslHelper.trustSelfSigned(conn)
            conn.connectTimeout = 5000
            conn.readTimeout = 10000
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.doOutput = true

            val payload = """{"username":"${escapeJson(username)}","password":"${escapeJson(password)}"}"""
            conn.outputStream.write(payload.toByteArray())

            val code = conn.responseCode
            val body = if (code in 200..299) {
                conn.inputStream.bufferedReader().readText()
            } else {
                conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $code"
            }

            // Extract Set-Cookie header
            val cookie = conn.getHeaderField("Set-Cookie")
            conn.disconnect()

            if (code == 200 && body.contains("\"ok\":true")) {
                // Store credentials and cookie
                sessionCookie = cookie
                val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                prefs.edit()
                    .putString(KEY_USERNAME, username)
                    .putString(KEY_PASSWORD, password)
                    .putString(KEY_SESSION_COOKIE, cookie ?: "")
                    .putBoolean(KEY_LOGGED_IN, true)
                    .apply()

                Log.i(TAG, "Login successful for $username")
                LoginResult(true, "Logged in as $username")
            } else {
                Log.w(TAG, "Login failed: HTTP $code - $body")
                LoginResult(false, "Invalid credentials")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Login error", e)
            LoginResult(false, "Connection error: ${e.message}")
        }
    }

    /**
     * Check if we have stored credentials and a valid session.
     */
    fun isLoggedIn(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getBoolean(KEY_LOGGED_IN, false) &&
               prefs.getString(KEY_USERNAME, null) != null
    }

    /**
     * Get stored username.
     */
    fun getUsername(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_USERNAME, "") ?: ""
    }

    /**
     * Get stored password.
     */
    fun getPassword(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.getString(KEY_PASSWORD, "") ?: ""
    }

    /**
     * Re-login using stored credentials (refreshes session cookie).
     */
    fun refreshSession(context: Context): Boolean {
        val username = getUsername(context)
        val password = getPassword(context)
        if (username.isEmpty() || password.isEmpty()) return false
        return login(context, username, password).success
    }

    /**
     * Attach the session cookie to an HttpURLConnection.
     * Call this before sending any request to the AUTARCH server.
     */
    fun attachSession(context: Context, conn: HttpURLConnection) {
        val cookie = sessionCookie ?: run {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.getString(KEY_SESSION_COOKIE, null)
        }
        if (cookie != null) {
            conn.setRequestProperty("Cookie", cookie)
        }
    }

    /**
     * Make an authenticated POST request to the AUTARCH server.
     * Handles cookie attachment and auto-refreshes session on 401.
     */
    fun authenticatedPost(context: Context, path: String, jsonPayload: String): HttpResult {
        val baseUrl = PrefsManager.getAutarchBaseUrl(context)
        return try {
            var result = doPost(context, "$baseUrl$path", jsonPayload)

            // If 401, try refreshing session once
            if (result.code == 401 || result.code == 302) {
                Log.i(TAG, "Session expired, refreshing...")
                if (refreshSession(context)) {
                    result = doPost(context, "$baseUrl$path", jsonPayload)
                }
            }

            result
        } catch (e: Exception) {
            Log.e(TAG, "Authenticated POST failed", e)
            HttpResult(-1, "", "Connection error: ${e.message}")
        }
    }

    private fun doPost(context: Context, urlStr: String, jsonPayload: String): HttpResult {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpURLConnection
        SslHelper.trustSelfSigned(conn)
        conn.connectTimeout = 5000
        conn.readTimeout = 15000
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.instanceFollowRedirects = false
        conn.doOutput = true

        attachSession(context, conn)

        conn.outputStream.write(jsonPayload.toByteArray())

        val code = conn.responseCode

        // Capture new cookie if server rotates it
        val newCookie = conn.getHeaderField("Set-Cookie")
        if (newCookie != null) {
            sessionCookie = newCookie
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            prefs.edit().putString(KEY_SESSION_COOKIE, newCookie).apply()
        }

        val body = if (code in 200..299) {
            conn.inputStream.bufferedReader().readText()
        } else {
            conn.errorStream?.bufferedReader()?.readText() ?: "HTTP $code"
        }
        conn.disconnect()

        return HttpResult(code, body, "")
    }

    /**
     * Logout — clear stored credentials and cookie.
     */
    fun logout(context: Context) {
        sessionCookie = null
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().clear().apply()
        Log.i(TAG, "Logged out")
    }

    private fun escapeJson(s: String): String {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
    }

    data class LoginResult(val success: Boolean, val message: String)
    data class HttpResult(val code: Int, val body: String, val error: String)
}
