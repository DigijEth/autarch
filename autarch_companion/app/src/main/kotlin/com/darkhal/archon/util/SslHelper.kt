package com.darkhal.archon.util

import java.net.HttpURLConnection
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * SSL helper for connecting to AUTARCH's self-signed HTTPS server.
 *
 * Since AUTARCH generates a self-signed cert at first launch,
 * Android's default trust store will reject it. This helper
 * creates a permissive SSLContext for LAN-only connections to
 * the known AUTARCH server.
 */
object SslHelper {

    private val trustAllManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    private val trustAllHostname = HostnameVerifier { _, _ -> true }

    private val sslContext: SSLContext by lazy {
        SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
        }
    }

    val socketFactory get() = sslContext.socketFactory

    /**
     * Apply self-signed cert trust to a connection.
     * If the connection is HTTPS, sets the permissive SSLSocketFactory
     * and hostname verifier. Plain HTTP connections are left unchanged.
     */
    fun trustSelfSigned(conn: HttpURLConnection) {
        if (conn is HttpsURLConnection) {
            conn.sslSocketFactory = socketFactory
            conn.hostnameVerifier = trustAllHostname
        }
    }
}
