package com.darkhal.archon.service

import android.content.Context
import android.util.Base64
import android.util.Log
import com.darkhal.archon.util.ShellResult
import io.github.muntashirakon.adb.AbsAdbConnectionManager
import io.github.muntashirakon.adb.android.AdbMdns
import org.conscrypt.Conscrypt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.Signature
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Calendar
import java.util.TimeZone
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import android.os.Build

/**
 * Self-contained local ADB client using libadb-android.
 * Handles wireless debugging pairing, mDNS discovery, and shell command execution.
 * No external ADB binary needed — pure Java/TLS implementation.
 */
object LocalAdbClient {

    private const val TAG = "LocalAdbClient"
    private const val PREFS_NAME = "archon_adb_keys"
    private const val KEY_PRIVATE = "adb_private_key"
    private const val KEY_CERTIFICATE = "adb_certificate"
    private const val LOCALHOST = "127.0.0.1"

    private var connectionManager: AbsAdbConnectionManager? = null
    private var connected = AtomicBoolean(false)
    private var connectedPort = AtomicInteger(0)

    init {
        // Install Conscrypt as the default TLS provider for TLSv1.3 support
        Security.insertProviderAt(Conscrypt.newProvider(), 1)
    }

    /**
     * Check if we have a stored ADB key pair (device has been paired before).
     */
    fun hasKeyPair(context: Context): Boolean {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(KEY_PRIVATE) && prefs.contains(KEY_CERTIFICATE)
    }

    /**
     * Generate a new RSA-2048 key pair for ADB authentication.
     * Stored in SharedPreferences.
     */
    fun generateKeyPair(context: Context) {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        // Generate self-signed certificate using Android's built-in X509 support
        val certificate = generateSelfSignedCert(keyPair)

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit()
            .putString(KEY_PRIVATE, Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP))
            .putString(KEY_CERTIFICATE, Base64.encodeToString(certificate.encoded, Base64.NO_WRAP))
            .apply()

        Log.i(TAG, "Generated new ADB key pair")
    }

    /**
     * Generate a self-signed X.509 v3 certificate for ADB authentication.
     * Built from raw DER/ASN.1 encoding — no sun.security or BouncyCastle needed.
     */
    private fun generateSelfSignedCert(keyPair: java.security.KeyPair): Certificate {
        val serial = BigInteger(64, SecureRandom())

        val notBefore = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        val notAfter = Calendar.getInstance(TimeZone.getTimeZone("UTC"))
        notAfter.add(Calendar.YEAR, 25)

        // DN: CN=adb_archon
        val dn = derSequence(derSet(derSequence(
            derOid(byteArrayOf(0x55, 0x04, 0x03)), // OID 2.5.4.3 = CN
            derUtf8String("adb_archon")
        )))

        // SHA256withRSA algorithm identifier
        // OID 1.2.840.113549.1.1.11
        val sha256WithRsa = byteArrayOf(
            0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xCE.toByte(),
            0x3D, 0x04, 0x03, 0x02 // placeholder, replaced below
        )
        // Correct OID bytes for 1.2.840.113549.1.1.11
        val sha256RsaOid = byteArrayOf(
            0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(),
            0x0D, 0x01, 0x01, 0x0B
        )
        val algId = derSequence(derOid(sha256RsaOid), derNull())

        // SubjectPublicKeyInfo — re-use the encoded form from the key
        val spki = keyPair.public.encoded // Already DER-encoded SubjectPublicKeyInfo

        // TBSCertificate
        val tbs = derSequence(
            derExplicit(0, derInteger(BigInteger.valueOf(2))), // v3
            derInteger(serial),
            algId,
            dn,                                                 // issuer
            derSequence(derUtcTime(notBefore), derUtcTime(notAfter)), // validity
            dn,                                                 // subject = issuer (self-signed)
            spki                                                // subjectPublicKeyInfo
        )

        // Sign the TBS
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initSign(keyPair.private)
        sig.update(tbs)
        val signature = sig.sign()

        // Full certificate: SEQUENCE { tbs, algId, BIT STRING(signature) }
        val certDer = derSequence(tbs, algId, derBitString(signature))

        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(certDer))
    }

    // ── ASN.1 / DER helpers ──────────────────────────────────────

    private fun derTag(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(tag)
        derWriteLength(out, content.size)
        out.write(content)
        return out.toByteArray()
    }

    private fun derWriteLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 0x80) {
            out.write(length)
        } else if (length < 0x100) {
            out.write(0x81)
            out.write(length)
        } else if (length < 0x10000) {
            out.write(0x82)
            out.write(length shr 8)
            out.write(length and 0xFF)
        } else {
            out.write(0x83)
            out.write(length shr 16)
            out.write((length shr 8) and 0xFF)
            out.write(length and 0xFF)
        }
    }

    private fun derSequence(vararg items: ByteArray): ByteArray {
        val content = ByteArrayOutputStream()
        for (item in items) content.write(item)
        return derTag(0x30, content.toByteArray())
    }

    private fun derSet(vararg items: ByteArray): ByteArray {
        val content = ByteArrayOutputStream()
        for (item in items) content.write(item)
        return derTag(0x31, content.toByteArray())
    }

    private fun derInteger(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return derTag(0x02, bytes)
    }

    private fun derOid(oidBytes: ByteArray): ByteArray {
        return derTag(0x06, oidBytes)
    }

    private fun derNull(): ByteArray = byteArrayOf(0x05, 0x00)

    private fun derUtf8String(s: String): ByteArray {
        return derTag(0x0C, s.toByteArray(Charsets.UTF_8))
    }

    private fun derBitString(data: ByteArray): ByteArray {
        val content = ByteArray(data.size + 1)
        content[0] = 0 // no unused bits
        System.arraycopy(data, 0, content, 1, data.size)
        return derTag(0x03, content)
    }

    private fun derUtcTime(cal: Calendar): ByteArray {
        val s = String.format(
            "%02d%02d%02d%02d%02d%02dZ",
            cal.get(Calendar.YEAR) % 100,
            cal.get(Calendar.MONTH) + 1,
            cal.get(Calendar.DAY_OF_MONTH),
            cal.get(Calendar.HOUR_OF_DAY),
            cal.get(Calendar.MINUTE),
            cal.get(Calendar.SECOND)
        )
        return derTag(0x17, s.toByteArray(Charsets.US_ASCII))
    }

    private fun derExplicit(tag: Int, content: ByteArray): ByteArray {
        return derTag(0xA0 or tag, content)
    }

    /**
     * Discover the wireless debugging pairing port via mDNS.
     */
    fun discoverPairingPort(context: Context, timeoutSec: Long = 15): Int? {
        val foundPort = AtomicInteger(-1)
        val latch = CountDownLatch(1)

        val mdns = AdbMdns(context, AdbMdns.SERVICE_TYPE_TLS_PAIRING) { hostAddress, port ->
            Log.i(TAG, "Found pairing service at $hostAddress:$port")
            foundPort.set(port)
            latch.countDown()
        }
        mdns.start()

        latch.await(timeoutSec, TimeUnit.SECONDS)
        mdns.stop()

        val port = foundPort.get()
        return if (port > 0) port else null
    }

    /**
     * Pair with the device's wireless debugging service.
     */
    fun pair(context: Context, host: String = LOCALHOST, port: Int, code: String): Boolean {
        return try {
            ensureKeyPair(context)
            val manager = getOrCreateManager(context)
            val success = manager.pair(host, port, code)
            Log.i(TAG, "Pairing result: $success")
            success
        } catch (e: Exception) {
            Log.e(TAG, "Pairing failed", e)
            false
        }
    }

    /**
     * Discover the wireless debugging connect port via mDNS.
     */
    fun discoverConnectPort(context: Context, timeoutSec: Long = 10): Int? {
        val foundPort = AtomicInteger(-1)
        val latch = CountDownLatch(1)

        val mdns = AdbMdns(context, AdbMdns.SERVICE_TYPE_TLS_CONNECT) { hostAddress, port ->
            Log.i(TAG, "Found connect service at $hostAddress:$port")
            foundPort.set(port)
            latch.countDown()
        }
        mdns.start()

        latch.await(timeoutSec, TimeUnit.SECONDS)
        mdns.stop()

        val port = foundPort.get()
        return if (port > 0) port else null
    }

    /**
     * Connect to the device's wireless debugging ADB service.
     */
    fun connect(context: Context, host: String = LOCALHOST, port: Int): Boolean {
        return try {
            val manager = getOrCreateManager(context)
            val success = manager.connect(host, port)
            connected.set(success)
            if (success) connectedPort.set(port)
            Log.i(TAG, "Connect result: $success (port=$port)")
            success
        } catch (e: Exception) {
            Log.e(TAG, "Connect failed", e)
            connected.set(false)
            false
        }
    }

    /**
     * Auto-connect: discover port via mDNS and connect.
     */
    fun autoConnect(context: Context): Boolean {
        val port = discoverConnectPort(context) ?: return false
        return connect(context, LOCALHOST, port)
    }

    /**
     * Disconnect the current ADB session.
     */
    fun disconnect() {
        try {
            connectionManager?.disconnect()
        } catch (e: Exception) {
            Log.w(TAG, "Disconnect error", e)
        }
        connected.set(false)
        connectedPort.set(0)
    }

    /**
     * Check if currently connected to an ADB session.
     */
    fun isConnected(): Boolean = connected.get()

    /**
     * Execute a shell command via the local ADB connection.
     */
    fun execute(command: String): ShellResult {
        if (!connected.get()) {
            return ShellResult("", "Not connected to local ADB", -1)
        }

        return try {
            val manager = connectionManager ?: return ShellResult("", "No connection manager", -1)
            val stream = manager.openStream("shell:$command")
            val inputStream = stream.openInputStream()
            val stdout = inputStream.bufferedReader().readText().trim()
            stream.close()
            ShellResult(stdout, "", 0)
        } catch (e: Exception) {
            Log.e(TAG, "Shell execute failed", e)
            connected.set(false)
            ShellResult("", "ADB shell error: ${e.message}", -1)
        }
    }

    /**
     * Check if we were previously paired (have keys stored).
     */
    fun isPaired(context: Context): Boolean = hasKeyPair(context)

    /**
     * Get a human-readable status string.
     */
    fun getStatusString(context: Context): String {
        return when {
            connected.get() -> "Connected (port ${connectedPort.get()})"
            hasKeyPair(context) -> "Paired, not connected"
            else -> "Not paired"
        }
    }

    // ── Internal ──────────────────────────────────────────────────

    private fun ensureKeyPair(context: Context) {
        if (!hasKeyPair(context)) {
            generateKeyPair(context)
        }
    }

    private fun getOrCreateManager(context: Context): AbsAdbConnectionManager {
        connectionManager?.let { return it }

        ensureKeyPair(context)

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val privateKeyBytes = Base64.decode(prefs.getString(KEY_PRIVATE, ""), Base64.NO_WRAP)
        val certBytes = Base64.decode(prefs.getString(KEY_CERTIFICATE, ""), Base64.NO_WRAP)

        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec)

        val certFactory = CertificateFactory.getInstance("X.509")
        val certificate = certFactory.generateCertificate(ByteArrayInputStream(certBytes))

        val manager = object : AbsAdbConnectionManager() {
            override fun getPrivateKey(): PrivateKey = privateKey
            override fun getCertificate(): Certificate = certificate
            override fun getDeviceName(): String = "archon_${Build.MODEL}"
        }
        manager.setApi(Build.VERSION.SDK_INT)
        manager.setHostAddress(LOCALHOST)

        connectionManager = manager
        return manager
    }
}
