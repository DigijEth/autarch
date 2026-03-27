package com.darkhal.archon.module

import android.content.Context
import com.darkhal.archon.util.PrivilegeManager

/**
 * Protection Shield module — scans for and removes stalkerware/spyware.
 * Ported from AUTARCH core/android_protect.py.
 *
 * All commands run through PrivilegeManager → ArchonServer (UID 2000).
 */
class ShieldModule : ArchonModule {

    override val id = "shield"
    override val name = "Protection Shield"
    override val description = "Scan & remove stalkerware, spyware, and surveillance tools"
    override val version = "1.0"

    // Known stalkerware/spyware package patterns
    private val stalkerwarePatterns = listOf(
        "mspy", "flexispy", "cocospy", "spyzie", "hoverwatch", "eyezy",
        "pctattoetool", "thewispy", "umobix", "xnspy", "cerberus",
        "trackview", "spyera", "mobile.tracker", "spy.phone", "phone.monitor",
        "gps.tracker.spy", "spyapp", "phonetracker", "stalkerware",
        "keylogger", "screenrecorder.secret", "hidden.camera",
        "com.android.providers.telephony.backup", // Fake system package
        "com.system.service", "com.android.system.manager", // Common disguises
    )

    // Suspicious permissions that stalkerware typically uses
    private val suspiciousPerms = listOf(
        "android.permission.READ_CALL_LOG",
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.PACKAGE_USAGE_STATS",
        "android.permission.SYSTEM_ALERT_WINDOW",
    )

    override fun getActions(): List<ModuleAction> = listOf(
        ModuleAction("full_scan", "Full Scan", "Run all security scans"),
        ModuleAction("scan_packages", "Scan Packages", "Check installed apps against stalkerware database"),
        ModuleAction("scan_permissions", "Scan Permissions", "Find apps with suspicious permission combos"),
        ModuleAction("scan_device_admins", "Scan Device Admins", "List active device administrators"),
        ModuleAction("scan_accessibility", "Scan Accessibility", "Check enabled accessibility services"),
        ModuleAction("scan_certificates", "Scan Certificates", "Check for user-installed CA certificates"),
        ModuleAction("scan_network", "Scan Network", "Check proxy, DNS, VPN settings"),
        ModuleAction("disable_app", "Disable App", "Disable a suspicious package (pm disable-user)"),
        ModuleAction("uninstall_app", "Uninstall App", "Uninstall a suspicious package"),
        ModuleAction("revoke_permissions", "Revoke Permissions", "Revoke dangerous permissions from a package"),
        ModuleAction("remove_device_admin", "Remove Device Admin", "Remove an active device admin component"),
        ModuleAction("clear_proxy", "Clear Proxy", "Remove HTTP proxy settings"),
        ModuleAction("remove_certificate", "Remove Certificate", "Remove a user-installed CA certificate"),
    )

    override fun executeAction(actionId: String, context: Context): ModuleResult {
        return when {
            actionId == "full_scan" -> fullScan(context)
            actionId == "scan_packages" -> scanPackages()
            actionId == "scan_permissions" -> scanPermissions()
            actionId == "scan_device_admins" -> scanDeviceAdmins()
            actionId == "scan_accessibility" -> scanAccessibility()
            actionId == "scan_certificates" -> scanCertificates()
            actionId == "scan_network" -> scanNetwork()
            actionId == "disable_app" -> ModuleResult(false, "Specify package: use disable_app:<package>")
            actionId == "uninstall_app" -> ModuleResult(false, "Specify package: use uninstall_app:<package>")
            actionId == "clear_proxy" -> clearProxy()
            actionId.startsWith("disable_app:") -> disableApp(actionId.substringAfter(":"))
            actionId.startsWith("uninstall_app:") -> uninstallApp(actionId.substringAfter(":"))
            actionId.startsWith("revoke_permissions:") -> revokePermissions(actionId.substringAfter(":"))
            actionId.startsWith("remove_device_admin:") -> removeDeviceAdmin(actionId.substringAfter(":"))
            actionId.startsWith("remove_certificate:") -> removeCertificate(actionId.substringAfter(":"))
            else -> ModuleResult(false, "Unknown action: $actionId")
        }
    }

    override fun getStatus(context: Context): ModuleStatus {
        return ModuleStatus(
            active = PrivilegeManager.isReady(),
            summary = if (PrivilegeManager.isReady()) "Ready to scan" else "Needs privilege setup"
        )
    }

    // ── Scan actions ────────────────────────────────────────────────

    private fun fullScan(context: Context): ModuleResult {
        val results = mutableListOf<String>()
        var threats = 0

        val scans = listOf(
            "Packages" to ::scanPackages,
            "Permissions" to ::scanPermissions,
            "Device Admins" to ::scanDeviceAdmins,
            "Accessibility" to ::scanAccessibility,
            "Certificates" to ::scanCertificates,
            "Network" to ::scanNetwork,
        )

        for ((name, scan) in scans) {
            val result = scan()
            results.add("=== $name ===")
            results.add(result.output)
            if (result.details.isNotEmpty()) {
                threats += result.details.size
                results.addAll(result.details)
            }
        }

        return ModuleResult(
            success = true,
            output = if (threats > 0) "$threats potential threat(s) found" else "No threats detected",
            details = results
        )
    }

    private fun scanPackages(): ModuleResult {
        val result = PrivilegeManager.execute("pm list packages")
        if (result.exitCode != 0) {
            return ModuleResult(false, "Failed to list packages: ${result.stderr}")
        }

        val packages = result.stdout.lines()
            .filter { it.startsWith("package:") }
            .map { it.removePrefix("package:") }

        val found = mutableListOf<String>()
        for (pkg in packages) {
            val lower = pkg.lowercase()
            for (pattern in stalkerwarePatterns) {
                if (lower.contains(pattern)) {
                    found.add("[!] $pkg (matches: $pattern)")
                    break
                }
            }
        }

        return ModuleResult(
            success = true,
            output = "Scanned ${packages.size} packages, ${found.size} suspicious",
            details = found
        )
    }

    private fun scanPermissions(): ModuleResult {
        // Get packages with dangerous permissions
        val result = PrivilegeManager.execute(
            "pm list packages -f | head -500"
        )
        if (result.exitCode != 0) {
            return ModuleResult(false, "Failed: ${result.stderr}")
        }

        val packages = result.stdout.lines()
            .filter { it.startsWith("package:") }
            .map { it.substringAfterLast("=") }
            .take(200) // Limit for performance

        val suspicious = mutableListOf<String>()
        for (pkg in packages) {
            val dump = PrivilegeManager.execute("dumpsys package $pkg 2>/dev/null | grep 'android.permission' | head -30")
            if (dump.exitCode != 0) continue

            val perms = dump.stdout.lines().map { it.trim() }
            val dangerousCount = perms.count { line ->
                suspiciousPerms.any { perm -> line.contains(perm) }
            }

            if (dangerousCount >= 5) {
                suspicious.add("[!] $pkg has $dangerousCount suspicious permissions")
            }
        }

        return ModuleResult(
            success = true,
            output = "Checked permissions on ${packages.size} packages, ${suspicious.size} suspicious",
            details = suspicious
        )
    }

    private fun scanDeviceAdmins(): ModuleResult {
        val result = PrivilegeManager.execute("dumpsys device_policy 2>/dev/null | grep -A 2 'Admin\\|DeviceAdminInfo'")
        if (result.exitCode != 0 && result.stdout.isEmpty()) {
            return ModuleResult(true, "No device admins found or could not query", emptyList())
        }

        val admins = result.stdout.lines().filter { it.isNotBlank() }
        return ModuleResult(
            success = true,
            output = "${admins.size} device admin entries found",
            details = admins.map { it.trim() }
        )
    }

    private fun scanAccessibility(): ModuleResult {
        val result = PrivilegeManager.execute("settings get secure enabled_accessibility_services")
        val services = result.stdout.trim()

        return if (services.isNotEmpty() && services != "null") {
            val list = services.split(":").filter { it.isNotBlank() }
            ModuleResult(
                success = true,
                output = "${list.size} accessibility service(s) enabled",
                details = list.map { "[!] $it" }
            )
        } else {
            ModuleResult(true, "No accessibility services enabled", emptyList())
        }
    }

    private fun scanCertificates(): ModuleResult {
        val result = PrivilegeManager.execute("ls /data/misc/user/0/cacerts-added/ 2>/dev/null")

        return if (result.exitCode == 0 && result.stdout.isNotBlank()) {
            val certs = result.stdout.lines().filter { it.isNotBlank() }
            ModuleResult(
                success = true,
                output = "${certs.size} user-installed CA certificate(s)",
                details = certs.map { "[!] Certificate: $it" }
            )
        } else {
            ModuleResult(true, "No user-installed CA certificates", emptyList())
        }
    }

    private fun scanNetwork(): ModuleResult {
        val findings = mutableListOf<String>()

        // Check HTTP proxy
        val proxy = PrivilegeManager.execute("settings get global http_proxy").stdout.trim()
        if (proxy.isNotEmpty() && proxy != "null" && proxy != ":0") {
            findings.add("[!] HTTP proxy set: $proxy")
        }

        // Check private DNS
        val dnsMode = PrivilegeManager.execute("settings get global private_dns_mode").stdout.trim()
        val dnsProvider = PrivilegeManager.execute("settings get global private_dns_specifier").stdout.trim()
        if (dnsMode == "hostname" && dnsProvider.isNotEmpty() && dnsProvider != "null") {
            findings.add("[i] Private DNS: $dnsProvider (mode: $dnsMode)")
        }

        // Check VPN always-on
        val vpn = PrivilegeManager.execute("settings get secure always_on_vpn_app").stdout.trim()
        if (vpn.isNotEmpty() && vpn != "null") {
            findings.add("[!] Always-on VPN: $vpn")
        }

        // Check global proxy pac
        val pac = PrivilegeManager.execute("settings get global global_http_proxy_pac").stdout.trim()
        if (pac.isNotEmpty() && pac != "null") {
            findings.add("[!] Proxy PAC configured: $pac")
        }

        return ModuleResult(
            success = true,
            output = if (findings.isEmpty()) "Network settings clean" else "${findings.size} network finding(s)",
            details = findings
        )
    }

    // ── Remediation actions ─────────────────────────────────────────

    private fun disableApp(pkg: String): ModuleResult {
        val result = PrivilegeManager.execute("pm disable-user --user 0 $pkg")
        return ModuleResult(
            success = result.exitCode == 0,
            output = if (result.exitCode == 0) "Disabled: $pkg" else "Failed: ${result.stderr}"
        )
    }

    private fun uninstallApp(pkg: String): ModuleResult {
        val result = PrivilegeManager.execute("pm uninstall --user 0 $pkg")
        return ModuleResult(
            success = result.exitCode == 0,
            output = if (result.exitCode == 0) "Uninstalled: $pkg" else "Failed: ${result.stderr}"
        )
    }

    private fun revokePermissions(pkg: String): ModuleResult {
        val revoked = mutableListOf<String>()
        for (perm in suspiciousPerms) {
            val result = PrivilegeManager.execute("pm revoke $pkg $perm 2>/dev/null")
            if (result.exitCode == 0) revoked.add(perm)
        }
        return ModuleResult(
            success = true,
            output = "Revoked ${revoked.size}/${suspiciousPerms.size} permissions from $pkg",
            details = revoked.map { "Revoked: $it" }
        )
    }

    private fun removeDeviceAdmin(component: String): ModuleResult {
        val result = PrivilegeManager.execute("dpm remove-active-admin $component")
        return ModuleResult(
            success = result.exitCode == 0,
            output = if (result.exitCode == 0) "Removed device admin: $component" else "Failed: ${result.stderr}"
        )
    }

    private fun clearProxy(): ModuleResult {
        val result = PrivilegeManager.execute("settings put global http_proxy :0")
        return ModuleResult(
            success = result.exitCode == 0,
            output = if (result.exitCode == 0) "HTTP proxy cleared" else "Failed: ${result.stderr}"
        )
    }

    private fun removeCertificate(hash: String): ModuleResult {
        val result = PrivilegeManager.execute("rm /data/misc/user/0/cacerts-added/$hash")
        return ModuleResult(
            success = result.exitCode == 0,
            output = if (result.exitCode == 0) "Certificate removed: $hash" else "Failed: ${result.stderr}"
        )
    }
}
