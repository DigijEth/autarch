package com.darkhal.archon.module

import android.content.Context
import com.darkhal.archon.util.PrivilegeManager

/**
 * Tracking Honeypot module — blocks ad trackers, resets IDs, fakes device fingerprints.
 * Ported from AUTARCH core/android_protect.py honeypot section.
 *
 * Tier 1: ADB-level (no root) — ad ID, DNS, scanning, diagnostics
 * Tier 2: ADB-level (app-specific) — restrict trackers, revoke perms, clear data
 * Tier 3: Root only — hosts blocklist, iptables, fake location, randomize identity
 */
class HoneypotModule : ArchonModule {

    override val id = "honeypot"
    override val name = "Tracking Honeypot"
    override val description = "Block trackers & fake device fingerprint data"
    override val version = "1.0"

    // Well-known tracker packages
    private val knownTrackers = listOf(
        "com.google.android.gms",     // Google Play Services (partial)
        "com.facebook.katana",         // Facebook
        "com.facebook.orca",           // Messenger
        "com.instagram.android",       // Instagram
        "com.zhiliaoapp.musically",    // TikTok
        "com.twitter.android",         // Twitter/X
        "com.snapchat.android",        // Snapchat
        "com.amazon.mShop.android.shopping", // Amazon
    )

    override fun getActions(): List<ModuleAction> = listOf(
        // Tier 1: ADB-level, no root
        ModuleAction("reset_ad_id", "Reset Ad ID", "Delete and regenerate advertising ID"),
        ModuleAction("opt_out_tracking", "Opt Out Tracking", "Enable limit_ad_tracking system setting"),
        ModuleAction("set_private_dns", "Set Private DNS", "Configure DNS-over-TLS (blocks tracker domains)"),
        ModuleAction("disable_scanning", "Disable Scanning", "Turn off WiFi/BLE background scanning"),
        ModuleAction("disable_diagnostics", "Disable Diagnostics", "Stop sending crash/usage data to Google"),
        ModuleAction("harden_all", "Harden All (Tier 1)", "Apply all Tier 1 protections at once"),

        // Tier 2: ADB-level, app-specific
        ModuleAction("restrict_trackers", "Restrict Trackers", "Deny background activity for known trackers"),
        ModuleAction("revoke_tracker_perms", "Revoke Tracker Perms", "Remove location/phone/contacts from trackers"),
        ModuleAction("force_stop_trackers", "Force Stop Trackers", "Kill all known tracker apps"),

        // Tier 3: Root only
        ModuleAction("deploy_hosts", "Deploy Hosts Blocklist", "Block tracker domains via /etc/hosts", rootOnly = true),
        ModuleAction("setup_iptables", "Setup Iptables Redirect", "Redirect tracker traffic to honeypot", rootOnly = true),
        ModuleAction("randomize_identity", "Randomize Identity", "Change android_id and device fingerprint", rootOnly = true),
    )

    override fun executeAction(actionId: String, context: Context): ModuleResult {
        return when (actionId) {
            "reset_ad_id" -> resetAdId()
            "opt_out_tracking" -> optOutTracking()
            "set_private_dns" -> setPrivateDns()
            "disable_scanning" -> disableScanning()
            "disable_diagnostics" -> disableDiagnostics()
            "harden_all" -> hardenAll()
            "restrict_trackers" -> restrictTrackers()
            "revoke_tracker_perms" -> revokeTrackerPerms()
            "force_stop_trackers" -> forceStopTrackers()
            "deploy_hosts" -> deployHostsBlocklist()
            "setup_iptables" -> setupIptablesRedirect()
            "randomize_identity" -> randomizeIdentity()
            else -> ModuleResult(false, "Unknown action: $actionId")
        }
    }

    override fun getStatus(context: Context): ModuleStatus {
        val method = PrivilegeManager.getAvailableMethod()
        val tier = when (method) {
            PrivilegeManager.Method.ROOT -> "Tier 1-3 (full)"
            PrivilegeManager.Method.ARCHON_SERVER,
            PrivilegeManager.Method.LOCAL_ADB,
            PrivilegeManager.Method.SERVER_ADB -> "Tier 1-2 (ADB)"
            PrivilegeManager.Method.NONE -> "Unavailable"
        }
        return ModuleStatus(
            active = method != PrivilegeManager.Method.NONE,
            summary = "Available: $tier"
        )
    }

    // ── Tier 1: ADB-level, system-wide ──────────────────────────────

    private fun resetAdId(): ModuleResult {
        val cmds = listOf(
            "settings delete secure advertising_id",
            "settings put secure limit_ad_tracking 1",
        )
        val results = cmds.map { PrivilegeManager.execute(it) }
        return ModuleResult(
            success = results.all { it.exitCode == 0 },
            output = "Advertising ID reset, tracking limited"
        )
    }

    private fun optOutTracking(): ModuleResult {
        val cmds = listOf(
            "settings put secure limit_ad_tracking 1",
            "settings put global are_app_usage_stats_enabled 0",
        )
        val results = cmds.map { PrivilegeManager.execute(it) }
        return ModuleResult(
            success = results.all { it.exitCode == 0 },
            output = "Ad tracking opt-out enabled"
        )
    }

    private fun setPrivateDns(): ModuleResult {
        val provider = "dns.adguard-dns.com" // AdGuard DNS blocks trackers
        val cmds = listOf(
            "settings put global private_dns_mode hostname",
            "settings put global private_dns_specifier $provider",
        )
        val results = cmds.map { PrivilegeManager.execute(it) }
        return ModuleResult(
            success = results.all { it.exitCode == 0 },
            output = "Private DNS set to $provider (tracker blocking)"
        )
    }

    private fun disableScanning(): ModuleResult {
        val cmds = listOf(
            "settings put global wifi_scan_always_enabled 0",
            "settings put global ble_scan_always_enabled 0",
        )
        val results = cmds.map { PrivilegeManager.execute(it) }
        return ModuleResult(
            success = results.all { it.exitCode == 0 },
            output = "WiFi/BLE background scanning disabled"
        )
    }

    private fun disableDiagnostics(): ModuleResult {
        val cmds = listOf(
            "settings put global send_action_app_error 0",
            "settings put secure send_action_app_error 0",
            "settings put global upload_apk_enable 0",
        )
        val results = cmds.map { PrivilegeManager.execute(it) }
        return ModuleResult(
            success = results.all { it.exitCode == 0 },
            output = "Diagnostics and crash reporting disabled"
        )
    }

    private fun hardenAll(): ModuleResult {
        val actions = listOf(
            "Ad ID" to ::resetAdId,
            "Tracking" to ::optOutTracking,
            "DNS" to ::setPrivateDns,
            "Scanning" to ::disableScanning,
            "Diagnostics" to ::disableDiagnostics,
        )
        val details = mutableListOf<String>()
        var success = true
        for ((name, action) in actions) {
            val result = action()
            details.add("$name: ${result.output}")
            if (!result.success) success = false
        }
        return ModuleResult(
            success = success,
            output = "Applied ${actions.size} Tier 1 protections",
            details = details
        )
    }

    // ── Tier 2: ADB-level, app-specific ─────────────────────────────

    private fun restrictTrackers(): ModuleResult {
        val details = mutableListOf<String>()
        var restricted = 0
        for (pkg in knownTrackers) {
            val check = PrivilegeManager.execute("pm list packages | grep $pkg")
            if (check.stdout.contains(pkg)) {
                val r = PrivilegeManager.execute("cmd appops set $pkg RUN_IN_BACKGROUND deny")
                if (r.exitCode == 0) {
                    restricted++
                    details.add("Restricted: $pkg")
                }
            }
        }
        return ModuleResult(
            success = true,
            output = "$restricted tracker(s) restricted from background",
            details = details
        )
    }

    private fun revokeTrackerPerms(): ModuleResult {
        val dangerousPerms = listOf(
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
        )
        val details = mutableListOf<String>()
        var totalRevoked = 0

        for (pkg in knownTrackers) {
            val check = PrivilegeManager.execute("pm list packages | grep $pkg")
            if (!check.stdout.contains(pkg)) continue

            var pkgRevoked = 0
            for (perm in dangerousPerms) {
                val r = PrivilegeManager.execute("pm revoke $pkg $perm 2>/dev/null")
                if (r.exitCode == 0) pkgRevoked++
            }
            if (pkgRevoked > 0) {
                totalRevoked += pkgRevoked
                details.add("$pkg: revoked $pkgRevoked permissions")
            }
        }
        return ModuleResult(
            success = true,
            output = "Revoked $totalRevoked permissions from trackers",
            details = details
        )
    }

    private fun forceStopTrackers(): ModuleResult {
        val details = mutableListOf<String>()
        var stopped = 0
        for (pkg in knownTrackers) {
            val check = PrivilegeManager.execute("pm list packages | grep $pkg")
            if (check.stdout.contains(pkg)) {
                PrivilegeManager.execute("am force-stop $pkg")
                stopped++
                details.add("Stopped: $pkg")
            }
        }
        return ModuleResult(
            success = true,
            output = "$stopped tracker(s) force-stopped",
            details = details
        )
    }

    // ── Tier 3: Root only ───────────────────────────────────────────

    private fun deployHostsBlocklist(): ModuleResult {
        if (PrivilegeManager.getAvailableMethod() != PrivilegeManager.Method.ROOT) {
            return ModuleResult(false, "Root access required for hosts file modification")
        }

        val trackerDomains = listOf(
            "graph.facebook.com", "pixel.facebook.com", "an.facebook.com",
            "analytics.google.com", "adservice.google.com", "pagead2.googlesyndication.com",
            "analytics.tiktok.com", "log.byteoversea.com",
            "graph.instagram.com",
            "ads-api.twitter.com", "analytics.twitter.com",
            "tr.snapchat.com", "sc-analytics.appspot.com",
        )

        val hostsEntries = trackerDomains.joinToString("\n") { "0.0.0.0 $it" }
        val cmds = listOf(
            "mount -o remount,rw /system 2>/dev/null || true",
            "cp /system/etc/hosts /system/etc/hosts.bak 2>/dev/null || true",
            "echo '# AUTARCH Honeypot blocklist\n$hostsEntries' >> /system/etc/hosts",
            "mount -o remount,ro /system 2>/dev/null || true",
        )

        for (cmd in cmds) {
            PrivilegeManager.execute(cmd)
        }

        return ModuleResult(
            success = true,
            output = "Deployed ${trackerDomains.size} tracker blocks to /system/etc/hosts"
        )
    }

    private fun setupIptablesRedirect(): ModuleResult {
        if (PrivilegeManager.getAvailableMethod() != PrivilegeManager.Method.ROOT) {
            return ModuleResult(false, "Root access required for iptables")
        }

        val cmds = listOf(
            "iptables -t nat -N AUTARCH_HONEYPOT 2>/dev/null || true",
            "iptables -t nat -F AUTARCH_HONEYPOT",
            // Redirect known tracker IPs to localhost (honeypot)
            "iptables -t nat -A AUTARCH_HONEYPOT -p tcp --dport 443 -d 157.240.0.0/16 -j REDIRECT --to-port 8443",
            "iptables -t nat -A AUTARCH_HONEYPOT -p tcp --dport 443 -d 31.13.0.0/16 -j REDIRECT --to-port 8443",
            "iptables -t nat -A OUTPUT -j AUTARCH_HONEYPOT",
        )

        val details = mutableListOf<String>()
        for (cmd in cmds) {
            val r = PrivilegeManager.execute(cmd)
            if (r.exitCode == 0) details.add("OK: ${cmd.take(60)}")
        }

        return ModuleResult(
            success = true,
            output = "Iptables honeypot chain configured",
            details = details
        )
    }

    private fun randomizeIdentity(): ModuleResult {
        if (PrivilegeManager.getAvailableMethod() != PrivilegeManager.Method.ROOT) {
            return ModuleResult(false, "Root access required for identity randomization")
        }

        val randomId = (1..16).map { "0123456789abcdef".random() }.joinToString("")
        val cmds = listOf(
            "settings put secure android_id $randomId",
            "settings delete secure advertising_id",
            "settings put secure limit_ad_tracking 1",
        )

        val details = mutableListOf<String>()
        for (cmd in cmds) {
            val r = PrivilegeManager.execute(cmd)
            details.add("${if (r.exitCode == 0) "OK" else "FAIL"}: ${cmd.take(50)}")
        }

        return ModuleResult(
            success = true,
            output = "Identity randomized (android_id=$randomId)",
            details = details
        )
    }
}
