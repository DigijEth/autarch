"""
AUTARCH Android Protection Shield
Anti-stalkerware and anti-spyware detection, analysis, and remediation.

Detects:
- Commercial stalkerware (400+ package signatures)
- Government-grade spyware (Pegasus, Predator, Hermit, FinSpy, etc.)
- Hidden apps, rogue device admins, suspicious accessibility services
- MITM certificates, proxy hijacking, dangerous permission combos

Remediates:
- Disable/uninstall threats, revoke permissions, remove device admins
- Clear rogue CA certs, proxy settings, developer options

Uses HardwareManager for ADB access. Shizuku for privileged ops on non-rooted devices.
"""

import json
import os
import random
import re
import time
import fnmatch
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

from core.paths import get_data_dir


class AndroidProtectManager:
    """Anti-stalkerware / anti-spyware shield for Android devices."""

    def __init__(self):
        self._data_dir = get_data_dir() / 'android_protect'
        self._data_dir.mkdir(parents=True, exist_ok=True)

        self._sig_path = get_data_dir() / 'stalkerware_signatures.json'
        self._signatures = None  # lazy load

        self._tracker_path = get_data_dir() / 'tracker_domains.json'
        self._tracker_db = None  # lazy load

    # ── Helpers ──────────────────────────────────────────────────────

    def _hw(self):
        """Get HardwareManager singleton (lazy import to avoid circular)."""
        from core.hardware import get_hardware_manager
        return get_hardware_manager()

    def _adb(self, args, serial=None, timeout=30):
        """Run ADB command via HardwareManager, return (stdout, stderr, rc)."""
        return self._hw()._run_adb(args, serial=serial, timeout=timeout)

    def _adb_shell(self, cmd, serial=None, timeout=30):
        """Shortcut for adb shell <cmd>."""
        return self._adb(['shell'] + (cmd if isinstance(cmd, list) else [cmd]),
                         serial=serial, timeout=timeout)

    def _device_dir(self, serial):
        """Per-device data directory."""
        safe = re.sub(r'[^\w\-.]', '_', serial)
        d = self._data_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _scans_dir(self, serial):
        d = self._device_dir(serial) / 'scans'
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── Signature Database ──────────────────────────────────────────

    def _load_signatures(self):
        """Load stalkerware/spyware signature database."""
        if self._signatures is not None:
            return self._signatures
        if not self._sig_path.exists():
            self._signatures = {}
            return self._signatures
        try:
            with open(self._sig_path, 'r') as f:
                self._signatures = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._signatures = {}
        return self._signatures

    def update_signatures(self, url=None):
        """Download latest signatures from GitHub."""
        import urllib.request
        if not url:
            url = ('https://raw.githubusercontent.com/AssoEchap/'
                   'stalkerware-indicators/master/generated/'
                   'stalkerware.json')
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'AUTARCH/1.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = json.loads(resp.read().decode())
            # Merge external indicators into our packages list
            sigs = self._load_signatures()
            merged = 0
            if isinstance(raw, list):
                # AssoEchap format: list of objects with "package" field
                if 'stalkerware' not in sigs:
                    sigs['stalkerware'] = {}
                existing_pkgs = set()
                for family in sigs['stalkerware'].values():
                    for pkg in family.get('packages', []):
                        existing_pkgs.add(pkg)
                new_family = sigs['stalkerware'].setdefault('AssoEchap Community', {
                    'severity': 'critical',
                    'packages': [],
                    'description': 'Community-sourced stalkerware indicators'
                })
                for entry in raw:
                    pkg = entry.get('package', '') if isinstance(entry, dict) else str(entry)
                    pkg = pkg.strip()
                    if pkg and pkg not in existing_pkgs:
                        new_family['packages'].append(pkg)
                        existing_pkgs.add(pkg)
                        merged += 1
            sigs['last_updated'] = datetime.now().strftime('%Y-%m-%d')
            with open(self._sig_path, 'w') as f:
                json.dump(sigs, f, indent=2)
            self._signatures = sigs
            return {'ok': True, 'merged': merged, 'source': url}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def get_signature_stats(self):
        """Count known threats by category."""
        sigs = self._load_signatures()
        stalkerware_families = len(sigs.get('stalkerware', {}))
        stalkerware_packages = sum(
            len(f.get('packages', []))
            for f in sigs.get('stalkerware', {}).values()
        )
        govt_spyware = len(sigs.get('government_spyware', {}))
        perm_combos = len(sigs.get('dangerous_permission_combos', []))
        return {
            'stalkerware_families': stalkerware_families,
            'stalkerware_packages': stalkerware_packages,
            'government_spyware': govt_spyware,
            'permission_combos': perm_combos,
            'version': sigs.get('version', 'unknown'),
            'last_updated': sigs.get('last_updated', 'unknown'),
        }

    # ── Shizuku Management ──────────────────────────────────────────

    def check_shizuku(self, serial):
        """Check Shizuku installation and status."""
        result = {'installed': False, 'running': False, 'version': ''}
        # Check installed
        stdout, _, rc = self._adb_shell(
            'pm list packages moe.shizuku.privileged.api', serial=serial)
        result['installed'] = 'moe.shizuku.privileged.api' in stdout
        if not result['installed']:
            return result
        # Get version
        stdout, _, rc = self._adb_shell(
            'dumpsys package moe.shizuku.privileged.api | grep versionName',
            serial=serial)
        m = re.search(r'versionName=(\S+)', stdout)
        if m:
            result['version'] = m.group(1)
        # Check running
        stdout, _, rc = self._adb_shell(
            'ps -A | grep shizuku', serial=serial, timeout=10)
        result['running'] = 'shizuku' in stdout.lower()
        return result

    def install_shizuku(self, serial, apk_path=None):
        """Install Shizuku APK via ADB."""
        if not apk_path:
            return {'ok': False, 'error': 'No APK path provided'}
        if not os.path.isfile(apk_path):
            return {'ok': False, 'error': f'APK not found: {apk_path}'}
        stdout, stderr, rc = self._adb(['install', '-r', apk_path],
                                       serial=serial, timeout=120)
        if rc == 0 and 'Success' in stdout:
            return {'ok': True, 'message': 'Shizuku installed'}
        return {'ok': False, 'error': stderr or stdout}

    def start_shizuku(self, serial):
        """Start Shizuku service via ADB."""
        stdout, stderr, rc = self._adb_shell(
            'sh /sdcard/Android/data/moe.shizuku.privileged.api/start.sh',
            serial=serial, timeout=15)
        if rc == 0:
            return {'ok': True, 'output': stdout.strip()}
        return {'ok': False, 'error': stderr or stdout}

    def stop_shizuku(self, serial):
        """Stop Shizuku server process."""
        stdout, stderr, rc = self._adb_shell(
            'am force-stop moe.shizuku.privileged.api', serial=serial)
        return {'ok': rc == 0, 'output': stdout.strip()}

    def shizuku_status(self, serial):
        """Full Shizuku status check."""
        info = self.check_shizuku(serial)
        # Check authorized apps
        if info['running']:
            stdout, _, _ = self._adb_shell(
                'dumpsys activity provider moe.shizuku.privileged.api',
                serial=serial, timeout=10)
            info['provider_info'] = stdout[:2000] if stdout else ''
        return info

    # ── Protection App Management ───────────────────────────────────

    def check_shield_app(self, serial):
        """Check if our protection app is installed."""
        stdout, _, rc = self._adb_shell(
            'pm list packages com.autarch.shield', serial=serial)
        installed = 'com.autarch.shield' in stdout
        version = ''
        if installed:
            stdout2, _, _ = self._adb_shell(
                'dumpsys package com.autarch.shield | grep versionName',
                serial=serial)
            m = re.search(r'versionName=(\S+)', stdout2)
            if m:
                version = m.group(1)
        return {'installed': installed, 'version': version}

    def install_shield_app(self, serial, apk_path):
        """Install our Shield APK via ADB."""
        if not os.path.isfile(apk_path):
            return {'ok': False, 'error': f'APK not found: {apk_path}'}
        stdout, stderr, rc = self._adb(['install', '-r', apk_path],
                                       serial=serial, timeout=120)
        if rc == 0 and 'Success' in stdout:
            return {'ok': True, 'message': 'Shield app installed'}
        return {'ok': False, 'error': stderr or stdout}

    def configure_shield(self, serial, config):
        """Push config to shield app via broadcast intent."""
        config_json = json.dumps(config)
        stdout, stderr, rc = self._adb_shell(
            f'am broadcast -a com.autarch.shield.CONFIGURE '
            f'--es config \'{config_json}\' '
            f'-n com.autarch.shield/.ConfigReceiver',
            serial=serial)
        return {'ok': rc == 0, 'output': stdout.strip()}

    def get_shield_status(self, serial):
        """Query shield app status via broadcast + logcat."""
        # Send status query
        self._adb_shell(
            'am broadcast -a com.autarch.shield.STATUS_QUERY '
            '-n com.autarch.shield/.StatusReceiver',
            serial=serial)
        # Read response from logcat
        stdout, _, _ = self._adb(
            ['logcat', '-d', '-t', '20', '-s', 'AutoarchShield:*'],
            serial=serial, timeout=5)
        return {'output': stdout.strip()}

    def grant_shield_permissions(self, serial):
        """Auto-grant required permissions to Shield app."""
        perms = [
            'android.permission.READ_SMS',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_CALL_LOG',
            'android.permission.READ_CONTACTS',
            'android.permission.PACKAGE_USAGE_STATS',
        ]
        granted = []
        failed = []
        for perm in perms:
            _, stderr, rc = self._adb_shell(
                f'pm grant com.autarch.shield {perm}', serial=serial)
            if rc == 0:
                granted.append(perm)
            else:
                failed.append({'perm': perm, 'error': stderr.strip()})
        return {'granted': granted, 'failed': failed}

    # ── Stalkerware Detection ───────────────────────────────────────

    def _get_installed_packages(self, serial):
        """Get all installed packages as a set."""
        stdout, _, rc = self._adb_shell('pm list packages', serial=serial, timeout=30)
        if rc != 0:
            return set()
        pkgs = set()
        for line in stdout.strip().split('\n'):
            line = line.strip()
            if line.startswith('package:'):
                pkgs.add(line[8:])
        return pkgs

    def scan_stalkerware(self, serial):
        """Scan all installed packages against signature database."""
        sigs = self._load_signatures()
        installed = self._get_installed_packages(serial)
        if not installed:
            return {'error': 'Could not list packages (ADB issue?)',
                    'found': [], 'clean_count': 0, 'total': 0}

        found = []
        stalkerware_db = sigs.get('stalkerware', {})
        # Also check suspicious system packages
        suspicious_sys = set(sigs.get('suspicious_system_packages', []))

        for family_name, family_data in stalkerware_db.items():
            for pkg in family_data.get('packages', []):
                if pkg in installed:
                    found.append({
                        'name': family_name,
                        'package': pkg,
                        'severity': family_data.get('severity', 'high'),
                        'description': family_data.get('description', ''),
                    })

        # Check suspicious system-mimicking packages
        for pkg in installed:
            if pkg in suspicious_sys:
                found.append({
                    'name': 'Suspicious System Package',
                    'package': pkg,
                    'severity': 'high',
                    'description': 'Package mimics a system app name — verify legitimacy',
                })

        matched_pkgs = {f['package'] for f in found}
        return {
            'found': found,
            'clean_count': len(installed) - len(matched_pkgs),
            'total': len(installed),
        }

    def scan_hidden_apps(self, serial):
        """Detect apps with no launcher icon (hidden from app drawer)."""
        # Get all packages
        installed = self._get_installed_packages(serial)
        # Get packages that have a launcher activity
        stdout, _, rc = self._adb_shell(
            'cmd package query-activities -a android.intent.action.MAIN '
            '-c android.intent.category.LAUNCHER',
            serial=serial, timeout=30)
        launcher_pkgs = set()
        if rc == 0:
            for line in stdout.split('\n'):
                line = line.strip()
                if '/' in line:
                    pkg = line.split('/')[0]
                    launcher_pkgs.add(pkg)
                elif line.startswith('package:'):
                    launcher_pkgs.add(line[8:].split('/')[0])
        # Fallback: try pm query-activities
        if not launcher_pkgs:
            stdout2, _, rc2 = self._adb_shell(
                'pm query-activities --brief -a android.intent.action.MAIN '
                '-c android.intent.category.LAUNCHER',
                serial=serial, timeout=30)
            if rc2 == 0:
                for line in stdout2.split('\n'):
                    line = line.strip()
                    if '/' in line:
                        launcher_pkgs.add(line.split('/')[0])

        # System packages that legitimately lack launcher icons
        system_prefixes = (
            'com.android.', 'com.google.android.', 'android.',
            'com.qualcomm.', 'com.samsung.', 'com.huawei.',
            'com.mediatek.', 'com.oppo.', 'com.vivo.',
            'com.xiaomi.', 'com.oneplus.', 'com.coloros.',
            'org.codeaurora.', 'com.oem.', 'com.sec.',
        )

        hidden = []
        for pkg in installed:
            if pkg not in launcher_pkgs:
                if any(pkg.startswith(p) for p in system_prefixes):
                    continue
                hidden.append(pkg)

        return {'hidden_apps': sorted(hidden), 'count': len(hidden)}

    def scan_device_admins(self, serial):
        """List device admin apps, flag suspicious ones."""
        stdout, _, rc = self._adb_shell(
            'dumpsys device_policy', serial=serial, timeout=15)
        admins = []
        if rc != 0:
            return {'admins': [], 'error': 'Could not query device policy'}

        # Parse admin entries
        current = None
        for line in stdout.split('\n'):
            line = line.strip()
            m = re.match(r'Admin\s*\((.+?)\):', line)
            if not m:
                m = re.match(r'(\S+/\S+):', line)
            if m:
                comp = m.group(1)
                pkg = comp.split('/')[0] if '/' in comp else comp
                current = {'component': comp, 'package': pkg, 'flags': []}
                admins.append(current)
            elif current and '=' in line:
                current['flags'].append(line)

        # Flag known-bad
        sigs = self._load_signatures()
        known_bad = set()
        for family in sigs.get('stalkerware', {}).values():
            known_bad.update(family.get('packages', []))

        for a in admins:
            a['suspicious'] = a['package'] in known_bad

        return {'admins': admins, 'count': len(admins)}

    def scan_accessibility_services(self, serial):
        """List accessibility services, flag non-legitimate ones."""
        stdout, _, rc = self._adb_shell(
            'settings get secure enabled_accessibility_services',
            serial=serial, timeout=10)
        services = []
        if rc != 0 or not stdout.strip() or stdout.strip() == 'null':
            return {'services': [], 'count': 0}

        sigs = self._load_signatures()
        legit = set(sigs.get('legitimate_accessibility_apps', []))
        known_bad = set()
        for family in sigs.get('stalkerware', {}).values():
            known_bad.update(family.get('packages', []))

        for svc in stdout.strip().split(':'):
            svc = svc.strip()
            if not svc:
                continue
            pkg = svc.split('/')[0] if '/' in svc else svc
            status = 'legitimate' if pkg in legit else (
                'malicious' if pkg in known_bad else 'unknown')
            services.append({
                'service': svc,
                'package': pkg,
                'status': status,
            })

        return {'services': services, 'count': len(services)}

    def scan_usage_access(self, serial):
        """Apps with usage stats access."""
        stdout, _, rc = self._adb_shell(
            'appops query-op USAGE_STATS allow', serial=serial, timeout=10)
        apps = []
        if rc == 0 and stdout.strip():
            for line in stdout.strip().split('\n'):
                pkg = line.strip()
                if pkg:
                    apps.append(pkg)
        # Fallback
        if not apps:
            stdout2, _, _ = self._adb_shell(
                'dumpsys usagestats | grep "package="', serial=serial, timeout=15)
            if stdout2:
                for line in stdout2.split('\n'):
                    m = re.search(r'package=(\S+)', line)
                    if m:
                        apps.append(m.group(1))
                apps = list(set(apps))
        return {'apps': sorted(apps), 'count': len(apps)}

    def scan_notification_listeners(self, serial):
        """Apps reading notifications."""
        stdout, _, rc = self._adb_shell(
            'settings get secure enabled_notification_listeners',
            serial=serial, timeout=10)
        listeners = []
        if rc != 0 or not stdout.strip() or stdout.strip() == 'null':
            return {'listeners': [], 'count': 0}

        sigs = self._load_signatures()
        known_bad = set()
        for family in sigs.get('stalkerware', {}).values():
            known_bad.update(family.get('packages', []))

        for svc in stdout.strip().split(':'):
            svc = svc.strip()
            if not svc:
                continue
            pkg = svc.split('/')[0] if '/' in svc else svc
            listeners.append({
                'service': svc,
                'package': pkg,
                'suspicious': pkg in known_bad,
            })

        return {'listeners': listeners, 'count': len(listeners)}

    # ── Government Spyware Detection ────────────────────────────────

    def scan_spyware_indicators(self, serial):
        """Check for known government spyware file paths, processes."""
        sigs = self._load_signatures()
        govt = sigs.get('government_spyware', {})
        findings = []

        for name, data in govt.items():
            indicators = data.get('indicators', {})
            matched = []

            # Check processes
            for proc in indicators.get('processes', []):
                stdout, _, rc = self._adb_shell(
                    f'ps -A | grep -i {proc}', serial=serial, timeout=5)
                if rc == 0 and proc.lower() in stdout.lower():
                    matched.append({'type': 'process', 'value': proc,
                                    'evidence': stdout.strip()[:200]})

            # Check files
            for fpath in indicators.get('files', []):
                stdout, _, rc = self._adb_shell(
                    f'ls -la {fpath} 2>/dev/null', serial=serial, timeout=5)
                if rc == 0 and stdout.strip() and 'No such file' not in stdout:
                    matched.append({'type': 'file', 'value': fpath,
                                    'evidence': stdout.strip()[:200]})

            # Check properties
            for prop in indicators.get('properties', []):
                stdout, _, rc = self._adb_shell(
                    f'getprop {prop}', serial=serial, timeout=5)
                if rc == 0 and stdout.strip():
                    matched.append({'type': 'property', 'value': prop,
                                    'evidence': stdout.strip()[:200]})

            if matched:
                findings.append({
                    'name': name,
                    'severity': data.get('severity', 'critical'),
                    'description': indicators.get('description',
                                                  data.get('description', '')),
                    'indicators_matched': matched,
                })

        return {'findings': findings, 'count': len(findings),
                'spyware_checked': len(govt)}

    def scan_system_integrity(self, serial):
        """Verify system hasn't been tampered with."""
        checks = {}

        # SELinux status
        stdout, _, _ = self._adb_shell('getenforce', serial=serial, timeout=5)
        selinux = stdout.strip()
        checks['selinux'] = {
            'value': selinux,
            'ok': selinux.lower() == 'enforcing',
            'description': 'SELinux should be Enforcing'
        }

        # Build fingerprint
        stdout, _, _ = self._adb_shell(
            'getprop ro.build.fingerprint', serial=serial, timeout=5)
        checks['build_fingerprint'] = {
            'value': stdout.strip(),
            'ok': bool(stdout.strip()),
            'description': 'Build fingerprint present'
        }

        # Verity mode
        stdout, _, _ = self._adb_shell(
            'getprop ro.boot.veritymode', serial=serial, timeout=5)
        verity = stdout.strip()
        checks['verity'] = {
            'value': verity or 'not set',
            'ok': verity.lower() in ('enforcing', ''),
            'description': 'DM-Verity should be enforcing or not set'
        }

        # Root check — su binary
        stdout, _, rc = self._adb_shell(
            'which su 2>/dev/null', serial=serial, timeout=5)
        has_su = bool(stdout.strip())
        checks['su_binary'] = {
            'value': stdout.strip() or 'not found',
            'ok': not has_su,
            'description': 'su binary should not be present'
        }

        # Boot state
        stdout, _, _ = self._adb_shell(
            'getprop ro.boot.verifiedbootstate', serial=serial, timeout=5)
        vb = stdout.strip()
        checks['verified_boot'] = {
            'value': vb or 'unknown',
            'ok': vb.lower() in ('green', ''),
            'description': 'Verified boot state should be green'
        }

        ok_count = sum(1 for c in checks.values() if c['ok'])
        return {'checks': checks, 'ok_count': ok_count,
                'total': len(checks)}

    def scan_suspicious_processes(self, serial):
        """Find suspicious processes."""
        findings = []

        # Processes in /data/local/tmp/
        stdout, _, rc = self._adb_shell(
            'ls -la /data/local/tmp/ 2>/dev/null', serial=serial, timeout=10)
        if rc == 0 and stdout.strip():
            for line in stdout.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('total') and not line.startswith('d'):
                    findings.append({
                        'type': 'tmp_file',
                        'detail': line,
                        'severity': 'high',
                        'description': 'File in /data/local/tmp/ — often used by exploits'
                    })

        # Running processes as root (non-standard)
        stdout, _, rc = self._adb_shell(
            'ps -A -o USER,PID,NAME 2>/dev/null || ps -A',
            serial=serial, timeout=10)
        if rc == 0:
            for line in stdout.strip().split('\n')[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 3:
                    user, pid, name = parts[0], parts[1], parts[-1]
                    # Flag unknown root processes
                    if user == 'root' and not any(
                        name.startswith(p) for p in (
                            'init', 'kthread', 'logd', 'vold', 'lmkd',
                            'servicemanager', 'surfaceflinger', 'zygote',
                            'adbd', 'healthd', 'installd', 'netd', 'storaged',
                            '/system/', '/vendor/', '[', 'ueventd', 'sh',
                        )
                    ):
                        # Only flag unusual ones
                        if '/' in name and '/data/' in name:
                            findings.append({
                                'type': 'suspicious_process',
                                'detail': f'{name} (PID {pid}, user {user})',
                                'severity': 'high',
                                'description': 'Root process running from /data/'
                            })

        return {'findings': findings, 'count': len(findings)}

    def scan_certificates(self, serial):
        """Check CA certificate store for MITM certs."""
        findings = []

        # User-installed CA certs
        stdout, _, rc = self._adb_shell(
            'ls /data/misc/user/0/cacerts-added/ 2>/dev/null',
            serial=serial, timeout=10)
        if rc == 0 and stdout.strip():
            for cert in stdout.strip().split('\n'):
                cert = cert.strip()
                if cert:
                    # Get cert details
                    detail_out, _, _ = self._adb_shell(
                        f'openssl x509 -in /data/misc/user/0/cacerts-added/{cert} '
                        f'-noout -subject -issuer 2>/dev/null',
                        serial=serial, timeout=5)
                    findings.append({
                        'hash': cert,
                        'detail': detail_out.strip() if detail_out else 'Unknown',
                        'severity': 'high',
                        'description': 'User-installed CA certificate — may enable MITM'
                    })

        # Also check settings for cert count
        stdout2, _, _ = self._adb_shell(
            'settings get global num_user_ca_certs 2>/dev/null',
            serial=serial, timeout=5)

        return {
            'certs': findings,
            'count': len(findings),
            'user_ca_count': stdout2.strip() if stdout2 and stdout2.strip() != 'null' else '0'
        }

    def scan_network_config(self, serial):
        """Check for rogue proxy, DNS, VPN."""
        checks = {}

        # Global HTTP proxy
        stdout, _, _ = self._adb_shell(
            'settings get global http_proxy', serial=serial, timeout=5)
        proxy = stdout.strip()
        checks['http_proxy'] = {
            'value': proxy if proxy and proxy != 'null' and proxy != ':0' else 'none',
            'ok': not proxy or proxy in ('null', ':0', ''),
            'description': 'HTTP proxy setting'
        }

        # Global proxy host/port
        for setting in ('global_http_proxy_host', 'global_http_proxy_port'):
            stdout, _, _ = self._adb_shell(
                f'settings get global {setting}', serial=serial, timeout=5)
            val = stdout.strip()
            checks[setting] = {
                'value': val if val and val != 'null' else 'none',
                'ok': not val or val in ('null', ''),
            }

        # DNS
        stdout, _, _ = self._adb_shell(
            'getprop net.dns1', serial=serial, timeout=5)
        dns = stdout.strip()
        checks['dns1'] = {
            'value': dns or 'default',
            'ok': True,  # We just report it
            'description': 'Primary DNS server'
        }

        # Private DNS
        stdout, _, _ = self._adb_shell(
            'settings get global private_dns_mode', serial=serial, timeout=5)
        checks['private_dns'] = {
            'value': stdout.strip() or 'default',
            'ok': True,
            'description': 'Private DNS mode'
        }

        # Active VPN
        stdout, _, _ = self._adb_shell(
            'dumpsys connectivity | grep -i "vpn"', serial=serial, timeout=10)
        has_vpn = 'CONNECTED' in stdout.upper() if stdout else False
        checks['vpn_active'] = {
            'value': 'Active' if has_vpn else 'None',
            'ok': True,  # VPN is not inherently bad
            'description': 'Active VPN connection'
        }

        ok_count = sum(1 for c in checks.values() if c.get('ok', True))
        return {'checks': checks, 'ok_count': ok_count, 'total': len(checks)}

    def scan_developer_options(self, serial):
        """Check developer options state."""
        checks = {}

        settings_map = {
            'adb_enabled': ('global', 'USB Debugging'),
            'development_settings_enabled': ('global', 'Developer Options'),
            'install_non_market_apps': ('secure', 'Unknown Sources (legacy)'),
            'allow_mock_location': ('secure', 'Mock Locations'),
        }

        for setting, (namespace, desc) in settings_map.items():
            stdout, _, _ = self._adb_shell(
                f'settings get {namespace} {setting}',
                serial=serial, timeout=5)
            val = stdout.strip()
            enabled = val == '1'
            checks[setting] = {
                'value': 'enabled' if enabled else 'disabled',
                'enabled': enabled,
                'description': desc,
            }

        # OEM unlock
        stdout, _, _ = self._adb_shell(
            'getprop sys.oem_unlock_allowed', serial=serial, timeout=5)
        oem = stdout.strip()
        checks['oem_unlock'] = {
            'value': 'allowed' if oem == '1' else 'locked',
            'enabled': oem == '1',
            'description': 'OEM Unlock',
        }

        return {'checks': checks}

    # ── Permission Analysis ─────────────────────────────────────────

    def analyze_app_permissions(self, serial, package):
        """Full permission breakdown for one app."""
        stdout, _, rc = self._adb_shell(
            f'dumpsys package {package}', serial=serial, timeout=15)
        if rc != 0:
            return {'error': f'Could not query package {package}'}

        perms = {'granted': [], 'denied': [], 'install': []}
        in_perms = False
        for line in stdout.split('\n'):
            line = line.strip()
            if 'requested permissions:' in line.lower():
                in_perms = True
                continue
            if 'install permissions:' in line.lower():
                in_perms = False
                continue
            if in_perms and line.startswith('android.permission.'):
                perms['install'].append(line.rstrip(':'))
            # Runtime permissions
            m = re.match(r'(android\.permission\.\w+).*granted=(\w+)', line)
            if m:
                perm_name, granted = m.group(1), m.group(2)
                if granted == 'true':
                    perms['granted'].append(perm_name)
                else:
                    perms['denied'].append(perm_name)

        # Get app info
        info = {}
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('versionName='):
                info['version'] = line.split('=', 1)[1]
            elif 'firstInstallTime=' in line:
                info['first_install'] = line.split('=', 1)[1]
            elif 'lastUpdateTime=' in line:
                info['last_update'] = line.split('=', 1)[1]

        return {'package': package, 'permissions': perms, 'info': info}

    def find_dangerous_apps(self, serial):
        """Find apps with dangerous permission combinations."""
        sigs = self._load_signatures()
        combos = sigs.get('dangerous_permission_combos', [])
        installed = self._get_installed_packages(serial)

        # System packages to skip
        system_prefixes = (
            'com.android.', 'com.google.android.', 'android.',
            'com.samsung.', 'com.huawei.', 'com.qualcomm.',
        )

        dangerous = []
        for pkg in installed:
            if any(pkg.startswith(p) for p in system_prefixes):
                continue
            # Get permissions
            stdout, _, rc = self._adb_shell(
                f'dumpsys package {pkg} | grep "android.permission"',
                serial=serial, timeout=10)
            if rc != 0 or not stdout:
                continue
            app_perms = set()
            for line in stdout.split('\n'):
                m = re.search(r'(android\.permission\.[\w.]+)', line)
                if m:
                    app_perms.add(m.group(1).replace('android.permission.', ''))

            # Check combos
            for combo in combos:
                combo_perms = combo if isinstance(combo, list) else combo.get('permissions', [])
                combo_name = combo.get('name', 'unknown') if isinstance(combo, dict) else 'pattern'
                combo_sev = combo.get('severity', 'high') if isinstance(combo, dict) else 'high'
                if all(p in app_perms for p in combo_perms):
                    dangerous.append({
                        'package': pkg,
                        'combo': combo_name,
                        'severity': combo_sev,
                        'matched_perms': combo_perms,
                    })
                    break  # One match per app is enough

        return {'dangerous': dangerous, 'count': len(dangerous)}

    def permission_heatmap(self, serial):
        """Which apps have which dangerous permissions (matrix view)."""
        installed = self._get_installed_packages(serial)
        system_prefixes = (
            'com.android.', 'com.google.android.', 'android.',
            'com.samsung.', 'com.huawei.', 'com.qualcomm.',
        )

        dangerous_perms = [
            'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION',
            'READ_SMS', 'READ_CONTACTS', 'READ_CALL_LOG',
            'READ_EXTERNAL_STORAGE', 'BIND_ACCESSIBILITY_SERVICE',
            'SYSTEM_ALERT_WINDOW', 'READ_PHONE_STATE',
            'ACCESS_BACKGROUND_LOCATION', 'RECEIVE_BOOT_COMPLETED',
        ]

        matrix = []
        for pkg in sorted(installed):
            if any(pkg.startswith(p) for p in system_prefixes):
                continue
            stdout, _, rc = self._adb_shell(
                f'dumpsys package {pkg} | grep -E "android.permission.({"|".join(dangerous_perms)})"',
                serial=serial, timeout=10)
            if rc != 0 or not stdout.strip():
                continue

            app_perms = set()
            for line in stdout.split('\n'):
                for perm in dangerous_perms:
                    if perm in line and 'granted=true' in line:
                        app_perms.add(perm)

            if app_perms:
                matrix.append({
                    'package': pkg,
                    'permissions': {p: p in app_perms for p in dangerous_perms},
                    'count': len(app_perms),
                })

        matrix.sort(key=lambda x: x['count'], reverse=True)
        return {'matrix': matrix, 'permission_names': dangerous_perms,
                'app_count': len(matrix)}

    # ── Remediation ─────────────────────────────────────────────────

    def disable_threat(self, serial, package):
        """Disable a stalkerware package."""
        stdout, stderr, rc = self._adb_shell(
            f'pm disable-user --user 0 {package}', serial=serial)
        if rc == 0:
            return {'ok': True, 'message': f'{package} disabled'}
        return {'ok': False, 'error': stderr or stdout}

    def uninstall_threat(self, serial, package):
        """Uninstall a stalkerware package."""
        stdout, stderr, rc = self._adb_shell(
            f'pm uninstall --user 0 {package}', serial=serial, timeout=30)
        if rc == 0 and 'Success' in stdout:
            return {'ok': True, 'message': f'{package} uninstalled'}
        # Try without --user flag
        stdout, stderr, rc = self._adb_shell(
            f'pm uninstall {package}', serial=serial, timeout=30)
        if rc == 0 and 'Success' in stdout:
            return {'ok': True, 'message': f'{package} uninstalled'}
        return {'ok': False, 'error': stderr or stdout}

    def revoke_dangerous_perms(self, serial, package):
        """Revoke all dangerous permissions from a package."""
        dangerous = [
            'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
            'READ_CONTACTS', 'WRITE_CONTACTS',
            'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'CAMERA', 'RECORD_AUDIO',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'ACCESS_BACKGROUND_LOCATION',
            'READ_PHONE_STATE', 'CALL_PHONE',
            'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
        ]
        revoked = []
        failed = []
        for perm in dangerous:
            full = f'android.permission.{perm}'
            _, stderr, rc = self._adb_shell(
                f'pm revoke {package} {full}', serial=serial)
            if rc == 0:
                revoked.append(perm)
            else:
                if 'not a changeable permission type' not in (stderr or ''):
                    failed.append(perm)
        return {'revoked': revoked, 'failed': failed, 'package': package}

    def remove_device_admin(self, serial, package):
        """Remove device admin before uninstall."""
        # Try to find the admin receiver component
        stdout, _, _ = self._adb_shell(
            f'dumpsys device_policy | grep {package}',
            serial=serial, timeout=10)
        component = None
        for line in stdout.split('\n'):
            m = re.search(r'(\S+/\S+)', line)
            if m and package in m.group(1):
                component = m.group(1)
                break

        if component:
            _, stderr, rc = self._adb_shell(
                f'dpm remove-active-admin {component}', serial=serial)
            if rc == 0:
                return {'ok': True, 'message': f'Removed admin: {component}'}
            return {'ok': False, 'error': stderr}

        # Fallback: try package/DeviceAdminReceiver
        _, stderr, rc = self._adb_shell(
            f'dpm remove-active-admin {package}/.DeviceAdminReceiver',
            serial=serial)
        if rc == 0:
            return {'ok': True, 'message': f'Removed admin: {package}'}
        return {'ok': False, 'error': 'Could not find device admin component'}

    def remove_ca_cert(self, serial, cert_hash):
        """Remove a user-installed CA cert."""
        path = f'/data/misc/user/0/cacerts-added/{cert_hash}'
        _, stderr, rc = self._adb_shell(
            f'rm {path}', serial=serial)
        if rc == 0:
            return {'ok': True, 'message': f'Removed cert {cert_hash}'}
        return {'ok': False, 'error': stderr or 'Failed to remove cert (may need root)'}

    def clear_proxy(self, serial):
        """Remove proxy settings."""
        results = []
        for setting in ('http_proxy', 'global_http_proxy_host',
                        'global_http_proxy_port', 'global_http_proxy_exclusion_list'):
            _, stderr, rc = self._adb_shell(
                f'settings put global {setting} :0' if setting == 'http_proxy'
                else f'settings delete global {setting}',
                serial=serial)
            results.append({'setting': setting, 'ok': rc == 0})
        return {'results': results}

    def disable_usb_debug(self, serial):
        """Turn off USB debugging."""
        _, stderr, rc = self._adb_shell(
            'settings put global adb_enabled 0', serial=serial)
        return {'ok': rc == 0,
                'message': 'USB debugging disabled' if rc == 0 else stderr}

    # ── Full Scans ──────────────────────────────────────────────────

    def quick_scan(self, serial):
        """Fast scan: stalkerware + device admins + accessibility only."""
        results = {
            'type': 'quick',
            'serial': serial,
            'timestamp': datetime.now().isoformat(),
        }
        results['stalkerware'] = self.scan_stalkerware(serial)
        results['device_admins'] = self.scan_device_admins(serial)
        results['accessibility'] = self.scan_accessibility_services(serial)

        # Summary
        threats = len(results['stalkerware'].get('found', []))
        suspicious_admins = sum(
            1 for a in results['device_admins'].get('admins', [])
            if a.get('suspicious'))
        bad_a11y = sum(
            1 for s in results['accessibility'].get('services', [])
            if s.get('status') == 'malicious')

        results['summary'] = {
            'threats_found': threats + suspicious_admins + bad_a11y,
            'stalkerware': threats,
            'suspicious_admins': suspicious_admins,
            'malicious_accessibility': bad_a11y,
        }
        return results

    def full_protection_scan(self, serial):
        """Run ALL scans, return comprehensive report."""
        results = {
            'type': 'full',
            'serial': serial,
            'timestamp': datetime.now().isoformat(),
        }

        results['stalkerware'] = self.scan_stalkerware(serial)
        results['hidden_apps'] = self.scan_hidden_apps(serial)
        results['device_admins'] = self.scan_device_admins(serial)
        results['accessibility'] = self.scan_accessibility_services(serial)
        results['notification_listeners'] = self.scan_notification_listeners(serial)
        results['usage_access'] = self.scan_usage_access(serial)
        results['spyware_indicators'] = self.scan_spyware_indicators(serial)
        results['system_integrity'] = self.scan_system_integrity(serial)
        results['suspicious_processes'] = self.scan_suspicious_processes(serial)
        results['certificates'] = self.scan_certificates(serial)
        results['network_config'] = self.scan_network_config(serial)
        results['developer_options'] = self.scan_developer_options(serial)
        results['dangerous_apps'] = self.find_dangerous_apps(serial)

        # Summary
        total_threats = 0
        total_threats += len(results['stalkerware'].get('found', []))
        total_threats += results['spyware_indicators'].get('count', 0)
        total_threats += sum(
            1 for a in results['device_admins'].get('admins', [])
            if a.get('suspicious'))
        total_threats += sum(
            1 for s in results['accessibility'].get('services', [])
            if s.get('status') == 'malicious')
        total_threats += sum(
            1 for l in results['notification_listeners'].get('listeners', [])
            if l.get('suspicious'))
        total_threats += results['suspicious_processes'].get('count', 0)
        total_threats += results['certificates'].get('count', 0)

        integrity_ok = results['system_integrity'].get('ok_count', 0)
        integrity_total = results['system_integrity'].get('total', 0)

        results['summary'] = {
            'threats_found': total_threats,
            'system_integrity': f'{integrity_ok}/{integrity_total}',
            'hidden_apps': results['hidden_apps'].get('count', 0),
            'dangerous_apps': results['dangerous_apps'].get('count', 0),
            'user_ca_certs': results['certificates'].get('count', 0),
        }

        return results

    def export_scan_report(self, serial, scan_result=None):
        """Save scan report as JSON file."""
        if scan_result is None:
            scan_result = self.full_protection_scan(serial)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname = f'scan_{ts}.json'
        fpath = self._scans_dir(serial) / fname
        with open(fpath, 'w') as f:
            json.dump(scan_result, f, indent=2, default=str)
        return {'ok': True, 'path': str(fpath), 'filename': fname}

    # ── Tracking Honeypot ──────────────────────────────────────────

    # -- Honeypot Helpers --

    def _load_tracker_domains(self):
        """Lazy-load tracker domain database."""
        if self._tracker_db is not None:
            return self._tracker_db
        if not self._tracker_path.exists():
            self._tracker_db = {}
            return self._tracker_db
        try:
            with open(self._tracker_path, 'r') as f:
                self._tracker_db = json.load(f)
        except (json.JSONDecodeError, OSError):
            self._tracker_db = {}
        return self._tracker_db

    def _check_root(self, serial):
        """Check if device has root (su) access."""
        stdout, _, rc = self._adb_shell('su -c id', serial=serial, timeout=10)
        return rc == 0 and 'uid=0' in stdout

    def _load_honeypot_config(self, serial):
        """Load per-device honeypot state."""
        cfg_path = self._device_dir(serial) / 'honeypot_config.json'
        if not cfg_path.exists():
            return {'active': False, 'tier': 0, 'protections': {}}
        try:
            with open(cfg_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {'active': False, 'tier': 0, 'protections': {}}

    def _save_honeypot_config(self, serial, config):
        """Save per-device honeypot state."""
        cfg_path = self._device_dir(serial) / 'honeypot_config.json'
        with open(cfg_path, 'w') as f:
            json.dump(config, f, indent=2)

    def generate_hosts_content(self):
        """Generate hosts-file blocklist from all tracker domains."""
        db = self._load_tracker_domains()
        domains = set()
        for cat in db.get('categories', {}).values():
            domains.update(cat.get('domains', []))
        for company in db.get('companies', {}).values():
            domains.update(company.get('domains', []))
        lines = ['# AUTARCH Tracking Honeypot Blocklist',
                 f'# Generated {datetime.now().isoformat()}',
                 f'# {len(domains)} domains blocked',
                 '127.0.0.1 localhost',
                 '::1 localhost']
        for d in sorted(domains):
            lines.append(f'127.0.0.1 {d}')
        return '\n'.join(lines) + '\n'

    # -- Status & Detection --

    def honeypot_status(self, serial):
        """Report honeypot status for a device."""
        config = self._load_honeypot_config(serial)
        result = {
            'active': config.get('active', False),
            'tier': config.get('tier', 0),
            'protections': config.get('protections', {}),
        }
        # Quick live checks
        stdout, _, _ = self._adb_shell(
            'settings get secure limit_ad_tracking', serial=serial, timeout=5)
        result['ad_tracking_limited'] = stdout.strip() == '1'

        stdout, _, _ = self._adb_shell(
            'settings get global private_dns_mode', serial=serial, timeout=5)
        result['private_dns_mode'] = stdout.strip() or 'off'

        stdout, _, _ = self._adb_shell(
            'settings get global private_dns_specifier', serial=serial, timeout=5)
        result['private_dns_host'] = stdout.strip() if stdout.strip() != 'null' else ''

        return result

    def scan_tracker_apps(self, serial):
        """Match installed packages against known tracker packages."""
        db = self._load_tracker_domains()
        tracker_pkgs = db.get('tracker_packages', [])
        installed = self._get_installed_packages(serial)
        if not installed:
            return {'error': 'Could not list packages', 'found': [], 'total': 0}

        found = []
        for pkg in installed:
            for tracker in tracker_pkgs:
                if pkg.startswith(tracker) or pkg == tracker:
                    found.append(pkg)
                    break

        # Also check company-specific tracker packages
        for company, data in db.get('companies', {}).items():
            for tpkg in data.get('tracker_packages', []):
                for pkg in installed:
                    if pkg.startswith(tpkg) and pkg not in found:
                        found.append(pkg)

        return {'found': sorted(found), 'count': len(found),
                'total': len(installed)}

    def scan_tracker_permissions(self, serial):
        """Find non-system apps with tracking-related permissions."""
        db = self._load_tracker_domains()
        tracking_perms = db.get('tracking_permissions', [
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'READ_PHONE_STATE', 'AD_ID',
        ])
        installed = self._get_installed_packages(serial)
        system_prefixes = (
            'com.android.', 'com.google.android.', 'android.',
            'com.samsung.', 'com.huawei.', 'com.qualcomm.',
        )

        results = []
        for pkg in installed:
            if any(pkg.startswith(p) for p in system_prefixes):
                continue
            stdout, _, rc = self._adb_shell(
                f'dumpsys package {pkg} | grep "android.permission"',
                serial=serial, timeout=10)
            if rc != 0 or not stdout:
                continue
            matched = []
            for perm in tracking_perms:
                full_perm = f'android.permission.{perm}'
                if full_perm in stdout and 'granted=true' in stdout.split(full_perm)[-1][:50]:
                    matched.append(perm)
            if matched:
                results.append({'package': pkg, 'permissions': matched})

        results.sort(key=lambda x: len(x['permissions']), reverse=True)
        return {'apps': results, 'count': len(results)}

    def get_advertising_id(self, serial):
        """Read the device advertising ID."""
        stdout, _, rc = self._adb_shell(
            'settings get secure advertising_id', serial=serial, timeout=5)
        ad_id = stdout.strip()
        if ad_id == 'null' or not ad_id:
            ad_id = 'Not set'
        return {'advertising_id': ad_id}

    def get_tracking_settings(self, serial):
        """Read all tracking-related device settings."""
        settings = {}
        checks = [
            ('limit_ad_tracking', 'secure', 'Ad tracking limited'),
            ('advertising_id', 'secure', 'Advertising ID'),
        ]
        for setting, namespace, desc in checks:
            stdout, _, _ = self._adb_shell(
                f'settings get {namespace} {setting}',
                serial=serial, timeout=5)
            val = stdout.strip()
            settings[setting] = {
                'value': val if val and val != 'null' else 'Not set',
                'description': desc,
            }

        # Location mode
        stdout, _, _ = self._adb_shell(
            'settings get secure location_mode', serial=serial, timeout=5)
        settings['location_mode'] = {
            'value': stdout.strip() or 'unknown',
            'description': 'Location mode (3=high accuracy)',
        }

        # Private DNS
        stdout, _, _ = self._adb_shell(
            'settings get global private_dns_mode', serial=serial, timeout=5)
        settings['private_dns_mode'] = {
            'value': stdout.strip() or 'off',
            'description': 'Private DNS mode',
        }

        # WiFi scanning
        stdout, _, _ = self._adb_shell(
            'settings get global wifi_scan_always_enabled',
            serial=serial, timeout=5)
        settings['wifi_scanning'] = {
            'value': 'enabled' if stdout.strip() == '1' else 'disabled',
            'description': 'WiFi background scanning',
        }

        # BT scanning
        stdout, _, _ = self._adb_shell(
            'settings get global ble_scan_always_enabled',
            serial=serial, timeout=5)
        settings['bt_scanning'] = {
            'value': 'enabled' if stdout.strip() == '1' else 'disabled',
            'description': 'Bluetooth background scanning',
        }

        # Usage diagnostics
        stdout, _, _ = self._adb_shell(
            'settings get global send_action_app_error',
            serial=serial, timeout=5)
        settings['diagnostics'] = {
            'value': 'enabled' if stdout.strip() == '1' else 'disabled',
            'description': 'Usage & diagnostics reporting',
        }

        return settings

    # -- Tier 1: ADB (no root required) --

    def reset_advertising_id(self, serial):
        """Reset Google Advertising ID."""
        # Delete existing ad ID
        _, _, rc1 = self._adb_shell(
            'settings delete secure advertising_id', serial=serial)
        # Send broadcast to GMS to regenerate
        _, _, rc2 = self._adb_shell(
            'am broadcast -a com.google.android.gms.ads.identifier.service.RESET',
            serial=serial)
        # Also try content provider approach
        self._adb_shell(
            'content call --uri content://com.google.android.gms.ads.identifier '
            '--method resetAdvertisingId',
            serial=serial, timeout=5)
        return {'ok': True, 'message': 'Advertising ID reset requested'}

    def opt_out_ad_tracking(self, serial):
        """Enable limit_ad_tracking opt-out."""
        _, _, rc = self._adb_shell(
            'settings put secure limit_ad_tracking 1', serial=serial)
        if rc == 0:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['ad_opt_out'] = True
            self._save_honeypot_config(serial, config)
            return {'ok': True, 'message': 'Ad tracking opt-out enabled'}
        return {'ok': False, 'error': 'Failed to set limit_ad_tracking'}

    def set_private_dns(self, serial, provider):
        """Set private DNS to an ad-blocking provider."""
        db = self._load_tracker_domains()
        providers = db.get('dns_providers', {})
        if provider not in providers:
            return {'ok': False,
                    'error': f'Unknown provider: {provider}. '
                             f'Available: {", ".join(providers.keys())}'}
        hostname = providers[provider]['hostname']
        # Set DNS mode
        _, _, rc1 = self._adb_shell(
            'settings put global private_dns_mode hostname',
            serial=serial)
        # Set DNS hostname
        _, _, rc2 = self._adb_shell(
            f'settings put global private_dns_specifier {hostname}',
            serial=serial)
        if rc1 == 0 and rc2 == 0:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['private_dns'] = provider
            self._save_honeypot_config(serial, config)
            return {'ok': True, 'message': f'Private DNS set to {hostname}',
                    'provider': provider}
        return {'ok': False, 'error': 'Failed to set private DNS'}

    def clear_private_dns(self, serial):
        """Revert private DNS to system default (opportunistic)."""
        _, _, rc = self._adb_shell(
            'settings put global private_dns_mode opportunistic',
            serial=serial)
        self._adb_shell(
            'settings delete global private_dns_specifier', serial=serial)
        if rc == 0:
            config = self._load_honeypot_config(serial)
            config.get('protections', {}).pop('private_dns', None)
            self._save_honeypot_config(serial, config)
            return {'ok': True, 'message': 'Private DNS reverted to default'}
        return {'ok': False, 'error': 'Failed to clear private DNS'}

    def disable_location_accuracy(self, serial):
        """Disable WiFi and Bluetooth background scanning."""
        results = []
        _, _, rc1 = self._adb_shell(
            'settings put global wifi_scan_always_enabled 0', serial=serial)
        results.append({'setting': 'wifi_scanning', 'ok': rc1 == 0})
        _, _, rc2 = self._adb_shell(
            'settings put global ble_scan_always_enabled 0', serial=serial)
        results.append({'setting': 'bt_scanning', 'ok': rc2 == 0})
        if rc1 == 0 and rc2 == 0:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['location_accuracy'] = True
            self._save_honeypot_config(serial, config)
        return {'ok': rc1 == 0 and rc2 == 0, 'results': results}

    def disable_usage_diagnostics(self, serial):
        """Turn off usage & diagnostics reporting."""
        _, _, rc1 = self._adb_shell(
            'settings put global send_action_app_error 0', serial=serial)
        _, _, rc2 = self._adb_shell(
            'settings put secure send_action_app_error 0', serial=serial)
        if rc1 == 0:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['diagnostics'] = True
            self._save_honeypot_config(serial, config)
        return {'ok': rc1 == 0, 'message': 'Usage diagnostics disabled'}

    # -- Tier 2: Shizuku-level --

    def restrict_app_background(self, serial, package):
        """Restrict an app's background activity."""
        results = []
        _, _, rc1 = self._adb_shell(
            f'cmd appops set {package} RUN_IN_BACKGROUND deny',
            serial=serial)
        results.append({'op': 'RUN_IN_BACKGROUND', 'ok': rc1 == 0})
        _, _, rc2 = self._adb_shell(
            f'cmd appops set {package} RUN_ANY_IN_BACKGROUND deny',
            serial=serial)
        results.append({'op': 'RUN_ANY_IN_BACKGROUND', 'ok': rc2 == 0})
        return {'ok': rc1 == 0, 'package': package, 'results': results}

    def revoke_tracker_permissions(self, serial, package):
        """Revoke tracking-related permissions from an app."""
        db = self._load_tracker_domains()
        tracking_perms = db.get('tracking_permissions', [
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'ACCESS_BACKGROUND_LOCATION', 'READ_PHONE_STATE',
            'GET_ACCOUNTS', 'READ_CONTACTS', 'READ_CALL_LOG',
        ])
        revoked = []
        failed = []
        for perm in tracking_perms:
            full = f'android.permission.{perm}'
            _, stderr, rc = self._adb_shell(
                f'pm revoke {package} {full}', serial=serial)
            if rc == 0:
                revoked.append(perm)
            elif 'not a changeable permission' not in (stderr or ''):
                failed.append(perm)
        return {'revoked': revoked, 'failed': failed, 'package': package}

    def clear_app_tracking_data(self, serial, package):
        """Clear tracking data for an app (cache + storage)."""
        _, _, rc = self._adb_shell(
            f'pm clear {package}', serial=serial, timeout=15)
        if rc == 0:
            return {'ok': True, 'message': f'Cleared all data for {package}'}
        # Fallback: reset appops
        _, _, rc2 = self._adb_shell(
            f'cmd appops reset {package}', serial=serial)
        return {'ok': rc2 == 0,
                'message': f'Reset appops for {package}' if rc2 == 0
                else f'Failed to clear data for {package}'}

    def force_stop_trackers(self, serial):
        """Force-stop all known tracker packages found on device."""
        db = self._load_tracker_domains()
        tracker_pkgs = set(db.get('tracker_packages', []))
        for company in db.get('companies', {}).values():
            tracker_pkgs.update(company.get('tracker_packages', []))
        installed = self._get_installed_packages(serial)

        stopped = []
        for pkg in installed:
            for tracker in tracker_pkgs:
                if pkg.startswith(tracker) or pkg == tracker:
                    _, _, rc = self._adb_shell(
                        f'am force-stop {pkg}', serial=serial, timeout=5)
                    if rc == 0:
                        stopped.append(pkg)
                    break
        return {'stopped': stopped, 'count': len(stopped)}

    # -- Tier 3: Root --

    def deploy_hosts_blocklist(self, serial):
        """Deploy tracker-blocking hosts file (requires root)."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        # Backup existing hosts
        self._adb_shell(
            'su -c "cp /system/etc/hosts /data/local/tmp/hosts.bak"',
            serial=serial)
        # Generate and push blocklist
        content = self.generate_hosts_content()
        tmp_path = self._device_dir(serial) / 'hosts_blocklist'
        with open(tmp_path, 'w') as f:
            f.write(content)
        # Push to device temp location
        self._adb(['push', str(tmp_path), '/data/local/tmp/hosts_new'],
                   serial=serial, timeout=30)
        # Mount rw, copy, mount ro
        stdout, _, rc = self._adb_shell(
            'su -c "'
            'mount -o remount,rw /system 2>/dev/null; '
            'cp /data/local/tmp/hosts_new /system/etc/hosts && '
            'chmod 644 /system/etc/hosts && '
            'mount -o remount,ro /system 2>/dev/null; '
            'echo DONE"',
            serial=serial, timeout=15)
        success = 'DONE' in stdout
        if success:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['hosts_blocklist'] = True
            self._save_honeypot_config(serial, config)
            domain_count = content.count('\n') - 5  # minus header lines
            return {'ok': True,
                    'message': f'Hosts blocklist deployed ({domain_count} domains)'}
        return {'ok': False, 'error': 'Failed to deploy hosts file'}

    def remove_hosts_blocklist(self, serial):
        """Restore original hosts file."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        stdout, _, rc = self._adb_shell(
            'su -c "'
            'mount -o remount,rw /system 2>/dev/null; '
            'if [ -f /data/local/tmp/hosts.bak ]; then '
            'cp /data/local/tmp/hosts.bak /system/etc/hosts; '
            'else echo 127.0.0.1 localhost > /system/etc/hosts; fi; '
            'chmod 644 /system/etc/hosts && '
            'mount -o remount,ro /system 2>/dev/null; '
            'echo DONE"',
            serial=serial, timeout=15)
        success = 'DONE' in stdout
        if success:
            config = self._load_honeypot_config(serial)
            config.get('protections', {}).pop('hosts_blocklist', None)
            self._save_honeypot_config(serial, config)
        return {'ok': success,
                'message': 'Hosts file restored' if success
                else 'Failed to restore hosts'}

    def get_hosts_status(self, serial):
        """Check current hosts file status."""
        stdout, _, rc = self._adb_shell(
            'wc -l /system/etc/hosts 2>/dev/null && '
            'head -3 /system/etc/hosts 2>/dev/null',
            serial=serial, timeout=5)
        is_blocklist = 'AUTARCH' in stdout
        lines = stdout.strip().split('\n')
        line_count = 0
        if lines and lines[0]:
            try:
                line_count = int(lines[0].split()[0])
            except (ValueError, IndexError):
                pass
        return {'line_count': line_count, 'is_blocklist': is_blocklist,
                'header': '\n'.join(lines[1:4]) if len(lines) > 1 else ''}

    def setup_iptables_redirect(self, serial, port=9040):
        """Redirect tracker traffic through local proxy via iptables."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        db = self._load_tracker_domains()
        # Get a subset of high-priority tracker IPs to redirect
        # We redirect DNS queries and HTTP(S) for tracker domains
        cmds = [
            f'iptables -t nat -N AUTARCH_HONEYPOT 2>/dev/null',
            f'iptables -t nat -F AUTARCH_HONEYPOT',
            f'iptables -t nat -A AUTARCH_HONEYPOT -p tcp --dport 80 -j REDIRECT --to-port {port}',
            f'iptables -t nat -A AUTARCH_HONEYPOT -p tcp --dport 443 -j REDIRECT --to-port {port}',
            f'iptables -t nat -A OUTPUT -p tcp -m owner ! --uid-owner 0 -j AUTARCH_HONEYPOT',
        ]
        cmd_str = ' && '.join(cmds)
        stdout, _, rc = self._adb_shell(
            f'su -c "{cmd_str}"', serial=serial, timeout=15)
        if rc == 0:
            config = self._load_honeypot_config(serial)
            config.setdefault('protections', {})['iptables_redirect'] = port
            self._save_honeypot_config(serial, config)
            return {'ok': True,
                    'message': f'Traffic redirect active on port {port}'}
        return {'ok': False, 'error': f'iptables setup failed: {stdout}'}

    def clear_iptables_redirect(self, serial):
        """Remove iptables redirect rules."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        stdout, _, rc = self._adb_shell(
            'su -c "'
            'iptables -t nat -D OUTPUT -p tcp -m owner ! --uid-owner 0 '
            '-j AUTARCH_HONEYPOT 2>/dev/null; '
            'iptables -t nat -F AUTARCH_HONEYPOT 2>/dev/null; '
            'iptables -t nat -X AUTARCH_HONEYPOT 2>/dev/null; '
            'echo DONE"',
            serial=serial, timeout=10)
        if 'DONE' in stdout:
            config = self._load_honeypot_config(serial)
            config.get('protections', {}).pop('iptables_redirect', None)
            self._save_honeypot_config(serial, config)
        return {'ok': 'DONE' in stdout,
                'message': 'iptables rules cleared' if 'DONE' in stdout
                else 'Failed to clear iptables'}

    def set_fake_location(self, serial, lat, lon):
        """Set fake GPS location for tracker apps (requires root)."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        # Enable mock locations
        self._adb_shell(
            'settings put secure allow_mock_location 1', serial=serial)
        # Send fake location to Shield app receiver
        self._adb_shell(
            f'am broadcast -a com.autarch.shield.FAKE_LOCATION '
            f'--ef lat {lat} --ef lon {lon} '
            f'-n com.autarch.shield/.LocationReceiver',
            serial=serial)
        # Also set via system property for root-level spoofing
        self._adb_shell(
            f'su -c "setprop persist.autarch.fake_lat {lat}"',
            serial=serial)
        self._adb_shell(
            f'su -c "setprop persist.autarch.fake_lon {lon}"',
            serial=serial)
        config = self._load_honeypot_config(serial)
        config.setdefault('protections', {})['fake_location'] = {
            'lat': lat, 'lon': lon}
        self._save_honeypot_config(serial, config)
        return {'ok': True, 'message': f'Fake location set: {lat}, {lon}'}

    def set_random_fake_location(self, serial):
        """Pick a random famous location from templates."""
        db = self._load_tracker_domains()
        locations = db.get('fake_data_templates', {}).get('locations', [])
        if not locations:
            return {'ok': False, 'error': 'No location templates available'}
        loc = random.choice(locations)
        result = self.set_fake_location(serial, loc['lat'], loc['lon'])
        result['location_name'] = loc.get('name', 'Unknown')
        return result

    def clear_fake_location(self, serial):
        """Disable fake location."""
        self._adb_shell(
            'settings put secure allow_mock_location 0', serial=serial)
        self._adb_shell(
            'su -c "setprop persist.autarch.fake_lat \"\""',
            serial=serial)
        self._adb_shell(
            'su -c "setprop persist.autarch.fake_lon \"\""',
            serial=serial)
        config = self._load_honeypot_config(serial)
        config.get('protections', {}).pop('fake_location', None)
        self._save_honeypot_config(serial, config)
        return {'ok': True, 'message': 'Fake location cleared'}

    def rotate_device_identity(self, serial):
        """Randomize device identifiers (requires root)."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        changes = []
        # Randomize android_id
        new_id = ''.join(random.choices('0123456789abcdef', k=16))
        _, _, rc = self._adb_shell(
            f'settings put secure android_id {new_id}', serial=serial)
        changes.append({'setting': 'android_id', 'value': new_id, 'ok': rc == 0})
        # Reset advertising ID
        self._adb_shell(
            'settings delete secure advertising_id', serial=serial)
        changes.append({'setting': 'advertising_id', 'value': 'reset', 'ok': True})
        # Randomize SSAID if possible
        new_ssaid = ''.join(random.choices('0123456789abcdef', k=16))
        _, _, rc = self._adb_shell(
            f'su -c "settings put secure android_id {new_id}"',
            serial=serial)
        config = self._load_honeypot_config(serial)
        config.setdefault('protections', {})['identity_rotated'] = True
        config['protections']['last_rotation'] = datetime.now().isoformat()
        self._save_honeypot_config(serial, config)
        return {'ok': True, 'changes': changes,
                'message': f'Device identity rotated (new ID: {new_id[:8]}...)'}

    def generate_fake_fingerprint(self, serial):
        """Set fake device model/manufacturer props (requires root)."""
        if not self._check_root(serial):
            return {'ok': False, 'error': 'Root access required'}
        db = self._load_tracker_domains()
        models = db.get('fake_data_templates', {}).get('device_models', [
            'Samsung Galaxy S25 Ultra', 'Google Pixel 9 Pro',
            'iPhone 16 Pro Max',
        ])
        model = random.choice(models)
        # Parse brand/model
        parts = model.split(' ', 1)
        brand = parts[0]
        model_name = parts[1] if len(parts) > 1 else model

        changes = []
        props = {
            'ro.product.model': model_name,
            'ro.product.brand': brand,
            'ro.product.manufacturer': brand,
            'ro.product.device': model_name.lower().replace(' ', '_'),
        }
        for prop, val in props.items():
            _, _, rc = self._adb_shell(
                f'su -c "setprop {prop} \'{val}\'"', serial=serial)
            changes.append({'prop': prop, 'value': val, 'ok': rc == 0})

        config = self._load_honeypot_config(serial)
        config.setdefault('protections', {})['fake_fingerprint'] = model
        self._save_honeypot_config(serial, config)
        return {'ok': True, 'model': model, 'changes': changes,
                'message': f'Device now reports as {model}'}

    # -- Composite Actions --

    def honeypot_activate(self, serial, tier=1):
        """Activate honeypot protections up to the specified tier."""
        results = {'tier': tier, 'actions': []}

        # Tier 1 — always applied
        r = self.reset_advertising_id(serial)
        results['actions'].append({'name': 'Reset Ad ID', 'result': r})
        r = self.opt_out_ad_tracking(serial)
        results['actions'].append({'name': 'Opt Out Ad Tracking', 'result': r})
        r = self.disable_location_accuracy(serial)
        results['actions'].append({'name': 'Disable Location Scanning', 'result': r})
        r = self.disable_usage_diagnostics(serial)
        results['actions'].append({'name': 'Disable Diagnostics', 'result': r})
        # Set DNS to AdGuard by default
        r = self.set_private_dns(serial, 'adguard')
        results['actions'].append({'name': 'Set Ad-Blocking DNS', 'result': r})

        # Tier 2 — stop trackers
        if tier >= 2:
            r = self.force_stop_trackers(serial)
            results['actions'].append({'name': 'Force Stop Trackers', 'result': r})

        # Tier 3 — root
        if tier >= 3:
            r = self.deploy_hosts_blocklist(serial)
            results['actions'].append({'name': 'Deploy Hosts Blocklist', 'result': r})
            r = self.set_random_fake_location(serial)
            results['actions'].append({'name': 'Set Fake Location', 'result': r})
            r = self.rotate_device_identity(serial)
            results['actions'].append({'name': 'Rotate Identity', 'result': r})
            r = self.generate_fake_fingerprint(serial)
            results['actions'].append({'name': 'Fake Fingerprint', 'result': r})

        config = self._load_honeypot_config(serial)
        config['active'] = True
        config['tier'] = tier
        config['activated_at'] = datetime.now().isoformat()
        self._save_honeypot_config(serial, config)

        ok_count = sum(1 for a in results['actions']
                       if a['result'].get('ok', False))
        results['summary'] = f'{ok_count}/{len(results["actions"])} protections applied'
        return results

    def honeypot_deactivate(self, serial):
        """Undo all active honeypot protections."""
        config = self._load_honeypot_config(serial)
        protections = config.get('protections', {})
        results = {'actions': []}

        # Revert DNS
        if 'private_dns' in protections:
            r = self.clear_private_dns(serial)
            results['actions'].append({'name': 'Clear DNS', 'result': r})

        # Re-enable ad tracking (user's original choice)
        if protections.get('ad_opt_out'):
            self._adb_shell(
                'settings put secure limit_ad_tracking 0', serial=serial)
            results['actions'].append({
                'name': 'Re-enable Ad Tracking',
                'result': {'ok': True}})

        # Re-enable scanning
        if protections.get('location_accuracy'):
            self._adb_shell(
                'settings put global wifi_scan_always_enabled 1',
                serial=serial)
            self._adb_shell(
                'settings put global ble_scan_always_enabled 1',
                serial=serial)
            results['actions'].append({
                'name': 'Re-enable Location Scanning',
                'result': {'ok': True}})

        # Re-enable diagnostics
        if protections.get('diagnostics'):
            self._adb_shell(
                'settings put global send_action_app_error 1',
                serial=serial)
            results['actions'].append({
                'name': 'Re-enable Diagnostics',
                'result': {'ok': True}})

        # Root: remove hosts blocklist
        if protections.get('hosts_blocklist'):
            r = self.remove_hosts_blocklist(serial)
            results['actions'].append({'name': 'Remove Hosts Blocklist', 'result': r})

        # Root: clear iptables
        if 'iptables_redirect' in protections:
            r = self.clear_iptables_redirect(serial)
            results['actions'].append({'name': 'Clear iptables', 'result': r})

        # Root: clear fake location
        if 'fake_location' in protections:
            r = self.clear_fake_location(serial)
            results['actions'].append({'name': 'Clear Fake Location', 'result': r})

        # Reset config
        config['active'] = False
        config['tier'] = 0
        config['protections'] = {}
        config['deactivated_at'] = datetime.now().isoformat()
        self._save_honeypot_config(serial, config)

        return results

    def get_fake_data_set(self, serial):
        """Generate a random fake persona from templates."""
        db = self._load_tracker_domains()
        templates = db.get('fake_data_templates', {})
        locations = templates.get('locations', [])
        searches = templates.get('searches', [])
        purchases = templates.get('purchases', [])
        interests = templates.get('interests', [])
        models = templates.get('device_models', [])

        persona = {
            'location': random.choice(locations) if locations else None,
            'recent_searches': random.sample(searches,
                                             min(5, len(searches))) if searches else [],
            'recent_purchases': random.sample(purchases,
                                              min(3, len(purchases))) if purchases else [],
            'interests': random.sample(interests,
                                       min(8, len(interests))) if interests else [],
            'device': random.choice(models) if models else None,
        }
        return persona

    # -- Data Management --

    def update_tracker_domains(self, url=None):
        """Download and merge tracker domains from remote source."""
        import urllib.request
        if not url:
            url = ('https://raw.githubusercontent.com/nickthetailmighty/'
                   'pi-hole-blocklist/master/base-blocklist.txt')
        try:
            req = urllib.request.Request(url,
                                        headers={'User-Agent': 'AUTARCH/1.0'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode()
            db = self._load_tracker_domains()
            merged = 0
            existing = set()
            for cat in db.get('categories', {}).values():
                existing.update(cat.get('domains', []))
            new_domains = []
            for line in raw.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Handle hosts-file format (0.0.0.0 domain or 127.0.0.1 domain)
                parts = line.split()
                domain = parts[-1] if parts else line
                domain = domain.strip()
                if domain and '.' in domain and domain not in existing:
                    new_domains.append(domain)
                    merged += 1
            # Add to advertising category
            if new_domains:
                db.setdefault('categories', {}).setdefault(
                    'advertising', {'domains': [], 'description': 'Ad networks'}
                )['domains'].extend(new_domains[:500])
            db['last_updated'] = datetime.now().strftime('%Y-%m-%d')
            with open(self._tracker_path, 'w') as f:
                json.dump(db, f, indent=2)
            self._tracker_db = db
            return {'ok': True, 'merged': merged, 'source': url}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def get_tracker_stats(self):
        """Domain/package counts by category."""
        db = self._load_tracker_domains()
        categories = {}
        total_domains = 0
        for cat_name, cat_data in db.get('categories', {}).items():
            count = len(cat_data.get('domains', []))
            categories[cat_name] = count
            total_domains += count
        companies = len(db.get('companies', {}))
        packages = len(db.get('tracker_packages', []))
        return {
            'total_domains': total_domains,
            'categories': categories,
            'companies': companies,
            'packages': packages,
            'version': db.get('version', 'unknown'),
            'dns_providers': list(db.get('dns_providers', {}).keys()),
        }


# ── Singleton ──────────────────────────────────────────────────────

_manager = None

def get_android_protect_manager():
    global _manager
    if _manager is None:
        _manager = AndroidProtectManager()
    return _manager
