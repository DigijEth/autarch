"""Android Protection Shield routes — anti-stalkerware/spyware scanning and remediation."""

import os
from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

android_protect_bp = Blueprint('android_protect', __name__, url_prefix='/android-protect')


def _mgr():
    from core.android_protect import get_android_protect_manager
    return get_android_protect_manager()


def _serial():
    """Extract serial from JSON body, form data, or query params."""
    data = request.get_json(silent=True) or {}
    serial = data.get('serial') or request.form.get('serial') or request.args.get('serial', '')
    return str(serial).strip() if serial else ''


# ── Main Page ───────────────────────────────────────────────────────

@android_protect_bp.route('/')
@login_required
def index():
    from core.hardware import get_hardware_manager
    hw = get_hardware_manager()
    status = hw.get_status()
    sig_stats = _mgr().get_signature_stats()
    return render_template('android_protect.html', status=status, sig_stats=sig_stats)


# ── Scan Routes ─────────────────────────────────────────────────────

@android_protect_bp.route('/scan/quick', methods=['POST'])
@login_required
def scan_quick():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().quick_scan(serial))


@android_protect_bp.route('/scan/full', methods=['POST'])
@login_required
def scan_full():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().full_protection_scan(serial))


@android_protect_bp.route('/scan/export', methods=['POST'])
@login_required
def scan_export():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    scan = _mgr().full_protection_scan(serial)
    return jsonify(_mgr().export_scan_report(serial, scan))


@android_protect_bp.route('/scan/stalkerware', methods=['POST'])
@login_required
def scan_stalkerware():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_stalkerware(serial))


@android_protect_bp.route('/scan/hidden', methods=['POST'])
@login_required
def scan_hidden():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_hidden_apps(serial))


@android_protect_bp.route('/scan/admins', methods=['POST'])
@login_required
def scan_admins():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_device_admins(serial))


@android_protect_bp.route('/scan/accessibility', methods=['POST'])
@login_required
def scan_accessibility():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_accessibility_services(serial))


@android_protect_bp.route('/scan/listeners', methods=['POST'])
@login_required
def scan_listeners():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_notification_listeners(serial))


@android_protect_bp.route('/scan/spyware', methods=['POST'])
@login_required
def scan_spyware():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_spyware_indicators(serial))


@android_protect_bp.route('/scan/integrity', methods=['POST'])
@login_required
def scan_integrity():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_system_integrity(serial))


@android_protect_bp.route('/scan/processes', methods=['POST'])
@login_required
def scan_processes():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_suspicious_processes(serial))


@android_protect_bp.route('/scan/certs', methods=['POST'])
@login_required
def scan_certs():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_certificates(serial))


@android_protect_bp.route('/scan/network', methods=['POST'])
@login_required
def scan_network():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_network_config(serial))


@android_protect_bp.route('/scan/devopt', methods=['POST'])
@login_required
def scan_devopt():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_developer_options(serial))


# ── Permission Routes ───────────────────────────────────────────────

@android_protect_bp.route('/perms/dangerous', methods=['POST'])
@login_required
def perms_dangerous():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().find_dangerous_apps(serial))


@android_protect_bp.route('/perms/analyze', methods=['POST'])
@login_required
def perms_analyze():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if not package:
        return jsonify({'error': 'No package provided'})
    return jsonify(_mgr().analyze_app_permissions(serial, package))


@android_protect_bp.route('/perms/heatmap', methods=['POST'])
@login_required
def perms_heatmap():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().permission_heatmap(serial))


# ── Remediation Routes ──────────────────────────────────────────────

@android_protect_bp.route('/fix/disable', methods=['POST'])
@login_required
def fix_disable():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().disable_threat(serial, package))


@android_protect_bp.route('/fix/uninstall', methods=['POST'])
@login_required
def fix_uninstall():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().uninstall_threat(serial, package))


@android_protect_bp.route('/fix/revoke', methods=['POST'])
@login_required
def fix_revoke():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().revoke_dangerous_perms(serial, package))


@android_protect_bp.route('/fix/remove-admin', methods=['POST'])
@login_required
def fix_remove_admin():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().remove_device_admin(serial, package))


@android_protect_bp.route('/fix/remove-cert', methods=['POST'])
@login_required
def fix_remove_cert():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    cert_hash = data.get('cert_hash', '').strip()
    if not serial or not cert_hash:
        return jsonify({'error': 'Serial and cert_hash required'})
    return jsonify(_mgr().remove_ca_cert(serial, cert_hash))


@android_protect_bp.route('/fix/clear-proxy', methods=['POST'])
@login_required
def fix_clear_proxy():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().clear_proxy(serial))


# ── Shizuku Routes ──────────────────────────────────────────────────

@android_protect_bp.route('/shizuku/status', methods=['POST'])
@login_required
def shizuku_status():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().shizuku_status(serial))


@android_protect_bp.route('/shizuku/install', methods=['POST'])
@login_required
def shizuku_install():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    # Handle file upload
    if 'apk' in request.files:
        from flask import current_app
        f = request.files['apk']
        upload_dir = current_app.config.get('UPLOAD_FOLDER', '/tmp')
        path = os.path.join(upload_dir, 'shizuku.apk')
        f.save(path)
        return jsonify(_mgr().install_shizuku(serial, path))
    data = request.get_json(silent=True) or {}
    apk_path = data.get('apk_path', '').strip()
    if not apk_path:
        return jsonify({'error': 'No APK provided'})
    return jsonify(_mgr().install_shizuku(serial, apk_path))


@android_protect_bp.route('/shizuku/start', methods=['POST'])
@login_required
def shizuku_start():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().start_shizuku(serial))


# ── Shield App Routes ──────────────────────────────────────────────

@android_protect_bp.route('/shield/status', methods=['POST'])
@login_required
def shield_status():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().check_shield_app(serial))


@android_protect_bp.route('/shield/install', methods=['POST'])
@login_required
def shield_install():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if 'apk' in request.files:
        from flask import current_app
        f = request.files['apk']
        upload_dir = current_app.config.get('UPLOAD_FOLDER', '/tmp')
        path = os.path.join(upload_dir, 'shield.apk')
        f.save(path)
        return jsonify(_mgr().install_shield_app(serial, path))
    data = request.get_json(silent=True) or {}
    apk_path = data.get('apk_path', '').strip()
    if not apk_path:
        return jsonify({'error': 'No APK provided'})
    return jsonify(_mgr().install_shield_app(serial, apk_path))


@android_protect_bp.route('/shield/configure', methods=['POST'])
@login_required
def shield_configure():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    config = data.get('config', {})
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().configure_shield(serial, config))


@android_protect_bp.route('/shield/permissions', methods=['POST'])
@login_required
def shield_permissions():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().grant_shield_permissions(serial))


# ── Database Routes ─────────────────────────────────────────────────

@android_protect_bp.route('/db/stats', methods=['POST'])
@login_required
def db_stats():
    return jsonify(_mgr().get_signature_stats())


@android_protect_bp.route('/db/update', methods=['POST'])
@login_required
def db_update():
    return jsonify(_mgr().update_signatures())


# ── Honeypot Routes ────────────────────────────────────────────────

@android_protect_bp.route('/honeypot/status', methods=['POST'])
@login_required
def honeypot_status():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().honeypot_status(serial))


@android_protect_bp.route('/honeypot/scan-trackers', methods=['POST'])
@login_required
def honeypot_scan_trackers():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_tracker_apps(serial))


@android_protect_bp.route('/honeypot/scan-tracker-perms', methods=['POST'])
@login_required
def honeypot_scan_tracker_perms():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().scan_tracker_permissions(serial))


@android_protect_bp.route('/honeypot/ad-settings', methods=['POST'])
@login_required
def honeypot_ad_settings():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().get_tracking_settings(serial))


@android_protect_bp.route('/honeypot/reset-ad-id', methods=['POST'])
@login_required
def honeypot_reset_ad_id():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().reset_advertising_id(serial))


@android_protect_bp.route('/honeypot/opt-out', methods=['POST'])
@login_required
def honeypot_opt_out():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().opt_out_ad_tracking(serial))


@android_protect_bp.route('/honeypot/set-dns', methods=['POST'])
@login_required
def honeypot_set_dns():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    provider = data.get('provider', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if not provider:
        return jsonify({'error': 'No provider specified'})
    return jsonify(_mgr().set_private_dns(serial, provider))


@android_protect_bp.route('/honeypot/clear-dns', methods=['POST'])
@login_required
def honeypot_clear_dns():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().clear_private_dns(serial))


@android_protect_bp.route('/honeypot/disable-location-scan', methods=['POST'])
@login_required
def honeypot_disable_location_scan():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().disable_location_accuracy(serial))


@android_protect_bp.route('/honeypot/disable-diagnostics', methods=['POST'])
@login_required
def honeypot_disable_diagnostics():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().disable_usage_diagnostics(serial))


@android_protect_bp.route('/honeypot/restrict-background', methods=['POST'])
@login_required
def honeypot_restrict_background():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().restrict_app_background(serial, package))


@android_protect_bp.route('/honeypot/revoke-tracker-perms', methods=['POST'])
@login_required
def honeypot_revoke_tracker_perms():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().revoke_tracker_permissions(serial, package))


@android_protect_bp.route('/honeypot/clear-tracker-data', methods=['POST'])
@login_required
def honeypot_clear_tracker_data():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    package = data.get('package', '').strip()
    if not serial or not package:
        return jsonify({'error': 'Serial and package required'})
    return jsonify(_mgr().clear_app_tracking_data(serial, package))


@android_protect_bp.route('/honeypot/force-stop-trackers', methods=['POST'])
@login_required
def honeypot_force_stop_trackers():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().force_stop_trackers(serial))


@android_protect_bp.route('/honeypot/deploy-hosts', methods=['POST'])
@login_required
def honeypot_deploy_hosts():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().deploy_hosts_blocklist(serial))


@android_protect_bp.route('/honeypot/remove-hosts', methods=['POST'])
@login_required
def honeypot_remove_hosts():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().remove_hosts_blocklist(serial))


@android_protect_bp.route('/honeypot/hosts-status', methods=['POST'])
@login_required
def honeypot_hosts_status():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().get_hosts_status(serial))


@android_protect_bp.route('/honeypot/iptables-setup', methods=['POST'])
@login_required
def honeypot_iptables_setup():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    port = data.get('port', 9040)
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().setup_iptables_redirect(serial, port))


@android_protect_bp.route('/honeypot/iptables-clear', methods=['POST'])
@login_required
def honeypot_iptables_clear():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().clear_iptables_redirect(serial))


@android_protect_bp.route('/honeypot/fake-location', methods=['POST'])
@login_required
def honeypot_fake_location():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    lat = data.get('lat')
    lon = data.get('lon')
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if lat is None or lon is None:
        return jsonify({'error': 'lat and lon required'})
    return jsonify(_mgr().set_fake_location(serial, float(lat), float(lon)))


@android_protect_bp.route('/honeypot/random-location', methods=['POST'])
@login_required
def honeypot_random_location():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().set_random_fake_location(serial))


@android_protect_bp.route('/honeypot/clear-location', methods=['POST'])
@login_required
def honeypot_clear_location():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().clear_fake_location(serial))


@android_protect_bp.route('/honeypot/rotate-identity', methods=['POST'])
@login_required
def honeypot_rotate_identity():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().rotate_device_identity(serial))


@android_protect_bp.route('/honeypot/fake-fingerprint', methods=['POST'])
@login_required
def honeypot_fake_fingerprint():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().generate_fake_fingerprint(serial))


@android_protect_bp.route('/honeypot/activate', methods=['POST'])
@login_required
def honeypot_activate():
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    tier = data.get('tier', 1)
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().honeypot_activate(serial, int(tier)))


@android_protect_bp.route('/honeypot/deactivate', methods=['POST'])
@login_required
def honeypot_deactivate():
    serial = _serial()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(_mgr().honeypot_deactivate(serial))


@android_protect_bp.route('/honeypot/tracker-stats', methods=['POST'])
@login_required
def honeypot_tracker_stats():
    return jsonify(_mgr().get_tracker_stats())


@android_protect_bp.route('/honeypot/update-domains', methods=['POST'])
@login_required
def honeypot_update_domains():
    return jsonify(_mgr().update_tracker_domains())


# ── Direct (WebUSB) Mode — Command Relay ─────────────────────────────────────

# Maps operation key → dict of {label: adb_shell_command}
_DIRECT_COMMANDS = {
    'scan_quick': {
        'packages':      'pm list packages',
        'devopt':        'settings get global development_settings_enabled',
        'adb_enabled':   'settings get global adb_enabled',
        'accessibility': 'settings get secure enabled_accessibility_services',
        'admins':        'dumpsys device_policy 2>/dev/null | head -60',
    },
    'scan_stalkerware': {
        'packages': 'pm list packages',
    },
    'scan_hidden': {
        'all':      'pm list packages',
        'launcher': 'cmd package query-activities -a android.intent.action.MAIN '
                    '-c android.intent.category.LAUNCHER 2>/dev/null',
    },
    'scan_admins': {
        'admins': 'dumpsys device_policy 2>/dev/null | head -100',
    },
    'scan_accessibility': {
        'services': 'settings get secure enabled_accessibility_services',
    },
    'scan_listeners': {
        'listeners': 'cmd notification list-listeners 2>/dev/null || dumpsys notification 2>/dev/null | grep -i listener | head -30',
    },
    'scan_spyware': {
        'packages':  'pm list packages',
        'processes': 'ps -A 2>/dev/null | head -100',
    },
    'scan_integrity': {
        'secure':      'getprop ro.secure',
        'debuggable':  'getprop ro.debuggable',
        'fingerprint': 'getprop ro.build.fingerprint',
        'devopt':      'settings get global development_settings_enabled',
        'kernel':      'cat /proc/version',
    },
    'scan_processes': {
        'ps': 'ps -A 2>/dev/null | head -200',
    },
    'scan_certs': {
        'certs': 'ls /data/misc/user/0/cacerts-added/ 2>/dev/null || echo ""',
    },
    'scan_network': {
        'proxy':          'settings get global http_proxy',
        'dns1':           'getprop net.dns1',
        'dns2':           'getprop net.dns2',
        'private_dns':    'settings get global private_dns_mode',
        'private_dns_h':  'settings get global private_dns_specifier',
    },
    'scan_devopt': {
        'devopt':    'settings get global development_settings_enabled',
        'adb':       'settings get global adb_enabled',
        'adb_wifi':  'settings get global adb_wifi_enabled',
        'verifier':  'settings get global package_verifier_enable',
    },
    'perms_dangerous': {
        'packages': 'pm list packages',
    },
}


@android_protect_bp.route('/cmd', methods=['POST'])
@login_required
def direct_cmd():
    """Return ADB shell commands for Direct (WebUSB) mode."""
    data = request.get_json(silent=True) or {}
    op   = data.get('op', '').replace('/', '_').replace('-', '_')
    cmds = _DIRECT_COMMANDS.get(op)
    if cmds:
        return jsonify({'commands': cmds, 'supported': True})
    return jsonify({'commands': {}, 'supported': False})


@android_protect_bp.route('/parse', methods=['POST'])
@login_required
def direct_parse():
    """Analyze raw ADB shell output from Direct (WebUSB) mode."""
    import re
    data = request.get_json(silent=True) or {}
    op   = data.get('op', '').replace('/', '_').replace('-', '_')
    raw  = data.get('raw', {})
    mgr  = _mgr()

    def _pkgs(output):
        """Parse 'pm list packages' output to a set of package names."""
        pkgs = set()
        for line in (output or '').strip().split('\n'):
            line = line.strip()
            if line.startswith('package:'):
                pkgs.add(line[8:].split('=')[0].strip())
        return pkgs

    try:
        if op in ('scan_stalkerware', 'scan_quick', 'scan_spyware'):
            packages = _pkgs(raw.get('packages', ''))
            sigs     = mgr._load_signatures()
            found    = []
            for family, fdata in sigs.get('stalkerware', {}).items():
                for pkg in fdata.get('packages', []):
                    if pkg in packages:
                        found.append({'name': family, 'package': pkg,
                                      'severity': fdata.get('severity', 'high'),
                                      'description': fdata.get('description', '')})
            for pkg in packages:
                if pkg in set(sigs.get('suspicious_system_packages', [])):
                    found.append({'name': 'Suspicious System Package', 'package': pkg,
                                  'severity': 'high',
                                  'description': 'Package mimics a system app name'})
            matched = {f['package'] for f in found}
            result  = {'found': found,
                       'clean_count': len(packages) - len(matched),
                       'total': len(packages)}
            if op == 'scan_quick':
                result['developer_options']    = raw.get('devopt', '').strip() == '1'
                result['accessibility_active'] = raw.get('accessibility', '').strip() not in ('', 'null')
            return jsonify(result)

        elif op == 'scan_hidden':
            all_pkgs      = _pkgs(raw.get('all', ''))
            launcher_out  = raw.get('launcher', '')
            launcher_pkgs = set()
            for line in launcher_out.split('\n'):
                line = line.strip()
                if '/' in line:
                    launcher_pkgs.add(line.split('/')[0])
            hidden = sorted(all_pkgs - launcher_pkgs)
            return jsonify({'hidden': hidden, 'total': len(all_pkgs),
                            'hidden_count': len(hidden)})

        elif op == 'scan_admins':
            admins_raw = raw.get('admins', '')
            active = [l.strip() for l in admins_raw.split('\n')
                      if 'ComponentInfo' in l or 'admin' in l.lower()]
            return jsonify({'admins': active, 'count': len(active)})

        elif op == 'scan_accessibility':
            raw_val  = raw.get('services', '').strip()
            services = [s.strip() for s in raw_val.split(':')
                        if s.strip() and s.strip() != 'null']
            return jsonify({'services': services, 'count': len(services)})

        elif op == 'scan_listeners':
            lines = [l.strip() for l in raw.get('listeners', '').split('\n') if l.strip()]
            return jsonify({'listeners': lines, 'count': len(lines)})

        elif op == 'scan_integrity':
            issues = []
            if raw.get('debuggable', '').strip() == '1':
                issues.append({'issue': 'Kernel debuggable', 'severity': 'high',
                                'detail': 'ro.debuggable=1'})
            if raw.get('secure', '').strip() == '0':
                issues.append({'issue': 'Insecure kernel', 'severity': 'high',
                                'detail': 'ro.secure=0'})
            if raw.get('devopt', '').strip() == '1':
                issues.append({'issue': 'Developer options enabled', 'severity': 'medium',
                                'detail': ''})
            return jsonify({'issues': issues,
                            'fingerprint': raw.get('fingerprint', '').strip(),
                            'kernel': raw.get('kernel', '').strip()})

        elif op == 'scan_processes':
            lines = [l for l in raw.get('ps', '').split('\n') if l.strip()]
            return jsonify({'processes': lines, 'count': len(lines)})

        elif op == 'scan_certs':
            certs = [c.strip() for c in raw.get('certs', '').split('\n')
                     if c.strip() and not c.startswith('ls:')]
            return jsonify({'user_certs': certs, 'count': len(certs),
                            'risk': 'high' if certs else 'none'})

        elif op == 'scan_network':
            proxy = raw.get('proxy', '').strip()
            return jsonify({
                'proxy':          proxy if proxy not in ('', 'null') else None,
                'dns_primary':    raw.get('dns1', '').strip(),
                'dns_secondary':  raw.get('dns2', '').strip(),
                'private_dns':    raw.get('private_dns', '').strip(),
                'private_dns_h':  raw.get('private_dns_h', '').strip(),
            })

        elif op == 'scan_devopt':
            def flag(k): return raw.get(k, '').strip() == '1'
            issues = []
            if flag('devopt'):   issues.append({'setting': 'Developer options', 'risk': 'medium'})
            if flag('adb'):      issues.append({'setting': 'ADB enabled', 'risk': 'medium'})
            if flag('adb_wifi'): issues.append({'setting': 'ADB over WiFi', 'risk': 'high'})
            if raw.get('verifier', '').strip() == '0':
                issues.append({'setting': 'Package verifier disabled', 'risk': 'high'})
            return jsonify({'settings': issues})

        elif op == 'perms_dangerous':
            packages = sorted(_pkgs(raw.get('packages', '')))
            return jsonify({'packages': packages, 'count': len(packages),
                            'note': 'Full permission analysis requires Server mode (needs per-package dumpsys)'})

        else:
            return jsonify({'error': f'Direct mode parse not implemented for: {op}. Use Server mode.'}), 200

    except Exception as exc:
        return jsonify({'error': str(exc)})
