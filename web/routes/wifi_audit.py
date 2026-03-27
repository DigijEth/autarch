"""WiFi Auditing routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

wifi_audit_bp = Blueprint('wifi_audit', __name__, url_prefix='/wifi')

def _get_auditor():
    from modules.wifi_audit import get_wifi_auditor
    return get_wifi_auditor()

@wifi_audit_bp.route('/')
@login_required
def index():
    return render_template('wifi_audit.html')

@wifi_audit_bp.route('/tools')
@login_required
def tools_status():
    return jsonify(_get_auditor().get_tools_status())

@wifi_audit_bp.route('/interfaces')
@login_required
def interfaces():
    return jsonify(_get_auditor().get_interfaces())

@wifi_audit_bp.route('/monitor/enable', methods=['POST'])
@login_required
def monitor_enable():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().enable_monitor(data.get('interface', '')))

@wifi_audit_bp.route('/monitor/disable', methods=['POST'])
@login_required
def monitor_disable():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().disable_monitor(data.get('interface')))

@wifi_audit_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().scan_networks(
        interface=data.get('interface'),
        duration=data.get('duration', 15)
    ))

@wifi_audit_bp.route('/scan/results')
@login_required
def scan_results():
    return jsonify(_get_auditor().get_scan_results())

@wifi_audit_bp.route('/deauth', methods=['POST'])
@login_required
def deauth():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().deauth(
        interface=data.get('interface'),
        bssid=data.get('bssid', ''),
        client=data.get('client'),
        count=data.get('count', 10)
    ))

@wifi_audit_bp.route('/handshake', methods=['POST'])
@login_required
def capture_handshake():
    data = request.get_json(silent=True) or {}
    a = _get_auditor()
    job_id = a.capture_handshake(
        interface=data.get('interface', a.monitor_interface or ''),
        bssid=data.get('bssid', ''),
        channel=data.get('channel', 1),
        deauth_count=data.get('deauth_count', 5),
        timeout=data.get('timeout', 60)
    )
    return jsonify({'ok': True, 'job_id': job_id})

@wifi_audit_bp.route('/crack', methods=['POST'])
@login_required
def crack():
    data = request.get_json(silent=True) or {}
    job_id = _get_auditor().crack_handshake(
        data.get('capture_file', ''), data.get('wordlist', ''), data.get('bssid')
    )
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@wifi_audit_bp.route('/wps/scan', methods=['POST'])
@login_required
def wps_scan():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().wps_scan(data.get('interface')))

@wifi_audit_bp.route('/wps/attack', methods=['POST'])
@login_required
def wps_attack():
    data = request.get_json(silent=True) or {}
    a = _get_auditor()
    job_id = a.wps_attack(
        interface=data.get('interface', a.monitor_interface or ''),
        bssid=data.get('bssid', ''),
        channel=data.get('channel', 1),
        pixie_dust=data.get('pixie_dust', True)
    )
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@wifi_audit_bp.route('/rogue/save', methods=['POST'])
@login_required
def rogue_save():
    return jsonify(_get_auditor().save_known_aps())

@wifi_audit_bp.route('/rogue/detect')
@login_required
def rogue_detect():
    return jsonify(_get_auditor().detect_rogue_aps())

@wifi_audit_bp.route('/capture/start', methods=['POST'])
@login_required
def capture_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_auditor().start_capture(
        data.get('interface'), data.get('channel'), data.get('bssid'), data.get('name')
    ))

@wifi_audit_bp.route('/capture/stop', methods=['POST'])
@login_required
def capture_stop():
    return jsonify(_get_auditor().stop_capture())

@wifi_audit_bp.route('/captures')
@login_required
def captures_list():
    return jsonify(_get_auditor().list_captures())

@wifi_audit_bp.route('/job/<job_id>')
@login_required
def job_status(job_id):
    job = _get_auditor().get_job(job_id)
    return jsonify(job or {'error': 'Job not found'})
