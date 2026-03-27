"""Starlink Terminal Security Analysis routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

starlink_hack_bp = Blueprint('starlink_hack', __name__, url_prefix='/starlink-hack')

_mgr = None


def _get_mgr():
    global _mgr
    if _mgr is None:
        from modules.starlink_hack import get_starlink_hack
        _mgr = get_starlink_hack()
    return _mgr


@starlink_hack_bp.route('/')
@login_required
def index():
    return render_template('starlink_hack.html')


@starlink_hack_bp.route('/status')
@login_required
def status():
    return jsonify(_get_mgr().get_status())


@starlink_hack_bp.route('/discover', methods=['POST'])
@login_required
def discover():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip')
    return jsonify(_get_mgr().discover_dish(ip=ip))


@starlink_hack_bp.route('/dish-status')
@login_required
def dish_status():
    return jsonify(_get_mgr().get_dish_status())


@starlink_hack_bp.route('/dish-info')
@login_required
def dish_info():
    return jsonify(_get_mgr().get_dish_info())


@starlink_hack_bp.route('/network')
@login_required
def network():
    return jsonify(_get_mgr().get_network_info())


@starlink_hack_bp.route('/scan-ports', methods=['POST'])
@login_required
def scan_ports():
    data = request.get_json(silent=True) or {}
    target = data.get('target')
    return jsonify(_get_mgr().scan_dish_ports(target=target))


@starlink_hack_bp.route('/grpc/enumerate', methods=['POST'])
@login_required
def grpc_enumerate():
    data = request.get_json(silent=True) or {}
    host = data.get('host')
    port = int(data['port']) if data.get('port') else None
    return jsonify(_get_mgr().grpc_enumerate(host=host, port=port))


@starlink_hack_bp.route('/grpc/call', methods=['POST'])
@login_required
def grpc_call():
    data = request.get_json(silent=True) or {}
    method = data.get('method', '')
    params = data.get('params')
    if not method:
        return jsonify({'ok': False, 'error': 'method is required'})
    return jsonify(_get_mgr().grpc_call(method, params))


@starlink_hack_bp.route('/grpc/stow', methods=['POST'])
@login_required
def grpc_stow():
    return jsonify(_get_mgr().stow_dish())


@starlink_hack_bp.route('/grpc/unstow', methods=['POST'])
@login_required
def grpc_unstow():
    return jsonify(_get_mgr().unstow_dish())


@starlink_hack_bp.route('/grpc/reboot', methods=['POST'])
@login_required
def grpc_reboot():
    return jsonify(_get_mgr().reboot_dish())


@starlink_hack_bp.route('/grpc/factory-reset', methods=['POST'])
@login_required
def grpc_factory_reset():
    data = request.get_json(silent=True) or {}
    confirm = data.get('confirm', False)
    return jsonify(_get_mgr().factory_reset(confirm=confirm))


@starlink_hack_bp.route('/firmware/check', methods=['POST'])
@login_required
def firmware_check():
    return jsonify(_get_mgr().check_firmware_version())


@starlink_hack_bp.route('/firmware/analyze', methods=['POST'])
@login_required
def firmware_analyze():
    import os
    from flask import current_app
    if 'file' in request.files:
        f = request.files['file']
        if f.filename:
            upload_dir = current_app.config.get('UPLOAD_FOLDER', '/tmp')
            save_path = os.path.join(upload_dir, f.filename)
            f.save(save_path)
            return jsonify(_get_mgr().analyze_firmware(save_path))
    data = request.get_json(silent=True) or {}
    fw_path = data.get('path', '')
    if not fw_path:
        return jsonify({'ok': False, 'error': 'No firmware file provided'})
    return jsonify(_get_mgr().analyze_firmware(fw_path))


@starlink_hack_bp.route('/firmware/debug', methods=['POST'])
@login_required
def firmware_debug():
    return jsonify(_get_mgr().find_debug_interfaces())


@starlink_hack_bp.route('/firmware/dump', methods=['POST'])
@login_required
def firmware_dump():
    data = request.get_json(silent=True) or {}
    output_path = data.get('output_path')
    return jsonify(_get_mgr().dump_firmware(output_path=output_path))


@starlink_hack_bp.route('/network/intercept', methods=['POST'])
@login_required
def network_intercept():
    data = request.get_json(silent=True) or {}
    target_ip = data.get('target_ip')
    interface = data.get('interface')
    return jsonify(_get_mgr().intercept_traffic(target_ip=target_ip, interface=interface))


@starlink_hack_bp.route('/network/intercept/stop', methods=['POST'])
@login_required
def network_intercept_stop():
    return jsonify(_get_mgr().stop_intercept())


@starlink_hack_bp.route('/network/dns-spoof', methods=['POST'])
@login_required
def network_dns_spoof():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '')
    ip = data.get('ip', '')
    interface = data.get('interface')
    if not domain or not ip:
        return jsonify({'ok': False, 'error': 'domain and ip are required'})
    return jsonify(_get_mgr().dns_spoof(domain, ip, interface=interface))


@starlink_hack_bp.route('/network/dns-spoof/stop', methods=['POST'])
@login_required
def network_dns_spoof_stop():
    return jsonify(_get_mgr().stop_dns_spoof())


@starlink_hack_bp.route('/network/mitm', methods=['POST'])
@login_required
def network_mitm():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface')
    return jsonify(_get_mgr().mitm_clients(interface=interface))


@starlink_hack_bp.route('/network/deauth', methods=['POST'])
@login_required
def network_deauth():
    data = request.get_json(silent=True) or {}
    target_mac = data.get('target_mac')
    interface = data.get('interface')
    return jsonify(_get_mgr().deauth_clients(target_mac=target_mac, interface=interface))


@starlink_hack_bp.route('/rf/downlink', methods=['POST'])
@login_required
def rf_downlink():
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 30))
    device = data.get('device', 'hackrf')
    return jsonify(_get_mgr().analyze_downlink(duration=duration, device=device))


@starlink_hack_bp.route('/rf/uplink', methods=['POST'])
@login_required
def rf_uplink():
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 30))
    return jsonify(_get_mgr().analyze_uplink(duration=duration))


@starlink_hack_bp.route('/rf/jamming', methods=['POST'])
@login_required
def rf_jamming():
    return jsonify(_get_mgr().detect_jamming())


@starlink_hack_bp.route('/cves')
@login_required
def cves():
    return jsonify(_get_mgr().check_known_cves())


@starlink_hack_bp.route('/exploits')
@login_required
def exploits():
    return jsonify(_get_mgr().get_exploit_database())


@starlink_hack_bp.route('/export', methods=['POST'])
@login_required
def export():
    data = request.get_json(silent=True) or {}
    path = data.get('path')
    return jsonify(_get_mgr().export_results(path=path))
