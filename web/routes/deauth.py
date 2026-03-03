"""Deauth Attack routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

deauth_bp = Blueprint('deauth', __name__, url_prefix='/deauth')


def _get_deauth():
    from modules.deauth import get_deauth
    return get_deauth()


@deauth_bp.route('/')
@login_required
def index():
    return render_template('deauth.html')


@deauth_bp.route('/interfaces')
@login_required
def interfaces():
    return jsonify({'interfaces': _get_deauth().get_interfaces()})


@deauth_bp.route('/monitor/start', methods=['POST'])
@login_required
def monitor_start():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', '').strip()
    return jsonify(_get_deauth().enable_monitor(interface))


@deauth_bp.route('/monitor/stop', methods=['POST'])
@login_required
def monitor_stop():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', '').strip()
    return jsonify(_get_deauth().disable_monitor(interface))


@deauth_bp.route('/scan/networks', methods=['POST'])
@login_required
def scan_networks():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', '').strip()
    duration = int(data.get('duration', 10))
    networks = _get_deauth().scan_networks(interface, duration)
    return jsonify({'networks': networks, 'total': len(networks)})


@deauth_bp.route('/scan/clients', methods=['POST'])
@login_required
def scan_clients():
    data = request.get_json(silent=True) or {}
    interface = data.get('interface', '').strip()
    target_bssid = data.get('target_bssid', '').strip() or None
    duration = int(data.get('duration', 10))
    clients = _get_deauth().scan_clients(interface, target_bssid, duration)
    return jsonify({'clients': clients, 'total': len(clients)})


@deauth_bp.route('/attack/targeted', methods=['POST'])
@login_required
def attack_targeted():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_deauth().deauth_targeted(
        interface=data.get('interface', '').strip(),
        target_bssid=data.get('bssid', '').strip(),
        client_mac=data.get('client', '').strip(),
        count=int(data.get('count', 10)),
        interval=float(data.get('interval', 0.1))
    ))


@deauth_bp.route('/attack/broadcast', methods=['POST'])
@login_required
def attack_broadcast():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_deauth().deauth_broadcast(
        interface=data.get('interface', '').strip(),
        target_bssid=data.get('bssid', '').strip(),
        count=int(data.get('count', 10)),
        interval=float(data.get('interval', 0.1))
    ))


@deauth_bp.route('/attack/multi', methods=['POST'])
@login_required
def attack_multi():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_deauth().deauth_multi(
        interface=data.get('interface', '').strip(),
        targets=data.get('targets', []),
        count=int(data.get('count', 10)),
        interval=float(data.get('interval', 0.1))
    ))


@deauth_bp.route('/attack/continuous/start', methods=['POST'])
@login_required
def attack_continuous_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_deauth().start_continuous(
        interface=data.get('interface', '').strip(),
        target_bssid=data.get('bssid', '').strip(),
        client_mac=data.get('client', '').strip() or None,
        interval=float(data.get('interval', 0.5)),
        burst=int(data.get('burst', 5))
    ))


@deauth_bp.route('/attack/continuous/stop', methods=['POST'])
@login_required
def attack_continuous_stop():
    return jsonify(_get_deauth().stop_continuous())


@deauth_bp.route('/attack/status')
@login_required
def attack_status():
    return jsonify(_get_deauth().get_attack_status())


@deauth_bp.route('/history')
@login_required
def history():
    return jsonify({'history': _get_deauth().get_attack_history()})


@deauth_bp.route('/history', methods=['DELETE'])
@login_required
def history_clear():
    return jsonify(_get_deauth().clear_history())
