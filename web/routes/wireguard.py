"""WireGuard VPN Manager routes — server, clients, remote ADB, USB/IP."""

from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

wireguard_bp = Blueprint('wireguard', __name__, url_prefix='/wireguard')


def _mgr():
    from core.wireguard import get_wireguard_manager
    return get_wireguard_manager()


def _json():
    """Get JSON body or empty dict."""
    return request.get_json(silent=True) or {}


# ── Main Page ────────────────────────────────────────────────────────

@wireguard_bp.route('/')
@login_required
def index():
    mgr = _mgr()
    available = mgr.is_available()
    usbip = mgr.get_usbip_status()
    return render_template('wireguard.html',
                           wg_available=available,
                           usbip_status=usbip)


# ── Server ───────────────────────────────────────────────────────────

@wireguard_bp.route('/server/status', methods=['POST'])
@login_required
def server_status():
    return jsonify(_mgr().get_server_status())


@wireguard_bp.route('/server/start', methods=['POST'])
@login_required
def server_start():
    return jsonify(_mgr().start_interface())


@wireguard_bp.route('/server/stop', methods=['POST'])
@login_required
def server_stop():
    return jsonify(_mgr().stop_interface())


@wireguard_bp.route('/server/restart', methods=['POST'])
@login_required
def server_restart():
    return jsonify(_mgr().restart_interface())


# ── Clients ──────────────────────────────────────────────────────────

@wireguard_bp.route('/clients/list', methods=['POST'])
@login_required
def clients_list():
    mgr = _mgr()
    clients = mgr.get_all_clients()
    peer_status = mgr.get_peer_status()
    # Merge peer status into client data
    for c in clients:
        ps = peer_status.get(c.get('public_key', ''), {})
        c['peer_status'] = ps
        hs = ps.get('latest_handshake')
        if hs is not None and hs < 180:
            c['online'] = True
        else:
            c['online'] = False
    return jsonify({'clients': clients, 'count': len(clients)})


@wireguard_bp.route('/clients/create', methods=['POST'])
@login_required
def clients_create():
    data = _json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Name required'})
    dns = data.get('dns', '').strip() or None
    allowed_ips = data.get('allowed_ips', '').strip() or None
    return jsonify(_mgr().create_client(name, dns=dns, allowed_ips=allowed_ips))


@wireguard_bp.route('/clients/<client_id>', methods=['POST'])
@login_required
def clients_detail(client_id):
    mgr = _mgr()
    client = mgr.get_client(client_id)
    if not client:
        return jsonify({'error': 'Client not found'})
    peer_status = mgr.get_peer_status()
    ps = peer_status.get(client.get('public_key', ''), {})
    client['peer_status'] = ps
    hs = ps.get('latest_handshake')
    client['online'] = hs is not None and hs < 180
    return jsonify(client)


@wireguard_bp.route('/clients/<client_id>/toggle', methods=['POST'])
@login_required
def clients_toggle(client_id):
    data = _json()
    enabled = data.get('enabled', True)
    return jsonify(_mgr().toggle_client(client_id, enabled))


@wireguard_bp.route('/clients/<client_id>/delete', methods=['POST'])
@login_required
def clients_delete(client_id):
    return jsonify(_mgr().delete_client(client_id))


@wireguard_bp.route('/clients/<client_id>/config', methods=['POST'])
@login_required
def clients_config(client_id):
    mgr = _mgr()
    client = mgr.get_client(client_id)
    if not client:
        return jsonify({'error': 'Client not found'})
    config_text = mgr.generate_client_config(client)
    return jsonify({'ok': True, 'config': config_text, 'name': client['name']})


@wireguard_bp.route('/clients/<client_id>/download')
@login_required
def clients_download(client_id):
    mgr = _mgr()
    client = mgr.get_client(client_id)
    if not client:
        return 'Not found', 404
    config_text = mgr.generate_client_config(client)
    filename = f"{client['name']}.conf"
    return Response(
        config_text,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename="{filename}"'})


@wireguard_bp.route('/clients/<client_id>/qr')
@login_required
def clients_qr(client_id):
    mgr = _mgr()
    client = mgr.get_client(client_id)
    if not client:
        return 'Not found', 404
    config_text = mgr.generate_client_config(client)
    png_bytes = mgr.generate_qr_code(config_text)
    if not png_bytes:
        return 'QR code generation failed (qrcode module missing?)', 500
    return Response(png_bytes, mimetype='image/png')


@wireguard_bp.route('/clients/import', methods=['POST'])
@login_required
def clients_import():
    return jsonify(_mgr().import_existing_peers())


# ── Remote ADB ───────────────────────────────────────────────────────

@wireguard_bp.route('/adb/connect', methods=['POST'])
@login_required
def adb_connect():
    data = _json()
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'})
    return jsonify(_mgr().adb_connect(ip))


@wireguard_bp.route('/adb/disconnect', methods=['POST'])
@login_required
def adb_disconnect():
    data = _json()
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'})
    return jsonify(_mgr().adb_disconnect(ip))


@wireguard_bp.route('/adb/auto-connect', methods=['POST'])
@login_required
def adb_auto_connect():
    return jsonify(_mgr().auto_connect_peers())


@wireguard_bp.route('/adb/devices', methods=['POST'])
@login_required
def adb_devices():
    devices = _mgr().get_adb_remote_devices()
    return jsonify({'devices': devices, 'count': len(devices)})


# ── USB/IP ───────────────────────────────────────────────────────────

@wireguard_bp.route('/usbip/status', methods=['POST'])
@login_required
def usbip_status():
    return jsonify(_mgr().get_usbip_status())


@wireguard_bp.route('/usbip/load-modules', methods=['POST'])
@login_required
def usbip_load_modules():
    return jsonify(_mgr().load_usbip_modules())


@wireguard_bp.route('/usbip/list-remote', methods=['POST'])
@login_required
def usbip_list_remote():
    data = _json()
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'})
    return jsonify(_mgr().usbip_list_remote(ip))


@wireguard_bp.route('/usbip/attach', methods=['POST'])
@login_required
def usbip_attach():
    data = _json()
    ip = data.get('ip', '').strip()
    busid = data.get('busid', '').strip()
    if not ip or not busid:
        return jsonify({'ok': False, 'error': 'IP and busid required'})
    return jsonify(_mgr().usbip_attach(ip, busid))


@wireguard_bp.route('/usbip/detach', methods=['POST'])
@login_required
def usbip_detach():
    data = _json()
    port = data.get('port', '').strip() if isinstance(data.get('port'), str) else str(data.get('port', ''))
    if not port:
        return jsonify({'ok': False, 'error': 'Port required'})
    return jsonify(_mgr().usbip_detach(port))


@wireguard_bp.route('/usbip/ports', methods=['POST'])
@login_required
def usbip_ports():
    return jsonify(_mgr().usbip_port_status())


# ── UPnP ─────────────────────────────────────────────────────────────

@wireguard_bp.route('/upnp/refresh', methods=['POST'])
@login_required
def upnp_refresh():
    return jsonify(_mgr().refresh_upnp_mapping())
