"""BLE Scanner routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

ble_scanner_bp = Blueprint('ble_scanner', __name__, url_prefix='/ble')

def _get_scanner():
    from modules.ble_scanner import get_ble_scanner
    return get_ble_scanner()

@ble_scanner_bp.route('/')
@login_required
def index():
    return render_template('ble_scanner.html')

@ble_scanner_bp.route('/status')
@login_required
def status():
    return jsonify(_get_scanner().get_status())

@ble_scanner_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().scan(data.get('duration', 10.0)))

@ble_scanner_bp.route('/devices')
@login_required
def devices():
    return jsonify(_get_scanner().get_devices())

@ble_scanner_bp.route('/device/<address>')
@login_required
def device_detail(address):
    return jsonify(_get_scanner().get_device_detail(address))

@ble_scanner_bp.route('/read', methods=['POST'])
@login_required
def read_char():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().read_characteristic(data.get('address', ''), data.get('uuid', '')))

@ble_scanner_bp.route('/write', methods=['POST'])
@login_required
def write_char():
    data = request.get_json(silent=True) or {}
    value = bytes.fromhex(data.get('data_hex', '')) if data.get('data_hex') else data.get('data', '').encode()
    return jsonify(_get_scanner().write_characteristic(data.get('address', ''), data.get('uuid', ''), value))

@ble_scanner_bp.route('/vulnscan', methods=['POST'])
@login_required
def vuln_scan():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().vuln_scan(data.get('address')))

@ble_scanner_bp.route('/track', methods=['POST'])
@login_required
def track():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().track_device(data.get('address', '')))

@ble_scanner_bp.route('/track/<address>/history')
@login_required
def tracking_history(address):
    return jsonify(_get_scanner().get_tracking_history(address))

@ble_scanner_bp.route('/scan/save', methods=['POST'])
@login_required
def save_scan():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().save_scan(data.get('name')))

@ble_scanner_bp.route('/scans')
@login_required
def list_scans():
    return jsonify(_get_scanner().list_scans())
