"""RFID/NFC Tools routes."""
from flask import Blueprint, request, jsonify, render_template
from web.routes.auth_routes import login_required

rfid_tools_bp = Blueprint('rfid_tools', __name__, url_prefix='/rfid')

def _get_mgr():
    from modules.rfid_tools import get_rfid_manager
    return get_rfid_manager()

@rfid_tools_bp.route('/')
@login_required
def index():
    return render_template('rfid_tools.html')

@rfid_tools_bp.route('/tools')
@login_required
def tools_status():
    return jsonify(_get_mgr().get_tools_status())

@rfid_tools_bp.route('/lf/search', methods=['POST'])
@login_required
def lf_search():
    return jsonify(_get_mgr().lf_search())

@rfid_tools_bp.route('/lf/read/em410x', methods=['POST'])
@login_required
def lf_read_em():
    return jsonify(_get_mgr().lf_read_em410x())

@rfid_tools_bp.route('/lf/clone', methods=['POST'])
@login_required
def lf_clone():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().lf_clone_em410x(data.get('card_id', '')))

@rfid_tools_bp.route('/lf/sim', methods=['POST'])
@login_required
def lf_sim():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().lf_sim_em410x(data.get('card_id', '')))

@rfid_tools_bp.route('/hf/search', methods=['POST'])
@login_required
def hf_search():
    return jsonify(_get_mgr().hf_search())

@rfid_tools_bp.route('/hf/dump', methods=['POST'])
@login_required
def hf_dump():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().hf_dump_mifare(data.get('keys_file')))

@rfid_tools_bp.route('/hf/clone', methods=['POST'])
@login_required
def hf_clone():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().hf_clone_mifare(data.get('dump_file', '')))

@rfid_tools_bp.route('/nfc/scan', methods=['POST'])
@login_required
def nfc_scan():
    return jsonify(_get_mgr().nfc_scan())

@rfid_tools_bp.route('/cards', methods=['GET', 'POST', 'DELETE'])
@login_required
def cards():
    mgr = _get_mgr()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return jsonify(mgr.save_card(data.get('card', {}), data.get('name')))
    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        return jsonify(mgr.delete_card(data.get('index', -1)))
    return jsonify(mgr.get_saved_cards())

@rfid_tools_bp.route('/dumps')
@login_required
def dumps():
    return jsonify(_get_mgr().list_dumps())

@rfid_tools_bp.route('/keys')
@login_required
def default_keys():
    return jsonify(_get_mgr().get_default_keys())

@rfid_tools_bp.route('/types')
@login_required
def card_types():
    return jsonify(_get_mgr().get_card_types())
