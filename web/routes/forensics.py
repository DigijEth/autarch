"""Forensics Toolkit routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

forensics_bp = Blueprint('forensics', __name__, url_prefix='/forensics')

def _get_engine():
    from modules.forensics import get_forensics
    return get_forensics()

@forensics_bp.route('/')
@login_required
def index():
    return render_template('forensics.html')

@forensics_bp.route('/hash', methods=['POST'])
@login_required
def hash_file():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().hash_file(data.get('file', ''), data.get('algorithms')))

@forensics_bp.route('/verify', methods=['POST'])
@login_required
def verify_hash():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().verify_hash(
        data.get('file', ''), data.get('hash', ''), data.get('algorithm')
    ))

@forensics_bp.route('/image', methods=['POST'])
@login_required
def create_image():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().create_image(data.get('source', ''), data.get('output')))

@forensics_bp.route('/carve', methods=['POST'])
@login_required
def carve_files():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().carve_files(
        data.get('source', ''), data.get('file_types'), data.get('max_files', 100)
    ))

@forensics_bp.route('/metadata', methods=['POST'])
@login_required
def extract_metadata():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().extract_metadata(data.get('file', '')))

@forensics_bp.route('/timeline', methods=['POST'])
@login_required
def build_timeline():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().build_timeline(
        data.get('directory', ''), data.get('recursive', True), data.get('max_entries', 10000)
    ))

@forensics_bp.route('/evidence')
@login_required
def list_evidence():
    return jsonify(_get_engine().list_evidence())

@forensics_bp.route('/carved')
@login_required
def list_carved():
    return jsonify(_get_engine().list_carved())

@forensics_bp.route('/custody')
@login_required
def custody_log():
    return jsonify(_get_engine().get_custody_log())
