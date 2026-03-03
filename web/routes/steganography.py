"""Steganography routes."""
import os
import base64
from flask import Blueprint, request, jsonify, render_template, current_app
from web.routes.auth_routes import login_required

steganography_bp = Blueprint('steganography', __name__, url_prefix='/stego')

def _get_mgr():
    from modules.steganography import get_stego_manager
    return get_stego_manager()

@steganography_bp.route('/')
@login_required
def index():
    return render_template('steganography.html')

@steganography_bp.route('/capabilities')
@login_required
def capabilities():
    return jsonify(_get_mgr().get_capabilities())

@steganography_bp.route('/capacity', methods=['POST'])
@login_required
def capacity():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().capacity(data.get('file', '')))

@steganography_bp.route('/hide', methods=['POST'])
@login_required
def hide():
    mgr = _get_mgr()
    # Support file upload or path-based
    if request.content_type and 'multipart' in request.content_type:
        carrier = request.files.get('carrier')
        if not carrier:
            return jsonify({'ok': False, 'error': 'No carrier file'})
        upload_dir = current_app.config.get('UPLOAD_FOLDER', '/tmp')
        carrier_path = os.path.join(upload_dir, carrier.filename)
        carrier.save(carrier_path)
        message = request.form.get('message', '')
        password = request.form.get('password') or None
        output_path = os.path.join(upload_dir, f'stego_{carrier.filename}')
        result = mgr.hide(carrier_path, message.encode(), output_path, password)
    else:
        data = request.get_json(silent=True) or {}
        carrier_path = data.get('carrier', '')
        message = data.get('message', '')
        password = data.get('password') or None
        output = data.get('output')
        result = mgr.hide(carrier_path, message.encode(), output, password)
    return jsonify(result)

@steganography_bp.route('/extract', methods=['POST'])
@login_required
def extract():
    data = request.get_json(silent=True) or {}
    result = _get_mgr().extract(data.get('file', ''), data.get('password'))
    if result.get('ok') and 'data' in result:
        try:
            result['text'] = result['data'].decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            result['base64'] = base64.b64encode(result['data']).decode()
        del result['data']  # Don't send raw bytes in JSON
    return jsonify(result)

@steganography_bp.route('/detect', methods=['POST'])
@login_required
def detect():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().detect(data.get('file', '')))

@steganography_bp.route('/whitespace/hide', methods=['POST'])
@login_required
def whitespace_hide():
    data = request.get_json(silent=True) or {}
    from modules.steganography import DocumentStego
    result = DocumentStego.hide_whitespace(
        data.get('text', ''), data.get('message', '').encode(),
        data.get('password')
    )
    return jsonify(result)

@steganography_bp.route('/whitespace/extract', methods=['POST'])
@login_required
def whitespace_extract():
    data = request.get_json(silent=True) or {}
    from modules.steganography import DocumentStego
    result = DocumentStego.extract_whitespace(data.get('text', ''), data.get('password'))
    if result.get('ok') and 'data' in result:
        try:
            result['text'] = result['data'].decode('utf-8')
        except (UnicodeDecodeError, AttributeError):
            result['base64'] = base64.b64encode(result['data']).decode()
        del result['data']
    return jsonify(result)
