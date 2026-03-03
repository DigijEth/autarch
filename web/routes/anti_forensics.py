"""Anti-Forensics routes."""
from flask import Blueprint, request, jsonify, render_template
from web.routes.auth_routes import login_required

anti_forensics_bp = Blueprint('anti_forensics', __name__, url_prefix='/anti-forensics')

def _get_mgr():
    from modules.anti_forensics import get_anti_forensics
    return get_anti_forensics()

@anti_forensics_bp.route('/')
@login_required
def index():
    return render_template('anti_forensics.html')

@anti_forensics_bp.route('/capabilities')
@login_required
def capabilities():
    return jsonify(_get_mgr().get_capabilities())

@anti_forensics_bp.route('/delete/file', methods=['POST'])
@login_required
def delete_file():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().delete.secure_delete_file(
        data.get('path', ''), data.get('passes', 3), data.get('method', 'random')
    ))

@anti_forensics_bp.route('/delete/directory', methods=['POST'])
@login_required
def delete_directory():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().delete.secure_delete_directory(
        data.get('path', ''), data.get('passes', 3)
    ))

@anti_forensics_bp.route('/wipe', methods=['POST'])
@login_required
def wipe_free_space():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().delete.wipe_free_space(data.get('mount_point', '')))

@anti_forensics_bp.route('/timestamps', methods=['GET', 'POST'])
@login_required
def timestamps():
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return jsonify(_get_mgr().timestamps.set_timestamps(
            data.get('path', ''), data.get('accessed'), data.get('modified')
        ))
    return jsonify(_get_mgr().timestamps.get_timestamps(request.args.get('path', '')))

@anti_forensics_bp.route('/timestamps/clone', methods=['POST'])
@login_required
def clone_timestamps():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().timestamps.clone_timestamps(data.get('source', ''), data.get('target', '')))

@anti_forensics_bp.route('/timestamps/randomize', methods=['POST'])
@login_required
def randomize_timestamps():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().timestamps.randomize_timestamps(data.get('path', '')))

@anti_forensics_bp.route('/logs')
@login_required
def list_logs():
    return jsonify(_get_mgr().logs.list_logs())

@anti_forensics_bp.route('/logs/clear', methods=['POST'])
@login_required
def clear_log():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().logs.clear_log(data.get('path', '')))

@anti_forensics_bp.route('/logs/remove', methods=['POST'])
@login_required
def remove_entries():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().logs.remove_entries(data.get('path', ''), data.get('pattern', '')))

@anti_forensics_bp.route('/logs/history', methods=['POST'])
@login_required
def clear_history():
    return jsonify(_get_mgr().logs.clear_bash_history())

@anti_forensics_bp.route('/scrub/image', methods=['POST'])
@login_required
def scrub_image():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().scrubber.scrub_image(data.get('path', ''), data.get('output')))

@anti_forensics_bp.route('/scrub/pdf', methods=['POST'])
@login_required
def scrub_pdf():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_mgr().scrubber.scrub_pdf_metadata(data.get('path', '')))
