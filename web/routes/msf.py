"""MSF RPC Console page — raw console interaction and connection management."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

msf_bp = Blueprint('msf', __name__, url_prefix='/msf')


@msf_bp.route('/')
@login_required
def index():
    return render_template('msf.html')


@msf_bp.route('/status')
@login_required
def status():
    """Check MSF connection status."""
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        result = {'connected': msf.is_connected}
        if msf.is_connected:
            try:
                settings = msf.manager.get_settings()
                result['host'] = settings.get('host', 'localhost')
                result['port'] = settings.get('port', 55553)
            except Exception:
                pass
        return jsonify(result)
    except Exception:
        return jsonify({'connected': False})


@msf_bp.route('/connect', methods=['POST'])
@login_required
def connect():
    """Reconnect to MSF RPC."""
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        ok, msg = msf.ensure_connected()
        return jsonify({'connected': ok, 'message': msg})
    except Exception as e:
        return jsonify({'connected': False, 'error': str(e)})


@msf_bp.route('/console/send', methods=['POST'])
@login_required
def console_send():
    """Send a command to the MSF console and return output."""
    data = request.get_json(silent=True) or {}
    cmd = data.get('cmd', '').strip()
    if not cmd:
        return jsonify({'output': ''})
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        if not msf.is_connected:
            return jsonify({'error': 'Not connected to MSF RPC'})
        ok, output = msf.run_console_command(cmd)
        return jsonify({'output': output, 'ok': ok})
    except Exception as e:
        return jsonify({'error': str(e)})
