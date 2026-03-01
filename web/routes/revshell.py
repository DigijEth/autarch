"""Reverse Shell routes — listener management, session control, command execution."""

import base64
import io
from flask import Blueprint, render_template, request, jsonify, send_file, Response
from web.auth import login_required

revshell_bp = Blueprint('revshell', __name__, url_prefix='/revshell')


def _listener():
    from core.revshell import get_listener
    return get_listener()


def _json():
    return request.get_json(silent=True) or {}


# ── Main Page ────────────────────────────────────────────────────────

@revshell_bp.route('/')
@login_required
def index():
    listener = _listener()
    return render_template('revshell.html',
                           running=listener.running,
                           token=listener.auth_token,
                           port=listener.port,
                           sessions=listener.list_sessions())


# ── Listener Control ─────────────────────────────────────────────────

@revshell_bp.route('/listener/start', methods=['POST'])
@login_required
def listener_start():
    data = _json()
    port = data.get('port', 17322)
    token = data.get('token', None)
    host = data.get('host', '0.0.0.0')

    from core.revshell import start_listener
    ok, msg = start_listener(host=host, port=int(port), token=token)
    return jsonify({'success': ok, 'message': msg, 'token': _listener().auth_token})


@revshell_bp.route('/listener/stop', methods=['POST'])
@login_required
def listener_stop():
    from core.revshell import stop_listener
    stop_listener()
    return jsonify({'success': True, 'message': 'Listener stopped'})


@revshell_bp.route('/listener/status', methods=['POST'])
@login_required
def listener_status():
    listener = _listener()
    return jsonify({
        'running': listener.running,
        'port': listener.port,
        'token': listener.auth_token,
        'host': listener.host,
        'session_count': len(listener.active_sessions),
    })


# ── Sessions ─────────────────────────────────────────────────────────

@revshell_bp.route('/sessions', methods=['POST'])
@login_required
def list_sessions():
    return jsonify({'sessions': _listener().list_sessions()})


@revshell_bp.route('/session/<sid>/disconnect', methods=['POST'])
@login_required
def disconnect_session(sid):
    _listener().remove_session(sid)
    return jsonify({'success': True, 'message': f'Session {sid} disconnected'})


@revshell_bp.route('/session/<sid>/info', methods=['POST'])
@login_required
def session_info(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    return jsonify({'success': True, 'session': session.to_dict()})


# ── Command Execution ────────────────────────────────────────────────

@revshell_bp.route('/session/<sid>/execute', methods=['POST'])
@login_required
def execute_command(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})

    data = _json()
    cmd = data.get('cmd', '')
    timeout = data.get('timeout', 30)

    if not cmd:
        return jsonify({'success': False, 'message': 'No command specified'})

    result = session.execute(cmd, timeout=int(timeout))
    return jsonify({
        'success': result['exit_code'] == 0,
        'stdout': result['stdout'],
        'stderr': result['stderr'],
        'exit_code': result['exit_code'],
    })


# ── Special Commands ─────────────────────────────────────────────────

@revshell_bp.route('/session/<sid>/sysinfo', methods=['POST'])
@login_required
def device_sysinfo(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    result = session.sysinfo()
    return jsonify({'success': result['exit_code'] == 0, **result})


@revshell_bp.route('/session/<sid>/packages', methods=['POST'])
@login_required
def device_packages(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    result = session.packages()
    return jsonify({'success': result['exit_code'] == 0, **result})


@revshell_bp.route('/session/<sid>/screenshot', methods=['POST'])
@login_required
def device_screenshot(sid):
    listener = _listener()
    filepath = listener.save_screenshot(sid)
    if filepath:
        return jsonify({'success': True, 'path': filepath})
    return jsonify({'success': False, 'message': 'Screenshot failed'})


@revshell_bp.route('/session/<sid>/screenshot/view', methods=['GET'])
@login_required
def view_screenshot(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return 'Session not found', 404
    png_data = session.screenshot()
    if not png_data:
        return 'Screenshot failed', 500
    return send_file(io.BytesIO(png_data), mimetype='image/png',
                     download_name=f'screenshot_{sid}.png')


@revshell_bp.route('/session/<sid>/processes', methods=['POST'])
@login_required
def device_processes(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    result = session.processes()
    return jsonify({'success': result['exit_code'] == 0, **result})


@revshell_bp.route('/session/<sid>/netstat', methods=['POST'])
@login_required
def device_netstat(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    result = session.netstat()
    return jsonify({'success': result['exit_code'] == 0, **result})


@revshell_bp.route('/session/<sid>/logcat', methods=['POST'])
@login_required
def device_logcat(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})
    data = _json()
    lines = data.get('lines', 100)
    result = session.dumplog(lines=int(lines))
    return jsonify({'success': result['exit_code'] == 0, **result})


@revshell_bp.route('/session/<sid>/download', methods=['POST'])
@login_required
def download_file(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})

    data = _json()
    remote_path = data.get('path', '')
    if not remote_path:
        return jsonify({'success': False, 'message': 'No path specified'})

    filepath = _listener().save_download(sid, remote_path)
    if filepath:
        return jsonify({'success': True, 'path': filepath})
    return jsonify({'success': False, 'message': 'Download failed'})


@revshell_bp.route('/session/<sid>/upload', methods=['POST'])
@login_required
def upload_file(sid):
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return jsonify({'success': False, 'message': 'Session not found or dead'})

    remote_path = request.form.get('path', '')
    if not remote_path:
        return jsonify({'success': False, 'message': 'No remote path specified'})

    uploaded = request.files.get('file')
    if not uploaded:
        return jsonify({'success': False, 'message': 'No file uploaded'})

    # Save temp, upload, cleanup
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        uploaded.save(tmp.name)
        result = session.upload(tmp.name, remote_path)
        return jsonify({
            'success': result['exit_code'] == 0,
            'stdout': result['stdout'],
            'stderr': result['stderr'],
        })
    finally:
        try:
            import os
            os.unlink(tmp.name)
        except Exception:
            pass


# ── SSE Stream for Interactive Shell ─────────────────────────────────

@revshell_bp.route('/session/<sid>/stream')
@login_required
def shell_stream(sid):
    """SSE endpoint for streaming command output."""
    session = _listener().get_session(sid)
    if not session or not session.alive:
        return 'Session not found', 404

    def generate():
        yield f"data: {jsonify_str({'type': 'connected', 'session': session.to_dict()})}\n\n"
        # The stream stays open; the client sends commands via POST /execute
        # and reads results. This SSE is mainly for status updates.
        while session.alive:
            import time
            time.sleep(5)
            yield f"data: {jsonify_str({'type': 'heartbeat', 'alive': session.alive, 'uptime': int(session.uptime)})}\n\n"
        yield f"data: {jsonify_str({'type': 'disconnected'})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


def jsonify_str(obj):
    """JSON serialize without Flask response wrapper."""
    import json
    return json.dumps(obj)
