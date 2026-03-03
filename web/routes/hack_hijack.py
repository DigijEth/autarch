"""Hack Hijack — web routes for scanning and taking over compromised systems."""

import threading
import uuid
from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

hack_hijack_bp = Blueprint('hack_hijack', __name__)

# Running scans keyed by job_id
_running_scans: dict = {}


def _svc():
    from modules.hack_hijack import get_hack_hijack
    return get_hack_hijack()


# ── UI ────────────────────────────────────────────────────────────────────────

@hack_hijack_bp.route('/hack-hijack/')
@login_required
def index():
    return render_template('hack_hijack.html')


# ── Scanning ──────────────────────────────────────────────────────────────────

@hack_hijack_bp.route('/hack-hijack/scan', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    scan_type = data.get('scan_type', 'quick')
    custom_ports = data.get('custom_ports', [])

    if not target:
        return jsonify({'ok': False, 'error': 'Target IP required'})

    # Validate scan type
    if scan_type not in ('quick', 'full', 'nmap', 'custom'):
        scan_type = 'quick'

    job_id = str(uuid.uuid4())[:8]
    result_holder = {'result': None, 'error': None, 'done': False}
    _running_scans[job_id] = result_holder

    def do_scan():
        try:
            svc = _svc()
            r = svc.scan_target(
                target,
                scan_type=scan_type,
                custom_ports=custom_ports,
                timeout=3.0,
            )
            result_holder['result'] = r.to_dict()
        except Exception as e:
            result_holder['error'] = str(e)
        finally:
            result_holder['done'] = True

    threading.Thread(target=do_scan, daemon=True).start()
    return jsonify({'ok': True, 'job_id': job_id,
                    'message': f'Scan started on {target} ({scan_type})'})


@hack_hijack_bp.route('/hack-hijack/scan/<job_id>', methods=['GET'])
@login_required
def scan_status(job_id):
    holder = _running_scans.get(job_id)
    if not holder:
        return jsonify({'ok': False, 'error': 'Job not found'})
    if not holder['done']:
        return jsonify({'ok': True, 'done': False, 'message': 'Scan in progress...'})
    if holder['error']:
        return jsonify({'ok': False, 'error': holder['error'], 'done': True})
    # Clean up
    _running_scans.pop(job_id, None)
    return jsonify({'ok': True, 'done': True, 'result': holder['result']})


# ── Takeover ──────────────────────────────────────────────────────────────────

@hack_hijack_bp.route('/hack-hijack/takeover', methods=['POST'])
@login_required
def attempt_takeover():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    backdoor = data.get('backdoor', {})
    if not host or not backdoor:
        return jsonify({'ok': False, 'error': 'Host and backdoor data required'})
    svc = _svc()
    result = svc.attempt_takeover(host, backdoor)
    return jsonify(result)


# ── Sessions ──────────────────────────────────────────────────────────────────

@hack_hijack_bp.route('/hack-hijack/sessions', methods=['GET'])
@login_required
def list_sessions():
    svc = _svc()
    return jsonify({'ok': True, 'sessions': svc.list_sessions()})


@hack_hijack_bp.route('/hack-hijack/sessions/<session_id>/exec', methods=['POST'])
@login_required
def shell_exec(session_id):
    data = request.get_json(silent=True) or {}
    command = data.get('command', '')
    if not command:
        return jsonify({'ok': False, 'error': 'No command provided'})
    svc = _svc()
    result = svc.shell_execute(session_id, command)
    return jsonify(result)


@hack_hijack_bp.route('/hack-hijack/sessions/<session_id>', methods=['DELETE'])
@login_required
def close_session(session_id):
    svc = _svc()
    return jsonify(svc.close_session(session_id))


# ── History ───────────────────────────────────────────────────────────────────

@hack_hijack_bp.route('/hack-hijack/history', methods=['GET'])
@login_required
def scan_history():
    svc = _svc()
    return jsonify({'ok': True, 'scans': svc.get_scan_history()})


@hack_hijack_bp.route('/hack-hijack/history', methods=['DELETE'])
@login_required
def clear_history():
    svc = _svc()
    return jsonify(svc.clear_history())
