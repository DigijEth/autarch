"""C2 Framework — web routes for command & control."""

from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

c2_framework_bp = Blueprint('c2_framework', __name__)


def _svc():
    from modules.c2_framework import get_c2_server
    return get_c2_server()


@c2_framework_bp.route('/c2/')
@login_required
def index():
    return render_template('c2_framework.html')


# ── Listeners ─────────────────────────────────────────────────────────────────

@c2_framework_bp.route('/c2/listeners', methods=['GET'])
@login_required
def list_listeners():
    return jsonify({'ok': True, 'listeners': _svc().list_listeners()})


@c2_framework_bp.route('/c2/listeners', methods=['POST'])
@login_required
def start_listener():
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().start_listener(
        name=data.get('name', 'default'),
        host=data.get('host', '0.0.0.0'),
        port=data.get('port', 4444),
    ))


@c2_framework_bp.route('/c2/listeners/<name>', methods=['DELETE'])
@login_required
def stop_listener(name):
    return jsonify(_svc().stop_listener(name))


# ── Agents ────────────────────────────────────────────────────────────────────

@c2_framework_bp.route('/c2/agents', methods=['GET'])
@login_required
def list_agents():
    return jsonify({'ok': True, 'agents': _svc().list_agents()})


@c2_framework_bp.route('/c2/agents/<agent_id>', methods=['DELETE'])
@login_required
def remove_agent(agent_id):
    return jsonify(_svc().remove_agent(agent_id))


# ── Tasks ─────────────────────────────────────────────────────────────────────

@c2_framework_bp.route('/c2/agents/<agent_id>/exec', methods=['POST'])
@login_required
def exec_command(agent_id):
    data = request.get_json(silent=True) or {}
    command = data.get('command', '')
    if not command:
        return jsonify({'ok': False, 'error': 'No command'})
    return jsonify(_svc().execute_command(agent_id, command))


@c2_framework_bp.route('/c2/agents/<agent_id>/download', methods=['POST'])
@login_required
def download_file(agent_id):
    data = request.get_json(silent=True) or {}
    path = data.get('path', '')
    if not path:
        return jsonify({'ok': False, 'error': 'No path'})
    return jsonify(_svc().download_file(agent_id, path))


@c2_framework_bp.route('/c2/agents/<agent_id>/upload', methods=['POST'])
@login_required
def upload_file(agent_id):
    f = request.files.get('file')
    data = request.form
    path = data.get('path', '')
    if not f or not path:
        return jsonify({'ok': False, 'error': 'File and path required'})
    return jsonify(_svc().upload_file(agent_id, path, f.read()))


@c2_framework_bp.route('/c2/tasks/<task_id>', methods=['GET'])
@login_required
def task_result(task_id):
    return jsonify(_svc().get_task_result(task_id))


@c2_framework_bp.route('/c2/tasks', methods=['GET'])
@login_required
def list_tasks():
    agent_id = request.args.get('agent_id', '')
    return jsonify({'ok': True, 'tasks': _svc().list_tasks(agent_id)})


# ── Agent Generation ──────────────────────────────────────────────────────────

@c2_framework_bp.route('/c2/generate', methods=['POST'])
@login_required
def generate_agent():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'ok': False, 'error': 'Callback host required'})
    result = _svc().generate_agent(
        host=host,
        port=data.get('port', 4444),
        agent_type=data.get('type', 'python'),
        interval=data.get('interval', 5),
        jitter=data.get('jitter', 2),
    )
    # Don't send filepath in API response
    result.pop('filepath', None)
    return jsonify(result)


@c2_framework_bp.route('/c2/oneliner', methods=['POST'])
@login_required
def get_oneliner():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'ok': False, 'error': 'Host required'})
    return jsonify(_svc().get_oneliner(host, data.get('port', 4444),
                                        data.get('type', 'python')))
