"""Offense category route - MSF server control, module search, sessions, browsing, execution."""

import json
import threading
import uuid
from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

_running_jobs: dict = {}  # job_id -> threading.Event (stop signal)

offense_bp = Blueprint('offense', __name__, url_prefix='/offense')


@offense_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'offense'}
    return render_template('offense.html', modules=modules)


@offense_bp.route('/status')
@login_required
def status():
    """Get MSF connection and server status."""
    try:
        from core.msf_interface import get_msf_interface
        from core.msf import get_msf_manager
        msf = get_msf_interface()
        mgr = get_msf_manager()
        connected = msf.is_connected
        settings = mgr.get_settings()

        # Check if server process is running
        server_running, server_pid = mgr.detect_server()

        result = {
            'connected': connected,
            'server_running': server_running,
            'server_pid': server_pid,
            'host': settings.get('host', '127.0.0.1'),
            'port': settings.get('port', 55553),
            'username': settings.get('username', 'msf'),
            'ssl': settings.get('ssl', True),
            'has_password': bool(settings.get('password', '')),
        }
        if connected:
            try:
                version = msf.manager.rpc.get_version()
                result['version'] = version.get('version', '')
            except Exception:
                pass

        return jsonify(result)
    except Exception as e:
        return jsonify({'connected': False, 'server_running': False, 'error': str(e)})


@offense_bp.route('/connect', methods=['POST'])
@login_required
def connect():
    """Connect to MSF RPC server."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '').strip()

    try:
        from core.msf import get_msf_manager
        mgr = get_msf_manager()
        settings = mgr.get_settings()

        # Use provided password or saved one
        pwd = password or settings.get('password', '')
        if not pwd:
            return jsonify({'ok': False, 'error': 'Password required'})

        mgr.connect(pwd)
        version = mgr.rpc.get_version() if mgr.rpc else {}
        return jsonify({
            'ok': True,
            'version': version.get('version', 'Connected')
        })
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/disconnect', methods=['POST'])
@login_required
def disconnect():
    """Disconnect from MSF RPC server."""
    try:
        from core.msf import get_msf_manager
        mgr = get_msf_manager()
        mgr.disconnect()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/server/start', methods=['POST'])
@login_required
def start_server():
    """Start the MSF RPC server."""
    data = request.get_json(silent=True) or {}

    try:
        from core.msf import get_msf_manager
        mgr = get_msf_manager()
        settings = mgr.get_settings()

        username = data.get('username', '').strip() or settings.get('username', 'msf')
        password = data.get('password', '').strip() or settings.get('password', '')
        host = data.get('host', '').strip() or settings.get('host', '127.0.0.1')
        port = int(data.get('port', 0) or settings.get('port', 55553))
        use_ssl = data.get('ssl', settings.get('ssl', True))

        if not password:
            return jsonify({'ok': False, 'error': 'Password required to start server'})

        # Save settings
        mgr.save_settings(host, port, username, password, use_ssl)

        # Kill existing server if running
        is_running, _ = mgr.detect_server()
        if is_running:
            mgr.kill_server(use_sudo=False)

        # Start server (no sudo on web — would hang waiting for password)
        import sys
        use_sudo = sys.platform != 'win32' and data.get('sudo', False)
        ok = mgr.start_server(username, password, host, port, use_ssl, use_sudo=use_sudo)

        if ok:
            # Auto-connect after starting
            try:
                mgr.connect(password)
                version = mgr.rpc.get_version() if mgr.rpc else {}
                return jsonify({
                    'ok': True,
                    'message': 'Server started and connected',
                    'version': version.get('version', '')
                })
            except Exception:
                return jsonify({'ok': True, 'message': 'Server started (connect manually)'})
        else:
            return jsonify({'ok': False, 'error': 'Failed to start server'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/server/stop', methods=['POST'])
@login_required
def stop_server():
    """Stop the MSF RPC server."""
    try:
        from core.msf import get_msf_manager
        mgr = get_msf_manager()
        ok = mgr.kill_server(use_sudo=False)
        return jsonify({'ok': ok})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/settings', methods=['POST'])
@login_required
def save_settings():
    """Save MSF connection settings."""
    data = request.get_json(silent=True) or {}
    try:
        from core.msf import get_msf_manager
        mgr = get_msf_manager()
        mgr.save_settings(
            host=data.get('host', '127.0.0.1'),
            port=int(data.get('port', 55553)),
            username=data.get('username', 'msf'),
            password=data.get('password', ''),
            use_ssl=data.get('ssl', True),
        )
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/jobs')
@login_required
def list_jobs():
    """List running MSF jobs."""
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        if not msf.is_connected:
            return jsonify({'jobs': {}, 'error': 'Not connected to MSF'})
        jobs = msf.list_jobs()
        return jsonify({'jobs': jobs})
    except Exception as e:
        return jsonify({'jobs': {}, 'error': str(e)})


@offense_bp.route('/jobs/<job_id>/stop', methods=['POST'])
@login_required
def stop_job(job_id):
    """Stop a running MSF job."""
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        ok = msf.stop_job(job_id)
        return jsonify({'ok': ok})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@offense_bp.route('/search', methods=['POST'])
@login_required
def search():
    """Search MSF modules (offline library first, then live if connected)."""
    data = request.get_json(silent=True) or {}
    query = data.get('query', '').strip()

    if not query:
        return jsonify({'error': 'No search query provided'})

    # Search offline library first
    try:
        from core.msf_modules import search_modules as offline_search
        results = offline_search(query, max_results=30)
        modules = [{'path': r['path'], 'name': r.get('name', ''), 'description': r.get('description', '')} for r in results]
    except Exception:
        modules = []

    # If no offline results and MSF is connected, try live search
    if not modules:
        try:
            from core.msf_interface import get_msf_interface
            msf = get_msf_interface()
            if msf.is_connected:
                live_results = msf.search_modules(query)
                modules = [{'path': r, 'name': r.split('/')[-1] if isinstance(r, str) else '', 'description': ''} for r in live_results[:30]]
        except Exception:
            pass

    return jsonify({'modules': modules})


@offense_bp.route('/sessions')
@login_required
def sessions():
    """List active MSF sessions."""
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        if not msf.is_connected:
            return jsonify({'sessions': {}, 'error': 'Not connected to MSF'})

        sessions_data = msf.list_sessions()
        # Convert session data to serializable format
        result = {}
        for sid, sinfo in sessions_data.items():
            if isinstance(sinfo, dict):
                result[str(sid)] = sinfo
            else:
                result[str(sid)] = {
                    'type': getattr(sinfo, 'type', ''),
                    'tunnel_peer': getattr(sinfo, 'tunnel_peer', ''),
                    'info': getattr(sinfo, 'info', ''),
                    'target_host': getattr(sinfo, 'target_host', ''),
                }

        return jsonify({'sessions': result})
    except Exception as e:
        return jsonify({'sessions': {}, 'error': str(e)})


@offense_bp.route('/modules/<module_type>')
@login_required
def browse_modules(module_type):
    """Browse modules by type from offline library."""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    try:
        from core.msf_modules import get_modules_by_type
        all_modules = get_modules_by_type(module_type)

        start = (page - 1) * per_page
        end = start + per_page
        page_modules = all_modules[start:end]

        modules = [{'path': m['path'], 'name': m.get('name', '')} for m in page_modules]

        return jsonify({
            'modules': modules,
            'total': len(all_modules),
            'page': page,
            'has_more': end < len(all_modules),
        })
    except Exception as e:
        return jsonify({'modules': [], 'error': str(e)})


@offense_bp.route('/module/info', methods=['POST'])
@login_required
def module_info():
    """Get module info."""
    data = request.get_json(silent=True) or {}
    module_path = data.get('module_path', '').strip()

    if not module_path:
        return jsonify({'error': 'No module path provided'})

    # Try offline library first
    try:
        from core.msf_modules import get_module_info
        info = get_module_info(module_path)
        if info:
            return jsonify({
                'path': module_path,
                'name': info.get('name', ''),
                'description': info.get('description', ''),
                'author': info.get('author', []),
                'platforms': info.get('platforms', []),
                'reliability': info.get('reliability', ''),
                'options': info.get('options', []),
                'notes': info.get('notes', ''),
            })
    except Exception:
        pass

    # Try live MSF
    try:
        from core.msf_interface import get_msf_interface
        msf = get_msf_interface()
        if msf.is_connected:
            info = msf.get_module_info(module_path)
            if info:
                return jsonify({
                    'path': module_path,
                    **info
                })
    except Exception:
        pass

    return jsonify({'error': f'Module not found: {module_path}'})


@offense_bp.route('/module/run', methods=['POST'])
@login_required
def run_module():
    """Run an MSF module and stream output via SSE."""
    data = request.get_json(silent=True) or {}
    module_path = data.get('module_path', '').strip()
    options = data.get('options', {})
    if not module_path:
        return jsonify({'error': 'No module_path provided'})

    job_id = str(uuid.uuid4())
    stop_event = threading.Event()
    _running_jobs[job_id] = stop_event

    def generate():
        yield f"data: {json.dumps({'status': 'running', 'job_id': job_id})}\n\n"
        try:
            from core.msf_interface import get_msf_interface
            msf = get_msf_interface()
            if not msf.is_connected:
                yield f"data: {json.dumps({'error': 'Not connected to MSF'})}\n\n"
                return
            result = msf.run_module(module_path, options)
            for line in (result.cleaned_output or '').splitlines():
                if stop_event.is_set():
                    break
                yield f"data: {json.dumps({'line': line})}\n\n"
            yield f"data: {json.dumps({'done': True, 'findings': result.findings, 'services': result.services, 'open_ports': result.open_ports})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            _running_jobs.pop(job_id, None)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@offense_bp.route('/module/stop', methods=['POST'])
@login_required
def stop_module():
    """Stop a running module job."""
    data = request.get_json(silent=True) or {}
    job_id = data.get('job_id', '')
    ev = _running_jobs.get(job_id)
    if ev:
        ev.set()
    return jsonify({'stopped': bool(ev)})
