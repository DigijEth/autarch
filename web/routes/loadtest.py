"""Load testing web routes — start/stop/monitor load tests from the web UI."""

import json
import queue
from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

loadtest_bp = Blueprint('loadtest', __name__, url_prefix='/loadtest')


@loadtest_bp.route('/')
@login_required
def index():
    return render_template('loadtest.html')


@loadtest_bp.route('/start', methods=['POST'])
@login_required
def start():
    """Start a load test."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'ok': False, 'error': 'Target is required'})

    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()

        if tester.running:
            return jsonify({'ok': False, 'error': 'A test is already running'})

        config = {
            'target': target,
            'attack_type': data.get('attack_type', 'http_flood'),
            'workers': int(data.get('workers', 10)),
            'duration': int(data.get('duration', 30)),
            'requests_per_worker': int(data.get('requests_per_worker', 0)),
            'ramp_pattern': data.get('ramp_pattern', 'constant'),
            'ramp_duration': int(data.get('ramp_duration', 0)),
            'method': data.get('method', 'GET'),
            'headers': data.get('headers', {}),
            'body': data.get('body', ''),
            'timeout': int(data.get('timeout', 10)),
            'follow_redirects': data.get('follow_redirects', True),
            'verify_ssl': data.get('verify_ssl', False),
            'rotate_useragent': data.get('rotate_useragent', True),
            'custom_useragent': data.get('custom_useragent', ''),
            'rate_limit': int(data.get('rate_limit', 0)),
            'payload_size': int(data.get('payload_size', 1024)),
        }

        tester.start(config)
        return jsonify({'ok': True, 'message': 'Test started'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@loadtest_bp.route('/stop', methods=['POST'])
@login_required
def stop():
    """Stop the running load test."""
    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()
        tester.stop()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@loadtest_bp.route('/pause', methods=['POST'])
@login_required
def pause():
    """Pause the running load test."""
    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()
        tester.pause()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@loadtest_bp.route('/resume', methods=['POST'])
@login_required
def resume():
    """Resume a paused load test."""
    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()
        tester.resume()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@loadtest_bp.route('/status')
@login_required
def status():
    """Get current test status and metrics."""
    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()
        metrics = tester.metrics.to_dict() if tester.running else {}
        return jsonify({
            'running': tester.running,
            'paused': not tester._pause_event.is_set() if tester.running else False,
            'metrics': metrics,
        })
    except Exception as e:
        return jsonify({'running': False, 'error': str(e)})


@loadtest_bp.route('/stream')
@login_required
def stream():
    """SSE stream for live metrics."""
    try:
        from modules.loadtest import get_load_tester
        tester = get_load_tester()
    except Exception:
        return Response("data: {}\n\n", mimetype='text/event-stream')

    sub = tester.subscribe()

    def generate():
        try:
            while tester.running:
                try:
                    data = sub.get(timeout=2)
                    yield f"data: {json.dumps(data)}\n\n"
                except queue.Empty:
                    # Send keepalive
                    m = tester.metrics.to_dict() if tester.running else {}
                    yield f"data: {json.dumps({'type': 'metrics', 'data': m})}\n\n"
            # Send final metrics
            m = tester.metrics.to_dict()
            yield f"data: {json.dumps({'type': 'done', 'data': m})}\n\n"
        finally:
            tester.unsubscribe(sub)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
