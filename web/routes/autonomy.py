"""Autonomy routes — daemon control, model management, rules CRUD, activity log."""

import json
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from web.auth import login_required

autonomy_bp = Blueprint('autonomy', __name__, url_prefix='/autonomy')


def _get_daemon():
    from core.autonomy import get_autonomy_daemon
    return get_autonomy_daemon()


def _get_router():
    from core.model_router import get_model_router
    return get_model_router()


# ==================== PAGES ====================

@autonomy_bp.route('/')
@login_required
def index():
    return render_template('autonomy.html')


# ==================== DAEMON CONTROL ====================

@autonomy_bp.route('/status')
@login_required
def status():
    daemon = _get_daemon()
    router = _get_router()
    return jsonify({
        'daemon': daemon.status,
        'models': router.status,
    })


@autonomy_bp.route('/start', methods=['POST'])
@login_required
def start():
    daemon = _get_daemon()
    ok = daemon.start()
    return jsonify({'success': ok, 'status': daemon.status})


@autonomy_bp.route('/stop', methods=['POST'])
@login_required
def stop():
    daemon = _get_daemon()
    daemon.stop()
    return jsonify({'success': True, 'status': daemon.status})


@autonomy_bp.route('/pause', methods=['POST'])
@login_required
def pause():
    daemon = _get_daemon()
    daemon.pause()
    return jsonify({'success': True, 'status': daemon.status})


@autonomy_bp.route('/resume', methods=['POST'])
@login_required
def resume():
    daemon = _get_daemon()
    daemon.resume()
    return jsonify({'success': True, 'status': daemon.status})


# ==================== MODELS ====================

@autonomy_bp.route('/models')
@login_required
def models():
    return jsonify(_get_router().status)


@autonomy_bp.route('/models/load/<tier>', methods=['POST'])
@login_required
def models_load(tier):
    from core.model_router import ModelTier
    try:
        mt = ModelTier(tier)
    except ValueError:
        return jsonify({'error': f'Invalid tier: {tier}'}), 400
    ok = _get_router().load_tier(mt, verbose=True)
    return jsonify({'success': ok, 'models': _get_router().status})


@autonomy_bp.route('/models/unload/<tier>', methods=['POST'])
@login_required
def models_unload(tier):
    from core.model_router import ModelTier
    try:
        mt = ModelTier(tier)
    except ValueError:
        return jsonify({'error': f'Invalid tier: {tier}'}), 400
    _get_router().unload_tier(mt)
    return jsonify({'success': True, 'models': _get_router().status})


# ==================== RULES ====================

@autonomy_bp.route('/rules')
@login_required
def rules_list():
    daemon = _get_daemon()
    rules = daemon.rules_engine.get_all_rules()
    return jsonify({'rules': [r.to_dict() for r in rules]})


@autonomy_bp.route('/rules', methods=['POST'])
@login_required
def rules_create():
    from core.rules import Rule
    data = request.get_json(silent=True) or {}
    rule = Rule.from_dict(data)
    daemon = _get_daemon()
    daemon.rules_engine.add_rule(rule)
    return jsonify({'success': True, 'rule': rule.to_dict()})


@autonomy_bp.route('/rules/<rule_id>', methods=['PUT'])
@login_required
def rules_update(rule_id):
    data = request.get_json(silent=True) or {}
    daemon = _get_daemon()
    rule = daemon.rules_engine.update_rule(rule_id, data)
    if rule:
        return jsonify({'success': True, 'rule': rule.to_dict()})
    return jsonify({'error': 'Rule not found'}), 404


@autonomy_bp.route('/rules/<rule_id>', methods=['DELETE'])
@login_required
def rules_delete(rule_id):
    daemon = _get_daemon()
    ok = daemon.rules_engine.delete_rule(rule_id)
    return jsonify({'success': ok})


@autonomy_bp.route('/templates')
@login_required
def rule_templates():
    """Pre-built rule templates for common scenarios."""
    templates = [
        {
            'name': 'Auto-Block Port Scanners',
            'description': 'Block IPs that trigger port scan detection',
            'conditions': [{'type': 'port_scan_detected'}],
            'actions': [
                {'type': 'block_ip', 'ip': '$source_ip'},
                {'type': 'alert', 'message': 'Blocked scanner: $source_ip'},
            ],
            'priority': 10,
            'cooldown_seconds': 300,
        },
        {
            'name': 'DDoS Auto-Response',
            'description': 'Rate-limit top talkers during DDoS attacks',
            'conditions': [{'type': 'ddos_detected'}],
            'actions': [
                {'type': 'rate_limit_ip', 'ip': '$source_ip', 'rate': '10/s'},
                {'type': 'alert', 'message': 'DDoS mitigated: $attack_type from $source_ip'},
            ],
            'priority': 5,
            'cooldown_seconds': 60,
        },
        {
            'name': 'High Threat Alert',
            'description': 'Send alert when threat score exceeds threshold',
            'conditions': [{'type': 'threat_score_above', 'value': 60}],
            'actions': [
                {'type': 'alert', 'message': 'Threat score: $threat_score ($threat_level)'},
            ],
            'priority': 20,
            'cooldown_seconds': 120,
        },
        {
            'name': 'New Port Investigation',
            'description': 'Use SAM agent to investigate new listening ports',
            'conditions': [{'type': 'new_listening_port'}],
            'actions': [
                {'type': 'escalate_to_lam', 'task': 'Investigate new listening port $new_port (PID $suspicious_pid). Determine if this is legitimate or suspicious.'},
            ],
            'priority': 30,
            'cooldown_seconds': 300,
        },
        {
            'name': 'Bandwidth Spike Alert',
            'description': 'Alert on unusual inbound bandwidth',
            'conditions': [{'type': 'bandwidth_rx_above_mbps', 'value': 100}],
            'actions': [
                {'type': 'alert', 'message': 'Bandwidth spike detected (>100 Mbps RX)'},
            ],
            'priority': 25,
            'cooldown_seconds': 60,
        },
    ]
    return jsonify({'templates': templates})


# ==================== ACTIVITY LOG ====================

@autonomy_bp.route('/activity')
@login_required
def activity():
    limit = request.args.get('limit', 50, type=int)
    offset = request.args.get('offset', 0, type=int)
    daemon = _get_daemon()
    entries = daemon.get_activity(limit=limit, offset=offset)
    return jsonify({'entries': entries, 'total': daemon.get_activity_count()})


@autonomy_bp.route('/activity/stream')
@login_required
def activity_stream():
    """SSE stream of live activity entries."""
    daemon = _get_daemon()
    q = daemon.subscribe()

    def generate():
        try:
            while True:
                try:
                    data = q.get(timeout=30)
                    yield f'data: {data}\n\n'
                except Exception:
                    # Send keepalive
                    yield f'data: {{"type":"keepalive"}}\n\n'
        finally:
            daemon.unsubscribe(q)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )
