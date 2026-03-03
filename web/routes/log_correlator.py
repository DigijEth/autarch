"""Log Correlator routes."""
from flask import Blueprint, request, jsonify, render_template
from web.routes.auth_routes import login_required

log_correlator_bp = Blueprint('log_correlator', __name__, url_prefix='/logs')

def _get_engine():
    from modules.log_correlator import get_log_correlator
    return get_log_correlator()

@log_correlator_bp.route('/')
@login_required
def index():
    return render_template('log_correlator.html')

@log_correlator_bp.route('/ingest/file', methods=['POST'])
@login_required
def ingest_file():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().ingest_file(data.get('path', ''), data.get('source')))

@log_correlator_bp.route('/ingest/text', methods=['POST'])
@login_required
def ingest_text():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().ingest_text(data.get('text', ''), data.get('source', 'paste')))

@log_correlator_bp.route('/search')
@login_required
def search():
    return jsonify(_get_engine().search_logs(
        request.args.get('q', ''), request.args.get('source'),
        int(request.args.get('limit', 100))
    ))

@log_correlator_bp.route('/alerts', methods=['GET', 'DELETE'])
@login_required
def alerts():
    if request.method == 'DELETE':
        _get_engine().clear_alerts()
        return jsonify({'ok': True})
    return jsonify(_get_engine().get_alerts(
        request.args.get('severity'), int(request.args.get('limit', 100))
    ))

@log_correlator_bp.route('/rules', methods=['GET', 'POST', 'DELETE'])
@login_required
def rules():
    engine = _get_engine()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.add_rule(
            rule_id=data.get('id', ''), name=data.get('name', ''),
            pattern=data.get('pattern', ''), severity=data.get('severity', 'medium'),
            threshold=data.get('threshold', 1), window_seconds=data.get('window_seconds', 0),
            description=data.get('description', '')
        ))
    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.remove_rule(data.get('id', '')))
    return jsonify(engine.get_rules())

@log_correlator_bp.route('/stats')
@login_required
def stats():
    return jsonify(_get_engine().get_stats())

@log_correlator_bp.route('/sources')
@login_required
def sources():
    return jsonify(_get_engine().get_sources())

@log_correlator_bp.route('/timeline')
@login_required
def timeline():
    return jsonify(_get_engine().get_timeline(int(request.args.get('hours', 24))))

@log_correlator_bp.route('/clear', methods=['POST'])
@login_required
def clear():
    _get_engine().clear_logs()
    return jsonify({'ok': True})
