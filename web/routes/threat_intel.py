"""Threat Intelligence routes."""
from flask import Blueprint, request, jsonify, render_template, Response
from web.auth import login_required

threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/threat-intel')

def _get_engine():
    from modules.threat_intel import get_threat_intel
    return get_threat_intel()

@threat_intel_bp.route('/')
@login_required
def index():
    return render_template('threat_intel.html')

@threat_intel_bp.route('/iocs', methods=['GET', 'POST', 'DELETE'])
@login_required
def iocs():
    engine = _get_engine()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.add_ioc(
            value=data.get('value', ''),
            ioc_type=data.get('ioc_type'),
            source=data.get('source', 'manual'),
            tags=data.get('tags', []),
            severity=data.get('severity', 'unknown'),
            description=data.get('description', ''),
            reference=data.get('reference', '')
        ))
    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.remove_ioc(data.get('id', '')))
    else:
        return jsonify(engine.get_iocs(
            ioc_type=request.args.get('type'),
            source=request.args.get('source'),
            severity=request.args.get('severity'),
            search=request.args.get('search')
        ))

@threat_intel_bp.route('/iocs/import', methods=['POST'])
@login_required
def import_iocs():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().bulk_import(
        data.get('text', ''), source=data.get('source', 'import'),
        ioc_type=data.get('ioc_type')
    ))

@threat_intel_bp.route('/iocs/export')
@login_required
def export_iocs():
    fmt = request.args.get('format', 'json')
    ioc_type = request.args.get('type')
    content = _get_engine().export_iocs(fmt=fmt, ioc_type=ioc_type)
    ct = {'csv': 'text/csv', 'stix': 'application/json', 'json': 'application/json'}.get(fmt, 'text/plain')
    return Response(content, mimetype=ct, headers={'Content-Disposition': f'attachment; filename=iocs.{fmt}'})

@threat_intel_bp.route('/iocs/detect')
@login_required
def detect_type():
    value = request.args.get('value', '')
    return jsonify({'type': _get_engine().detect_ioc_type(value)})

@threat_intel_bp.route('/stats')
@login_required
def stats():
    return jsonify(_get_engine().get_stats())

@threat_intel_bp.route('/feeds', methods=['GET', 'POST', 'DELETE'])
@login_required
def feeds():
    engine = _get_engine()
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.add_feed(
            name=data.get('name', ''), feed_type=data.get('feed_type', ''),
            url=data.get('url', ''), api_key=data.get('api_key', ''),
            interval_hours=data.get('interval_hours', 24)
        ))
    elif request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        return jsonify(engine.remove_feed(data.get('id', '')))
    return jsonify(engine.get_feeds())

@threat_intel_bp.route('/feeds/<feed_id>/fetch', methods=['POST'])
@login_required
def fetch_feed(feed_id):
    return jsonify(_get_engine().fetch_feed(feed_id))

@threat_intel_bp.route('/lookup/virustotal', methods=['POST'])
@login_required
def lookup_vt():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().lookup_virustotal(data.get('value', ''), data.get('api_key', '')))

@threat_intel_bp.route('/lookup/abuseipdb', methods=['POST'])
@login_required
def lookup_abuse():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().lookup_abuseipdb(data.get('ip', ''), data.get('api_key', '')))

@threat_intel_bp.route('/correlate/network', methods=['POST'])
@login_required
def correlate_network():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_engine().correlate_network(data.get('connections', [])))

@threat_intel_bp.route('/blocklist')
@login_required
def blocklist():
    return Response(
        _get_engine().generate_blocklist(
            fmt=request.args.get('format', 'plain'),
            ioc_type=request.args.get('type', 'ip'),
            min_severity=request.args.get('min_severity', 'low')
        ),
        mimetype='text/plain'
    )

@threat_intel_bp.route('/alerts')
@login_required
def alerts():
    return jsonify(_get_engine().get_alerts(int(request.args.get('limit', 100))))
