"""MITM Proxy routes."""

from flask import Blueprint, request, jsonify, render_template, Response
from web.auth import login_required

mitm_proxy_bp = Blueprint('mitm_proxy', __name__, url_prefix='/mitm-proxy')


def _get_proxy():
    from modules.mitm_proxy import get_mitm_proxy
    return get_mitm_proxy()


# ── Pages ────────────────────────────────────────────────────────────────

@mitm_proxy_bp.route('/')
@login_required
def index():
    return render_template('mitm_proxy.html')


# ── Proxy Lifecycle ──────────────────────────────────────────────────────

@mitm_proxy_bp.route('/start', methods=['POST'])
@login_required
def start():
    data = request.get_json(silent=True) or {}
    result = _get_proxy().start(
        listen_host=data.get('host', '127.0.0.1'),
        listen_port=int(data.get('port', 8888)),
        upstream_proxy=data.get('upstream', None),
    )
    return jsonify(result)


@mitm_proxy_bp.route('/stop', methods=['POST'])
@login_required
def stop():
    return jsonify(_get_proxy().stop())


@mitm_proxy_bp.route('/status')
@login_required
def status():
    return jsonify(_get_proxy().get_status())


# ── SSL Strip ────────────────────────────────────────────────────────────

@mitm_proxy_bp.route('/ssl-strip', methods=['POST'])
@login_required
def ssl_strip():
    data = request.get_json(silent=True) or {}
    enabled = data.get('enabled', True)
    return jsonify(_get_proxy().ssl_strip_mode(enabled))


# ── Certificate Management ──────────────────────────────────────────────

@mitm_proxy_bp.route('/cert/generate', methods=['POST'])
@login_required
def cert_generate():
    return jsonify(_get_proxy().generate_ca_cert())


@mitm_proxy_bp.route('/cert')
@login_required
def cert_download():
    result = _get_proxy().get_ca_cert()
    if not result.get('success'):
        return jsonify(result), 404
    # Return PEM as downloadable file
    return Response(
        result['pem'],
        mimetype='application/x-pem-file',
        headers={'Content-Disposition': 'attachment; filename=autarch-ca.pem'}
    )


@mitm_proxy_bp.route('/certs')
@login_required
def cert_list():
    return jsonify({'certs': _get_proxy().get_certs()})


# ── Rules ────────────────────────────────────────────────────────────────

@mitm_proxy_bp.route('/rules', methods=['POST'])
@login_required
def add_rule():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_proxy().add_rule(data))


@mitm_proxy_bp.route('/rules/<int:rule_id>', methods=['DELETE'])
@login_required
def remove_rule(rule_id):
    return jsonify(_get_proxy().remove_rule(rule_id))


@mitm_proxy_bp.route('/rules')
@login_required
def list_rules():
    return jsonify({'rules': _get_proxy().list_rules()})


@mitm_proxy_bp.route('/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def toggle_rule(rule_id):
    proxy = _get_proxy()
    for rule in proxy.list_rules():
        if rule['id'] == rule_id:
            if rule['enabled']:
                return jsonify(proxy.disable_rule(rule_id))
            else:
                return jsonify(proxy.enable_rule(rule_id))
    return jsonify({'success': False, 'error': f'Rule {rule_id} not found'}), 404


# ── Traffic Log ──────────────────────────────────────────────────────────

@mitm_proxy_bp.route('/traffic')
@login_required
def get_traffic():
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    filter_url = request.args.get('filter_url', None)
    filter_method = request.args.get('filter_method', None)
    filter_status = request.args.get('filter_status', None)
    return jsonify(_get_proxy().get_traffic(
        limit=limit, offset=offset,
        filter_url=filter_url, filter_method=filter_method,
        filter_status=filter_status,
    ))


@mitm_proxy_bp.route('/traffic/<int:traffic_id>')
@login_required
def get_request_detail(traffic_id):
    return jsonify(_get_proxy().get_request(traffic_id))


@mitm_proxy_bp.route('/traffic', methods=['DELETE'])
@login_required
def clear_traffic():
    return jsonify(_get_proxy().clear_traffic())


@mitm_proxy_bp.route('/traffic/export')
@login_required
def export_traffic():
    fmt = request.args.get('format', 'json')
    result = _get_proxy().export_traffic(fmt=fmt)
    if not result.get('success'):
        return jsonify(result), 400

    if fmt == 'json':
        return Response(
            result['data'],
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=mitm_traffic.json'}
        )
    elif fmt == 'csv':
        return Response(
            result['data'],
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=mitm_traffic.csv'}
        )

    return jsonify(result)
