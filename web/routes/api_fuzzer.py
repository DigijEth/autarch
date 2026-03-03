"""API Fuzzer routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

api_fuzzer_bp = Blueprint('api_fuzzer', __name__, url_prefix='/api-fuzzer')

def _get_fuzzer():
    from modules.api_fuzzer import get_api_fuzzer
    return get_api_fuzzer()

@api_fuzzer_bp.route('/')
@login_required
def index():
    return render_template('api_fuzzer.html')

@api_fuzzer_bp.route('/discover', methods=['POST'])
@login_required
def discover():
    data = request.get_json(silent=True) or {}
    job_id = _get_fuzzer().discover_endpoints(
        data.get('base_url', ''), data.get('custom_paths')
    )
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@api_fuzzer_bp.route('/openapi', methods=['POST'])
@login_required
def parse_openapi():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().parse_openapi(data.get('url', '')))

@api_fuzzer_bp.route('/fuzz', methods=['POST'])
@login_required
def fuzz():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().fuzz_params(
        url=data.get('url', ''),
        method=data.get('method', 'GET'),
        params=data.get('params', {}),
        payload_type=data.get('payload_type', 'type_confusion')
    ))

@api_fuzzer_bp.route('/auth/bypass', methods=['POST'])
@login_required
def auth_bypass():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().test_auth_bypass(data.get('url', '')))

@api_fuzzer_bp.route('/auth/idor', methods=['POST'])
@login_required
def idor():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().test_idor(
        data.get('url_template', ''),
        (data.get('start_id', 1), data.get('end_id', 10)),
        data.get('auth_token')
    ))

@api_fuzzer_bp.route('/ratelimit', methods=['POST'])
@login_required
def rate_limit():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().test_rate_limit(
        data.get('url', ''), data.get('count', 50), data.get('method', 'GET')
    ))

@api_fuzzer_bp.route('/graphql/introspect', methods=['POST'])
@login_required
def graphql_introspect():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().graphql_introspect(data.get('url', '')))

@api_fuzzer_bp.route('/graphql/depth', methods=['POST'])
@login_required
def graphql_depth():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().graphql_depth_test(data.get('url', ''), data.get('max_depth', 10)))

@api_fuzzer_bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_fuzzer().analyze_response(data.get('url', ''), data.get('method', 'GET')))

@api_fuzzer_bp.route('/auth/set', methods=['POST'])
@login_required
def set_auth():
    data = request.get_json(silent=True) or {}
    _get_fuzzer().set_auth(data.get('type', ''), data.get('value', ''), data.get('header', 'Authorization'))
    return jsonify({'ok': True})

@api_fuzzer_bp.route('/job/<job_id>')
@login_required
def job_status(job_id):
    job = _get_fuzzer().get_job(job_id)
    return jsonify(job or {'error': 'Job not found'})
