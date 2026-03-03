"""Cloud Security Scanner routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

cloud_scan_bp = Blueprint('cloud_scan', __name__, url_prefix='/cloud')

def _get_scanner():
    from modules.cloud_scan import get_cloud_scanner
    return get_cloud_scanner()

@cloud_scan_bp.route('/')
@login_required
def index():
    return render_template('cloud_scan.html')

@cloud_scan_bp.route('/s3/enum', methods=['POST'])
@login_required
def s3_enum():
    data = request.get_json(silent=True) or {}
    job_id = _get_scanner().enum_s3_buckets(
        data.get('keyword', ''), data.get('prefixes'), data.get('suffixes')
    )
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@cloud_scan_bp.route('/gcs/enum', methods=['POST'])
@login_required
def gcs_enum():
    data = request.get_json(silent=True) or {}
    job_id = _get_scanner().enum_gcs_buckets(data.get('keyword', ''))
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@cloud_scan_bp.route('/azure/enum', methods=['POST'])
@login_required
def azure_enum():
    data = request.get_json(silent=True) or {}
    job_id = _get_scanner().enum_azure_blobs(data.get('keyword', ''))
    return jsonify({'ok': bool(job_id), 'job_id': job_id})

@cloud_scan_bp.route('/services', methods=['POST'])
@login_required
def exposed_services():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().scan_exposed_services(data.get('target', '')))

@cloud_scan_bp.route('/metadata')
@login_required
def metadata():
    return jsonify(_get_scanner().check_metadata_access())

@cloud_scan_bp.route('/subdomains', methods=['POST'])
@login_required
def subdomains():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_scanner().enum_cloud_subdomains(data.get('domain', '')))

@cloud_scan_bp.route('/job/<job_id>')
@login_required
def job_status(job_id):
    job = _get_scanner().get_job(job_id)
    return jsonify(job or {'error': 'Job not found'})
