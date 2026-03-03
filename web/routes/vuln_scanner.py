"""Vulnerability Scanner routes."""

from flask import Blueprint, request, jsonify, render_template, Response
from web.auth import login_required

vuln_scanner_bp = Blueprint('vuln_scanner', __name__, url_prefix='/vuln-scanner')


def _get_scanner():
    from modules.vuln_scanner import get_vuln_scanner
    return get_vuln_scanner()


@vuln_scanner_bp.route('/')
@login_required
def index():
    return render_template('vuln_scanner.html')


@vuln_scanner_bp.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Start a vulnerability scan."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'ok': False, 'error': 'Target required'}), 400

    profile = data.get('profile', 'standard')
    ports = data.get('ports', '').strip() or None
    templates = data.get('templates') or None

    scanner = _get_scanner()
    job_id = scanner.scan(target, profile=profile, ports=ports, templates=templates)
    return jsonify({'ok': True, 'job_id': job_id})


@vuln_scanner_bp.route('/scan/<job_id>')
@login_required
def get_scan(job_id):
    """Get scan status and results."""
    scan = _get_scanner().get_scan(job_id)
    if not scan:
        return jsonify({'ok': False, 'error': 'Scan not found'}), 404
    return jsonify({'ok': True, **scan})


@vuln_scanner_bp.route('/scans')
@login_required
def list_scans():
    """List all scans."""
    scans = _get_scanner().list_scans()
    return jsonify({'ok': True, 'scans': scans})


@vuln_scanner_bp.route('/scan/<job_id>', methods=['DELETE'])
@login_required
def delete_scan(job_id):
    """Delete a scan."""
    deleted = _get_scanner().delete_scan(job_id)
    if not deleted:
        return jsonify({'ok': False, 'error': 'Scan not found'}), 404
    return jsonify({'ok': True})


@vuln_scanner_bp.route('/scan/<job_id>/export')
@login_required
def export_scan(job_id):
    """Export scan results."""
    fmt = request.args.get('format', 'json')
    result = _get_scanner().export_scan(job_id, fmt=fmt)
    if not result:
        return jsonify({'ok': False, 'error': 'Scan not found'}), 404

    return Response(
        result['content'],
        mimetype=result['mime'],
        headers={'Content-Disposition': f'attachment; filename="{result["filename"]}"'}
    )


@vuln_scanner_bp.route('/headers', methods=['POST'])
@login_required
def check_headers():
    """Check security headers for a URL."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'}), 400
    result = _get_scanner().check_headers(url)
    return jsonify({'ok': True, **result})


@vuln_scanner_bp.route('/ssl', methods=['POST'])
@login_required
def check_ssl():
    """Check SSL/TLS configuration."""
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    if not host:
        return jsonify({'ok': False, 'error': 'Host required'}), 400
    port = int(data.get('port', 443))
    result = _get_scanner().check_ssl(host, port)
    return jsonify({'ok': True, **result})


@vuln_scanner_bp.route('/creds', methods=['POST'])
@login_required
def check_creds():
    """Check default credentials for a target."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'ok': False, 'error': 'Target required'}), 400

    services = data.get('services', [])
    if not services:
        # Auto-detect services with a quick port scan
        scanner = _get_scanner()
        ports = data.get('ports', '21,22,23,80,443,1433,3306,5432,6379,8080,27017')
        services = scanner._socket_scan(target, ports)

    found = _get_scanner().check_default_creds(target, services)
    return jsonify({'ok': True, 'found': found, 'services_checked': len(services)})


@vuln_scanner_bp.route('/templates')
@login_required
def get_templates():
    """List available Nuclei templates."""
    result = _get_scanner().get_templates()
    return jsonify({'ok': True, **result})
