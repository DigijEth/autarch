"""Web Application Scanner — web routes."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

webapp_scanner_bp = Blueprint('webapp_scanner', __name__)


def _svc():
    from modules.webapp_scanner import get_webapp_scanner
    return get_webapp_scanner()


@webapp_scanner_bp.route('/web-scanner/')
@login_required
def index():
    return render_template('webapp_scanner.html')


@webapp_scanner_bp.route('/web-scanner/quick', methods=['POST'])
@login_required
def quick_scan():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    return jsonify({'ok': True, **_svc().quick_scan(url)})


@webapp_scanner_bp.route('/web-scanner/dirbust', methods=['POST'])
@login_required
def dir_bruteforce():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    extensions = data.get('extensions', [])
    return jsonify(_svc().dir_bruteforce(url, extensions=extensions or None,
                                         threads=data.get('threads', 10)))


@webapp_scanner_bp.route('/web-scanner/dirbust/<job_id>', methods=['GET'])
@login_required
def dirbust_status(job_id):
    return jsonify(_svc().get_job_status(job_id))


@webapp_scanner_bp.route('/web-scanner/subdomain', methods=['POST'])
@login_required
def subdomain_enum():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain required'})
    return jsonify(_svc().subdomain_enum(domain, use_ct=data.get('use_ct', True)))


@webapp_scanner_bp.route('/web-scanner/vuln', methods=['POST'])
@login_required
def vuln_scan():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    return jsonify(_svc().vuln_scan(url,
                                    scan_sqli=data.get('sqli', True),
                                    scan_xss=data.get('xss', True)))


@webapp_scanner_bp.route('/web-scanner/crawl', methods=['POST'])
@login_required
def crawl():
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    return jsonify(_svc().crawl(url,
                                max_pages=data.get('max_pages', 50),
                                depth=data.get('depth', 3)))
