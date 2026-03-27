"""Email Security routes."""

from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

email_sec_bp = Blueprint('email_sec', __name__, url_prefix='/email-sec')


def _get_es():
    from modules.email_sec import get_email_sec
    return get_email_sec()


@email_sec_bp.route('/')
@login_required
def index():
    return render_template('email_sec.html')


@email_sec_bp.route('/domain', methods=['POST'])
@login_required
def analyze_domain():
    """Full domain email security analysis."""
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    return jsonify(_get_es().analyze_domain(domain))


@email_sec_bp.route('/spf', methods=['POST'])
@login_required
def check_spf():
    """Check SPF record for a domain."""
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    return jsonify(_get_es().check_spf(domain))


@email_sec_bp.route('/dmarc', methods=['POST'])
@login_required
def check_dmarc():
    """Check DMARC record for a domain."""
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    return jsonify(_get_es().check_dmarc(domain))


@email_sec_bp.route('/dkim', methods=['POST'])
@login_required
def check_dkim():
    """Check DKIM selectors for a domain."""
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    selectors = data.get('selectors')
    if selectors and isinstance(selectors, str):
        selectors = [s.strip() for s in selectors.split(',') if s.strip()]
    return jsonify(_get_es().check_dkim(domain, selectors or None))


@email_sec_bp.route('/mx', methods=['POST'])
@login_required
def check_mx():
    """Check MX records for a domain."""
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    return jsonify(_get_es().check_mx(domain))


@email_sec_bp.route('/headers', methods=['POST'])
@login_required
def analyze_headers():
    """Analyze raw email headers."""
    data = request.get_json(silent=True) or {}
    raw_headers = data.get('raw_headers', '').strip()
    if not raw_headers:
        return jsonify({'error': 'Raw headers are required'}), 400
    return jsonify(_get_es().analyze_headers(raw_headers))


@email_sec_bp.route('/phishing', methods=['POST'])
@login_required
def detect_phishing():
    """Detect phishing indicators in email content."""
    data = request.get_json(silent=True) or {}
    email_content = data.get('email_content', '').strip()
    if not email_content:
        return jsonify({'error': 'Email content is required'}), 400
    return jsonify(_get_es().detect_phishing(email_content))


@email_sec_bp.route('/mailbox/search', methods=['POST'])
@login_required
def mailbox_search():
    """Search a mailbox for emails."""
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not host or not username or not password:
        return jsonify({'error': 'Host, username, and password are required'}), 400
    return jsonify(_get_es().search_mailbox(
        host=host,
        username=username,
        password=password,
        protocol=data.get('protocol', 'imap'),
        search_query=data.get('query') or None,
        folder=data.get('folder', 'INBOX'),
        use_ssl=data.get('ssl', True),
    ))


@email_sec_bp.route('/mailbox/fetch', methods=['POST'])
@login_required
def mailbox_fetch():
    """Fetch a full email by message ID."""
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    message_id = data.get('message_id', '').strip()
    if not host or not username or not password or not message_id:
        return jsonify({'error': 'Host, username, password, and message_id are required'}), 400
    return jsonify(_get_es().fetch_email(
        host=host,
        username=username,
        password=password,
        message_id=message_id,
        protocol=data.get('protocol', 'imap'),
        use_ssl=data.get('ssl', True),
    ))


@email_sec_bp.route('/blacklist', methods=['POST'])
@login_required
def check_blacklists():
    """Check IP or domain against email blacklists."""
    data = request.get_json(silent=True) or {}
    target = data.get('ip_or_domain', '').strip()
    if not target:
        return jsonify({'error': 'IP or domain is required'}), 400
    return jsonify(_get_es().check_blacklists(target))


@email_sec_bp.route('/abuse-report', methods=['POST'])
@login_required
def abuse_report():
    """Generate an abuse report."""
    data = request.get_json(silent=True) or {}
    incident_data = data.get('incident_data', data)
    return jsonify(_get_es().generate_abuse_report(incident_data))
