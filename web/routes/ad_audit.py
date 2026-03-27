"""Active Directory Audit routes."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

ad_audit_bp = Blueprint('ad_audit', __name__, url_prefix='/ad-audit')


def _get_ad():
    from modules.ad_audit import get_ad_audit
    return get_ad_audit()


@ad_audit_bp.route('/')
@login_required
def index():
    return render_template('ad_audit.html')


@ad_audit_bp.route('/connect', methods=['POST'])
@login_required
def connect():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    domain = data.get('domain', '').strip()
    username = data.get('username', '').strip() or None
    password = data.get('password', '') or None
    use_ssl = bool(data.get('ssl', False))
    if not host or not domain:
        return jsonify({'success': False, 'message': 'DC host and domain are required'}), 400
    return jsonify(_get_ad().connect(host, domain, username, password, use_ssl))


@ad_audit_bp.route('/disconnect', methods=['POST'])
@login_required
def disconnect():
    return jsonify(_get_ad().disconnect())


@ad_audit_bp.route('/status')
@login_required
def status():
    return jsonify(_get_ad().get_connection_info())


@ad_audit_bp.route('/users')
@login_required
def users():
    search_filter = request.args.get('filter')
    return jsonify(_get_ad().enumerate_users(search_filter))


@ad_audit_bp.route('/groups')
@login_required
def groups():
    search_filter = request.args.get('filter')
    return jsonify(_get_ad().enumerate_groups(search_filter))


@ad_audit_bp.route('/computers')
@login_required
def computers():
    return jsonify(_get_ad().enumerate_computers())


@ad_audit_bp.route('/ous')
@login_required
def ous():
    return jsonify(_get_ad().enumerate_ous())


@ad_audit_bp.route('/gpos')
@login_required
def gpos():
    return jsonify(_get_ad().enumerate_gpos())


@ad_audit_bp.route('/trusts')
@login_required
def trusts():
    return jsonify(_get_ad().enumerate_trusts())


@ad_audit_bp.route('/dcs')
@login_required
def dcs():
    return jsonify(_get_ad().find_dcs())


@ad_audit_bp.route('/kerberoast', methods=['POST'])
@login_required
def kerberoast():
    data = request.get_json(silent=True) or {}
    ad = _get_ad()
    host = data.get('host', '').strip() or ad.dc_host
    domain = data.get('domain', '').strip() or ad.domain
    username = data.get('username', '').strip() or ad.username
    password = data.get('password', '') or ad.password
    if not all([host, domain, username, password]):
        return jsonify({'error': 'Host, domain, username, and password are required'}), 400
    return jsonify(ad.kerberoast(host, domain, username, password))


@ad_audit_bp.route('/asrep', methods=['POST'])
@login_required
def asrep():
    data = request.get_json(silent=True) or {}
    ad = _get_ad()
    host = data.get('host', '').strip() or ad.dc_host
    domain = data.get('domain', '').strip() or ad.domain
    userlist = data.get('userlist')
    if isinstance(userlist, str):
        userlist = [u.strip() for u in userlist.split(',') if u.strip()]
    if not host or not domain:
        return jsonify({'error': 'Host and domain are required'}), 400
    return jsonify(ad.asrep_roast(host, domain, userlist or None))


@ad_audit_bp.route('/spray', methods=['POST'])
@login_required
def spray():
    data = request.get_json(silent=True) or {}
    ad = _get_ad()
    userlist = data.get('userlist', [])
    if isinstance(userlist, str):
        userlist = [u.strip() for u in userlist.split('\n') if u.strip()]
    password = data.get('password', '')
    host = data.get('host', '').strip() or ad.dc_host
    domain = data.get('domain', '').strip() or ad.domain
    protocol = data.get('protocol', 'ldap')
    if not userlist or not password or not host or not domain:
        return jsonify({'error': 'User list, password, host, and domain are required'}), 400
    return jsonify(ad.password_spray(userlist, password, host, domain, protocol))


@ad_audit_bp.route('/acls')
@login_required
def acls():
    target_dn = request.args.get('target_dn')
    return jsonify(_get_ad().analyze_acls(target_dn))


@ad_audit_bp.route('/admins')
@login_required
def admins():
    return jsonify(_get_ad().find_admin_accounts())


@ad_audit_bp.route('/spn-accounts')
@login_required
def spn_accounts():
    return jsonify(_get_ad().find_spn_accounts())


@ad_audit_bp.route('/asrep-accounts')
@login_required
def asrep_accounts():
    return jsonify(_get_ad().find_asrep_accounts())


@ad_audit_bp.route('/unconstrained')
@login_required
def unconstrained():
    return jsonify(_get_ad().find_unconstrained_delegation())


@ad_audit_bp.route('/constrained')
@login_required
def constrained():
    return jsonify(_get_ad().find_constrained_delegation())


@ad_audit_bp.route('/bloodhound', methods=['POST'])
@login_required
def bloodhound():
    data = request.get_json(silent=True) or {}
    ad = _get_ad()
    host = data.get('host', '').strip() or ad.dc_host
    domain = data.get('domain', '').strip() or ad.domain
    username = data.get('username', '').strip() or ad.username
    password = data.get('password', '') or ad.password
    if not all([host, domain, username, password]):
        return jsonify({'error': 'Host, domain, username, and password are required'}), 400
    return jsonify(ad.bloodhound_collect(host, domain, username, password))


@ad_audit_bp.route('/export')
@login_required
def export():
    fmt = request.args.get('format', 'json')
    return jsonify(_get_ad().export_results(fmt))
