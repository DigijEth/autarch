"""Counter-intelligence category route - threat detection and login analysis endpoints."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

counter_bp = Blueprint('counter', __name__, url_prefix='/counter')


@counter_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'counter'}
    return render_template('counter.html', modules=modules)


@counter_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    """Run full threat scan."""
    from modules.counter import Counter as CounterModule
    c = CounterModule()
    c.check_suspicious_processes()
    c.check_network_connections()
    c.check_login_anomalies()
    c.check_file_integrity()
    c.check_scheduled_tasks()
    c.check_rootkits()

    high = sum(1 for t in c.threats if t['severity'] == 'high')
    medium = sum(1 for t in c.threats if t['severity'] == 'medium')
    low = sum(1 for t in c.threats if t['severity'] == 'low')

    return jsonify({
        'threats': c.threats,
        'summary': f'{len(c.threats)} threats found ({high} high, {medium} medium, {low} low)',
    })


@counter_bp.route('/check/<check_name>', methods=['POST'])
@login_required
def check(check_name):
    """Run individual threat check."""
    from modules.counter import Counter as CounterModule
    c = CounterModule()

    checks_map = {
        'processes': c.check_suspicious_processes,
        'network': c.check_network_connections,
        'logins': c.check_login_anomalies,
        'integrity': c.check_file_integrity,
        'tasks': c.check_scheduled_tasks,
        'rootkits': c.check_rootkits,
    }

    func = checks_map.get(check_name)
    if not func:
        return jsonify({'error': f'Unknown check: {check_name}'}), 400

    func()

    if not c.threats:
        return jsonify({'threats': [], 'message': 'No threats found'})
    return jsonify({'threats': c.threats})


@counter_bp.route('/logins')
@login_required
def logins():
    """Login anomaly analysis with GeoIP enrichment."""
    from modules.counter import Counter as CounterModule
    c = CounterModule()
    attempts = c.parse_auth_logs()

    if not attempts:
        return jsonify({'attempts': [], 'error': 'No failed login attempts found or could not read logs'})

    # Enrich top 15 IPs with GeoIP
    sorted_ips = sorted(attempts.values(), key=lambda x: x.count, reverse=True)[:15]
    c.enrich_login_attempts({a.ip: a for a in sorted_ips}, show_progress=False)

    result = []
    for attempt in sorted_ips:
        result.append({
            'ip': attempt.ip,
            'count': attempt.count,
            'usernames': attempt.usernames[:10],
            'country': attempt.country or '',
            'city': attempt.city or '',
            'isp': attempt.isp or '',
            'hostname': attempt.hostname or '',
        })

    return jsonify({'attempts': result})
