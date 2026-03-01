"""Defense category route - security audit, firewall, and log analysis endpoints."""

import re
import subprocess
from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

defense_bp = Blueprint('defense', __name__, url_prefix='/defense')


def _run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except Exception:
        return False, ""


@defense_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'defense'}
    return render_template('defense.html', modules=modules)


@defense_bp.route('/audit', methods=['POST'])
@login_required
def audit():
    """Run full security audit."""
    from modules.defender import Defender
    d = Defender()
    d.check_firewall()
    d.check_ssh_config()
    d.check_open_ports()
    d.check_users()
    d.check_permissions()
    d.check_services()
    d.check_fail2ban()
    d.check_selinux()

    passed = sum(1 for r in d.results if r['passed'])
    total = len(d.results)
    score = int((passed / total) * 100) if total > 0 else 0

    return jsonify({
        'score': score,
        'passed': passed,
        'total': total,
        'checks': d.results
    })


@defense_bp.route('/check/<check_name>', methods=['POST'])
@login_required
def check(check_name):
    """Run individual security check."""
    from modules.defender import Defender
    d = Defender()

    checks_map = {
        'firewall': d.check_firewall,
        'ssh': d.check_ssh_config,
        'ports': d.check_open_ports,
        'users': d.check_users,
        'permissions': d.check_permissions,
        'services': d.check_services,
        'fail2ban': d.check_fail2ban,
        'selinux': d.check_selinux,
    }

    func = checks_map.get(check_name)
    if not func:
        return jsonify({'error': f'Unknown check: {check_name}'}), 400

    func()
    return jsonify({'checks': d.results})


@defense_bp.route('/firewall/rules')
@login_required
def firewall_rules():
    """Get current iptables rules."""
    success, output = _run_cmd("sudo iptables -L -n --line-numbers 2>/dev/null")
    if success:
        return jsonify({'rules': output})
    return jsonify({'rules': 'Could not read iptables rules (need sudo privileges)'})


@defense_bp.route('/firewall/block', methods=['POST'])
@login_required
def firewall_block():
    """Block an IP address."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    success, _ = _run_cmd(f"sudo iptables -A INPUT -s {ip} -j DROP")
    if success:
        return jsonify({'message': f'Blocked {ip}', 'success': True})
    return jsonify({'error': f'Failed to block {ip} (need sudo)', 'success': False})


@defense_bp.route('/firewall/unblock', methods=['POST'])
@login_required
def firewall_unblock():
    """Unblock an IP address."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    success, _ = _run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
    if success:
        return jsonify({'message': f'Unblocked {ip}', 'success': True})
    return jsonify({'error': f'Failed to unblock {ip}', 'success': False})


@defense_bp.route('/logs/analyze', methods=['POST'])
@login_required
def logs_analyze():
    """Analyze auth and web logs."""
    from modules.defender import Defender
    d = Defender()
    auth_results = d._analyze_auth_log()
    web_results = d._analyze_web_logs()

    return jsonify({
        'auth_results': auth_results[:20],
        'web_results': web_results[:20],
    })
