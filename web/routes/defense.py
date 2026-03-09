"""Defense category routes — landing page, Linux defense, Windows defense, Threat Monitor."""

import re
import subprocess
import platform
import socket
import json
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from web.auth import login_required

defense_bp = Blueprint('defense', __name__, url_prefix='/defense')


def _run_cmd(cmd, timeout=10):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except Exception:
        return False, ""


# ==================== LANDING PAGE ====================

@defense_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'defense'}

    # Gather system info for the landing page
    sys_info = {
        'platform': platform.system(),
        'hostname': socket.gethostname(),
        'os_version': platform.platform(),
    }
    try:
        sys_info['ip'] = socket.gethostbyname(socket.gethostname())
    except Exception:
        sys_info['ip'] = '127.0.0.1'

    return render_template('defense.html', modules=modules, sys_info=sys_info)


# ==================== LINUX DEFENSE ====================

@defense_bp.route('/linux')
@login_required
def linux_index():
    return render_template('defense_linux.html')


@defense_bp.route('/linux/audit', methods=['POST'])
@login_required
def linux_audit():
    """Run full Linux security audit."""
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


@defense_bp.route('/linux/check/<check_name>', methods=['POST'])
@login_required
def linux_check(check_name):
    """Run individual Linux security check."""
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


@defense_bp.route('/linux/firewall/rules')
@login_required
def linux_firewall_rules():
    """Get current iptables rules."""
    success, output = _run_cmd("sudo iptables -L -n --line-numbers 2>/dev/null")
    if success:
        return jsonify({'rules': output})
    return jsonify({'rules': 'Could not read iptables rules (need sudo privileges)'})


@defense_bp.route('/linux/firewall/block', methods=['POST'])
@login_required
def linux_firewall_block():
    """Block an IP address via iptables."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    success, _ = _run_cmd(f"sudo iptables -A INPUT -s {ip} -j DROP")
    if success:
        return jsonify({'message': f'Blocked {ip}', 'success': True})
    return jsonify({'error': f'Failed to block {ip} (need sudo)', 'success': False})


@defense_bp.route('/linux/firewall/unblock', methods=['POST'])
@login_required
def linux_firewall_unblock():
    """Unblock an IP address via iptables."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    success, _ = _run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
    if success:
        return jsonify({'message': f'Unblocked {ip}', 'success': True})
    return jsonify({'error': f'Failed to unblock {ip}', 'success': False})


@defense_bp.route('/linux/logs/analyze', methods=['POST'])
@login_required
def linux_logs_analyze():
    """Analyze auth and web logs (Linux)."""
    from modules.defender import Defender
    d = Defender()
    auth_results = d._analyze_auth_log()
    web_results = d._analyze_web_logs()

    return jsonify({
        'auth_results': auth_results[:20],
        'web_results': web_results[:20],
    })


# ==================== WINDOWS DEFENSE ====================

@defense_bp.route('/windows')
@login_required
def windows_index():
    """Windows defense sub-page."""
    return render_template('defense_windows.html')


@defense_bp.route('/windows/audit', methods=['POST'])
@login_required
def windows_audit():
    """Run full Windows security audit."""
    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()
    d.check_firewall()
    d.check_ssh_config()
    d.check_open_ports()
    d.check_updates()
    d.check_users()
    d.check_permissions()
    d.check_services()
    d.check_defender()
    d.check_uac()

    passed = sum(1 for r in d.results if r['passed'])
    total = len(d.results)
    score = int((passed / total) * 100) if total > 0 else 0

    return jsonify({
        'score': score,
        'passed': passed,
        'total': total,
        'checks': d.results
    })


@defense_bp.route('/windows/check/<check_name>', methods=['POST'])
@login_required
def windows_check(check_name):
    """Run individual Windows security check."""
    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()

    checks_map = {
        'firewall': d.check_firewall,
        'ssh': d.check_ssh_config,
        'ports': d.check_open_ports,
        'updates': d.check_updates,
        'users': d.check_users,
        'permissions': d.check_permissions,
        'services': d.check_services,
        'defender': d.check_defender,
        'uac': d.check_uac,
    }

    func = checks_map.get(check_name)
    if not func:
        return jsonify({'error': f'Unknown check: {check_name}'}), 400

    func()
    return jsonify({'checks': d.results})


@defense_bp.route('/windows/firewall/rules')
@login_required
def windows_firewall_rules():
    """Get Windows Firewall rules."""
    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()
    success, output = d.get_firewall_rules()
    if success:
        return jsonify({'rules': output})
    return jsonify({'rules': 'Could not read Windows Firewall rules (need admin privileges)'})


@defense_bp.route('/windows/firewall/block', methods=['POST'])
@login_required
def windows_firewall_block():
    """Block an IP via Windows Firewall."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()
    success, message = d.block_ip(ip)
    return jsonify({'message': message, 'success': success})


@defense_bp.route('/windows/firewall/unblock', methods=['POST'])
@login_required
def windows_firewall_unblock():
    """Unblock an IP via Windows Firewall."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()
    success, message = d.unblock_ip(ip)
    return jsonify({'message': message, 'success': success})


@defense_bp.route('/windows/logs/analyze', methods=['POST'])
@login_required
def windows_logs_analyze():
    """Analyze Windows Event Logs."""
    from modules.defender_windows import WindowsDefender
    d = WindowsDefender()
    auth_results, system_results = d.analyze_event_logs()

    return jsonify({
        'auth_results': auth_results[:20],
        'system_results': system_results[:20],
    })


# ==================== THREAT MONITOR ====================


def _get_monitor():
    """Get singleton ThreatMonitor instance."""
    from modules.defender_monitor import get_threat_monitor
    return get_threat_monitor()


@defense_bp.route('/monitor')
@login_required
def monitor_index():
    """Threat Monitor sub-page."""
    return render_template('defense_monitor.html')


@defense_bp.route('/monitor/stream')
@login_required
def monitor_stream():
    """SSE stream of real-time threat data."""
    return Response(stream_with_context(_get_monitor().monitor_stream()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@defense_bp.route('/monitor/connections', methods=['POST'])
@login_required
def monitor_connections():
    """Get current network connections."""
    m = _get_monitor()
    connections = m.get_connections()
    return jsonify({'connections': connections, 'total': len(connections)})


@defense_bp.route('/monitor/processes', methods=['POST'])
@login_required
def monitor_processes():
    """Get suspicious processes."""
    m = _get_monitor()
    processes = m.get_suspicious_processes()
    return jsonify({'processes': processes, 'total': len(processes)})


@defense_bp.route('/monitor/threats', methods=['POST'])
@login_required
def monitor_threats():
    """Get threat score and summary."""
    m = _get_monitor()
    report = m.generate_threat_report()
    return jsonify(report)


@defense_bp.route('/monitor/block-ip', methods=['POST'])
@login_required
def monitor_block_ip():
    """Counter-attack: block an IP."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    success, message = _get_monitor().auto_block_ip(ip)
    return jsonify({'message': message, 'success': success})


@defense_bp.route('/monitor/kill-process', methods=['POST'])
@login_required
def monitor_kill_process():
    """Counter-attack: kill a process."""
    data = request.get_json(silent=True) or {}
    pid = data.get('pid')
    if not pid:
        return jsonify({'error': 'No PID provided', 'success': False})

    success, message = _get_monitor().kill_process(pid)
    return jsonify({'message': message, 'success': success})


@defense_bp.route('/monitor/block-port', methods=['POST'])
@login_required
def monitor_block_port():
    """Counter-attack: block a port."""
    data = request.get_json(silent=True) or {}
    port = data.get('port')
    direction = data.get('direction', 'in')
    if not port:
        return jsonify({'error': 'No port provided', 'success': False})

    success, message = _get_monitor().block_port(port, direction)
    return jsonify({'message': message, 'success': success})


@defense_bp.route('/monitor/blocklist')
@login_required
def monitor_blocklist_get():
    """Get persistent blocklist."""
    return jsonify({'blocked_ips': _get_monitor().get_blocklist()})


@defense_bp.route('/monitor/blocklist', methods=['POST'])
@login_required
def monitor_blocklist_add():
    """Add IP to persistent blocklist."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})

    blocklist = _get_monitor().add_to_blocklist(ip)
    return jsonify({'blocked_ips': blocklist, 'success': True})


@defense_bp.route('/monitor/blocklist/remove', methods=['POST'])
@login_required
def monitor_blocklist_remove():
    """Remove IP from persistent blocklist."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP provided', 'success': False})

    blocklist = _get_monitor().remove_from_blocklist(ip)
    return jsonify({'blocked_ips': blocklist, 'success': True})


# ==================== MONITORING: BANDWIDTH, ARP, PORTS, GEOIP, CONN RATE ====================

@defense_bp.route('/monitor/bandwidth', methods=['POST'])
@login_required
def monitor_bandwidth():
    """Get bandwidth stats per interface."""
    return jsonify({'interfaces': _get_monitor().get_bandwidth()})


@defense_bp.route('/monitor/arp-check', methods=['POST'])
@login_required
def monitor_arp_check():
    """Check for ARP spoofing."""
    alerts = _get_monitor().check_arp_spoofing()
    return jsonify({'alerts': alerts, 'total': len(alerts)})


@defense_bp.route('/monitor/new-ports', methods=['POST'])
@login_required
def monitor_new_ports():
    """Check for new listening ports."""
    ports = _get_monitor().check_new_listening_ports()
    return jsonify({'new_ports': ports, 'total': len(ports)})


@defense_bp.route('/monitor/geoip', methods=['POST'])
@login_required
def monitor_geoip():
    """GeoIP lookup for an IP."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP provided'}), 400
    result = _get_monitor().geoip_lookup(ip)
    if result:
        return jsonify(result)
    return jsonify({'ip': ip, 'error': 'Private IP or lookup failed'})


@defense_bp.route('/monitor/connections-geo', methods=['POST'])
@login_required
def monitor_connections_geo():
    """Get connections enriched with GeoIP data."""
    connections = _get_monitor().get_connections_with_geoip()
    return jsonify({'connections': connections, 'total': len(connections)})


@defense_bp.route('/monitor/connection-rate', methods=['POST'])
@login_required
def monitor_connection_rate():
    """Get connection rate stats."""
    return jsonify(_get_monitor().get_connection_rate())


# ==================== PACKET CAPTURE (via WiresharkManager) ====================

@defense_bp.route('/monitor/capture/interfaces')
@login_required
def monitor_capture_interfaces():
    """Get available network interfaces for capture."""
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    return jsonify({'interfaces': wm.list_interfaces()})


@defense_bp.route('/monitor/capture/start', methods=['POST'])
@login_required
def monitor_capture_start():
    """Start packet capture."""
    data = request.get_json(silent=True) or {}
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    result = wm.start_capture(
        interface=data.get('interface', ''),
        bpf_filter=data.get('filter', ''),
        duration=int(data.get('duration', 30)),
    )
    return jsonify(result)


@defense_bp.route('/monitor/capture/stop', methods=['POST'])
@login_required
def monitor_capture_stop():
    """Stop packet capture."""
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    result = wm.stop_capture()
    return jsonify(result)


@defense_bp.route('/monitor/capture/stats')
@login_required
def monitor_capture_stats():
    """Get capture statistics."""
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    return jsonify(wm.get_capture_stats())


@defense_bp.route('/monitor/capture/stream')
@login_required
def monitor_capture_stream():
    """SSE stream of captured packets."""
    import time as _time
    from core.wireshark import get_wireshark_manager
    mgr = get_wireshark_manager()

    def generate():
        last_count = 0
        while mgr._capture_running:
            stats = mgr.get_capture_stats()
            count = stats.get('packet_count', 0)
            if count > last_count:
                new_packets = mgr._capture_packets[last_count:count]
                for pkt in new_packets:
                    yield f'data: {json.dumps({"type": "packet", **pkt})}\n\n'
                last_count = count
            yield f'data: {json.dumps({"type": "stats", "packet_count": count, "running": True})}\n\n'
            _time.sleep(0.5)
        stats = mgr.get_capture_stats()
        yield f'data: {json.dumps({"type": "done", **stats})}\n\n'

    return Response(stream_with_context(generate()),
                    mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@defense_bp.route('/monitor/capture/protocols', methods=['POST'])
@login_required
def monitor_capture_protocols():
    """Get protocol distribution from captured packets."""
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    return jsonify({'protocols': wm.get_protocol_hierarchy()})


@defense_bp.route('/monitor/capture/conversations', methods=['POST'])
@login_required
def monitor_capture_conversations():
    """Get top conversations from captured packets."""
    from core.wireshark import get_wireshark_manager
    wm = get_wireshark_manager()
    return jsonify({'conversations': wm.extract_conversations()})


# ==================== DDOS MITIGATION ====================

@defense_bp.route('/monitor/ddos/detect', methods=['POST'])
@login_required
def monitor_ddos_detect():
    """Detect DDoS/DoS attack patterns."""
    return jsonify(_get_monitor().detect_ddos())


@defense_bp.route('/monitor/ddos/top-talkers', methods=['POST'])
@login_required
def monitor_ddos_top_talkers():
    """Get top source IPs by connection count."""
    data = request.get_json(silent=True) or {}
    limit = int(data.get('limit', 20))
    return jsonify({'talkers': _get_monitor().get_top_talkers(limit)})


@defense_bp.route('/monitor/ddos/rate-limit', methods=['POST'])
@login_required
def monitor_ddos_rate_limit():
    """Apply rate limit to an IP."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    rate = data.get('rate', '25/min')
    if not ip or not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return jsonify({'error': 'Invalid IP address', 'success': False})
    success, msg = _get_monitor().apply_rate_limit(ip, rate)
    return jsonify({'message': msg, 'success': success})


@defense_bp.route('/monitor/ddos/rate-limit/remove', methods=['POST'])
@login_required
def monitor_ddos_rate_limit_remove():
    """Remove rate limit from an IP."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP provided', 'success': False})
    success, msg = _get_monitor().remove_rate_limit(ip)
    return jsonify({'message': msg, 'success': success})


@defense_bp.route('/monitor/ddos/syn-status')
@login_required
def monitor_ddos_syn_status():
    """Check SYN flood protection status."""
    return jsonify(_get_monitor().get_syn_protection_status())


@defense_bp.route('/monitor/ddos/syn-enable', methods=['POST'])
@login_required
def monitor_ddos_syn_enable():
    """Enable SYN flood protection."""
    success, msg = _get_monitor().enable_syn_protection()
    return jsonify({'message': msg, 'success': success})


@defense_bp.route('/monitor/ddos/syn-disable', methods=['POST'])
@login_required
def monitor_ddos_syn_disable():
    """Disable SYN flood protection."""
    success, msg = _get_monitor().disable_syn_protection()
    return jsonify({'message': msg, 'success': success})


@defense_bp.route('/monitor/ddos/config')
@login_required
def monitor_ddos_config_get():
    """Get DDoS auto-mitigation config."""
    return jsonify(_get_monitor().get_ddos_config())


@defense_bp.route('/monitor/ddos/config', methods=['POST'])
@login_required
def monitor_ddos_config_save():
    """Save DDoS auto-mitigation config."""
    data = request.get_json(silent=True) or {}
    config = _get_monitor().save_ddos_config(data)
    return jsonify({'config': config, 'success': True})


@defense_bp.route('/monitor/ddos/auto-mitigate', methods=['POST'])
@login_required
def monitor_ddos_auto_mitigate():
    """Run auto-mitigation."""
    result = _get_monitor().auto_mitigate()
    return jsonify(result)


@defense_bp.route('/monitor/ddos/history')
@login_required
def monitor_ddos_history():
    """Get mitigation history."""
    return jsonify({'history': _get_monitor().get_mitigation_history()})


@defense_bp.route('/monitor/ddos/history/clear', methods=['POST'])
@login_required
def monitor_ddos_history_clear():
    """Clear mitigation history."""
    _get_monitor().clear_mitigation_history()
    return jsonify({'success': True})
