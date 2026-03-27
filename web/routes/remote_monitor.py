"""Remote Monitoring Station — load .piap device profiles and control remote radios."""

import configparser
import logging
import os
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify

logger = logging.getLogger(__name__)

remote_monitor_bp = Blueprint('remote_monitor', __name__, url_prefix='/remote-monitor')

PIAP_DIR = Path(__file__).parent.parent.parent / 'data' / 'piap'
CAPTURE_DIR = Path(__file__).parent.parent.parent / 'data' / 'captures'

_ssh_sessions = {}
_capture_threads = {}


def _parse_piap(filepath):
    """Parse a .piap file into a dict structure."""
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read(filepath)

    device = dict(cfg['device']) if 'device' in cfg else {}
    connection = dict(cfg['connection']) if 'connection' in cfg else {}

    radios = []
    i = 0
    while f'radio_{i}' in cfg:
        radio = dict(cfg[f'radio_{i}'])
        radio['index'] = i
        if 'channels' in radio:
            radio['channel_list'] = [c.strip() for c in radio['channels'].split(',')]
        if 'modes' in radio:
            radio['mode_list'] = [m.strip() for m in radio['modes'].split(',')]
        radios.append(radio)
        i += 1

    features = dict(cfg['features']) if 'features' in cfg else {}
    info_cmds = dict(cfg['info']) if 'info' in cfg else {}

    return {
        'device': device,
        'connection': connection,
        'radios': radios,
        'features': features,
        'info': info_cmds,
        'filename': os.path.basename(filepath),
    }


def _ssh_cmd(conn, cmd, timeout=15):
    """Run a command on the remote device over SSH."""
    host = conn.get('host', '')
    port = conn.get('port', '22')
    user = conn.get('user', 'root')
    auth = conn.get('auth', 'key')
    key_path = conn.get('key_path', '')
    password = conn.get('password', '')
    ssh_timeout = conn.get('timeout', '10')

    ssh_args = ['ssh', '-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=' + ssh_timeout,
                '-p', port]

    if auth == 'key' and key_path:
        ssh_args += ['-i', key_path]

    ssh_args.append(f'{user}@{host}')
    ssh_args.append(cmd)

    try:
        r = subprocess.run(ssh_args, capture_output=True, text=True, timeout=timeout)
        return {'ok': r.returncode == 0, 'stdout': r.stdout.strip(), 'stderr': r.stderr.strip(), 'code': r.returncode}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'stdout': '', 'stderr': 'timeout', 'code': -1}
    except Exception as e:
        return {'ok': False, 'stdout': '', 'stderr': str(e), 'code': -1}


def _expand_cmd(cmd_template, radio=None, channel=None, bssid=None, count=None, timestamp=None):
    """Replace {variables} in a command template."""
    if not cmd_template:
        return ''
    cmd = cmd_template
    if radio:
        cmd = cmd.replace('{phy}', radio.get('phy', ''))
        cmd = cmd.replace('{interface}', radio.get('interface', ''))
        cmd = cmd.replace('{mon}', radio.get('monitor_interface', ''))
        cmd = cmd.replace('{channels}', radio.get('channels', ''))
    if channel:
        cmd = cmd.replace('{channel}', str(channel))
    elif radio:
        cmd = cmd.replace('{channel}', radio.get('default_channel', '1'))
    if bssid:
        cmd = cmd.replace('{bssid}', bssid)
    if count:
        cmd = cmd.replace('{count}', str(count))
    if timestamp is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    cmd = cmd.replace('{timestamp}', timestamp)
    return cmd


# ── Routes ──────────────────────────────────────────────────────────────────

@remote_monitor_bp.route('/')
def index():
    """Main page — loads available .piap files for dropdown."""
    piap_files = []
    for f in sorted(PIAP_DIR.glob('*.piap')):
        if f.name == 'template.piap':
            continue
        try:
            p = _parse_piap(f)
            piap_files.append({'filename': f.name, 'name': p['device'].get('name', f.stem)})
        except Exception as e:
            logger.warning("Failed to parse %s: %s", f, e)
    return render_template('remote_monitor.html', piap_files=piap_files)


@remote_monitor_bp.route('/api/load', methods=['POST'])
def load_piap():
    """Load a .piap file and return its full config."""
    filename = request.json.get('filename', '')
    filepath = PIAP_DIR / filename
    if not filepath.exists() or not filepath.suffix == '.piap':
        return jsonify({'ok': False, 'error': 'File not found'}), 404
    try:
        data = _parse_piap(filepath)
        return jsonify({'ok': True, 'data': data})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@remote_monitor_bp.route('/api/connect', methods=['POST'])
def connect():
    """Test SSH connection to the remote device."""
    conn = request.json.get('connection', {})
    result = _ssh_cmd(conn, 'echo ok')
    return jsonify(result)


@remote_monitor_bp.route('/api/info', methods=['POST'])
def device_info():
    """Get device info (uptime, memory, kernel, etc)."""
    conn = request.json.get('connection', {})
    info_cmds = request.json.get('info', {})
    results = {}
    for key, cmd in info_cmds.items():
        if key.startswith('cmd_'):
            label = key[4:]
            r = _ssh_cmd(conn, cmd)
            results[label] = r.get('stdout', r.get('stderr', ''))
    return jsonify({'ok': True, 'info': results})


@remote_monitor_bp.route('/api/radio/status', methods=['POST'])
def radio_status():
    """Get status of a specific radio."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    cmd = _expand_cmd(radio.get('cmd_status', 'iw dev'), radio)
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/radio/monitor-on', methods=['POST'])
def monitor_on():
    """Enable monitor mode on a radio."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    channel = request.json.get('channel', radio.get('default_channel', '1'))
    cmd = _expand_cmd(radio.get('cmd_monitor_on', ''), radio, channel=channel)
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/radio/monitor-off', methods=['POST'])
def monitor_off():
    """Disable monitor mode on a radio."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    cmd = _expand_cmd(radio.get('cmd_monitor_off', ''), radio)
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/radio/set-channel', methods=['POST'])
def set_channel():
    """Set channel on a monitor interface."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    channel = request.json.get('channel', '1')
    cmd = _expand_cmd(radio.get('cmd_set_channel', ''), radio, channel=channel)
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/capture/start', methods=['POST'])
def capture_start():
    """Start packet capture on remote device."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    features = request.json.get('features', {})
    cmd = _expand_cmd(features.get('cmd_capture_start', ''), radio)
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/capture/stop', methods=['POST'])
def capture_stop():
    """Stop packet capture on remote device."""
    conn = request.json.get('connection', {})
    features = request.json.get('features', {})
    cmd = features.get('cmd_capture_stop', 'killall tcpdump 2>/dev/null')
    result = _ssh_cmd(conn, cmd)
    return jsonify(result)


@remote_monitor_bp.route('/api/scan', methods=['POST'])
def wifi_scan():
    """Run passive WiFi scan."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    features = request.json.get('features', {})
    cmd = _expand_cmd(features.get('cmd_wifi_scan', ''), radio)
    result = _ssh_cmd(conn, cmd, timeout=30)
    return jsonify(result)


@remote_monitor_bp.route('/api/deauth', methods=['POST'])
def deauth():
    """Send deauth frames."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio', {})
    features = request.json.get('features', {})
    bssid = request.json.get('bssid', '')
    count = request.json.get('count', '10')
    cmd = _expand_cmd(features.get('cmd_deauth', ''), radio, bssid=bssid, count=count)
    result = _ssh_cmd(conn, cmd, timeout=30)
    return jsonify(result)


@remote_monitor_bp.route('/api/exec', methods=['POST'])
def exec_cmd():
    """Execute an arbitrary command on the remote device."""
    conn = request.json.get('connection', {})
    radio = request.json.get('radio')
    cmd = request.json.get('cmd', '')
    if radio:
        cmd = _expand_cmd(cmd, radio)
    result = _ssh_cmd(conn, cmd, timeout=30)
    return jsonify(result)


@remote_monitor_bp.route('/api/piap/list')
def list_piaps():
    """List available .piap files."""
    piap_files = []
    for f in sorted(PIAP_DIR.glob('*.piap')):
        if f.name == 'template.piap':
            continue
        try:
            p = _parse_piap(f)
            piap_files.append({'filename': f.name, 'name': p['device'].get('name', f.stem)})
        except:
            pass
    return jsonify({'ok': True, 'files': piap_files})
