"""Hardware route - ADB/Fastboot device management and ESP32 serial flashing."""

import json
import time
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from web.auth import login_required

hardware_bp = Blueprint('hardware', __name__, url_prefix='/hardware')


@hardware_bp.route('/')
@login_required
def index():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    status = mgr.get_status()
    return render_template('hardware.html', status=status)


@hardware_bp.route('/status')
@login_required
def status():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    return jsonify(mgr.get_status())


# ── ADB Endpoints ──────────────────────────────────────────────────

@hardware_bp.route('/adb/kill-server', methods=['POST'])
@login_required
def adb_kill_server():
    """Kill the ADB server."""
    from core.daemon import root_exec
    r = root_exec(['adb', 'kill-server'], timeout=10)
    return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr']})


@hardware_bp.route('/adb/start-server', methods=['POST'])
@login_required
def adb_start_server():
    """Start the ADB server."""
    from core.daemon import root_exec
    r = root_exec(['adb', 'start-server'], timeout=10)
    return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr']})


@hardware_bp.route('/adb/devices')
@login_required
def adb_devices():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    return jsonify({'devices': mgr.adb_devices()})


@hardware_bp.route('/adb/info', methods=['POST'])
@login_required
def adb_info():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(mgr.adb_device_info(serial))


@hardware_bp.route('/adb/shell', methods=['POST'])
@login_required
def adb_shell():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    command = data.get('command', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if not command:
        return jsonify({'error': 'No command provided'})
    result = mgr.adb_shell(serial, command)
    return jsonify({
        'stdout': result.get('output', ''),
        'stderr': '',
        'exit_code': result.get('returncode', -1),
    })


@hardware_bp.route('/adb/reboot', methods=['POST'])
@login_required
def adb_reboot():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    mode = data.get('mode', 'system').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if mode not in ('system', 'recovery', 'bootloader'):
        return jsonify({'error': 'Invalid mode'})
    return jsonify(mgr.adb_reboot(serial, mode))


@hardware_bp.route('/adb/sideload', methods=['POST'])
@login_required
def adb_sideload():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    filepath = data.get('filepath', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if not filepath:
        return jsonify({'error': 'No filepath provided'})
    return jsonify(mgr.adb_sideload(serial, filepath))


@hardware_bp.route('/adb/push', methods=['POST'])
@login_required
def adb_push():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    local_path = data.get('local', '').strip()
    remote_path = data.get('remote', '').strip()
    if not serial or not local_path or not remote_path:
        return jsonify({'error': 'Missing serial, local, or remote path'})
    return jsonify(mgr.adb_push(serial, local_path, remote_path))


@hardware_bp.route('/adb/pull', methods=['POST'])
@login_required
def adb_pull():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    remote_path = data.get('remote', '').strip()
    if not serial or not remote_path:
        return jsonify({'error': 'Missing serial or remote path'})
    return jsonify(mgr.adb_pull(serial, remote_path))


@hardware_bp.route('/adb/logcat', methods=['POST'])
@login_required
def adb_logcat():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    lines = int(data.get('lines', 100))
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(mgr.adb_logcat(serial, lines))


@hardware_bp.route('/archon/bootstrap', methods=['POST'])
def archon_bootstrap():
    """Bootstrap ArchonServer on a USB-connected Android device.

    No auth required — this is called by the companion app itself.
    Only runs the specific app_process bootstrap command (not arbitrary shell).
    """
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()

    data = request.get_json(silent=True) or {}
    apk_path = data.get('apk_path', '').strip()
    token = data.get('token', '').strip()
    port = int(data.get('port', 17321))

    if not apk_path or not token:
        return jsonify({'ok': False, 'error': 'Missing apk_path or token'}), 400

    # Validate inputs to prevent injection
    if not apk_path.startswith('/data/app/') or "'" in apk_path or '"' in apk_path:
        return jsonify({'ok': False, 'error': 'Invalid APK path'}), 400
    if not token.isalnum() or len(token) > 64:
        return jsonify({'ok': False, 'error': 'Invalid token'}), 400
    if port < 1024 or port > 65535:
        return jsonify({'ok': False, 'error': 'Invalid port'}), 400

    # Find USB-connected device
    devices = mgr.adb_devices()
    usb_devices = [d for d in devices if ':' not in d.get('serial', '')]
    if not usb_devices:
        usb_devices = devices
    if not usb_devices:
        return jsonify({'ok': False, 'error': 'No ADB devices connected'}), 404

    serial = usb_devices[0].get('serial', '')

    # Construct the bootstrap command (server-side, safe)
    cmd = (
        f"TMPDIR=/data/local/tmp "
        f"CLASSPATH='{apk_path}' "
        f"nohup /system/bin/app_process /system/bin "
        f"com.darkhal.archon.server.ArchonServer {token} {port} "
        f"> /data/local/tmp/archon_server.log 2>&1 & echo started"
    )

    result = mgr.adb_shell(serial, cmd)
    output = result.get('output', '')
    exit_code = result.get('returncode', -1)

    if exit_code == 0 or 'started' in output:
        return jsonify({'ok': True, 'stdout': output, 'stderr': '', 'exit_code': exit_code})
    else:
        return jsonify({'ok': False, 'stdout': output, 'stderr': '', 'exit_code': exit_code})


@hardware_bp.route('/adb/setup-tcp', methods=['POST'])
@login_required
def adb_setup_tcp():
    """Enable ADB TCP/IP mode on a USB-connected device.
    Called by the Archon companion app to set up remote ADB access.
    Finds the first USB-connected device, enables TCP mode on port 5555,
    and returns the device's IP address for wireless connection."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()

    data = request.get_json(silent=True) or {}
    port = int(data.get('port', 5555))
    serial = data.get('serial', '').strip()

    # Find a USB-connected device if no serial specified
    if not serial:
        devices = mgr.adb_devices()
        usb_devices = [d for d in devices if 'usb' in d.get('type', '').lower()
                       or ':' not in d.get('serial', '')]
        if not usb_devices:
            # Fall back to any connected device
            usb_devices = devices
        if not usb_devices:
            return jsonify({'ok': False, 'error': 'No ADB devices connected via USB'})
        serial = usb_devices[0].get('serial', '')

    if not serial:
        return jsonify({'ok': False, 'error': 'No device serial available'})

    # Get device IP address before switching to TCP mode
    ip_result = mgr.adb_shell(serial, 'ip route show default 2>/dev/null | grep -oP "src \\K[\\d.]+"')
    device_ip = ip_result.get('stdout', '').strip() if ip_result.get('exit_code', -1) == 0 else ''

    # Enable TCP/IP mode
    result = mgr.adb_shell(serial, f'setprop service.adb.tcp.port {port}')
    if result.get('exit_code', -1) != 0:
        return jsonify({'ok': False, 'error': f'Failed to set TCP port: {result.get("stderr", "")}'})

    # Restart adbd to apply
    mgr.adb_shell(serial, 'stop adbd && start adbd')

    return jsonify({
        'ok': True,
        'serial': serial,
        'ip': device_ip,
        'port': port,
        'message': f'ADB TCP mode enabled on {device_ip}:{port}'
    })


# ── Fastboot Endpoints ─────────────────────────────────────────────

@hardware_bp.route('/fastboot/devices')
@login_required
def fastboot_devices():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    return jsonify({'devices': mgr.fastboot_devices()})


@hardware_bp.route('/fastboot/info', methods=['POST'])
@login_required
def fastboot_info():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(mgr.fastboot_device_info(serial))


@hardware_bp.route('/fastboot/flash', methods=['POST'])
@login_required
def fastboot_flash():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    partition = data.get('partition', '').strip()
    filepath = data.get('filepath', '').strip()
    if not serial or not partition or not filepath:
        return jsonify({'error': 'Missing serial, partition, or filepath'})
    return jsonify(mgr.fastboot_flash(serial, partition, filepath))


@hardware_bp.route('/fastboot/reboot', methods=['POST'])
@login_required
def fastboot_reboot():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    mode = data.get('mode', 'system').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    if mode not in ('system', 'bootloader', 'recovery'):
        return jsonify({'error': 'Invalid mode'})
    return jsonify(mgr.fastboot_reboot(serial, mode))


@hardware_bp.route('/fastboot/unlock', methods=['POST'])
@login_required
def fastboot_unlock():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    serial = data.get('serial', '').strip()
    if not serial:
        return jsonify({'error': 'No serial provided'})
    return jsonify(mgr.fastboot_oem_unlock(serial))


# ── Operation Progress SSE ──────────────────────────────────────────

@hardware_bp.route('/progress/stream')
@login_required
def progress_stream():
    """SSE stream for operation progress (sideload, flash, etc.)."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    op_id = request.args.get('op_id', '')

    def generate():
        while True:
            prog = mgr.get_operation_progress(op_id)
            yield f'data: {json.dumps(prog)}\n\n'
            if prog.get('status') in ('done', 'error', 'unknown'):
                break
            time.sleep(0.5)

    return Response(stream_with_context(generate()), content_type='text/event-stream')


# ── Serial / ESP32 Endpoints ──────────────────────────────────────

@hardware_bp.route('/serial/ports')
@login_required
def serial_ports():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    return jsonify({'ports': mgr.list_serial_ports()})


@hardware_bp.route('/serial/detect', methods=['POST'])
@login_required
def serial_detect():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    port = data.get('port', '').strip()
    baud = int(data.get('baud', 115200))
    if not port:
        return jsonify({'error': 'No port provided'})
    return jsonify(mgr.detect_esp_chip(port, baud))


@hardware_bp.route('/serial/flash', methods=['POST'])
@login_required
def serial_flash():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    port = data.get('port', '').strip()
    filepath = data.get('filepath', '').strip()
    baud = int(data.get('baud', 460800))
    if not port or not filepath:
        return jsonify({'error': 'Missing port or filepath'})
    return jsonify(mgr.flash_esp(port, filepath, baud))


@hardware_bp.route('/serial/monitor/start', methods=['POST'])
@login_required
def monitor_start():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    port = data.get('port', '').strip()
    baud = int(data.get('baud', 115200))
    if not port:
        return jsonify({'error': 'No port provided'})
    return jsonify(mgr.serial_monitor_start(port, baud))


@hardware_bp.route('/serial/monitor/stop', methods=['POST'])
@login_required
def monitor_stop():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    return jsonify(mgr.serial_monitor_stop())


@hardware_bp.route('/serial/monitor/send', methods=['POST'])
@login_required
def monitor_send():
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    text = data.get('data', '')
    return jsonify(mgr.serial_monitor_send(text))


@hardware_bp.route('/serial/monitor/stream')
@login_required
def monitor_stream():
    """SSE stream for serial monitor output."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()

    def generate():
        last_index = 0
        while mgr.monitor_running:
            result = mgr.serial_monitor_get_output(last_index)
            if result['lines']:
                for line in result['lines']:
                    yield f'data: {json.dumps({"type": "data", "line": line["data"]})}\n\n'
                last_index = result['total']
            yield f'data: {json.dumps({"type": "status", "running": True, "total": result["total"]})}\n\n'
            time.sleep(0.3)
        yield f'data: {json.dumps({"type": "stopped"})}\n\n'

    return Response(stream_with_context(generate()), content_type='text/event-stream')
