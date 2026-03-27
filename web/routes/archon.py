"""Archon route — privileged Android device management via ArchonServer."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

archon_bp = Blueprint('archon', __name__, url_prefix='/archon')


@archon_bp.route('/')
@login_required
def index():
    return render_template('archon.html')


@archon_bp.route('/shell', methods=['POST'])
@login_required
def shell():
    """Run a shell command on the connected device via ADB."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    command = data.get('command', '').strip()
    if not command:
        return jsonify({'error': 'No command'})

    # Find connected device
    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'stdout': '', 'stderr': 'No ADB device connected', 'exit_code': -1})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, command)
    return jsonify({
        'stdout': result.get('output', ''),
        'stderr': '',
        'exit_code': result.get('returncode', -1),
    })


@archon_bp.route('/pull', methods=['POST'])
@login_required
def pull():
    """Pull a file from device to AUTARCH server."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    remote = data.get('remote', '').strip()
    if not remote:
        return jsonify({'error': 'No remote path'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No ADB device connected'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_pull(serial, remote)
    return jsonify(result)


@archon_bp.route('/push', methods=['POST'])
@login_required
def push():
    """Push a file from AUTARCH server to device."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    local = data.get('local', '').strip()
    remote = data.get('remote', '').strip()
    if not local or not remote:
        return jsonify({'error': 'Missing local or remote path'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No ADB device connected'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_push(serial, local, remote)
    return jsonify(result)


@archon_bp.route('/packages', methods=['GET'])
@login_required
def packages():
    """List installed packages."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    show_system = request.args.get('system', 'false') == 'true'
    flag = '-f' if not show_system else '-f -s'
    result = mgr.adb_shell(serial, f'pm list packages {flag}')
    output = result.get('output', '')

    pkgs = []
    for line in output.strip().split('\n'):
        if line.startswith('package:'):
            # format: package:/path/to/apk=com.package.name
            parts = line[8:].split('=', 1)
            if len(parts) == 2:
                pkgs.append({'apk': parts[0], 'package': parts[1]})
            else:
                pkgs.append({'apk': '', 'package': parts[0]})

    return jsonify({'packages': pkgs, 'count': len(pkgs)})


@archon_bp.route('/grant', methods=['POST'])
@login_required
def grant_permission():
    """Grant a permission to a package."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    package = data.get('package', '').strip()
    permission = data.get('permission', '').strip()
    if not package or not permission:
        return jsonify({'error': 'Missing package or permission'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, f'pm grant {package} {permission}')
    return jsonify({
        'success': result.get('returncode', -1) == 0,
        'output': result.get('output', ''),
    })


@archon_bp.route('/revoke', methods=['POST'])
@login_required
def revoke_permission():
    """Revoke a permission from a package."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    package = data.get('package', '').strip()
    permission = data.get('permission', '').strip()
    if not package or not permission:
        return jsonify({'error': 'Missing package or permission'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, f'pm revoke {package} {permission}')
    return jsonify({
        'success': result.get('returncode', -1) == 0,
        'output': result.get('output', ''),
    })


@archon_bp.route('/app-ops', methods=['POST'])
@login_required
def app_ops():
    """Set an appops permission for a package."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    package = data.get('package', '').strip()
    op = data.get('op', '').strip()
    mode = data.get('mode', '').strip()  # allow, deny, ignore, default
    if not package or not op or not mode:
        return jsonify({'error': 'Missing package, op, or mode'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, f'cmd appops set {package} {op} {mode}')
    return jsonify({
        'success': result.get('returncode', -1) == 0,
        'output': result.get('output', ''),
    })


@archon_bp.route('/settings-cmd', methods=['POST'])
@login_required
def settings_cmd():
    """Read or write Android system settings."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    namespace = data.get('namespace', 'system').strip()  # system, secure, global
    action = data.get('action', 'get').strip()  # get, put
    key = data.get('key', '').strip()
    value = data.get('value', '').strip()

    if namespace not in ('system', 'secure', 'global'):
        return jsonify({'error': 'Invalid namespace'})
    if not key:
        return jsonify({'error': 'Missing key'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')

    if action == 'put' and value:
        cmd = f'settings put {namespace} {key} {value}'
    else:
        cmd = f'settings get {namespace} {key}'

    result = mgr.adb_shell(serial, cmd)
    return jsonify({
        'value': result.get('output', '').strip(),
        'exit_code': result.get('returncode', -1),
    })


@archon_bp.route('/file-list', methods=['POST'])
@login_required
def file_list():
    """List files in a directory on the device."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    path = data.get('path', '/').strip()

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, f'ls -la {path}')
    return jsonify({
        'path': path,
        'output': result.get('output', ''),
        'exit_code': result.get('returncode', -1),
    })


@archon_bp.route('/file-copy', methods=['POST'])
@login_required
def file_copy():
    """Copy a file on the device (elevated shell can access protected paths)."""
    from core.hardware import get_hardware_manager
    mgr = get_hardware_manager()
    data = request.get_json(silent=True) or {}
    src = data.get('src', '').strip()
    dst = data.get('dst', '').strip()
    if not src or not dst:
        return jsonify({'error': 'Missing src or dst'})

    devices = mgr.adb_devices()
    if not devices:
        return jsonify({'error': 'No device'})

    serial = devices[0].get('serial', '')
    result = mgr.adb_shell(serial, f'cp -r {src} {dst}')
    return jsonify({
        'success': result.get('returncode', -1) == 0,
        'output': result.get('output', ''),
    })
