"""SSH / SSHD Configuration Manager routes."""

import logging
import os
import re
import tempfile
import time

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required
from core.daemon import root_exec

log = logging.getLogger(__name__)

ssh_manager_bp = Blueprint('ssh_manager', __name__, url_prefix='/ssh')

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_sshd_config(text: str) -> dict:
    """Parse sshd_config text into a dict of {directive: value} pairs.

    Handles comments, blank lines, and Match blocks (flattened).
    For repeated directives only the first occurrence is kept (sshd semantics).
    """
    result = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key, value = parts
        elif len(parts) == 1:
            key, value = parts[0], ''
        else:
            continue
        # sshd uses first-match semantics; keep only the first occurrence
        if key not in result:
            result[key] = value
    return result


# ─── Routes ──────────────────────────────────────────────────────────────────

@ssh_manager_bp.route('/')
@login_required
def index():
    """Render the SSH manager page."""
    return render_template('ssh_manager.html')


# ── Status ───────────────────────────────────────────────────────────────────

@ssh_manager_bp.route('/status', methods=['GET'])
@login_required
def status():
    """Return JSON with SSH service status."""
    # Check active state — try sshd first, then ssh
    active_result = root_exec('systemctl is-active sshd', timeout=10)
    if active_result.get('code', 1) != 0:
        active_result = root_exec('systemctl is-active ssh', timeout=10)
    active = active_result.get('stdout', '').strip()

    # Enabled state
    enabled_result = root_exec('systemctl is-enabled sshd', timeout=10)
    if enabled_result.get('code', 1) != 0:
        enabled_result = root_exec('systemctl is-enabled ssh', timeout=10)
    enabled = enabled_result.get('stdout', '').strip()

    # Config exists
    config_exists = os.path.isfile('/etc/ssh/sshd_config')

    # Version — sshd -V prints to stderr on OpenSSH
    ver_result = root_exec('sshd -V', timeout=10)
    version = (ver_result.get('stderr', '') + ver_result.get('stdout', '')).strip()
    # Often the first meaningful line is all we need
    if version:
        version = version.splitlines()[0]

    return jsonify({
        'ok': True,
        'active': active,
        'enabled': enabled,
        'config_exists': config_exists,
        'version': version,
    })


# ── Security Scan ────────────────────────────────────────────────────────────

@ssh_manager_bp.route('/scan', methods=['POST'])
@login_required
def scan():
    """Security scan of sshd_config."""
    result = root_exec('cat /etc/ssh/sshd_config', timeout=10)
    if not result.get('ok'):
        return jsonify({'ok': False, 'error': 'Failed to read sshd_config: ' + result.get('stderr', '')}), 500

    cfg = _parse_sshd_config(result['stdout'])
    checks = []

    def _add(name, severity, current, recommended, description, status='fail'):
        checks.append({
            'name': name,
            'status': status,
            'severity': severity,
            'current_value': current,
            'recommended': recommended,
            'description': description,
        })

    # PermitRootLogin
    val = cfg.get('PermitRootLogin', 'prohibit-password')
    if val.lower() == 'yes':
        _add('PermitRootLogin', 'CRITICAL', val, 'no', 'Root login with password is enabled — extremely dangerous.')
    else:
        _add('PermitRootLogin', 'CRITICAL', val, 'no', 'Root login is restricted.', 'pass')

    # PasswordAuthentication
    val = cfg.get('PasswordAuthentication', 'yes')
    if val.lower() == 'yes':
        _add('PasswordAuthentication', 'WARNING', val, 'no', 'Password authentication is enabled — prefer SSH keys.')
    else:
        _add('PasswordAuthentication', 'WARNING', val, 'no', 'Password authentication is disabled.', 'pass')

    # PermitEmptyPasswords
    val = cfg.get('PermitEmptyPasswords', 'no')
    if val.lower() == 'yes':
        _add('PermitEmptyPasswords', 'CRITICAL', val, 'no', 'Empty passwords are permitted — critical risk.')
    else:
        _add('PermitEmptyPasswords', 'CRITICAL', val, 'no', 'Empty passwords are not permitted.', 'pass')

    # X11Forwarding
    val = cfg.get('X11Forwarding', 'no')
    if val.lower() == 'yes':
        _add('X11Forwarding', 'LOW', val, 'no', 'X11 forwarding is enabled — consider disabling if not needed.')
    else:
        _add('X11Forwarding', 'LOW', val, 'no', 'X11 forwarding is disabled.', 'pass')

    # Port
    val = cfg.get('Port', '22')
    if val == '22':
        _add('Port', 'INFO', val, 'non-default', 'SSH is running on the default port — consider changing to reduce automated attacks.', 'info')
    else:
        _add('Port', 'INFO', val, 'non-default', 'SSH is running on a non-default port.', 'pass')

    # Protocol
    val = cfg.get('Protocol', '')
    if val == '1':
        _add('Protocol', 'CRITICAL', val, '2', 'SSHv1 is enabled — it has known vulnerabilities.')
    elif val:
        _add('Protocol', 'CRITICAL', val, '2', 'Protocol version is set.', 'pass')

    # MaxAuthTries
    val = cfg.get('MaxAuthTries', '6')
    try:
        if int(val) > 6:
            _add('MaxAuthTries', 'WARNING', val, '3-6', 'MaxAuthTries is high — allows excessive brute-force attempts.')
        else:
            _add('MaxAuthTries', 'WARNING', val, '3-6', 'MaxAuthTries is within acceptable range.', 'pass')
    except ValueError:
        _add('MaxAuthTries', 'WARNING', val, '3-6', 'Could not parse MaxAuthTries value.')

    # LoginGraceTime
    val = cfg.get('LoginGraceTime', '120')
    try:
        numeric = int(val.rstrip('smSM'))
        if numeric > 120:
            _add('LoginGraceTime', 'WARNING', val, '60-120', 'LoginGraceTime is too long — connections can linger.')
        else:
            _add('LoginGraceTime', 'WARNING', val, '60-120', 'LoginGraceTime is acceptable.', 'pass')
    except ValueError:
        _add('LoginGraceTime', 'WARNING', val, '60-120', 'Could not parse LoginGraceTime value.')

    # UsePAM
    val = cfg.get('UsePAM', 'yes')
    if val.lower() == 'no':
        _add('UsePAM', 'WARNING', val, 'yes', 'PAM is disabled — may break system authentication features.')
    else:
        _add('UsePAM', 'WARNING', val, 'yes', 'PAM is enabled.', 'pass')

    # AllowTcpForwarding
    val = cfg.get('AllowTcpForwarding', 'yes')
    if val.lower() == 'yes':
        _add('AllowTcpForwarding', 'LOW', val, 'no', 'TCP forwarding is enabled — consider disabling if not required.')
    else:
        _add('AllowTcpForwarding', 'LOW', val, 'no', 'TCP forwarding is disabled.', 'pass')

    # ClientAliveInterval
    val = cfg.get('ClientAliveInterval', '0')
    try:
        if int(val) == 0:
            _add('ClientAliveInterval', 'WARNING', val, '300', 'No client alive interval — idle sessions will never timeout.')
        else:
            _add('ClientAliveInterval', 'WARNING', val, '300', 'Client alive interval is set.', 'pass')
    except ValueError:
        _add('ClientAliveInterval', 'WARNING', val, '300', 'Could not parse ClientAliveInterval value.')

    return jsonify({'ok': True, 'checks': checks})


# ── Config Read / Save ───────────────────────────────────────────────────────

@ssh_manager_bp.route('/config', methods=['GET'])
@login_required
def config_read():
    """Read sshd_config file contents."""
    result = root_exec('cat /etc/ssh/sshd_config', timeout=10)
    if not result.get('ok'):
        return jsonify({'ok': False, 'error': result.get('stderr', 'Failed to read config')}), 500
    return jsonify({'ok': True, 'config': result['stdout']})


@ssh_manager_bp.route('/config/save', methods=['POST'])
@login_required
def config_save():
    """Save sshd_config with backup and syntax validation."""
    data = request.get_json(silent=True)
    if not data or 'config' not in data:
        return jsonify({'ok': False, 'error': 'Missing config field'}), 400

    config_text = data['config']
    timestamp = int(time.time())
    backup_path = f'/etc/ssh/sshd_config.bak.{timestamp}'

    # 1. Create backup
    bak = root_exec(f'cp /etc/ssh/sshd_config {backup_path}', timeout=10)
    if not bak.get('ok'):
        return jsonify({'ok': False, 'error': 'Failed to create backup: ' + bak.get('stderr', '')}), 500

    # 2. Write new config via a temp file
    try:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.sshd_config', delete=False)
        tmp.write(config_text)
        tmp.close()

        cp_result = root_exec(f'cp {tmp.name} /etc/ssh/sshd_config', timeout=10)
        os.unlink(tmp.name)

        if not cp_result.get('ok'):
            # Restore backup
            root_exec(f'cp {backup_path} /etc/ssh/sshd_config', timeout=10)
            return jsonify({'ok': False, 'error': 'Failed to write config: ' + cp_result.get('stderr', '')}), 500
    except Exception as exc:
        root_exec(f'cp {backup_path} /etc/ssh/sshd_config', timeout=10)
        return jsonify({'ok': False, 'error': f'Write error: {exc}'}), 500

    # 3. Validate syntax
    validate = root_exec('sshd -t', timeout=10)
    if validate.get('code', 1) != 0:
        # Restore backup
        root_exec(f'cp {backup_path} /etc/ssh/sshd_config', timeout=10)
        err = (validate.get('stderr', '') + validate.get('stdout', '')).strip()
        return jsonify({'ok': False, 'error': 'Syntax validation failed — backup restored.', 'validation': err}), 400

    return jsonify({
        'ok': True,
        'validation': 'Configuration is valid.',
        'backup': backup_path,
    })


# ── Config Generate ──────────────────────────────────────────────────────────

# All supported directives grouped logically
_CONFIG_GROUPS = {
    'Connection': [
        'Port', 'AddressFamily', 'ListenAddress', 'Protocol',
    ],
    'Authentication': [
        'PermitRootLogin', 'PubkeyAuthentication', 'PasswordAuthentication',
        'PermitEmptyPasswords', 'ChallengeResponseAuthentication',
        'KbdInteractiveAuthentication', 'UsePAM', 'AuthenticationMethods',
        'MaxAuthTries', 'LoginGraceTime',
    ],
    'Keys': [
        'HostKey', 'AuthorizedKeysFile', 'AuthorizedPrincipalsFile',
    ],
    'Session': [
        'MaxSessions', 'ClientAliveInterval', 'ClientAliveCountMax', 'TCPKeepAlive',
    ],
    'Access Control': [
        'AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups',
    ],
    'Forwarding': [
        'AllowTcpForwarding', 'X11Forwarding', 'X11DisplayOffset',
        'GatewayPorts', 'PermitTunnel',
    ],
    'Logging': [
        'SyslogFacility', 'LogLevel',
    ],
    'Security': [
        'StrictModes', 'HostbasedAuthentication', 'IgnoreRhosts',
        'IgnoreUserKnownHosts', 'RekeyLimit', 'Ciphers', 'MACs', 'KexAlgorithms',
    ],
    'Other': [
        'Subsystem', 'Banner', 'PrintMotd', 'PrintLastLog',
        'AcceptEnv', 'UseDNS', 'PermitUserEnvironment', 'Compression',
    ],
}

# Flatten for quick lookup
_ALL_DIRECTIVES = set()
for _directives in _CONFIG_GROUPS.values():
    _ALL_DIRECTIVES.update(_directives)


@ssh_manager_bp.route('/config/generate', methods=['POST'])
@login_required
def config_generate():
    """Generate a hardened sshd_config from submitted fields.

    Returns the text without saving so the user can review it first.
    """
    data = request.get_json(silent=True) or {}

    lines = [
        '# sshd_config — generated by AUTARCH SSH Manager',
        f'# Generated: {time.strftime("%Y-%m-%d %H:%M:%S %Z")}',
        '#',
        '# Review carefully before applying.',
        '',
    ]

    for group_name, directives in _CONFIG_GROUPS.items():
        group_lines = []
        for directive in directives:
            value = data.get(directive)
            if value is not None and str(value).strip() != '':
                group_lines.append(f'{directive} {value}')
        if group_lines:
            lines.append(f'# ── {group_name} {"─" * (60 - len(group_name))}')
            lines.extend(group_lines)
            lines.append('')

    config_text = '\n'.join(lines) + '\n'
    return jsonify({'ok': True, 'config': config_text})


# ── Service Control ──────────────────────────────────────────────────────────

_ALLOWED_ACTIONS = {'start', 'stop', 'restart', 'enable', 'disable'}


@ssh_manager_bp.route('/service/<action>', methods=['POST'])
@login_required
def service_action(action):
    """Start / stop / restart / enable / disable the SSH service."""
    if action not in _ALLOWED_ACTIONS:
        return jsonify({'ok': False, 'error': f'Invalid action: {action}'}), 400

    # Try sshd first, fall back to ssh
    result = root_exec(f'systemctl {action} sshd', timeout=20)
    if result.get('code', 1) != 0:
        result = root_exec(f'systemctl {action} ssh', timeout=20)

    output = (result.get('stdout', '') + '\n' + result.get('stderr', '')).strip()
    return jsonify({
        'ok': result.get('code', 1) == 0,
        'output': output,
    })


# ── Key Generation ───────────────────────────────────────────────────────────

@ssh_manager_bp.route('/keys/generate', methods=['POST'])
@login_required
def keys_generate():
    """Generate an SSH key pair (does not require root)."""
    data = request.get_json(silent=True) or {}
    key_type = data.get('type', 'ed25519')
    bits = int(data.get('bits', 4096))
    comment = data.get('comment', '')
    passphrase = data.get('passphrase', '')

    if key_type not in ('ed25519', 'rsa'):
        return jsonify({'ok': False, 'error': 'Unsupported key type (use ed25519 or rsa)'}), 400

    try:
        tmp_dir = tempfile.mkdtemp(prefix='autarch_sshkey_')
        key_path = os.path.join(tmp_dir, 'id_key')

        cmd = ['ssh-keygen', '-t', key_type, '-f', key_path, '-N', passphrase]
        if key_type == 'rsa':
            cmd += ['-b', str(bits)]
        if comment:
            cmd += ['-C', comment]

        import subprocess
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            return jsonify({'ok': False, 'error': proc.stderr.strip()}), 500

        with open(key_path, 'r') as f:
            private_key = f.read()
        with open(key_path + '.pub', 'r') as f:
            public_key = f.read().strip()

        # Get fingerprint
        fp_proc = subprocess.run(
            ['ssh-keygen', '-lf', key_path + '.pub'],
            capture_output=True, text=True, timeout=10,
        )
        fingerprint = fp_proc.stdout.strip()

        # Clean up temp files
        os.unlink(key_path)
        os.unlink(key_path + '.pub')
        os.rmdir(tmp_dir)

        return jsonify({
            'ok': True,
            'public_key': public_key,
            'private_key': private_key,
            'fingerprint': fingerprint,
        })
    except Exception as exc:
        log.exception('SSH key generation failed')
        return jsonify({'ok': False, 'error': str(exc)}), 500


# ── Host Keys ────────────────────────────────────────────────────────────────

@ssh_manager_bp.route('/keys/host', methods=['GET'])
@login_required
def keys_host():
    """List host public keys and their fingerprints."""
    import subprocess

    result = root_exec('ls /etc/ssh/ssh_host_*_key.pub', timeout=10)
    if not result.get('ok'):
        return jsonify({'ok': False, 'error': 'No host keys found or permission denied.'}), 500

    pub_files = [f.strip() for f in result['stdout'].splitlines() if f.strip()]
    keys = []
    for pub_file in pub_files:
        # Read the key
        cat_result = root_exec(f'cat {pub_file}', timeout=10)
        if not cat_result.get('ok'):
            continue
        key_text = cat_result['stdout'].strip()
        key_type = key_text.split()[0] if key_text else 'unknown'

        # Fingerprint
        fp_result = root_exec(f'ssh-keygen -lf {pub_file}', timeout=10)
        fingerprint = fp_result.get('stdout', '').strip() if fp_result.get('ok') else ''

        keys.append({
            'type': key_type,
            'fingerprint': fingerprint,
            'file': pub_file,
        })

    return jsonify({'ok': True, 'keys': keys})


# ── Authorized Keys ─────────────────────────────────────────────────────────

def _authorized_keys_path() -> str:
    return os.path.expanduser('~/.ssh/authorized_keys')


@ssh_manager_bp.route('/keys/authorized', methods=['GET'])
@login_required
def keys_authorized():
    """Read ~/.ssh/authorized_keys."""
    ak_path = _authorized_keys_path()
    keys = []
    try:
        if os.path.isfile(ak_path):
            with open(ak_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(None, 2)
                    comment = parts[2] if len(parts) >= 3 else ''
                    keys.append({'key': line, 'comment': comment})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500

    return jsonify({'ok': True, 'keys': keys})


@ssh_manager_bp.route('/keys/authorized/add', methods=['POST'])
@login_required
def keys_authorized_add():
    """Append a public key to authorized_keys."""
    data = request.get_json(silent=True) or {}
    key = data.get('key', '').strip()
    if not key:
        return jsonify({'ok': False, 'error': 'No key provided'}), 400

    ak_path = _authorized_keys_path()
    try:
        ssh_dir = os.path.dirname(ak_path)
        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        with open(ak_path, 'a') as f:
            f.write(key + '\n')
        os.chmod(ak_path, 0o600)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500

    return jsonify({'ok': True})


@ssh_manager_bp.route('/keys/authorized/remove', methods=['POST'])
@login_required
def keys_authorized_remove():
    """Remove a key by index from authorized_keys."""
    data = request.get_json(silent=True) or {}
    index = data.get('index')
    if index is None:
        return jsonify({'ok': False, 'error': 'No index provided'}), 400

    try:
        index = int(index)
    except (ValueError, TypeError):
        return jsonify({'ok': False, 'error': 'Index must be an integer'}), 400

    ak_path = _authorized_keys_path()
    try:
        if not os.path.isfile(ak_path):
            return jsonify({'ok': False, 'error': 'authorized_keys file does not exist'}), 404

        with open(ak_path, 'r') as f:
            lines = f.readlines()

        # Build list of non-empty, non-comment key lines with original indices
        key_lines = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped and not stripped.startswith('#'):
                key_lines.append(i)

        if index < 0 or index >= len(key_lines):
            return jsonify({'ok': False, 'error': f'Index {index} out of range (0-{len(key_lines) - 1})'}), 400

        # Remove the line at the original file index
        del lines[key_lines[index]]

        with open(ak_path, 'w') as f:
            f.writelines(lines)
        os.chmod(ak_path, 0o600)
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 500

    return jsonify({'ok': True})


# ══════════════════════════════════════════════════════════════════════════════
# FAIL2BAN
# ══════════════════════════════════════════════════════════════════════════════

@ssh_manager_bp.route('/fail2ban/status')
@login_required
def f2b_status():
    r = root_exec(['fail2ban-client', 'status'])
    if not r['ok']:
        return jsonify({'ok': False, 'error': r['stderr'] or 'fail2ban not running', 'active': False})
    jails = []
    total_banned = 0
    for line in r['stdout'].split('\n'):
        if 'Jail list:' in line:
            jails = [j.strip() for j in line.split(':')[1].strip().split(',') if j.strip()]
    jail_details = []
    for jail in jails:
        jr = root_exec(['fail2ban-client', 'status', jail])
        banned = 0
        banned_ips = []
        if jr['ok']:
            for line in jr['stdout'].split('\n'):
                if 'Currently banned:' in line:
                    try: banned = int(line.split(':')[1].strip())
                    except: pass
                elif 'Banned IP list:' in line:
                    banned_ips = [ip.strip() for ip in line.split(':',1)[1].strip().split() if ip.strip()]
        total_banned += banned
        jail_details.append({'name': jail, 'banned': banned, 'banned_ips': banned_ips})
    sr = root_exec(['systemctl', 'is-active', 'fail2ban'])
    return jsonify({'ok': True, 'active': sr['stdout'].strip() == 'active',
                    'jail_count': len(jails), 'total_banned': total_banned, 'jails': jail_details})


@ssh_manager_bp.route('/fail2ban/service/<action>', methods=['POST'])
@login_required
def f2b_service(action):
    if action not in ('start', 'stop', 'restart', 'enable', 'disable'):
        return jsonify({'ok': False, 'error': 'Invalid action'})
    r = root_exec(['systemctl', action, 'fail2ban'])
    return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr']})


@ssh_manager_bp.route('/fail2ban/banned')
@login_required
def f2b_banned():
    r = root_exec(['fail2ban-client', 'status'])
    if not r['ok']:
        return jsonify({'ok': False, 'error': 'fail2ban not running'})
    all_banned = []
    jails = []
    for line in r['stdout'].split('\n'):
        if 'Jail list:' in line:
            jails = [j.strip() for j in line.split(':')[1].strip().split(',') if j.strip()]
    for jail in jails:
        jr = root_exec(['fail2ban-client', 'status', jail])
        if jr['ok']:
            for line in jr['stdout'].split('\n'):
                if 'Banned IP list:' in line:
                    for ip in line.split(':', 1)[1].strip().split():
                        if ip.strip():
                            all_banned.append({'ip': ip.strip(), 'jail': jail})
    return jsonify({'ok': True, 'banned': all_banned, 'total': len(all_banned)})


@ssh_manager_bp.route('/fail2ban/ban', methods=['POST'])
@login_required
def f2b_ban():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', 'sshd').strip()
    if not ip: return jsonify({'ok': False, 'error': 'IP required'})
    r = root_exec(['fail2ban-client', 'set', jail, 'banip', ip])
    return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr']})


@ssh_manager_bp.route('/fail2ban/unban', methods=['POST'])
@login_required
def f2b_unban():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    jail = data.get('jail', '').strip()
    if not ip: return jsonify({'ok': False, 'error': 'IP required'})
    r = root_exec(['fail2ban-client', 'set', jail, 'unbanip', ip]) if jail else root_exec(['fail2ban-client', 'unban', ip])
    return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr']})


@ssh_manager_bp.route('/fail2ban/search', methods=['POST'])
@login_required
def f2b_search():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip: return jsonify({'ok': False, 'error': 'IP required'})
    results = []
    r = root_exec(['fail2ban-client', 'status'])
    jails = []
    if r['ok']:
        for line in r['stdout'].split('\n'):
            if 'Jail list:' in line:
                jails = [j.strip() for j in line.split(':')[1].strip().split(',') if j.strip()]
    for jail in jails:
        jr = root_exec(['fail2ban-client', 'status', jail])
        if jr['ok'] and ip in jr['stdout']:
            results.append({'jail': jail, 'status': 'banned'})
    lr = root_exec(['grep', ip, '/var/log/fail2ban.log'])
    log_entries = [l.strip() for l in lr['stdout'].strip().split('\n')[-20:] if l.strip()] if lr['ok'] else []
    return jsonify({'ok': True, 'ip': ip, 'active_bans': results, 'log_entries': log_entries})


@ssh_manager_bp.route('/fail2ban/jail/create', methods=['POST'])
@login_required
def f2b_jail_create():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return jsonify({'ok': False, 'error': 'Invalid jail name'})
    config = f"[{name}]\nenabled = {'true' if data.get('enabled', True) else 'false'}\nfilter = {data.get('filter', name)}\nlogpath = {data.get('logpath', '')}\nmaxretry = {data.get('maxretry', '5')}\nfindtime = {data.get('findtime', '10m')}\nbantime = {data.get('bantime', '1h')}\naction = {data.get('action', '%(action_mwl)s')}\n"
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.local', delete=False)
    tmp.write(config); tmp.close()
    r = root_exec(['cp', tmp.name, f'/etc/fail2ban/jail.d/{name}.local'])
    os.unlink(tmp.name)
    if not r['ok']: return jsonify({'ok': False, 'error': r['stderr']})
    root_exec(['fail2ban-client', 'reload'])
    return jsonify({'ok': True, 'config': config})


@ssh_manager_bp.route('/fail2ban/scan-apps', methods=['POST'])
@login_required
def f2b_scan_apps():
    checks = [
        ('sshd', 'openssh-server', '/var/log/auth.log', 'sshd'),
        ('apache2', 'apache2', '/var/log/apache2/error.log', 'apache-auth'),
        ('nginx', 'nginx', '/var/log/nginx/error.log', 'nginx-http-auth'),
        ('postfix', 'postfix', '/var/log/mail.log', 'postfix'),
        ('dovecot', 'dovecot-core', '/var/log/mail.log', 'dovecot'),
        ('mysql', 'mysql-server', '/var/log/mysql/error.log', 'mysqld-auth'),
        ('postgresql', 'postgresql', '/var/log/postgresql/*.log', 'postgresql'),
        ('vsftpd', 'vsftpd', '/var/log/vsftpd.log', 'vsftpd'),
        ('exim4', 'exim4', '/var/log/exim4/mainlog', 'exim'),
        ('recidive', None, '/var/log/fail2ban.log', 'recidive'),
    ]
    existing = set()
    r = root_exec(['fail2ban-client', 'status'])
    if r['ok']:
        for line in r['stdout'].split('\n'):
            if 'Jail list:' in line:
                existing = set(j.strip() for j in line.split(':')[1].strip().split(',') if j.strip())
    apps = []
    for service, pkg, logpath, filt in checks:
        installed = True if not pkg else (root_exec(['dpkg', '-l', pkg])['ok'] and 'ii' in root_exec(['dpkg', '-l', pkg])['stdout'])
        lr = root_exec(['ls', logpath.split('*')[0] if '*' in logpath else logpath])
        apps.append({'service': service, 'package': pkg, 'installed': installed,
                     'log_path': logpath, 'log_exists': lr['ok'], 'filter': filt,
                     'has_jail': filt in existing or service in existing})
    return jsonify({'ok': True, 'apps': apps})


@ssh_manager_bp.route('/fail2ban/auto-config', methods=['POST'])
@login_required
def f2b_auto_config():
    data = request.get_json(silent=True) or {}
    apply_now = data.get('apply', False)
    checks = [
        ('sshd', '/var/log/auth.log', 'sshd', '5', '10m', '1h'),
        ('apache2', '/var/log/apache2/error.log', 'apache-auth', '5', '10m', '1h'),
        ('nginx', '/var/log/nginx/error.log', 'nginx-http-auth', '5', '10m', '1h'),
        ('postfix', '/var/log/mail.log', 'postfix', '5', '10m', '1h'),
        ('recidive', '/var/log/fail2ban.log', 'recidive', '3', '1d', '1w'),
    ]
    generated = []
    for svc, logpath, filt, maxr, findt, bant in checks:
        if not root_exec(['ls', logpath])['ok']: continue
        generated.append({'service': svc, 'config': f"[{svc}]\nenabled = true\nfilter = {filt}\nlogpath = {logpath}\nmaxretry = {maxr}\nfindtime = {findt}\nbantime = {bant}\n"})
    if apply_now and generated:
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.local', delete=False)
        tmp.write('\n'.join(g['config'] for g in generated)); tmp.close()
        root_exec(['cp', tmp.name, '/etc/fail2ban/jail.d/autarch-auto.local'])
        os.unlink(tmp.name)
        root_exec(['fail2ban-client', 'reload'])
    return jsonify({'ok': True, 'generated': generated, 'applied': apply_now, 'count': len(generated)})
