#!/usr/bin/env python3
"""
AUTARCH Privileged Daemon
Runs as root, accepts commands from the unprivileged AUTARCH web process
over a Unix domain socket.

This allows Flask to run as a normal user while still executing privileged
operations (iptables, sysctl, iwlist scanning, systemctl, ARP manipulation, etc.)

Start:  sudo python3 core/daemon.py
Socket: /var/run/autarch-daemon.sock

Protocol: newline-delimited JSON over Unix socket
  Request:  {"cmd": ["iptables", "-A", "INPUT", ...], "timeout": 15}
  Response: {"ok": true, "stdout": "...", "stderr": "...", "code": 0}
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

SOCKET_PATH = '/var/run/autarch-daemon.sock'
PID_FILE = '/var/run/autarch-daemon.pid'
LOG_FILE = '/var/log/autarch-daemon.log'
SECRET_FILE = '/var/run/autarch-daemon.secret'
MAX_MSG_SIZE = 1024 * 1024  # 1MB
NONCE_EXPIRY = 30  # Nonces valid for 30 seconds

# ── HMAC Authentication ───────────────────────────────────────────────────────
# The daemon generates a shared secret on startup and writes it to SECRET_FILE.
# The client reads the secret and signs every request with HMAC-SHA256.
# This prevents other users/processes from injecting commands.

_daemon_secret = b''
_used_nonces = set()  # Replay protection


def _generate_daemon_secret() -> bytes:
    """Generate a random secret and write it to the secret file."""
    secret = secrets.token_bytes(32)
    with open(SECRET_FILE, 'wb') as f:
        f.write(secret)
    # Readable only by the autarch user's group
    try:
        autarch_dir = Path(__file__).parent.parent
        owner_gid = autarch_dir.stat().st_gid
        os.chown(SECRET_FILE, 0, owner_gid)
    except Exception:
        pass
    os.chmod(SECRET_FILE, 0o640)  # root can read/write, group can read
    return secret


def _load_daemon_secret() -> bytes:
    """Load the shared secret from the secret file (client side)."""
    try:
        with open(SECRET_FILE, 'rb') as f:
            return f.read()
    except (OSError, PermissionError):
        return b''


def _sign_request(payload_bytes: bytes, secret: bytes) -> str:
    """Create HMAC-SHA256 signature for a request."""
    return hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()


def _verify_request(payload_bytes: bytes, signature: str, secret: bytes) -> bool:
    """Verify HMAC-SHA256 signature."""
    expected = hmac.new(secret, payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)



# No allowlist — any command can run EXCEPT those in the blocklist below.
# The daemon runs as root and is protected by HMAC auth + SO_PEERCRED,
# so only AUTARCH can talk to it. The blocklist catches destructive commands.

# Commands that are NEVER allowed, even if they match an allowed prefix
BLOCKED_COMMANDS = {
    # ── Bricks the system (irreversible) ──
    'rm -rf /',
    'rm -rf /*',
    'rm -rf /home',
    'rm -rf /etc',
    'rm -rf /var',
    'rm -rf /usr',
    'rm -rf /boot',
    'mkfs /dev/sd',
    'mkfs /dev/nvme',
    'mkfs /dev/mmc',
    'dd if=/dev/zero of=/dev/sd',
    'dd if=/dev/zero of=/dev/nvme',
    'dd if=/dev/zero of=/dev/mmc',
    'dd if=/dev/random of=/dev/sd',
    'shred /dev/sd',
    'shred /dev/nvme',
    'shred /dev/mmc',
    'wipefs /dev/sd',
    'wipefs /dev/nvme',

    # ── Fork bombs ──
    ':(){',
    ':()',

    # ── Reboot / shutdown (human decision only) ──
    'reboot',
    'shutdown',
    'poweroff',
    'halt',
    'init 0',
    'init 6',
    'systemctl reboot',
    'systemctl poweroff',
    'systemctl halt',

    # ── Bootloader (unrecoverable if wrong) ──
    'update-grub',
    'grub-install',

    # ── Root account destruction ──
    'passwd root',
    'userdel root',
    'deluser root',
    'usermod -L root',

    # ── Loopback kill (breaks everything including the daemon) ──
    'ip link set lo down',
    'ifconfig lo down',

    # ── Partition table (destroys disk layout) ──
    'fdisk /dev/sd',
    'fdisk /dev/nvme',
    'fdisk /dev/mmc',
    'parted /dev/sd',
    'parted /dev/nvme',
    'cfdisk',
    'sfdisk',
}

_log = logging.getLogger('autarch.daemon')


def is_command_allowed(cmd_parts: list) -> tuple:
    """Check if a command is allowed.

    Args:
        cmd_parts: Command as list of strings

    Returns:
        (allowed: bool, reason: str)
    """
    if not cmd_parts:
        return False, 'Empty command'

    # Get the base command (strip path)
    base_cmd = os.path.basename(cmd_parts[0])

    # Remove 'sudo' prefix if present (we're already root)
    if base_cmd == 'sudo' and len(cmd_parts) > 1:
        cmd_parts = cmd_parts[1:]
        base_cmd = os.path.basename(cmd_parts[0])

    # Check against blocklist only
    full_cmd = ' '.join(cmd_parts)
    for blocked in BLOCKED_COMMANDS:
        if blocked in full_cmd:
            return False, f'Blocked: {blocked}'

    return True, 'OK'


def execute_command(cmd_parts: list, timeout: int = 30, stdin_data: str = None) -> dict:
    """Execute a command and return the result.

    Args:
        cmd_parts: Command as list of strings
        timeout: Maximum execution time in seconds
        stdin_data: Optional data to send to stdin

    Returns:
        dict with ok, stdout, stderr, code
    """
    # Strip sudo prefix — we're already root
    if cmd_parts and cmd_parts[0] == 'sudo':
        cmd_parts = cmd_parts[1:]

    allowed, reason = is_command_allowed(cmd_parts)
    if not allowed:
        return {'ok': False, 'stdout': '', 'stderr': reason, 'code': -1}

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.PIPE if stdin_data else None,
            input=stdin_data,
        )
        return {
            'ok': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'code': result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {'ok': False, 'stdout': '', 'stderr': f'Timeout after {timeout}s', 'code': -2}
    except FileNotFoundError:
        return {'ok': False, 'stdout': '', 'stderr': f'Command not found: {cmd_parts[0]}', 'code': -3}
    except Exception as e:
        return {'ok': False, 'stdout': '', 'stderr': str(e), 'code': -4}


def _verify_peer(conn: socket.socket) -> tuple:
    """Verify the connecting process is owned by the AUTARCH user.
    Uses SO_PEERCRED on Linux to get the peer's UID/PID.
    Returns (allowed: bool, info: str)."""
    try:
        import struct
        # SO_PEERCRED returns (pid, uid, gid) as 3 unsigned ints
        cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        pid, uid, gid = struct.unpack('3i', cred)

        # Allow: root (uid 0), or the user who owns the autarch directory
        autarch_dir = Path(__file__).parent.parent
        owner_uid = autarch_dir.stat().st_uid
        owner_gid = autarch_dir.stat().st_gid

        if uid == 0 or uid == owner_uid or gid == owner_gid:
            return True, f'pid={pid} uid={uid} gid={gid}'
        else:
            return False, f'Rejected: pid={pid} uid={uid} gid={gid} (expected uid={owner_uid} or gid={owner_gid})'
    except (AttributeError, OSError):
        # SO_PEERCRED not available (non-Linux) — fall back to HMAC-only auth
        return True, 'peercred not available'


def _builtin_capture(request: dict) -> dict:
    """Run scapy packet capture as root. Called by the daemon directly."""
    try:
        from scapy.all import sniff, wrpcap
    except ImportError:
        return {'ok': False, 'error': 'scapy not available'}

    interface = request.get('interface', '')
    bpf_filter = request.get('filter', '')
    duration = min(int(request.get('duration', 30)), 300)
    max_packets = int(request.get('max_packets', 1000))
    output_file = request.get('file', '')

    if not output_file:
        output_file = f'/tmp/autarch_capture_{os.getpid()}.pcap'

    _log.info(f'[Capture] Starting: iface={interface or "any"} duration={duration}s filter={bpf_filter or "none"} file={output_file}')

    try:
        kwargs = {'timeout': duration, 'count': max_packets, 'store': True}
        if interface:
            kwargs['iface'] = interface
        if bpf_filter:
            kwargs['filter'] = bpf_filter

        packets = sniff(**kwargs)
        count = len(packets)

        if packets and output_file:
            wrpcap(output_file, packets)
            os.chmod(output_file, 0o644)  # Make readable by non-root

        _log.info(f'[Capture] Done: {count} packets captured')
        return {
            'ok': True,
            'packet_count': count,
            'file': output_file if count > 0 else '',
            'duration': duration,
        }
    except Exception as e:
        _log.error(f'[Capture] Failed: {e}')
        return {'ok': False, 'error': str(e)}


def _builtin_wifi_scan() -> dict:
    """Run WiFi scan as root using iw or nmcli."""
    networks = []
    try:
        # Find wireless interface
        iface = None
        for name in os.listdir('/sys/class/net/'):
            if os.path.isdir(f'/sys/class/net/{name}/wireless'):
                iface = name
                break
        if not iface:
            return {'ok': False, 'error': 'No wireless interface'}

        # Try iw scan (needs root)
        r = subprocess.run(['iw', 'dev', iface, 'scan'], capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            import re
            current = {}
            for line in r.stdout.split('\n'):
                line = line.strip()
                if line.startswith('BSS '):
                    if current.get('bssid'):
                        networks.append(current)
                    m = re.match(r'BSS ([\da-f:]+)', line)
                    current = {'bssid': m.group(1) if m else '', 'ssid': '', 'channel': '', 'signal': '', 'security': ''}
                elif line.startswith('SSID:'):
                    current['ssid'] = line.split(':', 1)[1].strip() or '(Hidden)'
                elif 'primary channel:' in line.lower():
                    m = re.search(r'(\d+)', line)
                    if m:
                        current['channel'] = m.group(1)
                elif 'signal:' in line.lower():
                    m = re.search(r'(-?\d+)', line)
                    if m:
                        current['signal'] = m.group(1)
                elif 'RSN' in line:
                    current['security'] = 'WPA2'
                elif 'WPA' in line and current.get('security') != 'WPA2':
                    current['security'] = 'WPA'
            if current.get('bssid'):
                networks.append(current)
            return {'ok': True, 'networks': networks, 'interface': iface}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

    return {'ok': False, 'error': 'WiFi scan failed'}


def handle_client(conn: socket.socket, addr):
    """Handle a single client connection."""
    # Verify the peer is an authorized process
    allowed, peer_info = _verify_peer(conn)
    if not allowed:
        _log.warning(f'Connection rejected: {peer_info}')
        try:
            conn.sendall(json.dumps({'ok': False, 'stderr': 'Unauthorized process'}).encode() + b'\n')
        except Exception:
            pass
        conn.close()
        return

    try:
        data = b''
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if b'\n' in data:
                break
            if len(data) > MAX_MSG_SIZE:
                conn.sendall(json.dumps({'ok': False, 'stderr': 'Message too large'}).encode() + b'\n')
                return

        if not data:
            return

        # Parse request — format: {"payload": {...}, "sig": "hmac-hex", "nonce": "..."}
        try:
            envelope = json.loads(data.decode('utf-8').strip())
        except json.JSONDecodeError as e:
            conn.sendall(json.dumps({'ok': False, 'stderr': f'Invalid JSON: {e}'}).encode() + b'\n')
            return

        # ── HMAC Verification ──
        if _daemon_secret:
            sig = envelope.get('sig', '')
            nonce = envelope.get('nonce', '')
            payload_str = envelope.get('payload', '')

            if not sig or not nonce or not payload_str:
                _log.warning('Rejected: missing sig/nonce/payload')
                conn.sendall(json.dumps({'ok': False, 'stderr': 'Authentication required'}).encode() + b'\n')
                return

            # Verify signature
            payload_bytes = payload_str.encode() if isinstance(payload_str, str) else payload_str
            if not _verify_request(payload_bytes, sig, _daemon_secret):
                _log.warning('Rejected: invalid HMAC signature')
                conn.sendall(json.dumps({'ok': False, 'stderr': 'Invalid signature'}).encode() + b'\n')
                return

            # Replay protection — check nonce hasn't been used and isn't too old
            try:
                nonce_time = float(nonce.split(':')[0])
                if abs(time.time() - nonce_time) > NONCE_EXPIRY:
                    conn.sendall(json.dumps({'ok': False, 'stderr': 'Nonce expired'}).encode() + b'\n')
                    return
            except (ValueError, IndexError):
                conn.sendall(json.dumps({'ok': False, 'stderr': 'Invalid nonce'}).encode() + b'\n')
                return

            if nonce in _used_nonces:
                conn.sendall(json.dumps({'ok': False, 'stderr': 'Nonce reused (replay detected)'}).encode() + b'\n')
                return
            _used_nonces.add(nonce)
            # Prune old nonces periodically
            if len(_used_nonces) > 10000:
                _used_nonces.clear()

            request = json.loads(payload_str)
        else:
            # No secret configured — accept unsigned (backwards compat during setup)
            request = envelope

        cmd = request.get('cmd')
        timeout = min(request.get('timeout', 30), 300)  # Cap at 5 minutes
        stdin_data = request.get('stdin')

        if not cmd:
            conn.sendall(json.dumps({'ok': False, 'stderr': 'No cmd provided'}).encode() + b'\n')
            return

        # Handle string commands (split them)
        if isinstance(cmd, str):
            import shlex
            cmd = shlex.split(cmd)

        # ── Built-in actions (run Python directly as root, no shell) ──
        if cmd and cmd[0] == '__capture__':
            result = _builtin_capture(request)
            response = json.dumps(result).encode() + b'\n'
            conn.sendall(response)
            return

        if cmd and cmd[0] == '__wifi_scan__':
            result = _builtin_wifi_scan()
            response = json.dumps(result).encode() + b'\n'
            conn.sendall(response)
            return

        _log.info(f'Executing: {" ".join(cmd[:6])}{"..." if len(cmd) > 6 else ""}')

        # Execute
        result = execute_command(cmd, timeout=timeout, stdin_data=stdin_data)

        # Send response
        response = json.dumps(result).encode() + b'\n'
        conn.sendall(response)

    except BrokenPipeError:
        pass
    except Exception as e:
        _log.error(f'Client handler error: {e}', exc_info=True)
        try:
            conn.sendall(json.dumps({'ok': False, 'stderr': str(e)}).encode() + b'\n')
        except Exception:
            pass
    finally:
        conn.close()


def run_daemon():
    """Run the privileged daemon."""
    global _daemon_secret

    # Must be root
    if os.geteuid() != 0:
        print('ERROR: autarch-daemon must run as root', file=sys.stderr)
        sys.exit(1)

    # Generate shared secret for HMAC authentication
    _daemon_secret = _generate_daemon_secret()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(),
        ]
    )

    # Remove stale socket
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    # Create socket
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)

    # Allow the autarch user (and group) to connect
    os.chmod(SOCKET_PATH, 0o770)
    # Try to set group ownership to the autarch user's group
    try:
        import pwd
        # Find the user who owns the autarch directory
        autarch_dir = Path(__file__).parent.parent
        owner_uid = autarch_dir.stat().st_uid
        owner_gid = autarch_dir.stat().st_gid
        os.chown(SOCKET_PATH, 0, owner_gid)  # root:snake
    except Exception:
        # Fallback: world-accessible (less secure but works)
        os.chmod(SOCKET_PATH, 0o777)

    server.listen(10)

    # Write PID file
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    # Handle shutdown
    def shutdown(signum, frame):
        _log.info('Shutting down...')
        server.close()
        for f in (SOCKET_PATH, PID_FILE, SECRET_FILE):
            if os.path.exists(f):
                os.unlink(f)
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    _log.info(f'AUTARCH daemon started on {SOCKET_PATH} (PID {os.getpid()})')
    _log.info(f'Blocked commands: {len(BLOCKED_COMMANDS)}')

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except OSError:
            break  # Socket closed during shutdown


# ── Client API (used by Flask) ────────────────────────────────────────────────

def root_exec(cmd, timeout=30, stdin=None) -> dict:
    """Execute a command via the privileged daemon.

    This is the function Flask routes call instead of subprocess.run()
    when they need root privileges.

    Args:
        cmd: Command as string or list
        timeout: Max execution time
        stdin: Optional stdin data

    Returns:
        dict: {'ok': bool, 'stdout': str, 'stderr': str, 'code': int}

    Falls back to direct subprocess if daemon is not running.
    """
    if isinstance(cmd, str):
        import shlex
        cmd = shlex.split(cmd)

    # Try daemon first
    if os.path.exists(SOCKET_PATH):
        try:
            return _send_to_daemon(cmd, timeout, stdin)
        except (ConnectionRefusedError, FileNotFoundError, OSError):
            pass  # Daemon not running, fall through

    # Fallback: direct execution (works if we're already root)
    if os.geteuid() == 0:
        return execute_command(cmd, timeout=timeout, stdin_data=stdin)

    # Fallback: try with sudo (use original subprocess.run to avoid hook recursion)
    sudo_cmd = ['sudo', '-n'] + cmd  # -n = non-interactive
    run_fn = _original_subprocess_run or subprocess.run
    try:
        result = run_fn(
            sudo_cmd, capture_output=True, text=True, timeout=timeout
        )
        return {
            'ok': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'code': result.returncode,
        }
    except Exception as e:
        return {'ok': False, 'stdout': '', 'stderr': f'No daemon, not root, sudo failed: {e}', 'code': -5}


def _send_to_daemon(cmd, timeout, stdin) -> dict:
    """Send a signed command to the daemon via Unix socket."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout + 5)  # Extra time for daemon processing
    sock.connect(SOCKET_PATH)

    payload = json.dumps({'cmd': cmd, 'timeout': timeout, 'stdin': stdin})

    # Sign the request with HMAC if we have the shared secret
    secret = _load_daemon_secret()
    if secret:
        nonce = f"{time.time()}:{secrets.token_hex(8)}"
        sig = _sign_request(payload.encode(), secret)
        envelope = json.dumps({'payload': payload, 'sig': sig, 'nonce': nonce})
    else:
        envelope = payload  # Unsigned fallback

    sock.sendall((envelope + '\n').encode())

    # Read response
    data = b''
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'\n' in data:
            break

    sock.close()

    if not data:
        return {'ok': False, 'stdout': '', 'stderr': 'Empty response from daemon', 'code': -6}

    return json.loads(data.decode().strip())


# ── Global subprocess.run patch ───────────────────────────────────────────────
# Call install_subprocess_hook() once at startup to make ALL subprocess.run()
# calls with ['sudo', ...] auto-route through the daemon. This means we never
# miss a sudo call — even in third-party code or modules we haven't touched.

_original_subprocess_run = None
_hook_installed = False


def _patched_subprocess_run(cmd, *args, **kwargs):
    """Drop-in replacement for subprocess.run that intercepts sudo commands."""
    # Only intercept list commands starting with 'sudo'
    if isinstance(cmd, (list, tuple)) and len(cmd) > 1 and cmd[0] == 'sudo':
        actual_cmd = list(cmd[1:])
        # Strip -n flag if present (we don't need it, daemon is root)
        if actual_cmd and actual_cmd[0] == '-n':
            actual_cmd = actual_cmd[1:]
        if actual_cmd and actual_cmd[0] == '-E':
            actual_cmd = actual_cmd[1:]

        timeout = kwargs.get('timeout', 30)
        input_data = kwargs.get('input')

        r = root_exec(actual_cmd, timeout=timeout, stdin=input_data)

        # Return a subprocess.CompletedProcess to match the expected interface
        result = subprocess.CompletedProcess(
            args=cmd,
            returncode=r['code'],
            stdout=r['stdout'] if kwargs.get('text') or kwargs.get('capture_output') else r['stdout'].encode(),
            stderr=r['stderr'] if kwargs.get('text') or kwargs.get('capture_output') else r['stderr'].encode(),
        )

        # If check=True was passed, raise on non-zero
        if kwargs.get('check') and result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )
        return result

    # Not a sudo command — pass through to original subprocess.run
    return _original_subprocess_run(cmd, *args, **kwargs)


def install_subprocess_hook():
    """Install the global subprocess.run hook that intercepts sudo calls.

    Call this once at startup (e.g., in autarch.py or web/app.py).
    Safe to call multiple times — only installs once.
    """
    global _original_subprocess_run, _hook_installed
    if _hook_installed:
        return
    _original_subprocess_run = subprocess.run
    subprocess.run = _patched_subprocess_run
    _hook_installed = True
    _log.info('[Daemon] subprocess.run hook installed — sudo calls auto-route through daemon')


def uninstall_subprocess_hook():
    """Remove the hook and restore original subprocess.run."""
    global _hook_installed
    if _original_subprocess_run and _hook_installed:
        subprocess.run = _original_subprocess_run
        _hook_installed = False


def is_daemon_running() -> bool:
    """Check if the daemon is running."""
    if not os.path.exists(SOCKET_PATH):
        return False
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(SOCKET_PATH)
        sock.close()
        return True
    except (ConnectionRefusedError, FileNotFoundError, OSError):
        return False


if __name__ == '__main__':
    run_daemon()
