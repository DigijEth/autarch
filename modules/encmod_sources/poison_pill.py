"""
Poison Pill — AUTARCH Encrypted Module
Operator: darkHal Security Group / Setec Security Labs

Emergency data sanitization and anti-forensic self-protection module.
On activation, securely wipes configured data paths, rotates credentials,
kills active sessions, and optionally triggers a remote wipe signal
to registered companion devices.

USE ONLY IN AUTHORIZED EMERGENCY SCENARIOS.
All activations are logged to an external endpoint before wiping begins.
"""

import hashlib
import json
import os
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

MODULE_NAME    = "Poison Pill"
MODULE_VERSION = "1.0"
MODULE_AUTHOR  = "darkHal Security Group"
MODULE_TAGS    = ["anti-forensic", "emergency", "wipe", "self-protection"]

_stop_flag    = threading.Event()
_output_lines = []


def _emit(msg: str, level: str = "info") -> None:
    ts   = datetime.now(timezone.utc).strftime('%H:%M:%S')
    line = f"[{ts}][{level.upper()}] {msg}"
    _output_lines.append(line)
    print(line)


# ── Secure file overwrite ─────────────────────────────────────────────────────

def _secure_overwrite(path: Path, passes: int = 3) -> bool:
    """
    Overwrite a file with random data N passes, then delete.
    Returns True on success.
    """
    try:
        size = path.stat().st_size
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        path.unlink()
        return True
    except Exception as exc:
        _emit(f"Overwrite failed on {path}: {exc}", 'error')
        return False


def secure_wipe_file(path: Path, passes: int = 3) -> dict:
    """Securely wipe a single file."""
    if not path.exists():
        return {'path': str(path), 'status': 'not_found'}
    ok = _secure_overwrite(path, passes)
    return {'path': str(path), 'status': 'wiped' if ok else 'error', 'passes': passes}


def secure_wipe_dir(path: Path, passes: int = 3) -> dict:
    """Recursively and securely wipe a directory."""
    if not path.exists():
        return {'path': str(path), 'status': 'not_found', 'files_wiped': 0}
    count = 0
    errors = []
    for f in sorted(path.rglob('*')):
        if f.is_file():
            r = secure_wipe_file(f, passes)
            if r['status'] == 'wiped':
                count += 1
            else:
                errors.append(str(f))
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    return {'path': str(path), 'status': 'wiped', 'files_wiped': count, 'errors': errors}


# ── Credential rotation ───────────────────────────────────────────────────────

def rotate_web_password(new_password: Optional[str] = None) -> dict:
    """
    Rotate the AUTARCH web dashboard password.
    If new_password is None, generates a random 32-char alphanumeric password.
    """
    import secrets
    import string
    if new_password is None:
        alphabet = string.ascii_letters + string.digits
        new_password = ''.join(secrets.choice(alphabet) for _ in range(32))
    try:
        from web.auth import hash_password, save_credentials, load_credentials
        creds = load_credentials()
        save_credentials(creds.get('username', 'admin'), hash_password(new_password), force_change=False)
        return {'status': 'rotated', 'new_password': new_password}
    except Exception as exc:
        return {'status': 'error', 'error': str(exc)}


def rotate_secret_key() -> dict:
    """Generate a new Flask secret key and write it to config."""
    new_key = os.urandom(32).hex()
    try:
        from core.config import get_config
        cfg = get_config()
        cfg.set('web', 'secret_key', new_key)
        cfg.save()
        return {'status': 'rotated', 'key_length': len(new_key)}
    except Exception as exc:
        return {'status': 'error', 'error': str(exc)}


# ── Session termination ───────────────────────────────────────────────────────

def kill_active_sessions() -> dict:
    """Invalidate all active Flask sessions by rotating the secret key."""
    result = rotate_secret_key()
    return {'action': 'kill_sessions', **result}


# ── Remote wipe signal ────────────────────────────────────────────────────────

def signal_remote_wipe(devices: list[str], endpoint: Optional[str] = None) -> list[dict]:
    """
    Send a remote wipe signal to registered Archon companion devices.
    Each device is an Archon server endpoint (host:port).
    """
    results = []
    import requests
    for device in devices:
        url = f"http://{device}/wipe"
        try:
            resp = requests.post(url, json={'action': 'poison_pill', 'ts': time.time()}, timeout=5)
            results.append({'device': device, 'status': resp.status_code, 'ok': resp.ok})
        except Exception as exc:
            results.append({'device': device, 'status': -1, 'error': str(exc)})
    return results


# ── Pre-wipe beacon ───────────────────────────────────────────────────────────

def send_activation_beacon(endpoint: str, operator_id: str) -> dict:
    """
    POST an activation notice to an external logging endpoint BEFORE wiping.
    This creates an audit trail that the pill was triggered.
    """
    payload = {
        'event':       'poison_pill_activated',
        'operator_id': operator_id,
        'timestamp':   datetime.now(timezone.utc).isoformat(),
        'hostname':    __import__('socket').gethostname(),
    }
    try:
        import requests
        resp = requests.post(endpoint, json=payload, timeout=8)
        return {'status': resp.status_code, 'ok': resp.ok}
    except Exception as exc:
        return {'status': -1, 'error': str(exc)}


# ── Main run entry point ──────────────────────────────────────────────────────

def run(params: dict, output_cb=None) -> dict:
    """
    Main execution entry point.

    params:
      wipe_paths        — list of paths to securely wipe
      rotate_password   — bool, rotate web password
      kill_sessions     — bool, invalidate all sessions
      remote_devices    — list of Archon device endpoints for remote wipe
      beacon_endpoint   — URL to POST activation notice to (recommended)
      operator_id       — identifier logged with the beacon
      passes            — overwrite passes (default 3)
      confirm           — must be the string 'CONFIRM_POISON_PILL' to activate
    """
    _stop_flag.clear()
    _output_lines.clear()

    def emit(msg, level='info'):
        _emit(msg, level)
        if output_cb:
            output_cb({'line': f"[{level.upper()}] {msg}"})

    emit(f"=== {MODULE_NAME} v{MODULE_VERSION} ===")

    confirm = params.get('confirm', '')
    if confirm != 'CONFIRM_POISON_PILL':
        emit("ABORT: Confirmation string not provided. Set confirm='CONFIRM_POISON_PILL'", 'error')
        return {'status': 'aborted', 'reason': 'missing_confirmation'}

    emit("POISON PILL ACTIVATED — commencing emergency sanitization", 'warn')
    passes       = int(params.get('passes', 3))
    beacon_ep    = params.get('beacon_endpoint', '')
    operator_id  = params.get('operator_id', 'unknown')

    results = {'status': 'activated', 'actions': []}

    # 1 — Send beacon FIRST
    if beacon_ep:
        emit(f"Sending activation beacon to {beacon_ep}")
        beacon = send_activation_beacon(beacon_ep, operator_id)
        results['actions'].append({'type': 'beacon', **beacon})
    else:
        emit("No beacon endpoint configured — skipping audit trail", 'warn')

    # 2 — Kill active sessions
    if params.get('kill_sessions', True):
        emit("Killing active sessions...")
        r = kill_active_sessions()
        results['actions'].append({'type': 'kill_sessions', **r})
        emit(f"Sessions killed: {r['status']}")

    # 3 — Rotate web password
    if params.get('rotate_password', True):
        emit("Rotating web password...")
        r = rotate_web_password()
        results['actions'].append({'type': 'rotate_password', 'status': r['status']})
        emit(f"Password rotated: {r['status']}")

    # 4 — Secure wipe paths
    wipe_paths = params.get('wipe_paths', [])
    for raw_path in wipe_paths:
        if _stop_flag.is_set():
            break
        p = Path(raw_path)
        emit(f"Wiping: {p}")
        if p.is_file():
            r = secure_wipe_file(p, passes)
        elif p.is_dir():
            r = secure_wipe_dir(p, passes)
        else:
            r = {'path': str(p), 'status': 'not_found'}
        results['actions'].append({'type': 'wipe', **r})
        emit(f"  -> {r['status']}")

    # 5 — Remote wipe
    remote_devices = params.get('remote_devices', [])
    if remote_devices:
        emit(f"Sending remote wipe to {len(remote_devices)} device(s)...")
        rw = signal_remote_wipe(remote_devices)
        results['actions'].append({'type': 'remote_wipe', 'results': rw})

    emit("Poison Pill sequence complete.", 'warn')
    results['output'] = _output_lines[:]
    return results


def stop():
    _stop_flag.set()
