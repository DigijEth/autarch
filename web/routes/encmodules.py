"""Encrypted Modules — load and execute AES-encrypted Python modules."""

import io
import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

from flask import (Blueprint, Response, jsonify, render_template,
                   request, session)
from web.auth import login_required

encmodules_bp = Blueprint('encmodules', __name__, url_prefix='/encmodules')

# ── Storage ───────────────────────────────────────────────────────────────────

def _module_dir() -> Path:
    from core.paths import get_app_dir
    d = get_app_dir() / 'modules' / 'encrypted'
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── Module metadata ───────────────────────────────────────────────────────────

_DISPLAY_NAMES = {
    'tor_pedo_hunter_killer': 'TOR-Pedo Hunter Killer',
    'tor-pedo_hunter_killer': 'TOR-Pedo Hunter Killer',
    'tphk':                   'TOR-Pedo Hunter Killer',
    'poison_pill':            'Poison Pill',
    'poisonpill':             'Poison Pill',
    'floppy_dick':            'Floppy_Dick',
    'floppydick':             'Floppy_Dick',
}

_DESCRIPTIONS = {
    'TOR-Pedo Hunter Killer':
        'Identifies and reports CSAM distributors and predator networks on Tor hidden services. '
        'Generates law-enforcement referral dossiers. Authorized investigations only.',
    'Poison Pill':
        'Emergency anti-forensic self-protection. Securely wipes configured data paths, '
        'rotates credentials, kills sessions, and triggers remote wipe on companion devices.',
    'Floppy_Dick':
        'Legacy-protocol credential fuzzer. Tests FTP, Telnet, SMTP, SNMP v1/v2c, and '
        'other deprecated authentication endpoints. For authorized pentest engagements.',
}

_TAGS = {
    'TOR-Pedo Hunter Killer': ['CSAM', 'TOR', 'OSINT', 'counter'],
    'Poison Pill':            ['anti-forensic', 'emergency', 'wipe'],
    'Floppy_Dick':            ['brute-force', 'auth', 'legacy', 'pentest'],
}

_TAG_COLORS = {
    'CSAM': 'danger', 'TOR': 'danger', 'counter': 'warn',
    'OSINT': 'info', 'anti-forensic': 'warn', 'emergency': 'danger',
    'wipe': 'danger', 'brute-force': 'warn', 'auth': 'info',
    'legacy': 'dim', 'pentest': 'info',
}


def _resolve_display_name(stem: str) -> str:
    key = stem.lower().replace('-', '_')
    return _DISPLAY_NAMES.get(key, stem.replace('_', ' ').replace('-', ' ').title())


def _read_sidecar(aes_path: Path) -> dict:
    """Try to read a .json sidecar file alongside the .aes file."""
    sidecar = aes_path.with_suffix('.json')
    if sidecar.exists():
        try:
            return json.loads(sidecar.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {}


def _read_autarch_meta(aes_path: Path) -> dict:
    """Try to read embedded AUTARCH-format metadata without decrypting."""
    try:
        from core.module_crypto import read_metadata
        meta = read_metadata(aes_path)
        if meta:
            return meta
    except Exception:
        pass
    return {}


def _get_module_info(path: Path) -> dict:
    """Build a metadata dict for a single .aes file."""
    stem        = path.stem
    meta        = _read_autarch_meta(path) or _read_sidecar(path)
    display     = meta.get('name') or _resolve_display_name(stem)
    size_kb     = round(path.stat().st_size / 1024, 1)

    return {
        'id':          stem,
        'filename':    path.name,
        'path':        str(path),
        'name':        display,
        'description': meta.get('description') or _DESCRIPTIONS.get(display, ''),
        'version':     meta.get('version', '—'),
        'author':      meta.get('author', '—'),
        'tags':        meta.get('tags') or _TAGS.get(display, []),
        'tag_colors':  _TAG_COLORS,
        'size_kb':     size_kb,
    }


def _list_modules() -> list[dict]:
    d = _module_dir()
    modules = []
    for p in sorted(d.glob('*.aes')):
        modules.append(_get_module_info(p))
    return modules


# ── Decryption ────────────────────────────────────────────────────────────────

def _decrypt_aes_file(path: Path, password: str) -> str:
    """
    Decrypt an .aes file and return the Python source string.

    Tries AUTARCH format first, then falls back to raw AES-256-CBC
    with the password as a 32-byte key (PBKDF2-derived or raw).
    """
    data = path.read_bytes()

    # ── AUTARCH format ────────────────────────────────────────────────────────
    try:
        from core.module_crypto import decrypt_module
        source, _ = decrypt_module(data, password)
        return source
    except ValueError as e:
        if 'bad magic' not in str(e).lower():
            raise  # Wrong password or tampered — propagate
    except Exception:
        pass

    # ── Fallback: raw AES-256-CBC, IV in first 16 bytes ──────────────────────
    # Key derived from password via SHA-512 (first 32 bytes)
    import hashlib
    raw_key  = hashlib.sha512(password.encode('utf-8')).digest()[:32]
    iv       = data[:16]
    ciphertext = data[16:]

    from core.module_crypto import _aes_decrypt
    try:
        plaintext = _aes_decrypt(raw_key, iv, ciphertext)
        return plaintext.decode('utf-8')
    except Exception:
        pass

    # ── Fallback 2: PBKDF2 with fixed salt ───────────────────────────────────
    import struct
    # Try with the first 16 bytes as IV and empty salt PBKDF2
    pbkdf_key = hashlib.pbkdf2_hmac('sha512', password.encode(), b'\x00' * 32, 10000, dklen=32)
    try:
        plaintext = _aes_decrypt(pbkdf_key, iv, ciphertext)
        return plaintext.decode('utf-8')
    except Exception:
        pass

    raise ValueError("Decryption failed — check your password/key")


# ── Execution ─────────────────────────────────────────────────────────────────

_active_runs: dict = {}   # run_id -> {'steps': [], 'done': bool, 'stop': Event}


def _exec_module(source: str, params: dict, run_id: str) -> None:
    """Execute decrypted module source in a background thread."""
    run = _active_runs[run_id]
    steps = run['steps']

    def output_cb(item: dict) -> None:
        steps.append(item)

    output_cb({'line': '[MODULE] Starting...'})
    namespace: dict = {
        '__name__': '__encmod__',
        '__builtins__': __builtins__,
    }
    try:
        exec(compile(source, '<encrypted_module>', 'exec'), namespace)
        if 'run' in namespace and callable(namespace['run']):
            result = namespace['run'](params, output_cb=output_cb)
            steps.append({'line': f'[MODULE] Finished.', 'result': result})
        else:
            steps.append({'line': '[MODULE] No run() function found — module loaded but not executed.'})
    except Exception as exc:
        steps.append({'line': f'[MODULE][ERROR] {exc}', 'error': True})
    finally:
        run['done'] = True


# ── Routes ────────────────────────────────────────────────────────────────────

@encmodules_bp.route('/')
@login_required
def index():
    return render_template('encmodules.html', modules=_list_modules())


@encmodules_bp.route('/upload', methods=['POST'])
@login_required
def upload():
    f = request.files.get('module_file')
    if not f or not f.filename:
        return jsonify({'error': 'No file provided'})
    filename = f.filename
    if not filename.lower().endswith('.aes'):
        return jsonify({'error': 'Only .aes files are accepted'})
    dest = _module_dir() / Path(filename).name
    f.save(str(dest))
    info = _get_module_info(dest)
    return jsonify({'ok': True, 'module': info})


@encmodules_bp.route('/verify', methods=['POST'])
@login_required
def verify():
    """Try to decrypt a module with the given password and return status (no execution)."""
    data     = request.get_json(silent=True) or {}
    filename = data.get('filename', '').strip()
    password = data.get('password', '').strip()
    if not filename or not password:
        return jsonify({'error': 'filename and password required'})
    path = _module_dir() / filename
    if not path.exists():
        return jsonify({'error': 'Module not found'})
    try:
        source = _decrypt_aes_file(path, password)
        lines  = source.count('\n') + 1
        has_run = 'def run(' in source
        return jsonify({'ok': True, 'lines': lines, 'has_run': has_run})
    except ValueError as exc:
        return jsonify({'error': str(exc)})
    except Exception as exc:
        return jsonify({'error': f'Unexpected error: {exc}'})


@encmodules_bp.route('/run', methods=['POST'])
@login_required
def run_module():
    """Decrypt and execute a module, returning a run_id for SSE streaming."""
    data     = request.get_json(silent=True) or {}
    filename = data.get('filename', '').strip()
    password = data.get('password', '').strip()
    params   = data.get('params', {})
    if not filename or not password:
        return jsonify({'error': 'filename and password required'})
    path = _module_dir() / filename
    if not path.exists():
        return jsonify({'error': 'Module not found'})
    try:
        source = _decrypt_aes_file(path, password)
    except ValueError as exc:
        return jsonify({'error': str(exc)})
    except Exception as exc:
        return jsonify({'error': f'Decrypt error: {exc}'})

    run_id = str(uuid.uuid4())
    stop_ev = threading.Event()
    _active_runs[run_id] = {'steps': [], 'done': False, 'stop': stop_ev}

    t = threading.Thread(target=_exec_module, args=(source, params, run_id), daemon=True)
    t.start()

    return jsonify({'ok': True, 'run_id': run_id})


@encmodules_bp.route('/stream/<run_id>')
@login_required
def stream(run_id: str):
    """SSE stream for a running module."""
    def generate():
        run = _active_runs.get(run_id)
        if not run:
            yield f"data: {json.dumps({'error': 'Run not found'})}\n\n"
            return
        sent = 0
        while True:
            steps = run['steps']
            while sent < len(steps):
                yield f"data: {json.dumps(steps[sent])}\n\n"
                sent += 1
            if run['done']:
                yield f"data: {json.dumps({'done': True})}\n\n"
                _active_runs.pop(run_id, None)
                return
            time.sleep(0.1)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@encmodules_bp.route('/stop/<run_id>', methods=['POST'])
@login_required
def stop_run(run_id: str):
    run = _active_runs.get(run_id)
    if run:
        run['stop'].set()
        run['done'] = True
    return jsonify({'stopped': bool(run)})


@encmodules_bp.route('/delete', methods=['POST'])
@login_required
def delete():
    data     = request.get_json(silent=True) or {}
    filename = data.get('filename', '').strip()
    if not filename:
        return jsonify({'error': 'filename required'})
    path = _module_dir() / filename
    if path.exists() and path.suffix.lower() == '.aes':
        path.unlink()
        sidecar = path.with_suffix('.json')
        if sidecar.exists():
            sidecar.unlink()
        return jsonify({'ok': True})
    return jsonify({'error': 'File not found or invalid'})


@encmodules_bp.route('/list')
@login_required
def list_modules():
    return jsonify({'modules': _list_modules()})
