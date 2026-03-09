"""Settings route"""

import collections
import json
import logging
import os
import platform
import re
import subprocess
import threading
import time
from pathlib import Path

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app, Response
from web.auth import login_required, hash_password, save_credentials, load_credentials

# ── Debug Console infrastructure ─────────────────────────────────────────────

_debug_buffer: collections.deque = collections.deque(maxlen=2000)
_debug_enabled: bool = False
_debug_handler_installed: bool = False


def _buf_append(level: str, name: str, raw: str, msg: str, exc: str = '') -> None:
    """Thread-safe append to the debug buffer."""
    entry: dict = {'ts': time.time(), 'level': level, 'name': name, 'raw': raw, 'msg': msg}
    if exc:
        entry['exc'] = exc
    _debug_buffer.append(entry)


class _DebugBufferHandler(logging.Handler):
    """Captures ALL log records into the in-memory debug buffer (always active)."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            exc_text = ''
            if record.exc_info:
                import traceback as _tb
                exc_text = ''.join(_tb.format_exception(*record.exc_info))
            _buf_append(
                level=record.levelname,
                name=record.name,
                raw=record.getMessage(),
                msg=self.format(record),
                exc=exc_text,
            )
        except Exception:
            pass


class _PrintCapture:
    """Wraps sys.stdout or sys.stderr — passes through AND feeds lines to the debug buffer."""

    def __init__(self, original, level: str = 'STDOUT'):
        self._orig = original
        self._level = level
        self._line_buf = ''

    def write(self, text: str) -> int:
        self._orig.write(text)
        self._line_buf += text
        while '\n' in self._line_buf:
            line, self._line_buf = self._line_buf.split('\n', 1)
            if line.strip():
                _buf_append(self._level, 'print', line, line)
        return len(text)

    def flush(self) -> None:
        self._orig.flush()

    def __getattr__(self, name):
        return getattr(self._orig, name)


def _ensure_debug_handler() -> None:
    """Install logging handler + stdout/stderr capture once, at startup."""
    global _debug_handler_installed
    if _debug_handler_installed:
        return
    # Logging handler
    handler = _DebugBufferHandler()
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('%(name)s — %(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)
    if root.level == logging.NOTSET or root.level > logging.DEBUG:
        root.setLevel(logging.DEBUG)
    # stdout / stderr capture
    import sys as _sys
    if not isinstance(_sys.stdout, _PrintCapture):
        _sys.stdout = _PrintCapture(_sys.stdout, 'STDOUT')
    if not isinstance(_sys.stderr, _PrintCapture):
        _sys.stderr = _PrintCapture(_sys.stderr, 'STDERR')
    _debug_handler_installed = True


# Install immediately so we capture from process start, not just after toggle
_ensure_debug_handler()

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')


@settings_bp.route('/')
@login_required
def index():
    config = current_app.autarch_config
    return render_template('settings.html',
        llm_backend=config.get('autarch', 'llm_backend', 'local'),
        llama=config.get_llama_settings(),
        transformers=config.get_transformers_settings(),
        claude=config.get_claude_settings(),
        huggingface=config.get_huggingface_settings(),
        osint=config.get_osint_settings(),
        pentest=config.get_pentest_settings(),
        upnp=config.get_upnp_settings(),
        debug_enabled=_debug_enabled,
    )


@settings_bp.route('/password', methods=['POST'])
@login_required
def change_password():
    new_pass = request.form.get('new_password', '')
    confirm = request.form.get('confirm_password', '')

    if not new_pass or len(new_pass) < 4:
        flash('Password must be at least 4 characters.', 'error')
        return redirect(url_for('settings.index'))

    if new_pass != confirm:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('settings.index'))

    creds = load_credentials()
    save_credentials(creds['username'], hash_password(new_pass), force_change=False)
    flash('Password updated.', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/osint', methods=['POST'])
@login_required
def update_osint():
    config = current_app.autarch_config
    config.set('osint', 'max_threads', request.form.get('max_threads', '8'))
    config.set('osint', 'timeout', request.form.get('timeout', '8'))
    config.set('osint', 'include_nsfw', 'true' if request.form.get('include_nsfw') else 'false')
    config.save()
    flash('OSINT settings updated.', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/upnp', methods=['POST'])
@login_required
def update_upnp():
    config = current_app.autarch_config
    config.set('upnp', 'enabled', 'true' if request.form.get('enabled') else 'false')
    config.set('upnp', 'internal_ip', request.form.get('internal_ip', '10.0.0.26'))
    config.set('upnp', 'refresh_hours', request.form.get('refresh_hours', '12'))
    config.set('upnp', 'mappings', request.form.get('mappings', ''))
    config.save()
    flash('UPnP settings updated.', 'success')
    return redirect(url_for('settings.index'))


@settings_bp.route('/llm', methods=['POST'])
@login_required
def update_llm():
    config = current_app.autarch_config
    backend = request.form.get('backend', 'local')

    if backend == 'local':
        config.set('llama', 'model_path', request.form.get('model_path', ''))
        config.set('llama', 'n_ctx', request.form.get('n_ctx', '4096'))
        config.set('llama', 'n_threads', request.form.get('n_threads', '4'))
        config.set('llama', 'n_gpu_layers', request.form.get('n_gpu_layers', '0'))
        config.set('llama', 'n_batch', request.form.get('n_batch', '512'))
        config.set('llama', 'temperature', request.form.get('temperature', '0.7'))
        config.set('llama', 'top_p', request.form.get('top_p', '0.9'))
        config.set('llama', 'top_k', request.form.get('top_k', '40'))
        config.set('llama', 'repeat_penalty', request.form.get('repeat_penalty', '1.1'))
        config.set('llama', 'max_tokens', request.form.get('max_tokens', '2048'))
        config.set('llama', 'seed', request.form.get('seed', '-1'))
        config.set('llama', 'rope_scaling_type', request.form.get('rope_scaling_type', '0'))
        config.set('llama', 'mirostat_mode', request.form.get('mirostat_mode', '0'))
        config.set('llama', 'mirostat_tau', request.form.get('mirostat_tau', '5.0'))
        config.set('llama', 'mirostat_eta', request.form.get('mirostat_eta', '0.1'))
        config.set('llama', 'flash_attn', 'true' if request.form.get('flash_attn') else 'false')
        config.set('llama', 'gpu_backend', request.form.get('gpu_backend', 'cpu'))
    elif backend == 'transformers':
        config.set('transformers', 'model_path', request.form.get('model_path', ''))
        config.set('transformers', 'device', request.form.get('device', 'auto'))
        config.set('transformers', 'torch_dtype', request.form.get('torch_dtype', 'auto'))
        config.set('transformers', 'load_in_8bit', 'true' if request.form.get('load_in_8bit') else 'false')
        config.set('transformers', 'load_in_4bit', 'true' if request.form.get('load_in_4bit') else 'false')
        config.set('transformers', 'llm_int8_enable_fp32_cpu_offload', 'true' if request.form.get('llm_int8_enable_fp32_cpu_offload') else 'false')
        config.set('transformers', 'device_map', request.form.get('device_map', 'auto'))
        config.set('transformers', 'trust_remote_code', 'true' if request.form.get('trust_remote_code') else 'false')
        config.set('transformers', 'use_fast_tokenizer', 'true' if request.form.get('use_fast_tokenizer') else 'false')
        config.set('transformers', 'padding_side', request.form.get('padding_side', 'left'))
        config.set('transformers', 'do_sample', 'true' if request.form.get('do_sample') else 'false')
        config.set('transformers', 'num_beams', request.form.get('num_beams', '1'))
        config.set('transformers', 'temperature', request.form.get('temperature', '0.7'))
        config.set('transformers', 'top_p', request.form.get('top_p', '0.9'))
        config.set('transformers', 'top_k', request.form.get('top_k', '40'))
        config.set('transformers', 'repetition_penalty', request.form.get('repetition_penalty', '1.1'))
        config.set('transformers', 'max_tokens', request.form.get('max_tokens', '2048'))
    elif backend == 'claude':
        config.set('claude', 'model', request.form.get('model', 'claude-sonnet-4-20250514'))
        api_key = request.form.get('api_key', '')
        if api_key:
            config.set('claude', 'api_key', api_key)
        config.set('claude', 'max_tokens', request.form.get('max_tokens', '4096'))
        config.set('claude', 'temperature', request.form.get('temperature', '0.7'))
    elif backend == 'huggingface':
        config.set('huggingface', 'model', request.form.get('model', 'mistralai/Mistral-7B-Instruct-v0.3'))
        api_key = request.form.get('api_key', '')
        if api_key:
            config.set('huggingface', 'api_key', api_key)
        config.set('huggingface', 'endpoint', request.form.get('endpoint', ''))
        config.set('huggingface', 'provider', request.form.get('provider', 'auto'))
        config.set('huggingface', 'max_tokens', request.form.get('max_tokens', '1024'))
        config.set('huggingface', 'temperature', request.form.get('temperature', '0.7'))
        config.set('huggingface', 'top_p', request.form.get('top_p', '0.9'))
        config.set('huggingface', 'top_k', request.form.get('top_k', '40'))
        config.set('huggingface', 'repetition_penalty', request.form.get('repetition_penalty', '1.1'))
        config.set('huggingface', 'do_sample', 'true' if request.form.get('do_sample') else 'false')
        config.set('huggingface', 'seed', request.form.get('seed', '-1'))
        config.set('huggingface', 'stop_sequences', request.form.get('stop_sequences', ''))
    elif backend == 'openai':
        config.set('openai', 'model', request.form.get('model', 'gpt-4o'))
        api_key = request.form.get('api_key', '')
        if api_key:
            config.set('openai', 'api_key', api_key)
        config.set('openai', 'base_url', request.form.get('base_url', 'https://api.openai.com/v1'))
        config.set('openai', 'max_tokens', request.form.get('max_tokens', '4096'))
        config.set('openai', 'temperature', request.form.get('temperature', '0.7'))
        config.set('openai', 'top_p', request.form.get('top_p', '1.0'))
        config.set('openai', 'frequency_penalty', request.form.get('frequency_penalty', '0.0'))
        config.set('openai', 'presence_penalty', request.form.get('presence_penalty', '0.0'))

    # Switch active backend
    config.set('autarch', 'llm_backend', backend)
    config.save()

    _log = logging.getLogger('autarch.settings')
    _log.info(f"[Settings] LLM backend switched to: {backend}")

    # Reset LLM instance so next request triggers fresh load
    try:
        from core.llm import reset_llm
        reset_llm()
        _log.info("[Settings] LLM instance reset — will reload on next chat request")
    except Exception as exc:
        _log.error(f"[Settings] reset_llm() error: {exc}", exc_info=True)

    flash(f'LLM backend switched to {backend} and settings saved.', 'success')
    return redirect(url_for('settings.llm_settings'))


# ── LLM Settings Sub-Page ─────────────────────────────────────────────────────

@settings_bp.route('/llm')
@login_required
def llm_settings():
    config = current_app.autarch_config
    from core.paths import get_app_dir
    default_models_dir = str(get_app_dir() / 'models')
    return render_template('llm_settings.html',
        llm_backend=config.get('autarch', 'llm_backend', 'local'),
        llama=config.get_llama_settings(),
        transformers=config.get_transformers_settings(),
        claude=config.get_claude_settings(),
        openai=config.get_openai_settings(),
        huggingface=config.get_huggingface_settings(),
        default_models_dir=default_models_dir,
    )


@settings_bp.route('/llm/load', methods=['POST'])
@login_required
def llm_load():
    """Force-load the currently configured LLM backend and return status."""
    _log = logging.getLogger('autarch.settings')
    try:
        from core.llm import reset_llm, get_llm
        from core.config import get_config
        config = get_config()
        backend = config.get('autarch', 'llm_backend', 'local')
        _log.info(f"[LLM Load] Requested by user — backend: {backend}")
        reset_llm()
        llm = get_llm()
        model_name = llm.model_name if hasattr(llm, 'model_name') else 'unknown'
        _log.info(f"[LLM Load] Success — backend: {backend} | model: {model_name}")
        return jsonify({'ok': True, 'backend': backend, 'model_name': model_name})
    except Exception as exc:
        _log.error(f"[LLM Load] Failed: {exc}", exc_info=True)
        return jsonify({'ok': False, 'error': str(exc)})


@settings_bp.route('/llm/scan-models', methods=['POST'])
@login_required
def llm_scan_models():
    """Scan a folder for supported local model files and return a list."""
    data = request.get_json(silent=True) or {}
    folder = data.get('folder', '').strip()
    if not folder:
        return jsonify({'ok': False, 'error': 'No folder provided'})

    folder_path = Path(folder)
    if not folder_path.is_dir():
        return jsonify({'ok': False, 'error': f'Directory not found: {folder}'})

    models = []
    try:
        # GGUF / GGML / legacy bin files (single-file models)
        for ext in ('*.gguf', '*.ggml', '*.bin'):
            for p in sorted(folder_path.glob(ext)):
                size_mb = p.stat().st_size / (1024 * 1024)
                models.append({
                    'name': p.name,
                    'path': str(p),
                    'type': 'gguf' if p.suffix in ('.gguf', '.ggml') else 'bin',
                    'size_mb': round(size_mb, 1),
                })

        # SafeTensors model directories (contain config.json + *.safetensors)
        for child in sorted(folder_path.iterdir()):
            if not child.is_dir():
                continue
            has_config = (child / 'config.json').exists()
            has_st = any(child.glob('*.safetensors'))
            has_st_index = (child / 'model.safetensors.index.json').exists()
            if has_config and (has_st or has_st_index):
                total_mb = sum(
                    p.stat().st_size for p in child.glob('*.safetensors')
                ) / (1024 * 1024)
                models.append({
                    'name': child.name + '/',
                    'path': str(child),
                    'type': 'safetensors',
                    'size_mb': round(total_mb, 1),
                })

        # Also scan one level of subdirectories for GGUF files
        for child in sorted(folder_path.iterdir()):
            if not child.is_dir():
                continue
            for ext in ('*.gguf', '*.ggml'):
                for p in sorted(child.glob(ext)):
                    size_mb = p.stat().st_size / (1024 * 1024)
                    models.append({
                        'name': child.name + '/' + p.name,
                        'path': str(p),
                        'type': 'gguf',
                        'size_mb': round(size_mb, 1),
                    })

        return jsonify({'ok': True, 'models': models, 'folder': str(folder_path)})
    except PermissionError as e:
        return jsonify({'ok': False, 'error': f'Permission denied: {e}'})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/llm/hf-verify', methods=['POST'])
@login_required
def llm_hf_verify():
    """Verify a HuggingFace token and return account info."""
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    if not token:
        return jsonify({'ok': False, 'error': 'No token provided'})
    try:
        from huggingface_hub import HfApi
        api = HfApi(token=token)
        info = api.whoami()
        return jsonify({'ok': True, 'username': info.get('name', ''), 'email': info.get('email', '')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ── MCP Server API ───────────────────────────────────────────

@settings_bp.route('/mcp/status', methods=['POST'])
@login_required
def mcp_status():
    try:
        from core.mcp_server import get_server_status, get_autarch_tools
        status = get_server_status()
        tools = [{'name': t['name'], 'description': t['description']} for t in get_autarch_tools()]
        return jsonify({'ok': True, 'status': status, 'tools': tools})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/mcp/start', methods=['POST'])
@login_required
def mcp_start():
    try:
        from core.mcp_server import start_sse_server
        config = current_app.autarch_config
        port = int(config.get('web', 'mcp_port', fallback='8081'))
        result = start_sse_server(port=port)
        return jsonify(result)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/mcp/stop', methods=['POST'])
@login_required
def mcp_stop():
    try:
        from core.mcp_server import stop_sse_server
        result = stop_sse_server()
        return jsonify(result)
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/mcp/config', methods=['POST'])
@login_required
def mcp_config():
    try:
        from core.mcp_server import get_mcp_config_snippet
        return jsonify({'ok': True, 'config': get_mcp_config_snippet()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ── Discovery API ────────────────────────────────────────────

@settings_bp.route('/discovery/status', methods=['POST'])
@login_required
def discovery_status():
    try:
        from core.discovery import get_discovery_manager
        mgr = get_discovery_manager()
        return jsonify({'ok': True, 'status': mgr.get_status()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/discovery/start', methods=['POST'])
@login_required
def discovery_start():
    try:
        from core.discovery import get_discovery_manager
        mgr = get_discovery_manager()
        results = mgr.start_all()
        return jsonify({'ok': True, 'results': results})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@settings_bp.route('/discovery/stop', methods=['POST'])
@login_required
def discovery_stop():
    try:
        from core.discovery import get_discovery_manager
        mgr = get_discovery_manager()
        results = mgr.stop_all()
        return jsonify({'ok': True, 'results': results})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ── Debug Console API ─────────────────────────────────────────────────────────

@settings_bp.route('/debug/toggle', methods=['POST'])
@login_required
def debug_toggle():
    """Enable or disable the debug console UI (capture always runs)."""
    global _debug_enabled
    data = request.get_json(silent=True) or {}
    _debug_enabled = bool(data.get('enabled', False))
    if _debug_enabled:
        logging.getLogger('autarch.debug').info('Debug console opened')
    return jsonify({'ok': True, 'enabled': _debug_enabled})


@settings_bp.route('/debug/stream')
@login_required
def debug_stream():
    """SSE stream — pushes log records to the browser as they arrive.

    On connect: sends the last 200 buffered entries as history, then streams
    new entries live.  Handles deque wrap-around correctly.
    """
    def generate():
        buf = list(_debug_buffer)
        # Send last 200 entries as catch-up history
        history_start = max(0, len(buf) - 200)
        for entry in buf[history_start:]:
            yield f"data: {json.dumps(entry)}\n\n"
        sent = len(buf)

        while True:
            time.sleep(0.2)
            buf = list(_debug_buffer)
            n = len(buf)
            if sent > n:
                # deque wrapped; re-orient to current tail
                sent = n
            while sent < n:
                yield f"data: {json.dumps(buf[sent])}\n\n"
                sent += 1
            yield ': keepalive\n\n'

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@settings_bp.route('/debug/clear', methods=['POST'])
@login_required
def debug_clear():
    """Clear the in-memory debug buffer."""
    _debug_buffer.clear()
    return jsonify({'ok': True})


@settings_bp.route('/debug/test', methods=['POST'])
@login_required
def debug_test():
    """Emit one log record at each level so the user can verify the debug window."""
    log = logging.getLogger('autarch.test')
    log.debug('DEBUG  — detailed diagnostic info, variable states')
    log.info('INFO   — normal operation: module loaded, connection established')
    log.warning('WARNING — something unexpected but recoverable')
    log.error('ERROR  — an operation failed, check the details below')
    try:
        raise ValueError('Example exception to show stack trace capture')
    except ValueError:
        log.exception('EXCEPTION — error with full traceback')
    return jsonify({'ok': True, 'sent': 5})


# ==================== DEPENDENCIES ====================

@settings_bp.route('/deps')
@login_required
def deps_index():
    """Dependencies management page."""
    return render_template('system_deps.html')


@settings_bp.route('/deps/check', methods=['POST'])
@login_required
def deps_check():
    """Check all system dependencies."""
    import sys as _sys

    groups = {
        'core': {
            'flask': 'import flask; print(flask.__version__)',
            'jinja2': 'import jinja2; print(jinja2.__version__)',
            'requests': 'import requests; print(requests.__version__)',
            'cryptography': 'import cryptography; print(cryptography.__version__)',
        },
        'llm': {
            'llama-cpp-python': 'import llama_cpp; print(llama_cpp.__version__)',
            'transformers': 'import transformers; print(transformers.__version__)',
            'anthropic': 'import anthropic; print(anthropic.__version__)',
        },
        'training': {
            'torch': 'import torch; print(torch.__version__)',
            'peft': 'import peft; print(peft.__version__)',
            'datasets': 'import datasets; print(datasets.__version__)',
            'trl': 'import trl; print(trl.__version__)',
            'accelerate': 'import accelerate; print(accelerate.__version__)',
            'bitsandbytes': 'import bitsandbytes; print(bitsandbytes.__version__)',
            'unsloth': 'import unsloth; print(unsloth.__version__)',
        },
        'network': {
            'scapy': 'import scapy; print(scapy.VERSION)',
            'pyshark': 'import pyshark; print(pyshark.__version__)',
            'miniupnpc': 'import miniupnpc; print("installed")',
            'msgpack': 'import msgpack; print(msgpack.version)',
            'paramiko': 'import paramiko; print(paramiko.__version__)',
        },
        'hardware': {
            'pyserial': 'import serial; print(serial.__version__)',
            'esptool': 'import esptool; print(esptool.__version__)',
            'adb-shell': 'import adb_shell; print("installed")',
        },
    }

    results = {}
    for group, packages in groups.items():
        results[group] = {}
        for name, cmd in packages.items():
            try:
                result = subprocess.run(
                    [_sys.executable, '-c', cmd],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    results[group][name] = {'installed': True, 'version': result.stdout.strip()}
                else:
                    results[group][name] = {'installed': False, 'version': None}
            except Exception:
                results[group][name] = {'installed': False, 'version': None}

    # GPU info
    gpu = {}
    try:
        result = subprocess.run(
            [_sys.executable, '-c',
             'import torch; print(torch.cuda.is_available()); '
             'print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else "none"); '
             'print(torch.version.cuda or "none")'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            gpu['cuda_available'] = lines[0].strip() == 'True'
            gpu['device'] = lines[1].strip() if len(lines) > 1 else 'none'
            gpu['cuda_version'] = lines[2].strip() if len(lines) > 2 else 'none'
    except Exception:
        gpu['cuda_available'] = False
    results['gpu'] = gpu

    # Python info
    import sys as _s
    results['python'] = {
        'version': _s.version.split()[0],
        'executable': _s.executable,
        'platform': platform.platform(),
    }

    return jsonify(results)


@settings_bp.route('/deps/install', methods=['POST'])
@login_required
def deps_install():
    """Install packages."""
    import sys as _sys
    data = request.get_json(silent=True) or {}
    packages = data.get('packages', [])
    if not packages:
        return jsonify({'error': 'No packages specified'}), 400

    results = []
    for pkg in packages:
        # Sanitize package name
        if not re.match(r'^[a-zA-Z0-9_\-\[\]]+$', pkg):
            results.append({'package': pkg, 'success': False, 'output': 'Invalid package name'})
            continue
        try:
            result = subprocess.run(
                [_sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                capture_output=True, text=True, timeout=300
            )
            results.append({
                'package': pkg,
                'success': result.returncode == 0,
                'output': result.stdout.strip() or result.stderr.strip()[:200],
            })
        except Exception as e:
            results.append({'package': pkg, 'success': False, 'output': str(e)[:200]})

    return jsonify({'results': results})
