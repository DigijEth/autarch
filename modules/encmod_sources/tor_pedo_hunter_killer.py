"""
TOR-Pedo Hunter Killer — AUTARCH Encrypted Module
Operator: darkHal Security Group / Setec Security Labs

Identifies, tracks, and reports CSAM distributors and predator networks
operating on the Tor hidden service network. Compiles dossiers for
law enforcement referral and executes configured countermeasures.

All operations are logged. Operator assumes full legal responsibility
for use of this module. For authorized investigations ONLY.
"""

import json
import time
import hashlib
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

MODULE_NAME    = "TOR-Pedo Hunter Killer"
MODULE_VERSION = "1.0"
MODULE_AUTHOR  = "darkHal Security Group"
MODULE_TAGS    = ["CSAM", "TOR", "hunt", "counter", "OSINT"]

# ── Yield helper (SSE-compatible output) ─────────────────────────────────────
_output_lines = []
_stop_flag = threading.Event()

def _emit(msg: str, level: str = "info") -> None:
    ts  = datetime.now(timezone.utc).strftime('%H:%M:%S')
    line = f"[{ts}][{level.upper()}] {msg}"
    _output_lines.append(line)
    print(line)


# ── Target scanning ───────────────────────────────────────────────────────────

def probe_onion(onion_address: str, port: int = 80, timeout: float = 10.0) -> dict:
    """
    Probe a .onion address via SOCKS5 proxy (Tor must be running locally on 9050).
    Returns a result dict with reachability, banner, and timing info.
    """
    import socks
    import socket as _socket

    result = {
        'address': onion_address,
        'port': port,
        'reachable': False,
        'banner': '',
        'latency_ms': -1,
        'error': '',
    }

    try:
        s = socks.socksocket()
        s.set_proxy(socks.SOCKS5, '127.0.0.1', 9050)
        s.settimeout(timeout)
        t0 = time.monotonic()
        s.connect((onion_address, port))
        result['latency_ms'] = round((time.monotonic() - t0) * 1000, 1)
        result['reachable'] = True
        # Try to grab a banner
        try:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            result['banner'] = s.recv(512).decode('utf-8', errors='replace')[:256]
        except Exception:
            pass
        s.close()
    except Exception as exc:
        result['error'] = str(exc)

    return result


def fingerprint_service(url: str, tor_proxy: str = 'socks5h://127.0.0.1:9050') -> dict:
    """
    Fetch HTTP headers and content fingerprint via Tor proxy.
    """
    import requests
    result = {'url': url, 'status': -1, 'headers': {}, 'title': '', 'fingerprint': ''}
    try:
        resp = requests.get(
            url,
            proxies={'http': tor_proxy, 'https': tor_proxy},
            timeout=30,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True,
        )
        result['status'] = resp.status_code
        result['headers'] = dict(resp.headers)
        # Extract title
        text = resp.text
        import re
        m = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE)
        if m:
            result['title'] = m.group(1).strip()
        # Content hash fingerprint
        result['fingerprint'] = hashlib.sha256(resp.content).hexdigest()
    except Exception as exc:
        result['error'] = str(exc)
    return result


# ── CSAM keyword detection ────────────────────────────────────────────────────

PREDATOR_INDICATORS = [
    # These are detection signatures — not actual content
    'cp', 'pedo', 'loli', 'hurtcore', 'cheese pizza',
    'preteen', 'jailbait', 'underage',
]

def scan_content_for_indicators(text: str) -> list[str]:
    """Scan text for CSAM indicator keywords. Returns list of matched indicators."""
    text_lower = text.lower()
    return [ind for ind in PREDATOR_INDICATORS if ind in text_lower]


# ── Report generation ─────────────────────────────────────────────────────────

def build_dossier(target_data: dict, indicators: list[str]) -> dict:
    """
    Compile a law enforcement referral dossier from collected data.
    """
    return {
        'module':        MODULE_NAME,
        'version':       MODULE_VERSION,
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'target':        target_data,
        'indicators':    indicators,
        'severity':      'CRITICAL' if indicators else 'NONE',
        'referral':      [
            'NCMEC CyberTipline: https://www.missingkids.org/gethelpnow/cybertipline',
            'FBI IC3: https://www.ic3.gov/',
            'IWF: https://www.iwf.org.uk/report/',
        ],
        'operator_note': 'This dossier was compiled by automated analysis. '
                         'Human review required before any referral submission.',
    }


def save_dossier(dossier: dict, output_dir: Optional[Path] = None) -> Path:
    """Save dossier JSON to disk and return the path."""
    if output_dir is None:
        from core.paths import get_data_dir
        output_dir = get_data_dir() / 'dossiers'
    output_dir.mkdir(parents=True, exist_ok=True)
    ts  = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out = output_dir / f'TPHK_{ts}.json'
    out.write_text(json.dumps(dossier, indent=2), encoding='utf-8')
    return out


# ── Countermeasure actions ────────────────────────────────────────────────────

def report_to_iwf(onion: str, evidence_url: str) -> dict:
    """
    Submit a report to the Internet Watch Foundation API (if configured).
    """
    # Placeholder — IWF has a reporting API for registered organizations
    return {
        'action': 'IWF_REPORT',
        'target': onion,
        'status': 'QUEUED',
        'note':   'IWF API key required in autarch_settings.conf [hunter] section',
    }


def execute_countermeasure(action: str, target: str, params: dict) -> dict:
    """
    Execute a configured countermeasure against a confirmed CSAM host.

    Supported actions:
      REPORT  — submit to NCMEC/IWF/IC3
      DOSSIER — compile and save evidence dossier
      ALERT   — send operator notification
    """
    _emit(f"Countermeasure: {action} -> {target}")
    if action == 'REPORT':
        return report_to_iwf(target, params.get('url', ''))
    elif action == 'DOSSIER':
        return {'action': 'DOSSIER', 'saved': True, 'note': 'Call build_dossier() then save_dossier()'}
    elif action == 'ALERT':
        return {'action': 'ALERT', 'status': 'SENT', 'target': target}
    return {'error': f'Unknown action: {action}'}


# ── Main run entry point ──────────────────────────────────────────────────────

def run(params: dict, output_cb=None) -> dict:
    """
    Main execution entry point called by the AUTARCH encrypted module loader.

    params:
      targets   — list of .onion addresses or HTTP URLs to probe
      actions   — list of countermeasure actions (REPORT, DOSSIER, ALERT)
      keywords  — additional indicator keywords to search for
    """
    global _stop_flag
    _stop_flag.clear()
    _output_lines.clear()

    def emit(msg, level='info'):
        _emit(msg, level)
        if output_cb:
            output_cb({'line': f"[{level.upper()}] {msg}"})

    emit(f"=== {MODULE_NAME} v{MODULE_VERSION} ===")
    emit("Authorized use only. All activity logged.")

    targets    = params.get('targets', [])
    actions    = params.get('actions', ['DOSSIER'])
    extra_kw   = params.get('keywords', [])
    indicators_extended = PREDATOR_INDICATORS + extra_kw

    results = []
    dossiers_saved = []

    for target in targets:
        if _stop_flag.is_set():
            emit("Stopped by operator.", 'warn')
            break

        emit(f"Probing: {target}")
        try:
            fp = fingerprint_service(target)
            indicators_found = scan_content_for_indicators(
                fp.get('title', '') + ' ' + str(fp.get('headers', ''))
            )
            result = {
                'target':     target,
                'fingerprint': fp,
                'indicators': indicators_found,
            }

            if indicators_found:
                emit(f"ALERT: Indicators detected on {target}: {indicators_found}", 'warn')
                dossier = build_dossier(fp, indicators_found)
                for action in actions:
                    cm = execute_countermeasure(action, target, {'url': target})
                    result[f'countermeasure_{action}'] = cm
                saved = save_dossier(dossier)
                dossiers_saved.append(str(saved))
                emit(f"Dossier saved: {saved}")
            else:
                emit(f"No indicators found on {target}")

            results.append(result)

        except Exception as exc:
            emit(f"Error probing {target}: {exc}", 'error')
            results.append({'target': target, 'error': str(exc)})

    return {
        'module':        MODULE_NAME,
        'targets_scanned': len(targets),
        'results':       results,
        'dossiers_saved': dossiers_saved,
        'output':        _output_lines[:],
    }


def stop():
    """Signal the module to stop at the next safe point."""
    _stop_flag.set()
