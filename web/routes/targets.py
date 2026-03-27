"""Targets — scope and target management for pentest engagements."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

targets_bp = Blueprint('targets', __name__, url_prefix='/targets')

# ── Storage helpers ────────────────────────────────────────────────────────────

def _targets_file() -> Path:
    from core.paths import get_data_dir
    d = get_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / 'targets.json'


def _load() -> list:
    f = _targets_file()
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text(encoding='utf-8'))
    except Exception:
        return []


def _save(targets: list) -> None:
    _targets_file().write_text(json.dumps(targets, indent=2), encoding='utf-8')


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _new_target(data: dict) -> dict:
    host = data.get('host', '').strip()
    now = _now()
    return {
        'id':           str(uuid.uuid4()),
        'name':         data.get('name', '').strip() or host,
        'host':         host,
        'type':         data.get('type', 'ip'),
        'status':       data.get('status', 'active'),
        'os':           data.get('os', 'Unknown'),
        'tags':         [t.strip() for t in data.get('tags', '').split(',') if t.strip()],
        'ports':        data.get('ports', '').strip(),
        'notes':        data.get('notes', '').strip(),
        # Investigation profile fields
        'ipv4':         data.get('ipv4', '').strip(),
        'ipv6':         data.get('ipv6', '').strip(),
        'domain':       data.get('domain', '').strip(),
        'dns_records':  data.get('dns_records', '').strip(),
        'email':        data.get('email', '').strip(),
        'usernames':    data.get('usernames', '').strip(),
        'geo_country':  data.get('geo_country', '').strip(),
        'geo_city':     data.get('geo_city', '').strip(),
        'geo_isp':      data.get('geo_isp', '').strip(),
        'geo_asn':      data.get('geo_asn', '').strip(),
        'geo_coords':   data.get('geo_coords', '').strip(),
        'traceroute':   data.get('traceroute', '').strip(),
        'whois':        data.get('whois', '').strip(),
        'rdns':         data.get('rdns', '').strip(),
        'mac_address':  data.get('mac_address', '').strip(),
        'hostname':     data.get('hostname', '').strip(),
        'services':     data.get('services', '').strip(),
        'vulns':        data.get('vulns', '').strip(),
        'threat_level': data.get('threat_level', 'unknown'),
        'source':       data.get('source', '').strip(),
        'first_seen':   data.get('first_seen', now),
        'last_seen':    data.get('last_seen', now),
        'custom_fields': data.get('custom_fields', []),
        'created_at':   now,
        'updated_at':   now,
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@targets_bp.route('/')
@login_required
def index():
    return render_template('targets.html', targets=_load())


@targets_bp.route('/add', methods=['POST'])
@login_required
def add():
    data = request.get_json(silent=True) or {}
    if not data.get('host', '').strip():
        return jsonify({'error': 'Host/IP is required'})
    targets = _load()
    t = _new_target(data)
    targets.append(t)
    _save(targets)
    return jsonify({'ok': True, 'target': t})


@targets_bp.route('/update/<tid>', methods=['POST'])
@login_required
def update(tid):
    data = request.get_json(silent=True) or {}
    targets = _load()
    for t in targets:
        if t['id'] == tid:
            for field in ('name', 'host', 'type', 'status', 'os', 'ports', 'notes'):
                if field in data:
                    t[field] = str(data[field]).strip()
            if 'tags' in data:
                t['tags'] = [x.strip() for x in str(data['tags']).split(',') if x.strip()]
            t['updated_at'] = _now()
            _save(targets)
            return jsonify({'ok': True, 'target': t})
    return jsonify({'error': 'Target not found'})


@targets_bp.route('/delete/<tid>', methods=['POST'])
@login_required
def delete(tid):
    targets = _load()
    before = len(targets)
    targets = [t for t in targets if t['id'] != tid]
    if len(targets) < before:
        _save(targets)
        return jsonify({'ok': True})
    return jsonify({'error': 'Not found'})


@targets_bp.route('/status/<tid>', methods=['POST'])
@login_required
def set_status(tid):
    data = request.get_json(silent=True) or {}
    status = data.get('status', '')
    valid = {'active', 'pending', 'completed', 'out-of-scope'}
    if status not in valid:
        return jsonify({'error': f'Invalid status — use: {", ".join(sorted(valid))}'})
    targets = _load()
    for t in targets:
        if t['id'] == tid:
            t['status'] = status
            t['updated_at'] = _now()
            _save(targets)
            return jsonify({'ok': True})
    return jsonify({'error': 'Not found'})


@targets_bp.route('/export')
@login_required
def export():
    targets = _load()
    return Response(
        json.dumps(targets, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename="autarch_targets.json"'},
    )


@targets_bp.route('/import', methods=['POST'])
@login_required
def import_targets():
    data = request.get_json(silent=True) or {}
    incoming = data.get('targets', [])
    if not isinstance(incoming, list):
        return jsonify({'error': 'Expected JSON array'})
    existing = _load()
    existing_ids = {t['id'] for t in existing}
    now = _now()
    added = 0
    for item in incoming:
        if not isinstance(item, dict) or not item.get('host', '').strip():
            continue
        item.setdefault('id', str(uuid.uuid4()))
        if item['id'] in existing_ids:
            continue
        item.setdefault('name', item['host'])
        item.setdefault('type', 'ip')
        item.setdefault('status', 'active')
        item.setdefault('os', 'Unknown')
        item.setdefault('tags', [])
        item.setdefault('ports', '')
        item.setdefault('notes', '')
        item.setdefault('created_at', now)
        item.setdefault('updated_at', now)
        existing.append(item)
        added += 1
    _save(existing)
    return jsonify({'ok': True, 'added': added, 'total': len(existing)})


# ══════════════════════════════════════════════════════════════════════════════
# INVESTIGATION REPORTS (IR)
# ══════════════════════════════════════════════════════════════════════════════

def _ir_file() -> Path:
    p = Path(__file__).parent.parent.parent / 'data' / 'reports' / 'investigation_reports.json'
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def _load_irs() -> list:
    f = _ir_file()
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            return []
    return []


def _save_irs(irs: list):
    _ir_file().write_text(json.dumps(irs, indent=2))


def _generate_ir_id(ip: str = '') -> str:
    """Generate IR identifier — hex from IP if available, otherwise random 9-char hex."""
    if ip and ip.strip():
        # Convert IP octets to hex
        parts = ip.strip().split('.')
        if len(parts) == 4:
            try:
                return 'IR-' + ''.join(f'{int(p):02X}' for p in parts)
            except ValueError:
                pass
    # Random 9-char hex
    return 'IR-' + uuid.uuid4().hex[:9].upper()


@targets_bp.route('/ir')
@login_required
def ir_list():
    """List all investigation reports."""
    return jsonify({'ok': True, 'reports': _load_irs()})


@targets_bp.route('/ir/create', methods=['POST'])
@login_required
def ir_create():
    """Create a new investigation report."""
    data = request.get_json(silent=True) or {}
    now = datetime.now(timezone.utc).isoformat()

    ip = data.get('ip', data.get('host', ''))
    ir_id = _generate_ir_id(ip)

    # Detect if created by HAL
    is_hal = 'HAL' in data.get('source', '') or 'hal' in data.get('source', '').lower()

    report = {
        'id': ir_id,
        'title': data.get('title', f'Investigation {ir_id}'),
        'ip': ip,
        'status': data.get('status', 'open'),
        'threat_level': data.get('threat_level', 'unknown'),
        'source': data.get('source', ''),
        'created_by_hal': is_hal,
        'scan_type': data.get('scan_type', ''),
        'scan_output': data.get('scan_output', ''),
        'analysis': data.get('analysis', ''),
        'risk_level': data.get('risk_level', ''),
        'fix_attempted': data.get('fix_attempted', False),
        'fix_results': data.get('fix_results', ''),
        'recommendations': data.get('recommendations', ''),
        'geo': data.get('geo', {}),
        'custom_fields': data.get('custom_fields', []),
        'notes': data.get('notes', ''),
        'created_at': now,
        'updated_at': now,
    }

    irs = _load_irs()
    irs.insert(0, report)
    _save_irs(irs)
    return jsonify({'ok': True, 'ir': report})


@targets_bp.route('/ir/<ir_id>', methods=['GET'])
@login_required
def ir_get(ir_id):
    """Get a single IR."""
    irs = _load_irs()
    for ir in irs:
        if ir['id'] == ir_id:
            return jsonify({'ok': True, 'ir': ir})
    return jsonify({'ok': False, 'error': 'IR not found'})


@targets_bp.route('/ir/<ir_id>/update', methods=['POST'])
@login_required
def ir_update(ir_id):
    """Update an existing IR."""
    data = request.get_json(silent=True) or {}
    irs = _load_irs()
    for ir in irs:
        if ir['id'] == ir_id:
            for key in data:
                if key != 'id':
                    ir[key] = data[key]
            ir['updated_at'] = datetime.now(timezone.utc).isoformat()
            _save_irs(irs)
            return jsonify({'ok': True, 'ir': ir})
    return jsonify({'ok': False, 'error': 'IR not found'})


@targets_bp.route('/ir/<ir_id>/load-to-hal', methods=['POST'])
@login_required
def ir_load_to_hal(ir_id):
    """Load an IR's details into HAL's memory so the agent can continue working on it."""
    irs = _load_irs()
    for ir in irs:
        if ir['id'] == ir_id:
            try:
                from core.hal_memory import get_hal_memory
                mem = get_hal_memory()
                mem.add('context', json.dumps(ir), metadata={'type': 'ir_loaded', 'ir_id': ir_id})
                mem.save()
            except Exception:
                pass
            return jsonify({'ok': True, 'ir': ir})
    return jsonify({'ok': False, 'error': 'IR not found'})


@targets_bp.route('/ir/<ir_id>/delete', methods=['POST'])
@login_required
def ir_delete(ir_id):
    """Delete an IR."""
    irs = _load_irs()
    irs = [ir for ir in irs if ir['id'] != ir_id]
    _save_irs(irs)
    return jsonify({'ok': True})
