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
        'id':         str(uuid.uuid4()),
        'name':       data.get('name', '').strip() or host,
        'host':       host,
        'type':       data.get('type', 'ip'),
        'status':     data.get('status', 'active'),
        'os':         data.get('os', 'Unknown'),
        'tags':       [t.strip() for t in data.get('tags', '').split(',') if t.strip()],
        'ports':      data.get('ports', '').strip(),
        'notes':      data.get('notes', '').strip(),
        'created_at': now,
        'updated_at': now,
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
