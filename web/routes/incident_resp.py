"""Incident Response routes."""

from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

incident_resp_bp = Blueprint('incident_resp', __name__, url_prefix='/incident-resp')


def _get_ir():
    from modules.incident_resp import get_incident_resp
    return get_incident_resp()


# ── Page ─────────────────────────────────────────────────────────

@incident_resp_bp.route('/')
@login_required
def index():
    return render_template('incident_resp.html')


# ── Incidents CRUD ───────────────────────────────────────────────

@incident_resp_bp.route('/incidents', methods=['POST'])
@login_required
def create_incident():
    data = request.get_json(silent=True) or {}
    result = _get_ir().create_incident(
        name=data.get('name', '').strip(),
        incident_type=data.get('type', '').strip(),
        severity=data.get('severity', '').strip(),
        description=data.get('description', '').strip(),
    )
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@incident_resp_bp.route('/incidents', methods=['GET'])
@login_required
def list_incidents():
    status = request.args.get('status')
    incidents = _get_ir().list_incidents(status=status)
    return jsonify({'incidents': incidents})


@incident_resp_bp.route('/incidents/<incident_id>', methods=['GET'])
@login_required
def get_incident(incident_id):
    result = _get_ir().get_incident(incident_id)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>', methods=['PUT'])
@login_required
def update_incident(incident_id):
    data = request.get_json(silent=True) or {}
    result = _get_ir().update_incident(incident_id, data)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>', methods=['DELETE'])
@login_required
def delete_incident(incident_id):
    result = _get_ir().delete_incident(incident_id)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>/close', methods=['POST'])
@login_required
def close_incident(incident_id):
    data = request.get_json(silent=True) or {}
    result = _get_ir().close_incident(incident_id, data.get('resolution_notes', ''))
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


# ── Playbook ─────────────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/playbook', methods=['GET'])
@login_required
def get_playbook(incident_id):
    inc = _get_ir().get_incident(incident_id)
    if 'error' in inc:
        return jsonify(inc), 404
    pb = _get_ir().get_playbook(inc['type'])
    if 'error' in pb:
        return jsonify(pb), 404
    pb['progress'] = inc.get('playbook_progress', [])
    pb['outputs'] = inc.get('playbook_outputs', [])
    return jsonify(pb)


@incident_resp_bp.route('/incidents/<incident_id>/playbook/<int:step>', methods=['POST'])
@login_required
def run_playbook_step(incident_id, step):
    data = request.get_json(silent=True) or {}
    auto = data.get('auto', False)
    result = _get_ir().run_playbook_step(incident_id, step, auto=auto)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# ── Evidence ─────────────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/evidence/collect', methods=['POST'])
@login_required
def collect_evidence(incident_id):
    data = request.get_json(silent=True) or {}
    result = _get_ir().collect_evidence(incident_id, data.get('type', ''),
                                        source=data.get('source'))
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>/evidence', methods=['POST'])
@login_required
def add_evidence(incident_id):
    data = request.get_json(silent=True) or {}
    result = _get_ir().add_evidence(
        incident_id,
        name=data.get('name', 'manual_note'),
        content=data.get('content', ''),
        evidence_type=data.get('evidence_type', 'manual'),
    )
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>/evidence', methods=['GET'])
@login_required
def list_evidence(incident_id):
    evidence = _get_ir().list_evidence(incident_id)
    return jsonify({'evidence': evidence})


# ── IOC Sweep ────────────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/sweep', methods=['POST'])
@login_required
def sweep_iocs(incident_id):
    data = request.get_json(silent=True) or {}
    iocs = {
        'ips': [ip.strip() for ip in data.get('ips', []) if ip.strip()],
        'domains': [d.strip() for d in data.get('domains', []) if d.strip()],
        'hashes': [h.strip() for h in data.get('hashes', []) if h.strip()],
    }
    result = _get_ir().sweep_iocs(incident_id, iocs)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# ── Timeline ─────────────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/timeline', methods=['GET'])
@login_required
def get_timeline(incident_id):
    timeline = _get_ir().get_timeline(incident_id)
    return jsonify({'timeline': timeline})


@incident_resp_bp.route('/incidents/<incident_id>/timeline', methods=['POST'])
@login_required
def add_timeline_event(incident_id):
    data = request.get_json(silent=True) or {}
    from datetime import datetime, timezone
    ts = data.get('timestamp') or datetime.now(timezone.utc).isoformat()
    result = _get_ir().add_timeline_event(
        incident_id, ts,
        data.get('event', ''),
        data.get('source', 'manual'),
        data.get('details'),
    )
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>/timeline/auto', methods=['POST'])
@login_required
def auto_build_timeline(incident_id):
    result = _get_ir().auto_build_timeline(incident_id)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# ── Containment ──────────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/contain', methods=['POST'])
@login_required
def contain_host(incident_id):
    data = request.get_json(silent=True) or {}
    host = data.get('host', '').strip()
    actions = data.get('actions', [])
    if not host or not actions:
        return jsonify({'error': 'host and actions required'}), 400
    result = _get_ir().contain_host(incident_id, host, actions)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)


# ── Report & Export ──────────────────────────────────────────────

@incident_resp_bp.route('/incidents/<incident_id>/report', methods=['GET'])
@login_required
def generate_report(incident_id):
    result = _get_ir().generate_report(incident_id)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)


@incident_resp_bp.route('/incidents/<incident_id>/export', methods=['GET'])
@login_required
def export_incident(incident_id):
    fmt = request.args.get('fmt', 'json')
    result = _get_ir().export_incident(incident_id, fmt=fmt)
    if 'error' in result:
        return jsonify(result), 404
    return jsonify(result)
