"""Network Topology Mapper — web routes."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

net_mapper_bp = Blueprint('net_mapper', __name__)


def _svc():
    from modules.net_mapper import get_net_mapper
    return get_net_mapper()


@net_mapper_bp.route('/net-mapper/')
@login_required
def index():
    return render_template('net_mapper.html')


@net_mapper_bp.route('/net-mapper/discover', methods=['POST'])
@login_required
def discover():
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    if not target:
        return jsonify({'ok': False, 'error': 'Target required'})
    return jsonify(_svc().discover_hosts(target, method=data.get('method', 'auto')))


@net_mapper_bp.route('/net-mapper/discover/<job_id>', methods=['GET'])
@login_required
def discover_status(job_id):
    return jsonify(_svc().get_job_status(job_id))


@net_mapper_bp.route('/net-mapper/scan-host', methods=['POST'])
@login_required
def scan_host():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'})
    return jsonify(_svc().scan_host(ip,
        port_range=data.get('port_range', '1-1024'),
        service_detection=data.get('service_detection', True),
        os_detection=data.get('os_detection', True)))


@net_mapper_bp.route('/net-mapper/topology', methods=['POST'])
@login_required
def build_topology():
    data = request.get_json(silent=True) or {}
    hosts = data.get('hosts', [])
    return jsonify({'ok': True, **_svc().build_topology(hosts)})


@net_mapper_bp.route('/net-mapper/scans', methods=['GET'])
@login_required
def list_scans():
    return jsonify({'ok': True, 'scans': _svc().list_scans()})


@net_mapper_bp.route('/net-mapper/scans', methods=['POST'])
@login_required
def save_scan():
    data = request.get_json(silent=True) or {}
    name = data.get('name', 'unnamed')
    hosts = data.get('hosts', [])
    return jsonify(_svc().save_scan(name, hosts))


@net_mapper_bp.route('/net-mapper/scans/<filename>', methods=['GET'])
@login_required
def load_scan(filename):
    data = _svc().load_scan(filename)
    if data:
        return jsonify({'ok': True, 'scan': data})
    return jsonify({'ok': False, 'error': 'Scan not found'})


@net_mapper_bp.route('/net-mapper/diff', methods=['POST'])
@login_required
def diff_scans():
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().diff_scans(data.get('scan1', ''), data.get('scan2', '')))
