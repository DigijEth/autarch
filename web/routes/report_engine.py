"""Reporting Engine — web routes for pentest report management."""

from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

report_engine_bp = Blueprint('report_engine', __name__)


def _svc():
    from modules.report_engine import get_report_engine
    return get_report_engine()


@report_engine_bp.route('/reports/')
@login_required
def index():
    return render_template('report_engine.html')


@report_engine_bp.route('/reports/list', methods=['GET'])
@login_required
def list_reports():
    return jsonify({'ok': True, 'reports': _svc().list_reports()})


@report_engine_bp.route('/reports/create', methods=['POST'])
@login_required
def create_report():
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().create_report(
        title=data.get('title', 'Untitled Report'),
        client=data.get('client', ''),
        scope=data.get('scope', ''),
        methodology=data.get('methodology', ''),
    ))


@report_engine_bp.route('/reports/<report_id>', methods=['GET'])
@login_required
def get_report(report_id):
    r = _svc().get_report(report_id)
    if not r:
        return jsonify({'ok': False, 'error': 'Report not found'})
    return jsonify({'ok': True, 'report': r})


@report_engine_bp.route('/reports/<report_id>', methods=['PUT'])
@login_required
def update_report(report_id):
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().update_report(report_id, data))


@report_engine_bp.route('/reports/<report_id>', methods=['DELETE'])
@login_required
def delete_report(report_id):
    return jsonify(_svc().delete_report(report_id))


@report_engine_bp.route('/reports/<report_id>/findings', methods=['POST'])
@login_required
def add_finding(report_id):
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().add_finding(report_id, data))


@report_engine_bp.route('/reports/<report_id>/findings/<finding_id>', methods=['PUT'])
@login_required
def update_finding(report_id, finding_id):
    data = request.get_json(silent=True) or {}
    return jsonify(_svc().update_finding(report_id, finding_id, data))


@report_engine_bp.route('/reports/<report_id>/findings/<finding_id>', methods=['DELETE'])
@login_required
def delete_finding(report_id, finding_id):
    return jsonify(_svc().delete_finding(report_id, finding_id))


@report_engine_bp.route('/reports/templates', methods=['GET'])
@login_required
def finding_templates():
    return jsonify({'ok': True, 'templates': _svc().get_finding_templates()})


@report_engine_bp.route('/reports/<report_id>/export/<fmt>', methods=['GET'])
@login_required
def export_report(report_id, fmt):
    svc = _svc()
    if fmt == 'html':
        content = svc.export_html(report_id)
        if not content:
            return jsonify({'ok': False, 'error': 'Report not found'})
        return Response(content, mimetype='text/html',
                        headers={'Content-Disposition': f'attachment; filename=report_{report_id}.html'})
    elif fmt == 'markdown':
        content = svc.export_markdown(report_id)
        if not content:
            return jsonify({'ok': False, 'error': 'Report not found'})
        return Response(content, mimetype='text/markdown',
                        headers={'Content-Disposition': f'attachment; filename=report_{report_id}.md'})
    elif fmt == 'json':
        content = svc.export_json(report_id)
        if not content:
            return jsonify({'ok': False, 'error': 'Report not found'})
        return Response(content, mimetype='application/json',
                        headers={'Content-Disposition': f'attachment; filename=report_{report_id}.json'})
    return jsonify({'ok': False, 'error': 'Invalid format'})
