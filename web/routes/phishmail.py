"""Gone Fishing Mail Service — web routes."""

import json
import base64
from flask import (Blueprint, render_template, request, jsonify,
                   Response, redirect, send_file)
from web.auth import login_required

phishmail_bp = Blueprint('phishmail', __name__, url_prefix='/phishmail')


def _server():
    from modules.phishmail import get_gone_fishing
    return get_gone_fishing()


# ── Page ─────────────────────────────────────────────────────────────────────

@phishmail_bp.route('/')
@login_required
def index():
    return render_template('phishmail.html')


# ── Send ─────────────────────────────────────────────────────────────────────

@phishmail_bp.route('/send', methods=['POST'])
@login_required
def send():
    """Send a single email."""
    data = request.get_json(silent=True) or {}
    if not data.get('to_addrs'):
        return jsonify({'ok': False, 'error': 'Recipients required'})
    if not data.get('from_addr'):
        return jsonify({'ok': False, 'error': 'Sender address required'})

    to_addrs = data.get('to_addrs', '')
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.split(',') if a.strip()]

    config = {
        'from_addr': data.get('from_addr', ''),
        'from_name': data.get('from_name', ''),
        'to_addrs': to_addrs,
        'subject': data.get('subject', ''),
        'html_body': data.get('html_body', ''),
        'text_body': data.get('text_body', ''),
        'smtp_host': data.get('smtp_host', '127.0.0.1'),
        'smtp_port': int(data.get('smtp_port', 25)),
        'use_tls': data.get('use_tls', False),
        'cert_cn': data.get('cert_cn', ''),
        'reply_to': data.get('reply_to', ''),
        'x_mailer': data.get('x_mailer', 'Microsoft Outlook 16.0'),
    }

    result = _server().send_email(config)
    return jsonify(result)


@phishmail_bp.route('/validate', methods=['POST'])
@login_required
def validate():
    """Validate that a recipient is on the local network."""
    data = request.get_json(silent=True) or {}
    address = data.get('address', '')
    if not address:
        return jsonify({'ok': False, 'error': 'Address required'})

    from modules.phishmail import _validate_local_only
    ok, msg = _validate_local_only(address)
    return jsonify({'ok': ok, 'message': msg})


# ── Campaigns ────────────────────────────────────────────────────────────────

@phishmail_bp.route('/campaigns', methods=['GET'])
@login_required
def list_campaigns():
    server = _server()
    campaigns = server.campaigns.list_campaigns()
    for c in campaigns:
        c['stats'] = server.campaigns.get_stats(c['id'])
    return jsonify({'ok': True, 'campaigns': campaigns})


@phishmail_bp.route('/campaigns', methods=['POST'])
@login_required
def create_campaign():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Campaign name required'})

    template = data.get('template', '')
    targets = data.get('targets', [])
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split('\n') if t.strip()]

    cid = _server().campaigns.create_campaign(
        name=name,
        template=template,
        targets=targets,
        from_addr=data.get('from_addr', 'it@company.local'),
        from_name=data.get('from_name', 'IT Department'),
        subject=data.get('subject', ''),
        smtp_host=data.get('smtp_host', '127.0.0.1'),
        smtp_port=int(data.get('smtp_port', 25)),
    )
    return jsonify({'ok': True, 'id': cid})


@phishmail_bp.route('/campaigns/<cid>', methods=['GET'])
@login_required
def get_campaign(cid):
    server = _server()
    camp = server.campaigns.get_campaign(cid)
    if not camp:
        return jsonify({'ok': False, 'error': 'Campaign not found'})
    camp['stats'] = server.campaigns.get_stats(cid)
    return jsonify({'ok': True, 'campaign': camp})


@phishmail_bp.route('/campaigns/<cid>/send', methods=['POST'])
@login_required
def send_campaign(cid):
    data = request.get_json(silent=True) or {}
    base_url = data.get('base_url', request.host_url.rstrip('/'))
    result = _server().send_campaign(cid, base_url=base_url)
    return jsonify(result)


@phishmail_bp.route('/campaigns/<cid>', methods=['DELETE'])
@login_required
def delete_campaign(cid):
    if _server().campaigns.delete_campaign(cid):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Campaign not found'})


# ── Templates ────────────────────────────────────────────────────────────────

@phishmail_bp.route('/templates', methods=['GET'])
@login_required
def list_templates():
    templates = _server().templates.list_templates()
    return jsonify({'ok': True, 'templates': templates})


@phishmail_bp.route('/templates', methods=['POST'])
@login_required
def save_template():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Template name required'})
    _server().templates.save_template(
        name, data.get('html', ''), data.get('text', ''),
        data.get('subject', ''))
    return jsonify({'ok': True})


@phishmail_bp.route('/templates/<name>', methods=['DELETE'])
@login_required
def delete_template(name):
    if _server().templates.delete_template(name):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Template not found or is built-in'})


# ── SMTP Relay ───────────────────────────────────────────────────────────────

@phishmail_bp.route('/server/start', methods=['POST'])
@login_required
def server_start():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '0.0.0.0')
    port = int(data.get('port', 2525))
    result = _server().start_relay(host, port)
    return jsonify(result)


@phishmail_bp.route('/server/stop', methods=['POST'])
@login_required
def server_stop():
    result = _server().stop_relay()
    return jsonify(result)


@phishmail_bp.route('/server/status', methods=['GET'])
@login_required
def server_status():
    return jsonify(_server().relay_status())


# ── Certificate Generation ───────────────────────────────────────────────────

@phishmail_bp.route('/cert/generate', methods=['POST'])
@login_required
def cert_generate():
    data = request.get_json(silent=True) or {}
    result = _server().generate_cert(
        cn=data.get('cn', 'mail.example.com'),
        org=data.get('org', 'Example Inc'),
        ou=data.get('ou', ''),
        locality=data.get('locality', ''),
        state=data.get('state', ''),
        country=data.get('country', 'US'),
        days=int(data.get('days', 365)),
    )
    return jsonify(result)


@phishmail_bp.route('/cert/list', methods=['GET'])
@login_required
def cert_list():
    return jsonify({'ok': True, 'certs': _server().list_certs()})


# ── SMTP Connection Test ────────────────────────────────────────────────────

@phishmail_bp.route('/test', methods=['POST'])
@login_required
def test_smtp():
    data = request.get_json(silent=True) or {}
    host = data.get('host', '')
    port = int(data.get('port', 25))
    if not host:
        return jsonify({'ok': False, 'error': 'Host required'})
    result = _server().test_smtp(host, port)
    return jsonify(result)


# ── Tracking (no auth — accessed by email clients) ──────────────────────────

# 1x1 transparent GIF
_PIXEL_GIF = base64.b64decode(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')


@phishmail_bp.route('/track/pixel/<campaign>/<target>')
def track_pixel(campaign, target):
    """Tracking pixel — records email open."""
    try:
        _server().campaigns.record_open(campaign, target)
    except Exception:
        pass
    return Response(_PIXEL_GIF, mimetype='image/gif',
                    headers={'Cache-Control': 'no-store, no-cache'})


@phishmail_bp.route('/track/click/<campaign>/<target>/<link_data>')
def track_click(campaign, target, link_data):
    """Click tracking — records click and redirects."""
    try:
        _server().campaigns.record_click(campaign, target)
    except Exception:
        pass

    # Decode original URL
    try:
        original_url = base64.urlsafe_b64decode(link_data).decode()
    except Exception:
        original_url = '/'

    return redirect(original_url)


# ── Landing Pages / Credential Harvesting ─────────────────────────────────

@phishmail_bp.route('/landing-pages', methods=['GET'])
@login_required
def list_landing_pages():
    return jsonify({'ok': True, 'pages': _server().landing_pages.list_pages()})


@phishmail_bp.route('/landing-pages', methods=['POST'])
@login_required
def create_landing_page():
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    html = data.get('html', '')
    if not name:
        return jsonify({'ok': False, 'error': 'Name required'})
    pid = _server().landing_pages.create_page(
        name, html,
        redirect_url=data.get('redirect_url', ''),
        fields=data.get('fields', ['username', 'password']))
    return jsonify({'ok': True, 'id': pid})


@phishmail_bp.route('/landing-pages/<pid>', methods=['GET'])
@login_required
def get_landing_page(pid):
    page = _server().landing_pages.get_page(pid)
    if not page:
        return jsonify({'ok': False, 'error': 'Page not found'})
    return jsonify({'ok': True, 'page': page})


@phishmail_bp.route('/landing-pages/<pid>', methods=['DELETE'])
@login_required
def delete_landing_page(pid):
    if _server().landing_pages.delete_page(pid):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Page not found or is built-in'})


@phishmail_bp.route('/landing-pages/<pid>/preview')
@login_required
def preview_landing_page(pid):
    html = _server().landing_pages.render_page(pid, 'preview', 'preview', 'user@example.com')
    if not html:
        return 'Page not found', 404
    return html


# Landing page capture endpoints (NO AUTH — accessed by phish targets)
@phishmail_bp.route('/lp/<page_id>', methods=['GET', 'POST'])
def landing_page_serve(page_id):
    """Serve a landing page and capture credentials on POST."""
    server = _server()
    if request.method == 'GET':
        campaign = request.args.get('c', '')
        target = request.args.get('t', '')
        email = request.args.get('e', '')
        html = server.landing_pages.render_page(page_id, campaign, target, email)
        if not html:
            return 'Not found', 404
        return html

    # POST — capture credentials
    form_data = dict(request.form)
    req_info = {
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'referer': request.headers.get('Referer', ''),
    }
    capture = server.landing_pages.record_capture(page_id, form_data, req_info)

    # Also update campaign tracking if campaign/target provided
    campaign = form_data.get('_campaign', '')
    target = form_data.get('_target', '')
    if campaign and target:
        try:
            server.campaigns.record_click(campaign, target)
        except Exception:
            pass

    # Redirect to configured URL or generic "success" page
    page = server.landing_pages.get_page(page_id)
    redirect_url = (page or {}).get('redirect_url', '')
    if redirect_url:
        return redirect(redirect_url)
    return """<!DOCTYPE html><html><head><title>Success</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f5f5f5}
.card{background:#fff;padding:40px;border-radius:8px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
</style></head><body><div class="card"><h2>Authentication Successful</h2>
<p>You will be redirected shortly...</p></div></body></html>"""


@phishmail_bp.route('/captures', methods=['GET'])
@login_required
def list_captures():
    campaign = request.args.get('campaign', '')
    page = request.args.get('page', '')
    captures = _server().landing_pages.get_captures(campaign, page)
    return jsonify({'ok': True, 'captures': captures})


@phishmail_bp.route('/captures', methods=['DELETE'])
@login_required
def clear_captures():
    campaign = request.args.get('campaign', '')
    count = _server().landing_pages.clear_captures(campaign)
    return jsonify({'ok': True, 'cleared': count})


@phishmail_bp.route('/captures/export')
@login_required
def export_captures():
    campaign = request.args.get('campaign', '')
    captures = _server().landing_pages.get_captures(campaign)
    # CSV export
    import io, csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['timestamp', 'campaign', 'target', 'ip', 'user_agent', 'credentials'])
    for c in captures:
        creds_str = '; '.join(f"{k}={v}" for k, v in c.get('credentials', {}).items())
        writer.writerow([c.get('timestamp', ''), c.get('campaign', ''),
                        c.get('target', ''), c.get('ip', ''),
                        c.get('user_agent', ''), creds_str])
    return Response(output.getvalue(), mimetype='text/csv',
                   headers={'Content-Disposition': f'attachment;filename=captures_{campaign or "all"}.csv'})


# ── Campaign enhancements ─────────────────────────────────────────────────

@phishmail_bp.route('/campaigns/<cid>/export')
@login_required
def export_campaign(cid):
    """Export campaign results as CSV."""
    import io, csv
    camp = _server().campaigns.get_campaign(cid)
    if not camp:
        return jsonify({'ok': False, 'error': 'Campaign not found'})
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['email', 'target_id', 'status', 'sent_at', 'opened_at', 'clicked_at'])
    for t in camp.get('targets', []):
        writer.writerow([t['email'], t['id'], t.get('status', ''),
                        t.get('sent_at', ''), t.get('opened_at', ''),
                        t.get('clicked_at', '')])
    return Response(output.getvalue(), mimetype='text/csv',
                   headers={'Content-Disposition': f'attachment;filename=campaign_{cid}.csv'})


@phishmail_bp.route('/campaigns/import-targets', methods=['POST'])
@login_required
def import_targets_csv():
    """Import targets from CSV (email per line, or CSV with email column)."""
    data = request.get_json(silent=True) or {}
    csv_text = data.get('csv', '')
    if not csv_text:
        return jsonify({'ok': False, 'error': 'CSV data required'})

    import io, csv
    reader = csv.reader(io.StringIO(csv_text))
    emails = []
    for row in reader:
        if not row:
            continue
        # Try to find email in each column
        for cell in row:
            cell = cell.strip()
            if '@' in cell and '.' in cell:
                emails.append(cell)
                break
        else:
            # If no email found, treat first column as raw email
            val = row[0].strip()
            if val and not val.startswith('#'):
                emails.append(val)

    # Deduplicate
    seen = set()
    unique = []
    for e in emails:
        if e.lower() not in seen:
            seen.add(e.lower())
            unique.append(e)

    return jsonify({'ok': True, 'emails': unique, 'count': len(unique)})


# ── DKIM ──────────────────────────────────────────────────────────────────

@phishmail_bp.route('/dkim/generate', methods=['POST'])
@login_required
def dkim_generate():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain required'})
    return jsonify(_server().dkim.generate_keypair(domain))


@phishmail_bp.route('/dkim/keys', methods=['GET'])
@login_required
def dkim_list():
    return jsonify({'ok': True, 'keys': _server().dkim.list_keys()})


# ── DNS Auto-Setup ────────────────────────────────────────────────────────

@phishmail_bp.route('/dns-setup', methods=['POST'])
@login_required
def dns_setup():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain required'})
    return jsonify(_server().setup_dns_for_domain(
        domain,
        mail_host=data.get('mail_host', ''),
        spf_allow=data.get('spf_allow', '')))


@phishmail_bp.route('/dns-status', methods=['GET'])
@login_required
def dns_check():
    return jsonify(_server().dns_status())


# ── Evasion Preview ──────────────────────────────────────────────────────

@phishmail_bp.route('/evasion/preview', methods=['POST'])
@login_required
def evasion_preview():
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    mode = data.get('mode', 'homoglyph')
    from modules.phishmail import EmailEvasion
    ev = EmailEvasion()
    if mode == 'homoglyph':
        result = ev.homoglyph_text(text)
    elif mode == 'zero_width':
        result = ev.zero_width_insert(text)
    elif mode == 'html_entity':
        result = ev.html_entity_encode(text)
    elif mode == 'random_headers':
        result = ev.randomize_headers()
        return jsonify({'ok': True, 'headers': result})
    else:
        result = text
    return jsonify({'ok': True, 'result': result})
