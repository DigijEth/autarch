"""UPnP management route"""

import json
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from web.auth import login_required

upnp_bp = Blueprint('upnp', __name__, url_prefix='/upnp')


@upnp_bp.route('/')
@login_required
def index():
    from core.upnp import get_upnp_manager
    config = current_app.autarch_config
    upnp = get_upnp_manager(config)

    available = upnp.is_available()
    mappings = upnp.load_mappings_from_config()
    cron = upnp.get_cron_status()

    current_mappings = ''
    external_ip = ''
    if available:
        success, output = upnp.list_mappings()
        current_mappings = output if success else f'Error: {output}'
        success, ip = upnp.get_external_ip()
        external_ip = ip if success else 'N/A'

    return render_template('upnp.html',
        available=available,
        mappings=mappings,
        cron=cron,
        current_mappings=current_mappings,
        external_ip=external_ip,
        internal_ip=upnp._get_internal_ip(),
    )


@upnp_bp.route('/refresh', methods=['POST'])
@login_required
def refresh():
    from core.upnp import get_upnp_manager
    config = current_app.autarch_config
    upnp = get_upnp_manager(config)
    results = upnp.refresh_all()

    ok = sum(1 for r in results if r['success'])
    fail = sum(1 for r in results if not r['success'])

    if fail == 0:
        flash(f'Refreshed {ok} mapping(s) successfully.', 'success')
    else:
        flash(f'{ok} OK, {fail} failed.', 'warning')

    return redirect(url_for('upnp.index'))


@upnp_bp.route('/add', methods=['POST'])
@login_required
def add():
    from core.upnp import get_upnp_manager
    config = current_app.autarch_config
    upnp = get_upnp_manager(config)

    port = request.form.get('port', '')
    proto = request.form.get('protocol', 'TCP').upper()

    try:
        port = int(port)
    except ValueError:
        flash('Invalid port number.', 'error')
        return redirect(url_for('upnp.index'))

    internal_ip = upnp._get_internal_ip()
    success, msg = upnp.add_mapping(internal_ip, port, port, proto)

    if success:
        # Save to config
        mappings = upnp.load_mappings_from_config()
        if not any(m['port'] == port and m['protocol'] == proto for m in mappings):
            mappings.append({'port': port, 'protocol': proto})
            upnp.save_mappings_to_config(mappings)
        flash(f'Added {port}/{proto}', 'success')
    else:
        flash(f'Failed: {msg}', 'error')

    return redirect(url_for('upnp.index'))


@upnp_bp.route('/remove', methods=['POST'])
@login_required
def remove():
    from core.upnp import get_upnp_manager
    config = current_app.autarch_config
    upnp = get_upnp_manager(config)

    port = int(request.form.get('port', 0))
    proto = request.form.get('protocol', 'TCP')

    success, msg = upnp.remove_mapping(port, proto)
    if success:
        mappings = upnp.load_mappings_from_config()
        mappings = [m for m in mappings if not (m['port'] == port and m['protocol'] == proto)]
        upnp.save_mappings_to_config(mappings)
        flash(f'Removed {port}/{proto}', 'success')
    else:
        flash(f'Failed: {msg}', 'error')

    return redirect(url_for('upnp.index'))


@upnp_bp.route('/cron', methods=['POST'])
@login_required
def cron():
    from core.upnp import get_upnp_manager
    config = current_app.autarch_config
    upnp = get_upnp_manager(config)

    action = request.form.get('action', '')
    if action == 'install':
        hours = int(request.form.get('hours', 12))
        success, msg = upnp.install_cron(hours)
    elif action == 'uninstall':
        success, msg = upnp.uninstall_cron()
    else:
        flash('Invalid action.', 'error')
        return redirect(url_for('upnp.index'))

    flash(msg, 'success' if success else 'error')
    return redirect(url_for('upnp.index'))
