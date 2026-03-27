"""RCS/SMS Exploitation routes — complete API for the RCS Tools page."""
from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

rcs_tools_bp = Blueprint('rcs_tools', __name__, url_prefix='/rcs-tools')

_rcs = None


def _get_rcs():
    global _rcs
    if _rcs is None:
        from modules.rcs_tools import get_rcs_tools
        _rcs = get_rcs_tools()
    return _rcs


# ── Pages ────────────────────────────────────────────────────────────────────

@rcs_tools_bp.route('/')
@login_required
def index():
    return render_template('rcs_tools.html')


# ── Status / Device ─────────────────────────────────────────────────────────

@rcs_tools_bp.route('/status')
@login_required
def status():
    return jsonify(_get_rcs().get_status())


@rcs_tools_bp.route('/device')
@login_required
def device():
    return jsonify(_get_rcs().get_device_info())


@rcs_tools_bp.route('/shizuku')
@login_required
def shizuku():
    return jsonify(_get_rcs().check_shizuku_status())


@rcs_tools_bp.route('/archon')
@login_required
def archon():
    return jsonify(_get_rcs().check_archon_installed())


@rcs_tools_bp.route('/security-patch')
@login_required
def security_patch():
    return jsonify(_get_rcs().get_security_patch_level())


@rcs_tools_bp.route('/set-default', methods=['POST'])
@login_required
def set_default():
    data = request.get_json(silent=True) or {}
    package = data.get('package', '')
    if not package:
        return jsonify({'ok': False, 'error': 'Missing package name'})
    return jsonify(_get_rcs().set_default_sms_app(package))


# ── IMS/RCS Diagnostics ────────────────────────────────────────────────────

@rcs_tools_bp.route('/ims-status')
@login_required
def ims_status():
    return jsonify(_get_rcs().get_ims_status())


@rcs_tools_bp.route('/carrier-config')
@login_required
def carrier_config():
    return jsonify(_get_rcs().get_carrier_config())


@rcs_tools_bp.route('/rcs-state')
@login_required
def rcs_state():
    return jsonify(_get_rcs().get_rcs_registration_state())


@rcs_tools_bp.route('/enable-logging', methods=['POST'])
@login_required
def enable_logging():
    return jsonify(_get_rcs().enable_verbose_logging())


@rcs_tools_bp.route('/capture-logs', methods=['POST'])
@login_required
def capture_logs():
    data = request.get_json(silent=True) or {}
    duration = int(data.get('duration', 10))
    return jsonify(_get_rcs().capture_rcs_logs(duration))


@rcs_tools_bp.route('/pixel-diagnostics')
@login_required
def pixel_diagnostics():
    return jsonify(_get_rcs().pixel_diagnostics())


@rcs_tools_bp.route('/debug-menu')
@login_required
def debug_menu():
    return jsonify(_get_rcs().enable_debug_menu())


# ── Content Provider Extraction ─────────────────────────────────────────────

@rcs_tools_bp.route('/conversations')
@login_required
def conversations():
    convos = _get_rcs().read_conversations()
    return jsonify({'ok': True, 'conversations': convos, 'count': len(convos)})


@rcs_tools_bp.route('/messages')
@login_required
def messages():
    rcs = _get_rcs()
    thread_id = request.args.get('thread_id')
    address = request.args.get('address')
    keyword = request.args.get('keyword')
    limit = int(request.args.get('limit', 200))

    if thread_id:
        msgs = rcs.get_thread_messages(int(thread_id), limit=limit)
    elif address:
        msgs = rcs.get_messages_by_address(address, limit=limit)
    elif keyword:
        msgs = rcs.search_messages(keyword, limit=limit)
    else:
        msgs = rcs.read_sms_database(limit=limit)

    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/sms-inbox')
@login_required
def sms_inbox():
    msgs = _get_rcs().read_sms_inbox()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/sms-sent')
@login_required
def sms_sent():
    msgs = _get_rcs().read_sms_sent()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/mms')
@login_required
def mms():
    msgs = _get_rcs().read_mms_database()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/rcs-via-mms')
@login_required
def rcs_via_mms():
    thread_id = request.args.get('thread_id')
    tid = int(thread_id) if thread_id else None
    limit = int(request.args.get('limit', 200))
    msgs = _get_rcs().read_rcs_via_mms(tid, limit)
    rcs_count = sum(1 for m in msgs if m.get('is_rcs'))
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs), 'rcs_count': rcs_count})


@rcs_tools_bp.route('/rcs-only')
@login_required
def rcs_only():
    limit = int(request.args.get('limit', 200))
    msgs = _get_rcs().read_rcs_only(limit)
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/rcs-threads')
@login_required
def rcs_threads():
    threads = _get_rcs().read_rcs_threads()
    return jsonify({'ok': True, 'threads': threads, 'count': len(threads)})


@rcs_tools_bp.route('/backup-rcs-xml', methods=['POST'])
@login_required
def backup_rcs_xml():
    return jsonify(_get_rcs().backup_rcs_to_xml())


@rcs_tools_bp.route('/drafts')
@login_required
def drafts():
    msgs = _get_rcs().read_draft_messages()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/undelivered')
@login_required
def undelivered():
    msgs = _get_rcs().read_undelivered_messages()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/rcs-provider')
@login_required
def rcs_provider():
    return jsonify(_get_rcs().read_rcs_provider())


@rcs_tools_bp.route('/rcs-messages')
@login_required
def rcs_messages():
    thread_id = request.args.get('thread_id')
    tid = int(thread_id) if thread_id else None
    msgs = _get_rcs().read_rcs_messages(tid)
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@rcs_tools_bp.route('/rcs-participants')
@login_required
def rcs_participants():
    p = _get_rcs().read_rcs_participants()
    return jsonify({'ok': True, 'participants': p, 'count': len(p)})


@rcs_tools_bp.route('/rcs-file-transfers/<int:thread_id>')
@login_required
def rcs_file_transfers(thread_id):
    ft = _get_rcs().read_rcs_file_transfers(thread_id)
    return jsonify({'ok': True, 'file_transfers': ft, 'count': len(ft)})


@rcs_tools_bp.route('/enumerate-providers', methods=['POST'])
@login_required
def enumerate_providers():
    return jsonify(_get_rcs().enumerate_providers())


# ── bugle_db Extraction ─────────────────────────────────────────────────────

@rcs_tools_bp.route('/extract-bugle', methods=['POST'])
@login_required
def extract_bugle():
    return jsonify(_get_rcs().extract_bugle_db())


@rcs_tools_bp.route('/query-bugle', methods=['POST'])
@login_required
def query_bugle():
    data = request.get_json(silent=True) or {}
    sql = data.get('sql', '')
    if not sql:
        return jsonify({'ok': False, 'error': 'No SQL query provided'})
    return jsonify(_get_rcs().query_bugle_db(sql))


@rcs_tools_bp.route('/extract-rcs-bugle', methods=['POST'])
@login_required
def extract_rcs_bugle():
    return jsonify(_get_rcs().extract_rcs_from_bugle())


@rcs_tools_bp.route('/extract-conversations-bugle', methods=['POST'])
@login_required
def extract_conversations_bugle():
    return jsonify(_get_rcs().extract_conversations_from_bugle())


@rcs_tools_bp.route('/extract-edits', methods=['POST'])
@login_required
def extract_edits():
    return jsonify(_get_rcs().extract_message_edits())


@rcs_tools_bp.route('/extract-all-bugle', methods=['POST'])
@login_required
def extract_all_bugle():
    return jsonify(_get_rcs().extract_all_from_bugle())


@rcs_tools_bp.route('/extracted-dbs')
@login_required
def extracted_dbs():
    return jsonify(_get_rcs().list_extracted_dbs())


# ── CVE-2024-0044 Exploit ──────────────────────────────────────────────────

@rcs_tools_bp.route('/cve-check')
@login_required
def cve_check():
    return jsonify(_get_rcs().check_cve_2024_0044())


@rcs_tools_bp.route('/cve-exploit', methods=['POST'])
@login_required
def cve_exploit():
    data = request.get_json(silent=True) or {}
    target = data.get('target_package', 'com.google.android.apps.messaging')
    return jsonify(_get_rcs().exploit_cve_2024_0044(target))


@rcs_tools_bp.route('/cve-cleanup', methods=['POST'])
@login_required
def cve_cleanup():
    return jsonify(_get_rcs().cleanup_cve_exploit())


@rcs_tools_bp.route('/signal-state', methods=['POST'])
@login_required
def signal_state():
    return jsonify(_get_rcs().extract_signal_protocol_state())


# ── Export / Backup ──────────────────────────────────────────────────────────

@rcs_tools_bp.route('/export', methods=['POST'])
@login_required
def export():
    data = request.get_json(silent=True) or {}
    address = data.get('address') or None
    fmt = data.get('format', 'json')
    return jsonify(_get_rcs().export_messages(address=address, fmt=fmt))


@rcs_tools_bp.route('/backup', methods=['POST'])
@login_required
def backup():
    data = request.get_json(silent=True) or {}
    fmt = data.get('format', 'json')
    return jsonify(_get_rcs().full_backup(fmt))


@rcs_tools_bp.route('/restore', methods=['POST'])
@login_required
def restore():
    data = request.get_json(silent=True) or {}
    path = data.get('path', '')
    if not path:
        return jsonify({'ok': False, 'error': 'Missing backup path'})
    return jsonify(_get_rcs().full_restore(path))


@rcs_tools_bp.route('/clone', methods=['POST'])
@login_required
def clone():
    return jsonify(_get_rcs().clone_to_device())


@rcs_tools_bp.route('/backups')
@login_required
def list_backups():
    return jsonify(_get_rcs().list_backups())


@rcs_tools_bp.route('/exports')
@login_required
def list_exports():
    return jsonify(_get_rcs().list_exports())


# ── Forging ──────────────────────────────────────────────────────────────────

@rcs_tools_bp.route('/forge', methods=['POST'])
@login_required
def forge():
    data = request.get_json(silent=True) or {}
    result = _get_rcs().forge_sms(
        address=data.get('address', ''),
        body=data.get('body', ''),
        msg_type=int(data.get('type', 1)),
        timestamp=int(data['timestamp']) if data.get('timestamp') else None,
        contact_name=data.get('contact_name'),
        read=int(data.get('read', 1)),
    )
    return jsonify(result)


@rcs_tools_bp.route('/forge-mms', methods=['POST'])
@login_required
def forge_mms():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_rcs().forge_mms(
        address=data.get('address', ''),
        subject=data.get('subject', ''),
        body=data.get('body', ''),
        msg_box=int(data.get('msg_box', 1)),
        timestamp=int(data['timestamp']) if data.get('timestamp') else None,
    ))


@rcs_tools_bp.route('/forge-rcs', methods=['POST'])
@login_required
def forge_rcs():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_rcs().forge_rcs(
        address=data.get('address', ''),
        body=data.get('body', ''),
        msg_type=int(data.get('type', 1)),
        timestamp=int(data['timestamp']) if data.get('timestamp') else None,
    ))


@rcs_tools_bp.route('/forge-conversation', methods=['POST'])
@login_required
def forge_conversation():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_rcs().forge_conversation(
        address=data.get('address', ''),
        messages=data.get('messages', []),
        contact_name=data.get('contact_name'),
    ))


@rcs_tools_bp.route('/bulk-forge', methods=['POST'])
@login_required
def bulk_forge():
    data = request.get_json(silent=True) or {}
    msgs = data.get('messages', [])
    if not msgs:
        return jsonify({'ok': False, 'error': 'No messages provided'})
    return jsonify(_get_rcs().bulk_forge(msgs))


@rcs_tools_bp.route('/import-xml', methods=['POST'])
@login_required
def import_xml():
    data = request.get_json(silent=True) or {}
    xml = data.get('xml', '')
    if not xml:
        return jsonify({'ok': False, 'error': 'No XML content provided'})
    return jsonify(_get_rcs().import_sms_backup_xml(xml))


# ── Modification ─────────────────────────────────────────────────────────────

@rcs_tools_bp.route('/message/<int:msg_id>', methods=['PUT'])
@login_required
def modify_message(msg_id):
    data = request.get_json(silent=True) or {}
    return jsonify(_get_rcs().modify_message(
        msg_id=msg_id,
        new_body=data.get('body'),
        new_timestamp=int(data['timestamp']) if data.get('timestamp') else None,
        new_type=int(data['type']) if data.get('type') else None,
        new_read=int(data['read']) if data.get('read') is not None else None,
    ))


@rcs_tools_bp.route('/message/<int:msg_id>', methods=['DELETE'])
@login_required
def delete_message(msg_id):
    return jsonify(_get_rcs().delete_message(msg_id))


@rcs_tools_bp.route('/conversation/<int:thread_id>', methods=['DELETE'])
@login_required
def delete_conversation(thread_id):
    return jsonify(_get_rcs().delete_conversation(thread_id))


@rcs_tools_bp.route('/shift-timestamps', methods=['POST'])
@login_required
def shift_timestamps():
    data = request.get_json(silent=True) or {}
    address = data.get('address', '')
    offset = int(data.get('offset_minutes', 0))
    if not address:
        return jsonify({'ok': False, 'error': 'Missing address'})
    return jsonify(_get_rcs().shift_timestamps(address, offset))


@rcs_tools_bp.route('/change-sender', methods=['POST'])
@login_required
def change_sender():
    data = request.get_json(silent=True) or {}
    msg_id = int(data.get('msg_id', 0))
    new_address = data.get('new_address', '')
    if not msg_id or not new_address:
        return jsonify({'ok': False, 'error': 'Missing msg_id or new_address'})
    return jsonify(_get_rcs().change_sender(msg_id, new_address))


@rcs_tools_bp.route('/mark-read', methods=['POST'])
@login_required
def mark_read():
    data = request.get_json(silent=True) or {}
    thread_id = data.get('thread_id')
    tid = int(thread_id) if thread_id else None
    return jsonify(_get_rcs().mark_all_read(tid))


@rcs_tools_bp.route('/wipe-thread', methods=['POST'])
@login_required
def wipe_thread():
    data = request.get_json(silent=True) or {}
    thread_id = int(data.get('thread_id', 0))
    if not thread_id:
        return jsonify({'ok': False, 'error': 'Missing thread_id'})
    return jsonify(_get_rcs().wipe_thread(thread_id))


# ── RCS Exploitation ────────────────────────────────────────────────────────

@rcs_tools_bp.route('/rcs-features/<address>')
@login_required
def rcs_features(address):
    return jsonify(_get_rcs().read_rcs_features(address))


@rcs_tools_bp.route('/rcs-spoof-read', methods=['POST'])
@login_required
def rcs_spoof_read():
    data = request.get_json(silent=True) or {}
    msg_id = data.get('msg_id', '')
    if not msg_id:
        return jsonify({'ok': False, 'error': 'Missing msg_id'})
    return jsonify(_get_rcs().spoof_rcs_read_receipt(str(msg_id)))


@rcs_tools_bp.route('/rcs-spoof-typing', methods=['POST'])
@login_required
def rcs_spoof_typing():
    data = request.get_json(silent=True) or {}
    address = data.get('address', '')
    if not address:
        return jsonify({'ok': False, 'error': 'Missing address'})
    return jsonify(_get_rcs().spoof_rcs_typing(address))


@rcs_tools_bp.route('/clone-identity', methods=['POST'])
@login_required
def clone_identity():
    return jsonify(_get_rcs().clone_rcs_identity())


@rcs_tools_bp.route('/extract-media', methods=['POST'])
@login_required
def extract_media():
    data = request.get_json(silent=True) or {}
    msg_id = data.get('msg_id', '')
    if not msg_id:
        return jsonify({'ok': False, 'error': 'Missing msg_id'})
    return jsonify(_get_rcs().extract_rcs_media(str(msg_id)))


@rcs_tools_bp.route('/intercept-archival', methods=['POST'])
@login_required
def intercept_archival():
    return jsonify(_get_rcs().intercept_archival_broadcast())


@rcs_tools_bp.route('/cve-database')
@login_required
def cve_database():
    return jsonify(_get_rcs().get_rcs_cve_database())


# ── SMS/RCS Monitor ─────────────────────────────────────────────────────────

@rcs_tools_bp.route('/monitor/start', methods=['POST'])
@login_required
def monitor_start():
    return jsonify(_get_rcs().start_sms_monitor())


@rcs_tools_bp.route('/monitor/stop', methods=['POST'])
@login_required
def monitor_stop():
    return jsonify(_get_rcs().stop_sms_monitor())


@rcs_tools_bp.route('/monitor/messages')
@login_required
def monitor_messages():
    return jsonify(_get_rcs().get_intercepted_messages())


@rcs_tools_bp.route('/monitor/clear', methods=['POST'])
@login_required
def monitor_clear():
    return jsonify(_get_rcs().clear_intercepted())


@rcs_tools_bp.route('/forged-log')
@login_required
def forged_log():
    return jsonify({'ok': True, 'log': _get_rcs().get_forged_log()})


@rcs_tools_bp.route('/forged-log/clear', methods=['POST'])
@login_required
def clear_forged_log():
    return jsonify(_get_rcs().clear_forged_log())


# ── Archon Integration ──────────────────────────────────────────────────────

@rcs_tools_bp.route('/archon/extract', methods=['POST'])
@login_required
def archon_extract():
    return jsonify(_get_rcs().archon_extract_bugle())


@rcs_tools_bp.route('/archon/forge-rcs', methods=['POST'])
@login_required
def archon_forge_rcs():
    data = request.get_json(silent=True) or {}
    return jsonify(_get_rcs().archon_forge_rcs(
        address=data.get('address', ''),
        body=data.get('body', ''),
        direction=data.get('direction', 'incoming'),
    ))


@rcs_tools_bp.route('/archon/modify-rcs', methods=['POST'])
@login_required
def archon_modify_rcs():
    data = request.get_json(silent=True) or {}
    msg_id = int(data.get('msg_id', 0))
    body = data.get('body', '')
    if not msg_id or not body:
        return jsonify({'ok': False, 'error': 'Missing msg_id or body'})
    return jsonify(_get_rcs().archon_modify_rcs(msg_id, body))


@rcs_tools_bp.route('/archon/threads')
@login_required
def archon_threads():
    return jsonify(_get_rcs().archon_get_rcs_threads())


@rcs_tools_bp.route('/archon/backup', methods=['POST'])
@login_required
def archon_backup():
    return jsonify(_get_rcs().archon_backup_all())


@rcs_tools_bp.route('/archon/set-default', methods=['POST'])
@login_required
def archon_set_default():
    return jsonify(_get_rcs().archon_set_default_sms())
