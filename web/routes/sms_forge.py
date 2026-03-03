"""SMS Backup Forge routes."""
import os
import tempfile
from flask import Blueprint, request, jsonify, render_template, send_file, current_app
from web.auth import login_required

sms_forge_bp = Blueprint('sms_forge', __name__, url_prefix='/sms-forge')

_forge = None


def _get_forge():
    global _forge
    if _forge is None:
        from modules.sms_forge import get_sms_forge
        _forge = get_sms_forge()
    return _forge


@sms_forge_bp.route('/')
@login_required
def index():
    return render_template('sms_forge.html')


@sms_forge_bp.route('/status')
@login_required
def status():
    return jsonify(_get_forge().get_status())


@sms_forge_bp.route('/messages')
@login_required
def messages():
    forge = _get_forge()
    address = request.args.get('address') or None
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    keyword = request.args.get('keyword') or None
    date_from_int = int(date_from) if date_from else None
    date_to_int = int(date_to) if date_to else None
    if address or date_from_int or date_to_int or keyword:
        msgs = forge.find_messages(address, date_from_int, date_to_int, keyword)
    else:
        msgs = forge.get_messages()
    return jsonify({'ok': True, 'messages': msgs, 'count': len(msgs)})


@sms_forge_bp.route('/sms', methods=['POST'])
@login_required
def add_sms():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    result = forge.add_sms(
        address=data.get('address', ''),
        body=data.get('body', ''),
        msg_type=int(data.get('type', 1)),
        timestamp=int(data['timestamp']) if data.get('timestamp') else None,
        contact_name=data.get('contact_name', '(Unknown)'),
        read=int(data.get('read', 1)),
        locked=int(data.get('locked', 0)),
    )
    return jsonify(result)


@sms_forge_bp.route('/mms', methods=['POST'])
@login_required
def add_mms():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    attachments = data.get('attachments', [])
    result = forge.add_mms(
        address=data.get('address', ''),
        body=data.get('body', ''),
        attachments=attachments,
        msg_box=int(data.get('msg_box', 1)),
        timestamp=int(data['timestamp']) if data.get('timestamp') else None,
        contact_name=data.get('contact_name', '(Unknown)'),
    )
    return jsonify(result)


@sms_forge_bp.route('/conversation', methods=['POST'])
@login_required
def add_conversation():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    result = forge.add_conversation(
        address=data.get('address', ''),
        contact_name=data.get('contact_name', '(Unknown)'),
        messages=data.get('messages', []),
        start_timestamp=int(data['start_timestamp']) if data.get('start_timestamp') else None,
    )
    return jsonify(result)


@sms_forge_bp.route('/generate', methods=['POST'])
@login_required
def generate():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    result = forge.generate_conversation(
        address=data.get('address', ''),
        contact_name=data.get('contact_name', '(Unknown)'),
        template=data.get('template', ''),
        variables=data.get('variables', {}),
        start_timestamp=int(data['start_timestamp']) if data.get('start_timestamp') else None,
    )
    return jsonify(result)


@sms_forge_bp.route('/message/<int:idx>', methods=['PUT'])
@login_required
def modify_message(idx):
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    result = forge.modify_message(
        index=idx,
        new_body=data.get('body'),
        new_timestamp=int(data['timestamp']) if data.get('timestamp') else None,
        new_contact=data.get('contact_name'),
    )
    return jsonify(result)


@sms_forge_bp.route('/message/<int:idx>', methods=['DELETE'])
@login_required
def delete_message(idx):
    forge = _get_forge()
    result = forge.delete_messages([idx])
    return jsonify(result)


@sms_forge_bp.route('/replace-contact', methods=['POST'])
@login_required
def replace_contact():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    result = forge.replace_contact(
        old_address=data.get('old_address', ''),
        new_address=data.get('new_address', ''),
        new_name=data.get('new_name'),
    )
    return jsonify(result)


@sms_forge_bp.route('/shift-timestamps', methods=['POST'])
@login_required
def shift_timestamps():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    address = data.get('address') or None
    result = forge.shift_timestamps(
        address=address,
        offset_minutes=int(data.get('offset_minutes', 0)),
    )
    return jsonify(result)


@sms_forge_bp.route('/import', methods=['POST'])
@login_required
def import_file():
    forge = _get_forge()
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file uploaded'})
    f = request.files['file']
    if not f.filename:
        return jsonify({'ok': False, 'error': 'Empty filename'})
    upload_dir = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
    save_path = os.path.join(upload_dir, f.filename)
    f.save(save_path)
    ext = os.path.splitext(f.filename)[1].lower()
    if ext == '.csv':
        result = forge.import_csv(save_path)
    else:
        result = forge.import_xml(save_path)
    try:
        os.unlink(save_path)
    except OSError:
        pass
    return jsonify(result)


@sms_forge_bp.route('/export/<fmt>')
@login_required
def export_file(fmt):
    forge = _get_forge()
    upload_dir = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
    if fmt == 'csv':
        out_path = os.path.join(upload_dir, 'sms_forge_export.csv')
        result = forge.export_csv(out_path)
        mime = 'text/csv'
        dl_name = 'sms_backup.csv'
    else:
        out_path = os.path.join(upload_dir, 'sms_forge_export.xml')
        result = forge.export_xml(out_path)
        mime = 'application/xml'
        dl_name = 'sms_backup.xml'
    if not result.get('ok'):
        return jsonify(result)
    return send_file(out_path, mimetype=mime, as_attachment=True, download_name=dl_name)


@sms_forge_bp.route('/merge', methods=['POST'])
@login_required
def merge():
    forge = _get_forge()
    files = request.files.getlist('files')
    if not files:
        return jsonify({'ok': False, 'error': 'No files uploaded'})
    upload_dir = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
    saved = []
    for f in files:
        if f.filename:
            path = os.path.join(upload_dir, f'merge_{f.filename}')
            f.save(path)
            saved.append(path)
    result = forge.merge_backups(saved)
    for p in saved:
        try:
            os.unlink(p)
        except OSError:
            pass
    return jsonify(result)


@sms_forge_bp.route('/templates')
@login_required
def templates():
    return jsonify(_get_forge().get_templates())


@sms_forge_bp.route('/stats')
@login_required
def stats():
    return jsonify(_get_forge().get_backup_stats())


@sms_forge_bp.route('/validate', methods=['POST'])
@login_required
def validate():
    forge = _get_forge()
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file uploaded'})
    f = request.files['file']
    if not f.filename:
        return jsonify({'ok': False, 'error': 'Empty filename'})
    upload_dir = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
    save_path = os.path.join(upload_dir, f'validate_{f.filename}')
    f.save(save_path)
    result = forge.validate_backup(save_path)
    try:
        os.unlink(save_path)
    except OSError:
        pass
    return jsonify(result)


@sms_forge_bp.route('/bulk-import', methods=['POST'])
@login_required
def bulk_import():
    forge = _get_forge()
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'No file uploaded'})
    f = request.files['file']
    if not f.filename:
        return jsonify({'ok': False, 'error': 'Empty filename'})
    upload_dir = current_app.config.get('UPLOAD_FOLDER', tempfile.gettempdir())
    save_path = os.path.join(upload_dir, f.filename)
    f.save(save_path)
    result = forge.bulk_add(save_path)
    try:
        os.unlink(save_path)
    except OSError:
        pass
    return jsonify(result)


@sms_forge_bp.route('/templates/save', methods=['POST'])
@login_required
def save_template():
    data = request.get_json(silent=True) or {}
    forge = _get_forge()
    key = data.get('key', '').strip()
    template_data = data.get('template', {})
    if not key:
        return jsonify({'ok': False, 'error': 'Template key is required'})
    result = forge.save_custom_template(key, template_data)
    return jsonify(result)


@sms_forge_bp.route('/templates/<key>', methods=['DELETE'])
@login_required
def delete_template(key):
    forge = _get_forge()
    result = forge.delete_custom_template(key)
    return jsonify(result)


@sms_forge_bp.route('/clear', methods=['POST'])
@login_required
def clear():
    _get_forge().clear_messages()
    return jsonify({'ok': True})
