"""Password Toolkit — web routes for hash cracking, generation, and auditing."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

password_toolkit_bp = Blueprint('password_toolkit', __name__)


def _svc():
    from modules.password_toolkit import get_password_toolkit
    return get_password_toolkit()


@password_toolkit_bp.route('/password-toolkit/')
@login_required
def index():
    return render_template('password_toolkit.html')


@password_toolkit_bp.route('/password-toolkit/identify', methods=['POST'])
@login_required
def identify_hash():
    data = request.get_json(silent=True) or {}
    hashes = data.get('hashes', [])
    single = data.get('hash', '').strip()
    if single:
        hashes = [single]
    if not hashes:
        return jsonify({'ok': False, 'error': 'No hash provided'})
    svc = _svc()
    if len(hashes) == 1:
        return jsonify({'ok': True, 'types': svc.identify_hash(hashes[0])})
    return jsonify({'ok': True, 'results': svc.identify_batch(hashes)})


@password_toolkit_bp.route('/password-toolkit/crack', methods=['POST'])
@login_required
def crack_hash():
    data = request.get_json(silent=True) or {}
    hash_str = data.get('hash', '').strip()
    if not hash_str:
        return jsonify({'ok': False, 'error': 'No hash provided'})
    svc = _svc()
    result = svc.crack_hash(
        hash_str=hash_str,
        hash_type=data.get('hash_type', 'auto'),
        wordlist=data.get('wordlist', ''),
        attack_mode=data.get('attack_mode', 'dictionary'),
        rules=data.get('rules', ''),
        mask=data.get('mask', ''),
        tool=data.get('tool', 'auto'),
    )
    return jsonify(result)


@password_toolkit_bp.route('/password-toolkit/crack/<job_id>', methods=['GET'])
@login_required
def crack_status(job_id):
    return jsonify(_svc().get_crack_status(job_id))


@password_toolkit_bp.route('/password-toolkit/generate', methods=['POST'])
@login_required
def generate():
    data = request.get_json(silent=True) or {}
    svc = _svc()
    passwords = svc.generate_password(
        length=data.get('length', 16),
        count=data.get('count', 5),
        uppercase=data.get('uppercase', True),
        lowercase=data.get('lowercase', True),
        digits=data.get('digits', True),
        symbols=data.get('symbols', True),
        exclude_chars=data.get('exclude_chars', ''),
        pattern=data.get('pattern', ''),
    )
    audits = [svc.audit_password(pw) for pw in passwords]
    return jsonify({'ok': True, 'passwords': [
        {'password': pw, **audit} for pw, audit in zip(passwords, audits)
    ]})


@password_toolkit_bp.route('/password-toolkit/audit', methods=['POST'])
@login_required
def audit():
    data = request.get_json(silent=True) or {}
    pw = data.get('password', '')
    if not pw:
        return jsonify({'ok': False, 'error': 'No password provided'})
    return jsonify({'ok': True, **_svc().audit_password(pw)})


@password_toolkit_bp.route('/password-toolkit/hash', methods=['POST'])
@login_required
def hash_string():
    data = request.get_json(silent=True) or {}
    plaintext = data.get('plaintext', '')
    algorithm = data.get('algorithm', 'sha256')
    return jsonify(_svc().hash_string(plaintext, algorithm))


@password_toolkit_bp.route('/password-toolkit/spray', methods=['POST'])
@login_required
def spray():
    data = request.get_json(silent=True) or {}
    targets = data.get('targets', [])
    passwords = data.get('passwords', [])
    protocol = data.get('protocol', 'ssh')
    delay = data.get('delay', 1.0)
    return jsonify(_svc().credential_spray(targets, passwords, protocol, delay=delay))


@password_toolkit_bp.route('/password-toolkit/spray/<job_id>', methods=['GET'])
@login_required
def spray_status(job_id):
    return jsonify(_svc().get_spray_status(job_id))


@password_toolkit_bp.route('/password-toolkit/wordlists', methods=['GET'])
@login_required
def list_wordlists():
    return jsonify({'ok': True, 'wordlists': _svc().list_wordlists()})


@password_toolkit_bp.route('/password-toolkit/wordlists', methods=['POST'])
@login_required
def upload_wordlist():
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'ok': False, 'error': 'No file uploaded'})
    data = f.read()
    return jsonify(_svc().upload_wordlist(f.filename, data))


@password_toolkit_bp.route('/password-toolkit/wordlists/<name>', methods=['DELETE'])
@login_required
def delete_wordlist(name):
    return jsonify(_svc().delete_wordlist(name))


@password_toolkit_bp.route('/password-toolkit/tools', methods=['GET'])
@login_required
def tools_status():
    return jsonify({'ok': True, **_svc().get_tools_status()})
