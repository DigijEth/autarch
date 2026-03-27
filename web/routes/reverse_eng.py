"""Reverse Engineering routes."""

from flask import Blueprint, request, jsonify, render_template
from web.auth import login_required

reverse_eng_bp = Blueprint('reverse_eng', __name__, url_prefix='/reverse-eng')


def _get_re():
    from modules.reverse_eng import get_reverse_eng
    return get_reverse_eng()


# ==================== PAGE ====================

@reverse_eng_bp.route('/')
@login_required
def index():
    return render_template('reverse_eng.html')


# ==================== ANALYSIS ====================

@reverse_eng_bp.route('/analyze', methods=['POST'])
@login_required
def analyze():
    """Comprehensive binary analysis."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    result = _get_re().analyze_binary(file_path)
    return jsonify(result)


@reverse_eng_bp.route('/strings', methods=['POST'])
@login_required
def strings():
    """Extract strings from binary."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    min_length = int(data.get('min_length', 4))
    encoding = data.get('encoding', 'both')
    result = _get_re().extract_strings(file_path, min_length=min_length, encoding=encoding)
    return jsonify({'strings': result, 'total': len(result)})


# ==================== DISASSEMBLY ====================

@reverse_eng_bp.route('/disassemble', methods=['POST'])
@login_required
def disassemble():
    """Disassemble binary data or file."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    hex_data = data.get('hex', '').strip()
    arch = data.get('arch', 'x64')
    count = int(data.get('count', 100))
    section = data.get('section', '.text')

    if hex_data:
        try:
            raw = bytes.fromhex(hex_data.replace(' ', '').replace('\n', ''))
        except ValueError:
            return jsonify({'error': 'Invalid hex data'}), 400
        instructions = _get_re().disassemble(raw, arch=arch, count=count)
    elif file_path:
        offset = int(data.get('offset', 0))
        instructions = _get_re().disassemble_file(
            file_path, section=section, offset=offset, count=count)
    else:
        return jsonify({'error': 'Provide file path or hex data'}), 400

    return jsonify({'instructions': instructions, 'total': len(instructions)})


# ==================== HEX ====================

@reverse_eng_bp.route('/hex', methods=['POST'])
@login_required
def hex_dump():
    """Hex dump of file region."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    offset = int(data.get('offset', 0))
    length = int(data.get('length', 256))
    length = min(length, 65536)  # Cap at 64KB
    result = _get_re().hex_dump(file_path, offset=offset, length=length)
    return jsonify(result)


@reverse_eng_bp.route('/hex/search', methods=['POST'])
@login_required
def hex_search():
    """Search for hex pattern in binary."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    pattern = data.get('pattern', '').strip()
    if not file_path or not pattern:
        return jsonify({'error': 'File path and pattern required'}), 400
    result = _get_re().hex_search(file_path, pattern)
    return jsonify(result)


# ==================== YARA ====================

@reverse_eng_bp.route('/yara/scan', methods=['POST'])
@login_required
def yara_scan():
    """Scan file with YARA rules."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    rules_path = data.get('rules_path') or None
    rules_string = data.get('rules_string') or None
    result = _get_re().yara_scan(file_path, rules_path=rules_path, rules_string=rules_string)
    return jsonify(result)


@reverse_eng_bp.route('/yara/rules')
@login_required
def yara_rules():
    """List available YARA rule files."""
    rules = _get_re().list_yara_rules()
    return jsonify({'rules': rules, 'total': len(rules)})


# ==================== PACKER ====================

@reverse_eng_bp.route('/packer', methods=['POST'])
@login_required
def packer():
    """Detect packer in binary."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    result = _get_re().detect_packer(file_path)
    return jsonify(result)


# ==================== COMPARE ====================

@reverse_eng_bp.route('/compare', methods=['POST'])
@login_required
def compare():
    """Compare two binaries."""
    data = request.get_json(silent=True) or {}
    file1 = data.get('file1', '').strip()
    file2 = data.get('file2', '').strip()
    if not file1 or not file2:
        return jsonify({'error': 'Two file paths required'}), 400
    result = _get_re().compare_binaries(file1, file2)
    return jsonify(result)


# ==================== DECOMPILE ====================

@reverse_eng_bp.route('/decompile', methods=['POST'])
@login_required
def decompile():
    """Decompile binary with Ghidra headless."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    function = data.get('function') or None
    result = _get_re().ghidra_decompile(file_path, function=function)
    return jsonify(result)


# ==================== PE / ELF PARSING ====================

@reverse_eng_bp.route('/pe', methods=['POST'])
@login_required
def parse_pe():
    """Parse PE headers."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    result = _get_re().parse_pe(file_path)
    return jsonify(result)


@reverse_eng_bp.route('/elf', methods=['POST'])
@login_required
def parse_elf():
    """Parse ELF headers."""
    data = request.get_json(silent=True) or {}
    file_path = data.get('file', '').strip()
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
    result = _get_re().parse_elf(file_path)
    return jsonify(result)
