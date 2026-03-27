"""Analyze category route - file analysis, strings, hashes, log analysis, hex dump, compare."""

import os
import re
import zlib
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
from collections import Counter
from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

analyze_bp = Blueprint('analyze', __name__, url_prefix='/analyze')


def _run_cmd(cmd, timeout=60):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout.strip()
    except Exception:
        return False, ""


def _validate_path(filepath):
    """Validate and resolve a file path. Returns (Path, error_string)."""
    if not filepath:
        return None, 'No file path provided'
    p = Path(filepath).expanduser()
    if not p.exists():
        return None, f'File not found: {filepath}'
    if not p.is_file():
        return None, f'Not a file: {filepath}'
    return p, None


# ── Hash algorithm identification patterns ────────────────────────────
HASH_PATTERNS = [
    # Simple hex hashes by length
    {'name': 'CRC16',        'hashcat': None,  'regex': r'^[a-fA-F0-9]{4}$',   'desc': '16-bit CRC'},
    {'name': 'CRC32',        'hashcat': 11500, 'regex': r'^[a-fA-F0-9]{8}$',   'desc': '32-bit CRC checksum'},
    {'name': 'Adler32',      'hashcat': None,  'regex': r'^[a-fA-F0-9]{8}$',   'desc': 'Adler-32 checksum'},
    {'name': 'MySQL323',     'hashcat': 200,   'regex': r'^[a-fA-F0-9]{16}$',  'desc': 'MySQL v3.23 (OLD_PASSWORD)'},
    {'name': 'MD2',          'hashcat': None,  'regex': r'^[a-fA-F0-9]{32}$',  'desc': 'MD2 (128-bit, obsolete)'},
    {'name': 'MD4',          'hashcat': 900,   'regex': r'^[a-fA-F0-9]{32}$',  'desc': 'MD4 (128-bit, broken)'},
    {'name': 'MD5',          'hashcat': 0,     'regex': r'^[a-fA-F0-9]{32}$',  'desc': 'MD5 (128-bit)'},
    {'name': 'NTLM',         'hashcat': 1000,  'regex': r'^[a-fA-F0-9]{32}$',  'desc': 'NTLM (Windows, 128-bit)'},
    {'name': 'LM',           'hashcat': 3000,  'regex': r'^[a-fA-F0-9]{32}$',  'desc': 'LAN Manager hash'},
    {'name': 'RIPEMD-160',   'hashcat': 6000,  'regex': r'^[a-fA-F0-9]{40}$',  'desc': 'RIPEMD-160 (160-bit)'},
    {'name': 'SHA-1',        'hashcat': 100,   'regex': r'^[a-fA-F0-9]{40}$',  'desc': 'SHA-1 (160-bit, deprecated)'},
    {'name': 'Tiger-192',    'hashcat': 10000, 'regex': r'^[a-fA-F0-9]{48}$',  'desc': 'Tiger (192-bit)'},
    {'name': 'SHA-224',      'hashcat': None,  'regex': r'^[a-fA-F0-9]{56}$',  'desc': 'SHA-224 (224-bit)'},
    {'name': 'SHA-256',      'hashcat': 1400,  'regex': r'^[a-fA-F0-9]{64}$',  'desc': 'SHA-256 (256-bit)'},
    {'name': 'BLAKE2s-256',  'hashcat': None,  'regex': r'^[a-fA-F0-9]{64}$',  'desc': 'BLAKE2s (256-bit)'},
    {'name': 'Keccak-256',   'hashcat': 17800, 'regex': r'^[a-fA-F0-9]{64}$',  'desc': 'Keccak-256'},
    {'name': 'SHA3-256',     'hashcat': 17400, 'regex': r'^[a-fA-F0-9]{64}$',  'desc': 'SHA3-256'},
    {'name': 'SHA-384',      'hashcat': 10800, 'regex': r'^[a-fA-F0-9]{96}$',  'desc': 'SHA-384 (384-bit)'},
    {'name': 'SHA3-384',     'hashcat': 17500, 'regex': r'^[a-fA-F0-9]{96}$',  'desc': 'SHA3-384'},
    {'name': 'SHA-512',      'hashcat': 1700,  'regex': r'^[a-fA-F0-9]{128}$', 'desc': 'SHA-512 (512-bit)'},
    {'name': 'SHA3-512',     'hashcat': 17600, 'regex': r'^[a-fA-F0-9]{128}$', 'desc': 'SHA3-512'},
    {'name': 'BLAKE2b-512',  'hashcat': 600,   'regex': r'^[a-fA-F0-9]{128}$', 'desc': 'BLAKE2b (512-bit)'},
    {'name': 'Keccak-512',   'hashcat': 18000, 'regex': r'^[a-fA-F0-9]{128}$', 'desc': 'Keccak-512'},
    {'name': 'Whirlpool',    'hashcat': 6100,  'regex': r'^[a-fA-F0-9]{128}$', 'desc': 'Whirlpool (512-bit)'},
    # Structured / prefixed formats
    {'name': 'MySQL41',              'hashcat': 300,   'regex': r'^\*[a-fA-F0-9]{40}$',                                          'desc': 'MySQL v4.1+ (SHA1)'},
    {'name': 'bcrypt',               'hashcat': 3200,  'regex': r'^\$2[aby]?\$\d{2}\$.{53}$',                                    'desc': 'bcrypt (Blowfish)'},
    {'name': 'MD5 Unix (crypt)',     'hashcat': 500,   'regex': r'^\$1\$.{0,8}\$[a-zA-Z0-9/.]{22}$',                             'desc': 'MD5 Unix crypt ($1$)'},
    {'name': 'SHA-256 Unix (crypt)', 'hashcat': 7400,  'regex': r'^\$5\$(rounds=\d+\$)?[a-zA-Z0-9/.]{0,16}\$[a-zA-Z0-9/.]{43}$', 'desc': 'SHA-256 Unix crypt ($5$)'},
    {'name': 'SHA-512 Unix (crypt)', 'hashcat': 1800,  'regex': r'^\$6\$(rounds=\d+\$)?[a-zA-Z0-9/.]{0,16}\$[a-zA-Z0-9/.]{86}$', 'desc': 'SHA-512 Unix crypt ($6$)'},
    {'name': 'scrypt',               'hashcat': None,  'regex': r'^\$scrypt\$',                                                   'desc': 'scrypt KDF'},
    {'name': 'Argon2',               'hashcat': None,  'regex': r'^\$argon2(i|d|id)\$',                                           'desc': 'Argon2 (i/d/id)'},
    {'name': 'PBKDF2-SHA256',        'hashcat': 10900, 'regex': r'^\$pbkdf2-sha256\$',                                            'desc': 'PBKDF2-HMAC-SHA256'},
    {'name': 'PBKDF2-SHA1',          'hashcat': None,  'regex': r'^\$pbkdf2\$',                                                   'desc': 'PBKDF2-HMAC-SHA1'},
    {'name': 'Cisco Type 5',         'hashcat': 500,   'regex': r'^\$1\$[a-zA-Z0-9/.]{0,8}\$[a-zA-Z0-9/.]{22}$',                  'desc': 'Cisco IOS Type 5 (MD5)'},
    {'name': 'Cisco Type 8',         'hashcat': 9200,  'regex': r'^\$8\$[a-zA-Z0-9/.]{14}\$[a-zA-Z0-9/.]{43}$',                   'desc': 'Cisco Type 8 (PBKDF2-SHA256)'},
    {'name': 'Cisco Type 9',         'hashcat': 9300,  'regex': r'^\$9\$[a-zA-Z0-9/.]{14}\$[a-zA-Z0-9/.]{43}$',                   'desc': 'Cisco Type 9 (scrypt)'},
    {'name': 'Django PBKDF2-SHA256', 'hashcat': 10000, 'regex': r'^pbkdf2_sha256\$\d+\$',                                         'desc': 'Django PBKDF2-SHA256'},
    {'name': 'WordPress (phpass)',   'hashcat': 400,   'regex': r'^\$P\$[a-zA-Z0-9/.]{31}$',                                      'desc': 'WordPress / phpBB3 (phpass)'},
    {'name': 'Drupal7',              'hashcat': 7900,  'regex': r'^\$S\$[a-zA-Z0-9/.]{52}$',                                      'desc': 'Drupal 7 (SHA-512 iterated)'},
    # HMAC / salted
    {'name': 'HMAC-MD5',    'hashcat': 50,   'regex': r'^[a-fA-F0-9]{32}:[a-fA-F0-9]+$',  'desc': 'HMAC-MD5 (hash:salt)'},
    {'name': 'HMAC-SHA1',   'hashcat': 150,  'regex': r'^[a-fA-F0-9]{40}:[a-fA-F0-9]+$',  'desc': 'HMAC-SHA1 (hash:salt)'},
    {'name': 'HMAC-SHA256', 'hashcat': 1450, 'regex': r'^[a-fA-F0-9]{64}:[a-fA-F0-9]+$',  'desc': 'HMAC-SHA256 (hash:salt)'},
]


def _identify_hash(hash_str):
    """Return list of possible hash algorithm matches for the given string."""
    matches = []
    for entry in HASH_PATTERNS:
        if re.match(entry['regex'], hash_str):
            matches.append({
                'name': entry['name'],
                'hashcat': entry.get('hashcat'),
                'description': entry['desc'],
            })
    return matches


@analyze_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'analyze'}
    return render_template('analyze.html', modules=modules)


@analyze_bp.route('/file', methods=['POST'])
@login_required
def analyze_file():
    """Analyze a file - metadata, type, hashes."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    stat = p.stat()

    # File type detection
    mime_type = ''
    file_type = ''
    try:
        import magic
        file_magic = magic.Magic(mime=True)
        mime_type = file_magic.from_file(str(p))
        file_magic2 = magic.Magic()
        file_type = file_magic2.from_file(str(p))
    except Exception:
        success, output = _run_cmd(f"file '{p}'")
        if success:
            file_type = output.split(':', 1)[-1].strip()

    # Hashes
    hashes = {}
    try:
        with open(p, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
    except Exception:
        pass

    return jsonify({
        'path': str(p.absolute()),
        'size': stat.st_size,
        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        'mime': mime_type,
        'type': file_type,
        'hashes': hashes,
    })


@analyze_bp.route('/strings', methods=['POST'])
@login_required
def extract_strings():
    """Extract strings from a file."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()
    min_len = data.get('min_len', 4)

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    min_len = max(2, min(20, int(min_len)))
    success, output = _run_cmd(f"strings -n {min_len} '{p}' 2>/dev/null")
    if not success:
        return jsonify({'error': 'Failed to extract strings'})

    lines = output.split('\n')
    urls = [l for l in lines if re.search(r'https?://', l)][:20]
    ips = [l for l in lines if re.search(r'\b\d+\.\d+\.\d+\.\d+\b', l)][:20]
    emails = [l for l in lines if re.search(r'[\w.-]+@[\w.-]+', l)][:20]
    paths = [l for l in lines if re.search(r'^/[a-z]', l, re.I)][:20]

    return jsonify({
        'total': len(lines),
        'urls': urls,
        'ips': ips,
        'emails': emails,
        'paths': paths,
    })


@analyze_bp.route('/hash', methods=['POST'])
@login_required
def hash_lookup():
    """Hash lookup - return lookup URLs."""
    data = request.get_json(silent=True) or {}
    hash_input = data.get('hash', '').strip()

    if not hash_input:
        return jsonify({'error': 'No hash provided'})

    hash_len = len(hash_input)
    if hash_len == 32:
        hash_type = 'MD5'
    elif hash_len == 40:
        hash_type = 'SHA1'
    elif hash_len == 64:
        hash_type = 'SHA256'
    else:
        return jsonify({'error': 'Invalid hash length (expected MD5/SHA1/SHA256)'})

    return jsonify({
        'hash_type': hash_type,
        'links': [
            {'name': 'VirusTotal', 'url': f'https://www.virustotal.com/gui/file/{hash_input}'},
            {'name': 'Hybrid Analysis', 'url': f'https://www.hybrid-analysis.com/search?query={hash_input}'},
        ]
    })


@analyze_bp.route('/log', methods=['POST'])
@login_required
def analyze_log():
    """Analyze a log file."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    try:
        with open(p, 'r', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return jsonify({'error': f'Error reading file: {e}'})

    # Extract IPs
    all_ips = []
    for line in lines:
        found = re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', line)
        all_ips.extend(found)

    ip_counts = Counter(all_ips).most_common(10)

    # Error count
    errors = [l for l in lines if re.search(r'error|fail|denied|invalid', l, re.I)]

    # Time range
    timestamps = []
    for line in lines:
        match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
        if match:
            timestamps.append(match.group(1))

    time_range = None
    if timestamps:
        time_range = {'first': timestamps[0], 'last': timestamps[-1]}

    return jsonify({
        'total_lines': len(lines),
        'ip_counts': ip_counts,
        'error_count': len(errors),
        'time_range': time_range,
    })


@analyze_bp.route('/hex', methods=['POST'])
@login_required
def hex_dump():
    """Hex dump of a file."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()
    offset = data.get('offset', 0)
    length = data.get('length', 256)

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    offset = max(0, int(offset))
    length = max(1, min(4096, int(length)))

    try:
        with open(p, 'rb') as f:
            f.seek(offset)
            raw = f.read(length)
    except Exception as e:
        return jsonify({'error': f'Error reading file: {e}'})

    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i + 16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{offset + i:08x}  {hex_part:<48}  {ascii_part}')

    return jsonify({'hex': '\n'.join(lines)})


@analyze_bp.route('/compare', methods=['POST'])
@login_required
def compare_files():
    """Compare two files."""
    data = request.get_json(silent=True) or {}
    file1 = data.get('file1', '').strip()
    file2 = data.get('file2', '').strip()

    p1, err1 = _validate_path(file1)
    if err1:
        return jsonify({'error': f'File 1: {err1}'})
    p2, err2 = _validate_path(file2)
    if err2:
        return jsonify({'error': f'File 2: {err2}'})

    s1, s2 = p1.stat().st_size, p2.stat().st_size

    # Hashes
    def get_hashes(path):
        with open(path, 'rb') as f:
            content = f.read()
            return {
                'md5': hashlib.md5(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest(),
            }

    h1 = get_hashes(p1)
    h2 = get_hashes(p2)

    # Diff
    diff_text = ''
    if h1['sha256'] != h2['sha256']:
        success, output = _run_cmd(f"diff '{p1}' '{p2}' 2>/dev/null | head -30")
        if success:
            diff_text = output

    return jsonify({
        'file1_size': s1,
        'file2_size': s2,
        'size_diff': abs(s1 - s2),
        'md5_match': h1['md5'] == h2['md5'],
        'sha256_match': h1['sha256'] == h2['sha256'],
        'diff': diff_text,
    })


# ── Hash Toolkit routes ──────────────────────────────────────────────

@analyze_bp.route('/hash-detection')
@login_required
def hash_detection():
    """Hash Toolkit page."""
    return render_template('hash_detection.html')


@analyze_bp.route('/hash-detection/identify', methods=['POST'])
@login_required
def hash_identify():
    """Identify possible hash algorithms for a given string."""
    data = request.get_json(silent=True) or {}
    hash_input = data.get('hash', '').strip()
    if not hash_input:
        return jsonify({'error': 'No hash string provided'})

    matches = _identify_hash(hash_input)
    if not matches:
        return jsonify({
            'hash': hash_input, 'length': len(hash_input),
            'matches': [], 'message': 'No matching hash algorithms found',
        })

    return jsonify({'hash': hash_input, 'length': len(hash_input), 'matches': matches})


@analyze_bp.route('/hash-detection/file', methods=['POST'])
@login_required
def hash_file():
    """Compute multiple hash digests for a file."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    try:
        with open(p, 'rb') as f:
            content = f.read()
        return jsonify({
            'path': str(p.absolute()),
            'size': len(content),
            'hashes': {
                'crc32':  format(zlib.crc32(content) & 0xffffffff, '08x'),
                'md5':    hashlib.md5(content).hexdigest(),
                'sha1':   hashlib.sha1(content).hexdigest(),
                'sha256': hashlib.sha256(content).hexdigest(),
                'sha512': hashlib.sha512(content).hexdigest(),
            },
        })
    except Exception as e:
        return jsonify({'error': f'Error reading file: {e}'})


@analyze_bp.route('/hash-detection/text', methods=['POST'])
@login_required
def hash_text():
    """Hash arbitrary text with a selectable algorithm."""
    data = request.get_json(silent=True) or {}
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'sha256').lower().strip()

    if not text:
        return jsonify({'error': 'No text provided'})

    text_bytes = text.encode('utf-8')

    algo_map = {
        'md5':     lambda b: hashlib.md5(b).hexdigest(),
        'sha1':    lambda b: hashlib.sha1(b).hexdigest(),
        'sha224':  lambda b: hashlib.sha224(b).hexdigest(),
        'sha256':  lambda b: hashlib.sha256(b).hexdigest(),
        'sha384':  lambda b: hashlib.sha384(b).hexdigest(),
        'sha512':  lambda b: hashlib.sha512(b).hexdigest(),
        'sha3-256': lambda b: hashlib.sha3_256(b).hexdigest(),
        'sha3-512': lambda b: hashlib.sha3_512(b).hexdigest(),
        'blake2b': lambda b: hashlib.blake2b(b).hexdigest(),
        'blake2s': lambda b: hashlib.blake2s(b).hexdigest(),
        'crc32':   lambda b: format(zlib.crc32(b) & 0xffffffff, '08x'),
    }

    if algorithm == 'all':
        results = {}
        for name, fn in algo_map.items():
            try:
                results[name] = fn(text_bytes)
            except Exception:
                results[name] = '(not available)'
        return jsonify({'text_length': len(text), 'algorithm': 'all', 'hashes': results})

    fn = algo_map.get(algorithm)
    if not fn:
        return jsonify({'error': f'Unknown algorithm: {algorithm}. Available: {", ".join(sorted(algo_map.keys()))}'})

    return jsonify({'text_length': len(text), 'algorithm': algorithm, 'hash': fn(text_bytes)})


@analyze_bp.route('/hash-detection/mutate', methods=['POST'])
@login_required
def hash_mutate():
    """Change a file's hash by appending bytes to a copy."""
    data = request.get_json(silent=True) or {}
    filepath = data.get('filepath', '').strip()
    method = data.get('method', 'random').strip()
    num_bytes = data.get('num_bytes', 4)

    p, err = _validate_path(filepath)
    if err:
        return jsonify({'error': err})

    num_bytes = max(1, min(1024, int(num_bytes)))

    try:
        with open(p, 'rb') as f:
            original = f.read()

        # Compute original hashes
        orig_hashes = {
            'md5':    hashlib.md5(original).hexdigest(),
            'sha256': hashlib.sha256(original).hexdigest(),
        }

        # Generate mutation bytes
        if method == 'null':
            extra = b'\x00' * num_bytes
        elif method == 'space':
            extra = b'\x20' * num_bytes
        elif method == 'newline':
            extra = b'\n' * num_bytes
        else:  # random
            extra = os.urandom(num_bytes)

        mutated = original + extra

        # Write mutated copy next to original
        stem = p.stem
        suffix = p.suffix
        out_path = p.parent / f'{stem}_mutated{suffix}'
        with open(out_path, 'wb') as f:
            f.write(mutated)

        new_hashes = {
            'md5':    hashlib.md5(mutated).hexdigest(),
            'sha256': hashlib.sha256(mutated).hexdigest(),
        }

        return jsonify({
            'original_path': str(p.absolute()),
            'mutated_path': str(out_path.absolute()),
            'original_size': len(original),
            'mutated_size': len(mutated),
            'bytes_appended': num_bytes,
            'method': method,
            'original_hashes': orig_hashes,
            'new_hashes': new_hashes,
        })
    except Exception as e:
        return jsonify({'error': f'Mutation failed: {e}'})


@analyze_bp.route('/hash-detection/generate', methods=['POST'])
@login_required
def hash_generate():
    """Create dummy test files with known content and return their hashes."""
    data = request.get_json(silent=True) or {}
    output_dir = data.get('output_dir', '/tmp').strip()
    filename = data.get('filename', 'hashtest').strip()
    content_type = data.get('content_type', 'random').strip()
    size = data.get('size', 1024)
    custom_text = data.get('custom_text', '')

    out_dir = Path(output_dir).expanduser()
    if not out_dir.exists():
        return jsonify({'error': f'Directory not found: {output_dir}'})
    if not out_dir.is_dir():
        return jsonify({'error': f'Not a directory: {output_dir}'})

    size = max(1, min(10 * 1024 * 1024, int(size)))  # cap at 10MB

    # Generate content
    if content_type == 'zeros':
        content = b'\x00' * size
    elif content_type == 'ones':
        content = b'\xff' * size
    elif content_type == 'pattern':
        pattern = b'ABCDEFGHIJKLMNOP'
        content = (pattern * (size // len(pattern) + 1))[:size]
    elif content_type == 'text' and custom_text:
        raw = custom_text.encode('utf-8')
        content = (raw * (size // len(raw) + 1))[:size] if raw else os.urandom(size)
    else:  # random
        content = os.urandom(size)

    # Sanitize filename
    safe_name = re.sub(r'[^\w.\-]', '_', filename)
    out_path = out_dir / safe_name
    try:
        with open(out_path, 'wb') as f:
            f.write(content)

        hashes = {
            'crc32':  format(zlib.crc32(content) & 0xffffffff, '08x'),
            'md5':    hashlib.md5(content).hexdigest(),
            'sha1':   hashlib.sha1(content).hexdigest(),
            'sha256': hashlib.sha256(content).hexdigest(),
            'sha512': hashlib.sha512(content).hexdigest(),
        }

        return jsonify({
            'path': str(out_path.absolute()),
            'size': len(content),
            'content_type': content_type,
            'hashes': hashes,
        })
    except Exception as e:
        return jsonify({'error': f'File creation failed: {e}'})
