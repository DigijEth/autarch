"""Module Creator route - create, edit, validate, and manage AUTARCH modules"""

import ast
import os
import re
from datetime import datetime
from pathlib import Path
from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

module_creator_bp = Blueprint('module_creator', __name__, url_prefix='/module-creator')

MODULES_DIR = Path(__file__).parent.parent.parent / 'modules'

CATEGORIES = ['defense', 'offense', 'counter', 'analyze', 'osint', 'simulate', 'core', 'hardware']

CATEGORY_DESCRIPTIONS = {
    'defense': 'Defensive security module for monitoring, hardening, and threat detection',
    'offense': 'Offensive security module for penetration testing and exploitation',
    'counter': 'Counter-intelligence module for anti-surveillance and evasion',
    'analyze': 'Analysis module for forensics, traffic inspection, and data processing',
    'osint': 'Open-source intelligence gathering and reconnaissance module',
    'simulate': 'Simulation module for attack modeling and scenario testing',
    'core': 'Core infrastructure module for platform internals and utilities',
    'hardware': 'Hardware interface module for RF, BLE, RFID, SDR, and embedded devices',
}


def _module_skeleton(name, category, description, author):
    """Generate skeleton code for a new module."""
    return f'''"""
{description}
"""

DESCRIPTION = "{description}"
AUTHOR = "{author}"
VERSION = "1.0"
CATEGORY = "{category}"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


def run():
    """Main entry point."""
    clear_screen()
    display_banner()
    print(f"{{Colors.BOLD}}{name}{{Colors.RESET}}")
    print(f"{{Colors.DIM}}{{"─" * 50}}{{Colors.RESET}}\\n")

    # TODO: Implement module logic here
    print(f"{{Colors.GREEN}}[+] Module loaded successfully{{Colors.RESET}}")


if __name__ == "__main__":
    run()
'''


def _parse_module_metadata(filepath):
    """Extract metadata from a module file."""
    meta = {
        'name': filepath.stem,
        'category': 'unknown',
        'description': '',
        'version': '',
        'author': '',
        'file_size': filepath.stat().st_size,
        'last_modified': datetime.fromtimestamp(filepath.stat().st_mtime).strftime('%Y-%m-%d %H:%M'),
    }
    try:
        source = filepath.read_text(errors='replace')
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                        if target.id == 'DESCRIPTION':
                            meta['description'] = str(node.value.value)
                        elif target.id == 'CATEGORY':
                            meta['category'] = str(node.value.value)
                        elif target.id == 'VERSION':
                            meta['version'] = str(node.value.value)
                        elif target.id == 'AUTHOR':
                            meta['author'] = str(node.value.value)
    except Exception:
        pass
    return meta


@module_creator_bp.route('/')
@login_required
def index():
    return render_template('module_creator.html')


@module_creator_bp.route('/templates')
@login_required
def templates():
    """Return skeleton templates for each category."""
    result = []
    for cat in CATEGORIES:
        result.append({
            'name': f'new_{cat}_module',
            'category': cat,
            'description': CATEGORY_DESCRIPTIONS.get(cat, ''),
            'code': _module_skeleton(f'new_{cat}_module', cat, CATEGORY_DESCRIPTIONS.get(cat, ''), 'darkHal'),
        })
    return jsonify(result)


@module_creator_bp.route('/create', methods=['POST'])
@login_required
def create():
    """Create a new module file."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'Invalid JSON payload'}), 400

    name = data.get('name', '').strip()
    category = data.get('category', '').strip()
    description = data.get('description', '').strip()
    author = data.get('author', 'darkHal').strip()
    code = data.get('code', '').strip()

    # Validate name
    if not name:
        return jsonify({'success': False, 'error': 'Module name is required'}), 400
    if not re.match(r'^[A-Za-z0-9_]+$', name):
        return jsonify({'success': False, 'error': 'Module name must be alphanumeric and underscores only'}), 400

    # Check category
    if category not in CATEGORIES:
        return jsonify({'success': False, 'error': f'Invalid category. Must be one of: {", ".join(CATEGORIES)}'}), 400

    # Check existence
    target = MODULES_DIR / f'{name}.py'
    if target.exists():
        return jsonify({'success': False, 'error': f'Module "{name}" already exists'}), 409

    # Use provided code or generate skeleton
    if not code:
        code = _module_skeleton(name, category, description, author)

    try:
        target.write_text(code)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to write module: {e}'}), 500

    return jsonify({'success': True, 'message': f'Module "{name}" created successfully', 'path': str(target)})


@module_creator_bp.route('/validate', methods=['POST'])
@login_required
def validate():
    """Validate Python syntax and required attributes."""
    data = request.get_json(silent=True)
    if not data or 'code' not in data:
        return jsonify({'valid': False, 'errors': ['No code provided']}), 400

    code = data['code']
    errors = []
    warnings = []

    # Syntax check
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        return jsonify({
            'valid': False,
            'errors': [f'Syntax error at line {e.lineno}: {e.msg}'],
            'warnings': [],
        })

    # Check required attributes
    found_attrs = set()
    found_run = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('DESCRIPTION', 'CATEGORY'):
                    found_attrs.add(target.id)
        if isinstance(node, ast.FunctionDef) and node.name == 'run':
            found_run = True

    if 'DESCRIPTION' not in found_attrs:
        errors.append('Missing required attribute: DESCRIPTION')
    if 'CATEGORY' not in found_attrs:
        errors.append('Missing required attribute: CATEGORY')
    if not found_run:
        errors.append('Missing required function: run()')

    valid = len(errors) == 0
    if valid:
        warnings.append('All checks passed')

    return jsonify({'valid': valid, 'errors': errors, 'warnings': warnings})


@module_creator_bp.route('/list')
@login_required
def list_modules():
    """Return JSON list of all existing modules."""
    modules = []
    if MODULES_DIR.exists():
        for f in sorted(MODULES_DIR.glob('*.py')):
            if f.name.startswith('__'):
                continue
            modules.append(_parse_module_metadata(f))
    return jsonify(modules)


@module_creator_bp.route('/preview', methods=['POST'])
@login_required
def preview():
    """Load and return source code of an existing module."""
    data = request.get_json(silent=True)
    if not data or 'name' not in data:
        return jsonify({'success': False, 'error': 'Module name is required'}), 400

    name = data['name'].strip()
    target = MODULES_DIR / f'{name}.py'
    if not target.exists():
        return jsonify({'success': False, 'error': f'Module "{name}" not found'}), 404

    try:
        code = target.read_text(errors='replace')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

    meta = _parse_module_metadata(target)
    return jsonify({'success': True, 'code': code, 'metadata': meta})


@module_creator_bp.route('/save', methods=['POST'])
@login_required
def save():
    """Save edits to an existing module file."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({'success': False, 'error': 'Invalid JSON payload'}), 400

    name = data.get('name', '').strip()
    code = data.get('code', '')

    if not name:
        return jsonify({'success': False, 'error': 'Module name is required'}), 400
    if not re.match(r'^[A-Za-z0-9_]+$', name):
        return jsonify({'success': False, 'error': 'Invalid module name'}), 400

    target = MODULES_DIR / f'{name}.py'
    if not target.exists():
        return jsonify({'success': False, 'error': f'Module "{name}" does not exist'}), 404

    try:
        target.write_text(code)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to save: {e}'}), 500

    return jsonify({'success': True, 'message': f'Module "{name}" saved successfully'})
