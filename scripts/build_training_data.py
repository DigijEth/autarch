#!/usr/bin/env python3
"""
AUTARCH LoRA Training Data Generator
Extracts instruction/input/output triplets from the codebase
for fine-tuning LLMs on AUTARCH module creation patterns.

Run: python scripts/build_training_data.py
Output: data/codex/autarch_training.jsonl

Generates training pairs for:
- Module creation (description → code)
- Route creation (feature description → Flask blueprint)
- Config patterns (section description → config code)
- Template patterns (feature → Jinja2 template)
"""

import ast
import json
import sys
import re
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(FRAMEWORK_DIR))

OUTPUT_PATH = FRAMEWORK_DIR / 'data' / 'codex' / 'autarch_training.jsonl'


def extract_module_pair(filepath: Path) -> dict:
    """Extract a training pair from a module file."""
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return None

    description = None
    category = None
    author = None
    version = None
    docstring = ast.get_docstring(tree) or ''

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    if target.id == 'DESCRIPTION':
                        description = node.value.value
                    elif target.id == 'CATEGORY':
                        category = node.value.value
                    elif target.id == 'AUTHOR':
                        author = node.value.value
                    elif target.id == 'VERSION':
                        version = node.value.value

    if not description or not category:
        return None

    # Build the instruction
    instruction = (
        f"Create an AUTARCH module in the '{category}' category that {description.lower().rstrip('.')}. "
        f"The module should follow AUTARCH conventions with DESCRIPTION, AUTHOR, VERSION, CATEGORY "
        f"attributes and a run() entry point function."
    )

    return {
        'instruction': instruction,
        'input': f"Module name: {filepath.stem}\nCategory: {category}\nDescription: {description}",
        'output': source,
        'type': 'module_creation',
        'category': category,
        'source_file': str(filepath.relative_to(FRAMEWORK_DIR)),
    }


def extract_route_pair(filepath: Path) -> dict:
    """Extract a training pair from a route file."""
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return None

    docstring = ast.get_docstring(tree) or ''

    # Find blueprint name and prefix
    bp_name = None
    bp_prefix = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                    if hasattr(node.value, 'func'):
                        func_name = ''
                        if hasattr(node.value.func, 'id'):
                            func_name = node.value.func.id
                        elif hasattr(node.value.func, 'attr'):
                            func_name = node.value.func.attr
                        if func_name == 'Blueprint':
                            bp_name = target.id
                            for kw in node.value.keywords:
                                if kw.arg == 'url_prefix' and isinstance(kw.value, ast.Constant):
                                    bp_prefix = kw.value.value

    if not bp_name:
        return None

    # Count routes
    routes = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            for deco in node.decorator_list:
                if isinstance(deco, ast.Call) and hasattr(deco, 'func'):
                    if hasattr(deco.func, 'attr') and deco.func.attr == 'route':
                        doc = ast.get_docstring(node) or ''
                        routes.append({
                            'handler': node.name,
                            'doc': doc.split('\n')[0] if doc else '',
                        })

    feature_name = filepath.stem.replace('_', ' ').title()
    instruction = (
        f"Create a Flask blueprint route file for AUTARCH's '{feature_name}' feature. "
        f"It should have a blueprint with url_prefix='{bp_prefix or '/' + filepath.stem}', "
        f"use @login_required on all routes, and follow AUTARCH web route conventions. "
        f"It needs {len(routes)} route handlers."
    )

    return {
        'instruction': instruction,
        'input': f"Feature: {feature_name}\nBlueprint: {bp_name}\nPrefix: {bp_prefix}\nRoutes: {len(routes)}",
        'output': source,
        'type': 'route_creation',
        'source_file': str(filepath.relative_to(FRAMEWORK_DIR)),
    }


def extract_template_pair(filepath: Path) -> dict:
    """Extract a training pair from a template file."""
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return None

    if '{% extends' not in source or '{% block content %}' not in source:
        return None

    # Count sections, tabs, buttons, forms
    sections = source.count('class="section"') + source.count("class='section'")
    tabs = source.count('class="tab"') + source.count("class='tab'")
    forms = source.count('<form') + source.count('fetch(')
    has_script = '<script>' in source

    feature_name = filepath.stem.replace('_', ' ').title()
    instruction = (
        f"Create an AUTARCH web template for the '{feature_name}' page. "
        f"It should extend base.html, have a page header, and use AUTARCH's "
        f"CSS variables and UI patterns (sections, tab bars, data tables, buttons)."
    )

    return {
        'instruction': instruction,
        'input': (
            f"Template: {filepath.name}\n"
            f"Sections: {sections}\nTabs: {tabs}\nForms/API calls: {forms}\n"
            f"Has JavaScript: {has_script}"
        ),
        'output': source,
        'type': 'template_creation',
        'source_file': str(filepath.relative_to(FRAMEWORK_DIR)),
    }


def extract_core_api_pairs(filepath: Path) -> list:
    """Extract training pairs showing how to use core APIs."""
    pairs = []
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return pairs

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith('_'):
                continue
            doc = ast.get_docstring(node) or ''
            if not doc:
                continue

            # Extract the function source
            lines = source.split('\n')
            start = node.lineno - 1
            end = node.end_lineno if hasattr(node, 'end_lineno') else start + 20
            func_source = '\n'.join(lines[start:end])

            args = [a.arg for a in node.args.args if a.arg != 'self']
            module_name = filepath.stem

            pairs.append({
                'instruction': f"Show how to implement the `{node.name}` function in core/{module_name}.py",
                'input': f"Function: {node.name}({', '.join(args)})\nDocstring: {doc.split(chr(10))[0]}",
                'output': func_source,
                'type': 'api_reference',
                'source_file': f"core/{filepath.name}",
            })

    return pairs


def build_training_data():
    """Generate training data from the codebase."""
    print("[training] Scanning codebase for training pairs...")

    pairs = []

    # Module pairs
    modules_dir = FRAMEWORK_DIR / 'modules'
    for f in sorted(modules_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        pair = extract_module_pair(f)
        if pair:
            pairs.append(pair)

    module_count = len(pairs)
    print(f"  Modules: {module_count} pairs")

    # Route pairs
    routes_dir = FRAMEWORK_DIR / 'web' / 'routes'
    for f in sorted(routes_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        pair = extract_route_pair(f)
        if pair:
            pairs.append(pair)

    route_count = len(pairs) - module_count
    print(f"  Routes: {route_count} pairs")

    # Template pairs
    templates_dir = FRAMEWORK_DIR / 'web' / 'templates'
    for f in sorted(templates_dir.glob('*.html')):
        pair = extract_template_pair(f)
        if pair:
            pairs.append(pair)

    template_count = len(pairs) - module_count - route_count
    print(f"  Templates: {template_count} pairs")

    # Core API pairs
    core_dir = FRAMEWORK_DIR / 'core'
    api_start = len(pairs)
    for f in sorted(core_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        api_pairs = extract_core_api_pairs(f)
        pairs.extend(api_pairs)

    api_count = len(pairs) - api_start
    print(f"  Core API: {api_count} pairs")

    # Write JSONL
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        for pair in pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + '\n')

    total_size = OUTPUT_PATH.stat().st_size
    print(f"\n[training] Written {len(pairs)} training pairs ({total_size:,} bytes) to {OUTPUT_PATH}")
    print(f"[training] Breakdown: {module_count} modules, {route_count} routes, "
          f"{template_count} templates, {api_count} core API functions")

    # Also output a summary
    summary_path = OUTPUT_PATH.with_suffix('.summary.json')
    summary = {
        'generated': datetime.now().isoformat(),
        'total_pairs': len(pairs),
        'modules': module_count,
        'routes': route_count,
        'templates': template_count,
        'core_api': api_count,
        'output_bytes': total_size,
        'types': {},
    }
    for p in pairs:
        t = p['type']
        summary['types'][t] = summary['types'].get(t, 0) + 1
    summary_path.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(f"[training] Summary: {summary_path}")


if __name__ == '__main__':
    build_training_data()
