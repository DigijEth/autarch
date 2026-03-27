#!/usr/bin/env python3
"""
AUTARCH Codex Generator
Scans the codebase and generates a structured knowledge document
that LLM agents use to understand how to create modules, routes,
and features for AUTARCH.

Run: python scripts/build_codex.py
Output: data/codex/autarch_codex.md

This should be re-run after any significant codebase changes.
"""

import ast
import os
import sys
import json
import textwrap
from pathlib import Path
from datetime import datetime

FRAMEWORK_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(FRAMEWORK_DIR))

OUTPUT_PATH = FRAMEWORK_DIR / 'data' / 'codex' / 'autarch_codex.md'


def extract_module_metadata(filepath: Path) -> dict:
    """Extract module-level metadata from a Python file using AST."""
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return None

    meta = {'file': str(filepath.relative_to(FRAMEWORK_DIR)), 'functions': [], 'classes': []}

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                    meta[target.id] = node.value.value
        elif isinstance(node, ast.FunctionDef):
            doc = ast.get_docstring(node) or ''
            args = [a.arg for a in node.args.args if a.arg != 'self']
            meta['functions'].append({
                'name': node.name,
                'args': args,
                'doc': doc.split('\n')[0] if doc else '',
                'line': node.lineno,
            })
        elif isinstance(node, ast.ClassDef):
            doc = ast.get_docstring(node) or ''
            methods = []
            for item in node.body:
                if isinstance(item, ast.FunctionDef):
                    mdoc = ast.get_docstring(item) or ''
                    methods.append(item.name)
            meta['classes'].append({
                'name': node.name,
                'doc': doc.split('\n')[0] if doc else '',
                'methods': methods,
                'line': node.lineno,
            })

    return meta


def extract_route_info(filepath: Path) -> list:
    """Extract Flask route decorators and handler info."""
    routes = []
    try:
        source = filepath.read_text(encoding='utf-8', errors='ignore')
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError):
        return routes

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            for deco in node.decorator_list:
                route_path = None
                methods = ['GET']
                if isinstance(deco, ast.Call) and hasattr(deco, 'func'):
                    func = deco.func
                    if hasattr(func, 'attr') and func.attr == 'route':
                        if deco.args and isinstance(deco.args[0], ast.Constant):
                            route_path = deco.args[0].value
                        for kw in deco.keywords:
                            if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                                methods = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
                if route_path:
                    doc = ast.get_docstring(node) or ''
                    routes.append({
                        'path': route_path,
                        'methods': methods,
                        'handler': node.name,
                        'doc': doc.split('\n')[0] if doc else '',
                        'line': node.lineno,
                    })
    return routes


def extract_template_blocks(filepath: Path) -> dict:
    """Extract basic template structure info."""
    try:
        content = filepath.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return {}

    info = {'file': filepath.name, 'size': len(content)}
    if '{% extends' in content:
        import re
        m = re.search(r'{%\s*extends\s*["\'](.+?)["\']\s*%}', content)
        if m:
            info['extends'] = m.group(1)
    if '{% block content %}' in content:
        info['has_content_block'] = True
    return info


def get_example_module(modules_dir: Path) -> str:
    """Get a clean, representative module example."""
    # Pick a simple, well-structured module
    for candidate in ['geoip.py', 'dossier.py', 'loadtest.py', 'ipcapture.py']:
        path = modules_dir / candidate
        if path.exists():
            source = path.read_text(encoding='utf-8', errors='ignore')
            # Truncate to first 80 lines if long
            lines = source.split('\n')
            if len(lines) > 80:
                source = '\n'.join(lines[:80]) + '\n# ... (truncated)'
            return source
    return '# No example found'


def get_example_route(routes_dir: Path) -> str:
    """Get a representative route example."""
    for candidate in ['ipcapture.py', 'loadtest.py']:
        path = routes_dir / candidate
        if path.exists():
            source = path.read_text(encoding='utf-8', errors='ignore')
            lines = source.split('\n')
            if len(lines) > 80:
                source = '\n'.join(lines[:80]) + '\n# ... (truncated)'
            return source
    return '# No example found'


def build_codex():
    """Generate the full codex document."""
    print("[codex] Scanning codebase...")

    # Scan modules
    modules_dir = FRAMEWORK_DIR / 'modules'
    modules = {}
    for f in sorted(modules_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        meta = extract_module_metadata(f)
        if meta:
            modules[f.stem] = meta

    # Scan core
    core_dir = FRAMEWORK_DIR / 'core'
    core_modules = {}
    for f in sorted(core_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        meta = extract_module_metadata(f)
        if meta:
            core_modules[f.stem] = meta

    # Scan routes
    routes_dir = FRAMEWORK_DIR / 'web' / 'routes'
    all_routes = {}
    for f in sorted(routes_dir.glob('*.py')):
        if f.name == '__init__.py':
            continue
        routes = extract_route_info(f)
        if routes:
            all_routes[f.stem] = routes

    # Scan templates
    templates_dir = FRAMEWORK_DIR / 'web' / 'templates'
    templates = {}
    for f in sorted(templates_dir.glob('*.html')):
        info = extract_template_blocks(f)
        if info:
            templates[f.stem] = info

    # Read config defaults
    from core.config import Config
    config_defaults = Config.DEFAULT_CONFIG

    # Build the document
    sections = []

    # Header
    sections.append(f"""# AUTARCH Codex
## Codebase Knowledge Reference for AI Agents
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This document is auto-generated by `scripts/build_codex.py` and provides
structured knowledge about the AUTARCH codebase for LLM agents to use
when creating modules, routes, templates, and features.

---
""")

    # Module system
    categories = {}
    for name, meta in modules.items():
        cat = meta.get('CATEGORY', 'core')
        categories.setdefault(cat, []).append(name)

    sections.append("""## 1. Module System

AUTARCH modules are Python files in the `modules/` directory. Each module:
- Has a `run()` function as the entry point
- Declares metadata: `DESCRIPTION`, `AUTHOR`, `VERSION`, `CATEGORY`
- Is auto-discovered by `core/menu.py` at startup
- Can be run via CLI (`python autarch.py -m <name>`) or from the web UI

### Required Module Attributes

```python
DESCRIPTION = "Short description of what the module does"
AUTHOR = "Your Name"
VERSION = "1.0"
CATEGORY = "defense"  # One of: defense, offense, counter, analyze, osint, simulate, core, hardware
```

### Module Template

```python
\"\"\"
Module description here.
\"\"\"

DESCRIPTION = "Short description"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


def run():
    \"\"\"Main entry point — REQUIRED.\"\"\"
    clear_screen()
    display_banner()
    print(f"{Colors.BOLD}Module Name{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\\n")

    # Module logic here


if __name__ == "__main__":
    run()
```

### Categories and Module Counts

""")
    for cat in ['defense', 'offense', 'counter', 'analyze', 'osint', 'simulate', 'core', 'hardware']:
        mods = categories.get(cat, [])
        sections.append(f"- **{cat}** ({len(mods)}): {', '.join(mods[:10])}")
        if len(mods) > 10:
            sections.append(f"  ... and {len(mods) - 10} more")
    sections.append(f"\n**Total modules: {len(modules)}**\n")

    # Core API reference
    sections.append("""
---

## 2. Core API Reference

The `core/` directory contains the framework backbone. Key modules:

""")
    for name, meta in sorted(core_modules.items()):
        doc = meta.get('__doc__', '') or ''
        classes = meta.get('classes', [])
        functions = [f for f in meta.get('functions', [])
                     if not f['name'].startswith('_') and f['name'] != 'run']
        if not classes and not functions:
            continue

        sections.append(f"### core/{name}.py\n")
        if classes:
            for cls in classes[:3]:
                sections.append(f"- **class `{cls['name']}`** — {cls['doc']}")
                if cls['methods']:
                    public = [m for m in cls['methods'] if not m.startswith('_')][:8]
                    if public:
                        sections.append(f"  - Methods: `{'`, `'.join(public)}`")
        if functions:
            for func in functions[:8]:
                args_str = ', '.join(func['args'][:4])
                sections.append(f"- `{func['name']}({args_str})` — {func['doc']}")
        sections.append("")

    # Key imports
    sections.append("""
### Common Imports for Modules

```python
# Colors and display
from core.banner import Colors, clear_screen, display_banner

# Configuration
from core.config import get_config

# LLM access
from core.llm import get_llm, LLMError

# Agent tools
from core.tools import get_tool_registry

# File paths
from core.paths import get_app_dir, get_data_dir, find_tool

# Hardware (ADB/Fastboot)
from core.hardware import get_hardware_manager

# Available Colors
Colors.RED, Colors.GREEN, Colors.YELLOW, Colors.BLUE,
Colors.MAGENTA, Colors.CYAN, Colors.WHITE, Colors.BOLD,
Colors.DIM, Colors.RESET
```

""")

    # Web route patterns
    sections.append("""---

## 3. Web Route Patterns

Routes live in `web/routes/`. Each file defines a Flask Blueprint.

### Blueprint Template

```python
from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

myfeature_bp = Blueprint('myfeature', __name__, url_prefix='/myfeature')


@myfeature_bp.route('/')
@login_required
def index():
    return render_template('myfeature.html')


@myfeature_bp.route('/action', methods=['POST'])
@login_required
def action():
    data = request.get_json(silent=True) or {}
    # Process...
    return jsonify({'ok': True, 'result': ...})
```

### Registration

In `web/app.py`, add:
```python
from web.routes.myfeature import myfeature_bp
app.register_blueprint(myfeature_bp)
```

### Existing Routes

""")
    for name, routes in sorted(all_routes.items()):
        sections.append(f"**{name}** ({len(routes)} routes)")
        for r in routes[:5]:
            methods = ','.join(r['methods'])
            sections.append(f"  - `{methods} {r['path']}` → `{r['handler']}`")
        if len(routes) > 5:
            sections.append(f"  - ... and {len(routes) - 5} more")
        sections.append("")

    # Template patterns
    sections.append("""---

## 4. Template Patterns

Templates live in `web/templates/` and use Jinja2 extending `base.html`.

### Template Structure

```html
{%% extends "base.html" %%}
{%% block title %%}Feature Name - AUTARCH{%% endblock %%}

{%% block content %%}
<div class="page-header">
    <h1>Feature Name</h1>
</div>

<div class="section">
    <h2>Section Title</h2>
    <!-- Content here -->
</div>

<script>
// JS for this page
</script>
{%% endblock %%}
```

### CSS Variables Available
```
--bg-main, --bg-card, --bg-secondary, --bg-input
--text-primary, --text-secondary, --text-muted
--accent (green), --danger (red), --border
--radius (border radius), --success (green)
```

### Common UI Patterns
- Tab bar: `<div class="tab-bar"><button class="tab active">Tab 1</button></div>`
- Card: `<div style="border:1px solid var(--border);background:var(--bg-card);border-radius:var(--radius);padding:0.85rem 1rem">`
- Table: `<table class="data-table"><thead>...</thead><tbody>...</tbody></table>`
- Button: `<button class="btn btn-primary btn-sm">Action</button>`
- Form: `<div class="form-group"><label>...</label><input ...><small>Help text</small></div>`

""")
    sections.append(f"### Templates ({len(templates)} total)\n")
    for name, info in sorted(templates.items()):
        extends = info.get('extends', 'none')
        sections.append(f"- `{info['file']}` (extends: {extends})")

    # Config system
    sections.append(f"""

---

## 5. Configuration System

Config is managed by `core/config.py` using Python's configparser.
File: `autarch_settings.conf` (INI format).

### Config Sections

""")
    for section, defaults in config_defaults.items():
        keys = ', '.join(list(defaults.keys())[:8])
        more = f" ... +{len(defaults) - 8} more" if len(defaults) > 8 else ""
        sections.append(f"- **[{section}]**: {keys}{more}")

    sections.append("""
### Usage in Code

```python
from core.config import get_config
config = get_config()

# Read values
val = config.get('section', 'key', 'default')
num = config.get_int('section', 'key', 0)
flt = config.get_float('section', 'key', 0.0)
bol = config.get_bool('section', 'key', False)

# Write values
config.set('section', 'key', 'value')
config.save()

# Typed getters
config.get_llama_settings()      # dict
config.get_claude_settings()     # dict
config.get_mcp_settings()        # dict
config.get_agents_settings()     # dict
config.get_autonomy_settings()   # dict
```

""")

    # Sidebar navigation
    sections.append("""---

## 6. Adding to the Navigation

Edit `web/templates/base.html`. The sidebar has sections:
- Top (Dashboard, Port Scanner, Targets)
- Categories (Defense, Offense, Counter, Analyze, OSINT, Simulate)
- Network (Network Security, Wireshark, Net Mapper)
- Tools (Create Module, Enc Modules, Hardware, exploits, Shield, etc.)
- System (UPnP, WireGuard, MSF Console, DNS, Settings, etc.)

Add a nav item:
```html
<li><a href="{{ url_for('myfeature.index') }}"
       class="{% if request.blueprint == 'myfeature' %}active{% endif %}">
    My Feature</a></li>
```

Sub-items use: `style="padding-left:1.5rem;font-size:0.85rem"` with `&#x2514;` prefix.

""")

    # MCP tools
    sections.append("""---

## 7. MCP Tool System

Tools exposed via Model Context Protocol (MCP) are defined in `core/mcp_server.py`.
To add a new MCP tool:

```python
# In create_mcp_server(), add:
@mcp.tool()
def my_tool(param1: str, param2: int = 10) -> str:
    \"\"\"Description of what the tool does.\"\"\"
    return execute_tool('my_tool', {'param1': param1, 'param2': param2})

# In execute_tool(), add the handler:
elif name == 'my_tool':
    return _run_my_tool(arguments)

# Implement the handler:
def _run_my_tool(args: dict) -> str:
    # ... implementation
    return json.dumps({'result': ...})
```

""")

    # Write output
    content = '\n'.join(sections)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(content, encoding='utf-8')
    print(f"[codex] Written {len(content):,} bytes to {OUTPUT_PATH}")
    print(f"[codex] Scanned: {len(modules)} modules, {len(core_modules)} core files, "
          f"{sum(len(r) for r in all_routes.values())} routes, {len(templates)} templates")


if __name__ == '__main__':
    build_codex()
