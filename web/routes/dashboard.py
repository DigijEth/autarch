"""Dashboard route - main landing page"""

import platform
import shutil
import socket
import time
from datetime import datetime
from pathlib import Path
from flask import Blueprint, render_template, current_app, jsonify
from markupsafe import Markup
from web.auth import login_required

dashboard_bp = Blueprint('dashboard', __name__)


def get_system_info():
    info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'arch': platform.machine(),
    }
    try:
        info['ip'] = socket.gethostbyname(socket.gethostname())
    except Exception:
        info['ip'] = '127.0.0.1'

    # Uptime
    try:
        with open('/proc/uptime') as f:
            uptime_secs = float(f.read().split()[0])
        days = int(uptime_secs // 86400)
        hours = int((uptime_secs % 86400) // 3600)
        info['uptime'] = f"{days}d {hours}h"
    except Exception:
        info['uptime'] = 'N/A'

    return info


def get_tool_status():
    from core.paths import find_tool
    tools = {}
    for tool in ['nmap', 'tshark', 'upnpc', 'msfrpcd', 'wg']:
        tools[tool] = find_tool(tool) is not None
    return tools


def get_module_counts():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    counts = {}
    for name, info in menu.modules.items():
        cat = info.category
        counts[cat] = counts.get(cat, 0) + 1
    counts['total'] = len(menu.modules)
    return counts


@dashboard_bp.route('/')
@login_required
def index():
    config = current_app.autarch_config
    system = get_system_info()
    tools = get_tool_status()
    modules = get_module_counts()

    # LLM status
    llm_backend = config.get('autarch', 'llm_backend', fallback='local')
    if llm_backend == 'transformers':
        llm_model = config.get('transformers', 'model_path', fallback='')
    elif llm_backend == 'claude':
        llm_model = config.get('claude', 'model', fallback='')
    elif llm_backend == 'huggingface':
        llm_model = config.get('huggingface', 'model', fallback='')
    else:
        llm_model = config.get('llama', 'model_path', fallback='')

    # UPnP status
    upnp_enabled = config.get_bool('upnp', 'enabled', fallback=False)

    return render_template('dashboard.html',
        system=system,
        tools=tools,
        modules=modules,
        llm_backend=llm_backend,
        llm_model=llm_model,
        upnp_enabled=upnp_enabled,
    )


@dashboard_bp.route('/manual')
@login_required
def manual():
    """Render the user manual as HTML."""
    manual_path = Path(__file__).parent.parent.parent / 'user_manual.md'
    content = manual_path.read_text(encoding='utf-8') if manual_path.exists() else '# Manual not found'
    try:
        import markdown
        html = markdown.markdown(content, extensions=['tables', 'fenced_code', 'toc'])
    except ImportError:
        html = '<pre>' + content.replace('<', '&lt;') + '</pre>'
    return render_template('manual.html', manual_html=Markup(html))


@dashboard_bp.route('/manual/windows')
@login_required
def manual_windows():
    """Render the Windows-specific user manual."""
    manual_path = Path(__file__).parent.parent.parent / 'windows_manual.md'
    content = manual_path.read_text(encoding='utf-8') if manual_path.exists() else '# Windows manual not found'
    try:
        import markdown
        html = markdown.markdown(content, extensions=['tables', 'fenced_code', 'toc'])
    except ImportError:
        html = '<pre>' + content.replace('<', '&lt;') + '</pre>'
    return render_template('manual.html', manual_html=Markup(html))


@dashboard_bp.route('/api/modules/reload', methods=['POST'])
@login_required
def reload_modules():
    """Re-scan modules directory and return updated counts + module list."""
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()

    counts = {}
    modules = []
    for name, info in menu.modules.items():
        cat = info.category
        counts[cat] = counts.get(cat, 0) + 1
        modules.append({
            'name': name,
            'category': cat,
            'description': info.description,
            'version': info.version,
        })
    counts['total'] = len(menu.modules)

    return jsonify({'counts': counts, 'modules': modules, 'total': counts['total']})
