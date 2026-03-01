# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for AUTARCH
# Build: pyinstaller autarch.spec
# Output: dist/bin/AUTARCH/ (one-dir) and dist/bin/AUTARCH.exe (one-file via --onefile)

import sys
from pathlib import Path

SRC = Path(SPECPATH)

block_cipher = None

# ── Data files (non-Python assets to bundle) ─────────────────────────────────
added_files = [
    # Web assets
    (str(SRC / 'web' / 'templates'), 'web/templates'),
    (str(SRC / 'web' / 'static'),    'web/static'),

    # Data (SQLite DBs, site lists, config defaults)
    (str(SRC / 'data'),              'data'),

    # Modules directory (dynamically loaded)
    (str(SRC / 'modules'),           'modules'),

    # Root-level config and docs
    (str(SRC / 'autarch_settings.conf'),         '.'),
    (str(SRC / 'autarch_settings.conf'),         '.'),
    (str(SRC / 'user_manual.md'),                '.'),
    (str(SRC / 'windows_manual.md'),             '.'),
    (str(SRC / 'custom_sites.inf'),              '.'),
    (str(SRC / 'custom_adultsites.json'),         '.'),

    # Android ADB/fastboot tools
    (str(SRC / 'android'),           'android'),

    # Windows tool binaries (nmap, tshark, etc. — user fills this in)
    (str(SRC / 'tools'),             'tools'),
]

# ── Hidden imports ────────────────────────────────────────────────────────────
hidden_imports = [
    # Flask ecosystem
    'flask', 'flask.templating', 'jinja2', 'jinja2.ext',
    'werkzeug', 'werkzeug.serving', 'werkzeug.debug',
    'markupsafe',

    # Core libraries
    'bcrypt', 'requests', 'msgpack', 'pyserial', 'qrcode', 'PIL',
    'PIL.Image', 'PIL.ImageDraw', 'cryptography',

    # AUTARCH core modules
    'core.config', 'core.paths', 'core.banner', 'core.menu',
    'core.llm', 'core.agent', 'core.tools',
    'core.msf', 'core.msf_interface',
    'core.hardware', 'core.android_protect',
    'core.upnp', 'core.wireshark', 'core.wireguard',
    'core.mcp_server', 'core.discovery',
    'core.osint_db', 'core.nvd',

    # Web routes (Flask blueprints)
    'web.app', 'web.auth',
    'web.routes.auth_routes',
    'web.routes.dashboard',
    'web.routes.defense',
    'web.routes.offense',
    'web.routes.counter',
    'web.routes.analyze',
    'web.routes.osint',
    'web.routes.simulate',
    'web.routes.settings',
    'web.routes.upnp',
    'web.routes.wireshark',
    'web.routes.hardware',
    'web.routes.android_exploit',
    'web.routes.iphone_exploit',
    'web.routes.android_protect',
    'web.routes.wireguard',
    'web.routes.revshell',
    'web.routes.archon',
    'web.routes.msf',
    'web.routes.chat',
    'web.routes.targets',

    # Standard library (sometimes missed on Windows)
    'email.mime.text', 'email.mime.multipart',
    'xml.etree.ElementTree',
    'sqlite3', 'json', 'logging', 'logging.handlers',
    'threading', 'queue', 'uuid', 'hashlib',
    'configparser', 'platform', 'socket', 'shutil',
    'importlib', 'importlib.util', 'importlib.metadata',
]

a = Analysis(
    ['autarch.py'],
    pathex=[str(SRC)],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy optional deps not needed at runtime
        'torch', 'transformers', 'llama_cpp', 'anthropic',
        'tkinter', 'matplotlib', 'numpy',
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── One-directory build (recommended for Flask apps) ─────────────────────────
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='AUTARCH',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='AUTARCH',
)
