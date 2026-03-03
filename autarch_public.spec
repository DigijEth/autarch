# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for AUTARCH Public Release
#
# Build:   pyinstaller autarch_public.spec
# Output:  dist/autarch/
#            ├── autarch.exe       (CLI — full framework, console window)
#            └── autarch_web.exe   (Web — double-click to launch dashboard + tray icon, no console)

import sys
from pathlib import Path

SRC = Path(SPECPATH)

block_cipher = None

# ── Data files (non-Python assets to bundle) ─────────────────────────────────
# Only include files that actually exist to prevent build failures
_candidate_files = [
    # Web assets
    (SRC / 'web' / 'templates', 'web/templates'),
    (SRC / 'web' / 'static',    'web/static'),

    # Data (SQLite DBs, site lists, config defaults)
    (SRC / 'data',              'data'),

    # Modules directory (dynamically loaded at runtime)
    (SRC / 'modules',           'modules'),

    # Icon
    (SRC / 'autarch.ico',            '.'),

    # Root-level config and docs
    (SRC / 'autarch_settings.conf',  '.'),
    (SRC / 'user_manual.md',         '.'),
    (SRC / 'windows_manual.md',      '.'),
    (SRC / 'custom_sites.inf',       '.'),
    (SRC / 'custom_adultsites.json', '.'),
]

added_files = [(str(src), dst) for src, dst in _candidate_files if src.exists()]

# ── Hidden imports ────────────────────────────────────────────────────────────
hidden_imports = [
    # Flask ecosystem
    'flask', 'flask.templating', 'jinja2', 'jinja2.ext',
    'werkzeug', 'werkzeug.serving', 'werkzeug.debug',
    'markupsafe',

    # Core libraries
    'bcrypt', 'requests', 'msgpack', 'pyserial', 'qrcode', 'PIL',
    'PIL.Image', 'PIL.ImageDraw', 'PIL.ImageFont', 'cryptography',

    # System tray
    'pystray', 'pystray._win32',

    # AUTARCH core modules
    'core.config', 'core.paths', 'core.banner', 'core.menu', 'core.tray',
    'core.llm', 'core.agent', 'core.tools',
    'core.msf', 'core.msf_interface',
    'core.hardware', 'core.android_protect',
    'core.upnp', 'core.wireshark', 'core.wireguard',
    'core.mcp_server', 'core.discovery',
    'core.osint_db', 'core.nvd',
    'core.model_router', 'core.rules', 'core.autonomy',

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
    'web.routes.encmodules',
    'web.routes.llm_trainer',
    'web.routes.autonomy',

    # Standard library (sometimes missed on Windows)
    'email.mime.text', 'email.mime.multipart',
    'xml.etree.ElementTree',
    'sqlite3', 'json', 'logging', 'logging.handlers',
    'threading', 'queue', 'uuid', 'hashlib', 'zlib',
    'configparser', 'platform', 'socket', 'shutil',
    'importlib', 'importlib.util', 'importlib.metadata',
    'webbrowser', 'ssl',
]

excludes = [
    # Exclude heavy optional deps not needed at runtime
    'torch', 'transformers',
    'tkinter', 'matplotlib', 'numpy',
    # CUDA / quantization libraries
    'bitsandbytes',
    # HuggingFace ecosystem
    'huggingface_hub', 'safetensors', 'tokenizers',
    # MCP/uvicorn/starlette
    'mcp', 'uvicorn', 'starlette', 'anyio', 'httpx', 'httpx_sse',
    'httpcore', 'h11', 'h2', 'hpack', 'hyperframe',
    # Pydantic
    'pydantic', 'pydantic_core', 'pydantic_settings',
    # Other heavy packages
    'scipy', 'pandas', 'tensorflow', 'keras',
    'IPython', 'notebook', 'jupyterlab',
    'fsspec', 'rich', 'typer',
]

# ── Analysis for CLI entry point ─────────────────────────────────────────────
a_cli = Analysis(
    ['autarch.py'],
    pathex=[str(SRC)],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

# ── Analysis for Web entry point ─────────────────────────────────────────────
a_web = Analysis(
    ['autarch_web.py'],
    pathex=[str(SRC)],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

# ── Merge analyses (shared libraries only stored once) ───────────────────────
MERGE(
    (a_cli, 'autarch', 'autarch'),
    (a_web, 'autarch_web', 'autarch_web'),
)

# ── CLI executable (console window) ─────────────────────────────────────────
pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)
exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name='autarch',
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
    icon=str(SRC / 'autarch.ico'),
)

# ── Web executable (NO console window — tray icon only) ─────────────────────
pyz_web = PYZ(a_web.pure, a_web.zipped_data, cipher=block_cipher)
exe_web = EXE(
    pyz_web,
    a_web.scripts,
    [],
    exclude_binaries=True,
    name='autarch_web',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,       # <-- No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(SRC / 'autarch.ico'),
)

# ── Collect everything into one directory ────────────────────────────────────
coll = COLLECT(
    exe_cli,
    a_cli.binaries,
    a_cli.datas,
    exe_web,
    a_web.binaries,
    a_web.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='autarch',
)
