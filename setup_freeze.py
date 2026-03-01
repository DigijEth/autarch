"""
cx_Freeze setup for AUTARCH Windows MSI installer.

Usage:
    pip install cx_Freeze
    python setup_freeze.py bdist_msi

Output: dist/bin/autarch-1.3-win64.msi  (or similar)
"""

import sys
from pathlib import Path
from cx_Freeze import setup, Executable

SRC = Path(__file__).parent
VERSION = "1.3"

# ── Data files ────────────────────────────────────────────────────────────────
include_files = [
    # Web assets
    (str(SRC / 'web' / 'templates'), 'lib/web/templates'),
    (str(SRC / 'web' / 'static'),    'lib/web/static'),

    # Data directory
    (str(SRC / 'data'),              'lib/data'),

    # Modules (dynamically imported)
    (str(SRC / 'modules'),           'lib/modules'),

    # Docs and config
    (str(SRC / 'autarch_settings.conf'),  'autarch_settings.conf'),
    (str(SRC / 'user_manual.md'),         'user_manual.md'),
    (str(SRC / 'windows_manual.md'),      'windows_manual.md'),
    (str(SRC / 'custom_sites.inf'),       'custom_sites.inf'),
    (str(SRC / 'custom_adultsites.json'),  'custom_adultsites.json'),

    # Android tools
    (str(SRC / 'android'),           'android'),
    (str(SRC / 'tools'),             'tools'),
]

# ── Build options ─────────────────────────────────────────────────────────────
build_options = {
    'packages': [
        'flask', 'jinja2', 'werkzeug', 'markupsafe', 'bcrypt',
        'requests', 'msgpack', 'pyserial', 'qrcode', 'PIL',
        'core', 'web', 'modules',
    ],
    'excludes': ['tkinter', 'matplotlib', 'torch', 'transformers'],
    'include_files': include_files,
    'path': [str(SRC)] + sys.path,
    'build_exe': str(SRC / 'dist' / 'bin' / 'AUTARCH-build'),
}

# ── MSI-specific options ──────────────────────────────────────────────────────
bdist_msi_options = {
    'add_to_path': True,
    'initial_target_dir': r'[ProgramFilesFolder]\AUTARCH',
    'product_code': '{6E4A2B35-C8F1-4D28-A91E-8D4F7C3B2A91}',
    'upgrade_code': '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}',
    'install_icon': None,
    'summary_data': {
        'author': 'darkHal Security Group',
        'comments': 'AUTARCH Security Platform',
        'keywords': 'security, pentest, OSINT, AI',
    },
}

setup(
    name='AUTARCH',
    version=VERSION,
    description='AUTARCH — Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking',
    author='darkHal Security Group & Setec Security Labs',
    options={
        'build_exe': build_options,
        'bdist_msi': bdist_msi_options,
    },
    executables=[
        Executable(
            script='autarch.py',
            target_name='AUTARCH.exe',
            base='Console',  # Console app (not GUI)
            icon=None,
        )
    ],
)
