"""cx_Freeze MSI builder for AUTARCH Public Release.

Usage:  python setup_msi.py bdist_msi
Output: dist/autarch_public-*.msi
"""

import sys
from pathlib import Path
from cx_Freeze import setup, Executable

SRC = Path(__file__).parent

# Files/dirs to include alongside the executable
include_files = [
    (str(SRC / 'web' / 'templates'), 'web/templates'),
    (str(SRC / 'web' / 'static'),    'web/static'),
    (str(SRC / 'data'),              'data'),
    (str(SRC / 'modules'),           'modules'),
    (str(SRC / 'autarch_settings.conf'), 'autarch_settings.conf'),
    (str(SRC / 'user_manual.md'),        'user_manual.md'),
    (str(SRC / 'windows_manual.md'),     'windows_manual.md'),
]

# Only add files that exist
include_files = [(s, d) for s, d in include_files if Path(s).exists()]

build_exe_options = {
    'packages': [
        'flask', 'jinja2', 'werkzeug', 'markupsafe',
        'bcrypt', 'requests', 'pystray', 'PIL',
        'core', 'web', 'web.routes', 'modules',
    ],
    'includes': [
        'core.config', 'core.paths', 'core.banner', 'core.menu', 'core.tray',
        'core.llm', 'core.agent', 'core.tools',
        'core.msf', 'core.msf_interface',
        'core.hardware', 'core.android_protect',
        'core.upnp', 'core.wireshark', 'core.wireguard',
        'core.mcp_server', 'core.discovery',
        'core.sites_db', 'core.cve',
        'web.app', 'web.auth',
        'web.routes.auth_routes', 'web.routes.dashboard',
        'web.routes.defense', 'web.routes.offense',
        'web.routes.counter', 'web.routes.analyze',
        'web.routes.osint', 'web.routes.simulate',
        'web.routes.settings', 'web.routes.upnp',
        'web.routes.wireshark', 'web.routes.hardware',
        'web.routes.android_exploit', 'web.routes.iphone_exploit',
        'web.routes.android_protect', 'web.routes.wireguard',
        'web.routes.revshell', 'web.routes.archon',
        'web.routes.msf', 'web.routes.chat',
        'web.routes.targets', 'web.routes.encmodules',
        'web.routes.llm_trainer',
        'web.routes.autonomy',
        'web.routes.loadtest',
        'web.routes.phishmail',
        'web.routes.dns_service',
        'web.routes.ipcapture',
        'web.routes.hack_hijack',
        'web.routes.password_toolkit',
        'web.routes.webapp_scanner',
        'web.routes.report_engine',
        'web.routes.net_mapper',
        'web.routes.c2_framework',
        'web.routes.wifi_audit',
        'web.routes.threat_intel',
        'web.routes.steganography',
        'web.routes.api_fuzzer',
        'web.routes.ble_scanner',
        'web.routes.forensics',
        'web.routes.rfid_tools',
        'web.routes.cloud_scan',
        'web.routes.malware_sandbox',
        'web.routes.log_correlator',
        'web.routes.anti_forensics',
        'modules.loadtest',
        'modules.phishmail',
        'modules.ipcapture',
        'modules.hack_hijack',
        'modules.password_toolkit',
        'modules.webapp_scanner',
        'modules.report_engine',
        'modules.net_mapper',
        'modules.c2_framework',
        'modules.wifi_audit',
        'modules.threat_intel',
        'modules.steganography',
        'modules.api_fuzzer',
        'modules.ble_scanner',
        'modules.forensics',
        'modules.rfid_tools',
        'modules.cloud_scan',
        'modules.malware_sandbox',
        'modules.log_correlator',
        'modules.anti_forensics',
        'core.dns_service',
        'core.model_router', 'core.rules', 'core.autonomy',
    ],
    'excludes': ['torch', 'transformers',
                 'tkinter', 'matplotlib', 'numpy',
                 'bitsandbytes',
                 'huggingface_hub', 'safetensors', 'tokenizers',
                 'mcp', 'uvicorn', 'starlette', 'anyio', 'httpx', 'httpx_sse',
                 'httpcore', 'h11', 'h2', 'hpack', 'hyperframe',
                 'pydantic', 'pydantic_core', 'pydantic_settings',
                 'scipy', 'pandas', 'tensorflow', 'keras',
                 'IPython', 'notebook', 'jupyterlab',
                 'fsspec', 'rich', 'typer'],
    'include_files': include_files,
}

bdist_msi_options = {
    'upgrade_code': '{A07B3D2E-5F1C-4D8A-9E6B-0C2F7A8D4E1B}',
    'add_to_path': False,
    'initial_target_dir': r'[LocalAppDataFolder]\AUTARCH',
}

setup(
    name='AUTARCH',
    version='2.0',
    description='AUTARCH — Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking',
    author='darkHal Security Group & Setec Security Labs',
    options={
        'build_exe': build_exe_options,
        'bdist_msi': bdist_msi_options,
    },
    executables=[
        Executable(
            'autarch.py',
            target_name='autarch',
            base=None,  # console application (CLI)
        ),
        Executable(
            'autarch_web.py',
            target_name='autarch_web',
            base='Win32GUI',  # no console window (tray icon only)
        ),
    ],
)
