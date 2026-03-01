"""
AUTARCH Path Resolution
Centralized path management for cross-platform portability.

All paths resolve relative to the application root directory.
Tool lookup checks project directories first, then system PATH.
"""

import os
import platform
import shutil
from pathlib import Path
from typing import Optional, List


# ── Application Root ────────────────────────────────────────────────

# Computed once: the autarch project root (parent of core/)
_APP_DIR = Path(__file__).resolve().parent.parent


def get_app_dir() -> Path:
    """Return the AUTARCH application root directory."""
    return _APP_DIR


def get_core_dir() -> Path:
    return _APP_DIR / 'core'


def get_modules_dir() -> Path:
    return _APP_DIR / 'modules'


def get_data_dir() -> Path:
    d = _APP_DIR / 'data'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_config_path() -> Path:
    return _APP_DIR / 'autarch_settings.conf'


def get_results_dir() -> Path:
    d = _APP_DIR / 'results'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_reports_dir() -> Path:
    d = get_results_dir() / 'reports'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_dossiers_dir() -> Path:
    d = _APP_DIR / 'dossiers'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_uploads_dir() -> Path:
    d = get_data_dir() / 'uploads'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_backups_dir() -> Path:
    d = _APP_DIR / 'backups'
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_templates_dir() -> Path:
    return _APP_DIR / '.config'


def get_custom_configs_dir() -> Path:
    d = _APP_DIR / '.config' / 'custom'
    d.mkdir(parents=True, exist_ok=True)
    return d


# ── Platform Detection ──────────────────────────────────────────────

def _get_arch() -> str:
    """Return architecture string: 'x86_64', 'arm64', etc."""
    machine = platform.machine().lower()
    if machine in ('aarch64', 'arm64'):
        return 'arm64'
    elif machine in ('x86_64', 'amd64'):
        return 'x86_64'
    return machine


def get_platform() -> str:
    """Return platform: 'linux', 'windows', or 'darwin'."""
    return platform.system().lower()


def get_platform_tag() -> str:
    """Return platform-arch tag like 'linux-arm64', 'windows-x86_64'."""
    return f"{get_platform()}-{_get_arch()}"


def is_windows() -> bool:
    return platform.system() == 'Windows'


def is_linux() -> bool:
    return platform.system() == 'Linux'


def is_mac() -> bool:
    return platform.system() == 'Darwin'


# ── Tool / Binary Lookup ───────────────────────────────────────────
#
# Priority order:
#   1. System PATH (shutil.which — native binaries, correct arch)
#   2. Platform-specific well-known install locations
#   3. Platform-specific project tools (tools/linux-arm64/, etc.)
#   4. Generic project directories (android/, tools/, bin/)
#   5. Extra paths passed by caller
#

# Well-known install locations by platform (last resort)
_PLATFORM_SEARCH_PATHS = {
    'windows': [
        Path(os.environ.get('LOCALAPPDATA', '')) / 'Android' / 'Sdk' / 'platform-tools',
        Path(os.environ.get('USERPROFILE', '')) / 'Android' / 'Sdk' / 'platform-tools',
        Path('C:/Program Files (x86)/Nmap'),
        Path('C:/Program Files/Nmap'),
        Path('C:/Program Files/Wireshark'),
        Path('C:/Program Files (x86)/Wireshark'),
        Path('C:/metasploit-framework/bin'),
    ],
    'darwin': [
        Path('/opt/homebrew/bin'),
        Path('/usr/local/bin'),
    ],
    'linux': [
        Path('/usr/local/bin'),
        Path('/snap/bin'),
    ],
}

# Tools that need extra environment setup when run from bundled copies
_TOOL_ENV_SETUP = {
    'nmap': '_setup_nmap_env',
}


def _setup_nmap_env(tool_path: str):
    """Set NMAPDIR so bundled nmap finds its data files."""
    tool_dir = Path(tool_path).parent
    nmap_data = tool_dir / 'nmap-data'
    if nmap_data.is_dir():
        os.environ['NMAPDIR'] = str(nmap_data)


def _is_native_binary(path: str) -> bool:
    """Check if an ELF binary matches the host architecture."""
    try:
        with open(path, 'rb') as f:
            magic = f.read(20)
        if magic[:4] != b'\x7fELF':
            return True  # Not ELF (script, etc.) — assume OK
        # ELF e_machine at offset 18 (2 bytes, little-endian)
        e_machine = int.from_bytes(magic[18:20], 'little')
        arch = _get_arch()
        if arch == 'arm64' and e_machine == 183:     # EM_AARCH64
            return True
        if arch == 'x86_64' and e_machine == 62:     # EM_X86_64
            return True
        if arch == 'arm64' and e_machine == 62:       # x86-64 on arm64 host
            return False
        if arch == 'x86_64' and e_machine == 183:     # arm64 on x86-64 host
            return False
        return True  # Unknown arch combo — let it try
    except Exception:
        return True  # Can't read — assume OK


def find_tool(name: str, extra_paths: Optional[List[str]] = None) -> Optional[str]:
    """
    Find an executable binary by name.

    Search order:
      1. System PATH (native binaries, correct architecture)
      2. Platform-specific well-known install locations
      3. Platform-specific project tools (tools/linux-arm64/ etc.)
      4. Generic project directories (android/, tools/, bin/)
      5. Extra paths provided by caller

    Skips binaries that don't match the host architecture (e.g. x86-64
    binaries on ARM64 hosts) to avoid FEX/emulation issues with root.

    Returns absolute path string, or None if not found.
    """
    # On Windows, append .exe if no extension
    names = [name]
    if is_windows() and '.' not in name:
        names.append(name + '.exe')

    # 1. System PATH (most reliable — native packages)
    found = shutil.which(name)
    if found and _is_native_binary(found):
        return found

    # 2. Platform-specific well-known locations
    plat = get_platform()
    for search_dir in _PLATFORM_SEARCH_PATHS.get(plat, []):
        if search_dir.is_dir():
            for n in names:
                full = search_dir / n
                if full.is_file() and os.access(str(full), os.X_OK) and _is_native_binary(str(full)):
                    return str(full)

    # 3-4. Bundled project directories
    plat_tag = get_platform_tag()
    search_dirs = [
        _APP_DIR / 'tools' / plat_tag,   # Platform-specific (tools/linux-arm64/)
        _APP_DIR / 'android',             # Android tools
        _APP_DIR / 'tools',               # Generic tools/
        _APP_DIR / 'bin',                 # Generic bin/
    ]

    for tool_dir in search_dirs:
        if tool_dir.is_dir():
            for n in names:
                full = tool_dir / n
                if full.is_file() and os.access(str(full), os.X_OK):
                    found = str(full)
                    if not _is_native_binary(found):
                        continue  # Wrong arch — skip
                    # Apply environment setup for bundled tools
                    env_fn = _TOOL_ENV_SETUP.get(name)
                    if env_fn:
                        globals()[env_fn](found)
                    return found

    # 5. Extra paths from caller
    if extra_paths:
        for p in extra_paths:
            for n in names:
                full = os.path.join(p, n)
                if os.path.isfile(full) and os.access(full, os.X_OK) and _is_native_binary(full):
                    return full

    # Last resort: return system PATH result even if wrong arch (FEX may work for user)
    found = shutil.which(name)
    if found:
        return found

    return None


def tool_available(name: str) -> bool:
    """Check if a tool is available anywhere."""
    return find_tool(name) is not None
