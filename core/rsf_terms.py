"""
AUTARCH RouterSploit Option Term Bank
Centralized descriptions and validation for RSF module options.
Mirrors core/msf_terms.py patterns for RSF-specific options.
"""

from .banner import Colors


# ─── RSF Settings Definitions ───────────────────────────────────────────────

RSF_SETTINGS = {
    # ── Target Options ──────────────────────────────────────────────────────
    'target': {
        'description': 'Target IPv4 or IPv6 address of the device to test. '
                       'Can also be set to file:// path for batch targeting '
                       '(e.g. file:///tmp/targets.txt with one IP per line).',
        'input_type': 'ip',
        'examples': ['192.168.1.1', '10.0.0.1', 'file:///tmp/targets.txt'],
        'default': '',
        'aliases': ['TARGET', 'rhost'],
        'category': 'target',
        'required': True,
        'notes': 'Most RSF modules require a target. Batch mode via file:// '
                 'is supported by modules decorated with @multi.',
    },
    'port': {
        'description': 'Target port number for the service being tested. '
                       'Default depends on the module protocol (80 for HTTP, '
                       '21 for FTP, 22 for SSH, etc.).',
        'input_type': 'port',
        'examples': ['80', '443', '8080', '22'],
        'default': '',
        'aliases': ['PORT', 'rport'],
        'category': 'target',
        'required': False,
        'notes': 'Each module sets an appropriate default port. Only override '
                 'if the target runs on a non-standard port.',
    },
    'ssl': {
        'description': 'Enable SSL/TLS for the connection. Set to true for '
                       'HTTPS targets or services using encrypted transport.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'false',
        'aliases': ['SSL', 'use_ssl'],
        'category': 'connection',
        'required': False,
        'notes': 'Automatically set for modules targeting HTTPS services.',
    },

    # ── Authentication/Credential Options ───────────────────────────────────
    'threads': {
        'description': 'Number of threads for brute-force or scanning operations. '
                       'Higher values are faster but may trigger rate-limiting.',
        'input_type': 'integer',
        'examples': ['1', '4', '8', '16'],
        'default': '8',
        'aliases': ['THREADS'],
        'category': 'scan',
        'required': False,
        'notes': 'Default is typically 8. Reduce for slower targets or to '
                 'avoid detection. Increase for LAN testing.',
    },
    'usernames': {
        'description': 'Username or wordlist for credential testing. '
                       'Single value, comma-separated list, or file path.',
        'input_type': 'wordlist',
        'examples': ['admin', 'admin,root,user', 'file:///tmp/users.txt'],
        'default': 'admin',
        'aliases': ['USERNAMES', 'username'],
        'category': 'auth',
        'required': False,
        'notes': 'For brute-force modules. Use file:// prefix for wordlist files. '
                 'Default credential modules have built-in lists.',
    },
    'passwords': {
        'description': 'Password or wordlist for credential testing. '
                       'Single value, comma-separated list, or file path.',
        'input_type': 'wordlist',
        'examples': ['password', 'admin,password,1234', 'file:///tmp/pass.txt'],
        'default': '',
        'aliases': ['PASSWORDS', 'password'],
        'category': 'auth',
        'required': False,
        'notes': 'For brute-force modules. Default credential modules use '
                 'built-in vendor-specific password lists.',
    },
    'stop_on_success': {
        'description': 'Stop brute-force attack after finding the first valid '
                       'credential pair.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['STOP_ON_SUCCESS'],
        'category': 'auth',
        'required': False,
        'notes': 'Set to false to enumerate all valid credentials.',
    },

    # ── Verbosity/Output Options ────────────────────────────────────────────
    'verbosity': {
        'description': 'Control output verbosity level. When true, modules '
                       'print detailed progress information.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['VERBOSITY', 'verbose'],
        'category': 'output',
        'required': False,
        'notes': 'Disable for cleaner output during automated scanning.',
    },

    # ── Protocol-Specific Ports ─────────────────────────────────────────────
    'http_port': {
        'description': 'HTTP port for web-based exploits and scanners.',
        'input_type': 'port',
        'examples': ['80', '8080', '8443'],
        'default': '80',
        'aliases': ['HTTP_PORT'],
        'category': 'target',
        'required': False,
        'notes': 'Used by HTTP-based modules. Change for non-standard web ports.',
    },
    'ftp_port': {
        'description': 'FTP port for file transfer protocol modules.',
        'input_type': 'port',
        'examples': ['21', '2121'],
        'default': '21',
        'aliases': ['FTP_PORT'],
        'category': 'target',
        'required': False,
        'notes': 'Standard FTP port is 21.',
    },
    'ssh_port': {
        'description': 'SSH port for secure shell modules.',
        'input_type': 'port',
        'examples': ['22', '2222'],
        'default': '22',
        'aliases': ['SSH_PORT'],
        'category': 'target',
        'required': False,
        'notes': 'Standard SSH port is 22.',
    },
    'telnet_port': {
        'description': 'Telnet port for telnet-based modules.',
        'input_type': 'port',
        'examples': ['23', '2323'],
        'default': '23',
        'aliases': ['TELNET_PORT'],
        'category': 'target',
        'required': False,
        'notes': 'Standard Telnet port is 23. Many IoT devices use telnet.',
    },
    'snmp_port': {
        'description': 'SNMP port for SNMP-based modules.',
        'input_type': 'port',
        'examples': ['161'],
        'default': '161',
        'aliases': ['SNMP_PORT'],
        'category': 'target',
        'required': False,
        'notes': 'Standard SNMP port is 161.',
    },
    'snmp_community': {
        'description': 'SNMP community string for SNMP-based modules.',
        'input_type': 'string',
        'examples': ['public', 'private'],
        'default': 'public',
        'aliases': ['SNMP_COMMUNITY', 'community'],
        'category': 'auth',
        'required': False,
        'notes': 'Default community strings "public" and "private" are common '
                 'on unconfigured devices.',
    },

    # ── File/Path Options ───────────────────────────────────────────────────
    'filename': {
        'description': 'File path to read or write on the target device. '
                       'Used by path traversal and file disclosure modules.',
        'input_type': 'string',
        'examples': ['/etc/passwd', '/etc/shadow', '/etc/config/shadow'],
        'default': '/etc/shadow',
        'aliases': ['FILENAME', 'filepath'],
        'category': 'file',
        'required': False,
        'notes': 'Common targets: /etc/passwd, /etc/shadow for credential extraction.',
    },

    # ── Payload Options ─────────────────────────────────────────────────────
    'lhost': {
        'description': 'Local IP address for reverse connections (listener).',
        'input_type': 'ip',
        'examples': ['192.168.1.100', '10.0.0.50'],
        'default': '',
        'aliases': ['LHOST'],
        'category': 'payload',
        'required': False,
        'notes': 'Required for reverse shell payloads. Use your attacker IP.',
    },
    'lport': {
        'description': 'Local port for reverse connections (listener).',
        'input_type': 'port',
        'examples': ['4444', '5555', '8888'],
        'default': '5555',
        'aliases': ['LPORT'],
        'category': 'payload',
        'required': False,
        'notes': 'Required for reverse shell payloads.',
    },
    'rport': {
        'description': 'Remote port for bind shell connections.',
        'input_type': 'port',
        'examples': ['5555', '4444'],
        'default': '5555',
        'aliases': ['RPORT'],
        'category': 'payload',
        'required': False,
        'notes': 'Required for bind shell payloads.',
    },
    'encoder': {
        'description': 'Encoder to use for payload obfuscation.',
        'input_type': 'string',
        'examples': ['base64', 'xor'],
        'default': '',
        'aliases': ['ENCODER'],
        'category': 'payload',
        'required': False,
        'notes': 'Optional. Available encoders depend on payload architecture.',
    },
    'output': {
        'description': 'Output format for generated payloads.',
        'input_type': 'string',
        'examples': ['python', 'elf', 'c'],
        'default': 'python',
        'aliases': ['OUTPUT'],
        'category': 'payload',
        'required': False,
        'notes': 'Architecture-specific payloads support elf, c, and python output.',
    },

    # ── Vendor/Device Options ───────────────────────────────────────────────
    'vendor': {
        'description': 'Target device vendor for vendor-specific modules.',
        'input_type': 'string',
        'examples': ['dlink', 'cisco', 'netgear', 'tp-link'],
        'default': '',
        'aliases': ['VENDOR'],
        'category': 'target',
        'required': False,
        'notes': 'Used to filter modules by vendor.',
    },
}


# ── Setting Categories ──────────────────────────────────────────────────────

SETTING_CATEGORIES = {
    'target': {
        'name': 'Target Options',
        'description': 'Target device addressing',
        'color': Colors.RED,
    },
    'connection': {
        'name': 'Connection Options',
        'description': 'Network connection parameters',
        'color': Colors.CYAN,
    },
    'auth': {
        'name': 'Authentication Options',
        'description': 'Credentials and authentication',
        'color': Colors.YELLOW,
    },
    'scan': {
        'name': 'Scan Options',
        'description': 'Scanning and threading parameters',
        'color': Colors.GREEN,
    },
    'output': {
        'name': 'Output Options',
        'description': 'Verbosity and output control',
        'color': Colors.WHITE,
    },
    'file': {
        'name': 'File Options',
        'description': 'File path parameters',
        'color': Colors.MAGENTA,
    },
    'payload': {
        'name': 'Payload Options',
        'description': 'Payload generation and delivery',
        'color': Colors.RED,
    },
}


# ─── API Functions ──────────────────────────────────────────────────────────

def get_setting_info(name: str) -> dict:
    """Get full setting information by name.

    Checks primary name first, then aliases.

    Args:
        name: Setting name (case-insensitive)

    Returns:
        Setting dict or None
    """
    name_lower = name.lower()

    # Direct lookup
    if name_lower in RSF_SETTINGS:
        return RSF_SETTINGS[name_lower]

    # Alias lookup
    for key, info in RSF_SETTINGS.items():
        if name_lower in [a.lower() for a in info.get('aliases', [])]:
            return info

    return None


def get_setting_prompt(name: str, default=None, required: bool = False) -> str:
    """Get a formatted input prompt for a setting.

    Args:
        name: Setting name
        default: Default value to show
        required: Whether the setting is required

    Returns:
        Formatted prompt string
    """
    info = get_setting_info(name)

    if info:
        if default is None:
            default = info.get('default', '')
        desc = info.get('description', '').split('.')[0]  # First sentence
        req = f" {Colors.RED}(required){Colors.RESET}" if required else ""
        if default:
            return f"    {Colors.WHITE}{name}{Colors.RESET} [{default}]{req}: "
        return f"    {Colors.WHITE}{name}{Colors.RESET}{req}: "
    else:
        if default:
            return f"    {Colors.WHITE}{name}{Colors.RESET} [{default}]: "
        return f"    {Colors.WHITE}{name}{Colors.RESET}: "


def format_setting_help(name: str, include_examples: bool = True,
                        include_notes: bool = True) -> str:
    """Get formatted help text for a setting.

    Args:
        name: Setting name
        include_examples: Include usage examples
        include_notes: Include additional notes

    Returns:
        Formatted help string
    """
    info = get_setting_info(name)
    if not info:
        return f"  {Colors.YELLOW}No help available for '{name}'{Colors.RESET}"

    lines = []
    lines.append(f"  {Colors.BOLD}{Colors.WHITE}{name.upper()}{Colors.RESET}")
    lines.append(f"  {info['description']}")

    if info.get('input_type'):
        lines.append(f"  {Colors.DIM}Type: {info['input_type']}{Colors.RESET}")

    if info.get('default'):
        lines.append(f"  {Colors.DIM}Default: {info['default']}{Colors.RESET}")

    if include_examples and info.get('examples'):
        lines.append(f"  {Colors.DIM}Examples: {', '.join(info['examples'])}{Colors.RESET}")

    if include_notes and info.get('notes'):
        lines.append(f"  {Colors.DIM}Note: {info['notes']}{Colors.RESET}")

    return '\n'.join(lines)


def validate_setting_value(name: str, value: str) -> tuple:
    """Validate a setting value against its type.

    Args:
        name: Setting name
        value: Value to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    info = get_setting_info(name)
    if not info:
        return True, ""  # Unknown settings pass validation

    input_type = info.get('input_type', 'string')

    if input_type == 'port':
        try:
            port = int(value)
            if 0 <= port <= 65535:
                return True, ""
            return False, "Port must be between 0 and 65535"
        except ValueError:
            return False, "Port must be a number"

    elif input_type == 'ip':
        # Allow file:// paths for batch targeting
        if value.startswith('file://'):
            return True, ""
        # Basic IPv4 validation
        import re
        if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', value):
            parts = value.split('.')
            if all(0 <= int(p) <= 255 for p in parts):
                return True, ""
            return False, "Invalid IP address octets"
        # IPv6 - basic check
        if ':' in value:
            return True, ""
        return False, "Expected IPv4 address, IPv6 address, or file:// path"

    elif input_type == 'boolean':
        if value.lower() in ('true', 'false', '1', '0', 'yes', 'no'):
            return True, ""
        return False, "Expected true/false"

    elif input_type == 'integer':
        try:
            int(value)
            return True, ""
        except ValueError:
            return False, "Expected an integer"

    return True, ""
