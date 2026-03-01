"""
AUTARCH RouterSploit Curated Module Library
Offline-browsable metadata for key RSF modules.
Mirrors core/msf_modules.py patterns for RSF-specific modules.
"""

from .banner import Colors


# ─── Module Library ─────────────────────────────────────────────────────────

RSF_MODULES = {
    # ════════════════════════════════════════════════════════════════════════
    # EXPLOITS - ROUTERS
    # ════════════════════════════════════════════════════════════════════════

    # ── D-Link Routers ──────────────────────────────────────────────────────
    'exploits/routers/dlink/dir_300_600_rce': {
        'name': 'D-Link DIR-300 & DIR-600 RCE',
        'description': 'Exploits D-Link DIR-300, DIR-600 Remote Code Execution '
                       'vulnerability allowing command execution with root privileges.',
        'authors': ('Michael Messner', 'Marcin Bury'),
        'devices': ('D-Link DIR 300', 'D-Link DIR 600'),
        'references': ('http://www.s3cur1ty.de/m1adv2013-003',),
        'tags': ('dlink', 'rce', 'router', 'http'),
        'notes': 'Targets the web interface. Requires HTTP access to the router.',
    },
    'exploits/routers/dlink/dir_645_815_rce': {
        'name': 'D-Link DIR-645 & DIR-815 RCE',
        'description': 'Exploits D-Link DIR-645 and DIR-815 Remote Code Execution '
                       'vulnerability via the web interface.',
        'authors': ('Michael Messner', 'Marcin Bury'),
        'devices': ('DIR-815 v1.03b02', 'DIR-645 v1.02', 'DIR-645 v1.03',
                    'DIR-600 below v2.16b01', 'DIR-300 revB v2.13b01',
                    'DIR-412 Ver 1.14WWB02', 'DIR-110 Ver 1.01'),
        'references': ('http://www.s3cur1ty.de/m1adv2013-017',),
        'tags': ('dlink', 'rce', 'router', 'http'),
        'notes': 'Affects multiple DIR-series firmware versions.',
    },
    'exploits/routers/dlink/multi_hnap_rce': {
        'name': 'D-Link Multi HNAP RCE',
        'description': 'Exploits HNAP remote code execution in multiple D-Link devices '
                       'allowing command execution on the device.',
        'authors': ('Samuel Huntley', 'Craig Heffner', 'Marcin Bury'),
        'devices': ('D-Link DIR-645', 'D-Link DIR-880L', 'D-Link DIR-865L',
                    'D-Link DIR-860L revA/B', 'D-Link DIR-815 revB',
                    'D-Link DIR-300 revB', 'D-Link DIR-600 revB',
                    'D-Link DAP-1650 revB'),
        'references': ('https://www.exploit-db.com/exploits/37171/',
                       'http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/'),
        'tags': ('dlink', 'rce', 'hnap', 'router', 'http'),
        'notes': 'HNAP (Home Network Administration Protocol) vulnerability '
                 'affecting a wide range of D-Link devices.',
    },

    # ── Cisco Routers ───────────────────────────────────────────────────────
    'exploits/routers/cisco/rv320_command_injection': {
        'name': 'Cisco RV320 Command Injection',
        'description': 'Exploits Cisco RV320 Remote Command Injection in the '
                       'web-based certificate generator feature (CVE-2019-1652).',
        'authors': ('RedTeam Pentesting GmbH', 'GH0st3rs'),
        'devices': ('Cisco RV320 1.4.2.15 to 1.4.2.22', 'Cisco RV325'),
        'references': ('https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1652',),
        'tags': ('cisco', 'rce', 'command_injection', 'router', 'cve-2019-1652'),
        'notes': 'Requires HTTPS access (port 443). Targets certificate generator.',
    },
    'exploits/routers/cisco/ios_http_authorization_bypass': {
        'name': 'Cisco IOS HTTP Authorization Bypass',
        'description': 'HTTP server for Cisco IOS 11.3 to 12.2 allows attackers to '
                       'bypass authentication and execute commands by specifying a '
                       'high access level in the URL (CVE-2001-0537).',
        'authors': ('renos stoikos',),
        'devices': ('Cisco IOS 11.3 to 12.2',),
        'references': ('http://www.cvedetails.com/cve/cve-2001-0537',),
        'tags': ('cisco', 'auth_bypass', 'ios', 'router', 'http', 'cve-2001-0537'),
        'notes': 'Classic IOS vulnerability. Only affects very old IOS versions.',
    },

    # ── Netgear Routers ─────────────────────────────────────────────────────
    'exploits/routers/netgear/dgn2200_ping_cgi_rce': {
        'name': 'Netgear DGN2200 RCE',
        'description': 'Exploits Netgear DGN2200 RCE via ping.cgi script '
                       '(CVE-2017-6077).',
        'authors': ('SivertPL', 'Josh Abraham'),
        'devices': ('Netgear DGN2200v1-v4',),
        'references': ('https://www.exploit-db.com/exploits/41394/',
                       'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6077'),
        'tags': ('netgear', 'rce', 'router', 'http', 'cve-2017-6077'),
        'notes': 'Requires valid credentials (default: admin/password).',
    },
    'exploits/routers/netgear/multi_rce': {
        'name': 'Netgear Multi RCE',
        'description': 'Exploits remote command execution in multiple Netgear devices. '
                       'If vulnerable, opens a command loop with OS-level access.',
        'authors': ('Andrei Costin', 'Marcin Bury'),
        'devices': ('Netgear WG102', 'Netgear WG103', 'Netgear WN604',
                    'Netgear WNDAP350', 'Netgear WNDAP360', 'Netgear WNAP320',
                    'Netgear WNDAP660', 'Netgear WNDAP620'),
        'references': ('http://firmware.re/vulns/acsa-2015-001.php',),
        'tags': ('netgear', 'rce', 'router', 'http', 'multi'),
        'notes': 'Targets multiple Netgear enterprise wireless APs.',
    },

    # ── Mikrotik Routers ────────────────────────────────────────────────────
    'exploits/routers/mikrotik/winbox_auth_bypass_creds_disclosure': {
        'name': 'Mikrotik WinBox Auth Bypass - Credentials Disclosure',
        'description': 'Bypasses authentication through WinBox service in Mikrotik '
                       'devices v6.29 to v6.42 and retrieves admin credentials.',
        'authors': ('Alireza Mosajjal', 'Mostafa Yalpaniyan', 'Marcin Bury'),
        'devices': ('Mikrotik RouterOS 6.29 to 6.42',),
        'references': ('https://n0p.me/winbox-bug-dissection/',
                       'https://github.com/BasuCert/WinboxPoC'),
        'tags': ('mikrotik', 'auth_bypass', 'creds', 'winbox', 'router', 'tcp'),
        'notes': 'Targets WinBox service (port 8291). Very high impact.',
    },

    # ── TP-Link Routers ─────────────────────────────────────────────────────
    'exploits/routers/tplink/archer_c2_c20i_rce': {
        'name': 'TP-Link Archer C2 & C20i RCE',
        'description': 'Exploits TP-Link Archer C2 and C20i RCE allowing root-level '
                       'command execution.',
        'authors': ('Michal Sajdak', 'Marcin Bury'),
        'devices': ('TP-Link Archer C2', 'TP-Link Archer C20i'),
        'references': (),
        'tags': ('tplink', 'rce', 'router', 'http'),
        'notes': 'Targets the Archer web interface.',
    },

    # ── Asus Routers ────────────────────────────────────────────────────────
    'exploits/routers/asus/asuswrt_lan_rce': {
        'name': 'AsusWRT LAN RCE',
        'description': 'Exploits multiple vulnerabilities in AsusWRT firmware to achieve '
                       'RCE: HTTP auth bypass + VPN config upload + infosvr command '
                       'execution (CVE-2018-5999, CVE-2018-6000).',
        'authors': ('Pedro Ribeiro', 'Marcin Bury'),
        'devices': ('AsusWRT < v3.0.0.4.384.10007',),
        'references': ('https://nvd.nist.gov/vuln/detail/CVE-2018-5999',
                       'https://nvd.nist.gov/vuln/detail/CVE-2018-6000'),
        'tags': ('asus', 'rce', 'auth_bypass', 'router', 'http', 'udp',
                 'cve-2018-5999', 'cve-2018-6000'),
        'notes': 'Chains HTTP auth bypass with UDP infosvr for full RCE.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # EXPLOITS - CAMERAS
    # ════════════════════════════════════════════════════════════════════════

    'exploits/cameras/dlink/dcs_930l_932l_auth_bypass': {
        'name': 'D-Link DCS Cameras Auth Bypass',
        'description': 'D-Link DCS web cameras allow unauthenticated attackers to '
                       'obtain device configuration by accessing unprotected URLs.',
        'authors': ('Roberto Paleari', 'Dino Causevic'),
        'devices': ('D-Link DCS-930L fw 1.04', 'D-Link DCS-932L fw 1.02'),
        'references': ('https://www.exploit-db.com/exploits/24442/',),
        'tags': ('dlink', 'camera', 'auth_bypass', 'http'),
        'notes': 'Uses port 8080 by default.',
    },
    'exploits/cameras/cisco/video_surv_path_traversal': {
        'name': 'Cisco Video Surveillance Path Traversal',
        'description': 'Path traversal in Cisco Video Surveillance Operations '
                       'Manager 6.3.2 allowing file reads from the filesystem.',
        'authors': ('b.saleh', 'Marcin Bury'),
        'devices': ('Cisco Video Surveillance Operations Manager 6.3.2',),
        'references': ('https://www.exploit-db.com/exploits/38389/',),
        'tags': ('cisco', 'camera', 'path_traversal', 'http'),
        'notes': 'Read /etc/passwd or other files via path traversal.',
    },
    'exploits/cameras/brickcom/corp_network_cameras_conf_disclosure': {
        'name': 'Brickcom Network Camera Config Disclosure',
        'description': 'Exploits Brickcom Corporation Network Camera configuration '
                       'disclosure vulnerability to read device config and credentials.',
        'authors': ('Orwelllabs', 'Marcin Bury'),
        'devices': ('Brickcom FB-100Ae', 'Brickcom WCB-100Ap',
                    'Brickcom OB-200Np-LR', 'Brickcom VD-E200Nf'),
        'references': ('https://www.exploit-db.com/exploits/39696/',),
        'tags': ('brickcom', 'camera', 'config_disclosure', 'http'),
        'notes': 'Extracts admin credentials from configuration.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # EXPLOITS - GENERIC
    # ════════════════════════════════════════════════════════════════════════

    'exploits/generic/heartbleed': {
        'name': 'OpenSSL Heartbleed',
        'description': 'Exploits OpenSSL Heartbleed vulnerability (CVE-2014-0160). '
                       'Fake heartbeat length leaks memory data from the server.',
        'authors': ('Neel Mehta', 'Jared Stafford', 'Marcin Bury'),
        'devices': ('Multi',),
        'references': ('http://www.cvedetails.com/cve/2014-0160',
                       'http://heartbleed.com/'),
        'tags': ('heartbleed', 'openssl', 'ssl', 'tls', 'memory_leak', 'generic',
                 'cve-2014-0160'),
        'notes': 'Tests for Heartbleed on any SSL/TLS service. '
                 'Default port 443.',
    },
    'exploits/generic/shellshock': {
        'name': 'Shellshock',
        'description': 'Exploits Shellshock vulnerability (CVE-2014-6271) allowing '
                       'OS command execution via crafted HTTP headers.',
        'authors': ('Marcin Bury',),
        'devices': ('Multi',),
        'references': ('https://access.redhat.com/articles/1200223',),
        'tags': ('shellshock', 'bash', 'rce', 'http', 'generic', 'cve-2014-6271'),
        'notes': 'Injects via HTTP headers (default: User-Agent). '
                 'Configure path and method as needed.',
    },
    'exploits/generic/ssh_auth_keys': {
        'name': 'SSH Authorized Keys',
        'description': 'Tests for known default SSH keys that ship with various '
                       'embedded devices and appliances.',
        'authors': ('Marcin Bury',),
        'devices': ('Multi',),
        'references': (),
        'tags': ('ssh', 'keys', 'default_creds', 'generic'),
        'notes': 'Checks for factory SSH keys common on IoT/embedded devices.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # CREDENTIALS - GENERIC
    # ════════════════════════════════════════════════════════════════════════

    'creds/generic/ftp_bruteforce': {
        'name': 'FTP Bruteforce',
        'description': 'Performs bruteforce attack against FTP service. '
                       'Displays valid credentials when found.',
        'authors': ('Marcin Bury',),
        'devices': ('Multiple devices',),
        'references': (),
        'tags': ('ftp', 'bruteforce', 'creds', 'generic'),
        'notes': 'Supports file:// targets for batch mode. '
                 'Default port 21. Threaded (default 8 threads).',
    },
    'creds/generic/ssh_bruteforce': {
        'name': 'SSH Bruteforce',
        'description': 'Performs bruteforce attack against SSH service. '
                       'Displays valid credentials when found.',
        'authors': ('Marcin Bury',),
        'devices': ('Multiple devices',),
        'references': (),
        'tags': ('ssh', 'bruteforce', 'creds', 'generic'),
        'notes': 'Default port 22. Threaded. Supports batch targets via file://.',
    },
    'creds/generic/telnet_bruteforce': {
        'name': 'Telnet Bruteforce',
        'description': 'Performs bruteforce attack against Telnet service. '
                       'Displays valid credentials when found.',
        'authors': ('Marcin Bury',),
        'devices': ('Multiple devices',),
        'references': (),
        'tags': ('telnet', 'bruteforce', 'creds', 'generic'),
        'notes': 'Default port 23. Common on IoT devices with telnet enabled.',
    },
    'creds/generic/snmp_bruteforce': {
        'name': 'SNMP Bruteforce',
        'description': 'Performs bruteforce attack against SNMP service. '
                       'Discovers valid community strings.',
        'authors': ('Marcin Bury',),
        'devices': ('Multiple devices',),
        'references': (),
        'tags': ('snmp', 'bruteforce', 'creds', 'generic', 'community'),
        'notes': 'Tests SNMP community strings. Default port 161. '
                 'Supports SNMPv1 and SNMPv2c.',
    },
    'creds/generic/http_basic_digest_bruteforce': {
        'name': 'HTTP Basic/Digest Bruteforce',
        'description': 'Performs bruteforce against HTTP Basic/Digest authentication. '
                       'Displays valid credentials when found.',
        'authors': ('Marcin Bury', 'Alexander Yakovlev'),
        'devices': ('Multiple devices',),
        'references': (),
        'tags': ('http', 'bruteforce', 'creds', 'generic', 'basic_auth', 'digest'),
        'notes': 'Targets HTTP authentication. Configure path to the protected URL.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # SCANNERS
    # ════════════════════════════════════════════════════════════════════════

    'scanners/autopwn': {
        'name': 'AutoPwn',
        'description': 'Comprehensive scanner that tests ALL exploit and credential '
                       'modules against a target. The ultimate "scan everything" tool.',
        'authors': ('Marcin Bury',),
        'devices': ('Multi',),
        'references': (),
        'tags': ('scanner', 'autopwn', 'comprehensive', 'all'),
        'notes': 'Runs all exploits and creds against the target. '
                 'Can be filtered by vendor. Checks HTTP, FTP, SSH, Telnet, SNMP. '
                 'Very thorough but slow. Use specific scanners for faster results.',
    },
    'scanners/routers/router_scan': {
        'name': 'Router Scanner',
        'description': 'Scans for router vulnerabilities and weaknesses. '
                       'Tests generic and router-specific exploit modules.',
        'authors': ('Marcin Bury',),
        'devices': ('Router',),
        'references': (),
        'tags': ('scanner', 'router', 'comprehensive'),
        'notes': 'Faster than AutoPwn -- only tests router-relevant modules.',
    },
    'scanners/cameras/camera_scan': {
        'name': 'Camera Scanner',
        'description': 'Scans for IP camera vulnerabilities and weaknesses. '
                       'Tests generic and camera-specific exploit modules.',
        'authors': ('Marcin Bury',),
        'devices': ('Cameras',),
        'references': (),
        'tags': ('scanner', 'camera', 'ip_camera', 'comprehensive'),
        'notes': 'Tests all camera-related exploits against the target.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # EXPLOITS - MISC
    # ════════════════════════════════════════════════════════════════════════

    'exploits/misc/asus/b1m_projector_rce': {
        'name': 'Asus B1M Projector RCE',
        'description': 'Exploits Asus B1M Projector RCE allowing root-level '
                       'command execution.',
        'authors': ('Hacker House', 'Marcin Bury'),
        'devices': ('Asus B1M Projector',),
        'references': ('https://www.myhackerhouse.com/asus-b1m-projector-remote-root-0day/',),
        'tags': ('asus', 'projector', 'rce', 'misc', 'iot'),
        'notes': 'Targets network-connected projectors.',
    },

    # ════════════════════════════════════════════════════════════════════════
    # EXPLOITS - MORE ROUTERS
    # ════════════════════════════════════════════════════════════════════════

    'exploits/routers/linksys/smart_wifi_password_disclosure': {
        'name': 'Linksys Smart WiFi Password Disclosure',
        'description': 'Exploits information disclosure in Linksys Smart WiFi '
                       'routers to extract passwords.',
        'authors': ('Marcin Bury',),
        'devices': ('Linksys Smart WiFi routers',),
        'references': (),
        'tags': ('linksys', 'password', 'disclosure', 'router', 'http'),
        'notes': 'Targets Linksys Smart WiFi web interface.',
    },
    'exploits/routers/zyxel/d1000_rce': {
        'name': 'Zyxel D1000 RCE',
        'description': 'Exploits remote code execution in Zyxel D1000 modem/routers.',
        'authors': ('Marcin Bury',),
        'devices': ('Zyxel D1000',),
        'references': (),
        'tags': ('zyxel', 'rce', 'router', 'modem'),
        'notes': 'Targets Zyxel DSL modem/router combo devices.',
    },
    'exploits/routers/huawei/hg520_info_disclosure': {
        'name': 'Huawei HG520 Info Disclosure',
        'description': 'Information disclosure in Huawei HG520 home gateway '
                       'allowing extraction of device configuration.',
        'authors': ('Marcin Bury',),
        'devices': ('Huawei HG520',),
        'references': (),
        'tags': ('huawei', 'info_disclosure', 'router', 'http'),
        'notes': 'Targets Huawei home gateway web interface.',
    },
}


# ─── Module Type Mapping ────────────────────────────────────────────────────

MODULE_TYPES = {
    'exploits': {
        'name': 'Exploits',
        'description': 'Vulnerability exploits for routers, cameras, and devices',
        'color': Colors.RED,
    },
    'creds': {
        'name': 'Credentials',
        'description': 'Default credential and brute-force modules',
        'color': Colors.YELLOW,
    },
    'scanners': {
        'name': 'Scanners',
        'description': 'Automated vulnerability scanners (AutoPwn, etc.)',
        'color': Colors.CYAN,
    },
    'payloads': {
        'name': 'Payloads',
        'description': 'Shellcode and payload generators',
        'color': Colors.MAGENTA,
    },
    'encoders': {
        'name': 'Encoders',
        'description': 'Payload encoding and obfuscation',
        'color': Colors.GREEN,
    },
}


# ─── API Functions ──────────────────────────────────────────────────────────

def get_module_info(module_path: str) -> dict:
    """Get curated module info by path.

    Args:
        module_path: Module path like 'exploits/routers/dlink/dir_300_600_rce'

    Returns:
        Module info dict or None
    """
    return RSF_MODULES.get(module_path)


def get_module_description(module_path: str) -> str:
    """Get just the description for a module.

    Args:
        module_path: Module path

    Returns:
        Description string or empty string
    """
    info = RSF_MODULES.get(module_path)
    if info:
        return info.get('description', '')
    return ''


def search_modules(query: str) -> list:
    """Search curated modules by keyword.

    Searches name, description, tags, devices, and path.

    Args:
        query: Search string (case-insensitive)

    Returns:
        List of matching module info dicts (with 'path' key added)
    """
    results = []
    query_lower = query.lower()

    for path, info in RSF_MODULES.items():
        # Search in path
        if query_lower in path.lower():
            results.append({**info, 'path': path})
            continue

        # Search in name
        if query_lower in info.get('name', '').lower():
            results.append({**info, 'path': path})
            continue

        # Search in description
        if query_lower in info.get('description', '').lower():
            results.append({**info, 'path': path})
            continue

        # Search in tags
        if any(query_lower in tag.lower() for tag in info.get('tags', ())):
            results.append({**info, 'path': path})
            continue

        # Search in devices
        if any(query_lower in dev.lower() for dev in info.get('devices', ())):
            results.append({**info, 'path': path})
            continue

    return results


def get_modules_by_type(module_type: str) -> list:
    """Get curated modules filtered by type.

    Args:
        module_type: One of 'exploits', 'creds', 'scanners', etc.

    Returns:
        List of matching module info dicts (with 'path' key added)
    """
    results = []
    for path, info in RSF_MODULES.items():
        if path.startswith(module_type + '/'):
            results.append({**info, 'path': path})
    return results


def format_module_help(module_path: str) -> str:
    """Format detailed help text for a module.

    Args:
        module_path: Module path

    Returns:
        Formatted help string
    """
    info = RSF_MODULES.get(module_path)
    if not info:
        return f"  {Colors.YELLOW}No curated info for '{module_path}'{Colors.RESET}"

    lines = []
    lines.append(f"  {Colors.BOLD}{Colors.WHITE}{info.get('name', module_path)}{Colors.RESET}")
    lines.append(f"  {Colors.DIM}Path: {module_path}{Colors.RESET}")
    lines.append(f"")
    lines.append(f"  {info.get('description', '')}")

    if info.get('authors'):
        authors = ', '.join(info['authors'])
        lines.append(f"")
        lines.append(f"  {Colors.CYAN}Authors:{Colors.RESET} {authors}")

    if info.get('devices'):
        lines.append(f"  {Colors.CYAN}Devices:{Colors.RESET}")
        for dev in info['devices']:
            lines.append(f"    - {dev}")

    if info.get('references'):
        lines.append(f"  {Colors.CYAN}References:{Colors.RESET}")
        for ref in info['references']:
            lines.append(f"    {Colors.DIM}{ref}{Colors.RESET}")

    if info.get('notes'):
        lines.append(f"")
        lines.append(f"  {Colors.YELLOW}Note:{Colors.RESET} {info['notes']}")

    return '\n'.join(lines)


def get_all_modules() -> dict:
    """Get all curated modules.

    Returns:
        The full RSF_MODULES dict
    """
    return RSF_MODULES


def get_type_info(module_type: str) -> dict:
    """Get info about a module type.

    Args:
        module_type: One of 'exploits', 'creds', 'scanners', etc.

    Returns:
        Type info dict or None
    """
    return MODULE_TYPES.get(module_type)
