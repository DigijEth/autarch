"""
AUTARCH Metasploit Module Library
Descriptions and metadata for common Metasploit modules.

Provides user-friendly descriptions, common options, and usage guidance
for frequently used MSF modules without needing to query MSF itself.

Usage:
    from core.msf_modules import get_module_info, search_modules, get_modules_by_category

    info = get_module_info('auxiliary/scanner/smb/smb_version')
    print(info['description'])

    results = search_modules('eternalblue')
    for mod in results:
        print(mod['path'], mod['name'])
"""

from typing import Dict, Optional, List, Any


# =============================================================================
# MODULE LIBRARY
# =============================================================================
# Each module entry contains:
#   - name: Human-readable name
#   - description: What the module does (user-friendly)
#   - author: Module author(s)
#   - cve: CVE identifier(s) if applicable
#   - platforms: Target platforms (windows, linux, unix, multi, etc.)
#   - arch: Target architectures (x86, x64, etc.)
#   - reliability: excellent, great, good, normal, average, low
#   - options: List of key options with brief descriptions
#   - tags: Keywords for searching
#   - notes: Usage tips and warnings

MSF_MODULES = {
    # =========================================================================
    # SCANNERS - SMB
    # =========================================================================
    'auxiliary/scanner/smb/smb_version': {
        'name': 'SMB Version Scanner',
        'description': 'Scans for SMB servers and identifies the operating system, SMB version, '
                      'and other details. Essential first step for Windows network enumeration. '
                      'Identifies Windows version, domain membership, and SMB signing status.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads (default: 1)'},
        ],
        'tags': ['smb', 'scanner', 'enumeration', 'windows', 'version', 'fingerprint'],
        'notes': 'Safe to run - passive fingerprinting. Run this first on Windows networks.',
    },
    'auxiliary/scanner/smb/smb_enumshares': {
        'name': 'SMB Share Enumeration',
        'description': 'Enumerates SMB shares on target systems. Lists available shares, '
                      'their types (disk, printer, IPC), and access permissions. Can identify '
                      'readable/writable shares for further exploitation.',
        'author': ['hdm', 'tebo'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'SMBUser', 'required': False, 'desc': 'Username for authentication'},
            {'name': 'SMBPass', 'required': False, 'desc': 'Password for authentication'},
            {'name': 'SMBDomain', 'required': False, 'desc': 'Domain for authentication'},
        ],
        'tags': ['smb', 'scanner', 'enumeration', 'shares', 'windows'],
        'notes': 'Try with null session first (no creds), then with valid credentials for more results.',
    },
    'auxiliary/scanner/smb/smb_enumusers': {
        'name': 'SMB User Enumeration',
        'description': 'Enumerates users on Windows systems via SMB. Uses various techniques '
                      'including SAM enumeration and LSA queries. Useful for building username '
                      'lists for password attacks.',
        'author': ['hdm', 'tebo'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'great',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'SMBUser', 'required': False, 'desc': 'Username for authentication'},
            {'name': 'SMBPass', 'required': False, 'desc': 'Password for authentication'},
        ],
        'tags': ['smb', 'scanner', 'enumeration', 'users', 'windows', 'credentials'],
        'notes': 'May require authentication on modern Windows. Works well on older systems.',
    },
    'auxiliary/scanner/smb/smb_ms17_010': {
        'name': 'MS17-010 SMB Vulnerability Scanner',
        'description': 'Checks if target systems are vulnerable to MS17-010 (EternalBlue). '
                      'This vulnerability affects SMBv1 and allows remote code execution. '
                      'Does NOT exploit - only checks for vulnerability.',
        'author': ['zerosum0x0', 'Luke Jennings'],
        'cve': ['CVE-2017-0143', 'CVE-2017-0144', 'CVE-2017-0145'],
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['smb', 'scanner', 'ms17-010', 'eternalblue', 'vulnerability', 'windows'],
        'notes': 'Safe scanner - does not crash systems. Check before using EternalBlue exploit.',
    },
    'auxiliary/scanner/smb/smb_login': {
        'name': 'SMB Login Scanner',
        'description': 'Brute force SMB login credentials. Tests username/password combinations '
                      'against SMB authentication. Supports password lists, blank passwords, '
                      'and pass-the-hash attacks.',
        'author': ['tebo'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'SMBUser', 'required': False, 'desc': 'Username or USER_FILE'},
            {'name': 'SMBPass', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'SMBDomain', 'required': False, 'desc': 'Domain name'},
            {'name': 'BLANK_PASSWORDS', 'required': False, 'desc': 'Try blank passwords'},
            {'name': 'USER_AS_PASS', 'required': False, 'desc': 'Try username as password'},
        ],
        'tags': ['smb', 'scanner', 'brute', 'login', 'credentials', 'windows'],
        'notes': 'Be careful of account lockout policies. Start with small wordlists.',
    },

    # =========================================================================
    # SCANNERS - SSH
    # =========================================================================
    'auxiliary/scanner/ssh/ssh_version': {
        'name': 'SSH Version Scanner',
        'description': 'Identifies SSH server version and implementation. Reveals OpenSSH version, '
                      'OS hints, and supported authentication methods. Useful for identifying '
                      'outdated or vulnerable SSH servers.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'SSH port (default: 22)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['ssh', 'scanner', 'version', 'enumeration', 'linux', 'unix'],
        'notes': 'Safe passive scan. Version info can reveal vulnerable configurations.',
    },
    'auxiliary/scanner/ssh/ssh_login': {
        'name': 'SSH Login Scanner',
        'description': 'Brute force SSH login credentials. Tests username/password combinations '
                      'and SSH keys. Supports credential files, blank passwords, and key-based '
                      'authentication.',
        'author': ['todb'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'SSH port (default: 22)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Username or USER_FILE'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'BLANK_PASSWORDS', 'required': False, 'desc': 'Try blank passwords'},
            {'name': 'USER_AS_PASS', 'required': False, 'desc': 'Try username as password'},
        ],
        'tags': ['ssh', 'scanner', 'brute', 'login', 'credentials', 'linux'],
        'notes': 'SSH often has fail2ban - use slow speed. Creates shell session on success.',
    },
    'auxiliary/scanner/ssh/ssh_enumusers': {
        'name': 'SSH User Enumeration',
        'description': 'Enumerates valid usernames on SSH servers using timing attacks or '
                      'response differences. Works on older OpenSSH versions with user '
                      'enumeration vulnerabilities.',
        'author': ['kenkeiras', 'Nixawk'],
        'cve': ['CVE-2018-15473'],
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'good',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'SSH port (default: 22)'},
            {'name': 'USER_FILE', 'required': True, 'desc': 'File with usernames to test'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['ssh', 'scanner', 'enumeration', 'users', 'cve-2018-15473'],
        'notes': 'Only works on vulnerable OpenSSH versions (< 7.7). Patched on most modern systems.',
    },

    # =========================================================================
    # SCANNERS - HTTP/WEB
    # =========================================================================
    'auxiliary/scanner/http/http_version': {
        'name': 'HTTP Version Scanner',
        'description': 'Identifies web server software and version. Reveals server type '
                      '(Apache, Nginx, IIS), version numbers, and sometimes OS information. '
                      'Essential for web application testing.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port (default: 80)'},
            {'name': 'SSL', 'required': False, 'desc': 'Use HTTPS'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['http', 'scanner', 'web', 'version', 'enumeration'],
        'notes': 'Safe scan. Servers may hide version info. Check for X-Powered-By headers.',
    },
    'auxiliary/scanner/http/title': {
        'name': 'HTTP Title Scanner',
        'description': 'Retrieves the HTML title from web pages. Useful for quickly identifying '
                      'web applications, login pages, and default installations across many hosts.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port (default: 80)'},
            {'name': 'TARGETURI', 'required': False, 'desc': 'URI path (default: /)'},
            {'name': 'SSL', 'required': False, 'desc': 'Use HTTPS'},
        ],
        'tags': ['http', 'scanner', 'web', 'enumeration', 'title'],
        'notes': 'Quick way to identify web apps. Default titles reveal app type.',
    },
    'auxiliary/scanner/http/dir_scanner': {
        'name': 'HTTP Directory Scanner',
        'description': 'Brute forces common directories and files on web servers. Finds hidden '
                      'admin panels, backup files, configuration files, and sensitive paths.',
        'author': ['et'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port (default: 80)'},
            {'name': 'PATH', 'required': False, 'desc': 'Starting path'},
            {'name': 'DICTIONARY', 'required': False, 'desc': 'Wordlist file'},
            {'name': 'SSL', 'required': False, 'desc': 'Use HTTPS'},
        ],
        'tags': ['http', 'scanner', 'web', 'directory', 'brute', 'enumeration'],
        'notes': 'Use good wordlists (dirbuster, dirb). May trigger WAF alerts.',
    },
    'auxiliary/scanner/http/wordpress_scanner': {
        'name': 'WordPress Scanner',
        'description': 'Scans WordPress installations for version, themes, plugins, and '
                      'vulnerabilities. Identifies installed plugins which are common attack vectors.',
        'author': ['Christian Mehlmauer'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'great',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s)'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port'},
            {'name': 'TARGETURI', 'required': False, 'desc': 'WordPress path (default: /)'},
            {'name': 'SSL', 'required': False, 'desc': 'Use HTTPS'},
        ],
        'tags': ['http', 'scanner', 'web', 'wordpress', 'cms', 'enumeration'],
        'notes': 'Check wp-content/plugins/ and wp-content/themes/ for version info.',
    },

    # =========================================================================
    # SCANNERS - PORTS/SERVICES
    # =========================================================================
    'auxiliary/scanner/portscan/tcp': {
        'name': 'TCP Port Scanner',
        'description': 'Fast TCP port scanner using connect() method. Identifies open ports '
                      'on target systems. Supports port ranges and concurrent scanning.',
        'author': ['hdm', 'kris katterjohn'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'PORTS', 'required': True, 'desc': 'Ports to scan (e.g., 1-1000,8080)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads (default: 1)'},
            {'name': 'TIMEOUT', 'required': False, 'desc': 'Connection timeout'},
        ],
        'tags': ['scanner', 'portscan', 'tcp', 'enumeration', 'network'],
        'notes': 'Full connect scan - detected by IDS. For stealth, use SYN scan (requires raw sockets).',
    },
    'auxiliary/scanner/portscan/syn': {
        'name': 'SYN Port Scanner',
        'description': 'Stealthy TCP SYN port scanner. Sends SYN packets without completing '
                      'the handshake, making it harder to detect. Requires raw socket access (root).',
        'author': ['hdm', 'kris katterjohn'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'PORTS', 'required': True, 'desc': 'Ports to scan'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
            {'name': 'TIMEOUT', 'required': False, 'desc': 'Packet timeout'},
        ],
        'tags': ['scanner', 'portscan', 'syn', 'stealth', 'network'],
        'notes': 'Requires root/admin. Stealthier than connect scan. May miss some ports behind NAT.',
    },

    # =========================================================================
    # SCANNERS - FTP
    # =========================================================================
    'auxiliary/scanner/ftp/ftp_version': {
        'name': 'FTP Version Scanner',
        'description': 'Identifies FTP server software and version from banner. Reveals '
                      'server type (vsftpd, ProFTPD, Pure-FTPd, IIS FTP) and version numbers.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'FTP port (default: 21)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['ftp', 'scanner', 'version', 'enumeration'],
        'notes': 'Check banner for known vulnerable versions (vsftpd 2.3.4 backdoor, etc.).',
    },
    'auxiliary/scanner/ftp/anonymous': {
        'name': 'FTP Anonymous Login Scanner',
        'description': 'Checks if FTP servers allow anonymous login. Anonymous FTP can expose '
                      'sensitive files and sometimes allows file uploads.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'FTP port (default: 21)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['ftp', 'scanner', 'anonymous', 'login', 'enumeration'],
        'notes': 'Check for writable directories. Anonymous upload can lead to RCE on some servers.',
    },
    'auxiliary/scanner/ftp/ftp_login': {
        'name': 'FTP Login Scanner',
        'description': 'Brute force FTP login credentials. Tests username/password combinations '
                      'against FTP authentication.',
        'author': ['todb'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'FTP port (default: 21)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Username or USER_FILE'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'BLANK_PASSWORDS', 'required': False, 'desc': 'Try blank passwords'},
        ],
        'tags': ['ftp', 'scanner', 'brute', 'login', 'credentials'],
        'notes': 'FTP sends passwords in cleartext. Creates session on successful login.',
    },

    # =========================================================================
    # SCANNERS - DATABASE
    # =========================================================================
    'auxiliary/scanner/mysql/mysql_version': {
        'name': 'MySQL Version Scanner',
        'description': 'Identifies MySQL server version and configuration. Reveals version '
                      'number, protocol version, and server capabilities.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'MySQL port (default: 3306)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['mysql', 'scanner', 'database', 'version', 'enumeration'],
        'notes': 'MySQL should not be exposed to internet. Check for known vulnerable versions.',
    },
    'auxiliary/scanner/mysql/mysql_login': {
        'name': 'MySQL Login Scanner',
        'description': 'Brute force MySQL login credentials. Tests username/password combinations '
                      'including common defaults like root with no password.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'MySQL port (default: 3306)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Username (default: root)'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'BLANK_PASSWORDS', 'required': False, 'desc': 'Try blank passwords'},
        ],
        'tags': ['mysql', 'scanner', 'database', 'brute', 'login', 'credentials'],
        'notes': 'Try root with blank password first - common misconfiguration.',
    },
    'auxiliary/scanner/mssql/mssql_ping': {
        'name': 'MSSQL Server Discovery',
        'description': 'Discovers Microsoft SQL Server instances via UDP ping. Reveals instance '
                      'names, versions, and TCP ports. Works even when TCP port scanning fails.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['mssql', 'scanner', 'database', 'discovery', 'windows'],
        'notes': 'Uses UDP 1434. Finds named instances that may be on non-standard ports.',
    },
    'auxiliary/scanner/mssql/mssql_login': {
        'name': 'MSSQL Login Scanner',
        'description': 'Brute force Microsoft SQL Server login credentials. Tests both SQL '
                      'authentication and Windows authentication modes.',
        'author': ['hdm', 'todb'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'MSSQL port (default: 1433)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Username (default: sa)'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'BLANK_PASSWORDS', 'required': False, 'desc': 'Try blank passwords'},
        ],
        'tags': ['mssql', 'scanner', 'database', 'brute', 'login', 'credentials', 'windows'],
        'notes': 'Try sa with common passwords. MSSQL can execute OS commands via xp_cmdshell.',
    },
    'auxiliary/scanner/postgres/postgres_login': {
        'name': 'PostgreSQL Login Scanner',
        'description': 'Brute force PostgreSQL login credentials. Tests username/password '
                      'combinations against PostgreSQL authentication.',
        'author': ['todb'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'PostgreSQL port (default: 5432)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Username (default: postgres)'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Password or PASS_FILE'},
            {'name': 'DATABASE', 'required': False, 'desc': 'Database to connect to'},
        ],
        'tags': ['postgres', 'postgresql', 'scanner', 'database', 'brute', 'login'],
        'notes': 'Default user is postgres. Can lead to RCE via COPY command or extensions.',
    },

    # =========================================================================
    # SCANNERS - RDP/VNC
    # =========================================================================
    'auxiliary/scanner/rdp/rdp_scanner': {
        'name': 'RDP Service Scanner',
        'description': 'Identifies systems running Remote Desktop Protocol (RDP). Detects '
                      'RDP version, NLA requirements, and encryption level.',
        'author': ['hdm', 'altonjx'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'RDP port (default: 3389)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['rdp', 'scanner', 'windows', 'remote', 'desktop'],
        'notes': 'Check for BlueKeep (CVE-2019-0708) on older Windows. NLA provides some protection.',
    },
    'auxiliary/scanner/rdp/cve_2019_0708_bluekeep': {
        'name': 'BlueKeep Vulnerability Scanner',
        'description': 'Checks for CVE-2019-0708 (BlueKeep) RDP vulnerability. This critical '
                      'vulnerability allows remote code execution without authentication. '
                      'Affects Windows 7, Server 2008, and older.',
        'author': ['JaGoTu', 'zerosum0x0', 'ryHanson'],
        'cve': ['CVE-2019-0708'],
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'RDP port (default: 3389)'},
        ],
        'tags': ['rdp', 'scanner', 'bluekeep', 'cve-2019-0708', 'vulnerability', 'windows'],
        'notes': 'Safe scanner. Does not exploit, only checks. Affects Windows 7, 2008, XP.',
    },
    'auxiliary/scanner/vnc/vnc_none_auth': {
        'name': 'VNC No Authentication Scanner',
        'description': 'Checks for VNC servers with no authentication required. Unsecured VNC '
                      'provides full graphical access to the system.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
            {'name': 'RPORT', 'required': False, 'desc': 'VNC port (default: 5900)'},
            {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
        ],
        'tags': ['vnc', 'scanner', 'authentication', 'remote', 'desktop'],
        'notes': 'No-auth VNC = full desktop access. Connect with any VNC client.',
    },

    # =========================================================================
    # EXPLOITS - SMB/WINDOWS
    # =========================================================================
    'exploit/windows/smb/ms17_010_eternalblue': {
        'name': 'EternalBlue SMB Remote Code Execution',
        'description': 'Exploits the MS17-010 SMB vulnerability (EternalBlue) for remote code '
                      'execution. Affects Windows XP through Windows Server 2008 R2. One of '
                      'the most reliable remote Windows exploits. Used by WannaCry ransomware.',
        'author': ['Equation Group', 'Shadow Brokers', 'sleepya'],
        'cve': ['CVE-2017-0144'],
        'platforms': ['windows'],
        'arch': ['x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP for callback'},
            {'name': 'LPORT', 'required': False, 'desc': 'Callback port (default: 4444)'},
            {'name': 'PAYLOAD', 'required': True, 'desc': 'Payload (recommend meterpreter)'},
        ],
        'tags': ['exploit', 'smb', 'eternalblue', 'ms17-010', 'windows', 'remote', 'cve-2017-0144'],
        'notes': 'CRITICAL: May crash unpatched systems. Test with scanner first. x64 targets only.',
    },
    'exploit/windows/smb/ms17_010_psexec': {
        'name': 'EternalBlue/Romance/Synergy Combo Exploit',
        'description': 'Uses EternalBlue, EternalRomance, and EternalSynergy to achieve code '
                      'execution. More stable than pure EternalBlue. Works on x86 and x64.',
        'author': ['sleepya', 'zerosum0x0'],
        'cve': ['CVE-2017-0143', 'CVE-2017-0144', 'CVE-2017-0145'],
        'platforms': ['windows'],
        'arch': ['x86', 'x64'],
        'reliability': 'great',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP for callback'},
            {'name': 'LPORT', 'required': False, 'desc': 'Callback port'},
            {'name': 'PAYLOAD', 'required': True, 'desc': 'Payload to deliver'},
        ],
        'tags': ['exploit', 'smb', 'eternalblue', 'eternalromance', 'ms17-010', 'windows'],
        'notes': 'More reliable than pure EternalBlue. Works on both 32 and 64-bit Windows.',
    },
    'exploit/windows/smb/psexec': {
        'name': 'PsExec Remote Command Execution',
        'description': 'Executes commands on Windows systems using valid credentials via SMB. '
                      'Uploads a service binary, creates and starts a service, then cleans up. '
                      'Requires admin credentials.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['windows'],
        'arch': ['x86', 'x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'SMBUser', 'required': True, 'desc': 'Admin username'},
            {'name': 'SMBPass', 'required': True, 'desc': 'Admin password or NTLM hash'},
            {'name': 'SMBDomain', 'required': False, 'desc': 'Domain name'},
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP for callback'},
        ],
        'tags': ['exploit', 'smb', 'psexec', 'windows', 'credentials', 'lateral'],
        'notes': 'Requires admin creds. Detected by most AV. Use for lateral movement.',
    },
    'exploit/windows/smb/ms08_067_netapi': {
        'name': 'MS08-067 Server Service Vulnerability',
        'description': 'Exploits the MS08-067 vulnerability in Windows Server Service. '
                      'Affects Windows XP and Server 2003. Very reliable, pre-authentication RCE.',
        'author': ['hdm', 'Brett Moore', 'Harmony Security'],
        'cve': ['CVE-2008-4250'],
        'platforms': ['windows'],
        'arch': ['x86'],
        'reliability': 'great',
        'options': [
            {'name': 'RHOST', 'required': True, 'desc': 'Target IP'},
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP for callback'},
            {'name': 'LPORT', 'required': False, 'desc': 'Callback port'},
        ],
        'tags': ['exploit', 'smb', 'ms08-067', 'windows', 'xp', 'legacy', 'cve-2008-4250'],
        'notes': 'Old but still found in legacy environments. XP and Server 2003 only.',
    },

    # =========================================================================
    # EXPLOITS - SSH
    # =========================================================================
    'exploit/linux/ssh/sshexec': {
        'name': 'SSH User Code Execution',
        'description': 'Executes payload on target via SSH using valid credentials. '
                      'Creates a Meterpreter or shell session through SSH authentication.',
        'author': ['Spencer McIntyre', 'Brandon Knight'],
        'cve': None,
        'platforms': ['linux', 'unix'],
        'arch': ['x86', 'x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'SSH port (default: 22)'},
            {'name': 'USERNAME', 'required': True, 'desc': 'SSH username'},
            {'name': 'PASSWORD', 'required': True, 'desc': 'SSH password'},
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP for callback'},
        ],
        'tags': ['exploit', 'ssh', 'linux', 'credentials', 'remote'],
        'notes': 'Requires valid SSH creds. Use after successful ssh_login scan.',
    },

    # =========================================================================
    # EXPLOITS - WEB/HTTP
    # =========================================================================
    'exploit/multi/http/tomcat_mgr_upload': {
        'name': 'Apache Tomcat Manager Upload',
        'description': 'Uploads and executes a WAR file through Tomcat Manager. Requires '
                      'manager credentials. Very common in enterprise environments.',
        'author': ['rangercha'],
        'cve': None,
        'platforms': ['multi'],
        'arch': ['java'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port (default: 80)'},
            {'name': 'HttpUsername', 'required': True, 'desc': 'Tomcat manager username'},
            {'name': 'HttpPassword', 'required': True, 'desc': 'Tomcat manager password'},
            {'name': 'TARGETURI', 'required': False, 'desc': 'Manager path'},
        ],
        'tags': ['exploit', 'http', 'tomcat', 'java', 'web', 'upload'],
        'notes': 'Default creds: tomcat/tomcat, admin/admin, manager/manager. Check tomcat-users.xml.',
    },
    'exploit/multi/http/jenkins_script_console': {
        'name': 'Jenkins Script Console RCE',
        'description': 'Executes Groovy script via Jenkins Script Console. Requires access '
                      'to the /script endpoint (usually needs authentication or misconfiguration).',
        'author': ['Spencer McIntyre', 'altonjx'],
        'cve': None,
        'platforms': ['multi'],
        'arch': ['java'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port (default: 8080)'},
            {'name': 'USERNAME', 'required': False, 'desc': 'Jenkins username'},
            {'name': 'PASSWORD', 'required': False, 'desc': 'Jenkins password'},
            {'name': 'TARGETURI', 'required': False, 'desc': 'Jenkins path'},
        ],
        'tags': ['exploit', 'http', 'jenkins', 'java', 'web', 'rce'],
        'notes': 'Check for unauthenticated /script access. Also check for default creds.',
    },
    'exploit/unix/webapp/php_cgi_arg_injection': {
        'name': 'PHP CGI Argument Injection',
        'description': 'Exploits PHP-CGI argument injection (CVE-2012-1823). Allows remote '
                      'code execution by passing PHP configuration options via query string.',
        'author': ['hdm'],
        'cve': ['CVE-2012-1823'],
        'platforms': ['unix', 'linux'],
        'arch': ['cmd'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'HTTP port'},
            {'name': 'TARGETURI', 'required': False, 'desc': 'PHP file path'},
        ],
        'tags': ['exploit', 'http', 'php', 'cgi', 'web', 'rce', 'cve-2012-1823'],
        'notes': 'Old but still found. Test with ?-s to see PHP source leak.',
    },

    # =========================================================================
    # EXPLOITS - FTP
    # =========================================================================
    'exploit/unix/ftp/vsftpd_234_backdoor': {
        'name': 'VSFTPD 2.3.4 Backdoor',
        'description': 'Exploits a backdoor in vsftpd 2.3.4. Sending a smiley :) in the '
                      'username opens a shell on port 6200. One of the easiest exploits.',
        'author': ['hdm', 'mc'],
        'cve': ['CVE-2011-2523'],
        'platforms': ['unix'],
        'arch': ['cmd'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOST', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'FTP port (default: 21)'},
        ],
        'tags': ['exploit', 'ftp', 'vsftpd', 'backdoor', 'unix', 'linux'],
        'notes': 'Very easy exploit - just run it. Opens shell on port 6200.',
    },
    'exploit/unix/ftp/proftpd_133c_backdoor': {
        'name': 'ProFTPD 1.3.3c Backdoor',
        'description': 'Exploits a backdoor in ProFTPD 1.3.3c. Sends HELP ACIDBITCHEZ command '
                      'to trigger the backdoor and open a root shell.',
        'author': ['hdm', 'mc'],
        'cve': None,
        'platforms': ['unix'],
        'arch': ['cmd'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOST', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'FTP port (default: 21)'},
        ],
        'tags': ['exploit', 'ftp', 'proftpd', 'backdoor', 'unix', 'linux'],
        'notes': 'Opens root shell directly. Check FTP banner for version.',
    },

    # =========================================================================
    # EXPLOITS - DATABASE
    # =========================================================================
    'exploit/multi/mysql/mysql_udf_payload': {
        'name': 'MySQL UDF Remote Code Execution',
        'description': 'Creates a User Defined Function (UDF) in MySQL to execute system '
                      'commands. Requires FILE privilege and ability to write to plugin directory.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': ['x86', 'x64'],
        'reliability': 'great',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'MySQL port (default: 3306)'},
            {'name': 'USERNAME', 'required': True, 'desc': 'MySQL username'},
            {'name': 'PASSWORD', 'required': True, 'desc': 'MySQL password'},
        ],
        'tags': ['exploit', 'mysql', 'database', 'udf', 'rce'],
        'notes': 'Requires FILE privilege. Check with SHOW GRANTS. May need writable plugin dir.',
    },
    'exploit/windows/mssql/mssql_payload': {
        'name': 'MSSQL xp_cmdshell Payload Execution',
        'description': 'Executes payload via MSSQL xp_cmdshell. Enables xp_cmdshell if disabled '
                      'and executes system commands. Requires sysadmin privileges.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['windows'],
        'arch': ['x86', 'x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP'},
            {'name': 'RPORT', 'required': False, 'desc': 'MSSQL port (default: 1433)'},
            {'name': 'USERNAME', 'required': True, 'desc': 'MSSQL username (sa)'},
            {'name': 'PASSWORD', 'required': True, 'desc': 'MSSQL password'},
        ],
        'tags': ['exploit', 'mssql', 'database', 'xp_cmdshell', 'windows', 'rce'],
        'notes': 'Usually runs as SYSTEM. Use sa account. May need to enable xp_cmdshell first.',
    },

    # =========================================================================
    # POST-EXPLOITATION
    # =========================================================================
    'post/windows/gather/hashdump': {
        'name': 'Windows Password Hash Dump',
        'description': 'Dumps password hashes from the SAM database. Requires SYSTEM privileges '
                      'or the ability to read SAM. Hashes can be cracked or used for pass-the-hash.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'SESSION', 'required': True, 'desc': 'Meterpreter session ID'},
        ],
        'tags': ['post', 'windows', 'credentials', 'hashdump', 'sam', 'hashes'],
        'notes': 'Requires SYSTEM. Use getsystem or run as SYSTEM service. Hashes in LM:NT format.',
    },
    'post/multi/recon/local_exploit_suggester': {
        'name': 'Local Exploit Suggester',
        'description': 'Suggests local privilege escalation exploits based on the target system. '
                      'Checks patch level and configuration to recommend applicable exploits.',
        'author': ['sinn3r', 'Shelby Pace'],
        'cve': None,
        'platforms': ['windows', 'linux'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'SESSION', 'required': True, 'desc': 'Session ID'},
            {'name': 'SHOWDESCRIPTION', 'required': False, 'desc': 'Show exploit descriptions'},
        ],
        'tags': ['post', 'recon', 'privesc', 'suggester', 'local', 'escalation'],
        'notes': 'Run this first after getting a shell. Checks for missing patches.',
    },
    'post/windows/manage/migrate': {
        'name': 'Meterpreter Process Migration',
        'description': 'Migrates Meterpreter to another process. Improves stability and '
                      'can help bypass AV. Common targets: explorer.exe, svchost.exe.',
        'author': ['hdm', 'egypt'],
        'cve': None,
        'platforms': ['windows'],
        'arch': None,
        'reliability': 'great',
        'options': [
            {'name': 'SESSION', 'required': True, 'desc': 'Meterpreter session ID'},
            {'name': 'PID', 'required': False, 'desc': 'Target process ID'},
            {'name': 'NAME', 'required': False, 'desc': 'Target process name'},
        ],
        'tags': ['post', 'windows', 'migrate', 'process', 'stability'],
        'notes': 'Migrate to stable process quickly. If current process dies, session dies.',
    },
    'post/multi/manage/autoroute': {
        'name': 'Auto Route Setup',
        'description': 'Adds routes through a Meterpreter session for pivoting. Allows '
                      'scanning and exploiting systems on networks accessible to the compromised host.',
        'author': ['egypt', 'hdm'],
        'cve': None,
        'platforms': ['multi'],
        'arch': None,
        'reliability': 'excellent',
        'options': [
            {'name': 'SESSION', 'required': True, 'desc': 'Session ID'},
            {'name': 'SUBNET', 'required': False, 'desc': 'Subnet to route (auto-detected)'},
        ],
        'tags': ['post', 'pivot', 'route', 'network', 'lateral'],
        'notes': 'Essential for pivoting. Auto-detects subnets from session network config.',
    },

    # =========================================================================
    # PAYLOADS (Reference Only)
    # =========================================================================
    'payload/windows/meterpreter/reverse_tcp': {
        'name': 'Windows Meterpreter Reverse TCP',
        'description': 'Advanced payload that connects back to your machine. Provides file '
                      'system access, process manipulation, pivoting, screenshot, keylogging, '
                      'and more. The most capable Windows payload.',
        'author': ['hdm', 'skape'],
        'cve': None,
        'platforms': ['windows'],
        'arch': ['x86'],
        'reliability': 'excellent',
        'options': [
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP address'},
            {'name': 'LPORT', 'required': True, 'desc': 'Your listening port'},
        ],
        'tags': ['payload', 'windows', 'meterpreter', 'reverse', 'tcp'],
        'notes': 'Requires outbound TCP from target. Most feature-rich payload.',
    },
    'payload/windows/x64/meterpreter/reverse_tcp': {
        'name': 'Windows x64 Meterpreter Reverse TCP',
        'description': '64-bit Meterpreter for Windows x64 systems. Same capabilities as x86 '
                      'version but for 64-bit targets. Required for modern Windows.',
        'author': ['hdm', 'skape', 'sf'],
        'cve': None,
        'platforms': ['windows'],
        'arch': ['x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP address'},
            {'name': 'LPORT', 'required': True, 'desc': 'Your listening port'},
        ],
        'tags': ['payload', 'windows', 'meterpreter', 'reverse', 'tcp', 'x64'],
        'notes': 'Use for 64-bit Windows. Most modern Windows systems are x64.',
    },
    'payload/linux/x64/meterpreter/reverse_tcp': {
        'name': 'Linux x64 Meterpreter Reverse TCP',
        'description': 'Linux Meterpreter providing advanced post-exploitation capabilities. '
                      'File access, process control, and pivoting on Linux targets.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['linux'],
        'arch': ['x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP address'},
            {'name': 'LPORT', 'required': True, 'desc': 'Your listening port'},
        ],
        'tags': ['payload', 'linux', 'meterpreter', 'reverse', 'tcp', 'x64'],
        'notes': 'Full meterpreter features on Linux. Use for advanced post-exploitation.',
    },
    'payload/linux/x64/shell_reverse_tcp': {
        'name': 'Linux x64 Shell Reverse TCP',
        'description': 'Simple reverse shell for Linux. Connects back and provides /bin/sh. '
                      'Smaller and more reliable than Meterpreter when simplicity is needed.',
        'author': ['hdm'],
        'cve': None,
        'platforms': ['linux'],
        'arch': ['x64'],
        'reliability': 'excellent',
        'options': [
            {'name': 'LHOST', 'required': True, 'desc': 'Your IP address'},
            {'name': 'LPORT', 'required': True, 'desc': 'Your listening port'},
        ],
        'tags': ['payload', 'linux', 'shell', 'reverse', 'tcp', 'x64'],
        'notes': 'Simple shell - use when Meterpreter fails or is detected.',
    },
}


# =============================================================================
# MODULE CATEGORIES
# =============================================================================

MODULE_CATEGORIES = {
    'scanner': {
        'name': 'Scanners',
        'description': 'Modules that scan for information or vulnerabilities',
        'subcategories': ['smb', 'ssh', 'http', 'ftp', 'mysql', 'mssql', 'postgres', 'rdp', 'vnc', 'portscan'],
    },
    'exploit': {
        'name': 'Exploits',
        'description': 'Modules that exploit vulnerabilities to gain access',
        'subcategories': ['windows', 'linux', 'unix', 'multi', 'web'],
    },
    'post': {
        'name': 'Post-Exploitation',
        'description': 'Modules for actions after gaining access',
        'subcategories': ['gather', 'manage', 'recon', 'escalate'],
    },
    'payload': {
        'name': 'Payloads',
        'description': 'Payloads delivered by exploits',
        'subcategories': ['meterpreter', 'shell', 'reverse', 'bind'],
    },
    'auxiliary': {
        'name': 'Auxiliary',
        'description': 'Supporting modules (scanners, fuzzers, etc.)',
        'subcategories': ['scanner', 'admin', 'gather', 'fuzz'],
    },
}


# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_module_info(module_path: str) -> Optional[Dict[str, Any]]:
    """Get information about a module.

    Args:
        module_path: Full module path (e.g., 'auxiliary/scanner/smb/smb_version').

    Returns:
        Dictionary with module info, or None if not found.
    """
    return MSF_MODULES.get(module_path)


def get_module_description(module_path: str) -> str:
    """Get just the description for a module.

    Args:
        module_path: Module path.

    Returns:
        Description string, or 'Unknown module' if not found.
    """
    info = get_module_info(module_path)
    if info:
        return info['description']
    return f"No description available for: {module_path}"


def search_modules(query: str, max_results: int = 50) -> List[Dict[str, Any]]:
    """Search modules by keyword.

    Args:
        query: Search query (searches name, description, tags).
        max_results: Maximum results to return.

    Returns:
        List of matching modules with path and info.
    """
    query_lower = query.lower()
    results = []

    for path, info in MSF_MODULES.items():
        score = 0

        # Check path
        if query_lower in path.lower():
            score += 10

        # Check name
        if query_lower in info.get('name', '').lower():
            score += 8

        # Check tags
        for tag in info.get('tags', []):
            if query_lower in tag.lower():
                score += 5

        # Check description
        if query_lower in info.get('description', '').lower():
            score += 3

        # Check CVE
        for cve in (info.get('cve') or []):
            if query_lower in cve.lower():
                score += 10

        if score > 0:
            results.append({
                'path': path,
                'score': score,
                **info
            })

    # Sort by score descending
    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:max_results]


def get_modules_by_type(module_type: str) -> List[Dict[str, Any]]:
    """Get all modules of a specific type.

    Args:
        module_type: Module type prefix (exploit, auxiliary, post, payload).

    Returns:
        List of modules matching the type.
    """
    results = []
    prefix = module_type.lower().rstrip('/')

    for path, info in MSF_MODULES.items():
        if path.startswith(prefix):
            results.append({
                'path': path,
                **info
            })

    return results


def get_modules_by_tag(tag: str) -> List[Dict[str, Any]]:
    """Get all modules with a specific tag.

    Args:
        tag: Tag to search for.

    Returns:
        List of modules with that tag.
    """
    tag_lower = tag.lower()
    results = []

    for path, info in MSF_MODULES.items():
        if tag_lower in [t.lower() for t in info.get('tags', [])]:
            results.append({
                'path': path,
                **info
            })

    return results


def get_modules_by_platform(platform: str) -> List[Dict[str, Any]]:
    """Get all modules for a specific platform.

    Args:
        platform: Platform (windows, linux, unix, multi).

    Returns:
        List of modules for that platform.
    """
    platform_lower = platform.lower()
    results = []

    for path, info in MSF_MODULES.items():
        platforms = info.get('platforms', [])
        if platform_lower in [p.lower() for p in platforms]:
            results.append({
                'path': path,
                **info
            })

    return results


def get_module_options(module_path: str) -> List[Dict[str, Any]]:
    """Get the common options for a module.

    Args:
        module_path: Module path.

    Returns:
        List of option dictionaries.
    """
    info = get_module_info(module_path)
    if info:
        return info.get('options', [])
    return []


def format_module_help(module_path: str) -> str:
    """Get formatted help text for a module.

    Args:
        module_path: Module path.

    Returns:
        Formatted help string.
    """
    info = get_module_info(module_path)

    if not info:
        return f"No information available for: {module_path}"

    lines = [
        f"Module: {module_path}",
        f"Name: {info.get('name', 'Unknown')}",
        "",
        info.get('description', 'No description'),
        "",
    ]

    if info.get('cve'):
        lines.append(f"CVE: {', '.join(info['cve'])}")

    if info.get('platforms'):
        lines.append(f"Platforms: {', '.join(info['platforms'])}")

    if info.get('reliability'):
        lines.append(f"Reliability: {info['reliability']}")

    if info.get('options'):
        lines.append("")
        lines.append("Common Options:")
        for opt in info['options']:
            req = "(required)" if opt.get('required') else ""
            lines.append(f"  {opt['name']:15} - {opt.get('desc', '')} {req}")

    if info.get('notes'):
        lines.append("")
        lines.append(f"Notes: {info['notes']}")

    return '\n'.join(lines)


def list_all_modules() -> List[str]:
    """Get list of all module paths in the library.

    Returns:
        List of module paths.
    """
    return list(MSF_MODULES.keys())


def get_module_count() -> Dict[str, int]:
    """Get count of modules by type.

    Returns:
        Dictionary of type -> count.
    """
    counts = {'exploit': 0, 'auxiliary': 0, 'post': 0, 'payload': 0}

    for path in MSF_MODULES.keys():
        for mtype in counts.keys():
            if path.startswith(mtype):
                counts[mtype] += 1
                break

    counts['total'] = len(MSF_MODULES)
    return counts


# =============================================================================
# QUICK REFERENCE
# =============================================================================

def print_module_summary():
    """Print a summary of modules in the library."""
    counts = get_module_count()

    print("MSF Module Library Summary")
    print("=" * 50)
    print(f"Total modules: {counts['total']}")
    print(f"  Exploits: {counts['exploit']}")
    print(f"  Auxiliary/Scanners: {counts['auxiliary']}")
    print(f"  Post-exploitation: {counts['post']}")
    print(f"  Payloads: {counts['payload']}")


if __name__ == "__main__":
    print_module_summary()

    print("\n" + "=" * 50)
    print("Sample search for 'smb':")
    results = search_modules('smb', max_results=5)
    for r in results:
        print(f"  {r['path']}")
        print(f"    {r['name']}")

    print("\n" + "=" * 50)
    print("Sample module help:")
    print(format_module_help('exploit/windows/smb/ms17_010_eternalblue'))
