"""
AUTARCH Metasploit Term Bank
Centralized definitions for MSF options and settings.

Provides consistent explanations and prompts for all Metasploit options
so they don't need to be repeated throughout the codebase.

Usage:
    from core.msf_terms import get_setting_info, get_setting_prompt, format_setting_help

    info = get_setting_info('RHOSTS')
    print(info['description'])

    prompt = get_setting_prompt('RPORT', default=445)
    user_input = input(prompt)
"""

from typing import Dict, Optional, Any, List


# =============================================================================
# MSF SETTINGS TERM BANK
# =============================================================================
# Each setting has:
#   - description: What this option does
#   - input_type: Expected input type (ip, port, string, boolean, path, etc.)
#   - examples: Example values
#   - default: Common default value (if any)
#   - aliases: Other names that mean the same thing
#   - category: Grouping (target, connection, authentication, payload, etc.)
#   - required: Whether typically required
#   - notes: Additional tips or warnings

MSF_SETTINGS = {
    # =========================================================================
    # TARGET OPTIONS
    # =========================================================================
    'RHOSTS': {
        'description': 'The target host(s) to scan or exploit. Can be a single IP, '
                      'a hostname, a CIDR range (192.168.1.0/24), or a range '
                      '(192.168.1.1-254). Multiple targets can be separated by spaces.',
        'input_type': 'host_range',
        'examples': ['192.168.1.1', '192.168.1.0/24', '192.168.1.1-50', 'target.example.com'],
        'default': None,
        'aliases': ['RHOST', 'TARGET', 'TARGETS'],
        'category': 'target',
        'required': True,
        'notes': 'For single-target exploits, use RHOST. For scanners, RHOSTS supports ranges.',
    },
    'RHOST': {
        'description': 'The target host IP address or hostname. This is the system '
                      'you want to scan or exploit.',
        'input_type': 'host',
        'examples': ['192.168.1.1', 'target.example.com', '10.0.0.50'],
        'default': None,
        'aliases': ['RHOSTS', 'TARGET'],
        'category': 'target',
        'required': True,
        'notes': 'If you enter a hostname, it will be resolved to an IP address.',
    },
    'RPORT': {
        'description': 'The target port number on the remote host. This is the port '
                      'where the vulnerable service is running.',
        'input_type': 'port',
        'examples': ['22', '80', '443', '445', '3389'],
        'default': None,  # Varies by module
        'aliases': ['PORT', 'TARGET_PORT'],
        'category': 'target',
        'required': True,
        'notes': 'Common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 445 (SMB), 3389 (RDP).',
    },
    'TARGETURI': {
        'description': 'The URI path on the target web server. This is the path to '
                      'the vulnerable application or endpoint.',
        'input_type': 'path',
        'examples': ['/', '/admin', '/api/v1', '/wp-admin'],
        'default': '/',
        'aliases': ['URI', 'PATH'],
        'category': 'target',
        'required': False,
        'notes': 'Usually starts with /. Check the application documentation for the correct path.',
    },
    'VHOST': {
        'description': 'The virtual host (HTTP Host header) to use in requests. '
                      'Useful when multiple sites are hosted on the same IP.',
        'input_type': 'hostname',
        'examples': ['www.example.com', 'admin.target.local'],
        'default': None,
        'aliases': ['VIRTUALHOST'],
        'category': 'target',
        'required': False,
        'notes': 'Set this if the target uses virtual hosting or name-based routing.',
    },
    'DOMAIN': {
        'description': 'The Windows domain name for authentication or targeting. '
                      'Used in Active Directory environments.',
        'input_type': 'string',
        'examples': ['CORP', 'WORKGROUP', 'mydomain.local'],
        'default': 'WORKGROUP',
        'aliases': ['SMBDomain'],
        'category': 'target',
        'required': False,
        'notes': 'For workgroup machines, use WORKGROUP. For domain-joined, use the domain name.',
    },

    # =========================================================================
    # LOCAL/LISTENER OPTIONS
    # =========================================================================
    'LHOST': {
        'description': 'Your local IP address that the target will connect back to. '
                      'This is YOUR machine\'s IP, used for reverse shells and callbacks.',
        'input_type': 'ip',
        'examples': ['192.168.1.100', '10.10.14.5', 'eth0'],
        'default': None,
        'aliases': ['LOCALHOST', 'CALLBACK_HOST'],
        'category': 'local',
        'required': True,  # For reverse payloads
        'notes': 'Must be reachable from the target. Use your VPN/tun0 IP for remote targets. '
                'Can specify interface name (eth0) to auto-detect.',
    },
    'LPORT': {
        'description': 'The local port on your machine to listen for incoming connections. '
                      'The target will connect back to this port.',
        'input_type': 'port',
        'examples': ['4444', '443', '8080', '9001'],
        'default': '4444',
        'aliases': ['LOCALPORT', 'CALLBACK_PORT'],
        'category': 'local',
        'required': True,  # For reverse payloads
        'notes': 'Ports below 1024 require root. Using 443 or 80 may help bypass firewalls.',
    },
    'SRVHOST': {
        'description': 'The IP address for the local server to bind to. This is where '
                      'MSF will start a listener or HTTP server.',
        'input_type': 'ip',
        'examples': ['0.0.0.0', '192.168.1.100', '127.0.0.1'],
        'default': '0.0.0.0',
        'aliases': ['SERVER_HOST'],
        'category': 'local',
        'required': False,
        'notes': '0.0.0.0 listens on all interfaces. Use specific IP to restrict access.',
    },
    'SRVPORT': {
        'description': 'The port for the local server to listen on. Used for exploit '
                      'delivery servers, HTTP servers, etc.',
        'input_type': 'port',
        'examples': ['8080', '80', '443', '8888'],
        'default': '8080',
        'aliases': ['SERVER_PORT'],
        'category': 'local',
        'required': False,
        'notes': 'Choose a port that won\'t conflict with existing services.',
    },

    # =========================================================================
    # AUTHENTICATION OPTIONS
    # =========================================================================
    'USERNAME': {
        'description': 'The username for authentication to the target service.',
        'input_type': 'string',
        'examples': ['admin', 'root', 'administrator', 'sa'],
        'default': None,
        'aliases': ['USER', 'SMBUser', 'HttpUsername', 'FTPUser'],
        'category': 'auth',
        'required': False,
        'notes': 'Required for authenticated scans/exploits. Try common defaults if unknown.',
    },
    'PASSWORD': {
        'description': 'The password for authentication to the target service.',
        'input_type': 'password',
        'examples': ['password123', 'admin', 'P@ssw0rd'],
        'default': None,
        'aliases': ['PASS', 'SMBPass', 'HttpPassword', 'FTPPass'],
        'category': 'auth',
        'required': False,
        'notes': 'Can be blank for null password attempts. Consider using PASS_FILE for brute force.',
    },
    'USER_FILE': {
        'description': 'Path to a file containing usernames, one per line. '
                      'Used for credential brute forcing.',
        'input_type': 'file_path',
        'examples': ['/usr/share/wordlists/users.txt', '/opt/seclists/Usernames/top-usernames.txt'],
        'default': None,
        'aliases': ['USERPASS_FILE', 'USERNAME_FILE'],
        'category': 'auth',
        'required': False,
        'notes': 'For brute force attacks. Combine with PASS_FILE for credential stuffing.',
    },
    'PASS_FILE': {
        'description': 'Path to a file containing passwords, one per line. '
                      'Used for credential brute forcing.',
        'input_type': 'file_path',
        'examples': ['/usr/share/wordlists/rockyou.txt', '/opt/seclists/Passwords/common.txt'],
        'default': None,
        'aliases': ['PASSWORD_FILE'],
        'category': 'auth',
        'required': False,
        'notes': 'For brute force attacks. rockyou.txt is a common choice.',
    },
    'NTLM_HASH': {
        'description': 'The NTLM password hash for pass-the-hash (PtH) authentication. '
                      'This allows authentication without knowing the plaintext password. '
                      'Format is LM:NT (both hashes) or just the NT hash alone. The LM hash '
                      'can be set to the empty LM hash (aad3b435b51404eeaad3b435b51404ee) '
                      'if only the NT hash is available.',
        'input_type': 'hash',
        'examples': [
            'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
            '31d6cfe0d16ae931b73c59d7e0c089c0',
            'aad3b435b51404eeaad3b435b51404ee:a87f3a337d73085c45f9416be5787d86',
        ],
        'default': None,
        'aliases': ['SMB::NTLM', 'HASH', 'NTHASH'],
        'category': 'auth',
        'required': False,
        'notes': 'Obtain hashes via hashdump, mimikatz, secretsdump, or SAM extraction. '
                'PtH works on SMB, WMI, WinRM, and other Windows protocols.',
    },
    'PRIVATEKEY': {
        'description': 'Path to a private key file for SSH/SSL authentication.',
        'input_type': 'file_path',
        'examples': ['/root/.ssh/id_rsa', '/home/user/key.pem'],
        'default': None,
        'aliases': ['SSH_KEY', 'KEY_FILE'],
        'category': 'auth',
        'required': False,
        'notes': 'For SSH key-based authentication. Must be readable by MSF.',
    },

    # =========================================================================
    # PAYLOAD OPTIONS
    # =========================================================================
    'PAYLOAD': {
        'description': 'The payload to deliver to the target. Payloads determine what '
                      'happens after successful exploitation (shell, meterpreter, etc).',
        'input_type': 'module_path',
        'examples': [
            'windows/meterpreter/reverse_tcp',
            'linux/x64/shell_reverse_tcp',
            'cmd/unix/reverse_bash',
        ],
        'default': None,
        'aliases': ['P'],
        'category': 'payload',
        'required': True,  # For exploits
        'notes': 'Meterpreter provides advanced features. Shell payloads are simpler but reliable.',
    },
    'EXITFUNC': {
        'description': 'How the payload should exit after execution. Affects stability '
                      'and detection.',
        'input_type': 'enum',
        'examples': ['thread', 'process', 'seh', 'none'],
        'default': 'thread',
        'aliases': [],
        'category': 'payload',
        'required': False,
        'notes': 'thread=safest for services, process=kills app, seh=exception handler.',
    },
    'ENCODER': {
        'description': 'The encoder to use for obfuscating the payload. Helps evade '
                      'antivirus detection.',
        'input_type': 'module_path',
        'examples': ['x86/shikata_ga_nai', 'x64/xor', 'cmd/powershell_base64'],
        'default': None,
        'aliases': ['E'],
        'category': 'payload',
        'required': False,
        'notes': 'shikata_ga_nai is popular but well-detected. May need multiple iterations.',
    },
    'ITERATIONS': {
        'description': 'Number of times to encode the payload. More iterations = more obfuscation.',
        'input_type': 'integer',
        'examples': ['1', '5', '10'],
        'default': '1',
        'aliases': ['I'],
        'category': 'payload',
        'required': False,
        'notes': 'More iterations increases size. Diminishing returns after 5-10.',
    },

    # =========================================================================
    # CONNECTION OPTIONS
    # =========================================================================
    'SSL': {
        'description': 'Whether to use SSL/TLS encryption for the connection.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'false',
        'aliases': ['UseSSL', 'HTTPS'],
        'category': 'connection',
        'required': False,
        'notes': 'Enable for HTTPS targets (port 443). Disable for HTTP (port 80).',
    },
    'PROXIES': {
        'description': 'Proxy server(s) to route traffic through. Format: type:host:port.',
        'input_type': 'proxy',
        'examples': ['socks4:127.0.0.1:9050', 'http:proxy.example.com:8080'],
        'default': None,
        'aliases': ['PROXY'],
        'category': 'connection',
        'required': False,
        'notes': 'Useful for anonymity or pivoting. socks4/socks5/http supported.',
    },
    'TIMEOUT': {
        'description': 'Connection timeout in seconds. How long to wait for a response.',
        'input_type': 'integer',
        'examples': ['5', '10', '30', '60'],
        'default': '10',
        'aliases': ['ConnectTimeout', 'SOCKET_TIMEOUT'],
        'category': 'connection',
        'required': False,
        'notes': 'Increase for slow/distant targets. Decrease for faster scanning.',
    },
    'THREADS': {
        'description': 'Number of concurrent threads/connections to use. Higher = faster '
                      'but more noisy.',
        'input_type': 'integer',
        'examples': ['1', '5', '10', '50'],
        'default': '1',
        'aliases': ['CONCURRENCY'],
        'category': 'connection',
        'required': False,
        'notes': 'For scanners only. Higher threads may trigger IDS/IPS. Start low.',
    },

    # =========================================================================
    # SCAN OPTIONS
    # =========================================================================
    'PORTS': {
        'description': 'Target port(s) to scan. Can be a single port, range, or comma-separated list.',
        'input_type': 'port_range',
        'examples': ['22', '1-1000', '22,80,443,445', '21-25,80,443,8080-8090'],
        'default': '1-10000',
        'aliases': ['RPORTS', 'PORT_RANGE'],
        'category': 'scan',
        'required': False,
        'notes': 'Common ports: 21,22,23,25,80,443,445,3306,3389,5432,8080.',
    },
    'SHOW_PROGRESS': {
        'description': 'Display real-time progress information during scan execution. '
                      'When enabled, shows percentage complete, hosts scanned, and estimated '
                      'time remaining. Useful for long-running scans to monitor status and '
                      'ensure the scan is progressing normally.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['VERBOSE', 'PROGRESS'],
        'category': 'scan',
        'required': False,
        'notes': 'Disable for cleaner output in scripted/automated scans. Enable when '
                'running interactively to monitor large network scans.',
    },

    # =========================================================================
    # SESSION OPTIONS
    # =========================================================================
    'SESSION': {
        'description': 'The session ID to use for post-exploitation modules. '
                      'Refers to an existing compromised session.',
        'input_type': 'integer',
        'examples': ['1', '2', '3'],
        'default': None,
        'aliases': ['S'],
        'category': 'session',
        'required': True,  # For post modules
        'notes': 'Use "sessions -l" to list available sessions and their IDs.',
    },

    # =========================================================================
    # DATABASE OPTIONS
    # =========================================================================
    'DATABASE': {
        'description': 'The name of the target database to connect to or enumerate. '
                      'For MySQL/MariaDB, common databases include mysql, information_schema. '
                      'For MSSQL, master and msdb are system databases. For PostgreSQL, '
                      'postgres is the default. Web applications typically have custom '
                      'database names like webapp_db, wordpress, etc.',
        'input_type': 'string',
        'examples': ['mysql', 'information_schema', 'webapp_db', 'master', 'postgres'],
        'default': None,
        'aliases': ['DB', 'DBNAME', 'DATABASE_NAME'],
        'category': 'database',
        'required': False,
        'notes': 'Use information_schema (MySQL) or master (MSSQL) to enumerate other '
                'databases. Some modules auto-detect available databases.',
    },

    # =========================================================================
    # OUTPUT OPTIONS
    # =========================================================================
    'VERBOSE': {
        'description': 'Enable verbose output for more detailed information.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'false',
        'aliases': ['V', 'DEBUG'],
        'category': 'output',
        'required': False,
        'notes': 'Helpful for troubleshooting but increases output volume.',
    },
    'OUTPUT_FILE': {
        'description': 'File path where scan results or module output will be saved. '
                      'The output format depends on the module - some save raw text, '
                      'others save structured data (XML, JSON, CSV). Useful for '
                      'documentation, reporting, and further analysis. The directory '
                      'must exist and be writable.',
        'input_type': 'file_path',
        'examples': ['/tmp/scan_results.txt', '/root/loot/output.txt', './results/nmap_scan.xml'],
        'default': None,
        'aliases': ['OUTFILE', 'LOGFILE', 'OUTPUT'],
        'category': 'output',
        'required': False,
        'notes': 'Create a dedicated loot/results directory for organization. Some modules '
                'support format suffixes (.xml, .json) to control output format.',
    },

    # =========================================================================
    # SMB-SPECIFIC OPTIONS
    # =========================================================================
    'SMBUser': {
        'description': 'Username for SMB (Server Message Block) authentication to Windows '
                      'file shares and services. This is the Windows account username used '
                      'to authenticate. For domain accounts, just provide the username - '
                      'the domain is specified separately in SMBDomain.',
        'input_type': 'string',
        'examples': ['administrator', 'admin', 'guest', 'svc_backup', 'YOURUSER'],
        'default': None,
        'aliases': ['USERNAME', 'USER', 'SMBUSERNAME'],
        'category': 'smb',
        'required': False,
        'notes': 'Leave blank for anonymous/null session attempts. Guest account may work '
                'on misconfigured systems. Try administrator, admin, or service accounts.',
    },
    'SMBPass': {
        'description': 'Password for SMB authentication. This is the plaintext password '
                      'for the account specified in SMBUser. For pass-the-hash attacks, '
                      'leave this blank and use the NTLM_HASH option instead.',
        'input_type': 'password',
        'examples': ['password123', 'P@ssw0rd!', 'Summer2024!', 'Welcome1'],
        'default': None,
        'aliases': ['PASSWORD', 'PASS', 'SMBPASSWORD'],
        'category': 'smb',
        'required': False,
        'notes': 'Can use NTLM hash instead via SMB::NTLM or NTLM_HASH option for PtH attacks. '
                'Common weak passwords: Password1, Welcome1, Company123, Season+Year.',
    },
    'SMBDomain': {
        'description': 'The Windows domain or workgroup name for SMB authentication. For '
                      'domain-joined machines, use the NetBIOS domain name (e.g., CORP) or '
                      'FQDN (e.g., corp.local). For standalone/workgroup machines, use '
                      'WORKGROUP or a period (.) to indicate local authentication.',
        'input_type': 'string',
        'examples': ['WORKGROUP', 'CORP', 'domain.local', '.', 'MYDOMAIN'],
        'default': '.',
        'aliases': ['DOMAIN', 'SMB_DOMAIN'],
        'category': 'smb',
        'required': False,
        'notes': 'Use . or WORKGROUP for local account authentication. For domain accounts, '
                'the domain must match the target. Try both NETBIOS and FQDN formats.',
    },
    'SHARE': {
        'description': 'The SMB share name to connect to on the target. Administrative shares '
                      '(C$, ADMIN$, IPC$) are hidden shares that require admin privileges. '
                      'IPC$ is used for null sessions and named pipe communication. Custom '
                      'shares (shared, public, data) vary by system configuration.',
        'input_type': 'string',
        'examples': ['C$', 'ADMIN$', 'IPC$', 'shared', 'public', 'Users', 'NETLOGON', 'SYSVOL'],
        'default': None,
        'aliases': ['SMB_SHARE', 'SHARENAME'],
        'category': 'smb',
        'required': False,
        'notes': 'C$ = C: drive (admin), ADMIN$ = Windows dir (admin), IPC$ = inter-process '
                '(null sessions). NETLOGON/SYSVOL on DCs often readable by domain users.',
    },

    # =========================================================================
    # HTTP-SPECIFIC OPTIONS
    # =========================================================================
    'HttpUsername': {
        'description': 'Username for HTTP Basic or Digest authentication. This is used when '
                      'a web server or application requires HTTP-level authentication (the '
                      'browser popup dialog). Not the same as form-based login credentials. '
                      'The credentials are sent in the Authorization header.',
        'input_type': 'string',
        'examples': ['admin', 'root', 'user', 'webadmin', 'tomcat'],
        'default': None,
        'aliases': ['USERNAME', 'HTTP_USER', 'AUTH_USER'],
        'category': 'http',
        'required': False,
        'notes': 'For HTTP 401 authentication prompts. Common defaults: admin/admin, '
                'tomcat/tomcat, root/root. Check for .htpasswd files.',
    },
    'HttpPassword': {
        'description': 'Password for HTTP Basic or Digest authentication. Paired with '
                      'HttpUsername for HTTP-level authentication. These credentials are '
                      'base64-encoded (Basic) or hashed (Digest) in the Authorization header.',
        'input_type': 'password',
        'examples': ['admin', 'password', 'secret', 'tomcat', 'manager'],
        'default': None,
        'aliases': ['PASSWORD', 'HTTP_PASS', 'AUTH_PASS'],
        'category': 'http',
        'required': False,
        'notes': 'HTTP Basic sends credentials in easily-decoded base64. Always use HTTPS. '
                'Common combos: admin/admin, admin/password, tomcat/s3cret.',
    },
    'COOKIE': {
        'description': 'HTTP cookie(s) to include with every request. Used to maintain '
                      'authenticated sessions or provide required tokens. Multiple cookies '
                      'are separated by semicolons. Copy from browser DevTools (F12) > '
                      'Network tab > Request Headers > Cookie.',
        'input_type': 'string',
        'examples': [
            'session=abc123',
            'PHPSESSID=xyz789; auth=true',
            'JSESSIONID=ABC123; csrf_token=xyz',
            'wordpress_logged_in=admin%7C1234567890',
        ],
        'default': None,
        'aliases': ['COOKIES', 'HTTP_COOKIE', 'SESSION_COOKIE'],
        'category': 'http',
        'required': False,
        'notes': 'Get cookies from browser DevTools, Burp Suite, or login response. '
                'Cookies may expire - refresh if attacks fail after a while.',
    },
    'USERAGENT': {
        'description': 'The User-Agent HTTP header identifying the browser/client. Servers '
                      'may behave differently based on User-Agent. Some WAFs block suspicious '
                      'or non-browser User-Agents. Spoofing helps blend in with normal traffic.',
        'input_type': 'string',
        'examples': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (compatible; Googlebot/2.1)',
            'curl/7.68.0',
        ],
        'default': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)',
        'aliases': ['USER_AGENT', 'UA', 'HTTP_USER_AGENT'],
        'category': 'http',
        'required': False,
        'notes': 'Use current browser strings for stealth. Googlebot UA may bypass auth. '
                'Some sites serve different content to mobile vs desktop UAs.',
    },
    'METHOD': {
        'description': 'The HTTP method (verb) for the request. GET retrieves data, POST '
                      'submits data, PUT updates/creates resources, DELETE removes resources, '
                      'HEAD gets headers only. The correct method depends on the target '
                      'application and vulnerability being exploited.',
        'input_type': 'enum',
        'examples': ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'],
        'default': 'GET',
        'aliases': ['HTTP_METHOD', 'VERB', 'REQUEST_METHOD'],
        'category': 'http',
        'required': False,
        'notes': 'GET for reading/triggering, POST for sending payloads, PUT for upload vulns, '
                'OPTIONS for CORS checks. HEAD useful for fingerprinting without downloading.',
    },
    'DATA': {
        'description': 'The HTTP request body data, typically for POST/PUT requests. Can be '
                      'URL-encoded form data (param=value&param2=value2), JSON ({\"key\": \"val\"}), '
                      'XML, or raw data. The format should match the Content-Type header.',
        'input_type': 'string',
        'examples': [
            'username=admin&password=test',
            '{"user":"admin","pass":"secret"}',
            '<xml><user>admin</user></xml>',
            'cmd=whoami',
        ],
        'default': None,
        'aliases': ['POSTDATA', 'BODY', 'HTTP_DATA', 'REQUEST_BODY'],
        'category': 'http',
        'required': False,
        'notes': 'URL-encode special characters in form data. For JSON, ensure quotes are '
                'escaped properly. Capture real requests with Burp to get exact format.',
    },

    # =========================================================================
    # SSH-SPECIFIC OPTIONS
    # =========================================================================
    'SSH_TIMEOUT': {
        'description': 'Timeout in seconds for establishing SSH connections. If the target '
                      'does not respond within this time, the connection attempt is aborted. '
                      'Affects the initial TCP connection and SSH handshake. Increase for '
                      'high-latency networks, firewalled hosts, or slow systems.',
        'input_type': 'integer',
        'examples': ['10', '30', '60', '120'],
        'default': '30',
        'aliases': ['TIMEOUT', 'CONNECTION_TIMEOUT'],
        'category': 'ssh',
        'required': False,
        'notes': 'Too short may miss slow targets. Too long wastes time on dead hosts. '
                'Start with 30s, increase to 60-120s for distant or filtered targets.',
    },
    'SSH_KEYFILE_B64': {
        'description': 'Base64-encoded SSH private key for authentication. Alternative to '
                      'providing a key file path. Useful when the key is stored in a database '
                      'or passed programmatically rather than read from disk.',
        'input_type': 'string',
        'examples': [
            'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVE...',
            'LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVkt...',
        ],
        'default': None,
        'aliases': ['KEY_B64', 'SSH_KEY_B64'],
        'category': 'ssh',
        'required': False,
        'notes': 'Base64-encode key: cat id_rsa | base64 -w0. Useful for automation and API calls.',
    },

    # =========================================================================
    # COMMAND EXECUTION OPTIONS
    # =========================================================================
    'CMD': {
        'description': 'The shell command to execute on the target system after successful '
                      'exploitation. The command runs with the privileges of the compromised '
                      'user or service. For Windows use cmd.exe syntax, for Linux use bash. '
                      'Complex commands may need proper escaping or base64 encoding.',
        'input_type': 'string',
        'examples': [
            'whoami',
            'id',
            'cat /etc/passwd',
            'net user',
            'ipconfig /all',
            'uname -a',
            'powershell -enc <base64>',
        ],
        'default': None,
        'aliases': ['COMMAND', 'EXEC', 'EXECUTE', 'RUN'],
        'category': 'execution',
        'required': False,
        'notes': 'Commands run as the exploited user/service - check with whoami/id first. '
                'Avoid interactive commands. Use full paths if PATH is limited.',
    },
    'CMDSTAGER': {
        'description': 'The method used to stage and execute commands on the target. Different '
                      'stagers work better in different environments. VBS and PowerShell for '
                      'Windows, curl/wget for Linux, certutil for restricted Windows.',
        'input_type': 'enum',
        'examples': ['auto', 'vbs', 'powershell', 'curl', 'wget', 'certutil', 'tftp'],
        'default': 'auto',
        'aliases': ['STAGER', 'CMD_STAGER'],
        'category': 'execution',
        'required': False,
        'notes': 'auto selects best method. Try certutil/bitsadmin on hardened Windows. '
                'curl/wget need outbound access. tftp works without full shell.',
    },

    # =========================================================================
    # FILE OPERATION OPTIONS
    # =========================================================================
    'RFILE': {
        'description': 'Full path to the file on the remote/target system to read, download, '
                      'or manipulate. Use forward slashes (/) for Linux/Unix and backslashes '
                      '(\\) for Windows. Requires appropriate permissions on the target.',
        'input_type': 'path',
        'examples': [
            '/etc/passwd',
            '/etc/shadow',
            '/home/user/.ssh/id_rsa',
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Users\\Admin\\Desktop\\secrets.txt',
            '/var/www/html/config.php',
        ],
        'default': None,
        'aliases': ['REMOTE_FILE', 'FILE', 'PATH', 'FILEPATH'],
        'category': 'file',
        'required': False,
        'notes': 'High-value targets: /etc/shadow (Linux hashes), SAM/SYSTEM (Windows hashes), '
                'SSH keys, config files with credentials, .bash_history, web.config.',
    },
    'LFILE': {
        'description': 'Full path on your local system where files will be saved (for downloads) '
                      'or read from (for uploads). Ensure the directory exists and you have '
                      'write permissions. Organize loot in dedicated directories.',
        'input_type': 'file_path',
        'examples': [
            '/tmp/downloaded_file',
            '/root/loot/target_passwd',
            '/home/user/exfil/data.txt',
            './loot/credentials.txt',
        ],
        'default': None,
        'aliases': ['LOCAL_FILE', 'LOCALPATH', 'SAVEPATH'],
        'category': 'file',
        'required': False,
        'notes': 'Create organized directories: loot/, exfil/, downloads/. Use descriptive names '
                'including target and date. Ensure write permissions before running module.',
    },

    # =========================================================================
    # ADDITIONAL COMMON OPTIONS
    # =========================================================================
    'WORKSPACE': {
        'description': 'The Metasploit workspace to use for organizing data. Workspaces keep '
                      'hosts, services, and loot separated by engagement. Useful for managing '
                      'multiple assessments or clients.',
        'input_type': 'string',
        'examples': ['default', 'client_acme', 'internal_2024', 'webapp_test'],
        'default': 'default',
        'aliases': ['WS'],
        'category': 'database',
        'required': False,
        'notes': 'Create per-engagement workspaces to avoid data mixing. Use "workspace" '
                'command in msfconsole to list and switch.',
    },
    'BLANK_PASSWORDS': {
        'description': 'Whether to try blank/empty passwords during authentication attempts. '
                      'Many systems have accounts with no password set, especially default '
                      'or test accounts.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['EMPTY_PASSWORDS', 'TRY_BLANK'],
        'category': 'auth',
        'required': False,
        'notes': 'Often successful on default installs, test environments, and misconfigured '
                'systems. Quick win before full password attacks.',
    },
    'USER_AS_PASS': {
        'description': 'Whether to try the username as the password. Many users set their '
                      'password to match their username, especially on internal systems.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['USERNAME_AS_PASSWORD'],
        'category': 'auth',
        'required': False,
        'notes': 'Common lazy password pattern. Try before heavy wordlist attacks.',
    },
    'STOP_ON_SUCCESS': {
        'description': 'Whether to stop scanning/brute-forcing after the first successful '
                      'result. Enable for quick wins, disable to find all valid credentials.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'true',
        'aliases': ['ABORT_ON_SUCCESS'],
        'category': 'scan',
        'required': False,
        'notes': 'Disable to enumerate all valid creds. Enable when you just need one way in.',
    },
    'BRUTEFORCE_SPEED': {
        'description': 'Speed setting for brute force attacks. Higher speeds are faster but '
                      'more likely to trigger lockouts and detection. Lower speeds are stealthier.',
        'input_type': 'integer',
        'examples': ['1', '2', '3', '4', '5'],
        'default': '5',
        'aliases': ['SPEED'],
        'category': 'auth',
        'required': False,
        'notes': '5=fastest/loudest, 1=slowest/stealthiest. Use 2-3 for production systems '
                'with lockout policies. 5 okay for CTF/lab environments.',
    },
    'AutoRunScript': {
        'description': 'Script to automatically run when a session is created. Useful for '
                      'automating post-exploitation tasks like migration, persistence, or '
                      'privilege escalation checks.',
        'input_type': 'string',
        'examples': [
            'post/windows/manage/migrate',
            'post/multi/manage/autoroute',
            'post/windows/gather/hashdump',
        ],
        'default': None,
        'aliases': ['AUTORUN', 'InitialAutoRunScript'],
        'category': 'session',
        'required': False,
        'notes': 'Common: migrate (move to stable process), autoroute (pivot), hashdump (creds). '
                'Chain multiple scripts with semicolons.',
    },
    'PrependMigrate': {
        'description': 'Automatically migrate to a new process after payload execution. '
                      'Improves stability by moving out of the exploited process which may crash.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'false',
        'aliases': ['MIGRATE'],
        'category': 'payload',
        'required': False,
        'notes': 'Recommended for exploits targeting unstable processes. Target process '
                'set with PrependMigrateProc option.',
    },
    'DisablePayloadHandler': {
        'description': 'Whether to skip starting a handler for the payload. Enable when using '
                      'an external handler (multi/handler) or for payloads that connect to '
                      'an existing listener.',
        'input_type': 'boolean',
        'examples': ['true', 'false'],
        'default': 'false',
        'aliases': ['NOHANDLER'],
        'category': 'payload',
        'required': False,
        'notes': 'Enable when running multi/handler separately. Useful for mass exploitation '
                'where one handler catches multiple shells.',
    },
}


# =============================================================================
# CATEGORY DESCRIPTIONS
# =============================================================================

SETTING_CATEGORIES = {
    'target': {
        'name': 'Target Options',
        'description': 'Settings that define what system(s) to attack',
        'color': 'RED',
    },
    'local': {
        'name': 'Local/Listener Options',
        'description': 'Settings for your local machine (callbacks, listeners)',
        'color': 'GREEN',
    },
    'auth': {
        'name': 'Authentication Options',
        'description': 'Credentials and authentication settings',
        'color': 'YELLOW',
    },
    'payload': {
        'name': 'Payload Options',
        'description': 'Settings for the payload delivered after exploitation',
        'color': 'MAGENTA',
    },
    'connection': {
        'name': 'Connection Options',
        'description': 'Network connection settings (SSL, proxy, timeout)',
        'color': 'CYAN',
    },
    'scan': {
        'name': 'Scan Options',
        'description': 'Settings specific to scanning modules',
        'color': 'BLUE',
    },
    'session': {
        'name': 'Session Options',
        'description': 'Settings for working with existing sessions',
        'color': 'WHITE',
    },
    'database': {
        'name': 'Database Options',
        'description': 'Database-related settings',
        'color': 'CYAN',
    },
    'output': {
        'name': 'Output Options',
        'description': 'Logging and output settings',
        'color': 'WHITE',
    },
    'smb': {
        'name': 'SMB Options',
        'description': 'SMB/Windows-specific settings',
        'color': 'BLUE',
    },
    'http': {
        'name': 'HTTP Options',
        'description': 'HTTP/Web-specific settings',
        'color': 'GREEN',
    },
    'ssh': {
        'name': 'SSH Options',
        'description': 'SSH-specific settings',
        'color': 'YELLOW',
    },
    'execution': {
        'name': 'Execution Options',
        'description': 'Command execution settings',
        'color': 'RED',
    },
    'file': {
        'name': 'File Options',
        'description': 'File operation settings',
        'color': 'CYAN',
    },
}


# =============================================================================
# API FUNCTIONS
# =============================================================================

def get_setting_info(name: str) -> Optional[Dict[str, Any]]:
    """Get information about an MSF setting.

    Args:
        name: Setting name (case-insensitive).

    Returns:
        Dictionary with setting info, or None if not found.
    """
    # Normalize name
    name_upper = name.upper()

    # Direct lookup
    if name_upper in MSF_SETTINGS:
        return MSF_SETTINGS[name_upper].copy()

    # Check aliases
    for setting_name, info in MSF_SETTINGS.items():
        aliases = [a.upper() for a in info.get('aliases', [])]
        if name_upper in aliases:
            result = info.copy()
            result['canonical_name'] = setting_name
            return result

    return None


def get_setting_description(name: str) -> str:
    """Get just the description for a setting.

    Args:
        name: Setting name.

    Returns:
        Description string, or 'Unknown setting' if not found.
    """
    info = get_setting_info(name)
    if info:
        return info['description']
    return f"Unknown setting: {name}"


def get_setting_prompt(name: str, default: Any = None, required: bool = False) -> str:
    """Get a formatted input prompt for a setting.

    Args:
        name: Setting name.
        default: Default value to show.
        required: Whether the setting is required.

    Returns:
        Formatted prompt string.
    """
    info = get_setting_info(name)

    if info:
        # Build prompt with examples
        examples = info.get('examples', [])
        example_str = f" (e.g., {examples[0]})" if examples else ""

        if default is not None:
            return f"{name}{example_str} [{default}]: "
        elif required:
            return f"{name}{example_str} (required): "
        else:
            return f"{name}{example_str}: "
    else:
        if default is not None:
            return f"{name} [{default}]: "
        return f"{name}: "


def format_setting_help(name: str, include_examples: bool = True, include_notes: bool = True) -> str:
    """Get a formatted help text for a setting.

    Args:
        name: Setting name.
        include_examples: Whether to include examples.
        include_notes: Whether to include notes.

    Returns:
        Formatted help string.
    """
    info = get_setting_info(name)

    if not info:
        return f"No help available for: {name}"

    lines = [info['description']]

    if include_examples and info.get('examples'):
        examples = ', '.join(info['examples'][:3])
        lines.append(f"Examples: {examples}")

    if info.get('default'):
        lines.append(f"Default: {info['default']}")

    if include_notes and info.get('notes'):
        lines.append(f"Note: {info['notes']}")

    return '\n'.join(lines)


def get_settings_by_category(category: str) -> Dict[str, Dict]:
    """Get all settings in a category.

    Args:
        category: Category name.

    Returns:
        Dictionary of setting name -> info.
    """
    return {
        name: info for name, info in MSF_SETTINGS.items()
        if info.get('category') == category
    }


def get_common_settings() -> List[str]:
    """Get list of most commonly used settings.

    Returns:
        List of setting names.
    """
    return [
        'RHOSTS', 'RHOST', 'RPORT',
        'LHOST', 'LPORT',
        'USERNAME', 'PASSWORD',
        'PAYLOAD', 'THREADS', 'SSL',
    ]


def get_category_info(category: str) -> Optional[Dict[str, str]]:
    """Get information about a setting category.

    Args:
        category: Category name.

    Returns:
        Dictionary with category info, or None if not found.
    """
    return SETTING_CATEGORIES.get(category)


def list_all_settings() -> List[str]:
    """Get list of all known setting names.

    Returns:
        List of setting names.
    """
    return list(MSF_SETTINGS.keys())


def list_categories() -> List[str]:
    """Get list of all setting categories.

    Returns:
        List of category names.
    """
    return list(SETTING_CATEGORIES.keys())


def validate_setting_value(name: str, value: str) -> tuple:
    """Validate a value for a setting.

    Args:
        name: Setting name.
        value: Value to validate.

    Returns:
        Tuple of (is_valid, error_message or None).
    """
    info = get_setting_info(name)

    if not info:
        return True, None  # Unknown settings pass through

    input_type = info.get('input_type', 'string')

    if input_type == 'port':
        try:
            port = int(value)
            if not (1 <= port <= 65535):
                return False, "Port must be between 1 and 65535"
        except ValueError:
            return False, "Port must be a number"

    elif input_type == 'integer':
        try:
            int(value)
        except ValueError:
            return False, "Must be a number"

    elif input_type == 'boolean':
        if value.lower() not in ('true', 'false', 'yes', 'no', '1', '0'):
            return False, "Must be true/false, yes/no, or 1/0"

    elif input_type == 'ip':
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(ip_pattern, value):
            # Could be a hostname, which is also valid
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*$', value):
                return False, "Must be a valid IP address or hostname"

    elif input_type == 'port_range':
        # Validate port range format
        import re
        if not re.match(r'^[\d,\-\s]+$', value):
            return False, "Invalid port range format. Use: 22 or 1-1000 or 22,80,443"

    return True, None


# =============================================================================
# QUICK REFERENCE
# =============================================================================

def print_quick_reference():
    """Print a quick reference of common settings."""
    print("MSF Settings Quick Reference")
    print("=" * 60)

    for category in ['target', 'local', 'auth', 'payload', 'connection']:
        cat_info = SETTING_CATEGORIES.get(category, {})
        print(f"\n{cat_info.get('name', category.upper())}")
        print("-" * 40)

        settings = get_settings_by_category(category)
        for name, info in settings.items():
            desc = info['description'][:50] + "..." if len(info['description']) > 50 else info['description']
            print(f"  {name:15} - {desc}")


if __name__ == "__main__":
    # Test the module
    print_quick_reference()

    print("\n" + "=" * 60)
    print("Testing get_setting_info('RHOSTS'):")
    print(format_setting_help('RHOSTS'))

    print("\n" + "=" * 60)
    print("Testing get_setting_prompt('RPORT', default=445):")
    print(get_setting_prompt('RPORT', default=445))
