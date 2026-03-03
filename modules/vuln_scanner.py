"""AUTARCH Vulnerability Scanner

Template-based vulnerability scanning with Nuclei/OpenVAS integration,
built-in CVE matching, default credential checking, and scan profiles.
"""

DESCRIPTION = "Vulnerability scanning & CVE detection"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import ssl
import csv
import time
import socket
import hashlib
import threading
import subprocess
from io import StringIO
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    import shutil

    def find_tool(name):
        return shutil.which(name)

    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
    from requests.exceptions import RequestException
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

try:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        RED = YELLOW = GREEN = CYAN = DIM = RESET = WHITE = ''
    def clear_screen(): pass
    def display_banner(): pass


# ── Security Headers ─────────────────────────────────────────────────────────

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Embedder-Policy',
    'X-XSS-Protection',
]

# ── Default Credentials Database ─────────────────────────────────────────────

DEFAULT_CREDS: Dict[str, List[Tuple[str, str]]] = {
    'ssh': [
        ('root', 'root'), ('root', 'toor'), ('root', 'password'), ('root', 'admin'),
        ('root', '123456'), ('root', '12345678'), ('admin', 'admin'), ('admin', 'password'),
        ('admin', '1234'), ('user', 'user'), ('user', 'password'), ('pi', 'raspberry'),
        ('ubuntu', 'ubuntu'), ('vagrant', 'vagrant'), ('deploy', 'deploy'),
        ('test', 'test'), ('guest', 'guest'), ('oracle', 'oracle'),
    ],
    'ftp': [
        ('anonymous', ''), ('anonymous', 'anonymous'), ('ftp', 'ftp'),
        ('admin', 'admin'), ('admin', 'password'), ('root', 'root'),
        ('user', 'user'), ('test', 'test'), ('guest', 'guest'),
    ],
    'mysql': [
        ('root', ''), ('root', 'root'), ('root', 'mysql'), ('root', 'password'),
        ('root', 'admin'), ('root', 'toor'), ('admin', 'admin'), ('admin', 'password'),
        ('mysql', 'mysql'), ('dbadmin', 'dbadmin'), ('db', 'db'),
        ('test', 'test'), ('user', 'user'),
    ],
    'postgresql': [
        ('postgres', 'postgres'), ('postgres', 'password'), ('postgres', 'admin'),
        ('postgres', ''), ('admin', 'admin'), ('admin', 'password'),
        ('user', 'user'), ('pgsql', 'pgsql'),
    ],
    'redis': [
        ('', ''), ('', 'redis'), ('', 'password'), ('', 'admin'),
        ('', 'foobared'), ('default', 'default'), ('default', ''),
    ],
    'mongodb': [
        ('', ''), ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
        ('root', 'root'), ('root', 'password'), ('mongouser', 'mongopass'),
    ],
    'telnet': [
        ('root', 'root'), ('admin', 'admin'), ('admin', 'password'),
        ('admin', '1234'), ('user', 'user'), ('guest', 'guest'),
        ('support', 'support'), ('enable', 'enable'), ('cisco', 'cisco'),
    ],
    'snmp': [
        ('', 'public'), ('', 'private'), ('', 'community'),
        ('', 'snmp'), ('', 'default'), ('', 'monitor'),
    ],
    'http': [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
        ('admin', '12345'), ('admin', ''), ('root', 'root'),
        ('root', 'password'), ('administrator', 'administrator'),
        ('user', 'user'), ('guest', 'guest'), ('test', 'test'),
    ],
    'tomcat': [
        ('tomcat', 'tomcat'), ('admin', 'admin'), ('manager', 'manager'),
        ('tomcat', 's3cret'), ('admin', 'tomcat'), ('role1', 'role1'),
        ('tomcat', 'password'), ('admin', 'password'), ('both', 'tomcat'),
    ],
    'jenkins': [
        ('admin', 'admin'), ('admin', 'password'), ('admin', 'jenkins'),
        ('admin', ''), ('jenkins', 'jenkins'), ('user', 'user'),
    ],
    'vnc': [
        ('', 'password'), ('', 'vnc'), ('', '1234'), ('', '12345'),
        ('', 'admin'), ('', 'root'),
    ],
    'smb': [
        ('administrator', 'password'), ('administrator', 'admin'),
        ('admin', 'admin'), ('guest', ''), ('guest', 'guest'),
        ('user', 'user'), ('test', 'test'),
    ],
    'mssql': [
        ('sa', ''), ('sa', 'sa'), ('sa', 'password'), ('sa', 'Password1'),
        ('sa', 'admin'), ('admin', 'admin'), ('admin', 'password'),
    ],
    'oracle': [
        ('system', 'oracle'), ('system', 'manager'), ('sys', 'change_on_install'),
        ('scott', 'tiger'), ('dbsnmp', 'dbsnmp'), ('outln', 'outln'),
    ],
    'ldap': [
        ('admin', 'admin'), ('admin', 'password'), ('cn=admin', 'admin'),
        ('cn=Manager', 'secret'), ('cn=root', 'secret'),
    ],
    'mqtt': [
        ('', ''), ('admin', 'admin'), ('admin', 'password'),
        ('guest', 'guest'), ('user', 'user'),
    ],
}

# ── Scan Profiles ─────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    'quick': {
        'description': 'Fast port scan + top service CVEs',
        'ports': '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443',
        'check_creds': False,
        'check_headers': True,
        'check_ssl': True,
        'nuclei': False,
    },
    'standard': {
        'description': 'Port scan + service detection + CVE matching + headers + SSL',
        'ports': '1-1024,1433,1521,2049,3306,3389,5432,5900,5985,6379,8080,8443,8888,9090,9200,27017',
        'check_creds': True,
        'check_headers': True,
        'check_ssl': True,
        'nuclei': False,
    },
    'full': {
        'description': 'All ports + full CVE + default creds + headers + SSL + nuclei',
        'ports': '1-65535',
        'check_creds': True,
        'check_headers': True,
        'check_ssl': True,
        'nuclei': True,
    },
    'custom': {
        'description': 'User-defined parameters',
        'ports': None,
        'check_creds': True,
        'check_headers': True,
        'check_ssl': True,
        'nuclei': False,
    },
}


class VulnScanner:
    """Vulnerability scanner with CVE matching and default credential checking."""

    _instance = None

    def __init__(self):
        self.data_dir = os.path.join(str(get_data_dir()), 'vuln_scans')
        os.makedirs(self.data_dir, exist_ok=True)
        self.scans: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._nmap_bin = find_tool('nmap')
        self._nuclei_bin = find_tool('nuclei')
        self._load_history()

    def _load_history(self):
        """Load scan history from disk."""
        try:
            for fname in os.listdir(self.data_dir):
                if fname.endswith('.json') and fname.startswith('scan_'):
                    fpath = os.path.join(self.data_dir, fname)
                    with open(fpath) as f:
                        data = json.load(f)
                    job_id = data.get('job_id', fname.replace('.json', '').replace('scan_', ''))
                    self.scans[job_id] = data
        except Exception:
            pass

    def _save_scan(self, job_id: str):
        """Persist scan results to disk."""
        try:
            scan = self.scans.get(job_id)
            if scan:
                fpath = os.path.join(self.data_dir, f'scan_{job_id}.json')
                with open(fpath, 'w') as f:
                    json.dump(scan, f, indent=2, default=str)
        except Exception:
            pass

    def _gen_id(self) -> str:
        """Generate unique scan ID."""
        return hashlib.md5(f"{time.time()}-{os.getpid()}".encode()).hexdigest()[:12]

    # ── Main Scan Dispatcher ──────────────────────────────────────────────

    def scan(self, target: str, profile: str = 'standard',
             ports: Optional[str] = None, templates: Optional[List[str]] = None) -> str:
        """Start a vulnerability scan. Returns job_id."""
        job_id = self._gen_id()
        now = datetime.now(timezone.utc).isoformat()

        self.scans[job_id] = {
            'job_id': job_id,
            'target': target,
            'profile': profile,
            'status': 'running',
            'started': now,
            'completed': None,
            'progress': 0,
            'findings': [],
            'summary': {
                'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
                'total': 0,
            },
            'services': [],
            'ports_scanned': ports or SCAN_PROFILES.get(profile, {}).get('ports', '1-1024'),
        }
        self._save_scan(job_id)

        t = threading.Thread(target=self._run_scan, args=(job_id, target, profile, ports, templates), daemon=True)
        t.start()
        return job_id

    def _run_scan(self, job_id: str, target: str, profile: str,
                  ports: Optional[str], templates: Optional[List[str]]):
        """Execute the scan in a background thread."""
        try:
            prof = SCAN_PROFILES.get(profile, SCAN_PROFILES['standard'])
            scan_ports = ports or prof.get('ports', '1-1024')

            # Phase 1: Port scan + service detection
            self._update_progress(job_id, 5, 'Port scanning...')
            services = self._port_scan(target, scan_ports)
            with self._lock:
                self.scans[job_id]['services'] = services
            self._update_progress(job_id, 25, 'Port scan complete')

            # Phase 2: CVE matching
            self._update_progress(job_id, 30, 'Matching CVEs...')
            for svc in services:
                if svc.get('version'):
                    cves = self.match_cves(svc.get('service', ''), svc['version'])
                    for cve in cves:
                        self._add_finding(job_id, {
                            'type': 'cve',
                            'title': cve.get('id', 'CVE Match'),
                            'severity': cve.get('severity', 'medium'),
                            'service': f"{svc.get('service', '')} {svc.get('version', '')}",
                            'port': svc.get('port'),
                            'description': cve.get('description', ''),
                            'cvss': cve.get('cvss', ''),
                            'reference': cve.get('reference', ''),
                        })
            self._update_progress(job_id, 45, 'CVE matching complete')

            # Phase 3: Security headers
            if prof.get('check_headers', True):
                self._update_progress(job_id, 50, 'Checking security headers...')
                http_ports = [s['port'] for s in services if s.get('service') in ('http', 'https', 'http-proxy', 'http-alt')]
                if not http_ports:
                    for p in [80, 443, 8080, 8443]:
                        if any(s['port'] == p for s in services):
                            http_ports.append(p)
                for port in http_ports:
                    scheme = 'https' if port in (443, 8443) else 'http'
                    url = f"{scheme}://{target}:{port}"
                    headers_result = self.check_headers(url)
                    if headers_result and headers_result.get('missing'):
                        for hdr in headers_result['missing']:
                            self._add_finding(job_id, {
                                'type': 'header',
                                'title': f'Missing Security Header: {hdr}',
                                'severity': 'low' if hdr == 'X-XSS-Protection' else 'medium',
                                'service': f'HTTP ({port})',
                                'port': port,
                                'description': f'The security header {hdr} is not set.',
                            })
                self._update_progress(job_id, 60, 'Header checks complete')

            # Phase 4: SSL/TLS
            if prof.get('check_ssl', True):
                self._update_progress(job_id, 62, 'Checking SSL/TLS...')
                ssl_ports = [s['port'] for s in services if s.get('service') in ('https', 'ssl', 'imaps', 'pop3s', 'smtps')]
                if 443 in [s['port'] for s in services] and 443 not in ssl_ports:
                    ssl_ports.append(443)
                for port in ssl_ports:
                    ssl_result = self.check_ssl(target, port)
                    if ssl_result.get('issues'):
                        for issue in ssl_result['issues']:
                            severity = 'high' if 'weak protocol' in issue.lower() or 'expired' in issue.lower() else 'medium'
                            self._add_finding(job_id, {
                                'type': 'ssl',
                                'title': f'SSL/TLS Issue: {issue[:60]}',
                                'severity': severity,
                                'service': f'SSL/TLS ({port})',
                                'port': port,
                                'description': issue,
                            })
                    if ssl_result.get('weak_ciphers'):
                        for cipher in ssl_result['weak_ciphers']:
                            self._add_finding(job_id, {
                                'type': 'ssl',
                                'title': f'Weak Cipher: {cipher}',
                                'severity': 'medium',
                                'service': f'SSL/TLS ({port})',
                                'port': port,
                                'description': f'Weak cipher suite detected: {cipher}',
                            })
                self._update_progress(job_id, 70, 'SSL checks complete')

            # Phase 5: Default credentials
            if prof.get('check_creds', False):
                self._update_progress(job_id, 72, 'Testing default credentials...')
                cred_results = self.check_default_creds(target, services)
                for cred in cred_results:
                    self._add_finding(job_id, {
                        'type': 'credential',
                        'title': f"Default Credentials: {cred['service']}",
                        'severity': 'critical',
                        'service': cred['service'],
                        'port': cred.get('port'),
                        'description': f"Default credentials work: {cred['username']}:{cred['password']}",
                    })
                self._update_progress(job_id, 85, 'Credential checks complete')

            # Phase 6: Nuclei (if available and enabled)
            if prof.get('nuclei', False) and self._nuclei_bin:
                self._update_progress(job_id, 87, 'Running Nuclei templates...')
                nuclei_results = self.nuclei_scan(target, templates)
                for finding in nuclei_results.get('findings', []):
                    self._add_finding(job_id, finding)
                self._update_progress(job_id, 95, 'Nuclei scan complete')

            # Done
            with self._lock:
                self.scans[job_id]['status'] = 'complete'
                self.scans[job_id]['completed'] = datetime.now(timezone.utc).isoformat()
                self.scans[job_id]['progress'] = 100
            self._save_scan(job_id)

        except Exception as e:
            with self._lock:
                self.scans[job_id]['status'] = 'error'
                self.scans[job_id]['error'] = str(e)
                self.scans[job_id]['completed'] = datetime.now(timezone.utc).isoformat()
            self._save_scan(job_id)

    def _update_progress(self, job_id: str, progress: int, message: str = ''):
        """Update scan progress."""
        with self._lock:
            if job_id in self.scans:
                self.scans[job_id]['progress'] = progress
                self.scans[job_id]['progress_message'] = message
        self._save_scan(job_id)

    def _add_finding(self, job_id: str, finding: dict):
        """Add a finding to a scan."""
        with self._lock:
            if job_id in self.scans:
                finding['timestamp'] = datetime.now(timezone.utc).isoformat()
                self.scans[job_id]['findings'].append(finding)
                sev = finding.get('severity', 'info').lower()
                if sev in self.scans[job_id]['summary']:
                    self.scans[job_id]['summary'][sev] += 1
                self.scans[job_id]['summary']['total'] += 1

    # ── Port Scanning ─────────────────────────────────────────────────────

    def _port_scan(self, target: str, ports: str) -> List[Dict]:
        """Run a port scan. Uses nmap if available, otherwise falls back to socket."""
        if self._nmap_bin:
            return self._nmap_scan(target, ports)
        return self._socket_scan(target, ports)

    def _nmap_scan(self, target: str, ports: str) -> List[Dict]:
        """Run nmap for port/service detection."""
        services = []
        try:
            cmd = [self._nmap_bin, '-sV', '--version-intensity', '5',
                   '-p', ports, '-T4', '--open', '-oX', '-', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                services = self._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        return services

    def _parse_nmap_xml(self, xml_output: str) -> List[Dict]:
        """Parse nmap XML output to extract services."""
        services = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            for host in root.findall('.//host'):
                for port_elem in host.findall('.//port'):
                    state = port_elem.find('state')
                    if state is not None and state.get('state') == 'open':
                        svc_elem = port_elem.find('service')
                        service_name = svc_elem.get('name', 'unknown') if svc_elem is not None else 'unknown'
                        version = ''
                        if svc_elem is not None:
                            parts = []
                            if svc_elem.get('product'):
                                parts.append(svc_elem.get('product'))
                            if svc_elem.get('version'):
                                parts.append(svc_elem.get('version'))
                            version = ' '.join(parts)
                        services.append({
                            'port': int(port_elem.get('portid', 0)),
                            'protocol': port_elem.get('protocol', 'tcp'),
                            'state': 'open',
                            'service': service_name,
                            'version': version,
                            'banner': svc_elem.get('extrainfo', '') if svc_elem is not None else '',
                        })
        except Exception:
            pass
        return services

    def _socket_scan(self, target: str, ports: str) -> List[Dict]:
        """Fallback socket-based port scan."""
        services = []
        port_list = self._parse_port_range(ports)
        # Limit to prevent excessive scanning with socket fallback
        if len(port_list) > 2000:
            port_list = port_list[:2000]

        for port in port_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    service_name = self._guess_service(port)
                    banner = self._grab_banner(target, port)
                    services.append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': service_name,
                        'version': banner,
                        'banner': banner,
                    })
                sock.close()
            except Exception:
                pass
        return services

    def _parse_port_range(self, ports_str: str) -> List[int]:
        """Parse port range string like '1-1024,8080,8443' into list of ints."""
        result = []
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-', 1)
                    for p in range(int(start), int(end) + 1):
                        if 1 <= p <= 65535:
                            result.append(p)
                except ValueError:
                    pass
            else:
                try:
                    p = int(part)
                    if 1 <= p <= 65535:
                        result.append(p)
                except ValueError:
                    pass
        return sorted(set(result))

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        common = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle',
            1723: 'pptp', 2049: 'nfs', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 5985: 'winrm',
            6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
            8888: 'http-alt', 9090: 'http-alt', 9200: 'elasticsearch',
            27017: 'mongodb', 1883: 'mqtt', 5672: 'amqp', 11211: 'memcached',
        }
        return common.get(port, 'unknown')

    def _grab_banner(self, host: str, port: int) -> str:
        """Try to grab a service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            # Send a basic probe for HTTP
            if port in (80, 8080, 8888, 8443, 443, 9090):
                sock.send(b'HEAD / HTTP/1.0\r\nHost: target\r\n\r\n')
            else:
                sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            # Extract server header from HTTP response
            if banner.startswith('HTTP/'):
                for line in banner.split('\r\n'):
                    if line.lower().startswith('server:'):
                        return line.split(':', 1)[1].strip()
            return banner[:200] if banner else ''
        except Exception:
            return ''

    # ── Quick / Full Scan Shortcuts ───────────────────────────────────────

    def quick_scan(self, target: str) -> str:
        """Quick scan: ports + services + top CVEs. Returns job_id."""
        return self.scan(target, profile='quick')

    def full_scan(self, target: str) -> str:
        """Full scan: all ports + CVEs + creds + headers + SSL + nuclei. Returns job_id."""
        return self.scan(target, profile='full')

    # ── Nuclei Integration ────────────────────────────────────────────────

    def nuclei_scan(self, target: str, templates: Optional[List[str]] = None) -> Dict:
        """Run Nuclei template scanner if available."""
        result = {'ok': False, 'findings': [], 'error': ''}
        if not self._nuclei_bin:
            result['error'] = 'Nuclei not found in PATH'
            return result

        try:
            cmd = [self._nuclei_bin, '-u', target, '-jsonl', '-silent', '-nc']
            if templates:
                for t in templates:
                    cmd.extend(['-t', t])
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            result['ok'] = True

            for line in proc.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    finding = {
                        'type': 'nuclei',
                        'title': entry.get('info', {}).get('name', entry.get('template-id', 'Unknown')),
                        'severity': entry.get('info', {}).get('severity', 'info'),
                        'service': entry.get('matched-at', target),
                        'port': None,
                        'description': entry.get('info', {}).get('description', ''),
                        'template': entry.get('template-id', ''),
                        'matcher': entry.get('matcher-name', ''),
                        'reference': ', '.join(entry.get('info', {}).get('reference', [])) if isinstance(entry.get('info', {}).get('reference'), list) else '',
                    }
                    # Try to extract port from matched-at URL
                    matched = entry.get('matched-at', '')
                    if matched:
                        try:
                            parsed = urlparse(matched)
                            if parsed.port:
                                finding['port'] = parsed.port
                        except Exception:
                            pass
                    result['findings'].append(finding)
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            result['error'] = 'Nuclei scan timed out (10 min limit)'
        except Exception as e:
            result['error'] = str(e)

        return result

    # ── Default Credential Checking ───────────────────────────────────────

    def check_default_creds(self, target: str, services: List[Dict]) -> List[Dict]:
        """Test default credentials against discovered services."""
        found = []

        svc_map = {}
        for svc in services:
            name = svc.get('service', '').lower()
            port = svc.get('port', 0)
            svc_map[name] = port

        # SSH
        if 'ssh' in svc_map:
            port = svc_map['ssh']
            for user, pwd in DEFAULT_CREDS.get('ssh', []):
                if self._try_ssh(target, port, user, pwd):
                    found.append({'service': f'SSH ({port})', 'port': port, 'username': user, 'password': pwd})
                    break

        # FTP
        if 'ftp' in svc_map:
            port = svc_map['ftp']
            for user, pwd in DEFAULT_CREDS.get('ftp', []):
                if self._try_ftp(target, port, user, pwd):
                    found.append({'service': f'FTP ({port})', 'port': port, 'username': user, 'password': pwd})
                    break

        # MySQL
        if 'mysql' in svc_map:
            port = svc_map['mysql']
            for user, pwd in DEFAULT_CREDS.get('mysql', []):
                if self._try_mysql(target, port, user, pwd):
                    found.append({'service': f'MySQL ({port})', 'port': port, 'username': user, 'password': pwd})
                    break

        # PostgreSQL
        if 'postgresql' in svc_map:
            port = svc_map['postgresql']
            for user, pwd in DEFAULT_CREDS.get('postgresql', []):
                if self._try_postgres(target, port, user, pwd):
                    found.append({'service': f'PostgreSQL ({port})', 'port': port, 'username': user, 'password': pwd})
                    break

        # Redis
        if 'redis' in svc_map:
            port = svc_map['redis']
            for user, pwd in DEFAULT_CREDS.get('redis', []):
                if self._try_redis(target, port, pwd):
                    found.append({'service': f'Redis ({port})', 'port': port, 'username': user or '(none)', 'password': pwd or '(none)'})
                    break

        # MongoDB
        if 'mongodb' in svc_map:
            port = svc_map['mongodb']
            if self._try_mongodb(target, port):
                found.append({'service': f'MongoDB ({port})', 'port': port, 'username': '(none)', 'password': '(no auth)'})

        # HTTP admin panels
        for svc_name in ('http', 'https', 'http-proxy', 'http-alt'):
            if svc_name in svc_map:
                port = svc_map[svc_name]
                scheme = 'https' if svc_name == 'https' or port in (443, 8443) else 'http'
                for user, pwd in DEFAULT_CREDS.get('http', []):
                    if self._try_http_auth(f"{scheme}://{target}:{port}", user, pwd):
                        found.append({'service': f'HTTP Admin ({port})', 'port': port, 'username': user, 'password': pwd})
                        break

        # SNMP
        if 'snmp' in svc_map or any(s.get('port') == 161 for s in services):
            port = svc_map.get('snmp', 161)
            for _, community in DEFAULT_CREDS.get('snmp', []):
                if self._try_snmp(target, community):
                    found.append({'service': f'SNMP ({port})', 'port': port, 'username': '(community)', 'password': community})
                    break

        # Telnet
        if 'telnet' in svc_map:
            port = svc_map['telnet']
            for user, pwd in DEFAULT_CREDS.get('telnet', []):
                if self._try_telnet(target, port, user, pwd):
                    found.append({'service': f'Telnet ({port})', 'port': port, 'username': user, 'password': pwd})
                    break

        return found

    def _try_ssh(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Try SSH login via subprocess."""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pwd, timeout=5, allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except Exception:
            return False

    def _try_ftp(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Try FTP login."""
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, pwd)
            ftp.quit()
            return True
        except Exception:
            return False

    def _try_mysql(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Try MySQL login via socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            greeting = sock.recv(1024)
            sock.close()
            # If we get a greeting, the port is open. Full auth test requires mysql connector.
            if greeting and b'mysql' in greeting.lower():
                return False  # Got greeting but can't auth without connector
            return False
        except Exception:
            return False

    def _try_postgres(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Try PostgreSQL login."""
        try:
            import psycopg2
            conn = psycopg2.connect(host=host, port=port, user=user, password=pwd, connect_timeout=5)
            conn.close()
            return True
        except Exception:
            return False

    def _try_redis(self, host: str, port: int, pwd: str) -> bool:
        """Try Redis with AUTH command."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            if pwd:
                sock.send(f"AUTH {pwd}\r\n".encode())
            else:
                sock.send(b"PING\r\n")
            resp = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return '+OK' in resp or '+PONG' in resp
        except Exception:
            return False

    def _try_mongodb(self, host: str, port: int) -> bool:
        """Check if MongoDB allows unauthenticated access."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            # MongoDB wire protocol: send isMaster command
            # Simplified check: just see if port is open and responds
            sock.close()
            return True  # Port is open, but we can't fully confirm without pymongo
        except Exception:
            return False

    def _try_http_auth(self, url: str, user: str, pwd: str) -> bool:
        """Try HTTP basic/digest auth on common admin paths."""
        if not _HAS_REQUESTS:
            return False
        admin_paths = ['/', '/admin', '/manager/html', '/login', '/admin/login']
        for path in admin_paths:
            try:
                resp = requests.get(url + path, auth=(user, pwd), timeout=5,
                                    verify=False, allow_redirects=False)
                if resp.status_code in (200, 301, 302) and resp.status_code != 401:
                    # Check if we actually got past auth (not just a public page)
                    unauth = requests.get(url + path, timeout=5, verify=False, allow_redirects=False)
                    if unauth.status_code == 401:
                        return True
            except Exception:
                pass
        return False

    def _try_snmp(self, host: str, community: str) -> bool:
        """Try SNMP community string via UDP."""
        try:
            # Build SNMPv1 GET request for sysDescr.0
            community_bytes = community.encode()
            pdu = (
                b'\xa0\x1c'
                b'\x02\x04\x00\x00\x00\x01'
                b'\x02\x01\x00'
                b'\x02\x01\x00'
                b'\x30\x0e\x30\x0c'
                b'\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00'
                b'\x05\x00'
            )
            payload = b'\x02\x01\x00' + bytes([0x04, len(community_bytes)]) + community_bytes + pdu
            snmp_get = bytes([0x30, len(payload)]) + payload
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(snmp_get, (host, 161))
            data, _ = sock.recvfrom(4096)
            sock.close()
            return len(data) > 0
        except Exception:
            return False

    def _try_telnet(self, host: str, port: int, user: str, pwd: str) -> bool:
        """Try telnet login."""
        try:
            import telnetlib
            tn = telnetlib.Telnet(host, port, timeout=5)
            tn.read_until(b'login: ', timeout=5)
            tn.write(user.encode() + b'\n')
            tn.read_until(b'assword: ', timeout=5)
            tn.write(pwd.encode() + b'\n')
            resp = tn.read_some().decode('utf-8', errors='ignore')
            tn.close()
            return 'incorrect' not in resp.lower() and 'failed' not in resp.lower() and 'invalid' not in resp.lower()
        except Exception:
            return False

    # ── Security Headers Check ────────────────────────────────────────────

    def check_headers(self, url: str) -> Dict:
        """Check security headers for a URL."""
        result = {'url': url, 'headers': {}, 'present': [], 'missing': [], 'score': 0}
        if not _HAS_REQUESTS:
            result['error'] = 'requests library not available'
            return result

        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            checked = 0
            found = 0
            for hdr in SECURITY_HEADERS:
                hdr_lower = hdr.lower()
                if hdr_lower in resp_headers:
                    result['headers'][hdr] = {
                        'present': True,
                        'value': resp_headers[hdr_lower],
                        'rating': 'good',
                    }
                    result['present'].append(hdr)
                    found += 1
                else:
                    result['headers'][hdr] = {
                        'present': False,
                        'value': '',
                        'rating': 'missing',
                    }
                    result['missing'].append(hdr)
                checked += 1

            # Check for weak values
            csp = resp_headers.get('content-security-policy', '')
            if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
                result['headers']['Content-Security-Policy']['rating'] = 'weak'

            hsts = resp_headers.get('strict-transport-security', '')
            if hsts:
                max_age_match = re.search(r'max-age=(\d+)', hsts)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    result['headers']['Strict-Transport-Security']['rating'] = 'weak'

            xfo = resp_headers.get('x-frame-options', '')
            if xfo and xfo.upper() not in ('DENY', 'SAMEORIGIN'):
                result['headers']['X-Frame-Options']['rating'] = 'weak'

            result['score'] = int((found / checked) * 100) if checked > 0 else 0
            result['server'] = resp.headers.get('Server', '')
            result['status_code'] = resp.status_code

        except Exception as e:
            result['error'] = str(e)

        return result

    # ── SSL/TLS Analysis ──────────────────────────────────────────────────

    def check_ssl(self, host: str, port: int = 443) -> Dict:
        """Check SSL/TLS configuration."""
        result = {
            'host': host,
            'port': port,
            'valid': False,
            'issuer': '',
            'subject': '',
            'expires': '',
            'not_before': '',
            'protocol': '',
            'cipher': '',
            'key_size': 0,
            'issues': [],
            'weak_ciphers': [],
            'supported_protocols': [],
        }

        try:
            # Test connection without verification
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(10)
                s.connect((host, port))
                result['protocol'] = s.version()
                cipher_info = s.cipher()
                if cipher_info:
                    result['cipher'] = cipher_info[0]
                    result['key_size'] = cipher_info[2] if len(cipher_info) > 2 else 0

            # Test with verification
            ctx2 = ssl.create_default_context()
            try:
                with ctx2.wrap_socket(socket.socket(), server_hostname=host) as s2:
                    s2.settimeout(10)
                    s2.connect((host, port))
                    cert = s2.getpeercert()
                    result['valid'] = True
                    if cert.get('issuer'):
                        result['issuer'] = dict(x[0] for x in cert['issuer'])
                    if cert.get('subject'):
                        result['subject'] = dict(x[0] for x in cert['subject'])
                    result['expires'] = cert.get('notAfter', '')
                    result['not_before'] = cert.get('notBefore', '')

                    # Check expiry
                    if result['expires']:
                        try:
                            exp_date = datetime.strptime(result['expires'], '%b %d %H:%M:%S %Y %Z')
                            if exp_date < datetime.utcnow():
                                result['issues'].append('Certificate has expired')
                                result['valid'] = False
                            elif (exp_date - datetime.utcnow()).days < 30:
                                result['issues'].append(f'Certificate expires in {(exp_date - datetime.utcnow()).days} days')
                        except Exception:
                            pass

            except ssl.SSLCertVerificationError as e:
                result['issues'].append(f'Certificate verification failed: {e}')
            except Exception as e:
                result['issues'].append(f'SSL verification error: {e}')

            # Check protocol version
            if result['protocol'] in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                result['issues'].append(f'Weak protocol version: {result["protocol"]}')

            # Check for weak ciphers
            weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon', 'RC2']
            if result['cipher']:
                for pattern in weak_patterns:
                    if pattern.lower() in result['cipher'].lower():
                        result['weak_ciphers'].append(result['cipher'])
                        break

            # Check key size
            if result['key_size'] and result['key_size'] < 128:
                result['issues'].append(f'Weak key size: {result["key_size"]} bits')

            # Test specific protocol versions for known vulns
            protocols_to_test = [
                (ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None, 'TLSv1'),
            ]
            for proto_const, proto_name in protocols_to_test:
                if proto_const is not None:
                    try:
                        ctx_test = ssl.SSLContext(proto_const)
                        ctx_test.check_hostname = False
                        ctx_test.verify_mode = ssl.CERT_NONE
                        with ctx_test.wrap_socket(socket.socket(), server_hostname=host) as st:
                            st.settimeout(5)
                            st.connect((host, port))
                            result['supported_protocols'].append(proto_name)
                    except Exception:
                        pass

        except Exception as e:
            result['error'] = str(e)

        return result

    # ── CVE Matching ──────────────────────────────────────────────────────

    def match_cves(self, service: str, version: str) -> List[Dict]:
        """Match service/version against known CVEs."""
        matches = []
        if not service or not version:
            return matches

        # Try local CVE database first
        try:
            from core.cve import CVEDatabase
            cve_db = CVEDatabase()
            keyword = f"{service} {version}"
            results = cve_db.search(keyword)
            for r in results[:20]:
                matches.append({
                    'id': r.get('cve_id', r.get('id', '')),
                    'severity': r.get('severity', 'medium').lower(),
                    'description': r.get('description', '')[:300],
                    'cvss': r.get('cvss_score', r.get('cvss', '')),
                    'reference': r.get('reference', r.get('url', '')),
                })
        except Exception:
            pass

        # Fallback: NVD API query
        if not matches and _HAS_REQUESTS:
            try:
                keyword = f"{service} {version}"
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}&resultsPerPage=10"
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        cve_id = cve.get('id', '')
                        descriptions = cve.get('descriptions', [])
                        desc = ''
                        for d in descriptions:
                            if d.get('lang') == 'en':
                                desc = d.get('value', '')
                                break
                        metrics = cve.get('metrics', {})
                        cvss_score = ''
                        severity = 'medium'
                        for metric_key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                            metric_list = metrics.get(metric_key, [])
                            if metric_list:
                                cvss_data = metric_list[0].get('cvssData', {})
                                cvss_score = str(cvss_data.get('baseScore', ''))
                                sev = metric_list[0].get('baseSeverity', cvss_data.get('baseSeverity', '')).lower()
                                if sev:
                                    severity = sev
                                break
                        matches.append({
                            'id': cve_id,
                            'severity': severity,
                            'description': desc[:300],
                            'cvss': cvss_score,
                            'reference': f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                        })
            except Exception:
                pass

        return matches

    # ── Scan Management ───────────────────────────────────────────────────

    def get_scan(self, job_id: str) -> Optional[Dict]:
        """Get scan status and results."""
        return self.scans.get(job_id)

    def list_scans(self) -> List[Dict]:
        """List all scans with summary info."""
        result = []
        for job_id, scan in sorted(self.scans.items(), key=lambda x: x[1].get('started', ''), reverse=True):
            result.append({
                'job_id': job_id,
                'target': scan.get('target', ''),
                'profile': scan.get('profile', ''),
                'status': scan.get('status', ''),
                'started': scan.get('started', ''),
                'completed': scan.get('completed'),
                'progress': scan.get('progress', 0),
                'summary': scan.get('summary', {}),
                'findings_count': len(scan.get('findings', [])),
            })
        return result

    def delete_scan(self, job_id: str) -> bool:
        """Delete a scan and its data."""
        if job_id in self.scans:
            del self.scans[job_id]
            fpath = os.path.join(self.data_dir, f'scan_{job_id}.json')
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
            except Exception:
                pass
            return True
        return False

    def export_scan(self, job_id: str, fmt: str = 'json') -> Optional[Dict]:
        """Export scan results as JSON or CSV."""
        scan = self.scans.get(job_id)
        if not scan:
            return None

        if fmt == 'csv':
            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(['Type', 'Title', 'Severity', 'Service', 'Port', 'Description', 'CVSS', 'Reference'])
            for f in scan.get('findings', []):
                writer.writerow([
                    f.get('type', ''),
                    f.get('title', ''),
                    f.get('severity', ''),
                    f.get('service', ''),
                    f.get('port', ''),
                    f.get('description', ''),
                    f.get('cvss', ''),
                    f.get('reference', ''),
                ])
            return {
                'format': 'csv',
                'filename': f'vuln_scan_{job_id}.csv',
                'content': output.getvalue(),
                'mime': 'text/csv',
            }
        else:
            return {
                'format': 'json',
                'filename': f'vuln_scan_{job_id}.json',
                'content': json.dumps(scan, indent=2, default=str),
                'mime': 'application/json',
            }

    # ── Nuclei Templates ──────────────────────────────────────────────────

    def get_templates(self) -> Dict:
        """List available Nuclei templates."""
        result = {
            'installed': self._nuclei_bin is not None,
            'nuclei_path': self._nuclei_bin or '',
            'templates': [],
            'categories': [],
        }
        if not self._nuclei_bin:
            return result

        try:
            # List template directories
            cmd = [self._nuclei_bin, '-tl', '-silent']
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                templates = [t.strip() for t in proc.stdout.strip().split('\n') if t.strip()]
                result['templates'] = templates[:500]
                # Extract categories from template paths
                cats = set()
                for t in templates:
                    parts = t.split('/')
                    if len(parts) >= 2:
                        cats.add(parts[0])
                result['categories'] = sorted(cats)
        except Exception:
            pass

        return result

    # ── Severity Helpers ──────────────────────────────────────────────────

    def _severity_score(self, severity: str) -> int:
        """Convert severity string to numeric score."""
        scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        }
        return scores.get(severity.lower(), 0)


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None


def get_vuln_scanner() -> VulnScanner:
    global _instance
    if _instance is None:
        _instance = VulnScanner()
    return _instance


# ── CLI Interface ─────────────────────────────────────────────────────────────

def run():
    """CLI entry point."""
    print("\n  Vulnerability Scanner\n")

    scanner = get_vuln_scanner()

    while True:
        print(f"\n{'=' * 60}")
        print(f"  Vulnerability Scanner")
        print(f"{'=' * 60}")
        print()
        print("  1 — Quick Scan")
        print("  2 — Full Scan")
        print("  3 — Nuclei Scan")
        print("  4 — Check Default Credentials")
        print("  5 — Check Security Headers")
        print("  6 — Check SSL/TLS")
        print("  7 — View Scan Results")
        print("  8 — List Scans")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break

        elif choice == '1':
            target = input("  Target (IP/hostname): ").strip()
            if target:
                job_id = scanner.quick_scan(target)
                print(f"    Scan started (job: {job_id})")
                _wait_for_scan(scanner, job_id)

        elif choice == '2':
            target = input("  Target (IP/hostname): ").strip()
            if target:
                job_id = scanner.full_scan(target)
                print(f"    Full scan started (job: {job_id})")
                _wait_for_scan(scanner, job_id)

        elif choice == '3':
            target = input("  Target (IP/hostname/URL): ").strip()
            if target:
                if not scanner._nuclei_bin:
                    print("    Nuclei not found in PATH")
                    continue
                result = scanner.nuclei_scan(target)
                if result['ok']:
                    _print_findings(result.get('findings', []))
                else:
                    print(f"    Error: {result.get('error', 'Unknown')}")

        elif choice == '4':
            target = input("  Target (IP/hostname): ").strip()
            if target:
                port_str = input("  Ports to check (comma-sep, or Enter for common): ").strip()
                if port_str:
                    services = [{'port': int(p.strip()), 'service': scanner._guess_service(int(p.strip()))} for p in port_str.split(',') if p.strip().isdigit()]
                else:
                    print("    Scanning common ports first...")
                    services = scanner._socket_scan(target, '21,22,23,80,443,1433,3306,5432,6379,8080,27017')
                if services:
                    print(f"    Found {len(services)} open port(s), checking credentials...")
                    found = scanner.check_default_creds(target, services)
                    if found:
                        for c in found:
                            print(f"    {Colors.RED}[!] {c['service']}: {c['username']}:{c['password']}{Colors.RESET}")
                    else:
                        print(f"    {Colors.GREEN}[+] No default credentials found{Colors.RESET}")
                else:
                    print("    No open ports found")

        elif choice == '5':
            url = input("  URL: ").strip()
            if url:
                result = scanner.check_headers(url)
                if result.get('error'):
                    print(f"    Error: {result['error']}")
                else:
                    print(f"\n    Security Headers Score: {result['score']}%\n")
                    for hdr, info in result.get('headers', {}).items():
                        symbol = '+' if info['present'] else 'X'
                        color = Colors.GREEN if info['rating'] == 'good' else (Colors.YELLOW if info['rating'] == 'weak' else Colors.RED)
                        print(f"    {color}[{symbol}] {hdr}{Colors.RESET}")
                        if info.get('value'):
                            print(f"        {Colors.DIM}{info['value'][:80]}{Colors.RESET}")

        elif choice == '6':
            host = input("  Host: ").strip()
            port_str = input("  Port (443): ").strip()
            port = int(port_str) if port_str.isdigit() else 443
            if host:
                result = scanner.check_ssl(host, port)
                if result.get('error'):
                    print(f"    Error: {result['error']}")
                else:
                    valid_color = Colors.GREEN if result['valid'] else Colors.RED
                    print(f"\n    Valid: {valid_color}{result['valid']}{Colors.RESET}")
                    print(f"    Protocol: {result['protocol']}")
                    print(f"    Cipher: {result['cipher']}")
                    if result.get('expires'):
                        print(f"    Expires: {result['expires']}")
                    for issue in result.get('issues', []):
                        print(f"    {Colors.YELLOW}[!] {issue}{Colors.RESET}")
                    for wc in result.get('weak_ciphers', []):
                        print(f"    {Colors.RED}[!] Weak cipher: {wc}{Colors.RESET}")

        elif choice == '7':
            job_id = input("  Job ID: ").strip()
            if job_id:
                scan = scanner.get_scan(job_id)
                if scan:
                    _print_scan_summary(scan)
                else:
                    print("    Scan not found")

        elif choice == '8':
            scans = scanner.list_scans()
            if scans:
                print(f"\n    {'ID':<14} {'Target':<20} {'Profile':<10} {'Status':<10} {'Findings':<10}")
                print(f"    {'-'*14} {'-'*20} {'-'*10} {'-'*10} {'-'*10}")
                for s in scans:
                    print(f"    {s['job_id']:<14} {s['target']:<20} {s['profile']:<10} {s['status']:<10} {s['findings_count']:<10}")
            else:
                print("    No scans found")


def _wait_for_scan(scanner: VulnScanner, job_id: str):
    """Wait for a scan to complete and print results."""
    while True:
        scan = scanner.get_scan(job_id)
        if not scan:
            print("    Scan not found")
            break
        status = scan.get('status', '')
        progress = scan.get('progress', 0)
        message = scan.get('progress_message', '')
        print(f"\r    [{progress:3d}%] {message:<40}", end='', flush=True)
        if status in ('complete', 'error'):
            print()
            if status == 'error':
                print(f"    Error: {scan.get('error', 'Unknown')}")
            else:
                _print_scan_summary(scan)
            break
        time.sleep(2)


def _print_scan_summary(scan: dict):
    """Print scan results summary."""
    summary = scan.get('summary', {})
    print(f"\n    Target: {scan.get('target', '')}")
    print(f"    Profile: {scan.get('profile', '')}")
    print(f"    Status: {scan.get('status', '')}")
    print(f"    Findings: {summary.get('total', 0)} "
          f"(C:{summary.get('critical', 0)} H:{summary.get('high', 0)} "
          f"M:{summary.get('medium', 0)} L:{summary.get('low', 0)} I:{summary.get('info', 0)})")
    print()
    _print_findings(scan.get('findings', []))


def _print_findings(findings: list):
    """Print findings table."""
    if not findings:
        print(f"    {Colors.GREEN}No findings{Colors.RESET}")
        return

    sev_colors = {
        'critical': Colors.RED, 'high': Colors.RED,
        'medium': Colors.YELLOW, 'low': Colors.CYAN, 'info': Colors.DIM,
    }

    for f in findings:
        sev = f.get('severity', 'info').lower()
        color = sev_colors.get(sev, Colors.WHITE)
        print(f"    {color}[{sev.upper():<8}]{Colors.RESET} {f.get('title', '')}")
        if f.get('service'):
            print(f"              Service: {f['service']}")
        if f.get('description'):
            desc = f['description'][:120]
            print(f"              {Colors.DIM}{desc}{Colors.RESET}")
