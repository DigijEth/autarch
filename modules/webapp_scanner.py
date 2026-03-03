"""AUTARCH Web Application Scanner

Directory bruteforce, subdomain enumeration, vulnerability scanning (SQLi, XSS),
header analysis, technology fingerprinting, SSL/TLS audit, and crawler.
"""

DESCRIPTION = "Web application vulnerability scanner"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import ssl
import socket
import hashlib
import threading
import subprocess
from pathlib import Path
from urllib.parse import urlparse, urljoin, quote
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timezone

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


# ── Tech Fingerprints ─────────────────────────────────────────────────────────

TECH_SIGNATURES = {
    'WordPress': {'headers': [], 'body': ['wp-content', 'wp-includes', 'wp-json'], 'cookies': ['wordpress_']},
    'Drupal': {'headers': ['X-Drupal-'], 'body': ['Drupal.settings', 'sites/default'], 'cookies': ['SESS']},
    'Joomla': {'headers': [], 'body': ['/media/jui/', 'com_content'], 'cookies': []},
    'Laravel': {'headers': [], 'body': ['laravel_session'], 'cookies': ['laravel_session']},
    'Django': {'headers': [], 'body': ['csrfmiddlewaretoken', '__admin__'], 'cookies': ['csrftoken', 'sessionid']},
    'Express': {'headers': ['X-Powered-By: Express'], 'body': [], 'cookies': ['connect.sid']},
    'ASP.NET': {'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET'], 'body': ['__VIEWSTATE', '__EVENTVALIDATION'], 'cookies': ['ASP.NET_SessionId']},
    'PHP': {'headers': ['X-Powered-By: PHP'], 'body': ['.php'], 'cookies': ['PHPSESSID']},
    'Nginx': {'headers': ['Server: nginx'], 'body': [], 'cookies': []},
    'Apache': {'headers': ['Server: Apache'], 'body': [], 'cookies': []},
    'IIS': {'headers': ['Server: Microsoft-IIS'], 'body': [], 'cookies': []},
    'Cloudflare': {'headers': ['Server: cloudflare', 'cf-ray'], 'body': [], 'cookies': ['__cfduid']},
    'React': {'headers': [], 'body': ['react-root', '_reactRootContainer', 'data-reactroot'], 'cookies': []},
    'Angular': {'headers': [], 'body': ['ng-app', 'ng-controller', 'angular.min.js'], 'cookies': []},
    'Vue.js': {'headers': [], 'body': ['vue.min.js', 'v-bind:', 'v-if=', '__vue__'], 'cookies': []},
    'jQuery': {'headers': [], 'body': ['jquery.min.js', 'jquery-'], 'cookies': []},
    'Bootstrap': {'headers': [], 'body': ['bootstrap.min.css', 'bootstrap.min.js'], 'cookies': []},
}

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Embedder-Policy',
]

# Common directories for bruteforce
DIR_WORDLIST_SMALL = [
    'admin', 'login', 'wp-admin', 'administrator', 'phpmyadmin', 'cpanel',
    'dashboard', 'api', 'backup', 'config', 'db', 'debug', 'dev', 'docs',
    'dump', 'env', 'git', 'hidden', 'include', 'internal', 'log', 'logs',
    'old', 'panel', 'private', 'secret', 'server-status', 'shell', 'sql',
    'staging', 'status', 'temp', 'test', 'tmp', 'upload', 'uploads',
    'wp-content', 'wp-includes', '.env', '.git', '.htaccess', '.htpasswd',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'web.config',
    'composer.json', 'package.json', '.svn', '.DS_Store',
    'cgi-bin', 'server-info', 'info.php', 'phpinfo.php', 'xmlrpc.php',
    'wp-login.php', '.well-known', 'favicon.ico', 'humans.txt',
]

# SQLi test payloads
SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "\" OR 1=1--", "'; DROP TABLE--",
    "1' AND '1'='1", "1 AND 1=1", "1 UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--", "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
]

# XSS test payloads
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    '<body onload=alert(1)>',
]

# SQL error signatures
SQL_ERRORS = [
    'sql syntax', 'mysql_fetch', 'mysql_num_rows', 'mysql_query',
    'pg_query', 'pg_exec', 'sqlite3', 'SQLSTATE',
    'ORA-', 'Microsoft OLE DB', 'Unclosed quotation mark',
    'ODBC Microsoft Access', 'JET Database', 'Microsoft SQL Server',
    'java.sql.SQLException', 'PostgreSQL query failed',
    'supplied argument is not a valid MySQL', 'unterminated quoted string',
]


# ── Scanner Service ───────────────────────────────────────────────────────────

class WebAppScanner:
    """Web application vulnerability scanner."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'webapp_scanner')
        self._results_dir = os.path.join(self._data_dir, 'results')
        os.makedirs(self._results_dir, exist_ok=True)
        self._active_jobs: Dict[str, dict] = {}
        self._session = None

    def _get_session(self):
        if not _HAS_REQUESTS:
            raise RuntimeError('requests library required')
        if not self._session:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36',
            })
            self._session.verify = False
        return self._session

    # ── Quick Scan ────────────────────────────────────────────────────────

    def quick_scan(self, url: str) -> dict:
        """Run a quick scan — headers, tech fingerprint, basic checks."""
        if not _HAS_REQUESTS:
            return {'ok': False, 'error': 'requests library required'}
        url = self._normalize_url(url)
        results = {
            'url': url,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'headers': {},
            'security_headers': {},
            'technologies': [],
            'server': '',
            'status_code': 0,
            'redirects': [],
            'ssl': {},
        }

        try:
            sess = self._get_session()
            resp = sess.get(url, timeout=10, allow_redirects=True)
            results['status_code'] = resp.status_code
            results['headers'] = dict(resp.headers)
            results['server'] = resp.headers.get('Server', '')

            # Track redirects
            for r in resp.history:
                results['redirects'].append({
                    'url': r.url,
                    'status': r.status_code,
                })

            # Security headers
            results['security_headers'] = self._check_security_headers(resp.headers)

            # Technology fingerprint
            results['technologies'] = self._fingerprint_tech(resp)

            # SSL check
            parsed = urlparse(url)
            if parsed.scheme == 'https':
                results['ssl'] = self._check_ssl(parsed.hostname, parsed.port or 443)

        except Exception as e:
            results['error'] = str(e)

        return results

    # ── Directory Bruteforce ──────────────────────────────────────────────

    def dir_bruteforce(self, url: str, wordlist: List[str] = None,
                       extensions: List[str] = None,
                       threads: int = 10, timeout: float = 5.0) -> dict:
        """Directory bruteforce scan."""
        if not _HAS_REQUESTS:
            return {'ok': False, 'error': 'requests library required'}

        url = self._normalize_url(url).rstrip('/')
        if not wordlist:
            wordlist = DIR_WORDLIST_SMALL
        if not extensions:
            extensions = ['']

        job_id = f'dirbust_{int(time.time())}'
        holder = {'done': False, 'found': [], 'tested': 0,
                  'total': len(wordlist) * len(extensions)}
        self._active_jobs[job_id] = holder

        def do_scan():
            sess = self._get_session()
            results_lock = threading.Lock()

            def test_path(path):
                for ext in extensions:
                    full_path = f'{path}{ext}' if ext else path
                    test_url = f'{url}/{full_path}'
                    try:
                        r = sess.get(test_url, timeout=timeout,
                                     allow_redirects=False)
                        holder['tested'] += 1
                        if r.status_code not in (404, 403, 500):
                            with results_lock:
                                holder['found'].append({
                                    'path': '/' + full_path,
                                    'status': r.status_code,
                                    'size': len(r.content),
                                    'content_type': r.headers.get('Content-Type', ''),
                                })
                    except Exception:
                        holder['tested'] += 1

            threads_list = []
            for word in wordlist:
                t = threading.Thread(target=test_path, args=(word,), daemon=True)
                threads_list.append(t)
                t.start()
                if len(threads_list) >= threads:
                    for t in threads_list:
                        t.join(timeout=timeout + 5)
                    threads_list.clear()
            for t in threads_list:
                t.join(timeout=timeout + 5)
            holder['done'] = True

        threading.Thread(target=do_scan, daemon=True).start()
        return {'ok': True, 'job_id': job_id}

    # ── Subdomain Enumeration ─────────────────────────────────────────────

    def subdomain_enum(self, domain: str, wordlist: List[str] = None,
                       use_ct: bool = True) -> dict:
        """Enumerate subdomains via DNS bruteforce and CT logs."""
        found = []

        # Certificate Transparency logs
        if use_ct and _HAS_REQUESTS:
            try:
                resp = requests.get(
                    f'https://crt.sh/?q=%.{domain}&output=json',
                    timeout=15)
                if resp.status_code == 200:
                    for entry in resp.json():
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith('.' + domain) and sub not in found:
                                found.append(sub)
            except Exception:
                pass

        # DNS bruteforce
        if not wordlist:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'api', 'dev',
                        'staging', 'test', 'blog', 'shop', 'app', 'cdn',
                        'ns1', 'ns2', 'mx', 'smtp', 'imap', 'pop',
                        'vpn', 'remote', 'portal', 'webmail', 'secure',
                        'beta', 'demo', 'docs', 'git', 'jenkins', 'ci',
                        'grafana', 'kibana', 'prometheus', 'monitor',
                        'status', 'support', 'help', 'forum', 'wiki',
                        'internal', 'intranet', 'proxy', 'gateway']

        for sub in wordlist:
            fqdn = f'{sub}.{domain}'
            try:
                socket.getaddrinfo(fqdn, None)
                if fqdn not in found:
                    found.append(fqdn)
            except socket.gaierror:
                pass

        return {'ok': True, 'domain': domain, 'subdomains': sorted(set(found)),
                'count': len(set(found))}

    # ── Vulnerability Scanning ────────────────────────────────────────────

    def vuln_scan(self, url: str, scan_sqli: bool = True,
                  scan_xss: bool = True) -> dict:
        """Scan for SQL injection and XSS vulnerabilities."""
        if not _HAS_REQUESTS:
            return {'ok': False, 'error': 'requests library required'}

        url = self._normalize_url(url)
        findings = []
        sess = self._get_session()

        # Crawl to find forms and parameters
        try:
            resp = sess.get(url, timeout=10)
            body = resp.text
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        # Find URLs with parameters
        param_urls = self._extract_param_urls(body, url)

        # Test each URL with parameters
        for test_url in param_urls[:20]:  # Limit to prevent abuse
            parsed = urlparse(test_url)
            params = dict(p.split('=', 1) for p in parsed.query.split('&')
                          if '=' in p) if parsed.query else {}

            for param_name, param_val in params.items():
                if scan_sqli:
                    sqli_findings = self._test_sqli(sess, test_url, param_name, param_val)
                    findings.extend(sqli_findings)

                if scan_xss:
                    xss_findings = self._test_xss(sess, test_url, param_name, param_val)
                    findings.extend(xss_findings)

        return {
            'ok': True,
            'url': url,
            'findings': findings,
            'urls_tested': len(param_urls[:20]),
        }

    def _test_sqli(self, sess, url: str, param: str, original_val: str) -> List[dict]:
        """Test a parameter for SQL injection."""
        findings = []
        parsed = urlparse(url)
        base_params = dict(p.split('=', 1) for p in parsed.query.split('&')
                           if '=' in p) if parsed.query else {}

        for payload in SQLI_PAYLOADS[:6]:  # Limit payloads
            test_params = base_params.copy()
            test_params[param] = original_val + payload
            try:
                test_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                r = sess.get(test_url, params=test_params, timeout=5)
                body = r.text.lower()

                for error_sig in SQL_ERRORS:
                    if error_sig.lower() in body:
                        findings.append({
                            'type': 'sqli',
                            'severity': 'high',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': error_sig,
                            'description': f'SQL injection (error-based) in parameter "{param}"',
                        })
                        return findings  # One finding per param is enough
            except Exception:
                continue

        return findings

    def _test_xss(self, sess, url: str, param: str, original_val: str) -> List[dict]:
        """Test a parameter for reflected XSS."""
        findings = []
        parsed = urlparse(url)
        base_params = dict(p.split('=', 1) for p in parsed.query.split('&')
                           if '=' in p) if parsed.query else {}

        for payload in XSS_PAYLOADS[:4]:
            test_params = base_params.copy()
            test_params[param] = payload
            try:
                test_url = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                r = sess.get(test_url, params=test_params, timeout=5)
                if payload in r.text:
                    findings.append({
                        'type': 'xss',
                        'severity': 'high',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'description': f'Reflected XSS in parameter "{param}"',
                    })
                    return findings
            except Exception:
                continue

        return findings

    def _extract_param_urls(self, html: str, base_url: str) -> List[str]:
        """Extract URLs with parameters from HTML."""
        urls = set()
        # href/src/action attributes
        for match in re.finditer(r'(?:href|src|action)=["\']([^"\']+\?[^"\']+)["\']', html):
            u = match.group(1)
            full = urljoin(base_url, u)
            if urlparse(full).netloc == urlparse(base_url).netloc:
                urls.add(full)
        return list(urls)

    # ── Security Headers ──────────────────────────────────────────────────

    def _check_security_headers(self, headers) -> dict:
        """Check for presence and values of security headers."""
        results = {}
        for h in SECURITY_HEADERS:
            value = headers.get(h, '')
            results[h] = {
                'present': bool(value),
                'value': value,
                'rating': 'good' if value else 'missing',
            }

        # Specific checks
        csp = headers.get('Content-Security-Policy', '')
        if csp:
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                results['Content-Security-Policy']['rating'] = 'weak'

        hsts = headers.get('Strict-Transport-Security', '')
        if hsts:
            if 'max-age' in hsts:
                try:
                    age = int(re.search(r'max-age=(\d+)', hsts).group(1))
                    if age < 31536000:
                        results['Strict-Transport-Security']['rating'] = 'weak'
                except Exception:
                    pass

        return results

    # ── Technology Fingerprinting ─────────────────────────────────────────

    def _fingerprint_tech(self, resp) -> List[str]:
        """Identify technologies from response."""
        techs = []
        headers_str = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
        body = resp.text[:50000]  # Only check first 50KB
        cookies_str = ' '.join(resp.cookies.keys()) if resp.cookies else ''

        for tech, sigs in TECH_SIGNATURES.items():
            found = False
            for h_sig in sigs['headers']:
                if h_sig.lower() in headers_str.lower():
                    found = True
                    break
            if not found:
                for b_sig in sigs['body']:
                    if b_sig.lower() in body.lower():
                        found = True
                        break
            if not found:
                for c_sig in sigs['cookies']:
                    if c_sig.lower() in cookies_str.lower():
                        found = True
                        break
            if found:
                techs.append(tech)

        return techs

    # ── SSL/TLS Audit ─────────────────────────────────────────────────────

    def _check_ssl(self, hostname: str, port: int = 443) -> dict:
        """Check SSL/TLS configuration."""
        result = {
            'valid': False,
            'issuer': '',
            'subject': '',
            'expires': '',
            'protocol': '',
            'cipher': '',
            'issues': [],
        }
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname, port))
                cert = s.getpeercert(True)
                result['protocol'] = s.version()
                result['cipher'] = s.cipher()[0] if s.cipher() else ''

            # Try with verification
            ctx2 = ssl.create_default_context()
            try:
                with ctx2.wrap_socket(socket.socket(), server_hostname=hostname) as s2:
                    s2.settimeout(5)
                    s2.connect((hostname, port))
                    cert = s2.getpeercert()
                    result['valid'] = True
                    result['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    result['subject'] = dict(x[0] for x in cert.get('subject', []))
                    result['expires'] = cert.get('notAfter', '')
            except ssl.SSLCertVerificationError as e:
                result['issues'].append(f'Certificate validation failed: {e}')

            # Check for weak protocols
            if result['protocol'] in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                result['issues'].append(f'Weak protocol: {result["protocol"]}')

        except Exception as e:
            result['error'] = str(e)

        return result

    # ── Crawler ───────────────────────────────────────────────────────────

    def crawl(self, url: str, max_pages: int = 50, depth: int = 3) -> dict:
        """Spider a website and build a sitemap."""
        if not _HAS_REQUESTS:
            return {'ok': False, 'error': 'requests library required'}

        url = self._normalize_url(url)
        base_domain = urlparse(url).netloc
        visited: Set[str] = set()
        pages = []
        queue = [(url, 0)]
        sess = self._get_session()

        while queue and len(visited) < max_pages:
            current_url, current_depth = queue.pop(0)
            if current_url in visited or current_depth > depth:
                continue
            visited.add(current_url)

            try:
                r = sess.get(current_url, timeout=5, allow_redirects=True)
                page = {
                    'url': current_url,
                    'status': r.status_code,
                    'content_type': r.headers.get('Content-Type', ''),
                    'size': len(r.content),
                    'title': '',
                    'forms': 0,
                    'links_out': 0,
                }
                # Extract title
                title_match = re.search(r'<title[^>]*>([^<]+)</title>', r.text, re.I)
                if title_match:
                    page['title'] = title_match.group(1).strip()

                # Count forms
                page['forms'] = len(re.findall(r'<form', r.text, re.I))

                # Extract links for further crawling
                links = re.findall(r'href=["\']([^"\']+)["\']', r.text)
                outlinks = 0
                for link in links:
                    full_link = urljoin(current_url, link)
                    parsed = urlparse(full_link)
                    if parsed.netloc == base_domain:
                        clean = f'{parsed.scheme}://{parsed.netloc}{parsed.path}'
                        if clean not in visited:
                            queue.append((clean, current_depth + 1))
                    else:
                        outlinks += 1
                page['links_out'] = outlinks
                pages.append(page)

            except Exception:
                continue

        return {
            'ok': True,
            'url': url,
            'pages_crawled': len(pages),
            'pages': pages,
        }

    # ── Job Management ────────────────────────────────────────────────────

    def get_job_status(self, job_id: str) -> dict:
        holder = self._active_jobs.get(job_id)
        if not holder:
            return {'ok': False, 'error': 'Job not found'}
        result = {
            'ok': True,
            'done': holder['done'],
            'tested': holder['tested'],
            'total': holder['total'],
            'found': holder['found'],
        }
        if holder['done']:
            self._active_jobs.pop(job_id, None)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _normalize_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_webapp_scanner() -> WebAppScanner:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = WebAppScanner()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Web Application Scanner."""
    svc = get_webapp_scanner()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║      WEB APPLICATION SCANNER          ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — Quick Scan (headers + tech)      ║")
        print("║  2 — Directory Bruteforce              ║")
        print("║  3 — Subdomain Enumeration            ║")
        print("║  4 — Vulnerability Scan (SQLi/XSS)    ║")
        print("║  5 — Crawl / Spider                   ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            url = input("  URL: ").strip()
            if not url:
                continue
            print("  Scanning...")
            r = svc.quick_scan(url)
            print(f"\n  Status: {r.get('status_code')}")
            print(f"  Server: {r.get('server', 'unknown')}")
            if r.get('technologies'):
                print(f"  Technologies: {', '.join(r['technologies'])}")
            if r.get('security_headers'):
                print("  Security Headers:")
                for h, info in r['security_headers'].items():
                    mark = '\033[92m✓\033[0m' if info['present'] else '\033[91m✗\033[0m'
                    print(f"    {mark} {h}")
            if r.get('ssl'):
                ssl_info = r['ssl']
                print(f"  SSL: {'Valid' if ssl_info.get('valid') else 'INVALID'} "
                      f"({ssl_info.get('protocol', '?')})")
                for issue in ssl_info.get('issues', []):
                    print(f"    [!] {issue}")
        elif choice == '2':
            url = input("  URL: ").strip()
            if not url:
                continue
            print("  Starting directory bruteforce...")
            r = svc.dir_bruteforce(url)
            if r.get('job_id'):
                while True:
                    time.sleep(2)
                    s = svc.get_job_status(r['job_id'])
                    print(f"  [{s['tested']}/{s['total']}] Found: {len(s['found'])}", end='\r')
                    if s['done']:
                        print()
                        for item in s['found']:
                            print(f"    [{item['status']}] {item['path']} ({item['size']} bytes)")
                        break
        elif choice == '3':
            domain = input("  Domain: ").strip()
            if not domain:
                continue
            print("  Enumerating subdomains...")
            r = svc.subdomain_enum(domain)
            print(f"\n  Found {r['count']} subdomains:")
            for sub in r.get('subdomains', []):
                print(f"    {sub}")
        elif choice == '4':
            url = input("  URL: ").strip()
            if not url:
                continue
            print("  Scanning for vulnerabilities...")
            r = svc.vuln_scan(url)
            if r.get('findings'):
                print(f"\n  Found {len(r['findings'])} potential vulnerabilities:")
                for f in r['findings']:
                    print(f"    [{f['severity'].upper()}] {f['type'].upper()}: {f['description']}")
                    print(f"      Parameter: {f.get('parameter', '?')}, Payload: {f.get('payload', '?')}")
            else:
                print("  No vulnerabilities found in tested parameters.")
        elif choice == '5':
            url = input("  URL: ").strip()
            if not url:
                continue
            max_pages = int(input("  Max pages (default 50): ").strip() or '50')
            print("  Crawling...")
            r = svc.crawl(url, max_pages=max_pages)
            print(f"\n  Crawled {r.get('pages_crawled', 0)} pages:")
            for page in r.get('pages', []):
                print(f"    [{page['status']}] {page['url']}"
                      f"  ({page['size']} bytes, {page['forms']} forms)")
