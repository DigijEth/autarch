"""
AUTARCH MITM Proxy

HTTP/HTTPS interception proxy with SSL stripping, request/response
modification, traffic logging, WebSocket interception, and upstream chaining.
"""

import os
import sys
import re
import json
import time
import signal
import socket
import ssl
import threading
import subprocess
import uuid
import http.server
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime
from http.client import HTTPConnection, HTTPSConnection

# Module metadata
DESCRIPTION = "HTTP(S) interception proxy & traffic analysis"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner

try:
    from core.paths import get_data_dir, find_tool
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

    def find_tool(name):
        import shutil
        return shutil.which(name)


# ── Secret detection patterns ────────────────────────────────────────────

SECRET_PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 'API Key'),
    (r'(?i)(?:auth(?:orization)?|bearer)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})', 'Auth Token'),
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?(\S{4,})', 'Password'),
    (r'(?i)(?:secret|client_secret)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 'Secret'),
    (r'(?i)(?:token|access_token|refresh_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{16,})', 'Token'),
    (r'(?i)(?:aws_access_key_id)\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})', 'AWS Key'),
    (r'(?i)(?:aws_secret_access_key)\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', 'AWS Secret'),
    (r'(?i)(sk-[A-Za-z0-9]{32,})', 'OpenAI Key'),
    (r'(?i)(ghp_[A-Za-z0-9]{36,})', 'GitHub PAT'),
    (r'(?i)(glpat-[A-Za-z0-9_\-]{20,})', 'GitLab PAT'),
    (r'(?i)(?:session|sess_id|sessionid)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{16,})', 'Session ID'),
    (r'(?i)(?:cookie)\s*[:=]\s*["\']?(\S{16,})', 'Cookie'),
    (r'Authorization:\s*(Basic\s+[A-Za-z0-9+/=]+)', 'Basic Auth Header'),
    (r'Authorization:\s*(Bearer\s+[A-Za-z0-9_\-\.]+)', 'Bearer Auth Header'),
    (r'(?i)(?:private[_-]?key)\s*[:=]\s*["\']?(\S{16,})', 'Private Key'),
    (r'(?i)(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)', 'JWT Token'),
]

_COMPILED_SECRETS = [(re.compile(p), label) for p, label in SECRET_PATTERNS]


# ── Built-in Proxy Handler ───────────────────────────────────────────────

class _ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP proxy request handler that logs traffic and applies rules."""

    # Shared state — set by MITMProxy before starting the server
    mitm = None

    def log_message(self, fmt, *args):
        """Suppress default stderr logging."""
        pass

    def _get_upstream(self):
        """Return (host, port) for upstream proxy or None."""
        if self.mitm and self.mitm._upstream_proxy:
            return self.mitm._upstream_proxy
        return None

    def _read_body(self):
        """Read request body if Content-Length is present."""
        length = self.headers.get('Content-Length')
        if length:
            try:
                return self.rfile.read(int(length))
            except Exception:
                return b''
        return b''

    def _apply_rules(self, method, url, req_headers, req_body, resp_status=None,
                     resp_headers=None, resp_body=None, phase='request'):
        """Apply matching modification rules. Returns modified values."""
        if not self.mitm:
            return req_headers, req_body, resp_headers, resp_body, None

        for rule in self.mitm._rules:
            if not rule.get('enabled', True):
                continue

            # URL match
            url_pattern = rule.get('match_url', '')
            if url_pattern:
                try:
                    if not re.search(url_pattern, url, re.IGNORECASE):
                        continue
                except re.error:
                    continue

            # Method match
            match_method = rule.get('match_method', '')
            if match_method and match_method.upper() != 'ANY':
                if method.upper() != match_method.upper():
                    continue

            action = rule.get('action', '')
            params = rule.get('params', {})

            if action == 'block':
                return req_headers, req_body, resp_headers, resp_body, 'block'

            if action == 'redirect' and phase == 'request':
                return req_headers, req_body, resp_headers, resp_body, params.get('target_url', url)

            if action == 'modify_header' and phase == 'request':
                header_name = params.get('header_name', '')
                header_value = params.get('header_value', '')
                if header_name and req_headers is not None:
                    req_headers[header_name] = header_value

            if action == 'inject_header' and phase == 'response':
                header_name = params.get('header_name', '')
                header_value = params.get('header_value', '')
                if header_name and resp_headers is not None:
                    resp_headers[header_name] = header_value

            if action == 'modify_body' and phase == 'response':
                search = params.get('search', '')
                replace = params.get('replace', '')
                if search and resp_body is not None:
                    try:
                        if isinstance(resp_body, bytes):
                            resp_body = resp_body.replace(
                                search.encode('utf-8', errors='replace'),
                                replace.encode('utf-8', errors='replace')
                            )
                        else:
                            resp_body = resp_body.replace(search, replace)
                    except Exception:
                        pass

        return req_headers, req_body, resp_headers, resp_body, None

    def _handle_request(self, method):
        """Handle all HTTP methods."""
        start_time = time.time()
        url = self.path
        req_body = self._read_body()

        # Convert headers to dict
        req_headers = {}
        for key in self.headers:
            req_headers[key] = self.headers[key]

        # Apply request-phase rules
        req_headers, req_body, _, _, action = self._apply_rules(
            method, url, req_headers, req_body, phase='request'
        )

        # Handle block action
        if action == 'block':
            self.send_response(403)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Blocked by AUTARCH MITM Proxy')
            if self.mitm:
                self.mitm._log_traffic(method, url, 403, req_headers,
                                       req_body, {}, b'Blocked', 0, start_time)
            return

        # Handle redirect action
        if action and action != 'block':
            self.send_response(302)
            self.send_header('Location', action)
            self.end_headers()
            if self.mitm:
                self.mitm._log_traffic(method, url, 302, req_headers,
                                       req_body, {'Location': action}, b'', 0, start_time)
            return

        # SSL strip: rewrite HTTPS URLs to HTTP in the request
        if self.mitm and self.mitm._ssl_strip:
            url = url.replace('https://', 'http://')

        # Forward the request
        try:
            parsed = urllib.parse.urlparse(url)
            target_host = parsed.hostname or 'localhost'
            target_port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            target_path = parsed.path
            if parsed.query:
                target_path += '?' + parsed.query

            upstream = self._get_upstream()

            if upstream:
                # Route through upstream proxy
                conn = HTTPConnection(upstream[0], upstream[1], timeout=30)
                conn.request(method, url, body=req_body if req_body else None,
                             headers=req_headers)
            elif parsed.scheme == 'https':
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = HTTPSConnection(target_host, target_port, timeout=30,
                                       context=ctx)
                conn.request(method, target_path, body=req_body if req_body else None,
                             headers=req_headers)
            else:
                conn = HTTPConnection(target_host, target_port, timeout=30)
                conn.request(method, target_path, body=req_body if req_body else None,
                             headers=req_headers)

            resp = conn.getresponse()
            resp_body = resp.read()
            resp_status = resp.status
            resp_headers = dict(resp.getheaders())

            # Apply response-phase rules
            _, _, resp_headers, resp_body, _ = self._apply_rules(
                method, url, req_headers, req_body,
                resp_status=resp_status, resp_headers=resp_headers,
                resp_body=resp_body, phase='response'
            )

            # SSL strip: rewrite HTTPS links to HTTP in response body
            if self.mitm and self.mitm._ssl_strip and resp_body:
                resp_body = resp_body.replace(b'https://', b'http://')

            # Send response back to client
            self.send_response(resp_status)
            for key, value in resp_headers.items():
                if key.lower() in ('transfer-encoding', 'content-length',
                                   'content-encoding'):
                    continue
                self.send_header(key, value)
            self.send_header('Content-Length', str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

            # Log traffic
            if self.mitm:
                self.mitm._log_traffic(method, url, resp_status, req_headers,
                                       req_body, resp_headers, resp_body,
                                       len(resp_body), start_time)

            conn.close()

        except Exception as e:
            error_msg = f'MITM Proxy Error: {str(e)}'.encode('utf-8')
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(error_msg)))
            self.end_headers()
            self.wfile.write(error_msg)
            if self.mitm:
                self.mitm._log_traffic(method, url, 502, req_headers,
                                       req_body, {}, error_msg, 0, start_time)

    def do_GET(self):
        self._handle_request('GET')

    def do_POST(self):
        self._handle_request('POST')

    def do_PUT(self):
        self._handle_request('PUT')

    def do_DELETE(self):
        self._handle_request('DELETE')

    def do_PATCH(self):
        self._handle_request('PATCH')

    def do_HEAD(self):
        self._handle_request('HEAD')

    def do_OPTIONS(self):
        self._handle_request('OPTIONS')

    def do_CONNECT(self):
        """Handle CONNECT for HTTPS tunneling."""
        host_port = self.path.split(':')
        host = host_port[0]
        port = int(host_port[1]) if len(host_port) > 1 else 443

        self.send_response(200, 'Connection Established')
        self.end_headers()

        # Log the CONNECT request
        if self.mitm:
            self.mitm._log_traffic('CONNECT', self.path, 200,
                                   dict(self.headers), b'', {},
                                   b'Tunnel established', 0, time.time())


# ── MITM Proxy Core ──────────────────────────────────────────────────────

class MITMProxy:
    """HTTP/HTTPS interception proxy with traffic logging and rule engine."""

    _instance = None

    def __init__(self):
        self._running = False
        self._process = None
        self._server = None
        self._server_thread = None
        self._listen_host = '127.0.0.1'
        self._listen_port = 8888
        self._upstream_proxy = None
        self._ssl_strip = False
        self._use_mitmdump = False

        # Rules engine
        self._rules = []
        self._next_rule_id = 1

        # Traffic log
        self._traffic = []
        self._traffic_lock = threading.Lock()
        self._next_traffic_id = 1
        self._request_count = 0

        # Certificate storage
        data_dir = Path(get_data_dir()) if callable(get_data_dir) else Path(get_data_dir)
        self._mitm_dir = data_dir / 'mitm'
        self._cert_dir = self._mitm_dir / 'certs'
        self._rules_path = self._mitm_dir / 'rules.json'
        self._traffic_path = self._mitm_dir / 'traffic.json'

        self._mitm_dir.mkdir(parents=True, exist_ok=True)
        self._cert_dir.mkdir(parents=True, exist_ok=True)

        # Load persisted rules
        self._load_rules()

    # ── Proxy Lifecycle ──────────────────────────────────────────────

    def start(self, listen_host='127.0.0.1', listen_port=8888, upstream_proxy=None):
        """Start the MITM proxy.

        Tries mitmdump first; falls back to built-in proxy.
        Returns dict with status info.
        """
        if self._running:
            return {'success': False, 'error': 'Proxy already running',
                    'host': self._listen_host, 'port': self._listen_port}

        self._listen_host = listen_host
        self._listen_port = int(listen_port)

        # Parse upstream proxy
        if upstream_proxy:
            upstream_proxy = upstream_proxy.strip()
            if upstream_proxy:
                parts = upstream_proxy.replace('http://', '').replace('https://', '')
                if ':' in parts:
                    h, p = parts.rsplit(':', 1)
                    try:
                        self._upstream_proxy = (h, int(p))
                    except ValueError:
                        self._upstream_proxy = None
                else:
                    self._upstream_proxy = (parts, 8080)
        else:
            self._upstream_proxy = None

        # Try mitmdump first
        mitmdump_path = find_tool('mitmdump')
        if mitmdump_path:
            return self._start_mitmdump(mitmdump_path)

        # Fall back to built-in proxy
        return self._start_builtin()

    def _start_mitmdump(self, mitmdump_path):
        """Start proxy using mitmdump subprocess."""
        cmd = [
            mitmdump_path,
            '--listen-host', self._listen_host,
            '--listen-port', str(self._listen_port),
            '--set', 'flow_detail=0',
            '--set', f'confdir={str(self._cert_dir)}',
        ]

        if self._upstream_proxy:
            cmd.extend(['--mode', f'upstream:http://{self._upstream_proxy[0]}:{self._upstream_proxy[1]}'])

        if self._ssl_strip:
            cmd.extend(['--ssl-insecure'])

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            time.sleep(1.0)

            if self._process.poll() is not None:
                stderr = self._process.stderr.read().decode('utf-8', errors='replace')
                return {'success': False, 'error': f'mitmdump exited: {stderr}'}

            self._running = True
            self._use_mitmdump = True
            return {
                'success': True,
                'message': f'Proxy started (mitmdump) on {self._listen_host}:{self._listen_port}',
                'host': self._listen_host,
                'port': self._listen_port,
                'engine': 'mitmdump',
                'pid': self._process.pid,
            }
        except Exception as e:
            return {'success': False, 'error': f'Failed to start mitmdump: {str(e)}'}

    def _start_builtin(self):
        """Start proxy using built-in HTTP server."""
        try:
            _ProxyRequestHandler.mitm = self

            server = http.server.HTTPServer(
                (self._listen_host, self._listen_port),
                _ProxyRequestHandler
            )
            server.timeout = 1

            self._server = server
            self._running = True
            self._use_mitmdump = False

            def serve():
                while self._running:
                    try:
                        server.handle_request()
                    except Exception:
                        if self._running:
                            continue
                        break

            self._server_thread = threading.Thread(target=serve, daemon=True,
                                                   name='mitm-proxy')
            self._server_thread.start()

            return {
                'success': True,
                'message': f'Proxy started (built-in) on {self._listen_host}:{self._listen_port}',
                'host': self._listen_host,
                'port': self._listen_port,
                'engine': 'builtin',
            }
        except OSError as e:
            self._running = False
            return {'success': False, 'error': f'Failed to bind {self._listen_host}:{self._listen_port}: {str(e)}'}
        except Exception as e:
            self._running = False
            return {'success': False, 'error': f'Failed to start proxy: {str(e)}'}

    def stop(self):
        """Stop the MITM proxy."""
        if not self._running:
            return {'success': False, 'error': 'Proxy is not running'}

        self._running = False

        # Kill mitmdump process
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        # Shutdown built-in server
        if self._server:
            try:
                self._server.server_close()
            except Exception:
                pass
            self._server = None

        if self._server_thread:
            self._server_thread.join(timeout=3)
            self._server_thread = None

        _ProxyRequestHandler.mitm = None

        return {'success': True, 'message': 'Proxy stopped'}

    def is_running(self):
        """Check if proxy is active."""
        if self._process:
            if self._process.poll() is not None:
                self._running = False
                self._process = None
        return self._running

    def get_status(self):
        """Return proxy status information."""
        return {
            'running': self.is_running(),
            'host': self._listen_host,
            'port': self._listen_port,
            'engine': 'mitmdump' if self._use_mitmdump else 'builtin',
            'request_count': self._request_count,
            'traffic_entries': len(self._traffic),
            'rules_count': len(self._rules),
            'ssl_strip': self._ssl_strip,
            'upstream_proxy': f'{self._upstream_proxy[0]}:{self._upstream_proxy[1]}' if self._upstream_proxy else None,
            'pid': self._process.pid if self._process else None,
        }

    # ── Certificate Management ───────────────────────────────────────

    def generate_ca_cert(self):
        """Generate a CA certificate for HTTPS interception.

        Uses the cryptography library to create a self-signed CA cert.
        Returns dict with cert info or error.
        """
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            import datetime as dt

            # Generate RSA private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )

            # Build CA certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Cyberspace'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'AUTARCH MITM CA'),
                x509.NameAttribute(NameOID.COMMON_NAME, 'AUTARCH Interception CA'),
            ])

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(dt.datetime.utcnow())
                .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True, key_cert_sign=True,
                        crl_sign=True, key_encipherment=False,
                        content_commitment=False, data_encipherment=False,
                        key_agreement=False, encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True,
                )
                .sign(key, hashes.SHA256(), default_backend())
            )

            # Save private key
            key_path = self._cert_dir / 'ca-key.pem'
            with open(key_path, 'wb') as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Save certificate
            cert_path = self._cert_dir / 'ca-cert.pem'
            with open(cert_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            # Save DER format for browser import
            der_path = self._cert_dir / 'ca-cert.der'
            with open(der_path, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.DER))

            return {
                'success': True,
                'message': 'CA certificate generated',
                'cert_path': str(cert_path),
                'key_path': str(key_path),
                'der_path': str(der_path),
                'subject': 'AUTARCH Interception CA',
                'valid_days': 3650,
            }

        except ImportError:
            return {'success': False, 'error': 'cryptography library not installed (pip install cryptography)'}
        except Exception as e:
            return {'success': False, 'error': f'Failed to generate certificate: {str(e)}'}

    def get_ca_cert(self):
        """Return CA certificate content for client installation."""
        cert_path = self._cert_dir / 'ca-cert.pem'
        der_path = self._cert_dir / 'ca-cert.der'

        if not cert_path.exists():
            return {'success': False, 'error': 'No CA certificate found. Generate one first.'}

        try:
            with open(cert_path, 'r') as f:
                pem_data = f.read()

            result = {
                'success': True,
                'pem': pem_data,
                'pem_path': str(cert_path),
            }

            if der_path.exists():
                import base64
                with open(der_path, 'rb') as f:
                    result['der_b64'] = base64.b64encode(f.read()).decode('ascii')
                result['der_path'] = str(der_path)

            return result

        except Exception as e:
            return {'success': False, 'error': f'Failed to read certificate: {str(e)}'}

    def get_certs(self):
        """List generated interception certificates."""
        certs = []
        if self._cert_dir.exists():
            for f in sorted(self._cert_dir.iterdir()):
                if f.is_file():
                    stat = f.stat()
                    certs.append({
                        'name': f.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'path': str(f),
                    })
        return certs

    # ── Rules Engine ─────────────────────────────────────────────────

    def add_rule(self, rule):
        """Add a modification rule.

        Rule dict keys:
            match_url: regex pattern to match URL
            match_method: HTTP method or 'ANY'
            action: modify_header | modify_body | inject_header | redirect | block
            params: dict with action-specific parameters
        """
        rule_entry = {
            'id': self._next_rule_id,
            'match_url': rule.get('match_url', '.*'),
            'match_method': rule.get('match_method', 'ANY'),
            'action': rule.get('action', 'block'),
            'params': rule.get('params', {}),
            'enabled': True,
            'created': datetime.now().isoformat(),
        }

        # Validate regex
        try:
            re.compile(rule_entry['match_url'])
        except re.error as e:
            return {'success': False, 'error': f'Invalid URL pattern: {str(e)}'}

        # Validate action
        valid_actions = ('modify_header', 'modify_body', 'inject_header', 'redirect', 'block')
        if rule_entry['action'] not in valid_actions:
            return {'success': False, 'error': f'Invalid action. Must be one of: {", ".join(valid_actions)}'}

        self._rules.append(rule_entry)
        self._next_rule_id += 1
        self._save_rules()

        return {'success': True, 'rule': rule_entry}

    def remove_rule(self, rule_id):
        """Remove a rule by ID."""
        rule_id = int(rule_id)
        for i, rule in enumerate(self._rules):
            if rule['id'] == rule_id:
                removed = self._rules.pop(i)
                self._save_rules()
                return {'success': True, 'removed': removed}
        return {'success': False, 'error': f'Rule {rule_id} not found'}

    def list_rules(self):
        """List all active rules."""
        return self._rules

    def enable_rule(self, rule_id):
        """Enable a rule."""
        rule_id = int(rule_id)
        for rule in self._rules:
            if rule['id'] == rule_id:
                rule['enabled'] = True
                self._save_rules()
                return {'success': True, 'rule': rule}
        return {'success': False, 'error': f'Rule {rule_id} not found'}

    def disable_rule(self, rule_id):
        """Disable a rule."""
        rule_id = int(rule_id)
        for rule in self._rules:
            if rule['id'] == rule_id:
                rule['enabled'] = False
                self._save_rules()
                return {'success': True, 'rule': rule}
        return {'success': False, 'error': f'Rule {rule_id} not found'}

    def _save_rules(self):
        """Persist rules to disk."""
        try:
            with open(self._rules_path, 'w') as f:
                json.dump(self._rules, f, indent=2)
        except Exception:
            pass

    def _load_rules(self):
        """Load rules from disk."""
        if self._rules_path.exists():
            try:
                with open(self._rules_path, 'r') as f:
                    self._rules = json.load(f)
                if self._rules:
                    self._next_rule_id = max(r.get('id', 0) for r in self._rules) + 1
            except Exception:
                self._rules = []

    # ── Traffic Logging ──────────────────────────────────────────────

    def _log_traffic(self, method, url, status, req_headers, req_body,
                     resp_headers, resp_body, size, start_time):
        """Log a traffic entry."""
        duration = round((time.time() - start_time) * 1000, 1)

        # Safely encode body content for JSON storage
        def safe_body(body):
            if body is None:
                return ''
            if isinstance(body, bytes):
                try:
                    return body.decode('utf-8', errors='replace')[:10000]
                except Exception:
                    return f'<binary {len(body)} bytes>'
            return str(body)[:10000]

        # Detect secrets
        secrets = self._scan_for_secrets(req_headers, req_body, resp_headers, resp_body)

        entry = {
            'id': self._next_traffic_id,
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'url': url,
            'status': status,
            'request_headers': dict(req_headers) if isinstance(req_headers, dict) else {},
            'request_body': safe_body(req_body),
            'response_headers': dict(resp_headers) if isinstance(resp_headers, dict) else {},
            'response_body': safe_body(resp_body),
            'size': size,
            'duration': duration,
            'secrets_found': secrets,
        }

        with self._traffic_lock:
            self._traffic.append(entry)
            self._next_traffic_id += 1
            self._request_count += 1

            # Keep max 10000 entries in memory
            if len(self._traffic) > 10000:
                self._traffic = self._traffic[-5000:]

    def get_traffic(self, limit=100, offset=0, filter_url=None, filter_method=None,
                    filter_status=None):
        """Return captured traffic entries with optional filtering."""
        with self._traffic_lock:
            entries = list(self._traffic)

        # Apply filters
        if filter_url:
            try:
                pattern = re.compile(filter_url, re.IGNORECASE)
                entries = [e for e in entries if pattern.search(e.get('url', ''))]
            except re.error:
                entries = [e for e in entries if filter_url.lower() in e.get('url', '').lower()]

        if filter_method:
            entries = [e for e in entries if e.get('method', '').upper() == filter_method.upper()]

        if filter_status:
            try:
                status_code = int(filter_status)
                entries = [e for e in entries if e.get('status') == status_code]
            except (ValueError, TypeError):
                pass

        # Sort by most recent first
        entries = list(reversed(entries))

        total = len(entries)
        entries = entries[offset:offset + limit]

        # Strip bodies from list view for performance
        summary = []
        for e in entries:
            summary.append({
                'id': e['id'],
                'timestamp': e['timestamp'],
                'method': e['method'],
                'url': e['url'][:200],
                'status': e['status'],
                'size': e['size'],
                'duration': e['duration'],
                'secrets_found': len(e.get('secrets_found', [])) > 0,
            })

        return {'entries': summary, 'total': total, 'limit': limit, 'offset': offset}

    def get_request(self, request_id):
        """Get full request/response details for a traffic entry."""
        request_id = int(request_id)
        with self._traffic_lock:
            for entry in self._traffic:
                if entry['id'] == request_id:
                    return {'success': True, 'entry': entry}
        return {'success': False, 'error': f'Request {request_id} not found'}

    def clear_traffic(self):
        """Clear traffic log."""
        with self._traffic_lock:
            self._traffic.clear()
            self._request_count = 0
        return {'success': True, 'message': 'Traffic log cleared'}

    def export_traffic(self, fmt='json'):
        """Export traffic log."""
        with self._traffic_lock:
            entries = list(self._traffic)

        if fmt == 'json':
            return {
                'success': True,
                'format': 'json',
                'data': json.dumps(entries, indent=2),
                'count': len(entries),
            }
        elif fmt == 'csv':
            import io
            import csv
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['id', 'timestamp', 'method', 'url', 'status',
                             'size', 'duration', 'secrets'])
            for e in entries:
                writer.writerow([
                    e['id'], e['timestamp'], e['method'], e['url'],
                    e['status'], e['size'], e['duration'],
                    len(e.get('secrets_found', []))
                ])
            return {
                'success': True,
                'format': 'csv',
                'data': output.getvalue(),
                'count': len(entries),
            }
        else:
            return {'success': False, 'error': f'Unsupported format: {fmt}'}

    # ── Secret Detection ─────────────────────────────────────────────

    def _scan_for_secrets(self, req_headers, req_body, resp_headers, resp_body):
        """Scan request/response for secrets and sensitive data."""
        secrets = []
        search_texts = []

        # Collect all text to scan
        if isinstance(req_headers, dict):
            for k, v in req_headers.items():
                search_texts.append(f'{k}: {v}')
        if req_body:
            if isinstance(req_body, bytes):
                try:
                    search_texts.append(req_body.decode('utf-8', errors='replace'))
                except Exception:
                    pass
            else:
                search_texts.append(str(req_body))

        if isinstance(resp_headers, dict):
            for k, v in resp_headers.items():
                search_texts.append(f'{k}: {v}')
        if resp_body:
            if isinstance(resp_body, bytes):
                try:
                    search_texts.append(resp_body.decode('utf-8', errors='replace'))
                except Exception:
                    pass
            else:
                search_texts.append(str(resp_body))

        combined = '\n'.join(search_texts)

        for pattern, label in _COMPILED_SECRETS:
            matches = pattern.findall(combined)
            for match in matches:
                value = match if isinstance(match, str) else match[0]
                # Mask the secret value for display
                if len(value) > 8:
                    masked = value[:4] + '*' * (len(value) - 8) + value[-4:]
                else:
                    masked = value[:2] + '*' * (len(value) - 2)
                secrets.append({
                    'type': label,
                    'value_masked': masked,
                    'location': 'request/response',
                })

        return secrets

    def find_secrets(self, traffic_entry):
        """Scan a specific traffic entry for secrets. Returns list of findings."""
        if isinstance(traffic_entry, (int, str)):
            result = self.get_request(traffic_entry)
            if not result.get('success'):
                return []
            traffic_entry = result['entry']

        return self._scan_for_secrets(
            traffic_entry.get('request_headers', {}),
            traffic_entry.get('request_body', ''),
            traffic_entry.get('response_headers', {}),
            traffic_entry.get('response_body', ''),
        )

    # ── SSL Strip ────────────────────────────────────────────────────

    def ssl_strip_mode(self, enabled=True):
        """Toggle SSL stripping (rewrite HTTPS links to HTTP)."""
        self._ssl_strip = bool(enabled)
        return {
            'success': True,
            'ssl_strip': self._ssl_strip,
            'message': f'SSL stripping {"enabled" if self._ssl_strip else "disabled"}',
        }

    # ── CLI Interface ────────────────────────────────────────────────

    def run(self):
        """Interactive CLI for the MITM Proxy module."""
        while True:
            clear_screen()
            display_banner()
            print(f"\n{Colors.BOLD}{Colors.RED}MITM Proxy{Colors.RESET}")
            print(f"{Colors.DIM}HTTP(S) interception proxy & traffic analysis{Colors.RESET}\n")

            status = self.get_status()
            if status['running']:
                print(f"{Colors.GREEN}[+] Proxy RUNNING on {status['host']}:{status['port']}"
                      f" ({status['engine']}){Colors.RESET}")
                print(f"    Requests: {status['request_count']}  |  "
                      f"Rules: {status['rules_count']}  |  "
                      f"SSL Strip: {'ON' if status['ssl_strip'] else 'OFF'}")
                if status['upstream_proxy']:
                    print(f"    Upstream: {status['upstream_proxy']}")
            else:
                print(f"{Colors.YELLOW}[-] Proxy STOPPED{Colors.RESET}")

            print(f"\n{Colors.CYAN}1{Colors.RESET} Start Proxy")
            print(f"{Colors.CYAN}2{Colors.RESET} Stop Proxy")
            print(f"{Colors.CYAN}3{Colors.RESET} Add Rule")
            print(f"{Colors.CYAN}4{Colors.RESET} View Traffic")
            print(f"{Colors.CYAN}5{Colors.RESET} Find Secrets")
            print(f"{Colors.CYAN}6{Colors.RESET} Generate CA Certificate")
            print(f"{Colors.CYAN}7{Colors.RESET} Toggle SSL Strip")
            print(f"{Colors.CYAN}8{Colors.RESET} List Rules")
            print(f"{Colors.CYAN}0{Colors.RESET} Back\n")

            try:
                choice = input(f"{Colors.WHITE}Choice: {Colors.RESET}").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice == '0':
                break

            elif choice == '1':
                if status['running']:
                    print(f"\n{Colors.YELLOW}Proxy is already running.{Colors.RESET}")
                else:
                    host = input(f"Listen host [{self._listen_host}]: ").strip() or self._listen_host
                    port = input(f"Listen port [{self._listen_port}]: ").strip() or str(self._listen_port)
                    upstream = input("Upstream proxy (host:port, blank for none): ").strip() or None
                    result = self.start(host, int(port), upstream)
                    if result['success']:
                        print(f"\n{Colors.GREEN}[+] {result['message']}{Colors.RESET}")
                    else:
                        print(f"\n{Colors.RED}[-] {result['error']}{Colors.RESET}")

            elif choice == '2':
                result = self.stop()
                if result['success']:
                    print(f"\n{Colors.GREEN}[+] {result['message']}{Colors.RESET}")
                else:
                    print(f"\n{Colors.YELLOW}[-] {result['error']}{Colors.RESET}")

            elif choice == '3':
                print(f"\n{Colors.BOLD}Add Modification Rule{Colors.RESET}")
                url_pattern = input("URL pattern (regex): ").strip() or '.*'
                method = input("Method filter (GET/POST/ANY): ").strip().upper() or 'ANY'
                print("Actions: block, redirect, modify_header, inject_header, modify_body")
                action = input("Action: ").strip().lower()
                params = {}
                if action == 'redirect':
                    params['target_url'] = input("Redirect URL: ").strip()
                elif action in ('modify_header', 'inject_header'):
                    params['header_name'] = input("Header name: ").strip()
                    params['header_value'] = input("Header value: ").strip()
                elif action == 'modify_body':
                    params['search'] = input("Search string: ").strip()
                    params['replace'] = input("Replace with: ").strip()

                result = self.add_rule({
                    'match_url': url_pattern,
                    'match_method': method,
                    'action': action,
                    'params': params,
                })
                if result['success']:
                    print(f"\n{Colors.GREEN}[+] Rule added (ID: {result['rule']['id']}){Colors.RESET}")
                else:
                    print(f"\n{Colors.RED}[-] {result['error']}{Colors.RESET}")

            elif choice == '4':
                traffic = self.get_traffic(limit=20)
                entries = traffic.get('entries', [])
                if not entries:
                    print(f"\n{Colors.YELLOW}No traffic captured yet.{Colors.RESET}")
                else:
                    print(f"\n{Colors.BOLD}Recent Traffic ({traffic['total']} total){Colors.RESET}\n")
                    print(f"{'ID':>5}  {'Method':<8} {'Status':<7} {'Size':>8}  {'URL'}")
                    print("-" * 80)
                    for e in entries:
                        secrets_flag = ' *' if e.get('secrets_found') else ''
                        print(f"{e['id']:>5}  {e['method']:<8} {e['status']:<7} "
                              f"{e['size']:>8}  {e['url'][:50]}{secrets_flag}")

            elif choice == '5':
                traffic = self.get_traffic(limit=1000)
                entries = traffic.get('entries', [])
                found = [e for e in entries if e.get('secrets_found')]
                if not found:
                    print(f"\n{Colors.YELLOW}No secrets found in captured traffic.{Colors.RESET}")
                else:
                    print(f"\n{Colors.RED}[!] Secrets found in {len(found)} requests:{Colors.RESET}\n")
                    for e in found:
                        req = self.get_request(e['id'])
                        if req.get('success'):
                            full = req['entry']
                            for s in full.get('secrets_found', []):
                                print(f"  {Colors.YELLOW}{s['type']}{Colors.RESET}: "
                                      f"{s['value_masked']}  ({full['method']} {full['url'][:60]})")

            elif choice == '6':
                result = self.generate_ca_cert()
                if result['success']:
                    print(f"\n{Colors.GREEN}[+] {result['message']}{Colors.RESET}")
                    print(f"    Cert: {result['cert_path']}")
                    print(f"    Key:  {result['key_path']}")
                else:
                    print(f"\n{Colors.RED}[-] {result['error']}{Colors.RESET}")

            elif choice == '7':
                self._ssl_strip = not self._ssl_strip
                state = 'ENABLED' if self._ssl_strip else 'DISABLED'
                color = Colors.GREEN if self._ssl_strip else Colors.YELLOW
                print(f"\n{color}[*] SSL Strip mode {state}{Colors.RESET}")

            elif choice == '8':
                rules = self.list_rules()
                if not rules:
                    print(f"\n{Colors.YELLOW}No rules configured.{Colors.RESET}")
                else:
                    print(f"\n{Colors.BOLD}Active Rules{Colors.RESET}\n")
                    for r in rules:
                        state = f"{Colors.GREEN}ON{Colors.RESET}" if r['enabled'] else f"{Colors.RED}OFF{Colors.RESET}"
                        print(f"  [{r['id']}] {state}  {r['action']:<15} "
                              f"{r['match_method']:<6} {r['match_url']}")

            if choice in ('1', '2', '3', '4', '5', '6', '7', '8'):
                try:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                except (EOFError, KeyboardInterrupt):
                    break


# ==================== SINGLETON ====================

_mitm_proxy_instance = None


def get_mitm_proxy():
    """Get or create singleton MITMProxy instance."""
    global _mitm_proxy_instance
    if _mitm_proxy_instance is None:
        _mitm_proxy_instance = MITMProxy()
    return _mitm_proxy_instance


def run():
    get_mitm_proxy().run()


if __name__ == "__main__":
    run()
