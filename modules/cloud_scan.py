"""AUTARCH Cloud Security Scanner

AWS/Azure/GCP bucket enumeration, IAM misconfiguration detection, exposed
service scanning, and cloud resource discovery.
"""

DESCRIPTION = "Cloud infrastructure security scanning"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Cloud Provider Endpoints ─────────────────────────────────────────────────

AWS_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1',
]

COMMON_BUCKET_NAMES = [
    'backup', 'backups', 'data', 'dev', 'staging', 'prod', 'production',
    'logs', 'assets', 'media', 'uploads', 'images', 'static', 'public',
    'private', 'internal', 'config', 'configs', 'db', 'database',
    'archive', 'old', 'temp', 'tmp', 'test', 'debug', 'admin',
    'www', 'web', 'api', 'app', 'mobile', 'docs', 'documents',
    'reports', 'export', 'import', 'share', 'shared',
]

METADATA_ENDPOINTS = {
    'aws': 'http://169.254.169.254/latest/meta-data/',
    'gcp': 'http://metadata.google.internal/computeMetadata/v1/',
    'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    'digitalocean': 'http://169.254.169.254/metadata/v1/',
}


# ── Cloud Scanner ────────────────────────────────────────────────────────────

class CloudScanner:
    """Cloud infrastructure security scanner."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'cloud_scan')
        os.makedirs(self.data_dir, exist_ok=True)
        self.results: List[Dict] = []
        self._jobs: Dict[str, Dict] = {}

    # ── S3 Bucket Enumeration ────────────────────────────────────────────

    def enum_s3_buckets(self, keyword: str, prefixes: List[str] = None,
                        suffixes: List[str] = None) -> str:
        """Enumerate S3 buckets with naming permutations. Returns job_id."""
        if not HAS_REQUESTS:
            return ''

        job_id = f's3enum_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 's3_enum', 'status': 'running',
            'found': [], 'checked': 0, 'total': 0
        }

        def _enum():
            prefixes_list = prefixes or ['', 'dev-', 'staging-', 'prod-', 'test-', 'backup-']
            suffixes_list = suffixes or ['', '-backup', '-data', '-assets', '-logs', '-dev',
                                          '-staging', '-prod', '-public', '-private']

            bucket_names = set()
            for pfx in prefixes_list:
                for sfx in suffixes_list:
                    bucket_names.add(f'{pfx}{keyword}{sfx}')
            # Add common patterns
            for common in COMMON_BUCKET_NAMES:
                bucket_names.add(f'{keyword}-{common}')
                bucket_names.add(f'{common}-{keyword}')

            self._jobs[job_id]['total'] = len(bucket_names)
            found = []

            for name in bucket_names:
                try:
                    # Check S3 bucket
                    url = f'https://{name}.s3.amazonaws.com'
                    resp = requests.head(url, timeout=5, allow_redirects=True)
                    self._jobs[job_id]['checked'] += 1

                    if resp.status_code == 200:
                        # Try listing
                        list_resp = requests.get(url, timeout=5)
                        listable = '<ListBucketResult' in list_resp.text

                        found.append({
                            'bucket': name, 'provider': 'aws',
                            'url': url, 'status': resp.status_code,
                            'listable': listable, 'public': True
                        })
                    elif resp.status_code == 403:
                        found.append({
                            'bucket': name, 'provider': 'aws',
                            'url': url, 'status': 403,
                            'listable': False, 'public': False,
                            'exists': True
                        })
                except Exception:
                    self._jobs[job_id]['checked'] += 1

            self._jobs[job_id]['found'] = found
            self._jobs[job_id]['status'] = 'complete'

        threading.Thread(target=_enum, daemon=True).start()
        return job_id

    # ── GCS Bucket Enumeration ───────────────────────────────────────────

    def enum_gcs_buckets(self, keyword: str) -> str:
        """Enumerate Google Cloud Storage buckets. Returns job_id."""
        if not HAS_REQUESTS:
            return ''

        job_id = f'gcsenum_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'gcs_enum', 'status': 'running',
            'found': [], 'checked': 0, 'total': 0
        }

        def _enum():
            names = set()
            for suffix in ['', '-data', '-backup', '-assets', '-staging', '-prod', '-dev', '-logs']:
                names.add(f'{keyword}{suffix}')

            self._jobs[job_id]['total'] = len(names)
            found = []

            for name in names:
                try:
                    url = f'https://storage.googleapis.com/{name}'
                    resp = requests.head(url, timeout=5)
                    self._jobs[job_id]['checked'] += 1

                    if resp.status_code in (200, 403):
                        found.append({
                            'bucket': name, 'provider': 'gcp',
                            'url': url, 'status': resp.status_code,
                            'public': resp.status_code == 200
                        })
                except Exception:
                    self._jobs[job_id]['checked'] += 1

            self._jobs[job_id]['found'] = found
            self._jobs[job_id]['status'] = 'complete'

        threading.Thread(target=_enum, daemon=True).start()
        return job_id

    # ── Azure Blob Enumeration ───────────────────────────────────────────

    def enum_azure_blobs(self, keyword: str) -> str:
        """Enumerate Azure Blob Storage containers. Returns job_id."""
        if not HAS_REQUESTS:
            return ''

        job_id = f'azureenum_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'azure_enum', 'status': 'running',
            'found': [], 'checked': 0, 'total': 0
        }

        def _enum():
            # Storage account names
            accounts = [keyword, f'{keyword}storage', f'{keyword}data',
                        f'{keyword}backup', f'{keyword}dev', f'{keyword}prod']
            containers = ['$web', 'data', 'backup', 'uploads', 'assets',
                           'logs', 'public', 'media', 'images']

            total = len(accounts) * len(containers)
            self._jobs[job_id]['total'] = total
            found = []

            for account in accounts:
                for container in containers:
                    try:
                        url = f'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list'
                        resp = requests.get(url, timeout=5)
                        self._jobs[job_id]['checked'] += 1

                        if resp.status_code == 200:
                            found.append({
                                'account': account, 'container': container,
                                'provider': 'azure', 'url': url,
                                'status': resp.status_code, 'public': True
                            })
                        elif resp.status_code == 403:
                            found.append({
                                'account': account, 'container': container,
                                'provider': 'azure', 'url': url,
                                'status': 403, 'exists': True, 'public': False
                            })
                    except Exception:
                        self._jobs[job_id]['checked'] += 1

            self._jobs[job_id]['found'] = found
            self._jobs[job_id]['status'] = 'complete'

        threading.Thread(target=_enum, daemon=True).start()
        return job_id

    # ── Exposed Services ─────────────────────────────────────────────────

    def scan_exposed_services(self, target: str) -> Dict:
        """Check for commonly exposed cloud services on a target."""
        if not HAS_REQUESTS:
            return {'ok': False, 'error': 'requests not available'}

        services = []
        checks = [
            ('/server-status', 'Apache Status'),
            ('/nginx_status', 'Nginx Status'),
            ('/.env', 'Environment File'),
            ('/.git/config', 'Git Config'),
            ('/.aws/credentials', 'AWS Credentials'),
            ('/wp-config.php.bak', 'WordPress Config Backup'),
            ('/phpinfo.php', 'PHP Info'),
            ('/debug', 'Debug Endpoint'),
            ('/actuator', 'Spring Actuator'),
            ('/actuator/env', 'Spring Env'),
            ('/api/swagger.json', 'Swagger/OpenAPI Spec'),
            ('/.well-known/security.txt', 'Security Policy'),
            ('/robots.txt', 'Robots.txt'),
            ('/sitemap.xml', 'Sitemap'),
            ('/graphql', 'GraphQL Endpoint'),
            ('/console', 'Console'),
            ('/admin', 'Admin Panel'),
            ('/wp-admin', 'WordPress Admin'),
            ('/phpmyadmin', 'phpMyAdmin'),
        ]

        for path, name in checks:
            try:
                url = f'{target.rstrip("/")}{path}'
                resp = requests.get(url, timeout=5, allow_redirects=False)
                if resp.status_code == 200:
                    # Check content for sensitive data
                    sensitive = False
                    body = resp.text[:2000].lower()
                    sensitive_indicators = [
                        'password', 'secret', 'access_key', 'private_key',
                        'database', 'db_host', 'smtp_pass', 'api_key'
                    ]
                    if any(ind in body for ind in sensitive_indicators):
                        sensitive = True

                    services.append({
                        'path': path, 'name': name,
                        'url': url, 'status': resp.status_code,
                        'size': len(resp.content),
                        'sensitive': sensitive,
                        'content_type': resp.headers.get('content-type', '')
                    })
            except Exception:
                pass

        return {
            'ok': True,
            'target': target,
            'services': services,
            'count': len(services)
        }

    # ── Metadata SSRF Check ──────────────────────────────────────────────

    def check_metadata_access(self) -> Dict:
        """Check if cloud metadata service is accessible (SSRF indicator)."""
        results = {}
        for provider, url in METADATA_ENDPOINTS.items():
            try:
                headers = {}
                if provider == 'gcp':
                    headers['Metadata-Flavor'] = 'Google'

                resp = requests.get(url, headers=headers, timeout=3)
                results[provider] = {
                    'accessible': resp.status_code == 200,
                    'status': resp.status_code,
                    'content_preview': resp.text[:200] if resp.status_code == 200 else ''
                }
            except Exception:
                results[provider] = {'accessible': False, 'error': 'Connection failed'}

        return {'ok': True, 'metadata': results}

    # ── Subdomain / DNS Enumeration for Cloud ────────────────────────────

    def enum_cloud_subdomains(self, domain: str) -> Dict:
        """Check for cloud-specific subdomains."""
        if not HAS_REQUESTS:
            return {'ok': False, 'error': 'requests not available'}

        cloud_prefixes = [
            'aws', 's3', 'ec2', 'lambda', 'api', 'cdn',
            'azure', 'blob', 'cloud', 'gcp', 'storage',
            'dev', 'staging', 'prod', 'admin', 'internal',
            'vpn', 'mail', 'smtp', 'imap', 'ftp', 'ssh',
            'db', 'database', 'redis', 'elastic', 'kibana',
            'grafana', 'prometheus', 'jenkins', 'gitlab', 'docker',
            'k8s', 'kubernetes', 'consul', 'vault', 'traefik',
        ]

        found = []
        import socket
        for prefix in cloud_prefixes:
            subdomain = f'{prefix}.{domain}'
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({
                    'subdomain': subdomain,
                    'ip': ip,
                    'cloud_hint': self._identify_cloud_ip(ip)
                })
            except socket.gaierror:
                pass

        return {'ok': True, 'domain': domain, 'subdomains': found, 'count': len(found)}

    def _identify_cloud_ip(self, ip: str) -> str:
        """Try to identify cloud provider from IP."""
        # Rough range checks
        octets = ip.split('.')
        if len(octets) == 4:
            first = int(octets[0])
            if first in (3, 18, 52, 54, 35):
                return 'AWS'
            elif first in (20, 40, 52, 104, 13):
                return 'Azure'
            elif first in (34, 35, 104, 142):
                return 'GCP'
        return 'Unknown'

    # ── Job Management ───────────────────────────────────────────────────

    def get_job(self, job_id: str) -> Optional[Dict]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[Dict]:
        return [{'id': k, **v} for k, v in self._jobs.items()]

    # ── Save Results ─────────────────────────────────────────────────────

    def save_results(self, name: str, results: Dict) -> Dict:
        """Save scan results."""
        filepath = os.path.join(self.data_dir, f'{name}.json')
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        return {'ok': True, 'path': filepath}


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_cloud_scanner() -> CloudScanner:
    global _instance
    if _instance is None:
        _instance = CloudScanner()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Cloud Security module."""
    if not HAS_REQUESTS:
        print("  Error: requests library required")
        return

    scanner = get_cloud_scanner()

    while True:
        print(f"\n{'='*60}")
        print(f"  Cloud Security Scanner")
        print(f"{'='*60}")
        print()
        print("  1 — Enumerate S3 Buckets (AWS)")
        print("  2 — Enumerate GCS Buckets (Google)")
        print("  3 — Enumerate Azure Blobs")
        print("  4 — Scan Exposed Services")
        print("  5 — Check Metadata Access (SSRF)")
        print("  6 — Cloud Subdomain Enum")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            kw = input("  Target keyword: ").strip()
            if kw:
                job_id = scanner.enum_s3_buckets(kw)
                print(f"    Scanning... (job: {job_id})")
                while True:
                    job = scanner.get_job(job_id)
                    if job['status'] == 'complete':
                        for b in job['found']:
                            status = 'PUBLIC+LISTABLE' if b.get('listable') else \
                                     ('PUBLIC' if b.get('public') else 'EXISTS')
                            print(f"      [{status}] {b['bucket']}")
                        if not job['found']:
                            print("      No buckets found")
                        break
                    time.sleep(1)
        elif choice == '4':
            target = input("  Target URL: ").strip()
            if target:
                result = scanner.scan_exposed_services(target)
                for s in result['services']:
                    flag = ' [SENSITIVE]' if s.get('sensitive') else ''
                    print(f"      {s['path']}: {s['name']}{flag}")
        elif choice == '5':
            result = scanner.check_metadata_access()
            for provider, info in result['metadata'].items():
                status = 'ACCESSIBLE' if info.get('accessible') else 'blocked'
                print(f"      {provider}: {status}")
        elif choice == '6':
            domain = input("  Target domain: ").strip()
            if domain:
                result = scanner.enum_cloud_subdomains(domain)
                for s in result['subdomains']:
                    print(f"      {s['subdomain']} → {s['ip']}  ({s['cloud_hint']})")
