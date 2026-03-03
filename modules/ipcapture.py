"""IP Capture & Redirect — stealthy link tracking for OSINT.

Create disguised links that capture visitor IP + metadata,
then redirect to a legitimate target URL. Fast 302 redirect,
realistic URL paths, no suspicious indicators.
"""

DESCRIPTION = "IP Capture & Redirect — stealthy link tracking"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "osint"

import os
import json
import time
import random
import string
import hashlib
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Realistic URL path generation ────────────────────────────────────────────

_WORD_POOL = [
    'tech', 'news', 'science', 'world', 'business', 'health', 'politics',
    'sports', 'culture', 'opinion', 'breaking', 'latest', 'update', 'report',
    'analysis', 'insight', 'review', 'guide', 'how-to', 'explained',
    'ai', 'climate', 'economy', 'security', 'research', 'innovation',
    'digital', 'global', 'local', 'industry', 'future', 'trends',
    'development', 'infrastructure', 'community', 'education', 'policy',
]

_TITLE_PATTERNS = [
    '{adj}-{noun}-{verb}-{year}-{noun2}',
    '{noun}-{adj}-{noun2}-{verb}',
    'new-{noun}-{verb}-{adj}-{noun2}',
    '{noun}-report-{year}-{adj}-{noun2}',
    'how-{noun}-is-{verb}-the-{noun2}',
    '{adj}-{noun}-breakthrough-{noun2}',
]

_ADJECTIVES = [
    'major', 'new', 'latest', 'critical', 'emerging', 'global',
    'innovative', 'surprising', 'important', 'unprecedented',
]

_NOUNS = [
    'technology', 'researchers', 'companies', 'governments', 'scientists',
    'industry', 'market', 'community', 'experts', 'development',
]

_VERBS = [
    'changing', 'transforming', 'disrupting', 'advancing', 'impacting',
    'reshaping', 'driving', 'revealing', 'challenging', 'accelerating',
]


def _generate_article_path() -> str:
    """Generate a realistic-looking article URL path."""
    now = datetime.now()
    year = now.strftime('%Y')
    month = now.strftime('%m')

    pattern = random.choice(_TITLE_PATTERNS)
    slug = pattern.format(
        adj=random.choice(_ADJECTIVES),
        noun=random.choice(_NOUNS),
        noun2=random.choice(_NOUNS),
        verb=random.choice(_VERBS),
        year=year,
    )

    # Article-style path
    styles = [
        f'/article/{year}/{month}/{slug}',
        f'/news/{year}/{slug}',
        f'/stories/{slug}-{random.randint(1000, 9999)}',
        f'/p/{slug}',
        f'/read/{hashlib.md5(slug.encode()).hexdigest()[:8]}',
    ]
    return random.choice(styles)


def _generate_short_key(length: int = 8) -> str:
    """Generate a short random key."""
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))


# ── IP Capture Service ───────────────────────────────────────────────────────

class IPCaptureService:
    """Manage capture links and record visitor metadata."""

    def __init__(self):
        self._file = os.path.join(get_data_dir(), 'osint_captures.json')
        self._links = {}
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self._file):
            try:
                with open(self._file, 'r') as f:
                    self._links = json.load(f)
            except Exception:
                self._links = {}

    def _save(self):
        os.makedirs(os.path.dirname(self._file), exist_ok=True)
        with open(self._file, 'w') as f:
            json.dump(self._links, f, indent=2)

    def create_link(self, target_url: str, name: str = '',
                    disguise: str = 'article') -> dict:
        """Create a new capture link.

        Args:
            target_url: The legitimate URL to redirect to after capture.
            name: Friendly name for this link.
            disguise: URL style — 'short', 'article', or 'custom'.

        Returns:
            Dict with key, paths, and full URLs.
        """
        key = _generate_short_key()

        if disguise == 'article':
            article_path = _generate_article_path()
        elif disguise == 'short':
            article_path = f'/c/{key}'
        else:
            article_path = f'/c/{key}'

        with self._lock:
            self._links[key] = {
                'key': key,
                'name': name or f'Link {key}',
                'target_url': target_url,
                'disguise': disguise,
                'article_path': article_path,
                'short_path': f'/c/{key}',
                'created': datetime.now().isoformat(),
                'captures': [],
                'active': True,
            }
            self._save()

        return {
            'ok': True,
            'key': key,
            'short_path': f'/c/{key}',
            'article_path': article_path,
            'target_url': target_url,
        }

    def get_link(self, key: str) -> Optional[dict]:
        return self._links.get(key)

    def list_links(self) -> List[dict]:
        return list(self._links.values())

    def delete_link(self, key: str) -> bool:
        with self._lock:
            if key in self._links:
                del self._links[key]
                self._save()
                return True
        return False

    def find_by_path(self, path: str) -> Optional[dict]:
        """Find a link by its article path."""
        for link in self._links.values():
            if link.get('article_path') == path:
                return link
        return None

    def record_capture(self, key: str, ip: str, user_agent: str = '',
                       accept_language: str = '', referer: str = '',
                       headers: dict = None) -> bool:
        """Record a visitor capture."""
        with self._lock:
            link = self._links.get(key)
            if not link or not link.get('active'):
                return False

            capture = {
                'ip': ip,
                'timestamp': datetime.now().isoformat(),
                'user_agent': user_agent,
                'accept_language': accept_language,
                'referer': referer,
            }

            # Extract extra metadata from headers
            if headers:
                for h in ['X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP']:
                    val = headers.get(h, '')
                    if val:
                        capture[f'header_{h.lower().replace("-","_")}'] = val
                # Connection hints
                for h in ['Sec-CH-UA', 'Sec-CH-UA-Platform', 'Sec-CH-UA-Mobile',
                           'DNT', 'Upgrade-Insecure-Requests']:
                    val = headers.get(h, '')
                    if val:
                        capture[f'hint_{h.lower().replace("-","_")}'] = val

            # GeoIP lookup (best-effort)
            try:
                geo = self._geoip_lookup(ip)
                if geo:
                    capture['geo'] = geo
            except Exception:
                pass

            link['captures'].append(capture)
            self._save()
            return True

    def _geoip_lookup(self, ip: str) -> Optional[dict]:
        """Best-effort GeoIP lookup using the existing geoip module."""
        try:
            from modules.geoip import GeoIPLookup
            geo = GeoIPLookup()
            result = geo.lookup(ip)
            if result and result.get('success'):
                return {
                    'country': result.get('country', ''),
                    'region': result.get('region', ''),
                    'city': result.get('city', ''),
                    'isp': result.get('isp', ''),
                    'lat': result.get('latitude', ''),
                    'lon': result.get('longitude', ''),
                }
        except Exception:
            pass
        return None

    def get_captures(self, key: str) -> List[dict]:
        link = self._links.get(key)
        return link.get('captures', []) if link else []

    def get_stats(self, key: str) -> dict:
        link = self._links.get(key)
        if not link:
            return {}
        captures = link.get('captures', [])
        unique_ips = set(c['ip'] for c in captures)
        return {
            'total': len(captures),
            'unique_ips': len(unique_ips),
            'first': captures[0]['timestamp'] if captures else None,
            'last': captures[-1]['timestamp'] if captures else None,
        }

    def export_captures(self, key: str, fmt: str = 'json') -> str:
        """Export captures to JSON or CSV string."""
        captures = self.get_captures(key)
        if fmt == 'csv':
            if not captures:
                return 'ip,timestamp,user_agent,country,city\n'
            lines = ['ip,timestamp,user_agent,country,city']
            for c in captures:
                geo = c.get('geo', {})
                lines.append(','.join([
                    c.get('ip', ''),
                    c.get('timestamp', ''),
                    f'"{c.get("user_agent", "")}"',
                    geo.get('country', ''),
                    geo.get('city', ''),
                ]))
            return '\n'.join(lines)
        return json.dumps(captures, indent=2)


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_ip_capture() -> IPCaptureService:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = IPCaptureService()
    return _instance


# ── Interactive CLI ──────────────────────────────────────────────────────────

def run():
    """Interactive CLI for IP Capture & Redirect."""
    service = get_ip_capture()

    while True:
        print("\n" + "=" * 60)
        print("  IP CAPTURE & REDIRECT")
        print("  Stealthy link tracking for OSINT")
        print("=" * 60)
        links = service.list_links()
        active = sum(1 for l in links if l.get('active'))
        total_captures = sum(len(l.get('captures', [])) for l in links)
        print(f"  Active links: {active}  |  Total captures: {total_captures}")
        print()
        print("  1 — Create Capture Link")
        print("  2 — List Active Links")
        print("  3 — View Captures")
        print("  4 — Delete Link")
        print("  5 — Export Captures")
        print("  0 — Back")
        print()

        choice = input("  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            _cli_create(service)
        elif choice == '2':
            _cli_list(service)
        elif choice == '3':
            _cli_view(service)
        elif choice == '4':
            _cli_delete(service)
        elif choice == '5':
            _cli_export(service)


def _cli_create(service: IPCaptureService):
    """Create a new capture link."""
    print("\n--- Create Capture Link ---")
    target = input("  Target URL (redirect destination): ").strip()
    if not target:
        print("  [!] URL required")
        return
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    name = input("  Friendly name []: ").strip()
    print("  Disguise type:")
    print("    1 — Article URL (realistic path)")
    print("    2 — Short URL (/c/xxxxx)")
    dtype = input("  Select [1]: ").strip() or '1'
    disguise = 'article' if dtype == '1' else 'short'

    result = service.create_link(target, name, disguise)
    if result['ok']:
        print(f"\n  [+] Link created!")
        print(f"  Key:          {result['key']}")
        print(f"  Short URL:    <your-host>{result['short_path']}")
        print(f"  Article URL:  <your-host>{result['article_path']}")
        print(f"  Redirects to: {result['target_url']}")
    else:
        print(f"  [-] {result.get('error', 'Failed')}")


def _cli_list(service: IPCaptureService):
    """List all active links."""
    links = service.list_links()
    if not links:
        print("\n  No capture links")
        return
    print(f"\n--- Active Links ({len(links)}) ---")
    for l in links:
        stats = service.get_stats(l['key'])
        active = "ACTIVE" if l.get('active') else "DISABLED"
        print(f"\n  [{l['key']}] {l.get('name', 'Unnamed')} — {active}")
        print(f"    Target:   {l['target_url']}")
        print(f"    Short:    {l['short_path']}")
        print(f"    Article:  {l.get('article_path', 'N/A')}")
        print(f"    Captures: {stats.get('total', 0)} ({stats.get('unique_ips', 0)} unique)")
        if stats.get('last'):
            print(f"    Last hit:  {stats['last']}")


def _cli_view(service: IPCaptureService):
    """View captures for a link."""
    key = input("  Link key: ").strip()
    captures = service.get_captures(key)
    if not captures:
        print("  No captures for this link")
        return
    print(f"\n--- Captures ({len(captures)}) ---")
    for c in captures:
        geo = c.get('geo', {})
        location = f"{geo.get('city', '?')}, {geo.get('country', '?')}" if geo else 'Unknown'
        print(f"  {c['timestamp']}  {c['ip']:>15}  {location}")
        if c.get('user_agent'):
            ua = c['user_agent'][:80] + ('...' if len(c.get('user_agent', '')) > 80 else '')
            print(f"    UA: {ua}")


def _cli_delete(service: IPCaptureService):
    """Delete a link."""
    key = input("  Link key to delete: ").strip()
    if service.delete_link(key):
        print("  [+] Link deleted")
    else:
        print("  [-] Link not found")


def _cli_export(service: IPCaptureService):
    """Export captures."""
    key = input("  Link key: ").strip()
    fmt = input("  Format (json/csv) [json]: ").strip() or 'json'
    data = service.export_captures(key, fmt)
    print(f"\n{data}")

    save = input("\n  Save to file? [y/N]: ").strip().lower()
    if save == 'y':
        ext = 'csv' if fmt == 'csv' else 'json'
        filepath = os.path.join(get_data_dir(), 'exports', f'captures_{key}.{ext}')
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w') as f:
            f.write(data)
        print(f"  [+] Saved to {filepath}")
