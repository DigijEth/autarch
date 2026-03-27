"""AUTARCH Threat Intelligence Feed

IOC management, feed ingestion (STIX/TAXII, CSV, JSON), correlation with
OSINT dossiers, reputation lookups, alerting, and blocklist generation.
"""

DESCRIPTION = "Threat intelligence & IOC management"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

import os
import re
import json
import time
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urlparse

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
except ImportError:
    requests = None


# ── Data Structures ──────────────────────────────────────────────────────────

IOC_TYPES = ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'filename']

@dataclass
class IOC:
    value: str
    ioc_type: str
    source: str = "manual"
    tags: List[str] = field(default_factory=list)
    severity: str = "unknown"  # critical, high, medium, low, info, unknown
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""
    reference: str = ""
    active: bool = True

    def to_dict(self) -> Dict:
        return {
            'value': self.value, 'ioc_type': self.ioc_type,
            'source': self.source, 'tags': self.tags,
            'severity': self.severity, 'first_seen': self.first_seen,
            'last_seen': self.last_seen, 'description': self.description,
            'reference': self.reference, 'active': self.active,
            'id': hashlib.md5(f"{self.ioc_type}:{self.value}".encode()).hexdigest()[:12]
        }

    @staticmethod
    def from_dict(d: Dict) -> 'IOC':
        return IOC(
            value=d['value'], ioc_type=d['ioc_type'],
            source=d.get('source', 'manual'), tags=d.get('tags', []),
            severity=d.get('severity', 'unknown'),
            first_seen=d.get('first_seen', ''), last_seen=d.get('last_seen', ''),
            description=d.get('description', ''), reference=d.get('reference', ''),
            active=d.get('active', True)
        )

@dataclass
class Feed:
    name: str
    feed_type: str  # taxii, csv_url, json_url, stix_file
    url: str = ""
    api_key: str = ""
    enabled: bool = True
    last_fetch: str = ""
    ioc_count: int = 0
    interval_hours: int = 24

    def to_dict(self) -> Dict:
        return {
            'name': self.name, 'feed_type': self.feed_type,
            'url': self.url, 'api_key': self.api_key,
            'enabled': self.enabled, 'last_fetch': self.last_fetch,
            'ioc_count': self.ioc_count, 'interval_hours': self.interval_hours,
            'id': hashlib.md5(f"{self.name}:{self.url}".encode()).hexdigest()[:12]
        }


# ── Threat Intel Engine ──────────────────────────────────────────────────────

class ThreatIntelEngine:
    """IOC management and threat intelligence correlation."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'threat_intel')
        os.makedirs(self.data_dir, exist_ok=True)
        self.iocs: List[IOC] = []
        self.feeds: List[Feed] = []
        self.alerts: List[Dict] = []
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """Load IOCs and feeds from disk."""
        ioc_file = os.path.join(self.data_dir, 'iocs.json')
        if os.path.exists(ioc_file):
            try:
                with open(ioc_file) as f:
                    data = json.load(f)
                self.iocs = [IOC.from_dict(d) for d in data]
            except Exception:
                pass

        feed_file = os.path.join(self.data_dir, 'feeds.json')
        if os.path.exists(feed_file):
            try:
                with open(feed_file) as f:
                    data = json.load(f)
                self.feeds = [Feed(**d) for d in data]
            except Exception:
                pass

    def _save_iocs(self):
        """Persist IOCs to disk."""
        ioc_file = os.path.join(self.data_dir, 'iocs.json')
        with open(ioc_file, 'w') as f:
            json.dump([ioc.to_dict() for ioc in self.iocs], f, indent=2)

    def _save_feeds(self):
        """Persist feeds to disk."""
        feed_file = os.path.join(self.data_dir, 'feeds.json')
        with open(feed_file, 'w') as f:
            json.dump([feed.to_dict() for feed in self.feeds], f, indent=2)

    # ── IOC Type Detection ───────────────────────────────────────────────

    def detect_ioc_type(self, value: str) -> str:
        """Auto-detect IOC type from value."""
        value = value.strip()
        # Hash detection
        if re.match(r'^[a-fA-F0-9]{32}$', value):
            return 'hash_md5'
        if re.match(r'^[a-fA-F0-9]{40}$', value):
            return 'hash_sha1'
        if re.match(r'^[a-fA-F0-9]{64}$', value):
            return 'hash_sha256'
        # URL
        if re.match(r'^https?://', value, re.I):
            return 'url'
        # Email
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
            return 'email'
        # IP (v4)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'ip'
        # Domain
        if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$', value):
            return 'domain'
        # Filename
        if '.' in value and '/' not in value and '\\' not in value:
            return 'filename'
        return 'unknown'

    # ── IOC CRUD ─────────────────────────────────────────────────────────

    def add_ioc(self, value: str, ioc_type: str = None, source: str = "manual",
                tags: List[str] = None, severity: str = "unknown",
                description: str = "", reference: str = "") -> Dict:
        """Add a single IOC."""
        if not ioc_type:
            ioc_type = self.detect_ioc_type(value)

        now = datetime.now(timezone.utc).isoformat()

        # Check for duplicate
        with self._lock:
            for existing in self.iocs:
                if existing.value == value and existing.ioc_type == ioc_type:
                    existing.last_seen = now
                    if tags:
                        existing.tags = list(set(existing.tags + tags))
                    self._save_iocs()
                    return {'ok': True, 'action': 'updated', 'ioc': existing.to_dict()}

            ioc = IOC(
                value=value, ioc_type=ioc_type, source=source,
                tags=tags or [], severity=severity,
                first_seen=now, last_seen=now,
                description=description, reference=reference
            )
            self.iocs.append(ioc)
            self._save_iocs()

        return {'ok': True, 'action': 'created', 'ioc': ioc.to_dict()}

    def remove_ioc(self, ioc_id: str) -> Dict:
        """Remove IOC by ID."""
        with self._lock:
            before = len(self.iocs)
            self.iocs = [
                ioc for ioc in self.iocs
                if hashlib.md5(f"{ioc.ioc_type}:{ioc.value}".encode()).hexdigest()[:12] != ioc_id
            ]
            if len(self.iocs) < before:
                self._save_iocs()
                return {'ok': True}
        return {'ok': False, 'error': 'IOC not found'}

    def get_iocs(self, ioc_type: str = None, source: str = None,
                 severity: str = None, search: str = None,
                 active_only: bool = True) -> List[Dict]:
        """Query IOCs with filters."""
        results = []
        for ioc in self.iocs:
            if active_only and not ioc.active:
                continue
            if ioc_type and ioc.ioc_type != ioc_type:
                continue
            if source and ioc.source != source:
                continue
            if severity and ioc.severity != severity:
                continue
            if search and search.lower() not in ioc.value.lower() and \
               search.lower() not in ioc.description.lower() and \
               not any(search.lower() in t.lower() for t in ioc.tags):
                continue
            results.append(ioc.to_dict())
        return results

    def bulk_import(self, text: str, source: str = "import",
                    ioc_type: str = None) -> Dict:
        """Import IOCs from newline-separated text."""
        imported = 0
        skipped = 0
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Handle CSV-style (value,type,severity,description)
            parts = [p.strip() for p in line.split(',')]
            value = parts[0]
            t = parts[1] if len(parts) > 1 and parts[1] in IOC_TYPES else ioc_type
            sev = parts[2] if len(parts) > 2 else 'unknown'
            desc = parts[3] if len(parts) > 3 else ''

            if not value:
                skipped += 1
                continue

            result = self.add_ioc(value=value, ioc_type=t, source=source,
                                   severity=sev, description=desc)
            if result['ok']:
                imported += 1
            else:
                skipped += 1

        return {'ok': True, 'imported': imported, 'skipped': skipped}

    def export_iocs(self, fmt: str = 'json', ioc_type: str = None) -> str:
        """Export IOCs in specified format."""
        iocs = self.get_iocs(ioc_type=ioc_type, active_only=False)

        if fmt == 'csv':
            lines = ['value,type,severity,source,tags,description']
            for ioc in iocs:
                tags = ';'.join(ioc.get('tags', []))
                lines.append(f"{ioc['value']},{ioc['ioc_type']},{ioc['severity']},"
                              f"{ioc['source']},{tags},{ioc.get('description', '')}")
            return '\n'.join(lines)

        elif fmt == 'stix':
            # Basic STIX 2.1 bundle
            objects = []
            for ioc in iocs:
                stix_type = {
                    'ip': 'ipv4-addr', 'domain': 'domain-name',
                    'url': 'url', 'email': 'email-addr',
                    'hash_md5': 'file', 'hash_sha1': 'file', 'hash_sha256': 'file',
                    'filename': 'file'
                }.get(ioc['ioc_type'], 'artifact')

                if stix_type == 'file' and ioc['ioc_type'].startswith('hash_'):
                    hash_algo = ioc['ioc_type'].replace('hash_', '').upper().replace('SHA', 'SHA-')
                    obj = {
                        'type': 'indicator',
                        'id': f"indicator--{ioc['id']}",
                        'name': ioc['value'],
                        'pattern': f"[file:hashes.'{hash_algo}' = '{ioc['value']}']",
                        'pattern_type': 'stix',
                        'valid_from': ioc.get('first_seen', ''),
                        'labels': ioc.get('tags', [])
                    }
                else:
                    obj = {
                        'type': 'indicator',
                        'id': f"indicator--{ioc['id']}",
                        'name': ioc['value'],
                        'pattern': f"[{stix_type}:value = '{ioc['value']}']",
                        'pattern_type': 'stix',
                        'valid_from': ioc.get('first_seen', ''),
                        'labels': ioc.get('tags', [])
                    }
                objects.append(obj)

            bundle = {
                'type': 'bundle',
                'id': f'bundle--autarch-{int(time.time())}',
                'objects': objects
            }
            return json.dumps(bundle, indent=2)

        else:  # json
            return json.dumps(iocs, indent=2)

    def get_stats(self) -> Dict:
        """Get IOC database statistics."""
        by_type = {}
        by_severity = {}
        by_source = {}
        for ioc in self.iocs:
            by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1
            by_severity[ioc.severity] = by_severity.get(ioc.severity, 0) + 1
            by_source[ioc.source] = by_source.get(ioc.source, 0) + 1

        return {
            'total': len(self.iocs),
            'active': sum(1 for i in self.iocs if i.active),
            'by_type': by_type,
            'by_severity': by_severity,
            'by_source': by_source
        }

    # ── Feed Management ──────────────────────────────────────────────────

    def add_feed(self, name: str, feed_type: str, url: str,
                 api_key: str = "", interval_hours: int = 24) -> Dict:
        """Add a threat intelligence feed."""
        feed = Feed(
            name=name, feed_type=feed_type, url=url,
            api_key=api_key, interval_hours=interval_hours
        )
        self.feeds.append(feed)
        self._save_feeds()
        return {'ok': True, 'feed': feed.to_dict()}

    def remove_feed(self, feed_id: str) -> Dict:
        """Remove feed by ID."""
        before = len(self.feeds)
        self.feeds = [
            f for f in self.feeds
            if hashlib.md5(f"{f.name}:{f.url}".encode()).hexdigest()[:12] != feed_id
        ]
        if len(self.feeds) < before:
            self._save_feeds()
            return {'ok': True}
        return {'ok': False, 'error': 'Feed not found'}

    def get_feeds(self) -> List[Dict]:
        """List all feeds."""
        return [f.to_dict() for f in self.feeds]

    def fetch_feed(self, feed_id: str) -> Dict:
        """Fetch IOCs from a feed."""
        if not requests:
            return {'ok': False, 'error': 'requests library not available'}

        feed = None
        for f in self.feeds:
            if hashlib.md5(f"{f.name}:{f.url}".encode()).hexdigest()[:12] == feed_id:
                feed = f
                break
        if not feed:
            return {'ok': False, 'error': 'Feed not found'}

        try:
            headers = {}
            if feed.api_key:
                headers['Authorization'] = f'Bearer {feed.api_key}'
                headers['X-API-Key'] = feed.api_key

            resp = requests.get(feed.url, headers=headers, timeout=30)
            resp.raise_for_status()

            imported = 0
            if feed.feed_type == 'csv_url':
                result = self.bulk_import(resp.text, source=feed.name)
                imported = result['imported']
            elif feed.feed_type == 'json_url':
                data = resp.json()
                items = data if isinstance(data, list) else data.get('data', data.get('results', []))
                for item in items:
                    if isinstance(item, str):
                        self.add_ioc(item, source=feed.name)
                        imported += 1
                    elif isinstance(item, dict):
                        val = item.get('value', item.get('indicator', item.get('ioc', '')))
                        if val:
                            self.add_ioc(
                                val,
                                ioc_type=item.get('type', None),
                                source=feed.name,
                                severity=item.get('severity', 'unknown'),
                                description=item.get('description', ''),
                                tags=item.get('tags', [])
                            )
                            imported += 1
            elif feed.feed_type == 'stix_file':
                data = resp.json()
                objects = data.get('objects', [])
                for obj in objects:
                    if obj.get('type') == 'indicator':
                        pattern = obj.get('pattern', '')
                        # Extract value from STIX pattern
                        m = re.search(r"=\s*'([^']+)'", pattern)
                        if m:
                            self.add_ioc(
                                m.group(1), source=feed.name,
                                description=obj.get('name', ''),
                                tags=obj.get('labels', [])
                            )
                            imported += 1

            feed.last_fetch = datetime.now(timezone.utc).isoformat()
            feed.ioc_count = imported
            self._save_feeds()

            return {'ok': True, 'imported': imported, 'feed': feed.name}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Reputation Lookups ───────────────────────────────────────────────

    def lookup_virustotal(self, value: str, api_key: str) -> Dict:
        """Look up IOC on VirusTotal."""
        if not requests:
            return {'ok': False, 'error': 'requests library not available'}

        ioc_type = self.detect_ioc_type(value)
        headers = {'x-apikey': api_key}

        try:
            if ioc_type == 'ip':
                url = f'https://www.virustotal.com/api/v3/ip_addresses/{value}'
            elif ioc_type == 'domain':
                url = f'https://www.virustotal.com/api/v3/domains/{value}'
            elif ioc_type in ('hash_md5', 'hash_sha1', 'hash_sha256'):
                url = f'https://www.virustotal.com/api/v3/files/{value}'
            elif ioc_type == 'url':
                url_id = hashlib.sha256(value.encode()).hexdigest()
                url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            else:
                return {'ok': False, 'error': f'Unsupported type for VT lookup: {ioc_type}'}

            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
                return {
                    'ok': True,
                    'value': value,
                    'type': ioc_type,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                    'reputation': data.get('reputation', 0),
                    'source': 'virustotal'
                }
            elif resp.status_code == 404:
                return {'ok': True, 'value': value, 'message': 'Not found in VirusTotal'}
            else:
                return {'ok': False, 'error': f'VT API error: {resp.status_code}'}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def lookup_abuseipdb(self, ip: str, api_key: str) -> Dict:
        """Look up IP on AbuseIPDB."""
        if not requests:
            return {'ok': False, 'error': 'requests library not available'}

        try:
            resp = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': api_key, 'Accept': 'application/json'},
                timeout=15
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                return {
                    'ok': True,
                    'ip': ip,
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'country': data.get('countryCode', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'is_public': data.get('isPublic', False),
                    'source': 'abuseipdb'
                }
            return {'ok': False, 'error': f'AbuseIPDB error: {resp.status_code}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Correlation ──────────────────────────────────────────────────────

    def correlate_network(self, connections: List[Dict]) -> List[Dict]:
        """Check network connections against IOC database."""
        ioc_ips = {ioc.value for ioc in self.iocs if ioc.ioc_type == 'ip' and ioc.active}
        ioc_domains = {ioc.value for ioc in self.iocs if ioc.ioc_type == 'domain' and ioc.active}

        matches = []
        for conn in connections:
            remote_ip = conn.get('remote_addr', conn.get('ip', ''))
            remote_host = conn.get('hostname', '')

            if remote_ip in ioc_ips:
                ioc = next(i for i in self.iocs if i.value == remote_ip)
                matches.append({
                    'connection': conn,
                    'ioc': ioc.to_dict(),
                    'match_type': 'ip',
                    'severity': ioc.severity
                })
            if remote_host and remote_host in ioc_domains:
                ioc = next(i for i in self.iocs if i.value == remote_host)
                matches.append({
                    'connection': conn,
                    'ioc': ioc.to_dict(),
                    'match_type': 'domain',
                    'severity': ioc.severity
                })

        if matches:
            self.alerts.extend([{
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'type': 'network_match',
                **m
            } for m in matches])

        return matches

    def correlate_file_hashes(self, hashes: List[str]) -> List[Dict]:
        """Check file hashes against IOC database."""
        hash_iocs = {
            ioc.value.lower(): ioc
            for ioc in self.iocs
            if ioc.ioc_type.startswith('hash_') and ioc.active
        }

        matches = []
        for h in hashes:
            if h.lower() in hash_iocs:
                ioc = hash_iocs[h.lower()]
                matches.append({
                    'hash': h,
                    'ioc': ioc.to_dict(),
                    'severity': ioc.severity
                })

        return matches

    # ── Blocklist Generation ─────────────────────────────────────────────

    def generate_blocklist(self, fmt: str = 'plain', ioc_type: str = 'ip',
                           min_severity: str = 'low') -> str:
        """Generate blocklist from IOCs."""
        severity_order = ['info', 'low', 'medium', 'high', 'critical']
        min_idx = severity_order.index(min_severity) if min_severity in severity_order else 0

        items = []
        for ioc in self.iocs:
            if not ioc.active or ioc.ioc_type != ioc_type:
                continue
            sev_idx = severity_order.index(ioc.severity) if ioc.severity in severity_order else -1
            if sev_idx >= min_idx:
                items.append(ioc.value)

        if fmt == 'iptables':
            return '\n'.join(f'iptables -A INPUT -s {ip} -j DROP' for ip in items)
        elif fmt == 'nginx_deny':
            return '\n'.join(f'deny {ip};' for ip in items)
        elif fmt == 'hosts':
            return '\n'.join(f'0.0.0.0 {d}' for d in items)
        elif fmt == 'dns_blocklist':
            return '\n'.join(items)
        elif fmt == 'snort':
            return '\n'.join(
                f'alert ip {ip} any -> $HOME_NET any (msg:"AUTARCH IOC match {ip}"; sid:{i+1000000}; rev:1;)'
                for i, ip in enumerate(items)
            )
        else:  # plain
            return '\n'.join(items)

    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent correlation alerts."""
        return self.alerts[-limit:]

    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts.clear()


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_threat_intel() -> ThreatIntelEngine:
    global _instance
    if _instance is None:
        _instance = ThreatIntelEngine()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Threat Intel module."""
    engine = get_threat_intel()

    while True:
        stats = engine.get_stats()
        print(f"\n{'='*60}")
        print(f"  Threat Intelligence  ({stats['total']} IOCs, {len(engine.feeds)} feeds)")
        print(f"{'='*60}")
        print()
        print("  1 — Add IOC")
        print("  2 — Search IOCs")
        print("  3 — Bulk Import")
        print("  4 — Export IOCs")
        print("  5 — Manage Feeds")
        print("  6 — Reputation Lookup")
        print("  7 — Generate Blocklist")
        print("  8 — View Stats")
        print("  9 — View Alerts")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            value = input("  IOC value: ").strip()
            if value:
                ioc_type = input(f"  Type (auto-detected: {engine.detect_ioc_type(value)}): ").strip()
                severity = input("  Severity (critical/high/medium/low/info): ").strip() or 'unknown'
                desc = input("  Description: ").strip()
                result = engine.add_ioc(value, ioc_type=ioc_type or None,
                                         severity=severity, description=desc)
                print(f"    {result['action']}: {result['ioc']['value']} ({result['ioc']['ioc_type']})")
        elif choice == '2':
            search = input("  Search term: ").strip()
            results = engine.get_iocs(search=search)
            print(f"    Found {len(results)} IOCs:")
            for ioc in results[:20]:
                print(f"      [{ioc['severity']:<8}] {ioc['ioc_type']:<12} {ioc['value']}")
        elif choice == '3':
            print("  Paste IOCs (one per line, Ctrl+D/blank line to finish):")
            lines = []
            while True:
                try:
                    line = input()
                    if not line:
                        break
                    lines.append(line)
                except EOFError:
                    break
            if lines:
                result = engine.bulk_import('\n'.join(lines))
                print(f"    Imported: {result['imported']}, Skipped: {result['skipped']}")
        elif choice == '4':
            fmt = input("  Format (json/csv/stix): ").strip() or 'json'
            output = engine.export_iocs(fmt=fmt)
            outfile = os.path.join(engine.data_dir, f'export.{fmt}')
            with open(outfile, 'w') as f:
                f.write(output)
            print(f"    Exported to {outfile}")
        elif choice == '5':
            print(f"    Feeds ({len(engine.feeds)}):")
            for f in engine.get_feeds():
                print(f"      {f['name']} ({f['feed_type']}) — last: {f['last_fetch'] or 'never'}")
        elif choice == '6':
            value = input("  Value to look up: ").strip()
            api_key = input("  VirusTotal API key: ").strip()
            if value and api_key:
                result = engine.lookup_virustotal(value, api_key)
                if result['ok']:
                    print(f"    Malicious: {result.get('malicious', 'N/A')} | "
                          f"Suspicious: {result.get('suspicious', 'N/A')}")
                else:
                    print(f"    Error: {result.get('error', result.get('message'))}")
        elif choice == '7':
            fmt = input("  Format (plain/iptables/nginx_deny/hosts/snort): ").strip() or 'plain'
            ioc_type = input("  IOC type (ip/domain): ").strip() or 'ip'
            output = engine.generate_blocklist(fmt=fmt, ioc_type=ioc_type)
            print(f"    Generated {len(output.splitlines())} rules")
        elif choice == '8':
            print(f"    Total IOCs: {stats['total']}")
            print(f"    Active: {stats['active']}")
            print(f"    By type: {stats['by_type']}")
            print(f"    By severity: {stats['by_severity']}")
        elif choice == '9':
            alerts = engine.get_alerts()
            print(f"    {len(alerts)} alerts:")
            for a in alerts[-10:]:
                print(f"      [{a.get('severity', '?')}] {a.get('match_type')}: "
                      f"{a.get('ioc', {}).get('value', '?')}")
