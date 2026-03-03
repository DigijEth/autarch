"""AUTARCH Log Correlator

Syslog ingestion, pattern matching, anomaly detection, alert rules,
timeline correlation, and mini-SIEM functionality.
"""

DESCRIPTION = "Log correlation & anomaly detection (mini-SIEM)"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

import os
import re
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Any

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Built-in Detection Rules ────────────────────────────────────────────────

DEFAULT_RULES = [
    {
        'id': 'brute_force_ssh',
        'name': 'SSH Brute Force',
        'pattern': r'(Failed password|authentication failure).*ssh',
        'severity': 'high',
        'threshold': 5,
        'window_seconds': 60,
        'description': 'Multiple failed SSH login attempts'
    },
    {
        'id': 'brute_force_web',
        'name': 'Web Login Brute Force',
        'pattern': r'(401|403).*POST.*(login|auth|signin)',
        'severity': 'high',
        'threshold': 10,
        'window_seconds': 60,
        'description': 'Multiple failed web login attempts'
    },
    {
        'id': 'sql_injection',
        'name': 'SQL Injection Attempt',
        'pattern': r"(UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|'--|\bSLEEP\()",
        'severity': 'critical',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'SQL injection pattern detected'
    },
    {
        'id': 'xss_attempt',
        'name': 'XSS Attempt',
        'pattern': r'(<script|javascript:|onerror=|onload=|<svg\s+onload)',
        'severity': 'high',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'Cross-site scripting pattern detected'
    },
    {
        'id': 'path_traversal',
        'name': 'Path Traversal',
        'pattern': r'(\.\./|\.\.\\|%2e%2e)',
        'severity': 'high',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'Directory traversal attempt'
    },
    {
        'id': 'priv_escalation',
        'name': 'Privilege Escalation',
        'pattern': r'(sudo|su\s+-|pkexec|gpasswd|usermod.*-G.*sudo)',
        'severity': 'medium',
        'threshold': 3,
        'window_seconds': 300,
        'description': 'Multiple privilege escalation attempts'
    },
    {
        'id': 'port_scan',
        'name': 'Port Scan Detected',
        'pattern': r'(connection refused|reset by peer|SYN_RECV)',
        'severity': 'medium',
        'threshold': 20,
        'window_seconds': 10,
        'description': 'Rapid connection attempts indicate scanning'
    },
    {
        'id': 'suspicious_download',
        'name': 'Suspicious Download',
        'pattern': r'(wget|curl|python.*http|nc\s+-e)',
        'severity': 'medium',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'Potential malicious download or reverse shell'
    },
    {
        'id': 'service_crash',
        'name': 'Service Crash',
        'pattern': r'(segfault|core dumped|out of memory|killed process)',
        'severity': 'high',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'Service crash or OOM event'
    },
    {
        'id': 'root_login',
        'name': 'Root Login',
        'pattern': r'(session opened.*root|Accepted.*root|su.*root)',
        'severity': 'medium',
        'threshold': 1,
        'window_seconds': 0,
        'description': 'Root/admin login detected'
    },
]


# ── Log Parser ───────────────────────────────────────────────────────────────

class LogParser:
    """Multi-format log parser."""

    SYSLOG_RE = re.compile(
        r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)'
    )
    APACHE_RE = re.compile(
        r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'
    )
    JSON_LOG_RE = re.compile(r'^\{.*\}$')

    @staticmethod
    def parse_line(line: str) -> Optional[Dict]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        # Try JSON format
        if LogParser.JSON_LOG_RE.match(line):
            try:
                data = json.loads(line)
                return {
                    'format': 'json',
                    'timestamp': data.get('timestamp', data.get('time', data.get('@timestamp', ''))),
                    'source': data.get('source', data.get('host', '')),
                    'program': data.get('program', data.get('service', data.get('logger', ''))),
                    'message': data.get('message', data.get('msg', str(data))),
                    'level': data.get('level', data.get('severity', 'info')),
                    'raw': line
                }
            except json.JSONDecodeError:
                pass

        # Try syslog format
        m = LogParser.SYSLOG_RE.match(line)
        if m:
            return {
                'format': 'syslog',
                'timestamp': m.group(1),
                'source': m.group(2),
                'program': m.group(3),
                'pid': m.group(4),
                'message': m.group(5),
                'raw': line
            }

        # Try Apache/Nginx format
        m = LogParser.APACHE_RE.match(line)
        if m:
            return {
                'format': 'apache',
                'timestamp': m.group(2),
                'source': m.group(1),
                'method': m.group(3),
                'path': m.group(4),
                'status': int(m.group(5)),
                'size': int(m.group(6)),
                'message': line,
                'raw': line
            }

        # Generic fallback
        return {
            'format': 'unknown',
            'timestamp': '',
            'message': line,
            'raw': line
        }


# ── Log Correlator Engine ────────────────────────────────────────────────────

class LogCorrelator:
    """Log correlation and anomaly detection engine."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'log_correlator')
        os.makedirs(self.data_dir, exist_ok=True)

        self.rules: List[Dict] = list(DEFAULT_RULES)
        self.alerts: List[Dict] = []
        self.logs: List[Dict] = []
        self.sources: Dict[str, Dict] = {}
        self._rule_hits: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()
        self._load_custom_rules()
        self._load_alerts()

    def _load_custom_rules(self):
        rules_file = os.path.join(self.data_dir, 'custom_rules.json')
        if os.path.exists(rules_file):
            try:
                with open(rules_file) as f:
                    custom = json.load(f)
                self.rules.extend(custom)
            except Exception:
                pass

    def _save_custom_rules(self):
        # Only save non-default rules
        default_ids = {r['id'] for r in DEFAULT_RULES}
        custom = [r for r in self.rules if r['id'] not in default_ids]
        rules_file = os.path.join(self.data_dir, 'custom_rules.json')
        with open(rules_file, 'w') as f:
            json.dump(custom, f, indent=2)

    def _load_alerts(self):
        alerts_file = os.path.join(self.data_dir, 'alerts.json')
        if os.path.exists(alerts_file):
            try:
                with open(alerts_file) as f:
                    self.alerts = json.load(f)
            except Exception:
                pass

    def _save_alerts(self):
        alerts_file = os.path.join(self.data_dir, 'alerts.json')
        with open(alerts_file, 'w') as f:
            json.dump(self.alerts[-1000:], f, indent=2)

    # ── Log Ingestion ────────────────────────────────────────────────────

    def ingest_file(self, filepath: str, source_name: str = None) -> Dict:
        """Ingest log file for analysis."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        source = source_name or Path(filepath).name
        parsed = 0
        alerts_generated = 0

        try:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    entry = LogParser.parse_line(line)
                    if entry:
                        entry['source_file'] = source
                        self.logs.append(entry)
                        parsed += 1

                        # Run detection rules
                        new_alerts = self._check_rules(entry)
                        alerts_generated += len(new_alerts)

            self.sources[source] = {
                'file': filepath,
                'lines': parsed,
                'ingested': datetime.now(timezone.utc).isoformat()
            }

            if alerts_generated:
                self._save_alerts()

            return {
                'ok': True, 'source': source,
                'lines_parsed': parsed,
                'alerts_generated': alerts_generated
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def ingest_text(self, text: str, source_name: str = 'paste') -> Dict:
        """Ingest log text directly."""
        parsed = 0
        alerts_generated = 0

        for line in text.strip().splitlines():
            entry = LogParser.parse_line(line)
            if entry:
                entry['source_file'] = source_name
                self.logs.append(entry)
                parsed += 1
                new_alerts = self._check_rules(entry)
                alerts_generated += len(new_alerts)

        if alerts_generated:
            self._save_alerts()

        return {
            'ok': True, 'source': source_name,
            'lines_parsed': parsed,
            'alerts_generated': alerts_generated
        }

    # ── Detection ────────────────────────────────────────────────────────

    def _check_rules(self, entry: Dict) -> List[Dict]:
        """Check log entry against detection rules."""
        new_alerts = []
        message = entry.get('message', '') + ' ' + entry.get('raw', '')
        now = time.time()

        for rule in self.rules:
            try:
                if re.search(rule['pattern'], message, re.I):
                    rule_id = rule['id']

                    # Threshold check
                    if rule.get('threshold', 1) > 1 and rule.get('window_seconds', 0) > 0:
                        with self._lock:
                            self._rule_hits[rule_id].append(now)
                            # Clean old hits
                            window = rule['window_seconds']
                            self._rule_hits[rule_id] = [
                                t for t in self._rule_hits[rule_id]
                                if now - t <= window
                            ]
                            if len(self._rule_hits[rule_id]) < rule['threshold']:
                                continue

                    alert = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'rule_id': rule_id,
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'description': rule['description'],
                        'source': entry.get('source_file', ''),
                        'log_entry': entry.get('message', '')[:200],
                        'raw': entry.get('raw', '')[:300]
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)
            except re.error:
                pass

        return new_alerts

    # ── Rule Management ──────────────────────────────────────────────────

    def add_rule(self, rule_id: str, name: str, pattern: str,
                 severity: str = 'medium', threshold: int = 1,
                 window_seconds: int = 0, description: str = '') -> Dict:
        """Add custom detection rule."""
        # Validate regex
        try:
            re.compile(pattern)
        except re.error as e:
            return {'ok': False, 'error': f'Invalid regex: {e}'}

        rule = {
            'id': rule_id, 'name': name, 'pattern': pattern,
            'severity': severity, 'threshold': threshold,
            'window_seconds': window_seconds,
            'description': description
        }
        self.rules.append(rule)
        self._save_custom_rules()
        return {'ok': True, 'rule': rule}

    def remove_rule(self, rule_id: str) -> Dict:
        """Remove a custom rule."""
        default_ids = {r['id'] for r in DEFAULT_RULES}
        if rule_id in default_ids:
            return {'ok': False, 'error': 'Cannot remove built-in rule'}

        before = len(self.rules)
        self.rules = [r for r in self.rules if r['id'] != rule_id]
        if len(self.rules) < before:
            self._save_custom_rules()
            return {'ok': True}
        return {'ok': False, 'error': 'Rule not found'}

    def get_rules(self) -> List[Dict]:
        """List all detection rules."""
        default_ids = {r['id'] for r in DEFAULT_RULES}
        return [{**r, 'builtin': r['id'] in default_ids} for r in self.rules]

    # ── Analysis ─────────────────────────────────────────────────────────

    def search_logs(self, query: str, source: str = None,
                     limit: int = 100) -> List[Dict]:
        """Search ingested logs."""
        results = []
        for entry in reversed(self.logs):
            if source and entry.get('source_file') != source:
                continue
            if query.lower() in (entry.get('message', '') + entry.get('raw', '')).lower():
                results.append(entry)
                if len(results) >= limit:
                    break
        return results

    def get_stats(self) -> Dict:
        """Get correlator statistics."""
        severity_counts = Counter(a['severity'] for a in self.alerts)
        rule_counts = Counter(a['rule_id'] for a in self.alerts)
        source_counts = Counter(e.get('source_file', '') for e in self.logs)

        return {
            'total_logs': len(self.logs),
            'total_alerts': len(self.alerts),
            'sources': len(self.sources),
            'rules': len(self.rules),
            'alerts_by_severity': dict(severity_counts),
            'top_rules': dict(rule_counts.most_common(10)),
            'top_sources': dict(source_counts.most_common(10))
        }

    def get_alerts(self, severity: str = None, limit: int = 100) -> List[Dict]:
        """Get alerts with optional filtering."""
        alerts = self.alerts
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        return alerts[-limit:]

    def clear_alerts(self):
        """Clear all alerts."""
        self.alerts.clear()
        self._save_alerts()

    def clear_logs(self):
        """Clear ingested logs."""
        self.logs.clear()
        self.sources.clear()

    def get_sources(self) -> Dict:
        """Get ingested log sources."""
        return self.sources

    def get_timeline(self, hours: int = 24) -> List[Dict]:
        """Get alert timeline grouped by hour."""
        timeline = defaultdict(lambda: {'count': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0})

        for alert in self.alerts:
            ts = alert.get('timestamp', '')[:13]  # YYYY-MM-DDTHH
            timeline[ts]['count'] += 1
            sev = alert.get('severity', 'low')
            timeline[ts][sev] = timeline[ts].get(sev, 0) + 1

        return [{'hour': k, **v} for k, v in sorted(timeline.items())[-hours:]]


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_log_correlator() -> LogCorrelator:
    global _instance
    if _instance is None:
        _instance = LogCorrelator()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Log Correlator module."""
    engine = get_log_correlator()

    while True:
        stats = engine.get_stats()
        print(f"\n{'='*60}")
        print(f"  Log Correlator  ({stats['total_logs']} logs, {stats['total_alerts']} alerts)")
        print(f"{'='*60}")
        print()
        print("  1 — Ingest Log File")
        print("  2 — Paste Log Text")
        print("  3 — Search Logs")
        print("  4 — View Alerts")
        print("  5 — Manage Rules")
        print("  6 — View Stats")
        print("  7 — Alert Timeline")
        print("  8 — Clear Alerts")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            filepath = input("  Log file path: ").strip()
            if filepath:
                result = engine.ingest_file(filepath)
                if result['ok']:
                    print(f"    Parsed {result['lines_parsed']} lines, "
                          f"{result['alerts_generated']} alerts generated")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '2':
            print("  Paste log lines (blank line to finish):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            if lines:
                result = engine.ingest_text('\n'.join(lines))
                print(f"    Parsed {result['lines_parsed']} lines, "
                      f"{result['alerts_generated']} alerts")
        elif choice == '3':
            query = input("  Search query: ").strip()
            if query:
                results = engine.search_logs(query)
                print(f"    {len(results)} matches:")
                for r in results[:10]:
                    print(f"      [{r.get('source_file', '?')}] {r.get('message', '')[:80]}")
        elif choice == '4':
            sev = input("  Severity filter (blank=all): ").strip() or None
            alerts = engine.get_alerts(severity=sev)
            for a in alerts[-15:]:
                print(f"    [{a['severity']:<8}] {a['rule_name']}: {a['log_entry'][:60]}")
        elif choice == '5':
            rules = engine.get_rules()
            for r in rules:
                builtin = ' (built-in)' if r.get('builtin') else ''
                print(f"    {r['id']}: {r['name']} [{r['severity']}]{builtin}")
        elif choice == '6':
            print(f"    Logs: {stats['total_logs']}")
            print(f"    Alerts: {stats['total_alerts']}")
            print(f"    Sources: {stats['sources']}")
            print(f"    Rules: {stats['rules']}")
            if stats['alerts_by_severity']:
                print(f"    By severity: {stats['alerts_by_severity']}")
        elif choice == '7':
            timeline = engine.get_timeline()
            for t in timeline[-12:]:
                bar = '#' * min(t['count'], 40)
                print(f"    {t['hour']} | {bar} ({t['count']})")
        elif choice == '8':
            engine.clear_alerts()
            print("    Alerts cleared")
