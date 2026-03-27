"""AUTARCH Reporting Engine

Structured pentest report builder with findings, CVSS scoring, evidence,
and export to HTML/Markdown/JSON.
"""

DESCRIPTION = "Pentest report builder & exporter"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import json
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
import threading

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Finding Severity & CVSS ──────────────────────────────────────────────────

SEVERITY_MAP = {
    'critical': {'color': '#dc2626', 'score_range': '9.0-10.0', 'order': 0},
    'high':     {'color': '#ef4444', 'score_range': '7.0-8.9',  'order': 1},
    'medium':   {'color': '#f59e0b', 'score_range': '4.0-6.9',  'order': 2},
    'low':      {'color': '#22c55e', 'score_range': '0.1-3.9',  'order': 3},
    'info':     {'color': '#6366f1', 'score_range': '0.0',      'order': 4},
}

FINDING_TEMPLATES = [
    {
        'id': 'sqli',
        'title': 'SQL Injection',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'The application is vulnerable to SQL injection, allowing an attacker to manipulate database queries.',
        'impact': 'Complete database compromise, data exfiltration, authentication bypass, potential remote code execution.',
        'remediation': 'Use parameterized queries/prepared statements. Implement input validation and WAF rules.',
        'references': ['OWASP Top 10: A03:2021', 'CWE-89'],
    },
    {
        'id': 'xss',
        'title': 'Cross-Site Scripting (XSS)',
        'severity': 'high',
        'cvss': 7.5,
        'description': 'The application reflects user input without proper sanitization, enabling script injection.',
        'impact': 'Session hijacking, credential theft, defacement, malware distribution.',
        'remediation': 'Encode all output, implement Content-Security-Policy, use framework auto-escaping.',
        'references': ['OWASP Top 10: A03:2021', 'CWE-79'],
    },
    {
        'id': 'broken_auth',
        'title': 'Broken Authentication',
        'severity': 'critical',
        'cvss': 9.1,
        'description': 'Authentication mechanisms can be bypassed or abused to gain unauthorized access.',
        'impact': 'Account takeover, privilege escalation, unauthorized data access.',
        'remediation': 'Implement MFA, rate limiting, secure session management, strong password policies.',
        'references': ['OWASP Top 10: A07:2021', 'CWE-287'],
    },
    {
        'id': 'idor',
        'title': 'Insecure Direct Object Reference (IDOR)',
        'severity': 'high',
        'cvss': 7.5,
        'description': 'The application exposes internal object references that can be manipulated to access unauthorized resources.',
        'impact': 'Unauthorized access to other users\' data, horizontal privilege escalation.',
        'remediation': 'Implement proper access control checks, use indirect references.',
        'references': ['OWASP Top 10: A01:2021', 'CWE-639'],
    },
    {
        'id': 'missing_headers',
        'title': 'Missing Security Headers',
        'severity': 'low',
        'cvss': 3.1,
        'description': 'The application does not implement recommended security headers.',
        'impact': 'Increased attack surface for clickjacking, MIME sniffing, and XSS attacks.',
        'remediation': 'Implement CSP, X-Frame-Options, X-Content-Type-Options, HSTS headers.',
        'references': ['OWASP Secure Headers Project'],
    },
    {
        'id': 'weak_ssl',
        'title': 'Weak SSL/TLS Configuration',
        'severity': 'medium',
        'cvss': 5.3,
        'description': 'The server supports weak SSL/TLS protocols or cipher suites.',
        'impact': 'Potential for traffic interception via downgrade attacks.',
        'remediation': 'Disable TLS 1.0/1.1, remove weak ciphers, enable HSTS.',
        'references': ['CWE-326', 'NIST SP 800-52'],
    },
    {
        'id': 'info_disclosure',
        'title': 'Information Disclosure',
        'severity': 'medium',
        'cvss': 5.0,
        'description': 'The application reveals sensitive information such as server versions, stack traces, or internal paths.',
        'impact': 'Aids attackers in fingerprinting and planning targeted attacks.',
        'remediation': 'Remove version headers, disable debug modes, implement custom error pages.',
        'references': ['CWE-200'],
    },
    {
        'id': 'default_creds',
        'title': 'Default Credentials',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'The system uses default or well-known credentials that have not been changed.',
        'impact': 'Complete system compromise with minimal effort.',
        'remediation': 'Enforce password change on first login, remove default accounts.',
        'references': ['CWE-798'],
    },
    {
        'id': 'eternalblue',
        'title': 'MS17-010 (EternalBlue)',
        'severity': 'critical',
        'cvss': 9.8,
        'description': 'The target is vulnerable to the EternalBlue SMB exploit (MS17-010).',
        'impact': 'Remote code execution with SYSTEM privileges, wormable exploit.',
        'remediation': 'Apply Microsoft patch MS17-010, disable SMBv1.',
        'references': ['CVE-2017-0144', 'MS17-010'],
    },
    {
        'id': 'open_ports',
        'title': 'Unnecessary Open Ports',
        'severity': 'low',
        'cvss': 3.0,
        'description': 'The target exposes network services that are not required for operation.',
        'impact': 'Increased attack surface, potential exploitation of exposed services.',
        'remediation': 'Close unnecessary ports, implement firewall rules, use network segmentation.',
        'references': ['CIS Benchmarks'],
    },
]


# ── Report Engine ─────────────────────────────────────────────────────────────

class ReportEngine:
    """Pentest report builder with findings management and export."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'reports')
        os.makedirs(self._data_dir, exist_ok=True)

    # ── Report CRUD ───────────────────────────────────────────────────────

    def create_report(self, title: str, client: str = '',
                      scope: str = '', methodology: str = '') -> dict:
        """Create a new report."""
        report_id = str(uuid.uuid4())[:8]
        report = {
            'id': report_id,
            'title': title,
            'client': client,
            'scope': scope,
            'methodology': methodology or 'OWASP Testing Guide v4.2 / PTES',
            'executive_summary': '',
            'findings': [],
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'status': 'draft',
            'author': 'AUTARCH',
        }
        self._save_report(report)
        return {'ok': True, 'report': report}

    def get_report(self, report_id: str) -> Optional[dict]:
        path = os.path.join(self._data_dir, f'{report_id}.json')
        if not os.path.exists(path):
            return None
        with open(path, 'r') as f:
            return json.load(f)

    def update_report(self, report_id: str, updates: dict) -> dict:
        report = self.get_report(report_id)
        if not report:
            return {'ok': False, 'error': 'Report not found'}
        for k, v in updates.items():
            if k in report and k not in ('id', 'created_at'):
                report[k] = v
        report['updated_at'] = datetime.now(timezone.utc).isoformat()
        self._save_report(report)
        return {'ok': True, 'report': report}

    def delete_report(self, report_id: str) -> dict:
        path = os.path.join(self._data_dir, f'{report_id}.json')
        if os.path.exists(path):
            os.remove(path)
            return {'ok': True}
        return {'ok': False, 'error': 'Report not found'}

    def list_reports(self) -> List[dict]:
        reports = []
        for f in Path(self._data_dir).glob('*.json'):
            try:
                with open(f, 'r') as fh:
                    r = json.load(fh)
                    reports.append({
                        'id': r['id'],
                        'title': r['title'],
                        'client': r.get('client', ''),
                        'status': r.get('status', 'draft'),
                        'findings_count': len(r.get('findings', [])),
                        'created_at': r.get('created_at', ''),
                        'updated_at': r.get('updated_at', ''),
                    })
            except Exception:
                continue
        reports.sort(key=lambda r: r.get('updated_at', ''), reverse=True)
        return reports

    # ── Finding Management ────────────────────────────────────────────────

    def add_finding(self, report_id: str, finding: dict) -> dict:
        report = self.get_report(report_id)
        if not report:
            return {'ok': False, 'error': 'Report not found'}
        finding['id'] = str(uuid.uuid4())[:8]
        finding.setdefault('severity', 'medium')
        finding.setdefault('cvss', 5.0)
        finding.setdefault('status', 'open')
        finding.setdefault('evidence', [])
        report['findings'].append(finding)
        report['updated_at'] = datetime.now(timezone.utc).isoformat()
        self._save_report(report)
        return {'ok': True, 'finding': finding}

    def update_finding(self, report_id: str, finding_id: str,
                       updates: dict) -> dict:
        report = self.get_report(report_id)
        if not report:
            return {'ok': False, 'error': 'Report not found'}
        for f in report['findings']:
            if f['id'] == finding_id:
                for k, v in updates.items():
                    if k != 'id':
                        f[k] = v
                report['updated_at'] = datetime.now(timezone.utc).isoformat()
                self._save_report(report)
                return {'ok': True, 'finding': f}
        return {'ok': False, 'error': 'Finding not found'}

    def delete_finding(self, report_id: str, finding_id: str) -> dict:
        report = self.get_report(report_id)
        if not report:
            return {'ok': False, 'error': 'Report not found'}
        report['findings'] = [f for f in report['findings']
                              if f['id'] != finding_id]
        report['updated_at'] = datetime.now(timezone.utc).isoformat()
        self._save_report(report)
        return {'ok': True}

    def get_finding_templates(self) -> List[dict]:
        return FINDING_TEMPLATES

    # ── Export ────────────────────────────────────────────────────────────

    def export_html(self, report_id: str) -> Optional[str]:
        """Export report as styled HTML."""
        report = self.get_report(report_id)
        if not report:
            return None

        findings_html = ''
        sorted_findings = sorted(report.get('findings', []),
                                 key=lambda f: SEVERITY_MAP.get(f.get('severity', 'info'), {}).get('order', 5))
        for i, f in enumerate(sorted_findings, 1):
            sev = f.get('severity', 'info')
            color = SEVERITY_MAP.get(sev, {}).get('color', '#666')
            findings_html += f'''
            <div class="finding">
                <h3>{i}. {_esc(f.get('title', 'Untitled'))}</h3>
                <div class="finding-meta">
                    <span class="severity" style="background:{color}">{sev.upper()}</span>
                    <span>CVSS: {f.get('cvss', 'N/A')}</span>
                    <span>Status: {f.get('status', 'open')}</span>
                </div>
                <h4>Description</h4><p>{_esc(f.get('description', ''))}</p>
                <h4>Impact</h4><p>{_esc(f.get('impact', ''))}</p>
                <h4>Remediation</h4><p>{_esc(f.get('remediation', ''))}</p>
                {'<h4>Evidence</h4><pre>' + _esc(chr(10).join(f.get('evidence', []))) + '</pre>' if f.get('evidence') else ''}
                {'<h4>References</h4><ul>' + ''.join('<li>' + _esc(r) + '</li>' for r in f.get('references', [])) + '</ul>' if f.get('references') else ''}
            </div>'''

        # Summary stats
        severity_counts = {}
        for f in report.get('findings', []):
            s = f.get('severity', 'info')
            severity_counts[s] = severity_counts.get(s, 0) + 1

        summary_html = '<div class="severity-summary">'
        for sev in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(sev, 0)
            color = SEVERITY_MAP.get(sev, {}).get('color', '#666')
            summary_html += f'<div class="sev-box" style="border-color:{color}"><span class="sev-count" style="color:{color}">{count}</span><span class="sev-label">{sev.upper()}</span></div>'
        summary_html += '</div>'

        html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{_esc(report.get('title', 'Report'))}</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:900px;margin:0 auto;padding:40px;color:#1a1a2e;line-height:1.6}}
h1{{color:#0f1117;border-bottom:3px solid #6366f1;padding-bottom:10px}}
h2{{color:#333;margin-top:2rem}}
.meta{{color:#666;font-size:0.9rem;margin:1rem 0}}
.finding{{border:1px solid #ddd;border-radius:8px;padding:1.5rem;margin:1rem 0;page-break-inside:avoid}}
.finding h3{{margin-top:0;color:#1a1a2e}}
.finding h4{{color:#555;margin:1rem 0 0.3rem;font-size:0.95rem}}
.finding-meta{{display:flex;gap:1rem;margin:0.5rem 0}}
.severity{{color:#fff;padding:2px 10px;border-radius:4px;font-size:0.8rem;font-weight:700}}
pre{{background:#f5f5f5;padding:1rem;border-radius:4px;overflow-x:auto;font-size:0.85rem}}
.severity-summary{{display:flex;gap:1rem;margin:1.5rem 0}}
.sev-box{{border:2px solid;border-radius:8px;padding:0.75rem 1.5rem;text-align:center}}
.sev-count{{font-size:1.5rem;font-weight:700;display:block}}
.sev-label{{font-size:0.7rem;text-transform:uppercase;letter-spacing:0.05em}}
.footer{{margin-top:3rem;padding-top:1rem;border-top:1px solid #ddd;font-size:0.8rem;color:#999}}
</style></head><body>
<h1>{_esc(report.get('title', 'Penetration Test Report'))}</h1>
<div class="meta">
    <div><strong>Client:</strong> {_esc(report.get('client', 'N/A'))}</div>
    <div><strong>Date:</strong> {report.get('created_at', '')[:10]}</div>
    <div><strong>Author:</strong> {_esc(report.get('author', 'AUTARCH'))}</div>
    <div><strong>Status:</strong> {report.get('status', 'draft').upper()}</div>
</div>

<h2>Executive Summary</h2>
<p>{_esc(report.get('executive_summary', 'No executive summary provided.'))}</p>

<h2>Scope</h2>
<p>{_esc(report.get('scope', 'No scope defined.'))}</p>

<h2>Methodology</h2>
<p>{_esc(report.get('methodology', ''))}</p>

<h2>Findings Overview</h2>
{summary_html}

<h2>Detailed Findings</h2>
{findings_html if findings_html else '<p>No findings recorded.</p>'}

<div class="footer">
    Generated by AUTARCH Security Platform — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>
</body></html>'''
        return html

    def export_markdown(self, report_id: str) -> Optional[str]:
        """Export report as Markdown."""
        report = self.get_report(report_id)
        if not report:
            return None

        md = f"# {report.get('title', 'Report')}\n\n"
        md += f"**Client:** {report.get('client', 'N/A')}  \n"
        md += f"**Date:** {report.get('created_at', '')[:10]}  \n"
        md += f"**Author:** {report.get('author', 'AUTARCH')}  \n"
        md += f"**Status:** {report.get('status', 'draft')}  \n\n"

        md += "## Executive Summary\n\n"
        md += report.get('executive_summary', 'N/A') + "\n\n"

        md += "## Scope\n\n"
        md += report.get('scope', 'N/A') + "\n\n"

        md += "## Findings\n\n"
        sorted_findings = sorted(report.get('findings', []),
                                 key=lambda f: SEVERITY_MAP.get(f.get('severity', 'info'), {}).get('order', 5))
        for i, f in enumerate(sorted_findings, 1):
            md += f"### {i}. [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}\n\n"
            md += f"**CVSS:** {f.get('cvss', 'N/A')} | **Status:** {f.get('status', 'open')}\n\n"
            md += f"**Description:** {f.get('description', '')}\n\n"
            md += f"**Impact:** {f.get('impact', '')}\n\n"
            md += f"**Remediation:** {f.get('remediation', '')}\n\n"
            if f.get('evidence'):
                md += "**Evidence:**\n```\n" + '\n'.join(f['evidence']) + "\n```\n\n"
            if f.get('references'):
                md += "**References:** " + ', '.join(f['references']) + "\n\n"
            md += "---\n\n"

        md += f"\n*Generated by AUTARCH — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}*\n"
        return md

    def export_json(self, report_id: str) -> Optional[str]:
        report = self.get_report(report_id)
        if not report:
            return None
        return json.dumps(report, indent=2)

    # ── Internal ──────────────────────────────────────────────────────────

    def _save_report(self, report: dict):
        path = os.path.join(self._data_dir, f'{report["id"]}.json')
        with open(path, 'w') as f:
            json.dump(report, f, indent=2)


def _esc(s: str) -> str:
    return (s or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_report_engine() -> ReportEngine:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = ReportEngine()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Reporting Engine."""
    svc = get_report_engine()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║       REPORTING ENGINE                ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — List Reports                     ║")
        print("║  2 — Create Report                    ║")
        print("║  3 — Add Finding                      ║")
        print("║  4 — Export Report                    ║")
        print("║  5 — Finding Templates                ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            reports = svc.list_reports()
            if not reports:
                print("\n  No reports.")
                continue
            for r in reports:
                print(f"  [{r['id']}] {r['title']} — {r['findings_count']} findings "
                      f"({r['status']}) {r['updated_at'][:10]}")
        elif choice == '2':
            title = input("  Report title: ").strip()
            client = input("  Client name: ").strip()
            scope = input("  Scope: ").strip()
            r = svc.create_report(title, client, scope)
            print(f"  Created report: {r['report']['id']}")
        elif choice == '3':
            rid = input("  Report ID: ").strip()
            print("  Available templates:")
            for i, t in enumerate(FINDING_TEMPLATES, 1):
                print(f"    {i}. [{t['severity'].upper()}] {t['title']}")
            sel = input("  Template # (0 for custom): ").strip()
            if sel and sel != '0':
                idx = int(sel) - 1
                if 0 <= idx < len(FINDING_TEMPLATES):
                    f = FINDING_TEMPLATES[idx].copy()
                    f.pop('id', None)
                    r = svc.add_finding(rid, f)
                    if r['ok']:
                        print(f"  Added: {f['title']}")
            else:
                title = input("  Title: ").strip()
                severity = input("  Severity (critical/high/medium/low/info): ").strip()
                desc = input("  Description: ").strip()
                r = svc.add_finding(rid, {'title': title, 'severity': severity,
                                          'description': desc})
                if r['ok']:
                    print(f"  Added finding: {r['finding']['id']}")
        elif choice == '4':
            rid = input("  Report ID: ").strip()
            fmt = input("  Format (html/markdown/json): ").strip() or 'html'
            if fmt == 'html':
                content = svc.export_html(rid)
            elif fmt == 'markdown':
                content = svc.export_markdown(rid)
            else:
                content = svc.export_json(rid)
            if content:
                ext = {'html': 'html', 'markdown': 'md', 'json': 'json'}.get(fmt, 'txt')
                outpath = os.path.join(svc._data_dir, f'{rid}.{ext}')
                with open(outpath, 'w') as f:
                    f.write(content)
                print(f"  Exported to: {outpath}")
            else:
                print("  Report not found.")
        elif choice == '5':
            for t in FINDING_TEMPLATES:
                print(f"  [{t['severity'].upper():8s}] {t['title']} (CVSS {t['cvss']})")
