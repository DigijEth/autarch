"""
AUTARCH Report Generator
Generate HTML reports for scan results
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


class ReportGenerator:
    """Generate HTML reports for OSINT scan results."""

    def __init__(self, output_dir: str = None):
        """Initialize report generator.

        Args:
            output_dir: Directory to save reports. Defaults to results/reports.
        """
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            from core.paths import get_reports_dir
            self.output_dir = get_reports_dir()

        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _get_html_template(self) -> str:
        """Get base HTML template."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --accent-purple: #bc8cff;
            --border-color: #30363d;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        header {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
        }}

        header h1 {{
            color: var(--accent-red);
            font-size: 2em;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}

        header h1::before {{
            content: '';
            display: inline-block;
            width: 40px;
            height: 40px;
            background: var(--accent-red);
            mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'/%3E%3C/svg%3E");
            -webkit-mask-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z'/%3E%3C/svg%3E");
        }}

        .meta {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}

        .meta span {{
            margin-right: 20px;
        }}

        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}

        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: var(--accent-green);
        }}

        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}

        .stat-card.warning .number {{
            color: var(--accent-yellow);
        }}

        .stat-card.info .number {{
            color: var(--accent-blue);
        }}

        section {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 25px;
        }}

        section h2 {{
            color: var(--accent-blue);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        th {{
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
        }}

        tr:hover {{
            background: var(--bg-tertiary);
        }}

        a {{
            color: var(--accent-blue);
            text-decoration: none;
        }}

        a:hover {{
            text-decoration: underline;
        }}

        .confidence {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }}

        .confidence.high {{
            background: rgba(63, 185, 80, 0.2);
            color: var(--accent-green);
        }}

        .confidence.medium {{
            background: rgba(210, 153, 34, 0.2);
            color: var(--accent-yellow);
        }}

        .confidence.low {{
            background: rgba(248, 81, 73, 0.2);
            color: var(--accent-red);
        }}

        .category-tag {{
            display: inline-block;
            padding: 2px 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            font-size: 0.8em;
            color: var(--text-secondary);
        }}

        .footer {{
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 0.85em;
        }}

        .nsfw-warning {{
            background: rgba(248, 81, 73, 0.1);
            border: 1px solid var(--accent-red);
            color: var(--accent-red);
            padding: 10px 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }}

        .severity-critical {{
            background: rgba(248, 81, 73, 0.2);
            color: #f85149;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85em;
        }}

        .severity-high {{
            background: rgba(255, 100, 60, 0.2);
            color: #ff6a3d;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85em;
        }}

        .severity-medium {{
            background: rgba(210, 153, 34, 0.2);
            color: #d29922;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85em;
        }}

        .severity-low {{
            background: rgba(88, 166, 255, 0.2);
            color: #58a6ff;
            padding: 2px 8px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 0.85em;
        }}

        .score-gauge {{
            width: 100%;
            height: 30px;
            background: var(--bg-tertiary);
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }}

        .score-gauge .fill {{
            height: 100%;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
</body>
</html>'''

    def generate_username_report(
        self,
        username: str,
        results: List[Dict],
        total_checked: int,
        scan_time: float = 0
    ) -> str:
        """Generate HTML report for username scan.

        Args:
            username: The username that was scanned.
            results: List of found profile dictionaries.
            total_checked: Total sites checked.
            scan_time: Total scan time in seconds.

        Returns:
            Path to generated report file.
        """
        # Categorize results
        high_conf = [r for r in results if r.get('confidence', 0) >= 80 and r.get('status') != 'restricted']
        med_conf = [r for r in results if 60 <= r.get('confidence', 0) < 80 and r.get('status') != 'restricted']
        low_conf = [r for r in results if r.get('confidence', 0) < 60 and r.get('status') != 'restricted']
        restricted = [r for r in results if r.get('status') == 'restricted']

        # Group by category
        by_category = {}
        for r in results:
            if r.get('status') != 'restricted' and r.get('confidence', 0) >= 60:
                cat = r.get('category', 'other')
                if cat not in by_category:
                    by_category[cat] = []
                by_category[cat].append(r)

        # Build stats section
        stats_html = f'''
        <div class="stats">
            <div class="stat-card">
                <div class="number">{total_checked}</div>
                <div class="label">Sites Checked</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(results)}</div>
                <div class="label">Total Found</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(high_conf)}</div>
                <div class="label">High Confidence</div>
            </div>
            <div class="stat-card info">
                <div class="number">{len(med_conf)}</div>
                <div class="label">Medium Confidence</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{len(restricted)}</div>
                <div class="label">Restricted</div>
            </div>
        </div>
        '''

        # Build results table
        def get_confidence_class(conf):
            if conf >= 80:
                return 'high'
            elif conf >= 60:
                return 'medium'
            return 'low'

        confirmed_rows = ''
        for r in sorted(high_conf + med_conf, key=lambda x: -x.get('confidence', 0)):
            conf = r.get('confidence', 0)
            conf_class = get_confidence_class(conf)
            tracker_badge = ' <span style="color: var(--text-secondary);">[tracker]</span>' if r.get('is_tracker') else ''
            confirmed_rows += f'''
            <tr>
                <td>{r.get('name', 'Unknown')}{tracker_badge}</td>
                <td><a href="{r.get('url', '#')}" target="_blank">{r.get('url', '')}</a></td>
                <td><span class="category-tag">{r.get('category', 'other')}</span></td>
                <td><span class="confidence {conf_class}">{conf}%</span></td>
            </tr>
            '''

        # Build category breakdown
        category_rows = ''
        for cat, items in sorted(by_category.items(), key=lambda x: -len(x[1])):
            category_rows += f'''
            <tr>
                <td>{cat}</td>
                <td>{len(items)}</td>
            </tr>
            '''

        # Restricted section
        restricted_rows = ''
        for r in restricted[:30]:
            restricted_rows += f'''
            <tr>
                <td>{r.get('name', 'Unknown')}</td>
                <td><a href="{r.get('url', '#')}" target="_blank">{r.get('url', '')}</a></td>
                <td><span class="category-tag">{r.get('category', 'other')}</span></td>
                <td><span class="confidence low">Restricted</span></td>
            </tr>
            '''

        # Build full content
        content = f'''
        <header>
            <h1>AUTARCH Username Report</h1>
            <div class="meta">
                <span><strong>Target:</strong> {username}</span>
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Scan Time:</strong> {scan_time:.1f}s</span>
            </div>
        </header>

        {stats_html}

        <section>
            <h2>Confirmed Profiles ({len(high_conf) + len(med_conf)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Site</th>
                        <th>URL</th>
                        <th>Category</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {confirmed_rows if confirmed_rows else '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No confirmed profiles found</td></tr>'}
                </tbody>
            </table>
        </section>

        <section>
            <h2>By Category</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Count</th>
                    </tr>
                </thead>
                <tbody>
                    {category_rows if category_rows else '<tr><td colspan="2" style="text-align: center; color: var(--text-secondary);">No categories</td></tr>'}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Restricted Access ({len(restricted)})</h2>
            <p style="color: var(--text-secondary); margin-bottom: 15px;">
                These sites returned 403/401 errors - the profile may exist but requires authentication.
            </p>
            <table>
                <thead>
                    <tr>
                        <th>Site</th>
                        <th>URL</th>
                        <th>Category</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    {restricted_rows if restricted_rows else '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">None</td></tr>'}
                </tbody>
            </table>
        </section>

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
            <p>Report generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>
        '''

        # Generate HTML
        html = self._get_html_template().format(
            title=f"AUTARCH Report - {username}",
            content=content
        )

        # Save report
        filename = f"{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        return str(filepath)

    def generate_geoip_report(self, results: List[Dict]) -> str:
        """Generate HTML report for GEO IP lookups.

        Args:
            results: List of GEO IP lookup result dictionaries.

        Returns:
            Path to generated report file.
        """
        rows = ''
        for r in results:
            if 'error' in r:
                rows += f'''
                <tr>
                    <td>{r.get('target', 'Unknown')}</td>
                    <td colspan="5" style="color: var(--accent-red);">Error: {r['error']}</td>
                </tr>
                '''
            else:
                map_link = f'<a href="{r.get("map_osm", "#")}" target="_blank">View Map</a>' if r.get('map_osm') else '-'
                rows += f'''
                <tr>
                    <td>{r.get('target', '-')}</td>
                    <td>{r.get('ipv4', '-')}</td>
                    <td>{r.get('country_code', '-')}</td>
                    <td>{r.get('region', '-')}</td>
                    <td>{r.get('city', '-')}</td>
                    <td>{r.get('isp', '-')}</td>
                    <td>{map_link}</td>
                </tr>
                '''

        content = f'''
        <header>
            <h1>AUTARCH GEO IP Report</h1>
            <div class="meta">
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Total Lookups:</strong> {len(results)}</span>
            </div>
        </header>

        <section>
            <h2>GEO IP Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Target</th>
                        <th>IPv4</th>
                        <th>Country</th>
                        <th>Region</th>
                        <th>City</th>
                        <th>ISP</th>
                        <th>Map</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
        </div>
        '''

        html = self._get_html_template().format(
            title="AUTARCH GEO IP Report",
            content=content
        )

        filename = f"geoip_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

        return str(filepath)


    def generate_security_audit_report(
        self,
        system_info: Dict,
        issues: List[Dict],
        score: int
    ) -> str:
        """Generate HTML report for security audit.

        Args:
            system_info: System information dictionary.
            issues: List of security issues found.
            score: Security score 0-100.

        Returns:
            Path to generated report file.
        """
        # Score color
        if score >= 80:
            score_color = "var(--accent-green)"
        elif score >= 60:
            score_color = "var(--accent-yellow)"
        else:
            score_color = "var(--accent-red)"

        # System info rows
        sys_rows = ''
        for key, val in system_info.items():
            sys_rows += f'<tr><td><strong>{key}</strong></td><td>{val}</td></tr>\n'

        # Score gauge
        score_html = f'''
        <div class="score-gauge">
            <div class="fill" style="width: {score}%; background: {score_color}; color: var(--bg-primary);">
                {score}/100
            </div>
        </div>
        '''

        # Issues by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for issue in issues:
            sev = issue.get('severity', 'LOW').upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Issues table
        issue_rows = ''
        for issue in sorted(issues, key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].index(x.get('severity', 'LOW').upper())):
            sev = issue.get('severity', 'LOW').upper()
            sev_class = f'severity-{sev.lower()}'
            issue_rows += f'''
            <tr>
                <td><span class="{sev_class}">{sev}</span></td>
                <td>{issue.get('title', '')}</td>
                <td>{issue.get('description', '')}</td>
                <td>{issue.get('recommendation', '')}</td>
            </tr>
            '''

        content = f'''
        <header>
            <h1>Security Audit Report</h1>
            <div class="meta">
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Issues Found:</strong> {len(issues)}</span>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number" style="color: {score_color};">{score}</div>
                <div class="label">Security Score</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #f85149;">
                <div class="number" style="color: #f85149;">{severity_counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #ff6a3d;">
                <div class="number" style="color: #ff6a3d;">{severity_counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #d29922;">
                <div class="number" style="color: #d29922;">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #58a6ff;">
                <div class="number" style="color: #58a6ff;">{severity_counts['LOW']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        {score_html}

        <section>
            <h2>System Information</h2>
            <table>
                <thead><tr><th>Property</th><th>Value</th></tr></thead>
                <tbody>{sys_rows}</tbody>
            </table>
        </section>

        <section>
            <h2>Security Issues ({len(issues)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Description</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
                    {issue_rows if issue_rows else '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No issues found</td></tr>'}
                </tbody>
            </table>
        </section>

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
        </div>
        '''

        html = self._get_html_template().format(
            title="AUTARCH Security Audit Report",
            content=content
        )

        filename = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return str(filepath)

    def generate_network_scan_report(
        self,
        target: str,
        hosts: List[Dict],
        scan_time: float = 0
    ) -> str:
        """Generate HTML report for network scan.

        Args:
            target: Target subnet/IP.
            hosts: List of host dictionaries with ports/services.
            scan_time: Total scan time in seconds.

        Returns:
            Path to generated report file.
        """
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        all_services = set()
        for h in hosts:
            for p in h.get('ports', []):
                all_services.add(p.get('service', 'unknown'))

        # Host rows
        host_rows = ''
        for h in hosts:
            ports_str = ', '.join(str(p.get('port', '')) for p in h.get('ports', []))
            services_str = ', '.join(set(p.get('service', '') for p in h.get('ports', [])))
            host_rows += f'''
            <tr>
                <td>{h.get('ip', '')}</td>
                <td>{h.get('hostname', '-')}</td>
                <td>{h.get('os_guess', '-')}</td>
                <td>{ports_str or '-'}</td>
                <td>{services_str or '-'}</td>
            </tr>
            '''

        # Service distribution
        svc_count = {}
        for h in hosts:
            for p in h.get('ports', []):
                svc = p.get('service', 'unknown')
                svc_count[svc] = svc_count.get(svc, 0) + 1

        svc_rows = ''
        for svc, count in sorted(svc_count.items(), key=lambda x: -x[1]):
            svc_rows += f'<tr><td>{svc}</td><td>{count}</td></tr>\n'

        content = f'''
        <header>
            <h1>Network Scan Report</h1>
            <div class="meta">
                <span><strong>Target:</strong> {target}</span>
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Scan Time:</strong> {scan_time:.1f}s</span>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{len(hosts)}</div>
                <div class="label">Hosts Found</div>
            </div>
            <div class="stat-card info">
                <div class="number">{total_ports}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat-card warning">
                <div class="number">{len(all_services)}</div>
                <div class="label">Unique Services</div>
            </div>
        </div>

        <section>
            <h2>Host Map ({len(hosts)} hosts)</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>Services</th>
                    </tr>
                </thead>
                <tbody>
                    {host_rows if host_rows else '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No hosts found</td></tr>'}
                </tbody>
            </table>
        </section>

        <section>
            <h2>Service Distribution</h2>
            <table>
                <thead><tr><th>Service</th><th>Count</th></tr></thead>
                <tbody>{svc_rows}</tbody>
            </table>
        </section>

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
        </div>
        '''

        html = self._get_html_template().format(
            title=f"AUTARCH Network Scan - {target}",
            content=content
        )

        safe_target = target.replace('/', '_').replace('.', '-')
        filename = f"network_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return str(filepath)

    def generate_vulnerability_report(
        self,
        target: str,
        correlations: List[Dict],
        scan_time: float = 0
    ) -> str:
        """Generate HTML report for vulnerability scan.

        Args:
            target: Target IP/hostname.
            correlations: List of service-CVE correlation dicts.
            scan_time: Total scan time in seconds.

        Returns:
            Path to generated report file.
        """
        total_cves = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for corr in correlations:
            for cve in corr.get('cves', []):
                total_cves += 1
                score = cve.get('cvss', 0)
                if score >= 9.0:
                    severity_counts['CRITICAL'] += 1
                elif score >= 7.0:
                    severity_counts['HIGH'] += 1
                elif score >= 4.0:
                    severity_counts['MEDIUM'] += 1
                else:
                    severity_counts['LOW'] += 1

        # Per-service CVE sections
        service_sections = ''
        for corr in correlations:
            svc = corr.get('service', {})
            cves = corr.get('cves', [])
            svc_label = f"{svc.get('service', 'unknown')}:{svc.get('version', '?')} on port {svc.get('port', '?')}"

            cve_rows = ''
            for cve in sorted(cves, key=lambda x: -x.get('cvss', 0)):
                score = cve.get('cvss', 0)
                if score >= 9.0:
                    sev, sev_class = 'CRITICAL', 'severity-critical'
                elif score >= 7.0:
                    sev, sev_class = 'HIGH', 'severity-high'
                elif score >= 4.0:
                    sev, sev_class = 'MEDIUM', 'severity-medium'
                else:
                    sev, sev_class = 'LOW', 'severity-low'

                cve_rows += f'''
                <tr>
                    <td><a href="https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}" target="_blank">{cve.get('id', '')}</a></td>
                    <td><span class="{sev_class}">{sev} ({score})</span></td>
                    <td>{cve.get('description', '')[:200]}</td>
                </tr>
                '''

            service_sections += f'''
            <section>
                <h2>{svc_label} ({len(cves)} CVEs)</h2>
                <table>
                    <thead><tr><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead>
                    <tbody>{cve_rows if cve_rows else '<tr><td colspan="3" style="text-align:center; color:var(--text-secondary);">No CVEs found</td></tr>'}</tbody>
                </table>
            </section>
            '''

        content = f'''
        <header>
            <h1>Vulnerability Report</h1>
            <div class="meta">
                <span><strong>Target:</strong> {target}</span>
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                <span><strong>Scan Time:</strong> {scan_time:.1f}s</span>
            </div>
        </header>

        <div class="stats">
            <div class="stat-card">
                <div class="number">{total_cves}</div>
                <div class="label">Total CVEs</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #f85149;">
                <div class="number" style="color: #f85149;">{severity_counts['CRITICAL']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #ff6a3d;">
                <div class="number" style="color: #ff6a3d;">{severity_counts['HIGH']}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #d29922;">
                <div class="number" style="color: #d29922;">{severity_counts['MEDIUM']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card" style="border-left: 3px solid #58a6ff;">
                <div class="number" style="color: #58a6ff;">{severity_counts['LOW']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        {service_sections}

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
        </div>
        '''

        html = self._get_html_template().format(
            title=f"AUTARCH Vulnerability Report - {target}",
            content=content
        )

        safe_target = target.replace('/', '_').replace('.', '-')
        filename = f"vulns_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return str(filepath)

    def generate_pentest_report(
        self,
        target: str,
        network_data: Optional[List[Dict]] = None,
        vuln_data: Optional[List[Dict]] = None,
        exploit_data: Optional[List[Dict]] = None,
        audit_data: Optional[Dict] = None
    ) -> str:
        """Generate combined pentest report.

        Args:
            target: Target IP/hostname.
            network_data: Network map host list (optional).
            vuln_data: Vulnerability correlations (optional).
            exploit_data: Exploit suggestions (optional).
            audit_data: Security audit data with 'system_info', 'issues', 'score' (optional).

        Returns:
            Path to generated report file.
        """
        sections_html = ''

        # Executive summary
        summary_items = []
        if network_data:
            summary_items.append(f"<li>{len(network_data)} hosts discovered</li>")
        if vuln_data:
            total_cves = sum(len(c.get('cves', [])) for c in vuln_data)
            summary_items.append(f"<li>{total_cves} vulnerabilities identified across {len(vuln_data)} services</li>")
        if exploit_data:
            summary_items.append(f"<li>{len(exploit_data)} potential exploit paths identified</li>")
        if audit_data:
            summary_items.append(f"<li>Security score: {audit_data.get('score', 'N/A')}/100</li>")

        sections_html += f'''
        <section>
            <h2>Executive Summary</h2>
            <ul style="list-style: disc; padding-left: 20px; line-height: 2;">
                {''.join(summary_items) if summary_items else '<li>No data collected</li>'}
            </ul>
        </section>
        '''

        # Network map section
        if network_data:
            net_rows = ''
            for h in network_data:
                ports_str = ', '.join(str(p.get('port', '')) for p in h.get('ports', []))
                services_str = ', '.join(set(p.get('service', '') for p in h.get('ports', [])))
                net_rows += f'''
                <tr>
                    <td>{h.get('ip', '')}</td>
                    <td>{h.get('hostname', '-')}</td>
                    <td>{h.get('os_guess', '-')}</td>
                    <td>{ports_str or '-'}</td>
                    <td>{services_str or '-'}</td>
                </tr>
                '''
            sections_html += f'''
            <section>
                <h2>Network Map ({len(network_data)} hosts)</h2>
                <table>
                    <thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Ports</th><th>Services</th></tr></thead>
                    <tbody>{net_rows}</tbody>
                </table>
            </section>
            '''

        # Vulnerabilities section
        if vuln_data:
            vuln_rows = ''
            for corr in vuln_data:
                svc = corr.get('service', {})
                for cve in sorted(corr.get('cves', []), key=lambda x: -x.get('cvss', 0)):
                    score = cve.get('cvss', 0)
                    if score >= 9.0:
                        sev, sev_class = 'CRITICAL', 'severity-critical'
                    elif score >= 7.0:
                        sev, sev_class = 'HIGH', 'severity-high'
                    elif score >= 4.0:
                        sev, sev_class = 'MEDIUM', 'severity-medium'
                    else:
                        sev, sev_class = 'LOW', 'severity-low'
                    vuln_rows += f'''
                    <tr>
                        <td>{svc.get('service', '')}:{svc.get('port', '')}</td>
                        <td><a href="https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}" target="_blank">{cve.get('id', '')}</a></td>
                        <td><span class="{sev_class}">{sev} ({score})</span></td>
                        <td>{cve.get('description', '')[:150]}</td>
                    </tr>
                    '''
            sections_html += f'''
            <section>
                <h2>Vulnerabilities</h2>
                <table>
                    <thead><tr><th>Service</th><th>CVE</th><th>Severity</th><th>Description</th></tr></thead>
                    <tbody>{vuln_rows}</tbody>
                </table>
            </section>
            '''

        # Exploit suggestions section
        if exploit_data:
            exploit_rows = ''
            for i, exp in enumerate(exploit_data, 1):
                exploit_rows += f'''
                <tr>
                    <td>{i}</td>
                    <td><code>{exp.get('module', '')}</code></td>
                    <td>{exp.get('target', '')}</td>
                    <td>{exp.get('cve', '-')}</td>
                    <td>{exp.get('reasoning', '')}</td>
                </tr>
                '''
            sections_html += f'''
            <section>
                <h2>Exploit Suggestions ({len(exploit_data)})</h2>
                <table>
                    <thead><tr><th>#</th><th>Module</th><th>Target</th><th>CVE</th><th>Reasoning</th></tr></thead>
                    <tbody>{exploit_rows}</tbody>
                </table>
            </section>
            '''

        # Security audit section
        if audit_data:
            score = audit_data.get('score', 0)
            if score >= 80:
                score_color = "var(--accent-green)"
            elif score >= 60:
                score_color = "var(--accent-yellow)"
            else:
                score_color = "var(--accent-red)"

            audit_issue_rows = ''
            for issue in audit_data.get('issues', []):
                sev = issue.get('severity', 'LOW').upper()
                sev_class = f'severity-{sev.lower()}'
                audit_issue_rows += f'''
                <tr>
                    <td><span class="{sev_class}">{sev}</span></td>
                    <td>{issue.get('title', '')}</td>
                    <td>{issue.get('description', '')}</td>
                </tr>
                '''
            sections_html += f'''
            <section>
                <h2>Security Audit (Score: {score}/100)</h2>
                <div class="score-gauge">
                    <div class="fill" style="width: {score}%; background: {score_color}; color: var(--bg-primary);">
                        {score}/100
                    </div>
                </div>
                <table style="margin-top: 15px;">
                    <thead><tr><th>Severity</th><th>Issue</th><th>Description</th></tr></thead>
                    <tbody>{audit_issue_rows if audit_issue_rows else '<tr><td colspan="3" style="text-align:center; color:var(--text-secondary);">No issues</td></tr>'}</tbody>
                </table>
            </section>
            '''

        content = f'''
        <header>
            <h1>Penetration Test Report</h1>
            <div class="meta">
                <span><strong>Target:</strong> {target}</span>
                <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </header>

        {sections_html}

        <div class="footer">
            <p>Generated by AUTARCH Framework - darkHal Security Group</p>
        </div>
        '''

        html = self._get_html_template().format(
            title=f"AUTARCH Pentest Report - {target}",
            content=content
        )

        safe_target = target.replace('/', '_').replace('.', '-')
        filename = f"pentest_{safe_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return str(filepath)


def get_report_generator(output_dir: str = None) -> ReportGenerator:
    """Get a ReportGenerator instance.

    Args:
        output_dir: Optional output directory.

    Returns:
        ReportGenerator instance.
    """
    return ReportGenerator(output_dir)
