"""
AUTARCH CVE Database Module
SQLite-based local CVE database with NVD API synchronization
https://nvd.nist.gov/developers/vulnerabilities
"""

import os
import json
import time
import sqlite3
import platform
import subprocess
import urllib.request
import urllib.parse
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Callable

from .banner import Colors
from .config import get_config


class CVEDatabase:
    """SQLite-based CVE Database with NVD API synchronization."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DB_VERSION = 1
    RESULTS_PER_PAGE = 2000  # NVD max is 2000

    # OS to CPE mapping for common systems
    OS_CPE_MAP = {
        'ubuntu': 'cpe:2.3:o:canonical:ubuntu_linux',
        'debian': 'cpe:2.3:o:debian:debian_linux',
        'fedora': 'cpe:2.3:o:fedoraproject:fedora',
        'centos': 'cpe:2.3:o:centos:centos',
        'rhel': 'cpe:2.3:o:redhat:enterprise_linux',
        'rocky': 'cpe:2.3:o:rockylinux:rocky_linux',
        'alma': 'cpe:2.3:o:almalinux:almalinux',
        'arch': 'cpe:2.3:o:archlinux:arch_linux',
        'opensuse': 'cpe:2.3:o:opensuse:opensuse',
        'suse': 'cpe:2.3:o:suse:suse_linux',
        'kali': 'cpe:2.3:o:kali:kali_linux',
        'mint': 'cpe:2.3:o:linuxmint:linux_mint',
        'windows': 'cpe:2.3:o:microsoft:windows',
        'macos': 'cpe:2.3:o:apple:macos',
        'darwin': 'cpe:2.3:o:apple:macos',
    }

    # SQL Schema
    SCHEMA = """
    -- CVE main table
    CREATE TABLE IF NOT EXISTS cves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        description TEXT,
        published TEXT,
        modified TEXT,
        cvss_v3_score REAL,
        cvss_v3_severity TEXT,
        cvss_v3_vector TEXT,
        cvss_v2_score REAL,
        cvss_v2_severity TEXT,
        cvss_v2_vector TEXT
    );

    -- CPE (affected products) table
    CREATE TABLE IF NOT EXISTS cve_cpes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        cpe_criteria TEXT NOT NULL,
        vulnerable INTEGER DEFAULT 1,
        version_start TEXT,
        version_end TEXT,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
    );

    -- References table
    CREATE TABLE IF NOT EXISTS cve_references (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        url TEXT NOT NULL,
        source TEXT,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
    );

    -- Weaknesses (CWE) table
    CREATE TABLE IF NOT EXISTS cve_weaknesses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT NOT NULL,
        cwe_id TEXT NOT NULL,
        FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
    );

    -- Metadata table
    CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    -- Indexes for fast queries
    CREATE INDEX IF NOT EXISTS idx_cve_id ON cves(cve_id);
    CREATE INDEX IF NOT EXISTS idx_cve_severity ON cves(cvss_v3_severity);
    CREATE INDEX IF NOT EXISTS idx_cve_score ON cves(cvss_v3_score);
    CREATE INDEX IF NOT EXISTS idx_cve_published ON cves(published);
    CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cve_cpes(cve_id);
    CREATE INDEX IF NOT EXISTS idx_cpe_criteria ON cve_cpes(cpe_criteria);
    CREATE INDEX IF NOT EXISTS idx_ref_cve ON cve_references(cve_id);
    CREATE INDEX IF NOT EXISTS idx_weakness_cve ON cve_weaknesses(cve_id);
    """

    def __init__(self, db_path: str = None):
        """Initialize CVE database.

        Args:
            db_path: Path to SQLite database. Defaults to data/cve/cve.db
        """
        if db_path is None:
            from core.paths import get_data_dir
            self.data_dir = get_data_dir() / "cve"
            self.db_path = self.data_dir / "cve.db"
        else:
            self.db_path = Path(db_path)
            self.data_dir = self.db_path.parent

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.system_info = self._detect_system()
        self._conn = None
        self._lock = threading.Lock()
        self._init_database()

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-safe database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_database(self):
        """Initialize database schema."""
        with self._lock:
            conn = self._get_connection()
            conn.executescript(self.SCHEMA)
            conn.commit()

    def _detect_system(self) -> Dict[str, str]:
        """Detect the current system information."""
        info = {
            'os_type': platform.system().lower(),
            'os_name': '',
            'os_version': '',
            'os_id': '',
            'kernel': platform.release(),
            'arch': platform.machine(),
            'cpe_prefix': '',
        }

        if info['os_type'] == 'linux':
            os_release = Path("/etc/os-release")
            if os_release.exists():
                content = os_release.read_text()
                for line in content.split('\n'):
                    if line.startswith('ID='):
                        info['os_id'] = line.split('=')[1].strip('"').lower()
                    elif line.startswith('VERSION_ID='):
                        info['os_version'] = line.split('=')[1].strip('"')
                    elif line.startswith('PRETTY_NAME='):
                        info['os_name'] = line.split('=', 1)[1].strip('"')

            if not info['os_id']:
                if Path("/etc/debian_version").exists():
                    info['os_id'] = 'debian'
                elif Path("/etc/redhat-release").exists():
                    info['os_id'] = 'rhel'
                elif Path("/etc/arch-release").exists():
                    info['os_id'] = 'arch'

        elif info['os_type'] == 'darwin':
            info['os_id'] = 'macos'
            try:
                result = subprocess.run(['sw_vers', '-productVersion'],
                                       capture_output=True, text=True, timeout=5)
                info['os_version'] = result.stdout.strip()
            except:
                pass

        elif info['os_type'] == 'windows':
            info['os_id'] = 'windows'
            info['os_version'] = platform.version()
            info['os_name'] = platform.platform()

        for os_key, cpe in self.OS_CPE_MAP.items():
            if os_key in info['os_id']:
                info['cpe_prefix'] = cpe
                break

        return info

    def get_system_info(self) -> Dict[str, str]:
        """Get detected system information."""
        return self.system_info.copy()

    def get_db_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {
                'db_path': str(self.db_path),
                'db_size_mb': round(self.db_path.stat().st_size / 1024 / 1024, 2) if self.db_path.exists() else 0,
                'total_cves': 0,
                'total_cpes': 0,
                'last_sync': None,
                'last_modified': None,
            }

            try:
                cursor.execute("SELECT COUNT(*) FROM cves")
                stats['total_cves'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM cve_cpes")
                stats['total_cpes'] = cursor.fetchone()[0]

                cursor.execute("SELECT value FROM metadata WHERE key = 'last_sync'")
                row = cursor.fetchone()
                if row:
                    stats['last_sync'] = row[0]

                cursor.execute("SELECT value FROM metadata WHERE key = 'last_modified'")
                row = cursor.fetchone()
                if row:
                    stats['last_modified'] = row[0]

                # Count by severity
                cursor.execute("""
                    SELECT cvss_v3_severity, COUNT(*)
                    FROM cves
                    WHERE cvss_v3_severity IS NOT NULL
                    GROUP BY cvss_v3_severity
                """)
                stats['by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}

            except sqlite3.Error:
                pass

            return stats

    # =========================================================================
    # NVD API METHODS
    # =========================================================================

    def _make_nvd_request(self, params: Dict[str, str], verbose: bool = False) -> Optional[Dict]:
        """Make a request to the NVD API."""
        url = f"{self.NVD_API_BASE}?{urllib.parse.urlencode(params)}"

        if verbose:
            print(f"{Colors.DIM}    API: {url[:80]}...{Colors.RESET}")

        headers = {
            'User-Agent': 'AUTARCH-Security-Framework/1.0',
            'Accept': 'application/json',
        }

        config = get_config()
        api_key = config.get('nvd', 'api_key', fallback='')
        if api_key:
            headers['apiKey'] = api_key

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as response:
                return json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            if verbose:
                print(f"{Colors.RED}[X] NVD API error: {e.code} - {e.reason}{Colors.RESET}")
            return None
        except urllib.error.URLError as e:
            if verbose:
                print(f"{Colors.RED}[X] Network error: {e.reason}{Colors.RESET}")
            return None
        except Exception as e:
            if verbose:
                print(f"{Colors.RED}[X] Request failed: {e}{Colors.RESET}")
            return None

    def _parse_cve_data(self, vuln: Dict) -> Dict:
        """Parse CVE data from NVD API response."""
        cve_data = vuln.get('cve', {})
        cve_id = cve_data.get('id', '')

        # Description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # CVSS scores
        metrics = cve_data.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
        cvss_v2 = metrics.get('cvssMetricV2', [])

        cvss_v3_score = None
        cvss_v3_severity = None
        cvss_v3_vector = None
        cvss_v2_score = None
        cvss_v2_severity = None
        cvss_v2_vector = None

        if cvss_v3:
            cvss_data = cvss_v3[0].get('cvssData', {})
            cvss_v3_score = cvss_data.get('baseScore')
            cvss_v3_severity = cvss_data.get('baseSeverity')
            cvss_v3_vector = cvss_data.get('vectorString')

        if cvss_v2:
            cvss_data = cvss_v2[0].get('cvssData', {})
            cvss_v2_score = cvss_data.get('baseScore')
            cvss_v2_severity = cvss_v2[0].get('baseSeverity')
            cvss_v2_vector = cvss_data.get('vectorString')

        # CPEs (affected products)
        cpes = []
        for config in cve_data.get('configurations', []):
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    cpes.append({
                        'criteria': match.get('criteria', ''),
                        'vulnerable': match.get('vulnerable', True),
                        'version_start': match.get('versionStartIncluding') or match.get('versionStartExcluding'),
                        'version_end': match.get('versionEndIncluding') or match.get('versionEndExcluding'),
                    })

        # References
        references = [
            {'url': ref.get('url', ''), 'source': ref.get('source', '')}
            for ref in cve_data.get('references', [])
        ]

        # Weaknesses
        weaknesses = []
        for weakness in cve_data.get('weaknesses', []):
            for desc in weakness.get('description', []):
                if desc.get('lang') == 'en' and desc.get('value', '').startswith('CWE-'):
                    weaknesses.append(desc.get('value'))

        return {
            'cve_id': cve_id,
            'description': description,
            'published': cve_data.get('published', ''),
            'modified': cve_data.get('lastModified', ''),
            'cvss_v3_score': cvss_v3_score,
            'cvss_v3_severity': cvss_v3_severity,
            'cvss_v3_vector': cvss_v3_vector,
            'cvss_v2_score': cvss_v2_score,
            'cvss_v2_severity': cvss_v2_severity,
            'cvss_v2_vector': cvss_v2_vector,
            'cpes': cpes,
            'references': references,
            'weaknesses': weaknesses,
        }

    def _insert_cve(self, conn: sqlite3.Connection, cve_data: Dict):
        """Insert or update a CVE in the database."""
        cursor = conn.cursor()

        # Insert/update main CVE record
        cursor.execute("""
            INSERT OR REPLACE INTO cves
            (cve_id, description, published, modified,
             cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
             cvss_v2_score, cvss_v2_severity, cvss_v2_vector)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            cve_data['cve_id'],
            cve_data['description'],
            cve_data['published'],
            cve_data['modified'],
            cve_data['cvss_v3_score'],
            cve_data['cvss_v3_severity'],
            cve_data['cvss_v3_vector'],
            cve_data['cvss_v2_score'],
            cve_data['cvss_v2_severity'],
            cve_data['cvss_v2_vector'],
        ))

        cve_id = cve_data['cve_id']

        # Clear existing related data
        cursor.execute("DELETE FROM cve_cpes WHERE cve_id = ?", (cve_id,))
        cursor.execute("DELETE FROM cve_references WHERE cve_id = ?", (cve_id,))
        cursor.execute("DELETE FROM cve_weaknesses WHERE cve_id = ?", (cve_id,))

        # Insert CPEs
        for cpe in cve_data['cpes']:
            cursor.execute("""
                INSERT INTO cve_cpes (cve_id, cpe_criteria, vulnerable, version_start, version_end)
                VALUES (?, ?, ?, ?, ?)
            """, (cve_id, cpe['criteria'], 1 if cpe['vulnerable'] else 0,
                  cpe['version_start'], cpe['version_end']))

        # Insert references (limit to 10)
        for ref in cve_data['references'][:10]:
            cursor.execute("""
                INSERT INTO cve_references (cve_id, url, source)
                VALUES (?, ?, ?)
            """, (cve_id, ref['url'], ref['source']))

        # Insert weaknesses
        for cwe in cve_data['weaknesses']:
            cursor.execute("""
                INSERT INTO cve_weaknesses (cve_id, cwe_id)
                VALUES (?, ?)
            """, (cve_id, cwe))

    # =========================================================================
    # DATABASE SYNC
    # =========================================================================

    def sync_database(
        self,
        days_back: int = 120,
        full_sync: bool = False,
        progress_callback: Callable[[str, int, int], None] = None,
        verbose: bool = True
    ) -> Dict[str, Any]:
        """Synchronize database with NVD.

        Args:
            days_back: For incremental sync, get CVEs from last N days.
            full_sync: If True, download entire database (WARNING: slow, 200k+ CVEs).
            progress_callback: Callback function(message, current, total).
            verbose: Show progress messages.

        Returns:
            Sync statistics dictionary.
        """
        stats = {
            'started': datetime.now().isoformat(),
            'cves_processed': 0,
            'cves_added': 0,
            'cves_updated': 0,
            'errors': 0,
            'completed': False,
        }

        if verbose:
            print(f"{Colors.CYAN}[*] Starting CVE database sync...{Colors.RESET}")

        # Determine date range
        if full_sync:
            # Start from 1999 (first CVEs)
            start_date = datetime(1999, 1, 1)
            if verbose:
                print(f"{Colors.YELLOW}[!] Full sync requested - this may take a while...{Colors.RESET}")
        else:
            start_date = datetime.utcnow() - timedelta(days=days_back)

        end_date = datetime.utcnow()

        # Calculate total CVEs to fetch (estimate)
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
            'resultsPerPage': '1',
        }

        response = self._make_nvd_request(params, verbose)
        if not response:
            if verbose:
                print(f"{Colors.RED}[X] Failed to connect to NVD API{Colors.RESET}")
            return stats

        total_results = response.get('totalResults', 0)

        if verbose:
            print(f"{Colors.CYAN}[*] Found {total_results:,} CVEs to process{Colors.RESET}")

        if total_results == 0:
            stats['completed'] = True
            return stats

        # Process in batches
        start_index = 0
        batch_num = 0
        total_batches = (total_results + self.RESULTS_PER_PAGE - 1) // self.RESULTS_PER_PAGE

        with self._lock:
            conn = self._get_connection()

            while start_index < total_results:
                batch_num += 1

                if verbose:
                    pct = int((start_index / total_results) * 100)
                    print(f"{Colors.CYAN}[*] Batch {batch_num}/{total_batches} ({pct}%) - {start_index:,}/{total_results:,}{Colors.RESET}")

                if progress_callback:
                    progress_callback(f"Downloading batch {batch_num}/{total_batches}", start_index, total_results)

                params = {
                    'pubStartDate': start_date.strftime('%Y-%m-%dT00:00:00.000'),
                    'pubEndDate': end_date.strftime('%Y-%m-%dT23:59:59.999'),
                    'resultsPerPage': str(self.RESULTS_PER_PAGE),
                    'startIndex': str(start_index),
                }

                response = self._make_nvd_request(params, verbose=False)

                if not response:
                    stats['errors'] += 1
                    if verbose:
                        print(f"{Colors.YELLOW}[!] Batch {batch_num} failed, retrying...{Colors.RESET}")
                    time.sleep(6)  # NVD rate limit
                    continue

                vulnerabilities = response.get('vulnerabilities', [])

                for vuln in vulnerabilities:
                    try:
                        cve_data = self._parse_cve_data(vuln)
                        self._insert_cve(conn, cve_data)
                        stats['cves_processed'] += 1
                        stats['cves_added'] += 1
                    except Exception as e:
                        stats['errors'] += 1
                        if verbose:
                            print(f"{Colors.RED}[X] Error processing CVE: {e}{Colors.RESET}")

                conn.commit()
                start_index += self.RESULTS_PER_PAGE

                # Rate limiting - NVD allows 5 requests per 30 seconds without API key
                config = get_config()
                if not config.get('nvd', 'api_key', fallback=''):
                    time.sleep(6)
                else:
                    time.sleep(0.6)  # With API key: 50 requests per 30 seconds

            # Update metadata
            conn.execute("""
                INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_sync', ?)
            """, (datetime.now().isoformat(),))
            conn.execute("""
                INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', ?)
            """, (end_date.isoformat(),))
            conn.commit()

        stats['completed'] = True
        stats['finished'] = datetime.now().isoformat()

        if verbose:
            print(f"{Colors.GREEN}[+] Sync complete: {stats['cves_processed']:,} CVEs processed{Colors.RESET}")

        return stats

    def sync_recent(self, days: int = 7, verbose: bool = True) -> Dict[str, Any]:
        """Quick sync of recent CVEs only."""
        return self.sync_database(days_back=days, full_sync=False, verbose=verbose)

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def search_cves(
        self,
        keyword: str = None,
        cpe_pattern: str = None,
        severity: str = None,
        min_score: float = None,
        max_results: int = 100,
        days_back: int = None
    ) -> List[Dict]:
        """Search CVEs in local database.

        Args:
            keyword: Search in CVE ID or description.
            cpe_pattern: CPE pattern to match (uses LIKE).
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL).
            min_score: Minimum CVSS v3 score.
            max_results: Maximum results to return.
            days_back: Only return CVEs from last N days.

        Returns:
            List of matching CVE dictionaries.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = "SELECT DISTINCT c.* FROM cves c"
            conditions = []
            params = []

            if cpe_pattern:
                query += " LEFT JOIN cve_cpes cp ON c.cve_id = cp.cve_id"
                conditions.append("cp.cpe_criteria LIKE ?")
                params.append(f"%{cpe_pattern}%")

            if keyword:
                conditions.append("(c.cve_id LIKE ? OR c.description LIKE ?)")
                params.extend([f"%{keyword}%", f"%{keyword}%"])

            if severity:
                conditions.append("c.cvss_v3_severity = ?")
                params.append(severity.upper())

            if min_score is not None:
                conditions.append("c.cvss_v3_score >= ?")
                params.append(min_score)

            if days_back:
                cutoff = (datetime.utcnow() - timedelta(days=days_back)).strftime('%Y-%m-%d')
                conditions.append("c.published >= ?")
                params.append(cutoff)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY c.cvss_v3_score DESC NULLS LAST, c.published DESC"
            query += f" LIMIT {max_results}"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [self._row_to_dict(row) for row in rows]

    def get_cve(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information about a specific CVE.

        Args:
            cve_id: The CVE ID (e.g., CVE-2024-1234).

        Returns:
            CVE details dictionary or None if not found.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Get main CVE data
            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()

            if not row:
                return None

            cve = self._row_to_dict(row)

            # Get CPEs
            cursor.execute("SELECT * FROM cve_cpes WHERE cve_id = ?", (cve_id,))
            cve['cpes'] = [dict(r) for r in cursor.fetchall()]

            # Get references
            cursor.execute("SELECT url, source FROM cve_references WHERE cve_id = ?", (cve_id,))
            cve['references'] = [dict(r) for r in cursor.fetchall()]

            # Get weaknesses
            cursor.execute("SELECT cwe_id FROM cve_weaknesses WHERE cve_id = ?", (cve_id,))
            cve['weaknesses'] = [r['cwe_id'] for r in cursor.fetchall()]

            return cve

    def get_system_cves(
        self,
        severity_filter: str = None,
        max_results: int = 100
    ) -> List[Dict]:
        """Get CVEs relevant to the detected system.

        Args:
            severity_filter: Filter by severity.
            max_results: Maximum results.

        Returns:
            List of relevant CVEs.
        """
        cpe_prefix = self.system_info.get('cpe_prefix', '')
        if not cpe_prefix:
            return []

        # Build CPE pattern for this system
        cpe_pattern = cpe_prefix
        if self.system_info.get('os_version'):
            version = self.system_info['os_version'].split('.')[0]
            cpe_pattern = f"{cpe_prefix}:{version}"

        return self.search_cves(
            cpe_pattern=cpe_pattern,
            severity=severity_filter,
            max_results=max_results
        )

    def get_software_cves(
        self,
        software: str,
        vendor: str = None,
        version: str = None,
        max_results: int = 100
    ) -> List[Dict]:
        """Search CVEs for specific software.

        Args:
            software: Software/product name.
            vendor: Vendor name (optional).
            version: Software version (optional).
            max_results: Maximum results.

        Returns:
            List of CVEs.
        """
        # Try CPE-based search first
        cpe_pattern = software.lower().replace(' ', '_')
        if vendor:
            cpe_pattern = f"{vendor.lower()}:{cpe_pattern}"
        if version:
            cpe_pattern = f"{cpe_pattern}:{version}"

        results = self.search_cves(cpe_pattern=cpe_pattern, max_results=max_results)

        # Also search by keyword if CPE search returns few results
        if len(results) < 10:
            keyword = software
            if vendor:
                keyword = f"{vendor} {software}"
            keyword_results = self.search_cves(keyword=keyword, max_results=max_results)

            # Merge results, avoiding duplicates
            seen = {r['cve_id'] for r in results}
            for r in keyword_results:
                if r['cve_id'] not in seen:
                    results.append(r)
                    seen.add(r['cve_id'])

        return results[:max_results]

    def get_cves_by_severity(self, severity: str, max_results: int = 100) -> List[Dict]:
        """Get CVEs by severity level."""
        return self.search_cves(severity=severity, max_results=max_results)

    def get_recent_cves(self, days: int = 30, max_results: int = 100) -> List[Dict]:
        """Get recently published CVEs."""
        return self.search_cves(days_back=days, max_results=max_results)

    def _row_to_dict(self, row: sqlite3.Row) -> Dict:
        """Convert database row to dictionary."""
        return {
            'cve_id': row['cve_id'],
            'id': row['cve_id'],  # Alias for compatibility
            'description': row['description'],
            'published': row['published'],
            'modified': row['modified'],
            'cvss_score': row['cvss_v3_score'] or row['cvss_v2_score'] or 0,
            'cvss_v3_score': row['cvss_v3_score'],
            'cvss_v3_severity': row['cvss_v3_severity'],
            'cvss_v3_vector': row['cvss_v3_vector'],
            'cvss_v2_score': row['cvss_v2_score'],
            'cvss_v2_severity': row['cvss_v2_severity'],
            'cvss_v2_vector': row['cvss_v2_vector'],
            'severity': row['cvss_v3_severity'] or row['cvss_v2_severity'] or 'UNKNOWN',
        }

    # =========================================================================
    # ONLINE FALLBACK
    # =========================================================================

    def fetch_cve_online(self, cve_id: str, verbose: bool = False) -> Optional[Dict]:
        """Fetch a specific CVE from NVD API (online fallback).

        Args:
            cve_id: The CVE ID.
            verbose: Show progress.

        Returns:
            CVE details or None.
        """
        params = {'cveId': cve_id}

        if verbose:
            print(f"{Colors.CYAN}[*] Fetching {cve_id} from NVD...{Colors.RESET}")

        response = self._make_nvd_request(params, verbose)

        if not response or not response.get('vulnerabilities'):
            return None

        cve_data = self._parse_cve_data(response['vulnerabilities'][0])

        # Store in database
        with self._lock:
            conn = self._get_connection()
            self._insert_cve(conn, cve_data)
            conn.commit()

        return self.get_cve(cve_id)

    def search_online(
        self,
        keyword: str = None,
        cpe_name: str = None,
        severity: str = None,
        days_back: int = 120,
        max_results: int = 100,
        verbose: bool = False
    ) -> List[Dict]:
        """Search NVD API directly (online mode).

        Use this when local database is empty or for real-time results.
        """
        params = {
            'resultsPerPage': str(min(max_results, 2000)),
        }

        if keyword:
            params['keywordSearch'] = keyword

        if cpe_name:
            params['cpeName'] = cpe_name

        if severity:
            params['cvssV3Severity'] = severity.upper()

        if days_back > 0:
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days_back)
            params['pubStartDate'] = start_date.strftime('%Y-%m-%dT00:00:00.000')
            params['pubEndDate'] = end_date.strftime('%Y-%m-%dT23:59:59.999')

        if verbose:
            print(f"{Colors.CYAN}[*] Searching NVD online...{Colors.RESET}")

        response = self._make_nvd_request(params, verbose)

        if not response:
            return []

        cves = []
        for vuln in response.get('vulnerabilities', []):
            cve_data = self._parse_cve_data(vuln)
            cves.append({
                'cve_id': cve_data['cve_id'],
                'id': cve_data['cve_id'],
                'description': cve_data['description'][:200] + '...' if len(cve_data['description']) > 200 else cve_data['description'],
                'cvss_score': cve_data['cvss_v3_score'] or cve_data['cvss_v2_score'] or 0,
                'severity': cve_data['cvss_v3_severity'] or cve_data['cvss_v2_severity'] or 'UNKNOWN',
                'published': cve_data['published'][:10] if cve_data['published'] else '',
            })

        return cves

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# Global instance
_cve_db: Optional[CVEDatabase] = None


def get_cve_db() -> CVEDatabase:
    """Get the global CVE database instance."""
    global _cve_db
    if _cve_db is None:
        _cve_db = CVEDatabase()
    return _cve_db
