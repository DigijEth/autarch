"""
AUTARCH Sites Database Module
Unified username enumeration database from multiple OSINT sources

Database: dh_sites.db - Master database with detection patterns
"""

import os
import json
import sqlite3
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from .banner import Colors
from .config import get_config


class SitesDatabase:
    """Unified OSINT sites database with SQLite storage."""

    # Default database is dh_sites.db (the new categorized database with detection fields)
    DEFAULT_DB = "dh_sites.db"

    # Detection method mapping
    DETECTION_METHODS = {
        'status_code': 'status',
        'message': 'content',
        'response_url': 'redirect',
        'redirection': 'redirect',
    }

    def __init__(self, db_path: str = None):
        """Initialize sites database.

        Args:
            db_path: Path to SQLite database. Defaults to data/sites/dh_sites.db
        """
        if db_path is None:
            from core.paths import get_data_dir
            self.data_dir = get_data_dir() / "sites"
            self.db_path = self.data_dir / self.DEFAULT_DB
        else:
            self.db_path = Path(db_path)
            self.data_dir = self.db_path.parent

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._conn = None
        self._lock = threading.Lock()

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-safe database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {
                'db_path': str(self.db_path),
                'db_size_mb': round(self.db_path.stat().st_size / 1024 / 1024, 2) if self.db_path.exists() else 0,
                'total_sites': 0,
                'enabled_sites': 0,
                'nsfw_sites': 0,
                'with_detection': 0,
                'by_source': {},
                'by_category': {},
                'by_error_type': {},
            }

            try:
                cursor.execute("SELECT COUNT(*) FROM sites")
                stats['total_sites'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1")
                stats['enabled_sites'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sites WHERE nsfw = 1")
                stats['nsfw_sites'] = cursor.fetchone()[0]

                cursor.execute("SELECT COUNT(*) FROM sites WHERE error_type IS NOT NULL")
                stats['with_detection'] = cursor.fetchone()[0]

                cursor.execute("SELECT source, COUNT(*) FROM sites GROUP BY source ORDER BY COUNT(*) DESC")
                stats['by_source'] = {row[0]: row[1] for row in cursor.fetchall()}

                cursor.execute("SELECT category, COUNT(*) FROM sites GROUP BY category ORDER BY COUNT(*) DESC")
                stats['by_category'] = {row[0]: row[1] for row in cursor.fetchall()}

                cursor.execute("SELECT error_type, COUNT(*) FROM sites WHERE error_type IS NOT NULL GROUP BY error_type ORDER BY COUNT(*) DESC")
                stats['by_error_type'] = {row[0]: row[1] for row in cursor.fetchall()}

            except sqlite3.Error:
                pass

            return stats

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def get_sites(
        self,
        category: str = None,
        include_nsfw: bool = False,
        enabled_only: bool = True,
        source: str = None,
        limit: int = None,
        order_by: str = 'name'
    ) -> List[Dict]:
        """Get sites from database.

        Args:
            category: Filter by category.
            include_nsfw: Include NSFW sites.
            enabled_only: Only return enabled sites.
            source: Filter by source.
            limit: Maximum number of results.
            order_by: 'name' or 'category'.

        Returns:
            List of site dictionaries.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = "SELECT * FROM sites WHERE 1=1"
            params = []

            if category:
                query += " AND category = ?"
                params.append(category)

            if not include_nsfw:
                query += " AND nsfw = 0"

            if enabled_only:
                query += " AND enabled = 1"

            if source:
                query += " AND source = ?"
                params.append(source)

            query += f" ORDER BY {order_by} COLLATE NOCASE ASC"

            if limit:
                query += f" LIMIT {limit}"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [dict(row) for row in rows]

    def get_site(self, name: str) -> Optional[Dict]:
        """Get a specific site by name.

        Args:
            name: Site name.

        Returns:
            Site dictionary or None.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM sites WHERE name = ? COLLATE NOCASE", (name,))
            row = cursor.fetchone()

            return dict(row) if row else None

    def search_sites(self, query: str, include_nsfw: bool = False, limit: int = 100) -> List[Dict]:
        """Search sites by name.

        Args:
            query: Search query.
            include_nsfw: Include NSFW sites.
            limit: Maximum results.

        Returns:
            List of matching sites.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            sql = "SELECT * FROM sites WHERE name LIKE ? AND enabled = 1"
            params = [f"%{query}%"]

            if not include_nsfw:
                sql += " AND nsfw = 0"

            sql += f" ORDER BY name COLLATE NOCASE ASC LIMIT {limit}"

            cursor.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_categories(self) -> List[Tuple[str, int]]:
        """Get all categories with site counts.

        Returns:
            List of (category, count) tuples.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT category, COUNT(*) as count
                FROM sites
                WHERE enabled = 1
                GROUP BY category
                ORDER BY count DESC
            """)

            return [(row[0], row[1]) for row in cursor.fetchall()]

    def get_sites_for_scan(
        self,
        categories: List[str] = None,
        include_nsfw: bool = False,
        max_sites: int = 500,
        sort_alphabetically: bool = True
    ) -> List[Dict]:
        """Get sites optimized for username scanning with detection patterns.

        Args:
            categories: List of categories to include.
            include_nsfw: Include NSFW sites.
            max_sites: Maximum number of sites.
            sort_alphabetically: Sort by name (True) or by category (False).

        Returns:
            List of sites ready for scanning with detection info.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            query = """SELECT name, url_template, category, source, nsfw,
                              error_type, error_code, error_string, match_code, match_string
                       FROM sites WHERE enabled = 1"""
            params = []

            if categories:
                placeholders = ','.join('?' * len(categories))
                query += f" AND category IN ({placeholders})"
                params.extend(categories)

            if not include_nsfw:
                query += " AND nsfw = 0"

            # Sort order
            if sort_alphabetically:
                query += " ORDER BY name COLLATE NOCASE ASC"
            else:
                query += " ORDER BY category ASC, name COLLATE NOCASE ASC"

            query += f" LIMIT {max_sites}"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            # Format for scanning with detection info
            sites = []
            for row in rows:
                name, url, category, source, nsfw, error_type, error_code, error_string, match_code, match_string = row

                # Map error_type to detection method
                method = self.DETECTION_METHODS.get(error_type, 'status') if error_type else 'status'

                sites.append({
                    'name': name,
                    'url': url,
                    'category': category,
                    'source': source,
                    'nsfw': bool(nsfw),
                    # Detection fields
                    'method': method,
                    'error_type': error_type,
                    'error_code': error_code,          # HTTP code when NOT found (e.g., 404)
                    'error_string': error_string,      # String when NOT found
                    'match_code': match_code,          # HTTP code when found (e.g., 200)
                    'match_string': match_string,      # String when found
                })

            return sites

    def get_site_by_url(self, url_template: str) -> Optional[Dict]:
        """Get a site by its URL template.

        Args:
            url_template: URL template with {} placeholder.

        Returns:
            Site dictionary or None.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM sites WHERE url_template = ?", (url_template,))
            row = cursor.fetchone()

            return dict(row) if row else None

    def toggle_site(self, name: str, enabled: bool) -> bool:
        """Enable or disable a site.

        Args:
            name: Site name.
            enabled: Enable (True) or disable (False).

        Returns:
            True if successful.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute(
                "UPDATE sites SET enabled = ? WHERE name = ? COLLATE NOCASE",
                (1 if enabled else 0, name)
            )
            conn.commit()

            return cursor.rowcount > 0

    def add_site(
        self,
        name: str,
        url_template: str,
        category: str = 'other',
        source: str = 'custom',
        nsfw: bool = False,
        error_type: str = 'status_code',
        error_code: int = None,
        error_string: str = None,
        match_code: int = None,
        match_string: str = None,
    ) -> bool:
        """Add a custom site to the database.

        Args:
            name: Site name.
            url_template: URL with {} placeholder for username.
            category: Site category.
            source: Source identifier.
            nsfw: Whether site is NSFW.
            error_type: Detection type (status_code, message, etc).
            error_code: HTTP status when user NOT found.
            error_string: String when user NOT found.
            match_code: HTTP status when user found.
            match_string: String when user found.

        Returns:
            True if successful.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            try:
                cursor.execute("""
                    INSERT OR REPLACE INTO sites
                    (name, url_template, category, source, nsfw, enabled,
                     error_type, error_code, error_string, match_code, match_string)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                """, (
                    name,
                    url_template,
                    category,
                    source,
                    1 if nsfw else 0,
                    error_type,
                    error_code,
                    error_string,
                    match_code,
                    match_string,
                ))
                conn.commit()
                return True
            except Exception:
                return False

    def update_detection(
        self,
        name: str,
        error_type: str = None,
        error_code: int = None,
        error_string: str = None,
        match_code: int = None,
        match_string: str = None,
    ) -> bool:
        """Update detection settings for a site.

        Args:
            name: Site name.
            error_type: Detection type.
            error_code: HTTP status when NOT found.
            error_string: String when NOT found.
            match_code: HTTP status when found.
            match_string: String when found.

        Returns:
            True if successful.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            updates = []
            params = []

            if error_type is not None:
                updates.append("error_type = ?")
                params.append(error_type)
            if error_code is not None:
                updates.append("error_code = ?")
                params.append(error_code)
            if error_string is not None:
                updates.append("error_string = ?")
                params.append(error_string)
            if match_code is not None:
                updates.append("match_code = ?")
                params.append(match_code)
            if match_string is not None:
                updates.append("match_string = ?")
                params.append(match_string)

            if not updates:
                return False

            params.append(name)
            query = f"UPDATE sites SET {', '.join(updates)} WHERE name = ? COLLATE NOCASE"

            cursor.execute(query, params)
            conn.commit()

            return cursor.rowcount > 0

    def get_sites_without_detection(self, limit: int = 100) -> List[Dict]:
        """Get sites that don't have detection patterns configured.

        Args:
            limit: Maximum results.

        Returns:
            List of sites without detection info.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM sites
                WHERE enabled = 1
                AND (error_string IS NULL OR error_string = '')
                AND (match_string IS NULL OR match_string = '')
                ORDER BY name COLLATE NOCASE ASC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    def get_detection_coverage(self) -> Dict[str, Any]:
        """Get statistics on detection pattern coverage.

        Returns:
            Dictionary with coverage statistics.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            stats = {}

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1")
            total = cursor.fetchone()[0]
            stats['total_enabled'] = total

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1 AND error_type IS NOT NULL")
            stats['with_error_type'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1 AND error_string IS NOT NULL AND error_string != ''")
            stats['with_error_string'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1 AND match_string IS NOT NULL AND match_string != ''")
            stats['with_match_string'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1 AND error_code IS NOT NULL")
            stats['with_error_code'] = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 1 AND match_code IS NOT NULL")
            stats['with_match_code'] = cursor.fetchone()[0]

            # Calculate percentages
            if total > 0:
                stats['pct_error_type'] = round(stats['with_error_type'] * 100 / total, 1)
                stats['pct_error_string'] = round(stats['with_error_string'] * 100 / total, 1)
                stats['pct_match_string'] = round(stats['with_match_string'] * 100 / total, 1)

            return stats

    def get_disabled_count(self) -> int:
        """Get count of disabled sites."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM sites WHERE enabled = 0")
            return cursor.fetchone()[0]

    def enable_all_sites(self) -> int:
        """Re-enable all disabled sites."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE sites SET enabled = 1 WHERE enabled = 0")
            count = cursor.rowcount
            conn.commit()
            return count

    def disable_category(self, category: str) -> int:
        """Disable all sites in a category.

        Args:
            category: Category to disable.

        Returns:
            Number of sites disabled.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE sites SET enabled = 0 WHERE category = ? AND enabled = 1", (category,))
            count = cursor.rowcount
            conn.commit()
            return count

    def enable_category(self, category: str) -> int:
        """Enable all sites in a category.

        Args:
            category: Category to enable.

        Returns:
            Number of sites enabled.
        """
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE sites SET enabled = 1 WHERE category = ? AND enabled = 0", (category,))
            count = cursor.rowcount
            conn.commit()
            return count

    def load_from_json(self, json_path: str = None) -> Dict[str, int]:
        """Load/reload sites from the master dh.json file.

        Args:
            json_path: Path to JSON file. Defaults to data/sites/dh.json

        Returns:
            Statistics dict with import counts.
        """
        if json_path is None:
            json_path = self.data_dir / "dh.json"
        else:
            json_path = Path(json_path)

        stats = {'total': 0, 'new': 0, 'updated': 0, 'errors': 0}

        if not json_path.exists():
            print(f"{Colors.RED}[X] JSON file not found: {json_path}{Colors.RESET}")
            return stats

        print(f"{Colors.CYAN}[*] Loading sites from {json_path}...{Colors.RESET}")

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)

            sites = data.get('sites', [])
            stats['total'] = len(sites)

            with self._lock:
                conn = self._get_connection()
                cursor = conn.cursor()

                for site in sites:
                    try:
                        cursor.execute("""
                            INSERT OR REPLACE INTO sites
                            (name, url_template, category, source, nsfw, enabled,
                             error_type, error_code, error_string, match_code, match_string)
                            VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
                        """, (
                            site['name'],
                            site['url'],
                            site.get('category', 'other'),
                            site.get('source', 'dh'),
                            1 if site.get('nsfw') else 0,
                            site.get('error_type'),
                            site.get('error_code'),
                            site.get('error_string'),
                            site.get('match_code'),
                            site.get('match_string'),
                        ))
                        stats['new'] += 1
                    except Exception as e:
                        stats['errors'] += 1

                conn.commit()

            print(f"{Colors.GREEN}[+] Loaded {stats['new']} sites from JSON{Colors.RESET}")

        except Exception as e:
            print(f"{Colors.RED}[X] Error loading JSON: {e}{Colors.RESET}")

        return stats

    def export_to_json(self, json_path: str = None) -> bool:
        """Export database to JSON format.

        Args:
            json_path: Output path. Defaults to data/sites/dh_export.json

        Returns:
            True if successful.
        """
        if json_path is None:
            json_path = self.data_dir / "dh_export.json"
        else:
            json_path = Path(json_path)

        try:
            sites = self.get_sites(enabled_only=False, include_nsfw=True)

            # Get category and source stats
            stats = self.get_stats()

            export_data = {
                "project": "darkHal Security Group - AUTARCH",
                "version": "1.1",
                "description": "Exported sites database with detection patterns",
                "total_sites": len(sites),
                "stats": {
                    "by_category": stats['by_category'],
                    "by_source": stats['by_source'],
                    "by_error_type": stats['by_error_type'],
                },
                "sites": []
            }

            for site in sites:
                site_entry = {
                    "name": site['name'],
                    "url": site['url_template'],
                    "category": site['category'],
                    "source": site['source'],
                    "nsfw": bool(site['nsfw']),
                    "enabled": bool(site['enabled']),
                }

                # Add detection fields if present
                if site.get('error_type'):
                    site_entry['error_type'] = site['error_type']
                if site.get('error_code'):
                    site_entry['error_code'] = site['error_code']
                if site.get('error_string'):
                    site_entry['error_string'] = site['error_string']
                if site.get('match_code'):
                    site_entry['match_code'] = site['match_code']
                if site.get('match_string'):
                    site_entry['match_string'] = site['match_string']

                export_data['sites'].append(site_entry)

            with open(json_path, 'w') as f:
                json.dump(export_data, f, indent=2)

            print(f"{Colors.GREEN}[+] Exported {len(sites)} sites to {json_path}{Colors.RESET}")
            return True

        except Exception as e:
            print(f"{Colors.RED}[X] Export error: {e}{Colors.RESET}")
            return False

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# Global instance
_sites_db: Optional[SitesDatabase] = None


def get_sites_db() -> SitesDatabase:
    """Get the global sites database instance."""
    global _sites_db
    if _sites_db is None:
        _sites_db = SitesDatabase()
    return _sites_db
