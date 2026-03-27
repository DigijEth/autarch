"""
AUTARCH Snoop Database Decoder Module
Decrypts and imports Snoop Project databases into AUTARCH
"""

import base64
import json
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.banner import Colors
from core.sites_db import SitesDatabase

# Module metadata
NAME = "Snoop Decoder"
DESCRIPTION = "Decrypt and import Snoop Project databases"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"


class SnoopDecoder:
    """Decoder for Snoop Project encoded databases."""

    def __init__(self):
        self.sites_db = SitesDatabase()
        from core.paths import get_data_dir
        self.data_dir = get_data_dir() / "sites"
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def decode_database(self, filepath: str) -> dict:
        """Decode a Snoop database file.

        Args:
            filepath: Path to the encoded database file (BDdemo, BDfull, etc.)

        Returns:
            Decoded dictionary of sites.
        """
        print(f"{Colors.CYAN}[*] Reading encoded database...{Colors.RESET}")

        with open(filepath, 'r', encoding='utf8') as f:
            db = f.read().strip()

        original_size = len(db)
        print(f"{Colors.DIM}    Original size: {original_size:,} chars{Colors.RESET}")

        # Step 1: Decode base32
        print(f"{Colors.CYAN}[*] Decoding base32...{Colors.RESET}")
        try:
            db_bytes = base64.b32decode(db)
        except Exception as e:
            print(f"{Colors.RED}[X] Base32 decode failed: {e}{Colors.RESET}")
            return None

        print(f"{Colors.DIM}    After base32: {len(db_bytes):,} bytes{Colors.RESET}")

        # Step 2: Reverse bytes
        print(f"{Colors.CYAN}[*] Reversing byte order...{Colors.RESET}")
        db_bytes = db_bytes[::-1]

        # Step 3: Decode UTF-8 with error handling
        print(f"{Colors.CYAN}[*] Decoding UTF-8...{Colors.RESET}")
        content = db_bytes.decode('utf-8', errors='replace')

        # Step 4: Reverse string
        print(f"{Colors.CYAN}[*] Reversing string...{Colors.RESET}")
        content = content[::-1]

        # Step 5: Parse JSON
        print(f"{Colors.CYAN}[*] Parsing JSON...{Colors.RESET}")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"{Colors.RED}[X] JSON parse failed: {e}{Colors.RESET}")
            return None

        print(f"{Colors.GREEN}[+] Successfully decoded {len(data):,} sites!{Colors.RESET}")
        return data

    def save_decoded(self, data: dict, output_name: str = "snoop_decoded.json") -> str:
        """Save decoded database to JSON file.

        Args:
            data: Decoded site dictionary.
            output_name: Output filename.

        Returns:
            Path to saved file.
        """
        output_path = self.data_dir / output_name

        with open(output_path, 'w', encoding='utf8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        size_mb = output_path.stat().st_size / 1024 / 1024
        print(f"{Colors.GREEN}[+] Saved to: {output_path}{Colors.RESET}")
        print(f"{Colors.DIM}    File size: {size_mb:.2f} MB{Colors.RESET}")

        return str(output_path)

    def import_to_database(self, data: dict) -> dict:
        """Import decoded Snoop data into AUTARCH sites database.

        Args:
            data: Decoded site dictionary.

        Returns:
            Import statistics.
        """
        print(f"\n{Colors.CYAN}[*] Importing to AUTARCH database...{Colors.RESET}")

        sites_to_add = []
        skipped = 0

        for name, entry in data.items():
            if not isinstance(entry, dict):
                skipped += 1
                continue

            url = entry.get('url', '')
            if not url or '{}' not in url:
                skipped += 1
                continue

            # Get error type - handle encoding issues in key name
            error_type = None
            for key in entry.keys():
                if 'errorTyp' in key or 'errortype' in key.lower():
                    error_type = entry[key]
                    break

            # Map Snoop error types to detection methods
            detection_method = 'status'
            if error_type:
                if 'message' in str(error_type).lower():
                    detection_method = 'content'
                elif 'redirect' in str(error_type).lower():
                    detection_method = 'redirect'

            # Get error message pattern
            error_pattern = None
            for key in ['errorMsg', 'errorMsg2']:
                if key in entry and entry[key]:
                    error_pattern = str(entry[key])
                    break

            sites_to_add.append({
                'name': name,
                'url_template': url,
                'url_main': entry.get('urlMain'),
                'detection_method': detection_method,
                'error_pattern': error_pattern,
                'category': 'other',
                'nsfw': 0,
            })

        print(f"{Colors.DIM}    Valid sites: {len(sites_to_add):,}{Colors.RESET}")
        print(f"{Colors.DIM}    Skipped: {skipped:,}{Colors.RESET}")

        # Add to database
        stats = self.sites_db.add_sites_bulk(sites_to_add)

        print(f"{Colors.GREEN}[+] Import complete!{Colors.RESET}")
        print(f"{Colors.DIM}    Added: {stats['added']:,}{Colors.RESET}")
        print(f"{Colors.DIM}    Errors: {stats['errors']:,}{Colors.RESET}")

        return stats

    def show_sample(self, data: dict, count: int = 10):
        """Display sample sites from decoded database.

        Args:
            data: Decoded site dictionary.
            count: Number of samples to show.
        """
        print(f"\n{Colors.CYAN}Sample Sites ({count}):{Colors.RESET}")
        print("-" * 60)

        for i, (name, info) in enumerate(list(data.items())[:count]):
            url = info.get('url', 'N/A')
            country = info.get('country', '')
            print(f"  {country} {Colors.GREEN}{name}{Colors.RESET}")
            print(f"     {Colors.DIM}{url[:55]}...{Colors.RESET}" if len(url) > 55 else f"     {Colors.DIM}{url}{Colors.RESET}")

    def get_stats(self, data: dict) -> dict:
        """Get statistics about decoded database.

        Args:
            data: Decoded site dictionary.

        Returns:
            Statistics dictionary.
        """
        stats = {
            'total_sites': len(data),
            'by_country': {},
            'detection_methods': {'status_code': 0, 'message': 0, 'redirection': 0, 'other': 0},
        }

        for name, info in data.items():
            # Country stats
            country = info.get('country_klas', 'Unknown')
            stats['by_country'][country] = stats['by_country'].get(country, 0) + 1

            # Detection method stats
            error_type = None
            for key in info.keys():
                if 'errorTyp' in key:
                    error_type = str(info[key]).lower()
                    break

            if error_type:
                if 'status' in error_type:
                    stats['detection_methods']['status_code'] += 1
                elif 'message' in error_type:
                    stats['detection_methods']['message'] += 1
                elif 'redirect' in error_type:
                    stats['detection_methods']['redirection'] += 1
                else:
                    stats['detection_methods']['other'] += 1
            else:
                stats['detection_methods']['other'] += 1

        return stats


def display_menu():
    """Display the Snoop Decoder menu."""
    print(f"""
{Colors.CYAN}  Snoop Database Decoder{Colors.RESET}
{Colors.DIM}  Decrypt and import Snoop Project databases{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}

  {Colors.GREEN}[1]{Colors.RESET} Decode Snoop Database File
  {Colors.GREEN}[2]{Colors.RESET} Decode & Import to AUTARCH
  {Colors.GREEN}[3]{Colors.RESET} View Current Sites Database Stats

  {Colors.GREEN}[4]{Colors.RESET} Quick Import (BDfull from snoop-master)
  {Colors.GREEN}[5]{Colors.RESET} Quick Import (BDdemo from snoop-master)

  {Colors.RED}[0]{Colors.RESET} Back to OSINT Menu
""")


def get_file_path() -> str:
    """Prompt user for file path."""
    print(f"\n{Colors.CYAN}Enter path to Snoop database file:{Colors.RESET}")
    print(f"{Colors.DIM}(e.g., /path/to/BDfull or /path/to/BDdemo){Colors.RESET}")

    filepath = input(f"\n{Colors.GREEN}Path: {Colors.RESET}").strip()

    if not filepath:
        return None

    if not os.path.exists(filepath):
        print(f"{Colors.RED}[X] File not found: {filepath}{Colors.RESET}")
        return None

    return filepath


def run():
    """Main entry point for the module."""
    decoder = SnoopDecoder()

    # Common paths for Snoop databases
    from core.paths import get_app_dir, get_data_dir
    _app = get_app_dir()
    _data = get_data_dir()
    snoop_paths = {
        'bdfull': _app / "snoop" / "snoop-master" / "BDfull",
        'bddemo': _app / "snoop" / "snoop-master" / "BDdemo",
        'bdfull_alt': _data / "snoop" / "BDfull",
        'bddemo_alt': _data / "snoop" / "BDdemo",
    }

    while True:
        display_menu()

        choice = input(f"{Colors.GREEN}Select option: {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            # Decode only
            filepath = get_file_path()
            if not filepath:
                continue

            data = decoder.decode_database(filepath)
            if data:
                decoder.show_sample(data)

                stats = decoder.get_stats(data)
                print(f"\n{Colors.CYAN}Database Statistics:{Colors.RESET}")
                print(f"  Total sites: {stats['total_sites']:,}")
                print(f"  Detection methods: {stats['detection_methods']}")
                print(f"  Top countries: {dict(sorted(stats['by_country'].items(), key=lambda x: -x[1])[:10])}")

                # Ask to save
                save = input(f"\n{Colors.YELLOW}Save decoded JSON? (y/n): {Colors.RESET}").strip().lower()
                if save == 'y':
                    name = input(f"{Colors.GREEN}Output filename [snoop_decoded.json]: {Colors.RESET}").strip()
                    decoder.save_decoded(data, name if name else "snoop_decoded.json")

        elif choice == '2':
            # Decode and import
            filepath = get_file_path()
            if not filepath:
                continue

            data = decoder.decode_database(filepath)
            if data:
                decoder.show_sample(data, 5)

                confirm = input(f"\n{Colors.YELLOW}Import {len(data):,} sites to AUTARCH? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    # Save first
                    decoder.save_decoded(data, "snoop_imported.json")
                    # Then import
                    decoder.import_to_database(data)

                    # Show final stats
                    db_stats = decoder.sites_db.get_stats()
                    print(f"\n{Colors.GREEN}AUTARCH Database now has {db_stats['total_sites']:,} sites!{Colors.RESET}")

        elif choice == '3':
            # View current stats
            stats = decoder.sites_db.get_stats()
            print(f"\n{Colors.CYAN}AUTARCH Sites Database:{Colors.RESET}")
            print(f"  Total sites: {stats['total_sites']:,}")
            print(f"  NSFW sites: {stats['nsfw_sites']:,}")
            print(f"  Database size: {stats['db_size_mb']:.2f} MB")
            print(f"\n  {Colors.CYAN}By Source:{Colors.RESET}")
            for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
                print(f"    {source}: {count:,}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '4':
            # Quick import BDfull
            bdpath = None
            for key in ['bdfull', 'bdfull_alt']:
                if snoop_paths[key].exists():
                    bdpath = str(snoop_paths[key])
                    break

            if not bdpath:
                print(f"{Colors.RED}[X] BDfull not found in known locations{Colors.RESET}")
                print(f"{Colors.DIM}    Checked: {snoop_paths['bdfull']}{Colors.RESET}")
                print(f"{Colors.DIM}    Checked: {snoop_paths['bdfull_alt']}{Colors.RESET}")
                continue

            print(f"{Colors.GREEN}[+] Found BDfull: {bdpath}{Colors.RESET}")

            data = decoder.decode_database(bdpath)
            if data:
                confirm = input(f"\n{Colors.YELLOW}Import {len(data):,} sites? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    decoder.save_decoded(data, "snoop_full.json")
                    decoder.import_to_database(data)

                    db_stats = decoder.sites_db.get_stats()
                    print(f"\n{Colors.GREEN}AUTARCH Database now has {db_stats['total_sites']:,} sites!{Colors.RESET}")

        elif choice == '5':
            # Quick import BDdemo
            bdpath = None
            for key in ['bddemo', 'bddemo_alt']:
                if snoop_paths[key].exists():
                    bdpath = str(snoop_paths[key])
                    break

            if not bdpath:
                print(f"{Colors.RED}[X] BDdemo not found in known locations{Colors.RESET}")
                continue

            print(f"{Colors.GREEN}[+] Found BDdemo: {bdpath}{Colors.RESET}")

            data = decoder.decode_database(bdpath)
            if data:
                confirm = input(f"\n{Colors.YELLOW}Import {len(data):,} sites? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    decoder.save_decoded(data, "snoop_demo.json")
                    decoder.import_to_database(data)

                    db_stats = decoder.sites_db.get_stats()
                    print(f"\n{Colors.GREEN}AUTARCH Database now has {db_stats['total_sites']:,} sites!{Colors.RESET}")

        else:
            print(f"{Colors.RED}[!] Invalid option{Colors.RESET}")


if __name__ == "__main__":
    run()
