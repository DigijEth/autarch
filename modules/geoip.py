"""
AUTARCH GEO IP/Domain Lookup Module
Get geolocation info for IPs, domains, and URLs
Based on Snoop Project's GEO_IP/domain plugin
"""

import ipaddress
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.banner import Colors

# Module metadata
NAME = "GEO IP Lookup"
DESCRIPTION = "Get geolocation for IPs, domains, and URLs"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"

# Try to import requests
try:
    import requests
except ImportError:
    requests = None


class GeoIPLookup:
    """GEO IP/Domain lookup utility."""

    def __init__(self):
        self.session = None
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        self._init_session()

    def _init_session(self):
        """Initialize requests session."""
        if requests is None:
            return

        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=2)
        self.session.mount('https://', adapter)
        self.session.mount('http://', adapter)
        self.session.headers.update({'User-Agent': self.user_agent})

    def _resolve_domain(self, target: str, timeout: int = 4) -> dict:
        """Resolve domain to IP addresses.

        Args:
            target: Domain name or IP address.
            timeout: Socket timeout in seconds.

        Returns:
            Dict with resolved IPs and domain info.
        """
        result = {
            'domain': None,
            'ipv4': None,
            'ipv6': None,
        }

        def get_fqdn():
            try:
                result['domain'] = socket.getfqdn(target)
            except Exception:
                result['domain'] = target

        def get_ips():
            try:
                addr_info = socket.getaddrinfo(target, 443)
                for info in addr_info:
                    ip = info[4][0]
                    try:
                        if ipaddress.IPv4Address(ip):
                            result['ipv4'] = ip
                    except Exception:
                        pass
                    try:
                        if ipaddress.IPv6Address(ip):
                            result['ipv6'] = ip
                    except Exception:
                        pass
            except Exception:
                pass

        # Run in threads with timeout
        t1 = threading.Thread(target=get_fqdn)
        t2 = threading.Thread(target=get_ips)
        t1.start()
        t2.start()
        t1.join(timeout)
        t2.join(timeout)

        return result

    def _parse_target(self, target: str) -> str:
        """Parse and clean target input.

        Args:
            target: User input (IP, domain, or URL).

        Returns:
            Cleaned target string.
        """
        target = target.strip()

        # Check if it's a URL
        if '://' in target:
            parsed = urlparse(target)
            if parsed.hostname:
                target = parsed.hostname.replace('www.', '')
        elif '/' in target:
            target = target.split('/')[0]

        return target

    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except Exception:
            return False

    def lookup(self, target: str) -> dict:
        """Perform GEO IP lookup.

        Args:
            target: IP address, domain, or URL.

        Returns:
            Dict with geolocation information.
        """
        if self.session is None:
            return {'error': 'requests library not available'}

        target = self._parse_target(target)

        # Validate input
        if not target or len(target) < 4:
            return {'error': 'Invalid target'}

        if '..' in target:
            return {'error': 'Invalid target format'}

        result = {
            'target': target,
            'country_code': None,
            'country': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'isp': None,
            'org': None,
            'ipv4': None,
            'ipv6': None,
            'domain': None,
            'map_osm': None,
            'map_google': None,
        }

        # Resolve domain/IP
        print(f"{Colors.CYAN}[*] Resolving target...{Colors.RESET}")
        resolved = self._resolve_domain(target)
        result['domain'] = resolved.get('domain')
        result['ipv4'] = resolved.get('ipv4')
        result['ipv6'] = resolved.get('ipv6')

        # If target is IP, use it directly
        if self._is_ip(target):
            try:
                if ipaddress.IPv4Address(target):
                    result['ipv4'] = target
            except Exception:
                pass
            try:
                if ipaddress.IPv6Address(target):
                    result['ipv6'] = target
            except Exception:
                pass

        # Determine IP to lookup
        lookup_ip = result['ipv4'] or target

        # Try ipwho.is first
        print(f"{Colors.CYAN}[*] Querying geolocation APIs...{Colors.RESET}")
        geo_data = self._query_ipwhois(lookup_ip)

        if not geo_data or geo_data.get('success') is False:
            # Fallback to ipinfo.io
            geo_data = self._query_ipinfo(lookup_ip)

        if geo_data:
            result['country_code'] = geo_data.get('country_code') or geo_data.get('country')
            result['country'] = geo_data.get('country_name') or geo_data.get('country')
            result['region'] = geo_data.get('region')
            result['city'] = geo_data.get('city')
            result['latitude'] = geo_data.get('latitude') or geo_data.get('lat')
            result['longitude'] = geo_data.get('longitude') or geo_data.get('lon')
            result['isp'] = geo_data.get('isp') or geo_data.get('org')
            result['org'] = geo_data.get('org')

            if not result['ipv4']:
                result['ipv4'] = geo_data.get('ip')

        # Generate map links
        if result['latitude'] and result['longitude']:
            lat, lon = result['latitude'], result['longitude']
            result['map_osm'] = f"https://www.openstreetmap.org/#map=13/{lat}/{lon}"
            result['map_google'] = f"https://www.google.com/maps/@{lat},{lon},12z"

        return result

    def _query_ipwhois(self, ip: str) -> dict:
        """Query ipwho.is API.

        Args:
            ip: IP address to lookup.

        Returns:
            Dict with GEO data or None.
        """
        try:
            url = f"https://ipwho.is/{ip}" if ip else "https://ipwho.is/"
            response = self.session.get(url, timeout=self.timeout)
            data = response.json()

            if data.get('success') is False:
                return None

            return {
                'ip': data.get('ip'),
                'country_code': data.get('country_code'),
                'country_name': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'isp': data.get('connection', {}).get('isp'),
                'org': data.get('connection', {}).get('org'),
            }
        except Exception as e:
            print(f"{Colors.DIM}    ipwho.is error: {e}{Colors.RESET}")
            return None

    def _query_ipinfo(self, ip: str) -> dict:
        """Query ipinfo.io API.

        Args:
            ip: IP address to lookup.

        Returns:
            Dict with GEO data or None.
        """
        try:
            url = f"https://ipinfo.io/{ip}/json" if ip else "https://ipinfo.io/json"
            response = self.session.get(url, timeout=self.timeout)
            data = response.json()

            loc = data.get('loc', ',').split(',')
            lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
            lon = float(loc[1]) if len(loc) > 1 and loc[1] else None

            return {
                'ip': data.get('ip'),
                'country_code': data.get('country'),
                'country_name': data.get('country'),
                'region': data.get('region'),
                'city': data.get('city'),
                'latitude': lat,
                'longitude': lon,
                'isp': data.get('org'),
                'org': data.get('org'),
            }
        except Exception as e:
            print(f"{Colors.DIM}    ipinfo.io error: {e}{Colors.RESET}")
            return None

    def lookup_self(self) -> dict:
        """Lookup your own public IP.

        Returns:
            Dict with geolocation information.
        """
        print(f"{Colors.CYAN}[*] Looking up your public IP...{Colors.RESET}")
        return self.lookup('')

    def bulk_lookup(self, targets: list) -> list:
        """Perform bulk GEO lookups.

        Args:
            targets: List of IPs/domains to lookup.

        Returns:
            List of result dicts.
        """
        results = []
        for i, target in enumerate(targets):
            print(f"\n{Colors.CYAN}[{i+1}/{len(targets)}] Looking up: {target}{Colors.RESET}")
            result = self.lookup(target)
            results.append(result)
            time.sleep(0.5)  # Rate limiting
        return results


def display_result(result: dict):
    """Display lookup result nicely."""
    if 'error' in result:
        print(f"{Colors.RED}[X] Error: {result['error']}{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}Target:{Colors.RESET} {result['target']}")
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")

    if result['ipv4']:
        print(f"  {Colors.GREEN}IPv4:{Colors.RESET} {result['ipv4']}")
    if result['ipv6']:
        print(f"  {Colors.GREEN}IPv6:{Colors.RESET} {result['ipv6']}")
    if result['domain'] and result['domain'] != result['target']:
        print(f"  {Colors.GREEN}Domain:{Colors.RESET} {result['domain']}")

    print()

    if result['country_code']:
        country_str = f"{result['country_code']}"
        if result['country'] and result['country'] != result['country_code']:
            country_str += f" ({result['country']})"
        print(f"  {Colors.GREEN}Country:{Colors.RESET} {country_str}")

    if result['region']:
        print(f"  {Colors.GREEN}Region:{Colors.RESET} {result['region']}")
    if result['city']:
        print(f"  {Colors.GREEN}City:{Colors.RESET} {result['city']}")
    if result['isp']:
        print(f"  {Colors.GREEN}ISP:{Colors.RESET} {result['isp']}")

    if result['latitude'] and result['longitude']:
        print(f"\n  {Colors.GREEN}Coordinates:{Colors.RESET} {result['latitude']}, {result['longitude']}")

    if result['map_osm']:
        print(f"\n  {Colors.DIM}OpenStreetMap: {result['map_osm']}{Colors.RESET}")
    if result['map_google']:
        print(f"  {Colors.DIM}Google Maps: {result['map_google']}{Colors.RESET}")

    print()


def display_menu():
    """Display the GEO IP module menu."""
    print(f"""
{Colors.CYAN}  GEO IP/Domain Lookup{Colors.RESET}
{Colors.DIM}  Get geolocation for IPs, domains, and URLs{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}

  {Colors.GREEN}[1]{Colors.RESET} Lookup IP/Domain/URL
  {Colors.GREEN}[2]{Colors.RESET} Lookup My IP
  {Colors.GREEN}[3]{Colors.RESET} Bulk Lookup from File

  {Colors.RED}[0]{Colors.RESET} Back to OSINT Menu
""")


def run():
    """Main entry point for the module."""
    if requests is None:
        print(f"{Colors.RED}[X] This module requires 'requests' library{Colors.RESET}")
        print(f"{Colors.DIM}    Install with: pip install requests{Colors.RESET}")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        return

    lookup = GeoIPLookup()

    while True:
        display_menu()
        choice = input(f"{Colors.GREEN}Select option: {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            print(f"\n{Colors.CYAN}Enter IP, domain, or URL:{Colors.RESET}")
            print(f"{Colors.DIM}Examples: 8.8.8.8, google.com, https://example.com/path{Colors.RESET}")
            target = input(f"\n{Colors.GREEN}Target: {Colors.RESET}").strip()

            if not target:
                continue

            result = lookup.lookup(target)
            display_result(result)
            input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '2':
            result = lookup.lookup_self()
            display_result(result)
            input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '3':
            print(f"\n{Colors.CYAN}Enter path to file with targets (one per line):{Colors.RESET}")
            filepath = input(f"\n{Colors.GREEN}File path: {Colors.RESET}").strip()

            if not filepath or not os.path.exists(filepath):
                print(f"{Colors.RED}[X] File not found{Colors.RESET}")
                continue

            try:
                with open(filepath, 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]

                if not targets:
                    print(f"{Colors.RED}[X] No targets found in file{Colors.RESET}")
                    continue

                print(f"{Colors.GREEN}[+] Found {len(targets)} targets{Colors.RESET}")
                confirm = input(f"\n{Colors.YELLOW}Proceed with lookup? (y/n): {Colors.RESET}").strip().lower()

                if confirm == 'y':
                    results = lookup.bulk_lookup(targets)
                    for result in results:
                        display_result(result)

            except Exception as e:
                print(f"{Colors.RED}[X] Error reading file: {e}{Colors.RESET}")

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        else:
            print(f"{Colors.RED}[!] Invalid option{Colors.RESET}")


if __name__ == "__main__":
    run()
