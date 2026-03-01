"""
AUTARCH Network Test Module
Test network speed and connectivity
"""

import sys
import time
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.banner import Colors

# Module metadata
NAME = "Network Test"
DESCRIPTION = "Test network speed and connectivity"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "utility"

# Try to import optional dependencies
try:
    import speedtest
    HAS_SPEEDTEST = True
except ImportError:
    HAS_SPEEDTEST = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class NetworkTester:
    """Network testing utility."""

    def __init__(self):
        self.test_urls = [
            ("Google", "https://www.google.com"),
            ("Cloudflare", "https://1.1.1.1"),
            ("GitHub", "https://github.com"),
            ("Amazon", "https://aws.amazon.com"),
        ]

    def test_connectivity(self) -> dict:
        """Test basic internet connectivity.

        Returns:
            Dict with connectivity results.
        """
        if not HAS_REQUESTS:
            return {'error': 'requests library not available'}

        print(f"{Colors.CYAN}[*] Testing connectivity...{Colors.RESET}")

        results = {
            'tests': [],
            'success_count': 0,
            'fail_count': 0,
        }

        for name, url in self.test_urls:
            try:
                start = time.time()
                response = requests.get(url, timeout=10)
                elapsed = round((time.time() - start) * 1000)

                success = response.status_code == 200
                results['tests'].append({
                    'name': name,
                    'url': url,
                    'success': success,
                    'status': response.status_code,
                    'time_ms': elapsed,
                })

                if success:
                    results['success_count'] += 1
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {name}: {elapsed}ms")
                else:
                    results['fail_count'] += 1
                    print(f"  {Colors.RED}[-]{Colors.RESET} {name}: HTTP {response.status_code}")

            except requests.exceptions.Timeout:
                results['fail_count'] += 1
                results['tests'].append({
                    'name': name,
                    'url': url,
                    'success': False,
                    'error': 'Timeout',
                })
                print(f"  {Colors.RED}[-]{Colors.RESET} {name}: Timeout")

            except requests.exceptions.ConnectionError:
                results['fail_count'] += 1
                results['tests'].append({
                    'name': name,
                    'url': url,
                    'success': False,
                    'error': 'Connection failed',
                })
                print(f"  {Colors.RED}[-]{Colors.RESET} {name}: Connection failed")

            except Exception as e:
                results['fail_count'] += 1
                results['tests'].append({
                    'name': name,
                    'url': url,
                    'success': False,
                    'error': str(e),
                })
                print(f"  {Colors.RED}[-]{Colors.RESET} {name}: {str(e)}")

        return results

    def test_speed(self) -> dict:
        """Test network speed using speedtest.

        Returns:
            Dict with speed test results.
        """
        if not HAS_SPEEDTEST:
            return {'error': 'speedtest-cli library not available'}

        print(f"{Colors.CYAN}[*] Running speed test (this may take a minute)...{Colors.RESET}")

        try:
            st = speedtest.Speedtest(secure=True)

            print(f"  {Colors.DIM}Finding best server...{Colors.RESET}")
            st.get_best_server()

            print(f"  {Colors.DIM}Testing download speed...{Colors.RESET}")
            st.download(threads=None)

            print(f"  {Colors.DIM}Testing upload speed...{Colors.RESET}")
            st.upload(threads=None)

            results = st.results.dict()

            return {
                'download_mbps': round(results['download'] / 1_000_000, 2),
                'upload_mbps': round(results['upload'] / 1_000_000, 2),
                'ping_ms': round(results['ping']),
                'client': {
                    'ip': results.get('client', {}).get('ip'),
                    'isp': results.get('client', {}).get('isp'),
                    'country': results.get('client', {}).get('country'),
                },
                'server': {
                    'name': results.get('server', {}).get('name'),
                    'country': results.get('server', {}).get('country'),
                    'sponsor': results.get('server', {}).get('sponsor'),
                },
            }

        except Exception as e:
            return {'error': f'Speed test failed: {str(e)}'}

    def test_dns(self, domain: str = "google.com") -> dict:
        """Test DNS resolution.

        Args:
            domain: Domain to resolve.

        Returns:
            Dict with DNS test results.
        """
        import socket

        print(f"{Colors.CYAN}[*] Testing DNS resolution...{Colors.RESET}")

        results = {
            'domain': domain,
            'resolved': False,
            'addresses': [],
        }

        try:
            start = time.time()
            addrs = socket.getaddrinfo(domain, 80)
            elapsed = round((time.time() - start) * 1000)

            results['resolved'] = True
            results['time_ms'] = elapsed
            results['addresses'] = list(set(addr[4][0] for addr in addrs))

            print(f"  {Colors.GREEN}[+]{Colors.RESET} Resolved {domain} in {elapsed}ms")
            for addr in results['addresses'][:3]:
                print(f"      {Colors.DIM}{addr}{Colors.RESET}")

        except socket.gaierror as e:
            results['error'] = f"DNS resolution failed: {e}"
            print(f"  {Colors.RED}[-]{Colors.RESET} DNS resolution failed")

        except Exception as e:
            results['error'] = str(e)
            print(f"  {Colors.RED}[-]{Colors.RESET} Error: {e}")

        return results


def color_speed(value: float, thresholds: tuple) -> str:
    """Color code speed values.

    Args:
        value: Speed value.
        thresholds: (low, medium) thresholds.

    Returns:
        Colored string.
    """
    low, medium = thresholds
    if value < low:
        return f"{Colors.RED}{value}{Colors.RESET}"
    elif value < medium:
        return f"{Colors.YELLOW}{value}{Colors.RESET}"
    else:
        return f"{Colors.GREEN}{value}{Colors.RESET}"


def display_speed_result(result: dict):
    """Display speed test results nicely."""
    if 'error' in result:
        print(f"\n{Colors.RED}[X] {result['error']}{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}  NETWORK SPEED TEST RESULTS{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")

    # Download speed (low < 5 Mbps, medium < 25 Mbps)
    download = result['download_mbps']
    download_colored = color_speed(download, (5, 25))
    print(f"  {Colors.GREEN}Download:{Colors.RESET} {download_colored} Mbps")

    # Upload speed (low < 2 Mbps, medium < 10 Mbps)
    upload = result['upload_mbps']
    upload_colored = color_speed(upload, (2, 10))
    print(f"  {Colors.GREEN}Upload:{Colors.RESET}   {upload_colored} Mbps")

    # Ping (low > 100ms, medium > 50ms, inverted)
    ping = result['ping_ms']
    if ping > 100:
        ping_colored = f"{Colors.RED}{ping}{Colors.RESET}"
    elif ping > 50:
        ping_colored = f"{Colors.YELLOW}{ping}{Colors.RESET}"
    else:
        ping_colored = f"{Colors.GREEN}{ping}{Colors.RESET}"
    print(f"  {Colors.GREEN}Ping:{Colors.RESET}     {ping_colored} ms")

    # Client info
    client = result.get('client', {})
    if client:
        print(f"\n  {Colors.CYAN}Your Connection:{Colors.RESET}")
        if client.get('ip'):
            print(f"    IP: {client['ip']}")
        if client.get('isp'):
            print(f"    ISP: {client['isp']}")
        if client.get('country'):
            print(f"    Country: {client['country']}")

    # Server info
    server = result.get('server', {})
    if server:
        print(f"\n  {Colors.CYAN}Test Server:{Colors.RESET}")
        if server.get('sponsor'):
            print(f"    {server['sponsor']}")
        if server.get('name'):
            print(f"    {server['name']}, {server.get('country', '')}")

    print()


def display_menu():
    """Display the network test module menu."""
    speedtest_status = f"{Colors.GREEN}Available{Colors.RESET}" if HAS_SPEEDTEST else f"{Colors.RED}Not installed{Colors.RESET}"

    print(f"""
{Colors.CYAN}  Network Test{Colors.RESET}
{Colors.DIM}  Test network speed and connectivity{Colors.RESET}
{Colors.DIM}{'─' * 50}{Colors.RESET}

  {Colors.GREEN}[1]{Colors.RESET} Test Connectivity (ping websites)
  {Colors.GREEN}[2]{Colors.RESET} Full Speed Test [{speedtest_status}]
  {Colors.GREEN}[3]{Colors.RESET} Test DNS Resolution
  {Colors.GREEN}[4]{Colors.RESET} Run All Tests

  {Colors.RED}[0]{Colors.RESET} Back
""")


def run():
    """Main entry point for the module."""
    if not HAS_REQUESTS:
        print(f"{Colors.RED}[X] This module requires 'requests' library{Colors.RESET}")
        print(f"{Colors.DIM}    Install with: pip install requests{Colors.RESET}")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        return

    tester = NetworkTester()

    while True:
        display_menu()
        choice = input(f"{Colors.GREEN}Select option: {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            results = tester.test_connectivity()
            if 'error' not in results:
                total = results['success_count'] + results['fail_count']
                print(f"\n{Colors.GREEN}[+] Connectivity: {results['success_count']}/{total} tests passed{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '2':
            if not HAS_SPEEDTEST:
                print(f"\n{Colors.RED}[X] speedtest-cli library not installed{Colors.RESET}")
                print(f"{Colors.DIM}    Install with: pip install speedtest-cli{Colors.RESET}")
            else:
                results = tester.test_speed()
                display_speed_result(results)
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '3':
            print(f"\n{Colors.CYAN}Enter domain to resolve (default: google.com):{Colors.RESET}")
            domain = input(f"{Colors.GREEN}Domain: {Colors.RESET}").strip() or "google.com"
            tester.test_dns(domain)
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '4':
            print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
            print(f"{Colors.GREEN}{Colors.BOLD}  RUNNING ALL NETWORK TESTS{Colors.RESET}")
            print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

            # Connectivity
            print(f"{Colors.BOLD}1. Connectivity Test{Colors.RESET}")
            conn_results = tester.test_connectivity()

            # DNS
            print(f"\n{Colors.BOLD}2. DNS Resolution{Colors.RESET}")
            tester.test_dns()

            # Speed test
            if HAS_SPEEDTEST:
                print(f"\n{Colors.BOLD}3. Speed Test{Colors.RESET}")
                speed_results = tester.test_speed()
                display_speed_result(speed_results)
            else:
                print(f"\n{Colors.BOLD}3. Speed Test{Colors.RESET}")
                print(f"  {Colors.RED}[-]{Colors.RESET} Skipped (speedtest-cli not installed)")

            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        else:
            print(f"{Colors.RED}[!] Invalid option{Colors.RESET}")


if __name__ == "__main__":
    run()
