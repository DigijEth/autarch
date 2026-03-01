"""
AUTARCH Yandex OSINT Module
Gather information about Yandex users from their login, email, or public links
"""

import json
import os
import sys
import webbrowser
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.banner import Colors

# Module metadata
NAME = "Yandex OSINT"
DESCRIPTION = "Gather intel from Yandex user accounts"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"

# Try to import requests
try:
    import requests
except ImportError:
    requests = None


class YandexParser:
    """Parser for Yandex user information."""

    def __init__(self):
        self.session = None
        self.timeout = 10
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
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

    def lookup_by_login(self, login: str) -> dict:
        """Lookup Yandex user by login/email.

        Args:
            login: Yandex login or email.

        Returns:
            Dict with user information.
        """
        # Strip domain from email
        login = login.split('@')[0].strip()

        if not login:
            return {'error': 'Invalid login'}

        result = {
            'login': login,
            'email': f"{login}@yandex.ru",
            'display_name': None,
            'public_id': None,
            'avatar_url': None,
            'profiles': {},
        }

        print(f"{Colors.CYAN}[*] Looking up Yandex user: {login}{Colors.RESET}")

        # Query Yandex Collections API
        try:
            url = f"https://yandex.ru/collections/api/users/{login}/"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()

                if data.get('title') == "404 Not Found":
                    result['error'] = 'User not found'
                    return result

                result['display_name'] = data.get('display_name')
                result['public_id'] = data.get('public_id')

                avatar_id = data.get('default_avatar_id')
                if avatar_id:
                    result['avatar_url'] = f"https://avatars.mds.yandex.net/get-yapic/{avatar_id}/islands-300"

                # Build profile URLs
                pub_id = result['public_id']
                if pub_id:
                    result['profiles'] = {
                        'reviews': f"https://reviews.yandex.ru/user/{pub_id}",
                        'market': f"https://market.yandex.ru/user/{pub_id}/reviews",
                        'dzen': f"https://zen.yandex.ru/user/{pub_id}",
                        'qa': f"https://yandex.ru/q/profile/{pub_id}/",
                    }

                result['profiles']['music'] = f"https://music.yandex.ru/users/{login}/tracks"
                result['profiles']['disk'] = f"https://disk.yandex.ru/client/disk"

                print(f"{Colors.GREEN}[+] User found!{Colors.RESET}")

            elif response.status_code == 404:
                result['error'] = 'User not found'
            else:
                result['error'] = f'API error: {response.status_code}'

        except requests.exceptions.RequestException as e:
            result['error'] = f'Network error: {str(e)}'
        except json.JSONDecodeError:
            result['error'] = 'Invalid API response'
        except Exception as e:
            result['error'] = f'Error: {str(e)}'

        return result

    def lookup_by_disk_link(self, url: str) -> dict:
        """Extract user info from Yandex.Disk public link.

        Args:
            url: Public Yandex.Disk link.

        Returns:
            Dict with user information.
        """
        print(f"{Colors.CYAN}[*] Extracting user from Yandex.Disk link...{Colors.RESET}")

        try:
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code != 200:
                return {'error': 'Failed to fetch disk link'}

            # Extract displayName from page
            try:
                login = response.text.split('displayName":"')[1].split('"')[0]
            except (IndexError, AttributeError):
                return {'error': 'Could not extract user from link'}

            if not login:
                return {'error': 'No user found in link'}

            print(f"{Colors.GREEN}[+] Extracted login: {login}{Colors.RESET}")

            return self.lookup_by_login(login)

        except Exception as e:
            return {'error': f'Error: {str(e)}'}

    def lookup_by_public_id(self, public_id: str) -> dict:
        """Lookup user by Yandex public ID.

        Args:
            public_id: 26-character Yandex user identifier.

        Returns:
            Dict with user information.
        """
        if len(public_id) != 26:
            return {'error': 'Invalid public ID (must be 26 characters)'}

        result = {
            'public_id': public_id,
            'profiles': {
                'reviews': f"https://reviews.yandex.ru/user/{public_id}",
                'market': f"https://market.yandex.ru/user/{public_id}/reviews",
                'dzen': f"https://zen.yandex.ru/user/{public_id}",
                'qa': f"https://yandex.ru/q/profile/{public_id}/",
            }
        }

        print(f"{Colors.CYAN}[*] Looking up public ID: {public_id}{Colors.RESET}")

        # Try to get more info from collections API
        try:
            url = f"https://yandex.ru/collections/api/users/{public_id}/"
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get('title') != "404 Not Found":
                    result['display_name'] = data.get('display_name')
                    avatar_id = data.get('default_avatar_id')
                    if avatar_id:
                        result['avatar_url'] = f"https://avatars.mds.yandex.net/get-yapic/{avatar_id}/islands-300"

        except Exception:
            pass

        print(f"{Colors.GREEN}[+] Profile URLs generated!{Colors.RESET}")
        return result


def display_result(result: dict, open_browser: bool = False):
    """Display lookup result nicely.

    Args:
        result: Lookup result dict.
        open_browser: Whether to open URLs in browser.
    """
    if 'error' in result:
        print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}{'=' * 55}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}  YANDEX USER PROFILE{Colors.RESET}")
    print(f"{Colors.CYAN}{'=' * 55}{Colors.RESET}")

    if result.get('display_name'):
        print(f"  {Colors.GREEN}Name:{Colors.RESET} {result['display_name']}")
    if result.get('login'):
        print(f"  {Colors.GREEN}Login:{Colors.RESET} {result['login']}")
    if result.get('email'):
        print(f"  {Colors.GREEN}Email:{Colors.RESET} {result['email']}")
    if result.get('public_id'):
        print(f"  {Colors.GREEN}Public ID:{Colors.RESET} {result['public_id']}")

    if result.get('avatar_url'):
        print(f"\n  {Colors.GREEN}Avatar:{Colors.RESET}")
        print(f"  {Colors.DIM}{result['avatar_url']}{Colors.RESET}")

    profiles = result.get('profiles', {})
    if profiles:
        print(f"\n  {Colors.GREEN}Yandex Services:{Colors.RESET}")
        for name, url in profiles.items():
            print(f"    {Colors.CYAN}{name.title()}:{Colors.RESET} {url}")
            if open_browser:
                try:
                    webbrowser.open(url)
                except Exception:
                    pass

    print()


def display_menu():
    """Display the Yandex OSINT module menu."""
    print(f"""
{Colors.CYAN}  Yandex OSINT{Colors.RESET}
{Colors.DIM}  Gather intelligence from Yandex user accounts{Colors.RESET}
{Colors.DIM}{'─' * 55}{Colors.RESET}

  {Colors.GREEN}[1]{Colors.RESET} Lookup by Login/Email
  {Colors.GREEN}[2]{Colors.RESET} Lookup by Yandex.Disk Public Link
  {Colors.GREEN}[3]{Colors.RESET} Lookup by Public ID (26-char hash)

  {Colors.RED}[0]{Colors.RESET} Back to OSINT Menu
""")


def run():
    """Main entry point for the module."""
    if requests is None:
        print(f"{Colors.RED}[X] This module requires 'requests' library{Colors.RESET}")
        print(f"{Colors.DIM}    Install with: pip install requests{Colors.RESET}")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        return

    parser = YandexParser()

    while True:
        display_menu()
        choice = input(f"{Colors.GREEN}Select option: {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            print(f"\n{Colors.CYAN}Enter Yandex login or email:{Colors.RESET}")
            print(f"{Colors.DIM}Example: username or username@yandex.ru{Colors.RESET}")
            login = input(f"\n{Colors.GREEN}Login: {Colors.RESET}").strip()

            if not login:
                continue

            result = parser.lookup_by_login(login)

            open_links = input(f"\n{Colors.YELLOW}Open profile links in browser? (y/n): {Colors.RESET}").strip().lower()
            display_result(result, open_browser=(open_links == 'y'))

            input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '2':
            print(f"\n{Colors.CYAN}Enter Yandex.Disk public link:{Colors.RESET}")
            print(f"{Colors.DIM}Example: https://yadi.sk/d/xxxxx{Colors.RESET}")
            url = input(f"\n{Colors.GREEN}URL: {Colors.RESET}").strip()

            if not url:
                continue

            result = parser.lookup_by_disk_link(url)

            open_links = input(f"\n{Colors.YELLOW}Open profile links in browser? (y/n): {Colors.RESET}").strip().lower()
            display_result(result, open_browser=(open_links == 'y'))

            input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        elif choice == '3':
            print(f"\n{Colors.CYAN}Enter Yandex public ID (26 characters):{Colors.RESET}")
            print(f"{Colors.DIM}Example: tr6r2c8ea4tvdt3xmpy5atuwg0{Colors.RESET}")
            pub_id = input(f"\n{Colors.GREEN}Public ID: {Colors.RESET}").strip()

            if not pub_id:
                continue

            result = parser.lookup_by_public_id(pub_id)

            open_links = input(f"\n{Colors.YELLOW}Open profile links in browser? (y/n): {Colors.RESET}").strip().lower()
            display_result(result, open_browser=(open_links == 'y'))

            input(f"{Colors.DIM}Press Enter to continue...{Colors.RESET}")

        else:
            print(f"{Colors.RED}[!] Invalid option{Colors.RESET}")


if __name__ == "__main__":
    run()
