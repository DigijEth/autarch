"""
AUTARCH Adult Site Scanner Module
Username OSINT for adult-oriented platforms

Searches usernames across adult content sites, fanfiction platforms,
and related communities.
"""

import sys
import subprocess
import re
import json
from pathlib import Path
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# Module metadata
DESCRIPTION = "Adult site username OSINT scanner"
AUTHOR = "darkHal"
VERSION = "1.3"
CATEGORY = "osint"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner
from core.config import get_config

# Custom sites storage file
from core.paths import get_app_dir as _app_dir
CUSTOM_SITES_FILE = _app_dir() / "custom_adultsites.json"
# Bulk import file
BULK_IMPORT_FILE = _app_dir() / "custom_sites.inf"

# Common username URL patterns for auto-detection
COMMON_PATTERNS = [
    '/user/{}',
    '/users/{}',
    '/u/{}',
    '/profile/{}',
    '/profiles/{}',
    '/member/{}',
    '/members/{}',
    '/@{}',
    '/{}',
    '/people/{}',
    '/account/{}',
    '/id/{}',
    '/{}/profile',
    '/user/{}/profile',
    '/channel/{}',
    '/c/{}',
    '/p/{}',
]


class AdultScanner:
    """Username scanner for adult-oriented sites."""

    # Default site definitions: (name, url_template, method)
    # method: 'status' = check HTTP status, 'content' = check page content
    DEFAULT_SITES = {
        # Fanfiction & Story Sites
        'fanfiction': [
            ('Archive of Our Own', 'https://archiveofourown.org/users/{}/profile', 'status'),
            ('FanFiction.net', 'https://www.fanfiction.net/u/0/{}', 'content'),
            ('FimFiction', 'https://www.fimfiction.net/user/{}', 'status'),
            ('Wattpad', 'https://www.wattpad.com/user/{}', 'status'),
            ('Literotica', 'https://www.literotica.com/stories/memberpage.php?uid=0&username={}', 'content'),
            ('Adult-FanFiction', 'http://members.adult-fanfiction.org/profile.php?no=0&uname={}', 'content'),
            ('Hentai Foundry', 'https://www.hentai-foundry.com/user/{}/profile', 'status'),
            ('SoFurry', 'https://www.sofurry.com/browse/user/{}', 'status'),
            ('Inkbunny', 'https://inkbunny.net/{}', 'status'),
        ],

        # Art & Creative
        'art': [
            ('DeviantArt', 'https://www.deviantart.com/{}', 'status'),
            ('Fur Affinity', 'https://www.furaffinity.net/user/{}/', 'status'),
            ('Newgrounds', 'https://{}.newgrounds.com', 'status'),
            ('Pixiv', 'https://www.pixiv.net/en/users/{}', 'content'),
            ('Rule34', 'https://rule34.xxx/index.php?page=account&s=profile&uname={}', 'content'),
            ('e621', 'https://e621.net/users?name={}', 'content'),
            ('Derpibooru', 'https://derpibooru.org/profiles/{}', 'status'),
            ('Twitter/X', 'https://twitter.com/{}', 'status'),
            ('Tumblr', 'https://{}.tumblr.com', 'status'),
            ('Pillowfort', 'https://www.pillowfort.social/{}', 'status'),
        ],

        # Video & Streaming
        'video': [
            ('Pornhub', 'https://www.pornhub.com/users/{}', 'status'),
            ('XVideos', 'https://www.xvideos.com/profiles/{}', 'status'),
            ('xHamster', 'https://xhamster.com/users/{}', 'status'),
            ('Chaturbate', 'https://chaturbate.com/{}/', 'status'),
            ('OnlyFans', 'https://onlyfans.com/{}', 'status'),
            ('Fansly', 'https://fansly.com/{}', 'status'),
            ('ManyVids', 'https://www.manyvids.com/Profile/0/{}/', 'content'),
            ('PocketStars', 'https://pocketstars.com/{}', 'status'),
        ],

        # Forums & Communities
        'forums': [
            ('Reddit', 'https://www.reddit.com/user/{}', 'status'),
            ('F-List', 'https://www.f-list.net/c/{}', 'status'),
            ('FetLife', 'https://fetlife.com/users/{}', 'content'),
            ('Kink.com', 'https://www.kink.com/model/{}', 'content'),
            ('BDSMLR', 'https://{}.bdsmlr.com', 'status'),
            ('CollarSpace', 'https://www.collarspace.com/view/{}', 'content'),
        ],

        # Dating & Social
        'dating': [
            ('AdultFriendFinder', 'https://adultfriendfinder.com/p/{}', 'content'),
            ('Ashley Madison', 'https://www.ashleymadison.com/{}', 'content'),
            ('Grindr', 'https://www.grindr.com/{}', 'content'),
            ('Scruff', 'https://www.scruff.com/{}', 'content'),
            ('Recon', 'https://www.recon.com/{}', 'content'),
        ],

        # Gaming Related (with adult content)
        'gaming': [
            ('F95zone', 'https://f95zone.to/members/?username={}', 'content'),
            ('LoversLab', 'https://www.loverslab.com/profile/?name={}', 'content'),
            ('ULMF', 'https://ulmf.org/member.php?username={}', 'content'),
            ('Nutaku', 'https://www.nutaku.net/user/{}/', 'content'),
        ],
    }

    def __init__(self):
        self.results = []
        self.config = get_config()
        osint_settings = self.config.get_osint_settings()
        self.timeout = osint_settings['timeout']
        self.max_threads = osint_settings['max_threads']
        # Copy default sites and add custom sites
        self.sites = {k: list(v) for k, v in self.DEFAULT_SITES.items()}
        self.sites['custom'] = []
        self.load_custom_sites()

    def load_custom_sites(self):
        """Load custom sites from JSON file."""
        if CUSTOM_SITES_FILE.exists():
            try:
                with open(CUSTOM_SITES_FILE, 'r') as f:
                    data = json.load(f)
                    self.sites['custom'] = [tuple(site) for site in data.get('sites', [])]
            except Exception as e:
                self.sites['custom'] = []

    def save_custom_sites(self):
        """Save custom sites to JSON file."""
        try:
            data = {'sites': [list(site) for site in self.sites['custom']]}
            with open(CUSTOM_SITES_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            return False

    def add_custom_site(self):
        """Interactively add a custom site."""
        print(f"\n{Colors.BOLD}Add Custom Site{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
        print()
        print(f"{Colors.CYAN}URL Pattern Format:{Colors.RESET}")
        print(f"  Use {Colors.YELLOW}*{Colors.RESET} where the username should go")
        print(f"  Example: {Colors.DIM}https://example.com/user/*{Colors.RESET}")
        print(f"  Example: {Colors.DIM}https://example.com/profile?name=*{Colors.RESET}")
        print()

        # Get site name
        name = input(f"{Colors.WHITE}Site name: {Colors.RESET}").strip()
        if not name:
            self.print_status("Cancelled - no name provided", "warning")
            return

        # Get URL pattern
        url_pattern = input(f"{Colors.WHITE}URL pattern (use * for username): {Colors.RESET}").strip()
        if not url_pattern:
            self.print_status("Cancelled - no URL provided", "warning")
            return

        if '*' not in url_pattern:
            self.print_status("URL must contain * for username placeholder", "error")
            return

        # Convert * to {} for internal format
        url_template = url_pattern.replace('*', '{}')

        # Ensure URL has protocol
        if not url_template.startswith('http://') and not url_template.startswith('https://'):
            url_template = 'https://' + url_template

        # Get detection method
        print()
        print(f"{Colors.CYAN}Detection Method:{Colors.RESET}")
        print(f"  {Colors.GREEN}[1]{Colors.RESET} Status code (default) - Check HTTP response code")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Content - For sites with custom 404 pages")
        method_choice = input(f"{Colors.WHITE}Select [1]: {Colors.RESET}").strip() or "1"
        method = 'content' if method_choice == '2' else 'status'

        # Add to custom sites
        new_site = (name, url_template, method)
        self.sites['custom'].append(new_site)

        # Save to file
        if self.save_custom_sites():
            self.print_status(f"Added '{name}' to custom sites", "success")
            print(f"{Colors.DIM}  URL: {url_template.replace('{}', '<username>')}{Colors.RESET}")
        else:
            self.print_status("Failed to save custom sites", "error")

    def manage_custom_sites(self):
        """View and manage custom sites."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.BOLD}Manage Custom Sites{Colors.RESET}")
            print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
            print()

            custom = self.sites.get('custom', [])
            if not custom:
                print(f"{Colors.YELLOW}No custom sites added yet.{Colors.RESET}")
                print()
                print(f"  {Colors.GREEN}[1]{Colors.RESET} Add New Site")
                print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
                print()

                choice = input(f"{Colors.WHITE}Select: {Colors.RESET}").strip()
                if choice == "1":
                    self.add_custom_site()
                else:
                    break
            else:
                print(f"{Colors.CYAN}Custom Sites ({len(custom)}):{Colors.RESET}")
                print()
                for i, (name, url, method) in enumerate(custom, 1):
                    display_url = url.replace('{}', '*')
                    method_tag = f"[{method}]"
                    print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {name:25} {Colors.DIM}{method_tag}{Colors.RESET}")
                    print(f"      {Colors.DIM}{display_url}{Colors.RESET}")
                print()
                print(f"  {Colors.GREEN}[A]{Colors.RESET} Add New Site")
                print(f"  {Colors.RED}[R]{Colors.RESET} Remove Site")
                print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
                print()

                choice = input(f"{Colors.WHITE}Select: {Colors.RESET}").strip().upper()

                if choice == "0":
                    break
                elif choice == "A":
                    self.add_custom_site()
                elif choice == "R":
                    self.remove_custom_site()

    def remove_custom_site(self):
        """Remove a custom site."""
        custom = self.sites.get('custom', [])
        if not custom:
            self.print_status("No custom sites to remove", "warning")
            return

        print()
        idx_input = input(f"{Colors.WHITE}Enter site number to remove: {Colors.RESET}").strip()

        try:
            idx = int(idx_input) - 1
            if 0 <= idx < len(custom):
                removed = custom.pop(idx)
                if self.save_custom_sites():
                    self.print_status(f"Removed '{removed[0]}'", "success")
                else:
                    self.print_status("Failed to save changes", "error")
            else:
                self.print_status("Invalid selection", "error")
        except ValueError:
            self.print_status("Invalid number", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def auto_detect_site(self):
        """Auto-detect URL pattern for a domain."""
        print(f"\n{Colors.BOLD}Auto-Detect Site Pattern{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
        print()
        print(f"{Colors.CYAN}Enter just the domain name and we'll find the pattern.{Colors.RESET}")
        print(f"{Colors.DIM}Example: example.com or www.example.com{Colors.RESET}")
        print()

        # Get domain
        domain = input(f"{Colors.WHITE}Domain: {Colors.RESET}").strip()
        if not domain:
            self.print_status("Cancelled - no domain provided", "warning")
            return

        # Clean up domain
        domain = domain.replace('https://', '').replace('http://', '').rstrip('/')

        # Get test username
        print()
        print(f"{Colors.CYAN}We need a known username to test patterns.{Colors.RESET}")
        print(f"{Colors.DIM}Enter a username that you know EXISTS on this site.{Colors.RESET}")
        test_user = input(f"{Colors.WHITE}Test username: {Colors.RESET}").strip()
        if not test_user:
            self.print_status("Cancelled - no test username provided", "warning")
            return

        print(f"\n{Colors.CYAN}Testing {len(COMMON_PATTERNS)} common URL patterns...{Colors.RESET}\n")

        # Test each pattern
        working_patterns = []
        for i, pattern in enumerate(COMMON_PATTERNS):
            url = f"https://{domain}{pattern}".format(test_user)
            print(f"\r{Colors.DIM}  Testing pattern {i+1}/{len(COMMON_PATTERNS)}: {pattern}{' ' * 20}{Colors.RESET}", end="")

            cmd = f"curl -sI -o /dev/null -w '%{{http_code}}' -L --max-time 5 '{url}' 2>/dev/null"
            success, output, _ = self.run_cmd(cmd, 7)

            if success:
                status_code = output.strip()
                if status_code in ['200', '301', '302']:
                    working_patterns.append((pattern, status_code, url))

        print(f"\r{' ' * 80}\r", end="")  # Clear line

        if not working_patterns:
            print(f"{Colors.YELLOW}No working patterns found.{Colors.RESET}")
            print(f"{Colors.DIM}The site may use a non-standard URL format.{Colors.RESET}")
            print(f"{Colors.DIM}Try using manual add [A] with the correct URL pattern.{Colors.RESET}")
            return

        # Display working patterns
        print(f"{Colors.GREEN}Found {len(working_patterns)} working pattern(s):{Colors.RESET}\n")
        for i, (pattern, status, url) in enumerate(working_patterns, 1):
            status_info = "OK" if status == '200' else f"redirect ({status})"
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {pattern:20} {Colors.DIM}({status_info}){Colors.RESET}")
            print(f"      {Colors.DIM}{url}{Colors.RESET}")
        print()

        # Let user select
        print(f"  {Colors.DIM}[0]{Colors.RESET} Cancel")
        print()

        choice = input(f"{Colors.WHITE}Select pattern to add: {Colors.RESET}").strip()

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(working_patterns):
                selected_pattern, status, _ = working_patterns[idx]
                url_template = f"https://{domain}{selected_pattern}"

                # Get site name
                default_name = domain.split('.')[0].title()
                name = input(f"{Colors.WHITE}Site name [{default_name}]: {Colors.RESET}").strip() or default_name

                # Determine method based on status
                method = 'status' if status == '200' else 'content'

                # Add to custom sites
                new_site = (name, url_template, method)
                self.sites['custom'].append(new_site)

                if self.save_custom_sites():
                    self.print_status(f"Added '{name}' to custom sites", "success")
                    print(f"{Colors.DIM}  Pattern: {url_template.replace('{}', '*')}{Colors.RESET}")
                else:
                    self.print_status("Failed to save custom sites", "error")
            elif choice != "0":
                self.print_status("Cancelled", "warning")
        except ValueError:
            if choice != "0":
                self.print_status("Invalid selection", "error")

    def probe_domain(self, domain: str, test_user: str, quiet: bool = False) -> list:
        """Probe a domain for working URL patterns. Returns list of (pattern, status_code, url)."""
        domain = domain.replace('https://', '').replace('http://', '').rstrip('/')
        working_patterns = []

        for i, pattern in enumerate(COMMON_PATTERNS):
            url = f"https://{domain}{pattern}".format(test_user)
            if not quiet:
                print(f"\r{Colors.DIM}  Testing {domain}: pattern {i+1}/{len(COMMON_PATTERNS)}{' ' * 20}{Colors.RESET}", end="")

            cmd = f"curl -sI -o /dev/null -w '%{{http_code}}' -L --max-time 5 '{url}' 2>/dev/null"
            success, output, _ = self.run_cmd(cmd, 7)

            if success:
                status_code = output.strip()
                if status_code in ['200', '301', '302']:
                    working_patterns.append((pattern, status_code, url))
                    # For bulk mode, take first working pattern and stop
                    if quiet:
                        break

        if not quiet:
            print(f"\r{' ' * 80}\r", end="")

        return working_patterns

    def bulk_import(self):
        """Bulk import sites from custom_sites.inf file."""
        print(f"\n{Colors.BOLD}Bulk Import Sites{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
        print()

        # Check if file exists, create template if not
        if not BULK_IMPORT_FILE.exists():
            print(f"{Colors.YELLOW}Bulk import file not found.{Colors.RESET}")
            print(f"{Colors.DIM}Creating template at: {BULK_IMPORT_FILE}{Colors.RESET}")
            print()

            create = input(f"{Colors.WHITE}Create template file? (y/n): {Colors.RESET}").strip().lower()
            if create == 'y':
                template = """# AUTARCH Adult Site Scanner - Bulk Import File
# Add one domain per line (without http:// or https://)
# Lines starting with # are comments
#
# Example:
# example.com
# another-site.net
# subdomain.site.org
#
# After adding domains, run Bulk Import [B] again
# and provide a test username that exists on these sites.

"""
                with open(BULK_IMPORT_FILE, 'w') as f:
                    f.write(template)
                self.print_status(f"Created {BULK_IMPORT_FILE}", "success")
                print(f"{Colors.DIM}Edit this file and add domains, then run Bulk Import again.{Colors.RESET}")
            return

        # Read domains from file
        domains = []
        with open(BULK_IMPORT_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    # Clean up domain
                    domain = line.replace('https://', '').replace('http://', '').rstrip('/')
                    if domain:
                        domains.append(domain)

        if not domains:
            print(f"{Colors.YELLOW}No domains found in {BULK_IMPORT_FILE.name}{Colors.RESET}")
            print(f"{Colors.DIM}Add domains (one per line) and try again.{Colors.RESET}")
            return

        print(f"{Colors.CYAN}Found {len(domains)} domain(s) in {BULK_IMPORT_FILE.name}:{Colors.RESET}")
        for d in domains[:10]:
            print(f"  {Colors.DIM}-{Colors.RESET} {d}")
        if len(domains) > 10:
            print(f"  {Colors.DIM}... and {len(domains) - 10} more{Colors.RESET}")
        print()

        # Check which domains are already added
        existing_domains = set()
        for name, url, method in self.sites.get('custom', []):
            # Extract domain from URL template
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url.replace('{}', 'test'))
                existing_domains.add(parsed.netloc.lower())
            except:
                pass

        new_domains = [d for d in domains if d.lower() not in existing_domains]
        skipped = len(domains) - len(new_domains)

        if skipped > 0:
            print(f"{Colors.YELLOW}Skipping {skipped} already-added domain(s){Colors.RESET}")

        if not new_domains:
            print(f"{Colors.GREEN}All domains already added!{Colors.RESET}")
            return

        print(f"{Colors.CYAN}Will scan {len(new_domains)} new domain(s){Colors.RESET}")
        print()

        # Get test username
        print(f"{Colors.CYAN}We need a test username to probe URL patterns.{Colors.RESET}")
        print(f"{Colors.DIM}Use a common username that likely exists on most sites.{Colors.RESET}")
        print(f"{Colors.DIM}Example: admin, test, user, john, etc.{Colors.RESET}")
        print()
        test_user = input(f"{Colors.WHITE}Test username: {Colors.RESET}").strip()
        if not test_user:
            self.print_status("Cancelled - no test username provided", "warning")
            return

        print(f"\n{Colors.CYAN}Scanning {len(new_domains)} domains...{Colors.RESET}\n")

        # Scan each domain
        added = 0
        failed = []

        for i, domain in enumerate(new_domains):
            print(f"{Colors.DIM}[{i+1}/{len(new_domains)}] Scanning {domain}...{Colors.RESET}")

            # Use quiet mode to get first working pattern
            patterns = self.probe_domain(domain, test_user, quiet=True)

            if patterns:
                pattern, status, url = patterns[0]
                url_template = f"https://{domain}{pattern}"
                name = domain.split('.')[0].title()
                method = 'status' if status == '200' else 'content'

                # Add to custom sites
                new_site = (name, url_template, method)
                self.sites['custom'].append(new_site)
                added += 1
                print(f"  {Colors.GREEN}[+]{Colors.RESET} Added {name}: {pattern}")
            else:
                failed.append(domain)
                print(f"  {Colors.RED}[X]{Colors.RESET} No pattern found")

        # Save results
        if added > 0:
            if self.save_custom_sites():
                print(f"\n{Colors.GREEN}Successfully added {added} site(s){Colors.RESET}")
            else:
                print(f"\n{Colors.RED}Failed to save custom sites{Colors.RESET}")

        if failed:
            print(f"\n{Colors.YELLOW}Failed to detect patterns for {len(failed)} domain(s):{Colors.RESET}")
            for d in failed[:5]:
                print(f"  {Colors.DIM}-{Colors.RESET} {d}")
            if len(failed) > 5:
                print(f"  {Colors.DIM}... and {len(failed) - 5} more{Colors.RESET}")
            print(f"{Colors.DIM}Try adding these manually with [A] or [D]{Colors.RESET}")

        # Offer to clear the import file
        print()
        clear_file = input(f"{Colors.WHITE}Clear import file? (y/n): {Colors.RESET}").strip().lower()
        if clear_file == 'y':
            # Keep the header comments
            header = """# AUTARCH Adult Site Scanner - Bulk Import File
# Add one domain per line (without http:// or https://)
# Lines starting with # are comments

"""
            with open(BULK_IMPORT_FILE, 'w') as f:
                f.write(header)
            self.print_status("Import file cleared", "success")

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str, timeout: int = 10) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "", "timeout"
        except Exception as e:
            return False, "", str(e)

    def check_site(self, site_info: tuple, username: str) -> dict:
        """Check if username exists on a site."""
        name, url_template, method = site_info

        # Handle special URL formats
        if '{}' in url_template:
            url = url_template.format(username)
        else:
            url = url_template + username

        result = {
            'site': name,
            'url': url,
            'found': False,
            'status': 'unknown'
        }

        # Use curl to check
        cmd = f"curl -sI -o /dev/null -w '%{{http_code}}' -L --max-time {self.timeout} '{url}' 2>/dev/null"
        success, output, _ = self.run_cmd(cmd, self.timeout + 2)

        if success:
            status_code = output.strip()
            if method == 'status':
                # Check HTTP status code
                if status_code == '200':
                    result['found'] = True
                    result['status'] = 'found'
                elif status_code in ['301', '302']:
                    result['found'] = True
                    result['status'] = 'redirect'
                elif status_code == '404':
                    result['status'] = 'not_found'
                else:
                    result['status'] = f'http_{status_code}'
            else:
                # For content-based checks, we need to fetch the page
                if status_code == '200':
                    # Could do content analysis here
                    result['found'] = True
                    result['status'] = 'possible'
                elif status_code == '404':
                    result['status'] = 'not_found'
                else:
                    result['status'] = f'http_{status_code}'
        else:
            result['status'] = 'error'

        return result

    def scan_username(self, username: str, categories: list = None):
        """Scan username across selected site categories."""
        if categories is None:
            categories = list(self.sites.keys())

        # Collect all sites to scan
        sites_to_scan = []
        for cat in categories:
            if cat in self.sites:
                sites_to_scan.extend(self.sites[cat])

        print(f"\n{Colors.CYAN}Scanning {len(sites_to_scan)} sites for username: {username}{Colors.RESET}")
        print(f"{Colors.DIM}This may take a few minutes...{Colors.RESET}\n")

        self.results = []
        found_count = 0

        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(self.check_site, site, username): site for site in sites_to_scan}

            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                self.results.append(result)

                # Display progress
                if result['found']:
                    found_count += 1
                    status_color = Colors.GREEN if result['status'] == 'found' else Colors.YELLOW
                    print(f"  {status_color}[+]{Colors.RESET} {result['site']:25} {result['url']}")
                else:
                    # Show progress indicator
                    print(f"\r{Colors.DIM}  Checked {i+1}/{len(sites_to_scan)} sites, found {found_count}...{Colors.RESET}", end="")

        print(f"\r{' ' * 60}\r", end="")  # Clear progress line
        return self.results

    def display_results(self):
        """Display scan results."""
        found = [r for r in self.results if r['found']]
        not_found = [r for r in self.results if not r['found']]

        print(f"\n{Colors.BOLD}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Scan Results{Colors.RESET}")
        print(f"{Colors.BOLD}{'─' * 60}{Colors.RESET}\n")

        if found:
            print(f"{Colors.GREEN}Found ({len(found)} sites):{Colors.RESET}\n")
            for r in found:
                status_note = f" ({r['status']})" if r['status'] not in ['found'] else ""
                print(f"  {Colors.GREEN}+{Colors.RESET} {r['site']:25} {r['url']}{Colors.DIM}{status_note}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}No profiles found.{Colors.RESET}")

        print(f"\n{Colors.DIM}Total sites checked: {len(self.results)}{Colors.RESET}")
        print(f"{Colors.DIM}Profiles found: {len(found)}{Colors.RESET}")

    def export_results(self, filename: str):
        """Export results to file."""
        found = [r for r in self.results if r['found']]

        with open(filename, 'w') as f:
            f.write(f"Username OSINT Results\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Found Profiles ({len(found)}):\n\n")
            for r in found:
                f.write(f"{r['site']}: {r['url']}\n")

        self.print_status(f"Results exported to {filename}", "success")

    def show_menu(self):
        """Display main menu."""
        clear_screen()
        display_banner()

        print(f"{Colors.GREEN}{Colors.BOLD}  Adult Site Scanner{Colors.RESET}")
        print(f"{Colors.DIM}  Username OSINT for adult platforms{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Show category counts
        total = sum(len(sites) for sites in self.sites.values())
        custom_count = len(self.sites.get('custom', []))
        print(f"{Colors.DIM}  Sites in database: {total} ({custom_count} custom){Colors.RESET}")
        print()

        print(f"  {Colors.CYAN}Scan Categories:{Colors.RESET}")
        print(f"  {Colors.GREEN}[1]{Colors.RESET} Full Scan (all categories)")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Fanfiction & Story Sites")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Art & Creative Sites")
        print(f"  {Colors.GREEN}[4]{Colors.RESET} Video & Streaming Sites")
        print(f"  {Colors.GREEN}[5]{Colors.RESET} Forums & Communities")
        print(f"  {Colors.GREEN}[6]{Colors.RESET} Dating & Social Sites")
        print(f"  {Colors.GREEN}[7]{Colors.RESET} Gaming Related Sites")
        print(f"  {Colors.GREEN}[8]{Colors.RESET} Custom Sites Only")
        print(f"  {Colors.GREEN}[9]{Colors.RESET} Custom Category Selection")
        print()
        print(f"  {Colors.CYAN}Site Management:{Colors.RESET}")
        print(f"  {Colors.GREEN}[A]{Colors.RESET} Add Custom Site (manual)")
        print(f"  {Colors.GREEN}[D]{Colors.RESET} Auto-Detect Site Pattern")
        print(f"  {Colors.GREEN}[B]{Colors.RESET} Bulk Import from File")
        print(f"  {Colors.GREEN}[M]{Colors.RESET} Manage Custom Sites")
        print(f"  {Colors.GREEN}[L]{Colors.RESET} List All Sites")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def select_categories(self) -> list:
        """Let user select multiple categories."""
        print(f"\n{Colors.BOLD}Select Categories (comma-separated):{Colors.RESET}")
        print()

        cat_list = list(self.sites.keys())
        for i, cat in enumerate(cat_list, 1):
            count = len(self.sites[cat])
            print(f"  [{i}] {cat.title():20} ({count} sites)")

        print()
        selection = input(f"{Colors.WHITE}Enter numbers (e.g., 1,2,3): {Colors.RESET}").strip()

        selected = []
        try:
            for num in selection.split(','):
                idx = int(num.strip()) - 1
                if 0 <= idx < len(cat_list):
                    selected.append(cat_list[idx])
        except:
            pass

        return selected if selected else None

    def list_sites(self):
        """List all sites in database."""
        clear_screen()
        display_banner()

        print(f"{Colors.BOLD}Site Database{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        for category, sites in self.sites.items():
            if not sites:
                continue
            color = Colors.YELLOW if category == 'custom' else Colors.GREEN
            print(f"{color}{category.upper()} ({len(sites)} sites){Colors.RESET}")
            for name, url, method in sites:
                if category == 'custom':
                    display_url = url.replace('{}', '*')
                    print(f"  {Colors.DIM}-{Colors.RESET} {name} {Colors.DIM}({display_url}){Colors.RESET}")
                else:
                    print(f"  {Colors.DIM}-{Colors.RESET} {name}")
            print()

        input(f"{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def run_scan(self, categories: list = None):
        """Run a scan with given categories."""
        username = input(f"\n{Colors.WHITE}Enter username to search: {Colors.RESET}").strip()
        if not username:
            return

        self.scan_username(username, categories)
        self.display_results()

        # Export option
        export = input(f"\n{Colors.WHITE}Export results to file? (y/n): {Colors.RESET}").strip().lower()
        if export == 'y':
            filename = f"{username}_adultscan.txt"
            self.export_results(filename)

    def run(self):
        """Main loop."""
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().upper()

                if choice == "0":
                    break
                elif choice == "1":
                    self.run_scan()  # All categories
                elif choice == "2":
                    self.run_scan(['fanfiction'])
                elif choice == "3":
                    self.run_scan(['art'])
                elif choice == "4":
                    self.run_scan(['video'])
                elif choice == "5":
                    self.run_scan(['forums'])
                elif choice == "6":
                    self.run_scan(['dating'])
                elif choice == "7":
                    self.run_scan(['gaming'])
                elif choice == "8":
                    if self.sites.get('custom'):
                        self.run_scan(['custom'])
                    else:
                        self.print_status("No custom sites added yet. Use [A] to add sites.", "warning")
                        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                        continue
                elif choice == "9":
                    cats = self.select_categories()
                    if cats:
                        self.run_scan(cats)
                elif choice == "A":
                    self.add_custom_site()
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                    continue
                elif choice == "D":
                    self.auto_detect_site()
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                    continue
                elif choice == "B":
                    self.bulk_import()
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                    continue
                elif choice == "M":
                    self.manage_custom_sites()
                    continue
                elif choice == "L":
                    self.list_sites()
                    continue

                if choice in ["1", "2", "3", "4", "5", "6", "7", "8", "9"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    AdultScanner().run()


if __name__ == "__main__":
    run()
