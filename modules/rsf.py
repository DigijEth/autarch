"""
AUTARCH RouterSploit Module
Interface for RouterSploit Framework with module browser.

Provides easy access to RSF modules for IoT/embedded device testing.
Uses the RSF interface from core/rsf_interface.py.
Integrates with rsf_terms.py and rsf_modules.py for descriptions.
"""

import sys
import socket
from pathlib import Path
from typing import Optional

# Module metadata
DESCRIPTION = "RouterSploit Framework interface"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.rsf_interface import get_rsf_interface, RSFStatus
from core.rsf import get_rsf_manager, RSFError
from core.banner import Colors, clear_screen, display_banner
from core.rsf_terms import (
    get_setting_info, get_setting_prompt, format_setting_help, validate_setting_value
)
from core.rsf_modules import (
    get_module_info as get_library_module_info,
    search_modules as library_search_modules,
    get_modules_by_type as library_get_modules_by_type,
    format_module_help,
    MODULE_TYPES,
)


class RSFMenu:
    """RouterSploit menu interface with module browser."""

    # Module categories for browsing
    MODULE_CATEGORIES = {
        'exploits': {
            'name': 'Exploits',
            'description': 'Vulnerability exploits for routers, cameras, devices',
            'color': Colors.RED,
        },
        'creds': {
            'name': 'Credentials',
            'description': 'Default credential and brute-force modules',
            'color': Colors.YELLOW,
        },
        'scanners': {
            'name': 'Scanners',
            'description': 'Automated vulnerability scanners',
            'color': Colors.CYAN,
        },
        'payloads': {
            'name': 'Payloads',
            'description': 'Shellcode and payload generators',
            'color': Colors.MAGENTA,
        },
        'encoders': {
            'name': 'Encoders',
            'description': 'Payload encoding and obfuscation',
            'color': Colors.GREEN,
        },
    }

    def __init__(self):
        self.rsf = get_rsf_interface()
        self.rsf_manager = get_rsf_manager()
        self.current_module = None  # module path
        self.current_instance = None  # loaded module instance
        self.current_info = None  # RSFModuleInfo

        # Global target settings
        self.global_settings = {
            'target': '',
            'port': '',
            'ssl': 'false',
        }

    def print_status(self, message: str, status: str = "info"):
        """Print a status message."""
        colors = {"info": Colors.CYAN, "success": Colors.GREEN,
                  "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def wrap_text(self, text: str, width: int = 60, indent: str = "      ") -> str:
        """Word-wrap text with indent."""
        words = text.split()
        lines = []
        current_line = ""
        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line += (" " if current_line else "") + word
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        if current_line:
            lines.append(current_line)
        return f"\n{indent}".join(lines)

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    # =========================================================================
    # MAIN MENU
    # =========================================================================

    def show_main_menu(self):
        """Display RSF main menu."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  RouterSploit Framework{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Status
        if self.rsf.is_available:
            count = self.rsf.module_count
            print(f"  {Colors.GREEN}Status: Available ({count} modules){Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}Status: Not Available{Colors.RESET}")
            print(f"  {Colors.DIM}Check install path in Settings > RouterSploit{Colors.RESET}")

        # Show current settings
        if self.global_settings['target']:
            print(f"  {Colors.CYAN}Target:{Colors.RESET} {self.global_settings['target']}")
        if self.global_settings['port']:
            print(f"  {Colors.CYAN}Port:{Colors.RESET}   {self.global_settings['port']}")

        # Current module
        if self.current_module:
            print(f"  {Colors.YELLOW}Module:{Colors.RESET} {self.current_module}")

        print()
        print(f"  {Colors.RED}[1]{Colors.RESET} Set Target        {Colors.DIM}- Configure target device{Colors.RESET}")
        print(f"  {Colors.RED}[2]{Colors.RESET} Module Browser    {Colors.DIM}- Browse by category{Colors.RESET}")
        print(f"  {Colors.RED}[3]{Colors.RESET} Search Modules    {Colors.DIM}- Search all modules{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[4]{Colors.RESET} Current Module    {Colors.DIM}- View/configure selected module{Colors.RESET}")
        print(f"  {Colors.RED}[5]{Colors.RESET} Check Target      {Colors.DIM}- Vulnerability check (safe){Colors.RESET}")
        print(f"  {Colors.RED}[6]{Colors.RESET} Run Module        {Colors.DIM}- Execute current module{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[7]{Colors.RESET} Quick Scan        {Colors.DIM}- AutoPwn & common scanners{Colors.RESET}")
        print(f"  {Colors.RED}[8]{Colors.RESET} Credential Check  {Colors.DIM}- Default credential scanning{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back to Main Menu")
        print()

    # =========================================================================
    # TARGET SETTINGS
    # =========================================================================

    def show_target_settings(self):
        """Configure target device settings."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Target Configuration{Colors.RESET}")
            print(f"{Colors.DIM}  Configure the target device for RSF modules{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            target_val = self.global_settings['target'] or f"{Colors.YELLOW}(not set){Colors.RESET}"
            port_val = self.global_settings['port'] or f"{Colors.DIM}(module default){Colors.RESET}"
            ssl_val = self.global_settings['ssl']

            print(f"  {Colors.RED}[1]{Colors.RESET} Target  = {target_val}")
            target_info = get_setting_info('target')
            if target_info:
                print(f"      {Colors.DIM}{self.wrap_text(target_info['description'])}{Colors.RESET}")
            print()
            print(f"  {Colors.RED}[2]{Colors.RESET} Port    = {port_val}")
            print(f"      {Colors.DIM}Override module default port{Colors.RESET}")
            print()
            print(f"  {Colors.RED}[3]{Colors.RESET} SSL     = {ssl_val}")
            print(f"      {Colors.DIM}Enable SSL/TLS for connections{Colors.RESET}")
            print()
            print(f"  {Colors.GREEN}[R]{Colors.RESET} Resolve hostname to IP")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == '1':
                    self._set_target()
                elif choice == '2':
                    self._set_port()
                elif choice == '3':
                    self._toggle_ssl()
                elif choice == 'r':
                    self._resolve_hostname()

            except (EOFError, KeyboardInterrupt):
                break

    def _set_target(self):
        """Set target IP/hostname."""
        print()
        print(format_setting_help('target'))
        print()

        current = self.global_settings['target']
        prompt = f"Target [{current}]: " if current else "Target: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value and current:
            return

        if value:
            # Hostname resolution
            if not any(c.isdigit() for c in value.split('/')[0].split('-')[0]):
                print(f"{Colors.CYAN}[*] Resolving {value}...{Colors.RESET}")
                ip = self.resolve_hostname(value)
                if ip:
                    print(f"{Colors.GREEN}[+] Resolved to {ip}{Colors.RESET}")
                    use_ip = input(f"{Colors.WHITE}Use resolved IP? (y/n) [y]: {Colors.RESET}").strip().lower()
                    if use_ip != 'n':
                        value = ip
                else:
                    print(f"{Colors.YELLOW}[!] Could not resolve hostname{Colors.RESET}")

            self.global_settings['target'] = value
            self.print_status(f"target => {value}", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _set_port(self):
        """Set port override."""
        print()
        print(format_setting_help('port'))
        print()

        current = self.global_settings['port']
        prompt = f"Port [{current or 'module default'}]: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value:
            return

        if value == 'clear' or value == 'reset':
            self.global_settings['port'] = ''
            self.print_status("Port reset to module default", "success")
        else:
            valid, msg = validate_setting_value('port', value)
            if valid:
                self.global_settings['port'] = value
                self.print_status(f"port => {value}", "success")
            else:
                self.print_status(msg, "warning")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _toggle_ssl(self):
        """Toggle SSL setting."""
        current = self.global_settings['ssl']
        new_val = 'false' if current == 'true' else 'true'
        self.global_settings['ssl'] = new_val
        self.print_status(f"ssl => {new_val}", "success")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _resolve_hostname(self):
        """Resolve a hostname to IP."""
        print()
        hostname = input(f"{Colors.WHITE}Hostname to resolve: {Colors.RESET}").strip()
        if hostname:
            print(f"{Colors.CYAN}[*] Resolving {hostname}...{Colors.RESET}")
            ip = self.resolve_hostname(hostname)
            if ip:
                print(f"{Colors.GREEN}[+] {hostname} => {ip}{Colors.RESET}")
                use_it = input(f"{Colors.WHITE}Set as target? (y/n) [y]: {Colors.RESET}").strip().lower()
                if use_it != 'n':
                    self.global_settings['target'] = ip
                    self.print_status(f"target => {ip}", "success")
            else:
                self.print_status(f"Could not resolve '{hostname}'", "error")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # MODULE BROWSER
    # =========================================================================

    def show_module_browser(self):
        """Browse modules by category."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Module Browser{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            cats = list(self.MODULE_CATEGORIES.items())
            for i, (key, cat) in enumerate(cats, 1):
                # Get count
                try:
                    count = len(self.rsf.list_modules(key))
                except Exception:
                    count = 0
                print(f"  {cat['color']}[{i}]{Colors.RESET} {cat['name']:<15} "
                      f"{Colors.DIM}({count} modules) - {cat['description']}{Colors.RESET}")

            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == '0' or not choice:
                    break

                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(cats):
                        category_key = cats[idx][0]
                        self._browse_category(category_key)
                except ValueError:
                    pass

            except (EOFError, KeyboardInterrupt):
                break

    def _browse_category(self, category: str):
        """Browse modules within a category, with subcategory grouping."""
        cat_info = self.MODULE_CATEGORIES.get(category, {})

        try:
            modules = self.rsf.list_modules(category)
        except Exception as e:
            self.print_status(f"Error listing modules: {e}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        if not modules:
            self.print_status(f"No modules found in '{category}'", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Group by subcategory (e.g., exploits/routers/dlink -> routers/dlink)
        subcats = {}
        for mod_path in modules:
            parts = mod_path.split('/')
            if len(parts) >= 3:
                subcat = parts[1]  # routers, cameras, generic, etc.
            elif len(parts) >= 2:
                subcat = parts[1]
            else:
                subcat = 'other'
            if subcat not in subcats:
                subcats[subcat] = []
            subcats[subcat].append(mod_path)

        # Show subcategory menu
        while True:
            clear_screen()
            display_banner()

            print(f"{cat_info.get('color', Colors.WHITE)}{Colors.BOLD}  {cat_info.get('name', category)}{Colors.RESET}")
            print(f"{Colors.DIM}  {len(modules)} modules total{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            subcat_list = sorted(subcats.keys())
            for i, subcat in enumerate(subcat_list, 1):
                count = len(subcats[subcat])
                print(f"  {cat_info.get('color', Colors.WHITE)}[{i}]{Colors.RESET} "
                      f"{subcat:<20} {Colors.DIM}({count} modules){Colors.RESET}")

            print()
            print(f"  {Colors.GREEN}[A]{Colors.RESET} Show all {len(modules)} modules")
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == 'a':
                    self._paginated_module_list(modules, f"All {category}")
                else:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(subcat_list):
                            subcat_key = subcat_list[idx]
                            self._paginated_module_list(
                                subcats[subcat_key],
                                f"{category}/{subcat_key}"
                            )
                    except ValueError:
                        pass

            except (EOFError, KeyboardInterrupt):
                break

    def _paginated_module_list(self, modules: list, title: str):
        """Display a paginated list of modules with selection."""
        page_size = 20
        page = 0
        total_pages = max(1, (len(modules) + page_size - 1) // page_size)

        while True:
            clear_screen()
            display_banner()

            start = page * page_size
            end = min(start + page_size, len(modules))
            page_modules = modules[start:end]

            print(f"{Colors.RED}{Colors.BOLD}  {title}{Colors.RESET}")
            print(f"{Colors.DIM}  Page {page + 1}/{total_pages} ({len(modules)} modules){Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Two-column layout
            half = (len(page_modules) + 1) // 2
            for i in range(half):
                # Left column
                idx1 = start + i
                mod1 = page_modules[i]
                short1 = mod1.split('/')[-1][:25]
                left = f"  [{idx1 + 1:>3}] {short1:<28}"

                # Right column
                right = ""
                if i + half < len(page_modules):
                    idx2 = start + i + half
                    mod2 = page_modules[i + half]
                    short2 = mod2.split('/')[-1][:25]
                    right = f"[{idx2 + 1:>3}] {short2}"

                print(f"{left}{Colors.DIM}{right}{Colors.RESET}")

            print()

            # Navigation
            nav_parts = []
            if page > 0:
                nav_parts.append(f"[P] Prev")
            if page < total_pages - 1:
                nav_parts.append(f"[N] Next")
            nav_parts.append("[#] Select module by number")
            nav_parts.append("[0] Back")
            print(f"  {Colors.DIM}{' | '.join(nav_parts)}{Colors.RESET}")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == 'n' and page < total_pages - 1:
                    page += 1
                elif choice == 'p' and page > 0:
                    page -= 1
                else:
                    try:
                        num = int(choice)
                        if 1 <= num <= len(modules):
                            selected = modules[num - 1]
                            self._show_module_details(selected)
                    except ValueError:
                        pass

            except (EOFError, KeyboardInterrupt):
                break

    def _show_module_details(self, module_path: str):
        """Show detailed info about a module and offer to select it."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Module Details{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Try curated library first
        curated = get_library_module_info(module_path)
        if curated:
            print(format_module_help(module_path))
        else:
            # Try live introspection
            print(f"  {Colors.WHITE}Path:{Colors.RESET} {module_path}")
            try:
                info = self.rsf.get_module_info(module_path)
                print(f"  {Colors.WHITE}Name:{Colors.RESET} {info.name}")
                if info.description:
                    print(f"  {Colors.WHITE}Description:{Colors.RESET}")
                    print(f"    {self.wrap_text(info.description)}")
                if info.authors:
                    print(f"  {Colors.WHITE}Authors:{Colors.RESET} {', '.join(info.authors)}")
                if info.devices:
                    print(f"  {Colors.WHITE}Devices:{Colors.RESET}")
                    for dev in info.devices[:10]:
                        print(f"    - {dev}")
                    if len(info.devices) > 10:
                        print(f"    {Colors.DIM}... and {len(info.devices) - 10} more{Colors.RESET}")
                if info.references:
                    print(f"  {Colors.WHITE}References:{Colors.RESET}")
                    for ref in info.references[:5]:
                        print(f"    {Colors.DIM}{ref}{Colors.RESET}")
            except RSFError as e:
                print(f"  {Colors.YELLOW}Could not load module info: {e}{Colors.RESET}")

        print()
        print(f"  {Colors.GREEN}[S]{Colors.RESET} Select this module")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()
            if choice == 's':
                self._select_module(module_path)
        except (EOFError, KeyboardInterrupt):
            pass

    def _select_module(self, module_path: str):
        """Load and select a module as the current module."""
        try:
            instance, info = self.rsf_manager.load_module(module_path)
            self.current_module = module_path
            self.current_instance = instance
            self.current_info = info

            # Apply global settings
            if self.global_settings['target']:
                try:
                    self.rsf_manager.set_module_option(instance, 'target', self.global_settings['target'])
                except RSFError:
                    pass
            if self.global_settings['port']:
                try:
                    self.rsf_manager.set_module_option(instance, 'port', self.global_settings['port'])
                except RSFError:
                    pass

            self.print_status(f"Module selected: {module_path}", "success")
        except RSFError as e:
            self.print_status(f"Failed to load module: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # SEARCH
    # =========================================================================

    def search_modules(self):
        """Search for modules by keyword."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Search Modules{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        try:
            query = input(f"{Colors.WHITE}  Search: {Colors.RESET}").strip()
            if not query:
                return

            print(f"\n{Colors.CYAN}[*] Searching for '{query}'...{Colors.RESET}")

            results = self.rsf.search_modules(query)

            if not results:
                self.print_status(f"No modules found for '{query}'", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

            self.print_status(f"Found {len(results)} modules", "success")
            self._paginated_module_list(results, f"Search: {query}")

        except RSFError as e:
            self.print_status(f"Search error: {e}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
        except (EOFError, KeyboardInterrupt):
            pass

    # =========================================================================
    # CURRENT MODULE
    # =========================================================================

    def show_current_module(self):
        """View and configure the current selected module."""
        if not self.current_module or not self.current_instance:
            self.print_status("No module selected. Use Module Browser or Search first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Current Module{Colors.RESET}")
            print(f"{Colors.YELLOW}  {self.current_module}{Colors.RESET}")
            if self.current_info:
                print(f"  {Colors.DIM}{self.current_info.name}{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Show options
            options = self.rsf_manager.get_module_options(self.current_instance)

            if options:
                # Separate required (non-advanced, non-empty description) and optional
                required = [o for o in options if not o.get('advanced', False)]
                advanced = [o for o in options if o.get('advanced', False)]

                if required:
                    print(f"  {Colors.BOLD}Options:{Colors.RESET}")
                    for opt in required:
                        current = opt.get('current', '')
                        desc = opt.get('description', '')
                        print(f"    {Colors.CYAN}{opt['name']:<20}{Colors.RESET} "
                              f"= {current or Colors.DIM + '(empty)' + Colors.RESET}"
                              f"  {Colors.DIM}{desc[:40]}{Colors.RESET}")

                if advanced:
                    print()
                    print(f"  {Colors.DIM}Advanced Options:{Colors.RESET}")
                    for opt in advanced:
                        current = opt.get('current', '')
                        print(f"    {Colors.DIM}{opt['name']:<20} = {current}{Colors.RESET}")
            else:
                print(f"  {Colors.DIM}No configurable options{Colors.RESET}")

            print()
            print(f"  {Colors.RED}[1]{Colors.RESET} Set Option")
            print(f"  {Colors.RED}[2]{Colors.RESET} Show All Options")
            print(f"  {Colors.GREEN}[3]{Colors.RESET} Check Target (safe)")
            print(f"  {Colors.RED}[4]{Colors.RESET} Run Module")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == '0' or not choice:
                    break
                elif choice == '1':
                    self._set_option()
                elif choice == '2':
                    self._show_all_options()
                elif choice == '3':
                    self._check_target()
                elif choice == '4':
                    self._run_module()

            except (EOFError, KeyboardInterrupt):
                break

    def _set_option(self):
        """Set a module option."""
        print()
        name = input(f"{Colors.WHITE}  Option name: {Colors.RESET}").strip()
        if not name:
            return

        # Show help
        help_text = format_setting_help(name)
        if help_text and 'No help available' not in help_text:
            print(help_text)
            print()

        # Get current value
        try:
            current = getattr(self.current_instance, name, '')
        except Exception:
            current = ''

        prompt = f"  Value [{current}]: " if current else "  Value: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value and current:
            return

        if value:
            try:
                self.rsf_manager.set_module_option(self.current_instance, name, value)
                self.print_status(f"{name} => {value}", "success")

                # Update global settings if target/port
                if name == 'target':
                    self.global_settings['target'] = value
                elif name == 'port':
                    self.global_settings['port'] = value
            except RSFError as e:
                self.print_status(f"Error: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _show_all_options(self):
        """Show all options with details."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Module Options{Colors.RESET}")
        print(f"{Colors.YELLOW}  {self.current_module}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        options = self.rsf_manager.get_module_options(self.current_instance)
        for opt in options:
            adv_tag = f" {Colors.DIM}(advanced){Colors.RESET}" if opt.get('advanced') else ""
            print(f"  {Colors.CYAN}{opt['name']}{Colors.RESET}{adv_tag}")
            print(f"    Type:    {opt.get('type', 'string')}")
            print(f"    Current: {opt.get('current', '(empty)')}")
            print(f"    Default: {opt.get('default', '(none)')}")
            if opt.get('description'):
                print(f"    Desc:    {self.wrap_text(opt['description'], indent='             ')}")
            print()

        input(f"{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # CHECK & RUN
    # =========================================================================

    def _check_target(self):
        """Run check() on the current module."""
        if not self.current_module or not self.current_instance:
            self.print_status("No module selected", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        target = str(getattr(self.current_instance, 'target', ''))
        if not target:
            self.print_status("Target not set. Set target first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.CYAN}[*] Running check() on {target}...{Colors.RESET}")
        print(f"{Colors.DIM}    This is a safe vulnerability verification.{Colors.RESET}")
        print()

        from core.config import get_config
        timeout = get_config().get_int('rsf', 'execution_timeout', 120)

        check_result, output = self.rsf_manager.execute_check(self.current_instance, timeout)

        if check_result is True:
            self.print_status(f"Target IS VULNERABLE", "success")
        elif check_result is False:
            self.print_status(f"Target is NOT vulnerable", "info")
        else:
            self.print_status(f"Check returned no definitive result", "warning")

        if output:
            print()
            # Strip ANSI for display
            from core.rsf_interface import _ANSI_RE
            cleaned = _ANSI_RE.sub('', output)
            for line in cleaned.splitlines()[:30]:
                stripped = line.strip()
                if stripped:
                    if stripped.startswith('[+]'):
                        print(f"  {Colors.GREEN}{stripped}{Colors.RESET}")
                    elif stripped.startswith('[-]'):
                        print(f"  {Colors.RED}{stripped}{Colors.RESET}")
                    elif stripped.startswith('[*]'):
                        print(f"  {Colors.CYAN}{stripped}{Colors.RESET}")
                    else:
                        print(f"  {stripped}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _run_module(self):
        """Run the current module with confirmation."""
        if not self.current_module or not self.current_instance:
            self.print_status("No module selected", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        target = str(getattr(self.current_instance, 'target', ''))
        if not target:
            self.print_status("Target not set. Set target first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Confirmation
        print()
        print(f"  {Colors.RED}{Colors.BOLD}WARNING: This will execute the module against the target.{Colors.RESET}")
        print(f"  {Colors.CYAN}Module:{Colors.RESET} {self.current_module}")
        print(f"  {Colors.CYAN}Target:{Colors.RESET} {target}")
        print()

        confirm = input(f"{Colors.WHITE}  Proceed? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            self.print_status("Cancelled", "info")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.RED}[*] Executing module...{Colors.RESET}\n")

        # Build options dict from current instance
        options = {}
        for opt in self.rsf_manager.get_module_options(self.current_instance):
            options[opt['name']] = opt.get('current', '')

        result = self.rsf.run_module(self.current_module, options)
        self.rsf.print_result(result)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def run_check(self):
        """Run check from main menu (option 5)."""
        if not self.current_module:
            self.print_status("No module selected. Use Module Browser or Search first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return
        self._check_target()

    def run_module(self):
        """Run module from main menu (option 6)."""
        if not self.current_module:
            self.print_status("No module selected. Use Module Browser or Search first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return
        self._run_module()

    # =========================================================================
    # QUICK SCAN
    # =========================================================================

    def quick_scan(self):
        """Quick scan presets using RSF scanners."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Quick Scan{Colors.RESET}")
            print(f"{Colors.DIM}  Automated scanning presets{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            target = self.global_settings.get('target', '')
            if target:
                print(f"  {Colors.CYAN}Target:{Colors.RESET} {target}")
            else:
                print(f"  {Colors.YELLOW}Target: (not set - will be prompted){Colors.RESET}")
            print()

            print(f"  {Colors.RED}[1]{Colors.RESET} AutoPwn           {Colors.DIM}- Scan ALL modules (slow){Colors.RESET}")
            print(f"  {Colors.RED}[2]{Colors.RESET} Router Scan       {Colors.DIM}- Router-specific modules{Colors.RESET}")
            print(f"  {Colors.RED}[3]{Colors.RESET} Camera Scan       {Colors.DIM}- Camera-specific modules{Colors.RESET}")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == '0' or not choice:
                    break
                elif choice == '1':
                    self._run_scanner('scanners/autopwn', 'AutoPwn')
                elif choice == '2':
                    self._run_scanner('scanners/routers/router_scan', 'Router Scanner')
                elif choice == '3':
                    self._run_scanner('scanners/cameras/camera_scan', 'Camera Scanner')

            except (EOFError, KeyboardInterrupt):
                break

    def _run_scanner(self, module_path: str, name: str):
        """Run a scanner module."""
        target = self.global_settings.get('target', '')
        if not target:
            print()
            target = input(f"{Colors.WHITE}  Target IP: {Colors.RESET}").strip()
            if not target:
                return
            self.global_settings['target'] = target

        print()
        print(f"  {Colors.CYAN}Scanner:{Colors.RESET} {name}")
        print(f"  {Colors.CYAN}Target:{Colors.RESET}  {target}")
        print(f"  {Colors.DIM}This may take several minutes...{Colors.RESET}")
        print()

        confirm = input(f"{Colors.WHITE}  Start scan? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        print(f"\n{Colors.CYAN}[*] Starting {name}...{Colors.RESET}\n")

        options = {'target': target}
        if self.global_settings.get('port'):
            options['port'] = self.global_settings['port']

        result = self.rsf.run_module(module_path, options)
        self.rsf.print_result(result, verbose=True)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # CREDENTIAL CHECK
    # =========================================================================

    def credential_check(self):
        """Run credential checking modules."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.YELLOW}{Colors.BOLD}  Credential Check{Colors.RESET}")
            print(f"{Colors.DIM}  Test for default/weak credentials{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            target = self.global_settings.get('target', '')
            if target:
                print(f"  {Colors.CYAN}Target:{Colors.RESET} {target}")
            else:
                print(f"  {Colors.YELLOW}Target: (not set - will be prompted){Colors.RESET}")
            print()

            print(f"  {Colors.YELLOW}[1]{Colors.RESET} FTP Default Creds     {Colors.DIM}- Test FTP (port 21){Colors.RESET}")
            print(f"  {Colors.YELLOW}[2]{Colors.RESET} SSH Bruteforce        {Colors.DIM}- Test SSH (port 22){Colors.RESET}")
            print(f"  {Colors.YELLOW}[3]{Colors.RESET} Telnet Bruteforce     {Colors.DIM}- Test Telnet (port 23){Colors.RESET}")
            print(f"  {Colors.YELLOW}[4]{Colors.RESET} HTTP Basic Auth       {Colors.DIM}- Test HTTP auth (port 80){Colors.RESET}")
            print(f"  {Colors.YELLOW}[5]{Colors.RESET} SNMP Community Scan   {Colors.DIM}- Test SNMP (port 161){Colors.RESET}")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == '0' or not choice:
                    break
                elif choice == '1':
                    self._run_cred_check('creds/generic/ftp_bruteforce', 'FTP Bruteforce')
                elif choice == '2':
                    self._run_cred_check('creds/generic/ssh_bruteforce', 'SSH Bruteforce')
                elif choice == '3':
                    self._run_cred_check('creds/generic/telnet_bruteforce', 'Telnet Bruteforce')
                elif choice == '4':
                    self._run_cred_check('creds/generic/http_basic_digest_bruteforce', 'HTTP Auth Bruteforce')
                elif choice == '5':
                    self._run_cred_check('creds/generic/snmp_bruteforce', 'SNMP Bruteforce')

            except (EOFError, KeyboardInterrupt):
                break

    def _run_cred_check(self, module_path: str, name: str):
        """Run a credential checking module."""
        target = self.global_settings.get('target', '')
        if not target:
            print()
            target = input(f"{Colors.WHITE}  Target IP: {Colors.RESET}").strip()
            if not target:
                return
            self.global_settings['target'] = target

        print()
        print(f"  {Colors.YELLOW}Module:{Colors.RESET}  {name}")
        print(f"  {Colors.CYAN}Target:{Colors.RESET}  {target}")
        print()

        confirm = input(f"{Colors.WHITE}  Start credential check? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        print(f"\n{Colors.CYAN}[*] Running {name}...{Colors.RESET}\n")

        options = {'target': target}
        if self.global_settings.get('port'):
            options['port'] = self.global_settings['port']

        result = self.rsf.run_module(module_path, options)
        self.rsf.print_result(result)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")


# ─── Module Entry Point ────────────────────────────────────────────────────

def run():
    """Main entry point for the RSF module."""
    menu = RSFMenu()

    while True:
        menu.show_main_menu()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

            if choice == '0' or not choice:
                break
            elif choice == '1':
                menu.show_target_settings()
            elif choice == '2':
                menu.show_module_browser()
            elif choice == '3':
                menu.search_modules()
            elif choice == '4':
                menu.show_current_module()
            elif choice == '5':
                menu.run_check()
            elif choice == '6':
                menu.run_module()
            elif choice == '7':
                menu.quick_scan()
            elif choice == '8':
                menu.credential_check()

        except (EOFError, KeyboardInterrupt):
            break
