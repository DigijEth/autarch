"""
AUTARCH Metasploit Module
Enhanced interface for Metasploit Framework with module browser.

Provides easy access to MSF modules, exploits, and sessions.
Uses the centralized MSF interface from core/msf_interface.py.
Integrates with msf_terms.py and msf_modules.py for descriptions.
"""

import sys
import os
import re
import json
import time
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any

# Module metadata
DESCRIPTION = "Metasploit Framework interface"
AUTHOR = "darkHal"
VERSION = "2.0"
CATEGORY = "offense"

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.msf_interface import get_msf_interface
from core.banner import Colors, clear_screen, display_banner
from core.msf_terms import get_setting_info, get_setting_prompt, format_setting_help, validate_setting_value
from core.msf_modules import (
    get_module_info as get_library_module_info,
    get_module_description,
    search_modules as library_search_modules,
    get_modules_by_type,
    format_module_help,
    MSF_MODULES
)


class MSFMenu:
    """Enhanced Metasploit menu interface with module browser."""

    # Module categories for browsing
    MODULE_CATEGORIES = {
        'scanners': {
            'name': 'Scanners',
            'description': 'Network and vulnerability scanners',
            'types': ['auxiliary/scanner'],
            'color': Colors.CYAN
        },
        'exploits': {
            'name': 'Exploits',
            'description': 'Remote and local exploits',
            'types': ['exploit'],
            'color': Colors.RED
        },
        'post': {
            'name': 'Post-Exploitation',
            'description': 'Post-exploitation modules',
            'types': ['post'],
            'color': Colors.MAGENTA
        },
        'payloads': {
            'name': 'Payloads',
            'description': 'Payload generators',
            'types': ['payload'],
            'color': Colors.YELLOW
        },
        'auxiliary': {
            'name': 'Auxiliary',
            'description': 'Other auxiliary modules',
            'types': ['auxiliary'],
            'color': Colors.GREEN
        }
    }

    def __init__(self):
        self.msf = get_msf_interface()
        self.current_module = None
        self.current_module_type = None
        self.module_options = {}

        # Global target settings - persist across module selections
        self.global_settings = {
            'RHOSTS': '',
            'LHOST': '',
            'LPORT': '4444',
        }

    def print_status(self, message: str, status: str = "info"):
        """Print a status message."""
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def wrap_text(self, text: str, width: int = 60, indent: str = "      ") -> str:
        """Word-wrap text with indent for subsequent lines."""
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

    def ensure_connected(self) -> bool:
        """Ensure connected to MSF RPC."""
        connected, msg = self.msf.ensure_connected()
        if not connected:
            print(f"\n{Colors.YELLOW}{msg}{Colors.RESET}")
            print(f"{Colors.DIM}Make sure msfrpcd is running: msfrpcd -P <password> -S{Colors.RESET}")
        return connected

    def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            # Check if it's already an IP
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            pass

        # Try to resolve
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror:
            return None

    def get_local_ip(self) -> str:
        """Get local IP address for LHOST."""
        try:
            # Connect to external address to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    # =========================================================================
    # MAIN MENU
    # =========================================================================

    def show_main_menu(self):
        """Display MSF main menu."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Metasploit Framework{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Connection status
        if self.msf.is_connected:
            print(f"  {Colors.GREEN}Status: Connected{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}Status: Disconnected{Colors.RESET}")

        # Show current global settings
        if any(self.global_settings.values()):
            print()
            if self.global_settings['RHOSTS']:
                print(f"  {Colors.CYAN}Target:{Colors.RESET} {self.global_settings['RHOSTS']}")
            if self.global_settings['LHOST']:
                print(f"  {Colors.CYAN}LHOST:{Colors.RESET}  {self.global_settings['LHOST']}")
            if self.global_settings['LPORT'] and self.global_settings['LPORT'] != '4444':
                print(f"  {Colors.CYAN}LPORT:{Colors.RESET}  {self.global_settings['LPORT']}")

        # Current module
        if self.current_module:
            print(f"  {Colors.YELLOW}Module:{Colors.RESET} {self.current_module_type}/{self.current_module}")

        print()
        print(f"  {Colors.RED}[1]{Colors.RESET} Set Target        {Colors.DIM}- Configure target & listener settings{Colors.RESET}")
        print(f"  {Colors.RED}[2]{Colors.RESET} Module Browser    {Colors.DIM}- Browse modules by category{Colors.RESET}")
        print(f"  {Colors.RED}[3]{Colors.RESET} Search Modules    {Colors.DIM}- Search all modules{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[4]{Colors.RESET} Current Module    {Colors.DIM}- View/configure selected module{Colors.RESET}")
        print(f"  {Colors.RED}[5]{Colors.RESET} Run Module        {Colors.DIM}- Execute current module{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[6]{Colors.RESET} Sessions          {Colors.DIM}- View and interact with sessions{Colors.RESET}")
        print(f"  {Colors.RED}[7]{Colors.RESET} Jobs              {Colors.DIM}- View running background jobs{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[8]{Colors.RESET} MSF Console       {Colors.DIM}- Direct console access{Colors.RESET}")
        print(f"  {Colors.RED}[9]{Colors.RESET} Quick Scan        {Colors.DIM}- Common scanners{Colors.RESET}")
        print(f"  {Colors.RED}[E]{Colors.RESET} Exploit Suggester {Colors.DIM}- Suggest exploits from vuln data{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back to Main Menu")
        print()

    # =========================================================================
    # GLOBAL TARGET SETTINGS
    # =========================================================================

    def show_target_settings(self):
        """Configure global target settings."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Target Configuration{Colors.RESET}")
            print(f"{Colors.DIM}  Set target and listener options before selecting modules{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Display current settings with term bank descriptions
            rhosts_info = get_setting_info('RHOSTS')
            lhost_info = get_setting_info('LHOST')
            lport_info = get_setting_info('LPORT')

            rhosts_val = self.global_settings['RHOSTS'] or f"{Colors.YELLOW}(not set){Colors.RESET}"
            lhost_val = self.global_settings['LHOST'] or f"{Colors.YELLOW}(not set){Colors.RESET}"
            lport_val = self.global_settings['LPORT'] or '4444'

            print(f"  {Colors.RED}[1]{Colors.RESET} RHOSTS  = {rhosts_val}")
            print(f"      {Colors.DIM}{self.wrap_text(rhosts_info['description'])}{Colors.RESET}")
            print()
            print(f"  {Colors.RED}[2]{Colors.RESET} LHOST   = {lhost_val}")
            print(f"      {Colors.DIM}{self.wrap_text(lhost_info['description'])}{Colors.RESET}")
            print()
            print(f"  {Colors.RED}[3]{Colors.RESET} LPORT   = {lport_val}")
            print(f"      {Colors.DIM}{self.wrap_text(lport_info['description'])}{Colors.RESET}")
            print()
            print(f"  {Colors.GREEN}[A]{Colors.RESET} Auto-detect LHOST")
            print(f"  {Colors.GREEN}[R]{Colors.RESET} Resolve hostname to IP")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == '1':
                    self._set_rhosts()
                elif choice == '2':
                    self._set_lhost()
                elif choice == '3':
                    self._set_lport()
                elif choice == 'a':
                    self._auto_detect_lhost()
                elif choice == 'r':
                    self._resolve_hostname()

            except (EOFError, KeyboardInterrupt):
                break

    def _set_rhosts(self):
        """Set RHOSTS with validation and domain resolution."""
        print()
        print(format_setting_help('RHOSTS'))
        print()

        current = self.global_settings['RHOSTS']
        prompt = f"Target [{current}]: " if current else "Target: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value and current:
            return  # Keep current

        if value:
            # Check if it's a hostname that needs resolution
            if not any(c.isdigit() for c in value.split('/')[0].split('-')[0]):
                # Looks like a hostname
                print(f"{Colors.CYAN}[*] Resolving {value}...{Colors.RESET}")
                ip = self.resolve_hostname(value)
                if ip:
                    print(f"{Colors.GREEN}[+] Resolved to {ip}{Colors.RESET}")
                    use_ip = input(f"{Colors.WHITE}Use resolved IP? (y/n) [{Colors.GREEN}y{Colors.WHITE}]: {Colors.RESET}").strip().lower()
                    if use_ip != 'n':
                        value = ip
                else:
                    print(f"{Colors.YELLOW}[!] Could not resolve hostname{Colors.RESET}")

            # Validate
            valid, msg = validate_setting_value('RHOSTS', value)
            if valid:
                self.global_settings['RHOSTS'] = value
                self.print_status(f"RHOSTS => {value}", "success")
            else:
                self.print_status(msg, "warning")
                self.global_settings['RHOSTS'] = value  # Set anyway, user might know better

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _set_lhost(self):
        """Set LHOST."""
        print()
        print(format_setting_help('LHOST'))
        print()

        current = self.global_settings['LHOST']
        auto_ip = self.get_local_ip()

        print(f"  {Colors.DIM}Detected local IP: {auto_ip}{Colors.RESET}")
        prompt = f"LHOST [{current or auto_ip}]: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value:
            value = current or auto_ip

        if value:
            self.global_settings['LHOST'] = value
            self.print_status(f"LHOST => {value}", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _set_lport(self):
        """Set LPORT."""
        print()
        print(format_setting_help('LPORT'))
        print()

        current = self.global_settings['LPORT'] or '4444'
        prompt = f"LPORT [{current}]: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if not value:
            value = current

        # Validate port
        try:
            port = int(value)
            if 1 <= port <= 65535:
                self.global_settings['LPORT'] = value
                self.print_status(f"LPORT => {value}", "success")
            else:
                self.print_status("Port must be between 1 and 65535", "warning")
        except ValueError:
            self.print_status("Invalid port number", "warning")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _auto_detect_lhost(self):
        """Auto-detect LHOST."""
        ip = self.get_local_ip()
        self.global_settings['LHOST'] = ip
        self.print_status(f"LHOST => {ip} (auto-detected)", "success")
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
                use_as_target = input(f"{Colors.WHITE}Use as RHOSTS? (y/n): {Colors.RESET}").strip().lower()
                if use_as_target == 'y':
                    self.global_settings['RHOSTS'] = ip
                    self.print_status(f"RHOSTS => {ip}", "success")
            else:
                self.print_status(f"Could not resolve {hostname}", "error")

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
            print(f"{Colors.DIM}  Browse Metasploit modules by category{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Show categories
            for i, (cat_id, cat_info) in enumerate(self.MODULE_CATEGORIES.items(), 1):
                color = cat_info['color']
                print(f"  {color}[{i}]{Colors.RESET} {cat_info['name']}")
                print(f"      {Colors.DIM}{cat_info['description']}{Colors.RESET}")

            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select category: {Colors.RESET}").strip()

                if choice == '0' or not choice:
                    break

                try:
                    idx = int(choice) - 1
                    cat_ids = list(self.MODULE_CATEGORIES.keys())
                    if 0 <= idx < len(cat_ids):
                        self._browse_category(cat_ids[idx])
                except ValueError:
                    pass

            except (EOFError, KeyboardInterrupt):
                break

    def _browse_category(self, category: str):
        """Browse modules in a category with pagination."""
        cat_info = self.MODULE_CATEGORIES.get(category)
        if not cat_info:
            return

        # Get modules from library that match this category
        modules = []
        for path, info in MSF_MODULES.items():
            for type_prefix in cat_info['types']:
                if path.startswith(type_prefix):
                    modules.append({'path': path, **info})
                    break

        # Also try to get from MSF if connected
        if self.msf.is_connected:
            for type_prefix in cat_info['types']:
                if '/' in type_prefix:
                    # e.g., auxiliary/scanner
                    mtype = type_prefix.split('/')[0]
                else:
                    mtype = type_prefix

                msf_modules = self.msf.list_modules(mtype)
                if msf_modules:
                    for mod_path in msf_modules[:50]:  # Limit to avoid overwhelming
                        if mod_path not in [m['path'] for m in modules]:
                            # Add basic info for modules not in library
                            modules.append({
                                'path': mod_path,
                                'name': mod_path.split('/')[-1].replace('_', ' ').title(),
                                'description': 'Module from Metasploit (use "info" for details)',
                                'tags': []
                            })

        if not modules:
            self.print_status(f"No modules found in {cat_info['name']}", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Pagination
        page_size = 20
        page = 0
        total_pages = (len(modules) + page_size - 1) // page_size

        while True:
            clear_screen()
            display_banner()

            print(f"{cat_info['color']}{Colors.BOLD}  {cat_info['name']}{Colors.RESET}")
            print(f"{Colors.DIM}  Page {page + 1} of {total_pages} ({len(modules)} modules){Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Display modules in 2 columns
            start_idx = page * page_size
            end_idx = min(start_idx + page_size, len(modules))
            page_modules = modules[start_idx:end_idx]

            # Split into two columns
            half = (len(page_modules) + 1) // 2
            col1 = page_modules[:half]
            col2 = page_modules[half:]

            for i in range(max(len(col1), len(col2))):
                line = ""

                # Column 1
                if i < len(col1):
                    num = start_idx + i + 1
                    mod = col1[i]
                    name = mod.get('name', mod['path'].split('/')[-1])
                    if len(name) > 22:
                        name = name[:19] + "..."
                    line += f"  {cat_info['color']}[{num:2}]{Colors.RESET} {name:22}"
                else:
                    line += " " * 30

                # Column 2
                if i < len(col2):
                    num = start_idx + half + i + 1
                    mod = col2[i]
                    name = mod.get('name', mod['path'].split('/')[-1])
                    if len(name) > 22:
                        name = name[:19] + "..."
                    line += f"  {cat_info['color']}[{num:2}]{Colors.RESET} {name:22}"

                print(line)

            print()
            print(f"  {Colors.DIM}[N]{Colors.RESET} Next page   {Colors.DIM}[P]{Colors.RESET} Previous   {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select module: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == 'n' and page < total_pages - 1:
                    page += 1
                elif choice == 'p' and page > 0:
                    page -= 1
                else:
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(modules):
                            self._show_module_details(modules[idx])
                    except ValueError:
                        pass

            except (EOFError, KeyboardInterrupt):
                break

    def _show_module_details(self, module_info: Dict):
        """Show module details and offer to use it."""
        clear_screen()
        display_banner()

        path = module_info['path']
        name = module_info.get('name', path.split('/')[-1])

        print(f"{Colors.RED}{Colors.BOLD}  {name}{Colors.RESET}")
        print(f"{Colors.DIM}  {path}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Try to get full help from library
        help_text = format_module_help(path)
        if help_text:
            print(help_text)
        else:
            # Fall back to basic info
            desc = module_info.get('description', 'No description available')
            print(f"  {Colors.CYAN}Description:{Colors.RESET}")
            # Word wrap description
            words = desc.split()
            line = "    "
            for word in words:
                if len(line) + len(word) > 70:
                    print(line)
                    line = "    "
                line += word + " "
            if line.strip():
                print(line)
            print()

            if 'author' in module_info:
                authors = module_info['author']
                if isinstance(authors, list):
                    authors = ', '.join(authors)
                print(f"  {Colors.CYAN}Author:{Colors.RESET} {authors}")

            if 'cve' in module_info and module_info['cve']:
                print(f"  {Colors.CYAN}CVE:{Colors.RESET} {module_info['cve']}")

            if 'reliability' in module_info:
                print(f"  {Colors.CYAN}Reliability:{Colors.RESET} {module_info['reliability']}")

            if 'notes' in module_info:
                print()
                print(f"  {Colors.YELLOW}Notes:{Colors.RESET} {module_info['notes']}")

        print()
        print(f"  {Colors.GREEN}[U]{Colors.RESET} Use this module")
        print(f"  {Colors.CYAN}[I]{Colors.RESET} Get info from MSF")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == 'u':
                self._select_module(path)
            elif choice == 'i':
                self._show_msf_info(path)

        except (EOFError, KeyboardInterrupt):
            pass

    def _select_module(self, module_path: str):
        """Select a module and prepare it for execution."""
        if not self.ensure_connected():
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Parse module type and name
        parts = module_path.split('/', 1)
        mtype = parts[0]
        mname = parts[1] if len(parts) > 1 else module_path

        self.print_status(f"Loading {module_path}...", "info")

        # Get module info and options from MSF
        info = self.msf.get_module_info(module_path)
        options = self.msf.get_module_options(module_path)

        if not options:
            self.print_status(f"Failed to load module: {self.msf.last_error}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        self.current_module = mname
        self.current_module_type = mtype
        self.module_options = {}

        # Set defaults from module
        for opt_name, opt_info in options.items():
            if isinstance(opt_info, dict):
                default = opt_info.get('default')
                if default is not None and default != '':
                    self.module_options[opt_name] = default

        # Apply global settings
        if self.global_settings['RHOSTS'] and 'RHOSTS' in options:
            self.module_options['RHOSTS'] = self.global_settings['RHOSTS']
        if self.global_settings['RHOSTS'] and 'RHOST' in options:
            self.module_options['RHOST'] = self.global_settings['RHOSTS']
        if self.global_settings['LHOST'] and 'LHOST' in options:
            self.module_options['LHOST'] = self.global_settings['LHOST']
        if self.global_settings['LPORT'] and 'LPORT' in options:
            self.module_options['LPORT'] = self.global_settings['LPORT']

        self.print_status(f"Module loaded: {mtype}/{mname}", "success")

        # Show what was auto-filled
        auto_filled = []
        if 'RHOSTS' in self.module_options or 'RHOST' in self.module_options:
            target = self.module_options.get('RHOSTS') or self.module_options.get('RHOST')
            if target:
                auto_filled.append(f"Target: {target}")
        if 'LHOST' in self.module_options and self.module_options['LHOST']:
            auto_filled.append(f"LHOST: {self.module_options['LHOST']}")

        if auto_filled:
            print(f"{Colors.DIM}  Auto-filled: {', '.join(auto_filled)}{Colors.RESET}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _show_msf_info(self, module_path: str):
        """Get and display module info from MSF."""
        if not self.ensure_connected():
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        self.print_status(f"Fetching info for {module_path}...", "info")

        info = self.msf.get_module_info(module_path)
        if not info:
            self.print_status(f"Failed to get info: {self.msf.last_error}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Module Info (from MSF){Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Display info fields
        fields = ['name', 'fullname', 'description', 'author', 'references', 'rank', 'platform', 'arch']
        for field in fields:
            if field in info and info[field]:
                value = info[field]
                if isinstance(value, list):
                    if field == 'references':
                        print(f"  {Colors.CYAN}{field}:{Colors.RESET}")
                        for ref in value[:5]:
                            if isinstance(ref, (list, tuple)) and len(ref) >= 2:
                                print(f"    - {ref[0]}: {ref[1]}")
                            else:
                                print(f"    - {ref}")
                    else:
                        value = ', '.join(str(v) for v in value[:5])
                        print(f"  {Colors.CYAN}{field}:{Colors.RESET} {value}")
                elif field == 'description':
                    print(f"  {Colors.CYAN}{field}:{Colors.RESET}")
                    # Word wrap
                    words = str(value).split()
                    line = "    "
                    for word in words:
                        if len(line) + len(word) > 70:
                            print(line)
                            line = "    "
                        line += word + " "
                    if line.strip():
                        print(line)
                else:
                    print(f"  {Colors.CYAN}{field}:{Colors.RESET} {value}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # SEARCH MODULES
    # =========================================================================

    def search_modules(self):
        """Search for MSF modules."""
        if not self.ensure_connected():
            return

        print(f"\n{Colors.BOLD}Search Metasploit Modules{Colors.RESET}")
        print(f"{Colors.DIM}Examples: 'smb', 'apache', 'ssh', 'cve:2021', 'eternalblue'{Colors.RESET}\n")

        query = input(f"{Colors.WHITE}Search: {Colors.RESET}").strip()
        if not query:
            return

        self.print_status(f"Searching for '{query}'...", "info")

        # Search both library and MSF
        library_results = library_search_modules(query)
        msf_results = self.msf.search_modules(query)

        # Combine results, preferring library entries
        combined = {}
        for mod in library_results:
            combined[mod['path']] = mod

        if msf_results:
            for mod in msf_results:
                if isinstance(mod, dict):
                    fullname = mod.get('fullname', '')
                    if fullname and fullname not in combined:
                        combined[fullname] = {
                            'path': fullname,
                            'name': mod.get('name', fullname.split('/')[-1]),
                            'description': 'Module from Metasploit',
                            'rank': mod.get('rank', '')
                        }
                elif isinstance(mod, str) and mod not in combined:
                    combined[mod] = {
                        'path': mod,
                        'name': mod.split('/')[-1],
                        'description': 'Module from Metasploit'
                    }

        results = list(combined.values())

        if not results:
            self.print_status("No modules found", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Display with pagination
        page_size = 15
        page = 0
        total_pages = (len(results) + page_size - 1) // page_size

        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.GREEN}{Colors.BOLD}  Search Results: '{query}'{Colors.RESET}")
            print(f"{Colors.DIM}  Page {page + 1} of {total_pages} ({len(results)} found){Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            start_idx = page * page_size
            end_idx = min(start_idx + page_size, len(results))
            page_results = results[start_idx:end_idx]

            for i, mod in enumerate(page_results, start_idx + 1):
                name = mod.get('name', mod['path'].split('/')[-1])
                path = mod['path']
                if len(name) > 30:
                    name = name[:27] + "..."
                print(f"  {Colors.RED}[{i:2}]{Colors.RESET} {name}")
                print(f"       {Colors.DIM}{path}{Colors.RESET}")

            print()
            print(f"  {Colors.DIM}[N]{Colors.RESET} Next   {Colors.DIM}[P]{Colors.RESET} Previous   {Colors.DIM}[0]{Colors.RESET} Back")
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
                        idx = int(choice) - 1
                        if 0 <= idx < len(results):
                            self._show_module_details(results[idx])
                    except ValueError:
                        pass

            except (EOFError, KeyboardInterrupt):
                break

    # =========================================================================
    # CURRENT MODULE MANAGEMENT
    # =========================================================================

    def show_current_module(self):
        """Show and configure current module options."""
        if not self.current_module:
            self.print_status("No module selected. Use Module Browser or Search first.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        if not self.ensure_connected():
            return

        full_path = f"{self.current_module_type}/{self.current_module}"
        options = self.msf.get_module_options(full_path)

        if not options:
            self.print_status(f"Failed to get options: {self.msf.last_error}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  {full_path}{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Separate required and optional
            required = []
            optional = []

            for name, info in options.items():
                if isinstance(info, dict):
                    is_required = info.get('required', False)
                    current_val = self.module_options.get(name, info.get('default', ''))
                    desc = info.get('desc', '')[:35]

                    entry = (name, current_val, desc, is_required)
                    if is_required:
                        required.append(entry)
                    else:
                        optional.append(entry)

            # Show required first
            if required:
                print(f"  {Colors.RED}Required Options:{Colors.RESET}")
                for i, (name, val, desc, _) in enumerate(required, 1):
                    val_display = str(val) if val else f"{Colors.YELLOW}(not set){Colors.RESET}"
                    print(f"    {Colors.CYAN}[{i}]{Colors.RESET} {name:18} = {val_display}")

                    # Get help from term bank
                    term_info = get_setting_info(name)
                    if term_info:
                        print(f"        {Colors.DIM}{self.wrap_text(term_info['description'], width=55, indent='        ')}{Colors.RESET}")
                    else:
                        print(f"        {Colors.DIM}{self.wrap_text(desc, width=55, indent='        ')}{Colors.RESET}")
                print()

            # Show optional (just first 8)
            if optional:
                print(f"  {Colors.DIM}Optional (first 8):{Colors.RESET}")
                for name, val, desc, _ in optional[:8]:
                    val_display = str(val)[:20] if val else ""
                    print(f"    {Colors.DIM}{name:18} = {val_display}{Colors.RESET}")
                print()

            print(f"  {Colors.GREEN}[S]{Colors.RESET} Set option")
            print(f"  {Colors.GREEN}[R]{Colors.RESET} Run module")
            print(f"  {Colors.CYAN}[A]{Colors.RESET} Show all options")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == '0' or not choice:
                    break
                elif choice == 's':
                    self.set_option()
                elif choice == 'r':
                    self.run_module()
                    break
                elif choice == 'a':
                    self._show_all_options(options)
                elif choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(required):
                        self._set_specific_option(required[idx][0], options)

            except (EOFError, KeyboardInterrupt):
                break

    def _show_all_options(self, options: Dict):
        """Show all module options."""
        clear_screen()
        display_banner()

        full_path = f"{self.current_module_type}/{self.current_module}"
        print(f"{Colors.BOLD}All Options for {full_path}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        for name, info in sorted(options.items()):
            if isinstance(info, dict):
                is_required = info.get('required', False)
                current_val = self.module_options.get(name, info.get('default', ''))
                desc = info.get('desc', '')

                req_marker = f"{Colors.RED}*{Colors.RESET}" if is_required else " "
                val_display = str(current_val)[:30] if current_val else f"{Colors.DIM}(empty){Colors.RESET}"

                print(f"  {req_marker} {Colors.CYAN}{name:20}{Colors.RESET} = {val_display}")
                if desc:
                    print(f"      {Colors.DIM}{self.wrap_text(desc, width=55, indent='      ')}{Colors.RESET}")

        print(f"\n{Colors.DIM}* = required{Colors.RESET}")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _set_specific_option(self, opt_name: str, options: Dict):
        """Set a specific option with term bank help."""
        print()

        # Show help from term bank or module
        term_info = get_setting_info(opt_name)
        if term_info:
            print(format_setting_help(opt_name))
        elif opt_name in options:
            opt_info = options[opt_name]
            desc = opt_info.get('desc', 'No description')
            print(f"  {Colors.CYAN}{opt_name}:{Colors.RESET} {desc}")
        print()

        current = self.module_options.get(opt_name, '')
        prompt = f"{opt_name} [{current}]: " if current else f"{opt_name}: "
        value = input(f"{Colors.WHITE}{prompt}{Colors.RESET}").strip()

        if value or not current:
            self.module_options[opt_name] = value
            self.print_status(f"{opt_name} => {value}", "success")
        else:
            self.print_status(f"{opt_name} unchanged", "info")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def set_option(self):
        """Set a module option."""
        if not self.current_module:
            self.print_status("No module selected.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}Set Option{Colors.RESET}")
        print(f"{Colors.DIM}Common: RHOSTS, RPORT, LHOST, LPORT, PAYLOAD{Colors.RESET}\n")

        opt_name = input(f"{Colors.WHITE}Option name: {Colors.RESET}").strip().upper()
        if not opt_name:
            return

        # Show help
        term_info = get_setting_info(opt_name)
        if term_info:
            print()
            print(format_setting_help(opt_name))
            print()

        current = self.module_options.get(opt_name, '')
        prompt = f"{Colors.WHITE}Value [{current}]: {Colors.RESET}" if current else f"{Colors.WHITE}Value: {Colors.RESET}"
        opt_value = input(prompt).strip()

        if opt_value or not current:
            self.module_options[opt_name] = opt_value
            self.print_status(f"{opt_name} => {opt_value}", "success")
        else:
            self.print_status(f"{opt_name} unchanged", "info")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def run_module(self):
        """Execute the current module."""
        if not self.current_module:
            self.print_status("No module selected.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        if not self.ensure_connected():
            return

        full_path = f"{self.current_module_type}/{self.current_module}"

        print(f"\n{Colors.BOLD}Run Module: {full_path}{Colors.RESET}")
        print(f"\n{Colors.CYAN}Options:{Colors.RESET}")
        for k, v in self.module_options.items():
            if v:
                print(f"  {k} = {v}")

        confirm = input(f"\n{Colors.YELLOW}Execute? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        self.print_status("Executing module...", "info")

        # Use job execution for exploits, console execution for auxiliary/scanners
        if self.current_module_type in ['exploit', 'post']:
            success, job_id, error = self.msf.execute_module_job(full_path, self.module_options)
            if success:
                self.print_status(f"Module running as Job {job_id}", "success")
            else:
                self.print_status(f"Execution failed: {error}", "error")
        else:
            result = self.msf.run_module(full_path, self.module_options, timeout=120)
            self.msf.print_result(result, verbose=True)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # SESSIONS AND JOBS
    # =========================================================================

    def show_sessions(self):
        """Show active sessions."""
        if not self.ensure_connected():
            return

        sessions = self.msf.list_sessions()

        print(f"\n{Colors.BOLD}Active Sessions{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        if not sessions:
            self.print_status("No active sessions", "info")
        else:
            for sid, info in sessions.items():
                if isinstance(info, dict):
                    stype = info.get('type', 'shell')
                    target = info.get('target_host', 'unknown')
                    user = info.get('username', '')
                    via = info.get('via_exploit', '')[:30]
                    print(f"  {Colors.GREEN}[{sid}]{Colors.RESET} {stype} @ {target}")
                    if user:
                        print(f"      {Colors.DIM}User: {user}{Colors.RESET}")
                    if via:
                        print(f"      {Colors.DIM}Via: {via}{Colors.RESET}")
                else:
                    print(f"  {Colors.GREEN}[{sid}]{Colors.RESET} {info}")

            print()
            sid = input(f"{Colors.WHITE}Interact with session (or Enter to skip): {Colors.RESET}").strip()
            if sid and sid in sessions:
                self.interact_session(sid)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def interact_session(self, session_id: str):
        """Interact with a session."""
        print(f"\n{Colors.GREEN}Interacting with session {session_id}{Colors.RESET}")
        print(f"{Colors.DIM}Type 'exit' to return to menu{Colors.RESET}\n")

        while True:
            try:
                cmd = input(f"{Colors.RED}session({session_id})>{Colors.RESET} ").strip()

                if cmd.lower() == 'exit':
                    break

                if not cmd:
                    continue

                self.msf.session_write(session_id, cmd)
                time.sleep(1)
                success, output = self.msf.session_read(session_id)
                if success and output:
                    print(output)

            except (EOFError, KeyboardInterrupt):
                print()
                break
            except Exception as e:
                self.print_status(f"Session error: {e}", "error")
                break

    def show_jobs(self):
        """Show running jobs."""
        if not self.ensure_connected():
            return

        jobs = self.msf.list_jobs()

        print(f"\n{Colors.BOLD}Running Jobs{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        if not jobs:
            self.print_status("No running jobs", "info")
        else:
            for jid, jname in jobs.items():
                print(f"  {Colors.YELLOW}[{jid}]{Colors.RESET} {jname}")

            print()
            jid = input(f"{Colors.WHITE}Kill job (or Enter to skip): {Colors.RESET}").strip()
            if jid and jid in jobs:
                if self.msf.stop_job(jid):
                    self.print_status(f"Job {jid} stopped", "success")
                else:
                    self.print_status(f"Failed to stop job {jid}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # CONSOLE AND QUICK SCAN
    # =========================================================================

    def console_command(self):
        """Run console commands directly."""
        if not self.ensure_connected():
            return

        print(f"\n{Colors.BOLD}MSF Console{Colors.RESET}")
        print(f"{Colors.DIM}Enter commands directly (type 'exit' to return){Colors.RESET}\n")

        while True:
            try:
                cmd = input(f"{Colors.RED}msf>{Colors.RESET} ").strip()

                if cmd.lower() == 'exit':
                    break

                if not cmd:
                    continue

                success, output = self.msf.run_console_command(cmd)
                if output:
                    print(output)

            except (EOFError, KeyboardInterrupt):
                print()
                break

    def quick_scan(self):
        """Quick scanner with pre-set target."""
        if not self.ensure_connected():
            return

        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Quick Scan{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Show current target
        if self.global_settings['RHOSTS']:
            print(f"  {Colors.GREEN}Target: {self.global_settings['RHOSTS']}{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}Target: Not set (will prompt){Colors.RESET}")
        print()

        scanners = [
            ("auxiliary/scanner/portscan/tcp", "TCP Port Scanner", "Scan for open TCP ports"),
            ("auxiliary/scanner/smb/smb_version", "SMB Version", "Identify Windows/SMB version"),
            ("auxiliary/scanner/smb/smb_ms17_010", "MS17-010 Check", "Check for EternalBlue vulnerability"),
            ("auxiliary/scanner/ssh/ssh_version", "SSH Version", "Identify SSH server version"),
            ("auxiliary/scanner/http/http_version", "HTTP Version", "Identify web server version"),
            ("auxiliary/scanner/ftp/ftp_version", "FTP Version", "Identify FTP server version"),
        ]

        for i, (mod, name, desc) in enumerate(scanners, 1):
            print(f"  {Colors.RED}[{i}]{Colors.RESET} {name}")
            print(f"      {Colors.DIM}{desc}{Colors.RESET}")

        print(f"\n  {Colors.DIM}[0]{Colors.RESET} Cancel\n")

        choice = input(f"{Colors.WHITE}  Select scanner: {Colors.RESET}").strip()

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(scanners):
                scanner_mod, scanner_name, _ = scanners[idx]

                # Get target
                target = self.global_settings['RHOSTS']
                if not target:
                    target = input(f"{Colors.WHITE}Target (IP/range): {Colors.RESET}").strip()

                if not target:
                    return

                options = {'RHOSTS': target, 'THREADS': '10'}

                print(f"\n{Colors.CYAN}Running {scanner_name} against {target}...{Colors.RESET}")

                result = self.msf.run_scanner(scanner_mod, target, options=options, timeout=120)
                self.msf.print_result(result, verbose=False)

        except (ValueError, IndexError):
            pass
        except Exception as e:
            self.print_status(f"Scanner failed: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # EXPLOIT SUGGESTER
    # =========================================================================

    def exploit_suggester(self):
        """Suggest exploits based on vulnerability scan results."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Exploit Suggester{Colors.RESET}")
        print(f"{Colors.DIM}  Suggest attack paths based on detected vulnerabilities{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        print(f"  {Colors.RED}[1]{Colors.RESET} Load vuln_correlator JSON")
        print(f"  {Colors.RED}[2]{Colors.RESET} Run fresh scan")
        print(f"  {Colors.RED}[3]{Colors.RESET} Manual service list")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

        services = []
        cves = []

        if choice == "1":
            # Load from vuln correlator JSON
            results_dir = Path("results")
            json_files = sorted(results_dir.glob("vuln_correlator_*.json")) if results_dir.exists() else []
            if not json_files:
                self.print_status("No vuln correlator results found. Run OSINT > Vulnerability Correlator first.", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

            print(f"\n{Colors.CYAN}Available vuln reports:{Colors.RESET}")
            for i, f in enumerate(json_files, 1):
                print(f"  {Colors.RED}[{i}]{Colors.RESET} {f.name}")

            sel = input(f"\n{Colors.WHITE}Select: {Colors.RESET}").strip()
            try:
                idx = int(sel) - 1
                with open(json_files[idx], 'r') as f:
                    data = json.load(f)

                for corr in data.get('correlations', []):
                    svc = corr.get('service', {})
                    services.append(svc)
                    for cve in corr.get('cves', []):
                        cves.append(cve)
            except (ValueError, IndexError, json.JSONDecodeError) as e:
                self.print_status(f"Error loading file: {e}", "error")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

        elif choice == "2":
            target = self.global_settings.get('RHOSTS', '') or input(f"{Colors.WHITE}Target: {Colors.RESET}").strip()
            if not target:
                return

            self.print_status(f"Running nmap -sV on {target}...", "info")
            import subprocess
            try:
                result = subprocess.run(f"nmap -sV -T4 {target}", shell=True, capture_output=True, text=True, timeout=300)
                if result.returncode == 0:
                    port_re = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)')
                    for line in result.stdout.split('\n'):
                        m = port_re.match(line.strip())
                        if m:
                            parts = m.group(4).strip().split()
                            services.append({
                                'port': int(m.group(1)),
                                'service': parts[0] if parts else m.group(3),
                                'version': parts[1] if len(parts) > 1 else '',
                                'host': target,
                            })
            except Exception as e:
                self.print_status(f"Scan failed: {e}", "error")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

        elif choice == "3":
            print(f"\n{Colors.DIM}Enter services (format: port service version), empty line to finish:{Colors.RESET}")
            while True:
                line = input(f"{Colors.WHITE}  > {Colors.RESET}").strip()
                if not line:
                    break
                parts = line.split()
                if len(parts) >= 2:
                    services.append({
                        'port': int(parts[0]) if parts[0].isdigit() else 0,
                        'service': parts[1],
                        'version': parts[2] if len(parts) > 2 else '',
                    })
        else:
            return

        if not services:
            self.print_status("No services to analyze", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Try LLM-based suggestion first
        suggestions = []
        try:
            from core.llm import get_llm
            llm = get_llm()
            if llm.is_loaded:
                self.print_status("Using LLM for exploit analysis...", "info")
                prompt = self._build_exploit_prompt(services, cves)

                print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
                print(f"{Colors.BOLD}Exploit Analysis{Colors.RESET}")
                print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

                # Stream response
                full_response = ""
                for token in llm.generate(prompt, stream=True, max_tokens=1024):
                    print(token, end='', flush=True)
                    full_response += token
                print()

                suggestions = self._parse_exploit_suggestions(full_response)
            else:
                raise Exception("LLM not loaded")
        except Exception:
            # Fallback: direct CVE-to-MSF mapping
            self.print_status("Using direct CVE-to-MSF mapping (no LLM)...", "info")
            suggestions = self._fallback_exploit_suggestions(services, cves)

        # Display suggestions
        if suggestions:
            print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
            print(f"{Colors.BOLD}Suggested Exploits{Colors.RESET}")
            print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

            for i, s in enumerate(suggestions, 1):
                print(f"  {Colors.RED}[{i}]{Colors.RESET} {s.get('module', 'N/A')}")
                print(f"      Target: {s.get('target', 'N/A')}")
                if s.get('cve'):
                    print(f"      CVE: {s['cve']}")
                if s.get('reasoning'):
                    print(f"      {Colors.DIM}{s['reasoning']}{Colors.RESET}")
                print()

            self._offer_autoload(suggestions)
        else:
            self.print_status("No matching exploits found in module library", "info")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _build_exploit_prompt(self, services: list, cves: list) -> str:
        """Build LLM prompt for exploit suggestion."""
        # Gather available MSF modules
        relevant_modules = []
        for svc in services:
            svc_name = svc.get('service', '').lower()
            results = library_search_modules(svc_name, max_results=5)
            for mod in results:
                if mod['path'] not in [m['path'] for m in relevant_modules]:
                    relevant_modules.append(mod)

        # Also search by CVE
        for cve in cves[:10]:
            cve_id = cve.get('cve_id', '')
            if cve_id:
                results = library_search_modules(cve_id, max_results=3)
                for mod in results:
                    if mod['path'] not in [m['path'] for m in relevant_modules]:
                        relevant_modules.append(mod)

        prompt = "You are a penetration testing assistant. Based on the following target information, suggest the top 5 attack paths.\n\n"
        prompt += "TARGET SERVICES:\n"
        for svc in services:
            prompt += f"  - Port {svc.get('port', '?')}: {svc.get('service', '?')} {svc.get('version', '')}\n"

        if cves:
            prompt += "\nKNOWN VULNERABILITIES:\n"
            for cve in cves[:15]:
                prompt += f"  - {cve.get('cve_id', '?')} ({cve.get('severity', '?')} {cve.get('cvss_score', '?')}): {(cve.get('description', '') or '')[:100]}\n"

        if relevant_modules:
            prompt += "\nAVAILABLE METASPLOIT MODULES:\n"
            for mod in relevant_modules[:15]:
                prompt += f"  - {mod['path']}: {mod.get('name', '')}\n"

        prompt += "\nFor each suggestion, provide: module path, target service, CVE (if applicable), and reasoning.\n"
        prompt += "Format each as: RANK. MODULE_PATH | TARGET | CVE | REASONING\n"

        return prompt

    def _parse_exploit_suggestions(self, response: str) -> list:
        """Parse exploit suggestions from LLM response."""
        suggestions = []
        lines = response.split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Try to parse "N. module | target | cve | reasoning" format
            if '|' in line and ('/' in line or 'exploit' in line.lower() or 'auxiliary' in line.lower()):
                parts = [p.strip() for p in line.split('|')]
                # Remove leading number
                first = re.sub(r'^\d+\.\s*', '', parts[0])

                suggestion = {
                    'module': first,
                    'target': parts[1] if len(parts) > 1 else '',
                    'cve': parts[2] if len(parts) > 2 else '',
                    'reasoning': parts[3] if len(parts) > 3 else '',
                }
                suggestions.append(suggestion)

        return suggestions[:5]

    def _fallback_exploit_suggestions(self, services: list, cves: list) -> list:
        """Fallback exploit suggestion using direct CVE-to-MSF mapping."""
        suggestions = []
        seen_modules = set()

        # Search by CVE
        for cve in cves[:20]:
            cve_id = cve.get('cve_id', '')
            if not cve_id:
                continue
            results = library_search_modules(cve_id, max_results=3)
            for mod in results:
                if mod['path'] not in seen_modules:
                    seen_modules.add(mod['path'])
                    suggestions.append({
                        'module': mod['path'],
                        'target': mod.get('name', ''),
                        'cve': cve_id,
                        'reasoning': f"CVSS {cve.get('cvss_score', '?')} - Direct CVE match",
                    })

        # Search by service name
        for svc in services:
            svc_name = svc.get('service', '').lower()
            if not svc_name:
                continue
            results = library_search_modules(svc_name, max_results=3)
            for mod in results:
                if mod['path'] not in seen_modules and mod['path'].startswith('exploit'):
                    seen_modules.add(mod['path'])
                    suggestions.append({
                        'module': mod['path'],
                        'target': f"{svc_name} on port {svc.get('port', '?')}",
                        'cve': ', '.join(mod.get('cve', []) or []),
                        'reasoning': f"Service match: {svc_name} {svc.get('version', '')}",
                    })

        return suggestions[:5]

    def _offer_autoload(self, suggestions: list):
        """Offer to auto-load a suggested module."""
        choice = input(f"\n{Colors.WHITE}Load a module? (enter number or 0 to skip): {Colors.RESET}").strip()
        if not choice or choice == '0':
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(suggestions):
                module_path = suggestions[idx].get('module', '')
                if module_path and '/' in module_path:
                    self.print_status(f"Loading {module_path}...", "info")
                    self._select_module(module_path)
        except (ValueError, IndexError):
            pass

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    def run(self):
        """Main loop."""
        while True:
            self.show_main_menu()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    self.show_target_settings()
                elif choice == "2":
                    self.show_module_browser()
                elif choice == "3":
                    self.search_modules()
                elif choice == "4":
                    self.show_current_module()
                elif choice == "5":
                    self.run_module()
                elif choice == "6":
                    self.show_sessions()
                elif choice == "7":
                    self.show_jobs()
                elif choice == "8":
                    self.console_command()
                elif choice == "9":
                    self.quick_scan()
                elif choice.lower() == "e":
                    self.exploit_suggester()

            except (EOFError, KeyboardInterrupt):
                print()
                break


def run():
    """Module entry point."""
    menu = MSFMenu()
    menu.run()


if __name__ == "__main__":
    run()
