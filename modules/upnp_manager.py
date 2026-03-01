"""
AUTARCH UPnP Port Manager Module
Manage UPnP port forwarding and cron refresh jobs

Requires: miniupnpc (upnpc command)
"""

import sys
from pathlib import Path

# Module metadata
DESCRIPTION = "UPnP port forwarding manager"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen
from core.config import get_config
from core.upnp import get_upnp_manager


def print_status(message: str, status: str = "info"):
    colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
    symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
    print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")


def show_menu(upnp):
    """Display the UPnP manager menu."""
    cron = upnp.get_cron_status()
    cron_str = f"every {cron['interval']}" if cron['installed'] else "not installed"
    internal_ip = upnp._get_internal_ip()

    print(f"\n{Colors.BOLD}{Colors.BLUE}UPnP Port Manager{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")
    print(f"  Internal IP: {Colors.CYAN}{internal_ip}{Colors.RESET}")
    print(f"  Cron:        {Colors.GREEN if cron['installed'] else Colors.YELLOW}{cron_str}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")
    print(f"  {Colors.BLUE}[1]{Colors.RESET} Show Current Mappings")
    print(f"  {Colors.BLUE}[2]{Colors.RESET} Add Port Mapping")
    print(f"  {Colors.BLUE}[3]{Colors.RESET} Remove Port Mapping")
    print(f"  {Colors.BLUE}[4]{Colors.RESET} Refresh All Mappings")
    print(f"  {Colors.BLUE}[5]{Colors.RESET} Show External IP")
    print(f"  {Colors.BLUE}[6]{Colors.RESET} Cron Job Settings")
    print(f"  {Colors.BLUE}[7]{Colors.RESET} Edit Internal IP")
    print(f"  {Colors.BLUE}[8]{Colors.RESET} Edit Port Mappings Config")
    print(f"  {Colors.RED}[0]{Colors.RESET} Back")
    print()


def show_mappings(upnp):
    """Show current UPnP port mappings."""
    print(f"\n{Colors.BOLD}Current UPnP Mappings{Colors.RESET}")
    success, output = upnp.list_mappings()
    if success:
        print(output)
    else:
        print_status(output, "error")
    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")


def add_mapping(upnp):
    """Add a new port mapping."""
    print(f"\n{Colors.BOLD}Add Port Mapping{Colors.RESET}")
    try:
        internal_ip = upnp._get_internal_ip()
        ext_port = input(f"  External port: ").strip()
        if not ext_port:
            return
        ext_port = int(ext_port)

        int_port_str = input(f"  Internal port [{ext_port}]: ").strip()
        int_port = int(int_port_str) if int_port_str else ext_port

        proto = input(f"  Protocol (TCP/UDP) [TCP]: ").strip().upper()
        if not proto:
            proto = 'TCP'
        if proto not in ('TCP', 'UDP'):
            print_status("Invalid protocol", "error")
            return

        desc = input(f"  Description [AUTARCH]: ").strip()
        if not desc:
            desc = 'AUTARCH'

        success, output = upnp.add_mapping(internal_ip, int_port, ext_port, proto, desc)
        if success:
            print_status(f"Mapping added: {ext_port}/{proto} -> {internal_ip}:{int_port}", "success")
            # Offer to save to config
            save = input(f"\n  Save to config? (y/n) [y]: ").strip().lower()
            if save != 'n':
                mappings = upnp.load_mappings_from_config()
                # Check if already exists
                exists = any(m['port'] == ext_port and m['protocol'] == proto for m in mappings)
                if not exists:
                    mappings.append({'port': ext_port, 'protocol': proto})
                    upnp.save_mappings_to_config(mappings)
                    print_status("Saved to config", "success")
                else:
                    print_status("Already in config", "info")
        else:
            print_status(f"Failed: {output}", "error")
    except ValueError:
        print_status("Invalid port number", "error")
    except KeyboardInterrupt:
        print()


def remove_mapping(upnp):
    """Remove a port mapping."""
    print(f"\n{Colors.BOLD}Remove Port Mapping{Colors.RESET}")
    try:
        ext_port = input(f"  External port: ").strip()
        if not ext_port:
            return
        ext_port = int(ext_port)

        proto = input(f"  Protocol (TCP/UDP) [TCP]: ").strip().upper()
        if not proto:
            proto = 'TCP'

        success, output = upnp.remove_mapping(ext_port, proto)
        if success:
            print_status(f"Mapping removed: {ext_port}/{proto}", "success")
            # Offer to remove from config
            remove = input(f"\n  Remove from config? (y/n) [y]: ").strip().lower()
            if remove != 'n':
                mappings = upnp.load_mappings_from_config()
                mappings = [m for m in mappings if not (m['port'] == ext_port and m['protocol'] == proto)]
                upnp.save_mappings_to_config(mappings)
                print_status("Removed from config", "success")
        else:
            print_status(f"Failed: {output}", "error")
    except ValueError:
        print_status("Invalid port number", "error")
    except KeyboardInterrupt:
        print()


def refresh_all(upnp):
    """Refresh all configured mappings."""
    mappings = upnp.load_mappings_from_config()
    if not mappings:
        print_status("No mappings configured. Use option [8] to edit.", "warning")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        return

    print(f"\n{Colors.BOLD}Refreshing {len(mappings)} mapping(s)...{Colors.RESET}")
    results = upnp.refresh_all()
    for r in results:
        if r['success']:
            print_status(f"{r['port']}/{r['protocol']}: OK", "success")
        else:
            print_status(f"{r['port']}/{r['protocol']}: {r['message']}", "error")
    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")


def show_external_ip(upnp):
    """Show external IP."""
    success, ip = upnp.get_external_ip()
    if success:
        print(f"\n  {Colors.BOLD}External IP:{Colors.RESET} {Colors.GREEN}{ip}{Colors.RESET}")
    else:
        print_status(f"Failed: {ip}", "error")
    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")


def cron_settings(upnp):
    """Manage cron job settings."""
    cron = upnp.get_cron_status()

    print(f"\n{Colors.BOLD}Cron Job Settings{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")

    if cron['installed']:
        print(f"  Status:   {Colors.GREEN}Installed{Colors.RESET}")
        print(f"  Interval: every {cron['interval']}")
        print(f"  Entry:    {Colors.DIM}{cron['line']}{Colors.RESET}")
        print()
        print(f"  {Colors.BLUE}[1]{Colors.RESET} Change interval")
        print(f"  {Colors.RED}[2]{Colors.RESET} Uninstall cron job")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
    else:
        print(f"  Status: {Colors.YELLOW}Not installed{Colors.RESET}")
        print()
        print(f"  {Colors.BLUE}[1]{Colors.RESET} Install cron job")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")

    print()
    try:
        choice = input(f"  {Colors.BOLD}>{Colors.RESET} ").strip()

        if choice == '0':
            return

        if cron['installed']:
            if choice == '1':
                hours = input(f"  Refresh interval (hours) [12]: ").strip()
                hours = int(hours) if hours else 12
                if hours < 1 or hours > 24:
                    print_status("Interval must be 1-24 hours", "error")
                    return
                success, msg = upnp.install_cron(hours)
                print_status(msg, "success" if success else "error")
            elif choice == '2':
                success, msg = upnp.uninstall_cron()
                print_status(msg, "success" if success else "error")
        else:
            if choice == '1':
                hours = input(f"  Refresh interval (hours) [12]: ").strip()
                hours = int(hours) if hours else 12
                if hours < 1 or hours > 24:
                    print_status("Interval must be 1-24 hours", "error")
                    return
                success, msg = upnp.install_cron(hours)
                print_status(msg, "success" if success else "error")
    except (ValueError, KeyboardInterrupt):
        print()


def edit_internal_ip(upnp):
    """Edit the internal IP address."""
    config = get_config()
    current = upnp._get_internal_ip()
    print(f"\n  Current internal IP: {Colors.CYAN}{current}{Colors.RESET}")
    try:
        new_ip = input(f"  New internal IP [{current}]: ").strip()
        if new_ip and new_ip != current:
            config.set('upnp', 'internal_ip', new_ip)
            config.save()
            print_status(f"Internal IP set to {new_ip}", "success")
        elif not new_ip:
            print_status("Unchanged", "info")
    except KeyboardInterrupt:
        print()


def edit_mappings_config(upnp):
    """Edit configured port mappings."""
    mappings = upnp.load_mappings_from_config()

    print(f"\n{Colors.BOLD}Configured Port Mappings{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")

    if mappings:
        for i, m in enumerate(mappings, 1):
            print(f"  {Colors.BLUE}[{i}]{Colors.RESET} {m['port']}/{m['protocol']}")
    else:
        print(f"  {Colors.DIM}(none configured){Colors.RESET}")

    print()
    print(f"  {Colors.GREEN}[a]{Colors.RESET} Add mapping to config")
    if mappings:
        print(f"  {Colors.RED}[d]{Colors.RESET} Delete mapping from config")
    print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
    print()

    try:
        choice = input(f"  {Colors.BOLD}>{Colors.RESET} ").strip().lower()

        if choice == '0':
            return
        elif choice == 'a':
            port = input(f"  Port: ").strip()
            if not port:
                return
            port = int(port)
            proto = input(f"  Protocol (TCP/UDP) [TCP]: ").strip().upper()
            if not proto:
                proto = 'TCP'
            if proto not in ('TCP', 'UDP'):
                print_status("Invalid protocol", "error")
                return
            exists = any(m['port'] == port and m['protocol'] == proto for m in mappings)
            if exists:
                print_status("Already in config", "info")
                return
            mappings.append({'port': port, 'protocol': proto})
            upnp.save_mappings_to_config(mappings)
            print_status(f"Added {port}/{proto}", "success")
        elif choice == 'd' and mappings:
            idx = input(f"  Number to delete: ").strip()
            idx = int(idx) - 1
            if 0 <= idx < len(mappings):
                removed = mappings.pop(idx)
                upnp.save_mappings_to_config(mappings)
                print_status(f"Removed {removed['port']}/{removed['protocol']}", "success")
            else:
                print_status("Invalid selection", "error")
    except (ValueError, KeyboardInterrupt):
        print()


def run():
    """Main entry point for the UPnP manager module."""
    config = get_config()
    upnp = get_upnp_manager(config)

    if not upnp.is_available():
        print_status("upnpc (miniupnpc) is not installed!", "error")
        print(f"  {Colors.DIM}Install with: sudo apt install miniupnpc{Colors.RESET}")
        input(f"\n{Colors.DIM}Press Enter to go back...{Colors.RESET}")
        return

    while True:
        try:
            clear_screen()
            show_menu(upnp)
            choice = input(f"  {Colors.BOLD}>{Colors.RESET} ").strip()

            if choice == '0':
                break
            elif choice == '1':
                show_mappings(upnp)
            elif choice == '2':
                add_mapping(upnp)
            elif choice == '3':
                remove_mapping(upnp)
            elif choice == '4':
                refresh_all(upnp)
            elif choice == '5':
                show_external_ip(upnp)
            elif choice == '6':
                cron_settings(upnp)
            elif choice == '7':
                edit_internal_ip(upnp)
            elif choice == '8':
                edit_mappings_config(upnp)
        except KeyboardInterrupt:
            break
