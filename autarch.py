#!/usr/bin/env python3
"""
AUTARCH - Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking
By darkHal Security Group and Setec Security Labs

Main entry point for the AUTARCH framework.
"""

import sys
import shutil
import argparse
import importlib.util
from pathlib import Path
from textwrap import dedent

# Version info
VERSION = "2.4"
BUILD_DATE = "2026-03-20"

# Ensure the framework directory is in the path
FRAMEWORK_DIR = Path(__file__).parent
sys.path.insert(0, str(FRAMEWORK_DIR))

# ── Package resolution ────────────────────────────────────────────────────────
# AUTARCH needs root for raw sockets, iptables, hardware, etc., but pip packages
# live in user space. Solution priority:
#   1. Project venv (autarch/venv/) — best: works as any user, no conflicts
#   2. Owner's ~/.local site-packages — fallback: needs path priority fix
#
# If running from the venv python (venv/bin/python), everything just works.
# If running from system python via sudo, we fix the path so user packages win.

_venv_dir = FRAMEWORK_DIR / 'venv'
_running_in_venv = (
    hasattr(sys, 'prefix') and sys.prefix != sys.base_prefix  # standard venv check
) or (_venv_dir / 'bin' / 'python').exists() and str(_venv_dir) in sys.executable

if not _running_in_venv:
    # Not in venv — add user site-packages before system dist-packages
    try:
        import pwd as _pwd
        _owner_uid = FRAMEWORK_DIR.stat().st_uid
        _user_site = (
            Path(_pwd.getpwuid(_owner_uid).pw_dir) / '.local' / 'lib'
            / f'python{sys.version_info.major}.{sys.version_info.minor}' / 'site-packages'
        )
        if _user_site.is_dir() and str(_user_site) not in sys.path:
            sys.path.insert(1, str(_user_site))
            # Evict stale system modules that conflict with newer user versions
            for _mod_name in ('typing_extensions',):
                if _mod_name in sys.modules:
                    _mod = sys.modules[_mod_name]
                    if hasattr(_mod, '__file__') and '/usr/lib/' in str(getattr(_mod, '__file__', '')):
                        del sys.modules[_mod_name]
    except Exception:
        pass

from core.banner import Colors, clear_screen, display_banner

# Install the subprocess.run hook so ALL sudo calls auto-route through the daemon
from core.daemon import install_subprocess_hook
install_subprocess_hook()


def get_epilog():
    """Get detailed help epilog text."""
    return f"""{Colors.BOLD}CATEGORIES:{Colors.RESET}
  defense     Defensive security tools (hardening, audits, monitoring)
  offense     Penetration testing (Metasploit integration, exploits)
  counter     Counter-intelligence (threat hunting, anomaly detection)
  analyze     Forensics & analysis (file analysis, strings, hashes)
  osint       Open source intelligence (email, username, domain lookup)
  simulate    Attack simulation (port scan, payloads, stress test)

{Colors.BOLD}MODULES:{Colors.RESET}
  chat        Interactive LLM chat interface
  agent       Autonomous AI agent with tool access
  msf         Metasploit Framework interface
  defender    System hardening and security checks
  counter     Threat detection and hunting
  analyze     File forensics and analysis
  recon       OSINT reconnaissance (email, username, phone, domain)
  adultscan   Adult site username scanner
  simulate    Attack simulation tools

{Colors.BOLD}EXAMPLES:{Colors.RESET}
  {Colors.DIM}# Start interactive menu{Colors.RESET}
  python autarch.py

  {Colors.DIM}# Run a specific module{Colors.RESET}
  python autarch.py -m chat
  python autarch.py -m adultscan
  python autarch.py --module recon

  {Colors.DIM}# List all available modules{Colors.RESET}
  python autarch.py -l
  python autarch.py --list

  {Colors.DIM}# Quick OSINT username scan{Colors.RESET}
  python autarch.py osint <username>

  {Colors.DIM}# Show current configuration{Colors.RESET}
  python autarch.py --show-config

  {Colors.DIM}# Re-run setup wizard{Colors.RESET}
  python autarch.py --setup

  {Colors.DIM}# Skip setup (run without LLM){Colors.RESET}
  python autarch.py --skip-setup

  {Colors.DIM}# Use alternate config file{Colors.RESET}
  python autarch.py -c /path/to/config.conf

{Colors.BOLD}FILES:{Colors.RESET}
  autarch_settings.conf    Main configuration file
  user_manual.md           Comprehensive user manual
  custom_adultsites.json   Custom adult sites storage
  custom_sites.inf         Bulk import domains file
  GUIDE.md                 Quick reference guide
  DEVLOG.md                Development log

{Colors.BOLD}CONFIGURATION:{Colors.RESET}
  LLM settings:
    model_path      Path to GGUF model file
    n_ctx           Context window size (default: 4096)
    n_threads       CPU threads (default: 4)
    n_gpu_layers    GPU layers to offload (default: 0)
    temperature     Sampling temperature (default: 0.7)

  MSF settings:
    host            Metasploit RPC host (default: 127.0.0.1)
    port            Metasploit RPC port (default: 55553)
    ssl             Use SSL connection (default: true)
    autoconnect     Auto-start msfrpcd on launch (default: true)

{Colors.BOLD}METASPLOIT AUTO-CONNECT:{Colors.RESET}
  On startup, AUTARCH will:
    1. Scan for existing msfrpcd server
    2. If found: stop it and prompt for new credentials
    3. Start msfrpcd with sudo (for raw socket module support)
    4. Connect to the server

  To skip autoconnect:  python autarch.py --no-msf
  Quick connect:        python autarch.py --msf-user msf --msf-pass secret
  Without sudo:         python autarch.py --msf-no-sudo

{Colors.BOLD}MORE INFO:{Colors.RESET}
  Documentation:  See GUIDE.md for full documentation
  Development:    See DEVLOG.md for development history

{Colors.DIM}Project AUTARCH - By darkHal Security Group and Setec Security Labs{Colors.RESET}
"""


def create_parser():
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog='autarch',
        description=f'{Colors.BOLD}AUTARCH{Colors.RESET} - Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking',
        epilog=get_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # We'll add custom help
    )

    # Help and version
    parser.add_argument(
        '-h', '--help',
        action='store_true',
        help='Show this help message and exit'
    )
    parser.add_argument(
        '-v', '--version',
        action='store_true',
        help='Show version information and exit'
    )

    # Configuration
    parser.add_argument(
        '-c', '--config',
        metavar='FILE',
        help='Use alternate configuration file'
    )
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='Display current configuration and exit'
    )
    parser.add_argument(
        '--manual',
        action='store_true',
        help='Show the user manual'
    )
    parser.add_argument(
        '--setup',
        action='store_true',
        help='Run the setup wizard'
    )
    parser.add_argument(
        '--skip-setup',
        action='store_true',
        help='Skip first-time setup (run without LLM)'
    )

    # Module execution
    parser.add_argument(
        '-m', '--module',
        metavar='NAME',
        help='Run a specific module directly'
    )
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List all available modules'
    )
    parser.add_argument(
        '--list-category',
        metavar='CAT',
        choices=['defense', 'offense', 'counter', 'analyze', 'osint', 'simulate', 'core'],
        help='List modules in a specific category'
    )

    # Display options
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Suppress the ASCII banner'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Minimal output mode'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    # Web UI options
    parser.add_argument(
        '--web',
        action='store_true',
        help='Start the web dashboard'
    )
    parser.add_argument(
        '--web-port',
        type=int,
        metavar='PORT',
        help='Web dashboard port (default: 8181)'
    )
    parser.add_argument(
        '--no-tray',
        action='store_true',
        help='Disable system tray icon (run web server in foreground only)'
    )

    # Web service management
    parser.add_argument(
        '--service',
        metavar='ACTION',
        choices=['start', 'stop', 'restart', 'status', 'enable', 'disable', 'install'],
        help='Manage AUTARCH web service (start|stop|restart|status|enable|disable|install)'
    )

    # MCP server
    parser.add_argument(
        '--mcp',
        choices=['stdio', 'sse'],
        nargs='?',
        const='stdio',
        metavar='MODE',
        help='Start MCP server (stdio for Claude Desktop/Code, sse for web clients)'
    )
    parser.add_argument(
        '--mcp-port',
        type=int,
        default=8081,
        metavar='PORT',
        help='MCP SSE server port (default: 8081)'
    )

    # UPnP options
    parser.add_argument(
        '--upnp-refresh',
        action='store_true',
        help='Refresh all UPnP port mappings and exit (for cron use)'
    )

    # Metasploit options
    parser.add_argument(
        '--no-msf',
        action='store_true',
        help='Skip Metasploit autoconnect on startup'
    )
    parser.add_argument(
        '--msf-user',
        metavar='USER',
        help='MSF RPC username for quick connect'
    )
    parser.add_argument(
        '--msf-pass',
        metavar='PASS',
        help='MSF RPC password for quick connect'
    )
    parser.add_argument(
        '--msf-no-sudo',
        action='store_true',
        help='Do not use sudo when starting msfrpcd (limits some modules)'
    )

    # Quick commands (positional)
    parser.add_argument(
        'command',
        nargs='?',
        choices=['chat', 'agent', 'osint', 'scan', 'analyze'],
        help='Quick command to run'
    )
    parser.add_argument(
        'target',
        nargs='?',
        help='Target for quick commands (username, IP, file, etc.)'
    )

    return parser


def show_version():
    """Display version information."""
    print(f"""
{Colors.BOLD}AUTARCH{Colors.RESET} - Autonomous Tactical Agent
Version: {VERSION}
Build:   {BUILD_DATE}

{Colors.DIM}By darkHal Security Group and Setec Security Labs{Colors.RESET}

Components:
  - Core Framework    v{VERSION}
  - LLM Integration   llama-cpp-python
  - MSF Integration   Metasploit RPC
  - Agent System      Autonomous tools

Modules:
  - chat       Interactive LLM chat
  - agent      Autonomous AI agent
  - msf        Metasploit interface
  - defender   System hardening (defense)
  - counter    Threat detection (counter)
  - analyze    Forensics tools (analyze)
  - recon      OSINT reconnaissance (osint)
  - adultscan  Adult site scanner (osint)
  - simulate   Attack simulation (simulate)

Python: {sys.version.split()[0]}
Path:   {FRAMEWORK_DIR}
""")


def show_config():
    """Display current configuration."""
    from core.config import get_config

    config = get_config()
    print(f"\n{Colors.BOLD}AUTARCH Configuration{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

    print(f"{Colors.CYAN}Config File:{Colors.RESET} {config.config_path}")
    print()

    # LLM Settings
    print(f"{Colors.CYAN}LLM Settings:{Colors.RESET}")
    llama = config.get_llama_settings()
    for key, value in llama.items():
        print(f"  {key:20} = {value}")

    # Autarch Settings
    print(f"\n{Colors.CYAN}Autarch Settings:{Colors.RESET}")
    print(f"  {'first_run':20} = {config.get('autarch', 'first_run')}")
    print(f"  {'modules_path':20} = {config.get('autarch', 'modules_path')}")
    print(f"  {'verbose':20} = {config.get('autarch', 'verbose')}")

    # MSF Settings
    print(f"\n{Colors.CYAN}Metasploit Settings:{Colors.RESET}")
    try:
        from core.msf import get_msf_manager
        msf = get_msf_manager()
        settings = msf.get_settings()
        for key, value in settings.items():
            if key == 'password':
                value = '*' * len(value) if value else '(not set)'
            print(f"  {key:20} = {value}")
    except:
        print(f"  {Colors.DIM}(MSF not configured){Colors.RESET}")

    print()


def list_modules(category=None):
    """List available modules."""
    from core.menu import MainMenu, CATEGORIES

    menu = MainMenu()
    menu.load_modules()

    print(f"\n{Colors.BOLD}Available Modules{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

    if category:
        # List specific category
        cat_info = CATEGORIES.get(category, {})
        modules = menu.get_modules_by_category(category)

        color = cat_info.get('color', Colors.WHITE)
        print(f"{color}{Colors.BOLD}{category.upper()}{Colors.RESET} - {cat_info.get('description', '')}")
        print()

        if modules:
            for name, info in modules.items():
                print(f"  {color}{name:15}{Colors.RESET} {info.description}")
                print(f"  {Colors.DIM}{'':15} v{info.version} by {info.author}{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}No modules in this category{Colors.RESET}")
    else:
        # List all categories
        for cat_name, cat_info in CATEGORIES.items():
            modules = menu.get_modules_by_category(cat_name)
            if not modules:
                continue

            color = cat_info.get('color', Colors.WHITE)
            print(f"{color}{Colors.BOLD}{cat_name.upper()}{Colors.RESET} - {cat_info.get('description', '')}")

            for name, info in modules.items():
                print(f"  {color}[{name}]{Colors.RESET} {info.description}")

            print()

    print(f"{Colors.DIM}Total modules: {len(menu.modules)}{Colors.RESET}")
    print(f"{Colors.DIM}Run with: python autarch.py -m <module_name>{Colors.RESET}\n")


def run_module(module_name, quiet=False):
    """Run a specific module directly."""
    modules_path = FRAMEWORK_DIR / 'modules'
    module_file = modules_path / f"{module_name}.py"

    if not module_file.exists():
        print(f"{Colors.RED}[X] Module not found: {module_name}{Colors.RESET}")
        print(f"{Colors.DIM}Use --list to see available modules{Colors.RESET}")
        sys.exit(1)

    try:
        spec = importlib.util.spec_from_file_location(module_name, module_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        if hasattr(module, 'run'):
            if not quiet:
                clear_screen()
                display_banner()
                print(f"{Colors.GREEN}[+] Running module: {module_name}{Colors.RESET}")
                print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")
            module.run()
        else:
            print(f"{Colors.RED}[X] Module '{module_name}' has no run() function{Colors.RESET}")
            sys.exit(1)

    except Exception as e:
        print(f"{Colors.RED}[X] Module error: {e}{Colors.RESET}")
        sys.exit(1)


def quick_osint(username):
    """Quick OSINT username lookup."""
    print(f"\n{Colors.CYAN}Quick OSINT: {username}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}\n")

    # Run adultscan with username
    try:
        from modules.adultscan import AdultScanner
        scanner = AdultScanner()
        scanner.scan_username(username)
        scanner.display_results()
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")


def quick_scan(target):
    """Quick port scan."""
    print(f"\n{Colors.CYAN}Quick Scan: {target}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}\n")

    try:
        from modules.simulate import Simulator
        sim = Simulator()
        # Would need to modify simulator to accept target directly
        # For now, just inform user
        print(f"Use: python autarch.py -m simulate")
        print(f"Then select Port Scanner and enter: {target}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")


def manage_service(action):
    """Manage the AUTARCH web dashboard systemd service."""
    import subprocess

    SERVICE_NAME = "autarch-web"
    SERVICE_FILE = FRAMEWORK_DIR / "scripts" / "autarch-web.service"
    SYSTEMD_PATH = Path("/etc/systemd/system/autarch-web.service")

    if action == 'install':
        # Install the service file
        if not SERVICE_FILE.exists():
            print(f"{Colors.RED}[X] Service file not found: {SERVICE_FILE}{Colors.RESET}")
            return
        try:
            subprocess.run(['sudo', 'cp', str(SERVICE_FILE), str(SYSTEMD_PATH)], check=True)
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            print(f"{Colors.GREEN}[+] Service installed: {SYSTEMD_PATH}{Colors.RESET}")
            print(f"{Colors.DIM}    Enable with: python autarch.py --service enable{Colors.RESET}")
            print(f"{Colors.DIM}    Start with:  python autarch.py --service start{Colors.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[X] Install failed: {e}{Colors.RESET}")
        return

    if not SYSTEMD_PATH.exists():
        print(f"{Colors.YELLOW}[!] Service not installed. Run: python autarch.py --service install{Colors.RESET}")
        return

    cmd_map = {
        'start': ['sudo', 'systemctl', 'start', SERVICE_NAME],
        'stop': ['sudo', 'systemctl', 'stop', SERVICE_NAME],
        'restart': ['sudo', 'systemctl', 'restart', SERVICE_NAME],
        'enable': ['sudo', 'systemctl', 'enable', SERVICE_NAME],
        'disable': ['sudo', 'systemctl', 'disable', SERVICE_NAME],
    }

    if action == 'status':
        result = subprocess.run(
            ['systemctl', 'is-active', SERVICE_NAME],
            capture_output=True, text=True
        )
        is_active = result.stdout.strip()
        result2 = subprocess.run(
            ['systemctl', 'is-enabled', SERVICE_NAME],
            capture_output=True, text=True
        )
        is_enabled = result2.stdout.strip()

        color = Colors.GREEN if is_active == 'active' else Colors.RED
        print(f"\n  {Colors.BOLD}AUTARCH Web Service{Colors.RESET}")
        print(f"  {'─' * 30}")
        print(f"  Status:  {color}{is_active}{Colors.RESET}")
        print(f"  Enabled: {is_enabled}")
        print()

        # Show journal output
        result3 = subprocess.run(
            ['journalctl', '-u', SERVICE_NAME, '-n', '5', '--no-pager'],
            capture_output=True, text=True
        )
        if result3.stdout.strip():
            print(f"  {Colors.DIM}Recent logs:{Colors.RESET}")
            for line in result3.stdout.strip().split('\n'):
                print(f"  {Colors.DIM}{line}{Colors.RESET}")
        return

    if action in cmd_map:
        try:
            subprocess.run(cmd_map[action], check=True)
            print(f"{Colors.GREEN}[+] Service {action}: OK{Colors.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}[X] Service {action} failed: {e}{Colors.RESET}")


def check_first_run():
    """Check if this is the first run and execute setup if needed."""
    from core.config import get_config
    config = get_config()

    if config.is_first_run():
        from modules.setup import run as run_setup
        if not run_setup():
            print("Setup cancelled. Exiting.")
            sys.exit(1)


def msf_autoconnect(skip: bool = False, username: str = None, password: str = None,
                    use_sudo: bool = True):
    """Handle Metasploit autoconnect on startup.

    Args:
        skip: Skip autoconnect entirely
        username: Optional username for quick connect
        password: Optional password for quick connect
        use_sudo: Run msfrpcd with sudo (default True for raw socket support)
    """
    if skip:
        return

    from core.msf import get_msf_manager, msf_startup_autoconnect, msf_quick_connect, MSGPACK_AVAILABLE

    if not MSGPACK_AVAILABLE:
        print(f"{Colors.DIM}  [MSF] msgpack not available - skipping autoconnect{Colors.RESET}")
        return

    # If credentials provided via command line, use quick connect
    if password:
        msf_quick_connect(username=username, password=password, use_sudo=use_sudo)
    else:
        # Use interactive autoconnect
        msf_startup_autoconnect()


def run_setup_wizard():
    """Run the setup wizard."""
    from modules.setup import run as run_setup
    run_setup()


def main():
    """Main entry point for AUTARCH."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle help
    if args.help:
        if not args.quiet:
            display_banner()
        parser.print_help()
        sys.exit(0)

    # Handle version
    if args.version:
        show_version()
        sys.exit(0)

    # Handle config file override
    if args.config:
        from core import config as config_module
        config_module._config = config_module.Config(args.config)

    # Handle show config
    if args.show_config:
        show_config()
        sys.exit(0)

    # Handle manual
    if getattr(args, 'manual', False):
        manual_path = FRAMEWORK_DIR / 'user_manual.md'
        if manual_path.exists():
            # Try to use less/more for paging
            import subprocess
            pager = 'less' if shutil.which('less') else ('more' if shutil.which('more') else None)
            if pager:
                subprocess.run([pager, str(manual_path)])
            else:
                print(manual_path.read_text())
        else:
            print(f"{Colors.RED}[X] User manual not found: {manual_path}{Colors.RESET}")
        sys.exit(0)

    # Handle setup
    if args.setup:
        if not args.no_banner:
            clear_screen()
            display_banner()
        run_setup_wizard()
        sys.exit(0)

    # Handle skip setup
    if args.skip_setup:
        from modules.setup import SetupWizard
        wizard = SetupWizard()
        wizard.skip_setup()
        sys.exit(0)

    # Handle service management
    if args.service:
        manage_service(args.service)
        sys.exit(0)

    # Handle MCP server
    if args.mcp:
        from core.mcp_server import run_stdio, run_sse
        if args.mcp == 'sse':
            print(f"{Colors.CYAN}[*] Starting AUTARCH MCP server (SSE) on port {args.mcp_port}{Colors.RESET}")
            run_sse(port=args.mcp_port)
        else:
            run_stdio()
        sys.exit(0)

    # Handle web dashboard
    if args.web:
        from web.app import create_app
        from core.config import get_config
        from core.paths import get_data_dir
        config = get_config()
        app = create_app()
        host = config.get('web', 'host', fallback='0.0.0.0')
        port = args.web_port or config.get_int('web', 'port', fallback=8181)

        # Auto-generate self-signed TLS cert for HTTPS (required for WebUSB over LAN)
        ssl_ctx = None
        use_https = config.get('web', 'https', fallback='true').lower() != 'false'
        if use_https:
            import os, subprocess as _sp
            cert_dir = os.path.join(get_data_dir(), 'certs')
            os.makedirs(cert_dir, exist_ok=True)
            cert_path = os.path.join(cert_dir, 'autarch.crt')
            key_path = os.path.join(cert_dir, 'autarch.key')
            if not os.path.exists(cert_path) or not os.path.exists(key_path):
                print(f"{Colors.CYAN}[*] Generating self-signed TLS certificate...{Colors.RESET}")
                _sp.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', key_path, '-out', cert_path,
                    '-days', '3650', '-nodes',
                    '-subj', '/CN=AUTARCH/O=darkHal',
                ], check=True, capture_output=True)
            ssl_ctx = (cert_path, key_path)
            proto = 'https'
        else:
            proto = 'http'

        print(f"{Colors.GREEN}[+] Starting AUTARCH Web Dashboard on {proto}://{host}:{port}{Colors.RESET}")

        # System tray mode (default on desktop environments)
        if not args.no_tray:
            try:
                from core.tray import TrayManager, TRAY_AVAILABLE
                if TRAY_AVAILABLE:
                    print(f"{Colors.DIM}  System tray icon active — right-click to control{Colors.RESET}")
                    tray = TrayManager(app, host, port, ssl_context=ssl_ctx)
                    tray.run()  # Blocks until Exit
                    sys.exit(0)
            except Exception:
                pass  # Fall through to normal mode

        # Fallback: run Flask directly (headless / --no-tray)
        app.run(host=host, port=port, debug=False, ssl_context=ssl_ctx)
        sys.exit(0)

    # Handle UPnP refresh (for cron)
    if args.upnp_refresh:
        from core.upnp import get_upnp_manager
        upnp = get_upnp_manager()
        results = upnp.refresh_all()
        for r in results:
            status = "OK" if r['success'] else "FAIL"
            print(f"  {r['port']}/{r['protocol']}: {status}")
        sys.exit(0)

    # Handle list modules
    if args.list:
        list_modules()
        sys.exit(0)

    if args.list_category:
        list_modules(args.list_category)
        sys.exit(0)

    # Handle direct module execution
    if args.module:
        run_module(args.module, args.quiet)
        sys.exit(0)

    # Handle quick commands
    if args.command:
        if not args.no_banner:
            clear_screen()
            display_banner()

        if args.command == 'chat':
            run_module('chat', args.quiet)
        elif args.command == 'agent':
            run_module('agent', args.quiet)
        elif args.command == 'osint':
            if args.target:
                quick_osint(args.target)
            else:
                print(f"{Colors.RED}Usage: autarch osint <username>{Colors.RESET}")
        elif args.command == 'scan':
            if args.target:
                quick_scan(args.target)
            else:
                print(f"{Colors.RED}Usage: autarch scan <target>{Colors.RESET}")
        elif args.command == 'analyze':
            if args.target:
                run_module('analyze', args.quiet)
            else:
                run_module('analyze', args.quiet)
        sys.exit(0)

    # Default: run interactive menu
    try:
        # Display banner first
        if not args.no_banner:
            clear_screen()
            display_banner()

        # Check for first run and execute setup
        check_first_run()

        # Metasploit autoconnect
        msf_autoconnect(
            skip=args.no_msf,
            username=args.msf_user,
            password=args.msf_pass,
            use_sudo=not args.msf_no_sudo
        )

        # Apply CLI display flags to config for this session
        from core.config import get_config
        cfg = get_config()
        if args.verbose:
            cfg.set('autarch', 'verbose', 'true')
        if args.quiet:
            cfg.set('autarch', 'quiet', 'true')
        if args.no_banner:
            cfg.set('autarch', 'no_banner', 'true')

        # Start the main menu
        from core.menu import MainMenu
        menu = MainMenu()
        menu.run()

    except KeyboardInterrupt:
        print(f"\n\n{Colors.CYAN}Exiting AUTARCH...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.RESET}")
        if '--verbose' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
