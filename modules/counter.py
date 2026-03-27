"""
AUTARCH Counter Module
Threat detection and incident response

Monitors system for suspicious activity and potential threats.
"""

import os
import sys
import subprocess
import re
import socket
import json
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional, Any

# Module metadata
DESCRIPTION = "Threat detection & incident response"
AUTHOR = "darkHal"
VERSION = "2.0"
CATEGORY = "counter"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner

# Try to import requests for GeoIP lookup
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False


@dataclass
class LoginAttempt:
    """Information about a login attempt from an IP."""
    ip: str
    count: int
    last_attempt: Optional[datetime] = None
    usernames: List[str] = None
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    geo_data: Optional[Dict] = None

    def __post_init__(self):
        if self.usernames is None:
            self.usernames = []


# Metasploit recon modules for IP investigation
MSF_RECON_MODULES = [
    {
        'name': 'TCP Port Scan',
        'module': 'auxiliary/scanner/portscan/tcp',
        'description': 'TCP port scanner - scans common ports',
        'options': {'PORTS': '21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'}
    },
    {
        'name': 'SYN Port Scan',
        'module': 'auxiliary/scanner/portscan/syn',
        'description': 'SYN stealth port scanner (requires root)',
        'options': {'PORTS': '21-23,25,53,80,110,139,143,443,445,3306,3389,5900,8080'}
    },
    {
        'name': 'SSH Version Scanner',
        'module': 'auxiliary/scanner/ssh/ssh_version',
        'description': 'Detect SSH version and supported algorithms',
        'options': {}
    },
    {
        'name': 'SSH Login Check',
        'module': 'auxiliary/scanner/ssh/ssh_login',
        'description': 'Brute force SSH login (requires wordlists)',
        'options': {}
    },
    {
        'name': 'SMB Version Scanner',
        'module': 'auxiliary/scanner/smb/smb_version',
        'description': 'Detect SMB version and OS information',
        'options': {}
    },
    {
        'name': 'SMB Share Enumeration',
        'module': 'auxiliary/scanner/smb/smb_enumshares',
        'description': 'Enumerate available SMB shares',
        'options': {}
    },
    {
        'name': 'HTTP Version Scanner',
        'module': 'auxiliary/scanner/http/http_version',
        'description': 'Detect HTTP server version',
        'options': {}
    },
    {
        'name': 'FTP Version Scanner',
        'module': 'auxiliary/scanner/ftp/ftp_version',
        'description': 'Detect FTP server version',
        'options': {}
    },
    {
        'name': 'Telnet Version Scanner',
        'module': 'auxiliary/scanner/telnet/telnet_version',
        'description': 'Detect Telnet banner and version',
        'options': {}
    },
    {
        'name': 'SNMP Enumeration',
        'module': 'auxiliary/scanner/snmp/snmp_enum',
        'description': 'Enumerate SNMP information',
        'options': {}
    },
    {
        'name': 'RDP Scanner',
        'module': 'auxiliary/scanner/rdp/rdp_scanner',
        'description': 'Detect RDP service',
        'options': {}
    },
    {
        'name': 'MySQL Version Scanner',
        'module': 'auxiliary/scanner/mysql/mysql_version',
        'description': 'Detect MySQL server version',
        'options': {}
    },
    {
        'name': 'VNC None Auth Scanner',
        'module': 'auxiliary/scanner/vnc/vnc_none_auth',
        'description': 'Check for VNC servers with no authentication',
        'options': {}
    },
]


class Counter:
    """Threat detection and response."""

    def __init__(self):
        self.threats = []
        self.login_attempts: Dict[str, LoginAttempt] = {}
        self._init_session()

    def _init_session(self):
        """Initialize HTTP session for GeoIP lookups."""
        self.session = None
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            adapter = requests.adapters.HTTPAdapter(max_retries=2)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
            })

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def alert(self, category: str, message: str, severity: str = "medium"):
        """Record a threat alert."""
        self.threats.append({"category": category, "message": message, "severity": severity})
        color = Colors.RED if severity == "high" else Colors.YELLOW if severity == "medium" else Colors.CYAN
        print(f"{color}[ALERT] {category}: {message}{Colors.RESET}")

    def run_cmd(self, cmd: str) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout.strip()
        except:
            return False, ""

    def get_hostname(self, ip: str) -> Optional[str]:
        """Resolve IP to hostname via reverse DNS."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            return None

    def get_geoip(self, ip: str) -> Optional[Dict]:
        """Get geolocation data for an IP address."""
        if not self.session:
            return None

        # Skip private/local IPs
        if ip.startswith('127.') or ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return {'country': 'Local', 'city': 'Private Network', 'isp': 'N/A'}

        try:
            # Try ipwho.is first
            response = self.session.get(f"https://ipwho.is/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('success', True):
                    return {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('country_code', ''),
                        'region': data.get('region', ''),
                        'city': data.get('city', 'Unknown'),
                        'latitude': data.get('latitude'),
                        'longitude': data.get('longitude'),
                        'isp': data.get('connection', {}).get('isp', 'Unknown'),
                        'org': data.get('connection', {}).get('org', ''),
                        'asn': data.get('connection', {}).get('asn', ''),
                    }
        except Exception:
            pass

        try:
            # Fallback to ipinfo.io
            response = self.session.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                loc = data.get('loc', ',').split(',')
                lat = float(loc[0]) if len(loc) > 0 and loc[0] else None
                lon = float(loc[1]) if len(loc) > 1 and loc[1] else None
                return {
                    'country': data.get('country', 'Unknown'),
                    'country_code': data.get('country'),
                    'region': data.get('region', ''),
                    'city': data.get('city', 'Unknown'),
                    'latitude': lat,
                    'longitude': lon,
                    'isp': data.get('org', 'Unknown'),
                    'org': data.get('org', ''),
                }
        except Exception:
            pass

        return None

    def parse_auth_logs(self) -> Dict[str, LoginAttempt]:
        """Parse authentication logs and extract failed login attempts."""
        attempts: Dict[str, LoginAttempt] = {}
        raw_log_lines = []

        # Try different log locations
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/messages',
        ]

        log_content = ""
        for log_file in log_files:
            success, output = self.run_cmd(f"cat {log_file} 2>/dev/null")
            if success and output:
                log_content = output
                break

        if not log_content:
            return attempts

        # Parse log entries for failed attempts
        # Common patterns:
        # "Failed password for root from 192.168.1.100 port 22 ssh2"
        # "Failed password for invalid user admin from 192.168.1.100 port 22"
        # "Invalid user admin from 192.168.1.100 port 22"
        # "Connection closed by authenticating user root 192.168.1.100 port 22 [preauth]"

        patterns = [
            # Failed password for user from IP
            r'(\w{3}\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)',
            # Invalid user from IP
            r'(\w{3}\s+\d+\s+[\d:]+).*Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)',
            # Connection closed by authenticating user
            r'(\w{3}\s+\d+\s+[\d:]+).*Connection closed by (?:authenticating user )?(\S+) (\d+\.\d+\.\d+\.\d+)',
            # pam_unix authentication failure
            r'(\w{3}\s+\d+\s+[\d:]+).*pam_unix.*authentication failure.*ruser=(\S*) rhost=(\d+\.\d+\.\d+\.\d+)',
        ]

        for line in log_content.split('\n'):
            if 'failed' in line.lower() or 'invalid user' in line.lower() or 'authentication failure' in line.lower():
                raw_log_lines.append(line)

                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        timestamp_str, username, ip = match.groups()
                        username = username if username else 'unknown'

                        # Parse timestamp (assuming current year)
                        try:
                            current_year = datetime.now().year
                            timestamp = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                        except ValueError:
                            timestamp = None

                        if ip not in attempts:
                            attempts[ip] = LoginAttempt(ip=ip, count=0)

                        attempts[ip].count += 1
                        if timestamp:
                            if attempts[ip].last_attempt is None or timestamp > attempts[ip].last_attempt:
                                attempts[ip].last_attempt = timestamp
                        if username not in attempts[ip].usernames:
                            attempts[ip].usernames.append(username)

                        break

        # Store raw logs for later viewing
        self._raw_auth_logs = raw_log_lines

        return attempts

    def enrich_login_attempts(self, attempts: Dict[str, LoginAttempt], show_progress: bool = True):
        """Enrich login attempts with GeoIP and hostname data."""
        total = len(attempts)
        for i, (ip, attempt) in enumerate(attempts.items()):
            if show_progress:
                print(f"\r{Colors.CYAN}[*] Enriching IP data... {i+1}/{total}{Colors.RESET}", end='', flush=True)

            # Get hostname
            attempt.hostname = self.get_hostname(ip)

            # Get GeoIP data
            geo_data = self.get_geoip(ip)
            if geo_data:
                attempt.country = geo_data.get('country')
                attempt.city = geo_data.get('city')
                attempt.isp = geo_data.get('isp')
                attempt.geo_data = geo_data

        if show_progress:
            print()  # New line after progress

    def check_suspicious_processes(self):
        """Look for suspicious processes."""
        print(f"\n{Colors.BOLD}Scanning for Suspicious Processes...{Colors.RESET}\n")

        # Known malicious process names
        suspicious_names = [
            "nc", "ncat", "netcat", "socat",  # Reverse shells
            "msfconsole", "msfvenom", "meterpreter",  # Metasploit
            "mimikatz", "lazagne", "pwdump",  # Credential theft
            "xmrig", "minerd", "cgminer",  # Cryptominers
            "tor", "proxychains",  # Anonymizers
        ]

        success, output = self.run_cmd("ps aux")
        if not success:
            self.print_status("Failed to get process list", "error")
            return

        found = []
        for line in output.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 11:
                proc_name = parts[10].split('/')[-1]
                for sus in suspicious_names:
                    if sus in proc_name.lower():
                        found.append((parts[1], proc_name, parts[0]))  # PID, name, user

        if found:
            for pid, name, user in found:
                self.alert("Suspicious Process", f"PID {pid}: {name} (user: {user})", "high")
        else:
            self.print_status("No known suspicious processes found", "success")

        # Check for hidden processes (comparing ps and /proc)
        success, ps_pids = self.run_cmd("ps -e -o pid=")
        if success:
            ps_set = set(ps_pids.split())
            proc_pids = set(p.name for p in Path("/proc").iterdir() if p.name.isdigit())
            hidden = proc_pids - ps_set
            if hidden:
                self.alert("Hidden Process", f"PIDs not in ps output: {', '.join(list(hidden)[:5])}", "high")

    def check_network_connections(self):
        """Analyze network connections for anomalies."""
        print(f"\n{Colors.BOLD}Analyzing Network Connections...{Colors.RESET}\n")

        success, output = self.run_cmd("ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null")
        if not success:
            self.print_status("Failed to get network connections", "error")
            return

        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Common backdoor",
            1337: "Common backdoor",
            31337: "Back Orifice",
            6667: "IRC (C2)",
            6666: "Common backdoor",
        }

        established_foreign = []
        listeners = []

        for line in output.split('\n'):
            if 'ESTABLISHED' in line:
                # Extract foreign address
                match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)', line)
                if match:
                    local_ip, local_port, foreign_ip, foreign_port = match.groups()
                    if not foreign_ip.startswith('127.'):
                        established_foreign.append((foreign_ip, foreign_port, line))

            if 'LISTEN' in line:
                match = re.search(r':(\d+)\s', line)
                if match:
                    port = int(match.group(1))
                    if port in suspicious_ports:
                        self.alert("Suspicious Listener", f"Port {port} ({suspicious_ports[port]})", "high")
                    listeners.append(port)

        # Check for connections to suspicious ports
        for ip, port, line in established_foreign:
            port_int = int(port)
            if port_int in suspicious_ports:
                self.alert("Suspicious Connection", f"Connected to {ip}:{port} ({suspicious_ports[port_int]})", "high")

        self.print_status(f"Found {len(established_foreign)} external connections, {len(listeners)} listeners", "info")

        # Show top foreign connections
        if established_foreign:
            print(f"\n{Colors.CYAN}External Connections:{Colors.RESET}")
            seen = set()
            for ip, port, _ in established_foreign[:10]:
                if ip not in seen:
                    print(f"  {ip}:{port}")
                    seen.add(ip)

    def check_login_anomalies(self):
        """Check for suspicious login activity - quick summary version."""
        print(f"\n{Colors.BOLD}Checking Login Activity...{Colors.RESET}\n")

        # Parse logs
        attempts = self.parse_auth_logs()
        self.login_attempts = attempts

        if not attempts:
            self.print_status("No failed login attempts found or could not read logs", "info")
            return

        total_attempts = sum(a.count for a in attempts.values())

        if total_attempts > 100:
            self.alert("Brute Force Detected", f"{total_attempts} failed login attempts from {len(attempts)} IPs", "high")
        elif total_attempts > 20:
            self.alert("Elevated Failed Logins", f"{total_attempts} failed attempts from {len(attempts)} IPs", "medium")
        else:
            self.print_status(f"{total_attempts} failed login attempts from {len(attempts)} unique IPs", "info")

        # Show top 5 IPs
        sorted_attempts = sorted(attempts.values(), key=lambda x: x.count, reverse=True)[:5]
        print(f"\n{Colors.CYAN}Top Source IPs:{Colors.RESET}")
        for attempt in sorted_attempts:
            print(f"  {attempt.ip}: {attempt.count} attempts")

        # Successful root logins
        success, output = self.run_cmd("last -n 20 root 2>/dev/null")
        if success and output and "root" in output:
            lines = [l for l in output.split('\n') if l.strip() and 'wtmp' not in l]
            if lines:
                print(f"\n{Colors.CYAN}Recent root logins:{Colors.RESET}")
                for line in lines[:5]:
                    print(f"  {line}")

    def login_anomalies_menu(self):
        """Interactive login anomalies menu with detailed IP information."""
        self._raw_auth_logs = []

        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.MAGENTA}{Colors.BOLD}  Login Anomalies Analysis{Colors.RESET}")
            print(f"{Colors.DIM}  Investigate failed login attempts{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Show cached data or prompt to scan
            if not self.login_attempts:
                print(f"  {Colors.YELLOW}No data loaded. Run a scan first.{Colors.RESET}")
                print()
                print(f"  {Colors.MAGENTA}[1]{Colors.RESET} Quick Scan (no GeoIP)")
                print(f"  {Colors.MAGENTA}[2]{Colors.RESET} Full Scan (with GeoIP lookup)")
            else:
                # Show summary
                total_attempts = sum(a.count for a in self.login_attempts.values())
                unique_ips = len(self.login_attempts)

                if total_attempts > 100:
                    status_color = Colors.RED
                    status_text = "HIGH THREAT"
                elif total_attempts > 20:
                    status_color = Colors.YELLOW
                    status_text = "MODERATE"
                else:
                    status_color = Colors.GREEN
                    status_text = "LOW"

                print(f"  Status: {status_color}{status_text}{Colors.RESET}")
                print(f"  Total Failed Attempts: {Colors.CYAN}{total_attempts}{Colors.RESET}")
                print(f"  Unique IPs: {Colors.CYAN}{unique_ips}{Colors.RESET}")
                print()

                # Show IPs as options
                print(f"  {Colors.BOLD}Source IPs (sorted by attempts):{Colors.RESET}")
                print()

                sorted_attempts = sorted(self.login_attempts.values(), key=lambda x: x.count, reverse=True)

                for i, attempt in enumerate(sorted_attempts[:15], 1):
                    # Build info line
                    timestamp_str = ""
                    if attempt.last_attempt:
                        timestamp_str = attempt.last_attempt.strftime("%Y-%m-%d %H:%M")

                    location_str = ""
                    if attempt.country:
                        location_str = f"{attempt.country}"
                        if attempt.city and attempt.city != 'Unknown':
                            location_str += f"/{attempt.city}"

                    host_str = ""
                    if attempt.hostname:
                        host_str = f"({attempt.hostname[:30]})"

                    # Color based on attempt count
                    if attempt.count > 50:
                        count_color = Colors.RED
                    elif attempt.count > 10:
                        count_color = Colors.YELLOW
                    else:
                        count_color = Colors.WHITE

                    print(f"  {Colors.MAGENTA}[{i:2}]{Colors.RESET} {attempt.ip:16} "
                          f"{count_color}{attempt.count:4} attempts{Colors.RESET}", end='')

                    if timestamp_str:
                        print(f"  {Colors.DIM}Last: {timestamp_str}{Colors.RESET}", end='')
                    if location_str:
                        print(f"  {Colors.CYAN}{location_str}{Colors.RESET}", end='')

                    print()

                if len(sorted_attempts) > 15:
                    print(f"  {Colors.DIM}... and {len(sorted_attempts) - 15} more IPs{Colors.RESET}")

                print()
                print(f"  {Colors.MAGENTA}[R]{Colors.RESET} Rescan (Quick)")
                print(f"  {Colors.MAGENTA}[F]{Colors.RESET} Full Rescan (with GeoIP)")
                print(f"  {Colors.MAGENTA}[L]{Colors.RESET} View Raw Auth Log")

            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == '0':
                break

            elif choice in ['1', 'r'] and (not self.login_attempts or choice == 'r'):
                # Quick scan
                print(f"\n{Colors.CYAN}[*] Scanning authentication logs...{Colors.RESET}")
                self.login_attempts = self.parse_auth_logs()
                if self.login_attempts:
                    self.print_status(f"Found {len(self.login_attempts)} unique IPs", "success")
                else:
                    self.print_status("No failed login attempts found", "info")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice in ['2', 'f'] and (not self.login_attempts or choice == 'f'):
                # Full scan with GeoIP
                print(f"\n{Colors.CYAN}[*] Scanning authentication logs...{Colors.RESET}")
                self.login_attempts = self.parse_auth_logs()
                if self.login_attempts:
                    self.print_status(f"Found {len(self.login_attempts)} unique IPs", "success")
                    print(f"\n{Colors.CYAN}[*] Fetching GeoIP and hostname data...{Colors.RESET}")
                    self.enrich_login_attempts(self.login_attempts)
                    self.print_status("GeoIP enrichment complete", "success")
                else:
                    self.print_status("No failed login attempts found", "info")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice == 'l' and self.login_attempts:
                # View raw log
                self.view_raw_auth_log()

            elif choice.isdigit() and self.login_attempts:
                idx = int(choice)
                sorted_attempts = sorted(self.login_attempts.values(), key=lambda x: x.count, reverse=True)
                if 1 <= idx <= len(sorted_attempts):
                    self.ip_detail_menu(sorted_attempts[idx - 1])

    def view_raw_auth_log(self):
        """Display raw authentication log entries."""
        clear_screen()
        display_banner()

        print(f"{Colors.MAGENTA}{Colors.BOLD}  Raw Authentication Log{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        if not hasattr(self, '_raw_auth_logs') or not self._raw_auth_logs:
            print(f"  {Colors.YELLOW}No log data available. Run a scan first.{Colors.RESET}")
        else:
            # Show last 100 entries by default
            log_lines = self._raw_auth_logs[-100:]
            for line in log_lines:
                # Highlight IPs
                highlighted = re.sub(
                    r'(\d+\.\d+\.\d+\.\d+)',
                    f'{Colors.CYAN}\\1{Colors.RESET}',
                    line
                )
                # Highlight "failed"
                highlighted = re.sub(
                    r'(failed|invalid|authentication failure)',
                    f'{Colors.RED}\\1{Colors.RESET}',
                    highlighted,
                    flags=re.IGNORECASE
                )
                print(f"  {highlighted}")

            print()
            print(f"  {Colors.DIM}Showing last {len(log_lines)} of {len(self._raw_auth_logs)} entries{Colors.RESET}")

        print()
        input(f"{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def ip_detail_menu(self, attempt: LoginAttempt):
        """Show detailed information and options for a specific IP."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.MAGENTA}{Colors.BOLD}  IP Investigation: {attempt.ip}{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Basic info
            print(f"  {Colors.BOLD}Connection Statistics:{Colors.RESET}")
            print(f"    Failed Attempts:  {Colors.RED}{attempt.count}{Colors.RESET}")
            if attempt.last_attempt:
                print(f"    Last Attempt:     {Colors.CYAN}{attempt.last_attempt.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
            if attempt.usernames:
                usernames_str = ', '.join(attempt.usernames[:10])
                if len(attempt.usernames) > 10:
                    usernames_str += f" (+{len(attempt.usernames) - 10} more)"
                print(f"    Targeted Users:   {Colors.YELLOW}{usernames_str}{Colors.RESET}")
            print()

            # Network info
            print(f"  {Colors.BOLD}Network Information:{Colors.RESET}")
            print(f"    IP Address:       {Colors.CYAN}{attempt.ip}{Colors.RESET}")

            if attempt.hostname:
                print(f"    Hostname:         {Colors.CYAN}{attempt.hostname}{Colors.RESET}")
            else:
                # Try to resolve now if not cached
                hostname = self.get_hostname(attempt.ip)
                if hostname:
                    attempt.hostname = hostname
                    print(f"    Hostname:         {Colors.CYAN}{hostname}{Colors.RESET}")
                else:
                    print(f"    Hostname:         {Colors.DIM}(no reverse DNS){Colors.RESET}")

            print()

            # GeoIP info
            print(f"  {Colors.BOLD}Geolocation:{Colors.RESET}")
            if attempt.geo_data:
                geo = attempt.geo_data
                if geo.get('country'):
                    country_str = geo.get('country', 'Unknown')
                    if geo.get('country_code'):
                        country_str += f" ({geo['country_code']})"
                    print(f"    Country:          {Colors.CYAN}{country_str}{Colors.RESET}")
                if geo.get('region'):
                    print(f"    Region:           {Colors.CYAN}{geo['region']}{Colors.RESET}")
                if geo.get('city') and geo.get('city') != 'Unknown':
                    print(f"    City:             {Colors.CYAN}{geo['city']}{Colors.RESET}")
                if geo.get('isp'):
                    print(f"    ISP:              {Colors.CYAN}{geo['isp']}{Colors.RESET}")
                if geo.get('org') and geo.get('org') != geo.get('isp'):
                    print(f"    Organization:     {Colors.CYAN}{geo['org']}{Colors.RESET}")
                if geo.get('asn'):
                    print(f"    ASN:              {Colors.CYAN}{geo['asn']}{Colors.RESET}")
                if geo.get('latitude') and geo.get('longitude'):
                    print(f"    Coordinates:      {Colors.DIM}{geo['latitude']}, {geo['longitude']}{Colors.RESET}")
                    print(f"    Map:              {Colors.DIM}https://www.google.com/maps/@{geo['latitude']},{geo['longitude']},12z{Colors.RESET}")
            elif attempt.country:
                print(f"    Country:          {Colors.CYAN}{attempt.country}{Colors.RESET}")
                if attempt.city:
                    print(f"    City:             {Colors.CYAN}{attempt.city}{Colors.RESET}")
                if attempt.isp:
                    print(f"    ISP:              {Colors.CYAN}{attempt.isp}{Colors.RESET}")
            else:
                print(f"    {Colors.DIM}(GeoIP data not loaded - run Full Scan){Colors.RESET}")

            print()
            print(f"  {Colors.BOLD}Actions:{Colors.RESET}")
            print()
            print(f"  {Colors.MAGENTA}[G]{Colors.RESET} Fetch/Refresh GeoIP Data")
            print(f"  {Colors.MAGENTA}[W]{Colors.RESET} Whois Lookup")
            print(f"  {Colors.MAGENTA}[P]{Colors.RESET} Ping Target")
            print()
            print(f"  {Colors.BOLD}Metasploit Recon Modules:{Colors.RESET}")
            print()

            for i, module in enumerate(MSF_RECON_MODULES, 1):
                print(f"  {Colors.RED}[{i:2}]{Colors.RESET} {module['name']}")
                print(f"       {Colors.DIM}{module['description']}{Colors.RESET}")

            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == '0':
                break

            elif choice == 'g':
                # Refresh GeoIP
                print(f"\n{Colors.CYAN}[*] Fetching GeoIP data for {attempt.ip}...{Colors.RESET}")
                geo_data = self.get_geoip(attempt.ip)
                if geo_data:
                    attempt.geo_data = geo_data
                    attempt.country = geo_data.get('country')
                    attempt.city = geo_data.get('city')
                    attempt.isp = geo_data.get('isp')
                    self.print_status("GeoIP data updated", "success")
                else:
                    self.print_status("Could not fetch GeoIP data", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice == 'w':
                # Whois lookup
                print(f"\n{Colors.CYAN}[*] Running whois lookup for {attempt.ip}...{Colors.RESET}\n")
                success, output = self.run_cmd(f"whois {attempt.ip} 2>/dev/null | head -60")
                if success and output:
                    print(output)
                else:
                    self.print_status("Whois lookup failed or not available", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice == 'p':
                # Ping
                print(f"\n{Colors.CYAN}[*] Pinging {attempt.ip}...{Colors.RESET}\n")
                success, output = self.run_cmd(f"ping -c 4 {attempt.ip} 2>&1")
                print(output)
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice.isdigit():
                idx = int(choice)
                if 1 <= idx <= len(MSF_RECON_MODULES):
                    self.run_msf_recon(attempt.ip, MSF_RECON_MODULES[idx - 1])


    def run_msf_recon(self, target_ip: str, module_info: Dict):
        """Run a Metasploit recon module against the target IP."""
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Metasploit Recon: {module_info['name']}{Colors.RESET}")
        print(f"{Colors.DIM}  Target: {target_ip}{Colors.RESET}")
        print(f"{Colors.DIM}  Module: {module_info['module']}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Use the centralized MSF interface
        try:
            from core.msf_interface import get_msf_interface
        except ImportError:
            self.print_status("Metasploit interface not available", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        msf = get_msf_interface()

        # Ensure connected
        connected, msg = msf.ensure_connected()
        if not connected:
            print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")
            print()
            print(f"    To connect, ensure msfrpcd is running:")
            print(f"    {Colors.DIM}msfrpcd -P yourpassword -S{Colors.RESET}")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Build options
        options = {'RHOSTS': target_ip}
        options.update(module_info.get('options', {}))

        # Warn about SYN scan known issues
        if 'syn' in module_info['module'].lower():
            print(f"{Colors.YELLOW}[!] Note: SYN scan may produce errors if:{Colors.RESET}")
            print(f"    - Target has firewall filtering responses")
            print(f"    - Network NAT/filtering interferes with raw packets")
            print(f"    Consider TCP scan (option 1) for more reliable results.")
            print()

        # Show what we're about to run
        print(f"{Colors.CYAN}[*] Module Options:{Colors.RESET}")
        for key, value in options.items():
            print(f"    {key}: {value}")
        print()

        confirm = input(f"{Colors.YELLOW}Execute module? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        # Execute via the interface
        print(f"\n{Colors.CYAN}[*] Executing {module_info['name']}...{Colors.RESET}")

        result = msf.run_module(module_info['module'], options, timeout=120)

        # Display results using the interface's formatter
        msf.print_result(result, verbose=False)

        # Add SYN-specific error guidance
        if result.error_count > 0 and 'syn' in module_info['module'].lower():
            print(f"\n{Colors.DIM}    SYN scan errors are often caused by:{Colors.RESET}")
            print(f"{Colors.DIM}    - Target firewall blocking responses{Colors.RESET}")
            print(f"{Colors.DIM}    - Network filtering/NAT issues{Colors.RESET}")
            print(f"{Colors.DIM}    - Known MSF SYN scanner bugs{Colors.RESET}")
            print(f"{Colors.DIM}    Try using TCP scan (option 1) instead.{Colors.RESET}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def check_file_integrity(self):
        """Check for recently modified critical files."""
        print(f"\n{Colors.BOLD}Checking File Integrity...{Colors.RESET}\n")

        critical_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/etc/crontab",
            "/root/.ssh/authorized_keys",
        ]

        recent_threshold = datetime.now() - timedelta(days=7)

        for filepath in critical_paths:
            p = Path(filepath)
            if p.exists():
                mtime = datetime.fromtimestamp(p.stat().st_mtime)
                if mtime > recent_threshold:
                    self.alert("Recent Modification", f"{filepath} modified {mtime.strftime('%Y-%m-%d %H:%M')}", "medium")
                else:
                    self.print_status(f"{filepath} - OK", "success")

        # Check for new SUID binaries
        print(f"\n{Colors.CYAN}Checking SUID binaries...{Colors.RESET}")
        success, output = self.run_cmd("find /usr -perm -4000 -type f 2>/dev/null")
        if success:
            suid_files = output.split('\n')
            known_suid = ['sudo', 'su', 'passwd', 'ping', 'mount', 'umount', 'chsh', 'newgrp']
            for f in suid_files:
                if f:
                    name = Path(f).name
                    if not any(k in name for k in known_suid):
                        self.alert("Unknown SUID", f"{f}", "medium")

    def check_scheduled_tasks(self):
        """Check cron jobs and scheduled tasks."""
        print(f"\n{Colors.BOLD}Checking Scheduled Tasks...{Colors.RESET}\n")

        # System crontab
        crontab = Path("/etc/crontab")
        if crontab.exists():
            content = crontab.read_text()
            # Look for suspicious commands
            suspicious = ['curl', 'wget', 'nc ', 'bash -i', 'python -c', 'perl -e', 'base64']
            for sus in suspicious:
                if sus in content:
                    self.alert("Suspicious Cron", f"Found '{sus}' in /etc/crontab", "high")

        # User crontabs
        success, output = self.run_cmd("ls /var/spool/cron/crontabs/ 2>/dev/null")
        if success and output:
            users = output.split('\n')
            self.print_status(f"Found crontabs for: {', '.join(users)}", "info")

        # Check /etc/cron.d
        cron_d = Path("/etc/cron.d")
        if cron_d.exists():
            for f in cron_d.iterdir():
                if f.is_file():
                    content = f.read_text()
                    for sus in ['curl', 'wget', 'nc ', 'bash -i']:
                        if sus in content:
                            self.alert("Suspicious Cron", f"Found '{sus}' in {f}", "medium")

    def check_rootkits(self):
        """Basic rootkit detection."""
        print(f"\n{Colors.BOLD}Running Rootkit Checks...{Colors.RESET}\n")

        # Check for hidden files in /tmp
        success, output = self.run_cmd("ls -la /tmp/. /tmp/.. 2>/dev/null")
        if success:
            hidden = re.findall(r'\.\w+', output)
            if len(hidden) > 5:
                self.alert("Hidden Files", f"Many hidden files in /tmp: {len(hidden)}", "medium")

        # Check for kernel modules
        success, output = self.run_cmd("lsmod")
        if success:
            suspicious_modules = ['rootkit', 'hide', 'stealth', 'sniff']
            for line in output.split('\n'):
                for sus in suspicious_modules:
                    if sus in line.lower():
                        self.alert("Suspicious Module", f"Kernel module: {line.split()[0]}", "high")

        # Check for process hiding
        success, output = self.run_cmd("ps aux | wc -l")
        success2, output2 = self.run_cmd("ls /proc | grep -E '^[0-9]+$' | wc -l")
        if success and success2:
            ps_count = int(output)
            proc_count = int(output2)
            if abs(ps_count - proc_count) > 5:
                self.alert("Process Hiding", f"Mismatch: ps={ps_count}, /proc={proc_count}", "high")
            else:
                self.print_status("Process count consistent", "success")

        # Check for common rootkit files
        rootkit_files = [
            "/usr/lib/libproc.a",
            "/dev/ptyp",
            "/dev/ptyq",
            "/usr/include/file.h",
            "/usr/include/hosts.h",
        ]
        for f in rootkit_files:
            if Path(f).exists():
                self.alert("Rootkit Artifact", f"Suspicious file: {f}", "high")

        self.print_status("Rootkit checks complete", "info")

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.MAGENTA}{Colors.BOLD}  Counter Intelligence{Colors.RESET}")
        print(f"{Colors.DIM}  Threat detection & response{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.BOLD}Quick Scans{Colors.RESET}")
        print(f"  {Colors.MAGENTA}[1]{Colors.RESET} Full Threat Scan")
        print(f"  {Colors.MAGENTA}[2]{Colors.RESET} Suspicious Processes")
        print(f"  {Colors.MAGENTA}[3]{Colors.RESET} Network Analysis")
        print(f"  {Colors.MAGENTA}[4]{Colors.RESET} Login Anomalies (Quick)")
        print(f"  {Colors.MAGENTA}[5]{Colors.RESET} File Integrity")
        print(f"  {Colors.MAGENTA}[6]{Colors.RESET} Scheduled Tasks")
        print(f"  {Colors.MAGENTA}[7]{Colors.RESET} Rootkit Detection")
        print()
        print(f"  {Colors.BOLD}Investigation Tools{Colors.RESET}")
        print(f"  {Colors.MAGENTA}[8]{Colors.RESET} Login Anomalies Analysis {Colors.CYAN}(Interactive){Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def full_scan(self):
        """Run all threat checks."""
        self.threats = []
        self.check_suspicious_processes()
        self.check_network_connections()
        self.check_login_anomalies()
        self.check_file_integrity()
        self.check_scheduled_tasks()
        self.check_rootkits()

        # Summary
        high = sum(1 for t in self.threats if t['severity'] == 'high')
        medium = sum(1 for t in self.threats if t['severity'] == 'medium')

        print(f"\n{Colors.BOLD}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Threat Summary:{Colors.RESET}")
        print(f"  {Colors.RED}High: {high}{Colors.RESET}")
        print(f"  {Colors.YELLOW}Medium: {medium}{Colors.RESET}")

        if high > 0:
            print(f"\n{Colors.RED}CRITICAL: Immediate investigation required!{Colors.RESET}")

    def run(self):
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()
                self.threats = []

                if choice == "0":
                    break
                elif choice == "1":
                    self.full_scan()
                elif choice == "2":
                    self.check_suspicious_processes()
                elif choice == "3":
                    self.check_network_connections()
                elif choice == "4":
                    self.check_login_anomalies()
                elif choice == "5":
                    self.check_file_integrity()
                elif choice == "6":
                    self.check_scheduled_tasks()
                elif choice == "7":
                    self.check_rootkits()
                elif choice == "8":
                    self.login_anomalies_menu()
                    continue  # Skip the "Press Enter" prompt for interactive menu

                if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    Counter().run()


if __name__ == "__main__":
    run()
