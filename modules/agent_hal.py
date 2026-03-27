"""
AUTARCH Agent Hal Module
AI-powered security automation for defense and penetration testing

Uses LLM integration for intelligent security operations including:
- MITM attack detection and monitoring
- Automated Metasploit module execution via natural language
- Network security analysis
"""

import os
import sys
import subprocess
import re
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# Module metadata
NAME = "Agent Hal"
DESCRIPTION = "AI-powered security automation"
AUTHOR = "darkHal Security Group"
VERSION = "2.0"
CATEGORY = "core"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner
from core.config import get_config
from core.llm import LLM, LLMError
from core.pentest_tree import PentestTree, NodeStatus, PTTNodeType
from core.pentest_pipeline import PentestPipeline, detect_source_type
from core.pentest_session import PentestSession, PentestSessionState


class AgentHal:
    """AI-powered security automation agent."""

    def __init__(self):
        self.config = get_config()
        self.llm = None
        self.msf = None
        self.msf_connected = False
        self.pentest_session = None
        self.pentest_pipeline = None

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run a shell command and return output."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def _ensure_llm_loaded(self) -> bool:
        """Ensure LLM is loaded and ready."""
        if self.llm is None:
            self.llm = LLM()

        if not self.llm.is_loaded:
            self.print_status("Loading LLM model...", "info")
            try:
                self.llm.load_model(verbose=True)
                return True
            except LLMError as e:
                self.print_status(f"Failed to load LLM: {e}", "error")
                return False
        return True

    def _ensure_msf_connected(self) -> bool:
        """Ensure MSF RPC is connected via the centralized interface."""
        if self.msf is None:
            try:
                from core.msf_interface import get_msf_interface
                self.msf = get_msf_interface()
            except ImportError:
                self.print_status("MSF interface not available", "error")
                return False

        # Use the interface's connection management
        connected, msg = self.msf.ensure_connected(auto_prompt=False)
        if connected:
            self.msf_connected = True
            self.print_status("Connected to MSF RPC", "success")
            return True
        else:
            self.print_status(f"Failed to connect to MSF: {msg}", "error")
            return False

    # ==================== MITM DETECTION ====================

    def mitm_detection_menu(self):
        """MITM attack detection submenu."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  MITM Detection{Colors.RESET}")
            print(f"{Colors.DIM}  Detect Man-in-the-Middle attacks on your network{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} Full MITM Scan (All Checks)")
            print(f"  {Colors.GREEN}[2]{Colors.RESET} ARP Spoofing Detection")
            print(f"  {Colors.GREEN}[3]{Colors.RESET} DNS Spoofing Detection")
            print(f"  {Colors.GREEN}[4]{Colors.RESET} SSL/TLS Stripping Detection")
            print(f"  {Colors.GREEN}[5]{Colors.RESET} Rogue DHCP Detection")
            print(f"  {Colors.GREEN}[6]{Colors.RESET} Gateway Anomaly Check")
            print()
            print(f"  {Colors.CYAN}[7]{Colors.RESET} Continuous Monitoring Mode")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

            if choice == "0":
                break
            elif choice == "1":
                self.full_mitm_scan()
            elif choice == "2":
                self.detect_arp_spoofing()
            elif choice == "3":
                self.detect_dns_spoofing()
            elif choice == "4":
                self.detect_ssl_stripping()
            elif choice == "5":
                self.detect_rogue_dhcp()
            elif choice == "6":
                self.check_gateway_anomaly()
            elif choice == "7":
                self.continuous_monitoring()

            if choice in ["1", "2", "3", "4", "5", "6"]:
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def full_mitm_scan(self):
        """Run all MITM detection checks."""
        print(f"\n{Colors.BOLD}Full MITM Scan{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        issues = []

        # ARP Spoofing
        print(f"{Colors.CYAN}[1/5] Checking for ARP spoofing...{Colors.RESET}")
        arp_issues = self._check_arp_spoofing()
        issues.extend(arp_issues)

        # DNS Spoofing
        print(f"{Colors.CYAN}[2/5] Checking for DNS spoofing...{Colors.RESET}")
        dns_issues = self._check_dns_spoofing()
        issues.extend(dns_issues)

        # SSL Stripping
        print(f"{Colors.CYAN}[3/5] Checking for SSL stripping indicators...{Colors.RESET}")
        ssl_issues = self._check_ssl_stripping()
        issues.extend(ssl_issues)

        # Rogue DHCP
        print(f"{Colors.CYAN}[4/5] Checking for rogue DHCP servers...{Colors.RESET}")
        dhcp_issues = self._check_rogue_dhcp()
        issues.extend(dhcp_issues)

        # Gateway Anomaly
        print(f"{Colors.CYAN}[5/5] Checking gateway for anomalies...{Colors.RESET}")
        gw_issues = self._check_gateway()
        issues.extend(gw_issues)

        # Results
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Scan Results{Colors.RESET}\n")

        if issues:
            print(f"{Colors.RED}[!] Found {len(issues)} potential issue(s):{Colors.RESET}\n")
            for issue in issues:
                severity_color = Colors.RED if issue['severity'] == 'HIGH' else Colors.YELLOW
                print(f"  {severity_color}[{issue['severity']}]{Colors.RESET} {issue['type']}")
                print(f"       {issue['description']}")
                if issue.get('details'):
                    print(f"       {Colors.DIM}{issue['details']}{Colors.RESET}")
                print()
        else:
            print(f"{Colors.GREEN}[+] No MITM indicators detected{Colors.RESET}")
            print(f"{Colors.DIM}    Network appears clean{Colors.RESET}")

    def _check_arp_spoofing(self) -> List[Dict]:
        """Check for ARP spoofing indicators."""
        issues = []

        # Get ARP table
        success, output = self.run_cmd("arp -a")
        if not success:
            success, output = self.run_cmd("ip neigh show")

        if success and output:
            # Parse ARP entries
            mac_to_ips = {}
            lines = output.split('\n')

            for line in lines:
                # Extract MAC and IP
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)

                if mac_match and ip_match:
                    mac = mac_match.group().lower()
                    ip = ip_match.group()

                    if mac not in mac_to_ips:
                        mac_to_ips[mac] = []
                    mac_to_ips[mac].append(ip)

            # Check for duplicate MACs (potential ARP spoofing)
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    issues.append({
                        'type': 'ARP Spoofing Detected',
                        'severity': 'HIGH',
                        'description': f'Multiple IPs share same MAC address',
                        'details': f'MAC {mac} -> IPs: {", ".join(ips)}'
                    })

        return issues

    def detect_arp_spoofing(self):
        """Detailed ARP spoofing detection."""
        print(f"\n{Colors.BOLD}ARP Spoofing Detection{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Get ARP table
        print(f"{Colors.CYAN}[*] Fetching ARP table...{Colors.RESET}")
        success, output = self.run_cmd("arp -a")
        if not success:
            success, output = self.run_cmd("ip neigh show")

        if success and output:
            print(f"\n{Colors.CYAN}Current ARP Table:{Colors.RESET}")
            print(output)

            issues = self._check_arp_spoofing()

            if issues:
                print(f"\n{Colors.RED}[!] ARP Spoofing Indicators Found:{Colors.RESET}")
                for issue in issues:
                    print(f"    {issue['description']}")
                    print(f"    {Colors.DIM}{issue['details']}{Colors.RESET}")
            else:
                print(f"\n{Colors.GREEN}[+] No ARP spoofing detected{Colors.RESET}")

        # Get gateway MAC
        print(f"\n{Colors.CYAN}[*] Checking gateway MAC...{Colors.RESET}")
        success, gw = self.run_cmd("ip route | grep default | awk '{print $3}'")
        if success and gw:
            print(f"    Gateway IP: {gw}")
            success, gw_mac = self.run_cmd(f"arp -n {gw} | grep -v Address | awk '{{print $3}}'")
            if success and gw_mac:
                print(f"    Gateway MAC: {gw_mac}")

    def _check_dns_spoofing(self) -> List[Dict]:
        """Check for DNS spoofing indicators."""
        issues = []

        # Check resolv.conf for suspicious DNS
        success, output = self.run_cmd("cat /etc/resolv.conf")
        if success:
            dns_servers = re.findall(r'nameserver\s+(\S+)', output)

            # Known safe DNS servers
            safe_dns = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9', '208.67.222.222']

            for dns in dns_servers:
                if dns.startswith('127.') or dns.startswith('192.168.') or dns.startswith('10.'):
                    # Local DNS - could be legitimate or malicious
                    pass
                elif dns not in safe_dns:
                    issues.append({
                        'type': 'Suspicious DNS Server',
                        'severity': 'MEDIUM',
                        'description': f'Unknown DNS server configured',
                        'details': f'DNS: {dns}'
                    })

        # Test DNS resolution consistency
        test_domains = ['google.com', 'cloudflare.com']
        for domain in test_domains:
            success1, ip1 = self.run_cmd(f"dig +short {domain} @8.8.8.8 | head -1")
            success2, ip2 = self.run_cmd(f"dig +short {domain} | head -1")

            if success1 and success2 and ip1 and ip2:
                if ip1 != ip2:
                    issues.append({
                        'type': 'DNS Resolution Mismatch',
                        'severity': 'HIGH',
                        'description': f'DNS returns different IP than Google DNS',
                        'details': f'{domain}: Local={ip2}, Google={ip1}'
                    })

        return issues

    def detect_dns_spoofing(self):
        """Detailed DNS spoofing detection."""
        print(f"\n{Colors.BOLD}DNS Spoofing Detection{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Show current DNS config
        print(f"{Colors.CYAN}[*] Current DNS Configuration:{Colors.RESET}")
        success, output = self.run_cmd("cat /etc/resolv.conf | grep -v '^#'")
        if success:
            print(output)

        # Test DNS resolution
        print(f"\n{Colors.CYAN}[*] Testing DNS Resolution Consistency:{Colors.RESET}")
        test_domains = ['google.com', 'cloudflare.com', 'microsoft.com']

        for domain in test_domains:
            success1, ip1 = self.run_cmd(f"dig +short {domain} @8.8.8.8 | head -1")
            success2, ip2 = self.run_cmd(f"dig +short {domain} | head -1")

            if success1 and success2:
                match = "MATCH" if ip1 == ip2 else "MISMATCH"
                color = Colors.GREEN if ip1 == ip2 else Colors.RED
                print(f"    {domain}:")
                print(f"      Local DNS:  {ip2}")
                print(f"      Google DNS: {ip1}")
                print(f"      Status: {color}{match}{Colors.RESET}")

        issues = self._check_dns_spoofing()
        if issues:
            print(f"\n{Colors.RED}[!] DNS Issues Found:{Colors.RESET}")
            for issue in issues:
                print(f"    {issue['description']}: {issue['details']}")

    def _check_ssl_stripping(self) -> List[Dict]:
        """Check for SSL stripping indicators."""
        issues = []

        # Check if HSTS is being honored
        test_sites = ['https://www.google.com', 'https://www.cloudflare.com']

        for site in test_sites:
            success, output = self.run_cmd(f"curl -sI -m 5 {site} | head -1")
            if success:
                if 'HTTP/1.1 200' not in output and 'HTTP/2' not in output:
                    issues.append({
                        'type': 'HTTPS Connection Issue',
                        'severity': 'MEDIUM',
                        'description': f'Unexpected response from HTTPS site',
                        'details': f'{site}: {output}'
                    })

        # Check for SSL certificate issues
        success, output = self.run_cmd("curl -sI -m 5 https://www.google.com 2>&1 | grep -i 'certificate'")
        if success and 'certificate' in output.lower():
            issues.append({
                'type': 'SSL Certificate Warning',
                'severity': 'HIGH',
                'description': 'SSL certificate issues detected',
                'details': output
            })

        return issues

    def detect_ssl_stripping(self):
        """Detailed SSL stripping detection."""
        print(f"\n{Colors.BOLD}SSL/TLS Stripping Detection{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        test_sites = [
            ('https://www.google.com', 'Google'),
            ('https://www.cloudflare.com', 'Cloudflare'),
            ('https://www.github.com', 'GitHub'),
        ]

        print(f"{Colors.CYAN}[*] Testing HTTPS Connections:{Colors.RESET}\n")

        for url, name in test_sites:
            print(f"  Testing {name}...")

            # Check HTTP redirect
            http_url = url.replace('https://', 'http://')
            success, output = self.run_cmd(f"curl -sI -m 5 -o /dev/null -w '%{{http_code}} %{{redirect_url}}' {http_url}")

            if success:
                parts = output.split()
                code = parts[0] if parts else "000"
                redirect = parts[1] if len(parts) > 1 else ""

                if code in ['301', '302', '307', '308'] and redirect.startswith('https://'):
                    print(f"    {Colors.GREEN}[+] HTTP->HTTPS redirect working{Colors.RESET}")
                else:
                    print(f"    {Colors.YELLOW}[!] No HTTPS redirect (Code: {code}){Colors.RESET}")

            # Check HTTPS directly
            success, output = self.run_cmd(f"curl -sI -m 5 {url} 2>&1 | head -1")
            if success and ('200' in output or 'HTTP/2' in output):
                print(f"    {Colors.GREEN}[+] HTTPS connection successful{Colors.RESET}")
            else:
                print(f"    {Colors.RED}[!] HTTPS connection failed: {output}{Colors.RESET}")

            # Check certificate
            domain = url.replace('https://', '').replace('/', '')
            success, cert_info = self.run_cmd(f"echo | openssl s_client -connect {domain}:443 -servername {domain} 2>/dev/null | openssl x509 -noout -dates 2>/dev/null")
            if success and cert_info:
                print(f"    {Colors.GREEN}[+] Valid SSL certificate{Colors.RESET}")
                print(f"       {Colors.DIM}{cert_info.replace(chr(10), ' | ')}{Colors.RESET}")
            print()

    def _check_rogue_dhcp(self) -> List[Dict]:
        """Check for rogue DHCP servers."""
        issues = []

        # Get current DHCP server
        success, output = self.run_cmd("cat /var/lib/dhcp/dhclient.leases 2>/dev/null | grep 'dhcp-server-identifier' | tail -1")
        if not success:
            success, output = self.run_cmd("journalctl -u NetworkManager --no-pager -n 50 2>/dev/null | grep -i 'dhcp' | grep -i 'server'")

        # This is a basic check - full rogue DHCP detection requires nmap or specialized tools
        return issues

    def detect_rogue_dhcp(self):
        """Detect rogue DHCP servers."""
        print(f"\n{Colors.BOLD}Rogue DHCP Detection{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        print(f"{Colors.CYAN}[*] Current DHCP Information:{Colors.RESET}")

        # Check DHCP leases
        success, output = self.run_cmd("cat /var/lib/dhcp/dhclient.leases 2>/dev/null | tail -30")
        if success and output:
            print(output)
        else:
            # Try NetworkManager
            success, output = self.run_cmd("nmcli device show | grep -i 'dhcp\\|gateway\\|dns'")
            if success:
                print(output)

        print(f"\n{Colors.YELLOW}[!] Note: Full rogue DHCP detection requires nmap:{Colors.RESET}")
        print(f"    {Colors.DIM}nmap --script broadcast-dhcp-discover{Colors.RESET}")

        # Offer to run nmap scan
        run_nmap = input(f"\n{Colors.WHITE}Run nmap DHCP discovery? (y/n): {Colors.RESET}").strip().lower()
        if run_nmap == 'y':
            print(f"\n{Colors.CYAN}[*] Running DHCP discovery...{Colors.RESET}")
            success, output = self.run_cmd("nmap --script broadcast-dhcp-discover 2>/dev/null", timeout=60)
            if success:
                print(output)
            else:
                self.print_status("nmap not available or scan failed", "warning")

    def _check_gateway(self) -> List[Dict]:
        """Check gateway for anomalies."""
        issues = []

        # Get default gateway
        success, gateway = self.run_cmd("ip route | grep default | awk '{print $3}'")
        if success and gateway:
            # Ping gateway
            success, output = self.run_cmd(f"ping -c 1 -W 2 {gateway}")
            if not success:
                issues.append({
                    'type': 'Gateway Unreachable',
                    'severity': 'HIGH',
                    'description': 'Default gateway is not responding',
                    'details': f'Gateway: {gateway}'
                })

            # Check gateway MAC consistency
            success, mac = self.run_cmd(f"arp -n {gateway} | grep -v Address | awk '{{print $3}}'")
            if success and mac:
                # Check if MAC is from a known vendor (basic check)
                if mac.startswith('00:00:00') or mac == '(incomplete)':
                    issues.append({
                        'type': 'Suspicious Gateway MAC',
                        'severity': 'MEDIUM',
                        'description': 'Gateway MAC address appears suspicious',
                        'details': f'Gateway {gateway} has MAC {mac}'
                    })

        return issues

    def check_gateway_anomaly(self):
        """Check for gateway anomalies."""
        print(f"\n{Colors.BOLD}Gateway Anomaly Check{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Get gateway info
        success, gateway = self.run_cmd("ip route | grep default | awk '{print $3}'")
        if success and gateway:
            print(f"  Default Gateway: {gateway}")

            # Get MAC
            success, mac = self.run_cmd(f"arp -n {gateway} | grep -v Address | awk '{{print $3}}'")
            if success and mac:
                print(f"  Gateway MAC: {mac}")

            # Ping test
            success, output = self.run_cmd(f"ping -c 3 -W 2 {gateway}")
            if success:
                print(f"  {Colors.GREEN}[+] Gateway is reachable{Colors.RESET}")
                # Extract latency
                latency = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)', output)
                if latency:
                    print(f"  Latency: {latency.group(2)}ms avg")
            else:
                print(f"  {Colors.RED}[!] Gateway is NOT reachable{Colors.RESET}")

            # Traceroute
            print(f"\n{Colors.CYAN}[*] Route to Internet:{Colors.RESET}")
            success, output = self.run_cmd("traceroute -m 5 8.8.8.8 2>/dev/null", timeout=30)
            if success:
                print(output)
        else:
            print(f"  {Colors.RED}[!] Could not determine default gateway{Colors.RESET}")

    def continuous_monitoring(self):
        """Continuous MITM monitoring mode."""
        print(f"\n{Colors.BOLD}Continuous MITM Monitoring{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.DIM}Press Ctrl+C to stop monitoring{Colors.RESET}\n")

        # Store baseline
        success, baseline_arp = self.run_cmd("arp -a")
        baseline_macs = {}
        if success:
            for line in baseline_arp.split('\n'):
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
                if mac_match and ip_match:
                    baseline_macs[ip_match.group()] = mac_match.group().lower()

        print(f"{Colors.GREEN}[+] Baseline captured: {len(baseline_macs)} hosts{Colors.RESET}\n")

        try:
            check_count = 0
            while True:
                check_count += 1
                timestamp = datetime.now().strftime("%H:%M:%S")

                # Get current ARP table
                success, current_arp = self.run_cmd("arp -a")
                if success:
                    current_macs = {}
                    for line in current_arp.split('\n'):
                        mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
                        ip_match = re.search(r'(\d{1,3}\.){3}\d{1,3}', line)
                        if mac_match and ip_match:
                            current_macs[ip_match.group()] = mac_match.group().lower()

                    # Compare with baseline
                    for ip, mac in current_macs.items():
                        if ip in baseline_macs and baseline_macs[ip] != mac:
                            print(f"{Colors.RED}[{timestamp}] ALERT: MAC change detected!{Colors.RESET}")
                            print(f"         IP: {ip}")
                            print(f"         Old MAC: {baseline_macs[ip]}")
                            print(f"         New MAC: {mac}")
                            print()

                    # Check for new hosts
                    new_hosts = set(current_macs.keys()) - set(baseline_macs.keys())
                    for ip in new_hosts:
                        print(f"{Colors.YELLOW}[{timestamp}] New host detected: {ip} ({current_macs[ip]}){Colors.RESET}")

                print(f"\r{Colors.DIM}[{timestamp}] Check #{check_count} - {len(current_macs)} hosts{Colors.RESET}", end='', flush=True)
                time.sleep(5)

        except KeyboardInterrupt:
            print(f"\n\n{Colors.CYAN}[*] Monitoring stopped{Colors.RESET}")

    # ==================== MSF AUTOMATION ====================

    def msf_automation_menu(self):
        """LLM-driven Metasploit automation menu."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  MSF Automation (AI-Powered){Colors.RESET}")
            print(f"{Colors.DIM}  Use natural language to run Metasploit modules{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Status
            llm_status = f"{Colors.GREEN}Loaded{Colors.RESET}" if (self.llm and self.llm.is_loaded) else f"{Colors.RED}Not loaded{Colors.RESET}"
            msf_status = f"{Colors.GREEN}Connected{Colors.RESET}" if self.msf_connected else f"{Colors.RED}Not connected{Colors.RESET}"
            print(f"  {Colors.DIM}LLM: {llm_status}  |  MSF: {msf_status}{Colors.RESET}")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} Describe What You Want To Do")
            print(f"  {Colors.GREEN}[2]{Colors.RESET} Quick Scan Target")
            print(f"  {Colors.GREEN}[3]{Colors.RESET} Exploit Suggester")
            print(f"  {Colors.GREEN}[4]{Colors.RESET} Post-Exploitation Helper")
            print()
            print(f"  {Colors.CYAN}[C]{Colors.RESET} Connect to MSF")
            print(f"  {Colors.CYAN}[L]{Colors.RESET} Load LLM Model")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == "0":
                break
            elif choice == "1":
                self.natural_language_msf()
            elif choice == "2":
                self.quick_scan_target()
            elif choice == "3":
                self.exploit_suggester()
            elif choice == "4":
                self.post_exploitation_helper()
            elif choice == "c":
                self._ensure_msf_connected()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            elif choice == "l":
                self._ensure_llm_loaded()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def natural_language_msf(self):
        """Process natural language requests for MSF operations."""
        print(f"\n{Colors.BOLD}Natural Language MSF Control{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.DIM}Describe what you want to do in plain English.{Colors.RESET}")
        print(f"{Colors.DIM}Examples:{Colors.RESET}")
        print(f"{Colors.DIM}  - 'Scan 192.168.1.1 for open ports'{Colors.RESET}")
        print(f"{Colors.DIM}  - 'Check if target is vulnerable to EternalBlue'{Colors.RESET}")
        print(f"{Colors.DIM}  - 'Run SMB version scanner on 10.0.0.0/24'{Colors.RESET}")
        print()

        # Ensure LLM is loaded
        if not self._ensure_llm_loaded():
            return

        # Ensure MSF is connected
        if not self._ensure_msf_connected():
            print(f"{Colors.YELLOW}[!] MSF not connected. Will show commands but cannot execute.{Colors.RESET}")

        # Get user request
        request = input(f"{Colors.WHITE}What do you want to do? {Colors.RESET}").strip()
        if not request:
            return

        print(f"\n{Colors.CYAN}[*] Analyzing request...{Colors.RESET}")

        # Build prompt for LLM
        system_prompt = """You are a Metasploit expert assistant. Your job is to translate user requests into specific Metasploit module recommendations.

When the user describes what they want to do, respond with:
1. The recommended MSF module path (e.g., auxiliary/scanner/smb/smb_version)
2. Required options (e.g., RHOSTS, RPORT)
3. A brief explanation of what the module does

Format your response as JSON:
{
    "module_type": "auxiliary|exploit|post",
    "module_path": "full/module/path",
    "options": {"RHOSTS": "value", "THREADS": "10"},
    "explanation": "Brief description"
}

If you cannot determine an appropriate module, respond with:
{"error": "reason"}

Common modules:
- Port scan: auxiliary/scanner/portscan/tcp
- SMB version: auxiliary/scanner/smb/smb_version
- MS17-010 check: auxiliary/scanner/smb/smb_ms17_010
- SSH version: auxiliary/scanner/ssh/ssh_version
- HTTP version: auxiliary/scanner/http/http_version
- FTP version: auxiliary/scanner/ftp/ftp_version
- Vuln scan: auxiliary/scanner/smb/smb_ms08_067
"""

        try:
            # Clear history for fresh context
            self.llm.clear_history()

            # Get LLM response
            response = self.llm.chat(request, system_prompt=system_prompt)

            # Try to parse JSON from response
            try:
                # Find JSON in response
                json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
                if json_match:
                    module_info = json.loads(json_match.group())
                else:
                    module_info = json.loads(response)

                if 'error' in module_info:
                    print(f"\n{Colors.YELLOW}[!] {module_info['error']}{Colors.RESET}")
                    return

                # Display recommendation
                print(f"\n{Colors.GREEN}[+] Recommended Module:{Colors.RESET}")
                print(f"    Type: {module_info.get('module_type', 'unknown')}")
                print(f"    Path: {module_info.get('module_path', 'unknown')}")
                print(f"\n{Colors.CYAN}Options:{Colors.RESET}")
                for opt, val in module_info.get('options', {}).items():
                    print(f"    {opt}: {val}")
                print(f"\n{Colors.DIM}Explanation: {module_info.get('explanation', 'N/A')}{Colors.RESET}")

                # Ask to execute
                if self.msf and self.msf.is_connected:
                    execute = input(f"\n{Colors.WHITE}Execute this module? (y/n): {Colors.RESET}").strip().lower()
                    if execute == 'y':
                        self._execute_msf_module(module_info)

            except json.JSONDecodeError:
                # LLM didn't return valid JSON, show raw response
                print(f"\n{Colors.CYAN}LLM Response:{Colors.RESET}")
                print(response)

        except LLMError as e:
            self.print_status(f"LLM error: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _execute_msf_module(self, module_info: Dict):
        """Execute an MSF module based on LLM recommendation."""
        try:
            module_type = module_info.get('module_type', 'auxiliary')
            module_path = module_info.get('module_path', '')
            options = module_info.get('options', {})

            # Ensure full module path format (type/path)
            if not module_path.startswith(module_type + '/'):
                full_path = f"{module_type}/{module_path}"
            else:
                full_path = module_path

            print(f"\n{Colors.CYAN}[*] Executing {full_path}...{Colors.RESET}")

            # Use the interface's run_module method
            result = self.msf.run_module(full_path, options)

            if result.success:
                print(f"{Colors.GREEN}[+] Module executed successfully{Colors.RESET}")
                if result.findings:
                    print(f"\n{Colors.CYAN}Findings:{Colors.RESET}")
                    for finding in result.findings[:10]:
                        print(f"  {finding}")
                if result.info:
                    for info in result.info[:5]:
                        print(f"  {Colors.DIM}{info}{Colors.RESET}")
            else:
                print(f"{Colors.YELLOW}[!] {result.get_summary()}{Colors.RESET}")

        except Exception as e:
            self.print_status(f"Execution failed: {e}", "error")

    def quick_scan_target(self):
        """Quick scan a target using MSF."""
        print(f"\n{Colors.BOLD}Quick Target Scan{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        target = input(f"{Colors.WHITE}Enter target (IP or range): {Colors.RESET}").strip()
        if not target:
            return

        if not self._ensure_msf_connected():
            self.print_status("Cannot scan without MSF connection", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.CYAN}[*] Running quick scan on {target}...{Colors.RESET}\n")

        # Run common scanners
        scanners = [
            ('auxiliary/scanner/portscan/tcp', {'RHOSTS': target, 'PORTS': '21-25,80,443,445,3389,8080'}),
            ('auxiliary/scanner/smb/smb_version', {'RHOSTS': target}),
            ('auxiliary/scanner/ssh/ssh_version', {'RHOSTS': target}),
        ]

        for module_path, options in scanners:
            try:
                print(f"  Running {module_path}...")
                result = self.msf.run_module(module_path, options)
                if result.success:
                    print(f"    {Colors.GREEN}Completed{Colors.RESET}")
                    for finding in result.findings[:3]:
                        print(f"      {finding}")
                else:
                    print(f"    {Colors.YELLOW}{result.get_summary()}{Colors.RESET}")
            except Exception as e:
                print(f"    {Colors.RED}Failed: {e}{Colors.RESET}")

        print(f"\n{Colors.GREEN}[+] Quick scan completed.{Colors.RESET}")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def exploit_suggester(self):
        """Use LLM to suggest exploits based on target info."""
        print(f"\n{Colors.BOLD}Exploit Suggester{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.DIM}Describe your target and I'll suggest exploits.{Colors.RESET}\n")

        if not self._ensure_llm_loaded():
            return

        print(f"{Colors.WHITE}Enter target information:{Colors.RESET}")
        print(f"{Colors.DIM}(OS, services, versions, open ports, etc.){Colors.RESET}")
        target_info = input(f"{Colors.WHITE}> {Colors.RESET}").strip()

        if not target_info:
            return

        print(f"\n{Colors.CYAN}[*] Analyzing target...{Colors.RESET}")

        system_prompt = """You are a penetration testing expert. Based on the target information provided, suggest relevant Metasploit exploits and auxiliary modules.

Consider:
1. Operating system vulnerabilities
2. Service-specific exploits
3. Common misconfigurations
4. Post-exploitation opportunities

Format your response as a prioritized list with:
- Module path
- CVE (if applicable)
- Success likelihood (High/Medium/Low)
- Brief description

Focus on practical, commonly successful exploits."""

        try:
            self.llm.clear_history()
            response = self.llm.chat(f"Target information: {target_info}", system_prompt=system_prompt)
            print(f"\n{Colors.GREEN}Exploit Suggestions:{Colors.RESET}\n")
            print(response)
        except LLMError as e:
            self.print_status(f"LLM error: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def post_exploitation_helper(self):
        """LLM-assisted post-exploitation guidance."""
        print(f"\n{Colors.BOLD}Post-Exploitation Helper{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.DIM}Get guidance on post-exploitation steps.{Colors.RESET}\n")

        if not self._ensure_llm_loaded():
            return

        print(f"{Colors.WHITE}Describe your current access:{Colors.RESET}")
        print(f"{Colors.DIM}(Shell type, privileges, OS, what you've found){Colors.RESET}")
        access_info = input(f"{Colors.WHITE}> {Colors.RESET}").strip()

        if not access_info:
            return

        print(f"\n{Colors.CYAN}[*] Generating post-exploitation plan...{Colors.RESET}")

        system_prompt = """You are a post-exploitation expert. Based on the current access described, provide a structured post-exploitation plan.

Include:
1. Privilege escalation techniques (if not already root/SYSTEM)
2. Persistence mechanisms
3. Credential harvesting opportunities
4. Lateral movement options
5. Data exfiltration considerations
6. Relevant Metasploit post modules

Be specific with commands and module paths. Prioritize by likelihood of success."""

        try:
            self.llm.clear_history()
            response = self.llm.chat(f"Current access: {access_info}", system_prompt=system_prompt)
            print(f"\n{Colors.GREEN}Post-Exploitation Plan:{Colors.RESET}\n")
            print(response)
        except LLMError as e:
            self.print_status(f"LLM error: {e}", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # ==================== PENTEST PIPELINE ====================

    def pentest_pipeline_menu(self):
        """PentestGPT-style structured penetration testing menu."""
        while True:
            clear_screen()
            display_banner()

            print(f"{Colors.RED}{Colors.BOLD}  Pentest Pipeline (AI-Powered){Colors.RESET}")
            print(f"{Colors.DIM}  Structured penetration testing with task tree{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Status
            llm_status = f"{Colors.GREEN}Ready{Colors.RESET}" if (self.llm and self.llm.is_loaded) else f"{Colors.DIM}Not loaded{Colors.RESET}"
            msf_status = f"{Colors.GREEN}Connected{Colors.RESET}" if self.msf_connected else f"{Colors.DIM}Offline{Colors.RESET}"
            session_status = f"{Colors.GREEN}{self.pentest_session.target}{Colors.RESET}" if self.pentest_session else f"{Colors.DIM}None{Colors.RESET}"
            print(f"  {Colors.DIM}LLM: {llm_status}  |  MSF: {msf_status}{Colors.RESET}")
            print(f"  {Colors.DIM}Session: {session_status}{Colors.RESET}")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} New Pentest Session")
            print(f"  {Colors.GREEN}[2]{Colors.RESET} Resume Saved Session")
            print(f"  {Colors.GREEN}[3]{Colors.RESET} List Saved Sessions")
            print(f"  {Colors.GREEN}[4]{Colors.RESET} Delete Session")
            print()
            if self.pentest_session:
                print(f"  {Colors.CYAN}[S]{Colors.RESET} Show Task Tree")
                print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == "0":
                break
            elif choice == "1":
                self._start_new_pentest_session()
            elif choice == "2":
                self._resume_pentest_session()
            elif choice == "3":
                self._list_pentest_sessions()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            elif choice == "4":
                self._delete_pentest_session()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            elif choice == "s" and self.pentest_session:
                print(f"\n{self.pentest_session.tree.render_text()}")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _start_new_pentest_session(self):
        """Start a new pentest session with target."""
        print(f"\n{Colors.BOLD}New Pentest Session{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        target = input(f"{Colors.WHITE}Enter target (IP, hostname, or range): {Colors.RESET}").strip()
        if not target:
            return

        notes = input(f"{Colors.WHITE}Notes (optional): {Colors.RESET}").strip()

        # Ensure LLM is loaded
        if not self._ensure_llm_loaded():
            return

        # Create session
        self.pentest_session = PentestSession(target)
        self.pentest_session.notes = notes
        self.pentest_session.start()

        # Create pipeline
        self.pentest_pipeline = PentestPipeline(
            self.llm, target, self.pentest_session.tree
        )

        self.print_status(f"Session created: {self.pentest_session.session_id}", "success")
        self.print_status("Generating initial plan...", "info")

        # Generate initial plan
        try:
            plan = self.pentest_pipeline.get_initial_plan()

            print(f"\n{Colors.GREEN}Initial Plan:{Colors.RESET}")
            if plan.get('first_action'):
                print(f"  First action: {plan['first_action']}")
            if plan.get('reasoning'):
                print(f"  Reasoning: {plan['reasoning']}")

            if plan.get('commands'):
                print(f"\n{Colors.CYAN}Suggested Commands:{Colors.RESET}")
                for i, cmd in enumerate(plan['commands'], 1):
                    print(f"  {i}. {Colors.GREEN}{cmd['tool']}{Colors.RESET}: {json.dumps(cmd['args'])}")
                    print(f"     Expect: {cmd.get('expect', 'N/A')}")

            print(f"\n{Colors.DIM}Task tree initialized with {len(self.pentest_session.tree.nodes)} nodes{Colors.RESET}")
        except Exception as e:
            self.print_status(f"Plan generation error: {e}", "warning")
            print(f"{Colors.DIM}You can still use the session manually{Colors.RESET}")

        input(f"\n{Colors.WHITE}Press Enter to enter session...{Colors.RESET}")

        # Enter interactive loop
        self._pentest_interactive_loop()

    def _resume_pentest_session(self):
        """Resume a saved session."""
        sessions = PentestSession.list_sessions()
        if not sessions:
            self.print_status("No saved sessions found", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}Saved Sessions:{Colors.RESET}\n")
        resumable = []
        for i, s in enumerate(sessions, 1):
            state_color = Colors.YELLOW if s['state'] == 'paused' else Colors.DIM
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {s['target']} ({state_color}{s['state']}{Colors.RESET})")
            stats = s.get('tree_stats', {})
            print(f"      Steps: {s['steps']} | Findings: {s['findings']} | "
                  f"Tasks: {stats.get('todo', 0)} todo, {stats.get('completed', 0)} done")
            print(f"      {Colors.DIM}{s['session_id']}{Colors.RESET}")
            resumable.append(s)

        print(f"\n  {Colors.DIM}[0]{Colors.RESET} Cancel")
        choice = input(f"\n{Colors.WHITE}  Select session: {Colors.RESET}").strip()

        if choice == "0" or not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(resumable):
                session_id = resumable[idx]['session_id']
                self.pentest_session = PentestSession.load_session(session_id)
                self.pentest_session.resume()

                if not self._ensure_llm_loaded():
                    return

                self.pentest_pipeline = PentestPipeline(
                    self.llm, self.pentest_session.target,
                    self.pentest_session.tree
                )

                self.print_status(f"Resumed session: {self.pentest_session.target}", "success")
                input(f"\n{Colors.WHITE}Press Enter to enter session...{Colors.RESET}")
                self._pentest_interactive_loop()
        except (ValueError, FileNotFoundError) as e:
            self.print_status(f"Error: {e}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _list_pentest_sessions(self):
        """List all saved sessions."""
        sessions = PentestSession.list_sessions()
        if not sessions:
            self.print_status("No saved sessions", "info")
            return

        print(f"\n{Colors.BOLD}Saved Sessions ({len(sessions)}):{Colors.RESET}\n")
        for s in sessions:
            state_color = {
                'running': Colors.GREEN, 'paused': Colors.YELLOW,
                'completed': Colors.CYAN, 'error': Colors.RED,
            }.get(s['state'], Colors.DIM)
            print(f"  {s['target']:25} {state_color}{s['state']:10}{Colors.RESET} "
                  f"Steps: {s['steps']:3} Findings: {s['findings']}")
            print(f"  {Colors.DIM}{s['session_id']}{Colors.RESET}")
            print()

    def _delete_pentest_session(self):
        """Delete a saved session."""
        sessions = PentestSession.list_sessions()
        if not sessions:
            self.print_status("No saved sessions", "info")
            return

        print(f"\n{Colors.BOLD}Delete Session:{Colors.RESET}\n")
        for i, s in enumerate(sessions, 1):
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {s['target']} ({s['state']})")

        print(f"\n  {Colors.DIM}[0]{Colors.RESET} Cancel")
        choice = input(f"\n{Colors.WHITE}  Select: {Colors.RESET}").strip()

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(sessions):
                sid = sessions[idx]['session_id']
                confirm = input(f"{Colors.YELLOW}Delete {sid}? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    session = PentestSession.load_session(sid)
                    session.delete()
                    self.print_status("Session deleted", "success")
                    if self.pentest_session and self.pentest_session.session_id == sid:
                        self.pentest_session = None
                        self.pentest_pipeline = None
        except (ValueError, FileNotFoundError) as e:
            self.print_status(f"Error: {e}", "error")

    def _pentest_interactive_loop(self):
        """Interactive pentest session loop (PentestGPT-style)."""
        session = self.pentest_session
        pipeline = self.pentest_pipeline
        settings = self.config.get_pentest_settings()
        max_steps = settings['max_pipeline_steps']

        while session.state == PentestSessionState.RUNNING:
            clear_screen()
            stats = session.tree.get_stats()
            print(f"{Colors.RED}{Colors.BOLD}[Pentest Session: {session.target}]{Colors.RESET}")
            print(f"{Colors.DIM}[Step {session.step_count}/{max_steps}] "
                  f"[Tree: {stats['total']} nodes, {stats.get('todo', 0)} todo, "
                  f"{stats.get('completed', 0)} done]{Colors.RESET}")
            print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")
            print()

            # Show next recommended task
            next_todo = session.tree.get_next_todo()
            if next_todo:
                print(f"  {Colors.CYAN}Next task:{Colors.RESET} {next_todo.label} (P{next_todo.priority})")
            print()

            print(f"  {Colors.DIM}Commands:{Colors.RESET}")
            print(f"    {Colors.GREEN}next{Colors.RESET}    - Process tool output (paste results)")
            print(f"    {Colors.GREEN}exec{Colors.RESET}    - Auto-execute next recommended action")
            print(f"    {Colors.GREEN}discuss{Colors.RESET} - Ask a question (doesn't affect tree)")
            print(f"    {Colors.GREEN}google{Colors.RESET}  - Provide external research findings")
            print(f"    {Colors.GREEN}tree{Colors.RESET}    - Display current task tree")
            print(f"    {Colors.GREEN}status{Colors.RESET}  - Show session status")
            print(f"    {Colors.GREEN}pause{Colors.RESET}   - Save session and return to menu")
            print(f"    {Colors.GREEN}done{Colors.RESET}    - Complete session and generate report")
            print()

            try:
                cmd = input(f"{Colors.WHITE}  > {Colors.RESET}").strip().lower()
            except (EOFError, KeyboardInterrupt):
                cmd = "pause"

            if cmd == "next":
                self._handle_next(pipeline, session)
            elif cmd == "exec":
                self._handle_exec(pipeline, session)
            elif cmd == "discuss":
                self._handle_discuss(pipeline)
            elif cmd == "google":
                self._handle_google(pipeline, session)
            elif cmd == "tree":
                print(f"\n{session.tree.render_text()}")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            elif cmd == "status":
                self._handle_status(session)
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            elif cmd == "pause":
                session.pause()
                self.print_status("Session paused and saved", "success")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                break
            elif cmd == "done":
                self._handle_done(session)
                break

            # Check step limit
            if session.step_count >= max_steps:
                self.print_status(f"Step limit ({max_steps}) reached. Session paused.", "warning")
                session.pause()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                break

    def _handle_next(self, pipeline, session):
        """Handle 'next' command - process pasted tool output."""
        print(f"\n{Colors.CYAN}Paste tool output below (empty line to finish):{Colors.RESET}")
        lines = []
        while True:
            try:
                line = input()
                if line == "":
                    if lines:
                        break
                else:
                    lines.append(line)
            except EOFError:
                break

        if not lines:
            return

        raw_output = '\n'.join(lines)
        source_type = detect_source_type(raw_output)
        self.print_status(f"Detected source: {source_type}", "info")
        self.print_status("Processing through pipeline...", "info")

        result = pipeline.process_output(raw_output, source_type)

        # Log to session
        session.log_event('tool_output', {
            'source_type': source_type,
            'parsed_summary': result['parsed'].get('summary', ''),
        })
        session.log_pipeline_result(
            result['parsed'].get('summary', ''),
            result['reasoning'].get('reasoning', ''),
            result.get('commands', []),
        )

        # Add findings to session
        for finding in result['parsed'].get('findings', []):
            if '[VULN]' in finding or '[CRED]' in finding:
                severity = 'high' if '[VULN]' in finding else 'critical'
                session.add_finding(finding, finding, severity)

        # Display results
        print(f"\n{Colors.GREEN}--- Parsed ---{Colors.RESET}")
        print(f"  Summary: {result['parsed'].get('summary', 'N/A')}")
        if result['parsed'].get('findings'):
            print(f"  Findings:")
            for f in result['parsed']['findings']:
                color = Colors.RED if '[VULN]' in f else Colors.YELLOW if '[CRED]' in f else Colors.WHITE
                print(f"    {color}- {f}{Colors.RESET}")

        print(f"\n{Colors.GREEN}--- Reasoning ---{Colors.RESET}")
        print(f"  Next task: {result.get('next_task', 'N/A')}")
        print(f"  Reasoning: {result['reasoning'].get('reasoning', 'N/A')}")
        if result['reasoning'].get('tree_updates'):
            print(f"  Tree updates: {len(result['reasoning']['tree_updates'])}")

        if result.get('commands'):
            print(f"\n{Colors.GREEN}--- Suggested Commands ---{Colors.RESET}")
            for i, cmd in enumerate(result['commands'], 1):
                print(f"  {i}. {Colors.CYAN}{cmd['tool']}{Colors.RESET}: {json.dumps(cmd['args'])}")
                print(f"     Expect: {cmd.get('expect', 'N/A')}")
            if result.get('fallback'):
                print(f"\n  {Colors.DIM}Fallback: {result['fallback']}{Colors.RESET}")

        session.save()
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _handle_exec(self, pipeline, session):
        """Handle 'exec' command - auto-execute next recommended action."""
        next_todo = session.tree.get_next_todo()
        if not next_todo:
            self.print_status("No pending tasks in the tree", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        self.print_status(f"Generating commands for: {next_todo.label}", "info")

        # Generate commands
        context = ""
        if next_todo.details:
            context = next_todo.details
        gen_result = pipeline.generator.generate(
            next_todo.label, session.target, context=context
        )

        if not gen_result.get('commands'):
            self.print_status("No executable commands generated", "warning")
            if gen_result.get('raw_response'):
                print(f"\n{Colors.DIM}{gen_result['raw_response']}{Colors.RESET}")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Mark task as in progress
        session.tree.update_node(next_todo.id, status=NodeStatus.IN_PROGRESS)

        # Execute with confirmation
        print(f"\n{Colors.BOLD}Commands to execute:{Colors.RESET}")
        all_output = []
        for i, cmd in enumerate(gen_result['commands'], 1):
            print(f"\n  {i}. {Colors.CYAN}{cmd['tool']}{Colors.RESET}: {json.dumps(cmd['args'])}")
            print(f"     Expect: {cmd.get('expect', 'N/A')}")

            choice = input(f"     {Colors.WHITE}Execute? (y/n/skip): {Colors.RESET}").strip().lower()
            if choice == 'n':
                break
            elif choice == 'skip':
                continue

            # Execute the command
            output = self._execute_pipeline_action(cmd)
            if output:
                all_output.append(output)
                print(f"\n{Colors.DIM}Output:{Colors.RESET}")
                # Show truncated output
                display = output[:500]
                if len(output) > 500:
                    display += f"\n... ({len(output)} chars total)"
                print(display)

        # Process collected output through pipeline
        if all_output:
            combined = '\n'.join(all_output)
            self.print_status("Processing results through pipeline...", "info")
            result = pipeline.process_output(combined)
            session.log_pipeline_result(
                result['parsed'].get('summary', ''),
                result['reasoning'].get('reasoning', ''),
                result.get('commands', []),
            )

            print(f"\n{Colors.GREEN}Next task: {result.get('next_task', 'N/A')}{Colors.RESET}")
            print(f"Reasoning: {result['reasoning'].get('reasoning', 'N/A')}")

        session.save()
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _execute_pipeline_action(self, action: dict) -> Optional[str]:
        """Execute a single pipeline action. Returns output string or None."""
        tool_name = action.get('tool', '')
        args = action.get('args', {})

        try:
            if tool_name == 'shell':
                command = args.get('command', '')
                timeout = args.get('timeout', 30)
                success, output = self.run_cmd(command, timeout=timeout)
                return output

            elif tool_name.startswith('msf_'):
                from core.tools import get_tool_registry
                registry = get_tool_registry()
                result = registry.execute(tool_name, **args)
                if isinstance(result, dict):
                    return result.get('result', str(result))
                return str(result)

            else:
                self.print_status(f"Unknown tool: {tool_name}", "warning")
                return None

        except Exception as e:
            self.print_status(f"Execution error: {e}", "error")
            return f"Error: {e}"

    def _handle_discuss(self, pipeline):
        """Handle 'discuss' command - ad-hoc question."""
        question = input(f"\n{Colors.WHITE}Question: {Colors.RESET}").strip()
        if not question:
            return

        self.print_status("Thinking...", "info")
        response = pipeline.discuss(question)
        print(f"\n{Colors.GREEN}{response}{Colors.RESET}")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _handle_google(self, pipeline, session):
        """Handle 'google' command - inject external research."""
        print(f"\n{Colors.CYAN}Paste research findings below (empty line to finish):{Colors.RESET}")
        lines = []
        while True:
            try:
                line = input()
                if line == "" and lines:
                    break
                lines.append(line)
            except EOFError:
                break

        if not lines:
            return

        info = '\n'.join(lines)
        self.print_status("Injecting information into pipeline...", "info")
        result = pipeline.inject_information(info, source="research")

        session.log_event('research_injected', {'info': info[:200]})
        session.log_pipeline_result(
            result['parsed'].get('summary', ''),
            result['reasoning'].get('reasoning', ''),
            result.get('commands', []),
        )

        print(f"\n{Colors.GREEN}Updated reasoning:{Colors.RESET}")
        print(f"  Next task: {result.get('next_task', 'N/A')}")
        print(f"  Reasoning: {result['reasoning'].get('reasoning', 'N/A')}")

        session.save()
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _handle_status(self, session):
        """Display current session status."""
        stats = session.tree.get_stats()
        print(f"\n{Colors.BOLD}Session Status{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"  Target:    {session.target}")
        print(f"  Session:   {session.session_id}")
        print(f"  State:     {session.state.value}")
        print(f"  Steps:     {session.step_count}")
        print(f"  Findings:  {len(session.findings)}")
        print(f"\n  Task Tree:")
        print(f"    Total:     {stats['total']}")
        print(f"    Todo:      {stats.get('todo', 0)}")
        print(f"    Active:    {stats.get('in_progress', 0)}")
        print(f"    Done:      {stats.get('completed', 0)}")
        print(f"    N/A:       {stats.get('not_applicable', 0)}")

        if session.findings:
            print(f"\n  {Colors.YELLOW}Key Findings:{Colors.RESET}")
            for f in session.findings[-5:]:
                sev = f.get('severity', 'medium').upper()
                print(f"    [{sev}] {f['title']}")

    def _handle_done(self, session):
        """Handle 'done' command - complete session and generate report."""
        summary = input(f"\n{Colors.WHITE}Session summary (optional): {Colors.RESET}").strip()
        session.complete(summary)

        report = session.export_report()
        print(f"\n{report}")

        # Save report to file
        from core.paths import get_reports_dir
        report_path = get_reports_dir()
        report_file = report_path / f"pentest_{session.session_id}.txt"
        with open(report_file, 'w') as f:
            f.write(report)

        self.print_status(f"Report saved: {report_file}", "success")
        self.pentest_session = None
        self.pentest_pipeline = None
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # ==================== MAIN MENU ====================

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Agent Hal{Colors.RESET}")
        print(f"{Colors.DIM}  AI-powered security automation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Status line
        llm_status = f"{Colors.GREEN}Ready{Colors.RESET}" if (self.llm and self.llm.is_loaded) else f"{Colors.DIM}Not loaded{Colors.RESET}"
        msf_status = f"{Colors.GREEN}Connected{Colors.RESET}" if self.msf_connected else f"{Colors.DIM}Offline{Colors.RESET}"
        print(f"  {Colors.DIM}LLM: {llm_status}  |  MSF: {msf_status}{Colors.RESET}")
        print()

        print(f"  {Colors.RED}Defense{Colors.RESET}")
        print(f"    {Colors.GREEN}[1]{Colors.RESET} MITM Detection")
        print()
        print(f"  {Colors.RED}Offense{Colors.RESET}")
        print(f"    {Colors.GREEN}[2]{Colors.RESET} MSF Automation (AI)")
        print(f"    {Colors.GREEN}[3]{Colors.RESET} Pentest Pipeline (AI)")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def run(self):
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    self.mitm_detection_menu()
                elif choice == "2":
                    self.msf_automation_menu()
                elif choice == "3":
                    self.pentest_pipeline_menu()

            except (EOFError, KeyboardInterrupt):
                break


def run():
    AgentHal().run()


if __name__ == "__main__":
    run()
