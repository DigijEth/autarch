"""
AUTARCH Defender Module
System hardening and security posture assessment

Checks system configuration for security best practices.
"""

import os
import sys
import subprocess
import socket
import re
import time
import json
import threading
from pathlib import Path
from datetime import datetime

# Module metadata
DESCRIPTION = "System hardening & security checks"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


class Defender:
    """System security checker."""

    def __init__(self):
        self.results = []

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def check(self, name: str, passed: bool, details: str = ""):
        """Record a check result."""
        self.results.append({"name": name, "passed": passed, "details": details})
        status = "success" if passed else "warning"
        self.print_status(f"{name}: {'PASS' if passed else 'FAIL'}", status)
        if details and not passed:
            print(f"    {Colors.DIM}{details}{Colors.RESET}")

    def run_cmd(self, cmd: str) -> tuple:
        """Run command and return (success, output).
        Routes through the privileged daemon for commands that need root."""
        try:
            from core.daemon import root_exec
            import shlex
            # Strip shell redirections for the daemon (2>/dev/null, | head, etc.)
            # The daemon doesn't support shell pipes, so run the base command
            clean = cmd.split('2>/dev/null')[0].split('|')[0].strip()
            if clean.startswith('sudo '):
                clean = clean[5:].strip()
            parts = shlex.split(clean)
            r = root_exec(parts, timeout=10)
            return r['ok'], r['stdout'].strip()
        except Exception:
            # Fallback to direct shell execution
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                return result.returncode == 0, result.stdout.strip()
            except Exception:
                return False, ""

    def check_firewall(self):
        """Check if firewall is enabled."""
        # Check iptables
        success, output = self.run_cmd("iptables -L -n 2>/dev/null | head -20")
        if success and "Chain" in output:
            rules = output.count("\n")
            self.check("Firewall (iptables)", rules > 5, f"Found {rules} rules")
            return

        # Check ufw
        success, output = self.run_cmd("ufw status 2>/dev/null")
        if success and "active" in output.lower():
            self.check("Firewall (ufw)", True)
            return

        # Check firewalld
        success, output = self.run_cmd("firewall-cmd --state 2>/dev/null")
        if success and "running" in output.lower():
            self.check("Firewall (firewalld)", True)
            return

        self.check("Firewall", False, "No active firewall detected")

    def check_ssh_config(self):
        """Check SSH hardening."""
        ssh_config = Path("/etc/ssh/sshd_config")
        if not ssh_config.exists():
            self.check("SSH Config", True, "SSH not installed")
            return

        content = ssh_config.read_text()

        # Check root login
        if "PermitRootLogin no" in content or "PermitRootLogin prohibit-password" in content:
            self.check("SSH Root Login Disabled", True)
        else:
            self.check("SSH Root Login Disabled", False, "Root login may be enabled")

        # Check password auth
        if "PasswordAuthentication no" in content:
            self.check("SSH Password Auth Disabled", True)
        else:
            self.check("SSH Password Auth Disabled", False, "Consider using key-based auth only")

    def check_open_ports(self):
        """Check for listening ports."""
        success, output = self.run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if success:
            lines = [l for l in output.split('\n') if 'LISTEN' in l]
            high_risk = []
            for line in lines:
                if ':23 ' in line:  # Telnet
                    high_risk.append("23 (Telnet)")
                if ':21 ' in line:  # FTP
                    high_risk.append("21 (FTP)")
                if ':3389 ' in line:  # RDP
                    high_risk.append("3389 (RDP)")

            if high_risk:
                self.check("High-Risk Ports", False, f"Open: {', '.join(high_risk)}")
            else:
                self.check("High-Risk Ports", True, f"{len(lines)} services listening")

    def check_updates(self):
        """Check for available updates."""
        # Debian/Ubuntu
        success, output = self.run_cmd("apt list --upgradable 2>/dev/null | wc -l")
        if success:
            count = int(output) - 1 if output.isdigit() else 0
            self.check("System Updates", count < 10, f"{count} packages need updating")
            return

        # RHEL/CentOS
        success, output = self.run_cmd("yum check-update 2>/dev/null | wc -l")
        if success:
            self.check("System Updates", int(output) < 10 if output.isdigit() else True)
            return

        self.check("System Updates", True, "Could not check updates")

    def check_users(self):
        """Check user security."""
        # Users with UID 0
        success, output = self.run_cmd("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        if success:
            uid0_users = [u for u in output.split('\n') if u]
            self.check("Root UID Users", len(uid0_users) == 1, f"UID 0 users: {', '.join(uid0_users)}")

        # Empty passwords
        success, output = self.run_cmd("awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null")
        if success:
            empty = [u for u in output.split('\n') if u and u not in ['*', '!']]
            self.check("Empty Passwords", len(empty) == 0, f"Users with empty passwords: {', '.join(empty)}" if empty else "")

    def check_permissions(self):
        """Check critical file permissions."""
        checks = [
            ("/etc/passwd", "644"),
            ("/etc/shadow", "600"),
            ("/etc/ssh/sshd_config", "600"),
        ]

        for filepath, expected in checks:
            p = Path(filepath)
            if p.exists():
                mode = oct(p.stat().st_mode)[-3:]
                passed = int(mode) <= int(expected)
                self.check(f"Permissions {filepath}", passed, f"Mode: {mode} (expected: {expected})")

    def check_services(self):
        """Check for unnecessary services."""
        dangerous = ["telnet", "rsh", "rlogin", "tftp"]
        running = []

        for svc in dangerous:
            success, _ = self.run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if success:
                running.append(svc)
            success, _ = self.run_cmd(f"pgrep -x {svc} 2>/dev/null")
            if success:
                running.append(svc)

        self.check("Dangerous Services", len(running) == 0, f"Running: {', '.join(running)}" if running else "")

    def check_fail2ban(self):
        """Check if fail2ban is installed and running."""
        success, output = self.run_cmd("systemctl is-active fail2ban 2>/dev/null")
        if success and "active" in output:
            self.check("Fail2Ban", True, "Running")
        else:
            success, _ = self.run_cmd("which fail2ban-client 2>/dev/null")
            if success:
                self.check("Fail2Ban", False, "Installed but not running")
            else:
                self.check("Fail2Ban", False, "Not installed")

    def check_selinux(self):
        """Check SELinux/AppArmor status."""
        success, output = self.run_cmd("getenforce 2>/dev/null")
        if success:
            enforcing = output.strip().lower() == "enforcing"
            self.check("SELinux", enforcing, f"Status: {output.strip()}")
            return

        success, output = self.run_cmd("aa-status 2>/dev/null | head -1")
        if success and "apparmor" in output.lower():
            self.check("AppArmor", True, "Active")
            return

        self.check("MAC (SELinux/AppArmor)", False, "No mandatory access control")

    # ==================== SCAN MONITOR ====================

    def scan_monitor(self):
        """Setup and launch the scan monitor."""
        print(f"\n{Colors.BOLD}Scan Monitor Setup{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Check tcpdump
        from core.paths import find_tool
        if not find_tool('tcpdump'):
            self.print_status("tcpdump is not installed", "error")
            return

        counter_input = input(f"{Colors.WHITE}Enable counter-scan on detected attackers? (y/n) [{Colors.GREEN}y{Colors.WHITE}]: {Colors.RESET}").strip().lower()
        counter_scan = counter_input != 'n'

        whitelist_input = input(f"{Colors.WHITE}Whitelist IPs (comma-separated, or blank): {Colors.RESET}").strip()
        whitelist = [ip.strip() for ip in whitelist_input.split(',') if ip.strip()] if whitelist_input else []

        # Ensure results dir exists
        os.makedirs("results", exist_ok=True)

        self._monitor_with_tcpdump(counter_scan, whitelist)

    def _counter_scan(self, ip: str, log_file: str):
        """Counter-scan a detected attacker IP."""
        try:
            print(f"           {Colors.CYAN}[*] Counter-scanning {ip}...{Colors.RESET}")
            result = subprocess.run(
                f"nmap --top-ports 100 -T4 -sV {ip}",
                shell=True, capture_output=True, text=True, timeout=120
            )
            output = result.stdout

            # Parse open ports
            open_ports = []
            for line in output.split('\n'):
                if 'open' in line.lower() and ('tcp' in line.lower() or 'udp' in line.lower() or '/' in line):
                    port = line.split('/')[0].strip()
                    open_ports.append(port)

            if open_ports:
                ports_str = ','.join(open_ports)
                print(f"           {Colors.GREEN}[+] Counter-scan {ip}: {len(open_ports)} open ports ({ports_str}){Colors.RESET}")
            else:
                print(f"           {Colors.YELLOW}[+] Counter-scan {ip}: no open ports found{Colors.RESET}")

            # Append to log
            with open(log_file, 'a') as f:
                f.write(f"\n--- Counter-scan {ip} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                f.write(output)
                f.write("\n")

        except subprocess.TimeoutExpired:
            print(f"           {Colors.YELLOW}[!] Counter-scan {ip} timed out{Colors.RESET}")
        except Exception as e:
            print(f"           {Colors.RED}[X] Counter-scan {ip} failed: {e}{Colors.RESET}")

    def _monitor_with_tcpdump(self, counter_scan: bool, whitelist: list):
        """Core monitoring loop using tcpdump."""
        log_file = "results/scan_monitor.log"

        # Get local IPs to skip
        local_ips = {'127.0.0.1'}
        try:
            hostname = socket.gethostname()
            local_ips.add(socket.gethostbyname(hostname))
        except:
            pass
        try:
            result = subprocess.run(
                "hostname -I", shell=True, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for ip in result.stdout.strip().split():
                    local_ips.add(ip.strip())
        except:
            pass

        # Display header
        print(f"\n{Colors.BOLD}  Scan Monitor Active  {Colors.RED}[Ctrl+C to stop]{Colors.RESET}")
        print(f"  {Colors.CYAN}{'─' * 50}{Colors.RESET}")
        counter_str = f"{Colors.GREEN}Enabled{Colors.RESET}" if counter_scan else f"{Colors.RED}Disabled{Colors.RESET}"
        print(f"  Counter-scan: {counter_str} | Log: {log_file}")
        if whitelist:
            print(f"  Whitelisted: {', '.join(whitelist)}")
        print(f"  Local IPs: {', '.join(sorted(local_ips))}")
        print(f"  Monitoring on all interfaces...\n")

        # SYN-only filter: tcp-syn set AND tcp-ack NOT set
        # Use sudo if not root (tcpdump needs packet capture privileges)
        if os.geteuid() == 0:
            tcpdump_cmd = [
                "tcpdump", "-i", "any", "-n", "-l", "--immediate-mode",
                "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
            ]
        else:
            tcpdump_cmd = [
                "sudo", "tcpdump", "-i", "any", "-n", "-l", "--immediate-mode",
                "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
            ]

        # Tracking dict per source IP
        trackers = {}
        packet_re = re.compile(r'IP (\d+\.\d+\.\d+\.\d+)\.\d+ > [\d.]+\.(\d+):')
        total_packets = 0
        threats_detected = 0
        ips_logged = set()
        last_prune = time.time()

        proc = None
        try:
            proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            for raw_line in iter(proc.stdout.readline, b''):
                line = raw_line.decode('utf-8', errors='ignore').strip()
                if not line:
                    continue

                m = packet_re.search(line)
                if not m:
                    continue

                src_ip = m.group(1)
                dst_port = int(m.group(2))
                total_packets += 1
                now = time.time()

                # Skip whitelisted and local
                if src_ip in whitelist or src_ip in local_ips:
                    continue

                # Update tracker
                if src_ip not in trackers:
                    trackers[src_ip] = {
                        'ports': set(),
                        'port_counts': {},
                        'first_seen': now,
                        'last_seen': now,
                        'alerted_scan': False,
                        'alerted_brute': set(),
                    }

                t = trackers[src_ip]
                t['ports'].add(dst_port)
                t['port_counts'][dst_port] = t['port_counts'].get(dst_port, 0) + 1
                t['last_seen'] = now

                # Check port scan threshold: 10+ unique ports in 30s
                if not t['alerted_scan'] and len(t['ports']) >= 10:
                    elapsed = now - t['first_seen']
                    if elapsed <= 30:
                        t['alerted_scan'] = True
                        threats_detected += 1
                        ips_logged.add(src_ip)
                        ts = datetime.now().strftime('%H:%M:%S')
                        msg = f"PORT SCAN detected from {src_ip} ({len(t['ports'])} ports in {int(elapsed)}s)"
                        print(f"  {ts} {Colors.RED}[!] {msg}{Colors.RESET}")

                        with open(log_file, 'a') as f:
                            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

                        if counter_scan:
                            thread = threading.Thread(
                                target=self._counter_scan, args=(src_ip, log_file), daemon=True
                            )
                            thread.start()

                # Check brute force threshold: 15+ connections to single port in 60s
                for port, count in t['port_counts'].items():
                    if port not in t['alerted_brute'] and count >= 15:
                        elapsed = now - t['first_seen']
                        if elapsed <= 60:
                            t['alerted_brute'].add(port)
                            threats_detected += 1
                            ips_logged.add(src_ip)
                            ts = datetime.now().strftime('%H:%M:%S')
                            msg = f"BRUTE FORCE detected from {src_ip} ({count} connections to port {port} in {int(elapsed)}s)"
                            print(f"  {ts} {Colors.YELLOW}[!] {msg}{Colors.RESET}")

                            with open(log_file, 'a') as f:
                                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")

                            if counter_scan:
                                thread = threading.Thread(
                                    target=self._counter_scan, args=(src_ip, log_file), daemon=True
                                )
                                thread.start()

                # Prune stale entries every 5 seconds
                if now - last_prune >= 5:
                    stale = [ip for ip, tr in trackers.items() if now - tr['last_seen'] > 120]
                    for ip in stale:
                        del trackers[ip]
                    last_prune = now

        except KeyboardInterrupt:
            pass
        finally:
            if proc:
                proc.kill()
                proc.wait()

        # Summary
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Scan Monitor Summary{Colors.RESET}")
        print(f"  Total SYN packets:  {total_packets}")
        print(f"  Threats detected:   {threats_detected}")
        print(f"  Unique attacker IPs: {len(ips_logged)}")
        if ips_logged:
            print(f"  IPs logged: {', '.join(sorted(ips_logged))}")
        print(f"  Log file: {log_file}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")

    # ==================== HONEYPOT ====================

    HONEYPOT_BANNERS = {
        22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
        21: "220 FTP server ready.\r\n",
        80: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n<html><body>It works!</body></html>",
        23: "\xff\xfb\x01\xff\xfb\x03",
        3389: "",
        25: "220 mail.example.com ESMTP\r\n",
        3306: "5.7.38-0ubuntu0.20.04.1\x00",
    }

    def honeypot(self):
        """Honeypot setup submenu."""
        print(f"\n{Colors.BOLD}Honeypot Setup{Colors.RESET}")
        print(f"{Colors.DIM}Deploy fake service listeners to trap scanners{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        port_input = input(f"{Colors.WHITE}Ports to listen on [{Colors.GREEN}22,21,80,23,3389,25,3306{Colors.WHITE}]: {Colors.RESET}").strip()
        if not port_input:
            port_input = "22,21,80,23,3389,25,3306"

        try:
            ports = [int(p.strip()) for p in port_input.split(',')]
        except ValueError:
            self.print_status("Invalid port list", "error")
            return

        log_input = input(f"{Colors.WHITE}Enable logging? (y/n) [{Colors.GREEN}y{Colors.WHITE}]: {Colors.RESET}").strip().lower()
        enable_log = log_input != 'n'

        os.makedirs("results", exist_ok=True)
        log_file = "results/honeypot.log" if enable_log else None

        port_config = {}
        for p in ports:
            port_config[p] = self.HONEYPOT_BANNERS.get(p, "")

        self._run_honeypot(port_config, log_file)

    def _run_honeypot(self, ports: dict, log_file: str):
        """Start honeypot listeners on configured ports."""
        connections = []
        sockets_list = []
        threads = []

        print(f"\n{Colors.BOLD}  Honeypot Active  {Colors.RED}[Ctrl+C to stop]{Colors.RESET}")
        print(f"  {Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"  Listening on ports: {', '.join(str(p) for p in ports.keys())}")
        if log_file:
            print(f"  Log file: {log_file}")
        print()

        for port, banner in ports.items():
            t = threading.Thread(
                target=self._honeypot_listener,
                args=(port, banner, log_file, connections, sockets_list),
                daemon=True
            )
            threads.append(t)
            t.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        # Close all sockets
        for s in sockets_list:
            try:
                s.close()
            except:
                pass

        # Summary
        unique_ips = set(c['ip'] for c in connections)
        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Honeypot Summary{Colors.RESET}")
        print(f"  Total connections: {len(connections)}")
        print(f"  Unique IPs:       {len(unique_ips)}")
        if unique_ips:
            print(f"  IPs seen: {', '.join(sorted(unique_ips))}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")

    def _honeypot_listener(self, port: int, banner: str, log_file: str, connections: list, sockets_list: list):
        """Listen on a single port for honeypot connections."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            sockets_list.append(s)
        except OSError as e:
            self.print_status(f"Cannot bind port {port}: {e}", "error")
            return

        while True:
            try:
                conn, addr = s.accept()
                ip = addr[0]
                ts = datetime.now().strftime('%H:%M:%S')

                try:
                    data = conn.recv(1024)
                    data_len = len(data)
                except:
                    data_len = 0

                connections.append({'ip': ip, 'port': port, 'time': ts})

                print(f"  {ts} {Colors.RED}[TRAP]{Colors.RESET} Connection from {Colors.YELLOW}{ip}{Colors.RESET} on port {Colors.CYAN}{port}{Colors.RESET}")

                if log_file:
                    try:
                        with open(log_file, 'a') as f:
                            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HONEYPOT src={ip} port={port} data_len={data_len}\n")
                    except:
                        pass

                if banner:
                    try:
                        conn.send(banner.encode() if isinstance(banner, str) else banner)
                    except:
                        pass

                conn.close()
            except OSError:
                break

    # ==================== LOG ANALYZER ====================

    def log_analyzer(self):
        """Log analyzer submenu."""
        print(f"\n{Colors.BOLD}Log Analyzer{Colors.RESET}")
        print(f"{Colors.DIM}Parse system logs for security threats{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.BLUE}[1]{Colors.RESET} Auth Log Analysis")
        print(f"  {Colors.BLUE}[2]{Colors.RESET} Web Log Analysis")
        print(f"  {Colors.BLUE}[3]{Colors.RESET} All Logs")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

        auth_results = []
        web_results = []

        if choice == "1":
            auth_results = self._analyze_auth_log()
            self._display_log_summary(auth_results, [])
        elif choice == "2":
            web_results = self._analyze_web_logs()
            self._display_log_summary([], web_results)
        elif choice == "3":
            auth_results = self._analyze_auth_log()
            web_results = self._analyze_web_logs()
            self._display_log_summary(auth_results, web_results)

    def _analyze_auth_log(self) -> list:
        """Analyze auth.log for failed login attempts."""
        self.print_status("Analyzing authentication logs...", "info")

        failed_re = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)')
        ip_data = {}

        for log_path in ['/var/log/auth.log', '/var/log/auth.log.1']:
            if not os.path.exists(log_path):
                continue
            try:
                with open(log_path, 'r', errors='ignore') as f:
                    for line in f:
                        m = failed_re.search(line)
                        if m:
                            username = m.group(1)
                            ip = m.group(2)
                            if ip not in ip_data:
                                ip_data[ip] = {'count': 0, 'usernames': set(), 'timestamps': []}
                            ip_data[ip]['count'] += 1
                            ip_data[ip]['usernames'].add(username)
            except PermissionError:
                self.print_status(f"Permission denied: {log_path} (try with sudo)", "warning")
            except Exception as e:
                self.print_status(f"Error reading {log_path}: {e}", "error")

        results = []
        for ip, data in ip_data.items():
            results.append({
                'ip': ip,
                'count': data['count'],
                'usernames': list(data['usernames']),
            })

        results.sort(key=lambda x: x['count'], reverse=True)
        return results

    def _analyze_web_logs(self) -> list:
        """Analyze web server logs for suspicious activity."""
        self.print_status("Analyzing web server logs...", "info")

        findings = []
        web_logs = ['/var/log/apache2/access.log', '/var/log/nginx/access.log']

        sqli_patterns = re.compile(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|drop\s+table|--\s*$)", re.IGNORECASE)
        traversal_pattern = re.compile(r'\.\./|\.\.\\')

        for log_path in web_logs:
            if not os.path.exists(log_path):
                continue

            ip_requests = {}
            ip_errors = {}

            try:
                with open(log_path, 'r', errors='ignore') as f:
                    for line in f:
                        # Extract IP
                        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
                        if not ip_match:
                            continue
                        ip = ip_match.group(1)

                        ip_requests[ip] = ip_requests.get(ip, 0) + 1

                        # Check for 4xx status
                        status_match = re.search(r'" (\d{3}) ', line)
                        if status_match:
                            status = int(status_match.group(1))
                            if 400 <= status < 500:
                                ip_errors[ip] = ip_errors.get(ip, 0) + 1

                        # Check for path traversal
                        if traversal_pattern.search(line):
                            findings.append({'type': 'Path Traversal', 'ip': ip, 'detail': line.strip()[:120], 'severity': 'HIGH'})

                        # Check for SQL injection
                        if sqli_patterns.search(line):
                            findings.append({'type': 'SQL Injection Attempt', 'ip': ip, 'detail': line.strip()[:120], 'severity': 'HIGH'})

                # High request rate
                for ip, count in ip_requests.items():
                    if count > 1000:
                        findings.append({'type': 'High Request Rate', 'ip': ip, 'detail': f'{count} requests', 'severity': 'MEDIUM'})

                # 4xx floods
                for ip, count in ip_errors.items():
                    if count > 100:
                        findings.append({'type': '4xx Error Flood', 'ip': ip, 'detail': f'{count} error responses', 'severity': 'MEDIUM'})

            except PermissionError:
                self.print_status(f"Permission denied: {log_path}", "warning")
            except Exception as e:
                self.print_status(f"Error reading {log_path}: {e}", "error")

        return findings

    def _geoip_lookup(self, ip: str) -> dict:
        """Look up GeoIP information for an IP address."""
        try:
            success, output = self.run_cmd(f"curl -s 'http://ip-api.com/json/{ip}'")
            if success and output:
                data = json.loads(output)
                return {
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                }
        except:
            pass
        return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}

    def _display_log_summary(self, auth_results: list, web_results: list):
        """Display log analysis summary."""
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Log Analysis Summary{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")

        if auth_results:
            total_failures = sum(r['count'] for r in auth_results)
            print(f"\n  {Colors.RED}Total failed logins: {total_failures}{Colors.RESET}")

            # Most targeted usernames
            all_users = {}
            for r in auth_results:
                for u in r['usernames']:
                    all_users[u] = all_users.get(u, 0) + 1
            top_users = sorted(all_users.items(), key=lambda x: -x[1])[:5]
            if top_users:
                print(f"\n  {Colors.CYAN}Most targeted usernames:{Colors.RESET}")
                for user, count in top_users:
                    print(f"    {user:20} {count} attempts")

            # Top attacker IPs with GeoIP
            print(f"\n  {Colors.CYAN}Top 10 Attacker IPs:{Colors.RESET}")
            print(f"  {'IP':<18} {'Attempts':>8}  {'Users':>5}  {'Country':<15} {'ISP'}")
            print(f"  {'─' * 70}")
            for r in auth_results[:10]:
                geo = self._geoip_lookup(r['ip'])
                print(f"  {r['ip']:<18} {r['count']:>8}  {len(r['usernames']):>5}  {geo['country']:<15} {geo['isp'][:25]}")
                time.sleep(0.5)  # Rate limit GeoIP API

            # Offer to block
            if auth_results:
                block = input(f"\n{Colors.WHITE}Block top attacker IPs via firewall? (y/n): {Colors.RESET}").strip().lower()
                if block == 'y':
                    for r in auth_results[:10]:
                        self._fw_block_ip(r['ip'])

        if web_results:
            print(f"\n  {Colors.CYAN}Web Log Findings:{Colors.RESET}")
            for finding in web_results[:20]:
                sev_color = Colors.RED if finding['severity'] == 'HIGH' else Colors.YELLOW
                print(f"  {sev_color}[{finding['severity']}]{Colors.RESET} {finding['type']} from {finding['ip']}")
                print(f"       {Colors.DIM}{finding['detail'][:80]}{Colors.RESET}")

        if not auth_results and not web_results:
            self.print_status("No findings from log analysis", "info")

    # ==================== FIREWALL MANAGER ====================

    def firewall_manager(self):
        """Interactive firewall rule manager."""
        while True:
            print(f"\n{Colors.BOLD}Firewall Manager{Colors.RESET}")
            print(f"{Colors.DIM}Interactive iptables rule builder{Colors.RESET}")
            print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

            print(f"  {Colors.BLUE}[1]{Colors.RESET} View Rules")
            print(f"  {Colors.BLUE}[2]{Colors.RESET} Block IP")
            print(f"  {Colors.BLUE}[3]{Colors.RESET} Unblock IP")
            print(f"  {Colors.BLUE}[4]{Colors.RESET} Rate Limit Port")
            print(f"  {Colors.BLUE}[5]{Colors.RESET} Import from Scan Log")
            print(f"  {Colors.BLUE}[6]{Colors.RESET} Save Ruleset")
            print(f"  {Colors.BLUE}[7]{Colors.RESET} Restore Ruleset")
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    self._fw_view_rules()
                elif choice == "2":
                    self._fw_block_ip()
                elif choice == "3":
                    self._fw_unblock_ip()
                elif choice == "4":
                    self._fw_rate_limit()
                elif choice == "5":
                    self._fw_import_from_scanlog()
                elif choice == "6":
                    self._fw_save_rules()
                elif choice == "7":
                    self._fw_restore_rules()

                if choice in ["1", "2", "3", "4", "5", "6", "7"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def _fw_view_rules(self):
        """View current iptables rules with color coding."""
        print(f"\n{Colors.BOLD}Current Firewall Rules{Colors.RESET}\n")
        success, output = self.run_cmd("sudo iptables -L -n --line-numbers")
        if success and output:
            for line in output.split('\n'):
                if 'DROP' in line:
                    print(f"  {Colors.RED}{line}{Colors.RESET}")
                elif 'ACCEPT' in line:
                    print(f"  {Colors.GREEN}{line}{Colors.RESET}")
                elif 'Chain' in line:
                    print(f"  {Colors.CYAN}{Colors.BOLD}{line}{Colors.RESET}")
                else:
                    print(f"  {line}")
        else:
            self.print_status("Failed to read iptables rules (need sudo?)", "error")

    def _fw_block_ip(self, ip: str = None):
        """Block an IP address with iptables."""
        if ip is None:
            ip = input(f"{Colors.WHITE}IP to block: {Colors.RESET}").strip()
        if not ip:
            return

        success, _ = self.run_cmd(f"sudo iptables -A INPUT -s {ip} -j DROP")
        if success:
            self.print_status(f"Blocked {ip}", "success")
        else:
            self.print_status(f"Failed to block {ip}", "error")

    def _fw_unblock_ip(self):
        """Unblock an IP address."""
        # Show current DROP rules
        success, output = self.run_cmd("sudo iptables -L INPUT -n --line-numbers")
        if not success:
            self.print_status("Failed to read rules", "error")
            return

        drop_rules = []
        for line in output.split('\n'):
            if 'DROP' in line:
                drop_rules.append(line)
                print(f"  {Colors.RED}{line}{Colors.RESET}")

        if not drop_rules:
            self.print_status("No DROP rules found", "info")
            return

        ip = input(f"\n{Colors.WHITE}IP to unblock: {Colors.RESET}").strip()
        if ip:
            success, _ = self.run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
            if success:
                self.print_status(f"Unblocked {ip}", "success")
            else:
                self.print_status(f"Failed to unblock {ip}", "error")

    def _fw_rate_limit(self):
        """Add rate limiting rule for a port."""
        port = input(f"{Colors.WHITE}Port to rate limit: {Colors.RESET}").strip()
        rate = input(f"{Colors.WHITE}Max connections per minute [{Colors.GREEN}25{Colors.WHITE}]: {Colors.RESET}").strip() or "25"

        if not port:
            return

        try:
            int(port)
            int(rate)
        except ValueError:
            self.print_status("Invalid port or rate", "error")
            return

        # Add limit rule then drop excess
        cmd1 = f"sudo iptables -A INPUT -p tcp --dport {port} -m limit --limit {rate}/min --limit-burst 50 -j ACCEPT"
        cmd2 = f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP"

        s1, _ = self.run_cmd(cmd1)
        s2, _ = self.run_cmd(cmd2)

        if s1 and s2:
            self.print_status(f"Rate limit set: port {port} max {rate}/min", "success")
        else:
            self.print_status("Failed to set rate limit", "error")

    def _fw_import_from_scanlog(self):
        """Import IPs from scan monitor log."""
        log_file = "results/scan_monitor.log"
        if not os.path.exists(log_file):
            self.print_status("No scan monitor log found", "warning")
            return

        ip_re = re.compile(r'detected from (\d+\.\d+\.\d+\.\d+)')
        ips = set()

        with open(log_file, 'r') as f:
            for line in f:
                m = ip_re.search(line)
                if m:
                    ips.add(m.group(1))

        if not ips:
            self.print_status("No attacker IPs found in scan log", "info")
            return

        print(f"\n{Colors.CYAN}Found {len(ips)} attacker IPs in scan log:{Colors.RESET}")
        for ip in sorted(ips):
            print(f"  {Colors.RED}{ip}{Colors.RESET}")

        confirm = input(f"\n{Colors.WHITE}Block all {len(ips)} IPs? (y/n): {Colors.RESET}").strip().lower()
        if confirm == 'y':
            for ip in ips:
                self._fw_block_ip(ip)

    def _fw_save_rules(self):
        """Save current iptables rules to file."""
        os.makedirs("results", exist_ok=True)
        filename = f"results/iptables_{datetime.now().strftime('%Y%m%d_%H%M%S')}.rules"
        success, output = self.run_cmd("sudo iptables-save")
        if success and output:
            with open(filename, 'w') as f:
                f.write(output)
            self.print_status(f"Rules saved to {filename}", "success")
        else:
            self.print_status("Failed to save rules", "error")

    def _fw_restore_rules(self):
        """Restore iptables rules from file."""
        # List saved rule files
        rule_files = sorted(Path("results").glob("iptables_*.rules")) if Path("results").exists() else []
        if not rule_files:
            self.print_status("No saved rulesets found", "warning")
            return

        print(f"\n{Colors.CYAN}Saved Rulesets:{Colors.RESET}")
        for i, f in enumerate(rule_files, 1):
            print(f"  {Colors.BLUE}[{i}]{Colors.RESET} {f.name}")

        choice = input(f"\n{Colors.WHITE}Select ruleset: {Colors.RESET}").strip()
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(rule_files):
                success, _ = self.run_cmd(f"sudo iptables-restore < {rule_files[idx]}")
                if success:
                    self.print_status(f"Rules restored from {rule_files[idx].name}", "success")
                else:
                    self.print_status("Failed to restore rules", "error")
        except (ValueError, IndexError):
            self.print_status("Invalid selection", "error")

    def show_menu(self):
        """Display defender menu."""
        clear_screen()
        display_banner()

        print(f"{Colors.BLUE}{Colors.BOLD}  System Defender{Colors.RESET}")
        print(f"{Colors.DIM}  Security hardening assessment{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.GREEN}[M]{Colors.RESET} {Colors.BOLD}My System{Colors.RESET} - Full audit with CVE detection & auto-fix")
        print()
        print(f"  {Colors.BLUE}[1]{Colors.RESET} Quick Security Audit")
        print(f"  {Colors.BLUE}[2]{Colors.RESET} Firewall Check")
        print(f"  {Colors.BLUE}[3]{Colors.RESET} SSH Hardening Check")
        print(f"  {Colors.BLUE}[4]{Colors.RESET} Open Ports Scan")
        print(f"  {Colors.BLUE}[5]{Colors.RESET} User Security Check")
        print(f"  {Colors.BLUE}[6]{Colors.RESET} File Permissions Check")
        print(f"  {Colors.BLUE}[7]{Colors.RESET} Service Audit")
        print(f"  {Colors.BLUE}[8]{Colors.RESET} Scan Monitor       - Detect & counter incoming scans")
        print(f"  {Colors.BLUE}[9]{Colors.RESET} Honeypot           - Fake service listeners to trap scanners")
        print()
        print(f"  {Colors.MAGENTA}[A]{Colors.RESET} Firewall Manager   - Interactive iptables rule builder")
        print(f"  {Colors.MAGENTA}[B]{Colors.RESET} Log Analyzer       - Parse system logs for threats")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def full_audit(self):
        """Run all checks."""
        print(f"\n{Colors.BOLD}Running Full Security Audit...{Colors.RESET}\n")
        self.results = []

        self.check_firewall()
        self.check_ssh_config()
        self.check_open_ports()
        self.check_updates()
        self.check_users()
        self.check_permissions()
        self.check_services()
        self.check_fail2ban()
        self.check_selinux()

        # Summary
        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)
        score = int((passed / total) * 100) if total > 0 else 0

        print(f"\n{Colors.BOLD}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Security Score: {score}% ({passed}/{total} checks passed){Colors.RESET}")

        if score >= 80:
            print(f"{Colors.GREEN}Status: Good security posture{Colors.RESET}")
        elif score >= 50:
            print(f"{Colors.YELLOW}Status: Needs improvement{Colors.RESET}")
        else:
            print(f"{Colors.RED}Status: Critical - immediate action required{Colors.RESET}")

    def run(self):
        """Main loop."""
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == "0":
                    break
                elif choice == "m":
                    # Launch My System module
                    try:
                        from modules.mysystem import MySystem
                        MySystem().run()
                    except ImportError as e:
                        print(f"{Colors.RED}[X] Failed to load My System module: {e}{Colors.RESET}")
                        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                    continue
                elif choice == "1":
                    self.full_audit()
                elif choice == "2":
                    print()
                    self.results = []
                    self.check_firewall()
                elif choice == "3":
                    print()
                    self.results = []
                    self.check_ssh_config()
                elif choice == "4":
                    print()
                    self.results = []
                    self.check_open_ports()
                elif choice == "5":
                    print()
                    self.results = []
                    self.check_users()
                elif choice == "6":
                    print()
                    self.results = []
                    self.check_permissions()
                elif choice == "7":
                    print()
                    self.results = []
                    self.check_services()
                    self.check_fail2ban()
                    self.check_selinux()
                elif choice == "8":
                    self.scan_monitor()
                elif choice == "9":
                    self.honeypot()
                elif choice == "a":
                    self.firewall_manager()
                    continue
                elif choice == "b":
                    self.log_analyzer()

                if choice in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    Defender().run()


if __name__ == "__main__":
    run()
