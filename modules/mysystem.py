"""
AUTARCH My System Module
Comprehensive system security audit with CVE detection and remediation

Performs full system audit, saves results, and offers LLM-assisted or manual fixes.
"""

import os
import sys
import json
import subprocess
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# Module metadata
DESCRIPTION = "System audit with CVE detection & auto-fix"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner
from core.config import get_config
from core.cve import get_cve_db


class SecurityIssue:
    """Represents a security issue found during audit."""

    SEVERITY_COLORS = {
        'CRITICAL': Colors.RED,
        'HIGH': Colors.RED,
        'MEDIUM': Colors.YELLOW,
        'LOW': Colors.CYAN,
        'INFO': Colors.DIM,
    }

    def __init__(
        self,
        name: str,
        description: str,
        severity: str,
        category: str,
        fix_command: str = None,
        fix_instructions: str = None,
        cve_ids: List[str] = None
    ):
        self.name = name
        self.description = description
        self.severity = severity.upper()
        self.category = category
        self.fix_command = fix_command
        self.fix_instructions = fix_instructions
        self.cve_ids = cve_ids or []
        self.status = "open"  # open, fixed, ignored

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'fix_command': self.fix_command,
            'fix_instructions': self.fix_instructions,
            'cve_ids': self.cve_ids,
            'status': self.status,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'SecurityIssue':
        issue = cls(
            name=data.get('name', ''),
            description=data.get('description', ''),
            severity=data.get('severity', 'MEDIUM'),
            category=data.get('category', 'general'),
            fix_command=data.get('fix_command'),
            fix_instructions=data.get('fix_instructions'),
            cve_ids=data.get('cve_ids', []),
        )
        issue.status = data.get('status', 'open')
        return issue


class MySystem:
    """Comprehensive system security auditor."""

    @staticmethod
    def _system_inf_path():
        from core.paths import get_app_dir
        return get_app_dir() / "system.inf"

    def __init__(self):
        self.issues: List[SecurityIssue] = []
        self.system_info: Dict = {}
        self.audit_results: Dict = {}
        self.security_score: int = 100
        self.cve_db = get_cve_db()
        self.llm = None

    def print_status(self, message: str, status: str = "info"):
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED
        }
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str, timeout: int = 10) -> tuple:
        """Run command and return (success, output)."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except:
            return False, ""

    def collect_system_info(self):
        """Collect comprehensive system information."""
        self.print_status("Collecting system information...")

        info = self.cve_db.get_system_info()

        # Additional system info
        success, output = self.run_cmd("hostname")
        info['hostname'] = output if success else 'unknown'

        success, output = self.run_cmd("uptime -p 2>/dev/null || uptime")
        info['uptime'] = output if success else 'unknown'

        success, output = self.run_cmd("whoami")
        info['current_user'] = output if success else 'unknown'

        success, output = self.run_cmd("cat /proc/meminfo 2>/dev/null | grep MemTotal | awk '{print $2}'")
        if success and output:
            info['memory_kb'] = int(output)
            info['memory_gb'] = round(int(output) / 1024 / 1024, 1)

        success, output = self.run_cmd("nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null")
        info['cpu_cores'] = int(output) if success and output.isdigit() else 0

        self.system_info = info

    def add_issue(
        self,
        name: str,
        description: str,
        severity: str,
        category: str,
        fix_command: str = None,
        fix_instructions: str = None,
        score_penalty: int = 5
    ):
        """Add a security issue to the list."""
        issue = SecurityIssue(
            name=name,
            description=description,
            severity=severity,
            category=category,
            fix_command=fix_command,
            fix_instructions=fix_instructions,
        )
        self.issues.append(issue)

        # Adjust score based on severity
        penalties = {'CRITICAL': 20, 'HIGH': 15, 'MEDIUM': 10, 'LOW': 5, 'INFO': 0}
        self.security_score -= penalties.get(severity.upper(), score_penalty)
        self.security_score = max(0, self.security_score)

    # =========================================================================
    # AUDIT CHECKS
    # =========================================================================

    def check_firewall(self):
        """Check firewall status."""
        self.print_status("Checking firewall...")

        # Check iptables
        success, output = self.run_cmd("iptables -L -n 2>/dev/null | head -20")
        if success and "Chain" in output:
            rules = output.count("\n")
            if rules > 5:
                self.audit_results['firewall'] = {'status': 'enabled', 'type': 'iptables', 'rules': rules}
                return
            else:
                self.add_issue(
                    "Firewall - Minimal Rules",
                    f"iptables has only {rules} rules configured",
                    "MEDIUM",
                    "network",
                    fix_instructions="Configure iptables with appropriate rules or use ufw/firewalld for easier management"
                )
                return

        # Check ufw
        success, output = self.run_cmd("ufw status 2>/dev/null")
        if success and "active" in output.lower():
            self.audit_results['firewall'] = {'status': 'enabled', 'type': 'ufw'}
            return

        # Check firewalld
        success, output = self.run_cmd("firewall-cmd --state 2>/dev/null")
        if success and "running" in output.lower():
            self.audit_results['firewall'] = {'status': 'enabled', 'type': 'firewalld'}
            return

        # No firewall
        self.add_issue(
            "No Active Firewall",
            "No firewall (iptables/ufw/firewalld) is currently active",
            "HIGH",
            "network",
            fix_command="sudo ufw enable",
            fix_instructions="Enable UFW: sudo ufw enable\nOr install: sudo apt install ufw && sudo ufw enable"
        )

    def check_ssh_config(self):
        """Check SSH hardening."""
        self.print_status("Checking SSH configuration...")

        ssh_config = Path("/etc/ssh/sshd_config")
        if not ssh_config.exists():
            self.audit_results['ssh'] = {'status': 'not_installed'}
            return

        try:
            content = ssh_config.read_text()
        except PermissionError:
            success, content = self.run_cmd("sudo cat /etc/ssh/sshd_config 2>/dev/null")
            if not success:
                self.audit_results['ssh'] = {'status': 'permission_denied'}
                return

        self.audit_results['ssh'] = {'status': 'installed', 'issues': []}

        # Check root login
        if "PermitRootLogin no" not in content and "PermitRootLogin prohibit-password" not in content:
            self.add_issue(
                "SSH Root Login Enabled",
                "Root login via SSH is not disabled",
                "HIGH",
                "ssh",
                fix_command="sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
                fix_instructions="Edit /etc/ssh/sshd_config:\n  PermitRootLogin no\nThen restart: sudo systemctl restart sshd"
            )

        # Check password auth
        if "PasswordAuthentication no" not in content:
            self.add_issue(
                "SSH Password Auth Enabled",
                "Password authentication is enabled (key-based is more secure)",
                "MEDIUM",
                "ssh",
                fix_command="sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd",
                fix_instructions="Edit /etc/ssh/sshd_config:\n  PasswordAuthentication no\nEnsure you have SSH keys set up first!"
            )

        # Check protocol version
        if "Protocol 1" in content:
            self.add_issue(
                "SSH Protocol 1 Enabled",
                "Insecure SSH Protocol 1 is enabled",
                "CRITICAL",
                "ssh",
                fix_instructions="Remove 'Protocol 1' from /etc/ssh/sshd_config"
            )

    def check_open_ports(self):
        """Check for listening ports."""
        self.print_status("Scanning open ports...")

        success, output = self.run_cmd("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if not success:
            return

        lines = [l for l in output.split('\n') if 'LISTEN' in l]
        self.audit_results['ports'] = {'listening': len(lines), 'high_risk': []}

        high_risk_ports = {
            '21': ('FTP', 'HIGH', 'FTP transmits credentials in plaintext'),
            '23': ('Telnet', 'CRITICAL', 'Telnet is unencrypted'),
            '69': ('TFTP', 'HIGH', 'TFTP has no authentication'),
            '111': ('RPC', 'MEDIUM', 'RPC can expose services'),
            '135': ('MS-RPC', 'HIGH', 'Windows RPC - potential attack vector'),
            '139': ('NetBIOS', 'HIGH', 'NetBIOS session service'),
            '445': ('SMB', 'HIGH', 'SMB - common attack target'),
            '512': ('rexec', 'CRITICAL', 'Insecure remote execution'),
            '513': ('rlogin', 'CRITICAL', 'Insecure remote login'),
            '514': ('rsh', 'CRITICAL', 'Insecure remote shell'),
            '1433': ('MSSQL', 'MEDIUM', 'Database port exposed'),
            '3306': ('MySQL', 'MEDIUM', 'Database port exposed'),
            '3389': ('RDP', 'HIGH', 'Remote Desktop exposed'),
            '5432': ('PostgreSQL', 'MEDIUM', 'Database port exposed'),
            '5900': ('VNC', 'HIGH', 'VNC often weakly configured'),
        }

        for line in lines:
            for port, (name, severity, desc) in high_risk_ports.items():
                if f':{port} ' in line or f':{port}\t' in line:
                    self.audit_results['ports']['high_risk'].append(port)
                    self.add_issue(
                        f"High-Risk Port Open: {port} ({name})",
                        desc,
                        severity,
                        "network",
                        fix_instructions=f"Disable the {name} service if not needed:\n  sudo systemctl stop <service>\n  sudo systemctl disable <service>"
                    )

    def check_users(self):
        """Check user security."""
        self.print_status("Checking user accounts...")

        self.audit_results['users'] = {'issues': []}

        # Users with UID 0
        success, output = self.run_cmd("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        if success:
            uid0_users = [u for u in output.split('\n') if u]
            if len(uid0_users) > 1:
                extra_roots = [u for u in uid0_users if u != 'root']
                self.add_issue(
                    "Multiple Root Users",
                    f"Users with UID 0 besides root: {', '.join(extra_roots)}",
                    "CRITICAL",
                    "users",
                    fix_instructions="Review and remove extra UID 0 accounts:\n  sudo vipw\n  Change UID to non-zero or remove account"
                )

        # Empty passwords
        success, output = self.run_cmd("sudo awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>/dev/null")
        if success and output:
            empty = [u for u in output.split('\n') if u]
            if empty:
                self.add_issue(
                    "Users with Empty Passwords",
                    f"Accounts without passwords: {', '.join(empty)}",
                    "CRITICAL",
                    "users",
                    fix_instructions=f"Set passwords for these users:\n  sudo passwd <username>\nOr lock the accounts:\n  sudo usermod -L <username>"
                )

        # Users with shells that shouldn't have them
        success, output = self.run_cmd("awk -F: '($7 != \"/usr/sbin/nologin\" && $7 != \"/bin/false\" && $7 != \"/sbin/nologin\") {print $1}' /etc/passwd")
        if success:
            shell_users = [u for u in output.split('\n') if u]
            self.audit_results['users']['shell_users'] = len(shell_users)

    def check_permissions(self):
        """Check critical file permissions."""
        self.print_status("Checking file permissions...")

        critical_files = [
            ("/etc/passwd", "644", "User database"),
            ("/etc/shadow", "640", "Password hashes"),
            ("/etc/group", "644", "Group database"),
            ("/etc/gshadow", "640", "Group passwords"),
            ("/etc/ssh/sshd_config", "600", "SSH configuration"),
            ("/root", "700", "Root home directory"),
            ("/etc/crontab", "600", "System crontab"),
        ]

        self.audit_results['permissions'] = {'checked': 0, 'issues': 0}

        for filepath, expected, desc in critical_files:
            p = Path(filepath)
            if p.exists():
                self.audit_results['permissions']['checked'] += 1
                try:
                    mode = oct(p.stat().st_mode)[-3:]
                    if int(mode) > int(expected):
                        self.audit_results['permissions']['issues'] += 1
                        self.add_issue(
                            f"Insecure Permissions: {filepath}",
                            f"{desc} has mode {mode} (should be {expected} or less)",
                            "MEDIUM",
                            "permissions",
                            fix_command=f"sudo chmod {expected} {filepath}",
                            fix_instructions=f"Fix permissions:\n  sudo chmod {expected} {filepath}"
                        )
                except:
                    pass

        # Check for world-writable directories
        success, output = self.run_cmd("find /etc -type f -perm -002 2>/dev/null | head -5")
        if success and output:
            files = output.split('\n')
            self.add_issue(
                "World-Writable Files in /etc",
                f"Found {len(files)} world-writable files in /etc",
                "HIGH",
                "permissions",
                fix_instructions="Review and fix permissions:\n  find /etc -type f -perm -002 -exec chmod o-w {} \\;"
            )

    def check_services(self):
        """Check for unnecessary/dangerous services."""
        self.print_status("Auditing services...")

        dangerous_services = [
            ("telnet", "Telnet server"),
            ("rsh", "Remote shell"),
            ("rlogin", "Remote login"),
            ("tftp", "TFTP server"),
            ("vsftpd", "FTP server"),
            ("proftpd", "FTP server"),
            ("pure-ftpd", "FTP server"),
        ]

        self.audit_results['services'] = {'dangerous_running': []}

        for svc, desc in dangerous_services:
            success, _ = self.run_cmd(f"systemctl is-active {svc} 2>/dev/null")
            if success:
                self.audit_results['services']['dangerous_running'].append(svc)
                self.add_issue(
                    f"Dangerous Service Running: {svc}",
                    f"{desc} is running",
                    "HIGH",
                    "services",
                    fix_command=f"sudo systemctl stop {svc} && sudo systemctl disable {svc}",
                    fix_instructions=f"Stop and disable {svc}:\n  sudo systemctl stop {svc}\n  sudo systemctl disable {svc}"
                )

    def check_updates(self):
        """Check for available updates."""
        self.print_status("Checking for updates...")

        self.audit_results['updates'] = {'available': 0, 'security': 0}

        os_id = self.system_info.get('os_id', '')

        if os_id in ['debian', 'ubuntu', 'kali', 'mint']:
            success, output = self.run_cmd("apt list --upgradable 2>/dev/null | grep -c upgradable || echo 0", timeout=30)
            if success and output.isdigit():
                count = int(output)
                self.audit_results['updates']['available'] = count
                if count > 50:
                    self.add_issue(
                        "Many Pending Updates",
                        f"{count} packages need updating",
                        "MEDIUM",
                        "updates",
                        fix_command="sudo apt update && sudo apt upgrade -y",
                        fix_instructions="Update system:\n  sudo apt update\n  sudo apt upgrade"
                    )

        elif os_id in ['fedora', 'rhel', 'centos', 'rocky', 'alma']:
            success, output = self.run_cmd("dnf check-update 2>/dev/null | wc -l", timeout=30)
            if success and output.isdigit():
                self.audit_results['updates']['available'] = int(output)

    def check_fail2ban(self):
        """Check fail2ban status."""
        self.print_status("Checking fail2ban...")

        success, output = self.run_cmd("systemctl is-active fail2ban 2>/dev/null")
        if success and "active" in output:
            self.audit_results['fail2ban'] = {'status': 'running'}
        else:
            success, _ = self.run_cmd("which fail2ban-client 2>/dev/null")
            if success:
                self.add_issue(
                    "Fail2Ban Not Running",
                    "Fail2ban is installed but not running",
                    "MEDIUM",
                    "services",
                    fix_command="sudo systemctl start fail2ban && sudo systemctl enable fail2ban",
                    fix_instructions="Start fail2ban:\n  sudo systemctl start fail2ban\n  sudo systemctl enable fail2ban"
                )
            else:
                self.add_issue(
                    "Fail2Ban Not Installed",
                    "Fail2ban is not installed (protects against brute-force)",
                    "LOW",
                    "services",
                    fix_command="sudo apt install fail2ban -y && sudo systemctl enable fail2ban && sudo systemctl start fail2ban",
                    fix_instructions="Install fail2ban:\n  sudo apt install fail2ban\n  sudo systemctl enable --now fail2ban"
                )

    def check_antivirus(self):
        """Check for antivirus."""
        self.print_status("Checking antivirus...")

        # Check ClamAV
        success, _ = self.run_cmd("which clamscan 2>/dev/null")
        if success:
            self.audit_results['antivirus'] = {'status': 'installed', 'type': 'clamav'}
            return

        # Check for other AV
        for av in ['sophos', 'eset', 'kaspersky']:
            success, _ = self.run_cmd(f"which {av} 2>/dev/null")
            if success:
                self.audit_results['antivirus'] = {'status': 'installed', 'type': av}
                return

        self.add_issue(
            "No Antivirus Installed",
            "No antivirus solution detected",
            "LOW",
            "security",
            fix_command="sudo apt install clamav clamav-daemon -y && sudo freshclam",
            fix_instructions="Install ClamAV:\n  sudo apt install clamav clamav-daemon\n  sudo freshclam"
        )

    def check_cves(self, verbose: bool = True):
        """Check for CVEs affecting this system using local SQLite database."""
        self.print_status("Checking CVE database for system vulnerabilities...")

        # Get database stats
        db_stats = self.cve_db.get_db_stats()

        if db_stats['total_cves'] == 0:
            if verbose:
                print(f"{Colors.YELLOW}[!] Local CVE database is empty. Searching online...{Colors.RESET}")
            # Fall back to online search
            cves = self.cve_db.search_online(
                cpe_name=self.cve_db.system_info.get('cpe_prefix', ''),
                days_back=365,
                max_results=100,
                verbose=verbose
            )
        else:
            if verbose:
                print(f"{Colors.DIM}    Local DB: {db_stats['total_cves']:,} CVEs | Last sync: {db_stats.get('last_sync', 'Never')[:10] if db_stats.get('last_sync') else 'Never'}{Colors.RESET}")
            # Use local database
            cves = self.cve_db.get_system_cves(max_results=100)

        self.audit_results['cves'] = {
            'total': len(cves),
            'critical': sum(1 for c in cves if c.get('severity') == 'CRITICAL'),
            'high': sum(1 for c in cves if c.get('severity') == 'HIGH'),
            'medium': sum(1 for c in cves if c.get('severity') == 'MEDIUM'),
            'low': sum(1 for c in cves if c.get('severity') == 'LOW'),
            'items': cves[:20],  # Keep top 20
            'db_stats': db_stats,
        }

        if verbose:
            print(f"{Colors.GREEN}[+] Found {len(cves)} CVEs for your system{Colors.RESET}")

        # Add critical/high CVEs as issues
        for cve in cves[:10]:
            if cve.get('severity') in ['CRITICAL', 'HIGH']:
                cve_id = cve.get('cve_id') or cve.get('id', '')
                desc = cve.get('description', '')[:150]
                self.add_issue(
                    f"CVE: {cve_id}",
                    desc,
                    cve['severity'],
                    "cve",
                    fix_instructions=f"Check: https://nvd.nist.gov/vuln/detail/{cve_id}\nUpdate affected packages and apply patches.",
                    score_penalty=15 if cve['severity'] == 'CRITICAL' else 10
                )

    # =========================================================================
    # MAIN AUDIT
    # =========================================================================

    def run_full_audit(self, check_cves: bool = True):
        """Run complete system audit."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}{Colors.CYAN}Starting Full System Security Audit{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        self.issues = []
        self.audit_results = {}
        self.security_score = 100

        # Collect info and run checks
        self.collect_system_info()
        self.check_firewall()
        self.check_ssh_config()
        self.check_open_ports()
        self.check_users()
        self.check_permissions()
        self.check_services()
        self.check_updates()
        self.check_fail2ban()
        self.check_antivirus()

        if check_cves:
            self.check_cves()

        print(f"\n{Colors.DIM}{'─' * 50}{Colors.RESET}")
        self.print_summary()

    def print_summary(self):
        """Print audit summary."""
        print(f"\n{Colors.BOLD}Security Audit Summary{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 40}{Colors.RESET}")

        # System info
        print(f"\n{Colors.CYAN}System:{Colors.RESET} {self.system_info.get('os_name', 'Unknown')}")
        print(f"{Colors.CYAN}Hostname:{Colors.RESET} {self.system_info.get('hostname', 'Unknown')}")

        # Issue counts by severity
        critical = sum(1 for i in self.issues if i.severity == 'CRITICAL')
        high = sum(1 for i in self.issues if i.severity == 'HIGH')
        medium = sum(1 for i in self.issues if i.severity == 'MEDIUM')
        low = sum(1 for i in self.issues if i.severity == 'LOW')

        print(f"\n{Colors.BOLD}Issues Found:{Colors.RESET}")
        if critical:
            print(f"  {Colors.RED}CRITICAL: {critical}{Colors.RESET}")
        if high:
            print(f"  {Colors.RED}HIGH: {high}{Colors.RESET}")
        if medium:
            print(f"  {Colors.YELLOW}MEDIUM: {medium}{Colors.RESET}")
        if low:
            print(f"  {Colors.CYAN}LOW: {low}{Colors.RESET}")

        if not self.issues:
            print(f"  {Colors.GREEN}No issues found!{Colors.RESET}")

        # Security score
        print(f"\n{Colors.BOLD}Security Score: ", end="")
        if self.security_score >= 80:
            print(f"{Colors.GREEN}{self.security_score}/100{Colors.RESET}")
        elif self.security_score >= 50:
            print(f"{Colors.YELLOW}{self.security_score}/100{Colors.RESET}")
        else:
            print(f"{Colors.RED}{self.security_score}/100{Colors.RESET}")

    def save_to_file(self) -> bool:
        """Save audit results to system.inf."""
        try:
            data = {
                'audit_date': datetime.now().isoformat(),
                'system_info': self.system_info,
                'security_score': self.security_score,
                'audit_results': self.audit_results,
                'issues': [i.to_dict() for i in self.issues],
            }

            with open(self._system_inf_path(), 'w') as f:
                json.dump(data, f, indent=2, default=str)

            self.print_status(f"Results saved to {self._system_inf_path()}", "success")
            return True

        except Exception as e:
            self.print_status(f"Failed to save: {e}", "error")
            return False

    def load_from_file(self) -> bool:
        """Load previous audit results from system.inf."""
        if not self._system_inf_path().exists():
            return False

        try:
            with open(self._system_inf_path(), 'r') as f:
                data = json.load(f)

            self.system_info = data.get('system_info', {})
            self.security_score = data.get('security_score', 100)
            self.audit_results = data.get('audit_results', {})
            self.issues = [SecurityIssue.from_dict(i) for i in data.get('issues', [])]

            return True

        except Exception as e:
            self.print_status(f"Failed to load: {e}", "error")
            return False

    # =========================================================================
    # ISSUE REMEDIATION
    # =========================================================================

    def show_issue_details(self, issue: SecurityIssue):
        """Show detailed information about an issue."""
        clear_screen()
        display_banner()

        color = SecurityIssue.SEVERITY_COLORS.get(issue.severity, Colors.WHITE)

        print(f"\n{Colors.BOLD}Issue Details{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        print(f"{Colors.BOLD}Name:{Colors.RESET} {issue.name}")
        print(f"{Colors.BOLD}Severity:{Colors.RESET} {color}{issue.severity}{Colors.RESET}")
        print(f"{Colors.BOLD}Category:{Colors.RESET} {issue.category}")
        print(f"\n{Colors.BOLD}Description:{Colors.RESET}")
        print(f"  {issue.description}")

        if issue.cve_ids:
            print(f"\n{Colors.BOLD}Related CVEs:{Colors.RESET}")
            for cve in issue.cve_ids:
                print(f"  - {cve}")

        if issue.fix_instructions:
            print(f"\n{Colors.BOLD}Manual Fix Instructions:{Colors.RESET}")
            for line in issue.fix_instructions.split('\n'):
                print(f"  {line}")

        if issue.fix_command:
            print(f"\n{Colors.BOLD}Auto-Fix Command:{Colors.RESET}")
            print(f"  {Colors.CYAN}{issue.fix_command}{Colors.RESET}")

        print(f"\n{Colors.DIM}{'─' * 50}{Colors.RESET}")

    def attempt_llm_fix(self, issue: SecurityIssue) -> bool:
        """Use LLM to generate and optionally apply a fix."""
        try:
            from core.llm import get_llm, LLMError
        except ImportError:
            self.print_status("LLM module not available", "error")
            return False

        self.print_status("Consulting LLM for fix recommendation...", "info")

        try:
            llm = get_llm()

            if not llm.is_loaded:
                self.print_status("Loading LLM model...", "info")
                llm.load_model(verbose=True)

            # Build prompt
            prompt = f"""You are a Linux security expert. Analyze this security issue and provide a fix.

System: {self.system_info.get('os_name', 'Linux')}
Issue: {issue.name}
Severity: {issue.severity}
Description: {issue.description}
Category: {issue.category}

Provide:
1. A brief explanation of the risk
2. The exact command(s) to fix this issue
3. Any important warnings or prerequisites

Format your response clearly with sections."""

            print(f"\n{Colors.CYAN}LLM Analysis:{Colors.RESET}\n")

            # Generate response with streaming
            response_text = ""
            for token in llm.generate(prompt, stream=True, max_tokens=500):
                print(token, end="", flush=True)
                response_text += token

            print("\n")

            # Ask if user wants to apply suggested fix
            if issue.fix_command:
                print(f"\n{Colors.YELLOW}Suggested command:{Colors.RESET} {issue.fix_command}")
                choice = input(f"\n{Colors.WHITE}Apply this fix? (y/n): {Colors.RESET}").strip().lower()

                if choice == 'y':
                    print(f"\n{Colors.CYAN}[*] Executing: {issue.fix_command}{Colors.RESET}")
                    success, output = self.run_cmd(issue.fix_command, timeout=60)

                    if success:
                        self.print_status("Fix applied successfully!", "success")
                        issue.status = "fixed"
                        return True
                    else:
                        self.print_status(f"Command failed: {output}", "error")
                        return False

            return True

        except Exception as e:
            self.print_status(f"LLM error: {e}", "error")
            return False

    def apply_manual_fix(self, issue: SecurityIssue) -> bool:
        """Apply the predefined fix command."""
        if not issue.fix_command:
            self.print_status("No automatic fix available for this issue", "warning")
            return False

        print(f"\n{Colors.BOLD}Fix Command:{Colors.RESET}")
        print(f"  {Colors.CYAN}{issue.fix_command}{Colors.RESET}")

        print(f"\n{Colors.YELLOW}Warning: This will modify your system.{Colors.RESET}")
        choice = input(f"{Colors.WHITE}Execute this command? (y/n): {Colors.RESET}").strip().lower()

        if choice != 'y':
            self.print_status("Fix cancelled", "info")
            return False

        print(f"\n{Colors.CYAN}[*] Executing...{Colors.RESET}")
        success, output = self.run_cmd(issue.fix_command, timeout=60)

        if output:
            print(f"\n{Colors.DIM}Output:{Colors.RESET}")
            print(output)

        if success:
            self.print_status("Fix applied successfully!", "success")
            issue.status = "fixed"
            return True
        else:
            self.print_status("Command failed", "error")
            return False

    # =========================================================================
    # MENU SYSTEM
    # =========================================================================

    def show_menu(self):
        """Display main menu."""
        clear_screen()
        display_banner()

        # Load previous results if available
        has_results = self._system_inf_path().exists()

        # Get CVE database stats
        db_stats = self.cve_db.get_db_stats()

        print(f"\n{Colors.BLUE}{Colors.BOLD}  My System - Security Audit{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")

        # Show system info
        sys_info = self.cve_db.get_system_info()
        print(f"\n  {Colors.CYAN}Detected:{Colors.RESET} {sys_info.get('os_id', 'unknown')} {sys_info.get('os_version', '')}")
        print(f"  {Colors.CYAN}Kernel:{Colors.RESET} {sys_info.get('kernel', 'unknown')}")

        # Show CVE database status
        if db_stats['total_cves'] > 0:
            last_sync = db_stats.get('last_sync', '')[:10] if db_stats.get('last_sync') else 'Never'
            print(f"  {Colors.CYAN}CVE Database:{Colors.RESET} {db_stats['total_cves']:,} CVEs ({db_stats['db_size_mb']} MB)")
            print(f"  {Colors.CYAN}Last Sync:{Colors.RESET} {last_sync}")
        else:
            print(f"  {Colors.YELLOW}CVE Database:{Colors.RESET} Empty - sync required")

        if has_results and self.issues:
            print(f"  {Colors.CYAN}Last Score:{Colors.RESET} {self.security_score}/100")
            print(f"  {Colors.CYAN}Open Issues:{Colors.RESET} {sum(1 for i in self.issues if i.status == 'open')}")

        print(f"\n{Colors.DIM}  {'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Run Full System Audit")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Run Audit (Skip CVE Check)")

        if has_results:
            print(f"\n  {Colors.CYAN}[3]{Colors.RESET} View Issues ({len(self.issues)} found)")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} View CVE Report")

        print(f"\n  {Colors.YELLOW}[5]{Colors.RESET} Search CVE Database")
        print(f"  {Colors.YELLOW}[6]{Colors.RESET} Check Software for CVEs")

        print(f"\n  {Colors.MAGENTA}[7]{Colors.RESET} Sync CVE Database (Recent)")
        print(f"  {Colors.MAGENTA}[8]{Colors.RESET} Sync CVE Database (Full)")
        print(f"  {Colors.MAGENTA}[9]{Colors.RESET} CVE Database Info")

        print(f"\n  {Colors.DIM}[0]{Colors.RESET} Back to Main Menu")
        print()

    def show_issues_menu(self):
        """Display issues as selectable options."""
        if not self.issues:
            self.print_status("No issues found. Run an audit first.", "info")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        while True:
            clear_screen()
            display_banner()

            open_issues = [i for i in self.issues if i.status == 'open']
            fixed_issues = [i for i in self.issues if i.status == 'fixed']

            print(f"\n{Colors.BOLD}Security Issues{Colors.RESET}")
            print(f"{Colors.DIM}Score: {self.security_score}/100 | Open: {len(open_issues)} | Fixed: {len(fixed_issues)}{Colors.RESET}")
            print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

            if not open_issues:
                print(f"{Colors.GREEN}All issues have been addressed!{Colors.RESET}")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

            # List issues
            for idx, issue in enumerate(open_issues, 1):
                color = SecurityIssue.SEVERITY_COLORS.get(issue.severity, Colors.WHITE)
                severity_badge = f"{color}[{issue.severity[:4]}]{Colors.RESET}"
                print(f"  [{idx:2}] {severity_badge} {issue.name}")

            print(f"\n  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select issue to fix: {Colors.RESET}").strip()

                if choice == '0':
                    break

                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(open_issues):
                        self.handle_issue(open_issues[idx])

            except (EOFError, KeyboardInterrupt):
                break

    def handle_issue(self, issue: SecurityIssue):
        """Handle remediation of a single issue."""
        self.show_issue_details(issue)

        print(f"\n  {Colors.GREEN}[1]{Colors.RESET} Auto-Fix with LLM")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Apply Manual Fix")
        print(f"  {Colors.YELLOW}[3]{Colors.RESET} Mark as Ignored")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select action: {Colors.RESET}").strip()

            if choice == '1':
                self.attempt_llm_fix(issue)
                self.save_to_file()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice == '2':
                self.apply_manual_fix(issue)
                self.save_to_file()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            elif choice == '3':
                issue.status = 'ignored'
                self.print_status("Issue marked as ignored", "info")
                self.save_to_file()
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

        except (EOFError, KeyboardInterrupt):
            pass

    def show_cve_report(self):
        """Show CVE report from audit."""
        clear_screen()
        display_banner()

        cve_data = self.audit_results.get('cves', {})

        print(f"\n{Colors.BOLD}CVE Report for Your System{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        print(f"  {Colors.CYAN}Total CVEs:{Colors.RESET} {cve_data.get('total', 0)}")
        print(f"  {Colors.RED}Critical:{Colors.RESET} {cve_data.get('critical', 0)}")
        print(f"  {Colors.RED}High:{Colors.RESET} {cve_data.get('high', 0)}")
        print(f"  {Colors.YELLOW}Medium:{Colors.RESET} {cve_data.get('medium', 0)}")
        print(f"  {Colors.CYAN}Low:{Colors.RESET} {cve_data.get('low', 0)}")

        print(f"\n{Colors.BOLD}Top CVEs:{Colors.RESET}\n")

        for cve in cve_data.get('items', [])[:15]:
            color = SecurityIssue.SEVERITY_COLORS.get(cve['severity'], Colors.WHITE)
            print(f"  {color}{cve['id']}{Colors.RESET} ({cve['severity']}) - CVSS: {cve['cvss_score']}")
            print(f"    {Colors.DIM}{cve['description'][:70]}...{Colors.RESET}")
            print()

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def search_cve_interactive(self):
        """Interactive CVE search."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}CVE Database Search{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        db_stats = self.cve_db.get_db_stats()
        if db_stats['total_cves'] > 0:
            print(f"{Colors.DIM}Local database: {db_stats['total_cves']:,} CVEs{Colors.RESET}\n")
        else:
            print(f"{Colors.YELLOW}Local database empty - will search online{Colors.RESET}\n")

        keyword = input(f"{Colors.WHITE}Search keyword (or Enter for system CVEs): {Colors.RESET}").strip()

        print()
        self.print_status("Searching CVE database...", "info")

        # Try local database first, fall back to online
        if db_stats['total_cves'] > 0:
            if keyword:
                cves = self.cve_db.search_cves(keyword=keyword)
            else:
                cves = self.cve_db.get_system_cves()
        else:
            if keyword:
                cves = self.cve_db.search_online(keyword=keyword, verbose=True)
            else:
                cve_prefix = self.cve_db.system_info.get('cpe_prefix', '')
                cves = self.cve_db.search_online(cpe_name=cve_prefix, verbose=True)

        if not cves:
            self.print_status("No CVEs found", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}Results ({len(cves)} found):{Colors.RESET}\n")

        for cve in cves[:20]:
            color = SecurityIssue.SEVERITY_COLORS.get(cve.get('severity', ''), Colors.WHITE)
            cve_id = cve.get('cve_id') or cve.get('id', '')
            score = cve.get('cvss_score') or cve.get('cvss_v3_score') or 0
            desc = cve.get('description', '')[:80]
            print(f"  {color}{cve_id}{Colors.RESET} - CVSS: {score} ({cve.get('severity', 'N/A')})")
            print(f"    {Colors.DIM}{desc}...{Colors.RESET}")
            print()

        # Option to view details
        cve_id = input(f"\n{Colors.WHITE}Enter CVE ID for details (or Enter to go back): {Colors.RESET}").strip().upper()

        if cve_id:
            # Try local first, then online
            details = self.cve_db.get_cve(cve_id)
            if not details:
                details = self.cve_db.fetch_cve_online(cve_id, verbose=True)
            if details:
                self.show_cve_details(details)
            else:
                self.print_status(f"CVE {cve_id} not found", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def show_cve_details(self, cve: Dict):
        """Show detailed CVE information."""
        clear_screen()
        display_banner()

        cve_id = cve.get('cve_id') or cve.get('id', '')
        print(f"\n{Colors.BOLD}{cve_id}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}\n")

        print(f"{Colors.BOLD}Description:{Colors.RESET}")
        print(f"  {cve.get('description', 'N/A')}\n")

        # CVSS v3
        if cve.get('cvss_v3_score'):
            color = SecurityIssue.SEVERITY_COLORS.get(cve.get('cvss_v3_severity', ''), Colors.WHITE)
            print(f"{Colors.BOLD}CVSS v3:{Colors.RESET}")
            print(f"  Score: {color}{cve['cvss_v3_score']} ({cve.get('cvss_v3_severity', 'N/A')}){Colors.RESET}")
            if cve.get('cvss_v3_vector'):
                print(f"  Vector: {cve['cvss_v3_vector']}")

        # CVSS v2 (if no v3)
        elif cve.get('cvss_v2_score'):
            color = SecurityIssue.SEVERITY_COLORS.get(cve.get('cvss_v2_severity', ''), Colors.WHITE)
            print(f"{Colors.BOLD}CVSS v2:{Colors.RESET}")
            print(f"  Score: {color}{cve['cvss_v2_score']} ({cve.get('cvss_v2_severity', 'N/A')}){Colors.RESET}")
            if cve.get('cvss_v2_vector'):
                print(f"  Vector: {cve['cvss_v2_vector']}")

        if cve.get('published'):
            print(f"\n{Colors.BOLD}Published:{Colors.RESET} {cve['published'][:10]}")

        if cve.get('weaknesses'):
            print(f"\n{Colors.BOLD}Weaknesses (CWE):{Colors.RESET}")
            for w in cve['weaknesses'][:5]:
                print(f"  - {w}")

        if cve.get('references'):
            print(f"\n{Colors.BOLD}References:{Colors.RESET}")
            for ref in cve['references'][:5]:
                url = ref.get('url', ref) if isinstance(ref, dict) else ref
                print(f"  - {url}")

        if cve.get('cpes'):
            print(f"\n{Colors.BOLD}Affected Products:{Colors.RESET}")
            for cpe in cve['cpes'][:5]:
                criteria = cpe.get('cpe_criteria', cpe) if isinstance(cpe, dict) else cpe
                print(f"  - {criteria}")

        print(f"\n{Colors.CYAN}Full details: https://nvd.nist.gov/vuln/detail/{cve_id}{Colors.RESET}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def check_software_cves(self):
        """Check CVEs for specific software."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}Software CVE Check{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        db_stats = self.cve_db.get_db_stats()
        if db_stats['total_cves'] > 0:
            print(f"{Colors.DIM}Local database: {db_stats['total_cves']:,} CVEs{Colors.RESET}\n")

        software = input(f"{Colors.WHITE}Software name (e.g., apache, nginx, openssh): {Colors.RESET}").strip()
        if not software:
            return

        version = input(f"{Colors.WHITE}Version (optional): {Colors.RESET}").strip()

        print()
        self.print_status(f"Searching CVEs for {software}...", "info")

        # Try local database first
        if db_stats['total_cves'] > 0:
            cves = self.cve_db.get_software_cves(software, version=version if version else None)
        else:
            # Fall back to online search
            keyword = f"{software} {version}" if version else software
            cves = self.cve_db.search_online(keyword=keyword, verbose=True)

        if not cves:
            self.print_status("No CVEs found for this software", "success")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        print(f"\n{Colors.BOLD}Found {len(cves)} CVEs:{Colors.RESET}\n")

        for cve in cves[:15]:
            color = SecurityIssue.SEVERITY_COLORS.get(cve.get('severity', ''), Colors.WHITE)
            cve_id = cve.get('cve_id') or cve.get('id', '')
            score = cve.get('cvss_score') or cve.get('cvss_v3_score') or 0
            desc = cve.get('description', '')
            desc = desc[:70] + '...' if len(desc) > 70 else desc
            print(f"  {color}{cve_id}{Colors.RESET} - CVSS: {score} ({cve.get('severity', 'N/A')})")
            print(f"    {Colors.DIM}{desc}{Colors.RESET}")
            print()

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def sync_database_recent(self):
        """Sync recent CVEs (last 120 days)."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}CVE Database Sync (Recent){Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        print(f"This will download CVEs from the last 120 days.")
        print(f"Estimated time: 5-15 minutes (depending on API rate limits)\n")

        confirm = input(f"{Colors.WHITE}Start sync? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        print()
        stats = self.cve_db.sync_database(days_back=120, verbose=True)

        print(f"\n{Colors.BOLD}Sync Complete{Colors.RESET}")
        print(f"  CVEs processed: {stats.get('cves_processed', 0):,}")
        print(f"  Errors: {stats.get('errors', 0)}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def sync_database_full(self):
        """Full database sync (all CVEs since 1999)."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}CVE Database Sync (Full){Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        print(f"{Colors.YELLOW}WARNING: This will download ALL CVEs (200,000+){Colors.RESET}")
        print(f"Estimated time: 2-6 hours (depending on API rate limits)")
        print(f"Database size: ~150-300 MB\n")

        print(f"Consider getting an NVD API key for faster sync:")
        print(f"  https://nvd.nist.gov/developers/request-an-api-key\n")

        confirm = input(f"{Colors.WHITE}Start full sync? (y/n): {Colors.RESET}").strip().lower()
        if confirm != 'y':
            return

        print()
        stats = self.cve_db.sync_database(full_sync=True, verbose=True)

        print(f"\n{Colors.BOLD}Sync Complete{Colors.RESET}")
        print(f"  CVEs processed: {stats.get('cves_processed', 0):,}")
        print(f"  Errors: {stats.get('errors', 0)}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def show_database_info(self):
        """Show CVE database information."""
        clear_screen()
        display_banner()

        print(f"\n{Colors.BOLD}CVE Database Information{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        stats = self.cve_db.get_db_stats()

        print(f"  {Colors.CYAN}Database Path:{Colors.RESET} {stats['db_path']}")
        print(f"  {Colors.CYAN}Database Size:{Colors.RESET} {stats['db_size_mb']} MB")
        print(f"  {Colors.CYAN}Total CVEs:{Colors.RESET} {stats['total_cves']:,}")
        print(f"  {Colors.CYAN}Total CPEs:{Colors.RESET} {stats['total_cpes']:,}")
        print(f"  {Colors.CYAN}Last Sync:{Colors.RESET} {stats.get('last_sync', 'Never')}")

        if stats.get('by_severity'):
            print(f"\n  {Colors.BOLD}CVEs by Severity:{Colors.RESET}")
            for sev, count in sorted(stats['by_severity'].items()):
                color = SecurityIssue.SEVERITY_COLORS.get(sev, Colors.WHITE)
                print(f"    {color}{sev}:{Colors.RESET} {count:,}")

        sys_info = self.cve_db.get_system_info()
        print(f"\n  {Colors.BOLD}System Detection:{Colors.RESET}")
        print(f"    OS: {sys_info.get('os_name', 'Unknown')}")
        print(f"    CPE: {sys_info.get('cpe_prefix', 'Unknown')}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def run(self):
        """Main module loop."""
        # Try to load previous results
        self.load_from_file()

        while True:
            self.show_menu()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == '0':
                    break

                elif choice == '1':
                    self.run_full_audit(check_cves=True)
                    self.save_to_file()
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

                elif choice == '2':
                    self.run_full_audit(check_cves=False)
                    self.save_to_file()
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

                elif choice == '3' and self._system_inf_path().exists():
                    self.show_issues_menu()

                elif choice == '4' and self._system_inf_path().exists():
                    self.show_cve_report()

                elif choice == '5':
                    self.search_cve_interactive()

                elif choice == '6':
                    self.check_software_cves()

                elif choice == '7':
                    self.sync_database_recent()

                elif choice == '8':
                    self.sync_database_full()

                elif choice == '9':
                    self.show_database_info()

            except (EOFError, KeyboardInterrupt):
                break


def run():
    MySystem().run()


if __name__ == "__main__":
    run()
