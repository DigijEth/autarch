"""
AUTARCH Windows Defender Module
Windows-native security posture assessment

Checks Windows system configuration for security best practices.
"""

import os
import sys
import subprocess
import re
import json
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

# Module metadata
DESCRIPTION = "Windows system hardening & security checks"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"


class WindowsDefender:
    """Windows security checker."""

    def __init__(self):
        self.results = []

    def check(self, name: str, passed: bool, details: str = ""):
        """Record a check result."""
        self.results.append({"name": name, "passed": passed, "details": details})

    def run_cmd(self, cmd: str, timeout=15) -> tuple:
        """Run command and return (success, output)."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except Exception:
            return False, ""

    def run_ps(self, ps_command: str, timeout=15) -> tuple:
        """Run a PowerShell command and return (success, output)."""
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps_command}"'
        return self.run_cmd(cmd, timeout=timeout)

    # ==================== SECURITY CHECKS ====================

    def check_firewall(self):
        """Check Windows Firewall status for all profiles."""
        success, output = self.run_cmd("netsh advfirewall show allprofiles state")
        if success:
            profiles_on = output.lower().count("on")
            profiles_off = output.lower().count("off")
            if profiles_off > 0:
                self.check("Windows Firewall", False,
                           f"{profiles_off} profile(s) disabled")
            else:
                self.check("Windows Firewall", True,
                           f"All {profiles_on} profiles enabled")
        else:
            self.check("Windows Firewall", False, "Could not query firewall state")

    def check_ssh_config(self):
        """Check Windows OpenSSH configuration."""
        success, output = self.run_ps(
            "Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*' "
            "| Select-Object -ExpandProperty State"
        )
        if not success or "Installed" not in output:
            self.check("SSH Config", True, "OpenSSH Server not installed (good)")
            return

        sshd_config = Path(os.environ.get('ProgramData', 'C:\\ProgramData')) / 'ssh' / 'sshd_config'
        if not sshd_config.exists():
            self.check("SSH Config", False, "OpenSSH installed but sshd_config not found")
            return

        content = sshd_config.read_text(errors='ignore')

        if "PermitRootLogin no" in content or "PermitRootLogin prohibit-password" in content:
            self.check("SSH Root Login Disabled", True)
        else:
            self.check("SSH Root Login Disabled", False, "Root login may be enabled")

        if "PasswordAuthentication no" in content:
            self.check("SSH Password Auth Disabled", True)
        else:
            self.check("SSH Password Auth Disabled", False,
                        "Consider using key-based auth only")

    def check_open_ports(self):
        """Check for high-risk listening ports on Windows."""
        success, output = self.run_ps(
            "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue "
            "| Select-Object LocalPort, OwningProcess | Format-Table -AutoSize"
        )
        if not success:
            success, output = self.run_cmd("netstat -ano | findstr LISTENING")

        if success:
            high_risk = []
            if ':23 ' in output or '\t23\t' in output:
                high_risk.append("23 (Telnet)")
            if ':21 ' in output or '\t21\t' in output:
                high_risk.append("21 (FTP)")
            if ':3389 ' in output or '\t3389\t' in output:
                high_risk.append("3389 (RDP)")
            if ':445 ' in output or '\t445\t' in output:
                high_risk.append("445 (SMB)")
            if ':135 ' in output or '\t135\t' in output:
                high_risk.append("135 (RPC)")

            lines = [l for l in output.split('\n') if l.strip()]
            if high_risk:
                self.check("High-Risk Ports", False,
                           f"Open: {', '.join(high_risk)}")
            else:
                self.check("High-Risk Ports", True,
                           f"{len(lines)} services listening, no high-risk ports")
        else:
            self.check("High-Risk Ports", True, "Could not enumerate ports")

    def check_updates(self):
        """Check Windows update status."""
        success, output = self.run_ps(
            "Get-HotFix | Sort-Object InstalledOn -Descending "
            "| Select-Object -First 1 -ExpandProperty InstalledOn"
        )
        if success and output.strip():
            self.check("System Updates", True,
                        f"Last update installed: {output.strip()}")
        else:
            success, output = self.run_ps("(Get-HotFix).Count")
            if success and output.strip():
                self.check("System Updates", True,
                           f"{output.strip()} hotfixes installed")
            else:
                self.check("System Updates", False, "Could not query update status")

    def check_users(self):
        """Check Windows user security."""
        # Admin accounts
        success, output = self.run_ps(
            "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue "
            "| Select-Object -ExpandProperty Name"
        )
        if success:
            admins = [u.strip() for u in output.split('\n') if u.strip()]
            self.check("Admin Accounts", len(admins) <= 2,
                        f"Admin users: {', '.join(admins)}")

        # Enabled accounts with no password required
        success, output = self.run_ps(
            "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.PasswordRequired -eq $false} "
            "| Select-Object -ExpandProperty Name"
        )
        if success:
            no_pw = [u.strip() for u in output.split('\n') if u.strip()]
            self.check("Password Required", len(no_pw) == 0,
                        f"No password required: {', '.join(no_pw)}" if no_pw else "All accounts require passwords")

        # Guest account
        success, output = self.run_ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
        if success:
            guest_enabled = output.strip().lower() == 'true'
            self.check("Guest Account Disabled", not guest_enabled,
                        "Guest account is enabled" if guest_enabled else "Guest account disabled")

    def check_permissions(self):
        """Check critical Windows file/folder permissions."""
        critical_paths = [
            (os.environ.get('SystemRoot', 'C:\\Windows') + '\\System32\\config', "SAM Registry Hive"),
            (os.environ.get('ProgramData', 'C:\\ProgramData') + '\\ssh', "SSH Config Dir"),
        ]
        for filepath, label in critical_paths:
            if os.path.exists(filepath):
                success, output = self.run_cmd(f'icacls "{filepath}"')
                if success:
                    has_everyone_full = 'Everyone:(F)' in output or 'Everyone:(OI)(CI)(F)' in output
                    self.check(f"Permissions: {label}", not has_everyone_full,
                               f"Everyone has Full Control on {filepath}" if has_everyone_full else "Restricted")

    def check_services(self):
        """Check for dangerous or unnecessary Windows services."""
        dangerous = {
            "RemoteRegistry": "Remote Registry",
            "TlntSvr": "Telnet Server",
            "SNMP": "SNMP Service",
            "W3SVC": "IIS Web Server",
            "FTPSVC": "FTP Server",
            "SharedAccess": "Internet Connection Sharing",
        }
        running = []
        for svc_name, label in dangerous.items():
            success, output = self.run_ps(
                f"(Get-Service -Name '{svc_name}' -ErrorAction SilentlyContinue).Status"
            )
            if success and 'Running' in output:
                running.append(label)

        self.check("Dangerous Services", len(running) == 0,
                    f"Running: {', '.join(running)}" if running else "No dangerous services running")

    def check_defender(self):
        """Check Windows Defender antivirus status."""
        success, output = self.run_ps(
            "Get-MpComputerStatus -ErrorAction SilentlyContinue "
            "| Select-Object AntivirusEnabled, RealTimeProtectionEnabled, "
            "AntivirusSignatureLastUpdated | Format-List"
        )
        if success:
            av_on = re.search(r'AntivirusEnabled\s*:\s*True', output)
            rt_on = re.search(r'RealTimeProtectionEnabled\s*:\s*True', output)

            if av_on and rt_on:
                sig_match = re.search(r'AntivirusSignatureLastUpdated\s*:\s*(.+)', output)
                sig_date = sig_match.group(1).strip() if sig_match else "Unknown"
                self.check("Windows Defender", True,
                           f"AV enabled, real-time protection on. Signatures: {sig_date}")
            elif av_on:
                self.check("Windows Defender", False,
                           "AV enabled but real-time protection is OFF")
            else:
                self.check("Windows Defender", False, "Windows Defender is disabled")
        else:
            self.check("Windows Defender", False, "Could not query Defender status")

    def check_uac(self):
        """Check UAC (User Account Control) status."""
        success, output = self.run_ps(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name EnableLUA -ErrorAction SilentlyContinue).EnableLUA"
        )
        if success:
            enabled = output.strip() == '1'
            self.check("UAC Enabled", enabled,
                        "UAC is enabled" if enabled else "UAC is DISABLED — critical security risk")

        success, output = self.run_ps(
            "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name ConsentPromptBehaviorAdmin -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin"
        )
        if success and output.strip().isdigit():
            level = int(output.strip())
            level_names = {
                0: "Never notify (DANGEROUS)",
                1: "Prompt on secure desktop (no dimming)",
                2: "Prompt on secure desktop",
                3: "Prompt for credentials",
                4: "Prompt for consent",
                5: "Prompt for consent (default)"
            }
            desc = level_names.get(level, f"Unknown level: {level}")
            self.check("UAC Prompt Level", level >= 2, desc)

    # ==================== FIREWALL MANAGEMENT ====================

    def get_firewall_rules(self):
        """Get all Windows Firewall inbound rules."""
        success, output = self.run_cmd(
            "netsh advfirewall firewall show rule name=all dir=in"
        )
        return success, output

    def block_ip(self, ip):
        """Block an IP via Windows Firewall."""
        rule_name = f"AUTARCH_Block_{ip}"
        success, output = self.run_cmd(
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=block remoteip={ip}'
        )
        return success, f"Blocked {ip}" if success else f"Failed to block {ip} (need admin privileges)"

    def unblock_ip(self, ip):
        """Unblock an IP via Windows Firewall."""
        rule_name = f"AUTARCH_Block_{ip}"
        success, output = self.run_cmd(
            f'netsh advfirewall firewall delete rule name="{rule_name}"'
        )
        return success, f"Unblocked {ip}" if success else f"Failed to unblock {ip}"

    # ==================== EVENT LOG ANALYSIS ====================

    def analyze_event_logs(self):
        """Analyze Windows Security and System event logs."""
        # Failed logins (Event ID 4625)
        success, output = self.run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} "
            "-MaxEvents 500 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, @{N='IP';E={$_.Properties[19].Value}}, "
            "@{N='User';E={$_.Properties[5].Value}} | "
            "Group-Object IP | Sort-Object Count -Descending | "
            "Select-Object Count, Name, @{N='Users';E={($_.Group.User | Select-Object -Unique) -join ','}} | "
            "ConvertTo-Json"
        )
        auth_results = []
        if success and output.strip():
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    auth_results.append({
                        'ip': entry.get('Name', 'Unknown'),
                        'count': entry.get('Count', 0),
                        'usernames': (entry.get('Users', '') or '').split(','),
                    })
            except json.JSONDecodeError:
                pass

        # System warnings/errors
        success, output = self.run_ps(
            "Get-WinEvent -FilterHashtable @{LogName='System'; Level=1,2,3} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated, Id, LevelDisplayName, Message | "
            "ConvertTo-Json"
        )
        system_results = []
        if success and output.strip():
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]
                for entry in data[:20]:
                    system_results.append({
                        'type': entry.get('LevelDisplayName', 'Warning'),
                        'id': entry.get('Id', 0),
                        'time': str(entry.get('TimeCreated', '')),
                        'detail': (entry.get('Message', '') or '')[:200],
                        'severity': 'HIGH' if entry.get('LevelDisplayName') in ('Critical', 'Error') else 'MEDIUM',
                    })
            except json.JSONDecodeError:
                pass

        return auth_results, system_results


# ==================== CLI MENU ====================

def run():
    """CLI entry point."""
    from core.banner import Colors, clear_screen, display_banner
    clear_screen()
    display_banner()
    print(f"\n{Colors.BOLD}{Colors.BLUE}Windows System Defense{Colors.RESET}\n")

    d = WindowsDefender()
    print(f"{Colors.CYAN}Running Windows security audit...{Colors.RESET}\n")

    d.check_firewall()
    d.check_ssh_config()
    d.check_open_ports()
    d.check_updates()
    d.check_users()
    d.check_permissions()
    d.check_services()
    d.check_defender()
    d.check_uac()

    passed = sum(1 for r in d.results if r['passed'])
    total = len(d.results)
    score = int((passed / total) * 100) if total > 0 else 0

    print(f"\n{'=' * 50}")
    color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 50 else Colors.RED
    print(f"{color}Security Score: {score}% ({passed}/{total} checks passed){Colors.RESET}")
    print(f"{'=' * 50}\n")

    input("Press Enter to continue...")
