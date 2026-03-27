"""AUTARCH Incident Response

IR playbook runner, evidence collection, IOC sweeping, timeline building,
containment actions, and post-incident reporting for security operations.
"""

import os
import sys
import json
import time
import platform
import subprocess
import re
import hashlib
import shutil
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

# Module metadata
DESCRIPTION = "Incident response — playbooks, evidence & containment"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = WHITE = DIM = BOLD = RESET = ''
    def clear_screen(): pass
    def display_banner(): pass

_is_win = platform.system() == 'Windows'

# ── Valid enumerations ──────────────────────────────────────────────

INCIDENT_TYPES = [
    'ransomware', 'data_breach', 'insider_threat', 'ddos',
    'account_compromise', 'malware', 'phishing', 'unauthorized_access',
]

SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low']

STATUS_VALUES = ['open', 'investigating', 'contained', 'resolved', 'closed']

EVIDENCE_TYPES = [
    'system_logs', 'process_list', 'network_connections', 'running_services',
    'user_accounts', 'scheduled_tasks', 'recent_files', 'memory_info',
    'disk_info', 'installed_software',
]


# ── Playbooks ───────────────────────────────────────────────────────

IR_PLAYBOOKS = {
    'ransomware': {
        'name': 'Ransomware Response',
        'steps': [
            {
                'title': 'Isolate Affected Systems',
                'description': 'Immediately disconnect infected hosts from the network to prevent lateral movement and further encryption. Disable WiFi adapters and unplug Ethernet cables. Add firewall rules to block the host if remote.',
                'check_items': ['Disconnect from network', 'Disable WiFi adapters', 'Block at firewall', 'Disable shared drives/NFS mounts'],
                'automated': True,
                'commands': ['netsh interface set interface "Wi-Fi" disable' if _is_win else 'nmcli radio wifi off',
                             'netsh advfirewall set allprofiles state on' if _is_win else 'iptables -P INPUT DROP && iptables -P OUTPUT DROP && iptables -P FORWARD DROP'],
            },
            {
                'title': 'Preserve Evidence',
                'description': 'Capture volatile evidence before any remediation. Collect running processes, network connections, memory state, and ransom notes. Photograph any ransom screens.',
                'check_items': ['Capture process list', 'Capture network connections', 'Save ransom note text', 'Screenshot ransom screen', 'Record system time and timezone'],
                'automated': True,
                'commands': ['tasklist /v' if _is_win else 'ps auxf',
                             'netstat -anob' if _is_win else 'ss -tulnp'],
            },
            {
                'title': 'Identify Ransomware Variant',
                'description': 'Determine the ransomware family by examining the ransom note, encrypted file extensions, and behavior. Check ID Ransomware (id-ransomware.malwarehunterteam.com) and No More Ransom (nomoreransom.org) for known decryptors.',
                'check_items': ['Note encrypted file extension', 'Identify ransom note filename', 'Check ID Ransomware', 'Check No More Ransom project', 'Search threat intelligence feeds'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Assess Scope of Impact',
                'description': 'Determine which systems, shares, and data have been affected. Check backup integrity. Identify the initial infection vector (email attachment, RDP, exploit kit).',
                'check_items': ['Enumerate affected hosts', 'Check shared drive encryption status', 'Verify backup integrity', 'Identify infection vector', 'Determine data classification of affected files'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Eradicate Ransomware',
                'description': 'Remove the ransomware binary, persistence mechanisms, and any related malware. Scan all systems with updated AV signatures. Check scheduled tasks, startup items, and registry run keys.',
                'check_items': ['Identify and remove ransomware executable', 'Clear persistence mechanisms', 'Scan with updated AV signatures', 'Check scheduled tasks', 'Check registry run keys (Windows)', 'Check crontabs (Linux)'],
                'automated': True,
                'commands': ['schtasks /query /fo LIST /v' if _is_win else 'crontab -l 2>/dev/null; ls -la /etc/cron.*/ 2>/dev/null'],
            },
            {
                'title': 'Restore and Recover',
                'description': 'Restore affected systems from clean backups. Rebuild compromised systems if needed. Verify restored data integrity and gradually reconnect to the network.',
                'check_items': ['Restore from verified clean backup', 'Rebuild if no clean backup available', 'Verify data integrity post-restore', 'Patch vulnerability used for initial access', 'Reconnect to network gradually'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Post-Incident Review',
                'description': 'Conduct lessons learned meeting. Update IR playbook. Improve detection and prevention controls. Document full timeline for legal/compliance.',
                'check_items': ['Schedule lessons learned meeting', 'Update detection rules', 'Improve email filtering', 'Review backup strategy', 'Document full incident timeline', 'File regulatory notifications if required'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'data_breach': {
        'name': 'Data Breach Response',
        'steps': [
            {
                'title': 'Confirm and Scope the Breach',
                'description': 'Verify that a data breach has occurred. Determine what data was accessed or exfiltrated, which systems were involved, and the approximate timeframe.',
                'check_items': ['Verify breach indicators', 'Identify affected systems', 'Determine data types exposed', 'Establish breach timeframe', 'Check access logs for unauthorized activity'],
                'automated': True,
                'commands': ['wevtutil qe Security /c:50 /f:text /rd:true' if _is_win else 'grep -i "authentication failure\\|invalid user\\|unauthorized" /var/log/auth.log 2>/dev/null | tail -50'],
            },
            {
                'title': 'Contain the Breach',
                'description': 'Stop ongoing data exfiltration. Revoke compromised credentials, block attacker IPs, disable compromised accounts, and segment affected network areas.',
                'check_items': ['Block attacker IP addresses', 'Revoke compromised API keys/tokens', 'Disable compromised user accounts', 'Segment affected network zones', 'Enable enhanced logging'],
                'automated': True,
                'commands': ['netstat -anob' if _is_win else 'ss -tulnp',
                             'net user' if _is_win else 'cat /etc/passwd | grep -v nologin | grep -v false'],
            },
            {
                'title': 'Preserve Evidence',
                'description': 'Secure all evidence for potential legal proceedings. Create forensic images, preserve logs, and maintain chain of custody documentation.',
                'check_items': ['Create forensic disk images', 'Preserve all relevant logs', 'Document chain of custody', 'Capture network traffic logs', 'Save database query logs'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Assess Data Impact',
                'description': 'Classify the types and volume of data compromised. Determine if PII, PHI, financial data, or trade secrets were involved. Assess regulatory implications.',
                'check_items': ['Classify data types affected', 'Estimate number of records', 'Determine if PII/PHI involved', 'Check for financial data exposure', 'Identify regulatory frameworks triggered'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Notify Stakeholders',
                'description': 'Notify required parties according to regulatory requirements and company policy. This may include legal, management, affected individuals, and regulators.',
                'check_items': ['Notify legal counsel', 'Notify executive management', 'Prepare notification to affected individuals', 'File regulatory notifications (GDPR 72hr, HIPAA 60 days)', 'Notify law enforcement if appropriate', 'Prepare public statement if needed'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Remediate and Harden',
                'description': 'Fix the vulnerability or weakness that allowed the breach. Implement additional security controls and monitoring.',
                'check_items': ['Patch exploited vulnerability', 'Implement additional access controls', 'Enable MFA on affected systems', 'Deploy DLP controls', 'Enhance monitoring and alerting'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Post-Incident Review',
                'description': 'Document full incident timeline, root cause analysis, and lessons learned. Update policies, procedures, and detection rules.',
                'check_items': ['Complete incident report', 'Conduct root cause analysis', 'Update incident response plan', 'Implement improved controls', 'Schedule follow-up review'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'insider_threat': {
        'name': 'Insider Threat Response',
        'steps': [
            {
                'title': 'Identify and Verify Threat',
                'description': 'Confirm the insider threat indicators. Determine if activity is malicious or accidental. Review user activity logs, access patterns, and data movement.',
                'check_items': ['Review user access logs', 'Check data transfer volumes', 'Verify anomalous login patterns', 'Review email/messaging for exfiltration', 'Confirm with HR if termination-related'],
                'automated': True,
                'commands': ['wevtutil qe Security /c:100 /f:text /rd:true /q:"*[System[(EventID=4624 or EventID=4625)]]"' if _is_win else 'last -20 2>/dev/null; lastlog 2>/dev/null | head -20'],
            },
            {
                'title': 'Monitor Covertly',
                'description': 'If investigation is underway, continue monitoring the insider without alerting them. Coordinate with legal and HR before taking action.',
                'check_items': ['Enable enhanced audit logging', 'Monitor file access patterns', 'Track network activity from user workstation', 'Coordinate with HR and legal', 'Document all observations'],
                'automated': True,
                'commands': ['auditpol /get /category:*' if _is_win else 'auditctl -l 2>/dev/null'],
            },
            {
                'title': 'Contain the Threat',
                'description': 'When ready to act, disable the user account, revoke all access, and secure their workstation. Preserve all evidence before wiping anything.',
                'check_items': ['Disable user account', 'Revoke VPN/remote access', 'Revoke cloud service access', 'Secure physical workstation', 'Collect badges and keys', 'Disable email forwarding rules'],
                'automated': True,
                'commands': ['net user {username} /active:no' if _is_win else 'usermod -L {username} 2>/dev/null'],
            },
            {
                'title': 'Forensic Investigation',
                'description': 'Conduct thorough forensic analysis of the insider\'s workstation, email, cloud storage, and all systems they had access to.',
                'check_items': ['Image workstation hard drive', 'Review email sent items and drafts', 'Check USB device history', 'Review cloud storage activity', 'Check print logs', 'Review source code repository commits'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Assess Damage',
                'description': 'Determine what data was accessed, copied, or destroyed. Assess intellectual property theft, competitive harm, and regulatory impact.',
                'check_items': ['Inventory accessed files', 'Determine data classification', 'Assess competitive damage', 'Check for data destruction', 'Review customer data exposure'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Recovery and Remediation',
                'description': 'Rotate credentials, revoke remaining access, and implement controls to prevent similar incidents.',
                'check_items': ['Rotate shared credentials', 'Review access control lists', 'Implement separation of duties', 'Update DLP policies', 'Enhance user behavior analytics'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'ddos': {
        'name': 'DDoS Response',
        'steps': [
            {
                'title': 'Detect and Classify Attack',
                'description': 'Identify the type of DDoS attack (volumetric, protocol, application layer). Determine attack vector, source IPs, and traffic patterns.',
                'check_items': ['Identify attack type', 'Measure attack bandwidth', 'Identify source IP ranges', 'Determine targeted services', 'Check if amplification/reflection attack'],
                'automated': True,
                'commands': ['netstat -an | find /c "ESTABLISHED"' if _is_win else 'ss -s; netstat -an 2>/dev/null | awk \'{print $5}\' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20'],
            },
            {
                'title': 'Activate Upstream Mitigation',
                'description': 'Contact ISP and activate DDoS mitigation services. Enable CDN/WAF protections. Activate cloud-based scrubbing if available.',
                'check_items': ['Contact ISP for upstream filtering', 'Activate CDN DDoS protection', 'Enable WAF rate limiting', 'Activate cloud scrubbing service', 'Implement geo-blocking if appropriate'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Apply Local Mitigations',
                'description': 'Implement local firewall rules to drop attack traffic. Enable SYN cookies, rate limiting, and connection limits. Block identified source IPs.',
                'check_items': ['Enable SYN flood protection', 'Apply rate limiting rules', 'Block top attacking IPs', 'Increase connection table size', 'Drop malformed packets'],
                'automated': True,
                'commands': ['netsh advfirewall firewall add rule name="DDoS-RateLimit" dir=in action=block enable=yes' if _is_win else 'sysctl -w net.ipv4.tcp_syncookies=1; sysctl -w net.ipv4.tcp_max_syn_backlog=2048'],
            },
            {
                'title': 'Monitor and Adapt',
                'description': 'Continuously monitor attack patterns. Attackers often shift vectors when initial attack is mitigated. Update filtering rules as patterns change.',
                'check_items': ['Monitor bandwidth utilization', 'Track connection states', 'Watch for attack vector changes', 'Update filtering rules', 'Monitor service availability'],
                'automated': True,
                'commands': ['netstat -an' if _is_win else 'ss -s'],
            },
            {
                'title': 'Service Recovery',
                'description': 'Once attack subsides, gradually restore services. Verify all systems are functioning normally. Clear any queued requests.',
                'check_items': ['Verify attack has stopped', 'Remove emergency firewall rules', 'Restart affected services', 'Clear connection queues', 'Verify service availability'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Post-Attack Analysis',
                'description': 'Analyze attack traffic patterns for future prevention. Update DDoS response procedures. Consider additional protection services.',
                'check_items': ['Analyze attack traffic logs', 'Document attack timeline', 'Review effectiveness of mitigations', 'Update firewall rules permanently', 'Evaluate DDoS protection services'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'account_compromise': {
        'name': 'Account Compromise Response',
        'steps': [
            {
                'title': 'Confirm Compromise',
                'description': 'Verify that the account has been compromised. Check for unauthorized logins, unusual activity, email forwarding rules, and new MFA devices.',
                'check_items': ['Review login history for anomalies', 'Check for new email forwarding rules', 'Look for new MFA devices', 'Review recent account activity', 'Check for password change attempts'],
                'automated': True,
                'commands': ['wevtutil qe Security /c:30 /f:text /rd:true /q:"*[System[(EventID=4624)]]"' if _is_win else 'last -30 2>/dev/null; grep "session opened" /var/log/auth.log 2>/dev/null | tail -30'],
            },
            {
                'title': 'Secure the Account',
                'description': 'Reset the password immediately. Revoke all active sessions and tokens. Remove unauthorized MFA devices. Remove suspicious email rules.',
                'check_items': ['Reset account password', 'Revoke all active sessions', 'Remove unauthorized MFA devices', 'Remove email forwarding rules', 'Revoke OAuth application access'],
                'automated': True,
                'commands': ['net user {username} * /domain' if _is_win else 'passwd {username}'],
            },
            {
                'title': 'Assess Impact',
                'description': 'Determine what the attacker accessed using the compromised account. Check email, files, systems, and any actions taken.',
                'check_items': ['Review email access logs', 'Check file access history', 'Review system authentication logs', 'Look for data exfiltration', 'Check for lateral movement'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Check for Lateral Movement',
                'description': 'Determine if the attacker used the compromised account to access other systems or escalate privileges.',
                'check_items': ['Check other systems for the compromised credential', 'Review admin console access', 'Look for privilege escalation', 'Check for new accounts created', 'Review VPN connection logs'],
                'automated': True,
                'commands': ['net user' if _is_win else 'cat /etc/passwd | grep -v nologin'],
            },
            {
                'title': 'Remediate and Harden',
                'description': 'Implement additional security controls on the account and related systems.',
                'check_items': ['Enable MFA if not already active', 'Review account permissions', 'Implement conditional access policies', 'Update password policy', 'Enable login anomaly detection'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'malware': {
        'name': 'Malware Incident Response',
        'steps': [
            {
                'title': 'Identify and Isolate',
                'description': 'Identify the malware and isolate the affected system. Determine the malware type (trojan, worm, RAT, rootkit, etc.) and initial infection vector.',
                'check_items': ['Identify malware file/process', 'Isolate affected system from network', 'Determine malware type', 'Identify initial infection vector', 'Check if malware is actively communicating'],
                'automated': True,
                'commands': ['tasklist /v' if _is_win else 'ps auxf',
                             'netstat -anob' if _is_win else 'ss -tulnp',
                             'wmic process list full' if _is_win else 'ls -la /tmp /var/tmp /dev/shm 2>/dev/null'],
            },
            {
                'title': 'Collect Malware Sample',
                'description': 'Safely collect the malware binary for analysis. Calculate hashes (MD5, SHA256) and check against threat intelligence databases.',
                'check_items': ['Copy malware sample to quarantine', 'Calculate file hashes', 'Submit to VirusTotal', 'Check threat intel feeds', 'Document file metadata'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Analyze Behavior',
                'description': 'Determine malware capabilities: C2 communication, persistence, data exfiltration, privilege escalation, and lateral movement.',
                'check_items': ['Identify C2 domains/IPs', 'Check persistence mechanisms', 'Identify data exfiltration channels', 'Check for privilege escalation', 'Look for dropper/downloader behavior'],
                'automated': True,
                'commands': ['schtasks /query /fo LIST /v' if _is_win else 'crontab -l 2>/dev/null',
                             'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' if _is_win else 'systemctl list-unit-files --state=enabled 2>/dev/null'],
            },
            {
                'title': 'Scope the Infection',
                'description': 'Determine if other systems are infected. Sweep the network for IOCs found during analysis.',
                'check_items': ['Sweep network for IOCs', 'Check DNS logs for C2 domains', 'Review network flow data', 'Check other endpoints for same hash', 'Look for worm propagation'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Eradicate Malware',
                'description': 'Remove all malware components from affected systems. Clean persistence mechanisms, remove dropped files, and clear modified registry entries.',
                'check_items': ['Remove malware binaries', 'Clear persistence entries', 'Remove dropped files', 'Clean registry modifications', 'Verify clean with multiple AV engines'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Recover and Monitor',
                'description': 'Restore system to clean state. Patch the vulnerability used for initial access. Monitor for reinfection.',
                'check_items': ['Restore from clean backup if needed', 'Apply security patches', 'Update AV signatures', 'Monitor for reinfection indicators', 'Update detection rules with new IOCs'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'phishing': {
        'name': 'Phishing Incident Response',
        'steps': [
            {
                'title': 'Analyze the Phishing Email',
                'description': 'Examine the phishing email headers, sender, links, and attachments. Determine the campaign scope and targets.',
                'check_items': ['Examine email headers for origin', 'Analyze URLs (do not click)', 'Check attachments in sandbox', 'Identify phishing kit or campaign', 'Determine number of recipients'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Identify Affected Users',
                'description': 'Determine which users received, opened, clicked links, or submitted credentials to the phishing page.',
                'check_items': ['Query email gateway for all recipients', 'Check proxy logs for phishing URL visits', 'Review web filter logs', 'Identify users who submitted credentials', 'Check for downloaded attachments'],
                'automated': True,
                'commands': ['ipconfig /displaydns' if _is_win else 'cat /etc/resolv.conf; grep -r "dns" /var/log/ 2>/dev/null | tail -20'],
            },
            {
                'title': 'Contain the Threat',
                'description': 'Block the phishing URLs and sender addresses. Reset credentials for affected users. Purge remaining phishing emails from inboxes.',
                'check_items': ['Block phishing URL at proxy/firewall', 'Block sender email address', 'Reset passwords for affected users', 'Purge phishing email from all mailboxes', 'Block phishing domain in DNS'],
                'automated': True,
                'commands': ['netsh advfirewall firewall add rule name="Block-Phish" dir=out action=block remoteip={ip}' if _is_win else 'iptables -A OUTPUT -d {ip} -j DROP'],
            },
            {
                'title': 'Check for Secondary Compromise',
                'description': 'If users clicked links or submitted credentials, check for follow-on compromise: unauthorized access, malware installation, data theft.',
                'check_items': ['Check for unauthorized logins with stolen creds', 'Scan workstations for malware', 'Review data access logs', 'Check for OAuth token theft', 'Look for lateral movement'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Remediate',
                'description': 'Ensure all affected accounts are secured. Update email filtering rules. Deploy additional protections.',
                'check_items': ['Verify all affected passwords reset', 'Enable MFA for affected accounts', 'Update email filter rules', 'Add phishing indicators to blocklists', 'Submit phishing page for takedown'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'User Awareness',
                'description': 'Notify users about the phishing campaign. Provide guidance on identifying phishing. Consider additional security awareness training.',
                'check_items': ['Send company-wide alert about campaign', 'Provide phishing identification tips', 'Schedule security awareness training', 'Update phishing simulation program', 'Document lessons learned'],
                'automated': False,
                'commands': [],
            },
        ],
    },
    'unauthorized_access': {
        'name': 'Unauthorized Access Response',
        'steps': [
            {
                'title': 'Detect and Confirm',
                'description': 'Verify unauthorized access indicators. Review authentication logs, IDS/IPS alerts, and anomalous activity.',
                'check_items': ['Review authentication logs', 'Check IDS/IPS alerts', 'Verify anomalous access patterns', 'Identify accessed resources', 'Determine access method (exploit, stolen creds, misconfiguration)'],
                'automated': True,
                'commands': ['wevtutil qe Security /c:50 /f:text /rd:true' if _is_win else 'grep -i "accepted\\|failed\\|invalid" /var/log/auth.log 2>/dev/null | tail -50'],
            },
            {
                'title': 'Block Attacker Access',
                'description': 'Immediately block the attacker\'s access. Firewall the source IP, disable exploited service, close the vulnerability.',
                'check_items': ['Block attacker IP at firewall', 'Disable exploited service', 'Close vulnerable ports', 'Revoke any created credentials', 'Reset compromised accounts'],
                'automated': True,
                'commands': ['netsh advfirewall firewall add rule name="Block-Attacker" dir=in action=block remoteip={ip}' if _is_win else 'iptables -A INPUT -s {ip} -j DROP'],
            },
            {
                'title': 'Preserve Evidence',
                'description': 'Capture all evidence of the intrusion before remediation changes it.',
                'check_items': ['Capture running processes', 'Save network connections', 'Preserve log files', 'Save modified files list', 'Document access timeline'],
                'automated': True,
                'commands': ['tasklist /v' if _is_win else 'ps auxf',
                             'netstat -anob' if _is_win else 'ss -tulnp',
                             'dir /t:w /o:-d /s C:\\Users' if _is_win else 'find / -mtime -1 -type f 2>/dev/null | head -100'],
            },
            {
                'title': 'Assess Scope and Impact',
                'description': 'Determine what the attacker accessed, modified, or exfiltrated. Check for backdoors, new accounts, and persistence mechanisms.',
                'check_items': ['Check for new user accounts', 'Look for backdoors and webshells', 'Review file modification times', 'Check for data exfiltration', 'Look for persistence mechanisms'],
                'automated': True,
                'commands': ['net user' if _is_win else 'cat /etc/passwd',
                             'schtasks /query /fo LIST' if _is_win else 'crontab -l 2>/dev/null'],
            },
            {
                'title': 'Eradicate and Harden',
                'description': 'Remove all attacker artifacts. Patch the exploited vulnerability. Harden the system against future attacks.',
                'check_items': ['Remove attacker backdoors', 'Patch exploited vulnerability', 'Remove unauthorized accounts', 'Harden service configurations', 'Update firewall rules', 'Enable enhanced logging'],
                'automated': False,
                'commands': [],
            },
            {
                'title': 'Post-Incident Review',
                'description': 'Document the full attack chain. Update detection rules and security controls. Implement lessons learned.',
                'check_items': ['Document complete attack chain', 'Update IDS/IPS signatures', 'Review and update access controls', 'Implement additional monitoring', 'Schedule penetration test'],
                'automated': False,
                'commands': [],
            },
        ],
    },
}


# ── Incident Response Engine ────────────────────────────────────────

class IncidentResponse:
    """IR playbook runner, evidence collector, IOC sweeper, and reporting engine."""

    _instance = None

    def __init__(self):
        data_dir = get_data_dir()
        if isinstance(data_dir, str):
            data_dir = Path(data_dir)
        self._incidents_dir = data_dir / 'incidents'
        self._incidents_dir.mkdir(parents=True, exist_ok=True)

    # ── helpers ──────────────────────────────────────────────────

    def _run_cmd(self, cmd, timeout=30):
        """Run a shell command, return (success, output)."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except Exception as e:
            return False, str(e)

    def _now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def _gen_id(self):
        """Generate a unique incident ID like IR-20260303-A1B2."""
        ts = datetime.now().strftime('%Y%m%d')
        suffix = hashlib.md5(str(time.time()).encode()).hexdigest()[:4].upper()
        return f'IR-{ts}-{suffix}'

    def _incident_dir(self, incident_id):
        d = self._incidents_dir / incident_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _load_incident(self, incident_id):
        path = self._incident_dir(incident_id) / 'incident.json'
        if not path.exists():
            return None
        with open(path, 'r') as f:
            return json.load(f)

    def _save_incident(self, incident):
        idir = self._incident_dir(incident['id'])
        with open(idir / 'incident.json', 'w') as f:
            json.dump(incident, f, indent=2, default=str)

    def _load_timeline(self, incident_id):
        path = self._incident_dir(incident_id) / 'timeline.json'
        if not path.exists():
            return []
        with open(path, 'r') as f:
            return json.load(f)

    def _save_timeline(self, incident_id, timeline):
        path = self._incident_dir(incident_id) / 'timeline.json'
        with open(path, 'w') as f:
            json.dump(timeline, f, indent=2, default=str)

    def _evidence_dir(self, incident_id):
        d = self._incident_dir(incident_id) / 'evidence'
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ── CRUD ─────────────────────────────────────────────────────

    def create_incident(self, name, incident_type, severity, description=''):
        """Create a new incident case and return the incident dict."""
        if incident_type not in INCIDENT_TYPES:
            return {'error': f'Invalid type. Must be one of: {", ".join(INCIDENT_TYPES)}'}
        if severity not in SEVERITY_LEVELS:
            return {'error': f'Invalid severity. Must be one of: {", ".join(SEVERITY_LEVELS)}'}

        incident_id = self._gen_id()
        playbook = IR_PLAYBOOKS.get(incident_type, {})
        step_count = len(playbook.get('steps', []))

        incident = {
            'id': incident_id,
            'name': name,
            'type': incident_type,
            'severity': severity,
            'description': description,
            'status': 'open',
            'assignee': '',
            'notes': '',
            'created': self._now_iso(),
            'updated': self._now_iso(),
            'closed': None,
            'resolution_notes': '',
            'playbook_progress': [False] * step_count,
            'playbook_outputs': [''] * step_count,
            'evidence_count': 0,
        }
        self._save_incident(incident)
        self._save_timeline(incident_id, [])

        # add creation event to timeline
        self.add_timeline_event(incident_id, self._now_iso(),
                                f'Incident created: {name}', 'system',
                                f'Type: {incident_type}, Severity: {severity}')
        return incident

    def get_incident(self, incident_id):
        """Return full incident details including timeline and evidence list."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}
        incident['timeline'] = self._load_timeline(incident_id)
        incident['evidence'] = self.list_evidence(incident_id)
        return incident

    def list_incidents(self, status=None):
        """Return list of all incidents, optionally filtered by status."""
        incidents = []
        if not self._incidents_dir.exists():
            return incidents
        for d in sorted(self._incidents_dir.iterdir(), reverse=True):
            if d.is_dir():
                inc = self._load_incident(d.name)
                if inc:
                    if status and inc.get('status') != status:
                        continue
                    incidents.append(inc)
        return incidents

    def update_incident(self, incident_id, updates):
        """Update incident fields (status, severity, notes, assignee)."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        allowed = {'status', 'severity', 'notes', 'assignee', 'name', 'description'}
        changes = []
        for key, val in updates.items():
            if key in allowed:
                old_val = incident.get(key, '')
                if old_val != val:
                    incident[key] = val
                    changes.append(f'{key}: {old_val} -> {val}')

        if 'status' in updates and updates['status'] not in STATUS_VALUES:
            return {'error': f'Invalid status. Must be one of: {", ".join(STATUS_VALUES)}'}
        if 'severity' in updates and updates['severity'] not in SEVERITY_LEVELS:
            return {'error': f'Invalid severity. Must be one of: {", ".join(SEVERITY_LEVELS)}'}

        incident['updated'] = self._now_iso()
        self._save_incident(incident)

        if changes:
            self.add_timeline_event(incident_id, self._now_iso(),
                                    'Incident updated', 'system',
                                    '; '.join(changes))
        return incident

    def close_incident(self, incident_id, resolution_notes=''):
        """Close an incident with resolution notes."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        incident['status'] = 'closed'
        incident['closed'] = self._now_iso()
        incident['updated'] = self._now_iso()
        incident['resolution_notes'] = resolution_notes
        self._save_incident(incident)

        self.add_timeline_event(incident_id, self._now_iso(),
                                'Incident closed', 'system', resolution_notes)
        return incident

    def delete_incident(self, incident_id):
        """Delete an incident and all associated data."""
        idir = self._incidents_dir / incident_id
        if not idir.exists():
            return {'error': 'Incident not found'}
        shutil.rmtree(str(idir), ignore_errors=True)
        return {'success': True, 'deleted': incident_id}

    # ── Playbooks ────────────────────────────────────────────────

    def get_playbook(self, incident_type):
        """Return the IR playbook for an incident type."""
        pb = IR_PLAYBOOKS.get(incident_type)
        if not pb:
            return {'error': f'No playbook for type: {incident_type}'}
        return pb

    def run_playbook_step(self, incident_id, step_index, auto=False):
        """Execute or mark a playbook step as done."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        playbook = IR_PLAYBOOKS.get(incident['type'], {})
        steps = playbook.get('steps', [])
        if step_index < 0 or step_index >= len(steps):
            return {'error': f'Invalid step index: {step_index}'}

        step = steps[step_index]
        output = ''

        if auto and step.get('automated') and step.get('commands'):
            # Run the commands and capture output
            outputs = []
            for cmd in step['commands']:
                success, result = self._run_cmd(cmd)
                outputs.append(f'$ {cmd}\n{result}\n{"[OK]" if success else "[FAILED]"}')
            output = '\n\n'.join(outputs)

            # Store the output as evidence
            self.add_evidence(incident_id,
                              f'playbook_step_{step_index}_{step["title"].replace(" ", "_")}',
                              output, evidence_type='playbook_auto')

        # Mark step as complete
        progress = incident.get('playbook_progress', [])
        while len(progress) <= step_index:
            progress.append(False)
        progress[step_index] = True

        pb_outputs = incident.get('playbook_outputs', [])
        while len(pb_outputs) <= step_index:
            pb_outputs.append('')
        pb_outputs[step_index] = output

        incident['playbook_progress'] = progress
        incident['playbook_outputs'] = pb_outputs
        incident['updated'] = self._now_iso()

        # auto-advance status
        if incident['status'] == 'open':
            incident['status'] = 'investigating'

        self._save_incident(incident)
        self.add_timeline_event(incident_id, self._now_iso(),
                                f'Playbook step completed: {step["title"]}',
                                'playbook',
                                f'Step {step_index + 1}/{len(steps)}, auto={auto}')

        return {
            'step_index': step_index,
            'title': step['title'],
            'completed': True,
            'auto': auto,
            'output': output,
            'progress': progress,
        }

    # ── Evidence Collection ──────────────────────────────────────

    def collect_evidence(self, incident_id, evidence_type, source=None):
        """Collect evidence from the local system and store it under the incident."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}
        if evidence_type not in EVIDENCE_TYPES:
            return {'error': f'Unknown evidence type. Options: {", ".join(EVIDENCE_TYPES)}'}

        content = ''
        name = evidence_type

        if evidence_type == 'system_logs':
            if _is_win:
                _, content = self._run_cmd(
                    'wevtutil qe System /c:50 /f:text /rd:true', timeout=20)
                _, auth = self._run_cmd(
                    'wevtutil qe Security /c:50 /f:text /rd:true', timeout=20)
                content = f'=== System Log ===\n{content}\n\n=== Security Log ===\n{auth}'
            else:
                parts = []
                for log in ['/var/log/syslog', '/var/log/messages', '/var/log/auth.log',
                            '/var/log/secure', '/var/log/kern.log']:
                    _, out = self._run_cmd(f'tail -100 {log} 2>/dev/null')
                    if out:
                        parts.append(f'=== {log} ===\n{out}')
                content = '\n\n'.join(parts) if parts else 'No accessible logs found'

        elif evidence_type == 'process_list':
            if _is_win:
                _, content = self._run_cmd('tasklist /v /fo csv', timeout=15)
            else:
                _, content = self._run_cmd('ps auxf', timeout=15)

        elif evidence_type == 'network_connections':
            if _is_win:
                _, content = self._run_cmd('netstat -anob', timeout=15)
            else:
                _, content = self._run_cmd('ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null', timeout=15)

        elif evidence_type == 'running_services':
            if _is_win:
                _, content = self._run_cmd('sc query state= all', timeout=20)
            else:
                _, content = self._run_cmd('systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null', timeout=15)

        elif evidence_type == 'user_accounts':
            if _is_win:
                _, content = self._run_cmd('net user', timeout=10)
                _, detailed = self._run_cmd('wmic useraccount list full', timeout=15)
                content = f'{content}\n\n=== Detailed ===\n{detailed}'
            else:
                _, content = self._run_cmd('cat /etc/passwd; echo "---"; last -20 2>/dev/null', timeout=10)

        elif evidence_type == 'scheduled_tasks':
            if _is_win:
                _, content = self._run_cmd('schtasks /query /fo LIST /v', timeout=20)
            else:
                parts = []
                _, out = self._run_cmd('crontab -l 2>/dev/null')
                if out:
                    parts.append(f'=== User Crontab ===\n{out}')
                _, out = self._run_cmd('ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null')
                if out:
                    parts.append(f'=== System Cron ===\n{out}')
                _, out = self._run_cmd('systemctl list-timers --all 2>/dev/null')
                if out:
                    parts.append(f'=== Systemd Timers ===\n{out}')
                content = '\n\n'.join(parts) if parts else 'No scheduled tasks found'

        elif evidence_type == 'recent_files':
            if _is_win:
                _, content = self._run_cmd(
                    'forfiles /P C:\\Users /S /D -1 /C "cmd /c echo @path @fdate @ftime" 2>nul',
                    timeout=30)
                if not content:
                    _, content = self._run_cmd('dir /t:w /o:-d /s C:\\Users\\*.*', timeout=30)
            else:
                _, content = self._run_cmd(
                    'find /home /tmp /var/tmp /root -mtime -1 -type f 2>/dev/null | head -200',
                    timeout=30)

        elif evidence_type == 'memory_info':
            if _is_win:
                _, content = self._run_cmd(
                    'systeminfo | findstr /C:"Total Physical" /C:"Available Physical" /C:"Virtual Memory"',
                    timeout=15)
                _, procs = self._run_cmd(
                    'wmic process get Name,WorkingSetSize,ProcessId /format:csv', timeout=15)
                content = f'{content}\n\n=== Top Processes ===\n{procs}'
            else:
                _, content = self._run_cmd('free -h; echo "---"; cat /proc/meminfo | head -20', timeout=10)

        elif evidence_type == 'disk_info':
            if _is_win:
                _, content = self._run_cmd('wmic logicaldisk get size,freespace,caption', timeout=10)
            else:
                _, content = self._run_cmd('df -h; echo "---"; lsblk 2>/dev/null', timeout=10)

        elif evidence_type == 'installed_software':
            if _is_win:
                _, content = self._run_cmd(
                    'wmic product get name,version /format:csv 2>nul', timeout=30)
                if not content:
                    _, content = self._run_cmd(
                        'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" /s /v DisplayName 2>nul',
                        timeout=20)
            else:
                _, content = self._run_cmd(
                    'dpkg -l 2>/dev/null || rpm -qa 2>/dev/null || pacman -Q 2>/dev/null',
                    timeout=20)

        # Save evidence
        return self.add_evidence(incident_id, name, content, evidence_type='collected')

    def add_evidence(self, incident_id, name, content, evidence_type='manual'):
        """Add evidence (manual note, collected data, etc.) to an incident."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        edir = self._evidence_dir(incident_id)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        filename = f'{ts}_{safe_name}.txt'
        filepath = edir / filename

        with open(filepath, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content)

        # Update evidence count
        incident['evidence_count'] = incident.get('evidence_count', 0) + 1
        incident['updated'] = self._now_iso()
        self._save_incident(incident)

        # Log in timeline
        self.add_timeline_event(incident_id, self._now_iso(),
                                f'Evidence added: {name}', 'evidence',
                                f'Type: {evidence_type}, File: {filename}, Size: {len(content)} bytes')

        return {
            'name': name,
            'filename': filename,
            'type': evidence_type,
            'size': len(content),
            'collected_at': self._now_iso(),
            'preview': content[:500] if content else '',
        }

    def list_evidence(self, incident_id):
        """List all evidence files for an incident."""
        edir = self._evidence_dir(incident_id)
        evidence = []
        if not edir.exists():
            return evidence
        for f in sorted(edir.iterdir()):
            if f.is_file():
                stat = f.stat()
                evidence.append({
                    'filename': f.name,
                    'name': f.stem,
                    'size': stat.st_size,
                    'collected_at': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        return evidence

    def get_evidence_content(self, incident_id, filename):
        """Return the content of a specific evidence file."""
        filepath = self._evidence_dir(incident_id) / filename
        if not filepath.exists():
            return {'error': 'Evidence file not found'}
        try:
            content = filepath.read_text(encoding='utf-8', errors='replace')
            return {'filename': filename, 'content': content, 'size': len(content)}
        except Exception as e:
            return {'error': str(e)}

    # ── IOC Sweep ────────────────────────────────────────────────

    def sweep_iocs(self, incident_id, iocs):
        """Scan local system for indicators of compromise.

        iocs = {
            'ips': ['1.2.3.4', ...],
            'domains': ['evil.com', ...],
            'hashes': ['sha256:abcdef...', ...],
        }
        """
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        matches = []
        ip_list = [ip.strip() for ip in iocs.get('ips', []) if ip.strip()]
        domain_list = [d.strip() for d in iocs.get('domains', []) if d.strip()]
        hash_list = [h.strip() for h in iocs.get('hashes', []) if h.strip()]

        # Check network connections against IP list
        if ip_list:
            if _is_win:
                _, netout = self._run_cmd('netstat -an')
            else:
                _, netout = self._run_cmd('ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null')

            for ip in ip_list:
                if ip in netout:
                    matches.append({
                        'type': 'ip',
                        'ioc': ip,
                        'found_in': 'active_connections',
                        'severity': 'critical',
                        'details': f'IP {ip} found in active network connections',
                    })

        # Check running processes against hash list
        if hash_list:
            if _is_win:
                _, proc_out = self._run_cmd('wmic process get ExecutablePath /format:csv')
                proc_paths = [line.split(',')[-1].strip() for line in proc_out.splitlines()
                              if '\\' in line]
            else:
                _, proc_out = self._run_cmd("ls -1 /proc/*/exe 2>/dev/null | xargs readlink 2>/dev/null | sort -u")
                proc_paths = [p.strip() for p in proc_out.splitlines() if p.strip()]

            for proc_path in proc_paths:
                if not os.path.isfile(proc_path):
                    continue
                try:
                    sha = hashlib.sha256(open(proc_path, 'rb').read()).hexdigest()
                    md5 = hashlib.md5(open(proc_path, 'rb').read()).hexdigest()
                    for h in hash_list:
                        hval = h.split(':')[-1] if ':' in h else h
                        if hval.lower() in (sha.lower(), md5.lower()):
                            matches.append({
                                'type': 'hash',
                                'ioc': h,
                                'found_in': proc_path,
                                'severity': 'critical',
                                'details': f'Hash match on running process: {proc_path}',
                            })
                except (PermissionError, OSError):
                    continue

        # Check DNS cache against domain list
        if domain_list:
            if _is_win:
                _, dns_out = self._run_cmd('ipconfig /displaydns')
            else:
                _, dns_out = self._run_cmd(
                    'cat /etc/hosts 2>/dev/null; '
                    'grep -r "query" /var/log/syslog 2>/dev/null | tail -200')

            for domain in domain_list:
                if domain.lower() in dns_out.lower():
                    matches.append({
                        'type': 'domain',
                        'ioc': domain,
                        'found_in': 'dns_cache',
                        'severity': 'high',
                        'details': f'Domain {domain} found in DNS cache/logs',
                    })

        # Store sweep results as evidence
        result = {
            'total_iocs': len(ip_list) + len(domain_list) + len(hash_list),
            'matches_found': len(matches),
            'matches': matches,
            'swept_at': self._now_iso(),
        }

        self.add_evidence(incident_id, 'ioc_sweep_results',
                          json.dumps(result, indent=2), evidence_type='ioc_sweep')

        self.add_timeline_event(incident_id, self._now_iso(),
                                f'IOC sweep completed: {len(matches)} matches from {result["total_iocs"]} indicators',
                                'sweep', json.dumps({'matches': len(matches)}))

        return result

    # ── Timeline ─────────────────────────────────────────────────

    def add_timeline_event(self, incident_id, timestamp, event, source, details=None):
        """Add an event to the incident timeline."""
        timeline = self._load_timeline(incident_id)
        entry = {
            'timestamp': timestamp,
            'event': event,
            'source': source,
            'details': details or '',
        }
        timeline.append(entry)
        # Sort chronologically
        timeline.sort(key=lambda e: e.get('timestamp', ''))
        self._save_timeline(incident_id, timeline)
        return entry

    def get_timeline(self, incident_id):
        """Get the full chronological timeline for an incident."""
        return self._load_timeline(incident_id)

    def auto_build_timeline(self, incident_id):
        """Automatically build timeline from collected evidence by parsing timestamps."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        evidence_files = self.list_evidence(incident_id)
        events_added = 0
        edir = self._evidence_dir(incident_id)

        # Timestamp patterns
        patterns = [
            # ISO 8601
            (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', '%Y-%m-%dT%H:%M:%S'),
            # Syslog
            (r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', None),
            # Windows Event Log
            (r'Date:\s+(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*[AP]M)', '%m/%d/%Y %I:%M:%S %p'),
        ]

        for ef in evidence_files:
            filepath = edir / ef['filename']
            try:
                content = filepath.read_text(encoding='utf-8', errors='replace')
            except Exception:
                continue

            lines = content.splitlines()
            for line in lines[:500]:  # limit to first 500 lines per file
                for pattern, fmt in patterns:
                    match = re.search(pattern, line)
                    if match:
                        ts_str = match.group(1)
                        try:
                            if fmt:
                                ts_str = ts_str.replace('T', ' ')
                                dt = datetime.strptime(ts_str.strip(), fmt.replace('T', ' '))
                                ts_iso = dt.isoformat()
                            else:
                                # Syslog format — use current year
                                year = datetime.now().year
                                dt = datetime.strptime(f'{year} {ts_str}', '%Y %b %d %H:%M:%S')
                                ts_iso = dt.isoformat()
                        except ValueError:
                            continue

                        # Extract a useful event description from the line
                        event_text = line[match.end():].strip()[:200]
                        if event_text:
                            self.add_timeline_event(
                                incident_id, ts_iso,
                                event_text,
                                ef['filename'],
                                f'Auto-extracted from {ef["filename"]}')
                            events_added += 1
                        break  # only match first pattern per line

                if events_added >= 200:
                    break
            if events_added >= 200:
                break

        self.add_timeline_event(incident_id, self._now_iso(),
                                f'Auto-built timeline: {events_added} events extracted',
                                'system', f'Parsed {len(evidence_files)} evidence files')

        return {
            'events_added': events_added,
            'evidence_parsed': len(evidence_files),
            'total_timeline_events': len(self._load_timeline(incident_id)),
        }

    # ── Containment ──────────────────────────────────────────────

    def contain_host(self, incident_id, host, actions):
        """Execute containment actions against a host/IP.

        actions: list of strings from ['block_ip', 'kill_process', 'disable_user', 'isolate_network']
        """
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        results = []

        for action in actions:
            if action == 'block_ip':
                if _is_win:
                    success, out = self._run_cmd(
                        f'netsh advfirewall firewall add rule name="AUTARCH-IR-Block-{host}" '
                        f'dir=in action=block remoteip={host}')
                else:
                    success, out = self._run_cmd(f'iptables -A INPUT -s {host} -j DROP')
                results.append({
                    'action': 'block_ip',
                    'target': host,
                    'success': success,
                    'output': out,
                })

            elif action == 'kill_process':
                # host here is treated as PID or process name
                if _is_win:
                    success, out = self._run_cmd(f'taskkill /F /PID {host} 2>nul || taskkill /F /IM {host} 2>nul')
                else:
                    success, out = self._run_cmd(f'kill -9 {host} 2>/dev/null || pkill -9 {host} 2>/dev/null')
                results.append({
                    'action': 'kill_process',
                    'target': host,
                    'success': success,
                    'output': out,
                })

            elif action == 'disable_user':
                if _is_win:
                    success, out = self._run_cmd(f'net user {host} /active:no')
                else:
                    success, out = self._run_cmd(f'usermod -L {host} 2>/dev/null; passwd -l {host} 2>/dev/null')
                results.append({
                    'action': 'disable_user',
                    'target': host,
                    'success': success,
                    'output': out,
                })

            elif action == 'isolate_network':
                if _is_win:
                    cmds = [
                        f'netsh advfirewall firewall add rule name="AUTARCH-IR-Isolate-In" dir=in action=block remoteip=any',
                        f'netsh advfirewall firewall add rule name="AUTARCH-IR-Isolate-Out" dir=out action=block remoteip=any',
                    ]
                else:
                    cmds = [
                        'iptables -P INPUT DROP',
                        'iptables -P OUTPUT DROP',
                        'iptables -P FORWARD DROP',
                        # Allow loopback
                        'iptables -A INPUT -i lo -j ACCEPT',
                        'iptables -A OUTPUT -o lo -j ACCEPT',
                    ]
                all_ok = True
                combined = []
                for cmd in cmds:
                    s, o = self._run_cmd(cmd)
                    combined.append(o)
                    if not s:
                        all_ok = False
                results.append({
                    'action': 'isolate_network',
                    'target': host,
                    'success': all_ok,
                    'output': '\n'.join(combined),
                })

        # Update incident status to contained
        if incident['status'] in ('open', 'investigating'):
            incident['status'] = 'contained'
            incident['updated'] = self._now_iso()
            self._save_incident(incident)

        # Log all actions
        action_summary = ', '.join(f'{r["action"]}:{r["target"]}={"OK" if r["success"] else "FAIL"}' for r in results)
        self.add_timeline_event(incident_id, self._now_iso(),
                                f'Containment actions executed', 'containment',
                                action_summary)

        # Store as evidence
        self.add_evidence(incident_id, 'containment_actions',
                          json.dumps(results, indent=2), evidence_type='containment')

        return {'results': results, 'status': incident.get('status')}

    # ── Reporting ────────────────────────────────────────────────

    def generate_report(self, incident_id):
        """Generate a comprehensive post-incident report."""
        incident = self._load_incident(incident_id)
        if not incident:
            return {'error': 'Incident not found'}

        timeline = self._load_timeline(incident_id)
        evidence = self.list_evidence(incident_id)
        playbook = IR_PLAYBOOKS.get(incident['type'], {})
        steps = playbook.get('steps', [])
        progress = incident.get('playbook_progress', [])

        completed_steps = sum(1 for p in progress if p)
        total_steps = len(steps)

        # Build report sections
        report = {
            'title': f'Incident Report: {incident["name"]}',
            'incident_id': incident['id'],
            'generated_at': self._now_iso(),
            'executive_summary': {
                'incident_name': incident['name'],
                'incident_type': incident['type'],
                'severity': incident['severity'],
                'status': incident['status'],
                'created': incident['created'],
                'closed': incident.get('closed'),
                'duration': self._calc_duration(incident['created'], incident.get('closed')),
                'description': incident['description'],
            },
            'timeline': timeline,
            'timeline_summary': f'{len(timeline)} events recorded',
            'evidence_summary': {
                'total_evidence': len(evidence),
                'evidence_list': [{'name': e['name'], 'size': e['size'],
                                   'collected_at': e['collected_at']} for e in evidence],
            },
            'playbook_progress': {
                'playbook_name': playbook.get('name', 'N/A'),
                'completed_steps': completed_steps,
                'total_steps': total_steps,
                'completion_pct': int(completed_steps / total_steps * 100) if total_steps > 0 else 0,
                'steps': [],
            },
            'actions_taken': [],
            'resolution': incident.get('resolution_notes', ''),
            'recommendations': self._generate_recommendations(incident['type']),
            'lessons_learned': [],
        }

        for i, step in enumerate(steps):
            done = progress[i] if i < len(progress) else False
            report['playbook_progress']['steps'].append({
                'step': i + 1,
                'title': step['title'],
                'completed': done,
            })

        # Extract containment actions from timeline
        for event in timeline:
            if event.get('source') in ('containment', 'playbook'):
                report['actions_taken'].append({
                    'timestamp': event['timestamp'],
                    'action': event['event'],
                    'details': event.get('details', ''),
                })

        return report

    def _calc_duration(self, start_str, end_str):
        """Calculate human-readable duration between two ISO timestamps."""
        try:
            start = datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            if end_str:
                end = datetime.fromisoformat(end_str.replace('Z', '+00:00'))
            else:
                end = datetime.now(timezone.utc)
            delta = end - start
            hours = int(delta.total_seconds() // 3600)
            minutes = int((delta.total_seconds() % 3600) // 60)
            if hours > 24:
                days = hours // 24
                hours = hours % 24
                return f'{days}d {hours}h {minutes}m'
            return f'{hours}h {minutes}m'
        except Exception:
            return 'unknown'

    def _generate_recommendations(self, incident_type):
        """Generate post-incident recommendations based on incident type."""
        recs = {
            'ransomware': [
                'Implement network segmentation to limit lateral movement',
                'Deploy endpoint detection and response (EDR) on all systems',
                'Implement immutable backups with offline/offsite copies',
                'Enable application whitelisting on critical servers',
                'Conduct regular phishing awareness training',
                'Implement email attachment sandboxing',
            ],
            'data_breach': [
                'Deploy Data Loss Prevention (DLP) tools',
                'Implement database activity monitoring',
                'Enable multi-factor authentication on all accounts',
                'Encrypt sensitive data at rest and in transit',
                'Implement least-privilege access controls',
                'Conduct regular access reviews',
            ],
            'insider_threat': [
                'Implement user behavior analytics (UBA)',
                'Enable comprehensive audit logging',
                'Enforce separation of duties',
                'Implement DLP with content-aware policies',
                'Conduct regular access certification reviews',
                'Establish clear data handling policies',
            ],
            'ddos': [
                'Subscribe to a DDoS mitigation service',
                'Implement rate limiting at all network layers',
                'Deploy a web application firewall (WAF)',
                'Configure SYN flood protection on all servers',
                'Implement anycast DNS for resilience',
                'Create and test DDoS runbooks quarterly',
            ],
            'account_compromise': [
                'Enforce MFA on all user accounts',
                'Implement conditional access policies',
                'Deploy password manager for the organization',
                'Enable login anomaly detection',
                'Implement session timeout policies',
                'Conduct regular credential audits',
            ],
            'malware': [
                'Deploy next-gen antivirus with behavioral detection',
                'Implement application whitelisting',
                'Enable automatic OS and application patching',
                'Restrict macro execution in Office documents',
                'Implement email gateway scanning',
                'Deploy network-level malware detection',
            ],
            'phishing': [
                'Deploy advanced email gateway with AI detection',
                'Implement DMARC, DKIM, and SPF for email authentication',
                'Conduct regular phishing simulation exercises',
                'Enable browser isolation for email links',
                'Implement URL rewriting and time-of-click protection',
                'Establish easy phishing report button for users',
            ],
            'unauthorized_access': [
                'Implement zero-trust network architecture',
                'Deploy intrusion detection/prevention systems',
                'Enable comprehensive authentication logging',
                'Conduct regular vulnerability assessments',
                'Implement network access control (NAC)',
                'Deploy privileged access management (PAM)',
            ],
        }
        return recs.get(incident_type, ['Review and update security controls'])

    def export_incident(self, incident_id, fmt='json'):
        """Export the full incident package as JSON."""
        incident = self.get_incident(incident_id)
        if 'error' in incident:
            return incident

        # Include evidence content
        edir = self._evidence_dir(incident_id)
        evidence_data = []
        for ef in incident.get('evidence', []):
            filepath = edir / ef['filename']
            try:
                content = filepath.read_text(encoding='utf-8', errors='replace')
            except Exception:
                content = '[Could not read file]'
            evidence_data.append({
                'filename': ef['filename'],
                'name': ef['name'],
                'size': ef['size'],
                'collected_at': ef['collected_at'],
                'content': content,
            })

        export = {
            'incident': incident,
            'evidence_data': evidence_data,
            'report': self.generate_report(incident_id),
            'exported_at': self._now_iso(),
        }
        return export


# ── Singleton ────────────────────────────────────────────────────

_instance = None


def get_incident_resp():
    """Get or create singleton IncidentResponse instance."""
    global _instance
    if _instance is None:
        _instance = IncidentResponse()
    return _instance


# ── CLI Runner ───────────────────────────────────────────────────

def run():
    """CLI interface for incident response module."""
    ir = get_incident_resp()

    while True:
        clear_screen()
        display_banner()
        print(f'\n{Colors.CYAN}{"=" * 50}')
        print(f'  INCIDENT RESPONSE')
        print(f'{"=" * 50}{Colors.RESET}\n')

        incidents = ir.list_incidents()
        open_count = sum(1 for i in incidents if i['status'] != 'closed')
        print(f'  Active incidents: {open_count}\n')

        print(f'  {Colors.GREEN}1{Colors.RESET} Create Incident')
        print(f'  {Colors.GREEN}2{Colors.RESET} List Incidents')
        print(f'  {Colors.GREEN}3{Colors.RESET} View Incident')
        print(f'  {Colors.GREEN}4{Colors.RESET} Run Playbook')
        print(f'  {Colors.GREEN}5{Colors.RESET} Collect Evidence')
        print(f'  {Colors.GREEN}6{Colors.RESET} Sweep IOCs')
        print(f'  {Colors.GREEN}7{Colors.RESET} Generate Report')
        print(f'  {Colors.RED}0{Colors.RESET} Back\n')

        choice = input(f'{Colors.CYAN}>{Colors.RESET} ').strip()

        if choice == '0':
            break

        elif choice == '1':
            print(f'\n{Colors.CYAN}Create New Incident{Colors.RESET}')
            name = input('  Name: ').strip()
            if not name:
                continue
            print(f'  Types: {", ".join(INCIDENT_TYPES)}')
            itype = input('  Type: ').strip()
            print(f'  Severity: {", ".join(SEVERITY_LEVELS)}')
            severity = input('  Severity: ').strip()
            desc = input('  Description: ').strip()
            result = ir.create_incident(name, itype, severity, desc)
            if 'error' in result:
                print(f'\n  {Colors.RED}Error: {result["error"]}{Colors.RESET}')
            else:
                print(f'\n  {Colors.GREEN}Created incident: {result["id"]}{Colors.RESET}')
            input('\n  Press Enter...')

        elif choice == '2':
            print(f'\n{Colors.CYAN}Incidents{Colors.RESET}\n')
            for inc in incidents:
                sev_color = {
                    'critical': Colors.RED, 'high': Colors.YELLOW,
                    'medium': Colors.CYAN, 'low': Colors.GREEN,
                }.get(inc['severity'], Colors.WHITE)
                print(f'  {inc["id"]} | {inc["name"][:30]:30s} | '
                      f'{sev_color}{inc["severity"]:8s}{Colors.RESET} | '
                      f'{inc["status"]:12s} | {inc["type"]}')
            if not incidents:
                print('  No incidents found.')
            input('\n  Press Enter...')

        elif choice == '3':
            iid = input('\n  Incident ID: ').strip()
            inc = ir.get_incident(iid)
            if 'error' in inc:
                print(f'\n  {Colors.RED}{inc["error"]}{Colors.RESET}')
            else:
                print(f'\n  {Colors.BOLD}{inc["name"]}{Colors.RESET}')
                print(f'  Type: {inc["type"]} | Severity: {inc["severity"]} | Status: {inc["status"]}')
                print(f'  Created: {inc["created"]}')
                print(f'  Description: {inc.get("description", "")}')
                print(f'\n  Timeline events: {len(inc.get("timeline", []))}')
                print(f'  Evidence items: {len(inc.get("evidence", []))}')
                progress = inc.get('playbook_progress', [])
                done = sum(1 for p in progress if p)
                print(f'  Playbook progress: {done}/{len(progress)} steps')
            input('\n  Press Enter...')

        elif choice == '4':
            iid = input('\n  Incident ID: ').strip()
            inc = ir.get_incident(iid)
            if 'error' in inc:
                print(f'\n  {Colors.RED}{inc["error"]}{Colors.RESET}')
                input('\n  Press Enter...')
                continue
            pb = ir.get_playbook(inc['type'])
            if 'error' in pb:
                print(f'\n  {Colors.RED}{pb["error"]}{Colors.RESET}')
                input('\n  Press Enter...')
                continue
            print(f'\n  {Colors.CYAN}Playbook: {pb["name"]}{Colors.RESET}\n')
            progress = inc.get('playbook_progress', [])
            for i, step in enumerate(pb['steps']):
                done = progress[i] if i < len(progress) else False
                mark = f'{Colors.GREEN}[X]{Colors.RESET}' if done else f'{Colors.RED}[ ]{Colors.RESET}'
                auto_tag = f' {Colors.YELLOW}[AUTO]{Colors.RESET}' if step.get('automated') else ''
                print(f'  {mark} {i}: {step["title"]}{auto_tag}')
            step_idx = input('\n  Step # to run (or Enter to skip): ').strip()
            if step_idx.isdigit():
                auto = input('  Auto-execute commands? (y/n): ').strip().lower() == 'y'
                result = ir.run_playbook_step(iid, int(step_idx), auto=auto)
                if 'error' in result:
                    print(f'\n  {Colors.RED}{result["error"]}{Colors.RESET}')
                else:
                    print(f'\n  {Colors.GREEN}Step completed: {result["title"]}{Colors.RESET}')
                    if result.get('output'):
                        print(f'\n{result["output"][:500]}')
            input('\n  Press Enter...')

        elif choice == '5':
            iid = input('\n  Incident ID: ').strip()
            print(f'\n  Evidence types: {", ".join(EVIDENCE_TYPES)}')
            etype = input('  Type: ').strip()
            result = ir.collect_evidence(iid, etype)
            if 'error' in result:
                print(f'\n  {Colors.RED}{result["error"]}{Colors.RESET}')
            else:
                print(f'\n  {Colors.GREEN}Collected: {result["name"]} ({result["size"]} bytes){Colors.RESET}')
                if result.get('preview'):
                    print(f'\n  Preview:\n{result["preview"][:300]}')
            input('\n  Press Enter...')

        elif choice == '6':
            iid = input('\n  Incident ID: ').strip()
            print('\n  Enter IOCs (comma-separated):')
            ips = input('  IPs: ').strip()
            domains = input('  Domains: ').strip()
            hashes = input('  Hashes: ').strip()
            iocs = {
                'ips': [x.strip() for x in ips.split(',') if x.strip()],
                'domains': [x.strip() for x in domains.split(',') if x.strip()],
                'hashes': [x.strip() for x in hashes.split(',') if x.strip()],
            }
            result = ir.sweep_iocs(iid, iocs)
            if 'error' in result:
                print(f'\n  {Colors.RED}{result["error"]}{Colors.RESET}')
            else:
                print(f'\n  {Colors.CYAN}Swept {result["total_iocs"]} IOCs, '
                      f'found {result["matches_found"]} matches{Colors.RESET}')
                for m in result.get('matches', []):
                    sev_color = Colors.RED if m['severity'] == 'critical' else Colors.YELLOW
                    print(f'  {sev_color}[{m["severity"].upper()}]{Colors.RESET} '
                          f'{m["type"]}: {m["ioc"]} in {m["found_in"]}')
            input('\n  Press Enter...')

        elif choice == '7':
            iid = input('\n  Incident ID: ').strip()
            report = ir.generate_report(iid)
            if 'error' in report:
                print(f'\n  {Colors.RED}{report["error"]}{Colors.RESET}')
            else:
                es = report['executive_summary']
                print(f'\n  {Colors.BOLD}{report["title"]}{Colors.RESET}')
                print(f'  Type: {es["incident_type"]} | Severity: {es["severity"]}')
                print(f'  Status: {es["status"]} | Duration: {es["duration"]}')
                print(f'  Timeline: {report["timeline_summary"]}')
                pp = report['playbook_progress']
                print(f'  Playbook: {pp["completed_steps"]}/{pp["total_steps"]} steps ({pp["completion_pct"]}%)')
                print(f'  Evidence: {report["evidence_summary"]["total_evidence"]} items')
                print(f'  Actions taken: {len(report["actions_taken"])}')
                print(f'\n  {Colors.CYAN}Recommendations:{Colors.RESET}')
                for r in report.get('recommendations', []):
                    print(f'    - {r}')
            input('\n  Press Enter...')
