"""
AUTARCH Threat Monitor Module
Real-time threat detection, monitoring, and counter-attack

Cross-platform network monitoring with active response capabilities.
"""

import os
import sys
import subprocess
import re
import json
import time
import platform
import urllib.request
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))

# Module metadata
DESCRIPTION = "Real-time threat detection & counter-attack"
AUTHOR = "darkHal"
VERSION = "2.0"
CATEGORY = "defense"

_is_win = platform.system() == 'Windows'


class ThreatMonitor:
    """Cross-platform real-time threat monitoring."""

    def __init__(self):
        self._data_dir = Path(__file__).parent.parent / 'data'
        self._blocklist_path = self._data_dir / 'blocklist.json'
        self._ddos_config_path = self._data_dir / 'ddos_config.json'
        self._mitigation_log_path = self._data_dir / 'mitigation_log.json'

        # In-memory state for tracking
        self._prev_bandwidth = {}
        self._prev_listening_ports = set()
        self._prev_listening_initialized = False
        self._connection_rate_history = []
        self._arp_table_cache = {}
        self._geoip_cache = {}

        # Process name cache to avoid repeated tasklist calls
        self._proc_name_cache = {}
        self._proc_name_cache_time = 0

    def run_cmd(self, cmd: str, timeout=15) -> tuple:
        """Run command and return (success, output)."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True,
                                    text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except Exception:
            return False, ""

    def run_ps(self, ps_command: str, timeout=15) -> tuple:
        """Run a PowerShell command (Windows only)."""
        cmd = f'powershell -NoProfile -ExecutionPolicy Bypass -Command "{ps_command}"'
        return self.run_cmd(cmd, timeout=timeout)

    # ==================== MONITORING ====================

    def get_connections(self):
        """Get active network connections with process info."""
        connections = []

        if _is_win:
            success, output = self.run_ps(
                "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
                "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | "
                "ConvertTo-Json -Depth 2"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    for c in data:
                        pid = c.get('OwningProcess', 0)
                        proc_name = self._get_process_name_win(pid)
                        connections.append({
                            'local_addr': c.get('LocalAddress', ''),
                            'local_port': c.get('LocalPort', 0),
                            'remote_addr': c.get('RemoteAddress', ''),
                            'remote_port': c.get('RemotePort', 0),
                            'state': c.get('State', ''),
                            'pid': pid,
                            'process': proc_name,
                        })
                except json.JSONDecodeError:
                    pass
        else:
            success, output = self.run_cmd("ss -tnp 2>/dev/null")
            if success:
                for line in output.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 5:
                        state = parts[0]
                        local = parts[3]
                        remote = parts[4]
                        proc_info = parts[5] if len(parts) > 5 else ""

                        local_parts = local.rsplit(':', 1)
                        remote_parts = remote.rsplit(':', 1)

                        pid_match = re.search(r'pid=(\d+)', proc_info)
                        proc_match = re.search(r'"([^"]+)"', proc_info)

                        connections.append({
                            'local_addr': local_parts[0] if len(local_parts) > 1 else '',
                            'local_port': int(local_parts[1]) if len(local_parts) > 1 else 0,
                            'remote_addr': remote_parts[0] if len(remote_parts) > 1 else '',
                            'remote_port': int(remote_parts[1]) if len(remote_parts) > 1 else 0,
                            'state': state,
                            'pid': int(pid_match.group(1)) if pid_match else 0,
                            'process': proc_match.group(1) if proc_match else '',
                        })

        return connections

    def _get_process_name_win(self, pid):
        """Get process name from PID on Windows (cached)."""
        if not pid:
            return ""
        # Refresh cache every 10 seconds
        now = time.time()
        if now - self._proc_name_cache_time > 10:
            self._proc_name_cache.clear()
            self._proc_name_cache_time = now
            # Bulk fetch all process names in one call
            success, output = self.run_cmd('tasklist /FO CSV /NH', timeout=10)
            if success and output.strip():
                for line in output.strip().split('\n'):
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        name = parts[0].strip('"')
                        p = parts[1].strip('"')
                        if p.isdigit():
                            self._proc_name_cache[int(p)] = name
        return self._proc_name_cache.get(int(pid), "")

    def check_port_scan_indicators(self):
        """Detect port scan patterns in active connections."""
        connections = self.get_connections()
        indicators = []

        # Group connections by remote IP
        ip_connections = {}
        for c in connections:
            rip = c.get('remote_addr', '')
            if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                ip_connections.setdefault(rip, []).append(c)

        for ip, conns in ip_connections.items():
            # Many connections from single IP to different local ports = scan
            local_ports = set(c['local_port'] for c in conns)
            syn_conns = [c for c in conns if 'SYN' in str(c.get('state', '')).upper()
                         or 'TimeWait' in str(c.get('state', ''))]

            if len(local_ports) > 10:
                indicators.append({
                    'type': 'port_scan',
                    'ip': ip,
                    'ports_targeted': len(local_ports),
                    'total_connections': len(conns),
                    'severity': 'HIGH',
                    'detail': f"{ip} connected to {len(local_ports)} different ports",
                })
            elif len(syn_conns) > 5:
                indicators.append({
                    'type': 'syn_flood',
                    'ip': ip,
                    'syn_count': len(syn_conns),
                    'severity': 'HIGH',
                    'detail': f"{ip} has {len(syn_conns)} SYN/half-open connections",
                })

        return indicators

    def get_suspicious_processes(self):
        """Identify suspicious processes."""
        suspicious = []

        if _is_win:
            success, output = self.run_ps(
                "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
                "Select-Object ProcessId, Name, CommandLine, "
                "@{N='CPU';E={$_.KernelModeTime + $_.UserModeTime}} | "
                "ConvertTo-Json -Depth 2"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    suspicious_names = {
                        'nc.exe', 'ncat.exe', 'netcat.exe', 'powershell.exe',
                        'cmd.exe', 'mshta.exe', 'wscript.exe', 'cscript.exe',
                        'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
                    }
                    for proc in data:
                        name = (proc.get('Name') or '').lower()
                        cmdline = proc.get('CommandLine') or ''
                        if name in suspicious_names and cmdline:
                            # Check for suspicious command line patterns
                            sus_patterns = ['-e cmd', '-e powershell', 'bypass', 'hidden',
                                            'downloadstring', 'invoke-expression', 'iex',
                                            'encodedcommand', '-enc ', 'base64']
                            for pat in sus_patterns:
                                if pat.lower() in cmdline.lower():
                                    suspicious.append({
                                        'pid': proc.get('ProcessId', 0),
                                        'name': proc.get('Name', ''),
                                        'cmdline': cmdline[:200],
                                        'reason': f"Suspicious pattern: {pat}",
                                        'severity': 'HIGH',
                                    })
                                    break
                except json.JSONDecodeError:
                    pass
        else:
            success, output = self.run_cmd("ps aux --no-headers 2>/dev/null")
            if success:
                suspicious_cmds = ['nc -', 'ncat ', '/bin/sh -i', '/bin/bash -i',
                                   'python -c', 'perl -e', 'ruby -e']
                for line in output.split('\n'):
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        cmdline = parts[10]
                        for pat in suspicious_cmds:
                            if pat in cmdline:
                                suspicious.append({
                                    'pid': int(parts[1]) if parts[1].isdigit() else 0,
                                    'name': parts[10].split()[0] if parts[10] else '',
                                    'cmdline': cmdline[:200],
                                    'reason': f"Suspicious pattern: {pat}",
                                    'severity': 'HIGH',
                                })
                                break

        return suspicious

    def get_recent_failed_logins(self, minutes=10):
        """Get recent failed login attempts."""
        logins = []

        if _is_win:
            success, output = self.run_ps(
                f"Get-WinEvent -FilterHashtable @{{LogName='Security'; Id=4625}} "
                f"-MaxEvents 100 -ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.TimeCreated -gt (Get-Date).AddMinutes(-{minutes}) }} | "
                f"Select-Object TimeCreated, "
                f"@{{N='IP';E={{$_.Properties[19].Value}}}}, "
                f"@{{N='User';E={{$_.Properties[5].Value}}}} | "
                f"ConvertTo-Json"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    for entry in data:
                        logins.append({
                            'time': str(entry.get('TimeCreated', '')),
                            'ip': entry.get('IP', 'Unknown'),
                            'user': entry.get('User', 'Unknown'),
                        })
                except json.JSONDecodeError:
                    pass
        else:
            success, output = self.run_cmd(
                f"grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -50"
            )
            if success:
                for line in output.split('\n'):
                    if not line.strip():
                        continue
                    ip_match = re.search(r'from\s+(\S+)', line)
                    user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', line)
                    time_match = re.match(r'^(\w+\s+\d+\s+[\d:]+)', line)
                    logins.append({
                        'time': time_match.group(1) if time_match else '',
                        'ip': ip_match.group(1) if ip_match else 'Unknown',
                        'user': user_match.group(1) if user_match else 'Unknown',
                    })

        return logins

    def get_dns_cache(self):
        """Get DNS cache entries."""
        entries = []

        if _is_win:
            success, output = self.run_ps(
                "Get-DnsClientCache -ErrorAction SilentlyContinue | "
                "Select-Object Entry, RecordName, Data, Type, TimeToLive | "
                "ConvertTo-Json -Depth 2"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    for e in data[:50]:
                        entries.append({
                            'name': e.get('Entry') or e.get('RecordName', ''),
                            'data': e.get('Data', ''),
                            'type': e.get('Type', ''),
                            'ttl': e.get('TimeToLive', 0),
                        })
                except json.JSONDecodeError:
                    pass
        else:
            # Check systemd-resolved
            success, output = self.run_cmd("resolvectl statistics 2>/dev/null")
            if success:
                entries.append({'name': 'systemd-resolved', 'data': output[:200], 'type': 'stats', 'ttl': 0})

        return entries

    # ==================== BANDWIDTH ====================

    def get_bandwidth(self):
        """Get bytes in/out per network interface with deltas."""
        interfaces = []

        if _is_win:
            success, output = self.run_ps(
                "Get-NetAdapterStatistics -ErrorAction SilentlyContinue | "
                "Select-Object Name, ReceivedBytes, SentBytes | ConvertTo-Json"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    for iface in data:
                        name = iface.get('Name', '')
                        rx = iface.get('ReceivedBytes', 0)
                        tx = iface.get('SentBytes', 0)
                        prev = self._prev_bandwidth.get(name, {})
                        interfaces.append({
                            'interface': name,
                            'rx_bytes': rx, 'tx_bytes': tx,
                            'rx_delta': max(0, rx - prev.get('rx', rx)),
                            'tx_delta': max(0, tx - prev.get('tx', tx)),
                        })
                        self._prev_bandwidth[name] = {'rx': rx, 'tx': tx}
                except json.JSONDecodeError:
                    pass
        else:
            try:
                with open('/proc/net/dev', 'r') as f:
                    for line in f:
                        if ':' not in line:
                            continue
                        name, stats = line.split(':', 1)
                        name = name.strip()
                        parts = stats.split()
                        if len(parts) >= 10:
                            rx = int(parts[0])
                            tx = int(parts[8])
                            prev = self._prev_bandwidth.get(name, {})
                            interfaces.append({
                                'interface': name,
                                'rx_bytes': rx, 'tx_bytes': tx,
                                'rx_delta': max(0, rx - prev.get('rx', rx)),
                                'tx_delta': max(0, tx - prev.get('tx', tx)),
                            })
                            self._prev_bandwidth[name] = {'rx': rx, 'tx': tx}
            except Exception:
                pass

        return interfaces

    # ==================== ARP SPOOF DETECTION ====================

    def check_arp_spoofing(self):
        """Detect ARP spoofing — multiple MACs for same IP."""
        alerts = []

        if _is_win:
            success, output = self.run_cmd("arp -a")
        else:
            success, output = self.run_cmd("ip neigh show 2>/dev/null || arp -an 2>/dev/null")

        if not success:
            return alerts

        ip_macs = defaultdict(set)
        for line in output.split('\n'):
            # Match IP and MAC patterns
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', line)
            if ip_match and mac_match:
                ip = ip_match.group(1)
                mac = mac_match.group(0).lower()
                if ip not in ('255.255.255.255',) and not ip.startswith('224.'):
                    ip_macs[ip].add(mac)

        # Merge into cache for history tracking
        for ip, macs in ip_macs.items():
            self._arp_table_cache.setdefault(ip, set()).update(macs)

        # Check for IPs with multiple MACs
        for ip, macs in self._arp_table_cache.items():
            if len(macs) > 1:
                alerts.append({
                    'ip': ip,
                    'macs': list(macs),
                    'severity': 'CRITICAL',
                    'detail': f"{ip} has {len(macs)} different MAC addresses",
                })

        return alerts

    # ==================== NEW LISTENING PORTS ====================

    def check_new_listening_ports(self):
        """Detect new listening ports since last check."""
        current_ports = {}

        if _is_win:
            success, output = self.run_ps(
                "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                "Select-Object LocalPort, OwningProcess | ConvertTo-Json"
            )
            if success and output.strip():
                try:
                    data = json.loads(output)
                    if isinstance(data, dict):
                        data = [data]
                    for entry in data:
                        port = entry.get('LocalPort', 0)
                        pid = entry.get('OwningProcess', 0)
                        current_ports[port] = {'port': port, 'pid': pid, 'process': self._get_process_name_win(pid)}
                except json.JSONDecodeError:
                    pass
        else:
            success, output = self.run_cmd("ss -tlnp 2>/dev/null")
            if success:
                for line in output.split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[3]
                        port_match = re.search(r':(\d+)$', local)
                        if port_match:
                            port = int(port_match.group(1))
                            pid_match = re.search(r'pid=(\d+)', line)
                            proc_match = re.search(r'"([^"]+)"', line)
                            current_ports[port] = {
                                'port': port,
                                'pid': int(pid_match.group(1)) if pid_match else 0,
                                'process': proc_match.group(1) if proc_match else '',
                            }

        current_set = set(current_ports.keys())

        if not self._prev_listening_initialized:
            self._prev_listening_ports = current_set
            self._prev_listening_initialized = True
            return []

        new_ports = current_set - self._prev_listening_ports
        self._prev_listening_ports = current_set

        return [current_ports[p] for p in new_ports if p in current_ports]

    # ==================== GEOIP ====================

    def geoip_lookup(self, ip):
        """GeoIP lookup via ipwho.is (free, no API key)."""
        # Skip private IPs
        if ip.startswith(('127.', '10.', '192.168.', '0.0.0.', '::')) or ip == '::1':
            return None
        if re.match(r'^172\.(1[6-9]|2\d|3[01])\.', ip):
            return None

        # Check cache
        if ip in self._geoip_cache:
            return self._geoip_cache[ip]

        try:
            req = urllib.request.Request(f'https://ipwho.is/{ip}',
                                          headers={'User-Agent': 'AUTARCH/2.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get('success'):
                    result = {
                        'ip': ip,
                        'country': data.get('country', ''),
                        'country_code': data.get('country_code', ''),
                        'city': data.get('city', ''),
                        'isp': data.get('connection', {}).get('isp', ''),
                        'org': data.get('connection', {}).get('org', ''),
                        'asn': data.get('connection', {}).get('asn', 0),
                    }
                    self._geoip_cache[ip] = result
                    return result
        except Exception:
            pass
        return None

    def get_connections_with_geoip(self):
        """Get connections enriched with GeoIP data."""
        connections = self.get_connections()
        for conn in connections:
            remote = conn.get('remote_addr', '')
            if remote and remote not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                geo = self.geoip_lookup(remote)
                conn['geo'] = geo
        return connections

    # ==================== CONNECTION RATE ====================

    def get_connection_rate(self):
        """Track connections per second with trending."""
        now = time.time()
        count = len(self.get_connections())
        self._connection_rate_history.append((now, count))

        # Trim to last 5 minutes
        cutoff = now - 300
        self._connection_rate_history = [(t, c) for t, c in self._connection_rate_history if t > cutoff]

        history = self._connection_rate_history
        current_rate = count

        # 1-minute average
        one_min = [c for t, c in history if t > now - 60]
        avg_1m = sum(one_min) / max(len(one_min), 1)

        # 5-minute average
        avg_5m = sum(c for _, c in history) / max(len(history), 1)

        # Peak
        peak = max((c for _, c in history), default=0)

        return {
            'current_rate': current_rate,
            'avg_rate_1m': round(avg_1m, 1),
            'avg_rate_5m': round(avg_5m, 1),
            'peak_rate': peak,
        }

    # ==================== DDOS DETECTION ====================

    def detect_ddos(self):
        """Detect DDoS/DoS attack patterns."""
        connections = self.get_connections()
        indicators = []
        attack_type = 'none'
        under_attack = False

        # Group by remote IP
        ip_conns = defaultdict(list)
        for c in connections:
            rip = c.get('remote_addr', '')
            if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                ip_conns[rip].append(c)

        # SYN flood: many SYN_RECV/TimeWait connections
        syn_count = sum(1 for c in connections
                        if 'SYN' in str(c.get('state', '')).upper()
                        or 'TimeWait' in str(c.get('state', '')))
        if syn_count > 50:
            under_attack = True
            attack_type = 'syn_flood'
            indicators.append(f"{syn_count} SYN/half-open connections detected")

        # Connection flood: single IP with many connections
        for ip, conns in ip_conns.items():
            if len(conns) > 50:
                under_attack = True
                if attack_type == 'none':
                    attack_type = 'connection_flood'
                indicators.append(f"{ip}: {len(conns)} connections")

        # Bandwidth spike
        bw = self.get_bandwidth()
        for iface in bw:
            rx_mbps = iface.get('rx_delta', 0) / 1_000_000
            if rx_mbps > 100:
                under_attack = True
                if attack_type == 'none':
                    attack_type = 'bandwidth_spike'
                indicators.append(f"{iface['interface']}: {rx_mbps:.1f} MB/s inbound")

        # Top talkers
        top_talkers = sorted(
            [{'ip': ip, 'connections': len(conns)} for ip, conns in ip_conns.items()],
            key=lambda x: x['connections'], reverse=True
        )[:10]

        return {
            'under_attack': under_attack,
            'attack_type': attack_type,
            'severity': 'CRITICAL' if under_attack else 'LOW',
            'indicators': indicators,
            'top_talkers': top_talkers,
            'total_connections': len(connections),
            'syn_count': syn_count,
        }

    def get_top_talkers(self, limit=20):
        """Get top source IPs by connection count."""
        connections = self.get_connections()
        ip_stats = defaultdict(lambda: {'count': 0, 'states': defaultdict(int)})

        for c in connections:
            rip = c.get('remote_addr', '')
            if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                ip_stats[rip]['count'] += 1
                state = c.get('state', 'Unknown')
                ip_stats[rip]['states'][state] += 1

        total = len(connections) or 1
        result = []
        for ip, stats in sorted(ip_stats.items(), key=lambda x: x[1]['count'], reverse=True)[:limit]:
            result.append({
                'ip': ip,
                'connections': stats['count'],
                'percent': round(stats['count'] / total * 100, 1),
                'state_breakdown': dict(stats['states']),
            })

        return result

    # ==================== RATE LIMITING ====================

    def apply_rate_limit(self, ip, rate='25/min'):
        """Apply rate limit for a specific IP."""
        if _is_win:
            # Windows doesn't support rate limiting natively in netsh
            # Use a block rule as fallback with a note
            rule_name = f"AUTARCH_RateLimit_{ip}"
            success, output = self.run_cmd(
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip}'
            )
            msg = f"Rate limit applied for {ip} (Windows: block rule)" if success else f"Failed to rate-limit {ip}"
        else:
            # Linux iptables rate limiting
            success1, _ = self.run_cmd(
                f"sudo iptables -A INPUT -s {ip} -m limit --limit {rate} --limit-burst 10 -j ACCEPT"
            )
            success2, _ = self.run_cmd(
                f"sudo iptables -A INPUT -s {ip} -j DROP"
            )
            success = success1 and success2
            msg = f"Rate limit {rate} applied for {ip}" if success else f"Failed to rate-limit {ip}"

        if success:
            self.log_mitigation('rate_limit', ip, f'Rate limit: {rate}')
        return success, msg

    def remove_rate_limit(self, ip):
        """Remove rate limit rules for an IP."""
        if _is_win:
            rule_name = f"AUTARCH_RateLimit_{ip}"
            success, _ = self.run_cmd(f'netsh advfirewall firewall delete rule name="{rule_name}"')
        else:
            self.run_cmd(f"sudo iptables -D INPUT -s {ip} -m limit --limit 25/min --limit-burst 10 -j ACCEPT")
            success, _ = self.run_cmd(f"sudo iptables -D INPUT -s {ip} -j DROP")
        return success, f"Rate limit removed for {ip}" if success else f"Failed to remove rate limit for {ip}"

    # ==================== SYN PROTECTION ====================

    def get_syn_protection_status(self):
        """Check SYN flood protection status."""
        if _is_win:
            success, output = self.run_cmd(
                'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" '
                '/v SynAttackProtect 2>nul'
            )
            enabled = '0x1' in output if success else False
            return {'enabled': enabled, 'platform': 'windows'}
        else:
            success, output = self.run_cmd("cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null")
            return {'enabled': output.strip() == '1' if success else False, 'platform': 'linux'}

    def enable_syn_protection(self):
        """Enable SYN flood protection."""
        if _is_win:
            success, _ = self.run_cmd(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" '
                '/v SynAttackProtect /t REG_DWORD /d 1 /f'
            )
        else:
            success, _ = self.run_cmd("sudo sysctl -w net.ipv4.tcp_syncookies=1")
        if success:
            self.log_mitigation('syn_protection', 'system', 'Enabled SYN protection')
        return success, "SYN protection enabled" if success else "Failed to enable SYN protection"

    def disable_syn_protection(self):
        """Disable SYN flood protection."""
        if _is_win:
            success, _ = self.run_cmd(
                'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" '
                '/v SynAttackProtect /t REG_DWORD /d 0 /f'
            )
        else:
            success, _ = self.run_cmd("sudo sysctl -w net.ipv4.tcp_syncookies=0")
        return success, "SYN protection disabled" if success else "Failed to disable SYN protection"

    # ==================== DDOS CONFIG ====================

    def get_ddos_config(self):
        """Get DDoS auto-mitigation configuration."""
        if self._ddos_config_path.exists():
            try:
                return json.loads(self._ddos_config_path.read_text())
            except json.JSONDecodeError:
                pass
        return {
            'enabled': False,
            'connection_threshold': 100,
            'syn_threshold': 50,
            'auto_block_top_talkers': True,
            'auto_enable_syn_cookies': True,
        }

    def save_ddos_config(self, config):
        """Save DDoS auto-mitigation configuration."""
        config['updated'] = datetime.now().isoformat()
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._ddos_config_path.write_text(json.dumps(config, indent=2))
        return config

    def auto_mitigate(self):
        """Run auto-mitigation based on DDoS detection."""
        config = self.get_ddos_config()
        if not config.get('enabled'):
            return {'actions': [], 'message': 'Auto-mitigation is disabled'}

        actions = []
        ddos = self.detect_ddos()

        if not ddos['under_attack']:
            return {'actions': [], 'message': 'No attack detected'}

        # Auto-block top talkers
        if config.get('auto_block_top_talkers'):
            threshold = config.get('connection_threshold', 100)
            for talker in ddos.get('top_talkers', []):
                if talker['connections'] > threshold:
                    ip = talker['ip']
                    success, msg = self.auto_block_ip(ip)
                    actions.append({'action': 'block_ip', 'target': ip, 'success': success, 'message': msg})

        # Auto-enable SYN cookies
        if config.get('auto_enable_syn_cookies') and ddos.get('syn_count', 0) > config.get('syn_threshold', 50):
            status = self.get_syn_protection_status()
            if not status.get('enabled'):
                success, msg = self.enable_syn_protection()
                actions.append({'action': 'enable_syn_protection', 'target': 'system', 'success': success, 'message': msg})

        return {'actions': actions, 'attack_type': ddos['attack_type']}

    # ==================== MITIGATION HISTORY ====================

    def get_mitigation_history(self):
        """Get log of all mitigation actions."""
        if self._mitigation_log_path.exists():
            try:
                return json.loads(self._mitigation_log_path.read_text())
            except json.JSONDecodeError:
                pass
        return []

    def log_mitigation(self, action, target, reason, auto=False):
        """Log a mitigation action."""
        history = self.get_mitigation_history()
        history.append({
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'target': target,
            'reason': reason,
            'auto': auto,
        })
        # Keep last 500
        history = history[-500:]
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._mitigation_log_path.write_text(json.dumps(history, indent=2))

    def clear_mitigation_history(self):
        """Clear mitigation history."""
        if self._mitigation_log_path.exists():
            self._mitigation_log_path.write_text('[]')

    # ==================== THREAT SCORE (ENHANCED) ====================

    def calculate_threat_score(self):
        """Calculate composite threat score (0-100). Higher = more threats."""
        score = 0
        details = []

        # Port scan indicators
        scans = self.check_port_scan_indicators()
        if scans:
            score += min(len(scans) * 15, 30)
            details.append(f"{len(scans)} port scan indicator(s)")

        # Suspicious processes
        sus_procs = self.get_suspicious_processes()
        if sus_procs:
            score += min(len(sus_procs) * 20, 40)
            details.append(f"{len(sus_procs)} suspicious process(es)")

        # Failed logins
        failed = self.get_recent_failed_logins(minutes=5)
        if len(failed) > 5:
            score += min(len(failed) * 2, 20)
            details.append(f"{len(failed)} failed logins in 5 min")

        # Active connections from blocklist
        blocklist = self.get_blocklist()
        connections = self.get_connections()
        blocked_active = [c for c in connections if c.get('remote_addr') in blocklist]
        if blocked_active:
            score += min(len(blocked_active) * 10, 30)
            details.append(f"{len(blocked_active)} active connection(s) from blocklisted IPs")

        # ARP spoofing
        arp_alerts = self.check_arp_spoofing()
        if arp_alerts:
            score += min(len(arp_alerts) * 20, 30)
            details.append(f"{len(arp_alerts)} ARP spoof alert(s)")

        # New listening ports
        new_ports = self.check_new_listening_ports()
        if new_ports:
            score += min(len(new_ports) * 10, 20)
            details.append(f"{len(new_ports)} new listening port(s)")

        # DDoS
        ddos = self.detect_ddos()
        if ddos.get('under_attack'):
            score += 30
            details.append(f"DDoS detected: {ddos.get('attack_type', 'unknown')}")

        return {
            'score': min(score, 100),
            'level': 'CRITICAL' if score >= 70 else 'HIGH' if score >= 40 else 'MEDIUM' if score >= 15 else 'LOW',
            'details': details,
        }

    # ==================== COUNTER-ATTACK ====================

    def auto_block_ip(self, ip):
        """Block an IP address using platform-appropriate firewall."""
        if _is_win:
            rule_name = f"AUTARCH_Block_{ip}"
            success, output = self.run_cmd(
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir=in action=block remoteip={ip}'
            )
        else:
            success, output = self.run_cmd(f"sudo iptables -A INPUT -s {ip} -j DROP")

        if success:
            self.add_to_blocklist(ip)
        return success, f"Blocked {ip}" if success else f"Failed to block {ip}"

    def kill_process(self, pid):
        """Kill a process by PID."""
        pid = int(pid)
        if _is_win:
            success, output = self.run_cmd(f"taskkill /F /PID {pid}")
        else:
            success, output = self.run_cmd(f"kill -9 {pid}")
        return success, f"Killed PID {pid}" if success else f"Failed to kill PID {pid}"

    def block_port(self, port, direction='in'):
        """Block a port using platform-appropriate firewall."""
        port = int(port)
        if _is_win:
            rule_name = f"AUTARCH_BlockPort_{port}_{direction}"
            success, output = self.run_cmd(
                f'netsh advfirewall firewall add rule name="{rule_name}" '
                f'dir={direction} action=block protocol=tcp localport={port}'
            )
        else:
            chain = 'INPUT' if direction == 'in' else 'OUTPUT'
            success, output = self.run_cmd(
                f"sudo iptables -A {chain} -p tcp --dport {port} -j DROP"
            )
        return success, f"Blocked port {port} ({direction})" if success else f"Failed to block port {port}"

    # ==================== BLOCKLIST ====================

    def get_blocklist(self):
        """Get persistent IP blocklist."""
        if self._blocklist_path.exists():
            try:
                data = json.loads(self._blocklist_path.read_text())
                return data.get('blocked_ips', [])
            except (json.JSONDecodeError, KeyError):
                pass
        return []

    def add_to_blocklist(self, ip):
        """Add IP to persistent blocklist."""
        blocklist = self.get_blocklist()
        if ip not in blocklist:
            blocklist.append(ip)
            self._blocklist_path.parent.mkdir(parents=True, exist_ok=True)
            self._blocklist_path.write_text(json.dumps({
                'blocked_ips': blocklist,
                'updated': datetime.now().isoformat(),
            }, indent=2))
        return blocklist

    def remove_from_blocklist(self, ip):
        """Remove IP from persistent blocklist."""
        blocklist = self.get_blocklist()
        if ip in blocklist:
            blocklist.remove(ip)
            self._blocklist_path.write_text(json.dumps({
                'blocked_ips': blocklist,
                'updated': datetime.now().isoformat(),
            }, indent=2))
        return blocklist

    def generate_threat_report(self):
        """Generate comprehensive threat report."""
        return {
            'timestamp': datetime.now().isoformat(),
            'threat_score': self.calculate_threat_score(),
            'scan_indicators': self.check_port_scan_indicators(),
            'suspicious_processes': self.get_suspicious_processes(),
            'recent_failed_logins': self.get_recent_failed_logins(minutes=10),
            'blocklist': self.get_blocklist(),
            'connection_count': len(self.get_connections()),
        }

    # ==================== SSE STREAM ====================

    def monitor_stream(self):
        """Generator for SSE streaming — yields threat data every 3 seconds."""
        # Immediate heartbeat so the browser knows the connection is live
        yield f"data: {json.dumps({'type': 'heartbeat', 'timestamp': datetime.now().isoformat()})}\n\n"

        while True:
            try:
                # Fetch shared data ONCE per iteration to avoid redundant subprocess calls
                connections = self.get_connections()
                bw = self.get_bandwidth()
                arp = self.check_arp_spoofing()
                new_ports = self.check_new_listening_ports()

                # DDoS detection uses connections + bandwidth (pass cached data)
                ddos = self._detect_ddos_cached(connections, bw)

                # Threat score using cached data
                threat_score = self._calculate_threat_score_cached(connections, bw, arp, new_ports, ddos)

                # Connection rate tracking
                now = time.time()
                self._connection_rate_history.append((now, len(connections)))
                cutoff = now - 300
                self._connection_rate_history = [(t, c) for t, c in self._connection_rate_history if t > cutoff]
                history = self._connection_rate_history
                one_min = [c for t, c in history if t > now - 60]
                avg_1m = sum(one_min) / max(len(one_min), 1)
                avg_5m = sum(c for _, c in history) / max(len(history), 1)
                peak = max((c for _, c in history), default=0)

                total_rx = sum(i.get('rx_delta', 0) for i in bw)
                total_tx = sum(i.get('tx_delta', 0) for i in bw)

                data = {
                    'timestamp': datetime.now().isoformat(),
                    'threat_score': threat_score,
                    'connection_count': len(connections),
                    'failed_logins': 0,  # Expensive — fetched on-demand via Threats tab
                    'suspicious_processes': 0,  # Expensive — fetched on-demand via Threats tab
                    'scan_indicators': 0,
                    'bandwidth': {
                        'rx_delta': total_rx, 'tx_delta': total_tx,
                        'rx_mbps': round(total_rx / 1_000_000, 2),
                        'tx_mbps': round(total_tx / 1_000_000, 2),
                    },
                    'arp_alerts': len(arp),
                    'new_ports': len(new_ports),
                    'connection_rate': {
                        'current_rate': len(connections),
                        'avg_rate_1m': round(avg_1m, 1),
                        'avg_rate_5m': round(avg_5m, 1),
                        'peak_rate': peak,
                    },
                    'ddos': {
                        'under_attack': ddos['under_attack'],
                        'attack_type': ddos['attack_type'],
                        'syn_count': ddos['syn_count'],
                    },
                }

                if new_ports:
                    data['new_port_details'] = [{'port': p['port'], 'process': p.get('process', '')} for p in new_ports]

                # Scan indicators from cached connections (no extra subprocess call)
                ip_connections = {}
                for c in connections:
                    rip = c.get('remote_addr', '')
                    if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                        ip_connections.setdefault(rip, []).append(c)
                scan_count = sum(1 for ip, conns in ip_connections.items()
                                 if len(set(c['local_port'] for c in conns)) > 10)
                data['scan_indicators'] = scan_count

                yield f"data: {json.dumps(data)}\n\n"
                time.sleep(3)
            except GeneratorExit:
                break
            except Exception:
                time.sleep(3)

    def _detect_ddos_cached(self, connections, bw):
        """DDoS detection using pre-fetched connections and bandwidth data."""
        indicators = []
        attack_type = 'none'
        under_attack = False

        ip_conns = defaultdict(list)
        for c in connections:
            rip = c.get('remote_addr', '')
            if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                ip_conns[rip].append(c)

        syn_count = sum(1 for c in connections
                        if 'SYN' in str(c.get('state', '')).upper()
                        or 'TimeWait' in str(c.get('state', '')))
        if syn_count > 50:
            under_attack = True
            attack_type = 'syn_flood'
            indicators.append(f"{syn_count} SYN/half-open connections detected")

        for ip, conns in ip_conns.items():
            if len(conns) > 50:
                under_attack = True
                if attack_type == 'none':
                    attack_type = 'connection_flood'
                indicators.append(f"{ip}: {len(conns)} connections")

        for iface in bw:
            rx_mbps = iface.get('rx_delta', 0) / 1_000_000
            if rx_mbps > 100:
                under_attack = True
                if attack_type == 'none':
                    attack_type = 'bandwidth_spike'
                indicators.append(f"{iface['interface']}: {rx_mbps:.1f} MB/s inbound")

        return {
            'under_attack': under_attack,
            'attack_type': attack_type,
            'severity': 'CRITICAL' if under_attack else 'LOW',
            'indicators': indicators,
            'total_connections': len(connections),
            'syn_count': syn_count,
        }

    def _calculate_threat_score_cached(self, connections, bw, arp, new_ports, ddos):
        """Lightweight threat score using pre-fetched data (no extra subprocess calls)."""
        score = 0
        details = []

        # Port scan indicators from cached connections
        ip_connections = {}
        for c in connections:
            rip = c.get('remote_addr', '')
            if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                ip_connections.setdefault(rip, []).append(c)
        scans = sum(1 for ip, conns in ip_connections.items()
                    if len(set(c['local_port'] for c in conns)) > 10)
        if scans:
            score += min(scans * 15, 30)
            details.append(f"{scans} port scan indicator(s)")

        # Active connections from blocklist
        blocklist = self.get_blocklist()
        blocked_active = [c for c in connections if c.get('remote_addr') in blocklist]
        if blocked_active:
            score += min(len(blocked_active) * 10, 30)
            details.append(f"{len(blocked_active)} active connection(s) from blocklisted IPs")

        # ARP spoofing
        if arp:
            score += min(len(arp) * 20, 30)
            details.append(f"{len(arp)} ARP spoof alert(s)")

        # New listening ports
        if new_ports:
            score += min(len(new_ports) * 10, 20)
            details.append(f"{len(new_ports)} new listening port(s)")

        # DDoS
        if ddos.get('under_attack'):
            score += 30
            details.append(f"DDoS detected: {ddos.get('attack_type', 'unknown')}")

        return {
            'score': min(score, 100),
            'level': 'CRITICAL' if score >= 70 else 'HIGH' if score >= 40 else 'MEDIUM' if score >= 15 else 'LOW',
            'details': details,
        }


# ==================== CLI MENU ====================

def run():
    """CLI entry point."""
    from core.banner import Colors, clear_screen, display_banner
    clear_screen()
    display_banner()
    print(f"\n{Colors.BOLD}{Colors.PURPLE}Threat Monitor{Colors.RESET}\n")

    m = ThreatMonitor()
    report = m.generate_threat_report()

    score = report['threat_score']
    color = Colors.RED if score['score'] >= 40 else Colors.YELLOW if score['score'] >= 15 else Colors.GREEN
    print(f"{color}Threat Score: {score['score']}/100 ({score['level']}){Colors.RESET}")
    if score['details']:
        for d in score['details']:
            print(f"  - {d}")

    print(f"\n{Colors.CYAN}Active connections: {report['connection_count']}{Colors.RESET}")
    print(f"{Colors.CYAN}Failed logins (10m): {len(report['recent_failed_logins'])}{Colors.RESET}")
    print(f"{Colors.CYAN}Suspicious processes: {len(report['suspicious_processes'])}{Colors.RESET}")
    print(f"{Colors.CYAN}Scan indicators: {len(report['scan_indicators'])}{Colors.RESET}")
    print(f"{Colors.CYAN}Blocklisted IPs: {len(report['blocklist'])}{Colors.RESET}")

    if report['suspicious_processes']:
        print(f"\n{Colors.RED}Suspicious Processes:{Colors.RESET}")
        for p in report['suspicious_processes']:
            print(f"  PID {p['pid']} — {p['name']}: {p['reason']}")

    if report['scan_indicators']:
        print(f"\n{Colors.RED}Port Scan Indicators:{Colors.RESET}")
        for s in report['scan_indicators']:
            print(f"  {s['ip']}: {s['detail']}")

    input("\nPress Enter to continue...")


# ==================== SINGLETON ====================

_threat_monitor_instance = None


def get_threat_monitor():
    """Get or create singleton ThreatMonitor instance (preserves in-memory state)."""
    global _threat_monitor_instance
    if _threat_monitor_instance is None:
        _threat_monitor_instance = ThreatMonitor()
    return _threat_monitor_instance
