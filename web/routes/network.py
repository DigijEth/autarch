"""Network Security — connections, IDS, rogue device detection, monitoring."""

import json
import logging
import os
import platform
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from flask import Blueprint, render_template, request, jsonify, Response

from web.auth import login_required
from core.daemon import root_exec

logger = logging.getLogger(__name__)

network_bp = Blueprint('network', __name__, url_prefix='/network')

# ── Paths ────────────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent.parent / 'data' / 'network'
KNOWN_DEVICES_FILE = DATA_DIR / 'known_devices.json'

# ── Monitor state ────────────────────────────────────────────────────────────
_monitor_active = False
_monitor_thread = None
_monitor_buffer = deque(maxlen=500)
_monitor_lock = threading.Lock()

# ── Helpers ──────────────────────────────────────────────────────────────────

def _run(cmd, timeout=15):
    """Run a command and return dict {'ok', 'stdout', 'stderr', 'code'}.
    Accepts both string (shell) and list commands.
    Also supports tuple unpacking: ok, out = _run('cmd') still works."""
    try:
        if isinstance(cmd, (list, tuple)):
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return _RunResult(r.returncode == 0, r.stdout.strip(), r.stderr.strip(), r.returncode)
    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", cmd)
        return _RunResult(False, "", "timeout", -1)
    except Exception as e:
        logger.error("Command failed: %s — %s", cmd, e)
        return _RunResult(False, "", str(e), -1)


class _RunResult:
    """Result that works as both a dict and a tuple for backwards compatibility."""
    def __init__(self, ok, stdout, stderr='', code=0):
        self.ok = ok
        self.stdout = stdout
        self.stderr = stderr
        self.code = code
        self._tuple = (ok, stdout)
    def __getitem__(self, key):
        if isinstance(key, int):
            return self._tuple[key]
        return {'ok': self.ok, 'stdout': self.stdout, 'stderr': self.stderr, 'code': self.code}[key]
    def __iter__(self):
        return iter(self._tuple)
    def __bool__(self):
        return self.ok
    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default


def _run_root(cmd, timeout=15):
    """Run a command via the privileged daemon. No 'sudo' prefix needed.

    Args:
        cmd: Command as list of strings or a string
    Returns:
        dict from root_exec: {'ok': bool, 'stdout': str, 'stderr': str, 'code': int}
    """
    if isinstance(cmd, str):
        import shlex
        cmd = shlex.split(cmd)
    # Strip sudo if someone passes it — daemon is already root
    if cmd and cmd[0] == 'sudo':
        cmd = cmd[1:]
    return root_exec(cmd, timeout=timeout)


def _parse_nmcli_line(line):
    """Parse a nmcli -t output line, handling escaped colons in BSSIDs.
    nmcli escapes colons in values as \\: but uses : as field separator."""
    parts = re.split(r'(?<!\\):', line)
    # Unescape \\: back to : in each field
    return [p.replace('\\:', ':') for p in parts]


def _is_linux():
    return platform.system() == 'Linux'


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return str(DATA_DIR)


def _load_known_devices():
    _ensure_data_dir()
    if KNOWN_DEVICES_FILE.exists():
        try:
            return json.loads(KNOWN_DEVICES_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_known_devices(devices):
    _ensure_data_dir()
    KNOWN_DEVICES_FILE.write_text(json.dumps(devices, indent=2))


def _is_rfc1918(ip):
    """Check if IP is private (RFC1918)."""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


STANDARD_PORTS = {20, 21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
                  8080, 8443, 3306, 5432, 123, 853, 5353}

# ── Routes ───────────────────────────────────────────────────────────────────

@network_bp.route('/')
@login_required
def index():
    return render_template('network.html')


@network_bp.route('/connections', methods=['POST'])
@login_required
def connections():
    """Return active network connections."""
    logger.info("Scanning active connections")
    if _is_linux():
        ok, out = _run('ss -tunap')
    else:
        ok, out = _run('netstat -ano')

    if not ok:
        return jsonify({'ok': False, 'error': 'Failed to get connections'})

    lines = out.splitlines()
    conns = []
    if _is_linux() and len(lines) > 1:
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                entry = {
                    'protocol': parts[0],
                    'state': parts[1] if len(parts) > 5 else '',
                    'recv_q': parts[1] if len(parts) > 5 else parts[1],
                    'local': parts[4] if len(parts) > 5 else parts[3],
                    'remote': parts[5] if len(parts) > 5 else parts[4],
                    'process': parts[6] if len(parts) > 6 else '',
                }
                conns.append(entry)
    else:
        for line in lines[4:]:
            parts = line.split()
            if len(parts) >= 4:
                conns.append({
                    'protocol': parts[0],
                    'local': parts[1],
                    'remote': parts[2],
                    'state': parts[3] if len(parts) > 3 else '',
                    'process': parts[4] if len(parts) > 4 else '',
                })

    return jsonify({'ok': True, 'connections': conns, 'count': len(conns)})


@network_bp.route('/arp-table', methods=['POST'])
@login_required
def arp_table():
    """Return the ARP table."""
    logger.info("Fetching ARP table")
    if _is_linux():
        ok, out = _run('ip neigh')
    else:
        ok, out = _run('arp -a')

    if not ok:
        return jsonify({'ok': False, 'error': 'Failed to get ARP table'})

    entries = []
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if _is_linux() and len(parts) >= 4:
            entry = {
                'ip': parts[0],
                'dev': parts[2] if 'dev' in parts else '',
                'mac': '',
                'state': parts[-1],
            }
            if 'lladdr' in parts:
                idx = parts.index('lladdr')
                if idx + 1 < len(parts):
                    entry['mac'] = parts[idx + 1]
            entries.append(entry)
        elif not _is_linux() and len(parts) >= 3:
            ip_match = re.search(r'([\d.]+)', parts[0])
            entries.append({
                'ip': ip_match.group(1) if ip_match else parts[0],
                'mac': parts[1] if len(parts) > 1 else '',
                'state': parts[2] if len(parts) > 2 else '',
                'dev': '',
            })

    return jsonify({'ok': True, 'entries': entries, 'count': len(entries)})


@network_bp.route('/interfaces', methods=['POST'])
@login_required
def interfaces():
    """Return network interfaces with IPs."""
    logger.info("Listing network interfaces")
    ifaces = []

    if _is_linux():
        ok, out = _run('ip -j addr show')
        if ok and out:
            try:
                data = json.loads(out)
                for iface in data:
                    addrs = []
                    for a in iface.get('addr_info', []):
                        addrs.append({
                            'family': a.get('family', ''),
                            'address': a.get('local', ''),
                            'prefix': a.get('prefixlen', ''),
                        })
                    ifaces.append({
                        'name': iface.get('ifname', ''),
                        'state': iface.get('operstate', ''),
                        'mac': iface.get('address', ''),
                        'mtu': iface.get('mtu', ''),
                        'addresses': addrs,
                    })
                return jsonify({'ok': True, 'interfaces': ifaces})
            except json.JSONDecodeError:
                pass

        # Fallback
        ok, out = _run('ip addr show')
        if ok:
            current = None
            for line in out.splitlines():
                m = re.match(r'^\d+:\s+(\S+):', line)
                if m:
                    current = {'name': m.group(1), 'addresses': [], 'mac': '', 'state': '', 'mtu': ''}
                    ifaces.append(current)
                    mtu_m = re.search(r'mtu\s+(\d+)', line)
                    if mtu_m:
                        current['mtu'] = mtu_m.group(1)
                    if 'UP' in line:
                        current['state'] = 'UP'
                    else:
                        current['state'] = 'DOWN'
                elif current:
                    lm = re.search(r'link/ether\s+([\da-f:]+)', line)
                    if lm:
                        current['mac'] = lm.group(1)
                    im = re.search(r'inet6?\s+(\S+)', line)
                    if im:
                        current['addresses'].append({'address': im.group(1)})
    else:
        ok, out = _run('ipconfig /all')
        if ok:
            current = None
            for line in out.splitlines():
                if re.match(r'\S', line) and ':' in line:
                    current = {'name': line.strip().rstrip(':'), 'addresses': [], 'mac': '', 'state': 'UP', 'mtu': ''}
                    ifaces.append(current)
                elif current:
                    if 'Physical Address' in line:
                        m = re.search(r':\s+(.+)', line)
                        if m:
                            current['mac'] = m.group(1).strip()
                    elif 'IPv4 Address' in line or 'IP Address' in line:
                        m = re.search(r':\s+([\d.]+)', line)
                        if m:
                            current['addresses'].append({'address': m.group(1), 'family': 'inet'})

    return jsonify({'ok': True, 'interfaces': ifaces})


# ── Intrusion Detection Scan ─────────────────────────────────────────────────

@network_bp.route('/ids/scan', methods=['POST'])
@login_required
def ids_scan():
    """Run intrusion detection checks."""
    logger.info("Running IDS scan")
    results = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'arp_spoof': _check_arp_spoof(),
        'promiscuous': _check_promiscuous(),
        'dhcp': _check_unauthorized_dhcp(),
        'suspicious_conns': _check_suspicious_connections(),
        'raw_sockets': _check_raw_sockets(),
    }

    # Compute overall severity
    severities = []
    for key in ('arp_spoof', 'promiscuous', 'dhcp', 'suspicious_conns', 'raw_sockets'):
        severities.append(results[key].get('severity', 'clean'))

    if 'critical' in severities:
        results['overall'] = 'critical'
    elif 'warning' in severities:
        results['overall'] = 'warning'
    else:
        results['overall'] = 'clean'

    return jsonify({'ok': True, 'results': results})


def _check_arp_spoof():
    """Check ARP table for spoofing indicators."""
    if not _is_linux():
        return {'severity': 'clean', 'details': 'ARP spoof check only supported on Linux', 'alerts': []}

    ok, out = _run('ip neigh')
    if not ok:
        return {'severity': 'clean', 'details': 'Could not read ARP table', 'alerts': []}

    ip_to_macs = {}
    mac_to_ips = {}
    for line in out.splitlines():
        parts = line.split()
        if 'lladdr' not in parts:
            continue
        ip = parts[0]
        idx = parts.index('lladdr')
        if idx + 1 >= len(parts):
            continue
        mac = parts[idx + 1].lower()

        ip_to_macs.setdefault(ip, set()).add(mac)
        mac_to_ips.setdefault(mac, set()).add(ip)

    alerts = []
    # IPs with multiple MACs
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            alerts.append({
                'type': 'ip_multi_mac',
                'message': f'IP {ip} has multiple MACs: {", ".join(macs)}',
                'ip': ip,
                'macs': list(macs),
            })

    # MACs with multiple IPs (could be router, but flag it)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 3:  # threshold — routers may have a couple
            alerts.append({
                'type': 'mac_multi_ip',
                'message': f'MAC {mac} has {len(ips)} IPs: {", ".join(list(ips)[:5])}',
                'mac': mac,
                'ips': list(ips),
            })

    severity = 'critical' if any(a['type'] == 'ip_multi_mac' for a in alerts) else \
               'warning' if alerts else 'clean'

    return {'severity': severity, 'alerts': alerts, 'details': f'{len(alerts)} issue(s) found'}


def _check_promiscuous():
    """Check for interfaces in promiscuous mode."""
    alerts = []
    if not _is_linux():
        return {'severity': 'clean', 'details': 'Promiscuous check only on Linux', 'alerts': []}

    try:
        net_dir = Path('/sys/class/net')
        if net_dir.exists():
            for iface_dir in net_dir.iterdir():
                flags_file = iface_dir / 'flags'
                if flags_file.exists():
                    flags_hex = flags_file.read_text().strip()
                    try:
                        flags = int(flags_hex, 16)
                        if flags & 0x100:  # IFF_PROMISC
                            alerts.append({
                                'type': 'promiscuous',
                                'interface': iface_dir.name,
                                'message': f'Interface {iface_dir.name} is in promiscuous mode',
                            })
                    except ValueError:
                        pass
    except Exception as e:
        logger.error("Promisc check error: %s", e)

    severity = 'warning' if alerts else 'clean'
    return {'severity': severity, 'alerts': alerts, 'details': f'{len(alerts)} interface(s) in promiscuous mode'}


def _check_unauthorized_dhcp():
    """Scan for unauthorized DHCP servers."""
    alerts = []
    if not _is_linux():
        return {'severity': 'clean', 'details': 'DHCP check only on Linux', 'alerts': []}

    # Check for DHCP servers by looking at lease files and listening
    ok, out = _run('ip route show default')
    gateway = ''
    if ok:
        m = re.search(r'via\s+([\d.]+)', out)
        if m:
            gateway = m.group(1)

    # Check dhclient leases for DHCP server info
    lease_paths = [
        '/var/lib/dhcp/dhclient.leases',
        '/var/lib/dhclient/dhclient.leases',
        '/var/lib/NetworkManager/*.lease',
    ]
    dhcp_servers = set()
    for lp in lease_paths:
        import glob as globmod
        for f in globmod.glob(lp):
            try:
                content = Path(f).read_text()
                for m in re.finditer(r'dhcp-server-identifier\s+([\d.]+)', content):
                    dhcp_servers.add(m.group(1))
            except Exception:
                pass

    # Also check ss for anything listening on port 67 (DHCP server)
    ok, out = _run('ss -ulnp sport = :67')
    if ok and len(out.splitlines()) > 1:
        for line in out.splitlines()[1:]:
            alerts.append({
                'type': 'local_dhcp',
                'message': f'Local DHCP server process detected: {line.strip()}',
            })

    for server in dhcp_servers:
        if gateway and server != gateway:
            alerts.append({
                'type': 'unauthorized_dhcp',
                'message': f'DHCP server {server} differs from gateway {gateway}',
                'server': server,
                'gateway': gateway,
            })

    severity = 'critical' if any(a['type'] == 'unauthorized_dhcp' for a in alerts) else \
               'warning' if alerts else 'clean'
    return {'severity': severity, 'alerts': alerts, 'details': f'{len(dhcp_servers)} DHCP server(s) seen'}


def _check_suspicious_connections():
    """Flag connections to non-RFC1918 IPs on unusual ports."""
    alerts = []
    if _is_linux():
        ok, out = _run('ss -tunp')
    else:
        ok, out = _run('netstat -ano')

    if not ok:
        return {'severity': 'clean', 'details': 'Could not read connections', 'alerts': []}

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 5:
            continue
        # Get remote address
        remote = parts[5] if len(parts) > 5 else parts[4]
        # Parse IP:port
        m = re.match(r'([\d.]+):(\d+)', remote)
        if not m:
            # Try [ipv6]:port
            m = re.match(r'\[([^\]]+)\]:(\d+)', remote)
        if not m:
            continue

        ip, port_str = m.group(1), m.group(2)
        try:
            port = int(port_str)
        except ValueError:
            continue

        if ip in ('0.0.0.0', '*', '127.0.0.1', '::1', '::'):
            continue

        if not _is_rfc1918(ip) and port not in STANDARD_PORTS:
            process = parts[6] if len(parts) > 6 else ''
            alerts.append({
                'type': 'suspicious_conn',
                'message': f'Connection to {ip}:{port} (non-standard port, external IP)',
                'remote_ip': ip,
                'remote_port': port,
                'process': process,
            })

    # Cap alerts to avoid noise
    severity = 'warning' if alerts else 'clean'
    if len(alerts) > 20:
        severity = 'critical'

    return {
        'severity': severity,
        'alerts': alerts[:50],
        'total': len(alerts),
        'details': f'{len(alerts)} suspicious connection(s)',
    }


def _check_raw_sockets():
    """Check /proc/net/raw and /proc/net/raw6 for processes with raw socket access."""
    alerts = []
    if not _is_linux():
        return {'severity': 'clean', 'details': 'Raw socket check only on Linux', 'alerts': []}

    for path in ('/proc/net/raw', '/proc/net/raw6'):
        try:
            content = Path(path).read_text()
            lines = content.strip().splitlines()
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        alerts.append({
                            'type': 'raw_socket',
                            'source': path,
                            'local_addr': parts[1] if len(parts) > 1 else '',
                            'remote_addr': parts[2] if len(parts) > 2 else '',
                            'uid': parts[7] if len(parts) > 7 else '',
                            'message': f'Raw socket in {path}: local={parts[1]}',
                        })
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.error("Raw socket check error for %s: %s", path, e)

    severity = 'warning' if alerts else 'clean'
    return {'severity': severity, 'alerts': alerts, 'details': f'{len(alerts)} raw socket(s) open'}


# ── Rogue Device Detection ───────────────────────────────────────────────────

@network_bp.route('/rogue-detect', methods=['POST'])
@login_required
def rogue_detect():
    """Scan for rogue devices on the network."""
    logger.info("Scanning for rogue devices")

    known = _load_known_devices()

    # Get current ARP table
    if _is_linux():
        ok, out = _run('ip neigh')
    else:
        ok, out = _run('arp -a')

    if not ok:
        return jsonify({'ok': False, 'error': 'Failed to read ARP table'})

    current_devices = {}
    for line in out.splitlines():
        parts = line.split()
        if _is_linux():
            if 'lladdr' not in parts:
                continue
            ip = parts[0]
            idx = parts.index('lladdr')
            mac = parts[idx + 1].lower() if idx + 1 < len(parts) else ''
        else:
            ip_match = re.search(r'([\d.]+)', parts[0] if parts else '')
            if not ip_match:
                continue
            ip = ip_match.group(1)
            mac = parts[1].lower() if len(parts) > 1 else ''

        if mac and mac != '00:00:00:00:00:00':
            current_devices[ip] = {
                'ip': ip,
                'mac': mac,
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'last_seen': datetime.now(timezone.utc).isoformat(),
            }

    # Compare with known devices
    new_devices = []
    spoofed = []
    unauthorized = []

    for ip, dev in current_devices.items():
        if ip in known:
            # Check MAC change (possible spoof)
            if known[ip].get('mac') and known[ip]['mac'] != dev['mac']:
                spoofed.append({
                    'ip': ip,
                    'expected_mac': known[ip]['mac'],
                    'actual_mac': dev['mac'],
                    'message': f'MAC changed for {ip}: expected {known[ip]["mac"]}, got {dev["mac"]}',
                })
            known[ip]['last_seen'] = dev['last_seen']
        else:
            new_devices.append(dev)
            # Check if this MAC appears for another known IP (MAC spoof)
            for kip, kdev in known.items():
                if kdev.get('mac') == dev['mac'] and kip != ip:
                    spoofed.append({
                        'ip': ip,
                        'known_ip': kip,
                        'mac': dev['mac'],
                        'message': f'MAC {dev["mac"]} is known for {kip} but appeared on {ip}',
                    })

    # Unauthorized = not in known and not newly trusted
    for dev in new_devices:
        unauthorized.append({
            'ip': dev['ip'],
            'mac': dev['mac'],
            'message': f'Unknown device {dev["ip"]} ({dev["mac"]})',
        })

    _save_known_devices(known)

    return jsonify({
        'ok': True,
        'current_devices': list(current_devices.values()),
        'known_devices': known,
        'new_devices': new_devices,
        'spoofed': spoofed,
        'unauthorized': unauthorized,
        'summary': {
            'total': len(current_devices),
            'known': len([ip for ip in current_devices if ip in known]),
            'new': len(new_devices),
            'spoofed': len(spoofed),
        },
    })


@network_bp.route('/rogue-detect/trust', methods=['POST'])
@login_required
def trust_device():
    """Add a device to the known devices list."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    mac = data.get('mac', '').strip().lower()
    if not ip or not mac:
        return jsonify({'ok': False, 'error': 'IP and MAC required'})

    known = _load_known_devices()
    known[ip] = {
        'mac': mac,
        'trusted': True,
        'trusted_at': datetime.now(timezone.utc).isoformat(),
        'first_seen': known.get(ip, {}).get('first_seen', datetime.now(timezone.utc).isoformat()),
        'last_seen': datetime.now(timezone.utc).isoformat(),
    }
    _save_known_devices(known)
    logger.info("Trusted device: %s (%s)", ip, mac)
    return jsonify({'ok': True, 'message': f'Device {ip} trusted'})


# ── Intruder Trace ───────────────────────────────────────────────────────────

@network_bp.route('/intruder-trace', methods=['POST'])
@login_required
def intruder_trace():
    """Trace an IP: reverse DNS, whois, open ports, associated processes."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'ok': False, 'error': 'IP address required'})

    # Validate IP format
    if not re.match(r'^[\d.]+$', ip) and not re.match(r'^[a-fA-F0-9:]+$', ip):
        return jsonify({'ok': False, 'error': 'Invalid IP format'})

    logger.info("Tracing intruder IP: %s", ip)
    result = {'ip': ip}

    # Reverse DNS
    ok, out = _run(f'dig +short -x {ip}', timeout=10)
    result['reverse_dns'] = out if ok and out else 'No reverse DNS'

    # GeoIP (using external service or local geoiplookup)
    ok, out = _run(f'geoiplookup {ip}', timeout=10)
    if ok and out and 'not found' not in out.lower():
        result['geoip'] = out
    else:
        result['geoip'] = 'GeoIP data not available'

    # Whois (truncated)
    ok, out = _run(f'whois {ip}', timeout=15)
    if ok and out:
        # Extract key fields
        whois_lines = []
        for line in out.splitlines()[:60]:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('%'):
                whois_lines.append(line)
        result['whois'] = '\n'.join(whois_lines[:40])
    else:
        result['whois'] = 'Whois lookup failed'

    # Open ports (quick scan)
    ok, out = _run(f'nmap -F -T4 --open {ip}', timeout=30)
    if ok and out:
        result['open_ports'] = out
    else:
        result['open_ports'] = 'Port scan unavailable (nmap not installed?)'

    # Associated processes
    if _is_linux():
        ok, out = _run(f'ss -tunp | grep {ip}')
    else:
        ok, out = _run(f'netstat -ano | findstr {ip}')
    result['processes'] = out if ok and out else 'No active connections to this IP'

    # Connection history (from conntrack if available)
    if _is_linux():
        ok, out = _run(f'conntrack -L -d {ip} 2>/dev/null || conntrack -L -s {ip} 2>/dev/null')
        result['connection_history'] = out if ok and out else 'conntrack not available or no history'
    else:
        result['connection_history'] = 'Connection history not available on this platform'

    return jsonify({'ok': True, 'trace': result})


# ── Block IP ─────────────────────────────────────────────────────────────────

@network_bp.route('/block-ip', methods=['POST'])
@login_required
def block_ip():
    """Block or unblock an IP using iptables/nftables."""
    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    action = data.get('action', 'block').strip()

    if not ip:
        return jsonify({'ok': False, 'error': 'IP required'})
    if not re.match(r'^[\d.]+$', ip):
        return jsonify({'ok': False, 'error': 'Invalid IP format'})
    if action not in ('block', 'unblock'):
        return jsonify({'ok': False, 'error': 'Action must be block or unblock'})

    logger.info("Firewall %s IP: %s", action, ip)

    if not _is_linux():
        return jsonify({'ok': False, 'error': 'Firewall control only supported on Linux'})

    if action == 'block':
        # Try nftables first, fall back to iptables
        r = _run_root(['nft', 'add', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip, 'drop'])
        if not r['ok']:
            r = _run_root(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
        ok, out = r['ok'], r['stdout']
        r2 = _run_root(['nft', 'add', 'rule', 'inet', 'filter', 'output', 'ip', 'daddr', ip, 'drop'])
        if not r2['ok']:
            r2 = _run_root(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'])
        ok2 = r2['ok']
    else:
        _run_root(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
        _run_root(['iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'])
        _run_root(['nft', 'delete', 'rule', 'inet', 'filter', 'input', 'ip', 'saddr', ip, 'drop'])
        _run_root(['nft', 'delete', 'rule', 'inet', 'filter', 'output', 'ip', 'daddr', ip, 'drop'])
        ok, out = True, ''

    return jsonify({
        'ok': ok,
        'message': f'IP {ip} {"blocked" if action == "block" else "unblocked"}',
        'ip': ip,
        'action': action,
    })


# ── ARP Spoof Detection & Remediation ─────────────────────────────────────────

@network_bp.route('/arp-spoof/scan', methods=['POST'])
@login_required
def arp_spoof_scan():
    """Deep ARP spoof scan: checks ARP table, gateway MAC, compares with stored baseline."""
    import re
    findings = []
    gateway_info = {}

    # Get default gateway
    r = _run(['ip', 'route', 'show', 'default'], timeout=5)
    if r['ok']:
        m = re.search(r'default via (\S+)\s+dev\s+(\S+)', r['stdout'])
        if m:
            gateway_info['ip'] = m.group(1)
            gateway_info['interface'] = m.group(2)

    # Get gateway MAC
    if gateway_info.get('ip'):
        r = _run(['ip', 'neigh', 'show', gateway_info['ip']], timeout=5)
        if r['ok']:
            m = re.search(r'lladdr\s+([\da-fA-F:]+)', r['stdout'])
            if m:
                gateway_info['mac'] = m.group(1).lower()

    # Load stored baseline
    data_dir = _ensure_data_dir()
    baseline_file = os.path.join(data_dir, 'arp_baseline.json')
    baseline = {}
    if os.path.exists(baseline_file):
        try:
            with open(baseline_file) as f:
                baseline = json.load(f)
        except Exception:
            pass

    # Compare gateway MAC with baseline
    if gateway_info.get('mac') and baseline.get('gateway_mac'):
        if gateway_info['mac'] != baseline['gateway_mac']:
            findings.append({
                'severity': 'critical',
                'type': 'gateway_mac_changed',
                'message': f"Gateway MAC changed! Stored: {baseline['gateway_mac']}, Current: {gateway_info['mac']}",
                'detail': 'This is a strong indicator of ARP poisoning. Someone may be intercepting your traffic.',
                'fix': f"sudo arp -s {gateway_info['ip']} {baseline['gateway_mac']}",
            })

    # Full ARP table scan
    r = _run(['ip', 'neigh'], timeout=5)
    arp_entries = []
    ip_to_macs = {}
    mac_to_ips = {}
    if r['ok']:
        for line in r['stdout'].strip().split('\n'):
            parts = line.split()
            if 'lladdr' not in parts:
                continue
            ip = parts[0]
            idx = parts.index('lladdr')
            mac = parts[idx + 1].lower() if idx + 1 < len(parts) else ''
            state = parts[-1] if parts else ''
            arp_entries.append({'ip': ip, 'mac': mac, 'state': state})
            ip_to_macs.setdefault(ip, set()).add(mac)
            mac_to_ips.setdefault(mac, set()).add(ip)

    # Detect IP with multiple MACs (definitive spoof indicator)
    for ip, macs in ip_to_macs.items():
        if len(macs) > 1:
            findings.append({
                'severity': 'critical',
                'type': 'ip_multi_mac',
                'message': f"IP {ip} resolves to multiple MACs: {', '.join(macs)}",
                'detail': 'An attacker is sending fake ARP replies to associate their MAC with this IP.',
                'fix': f"sudo arp -d {ip} && sudo arp -s {ip} <CORRECT_MAC>",
            })

    # Detect MAC claiming too many IPs
    for mac, ips in mac_to_ips.items():
        if len(ips) > 4:
            findings.append({
                'severity': 'warning',
                'type': 'mac_multi_ip',
                'message': f"MAC {mac} claims {len(ips)} IPs: {', '.join(list(ips)[:6])}",
                'detail': 'This device is responding to ARP requests for many IPs. Could be a router or an ARP spoofer.',
                'fix': 'Verify this MAC belongs to your router. If not, block it.',
            })

    # Detect gratuitous ARP (broadcast MAC in table)
    for entry in arp_entries:
        if entry['mac'] == 'ff:ff:ff:ff:ff:ff':
            findings.append({
                'severity': 'warning',
                'type': 'broadcast_mac',
                'message': f"IP {entry['ip']} has broadcast MAC ff:ff:ff:ff:ff:ff",
                'detail': 'This is unusual and may indicate ARP table corruption or an attack.',
                'fix': f"sudo arp -d {entry['ip']}",
            })

    severity = 'critical' if any(f['severity'] == 'critical' for f in findings) else \
               'warning' if findings else 'clean'

    return jsonify({
        'ok': True,
        'severity': severity,
        'findings': findings,
        'gateway': gateway_info,
        'arp_table': arp_entries,
        'has_baseline': bool(baseline.get('gateway_mac')),
    })


@network_bp.route('/arp-spoof/save-baseline', methods=['POST'])
@login_required
def arp_spoof_save_baseline():
    """Save the current ARP state as the trusted baseline."""
    import re
    data_dir = _ensure_data_dir()
    baseline_file = os.path.join(data_dir, 'arp_baseline.json')

    baseline = {'timestamp': __import__('time').time(), 'entries': {}}

    # Get gateway
    r = _run(['ip', 'route', 'show', 'default'], timeout=5)
    if r['ok']:
        m = re.search(r'default via (\S+)', r['stdout'])
        if m:
            baseline['gateway_ip'] = m.group(1)
            r2 = _run(['ip', 'neigh', 'show', m.group(1)], timeout=5)
            if r2['ok']:
                m2 = re.search(r'lladdr\s+([\da-fA-F:]+)', r2['stdout'])
                if m2:
                    baseline['gateway_mac'] = m2.group(1).lower()

    # Save all ARP entries
    r = _run(['ip', 'neigh'], timeout=5)
    if r['ok']:
        for line in r['stdout'].strip().split('\n'):
            parts = line.split()
            if 'lladdr' in parts:
                ip = parts[0]
                idx = parts.index('lladdr')
                mac = parts[idx + 1].lower() if idx + 1 < len(parts) else ''
                baseline['entries'][ip] = mac

    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=2)

    return jsonify({'ok': True, 'gateway_mac': baseline.get('gateway_mac', ''),
                    'entries': len(baseline['entries'])})


@network_bp.route('/arp-spoof/fix', methods=['POST'])
@login_required
def arp_spoof_fix():
    """Apply ARP spoof remediation: static ARP entry, flush poisoned entries."""
    data = request.get_json(silent=True) or {}
    action = data.get('action', '')
    results = []

    if action == 'flush_and_static':
        # Flush ARP cache and set static entry for gateway
        ip = data.get('ip', '')
        mac = data.get('mac', '')
        if not ip or not mac:
            return jsonify({'ok': False, 'error': 'IP and MAC required'})

        # Flush the entry
        r = _run_root(['ip', 'neigh', 'flush', ip], timeout=5)
        results.append({'cmd': f'ip neigh flush {ip}', 'ok': r['ok'], 'output': r['stdout'] + r['stderr']})

        # Set static entry
        r = _run_root(['arp', '-s', ip, mac], timeout=5)
        results.append({'cmd': f'arp -s {ip} {mac}', 'ok': r['ok'], 'output': r['stdout'] + r['stderr']})

    elif action == 'enable_arp_protection':
        # Enable kernel-level ARP protection
        cmds = [
            ['sysctl', '-w', 'net.ipv4.conf.all.arp_announce=2'],
            ['sysctl', '-w', 'net.ipv4.conf.all.arp_ignore=1'],
            ['sysctl', '-w', 'net.ipv4.conf.all.rp_filter=1'],
        ]
        for cmd in cmds:
            r = _run_root(cmd, timeout=5)
            results.append({'cmd': ' '.join(cmd), 'ok': r['ok'], 'output': r['stdout'] + r['stderr']})

    elif action == 'flush_entry':
        ip = data.get('ip', '')
        if not ip:
            return jsonify({'ok': False, 'error': 'IP required'})
        r = _run_root(['ip', 'neigh', 'flush', ip], timeout=5)
        results.append({'cmd': f'ip neigh flush {ip}', 'ok': r['ok'], 'output': r['stdout'] + r['stderr']})

    else:
        return jsonify({'ok': False, 'error': f'Unknown action: {action}'})

    return jsonify({'ok': True, 'results': results})


# ── WiFi Attack Detection ─────────────────────────────────────────────────────

@network_bp.route('/wifi/scan', methods=['POST'])
@login_required
def wifi_scan():
    """Scan for nearby WiFi networks using iw dev scan."""
    results = []
    try:
        iface = _get_wireless_interface()
        if not iface:
            return jsonify({'ok': False, 'error': 'No wireless interface found'})

        r = _run_root(['iw', 'dev', iface, 'scan'], timeout=20)
        if r['ok']:
            results = _parse_iw_scan(r['stdout'])
        else:
            return jsonify({'ok': False, 'error': r.get('stderr', 'WiFi scan failed')})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})

    return jsonify({'ok': True, 'networks': results, 'count': len(results)})


@network_bp.route('/wifi/ssid-map', methods=['POST'])
@login_required
def ssid_map():
    """Build an SSID map showing all access points, their BSSIDs, channels, and signal strength.
    Groups by SSID to show all APs broadcasting the same network name."""
    try:
        iface = _get_wireless_interface()
        if not iface:
            return jsonify({'ok': False, 'error': 'No wireless interface found'})

        r = _run_root(['iw', 'dev', iface, 'scan'], timeout=20)
        if not r['ok']:
            return jsonify({'ok': False, 'error': r.get('stderr', 'WiFi scan failed')})

        scan_results = _parse_iw_scan(r['stdout'])
        networks = {}
        for net in scan_results:
            ssid = net.get('ssid', '(Hidden)') or '(Hidden)'
            entry = {
                'bssid': net.get('bssid', ''),
                'channel': net.get('channel', ''),
                'signal': net.get('signal', ''),
                'security': net.get('security', ''),
            }
            if ssid not in networks:
                networks[ssid] = {'ssid': ssid, 'aps': [], 'security': entry['security']}
            networks[ssid]['aps'].append(entry)

        ssid_list = sorted(networks.values(), key=lambda x: max(int(a.get('signal', '0') or '0') for a in x['aps']), reverse=True)
        return jsonify({'ok': True, 'ssids': ssid_list, 'total_ssids': len(ssid_list),
                        'total_aps': sum(len(s['aps']) for s in ssid_list)})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@network_bp.route('/wifi/detect-attacks', methods=['POST'])
@login_required
def detect_wifi_attacks():
    """Detect active WiFi attacks: deauth floods, evil twins, rogue APs, MITM, pineapple."""
    _log = logging.getLogger('autarch.network')
    findings = []

    # 1. Deauth detection - check for deauth/disassoc frames in recent logs
    deauth_result = _detect_deauth()
    findings.append(deauth_result)

    # 2. Evil Twin detection - multiple APs with same SSID but different BSSID/channel
    evil_twin_result = _detect_evil_twin()
    findings.append(evil_twin_result)

    # 3. Rogue AP / Pineapple detection - open APs with suspicious names or karma behavior
    pineapple_result = _detect_pineapple()
    findings.append(pineapple_result)

    # 4. MITM detection - ARP poisoning, gateway MAC changes, DNS hijacking
    mitm_result = _detect_mitm()
    findings.append(mitm_result)

    # 5. SSL Strip detection - check for HTTP redirects on HTTPS sites
    ssl_strip_result = _detect_ssl_strip()
    findings.append(ssl_strip_result)

    severity_counts = {'critical': 0, 'warning': 0, 'clean': 0}
    for f in findings:
        severity_counts[f.get('severity', 'clean')] += 1

    return jsonify({'ok': True, 'findings': findings, 'severity': severity_counts})


def _get_wireless_interface():
    """Find the first wireless interface."""
    try:
        r = _run(['iw', 'dev'], timeout=5)
        if r['ok']:
            import re
            match = re.search(r'Interface\s+(\S+)', r['stdout'])
            if match:
                return match.group(1)
    except Exception:
        pass
    # Fallback: check /sys/class/net/*/wireless
    import os
    for iface in os.listdir('/sys/class/net/'):
        if os.path.isdir(f'/sys/class/net/{iface}/wireless'):
            return iface
    return None


def _parse_iw_scan(output):
    """Parse 'iw dev <iface> scan' output into structured data."""
    networks = []
    current = None
    for line in output.split('\n'):
        line_s = line.strip()
        # New BSS block
        m = re.match(r'^BSS\s+([\da-fA-F:]+)', line)
        if m:
            if current:
                networks.append(current)
            current = {'bssid': m.group(1).upper(), 'ssid': '', 'channel': '',
                       'frequency': '', 'signal': '', 'security': 'Open', 'mode': ''}
            continue
        if current is None:
            continue
        if line_s.startswith('SSID:'):
            current['ssid'] = line_s[5:].strip() or '(Hidden)'
        elif line_s.startswith('freq:'):
            current['frequency'] = line_s[5:].strip()
        elif line_s.startswith('signal:'):
            m = re.search(r'(-?[\d.]+)', line_s)
            if m:
                current['signal'] = str(int(float(m.group(1))))
        elif line_s.startswith('DS Parameter set: channel'):
            m = re.search(r'channel\s+(\d+)', line_s)
            if m:
                current['channel'] = m.group(1)
        elif 'primary channel:' in line_s:
            m = re.search(r'primary channel:\s*(\d+)', line_s)
            if m and not current['channel']:
                current['channel'] = m.group(1)
        elif 'RSN:' in line_s or 'WPA:' in line_s:
            if 'RSN:' in line_s:
                current['security'] = 'WPA2'
            elif current['security'] == 'Open':
                current['security'] = 'WPA'
        elif 'BSS Load:' in line_s or 'capability:' in line_s:
            if 'ESS' in line_s:
                current['mode'] = 'Infra'
            elif 'IBSS' in line_s:
                current['mode'] = 'Ad-Hoc'
    if current:
        networks.append(current)
    return networks


def _detect_deauth():
    """Detect deauthentication/disassociation attacks."""
    result = {'check': 'Deauth Attack', 'severity': 'clean', 'details': [], 'description': 'No deauth flood detected'}

    # Check dmesg for deauth events
    r = _run(['dmesg', '--time-format=reltime'], timeout=5)
    if r['ok']:
        import re
        deauth_lines = []
        for line in r['stdout'].split('\n'):
            if any(x in line.lower() for x in ['deauth', 'disassoc', 'deauthentication', 'disassociation']):
                deauth_lines.append(line.strip())

        if len(deauth_lines) > 5:
            result['severity'] = 'critical'
            result['description'] = f'Deauth flood detected: {len(deauth_lines)} deauth events in kernel log'
            result['details'] = deauth_lines[-10:]  # Last 10
        elif deauth_lines:
            result['severity'] = 'warning'
            result['description'] = f'{len(deauth_lines)} deauth event(s) found — could be normal roaming or an attack'
            result['details'] = deauth_lines[-5:]

    # Also check if we're frequently disconnecting/reconnecting
    r2 = _run(['journalctl', '-u', 'NetworkManager', '--since', '10 min ago', '--no-pager', '-q'], timeout=5)
    if r2['ok']:
        disconnects = sum(1 for l in r2['stdout'].split('\n') if 'disconnected' in l.lower() or 'association' in l.lower())
        if disconnects > 3:
            if result['severity'] == 'clean':
                result['severity'] = 'warning'
            result['details'].append(f'NetworkManager: {disconnects} disconnect events in last 10 minutes')

    return result


def _detect_evil_twin():
    """Detect evil twin attacks - same SSID from different BSSIDs or unexpected channels."""
    result = {'check': 'Evil Twin', 'severity': 'clean', 'details': [], 'description': 'No evil twin detected'}

    r = _run(['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list'], timeout=15)
    if not r['ok']:
        result['description'] = 'Could not scan WiFi networks'
        return result

    # Group by SSID
    ssid_aps = {}
    for line in r['stdout'].strip().split('\n'):
        if not line.strip():
            continue
        parts = _parse_nmcli_line(line)
        if len(parts) >= 3:
            ssid = parts[0]
            if not ssid:
                continue
            bssid = parts[1]
            security = parts[4] if len(parts) >= 5 else ''
            if ssid not in ssid_aps:
                ssid_aps[ssid] = []
            ssid_aps[ssid].append({'bssid': bssid, 'security': security})

    # Check for SSIDs with mixed security (open + encrypted = likely evil twin)
    for ssid, aps in ssid_aps.items():
        securities = set(a.get('security', '') for a in aps)
        has_open = any(not s or s == '--' or 'open' in s.lower() for s in securities)
        has_encrypted = any(s and s != '--' and 'open' not in s.lower() for s in securities)
        if has_open and has_encrypted and len(aps) > 1:
            result['severity'] = 'critical'
            result['details'].append(
                f'SSID "{ssid}" has {len(aps)} APs with MIXED security (open + encrypted) — likely evil twin!'
            )

    # Check for our connected SSID having unexpected duplicate
    r2 = _run(['nmcli', '-t', '-f', 'NAME,DEVICE', 'con', 'show', '--active'], timeout=5)
    if r2['ok']:
        for line in r2['stdout'].strip().split('\n'):
            parts = line.split(':')
            if parts:
                connected_ssid = parts[0]
                if connected_ssid in ssid_aps and len(ssid_aps[connected_ssid]) > 2:
                    if result['severity'] == 'clean':
                        result['severity'] = 'warning'
                    result['details'].append(
                        f'Your connected network "{connected_ssid}" has {len(ssid_aps[connected_ssid])} APs — verify they are legitimate'
                    )

    if not result['details']:
        result['description'] = 'No evil twin indicators found'
    else:
        result['description'] = f'{len(result["details"])} suspicious finding(s)'

    return result


def _detect_pineapple():
    """Detect WiFi Pineapple / rogue open APs with suspicious characteristics."""
    result = {'check': 'Rogue AP / Pineapple', 'severity': 'clean', 'details': [], 'description': 'No rogue APs detected'}

    suspicious_ssids = [
        'free wifi', 'free internet', 'open', 'guest', 'public wifi',
        'airport wifi', 'hotel wifi', 'starbucks', 'xfinity wifi',
        'attwifi', 'google starbucks', 'linksys', 'netgear', 'default',
    ]

    r = _run(['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY', 'dev', 'wifi', 'list'], timeout=15)
    if not r['ok']:
        result['description'] = 'Could not scan WiFi'
        return result

    for line in r['stdout'].strip().split('\n'):
        if not line.strip():
            continue
        parts = _parse_nmcli_line(line)
        if len(parts) >= 2:
            ssid = parts[0].strip()
            security = parts[3].strip() if len(parts) >= 4 else ''
            signal = parts[2].strip() if len(parts) >= 3 else ''

            is_open = not security or security == '--' or 'open' in security.lower()
            is_strong = signal and int(signal) > 70 if signal.isdigit() else False

            # Flag: open AP with suspicious name
            if is_open and ssid.lower() in suspicious_ssids:
                result['severity'] = 'warning'
                result['details'].append(f'Suspicious open AP: "{ssid}" (signal: {signal}%) — common Pineapple bait SSID')

            # Flag: open AP with very strong signal (close proximity = likely rogue)
            if is_open and is_strong and ssid:
                if result['severity'] == 'clean':
                    result['severity'] = 'warning'
                result['details'].append(f'Strong open AP: "{ssid}" (signal: {signal}%) — verify this is legitimate')

    if not result['details']:
        result['description'] = 'No suspicious rogue APs detected'
    else:
        result['description'] = f'{len(result["details"])} suspicious AP(s) found'

    return result


def _detect_mitm():
    """Detect Man-in-the-Middle attacks via ARP cache analysis and gateway verification."""
    result = {'check': 'MITM / ARP Poisoning', 'severity': 'clean', 'details': [], 'description': 'No MITM indicators found'}

    # Get default gateway
    gateway_ip = None
    r = _run(['ip', 'route', 'show', 'default'], timeout=5)
    if r['ok']:
        import re
        m = re.search(r'default via (\S+)', r['stdout'])
        if m:
            gateway_ip = m.group(1)

    if not gateway_ip:
        result['description'] = 'Could not determine default gateway'
        return result

    # Get gateway MAC from ARP
    r = _run(['ip', 'neigh', 'show', gateway_ip], timeout=5)
    if r['ok']:
        import re
        m = re.search(r'lladdr\s+([\da-fA-F:]+)', r['stdout'])
        gateway_mac = m.group(1) if m else None

        if gateway_mac:
            # Check if gateway MAC has changed (compare with stored value)
            gw_file = os.path.join(_ensure_data_dir(), 'gateway_mac.json')
            stored = {}
            if os.path.exists(gw_file):
                try:
                    with open(gw_file) as f:
                        stored = json.load(f)
                except Exception:
                    pass

            if stored.get('mac') and stored['mac'] != gateway_mac:
                result['severity'] = 'critical'
                result['details'].append(
                    f'Gateway MAC changed! Was {stored["mac"]}, now {gateway_mac} — possible ARP poisoning!'
                )

            # Store current gateway MAC
            with open(gw_file, 'w') as f:
                json.dump({'ip': gateway_ip, 'mac': gateway_mac, 'timestamp': __import__('time').time()}, f)

    # Check for duplicate MACs in ARP table (ARP spoofing indicator)
    r = _run(['ip', 'neigh'], timeout=5)
    if r['ok']:
        import re
        mac_to_ips = {}
        for line in r['stdout'].strip().split('\n'):
            m = re.search(r'^(\S+)\s.*lladdr\s+([\da-fA-F:]+)', line)
            if m:
                ip, mac = m.group(1), m.group(2).lower()
                mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                result['severity'] = 'critical'
                result['details'].append(f'MAC {mac} has multiple IPs: {", ".join(ips)} — ARP spoofing indicator')

    # Check DNS: resolve a known domain and see if it matches
    r = _run(['dig', '+short', 'www.google.com', '@8.8.8.8'], timeout=5)
    r2 = _run(['dig', '+short', 'www.google.com'], timeout=5)
    if r['ok'] and r2['ok']:
        real_ips = set(r['stdout'].strip().split('\n'))
        local_ips = set(r2['stdout'].strip().split('\n'))
        if real_ips and local_ips and not real_ips.intersection(local_ips):
            if result['severity'] != 'critical':
                result['severity'] = 'warning'
            result['details'].append(
                f'DNS hijacking possible: google.com resolves differently through local DNS vs 8.8.8.8'
            )

    if not result['details']:
        result['description'] = 'No MITM indicators found — gateway MAC verified'
    else:
        result['description'] = f'{len(result["details"])} MITM indicator(s) detected'

    return result


def _detect_ssl_strip():
    """Detect potential SSL stripping by checking for unexpected HTTP redirects."""
    result = {'check': 'SSL Strip', 'severity': 'clean', 'details': [], 'description': 'No SSL strip indicators'}

    # Check if we can reach HTTPS sites properly
    test_sites = ['https://www.google.com', 'https://www.cloudflare.com']
    for site in test_sites:
        try:
            r = _run(['curl', '-sI', '-m', '5', '--max-redirs', '0', '-o', '/dev/null', '-w', '%{http_code}:%{ssl_verify_result}:%{redirect_url}', site], timeout=8)
            if r['ok']:
                parts = r['stdout'].strip().split(':')
                status = parts[0] if parts else ''
                ssl_verify = parts[1] if len(parts) > 1 else ''
                redirect = ':'.join(parts[2:]) if len(parts) > 2 else ''

                if ssl_verify and ssl_verify != '0':
                    result['severity'] = 'warning'
                    result['details'].append(f'{site}: SSL certificate verification failed (code {ssl_verify})')

                if redirect and redirect.startswith('http://'):
                    result['severity'] = 'critical'
                    result['details'].append(f'{site}: Redirecting to HTTP! Possible SSL strip attack')
        except Exception:
            pass

    if not result['details']:
        result['description'] = 'HTTPS connections verified — no SSL stripping detected'
    else:
        result['description'] = f'{len(result["details"])} SSL issue(s) found'

    return result


# ── Real-time Monitor ───────────────────────────────────────────────────────

def _monitor_loop():
    """Background thread: poll connections and buffer new ones."""
    global _monitor_active
    seen = set()

    while _monitor_active:
        try:
            if _is_linux():
                ok, out = _run('ss -tunp', timeout=5)
            else:
                ok, out = _run('netstat -ano', timeout=5)

            if ok:
                for line in out.splitlines()[1:]:
                    line_hash = hash(line.strip())
                    if line_hash not in seen:
                        seen.add(line_hash)
                        parts = line.split()
                        if len(parts) >= 5:
                            entry = {
                                'timestamp': datetime.now(timezone.utc).isoformat(),
                                'raw': line.strip(),
                                'protocol': parts[0],
                                'local': parts[4] if len(parts) > 5 else parts[3],
                                'remote': parts[5] if len(parts) > 5 else parts[4],
                                'process': parts[6] if len(parts) > 6 else '',
                            }
                            with _monitor_lock:
                                _monitor_buffer.append(entry)

            # Keep seen set manageable
            if len(seen) > 10000:
                seen = set(list(seen)[-5000:])

        except Exception as e:
            logger.error("Monitor loop error: %s", e)

        time.sleep(2)


@network_bp.route('/monitor/start', methods=['POST'])
@login_required
def monitor_start():
    """Start background connection monitoring."""
    global _monitor_active, _monitor_thread

    if _monitor_active:
        return jsonify({'ok': True, 'message': 'Monitor already running'})

    _monitor_active = True
    _monitor_buffer.clear()
    _monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
    _monitor_thread.start()
    logger.info("Connection monitor started")
    return jsonify({'ok': True, 'message': 'Monitor started'})


@network_bp.route('/monitor/stop', methods=['POST'])
@login_required
def monitor_stop():
    """Stop the connection monitor."""
    global _monitor_active, _monitor_thread

    if not _monitor_active:
        return jsonify({'ok': True, 'message': 'Monitor not running'})

    _monitor_active = False
    if _monitor_thread:
        _monitor_thread.join(timeout=5)
        _monitor_thread = None
    logger.info("Connection monitor stopped")
    return jsonify({'ok': True, 'message': 'Monitor stopped'})


@network_bp.route('/monitor/feed')
@login_required
def monitor_feed():
    """SSE endpoint streaming new connections in real-time."""
    def generate():
        last_idx = 0
        while _monitor_active:
            with _monitor_lock:
                buf_len = len(_monitor_buffer)
                if buf_len > last_idx:
                    new_items = list(_monitor_buffer)[last_idx:buf_len]
                    last_idx = buf_len
                else:
                    new_items = []

            for item in new_items:
                yield f"data: {json.dumps(item)}\n\n"

            if not new_items:
                yield ": keepalive\n\n"

            time.sleep(1)

        yield "data: {\"done\": true}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
