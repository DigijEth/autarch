"""AUTARCH Network Topology Mapper

Host discovery, service enumeration, OS fingerprinting, and visual
network topology mapping with scan diffing.
"""

DESCRIPTION = "Network topology discovery & mapping"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import socket
import struct
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timezone
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


@dataclass
class Host:
    ip: str
    mac: str = ''
    hostname: str = ''
    os_guess: str = ''
    ports: List[dict] = field(default_factory=list)
    state: str = 'up'
    subnet: str = ''

    def to_dict(self) -> dict:
        return {
            'ip': self.ip, 'mac': self.mac, 'hostname': self.hostname,
            'os_guess': self.os_guess, 'ports': self.ports,
            'state': self.state, 'subnet': self.subnet,
        }


class NetMapper:
    """Network topology discovery and mapping."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'net_mapper')
        os.makedirs(self._data_dir, exist_ok=True)
        self._active_jobs: Dict[str, dict] = {}

    # ── Host Discovery ────────────────────────────────────────────────────

    def discover_hosts(self, target: str, method: str = 'auto',
                       timeout: float = 3.0) -> dict:
        """Discover live hosts on a network.

        target: IP, CIDR (192.168.1.0/24), or range (192.168.1.1-254)
        method: 'arp', 'icmp', 'tcp', 'nmap', 'auto'
        """
        job_id = f'discover_{int(time.time())}'
        holder = {'done': False, 'hosts': [], 'error': None}
        self._active_jobs[job_id] = holder

        def do_discover():
            try:
                nmap = find_tool('nmap')
                if method == 'nmap' or (method == 'auto' and nmap):
                    hosts = self._nmap_discover(target, nmap, timeout)
                elif method == 'icmp' or method == 'auto':
                    hosts = self._ping_sweep(target, timeout)
                elif method == 'tcp':
                    hosts = self._tcp_discover(target, timeout)
                else:
                    hosts = self._ping_sweep(target, timeout)
                holder['hosts'] = [h.to_dict() for h in hosts]
            except Exception as e:
                holder['error'] = str(e)
            finally:
                holder['done'] = True

        threading.Thread(target=do_discover, daemon=True).start()
        return {'ok': True, 'job_id': job_id}

    def _nmap_discover(self, target: str, nmap: str, timeout: float) -> List[Host]:
        """Discover hosts using nmap."""
        cmd = [nmap, '-sn', '-PE', '-PA21,22,80,443,445,3389', '-oX', '-', target]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return self._parse_nmap_xml(result.stdout)
        except Exception:
            return []

    def _ping_sweep(self, target: str, timeout: float) -> List[Host]:
        """ICMP ping sweep."""
        ips = self._expand_target(target)
        hosts = []
        lock = threading.Lock()

        def ping(ip):
            try:
                # Use socket instead of subprocess for speed
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                # Try common ports to detect hosts even if ICMP is blocked
                for port in (80, 443, 22, 445):
                    try:
                        r = s.connect_ex((ip, port))
                        if r == 0:
                            h = Host(ip=ip, state='up',
                                     subnet='.'.join(ip.split('.')[:3]) + '.0/24')
                            try:
                                h.hostname = socket.getfqdn(ip)
                                if h.hostname == ip:
                                    h.hostname = ''
                            except Exception:
                                pass
                            with lock:
                                hosts.append(h)
                            s.close()
                            return
                    except Exception:
                        pass
                s.close()
            except Exception:
                pass

        threads = []
        for ip in ips:
            t = threading.Thread(target=ping, args=(ip,), daemon=True)
            threads.append(t)
            t.start()
            if len(threads) >= 100:
                for t in threads:
                    t.join(timeout=timeout + 2)
                threads.clear()
        for t in threads:
            t.join(timeout=timeout + 2)

        return sorted(hosts, key=lambda h: [int(x) for x in h.ip.split('.')])

    def _tcp_discover(self, target: str, timeout: float) -> List[Host]:
        """TCP SYN scan for discovery."""
        return self._ping_sweep(target, timeout)  # Same logic for now

    # ── Port Scanning ─────────────────────────────────────────────────────

    def scan_host(self, ip: str, port_range: str = '1-1024',
                  service_detection: bool = True,
                  os_detection: bool = True) -> dict:
        """Detailed scan of a single host."""
        nmap = find_tool('nmap')
        if nmap:
            return self._nmap_scan_host(ip, nmap, port_range,
                                        service_detection, os_detection)
        return self._socket_scan_host(ip, port_range)

    def _nmap_scan_host(self, ip: str, nmap: str, port_range: str,
                        svc: bool, os_det: bool) -> dict:
        cmd = [nmap, '-Pn', '-p', port_range, '-oX', '-', ip]
        if svc:
            cmd.insert(2, '-sV')
        if os_det:
            cmd.insert(2, '-O')
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            hosts = self._parse_nmap_xml(result.stdout)
            if hosts:
                return {'ok': True, 'host': hosts[0].to_dict(), 'raw': result.stdout}
            return {'ok': True, 'host': Host(ip=ip, state='unknown').to_dict()}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _socket_scan_host(self, ip: str, port_range: str) -> dict:
        """Fallback socket-based port scan."""
        start_port, end_port = 1, 1024
        if '-' in port_range:
            parts = port_range.split('-')
            start_port, end_port = int(parts[0]), int(parts[1])

        open_ports = []
        for port in range(start_port, min(end_port + 1, 65536)):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append({
                        'port': port, 'protocol': 'tcp', 'state': 'open',
                        'service': self._guess_service(port),
                    })
                s.close()
            except Exception:
                pass

        host = Host(ip=ip, state='up', ports=open_ports,
                    subnet='.'.join(ip.split('.')[:3]) + '.0/24')
        return {'ok': True, 'host': host.to_dict()}

    # ── Topology / Scan Management ────────────────────────────────────────

    def save_scan(self, name: str, hosts: List[dict]) -> dict:
        """Save a network scan for later comparison."""
        scan = {
            'name': name,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'hosts': hosts,
            'host_count': len(hosts),
        }
        path = os.path.join(self._data_dir, f'scan_{name}_{int(time.time())}.json')
        with open(path, 'w') as f:
            json.dump(scan, f, indent=2)
        return {'ok': True, 'path': path}

    def list_scans(self) -> List[dict]:
        scans = []
        for f in Path(self._data_dir).glob('scan_*.json'):
            try:
                with open(f, 'r') as fh:
                    data = json.load(fh)
                    scans.append({
                        'file': f.name,
                        'name': data.get('name', ''),
                        'timestamp': data.get('timestamp', ''),
                        'host_count': data.get('host_count', 0),
                    })
            except Exception:
                continue
        return sorted(scans, key=lambda s: s.get('timestamp', ''), reverse=True)

    def load_scan(self, filename: str) -> Optional[dict]:
        path = os.path.join(self._data_dir, filename)
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return None

    def diff_scans(self, scan1_file: str, scan2_file: str) -> dict:
        """Compare two scans and find differences."""
        s1 = self.load_scan(scan1_file)
        s2 = self.load_scan(scan2_file)
        if not s1 or not s2:
            return {'ok': False, 'error': 'Scan(s) not found'}

        ips1 = {h['ip'] for h in s1.get('hosts', [])}
        ips2 = {h['ip'] for h in s2.get('hosts', [])}

        return {
            'ok': True,
            'new_hosts': sorted(ips2 - ips1),
            'removed_hosts': sorted(ips1 - ips2),
            'unchanged_hosts': sorted(ips1 & ips2),
            'scan1': {'name': s1.get('name'), 'timestamp': s1.get('timestamp'),
                      'count': len(ips1)},
            'scan2': {'name': s2.get('name'), 'timestamp': s2.get('timestamp'),
                      'count': len(ips2)},
        }

    def get_job_status(self, job_id: str) -> dict:
        holder = self._active_jobs.get(job_id)
        if not holder:
            return {'ok': False, 'error': 'Job not found'}
        result = {'ok': True, 'done': holder['done'], 'hosts': holder['hosts']}
        if holder.get('error'):
            result['error'] = holder['error']
        if holder['done']:
            self._active_jobs.pop(job_id, None)
        return result

    # ── Topology Data (for visualization) ─────────────────────────────────

    def build_topology(self, hosts: List[dict]) -> dict:
        """Build topology graph data from host list for visualization."""
        nodes = []
        edges = []
        subnets = {}

        for h in hosts:
            subnet = '.'.join(h['ip'].split('.')[:3]) + '.0/24'
            if subnet not in subnets:
                subnets[subnet] = {
                    'id': f'subnet_{subnet}', 'label': subnet,
                    'type': 'subnet', 'hosts': [],
                }
            subnets[subnet]['hosts'].append(h['ip'])

            node_type = 'host'
            if h.get('ports'):
                services = [p.get('service', '') for p in h['ports']]
                if any('http' in s.lower() for s in services):
                    node_type = 'web'
                elif any('ssh' in s.lower() for s in services):
                    node_type = 'server'
                elif any('smb' in s.lower() or 'netbios' in s.lower() for s in services):
                    node_type = 'windows'

            nodes.append({
                'id': h['ip'],
                'label': h.get('hostname') or h['ip'],
                'ip': h['ip'],
                'type': node_type,
                'os': h.get('os_guess', ''),
                'ports': len(h.get('ports', [])),
                'subnet': subnet,
            })

            # Edge from host to subnet gateway
            gateway = '.'.join(h['ip'].split('.')[:3]) + '.1'
            edges.append({'from': h['ip'], 'to': gateway, 'type': 'network'})

        # Add subnet nodes
        for subnet_data in subnets.values():
            nodes.append(subnet_data)

        return {
            'nodes': nodes,
            'edges': edges,
            'subnets': list(subnets.keys()),
            'total_hosts': len(hosts),
        }

    # ── Helpers ───────────────────────────────────────────────────────────

    def _expand_target(self, target: str) -> List[str]:
        """Expand CIDR or range to list of IPs."""
        if '/' in target:
            return self._cidr_to_ips(target)
        if '-' in target.split('.')[-1]:
            base = '.'.join(target.split('.')[:3])
            range_part = target.split('.')[-1]
            if '-' in range_part:
                start, end = range_part.split('-')
                return [f'{base}.{i}' for i in range(int(start), int(end) + 1)]
        return [target]

    @staticmethod
    def _cidr_to_ips(cidr: str) -> List[str]:
        parts = cidr.split('/')
        if len(parts) != 2:
            return [cidr]
        ip = parts[0]
        prefix = int(parts[1])
        if prefix < 16:
            return [ip]  # Too large, don't expand
        ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        network = ip_int & mask
        broadcast = network | (~mask & 0xFFFFFFFF)
        return [socket.inet_ntoa(struct.pack('!I', i))
                for i in range(network + 1, broadcast)]

    def _parse_nmap_xml(self, xml_text: str) -> List[Host]:
        """Parse nmap XML output to Host objects."""
        hosts = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_text)
            for host_el in root.findall('.//host'):
                state = host_el.find('status')
                if state is not None and state.get('state') != 'up':
                    continue
                addr = host_el.find("address[@addrtype='ipv4']")
                if addr is None:
                    continue
                ip = addr.get('addr', '')
                mac_el = host_el.find("address[@addrtype='mac']")
                hostname_el = host_el.find('.//hostname')
                os_el = host_el.find('.//osmatch')

                h = Host(
                    ip=ip,
                    mac=mac_el.get('addr', '') if mac_el is not None else '',
                    hostname=hostname_el.get('name', '') if hostname_el is not None else '',
                    os_guess=os_el.get('name', '') if os_el is not None else '',
                    subnet='.'.join(ip.split('.')[:3]) + '.0/24',
                )

                for port_el in host_el.findall('.//port'):
                    state_el = port_el.find('state')
                    if state_el is not None and state_el.get('state') == 'open':
                        svc_el = port_el.find('service')
                        h.ports.append({
                            'port': int(port_el.get('portid', 0)),
                            'protocol': port_el.get('protocol', 'tcp'),
                            'state': 'open',
                            'service': svc_el.get('name', '') if svc_el is not None else '',
                            'version': svc_el.get('version', '') if svc_el is not None else '',
                        })
                hosts.append(h)
        except Exception:
            pass
        return hosts

    @staticmethod
    def _guess_service(port: int) -> str:
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            993: 'imaps', 995: 'pop3s', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
            8443: 'https-alt', 27017: 'mongodb',
        }
        return services.get(port, '')


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_net_mapper() -> NetMapper:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = NetMapper()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Network Mapper."""
    svc = get_net_mapper()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║       NETWORK TOPOLOGY MAPPER         ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — Discover Hosts                   ║")
        print("║  2 — Scan Host (detailed)             ║")
        print("║  3 — List Saved Scans                 ║")
        print("║  4 — Compare Scans                    ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            target = input("  Target (CIDR/range): ").strip()
            if not target:
                continue
            print("  Discovering hosts...")
            r = svc.discover_hosts(target)
            if r.get('job_id'):
                while True:
                    time.sleep(2)
                    s = svc.get_job_status(r['job_id'])
                    if s['done']:
                        hosts = s['hosts']
                        print(f"\n  Found {len(hosts)} hosts:")
                        for h in hosts:
                            ports = len(h.get('ports', []))
                            print(f"    {h['ip']:16s} {h.get('hostname',''):20s} "
                                  f"{h.get('os_guess',''):20s} {ports} ports")
                        save = input("\n  Save scan? (name/empty=skip): ").strip()
                        if save:
                            svc.save_scan(save, hosts)
                            print(f"  Saved as: {save}")
                        break
        elif choice == '2':
            ip = input("  Host IP: ").strip()
            if not ip:
                continue
            print("  Scanning...")
            r = svc.scan_host(ip)
            if r.get('ok'):
                h = r['host']
                print(f"\n  {h['ip']} — {h.get('os_guess', 'unknown OS')}")
                for p in h.get('ports', []):
                    print(f"    {p['port']:6d}/{p['protocol']}  {p.get('service','')}"
                          f"  {p.get('version','')}")
        elif choice == '3':
            scans = svc.list_scans()
            if not scans:
                print("\n  No saved scans.")
                continue
            for s in scans:
                print(f"  {s['file']:40s} {s['name']:15s} "
                      f"{s['host_count']} hosts  {s['timestamp'][:19]}")
        elif choice == '4':
            scans = svc.list_scans()
            if len(scans) < 2:
                print("  Need at least 2 saved scans.")
                continue
            for i, s in enumerate(scans, 1):
                print(f"  {i}. {s['file']} ({s['host_count']} hosts)")
            a = int(input("  Scan 1 #: ").strip()) - 1
            b = int(input("  Scan 2 #: ").strip()) - 1
            diff = svc.diff_scans(scans[a]['file'], scans[b]['file'])
            if diff.get('ok'):
                print(f"\n  New hosts:     {len(diff['new_hosts'])}")
                for h in diff['new_hosts']:
                    print(f"    + {h}")
                print(f"  Removed hosts: {len(diff['removed_hosts'])}")
                for h in diff['removed_hosts']:
                    print(f"    - {h}")
                print(f"  Unchanged:     {len(diff['unchanged_hosts'])}")
