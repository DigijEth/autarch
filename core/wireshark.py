"""
AUTARCH Wireshark/Packet Analysis Engine
Scapy-based packet capture and analysis with optional tshark fallback.

Primary engine: scapy (pure Python, needs libpcap for live capture)
Fallback: tshark CLI (if installed, for advanced protocol dissection)
"""

import os
import re
import json
import time
import struct
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict
from typing import Optional, List, Dict, Any, Callable

from core.paths import find_tool, get_data_dir

# Try importing scapy
SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        sniff, rdpcap, wrpcap, get_if_list, conf,
        IP, IPv6, TCP, UDP, DNS, DNSQR, DNSRR, Raw, Ether, ARP, ICMP,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# Check for tshark
TSHARK_PATH = find_tool('tshark')


class WiresharkManager:
    """Packet capture and analysis using scapy + optional tshark."""

    def __init__(self):
        self._capture_thread = None
        self._capture_running = False
        self._capture_packets = []
        self._capture_stats = {}
        self._capture_callback = None
        self._last_packets = None
        self._capture_file = None
        self._data_dir = get_data_dir() / 'captures'
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def scapy_available(self):
        return SCAPY_AVAILABLE

    @property
    def tshark_available(self):
        return TSHARK_PATH is not None

    @property
    def can_capture(self):
        """Check if live capture is possible (needs root + libpcap)."""
        if not SCAPY_AVAILABLE:
            return False
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Windows - check differently
            return True

    def get_status(self) -> Dict[str, Any]:
        """Get engine status."""
        return {
            'scapy': SCAPY_AVAILABLE,
            'tshark': self.tshark_available,
            'tshark_path': TSHARK_PATH or '',
            'can_capture': self.can_capture,
            'capturing': self._capture_running,
        }

    # ==================== INTERFACES ====================

    def list_interfaces(self) -> List[Dict[str, str]]:
        """List available network interfaces."""
        interfaces = []

        if SCAPY_AVAILABLE:
            try:
                for iface in get_if_list():
                    interfaces.append({'name': iface, 'description': '', 'source': 'scapy'})
            except Exception:
                pass

        # Fallback/supplement with tshark
        if TSHARK_PATH and not interfaces:
            try:
                result = subprocess.run(
                    [TSHARK_PATH, '-D'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            # Format: "1. eth0 (Description)"
                            match = re.match(r'\d+\.\s+(\S+)\s*(?:\((.+)\))?', line)
                            if match:
                                interfaces.append({
                                    'name': match.group(1),
                                    'description': match.group(2) or '',
                                    'source': 'tshark',
                                })
            except Exception:
                pass

        # Fallback to /sys/class/net
        if not interfaces:
            net_dir = Path('/sys/class/net')
            if net_dir.exists():
                for d in sorted(net_dir.iterdir()):
                    interfaces.append({'name': d.name, 'description': '', 'source': 'sysfs'})

        return interfaces

    # ==================== CAPTURE ====================

    def start_capture(self, interface: str = None, bpf_filter: str = None,
                      duration: int = 30, output_file: str = None,
                      callback: Callable = None) -> Dict[str, Any]:
        """Start packet capture in a background thread.

        Args:
            interface: Network interface (None = default)
            bpf_filter: BPF filter string (e.g., "tcp port 80")
            duration: Capture duration in seconds (max 300)
            output_file: Save to pcap file
            callback: Called with each packet dict for live streaming

        Returns:
            Status dict
        """
        if not SCAPY_AVAILABLE:
            return {'error': 'Scapy not available'}
        if not self.can_capture:
            return {'error': 'Root privileges required for live capture'}
        if self._capture_running:
            return {'error': 'Capture already running'}

        duration = max(5, min(300, duration))
        self._capture_packets = []
        self._capture_running = True
        self._capture_callback = callback
        self._capture_stats = {
            'interface': interface or 'default',
            'filter': bpf_filter or '',
            'start_time': datetime.now().isoformat(),
            'duration': duration,
            'packet_count': 0,
        }

        if output_file:
            self._capture_file = output_file
        else:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            self._capture_file = str(self._data_dir / f'capture_{ts}.pcap')

        def _do_capture():
            try:
                kwargs = {
                    'timeout': duration,
                    'prn': self._packet_handler,
                    'store': True,
                }
                if interface:
                    kwargs['iface'] = interface
                if bpf_filter:
                    kwargs['filter'] = bpf_filter

                packets = sniff(**kwargs)
                self._last_packets = packets

                # Save to pcap
                if self._capture_file and packets:
                    wrpcap(self._capture_file, packets)
                    self._capture_stats['output_file'] = self._capture_file

            except Exception as e:
                self._capture_stats['error'] = str(e)
            finally:
                self._capture_running = False
                self._capture_stats['end_time'] = datetime.now().isoformat()
                self._capture_stats['packet_count'] = len(self._capture_packets)

        self._capture_thread = threading.Thread(target=_do_capture, daemon=True)
        self._capture_thread.start()

        return {'status': 'started', 'file': self._capture_file}

    def _packet_handler(self, pkt):
        """Process each captured packet."""
        summary = self._packet_to_dict(pkt)
        self._capture_packets.append(summary)
        self._capture_stats['packet_count'] = len(self._capture_packets)

        if self._capture_callback:
            try:
                self._capture_callback(summary)
            except Exception:
                pass

    def stop_capture(self) -> Dict[str, Any]:
        """Stop running capture."""
        if not self._capture_running:
            return {'status': 'not_running'}

        self._capture_running = False
        # Signal scapy to stop - set a flag it checks
        try:
            conf.sniff_promisc = False  # This won't stop it, but thread will timeout
        except Exception:
            pass

        return {
            'status': 'stopping',
            'packets': len(self._capture_packets),
            'file': self._capture_file,
        }

    def get_capture_stats(self) -> Dict[str, Any]:
        """Get current/last capture statistics."""
        stats = dict(self._capture_stats)
        stats['running'] = self._capture_running
        stats['packet_count'] = len(self._capture_packets)
        return stats

    # ==================== PCAP READING ====================

    def read_pcap(self, filepath: str, max_packets: int = 10000) -> Dict[str, Any]:
        """Read and parse a PCAP file.

        Args:
            filepath: Path to pcap file
            max_packets: Maximum packets to load

        Returns:
            Dict with packets list and metadata
        """
        p = Path(filepath)
        if not p.exists():
            return {'error': f'File not found: {filepath}'}

        if not SCAPY_AVAILABLE:
            # Fallback to tshark
            if TSHARK_PATH:
                return self._read_pcap_tshark(filepath, max_packets)
            return {'error': 'Neither scapy nor tshark available'}

        try:
            packets = rdpcap(str(p), count=max_packets)
            self._last_packets = packets

            packet_list = []
            for pkt in packets:
                packet_list.append(self._packet_to_dict(pkt))

            return {
                'file': str(p),
                'size': p.stat().st_size,
                'total_packets': len(packets),
                'packets': packet_list,
            }
        except Exception as e:
            return {'error': f'Failed to read PCAP: {e}'}

    def _read_pcap_tshark(self, filepath: str, max_packets: int) -> Dict[str, Any]:
        """Read PCAP using tshark fallback."""
        try:
            result = subprocess.run(
                [TSHARK_PATH, '-r', filepath, '-c', str(max_packets),
                 '-T', 'fields',
                 '-e', 'frame.number', '-e', 'frame.time_relative',
                 '-e', 'ip.src', '-e', 'ip.dst',
                 '-e', 'frame.protocols', '-e', 'frame.len',
                 '-e', '_ws.col.Info',
                 '-E', 'separator=|'],
                capture_output=True, text=True, timeout=30
            )
            packets = []
            for line in result.stdout.strip().split('\n'):
                if not line.strip():
                    continue
                parts = line.split('|')
                if len(parts) >= 6:
                    packets.append({
                        'number': int(parts[0]) if parts[0] else 0,
                        'time': parts[1],
                        'src': parts[2],
                        'dst': parts[3],
                        'protocol': parts[4].split(':')[-1] if parts[4] else '',
                        'length': int(parts[5]) if parts[5] else 0,
                        'info': parts[6] if len(parts) > 6 else '',
                    })
            return {
                'file': filepath,
                'total_packets': len(packets),
                'packets': packets,
                'source': 'tshark',
            }
        except Exception as e:
            return {'error': f'tshark failed: {e}'}

    def _packet_to_dict(self, pkt) -> Dict[str, Any]:
        """Convert a scapy packet to a serializable dict."""
        d = {
            'length': len(pkt),
            'protocol': '',
            'src': '',
            'dst': '',
            'sport': None,
            'dport': None,
            'info': '',
            'time': float(pkt.time) if hasattr(pkt, 'time') else 0,
        }

        if pkt.haslayer(IP):
            d['src'] = pkt[IP].src
            d['dst'] = pkt[IP].dst
            d['protocol'] = 'IP'
        elif pkt.haslayer(IPv6):
            d['src'] = pkt[IPv6].src
            d['dst'] = pkt[IPv6].dst
            d['protocol'] = 'IPv6'
        elif pkt.haslayer(ARP):
            d['protocol'] = 'ARP'
            d['src'] = pkt[ARP].psrc
            d['dst'] = pkt[ARP].pdst
            d['info'] = f'ARP {pkt[ARP].op}'

        if pkt.haslayer(TCP):
            d['sport'] = pkt[TCP].sport
            d['dport'] = pkt[TCP].dport
            d['protocol'] = 'TCP'
            flags = pkt[TCP].flags
            d['info'] = f'{pkt[TCP].sport} -> {pkt[TCP].dport} [{flags}]'
        elif pkt.haslayer(UDP):
            d['sport'] = pkt[UDP].sport
            d['dport'] = pkt[UDP].dport
            d['protocol'] = 'UDP'
            d['info'] = f'{pkt[UDP].sport} -> {pkt[UDP].dport}'
        elif pkt.haslayer(ICMP):
            d['protocol'] = 'ICMP'
            d['info'] = f'Type {pkt[ICMP].type} Code {pkt[ICMP].code}'

        if pkt.haslayer(DNS):
            d['protocol'] = 'DNS'
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode(errors='ignore').rstrip('.')
                d['info'] = f'Query: {qname}'

        # Detect common application protocols by port
        if d['protocol'] in ('TCP', 'UDP'):
            ports = (d.get('sport'), d.get('dport'))
            if 80 in ports or 8080 in ports:
                d['protocol'] = 'HTTP'
            elif 443 in ports or 8443 in ports:
                d['protocol'] = 'TLS'
            elif 53 in ports:
                d['protocol'] = 'DNS'
            elif 22 in ports:
                d['protocol'] = 'SSH'
            elif 21 in ports:
                d['protocol'] = 'FTP'
            elif 25 in ports or 587 in ports:
                d['protocol'] = 'SMTP'
            elif 23 in ports:
                d['protocol'] = 'Telnet'

        return d

    # ==================== ANALYSIS ====================

    def _get_packets(self, packets=None):
        """Get packets from argument or last loaded."""
        if packets is not None:
            return packets
        if self._last_packets is not None:
            return self._last_packets
        if self._capture_packets:
            return self._capture_packets
        return []

    def get_protocol_hierarchy(self, packets=None) -> Dict[str, Any]:
        """Get protocol distribution from packets.

        Returns dict with protocol counts and percentages.
        """
        pkts = self._get_packets(packets)
        if not pkts:
            return {'protocols': {}, 'total': 0}

        counts = Counter()
        total = len(pkts)

        for pkt in pkts:
            if isinstance(pkt, dict):
                proto = pkt.get('protocol', 'Unknown')
            else:
                proto = self._packet_to_dict(pkt).get('protocol', 'Unknown')
            counts[proto] += 1

        protocols = {}
        for proto, count in counts.most_common():
            protocols[proto] = {
                'count': count,
                'percent': round(count * 100 / total, 1) if total else 0,
            }

        return {'protocols': protocols, 'total': total}

    def extract_conversations(self, packets=None) -> List[Dict[str, Any]]:
        """Extract IP conversations (src-dst pairs with stats)."""
        pkts = self._get_packets(packets)
        if not pkts:
            return []

        convos = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': set()})

        for pkt in pkts:
            if isinstance(pkt, dict):
                src = pkt.get('src', '')
                dst = pkt.get('dst', '')
                proto = pkt.get('protocol', '')
                length = pkt.get('length', 0)
            else:
                d = self._packet_to_dict(pkt)
                src, dst, proto, length = d['src'], d['dst'], d['protocol'], d['length']

            if not src or not dst:
                continue

            # Normalize key (sorted so A->B and B->A are same conversation)
            key = tuple(sorted([src, dst]))
            convos[key]['packets'] += 1
            convos[key]['bytes'] += length
            convos[key]['protocols'].add(proto)
            convos[key]['src'] = key[0]
            convos[key]['dst'] = key[1]

        result = []
        for key, data in sorted(convos.items(), key=lambda x: x[1]['packets'], reverse=True):
            result.append({
                'src': data['src'],
                'dst': data['dst'],
                'packets': data['packets'],
                'bytes': data['bytes'],
                'protocols': list(data['protocols']),
            })

        return result[:100]  # Top 100

    def extract_dns_queries(self, packets=None) -> List[Dict[str, Any]]:
        """Extract DNS queries and responses."""
        pkts = self._get_packets(packets)
        if not pkts:
            return []

        queries = []

        for pkt in pkts:
            if isinstance(pkt, dict):
                # From captured packet summaries - limited info
                if pkt.get('protocol') == 'DNS' and 'Query:' in pkt.get('info', ''):
                    queries.append({
                        'query': pkt['info'].replace('Query: ', ''),
                        'type': 'A',
                        'src': pkt.get('src', ''),
                        'response': '',
                    })
            else:
                # Full scapy packet
                if pkt.haslayer(DNS):
                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode(errors='ignore').rstrip('.')
                        qtype_num = pkt[DNSQR].qtype
                        qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA',
                                     15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV'}
                        qtype = qtype_map.get(qtype_num, str(qtype_num))

                        response = ''
                        if pkt.haslayer(DNSRR) and pkt[DNS].ancount > 0:
                            try:
                                rdata = pkt[DNSRR].rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode(errors='ignore')
                                response = str(rdata)
                            except Exception:
                                pass

                        src = pkt[IP].src if pkt.haslayer(IP) else ''
                        queries.append({
                            'query': qname,
                            'type': qtype,
                            'src': src,
                            'response': response,
                        })

        # Deduplicate and count
        seen = {}
        for q in queries:
            key = q['query']
            if key in seen:
                seen[key]['count'] += 1
                if q['response'] and not seen[key]['response']:
                    seen[key]['response'] = q['response']
            else:
                seen[key] = {**q, 'count': 1}

        return sorted(seen.values(), key=lambda x: x['count'], reverse=True)[:200]

    def extract_http_requests(self, packets=None) -> List[Dict[str, Any]]:
        """Extract HTTP requests from packets."""
        pkts = self._get_packets(packets)
        if not pkts:
            return []

        requests = []
        http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']

        for pkt in pkts:
            if isinstance(pkt, dict):
                continue  # Can't extract HTTP from summaries

            if not pkt.haslayer(Raw):
                continue
            if not pkt.haslayer(TCP):
                continue

            try:
                payload = bytes(pkt[Raw].load)
                # Check if it starts with an HTTP method
                is_http = any(payload.startswith(m + b' ') for m in http_methods)
                if not is_http:
                    continue

                lines = payload.split(b'\r\n')
                request_line = lines[0].decode(errors='ignore')
                parts = request_line.split(' ')
                if len(parts) < 2:
                    continue

                method = parts[0]
                path = parts[1]
                host = ''
                user_agent = ''
                content_type = ''

                for line in lines[1:]:
                    line_str = line.decode(errors='ignore')
                    lower = line_str.lower()
                    if lower.startswith('host:'):
                        host = line_str.split(':', 1)[1].strip()
                    elif lower.startswith('user-agent:'):
                        user_agent = line_str.split(':', 1)[1].strip()
                    elif lower.startswith('content-type:'):
                        content_type = line_str.split(':', 1)[1].strip()

                src = pkt[IP].src if pkt.haslayer(IP) else ''
                dst = pkt[IP].dst if pkt.haslayer(IP) else ''

                requests.append({
                    'method': method,
                    'host': host,
                    'path': path,
                    'src': src,
                    'dst': dst,
                    'user_agent': user_agent[:100],
                    'content_type': content_type,
                })
            except Exception:
                continue

        return requests[:500]

    def extract_credentials(self, packets=None) -> List[Dict[str, Any]]:
        """Detect plaintext credentials in packets.

        Checks FTP, HTTP Basic Auth, Telnet, SMTP, POP3, IMAP.
        """
        pkts = self._get_packets(packets)
        if not pkts:
            return []

        creds = []

        for pkt in pkts:
            if isinstance(pkt, dict):
                continue

            if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
                continue

            try:
                payload = bytes(pkt[Raw].load)
                payload_str = payload.decode(errors='ignore')
                payload_lower = payload_str.lower()
                src = pkt[IP].src if pkt.haslayer(IP) else ''
                dst = pkt[IP].dst if pkt.haslayer(IP) else ''
                dport = pkt[TCP].dport

                # FTP credentials
                if dport == 21:
                    if payload_str.startswith('USER '):
                        creds.append({
                            'protocol': 'FTP',
                            'type': 'username',
                            'value': payload_str.split(' ', 1)[1].strip(),
                            'src': src, 'dst': dst,
                        })
                    elif payload_str.startswith('PASS '):
                        creds.append({
                            'protocol': 'FTP',
                            'type': 'password',
                            'value': payload_str.split(' ', 1)[1].strip(),
                            'src': src, 'dst': dst,
                        })

                # HTTP Basic Auth
                if dport in (80, 8080, 8443):
                    auth_match = re.search(r'Authorization:\s*Basic\s+(\S+)', payload_str, re.IGNORECASE)
                    if auth_match:
                        import base64
                        try:
                            decoded = base64.b64decode(auth_match.group(1)).decode(errors='ignore')
                            creds.append({
                                'protocol': 'HTTP',
                                'type': 'basic_auth',
                                'value': decoded,
                                'src': src, 'dst': dst,
                            })
                        except Exception:
                            pass

                # HTTP form data (POST with password fields)
                if dport in (80, 8080) and b'POST' in payload[:10]:
                    for pattern in [r'password=([^&\s]+)', r'passwd=([^&\s]+)', r'pass=([^&\s]+)']:
                        match = re.search(pattern, payload_str, re.IGNORECASE)
                        if match:
                            creds.append({
                                'protocol': 'HTTP',
                                'type': 'form_password',
                                'value': match.group(1),
                                'src': src, 'dst': dst,
                            })
                            break

                # SMTP AUTH
                if dport in (25, 587):
                    if payload_str.startswith('AUTH LOGIN') or payload_str.startswith('AUTH PLAIN'):
                        creds.append({
                            'protocol': 'SMTP',
                            'type': 'auth',
                            'value': payload_str.strip(),
                            'src': src, 'dst': dst,
                        })

                # Telnet (look for login/password prompts followed by data)
                if dport == 23:
                    if any(k in payload_lower for k in ['login:', 'username:', 'password:']):
                        creds.append({
                            'protocol': 'Telnet',
                            'type': 'prompt',
                            'value': payload_str.strip()[:100],
                            'src': src, 'dst': dst,
                        })

                # POP3
                if dport == 110:
                    if payload_str.startswith('USER ') or payload_str.startswith('PASS '):
                        creds.append({
                            'protocol': 'POP3',
                            'type': 'auth',
                            'value': payload_str.strip(),
                            'src': src, 'dst': dst,
                        })

            except Exception:
                continue

        return creds[:100]

    # ==================== EXPORT ====================

    def export_packets(self, packets=None, fmt: str = 'json',
                       filepath: str = None) -> Dict[str, Any]:
        """Export packets to JSON or CSV.

        Args:
            packets: Packet list (uses last loaded if None)
            fmt: 'json' or 'csv'
            filepath: Output path (auto-generated if None)

        Returns:
            Dict with success status and filepath
        """
        pkts = self._get_packets(packets)
        if not pkts:
            return {'error': 'No packets to export'}

        # Convert to dicts if needed
        packet_dicts = []
        for pkt in pkts:
            if isinstance(pkt, dict):
                packet_dicts.append(pkt)
            else:
                packet_dicts.append(self._packet_to_dict(pkt))

        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        from core.paths import get_data_dir
        export_dir = get_data_dir() / 'exports'
        export_dir.mkdir(parents=True, exist_ok=True)

        if fmt == 'csv':
            if not filepath:
                filepath = str(export_dir / f'packets_{ts}.csv')
            lines = ['Time,Source,Destination,Protocol,Length,Info']
            for p in packet_dicts:
                lines.append(f'{p.get("time","")},{p.get("src","")},{p.get("dst","")},{p.get("protocol","")},{p.get("length",0)},{p.get("info","")}')
            Path(filepath).write_text('\n'.join(lines))
        else:
            if not filepath:
                filepath = str(export_dir / f'packets_{ts}.json')
            export_data = {
                'exported': datetime.now().isoformat(),
                'total_packets': len(packet_dicts),
                'packets': packet_dicts,
            }
            Path(filepath).write_text(json.dumps(export_data, indent=2))

        return {'success': True, 'filepath': filepath, 'count': len(packet_dicts)}


# Global instance
_manager: Optional[WiresharkManager] = None


def get_wireshark_manager() -> WiresharkManager:
    """Get the global WiresharkManager instance."""
    global _manager
    if _manager is None:
        _manager = WiresharkManager()
    return _manager
