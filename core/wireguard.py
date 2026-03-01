"""
AUTARCH WireGuard VPN Manager
Server management, client/peer CRUD, remote ADB (TCP/IP + USB/IP).

Integrates /home/snake/wg_setec/ functionality into the AUTARCH framework
with added remote ADB and USB/IP support for Android device management
over WireGuard tunnels.
"""

import io
import json
import re
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

from core.paths import get_data_dir, find_tool


class WireGuardManager:
    """WireGuard VPN + Remote ADB manager."""

    def __init__(self, config=None):
        self._wg_bin = find_tool('wg')
        self._wg_quick = find_tool('wg-quick')
        self._usbip_bin = find_tool('usbip')

        self._data_dir = get_data_dir() / 'wireguard'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._clients_file = self._data_dir / 'clients.json'
        self._last_ip_file = self._data_dir / 'last_ip'

        # Config from autarch_settings.conf [wireguard] section
        self._config = config or {}
        self._wg_config_path = self._config.get('config_path', '/etc/wireguard/wg0.conf')
        self._interface = self._config.get('interface', 'wg0')
        self._subnet = self._config.get('subnet', '10.1.0.0/24')
        self._server_address = self._config.get('server_address', '10.1.0.1')
        self._listen_port = self._config.get('listen_port', '51820')
        self._default_dns = self._config.get('default_dns', '1.1.1.1, 8.8.8.8')
        self._default_allowed_ips = self._config.get('default_allowed_ips', '0.0.0.0/0, ::/0')

    # ── Helpers ──────────────────────────────────────────────────────

    def _run_wg(self, args, timeout=10):
        """Run wg command, return (stdout, stderr, rc)."""
        if not self._wg_bin:
            return ('', 'wg binary not found', 1)
        cmd = [self._wg_bin] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            return ('', 'Command timed out', 1)
        except Exception as e:
            return ('', str(e), 1)

    def _run_wg_sudo(self, args, timeout=10):
        """Run wg command with sudo, return (stdout, stderr, rc)."""
        if not self._wg_bin:
            return ('', 'wg binary not found', 1)
        cmd = ['sudo', self._wg_bin] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            return ('', 'Command timed out', 1)
        except Exception as e:
            return ('', str(e), 1)

    def _run_cmd(self, cmd, timeout=10, input_data=None):
        """Run arbitrary command, return (stdout, stderr, rc)."""
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout, input=input_data
            )
            return (proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            return ('', 'Command timed out', 1)
        except Exception as e:
            return ('', str(e), 1)

    def _load_clients(self):
        """Load clients from JSON file."""
        if not self._clients_file.exists():
            return {}
        try:
            with open(self._clients_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_clients(self, data):
        """Save clients to JSON file."""
        with open(self._clients_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _get_server_public_key(self):
        """Read server public key."""
        # Try file first
        key_path = Path('/etc/wireguard/server_public.key')
        if key_path.exists():
            try:
                return key_path.read_text().strip()
            except OSError:
                pass
        # Try wg show
        stdout, _, rc = self._run_wg_sudo(['show', self._interface, 'public-key'])
        if rc == 0 and stdout.strip():
            return stdout.strip()
        return ''

    def _get_server_endpoint(self):
        """Read server public IP/endpoint."""
        ip_path = Path('/etc/wireguard/server_public_ip')
        if ip_path.exists():
            try:
                return ip_path.read_text().strip()
            except OSError:
                pass
        return ''

    def _adb_bin(self):
        """Get ADB binary path."""
        return find_tool('adb')

    def _run_adb(self, args, timeout=30):
        """Run ADB command, return (stdout, stderr, rc)."""
        adb = self._adb_bin()
        if not adb:
            return ('', 'adb binary not found', 1)
        cmd = [adb] + args
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return (proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired:
            return ('', 'Command timed out', 1)
        except Exception as e:
            return ('', str(e), 1)

    # ── Server Management ────────────────────────────────────────────

    def is_available(self):
        """Check if wg binary exists."""
        return self._wg_bin is not None

    def get_server_status(self):
        """Parse wg show for interface info."""
        stdout, stderr, rc = self._run_wg_sudo(['show', self._interface])
        if rc != 0:
            return {
                'running': False,
                'interface': self._interface,
                'error': stderr.strip() if stderr else 'Interface not running',
            }

        info = {
            'interface': self._interface,
            'running': True,
            'public_key': self._get_server_public_key(),
            'endpoint': f'{self._get_server_endpoint()}:{self._listen_port}',
            'listen_port': self._listen_port,
        }

        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('listening port:'):
                info['listen_port'] = line.split(':', 1)[1].strip()
            elif line.startswith('public key:'):
                info['public_key'] = line.split(':', 1)[1].strip()

        # Count peers
        peer_count = stdout.count('peer:')
        info['peer_count'] = peer_count

        return info

    def start_interface(self):
        """Start WireGuard interface with wg-quick."""
        if not self._wg_quick:
            return {'ok': False, 'error': 'wg-quick not found'}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._wg_quick, 'up', self._interface], timeout=15)
        if rc == 0:
            return {'ok': True, 'message': f'{self._interface} started'}
        # Already running is not an error
        if 'already exists' in stderr:
            return {'ok': True, 'message': f'{self._interface} already running'}
        return {'ok': False, 'error': stderr.strip() or 'Failed to start'}

    def stop_interface(self):
        """Stop WireGuard interface with wg-quick."""
        if not self._wg_quick:
            return {'ok': False, 'error': 'wg-quick not found'}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._wg_quick, 'down', self._interface], timeout=15)
        if rc == 0:
            return {'ok': True, 'message': f'{self._interface} stopped'}
        if 'is not a WireGuard interface' in stderr:
            return {'ok': True, 'message': f'{self._interface} already stopped'}
        return {'ok': False, 'error': stderr.strip() or 'Failed to stop'}

    def restart_interface(self):
        """Restart WireGuard interface."""
        self.stop_interface()
        time.sleep(1)
        return self.start_interface()

    # ── Key Generation ───────────────────────────────────────────────

    def generate_keypair(self):
        """Generate WireGuard keypair. Returns (private_key, public_key)."""
        priv_out, priv_err, priv_rc = self._run_wg(['genkey'])
        if priv_rc != 0:
            return (None, None)
        private_key = priv_out.strip()
        pub_out, pub_err, pub_rc = self._run_wg(['pubkey'], timeout=5)
        # pubkey reads from stdin, need to pipe
        proc = subprocess.run(
            [self._wg_bin, 'pubkey'], input=private_key,
            capture_output=True, text=True, timeout=5
        )
        if proc.returncode != 0:
            return (None, None)
        public_key = proc.stdout.strip()
        return (private_key, public_key)

    def generate_preshared_key(self):
        """Generate WireGuard preshared key."""
        stdout, _, rc = self._run_wg(['genpsk'])
        if rc == 0:
            return stdout.strip()
        return None

    # ── IP Assignment ────────────────────────────────────────────────

    def get_next_ip(self):
        """Get next available client IP in the subnet."""
        try:
            if self._last_ip_file.exists():
                last_octet = int(self._last_ip_file.read_text().strip())
            else:
                last_octet = 1
        except (ValueError, OSError):
            last_octet = 1

        next_octet = last_octet + 1
        self._last_ip_file.write_text(str(next_octet))

        # Extract subnet prefix (e.g. "10.1.0" from "10.1.0.0/24")
        prefix = '.'.join(self._subnet.split('.')[:3])
        return f'{prefix}.{next_octet}'

    # ── Client/Peer Management ───────────────────────────────────────

    def create_client(self, name, dns=None, allowed_ips=None):
        """Create a new WireGuard client/peer."""
        private_key, public_key = self.generate_keypair()
        if not private_key:
            return {'ok': False, 'error': 'Failed to generate keypair'}

        preshared_key = self.generate_preshared_key()
        assigned_ip = self.get_next_ip()

        client_id = str(uuid.uuid4())[:8]
        client = {
            'id': client_id,
            'name': name,
            'private_key': private_key,
            'public_key': public_key,
            'preshared_key': preshared_key or '',
            'assigned_ip': assigned_ip,
            'dns': dns or self._default_dns,
            'allowed_ips': allowed_ips or self._default_allowed_ips,
            'enabled': True,
            'created_at': datetime.now().isoformat(),
        }

        # Add to live WireGuard
        try:
            self._add_peer_to_wg(public_key, preshared_key, assigned_ip)
        except Exception as e:
            return {'ok': False, 'error': f'Failed to add peer to WG: {e}'}

        # Add to config file
        try:
            self._append_peer_to_config(public_key, preshared_key, assigned_ip, name)
        except Exception as e:
            pass  # Non-fatal, peer is live

        # Save to JSON store
        clients = self._load_clients()
        clients[client_id] = client
        self._save_clients(clients)

        return {'ok': True, 'client': client}

    def delete_client(self, client_id):
        """Delete a client/peer."""
        clients = self._load_clients()
        client = clients.get(client_id)
        if not client:
            return {'ok': False, 'error': 'Client not found'}

        # Remove from live WG
        self._remove_peer_from_wg(client['public_key'])

        # Remove from config file
        try:
            self._remove_peer_from_config(client['public_key'])
        except Exception:
            pass

        # Remove from JSON
        del clients[client_id]
        self._save_clients(clients)

        return {'ok': True, 'message': f'Client {client["name"]} deleted'}

    def toggle_client(self, client_id, enabled):
        """Enable or disable a client."""
        clients = self._load_clients()
        client = clients.get(client_id)
        if not client:
            return {'ok': False, 'error': 'Client not found'}

        if enabled and not client.get('enabled', True):
            # Re-add peer
            self._add_peer_to_wg(
                client['public_key'], client.get('preshared_key', ''),
                client['assigned_ip'])
        elif not enabled and client.get('enabled', True):
            # Remove peer
            self._remove_peer_from_wg(client['public_key'])

        client['enabled'] = enabled
        self._save_clients(clients)
        action = 'enabled' if enabled else 'disabled'
        return {'ok': True, 'message': f'Client {client["name"]} {action}'}

    def get_all_clients(self):
        """Get list of all clients."""
        clients = self._load_clients()
        return list(clients.values())

    def get_client(self, client_id):
        """Get single client by ID."""
        clients = self._load_clients()
        return clients.get(client_id)

    def get_peer_status(self):
        """Parse wg show for per-peer stats. Returns dict keyed by public key."""
        stdout, _, rc = self._run_wg_sudo(['show', self._interface])
        if rc != 0:
            return {}

        peers = {}
        current_peer = None

        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                peers[current_peer] = {
                    'public_key': current_peer,
                    'latest_handshake': None,
                    'latest_handshake_str': '',
                    'transfer_rx': 0,
                    'transfer_tx': 0,
                    'transfer_rx_str': '',
                    'transfer_tx_str': '',
                    'allowed_ips': '',
                    'endpoint': '',
                }
            elif current_peer:
                if line.startswith('latest handshake:'):
                    hs_str = line.split(':', 1)[1].strip()
                    peers[current_peer]['latest_handshake'] = _parse_handshake(hs_str)
                    peers[current_peer]['latest_handshake_str'] = hs_str
                elif line.startswith('transfer:'):
                    transfer = line.split(':', 1)[1].strip()
                    parts = transfer.split(',')
                    if len(parts) == 2:
                        peers[current_peer]['transfer_rx'] = _parse_transfer(parts[0].strip())
                        peers[current_peer]['transfer_tx'] = _parse_transfer(parts[1].strip())
                        peers[current_peer]['transfer_rx_str'] = parts[0].strip().replace('received', '').strip()
                        peers[current_peer]['transfer_tx_str'] = parts[1].strip().replace('sent', '').strip()
                elif line.startswith('allowed ips:'):
                    peers[current_peer]['allowed_ips'] = line.split(':', 1)[1].strip()
                elif line.startswith('endpoint:'):
                    peers[current_peer]['endpoint'] = line.split(':', 1)[1].strip()

        return peers

    def _add_peer_to_wg(self, public_key, preshared_key, allowed_ip):
        """Add peer to live WireGuard interface."""
        if preshared_key:
            stdout, stderr, rc = self._run_cmd(
                ['sudo', self._wg_bin, 'set', self._interface,
                 'peer', public_key,
                 'preshared-key', '/dev/stdin',
                 'allowed-ips', f'{allowed_ip}/32'],
                input_data=preshared_key, timeout=10
            )
        else:
            stdout, stderr, rc = self._run_wg_sudo(
                ['set', self._interface,
                 'peer', public_key,
                 'allowed-ips', f'{allowed_ip}/32'])
        if rc != 0:
            raise RuntimeError(f'wg set failed: {stderr}')

    def _remove_peer_from_wg(self, public_key):
        """Remove peer from live WireGuard interface."""
        self._run_wg_sudo(
            ['set', self._interface, 'peer', public_key, 'remove'])

    def _append_peer_to_config(self, public_key, preshared_key, allowed_ip, name=''):
        """Append [Peer] block to wg0.conf."""
        config_path = Path(self._wg_config_path)
        if not config_path.exists():
            return
        content = config_path.read_text()
        timestamp = time.strftime('%c')
        block = f'\n# Client: {name} - Added {timestamp}\n[Peer]\n'
        block += f'PublicKey = {public_key}\n'
        if preshared_key:
            block += f'PresharedKey = {preshared_key}\n'
        block += f'AllowedIPs = {allowed_ip}/32\n'
        # Write via sudo tee
        self._run_cmd(
            ['sudo', 'tee', '-a', self._wg_config_path],
            input_data=block, timeout=5)

    def _remove_peer_from_config(self, public_key):
        """Remove [Peer] block from wg0.conf."""
        config_path = Path(self._wg_config_path)
        if not config_path.exists():
            return
        # Read via sudo
        stdout, _, rc = self._run_cmd(['sudo', 'cat', self._wg_config_path])
        if rc != 0:
            return
        content = stdout

        lines = content.split('\n')
        new_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            # Check comment line preceding peer block
            if line.strip().startswith('# Client:') and i + 1 < len(lines):
                block_lines = [line]
                j = i + 1
                while j < len(lines):
                    if (lines[j].strip() == '' or
                        (lines[j].strip().startswith('[') and lines[j].strip() != '[Peer]') or
                        lines[j].strip().startswith('# Client:')):
                        break
                    block_lines.append(lines[j])
                    j += 1
                if public_key in '\n'.join(block_lines):
                    i = j
                    continue
            elif line.strip() == '[Peer]':
                block_lines = [line]
                j = i + 1
                while j < len(lines):
                    if (lines[j].strip() == '' or
                        (lines[j].strip().startswith('[') and lines[j].strip() != '[Peer]') or
                        lines[j].strip().startswith('# Client:')):
                        break
                    block_lines.append(lines[j])
                    j += 1
                if public_key in '\n'.join(block_lines):
                    i = j
                    continue
            new_lines.append(line)
            i += 1

        cleaned = re.sub(r'\n{3,}', '\n\n', '\n'.join(new_lines))
        # Write back via sudo tee
        self._run_cmd(
            ['sudo', 'tee', self._wg_config_path],
            input_data=cleaned, timeout=5)

    def import_existing_peers(self):
        """Parse wg0.conf and import existing peers into JSON store."""
        stdout, _, rc = self._run_cmd(['sudo', 'cat', self._wg_config_path])
        if rc != 0:
            return {'ok': False, 'error': 'Cannot read WG config', 'imported': 0}

        lines = stdout.split('\n')
        peers = []
        current_peer = None
        pending_name = None

        for line in lines:
            stripped = line.strip()
            name_match = re.match(r'# Client:\s*(.+?)(?:\s*-\s*Added|$)', stripped)
            if name_match:
                pending_name = name_match.group(1).strip()
                continue
            if stripped == '[Peer]':
                current_peer = {'name': pending_name}
                peers.append(current_peer)
                pending_name = None
                continue
            if stripped.startswith('['):
                current_peer = None
                pending_name = None
                continue
            if current_peer is not None and '=' in stripped:
                key, val = stripped.split('=', 1)
                current_peer[key.strip()] = val.strip()

        clients = self._load_clients()
        existing_keys = {c['public_key'] for c in clients.values()}
        imported = 0

        for peer in peers:
            public_key = peer.get('PublicKey')
            allowed_ip = peer.get('AllowedIPs', '').replace('/32', '')
            preshared_key = peer.get('PresharedKey', '')
            name = peer.get('name') or 'legacy-client'

            if not public_key or not allowed_ip:
                continue
            if public_key in existing_keys:
                continue

            # Ensure unique name
            existing_names = {c['name'] for c in clients.values()}
            final_name = name
            counter = 1
            while final_name in existing_names:
                final_name = f'{name}-{counter}'
                counter += 1

            client_id = str(uuid.uuid4())[:8]
            clients[client_id] = {
                'id': client_id,
                'name': final_name,
                'private_key': '',
                'public_key': public_key,
                'preshared_key': preshared_key,
                'assigned_ip': allowed_ip,
                'dns': self._default_dns,
                'allowed_ips': self._default_allowed_ips,
                'enabled': True,
                'created_at': datetime.now().isoformat(),
                'imported': True,
            }
            existing_keys.add(public_key)
            imported += 1

        self._save_clients(clients)
        return {'ok': True, 'imported': imported}

    # ── Client Config Generation ─────────────────────────────────────

    def generate_client_config(self, client):
        """Build the .conf file content for a client."""
        server_pubkey = self._get_server_public_key()
        server_endpoint = self._get_server_endpoint()

        lines = ['[Interface]']
        if client.get('private_key'):
            lines.append(f"PrivateKey = {client['private_key']}")
        lines.append(f"Address = {client['assigned_ip']}/32")
        lines.append(f"DNS = {client.get('dns', self._default_dns)}")
        lines.append('')
        lines.append('[Peer]')
        lines.append(f'PublicKey = {server_pubkey}')
        if client.get('preshared_key'):
            lines.append(f"PresharedKey = {client['preshared_key']}")
        lines.append(f'Endpoint = {server_endpoint}:{self._listen_port}')
        lines.append(f"AllowedIPs = {client.get('allowed_ips', self._default_allowed_ips)}")
        lines.append('PersistentKeepalive = 25')
        lines.append('')
        return '\n'.join(lines)

    def generate_qr_code(self, config_text):
        """Generate QR code PNG bytes from config text."""
        try:
            import qrcode
            qr = qrcode.QRCode(
                version=1, box_size=10, border=4,
                error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(config_text)
            qr.make(fit=True)
            img = qr.make_image(fill_color='black', back_color='white')
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)
            return buf.getvalue()
        except ImportError:
            return None

    # ── Remote ADB — TCP/IP ──────────────────────────────────────────

    def adb_connect(self, client_ip):
        """Connect to device via ADB TCP/IP over WireGuard tunnel."""
        stdout, stderr, rc = self._run_adb(
            ['connect', f'{client_ip}:5555'], timeout=15)
        output = (stdout + stderr).strip()
        if 'connected' in output.lower():
            return {'ok': True, 'message': output}
        return {'ok': False, 'error': output or 'Connection failed'}

    def adb_disconnect(self, client_ip):
        """Disconnect ADB TCP/IP device."""
        stdout, stderr, rc = self._run_adb(
            ['disconnect', f'{client_ip}:5555'], timeout=10)
        return {'ok': rc == 0, 'message': (stdout + stderr).strip()}

    def get_adb_remote_devices(self):
        """Filter adb devices for WireGuard subnet IPs."""
        stdout, _, rc = self._run_adb(['devices', '-l'], timeout=10)
        if rc != 0:
            return []
        # Extract WG subnet prefix
        prefix = '.'.join(self._subnet.split('.')[:3]) + '.'
        devices = []
        for line in stdout.strip().split('\n')[1:]:  # skip header
            line = line.strip()
            if not line or 'List of' in line:
                continue
            parts = line.split()
            if parts and parts[0].startswith(prefix):
                serial = parts[0]
                state = parts[1] if len(parts) > 1 else 'unknown'
                model = ''
                for p in parts[2:]:
                    if p.startswith('model:'):
                        model = p.split(':', 1)[1]
                devices.append({
                    'serial': serial,
                    'state': state,
                    'model': model,
                    'ip': serial.split(':')[0],
                })
        return devices

    def auto_connect_peers(self):
        """Try ADB connect on all active WG peers."""
        peer_status = self.get_peer_status()
        clients = self._load_clients()
        results = []

        for client in clients.values():
            if not client.get('enabled', True):
                continue
            # Check if peer has recent handshake
            pub_key = client['public_key']
            peer = peer_status.get(pub_key, {})
            hs = peer.get('latest_handshake')
            if hs is not None and hs < 180:  # Active within 3 minutes
                ip = client['assigned_ip']
                result = self.adb_connect(ip)
                results.append({
                    'name': client['name'],
                    'ip': ip,
                    'result': result,
                })

        return {'ok': True, 'results': results, 'attempted': len(results)}

    # ── Remote ADB — USB/IP ──────────────────────────────────────────

    def usbip_available(self):
        """Check if usbip binary exists."""
        return self._usbip_bin is not None

    def check_usbip_modules(self):
        """Check if vhci-hcd kernel module is loaded."""
        stdout, _, rc = self._run_cmd(['lsmod'], timeout=5)
        return 'vhci_hcd' in stdout

    def load_usbip_modules(self):
        """Load vhci-hcd kernel module."""
        stdout, stderr, rc = self._run_cmd(
            ['sudo', 'modprobe', 'vhci-hcd'], timeout=10)
        if rc == 0:
            return {'ok': True, 'message': 'vhci-hcd module loaded'}
        return {'ok': False, 'error': stderr.strip() or 'Failed to load module'}

    def usbip_list_remote(self, client_ip):
        """List exportable USB devices on remote host."""
        if not self._usbip_bin:
            return {'ok': False, 'error': 'usbip not found', 'devices': []}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._usbip_bin, 'list', '-r', client_ip], timeout=15)
        if rc != 0:
            return {'ok': False, 'error': stderr.strip() or 'Failed to list',
                    'devices': []}

        devices = []
        current = None
        for line in stdout.split('\n'):
            line = line.strip()
            # Parse device lines like: "1-1: vendor:product ..."
            m = re.match(r'(\d+-[\d.]+):\s*(.+)', line)
            if m:
                current = {
                    'busid': m.group(1),
                    'description': m.group(2).strip(),
                }
                devices.append(current)
            elif current and ':' in line and not line.startswith('usbip'):
                # Additional info lines
                current['description'] += f' | {line}'

        return {'ok': True, 'devices': devices}

    def usbip_attach(self, client_ip, busid):
        """Attach remote USB device via USB/IP."""
        if not self._usbip_bin:
            return {'ok': False, 'error': 'usbip not found'}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._usbip_bin, 'attach', '-r', client_ip, '-b', busid],
            timeout=15)
        if rc == 0:
            return {'ok': True, 'message': f'Attached {busid} from {client_ip}'}
        return {'ok': False, 'error': stderr.strip() or 'Failed to attach'}

    def usbip_detach(self, port):
        """Detach USB/IP virtual device by port number."""
        if not self._usbip_bin:
            return {'ok': False, 'error': 'usbip not found'}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._usbip_bin, 'detach', '-p', str(port)], timeout=10)
        if rc == 0:
            return {'ok': True, 'message': f'Detached port {port}'}
        return {'ok': False, 'error': stderr.strip() or 'Failed to detach'}

    def usbip_port_status(self):
        """List imported virtual USB devices."""
        if not self._usbip_bin:
            return {'ok': False, 'error': 'usbip not found', 'ports': []}
        stdout, stderr, rc = self._run_cmd(
            ['sudo', self._usbip_bin, 'port'], timeout=10)
        if rc != 0:
            return {'ok': False, 'error': stderr.strip(), 'ports': []}

        ports = []
        current = None
        for line in stdout.split('\n'):
            line = line.strip()
            m = re.match(r'Port\s+(\d+):\s*(.+)', line)
            if m:
                current = {
                    'port': m.group(1),
                    'status': m.group(2).strip(),
                }
                ports.append(current)
            elif current and line and not line.startswith('Port'):
                current['detail'] = line

        return {'ok': True, 'ports': ports}

    def get_usbip_status(self):
        """Combined USB/IP status."""
        available = self.usbip_available()
        modules_loaded = self.check_usbip_modules() if available else False
        ports = self.usbip_port_status() if available else {'ports': []}
        return {
            'available': available,
            'modules_loaded': modules_loaded,
            'active_imports': len(ports.get('ports', [])),
            'ports': ports.get('ports', []),
        }

    # ── UPnP Integration ─────────────────────────────────────────────

    def refresh_upnp_mapping(self):
        """Ensure port 51820/UDP is UPnP-mapped."""
        try:
            from core.upnp import get_upnp_manager
            mgr = get_upnp_manager()
            result = mgr.add_mapping(
                int(self._listen_port), 'UDP',
                f'WireGuard VPN (port {self._listen_port})')
            return result
        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Utility Functions ────────────────────────────────────────────────

def _parse_handshake(hs_str):
    """Parse handshake time string into seconds ago, or None."""
    total_seconds = 0
    parts = hs_str.replace(' ago', '').split(',')
    for part in parts:
        part = part.strip()
        match = re.match(r'(\d+)\s+(second|minute|hour|day)', part)
        if match:
            val = int(match.group(1))
            unit = match.group(2)
            if unit == 'second':
                total_seconds += val
            elif unit == 'minute':
                total_seconds += val * 60
            elif unit == 'hour':
                total_seconds += val * 3600
            elif unit == 'day':
                total_seconds += val * 86400
    return total_seconds if total_seconds > 0 else None


def _parse_transfer(s):
    """Parse transfer string like '1.5 MiB' into bytes."""
    match = re.match(r'([\d.]+)\s*(\w+)', s)
    if not match:
        return 0
    val = float(match.group(1))
    unit = match.group(2)
    multipliers = {
        'B': 1, 'KiB': 1024, 'MiB': 1024**2,
        'GiB': 1024**3, 'TiB': 1024**4
    }
    return int(val * multipliers.get(unit, 1))


# ── Singleton ────────────────────────────────────────────────────────

_manager = None

def get_wireguard_manager(config=None):
    global _manager
    if _manager is None:
        # Load config from autarch_settings.conf
        if config is None:
            try:
                from core.config import get_config
                cfg = get_config()
                config = {
                    'config_path': cfg.get('wireguard', 'config_path',
                                           fallback='/etc/wireguard/wg0.conf'),
                    'interface': cfg.get('wireguard', 'interface', fallback='wg0'),
                    'subnet': cfg.get('wireguard', 'subnet', fallback='10.1.0.0/24'),
                    'server_address': cfg.get('wireguard', 'server_address',
                                              fallback='10.1.0.1'),
                    'listen_port': cfg.get('wireguard', 'listen_port', fallback='51820'),
                    'default_dns': cfg.get('wireguard', 'default_dns',
                                           fallback='1.1.1.1, 8.8.8.8'),
                    'default_allowed_ips': cfg.get('wireguard', 'default_allowed_ips',
                                                   fallback='0.0.0.0/0, ::/0'),
                }
            except Exception:
                config = {}
        _manager = WireGuardManager(config)
    return _manager
