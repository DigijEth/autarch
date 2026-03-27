"""AUTARCH DNS Service Manager — controls the Go-based autarch-dns binary."""

import os
import sys
import json
import time
import signal
import socket
import subprocess
import threading
from pathlib import Path

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        import shutil
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class DNSServiceManager:
    """Manage the autarch-dns Go binary (start/stop/API calls)."""

    def __init__(self):
        self._process = None
        self._pid = None
        self._config = None
        self._config_path = os.path.join(get_data_dir(), 'dns', 'config.json')
        self._load_config()

    def _load_config(self):
        if os.path.exists(self._config_path):
            try:
                with open(self._config_path, 'r') as f:
                    self._config = json.load(f)
            except Exception:
                self._config = None
        if not self._config:
            self._config = {
                'listen_dns': '0.0.0.0:53',
                'listen_api': '127.0.0.1:5380',
                'api_token': os.urandom(16).hex(),
                'upstream': [],  # Empty = pure recursive from root hints
                'cache_ttl': 300,
                'zones_dir': os.path.join(get_data_dir(), 'dns', 'zones'),
                'dnssec_keys_dir': os.path.join(get_data_dir(), 'dns', 'keys'),
                'log_queries': True,
            }
            self._save_config()

    def _save_config(self):
        os.makedirs(os.path.dirname(self._config_path), exist_ok=True)
        with open(self._config_path, 'w') as f:
            json.dump(self._config, f, indent=2)

    @property
    def api_base(self) -> str:
        addr = self._config.get('listen_api', '127.0.0.1:5380')
        return f'http://{addr}'

    @property
    def api_token(self) -> str:
        return self._config.get('api_token', '')

    def find_binary(self) -> str:
        """Find the autarch-dns binary."""
        binary = find_tool('autarch-dns')
        if binary:
            return binary
        # Check common locations
        base = Path(__file__).parent.parent
        candidates = [
            base / 'services' / 'dns-server' / 'autarch-dns',
            base / 'services' / 'dns-server' / 'autarch-dns.exe',
            base / 'tools' / 'windows-x86_64' / 'autarch-dns.exe',
            base / 'tools' / 'linux-arm64' / 'autarch-dns',
            base / 'tools' / 'linux-x86_64' / 'autarch-dns',
        ]
        for c in candidates:
            if c.exists():
                return str(c)
        return None

    def is_running(self) -> bool:
        """Check if the DNS service is running."""
        # Check process
        if self._process and self._process.poll() is None:
            return True
        # Check by API
        try:
            resp = self._api_get('/api/status')
            return resp.get('ok', False)
        except Exception:
            return False

    def start(self) -> dict:
        """Start the DNS service."""
        if self.is_running():
            return {'ok': True, 'message': 'DNS service already running'}

        binary = self.find_binary()
        if not binary:
            return {'ok': False, 'error': 'autarch-dns binary not found. Build it with: cd services/dns-server && go build'}

        # Ensure zone dirs exist
        os.makedirs(self._config.get('zones_dir', ''), exist_ok=True)
        os.makedirs(self._config.get('dnssec_keys_dir', ''), exist_ok=True)

        # Save config for the Go binary to read
        self._save_config()

        cmd = [
            binary,
            '-config', self._config_path,
        ]

        try:
            kwargs = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
            }
            if sys.platform == 'win32':
                kwargs['creationflags'] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP |
                    subprocess.CREATE_NO_WINDOW
                )
            else:
                kwargs['start_new_session'] = True

            self._process = subprocess.Popen(cmd, **kwargs)
            self._pid = self._process.pid

            # Wait for API to be ready
            for _ in range(30):
                time.sleep(0.5)
                try:
                    resp = self._api_get('/api/status')
                    if resp.get('ok'):
                        return {
                            'ok': True,
                            'message': f'DNS service started (PID {self._pid})',
                            'pid': self._pid,
                        }
                except Exception:
                    if self._process.poll() is not None:
                        return {'ok': False, 'error': 'DNS service exited immediately — may need admin/root for port 53'}
                    continue

            return {'ok': False, 'error': 'DNS service started but API not responding'}
        except PermissionError:
            return {'ok': False, 'error': 'Permission denied — DNS on port 53 requires admin/root'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def stop(self) -> dict:
        """Stop the DNS service."""
        if self._process and self._process.poll() is None:
            try:
                if sys.platform == 'win32':
                    self._process.terminate()
                else:
                    os.kill(self._process.pid, signal.SIGTERM)
                self._process.wait(timeout=5)
            except Exception:
                self._process.kill()
            self._process = None
            self._pid = None
            return {'ok': True, 'message': 'DNS service stopped'}
        return {'ok': True, 'message': 'DNS service was not running'}

    def status(self) -> dict:
        """Get service status."""
        running = self.is_running()
        result = {
            'running': running,
            'pid': self._pid,
            'listen_dns': self._config.get('listen_dns', ''),
            'listen_api': self._config.get('listen_api', ''),
        }
        if running:
            try:
                resp = self._api_get('/api/status')
                result.update(resp)
            except Exception:
                pass
        return result

    # ── API wrappers ─────────────────────────────────────────────────────

    def _api_get(self, endpoint: str) -> dict:
        if not _HAS_REQUESTS:
            return self._api_urllib(endpoint, 'GET')
        resp = requests.get(
            f'{self.api_base}{endpoint}',
            headers={'Authorization': f'Bearer {self.api_token}'},
            timeout=5,
        )
        return resp.json()

    def _api_post(self, endpoint: str, data: dict = None) -> dict:
        if not _HAS_REQUESTS:
            return self._api_urllib(endpoint, 'POST', data)
        resp = requests.post(
            f'{self.api_base}{endpoint}',
            headers={'Authorization': f'Bearer {self.api_token}', 'Content-Type': 'application/json'},
            json=data or {},
            timeout=5,
        )
        return resp.json()

    def _api_delete(self, endpoint: str) -> dict:
        if not _HAS_REQUESTS:
            return self._api_urllib(endpoint, 'DELETE')
        resp = requests.delete(
            f'{self.api_base}{endpoint}',
            headers={'Authorization': f'Bearer {self.api_token}'},
            timeout=5,
        )
        return resp.json()

    def _api_put(self, endpoint: str, data: dict = None) -> dict:
        if not _HAS_REQUESTS:
            return self._api_urllib(endpoint, 'PUT', data)
        resp = requests.put(
            f'{self.api_base}{endpoint}',
            headers={'Authorization': f'Bearer {self.api_token}', 'Content-Type': 'application/json'},
            json=data or {},
            timeout=5,
        )
        return resp.json()

    def _api_urllib(self, endpoint: str, method: str, data: dict = None) -> dict:
        """Fallback using urllib (no requests dependency)."""
        import urllib.request
        url = f'{self.api_base}{endpoint}'
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            url, data=body, method=method,
            headers={
                'Authorization': f'Bearer {self.api_token}',
                'Content-Type': 'application/json',
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())

    # ── High-level zone operations ───────────────────────────────────────

    def list_zones(self) -> list:
        return self._api_get('/api/zones').get('zones', [])

    def create_zone(self, domain: str) -> dict:
        return self._api_post('/api/zones', {'domain': domain})

    def get_zone(self, domain: str) -> dict:
        return self._api_get(f'/api/zones/{domain}')

    def delete_zone(self, domain: str) -> dict:
        return self._api_delete(f'/api/zones/{domain}')

    def list_records(self, domain: str) -> list:
        return self._api_get(f'/api/zones/{domain}/records').get('records', [])

    def add_record(self, domain: str, rtype: str, name: str, value: str,
                   ttl: int = 300, priority: int = 0) -> dict:
        return self._api_post(f'/api/zones/{domain}/records', {
            'type': rtype, 'name': name, 'value': value,
            'ttl': ttl, 'priority': priority,
        })

    def delete_record(self, domain: str, record_id: str) -> dict:
        return self._api_delete(f'/api/zones/{domain}/records/{record_id}')

    def setup_mail_records(self, domain: str, mx_host: str = '',
                           dkim_key: str = '', spf_allow: str = '') -> dict:
        return self._api_post(f'/api/zones/{domain}/mail-setup', {
            'mx_host': mx_host, 'dkim_key': dkim_key, 'spf_allow': spf_allow,
        })

    def enable_dnssec(self, domain: str) -> dict:
        return self._api_post(f'/api/zones/{domain}/dnssec/enable')

    def disable_dnssec(self, domain: str) -> dict:
        return self._api_post(f'/api/zones/{domain}/dnssec/disable')

    def get_metrics(self) -> dict:
        return self._api_get('/api/metrics').get('metrics', {})

    def get_config(self) -> dict:
        return self._config.copy()

    def update_config(self, updates: dict) -> dict:
        for k, v in updates.items():
            if k in self._config:
                self._config[k] = v
        self._save_config()
        # Also update running service
        try:
            return self._api_put('/api/config', updates)
        except Exception:
            return {'ok': True, 'message': 'Config saved (service not running)'}


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_dns_service() -> DNSServiceManager:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = DNSServiceManager()
    return _instance
