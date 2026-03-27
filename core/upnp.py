"""
AUTARCH UPnP Manager
Manages UPnP port forwarding via miniupnpc (upnpc CLI)
"""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional, Tuple

from core.paths import find_tool


class UPnPManager:
    """UPnP port forwarding manager wrapping the upnpc CLI."""

    def __init__(self, config=None):
        self.config = config
        self._upnpc = find_tool('upnpc')

    def is_available(self) -> bool:
        """Check if upnpc is installed."""
        return self._upnpc is not None

    def _run(self, args: list, timeout: int = 15) -> Tuple[bool, str]:
        """Run upnpc with arguments and return (success, output)."""
        if not self._upnpc:
            return False, "upnpc not found. Install miniupnpc."
        try:
            result = subprocess.run(
                [self._upnpc] + args,
                capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout + result.stderr
            return result.returncode == 0, output.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except Exception as e:
            return False, str(e)

    def list_mappings(self) -> Tuple[bool, str]:
        """List current UPnP port mappings."""
        return self._run(['-l'])

    def add_mapping(self, internal_ip: str, internal_port: int,
                    external_port: int, protocol: str,
                    description: str = "AUTARCH") -> Tuple[bool, str]:
        """Add a UPnP port mapping.

        Args:
            internal_ip: LAN IP to forward to
            internal_port: Internal port number
            external_port: External port number
            protocol: TCP or UDP
            description: Mapping description
        """
        protocol = protocol.upper()
        if protocol not in ('TCP', 'UDP'):
            return False, "Protocol must be TCP or UDP"
        return self._run([
            '-a', internal_ip,
            str(internal_port), str(external_port),
            protocol, '0', description
        ])

    def remove_mapping(self, external_port: int, protocol: str) -> Tuple[bool, str]:
        """Remove a UPnP port mapping."""
        protocol = protocol.upper()
        return self._run(['-d', str(external_port), protocol])

    def get_external_ip(self) -> Tuple[bool, str]:
        """Get the external IP via UPnP."""
        success, output = self._run(['-e'])
        if success:
            # Parse "ExternalIPAddress = x.x.x.x" from output
            for line in output.splitlines():
                if 'ExternalIPAddress' in line:
                    parts = line.split('=')
                    if len(parts) >= 2:
                        return True, parts[-1].strip()
            # If no specific line found, return raw output
            return True, output
        return False, output

    def refresh_all(self) -> List[Dict]:
        """Re-add all configured port mappings. Returns list of results."""
        mappings = self.load_mappings_from_config()
        internal_ip = self._get_internal_ip()
        results = []

        for mapping in mappings:
            port = mapping['port']
            proto = mapping['protocol']
            desc = mapping.get('description', 'AUTARCH')
            success, output = self.add_mapping(
                internal_ip, port, port, proto, desc
            )
            results.append({
                'port': port,
                'protocol': proto,
                'success': success,
                'message': output
            })

        return results

    def _get_internal_ip(self) -> str:
        """Get the configured internal IP."""
        if self.config:
            return self.config.get('upnp', 'internal_ip', fallback='10.0.0.26')
        return '10.0.0.26'

    def load_mappings_from_config(self) -> List[Dict]:
        """Load port mappings from config file.

        Config format: mappings = 443:TCP,51820:UDP,8080:TCP
        """
        if not self.config:
            return []

        mappings_str = self.config.get('upnp', 'mappings', fallback='')
        if not mappings_str:
            return []

        mappings = []
        for entry in mappings_str.split(','):
            entry = entry.strip()
            if ':' in entry:
                parts = entry.split(':')
                try:
                    mappings.append({
                        'port': int(parts[0]),
                        'protocol': parts[1].upper()
                    })
                except (ValueError, IndexError):
                    continue
        return mappings

    def save_mappings_to_config(self, mappings: List[Dict]):
        """Save port mappings to config file."""
        if not self.config:
            return

        mappings_str = ','.join(
            f"{m['port']}:{m['protocol']}" for m in mappings
        )
        self.config.set('upnp', 'mappings', mappings_str)
        self.config.save()

    # --- Cron Management ---

    def _get_autarch_path(self) -> str:
        """Get the path to autarch.py."""
        from core.paths import get_app_dir
        return str(get_app_dir() / 'autarch.py')

    def _get_cron_command(self) -> str:
        """Get the cron command string for UPnP refresh."""
        autarch_path = self._get_autarch_path()
        return f'/usr/bin/python3 {autarch_path} --upnp-refresh > /dev/null 2>&1'

    def get_cron_status(self) -> Dict:
        """Check if UPnP cron job is installed.

        Returns:
            Dict with 'installed' (bool), 'interval' (str), 'line' (str)
        """
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return {'installed': False, 'interval': None, 'line': None}

            for line in result.stdout.splitlines():
                if 'upnp-refresh' in line and not line.startswith('#'):
                    # Parse interval from cron expression
                    match = re.match(r'^\d+\s+\*/(\d+)', line)
                    interval = match.group(1) if match else '?'
                    return {
                        'installed': True,
                        'interval': f'{interval}h',
                        'line': line.strip()
                    }

            return {'installed': False, 'interval': None, 'line': None}
        except Exception:
            return {'installed': False, 'interval': None, 'line': None}

    def install_cron(self, interval_hours: int = 12) -> Tuple[bool, str]:
        """Install a crontab entry for periodic UPnP refresh.

        Args:
            interval_hours: How often to refresh (in hours)
        """
        # First remove any existing entry
        self.uninstall_cron()

        cron_line = f'0 */{interval_hours} * * * {self._get_cron_command()}'

        try:
            # Get current crontab
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True, text=True, timeout=5
            )
            existing = result.stdout if result.returncode == 0 else ''

            # Append new entry
            new_crontab = existing.rstrip('\n') + '\n' + cron_line + '\n'

            # Install
            proc = subprocess.run(
                ['crontab', '-'],
                input=new_crontab, capture_output=True, text=True, timeout=5
            )

            if proc.returncode == 0:
                # Save interval to config
                if self.config:
                    self.config.set('upnp', 'refresh_hours', str(interval_hours))
                    self.config.save()
                return True, f"Cron job installed: every {interval_hours} hours"
            else:
                return False, proc.stderr
        except Exception as e:
            return False, str(e)

    def uninstall_cron(self) -> Tuple[bool, str]:
        """Remove the UPnP refresh cron job."""
        try:
            result = subprocess.run(
                ['crontab', '-l'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return True, "No crontab exists"

            # Filter out our line
            lines = result.stdout.splitlines()
            filtered = [l for l in lines if 'upnp-refresh' not in l]

            if len(lines) == len(filtered):
                return True, "No UPnP cron job found"

            new_crontab = '\n'.join(filtered) + '\n'

            proc = subprocess.run(
                ['crontab', '-'],
                input=new_crontab, capture_output=True, text=True, timeout=5
            )

            if proc.returncode == 0:
                return True, "Cron job removed"
            else:
                return False, proc.stderr
        except Exception as e:
            return False, str(e)


# Singleton
_upnp_manager = None


def get_upnp_manager(config=None) -> UPnPManager:
    """Get the global UPnP manager instance."""
    global _upnp_manager
    if _upnp_manager is None:
        if config is None:
            from core.config import get_config
            config = get_config()
        _upnp_manager = UPnPManager(config)
    return _upnp_manager
