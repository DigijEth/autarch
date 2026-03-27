"""AUTARCH BLE Scanner

Bluetooth Low Energy device discovery, service enumeration, characteristic
read/write, vulnerability scanning, and proximity tracking.
"""

DESCRIPTION = "BLE device scanning & security analysis"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

# Optional BLE library
try:
    import asyncio
    from bleak import BleakScanner, BleakClient
    HAS_BLEAK = True
except ImportError:
    HAS_BLEAK = False


# ── Known Service UUIDs ──────────────────────────────────────────────────────

KNOWN_SERVICES = {
    '00001800-0000-1000-8000-00805f9b34fb': 'Generic Access',
    '00001801-0000-1000-8000-00805f9b34fb': 'Generic Attribute',
    '0000180a-0000-1000-8000-00805f9b34fb': 'Device Information',
    '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service',
    '00001812-0000-1000-8000-00805f9b34fb': 'Human Interface Device',
    '0000180d-0000-1000-8000-00805f9b34fb': 'Heart Rate',
    '00001809-0000-1000-8000-00805f9b34fb': 'Health Thermometer',
    '00001802-0000-1000-8000-00805f9b34fb': 'Immediate Alert',
    '00001803-0000-1000-8000-00805f9b34fb': 'Link Loss',
    '00001804-0000-1000-8000-00805f9b34fb': 'Tx Power',
    '00001805-0000-1000-8000-00805f9b34fb': 'Current Time',
    '00001808-0000-1000-8000-00805f9b34fb': 'Glucose',
    '00001810-0000-1000-8000-00805f9b34fb': 'Blood Pressure',
    '00001813-0000-1000-8000-00805f9b34fb': 'Scan Parameters',
    '00001816-0000-1000-8000-00805f9b34fb': 'Cycling Speed & Cadence',
    '00001818-0000-1000-8000-00805f9b34fb': 'Cycling Power',
    '00001814-0000-1000-8000-00805f9b34fb': 'Running Speed & Cadence',
    '0000fee0-0000-1000-8000-00805f9b34fb': 'Mi Band Service',
    '0000feaa-0000-1000-8000-00805f9b34fb': 'Eddystone (Google)',
}

MANUFACTURER_IDS = {
    0x004C: 'Apple',
    0x0006: 'Microsoft',
    0x000F: 'Texas Instruments',
    0x0059: 'Nordic Semiconductor',
    0x0075: 'Samsung',
    0x00E0: 'Google',
    0x0157: 'Xiaomi',
    0x0171: 'Amazon',
    0x02FF: 'Huawei',
    0x0310: 'Fitbit',
}

KNOWN_VULNS = {
    'KNOB': {
        'description': 'Key Negotiation of Bluetooth Attack — downgrades encryption key entropy',
        'cve': 'CVE-2019-9506',
        'severity': 'high',
        'check': 'Requires active MITM during pairing'
    },
    'BLESA': {
        'description': 'BLE Spoofing Attack — reconnection spoofing without auth',
        'cve': 'CVE-2020-9770',
        'severity': 'medium',
        'check': 'Affects reconnection after disconnect'
    },
    'SweynTooth': {
        'description': 'Family of BLE implementation bugs causing crashes/deadlocks',
        'cve': 'Multiple (CVE-2019-16336, CVE-2019-17519, etc.)',
        'severity': 'high',
        'check': 'Vendor-specific, requires firmware version check'
    },
    'BlueBorne': {
        'description': 'Remote code execution via Bluetooth without pairing',
        'cve': 'CVE-2017-0781 to CVE-2017-0785',
        'severity': 'critical',
        'check': 'Requires classic BT stack, pre-2018 devices vulnerable'
    }
}


# ── BLE Scanner ──────────────────────────────────────────────────────────────

class BLEScanner:
    """Bluetooth Low Energy device scanner and analyzer."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'ble')
        os.makedirs(self.data_dir, exist_ok=True)
        self.devices: Dict[str, Dict] = {}
        self.tracking_history: Dict[str, List[Dict]] = {}
        self._scan_running = False

    def is_available(self) -> bool:
        """Check if BLE scanning is available."""
        return HAS_BLEAK

    def get_status(self) -> Dict:
        """Get scanner status."""
        return {
            'available': HAS_BLEAK,
            'devices_found': len(self.devices),
            'scanning': self._scan_running,
            'tracking': len(self.tracking_history)
        }

    # ── Scanning ─────────────────────────────────────────────────────────

    def scan(self, duration: float = 10.0) -> Dict:
        """Scan for BLE devices."""
        if not HAS_BLEAK:
            return {'ok': False, 'error': 'bleak library not installed (pip install bleak)'}

        self._scan_running = True

        try:
            loop = asyncio.new_event_loop()
            devices = loop.run_until_complete(self._async_scan(duration))
            loop.close()

            results = []
            for dev in devices:
                info = self._parse_device(dev)
                self.devices[info['address']] = info
                results.append(info)

            self._scan_running = False
            return {
                'ok': True,
                'devices': results,
                'count': len(results),
                'duration': duration
            }

        except Exception as e:
            self._scan_running = False
            return {'ok': False, 'error': str(e)}

    async def _async_scan(self, duration: float):
        """Async BLE scan."""
        devices = await BleakScanner.discover(timeout=duration, return_adv=True)
        return devices

    def _parse_device(self, dev_adv) -> Dict:
        """Parse BLE device advertisement data."""
        if isinstance(dev_adv, tuple):
            dev, adv = dev_adv
        else:
            dev = dev_adv
            adv = None

        info = {
            'address': str(dev.address) if hasattr(dev, 'address') else str(dev),
            'name': dev.name if hasattr(dev, 'name') else 'Unknown',
            'rssi': dev.rssi if hasattr(dev, 'rssi') else (adv.rssi if adv and hasattr(adv, 'rssi') else 0),
            'services': [],
            'manufacturer': 'Unknown',
            'device_type': 'unknown',
            'connectable': True,
            'last_seen': datetime.now(timezone.utc).isoformat(),
        }

        # Parse advertisement data
        if adv:
            # Service UUIDs
            if hasattr(adv, 'service_uuids'):
                for uuid in adv.service_uuids:
                    service_name = KNOWN_SERVICES.get(uuid.lower(), uuid)
                    info['services'].append({'uuid': uuid, 'name': service_name})

            # Manufacturer data
            if hasattr(adv, 'manufacturer_data'):
                for company_id, data in adv.manufacturer_data.items():
                    info['manufacturer'] = MANUFACTURER_IDS.get(company_id, f'ID: {company_id:#06x}')
                    info['manufacturer_data'] = data.hex() if isinstance(data, bytes) else str(data)

            # TX Power
            if hasattr(adv, 'tx_power'):
                info['tx_power'] = adv.tx_power

        # Classify device type
        info['device_type'] = self._classify_device(info)

        return info

    def _classify_device(self, info: Dict) -> str:
        """Classify device type from services and name."""
        name = (info.get('name') or '').lower()
        services = [s['uuid'].lower() for s in info.get('services', [])]

        if any('1812' in s for s in services):
            return 'hid'  # keyboard/mouse
        if any('180d' in s for s in services):
            return 'fitness'
        if any('180f' in s for s in services):
            if 'headphone' in name or 'airpod' in name or 'buds' in name:
                return 'audio'
        if any('fee0' in s for s in services):
            return 'wearable'
        if info.get('manufacturer') == 'Apple':
            if 'watch' in name:
                return 'wearable'
            if 'airpod' in name:
                return 'audio'
            return 'apple_device'
        if 'tv' in name or 'chromecast' in name or 'roku' in name:
            return 'media'
        if 'lock' in name or 'door' in name:
            return 'smart_lock'
        if 'light' in name or 'bulb' in name or 'hue' in name:
            return 'smart_light'
        if 'beacon' in name or any('feaa' in s for s in services):
            return 'beacon'
        if 'tile' in name or 'airtag' in name or 'tracker' in name:
            return 'tracker'
        return 'unknown'

    # ── Device Detail ────────────────────────────────────────────────────

    def get_device_detail(self, address: str) -> Dict:
        """Connect to device and enumerate services/characteristics."""
        if not HAS_BLEAK:
            return {'ok': False, 'error': 'bleak not installed'}

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self._async_detail(address))
            loop.close()
            return result
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    async def _async_detail(self, address: str) -> Dict:
        """Async device detail enumeration."""
        async with BleakClient(address) as client:
            services = []
            for service in client.services:
                svc = {
                    'uuid': service.uuid,
                    'name': KNOWN_SERVICES.get(service.uuid.lower(), service.description or service.uuid),
                    'characteristics': []
                }
                for char in service.characteristics:
                    ch = {
                        'uuid': char.uuid,
                        'description': char.description or char.uuid,
                        'properties': char.properties,
                        'value': None
                    }
                    # Try to read if readable
                    if 'read' in char.properties:
                        try:
                            val = await client.read_gatt_char(char.uuid)
                            ch['value'] = val.hex() if isinstance(val, bytes) else str(val)
                            # Try UTF-8 decode
                            try:
                                ch['value_text'] = val.decode('utf-8')
                            except (UnicodeDecodeError, AttributeError):
                                pass
                        except Exception:
                            ch['value'] = '<read failed>'

                    svc['characteristics'].append(ch)
                services.append(svc)

            return {
                'ok': True,
                'address': address,
                'connected': True,
                'services': services,
                'service_count': len(services),
                'char_count': sum(len(s['characteristics']) for s in services)
            }

    def read_characteristic(self, address: str, char_uuid: str) -> Dict:
        """Read a specific characteristic value."""
        if not HAS_BLEAK:
            return {'ok': False, 'error': 'bleak not installed'}

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self._async_read(address, char_uuid))
            loop.close()
            return result
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    async def _async_read(self, address: str, char_uuid: str) -> Dict:
        async with BleakClient(address) as client:
            val = await client.read_gatt_char(char_uuid)
            return {
                'ok': True,
                'address': address,
                'characteristic': char_uuid,
                'value_hex': val.hex(),
                'value_bytes': list(val),
                'size': len(val)
            }

    def write_characteristic(self, address: str, char_uuid: str,
                              data: bytes) -> Dict:
        """Write to a characteristic."""
        if not HAS_BLEAK:
            return {'ok': False, 'error': 'bleak not installed'}

        try:
            loop = asyncio.new_event_loop()
            result = loop.run_until_complete(self._async_write(address, char_uuid, data))
            loop.close()
            return result
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    async def _async_write(self, address: str, char_uuid: str, data: bytes) -> Dict:
        async with BleakClient(address) as client:
            await client.write_gatt_char(char_uuid, data)
            return {'ok': True, 'address': address, 'characteristic': char_uuid,
                    'written': len(data)}

    # ── Vulnerability Scanning ───────────────────────────────────────────

    def vuln_scan(self, address: str = None) -> Dict:
        """Check for known BLE vulnerabilities."""
        vulns = []

        for vuln_name, vuln_info in KNOWN_VULNS.items():
            entry = {
                'name': vuln_name,
                'description': vuln_info['description'],
                'cve': vuln_info['cve'],
                'severity': vuln_info['severity'],
                'status': 'check_required',
                'note': vuln_info['check']
            }
            vulns.append(entry)

        # Device-specific checks
        if address and address in self.devices:
            dev = self.devices[address]
            manufacturer = dev.get('manufacturer', '')

            # Apple devices with older firmware
            if manufacturer == 'Apple':
                vulns.append({
                    'name': 'Apple BLE Tracking',
                    'description': 'Apple devices broadcast continuity messages that can be tracked',
                    'severity': 'info',
                    'status': 'detected' if 'apple_device' in dev.get('device_type', '') else 'not_applicable',
                    'note': 'Apple continuity protocol leaks device info'
                })

            # Devices without encryption
            for svc in dev.get('services', []):
                if 'immediate alert' in svc.get('name', '').lower():
                    vulns.append({
                        'name': 'Unauthenticated Alert Service',
                        'description': 'Immediate Alert service accessible without pairing',
                        'severity': 'low',
                        'status': 'detected',
                        'note': 'Can trigger alerts on device without authentication'
                    })

        return {
            'ok': True,
            'address': address,
            'vulnerabilities': vulns,
            'vuln_count': len(vulns)
        }

    # ── Proximity Tracking ───────────────────────────────────────────────

    def track_device(self, address: str) -> Dict:
        """Record RSSI for proximity tracking."""
        if address not in self.devices:
            return {'ok': False, 'error': 'Device not found. Run scan first.'}

        dev = self.devices[address]
        rssi = dev.get('rssi', 0)
        tx_power = dev.get('tx_power', -59)  # default TX power

        # Estimate distance (rough path-loss model)
        if rssi != 0:
            ratio = rssi / tx_power
            if ratio < 1.0:
                distance = pow(ratio, 10)
            else:
                distance = 0.89976 * pow(ratio, 7.7095) + 0.111
        else:
            distance = -1

        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'rssi': rssi,
            'estimated_distance_m': round(distance, 2),
            'tx_power': tx_power
        }

        if address not in self.tracking_history:
            self.tracking_history[address] = []
        self.tracking_history[address].append(entry)

        return {
            'ok': True,
            'address': address,
            'name': dev.get('name', 'Unknown'),
            'current': entry,
            'history_count': len(self.tracking_history[address])
        }

    def get_tracking_history(self, address: str) -> List[Dict]:
        """Get tracking history for a device."""
        return self.tracking_history.get(address, [])

    # ── Persistence ──────────────────────────────────────────────────────

    def save_scan(self, name: str = None) -> Dict:
        """Save current scan results."""
        name = name or f'scan_{int(time.time())}'
        filepath = os.path.join(self.data_dir, f'{name}.json')
        with open(filepath, 'w') as f:
            json.dump({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'devices': list(self.devices.values()),
                'count': len(self.devices)
            }, f, indent=2)
        return {'ok': True, 'path': filepath, 'count': len(self.devices)}

    def list_scans(self) -> List[Dict]:
        """List saved scans."""
        scans = []
        for f in Path(self.data_dir).glob('*.json'):
            try:
                with open(f) as fh:
                    data = json.load(fh)
                scans.append({
                    'name': f.stem,
                    'path': str(f),
                    'timestamp': data.get('timestamp', ''),
                    'count': data.get('count', 0)
                })
            except Exception:
                pass
        return scans

    def get_devices(self) -> List[Dict]:
        """Get all discovered devices."""
        return list(self.devices.values())


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_ble_scanner() -> BLEScanner:
    global _instance
    if _instance is None:
        _instance = BLEScanner()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for BLE Scanner module."""
    scanner = get_ble_scanner()

    while True:
        status = scanner.get_status()
        print(f"\n{'='*60}")
        print(f"  BLE Scanner  (bleak: {'OK' if status['available'] else 'MISSING'})")
        print(f"{'='*60}")
        print(f"  Devices found: {status['devices_found']}")
        print()
        print("  1 — Scan for Devices")
        print("  2 — View Devices")
        print("  3 — Device Detail (connect)")
        print("  4 — Vulnerability Scan")
        print("  5 — Track Device (proximity)")
        print("  6 — Save Scan")
        print("  7 — List Saved Scans")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            dur = input("  Scan duration (seconds, default 10): ").strip()
            result = scanner.scan(float(dur) if dur else 10.0)
            if result['ok']:
                print(f"    Found {result['count']} devices:")
                for dev in result['devices']:
                    print(f"      {dev['address']}  {dev.get('name', '?'):<20}  "
                          f"RSSI={dev['rssi']}  {dev['device_type']}  ({dev['manufacturer']})")
            else:
                print(f"    Error: {result['error']}")
        elif choice == '2':
            devices = scanner.get_devices()
            for dev in devices:
                print(f"    {dev['address']}  {dev.get('name', '?'):<20}  "
                      f"RSSI={dev['rssi']}  {dev['device_type']}")
        elif choice == '3':
            addr = input("  Device address: ").strip()
            if addr:
                result = scanner.get_device_detail(addr)
                if result['ok']:
                    print(f"    Services: {result['service_count']}  Characteristics: {result['char_count']}")
                    for svc in result['services']:
                        print(f"      [{svc['name']}]")
                        for ch in svc['characteristics']:
                            val = ch.get('value_text', ch.get('value', ''))
                            print(f"        {ch['description']}  props={ch['properties']}  val={val}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '4':
            addr = input("  Device address (blank=general): ").strip() or None
            result = scanner.vuln_scan(addr)
            for v in result['vulnerabilities']:
                print(f"    [{v['severity']:<8}] {v['name']}: {v['description'][:60]}")
        elif choice == '5':
            addr = input("  Device address: ").strip()
            if addr:
                result = scanner.track_device(addr)
                if result['ok']:
                    c = result['current']
                    print(f"    RSSI: {c['rssi']}  Distance: ~{c['estimated_distance_m']}m")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '6':
            name = input("  Scan name (blank=auto): ").strip() or None
            result = scanner.save_scan(name)
            print(f"    Saved {result['count']} devices")
        elif choice == '7':
            for s in scanner.list_scans():
                print(f"    {s['name']}  ({s['count']} devices)  {s['timestamp']}")
