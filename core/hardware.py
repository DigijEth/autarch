"""
AUTARCH Hardware Manager
ADB/Fastboot device management and ESP32 serial flashing.

Provides server-side access to USB-connected devices:
- ADB: Android device shell, sideload, push/pull, logcat
- Fastboot: Partition flashing, OEM unlock, device info
- Serial/ESP32: Port detection, chip ID, firmware flash, serial monitor
"""

import os
import re
import json
import time
import subprocess
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable

from core.paths import find_tool, get_data_dir

# Try importing serial
PYSERIAL_AVAILABLE = False
try:
    import serial
    import serial.tools.list_ports
    PYSERIAL_AVAILABLE = True
except ImportError:
    pass

# Try importing esptool
ESPTOOL_AVAILABLE = False
try:
    import esptool
    ESPTOOL_AVAILABLE = True
except ImportError:
    pass


class HardwareManager:
    """Manages ADB, Fastboot, and Serial/ESP32 devices."""

    def __init__(self):
        # Tool paths - find_tool checks system PATH first, then bundled
        self.adb_path = find_tool('adb')
        self.fastboot_path = find_tool('fastboot')

        # Data directory
        self._data_dir = get_data_dir() / 'hardware'
        self._data_dir.mkdir(parents=True, exist_ok=True)

        # Serial monitor state
        self._monitor_thread = None
        self._monitor_running = False
        self._monitor_serial = None
        self._monitor_buffer = []
        self._monitor_lock = threading.Lock()

        # Flash/sideload progress state
        self._operation_progress = {}
        self._operation_lock = threading.Lock()

    # ── Status ──────────────────────────────────────────────────────

    def get_status(self):
        """Get availability status of all backends."""
        return {
            'adb': self.adb_path is not None,
            'adb_path': self.adb_path or '',
            'fastboot': self.fastboot_path is not None,
            'fastboot_path': self.fastboot_path or '',
            'serial': PYSERIAL_AVAILABLE,
            'esptool': ESPTOOL_AVAILABLE,
        }

    # ── ADB Methods ────────────────────────────────────────────────

    def _run_adb(self, args, serial=None, timeout=30):
        """Run an adb command and return (stdout, stderr, returncode)."""
        if not self.adb_path:
            return '', 'adb not found', 1
        cmd = [self.adb_path]
        if serial:
            cmd += ['-s', serial]
        cmd += args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Command timed out', 1
        except Exception as e:
            return '', str(e), 1

    def adb_devices(self):
        """List connected ADB devices."""
        stdout, stderr, rc = self._run_adb(['devices', '-l'])
        if rc != 0:
            return []
        devices = []
        for line in stdout.strip().split('\n')[1:]:
            line = line.strip()
            if not line or 'List of' in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            dev = {
                'serial': parts[0],
                'state': parts[1],
                'model': '',
                'product': '',
                'transport_id': '',
            }
            for part in parts[2:]:
                if ':' in part:
                    key, val = part.split(':', 1)
                    if key == 'model':
                        dev['model'] = val
                    elif key == 'product':
                        dev['product'] = val
                    elif key == 'transport_id':
                        dev['transport_id'] = val
                    elif key == 'device':
                        dev['device'] = val
            devices.append(dev)
        return devices

    def adb_device_info(self, serial):
        """Get detailed info about an ADB device."""
        props = {}
        prop_keys = {
            'ro.product.model': 'model',
            'ro.product.brand': 'brand',
            'ro.product.name': 'product',
            'ro.build.version.release': 'android_version',
            'ro.build.version.sdk': 'sdk',
            'ro.build.display.id': 'build',
            'ro.build.version.security_patch': 'security_patch',
            'ro.product.cpu.abi': 'cpu_abi',
            'ro.serialno': 'serialno',
            'ro.bootimage.build.date': 'build_date',
        }
        # Get all properties at once
        stdout, _, rc = self._run_adb(['shell', 'getprop'], serial=serial)
        if rc == 0:
            for line in stdout.split('\n'):
                m = re.match(r'\[(.+?)\]:\s*\[(.+?)\]', line)
                if m:
                    key, val = m.group(1), m.group(2)
                    if key in prop_keys:
                        props[prop_keys[key]] = val

        # Battery level
        stdout, _, rc = self._run_adb(['shell', 'dumpsys', 'battery'], serial=serial)
        if rc == 0:
            for line in stdout.split('\n'):
                line = line.strip()
                if line.startswith('level:'):
                    props['battery'] = line.split(':')[1].strip()
                elif line.startswith('status:'):
                    status_map = {'2': 'Charging', '3': 'Discharging', '4': 'Not charging', '5': 'Full'}
                    val = line.split(':')[1].strip()
                    props['battery_status'] = status_map.get(val, val)

        # Storage
        stdout, _, rc = self._run_adb(['shell', 'df', '/data'], serial=serial, timeout=10)
        if rc == 0:
            lines = stdout.strip().split('\n')
            if len(lines) >= 2:
                parts = lines[1].split()
                if len(parts) >= 4:
                    props['storage_total'] = parts[1]
                    props['storage_used'] = parts[2]
                    props['storage_free'] = parts[3]

        props['serial'] = serial
        return props

    def adb_shell(self, serial, command):
        """Run a shell command on an ADB device."""
        # Sanitize: block dangerous commands
        dangerous = ['rm -rf /', 'mkfs', 'dd if=/dev/zero', 'format', '> /dev/', 'reboot']
        cmd_lower = command.lower().strip()
        for d in dangerous:
            if d in cmd_lower:
                return {'output': f'Blocked dangerous command: {d}', 'returncode': 1}

        stdout, stderr, rc = self._run_adb(['shell', command], serial=serial, timeout=30)
        return {
            'output': stdout or stderr,
            'returncode': rc,
        }

    def adb_shell_raw(self, serial, command, timeout=30):
        """Run shell command without safety filter. For exploit modules."""
        stdout, stderr, rc = self._run_adb(['shell', command], serial=serial, timeout=timeout)
        return {'output': stdout or stderr, 'returncode': rc}

    def adb_reboot(self, serial, mode='system'):
        """Reboot an ADB device. mode: system, recovery, bootloader"""
        args = ['reboot']
        if mode and mode != 'system':
            args.append(mode)
        stdout, stderr, rc = self._run_adb(args, serial=serial, timeout=15)
        return {'success': rc == 0, 'output': stdout or stderr}

    def adb_install(self, serial, apk_path):
        """Install an APK on device."""
        if not os.path.isfile(apk_path):
            return {'success': False, 'error': f'File not found: {apk_path}'}
        stdout, stderr, rc = self._run_adb(
            ['install', '-r', apk_path], serial=serial, timeout=120
        )
        return {'success': rc == 0, 'output': stdout or stderr}

    def adb_sideload(self, serial, filepath):
        """Sideload a file (APK/ZIP). Returns operation ID for progress tracking."""
        if not os.path.isfile(filepath):
            return {'success': False, 'error': f'File not found: {filepath}'}

        op_id = f'sideload_{int(time.time())}'
        with self._operation_lock:
            self._operation_progress[op_id] = {
                'status': 'starting', 'progress': 0, 'message': 'Starting sideload...'
            }

        def _do_sideload():
            try:
                ext = os.path.splitext(filepath)[1].lower()
                if ext == '.apk':
                    cmd = [self.adb_path, '-s', serial, 'install', '-r', filepath]
                else:
                    cmd = [self.adb_path, '-s', serial, 'sideload', filepath]

                with self._operation_lock:
                    self._operation_progress[op_id]['status'] = 'running'
                    self._operation_progress[op_id]['progress'] = 10
                    self._operation_progress[op_id]['message'] = 'Transferring...'

                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

                with self._operation_lock:
                    if result.returncode == 0:
                        self._operation_progress[op_id] = {
                            'status': 'done', 'progress': 100,
                            'message': 'Sideload complete',
                            'output': result.stdout,
                        }
                    else:
                        self._operation_progress[op_id] = {
                            'status': 'error', 'progress': 0,
                            'message': result.stderr or 'Sideload failed',
                        }
            except Exception as e:
                with self._operation_lock:
                    self._operation_progress[op_id] = {
                        'status': 'error', 'progress': 0, 'message': str(e),
                    }

        thread = threading.Thread(target=_do_sideload, daemon=True)
        thread.start()
        return {'success': True, 'op_id': op_id}

    def adb_push(self, serial, local_path, remote_path):
        """Push a file to device."""
        if not os.path.isfile(local_path):
            return {'success': False, 'error': f'File not found: {local_path}'}
        stdout, stderr, rc = self._run_adb(
            ['push', local_path, remote_path], serial=serial, timeout=120
        )
        return {'success': rc == 0, 'output': stdout or stderr}

    def adb_pull(self, serial, remote_path, local_path=None):
        """Pull a file from device."""
        if not local_path:
            local_path = str(self._data_dir / os.path.basename(remote_path))
        stdout, stderr, rc = self._run_adb(
            ['pull', remote_path, local_path], serial=serial, timeout=120
        )
        return {'success': rc == 0, 'output': stdout or stderr, 'local_path': local_path}

    def adb_logcat(self, serial, lines=100):
        """Get last N lines of logcat."""
        stdout, stderr, rc = self._run_adb(
            ['logcat', '-d', '-t', str(lines)], serial=serial, timeout=15
        )
        return {'output': stdout or stderr, 'lines': lines}

    # ── Fastboot Methods ───────────────────────────────────────────

    def _run_fastboot(self, args, serial=None, timeout=30):
        """Run a fastboot command."""
        if not self.fastboot_path:
            return '', 'fastboot not found', 1
        cmd = [self.fastboot_path]
        if serial:
            cmd += ['-s', serial]
        cmd += args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            # fastboot outputs to stderr for many commands
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return '', 'Command timed out', 1
        except Exception as e:
            return '', str(e), 1

    def fastboot_devices(self):
        """List fastboot devices."""
        stdout, stderr, rc = self._run_fastboot(['devices'])
        if rc != 0:
            return []
        devices = []
        output = stdout or stderr
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                devices.append({
                    'serial': parts[0].strip(),
                    'state': parts[1].strip(),
                })
        return devices

    def fastboot_device_info(self, serial):
        """Get fastboot device variables."""
        info = {}
        vars_to_get = [
            'product', 'variant', 'serialno', 'secure', 'unlocked',
            'is-userspace', 'hw-revision', 'battery-level',
            'current-slot', 'slot-count',
        ]
        for var in vars_to_get:
            stdout, stderr, rc = self._run_fastboot(
                ['getvar', var], serial=serial, timeout=10
            )
            output = stderr or stdout  # fastboot puts getvar in stderr
            for line in output.split('\n'):
                if line.startswith(f'{var}:'):
                    info[var] = line.split(':', 1)[1].strip()
                    break
        info['serial'] = serial
        return info

    def fastboot_flash(self, serial, partition, filepath):
        """Flash a partition. Returns operation ID for progress tracking."""
        if not os.path.isfile(filepath):
            return {'success': False, 'error': f'File not found: {filepath}'}

        valid_partitions = [
            'boot', 'recovery', 'system', 'vendor', 'vbmeta', 'dtbo',
            'radio', 'bootloader', 'super', 'userdata', 'cache',
            'product', 'system_ext', 'vendor_boot', 'init_boot',
        ]
        if partition not in valid_partitions:
            return {'success': False, 'error': f'Invalid partition: {partition}'}

        op_id = f'flash_{int(time.time())}'
        with self._operation_lock:
            self._operation_progress[op_id] = {
                'status': 'starting', 'progress': 0,
                'message': f'Flashing {partition}...',
            }

        def _do_flash():
            try:
                with self._operation_lock:
                    self._operation_progress[op_id]['status'] = 'running'
                    self._operation_progress[op_id]['progress'] = 10

                result = subprocess.run(
                    [self.fastboot_path, '-s', serial, 'flash', partition, filepath],
                    capture_output=True, text=True, timeout=600,
                )

                with self._operation_lock:
                    output = result.stderr or result.stdout
                    if result.returncode == 0:
                        self._operation_progress[op_id] = {
                            'status': 'done', 'progress': 100,
                            'message': f'Flashed {partition} successfully',
                            'output': output,
                        }
                    else:
                        self._operation_progress[op_id] = {
                            'status': 'error', 'progress': 0,
                            'message': output or 'Flash failed',
                        }
            except Exception as e:
                with self._operation_lock:
                    self._operation_progress[op_id] = {
                        'status': 'error', 'progress': 0, 'message': str(e),
                    }

        thread = threading.Thread(target=_do_flash, daemon=True)
        thread.start()
        return {'success': True, 'op_id': op_id}

    def fastboot_reboot(self, serial, mode='system'):
        """Reboot a fastboot device. mode: system, bootloader, recovery"""
        if mode == 'system':
            args = ['reboot']
        elif mode == 'bootloader':
            args = ['reboot-bootloader']
        elif mode == 'recovery':
            args = ['reboot', 'recovery']
        else:
            args = ['reboot']
        stdout, stderr, rc = self._run_fastboot(args, serial=serial, timeout=15)
        return {'success': rc == 0, 'output': stderr or stdout}

    def fastboot_oem_unlock(self, serial):
        """OEM unlock (requires user confirmation in UI)."""
        stdout, stderr, rc = self._run_fastboot(
            ['flashing', 'unlock'], serial=serial, timeout=30
        )
        return {'success': rc == 0, 'output': stderr or stdout}

    def get_operation_progress(self, op_id):
        """Get progress for a running operation."""
        with self._operation_lock:
            return self._operation_progress.get(op_id, {
                'status': 'unknown', 'progress': 0, 'message': 'Unknown operation',
            })

    # ── Serial / ESP32 Methods ─────────────────────────────────────

    def list_serial_ports(self):
        """List available serial ports."""
        if not PYSERIAL_AVAILABLE:
            return []
        ports = []
        for port in serial.tools.list_ports.comports():
            ports.append({
                'port': port.device,
                'desc': port.description,
                'hwid': port.hwid,
                'vid': f'{port.vid:04x}' if port.vid else '',
                'pid': f'{port.pid:04x}' if port.pid else '',
                'manufacturer': port.manufacturer or '',
                'serial_number': port.serial_number or '',
            })
        return ports

    def detect_esp_chip(self, port, baud=115200):
        """Detect ESP chip type using esptool."""
        if not ESPTOOL_AVAILABLE:
            return {'success': False, 'error': 'esptool not installed'}
        try:
            result = subprocess.run(
                ['python3', '-m', 'esptool', '--port', port, '--baud', str(baud), 'chip_id'],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout + result.stderr
            chip = 'Unknown'
            chip_id = ''
            for line in output.split('\n'):
                if 'Chip is' in line:
                    chip = line.split('Chip is')[1].strip()
                elif 'Chip ID:' in line:
                    chip_id = line.split('Chip ID:')[1].strip()
            return {
                'success': result.returncode == 0,
                'chip': chip,
                'chip_id': chip_id,
                'output': output,
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'Detection timed out'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def flash_esp(self, port, firmware_path, baud=460800):
        """Flash ESP32 firmware. Returns operation ID for progress tracking."""
        if not ESPTOOL_AVAILABLE:
            return {'success': False, 'error': 'esptool not installed'}
        if not os.path.isfile(firmware_path):
            return {'success': False, 'error': f'File not found: {firmware_path}'}

        op_id = f'esp_flash_{int(time.time())}'
        with self._operation_lock:
            self._operation_progress[op_id] = {
                'status': 'starting', 'progress': 0,
                'message': 'Starting ESP flash...',
            }

        def _do_flash():
            try:
                with self._operation_lock:
                    self._operation_progress[op_id]['status'] = 'running'
                    self._operation_progress[op_id]['progress'] = 5
                    self._operation_progress[op_id]['message'] = 'Connecting to chip...'

                cmd = [
                    'python3', '-m', 'esptool',
                    '--port', port,
                    '--baud', str(baud),
                    'write_flash', '0x0', firmware_path,
                ]
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                )

                output_lines = []
                for line in proc.stdout:
                    line = line.strip()
                    output_lines.append(line)

                    # Parse progress from esptool output
                    if 'Writing at' in line and '%' in line:
                        m = re.search(r'\((\d+)\s*%\)', line)
                        if m:
                            pct = int(m.group(1))
                            with self._operation_lock:
                                self._operation_progress[op_id]['progress'] = pct
                                self._operation_progress[op_id]['message'] = f'Flashing... {pct}%'
                    elif 'Connecting' in line:
                        with self._operation_lock:
                            self._operation_progress[op_id]['message'] = 'Connecting...'
                    elif 'Erasing' in line:
                        with self._operation_lock:
                            self._operation_progress[op_id]['progress'] = 3
                            self._operation_progress[op_id]['message'] = 'Erasing flash...'

                proc.wait(timeout=300)
                output = '\n'.join(output_lines)

                with self._operation_lock:
                    if proc.returncode == 0:
                        self._operation_progress[op_id] = {
                            'status': 'done', 'progress': 100,
                            'message': 'Flash complete',
                            'output': output,
                        }
                    else:
                        self._operation_progress[op_id] = {
                            'status': 'error', 'progress': 0,
                            'message': output or 'Flash failed',
                        }
            except Exception as e:
                with self._operation_lock:
                    self._operation_progress[op_id] = {
                        'status': 'error', 'progress': 0, 'message': str(e),
                    }

        thread = threading.Thread(target=_do_flash, daemon=True)
        thread.start()
        return {'success': True, 'op_id': op_id}

    # ── Serial Monitor ─────────────────────────────────────────────

    def serial_monitor_start(self, port, baud=115200):
        """Start serial monitor on a port."""
        if not PYSERIAL_AVAILABLE:
            return {'success': False, 'error': 'pyserial not installed'}
        if self._monitor_running:
            return {'success': False, 'error': 'Monitor already running'}

        try:
            self._monitor_serial = serial.Serial(port, baud, timeout=0.1)
        except Exception as e:
            return {'success': False, 'error': str(e)}

        self._monitor_running = True
        self._monitor_buffer = []

        def _read_loop():
            while self._monitor_running and self._monitor_serial and self._monitor_serial.is_open:
                try:
                    data = self._monitor_serial.readline()
                    if data:
                        text = data.decode('utf-8', errors='replace').rstrip()
                        with self._monitor_lock:
                            self._monitor_buffer.append({
                                'time': time.time(),
                                'data': text,
                            })
                            # Keep buffer manageable
                            if len(self._monitor_buffer) > 5000:
                                self._monitor_buffer = self._monitor_buffer[-3000:]
                except Exception:
                    if not self._monitor_running:
                        break
                    time.sleep(0.1)

        self._monitor_thread = threading.Thread(target=_read_loop, daemon=True)
        self._monitor_thread.start()
        return {'success': True, 'port': port, 'baud': baud}

    def serial_monitor_stop(self):
        """Stop serial monitor."""
        self._monitor_running = False
        if self._monitor_serial and self._monitor_serial.is_open:
            try:
                self._monitor_serial.close()
            except Exception:
                pass
        self._monitor_serial = None
        return {'success': True}

    def serial_monitor_send(self, data):
        """Send data to the monitored serial port."""
        if not self._monitor_running or not self._monitor_serial:
            return {'success': False, 'error': 'Monitor not running'}
        try:
            self._monitor_serial.write((data + '\n').encode('utf-8'))
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def serial_monitor_get_output(self, since_index=0):
        """Get buffered serial output since given index."""
        with self._monitor_lock:
            data = self._monitor_buffer[since_index:]
            return {
                'lines': data,
                'total': len(self._monitor_buffer),
                'running': self._monitor_running,
            }

    @property
    def monitor_running(self):
        return self._monitor_running


# ── Singleton ──────────────────────────────────────────────────────

_manager = None

def get_hardware_manager():
    global _manager
    if _manager is None:
        _manager = HardwareManager()
    return _manager
