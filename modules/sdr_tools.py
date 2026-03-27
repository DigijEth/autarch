"""AUTARCH SDR / RF Tools

Software-defined radio integration for spectrum analysis, signal capture/replay,
ADS-B tracking, FM/AM demodulation, and GPS spoofing detection.
Supports HackRF, RTL-SDR, and compatible devices.
"""

DESCRIPTION = "SDR/RF — spectrum analysis, signal capture & replay"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import shutil
import struct
import subprocess
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Common Frequencies Reference ─────────────────────────────────────────────

COMMON_FREQUENCIES = {
    'FM Broadcast': {
        'range': '87.5-108 MHz',
        'entries': [
            {'freq': 87500000, 'name': 'FM Band Start'},
            {'freq': 92100000, 'name': 'FM Example (92.1)'},
            {'freq': 97500000, 'name': 'FM Example (97.5)'},
            {'freq': 108000000, 'name': 'FM Band End'},
        ],
    },
    'Aviation': {
        'range': '108-137 MHz',
        'entries': [
            {'freq': 108000000, 'name': 'VOR/ILS Start'},
            {'freq': 118000000, 'name': 'Air Traffic Control Start'},
            {'freq': 121500000, 'name': 'Emergency / Guard'},
            {'freq': 123450000, 'name': 'Air-to-Air (Unicom)'},
            {'freq': 128825000, 'name': 'Eurocontrol UAC'},
            {'freq': 132000000, 'name': 'Approach Control'},
            {'freq': 136975000, 'name': 'ACARS'},
        ],
    },
    'Marine VHF': {
        'range': '156-162 MHz',
        'entries': [
            {'freq': 156000000, 'name': 'Ch 0 — Coast Guard'},
            {'freq': 156300000, 'name': 'Ch 6 — Intership Safety'},
            {'freq': 156525000, 'name': 'Ch 70 — DSC Distress'},
            {'freq': 156800000, 'name': 'Ch 16 — Distress / Calling'},
            {'freq': 161975000, 'name': 'AIS 1'},
            {'freq': 162025000, 'name': 'AIS 2'},
        ],
    },
    'Weather': {
        'range': '162.4-162.55 MHz',
        'entries': [
            {'freq': 162400000, 'name': 'NOAA WX1'},
            {'freq': 162425000, 'name': 'NOAA WX2'},
            {'freq': 162450000, 'name': 'NOAA WX3'},
            {'freq': 162475000, 'name': 'NOAA WX4'},
            {'freq': 162500000, 'name': 'NOAA WX5'},
            {'freq': 162525000, 'name': 'NOAA WX6'},
            {'freq': 162550000, 'name': 'NOAA WX7'},
        ],
    },
    'ISM 433': {
        'range': '433-434 MHz',
        'notes': 'Garage doors, key fobs, weather stations, tire pressure sensors',
        'entries': [
            {'freq': 433050000, 'name': 'ISM 433.05 — Key Fobs'},
            {'freq': 433420000, 'name': 'ISM 433.42 — TPMS'},
            {'freq': 433920000, 'name': 'ISM 433.92 — Common Remote'},
            {'freq': 434000000, 'name': 'ISM Band End'},
        ],
    },
    'ISM 915': {
        'range': '902-928 MHz',
        'notes': 'LoRa, smart meters, Z-Wave, RFID',
        'entries': [
            {'freq': 902000000, 'name': 'ISM 902 Band Start'},
            {'freq': 903900000, 'name': 'LoRa Uplink Start'},
            {'freq': 915000000, 'name': 'ISM Center'},
            {'freq': 923300000, 'name': 'LoRa Downlink Start'},
            {'freq': 928000000, 'name': 'ISM 928 Band End'},
        ],
    },
    'Pager': {
        'range': '929-932 MHz',
        'entries': [
            {'freq': 929000000, 'name': 'Pager Band Start'},
            {'freq': 931000000, 'name': 'Common Pager Freq'},
            {'freq': 931862500, 'name': 'FLEX Pager'},
        ],
    },
    'ADS-B': {
        'range': '1090 MHz',
        'entries': [
            {'freq': 978000000, 'name': 'UAT (978 MHz) — GA'},
            {'freq': 1090000000, 'name': 'Mode S Extended Squitter'},
        ],
    },
    'GPS L1': {
        'range': '1575.42 MHz',
        'entries': [
            {'freq': 1575420000, 'name': 'GPS L1 C/A'},
            {'freq': 1176450000, 'name': 'GPS L5'},
            {'freq': 1227600000, 'name': 'GPS L2'},
            {'freq': 1602000000, 'name': 'GLONASS L1'},
        ],
    },
    'WiFi 2.4': {
        'range': '2.4-2.5 GHz',
        'entries': [
            {'freq': 2412000000, 'name': 'Channel 1'},
            {'freq': 2437000000, 'name': 'Channel 6'},
            {'freq': 2462000000, 'name': 'Channel 11'},
        ],
    },
    'Public Safety': {
        'range': '150-174 / 450-470 MHz',
        'entries': [
            {'freq': 155475000, 'name': 'Police Mutual Aid'},
            {'freq': 155520000, 'name': 'Fire Mutual Aid'},
            {'freq': 156750000, 'name': 'Search & Rescue'},
            {'freq': 460025000, 'name': 'Police UHF Common'},
            {'freq': 462562500, 'name': 'FRS Channel 1'},
            {'freq': 462675000, 'name': 'GMRS Repeater'},
        ],
    },
    'Amateur': {
        'range': 'Various bands',
        'entries': [
            {'freq': 144000000, 'name': '2m Band Start'},
            {'freq': 146520000, 'name': '2m Calling Freq'},
            {'freq': 146940000, 'name': '2m Repeater'},
            {'freq': 440000000, 'name': '70cm Band Start'},
            {'freq': 446000000, 'name': '70cm Calling Freq'},
        ],
    },
}


# ── Drone RF Frequency Reference ─────────────────────────────────────────────

DRONE_FREQUENCIES = {
    'dji_control_2g': {'center': 2437000000, 'bandwidth': 40000000, 'desc': 'DJI OcuSync 2.4 GHz Control'},
    'dji_control_5g': {'center': 5787000000, 'bandwidth': 80000000, 'desc': 'DJI OcuSync 5.8 GHz Control'},
    'fpv_video_5g': {'center': 5800000000, 'bandwidth': 200000000, 'desc': 'Analog FPV 5.8 GHz Video'},
    'crossfire_900': {'center': 915000000, 'bandwidth': 26000000, 'desc': 'TBS Crossfire 900 MHz'},
    'elrs_2g': {'center': 2440000000, 'bandwidth': 80000000, 'desc': 'ExpressLRS 2.4 GHz'},
    'elrs_900': {'center': 915000000, 'bandwidth': 26000000, 'desc': 'ExpressLRS 900 MHz'},
    'analog_video_12g': {'center': 1280000000, 'bandwidth': 100000000, 'desc': '1.2 GHz Analog Video'},
    'telemetry_433': {'center': 433000000, 'bandwidth': 2000000, 'desc': '433 MHz Telemetry'},
}

FPV_5G_CHANNELS = {
    'R1': 5658, 'R2': 5695, 'R3': 5732, 'R4': 5769, 'R5': 5806, 'R6': 5843, 'R7': 5880, 'R8': 5917,
    'F1': 5740, 'F2': 5760, 'F3': 5780, 'F4': 5800, 'F5': 5820, 'F6': 5840, 'F7': 5860, 'F8': 5880,
    'E1': 5705, 'E2': 5685, 'E3': 5665, 'E4': 5645, 'E5': 5885, 'E6': 5905, 'E7': 5925, 'E8': 5945,
    'A1': 5865, 'A2': 5845, 'A3': 5825, 'A4': 5805, 'A5': 5785, 'A6': 5765, 'A7': 5745, 'A8': 5725,
}


# ── SDR Tools Class ──────────────────────────────────────────────────────────

class SDRTools:
    """Software-defined radio integration for the AUTARCH platform."""

    _instance = None

    def __init__(self):
        self._sdr_dir = Path(str(get_data_dir())) / 'sdr'
        self._sdr_dir.mkdir(parents=True, exist_ok=True)
        self._recordings_dir = self._sdr_dir / 'recordings'
        self._recordings_dir.mkdir(parents=True, exist_ok=True)
        self._metadata_file = self._sdr_dir / 'recordings_meta.json'
        self._capture_process: Optional[subprocess.Popen] = None
        self._capture_lock = threading.Lock()
        self._capture_info: Dict[str, Any] = {}
        self._adsb_process: Optional[subprocess.Popen] = None
        self._adsb_thread: Optional[threading.Thread] = None
        self._adsb_running = False
        self._adsb_aircraft: Dict[str, Dict[str, Any]] = {}
        self._adsb_lock = threading.Lock()
        # Drone detection state
        self._drone_process: Optional[subprocess.Popen] = None
        self._drone_thread: Optional[threading.Thread] = None
        self._drone_running = False
        self._drone_detections: List[Dict[str, Any]] = []
        self._drone_lock = threading.Lock()
        self._drone_detections_file = self._sdr_dir / 'drone_detections.json'
        self._load_drone_detections()
        self._load_metadata()

    def _load_metadata(self):
        """Load recording metadata from disk."""
        try:
            if self._metadata_file.exists():
                with open(self._metadata_file, 'r') as f:
                    self._metadata = json.load(f)
            else:
                self._metadata = []
        except Exception:
            self._metadata = []

    def _save_metadata(self):
        """Persist recording metadata to disk."""
        try:
            with open(self._metadata_file, 'w') as f:
                json.dump(self._metadata, f, indent=2)
        except Exception:
            pass

    def _run_cmd(self, cmd: str, timeout: int = 30) -> tuple:
        """Run a shell command and return (success, stdout)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    # ── Device Detection ─────────────────────────────────────────────────────

    def detect_devices(self) -> List[Dict[str, Any]]:
        """Detect connected SDR devices (RTL-SDR, HackRF)."""
        devices = []

        # Check RTL-SDR
        rtl_test = find_tool('rtl_test')
        if rtl_test:
            try:
                result = subprocess.run(
                    [rtl_test, '-t'],
                    capture_output=True, text=True, timeout=8
                )
                output = result.stdout + result.stderr
                # Look for "Found N device(s)" pattern
                match = re.search(r'Found\s+(\d+)\s+device', output)
                if match:
                    count = int(match.group(1))
                    if count > 0:
                        # Parse each device
                        for m in re.finditer(
                            r'(\d+):\s+(.+?)(?:,\s*(.+?))?\s*(?:SN:\s*(\S+))?',
                            output
                        ):
                            devices.append({
                                'type': 'rtl-sdr',
                                'index': int(m.group(1)),
                                'name': m.group(2).strip(),
                                'serial': m.group(4) or 'N/A',
                                'status': 'available',
                                'capabilities': ['rx'],
                            })
                        # If regex didn't match specifics, add generic entry
                        if not devices:
                            for i in range(count):
                                devices.append({
                                    'type': 'rtl-sdr',
                                    'index': i,
                                    'name': 'RTL-SDR Device',
                                    'serial': 'N/A',
                                    'status': 'available',
                                    'capabilities': ['rx'],
                                })
                elif 'No supported devices' not in output:
                    # rtl_test ran but gave unexpected output
                    pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        else:
            devices.append({
                'type': 'rtl-sdr',
                'name': 'RTL-SDR',
                'serial': 'N/A',
                'status': 'tool_missing',
                'note': 'rtl_test not found — install rtl-sdr package',
                'capabilities': [],
            })

        # Check HackRF
        hackrf_info = find_tool('hackrf_info')
        if hackrf_info:
            try:
                result = subprocess.run(
                    [hackrf_info],
                    capture_output=True, text=True, timeout=8
                )
                output = result.stdout + result.stderr
                if 'Serial number' in output:
                    serials = re.findall(r'Serial number:\s*(\S+)', output)
                    fw_versions = re.findall(r'Firmware Version:\s*(.+)', output)
                    for idx, serial in enumerate(serials):
                        devices.append({
                            'type': 'hackrf',
                            'index': idx,
                            'name': 'HackRF One',
                            'serial': serial,
                            'firmware': fw_versions[idx].strip() if idx < len(fw_versions) else 'Unknown',
                            'status': 'available',
                            'capabilities': ['rx', 'tx'],
                        })
                elif 'No HackRF' in output or result.returncode != 0:
                    pass
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
        else:
            devices.append({
                'type': 'hackrf',
                'name': 'HackRF',
                'serial': 'N/A',
                'status': 'tool_missing',
                'note': 'hackrf_info not found — install hackrf package',
                'capabilities': [],
            })

        return devices

    # ── Spectrum Scanning ────────────────────────────────────────────────────

    def scan_spectrum(self, device: str = 'rtl', freq_start: int = 88000000,
                      freq_end: int = 108000000, step: Optional[int] = None,
                      gain: Optional[int] = None, duration: int = 5) -> Dict[str, Any]:
        """Sweep a frequency range and collect signal strength at each step.

        Returns a dict with 'data' (list of {freq, power_db}) and scan metadata.
        """
        if step is None:
            # Auto-calculate step based on range
            span = freq_end - freq_start
            if span <= 1000000:
                step = 10000       # 10 kHz steps for narrow scans
            elif span <= 10000000:
                step = 100000      # 100 kHz steps
            elif span <= 100000000:
                step = 250000      # 250 kHz steps
            else:
                step = 1000000     # 1 MHz steps for wide scans

        results = {'data': [], 'device': device, 'freq_start': freq_start,
                   'freq_end': freq_end, 'step': step, 'timestamp': datetime.now(timezone.utc).isoformat()}

        if device == 'hackrf':
            return self._scan_hackrf(freq_start, freq_end, step, gain, duration, results)
        else:
            return self._scan_rtl(freq_start, freq_end, step, gain, duration, results)

    def _scan_rtl(self, freq_start, freq_end, step, gain, duration, results):
        """Spectrum scan using rtl_power."""
        rtl_power = find_tool('rtl_power')
        if not rtl_power:
            results['error'] = 'rtl_power not found — install rtl-sdr package'
            return results

        # rtl_power output file
        outfile = self._sdr_dir / 'spectrum_scan.csv'
        if outfile.exists():
            outfile.unlink()

        # Build command: rtl_power -f <start>:<end>:<step> -g <gain> -i <interval> -1 <outfile>
        cmd = [rtl_power,
               '-f', f'{freq_start}:{freq_end}:{step}',
               '-i', str(duration),
               '-1']   # single sweep
        if gain is not None:
            cmd.extend(['-g', str(gain)])
        cmd.append(str(outfile))

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=duration + 30)
            if not outfile.exists():
                results['error'] = 'No output from rtl_power: ' + (proc.stderr or proc.stdout)
                return results

            # Parse CSV: date,time,Hz_low,Hz_high,Hz_step,samples,dB,dB,...
            with open(outfile, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(',')
                    if len(parts) < 7:
                        continue
                    try:
                        hz_low = float(parts[2])
                        hz_step = float(parts[4])
                        db_values = [float(x) for x in parts[6:] if x.strip()]
                        for i, db in enumerate(db_values):
                            freq = hz_low + (i * hz_step)
                            results['data'].append({
                                'freq': int(freq),
                                'power_db': round(db, 2)
                            })
                    except (ValueError, IndexError):
                        continue

            results['points'] = len(results['data'])
        except subprocess.TimeoutExpired:
            results['error'] = 'Spectrum scan timed out'
        except Exception as e:
            results['error'] = str(e)

        return results

    def _scan_hackrf(self, freq_start, freq_end, step, gain, duration, results):
        """Spectrum scan using hackrf_sweep."""
        hackrf_sweep = find_tool('hackrf_sweep')
        if not hackrf_sweep:
            results['error'] = 'hackrf_sweep not found — install hackrf package'
            return results

        # Convert Hz to MHz for hackrf_sweep
        f_start_mhz = freq_start // 1000000
        f_end_mhz = max(freq_end // 1000000, f_start_mhz + 1)

        cmd = [hackrf_sweep,
               '-f', f'{f_start_mhz}:{f_end_mhz}',
               '-n', '8192',    # FFT bin width
               '-w', str(step)]
        if gain is not None:
            cmd.extend(['-l', str(gain)])   # LNA gain

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=duration + 30)
            output = proc.stdout
            # Parse hackrf_sweep output: date,time,Hz_low,Hz_high,Hz_bin_width,num_samples,dB...
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(',')
                if len(parts) < 7:
                    continue
                try:
                    hz_low = float(parts[2].strip())
                    hz_bin_width = float(parts[4].strip())
                    db_values = [float(x.strip()) for x in parts[6:] if x.strip()]
                    for i, db in enumerate(db_values):
                        freq = hz_low + (i * hz_bin_width)
                        if freq_start <= freq <= freq_end:
                            results['data'].append({
                                'freq': int(freq),
                                'power_db': round(db, 2)
                            })
                except (ValueError, IndexError):
                    continue

            results['points'] = len(results['data'])
        except subprocess.TimeoutExpired:
            results['error'] = 'HackRF sweep timed out'
        except Exception as e:
            results['error'] = str(e)

        return results

    # ── Signal Capture ───────────────────────────────────────────────────────

    def start_capture(self, device: str = 'rtl', frequency: int = 100000000,
                      sample_rate: int = 2048000, gain: str = 'auto',
                      duration: int = 10, output: Optional[str] = None) -> Dict[str, Any]:
        """Capture raw IQ samples to a file."""
        with self._capture_lock:
            if self._capture_process is not None and self._capture_process.poll() is None:
                return {'error': 'Capture already in progress', 'capturing': True}

            ts = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            freq_mhz = frequency / 1000000
            filename = output or f'capture_{freq_mhz:.3f}MHz_{ts}.raw'
            filepath = self._recordings_dir / filename

            if device == 'hackrf':
                tool = find_tool('hackrf_transfer')
                if not tool:
                    return {'error': 'hackrf_transfer not found — install hackrf package'}
                cmd = [tool,
                       '-r', str(filepath),
                       '-f', str(frequency),
                       '-s', str(sample_rate),
                       '-n', str(sample_rate * duration)]
                if gain != 'auto':
                    cmd.extend(['-l', str(gain)])
            else:
                tool = find_tool('rtl_sdr')
                if not tool:
                    return {'error': 'rtl_sdr not found — install rtl-sdr package'}
                cmd = [tool,
                       '-f', str(frequency),
                       '-s', str(sample_rate),
                       '-n', str(sample_rate * duration)]
                if gain != 'auto':
                    cmd.extend(['-g', str(gain)])
                cmd.append(str(filepath))

            try:
                self._capture_process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                self._capture_info = {
                    'file': str(filepath),
                    'filename': filename,
                    'device': device,
                    'frequency': frequency,
                    'sample_rate': sample_rate,
                    'gain': gain,
                    'duration': duration,
                    'started': datetime.now(timezone.utc).isoformat(),
                    'pid': self._capture_process.pid,
                }

                # Auto-stop thread
                def _auto_stop():
                    try:
                        self._capture_process.wait(timeout=duration + 5)
                    except subprocess.TimeoutExpired:
                        self._capture_process.terminate()
                    finally:
                        self._finalize_capture()

                t = threading.Thread(target=_auto_stop, daemon=True)
                t.start()

                return {
                    'status': 'capturing',
                    'file': filename,
                    'frequency': frequency,
                    'sample_rate': sample_rate,
                    'duration': duration,
                    'device': device,
                }
            except Exception as e:
                self._capture_process = None
                return {'error': f'Failed to start capture: {e}'}

    def _finalize_capture(self):
        """Save metadata for a completed capture."""
        with self._capture_lock:
            info = self._capture_info.copy()
            filepath = Path(info.get('file', ''))
            if filepath.exists():
                size = filepath.stat().st_size
                info['size'] = size
                info['size_human'] = self._human_size(size)
                # Calculate actual duration from file size
                sr = info.get('sample_rate', 2048000)
                # IQ samples: 2 bytes per sample (8-bit I + 8-bit Q) for RTL-SDR
                bytes_per_sample = 2
                actual_samples = size / bytes_per_sample
                info['actual_duration'] = round(actual_samples / sr, 2) if sr > 0 else 0
                info['completed'] = datetime.now(timezone.utc).isoformat()
                self._metadata.append(info)
                self._save_metadata()
            self._capture_process = None
            self._capture_info = {}

    def stop_capture(self) -> Dict[str, Any]:
        """Stop an active capture."""
        with self._capture_lock:
            if self._capture_process is None or self._capture_process.poll() is not None:
                return {'status': 'no_capture', 'message': 'No capture is running'}
            try:
                self._capture_process.terminate()
                self._capture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._capture_process.kill()
            except Exception:
                pass
            self._finalize_capture()
            return {'status': 'stopped', 'message': 'Capture stopped'}

    def is_capturing(self) -> bool:
        """Check if a capture is currently running."""
        with self._capture_lock:
            return (self._capture_process is not None
                    and self._capture_process.poll() is None)

    # ── Replay ───────────────────────────────────────────────────────────────

    def replay_signal(self, file_path: str, frequency: int = 100000000,
                      sample_rate: int = 2048000, gain: int = 47) -> Dict[str, Any]:
        """Transmit a captured signal via HackRF (TX only on HackRF)."""
        hackrf = find_tool('hackrf_transfer')
        if not hackrf:
            return {'error': 'hackrf_transfer not found — install hackrf package'}

        # Resolve file path
        fpath = Path(file_path)
        if not fpath.is_absolute():
            fpath = self._recordings_dir / file_path
        if not fpath.exists():
            return {'error': f'Recording file not found: {file_path}'}

        cmd = [hackrf,
               '-t', str(fpath),
               '-f', str(frequency),
               '-s', str(sample_rate),
               '-x', str(gain)]   # -x = TX VGA gain

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                return {
                    'status': 'completed',
                    'message': f'Replayed {fpath.name} at {frequency/1e6:.3f} MHz',
                    'file': fpath.name,
                    'frequency': frequency,
                }
            else:
                return {
                    'error': f'Replay failed: {result.stderr or result.stdout}',
                    'returncode': result.returncode,
                }
        except subprocess.TimeoutExpired:
            return {'error': 'Replay timed out'}
        except Exception as e:
            return {'error': str(e)}

    # ── Recordings Management ────────────────────────────────────────────────

    def list_recordings(self) -> List[Dict[str, Any]]:
        """List all saved recordings with metadata."""
        self._load_metadata()
        recordings = []
        # Include metadata-tracked recordings
        for meta in self._metadata:
            filepath = Path(meta.get('file', ''))
            if filepath.exists():
                meta_copy = meta.copy()
                meta_copy['exists'] = True
                recordings.append(meta_copy)
            else:
                meta_copy = meta.copy()
                meta_copy['exists'] = False
                recordings.append(meta_copy)

        # Also check for un-tracked files in the recordings directory
        tracked_files = {Path(m.get('file', '')).name for m in self._metadata}
        for f in self._recordings_dir.iterdir():
            if f.is_file() and f.suffix in ('.raw', '.iq', '.wav', '.cu8', '.cs8'):
                if f.name not in tracked_files:
                    stat = f.stat()
                    recordings.append({
                        'file': str(f),
                        'filename': f.name,
                        'size': stat.st_size,
                        'size_human': self._human_size(stat.st_size),
                        'device': 'unknown',
                        'frequency': 0,
                        'sample_rate': 0,
                        'completed': datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                        'exists': True,
                        'untracked': True,
                    })

        # Sort by completed time, newest first
        recordings.sort(key=lambda r: r.get('completed', ''), reverse=True)
        return recordings

    def delete_recording(self, recording_id: str) -> Dict[str, Any]:
        """Delete a recording by filename."""
        # Try to match against metadata
        self._load_metadata()
        new_meta = []
        deleted = False
        for meta in self._metadata:
            fname = Path(meta.get('file', '')).name
            if fname == recording_id or meta.get('filename') == recording_id:
                filepath = Path(meta.get('file', ''))
                if filepath.exists():
                    try:
                        filepath.unlink()
                    except Exception:
                        pass
                deleted = True
            else:
                new_meta.append(meta)

        if deleted:
            self._metadata = new_meta
            self._save_metadata()
            return {'status': 'deleted', 'file': recording_id}

        # Try direct file match in recordings directory
        fpath = self._recordings_dir / recording_id
        if fpath.exists():
            try:
                fpath.unlink()
                return {'status': 'deleted', 'file': recording_id}
            except Exception as e:
                return {'error': f'Could not delete: {e}'}

        return {'error': f'Recording not found: {recording_id}'}

    # ── Demodulation ─────────────────────────────────────────────────────────

    def demodulate_fm(self, file_path: str, frequency: Optional[int] = None) -> Dict[str, Any]:
        """FM demodulate captured IQ data to audio."""
        fpath = self._resolve_recording(file_path)
        if not fpath:
            return {'error': f'Recording file not found: {file_path}'}

        outfile = fpath.with_suffix('.fm.wav')

        # Method 1: Use rtl_fm pipeline (if file was captured with rtl_sdr)
        sox = find_tool('sox')
        rtl_fm = find_tool('rtl_fm')

        # We'll use a Python-based approach: read raw IQ, apply FM demod, write WAV
        try:
            raw = fpath.read_bytes()
            if len(raw) < 1024:
                return {'error': 'File too small to demodulate'}

            # Assume unsigned 8-bit IQ (RTL-SDR default)
            samples = []
            for i in range(0, len(raw) - 1, 2):
                i_val = (raw[i] - 127.5) / 127.5
                q_val = (raw[i + 1] - 127.5) / 127.5
                samples.append(complex(i_val, q_val))

            if len(samples) < 2:
                return {'error': 'Not enough samples for demodulation'}

            # FM demodulation: phase difference between consecutive samples
            audio = []
            for i in range(1, len(samples)):
                conj = complex(samples[i - 1].real, -samples[i - 1].imag)
                product = samples[i] * conj
                import math
                phase = math.atan2(product.imag, product.real)
                audio.append(phase)

            # Downsample to ~48 kHz audio
            # Assume 2.048 MHz sample rate → decimate by 42 for ~48.7 kHz
            decimation = 42
            decimated = [audio[i] for i in range(0, len(audio), decimation)]

            # Normalize to 16-bit PCM
            if not decimated:
                return {'error': 'Demodulation produced no audio samples'}
            max_val = max(abs(s) for s in decimated) or 1.0
            pcm = [int((s / max_val) * 32000) for s in decimated]

            # Write WAV file
            import wave
            with wave.open(str(outfile), 'w') as wav:
                wav.setnchannels(1)
                wav.setsampwidth(2)
                wav.setframerate(48000)
                wav.writeframes(struct.pack(f'<{len(pcm)}h', *pcm))

            return {
                'status': 'completed',
                'output': str(outfile),
                'filename': outfile.name,
                'samples': len(pcm),
                'duration': round(len(pcm) / 48000, 2),
                'mode': 'FM',
            }
        except Exception as e:
            return {'error': f'FM demodulation failed: {e}'}

    def demodulate_am(self, file_path: str, frequency: Optional[int] = None) -> Dict[str, Any]:
        """AM demodulate captured IQ data to audio."""
        fpath = self._resolve_recording(file_path)
        if not fpath:
            return {'error': f'Recording file not found: {file_path}'}

        outfile = fpath.with_suffix('.am.wav')

        try:
            raw = fpath.read_bytes()
            if len(raw) < 1024:
                return {'error': 'File too small to demodulate'}

            # AM demodulation: envelope detection (magnitude of IQ samples)
            audio = []
            for i in range(0, len(raw) - 1, 2):
                i_val = (raw[i] - 127.5) / 127.5
                q_val = (raw[i + 1] - 127.5) / 127.5
                import math
                magnitude = math.sqrt(i_val * i_val + q_val * q_val)
                audio.append(magnitude)

            if not audio:
                return {'error': 'Not enough samples for AM demodulation'}

            # Remove DC offset
            mean_val = sum(audio) / len(audio)
            audio = [s - mean_val for s in audio]

            # Downsample to ~48 kHz
            decimation = 42
            decimated = [audio[i] for i in range(0, len(audio), decimation)]

            # Normalize to 16-bit PCM
            if not decimated:
                return {'error': 'Demodulation produced no audio samples'}
            max_val = max(abs(s) for s in decimated) or 1.0
            pcm = [int((s / max_val) * 32000) for s in decimated]

            # Write WAV
            import wave
            with wave.open(str(outfile), 'w') as wav:
                wav.setnchannels(1)
                wav.setsampwidth(2)
                wav.setframerate(48000)
                wav.writeframes(struct.pack(f'<{len(pcm)}h', *pcm))

            return {
                'status': 'completed',
                'output': str(outfile),
                'filename': outfile.name,
                'samples': len(pcm),
                'duration': round(len(pcm) / 48000, 2),
                'mode': 'AM',
            }
        except Exception as e:
            return {'error': f'AM demodulation failed: {e}'}

    # ── ADS-B Tracking ───────────────────────────────────────────────────────

    def start_adsb(self, device: str = 'rtl') -> Dict[str, Any]:
        """Start ADS-B aircraft tracking (1090 MHz)."""
        with self._adsb_lock:
            if self._adsb_running:
                return {'status': 'already_running', 'message': 'ADS-B tracking is already active'}

        # Try dump1090 first, then rtl_adsb
        dump1090 = find_tool('dump1090')
        rtl_adsb = find_tool('rtl_adsb')
        tool = dump1090 or rtl_adsb

        if not tool:
            return {'error': 'No ADS-B tool found — install dump1090 or rtl-sdr (rtl_adsb)'}

        try:
            if dump1090:
                cmd = [dump1090, '--raw', '--net-only', '--quiet']
            else:
                cmd = [rtl_adsb]

            self._adsb_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self._adsb_running = True
            self._adsb_aircraft.clear()

            # Background thread to parse output
            self._adsb_thread = threading.Thread(
                target=self._adsb_reader, daemon=True
            )
            self._adsb_thread.start()

            return {
                'status': 'started',
                'tool': Path(tool).name,
                'message': f'ADS-B tracking started with {Path(tool).name}',
            }
        except Exception as e:
            self._adsb_running = False
            return {'error': f'Failed to start ADS-B: {e}'}

    def _adsb_reader(self):
        """Background thread to read and parse ADS-B output."""
        try:
            while self._adsb_running and self._adsb_process:
                line = self._adsb_process.stdout.readline()
                if not line:
                    if self._adsb_process.poll() is not None:
                        break
                    continue
                line = line.strip()
                if not line:
                    continue
                self._parse_adsb_message(line)
        except Exception:
            pass
        finally:
            self._adsb_running = False

    def _parse_adsb_message(self, msg: str):
        """Parse a raw ADS-B hex message and update aircraft tracking."""
        # Clean up message
        msg = msg.strip().lstrip('*').rstrip(';')
        if not msg or len(msg) < 14:
            return

        try:
            data = bytes.fromhex(msg)
        except ValueError:
            return

        # Downlink Format (first 5 bits)
        df = (data[0] >> 3) & 0x1F

        # We primarily care about DF17 (ADS-B extended squitter)
        if df == 17 and len(data) >= 7:
            # ICAO address is bytes 1-3
            icao = data[1:4].hex().upper()
            # Type code is first 5 bits of ME field (byte 4)
            tc = (data[4] >> 3) & 0x1F

            now = datetime.now(timezone.utc).isoformat()

            with self._adsb_lock:
                if icao not in self._adsb_aircraft:
                    self._adsb_aircraft[icao] = {
                        'icao': icao,
                        'callsign': '',
                        'altitude': None,
                        'speed': None,
                        'heading': None,
                        'lat': None,
                        'lon': None,
                        'vertical_rate': None,
                        'squawk': '',
                        'first_seen': now,
                        'last_seen': now,
                        'messages': 0,
                    }

                ac = self._adsb_aircraft[icao]
                ac['last_seen'] = now
                ac['messages'] += 1

                # TC 1-4: Aircraft identification
                if 1 <= tc <= 4:
                    charset = '#ABCDEFGHIJKLMNOPQRSTUVWXYZ#####_###############0123456789######'
                    callsign = ''
                    if len(data) >= 11:
                        bits = int.from_bytes(data[4:11], 'big')
                        for i in range(8):
                            idx = (bits >> (42 - i * 6)) & 0x3F
                            if idx < len(charset):
                                callsign += charset[idx]
                        ac['callsign'] = callsign.strip().strip('#')

                # TC 9-18: Airborne position
                elif 9 <= tc <= 18:
                    if len(data) >= 11:
                        alt_code = ((data[5] & 0xFF) << 4) | ((data[6] >> 4) & 0x0F)
                        # Remove Q-bit (bit 4)
                        q_bit = (alt_code >> 4) & 1
                        if q_bit:
                            n = ((alt_code >> 5) << 4) | (alt_code & 0x0F)
                            ac['altitude'] = n * 25 - 1000

                # TC 19: Airborne velocity
                elif tc == 19:
                    if len(data) >= 11:
                        sub = data[4] & 0x07
                        if sub in (1, 2):
                            ew_dir = (data[5] >> 2) & 1
                            ew_vel = ((data[5] & 0x03) << 8) | data[6]
                            ns_dir = (data[7] >> 7) & 1
                            ns_vel = ((data[7] & 0x7F) << 3) | ((data[8] >> 5) & 0x07)
                            ew_vel = (ew_vel - 1) * (-1 if ew_dir else 1)
                            ns_vel = (ns_vel - 1) * (-1 if ns_dir else 1)
                            import math
                            ac['speed'] = round(math.sqrt(ew_vel**2 + ns_vel**2))
                            ac['heading'] = round(math.degrees(math.atan2(ew_vel, ns_vel)) % 360)

    def stop_adsb(self) -> Dict[str, Any]:
        """Stop ADS-B tracking."""
        with self._adsb_lock:
            if not self._adsb_running:
                return {'status': 'not_running', 'message': 'ADS-B tracking is not active'}

            self._adsb_running = False
            if self._adsb_process:
                try:
                    self._adsb_process.terminate()
                    self._adsb_process.wait(timeout=5)
                except Exception:
                    try:
                        self._adsb_process.kill()
                    except Exception:
                        pass
                self._adsb_process = None

            count = len(self._adsb_aircraft)
            return {
                'status': 'stopped',
                'message': f'ADS-B tracking stopped — {count} aircraft tracked',
                'aircraft_count': count,
            }

    def get_adsb_aircraft(self) -> List[Dict[str, Any]]:
        """Return current list of tracked aircraft."""
        with self._adsb_lock:
            aircraft = list(self._adsb_aircraft.values())
        # Sort by last seen, most recent first
        aircraft.sort(key=lambda a: a.get('last_seen', ''), reverse=True)
        return aircraft

    # ── GPS Spoofing Detection ───────────────────────────────────────────────

    def detect_gps_spoofing(self, duration: int = 30) -> Dict[str, Any]:
        """Monitor GPS L1 frequency for spoofing indicators.

        Checks for: multiple strong signals, unusual power levels,
        inconsistent signal patterns that suggest spoofing.
        """
        gps_freq = 1575420000   # GPS L1 C/A: 1575.42 MHz
        bandwidth = 2048000     # 2 MHz bandwidth around center

        rtl_power = find_tool('rtl_power')
        rtl_sdr = find_tool('rtl_sdr')

        if not rtl_power and not rtl_sdr:
            return {'error': 'No RTL-SDR tools found — install rtl-sdr package'}

        results = {
            'frequency': gps_freq,
            'duration': duration,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'analysis': {},
            'spoofing_indicators': [],
            'risk_level': 'unknown',
        }

        # Capture a short sample at GPS L1 frequency
        if rtl_power:
            outfile = self._sdr_dir / 'gps_check.csv'
            if outfile.exists():
                outfile.unlink()

            freq_lo = gps_freq - 1000000
            freq_hi = gps_freq + 1000000
            cmd = [rtl_power,
                   '-f', f'{freq_lo}:{freq_hi}:10000',
                   '-i', str(min(duration, 10)),
                   '-1',
                   str(outfile)]

            try:
                subprocess.run(cmd, capture_output=True, timeout=duration + 15)

                if outfile.exists():
                    powers = []
                    with open(outfile, 'r') as f:
                        for line in f:
                            parts = line.strip().split(',')
                            if len(parts) >= 7:
                                try:
                                    db_values = [float(x) for x in parts[6:] if x.strip()]
                                    powers.extend(db_values)
                                except ValueError:
                                    continue

                    if powers:
                        avg_power = sum(powers) / len(powers)
                        max_power = max(powers)
                        min_power = min(powers)
                        # Count strong signals (above average + 10dB)
                        threshold = avg_power + 10
                        strong_signals = sum(1 for p in powers if p > threshold)

                        results['analysis'] = {
                            'avg_power_db': round(avg_power, 2),
                            'max_power_db': round(max_power, 2),
                            'min_power_db': round(min_power, 2),
                            'power_range_db': round(max_power - min_power, 2),
                            'strong_signals': strong_signals,
                            'total_bins': len(powers),
                        }

                        # Spoofing indicators
                        if max_power > -20:
                            results['spoofing_indicators'].append({
                                'indicator': 'Unusually strong GPS signal',
                                'detail': f'Max power: {max_power:.1f} dBm (normal GPS: -130 to -120 dBm at ground)',
                                'severity': 'high',
                            })

                        if strong_signals > len(powers) * 0.3:
                            results['spoofing_indicators'].append({
                                'indicator': 'Multiple strong carriers detected',
                                'detail': f'{strong_signals} strong signals out of {len(powers)} bins',
                                'severity': 'high',
                            })

                        if max_power - min_power < 5 and max_power > -60:
                            results['spoofing_indicators'].append({
                                'indicator': 'Flat power distribution',
                                'detail': f'Power range only {max_power - min_power:.1f} dB — consistent with artificial signal',
                                'severity': 'medium',
                            })

                        if max_power > -80:
                            results['spoofing_indicators'].append({
                                'indicator': 'Signal strength above expected GPS level',
                                'detail': f'Max {max_power:.1f} dBm is well above typical GPS signal levels',
                                'severity': 'medium',
                            })

                        # Overall risk
                        high = sum(1 for i in results['spoofing_indicators'] if i['severity'] == 'high')
                        med = sum(1 for i in results['spoofing_indicators'] if i['severity'] == 'medium')
                        if high >= 2:
                            results['risk_level'] = 'high'
                        elif high >= 1 or med >= 2:
                            results['risk_level'] = 'medium'
                        elif med >= 1:
                            results['risk_level'] = 'low'
                        else:
                            results['risk_level'] = 'none'
                    else:
                        results['analysis']['note'] = 'No power data collected — antenna may not receive GPS L1'
                        results['risk_level'] = 'unknown'
            except subprocess.TimeoutExpired:
                results['error'] = 'GPS monitoring timed out'
            except Exception as e:
                results['error'] = str(e)
        else:
            results['error'] = 'rtl_power not found (required for GPS analysis)'

        return results

    # ── Drone RF Detection ─────────────────────────────────────────────────

    def _load_drone_detections(self):
        """Load saved drone detections from disk."""
        try:
            if self._drone_detections_file.exists():
                with open(self._drone_detections_file, 'r') as f:
                    self._drone_detections = json.load(f)
            else:
                self._drone_detections = []
        except Exception:
            self._drone_detections = []

    def _save_drone_detections(self):
        """Persist drone detections to disk."""
        try:
            with open(self._drone_detections_file, 'w') as f:
                json.dump(self._drone_detections, f, indent=2)
        except Exception:
            pass

    def start_drone_detection(self, device: str = 'rtl', duration: int = 0) -> Dict[str, Any]:
        """Start continuous drone RF detection.

        Monitors known drone control frequencies:
        - 2.4 GHz ISM band (DJI, common FPV)
        - 5.8 GHz (DJI FPV, video downlinks)
        - 900 MHz (long-range control links)
        - 1.2 GHz (analog video)
        - 433 MHz (some telemetry)

        DJI drones use OcuSync/Lightbridge on 2.4/5.8 GHz with frequency hopping.
        FPV drones typically use fixed channels on 5.8 GHz for video.

        Args:
            device: 'rtl' or 'hackrf'
            duration: seconds to run (0 = until stopped)

        Returns detection results including:
        - Frequency hopping patterns (characteristic of drone control)
        - Signal strength and bearing estimation
        - Protocol identification (DJI OcuSync, analog FPV, Crossfire, ELRS)
        - Drone type estimation
        """
        with self._drone_lock:
            if self._drone_running:
                return {'status': 'already_running', 'message': 'Drone detection is already active'}

        # Verify we have the required tools
        if device == 'hackrf':
            tool = find_tool('hackrf_sweep')
            tool_name = 'hackrf_sweep'
            if not tool:
                return {'error': 'hackrf_sweep not found -- install hackrf package'}
        else:
            tool = find_tool('rtl_power')
            tool_name = 'rtl_power'
            if not tool:
                return {'error': 'rtl_power not found -- install rtl-sdr package'}

        with self._drone_lock:
            self._drone_running = True

        # Start background monitoring thread
        self._drone_thread = threading.Thread(
            target=self._drone_scan_loop,
            args=(device, tool, duration),
            daemon=True
        )
        self._drone_thread.start()

        return {
            'status': 'started',
            'device': device,
            'tool': tool_name,
            'duration': duration if duration > 0 else 'continuous',
            'message': f'Drone detection started with {tool_name}',
            'bands': [v['desc'] for v in DRONE_FREQUENCIES.values()],
        }

    def _drone_scan_loop(self, device: str, tool: str, duration: int):
        """Background loop that sweeps drone frequency bands repeatedly."""
        import math
        start_time = time.time()

        # Define scan bands -- we focus on 2.4 GHz and 5.8 GHz as primary,
        # plus 900 MHz and 433 MHz as secondary bands
        scan_bands = [
            {
                'name': '2.4 GHz ISM',
                'freq_start': 2400000000,
                'freq_end': 2500000000,
                'protocols': ['dji_control_2g', 'elrs_2g'],
            },
            {
                'name': '5.8 GHz',
                'freq_start': 5640000000,
                'freq_end': 5950000000,
                'protocols': ['dji_control_5g', 'fpv_video_5g'],
            },
            {
                'name': '900 MHz',
                'freq_start': 900000000,
                'freq_end': 930000000,
                'protocols': ['crossfire_900', 'elrs_900'],
            },
            {
                'name': '433 MHz',
                'freq_start': 432000000,
                'freq_end': 435000000,
                'protocols': ['telemetry_433'],
            },
        ]

        # History of power readings per band for hopping detection
        band_history: Dict[str, List[Dict[str, Any]]] = {b['name']: [] for b in scan_bands}

        try:
            while self._drone_running:
                # Check duration limit
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

                for band in scan_bands:
                    if not self._drone_running:
                        break

                    spectrum_data = self._drone_sweep_band(
                        device, tool,
                        band['freq_start'], band['freq_end']
                    )

                    if not spectrum_data:
                        continue

                    # Analyze the spectrum for drone signatures
                    detections = self._analyze_drone_spectrum(
                        spectrum_data, band, band_history[band['name']]
                    )

                    # Store sweep in history (keep last 10 sweeps per band)
                    band_history[band['name']].append({
                        'time': time.time(),
                        'data': spectrum_data,
                    })
                    if len(band_history[band['name']]) > 10:
                        band_history[band['name']].pop(0)

                    # Add any new detections
                    if detections:
                        with self._drone_lock:
                            for det in detections:
                                self._drone_detections.append(det)
                            self._save_drone_detections()

                # Brief pause between full scan cycles
                if self._drone_running:
                    time.sleep(1)

        except Exception:
            pass
        finally:
            with self._drone_lock:
                self._drone_running = False

    def _drone_sweep_band(self, device: str, tool: str,
                          freq_start: int, freq_end: int) -> List[Dict[str, Any]]:
        """Perform a single spectrum sweep of a frequency band.

        Returns list of {freq, power_db} dicts.
        """
        data = []

        if device == 'hackrf':
            # hackrf_sweep: output in CSV format
            f_start_mhz = freq_start // 1000000
            f_end_mhz = max(freq_end // 1000000, f_start_mhz + 1)
            cmd = [tool, '-f', f'{f_start_mhz}:{f_end_mhz}', '-n', '8192', '-w', '1000000']

            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split(',')
                    if len(parts) < 7:
                        continue
                    try:
                        hz_low = float(parts[2].strip())
                        hz_bin_width = float(parts[4].strip())
                        db_values = [float(x.strip()) for x in parts[6:] if x.strip()]
                        for i, db in enumerate(db_values):
                            freq = hz_low + (i * hz_bin_width)
                            if freq_start <= freq <= freq_end:
                                data.append({'freq': int(freq), 'power_db': round(db, 2)})
                    except (ValueError, IndexError):
                        continue
            except (subprocess.TimeoutExpired, Exception):
                pass
        else:
            # rtl_power
            outfile = self._sdr_dir / 'drone_sweep.csv'
            if outfile.exists():
                outfile.unlink()

            # RTL-SDR tops out around 1766 MHz, so for 2.4/5.8 GHz bands
            # we need HackRF. But we still try -- rtl_power will just fail
            # gracefully if frequency is out of range.
            step = 250000  # 250 kHz steps for drone detection
            cmd = [tool, '-f', f'{freq_start}:{freq_end}:{step}', '-i', '2', '-1', str(outfile)]

            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if outfile.exists():
                    with open(outfile, 'r') as f:
                        for line in f:
                            parts = line.strip().split(',')
                            if len(parts) < 7:
                                continue
                            try:
                                hz_low = float(parts[2])
                                hz_step = float(parts[4])
                                db_values = [float(x) for x in parts[6:] if x.strip()]
                                for i, db in enumerate(db_values):
                                    freq = hz_low + (i * hz_step)
                                    data.append({'freq': int(freq), 'power_db': round(db, 2)})
                            except (ValueError, IndexError):
                                continue
            except (subprocess.TimeoutExpired, Exception):
                pass

        return data

    def _analyze_drone_spectrum(self, spectrum_data: List[Dict[str, Any]],
                                band: Dict[str, Any],
                                history: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze spectrum sweep data for drone RF signatures.

        Looks for:
        - Strong signals above the noise floor
        - FHSS patterns (power appearing/disappearing at different frequencies)
        - Characteristic bandwidths matching known drone protocols
        - Fixed carriers on known FPV video channels
        """
        import math

        detections = []
        if not spectrum_data:
            return detections

        now = datetime.now(timezone.utc).isoformat()
        powers = [d['power_db'] for d in spectrum_data]
        if not powers:
            return detections

        avg_power = sum(powers) / len(powers)
        max_power = max(powers)
        # Noise floor estimate: median of lowest 50% of readings
        sorted_powers = sorted(powers)
        noise_floor = sorted_powers[len(sorted_powers) // 4] if sorted_powers else avg_power

        # Detection threshold: noise floor + 15 dB
        threshold = noise_floor + 15

        # Find strong signal clusters above threshold
        strong_bins = [d for d in spectrum_data if d['power_db'] > threshold]
        if not strong_bins:
            return detections

        # Group adjacent strong bins into clusters
        clusters = self._cluster_signals(strong_bins)

        for cluster in clusters:
            if len(cluster) < 2:
                continue

            cluster_freqs = [d['freq'] for d in cluster]
            cluster_powers = [d['power_db'] for d in cluster]
            center_freq = (min(cluster_freqs) + max(cluster_freqs)) // 2
            bandwidth_hz = max(cluster_freqs) - min(cluster_freqs)
            peak_power = max(cluster_powers)
            avg_cluster_power = sum(cluster_powers) / len(cluster_powers)

            # Identify the likely protocol
            protocol = self.identify_drone_protocol({
                'center_freq': center_freq,
                'bandwidth_hz': bandwidth_hz,
                'peak_power': peak_power,
                'avg_power': avg_cluster_power,
                'noise_floor': noise_floor,
                'num_bins': len(cluster),
                'band_name': band['name'],
                'history': history,
            })

            if protocol['protocol'] == 'unknown':
                continue

            # Calculate confidence based on signal characteristics
            confidence = protocol.get('confidence', 0)

            # Check history for frequency hopping patterns
            hopping_detected = False
            if len(history) >= 3:
                hopping_detected = self._detect_fhss_pattern(
                    center_freq, bandwidth_hz, history
                )
                if hopping_detected:
                    confidence = min(confidence + 20, 100)

            detection = {
                'time': now,
                'frequency': center_freq,
                'frequency_mhz': round(center_freq / 1e6, 3),
                'bandwidth_mhz': round(bandwidth_hz / 1e6, 3),
                'signal_strength_db': round(peak_power, 1),
                'noise_floor_db': round(noise_floor, 1),
                'snr_db': round(peak_power - noise_floor, 1),
                'protocol': protocol['protocol'],
                'protocol_detail': protocol.get('detail', ''),
                'drone_type': protocol.get('drone_type', 'Unknown'),
                'confidence': confidence,
                'band': band['name'],
                'fhss_detected': hopping_detected,
                'duration_s': 0,
            }

            # Update duration if we have seen this signal before
            with self._drone_lock:
                for prev in reversed(self._drone_detections):
                    if (prev.get('protocol') == detection['protocol']
                            and abs(prev.get('frequency', 0) - center_freq) < 5000000):
                        try:
                            prev_time = datetime.fromisoformat(prev['time'])
                            now_time = datetime.fromisoformat(now)
                            delta = (now_time - prev_time).total_seconds()
                            if delta < 60:
                                detection['duration_s'] = round(
                                    prev.get('duration_s', 0) + delta, 1
                                )
                        except Exception:
                            pass
                        break

            detections.append(detection)

        return detections

    def _cluster_signals(self, strong_bins: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Group adjacent frequency bins into signal clusters.

        Bins within 2 MHz of each other are considered part of the same signal.
        """
        if not strong_bins:
            return []

        sorted_bins = sorted(strong_bins, key=lambda d: d['freq'])
        clusters: List[List[Dict[str, Any]]] = [[sorted_bins[0]]]

        for b in sorted_bins[1:]:
            # Adjacent if within 2 MHz of last bin in current cluster
            if b['freq'] - clusters[-1][-1]['freq'] <= 2000000:
                clusters[-1].append(b)
            else:
                clusters.append([b])

        return clusters

    def _detect_fhss_pattern(self, center_freq: int, bandwidth_hz: int,
                             history: List[Dict[str, Any]]) -> bool:
        """Detect frequency hopping spread spectrum patterns by comparing
        sequential sweeps for signals that appear/disappear at different
        frequencies within the same band.

        FHSS signature: power peaks shift between sweeps while maintaining
        similar amplitude, consistent with drone control hopping patterns.
        """
        if len(history) < 3:
            return False

        # Look at the last few sweeps for peak frequency shifts
        peak_freqs = []
        for sweep in history[-5:]:
            data = sweep.get('data', [])
            if not data:
                continue
            # Find the peak frequency in this sweep within the band
            band_data = [d for d in data
                         if abs(d['freq'] - center_freq) < bandwidth_hz]
            if band_data:
                peak = max(band_data, key=lambda d: d['power_db'])
                peak_freqs.append(peak['freq'])

        if len(peak_freqs) < 3:
            return False

        # FHSS: peak frequency changes between sweeps by more than 1 MHz
        # but stays within the same band
        freq_shifts = []
        for i in range(1, len(peak_freqs)):
            shift = abs(peak_freqs[i] - peak_freqs[i - 1])
            freq_shifts.append(shift)

        # At least 2 significant frequency shifts = likely FHSS
        significant_shifts = sum(1 for s in freq_shifts if s > 1000000)
        return significant_shifts >= 2

    def identify_drone_protocol(self, spectrum_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze spectrum sweep data and return likely drone protocol
        based on bandwidth, frequency, and signal characteristics.

        Args:
            spectrum_data: dict with keys:
                center_freq, bandwidth_hz, peak_power, avg_power,
                noise_floor, num_bins, band_name, history

        Returns:
            dict with protocol, detail, drone_type, confidence
        """
        center = spectrum_data.get('center_freq', 0)
        bw = spectrum_data.get('bandwidth_hz', 0)
        peak = spectrum_data.get('peak_power', -100)
        noise = spectrum_data.get('noise_floor', -80)
        snr = peak - noise
        band = spectrum_data.get('band_name', '')

        result = {
            'protocol': 'unknown',
            'detail': '',
            'drone_type': 'Unknown',
            'confidence': 0,
        }

        # Minimum SNR for a valid detection
        if snr < 10:
            return result

        # ── 2.4 GHz band analysis ──
        if band == '2.4 GHz ISM' or 2400000000 <= center <= 2500000000:
            # DJI OcuSync 2.x/3.0: ~10-40 MHz wide FHSS on 2.4 GHz
            if 8000000 <= bw <= 45000000:
                result['protocol'] = 'DJI OcuSync'
                result['detail'] = f'{bw/1e6:.0f} MHz wide FHSS on 2.4 GHz'
                result['drone_type'] = 'DJI (Mavic/Air/Mini series)'
                result['confidence'] = min(40 + int(snr), 85)
            # ExpressLRS 2.4 GHz: narrower, ~1-5 MHz
            elif 500000 <= bw <= 6000000:
                result['protocol'] = 'ExpressLRS 2.4G'
                result['detail'] = f'{bw/1e6:.1f} MHz narrow band on 2.4 GHz'
                result['drone_type'] = 'FPV Racing/Freestyle Drone'
                result['confidence'] = min(30 + int(snr), 70)
            # Generic 2.4 GHz control -- could be WiFi drone
            elif bw <= 25000000:
                result['protocol'] = 'WiFi/2.4G Control'
                result['detail'] = f'{bw/1e6:.1f} MHz signal on 2.4 GHz'
                result['drone_type'] = 'WiFi-based drone or controller'
                result['confidence'] = min(20 + int(snr * 0.5), 50)

        # ── 5.8 GHz band analysis ──
        elif band == '5.8 GHz' or 5640000000 <= center <= 5950000000:
            # Check against known FPV analog video channels
            center_mhz = center / 1e6
            matched_channel = None
            for ch_name, ch_mhz in FPV_5G_CHANNELS.items():
                if abs(center_mhz - ch_mhz) < 10:
                    matched_channel = ch_name
                    break

            if matched_channel and bw <= 15000000:
                # Analog FPV video: constant carrier, ~10-12 MHz bandwidth
                result['protocol'] = 'Analog FPV Video'
                result['detail'] = f'Channel {matched_channel} ({center_mhz:.0f} MHz)'
                result['drone_type'] = 'FPV Drone (analog video)'
                result['confidence'] = min(50 + int(snr), 90)
            elif 10000000 <= bw <= 80000000:
                # DJI FPV / OcuSync on 5.8 GHz
                result['protocol'] = 'DJI OcuSync 5.8G'
                result['detail'] = f'{bw/1e6:.0f} MHz wide on 5.8 GHz'
                result['drone_type'] = 'DJI FPV / Digital Link'
                result['confidence'] = min(35 + int(snr), 80)
            elif bw <= 10000000:
                # Could be digital FPV (HDZero, Walksnail)
                result['protocol'] = 'Digital FPV Video'
                result['detail'] = f'{bw/1e6:.1f} MHz on 5.8 GHz'
                result['drone_type'] = 'FPV Drone (digital video)'
                result['confidence'] = min(25 + int(snr * 0.7), 65)

        # ── 900 MHz band analysis ──
        elif band == '900 MHz' or 900000000 <= center <= 930000000:
            if bw <= 2000000:
                # Crossfire or ELRS 900 MHz -- narrow, hopping
                result['protocol'] = 'Crossfire/ELRS 900'
                result['detail'] = f'{bw/1e3:.0f} kHz on 900 MHz ISM'
                result['drone_type'] = 'Long-range FPV/RC Drone'
                result['confidence'] = min(30 + int(snr), 70)
            elif 2000000 < bw <= 26000000:
                result['protocol'] = 'Crossfire 900'
                result['detail'] = f'{bw/1e6:.1f} MHz wideband 900 MHz'
                result['drone_type'] = 'Long-range FPV Drone'
                result['confidence'] = min(25 + int(snr * 0.7), 65)

        # ── 433 MHz band analysis ──
        elif band == '433 MHz' or 432000000 <= center <= 435000000:
            if bw <= 1000000:
                result['protocol'] = '433 MHz Telemetry'
                result['detail'] = f'{bw/1e3:.0f} kHz telemetry link'
                result['drone_type'] = 'Drone with 433 telemetry'
                result['confidence'] = min(20 + int(snr * 0.5), 50)

        return result

    def stop_drone_detection(self) -> Dict[str, Any]:
        """Stop the drone detection background scan."""
        with self._drone_lock:
            if not self._drone_running:
                return {'status': 'not_running', 'message': 'Drone detection is not active'}

            self._drone_running = False

        # Wait briefly for the thread to finish
        if self._drone_thread and self._drone_thread.is_alive():
            self._drone_thread.join(timeout=5)
        self._drone_thread = None

        with self._drone_lock:
            count = len(self._drone_detections)

        return {
            'status': 'stopped',
            'message': f'Drone detection stopped -- {count} detections recorded',
            'detection_count': count,
        }

    def get_drone_detections(self) -> List[Dict[str, Any]]:
        """Return current list of drone detections, newest first."""
        with self._drone_lock:
            dets = list(self._drone_detections)
        dets.sort(key=lambda d: d.get('time', ''), reverse=True)
        return dets

    def clear_drone_detections(self):
        """Clear all stored drone detections."""
        with self._drone_lock:
            self._drone_detections = []
            self._save_drone_detections()

    def is_drone_detecting(self) -> bool:
        """Check if drone detection is currently running."""
        with self._drone_lock:
            return self._drone_running

    # ── Signal Analysis ──────────────────────────────────────────────────────

    def analyze_signal(self, file_path: str) -> Dict[str, Any]:
        """Basic signal analysis on a captured IQ file."""
        fpath = self._resolve_recording(file_path)
        if not fpath:
            return {'error': f'Recording file not found: {file_path}'}

        try:
            raw = fpath.read_bytes()
            size = len(raw)
            if size < 64:
                return {'error': 'File too small for analysis'}

            # Parse as unsigned 8-bit IQ (RTL-SDR format)
            i_samples = []
            q_samples = []
            magnitudes = []
            import math
            for idx in range(0, min(size, 2048000) - 1, 2):
                i_val = (raw[idx] - 127.5) / 127.5
                q_val = (raw[idx + 1] - 127.5) / 127.5
                i_samples.append(i_val)
                q_samples.append(q_val)
                magnitudes.append(math.sqrt(i_val * i_val + q_val * q_val))

            if not magnitudes:
                return {'error': 'No valid samples found'}

            avg_mag = sum(magnitudes) / len(magnitudes)
            max_mag = max(magnitudes)
            min_mag = min(magnitudes)

            # Estimate power in dB (relative to full scale)
            avg_power_db = round(20 * math.log10(avg_mag + 1e-10), 2)
            peak_power_db = round(20 * math.log10(max_mag + 1e-10), 2)

            # Simple duty cycle: percentage of time signal is above 50% of max
            threshold = max_mag * 0.5
            above = sum(1 for m in magnitudes if m > threshold)
            duty_cycle = round(above / len(magnitudes) * 100, 1)

            # Estimate bandwidth using power spectral density
            # Simple FFT-based approach
            n = min(len(i_samples), 4096)
            fft_input = [complex(i_samples[k], q_samples[k]) for k in range(n)]
            # Manual DFT for small N, or use simple approximation
            bandwidth_estimate = 'N/A (requires numpy for FFT)'

            # Try modulation type guess based on signal characteristics
            # AM: magnitude varies, phase relatively stable
            # FM: magnitude relatively stable, phase varies
            mag_variance = sum((m - avg_mag) ** 2 for m in magnitudes) / len(magnitudes)
            mag_std = math.sqrt(mag_variance)
            mag_cv = mag_std / (avg_mag + 1e-10)  # coefficient of variation

            if mag_cv < 0.15:
                mod_guess = 'FM (constant envelope)'
            elif mag_cv > 0.5:
                mod_guess = 'AM or OOK (high amplitude variation)'
            else:
                mod_guess = 'Mixed / Unknown'

            # Recording metadata from our store
            meta = {}
            for m in self._metadata:
                if Path(m.get('file', '')).name == fpath.name:
                    meta = m
                    break

            return {
                'file': fpath.name,
                'file_size': size,
                'file_size_human': self._human_size(size),
                'total_samples': size // 2,
                'analyzed_samples': len(magnitudes),
                'power': {
                    'average_db': avg_power_db,
                    'peak_db': peak_power_db,
                    'dynamic_range_db': round(peak_power_db - avg_power_db, 2),
                },
                'magnitude': {
                    'average': round(avg_mag, 4),
                    'max': round(max_mag, 4),
                    'min': round(min_mag, 4),
                    'std_dev': round(mag_std, 4),
                },
                'duty_cycle_pct': duty_cycle,
                'modulation_guess': mod_guess,
                'bandwidth_estimate': bandwidth_estimate,
                'frequency': meta.get('frequency', 'Unknown'),
                'sample_rate': meta.get('sample_rate', 'Unknown'),
                'device': meta.get('device', 'Unknown'),
            }
        except Exception as e:
            return {'error': f'Analysis failed: {e}'}

    # ── Common Frequencies ───────────────────────────────────────────────────

    def get_common_frequencies(self) -> Dict[str, Any]:
        """Return the common frequencies reference dictionary."""
        return COMMON_FREQUENCIES

    # ── Status ───────────────────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get current SDR status: device info, active capture, ADS-B state, drone detection."""
        capturing = self.is_capturing()
        adsb_running = self._adsb_running

        status = {
            'capturing': capturing,
            'capture_info': self._capture_info if capturing else None,
            'adsb_running': adsb_running,
            'adsb_aircraft_count': len(self._adsb_aircraft),
            'drone_detecting': self.is_drone_detecting(),
            'drone_detection_count': len(self._drone_detections),
            'recordings_count': len(self.list_recordings()),
            'recordings_dir': str(self._recordings_dir),
        }
        return status

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _resolve_recording(self, file_path: str) -> Optional[Path]:
        """Resolve a recording file path, checking recordings dir."""
        fpath = Path(file_path)
        if fpath.exists():
            return fpath
        # Try in recordings directory
        fpath = self._recordings_dir / file_path
        if fpath.exists():
            return fpath
        # Try just filename
        fpath = self._recordings_dir / Path(file_path).name
        if fpath.exists():
            return fpath
        return None

    @staticmethod
    def _human_size(nbytes: int) -> str:
        """Convert bytes to human-readable size string."""
        for unit in ('B', 'KB', 'MB', 'GB'):
            if abs(nbytes) < 1024:
                return f'{nbytes:.1f} {unit}'
            nbytes /= 1024
        return f'{nbytes:.1f} TB'


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_sdr_tools() -> SDRTools:
    global _instance
    if _instance is None:
        _instance = SDRTools()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for SDR/RF Tools module."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from core.banner import Colors, clear_screen, display_banner

    sdr = get_sdr_tools()

    while True:
        clear_screen()
        display_banner()
        print(f"\n{Colors.CYAN}=== SDR / RF Tools ==={Colors.RESET}\n")
        print(f"  {Colors.GREEN}1{Colors.RESET}) Detect Devices")
        print(f"  {Colors.GREEN}2{Colors.RESET}) Spectrum Scan")
        print(f"  {Colors.GREEN}3{Colors.RESET}) Capture Signal")
        print(f"  {Colors.GREEN}4{Colors.RESET}) Replay Signal")
        print(f"  {Colors.GREEN}5{Colors.RESET}) ADS-B Track")
        print(f"  {Colors.GREEN}6{Colors.RESET}) FM Demod")
        print(f"  {Colors.GREEN}7{Colors.RESET}) AM Demod")
        print(f"  {Colors.GREEN}8{Colors.RESET}) List Recordings")
        print(f"  {Colors.GREEN}9{Colors.RESET}) Analyze Signal")
        print(f"  {Colors.RED}0{Colors.RESET}) Back\n")

        choice = input(f"{Colors.CYAN}Select> {Colors.RESET}").strip()

        if choice == '0':
            break

        elif choice == '1':
            print(f"\n{Colors.CYAN}[*] Detecting SDR devices...{Colors.RESET}")
            devices = sdr.detect_devices()
            if not devices:
                print(f"{Colors.YELLOW}[!] No SDR devices found{Colors.RESET}")
            else:
                for d in devices:
                    status_color = Colors.GREEN if d['status'] == 'available' else Colors.YELLOW
                    print(f"  {status_color}[{d['status']}]{Colors.RESET} {d['type']}: {d.get('name', 'Unknown')} (SN: {d.get('serial', 'N/A')})")
                    if d.get('capabilities'):
                        print(f"    Capabilities: {', '.join(d['capabilities'])}")
                    if d.get('note'):
                        print(f"    {Colors.YELLOW}{d['note']}{Colors.RESET}")

        elif choice == '2':
            try:
                dev = input("  Device (rtl/hackrf) [rtl]: ").strip() or 'rtl'
                f_start = input("  Start frequency MHz [88]: ").strip() or '88'
                f_end = input("  End frequency MHz [108]: ").strip() or '108'
                dur = input("  Duration seconds [5]: ").strip() or '5'
                print(f"\n{Colors.CYAN}[*] Scanning spectrum {f_start}-{f_end} MHz...{Colors.RESET}")
                result = sdr.scan_spectrum(
                    device=dev,
                    freq_start=int(float(f_start) * 1000000),
                    freq_end=int(float(f_end) * 1000000),
                    duration=int(dur)
                )
                if result.get('error'):
                    print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                else:
                    points = result.get('data', [])
                    print(f"{Colors.GREEN}[+] Collected {len(points)} data points{Colors.RESET}")
                    # Show top 10 strongest signals
                    top = sorted(points, key=lambda p: p['power_db'], reverse=True)[:10]
                    if top:
                        print(f"\n  {'Frequency':>15s}  {'Power (dB)':>10s}")
                        print(f"  {'-'*15}  {'-'*10}")
                        for p in top:
                            freq_str = f"{p['freq']/1e6:.3f} MHz"
                            print(f"  {freq_str:>15s}  {p['power_db']:>10.1f}")
            except (ValueError, KeyboardInterrupt):
                print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")

        elif choice == '3':
            try:
                dev = input("  Device (rtl/hackrf) [rtl]: ").strip() or 'rtl'
                freq = input("  Frequency MHz [100.0]: ").strip() or '100.0'
                dur = input("  Duration seconds [10]: ").strip() or '10'
                print(f"\n{Colors.CYAN}[*] Capturing at {freq} MHz for {dur}s...{Colors.RESET}")
                result = sdr.start_capture(
                    device=dev,
                    frequency=int(float(freq) * 1000000),
                    duration=int(dur)
                )
                if result.get('error'):
                    print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}[+] Capturing to: {result.get('file')}{Colors.RESET}")
                    print(f"  Press Enter to wait for completion...")
                    input()
            except (ValueError, KeyboardInterrupt):
                sdr.stop_capture()
                print(f"\n{Colors.YELLOW}[!] Capture stopped{Colors.RESET}")

        elif choice == '4':
            recordings = sdr.list_recordings()
            if not recordings:
                print(f"\n{Colors.YELLOW}[!] No recordings found{Colors.RESET}")
            else:
                print(f"\n  Recordings:")
                for i, r in enumerate(recordings):
                    print(f"  {i+1}) {r.get('filename', 'unknown')} ({r.get('size_human', '?')})")
                try:
                    idx = int(input(f"\n  Select recording [1-{len(recordings)}]: ").strip()) - 1
                    rec = recordings[idx]
                    freq = input(f"  TX Frequency MHz [{rec.get('frequency', 100000000)/1e6:.3f}]: ").strip()
                    if not freq:
                        freq = str(rec.get('frequency', 100000000) / 1e6)
                    print(f"\n{Colors.CYAN}[*] Replaying {rec.get('filename')} at {freq} MHz...{Colors.RESET}")
                    result = sdr.replay_signal(
                        rec.get('file', rec.get('filename', '')),
                        frequency=int(float(freq) * 1000000)
                    )
                    if result.get('error'):
                        print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}[+] {result.get('message', 'Done')}{Colors.RESET}")
                except (ValueError, IndexError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")

        elif choice == '5':
            if sdr._adsb_running:
                print(f"\n{Colors.CYAN}[*] ADS-B is running. Showing aircraft...{Colors.RESET}")
                aircraft = sdr.get_adsb_aircraft()
                if not aircraft:
                    print(f"{Colors.YELLOW}  No aircraft detected yet{Colors.RESET}")
                else:
                    print(f"\n  {'ICAO':>8s}  {'Callsign':>10s}  {'Alt(ft)':>8s}  {'Spd(kn)':>8s}  {'Hdg':>5s}  {'Msgs':>5s}")
                    print(f"  {'-'*8}  {'-'*10}  {'-'*8}  {'-'*8}  {'-'*5}  {'-'*5}")
                    for ac in aircraft[:20]:
                        alt = str(ac.get('altitude', '')) if ac.get('altitude') is not None else '--'
                        spd = str(ac.get('speed', '')) if ac.get('speed') is not None else '--'
                        hdg = str(ac.get('heading', '')) if ac.get('heading') is not None else '--'
                        print(f"  {ac['icao']:>8s}  {ac.get('callsign', ''):>10s}  {alt:>8s}  {spd:>8s}  {hdg:>5s}  {ac.get('messages', 0):>5d}")

                stop = input(f"\n  Stop tracking? [y/N]: ").strip().lower()
                if stop == 'y':
                    result = sdr.stop_adsb()
                    print(f"{Colors.GREEN}[+] {result.get('message', 'Stopped')}{Colors.RESET}")
            else:
                dev = input("  Device (rtl) [rtl]: ").strip() or 'rtl'
                print(f"\n{Colors.CYAN}[*] Starting ADS-B tracking...{Colors.RESET}")
                result = sdr.start_adsb(device=dev)
                if result.get('error'):
                    print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                else:
                    print(f"{Colors.GREEN}[+] {result.get('message', 'Started')}{Colors.RESET}")

        elif choice == '6':
            recordings = sdr.list_recordings()
            if not recordings:
                print(f"\n{Colors.YELLOW}[!] No recordings found{Colors.RESET}")
            else:
                print(f"\n  Recordings:")
                for i, r in enumerate(recordings):
                    print(f"  {i+1}) {r.get('filename', 'unknown')} ({r.get('size_human', '?')})")
                try:
                    idx = int(input(f"\n  Select recording [1-{len(recordings)}]: ").strip()) - 1
                    rec = recordings[idx]
                    print(f"\n{Colors.CYAN}[*] FM demodulating {rec.get('filename')}...{Colors.RESET}")
                    result = sdr.demodulate_fm(rec.get('file', rec.get('filename', '')))
                    if result.get('error'):
                        print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}[+] Output: {result.get('filename')}{Colors.RESET}")
                        print(f"  Duration: {result.get('duration', 0):.2f}s, Samples: {result.get('samples', 0)}")
                except (ValueError, IndexError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")

        elif choice == '7':
            recordings = sdr.list_recordings()
            if not recordings:
                print(f"\n{Colors.YELLOW}[!] No recordings found{Colors.RESET}")
            else:
                print(f"\n  Recordings:")
                for i, r in enumerate(recordings):
                    print(f"  {i+1}) {r.get('filename', 'unknown')} ({r.get('size_human', '?')})")
                try:
                    idx = int(input(f"\n  Select recording [1-{len(recordings)}]: ").strip()) - 1
                    rec = recordings[idx]
                    print(f"\n{Colors.CYAN}[*] AM demodulating {rec.get('filename')}...{Colors.RESET}")
                    result = sdr.demodulate_am(rec.get('file', rec.get('filename', '')))
                    if result.get('error'):
                        print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                    else:
                        print(f"{Colors.GREEN}[+] Output: {result.get('filename')}{Colors.RESET}")
                        print(f"  Duration: {result.get('duration', 0):.2f}s, Samples: {result.get('samples', 0)}")
                except (ValueError, IndexError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")

        elif choice == '8':
            recordings = sdr.list_recordings()
            if not recordings:
                print(f"\n{Colors.YELLOW}[!] No recordings found{Colors.RESET}")
            else:
                print(f"\n  {'#':>3s}  {'Filename':>30s}  {'Freq':>12s}  {'Size':>10s}  {'Device':>8s}  {'Date':>20s}")
                print(f"  {'-'*3}  {'-'*30}  {'-'*12}  {'-'*10}  {'-'*8}  {'-'*20}")
                for i, r in enumerate(recordings):
                    freq = r.get('frequency', 0)
                    freq_str = f"{freq/1e6:.3f} MHz" if freq else 'N/A'
                    date_str = r.get('completed', '')[:19] if r.get('completed') else 'N/A'
                    print(f"  {i+1:>3d}  {r.get('filename', 'unknown'):>30s}  {freq_str:>12s}  {r.get('size_human', '?'):>10s}  {r.get('device', '?'):>8s}  {date_str:>20s}")

        elif choice == '9':
            recordings = sdr.list_recordings()
            if not recordings:
                print(f"\n{Colors.YELLOW}[!] No recordings found{Colors.RESET}")
            else:
                print(f"\n  Recordings:")
                for i, r in enumerate(recordings):
                    print(f"  {i+1}) {r.get('filename', 'unknown')} ({r.get('size_human', '?')})")
                try:
                    idx = int(input(f"\n  Select recording [1-{len(recordings)}]: ").strip()) - 1
                    rec = recordings[idx]
                    print(f"\n{Colors.CYAN}[*] Analyzing {rec.get('filename')}...{Colors.RESET}")
                    result = sdr.analyze_signal(rec.get('file', rec.get('filename', '')))
                    if result.get('error'):
                        print(f"{Colors.RED}[X] {result['error']}{Colors.RESET}")
                    else:
                        print(f"\n  {Colors.GREEN}Signal Analysis:{Colors.RESET}")
                        print(f"  File: {result.get('file', 'unknown')}")
                        print(f"  Size: {result.get('file_size_human', '?')}")
                        print(f"  Samples: {result.get('total_samples', 0):,}")
                        pwr = result.get('power', {})
                        print(f"  Avg Power: {pwr.get('average_db', '?')} dB")
                        print(f"  Peak Power: {pwr.get('peak_db', '?')} dB")
                        print(f"  Dynamic Range: {pwr.get('dynamic_range_db', '?')} dB")
                        print(f"  Duty Cycle: {result.get('duty_cycle_pct', '?')}%")
                        print(f"  Modulation: {result.get('modulation_guess', '?')}")
                except (ValueError, IndexError, KeyboardInterrupt):
                    print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.RESET}")

        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
