"""AUTARCH Anti-Forensics

Secure file deletion, timestamp manipulation, log clearing, metadata scrubbing,
and counter-forensics techniques for operational security.
"""

DESCRIPTION = "Anti-forensics & counter-investigation tools"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "counter"

import os
import re
import json
import time
import struct
import shutil
import secrets
import subprocess
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

try:
    from PIL import Image as PILImage
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ── Secure Deletion ─────────────────────────────────────────────────────────

class SecureDelete:
    """Secure file/directory deletion with overwrite patterns."""

    PATTERNS = {
        'zeros': b'\x00',
        'ones': b'\xFF',
        'random': None,  # Generated per-pass
        'dod_3pass': [b'\x00', None, b'\xFF'],  # DoD 5220.22-M simplified
        'gutmann': None,  # 35 passes with specific patterns
    }

    @staticmethod
    def secure_delete_file(filepath: str, passes: int = 3,
                            method: str = 'random') -> Dict:
        """Securely delete a file by overwriting before unlinking."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        try:
            file_size = os.path.getsize(filepath)

            if method == 'dod_3pass':
                patterns = [b'\x00', None, b'\xFF']
            else:
                patterns = [None] * passes  # All random

            # Overwrite passes
            for i, pattern in enumerate(patterns):
                with open(filepath, 'r+b') as f:
                    remaining = file_size
                    while remaining > 0:
                        chunk_size = min(4096, remaining)
                        if pattern is None:
                            chunk = secrets.token_bytes(chunk_size)
                        else:
                            chunk = pattern * chunk_size
                        f.write(chunk[:chunk_size])
                        remaining -= chunk_size
                    f.flush()
                    os.fsync(f.fileno())

            # Truncate to zero
            with open(filepath, 'w') as f:
                pass

            # Rename to random name before deletion (anti-filename recovery)
            directory = os.path.dirname(filepath)
            random_name = os.path.join(directory, secrets.token_hex(16))
            os.rename(filepath, random_name)
            os.unlink(random_name)

            return {
                'ok': True,
                'file': filepath,
                'size': file_size,
                'passes': len(patterns),
                'method': method,
                'message': f'Securely deleted {filepath} ({file_size} bytes, {len(patterns)} passes)'
            }

        except PermissionError:
            return {'ok': False, 'error': 'Permission denied'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def secure_delete_directory(dirpath: str, passes: int = 3) -> Dict:
        """Recursively securely delete all files in a directory."""
        if not os.path.isdir(dirpath):
            return {'ok': False, 'error': 'Directory not found'}

        deleted = 0
        errors = 0

        for root, dirs, files in os.walk(dirpath, topdown=False):
            for name in files:
                filepath = os.path.join(root, name)
                result = SecureDelete.secure_delete_file(filepath, passes)
                if result['ok']:
                    deleted += 1
                else:
                    errors += 1

            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except OSError:
                    errors += 1

        try:
            os.rmdir(dirpath)
        except OSError:
            errors += 1

        return {
            'ok': True,
            'directory': dirpath,
            'files_deleted': deleted,
            'errors': errors
        }

    @staticmethod
    def wipe_free_space(mount_point: str, passes: int = 1) -> Dict:
        """Fill free space with random data then delete (anti-carving)."""
        try:
            temp_file = os.path.join(mount_point, f'.wipe_{secrets.token_hex(8)}')
            chunk_size = 1024 * 1024  # 1MB
            written = 0

            with open(temp_file, 'wb') as f:
                try:
                    while True:
                        f.write(secrets.token_bytes(chunk_size))
                        written += chunk_size
                        f.flush()
                except (OSError, IOError):
                    pass  # Disk full — expected

            os.unlink(temp_file)

            return {
                'ok': True,
                'mount_point': mount_point,
                'wiped_bytes': written,
                'wiped_mb': round(written / (1024*1024), 1)
            }

        except Exception as e:
            # Clean up temp file
            if os.path.exists(temp_file):
                os.unlink(temp_file)
            return {'ok': False, 'error': str(e)}


# ── Timestamp Manipulation ───────────────────────────────────────────────────

class TimestampManip:
    """File timestamp modification for counter-forensics."""

    @staticmethod
    def get_timestamps(filepath: str) -> Dict:
        """Get file timestamps."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        stat = os.stat(filepath)
        return {
            'ok': True,
            'file': filepath,
            'accessed': datetime.fromtimestamp(stat.st_atime, timezone.utc).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
            'atime': stat.st_atime,
            'mtime': stat.st_mtime,
            'ctime': stat.st_ctime
        }

    @staticmethod
    def set_timestamps(filepath: str, accessed: float = None,
                        modified: float = None) -> Dict:
        """Set file access and modification timestamps."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        try:
            stat = os.stat(filepath)
            atime = accessed if accessed is not None else stat.st_atime
            mtime = modified if modified is not None else stat.st_mtime
            os.utime(filepath, (atime, mtime))

            return {
                'ok': True,
                'file': filepath,
                'accessed': datetime.fromtimestamp(atime, timezone.utc).isoformat(),
                'modified': datetime.fromtimestamp(mtime, timezone.utc).isoformat()
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def clone_timestamps(source: str, target: str) -> Dict:
        """Copy timestamps from one file to another."""
        if not os.path.exists(source):
            return {'ok': False, 'error': 'Source file not found'}
        if not os.path.exists(target):
            return {'ok': False, 'error': 'Target file not found'}

        try:
            stat = os.stat(source)
            os.utime(target, (stat.st_atime, stat.st_mtime))
            return {
                'ok': True,
                'source': source,
                'target': target,
                'message': 'Timestamps cloned'
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def randomize_timestamps(filepath: str, start_epoch: float = None,
                              end_epoch: float = None) -> Dict:
        """Set random timestamps within a range."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        if start_epoch is None:
            start_epoch = time.time() - 365 * 24 * 3600  # 1 year ago
        if end_epoch is None:
            end_epoch = time.time()

        import random
        atime = random.uniform(start_epoch, end_epoch)
        mtime = random.uniform(start_epoch, end_epoch)

        return TimestampManip.set_timestamps(filepath, atime, mtime)


# ── Log Clearing ─────────────────────────────────────────────────────────────

class LogCleaner:
    """System log manipulation and clearing."""

    COMMON_LOG_PATHS = [
        '/var/log/auth.log', '/var/log/syslog', '/var/log/messages',
        '/var/log/kern.log', '/var/log/daemon.log', '/var/log/secure',
        '/var/log/wtmp', '/var/log/btmp', '/var/log/lastlog',
        '/var/log/faillog', '/var/log/apache2/access.log',
        '/var/log/apache2/error.log', '/var/log/nginx/access.log',
        '/var/log/nginx/error.log', '/var/log/mysql/error.log',
    ]

    @staticmethod
    def list_logs() -> List[Dict]:
        """List available log files."""
        logs = []
        for path in LogCleaner.COMMON_LOG_PATHS:
            if os.path.exists(path):
                try:
                    stat = os.stat(path)
                    logs.append({
                        'path': path,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                        'writable': os.access(path, os.W_OK)
                    })
                except OSError:
                    pass
        return logs

    @staticmethod
    def clear_log(filepath: str) -> Dict:
        """Clear a log file (truncate to zero)."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}
        try:
            original_size = os.path.getsize(filepath)
            with open(filepath, 'w') as f:
                pass
            return {
                'ok': True,
                'file': filepath,
                'cleared_bytes': original_size
            }
        except PermissionError:
            return {'ok': False, 'error': 'Permission denied (need root?)'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def remove_entries(filepath: str, pattern: str) -> Dict:
        """Remove specific entries matching a pattern from log file."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        try:
            with open(filepath, 'r', errors='ignore') as f:
                lines = f.readlines()

            original_count = len(lines)
            filtered = [l for l in lines if not re.search(pattern, l, re.I)]
            removed = original_count - len(filtered)

            with open(filepath, 'w') as f:
                f.writelines(filtered)

            return {
                'ok': True,
                'file': filepath,
                'original_lines': original_count,
                'removed': removed,
                'remaining': len(filtered)
            }
        except PermissionError:
            return {'ok': False, 'error': 'Permission denied'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def clear_bash_history() -> Dict:
        """Clear bash history."""
        results = []
        history_files = [
            os.path.expanduser('~/.bash_history'),
            os.path.expanduser('~/.zsh_history'),
            os.path.expanduser('~/.python_history'),
        ]
        for hf in history_files:
            if os.path.exists(hf):
                try:
                    size = os.path.getsize(hf)
                    with open(hf, 'w') as f:
                        pass
                    results.append({'file': hf, 'cleared': size})
                except Exception:
                    pass

        # Also clear in-memory history
        try:
            subprocess.run(['history', '-c'], shell=True, capture_output=True)
        except Exception:
            pass

        return {'ok': True, 'cleared': results}


# ── Metadata Scrubbing ───────────────────────────────────────────────────────

class MetadataScrubber:
    """Remove identifying metadata from files."""

    @staticmethod
    def scrub_image(filepath: str, output: str = None) -> Dict:
        """Remove EXIF data from image."""
        if not HAS_PIL:
            return {'ok': False, 'error': 'Pillow not installed'}

        try:
            img = PILImage.open(filepath)
            # Create clean copy without EXIF
            clean = PILImage.new(img.mode, img.size)
            clean.putdata(list(img.getdata()))

            out_path = output or filepath
            clean.save(out_path)

            return {
                'ok': True,
                'file': out_path,
                'message': 'EXIF data removed'
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def scrub_pdf_metadata(filepath: str) -> Dict:
        """Remove metadata from PDF (basic — rewrites info dict)."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read()

            # Remove common metadata keys
            for key in [b'/Author', b'/Creator', b'/Producer',
                        b'/Title', b'/Subject', b'/Keywords']:
                # Simple regex replacement of metadata values
                pattern = key + rb'\s*\([^)]*\)'
                data = re.sub(pattern, key + b' ()', data)

            with open(filepath, 'wb') as f:
                f.write(data)

            return {'ok': True, 'file': filepath, 'message': 'PDF metadata scrubbed'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Anti-Forensics Manager ──────────────────────────────────────────────────

class AntiForensicsManager:
    """Unified interface for anti-forensics operations."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'anti_forensics')
        os.makedirs(self.data_dir, exist_ok=True)
        self.delete = SecureDelete()
        self.timestamps = TimestampManip()
        self.logs = LogCleaner()
        self.scrubber = MetadataScrubber()
        self.audit_log: List[Dict] = []

    def _log_action(self, action: str, target: str, details: str = ''):
        """Internal audit log (ironic for anti-forensics)."""
        self.audit_log.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'target': target,
            'details': details
        })

    def get_capabilities(self) -> Dict:
        """Check available capabilities."""
        return {
            'secure_delete': True,
            'timestamp_manip': True,
            'log_clearing': True,
            'metadata_scrub_image': HAS_PIL,
            'metadata_scrub_pdf': True,
            'free_space_wipe': True,
        }


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_anti_forensics() -> AntiForensicsManager:
    global _instance
    if _instance is None:
        _instance = AntiForensicsManager()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Anti-Forensics module."""
    mgr = get_anti_forensics()

    while True:
        print(f"\n{'='*60}")
        print(f"  Anti-Forensics Toolkit")
        print(f"{'='*60}")
        print()
        print("  1 — Secure Delete File")
        print("  2 — Secure Delete Directory")
        print("  3 — Wipe Free Space")
        print("  4 — View File Timestamps")
        print("  5 — Set Timestamps")
        print("  6 — Clone Timestamps")
        print("  7 — Randomize Timestamps")
        print("  8 — List System Logs")
        print("  9 — Clear Log File")
        print("  10 — Remove Log Entries (pattern)")
        print("  11 — Clear Shell History")
        print("  12 — Scrub Image Metadata")
        print("  13 — Scrub PDF Metadata")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            path = input("  File path: ").strip()
            passes = input("  Overwrite passes (default 3): ").strip()
            if path:
                result = mgr.delete.secure_delete_file(path, int(passes) if passes.isdigit() else 3)
                print(f"    {result.get('message', result.get('error'))}")
        elif choice == '2':
            path = input("  Directory path: ").strip()
            if path:
                confirm = input(f"    DELETE ALL in {path}? (yes/no): ").strip()
                if confirm == 'yes':
                    result = mgr.delete.secure_delete_directory(path)
                    print(f"    Deleted {result.get('files_deleted', 0)} files, {result.get('errors', 0)} errors")
        elif choice == '3':
            mount = input("  Mount point: ").strip()
            if mount:
                result = mgr.delete.wipe_free_space(mount)
                if result['ok']:
                    print(f"    Wiped {result['wiped_mb']} MB of free space")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '4':
            path = input("  File path: ").strip()
            if path:
                result = mgr.timestamps.get_timestamps(path)
                if result['ok']:
                    print(f"    Accessed: {result['accessed']}")
                    print(f"    Modified: {result['modified']}")
                    print(f"    Created:  {result['created']}")
        elif choice == '5':
            path = input("  File path: ").strip()
            date_str = input("  Date (YYYY-MM-DD HH:MM:SS): ").strip()
            if path and date_str:
                try:
                    ts = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').timestamp()
                    result = mgr.timestamps.set_timestamps(path, ts, ts)
                    print(f"    Timestamps set to {date_str}")
                except ValueError:
                    print("    Invalid date format")
        elif choice == '6':
            source = input("  Source file: ").strip()
            target = input("  Target file: ").strip()
            if source and target:
                result = mgr.timestamps.clone_timestamps(source, target)
                print(f"    {result.get('message', result.get('error'))}")
        elif choice == '7':
            path = input("  File path: ").strip()
            if path:
                result = mgr.timestamps.randomize_timestamps(path)
                if result['ok']:
                    print(f"    Set to: {result.get('modified', '?')}")
        elif choice == '8':
            logs = mgr.logs.list_logs()
            for l in logs:
                writable = 'writable' if l['writable'] else 'read-only'
                print(f"    {l['path']}  ({l['size']} bytes)  [{writable}]")
        elif choice == '9':
            path = input("  Log file path: ").strip()
            if path:
                result = mgr.logs.clear_log(path)
                if result['ok']:
                    print(f"    Cleared {result['cleared_bytes']} bytes")
                else:
                    print(f"    {result['error']}")
        elif choice == '10':
            path = input("  Log file path: ").strip()
            pattern = input("  Pattern to remove: ").strip()
            if path and pattern:
                result = mgr.logs.remove_entries(path, pattern)
                if result['ok']:
                    print(f"    Removed {result['removed']} of {result['original_lines']} lines")
                else:
                    print(f"    {result['error']}")
        elif choice == '11':
            result = mgr.logs.clear_bash_history()
            for c in result['cleared']:
                print(f"    Cleared {c['file']} ({c['cleared']} bytes)")
        elif choice == '12':
            path = input("  Image path: ").strip()
            if path:
                result = mgr.scrubber.scrub_image(path)
                print(f"    {result.get('message', result.get('error'))}")
        elif choice == '13':
            path = input("  PDF path: ").strip()
            if path:
                result = mgr.scrubber.scrub_pdf_metadata(path)
                print(f"    {result.get('message', result.get('error'))}")
