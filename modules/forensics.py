"""AUTARCH Forensics Toolkit

Disk imaging, file carving, metadata extraction, timeline building,
hash verification, and chain of custody logging for digital forensics.
"""

DESCRIPTION = "Digital forensics & evidence analysis"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import hashlib
import struct
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

# Optional imports
try:
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS, GPSTAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


# ── File Signatures for Carving ──────────────────────────────────────────────

FILE_SIGNATURES = [
    {'name': 'JPEG', 'ext': '.jpg', 'magic': b'\xFF\xD8\xFF', 'footer': b'\xFF\xD9', 'max_size': 50*1024*1024},
    {'name': 'PNG', 'ext': '.png', 'magic': b'\x89PNG\r\n\x1a\n', 'footer': b'IEND\xAE\x42\x60\x82', 'max_size': 50*1024*1024},
    {'name': 'GIF', 'ext': '.gif', 'magic': b'GIF8', 'footer': b'\x00\x3B', 'max_size': 20*1024*1024},
    {'name': 'PDF', 'ext': '.pdf', 'magic': b'%PDF', 'footer': b'%%EOF', 'max_size': 100*1024*1024},
    {'name': 'ZIP', 'ext': '.zip', 'magic': b'PK\x03\x04', 'footer': None, 'max_size': 500*1024*1024},
    {'name': 'RAR', 'ext': '.rar', 'magic': b'Rar!\x1a\x07', 'footer': None, 'max_size': 500*1024*1024},
    {'name': 'ELF', 'ext': '.elf', 'magic': b'\x7fELF', 'footer': None, 'max_size': 100*1024*1024},
    {'name': 'PE/EXE', 'ext': '.exe', 'magic': b'MZ', 'footer': None, 'max_size': 100*1024*1024},
    {'name': 'SQLite', 'ext': '.sqlite', 'magic': b'SQLite format 3\x00', 'footer': None, 'max_size': 500*1024*1024},
    {'name': 'DOCX', 'ext': '.docx', 'magic': b'PK\x03\x04', 'footer': None, 'max_size': 100*1024*1024},
    {'name': '7z', 'ext': '.7z', 'magic': b"7z\xBC\xAF'\x1C", 'footer': None, 'max_size': 500*1024*1024},
    {'name': 'BMP', 'ext': '.bmp', 'magic': b'BM', 'footer': None, 'max_size': 50*1024*1024},
    {'name': 'MP3', 'ext': '.mp3', 'magic': b'\xFF\xFB', 'footer': None, 'max_size': 50*1024*1024},
    {'name': 'MP4', 'ext': '.mp4', 'magic': b'\x00\x00\x00\x18ftyp', 'footer': None, 'max_size': 1024*1024*1024},
    {'name': 'AVI', 'ext': '.avi', 'magic': b'RIFF', 'footer': None, 'max_size': 1024*1024*1024},
]


# ── Chain of Custody Logger ──────────────────────────────────────────────────

class CustodyLog:
    """Chain of custody logging for forensic evidence."""

    def __init__(self, data_dir: str):
        self.log_file = os.path.join(data_dir, 'custody_log.json')
        self.entries: List[Dict] = []
        self._load()

    def _load(self):
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file) as f:
                    self.entries = json.load(f)
            except Exception:
                pass

    def _save(self):
        with open(self.log_file, 'w') as f:
            json.dump(self.entries, f, indent=2)

    def log(self, action: str, target: str, details: str = "",
            evidence_hash: str = "") -> Dict:
        """Log a forensic action."""
        entry = {
            'id': len(self.entries) + 1,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': action,
            'target': target,
            'details': details,
            'evidence_hash': evidence_hash,
            'user': os.getenv('USER', os.getenv('USERNAME', 'unknown'))
        }
        self.entries.append(entry)
        self._save()
        return entry

    def get_log(self) -> List[Dict]:
        return self.entries


# ── Forensics Engine ─────────────────────────────────────────────────────────

class ForensicsEngine:
    """Digital forensics toolkit."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'forensics')
        os.makedirs(self.data_dir, exist_ok=True)
        self.evidence_dir = os.path.join(self.data_dir, 'evidence')
        os.makedirs(self.evidence_dir, exist_ok=True)
        self.carved_dir = os.path.join(self.data_dir, 'carved')
        os.makedirs(self.carved_dir, exist_ok=True)
        self.custody = CustodyLog(self.data_dir)
        self.dd = find_tool('dd') or shutil.which('dd')

    # ── Hash Verification ────────────────────────────────────────────────

    def hash_file(self, filepath: str, algorithms: List[str] = None) -> Dict:
        """Calculate file hashes for evidence integrity."""
        algorithms = algorithms or ['md5', 'sha1', 'sha256']

        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        try:
            hashers = {alg: hashlib.new(alg) for alg in algorithms}
            file_size = os.path.getsize(filepath)

            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    for h in hashers.values():
                        h.update(chunk)

            hashes = {alg: h.hexdigest() for alg, h in hashers.items()}

            self.custody.log('hash_verify', filepath,
                            f'Hashes: {", ".join(f"{k}={v[:16]}..." for k, v in hashes.items())}',
                            hashes.get('sha256', ''))

            return {
                'ok': True, 'file': filepath,
                'size': file_size, 'hashes': hashes
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def verify_hash(self, filepath: str, expected_hash: str,
                     algorithm: str = None) -> Dict:
        """Verify file against expected hash."""
        # Auto-detect algorithm from hash length
        if not algorithm:
            hash_len = len(expected_hash)
            algorithm = {32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512'}.get(hash_len)
            if not algorithm:
                return {'ok': False, 'error': f'Cannot detect algorithm for hash length {hash_len}'}

        result = self.hash_file(filepath, [algorithm])
        if not result['ok']:
            return result

        actual = result['hashes'][algorithm]
        match = actual.lower() == expected_hash.lower()

        self.custody.log('hash_verify', filepath,
                         f'Expected: {expected_hash[:16]}... Match: {match}')

        return {
            'ok': True, 'match': match,
            'algorithm': algorithm,
            'expected': expected_hash,
            'actual': actual,
            'file': filepath
        }

    # ── Disk Imaging ─────────────────────────────────────────────────────

    def create_image(self, source: str, output: str = None,
                      block_size: int = 4096) -> Dict:
        """Create forensic disk image using dd."""
        if not self.dd:
            return {'ok': False, 'error': 'dd not found'}

        if not output:
            name = Path(source).name.replace('/', '_')
            output = os.path.join(self.evidence_dir, f'{name}_{int(time.time())}.img')

        self.custody.log('disk_image', source, f'Creating image: {output}')

        try:
            result = subprocess.run(
                [self.dd, f'if={source}', f'of={output}', f'bs={block_size}',
                 'conv=noerror,sync', 'status=progress'],
                capture_output=True, text=True, timeout=3600
            )

            if os.path.exists(output):
                # Hash the image
                hashes = self.hash_file(output, ['md5', 'sha256'])

                self.custody.log('disk_image_complete', output,
                                 f'Image created, SHA256: {hashes.get("hashes", {}).get("sha256", "?")}')

                return {
                    'ok': True, 'source': source, 'output': output,
                    'size': os.path.getsize(output),
                    'hashes': hashes.get('hashes', {}),
                    'dd_output': result.stderr
                }
            return {'ok': False, 'error': 'Image file not created', 'stderr': result.stderr}

        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': 'Imaging timed out (1hr limit)'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── File Carving ─────────────────────────────────────────────────────

    def carve_files(self, source: str, file_types: List[str] = None,
                    max_files: int = 100) -> Dict:
        """Recover files from raw data by magic byte signatures."""
        if not os.path.exists(source):
            return {'ok': False, 'error': 'Source file not found'}

        self.custody.log('file_carving', source, f'Starting carve, types={file_types}')

        # Filter signatures
        sigs = FILE_SIGNATURES
        if file_types:
            type_set = {t.lower() for t in file_types}
            sigs = [s for s in sigs if s['name'].lower() in type_set or
                     s['ext'].lstrip('.').lower() in type_set]

        carved = []
        file_size = os.path.getsize(source)
        chunk_size = 1024 * 1024  # 1MB chunks

        try:
            with open(source, 'rb') as f:
                offset = 0
                while offset < file_size and len(carved) < max_files:
                    f.seek(offset)
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    for sig in sigs:
                        pos = 0
                        while pos < len(chunk) and len(carved) < max_files:
                            idx = chunk.find(sig['magic'], pos)
                            if idx == -1:
                                break

                            abs_offset = offset + idx
                            # Try to find file end
                            file_end = abs_offset + sig['max_size']
                            if sig['footer']:
                                f.seek(abs_offset)
                                search_data = f.read(min(sig['max_size'], file_size - abs_offset))
                                footer_pos = search_data.find(sig['footer'], len(sig['magic']))
                                if footer_pos != -1:
                                    file_end = abs_offset + footer_pos + len(sig['footer'])

                            # Extract file
                            extract_size = min(file_end - abs_offset, sig['max_size'])
                            f.seek(abs_offset)
                            file_data = f.read(extract_size)

                            # Save carved file
                            carved_name = f'carved_{len(carved):04d}_{sig["name"]}{sig["ext"]}'
                            carved_path = os.path.join(self.carved_dir, carved_name)
                            with open(carved_path, 'wb') as cf:
                                cf.write(file_data)

                            file_hash = hashlib.md5(file_data).hexdigest()
                            carved.append({
                                'name': carved_name,
                                'path': carved_path,
                                'type': sig['name'],
                                'offset': abs_offset,
                                'size': len(file_data),
                                'md5': file_hash
                            })

                            pos = idx + len(sig['magic'])

                    offset += chunk_size - max(len(s['magic']) for s in sigs)

            self.custody.log('file_carving_complete', source,
                             f'Carved {len(carved)} files')

            return {
                'ok': True, 'source': source,
                'carved': carved, 'count': len(carved),
                'output_dir': self.carved_dir
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Metadata Extraction ──────────────────────────────────────────────

    def extract_metadata(self, filepath: str) -> Dict:
        """Extract metadata from files (EXIF, PDF, Office, etc.)."""
        if not os.path.exists(filepath):
            return {'ok': False, 'error': 'File not found'}

        ext = Path(filepath).suffix.lower()
        metadata = {
            'file': filepath,
            'name': Path(filepath).name,
            'size': os.path.getsize(filepath),
            'created': datetime.fromtimestamp(os.path.getctime(filepath), timezone.utc).isoformat(),
            'modified': datetime.fromtimestamp(os.path.getmtime(filepath), timezone.utc).isoformat(),
            'accessed': datetime.fromtimestamp(os.path.getatime(filepath), timezone.utc).isoformat(),
        }

        # EXIF for images
        if ext in ('.jpg', '.jpeg', '.tiff', '.tif', '.png') and HAS_PIL:
            try:
                img = PILImage.open(filepath)
                metadata['image'] = {
                    'width': img.size[0], 'height': img.size[1],
                    'format': img.format, 'mode': img.mode
                }
                exif = img._getexif()
                if exif:
                    exif_data = {}
                    gps_data = {}
                    for tag_id, value in exif.items():
                        tag = TAGS.get(tag_id, tag_id)
                        if tag == 'GPSInfo':
                            for gps_id, gps_val in value.items():
                                gps_tag = GPSTAGS.get(gps_id, gps_id)
                                gps_data[str(gps_tag)] = str(gps_val)
                        else:
                            # Convert bytes to string for JSON serialization
                            if isinstance(value, bytes):
                                try:
                                    value = value.decode('utf-8', errors='replace')
                                except Exception:
                                    value = value.hex()
                            exif_data[str(tag)] = str(value)
                    metadata['exif'] = exif_data
                    if gps_data:
                        metadata['gps'] = gps_data
            except Exception:
                pass

        # PDF metadata
        elif ext == '.pdf':
            try:
                with open(filepath, 'rb') as f:
                    content = f.read(4096)
                    # Extract info dict
                    for key in [b'/Title', b'/Author', b'/Subject', b'/Creator',
                                b'/Producer', b'/CreationDate', b'/ModDate']:
                        pattern = key + rb'\s*\(([^)]*)\)'
                        m = re.search(pattern, content)
                        if m:
                            k = key.decode().lstrip('/')
                            metadata.setdefault('pdf', {})[k] = m.group(1).decode('utf-8', errors='replace')
            except Exception:
                pass

        # Generic file header
        try:
            with open(filepath, 'rb') as f:
                header = f.read(16)
                metadata['magic_bytes'] = header.hex()
                for sig in FILE_SIGNATURES:
                    if header.startswith(sig['magic']):
                        metadata['detected_type'] = sig['name']
                        break
        except Exception:
            pass

        self.custody.log('metadata_extract', filepath, f'Type: {metadata.get("detected_type", "unknown")}')

        return {'ok': True, **metadata}

    # ── Timeline Builder ─────────────────────────────────────────────────

    def build_timeline(self, directory: str, recursive: bool = True,
                        max_entries: int = 10000) -> Dict:
        """Build filesystem timeline from directory metadata."""
        if not os.path.exists(directory):
            return {'ok': False, 'error': 'Directory not found'}

        events = []
        count = 0

        walk_fn = os.walk if recursive else lambda d: [(d, [], os.listdir(d))]
        for root, dirs, files in walk_fn(directory):
            for name in files:
                if count >= max_entries:
                    break
                filepath = os.path.join(root, name)
                try:
                    stat = os.stat(filepath)
                    events.append({
                        'type': 'modified',
                        'timestamp': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                        'epoch': stat.st_mtime,
                        'file': filepath,
                        'size': stat.st_size
                    })
                    events.append({
                        'type': 'created',
                        'timestamp': datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
                        'epoch': stat.st_ctime,
                        'file': filepath,
                        'size': stat.st_size
                    })
                    events.append({
                        'type': 'accessed',
                        'timestamp': datetime.fromtimestamp(stat.st_atime, timezone.utc).isoformat(),
                        'epoch': stat.st_atime,
                        'file': filepath,
                        'size': stat.st_size
                    })
                    count += 1
                except (OSError, PermissionError):
                    pass

        # Sort by timestamp
        events.sort(key=lambda e: e['epoch'])

        self.custody.log('timeline_build', directory,
                         f'{count} files, {len(events)} events')

        return {
            'ok': True, 'directory': directory,
            'events': events, 'event_count': len(events),
            'file_count': count
        }

    # ── Evidence Management ──────────────────────────────────────────────

    def list_evidence(self) -> List[Dict]:
        """List evidence files."""
        evidence = []
        edir = Path(self.evidence_dir)
        for f in sorted(edir.iterdir()):
            if f.is_file():
                evidence.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat()
                })
        return evidence

    def list_carved(self) -> List[Dict]:
        """List carved files."""
        carved = []
        cdir = Path(self.carved_dir)
        for f in sorted(cdir.iterdir()):
            if f.is_file():
                carved.append({
                    'name': f.name,
                    'path': str(f),
                    'size': f.stat().st_size
                })
        return carved

    def get_custody_log(self) -> List[Dict]:
        """Get chain of custody log."""
        return self.custody.get_log()


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_forensics() -> ForensicsEngine:
    global _instance
    if _instance is None:
        _instance = ForensicsEngine()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Forensics module."""
    engine = get_forensics()

    while True:
        print(f"\n{'='*60}")
        print(f"  Digital Forensics Toolkit")
        print(f"{'='*60}")
        print()
        print("  1 — Hash File (integrity verification)")
        print("  2 — Verify Hash")
        print("  3 — Create Disk Image")
        print("  4 — Carve Files (recover deleted)")
        print("  5 — Extract Metadata (EXIF/PDF/headers)")
        print("  6 — Build Timeline")
        print("  7 — List Evidence")
        print("  8 — List Carved Files")
        print("  9 — Chain of Custody Log")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            filepath = input("  File path: ").strip()
            if filepath:
                result = engine.hash_file(filepath)
                if result['ok']:
                    print(f"    Size: {result['size']} bytes")
                    for alg, h in result['hashes'].items():
                        print(f"    {alg.upper()}: {h}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '2':
            filepath = input("  File path: ").strip()
            expected = input("  Expected hash: ").strip()
            if filepath and expected:
                result = engine.verify_hash(filepath, expected)
                if result['ok']:
                    status = 'MATCH' if result['match'] else 'MISMATCH'
                    print(f"    {status} ({result['algorithm'].upper()})")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '3':
            source = input("  Source device/file: ").strip()
            output = input("  Output path (blank=auto): ").strip() or None
            if source:
                result = engine.create_image(source, output)
                if result['ok']:
                    mb = result['size'] / (1024*1024)
                    print(f"    Image created: {result['output']} ({mb:.1f} MB)")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '4':
            source = input("  Source file/image: ").strip()
            types = input("  File types (blank=all, comma-sep): ").strip()
            if source:
                file_types = [t.strip() for t in types.split(',')] if types else None
                result = engine.carve_files(source, file_types)
                if result['ok']:
                    print(f"    Carved {result['count']} files to {result['output_dir']}")
                    for c in result['carved'][:10]:
                        print(f"      {c['name']}  {c['type']}  {c['size']} bytes  offset={c['offset']}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '5':
            filepath = input("  File path: ").strip()
            if filepath:
                result = engine.extract_metadata(filepath)
                if result['ok']:
                    print(f"    Name: {result['name']}")
                    print(f"    Size: {result['size']}")
                    print(f"    Type: {result.get('detected_type', 'unknown')}")
                    if 'exif' in result:
                        print(f"    EXIF entries: {len(result['exif'])}")
                        for k, v in list(result['exif'].items())[:5]:
                            print(f"      {k}: {v[:50]}")
                    if 'gps' in result:
                        print(f"    GPS data: {result['gps']}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '6':
            directory = input("  Directory path: ").strip()
            if directory:
                result = engine.build_timeline(directory)
                if result['ok']:
                    print(f"    {result['file_count']} files, {result['event_count']} events")
                    for e in result['events'][:10]:
                        print(f"      {e['timestamp']}  {e['type']:<10}  {Path(e['file']).name}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '7':
            for e in engine.list_evidence():
                mb = e['size'] / (1024*1024)
                print(f"    {e['name']}  ({mb:.1f} MB)")
        elif choice == '8':
            for c in engine.list_carved():
                print(f"    {c['name']}  ({c['size']} bytes)")
        elif choice == '9':
            log = engine.get_custody_log()
            print(f"    {len(log)} entries:")
            for entry in log[-10:]:
                print(f"      [{entry['timestamp'][:19]}] {entry['action']}: {entry['target']}")
