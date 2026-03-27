"""AUTARCH Reverse Engineering Toolkit

Binary analysis, PE/ELF parsing, disassembly, YARA scanning,
hex viewing, packer detection, and Ghidra headless integration.
"""

DESCRIPTION = "Binary analysis, disassembly & reverse engineering"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import sys
import re
import math
import json
import struct
import hashlib
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.paths import get_data_dir, find_tool
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

    def find_tool(name, extra_paths=None):
        import shutil
        return shutil.which(name)

try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        CYAN = BOLD = GREEN = YELLOW = RED = WHITE = DIM = RESET = ""
    def clear_screen(): pass
    def display_banner(): pass

# Optional: capstone disassembler
try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# Optional: yara-python
try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False


# ── Magic Bytes ──────────────────────────────────────────────────────────────

MAGIC_BYTES = {
    b'\x4d\x5a':             'PE',
    b'\x7fELF':              'ELF',
    b'\xfe\xed\xfa\xce':     'Mach-O (32-bit)',
    b'\xfe\xed\xfa\xcf':     'Mach-O (64-bit)',
    b'\xce\xfa\xed\xfe':     'Mach-O (32-bit, reversed)',
    b'\xcf\xfa\xed\xfe':     'Mach-O (64-bit, reversed)',
    b'\xca\xfe\xba\xbe':     'Mach-O (Universal)',
    b'\x50\x4b\x03\x04':     'ZIP/JAR/APK/DOCX',
    b'\x50\x4b\x05\x06':     'ZIP (empty)',
    b'\x25\x50\x44\x46':     'PDF',
    b'\xd0\xcf\x11\xe0':     'OLE2 (DOC/XLS/PPT)',
    b'\x89\x50\x4e\x47':     'PNG',
    b'\xff\xd8\xff':          'JPEG',
    b'\x47\x49\x46\x38':     'GIF',
    b'\x1f\x8b':              'GZIP',
    b'\x42\x5a\x68':          'BZIP2',
    b'\xfd\x37\x7a\x58':     'XZ',
    b'\x37\x7a\xbc\xaf':     '7-Zip',
    b'\x52\x61\x72\x21':     'RAR',
    b'\xca\xfe\xba\xbe':     'Java Class / Mach-O Universal',
    b'\x7f\x45\x4c\x46':     'ELF',
    b'\x23\x21':              'Script (shebang)',
    b'\x00\x61\x73\x6d':     'WebAssembly',
    b'\xed\xab\xee\xdb':     'RPM',
    b'\x21\x3c\x61\x72':     'Debian/AR archive',
}


# ── Packer Signatures ───────────────────────────────────────────────────────

PACKER_SIGNATURES = {
    'UPX': {
        'section_names': [b'UPX0', b'UPX1', b'UPX2', b'UPX!'],
        'magic': [b'UPX!', b'UPX0', b'\x55\x50\x58'],
        'description': 'Ultimate Packer for Executables',
    },
    'Themida': {
        'section_names': [b'.themida', b'.winlice'],
        'magic': [],
        'description': 'Themida / WinLicense protector',
    },
    'ASPack': {
        'section_names': [b'.aspack', b'.adata'],
        'magic': [b'\x60\xe8\x00\x00\x00\x00\x5d\x81\xed'],
        'description': 'ASPack packer',
    },
    'MPRESS': {
        'section_names': [b'.MPRESS1', b'.MPRESS2'],
        'magic': [],
        'description': 'MPRESS packer',
    },
    'VMProtect': {
        'section_names': [b'.vmp0', b'.vmp1', b'.vmp2'],
        'magic': [],
        'description': 'VMProtect software protection',
    },
    'PECompact': {
        'section_names': [b'PEC2', b'pec1', b'pec2', b'PEC2TO'],
        'magic': [],
        'description': 'PECompact packer',
    },
    'Petite': {
        'section_names': [b'.petite'],
        'magic': [b'\xb8\x00\x00\x00\x00\x66\x9c\x60\x50'],
        'description': 'Petite packer',
    },
    'NSPack': {
        'section_names': [b'.nsp0', b'.nsp1', b'.nsp2', b'nsp0', b'nsp1'],
        'magic': [],
        'description': 'NSPack (North Star) packer',
    },
    'Enigma': {
        'section_names': [b'.enigma1', b'.enigma2'],
        'magic': [],
        'description': 'Enigma Protector',
    },
    'MEW': {
        'section_names': [b'MEW'],
        'magic': [],
        'description': 'MEW packer',
    },
}


# ── PE Constants ─────────────────────────────────────────────────────────────

PE_MACHINE_TYPES = {
    0x0:    'Unknown',
    0x14c:  'x86 (i386)',
    0x166:  'MIPS R4000',
    0x1a2:  'Hitachi SH3',
    0x1a6:  'Hitachi SH4',
    0x1c0:  'ARM',
    0x1c4:  'ARM Thumb-2',
    0x200:  'Intel IA-64',
    0x8664: 'x86-64 (AMD64)',
    0xaa64: 'ARM64 (AArch64)',
    0x5032: 'RISC-V 32-bit',
    0x5064: 'RISC-V 64-bit',
}

PE_SECTION_FLAGS = {
    0x00000020: 'CODE',
    0x00000040: 'INITIALIZED_DATA',
    0x00000080: 'UNINITIALIZED_DATA',
    0x02000000: 'DISCARDABLE',
    0x04000000: 'NOT_CACHED',
    0x08000000: 'NOT_PAGED',
    0x10000000: 'SHARED',
    0x20000000: 'EXECUTE',
    0x40000000: 'READ',
    0x80000000: 'WRITE',
}


# ── ELF Constants ────────────────────────────────────────────────────────────

ELF_MACHINE_TYPES = {
    0:   'None',
    2:   'SPARC',
    3:   'x86',
    8:   'MIPS',
    20:  'PowerPC',
    21:  'PowerPC64',
    40:  'ARM',
    43:  'SPARC V9',
    50:  'IA-64',
    62:  'x86-64',
    183: 'AArch64 (ARM64)',
    243: 'RISC-V',
    247: 'eBPF',
}

ELF_TYPES = {0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE'}

ELF_OSABI = {
    0: 'UNIX System V', 1: 'HP-UX', 2: 'NetBSD', 3: 'Linux',
    6: 'Solaris', 7: 'AIX', 8: 'IRIX', 9: 'FreeBSD', 12: 'OpenBSD',
}

ELF_SH_TYPES = {
    0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
    5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
    11: 'DYNSYM',
}

ELF_PT_TYPES = {
    0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE',
    5: 'SHLIB', 6: 'PHDR', 7: 'TLS',
    0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
    0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY',
}


# ── ReverseEngineer Class ────────────────────────────────────────────────────

class ReverseEngineer:
    """Comprehensive binary analysis and reverse engineering toolkit."""

    _instance = None

    def __init__(self):
        data_dir = get_data_dir() if callable(get_data_dir) else get_data_dir
        self.storage_dir = Path(str(data_dir)) / 'reverse_eng'
        self.yara_rules_dir = self.storage_dir / 'yara_rules'
        self.cache_dir = self.storage_dir / 'cache'
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.yara_rules_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._analysis_cache: Dict[str, Any] = {}

    # ── File Type Detection ──────────────────────────────────────────────

    def get_file_type(self, file_path: str) -> Dict[str, str]:
        """Identify file type from magic bytes."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return {'type': 'unknown', 'error': 'File not found'}

        try:
            with open(p, 'rb') as f:
                header = f.read(16)
        except Exception as e:
            return {'type': 'unknown', 'error': str(e)}

        if len(header) < 2:
            return {'type': 'empty', 'description': 'File too small'}

        # Check magic bytes, longest match first
        for magic, file_type in sorted(MAGIC_BYTES.items(), key=lambda x: -len(x[0])):
            if header[:len(magic)] == magic:
                return {'type': file_type, 'magic_hex': magic.hex()}

        # Heuristic: check if text file
        try:
            with open(p, 'rb') as f:
                sample = f.read(8192)
            text_chars = set(range(7, 14)) | set(range(32, 127)) | {0}
            non_text = sum(1 for b in sample if b not in text_chars)
            if non_text / max(len(sample), 1) < 0.05:
                return {'type': 'Text', 'description': 'ASCII/UTF-8 text file'}
        except Exception:
            pass

        return {'type': 'unknown', 'magic_hex': header[:8].hex()}

    # ── Entropy Calculation ──────────────────────────────────────────────

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data. Returns 0.0 to 8.0."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    def section_entropy(self, file_path: str) -> List[Dict[str, Any]]:
        """Calculate entropy per section for PE/ELF binaries."""
        ft = self.get_file_type(file_path)
        file_type = ft.get('type', '')

        results = []
        if file_type == 'PE':
            pe_info = self.parse_pe(file_path)
            if 'error' not in pe_info:
                with open(file_path, 'rb') as f:
                    for sec in pe_info.get('sections', []):
                        offset = sec.get('raw_offset', 0)
                        size = sec.get('raw_size', 0)
                        if size > 0 and offset > 0:
                            f.seek(offset)
                            data = f.read(size)
                            ent = self.calculate_entropy(data)
                            results.append({
                                'name': sec.get('name', ''),
                                'offset': offset,
                                'size': size,
                                'entropy': ent,
                                'packed': ent > 7.0,
                            })
        elif file_type == 'ELF':
            elf_info = self.parse_elf(file_path)
            if 'error' not in elf_info:
                with open(file_path, 'rb') as f:
                    for sec in elf_info.get('sections', []):
                        offset = sec.get('offset', 0)
                        size = sec.get('size', 0)
                        if size > 0 and offset > 0:
                            f.seek(offset)
                            data = f.read(size)
                            ent = self.calculate_entropy(data)
                            results.append({
                                'name': sec.get('name', ''),
                                'offset': offset,
                                'size': size,
                                'entropy': ent,
                                'packed': ent > 7.0,
                            })
        return results

    # ── Comprehensive Binary Analysis ────────────────────────────────────

    def analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """Comprehensive binary analysis: type, hashes, entropy, strings, architecture."""
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            return {'error': f'File not found: {file_path}'}

        stat = p.stat()

        # Read file data
        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {'error': f'Cannot read file: {e}'}

        # File type
        file_type = self.get_file_type(file_path)

        # Hashes
        hashes = {
            'md5': hashlib.md5(data).hexdigest(),
            'sha1': hashlib.sha1(data).hexdigest(),
            'sha256': hashlib.sha256(data).hexdigest(),
        }

        # Overall entropy
        overall_entropy = self.calculate_entropy(data)

        # Section entropy
        sec_entropy = self.section_entropy(file_path)

        # Architecture detection
        arch = 'unknown'
        ftype = file_type.get('type', '')
        if ftype == 'PE':
            pe = self.parse_pe(file_path)
            arch = pe.get('machine_str', 'unknown')
        elif ftype == 'ELF':
            elf = self.parse_elf(file_path)
            arch = elf.get('machine_str', 'unknown')

        # Extract strings (limited to first 1MB for speed)
        sample = data[:1024 * 1024]
        strings = self._extract_strings_from_data(sample, min_length=4)

        # Packer detection
        packer = self.detect_packer(file_path)

        result = {
            'file': str(p.absolute()),
            'name': p.name,
            'size': stat.st_size,
            'size_human': self._human_size(stat.st_size),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'file_type': file_type,
            'architecture': arch,
            'hashes': hashes,
            'entropy': overall_entropy,
            'entropy_level': 'high' if overall_entropy > 7.0 else ('medium' if overall_entropy > 6.0 else 'low'),
            'section_entropy': sec_entropy,
            'strings_count': len(strings),
            'strings_preview': strings[:100],
            'packer': packer,
        }

        # Add imports/exports if applicable
        if ftype == 'PE':
            result['imports'] = self.get_imports(file_path)
            result['exports'] = self.get_exports(file_path)
        elif ftype == 'ELF':
            result['imports'] = self.get_imports(file_path)
            result['exports'] = self.get_exports(file_path)

        # Cache result
        self._analysis_cache[file_path] = result
        return result

    # ── PE Parsing ───────────────────────────────────────────────────────

    def parse_pe(self, file_path: str) -> Dict[str, Any]:
        """Parse PE (Portable Executable) headers using struct.unpack."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found'}

        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {'error': str(e)}

        if len(data) < 64 or data[:2] != b'\x4d\x5a':
            return {'error': 'Not a valid PE file (missing MZ header)'}

        # DOS Header
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        if e_lfanew + 24 > len(data):
            return {'error': 'Invalid PE offset'}

        # PE Signature
        pe_sig = data[e_lfanew:e_lfanew + 4]
        if pe_sig != b'PE\x00\x00':
            return {'error': 'Invalid PE signature'}

        # COFF Header (20 bytes after PE signature)
        coff_offset = e_lfanew + 4
        if coff_offset + 20 > len(data):
            return {'error': 'Truncated COFF header'}

        machine, num_sections, time_stamp, sym_table_ptr, num_symbols, \
            opt_header_size, characteristics = struct.unpack_from(
                '<HHIIIHH', data, coff_offset)

        machine_str = PE_MACHINE_TYPES.get(machine, f'Unknown (0x{machine:04x})')
        timestamp_str = datetime.utcfromtimestamp(time_stamp).isoformat() if time_stamp else 'N/A'

        # Optional Header
        opt_offset = coff_offset + 20
        if opt_offset + 2 > len(data):
            return {'error': 'Truncated optional header'}

        opt_magic = struct.unpack_from('<H', data, opt_offset)[0]
        is_pe32_plus = (opt_magic == 0x20b)  # PE32+ (64-bit)
        is_pe32 = (opt_magic == 0x10b)       # PE32 (32-bit)

        opt_info = {'magic': f'0x{opt_magic:04x}', 'format': 'PE32+' if is_pe32_plus else 'PE32'}

        if is_pe32_plus and opt_offset + 112 <= len(data):
            _, major_link, minor_link, code_size, init_data, uninit_data, \
                entry_point, code_base = struct.unpack_from('<HBBIIIII', data, opt_offset)
            image_base = struct.unpack_from('<Q', data, opt_offset + 24)[0]
            section_align, file_align = struct.unpack_from('<II', data, opt_offset + 32)[0:2]
            opt_info.update({
                'linker_version': f'{major_link}.{minor_link}',
                'code_size': code_size,
                'entry_point': f'0x{entry_point:08x}',
                'image_base': f'0x{image_base:016x}',
                'section_alignment': section_align,
                'file_alignment': file_align,
            })
        elif is_pe32 and opt_offset + 96 <= len(data):
            _, major_link, minor_link, code_size, init_data, uninit_data, \
                entry_point, code_base = struct.unpack_from('<HBBIIIII', data, opt_offset)
            image_base = struct.unpack_from('<I', data, opt_offset + 28)[0]
            section_align, file_align = struct.unpack_from('<II', data, opt_offset + 32)[0:2]
            opt_info.update({
                'linker_version': f'{major_link}.{minor_link}',
                'code_size': code_size,
                'entry_point': f'0x{entry_point:08x}',
                'image_base': f'0x{image_base:08x}',
                'section_alignment': section_align,
                'file_alignment': file_align,
            })

        # Parse Data Directories (for imports/exports)
        data_dirs = []
        if is_pe32_plus:
            dd_offset = opt_offset + 112
            num_dd = struct.unpack_from('<I', data, opt_offset + 108)[0] if opt_offset + 112 <= len(data) else 0
        elif is_pe32:
            dd_offset = opt_offset + 96
            num_dd = struct.unpack_from('<I', data, opt_offset + 92)[0] if opt_offset + 96 <= len(data) else 0
        else:
            dd_offset = 0
            num_dd = 0

        dd_names = ['Export', 'Import', 'Resource', 'Exception', 'Security',
                     'BaseReloc', 'Debug', 'Architecture', 'GlobalPtr', 'TLS',
                     'LoadConfig', 'BoundImport', 'IAT', 'DelayImport', 'CLR', 'Reserved']
        for i in range(min(num_dd, 16)):
            off = dd_offset + i * 8
            if off + 8 <= len(data):
                rva, size = struct.unpack_from('<II', data, off)
                if rva or size:
                    data_dirs.append({
                        'name': dd_names[i] if i < len(dd_names) else f'Dir_{i}',
                        'rva': f'0x{rva:08x}',
                        'size': size,
                    })

        # Section Headers
        sections = []
        sec_offset = opt_offset + opt_header_size
        for i in range(num_sections):
            off = sec_offset + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8]
            name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
            vsize, vaddr, raw_size, raw_offset, reloc_ptr, linenum_ptr, \
                num_relocs, num_linenums, chars = struct.unpack_from(
                    '<IIIIIIHHI', data, off + 8)

            flags = []
            for flag_val, flag_name in PE_SECTION_FLAGS.items():
                if chars & flag_val:
                    flags.append(flag_name)

            sections.append({
                'name': name,
                'virtual_size': vsize,
                'virtual_address': f'0x{vaddr:08x}',
                'raw_size': raw_size,
                'raw_offset': raw_offset,
                'characteristics': f'0x{chars:08x}',
                'flags': flags,
            })

        result = {
            'format': 'PE',
            'machine': f'0x{machine:04x}',
            'machine_str': machine_str,
            'num_sections': num_sections,
            'timestamp': timestamp_str,
            'timestamp_raw': time_stamp,
            'characteristics': f'0x{characteristics:04x}',
            'optional_header': opt_info,
            'data_directories': data_dirs,
            'sections': sections,
        }

        return result

    # ── ELF Parsing ──────────────────────────────────────────────────────

    def parse_elf(self, file_path: str) -> Dict[str, Any]:
        """Parse ELF (Executable and Linkable Format) headers using struct.unpack."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found'}

        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {'error': str(e)}

        if len(data) < 16 or data[:4] != b'\x7fELF':
            return {'error': 'Not a valid ELF file'}

        # ELF Identification
        ei_class = data[4]  # 1=32-bit, 2=64-bit
        ei_data = data[5]   # 1=little-endian, 2=big-endian
        ei_version = data[6]
        ei_osabi = data[7]

        is_64 = (ei_class == 2)
        endian = '<' if ei_data == 1 else '>'
        bits_str = '64-bit' if is_64 else '32-bit'
        endian_str = 'Little Endian' if ei_data == 1 else 'Big Endian'

        # ELF Header
        if is_64:
            if len(data) < 64:
                return {'error': 'Truncated ELF64 header'}
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, \
                e_shnum, e_shstrndx = struct.unpack_from(
                    f'{endian}HHIQQQIHHHHHH', data, 16)
        else:
            if len(data) < 52:
                return {'error': 'Truncated ELF32 header'}
            e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, \
                e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, \
                e_shnum, e_shstrndx = struct.unpack_from(
                    f'{endian}HHIIIIIHHHHHH', data, 16)

        machine_str = ELF_MACHINE_TYPES.get(e_machine, f'Unknown ({e_machine})')
        type_str = ELF_TYPES.get(e_type, f'Unknown ({e_type})')
        osabi_str = ELF_OSABI.get(ei_osabi, f'Unknown ({ei_osabi})')

        # Section Headers
        sections = []
        shstrtab_data = b''
        if e_shstrndx < e_shnum and e_shoff > 0:
            strtab_off = e_shoff + e_shstrndx * e_shentsize
            if is_64 and strtab_off + 64 <= len(data):
                sh_offset = struct.unpack_from(f'{endian}Q', data, strtab_off + 24)[0]
                sh_size = struct.unpack_from(f'{endian}Q', data, strtab_off + 32)[0]
            elif not is_64 and strtab_off + 40 <= len(data):
                sh_offset = struct.unpack_from(f'{endian}I', data, strtab_off + 16)[0]
                sh_size = struct.unpack_from(f'{endian}I', data, strtab_off + 20)[0]
            else:
                sh_offset = 0
                sh_size = 0
            if sh_offset + sh_size <= len(data):
                shstrtab_data = data[sh_offset:sh_offset + sh_size]

        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            if is_64:
                if off + 64 > len(data):
                    break
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
                    sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                        f'{endian}IIQQQQIIQQ', data, off)
            else:
                if off + 40 > len(data):
                    break
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, \
                    sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from(
                        f'{endian}IIIIIIIIII', data, off)

            # Resolve section name from string table
            name = ''
            if sh_name < len(shstrtab_data):
                end = shstrtab_data.index(b'\x00', sh_name) if b'\x00' in shstrtab_data[sh_name:] else len(shstrtab_data)
                name = shstrtab_data[sh_name:end].decode('ascii', errors='replace')

            type_name = ELF_SH_TYPES.get(sh_type, f'0x{sh_type:x}')

            sections.append({
                'name': name,
                'type': type_name,
                'type_raw': sh_type,
                'flags': f'0x{sh_flags:x}',
                'address': f'0x{sh_addr:x}',
                'offset': sh_offset,
                'size': sh_size,
                'link': sh_link,
                'info': sh_info,
                'alignment': sh_addralign,
                'entry_size': sh_entsize,
            })

        # Program Headers
        program_headers = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            if is_64:
                if off + 56 > len(data):
                    break
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, \
                    p_memsz, p_align = struct.unpack_from(
                        f'{endian}IIQQQQQQ', data, off)
            else:
                if off + 32 > len(data):
                    break
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, \
                    p_flags, p_align = struct.unpack_from(
                        f'{endian}IIIIIIII', data, off)

            pt_name = ELF_PT_TYPES.get(p_type, f'0x{p_type:x}')
            perm_str = ''
            perm_str += 'R' if p_flags & 4 else '-'
            perm_str += 'W' if p_flags & 2 else '-'
            perm_str += 'X' if p_flags & 1 else '-'

            program_headers.append({
                'type': pt_name,
                'type_raw': p_type,
                'flags': perm_str,
                'offset': f'0x{p_offset:x}',
                'vaddr': f'0x{p_vaddr:x}',
                'paddr': f'0x{p_paddr:x}',
                'file_size': p_filesz,
                'mem_size': p_memsz,
                'alignment': p_align,
            })

        # Dynamic section symbols
        dynamic = []
        for sec in sections:
            if sec['type'] == 'DYNAMIC' and sec['size'] > 0:
                dyn_off = sec['offset']
                dyn_size = sec['size']
                entry_sz = 16 if is_64 else 8
                for j in range(0, dyn_size, entry_sz):
                    off = dyn_off + j
                    if is_64 and off + 16 <= len(data):
                        d_tag, d_val = struct.unpack_from(f'{endian}qQ', data, off)
                    elif not is_64 and off + 8 <= len(data):
                        d_tag, d_val = struct.unpack_from(f'{endian}iI', data, off)
                    else:
                        break
                    if d_tag == 0:
                        break
                    dynamic.append({'tag': d_tag, 'value': f'0x{d_val:x}'})

        result = {
            'format': 'ELF',
            'class': bits_str,
            'endianness': endian_str,
            'osabi': osabi_str,
            'type': type_str,
            'type_raw': e_type,
            'machine': f'0x{e_machine:x}',
            'machine_str': machine_str,
            'entry_point': f'0x{e_entry:x}',
            'flags': f'0x{e_flags:x}',
            'num_sections': e_shnum,
            'num_program_headers': e_phnum,
            'sections': sections,
            'program_headers': program_headers,
            'dynamic': dynamic[:50],
        }

        return result

    # ── String Extraction ────────────────────────────────────────────────

    def _extract_strings_from_data(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII and Unicode strings from raw byte data."""
        results = []

        # ASCII strings
        ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}')
        for match in ascii_pattern.finditer(data):
            results.append({
                'offset': match.start(),
                'string': match.group().decode('ascii', errors='replace'),
                'encoding': 'ascii',
            })

        # UTF-16LE strings (common in PE binaries)
        i = 0
        while i < len(data) - 1:
            # Look for sequences of printable chars with null bytes interleaved
            chars = []
            start = i
            while i < len(data) - 1:
                lo, hi = data[i], data[i + 1]
                if hi == 0 and 0x20 <= lo <= 0x7e:
                    chars.append(chr(lo))
                    i += 2
                else:
                    break
            if len(chars) >= min_length:
                results.append({
                    'offset': start,
                    'string': ''.join(chars),
                    'encoding': 'unicode',
                })
            else:
                i += 1

        # Sort by offset and deduplicate
        results.sort(key=lambda x: x['offset'])
        return results

    def extract_strings(self, file_path: str, min_length: int = 4,
                        encoding: str = 'both') -> List[Dict[str, Any]]:
        """Extract printable strings from a binary file."""
        p = Path(file_path)
        if not p.exists():
            return []

        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception:
            return []

        results = self._extract_strings_from_data(data, min_length)

        if encoding == 'ascii':
            results = [s for s in results if s['encoding'] == 'ascii']
        elif encoding == 'unicode':
            results = [s for s in results if s['encoding'] == 'unicode']

        return results

    # ── Disassembly ──────────────────────────────────────────────────────

    def disassemble(self, data: bytes, arch: str = 'x64', mode: str = '64',
                    offset: int = 0, count: int = 0) -> List[Dict[str, Any]]:
        """Disassemble raw bytes. Uses capstone if available, otherwise objdump."""
        if HAS_CAPSTONE:
            return self._disassemble_capstone(data, arch, mode, offset, count)
        return self._disassemble_objdump(data, arch, offset, count)

    def _disassemble_capstone(self, data: bytes, arch: str, mode: str,
                              offset: int, count: int) -> List[Dict[str, Any]]:
        """Disassemble using capstone."""
        arch_map = {
            'x86':   (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            'x64':   (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            'arm':   (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            'arm64': (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            'mips':  (capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32),
        }

        cs_arch, cs_mode = arch_map.get(arch.lower(), (capstone.CS_ARCH_X86, capstone.CS_MODE_64))
        md = capstone.Cs(cs_arch, cs_mode)

        instructions = []
        for i, (address, size, mnemonic, op_str) in enumerate(md.disasm_lite(data, offset)):
            if count > 0 and i >= count:
                break
            inst_bytes = data[address - offset:address - offset + size]
            instructions.append({
                'address': f'0x{address:08x}',
                'mnemonic': mnemonic,
                'op_str': op_str,
                'bytes_hex': inst_bytes.hex(),
                'size': size,
            })

        return instructions

    def _disassemble_objdump(self, data: bytes, arch: str,
                             offset: int, count: int) -> List[Dict[str, Any]]:
        """Disassemble using objdump as fallback."""
        objdump = find_tool('objdump')
        if not objdump:
            return [{'error': 'No disassembler available. Install capstone (pip install capstone) or objdump.'}]

        # Write data to temporary file
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            arch_flag = {
                'x86': 'i386', 'x64': 'i386:x86-64',
                'arm': 'arm', 'arm64': 'aarch64',
            }.get(arch.lower(), 'i386:x86-64')

            cmd = [objdump, '-D', '-b', 'binary', '-m', arch_flag, tmp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            instructions = []
            for line in result.stdout.splitlines():
                match = re.match(r'\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s+(\w+)\s*(.*)', line)
                if match:
                    addr_str, bytes_hex, mnemonic, op_str = match.groups()
                    instructions.append({
                        'address': f'0x{int(addr_str, 16) + offset:08x}',
                        'mnemonic': mnemonic.strip(),
                        'op_str': op_str.strip(),
                        'bytes_hex': bytes_hex.replace(' ', ''),
                    })
                    if count > 0 and len(instructions) >= count:
                        break

            return instructions
        except Exception as e:
            return [{'error': f'objdump failed: {e}'}]
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def disassemble_file(self, file_path: str, section: str = '.text',
                         offset: int = 0, count: int = 100) -> List[Dict[str, Any]]:
        """Disassemble a specific section of a binary file."""
        p = Path(file_path)
        if not p.exists():
            return [{'error': 'File not found'}]

        ft = self.get_file_type(file_path)
        ftype = ft.get('type', '')

        arch = 'x64'
        sec_offset = offset
        sec_size = 0

        if ftype == 'PE':
            pe = self.parse_pe(file_path)
            if 'error' in pe:
                return [{'error': pe['error']}]
            machine = pe.get('machine', '')
            if '14c' in machine:
                arch = 'x86'
            elif 'aa64' in machine:
                arch = 'arm64'
            elif '1c0' in machine or '1c4' in machine:
                arch = 'arm'

            for sec in pe.get('sections', []):
                if sec['name'].strip('\x00') == section.strip('.'):
                    sec_offset = sec['raw_offset'] + offset
                    sec_size = sec['raw_size']
                    break
                elif sec['name'].strip('\x00').lower() == section.lstrip('.').lower():
                    sec_offset = sec['raw_offset'] + offset
                    sec_size = sec['raw_size']
                    break

        elif ftype == 'ELF':
            elf = self.parse_elf(file_path)
            if 'error' in elf:
                return [{'error': elf['error']}]
            machine_str = elf.get('machine_str', '')
            if 'x86-64' in machine_str:
                arch = 'x64'
            elif 'x86' in machine_str:
                arch = 'x86'
            elif 'ARM64' in machine_str or 'AArch64' in machine_str:
                arch = 'arm64'
            elif 'ARM' in machine_str:
                arch = 'arm'

            for sec in elf.get('sections', []):
                if sec['name'] == section:
                    sec_offset = sec['offset'] + offset
                    sec_size = sec['size']
                    break

        # Read section data
        try:
            with open(p, 'rb') as f:
                if sec_size > 0:
                    f.seek(sec_offset)
                    data = f.read(min(sec_size, 0x10000))
                else:
                    f.seek(sec_offset)
                    data = f.read(0x10000)
        except Exception as e:
            return [{'error': f'Cannot read file: {e}'}]

        return self.disassemble(data, arch=arch, offset=sec_offset, count=count)

    # ── YARA Scanning ────────────────────────────────────────────────────

    def yara_scan(self, file_path: str, rules_path: Optional[str] = None,
                  rules_string: Optional[str] = None) -> Dict[str, Any]:
        """Scan a file with YARA rules."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found', 'matches': []}

        if HAS_YARA:
            return self._yara_scan_python(file_path, rules_path, rules_string)
        return self._yara_scan_cli(file_path, rules_path, rules_string)

    def _yara_scan_python(self, file_path: str, rules_path: Optional[str],
                          rules_string: Optional[str]) -> Dict[str, Any]:
        """Scan using yara-python library."""
        try:
            if rules_string:
                rules = yara.compile(source=rules_string)
            elif rules_path:
                rules = yara.compile(filepath=rules_path)
            else:
                # Use all rules in yara_rules directory
                rule_files = list(self.yara_rules_dir.glob('*.yar')) + \
                             list(self.yara_rules_dir.glob('*.yara'))
                if not rule_files:
                    return {'error': 'No YARA rules found', 'matches': []}
                sources = {}
                for rf in rule_files:
                    ns = rf.stem
                    sources[ns] = str(rf)
                rules = yara.compile(filepaths=sources)

            matches = rules.match(file_path)
            results = []
            for match in matches:
                strings_found = []
                for string_match in match.strings:
                    for instance in string_match.instances:
                        strings_found.append({
                            'offset': instance.offset,
                            'identifier': string_match.identifier,
                            'data': instance.matched_data.hex() if len(instance.matched_data) <= 64 else instance.matched_data[:64].hex() + '...',
                        })
                results.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': list(match.tags),
                    'meta': dict(match.meta) if match.meta else {},
                    'strings': strings_found,
                })

            return {'matches': results, 'total': len(results), 'engine': 'yara-python'}

        except Exception as e:
            return {'error': str(e), 'matches': []}

    def _yara_scan_cli(self, file_path: str, rules_path: Optional[str],
                       rules_string: Optional[str]) -> Dict[str, Any]:
        """Scan using yara CLI tool as fallback."""
        yara_bin = find_tool('yara')
        if not yara_bin:
            return {'error': 'YARA not available. Install yara-python (pip install yara-python) or yara CLI.', 'matches': []}

        try:
            if rules_string:
                with tempfile.NamedTemporaryFile(suffix='.yar', mode='w', delete=False) as tmp:
                    tmp.write(rules_string)
                    tmp_rules = tmp.name
                rules_file = tmp_rules
            elif rules_path:
                rules_file = rules_path
                tmp_rules = None
            else:
                rule_files = list(self.yara_rules_dir.glob('*.yar')) + \
                             list(self.yara_rules_dir.glob('*.yara'))
                if not rule_files:
                    return {'error': 'No YARA rules found', 'matches': []}
                rules_file = str(rule_files[0])
                tmp_rules = None

            cmd = [yara_bin, '-s', rules_file, file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

            matches = []
            current_rule = None
            for line in result.stdout.splitlines():
                rule_match = re.match(r'^(\S+)\s+\S+$', line)
                if rule_match and ':' not in line:
                    current_rule = {'rule': rule_match.group(1), 'strings': []}
                    matches.append(current_rule)
                elif current_rule and ':' in line:
                    parts = line.strip().split(':', 2)
                    if len(parts) >= 3:
                        current_rule['strings'].append({
                            'offset': int(parts[0], 0) if parts[0].strip() else 0,
                            'identifier': parts[1].strip(),
                            'data': parts[2].strip(),
                        })

            if tmp_rules:
                os.unlink(tmp_rules)

            return {'matches': matches, 'total': len(matches), 'engine': 'yara-cli'}

        except Exception as e:
            return {'error': str(e), 'matches': []}

    def list_yara_rules(self) -> List[Dict[str, str]]:
        """List available YARA rule files."""
        rules = []
        for ext in ('*.yar', '*.yara'):
            for f in self.yara_rules_dir.glob(ext):
                stat = f.stat()
                rules.append({
                    'name': f.name,
                    'path': str(f),
                    'size': stat.st_size,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                })
        return sorted(rules, key=lambda x: x['name'])

    # ── Packer Detection ─────────────────────────────────────────────────

    def detect_packer(self, file_path: str) -> Dict[str, Any]:
        """Detect common executable packers."""
        p = Path(file_path)
        if not p.exists():
            return {'detected': False, 'error': 'File not found'}

        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {'detected': False, 'error': str(e)}

        ft = self.get_file_type(file_path)
        detections = []

        # Check magic byte signatures in file body
        for packer, sig_info in PACKER_SIGNATURES.items():
            score = 0
            evidence = []

            # Check for magic byte patterns
            for pattern in sig_info.get('magic', []):
                idx = data.find(pattern)
                if idx != -1:
                    score += 40
                    evidence.append(f'Magic pattern at offset 0x{idx:x}')

            # Check section names (for PE files)
            if ft.get('type') == 'PE':
                pe = self.parse_pe(file_path)
                if 'error' not in pe:
                    for sec in pe.get('sections', []):
                        sec_name = sec['name'].encode('ascii', errors='ignore')
                        for packer_sec in sig_info.get('section_names', []):
                            if sec_name.rstrip(b'\x00').startswith(packer_sec.rstrip(b'\x00')):
                                score += 50
                                evidence.append(f'Section name: {sec["name"]}')

            if score > 0:
                detections.append({
                    'packer': packer,
                    'confidence': min(score, 100),
                    'description': sig_info.get('description', ''),
                    'evidence': evidence,
                })

        # Heuristic checks
        overall_entropy = self.calculate_entropy(data)
        if overall_entropy > 7.2:
            detections.append({
                'packer': 'Unknown (high entropy)',
                'confidence': 60,
                'description': f'High overall entropy ({overall_entropy:.2f}) suggests packing or encryption',
                'evidence': [f'Entropy: {overall_entropy:.4f}'],
            })

        # Check for small code section with high entropy (common in packed binaries)
        if ft.get('type') == 'PE':
            sec_ent = self.section_entropy(file_path)
            high_ent_sections = [s for s in sec_ent if s.get('entropy', 0) > 7.0]
            if high_ent_sections and not detections:
                names = ', '.join(s['name'] for s in high_ent_sections)
                detections.append({
                    'packer': 'Unknown (packed sections)',
                    'confidence': 50,
                    'description': f'High entropy sections detected: {names}',
                    'evidence': [f'{s["name"]}: entropy {s["entropy"]:.2f}' for s in high_ent_sections],
                })

        # Sort by confidence
        detections.sort(key=lambda x: -x['confidence'])

        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'overall_entropy': overall_entropy if 'overall_entropy' in dir() else self.calculate_entropy(data),
        }

    # ── Hex Dump ─────────────────────────────────────────────────────────

    def hex_dump(self, file_path: str, offset: int = 0, length: int = 256) -> Dict[str, Any]:
        """Generate formatted hex dump of a file region."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found'}

        try:
            file_size = p.stat().st_size
            with open(p, 'rb') as f:
                f.seek(offset)
                data = f.read(length)
        except Exception as e:
            return {'error': str(e)}

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            # Add spacing between 8-byte groups
            if len(chunk) > 8:
                hex_bytes = [f'{b:02x}' for b in chunk]
                hex_part = ' '.join(hex_bytes[:8]) + '  ' + ' '.join(hex_bytes[8:])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append({
                'offset': f'{offset + i:08x}',
                'hex': hex_part,
                'ascii': ascii_part,
            })

        # Also produce a formatted text version
        text_lines = []
        for line in lines:
            text_lines.append(f'{line["offset"]}  {line["hex"]:<49}  |{line["ascii"]}|')

        return {
            'offset': offset,
            'length': len(data),
            'file_size': file_size,
            'lines': lines,
            'text': '\n'.join(text_lines),
        }

    def hex_search(self, file_path: str, pattern: str) -> Dict[str, Any]:
        """Search for a hex pattern in a binary file. Pattern: space/dash separated hex bytes."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found', 'matches': []}

        # Parse hex pattern
        clean = re.sub(r'[^0-9a-fA-F?]', '', pattern.replace('??', 'FF'))
        if len(clean) % 2 != 0:
            return {'error': 'Invalid hex pattern (odd number of nibbles)', 'matches': []}

        try:
            search_bytes = bytes.fromhex(re.sub(r'[^0-9a-fA-F]', '', pattern.replace(' ', '').replace('-', '')))
        except ValueError:
            return {'error': 'Invalid hex pattern', 'matches': []}

        try:
            with open(p, 'rb') as f:
                data = f.read()
        except Exception as e:
            return {'error': str(e), 'matches': []}

        matches = []
        start = 0
        while True:
            idx = data.find(search_bytes, start)
            if idx == -1:
                break
            context = data[max(0, idx - 8):idx + len(search_bytes) + 8]
            matches.append({
                'offset': idx,
                'offset_hex': f'0x{idx:08x}',
                'context': context.hex(),
            })
            start = idx + 1
            if len(matches) >= 1000:
                break

        return {
            'pattern': search_bytes.hex(),
            'matches': matches,
            'total': len(matches),
            'file_size': len(data),
        }

    # ── Binary Comparison ────────────────────────────────────────────────

    def compare_binaries(self, file1: str, file2: str) -> Dict[str, Any]:
        """Compare two binary files: sizes, hashes, section diffs, byte-level changes."""
        p1, p2 = Path(file1), Path(file2)
        if not p1.exists():
            return {'error': f'File not found: {file1}'}
        if not p2.exists():
            return {'error': f'File not found: {file2}'}

        try:
            with open(p1, 'rb') as f:
                data1 = f.read()
            with open(p2, 'rb') as f:
                data2 = f.read()
        except Exception as e:
            return {'error': str(e)}

        # Size comparison
        size1, size2 = len(data1), len(data2)

        # Hashes
        hashes1 = {
            'md5': hashlib.md5(data1).hexdigest(),
            'sha256': hashlib.sha256(data1).hexdigest(),
        }
        hashes2 = {
            'md5': hashlib.md5(data2).hexdigest(),
            'sha256': hashlib.sha256(data2).hexdigest(),
        }

        identical = hashes1['sha256'] == hashes2['sha256']

        # Byte-level diff summary
        min_len = min(len(data1), len(data2))
        diff_count = 0
        diff_regions = []
        in_diff = False
        diff_start = 0

        for i in range(min_len):
            if data1[i] != data2[i]:
                diff_count += 1
                if not in_diff:
                    in_diff = True
                    diff_start = i
            else:
                if in_diff:
                    in_diff = False
                    diff_regions.append({
                        'offset': f'0x{diff_start:08x}',
                        'length': i - diff_start,
                    })
        if in_diff:
            diff_regions.append({
                'offset': f'0x{diff_start:08x}',
                'length': min_len - diff_start,
            })

        # Add difference for size mismatch
        if size1 != size2:
            diff_count += abs(size1 - size2)

        # Section-level comparison for PE/ELF
        section_diffs = []
        ft1 = self.get_file_type(file1)
        ft2 = self.get_file_type(file2)
        if ft1.get('type') == ft2.get('type') and ft1.get('type') in ('PE', 'ELF'):
            if ft1['type'] == 'PE':
                pe1, pe2 = self.parse_pe(file1), self.parse_pe(file2)
                secs1 = {s['name']: s for s in pe1.get('sections', [])}
                secs2 = {s['name']: s for s in pe2.get('sections', [])}
            else:
                elf1, elf2 = self.parse_elf(file1), self.parse_elf(file2)
                secs1 = {s['name']: s for s in elf1.get('sections', [])}
                secs2 = {s['name']: s for s in elf2.get('sections', [])}

            all_names = sorted(set(list(secs1.keys()) + list(secs2.keys())))
            for name in all_names:
                s1 = secs1.get(name)
                s2 = secs2.get(name)
                if s1 and s2:
                    size_key = 'raw_size' if ft1['type'] == 'PE' else 'size'
                    section_diffs.append({
                        'name': name,
                        'status': 'modified' if s1.get(size_key) != s2.get(size_key) else 'unchanged',
                        'size_file1': s1.get(size_key, 0),
                        'size_file2': s2.get(size_key, 0),
                    })
                elif s1:
                    section_diffs.append({'name': name, 'status': 'removed'})
                else:
                    section_diffs.append({'name': name, 'status': 'added'})

        # Entropy comparison
        ent1 = self.calculate_entropy(data1)
        ent2 = self.calculate_entropy(data2)

        return {
            'file1': {'name': p1.name, 'size': size1, 'hashes': hashes1, 'entropy': ent1},
            'file2': {'name': p2.name, 'size': size2, 'hashes': hashes2, 'entropy': ent2},
            'identical': identical,
            'diff_bytes': diff_count,
            'diff_percentage': round((diff_count / max(max(size1, size2), 1)) * 100, 2),
            'diff_regions': diff_regions[:100],
            'diff_regions_total': len(diff_regions),
            'section_diffs': section_diffs,
        }

    # ── Ghidra Integration ───────────────────────────────────────────────

    def ghidra_decompile(self, file_path: str, function: Optional[str] = None) -> Dict[str, Any]:
        """Run Ghidra headless analysis and return decompiled output."""
        p = Path(file_path)
        if not p.exists():
            return {'error': 'File not found'}

        analyze_headless = find_tool('analyzeHeadless')
        if not analyze_headless:
            # Try common Ghidra install locations
            ghidra_paths = []
            if os.name == 'nt':
                for drive in ['C', 'D']:
                    ghidra_paths.extend([
                        Path(f'{drive}:/ghidra/support/analyzeHeadless.bat'),
                        Path(f'{drive}:/Program Files/ghidra/support/analyzeHeadless.bat'),
                    ])
            else:
                ghidra_paths.extend([
                    Path('/opt/ghidra/support/analyzeHeadless'),
                    Path('/usr/local/ghidra/support/analyzeHeadless'),
                    Path.home() / 'ghidra' / 'support' / 'analyzeHeadless',
                ])

            for gp in ghidra_paths:
                if gp.exists():
                    analyze_headless = str(gp)
                    break

        if not analyze_headless:
            return {'error': 'Ghidra not found. Install Ghidra and ensure analyzeHeadless is in PATH.'}

        # Create temporary project directory
        with tempfile.TemporaryDirectory(prefix='autarch_ghidra_') as tmp_dir:
            project_name = 'autarch_analysis'

            cmd = [
                analyze_headless,
                tmp_dir, project_name,
                '-import', str(p),
                '-postScript', 'DecompileHeadless.java',
                '-scriptlog', os.path.join(tmp_dir, 'script.log'),
                '-deleteProject',
            ]

            if function:
                cmd.extend(['-scriptArgs', function])

            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300,
                    cwd=tmp_dir)

                output = result.stdout + '\n' + result.stderr

                # Try to read script output
                log_path = os.path.join(tmp_dir, 'script.log')
                script_output = ''
                if os.path.exists(log_path):
                    with open(log_path, 'r') as f:
                        script_output = f.read()

                return {
                    'output': output,
                    'script_output': script_output,
                    'return_code': result.returncode,
                    'function': function,
                }
            except subprocess.TimeoutExpired:
                return {'error': 'Ghidra analysis timed out (300s limit)'}
            except Exception as e:
                return {'error': f'Ghidra execution failed: {e}'}

    # ── Import / Export Extraction ───────────────────────────────────────

    def get_imports(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract imported functions from PE or ELF binary."""
        ft = self.get_file_type(file_path)
        ftype = ft.get('type', '')

        if ftype == 'PE':
            return self._get_pe_imports(file_path)
        elif ftype == 'ELF':
            return self._get_elf_imports(file_path)
        return []

    def _get_pe_imports(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse PE import directory table."""
        pe = self.parse_pe(file_path)
        if 'error' in pe:
            return []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return []

        # Find import directory RVA
        import_dir = None
        for dd in pe.get('data_directories', []):
            if dd['name'] == 'Import':
                import_dir = dd
                break

        if not import_dir:
            return []

        import_rva = int(import_dir['rva'], 16)
        if import_rva == 0:
            return []

        # Convert RVA to file offset using section mapping
        sections = pe.get('sections', [])

        def rva_to_offset(rva):
            for sec in sections:
                sec_va = int(sec['virtual_address'], 16)
                sec_raw = sec['raw_offset']
                sec_vs = sec['virtual_size']
                if sec_va <= rva < sec_va + sec_vs:
                    return sec_raw + (rva - sec_va)
            return rva

        imports = []
        offset = rva_to_offset(import_rva)

        # Read Import Directory entries (20 bytes each)
        while offset + 20 <= len(data):
            ilt_rva, timestamp, forwarder, name_rva, iat_rva = struct.unpack_from('<IIIII', data, offset)
            if ilt_rva == 0 and name_rva == 0:
                break  # End of import directory

            # Read DLL name
            name_off = rva_to_offset(name_rva)
            dll_name = ''
            if name_off < len(data):
                end = data.find(b'\x00', name_off)
                if end != -1:
                    dll_name = data[name_off:end].decode('ascii', errors='replace')

            # Read import names from ILT (or IAT if ILT is 0)
            lookup_rva = ilt_rva if ilt_rva else iat_rva
            func_offset = rva_to_offset(lookup_rva)
            functions = []

            is_64 = pe.get('optional_header', {}).get('format') == 'PE32+'
            entry_size = 8 if is_64 else 4

            func_count = 0
            while func_offset + entry_size <= len(data) and func_count < 500:
                if is_64:
                    entry = struct.unpack_from('<Q', data, func_offset)[0]
                    ordinal_flag = 1 << 63
                else:
                    entry = struct.unpack_from('<I', data, func_offset)[0]
                    ordinal_flag = 1 << 31

                if entry == 0:
                    break

                if entry & ordinal_flag:
                    ordinal = entry & 0xFFFF
                    functions.append({'name': f'Ordinal_{ordinal}', 'ordinal': ordinal})
                else:
                    hint_off = rva_to_offset(entry & 0x7FFFFFFF)
                    if hint_off + 2 < len(data):
                        hint = struct.unpack_from('<H', data, hint_off)[0]
                        name_end = data.find(b'\x00', hint_off + 2)
                        if name_end != -1 and name_end - (hint_off + 2) < 256:
                            func_name = data[hint_off + 2:name_end].decode('ascii', errors='replace')
                            functions.append({'name': func_name, 'hint': hint})

                func_offset += entry_size
                func_count += 1

            imports.append({
                'library': dll_name,
                'functions': functions,
                'count': len(functions),
            })

            offset += 20

        return imports

    def _get_elf_imports(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract imported symbols from ELF dynamic symbol table."""
        elf = self.parse_elf(file_path)
        if 'error' in elf:
            return []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return []

        is_64 = '64-bit' in elf.get('class', '')
        endian = '<' if 'Little' in elf.get('endianness', 'Little') else '>'

        # Find .dynsym and .dynstr sections
        dynsym_sec = None
        dynstr_sec = None
        for sec in elf.get('sections', []):
            if sec['name'] == '.dynsym':
                dynsym_sec = sec
            elif sec['name'] == '.dynstr':
                dynstr_sec = sec

        if not dynsym_sec or not dynstr_sec:
            return []

        # Read string table
        str_off = dynstr_sec['offset']
        str_size = dynstr_sec['size']
        if str_off + str_size > len(data):
            return []
        strtab = data[str_off:str_off + str_size]

        # Read symbol table
        sym_off = dynsym_sec['offset']
        sym_size = dynsym_sec['size']
        entry_size = 24 if is_64 else 16

        imports = []
        for i in range(0, sym_size, entry_size):
            off = sym_off + i
            if is_64 and off + 24 <= len(data):
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    f'{endian}IBBHQQ', data, off)
            elif not is_64 and off + 16 <= len(data):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    f'{endian}IIIBBH', data, off)
            else:
                break

            # Undefined symbols (imports) have shndx == 0
            if st_shndx == 0 and st_name > 0 and st_name < len(strtab):
                end = strtab.find(b'\x00', st_name)
                if end != -1:
                    sym_name = strtab[st_name:end].decode('ascii', errors='replace')
                    if sym_name:
                        bind = (st_info >> 4) & 0xf
                        sym_type = st_info & 0xf
                        bind_str = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}.get(bind, str(bind))
                        type_str = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC'}.get(sym_type, str(sym_type))
                        imports.append({
                            'name': sym_name,
                            'bind': bind_str,
                            'type': type_str,
                        })

        # Group by library if possible (from NEEDED entries in dynamic section)
        needed_libs = []
        for dyn in elf.get('dynamic', []):
            if dyn['tag'] == 1:  # DT_NEEDED
                val = int(dyn['value'], 16)
                if val < len(strtab):
                    end = strtab.find(b'\x00', val)
                    if end != -1:
                        needed_libs.append(strtab[val:end].decode('ascii', errors='replace'))

        result = [{'library': lib, 'functions': [], 'count': 0} for lib in needed_libs]
        if imports:
            ungrouped = {'library': '(dynamic imports)', 'functions': imports, 'count': len(imports)}
            result.append(ungrouped)

        return result

    def get_exports(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract exported functions from PE or ELF binary."""
        ft = self.get_file_type(file_path)
        ftype = ft.get('type', '')

        if ftype == 'PE':
            return self._get_pe_exports(file_path)
        elif ftype == 'ELF':
            return self._get_elf_exports(file_path)
        return []

    def _get_pe_exports(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse PE export directory table."""
        pe = self.parse_pe(file_path)
        if 'error' in pe:
            return []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return []

        export_dir = None
        for dd in pe.get('data_directories', []):
            if dd['name'] == 'Export':
                export_dir = dd
                break

        if not export_dir:
            return []

        export_rva = int(export_dir['rva'], 16)
        if export_rva == 0:
            return []

        sections = pe.get('sections', [])

        def rva_to_offset(rva):
            for sec in sections:
                sec_va = int(sec['virtual_address'], 16)
                sec_raw = sec['raw_offset']
                sec_vs = sec['virtual_size']
                if sec_va <= rva < sec_va + sec_vs:
                    return sec_raw + (rva - sec_va)
            return rva

        offset = rva_to_offset(export_rva)
        if offset + 40 > len(data):
            return []

        _, timestamp, major_ver, minor_ver, name_rva, ordinal_base, \
            num_functions, num_names, addr_functions_rva, addr_names_rva, \
            addr_ordinals_rva = struct.unpack_from('<IIHHIIIIIII', data, offset)

        exports = []
        names_offset = rva_to_offset(addr_names_rva)
        ordinals_offset = rva_to_offset(addr_ordinals_rva)
        functions_offset = rva_to_offset(addr_functions_rva)

        for i in range(min(num_names, 2000)):
            if names_offset + (i + 1) * 4 > len(data):
                break
            name_rva = struct.unpack_from('<I', data, names_offset + i * 4)[0]
            name_off = rva_to_offset(name_rva)
            if name_off < len(data):
                end = data.find(b'\x00', name_off)
                if end != -1 and end - name_off < 256:
                    func_name = data[name_off:end].decode('ascii', errors='replace')
                else:
                    func_name = f'<unknown_{i}>'
            else:
                func_name = f'<unknown_{i}>'

            ordinal = 0
            if ordinals_offset + (i + 1) * 2 <= len(data):
                ordinal = struct.unpack_from('<H', data, ordinals_offset + i * 2)[0]

            func_rva = 0
            func_idx = ordinal
            if functions_offset + (func_idx + 1) * 4 <= len(data):
                func_rva = struct.unpack_from('<I', data, functions_offset + func_idx * 4)[0]

            exports.append({
                'name': func_name,
                'ordinal': ordinal + ordinal_base,
                'address': f'0x{func_rva:08x}',
            })

        return exports

    def _get_elf_exports(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract exported (defined GLOBAL/WEAK) symbols from ELF."""
        elf = self.parse_elf(file_path)
        if 'error' in elf:
            return []

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return []

        is_64 = '64-bit' in elf.get('class', '')
        endian = '<' if 'Little' in elf.get('endianness', 'Little') else '>'

        # Find .dynsym and .dynstr
        dynsym_sec = None
        dynstr_sec = None
        for sec in elf.get('sections', []):
            if sec['name'] == '.dynsym':
                dynsym_sec = sec
            elif sec['name'] == '.dynstr':
                dynstr_sec = sec

        if not dynsym_sec or not dynstr_sec:
            return []

        str_off = dynstr_sec['offset']
        str_size = dynstr_sec['size']
        if str_off + str_size > len(data):
            return []
        strtab = data[str_off:str_off + str_size]

        sym_off = dynsym_sec['offset']
        sym_size = dynsym_sec['size']
        entry_size = 24 if is_64 else 16

        exports = []
        for i in range(0, sym_size, entry_size):
            off = sym_off + i
            if is_64 and off + 24 <= len(data):
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
                    f'{endian}IBBHQQ', data, off)
            elif not is_64 and off + 16 <= len(data):
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(
                    f'{endian}IIIBBH', data, off)
            else:
                break

            # Exported = defined (shndx != 0) and GLOBAL or WEAK binding
            bind = (st_info >> 4) & 0xf
            if st_shndx != 0 and bind in (1, 2) and st_name > 0 and st_name < len(strtab):
                end = strtab.find(b'\x00', st_name)
                if end != -1:
                    sym_name = strtab[st_name:end].decode('ascii', errors='replace')
                    if sym_name:
                        sym_type = st_info & 0xf
                        type_str = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC'}.get(sym_type, str(sym_type))
                        exports.append({
                            'name': sym_name,
                            'address': f'0x{st_value:x}',
                            'type': type_str,
                            'size': st_size,
                        })

        return exports

    # ── Utility Methods ──────────────────────────────────────────────────

    @staticmethod
    def _human_size(size: int) -> str:
        """Convert bytes to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f'{size:.1f} {unit}' if unit != 'B' else f'{size} {unit}'
            size /= 1024
        return f'{size:.1f} PB'

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN,
                  "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    # ── CLI Interface ────────────────────────────────────────────────────

    def show_menu(self):
        clear_screen()
        display_banner()
        print(f"{Colors.CYAN}{Colors.BOLD}  Reverse Engineering Toolkit{Colors.RESET}")
        print(f"{Colors.DIM}  Binary analysis, disassembly & YARA scanning{Colors.RESET}")
        print(f"{Colors.DIM}  {'=' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.CYAN}[1]{Colors.RESET} Analyze Binary")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Disassemble")
        print(f"  {Colors.CYAN}[3]{Colors.RESET} YARA Scan")
        print(f"  {Colors.CYAN}[4]{Colors.RESET} Hex Dump")
        print(f"  {Colors.CYAN}[5]{Colors.RESET} Detect Packer")
        print(f"  {Colors.CYAN}[6]{Colors.RESET} Compare Binaries")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def cli_analyze(self):
        filepath = input(f"{Colors.WHITE}  Enter file path: {Colors.RESET}").strip()
        if not filepath:
            return
        result = self.analyze_binary(filepath)
        if 'error' in result:
            self.print_status(result['error'], 'error')
            return
        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"  {Colors.BOLD}{result['name']}{Colors.RESET}")
        print(f"  Type: {result['file_type'].get('type', 'unknown')}  |  "
              f"Arch: {result['architecture']}  |  Size: {result['size_human']}")
        print(f"\n  {Colors.CYAN}Hashes:{Colors.RESET}")
        for algo, val in result['hashes'].items():
            print(f"    {algo.upper():8} {val}")
        print(f"\n  {Colors.CYAN}Entropy:{Colors.RESET} {result['entropy']} ({result['entropy_level']})")
        if result['section_entropy']:
            for s in result['section_entropy']:
                bar = '#' * int(s['entropy'] * 3)
                color = Colors.RED if s['entropy'] > 7.0 else (Colors.YELLOW if s['entropy'] > 6.0 else Colors.GREEN)
                print(f"    {s['name']:12} {color}{s['entropy']:.2f}{Colors.RESET} {bar}")
        print(f"\n  {Colors.CYAN}Strings:{Colors.RESET} {result['strings_count']} found")
        if result['packer']['detected']:
            print(f"\n  {Colors.RED}Packer Detected:{Colors.RESET}")
            for d in result['packer']['detections']:
                print(f"    {d['packer']} (confidence: {d['confidence']}%)")

    def cli_disassemble(self):
        filepath = input(f"{Colors.WHITE}  Enter file path: {Colors.RESET}").strip()
        if not filepath:
            return
        section = input(f"{Colors.WHITE}  Section [.text]: {Colors.RESET}").strip() or '.text'
        count = input(f"{Colors.WHITE}  Instruction count [50]: {Colors.RESET}").strip() or '50'
        try:
            count = int(count)
        except ValueError:
            count = 50

        results = self.disassemble_file(filepath, section=section, count=count)
        if results and 'error' in results[0]:
            self.print_status(results[0]['error'], 'error')
            return
        print(f"\n{Colors.CYAN}{'Address':<14} {'Bytes':<24} {'Mnemonic':<10} {'Operands'}{Colors.RESET}")
        print(f"{'-' * 70}")
        for inst in results:
            print(f"  {inst['address']:<12} {inst.get('bytes_hex', ''):<22} "
                  f"{Colors.CYAN}{inst['mnemonic']:<10}{Colors.RESET} {inst.get('op_str', '')}")

    def cli_yara_scan(self):
        filepath = input(f"{Colors.WHITE}  Enter file path to scan: {Colors.RESET}").strip()
        if not filepath:
            return
        rules_path = input(f"{Colors.WHITE}  YARA rules file (or Enter for all): {Colors.RESET}").strip() or None
        result = self.yara_scan(filepath, rules_path=rules_path)
        if 'error' in result and result['error']:
            self.print_status(result['error'], 'error')
        if result.get('matches'):
            print(f"\n  {Colors.RED}Matches: {result['total']}{Colors.RESET}")
            for m in result['matches']:
                print(f"    Rule: {m['rule']}")
                for s in m.get('strings', [])[:5]:
                    print(f"      0x{s.get('offset', 0):08x}: {s.get('identifier', '')} = {s.get('data', '')}")
        else:
            self.print_status("No matches found", "info")

    def cli_hex_dump(self):
        filepath = input(f"{Colors.WHITE}  Enter file path: {Colors.RESET}").strip()
        if not filepath:
            return
        offset = input(f"{Colors.WHITE}  Offset [0]: {Colors.RESET}").strip() or '0'
        length = input(f"{Colors.WHITE}  Length [256]: {Colors.RESET}").strip() or '256'
        try:
            offset = int(offset, 0)
            length = int(length, 0)
        except ValueError:
            self.print_status("Invalid offset or length", "error")
            return
        result = self.hex_dump(filepath, offset, length)
        if 'error' in result:
            self.print_status(result['error'], 'error')
            return
        print(f"\n{Colors.CYAN}{result['text']}{Colors.RESET}")

    def cli_detect_packer(self):
        filepath = input(f"{Colors.WHITE}  Enter file path: {Colors.RESET}").strip()
        if not filepath:
            return
        result = self.detect_packer(filepath)
        if 'error' in result:
            self.print_status(result['error'], 'error')
            return
        if result['detected']:
            print(f"\n  {Colors.RED}Packer(s) Detected:{Colors.RESET}")
            for d in result['detections']:
                print(f"    {d['packer']} — confidence {d['confidence']}%")
                print(f"      {d['description']}")
                for e in d.get('evidence', []):
                    print(f"        {e}")
        else:
            self.print_status("No packer detected", "success")
            print(f"    Entropy: {result.get('overall_entropy', 0):.4f}")

    def cli_compare(self):
        file1 = input(f"{Colors.WHITE}  First file:  {Colors.RESET}").strip()
        file2 = input(f"{Colors.WHITE}  Second file: {Colors.RESET}").strip()
        if not file1 or not file2:
            return
        result = self.compare_binaries(file1, file2)
        if 'error' in result:
            self.print_status(result['error'], 'error')
            return
        f1, f2 = result['file1'], result['file2']
        print(f"\n{Colors.CYAN}{'=' * 60}{Colors.RESET}")
        print(f"  File 1: {f1['name']}  ({f1['size']:,} bytes, entropy {f1['entropy']:.2f})")
        print(f"  File 2: {f2['name']}  ({f2['size']:,} bytes, entropy {f2['entropy']:.2f})")
        if result['identical']:
            self.print_status("Files are identical", "success")
        else:
            print(f"\n  {Colors.YELLOW}Different bytes: {result['diff_bytes']:,} ({result['diff_percentage']}%){Colors.RESET}")
            print(f"  Diff regions: {result['diff_regions_total']}")
            for sd in result.get('section_diffs', []):
                status_color = Colors.RED if sd['status'] != 'unchanged' else Colors.GREEN
                print(f"    {sd['name']:16} {status_color}{sd['status']}{Colors.RESET}")

    def run(self):
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()
                if choice == "0":
                    break
                elif choice == "1":
                    self.cli_analyze()
                elif choice == "2":
                    self.cli_disassemble()
                elif choice == "3":
                    self.cli_yara_scan()
                elif choice == "4":
                    self.cli_hex_dump()
                elif choice == "5":
                    self.cli_detect_packer()
                elif choice == "6":
                    self.cli_compare()

                if choice in ["1", "2", "3", "4", "5", "6"]:
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_reverse_eng() -> ReverseEngineer:
    global _instance
    if _instance is None:
        _instance = ReverseEngineer()
    return _instance


def run():
    get_reverse_eng().run()


if __name__ == "__main__":
    run()
