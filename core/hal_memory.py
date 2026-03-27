"""
AUTARCH HAL Memory Cache
Encrypted conversation history for the HAL AI agent.

Stores all HAL conversations in an AES-encrypted file.
Only the AI agent system can read them — the decryption key is
derived from the machine ID + a HAL-specific salt, same pattern
as the vault but with a separate keyspace.

Max size: configurable, default 4GB. Trims oldest entries when exceeded.

Usage:
    from core.hal_memory import get_hal_memory
    mem = get_hal_memory()
    mem.add('user', 'scan my network')
    mem.add('hal', 'Running nmap on 10.0.0.0/24...')
    history = mem.get_history(last_n=50)
    mem.add_context('scan_result', {'tool': 'nmap', 'output': '...'})
"""

import hashlib
import json
import logging
import os
import struct
import time
from pathlib import Path
from typing import Optional

_log = logging.getLogger('autarch.hal_memory')

_MEMORY_DIR = Path(__file__).parent.parent / 'data'
_MEMORY_FILE = _MEMORY_DIR / 'hal_memory.enc'
_MEMORY_MAGIC = b'HALM'
_MEMORY_VERSION = 1
_DEFAULT_MAX_BYTES = 4 * 1024 * 1024 * 1024  # 4GB


def _derive_key(salt: bytes) -> bytes:
    """Derive AES key from machine identity + HAL-specific material."""
    machine_id = b''
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path) as f:
                machine_id = f.read().strip().encode()
                break
        except Exception:
            continue
    if not machine_id:
        import socket
        machine_id = f"hal-{socket.gethostname()}".encode()
    return hashlib.pbkdf2_hmac('sha256', machine_id + b'HAL-MEMORY-KEY', salt, 100_000, dklen=32)


def _encrypt(plaintext: bytes, key: bytes) -> tuple:
    iv = os.urandom(16)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return iv, enc.update(padded) + enc.finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        return iv, AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    except ImportError:
        raise RuntimeError('No crypto backend available')


def _decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        return PKCS7(128).unpadder().update(padded) + PKCS7(128).unpadder().finalize()
    except ImportError:
        pass
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
    except ImportError:
        raise RuntimeError('No crypto backend available')


class HalMemory:
    """Encrypted conversation memory for HAL."""

    def __init__(self, max_bytes: int = _DEFAULT_MAX_BYTES):
        self._max_bytes = max_bytes
        self._salt = b''
        self._entries = []
        self._load()

    def _load(self):
        if not _MEMORY_FILE.exists():
            self._salt = os.urandom(32)
            self._entries = []
            return
        try:
            with open(_MEMORY_FILE, 'rb') as f:
                magic = f.read(4)
                if magic != _MEMORY_MAGIC:
                    self._salt = os.urandom(32)
                    self._entries = []
                    return
                f.read(1)  # version
                self._salt = f.read(32)
                iv = f.read(16)
                ciphertext = f.read()
            key = _derive_key(self._salt)
            plaintext = _decrypt(iv, ciphertext, key)
            self._entries = json.loads(plaintext.decode('utf-8'))
            _log.info(f'[HAL Memory] Loaded {len(self._entries)} entries')
        except Exception as e:
            _log.error(f'[HAL Memory] Load failed: {e}')
            self._salt = os.urandom(32)
            self._entries = []

    def _save(self):
        try:
            _MEMORY_DIR.mkdir(parents=True, exist_ok=True)
            key = _derive_key(self._salt)
            plaintext = json.dumps(self._entries).encode('utf-8')

            # Trim if over max size
            while len(plaintext) > self._max_bytes and len(self._entries) > 10:
                self._entries = self._entries[len(self._entries) // 4:]  # Drop oldest 25%
                plaintext = json.dumps(self._entries).encode('utf-8')
                _log.info(f'[HAL Memory] Trimmed to {len(self._entries)} entries ({len(plaintext)} bytes)')

            iv, ciphertext = _encrypt(plaintext, key)
            with open(_MEMORY_FILE, 'wb') as f:
                f.write(_MEMORY_MAGIC)
                f.write(struct.pack('B', _MEMORY_VERSION))
                f.write(self._salt)
                f.write(iv)
                f.write(ciphertext)
            os.chmod(_MEMORY_FILE, 0o600)
        except Exception as e:
            _log.error(f'[HAL Memory] Save failed: {e}')

    def add(self, role: str, content: str, metadata: dict = None):
        """Add a conversation entry."""
        entry = {
            'role': role,
            'content': content,
            'timestamp': time.time(),
        }
        if metadata:
            entry['metadata'] = metadata
        self._entries.append(entry)
        # Auto-save every 20 entries
        if len(self._entries) % 20 == 0:
            self._save()

    def add_context(self, context_type: str, data: dict):
        """Add a context entry (scan result, fix result, IR, etc.)."""
        self.add('context', json.dumps(data), metadata={'type': context_type})

    def get_history(self, last_n: int = 50) -> list:
        """Get recent conversation history."""
        return self._entries[-last_n:] if self._entries else []

    def get_full_history(self) -> list:
        """Get all entries."""
        return self._entries

    def search(self, query: str, max_results: int = 20) -> list:
        """Search memory for entries containing query string."""
        query_lower = query.lower()
        results = []
        for entry in reversed(self._entries):
            if query_lower in entry.get('content', '').lower():
                results.append(entry)
                if len(results) >= max_results:
                    break
        return results

    def clear(self):
        """Clear all memory."""
        self._entries = []
        self._save()

    def save(self):
        """Force save to disk."""
        self._save()

    def stats(self) -> dict:
        """Get memory stats."""
        total_bytes = len(json.dumps(self._entries).encode())
        return {
            'entries': len(self._entries),
            'bytes': total_bytes,
            'max_bytes': self._max_bytes,
            'percent_used': round(total_bytes / self._max_bytes * 100, 2) if self._max_bytes else 0,
        }


# Singleton
_instance: Optional[HalMemory] = None


def get_hal_memory(max_bytes: int = None) -> HalMemory:
    global _instance
    if _instance is None:
        from core.config import get_config
        config = get_config()
        if max_bytes is None:
            max_bytes = config.get_int('hal_memory', 'max_bytes', _DEFAULT_MAX_BYTES)
        _instance = HalMemory(max_bytes=max_bytes)
    return _instance
