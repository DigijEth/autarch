"""
AUTARCH Secrets Vault
Encrypted storage for API keys, tokens, and sensitive credentials.

Stores secrets in data/vault.enc using AES-256-CBC with a machine-derived key.
The key is derived from a combination of:
  - Machine ID (/etc/machine-id or hostname)
  - The vault salt (random, stored alongside the ciphertext)
  - PBKDF2-HMAC-SHA256 with 200,000 iterations

This means:
  - Secrets are encrypted at rest (not plaintext in .conf files)
  - The vault is tied to this machine (moving the file to another machine won't decrypt it)
  - No master password needed for normal operation (machine identity IS the key)
  - Optionally, a user-provided master password can be added for extra security

Usage:
    from core.vault import get_vault
    vault = get_vault()

    # Store a secret
    vault.set('claude_api_key', 'sk-ant-...')
    vault.set('openai_api_key', 'sk-...')

    # Retrieve a secret
    key = vault.get('claude_api_key')  # Returns '' if not set

    # List stored keys (not values)
    vault.keys()  # ['claude_api_key', 'openai_api_key']

    # Delete a secret
    vault.delete('old_key')
"""

import hashlib
import json
import logging
import os
import secrets
import struct
from pathlib import Path
from typing import Optional

_log = logging.getLogger('autarch.vault')

# Vault file location
_VAULT_DIR = Path(__file__).parent.parent / 'data'
_VAULT_FILE = _VAULT_DIR / 'vault.enc'
_VAULT_MAGIC = b'ATVL'  # AUTARCH VauLt
_VAULT_VERSION = 1


def _get_machine_id() -> bytes:
    """Get a stable machine identifier for key derivation."""
    # Try /etc/machine-id (Linux, unique per install)
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path) as f:
                mid = f.read().strip()
                if mid:
                    return mid.encode()
        except (OSError, PermissionError):
            continue

    # Fallback: hostname + username + home dir (less unique but works everywhere)
    import socket
    fallback = f"{socket.gethostname()}:{os.getenv('USER', 'autarch')}:{Path.home()}"
    return fallback.encode()


def _derive_key(salt: bytes, master_password: str = '') -> bytes:
    """Derive a 32-byte AES key from machine ID + optional master password."""
    machine_id = _get_machine_id()
    material = machine_id + master_password.encode()
    return hashlib.pbkdf2_hmac('sha256', material, salt, 200_000, dklen=32)


def _encrypt(plaintext: bytes, key: bytes) -> tuple:
    """Encrypt with AES-256-CBC. Returns (iv, ciphertext)."""
    iv = os.urandom(16)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return iv, ct
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(plaintext, 16))
        return iv, ct
    except ImportError:
        pass

    raise RuntimeError('No crypto backend available (install cryptography or PyCryptodome)')


def _decrypt(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-CBC. Returns plaintext."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.padding import PKCS7
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
        unpadder = PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), 16)
    except ImportError:
        pass

    raise RuntimeError('No crypto backend available')


class Vault:
    """Encrypted secrets vault."""

    def __init__(self, vault_path: Path = None, master_password: str = ''):
        self._path = vault_path or _VAULT_FILE
        self._master = master_password
        self._secrets: dict = {}
        self._salt: bytes = b''
        self._load()

    def _load(self):
        """Load and decrypt the vault file."""
        if not self._path.exists():
            self._salt = os.urandom(32)
            self._secrets = {}
            return

        try:
            with open(self._path, 'rb') as f:
                magic = f.read(4)
                if magic != _VAULT_MAGIC:
                    _log.warning('[Vault] Invalid vault file — starting fresh')
                    self._salt = os.urandom(32)
                    self._secrets = {}
                    return

                version = struct.unpack('B', f.read(1))[0]
                self._salt = f.read(32)
                iv = f.read(16)
                ciphertext = f.read()

            key = _derive_key(self._salt, self._master)
            plaintext = _decrypt(iv, ciphertext, key)
            self._secrets = json.loads(plaintext.decode('utf-8'))
            _log.info(f'[Vault] Loaded {len(self._secrets)} secret(s)')

        except Exception as e:
            _log.error(f'[Vault] Failed to load vault: {e}')
            self._salt = os.urandom(32)
            self._secrets = {}

    def _save(self):
        """Encrypt and write the vault file."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            key = _derive_key(self._salt, self._master)
            plaintext = json.dumps(self._secrets).encode('utf-8')
            iv, ciphertext = _encrypt(plaintext, key)

            with open(self._path, 'wb') as f:
                f.write(_VAULT_MAGIC)
                f.write(struct.pack('B', _VAULT_VERSION))
                f.write(self._salt)
                f.write(iv)
                f.write(ciphertext)

            # Restrict permissions
            os.chmod(self._path, 0o600)
            _log.info(f'[Vault] Saved {len(self._secrets)} secret(s)')

        except Exception as e:
            _log.error(f'[Vault] Failed to save: {e}')
            raise

    def get(self, key: str, default: str = '') -> str:
        """Get a secret value."""
        return self._secrets.get(key, default)

    def set(self, key: str, value: str):
        """Set a secret value and save."""
        self._secrets[key] = value
        self._save()

    def delete(self, key: str):
        """Delete a secret and save."""
        self._secrets.pop(key, None)
        self._save()

    def keys(self) -> list:
        """List all stored secret names."""
        return list(self._secrets.keys())

    def has(self, key: str) -> bool:
        """Check if a secret exists."""
        return key in self._secrets

    def export_masked(self) -> dict:
        """Export secrets with values masked (for UI display)."""
        return {k: v[:8] + '...' if len(v) > 12 else '***' for k, v in self._secrets.items()}


# ── Singleton ─────────────────────────────────────────────────────────────────

_vault_instance: Optional[Vault] = None


def get_vault(master_password: str = '') -> Vault:
    """Get the global vault instance."""
    global _vault_instance
    if _vault_instance is None:
        _vault_instance = Vault(master_password=master_password)
    return _vault_instance
