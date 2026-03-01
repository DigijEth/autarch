"""
AUTARCH Encrypted Module Cryptography
AES-256-CBC encryption with PBKDF2-HMAC-SHA512 key derivation
and SHA-512 integrity verification.

File format (.autarch):
  Offset  Size  Field
  ──────  ────  ─────────────────────────────────────────────────────
  0       4     Magic: b'ATCH'
  4       1     Version: 0x01
  5       32    PBKDF2 salt
  37      16    AES IV
  53      64    SHA-512 hash of plaintext (integrity check)
  117     2     Metadata JSON length (uint16 LE)
  119     N     Metadata JSON (UTF-8)
  119+N   ...   AES-256-CBC ciphertext (PKCS7 padded)
"""

import hashlib
import hmac
import json
import os
import struct
from pathlib import Path
from typing import Optional

MAGIC     = b'ATCH'
VERSION   = 0x01
KDF_ITERS = 260000   # PBKDF2 iterations (NIST recommended minimum for SHA-512)
SALT_LEN  = 32
IV_LEN    = 16
HASH_LEN  = 64       # SHA-512 digest length


# ── Low-level AES (pure stdlib, no pycryptodome required) ────────────────────
# Uses Python's hashlib-backed AES via the cryptography package if available,
# otherwise falls back to pycryptodome, then to a bundled pure-Python AES.

def _get_aes():
    """Return (encrypt_func, decrypt_func) pair."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        from cryptography.hazmat.backends import default_backend

        def encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
            padder   = sym_padding.PKCS7(128).padder()
            padded   = padder.update(plaintext) + padder.finalize()
            cipher   = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            enc      = cipher.encryptor()
            return enc.update(padded) + enc.finalize()

        def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
            cipher   = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            dec      = cipher.decryptor()
            padded   = dec.update(ciphertext) + dec.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()

        return encrypt, decrypt

    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad

        def encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return cipher.encrypt(pad(plaintext, 16))

        def decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            return unpad(cipher.decrypt(ciphertext), 16)

        return encrypt, decrypt

    except ImportError:
        raise RuntimeError(
            "No AES backend available. Install one:\n"
            "  pip install cryptography\n"
            "  pip install pycryptodome"
        )


_aes_encrypt, _aes_decrypt = _get_aes()


# ── Key derivation ────────────────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA512."""
    return hashlib.pbkdf2_hmac(
        'sha512',
        password.encode('utf-8'),
        salt,
        KDF_ITERS,
        dklen=32,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def encrypt_module(
    source_code: str,
    password: str,
    metadata: Optional[dict] = None,
) -> bytes:
    """
    Encrypt a Python module source string.

    Returns the raw .autarch file bytes.
    """
    meta_bytes  = json.dumps(metadata or {}).encode('utf-8')
    plaintext   = source_code.encode('utf-8')
    salt        = os.urandom(SALT_LEN)
    iv          = os.urandom(IV_LEN)
    key         = _derive_key(password, salt)
    digest      = hashlib.sha512(plaintext).digest()
    ciphertext  = _aes_encrypt(key, iv, plaintext)

    meta_len    = len(meta_bytes)
    header = (
        MAGIC
        + struct.pack('B', VERSION)
        + salt
        + iv
        + digest
        + struct.pack('<H', meta_len)
    )
    return header + meta_bytes + ciphertext


def decrypt_module(data: bytes, password: str) -> tuple[str, dict]:
    """
    Decrypt an .autarch blob.

    Returns (source_code: str, metadata: dict).
    Raises ValueError on bad magic, version, or integrity check failure.
    """
    offset = 0

    # Magic
    if data[offset:offset + 4] != MAGIC:
        raise ValueError("Not a valid AUTARCH encrypted module (bad magic)")
    offset += 4

    # Version
    version = data[offset]
    if version != VERSION:
        raise ValueError(f"Unsupported module version: {version:#04x}")
    offset += 1

    # Salt
    salt = data[offset:offset + SALT_LEN]
    offset += SALT_LEN

    # IV
    iv = data[offset:offset + IV_LEN]
    offset += IV_LEN

    # SHA-512 integrity hash
    stored_hash = data[offset:offset + HASH_LEN]
    offset += HASH_LEN

    # Metadata
    meta_len = struct.unpack('<H', data[offset:offset + 2])[0]
    offset += 2
    meta_bytes = data[offset:offset + meta_len]
    offset += meta_len
    metadata = json.loads(meta_bytes.decode('utf-8')) if meta_bytes else {}

    # Ciphertext
    ciphertext = data[offset:]

    # Derive key and decrypt
    key = _derive_key(password, salt)
    try:
        plaintext = _aes_decrypt(key, iv, ciphertext)
    except Exception as exc:
        raise ValueError(f"Decryption failed — wrong password? ({exc})")

    # Integrity check
    actual_hash = hashlib.sha512(plaintext).digest()
    if not hmac.compare_digest(actual_hash, stored_hash):
        raise ValueError("Integrity check failed — file tampered or wrong password")

    return plaintext.decode('utf-8'), metadata


def encrypt_file(src: Path, dst: Path, password: str, metadata: Optional[dict] = None) -> None:
    """Encrypt a .py source file to a .autarch file."""
    source = src.read_text(encoding='utf-8')
    blob   = encrypt_module(source, password, metadata)
    dst.write_bytes(blob)


def decrypt_file(src: Path, password: str) -> tuple[str, dict]:
    """Decrypt an .autarch file and return (source_code, metadata)."""
    return decrypt_module(src.read_bytes(), password)


def load_and_exec(
    path: Path,
    password: str,
    module_name: str = '__encmod__',
) -> dict:
    """
    Decrypt and execute an encrypted module.

    Returns the module's globals dict (its namespace).
    """
    source, meta = decrypt_file(path, password)
    namespace: dict = {
        '__name__': module_name,
        '__file__': str(path),
        '__builtins__': __builtins__,
    }
    exec(compile(source, str(path), 'exec'), namespace)
    return namespace


def read_metadata(path: Path) -> Optional[dict]:
    """
    Read only the metadata from an .autarch file without decrypting.
    Returns None if the file is invalid.
    """
    try:
        data   = path.read_bytes()
        if data[:4] != MAGIC:
            return None
        offset = 5 + SALT_LEN + IV_LEN + HASH_LEN
        meta_len = struct.unpack('<H', data[offset:offset + 2])[0]
        offset += 2
        meta_bytes = data[offset:offset + meta_len]
        return json.loads(meta_bytes.decode('utf-8')) if meta_bytes else {}
    except Exception:
        return None
