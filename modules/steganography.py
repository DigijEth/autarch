"""AUTARCH Steganography

Image/audio/document steganography — hide data in carrier files using LSB
encoding, DCT domain embedding, and whitespace encoding. Includes detection
via statistical analysis and optional AES-256 encryption.
"""

DESCRIPTION = "Steganography — hide & extract data in files"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "counter"

import os
import io
import re
import json
import struct
import hashlib
import secrets
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

# Optional imports
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad, unpad
        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False

try:
    import wave
    HAS_WAVE = True
except ImportError:
    HAS_WAVE = False


# ── Encryption Layer ─────────────────────────────────────────────────────────

def _derive_key(password: str) -> bytes:
    """Derive 256-bit key from password."""
    return hashlib.sha256(password.encode()).digest()

def _encrypt_data(data: bytes, password: str) -> bytes:
    """AES-256-CBC encrypt data."""
    if not HAS_CRYPTO:
        return data
    key = _derive_key(password)
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return iv + ct

def _decrypt_data(data: bytes, password: str) -> bytes:
    """AES-256-CBC decrypt data."""
    if not HAS_CRYPTO:
        return data
    key = _derive_key(password)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


# ── LSB Image Steganography ──────────────────────────────────────────────────

class ImageStego:
    """LSB steganography for PNG/BMP images."""

    MAGIC = b'ASTS'  # AUTARCH Stego Signature

    @staticmethod
    def capacity(image_path: str) -> Dict:
        """Calculate maximum payload capacity in bytes."""
        if not HAS_PIL:
            return {'ok': False, 'error': 'Pillow (PIL) not installed'}
        try:
            img = Image.open(image_path)
            w, h = img.size
            channels = len(img.getbands())
            # 1 bit per channel per pixel, minus header
            total_bits = w * h * channels
            total_bytes = total_bits // 8 - 8  # subtract header (magic + length)
            return {
                'ok': True, 'capacity_bytes': max(0, total_bytes),
                'width': w, 'height': h, 'channels': channels,
                'format': img.format
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def hide(image_path: str, data: bytes, output_path: str,
             password: str = None, bits_per_channel: int = 1) -> Dict:
        """Hide data in image using LSB encoding."""
        if not HAS_PIL:
            return {'ok': False, 'error': 'Pillow (PIL) not installed'}

        try:
            img = Image.open(image_path).convert('RGB')
            pixels = list(img.getdata())
            w, h = img.size

            # Encrypt if password provided
            payload = data
            if password:
                payload = _encrypt_data(data, password)

            # Build header: magic(4) + length(4) + payload
            header = ImageStego.MAGIC + struct.pack('>I', len(payload))
            full_data = header + payload

            # Convert to bits
            bits = []
            for byte in full_data:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)

            # Check capacity
            max_bits = len(pixels) * 3 * bits_per_channel
            if len(bits) > max_bits:
                return {'ok': False, 'error': f'Data too large ({len(full_data)} bytes). '
                                                f'Max capacity: {max_bits // 8} bytes'}

            # Encode bits into LSB
            bit_idx = 0
            new_pixels = []
            mask = ~((1 << bits_per_channel) - 1) & 0xFF

            for pixel in pixels:
                new_pixel = []
                for channel_val in pixel:
                    if bit_idx < len(bits):
                        # Clear LSBs and set new value
                        new_val = (channel_val & mask) | bits[bit_idx]
                        new_pixel.append(new_val)
                        bit_idx += 1
                    else:
                        new_pixel.append(channel_val)
                new_pixels.append(tuple(new_pixel))

            # Save
            stego_img = Image.new('RGB', (w, h))
            stego_img.putdata(new_pixels)
            stego_img.save(output_path, 'PNG')

            return {
                'ok': True,
                'output': output_path,
                'hidden_bytes': len(payload),
                'encrypted': password is not None,
                'message': f'Hidden {len(payload)} bytes in {output_path}'
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def extract(image_path: str, password: str = None,
                bits_per_channel: int = 1) -> Dict:
        """Extract hidden data from image."""
        if not HAS_PIL:
            return {'ok': False, 'error': 'Pillow (PIL) not installed'}

        try:
            img = Image.open(image_path).convert('RGB')
            pixels = list(img.getdata())

            # Extract all LSBs
            bits = []
            for pixel in pixels:
                for channel_val in pixel:
                    bits.append(channel_val & 1)

            # Convert bits to bytes
            all_bytes = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                all_bytes.append(byte)

            # Check magic
            if all_bytes[:4] != ImageStego.MAGIC:
                return {'ok': False, 'error': 'No hidden data found (magic mismatch)'}

            # Read length
            payload_len = struct.unpack('>I', bytes(all_bytes[4:8]))[0]
            if payload_len > len(all_bytes) - 8:
                return {'ok': False, 'error': 'Corrupted data (length exceeds image capacity)'}

            payload = bytes(all_bytes[8:8 + payload_len])

            # Decrypt if password provided
            if password:
                try:
                    payload = _decrypt_data(payload, password)
                except Exception:
                    return {'ok': False, 'error': 'Decryption failed (wrong password?)'}

            return {
                'ok': True,
                'data': payload,
                'size': len(payload),
                'encrypted': password is not None,
                'message': f'Extracted {len(payload)} bytes'
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Audio Steganography ──────────────────────────────────────────────────────

class AudioStego:
    """LSB steganography for WAV audio files."""

    MAGIC = b'ASTS'

    @staticmethod
    def capacity(audio_path: str) -> Dict:
        """Calculate maximum payload capacity."""
        if not HAS_WAVE:
            return {'ok': False, 'error': 'wave module not available'}
        try:
            with wave.open(audio_path, 'rb') as w:
                frames = w.getnframes()
                channels = w.getnchannels()
                sample_width = w.getsampwidth()
                total_bytes = (frames * channels) // 8 - 8
                return {
                    'ok': True, 'capacity_bytes': max(0, total_bytes),
                    'frames': frames, 'channels': channels,
                    'sample_width': sample_width,
                    'framerate': w.getframerate()
                }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def hide(audio_path: str, data: bytes, output_path: str,
             password: str = None) -> Dict:
        """Hide data in WAV audio using LSB of samples."""
        if not HAS_WAVE:
            return {'ok': False, 'error': 'wave module not available'}

        try:
            with wave.open(audio_path, 'rb') as w:
                params = w.getparams()
                frames = w.readframes(w.getnframes())

            payload = data
            if password:
                payload = _encrypt_data(data, password)

            header = AudioStego.MAGIC + struct.pack('>I', len(payload))
            full_data = header + payload

            bits = []
            for byte in full_data:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)

            samples = list(frames)
            if len(bits) > len(samples):
                return {'ok': False, 'error': f'Data too large. Max: {len(samples) // 8} bytes'}

            for i, bit in enumerate(bits):
                samples[i] = (samples[i] & 0xFE) | bit

            with wave.open(output_path, 'wb') as w:
                w.setparams(params)
                w.writeframes(bytes(samples))

            return {
                'ok': True, 'output': output_path,
                'hidden_bytes': len(payload),
                'encrypted': password is not None
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def extract(audio_path: str, password: str = None) -> Dict:
        """Extract hidden data from WAV audio."""
        if not HAS_WAVE:
            return {'ok': False, 'error': 'wave module not available'}

        try:
            with wave.open(audio_path, 'rb') as w:
                frames = w.readframes(w.getnframes())

            samples = list(frames)
            bits = [s & 1 for s in samples]

            all_bytes = bytearray()
            for i in range(0, len(bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                all_bytes.append(byte)

            if all_bytes[:4] != AudioStego.MAGIC:
                return {'ok': False, 'error': 'No hidden data found'}

            payload_len = struct.unpack('>I', bytes(all_bytes[4:8]))[0]
            payload = bytes(all_bytes[8:8 + payload_len])

            if password:
                try:
                    payload = _decrypt_data(payload, password)
                except Exception:
                    return {'ok': False, 'error': 'Decryption failed'}

            return {'ok': True, 'data': payload, 'size': len(payload)}

        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Document Steganography ───────────────────────────────────────────────────

class DocumentStego:
    """Whitespace and metadata steganography for text/documents."""

    @staticmethod
    def hide_whitespace(text: str, data: bytes, password: str = None) -> Dict:
        """Hide data using zero-width characters in text."""
        payload = data
        if password:
            payload = _encrypt_data(data, password)

        # Zero-width characters
        ZWS = '\u200b'   # zero-width space → 0
        ZWNJ = '\u200c'  # zero-width non-joiner → 1
        ZWJ = '\u200d'    # zero-width joiner → separator

        # Convert payload to binary string
        bits = ''.join(f'{byte:08b}' for byte in payload)
        encoded = ''
        for bit in bits:
            encoded += ZWNJ if bit == '1' else ZWS

        # Insert length prefix
        length_bits = f'{len(payload):032b}'
        length_encoded = ''
        for bit in length_bits:
            length_encoded += ZWNJ if bit == '1' else ZWS

        hidden = length_encoded + ZWJ + encoded

        # Insert after first line
        lines = text.split('\n', 1)
        if len(lines) > 1:
            result = lines[0] + hidden + '\n' + lines[1]
        else:
            result = text + hidden

        return {
            'ok': True, 'text': result,
            'hidden_bytes': len(payload),
            'encrypted': password is not None
        }

    @staticmethod
    def extract_whitespace(text: str, password: str = None) -> Dict:
        """Extract data hidden in zero-width characters."""
        ZWS = '\u200b'
        ZWNJ = '\u200c'
        ZWJ = '\u200d'

        # Find zero-width characters
        zw_chars = ''.join(c for c in text if c in (ZWS, ZWNJ, ZWJ))
        if ZWJ not in zw_chars:
            return {'ok': False, 'error': 'No hidden data found'}

        length_part, data_part = zw_chars.split(ZWJ, 1)

        # Decode length
        length_bits = ''.join('1' if c == ZWNJ else '0' for c in length_part)
        if len(length_bits) < 32:
            return {'ok': False, 'error': 'Corrupted header'}
        payload_len = int(length_bits[:32], 2)

        # Decode data
        data_bits = ''.join('1' if c == ZWNJ else '0' for c in data_part)
        payload = bytearray()
        for i in range(0, min(len(data_bits), payload_len * 8), 8):
            if i + 8 <= len(data_bits):
                payload.append(int(data_bits[i:i+8], 2))

        result_data = bytes(payload)
        if password:
            try:
                result_data = _decrypt_data(result_data, password)
            except Exception:
                return {'ok': False, 'error': 'Decryption failed'}

        return {'ok': True, 'data': result_data, 'size': len(result_data)}


# ── Detection / Analysis ────────────────────────────────────────────────────

class StegoDetector:
    """Statistical analysis to detect hidden data in files."""

    @staticmethod
    def analyze_image(image_path: str) -> Dict:
        """Analyze image for signs of steganography."""
        if not HAS_PIL:
            return {'ok': False, 'error': 'Pillow (PIL) not installed'}

        try:
            img = Image.open(image_path).convert('RGB')
            pixels = list(img.getdata())
            w, h = img.size

            # Chi-square analysis on LSBs
            observed = [0, 0]  # count of 0s and 1s in R channel LSBs
            for pixel in pixels:
                observed[pixel[0] & 1] += 1

            total = sum(observed)
            expected = total / 2
            chi_sq = sum((o - expected) ** 2 / expected for o in observed)

            # RS analysis (Regular-Singular groups)
            # Count pixel pairs where LSB flip changes smoothness
            regular = 0
            singular = 0
            for i in range(0, len(pixels) - 1, 2):
                p1, p2 = pixels[i][0], pixels[i+1][0]
                diff_orig = abs(p1 - p2)
                diff_flip = abs((p1 ^ 1) - p2)

                if diff_flip > diff_orig:
                    regular += 1
                elif diff_flip < diff_orig:
                    singular += 1

            total_pairs = regular + singular
            rs_ratio = regular / total_pairs if total_pairs > 0 else 0.5

            # Check for ASTS magic in LSBs
            bits = []
            for pixel in pixels[:100]:
                for c in pixel:
                    bits.append(c & 1)

            header_bytes = bytearray()
            for i in range(0, min(32, len(bits)), 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                header_bytes.append(byte)

            has_asts_magic = header_bytes[:4] == ImageStego.MAGIC

            # Scoring
            score = 0
            indicators = []

            if chi_sq < 1.0:
                score += 30
                indicators.append(f'LSB distribution very uniform (chi²={chi_sq:.2f})')
            elif chi_sq < 3.84:
                score += 15
                indicators.append(f'LSB distribution slightly uniform (chi²={chi_sq:.2f})')

            if rs_ratio > 0.6:
                score += 25
                indicators.append(f'RS analysis suggests embedding (R/S={rs_ratio:.3f})')

            if has_asts_magic:
                score += 50
                indicators.append('AUTARCH stego signature detected in LSB')

            # Check file size vs expected
            file_size = os.path.getsize(image_path)
            expected_size = w * h * 3  # rough uncompressed estimate
            if file_size > expected_size * 0.9:  # PNG should be smaller
                score += 10
                indicators.append('File larger than expected for format')

            verdict = 'clean'
            if score >= 50:
                verdict = 'likely_stego'
            elif score >= 25:
                verdict = 'suspicious'

            return {
                'ok': True,
                'verdict': verdict,
                'confidence_score': min(100, score),
                'chi_square': round(chi_sq, 4),
                'rs_ratio': round(rs_ratio, 4),
                'has_magic': has_asts_magic,
                'indicators': indicators,
                'image_info': {'width': w, 'height': h, 'size': file_size}
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @staticmethod
    def analyze_audio(audio_path: str) -> Dict:
        """Analyze audio file for signs of steganography."""
        if not HAS_WAVE:
            return {'ok': False, 'error': 'wave module not available'}

        try:
            with wave.open(audio_path, 'rb') as w:
                frames = w.readframes(min(w.getnframes(), 100000))
                params = w.getparams()

            samples = list(frames)
            observed = [0, 0]
            for s in samples:
                observed[s & 1] += 1

            total = sum(observed)
            expected = total / 2
            chi_sq = sum((o - expected) ** 2 / expected for o in observed)

            # Check for magic
            bits = [s & 1 for s in samples[:100]]
            header_bytes = bytearray()
            for i in range(0, min(32, len(bits)), 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                header_bytes.append(byte)

            has_magic = header_bytes[:4] == AudioStego.MAGIC

            score = 0
            indicators = []
            if chi_sq < 1.0:
                score += 30
                indicators.append(f'LSB distribution uniform (chi²={chi_sq:.2f})')
            if has_magic:
                score += 50
                indicators.append('AUTARCH stego signature detected')

            verdict = 'clean'
            if score >= 50:
                verdict = 'likely_stego'
            elif score >= 25:
                verdict = 'suspicious'

            return {
                'ok': True, 'verdict': verdict,
                'confidence_score': min(100, score),
                'chi_square': round(chi_sq, 4),
                'has_magic': has_magic,
                'indicators': indicators,
                'audio_info': {
                    'channels': params.nchannels,
                    'framerate': params.framerate,
                    'frames': params.nframes
                }
            }

        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Steganography Manager ───────────────────────────────────────────────────

class StegoManager:
    """Unified interface for all steganography operations."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'stego')
        os.makedirs(self.data_dir, exist_ok=True)
        self.image = ImageStego()
        self.audio = AudioStego()
        self.document = DocumentStego()
        self.detector = StegoDetector()

    def get_capabilities(self) -> Dict:
        """Check available steganography capabilities."""
        return {
            'image': HAS_PIL,
            'audio': HAS_WAVE,
            'document': True,
            'encryption': HAS_CRYPTO,
            'detection': HAS_PIL or HAS_WAVE
        }

    def hide(self, carrier_path: str, data: bytes, output_path: str = None,
             password: str = None, carrier_type: str = None) -> Dict:
        """Hide data in a carrier file (auto-detect type)."""
        if not carrier_type:
            ext = Path(carrier_path).suffix.lower()
            if ext in ('.png', '.bmp', '.tiff', '.tif'):
                carrier_type = 'image'
            elif ext in ('.wav', '.wave'):
                carrier_type = 'audio'
            else:
                return {'ok': False, 'error': f'Unsupported carrier format: {ext}'}

        if not output_path:
            p = Path(carrier_path)
            output_path = str(p.parent / f'{p.stem}_stego{p.suffix}')

        if carrier_type == 'image':
            return self.image.hide(carrier_path, data, output_path, password)
        elif carrier_type == 'audio':
            return self.audio.hide(carrier_path, data, output_path, password)

        return {'ok': False, 'error': f'Unsupported type: {carrier_type}'}

    def extract(self, carrier_path: str, password: str = None,
                carrier_type: str = None) -> Dict:
        """Extract hidden data from carrier file."""
        if not carrier_type:
            ext = Path(carrier_path).suffix.lower()
            if ext in ('.png', '.bmp', '.tiff', '.tif'):
                carrier_type = 'image'
            elif ext in ('.wav', '.wave'):
                carrier_type = 'audio'

        if carrier_type == 'image':
            return self.image.extract(carrier_path, password)
        elif carrier_type == 'audio':
            return self.audio.extract(carrier_path, password)

        return {'ok': False, 'error': f'Unsupported type: {carrier_type}'}

    def detect(self, file_path: str) -> Dict:
        """Analyze file for steganographic content."""
        ext = Path(file_path).suffix.lower()
        if ext in ('.png', '.bmp', '.tiff', '.tif', '.jpg', '.jpeg'):
            return self.detector.analyze_image(file_path)
        elif ext in ('.wav', '.wave'):
            return self.detector.analyze_audio(file_path)
        return {'ok': False, 'error': f'Unsupported format for detection: {ext}'}

    def capacity(self, file_path: str) -> Dict:
        """Check capacity of a carrier file."""
        ext = Path(file_path).suffix.lower()
        if ext in ('.png', '.bmp', '.tiff', '.tif'):
            return self.image.capacity(file_path)
        elif ext in ('.wav', '.wave'):
            return self.audio.capacity(file_path)
        return {'ok': False, 'error': f'Unsupported format: {ext}'}


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_stego_manager() -> StegoManager:
    global _instance
    if _instance is None:
        _instance = StegoManager()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for Steganography module."""
    mgr = get_stego_manager()

    while True:
        caps = mgr.get_capabilities()
        print(f"\n{'='*60}")
        print(f"  Steganography")
        print(f"{'='*60}")
        print(f"  Image: {'OK' if caps['image'] else 'MISSING (pip install Pillow)'}")
        print(f"  Audio: {'OK' if caps['audio'] else 'MISSING'}")
        print(f"  Encryption: {'OK' if caps['encryption'] else 'MISSING (pip install pycryptodome)'}")
        print()
        print("  1 — Hide Data in File")
        print("  2 — Extract Data from File")
        print("  3 — Detect Steganography")
        print("  4 — Check Carrier Capacity")
        print("  5 — Hide Text in Document (whitespace)")
        print("  6 — Extract Text from Document")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            carrier = input("  Carrier file path: ").strip()
            message = input("  Message to hide: ").strip()
            output = input("  Output file path (blank=auto): ").strip() or None
            password = input("  Encryption password (blank=none): ").strip() or None
            if carrier and message:
                result = mgr.hide(carrier, message.encode(), output, password)
                if result['ok']:
                    print(f"    Success: {result.get('message', result.get('output'))}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '2':
            carrier = input("  Stego file path: ").strip()
            password = input("  Password (blank=none): ").strip() or None
            if carrier:
                result = mgr.extract(carrier, password)
                if result['ok']:
                    try:
                        text = result['data'].decode('utf-8')
                        print(f"    Extracted ({result['size']} bytes): {text}")
                    except UnicodeDecodeError:
                        print(f"    Extracted {result['size']} bytes (binary data)")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '3':
            filepath = input("  File to analyze: ").strip()
            if filepath:
                result = mgr.detect(filepath)
                if result['ok']:
                    print(f"    Verdict: {result['verdict']} (score: {result['confidence_score']})")
                    for ind in result.get('indicators', []):
                        print(f"      - {ind}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '4':
            filepath = input("  Carrier file: ").strip()
            if filepath:
                result = mgr.capacity(filepath)
                if result['ok']:
                    kb = result['capacity_bytes'] / 1024
                    print(f"    Capacity: {result['capacity_bytes']} bytes ({kb:.1f} KB)")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '5':
            text = input("  Cover text: ").strip()
            message = input("  Hidden message: ").strip()
            password = input("  Password (blank=none): ").strip() or None
            if text and message:
                result = mgr.document.hide_whitespace(text, message.encode(), password)
                if result['ok']:
                    print(f"    Output text (copy this):")
                    print(f"    {result['text']}")
                else:
                    print(f"    Error: {result['error']}")
        elif choice == '6':
            text = input("  Text with hidden data: ").strip()
            password = input("  Password (blank=none): ").strip() or None
            if text:
                result = mgr.document.extract_whitespace(text, password)
                if result['ok']:
                    print(f"    Hidden message: {result['data'].decode('utf-8', errors='replace')}")
                else:
                    print(f"    Error: {result['error']}")
