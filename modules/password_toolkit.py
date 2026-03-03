"""AUTARCH Password Toolkit

Hash identification, cracking (hashcat/john integration), password generation,
credential spray/stuff testing, wordlist management, and password policy auditing.
"""

DESCRIPTION = "Password cracking & credential testing"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import string
import secrets
import hashlib
import threading
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    import shutil
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Hash Type Signatures ──────────────────────────────────────────────────────

@dataclass
class HashSignature:
    name: str
    regex: str
    hashcat_mode: int
    john_format: str
    example: str
    bits: int = 0


HASH_SIGNATURES: List[HashSignature] = [
    HashSignature('MD5',           r'^[a-fA-F0-9]{32}$',                   0,    'raw-md5',        'd41d8cd98f00b204e9800998ecf8427e', 128),
    HashSignature('SHA-1',         r'^[a-fA-F0-9]{40}$',                   100,  'raw-sha1',       'da39a3ee5e6b4b0d3255bfef95601890afd80709', 160),
    HashSignature('SHA-224',       r'^[a-fA-F0-9]{56}$',                   1300, 'raw-sha224',     'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f', 224),
    HashSignature('SHA-256',       r'^[a-fA-F0-9]{64}$',                   1400, 'raw-sha256',     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 256),
    HashSignature('SHA-384',       r'^[a-fA-F0-9]{96}$',                   10800,'raw-sha384',     '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b', 384),
    HashSignature('SHA-512',       r'^[a-fA-F0-9]{128}$',                  1700, 'raw-sha512',     'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', 512),
    HashSignature('NTLM',          r'^[a-fA-F0-9]{32}$',                   1000, 'nt',             '31d6cfe0d16ae931b73c59d7e0c089c0', 128),
    HashSignature('LM',            r'^[a-fA-F0-9]{32}$',                   3000, 'lm',             'aad3b435b51404eeaad3b435b51404ee', 128),
    HashSignature('bcrypt',        r'^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$', 3200, 'bcrypt',    '$2b$12$LJ3m4ys3Lg2VBe5F.4oXzuLKmRPBRWvs5fS5K.zL1E8CfJzqS/VfO', 0),
    HashSignature('scrypt',        r'^\$7\$',                              8900, 'scrypt',         '', 0),
    HashSignature('Argon2',        r'^\$argon2(i|d|id)\$',                 0,    'argon2',         '', 0),
    HashSignature('MySQL 4.1+',    r'^\*[a-fA-F0-9]{40}$',                300,  'mysql-sha1',     '*6C8989366EAF6BCBBAA855D6DA93DE65C96D33D9', 160),
    HashSignature('SHA-512 Crypt', r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$', 1800, 'sha512crypt', '', 0),
    HashSignature('SHA-256 Crypt', r'^\$5\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{43}$', 7400, 'sha256crypt', '', 0),
    HashSignature('MD5 Crypt',     r'^\$1\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{22}$', 500,  'md5crypt',  '', 0),
    HashSignature('DES Crypt',     r'^[./A-Za-z0-9]{13}$',                1500, 'descrypt',       '', 0),
    HashSignature('APR1 MD5',      r'^\$apr1\$',                           1600, 'md5apr1',        '', 0),
    HashSignature('Cisco Type 5',  r'^\$1\$[./A-Za-z0-9]{8}\$[./A-Za-z0-9]{22}$', 500, 'md5crypt', '', 0),
    HashSignature('Cisco Type 7',  r'^[0-9]{2}[0-9A-Fa-f]+$',             0,    '',               '', 0),
    HashSignature('PBKDF2-SHA256', r'^\$pbkdf2-sha256\$',                  10900,'pbkdf2-hmac-sha256', '', 0),
    HashSignature('Django SHA256', r'^pbkdf2_sha256\$',                    10000,'django',         '', 0),
    HashSignature('CRC32',         r'^[a-fA-F0-9]{8}$',                   0,    '',               'deadbeef', 32),
]


# ── Password Toolkit Service ─────────────────────────────────────────────────

class PasswordToolkit:
    """Hash identification, cracking, generation, and credential testing."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'password_toolkit')
        self._wordlists_dir = os.path.join(self._data_dir, 'wordlists')
        self._results_dir = os.path.join(self._data_dir, 'results')
        os.makedirs(self._wordlists_dir, exist_ok=True)
        os.makedirs(self._results_dir, exist_ok=True)
        self._active_jobs: Dict[str, dict] = {}

    # ── Hash Identification ───────────────────────────────────────────────

    def identify_hash(self, hash_str: str) -> List[dict]:
        """Identify possible hash types for a given hash string."""
        hash_str = hash_str.strip()
        matches = []
        for sig in HASH_SIGNATURES:
            if re.match(sig.regex, hash_str):
                matches.append({
                    'name': sig.name,
                    'hashcat_mode': sig.hashcat_mode,
                    'john_format': sig.john_format,
                    'bits': sig.bits,
                    'confidence': self._hash_confidence(hash_str, sig),
                })
        # Sort by confidence
        matches.sort(key=lambda m: {'high': 0, 'medium': 1, 'low': 2}.get(m['confidence'], 3))
        return matches

    def _hash_confidence(self, hash_str: str, sig: HashSignature) -> str:
        """Estimate confidence of hash type match."""
        # bcrypt, scrypt, argon2, crypt formats are definitive
        if sig.name in ('bcrypt', 'scrypt', 'Argon2', 'SHA-512 Crypt',
                        'SHA-256 Crypt', 'MD5 Crypt', 'APR1 MD5',
                        'PBKDF2-SHA256', 'Django SHA256', 'MySQL 4.1+'):
            return 'high'
        # Length-based can be ambiguous (MD5 vs NTLM vs LM)
        if len(hash_str) == 32:
            return 'medium'  # Could be MD5, NTLM, or LM
        if len(hash_str) == 8:
            return 'low'     # CRC32 vs short hex
        return 'medium'

    def identify_batch(self, hashes: List[str]) -> List[dict]:
        """Identify types for multiple hashes."""
        results = []
        for h in hashes:
            h = h.strip()
            if not h:
                continue
            ids = self.identify_hash(h)
            results.append({'hash': h, 'types': ids})
        return results

    # ── Hash Cracking ─────────────────────────────────────────────────────

    def crack_hash(self, hash_str: str, hash_type: str = 'auto',
                   wordlist: str = '', attack_mode: str = 'dictionary',
                   rules: str = '', mask: str = '',
                   tool: str = 'auto') -> dict:
        """Start a hash cracking job.

        attack_mode: 'dictionary', 'brute_force', 'mask', 'hybrid'
        tool: 'hashcat', 'john', 'auto' (try hashcat first, then john)
        """
        hash_str = hash_str.strip()
        if not hash_str:
            return {'ok': False, 'error': 'No hash provided'}

        # Auto-detect hash type if needed
        if hash_type == 'auto':
            ids = self.identify_hash(hash_str)
            if not ids:
                return {'ok': False, 'error': 'Could not identify hash type'}
            hash_type = ids[0]['name']

        # Find cracking tool
        hashcat = find_tool('hashcat')
        john = find_tool('john')

        if tool == 'auto':
            tool = 'hashcat' if hashcat else ('john' if john else None)
        elif tool == 'hashcat' and not hashcat:
            return {'ok': False, 'error': 'hashcat not found'}
        elif tool == 'john' and not john:
            return {'ok': False, 'error': 'john not found'}

        if not tool:
            # Fallback: Python-based dictionary attack (slow but works)
            return self._python_crack(hash_str, hash_type, wordlist)

        # Default wordlist
        if not wordlist:
            wordlist = self._find_default_wordlist()

        job_id = f'crack_{int(time.time())}_{secrets.token_hex(4)}'

        if tool == 'hashcat':
            return self._crack_hashcat(job_id, hash_str, hash_type,
                                       wordlist, attack_mode, rules, mask)
        else:
            return self._crack_john(job_id, hash_str, hash_type,
                                    wordlist, attack_mode, rules, mask)

    def _crack_hashcat(self, job_id: str, hash_str: str, hash_type: str,
                       wordlist: str, attack_mode: str, rules: str,
                       mask: str) -> dict:
        """Crack using hashcat."""
        hashcat = find_tool('hashcat')
        # Get hashcat mode
        mode = 0
        for sig in HASH_SIGNATURES:
            if sig.name == hash_type:
                mode = sig.hashcat_mode
                break

        # Write hash to temp file
        hash_file = os.path.join(self._results_dir, f'{job_id}.hash')
        out_file = os.path.join(self._results_dir, f'{job_id}.pot')
        with open(hash_file, 'w') as f:
            f.write(hash_str + '\n')

        cmd = [hashcat, '-m', str(mode), hash_file, '-o', out_file, '--potfile-disable']

        attack_modes = {'dictionary': '0', 'brute_force': '3', 'mask': '3', 'hybrid': '6'}
        cmd.extend(['-a', attack_modes.get(attack_mode, '0')])

        if attack_mode in ('dictionary', 'hybrid') and wordlist:
            cmd.append(wordlist)
        if attack_mode in ('brute_force', 'mask') and mask:
            cmd.append(mask)
        elif attack_mode == 'brute_force' and not mask:
            cmd.append('?a?a?a?a?a?a?a?a')  # Default 8-char brute force
        if rules:
            cmd.extend(['-r', rules])

        result_holder = {'result': None, 'done': False, 'process': None}
        self._active_jobs[job_id] = result_holder

        def run_crack():
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                result_holder['process'] = None
                cracked = ''
                if os.path.exists(out_file):
                    with open(out_file, 'r') as f:
                        cracked = f.read().strip()
                result_holder['result'] = {
                    'ok': True,
                    'cracked': cracked,
                    'output': proc.stdout[-2000:] if proc.stdout else '',
                    'returncode': proc.returncode,
                }
            except subprocess.TimeoutExpired:
                result_holder['result'] = {'ok': False, 'error': 'Crack timed out (1 hour)'}
            except Exception as e:
                result_holder['result'] = {'ok': False, 'error': str(e)}
            finally:
                result_holder['done'] = True

        threading.Thread(target=run_crack, daemon=True).start()
        return {'ok': True, 'job_id': job_id, 'message': f'Cracking started with hashcat (mode {mode})'}

    def _crack_john(self, job_id: str, hash_str: str, hash_type: str,
                    wordlist: str, attack_mode: str, rules: str,
                    mask: str) -> dict:
        """Crack using John the Ripper."""
        john = find_tool('john')
        fmt = ''
        for sig in HASH_SIGNATURES:
            if sig.name == hash_type:
                fmt = sig.john_format
                break

        hash_file = os.path.join(self._results_dir, f'{job_id}.hash')
        with open(hash_file, 'w') as f:
            f.write(hash_str + '\n')

        cmd = [john, hash_file]
        if fmt:
            cmd.extend(['--format=' + fmt])
        if wordlist and attack_mode == 'dictionary':
            cmd.extend(['--wordlist=' + wordlist])
        if rules:
            cmd.extend(['--rules=' + rules])
        if attack_mode in ('mask', 'brute_force') and mask:
            cmd.extend(['--mask=' + mask])

        result_holder = {'result': None, 'done': False}
        self._active_jobs[job_id] = result_holder

        def run_crack():
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
                # Get cracked results
                show = subprocess.run([john, '--show', hash_file],
                                      capture_output=True, text=True, timeout=10)
                result_holder['result'] = {
                    'ok': True,
                    'cracked': show.stdout.strip() if show.stdout else '',
                    'output': proc.stdout[-2000:] if proc.stdout else '',
                    'returncode': proc.returncode,
                }
            except subprocess.TimeoutExpired:
                result_holder['result'] = {'ok': False, 'error': 'Crack timed out (1 hour)'}
            except Exception as e:
                result_holder['result'] = {'ok': False, 'error': str(e)}
            finally:
                result_holder['done'] = True

        threading.Thread(target=run_crack, daemon=True).start()
        return {'ok': True, 'job_id': job_id, 'message': f'Cracking started with john ({fmt or "auto"})'}

    def _python_crack(self, hash_str: str, hash_type: str,
                      wordlist: str) -> dict:
        """Fallback pure-Python dictionary crack for common hash types."""
        algo_map = {
            'MD5': 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256',
            'SHA-512': 'sha512', 'SHA-224': 'sha224', 'SHA-384': 'sha384',
        }
        algo = algo_map.get(hash_type)
        if not algo:
            return {'ok': False, 'error': f'Python cracker does not support {hash_type}. Install hashcat or john.'}

        if not wordlist:
            wordlist = self._find_default_wordlist()
        if not wordlist or not os.path.exists(wordlist):
            return {'ok': False, 'error': 'No wordlist available'}

        hash_lower = hash_str.lower()
        tried = 0
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if not word:
                        continue
                    h = hashlib.new(algo, word.encode('utf-8')).hexdigest()
                    tried += 1
                    if h == hash_lower:
                        return {
                            'ok': True,
                            'cracked': f'{hash_str}:{word}',
                            'plaintext': word,
                            'tried': tried,
                            'message': f'Cracked! Password: {word}',
                        }
                    if tried >= 10_000_000:
                        break
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        return {'ok': True, 'cracked': '', 'tried': tried,
                'message': f'Not cracked. Tried {tried:,} candidates.'}

    def get_crack_status(self, job_id: str) -> dict:
        """Check status of a cracking job."""
        holder = self._active_jobs.get(job_id)
        if not holder:
            return {'ok': False, 'error': 'Job not found'}
        if not holder['done']:
            return {'ok': True, 'done': False, 'message': 'Cracking in progress...'}
        self._active_jobs.pop(job_id, None)
        return {'ok': True, 'done': True, **holder['result']}

    # ── Password Generation ───────────────────────────────────────────────

    def generate_password(self, length: int = 16, count: int = 1,
                          uppercase: bool = True, lowercase: bool = True,
                          digits: bool = True, symbols: bool = True,
                          exclude_chars: str = '',
                          pattern: str = '') -> List[str]:
        """Generate secure random passwords."""
        if pattern:
            return [self._generate_from_pattern(pattern) for _ in range(count)]

        charset = ''
        if uppercase:
            charset += string.ascii_uppercase
        if lowercase:
            charset += string.ascii_lowercase
        if digits:
            charset += string.digits
        if symbols:
            charset += '!@#$%^&*()-_=+[]{}|;:,.<>?'
        if exclude_chars:
            charset = ''.join(c for c in charset if c not in exclude_chars)
        if not charset:
            charset = string.ascii_letters + string.digits

        length = max(4, min(length, 128))
        count = max(1, min(count, 100))

        passwords = []
        for _ in range(count):
            pw = ''.join(secrets.choice(charset) for _ in range(length))
            passwords.append(pw)
        return passwords

    def _generate_from_pattern(self, pattern: str) -> str:
        """Generate password from pattern.
        ?u = uppercase, ?l = lowercase, ?d = digit, ?s = symbol, ?a = any
        """
        result = []
        i = 0
        while i < len(pattern):
            if pattern[i] == '?' and i + 1 < len(pattern):
                c = pattern[i + 1]
                if c == 'u':
                    result.append(secrets.choice(string.ascii_uppercase))
                elif c == 'l':
                    result.append(secrets.choice(string.ascii_lowercase))
                elif c == 'd':
                    result.append(secrets.choice(string.digits))
                elif c == 's':
                    result.append(secrets.choice('!@#$%^&*()-_=+'))
                elif c == 'a':
                    result.append(secrets.choice(
                        string.ascii_letters + string.digits + '!@#$%^&*'))
                else:
                    result.append(pattern[i:i+2])
                i += 2
            else:
                result.append(pattern[i])
                i += 1
        return ''.join(result)

    # ── Password Policy Audit ─────────────────────────────────────────────

    def audit_password(self, password: str) -> dict:
        """Audit a password against common policies and calculate entropy."""
        import math
        checks = {
            'length_8': len(password) >= 8,
            'length_12': len(password) >= 12,
            'length_16': len(password) >= 16,
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'[0-9]', password)),
            'has_symbol': bool(re.search(r'[^A-Za-z0-9]', password)),
            'no_common_patterns': not self._has_common_patterns(password),
            'no_sequential': not self._has_sequential(password),
            'no_repeated': not self._has_repeated(password),
        }

        # Calculate entropy
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            charset_size += 32
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0

        # Strength rating
        if entropy >= 80 and all(checks.values()):
            strength = 'very_strong'
        elif entropy >= 60 and checks['length_12']:
            strength = 'strong'
        elif entropy >= 40 and checks['length_8']:
            strength = 'medium'
        elif entropy >= 28:
            strength = 'weak'
        else:
            strength = 'very_weak'

        return {
            'length': len(password),
            'entropy': round(entropy, 1),
            'strength': strength,
            'checks': checks,
            'charset_size': charset_size,
        }

    def _has_common_patterns(self, pw: str) -> bool:
        common = ['password', '123456', 'qwerty', 'abc123', 'letmein',
                  'admin', 'welcome', 'monkey', 'dragon', 'master',
                  'login', 'princess', 'football', 'shadow', 'sunshine',
                  'trustno1', 'iloveyou', 'batman', 'access', 'hello']
        pl = pw.lower()
        return any(c in pl for c in common)

    def _has_sequential(self, pw: str) -> bool:
        for i in range(len(pw) - 2):
            if (ord(pw[i]) + 1 == ord(pw[i+1]) == ord(pw[i+2]) - 1):
                return True
        return False

    def _has_repeated(self, pw: str) -> bool:
        for i in range(len(pw) - 2):
            if pw[i] == pw[i+1] == pw[i+2]:
                return True
        return False

    # ── Credential Spray / Stuff ──────────────────────────────────────────

    def credential_spray(self, targets: List[dict], passwords: List[str],
                         protocol: str = 'ssh', threads: int = 4,
                         delay: float = 1.0) -> dict:
        """Spray passwords against target services.

        targets: [{'host': '...', 'port': 22, 'username': 'admin'}, ...]
        protocol: 'ssh', 'ftp', 'smb', 'http_basic', 'http_form'
        """
        if not targets or not passwords:
            return {'ok': False, 'error': 'Targets and passwords required'}

        job_id = f'spray_{int(time.time())}_{secrets.token_hex(4)}'
        result_holder = {
            'done': False,
            'results': [],
            'total': len(targets) * len(passwords),
            'tested': 0,
            'found': [],
        }
        self._active_jobs[job_id] = result_holder

        def do_spray():
            import socket as sock_mod
            for target in targets:
                host = target.get('host', '')
                port = target.get('port', 0)
                username = target.get('username', '')
                for pw in passwords:
                    if protocol == 'ssh':
                        ok = self._test_ssh(host, port or 22, username, pw)
                    elif protocol == 'ftp':
                        ok = self._test_ftp(host, port or 21, username, pw)
                    elif protocol == 'smb':
                        ok = self._test_smb(host, port or 445, username, pw)
                    else:
                        ok = False

                    result_holder['tested'] += 1
                    if ok:
                        cred = {'host': host, 'port': port, 'username': username,
                                'password': pw, 'protocol': protocol}
                        result_holder['found'].append(cred)

                    time.sleep(delay)
            result_holder['done'] = True

        threading.Thread(target=do_spray, daemon=True).start()
        return {'ok': True, 'job_id': job_id,
                'message': f'Spray started: {len(targets)} targets × {len(passwords)} passwords'}

    def _test_ssh(self, host: str, port: int, user: str, pw: str) -> bool:
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pw,
                           timeout=5, look_for_keys=False, allow_agent=False)
            client.close()
            return True
        except Exception:
            return False

    def _test_ftp(self, host: str, port: int, user: str, pw: str) -> bool:
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, pw)
            ftp.quit()
            return True
        except Exception:
            return False

    def _test_smb(self, host: str, port: int, user: str, pw: str) -> bool:
        try:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(host, host, sess_port=port)
            conn.login(user, pw)
            conn.close()
            return True
        except Exception:
            return False

    def get_spray_status(self, job_id: str) -> dict:
        holder = self._active_jobs.get(job_id)
        if not holder:
            return {'ok': False, 'error': 'Job not found'}
        return {
            'ok': True,
            'done': holder['done'],
            'tested': holder['tested'],
            'total': holder['total'],
            'found': holder['found'],
        }

    # ── Wordlist Management ───────────────────────────────────────────────

    def list_wordlists(self) -> List[dict]:
        """List available wordlists."""
        results = []
        for f in Path(self._wordlists_dir).glob('*'):
            if f.is_file():
                size = f.stat().st_size
                line_count = 0
                try:
                    with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                        for _ in fh:
                            line_count += 1
                            if line_count > 10_000_000:
                                break
                except Exception:
                    pass
                results.append({
                    'name': f.name,
                    'path': str(f),
                    'size': size,
                    'size_human': self._human_size(size),
                    'lines': line_count,
                })
        # Also check common system locations
        system_lists = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
            '/usr/share/wordlists/fasttrack.txt',
        ]
        for path in system_lists:
            if os.path.exists(path) and not any(r['path'] == path for r in results):
                size = os.path.getsize(path)
                results.append({
                    'name': os.path.basename(path),
                    'path': path,
                    'size': size,
                    'size_human': self._human_size(size),
                    'lines': -1,  # Don't count for system lists
                    'system': True,
                })
        return results

    def _find_default_wordlist(self) -> str:
        """Find the best available wordlist."""
        # Check our wordlists dir first
        for f in Path(self._wordlists_dir).glob('*'):
            if f.is_file() and f.stat().st_size > 100:
                return str(f)
        # System locations
        candidates = [
            '/usr/share/wordlists/rockyou.txt',
            '/usr/share/wordlists/fasttrack.txt',
            '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return ''

    def upload_wordlist(self, filename: str, data: bytes) -> dict:
        """Save an uploaded wordlist."""
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        path = os.path.join(self._wordlists_dir, safe_name)
        with open(path, 'wb') as f:
            f.write(data)
        return {'ok': True, 'path': path, 'name': safe_name}

    def delete_wordlist(self, name: str) -> dict:
        path = os.path.join(self._wordlists_dir, name)
        if os.path.exists(path):
            os.remove(path)
            return {'ok': True}
        return {'ok': False, 'error': 'Wordlist not found'}

    # ── Hash Generation (for testing) ─────────────────────────────────────

    def hash_string(self, plaintext: str, algorithm: str = 'md5') -> dict:
        """Hash a string with a given algorithm."""
        algo_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
        }
        fn = algo_map.get(algorithm.lower())
        if not fn:
            return {'ok': False, 'error': f'Unsupported algorithm: {algorithm}'}
        h = fn(plaintext.encode('utf-8')).hexdigest()
        return {'ok': True, 'hash': h, 'algorithm': algorithm, 'plaintext': plaintext}

    # ── Tool Detection ────────────────────────────────────────────────────

    def get_tools_status(self) -> dict:
        """Check which cracking tools are available."""
        return {
            'hashcat': bool(find_tool('hashcat')),
            'john': bool(find_tool('john')),
            'hydra': bool(find_tool('hydra')),
            'ncrack': bool(find_tool('ncrack')),
        }

    @staticmethod
    def _human_size(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024:
                return f'{size:.1f} {unit}'
            size /= 1024
        return f'{size:.1f} TB'


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_password_toolkit() -> PasswordToolkit:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = PasswordToolkit()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Password Toolkit."""
    svc = get_password_toolkit()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║       PASSWORD TOOLKIT                ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — Identify Hash                    ║")
        print("║  2 — Crack Hash                       ║")
        print("║  3 — Generate Passwords               ║")
        print("║  4 — Audit Password Strength          ║")
        print("║  5 — Hash a String                    ║")
        print("║  6 — Wordlist Management              ║")
        print("║  7 — Tool Status                      ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            h = input("  Hash: ").strip()
            if not h:
                continue
            results = svc.identify_hash(h)
            if results:
                print(f"\n  Possible types ({len(results)}):")
                for r in results:
                    print(f"    [{r['confidence'].upper():6s}] {r['name']}"
                          f"  (hashcat: {r['hashcat_mode']}, john: {r['john_format']})")
            else:
                print("  No matching hash types found.")
        elif choice == '2':
            h = input("  Hash: ").strip()
            wl = input("  Wordlist (empty=default): ").strip()
            result = svc.crack_hash(h, wordlist=wl)
            if result.get('job_id'):
                print(f"  {result['message']}")
                print("  Waiting...")
                while True:
                    time.sleep(2)
                    s = svc.get_crack_status(result['job_id'])
                    if s.get('done'):
                        if s.get('cracked'):
                            print(f"\n  CRACKED: {s['cracked']}")
                        else:
                            print(f"\n  Not cracked. {s.get('message', '')}")
                        break
            elif result.get('cracked'):
                print(f"\n  CRACKED: {result['cracked']}")
            else:
                print(f"  {result.get('message', result.get('error', ''))}")
        elif choice == '3':
            length = int(input("  Length (default 16): ").strip() or '16')
            count = int(input("  Count (default 5): ").strip() or '5')
            passwords = svc.generate_password(length=length, count=count)
            print("\n  Generated passwords:")
            for pw in passwords:
                audit = svc.audit_password(pw)
                print(f"    {pw}  [{audit['strength']}] {audit['entropy']} bits")
        elif choice == '4':
            pw = input("  Password: ").strip()
            if not pw:
                continue
            audit = svc.audit_password(pw)
            print(f"\n  Strength: {audit['strength']}")
            print(f"  Entropy:  {audit['entropy']} bits")
            print(f"  Length:   {audit['length']}")
            print(f"  Charset:  {audit['charset_size']} characters")
            for check, passed in audit['checks'].items():
                mark = '\033[92m✓\033[0m' if passed else '\033[91m✗\033[0m'
                print(f"    {mark} {check}")
        elif choice == '5':
            text = input("  Plaintext: ").strip()
            algo = input("  Algorithm (md5/sha1/sha256/sha512): ").strip() or 'sha256'
            r = svc.hash_string(text, algo)
            if r['ok']:
                print(f"  {r['algorithm']}: {r['hash']}")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '6':
            wls = svc.list_wordlists()
            if wls:
                print(f"\n  Wordlists ({len(wls)}):")
                for w in wls:
                    sys_tag = ' [system]' if w.get('system') else ''
                    print(f"    {w['name']} — {w['size_human']}{sys_tag}")
            else:
                print("  No wordlists found.")
        elif choice == '7':
            tools = svc.get_tools_status()
            print("\n  Tool Status:")
            for tool, available in tools.items():
                mark = '\033[92m✓\033[0m' if available else '\033[91m✗\033[0m'
                print(f"    {mark} {tool}")
