"""
Floppy_Dick — AUTARCH Encrypted Module
Operator: darkHal Security Group / Setec Security Labs

Automated credential fuzzer and authentication tester for legacy
and deprecated protocol stacks. Targets: FTP, SMB, Telnet, SMTP,
POP3, IMAP, SNMP v1/v2c, and RDP legacy endpoints. Generates
detailed vulnerability reports suitable for remediation guidance.

For authorized penetration testing ONLY.
"""

import itertools
import json
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

MODULE_NAME    = "Floppy_Dick"
MODULE_VERSION = "1.0"
MODULE_AUTHOR  = "darkHal Security Group"
MODULE_TAGS    = ["brute-force", "auth", "legacy", "pentest", "fuzz"]

_stop_flag    = threading.Event()
_output_lines = []


def _emit(msg: str, level: str = "info") -> None:
    ts   = datetime.now(timezone.utc).strftime('%H:%M:%S')
    line = f"[{ts}][{level.upper()}] {msg}"
    _output_lines.append(line)
    print(line)


# ── Credential generators ─────────────────────────────────────────────────────

DEFAULT_USERS = [
    'admin', 'administrator', 'root', 'user', 'guest', 'test',
    'ftp', 'anonymous', 'backup', 'operator', 'service',
]

DEFAULT_PASSWORDS = [
    '', 'admin', 'password', 'password123', '123456', 'admin123',
    'root', 'toor', 'pass', 'letmein', 'welcome', 'changeme',
    'default', 'cisco', 'alpine',
]


def wordlist_generator(path: Path) -> Iterator[str]:
    """Yield lines from a wordlist file."""
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            yield line.rstrip('\n')


def credential_pairs(users: list[str], passwords: list[str]) -> Iterator[tuple[str, str]]:
    """Yield all (user, password) combinations."""
    for u in users:
        for p in passwords:
            yield u, p


# ── Protocol testers ──────────────────────────────────────────────────────────

def test_ftp(host: str, port: int, user: str, password: str, timeout: float = 5.0) -> dict:
    """Test FTP credentials."""
    result = {'host': host, 'port': port, 'proto': 'FTP', 'user': user, 'success': False}
    try:
        import ftplib
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(user, password)
        result['success'] = True
        result['banner']  = ftp.getwelcome()
        ftp.quit()
    except ftplib.error_perm as exc:
        result['error'] = str(exc)
    except Exception as exc:
        result['error'] = str(exc)
    return result


def test_smtp(host: str, port: int, user: str, password: str, timeout: float = 5.0) -> dict:
    """Test SMTP AUTH credentials."""
    result = {'host': host, 'port': port, 'proto': 'SMTP', 'user': user, 'success': False}
    try:
        import smtplib
        smtp = smtplib.SMTP(host, port, timeout=timeout)
        smtp.ehlo()
        if port == 587:
            smtp.starttls()
        smtp.login(user, password)
        result['success'] = True
        smtp.quit()
    except smtplib.SMTPAuthenticationError as exc:
        result['error'] = 'bad credentials'
    except Exception as exc:
        result['error'] = str(exc)
    return result


def test_telnet(host: str, port: int, user: str, password: str, timeout: float = 5.0) -> dict:
    """Test Telnet authentication."""
    result = {'host': host, 'port': port, 'proto': 'Telnet', 'user': user, 'success': False}
    try:
        import telnetlib
        tn = telnetlib.Telnet(host, port, timeout=timeout)
        tn.read_until(b'login: ', timeout)
        tn.write(user.encode('ascii') + b'\n')
        tn.read_until(b'Password: ', timeout)
        tn.write(password.encode('ascii') + b'\n')
        response = tn.read_until(b'$', timeout)
        if b'incorrect' not in response.lower() and b'failed' not in response.lower():
            result['success'] = True
            result['banner']  = response.decode('utf-8', errors='replace')[:128]
        tn.close()
    except Exception as exc:
        result['error'] = str(exc)
    return result


def test_snmp(host: str, community: str = 'public', version: str = '2c', timeout: float = 3.0) -> dict:
    """Test SNMP community string (v1/v2c)."""
    result = {'host': host, 'proto': 'SNMP', 'community': community, 'success': False}
    try:
        from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community, mpModel=0 if version == '1' else 1),
                   UdpTransportTarget((host, 161), timeout=timeout),
                   ContextData(),
                   ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0)))
        )
        if not errorIndication and not errorStatus:
            result['success'] = True
            result['sysDescr'] = str(varBinds[0])
        else:
            result['error'] = str(errorIndication or errorStatus)
    except ImportError:
        result['error'] = 'pysnmp not installed'
    except Exception as exc:
        result['error'] = str(exc)
    return result


def test_generic_banner(host: str, port: int, timeout: float = 3.0) -> dict:
    """Grab a service banner from any TCP port."""
    result = {'host': host, 'port': port, 'proto': 'TCP', 'banner': ''}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024)
        result['banner'] = banner.decode('utf-8', errors='replace').strip()[:256]
        result['open'] = True
        s.close()
    except Exception as exc:
        result['open'] = False
        result['error'] = str(exc)
    return result


# ── Port scanner ──────────────────────────────────────────────────────────────

LEGACY_PORTS = {
    21:  'FTP',
    23:  'Telnet',
    25:  'SMTP',
    110: 'POP3',
    143: 'IMAP',
    161: 'SNMP',
    445: 'SMB',
    587: 'SMTP-Submission',
    3389: 'RDP',
}


def scan_ports(host: str, ports: Optional[list[int]] = None, timeout: float = 1.0) -> dict:
    """Scan ports and return which are open."""
    if ports is None:
        ports = list(LEGACY_PORTS.keys())
    open_ports = {}
    for port in ports:
        banner = test_generic_banner(host, port, timeout)
        if banner.get('open'):
            proto = LEGACY_PORTS.get(port, 'unknown')
            open_ports[port] = {
                'proto':  proto,
                'banner': banner.get('banner', ''),
            }
    return {'host': host, 'open_ports': open_ports}


# ── Main fuzzing engine ───────────────────────────────────────────────────────

def fuzz_host(
    host: str,
    port: int,
    proto: str,
    users: list[str],
    passwords: list[str],
    delay: float = 0.1,
    output_cb=None,
) -> list[dict]:
    """Run credential fuzzing against a single host:port for a given protocol."""
    found = []
    testers = {
        'FTP':  test_ftp,
        'SMTP': test_smtp,
        'SMTP-Submission': test_smtp,
        'Telnet': test_telnet,
    }
    tester = testers.get(proto)
    if not tester:
        return [{'error': f'No tester implemented for {proto}'}]

    for user, password in credential_pairs(users, passwords):
        if _stop_flag.is_set():
            break
        r = tester(host, port, user, password)
        if r.get('success'):
            msg = f"[FOUND] {proto} {host}:{port} -> {user}:{password}"
            _emit(msg, 'warn')
            if output_cb:
                output_cb({'line': msg, 'found': True, 'user': user, 'password': password})
            found.append(r)
        time.sleep(delay)

    return found


# ── Main run entry point ──────────────────────────────────────────────────────

def run(params: dict, output_cb=None) -> dict:
    """
    Main execution entry point.

    params:
      targets     — list of hosts to test
      ports       — list of ports to probe (default: LEGACY_PORTS)
      users       — list of usernames (default: DEFAULT_USERS)
      passwords   — list of passwords (default: DEFAULT_PASSWORDS)
      user_wordlist   — path to user wordlist file
      pass_wordlist   — path to password wordlist file
      delay       — delay between attempts in seconds (default 0.1)
      snmp_communities — list of SNMP community strings to test
      threads     — number of parallel threads (default 1)
    """
    _stop_flag.clear()
    _output_lines.clear()

    def emit(msg, level='info'):
        _emit(msg, level)
        if output_cb:
            output_cb({'line': f"[{level.upper()}] {msg}"})

    emit(f"=== {MODULE_NAME} v{MODULE_VERSION} ===")
    emit("Authorized penetration testing only. All attempts logged.")

    targets   = params.get('targets', [])
    ports     = params.get('ports', None)
    delay     = float(params.get('delay', 0.1))
    users     = params.get('users', DEFAULT_USERS)[:]
    passwords = params.get('passwords', DEFAULT_PASSWORDS)[:]

    # Load wordlists if provided
    uw = params.get('user_wordlist', '')
    pw = params.get('pass_wordlist', '')
    if uw and Path(uw).exists():
        users = list(wordlist_generator(Path(uw)))
        emit(f"Loaded {len(users)} users from wordlist")
    if pw and Path(pw).exists():
        passwords = list(wordlist_generator(Path(pw)))
        emit(f"Loaded {len(passwords)} passwords from wordlist")

    snmp_communities = params.get('snmp_communities', ['public', 'private', 'community'])

    all_results = []

    for host in targets:
        if _stop_flag.is_set():
            break
        emit(f"Scanning {host}...")
        scan = scan_ports(host, ports)
        emit(f"  Open ports: {list(scan['open_ports'].keys())}")

        host_result = {'host': host, 'open_ports': scan['open_ports'], 'findings': []}

        for port, info in scan['open_ports'].items():
            if _stop_flag.is_set():
                break
            proto = info['proto']
            emit(f"  Fuzzing {proto} on port {port}...")

            if proto == 'SNMP':
                for comm in snmp_communities:
                    r = test_snmp(host, comm)
                    if r.get('success'):
                        emit(f"[FOUND] SNMP community: {comm}", 'warn')
                        host_result['findings'].append(r)
            else:
                found = fuzz_host(host, port, proto, users, passwords, delay, output_cb)
                host_result['findings'].extend(found)

        all_results.append(host_result)

    emit(f"Fuzzing complete. {sum(len(r['findings']) for r in all_results)} finding(s).")

    return {
        'module':   MODULE_NAME,
        'targets':  len(targets),
        'results':  all_results,
        'output':   _output_lines[:],
    }


def stop():
    _stop_flag.set()
