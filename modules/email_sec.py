"""AUTARCH Email Security

DMARC/SPF/DKIM analysis, email header forensics, phishing detection,
mailbox search, and abuse report generation for email security assessment.
"""

DESCRIPTION = "Email security — DMARC, SPF, header forensics"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

import os
import re
import sys
import json
import ssl
import time
import socket
import struct
import hashlib
import imaplib
import poplib
import email
import email.header
import email.utils
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse
import subprocess

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        RED = BLUE = GREEN = YELLOW = CYAN = WHITE = DIM = RESET = ''
    def clear_screen(): pass
    def display_banner(): pass


# -- Constants ---------------------------------------------------------------

COMMON_DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2',
    'dkim', 'mail', 's1', 's2', 'smtp', 'mandrill', 'everlytickey1',
    'everlytickey2', 'sig1', 'mxvault', 'a1', 'a2', 'cm', 'pm',
    'protonmail', 'protonmail2', 'protonmail3',
]

BLACKLISTS = [
    'zen.spamhaus.org',
    'bl.spamcop.net',
    'b.barracudacentral.org',
    'dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'cbl.abuseat.org',
    'dnsbl-1.uceprotect.net',
    'psbl.surriel.com',
    'all.s5h.net',
    'rbl.interserver.net',
    'dnsbl.dronebl.org',
    'db.wpbl.info',
    'bl.mailspike.net',
    'truncate.gbudb.net',
]

PHISHING_INDICATORS = {
    'urgency_words': {
        'patterns': [
            r'\b(urgent|immediate|action\s+required|act\s+now|expires?\s+today)\b',
            r'\b(suspended|disabled|locked|compromised|unauthorized)\b',
            r'\b(verify\s+your|confirm\s+your|update\s+your|validate)\b',
            r'\b(within\s+24\s+hours|limited\s+time|final\s+notice|last\s+chance)\b',
        ],
        'weight': 15,
    },
    'suspicious_urls': {
        'patterns': [
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IP-based URLs
            r'https?://[^/]*\.(tk|ml|ga|cf|gq|xyz|top|buzz|club|work|click)\b',  # suspicious TLDs
            r'https?://bit\.ly|tinyurl\.com|goo\.gl|t\.co|is\.gd|shorte\.st',     # shorteners
        ],
        'weight': 25,
    },
    'brand_impersonation': {
        'patterns': [
            r'\b(paypal|apple|microsoft|google|amazon|facebook|netflix|bank)\b',
        ],
        'weight': 10,
    },
    'dangerous_attachments': {
        'patterns': [
            r'\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|ps1|msi|dll)\b',
            r'\.(doc|xls|ppt)m\b',  # macro-enabled Office
            r'\.iso\b|\.img\b|\.hta\b',
        ],
        'weight': 30,
    },
    'encoding_tricks': {
        'patterns': [
            r'xn--',           # punycode
            r'&#\d+;',         # HTML entities numeric
            r'&#x[0-9a-f]+;',  # HTML entities hex
            r'=\?[^?]*\?B\?',  # Base64 encoded headers
        ],
        'weight': 20,
    },
}

URL_SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'shorte.st',
    'ow.ly', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'tiny.cc', 'lnkd.in',
    'rb.gy', 'v.gd', 'qr.ae', 'bl.ink',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz',
    '.club', '.work', '.click', '.link', '.info', '.biz', '.stream',
    '.download', '.win', '.racing', '.review', '.country', '.science',
}


# -- Helper ------------------------------------------------------------------

def _dns_query(name: str, record_type: str = 'TXT', timeout: int = 5) -> List[str]:
    """Query DNS records using nslookup subprocess fallback."""
    results = []
    try:
        if record_type == 'TXT':
            # Try socket-based approach first for basic lookups
            try:
                answers = socket.getaddrinfo(name, None)
                # socket.getaddrinfo doesn't return TXT — fall through
            except Exception:
                pass

            # Use nslookup as cross-platform fallback
            cmd = ['nslookup', '-type=' + record_type, name]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = proc.stdout + proc.stderr

            # Parse TXT records from nslookup output
            for line in output.split('\n'):
                line = line.strip()
                if '=' in line and 'text' in line.lower():
                    # Format: text = "v=spf1 ..."
                    txt = line.split('=', 1)[1].strip().strip('"')
                    results.append(txt)
                elif line.startswith('"') and line.endswith('"'):
                    results.append(line.strip('"'))
                elif 'v=spf1' in line or 'v=DMARC1' in line or 'v=DKIM1' in line:
                    # Sometimes the record is on the line itself
                    match = re.search(r'"([^"]+)"', line)
                    if match:
                        results.append(match.group(1))
                    elif 'v=' in line:
                        # Grab from v= onward
                        idx = line.index('v=')
                        results.append(line[idx:].strip().strip('"'))

        elif record_type == 'MX':
            cmd = ['nslookup', '-type=MX', name]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = proc.stdout

            for line in output.split('\n'):
                line = line.strip()
                # "mail exchanger = 10 mx1.example.com."
                mx_match = re.search(r'mail exchanger\s*=\s*(\d+)\s+(\S+)', line, re.I)
                if mx_match:
                    priority = int(mx_match.group(1))
                    host = mx_match.group(2).rstrip('.')
                    results.append(f"{priority} {host}")
                # Also handle "MX preference = 10, mail exchanger = ..."
                mx_match2 = re.search(r'preference\s*=\s*(\d+).*exchanger\s*=\s*(\S+)', line, re.I)
                if mx_match2:
                    priority = int(mx_match2.group(1))
                    host = mx_match2.group(2).rstrip('.')
                    results.append(f"{priority} {host}")

        elif record_type in ('A', 'AAAA'):
            cmd = ['nslookup', '-type=' + record_type, name]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = proc.stdout

            for line in output.split('\n'):
                line = line.strip()
                addr_match = re.search(r'Address:\s*(\S+)', line)
                if addr_match:
                    addr = addr_match.group(1)
                    # Skip the DNS server address (first one, usually has #53)
                    if '#' not in addr and addr != name:
                        results.append(addr)

    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        pass
    except Exception:
        pass

    return results


def _reverse_ip(ip: str) -> str:
    """Reverse an IPv4 address for DNSBL lookup."""
    parts = ip.split('.')
    parts.reverse()
    return '.'.join(parts)


def _is_valid_ip(s: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        socket.inet_aton(s)
        return True
    except (socket.error, OSError):
        return False


def _resolve_domain(domain: str) -> Optional[str]:
    """Resolve a domain to an IPv4 address."""
    try:
        return socket.gethostbyname(domain)
    except (socket.gaierror, socket.herror):
        return None


# -- EmailSecurity class -----------------------------------------------------

class EmailSecurity:
    """Email security analysis engine."""

    _instance = None

    def __init__(self):
        data_dir = get_data_dir()
        if isinstance(data_dir, str):
            data_dir = Path(data_dir)
        self.storage_dir = data_dir / 'email_sec'
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes

    # -- DNS helper ----------------------------------------------------------

    def get_dns_record(self, domain: str, record_type: str = 'TXT') -> List[str]:
        """Query DNS records for a domain."""
        cache_key = f"{record_type}:{domain}"
        cached = self._cache.get(cache_key)
        if cached and time.time() - cached['ts'] < self._cache_ttl:
            return cached['data']

        results = _dns_query(domain, record_type)
        self._cache[cache_key] = {'data': results, 'ts': time.time()}
        return results

    # -- SPF -----------------------------------------------------------------

    def check_spf(self, domain: str) -> Dict[str, Any]:
        """Parse and analyze the SPF record for a domain."""
        records = self.get_dns_record(domain, 'TXT')
        spf_record = None
        for rec in records:
            if rec.strip().startswith('v=spf1'):
                spf_record = rec.strip()
                break

        result = {
            'domain': domain,
            'found': spf_record is not None,
            'record': spf_record or '',
            'mechanisms': [],
            'qualifiers': {},
            'includes': [],
            'all_policy': 'missing',
            'dns_lookups': 0,
            'findings': [],
            'status': 'fail',
        }

        if not spf_record:
            result['findings'].append({'level': 'fail', 'message': 'No SPF record found'})
            return result

        # Parse mechanisms
        parts = spf_record.split()
        lookup_count = 0

        for part in parts[1:]:  # skip v=spf1
            qualifier = '+'
            mechanism = part

            if part[0] in '+-~?':
                qualifier = part[0]
                mechanism = part[1:]

            if mechanism.startswith('ip4:') or mechanism.startswith('ip6:'):
                mtype = 'ip4' if mechanism.startswith('ip4:') else 'ip6'
                value = mechanism.split(':', 1)[1]
                result['mechanisms'].append({'type': mtype, 'value': value, 'qualifier': qualifier})
            elif mechanism.startswith('include:'):
                include_domain = mechanism.split(':', 1)[1]
                result['includes'].append(include_domain)
                result['mechanisms'].append({'type': 'include', 'value': include_domain, 'qualifier': qualifier})
                lookup_count += 1
            elif mechanism.startswith('a:') or mechanism == 'a':
                value = mechanism.split(':', 1)[1] if ':' in mechanism else domain
                result['mechanisms'].append({'type': 'a', 'value': value, 'qualifier': qualifier})
                lookup_count += 1
            elif mechanism.startswith('mx:') or mechanism == 'mx':
                value = mechanism.split(':', 1)[1] if ':' in mechanism else domain
                result['mechanisms'].append({'type': 'mx', 'value': value, 'qualifier': qualifier})
                lookup_count += 1
            elif mechanism.startswith('ptr'):
                result['mechanisms'].append({'type': 'ptr', 'value': mechanism, 'qualifier': qualifier})
                lookup_count += 1
                result['findings'].append({'level': 'warn', 'message': 'PTR mechanism is deprecated (RFC 7208)'})
            elif mechanism.startswith('exists:'):
                value = mechanism.split(':', 1)[1]
                result['mechanisms'].append({'type': 'exists', 'value': value, 'qualifier': qualifier})
                lookup_count += 1
            elif mechanism.startswith('redirect='):
                value = mechanism.split('=', 1)[1]
                result['mechanisms'].append({'type': 'redirect', 'value': value, 'qualifier': qualifier})
                lookup_count += 1
            elif mechanism == 'all':
                result['all_policy'] = qualifier
                qualifier_names = {'+': 'pass', '-': 'hardfail', '~': 'softfail', '?': 'neutral'}
                result['mechanisms'].append({'type': 'all', 'value': 'all', 'qualifier': qualifier})
                result['qualifiers']['all'] = qualifier_names.get(qualifier, qualifier)

        result['dns_lookups'] = lookup_count

        # Analyze findings
        if result['all_policy'] == '-':
            result['findings'].append({'level': 'pass', 'message': 'SPF uses hardfail (-all) — recommended'})
            result['status'] = 'pass'
        elif result['all_policy'] == '~':
            result['findings'].append({'level': 'warn', 'message': 'SPF uses softfail (~all) — hardfail (-all) recommended'})
            result['status'] = 'warn'
        elif result['all_policy'] == '+':
            result['findings'].append({'level': 'fail', 'message': 'SPF allows all senders (+all) — anyone can spoof this domain'})
            result['status'] = 'fail'
        elif result['all_policy'] == '?':
            result['findings'].append({'level': 'warn', 'message': 'SPF uses neutral (?all) — provides no protection'})
            result['status'] = 'warn'
        elif result['all_policy'] == 'missing':
            result['findings'].append({'level': 'fail', 'message': 'No "all" mechanism — implicit +all (no protection)'})
            result['status'] = 'fail'

        if lookup_count > 10:
            result['findings'].append({
                'level': 'fail',
                'message': f'Too many DNS lookups ({lookup_count}) — SPF limit is 10 (RFC 7208)'
            })
        elif lookup_count > 7:
            result['findings'].append({
                'level': 'warn',
                'message': f'{lookup_count} DNS lookups — approaching SPF limit of 10'
            })

        if len(result['includes']) > 5:
            result['findings'].append({
                'level': 'warn',
                'message': f'{len(result["includes"])} include directives — consider consolidating'
            })

        return result

    # -- DMARC ---------------------------------------------------------------

    def check_dmarc(self, domain: str) -> Dict[str, Any]:
        """Parse and analyze the DMARC record for a domain."""
        dmarc_domain = f'_dmarc.{domain}'
        records = self.get_dns_record(dmarc_domain, 'TXT')
        dmarc_record = None
        for rec in records:
            if rec.strip().startswith('v=DMARC1'):
                dmarc_record = rec.strip()
                break

        result = {
            'domain': domain,
            'found': dmarc_record is not None,
            'record': dmarc_record or '',
            'policy': 'none',
            'subdomain_policy': None,
            'pct': 100,
            'rua': [],
            'ruf': [],
            'aspf': 'r',  # relaxed
            'adkim': 'r',  # relaxed
            'fo': '0',
            'findings': [],
            'status': 'fail',
        }

        if not dmarc_record:
            result['findings'].append({'level': 'fail', 'message': 'No DMARC record found'})
            return result

        # Parse tags
        tags = {}
        for part in dmarc_record.split(';'):
            part = part.strip()
            if '=' in part:
                key, val = part.split('=', 1)
                tags[key.strip()] = val.strip()

        result['policy'] = tags.get('p', 'none')
        result['subdomain_policy'] = tags.get('sp')
        result['pct'] = int(tags.get('pct', '100'))
        result['aspf'] = tags.get('aspf', 'r')
        result['adkim'] = tags.get('adkim', 'r')
        result['fo'] = tags.get('fo', '0')

        if 'rua' in tags:
            result['rua'] = [u.strip() for u in tags['rua'].split(',')]
        if 'ruf' in tags:
            result['ruf'] = [u.strip() for u in tags['ruf'].split(',')]

        # Analyze
        policy = result['policy']
        if policy == 'reject':
            result['findings'].append({'level': 'pass', 'message': 'DMARC policy is "reject" — strongest protection'})
            result['status'] = 'pass'
        elif policy == 'quarantine':
            result['findings'].append({'level': 'warn', 'message': 'DMARC policy is "quarantine" — "reject" recommended'})
            result['status'] = 'warn'
        elif policy == 'none':
            result['findings'].append({'level': 'fail', 'message': 'DMARC policy is "none" — no protection (monitoring only)'})
            result['status'] = 'fail'

        if result['pct'] < 100:
            result['findings'].append({
                'level': 'warn',
                'message': f'DMARC pct={result["pct"]}% — only applies to {result["pct"]}% of messages'
            })

        if not result['rua']:
            result['findings'].append({'level': 'warn', 'message': 'No aggregate report URI (rua) — no visibility into failures'})

        if result['subdomain_policy'] and result['subdomain_policy'] != policy:
            result['findings'].append({
                'level': 'warn',
                'message': f'Subdomain policy (sp={result["subdomain_policy"]}) differs from domain policy (p={policy})'
            })

        if result['aspf'] == 'r':
            result['findings'].append({'level': 'warn', 'message': 'SPF alignment is relaxed — strict (aspf=s) recommended'})
        if result['adkim'] == 'r':
            result['findings'].append({'level': 'warn', 'message': 'DKIM alignment is relaxed — strict (adkim=s) recommended'})

        return result

    # -- DKIM ----------------------------------------------------------------

    def check_dkim(self, domain: str, selectors: Optional[List[str]] = None) -> Dict[str, Any]:
        """Try common DKIM selectors to find signing keys."""
        if selectors is None:
            selectors = COMMON_DKIM_SELECTORS

        result = {
            'domain': domain,
            'found_selectors': [],
            'checked_selectors': selectors,
            'findings': [],
            'status': 'fail',
        }

        for selector in selectors:
            dkim_domain = f'{selector}._domainkey.{domain}'
            records = self.get_dns_record(dkim_domain, 'TXT')

            for rec in records:
                if 'v=DKIM1' in rec or 'k=' in rec or 'p=' in rec:
                    key_info = {'selector': selector, 'record': rec}

                    # Parse key fields
                    tags = {}
                    for part in rec.split(';'):
                        part = part.strip()
                        if '=' in part:
                            k, v = part.split('=', 1)
                            tags[k.strip()] = v.strip()

                    key_info['version'] = tags.get('v', '')
                    key_info['key_type'] = tags.get('k', 'rsa')
                    key_info['public_key'] = tags.get('p', '')
                    key_info['flags'] = tags.get('t', '')
                    key_info['hash_algorithms'] = tags.get('h', '')
                    key_info['notes'] = tags.get('n', '')

                    if not tags.get('p'):
                        key_info['revoked'] = True
                        result['findings'].append({
                            'level': 'warn',
                            'message': f'Selector "{selector}" has empty public key — key may be revoked'
                        })
                    else:
                        key_info['revoked'] = False

                    result['found_selectors'].append(key_info)
                    break

        if result['found_selectors']:
            active = [s for s in result['found_selectors'] if not s.get('revoked')]
            if active:
                result['status'] = 'pass'
                result['findings'].insert(0, {
                    'level': 'pass',
                    'message': f'Found {len(active)} active DKIM selector(s): {", ".join(s["selector"] for s in active)}'
                })
            else:
                result['findings'].insert(0, {
                    'level': 'warn',
                    'message': 'DKIM selectors found but all appear revoked'
                })
        else:
            result['findings'].append({
                'level': 'warn',
                'message': f'No DKIM records found for {len(selectors)} common selectors'
            })

        return result

    # -- MX ------------------------------------------------------------------

    def check_mx(self, domain: str) -> Dict[str, Any]:
        """Query MX records and analyze mail servers."""
        mx_records = self.get_dns_record(domain, 'MX')

        result = {
            'domain': domain,
            'mx_records': [],
            'findings': [],
            'status': 'fail',
        }

        if not mx_records:
            result['findings'].append({'level': 'fail', 'message': 'No MX records found'})
            return result

        result['status'] = 'pass'

        for mx_entry in mx_records:
            parts = mx_entry.split(None, 1)
            if len(parts) == 2:
                priority = int(parts[0])
                host = parts[1].rstrip('.')
            else:
                priority = 0
                host = mx_entry.rstrip('.')

            mx_info = {
                'priority': priority,
                'host': host,
                'ip': _resolve_domain(host),
                'starttls': False,
                'starttls_error': None,
            }

            # Check STARTTLS
            tls_result = self.check_starttls(host)
            mx_info['starttls'] = tls_result.get('starttls', False)
            mx_info['starttls_error'] = tls_result.get('error')
            mx_info['banner'] = tls_result.get('banner', '')

            if not mx_info['starttls']:
                result['findings'].append({
                    'level': 'warn',
                    'message': f'MX {host} does not support STARTTLS'
                })

            result['mx_records'].append(mx_info)

        result['mx_records'].sort(key=lambda x: x['priority'])

        if len(result['mx_records']) == 1:
            result['findings'].append({
                'level': 'warn',
                'message': 'Only one MX record — no redundancy for mail delivery'
            })

        all_tls = all(mx['starttls'] for mx in result['mx_records'])
        if all_tls:
            result['findings'].insert(0, {
                'level': 'pass',
                'message': f'All {len(result["mx_records"])} MX servers support STARTTLS'
            })

        return result

    # -- STARTTLS ------------------------------------------------------------

    def check_starttls(self, host: str, port: int = 25) -> Dict[str, Any]:
        """Check if an SMTP server supports STARTTLS."""
        result = {
            'host': host,
            'port': port,
            'starttls': False,
            'banner': '',
            'tls_version': None,
            'cipher': None,
            'error': None,
        }

        try:
            sock = socket.create_connection((host, port), timeout=8)
            banner = sock.recv(1024).decode('utf-8', errors='replace').strip()
            result['banner'] = banner

            # Send EHLO
            sock.sendall(b'EHLO autarch.local\r\n')
            ehlo_resp = sock.recv(4096).decode('utf-8', errors='replace')

            if 'STARTTLS' in ehlo_resp.upper():
                result['starttls'] = True

                # Try upgrading
                sock.sendall(b'STARTTLS\r\n')
                tls_resp = sock.recv(1024).decode('utf-8', errors='replace')

                if tls_resp.startswith('220'):
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        tls_sock = context.wrap_socket(sock, server_hostname=host)
                        result['tls_version'] = tls_sock.version()
                        cipher = tls_sock.cipher()
                        if cipher:
                            result['cipher'] = cipher[0]
                        tls_sock.close()
                        return result
                    except ssl.SSLError as e:
                        result['error'] = f'TLS handshake failed: {e}'

            sock.sendall(b'QUIT\r\n')
            sock.close()
        except socket.timeout:
            result['error'] = 'Connection timed out'
        except ConnectionRefusedError:
            result['error'] = 'Connection refused'
        except Exception as e:
            result['error'] = str(e)

        return result

    # -- Domain Analysis (full) ----------------------------------------------

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Comprehensive email security analysis for a domain."""
        domain = domain.strip().lower()

        spf = self.check_spf(domain)
        dmarc = self.check_dmarc(domain)
        dkim = self.check_dkim(domain)
        mx = self.check_mx(domain)

        # Calculate overall score
        scores = {'pass': 0, 'warn': 0, 'fail': 0}
        for check in [spf, dmarc, dkim, mx]:
            status = check.get('status', 'fail')
            scores[status] = scores.get(status, 0) + 1

        total = sum(scores.values())
        if total > 0:
            score = int(((scores['pass'] * 100) + (scores['warn'] * 50)) / total)
        else:
            score = 0

        # Grade
        if score >= 90:
            grade = 'A'
        elif score >= 75:
            grade = 'B'
        elif score >= 60:
            grade = 'C'
        elif score >= 40:
            grade = 'D'
        else:
            grade = 'F'

        result = {
            'domain': domain,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'spf': spf,
            'dmarc': dmarc,
            'dkim': dkim,
            'mx': mx,
            'score': score,
            'grade': grade,
            'summary': {
                'spf_status': spf['status'],
                'dmarc_status': dmarc['status'],
                'dkim_status': dkim['status'],
                'mx_status': mx['status'],
            }
        }

        # Save analysis
        self._save_analysis(domain, result)
        return result

    # -- Header Analysis -----------------------------------------------------

    def analyze_headers(self, raw_headers: str) -> Dict[str, Any]:
        """Parse and analyze email headers for security issues."""
        result = {
            'received_chain': [],
            'authentication': {
                'spf': 'none',
                'dkim': 'none',
                'dmarc': 'none',
            },
            'from': '',
            'return_path': '',
            'reply_to': '',
            'message_id': '',
            'date': '',
            'subject': '',
            'originating_ip': None,
            'spoofing_indicators': [],
            'findings': [],
        }

        # Parse with email module
        msg = email.message_from_string(raw_headers)

        # Extract basic headers
        result['from'] = str(msg.get('From', ''))
        result['return_path'] = str(msg.get('Return-Path', ''))
        result['reply_to'] = str(msg.get('Reply-To', ''))
        result['message_id'] = str(msg.get('Message-ID', ''))
        result['date'] = str(msg.get('Date', ''))
        result['subject'] = str(msg.get('Subject', ''))

        # Decode encoded headers
        for field in ['from', 'subject', 'reply_to']:
            val = result[field]
            if val and '=?' in val:
                decoded_parts = email.header.decode_header(val)
                decoded = ''
                for part, charset in decoded_parts:
                    if isinstance(part, bytes):
                        decoded += part.decode(charset or 'utf-8', errors='replace')
                    else:
                        decoded += str(part)
                result[field] = decoded

        # Parse Received chain
        received_headers = msg.get_all('Received', [])
        for i, recv in enumerate(received_headers):
            hop = {'raw': recv, 'hop': i + 1}

            # Extract from/by
            from_match = re.search(r'from\s+(\S+)', recv, re.I)
            by_match = re.search(r'by\s+(\S+)', recv, re.I)
            if from_match:
                hop['from'] = from_match.group(1)
            if by_match:
                hop['by'] = by_match.group(1)

            # Extract IP
            ip_match = re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', recv)
            if ip_match:
                hop['ip'] = ip_match.group(1)

            # Extract timestamp
            ts_match = re.search(r';\s*(.+?)$', recv)
            if ts_match:
                hop['timestamp'] = ts_match.group(1).strip()

            result['received_chain'].append(hop)

        # Originating IP (last Received header — outermost hop)
        if result['received_chain']:
            for hop in reversed(result['received_chain']):
                if hop.get('ip') and not hop['ip'].startswith(('10.', '192.168.', '172.')):
                    result['originating_ip'] = hop['ip']
                    break

        # Parse Authentication-Results
        auth_results = msg.get_all('Authentication-Results', [])
        for ar in auth_results:
            ar_lower = ar.lower()
            if 'spf=' in ar_lower:
                spf_match = re.search(r'spf=(\w+)', ar_lower)
                if spf_match:
                    result['authentication']['spf'] = spf_match.group(1)
            if 'dkim=' in ar_lower:
                dkim_match = re.search(r'dkim=(\w+)', ar_lower)
                if dkim_match:
                    result['authentication']['dkim'] = dkim_match.group(1)
            if 'dmarc=' in ar_lower:
                dmarc_match = re.search(r'dmarc=(\w+)', ar_lower)
                if dmarc_match:
                    result['authentication']['dmarc'] = dmarc_match.group(1)

        # Spoofing indicators
        from_addr = result['from']
        return_path = result['return_path']
        reply_to = result['reply_to']

        # Extract domain from From header
        from_domain_match = re.search(r'@([\w.-]+)', from_addr)
        from_domain = from_domain_match.group(1) if from_domain_match else ''

        rp_domain_match = re.search(r'@([\w.-]+)', return_path)
        rp_domain = rp_domain_match.group(1) if rp_domain_match else ''

        if from_domain and rp_domain and from_domain.lower() != rp_domain.lower():
            result['spoofing_indicators'].append({
                'level': 'warn',
                'indicator': 'From/Return-Path mismatch',
                'detail': f'From domain: {from_domain}, Return-Path domain: {rp_domain}'
            })

        if reply_to:
            rt_domain_match = re.search(r'@([\w.-]+)', reply_to)
            rt_domain = rt_domain_match.group(1) if rt_domain_match else ''
            if from_domain and rt_domain and from_domain.lower() != rt_domain.lower():
                result['spoofing_indicators'].append({
                    'level': 'warn',
                    'indicator': 'From/Reply-To mismatch',
                    'detail': f'From domain: {from_domain}, Reply-To domain: {rt_domain}'
                })

        # Check authentication failures
        for auth_type, auth_result in result['authentication'].items():
            if auth_result == 'fail':
                result['findings'].append({
                    'level': 'fail',
                    'message': f'{auth_type.upper()} authentication failed'
                })
            elif auth_result == 'pass':
                result['findings'].append({
                    'level': 'pass',
                    'message': f'{auth_type.upper()} authentication passed'
                })
            elif auth_result == 'none':
                result['findings'].append({
                    'level': 'warn',
                    'message': f'No {auth_type.upper()} authentication result'
                })

        # Check for suspicious Received hops
        if len(result['received_chain']) > 8:
            result['findings'].append({
                'level': 'warn',
                'message': f'Unusually long Received chain ({len(result["received_chain"])} hops)'
            })

        return result

    # -- Phishing Detection --------------------------------------------------

    def detect_phishing(self, email_content: str) -> Dict[str, Any]:
        """Analyze email content for phishing indicators."""
        result = {
            'risk_score': 0,
            'risk_level': 'low',
            'findings': [],
            'urls_found': [],
            'suspicious_urls': [],
            'attachment_refs': [],
        }

        content_lower = email_content.lower()
        total_weight = 0

        # Check each indicator category
        for category, info in PHISHING_INDICATORS.items():
            category_hits = []
            for pattern in info['patterns']:
                matches = re.findall(pattern, content_lower, re.I)
                if matches:
                    category_hits.extend(matches)

            if category_hits:
                total_weight += info['weight']
                result['findings'].append({
                    'category': category,
                    'severity': 'high' if info['weight'] >= 25 else 'medium' if info['weight'] >= 15 else 'low',
                    'matches': list(set(str(m) if isinstance(m, str) else str(m) for m in category_hits[:10])),
                    'weight': info['weight'],
                })

        # Extract and analyze URLs
        urls = re.findall(r'https?://[^\s<>"\')\]]+', email_content, re.I)
        result['urls_found'] = list(set(urls))

        for url in result['urls_found']:
            suspicious_reasons = []
            parsed = urlparse(url)
            hostname = parsed.hostname or ''

            # IP-based URL
            if _is_valid_ip(hostname):
                suspicious_reasons.append('IP-based URL')

            # URL shortener
            if hostname.lower() in URL_SHORTENER_DOMAINS:
                suspicious_reasons.append('URL shortener')

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    suspicious_reasons.append(f'Suspicious TLD ({tld})')
                    break

            # Long subdomain (possible typosquatting)
            parts = hostname.split('.')
            if len(parts) > 4:
                suspicious_reasons.append('Excessive subdomains')

            # @-symbol in URL (credential harvesting trick)
            if '@' in url:
                suspicious_reasons.append('Contains @ symbol (possible credential trick)')

            # Homograph / punycode
            if hostname.startswith('xn--'):
                suspicious_reasons.append('Punycode/IDN domain')

            if suspicious_reasons:
                result['suspicious_urls'].append({
                    'url': url,
                    'reasons': suspicious_reasons,
                })
                total_weight += 10

        # Check for attachment references
        attachment_exts = re.findall(
            r'[\w.-]+\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|wsh|ps1|msi|dll|docm|xlsm|pptm|iso|img|hta|lnk|zip|rar|7z)',
            content_lower
        )
        if attachment_exts:
            result['attachment_refs'] = list(set(attachment_exts))
            total_weight += 15

        # Calculate risk score (0-100)
        result['risk_score'] = min(100, total_weight)
        if result['risk_score'] >= 70:
            result['risk_level'] = 'critical'
        elif result['risk_score'] >= 50:
            result['risk_level'] = 'high'
        elif result['risk_score'] >= 30:
            result['risk_level'] = 'medium'
        else:
            result['risk_level'] = 'low'

        return result

    # -- Mailbox Search ------------------------------------------------------

    def search_mailbox(self, host: str, username: str, password: str,
                       protocol: str = 'imap', search_query: Optional[str] = None,
                       folder: str = 'INBOX', use_ssl: bool = True) -> Dict[str, Any]:
        """Connect to a mailbox and search for emails."""
        result = {
            'host': host,
            'protocol': protocol,
            'folder': folder,
            'messages': [],
            'total': 0,
            'error': None,
        }

        try:
            if protocol.lower() == 'imap':
                result = self._search_imap(host, username, password, search_query, folder, use_ssl)
            elif protocol.lower() == 'pop3':
                result = self._search_pop3(host, username, password, search_query, use_ssl)
            else:
                result['error'] = f'Unsupported protocol: {protocol}'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _search_imap(self, host: str, username: str, password: str,
                     search_query: Optional[str], folder: str, use_ssl: bool) -> Dict:
        """Search via IMAP."""
        result = {'host': host, 'protocol': 'imap', 'folder': folder, 'messages': [], 'total': 0, 'error': None}

        try:
            if use_ssl:
                conn = imaplib.IMAP4_SSL(host, timeout=15)
            else:
                conn = imaplib.IMAP4(host, timeout=15)

            conn.login(username, password)
            conn.select(folder, readonly=True)

            # Build search criteria
            if search_query:
                # Support simple search syntax
                criteria = search_query.upper()
                if not criteria.startswith('('):
                    # Wrap simple queries
                    if '@' in search_query:
                        criteria = f'(FROM "{search_query}")'
                    elif re.match(r'\d{1,2}-\w{3}-\d{4}', search_query):
                        criteria = f'(SINCE "{search_query}")'
                    else:
                        criteria = f'(SUBJECT "{search_query}")'
            else:
                criteria = 'ALL'

            status, data = conn.search(None, criteria)
            if status != 'OK':
                result['error'] = 'Search failed'
                conn.logout()
                return result

            msg_ids = data[0].split()
            result['total'] = len(msg_ids)

            # Fetch last 50 message summaries
            for msg_id in msg_ids[-50:]:
                status, msg_data = conn.fetch(msg_id, '(RFC822.SIZE BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)])')
                if status == 'OK' and msg_data[0]:
                    header_data = msg_data[0][1] if isinstance(msg_data[0], tuple) else msg_data[0]
                    if isinstance(header_data, bytes):
                        header_data = header_data.decode('utf-8', errors='replace')

                    msg = email.message_from_string(header_data)
                    size = 0
                    # Try to get size from FETCH response
                    if isinstance(msg_data[0], tuple):
                        size_match = re.search(r'RFC822\.SIZE\s+(\d+)', str(msg_data[0][0]))
                        if size_match:
                            size = int(size_match.group(1))

                    summary = {
                        'id': msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id),
                        'from': str(msg.get('From', '')),
                        'subject': str(msg.get('Subject', '')),
                        'date': str(msg.get('Date', '')),
                        'message_id': str(msg.get('Message-ID', '')),
                        'size': size,
                    }

                    # Decode encoded headers
                    for field in ['from', 'subject']:
                        if summary[field] and '=?' in summary[field]:
                            try:
                                decoded_parts = email.header.decode_header(summary[field])
                                decoded = ''
                                for part, charset in decoded_parts:
                                    if isinstance(part, bytes):
                                        decoded += part.decode(charset or 'utf-8', errors='replace')
                                    else:
                                        decoded += str(part)
                                summary[field] = decoded
                            except Exception:
                                pass

                    result['messages'].append(summary)

            conn.logout()
        except imaplib.IMAP4.error as e:
            result['error'] = f'IMAP error: {e}'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _search_pop3(self, host: str, username: str, password: str,
                     search_query: Optional[str], use_ssl: bool) -> Dict:
        """Search via POP3 (limited — retrieves headers of recent messages)."""
        result = {'host': host, 'protocol': 'pop3', 'folder': 'INBOX', 'messages': [], 'total': 0, 'error': None}

        try:
            if use_ssl:
                conn = poplib.POP3_SSL(host, timeout=15)
            else:
                conn = poplib.POP3(host, timeout=15)

            conn.user(username)
            conn.pass_(password)

            count, size = conn.stat()
            result['total'] = count

            # Fetch last 50 messages' headers
            start = max(1, count - 49)
            query_lower = search_query.lower() if search_query else None

            for i in range(start, count + 1):
                resp, lines, octets = conn.top(i, 0)
                header_text = b'\r\n'.join(lines).decode('utf-8', errors='replace')
                msg = email.message_from_string(header_text)

                summary = {
                    'id': str(i),
                    'from': str(msg.get('From', '')),
                    'subject': str(msg.get('Subject', '')),
                    'date': str(msg.get('Date', '')),
                    'message_id': str(msg.get('Message-ID', '')),
                    'size': octets,
                }

                # Apply client-side filter
                if query_lower:
                    match = (query_lower in summary['from'].lower() or
                             query_lower in summary['subject'].lower())
                    if not match:
                        continue

                result['messages'].append(summary)

            conn.quit()
        except Exception as e:
            result['error'] = str(e)

        return result

    # -- Fetch Full Email ----------------------------------------------------

    def fetch_email(self, host: str, username: str, password: str,
                    message_id: str, protocol: str = 'imap',
                    use_ssl: bool = True) -> Dict[str, Any]:
        """Fetch a complete email by message ID."""
        result = {'message_id': message_id, 'raw_headers': '', 'body': '', 'attachments': [], 'error': None}

        try:
            if protocol.lower() == 'imap':
                if use_ssl:
                    conn = imaplib.IMAP4_SSL(host, timeout=15)
                else:
                    conn = imaplib.IMAP4(host, timeout=15)

                conn.login(username, password)
                conn.select('INBOX', readonly=True)

                status, data = conn.fetch(message_id.encode() if isinstance(message_id, str) else message_id,
                                          '(RFC822)')
                if status == 'OK' and data[0]:
                    raw = data[0][1] if isinstance(data[0], tuple) else data[0]
                    if isinstance(raw, bytes):
                        raw = raw.decode('utf-8', errors='replace')

                    msg = email.message_from_string(raw)

                    # Headers
                    header_keys = ['From', 'To', 'Cc', 'Subject', 'Date', 'Message-ID',
                                   'Return-Path', 'Reply-To', 'Received',
                                   'Authentication-Results', 'DKIM-Signature',
                                   'X-Mailer', 'X-Originating-IP']
                    headers_text = ''
                    for key in header_keys:
                        vals = msg.get_all(key, [])
                        for v in vals:
                            headers_text += f'{key}: {v}\n'
                    result['raw_headers'] = headers_text

                    # Body
                    if msg.is_multipart():
                        for part in msg.walk():
                            ct = part.get_content_type()
                            cd = str(part.get('Content-Disposition', ''))

                            if 'attachment' in cd:
                                result['attachments'].append({
                                    'filename': part.get_filename() or 'unknown',
                                    'content_type': ct,
                                    'size': len(part.get_payload(decode=True) or b''),
                                })
                            elif ct == 'text/plain':
                                payload = part.get_payload(decode=True)
                                if payload:
                                    result['body'] = payload.decode('utf-8', errors='replace')
                            elif ct == 'text/html' and not result['body']:
                                payload = part.get_payload(decode=True)
                                if payload:
                                    result['body'] = payload.decode('utf-8', errors='replace')
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            result['body'] = payload.decode('utf-8', errors='replace')

                conn.logout()

            elif protocol.lower() == 'pop3':
                if use_ssl:
                    conn = poplib.POP3_SSL(host, timeout=15)
                else:
                    conn = poplib.POP3(host, timeout=15)

                conn.user(username)
                conn.pass_(password)

                resp, lines, octets = conn.retr(int(message_id))
                raw = b'\r\n'.join(lines).decode('utf-8', errors='replace')
                msg = email.message_from_string(raw)

                result['raw_headers'] = '\n'.join(
                    f'{k}: {v}' for k, v in msg.items()
                )

                if msg.is_multipart():
                    for part in msg.walk():
                        ct = part.get_content_type()
                        if ct == 'text/plain':
                            payload = part.get_payload(decode=True)
                            if payload:
                                result['body'] = payload.decode('utf-8', errors='replace')
                                break
                else:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        result['body'] = payload.decode('utf-8', errors='replace')

                conn.quit()

        except Exception as e:
            result['error'] = str(e)

        return result

    # -- Abuse Report --------------------------------------------------------

    def generate_abuse_report(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a formatted abuse report for ISP/hosting provider."""
        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        incident_type = incident_data.get('type', 'spam/phishing')
        source_ip = incident_data.get('source_ip', 'Unknown')
        source_domain = incident_data.get('source_domain', 'Unknown')
        description = incident_data.get('description', '')
        evidence_headers = incident_data.get('headers', '')
        evidence_urls = incident_data.get('urls', [])
        reporter_name = incident_data.get('reporter_name', 'AUTARCH Security Platform')
        reporter_email = incident_data.get('reporter_email', '')

        report_lines = [
            '=' * 72,
            'ABUSE REPORT',
            '=' * 72,
            '',
            f'Date:            {now}',
            f'Report Type:     {incident_type}',
            f'Reporter:        {reporter_name}',
        ]
        if reporter_email:
            report_lines.append(f'Reporter Email:  {reporter_email}')

        report_lines += [
            '',
            '-' * 72,
            'INCIDENT DETAILS',
            '-' * 72,
            '',
            f'Source IP:        {source_ip}',
            f'Source Domain:    {source_domain}',
            f'Incident Type:   {incident_type}',
            '',
            'Description:',
            description or '(No description provided)',
            '',
        ]

        if evidence_headers:
            report_lines += [
                '-' * 72,
                'EVIDENCE — EMAIL HEADERS',
                '-' * 72,
                '',
                evidence_headers,
                '',
            ]

        if evidence_urls:
            report_lines += [
                '-' * 72,
                'EVIDENCE — MALICIOUS URLs',
                '-' * 72,
                '',
            ]
            for url in evidence_urls:
                report_lines.append(f'  - {url}')
            report_lines.append('')

        report_lines += [
            '-' * 72,
            'REQUESTED ACTION',
            '-' * 72,
            '',
            'We request that you:',
            '  1. Investigate the reported IP address/domain for abusive activity',
            '  2. Take appropriate action (suspension, warning, content removal)',
            '  3. Implement measures to prevent recurring abuse',
            '  4. Respond with your findings and actions taken',
            '',
            '-' * 72,
            'ADDITIONAL INFORMATION',
            '-' * 72,
            '',
            'This report was generated by AUTARCH Security Platform.',
            'The evidence presented is accurate and collected through legitimate',
            'security analysis. We are available for further investigation if needed.',
            '',
            '=' * 72,
        ]

        report_text = '\n'.join(report_lines)

        # Save the report
        report_id = hashlib.md5(f'{now}:{source_ip}:{incident_type}'.encode()).hexdigest()[:12]
        report_path = self.storage_dir / f'abuse_report_{report_id}.txt'
        with open(report_path, 'w') as f:
            f.write(report_text)

        return {
            'report_id': report_id,
            'report_text': report_text,
            'saved_to': str(report_path),
        }

    # -- Blacklist Check -----------------------------------------------------

    def check_blacklists(self, ip_or_domain: str) -> Dict[str, Any]:
        """Check if an IP or domain is on common email blacklists."""
        ip_or_domain = ip_or_domain.strip()

        # Resolve domain to IP if needed
        if _is_valid_ip(ip_or_domain):
            ip = ip_or_domain
        else:
            ip = _resolve_domain(ip_or_domain)
            if not ip:
                return {
                    'query': ip_or_domain,
                    'error': f'Could not resolve {ip_or_domain} to an IP address',
                    'results': [],
                    'listed_count': 0,
                }

        reversed_ip = _reverse_ip(ip)
        results = []
        listed_count = 0

        for bl in BLACKLISTS:
            lookup = f'{reversed_ip}.{bl}'
            entry = {'blacklist': bl, 'listed': False, 'details': ''}

            try:
                socket.setdefaulttimeout(3)
                addr = socket.gethostbyname(lookup)
                entry['listed'] = True
                entry['details'] = f'Listed (response: {addr})'
                listed_count += 1

                # Try to get TXT reason
                try:
                    txt_records = _dns_query(lookup, 'TXT')
                    if txt_records:
                        entry['details'] = txt_records[0]
                except Exception:
                    pass

            except (socket.gaierror, socket.herror):
                entry['details'] = 'Not listed'
            except socket.timeout:
                entry['details'] = 'Timeout'
            except Exception as e:
                entry['details'] = f'Error: {e}'

            results.append(entry)

        return {
            'query': ip_or_domain,
            'ip': ip,
            'results': results,
            'listed_count': listed_count,
            'total_checked': len(BLACKLISTS),
            'clean': listed_count == 0,
        }

    # -- Storage Helpers -----------------------------------------------------

    def _save_analysis(self, domain: str, data: Dict):
        """Save domain analysis to storage."""
        safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
        path = self.storage_dir / f'analysis_{safe_name}.json'
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def get_saved_analyses(self) -> List[Dict]:
        """List saved domain analyses."""
        analyses = []
        for f in sorted(self.storage_dir.glob('analysis_*.json'), key=os.path.getmtime, reverse=True):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                    analyses.append({
                        'domain': data.get('domain', ''),
                        'grade': data.get('grade', '?'),
                        'score': data.get('score', 0),
                        'timestamp': data.get('timestamp', ''),
                        'file': str(f),
                    })
            except Exception:
                pass
        return analyses


# -- Singleton ---------------------------------------------------------------

_instance = None


def get_email_sec() -> EmailSecurity:
    global _instance
    if _instance is None:
        _instance = EmailSecurity()
    return _instance


# -- CLI Interface -----------------------------------------------------------

def run():
    """CLI entry point for Email Security module."""
    es = get_email_sec()

    while True:
        print(f"\n{'='*60}")
        print(f"  Email Security")
        print(f"{'='*60}")
        print()
        print("  1 -- Analyze Domain")
        print("  2 -- Analyze Headers")
        print("  3 -- Detect Phishing")
        print("  4 -- Search Mailbox")
        print("  5 -- Check Blacklists")
        print("  6 -- Generate Abuse Report")
        print("  0 -- Back")
        print()

        choice = input(f"  {Colors.CYAN}>{Colors.RESET} ").strip()

        if choice == '0':
            break

        elif choice == '1':
            domain = input("\n  Domain: ").strip()
            if not domain:
                continue
            print(f"\n  Analyzing {domain}...")
            result = es.analyze_domain(domain)
            print(f"\n  Grade: {result['grade']} (Score: {result['score']}/100)")
            print(f"  SPF:   {result['summary']['spf_status']}")
            print(f"  DMARC: {result['summary']['dmarc_status']}")
            print(f"  DKIM:  {result['summary']['dkim_status']}")
            print(f"  MX:    {result['summary']['mx_status']}")

            for check_name in ['spf', 'dmarc', 'dkim', 'mx']:
                check = result[check_name]
                findings = check.get('findings', [])
                if findings:
                    print(f"\n  {check_name.upper()} findings:")
                    for f in findings:
                        level = f.get('level', 'info')
                        sym = '+' if level == 'pass' else '!' if level == 'warn' else 'X'
                        print(f"    [{sym}] {f['message']}")

        elif choice == '2':
            print("\n  Paste raw email headers (end with empty line):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            raw = '\n'.join(lines)
            if not raw:
                continue

            result = es.analyze_headers(raw)
            print(f"\n  From:        {result['from']}")
            print(f"  Subject:     {result['subject']}")
            print(f"  Date:        {result['date']}")
            print(f"  Origin IP:   {result.get('originating_ip', 'Unknown')}")
            print(f"  SPF:         {result['authentication']['spf']}")
            print(f"  DKIM:        {result['authentication']['dkim']}")
            print(f"  DMARC:       {result['authentication']['dmarc']}")

            if result['received_chain']:
                print(f"\n  Received chain ({len(result['received_chain'])} hops):")
                for hop in result['received_chain']:
                    print(f"    Hop {hop['hop']}: {hop.get('from', '?')} -> {hop.get('by', '?')}"
                          f"  [{hop.get('ip', '?')}]")

            if result['spoofing_indicators']:
                print(f"\n  Spoofing indicators:")
                for s in result['spoofing_indicators']:
                    print(f"    [!] {s['indicator']}: {s['detail']}")

        elif choice == '3':
            print("\n  Paste email content (end with empty line):")
            lines = []
            while True:
                line = input()
                if not line:
                    break
                lines.append(line)
            content = '\n'.join(lines)
            if not content:
                continue

            result = es.detect_phishing(content)
            print(f"\n  Risk Score: {result['risk_score']}/100 ({result['risk_level']})")

            if result['findings']:
                print(f"\n  Findings:")
                for f in result['findings']:
                    print(f"    [{f['severity']}] {f['category']}: {', '.join(f['matches'][:5])}")

            if result['suspicious_urls']:
                print(f"\n  Suspicious URLs:")
                for u in result['suspicious_urls']:
                    print(f"    {u['url']}")
                    for r in u['reasons']:
                        print(f"      - {r}")

        elif choice == '4':
            host = input("\n  Mail server: ").strip()
            username = input("  Username: ").strip()
            password = input("  Password: ").strip()
            protocol = input("  Protocol (imap/pop3) [imap]: ").strip() or 'imap'
            query = input("  Search query (optional): ").strip() or None

            if not host or not username or not password:
                print("  Missing required fields")
                continue

            print(f"\n  Connecting to {host}...")
            result = es.search_mailbox(host, username, password, protocol, query)

            if result.get('error'):
                print(f"  Error: {result['error']}")
            else:
                print(f"  Found {result['total']} messages")
                for msg in result.get('messages', [])[-20:]:
                    print(f"    [{msg['id']}] {msg['date'][:16]}  {msg['from'][:30]}  {msg['subject'][:40]}")

        elif choice == '5':
            target = input("\n  IP or domain: ").strip()
            if not target:
                continue
            print(f"\n  Checking {len(BLACKLISTS)} blacklists...")
            result = es.check_blacklists(target)

            if result.get('error'):
                print(f"  Error: {result['error']}")
            else:
                print(f"  IP: {result.get('ip', target)}")
                print(f"  Listed on {result['listed_count']}/{result['total_checked']} blacklists")
                for bl in result['results']:
                    status = 'LISTED' if bl['listed'] else 'clean'
                    sym = 'X' if bl['listed'] else '+'
                    print(f"    [{sym}] {bl['blacklist']}: {status}")

        elif choice == '6':
            print("\n  Abuse Report Generator")
            incident_type = input("  Incident type (spam/phishing/malware): ").strip() or 'spam'
            source_ip = input("  Source IP: ").strip()
            source_domain = input("  Source domain: ").strip()
            description = input("  Description: ").strip()

            data = {
                'type': incident_type,
                'source_ip': source_ip,
                'source_domain': source_domain,
                'description': description,
            }

            result = es.generate_abuse_report(data)
            print(f"\n{result['report_text']}")
            print(f"\n  Report saved to: {result['saved_to']}")
