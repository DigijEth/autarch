"""AUTARCH SMS/MMS Backup Forge

Create and modify SMS/MMS backup XML files in the format used by
"SMS Backup & Restore" (SyncTech) -- the most popular Android SMS backup app.
Supports full conversation generation, template-based message creation,
bulk import/export, and timestamp manipulation.
"""

DESCRIPTION = "SMS/MMS Backup Forge — Create & Modify Backup Conversations"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"


def run():
    """CLI entry point — this module is used via the web UI."""
    print("SMS Forge is managed through the AUTARCH web interface.")
    print("Navigate to Offense → SMS Forge in the dashboard.")

import os
import csv
import json
import uuid
import time
import base64
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from xml.etree import ElementTree as ET

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return Path(__file__).resolve().parent.parent / 'data'


# ── Module-level singleton ──────────────────────────────────────────────────

_instance: Optional['SMSForge'] = None


def get_sms_forge() -> 'SMSForge':
    """Return the module singleton, creating it on first call."""
    global _instance
    if _instance is None:
        _instance = SMSForge()
    return _instance


# ── Built-in Conversation Templates ────────────────────────────────────────

BUILTIN_TEMPLATES = {
    "business_meeting": {
        "name": "Business Meeting",
        "description": "Scheduling a meeting, confirming time and place",
        "messages": [
            {"body": "Hi {contact}, are you available for a meeting on {date}?", "type": 2, "delay_minutes": 0},
            {"body": "Let me check my schedule. What time works for you?", "type": 1, "delay_minutes": 12},
            {"body": "How about {time} at {location}?", "type": 2, "delay_minutes": 5},
            {"body": "That works for me. I'll bring the {topic} documents.", "type": 1, "delay_minutes": 8},
            {"body": "Perfect. See you then!", "type": 2, "delay_minutes": 3},
            {"body": "See you there. Thanks for setting this up.", "type": 1, "delay_minutes": 2},
        ],
        "variables": ["contact", "date", "time", "location", "topic"],
    },
    "casual_chat": {
        "name": "Casual Chat",
        "description": "General friendly conversation between friends",
        "messages": [
            {"body": "Hey {contact}! How's it going?", "type": 2, "delay_minutes": 0},
            {"body": "Hey! Pretty good, just got back from {activity}. You?", "type": 1, "delay_minutes": 15},
            {"body": "Nice! I've been {my_activity}. We should hang out soon.", "type": 2, "delay_minutes": 7},
            {"body": "Definitely! How about {day}?", "type": 1, "delay_minutes": 4},
            {"body": "Sounds great, let's do it. I'll text you the details later.", "type": 2, "delay_minutes": 3},
            {"body": "Cool, talk to you later!", "type": 1, "delay_minutes": 1},
        ],
        "variables": ["contact", "activity", "my_activity", "day"],
    },
    "delivery_notification": {
        "name": "Delivery Notification",
        "description": "Package tracking updates from a delivery service",
        "messages": [
            {"body": "Your order #{order_id} has been shipped! Track at: {tracking_url}", "type": 1, "delay_minutes": 0},
            {"body": "Update: Your package is out for delivery today. Estimated arrival: {eta}.", "type": 1, "delay_minutes": 1440},
            {"body": "Your package has been delivered! Left at: {location}.", "type": 1, "delay_minutes": 360},
        ],
        "variables": ["order_id", "tracking_url", "eta", "location"],
    },
    "verification_codes": {
        "name": "Verification Codes",
        "description": "OTP/2FA codes from various services",
        "messages": [
            {"body": "Your {service} verification code is: {code}. Do not share this code.", "type": 1, "delay_minutes": 0},
            {"body": "{service2} security code: {code2}. This code expires in 10 minutes.", "type": 1, "delay_minutes": 120},
            {"body": "Your {service3} login code is {code3}. If you didn't request this, ignore this message.", "type": 1, "delay_minutes": 240},
        ],
        "variables": ["service", "code", "service2", "code2", "service3", "code3"],
    },
    "bank_alerts": {
        "name": "Bank Alerts",
        "description": "Bank transaction notifications and alerts",
        "messages": [
            {"body": "{bank}: Purchase of ${amount} at {merchant} on card ending {card_last4}. Balance: ${balance}.", "type": 1, "delay_minutes": 0},
            {"body": "{bank}: Direct deposit of ${deposit_amount} received. New balance: ${new_balance}.", "type": 1, "delay_minutes": 4320},
            {"body": "{bank} Alert: Unusual activity detected on your account. If this was not you, call {phone}.", "type": 1, "delay_minutes": 2880},
            {"body": "{bank}: Your scheduled payment of ${payment_amount} to {payee} has been processed.", "type": 1, "delay_minutes": 1440},
        ],
        "variables": ["bank", "amount", "merchant", "card_last4", "balance",
                       "deposit_amount", "new_balance", "phone",
                       "payment_amount", "payee"],
    },
    "custom": {
        "name": "Custom",
        "description": "Empty template for user-defined conversations",
        "messages": [],
        "variables": [],
    },
}


# ── SMS Forge Class ─────────────────────────────────────────────────────────

class SMSForge:
    """Create, modify, and export SMS/MMS backup XML files."""

    def __init__(self):
        self._data_dir = Path(get_data_dir()) / 'sms_forge'
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._messages: List[Dict[str, Any]] = []
        self._backup_set: str = self._generate_uuid()
        self._backup_date: int = int(time.time() * 1000)
        self._backup_type: str = "full"
        self._custom_templates: Dict[str, dict] = {}
        self._load_custom_templates()

    # ── Backup Management ───────────────────────────────────────────────────

    def create_backup(self, messages: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
        """Create a new SMS Backup & Restore XML file from a list of message dicts.

        Each message dict should have at minimum:
            address, body, type (for SMS) or msg_box (for MMS)
        Optional: timestamp, contact_name, read, locked, attachments
        """
        self._messages = []
        for msg in messages:
            if msg.get('is_mms') or msg.get('attachments'):
                self.add_mms(
                    address=msg.get('address', ''),
                    body=msg.get('body', ''),
                    attachments=msg.get('attachments', []),
                    msg_box=msg.get('msg_box', msg.get('type', 1)),
                    timestamp=msg.get('timestamp') or msg.get('date'),
                    contact_name=msg.get('contact_name', '(Unknown)'),
                )
            else:
                self.add_sms(
                    address=msg.get('address', ''),
                    body=msg.get('body', ''),
                    msg_type=msg.get('type', 1),
                    timestamp=msg.get('timestamp') or msg.get('date'),
                    contact_name=msg.get('contact_name', '(Unknown)'),
                    read=msg.get('read', 1),
                    locked=msg.get('locked', 0),
                )
        return self.save_backup(output_path)

    def load_backup(self, xml_path: str) -> Dict[str, Any]:
        """Parse existing backup XML into internal format."""
        path = Path(xml_path)
        if not path.exists():
            return {'ok': False, 'error': f'File not found: {xml_path}'}
        try:
            tree = ET.parse(str(path))
            root = tree.getroot()
            if root.tag != 'smses':
                return {'ok': False, 'error': 'Invalid XML: root element must be <smses>'}

            self._backup_set = root.get('backup_set', self._generate_uuid())
            self._backup_date = int(root.get('backup_date', str(int(time.time() * 1000))))
            self._backup_type = root.get('type', 'full')
            self._messages = []

            for elem in root:
                if elem.tag == 'sms':
                    msg = {
                        'msg_kind': 'sms',
                        'protocol': elem.get('protocol', '0'),
                        'address': elem.get('address', ''),
                        'date': int(elem.get('date', '0')),
                        'type': int(elem.get('type', '1')),
                        'subject': elem.get('subject', 'null'),
                        'body': elem.get('body', ''),
                        'toa': elem.get('toa', 'null'),
                        'sc_toa': elem.get('sc_toa', 'null'),
                        'service_center': elem.get('service_center', 'null'),
                        'read': int(elem.get('read', '1')),
                        'status': int(elem.get('status', '-1')),
                        'locked': int(elem.get('locked', '0')),
                        'sub_id': elem.get('sub_id', '-1'),
                        'readable_date': elem.get('readable_date', ''),
                        'contact_name': elem.get('contact_name', '(Unknown)'),
                    }
                    self._messages.append(msg)
                elif elem.tag == 'mms':
                    msg = self._parse_mms_element(elem)
                    self._messages.append(msg)

            return {
                'ok': True,
                'count': len(self._messages),
                'backup_set': self._backup_set,
                'backup_date': self._backup_date,
            }
        except ET.ParseError as e:
            return {'ok': False, 'error': f'XML parse error: {e}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def _parse_mms_element(self, elem: ET.Element) -> Dict[str, Any]:
        """Parse a single <mms> element into a dict."""
        msg: Dict[str, Any] = {
            'msg_kind': 'mms',
            'date': int(elem.get('date', '0')),
            'ct_t': elem.get('ct_t', 'application/vnd.wap.multipart.related'),
            'msg_box': int(elem.get('msg_box', '1')),
            'address': elem.get('address', ''),
            'sub': elem.get('sub', 'null'),
            'retr_st': elem.get('retr_st', 'null'),
            'd_tm': elem.get('d_tm', 'null'),
            'exp': elem.get('exp', 'null'),
            'locked': int(elem.get('locked', '0')),
            'm_id': elem.get('m_id', 'null'),
            'st': elem.get('st', 'null'),
            'retr_txt_cs': elem.get('retr_txt_cs', 'null'),
            'retr_txt': elem.get('retr_txt', 'null'),
            'creator': elem.get('creator', 'null'),
            'date_sent': elem.get('date_sent', '0'),
            'seen': int(elem.get('seen', '1')),
            'm_size': elem.get('m_size', 'null'),
            'rr': elem.get('rr', '129'),
            'sub_cs': elem.get('sub_cs', 'null'),
            'resp_st': elem.get('resp_st', 'null'),
            'ct_cls': elem.get('ct_cls', 'null'),
            'm_cls': elem.get('m_cls', 'personal'),
            'd_rpt': elem.get('d_rpt', '129'),
            'v': elem.get('v', '18'),
            '_id': elem.get('_id', '1'),
            'tr_id': elem.get('tr_id', 'null'),
            'resp_txt': elem.get('resp_txt', 'null'),
            'ct_l': elem.get('ct_l', 'null'),
            'm_type': elem.get('m_type', '132'),
            'readable_date': elem.get('readable_date', ''),
            'contact_name': elem.get('contact_name', '(Unknown)'),
            'pri': elem.get('pri', '129'),
            'sub_id': elem.get('sub_id', '-1'),
            'text_only': elem.get('text_only', '0'),
            'parts': [],
            'addrs': [],
            'body': '',
        }

        parts_elem = elem.find('parts')
        if parts_elem is not None:
            for part_elem in parts_elem.findall('part'):
                part = {
                    'seq': part_elem.get('seq', '0'),
                    'ct': part_elem.get('ct', 'text/plain'),
                    'name': part_elem.get('name', 'null'),
                    'chset': part_elem.get('chset', 'null'),
                    'cd': part_elem.get('cd', 'null'),
                    'fn': part_elem.get('fn', 'null'),
                    'cid': part_elem.get('cid', 'null'),
                    'cl': part_elem.get('cl', 'null'),
                    'ctt_s': part_elem.get('ctt_s', 'null'),
                    'ctt_t': part_elem.get('ctt_t', 'null'),
                    'text': part_elem.get('text', 'null'),
                    'data': part_elem.get('data', 'null'),
                }
                msg['parts'].append(part)
                # Extract body text from text/plain part
                if part['ct'] == 'text/plain' and part['text'] != 'null':
                    msg['body'] = part['text']

        addrs_elem = elem.find('addrs')
        if addrs_elem is not None:
            for addr_elem in addrs_elem.findall('addr'):
                addr = {
                    'address': addr_elem.get('address', ''),
                    'type': addr_elem.get('type', '137'),
                    'charset': addr_elem.get('charset', '106'),
                }
                msg['addrs'].append(addr)

        return msg

    def save_backup(self, output_path: str) -> Dict[str, Any]:
        """Save current state to XML in SMS Backup & Restore format."""
        try:
            xml_str = self._build_xml()
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(xml_str, encoding='utf-8')
            return {
                'ok': True,
                'path': str(out),
                'count': len(self._messages),
                'size': out.stat().st_size,
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def merge_backups(self, paths: List[str]) -> Dict[str, Any]:
        """Merge multiple backup files, deduplicating by date+address+body."""
        seen = set()
        for msg in self._messages:
            seen.add(self._dedup_key(msg))

        added = 0
        errors = []
        for p in paths:
            try:
                tree = ET.parse(p)
                root = tree.getroot()
                if root.tag != 'smses':
                    errors.append(f'{p}: root element is not <smses>')
                    continue

                for elem in root:
                    if elem.tag == 'sms':
                        key = f"{elem.get('date', '0')}|{elem.get('address', '')}|{elem.get('body', '')}"
                        if key not in seen:
                            seen.add(key)
                            msg = {
                                'msg_kind': 'sms',
                                'protocol': elem.get('protocol', '0'),
                                'address': elem.get('address', ''),
                                'date': int(elem.get('date', '0')),
                                'type': int(elem.get('type', '1')),
                                'subject': elem.get('subject', 'null'),
                                'body': elem.get('body', ''),
                                'toa': elem.get('toa', 'null'),
                                'sc_toa': elem.get('sc_toa', 'null'),
                                'service_center': elem.get('service_center', 'null'),
                                'read': int(elem.get('read', '1')),
                                'status': int(elem.get('status', '-1')),
                                'locked': int(elem.get('locked', '0')),
                                'sub_id': elem.get('sub_id', '-1'),
                                'readable_date': elem.get('readable_date', ''),
                                'contact_name': elem.get('contact_name', '(Unknown)'),
                            }
                            self._messages.append(msg)
                            added += 1
                    elif elem.tag == 'mms':
                        mms_msg = self._parse_mms_element(elem)
                        key = self._dedup_key(mms_msg)
                        if key not in seen:
                            seen.add(key)
                            self._messages.append(mms_msg)
                            added += 1
            except Exception as e:
                errors.append(f'{p}: {e}')

        self._messages.sort(key=lambda m: m.get('date', 0))
        result: Dict[str, Any] = {
            'ok': True,
            'total': len(self._messages),
            'added': added,
        }
        if errors:
            result['errors'] = errors
        return result

    def _dedup_key(self, msg: Dict[str, Any]) -> str:
        """Generate a deduplication key from a message dict."""
        date_val = str(msg.get('date', '0'))
        addr = msg.get('address', '')
        body = msg.get('body', '')
        if msg.get('msg_kind') == 'mms' and not body:
            for part in msg.get('parts', []):
                if part.get('ct') == 'text/plain' and part.get('text', 'null') != 'null':
                    body = part['text']
                    break
        return f"{date_val}|{addr}|{body}"

    def get_backup_stats(self) -> Dict[str, Any]:
        """Return stats: message count, contacts, date range, SMS/MMS breakdown."""
        if not self._messages:
            return {
                'total': 0,
                'sms_count': 0,
                'mms_count': 0,
                'contacts': [],
                'date_range': None,
                'sent': 0,
                'received': 0,
            }

        sms_count = sum(1 for m in self._messages if m.get('msg_kind') == 'sms')
        mms_count = sum(1 for m in self._messages if m.get('msg_kind') == 'mms')

        contacts: Dict[str, Dict[str, Any]] = {}
        for m in self._messages:
            addr = m.get('address', '')
            name = m.get('contact_name', '(Unknown)')
            if addr not in contacts:
                contacts[addr] = {'address': addr, 'name': name, 'count': 0}
            contacts[addr]['count'] += 1

        dates = [m.get('date', 0) for m in self._messages if m.get('date', 0) > 0]
        date_range = None
        if dates:
            date_range = {
                'earliest': min(dates),
                'latest': max(dates),
                'earliest_readable': self._timestamp_to_readable(min(dates)),
                'latest_readable': self._timestamp_to_readable(max(dates)),
            }

        sent = 0
        received = 0
        for m in self._messages:
            if m.get('msg_kind') == 'sms':
                if m.get('type') == 2:
                    sent += 1
                elif m.get('type') == 1:
                    received += 1
            elif m.get('msg_kind') == 'mms':
                if m.get('msg_box') == 2:
                    sent += 1
                elif m.get('msg_box') == 1:
                    received += 1

        return {
            'total': len(self._messages),
            'sms_count': sms_count,
            'mms_count': mms_count,
            'contacts': list(contacts.values()),
            'date_range': date_range,
            'sent': sent,
            'received': received,
            'backup_set': self._backup_set,
        }

    # ── Message Creation ────────────────────────────────────────────────────

    def add_sms(self, address: str, body: str, msg_type: int = 1,
                timestamp: Optional[int] = None, contact_name: str = '(Unknown)',
                read: int = 1, locked: int = 0) -> Dict[str, Any]:
        """Add a single SMS message.

        Args:
            address: Phone number (e.g. +15551234567)
            body: Message text
            msg_type: 1=received, 2=sent, 3=draft, 4=outbox, 5=failed, 6=queued
            timestamp: Epoch milliseconds (defaults to now)
            contact_name: Display name for contact
            read: 1=read, 0=unread
            locked: 0=unlocked, 1=locked
        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)

        msg = {
            'msg_kind': 'sms',
            'protocol': '0',
            'address': address,
            'date': timestamp,
            'type': msg_type,
            'subject': 'null',
            'body': body,
            'toa': 'null',
            'sc_toa': 'null',
            'service_center': 'null',
            'read': read,
            'status': -1,
            'locked': locked,
            'sub_id': '-1',
            'readable_date': self._timestamp_to_readable(timestamp),
            'contact_name': contact_name,
        }
        self._messages.append(msg)
        return {'ok': True, 'index': len(self._messages) - 1, 'date': timestamp}

    def add_mms(self, address: str, body: str = '',
                attachments: Optional[List[Dict[str, str]]] = None,
                msg_box: int = 1, timestamp: Optional[int] = None,
                contact_name: str = '(Unknown)') -> Dict[str, Any]:
        """Add an MMS message with optional attachments.

        Args:
            address: Phone number
            body: Text body of the MMS
            attachments: List of dicts with keys: path (file path), content_type (MIME),
                         or data (base64 encoded), filename
            msg_box: 1=received, 2=sent, 3=draft, 4=outbox
            timestamp: Epoch milliseconds
            contact_name: Display name
        """
        if timestamp is None:
            timestamp = int(time.time() * 1000)
        if attachments is None:
            attachments = []

        parts: List[Dict[str, str]] = []
        has_media = len(attachments) > 0

        # SMIL part (required for MMS with attachments)
        if has_media:
            smil_body = '<smil><head><layout><root-layout/>'
            smil_body += '<region id="Text" top="70%" left="0%" height="30%" width="100%"/>'
            smil_body += '<region id="Image" top="0%" left="0%" height="70%" width="100%"/>'
            smil_body += '</layout></head><body><par dur="5000ms">'
            if body:
                smil_body += '<text src="txt000.txt" region="Text"/>'
            for i, att in enumerate(attachments):
                fname = att.get('filename', f'attachment_{i}')
                ct = att.get('content_type', 'application/octet-stream')
                if ct.startswith('image/'):
                    smil_body += f'<img src="{self._escape_xml(fname)}" region="Image"/>'
                elif ct.startswith('audio/'):
                    smil_body += f'<audio src="{self._escape_xml(fname)}"/>'
                elif ct.startswith('video/'):
                    smil_body += f'<video src="{self._escape_xml(fname)}"/>'
            smil_body += '</par></body></smil>'
            parts.append({
                'seq': '0', 'ct': 'application/smil', 'name': 'null',
                'chset': 'null', 'cd': 'null', 'fn': 'null',
                'cid': '<smil>', 'cl': 'smil.xml',
                'ctt_s': 'null', 'ctt_t': 'null',
                'text': smil_body, 'data': 'null',
            })

        # Attachment parts
        for i, att in enumerate(attachments):
            fname = att.get('filename', f'attachment_{i}')
            ct = att.get('content_type', 'application/octet-stream')
            data = 'null'
            if 'path' in att and os.path.isfile(att['path']):
                data = self._encode_attachment(att['path'])
            elif 'data' in att:
                data = att['data']
            parts.append({
                'seq': '0', 'ct': ct, 'name': fname,
                'chset': 'null', 'cd': 'null', 'fn': 'null',
                'cid': f'<{fname}>', 'cl': fname,
                'ctt_s': 'null', 'ctt_t': 'null',
                'text': 'null', 'data': data,
            })

        # Text part
        if body:
            parts.append({
                'seq': '0', 'ct': 'text/plain', 'name': 'null',
                'chset': '106', 'cd': 'null', 'fn': 'null',
                'cid': 'null', 'cl': 'txt000.txt',
                'ctt_s': 'null', 'ctt_t': 'null',
                'text': body, 'data': 'null',
            })

        text_only = '1' if not has_media else '0'

        # Address records
        addrs = []
        if msg_box == 1:
            # Received: sender is type 137, self is type 151
            addrs.append({'address': address, 'type': '137', 'charset': '106'})
            addrs.append({'address': 'insert-address-token', 'type': '151', 'charset': '106'})
        else:
            # Sent: self is type 137, recipient is type 151
            addrs.append({'address': 'insert-address-token', 'type': '137', 'charset': '106'})
            addrs.append({'address': address, 'type': '151', 'charset': '106'})

        msg: Dict[str, Any] = {
            'msg_kind': 'mms',
            'date': timestamp,
            'ct_t': 'application/vnd.wap.multipart.related',
            'msg_box': msg_box,
            'address': address,
            'sub': 'null',
            'retr_st': 'null',
            'd_tm': 'null',
            'exp': 'null',
            'locked': 0,
            'm_id': 'null',
            'st': 'null',
            'retr_txt_cs': 'null',
            'retr_txt': 'null',
            'creator': 'null',
            'date_sent': '0',
            'seen': 1,
            'm_size': 'null',
            'rr': '129',
            'sub_cs': 'null',
            'resp_st': 'null',
            'ct_cls': 'null',
            'm_cls': 'personal',
            'd_rpt': '129',
            'v': '18',
            '_id': str(len(self._messages) + 1),
            'tr_id': 'null',
            'resp_txt': 'null',
            'ct_l': 'null',
            'm_type': '132',
            'readable_date': self._timestamp_to_readable(timestamp),
            'contact_name': contact_name,
            'pri': '129',
            'sub_id': '-1',
            'text_only': text_only,
            'parts': parts,
            'addrs': addrs,
            'body': body,
        }
        self._messages.append(msg)
        return {'ok': True, 'index': len(self._messages) - 1, 'date': timestamp}

    def add_conversation(self, address: str, contact_name: str,
                         messages: List[Dict[str, Any]],
                         start_timestamp: Optional[int] = None) -> Dict[str, Any]:
        """Add a full conversation from a list of message dicts.

        Each message dict: {body: str, type: int (1=received, 2=sent), delay_minutes: int}
        """
        if start_timestamp is None:
            start_timestamp = int(time.time() * 1000)

        current_ts = start_timestamp
        added = 0
        for msg in messages:
            delay = msg.get('delay_minutes', 0)
            current_ts += delay * 60 * 1000
            self.add_sms(
                address=address,
                body=msg.get('body', ''),
                msg_type=msg.get('type', 1),
                timestamp=current_ts,
                contact_name=contact_name,
                read=msg.get('read', 1),
                locked=msg.get('locked', 0),
            )
            added += 1

        return {
            'ok': True,
            'added': added,
            'start': start_timestamp,
            'end': current_ts,
        }

    def generate_conversation(self, address: str, contact_name: str,
                              template: str, variables: Optional[Dict[str, str]] = None,
                              start_timestamp: Optional[int] = None) -> Dict[str, Any]:
        """Generate a conversation from a template with variable substitution.

        Args:
            address: Phone number
            contact_name: Display name
            template: Template name (e.g. 'business_meeting', 'casual_chat')
            variables: Dict of variable names to values for substitution
            start_timestamp: Starting epoch ms timestamp
        """
        tmpl = self._get_template(template)
        if tmpl is None:
            return {'ok': False, 'error': f'Template not found: {template}'}

        if variables is None:
            variables = {}

        messages = []
        for msg_tmpl in tmpl.get('messages', []):
            body = msg_tmpl['body']
            for key, val in variables.items():
                body = body.replace('{' + key + '}', str(val))
            messages.append({
                'body': body,
                'type': msg_tmpl.get('type', 1),
                'delay_minutes': msg_tmpl.get('delay_minutes', 0),
            })

        return self.add_conversation(address, contact_name, messages, start_timestamp)

    def bulk_add(self, csv_path: str) -> Dict[str, Any]:
        """Import messages from CSV file.

        Expected CSV columns: address, body, type, timestamp, contact_name
        """
        path = Path(csv_path)
        if not path.exists():
            return {'ok': False, 'error': f'File not found: {csv_path}'}
        try:
            added = 0
            errors = []
            with open(str(path), 'r', encoding='utf-8', newline='') as f:
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):
                    try:
                        address = row.get('address', '').strip()
                        body = row.get('body', '').strip()
                        msg_type = int(row.get('type', '1').strip())
                        ts_str = row.get('timestamp', '').strip()
                        timestamp = int(ts_str) if ts_str else None
                        contact_name = row.get('contact_name', '(Unknown)').strip()
                        self.add_sms(address, body, msg_type, timestamp, contact_name)
                        added += 1
                    except Exception as e:
                        errors.append(f'Row {row_num}: {e}')
            result: Dict[str, Any] = {'ok': True, 'added': added}
            if errors:
                result['errors'] = errors
            return result
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Message Modification ────────────────────────────────────────────────

    def find_messages(self, address: Optional[str] = None,
                      date_from: Optional[int] = None,
                      date_to: Optional[int] = None,
                      keyword: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search messages with filters. Returns list of {index, ...msg} dicts."""
        results = []
        for i, msg in enumerate(self._messages):
            if address and msg.get('address', '') != address:
                continue
            msg_date = msg.get('date', 0)
            if date_from and msg_date < date_from:
                continue
            if date_to and msg_date > date_to:
                continue
            if keyword:
                body = msg.get('body', '')
                if msg.get('msg_kind') == 'mms' and not body:
                    for part in msg.get('parts', []):
                        if part.get('ct') == 'text/plain' and part.get('text', 'null') != 'null':
                            body = part['text']
                            break
                if keyword.lower() not in body.lower():
                    continue
            result = dict(msg)
            result['index'] = i
            results.append(result)
        return results

    def modify_message(self, index: int, new_body: Optional[str] = None,
                       new_timestamp: Optional[int] = None,
                       new_contact: Optional[str] = None) -> Dict[str, Any]:
        """Modify an existing message by index."""
        if index < 0 or index >= len(self._messages):
            return {'ok': False, 'error': f'Invalid index: {index}'}

        msg = self._messages[index]
        if new_body is not None:
            if msg.get('msg_kind') == 'mms':
                # Update text part in MMS
                found_text = False
                for part in msg.get('parts', []):
                    if part.get('ct') == 'text/plain':
                        part['text'] = new_body
                        found_text = True
                        break
                if not found_text:
                    msg.setdefault('parts', []).append({
                        'seq': '0', 'ct': 'text/plain', 'name': 'null',
                        'chset': '106', 'cd': 'null', 'fn': 'null',
                        'cid': 'null', 'cl': 'txt000.txt',
                        'ctt_s': 'null', 'ctt_t': 'null',
                        'text': new_body, 'data': 'null',
                    })
                msg['body'] = new_body
            else:
                msg['body'] = new_body

        if new_timestamp is not None:
            msg['date'] = new_timestamp
            msg['readable_date'] = self._timestamp_to_readable(new_timestamp)

        if new_contact is not None:
            msg['contact_name'] = new_contact

        return {'ok': True, 'index': index}

    def delete_messages(self, indices: List[int]) -> Dict[str, Any]:
        """Delete messages by index. Indices are processed in reverse order."""
        valid = [i for i in sorted(set(indices), reverse=True)
                 if 0 <= i < len(self._messages)]
        for i in valid:
            self._messages.pop(i)
        return {'ok': True, 'deleted': len(valid), 'remaining': len(self._messages)}

    def replace_contact(self, old_address: str, new_address: str,
                        new_name: Optional[str] = None) -> Dict[str, Any]:
        """Change contact address (and optionally name) across all messages."""
        updated = 0
        for msg in self._messages:
            if msg.get('address') == old_address:
                msg['address'] = new_address
                if new_name is not None:
                    msg['contact_name'] = new_name
                updated += 1
                # Also update MMS addr records
                for addr in msg.get('addrs', []):
                    if addr.get('address') == old_address:
                        addr['address'] = new_address
        return {'ok': True, 'updated': updated}

    def shift_timestamps(self, address: Optional[str], offset_minutes: int) -> Dict[str, Any]:
        """Shift all timestamps for a contact (or all messages if address is None)."""
        offset_ms = offset_minutes * 60 * 1000
        shifted = 0
        for msg in self._messages:
            if address is None or msg.get('address') == address:
                msg['date'] = msg.get('date', 0) + offset_ms
                msg['readable_date'] = self._timestamp_to_readable(msg['date'])
                shifted += 1
        return {'ok': True, 'shifted': shifted, 'offset_minutes': offset_minutes}

    # ── Conversation Templates ──────────────────────────────────────────────

    def get_templates(self) -> Dict[str, Any]:
        """Return all available conversation templates (built-in + custom)."""
        templates = {}
        for key, tmpl in BUILTIN_TEMPLATES.items():
            templates[key] = {
                'name': tmpl['name'],
                'description': tmpl['description'],
                'variables': tmpl.get('variables', []),
                'message_count': len(tmpl.get('messages', [])),
                'messages': tmpl.get('messages', []),
                'builtin': True,
            }
        for key, tmpl in self._custom_templates.items():
            templates[key] = {
                'name': tmpl.get('name', key),
                'description': tmpl.get('description', ''),
                'variables': tmpl.get('variables', []),
                'message_count': len(tmpl.get('messages', [])),
                'messages': tmpl.get('messages', []),
                'builtin': False,
            }
        return templates

    def save_custom_template(self, key: str, template: Dict[str, Any]) -> Dict[str, Any]:
        """Save a custom template."""
        self._custom_templates[key] = template
        self._save_custom_templates()
        return {'ok': True, 'key': key}

    def delete_custom_template(self, key: str) -> Dict[str, Any]:
        """Delete a custom template."""
        if key in self._custom_templates:
            del self._custom_templates[key]
            self._save_custom_templates()
            return {'ok': True}
        return {'ok': False, 'error': f'Template not found: {key}'}

    def _get_template(self, name: str) -> Optional[Dict[str, Any]]:
        """Look up a template by name from built-in and custom templates."""
        if name in BUILTIN_TEMPLATES:
            return BUILTIN_TEMPLATES[name]
        if name in self._custom_templates:
            return self._custom_templates[name]
        return None

    def _load_custom_templates(self):
        """Load custom templates from disk."""
        tmpl_file = self._data_dir / 'custom_templates.json'
        if tmpl_file.exists():
            try:
                self._custom_templates = json.loads(tmpl_file.read_text('utf-8'))
            except Exception:
                self._custom_templates = {}

    def _save_custom_templates(self):
        """Persist custom templates to disk."""
        tmpl_file = self._data_dir / 'custom_templates.json'
        tmpl_file.write_text(json.dumps(self._custom_templates, indent=2), encoding='utf-8')

    # ── Export / Import ─────────────────────────────────────────────────────

    def export_xml(self, path: str) -> Dict[str, Any]:
        """Export current messages to SMS Backup & Restore XML format."""
        return self.save_backup(path)

    def import_xml(self, path: str) -> Dict[str, Any]:
        """Import messages from an XML backup file (appends to current messages)."""
        old_messages = list(self._messages)
        old_backup_set = self._backup_set
        old_backup_date = self._backup_date
        result = self.load_backup(path)
        if result.get('ok'):
            new_messages = list(self._messages)
            self._messages = old_messages + new_messages
            self._backup_set = old_backup_set
            self._backup_date = old_backup_date
            result['added'] = len(new_messages)
            result['total'] = len(self._messages)
        else:
            self._messages = old_messages
            self._backup_set = old_backup_set
            self._backup_date = old_backup_date
        return result

    def export_csv(self, path: str) -> Dict[str, Any]:
        """Export current messages to CSV format."""
        try:
            out = Path(path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(str(out), 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['address', 'body', 'type', 'timestamp',
                                 'contact_name', 'readable_date', 'msg_kind'])
                for msg in self._messages:
                    body = msg.get('body', '')
                    if msg.get('msg_kind') == 'mms' and not body:
                        for part in msg.get('parts', []):
                            if part.get('ct') == 'text/plain' and part.get('text', 'null') != 'null':
                                body = part['text']
                                break
                    msg_type = msg.get('type', msg.get('msg_box', 1))
                    writer.writerow([
                        msg.get('address', ''),
                        body,
                        msg_type,
                        msg.get('date', 0),
                        msg.get('contact_name', ''),
                        msg.get('readable_date', ''),
                        msg.get('msg_kind', 'sms'),
                    ])
            return {
                'ok': True,
                'path': str(out),
                'count': len(self._messages),
                'size': out.stat().st_size,
            }
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    def import_csv(self, path: str) -> Dict[str, Any]:
        """Import messages from CSV (same format as export_csv)."""
        return self.bulk_add(path)

    def validate_backup(self, path: str) -> Dict[str, Any]:
        """Validate XML structure matches SMS Backup & Restore format."""
        p = Path(path)
        if not p.exists():
            return {'ok': False, 'valid': False, 'error': 'File not found'}

        issues: List[str] = []
        try:
            tree = ET.parse(str(p))
            root = tree.getroot()

            if root.tag != 'smses':
                issues.append(f'Root element is <{root.tag}>, expected <smses>')

            if not root.get('count'):
                issues.append('Missing count attribute on <smses>')
            else:
                declared = int(root.get('count', '0'))
                actual = len(list(root))
                if declared != actual:
                    issues.append(f'Count mismatch: declared {declared}, actual {actual}')

            if not root.get('backup_set'):
                issues.append('Missing backup_set attribute')
            if not root.get('backup_date'):
                issues.append('Missing backup_date attribute')

            sms_req = ['address', 'date', 'type', 'body']
            mms_req = ['date', 'msg_box', 'address']

            for i, elem in enumerate(root):
                if elem.tag == 'sms':
                    for attr in sms_req:
                        if elem.get(attr) is None:
                            issues.append(f'SMS #{i}: missing required attribute "{attr}"')
                elif elem.tag == 'mms':
                    for attr in mms_req:
                        if elem.get(attr) is None:
                            issues.append(f'MMS #{i}: missing required attribute "{attr}"')
                    parts = elem.find('parts')
                    if parts is None:
                        issues.append(f'MMS #{i}: missing <parts> element')
                    addrs = elem.find('addrs')
                    if addrs is None:
                        issues.append(f'MMS #{i}: missing <addrs> element')
                else:
                    issues.append(f'Element #{i}: unexpected tag <{elem.tag}>')

            return {
                'ok': True,
                'valid': len(issues) == 0,
                'issues': issues,
                'element_count': len(list(root)),
            }

        except ET.ParseError as e:
            return {'ok': False, 'valid': False, 'error': f'XML parse error: {e}'}
        except Exception as e:
            return {'ok': False, 'valid': False, 'error': str(e)}

    # ── XML Builder ─────────────────────────────────────────────────────────

    def _build_xml(self) -> str:
        """Build the full XML string in SMS Backup & Restore format."""
        lines = []
        lines.append("<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>")
        lines.append('<?xml-stylesheet type="text/xsl" href="sms.xsl"?>')

        count = len(self._messages)
        backup_date = str(self._backup_date)
        lines.append(
            f'<smses count="{count}" backup_set="{self._escape_xml(self._backup_set)}" '
            f'backup_date="{backup_date}" type="{self._escape_xml(self._backup_type)}">'
        )

        for msg in self._messages:
            if msg.get('msg_kind') == 'mms':
                lines.append(self._build_mms_element(msg))
            else:
                lines.append(self._build_sms_element(msg))

        lines.append('</smses>')
        return '\n'.join(lines)

    def _build_sms_element(self, msg: Dict[str, Any]) -> str:
        """Build a single <sms /> XML element."""
        attrs = {
            'protocol': str(msg.get('protocol', '0')),
            'address': str(msg.get('address', '')),
            'date': str(msg.get('date', 0)),
            'type': str(msg.get('type', 1)),
            'subject': str(msg.get('subject', 'null')),
            'body': str(msg.get('body', '')),
            'toa': str(msg.get('toa', 'null')),
            'sc_toa': str(msg.get('sc_toa', 'null')),
            'service_center': str(msg.get('service_center', 'null')),
            'read': str(msg.get('read', 1)),
            'status': str(msg.get('status', -1)),
            'locked': str(msg.get('locked', 0)),
            'sub_id': str(msg.get('sub_id', '-1')),
            'readable_date': str(msg.get('readable_date', '')),
            'contact_name': str(msg.get('contact_name', '(Unknown)')),
        }
        attr_str = ' '.join(f'{k}="{self._escape_xml(v)}"' for k, v in attrs.items())
        return f'  <sms {attr_str} />'

    def _build_mms_element(self, msg: Dict[str, Any]) -> str:
        """Build a single <mms>...</mms> XML element."""
        mms_attrs = {
            'date': str(msg.get('date', 0)),
            'ct_t': str(msg.get('ct_t', 'application/vnd.wap.multipart.related')),
            'msg_box': str(msg.get('msg_box', 1)),
            'address': str(msg.get('address', '')),
            'sub': str(msg.get('sub', 'null')),
            'retr_st': str(msg.get('retr_st', 'null')),
            'd_tm': str(msg.get('d_tm', 'null')),
            'exp': str(msg.get('exp', 'null')),
            'locked': str(msg.get('locked', 0)),
            'm_id': str(msg.get('m_id', 'null')),
            'st': str(msg.get('st', 'null')),
            'retr_txt_cs': str(msg.get('retr_txt_cs', 'null')),
            'retr_txt': str(msg.get('retr_txt', 'null')),
            'creator': str(msg.get('creator', 'null')),
            'date_sent': str(msg.get('date_sent', '0')),
            'seen': str(msg.get('seen', 1)),
            'm_size': str(msg.get('m_size', 'null')),
            'rr': str(msg.get('rr', '129')),
            'sub_cs': str(msg.get('sub_cs', 'null')),
            'resp_st': str(msg.get('resp_st', 'null')),
            'ct_cls': str(msg.get('ct_cls', 'null')),
            'm_cls': str(msg.get('m_cls', 'personal')),
            'd_rpt': str(msg.get('d_rpt', '129')),
            'v': str(msg.get('v', '18')),
            '_id': str(msg.get('_id', '1')),
            'tr_id': str(msg.get('tr_id', 'null')),
            'resp_txt': str(msg.get('resp_txt', 'null')),
            'ct_l': str(msg.get('ct_l', 'null')),
            'm_type': str(msg.get('m_type', '132')),
            'readable_date': str(msg.get('readable_date', '')),
            'contact_name': str(msg.get('contact_name', '(Unknown)')),
            'pri': str(msg.get('pri', '129')),
            'sub_id': str(msg.get('sub_id', '-1')),
            'text_only': str(msg.get('text_only', '0')),
        }
        attr_str = ' '.join(f'{k}="{self._escape_xml(v)}"' for k, v in mms_attrs.items())

        lines = [f'  <mms {attr_str}>']

        # Parts
        lines.append('    <parts>')
        for part in msg.get('parts', []):
            part_attrs = {
                'seq': str(part.get('seq', '0')),
                'ct': str(part.get('ct', 'text/plain')),
                'name': str(part.get('name', 'null')),
                'chset': str(part.get('chset', 'null')),
                'cd': str(part.get('cd', 'null')),
                'fn': str(part.get('fn', 'null')),
                'cid': str(part.get('cid', 'null')),
                'cl': str(part.get('cl', 'null')),
                'ctt_s': str(part.get('ctt_s', 'null')),
                'ctt_t': str(part.get('ctt_t', 'null')),
                'text': str(part.get('text', 'null')),
                'data': str(part.get('data', 'null')),
            }
            pa_str = ' '.join(f'{k}="{self._escape_xml(v)}"' for k, v in part_attrs.items())
            lines.append(f'      <part {pa_str} />')
        lines.append('    </parts>')

        # Addrs
        lines.append('    <addrs>')
        for addr in msg.get('addrs', []):
            addr_attrs = {
                'address': str(addr.get('address', '')),
                'type': str(addr.get('type', '137')),
                'charset': str(addr.get('charset', '106')),
            }
            aa_str = ' '.join(f'{k}="{self._escape_xml(v)}"' for k, v in addr_attrs.items())
            lines.append(f'      <addr {aa_str} />')
        lines.append('    </addrs>')

        lines.append('  </mms>')
        return '\n'.join(lines)

    # ── Utility ─────────────────────────────────────────────────────────────

    @staticmethod
    def _generate_uuid() -> str:
        """Generate a backup_set UUID."""
        return str(uuid.uuid4())

    @staticmethod
    def _timestamp_to_readable(ms_timestamp: int) -> str:
        """Convert epoch milliseconds to readable date string (SMS Backup & Restore format)."""
        try:
            dt = datetime.fromtimestamp(ms_timestamp / 1000.0)
            # Format: "Mar 1, 2023 12:45:21 PM"
            if os.name == 'nt':
                return dt.strftime('%b %#d, %Y %#I:%M:%S %p')
            return dt.strftime('%b %-d, %Y %-I:%M:%S %p')
        except (ValueError, OSError, OverflowError):
            return ''

    @staticmethod
    def _readable_to_timestamp(readable: str) -> Optional[int]:
        """Convert readable date string to epoch milliseconds."""
        formats = [
            '%b %d, %Y %I:%M:%S %p',
            '%b %d, %Y %H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%m/%d/%Y %I:%M:%S %p',
            '%m/%d/%Y %H:%M:%S',
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(readable.strip(), fmt)
                return int(dt.timestamp() * 1000)
            except ValueError:
                continue
        return None

    @staticmethod
    def _escape_xml(text: str) -> str:
        """Proper XML attribute escaping."""
        return html.escape(str(text), quote=True)

    @staticmethod
    def _encode_attachment(file_path: str) -> str:
        """Base64 encode a file for MMS attachment data."""
        with open(file_path, 'rb') as f:
            return base64.b64encode(f.read()).decode('ascii')

    def get_messages(self) -> List[Dict[str, Any]]:
        """Return a copy of all messages with indices."""
        result = []
        for i, msg in enumerate(self._messages):
            m = dict(msg)
            m['index'] = i
            result.append(m)
        return result

    def clear_messages(self):
        """Clear all messages from the working set."""
        self._messages = []
        self._backup_set = self._generate_uuid()
        self._backup_date = int(time.time() * 1000)

    def get_status(self) -> Dict[str, Any]:
        """Module status information."""
        return {
            'ok': True,
            'module': 'sms_forge',
            'version': VERSION,
            'description': DESCRIPTION,
            'message_count': len(self._messages),
            'backup_set': self._backup_set,
            'data_dir': str(self._data_dir),
            'custom_templates': len(self._custom_templates),
        }

    def run(self):
        """CLI interactive menu for the SMS Forge module."""
        while True:
            print("\n" + "=" * 60)
            print("  SMS/MMS Backup Forge")
            print("=" * 60)
            print(f"  Messages loaded: {len(self._messages)}")
            print()
            print("  1. Create new backup")
            print("  2. Load existing backup")
            print("  3. Add SMS message")
            print("  4. Add MMS message")
            print("  5. Add conversation")
            print("  6. Generate from template")
            print("  7. Find messages")
            print("  8. Modify message")
            print("  9. Delete messages")
            print("  10. Replace contact")
            print("  11. Shift timestamps")
            print("  12. Export XML")
            print("  13. Export CSV")
            print("  14. Import CSV (bulk)")
            print("  15. Merge backups")
            print("  16. Validate backup")
            print("  17. View stats")
            print("  18. List templates")
            print("  0. Exit")
            print()

            try:
                choice = input("  Select: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if choice == '0':
                break
            elif choice == '1':
                self._cli_create_backup()
            elif choice == '2':
                self._cli_load_backup()
            elif choice == '3':
                self._cli_add_sms()
            elif choice == '4':
                self._cli_add_mms()
            elif choice == '5':
                self._cli_add_conversation()
            elif choice == '6':
                self._cli_generate_template()
            elif choice == '7':
                self._cli_find_messages()
            elif choice == '8':
                self._cli_modify_message()
            elif choice == '9':
                self._cli_delete_messages()
            elif choice == '10':
                self._cli_replace_contact()
            elif choice == '11':
                self._cli_shift_timestamps()
            elif choice == '12':
                self._cli_export_xml()
            elif choice == '13':
                self._cli_export_csv()
            elif choice == '14':
                self._cli_import_csv()
            elif choice == '15':
                self._cli_merge_backups()
            elif choice == '16':
                self._cli_validate()
            elif choice == '17':
                self._cli_stats()
            elif choice == '18':
                self._cli_list_templates()
            else:
                print("  Invalid selection.")

    # ── CLI Helpers ─────────────────────────────────────────────────────────

    def _cli_input(self, prompt: str, default: str = '') -> str:
        """Read input with optional default."""
        suffix = f' [{default}]' if default else ''
        try:
            val = input(f'  {prompt}{suffix}: ').strip()
            return val if val else default
        except (EOFError, KeyboardInterrupt):
            return default

    def _cli_create_backup(self):
        path = self._cli_input('Output path', str(self._data_dir / 'backup.xml'))
        result = self.save_backup(path)
        if result.get('ok'):
            print(f"  Backup created: {result['path']} ({result['count']} messages)")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_load_backup(self):
        path = self._cli_input('XML file path')
        if not path:
            print("  No path provided.")
            return
        result = self.load_backup(path)
        if result.get('ok'):
            print(f"  Loaded {result['count']} messages")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_add_sms(self):
        address = self._cli_input('Phone number (e.g. +15551234567)')
        body = self._cli_input('Message body')
        type_str = self._cli_input('Type (1=received, 2=sent)', '1')
        contact = self._cli_input('Contact name', '(Unknown)')
        result = self.add_sms(address, body, int(type_str), contact_name=contact)
        print(f"  Added SMS at index {result['index']}")

    def _cli_add_mms(self):
        address = self._cli_input('Phone number')
        body = self._cli_input('Text body')
        box_str = self._cli_input('Msg box (1=received, 2=sent)', '1')
        contact = self._cli_input('Contact name', '(Unknown)')
        att_path = self._cli_input('Attachment file path (blank for none)')
        attachments = []
        if att_path and os.path.isfile(att_path):
            ct = self._cli_input('Content type', 'image/jpeg')
            attachments.append({
                'path': att_path,
                'content_type': ct,
                'filename': os.path.basename(att_path),
            })
        result = self.add_mms(address, body, attachments, int(box_str), contact_name=contact)
        print(f"  Added MMS at index {result['index']}")

    def _cli_add_conversation(self):
        address = self._cli_input('Phone number')
        contact = self._cli_input('Contact name', '(Unknown)')
        print("  Enter messages (empty body to finish):")
        messages = []
        while True:
            body = self._cli_input(f'  Message {len(messages) + 1} body')
            if not body:
                break
            type_str = self._cli_input('  Type (1=received, 2=sent)', '1')
            delay_str = self._cli_input('  Delay (minutes from previous)', '5')
            messages.append({
                'body': body,
                'type': int(type_str),
                'delay_minutes': int(delay_str),
            })
        if messages:
            result = self.add_conversation(address, contact, messages)
            print(f"  Added {result['added']} messages")
        else:
            print("  No messages to add.")

    def _cli_generate_template(self):
        templates = self.get_templates()
        print("  Available templates:")
        for key, tmpl in templates.items():
            print(f"    {key}: {tmpl['name']} -- {tmpl['description']}")
        name = self._cli_input('Template name')
        if name not in templates:
            print("  Template not found.")
            return
        address = self._cli_input('Phone number')
        contact = self._cli_input('Contact name')
        variables = {}
        tmpl = templates[name]
        for var in tmpl.get('variables', []):
            val = self._cli_input(f'  {var}')
            variables[var] = val
        result = self.generate_conversation(address, contact, name, variables)
        if result.get('ok'):
            print(f"  Generated {result.get('added', 0)} messages")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_find_messages(self):
        address = self._cli_input('Filter by address (blank for all)')
        keyword = self._cli_input('Filter by keyword (blank for all)')
        results = self.find_messages(
            address=address if address else None,
            keyword=keyword if keyword else None,
        )
        print(f"  Found {len(results)} messages:")
        for msg in results[:20]:
            direction = 'IN' if msg.get('type', msg.get('msg_box', 1)) == 1 else 'OUT'
            body = msg.get('body', '')[:60]
            print(f"    [{msg['index']}] {direction} {msg.get('address', '')}: {body}")
        if len(results) > 20:
            print(f"    ... and {len(results) - 20} more")

    def _cli_modify_message(self):
        idx_str = self._cli_input('Message index')
        if not idx_str:
            return
        new_body = self._cli_input('New body (blank to skip)')
        new_contact = self._cli_input('New contact name (blank to skip)')
        result = self.modify_message(
            int(idx_str),
            new_body=new_body if new_body else None,
            new_contact=new_contact if new_contact else None,
        )
        if result.get('ok'):
            print("  Message modified.")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_delete_messages(self):
        idx_str = self._cli_input('Message indices (comma-separated)')
        if not idx_str:
            return
        indices = [int(x.strip()) for x in idx_str.split(',') if x.strip().isdigit()]
        result = self.delete_messages(indices)
        print(f"  Deleted {result['deleted']} messages, {result['remaining']} remaining.")

    def _cli_replace_contact(self):
        old = self._cli_input('Old address')
        new = self._cli_input('New address')
        name = self._cli_input('New contact name (blank to keep)')
        result = self.replace_contact(old, new, name if name else None)
        print(f"  Updated {result['updated']} messages.")

    def _cli_shift_timestamps(self):
        address = self._cli_input('Address (blank for all)')
        offset = self._cli_input('Offset in minutes (negative to go back)')
        result = self.shift_timestamps(
            address if address else None,
            int(offset),
        )
        print(f"  Shifted {result['shifted']} messages by {result['offset_minutes']} minutes.")

    def _cli_export_xml(self):
        path = self._cli_input('Output path', str(self._data_dir / 'export.xml'))
        result = self.export_xml(path)
        if result.get('ok'):
            print(f"  Exported to {result['path']} ({result['count']} messages, {result['size']} bytes)")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_export_csv(self):
        path = self._cli_input('Output path', str(self._data_dir / 'export.csv'))
        result = self.export_csv(path)
        if result.get('ok'):
            print(f"  Exported to {result['path']} ({result['count']} messages)")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_import_csv(self):
        path = self._cli_input('CSV file path')
        if not path:
            return
        result = self.bulk_add(path)
        if result.get('ok'):
            print(f"  Imported {result['added']} messages")
            if result.get('errors'):
                for err in result['errors'][:5]:
                    print(f"    Warning: {err}")
        else:
            print(f"  Error: {result.get('error')}")

    def _cli_merge_backups(self):
        paths_str = self._cli_input('Backup file paths (comma-separated)')
        if not paths_str:
            return
        paths = [p.strip() for p in paths_str.split(',') if p.strip()]
        result = self.merge_backups(paths)
        if result.get('ok'):
            print(f"  Merged: {result['total']} total messages ({result['added']} new)")
        if result.get('errors'):
            for err in result['errors']:
                print(f"    Error: {err}")

    def _cli_validate(self):
        path = self._cli_input('XML file path')
        if not path:
            return
        result = self.validate_backup(path)
        if result.get('valid'):
            print(f"  Valid backup ({result['element_count']} elements)")
        else:
            print("  Invalid backup:")
            for issue in result.get('issues', []):
                print(f"    - {issue}")
            if result.get('error'):
                print(f"    Error: {result['error']}")

    def _cli_stats(self):
        stats = self.get_backup_stats()
        print(f"  Total messages: {stats['total']}")
        print(f"  SMS: {stats['sms_count']}, MMS: {stats['mms_count']}")
        print(f"  Sent: {stats['sent']}, Received: {stats['received']}")
        print(f"  Contacts: {len(stats['contacts'])}")
        if stats.get('date_range'):
            dr = stats['date_range']
            print(f"  Date range: {dr['earliest_readable']} -- {dr['latest_readable']}")
        for c in stats.get('contacts', [])[:10]:
            print(f"    {c['address']} ({c['name']}): {c['count']} messages")

    def _cli_list_templates(self):
        templates = self.get_templates()
        for key, tmpl in templates.items():
            tag = '[builtin]' if tmpl.get('builtin') else '[custom]'
            print(f"  {key} {tag}: {tmpl['name']}")
            print(f"    {tmpl['description']}")
            print(f"    Messages: {tmpl['message_count']}, Variables: {', '.join(tmpl.get('variables', []))}")
            print()
