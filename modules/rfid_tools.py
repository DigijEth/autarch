"""AUTARCH RFID/NFC Tools

Proxmark3 integration, badge cloning, NFC read/write, MIFARE operations,
and card analysis for physical access security testing.
"""

DESCRIPTION = "RFID/NFC badge cloning & analysis"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

import os
import re
import json
import time
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

try:
    from core.paths import find_tool, get_data_dir
except ImportError:
    def find_tool(name):
        return shutil.which(name)
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Card Types ───────────────────────────────────────────────────────────────

CARD_TYPES = {
    'em410x': {'name': 'EM410x', 'frequency': '125 kHz', 'category': 'LF'},
    'hid_prox': {'name': 'HID ProxCard', 'frequency': '125 kHz', 'category': 'LF'},
    't5577': {'name': 'T5577', 'frequency': '125 kHz', 'category': 'LF', 'writable': True},
    'mifare_classic_1k': {'name': 'MIFARE Classic 1K', 'frequency': '13.56 MHz', 'category': 'HF'},
    'mifare_classic_4k': {'name': 'MIFARE Classic 4K', 'frequency': '13.56 MHz', 'category': 'HF'},
    'mifare_ultralight': {'name': 'MIFARE Ultralight', 'frequency': '13.56 MHz', 'category': 'HF'},
    'mifare_desfire': {'name': 'MIFARE DESFire', 'frequency': '13.56 MHz', 'category': 'HF'},
    'ntag213': {'name': 'NTAG213', 'frequency': '13.56 MHz', 'category': 'HF', 'nfc': True},
    'ntag215': {'name': 'NTAG215', 'frequency': '13.56 MHz', 'category': 'HF', 'nfc': True},
    'ntag216': {'name': 'NTAG216', 'frequency': '13.56 MHz', 'category': 'HF', 'nfc': True},
    'iclass': {'name': 'iCLASS', 'frequency': '13.56 MHz', 'category': 'HF'},
    'iso14443a': {'name': 'ISO 14443A', 'frequency': '13.56 MHz', 'category': 'HF'},
    'iso15693': {'name': 'ISO 15693', 'frequency': '13.56 MHz', 'category': 'HF'},
    'legic': {'name': 'LEGIC', 'frequency': '13.56 MHz', 'category': 'HF'},
}

MIFARE_DEFAULT_KEYS = [
    'FFFFFFFFFFFF', 'A0A1A2A3A4A5', 'D3F7D3F7D3F7',
    '000000000000', 'B0B1B2B3B4B5', '4D3A99C351DD',
    '1A982C7E459A', 'AABBCCDDEEFF', '714C5C886E97',
    '587EE5F9350F', 'A0478CC39091', '533CB6C723F6',
]


# ── RFID Manager ─────────────────────────────────────────────────────────────

class RFIDManager:
    """RFID/NFC tool management via Proxmark3 and nfc-tools."""

    def __init__(self):
        self.data_dir = os.path.join(get_data_dir(), 'rfid')
        os.makedirs(self.data_dir, exist_ok=True)
        self.dumps_dir = os.path.join(self.data_dir, 'dumps')
        os.makedirs(self.dumps_dir, exist_ok=True)

        # Tool discovery
        self.pm3_client = find_tool('pm3') or find_tool('proxmark3') or shutil.which('pm3') or shutil.which('proxmark3')
        self.nfc_list = shutil.which('nfc-list')
        self.nfc_poll = shutil.which('nfc-poll')
        self.nfc_mfclassic = shutil.which('nfc-mfclassic')

        self.cards: List[Dict] = []
        self.last_read: Optional[Dict] = None

    def get_tools_status(self) -> Dict:
        """Check available tools."""
        return {
            'proxmark3': self.pm3_client is not None,
            'nfc-list': self.nfc_list is not None,
            'nfc-mfclassic': self.nfc_mfclassic is not None,
            'card_types': len(CARD_TYPES),
            'saved_cards': len(self.cards)
        }

    # ── Proxmark3 Commands ───────────────────────────────────────────────

    def _pm3_cmd(self, command: str, timeout: int = 15) -> Dict:
        """Execute Proxmark3 command."""
        if not self.pm3_client:
            return {'ok': False, 'error': 'Proxmark3 client not found'}

        try:
            result = subprocess.run(
                [self.pm3_client, '-c', command],
                capture_output=True, text=True, timeout=timeout
            )
            return {
                'ok': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'ok': False, 'error': f'Command timed out: {command}'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Low Frequency (125 kHz) ──────────────────────────────────────────

    def lf_search(self) -> Dict:
        """Search for LF (125 kHz) cards."""
        result = self._pm3_cmd('lf search')
        if not result['ok']:
            return result

        output = result['stdout']
        card = {'frequency': '125 kHz', 'category': 'LF'}

        # Parse EM410x
        em_match = re.search(r'EM\s*410x.*?ID[:\s]*([A-Fa-f0-9]+)', output, re.I)
        if em_match:
            card['type'] = 'em410x'
            card['id'] = em_match.group(1)
            card['name'] = 'EM410x'

        # Parse HID
        hid_match = re.search(r'HID.*?Card.*?([A-Fa-f0-9]+)', output, re.I)
        if hid_match:
            card['type'] = 'hid_prox'
            card['id'] = hid_match.group(1)
            card['name'] = 'HID ProxCard'

        if 'id' in card:
            card['raw_output'] = output
            self.last_read = card
            return {'ok': True, 'card': card}

        return {'ok': False, 'error': 'No LF card found', 'raw': output}

    def lf_read_em410x(self) -> Dict:
        """Read EM410x card."""
        result = self._pm3_cmd('lf em 410x reader')
        if not result['ok']:
            return result

        match = re.search(r'EM\s*410x\s+ID[:\s]*([A-Fa-f0-9]+)', result['stdout'], re.I)
        if match:
            card = {
                'type': 'em410x', 'id': match.group(1),
                'name': 'EM410x', 'frequency': '125 kHz'
            }
            self.last_read = card
            return {'ok': True, 'card': card}
        return {'ok': False, 'error': 'Could not read EM410x', 'raw': result['stdout']}

    def lf_clone_em410x(self, card_id: str) -> Dict:
        """Clone EM410x ID to T5577 card."""
        result = self._pm3_cmd(f'lf em 410x clone --id {card_id}')
        return {
            'ok': 'written' in result.get('stdout', '').lower() or result['ok'],
            'message': f'Cloned EM410x ID {card_id}' if result['ok'] else result.get('error', ''),
            'raw': result.get('stdout', '')
        }

    def lf_sim_em410x(self, card_id: str) -> Dict:
        """Simulate EM410x card."""
        result = self._pm3_cmd(f'lf em 410x sim --id {card_id}', timeout=30)
        return {
            'ok': result['ok'],
            'message': f'Simulating EM410x ID {card_id}',
            'raw': result.get('stdout', '')
        }

    # ── High Frequency (13.56 MHz) ───────────────────────────────────────

    def hf_search(self) -> Dict:
        """Search for HF (13.56 MHz) cards."""
        result = self._pm3_cmd('hf search')
        if not result['ok']:
            return result

        output = result['stdout']
        card = {'frequency': '13.56 MHz', 'category': 'HF'}

        # Parse UID
        uid_match = re.search(r'UID[:\s]*([A-Fa-f0-9\s]+)', output, re.I)
        if uid_match:
            card['uid'] = uid_match.group(1).replace(' ', '').strip()

        # Parse ATQA/SAK
        atqa_match = re.search(r'ATQA[:\s]*([A-Fa-f0-9\s]+)', output, re.I)
        if atqa_match:
            card['atqa'] = atqa_match.group(1).strip()
        sak_match = re.search(r'SAK[:\s]*([A-Fa-f0-9]+)', output, re.I)
        if sak_match:
            card['sak'] = sak_match.group(1).strip()

        # Detect type
        if 'mifare classic 1k' in output.lower():
            card['type'] = 'mifare_classic_1k'
            card['name'] = 'MIFARE Classic 1K'
        elif 'mifare classic 4k' in output.lower():
            card['type'] = 'mifare_classic_4k'
            card['name'] = 'MIFARE Classic 4K'
        elif 'ultralight' in output.lower() or 'ntag' in output.lower():
            card['type'] = 'mifare_ultralight'
            card['name'] = 'MIFARE Ultralight/NTAG'
        elif 'desfire' in output.lower():
            card['type'] = 'mifare_desfire'
            card['name'] = 'MIFARE DESFire'
        elif 'iso14443' in output.lower():
            card['type'] = 'iso14443a'
            card['name'] = 'ISO 14443A'

        if 'uid' in card:
            card['raw_output'] = output
            self.last_read = card
            return {'ok': True, 'card': card}

        return {'ok': False, 'error': 'No HF card found', 'raw': output}

    def hf_dump_mifare(self, keys_file: str = None) -> Dict:
        """Dump MIFARE Classic card data."""
        cmd = 'hf mf autopwn'
        if keys_file:
            cmd += f' -f {keys_file}'

        result = self._pm3_cmd(cmd, timeout=120)
        if not result['ok']:
            return result

        output = result['stdout']

        # Look for dump file
        dump_match = re.search(r'saved.*?(\S+\.bin)', output, re.I)
        if dump_match:
            dump_file = dump_match.group(1)
            # Copy to our dumps directory
            dest = os.path.join(self.dumps_dir, Path(dump_file).name)
            if os.path.exists(dump_file):
                shutil.copy2(dump_file, dest)

            return {
                'ok': True,
                'dump_file': dest,
                'message': 'MIFARE dump complete',
                'raw': output
            }

        # Check for found keys
        keys = re.findall(r'key\s*[AB][:\s]*([A-Fa-f0-9]{12})', output, re.I)
        if keys:
            return {
                'ok': True,
                'keys_found': list(set(keys)),
                'message': f'Found {len(set(keys))} keys',
                'raw': output
            }

        return {'ok': False, 'error': 'Dump failed', 'raw': output}

    def hf_clone_mifare(self, dump_file: str) -> Dict:
        """Write MIFARE dump to blank card."""
        result = self._pm3_cmd(f'hf mf restore -f {dump_file}', timeout=60)
        return {
            'ok': 'restored' in result.get('stdout', '').lower() or result['ok'],
            'message': 'Card cloned' if result['ok'] else 'Clone failed',
            'raw': result.get('stdout', '')
        }

    # ── NFC Operations (via libnfc) ──────────────────────────────────────

    def nfc_scan(self) -> Dict:
        """Scan for NFC tags using libnfc."""
        if not self.nfc_list:
            return {'ok': False, 'error': 'nfc-list not found (install libnfc)'}

        try:
            result = subprocess.run(
                [self.nfc_list], capture_output=True, text=True, timeout=10
            )
            tags = []
            for line in result.stdout.splitlines():
                uid_match = re.search(r'UID.*?:\s*([A-Fa-f0-9\s:]+)', line, re.I)
                if uid_match:
                    tags.append({
                        'uid': uid_match.group(1).replace(' ', '').replace(':', ''),
                        'raw': line.strip()
                    })
            return {'ok': True, 'tags': tags, 'count': len(tags)}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    # ── Card Database ────────────────────────────────────────────────────

    def save_card(self, card: Dict, name: str = None) -> Dict:
        """Save card data to database."""
        card['saved_at'] = datetime.now(timezone.utc).isoformat()
        card['display_name'] = name or card.get('name', 'Unknown Card')
        # Remove raw output to save space
        card.pop('raw_output', None)
        self.cards.append(card)
        self._save_cards()
        return {'ok': True, 'count': len(self.cards)}

    def get_saved_cards(self) -> List[Dict]:
        """List saved cards."""
        return self.cards

    def delete_card(self, index: int) -> Dict:
        """Delete saved card by index."""
        if 0 <= index < len(self.cards):
            self.cards.pop(index)
            self._save_cards()
            return {'ok': True}
        return {'ok': False, 'error': 'Invalid index'}

    def _save_cards(self):
        cards_file = os.path.join(self.data_dir, 'cards.json')
        with open(cards_file, 'w') as f:
            json.dump(self.cards, f, indent=2)

    def _load_cards(self):
        cards_file = os.path.join(self.data_dir, 'cards.json')
        if os.path.exists(cards_file):
            try:
                with open(cards_file) as f:
                    self.cards = json.load(f)
            except Exception:
                pass

    def list_dumps(self) -> List[Dict]:
        """List saved card dumps."""
        dumps = []
        for f in Path(self.dumps_dir).iterdir():
            if f.is_file():
                dumps.append({
                    'name': f.name, 'path': str(f),
                    'size': f.stat().st_size,
                    'modified': datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat()
                })
        return dumps

    def get_default_keys(self) -> List[str]:
        """Return common MIFARE default keys."""
        return MIFARE_DEFAULT_KEYS

    def get_card_types(self) -> Dict:
        """Return supported card type info."""
        return CARD_TYPES


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None

def get_rfid_manager() -> RFIDManager:
    global _instance
    if _instance is None:
        _instance = RFIDManager()
        _instance._load_cards()
    return _instance


# ── CLI Interface ────────────────────────────────────────────────────────────

def run():
    """CLI entry point for RFID/NFC module."""
    mgr = get_rfid_manager()

    while True:
        tools = mgr.get_tools_status()
        print(f"\n{'='*60}")
        print(f"  RFID / NFC Tools")
        print(f"{'='*60}")
        print(f"  Proxmark3: {'OK' if tools['proxmark3'] else 'NOT FOUND'}")
        print(f"  libnfc: {'OK' if tools['nfc-list'] else 'NOT FOUND'}")
        print(f"  Saved cards: {tools['saved_cards']}")
        print()
        print("  1 — LF Search (125 kHz)")
        print("  2 — HF Search (13.56 MHz)")
        print("  3 — Read EM410x")
        print("  4 — Clone EM410x to T5577")
        print("  5 — Dump MIFARE Classic")
        print("  6 — Clone MIFARE from Dump")
        print("  7 — NFC Scan (libnfc)")
        print("  8 — Saved Cards")
        print("  9 — Card Dumps")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break
        elif choice == '1':
            result = mgr.lf_search()
            if result['ok']:
                c = result['card']
                print(f"    Found: {c.get('name', '?')}  ID: {c.get('id', '?')}")
            else:
                print(f"    {result.get('error', 'No card found')}")
        elif choice == '2':
            result = mgr.hf_search()
            if result['ok']:
                c = result['card']
                print(f"    Found: {c.get('name', '?')}  UID: {c.get('uid', '?')}")
            else:
                print(f"    {result.get('error', 'No card found')}")
        elif choice == '3':
            result = mgr.lf_read_em410x()
            if result['ok']:
                print(f"    EM410x ID: {result['card']['id']}")
                save = input("    Save card? (y/n): ").strip()
                if save.lower() == 'y':
                    mgr.save_card(result['card'])
            else:
                print(f"    {result['error']}")
        elif choice == '4':
            card_id = input("  EM410x ID to clone: ").strip()
            if card_id:
                result = mgr.lf_clone_em410x(card_id)
                print(f"    {result.get('message', result.get('error'))}")
        elif choice == '5':
            result = mgr.hf_dump_mifare()
            if result['ok']:
                print(f"    {result['message']}")
                if 'keys_found' in result:
                    for k in result['keys_found']:
                        print(f"      Key: {k}")
            else:
                print(f"    {result['error']}")
        elif choice == '6':
            dump = input("  Dump file path: ").strip()
            if dump:
                result = mgr.hf_clone_mifare(dump)
                print(f"    {result['message']}")
        elif choice == '7':
            result = mgr.nfc_scan()
            if result['ok']:
                print(f"    Found {result['count']} tags:")
                for t in result['tags']:
                    print(f"      UID: {t['uid']}")
            else:
                print(f"    {result['error']}")
        elif choice == '8':
            cards = mgr.get_saved_cards()
            for i, c in enumerate(cards):
                print(f"    [{i}] {c.get('display_name', '?')}  "
                      f"{c.get('type', '?')}  ID={c.get('id', c.get('uid', '?'))}")
        elif choice == '9':
            for d in mgr.list_dumps():
                print(f"    {d['name']}  ({d['size']} bytes)")
