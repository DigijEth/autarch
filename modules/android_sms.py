"""
Android SMS/RCS Manipulation - Insert, delete, spoof messages with custom timestamps
"""

DESCRIPTION = "Android SMS/RCS manipulation (add, remove, spoof dates, RCS inject)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidSms:
    """Interactive menu for SMS/RCS manipulation."""

    def __init__(self):
        from core.android_exploit import get_exploit_manager
        from core.hardware import get_hardware_manager
        self.mgr = get_exploit_manager()
        self.hw = get_hardware_manager()
        self.serial = None

    def _select_device(self):
        devices = self.hw.adb_devices()
        if not devices:
            print("  No ADB devices connected.")
            return
        if len(devices) == 1:
            self.serial = devices[0]['serial']
            print(f"  Selected: {self.serial}")
            return
        print("\n  Select device:")
        for i, d in enumerate(devices, 1):
            model = d.get('model', '')
            print(f"    {i}) {d['serial']} {model}")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(devices):
                self.serial = devices[choice - 1]['serial']
        except (ValueError, EOFError, KeyboardInterrupt):
            pass

    def _ensure_device(self):
        if not self.serial:
            self._select_device()
        return self.serial is not None

    def show_menu(self):
        print(f"\n{'='*55}")
        print("  SMS / RCS Manipulation")
        print(f"{'='*55}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  ── SMS (content provider) ──")
        print("  [1] List SMS Messages")
        print("  [2] Insert SMS (spoofed)")
        print("  [3] Insert Batch SMS")
        print("  [4] Edit SMS")
        print("  [5] Delete SMS by ID")
        print("  [6] Delete SMS by Number")
        print("  [7] Delete ALL SMS")
        print()
        print("  ── RCS (Google Messages) ──       [ROOT]")
        print("  [8] Check RCS Support")
        print("  [9] List RCS Messages")
        print("  [a] Insert RCS Message (spoofed)")
        print("  [b] Delete RCS Message")
        print()
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def list_sms(self):
        if not self._ensure_device():
            return
        try:
            addr = input("  Filter by number (Enter for all): ").strip() or None
            limit = input("  Limit [50]: ").strip()
            limit = int(limit) if limit else 50
        except (EOFError, KeyboardInterrupt, ValueError):
            return
        result = self.mgr.sms_list(self.serial, limit=limit, address=addr)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} messages:")
        print(f"  {'ID':<6} {'Type':<8} {'Address':<16} {'Date':<20} Body")
        print(f"  {'-'*75}")
        for m in result['messages']:
            body = m.get('body', '')
            if len(body) > 40:
                body = body[:40] + '...'
            date = m.get('date_readable', m.get('date', '?'))
            print(f"  {m.get('_id','?'):<6} {m.get('type_label','?'):<8} {m.get('address','?'):<16} {date:<20} {body}")

    def insert_sms(self):
        if not self._ensure_device():
            return
        try:
            print("\n  Insert Spoofed SMS")
            print(f"  {'-'*40}")
            address = input("  Phone number: ").strip()
            if not address:
                return
            body = input("  Message body: ").strip()
            if not body:
                return
            print("  Type: 1=inbox (received), 2=sent, 3=draft")
            msg_type = input("  Type [inbox]: ").strip() or 'inbox'
            date = input("  Date (YYYY-MM-DD) [today]: ").strip() or None
            time_val = input("  Time (HH:MM:SS) [now]: ").strip() or None
            read = input("  Mark as read? [Y/n]: ").strip().lower() != 'n'
        except (EOFError, KeyboardInterrupt):
            return

        print("  Inserting...")
        result = self.mgr.sms_insert(self.serial, address, body,
                                     date_str=date, time_str=time_val,
                                     msg_type=msg_type, read=read)
        if result['success']:
            print(f"  SMS inserted:")
            print(f"    From/To: {result['address']}")
            print(f"    Date:    {result['date']}")
            print(f"    Type:    {result['type']}")
            print(f"    Body:    {result['body'][:60]}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def insert_batch(self):
        if not self._ensure_device():
            return
        print("\n  Batch SMS Insert")
        print("  Enter messages one per line. Format:")
        print("    number|body|YYYY-MM-DD|HH:MM:SS|type")
        print("  Type is inbox/sent. Date/time optional. Empty line to finish.")
        print()
        messages = []
        while True:
            try:
                line = input("  > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            parts = line.split('|')
            if len(parts) < 2:
                print("    Need at least: number|body")
                continue
            msg = {'address': parts[0].strip(), 'body': parts[1].strip()}
            if len(parts) >= 3 and parts[2].strip():
                msg['date'] = parts[2].strip()
            if len(parts) >= 4 and parts[3].strip():
                msg['time'] = parts[3].strip()
            if len(parts) >= 5 and parts[4].strip():
                msg['type'] = parts[4].strip()
            messages.append(msg)
            print(f"    Queued: {msg['address']} -> {msg['body'][:30]}")

        if not messages:
            print("  No messages to insert.")
            return

        print(f"\n  Inserting {len(messages)} messages...")
        result = self.mgr.sms_bulk_insert(self.serial, messages)
        print(f"  Done: {result['inserted']}/{result['total']} inserted successfully.")

    def edit_sms(self):
        if not self._ensure_device():
            return
        try:
            sms_id = input("  SMS _id to edit: ").strip()
            if not sms_id:
                return
            print("  Leave fields blank to keep current value.")
            body = input("  New body (or Enter to skip): ").strip() or None
            address = input("  New address (or Enter to skip): ").strip() or None
            date = input("  New date YYYY-MM-DD (or Enter): ").strip() or None
            time_val = input("  New time HH:MM:SS (or Enter): ").strip() or None
            msg_type = input("  New type inbox/sent (or Enter): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            return

        result = self.mgr.sms_update(self.serial, sms_id, body=body, address=address,
                                     date_str=date, time_str=time_val, msg_type=msg_type)
        if result['success']:
            print(f"  SMS {sms_id} updated.")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def delete_by_id(self):
        if not self._ensure_device():
            return
        try:
            sms_id = input("  SMS _id to delete: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not sms_id:
            return
        result = self.mgr.sms_delete(self.serial, sms_id=sms_id)
        if result['success']:
            print(f"  Deleted SMS #{sms_id}")
        else:
            print(f"  Error: {result.get('error', result.get('output', 'Failed'))}")

    def delete_by_number(self):
        if not self._ensure_device():
            return
        try:
            address = input("  Phone number to delete all messages from: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not address:
            return
        try:
            confirm = input(f"  Delete ALL SMS from {address}? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'y':
            print("  Cancelled.")
            return
        result = self.mgr.sms_delete(self.serial, address=address, delete_all_from=True)
        if result['success']:
            print(f"  Deleted all SMS from {address}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def delete_all(self):
        if not self._ensure_device():
            return
        try:
            confirm = input("  DELETE ALL SMS on device? Type 'YES': ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'YES':
            print("  Cancelled.")
            return
        result = self.mgr.sms_delete_all(self.serial)
        if result['success']:
            print("  All SMS deleted.")
        else:
            print(f"  Error: {result.get('output', 'Failed')}")

    def rcs_check(self):
        if not self._ensure_device():
            return
        print("  Checking RCS support...")
        info = self.mgr.rcs_check_support(self.serial)
        print(f"\n  RCS Available: {'YES' if info['rcs_available'] else 'NO'}")
        print(f"  Messaging App: {info.get('messaging_app', 'not found')}")
        print(f"  Database:      {info.get('database', 'not found (need root)')}")

    def rcs_list_msgs(self):
        if not self._ensure_device():
            return
        try:
            limit = input("  Limit [50]: ").strip()
            limit = int(limit) if limit else 50
        except (EOFError, KeyboardInterrupt, ValueError):
            return
        print("  Fetching RCS messages (requires root)...")
        result = self.mgr.rcs_list(self.serial, limit=limit)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} messages:")
        print(f"  {'ID':<6} {'Proto':<6} {'Date':<20} {'Conv':<20} Text")
        print(f"  {'-'*80}")
        for m in result['messages']:
            text = m.get('text', '')
            if len(text) > 35:
                text = text[:35] + '...'
            conv = m.get('conversation_name', '')[:18]
            print(f"  {m.get('message_id','?'):<6} {m.get('protocol','?'):<6} {m.get('timestamp_readable','?'):<20} {conv:<20} {text}")

    def rcs_insert_msg(self):
        if not self._ensure_device():
            return
        try:
            print("\n  Insert Spoofed RCS Message (requires root)")
            print(f"  {'-'*45}")
            address = input("  Phone number / contact: ").strip()
            if not address:
                return
            body = input("  Message body: ").strip()
            if not body:
                return
            sender = input("  Sender display name (or Enter for number): ").strip() or None
            direction = input("  Direction - incoming/outgoing [incoming]: ").strip().lower()
            is_out = direction.startswith('out')
            date = input("  Date (YYYY-MM-DD) [today]: ").strip() or None
            time_val = input("  Time (HH:MM:SS) [now]: ").strip() or None
        except (EOFError, KeyboardInterrupt):
            return

        print("  Injecting RCS message...")
        result = self.mgr.rcs_insert(self.serial, address, body,
                                     date_str=date, time_str=time_val,
                                     sender_name=sender, is_outgoing=is_out)
        if result['success']:
            print(f"  RCS message injected:")
            print(f"    Address:  {result['address']}")
            print(f"    Date:     {result['date']}")
            print(f"    Protocol: {result['protocol']}")
            print(f"    Dir:      {'outgoing' if result['is_outgoing'] else 'incoming'}")
            print(f"    Body:     {result['body'][:60]}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def rcs_delete_msg(self):
        if not self._ensure_device():
            return
        try:
            msg_id = input("  RCS message _id to delete: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not msg_id:
            return
        print("  Deleting RCS message (requires root)...")
        result = self.mgr.rcs_delete(self.serial, int(msg_id))
        if result['success']:
            print(f"  Deleted RCS message #{msg_id}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def run_interactive(self):
        while True:
            self.show_menu()
            try:
                choice = input("  Select > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == '0':
                break
            actions = {
                '1': self.list_sms,
                '2': self.insert_sms,
                '3': self.insert_batch,
                '4': self.edit_sms,
                '5': self.delete_by_id,
                '6': self.delete_by_number,
                '7': self.delete_all,
                '8': self.rcs_check,
                '9': self.rcs_list_msgs,
                'a': self.rcs_insert_msg,
                'b': self.rcs_delete_msg,
                's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidSms()
    m.run_interactive()
