"""
Android Device Reconnaissance - Extract device data, accounts, messages, history
"""

DESCRIPTION = "Android device reconnaissance (data extraction, accounts, logs)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidRecon:
    """Interactive menu for Android device reconnaissance."""

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
        print(f"\n{'='*50}")
        print("  Device Reconnaissance")
        print(f"{'='*50}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] Full Device Dump")
        print("  [2] Installed Accounts")
        print("  [3] WiFi Passwords        [ROOT]")
        print("  [4] Call Logs")
        print("  [5] SMS Messages")
        print("  [6] Contacts")
        print("  [7] Browser History        [ROOT]")
        print("  [8] Saved Credentials      [ROOT]")
        print("  [9] Export Full Report")
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def device_dump(self):
        if not self._ensure_device():
            return
        print("  Running full device dump...")
        dump = self.mgr.full_device_dump(self.serial)
        print(f"\n  SELinux: {dump.get('selinux', 'unknown')}")
        print(f"  Kernel: {dump.get('kernel', 'unknown')}")
        print(f"  Fingerprint: {dump.get('fingerprint', 'unknown')}")
        print(f"  Packages: {dump.get('package_count', '?')}")
        info = dump.get('device_info', {})
        if info:
            print(f"\n  Device Info:")
            for k, v in info.items():
                print(f"    {k:<20} {v}")

    def accounts(self):
        if not self._ensure_device():
            return
        result = self.mgr.get_accounts(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} accounts:")
        for a in result['accounts']:
            print(f"    {a['name']} ({a['type']})")

    def wifi_passwords(self):
        if not self._ensure_device():
            return
        print("  Extracting WiFi passwords (requires root)...")
        result = self.mgr.get_wifi_passwords(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} saved networks:")
        for w in result['passwords']:
            print(f"    SSID: {w['ssid']}")
            print(f"    PSK:  {w['password']}")
            print()

    def call_logs(self):
        if not self._ensure_device():
            return
        result = self.mgr.extract_call_logs(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} call log entries:")
        print(f"  {'Number':<20} {'Type':<12} {'Duration'}")
        print(f"  {'-'*50}")
        for c in result['calls'][:50]:
            print(f"  {c.get('number','?'):<20} {c.get('type_label','?'):<12} {c.get('duration','?')}s")

    def sms_messages(self):
        if not self._ensure_device():
            return
        result = self.mgr.extract_sms(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} SMS messages:")
        for m in result['messages'][:30]:
            print(f"\n  [{m.get('type_label','?')}] {m.get('address','?')}")
            body = m.get('body', '')
            if len(body) > 100:
                body = body[:100] + '...'
            print(f"    {body}")

    def contacts(self):
        if not self._ensure_device():
            return
        result = self.mgr.extract_contacts(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} contacts:")
        print(f"  {'Name':<25} {'Number'}")
        print(f"  {'-'*45}")
        for c in result['contacts']:
            print(f"  {c.get('display_name','?'):<25} {c.get('number','?')}")

    def browser_history(self):
        if not self._ensure_device():
            return
        print("  Extracting browser history (requires root)...")
        result = self.mgr.extract_browser_history(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} history entries:")
        for h in result['history'][:30]:
            title = h.get('title', '')[:50]
            print(f"    {title}")
            print(f"      {h['url']}")

    def saved_credentials(self):
        if not self._ensure_device():
            return
        print("  Extracting saved credentials (requires root)...")
        result = self.mgr.extract_saved_credentials(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        print(f"\n  Found {result['count']} saved credentials:")
        for c in result['credentials']:
            print(f"    URL:  {c['url']}")
            print(f"    User: {c['username']}")
            print(f"    Pass: {'[encrypted]' if c['password_encrypted'] else '[empty]'}")
            print()

    def export_report(self):
        if not self._ensure_device():
            return
        print("  Generating full recon report...")
        result = self.mgr.export_recon_report(self.serial)
        if result['success']:
            print(f"  Report saved: {result['report_path']}")
            print(f"  Sections: {', '.join(result['sections'])}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def run_interactive(self):
        while True:
            self.show_menu()
            try:
                choice = input("  Select > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            actions = {
                '0': None,
                '1': self.device_dump,
                '2': self.accounts,
                '3': self.wifi_passwords,
                '4': self.call_logs,
                '5': self.sms_messages,
                '6': self.contacts,
                '7': self.browser_history,
                '8': self.saved_credentials,
                '9': self.export_report,
                's': self._select_device,
            }
            if choice == '0':
                break
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidRecon()
    m.run_interactive()
