"""
Android Root Methods - Root detection, Magisk install, exploit-based rooting
"""

DESCRIPTION = "Android root methods (Magisk, exploits, root detection)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidRoot:
    """Interactive menu for Android rooting operations."""

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
        print("  Root Methods")
        print(f"{'='*50}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] Check Root Status")
        print("  [2] Install Magisk APK")
        print("  [3] Pull Patched Boot Image")
        print("  [4] Root via Exploit")
        print("  [5] ADB Root Shell (debug builds)")
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def check_root(self):
        if not self._ensure_device():
            return
        print("  Checking root status...")
        result = self.mgr.check_root(self.serial)
        print(f"\n  Rooted: {'YES' if result['rooted'] else 'NO'}")
        if result['method']:
            print(f"  Method: {result['method']}")
        if result['version']:
            print(f"  Version: {result['version']}")
        details = result.get('details', {})
        if details:
            print(f"  Details:")
            for k, v in details.items():
                print(f"    {k}: {v}")

    def install_magisk(self):
        if not self._ensure_device():
            return
        try:
            apk = input("  Magisk APK path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not apk:
            return
        print("  Installing Magisk APK...")
        result = self.mgr.install_magisk(self.serial, apk)
        if result['success']:
            print("  Magisk installed successfully.")
            print("  Next: Open Magisk app, patch boot image, then flash patched boot.")
        else:
            print(f"  Error: {result.get('error', result.get('output', 'Failed'))}")

    def pull_patched(self):
        if not self._ensure_device():
            return
        print("  Looking for patched boot image...")
        result = self.mgr.pull_patched_boot(self.serial)
        if result['success']:
            size_mb = result['size'] / (1024 * 1024)
            print(f"  Saved: {result['local_path']} ({size_mb:.1f} MB)")
            print("  Next: Reboot to fastboot, flash this as boot partition.")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def root_exploit(self):
        if not self._ensure_device():
            return
        try:
            exploit = input("  Exploit binary path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not exploit:
            return
        print("  Deploying and executing exploit...")
        result = self.mgr.root_via_exploit(self.serial, exploit)
        if result['success']:
            print("  ROOT OBTAINED!")
        else:
            print("  Root not obtained.")
        print(f"  Exploit output:\n{result.get('exploit_output', '')}")

    def adb_root(self):
        if not self._ensure_device():
            return
        print("  Attempting adb root (userdebug/eng builds only)...")
        result = self.mgr.adb_root_shell(self.serial)
        if result['success']:
            print("  ADB running as root.")
        else:
            print(f"  Failed: {result['output']}")

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
                '1': self.check_root,
                '2': self.install_magisk,
                '3': self.pull_patched,
                '4': self.root_exploit,
                '5': self.adb_root,
                's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidRoot()
    m.run_interactive()
