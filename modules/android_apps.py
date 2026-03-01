"""
Android App Extraction - Pull APKs, app data, shared preferences
"""

DESCRIPTION = "Android app extraction (APK pull, app data, shared prefs)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "hardware"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidApps:
    """Interactive menu for Android app extraction."""

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
        print("  App Extraction")
        print(f"{'='*50}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] List Packages")
        print("  [2] Pull APK")
        print("  [3] Pull App Data (root/debuggable)")
        print("  [4] Extract Shared Prefs")
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def list_packages(self):
        if not self._ensure_device():
            return
        try:
            inc = input("  Include system apps? [y/N]: ").strip().lower() == 'y'
        except (EOFError, KeyboardInterrupt):
            return
        result = self.mgr.list_packages(self.serial, include_system=inc)
        if 'error' in result:
            print(f"  Error: {result['error']}")
            return
        print(f"\n  Found {result['count']} packages:")
        for pkg in result['packages']:
            flag = ' [SYS]' if pkg['is_system'] else ''
            print(f"    {pkg['package']}{flag}")
            print(f"      {pkg['path']}")

    def pull_apk(self):
        if not self._ensure_device():
            return
        try:
            package = input("  Package name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not package:
            return
        print(f"  Pulling APK for {package}...")
        result = self.mgr.pull_apk(self.serial, package)
        if result['success']:
            size_mb = result['size'] / (1024 * 1024)
            print(f"  Saved: {result['local_path']} ({size_mb:.1f} MB)")
        else:
            print(f"  Error: {result['error']}")

    def pull_app_data(self):
        if not self._ensure_device():
            return
        try:
            package = input("  Package name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not package:
            return
        print(f"  Pulling app data for {package}...")
        result = self.mgr.pull_app_data(self.serial, package)
        if result['success']:
            print(f"  Output dir: {result['output_dir']}")
            for f in result['files']:
                print(f"    {f}")
        else:
            print("  No data extracted (need debuggable app or root).")

    def extract_prefs(self):
        if not self._ensure_device():
            return
        try:
            package = input("  Package name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not package:
            return
        print(f"  Extracting shared prefs for {package}...")
        result = self.mgr.extract_shared_prefs(self.serial, package)
        if result['success']:
            print(f"  Found {result['count']} pref files:")
            for name, content in result['prefs'].items():
                print(f"\n  --- {name} ---")
                # Show first 20 lines
                lines = content.split('\n')[:20]
                for line in lines:
                    print(f"    {line}")
                if len(content.split('\n')) > 20:
                    print("    ...")
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
            elif choice == '1':
                self.list_packages()
            elif choice == '2':
                self.pull_apk()
            elif choice == '3':
                self.pull_app_data()
            elif choice == '4':
                self.extract_prefs()
            elif choice == 's':
                self._select_device()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidApps()
    m.run_interactive()
