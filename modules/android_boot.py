"""
Android Boot / Recovery Exploit - Bootloader unlock, flash, dm-verity
"""

DESCRIPTION = "Android boot/recovery exploits (flash, unlock, verity bypass)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidBoot:
    """Interactive menu for boot/recovery operations."""

    def __init__(self):
        from core.android_exploit import get_exploit_manager
        from core.hardware import get_hardware_manager
        self.mgr = get_exploit_manager()
        self.hw = get_hardware_manager()
        self.serial = None

    def _select_device(self):
        """Select from fastboot devices (boot ops need fastboot mostly)."""
        fb_devices = self.hw.fastboot_devices()
        adb_devices = self.hw.adb_devices()
        all_devs = []
        for d in fb_devices:
            all_devs.append({'serial': d['serial'], 'mode': 'fastboot'})
        for d in adb_devices:
            all_devs.append({'serial': d['serial'], 'mode': 'adb'})
        if not all_devs:
            print("  No devices found (ADB or fastboot).")
            return
        if len(all_devs) == 1:
            self.serial = all_devs[0]['serial']
            print(f"  Selected: {self.serial} ({all_devs[0]['mode']})")
            return
        print("\n  Select device:")
        for i, d in enumerate(all_devs, 1):
            print(f"    {i}) {d['serial']} [{d['mode']}]")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(all_devs):
                self.serial = all_devs[choice - 1]['serial']
        except (ValueError, EOFError, KeyboardInterrupt):
            pass

    def _ensure_device(self):
        if not self.serial:
            self._select_device()
        return self.serial is not None

    def show_menu(self):
        print(f"\n{'='*50}")
        print("  Boot / Recovery Exploit")
        print(f"{'='*50}")
        print("  !! WARNING: Can BRICK device / WIPE data !!")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] Bootloader Info")
        print("  [2] Backup Boot Image")
        print("  [3] Unlock Bootloader     [WIPES DATA]")
        print("  [4] Flash Custom Recovery")
        print("  [5] Flash Boot Image")
        print("  [6] Disable dm-verity/AVB")
        print("  [7] Temp Boot (no flash)")
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def bootloader_info(self):
        if not self._ensure_device():
            return
        print("  Querying bootloader...")
        info = self.mgr.get_bootloader_info(self.serial)
        if not info:
            print("  No info returned (device might not be in fastboot mode).")
            return
        print(f"\n  Bootloader Variables:")
        for k, v in info.items():
            print(f"    {k:<25} {v}")

    def backup_boot(self):
        if not self._ensure_device():
            return
        print("  Backing up boot image (requires root via ADB)...")
        result = self.mgr.backup_boot_image(self.serial)
        if result['success']:
            size_mb = result['size'] / (1024 * 1024)
            print(f"  Saved: {result['local_path']} ({size_mb:.1f} MB)")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def unlock_bootloader(self):
        if not self._ensure_device():
            return
        print("\n  !! WARNING: This will WIPE ALL DATA on the device !!")
        try:
            confirm = input("  Type 'YES' to proceed: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'YES':
            print("  Cancelled.")
            return
        print("  Unlocking bootloader...")
        result = self.mgr.unlock_bootloader(self.serial)
        if result['success']:
            print("  Bootloader unlocked (or confirmation pending on device).")
        else:
            print(f"  Result: {result.get('output', 'Unknown')}")

    def flash_recovery(self):
        if not self._ensure_device():
            return
        try:
            img = input("  Recovery image path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not img:
            return
        print("  Flashing recovery...")
        result = self.mgr.flash_recovery(self.serial, img)
        if result.get('success'):
            print(f"  Flash started (op: {result.get('op_id', '?')})")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def flash_boot(self):
        if not self._ensure_device():
            return
        try:
            img = input("  Boot image path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not img:
            return
        print("  Flashing boot...")
        result = self.mgr.flash_boot(self.serial, img)
        if result.get('success'):
            print(f"  Flash started (op: {result.get('op_id', '?')})")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def disable_verity(self):
        if not self._ensure_device():
            return
        try:
            vbmeta = input("  vbmeta image path (optional, Enter to skip): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            return
        print("  Disabling dm-verity/AVB...")
        result = self.mgr.disable_verity(self.serial, vbmeta)
        print(f"  Result: {result.get('output', 'Done')}")
        print(f"  Method: {result.get('method', '?')}")

    def temp_boot(self):
        if not self._ensure_device():
            return
        try:
            img = input("  Boot image path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not img:
            return
        print("  Temp-booting image (no permanent flash)...")
        result = self.mgr.boot_temp(self.serial, img)
        if result['success']:
            print("  Device booting from temporary image.")
        else:
            print(f"  Error: {result.get('output', 'Failed')}")

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
                '1': self.bootloader_info,
                '2': self.backup_boot,
                '3': self.unlock_bootloader,
                '4': self.flash_recovery,
                '5': self.flash_boot,
                '6': self.disable_verity,
                '7': self.temp_boot,
                's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidBoot()
    m.run_interactive()
