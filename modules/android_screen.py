"""
Android Screen & Input Control - Screenshots, recording, input injection, keylogger
"""

DESCRIPTION = "Android screen capture, input injection, keylogger, camera/audio"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidScreen:
    """Interactive menu for screen/input/capture operations."""

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
            print(f"    {i}) {d['serial']} {d.get('model','')}")
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
        print("  Screen & Input Control")
        print(f"{'='*55}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  ── Capture ──")
        print("  [1]  Screenshot")
        print("  [2]  Screen Record")
        print("  [3]  Camera Photo")
        print("  [4]  Audio Record")
        print()
        print("  ── Input Injection ──")
        print("  [5]  Tap Coordinates")
        print("  [6]  Swipe")
        print("  [7]  Type Text")
        print("  [8]  Send Key Event")
        print("  [9]  Wake / Dismiss Lockscreen")
        print("  [10] Disable Lockscreen")
        print()
        print("  ── Keylogger ──")
        print("  [11] Start Keylogger")
        print("  [12] Stop & Pull Keylog")
        print()
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def screenshot(self):
        if not self._ensure_device(): return
        print("  Capturing screenshot...")
        r = self.mgr.screen_capture(self.serial)
        if r['success']:
            print(f"  Saved: {r['path']} ({r['size']} bytes)")
        else:
            print(f"  Error: {r.get('error')}")

    def screen_record(self):
        if not self._ensure_device(): return
        try:
            dur = input("  Duration in seconds [10]: ").strip()
            dur = int(dur) if dur else 10
        except (ValueError, EOFError, KeyboardInterrupt):
            return
        print(f"  Recording for {dur}s...")
        r = self.mgr.screen_record(self.serial, duration=dur)
        if r['success']:
            print(f"  Saved: {r['path']} ({r['size']} bytes)")
        else:
            print(f"  Error: {r.get('error')}")

    def camera(self):
        if not self._ensure_device(): return
        try:
            cam = input("  Camera [back/front]: ").strip() or 'back'
        except (EOFError, KeyboardInterrupt):
            return
        print("  Opening camera (device screen will activate)...")
        r = self.mgr.camera_capture(self.serial, camera=cam)
        if r['success']:
            print(f"  Photo saved: {r['path']}")
        else:
            print(f"  Note: {r.get('error')}")

    def audio(self):
        if not self._ensure_device(): return
        try:
            dur = input("  Duration in seconds [10]: ").strip()
            dur = int(dur) if dur else 10
        except (ValueError, EOFError, KeyboardInterrupt):
            return
        r = self.mgr.audio_record(self.serial, duration=dur)
        print(f"  {r.get('note', 'Started')}")

    def tap(self):
        if not self._ensure_device(): return
        try:
            x = int(input("  X coordinate: ").strip())
            y = int(input("  Y coordinate: ").strip())
        except (ValueError, EOFError, KeyboardInterrupt):
            return
        self.mgr.input_tap(self.serial, x, y)
        print(f"  Tapped ({x}, {y})")

    def swipe(self):
        if not self._ensure_device(): return
        try:
            x1 = int(input("  From X: ").strip())
            y1 = int(input("  From Y: ").strip())
            x2 = int(input("  To X: ").strip())
            y2 = int(input("  To Y: ").strip())
            ms = input("  Duration ms [300]: ").strip()
            ms = int(ms) if ms else 300
        except (ValueError, EOFError, KeyboardInterrupt):
            return
        self.mgr.input_swipe(self.serial, x1, y1, x2, y2, ms)
        print(f"  Swiped ({x1},{y1}) -> ({x2},{y2})")

    def type_text(self):
        if not self._ensure_device(): return
        try:
            text = input("  Text to type: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if text:
            self.mgr.input_text(self.serial, text)
            print(f"  Typed: {text[:50]}")

    def keyevent(self):
        if not self._ensure_device(): return
        print("  Common: 3=HOME 4=BACK 26=POWER 82=MENU 24/25=VOL 187=RECENTS 224=WAKEUP")
        try:
            code = input("  Keycode: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if code:
            self.mgr.input_keyevent(self.serial, code)
            print(f"  Sent keyevent {code}")

    def wake_dismiss(self):
        if not self._ensure_device(): return
        r = self.mgr.dismiss_lockscreen(self.serial)
        print(f"  Lock screen: {'still locked' if r['locked'] else 'dismissed'}")

    def disable_lock(self):
        if not self._ensure_device(): return
        r = self.mgr.disable_lockscreen(self.serial)
        print("  Attempted lock screen disable:")
        for x in r['results']:
            print(f"    {x['cmd']}: rc={x['rc']}")

    def start_keylog(self):
        if not self._ensure_device(): return
        r = self.mgr.start_keylogger(self.serial)
        print(f"  Keylogger started, PID: {r['pid']}, log: {r['log_path']}")

    def stop_keylog(self):
        if not self._ensure_device(): return
        r = self.mgr.stop_keylogger(self.serial)
        if r['success']:
            print(f"  Keylog saved: {r['path']} ({r['size']} bytes)")
        else:
            print(f"  {r.get('error')}")

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
                '1': self.screenshot, '2': self.screen_record,
                '3': self.camera, '4': self.audio,
                '5': self.tap, '6': self.swipe,
                '7': self.type_text, '8': self.keyevent,
                '9': self.wake_dismiss, '10': self.disable_lock,
                '11': self.start_keylog, '12': self.stop_keylog,
                's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidScreen()
    m.run_interactive()
