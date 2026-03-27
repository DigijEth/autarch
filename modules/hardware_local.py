"""
Hardware Local - Physical device access (ADB/Fastboot/Serial)
Direct access to USB-connected devices on this machine.
"""

DESCRIPTION = "Physical device access (ADB/Fastboot/Serial)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "hardware"


class HardwareLocal:
    """Interactive hardware access menu."""

    def __init__(self):
        from core.hardware import get_hardware_manager
        self.mgr = get_hardware_manager()

    def show_menu(self):
        status = self.mgr.get_status()
        print(f"\n{'='*50}")
        print("  Hardware Access (Local)")
        print(f"{'='*50}")
        print(f"  ADB:      {'Available' if status['adb'] else 'Not found'}")
        print(f"  Fastboot: {'Available' if status['fastboot'] else 'Not found'}")
        print(f"  Serial:   {'Available' if status['serial'] else 'Not installed'}")
        print(f"  ESPTool:  {'Available' if status['esptool'] else 'Not installed'}")
        print()
        print("  1) List ADB Devices")
        print("  2) ADB Device Info")
        print("  3) ADB Shell")
        print("  4) ADB Sideload/Install")
        print("  5) List Fastboot Devices")
        print("  6) Fastboot Device Info")
        print("  7) Fastboot Flash Partition")
        print("  8) List Serial Ports")
        print("  9) Detect ESP Chip")
        print(" 10) Flash ESP32 Firmware")
        print("  0) Back")
        print()

    def _pick_device(self, devices, label="device"):
        if not devices:
            print(f"  No {label}s found.")
            return None
        if len(devices) == 1:
            return devices[0]['serial']
        print(f"\n  Select {label}:")
        for i, d in enumerate(devices, 1):
            extra = d.get('model', '') or d.get('state', '')
            print(f"    {i}) {d['serial']} {extra}")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(devices):
                return devices[choice - 1]['serial']
        except (ValueError, EOFError):
            pass
        return None

    def list_adb_devices(self):
        devices = self.mgr.adb_devices()
        if not devices:
            print("  No ADB devices connected.")
            return
        print(f"\n  {'Serial':<20} {'State':<12} {'Model':<15} {'Product'}")
        print(f"  {'-'*60}")
        for d in devices:
            print(f"  {d['serial']:<20} {d['state']:<12} {d.get('model',''):<15} {d.get('product','')}")

    def adb_device_info(self):
        devices = self.mgr.adb_devices()
        serial = self._pick_device(devices, "ADB device")
        if not serial:
            return
        info = self.mgr.adb_device_info(serial)
        print(f"\n  Device Info: {serial}")
        print(f"  {'-'*40}")
        for k, v in info.items():
            print(f"  {k:<20} {v}")

    def adb_shell(self):
        devices = self.mgr.adb_devices()
        serial = self._pick_device(devices, "ADB device")
        if not serial:
            return
        print(f"  ADB Shell ({serial}) - type 'exit' to quit")
        while True:
            try:
                cmd = input(f"  {serial}$ ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if cmd.lower() in ('exit', 'quit', ''):
                break
            result = self.mgr.adb_shell(serial, cmd)
            if result['output']:
                print(result['output'])

    def adb_sideload(self):
        devices = self.mgr.adb_devices()
        serial = self._pick_device(devices, "ADB device")
        if not serial:
            return
        try:
            filepath = input("  File path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not filepath:
            return
        result = self.mgr.adb_sideload(serial, filepath)
        if result.get('success'):
            print(f"  Sideload started (op: {result['op_id']})")
            # Poll progress
            import time
            while True:
                time.sleep(1)
                prog = self.mgr.get_operation_progress(result['op_id'])
                print(f"  [{prog.get('progress', 0)}%] {prog.get('message', '')}", end='\r')
                if prog.get('status') in ('done', 'error'):
                    print()
                    break
        else:
            print(f"  Error: {result.get('error', 'Unknown error')}")

    def list_fastboot_devices(self):
        devices = self.mgr.fastboot_devices()
        if not devices:
            print("  No Fastboot devices connected.")
            return
        print(f"\n  {'Serial':<25} {'State'}")
        print(f"  {'-'*35}")
        for d in devices:
            print(f"  {d['serial']:<25} {d['state']}")

    def fastboot_device_info(self):
        devices = self.mgr.fastboot_devices()
        serial = self._pick_device(devices, "Fastboot device")
        if not serial:
            return
        info = self.mgr.fastboot_device_info(serial)
        print(f"\n  Fastboot Info: {serial}")
        print(f"  {'-'*40}")
        for k, v in info.items():
            print(f"  {k:<20} {v}")

    def fastboot_flash(self):
        devices = self.mgr.fastboot_devices()
        serial = self._pick_device(devices, "Fastboot device")
        if not serial:
            return
        try:
            partition = input("  Partition (boot/recovery/system/vendor): ").strip()
            filepath = input("  Firmware path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not partition or not filepath:
            return
        result = self.mgr.fastboot_flash(serial, partition, filepath)
        if result.get('success'):
            print(f"  Flash started (op: {result['op_id']})")
            import time
            while True:
                time.sleep(1)
                prog = self.mgr.get_operation_progress(result['op_id'])
                print(f"  [{prog.get('progress', 0)}%] {prog.get('message', '')}", end='\r')
                if prog.get('status') in ('done', 'error'):
                    print()
                    break
        else:
            print(f"  Error: {result.get('error', 'Unknown error')}")

    def list_serial_ports(self):
        ports = self.mgr.list_serial_ports()
        if not ports:
            print("  No serial ports found.")
            return
        print(f"\n  {'Port':<20} {'Description':<30} {'VID:PID'}")
        print(f"  {'-'*60}")
        for p in ports:
            vid_pid = f"{p['vid']}:{p['pid']}" if p['vid'] else ''
            print(f"  {p['port']:<20} {p['desc']:<30} {vid_pid}")

    def detect_esp(self):
        ports = self.mgr.list_serial_ports()
        if not ports:
            print("  No serial ports found.")
            return
        print("  Select port:")
        for i, p in enumerate(ports, 1):
            print(f"    {i}) {p['port']} - {p['desc']}")
        try:
            choice = int(input("  > ").strip())
            port = ports[choice - 1]['port']
        except (ValueError, IndexError, EOFError):
            return
        result = self.mgr.detect_esp_chip(port)
        if result.get('success'):
            print(f"  Chip: {result['chip']}")
            print(f"  ID: {result.get('chip_id', 'N/A')}")
        else:
            print(f"  Error: {result.get('error', 'Detection failed')}")

    def flash_esp(self):
        ports = self.mgr.list_serial_ports()
        if not ports:
            print("  No serial ports found.")
            return
        print("  Select port:")
        for i, p in enumerate(ports, 1):
            print(f"    {i}) {p['port']} - {p['desc']}")
        try:
            choice = int(input("  > ").strip())
            port = ports[choice - 1]['port']
            firmware = input("  Firmware path: ").strip()
        except (ValueError, IndexError, EOFError):
            return
        if not firmware:
            return
        result = self.mgr.flash_esp(port, firmware)
        if result.get('success'):
            print(f"  Flash started (op: {result['op_id']})")
            import time
            while True:
                time.sleep(1)
                prog = self.mgr.get_operation_progress(result['op_id'])
                print(f"  [{prog.get('progress', 0)}%] {prog.get('message', '')}", end='\r')
                if prog.get('status') in ('done', 'error'):
                    print()
                    break
        else:
            print(f"  Error: {result.get('error', 'Flash failed')}")

    def run_interactive(self):
        while True:
            self.show_menu()
            try:
                choice = input("  Select > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == '0':
                break
            actions = {
                '1': self.list_adb_devices,
                '2': self.adb_device_info,
                '3': self.adb_shell,
                '4': self.adb_sideload,
                '5': self.list_fastboot_devices,
                '6': self.fastboot_device_info,
                '7': self.fastboot_flash,
                '8': self.list_serial_ports,
                '9': self.detect_esp,
                '10': self.flash_esp,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    hw = HardwareLocal()
    hw.run_interactive()
