"""
Android Advanced Exploits - Network, app manipulation, system control, data exfil
"""

DESCRIPTION = "Android advanced exploits (network, apps, system, data extraction)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class AndroidAdvanced:
    """Interactive menu for advanced Android exploits."""

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
        print(f"\n{'='*60}")
        print("  Advanced Android Exploits")
        print(f"{'='*60}")
        print(f"  Device: {self.serial or '(none)'}")
        print()
        print("  ── Data Exfiltration ──")
        print("  [1]  Clipboard Content")
        print("  [2]  Notifications")
        print("  [3]  Location Data")
        print("  [4]  List Media Files")
        print("  [5]  Pull Media Folder")
        print("  [6]  WhatsApp DB              [ROOT]")
        print("  [7]  Telegram DB              [ROOT]")
        print("  [8]  Signal DB                [ROOT]")
        print("  [9]  Dump Settings (all)")
        print("  [10] Device Fingerprint")
        print("  [11] Dump Any Database        [ROOT]")
        print()
        print("  ── Network ──")
        print("  [20] Network Info")
        print("  [21] Set Proxy (MITM)")
        print("  [22] Clear Proxy")
        print("  [23] Set DNS                  [ROOT]")
        print("  [24] WiFi Scan")
        print("  [25] WiFi Connect")
        print("  [26] WiFi On/Off")
        print("  [27] Enable Hotspot")
        print("  [28] Capture Traffic          [ROOT]")
        print("  [29] Port Forward")
        print("  [30] ADB over WiFi")
        print()
        print("  ── App Manipulation ──")
        print("  [40] Grant Permission")
        print("  [41] Revoke Permission")
        print("  [42] List App Permissions")
        print("  [43] Disable App")
        print("  [44] Enable App")
        print("  [45] Clear App Data")
        print("  [46] Force Stop App")
        print("  [47] Launch App")
        print("  [48] Launch Activity")
        print("  [49] Send Broadcast")
        print("  [50] Content Query")
        print("  [51] Enable Overlay")
        print()
        print("  ── System ──")
        print("  [60] SELinux Permissive       [ROOT]")
        print("  [61] Remount /system RW       [ROOT]")
        print("  [62] Logcat Sensitive Data")
        print("  [63] Deploy Frida Server      [ROOT]")
        print("  [64] Running Processes")
        print("  [65] Open Ports")
        print("  [66] Modify Setting")
        print()
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def _print_result(self, r):
        import json
        if isinstance(r, dict):
            for k, v in r.items():
                if isinstance(v, (list, dict)) and len(str(v)) > 200:
                    print(f"    {k}: [{len(v)} items]" if isinstance(v, list) else f"    {k}: [dict]")
                else:
                    val = str(v)
                    if len(val) > 120:
                        val = val[:120] + '...'
                    print(f"    {k}: {val}")

    def run_interactive(self):
        while True:
            self.show_menu()
            try:
                choice = input("  Select > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == '0':
                break
            elif choice == 's':
                self._select_device()
                continue

            if not self._ensure_device():
                continue

            try:
                self._dispatch(choice)
            except (EOFError, KeyboardInterrupt):
                continue

    def _dispatch(self, choice):
        s = self.serial
        m = self.mgr
        # Data Exfil
        if choice == '1':
            self._print_result(m.extract_clipboard(s))
        elif choice == '2':
            r = m.dump_notifications(s)
            print(f"  {r.get('count', 0)} notifications:")
            for n in r.get('notifications', [])[:20]:
                print(f"    [{n.get('package','')}] {n.get('title','')} - {n.get('text','')}")
        elif choice == '3':
            self._print_result(m.extract_location(s))
        elif choice == '4':
            t = input("  Type (photos/downloads/screenshots/whatsapp_media): ").strip() or 'photos'
            r = m.extract_media_list(s, media_type=t)
            print(f"  {r['count']} files in {r['path']}:")
            for f in r['files'][:30]:
                print(f"    {f}")
        elif choice == '5':
            t = input("  Type (photos/downloads/screenshots): ").strip() or 'photos'
            lim = input("  Limit [50]: ").strip()
            r = m.pull_media_folder(s, media_type=t, limit=int(lim) if lim else 50)
            print(f"  Pulled {r['count']} files to {r.get('output_dir','')}")
        elif choice == '6':
            r = m.extract_whatsapp_db(s)
            self._print_result(r)
        elif choice == '7':
            r = m.extract_telegram_db(s)
            self._print_result(r)
        elif choice == '8':
            r = m.extract_signal_db(s)
            self._print_result(r)
        elif choice == '9':
            r = m.dump_all_settings(s)
            for ns, entries in r.get('settings', {}).items():
                print(f"\n  [{ns}] ({len(entries)} entries)")
                for k, v in list(entries.items())[:10]:
                    print(f"    {k}={v}")
                if len(entries) > 10:
                    print(f"    ... and {len(entries)-10} more")
        elif choice == '10':
            fp = m.get_device_fingerprint(s)
            print("\n  Device Fingerprint:")
            for k, v in fp.items():
                print(f"    {k:<25} {v}")
        elif choice == '11':
            db_path = input("  Database path on device: ").strip()
            table = input("  Table name (or Enter to list tables): ").strip() or None
            r = m.dump_database(s, db_path, table=table)
            if r['success']:
                print(f"  Tables: {', '.join(r['tables'])}")
                if r['rows']:
                    for row in r['rows'][:10]:
                        print(f"    {row}")
            else:
                print(f"  Error: {r['error']}")
        # Network
        elif choice == '20':
            info = m.get_network_info(s)
            for k, v in info.items():
                val = str(v)[:200]
                print(f"  {k}: {val}")
        elif choice == '21':
            host = input("  Proxy host: ").strip()
            port = input("  Proxy port: ").strip()
            if host and port:
                r = m.set_proxy(s, host, port)
                print(f"  Proxy set: {r.get('proxy')}")
        elif choice == '22':
            m.clear_proxy(s)
            print("  Proxy cleared.")
        elif choice == '23':
            dns1 = input("  DNS1: ").strip()
            dns2 = input("  DNS2 (optional): ").strip()
            if dns1:
                m.set_dns(s, dns1, dns2)
                print(f"  DNS set: {dns1} {dns2}")
        elif choice == '24':
            r = m.wifi_scan(s)
            print(r.get('output', 'No results'))
        elif choice == '25':
            ssid = input("  SSID: ").strip()
            pwd = input("  Password (Enter for open): ").strip()
            if ssid:
                r = m.wifi_connect(s, ssid, pwd)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '26':
            action = input("  Enable or disable? [e/d]: ").strip().lower()
            if action == 'd':
                m.wifi_disconnect(s)
                print("  WiFi disabled.")
            else:
                m.wifi_enable(s)
                print("  WiFi enabled.")
        elif choice == '27':
            ssid = input("  Hotspot SSID [AUTARCH_AP]: ").strip() or 'AUTARCH_AP'
            pwd = input("  Password [autarch123]: ").strip() or 'autarch123'
            r = m.enable_hotspot(s, ssid, pwd)
            print(f"  Hotspot: {ssid}")
        elif choice == '28':
            iface = input("  Interface [any]: ").strip() or 'any'
            dur = input("  Duration seconds [30]: ").strip()
            filt = input("  Filter (optional): ").strip()
            r = m.capture_traffic(s, iface, int(dur) if dur else 30, filt)
            if r['success']:
                print(f"  PCAP saved: {r['path']} ({r['size']} bytes)")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '29':
            lp = input("  Local port: ").strip()
            rp = input("  Remote port: ").strip()
            if lp and rp:
                r = m.port_forward(s, lp, rp)
                print(f"  Forward: localhost:{lp} -> device:{rp}")
        elif choice == '30':
            port = input("  Port [5555]: ").strip() or '5555'
            r = m.enable_adb_wifi(s, int(port))
            print(f"  ADB WiFi: {r.get('connect_cmd', '?')}")
        # App Manipulation
        elif choice == '40':
            pkg = input("  Package: ").strip()
            perm = input("  Permission (e.g. android.permission.CAMERA): ").strip()
            if pkg and perm:
                r = m.grant_permission(s, pkg, perm)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '41':
            pkg = input("  Package: ").strip()
            perm = input("  Permission: ").strip()
            if pkg and perm:
                r = m.revoke_permission(s, pkg, perm)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '42':
            pkg = input("  Package: ").strip()
            if pkg:
                r = m.list_permissions(s, pkg)
                print(f"  Granted ({len(r['granted'])}):")
                for p in r['granted'][:20]:
                    print(f"    + {p}")
                print(f"  Denied ({len(r['denied'])}):")
                for p in r['denied'][:10]:
                    print(f"    - {p}")
        elif choice == '43':
            pkg = input("  Package to disable: ").strip()
            if pkg:
                r = m.disable_app(s, pkg)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '44':
            pkg = input("  Package to enable: ").strip()
            if pkg:
                r = m.enable_app(s, pkg)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '45':
            pkg = input("  Package to clear: ").strip()
            if pkg:
                confirm = input(f"  Clear ALL data for {pkg}? [y/N]: ").strip().lower()
                if confirm == 'y':
                    r = m.clear_app_data(s, pkg)
                    print(f"  {r.get('output', 'Done')}")
        elif choice == '46':
            pkg = input("  Package to force stop: ").strip()
            if pkg:
                m.force_stop_app(s, pkg)
                print(f"  Force stopped {pkg}")
        elif choice == '47':
            pkg = input("  Package to launch: ").strip()
            if pkg:
                m.launch_app(s, pkg)
                print(f"  Launched {pkg}")
        elif choice == '48':
            comp = input("  Component (com.pkg/.Activity): ").strip()
            extras = input("  Extras (optional am flags): ").strip()
            if comp:
                r = m.launch_activity(s, comp, extras)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '49':
            action = input("  Broadcast action: ").strip()
            extras = input("  Extras (optional): ").strip()
            if action:
                r = m.send_broadcast(s, action, extras)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '50':
            uri = input("  Content URI: ").strip()
            proj = input("  Projection (col1:col2 or Enter): ").strip()
            where = input("  Where clause (or Enter): ").strip()
            if uri:
                r = m.content_query(s, uri, proj, where)
                print(f"  {r['count']} rows:")
                for row in r['rows'][:20]:
                    print(f"    {row}")
        elif choice == '51':
            pkg = input("  Package for overlay: ").strip()
            if pkg:
                m.overlay_attack_enable(s, pkg)
                print(f"  Overlay enabled for {pkg}")
        # System
        elif choice == '60':
            r = m.set_selinux(s, 'permissive')
            print(f"  SELinux: {r.get('mode', '?')}")
        elif choice == '61':
            r = m.remount_system(s)
            print(f"  /system remounted {r.get('mode')}: {r.get('output','')}")
        elif choice == '62':
            dur = input("  Scan duration [10]: ").strip()
            r = m.logcat_sensitive(s, int(dur) if dur else 10)
            print(f"  Found {r['count']} sensitive lines:")
            for line in r['lines'][:20]:
                print(f"    {line[:120]}")
        elif choice == '63':
            path = input("  Frida server binary path: ").strip()
            if path:
                r = m.deploy_frida(s, path)
                if r['success']:
                    print(f"  Frida running, PID: {r['pid']}")
                else:
                    print(f"  Error: {r.get('error')}")
        elif choice == '64':
            r = m.get_running_processes(s)
            print(f"  {r['count']} processes:")
            for p in r['processes'][:30]:
                print(f"    {p.get('pid','?'):>6} {p.get('user',''):>12} {p.get('name','')}")
        elif choice == '65':
            r = m.get_open_ports(s)
            print(f"  {r['count']} listening ports:")
            for p in r['ports']:
                print(f"    {p}")
        elif choice == '66':
            ns = input("  Namespace (system/secure/global): ").strip()
            key = input("  Key: ").strip()
            val = input("  Value: ").strip()
            if ns and key and val:
                r = m.modify_setting(s, ns, key, val)
                print(f"  {ns}.{key} = {r.get('value','?')}")
        else:
            print("  Invalid choice.")


def run():
    m = AndroidAdvanced()
    m.run_interactive()
