"""
iPhone Local USB - Device access via libimobiledevice
"""

DESCRIPTION = "iPhone USB exploitation (info, backup, extract, apps, profiles)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "hardware"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class IPhoneLocal:
    """Interactive menu for iPhone USB device access."""

    def __init__(self):
        from core.iphone_exploit import get_iphone_manager
        self.mgr = get_iphone_manager()
        self.udid = None

    def _select_device(self):
        devices = self.mgr.list_devices()
        if not devices:
            print("  No iOS devices connected.")
            return
        if len(devices) == 1:
            self.udid = devices[0]['udid']
            print(f"  Selected: {devices[0].get('name','')} ({self.udid[:12]}...)")
            return
        print("\n  Select device:")
        for i, d in enumerate(devices, 1):
            print(f"    {i}) {d.get('name','')} - {d.get('model','')} iOS {d.get('ios_version','')} [{d['udid'][:12]}...]")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(devices):
                self.udid = devices[choice - 1]['udid']
        except (ValueError, EOFError, KeyboardInterrupt):
            pass

    def _ensure_device(self):
        if not self.udid:
            self._select_device()
        return self.udid is not None

    def show_menu(self):
        status = self.mgr.get_status()
        print(f"\n{'='*60}")
        print("  iPhone USB Exploitation")
        print(f"{'='*60}")
        print(f"  Tools: {status['found']}/{status['total']} available")
        print(f"  Device: {self.udid[:16] + '...' if self.udid else '(none)'}")
        print()
        print("  ── Device ──")
        print("  [1]  List Devices")
        print("  [2]  Device Info")
        print("  [3]  Full Fingerprint")
        print("  [4]  Pair / Validate")
        print("  [5]  Get/Set Device Name")
        print("  [6]  Restart / Shutdown / Sleep")
        print()
        print("  ── Capture ──")
        print("  [10] Screenshot")
        print("  [11] Syslog Dump")
        print("  [12] Syslog Grep (sensitive)")
        print("  [13] Crash Reports")
        print()
        print("  ── Apps ──")
        print("  [20] List Apps")
        print("  [21] Install IPA")
        print("  [22] Uninstall App")
        print()
        print("  ── Backup & Extraction ──")
        print("  [30] Create Backup")
        print("  [31] List Backups")
        print("  [32] Extract SMS/iMessage")
        print("  [33] Extract Contacts")
        print("  [34] Extract Call Log")
        print("  [35] Extract Notes")
        print("  [36] Browse Backup Files")
        print("  [37] Extract Backup File")
        print()
        print("  ── Filesystem & Profiles ──")
        print("  [40] Mount Filesystem (ifuse)")
        print("  [41] Mount App Documents")
        print("  [42] Unmount")
        print("  [43] List Profiles")
        print("  [44] Install Profile")
        print("  [45] Remove Profile")
        print()
        print("  ── Network ──")
        print("  [50] Port Forward (iproxy)")
        print("  [51] Export Recon Report")
        print()
        print("  [s] Select Device")
        print("  [0] Back")
        print()

    def _pick_backup(self):
        backups = self.mgr.list_backups()
        if not backups['backups']:
            print("  No backups found. Create one first.")
            return None
        print("\n  Available backups:")
        for i, b in enumerate(backups['backups'], 1):
            name = b.get('device_name', b['udid'][:12])
            size = b.get('size_mb', 0)
            print(f"    {i}) {name} - {b.get('ios_version','')} ({size:.0f} MB)")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(backups['backups']):
                return backups['backups'][choice - 1]['path']
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        return None

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

            try:
                self._dispatch(choice)
            except (EOFError, KeyboardInterrupt):
                continue

    def _dispatch(self, choice):
        m = self.mgr
        # Device
        if choice == '1':
            devices = m.list_devices()
            if not devices:
                print("  No iOS devices connected.")
            else:
                print(f"\n  {'UDID':<42} {'Name':<20} {'Model':<15} iOS")
                print(f"  {'-'*85}")
                for d in devices:
                    print(f"  {d['udid']:<42} {d.get('name',''):<20} {d.get('model',''):<15} {d.get('ios_version','')}")
        elif choice == '2':
            if not self._ensure_device(): return
            info = m.device_info(self.udid)
            if 'error' in info:
                print(f"  Error: {info['error']}")
            else:
                for k, v in list(info.items())[:40]:
                    print(f"    {k:<35} {v}")
                if len(info) > 40:
                    print(f"    ... and {len(info)-40} more fields")
        elif choice == '3':
            if not self._ensure_device(): return
            fp = m.full_fingerprint(self.udid)
            for k, v in list(fp.items())[:50]:
                if isinstance(v, dict):
                    print(f"    {k}:")
                    for sk, sv in list(v.items())[:10]:
                        print(f"      {sk}: {sv}")
                else:
                    print(f"    {k:<35} {v}")
        elif choice == '4':
            if not self._ensure_device(): return
            action = input("  [p]air / [v]alidate / [u]npair? ").strip().lower()
            if action == 'p':
                r = m.pair_device(self.udid)
            elif action == 'u':
                r = m.unpair_device(self.udid)
            else:
                r = m.validate_pair(self.udid)
            print(f"  {r.get('output', r)}")
        elif choice == '5':
            if not self._ensure_device(): return
            r = m.get_name(self.udid)
            print(f"  Current name: {r['name']}")
            new = input("  New name (Enter to keep): ").strip()
            if new:
                m.set_name(self.udid, new)
                print(f"  Name set to: {new}")
        elif choice == '6':
            if not self._ensure_device(): return
            action = input("  [r]estart / [s]hutdown / s[l]eep? ").strip().lower()
            if action == 'r':
                r = m.restart_device(self.udid)
            elif action == 's':
                r = m.shutdown_device(self.udid)
            elif action == 'l':
                r = m.sleep_device(self.udid)
            else:
                print("  Invalid."); return
            print(f"  {r.get('output', 'Done')}")
        # Capture
        elif choice == '10':
            if not self._ensure_device(): return
            r = m.screenshot(self.udid)
            if r['success']:
                print(f"  Screenshot: {r['path']} ({r['size']} bytes)")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '11':
            if not self._ensure_device(): return
            dur = input("  Duration [5]: ").strip()
            r = m.syslog_dump(self.udid, duration=int(dur) if dur else 5)
            if r['success']:
                print(f"  Syslog: {r['path']} ({r['lines']} lines)")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '12':
            if not self._ensure_device(): return
            pattern = input("  Grep pattern [password|token|key]: ").strip() or 'password|token|key|secret'
            dur = input("  Duration [5]: ").strip()
            r = m.syslog_grep(self.udid, pattern, duration=int(dur) if dur else 5)
            print(f"  {r['count']} matches:")
            for line in r.get('matches', [])[:20]:
                print(f"    {line[:120]}")
        elif choice == '13':
            if not self._ensure_device(): return
            r = m.crash_reports(self.udid)
            if r['success']:
                print(f"  {r['count']} crash reports in {r['output_dir']}")
            else:
                print(f"  Error: {r['error']}")
        # Apps
        elif choice == '20':
            if not self._ensure_device(): return
            t = input("  Type [user/system/all]: ").strip() or 'user'
            r = m.list_apps(self.udid, app_type=t)
            if r['success']:
                print(f"  {r['count']} apps:")
                for a in r['apps']:
                    print(f"    {a.get('bundle_id',''):<40} {a.get('name','')}")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '21':
            if not self._ensure_device(): return
            path = input("  IPA path: ").strip()
            if path:
                r = m.install_app(self.udid, path)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '22':
            if not self._ensure_device(): return
            bid = input("  Bundle ID to remove: ").strip()
            if bid:
                r = m.uninstall_app(self.udid, bid)
                print(f"  {r.get('output', 'Done')}")
        # Backup
        elif choice == '30':
            if not self._ensure_device(): return
            enc = input("  Encrypted backup? [y/N]: ").strip().lower() == 'y'
            pwd = ''
            if enc:
                pwd = input("  Backup password: ").strip()
            print("  Creating backup (this may take several minutes)...")
            r = m.create_backup(self.udid, encrypted=enc, password=pwd)
            if r['success']:
                print(f"  Backup saved: {r['backup_path']}")
            else:
                print(f"  Error: {r.get('output', 'Failed')}")
        elif choice == '31':
            r = m.list_backups()
            print(f"  {r['count']} backups:")
            for b in r['backups']:
                name = b.get('device_name', b['udid'][:12])
                print(f"    {name} - iOS {b.get('ios_version','')} - {b.get('size_mb',0):.0f}MB - {b.get('date','')}")
        elif choice == '32':
            bp = self._pick_backup()
            if bp:
                r = m.extract_backup_sms(bp)
                if r['success']:
                    print(f"  {r['count']} messages:")
                    for msg in r['messages'][:20]:
                        d = 'ME' if msg['is_from_me'] else msg['handle']
                        print(f"    [{msg['date']}] {d}: {msg['text'][:60]}")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '33':
            bp = self._pick_backup()
            if bp:
                r = m.extract_backup_contacts(bp)
                if r['success']:
                    print(f"  {r['count']} contacts:")
                    for c in r['contacts'][:30]:
                        print(f"    {c['first']} {c['last']} {c.get('organization','')} - {', '.join(c['values'][:3])}")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '34':
            bp = self._pick_backup()
            if bp:
                r = m.extract_backup_call_log(bp)
                if r['success']:
                    print(f"  {r['count']} calls:")
                    for c in r['calls'][:20]:
                        print(f"    [{c['date']}] {c['type']:<10} {c['address']} ({c['duration']}s)")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '35':
            bp = self._pick_backup()
            if bp:
                r = m.extract_backup_notes(bp)
                if r['success']:
                    print(f"  {r['count']} notes:")
                    for n in r['notes'][:15]:
                        print(f"    [{n['date']}] {n['title']}")
                        if n['body']:
                            print(f"      {n['body'][:80]}")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '36':
            bp = self._pick_backup()
            if bp:
                domain = input("  Domain filter (or Enter): ").strip()
                path_f = input("  Path filter (or Enter): ").strip()
                r = m.list_backup_files(bp, domain=domain, path_filter=path_f)
                if r['success']:
                    print(f"  {r['count']} files:")
                    for f in r['files'][:30]:
                        print(f"    [{f['domain']}] {f['path']}")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '37':
            bp = self._pick_backup()
            if bp:
                fhash = input("  File hash: ").strip()
                name = input("  Output filename (or Enter): ").strip() or None
                if fhash:
                    r = m.extract_backup_file(bp, fhash, output_name=name)
                    if r['success']:
                        print(f"  Extracted: {r['path']} ({r['size']} bytes)")
                    else:
                        print(f"  Error: {r['error']}")
        # Filesystem
        elif choice == '40':
            if not self._ensure_device(): return
            r = m.mount_filesystem(self.udid)
            if r['success']:
                print(f"  Mounted at: {r['mountpoint']}")
            else:
                print(f"  Error: {r.get('error', r.get('output'))}")
        elif choice == '41':
            if not self._ensure_device(): return
            bid = input("  Bundle ID: ").strip()
            if bid:
                r = m.mount_app_documents(self.udid, bid)
                if r['success']:
                    print(f"  Mounted at: {r['mountpoint']}")
                else:
                    print(f"  Error: {r.get('error', r.get('output'))}")
        elif choice == '42':
            mp = input("  Mountpoint to unmount: ").strip()
            if mp:
                m.unmount_filesystem(mp)
                print("  Unmounted.")
        elif choice == '43':
            if not self._ensure_device(): return
            r = m.list_profiles(self.udid)
            if r['success']:
                print(f"  {r['count']} profiles:")
                for p in r['profiles']:
                    print(f"    {p.get('id','')} - {p.get('name','')}")
            else:
                print(f"  Error: {r['error']}")
        elif choice == '44':
            if not self._ensure_device(): return
            path = input("  Profile path (.mobileprovision/.mobileconfig): ").strip()
            if path:
                r = m.install_profile(self.udid, path)
                print(f"  {r.get('output', 'Done')}")
        elif choice == '45':
            if not self._ensure_device(): return
            pid = input("  Profile ID to remove: ").strip()
            if pid:
                r = m.remove_profile(self.udid, pid)
                print(f"  {r.get('output', 'Done')}")
        # Network
        elif choice == '50':
            if not self._ensure_device(): return
            lp = input("  Local port: ").strip()
            dp = input("  Device port: ").strip()
            if lp and dp:
                r = m.port_forward(self.udid, int(lp), int(dp))
                if r['success']:
                    print(f"  Forwarding localhost:{lp} -> device:{dp} (PID: {r['pid']})")
                else:
                    print(f"  Error: {r['error']}")
        elif choice == '51':
            if not self._ensure_device(): return
            r = m.export_recon_report(self.udid)
            if r['success']:
                print(f"  Report: {r['report_path']}")
        else:
            print("  Invalid choice.")


def run():
    m = IPhoneLocal()
    m.run_interactive()
