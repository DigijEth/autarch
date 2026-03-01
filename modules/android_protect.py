"""
Android Protection Shield - Anti-stalkerware & anti-spyware defense
Detect, analyze, and remove stalkerware and government-grade spyware from Android devices.
"""

DESCRIPTION = "Android anti-stalkerware/spyware shield"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "defense"


class AndroidProtect:
    """Interactive Android protection menu."""

    def __init__(self):
        from core.android_protect import get_android_protect_manager
        from core.hardware import get_hardware_manager
        self.mgr = get_android_protect_manager()
        self.hw = get_hardware_manager()
        self.serial = None

    def _pick_device(self):
        """Select an ADB device."""
        devices = self.hw.adb_devices()
        if not devices:
            print("  No ADB devices connected.")
            return None
        if len(devices) == 1:
            self.serial = devices[0]['serial']
            return self.serial
        print("\n  Select device:")
        for i, d in enumerate(devices, 1):
            model = d.get('model', '')
            print(f"    {i}) {d['serial']} {model}")
        try:
            choice = int(input("  > ").strip())
            if 1 <= choice <= len(devices):
                self.serial = devices[choice - 1]['serial']
                return self.serial
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        return None

    def _ensure_device(self):
        """Ensure we have a selected device."""
        if self.serial:
            return self.serial
        return self._pick_device()

    def _print_severity(self, sev):
        """Color indicator for severity."""
        markers = {
            'critical': '[!!!]',
            'high': '[!! ]',
            'medium': '[!  ]',
            'low': '[   ]',
        }
        return markers.get(sev, '[?  ]')

    def show_menu(self):
        status = self.hw.get_status()
        serial_str = self.serial or 'None selected'

        # Shizuku/Shield info
        shizuku_str = 'N/A'
        shield_str = 'N/A'
        if self.serial:
            try:
                sz = self.mgr.check_shizuku(self.serial)
                if sz['installed']:
                    shizuku_str = f"{'Running' if sz['running'] else 'Stopped'}"
                    if sz['version']:
                        shizuku_str += f" v{sz['version']}"
                else:
                    shizuku_str = 'Not installed'
                sh = self.mgr.check_shield_app(self.serial)
                shield_str = f"v{sh['version']}" if sh['installed'] else 'Not installed'
            except Exception:
                pass

        sig_stats = self.mgr.get_signature_stats()

        print(f"\n{'='*60}")
        print("  Android Protection Shield")
        print(f"{'='*60}")
        print(f"  ADB: {'Available' if status['adb'] else 'Not found'}")
        print(f"  Device: {serial_str}")
        print(f"  Shizuku: {shizuku_str} | Shield: {shield_str}")
        print(f"  DB: {sig_stats['stalkerware_packages']} packages, "
              f"{sig_stats['government_spyware']} govt spyware")
        print()
        print("  -- Quick Actions --")
        print("   1) Quick Scan (fast)")
        print("   2) Full Protection Scan")
        print("   3) Export Scan Report")
        print()
        print("  -- Detection --")
        print("  10) Scan Stalkerware")
        print("  11) Scan Hidden Apps")
        print("  12) Scan Device Admins")
        print("  13) Scan Accessibility Services")
        print("  14) Scan Notification Listeners")
        print("  15) Scan Spyware Indicators (Pegasus/Predator)")
        print("  16) Scan System Integrity")
        print("  17) Scan Suspicious Processes")
        print("  18) Scan Certificates (MITM)")
        print("  19) Scan Network Config")
        print("  20) Scan Developer Options")
        print()
        print("  -- Permission Analysis --")
        print("  30) Find Dangerous Apps")
        print("  31) Analyze App Permissions")
        print("  32) Permission Heatmap")
        print()
        print("  -- Remediation --")
        print("  40) Disable Threat")
        print("  41) Uninstall Threat")
        print("  42) Revoke Dangerous Permissions")
        print("  43) Remove Device Admin")
        print("  44) Remove Rogue CA Cert")
        print("  45) Clear Proxy Settings")
        print()
        print("  -- Shizuku & Shield --")
        print("  50) Shizuku Status")
        print("  51) Install Shizuku")
        print("  52) Start Shizuku Service")
        print("  53) Install Shield App")
        print("  54) Configure Shield")
        print("  55) Grant Shield Permissions")
        print()
        print("  -- Database --")
        print("  60) Signature Stats")
        print("  61) Update Signatures")
        print()
        print("  -- Tracking Honeypot --")
        print("  70) Honeypot Status")
        print("  71) Scan Tracker Apps")
        print("  72) Scan Tracker Permissions")
        print("  73) View Ad Tracking Settings")
        print()
        print("  74) Reset Advertising ID")
        print("  75) Opt Out of Ad Tracking")
        print("  76) Set Ad-Blocking DNS")
        print("  77) Disable Location Scanning")
        print()
        print("  78) Deploy Hosts Blocklist (root)")
        print("  79) Setup Traffic Redirect (root)")
        print("  80) Set Fake Location (root)")
        print("  81) Random Fake Location (root)")
        print("  82) Rotate Device Identity (root)")
        print("  83) Generate Fake Fingerprint (root)")
        print()
        print("  84) Activate Honeypot (all tiers)")
        print("  85) Deactivate Honeypot")
        print()
        print("  86) Tracker Domain Stats")
        print("  87) Update Tracker Domains")
        print()
        print("  [s] Select Device")
        print("   0) Back")
        print()

    # ── Quick Actions ───────────────────────────────────────────────

    def do_quick_scan(self):
        if not self._ensure_device():
            return
        print(f"\n  Running quick scan on {self.serial}...")
        result = self.mgr.quick_scan(self.serial)
        summary = result.get('summary', {})
        print(f"\n  {'='*50}")
        print(f"  Quick Scan Results")
        print(f"  {'='*50}")
        print(f"  Threats found: {summary.get('threats_found', 0)}")
        print(f"    Stalkerware:            {summary.get('stalkerware', 0)}")
        print(f"    Suspicious admins:      {summary.get('suspicious_admins', 0)}")
        print(f"    Malicious accessibility: {summary.get('malicious_accessibility', 0)}")

        found = result.get('stalkerware', {}).get('found', [])
        if found:
            print(f"\n  Stalkerware Detected:")
            for f in found:
                print(f"    {self._print_severity(f['severity'])} {f['name']} ({f['package']})")
                print(f"           {f['description']}")

    def do_full_scan(self):
        if not self._ensure_device():
            return
        print(f"\n  Running full protection scan on {self.serial}...")
        print("  This may take a few minutes...")
        result = self.mgr.full_protection_scan(self.serial)
        summary = result.get('summary', {})
        print(f"\n  {'='*50}")
        print(f"  Full Scan Results")
        print(f"  {'='*50}")
        print(f"  Total threats:     {summary.get('threats_found', 0)}")
        print(f"  System integrity:  {summary.get('system_integrity', 'N/A')}")
        print(f"  Hidden apps:       {summary.get('hidden_apps', 0)}")
        print(f"  Dangerous apps:    {summary.get('dangerous_apps', 0)}")
        print(f"  User CA certs:     {summary.get('user_ca_certs', 0)}")

        found = result.get('stalkerware', {}).get('found', [])
        if found:
            print(f"\n  Stalkerware:")
            for f in found:
                print(f"    {self._print_severity(f['severity'])} {f['name']} ({f['package']})")

        spyware = result.get('spyware_indicators', {}).get('findings', [])
        if spyware:
            print(f"\n  Government Spyware Indicators:")
            for s in spyware:
                print(f"    {self._print_severity(s['severity'])} {s['name']}")
                for ind in s.get('indicators_matched', []):
                    print(f"      {ind['type']}: {ind['value']}")

    def do_export_report(self):
        if not self._ensure_device():
            return
        print(f"\n  Running full scan and exporting...")
        scan = self.mgr.full_protection_scan(self.serial)
        result = self.mgr.export_scan_report(self.serial, scan)
        if result.get('ok'):
            print(f"  Report saved: {result['path']}")
        else:
            print(f"  Error: {result.get('error', 'Unknown')}")

    # ── Detection ───────────────────────────────────────────────────

    def do_scan_stalkerware(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for stalkerware...")
        result = self.mgr.scan_stalkerware(self.serial)
        if result.get('error'):
            print(f"  Error: {result['error']}")
            return
        print(f"  Scanned {result['total']} packages, {result['clean_count']} clean")
        found = result.get('found', [])
        if found:
            print(f"\n  Found {len(found)} threats:")
            for f in found:
                print(f"    {self._print_severity(f['severity'])} {f['name']}")
                print(f"      Package: {f['package']}")
                print(f"      {f['description']}")
        else:
            print("  No stalkerware detected.")

    def do_scan_hidden(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for hidden apps...")
        result = self.mgr.scan_hidden_apps(self.serial)
        apps = result.get('hidden_apps', [])
        print(f"  Found {len(apps)} hidden apps (no launcher icon):")
        for app in apps:
            print(f"    - {app}")

    def do_scan_admins(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning device admins...")
        result = self.mgr.scan_device_admins(self.serial)
        admins = result.get('admins', [])
        print(f"  Found {len(admins)} device admins:")
        for a in admins:
            marker = " [SUSPICIOUS]" if a.get('suspicious') else ""
            print(f"    - {a['package']}{marker}")

    def do_scan_accessibility(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning accessibility services...")
        result = self.mgr.scan_accessibility_services(self.serial)
        services = result.get('services', [])
        if not services:
            print("  No accessibility services enabled.")
            return
        for s in services:
            status = s.get('status', 'unknown')
            marker = {'legitimate': '[OK]', 'malicious': '[BAD]', 'unknown': '[??]'}
            print(f"    {marker.get(status, '[??]')} {s['package']}")

    def do_scan_listeners(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning notification listeners...")
        result = self.mgr.scan_notification_listeners(self.serial)
        listeners = result.get('listeners', [])
        if not listeners:
            print("  No notification listeners enabled.")
            return
        for l in listeners:
            marker = " [SUSPICIOUS]" if l.get('suspicious') else ""
            print(f"    - {l['package']}{marker}")

    def do_scan_spyware(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for government spyware indicators...")
        print("  Checking Pegasus, Predator, Hermit, FinSpy, etc...")
        result = self.mgr.scan_spyware_indicators(self.serial)
        print(f"  Checked {result.get('spyware_checked', 0)} spyware families")
        findings = result.get('findings', [])
        if findings:
            print(f"\n  ALERT: Found {len(findings)} indicators:")
            for f in findings:
                print(f"    {self._print_severity(f['severity'])} {f['name']}")
                print(f"      {f.get('description', '')}")
                for ind in f.get('indicators_matched', []):
                    print(f"        {ind['type']}: {ind['value']}")
        else:
            print("  No government spyware indicators found.")

    def do_scan_integrity(self):
        if not self._ensure_device():
            return
        print(f"\n  Checking system integrity...")
        result = self.mgr.scan_system_integrity(self.serial)
        print(f"  Passed: {result['ok_count']}/{result['total']}")
        for name, check in result.get('checks', {}).items():
            status = "[OK]" if check['ok'] else "[!!]"
            print(f"    {status} {check['description']}: {check['value']}")

    def do_scan_processes(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for suspicious processes...")
        result = self.mgr.scan_suspicious_processes(self.serial)
        findings = result.get('findings', [])
        if findings:
            print(f"  Found {len(findings)} suspicious items:")
            for f in findings:
                print(f"    [{f['severity'].upper()}] {f['type']}: {f['detail']}")
        else:
            print("  No suspicious processes found.")

    def do_scan_certs(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning certificates...")
        result = self.mgr.scan_certificates(self.serial)
        certs = result.get('certs', [])
        if certs:
            print(f"  Found {len(certs)} user-installed CA certs:")
            for c in certs:
                print(f"    - {c['hash']}: {c['detail']}")
        else:
            print("  No user-installed CA certificates.")

    def do_scan_network(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning network configuration...")
        result = self.mgr.scan_network_config(self.serial)
        for name, check in result.get('checks', {}).items():
            status = "[OK]" if check.get('ok', True) else "[!!]"
            desc = check.get('description', name)
            print(f"    {status} {desc}: {check['value']}")

    def do_scan_devopt(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning developer options...")
        result = self.mgr.scan_developer_options(self.serial)
        for name, check in result.get('checks', {}).items():
            marker = "[ON] " if check.get('enabled') else "[OFF]"
            print(f"    {marker} {check['description']}: {check['value']}")

    # ── Permission Analysis ─────────────────────────────────────────

    def do_dangerous_apps(self):
        if not self._ensure_device():
            return
        print(f"\n  Finding apps with dangerous permission combos...")
        print("  This may take a while...")
        result = self.mgr.find_dangerous_apps(self.serial)
        dangerous = result.get('dangerous', [])
        if dangerous:
            print(f"\n  Found {len(dangerous)} dangerous apps:")
            for d in dangerous:
                print(f"    {self._print_severity(d['severity'])} {d['package']}")
                print(f"      Pattern: {d['combo']}")
                print(f"      Perms: {', '.join(d['matched_perms'])}")
        else:
            print("  No apps with dangerous permission combos found.")

    def do_analyze_perms(self):
        if not self._ensure_device():
            return
        try:
            package = input("  Package name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not package:
            return
        result = self.mgr.analyze_app_permissions(self.serial, package)
        if result.get('error'):
            print(f"  Error: {result['error']}")
            return
        perms = result.get('permissions', {})
        info = result.get('info', {})
        print(f"\n  {package}")
        if info:
            for k, v in info.items():
                print(f"    {k}: {v}")
        print(f"\n  Granted ({len(perms.get('granted', []))}):")
        for p in perms.get('granted', []):
            print(f"    + {p}")
        print(f"  Denied ({len(perms.get('denied', []))}):")
        for p in perms.get('denied', []):
            print(f"    - {p}")

    def do_perm_heatmap(self):
        if not self._ensure_device():
            return
        print(f"\n  Building permission heatmap...")
        print("  This scans all non-system apps, may take a while...")
        result = self.mgr.permission_heatmap(self.serial)
        matrix = result.get('matrix', [])
        perm_names = result.get('permission_names', [])
        if not matrix:
            print("  No apps with dangerous permissions found.")
            return
        # Print header
        short = [p[:8] for p in perm_names]
        header = f"  {'Package':<35} " + " ".join(f"{s:<8}" for s in short)
        print(f"\n{header}")
        print(f"  {'-'*len(header)}")
        for row in matrix[:30]:  # Limit display
            pkg = row['package'][:34]
            perms = row['permissions']
            cells = " ".join(
                f"{'  X     ' if perms.get(p) else '  .     '}"
                for p in perm_names
            )
            print(f"  {pkg:<35} {cells}")
        if len(matrix) > 30:
            print(f"  ... and {len(matrix) - 30} more apps")

    # ── Remediation ─────────────────────────────────────────────────

    def _get_package_input(self, prompt="  Package to target: "):
        try:
            return input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return ''

    def do_disable(self):
        if not self._ensure_device():
            return
        pkg = self._get_package_input()
        if not pkg:
            return
        result = self.mgr.disable_threat(self.serial, pkg)
        if result.get('ok'):
            print(f"  Disabled: {pkg}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_uninstall(self):
        if not self._ensure_device():
            return
        pkg = self._get_package_input()
        if not pkg:
            return
        try:
            confirm = input(f"  Uninstall {pkg}? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'y':
            print("  Cancelled.")
            return
        result = self.mgr.uninstall_threat(self.serial, pkg)
        if result.get('ok'):
            print(f"  Uninstalled: {pkg}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_revoke(self):
        if not self._ensure_device():
            return
        pkg = self._get_package_input()
        if not pkg:
            return
        result = self.mgr.revoke_dangerous_perms(self.serial, pkg)
        print(f"  Revoked: {', '.join(result['revoked'])}")
        if result['failed']:
            print(f"  Failed: {', '.join(result['failed'])}")

    def do_remove_admin(self):
        if not self._ensure_device():
            return
        pkg = self._get_package_input()
        if not pkg:
            return
        result = self.mgr.remove_device_admin(self.serial, pkg)
        if result.get('ok'):
            print(f"  Removed device admin: {result.get('message', pkg)}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_remove_cert(self):
        if not self._ensure_device():
            return
        # List certs first
        certs = self.mgr.scan_certificates(self.serial).get('certs', [])
        if not certs:
            print("  No user CA certs to remove.")
            return
        print("  User CA certificates:")
        for i, c in enumerate(certs, 1):
            print(f"    {i}) {c['hash']}: {c['detail']}")
        try:
            choice = int(input("  Remove #: ").strip())
            if 1 <= choice <= len(certs):
                result = self.mgr.remove_ca_cert(self.serial, certs[choice - 1]['hash'])
                if result.get('ok'):
                    print(f"  Removed.")
                else:
                    print(f"  Error: {result.get('error')}")
        except (ValueError, EOFError, KeyboardInterrupt):
            pass

    def do_clear_proxy(self):
        if not self._ensure_device():
            return
        result = self.mgr.clear_proxy(self.serial)
        for r in result.get('results', []):
            status = "OK" if r['ok'] else "FAIL"
            print(f"    [{status}] {r['setting']}")

    # ── Shizuku & Shield ────────────────────────────────────────────

    def do_shizuku_status(self):
        if not self._ensure_device():
            return
        result = self.mgr.shizuku_status(self.serial)
        print(f"\n  Shizuku Status:")
        print(f"    Installed: {result['installed']}")
        print(f"    Running:   {result.get('running', False)}")
        print(f"    Version:   {result.get('version', 'N/A')}")

    def do_install_shizuku(self):
        if not self._ensure_device():
            return
        try:
            apk = input("  Shizuku APK path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not apk:
            return
        result = self.mgr.install_shizuku(self.serial, apk)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error')}")

    def do_start_shizuku(self):
        if not self._ensure_device():
            return
        result = self.mgr.start_shizuku(self.serial)
        if result.get('ok'):
            print(f"  Shizuku started: {result.get('output', '')}")
        else:
            print(f"  Error: {result.get('error')}")

    def do_install_shield(self):
        if not self._ensure_device():
            return
        try:
            apk = input("  Shield APK path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not apk:
            return
        result = self.mgr.install_shield_app(self.serial, apk)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error')}")

    def do_configure_shield(self):
        if not self._ensure_device():
            return
        print("  Shield Configuration (JSON):")
        try:
            config_str = input("  > ").strip()
            config = json.loads(config_str)
        except (EOFError, KeyboardInterrupt):
            return
        except json.JSONDecodeError:
            print("  Invalid JSON.")
            return
        result = self.mgr.configure_shield(self.serial, config)
        if result.get('ok'):
            print(f"  Config sent: {result.get('output', '')}")
        else:
            print(f"  Error: {result.get('output', 'Failed')}")

    def do_grant_shield_perms(self):
        if not self._ensure_device():
            return
        result = self.mgr.grant_shield_permissions(self.serial)
        for p in result.get('granted', []):
            print(f"    [OK] {p}")
        for f in result.get('failed', []):
            print(f"    [!!] {f['perm']}: {f['error']}")

    # ── Tracking Honeypot ─────────────────────────────────────────

    def do_honeypot_status(self):
        if not self._ensure_device():
            return
        print(f"\n  Checking honeypot status...")
        result = self.mgr.honeypot_status(self.serial)
        print(f"\n  Honeypot Status:")
        print(f"    Active:         {result.get('active', False)}")
        print(f"    Tier:           {result.get('tier', 0)}")
        print(f"    Ad tracking:    {'limited' if result.get('ad_tracking_limited') else 'not limited'}")
        print(f"    Private DNS:    {result.get('private_dns_mode', 'off')}")
        if result.get('private_dns_host'):
            print(f"    DNS host:       {result['private_dns_host']}")
        protections = result.get('protections', {})
        if protections:
            print(f"    Protections:")
            for k, v in protections.items():
                print(f"      {k}: {v}")

    def do_scan_tracker_apps(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for tracker apps...")
        result = self.mgr.scan_tracker_apps(self.serial)
        if result.get('error'):
            print(f"  Error: {result['error']}")
            return
        found = result.get('found', [])
        print(f"  Found {len(found)} tracker packages out of {result.get('total', 0)} installed:")
        for pkg in found:
            print(f"    - {pkg}")
        if not found:
            print("  No known tracker apps found.")

    def do_scan_tracker_perms(self):
        if not self._ensure_device():
            return
        print(f"\n  Scanning for tracking permissions...")
        result = self.mgr.scan_tracker_permissions(self.serial)
        apps = result.get('apps', [])
        if apps:
            print(f"  {len(apps)} apps have tracking permissions:")
            for app in apps[:30]:
                print(f"    {app['package']}: {', '.join(app['permissions'])}")
            if len(apps) > 30:
                print(f"    ... and {len(apps) - 30} more")
        else:
            print("  No apps with tracking permissions found.")

    def do_ad_settings(self):
        if not self._ensure_device():
            return
        print(f"\n  Ad Tracking Settings:")
        result = self.mgr.get_tracking_settings(self.serial)
        for name, info in result.items():
            print(f"    {info.get('description', name)}: {info['value']}")

    def do_reset_ad_id(self):
        if not self._ensure_device():
            return
        result = self.mgr.reset_advertising_id(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_opt_out_tracking(self):
        if not self._ensure_device():
            return
        result = self.mgr.opt_out_ad_tracking(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_set_dns(self):
        if not self._ensure_device():
            return
        print("  Available DNS providers:")
        db = self.mgr._load_tracker_domains()
        providers = db.get('dns_providers', {})
        for name, info in providers.items():
            print(f"    {name}: {info.get('description', info.get('hostname', ''))}")
        try:
            provider = input("  Provider name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not provider:
            return
        result = self.mgr.set_private_dns(self.serial, provider)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_disable_location(self):
        if not self._ensure_device():
            return
        result = self.mgr.disable_location_accuracy(self.serial)
        if result.get('ok'):
            print("  WiFi and Bluetooth scanning disabled.")
        else:
            print("  Some settings failed:")
            for r in result.get('results', []):
                status = "OK" if r['ok'] else "FAIL"
                print(f"    [{status}] {r['setting']}")

    def do_deploy_hosts(self):
        if not self._ensure_device():
            return
        print("  Deploying hosts blocklist (requires root)...")
        result = self.mgr.deploy_hosts_blocklist(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_setup_iptables(self):
        if not self._ensure_device():
            return
        try:
            port_str = input("  Redirect port [9040]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        port = int(port_str) if port_str else 9040
        result = self.mgr.setup_iptables_redirect(self.serial, port)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_set_fake_location(self):
        if not self._ensure_device():
            return
        try:
            lat = float(input("  Latitude: ").strip())
            lon = float(input("  Longitude: ").strip())
        except (ValueError, EOFError, KeyboardInterrupt):
            print("  Invalid coordinates.")
            return
        result = self.mgr.set_fake_location(self.serial, lat, lon)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_random_location(self):
        if not self._ensure_device():
            return
        result = self.mgr.set_random_fake_location(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
            if result.get('location_name'):
                print(f"  Location: {result['location_name']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_rotate_identity(self):
        if not self._ensure_device():
            return
        result = self.mgr.rotate_device_identity(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
            for c in result.get('changes', []):
                status = "OK" if c['ok'] else "FAIL"
                print(f"    [{status}] {c['setting']}: {c['value']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_fake_fingerprint(self):
        if not self._ensure_device():
            return
        result = self.mgr.generate_fake_fingerprint(self.serial)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_activate_honeypot(self):
        if not self._ensure_device():
            return
        print("  Select protection tier:")
        print("    1) ADB only (no root)")
        print("    2) ADB + Shizuku")
        print("    3) Full (ADB + Shizuku + Root)")
        try:
            tier = int(input("  Tier [1]: ").strip() or '1')
        except (ValueError, EOFError, KeyboardInterrupt):
            return
        if tier not in (1, 2, 3):
            print("  Invalid tier.")
            return
        print(f"\n  Activating Tier {tier} honeypot...")
        result = self.mgr.honeypot_activate(self.serial, tier)
        print(f"  {result.get('summary', 'Done')}")
        for action in result.get('actions', []):
            r = action['result']
            status = "OK" if r.get('ok', False) else "FAIL"
            msg = r.get('message', r.get('error', ''))
            print(f"    [{status}] {action['name']}: {msg}")

    def do_deactivate_honeypot(self):
        if not self._ensure_device():
            return
        print("  Deactivating honeypot...")
        result = self.mgr.honeypot_deactivate(self.serial)
        for action in result.get('actions', []):
            r = action['result']
            status = "OK" if r.get('ok', False) else "FAIL"
            print(f"    [{status}] {action['name']}")
        print("  Honeypot deactivated.")

    def do_tracker_stats(self):
        stats = self.mgr.get_tracker_stats()
        print(f"\n  Tracker Domain Database:")
        print(f"    Version:         {stats['version']}")
        print(f"    Total domains:   {stats['total_domains']}")
        print(f"    Companies:       {stats['companies']}")
        print(f"    Tracker pkgs:    {stats['packages']}")
        print(f"    DNS providers:   {', '.join(stats.get('dns_providers', []))}")
        print(f"    Categories:")
        for cat, count in stats.get('categories', {}).items():
            print(f"      {cat}: {count} domains")

    def do_update_trackers(self):
        print("  Updating tracker domains...")
        result = self.mgr.update_tracker_domains()
        if result.get('ok'):
            print(f"  Updated: merged {result['merged']} new domains")
        else:
            print(f"  Error: {result.get('error')}")

    # ── Database ────────────────────────────────────────────────────

    def do_sig_stats(self):
        stats = self.mgr.get_signature_stats()
        print(f"\n  Signature Database Stats:")
        print(f"    Version:             {stats['version']}")
        print(f"    Last updated:        {stats['last_updated']}")
        print(f"    Stalkerware families: {stats['stalkerware_families']}")
        print(f"    Stalkerware packages: {stats['stalkerware_packages']}")
        print(f"    Government spyware:  {stats['government_spyware']}")
        print(f"    Permission combos:   {stats['permission_combos']}")

    def do_update_sigs(self):
        print("  Updating signatures from GitHub...")
        result = self.mgr.update_signatures()
        if result.get('ok'):
            print(f"  Updated: merged {result['merged']} new packages")
        else:
            print(f"  Error: {result.get('error')}")

    # ── Main Loop ───────────────────────────────────────────────────

    def run_interactive(self):
        import json
        while True:
            self.show_menu()
            try:
                choice = input("  Select > ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if choice == '0':
                break

            actions = {
                '1': self.do_quick_scan,
                '2': self.do_full_scan,
                '3': self.do_export_report,
                '10': self.do_scan_stalkerware,
                '11': self.do_scan_hidden,
                '12': self.do_scan_admins,
                '13': self.do_scan_accessibility,
                '14': self.do_scan_listeners,
                '15': self.do_scan_spyware,
                '16': self.do_scan_integrity,
                '17': self.do_scan_processes,
                '18': self.do_scan_certs,
                '19': self.do_scan_network,
                '20': self.do_scan_devopt,
                '30': self.do_dangerous_apps,
                '31': self.do_analyze_perms,
                '32': self.do_perm_heatmap,
                '40': self.do_disable,
                '41': self.do_uninstall,
                '42': self.do_revoke,
                '43': self.do_remove_admin,
                '44': self.do_remove_cert,
                '45': self.do_clear_proxy,
                '50': self.do_shizuku_status,
                '51': self.do_install_shizuku,
                '52': self.do_start_shizuku,
                '53': self.do_install_shield,
                '54': self.do_configure_shield,
                '55': self.do_grant_shield_perms,
                '60': self.do_sig_stats,
                '61': self.do_update_sigs,
                '70': self.do_honeypot_status,
                '71': self.do_scan_tracker_apps,
                '72': self.do_scan_tracker_perms,
                '73': self.do_ad_settings,
                '74': self.do_reset_ad_id,
                '75': self.do_opt_out_tracking,
                '76': self.do_set_dns,
                '77': self.do_disable_location,
                '78': self.do_deploy_hosts,
                '79': self.do_setup_iptables,
                '80': self.do_set_fake_location,
                '81': self.do_random_location,
                '82': self.do_rotate_identity,
                '83': self.do_fake_fingerprint,
                '84': self.do_activate_honeypot,
                '85': self.do_deactivate_honeypot,
                '86': self.do_tracker_stats,
                '87': self.do_update_trackers,
                's': self._pick_device,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    ap = AndroidProtect()
    ap.run_interactive()
