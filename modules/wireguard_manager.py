"""
WireGuard VPN Manager - Server management, client CRUD, remote ADB
Manage WireGuard VPN server, clients, and remote ADB connections over VPN tunnel.
"""

DESCRIPTION = "WireGuard VPN + Remote ADB manager"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "defense"


class WireGuardVPN:
    """Interactive WireGuard VPN menu."""

    def __init__(self):
        from core.wireguard import get_wireguard_manager
        self.mgr = get_wireguard_manager()

    def show_menu(self):
        status = self.mgr.get_server_status()
        running = status.get('running', False)
        endpoint = status.get('endpoint', 'N/A')
        clients = self.mgr.get_all_clients()
        peer_status = self.mgr.get_peer_status() if running else {}

        # Count online peers
        online = 0
        for c in clients:
            ps = peer_status.get(c.get('public_key', ''), {})
            hs = ps.get('latest_handshake')
            if hs is not None and hs < 180:
                online += 1

        print(f"\n{'='*55}")
        print("  WireGuard VPN Manager")
        print(f"{'='*55}")
        print(f"  Interface: {status.get('interface', 'wg0')} | "
              f"Status: {'Running' if running else 'Stopped'}")
        print(f"  Endpoint: {endpoint}")
        print(f"  Clients: {len(clients)} ({online} online)")
        print()
        print("  -- Server --")
        print("   1) Server Status")
        print("   2) Start Interface")
        print("   3) Stop Interface")
        print("   4) Restart Interface")
        print()
        print("  -- Clients --")
        print("  10) List All Clients")
        print("  11) Create New Client")
        print("  12) View Client Detail")
        print("  13) Delete Client")
        print("  14) Enable/Disable Client")
        print("  15) Import Existing Peers")
        print()
        print("  -- Remote ADB --")
        print("  20) ADB Connect (TCP/IP)")
        print("  21) ADB Disconnect")
        print("  22) Auto-Connect All Peers")
        print("  23) List Remote ADB Devices")
        print()
        print("  -- USB/IP --")
        print("  30) USB/IP Status")
        print("  31) Load USB/IP Modules")
        print("  32) List Remote USB Devices")
        print("  33) Attach USB Device")
        print("  34) Detach USB Device")
        print("  35) List Attached Ports")
        print()
        print("  -- Config --")
        print("  40) Generate Client Config")
        print("  41) Show QR Code (terminal)")
        print("  42) Refresh UPnP Mapping")
        print()
        print("   0) Back")
        print()

    # ── Helpers ─────────────────────────────────────────────────────

    def _pick_client(self, prompt="  Select client #: "):
        """Select a client from the list."""
        clients = self.mgr.get_all_clients()
        if not clients:
            print("  No clients configured.")
            return None
        print("\n  Clients:")
        for i, c in enumerate(clients, 1):
            status = "ON " if c.get('enabled', True) else "OFF"
            print(f"    {i}) [{status}] {c['name']} ({c['assigned_ip']})")
        try:
            choice = int(input(prompt).strip())
            if 1 <= choice <= len(clients):
                return clients[choice - 1]
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        return None

    def _pick_client_ip(self, prompt="  Client IP (or # to select): "):
        """Get a client IP either directly or by selection."""
        try:
            val = input(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not val:
            return None
        # If numeric, treat as selection
        if val.isdigit():
            clients = self.mgr.get_all_clients()
            idx = int(val) - 1
            if 0 <= idx < len(clients):
                return clients[idx]['assigned_ip']
            print("  Invalid selection.")
            return None
        return val

    # ── Server ─────────────────────────────────────────────────────

    def do_server_status(self):
        status = self.mgr.get_server_status()
        print(f"\n  Server Status:")
        print(f"    Interface:  {status.get('interface', 'wg0')}")
        print(f"    Running:    {status.get('running', False)}")
        print(f"    Public Key: {status.get('public_key', 'N/A')}")
        print(f"    Endpoint:   {status.get('endpoint', 'N/A')}")
        print(f"    Listen Port: {status.get('listen_port', 'N/A')}")
        print(f"    Peers:      {status.get('peer_count', 0)}")
        if status.get('error'):
            print(f"    Error:      {status['error']}")

    def do_start(self):
        print("  Starting WireGuard interface...")
        result = self.mgr.start_interface()
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_stop(self):
        print("  Stopping WireGuard interface...")
        result = self.mgr.stop_interface()
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_restart(self):
        print("  Restarting WireGuard interface...")
        result = self.mgr.restart_interface()
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    # ── Clients ────────────────────────────────────────────────────

    def do_list_clients(self):
        clients = self.mgr.get_all_clients()
        peer_status = self.mgr.get_peer_status()
        if not clients:
            print("\n  No clients configured.")
            return
        print(f"\n  {'Name':<20} {'IP':<16} {'Status':<8} {'Handshake':<20} {'RX/TX'}")
        print(f"  {'-'*80}")
        for c in clients:
            ps = peer_status.get(c.get('public_key', ''), {})
            hs = ps.get('latest_handshake')
            hs_str = ps.get('latest_handshake_str', 'never')
            if hs is not None and hs < 180:
                status = 'ONLINE'
            elif hs is not None:
                status = 'idle'
            else:
                status = 'offline'
            if not c.get('enabled', True):
                status = 'disabled'
            rx = ps.get('transfer_rx_str', '-')
            tx = ps.get('transfer_tx_str', '-')
            print(f"  {c['name']:<20} {c['assigned_ip']:<16} {status:<8} "
                  f"{hs_str:<20} {rx}/{tx}")

    def do_create_client(self):
        try:
            name = input("  Client name: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not name:
            print("  Name required.")
            return
        try:
            dns = input(f"  DNS [{self.mgr._default_dns}]: ").strip()
            allowed = input(f"  Allowed IPs [{self.mgr._default_allowed_ips}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        print(f"  Creating client '{name}'...")
        result = self.mgr.create_client(
            name,
            dns=dns or None,
            allowed_ips=allowed or None)
        if result.get('ok'):
            client = result['client']
            print(f"  Created: {client['name']} ({client['assigned_ip']})")
            print(f"  ID: {client['id']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_view_client(self):
        client = self._pick_client()
        if not client:
            return
        print(f"\n  Client: {client['name']}")
        print(f"    ID:          {client['id']}")
        print(f"    IP:          {client['assigned_ip']}")
        print(f"    Public Key:  {client['public_key']}")
        print(f"    PSK:         {'Yes' if client.get('preshared_key') else 'No'}")
        print(f"    DNS:         {client.get('dns', 'default')}")
        print(f"    Allowed IPs: {client.get('allowed_ips', 'default')}")
        print(f"    Enabled:     {client.get('enabled', True)}")
        print(f"    Created:     {client.get('created_at', 'N/A')}")

        # Show live status
        peer_status = self.mgr.get_peer_status()
        ps = peer_status.get(client['public_key'], {})
        if ps:
            print(f"    Handshake:   {ps.get('latest_handshake_str', 'never')}")
            print(f"    Endpoint:    {ps.get('endpoint', 'N/A')}")
            print(f"    RX:          {ps.get('transfer_rx_str', '-')}")
            print(f"    TX:          {ps.get('transfer_tx_str', '-')}")

    def do_delete_client(self):
        client = self._pick_client()
        if not client:
            return
        try:
            confirm = input(f"  Delete '{client['name']}'? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'y':
            print("  Cancelled.")
            return
        result = self.mgr.delete_client(client['id'])
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_toggle_client(self):
        client = self._pick_client()
        if not client:
            return
        current = client.get('enabled', True)
        new_state = not current
        action = 'Enable' if new_state else 'Disable'
        try:
            confirm = input(f"  {action} '{client['name']}'? (y/N): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return
        if confirm != 'y':
            print("  Cancelled.")
            return
        result = self.mgr.toggle_client(client['id'], new_state)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_import_peers(self):
        print("  Importing existing peers from wg0.conf...")
        result = self.mgr.import_existing_peers()
        if result.get('ok'):
            print(f"  Imported {result['imported']} peers.")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    # ── Remote ADB ─────────────────────────────────────────────────

    def do_adb_connect(self):
        clients = self.mgr.get_all_clients()
        if clients:
            print("\n  Available clients:")
            for i, c in enumerate(clients, 1):
                print(f"    {i}) {c['name']} ({c['assigned_ip']})")
        ip = self._pick_client_ip()
        if not ip:
            return
        print(f"  Connecting to {ip}:5555...")
        result = self.mgr.adb_connect(ip)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_adb_disconnect(self):
        ip = self._pick_client_ip("  Client IP to disconnect: ")
        if not ip:
            return
        result = self.mgr.adb_disconnect(ip)
        print(f"  {result.get('message', 'Done')}")

    def do_auto_connect(self):
        print("  Auto-connecting to all active WG peers...")
        result = self.mgr.auto_connect_peers()
        for r in result.get('results', []):
            status = "OK" if r['result'].get('ok') else "FAIL"
            print(f"    [{status}] {r['name']} ({r['ip']}): "
                  f"{r['result'].get('message', r['result'].get('error', ''))}")
        if not result.get('results'):
            print("  No active peers found.")

    def do_list_adb_devices(self):
        devices = self.mgr.get_adb_remote_devices()
        if not devices:
            print("\n  No remote ADB devices connected via WireGuard.")
            return
        print(f"\n  Remote ADB Devices:")
        for d in devices:
            print(f"    {d['serial']} - {d['state']} "
                  f"{'(' + d['model'] + ')' if d.get('model') else ''}")

    # ── USB/IP ─────────────────────────────────────────────────────

    def do_usbip_status(self):
        status = self.mgr.get_usbip_status()
        print(f"\n  USB/IP Status:")
        print(f"    Available:      {status['available']}")
        print(f"    Modules loaded: {status['modules_loaded']}")
        print(f"    Active imports: {status['active_imports']}")
        if status.get('ports'):
            for p in status['ports']:
                print(f"      Port {p['port']}: {p['status']}")

    def do_load_modules(self):
        result = self.mgr.load_usbip_modules()
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_list_remote_usb(self):
        ip = self._pick_client_ip()
        if not ip:
            return
        print(f"  Listing USB devices on {ip}...")
        result = self.mgr.usbip_list_remote(ip)
        if not result.get('ok'):
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        devices = result.get('devices', [])
        if not devices:
            print("  No exportable USB devices found.")
            return
        for d in devices:
            print(f"    [{d['busid']}] {d['description']}")

    def do_attach_usb(self):
        ip = self._pick_client_ip("  Remote host IP: ")
        if not ip:
            return
        # List devices first
        result = self.mgr.usbip_list_remote(ip)
        devices = result.get('devices', [])
        if not devices:
            print("  No exportable devices found.")
            return
        print("\n  Available devices:")
        for i, d in enumerate(devices, 1):
            print(f"    {i}) [{d['busid']}] {d['description']}")
        try:
            choice = input("  Attach #: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                busid = devices[idx]['busid']
            else:
                print("  Invalid selection.")
                return
        else:
            busid = choice

        print(f"  Attaching {busid} from {ip}...")
        result = self.mgr.usbip_attach(ip, busid)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_detach_usb(self):
        # Show current ports
        ports = self.mgr.usbip_port_status()
        if not ports.get('ports'):
            print("  No attached USB/IP devices.")
            return
        print("\n  Attached ports:")
        for p in ports['ports']:
            print(f"    Port {p['port']}: {p['status']}")
        try:
            port = input("  Detach port #: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not port:
            return
        result = self.mgr.usbip_detach(port)
        if result.get('ok'):
            print(f"  {result['message']}")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    def do_list_ports(self):
        result = self.mgr.usbip_port_status()
        if not result.get('ok'):
            print(f"  Error: {result.get('error', 'Failed')}")
            return
        ports = result.get('ports', [])
        if not ports:
            print("  No attached USB/IP ports.")
            return
        for p in ports:
            detail = f" - {p['detail']}" if p.get('detail') else ''
            print(f"    Port {p['port']}: {p['status']}{detail}")

    # ── Config ─────────────────────────────────────────────────────

    def do_gen_config(self):
        client = self._pick_client()
        if not client:
            return
        config = self.mgr.generate_client_config(client)
        print(f"\n  Config for {client['name']}:\n")
        print(f"  {'─'*40}")
        for line in config.split('\n'):
            print(f"  {line}")
        print(f"  {'─'*40}")

    def do_show_qr(self):
        client = self._pick_client()
        if not client:
            return
        config = self.mgr.generate_client_config(client)
        try:
            import qrcode
            qr = qrcode.QRCode(box_size=1, border=1)
            qr.add_data(config)
            qr.make(fit=True)
            qr.print_ascii(invert=True)
        except ImportError:
            print("  qrcode module not installed. Install: pip install qrcode")

    def do_refresh_upnp(self):
        print("  Refreshing UPnP mapping for WireGuard port...")
        result = self.mgr.refresh_upnp_mapping()
        if result.get('ok'):
            print(f"  UPnP mapping refreshed.")
        else:
            print(f"  Error: {result.get('error', 'Failed')}")

    # ── Main Loop ──────────────────────────────────────────────────

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
                '1': self.do_server_status,
                '2': self.do_start,
                '3': self.do_stop,
                '4': self.do_restart,
                '10': self.do_list_clients,
                '11': self.do_create_client,
                '12': self.do_view_client,
                '13': self.do_delete_client,
                '14': self.do_toggle_client,
                '15': self.do_import_peers,
                '20': self.do_adb_connect,
                '21': self.do_adb_disconnect,
                '22': self.do_auto_connect,
                '23': self.do_list_adb_devices,
                '30': self.do_usbip_status,
                '31': self.do_load_modules,
                '32': self.do_list_remote_usb,
                '33': self.do_attach_usb,
                '34': self.do_detach_usb,
                '35': self.do_list_ports,
                '40': self.do_gen_config,
                '41': self.do_show_qr,
                '42': self.do_refresh_upnp,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    wg = WireGuardVPN()
    wg.run_interactive()
