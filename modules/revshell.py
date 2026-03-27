"""
Reverse Shell Manager - Manage incoming reverse shell connections from Archon companion app.
Control the RevShell listener, manage sessions, execute commands, transfer files.
"""

DESCRIPTION = "Reverse Shell — remote device management via Archon"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "offense"

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))


class RevShellManager:
    """Interactive reverse shell management menu."""

    def __init__(self):
        from core.revshell import get_listener
        self._get_listener = get_listener

    @property
    def listener(self):
        return self._get_listener()

    def show_menu(self):
        li = self.listener
        sessions = li.list_sessions()
        alive = [s for s in sessions if s.get('alive', False)]

        print(f"\n{'='*55}")
        print("  Reverse Shell Manager")
        print(f"{'='*55}")
        print(f"  Listener: {'RUNNING on ' + str(li.host) + ':' + str(li.port) if li.running else 'Stopped'}")
        print(f"  Sessions: {len(alive)} active, {len(sessions)} total")
        if li.running:
            print(f"  Token:    {li.auth_token}")
        print()
        print("  -- Listener --")
        print("   1) Start Listener")
        print("   2) Stop Listener")
        print("   3) Listener Status")
        print()
        print("  -- Sessions --")
        print("  10) List Sessions")
        print("  11) Select Session (interactive shell)")
        print("  12) Execute Command")
        print("  13) Disconnect Session")
        print()
        print("  -- Device Info --")
        print("  20) System Info")
        print("  21) Installed Packages")
        print("  22) Running Processes")
        print("  23) Network Connections")
        print("  24) Logcat Output")
        print()
        print("  -- Capture --")
        print("  30) Take Screenshot")
        print("  31) Download File")
        print("  32) Upload File")
        print()
        print("   0) Back")
        print()

    # ── Helpers ─────────────────────────────────────────────────────

    def _pick_session(self, prompt="  Select session #: "):
        """Let user pick a session from the list."""
        sessions = self.listener.list_sessions()
        alive = [s for s in sessions if s.get('alive', False)]
        if not alive:
            print("  No active sessions.")
            return None
        print("\n  Active Sessions:")
        for i, s in enumerate(alive, 1):
            uptime_m = s.get('uptime', 0) // 60
            print(f"    {i}) [{s['session_id'][:8]}] {s['device']} "
                  f"(Android {s['android']}, UID {s['uid']}) — {uptime_m}m")
        try:
            choice = int(input(prompt).strip())
            if 1 <= choice <= len(alive):
                return alive[choice - 1]['session_id']
        except (ValueError, EOFError, KeyboardInterrupt):
            pass
        return None

    def _get_session_obj(self, sid):
        """Get the actual session object."""
        session = self.listener.get_session(sid)
        if not session or not session.alive:
            print(f"  Session {sid} not found or dead.")
            return None
        return session

    # ── Listener ────────────────────────────────────────────────────

    def do_start(self):
        if self.listener.running:
            print("  Listener already running.")
            return
        try:
            host = input(f"  Bind address [0.0.0.0]: ").strip() or '0.0.0.0'
            port_s = input(f"  Port [17322]: ").strip() or '17322'
            token = input(f"  Auth token (blank=random): ").strip() or None
        except (EOFError, KeyboardInterrupt):
            return

        from core.revshell import start_listener
        ok, msg = start_listener(host=host, port=int(port_s), token=token)
        if ok:
            print(f"  {msg}")
            print(f"  Token: {self.listener.auth_token}")
        else:
            print(f"  Error: {msg}")

    def do_stop(self):
        if not self.listener.running:
            print("  Listener not running.")
            return
        from core.revshell import stop_listener
        stop_listener()
        print("  Listener stopped.")

    def do_status(self):
        li = self.listener
        print(f"\n  Listener Status:")
        print(f"    Running:  {li.running}")
        print(f"    Host:     {li.host}")
        print(f"    Port:     {li.port}")
        print(f"    Token:    {li.auth_token}")
        sessions = li.list_sessions()
        alive = [s for s in sessions if s.get('alive', False)]
        print(f"    Sessions: {len(alive)} active, {len(sessions)} total")

    # ── Sessions ────────────────────────────────────────────────────

    def do_list_sessions(self):
        sessions = self.listener.list_sessions()
        if not sessions:
            print("\n  No sessions.")
            return
        print(f"\n  {'ID':<14} {'Device':<20} {'Android':<10} {'UID':<6} {'Uptime':<10} {'Cmds':<6} {'Status'}")
        print(f"  {'-'*80}")
        for s in sessions:
            uptime_m = s.get('uptime', 0) // 60
            status = 'ALIVE' if s.get('alive') else 'DEAD'
            print(f"  {s['session_id']:<14} {s['device']:<20} {s['android']:<10} "
                  f"{s['uid']:<6} {uptime_m}m{'':<7} {s.get('commands_executed', 0):<6} {status}")

    def do_interactive_shell(self):
        sid = self._pick_session()
        if not sid:
            return
        session = self._get_session_obj(sid)
        if not session:
            return

        print(f"\n  Interactive shell — {session.device_name} (Android {session.android_version})")
        print(f"  Type 'exit' or Ctrl+C to leave.\n")

        while session.alive:
            try:
                cmd = input(f"  {session.device_name}$ ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            if cmd.lower() in ('exit', 'quit'):
                break

            result = session.execute(cmd, timeout=30)
            if result['stdout']:
                for line in result['stdout'].rstrip('\n').split('\n'):
                    print(f"  {line}")
            if result['stderr']:
                for line in result['stderr'].rstrip('\n').split('\n'):
                    print(f"  [stderr] {line}")
            if result['exit_code'] != 0:
                print(f"  [exit code: {result['exit_code']}]")

    def do_execute_command(self):
        sid = self._pick_session()
        if not sid:
            return
        session = self._get_session_obj(sid)
        if not session:
            return
        try:
            cmd = input("  Command: ").strip()
            timeout_s = input("  Timeout [30]: ").strip() or '30'
        except (EOFError, KeyboardInterrupt):
            return
        if not cmd:
            return

        print(f"  Executing on {session.device_name}...")
        result = session.execute(cmd, timeout=int(timeout_s))
        if result['stdout']:
            print(f"\n  --- stdout ---")
            for line in result['stdout'].rstrip('\n').split('\n'):
                print(f"  {line}")
        if result['stderr']:
            print(f"\n  --- stderr ---")
            for line in result['stderr'].rstrip('\n').split('\n'):
                print(f"  {line}")
        print(f"\n  Exit code: {result['exit_code']}")

    def do_disconnect_session(self):
        sid = self._pick_session("  Session to disconnect #: ")
        if not sid:
            return
        self.listener.remove_session(sid)
        print(f"  Session {sid} disconnected.")

    # ── Device Info ─────────────────────────────────────────────────

    def _run_special(self, label, method_name, **kwargs):
        sid = self._pick_session()
        if not sid:
            return
        session = self._get_session_obj(sid)
        if not session:
            return
        print(f"  Fetching {label} from {session.device_name}...")
        method = getattr(session, method_name)
        result = method(**kwargs)
        if result.get('exit_code', -1) == 0:
            output = result.get('stdout', '')
            if output:
                for line in output.rstrip('\n').split('\n'):
                    print(f"  {line}")
            else:
                print(f"  (no output)")
        else:
            print(f"  Error: {result.get('stderr', 'Failed')}")

    def do_sysinfo(self):
        self._run_special("system info", "sysinfo")

    def do_packages(self):
        self._run_special("packages", "packages")

    def do_processes(self):
        self._run_special("processes", "processes")

    def do_netstat(self):
        self._run_special("network connections", "netstat")

    def do_logcat(self):
        try:
            lines = input("  Lines [100]: ").strip() or '100'
        except (EOFError, KeyboardInterrupt):
            return
        sid = self._pick_session()
        if not sid:
            return
        session = self._get_session_obj(sid)
        if not session:
            return
        print(f"  Fetching logcat ({lines} lines) from {session.device_name}...")
        result = session.dumplog(lines=int(lines))
        if result.get('exit_code', -1) == 0:
            output = result.get('stdout', '')
            if output:
                for line in output.rstrip('\n').split('\n'):
                    print(f"  {line}")
        else:
            print(f"  Error: {result.get('stderr', 'Failed')}")

    # ── Capture ─────────────────────────────────────────────────────

    def do_screenshot(self):
        sid = self._pick_session()
        if not sid:
            return
        print(f"  Taking screenshot...")
        filepath = self.listener.save_screenshot(sid)
        if filepath:
            print(f"  Saved: {filepath}")
        else:
            print(f"  Screenshot failed.")

    def do_download(self):
        sid = self._pick_session()
        if not sid:
            return
        try:
            remote_path = input("  Remote file path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not remote_path:
            return
        print(f"  Downloading {remote_path}...")
        filepath = self.listener.save_download(sid, remote_path)
        if filepath:
            print(f"  Saved: {filepath}")
        else:
            print(f"  Download failed.")

    def do_upload(self):
        sid = self._pick_session()
        if not sid:
            return
        try:
            local_path = input("  Local file path: ").strip()
            remote_path = input("  Remote destination: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not local_path or not remote_path:
            return
        if not Path(local_path).exists():
            print(f"  Local file not found: {local_path}")
            return

        session = self._get_session_obj(sid)
        if not session:
            return
        print(f"  Uploading to {remote_path}...")
        result = session.upload(local_path, remote_path)
        if result.get('exit_code', -1) == 0:
            print(f"  Upload complete.")
        else:
            print(f"  Error: {result.get('stderr', 'Failed')}")

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
                '1': self.do_start,
                '2': self.do_stop,
                '3': self.do_status,
                '10': self.do_list_sessions,
                '11': self.do_interactive_shell,
                '12': self.do_execute_command,
                '13': self.do_disconnect_session,
                '20': self.do_sysinfo,
                '21': self.do_packages,
                '22': self.do_processes,
                '23': self.do_netstat,
                '24': self.do_logcat,
                '30': self.do_screenshot,
                '31': self.do_download,
                '32': self.do_upload,
            }
            action = actions.get(choice)
            if action:
                action()
            else:
                print("  Invalid choice.")


def run():
    mgr = RevShellManager()
    mgr.run_interactive()
