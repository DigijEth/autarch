#!/usr/bin/env python3
"""AUTARCH Desktop Launcher"""

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GdkPixbuf, GLib, Pango
import subprocess, os, sys, signal, configparser, json, threading, time
from pathlib import Path

DIR = Path(__file__).parent
CONF = DIR / 'autarch_settings.conf'
LOGO = DIR / 'assets' / 'logo.png'
SPLASH_FLAG = DIR / 'data' / '.splash_accepted'
VENV_PY = DIR / 'venv' / 'bin' / 'python'
SYS_PY = 'python3'
DAEMON_SOCK = '/var/run/autarch-daemon.sock'

_web_proc = None
_daemon_proc = None


def get_py():
    return str(VENV_PY) if VENV_PY.exists() else SYS_PY


def is_daemon_running():
    return os.path.exists(DAEMON_SOCK)


def is_web_running():
    global _web_proc
    return _web_proc is not None and _web_proc.poll() is None


def start_daemon():
    global _daemon_proc
    if is_daemon_running():
        return True
    try:
        py = get_py()
        daemon_script = str(DIR / 'core' / 'daemon.py')

        if os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
            # Use pkexec with a wrapper that backgrounds the daemon.
            # pkexec runs the command and waits, so we use bash -c to fork it.
            _daemon_proc = subprocess.Popen([
                'pkexec', 'bash', '-c',
                f'{py} {daemon_script} &'
            ])
            # Wait for pkexec to finish (just the auth + fork, not the daemon itself)
            _daemon_proc.wait(timeout=60)
        else:
            _daemon_proc = subprocess.Popen(['sudo', py, daemon_script])

        # Give the daemon a moment to create the socket
        for _ in range(10):
            time.sleep(0.5)
            if is_daemon_running():
                return True
        return is_daemon_running()
    except subprocess.TimeoutExpired:
        # User took too long on password dialog — that's ok
        return is_daemon_running()
    except Exception:
        return False


def stop_daemon():
    global _daemon_proc
    # Read PID from pidfile and kill it — one pkexec prompt max
    pid = None
    try:
        with open('/var/run/autarch-daemon.pid') as f:
            pid = int(f.read().strip())
    except Exception:
        pass

    if pid:
        # Single elevated call to kill the daemon — it cleans up its own files on shutdown
        _elevate(['kill', str(pid)])
        # Wait for it to actually die
        for _ in range(10):
            time.sleep(0.3)
            if not is_daemon_running():
                break
    elif is_daemon_running():
        _elevate(['pkill', '-f', 'core/daemon.py'])

    _daemon_proc = None


def _elevate(cmd):
    """Run a command with root privileges using pkexec (GUI) or sudo (terminal)."""
    if os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'):
        return subprocess.run(['pkexec'] + cmd, capture_output=True)
    return subprocess.run(['sudo'] + cmd, capture_output=True)


def start_web():
    global _web_proc
    if is_web_running():
        return True
    _web_proc = subprocess.Popen([get_py(), str(DIR / 'autarch.py'), '--web', '--no-banner'])
    return True


def stop_web():
    global _web_proc
    if _web_proc:
        _web_proc.terminate()
        try:
            _web_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _web_proc.kill()
    _web_proc = None
    subprocess.run(['pkill', '-f', 'autarch.py --web'], capture_output=True)


def stop_all():
    stop_web()
    stop_daemon()


# ── Splash Screen ─────────────────────────────────────────────────────────────

EULA_TEXT = """AUTARCH — Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking
By darkHal Security Group & Setec Security Labs

END USER LICENSE AGREEMENT

1. DISCLAIMER OF WARRANTY
This software is provided "AS IS" without warranty of any kind, express or implied. The authors make no guarantees regarding functionality, reliability, or fitness for any particular purpose. Use at your own risk.

2. LIMITATION OF LIABILITY
In no event shall darkHal Security Group, Setec Security Labs, or any contributors be held liable for any damages whatsoever arising from the use of this software, including but not limited to direct, indirect, incidental, special, or consequential damages.

3. AUTHORIZED USE ONLY
This software is designed for authorized security testing and research. You are solely responsible for ensuring you have proper authorization before testing any system. Unauthorized access to computer systems is illegal.

4. LICENSE
Unless otherwise noted on a module, tool, addon, or extension:
  • This software is FREE for personal/home use
  • This software is FREE to give away (unmodified) for home use
  • Commercial use is NOT permitted without a commercial license
  • Government use is PROHIBITED — however, a single-day user license may be purchased for the deed to half of the United States of America, or $10,000 USD per minute of use, whichever is greater

5. NO RESPONSIBILITY
We are not responsible for what you do with this software. If you break the law, that's on you. If you get caught, that's also on you. We told you not to do it.
"""

PRIVACY_TEXT = """PRIVACY POLICY & ACKNOWLEDGEMENTS

COOKIES & DATA COLLECTION
AUTARCH does not collect, transmit, or sell any user data. All data stays on your machine. There are no analytics, telemetry, tracking pixels, or phone-home features. We don't want your data. We have enough of our own problems.

This policy complies with GDPR (EU), CCPA (California), PIPEDA (Canada), LGPD (Brazil), POPIA (South Africa), and every other privacy regulation because the answer to "what data do you collect?" is "none."

THIRD-PARTY ACKNOWLEDGEMENTS
All rights reserved © Setec Security Labs 2020–2026.

AUTARCH is built with the help of outstanding open-source projects. We are NOT affiliated with any of the following organizations. All trademarks belong to their respective owners:

• Python™ is managed by the Python Software Foundation (PSF)
• Java™ is a trademark of Oracle Corporation (originally Sun Microsystems)
• Flask is created by Armin Ronacher / Pallets Projects
• llama.cpp is created by Georgi Gerganov
• Anthropic, Claude, and the Claude API are trademarks of Anthropic, PBC
• OpenAI and GPT are trademarks of OpenAI, Inc.
• HuggingFace and Transformers are trademarks of Hugging Face, Inc.
• Metasploit is a trademark of Rapid7, Inc.
• Nmap is created by Gordon Lyon (Fyodor)
• Wireshark is a trademark of the Wireshark Foundation
• WireGuard is a trademark of Jason A. Donenfeld
• Scapy is created by Philippe Biondi
• Node.js is a trademark of the OpenJS Foundation
• Go is a trademark of Google LLC
• Android is a trademark of Google LLC
• Linux is a trademark of Linus Torvalds
• Raspberry Pi is a trademark of Raspberry Pi Ltd

PLEASE SUPPORT THESE PROJECTS
If you find AUTARCH useful, consider donating to the open-source projects that make it possible. They do the hard work. We just glued it together.

• Python: python.org/psf/donations
• Flask: palletsprojects.com
• llama.cpp: github.com/ggml-org/llama.cpp
• Nmap: nmap.org
• Wireshark: wireshark.org
• Scapy: scapy.net

All rights reserved © Setec Security Labs 2020–2026
"""


class SplashScreen(Gtk.Window):
    def __init__(self, on_accept):
        super().__init__(title="AUTARCH")
        self.on_accept = on_accept
        self.set_default_size(600, 700)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.set_resizable(False)
        # Don't quit the app when splash closes — we open the launcher next
        self.connect('delete-event', lambda w, e: Gtk.main_quit() or False)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        box.override_background_color(Gtk.StateFlags.NORMAL, _rgba(0.08, 0.08, 0.1, 1))
        self.add(box)

        # Logo
        if LOGO.exists():
            pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(LOGO), 200, 200, True)
            img = Gtk.Image.new_from_pixbuf(pb)
            img.set_margin_top(20)
            box.pack_start(img, False, False, 0)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.SLIDE_LEFT)
        box.pack_start(self.stack, True, True, 0)

        # Page 1: EULA
        self.stack.add_named(self._make_eula_page(), 'eula')
        # Page 2: Privacy
        self.stack.add_named(self._make_privacy_page(), 'privacy')

        self.show_all()

    def _make_scroll_text(self, text, on_scroll_end=None):
        frame = Gtk.Frame()
        frame.set_margin_start(20); frame.set_margin_end(20); frame.set_margin_top(10)
        sw = Gtk.ScrolledWindow()
        sw.set_min_content_height(350)
        tv = Gtk.TextView()
        tv.set_editable(False); tv.set_wrap_mode(Gtk.WrapMode.WORD)
        tv.set_left_margin(12); tv.set_right_margin(12); tv.set_top_margin(8)
        tv.override_background_color(Gtk.StateFlags.NORMAL, _rgba(0.06, 0.06, 0.08, 1))
        tv.override_color(Gtk.StateFlags.NORMAL, _rgba(0.7, 0.7, 0.7, 1))
        tv.override_font(Pango.FontDescription('monospace 9'))
        tv.get_buffer().set_text(text)
        sw.add(tv)
        frame.add(sw)
        if on_scroll_end:
            adj = sw.get_vadjustment()
            adj.connect('value-changed', lambda a: on_scroll_end() if a.get_value() >= a.get_upper() - a.get_page_size() - 10 else None)
        return frame

    def _make_eula_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        page.pack_start(self._make_scroll_text(EULA_TEXT), True, True, 0)
        btnbox = Gtk.Box(spacing=12)
        btnbox.set_halign(Gtk.Align.CENTER); btnbox.set_margin_bottom(15); btnbox.set_margin_top(8)
        accept = Gtk.Button(label="I Accept")
        accept.get_style_context().add_class('suggested-action')
        accept.connect('clicked', self._on_accept_eula)
        screw = Gtk.Button(label="Screw This Shit")
        screw.get_style_context().add_class('destructive-action')
        screw.connect('clicked', self._on_reject)
        btnbox.pack_start(screw, False, False, 0)
        btnbox.pack_start(accept, False, False, 0)
        page.pack_start(btnbox, False, False, 0)
        return page

    def _make_privacy_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        lbl = Gtk.Label(label="↓ Scroll to the bottom to continue ↓")
        lbl.override_color(Gtk.StateFlags.NORMAL, _rgba(0.4, 0.9, 0.4, 1))
        lbl.set_margin_top(5)
        page.pack_start(lbl, False, False, 0)
        self._next_btn = Gtk.Button(label="Next →")
        self._next_btn.get_style_context().add_class('suggested-action')
        self._next_btn.set_sensitive(False)
        self._next_btn.connect('clicked', self._on_next)
        page.pack_start(self._make_scroll_text(PRIVACY_TEXT, on_scroll_end=lambda: self._next_btn.set_sensitive(True)), True, True, 0)
        btnbox = Gtk.Box(); btnbox.set_halign(Gtk.Align.CENTER); btnbox.set_margin_bottom(15); btnbox.set_margin_top(8)
        btnbox.pack_start(self._next_btn, False, False, 0)
        page.pack_start(btnbox, False, False, 0)
        return page

    def _on_accept_eula(self, btn):
        self.stack.set_visible_child_name('privacy')

    def _on_reject(self, btn):
        d = Gtk.MessageDialog(parent=self, modal=True, message_type=Gtk.MessageType.QUESTION,
                              buttons=Gtk.ButtonsType.YES_NO,
                              text="Really? You're going to pass on this masterpiece?")
        d.format_secondary_text("Your loss. The internet will remain unprotected. Are you sure you want to quit?")
        resp = d.run(); d.destroy()
        if resp == Gtk.ResponseType.YES:
            Gtk.main_quit()

    def _on_next(self, btn):
        SPLASH_FLAG.parent.mkdir(parents=True, exist_ok=True)
        SPLASH_FLAG.write_text('accepted')
        self.destroy()
        self.on_accept()


# ── Main Launcher Window ──────────────────────────────────────────────────────

class LauncherWindow(Gtk.Window):
    def __init__(self):
        super().__init__(title="AUTARCH Launcher")
        self.set_default_size(500, 420)
        self.set_position(Gtk.WindowPosition.CENTER)
        self.connect('destroy', self._on_quit)

        # Set window icon
        icon_svg = DIR / 'icon.svg'
        if icon_svg.exists():
            try:
                self.set_icon_from_file(str(icon_svg))
            except Exception:
                pass

        main = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        main.override_background_color(Gtk.StateFlags.NORMAL, _rgba(0.08, 0.08, 0.1, 1))
        self.add(main)

        # Header
        if LOGO.exists():
            pb = GdkPixbuf.Pixbuf.new_from_file_at_scale(str(LOGO), 64, 64, True)
            hbox = Gtk.Box(spacing=10); hbox.set_margin_top(12); hbox.set_margin_start(15)
            hbox.pack_start(Gtk.Image.new_from_pixbuf(pb), False, False, 0)
            lbl = Gtk.Label(); lbl.set_markup('<span size="x-large" weight="bold" color="#00ff41">AUTARCH</span>\n<span size="small" color="#888">Security Platform</span>')
            hbox.pack_start(lbl, False, False, 0)
            main.pack_start(hbox, False, False, 0)

        # Status bar
        self.status = Gtk.Label(label="Stopped")
        self.status.set_margin_top(8); self.status.set_margin_bottom(4)
        self.status.override_color(Gtk.StateFlags.NORMAL, _rgba(0.6, 0.6, 0.6, 1))
        main.pack_start(self.status, False, False, 0)

        # Buttons
        grid = Gtk.Grid(column_spacing=10, row_spacing=10)
        grid.set_halign(Gtk.Align.CENTER); grid.set_margin_top(10); grid.set_margin_bottom(10)

        self.btn_start = self._btn("▶ Start All", self._on_start, '#00ff41')
        self.btn_stop = self._btn("■ Stop All", self._on_stop, '#ff3b30')
        self.btn_reload = self._btn("↻ Reload", self._on_reload, '#f59e0b')
        self.btn_web = self._btn("Web Server", self._on_start_web, '#5ac8fa')
        self.btn_daemon = self._btn("Daemon", self._on_start_daemon, '#5ac8fa')

        grid.attach(self.btn_start, 0, 0, 2, 1)
        grid.attach(self.btn_stop, 2, 0, 1, 1)
        grid.attach(self.btn_reload, 0, 1, 1, 1)
        grid.attach(self.btn_web, 1, 1, 1, 1)
        grid.attach(self.btn_daemon, 2, 1, 1, 1)
        main.pack_start(grid, False, False, 0)

        # Settings tabs
        nb = Gtk.Notebook()
        nb.set_margin_start(10); nb.set_margin_end(10); nb.set_margin_bottom(10)
        nb.append_page(self._make_web_settings(), Gtk.Label(label="AUTARCH WebUI"))
        nb.append_page(self._make_daemon_settings(), Gtk.Label(label="AUTARCH Daemon"))
        main.pack_start(nb, True, True, 0)

        self._refresh_status()
        GLib.timeout_add_seconds(3, self._refresh_status)
        self.show_all()

    def _btn(self, label, callback, color):
        b = Gtk.Button(label=label)
        b.connect('clicked', callback)
        b.set_size_request(140, 36)
        return b

    def _make_web_settings(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_start(8); box.set_margin_end(8); box.set_margin_top(8)

        self.cfg = configparser.ConfigParser()
        if CONF.exists():
            self.cfg.read(str(CONF))

        grid = Gtk.Grid(column_spacing=10, row_spacing=6)
        self.web_entries = {}
        fields = [('web', 'host', 'Listen Host'), ('web', 'port', 'Listen Port'),
                  ('web', 'mcp_port', 'MCP Port'), ('revshell', 'port', 'RevShell Port')]
        for i, (sec, key, label) in enumerate(fields):
            grid.attach(Gtk.Label(label=label, xalign=0), 0, i, 1, 1)
            e = Gtk.Entry(); e.set_text(self.cfg.get(sec, key, fallback=''))
            e.set_width_chars(20)
            self.web_entries[(sec, key)] = e
            grid.attach(e, 1, i, 1, 1)

        box.pack_start(grid, False, False, 0)
        save = Gtk.Button(label="Save Settings")
        save.connect('clicked', self._save_web_settings)
        save.set_halign(Gtk.Align.START); save.set_margin_top(6)
        box.pack_start(save, False, False, 0)
        return box

    def _make_daemon_settings(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_start(8); box.set_margin_end(8); box.set_margin_top(8)

        lbl = Gtk.Label()
        lbl.set_markup('<span color="#f59e0b">⚠ Only edit if you know what you are doing</span>')
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # Whitelist editor
        edit_btn = Gtk.Button(label="Edit Command Whitelist")
        edit_btn.connect('clicked', self._edit_whitelist)
        box.pack_start(edit_btn, False, False, 0)

        # Socket path display
        hb = Gtk.Box(spacing=6)
        hb.pack_start(Gtk.Label(label="Socket:", xalign=0), False, False, 0)
        hb.pack_start(Gtk.Label(label=DAEMON_SOCK), False, False, 0)
        box.pack_start(hb, False, False, 0)

        return box

    def _save_web_settings(self, btn):
        for (sec, key), entry in self.web_entries.items():
            if not self.cfg.has_section(sec):
                self.cfg.add_section(sec)
            self.cfg.set(sec, key, entry.get_text())
        with open(CONF, 'w') as f:
            self.cfg.write(f)
        self.status.set_text("Settings saved")

    def _edit_whitelist(self, btn):
        # Read current whitelist from daemon.py
        daemon_py = DIR / 'core' / 'daemon.py'
        import re
        src = daemon_py.read_text()
        m = re.search(r'ALLOWED_COMMANDS\s*=\s*\{([^}]+)\}', src, re.DOTALL)
        if not m:
            return
        cmds = sorted(c.strip().strip("'\"") for c in m.group(1).split(',') if c.strip().strip("'\""))

        d = Gtk.Dialog(title="Command Whitelist", parent=self, modal=True)
        d.set_default_size(400, 400)
        d.add_button("Cancel", Gtk.ResponseType.CANCEL)
        d.add_button("Save", Gtk.ResponseType.OK)

        sw = Gtk.ScrolledWindow()
        tv = Gtk.TextView()
        tv.set_left_margin(8); tv.set_top_margin(8)
        tv.get_buffer().set_text('\n'.join(cmds))
        tv.override_font(Pango.FontDescription('monospace 10'))
        sw.add(tv)
        d.get_content_area().pack_start(sw, True, True, 0)
        d.show_all()

        if d.run() == Gtk.ResponseType.OK:
            buf = tv.get_buffer()
            text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
            new_cmds = sorted(set(c.strip() for c in text.split('\n') if c.strip()))
            new_set = '{\n' + ''.join(f"    '{c}',\n" for c in new_cmds) + '}'
            new_src = re.sub(r'ALLOWED_COMMANDS\s*=\s*\{[^}]+\}', f'ALLOWED_COMMANDS = {new_set}', src, count=1)
            daemon_py.write_text(new_src)
            self.status.set_text(f"Whitelist saved: {len(new_cmds)} commands")
        d.destroy()

    def _refresh_status(self):
        d = "●" if is_daemon_running() else "○"
        w = "●" if is_web_running() else "○"
        dc = "#00ff41" if is_daemon_running() else "#ff3b30"
        wc = "#00ff41" if is_web_running() else "#ff3b30"
        self.status.set_markup(
            f'<span color="{dc}">{d} Daemon</span>  '
            f'<span color="{wc}">{w} Web Server</span>'
        )
        return True  # keep timer

    def _on_start(self, btn):
        btn.set_sensitive(False)
        self.status.set_text("Starting daemon (enter password)...")
        # Run everything in a thread — pkexec is its own window, doesn't need the main thread
        threading.Thread(target=self._do_start_all, args=(btn,), daemon=True).start()

    def _do_start_all(self, btn):
        start_daemon()
        GLib.idle_add(self._refresh_status)
        start_web()
        GLib.idle_add(self._refresh_status)
        GLib.idle_add(lambda: btn.set_sensitive(True))

    def _on_stop(self, btn):
        btn.set_sensitive(False)
        self.status.set_text("Stopping...")
        threading.Thread(target=self._do_stop_all, args=(btn,), daemon=True).start()

    def _do_stop_all(self, btn):
        stop_all()
        GLib.idle_add(self._refresh_status)
        GLib.idle_add(lambda: btn.set_sensitive(True))

    def _on_reload(self, btn):
        btn.set_sensitive(False)
        self.status.set_text("Reloading...")
        def do_reload():
            stop_all()
            GLib.idle_add(self._refresh_status)
            GLib.idle_add(lambda: self.status.set_text("Waiting 5 seconds..."))
            time.sleep(5)
            GLib.idle_add(lambda: self.status.set_text("Starting daemon (enter password)..."))
            start_daemon()
            GLib.idle_add(self._refresh_status)
            start_web()
            GLib.idle_add(self._refresh_status)
            GLib.idle_add(lambda: btn.set_sensitive(True))
        threading.Thread(target=do_reload, daemon=True).start()

    def _on_start_web(self, btn):
        threading.Thread(target=lambda: (start_web(), GLib.idle_add(self._refresh_status)), daemon=True).start()

    def _on_start_daemon(self, btn):
        btn.set_sensitive(False)
        self.status.set_text("Starting daemon (enter password)...")
        def do():
            start_daemon()
            GLib.idle_add(self._refresh_status)
            GLib.idle_add(lambda: btn.set_sensitive(True))
        threading.Thread(target=do, daemon=True).start()

    def _on_quit(self, *a):
        # Only stop the web server (runs as user, no password needed)
        # Leave the daemon running — it's a system service
        stop_web()
        Gtk.main_quit()


def _rgba(r, g, b, a):
    from gi.repository import Gdk
    c = Gdk.RGBA(); c.red = r; c.green = g; c.blue = b; c.alpha = a
    return c


def main():
    def launch():
        win = LauncherWindow()

    if SPLASH_FLAG.exists():
        launch()
    else:
        SplashScreen(on_accept=launch)

    Gtk.main()


if __name__ == '__main__':
    main()
