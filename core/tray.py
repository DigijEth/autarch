"""AUTARCH System Tray Icon

Provides a taskbar/system tray icon with Start, Stop, Restart, Open Dashboard,
and Exit controls for the web dashboard.

Requires: pystray, Pillow
"""

import sys
import threading
import webbrowser
from pathlib import Path

try:
    import pystray
    from PIL import Image, ImageDraw, ImageFont
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


def _get_icon_path():
    """Find the .ico file — works in both source and frozen (PyInstaller) builds."""
    if getattr(sys, 'frozen', False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).parent.parent
    ico = base / 'autarch.ico'
    if ico.exists():
        return ico
    return None


def create_icon_image(size=64):
    """Load tray icon from .ico file, falling back to programmatic generation."""
    ico_path = _get_icon_path()
    if ico_path:
        try:
            img = Image.open(str(ico_path))
            img = img.resize((size, size), Image.LANCZOS)
            return img.convert('RGBA')
        except Exception:
            pass

    # Fallback: generate programmatically
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([1, 1, size - 2, size - 2], fill=(15, 15, 25, 255),
                 outline=(0, 180, 255, 255), width=2)
    try:
        font = ImageFont.truetype("arial.ttf", int(size * 0.5))
    except OSError:
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "A", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (size - tw) // 2
    y = (size - th) // 2 - bbox[1]
    draw.text((x, y), "A", fill=(0, 200, 255, 255), font=font)
    return img


class TrayManager:
    """Manages the system tray icon and Flask server lifecycle."""

    def __init__(self, app, host, port, ssl_context=None):
        self.app = app
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self._server = None
        self._thread = None
        self.running = False
        self._icon = None
        self._proto = 'https' if ssl_context else 'http'

    def start_server(self):
        """Start the Flask web server in a background thread."""
        if self.running:
            return

        from werkzeug.serving import make_server
        self._server = make_server(self.host, self.port, self.app, threaded=True)

        if self.ssl_context:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.ssl_context[0], self.ssl_context[1])
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)

        self.running = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop_server(self):
        """Stop the Flask web server."""
        if not self.running or not self._server:
            return
        self._server.shutdown()
        self._server = None
        self._thread = None
        self.running = False

    def restart_server(self):
        """Stop and restart the Flask web server."""
        self.stop_server()
        self.start_server()

    def open_browser(self):
        """Open the dashboard in the default web browser."""
        if self.running:
            host = 'localhost' if self.host in ('0.0.0.0', '::') else self.host
            webbrowser.open(f"{self._proto}://{host}:{self.port}")

    def quit(self):
        """Stop server and exit the tray icon."""
        self.stop_server()
        if self._icon:
            self._icon.stop()

    def run(self):
        """Start server and show tray icon. Blocks until Exit is clicked."""
        if not TRAY_AVAILABLE:
            raise RuntimeError("pystray or Pillow not installed")

        self.start_server()

        image = create_icon_image()
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: f"AUTARCH — {'Running' if self.running else 'Stopped'}",
                None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Start", lambda: self.start_server(),
                             enabled=lambda item: not self.running),
            pystray.MenuItem("Stop", lambda: self.stop_server(),
                             enabled=lambda item: self.running),
            pystray.MenuItem("Restart", lambda: self.restart_server(),
                             enabled=lambda item: self.running),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Dashboard", lambda: self.open_browser(),
                             enabled=lambda item: self.running, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", lambda: self.quit()),
        )

        self._icon = pystray.Icon("autarch", image, "AUTARCH", menu=menu)
        self._icon.run()  # Blocks until quit()
