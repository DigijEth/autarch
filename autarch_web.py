"""AUTARCH Web Launcher — double-click to start the web dashboard with system tray.

This is the entry point for autarch_web.exe (no console window).
It starts the Flask web server and shows a system tray icon for control.
"""

import sys
import os
from pathlib import Path

# Ensure framework is importable
if getattr(sys, 'frozen', False):
    FRAMEWORK_DIR = Path(sys._MEIPASS)
else:
    FRAMEWORK_DIR = Path(__file__).parent
sys.path.insert(0, str(FRAMEWORK_DIR))


def main():
    from web.app import create_app
    from core.config import get_config
    from core.paths import get_data_dir

    config = get_config()
    app = create_app()
    host = config.get('web', 'host', fallback='0.0.0.0')
    port = config.get_int('web', 'port', fallback=8181)

    # Auto-generate self-signed TLS cert
    ssl_ctx = None
    use_https = config.get('web', 'https', fallback='true').lower() != 'false'
    if use_https:
        import subprocess
        cert_dir = os.path.join(get_data_dir(), 'certs')
        os.makedirs(cert_dir, exist_ok=True)
        cert_path = os.path.join(cert_dir, 'autarch.crt')
        key_path = os.path.join(cert_dir, 'autarch.key')
        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            try:
                subprocess.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', key_path, '-out', cert_path,
                    '-days', '3650', '-nodes',
                    '-subj', '/CN=AUTARCH/O=darkHal',
                ], check=True, capture_output=True)
            except Exception:
                use_https = False
        if use_https:
            ssl_ctx = (cert_path, key_path)

    # Try system tray mode (preferred — no console window needed)
    try:
        from core.tray import TrayManager, TRAY_AVAILABLE
        if TRAY_AVAILABLE:
            tray = TrayManager(app, host, port, ssl_context=ssl_ctx)
            tray.run()
            return
    except Exception:
        pass

    # Fallback: run Flask directly
    app.run(host=host, port=port, debug=False, ssl_context=ssl_ctx)


if __name__ == "__main__":
    main()
