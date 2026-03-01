"""
AUTARCH Web Application Factory
Flask-based web dashboard for the AUTARCH security platform
"""

import os
import sys
from pathlib import Path
from flask import Flask

# Ensure framework is importable
FRAMEWORK_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(FRAMEWORK_DIR))


def create_app():
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / 'templates'),
        static_folder=str(Path(__file__).parent / 'static')
    )

    # Config
    from core.config import get_config
    config = get_config()

    app.secret_key = config.get('web', 'secret_key', fallback=None) or os.urandom(32).hex()

    # Upload config
    from core.paths import get_uploads_dir
    upload_dir = str(get_uploads_dir())
    os.makedirs(upload_dir, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_dir
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

    # Store config on app for route access
    app.autarch_config = config

    # Register blueprints
    from web.routes.auth_routes import auth_bp
    from web.routes.dashboard import dashboard_bp
    from web.routes.defense import defense_bp
    from web.routes.offense import offense_bp
    from web.routes.counter import counter_bp
    from web.routes.analyze import analyze_bp
    from web.routes.osint import osint_bp
    from web.routes.simulate import simulate_bp
    from web.routes.settings import settings_bp
    from web.routes.upnp import upnp_bp
    from web.routes.wireshark import wireshark_bp
    from web.routes.hardware import hardware_bp
    from web.routes.android_exploit import android_exploit_bp
    from web.routes.iphone_exploit import iphone_exploit_bp
    from web.routes.android_protect import android_protect_bp
    from web.routes.wireguard import wireguard_bp
    from web.routes.revshell import revshell_bp
    from web.routes.archon import archon_bp
    from web.routes.msf import msf_bp
    from web.routes.chat import chat_bp
    from web.routes.targets import targets_bp
    from web.routes.encmodules import encmodules_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(defense_bp)
    app.register_blueprint(offense_bp)
    app.register_blueprint(counter_bp)
    app.register_blueprint(analyze_bp)
    app.register_blueprint(osint_bp)
    app.register_blueprint(simulate_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(upnp_bp)
    app.register_blueprint(wireshark_bp)
    app.register_blueprint(hardware_bp)
    app.register_blueprint(android_exploit_bp)
    app.register_blueprint(iphone_exploit_bp)
    app.register_blueprint(android_protect_bp)
    app.register_blueprint(wireguard_bp)
    app.register_blueprint(revshell_bp)
    app.register_blueprint(archon_bp)
    app.register_blueprint(msf_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(targets_bp)
    app.register_blueprint(encmodules_bp)

    # Start network discovery advertising (mDNS + Bluetooth)
    try:
        from core.discovery import get_discovery_manager
        enabled = config.get('discovery', 'enabled', fallback='true').lower() == 'true'
        if enabled:
            discovery = get_discovery_manager()
            results = discovery.start_all()
            for method, result in results.items():
                if result['ok']:
                    print(f"  [discovery] {method}: {result['message']}")
    except Exception as e:
        print(f"  [discovery] Warning: {e}")

    return app
