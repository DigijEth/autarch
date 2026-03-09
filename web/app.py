"""
AUTARCH Web Application Factory
Flask-based web dashboard for the AUTARCH security platform
"""

import os
import sys
from pathlib import Path
from flask import Flask

# Ensure framework is importable
if getattr(sys, 'frozen', False):
    FRAMEWORK_DIR = Path(sys._MEIPASS)
else:
    FRAMEWORK_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(FRAMEWORK_DIR))


def create_app():
    # In frozen builds, templates/static are inside _MEIPASS, not next to __file__
    bundle_web = FRAMEWORK_DIR / 'web'
    app = Flask(
        __name__,
        template_folder=str(bundle_web / 'templates'),
        static_folder=str(bundle_web / 'static')
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
    from web.routes.llm_trainer import llm_trainer_bp
    from web.routes.autonomy import autonomy_bp
    from web.routes.loadtest import loadtest_bp
    from web.routes.phishmail import phishmail_bp
    from web.routes.dns_service import dns_service_bp
    from web.routes.ipcapture import ipcapture_bp
    from web.routes.hack_hijack import hack_hijack_bp
    from web.routes.password_toolkit import password_toolkit_bp
    from web.routes.webapp_scanner import webapp_scanner_bp
    from web.routes.report_engine import report_engine_bp
    from web.routes.net_mapper import net_mapper_bp
    from web.routes.c2_framework import c2_framework_bp
    from web.routes.wifi_audit import wifi_audit_bp
    from web.routes.threat_intel import threat_intel_bp
    from web.routes.steganography import steganography_bp
    from web.routes.api_fuzzer import api_fuzzer_bp
    from web.routes.ble_scanner import ble_scanner_bp
    from web.routes.forensics import forensics_bp
    from web.routes.rfid_tools import rfid_tools_bp
    from web.routes.cloud_scan import cloud_scan_bp
    from web.routes.malware_sandbox import malware_sandbox_bp
    from web.routes.log_correlator import log_correlator_bp
    from web.routes.anti_forensics import anti_forensics_bp
    from web.routes.vuln_scanner import vuln_scanner_bp
    from web.routes.social_eng import social_eng_bp
    from web.routes.deauth import deauth_bp
    from web.routes.exploit_dev import exploit_dev_bp
    from web.routes.ad_audit import ad_audit_bp
    from web.routes.container_sec import container_sec_bp
    from web.routes.sdr_tools import sdr_tools_bp
    from web.routes.reverse_eng import reverse_eng_bp
    from web.routes.email_sec import email_sec_bp
    from web.routes.mitm_proxy import mitm_proxy_bp
    from web.routes.pineapple import pineapple_bp
    from web.routes.incident_resp import incident_resp_bp
    from web.routes.sms_forge import sms_forge_bp
    from web.routes.starlink_hack import starlink_hack_bp
    from web.routes.rcs_tools import rcs_tools_bp
    from web.routes.port_scanner import port_scanner_bp

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
    app.register_blueprint(llm_trainer_bp)
    app.register_blueprint(autonomy_bp)
    app.register_blueprint(loadtest_bp)
    app.register_blueprint(phishmail_bp)
    app.register_blueprint(dns_service_bp)
    app.register_blueprint(ipcapture_bp)
    app.register_blueprint(hack_hijack_bp)
    app.register_blueprint(password_toolkit_bp)
    app.register_blueprint(webapp_scanner_bp)
    app.register_blueprint(report_engine_bp)
    app.register_blueprint(net_mapper_bp)
    app.register_blueprint(c2_framework_bp)
    app.register_blueprint(wifi_audit_bp)
    app.register_blueprint(threat_intel_bp)
    app.register_blueprint(steganography_bp)
    app.register_blueprint(api_fuzzer_bp)
    app.register_blueprint(ble_scanner_bp)
    app.register_blueprint(forensics_bp)
    app.register_blueprint(rfid_tools_bp)
    app.register_blueprint(cloud_scan_bp)
    app.register_blueprint(malware_sandbox_bp)
    app.register_blueprint(log_correlator_bp)
    app.register_blueprint(anti_forensics_bp)
    app.register_blueprint(vuln_scanner_bp)
    app.register_blueprint(social_eng_bp)
    app.register_blueprint(deauth_bp)
    app.register_blueprint(exploit_dev_bp)
    app.register_blueprint(ad_audit_bp)
    app.register_blueprint(sdr_tools_bp)
    app.register_blueprint(reverse_eng_bp)
    app.register_blueprint(container_sec_bp)
    app.register_blueprint(email_sec_bp)
    app.register_blueprint(mitm_proxy_bp)
    app.register_blueprint(pineapple_bp)
    app.register_blueprint(incident_resp_bp)
    app.register_blueprint(sms_forge_bp)
    app.register_blueprint(starlink_hack_bp)
    app.register_blueprint(rcs_tools_bp)
    app.register_blueprint(port_scanner_bp)

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
