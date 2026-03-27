"""
Hardware Remote - Remote physical device access via web UI
Devices connected to the AUTARCH server are accessible through the web browser.
"""

DESCRIPTION = "Remote physical device access (via web UI)"
AUTHOR = "AUTARCH"
VERSION = "1.0"
CATEGORY = "hardware"


def run():
    print("\n  Hardware Remote Access")
    print("  " + "=" * 40)
    print("  Remote hardware access is available through the web UI.")
    print("  Devices plugged into this server (USB/Serial) can be")
    print("  managed remotely via your browser.")
    print()
    print("  Start the web server with: python3 autarch.py --web")
    print("  Then navigate to: http://<server-ip>:5000/hardware")
    print()
    print("  Supported devices:")
    print("    - Android (ADB/Fastboot)")
    print("    - ESP32 (Serial flash/monitor)")
    print()
