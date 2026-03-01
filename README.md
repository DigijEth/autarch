# AUTARCH

**Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking**

By **darkHal Security Group** & **Setec Security Labs**

---

## Overview

AUTARCH is a modular security platform combining defensive hardening, offensive testing, forensic analysis, OSINT reconnaissance, and attack simulation into a single web-based dashboard. It features local and cloud LLM integration, an autonomous AI agent, hardware device management over WebUSB, and a companion Android application.

## Features

- **Defense** — System hardening audits, firewall checks, permission analysis, security scoring
- **Offense** — Metasploit & RouterSploit integration, module execution with live SSE streaming
- **Counter** — Threat detection, suspicious process analysis, rootkit checks, network monitoring
- **Analyze** — File forensics, hash toolkit (43 algorithm patterns), hex dumps, string extraction, log analysis
- **OSINT** — Email/username/phone/domain/IP reconnaissance, 7,287+ indexed sites
- **Simulate** — Attack simulation, port scanning, password auditing, payload generation
- **Hardware** — ADB/Fastboot over WebUSB, ESP32 flashing via Web Serial, dual-mode (server + direct)
- **Android Protection** — Anti-stalkerware/spyware shield, signature-based scanning, permission auditing
- **Agent Hal** — Autonomous AI agent with tool use, available as a global chat panel
- **Hash Toolkit** — Hash algorithm identification (hashid-style), file/text hashing, hash mutation, threat intel lookups
- **Enc Modules** — Encrypted module system for sensitive payloads
- **Reverse Shell** — Multi-language reverse shell generator
- **WireGuard VPN** — Tunnel management and remote device access
- **UPnP** — Automated port forwarding
- **Wireshark** — Packet capture and analysis via tshark/pyshark
- **MSF Console** — Web-based Metasploit console with live terminal
- **Debug Console** — Real-time Python logging output with 5 filter modes

## Architecture

```
autarch.py                  # Main entry point (CLI + web server)
core/                       # 25+ Python modules (agent, config, hardware, llm, msf, etc.)
modules/                    # 26 loadable modules (defense, offense, counter, analyze, osint, simulate)
web/
  app.py                    # Flask app factory (16 blueprints)
  routes/                   # 15 route files
  templates/                # 16 Jinja2 templates
  static/                   # JS, CSS, WebUSB bundles
autarch_companion/          # Archon Android app (Kotlin)
data/                       # SQLite DBs, JSON configs, stalkerware signatures
```

## Quick Start

### From Source

```bash
# Clone
git clone https://github.com/digijeth/autarch.git
cd autarch

# Install dependencies
pip install -r requirements.txt

# Run
python autarch.py
```

The web dashboard starts at `https://localhost:8080` (self-signed cert).

### Windows Installer

Download `autarch_public.msi` or `autarch_public.exe` from the [Releases](https://github.com/digijeth/autarch/releases) page.

## Configuration

Settings are managed via `autarch_settings.conf` (auto-generated on first run) and the web UI Settings page.

Key sections: `[server]`, `[llm]`, `[msf]`, `[wireguard]`, `[upnp]`, `[hardware]`

### LLM Backends

- **Local** — llama-cpp-python (GGUF models) or HuggingFace Transformers (SafeTensors)
- **Claude** — Anthropic Claude API
- **OpenAI** — OpenAI-compatible API (custom endpoint support)
- **HuggingFace** — HuggingFace Inference API (8 provider options)

## Ports

| Port  | Service |
|-------|---------|
| 8080  | Web Dashboard (HTTPS) |
| 8081  | MCP Server (SSE) |
| 17321 | Archon Server (Android companion) |
| 17322 | Reverse Shell Listener |
| 51820 | WireGuard VPN |

## Platform Support

- **Primary:** Linux (Orange Pi 5 Plus, RK3588 ARM64)
- **Supported:** Windows 10/11 (x86_64)
- **WebUSB:** Chromium-based browsers required for Direct mode hardware access

## Acknowledgements

AUTARCH builds on the work of many outstanding open-source projects. We thank and acknowledge them all:

### Frameworks & Libraries

- [Flask](https://flask.palletsprojects.com/) — Web application framework
- [Jinja2](https://jinja.palletsprojects.com/) — Template engine
- [llama.cpp](https://github.com/ggml-org/llama.cpp) — Local LLM inference engine
- [llama-cpp-python](https://github.com/abetlen/llama-cpp-python) — Python bindings for llama.cpp
- [HuggingFace Transformers](https://github.com/huggingface/transformers) — ML model library
- [Anthropic Claude API](https://docs.anthropic.com/) — Cloud LLM backend
- [FastMCP](https://github.com/jlowin/fastmcp) — Model Context Protocol server

### Security Tools

- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — Penetration testing framework
- [RouterSploit](https://github.com/threat9/routersploit) — Router exploitation framework
- [Nmap](https://nmap.org/) — Network scanner and mapper
- [Wireshark / tshark](https://www.wireshark.org/) — Network protocol analyzer
- [Scapy](https://scapy.net/) — Packet crafting and analysis
- [WireGuard](https://www.wireguard.com/) — Modern VPN tunnel

### Hardware & Mobile

- [@yume-chan/adb](https://github.com/nicola-nicola/nicola-nicola) — ADB over WebUSB
- [android-fastboot](https://github.com/nicola-nicola/nicola-nicola) — Fastboot over WebUSB
- [esptool-js](https://github.com/nicola-nicola/nicola-nicola) — ESP32 flashing in browser
- [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools) — ADB & Fastboot CLI
- [esptool](https://github.com/nicola-nicola/nicola-nicola) — ESP32 firmware flashing
- [pyserial](https://github.com/pyserial/pyserial) — Serial port communication
- [pyshark](https://github.com/KimiNewt/pyshark) — Wireshark Python interface
- [scrcpy](https://github.com/Genymobile/scrcpy) — Android screen mirroring
- [libadb-android](https://github.com/nicola-nicola/nicola-nicola) — ADB client for Android

### Python Libraries

- [bcrypt](https://github.com/pyca/bcrypt) — Password hashing
- [requests](https://github.com/psf/requests) — HTTP client
- [msgpack](https://github.com/msgpack/msgpack-python) — Serialization (Metasploit RPC)
- [cryptography](https://github.com/pyca/cryptography) — Cryptographic primitives
- [PyCryptodome](https://github.com/Legrandin/pycryptodome) — AES encryption
- [Pillow](https://github.com/python-pillow/Pillow) — Image processing
- [qrcode](https://github.com/lincolnloop/python-qrcode) — QR code generation
- [zeroconf](https://github.com/python-zeroconf/python-zeroconf) — mDNS service discovery
- [PyInstaller](https://github.com/pyinstaller/pyinstaller) — Executable packaging
- [cx_Freeze](https://github.com/marcelotduarte/cx_Freeze) — MSI installer packaging

### Android / Kotlin

- [AndroidX](https://developer.android.com/jetpack/androidx) — Jetpack libraries
- [Material Design 3](https://m3.material.io/) — UI components
- [Conscrypt](https://github.com/nicola-nicola/nicola-nicola) — SSL/TLS provider for Android

### Build Tools

- [esbuild](https://esbuild.github.io/) — JavaScript bundler
- [Gradle](https://gradle.org/) — Android build system

### Data Sources

- [NVD API v2.0](https://nvd.nist.gov/developers/vulnerabilities) — National Vulnerability Database

## License

Restricted Public Release. Authorized use only — activity is logged.

## Disclaimer

AUTARCH is a security research and authorized penetration testing platform. Use only on systems you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The authors accept no liability for misuse.

---

*Built with discipline by darkHal Security Group & Setec Security Labs.*
