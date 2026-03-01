# AUTARCH Development Status
## darkHal Security Group - Project AUTARCH
**Last Updated:** 2026-02-28

---

## Project Overview

AUTARCH is a full-stack security platform built in Python. It combines a CLI framework with a Flask web dashboard, LLM integration (llama.cpp, HuggingFace transformers, Claude API), Metasploit/RouterSploit RPC integration, an OSINT database with 7,200+ sites, and physical hardware device management.

**Codebase:** ~40,000 lines of Python across 65 source files + 3,237 lines JS/CSS
**Location:** `/home/snake/autarch/`
**Platform:** Linux (Orange Pi 5 Plus, RK3588 ARM64)

---

## Current Architecture

```
autarch/
├── autarch.py                  # Main entry point (613 lines) - CLI + --web flag
├── autarch_settings.conf       # INI config (11 sections)
├── core/                       # 25 Python modules (~12,500 lines)
│   ├── agent.py                # Autonomous agent loop (THOUGHT/ACTION/PARAMS)
│   ├── banner.py               # ASCII banner
│   ├── config.py               # Config handler with typed getters
│   ├── cve.py                  # NVD API v2.0 + SQLite CVE database
│   ├── android_protect.py      # Anti-stalkerware/spyware shield
│   ├── hardware.py             # ADB/Fastboot/Serial/ESP32 manager
│   ├── llm.py                  # LLM wrapper (llama.cpp + transformers + Claude + HuggingFace)
│   ├── menu.py                 # Category menu system (8 categories)
│   ├── msf.py                  # Metasploit RPC client (msgpack)
│   ├── msf_interface.py        # Centralized MSF interface
│   ├── msf_modules.py          # MSF module library (45 modules)
│   ├── msf_terms.py            # MSF settings term bank (54 settings)
│   ├── pentest_pipeline.py     # PentestGPT 3-module pipeline
│   ├── pentest_session.py      # Pentest session persistence
│   ├── pentest_tree.py         # Penetration Testing Tree (MITRE ATT&CK)
│   ├── report_generator.py     # HTML report generator
│   ├── rsf.py                  # RouterSploit integration
│   ├── rsf_interface.py        # Centralized RSF interface
│   ├── rsf_modules.py          # RSF module library
│   ├── rsf_terms.py            # RSF settings term bank
│   ├── sites_db.py             # OSINT sites SQLite DB (7,287 sites)
│   ├── tools.py                # Tool registry (12+ tools + MSF tools)
│   ├── upnp.py                 # UPnP port forwarding manager
│   ├── wireshark.py            # tshark/pyshark wrapper
│   ├── wireguard.py            # WireGuard VPN + Remote ADB manager
│   ├── discovery.py            # Network discovery (mDNS + Bluetooth advertising)
│   └── mcp_server.py           # MCP server (expose AUTARCH tools to AI clients)
│
├── modules/                    # 26 modules (~11,000 lines)
│   ├── adultscan.py            # Adult site username scanner (osint)
│   ├── android_protect.py      # Android protection shield CLI (defense)
│   ├── agent.py                # Agent task interface (core)
│   ├── agent_hal.py            # Agent Hal v2.0 - AI automation (core)
│   ├── analyze.py              # File forensics (analyze)
│   ├── chat.py                 # LLM chat interface (core)
│   ├── counter.py              # Threat detection (counter)
│   ├── defender.py             # System hardening + scan monitor (defense)
│   ├── dossier.py              # OSINT investigation manager (osint)
│   ├── geoip.py                # GEO IP lookup (osint)
│   ├── hardware_local.py       # Local hardware access CLI (hardware)
│   ├── hardware_remote.py      # Remote hardware stub (hardware)
│   ├── msf.py                  # MSF interface v2.0 (offense)
│   ├── mysystem.py             # System audit + CVE detection (defense)
│   ├── nettest.py              # Network testing (utility)
│   ├── recon.py                # OSINT recon + nmap scanner (osint)
│   ├── rsf.py                  # RouterSploit interface (offense)
│   ├── setup.py                # First-run setup wizard
│   ├── simulate.py             # Attack simulation (simulate)
│   ├── snoop_decoder.py        # Snoop database decoder (osint)
│   ├── upnp_manager.py         # UPnP port management (defense)
│   ├── wireshark.py            # Packet capture/analysis (analyze)
│   ├── wireguard_manager.py    # WireGuard VPN manager CLI (defense)
│   ├── workflow.py             # Workflow automation
│   └── yandex_osint.py         # Yandex OSINT (osint)
│
├── web/                        # Flask web dashboard
│   ├── app.py                  # App factory (16 blueprints)
│   ├── auth.py                 # Session auth (bcrypt)
│   ├── routes/                 # 15 route files (~4,500 lines)
│   │   ├── analyze.py, android_protect.py, auth_routes.py, counter.py
│   │   ├── chat.py, dashboard.py, defense.py, hardware.py, msf.py, offense.py
│   │   ├── osint.py, settings.py, simulate.py, upnp.py, wireshark.py
│   │   └── wireguard.py
│   ├── templates/              # 18 Jinja2 templates
│   │   ├── base.html (dark theme, sidebar nav, HAL chat panel, debug popup)
│   │   ├── android_protect.html, dashboard.html, login.html
│   │   ├── hardware.html, wireshark.html, wireguard.html, defense.html, offense.html
│   │   ├── counter.html, analyze.html, osint.html, simulate.html
│   │   ├── msf.html (MSF RPC terminal console)
│   │   ├── settings.html, llm_settings.html, upnp.html, category.html
│   └── static/
│       ├── css/style.css       # Dark theme
│       ├── js/app.js           # Vanilla JS (HAL chat + debug console + hardware)
│       ├── js/hardware-direct.js  # WebUSB/Web Serial direct-mode API (752 lines)
│       └── js/lib/
│           ├── adb-bundle.js      # ya-webadb bundled (57KB)
│           ├── fastboot-bundle.js # fastboot.js bundled (146KB)
│           └── esptool-bundle.js  # esptool-js bundled (176KB)
│
├── autarch_companion/           # Archon Android app (29 files, Kotlin)
│   ├── app/src/main/kotlin/com/darkhal/archon/  # Kotlin source (8 files)
│   ├── app/src/main/res/       # Layouts, themes, icons (12 XML files)
│   └── app/src/main/assets/bbs/ # BBS terminal WebView (3 files)
│
├── data/                       # Persistent data
│   ├── android_protect/        # Per-device scan reports and configs
│   ├── wireguard/              # WireGuard client configs and state
│   ├── cve/cve.db              # CVE SQLite database
│   ├── hardware/               # Hardware operation data
│   ├── pentest_sessions/       # Pentest session JSON files
│   ├── sites/sites.db          # OSINT sites database
│   ├── stalkerware_signatures.json  # Stalkerware/spyware signature DB (275+ packages)
│   └── uploads/                # Web file uploads
│
├── .config/                    # Hardware config templates
│   ├── nvidia_4070_mobile.conf
│   ├── amd_rx6700xt.conf
│   ├── orangepi5plus_cpu.conf
│   ├── orangepi5plus_mali.conf
│   └── custom/                 # User-saved configs
│
├── dossiers/                   # OSINT dossier JSON files
└── results/                    # Reports and scan results
```

---

## Categories & Menu System

| # | Category | Modules | Description |
|---|----------|---------|-------------|
| 1 | Defense | defender, mysystem, upnp_manager, scan monitor, android_protect, wireguard_manager | System audit, CVE detection, UPnP, scan monitoring, Android anti-stalkerware, WireGuard VPN |
| 2 | Offense | msf, rsf, agent_hal (pentest pipeline) | MSF/RSF automation, AI-guided pentesting |
| 3 | Counter | counter | Threat detection, rootkit checks, anomaly detection |
| 4 | Analyze | analyze, wireshark | File forensics, packet capture/analysis |
| 5 | OSINT | recon, adultscan, dossier, geoip, yandex, snoop | Username scan (7K+ sites), nmap, dossier management |
| 6 | Simulate | simulate | Port scan, password audit, payload generation |
| 7 | Hardware | hardware_local, hardware_remote | ADB/Fastboot/Serial/ESP32 device management |
| 99 | Settings | setup | LLM, MSF, OSINT, UPnP, web, pentest config |

---

## Technology Stack

- **Language:** Python 3.10
- **Web:** Flask, Jinja2, vanilla JS, SSE (Server-Sent Events)
- **LLM Backends:** llama-cpp-python (GGUF), HuggingFace transformers (SafeTensors), Anthropic Claude API, HuggingFace Inference API
- **MCP:** Model Context Protocol server (11 tools, stdio + SSE transports)
- **Databases:** SQLite (CVEs, OSINT sites), JSON (sessions, dossiers, configs, stalkerware signatures)
- **Integrations:** Metasploit RPC (msgpack), RouterSploit, NVD API v2.0, social-analyzer
- **Hardware:** ADB/Fastboot (Android SDK), pyserial + esptool (ESP32), tshark/pyshark
- **Network:** miniupnpc (UPnP), nmap, tcpdump, WireGuard (wg/wg-quick), USB/IP

---

## Evolution Plan (from master_plan.md)

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Backup & new working directory (`~/autarch`) | DONE |
| Phase 1 | UPnP Manager integration | DONE |
| Phase 2 | Flask web dashboard (12 blueprints, 14 templates) | DONE |
| Phase 3 | OSINT search engine (web UI) | DONE |
| Phase 4 | Wireshark module (tshark + pyshark) | DONE |
| Phase 4.5 | Hardware module (ADB/Fastboot/ESP32) | DONE |
| Phase 4.6 | Android Protection Shield (anti-stalkerware/spyware) | DONE |
| Phase 4.7 | Tracking Honeypot (fake data for ad trackers) | DONE |
| Phase 4.8 | WireGuard VPN + Remote ADB (TCP/IP & USB/IP) | DONE |
| Phase 4.9 | Archon Android Companion App | DONE |
| Phase 4.10 | HuggingFace Inference + MCP Server + Service Mode | DONE |
| Phase 4.12 | MSF Web Module Execution + Agent Hal + Global AI Chat | DONE |
| Phase 4.13 | Debug Console (floating log panel, 5 filter modes) | DONE |
| Phase 4.14 | WebUSB "Already In Use" fix (USB interface release on disconnect) | DONE |
| Phase 4.15 | LLM Settings sub-page (4 backends, full params, folder model scanner) | DONE |
| Phase 5 | Path portability & Windows support | MOSTLY DONE |
| Phase 6 | Docker packaging | NOT STARTED |
| Phase 7 | System Tray + Beta Release (EXE + MSI) | TODO |

### Additions Beyond Original Plan
- **RSF (RouterSploit)** integration (core/rsf*.py, modules/rsf.py)
- **Workflow module** (modules/workflow.py)
- **Nmap scanner** integrated into OSINT recon
- **Scan monitor** integrated into defense module
- **Android Protection Shield** — anti-stalkerware/spyware detection and remediation
- **MCP Server** — expose 11 AUTARCH tools via Model Context Protocol
- **HuggingFace Inference API** — remote model inference backend
- **Systemd Service** — run web dashboard as background service
- **Sideload** — push Archon APK to Android devices via ADB

---

## What Was Recently Added (Phase 4.12–4.15)

### MSF Web Module Execution + Agent Hal (Phase 4.12)
- `web/routes/offense.py` — `POST /offense/module/run` SSE stream + `POST /offense/module/stop`
- `web/templates/offense.html` — Run Module tabs (SSH/PortScan/OSDetect/Custom) + Agent Hal panel
- `web/routes/msf.py` (NEW) — MSF RPC console blueprint at `/msf/`
- `web/templates/msf.html` (NEW) — dark terminal MSF console UI
- `web/routes/chat.py` (NEW) — `/api/chat` SSE, `/api/agent/run|stream|stop`
- `web/templates/base.html` — global HAL chat panel (fixed bottom-right) + MSF Console nav link
- `web/static/js/app.js` — `halToggle/Send/Append/Scroll/Clear()` functions
- `web/app.py` — registered msf_bp + chat_bp
- `core/agent.py` — added `step_callback` param to `Agent.run()` for SSE step streaming

### Debug Console (Phase 4.13)
- `web/routes/settings.py` — `_DebugBufferHandler`, `_ensure_debug_handler()`, 4 debug API routes
- `web/templates/settings.html` — Debug Console section with enable toggle + test buttons
- `web/templates/base.html` — draggable floating debug popup, DBG toggle button
- `web/static/js/app.js` — full debug JS: stream, filter (5 modes), format, drag
- 5 filter modes: Warnings & Errors | Full Verbose | Full Debug + Symbols | Output Only | Show Everything

### WebUSB "Already In Use" Fix (Phase 4.14)
- `web/static/js/hardware-direct.js` — `adbDisconnect()` releases USB interface; `adbConnect()` detects Windows "already in use", auto-retries, shows actionable "run adb kill-server" message

### LLM Settings Sub-Page (Phase 4.15)
- `core/config.py` — added `get_openai_settings()` (api_key, base_url, model, max_tokens, temperature, top_p, frequency_penalty, presence_penalty)
- `web/routes/settings.py` — `GET /settings/llm` (sub-page), `POST /settings/llm/scan-models` (folder scanner), updated `POST /settings/llm` for openai backend
- `web/templates/settings.html` — LLM section replaced with sub-menu card linking to `/settings/llm`
- `web/templates/llm_settings.html` (NEW) — 4-tab dedicated LLM config page:
  - **Local**: folder browser → model file list (.gguf/.safetensors) + full llama.cpp AND transformers params
  - **Claude**: API key + model dropdown + basic params
  - **OpenAI**: API key + base_url + model + basic params
  - **HuggingFace**: token login + verify + model ID + 8 provider options + full generation params

---

## What Was Recently Added (Phase 4.10)

### HuggingFace Inference API Backend
- `core/llm.py` — `HuggingFaceLLM` class using `huggingface_hub.InferenceClient`
- Supports `text_generation()` and `chat_completion()` with streaming
- Config section: `[huggingface]` (api_key, model, endpoint, max_tokens, temperature, top_p)
- `config.py` — added `get_huggingface_settings()` method

### MCP Server (Model Context Protocol)
- `core/mcp_server.py` — FastMCP server exposing 11 AUTARCH tools
- **Tools:** nmap_scan, geoip_lookup, dns_lookup, whois_lookup, packet_capture, wireguard_status, upnp_status, system_info, llm_chat, android_devices, config_get
- **Transports:** stdio (for Claude Desktop/Code), SSE (for web clients)
- **CLI:** `python autarch.py --mcp [stdio|sse]` with `--mcp-port`
- **Web:** 4 API endpoints under `/settings/mcp/` (status, start, stop, config)
- **Menu:** option [10] MCP Server with start/stop SSE, show config, run stdio
- Config snippet generator for Claude Desktop / Claude Code integration

### Systemd Service + Sideload
- `scripts/autarch-web.service` — systemd unit file for web dashboard
- `autarch.py --service [install|start|stop|restart|status|enable|disable]`
- Menu [8] Web Service — full service management UI
- Menu [9] Sideload App — push Archon APK to Android device via ADB

### Web UI LLM Settings
- Settings page now shows all 4 backends with save+activate forms
- Each backend has its own form with relevant settings
- `/settings/llm` POST route switches backend and saves settings

---

## What Was Recently Added (Phase 4.9)

### Archon — Android Companion App
- **Location:** `autarch_companion/` (29 files)
- **Package:** `com.darkhal.archon` — Kotlin, Material Design 3, Single Activity + Bottom Nav
- **Name origin:** Greek ἄρχων (archon = ruler), etymological root of "autarch"
- **4 Tabs:**
  - **Dashboard** — ADB TCP/IP toggle, USB/IP export toggle, kill/restart ADB with 5s auto-restart watchdog, WireGuard tunnel status
  - **Links** — Grid of 9 cards linking to AUTARCH web UI sections (Dashboard, WireGuard, Shield, Hardware, Wireshark, OSINT, Defense, Offense, Settings)
  - **BBS** — Terminal-style WebView for Autarch BBS via Veilid protocol (placeholder — veilid-wasm integration pending VPS deployment)
  - **Settings** — Server IP, web/ADB/USB-IP ports, auto-restart toggle, BBS address, connection test
- **Key files:**
  - `service/AdbManager.kt` — ADB TCP/IP enable/disable, kill/restart, status check via root shell
  - `service/UsbIpManager.kt` — usbipd start/stop, device listing, bind/unbind
  - `util/ShellExecutor.kt` — Shell/root command execution with timeout
  - `util/PrefsManager.kt` — SharedPreferences wrapper for all config
  - `assets/bbs/` — BBS terminal HTML/CSS/JS with command system and Veilid bridge placeholder
- **Theme:** Dark hacker aesthetic — terminal green (#00FF41) on black (#0D0D0D), monospace fonts
- **Build:** Gradle 8.5, AGP 8.2.2, Kotlin 1.9.22, minSdk 26, targetSdk 34
- **Network Discovery:**
  - Server: `core/discovery.py` — DiscoveryManager singleton, mDNS (`_autarch._tcp.local.`) + Bluetooth (name="AUTARCH", requires security)
  - App: `service/DiscoveryManager.kt` — NSD (mDNS) + Wi-Fi Direct + Bluetooth scanning, auto-configures server IP/port
  - Priority: LAN mDNS > Wi-Fi Direct > Bluetooth
  - Config: `autarch_settings.conf [discovery]` section, 3 API routes under `/settings/discovery/`

---

## Previously Added (Phase 4.8)

### WireGuard VPN + Remote ADB
- See devjournal.md Session 15 for full details

---

## Previously Added (Phase 4.7)

### Tracking Honeypot — Feed Fake Data to Ad Trackers
- **Concept**: Feed fake data to ad trackers (Google, Meta, data brokers) while letting real apps function normally
- `data/tracker_domains.json` — 2000+ tracker domains from EasyList/EasyPrivacy/Disconnect patterns
  - 5 categories: advertising (882), analytics (332+), fingerprinting (134), social_tracking (213), data_brokers (226)
  - 12 company profiles (Google, Meta, Amazon, Microsoft, etc.) with SDK package names
  - 139 known Android tracker SDK packages
  - 25 tracking-related Android permissions
  - 4 ad-blocking DNS providers (AdGuard, NextDNS, Quad9, Mullvad)
  - Fake data templates: 35 locations, 42 searches, 30 purchases, 44 interests, 25 device models
- `core/android_protect.py` — added ~35 honeypot methods to AndroidProtectManager
  - **3 tiers of protection**: Tier 1 (ADB), Tier 2 (Shizuku), Tier 3 (Root)
  - **Tier 1**: Reset ad ID, opt out tracking, ad-blocking DNS, disable location scanning, disable diagnostics
  - **Tier 2**: Restrict background data, revoke tracking perms, clear tracker data, force-stop trackers
  - **Tier 3**: Hosts file blocklist, iptables redirect, fake GPS, rotate device identity, fake device fingerprint
  - **Composite**: Activate/deactivate all protections by tier, per-device state persistence
  - **Detection**: Scan tracker apps, scan tracker permissions, view ad tracking settings
- `modules/android_protect.py` — added menu items 70-87 with 18 handler methods
- `web/routes/android_protect.py` — added 28 honeypot routes under `/android-protect/honeypot/`
- `web/templates/android_protect.html` — added 5th "Honeypot" tab with 7 sections and ~20 JS functions

---

## Previously Added (Phase 4.6)

### Android Protection Shield — Anti-Stalkerware & Anti-Spyware
- `core/android_protect.py` - AndroidProtectManager singleton (~650 lines)
  - **Stalkerware detection**: scans installed packages against 275+ known stalkerware signatures across 103 families
  - **Government spyware detection**: checks for Pegasus, Predator, Hermit, FinSpy, QuaDream, Candiru, Chrysaor, Exodus, Phantom, Dark Caracal indicators (files, processes, properties)
  - **System integrity**: SELinux, verified boot, dm-verity, su binary, build fingerprint
  - **Hidden app detection**: apps without launcher icons (filtered from system packages)
  - **Device admin audit**: flags suspicious device admins against stalkerware DB
  - **Accessibility/notification listener abuse**: flags non-legitimate services
  - **Certificate audit**: user-installed CA certs (MITM detection)
  - **Network config audit**: proxy hijacking, DNS, VPN profiles
  - **Developer options check**: USB debug, unknown sources, mock locations, OEM unlock
  - **Permission analysis**: dangerous combo finder (8 patterns), per-app breakdown, heatmap matrix
  - **Remediation**: disable/uninstall threats, revoke permissions, remove device admin, remove CA certs, clear proxy
  - **Shizuku management**: install, start, stop, status check for privileged operations on non-rooted devices
  - **Shield app management**: install, configure, grant permissions to protection companion app
  - **Signature DB**: updatable from GitHub (AssoEchap/stalkerware-indicators), JSON format
  - **Scan reports**: JSON export, per-device storage in `data/android_protect/<serial>/scans/`
- `modules/android_protect.py` - CLI module (CATEGORY=defense) with 30+ menu items
- `web/routes/android_protect.py` - Flask blueprint with 33 routes under `/android-protect/`
- `web/templates/android_protect.html` - Web UI with 4 tabs (Scan, Permissions, Remediate, Shizuku)
- `data/stalkerware_signatures.json` - Threat signature database (103 families, 275 packages, 10 govt spyware, 8 permission combos)
- Modified `web/app.py` — registered `android_protect_bp` blueprint
- Modified `web/templates/base.html` — added "Shield" link in Tools sidebar section

---

## Previously Added (Phase 4.5)

### Hardware Module - ADB/Fastboot/ESP32 Access
- `core/hardware.py` - HardwareManager singleton (646 lines)
  - ADB: device listing, info, shell (with command sanitization), reboot, sideload, push/pull, logcat
  - Fastboot: device listing, info, partition flash (whitelist), reboot, OEM unlock
  - Serial/ESP32: port listing, chip detection, firmware flash with progress, serial monitor
  - All long operations run in background threads with progress tracking
- `modules/hardware_local.py` - CLI module with interactive menu (263 lines)
- `modules/hardware_remote.py` - Web UI redirect stub (26 lines)
- `web/routes/hardware.py` - Flask blueprint with ~20 endpoints + SSE streams (307 lines)
- `web/templates/hardware.html` - Full UI with Android/ESP32 tabs (309 lines)
- JS functions in `app.js` (16+ hw*() functions, lines 1100-1477)
- CSS styles: `--hardware: #f97316` (orange), progress bars, serial monitor, device grids

### Session 11 (2026-02-14) - Nmap & Scan Monitor
- Nmap scanner added to OSINT recon module (9 scan types, live-streaming output)
- Scan monitor added to defense module (tcpdump SYN capture, per-IP tracking, counter-scan)

### Session 12 (2026-02-14) - Path Portability & Bundled Tools (Phase 5)
- Created `core/paths.py` — centralized path resolution for entire project
  - `get_app_dir()`, `get_data_dir()`, `get_config_path()`, `get_results_dir()`, etc.
  - `find_tool(name)` — unified tool lookup: project dirs first, then system PATH
  - `get_platform_tag()` — returns `linux-arm64`, `windows-x86_64`, etc.
  - Platform-specific tool directories: `tools/linux-arm64/`, `tools/windows-x86_64/`
  - Auto-sets NMAPDIR for bundled nmap data files
  - Windows support: checks `.exe` extension, system/user PATH env vars, well-known install paths
- Copied Android platform-tools into `android/` directory (adb, fastboot)
- Copied system tools into `tools/linux-arm64/` (nmap, tcpdump, upnpc, wg + nmap-data/)
- **Convention: ALL Android deps go in `autarch/android/`, all other tools in `tools/<platform>/`**
- Replaced ALL hardcoded paths across 25+ files:
  - `core/hardware.py` — uses `find_tool('adb')` / `find_tool('fastboot')`
  - `core/wireshark.py` — uses `find_tool('tshark')`
  - `core/upnp.py` — uses `find_tool('upnpc')`
  - `core/msf.py` — uses `find_tool('msfrpcd')`
  - `core/config.py` — uses `get_config_path()`, `get_templates_dir()`
  - `core/cve.py`, `core/sites_db.py`, `core/pentest_session.py`, `core/report_generator.py` — use `get_data_dir()`
  - `modules/defender.py` — uses `find_tool('tcpdump')`
  - `modules/recon.py` — uses `find_tool('nmap')`
  - `modules/adultscan.py`, `modules/dossier.py`, `modules/mysystem.py`, `modules/snoop_decoder.py`, `modules/agent_hal.py`, `modules/setup.py` — use `get_app_dir()` / `get_data_dir()` / `get_reports_dir()`
  - `web/app.py`, `web/auth.py`, `web/routes/dashboard.py`, `web/routes/osint.py` — use paths.py
  - `core/menu.py` — all `Path(__file__).parent.parent` replaced with `self._app_dir`
- Zero `/home/snake` references remain in any .py file
- Created `requirements.txt` with all Python dependencies

**Tool resolution verification:**
```
Platform: linux-arm64
  adb          autarch/android/adb             [BUNDLED]
  fastboot     autarch/android/fastboot        [BUNDLED]
  nmap         autarch/tools/linux-arm64/nmap  [BUNDLED]
  tcpdump      autarch/tools/linux-arm64/...   [BUNDLED]
  upnpc        autarch/tools/linux-arm64/...   [BUNDLED]
  wg           autarch/tools/linux-arm64/...   [BUNDLED]
  msfrpcd      /usr/bin/msfrpcd                [SYSTEM]
  esptool      ~/.local/bin/esptool            [SYSTEM]
```

### Session 13 (2026-02-14) - Browser-Based Hardware Access (WebUSB/Web Serial)
- Created `android_plan.md` — full implementation plan for direct browser-to-device hardware access
- **Architecture: Dual-mode** — Server mode (existing, device on host) + Direct mode (NEW, device on user's PC)
- Bundled 3 JavaScript libraries for browser-based hardware access:
  - `@yume-chan/adb` v2.5.1 + `@yume-chan/adb-daemon-webusb` v2.3.2 → `adb-bundle.js` (57KB)
  - `android-fastboot` v1.1.3 (kdrag0n/fastboot.js) → `fastboot-bundle.js` (146KB)
  - `esptool-js` v0.5.7 (Espressif) → `esptool-bundle.js` (176KB)
- Build infrastructure: `package.json`, `scripts/build-hw-libs.sh`, `src/*-entry.js`
  - Uses esbuild to create IIFE browser bundles from npm packages
  - Build is dev-only; bundled JS files are static assets served by Flask
- Created `web/static/js/hardware-direct.js` (752 lines) — unified browser API:
  - **ADB via WebUSB**: device enumeration, connect, shell, getprop, reboot, push/pull files, logcat, install APK
  - **Fastboot via WebUSB**: connect, getvar, flash partition with progress, reboot, OEM unlock, factory ZIP flash
  - **ESP32 via Web Serial**: port select, chip detect, firmware flash with progress, serial monitor
  - ADB key management via Web Crypto API + IndexedDB (persistent RSA keys)
- Rewrote `web/templates/hardware.html` (309→531 lines):
  - Connection mode toggle bar (Server / Direct)
  - Direct-mode capability detection (WebUSB, Web Serial support)
  - Direct-mode connect/disconnect buttons for ADB, Fastboot, ESP32
  - File picker inputs (direct mode uses browser File API instead of server paths)
  - New "Factory Flash" tab (PixelFlasher PoC)
- Updated `web/static/js/app.js` (1477→1952 lines):
  - All hw*() functions are now mode-aware (check hwConnectionMode)
  - Server mode: existing Flask API calls preserved unchanged
  - Direct mode: routes through HWDirect.* browser API
  - Mode toggle with localStorage persistence
  - Factory flash workflow: ZIP upload → flash plan → progress tracking
- Updated `web/static/css/style.css`: mode toggle bar, checkbox styles, warning banners
- Added `{% block extra_head %}` to `web/templates/base.html` for page-specific script includes

---

## What's Left

### Phase 7: System Tray + Beta Release — TODO

#### System Tray (pystray + Pillow)
- `autarch.py` — add `--tray` flag to launch in system tray mode
- `core/tray.py` — `TrayManager` using `pystray` + `PIL.Image`
- **Tray icon menu:**
  - Open Dashboard (opens browser to http://localhost:8080)
  - Server Settings submenu:
    - Server address/port
    - Default model folder
    - Default tools folder
    - Auto-start on login toggle
  - Metasploit Integration submenu:
    - MSF RPC host + port + password
    - Start msfrpcd (runs `find_tool('msfrpcd')` with auto SSL)
    - Connect to existing msfrpcd
    - RPC connection status indicator
  - Separator
  - Start/Stop Web Server
  - View Logs
  - Separator
  - Quit

#### Beta Release
- `release/` — output folder for distribution artifacts
- `release/autarch.spec` — PyInstaller spec file:
  - One-file EXE (--onefile) or one-dir (--onedir) bundle
  - Include: `data/`, `web/`, `models/` (optional), `tools/`, `android/`, `autarch_settings.conf`
  - Console window: optional (--noconsole for tray-only mode, --console for CLI mode)
  - Icon: `web/static/img/autarch.ico`
- `release/build_exe.bat` / `release/build_exe.sh` — build scripts
- `release/autarch.wxs` or `release/installer.nsi` — MSI/NSIS installer:
  - Install to `%PROGRAMFILES%\AUTARCH\`
  - Create Start Menu shortcut
  - Register Windows service option
  - Include Metasploit installer link if not found
  - Uninstaller

### Phase 4.5 Remaining: Browser Hardware Access Polish
- Test WebUSB ADB connection end-to-end with a physical device
- Test WebUSB Fastboot flashing end-to-end
- Test Web Serial ESP32 flashing end-to-end
- Test factory ZIP flash (PixelFlasher PoC) with a real factory image
- Add boot.img patching for Magisk/KernelSU (future enhancement)
- HTTPS required for WebUSB in production (reverse proxy or localhost only)
- Note: WebUSB/Web Serial only work in Chromium-based browsers (Chrome, Edge, Brave)

### Phase 5: Path Portability & Windows Support — MOSTLY DONE

Completed:
- `core/paths.py` with full path resolution and tool finding
- All hardcoded paths replaced
- Platform-specific tool bundling structure
- requirements.txt

Remaining:
- Windows-specific `sudo` handling (use `ctypes.windll.shell32.IsUserAnAdmin()` check)
- Bundle Windows tool binaries in `tools/windows-x86_64/` (nmap.exe, tshark.exe, etc.)
- Test on Windows and macOS
- Add `[hardware]` config section for customizable tool paths

### Phase 6: Docker Packaging

**Goal:** Portable deployment with all dependencies bundled.

**Tasks:**
1. Create `Dockerfile` (python:3.11-slim base)
2. Create `docker-compose.yml` (volume mounts for data/models/results)
3. Create `.dockerignore`
4. Create `scripts/entrypoint.sh` (start CLI, web, or both)
5. Create `scripts/install-tools.sh` (nmap, tshark, miniupnpc, wireguard-tools)
6. Expose ports: 8080 (web), 55553 (MSF RPC passthrough)
7. Test full build and deployment

---

## Known Issues / Gaps

1. ~~**Hardcoded paths**~~ - FIXED (all use core/paths.py now)
2. ~~**No requirements.txt**~~ - FIXED (created)
3. **No `[hardware]` config section** - hardware settings not in autarch_settings.conf
4. **No HTTPS** - web UI runs plain HTTP
5. **No test suite** - no automated tests
6. **Large backup file** - `claude.bk` (213MB) should be cleaned up
7. **tshark not installed** - Wireshark/packet capture limited to scapy
8. **msfrpcd not bundleable** - depends on full Metasploit ruby framework
9. **Windows/macOS untested** - tool bundling structure ready but no binaries yet
10. **Local model folder hardcoded to `models/`** - should use AppData in release build (TODO: change for Phase 7 release)
11. **No OpenAI LLM backend implementation** - config added; `core/llm.py` needs `OpenAILLM` class
