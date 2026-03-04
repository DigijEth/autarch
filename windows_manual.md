# AUTARCH — Windows User Manual

**Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking**
*By darkHal Security Group and Setec Security Labs*

---

## Table of Contents

1. [Windows Overview](#1-windows-overview)
2. [System Requirements](#2-system-requirements)
3. [Installation](#3-installation)
4. [Running AUTARCH on Windows](#4-running-autarch-on-windows)
5. [Web Dashboard](#5-web-dashboard)
6. [LLM Setup on Windows](#6-llm-setup-on-windows)
7. [Metasploit on Windows](#7-metasploit-on-windows)
8. [Nmap on Windows](#8-nmap-on-windows)
9. [Hardware & Device Tools](#9-hardware--device-tools)
10. [WireGuard VPN](#10-wireguard-vpn)
11. [Known Limitations on Windows](#11-known-limitations-on-windows)
12. [Troubleshooting](#12-troubleshooting)
13. [Quick Reference](#13-quick-reference)

---

## 1. Windows Overview

AUTARCH runs on Windows with most features fully functional. A few Linux-specific tools (like `tshark` packet capture and WireGuard kernel integration) have limited support, but the web dashboard, AI chat, OSINT tools, hardware management, and Metasploit all work on Windows.

**What works on Windows:**
- Web dashboard (full UI — 59 blueprints, all tool pages)
- AI chat (all LLM backends — Claude API, OpenAI, local GGUF, HuggingFace)
- All 72 CLI modules
- OSINT tools (7,200+ sites, username/email/domain/IP/phone lookup)
- Android/iPhone device management via ADB (USB or WebUSB)
- Hardware ESP32 flashing
- Metasploit RPC client (MSF must be started separately)
- Reverse usersll management
- C2 Framework, Load Test, Gone Fishing Mail Server
- Vulnerability Scanner, Exploit Development, Social Engineering
- Active Directory Audit, MITM Proxy, WiFi Audit
- Password Toolkit, Web Scanner, API Fuzzer, Cloud Scanner
- Steganography, Anti-Forensics, Forensics, Reverse Engineering
- BLE Scanner, RFID/NFC Tools, Malware Sandbox
- Container Security, Email Security, Incident Response
- Report Engine, Net Mapper, Log Correlator, Threat Intel
- SDR/RF Tools (with Drone Detection), Starlink Hack
- SMS Forge, RCS/SMS Exploitation
- Pineapple/Rogue AP, Deauth (require Linux/Raspberry Pi for full functionality)
- Targets, Autonomy, Encrypted Modules, LLM Trainer
- Agent Hal (autonomous AI agent)

**What has reduced functionality on Windows:**
- Packet capture (`tshark`/`pyshark`) — requires Npcap
- WireGuard — requires Windows WireGuard app
- Linux service manager (`--service` flag) — use Task Scheduler instead
- Metasploit auto-start — must start MSF manually

---

## 2. System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Windows 10 (64-bit) | Windows 11 |
| RAM | 4 GB | 16 GB (for local AI models) |
| Storage | 2 GB free | 20 GB (for AI models) |
| Python | 3.10 | 3.11 or 3.12 |
| Browser | Chrome / Edge | Chrome (required for WebUSB) |
| GPU (AI) | None needed | NVIDIA GPU (for GPU-accelerated models) |

---

## 3. Installation

### Step 1 — Install Python

Download Python from [python.org](https://www.python.org/downloads/). During installation:

- **Check "Add Python to PATH"** (critical — do this before clicking Install Now)
- Check "Install pip"
- Use the default installation path

Verify the install by opening Command Prompt and typing:

```
python --version
pip --version
```

Both should print version numbers without errors.

### Step 2 — Get AUTARCH

If you received AUTARCH as a ZIP file, extract it to a folder like `C:\users\autarch`.

### Step 3 — Install Dependencies

Open Command Prompt, navigate to your AUTARCH folder, and run:

```
cd C:\users\autarch
pip install -r requirements.txt
```

This installs Flask, requests, and other core libraries. It may take a few minutes.

**Note on bitsandbytes:** The `requirements.txt` includes `bitsandbytes` for GPU model quantization. This package requires Linux/CUDA to fully work. On Windows without CUDA:

```
pip install bitsandbytes --prefer-binary
```

If it fails, you can skip it — AUTARCH will detect its absence and load models without quantization automatically. No other features are affected.

### Step 4 — First Run -- Run in admin powershell

### Starting the Terminal Menu

```
python autarch.py
```

Navigate with number keys. Type `0` to go back. Type `99` for Settings.

### Starting the Web Dashboard (recommended for windows)

```
python autarch.py --web
```

Then open your browser to: `http://localhost:8181`

> **Tip:** Use `http://YOUR-IP:8181` (find your IP with `ipconfig`) to access from other devices on your network.

### Useful Startup Flags

| Command | What It Does |
|---------|-------------|
| `python autarch.py` | Start the interactive menu |
| `python autarch.py --web` | Start the web dashboard |
| `python autarch.py --web --port 9090` | Use a different port |
| `python autarch.py -m chat` | Start AI chat directly |
| `python autarch.py --setup` | Re-run the setup wizard |
| `python autarch.py --skip-setup` | Skip AI setup |
| `python autarch.py --show-config` | Show current settings |
| `python autarch.py --mcp stdio` | Start MCP server |
| `python autarch.py -l` | List all available modules |

### Running as a Background Service on Windows

AUTARCH's `--service` commands use Linux `systemd`. On Windows, use **Task Scheduler** instead:

1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task → name it "AUTARCH"
3. Trigger: "When the computer starts"
4. Action: Start a program
   - Program: `python`
   - Arguments: `C:\users\autarch\autarch.py --web`
   - Start in: `C:\users\autarch`
5. Run whether user is logged on or not

Alternatively, use **NSSM** (Non-Sucking Service Manager) for a proper Windows service:

```
nssm install AUTARCH "python" "C:\users\autarch\autarch.py --web"
nssm start AUTARCH
```

---

## 5. Web Dashboard

The dashboard runs on port **8181** by default. Access it at `http://localhost:8181`.

### Login

Default credentials are admin/admin. Change them in Settings → Password.

### Sidebar Navigation

| Section | What's There |
|---------|-------------|
| Dashboard | System overview, tool status |
| Targets | Pentest scope and target management |
| Autonomy | AI-driven autonomous security operations |
| Defense | System hardening, Linux/Windows/Threat Monitor, Threat Intel, Log Correlator, Container Sec, Email Sec, Incident Response |
| Offense | Metasploit, Load Test, Gone Fishing, Social Eng, Hack Hijack, Web Scanner, C2 Framework, WiFi Audit, Deauth, API Fuzzer, Cloud Scan, Vuln Scanner, Exploit Dev, AD Audit, MITM Proxy, Pineapple, SMS Forge |
| Counter | Threat hunting, Steganography, Anti-Forensics |
| Analyze | File forensics, Hash Toolkit, LLM Trainer, Password Toolkit, Net Mapper, Reports, BLE Scanner, Forensics, RFID/NFC, Malware Sandbox, Reverse Eng |
| OSINT | Intelligence gathering, IP Capture |
| Simulate | Attack scenarios, Legendary Creator |
| Tools | Enc Modules, Wireshark, Hardware, Android Exploit (+ SMS Forge), iPhone Exploit, Shield, Reverse usersll, Archon, SDR/RF Tools, Starlink Hack, RCS Tools |
| System | UPnP, WireGuard, DNS Server, MSF Console, Chat, Settings |

### HAL Chat Button

The **HAL** button in the bottom-right corner opens a persistent AI chat panel. It works on every page and uses whatever LLM backend you have configured.

### Debug Console

The **DBG** button (bottom-right, appears after first action) opens a live debug panel showing system logs. Use it to diagnose errors, see LLM load status, and trace tool activity.

---

## 6. LLM Setup on Windows

AUTARCH supports four AI backends. All work on Windows — but local GPU models have some limitations.

### Option A — Claude API (Easiest, Recommended for Windows)

No local GPU needed. Uses Anthropic's cloud API.

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. In AUTARCH: Settings → LLM Config → Claude tab
3. Paste your API key
4. Select a model (e.g. `claude-sonnet-4-6`)
5. Click **Save & Activate Claude**
6. Click **Load Model** — status dot turns green

### Option B — OpenAI API

Works the same way as Claude. Also supports local LLM servers (Ollama, vLLM, LM Studio).

1. Get an API key from [platform.openai.com](https://platform.openai.com)
2. In AUTARCH: Settings → LLM Config → OpenAI tab
3. Paste your API key and select a model
4. Click **Save & Activate OpenAI** then **Load Model**

**Using with a local server (Ollama, LM Studio):**
- Set Base URL to your local server (e.g. `http://localhost:11434/v1` for Ollama)
- Leave API key blank or use `ollama`
- Set model to the name you pulled (e.g. `llama3`)

### Option C — Local GGUF Model (CPU, No Internet)

Runs on CPU — no GPU required, but slow on large models.

1. Install llama-cpp-python:
   ```
   pip install llama-cpp-python
   ```
2. Download a GGUF model file (e.g. from [HuggingFace](https://huggingface.co) — look for Q4_K_M quantized files, they're the best balance of speed and quality)
3. In AUTARCH: Settings → LLM Config → Local Model tab
4. Set Models Folder path (e.g. `C:\models`)
5. Select your GGUF file
6. Click **Save & Activate Local**
7. Click **Load Model** — first load takes 10–60 seconds

**Recommended GGUF models for Windows (CPU):**
- `mistral-7b-instruct-v0.3.Q4_K_M.gguf` — good for most tasks
- `phi-3-mini-4k-instruct.Q4_K_M.gguf` — fast, good on low-RAM systems
- `llama-3.2-3b-instruct.Q4_K_M.gguf` — very fast, lightweight

### Option D — HuggingFace Transformers (GPU Recommended)

For NVIDIA GPU users. On Windows without CUDA, models will load on CPU (very slow for large models).

1. Install PyTorch for your platform:
   - **With NVIDIA GPU:** Visit [pytorch.org](https://pytorch.org/get-started/locally/) and get the CUDA version
   - **CPU only:** `pip install torch --index-url https://download.pytorch.org/whl/cpu`
2. Install remaining dependencies:
   ```
   pip install transformers accelerate
   ```
3. Optionally install bitsandbytes for quantization (CUDA required):
   ```
   pip install bitsandbytes --prefer-binary
   ```
4. In AUTARCH: Settings → LLM Config → Local Model tab → enable "Use HuggingFace Transformers"
5. Enter a model ID (e.g. `microsoft/Phi-3-mini-4k-instruct`)

> **Windows note:** If bitsandbytes is not installed or doesn't work, AUTARCH will automatically disable 4-bit/8-bit quantization and load the model in full precision. You'll see a warning in the debug log — this is normal and expected.

### LLM Load Button

On the LLM Config page, after saving settings, always click **Load Model** to initialize the backend. The status indicator shows:

| Color | Meaning |
|-------|---------|
| Grey | Not loaded |
| Amber | Loading... |
| Green | Ready |
| Red | Error — check Debug Log |

Click **Debug Log** to open the live debug console and see exactly what went wrong.

---

## 7. Metasploit on Windows

Metasploit Framework runs on Windows via the official Windows installer.

### Installing Metasploit

1. Download the Windows installer from [metasploit.com](https://www.metasploit.com/download)
2. Run the installer — it installs to `C:\metasploit-framework` by default
3. After install, start the MSF RPC daemon:
   ```
   C:\metasploit-framework\bin\msfrpcd.bat -P yourpassword -S -f
   ```
   Or use msfconsole directly and enable RPC from within it.

### Connecting AUTARCH to MSF

1. Go to Settings in AUTARCH
2. Set MSF RPC host: `127.0.0.1`, port: `55553`
3. Enter your RPC password
4. In the web dashboard, go to **MSF Console** and click **Reconnect**

### Using MSF in AUTARCH

- **MSF Console page** (`/msf`) — terminal-style console, type commands directly
- **Offense → Run Module** — quick-launch SSH scanners, port scanners, OS detection with live output
- **Offense → Agent Hal** — tell the AI to run operations autonomously

> **Note:** AUTARCH cannot auto-start/stop the MSF daemon on Windows (that uses Linux `pgrep`/`pkill`). Start MSF manually before connecting.

---

## 8. Nmap on Windows

Nmap is used by many AUTARCH scanning modules.

### Installing Nmap

1. Download from [nmap.org](https://nmap.org/download.html) — use the Windows installer
2. During install, **also install Npcap** (required for raw socket scanning)
3. Nmap installs to `C:\Program Files (x86)\Nmap` by default

### Configuring Path

If AUTARCH can't find nmap, add it to Settings → Tool Paths, or add `C:\Program Files (x86)\Nmap` to your Windows PATH:

1. Search for "Environment Variables" in Start
2. Edit System Environment Variables → Path
3. Add `C:\Program Files (x86)\Nmap`

---

## 9. Hardware & Device Tools

### ADB / Android Devices

AUTARCH includes bundled ADB binaries in `android/`. No separate install needed.

**USB Device Access:** Windows handles USB permissions automatically for most devices. Enable USB Debugging on your Android phone first (Settings → Developer Options → USB Debugging).

**WebUSB Mode (Direct Connection):**

AUTARCH supports WebUSB for direct ADB access from your browser without a server connection. This requires:
- **Chromium-based browser** (Chrome or Edge) — Firefox does not support WebUSB
- Install the [Android ADB driver](https://developer.android.com/studio/run/win-usb) for your device manufacturer
- Go to Hardware page → click the connection mode toggle → select "Direct (WebUSB)"

> **Note:** WinUSB driver is needed for WebUSB. If your device is recognized by standard ADB but not WebUSB, use [Zadig](https://zadig.akeo.ie/) to install the WinUSB driver.

### ESP32 Flashing

Fully supported on Windows. Connect your ESP32 via USB-serial adapter:

1. Install the CP210x or CH340 USB-serial driver for your adapter
2. Windows will assign it a COM port (e.g. `COM3`)
3. In AUTARCH Hardware page → ESP32 tab → select your COM port
4. Flash or interact normally

### Wireshark / Packet Capture

Requires Npcap (installed with Nmap or Wireshark):

1. Install [Wireshark for Windows](https://www.wireshark.org/download.html) — it includes Npcap
2. After install, `tshark` will be available in `C:\Program Files\Wireshark\`
3. Run AUTARCH as Administrator for raw packet capture permissions

---

## 10. WireGuard VPN

### Installing WireGuard

1. Download from [wireguard.com](https://www.wireguard.com/install/)
2. Install the Windows app

### Using with AUTARCH

AUTARCH's WireGuard page generates and manages config files. On Windows, apply the config manually:

1. Generate your config in AUTARCH → WireGuard
2. Copy the config
3. Open the WireGuard Windows app
4. Click "Add Tunnel" → Import from clipboard or file
5. Click Activate

> **Note:** Automatic WireGuard tunnel management (via `wg` CLI) requires WireGuard to be in your PATH or configured in AUTARCH Settings.

---

## 11. Known Limitations on Windows

| Feature | Status | Notes |
|---------|--------|-------|
| Web dashboard (59 blueprints) | Full | Works perfectly |
| AI chat (cloud APIs) | Full | Claude, OpenAI, HuggingFace all work |
| AI chat (local GGUF) | Full (CPU) | Slow without GPU |
| GPU quantization (4-bit/8-bit) | Partial | Needs CUDA + bitsandbytes |
| Nmap scanning | Full | Needs Nmap + Npcap installed |
| Packet capture | Partial | Needs Npcap + admin rights |
| Metasploit | Full (manual start) | MSF must be started manually |
| ADB (server mode) | Full | Bundled ADB binary works |
| ADB (WebUSB/Direct) | Full | Chrome/Edge only, needs WinUSB driver |
| ESP32 flashing | Full | COM port instead of /dev/ttyUSB |
| WireGuard | Partial | Needs Windows WireGuard app |
| SDR/RF Tools | Full | Needs HackRF or RTL-SDR hardware + drivers |
| Starlink Hack | Full | Needs network access to Starlink dish |
| SMS Forge / RCS Tools | Full | Needs ADB connection to Android device |
| WiFi Audit / Deauth / Pineapple | Partial | Full functionality requires Linux/monitor-mode adapter |
| C2 Framework | Full | All agent types work |
| Vulnerability Scanner | Full | Nuclei recommended for template scanning |
| Container Security | Full | Needs Docker Desktop installed |
| Background service | Via Task Scheduler | `--service` flag doesn't work |
| System uptime | N/A | Shows "N/A" (uses /proc/uptime) |
| mDNS discovery | Partial | May require Bonjour |

---

## 12. Troubleshooting

### "Python not found" or command not recognized

Python is not in your PATH. Either:
- Reinstall Python and check "Add to PATH"
- Or run: `py autarch.py` instead of `python autarch.py`

### Web dashboard won't start — "Port already in use"

Another process is on port 8181. Use a different port:
```
python autarch.py --web --port 8090
```
Or find and kill the conflicting process:
```
netstat -ano | findstr :8181
taskkill /PID <PID> /F
```

### bitsandbytes install error

```
ERROR: Could not find a version that satisfies the requirement bitsandbytes
```

This is normal on Windows without CUDA. Either:
- Install with `pip install bitsandbytes --prefer-binary` for a best-effort install
- Or skip it — AUTARCH detects absence and disables quantization automatically

### LLM won't load — "No module named llama_cpp"

Install llama-cpp-python:
```
pip install llama-cpp-python
```
If you have an NVIDIA GPU and want GPU acceleration:
```
set CMAKE_ARGS="-DLLAMA_CUBLAS=on"
pip install llama-cpp-python --force-reinstall --no-cache-dir
```

### ADB device not detected

1. Enable USB Debugging on your phone (Settings → Developer Options → USB Debugging)
2. When prompted on the phone, tap "Allow"
3. Check if Windows recognizes the device: `android\adb.exe devices`
4. Install the correct USB driver for your phone manufacturer

### Nmap not found

AUTARCH reports "nmap not found" in the Dashboard. Fix it:
1. Install Nmap from [nmap.org](https://nmap.org/download.html)
2. Add `C:\Program Files (x86)\Nmap` to your Windows PATH
3. Or configure the path in AUTARCH Settings → Tool Paths

### Metasploit can't connect

1. Verify MSF RPC daemon is running: `netstat -ano | findstr :55553`
2. If not running, start it: `msfrpcd -P yourpassword -S -f`
3. Check password matches what's in AUTARCH Settings
4. Try clicking **Reconnect** in the MSF Console page

### Firewall blocking the dashboard

Windows Firewall may block port 8181. Allow it:
1. Windows Defender Firewall → Advanced Settings
2. Inbound Rules → New Rule
3. Port → TCP → 8181 → Allow

Or from Command Prompt (as Administrator):
```
netsh advfirewall firewall add rule name="AUTARCH" dir=in action=allow protocol=TCP localport=8181
```

### "Permission denied" errors

Run Command Prompt as Administrator. Right-click Command Prompt → Run as Administrator.

---

## 13. Quick Reference

### Startup Commands

```
# Start menu
python autarch.py

# Start web dashboard
python autarch.py --web

# Different port
python autarch.py --web --port 9090

# List all modules
python autarch.py -l

# Run AI chat
python autarch.py -m chat

# Reset configuration
python autarch.py --setup
```

### Key URLs

| URL | What It Is |
|-----|-----------|
| `http://localhost:8181` | Main web dashboard |
| `http://localhost:8181/targets` | Target management |
| `http://localhost:8181/settings/llm` | LLM configuration |
| `http://localhost:8181/msf` | MSF Console terminal |
| `http://localhost:8181/manual` | Full user manual |

### Important Paths

| Path | What It Contains |
|------|----------------|
| `autarch_settings.conf` | All configuration |
| `data/targets.json` | Saved targets |
| `data/sessions/` | Saved sessions |
| `data/dossiers/` | OSINT dossiers |
| `android/adb.exe` | Bundled ADB binary |
| `tools/` | Bundled tools |

### Common Tool Locations (Windows Defaults)

| Tool | Default Path |
|------|-------------|
| Nmap | `C:\Program Files (x86)\Nmap\nmap.exe` |
| Metasploit | `C:\metasploit-framework\bin\` |
| WireGuard | `C:\Program Files\WireGuard\` |
| Wireshark | `C:\Program Files\Wireshark\` |
| Python | `C:\Python311\` or `C:\Users\<you>\AppData\Local\Programs\Python\` |

---

---

## 14. New Tools Overview (v2.3)

AUTARCH v2.3 includes 59 web blueprints and 72 CLI modules. Here is a summary of the major tool categories added since v2.0:

### Offense Tools
| Tool | Description |
|------|-------------|
| Vulnerability Scanner | Nuclei/OpenVAS template-based scanning with severity ratings |
| Exploit Development | usersllcode gen, payload encoding, ROP chains, pattern generator |
| Social Engineering | Credential harvest, pretexts, QR phishing, campaign tracking |
| AD Audit | LDAP enumeration, Kerberoasting, AS-REP roast, ACL analysis |
| MITM Proxy | HTTP(S) interception, SSL strip, request modification |
| Pineapple | Rogue AP, Evil Twin, captive portal (Raspberry Pi) |
| Deauth Attack | WiFi deauthentication (Raspberry Pi + monitor-mode adapter) |
| C2 Framework | Multi-agent command & control with task queuing |
| WiFi Audit | Wireless network security assessment |
| SMS Forge | Create/modify SMS Backup & Restore XML backups |
| RCS/SMS Exploit | Message extraction, forging, and RCS exploitation via ADB |
| Starlink Hack | Starlink terminal security analysis and gRPC exploitation |

### Defense Tools
| Tool | Description |
|------|-------------|
| Container Security | Docker/K8s audit, image scanning, escape detection |
| Email Security | DMARC/SPF/DKIM analysis, header forensics, phishing detection |
| Incident Response | IR playbooks, evidence collection, IOC sweeping, timeline |
| Threat Intelligence | Feed aggregation, IOC management, STIX/TAXII |
| Log Correlator | Multi-source log aggregation and event correlation |

### Analysis Tools
| Tool | Description |
|------|-------------|
| Reverse Engineering | Binary analysis, Capstone disassembly, YARA, Ghidra integration |
| Digital Forensics | Disk/memory forensics, artifact extraction |
| SDR/RF Tools | Spectrum analysis, RF replay, ADS-B tracking, drone detection |
| Steganography | Data hiding/extraction in images and audio |
| BLE Scanner | Bluetooth Low Energy discovery and fuzzing |
| RFID/NFC Tools | Card reading, cloning, emulation |
| Malware Sandbox | Safe detonation and behavior analysis |
| Net Mapper | Network topology discovery with SVG visualization |

All tools are accessible from the web dashboard sidebar and most are also available via CLI (`python autarch.py -m <module_name>`).

---

*AUTARCH v2.3 — By darkHal Security Group and Setec Security Labs*
*For authorized security testing and research only. Always obtain written permission before testing systems you do not own.*
