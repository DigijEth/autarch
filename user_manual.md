# AUTARCH User Manual

**Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking**
*By darkHal Security Group and Setec Security Labs*

---

## What Is AUTARCH?

AUTARCH is an all-in-one security platform that puts professional-grade security tools at your fingertips. Think of it as your personal security command center — it can scan networks, investigate threats on your phone, gather intelligence, test your own defenses, and even chat with AI about security topics.

You can use it two ways:
- **Terminal (CLI)** — A text menu you navigate with number keys
- **Web Dashboard** — A browser-based interface you can access from any device on your network

No prior hacking experience is needed to use most features. This manual will walk you through everything step by step.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [The Main Menu (CLI)](#2-the-main-menu-cli)
3. [The Web Dashboard](#3-the-web-dashboard)
4. [Defense Tools](#4-defense-tools)
5. [Offense Tools](#5-offense-tools)
6. [Counter-Intelligence](#6-counter-intelligence)
7. [Analysis & Forensics](#7-analysis--forensics)
8. [OSINT (Intelligence Gathering)](#8-osint-intelligence-gathering)
9. [Attack Simulation](#9-attack-simulation)
10. [Hardware & Device Management](#10-hardware--device-management)
11. [Android Protection Shield](#11-android-protection-shield)
12. [WireGuard VPN](#12-wireguard-vpn)
13. [Reverse Shell](#13-reverse-shell)
14. [Archon Companion App](#14-archon-companion-app)
15. [AI Chat & Agents](#15-ai-chat--agents)
16. [MCP Server](#16-mcp-server)
17. [Configuration & Settings](#17-configuration--settings)
18. [Troubleshooting](#18-troubleshooting)
19. [Quick Reference](#19-quick-reference)
20. [Safety & Legal Notice](#20-safety--legal-notice)

---

## 1. Getting Started

### What You Need

- A computer running Linux (AUTARCH is built for Orange Pi 5 Plus / ARM64, but works on any Linux)
- Python 3.10 or newer (already installed on most Linux systems)
- A web browser (for the dashboard)
- An Android phone (optional, for companion app features)

### Starting AUTARCH for the First Time

Open a terminal and type:

```
python autarch.py
```

The first time you run AUTARCH, a **setup wizard** appears. It asks you to pick an AI backend:

| Option | What It Is | Do You Need It? |
|--------|-----------|-----------------|
| Local GGUF | AI model running on your machine | Optional — needs a model file |
| Transformers | PyTorch-based AI | Optional — needs GPU or lots of RAM |
| Claude API | Anthropic's cloud AI | Optional — needs an API key |
| HuggingFace | Cloud AI via HuggingFace | Optional — needs an API key |
| Skip Setup | Run without AI | Works fine — most tools don't need AI |

**Tip:** If you're not sure, choose "Skip Setup." You can always configure AI later. Most of AUTARCH's tools (scanning, OSINT, defense, hardware) work perfectly without an AI model.

### Starting the Web Dashboard

If you prefer a graphical interface instead of the terminal menu:

```
python autarch.py --web
```

Then open your browser and go to: `http://your-ip-address:8080`

The default login credentials are set during first run. You can change them in Settings.

### Running a Specific Tool Directly

If you know exactly what you want to run:

```
python autarch.py -m chat          # Start AI chat
python autarch.py -m adultscan     # Username scanner
python autarch.py osint johndoe    # Quick OSINT lookup
python autarch.py --list           # Show all available tools
```

### Command Line Options at a Glance

| Command | What It Does |
|---------|-------------|
| `python autarch.py` | Start the interactive menu |
| `python autarch.py --web` | Start the web dashboard |
| `python autarch.py -m <name>` | Run a specific module |
| `python autarch.py -l` | List all modules |
| `python autarch.py --setup` | Re-run the setup wizard |
| `python autarch.py --skip-setup` | Skip AI setup, run without LLM |
| `python autarch.py --show-config` | Show current settings |
| `python autarch.py --mcp stdio` | Start MCP server for Claude |
| `python autarch.py --service start` | Start as background service |
| `python autarch.py -h` | Show all command line options |

---

## 2. The Main Menu (CLI)

When you start AUTARCH, you'll see a menu like this:

```
═══════════════════════════════════
  AUTARCH — Security Platform
═══════════════════════════════════

  [1]  Defense        System hardening & monitoring
  [2]  Offense        Penetration testing
  [3]  Counter        Threat detection & hunting
  [4]  Analyze        Forensics & file analysis
  [5]  OSINT          Intelligence gathering
  [6]  Simulate       Attack simulation

  [7]  Agent Hal      AI security automation
  [8]  Web Service    Start/stop web dashboard
  [9]  Sideload App   Push Archon to phone
  [10] MCP Server     AI tool server

  [99] Settings
  [98] Exit

  Select >
```

**How to use it:** Type a number and press Enter. Each option opens a sub-menu with more choices. Type `0` to go back to the previous menu.

---

## 3. The Web Dashboard

The web dashboard gives you the same tools as the CLI, but in a visual browser interface.

### Starting the Dashboard

From the CLI menu, select **[8] Web Service**, or run:

```
python autarch.py --web
```

### Navigating the Dashboard

The left sidebar has these sections:

**Dashboard** — System overview showing:
- Your device info (hostname, IP, platform)
- System uptime
- Which tools are available (nmap, tshark, etc.)
- Module counts
- LLM and UPnP status

**Categories** — The 6 main tool categories (Defense, Offense, Counter, Analyze, OSINT, Simulate)

**Tools** — Specialized tool pages:
- **Wireshark** — Packet capture & analysis
- **Hardware** — Android/iPhone/ESP32 device management
- **Android Exploit** — Android-specific attack tools
- **iPhone Exploit** — iPhone forensics tools
- **Shield** — Anti-stalkerware/spyware scanner
- **Reverse Shell** — Remote device management

**System** — Infrastructure management:
- **UPnP** — Port forwarding
- **WireGuard** — VPN management
- **Settings** — All configuration options

### Running as a Background Service

To keep the dashboard running even when you close your terminal:

```
python autarch.py --service install   # One-time: install the service
python autarch.py --service enable    # Start on boot
python autarch.py --service start     # Start now
python autarch.py --service status    # Check if it's running
```

---

## 4. Defense Tools

Defense tools help you check and strengthen your system's security.

### What's Available

| Tool | What It Does |
|------|-------------|
| **Full Security Audit** | Runs all checks at once — the "check everything" button |
| **Firewall Check** | Shows your firewall rules and warns if it's off |
| **SSH Hardening** | Reviews your SSH configuration for weaknesses |
| **Open Ports Scan** | Lists all network ports your machine is exposing |
| **User Security Check** | Finds accounts with weak or no passwords |
| **File Permissions Audit** | Finds files with dangerous permissions (world-writable, SUID) |
| **Service Audit** | Lists running services and flags suspicious ones |
| **System Audit & CVE Detection** | Checks installed software against known vulnerabilities |
| **Scan Monitor** | Watches your network for incoming port scans in real-time |

### How to Use (CLI)

1. From the main menu, type `1` for Defense
2. Pick a tool by number (e.g., `1` for Full Audit)
3. Read the results — warnings are highlighted in red/yellow
4. Type `0` to go back

### How to Use (Web)

1. Click **Defense** in the sidebar
2. Click any tool button
3. Results appear on the page

### Tips

- Run the **Full Security Audit** first to get an overview
- If you see red warnings, address those first — they're the most critical
- The **Scan Monitor** runs continuously — press Ctrl+C to stop it in CLI mode

---

## 5. Offense Tools

Offense tools are for testing your own systems' security. These are professional penetration testing tools.

### What's Available

| Tool | What It Does |
|------|-------------|
| **Metasploit Framework** | The industry-standard exploit framework |
| **RouterSploit** | Test your router for known vulnerabilities |
| **Reverse Shell** | Remote shell to Android devices via Archon app |
| **Android Exploit Tools** | Root methods, payload deployment, boot exploits |
| **iPhone Exploit Tools** | USB-based forensics and extraction |
| **Workflow Automation** | Chain multiple attack steps together |

### Metasploit Integration

AUTARCH connects to Metasploit via RPC, giving you a friendlier interface:

1. From Offense menu, select **Metasploit**
2. **Search** for modules (e.g., "ssh" to find SSH exploits)
3. **Configure** a module with target IP, port, etc.
4. **Execute** the module
5. **Manage sessions** if you get a shell

**Setup:** Metasploit needs to be installed separately. AUTARCH auto-starts it on launch unless you use `--no-msf`.

### Reverse Shell Manager

The reverse shell lets you control Android devices remotely through the Archon companion app:

1. **Start Listener** — AUTARCH opens a port (default 17322) and waits for connections
2. **Configure Archon** — Enter your AUTARCH server IP in the Archon app
3. **Connect** — Tap Connect in the Archon app's Modules tab
4. **Use** — You can now run commands, take screenshots, download files, etc.

See [Section 13: Reverse Shell](#13-reverse-shell) for detailed instructions.

---

## 6. Counter-Intelligence

Counter-intelligence tools help you detect if someone is already inside your system.

### What's Available

| Tool | What It Does |
|------|-------------|
| **Full Threat Scan** | Runs all detection checks at once |
| **Suspicious Process Detection** | Finds processes that shouldn't be running |
| **Network Analysis** | Looks for unusual network connections |
| **Login Anomalies** | Detects weird login patterns (odd hours, unknown IPs) |
| **File Integrity Monitoring** | Detects if system files have been changed |
| **Scheduled Task Audit** | Checks cron jobs for hidden backdoors |
| **Rootkit Detection** | Scans for rootkits and kernel modifications |
| **Hidden App Detection** | Finds applications trying to hide themselves |

### When to Use These

- After you suspect a compromise
- As a regular security check (weekly is good)
- After installing unfamiliar software
- If your system is acting strangely (slow, unexpected network traffic)

---

## 7. Analysis & Forensics

These tools help you examine files, network traffic, and system artifacts.

### File Analysis

Drop a file in and get:
- **File type** — What the file actually is (even if renamed)
- **Hashes** — MD5 and SHA256 for verification
- **Strings** — Readable text hidden inside binaries
- **Hex dump** — Raw byte-level view
- **VirusTotal lookup** — Check if it's known malware

### Packet Capture (Wireshark Integration)

Capture and analyze network traffic:

1. Select your network interface
2. Set optional filters (e.g., "port 80" for web traffic)
3. Start capture
4. Browse the results — protocols, source/destination, payload data

**In the web UI:** The Wireshark page gives you a visual packet inspector.

---

## 8. OSINT (Intelligence Gathering)

OSINT (Open Source Intelligence) tools help you find publicly available information about people, domains, and IP addresses.

### Username Lookup

Check if a username exists across **7,200+ websites**:

1. Enter a username
2. AUTARCH checks hundreds of sites simultaneously
3. Results show which sites have that username registered

**Categories searched:** Social media, forums, dating sites, gaming, email providers, developer platforms, and more.

### Email Lookup

- Validates if an email address is real
- Checks format and domain
- Generates email permutations (firstname.lastname, flastname, etc.)

### Domain Reconnaissance

Enter a domain name and get:
- **WHOIS** — Registration info, owner, dates
- **DNS records** — A, MX, NS, TXT records
- **Subdomains** — Discovered subdomains
- **Technology stack** — What software the website runs

### IP Address Lookup

Enter an IP address and get:
- **Geolocation** — Country, city, coordinates
- **Reverse DNS** — Associated domain names
- **Network info** — ISP, ASN, organization

### Phone Number Lookup

- Validates phone numbers
- Identifies carrier
- Traces to geographic region

### Adult Site Scanner

Checks usernames across 50+ adult content sites. This is useful for investigating potential abuse or stalking.

### Nmap Network Scanner

9 different scan types for network reconnaissance:
- **SYN Scan** — Fast stealth scan (most common)
- **FIN/NULL/Xmas** — Firewall evasion techniques
- **ACK Scan** — Map firewall rules
- **UDP Scan** — Find UDP services
- **Window/Idle/Maimon** — Advanced stealth techniques

### How to Use (CLI)

1. Main menu → `5` for OSINT
2. Pick a tool (e.g., `2` for Username Lookup)
3. Enter your search target
4. Wait for results (username lookups can take 30-60 seconds)

### How to Use (Web)

1. Click **OSINT** in the sidebar
2. Fill in the search fields
3. Click the action button
4. Results display below

---

## 9. Attack Simulation

Simulation tools let you test attack scenarios in a controlled way.

| Tool | What It Does |
|------|-------------|
| **Password Audit** | Tests password strength with common patterns |
| **Port Scanner** | Quick port scanning (lighter than nmap) |
| **Banner Grabber** | Identifies services by their response banners |
| **Payload Generator** | Creates test payloads (XSS, SQLi, command injection) |
| **Network Stress Test** | Tests how many connections a service can handle |

---

## 10. Hardware & Device Management

AUTARCH can directly control physical devices connected to it.

### Android Devices (ADB/Fastboot)

If you connect an Android phone via USB (with USB debugging enabled):

- **ADB Shell** — Run commands on the phone
- **Install/Uninstall apps** — Push APKs or remove apps
- **Pull/Push files** — Transfer files to/from the phone
- **Logcat** — View the phone's system logs
- **Fastboot** — Flash firmware, unlock bootloader, manage partitions

### iPhone (USB Forensics)

Connect an iPhone via USB for:
- Device information and serial number
- Backup extraction
- App enumeration
- File retrieval

### ESP32 (Serial Programming)

Flash firmware to ESP32 microcontrollers:
- Select serial port
- Pick firmware binary
- Flash and verify

### Two Modes in the Web UI

- **Server Mode** — The device is plugged into AUTARCH's USB port
- **Direct Mode** — The device is plugged into YOUR computer, and your browser talks to it directly via WebUSB/Web Serial

Toggle between modes in the Hardware page header.

---

## 11. Android Protection Shield

The Shield protects Android devices from stalkerware, spyware, and tracking.

### What It Detects

- **Stalkerware** — 275+ known surveillance apps (mSpy, FlexiSpy, Cerberus, etc.)
- **Government spyware** — Pegasus, Predator, Hermit, and similar
- **Hidden apps** — Apps that have removed their icons to hide
- **Device admin abuse** — Apps with dangerous admin privileges
- **Certificate manipulation** — MITM proxy certificates
- **Accessibility abuse** — Apps using accessibility to read your screen
- **Dangerous permission combos** — Apps with suspicious permission combinations

### How to Run a Scan

**CLI:**
1. Main menu → `1` Defense → Android Protection Shield
2. Choose scan type (Full Scan recommended for first time)
3. Review results — threats are highlighted in red

**Web:**
1. Click **Shield** in the sidebar
2. Click **Full Scan**
3. Review the results

**Archon App:**
1. Open the Archon companion app
2. Go to the **Modules** tab
3. Tap **FULL SCAN** under Protection Shield

### Tracking Honeypot

The honeypot feeds fake data to ad trackers, making their profiles of you useless:

- **Reset Ad ID** — Generate a new advertising identifier
- **Private DNS** — Route DNS through ad-blocking servers
- **Restrict Trackers** — Block tracker apps from background data
- **Revoke Tracker Perms** — Remove permissions from known trackers
- **Harden All** — Do everything above at once

### Protection Tiers

| Tier | Requires | What It Can Do |
|------|----------|---------------|
| Tier 1 | ADB connection | Ad ID reset, tracking opt-out, DNS blocking |
| Tier 2 | Archon Server | Background data restriction, permission revocation |
| Tier 3 | Root access | Hosts file blocking, iptables rules, GPS spoofing, identity rotation |

---

## 12. WireGuard VPN

AUTARCH includes a full WireGuard VPN server for secure connections.

### What It Does

- Creates encrypted VPN tunnels between your AUTARCH server and other devices
- Lets you access AUTARCH remotely (and securely)
- Enables Remote ADB — control Android devices over the VPN
- USB/IP — share USB devices over the network

### Setting Up

**CLI:** Main menu → `1` Defense → WireGuard VPN Manager

1. **Start Interface** — Bring up the WireGuard tunnel
2. **Create Client** — Add a new device (phone, laptop, etc.)
3. **Generate Config** — Get the config file/QR code for the client
4. **Import the config** on your phone/laptop's WireGuard app

### Remote ADB Over VPN

Once a phone is connected to your VPN:
1. Go to **Remote ADB** section
2. Select the client
3. Connect — you now have ADB access over the encrypted tunnel

### USB/IP

Share USB devices from remote machines over the VPN:
1. Load USB/IP kernel modules
2. List USB devices on the remote host
3. Attach the device — it appears as if it's plugged into AUTARCH locally

---

## 13. Reverse Shell

The Reverse Shell lets you remotely manage Android devices through the Archon companion app.

### How It Works

1. **AUTARCH listens** on a port (default 17322)
2. **The phone connects out** to AUTARCH (this is why it's called "reverse" — the phone initiates the connection)
3. **You control the phone** from AUTARCH's web terminal or CLI

### Setting Up (Step by Step)

**On AUTARCH (your server):**

1. **Web UI:** Go to **Reverse Shell** in the sidebar → Enter a port (or use default 17322) → Click **Start Listener**
2. **CLI:** Main menu → `2` Offense → Reverse Shell → `1` Start Listener
3. Note the **auth token** — you'll need it for the phone

**On the Android phone:**

1. Open the **Archon** companion app
2. Go to **Settings** → Set your AUTARCH server's IP address
3. Go to **Modules** tab
4. Under **Reverse Shell**, tap **CONNECT**
5. Accept all 3 safety warnings (they explain what this does)

**Back on AUTARCH:**

The session should now appear. You can:

| Action | What It Does |
|--------|-------------|
| **Interactive Shell** | Type commands as if you were on the phone |
| **System Info** | Get device details (model, Android version, storage) |
| **Screenshot** | Capture the phone's screen |
| **Packages** | List all installed apps |
| **Processes** | See what's running |
| **Network** | View active network connections |
| **Logcat** | Read the phone's system logs |
| **Download File** | Pull a file from the phone |
| **Upload File** | Send a file to the phone |

### Safety Features

The reverse shell has multiple safety measures:

- **Disabled by default** — Must be explicitly enabled
- **3 warnings** — You must acknowledge all 3 before it activates
- **Auth token** — Random per-session, prevents unauthorized access
- **Auto-timeout** — Connection drops after 30 minutes (configurable)
- **Kill switch** — Disconnect anytime from the app or by force-stopping
- **Audit log** — Every command is logged on the phone
- **Command blocklist** — Dangerous commands (rm -rf /, reboot, etc.) are blocked

---

## 14. Archon Companion App

The Archon app runs on your Android phone and connects to AUTARCH for remote management.

### Installation

**From AUTARCH (easiest):**
1. Connect your phone via USB with USB debugging enabled
2. Main menu → `9` Sideload App
3. The APK is pushed and installed automatically

**Manual install:**
1. Copy the APK from `autarch_companion/app/build/outputs/apk/debug/`
2. Transfer to your phone
3. Enable "Install from unknown sources" in phone settings
4. Open and install the APK

### App Tabs

**Dashboard**
- Toggle ADB TCP/IP mode (for wireless debugging)
- USB/IP device management
- WireGuard connection status
- Quick system info

**Links**
- 9 quick links to AUTARCH web UI sections
- Opens directly in your phone's browser
- Requires your AUTARCH server IP to be set in Settings

**Modules**
- **Protection Shield** — Scan for stalkerware/spyware directly from your phone
- **Tracking Honeypot** — Block trackers and fake ad data
- **Reverse Shell** — Connect back to AUTARCH for remote management

**Settings**
- Set AUTARCH server IP and port
- Test the connection
- View Archon Server status

**Setup**
- Wireless ADB pairing (for first-time setup without USB)
- Archon Server bootstrap (starts the privileged helper)

### The Archon Server

The Archon Server is a helper process that runs on your phone at elevated privileges (UID 2000, same as ADB shell). It lets the app perform actions that normally require a USB computer connection.

**How to start it:**
1. Go to the **Setup** tab
2. Pair via Wireless Debugging (one-time)
3. Tap **Start Server**

The server stays running in the background. You can stop it anytime.

### arish — The Interactive Shell

`arish` is a command-line shell you can run on your Android device (via adb shell or a terminal emulator app). It connects to the Archon Server and gives you shell-level access:

```
adb push arish /data/local/tmp/arish
adb shell chmod 755 /data/local/tmp/arish
adb shell /data/local/tmp/arish
```

Then you can type commands interactively:
```
arish$ pm list packages
arish$ dumpsys battery
arish$ ls /data/local/tmp
arish$ exit
```

Or run a single command:
```
adb shell /data/local/tmp/arish pm list packages -3
```

---

## 15. AI Chat & Agents

AUTARCH can connect to AI language models for intelligent security assistance.

### Chat Module

An interactive conversation with an AI about security topics:

```
python autarch.py -m chat
```

**Useful commands inside chat:**
- `/help` — Show all chat commands
- `/clear` — Start a fresh conversation
- `/system <prompt>` — Change the AI's behavior
- `/temp 0.3` — Lower temperature for more precise answers
- `/stream` — Toggle streaming (see words as they appear)
- `/exit` — Leave chat

### Agent Hal

An autonomous AI agent that can use AUTARCH's tools:

```
python autarch.py -m agent
```

Tell it what you want in plain English:
- "Scan 192.168.1.0/24 for open ports"
- "Check if my SSH config is secure"
- "Look up the username 'johndoe' on social media"

The agent will use the appropriate tools, show you what it's doing, and present results.

### Supported AI Backends

| Backend | Speed | Cost | Quality |
|---------|-------|------|---------|
| **Local GGUF** | Slow (CPU) | Free | Good (depends on model) |
| **Transformers** | Medium | Free | Good |
| **Claude API** | Fast | Paid | Excellent |
| **HuggingFace** | Fast | Free tier available | Good |

Configure in Settings → LLM Settings, or edit `autarch_settings.conf`.

---

## 16. MCP Server

MCP (Model Context Protocol) lets AI assistants like Claude use AUTARCH's tools directly.

### Starting the MCP Server

```
# For Claude Desktop or Claude Code
python autarch.py --mcp stdio

# For web-based clients
python autarch.py --mcp sse --mcp-port 8081
```

### What Tools Are Exposed

| Tool | What It Does |
|------|-------------|
| `nmap_scan` | Network scanning |
| `geoip_lookup` | IP geolocation |
| `dns_lookup` | DNS record queries |
| `whois_lookup` | Domain registration info |
| `packet_capture` | Network packet capture |
| `wireguard_status` | VPN tunnel status |
| `upnp_status` | Port mapping status |
| `system_info` | Host system information |
| `llm_chat` | Chat with the configured LLM |
| `android_devices` | List connected Android devices |
| `config_get` | Read AUTARCH configuration |

### How to Use with Claude Desktop

Add to your Claude Desktop config:
```json
{
  "mcpServers": {
    "autarch": {
      "command": "python",
      "args": ["/path/to/autarch.py", "--mcp", "stdio"]
    }
  }
}
```

Then in Claude Desktop, you can say things like "Use AUTARCH to scan 192.168.1.1" and Claude will use the tools.

---

## 17. Configuration & Settings

### The Config File

All settings live in `autarch_settings.conf` in the AUTARCH directory. You can edit it with any text editor, or use the Settings menu.

### Key Settings

**LLM (AI Model)**
```ini
[autarch]
llm_backend = local          # local, transformers, claude, or huggingface

[llama]
model_path = /path/to/model.gguf
n_ctx = 4096                 # Context window size
n_threads = 4                # CPU threads
temperature = 0.7            # Creativity (0.0 = precise, 1.0 = creative)
max_tokens = 2048            # Max response length

[claude]
api_key = sk-ant-...         # Your Anthropic API key
model = claude-sonnet-4-20250514

[huggingface]
api_key = hf_...             # Your HuggingFace token
model = mistralai/Mistral-7B-Instruct-v0.3
```

**Web Dashboard**
```ini
[web]
host = 0.0.0.0              # Listen on all interfaces
port = 8080                  # Dashboard port
```

**OSINT**
```ini
[osint]
max_threads = 8              # Parallel lookups (higher = faster but more bandwidth)
timeout = 8                  # Seconds before giving up on a site
include_nsfw = false         # Include adult sites in scans
```

**Reverse Shell**
```ini
[revshell]
enabled = true
host = 0.0.0.0
port = 17322                 # Listener port
auto_start = false           # Start listener on AUTARCH boot
```

**UPnP**
```ini
[upnp]
enabled = true
internal_ip = 10.0.0.26     # Your machine's local IP
refresh_hours = 12           # Re-apply mappings interval
mappings = 443:TCP,51820:UDP,8080:TCP
```

### Changing Settings

**CLI:** Main menu → `99` Settings → pick a category

**Web:** Click **Settings** in the sidebar

**Manual:** Edit `autarch_settings.conf` with a text editor, then restart AUTARCH

---

## 18. Troubleshooting

### "Module not found" error
- Run `python autarch.py --list` to see available modules
- Check that the module file exists in the `modules/` directory
- Make sure the file has a `run()` function

### Web dashboard won't start
- Check if port 8080 is already in use: `ss -tlnp | grep 8080`
- Try a different port: `python autarch.py --web --web-port 9090`
- Check the terminal for error messages

### AI chat says "no model configured"
- Run `python autarch.py --setup` to configure an AI backend
- For local models: make sure `model_path` points to a valid `.gguf` file
- For cloud APIs: verify your API key is correct

### Metasploit won't connect
- Make sure Metasploit is installed
- Start the RPC server: `msfrpcd -P yourpassword -S -a 127.0.0.1`
- Check the password matches in Settings

### Android device not detected
- Enable **USB Debugging** on the phone (Settings → Developer Options)
- Try a different USB cable (some cables are charge-only)
- Run `adb devices` to verify the connection
- Accept the debugging prompt on the phone

### Reverse shell won't connect
- Make sure the listener is started on AUTARCH
- Verify the server IP is correct in the Archon app
- Check that port 17322 is not blocked by a firewall
- If on different networks, make sure you have a VPN (WireGuard) or port forwarding set up

### Scan taking too long
- Reduce thread count in OSINT settings (lower = slower but more reliable)
- Increase timeout if on a slow connection
- Some nmap scans (UDP, Idle) are inherently slow — use SYN scan for speed

### App crashes or hangs
- Check the terminal for Python traceback errors
- Run with `--verbose` for more detail: `python autarch.py --verbose`
- Make sure all Python dependencies are installed: `pip install -r requirements.txt`

---

## 19. Quick Reference

### Most-Used Commands

```bash
python autarch.py                    # Interactive menu
python autarch.py --web              # Web dashboard
python autarch.py -m chat            # AI chat
python autarch.py -m adultscan       # Username scanner
python autarch.py osint <username>   # Quick OSINT
python autarch.py -l                 # List all modules
python autarch.py --setup            # Setup wizard
python autarch.py --show-config      # View settings
python autarch.py --mcp stdio        # MCP server
python autarch.py --service status   # Check web service
```

### Module Categories

| # | Category | Color | What's In It |
|---|----------|-------|-------------|
| 1 | Defense | Blue | System hardening, shield, VPN, scan monitor |
| 2 | Offense | Red | Metasploit, reverse shell, Android exploits |
| 3 | Counter | Purple | Threat detection, rootkit scanning |
| 4 | Analyze | Cyan | File forensics, packet capture |
| 5 | OSINT | Green | Username/email/domain/IP lookup |
| 6 | Simulate | Yellow | Port scanning, payload generation |

### Key Ports

| Port | Service |
|------|---------|
| 8080 | Web dashboard |
| 8081 | MCP server (SSE mode) |
| 17321 | Archon Server (on phone, localhost only) |
| 17322 | Reverse Shell listener |
| 51820 | WireGuard VPN |

### File Locations

| File | Purpose |
|------|---------|
| `autarch.py` | Main entry point |
| `autarch_settings.conf` | All configuration |
| `modules/` | CLI tool modules |
| `core/` | Core framework libraries |
| `web/` | Web dashboard (Flask) |
| `tools/linux-arm64/` | Bundled tools (nmap, tcpdump, etc.) |
| `android/` | ADB and Fastboot binaries |
| `autarch_companion/` | Android companion app source |
| `data/` | Runtime data (screenshots, downloads, databases) |

---

## 20. Safety & Legal Notice

AUTARCH is a powerful security platform. Use it responsibly.

### Rules

1. **Only test systems you own or have written permission to test**
2. **Never use these tools against someone else's devices without their explicit consent**
3. **The Android Protection Shield is meant to protect YOUR phone** — scanning someone else's phone without permission is illegal in most jurisdictions
4. **The reverse shell is for managing YOUR devices** — using it on someone else's device without consent is a crime
5. **OSINT tools search public information** — but using that information to harass or stalk someone is illegal
6. **You are responsible for how you use these tools** — the developers are not liable for misuse

### Ethical Use

- Use defense tools to protect your own systems
- Use offense tools only with explicit authorization
- Report vulnerabilities you find through proper channels
- Respect privacy — just because you can find information doesn't mean you should use it

### Emergency

If you discover your device has been compromised:
1. Run the **Protection Shield** full scan
2. Check **Counter-Intelligence** for system threats
3. Change all passwords from a different, clean device
4. Consider a factory reset if the compromise is severe

---

*AUTARCH v1.3 — By darkHal Security Group and Setec Security Labs*
*This manual covers all features through Phase 5 (February 2026)*
