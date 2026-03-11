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
17. [Advanced Offense Tools](#17-advanced-offense-tools)
18. [Advanced Defense Tools](#18-advanced-defense-tools)
19. [Advanced Analysis Tools](#19-advanced-analysis-tools)
20. [SDR/RF & Starlink Tools](#20-sdrrf--starlink-tools)
21. [Configuration & Settings](#21-configuration--settings)
22. [Troubleshooting](#22-troubleshooting)
23. [Quick Reference](#23-quick-reference)
24. [Safety & Legal Notice](#24-safety--legal-notice)

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

**Autonomy** — AI-driven autonomous security operations

**Categories** — The 6 main tool categories:
- **Defense** — System hardening, firewall, SSH, services, scan monitor
  - Linux / Windows / Threat Monitor sub-pages
  - Threat Intel, Log Correlator, Container Sec, Email Sec, Incident Response
- **Offense** — Penetration testing & exploitation
  - Load Test, Gone Fishing, Social Eng, Hack Hijack, Web Scanner
  - C2 Framework, WiFi Audit, Deauth, API Fuzzer, Cloud Scan
  - Vuln Scanner, Exploit Dev, AD Audit, MITM Proxy, Pineapple, SMS Forge
- **Counter** — Threat detection & hunting
  - Steganography, Anti-Forensics
- **Analyze** — Forensics & analysis
  - Hash Toolkit, LLM Trainer, Password Toolkit, Net Mapper, Reports
  - BLE Scanner, Forensics, RFID/NFC, Malware Sandbox, Reverse Eng
- **OSINT** — Intelligence gathering
  - IP Capture
- **Simulate** — Attack scenarios & Legendary Creator

**Tools** — Specialized tool pages:
- **Enc Modules** — Encrypted module management
- **Wireshark** — Packet capture & analysis
- **Hardware** — Android/iPhone/ESP32 device management
- **Android Exploit** — Android-specific attack tools
  - SMS Forge — SMS backup forging
- **iPhone Exploit** — iPhone forensics tools
- **Shield** — Anti-stalkerware/spyware scanner
- **Reverse Shell** — Remote device management
- **Archon** — Android companion app
- **SDR/RF Tools** — Software-defined radio & drone detection
- **Starlink Hack** — Starlink terminal exploitation
- **RCS Tools** — SMS/RCS message exploitation

**System** — Infrastructure management:
- **UPnP** — Port forwarding
- **WireGuard** — VPN management
- **DNS Server** — Built-in DNS service
- **MSF Console** — Metasploit terminal
- **Chat** — AI chat interface
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

## 17. Advanced Offense Tools

AUTARCH v2.3 includes a comprehensive suite of offense modules for authorized penetration testing.

### Vulnerability Scanner

Template-based vulnerability scanning with Nuclei and OpenVAS integration.

- **Scan profiles:** Quick, Standard, Full, or custom template selection
- **Results:** Severity-rated findings (Critical/High/Medium/Low/Info)
- **Integration:** Feeds results into the Report Engine
- **Web UI:** 3 tabs — Scan, Templates, Results

### Exploit Development

Shellcode generation, payload encoding, ROP chain building, and buffer overflow pattern tools.

- **Shellcode:** Reverse shell, bind shell — x86, x64, ARM
- **Encoder:** XOR, AES, polymorphic stub generation
- **ROP Builder:** Gadget finder from binary, chain assembly
- **Patterns:** Cyclic pattern create/offset for buffer overflow development
- **Web UI:** 4 tabs — Shellcode, Encoder, ROP, Patterns

### Social Engineering

Credential harvesting, pretexting, QR phishing, and campaign tracking.

- **Page Cloner:** Clone login pages for authorized phishing tests
- **Pretexts:** Library of IT support, HR, vendor, delivery templates
- **QR Codes:** Embed URLs in QR codes with custom branding
- **Campaigns:** Track which pretexts and vectors get clicks
- **Integration:** Works with Gone Fishing mail server and IP Capture
- **Web UI:** 4 tabs — Harvest, Pretexts, QR Codes, Campaigns

### Active Directory Audit

LDAP enumeration, Kerberoasting, AS-REP roasting, ACL analysis, and BloodHound data collection.

- **Enumerate:** Users, groups, OUs, GPOs, trusts, domain controllers
- **Kerberoast:** Request TGS tickets, extract hashes for offline cracking
- **ACL Analysis:** Find dangerous permissions (WriteDACL, GenericAll)
- **BloodHound:** JSON ingestor for graph-based attack path analysis
- **Web UI:** 4 tabs — Enumerate, Attack, ACLs, BloodHound

### MITM Proxy

HTTP(S) interception with SSL stripping, request modification, and traffic logging.

- **Proxy:** Intercept and modify HTTP/HTTPS traffic (mitmproxy integration)
- **SSL Strip:** Test SSL stripping detection
- **Rules:** Header injection, body replacement, WebSocket interception
- **Upstream:** Proxy chaining through Tor or SOCKS proxies
- **Web UI:** 3 tabs — Proxy, Rules, Traffic Log

### WiFi Pineapple / Rogue AP

Rogue access point creation, Evil Twin attacks, captive portals, and Karma attacks. Designed for Raspberry Pi and similar SBCs.

- **Rogue AP:** hostapd-based fake AP with configurable SSID, channel, encryption
- **Evil Twin:** Clone target AP, deauth original, capture reconnections
- **Captive Portal:** Hotel WiFi, corporate, social media login pages
- **Karma Attack:** Respond to all probe requests, auto-associate clients
- **Tools:** hostapd, dnsmasq, iptables/nftables, airbase-ng
- **Web UI:** 4 tabs — Rogue AP, Captive Portal, Clients, Traffic

### Deauth Attack

Targeted and broadcast deauthentication attacks. Designed for Raspberry Pi with monitor-mode WiFi adapters.

- **Targeted:** Disconnect specific client from specific AP
- **Broadcast:** Disconnect all clients from target AP
- **Continuous:** Persistent deauth with configurable interval and burst count
- **Channel Hop:** Auto-detect target channel or sweep all channels
- **Tools:** aireplay-ng, mdk3/mdk4, scapy raw frame injection
- **Integration:** Pairs with WiFi Audit for handshake capture after deauth
- **Web UI:** 3 tabs — Targets, Attack, Monitor

### C2 Framework

Multi-agent command and control with task queuing, agent management, and payload generation.

- **Listeners:** Multi-port TCP accept with agent registration
- **Agents:** Python, Bash, PowerShell templates with configurable beacon interval/jitter
- **Tasks:** exec, download, upload, sysinfo commands
- **Payloads:** One-liner generators with copy-to-clipboard
- **Web UI:** 3 tabs — Dashboard (auto-refresh), Agents (interactive shell), Generate

### Load Test

HTTP load/stress testing with configurable concurrency and duration.

- **Modes:** GET, POST, custom headers, authentication
- **Metrics:** Requests/sec, latency percentiles, error rate, throughput
- **Web UI:** Configure target, run test, view live results

### Gone Fishing Mail Server

Built-in SMTP mail server for phishing simulation campaigns.

- **Local Network:** The public release operates on local network only
- **Templates:** Customizable email templates with variable substitution
- **Tracking:** Integrates with IP Capture for open/click tracking
- **Web UI:** Compose, send, and track phishing emails

### Hack & Hijack

Session hijacking, cookie theft, and DNS hijacking tools.

- **Session Hijack:** Capture and replay session tokens
- **DNS Hijack:** Redirect domain resolution
- **Web UI:** Configure targets and execute attacks

### Web Application Scanner

Automated web vulnerability scanning with crawling and fuzzing.

- **Crawler:** Discover pages, forms, and API endpoints
- **Scanners:** XSS, SQLi, CSRF, directory traversal, header injection
- **Reports:** Severity-rated findings with remediation guidance
- **Web UI:** Scan configuration, results viewer

### API Fuzzer

REST/GraphQL API endpoint fuzzing and security testing.

- **Discovery:** Endpoint enumeration from OpenAPI specs or crawling
- **Fuzzing:** Parameter mutation, boundary testing, injection payloads
- **Auth Testing:** Token manipulation, privilege escalation checks
- **Web UI:** 3 tabs — Endpoints, Fuzz, Results

### Cloud Security Scanner

AWS, Azure, and GCP misconfiguration scanning.

- **S3/Blob:** Public bucket/container detection
- **IAM:** Overprivileged role analysis
- **Network:** Security group and firewall rule audit
- **Web UI:** Provider selection, scan results with severity

### SMS Forge

Create and modify SMS/MMS backup XML files in SMS Backup & Restore format for Android.

- **Create:** Build fake conversations with realistic timestamps
- **Modify:** Edit existing backup files — change bodies, senders, timestamps
- **Templates:** Business meeting, casual chat, delivery notifications, verification codes
- **Export:** XML (SMS Backup & Restore compatible), CSV, HTML chat view
- **Web UI:** 3 tabs — Create (chat bubble preview), Editor, Tools

### RCS/SMS Exploitation (v2.0)

Comprehensive RCS/SMS database extraction, forging, modification, backup, and exploitation
on connected Android devices. Uses content providers (no root), Archon app relay with Shizuku,
CVE-2024-0044 privilege escalation, and direct bugle_db access. Messages in Google Messages'
bugle_db are stored as **plaintext** — no decryption needed.

**Exploitation Paths (in order of preference):**

1. Content providers at UID 2000 (shell/Shizuku) — SMS/MMS, no root needed
2. Archon app relay (READ_SMS + Shizuku) — full bugle_db access including RCS
3. CVE-2024-0044 exploit (Android 12-13 pre-Oct 2024 patch) — full app-UID access
4. ADB backup (deprecated Android 12+ but works on some devices)
5. Root access (if available)

**7 Tabs in Web UI:**

- **Extract** — Read SMS/MMS via content providers, query AOSP RCS provider (`content://rcs/`),
  enumerate all accessible messaging content providers, filter by address/keyword/thread, export
  to JSON/CSV/XML (SMS Backup & Restore format)
- **Database** — Extract Google Messages bugle_db (encrypted at rest — requires key extraction
  or Archon relay for decrypted access), run arbitrary SQL queries against extracted databases,
  extract RCS-only messages, conversation exports, message edit history, preset queries for
  common forensic tasks
- **Forge** — Insert fake SMS/MMS/RCS messages with arbitrary sender, body, timestamp, and
  direction. Forge entire conversations, bulk insert, import SMS Backup & Restore XML files.
  RCS forging via Archon relay for direct bugle_db insertion
- **Modify** — Change message bodies, senders, timestamps, type (inbox/sent). Shift all
  timestamps for an address, mark messages read, wipe threads, delete individual messages
- **Exploit** — CVE-2024-0044 run-as privilege escalation (check vulnerability, execute exploit,
  cleanup traces). RCS spoofing (typing indicators, read receipts). Clone RCS identity, extract
  Signal Protocol E2EE session state. Known CVE database (CVE-2023-24033 Exynos baseband,
  CVE-2024-49415 Samsung zero-click, CVE-2025-48593 Android system RCE). IMS/RCS diagnostics
  (dumpsys telephony_ims, carrier config, Phenotype verbose logging, RCS log capture, Pixel
  diagnostics, Google Messages debug menu activation via `*xyzzy*`)
- **Backup** — Full SMS/MMS/RCS backup to JSON or XML, restore from backup, clone messages to
  another device. Archon full backup (including RCS and attachments). Set default SMS app
  (Archon/Google Messages/Samsung). List saved backups and exports
- **Monitor** — Real-time SMS/RCS interception via logcat, intercepted message feed with
  auto-refresh

**Key bugle_db Tables** (encrypted at rest — requires decryption key or app-context access):
- `conversations` — Thread metadata, snippet, participants
- `messages` — `message_protocol` field: 0=SMS, 1=MMS, 2+=RCS
- `parts` — Message bodies in `text` column, attachment URIs
- `participants` — Phone numbers and contact names
- `message_edits` — RCS message edit history

**Database Encryption:**
- bugle_db uses SQLCipher / Android encrypted SQLite — raw file is unreadable without key
- Key stored in `shared_prefs/` XML files or Android Keystore (hardware-backed)
- Samsung devices add additional proprietary encryption layer
- Best extraction: Archon relay queries from decrypted app context (no key needed)
- CVE-2024-0044: run as app UID, can open DB with app's own key
- Root: extract DB + shared_prefs/ + files/ for offline key recovery

**AOSP RCS Provider URIs (content://rcs/):**
- `content://rcs/thread`, `content://rcs/p2p_thread`, `content://rcs/group_thread`
- `content://rcs/participant`, `content://rcs/.../message`, `content://rcs/.../file_transfer`

**Archon Integration:**
- Set Archon as default SMS app for full message access
- Query decrypted messages from within app context (bypasses DB encryption)
- Forge/modify RCS messages directly in bugle_db via broadcast commands
- Full backup including RCS messages and attachments

### Starlink Hack

Starlink terminal security analysis and exploitation for authorized testing.

- **Discovery:** Find dish on network (192.168.100.1), gRPC enumeration
- **gRPC Control:** Stow, unstow, reboot, factory reset via gRPC API
- **Firmware:** Version check against known vulnerabilities (CVE database)
- **Network:** Subnet scan, DNS/CGNAT bypass testing, WiFi security audit
- **RF Analysis:** Ku-band downlink capture with SDR (HackRF/RTL-SDR)
- **Web UI:** 4 tabs — Terminal, Attack, Signal, Network

---

## 18. Advanced Defense Tools

### Container Security

Docker and Kubernetes security auditing.

- **Docker:** Socket access audit, privileged container detection, capability review, image scanning
- **Kubernetes:** Pod enumeration, RBAC review, secrets exposure, network policies
- **Image Scan:** Trivy/Grype integration for CVE scanning
- **Container Escape:** Check for common breakout vectors
- **Web UI:** 3 tabs — Docker, Kubernetes, Image Scan

### Email Security

DMARC/SPF/DKIM analysis, email header forensics, and phishing detection.

- **DNS Records:** Validate DMARC, SPF, DKIM for any domain
- **Header Forensics:** Trace email routing, identify spoofing indicators
- **Phishing Detection:** URL analysis, attachment scanning, brand impersonation
- **Mailbox:** IMAP/POP3 connection, keyword search, export
- **Web UI:** 3 tabs — Analyze, Headers, Mailbox

### Incident Response

IR playbook runner, evidence collection, IOC sweeping, and timeline building.

- **Playbooks:** Step-by-step guided response (ransomware, data breach, insider threat, DDoS)
- **Evidence:** Automated log gathering, memory dump, disk image
- **IOC Sweeper:** Scan hosts for indicators from threat intel
- **Timeline:** Aggregate events from multiple sources into unified timeline
- **Web UI:** 4 tabs — Playbooks, Evidence, Sweep, Timeline

### Threat Intelligence

Threat feed aggregation, IOC management, and STIX/TAXII integration.

- **Feeds:** Aggregate from multiple threat intel sources
- **IOCs:** Manage indicators of compromise (IP, domain, hash, URL)
- **Correlation:** Cross-reference IOCs with local logs and network data
- **Web UI:** Feed management, IOC search, correlation results

### Log Correlator

Multi-source log aggregation and security event correlation.

- **Sources:** Syslog, Windows Event Log, application logs, network devices
- **Rules:** Correlation rules for detecting attack patterns
- **Alerts:** Real-time alerting on suspicious event combinations
- **Web UI:** Log viewer, rule editor, alert dashboard

---

## 19. Advanced Analysis Tools

### Reverse Engineering

Binary analysis, disassembly, YARA scanning, and hex viewing.

- **Binary Analysis:** File type detection, strings, entropy analysis
- **PE/ELF Parser:** Headers, sections, imports/exports, resources
- **Disassembler:** Capstone integration for x86/x64/ARM
- **Decompiler:** Ghidra headless integration
- **YARA Scanner:** Match binaries against rule sets
- **Packer Detection:** UPX, Themida, custom packer signatures
- **Web UI:** 4 tabs — Analyze, Disasm, YARA, Hex View

### Digital Forensics

Disk forensics, memory analysis, and artifact extraction.

- **Disk:** Image mounting, file system analysis, deleted file recovery
- **Memory:** Volatility integration for RAM analysis
- **Artifacts:** Browser history, registry hives, prefetch files
- **Timeline:** Forensic timeline from multiple evidence sources
- **Web UI:** Evidence management, analysis tools, reporting

### Steganography

Hide and extract data in images, audio, and other media.

- **Embed:** LSB encoding, DCT domain, spread spectrum
- **Extract:** Detect and extract hidden data from media files
- **Analysis:** Statistical steganalysis to detect hidden content
- **Web UI:** Embed, Extract, and Analyze tabs

### Anti-Forensics

Counter-forensics tools for testing forensic resilience.

- **Timestamp Manipulation:** Modify file timestamps
- **Log Cleaning:** Selective log entry removal
- **Secure Delete:** Overwrite and wipe files beyond recovery
- **Metadata Stripping:** Remove EXIF, document metadata
- **Web UI:** Tools for each anti-forensic technique

### Malware Sandbox

Safe malware detonation and behavior analysis.

- **Sandbox:** Isolated execution environment for suspicious files
- **Behavior:** System call monitoring, network activity, file changes
- **Reports:** Automated analysis reports with IOC extraction
- **Web UI:** Upload, execute, analyze, report

### BLE Scanner

Bluetooth Low Energy device discovery and security testing.

- **Discovery:** Scan for BLE devices, services, characteristics
- **Enumeration:** Read GATT services and characteristics
- **Fuzzing:** Write malformed data to characteristics
- **Tracking:** Monitor BLE advertisement patterns
- **Web UI:** Scan, enumerate, and test BLE devices

### RFID/NFC Tools

RFID and NFC card reading, cloning, and emulation.

- **Read:** UID, ATQA, SAK, data blocks from Mifare/NTAG
- **Clone:** Duplicate cards to writable blanks
- **Emulate:** NFC tag emulation for testing access systems
- **Web UI:** Card reader, data viewer, cloning tools

### Net Mapper

Network topology discovery and visualization.

- **Discovery:** Host discovery via nmap or ICMP/TCP ping sweep
- **Topology:** SVG visualization with force-directed layout
- **Diff:** Compare scans over time to detect changes
- **Web UI:** 3 tabs — Discover, Map, Saved Scans

### Report Engine

Professional penetration test report generation.

- **Templates:** Executive summary, methodology, findings, recommendations
- **Findings:** Pre-built templates with CVSS scores (OWASP Top 10)
- **Export:** HTML (styled), Markdown, JSON
- **Web UI:** 3 tabs — Reports, Editor, Templates

### Password Toolkit

Password analysis, generation, and cracking tools.

- **Analysis:** Strength checking, entropy calculation, policy compliance
- **Generation:** Secure password/passphrase generation
- **Cracking:** Dictionary, brute-force, rule-based attack simulation
- **Web UI:** Analyze, generate, and test passwords

---

## 20. SDR/RF & Starlink Tools

### SDR/RF Tools

Software-defined radio spectrum analysis with HackRF and RTL-SDR support.

- **Spectrum Analyzer:** Frequency scanning, signal strength visualization
- **RF Replay:** Capture and retransmit signals (authorized testing)
- **ADS-B:** Aircraft tracking via dump1090 integration
- **GPS Spoofing Detection:** Monitor for GPS signal anomalies
- **Drone Detection:** Real-time drone RF signature detection and classification
  - Scans 2.4 GHz, 5.8 GHz, 900 MHz, and 433 MHz bands
  - Identifies DJI OcuSync, analog/digital FPV, ExpressLRS, TBS Crossfire
  - FHSS pattern analysis for frequency-hopping protocols
  - Confidence-scored detections with protocol identification
  - All 32 standard 5.8 GHz FPV video channels mapped
- **Web UI:** 4 tabs — Spectrum, Capture/Replay, ADS-B, Drone Detection

### Starlink Hack

See [Section 17: Advanced Offense Tools — Starlink Hack](#starlink-hack) for full details.

---

## 21. Configuration & Settings

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

## 22. Troubleshooting

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

## 23. Quick Reference

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
| 1 | Defense | Blue | System hardening, shield, VPN, scan monitor, threat intel, container/email sec, incident response |
| 2 | Offense | Red | Metasploit, reverse shell, C2 framework, WiFi audit, deauth, vuln scanner, exploit dev, AD audit, MITM, pineapple, social eng, SMS forge, RCS tools, Starlink hack |
| 3 | Counter | Purple | Threat detection, rootkit scanning, steganography, anti-forensics |
| 4 | Analyze | Cyan | File forensics, packet capture, reverse engineering, BLE/RFID, malware sandbox, SDR/RF, drone detection |
| 5 | OSINT | Green | Username/email/domain/IP lookup, IP capture |
| 6 | Simulate | Yellow | Port scanning, payload generation, Legendary Creator |

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

## 24. Safety & Legal Notice

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

*AUTARCH v2.3 — By darkHal Security Group and Setec Security Labs*
*This manual covers all features including 59 web modules, 72 CLI modules, SDR drone detection, Starlink hacking, SMS/RCS exploitation, and the Archon companion app (March 2026)*
