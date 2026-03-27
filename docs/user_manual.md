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
4. [The Privileged Daemon](#4-the-privileged-daemon)
5. [Network Security](#5-network-security)
6. [Defense Tools](#6-defense-tools)
7. [Offense Tools](#7-offense-tools)
8. [Counter-Intelligence](#8-counter-intelligence)
9. [Analysis & Forensics](#9-analysis--forensics)
10. [OSINT (Intelligence Gathering)](#10-osint-intelligence-gathering)
11. [Attack Simulation](#11-attack-simulation)
12. [Hardware & Device Management](#12-hardware--device-management)
13. [Android Protection Shield](#13-android-protection-shield)
14. [WireGuard VPN](#14-wireguard-vpn)
15. [Reverse Shell](#15-reverse-shell)
16. [Archon Companion App](#16-archon-companion-app)
17. [AI Chat & Agents](#17-ai-chat--agents)
18. [HAL AI Analyst](#18-hal-ai-analyst)
19. [MCP Server](#19-mcp-server)
20. [Encrypted Vault](#20-encrypted-vault)
21. [Module Creator](#21-module-creator)
22. [Desktop Launcher](#22-desktop-launcher)
23. [Advanced Offense Tools](#23-advanced-offense-tools)
24. [Advanced Defense Tools](#24-advanced-defense-tools)
25. [Advanced Analysis Tools](#25-advanced-analysis-tools)
26. [SDR/RF & Starlink Tools](#26-sdrrf--starlink-tools)
27. [Configuration & Settings](#27-configuration--settings)
28. [Troubleshooting](#28-troubleshooting)
29. [Quick Reference](#29-quick-reference)
30. [Safety & Legal Notice](#30-safety--legal-notice)

---

## 1. Getting Started

### What You Need

- A computer running Linux (AUTARCH is built for Orange Pi 5 Plus / ARM64, but works on any Linux)
- Python 3.10 or newer (already installed on most Linux systems)
- A web browser (for the dashboard)
- An Android phone (optional, for companion app features)

### Setting Up the Virtual Environment

Before running AUTARCH for the first time, set up an isolated Python environment so that dependencies do not conflict with your system packages:

```
bash scripts/setup-venv.sh
```

This creates a `venv/` directory inside the AUTARCH folder. Once the venv exists, you can use it explicitly with:

```
./venv/bin/python autarch.py
```

All of the launch methods described below (the launcher, `start.sh`, manual start) will use the venv automatically if it exists. If you skip this step, AUTARCH falls back to your system Python.

### Starting AUTARCH

There are three ways to start AUTARCH. Pick whichever fits your workflow.

#### Option A: The Desktop Launcher (Recommended)

```
python3 launcher.py
```

This opens a GTK window with a splash screen, EULA acknowledgement, and buttons for Start All / Stop All / Reload. It starts both the privileged daemon and the web dashboard for you. See [Section 22: Desktop Launcher](#22-desktop-launcher) for full details.

#### Option B: Shell Scripts

```
bash start.sh        # Start daemon + web dashboard
bash stop.sh         # Stop everything
```

`start.sh` handles the correct startup order — it launches the privileged daemon first (with `sudo`), waits for it to be ready, then starts the Flask web server. `stop.sh` tears everything down cleanly.

#### Option C: Manual Start

If you want full control, start each component yourself:

```
sudo python3 core/daemon.py       # Step 1: start the privileged daemon
python3 autarch.py --web           # Step 2: start the web dashboard
```

The daemon must be running before the web dashboard so that tools requiring root access (iptables, WiFi scanning, packet capture, etc.) work correctly. See [Section 4: The Privileged Daemon](#4-the-privileged-daemon) for why this matters.

#### Starting the CLI Only

If you just want the terminal menu (no web dashboard, no daemon needed for basic tools):

```
python3 autarch.py
```

### First-Time Setup

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
| `python autarch.py --mcp stdio` | Start MCP server (stdio) for Claude |
| `python autarch.py --mcp sse` | Start MCP server (SSE) for web clients |
| `python autarch.py --service start` | Start as background service |
| `python autarch.py -h` | Show all command line options |
| `bash start.sh` | Start daemon + web (recommended) |
| `bash stop.sh` | Stop everything |
| `python3 launcher.py` | Open the GTK desktop launcher |

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

The web dashboard gives you the same tools as the CLI, but in a visual browser interface. AUTARCH v2.4 includes 1,130 web routes across 63 route files, rendering 74 templates, backed by 40 core files and 73 CLI modules.

### Starting the Dashboard

From the CLI menu, select **[8] Web Service**, or run:

```
python autarch.py --web
```

Or use `bash start.sh` to start both the daemon and the web dashboard together.

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
- **Network Security** — Connection monitoring, IDS, rogue device detection, WiFi scanning, attack detection

**System** — Infrastructure management:
- **UPnP** — Port forwarding
- **WireGuard** — VPN management
- **DNS Server** — Built-in DNS service
- **MSF Console** — Metasploit terminal
- **Chat** — AI chat interface
- **Module Creator** — Create new AUTARCH modules from the browser
- **MCP Settings** — Model Context Protocol server configuration
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

## 4. The Privileged Daemon

AUTARCH uses a split-privilege architecture. The web dashboard runs as your normal user (so `pip install` and Python packages work without permission issues), while a separate daemon runs as root to handle operations that require elevated privileges.

### Why It Exists

Many security tools need root access — `iptables` for firewall rules, raw sockets for WiFi scanning, `tcpdump` for packet capture, ARP table manipulation, and more. Rather than running the entire Flask web server as root (which would be a security risk), AUTARCH runs only the daemon as root. The web server sends requests to the daemon when it needs a privileged operation.

### How It Works

The daemon listens on a Unix domain socket at:

```
/var/run/autarch-daemon.sock
```

When the web dashboard needs to run a privileged command (for example, flushing an ARP entry or starting a WiFi scan), it sends a signed request to the daemon over this socket. The daemon validates the request, checks the command against its whitelist, and executes it.

### Security Measures

The daemon implements multiple layers of protection:

- **HMAC-SHA256 signed requests** — Every request from the web server must be signed with a shared secret. The daemon rejects unsigned or incorrectly signed requests.
- **SO_PEERCRED peer verification** — The daemon checks the identity of the connecting process via the kernel's socket credentials. Only the expected user can communicate with it.
- **Nonce replay protection** — Each request includes a unique nonce. The daemon tracks recent nonces and rejects duplicates, preventing replay attacks.
- **Command whitelist** — Only 68 specific commands are allowed. Everything else is denied.
- **Built-in actions** — In addition to the 68 whitelisted shell commands, the daemon handles packet capture and WiFi scanning as built-in actions that bypass the shell entirely:
  - `__capture__` — Runs scapy's `sniff()` as root, writes pcap files with 644 permissions so the unprivileged web server can read them. No separate capture agent is needed.
  - `__wifi_scan__` — Runs `iw dev scan` as root for WiFi enumeration.
- **Blocked patterns** — 45 dangerous patterns (like `rm -rf /`, pipe to shell, etc.) are explicitly blocked even if they appear inside an allowed command.

### Starting the Daemon

The daemon is started automatically by `start.sh` and the desktop launcher. To start it manually:

```
sudo python3 core/daemon.py
```

### Cleanup

When the daemon shuts down (via `stop.sh`, the launcher, or a signal), it cleans up after itself:
- Removes the Unix socket file
- Removes its PID file
- Removes the shared secret file

This prevents stale socket files from blocking the next startup.

---

## 5. Network Security

The Network Security page is a dedicated section of the web dashboard for monitoring and defending your local network. It is organized into 8 tabs, each focused on a different aspect of network defense.

### Connections Tab

Displays your machine's current network state:

- **Active Connections** — All TCP/UDP connections from `ss`, showing local address, remote address, state, and process
- **ARP Table** — Every device your machine has communicated with recently, listed by IP and MAC address
- **Network Interfaces** — All network interfaces (Ethernet, WiFi, VPN, loopback) with their IP addresses and status

This is the first place to look when you want to understand what your machine is talking to right now.

### Intrusion Detection Tab

Runs a battery of checks to detect active attacks on your network:

- **ARP Spoof Detection** — Checks if two different IPs claim the same MAC address (a sign of ARP poisoning)
- **Promiscuous Mode Detection** — Flags network interfaces that are in promiscuous mode (may indicate a sniffer)
- **Unauthorized DHCP Servers** — Scans for DHCP servers that should not be on your network (rogue DHCP is a common MITM technique)
- **Suspicious Connections** — Identifies connections to known-bad ports or unusual destinations
- **Raw Socket Processes** — Lists processes that have opened raw sockets (used for packet sniffing or crafting)

### Rogue Devices Tab

Helps you detect unknown devices on your network:

- Scans the ARP table and compares it against a **known device baseline** you build over time
- New or unknown devices are flagged for your review
- You can **trust** a device (add it to your baseline) or **block** it
- Useful for detecting unauthorized devices that have joined your WiFi or plugged into your switch

### Monitor Tab

A real-time connection feed powered by Server-Sent Events (SSE):

- Shows new connections as they appear, without needing to refresh the page
- Useful for watching network activity during an investigation or while running other tools
- Runs continuously in the background — just leave the tab open

### WiFi Scanner Tab

Scans for nearby wireless networks using `nmcli` or `iwlist`:

- Lists all visible access points with SSID, BSSID (MAC), channel, signal strength, and security type (Open, WEP, WPA2, WPA3)
- Helps you identify your own networks, detect neighbors, and spot rogue access points
- No monitor-mode adapter required — uses your normal WiFi interface

### Attack Detection Tab

Automated detection of common wireless and network attacks:

- **Deauth Flood Detection** — Identifies mass deauthentication frames (used to knock devices off WiFi)
- **Evil Twin Detection** — Finds access points that clone your SSID but have a different BSSID
- **Pineapple / Rogue AP Detection** — Identifies access points with suspicious characteristics (known pineapple MACs, Karma-like behavior)
- **MITM / ARP Poisoning** — Detects when your gateway's MAC address changes unexpectedly
- **SSL Strip Detection** — Identifies signs of HTTPS downgrade attacks

Each detection includes links to the relevant pentest tools in AUTARCH's offense suite, so you can investigate further or simulate the attack yourself in a lab.

### ARP Spoof Tab

A deep-dive tool specifically for ARP spoofing defense:

- **Gateway MAC Baseline** — Records your gateway's legitimate MAC address so AUTARCH can detect when it changes
- **Deep Scan** — Sends ARP requests to every host on the subnet and compares responses to the baseline
- **Remediation Tools:**
  - **Flush & Static** — Clears the ARP cache and sets a static entry for your gateway, preventing spoofing
  - **Kernel Protection** — Enables kernel-level ARP validation (`arp_accept`, `arp_announce`, `arp_ignore`)
  - **Per-Entry Flush** — Flush a single suspicious ARP entry without clearing the entire cache
- **How-To Guide** — Built-in step-by-step guide explaining what ARP spoofing is, how to detect it, and how to fix it

### SSID Map Tab

Groups all detected access points by SSID:

- Shows every SSID visible in your area
- Under each SSID, lists all BSSIDs (individual access points) broadcasting that name
- Useful for identifying networks with multiple access points (mesh, enterprise) vs. potential evil twins (same SSID, unexpected BSSID)

---

## 6. Defense Tools

Defense tools help you check and strengthen your system's security. In AUTARCH v2.4, every defense tool automatically sends its output to the HAL AI Analyst for intelligent analysis. See [Section 18: HAL AI Analyst](#18-hal-ai-analyst) for details.

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
4. HAL automatically analyzes the output — look for the risk badge and recommendations in the HAL chat panel

### Tips

- Run the **Full Security Audit** first to get an overview
- If you see red warnings, address those first — they're the most critical
- The **Scan Monitor** runs continuously — press Ctrl+C to stop it in CLI mode
- When HAL identifies a fixable issue, you can click "Let HAL Fix It" to apply the recommended remediation

---

## 7. Offense Tools

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

See [Section 15: Reverse Shell](#15-reverse-shell) for detailed instructions.

---

## 8. Counter-Intelligence

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

## 9. Analysis & Forensics

These tools help you examine files, network traffic, and system artifacts. Like defense tools, analysis results are automatically sent to HAL for intelligent commentary.

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

Packet capture goes through the privileged daemon — no separate capture agent is needed. The daemon runs scapy's `sniff()` as root via the `__capture__` built-in action and writes pcap files with 644 permissions so the web dashboard can read them.

**In the web UI:** The Wireshark page gives you a visual packet inspector.

---

## 10. OSINT (Intelligence Gathering)

OSINT (Open Source Intelligence) tools help you find publicly available information about people, domains, and IP addresses. AUTARCH v2.4 checks against **25,475 sites** across all OSINT modules.

### Username Lookup

Check if a username exists across thousands of websites:

1. Enter a username
2. AUTARCH checks sites simultaneously using parallel threads
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

## 11. Attack Simulation

Simulation tools let you test attack scenarios in a controlled way.

| Tool | What It Does |
|------|-------------|
| **Password Audit** | Tests password strength with common patterns |
| **Port Scanner** | Quick port scanning (lighter than nmap) |
| **Banner Grabber** | Identifies services by their response banners |
| **Payload Generator** | Creates test payloads (XSS, SQLi, command injection) |
| **Network Stress Test** | Tests how many connections a service can handle |

---

## 12. Hardware & Device Management

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

## 13. Android Protection Shield

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

## 14. WireGuard VPN

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

## 15. Reverse Shell

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

## 16. Archon Companion App

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

## 17. AI Chat & Agents

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
| **OpenAI API** | Fast | Paid | Excellent |

Configure in Settings → LLM Settings, or edit `autarch_settings.conf`.

---

## 18. HAL AI Analyst

HAL is AUTARCH's built-in AI analyst. It watches the output of every defensive and analysis tool and provides automatic, intelligent commentary — explaining what the results mean, highlighting risks, and suggesting next steps.

### How It Works

1. **You run a tool** — for example, a firewall check, an ARP spoof scan, or a forensic analysis
2. **HAL receives the output** — the tool's results are automatically sent to whatever LLM backend you have configured (Claude, OpenAI, local model, HuggingFace)
3. **HAL analyzes** — while the AI is thinking, the HAL button in the web interface pulses with status messages so you know it is working
4. **Results appear** — HAL's analysis shows up in the HAL chat panel on the right side of the page, complete with a risk level badge (Info, Low, Medium, High, Critical)

You do not need to copy/paste output or ask HAL to look at anything. It happens automatically for every tool that produces security-relevant output.

### The HAL Chat Panel

The HAL panel is always visible on the right side of the web dashboard. It contains:

- **Analysis messages** — Each analysis includes a risk badge, a plain-English explanation of what was found, and specific recommendations
- **Auto-Fix button** — When HAL identifies a problem it knows how to fix, it extracts the remediation commands from its analysis. A "Let HAL Fix It" button appears, and clicking it executes those commands (via the privileged daemon if root is needed)
- **Feedback toggle (FB button)** — In the HAL panel header, the FB button lets you disable automatic analysis. When disabled, HAL will not analyze tool output until you re-enable it. Useful if you are running many tools quickly and do not want to wait for AI processing
- **Stop button** — Stops HAL mid-generation if you do not need the rest of the analysis

### Supported Backends

HAL works with every LLM backend AUTARCH supports:
- Claude API
- OpenAI API
- Local GGUF models
- HuggingFace Inference API
- Local Transformers models

If no LLM is configured, HAL stays inactive. Configure a backend in Settings → LLM Settings to enable it.

---

## 19. MCP Server

MCP (Model Context Protocol) lets AI assistants like Claude Desktop and Claude Code use AUTARCH's tools directly.

### What It Is

The Model Context Protocol is a standard that allows AI applications to call external tools. When you enable AUTARCH's MCP server, Claude (or any MCP-compatible client) can run scans, look up IPs, capture packets, and more — all through natural language conversation.

### Starting the MCP Server

```
# For Claude Desktop or Claude Code (stdio transport)
python autarch.py --mcp stdio

# For web-based clients (SSE transport)
python autarch.py --mcp sse --mcp-port 8081
```

You can also configure and start the MCP server from the web dashboard under **Settings → MCP Server**.

### What Tools Are Exposed

AUTARCH exposes 11 tools via MCP:

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

Add to your Claude Desktop configuration file (`claude_desktop_config.json`):

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

### How to Use with Claude Code

In your Claude Code MCP configuration, add AUTARCH the same way — point the command at `autarch.py --mcp stdio`. Claude Code will discover the available tools and use them when relevant.

---

## 20. Encrypted Vault

AUTARCH v2.4 stores sensitive credentials (API keys, tokens, passwords) in an encrypted vault rather than in plaintext configuration files.

### How It Works

- All secrets are stored in `data/vault.enc`
- The vault uses **AES-256-CBC** encryption
- The encryption key is derived using **PBKDF2-HMAC-SHA256** with a high iteration count
- The key derivation is tied to your **machine identity** (from `/etc/machine-id`), so the vault file cannot be decrypted on a different machine

### What Gets Stored

Any API key or token that you enter in Settings is stored in the vault:
- Claude API key
- OpenAI API key
- HuggingFace token
- Metasploit RPC password
- Any other credential managed by AUTARCH

### Automatic Migration

If you are upgrading from an earlier version of AUTARCH that stored API keys in plaintext inside `autarch_settings.conf`, the vault handles migration automatically:

1. On first run, AUTARCH checks `autarch_settings.conf` for plaintext API keys
2. Any keys found are encrypted and stored in `data/vault.enc`
3. The plaintext values are cleared from the config file

You do not need to do anything — the migration is transparent. After migration, the `.conf` file will have empty key fields, and the actual values will live safely in the vault.

### Security Notes

- The vault is only as secure as your machine. If someone has root access to your AUTARCH host, they can decrypt the vault (because they can read `/etc/machine-id`)
- The vault protects against casual file browsing, accidental exposure in screenshots, and config file leaks (e.g., if you share your `.conf` file)
- Back up `data/vault.enc` if you need to preserve your credentials. Remember that the backup is only usable on the same machine

---

## 21. Module Creator

The Module Creator lets you build new AUTARCH modules directly from the web dashboard — no need to manually create files or remember the module structure.

### What It Does

- **Template generator** — Select a module category (Defense, Offense, Counter, Analyze, OSINT, Simulate) and the creator generates a properly structured Python module with all the boilerplate filled in
- **Python syntax validation** — Before saving, the creator checks your code for syntax errors and highlights problems
- **Module browser** — Browse all existing modules, view their source code, and edit them in place

### How to Use

1. In the web dashboard, click **Module Creator** in the sidebar
2. Choose a category for your new module
3. Fill in the module name, description, and any custom code
4. Click **Create** — the creator validates the syntax and writes the file to the `modules/` directory
5. Your new module immediately appears in the CLI menu and web dashboard

### Editing Existing Modules

1. Open the Module Creator
2. Use the module browser to find the module you want to edit
3. Click on it to load its source code into the editor
4. Make your changes and save

---

## 22. Desktop Launcher

The Desktop Launcher is a GTK application for Linux desktops (GNOME, KDE, and other GTK-compatible environments). It provides a graphical way to manage AUTARCH without touching the terminal.

### Starting the Launcher

```
python3 launcher.py
```

Or, if you have installed the `.desktop` file (located at `scripts/autarch.desktop`), you can launch it from your GNOME/KDE application menu like any other app.

### Splash Screen

On first launch, the launcher displays a splash screen with:
- The AUTARCH EULA (End User License Agreement)
- Privacy acknowledgements
- A consent button you must accept before proceeding

This only appears once. After acceptance, the launcher opens directly to the control panel.

### Controls

The launcher window provides:

- **Start All** — Starts the privileged daemon and web dashboard together (equivalent to `bash start.sh`)
- **Stop All** — Stops both the daemon and web server cleanly (equivalent to `bash stop.sh`)
- **Reload** — Restarts the web server without stopping the daemon (picks up config changes)
- **Individual controls** — Start or stop the daemon and web server independently

### Settings Tabs

The launcher includes built-in settings editors:

- **WebUI tab** — Configure the web dashboard host, port, and authentication
- **Daemon tab** — Configure daemon socket path, logging, and behavior
- **Whitelist editor** — View and modify the daemon's command whitelist (the 68 allowed commands)

### Installing the Desktop Entry

To add AUTARCH to your application launcher:

```
cp scripts/autarch.desktop ~/.local/share/applications/
```

After this, AUTARCH appears in your GNOME Activities or KDE application menu.

---

## 23. Advanced Offense Tools

AUTARCH v2.4 includes a comprehensive suite of offense modules for authorized penetration testing.

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

## 24. Advanced Defense Tools

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

## 25. Advanced Analysis Tools

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

## 26. SDR/RF & Starlink Tools

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

See [Section 23: Advanced Offense Tools — Starlink Hack](#starlink-hack) for full details.

---

## 27. Configuration & Settings

### The Config File

All settings live in `autarch_settings.conf` in the AUTARCH directory. You can edit it with any text editor, or use the Settings menu. API keys and tokens are stored separately in the encrypted vault (see [Section 20: Encrypted Vault](#20-encrypted-vault)).

### Key Settings

**LLM (AI Model)**
```ini
[autarch]
llm_backend = local          # local, transformers, claude, openai, or huggingface

[llama]
model_path = /path/to/model.gguf
n_ctx = 4096                 # Context window size
n_threads = 4                # CPU threads
temperature = 0.7            # Creativity (0.0 = precise, 1.0 = creative)
max_tokens = 2048            # Max response length

[claude]
api_key = <stored in vault>
model = claude-sonnet-4-20250514

[huggingface]
api_key = <stored in vault>
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

## 28. Troubleshooting

### "Module not found" error
- Run `python autarch.py --list` to see available modules
- Check that the module file exists in the `modules/` directory
- Make sure the file has a `run()` function

### Web dashboard won't start
- Check if port 8080 is already in use: `ss -tlnp | grep 8080`
- Try a different port: `python autarch.py --web --web-port 9090`
- Check the terminal for error messages

### Daemon won't start
- Make sure you are running it with `sudo`: `sudo python3 core/daemon.py`
- Check if the socket file already exists: `ls -la /var/run/autarch-daemon.sock` — if it does, a previous daemon may not have shut down cleanly. Remove the stale socket file and try again
- Check the terminal output for permission errors

### Web tools say "daemon not running" or "permission denied"
- Make sure the daemon is running: check for the process with `ps aux | grep daemon.py`
- If you started the web server manually, make sure you started the daemon first
- Use `bash start.sh` to start both in the correct order

### AI chat says "no model configured"
- Run `python autarch.py --setup` to configure an AI backend
- For local models: make sure `model_path` points to a valid `.gguf` file
- For cloud APIs: verify your API key is correct (check Settings → LLM Settings)

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

### HAL not analyzing tool output
- Make sure an LLM backend is configured (Settings → LLM Settings)
- Check that the Feedback toggle (FB button) in the HAL panel header is not set to "off"
- If using a cloud API, verify your API key and check for rate limits

### Vault errors or lost API keys
- The vault is tied to your machine identity. If `/etc/machine-id` has changed (e.g., after an OS reinstall), the old vault cannot be decrypted
- Re-enter your API keys in Settings — they will be stored in a new vault

### Packet capture not working
- Make sure the daemon is running (`bash start.sh`). The daemon runs scapy as root for packet capture
- Check daemon status with: `ls -la /var/run/autarch-daemon.sock`

### App crashes or hangs
- Check the terminal for Python traceback errors
- Run with `--verbose` for more detail: `python autarch.py --verbose`
- Make sure all Python dependencies are installed: `pip install -r requirements.txt`
- If using the venv: `./venv/bin/pip install -r requirements.txt`

---

## 29. Quick Reference

### Most-Used Commands

```bash
bash start.sh                        # Start daemon + web (recommended)
bash stop.sh                         # Stop everything
python3 launcher.py                  # GTK desktop launcher
python autarch.py                    # Interactive CLI menu
python autarch.py --web              # Web dashboard only (no daemon)
sudo python3 core/daemon.py          # Daemon only (manual start)
python autarch.py -m chat            # AI chat
python autarch.py -m adultscan       # Username scanner
python autarch.py osint <username>   # Quick OSINT
python autarch.py -l                 # List all modules
python autarch.py --setup            # Setup wizard
python autarch.py --show-config      # View settings
python autarch.py --mcp stdio        # MCP server (stdio)
python autarch.py --mcp sse          # MCP server (SSE)
python autarch.py --service status   # Check web service
bash scripts/setup-venv.sh           # Create virtual environment
```

### Module Categories

| # | Category | Color | What's In It |
|---|----------|-------|-------------|
| 1 | Defense | Blue | System hardening, shield, VPN, scan monitor, threat intel, container/email sec, incident response, network security |
| 2 | Offense | Red | Metasploit, reverse shell, C2 framework, WiFi audit, deauth, vuln scanner, exploit dev, AD audit, MITM, pineapple, social eng, SMS forge, RCS tools, Starlink hack |
| 3 | Counter | Purple | Threat detection, rootkit scanning, steganography, anti-forensics |
| 4 | Analyze | Cyan | File forensics, packet capture, reverse engineering, BLE/RFID, malware sandbox, SDR/RF, drone detection |
| 5 | OSINT | Green | Username/email/domain/IP lookup across 25,475 sites, IP capture |
| 6 | Simulate | Yellow | Port scanning, payload generation, Legendary Creator |

### Key Ports

| Port | Service |
|------|---------|
| 8080 | Web dashboard |
| 8081 | MCP server (SSE mode) |
| 17321 | Archon Server (on phone, localhost only) |
| 17322 | Reverse Shell listener |
| 51820 | WireGuard VPN |

### Key Sockets

| Path | Service |
|------|---------|
| `/var/run/autarch-daemon.sock` | Privileged daemon |

### File Locations

| File | Purpose |
|------|---------|
| `autarch.py` | Main entry point |
| `autarch_settings.conf` | All configuration |
| `launcher.py` | GTK desktop launcher |
| `start.sh` | Start daemon + web |
| `stop.sh` | Stop everything |
| `core/daemon.py` | Privileged daemon |
| `core/vault.py` | Encrypted credential vault |
| `core/hal_analyst.py` | HAL AI analyst engine |
| `modules/` | CLI tool modules (73 modules) |
| `core/` | Core framework libraries (40 files) |
| `web/` | Web dashboard (Flask) — 63 route files, 74 templates |
| `web/routes/module_creator.py` | Module creator backend |
| `web/templates/module_creator.html` | Module creator UI |
| `web/routes/network.py` | Network security backend |
| `web/templates/network.html` | Network security UI |
| `web/templates/mcp_settings.html` | MCP server settings UI |
| `scripts/setup-venv.sh` | Virtual environment setup |
| `scripts/autarch.desktop` | GNOME/KDE desktop entry |
| `scripts/autarch-daemon.service` | Systemd unit for daemon |
| `tools/linux-arm64/` | Bundled tools (nmap, tcpdump, etc.) |
| `android/` | ADB and Fastboot binaries |
| `autarch_companion/` | Android companion app source |
| `data/` | Runtime data (screenshots, downloads, databases) |
| `data/vault.enc` | Encrypted API key vault |

---

## 30. Safety & Legal Notice

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

*AUTARCH v2.4 — By darkHal Security Group and Setec Security Labs*
*This manual covers all features including 1,130 web routes, 73 CLI modules, 74 templates, 63 route files, 40 core files, 25,475 OSINT sites, the privileged daemon, HAL AI analyst, encrypted vault, network security suite, MCP server, module creator, desktop launcher, and the Archon companion app (March 2026)*
