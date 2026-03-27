# AUTARCH User Guide

## Project Overview

**AUTARCH** (Autonomous Tactical Agent for Reconnaissance, Counterintelligence, and Hacking) is a comprehensive security framework developed by **darkHal Security Group** and **Setec Security Labs**.

### What We Built

AUTARCH is a modular Python security framework featuring:

- **LLM Integration** - Local AI via llama.cpp for autonomous assistance
- **Autonomous Agent** - AI agent that can execute tools and complete tasks
- **Metasploit Integration** - Direct MSF RPC control from within the framework
- **Modular Architecture** - Plugin-based system for easy extension
- **6 Security Categories** - Defense, Offense, Counter, Analyze, OSINT, Simulate

---

## Project Structure

```
dh_framework/
├── autarch.py                  # Main entry point
├── autarch_settings.conf       # Configuration file
├── custom_adultsites.json      # Custom adult sites storage
├── custom_sites.inf            # Bulk import file
├── DEVLOG.md                   # Development log
├── GUIDE.md                    # This guide
│
├── core/                       # Core framework modules
│   ├── __init__.py
│   ├── agent.py               # Autonomous AI agent
│   ├── banner.py              # ASCII banner and colors
│   ├── config.py              # Configuration handler
│   ├── llm.py                 # LLM wrapper (llama-cpp-python)
│   ├── menu.py                # Main menu system
│   ├── msf.py                 # Metasploit RPC client
│   └── tools.py               # Agent tool registry
│
└── modules/                    # User-facing modules
    ├── __init__.py
    ├── setup.py               # First-time setup wizard
    ├── chat.py                # Interactive LLM chat (core)
    ├── agent.py               # Agent interface (core)
    ├── msf.py                 # Metasploit interface (offense)
    ├── defender.py            # System hardening (defense)
    ├── counter.py             # Threat detection (counter)
    ├── analyze.py             # Forensics tools (analyze)
    ├── recon.py               # OSINT reconnaissance (osint)
    ├── adultscan.py           # Adult site scanner (osint)
    └── simulate.py            # Attack simulation (simulate)
```

---

## Installation & Setup

### Requirements

- Python 3.8+
- llama-cpp-python (pre-installed)
- A GGUF model file for LLM features
- Metasploit Framework (optional, for MSF features)

### First Run

```bash
cd /home/snake/dh_framework
python autarch.py
```

On first run, the setup wizard automatically launches with options:
1. **Configure LLM** - Set up model for chat & agent features
2. **Skip Setup** - Use without LLM (most modules still work)

### Running Without LLM

Many modules work without an LLM configured:

```bash
# Skip setup on first run
python autarch.py --skip-setup
```

**Modules that work without LLM:**
- defender (Defense) - System hardening checks
- counter (Counter) - Threat detection
- analyze (Analyze) - File forensics
- recon (OSINT) - Email, username, domain lookup
- adultscan (OSINT) - Adult site scanner
- simulate (Simulate) - Port scan, payloads
- msf (Offense) - Metasploit interface

**Modules that require LLM:**
- chat - Interactive LLM chat
- agent - Autonomous AI agent

You can configure LLM later with `python autarch.py --setup`

---

## Command Line Interface

### Basic Usage

```bash
python autarch.py [OPTIONS] [COMMAND]
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message and exit |
| `-v, --version` | Show version information |
| `-c, --config FILE` | Use alternate config file |
| `--skip-setup` | Skip first-time setup (run without LLM) |
| `-m, --module NAME` | Run a specific module directly |
| `-l, --list` | List all available modules |
| `--setup` | Force run the setup wizard |
| `--no-banner` | Suppress the ASCII banner |
| `-q, --quiet` | Minimal output mode |

### Commands

| Command | Description |
|---------|-------------|
| `chat` | Start interactive LLM chat |
| `agent` | Start the autonomous agent |
| `scan <target>` | Quick port scan |
| `osint <username>` | Quick username OSINT |

### Examples

```bash
# Show help
python autarch.py --help

# Run a specific module
python autarch.py -m chat
python autarch.py -m adultscan

# List all modules
python autarch.py --list

# Quick OSINT scan
python autarch.py osint targetuser

# Re-run setup
python autarch.py --setup
```

---

## Main Menu Navigation

### Menu Structure

```
  Main Menu
  ──────────────────────────────────────────────────

  [1]  Defense      - Defensive security tools
  [2]  Offense      - Penetration testing
  [3]  Counter      - Counter-intelligence
  [4]  Analyze      - Analysis & forensics
  [5]  OSINT        - Open source intelligence
  [6]  Simulate     - Attack simulation

  [99] Settings
  [98] Exit
```

### Category Details

#### [1] Defense
System hardening and defensive security:
- Full Security Audit
- Firewall Check
- SSH Hardening
- Open Ports Scan
- User Security Check
- File Permissions Audit
- Service Audit

#### [2] Offense
Penetration testing with Metasploit:
- Search Modules
- Use/Configure Modules
- Run Exploits
- Manage Sessions
- Console Commands
- Quick Scanners

#### [3] Counter
Counter-intelligence and threat hunting:
- Full Threat Scan
- Suspicious Process Detection
- Network Analysis
- Login Anomalies
- File Integrity Monitoring
- Scheduled Task Audit
- Rootkit Detection

#### [4] Analyze
Forensics and file analysis:
- File Analysis (metadata, hashes, type)
- String Extraction
- Hash Lookup (VirusTotal, Hybrid Analysis)
- Log Analysis
- Hex Dump Viewer
- File Comparison

#### [5] OSINT
Open source intelligence gathering:
- **recon.py** - Email, username, phone, domain, IP lookup
- **adultscan.py** - Adult site username scanner

#### [6] Simulate
Attack simulation and red team:
- Password Audit
- Port Scanner
- Banner Grabber
- Payload Generator (XSS, SQLi, etc.)
- Network Stress Test

---

## Module Reference

### Core Modules

#### chat.py - Interactive Chat
```
Category: core
Commands:
  /help      - Show available commands
  /clear     - Clear conversation history
  /history   - Show conversation history
  /info      - Show model information
  /system    - Set system prompt
  /temp      - Set temperature
  /tokens    - Set max tokens
  /stream    - Toggle streaming
  /exit      - Exit chat
```

#### agent.py - Autonomous Agent
```
Category: core
Commands:
  tools      - Show available tools
  exit       - Return to main menu
  help       - Show help

Available Tools:
  shell          - Execute shell commands
  read_file      - Read file contents
  write_file     - Write to files
  list_dir       - List directory contents
  search_files   - Glob pattern search
  search_content - Content search (grep)
  task_complete  - Signal completion
  ask_user       - Request user input
  msf_*          - Metasploit tools
```

### OSINT Modules

#### recon.py - OSINT Reconnaissance
```
Category: osint
Version: 2.0

Menu:
  Email
    [1] Email Lookup
    [2] Email Permutator

  Username
    [3] Username Lookup (17+ platforms)
    [4] Social Analyzer integration

  Phone
    [5] Phone Number Lookup

  Domain/IP
    [6] Domain Recon
    [7] IP Address Lookup
    [8] Subdomain Enumeration
    [9] Technology Detection
```

#### adultscan.py - Adult Site Scanner
```
Category: osint
Version: 1.3

Menu:
  Scan Categories:
    [1] Full Scan (all categories)
    [2] Fanfiction & Story Sites
    [3] Art & Creative Sites
    [4] Video & Streaming Sites
    [5] Forums & Communities
    [6] Dating & Social Sites
    [7] Gaming Related Sites
    [8] Custom Sites Only
    [9] Custom Category Selection

  Site Management:
    [A] Add Custom Site (manual)
    [D] Auto-Detect Site Pattern
    [B] Bulk Import from File
    [M] Manage Custom Sites
    [L] List All Sites

Sites Database: 50+ built-in sites
Categories: fanfiction, art, video, forums, dating, gaming, custom
```

##### Adding Custom Sites

**Manual Add [A]:**
```
Site name: MySite
URL pattern (use * for username): mysite.com/user/*
Detection Method: [1] Status code
```

**Auto-Detect [D]:**
```
Domain: example.com
Test username: knownuser
(System probes 17 common patterns)
```

**Bulk Import [B]:**

1. Edit `custom_sites.inf`:
```
# One domain per line
site1.com
site2.net
site3.org
```

2. Run Bulk Import and provide test username
3. System auto-detects patterns for each domain

---

## Configuration

### Config File: autarch_settings.conf

```ini
[llama]
model_path = /path/to/model.gguf
n_ctx = 4096
n_threads = 4
n_gpu_layers = 0
temperature = 0.7
top_p = 0.9
top_k = 40
repeat_penalty = 1.1
max_tokens = 2048
seed = -1

[autarch]
first_run = false
modules_path = modules
verbose = false

[msf]
host = 127.0.0.1
port = 55553
username = msf
password =
ssl = true
```

### LLM Settings

| Setting | Default | Description |
|---------|---------|-------------|
| model_path | (required) | Path to GGUF model file |
| n_ctx | 4096 | Context window size |
| n_threads | 4 | CPU threads for inference |
| n_gpu_layers | 0 | Layers to offload to GPU |
| temperature | 0.7 | Sampling temperature (0.0-2.0) |
| top_p | 0.9 | Nucleus sampling threshold |
| top_k | 40 | Top-K sampling |
| repeat_penalty | 1.1 | Repetition penalty |
| max_tokens | 2048 | Maximum response length |
| seed | -1 | Random seed (-1 = random) |

### Metasploit Settings

| Setting | Default | Description |
|---------|---------|-------------|
| host | 127.0.0.1 | MSF RPC host |
| port | 55553 | MSF RPC port |
| username | msf | RPC username |
| password | (none) | RPC password |
| ssl | true | Use SSL connection |

**Starting msfrpcd:**
```bash
msfrpcd -P yourpassword -S -a 127.0.0.1
```

---

## Creating Custom Modules

### Module Template

```python
"""
Module description here
"""

# Module metadata (required)
DESCRIPTION = "Short description"
AUTHOR = "Your Name"
VERSION = "1.0"
CATEGORY = "osint"  # defense, offense, counter, analyze, osint, simulate, core

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


def run():
    """Main entry point - REQUIRED"""
    clear_screen()
    display_banner()

    print(f"{Colors.BOLD}My Module{Colors.RESET}")
    # Your code here


if __name__ == "__main__":
    run()
```

### Available Colors

```python
from core.banner import Colors

Colors.RED
Colors.GREEN
Colors.YELLOW
Colors.BLUE
Colors.MAGENTA
Colors.CYAN
Colors.WHITE
Colors.BOLD
Colors.DIM
Colors.RESET
```

### Module Categories

| Category | Color | Description |
|----------|-------|-------------|
| defense | Blue | Defensive security |
| offense | Red | Penetration testing |
| counter | Magenta | Counter-intelligence |
| analyze | Cyan | Forensics & analysis |
| osint | Green | Open source intelligence |
| simulate | Yellow | Attack simulation |
| core | White | Core framework modules |

---

## Agent Tools Reference

The autonomous agent has access to these tools:

### File Operations
```
read_file(path)           - Read file contents
write_file(path, content) - Write to file
list_dir(path)            - List directory
search_files(pattern)     - Glob search
search_content(pattern)   - Grep search
```

### System Operations
```
shell(command, timeout)   - Execute shell command
```

### User Interaction
```
ask_user(question)        - Prompt user for input
task_complete(result)     - Signal task completion
```

### Metasploit Operations
```
msf_connect()                    - Connect to MSF RPC
msf_search(query)                - Search modules
msf_module_info(module)          - Get module info
msf_module_options(module)       - Get module options
msf_execute(module, options)     - Execute module
msf_sessions()                   - List sessions
msf_session_command(id, cmd)     - Run session command
msf_console(command)             - Direct console
```

---

## Troubleshooting

### Common Issues

**LLM not loading:**
- Verify model_path in autarch_settings.conf
- Check file permissions on model file
- Ensure sufficient RAM for model size

**MSF connection failed:**
- Verify msfrpcd is running: `msfrpcd -P password -S`
- Check host/port in settings
- Verify password is correct

**Module not appearing:**
- Ensure module has `CATEGORY` attribute
- Ensure module has `run()` function
- Check for syntax errors

**Adult scanner false positives:**
- Some sites return 200 for all requests
- Use content-based detection for those sites
- Verify with a known username

### Debug Mode

```bash
# Enable verbose output
python autarch.py --verbose

# Check configuration
python autarch.py --show-config
```

---

## Security Notice

AUTARCH is designed for **authorized security testing only**. Users are responsible for:

- Obtaining proper authorization before testing
- Complying with all applicable laws
- Using tools ethically and responsibly

**Do not use for:**
- Unauthorized access
- Harassment or stalking
- Any illegal activities

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-14 | Initial release |
| 1.1 | 2026-01-14 | Added custom site management |
| 1.2 | 2026-01-14 | Added auto-detect patterns |
| 1.3 | 2026-01-14 | Added bulk import |

---

## Credits

**Project AUTARCH**
By darkHal Security Group and Setec Security Labs

---

*For development history, see DEVLOG.md*
