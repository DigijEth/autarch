# AUTARCH Development Log
## Project: darkHal Security Group - Project AUTARCH

---

## Session 1 - 2026-01-14

### Initial Request

**User Prompt:**
> Hello claude. Today we are building the framework for the darkHal Security Group's "Project AUTARCH". Right now all need to do is setup the frameworks main menu's and the LLM intagration using llamacpp and llama-cpp-python (the python packages are installed). the core c files are https://github.com/ggml-org/llama.cpp. The framework will be written in python and besides running the LLM and the agent its only other function is to load python modules that do the work. In other words, this application is just the front end. Lets start with the main menu. The main menu should have a ascii banner that says "AUTARCH" with a tagline that says "By darkHal and Setec Security Labs." On first launch the application auto runs the setup module (we need to create this as well). The setup module will setup the autarch_settings.conf. This module controls the llamacpp settings

---

### Work Completed

#### 1. Project Structure Created
```
dh_framework/
├── autarch.py          # Main entry point
├── autarch_settings.conf  # Configuration file (auto-generated)
├── core/
│   ├── __init__.py
│   ├── banner.py       # ASCII banner display
│   ├── config.py       # Configuration handler
│   └── menu.py         # Main menu system
└── modules/
    ├── __init__.py
    └── setup.py        # First-time setup wizard
```

#### 2. Components Implemented

**core/banner.py**
- ASCII art banner for "AUTARCH"
- Color support using ANSI codes
- Tagline: "By darkHal and Setec Security Labs."
- Helper functions for display and screen clearing

**core/config.py**
- Configuration handler for `autarch_settings.conf`
- Manages llama.cpp settings:
  - model_path
  - n_ctx (context size)
  - n_threads
  - n_gpu_layers
  - temperature
  - top_p
  - top_k
  - repeat_penalty
  - max_tokens
  - seed
- First-run detection
- Type-safe getters (get_int, get_float, get_bool)

**core/menu.py**
- Main menu with options:
  1. Load Module
  2. List Modules
  3. Settings
  4. Run Setup
  0. Exit
- Dynamic module loading from `modules/` directory
- Module info display (name, description, author, version)
- Status display showing current model

**modules/setup.py**
- Interactive first-time setup wizard
- Configures all llama.cpp parameters
- Model path validation
- Input validation with min/max bounds
- Saves configuration to `autarch_settings.conf`

**autarch.py**
- Main entry point
- Auto-runs setup on first launch
- Launches main menu

---

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| core/__init__.py | 2 | Package init |
| modules/__init__.py | 2 | Package init |
| core/banner.py | 42 | ASCII banner |
| core/config.py | 137 | Config management |
| core/menu.py | 232 | Menu system |
| modules/setup.py | 234 | Setup wizard |
| autarch.py | 47 | Entry point |

---

---

## Session 1 (Continued) - LLM Integration

### User Request
> yes lets do the llm integration

---

### Work Completed

#### 3. LLM Integration Added

**core/llm.py** - LLM Wrapper Class
- Wraps llama-cpp-python for model interaction
- Features:
  - `load_model()` - Load GGUF models with config settings
  - `unload_model()` - Free resources
  - `generate()` - Text completion with streaming support
  - `chat()` - Chat-style interaction with history
  - `_build_chat_prompt()` - ChatML-style prompt formatting
  - `clear_history()` / `get_history()` / `set_history()` - Conversation management
  - `get_model_info()` - Model metadata
- Global instance via `get_llm()`
- Custom `LLMError` exception class

**modules/chat.py** - Interactive Chat Module
- Full chat interface for the LLM
- Commands:
  - `/help` - Show available commands
  - `/clear` - Clear conversation history
  - `/history` - Show conversation history
  - `/info` - Show model information
  - `/system <prompt>` - Set system prompt
  - `/temp <value>` - Set temperature
  - `/tokens <value>` - Set max tokens
  - `/stream` - Toggle streaming mode
  - `/exit` - Exit chat
- Streaming output support
- Automatic model loading
- Default system prompt for AUTARCH persona

---

### Updated Project Structure
```
dh_framework/
├── autarch.py              # Main entry point
├── autarch_settings.conf   # Configuration file (auto-generated)
├── DEVLOG.md               # Development log
├── core/
│   ├── __init__.py
│   ├── banner.py           # ASCII banner display
│   ├── config.py           # Configuration handler
│   ├── llm.py              # LLM wrapper (NEW)
│   └── menu.py             # Main menu system
└── modules/
    ├── __init__.py
    ├── chat.py             # Chat interface (NEW)
    └── setup.py            # First-time setup wizard
```

---

### Files Added This Session

| File | Lines | Purpose |
|------|-------|---------|
| core/llm.py | ~280 | LLM wrapper for llama-cpp-python |
| modules/chat.py | ~250 | Interactive chat interface |

---

---

## Session 1 (Continued) - Agent System

### User Request
> yes lets do the agent system

---

### Work Completed

#### 4. Agent System Implemented

**core/tools.py** - Tool System
- `Tool` and `ToolParameter` dataclasses for tool definitions
- `ToolRegistry` class for managing available tools
- Built-in tools:
  - `shell` - Execute shell commands with timeout
  - `read_file` - Read file contents
  - `write_file` - Write content to files
  - `list_dir` - List directory contents
  - `search_files` - Glob pattern file search
  - `search_content` - Grep-style content search
  - `task_complete` - Signal task completion
  - `ask_user` - Request user input
- JSON schema generation for LLM tool descriptions
- Global registry via `get_tool_registry()`

**core/agent.py** - Autonomous Agent
- `Agent` class implementing the autonomous loop
- `AgentState` enum: IDLE, THINKING, EXECUTING, WAITING_USER, COMPLETE, ERROR
- `AgentStep` dataclass for recording step history
- `AgentResult` dataclass for task results
- Features:
  - Structured response parsing (THOUGHT/ACTION/PARAMS format)
  - Tool execution with error handling
  - User interaction via `ask_user` tool
  - Step limit (default 20) to prevent infinite loops
  - Callbacks for step completion and state changes
  - ChatML-style prompt building
- System prompt instructs LLM on tool usage format

**modules/agent.py** - Agent Interface Module
- Interactive task input loop
- Commands:
  - `tools` - Show available tools
  - `exit` - Return to main menu
  - `help` - Show help
- Task execution with progress display
- Result summary with success/failure status
- Step count reporting

---

### Updated Project Structure
```
dh_framework/
├── autarch.py              # Main entry point
├── autarch_settings.conf   # Configuration file (auto-generated)
├── DEVLOG.md               # Development log
├── core/
│   ├── __init__.py
│   ├── agent.py            # Autonomous agent (NEW)
│   ├── banner.py           # ASCII banner display
│   ├── config.py           # Configuration handler
│   ├── llm.py              # LLM wrapper
│   ├── menu.py             # Main menu system
│   └── tools.py            # Tool system (NEW)
└── modules/
    ├── __init__.py
    ├── agent.py            # Agent interface (NEW)
    ├── chat.py             # Chat interface
    └── setup.py            # First-time setup wizard
```

---

### Files Added This Session

| File | Lines | Purpose |
|------|-------|---------|
| core/tools.py | ~290 | Tool definitions and registry |
| core/agent.py | ~320 | Autonomous agent loop |
| modules/agent.py | ~175 | Agent user interface |

---

### Agent Response Format
The agent uses a structured format:
```
THOUGHT: [reasoning about what to do]
ACTION: [tool_name]
PARAMS: {"param1": "value1"}
```

Observations are fed back as:
```
OBSERVATION: [tool output]
```

---

---

## Session 1 (Continued) - Metasploit Integration & Menu Overhaul

### User Request
> lets first add a few other features. Lets add metasploit compatability so the framework can use metasploit modules, and then add the main menu: 1) Defense 2) Offense 3) Counter 4) Analyze 5) OSINT 6) Simulate 99) Settings 98) Exit

---

### Work Completed

#### 5. Metasploit Integration

**core/msf.py** - Metasploit RPC Client
- `MetasploitRPC` class for MSF RPC communication
- Uses msgpack for binary protocol
- Features:
  - `connect()` / `disconnect()` - Authentication
  - `list_modules()` / `search_modules()` - Module discovery
  - `get_module_info()` / `get_module_options()` - Module details
  - `execute_module()` - Run exploits/auxiliary modules
  - `list_jobs()` / `stop_job()` - Job management
  - `list_sessions()` - Active session listing
  - `session_shell_read()` / `session_shell_write()` - Session interaction
  - `run_console_command()` - Direct console access
- `MSFManager` class for settings management
- Configuration stored in `autarch_settings.conf` [msf] section

**Agent MSF Tools Added to core/tools.py:**
- `msf_connect` - Connect to MSF RPC
- `msf_search` - Search for modules
- `msf_module_info` - Get module details
- `msf_module_options` - Get module options
- `msf_execute` - Execute modules
- `msf_sessions` - List active sessions
- `msf_session_command` - Run commands in sessions
- `msf_console` - Direct console commands

#### 6. Main Menu Overhaul

**New Menu Structure:**
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

**Category System:**
- Modules now have `CATEGORY` attribute
- Categories: defense, offense, counter, analyze, osint, simulate, core
- Category submenus show only relevant modules
- Color-coded by category

**Settings Menu:**
- LLM Settings
- Metasploit Settings (with connection test)
- View All Settings
- Run Setup Wizard

**Status Line:**
- Shows current model name
- Shows MSF connection status

---

### Updated Project Structure
```
dh_framework/
├── autarch.py              # Main entry point
├── autarch_settings.conf   # Configuration file
├── DEVLOG.md               # Development log
├── core/
│   ├── __init__.py
│   ├── agent.py            # Autonomous agent
│   ├── banner.py           # ASCII banner display
│   ├── config.py           # Configuration handler
│   ├── llm.py              # LLM wrapper
│   ├── menu.py             # Main menu (UPDATED)
│   ├── msf.py              # Metasploit integration (NEW)
│   └── tools.py            # Tool system (UPDATED)
└── modules/
    ├── __init__.py
    ├── agent.py            # Agent interface (CATEGORY: core)
    ├── chat.py             # Chat interface (CATEGORY: core)
    └── setup.py            # First-time setup wizard
```

---

### Files Added/Modified This Session

| File | Lines | Purpose |
|------|-------|---------|
| core/msf.py | ~380 | Metasploit RPC integration |
| core/menu.py | ~480 | Updated with categories |
| core/tools.py | ~500 | Added MSF tools |

---

### Module Categories

| Category | Description | Color |
|----------|-------------|-------|
| defense | Defensive security tools | Blue |
| offense | Penetration testing | Red |
| counter | Counter-intelligence | Magenta |
| analyze | Analysis & forensics | Cyan |
| osint | Open source intelligence | Green |
| simulate | Attack simulation | Yellow |
| core | Core framework modules | White |

---

### MSF Configuration (autarch_settings.conf)
```ini
[msf]
host = 127.0.0.1
port = 55553
username = msf
password =
ssl = true
```

---

---

## Session 1 (Continued) - Simplified MSF Interface

### User Request
> lets simplify how metasploit modules can be used

---

### Work Completed

#### 7. Simplified Metasploit Module

**modules/msf.py** - User-Friendly MSF Interface (CATEGORY: offense)

Menu-driven interface:
```
  Metasploit Framework
  ──────────────────────────────────────────────────
  Status: Connected/Disconnected
  Module: current/module (if selected)

  [1] Search Modules
  [2] Use Module
  [3] Show Options
  [4] Set Option
  [5] Run Module

  [6] Sessions
  [7] Jobs

  [8] Console Command
  [9] Quick Scan (auxiliary/scanner)

  [0] Back to Main Menu
```

**Features:**
- **Search Modules** - Search by keyword, grouped results by type
- **Use Module** - Select by full path OR search and pick from list
- **Show Options** - Display required/optional with current values
- **Set Option** - Set individual options (RHOSTS, LHOST, etc.)
- **Run Module** - Execute with confirmation
- **Sessions** - List and interact with active sessions
- **Jobs** - View and kill running jobs
- **Console Command** - Direct MSF console access
- **Quick Scan** - Pre-configured scanners:
  - TCP Port Scanner
  - SMB Version Scanner
  - SSH Version Scanner
  - HTTP Version Scanner
  - FTP Version Scanner
  - MS17-010 (EternalBlue) Check

**Workflow Example:**
```
1. Select "Search Modules" → search "eternalblue"
2. Select "Use Module" → pick from results
3. Select "Set Option" → set RHOSTS=192.168.1.100
4. Select "Show Options" → verify configuration
5. Select "Run Module" → execute exploit
6. Select "Sessions" → interact with shell
```

---

### Updated Project Structure
```
dh_framework/
├── autarch.py
├── autarch_settings.conf
├── DEVLOG.md
├── core/
│   ├── agent.py
│   ├── banner.py
│   ├── config.py
│   ├── llm.py
│   ├── menu.py
│   ├── msf.py
│   └── tools.py
└── modules/
    ├── __init__.py
    ├── agent.py      # CATEGORY: core
    ├── chat.py       # CATEGORY: core
    ├── msf.py        # CATEGORY: offense (NEW)
    └── setup.py
```

---

### Files Added This Session

| File | Lines | Purpose |
|------|-------|---------|
| modules/msf.py | ~420 | Simplified MSF interface |

---

---

## Session 1 (Continued) - Category Modules

### User Request
> lets add modules for the other categories

---

### Work Completed

#### 8. Category Modules Added

**modules/defender.py** - Defense Module (CATEGORY: defense)
- Full Security Audit
- Firewall Check (iptables/ufw/firewalld)
- SSH Hardening Check
- Open Ports Scan
- User Security Check (UID 0, empty passwords)
- File Permissions Check
- Service Audit
- Fail2Ban/SELinux/AppArmor detection
- Security score calculation

**modules/counter.py** - Counter-Intelligence Module (CATEGORY: counter)
- Full Threat Scan
- Suspicious Process Detection (known malware, hidden processes)
- Network Analysis (suspicious ports, C2 connections)
- Login Anomalies (brute force detection, failed logins)
- File Integrity Monitoring (critical file changes, SUID binaries)
- Scheduled Task Audit (cron job analysis)
- Rootkit Detection (hidden files, kernel modules)

**modules/analyze.py** - Forensics Module (CATEGORY: analyze)
- File Analysis (metadata, hashes, type detection)
- String Extraction (URLs, IPs, emails, paths)
- Hash Lookup (VirusTotal/Hybrid Analysis links)
- Log Analysis (IP extraction, error patterns)
- Hex Dump viewer
- File Comparison

**modules/recon.py** - OSINT Module (CATEGORY: osint)
- Domain Reconnaissance (DNS, WHOIS, subdomains via crt.sh)
- IP Address Lookup (reverse DNS, geolocation, quick port scan)
- Email Harvester
- Subdomain Enumeration (certificate transparency + brute force)
- Technology Detection (server, CMS, frontend frameworks)

**modules/simulate.py** - Attack Simulation Module (CATEGORY: simulate)
- Password Audit (strength analysis, hash generation)
- Port Scanner (TCP scan with service detection)
- Banner Grabber
- Payload Generator (XSS, SQLi, Command Injection, Path Traversal, SSTI)
- Network Stress Test (controlled)

---

### Updated Project Structure
```
dh_framework/
├── autarch.py
├── autarch_settings.conf
├── DEVLOG.md
├── core/
│   ├── __init__.py
│   ├── agent.py
│   ├── banner.py
│   ├── config.py
│   ├── llm.py
│   ├── menu.py
│   ├── msf.py
│   └── tools.py
└── modules/
    ├── __init__.py
    ├── agent.py       # CATEGORY: core
    ├── analyze.py     # CATEGORY: analyze (NEW)
    ├── chat.py        # CATEGORY: core
    ├── counter.py     # CATEGORY: counter (NEW)
    ├── defender.py    # CATEGORY: defense (NEW)
    ├── msf.py         # CATEGORY: offense
    ├── recon.py       # CATEGORY: osint (NEW)
    ├── setup.py
    └── simulate.py    # CATEGORY: simulate (NEW)
```

---

### Files Added This Session

| File | Lines | Purpose |
|------|-------|---------|
| modules/defender.py | ~280 | System hardening checks |
| modules/counter.py | ~350 | Threat detection |
| modules/analyze.py | ~320 | Forensics tools |
| modules/recon.py | ~330 | OSINT reconnaissance |
| modules/simulate.py | ~310 | Attack simulation |

---

### Module Summary by Category

| Category | Module | Features |
|----------|--------|----------|
| Defense | defender | Security audit, firewall, SSH, permissions |
| Offense | msf | Metasploit interface, exploits, sessions |
| Counter | counter | Threat detection, rootkit checks, anomalies |
| Analyze | analyze | File forensics, strings, hashes, logs |
| OSINT | recon | Email/username/phone/domain/IP lookup |
| Simulate | simulate | Port scan, password audit, payloads |
| Core | agent | Autonomous AI agent |
| Core | chat | Interactive LLM chat |

---

## Session 1 (Continued) - Expanded OSINT

### User Request
> lets add modules for OSINT as well as add social-analyzer intagration. For OSINT lets add the sub catagories for email, username, phone number

---

### Work Completed

#### 9. Expanded OSINT Module

**modules/recon.py** - Enhanced to v2.0

New subcategorized menu:
```
  OSINT & Reconnaissance
  social-analyzer: Available/Not installed
  ──────────────────────────────────────────────────

  Email
    [1] Email Lookup
    [2] Email Permutator

  Username
    [3] Username Lookup
    [4] Social Analyzer

  Phone
    [5] Phone Number Lookup

  Domain/IP
    [6] Domain Recon
    [7] IP Address Lookup
    [8] Subdomain Enum
    [9] Tech Detection

  [0] Back
```

**Email OSINT Features:**
- Email format analysis
- MX record verification
- Breach check resources (HaveIBeenPwned, DeHashed, IntelX)
- Disposable email detection
- Gravatar lookup
- Email permutation generator (first.last, flast, etc.)

**Username OSINT Features:**
- Multi-platform check (17+ platforms)
- Twitter/X, Instagram, Facebook, GitHub, Reddit, LinkedIn
- TikTok, YouTube, Pinterest, Twitch, Steam, Spotify
- Medium, Dev.to, HackerNews, Keybase, Telegram
- HTTP status verification
- social-analyzer integration for deep scanning

**Phone OSINT Features:**
- Country code detection (12 countries)
- Carrier lookup resources (NumVerify, Twilio)
- Search resources (TrueCaller, Sync.me, SpyDialer, WhitePages)
- Messaging app check (WhatsApp, Telegram, Signal)
- Spam/scam database check

**social-analyzer Integration:**
- Auto-detection of installation
- Deep profile scanning across 300+ sites
- JSON output parsing
- Profile link extraction

---

### Updated recon.py Stats

| Feature | Lines | Description |
|---------|-------|-------------|
| Email OSINT | ~90 | Lookup, permutator |
| Username OSINT | ~100 | Platform check, social-analyzer |
| Phone OSINT | ~60 | Number analysis, resources |
| Domain/IP | ~200 | DNS, WHOIS, subdomains, tech |
| **Total** | ~590 | Expanded from ~330 |

---

### Notes
- Framework uses llama-cpp-python for LLM integration (package pre-installed)
- Modules can define DESCRIPTION, AUTHOR, VERSION, CATEGORY attributes
- All modules must have a `run()` function entry point
- Chat uses ChatML format (`<|im_start|>` / `<|im_end|>`) for compatibility
- Agent uses lower temperature (0.3) for more focused tool selection
- MSF RPC requires msfrpcd running: `msfrpcd -P password -S`
- social-analyzer: `pip install social-analyzer`

---

---

## Session 1 (Continued) - Adult Site Username Scanner

### User Request
> i am not doing the preditor tool anymore. Just a username OSINT tool like social-analyzer

---

### Work Completed

#### 10. Adult Site Username Scanner

**modules/adultscan.py** - Adult Site OSINT (CATEGORY: osint)

Username scanner for adult-oriented platforms with parallel scanning:

```
  Adult Site Scanner
  Username OSINT for adult platforms
  Sites in database: 50+
  ──────────────────────────────────────────────────

  [1] Full Scan (all categories)
  [2] Fanfiction & Story Sites
  [3] Art & Creative Sites
  [4] Video & Streaming Sites
  [5] Forums & Communities
  [6] Dating & Social Sites
  [7] Gaming Related Sites
  [8] Custom Category Selection

  [9] List All Sites

  [0] Back
```

**Site Categories:**

| Category | Sites | Examples |
|----------|-------|----------|
| fanfiction | 9 | Archive of Our Own, FanFiction.net, FimFiction, Wattpad, Literotica, Hentai Foundry |
| art | 10 | DeviantArt, Fur Affinity, Newgrounds, Pixiv, Rule34, e621, Tumblr |
| video | 8 | Pornhub, XVideos, xHamster, Chaturbate, OnlyFans, Fansly, ManyVids |
| forums | 6 | Reddit, F-List, FetLife, Kink.com, BDSMLR, CollarSpace |
| dating | 5 | AdultFriendFinder, Ashley Madison, Grindr, Scruff, Recon |
| gaming | 4 | F95zone, LoversLab, ULMF, Nutaku |

**Features:**
- Parallel scanning with ThreadPoolExecutor (10 workers)
- Two detection methods:
  - `status` - HTTP status code check (200/301/302 = found, 404 = not found)
  - `content` - Page content analysis for sites with custom error pages
- Progress indicator during scan
- Category selection (single, multiple, or all)
- Results export to file
- Color-coded output (green = found, yellow = possible/redirect)

**Detection Flow:**
```python
def check_site(self, site_info, username):
    # 1. Format URL with username
    url = url_template.format(username)

    # 2. Use curl to get HTTP status
    cmd = f"curl -sI -o /dev/null -w '%{{http_code}}' -L --max-time {timeout} '{url}'"

    # 3. Interpret based on method
    if method == 'status':
        # 200 = found, 404 = not found
    else:
        # Content-based: 200 = possible match
```

---

### Updated Project Structure
```
dh_framework/
├── autarch.py
├── autarch_settings.conf
├── DEVLOG.md
├── core/
│   ├── __init__.py
│   ├── agent.py
│   ├── banner.py
│   ├── config.py
│   ├── llm.py
│   ├── menu.py
│   ├── msf.py
│   └── tools.py
└── modules/
    ├── __init__.py
    ├── adultscan.py    # CATEGORY: osint (NEW)
    ├── agent.py        # CATEGORY: core
    ├── analyze.py      # CATEGORY: analyze
    ├── chat.py         # CATEGORY: core
    ├── counter.py      # CATEGORY: counter
    ├── defender.py     # CATEGORY: defense
    ├── msf.py          # CATEGORY: offense
    ├── recon.py        # CATEGORY: osint
    ├── setup.py
    └── simulate.py     # CATEGORY: simulate
```

---

### Files Added This Session

| File | Lines | Purpose |
|------|-------|---------|
| modules/adultscan.py | ~365 | Adult site username scanner |

---

### OSINT Module Summary

| Module | Purpose | Features |
|--------|---------|----------|
| recon.py | General OSINT | Email, username (mainstream), phone, domain, IP |
| adultscan.py | Adult sites | 50+ adult/fanfiction/art platforms |

---

### Notes
- Scanner respects site rate limits via 10-second timeout per request
- Uses curl for HTTP requests (more reliable than Python requests for some sites)
- Some sites use content-based detection due to custom 404 pages
- Export format: plain text with site names and URLs

---

---

## Session 1 (Continued) - Custom Site Management

### User Request
> for the Adult Site Scanner Module, lets add two options, Manually add website to the list with the default username pattern such as if i wanted to add fakeadult.com to the list i would add fakeadult.com/user/* where the star gets replaces by the username

---

### Work Completed

#### 11. Custom Site Management for Adult Scanner

**modules/adultscan.py** - Updated to v1.1

Added custom site management features:

**New Menu Structure:**
```
  Adult Site Scanner
  Sites in database: 50+ (X custom)
  ──────────────────────────────────────────────────

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
  [A] Add Custom Site
  [M] Manage Custom Sites
  [L] List All Sites

  [0] Back
```

**Add Custom Site (`[A]`):**
- Prompts for site name
- URL pattern using `*` as username placeholder
  - Example: `https://example.com/user/*`
  - Example: `example.com/profile?name=*`
- Auto-adds `https://` if no protocol specified
- Detection method selection:
  - Status code (default) - checks HTTP response
  - Content - for sites with custom 404 pages
- Saves to `custom_adultsites.json`

**Manage Custom Sites (`[M]`):**
- Lists all custom sites with URL patterns and methods
- Add new sites
- Remove existing sites by number

**Custom Sites Only (`[8]`):**
- Scan only user-added custom sites

**Storage:**
- Custom sites stored in `custom_adultsites.json` in framework root
- JSON format: `{"sites": [["name", "url_template", "method"], ...]}`
- Persists between sessions

**Example Usage:**
```
Site name: FakeAdult
URL pattern (use * for username): fakeadult.com/user/*
Detection Method: [1] Status code

[+] Added 'FakeAdult' to custom sites
    URL: https://fakeadult.com/user/<username>
```

---

### Files Modified

| File | Changes |
|------|---------|
| modules/adultscan.py | Added custom site management (~150 new lines) |

---

### New Methods Added

| Method | Purpose |
|--------|---------|
| `load_custom_sites()` | Load from JSON file |
| `save_custom_sites()` | Save to JSON file |
| `add_custom_site()` | Interactive add wizard |
| `manage_custom_sites()` | View/manage menu |
| `remove_custom_site()` | Remove by index |

---

### Storage Format (custom_adultsites.json)
```json
{
  "sites": [
    ["Site Name", "https://example.com/user/{}", "status"],
    ["Another Site", "https://other.com/profile/{}", "content"]
  ]
}
```

Note: `*` in user input is converted to `{}` for internal template formatting.

---

---

## Session 1 (Continued) - Auto-Detect Site Patterns

### User Request
> lets add auto detection add, all the user has to is add fakeadult.com and the application just searches for a username using the most common patterns like fakeadult.com/u/* fakeadult.com/user/* etc

---

### Work Completed

#### 12. Auto-Detect Site Pattern Feature

**modules/adultscan.py** - Updated to v1.2

Added auto-detection that probes common URL patterns:

**New Menu Option:**
```
  Site Management:
  [A] Add Custom Site (manual)
  [D] Auto-Detect Site Pattern    <- NEW
  [M] Manage Custom Sites
  [L] List All Sites
```

**Common Patterns Tested:**
```python
COMMON_PATTERNS = [
    '/user/{}',
    '/users/{}',
    '/u/{}',
    '/profile/{}',
    '/profiles/{}',
    '/member/{}',
    '/members/{}',
    '/@{}',
    '/{}',
    '/people/{}',
    '/account/{}',
    '/id/{}',
    '/{}/profile',
    '/user/{}/profile',
    '/channel/{}',
    '/c/{}',
    '/p/{}',
]
```

**Workflow:**
1. User enters just the domain (e.g., `example.com`)
2. User provides a known-existing username for testing
3. System probes all 17 common patterns
4. Shows which patterns return 200/301/302 responses
5. User selects the working pattern to add
6. Site is saved to custom sites

**Example Usage:**
```
Domain: fakeadult.com
Test username: knownuser

Testing 17 common URL patterns...

Found 2 working pattern(s):

  [1] /user/{}            (OK)
      https://fakeadult.com/user/knownuser
  [2] /u/{}               (redirect 302)
      https://fakeadult.com/u/knownuser

  [0] Cancel

Select pattern to add: 1
Site name [Fakeadult]: FakeAdult
[+] Added 'FakeAdult' to custom sites
    Pattern: https://fakeadult.com/user/*
```

**Detection Logic:**
- Uses 5-second timeout per pattern
- HTTP 200 = confirmed working
- HTTP 301/302 = working (redirect)
- HTTP 404/other = not working
- Auto-selects detection method based on response

---

### Files Modified

| File | Changes |
|------|---------|
| modules/adultscan.py | Added auto-detect (~90 new lines) |

---

### New Components

| Component | Purpose |
|-----------|---------|
| `COMMON_PATTERNS` | List of 17 common URL patterns |
| `auto_detect_site()` | Interactive auto-detection wizard |

---

### Notes
- Auto-detect requires a known valid username to test against
- Some sites may have rate limiting that affects detection
- Falls back to manual add if no patterns work

---

---

## Session 1 (Continued) - Bulk Import Feature

### User Request
> lets also add a bulk list function where the user can add sites to custom.inf and then it scans for new sites using autodetect

---

### Work Completed

#### 13. Bulk Import from File

**modules/adultscan.py** - Updated to v1.3

Added bulk import that reads domains from a file and auto-detects patterns:

**New Menu Option:**
```
  Site Management:
  [A] Add Custom Site (manual)
  [D] Auto-Detect Site Pattern
  [B] Bulk Import from File        <- NEW
  [M] Manage Custom Sites
  [L] List All Sites
```

**Bulk Import File:** `custom_sites.inf`

**File Format:**
```
# AUTARCH Adult Site Scanner - Bulk Import File
# Add one domain per line (without http:// or https://)
# Lines starting with # are comments

example.com
another-site.net
subdomain.site.org
```

**Workflow:**
1. User adds domains to `custom_sites.inf` (one per line)
2. Run Bulk Import `[B]`
3. System reads domains from file
4. Skips already-added domains
5. Prompts for test username (e.g., "admin", "test")
6. Auto-detects URL pattern for each domain
7. Adds working sites to custom sites
8. Reports failed domains
9. Option to clear import file when done

**Example Session:**
```
Found 5 domain(s) in custom_sites.inf:
  - site1.com
  - site2.net
  - site3.org
  ...

Will scan 5 new domain(s)

Test username: admin

Scanning 5 domains...

[1/5] Scanning site1.com...
  [+] Added Site1: /user/{}
[2/5] Scanning site2.net...
  [+] Added Site2: /profile/{}
[3/5] Scanning site3.org...
  [X] No pattern found
...

Successfully added 4 site(s)

Failed to detect patterns for 1 domain(s):
  - site3.org
Try adding these manually with [A] or [D]

Clear import file? (y/n): y
[+] Import file cleared
```

**Features:**
- Creates template file if not exists
- Skips domains already in custom sites
- Uses first working pattern found (efficient)
- Reports failures for manual follow-up
- Option to clear file after import

---

### Files Modified

| File | Changes |
|------|---------|
| modules/adultscan.py | Added bulk import (~120 new lines) |

---

### New Components

| Component | Purpose |
|-----------|---------|
| `BULK_IMPORT_FILE` | Path to `custom_sites.inf` |
| `probe_domain()` | Reusable pattern detection helper |
| `bulk_import()` | Bulk import wizard |

---

### File Locations

| File | Purpose |
|------|---------|
| `custom_sites.inf` | Domains to import (user editable) |
| `custom_adultsites.json` | Saved custom sites (auto-managed) |

---

---

## Session 1 (Continued) - CLI System & Documentation

### User Request
> give me an overview of what we have done so far and create in depth technical user guide with all the cli commands and arguments and add a detailed --help argument

---

### Work Completed

#### 14. Comprehensive CLI System

**autarch.py** - Complete rewrite with argparse CLI

**New CLI Options:**
```
Usage: python autarch.py [OPTIONS] [COMMAND]

Options:
  -h, --help              Show detailed help message
  -v, --version           Show version information
  -c, --config FILE       Use alternate config file
  -m, --module NAME       Run a specific module directly
  -l, --list              List all available modules
  --list-category CAT     List modules in specific category
  --show-config           Display current configuration
  --setup                 Force run setup wizard
  --no-banner             Suppress ASCII banner
  -q, --quiet             Minimal output mode
  --verbose               Enable verbose output

Commands:
  chat                    Start interactive LLM chat
  agent                   Start autonomous agent
  osint <username>        Quick OSINT username scan
  scan <target>           Quick port scan
  analyze                 Run analyze module
```

**Examples:**
```bash
# Show help
python autarch.py --help

# Run specific module
python autarch.py -m adultscan
python autarch.py -m recon

# List modules
python autarch.py --list
python autarch.py --list-category osint

# Quick OSINT
python autarch.py osint targetuser

# Show config
python autarch.py --show-config

# Re-run setup
python autarch.py --setup
```

**Help Output Features:**
- Detailed epilog with categories, modules, examples
- Configuration reference
- File locations
- Color-coded output

---

#### 15. Technical User Guide

**GUIDE.md** - Comprehensive documentation created

Contents:
1. Project Overview
2. Project Structure
3. Installation & Setup
4. Command Line Interface (all options)
5. Main Menu Navigation
6. Module Reference (all modules)
7. Configuration Reference
8. Creating Custom Modules
9. Agent Tools Reference
10. Troubleshooting
11. Security Notice

---

### Files Created/Modified

| File | Changes |
|------|---------|
| autarch.py | Complete CLI rewrite (~480 lines) |
| GUIDE.md | New comprehensive guide (~600 lines) |

---

### New CLI Functions

| Function | Purpose |
|----------|---------|
| `create_parser()` | Build argparse parser with all options |
| `get_epilog()` | Generate detailed help epilog |
| `show_version()` | Display version info |
| `show_config()` | Display current config |
| `list_modules()` | List available modules |
| `run_module()` | Run module directly |
| `quick_osint()` | Quick OSINT scan |
| `quick_scan()` | Quick port scan |

---

### Project Summary

**Total Files Created:** 19 Python files + 3 documentation files

**Core Framework (core/):**
| File | Lines | Purpose |
|------|-------|---------|
| banner.py | ~42 | ASCII banner, colors |
| config.py | ~143 | Configuration handler |
| llm.py | ~280 | LLM wrapper |
| agent.py | ~320 | Autonomous agent |
| tools.py | ~500 | Tool registry |
| menu.py | ~480 | Main menu system |
| msf.py | ~380 | Metasploit RPC |

**Modules (modules/):**
| File | Lines | Category | Purpose |
|------|-------|----------|---------|
| setup.py | ~234 | - | Setup wizard |
| chat.py | ~250 | core | LLM chat |
| agent.py | ~175 | core | Agent interface |
| msf.py | ~420 | offense | MSF interface |
| defender.py | ~280 | defense | System hardening |
| counter.py | ~350 | counter | Threat detection |
| analyze.py | ~320 | analyze | Forensics |
| recon.py | ~590 | osint | OSINT recon |
| adultscan.py | ~650 | osint | Adult site scanner |
| simulate.py | ~310 | simulate | Attack simulation |

**Documentation:**
| File | Purpose |
|------|---------|
| DEVLOG.md | Development history |
| GUIDE.md | User guide |
| README.md | (not created, can add) |

**Configuration Files:**
| File | Purpose |
|------|---------|
| autarch_settings.conf | Main config |
| custom_adultsites.json | Custom sites storage |
| custom_sites.inf | Bulk import file |

---

### Feature Summary

**LLM Integration:**
- llama-cpp-python wrapper
- ChatML format prompts
- Streaming support
- Configurable parameters

**Agent System:**
- Autonomous task execution
- Tool registry (12+ tools)
- THOUGHT/ACTION/PARAMS format
- User interaction support

**Metasploit Integration:**
- RPC client
- Module search/execution
- Session management
- Console commands

**OSINT Capabilities:**
- Email lookup/permutation
- Username search (17+ platforms)
- Phone number analysis
- Domain/IP reconnaissance
- Adult site scanner (50+ sites)
- Custom site management
- Auto-pattern detection
- Bulk import

**Security Tools:**
- System hardening audit
- Threat detection
- File forensics
- Attack simulation
- Payload generation

**CLI Features:**
- Full argparse integration
- Module direct execution
- Quick commands
- Configuration display
- Verbose/quiet modes

---

---

## Session 2 - 2026-01-15

### User Request
> lets add a new option to defensive 'My System'. When user selects this option it prompts the user to run the full system audit, save the info to system.inf, and scores your security. Then it shows the results as options. when the selects one, it offers to use the llm to auto fix the issue or shows you the options on how to do it manually. Lets also add a CVE database, not just for the system audit, but for other modules as well. For my system menu, have the application detect the system the application is running on and download the database. have the app use https://nvd.nist.gov/developers/vulnerabilities to get the info.

---

### Work Completed

#### 1. CVE Database System (core/cve.py)

**CVEDatabase Class** - Full NVD API Integration:
- Uses NIST NVD REST API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
- Automatic OS detection with CPE mapping
- Supports 15+ operating systems:
  - Ubuntu, Debian, Fedora, CentOS, RHEL
  - Rocky Linux, Alma Linux, Arch, openSUSE, SUSE
  - Kali, Linux Mint, Windows, macOS

**Key Methods:**
| Method | Purpose |
|--------|---------|
| `_detect_system()` | Auto-detect OS type, version, kernel |
| `search_cves()` | Search NVD by keyword, CPE, severity |
| `get_cve_details()` | Get detailed CVE information |
| `get_system_cves()` | Get CVEs for detected system |
| `get_software_cves()` | Search CVEs for specific software |
| `get_installed_packages()` | List system packages (dpkg/rpm/pacman) |

**Features:**
- Local JSON cache (24-hour expiry)
- API key support for higher rate limits
- CVSS v2/v3 score parsing
- CPE-based vulnerability matching
- Severity filtering (LOW/MEDIUM/HIGH/CRITICAL)
- Progress callbacks for UI integration

**OS to CPE Mapping:**
```python
OS_CPE_MAP = {
    'ubuntu': 'cpe:2.3:o:canonical:ubuntu_linux',
    'debian': 'cpe:2.3:o:debian:debian_linux',
    'fedora': 'cpe:2.3:o:fedoraproject:fedora',
    'rhel': 'cpe:2.3:o:redhat:enterprise_linux',
    'windows': 'cpe:2.3:o:microsoft:windows',
    'macos': 'cpe:2.3:o:apple:macos',
    # ... and more
}
```

---

#### 2. My System Module (modules/mysystem.py)

**Comprehensive System Audit with CVE Detection & Auto-Fix**

**Menu Structure:**
```
  My System - Security Audit
  ──────────────────────────────────────────────────
  Detected: ubuntu 22.04
  Kernel: 5.10.0-1012-rockchip
  Last Score: 75/100
  Open Issues: 5

  [1] Run Full System Audit
  [2] Run Audit (Skip CVE Check)

  [3] View Issues (X found)
  [4] View CVE Report

  [5] Search CVE Database
  [6] Check Software for CVEs

  [0] Back to Main Menu
```

**Security Checks Performed:**
| Check | Description | Severity Impact |
|-------|-------------|-----------------|
| Firewall | iptables/ufw/firewalld status | HIGH if missing |
| SSH Config | Root login, password auth, protocol | HIGH-CRITICAL |
| Open Ports | 15 high-risk ports detection | MEDIUM-CRITICAL |
| Users | UID 0 accounts, empty passwords | CRITICAL |
| Permissions | Critical file modes (/etc/shadow, etc.) | MEDIUM |
| Services | Dangerous services (telnet, rsh, etc.) | HIGH |
| Updates | Pending package updates | MEDIUM |
| Fail2Ban | Brute-force protection status | LOW-MEDIUM |
| Antivirus | ClamAV or other AV detection | LOW |
| CVEs | System-specific vulnerabilities | HIGH-CRITICAL |

**Issue Tracking:**
- `SecurityIssue` class with severity levels
- Automatic security score calculation (0-100)
- Score penalties: CRITICAL=-20, HIGH=-15, MEDIUM=-10, LOW=-5
- Persists to `system.inf` JSON file

**Issue Remediation Options:**
```
  Issue Details
  ──────────────────────────────────────────────────
  Name: SSH Root Login Enabled
  Severity: HIGH
  Category: ssh

  Description:
    Root login via SSH is not disabled

  Manual Fix Instructions:
    Edit /etc/ssh/sshd_config:
      PermitRootLogin no
    Then restart: sudo systemctl restart sshd

  Auto-Fix Command:
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd

  [1] Auto-Fix with LLM
  [2] Apply Manual Fix
  [3] Mark as Ignored
  [0] Back
```

**LLM Auto-Fix Feature:**
- Consults LLM for fix recommendations
- Provides risk explanation
- Generates context-aware fix commands
- User confirmation before execution
- Streaming response display

**CVE Features:**
- CVE report with severity breakdown
- Interactive CVE search
- Software-specific CVE lookup
- Detailed CVE view with CVSS scores

---

#### 3. Defender Module Update

**modules/defender.py** - Added "My System" option:
```
  System Defender
  ──────────────────────────────────────────────────

  [M] My System - Full audit with CVE detection & auto-fix

  [1] Quick Security Audit
  [2] Firewall Check
  ...
```

---

### Updated Project Structure
```
dh_framework/
├── autarch.py
├── autarch_settings.conf
├── system.inf                 # Audit results (NEW)
├── DEVLOG.md
├── GUIDE.md
├── data/
│   └── cve/
│       └── cve_cache.json     # CVE cache (NEW)
├── core/
│   ├── __init__.py
│   ├── agent.py
│   ├── banner.py
│   ├── config.py
│   ├── cve.py                 # CVE database (NEW)
│   ├── llm.py
│   ├── menu.py
│   ├── msf.py
│   └── tools.py
└── modules/
    ├── __init__.py
    ├── adultscan.py
    ├── agent.py
    ├── analyze.py
    ├── chat.py
    ├── counter.py
    ├── defender.py            # Updated with My System
    ├── msf.py
    ├── mysystem.py            # My System module (NEW)
    ├── recon.py
    ├── setup.py
    └── simulate.py
```

---

### Files Added/Modified

| File | Lines | Purpose |
|------|-------|---------|
| core/cve.py | ~500 | CVE database with NVD API |
| modules/mysystem.py | ~680 | My System audit module |
| modules/defender.py | +10 | Added My System menu option |

---

### Configuration (autarch_settings.conf)

New optional section for NVD API:
```ini
[nvd]
api_key =   ; Optional - for higher rate limits
```

---

### Storage Files

| File | Format | Purpose |
|------|--------|---------|
| system.inf | JSON | Audit results, issues, scores |
| data/cve/cve.db | SQLite | CVE database |
| custom_apis.json | JSON | Custom API configurations |

---

### Notes

- NVD API has rate limits: 5 requests/30s without key, 50 requests/30s with key
- Request API key at: https://nvd.nist.gov/developers/request-an-api-key
- SQLite database enables fast offline CVE queries
- LLM auto-fix requires loaded model
- Security score is cumulative based on issue severity

---

---

## Session 2 (Continued) - SQLite CVE Database & Settings Menus

### User Request
> what database format did you use for the database... yes lets use sqlite
> in the settings menu, lets add a CVE menu. Lets also add a menu for users to add custom api's and a menu for this applications api (not implemented yet)

---

### Work Completed

#### 1. SQLite CVE Database (core/cve.py rewrite)

Replaced JSON caching with full SQLite database:

**Database Schema:**
```sql
-- Main CVE table
CREATE TABLE cves (
    id INTEGER PRIMARY KEY,
    cve_id TEXT UNIQUE NOT NULL,
    description TEXT,
    published TEXT,
    modified TEXT,
    cvss_v3_score REAL,
    cvss_v3_severity TEXT,
    cvss_v3_vector TEXT,
    cvss_v2_score REAL,
    cvss_v2_severity TEXT,
    cvss_v2_vector TEXT
);

-- Affected products (CPE)
CREATE TABLE cve_cpes (
    cve_id TEXT,
    cpe_criteria TEXT,
    vulnerable INTEGER,
    version_start TEXT,
    version_end TEXT
);

-- References
CREATE TABLE cve_references (
    cve_id TEXT,
    url TEXT,
    source TEXT
);

-- Weaknesses (CWE)
CREATE TABLE cve_weaknesses (
    cve_id TEXT,
    cwe_id TEXT
);

-- Metadata
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

**Key Methods:**
| Method | Purpose |
|--------|---------|
| `sync_database()` | Download CVEs from NVD API |
| `sync_recent()` | Quick sync (last 7 days) |
| `search_cves()` | Local database search |
| `get_cve()` | Get detailed CVE info |
| `get_system_cves()` | CVEs for detected OS |
| `get_software_cves()` | CVEs for specific software |
| `fetch_cve_online()` | Online fallback for single CVE |
| `search_online()` | Online search fallback |

**Features:**
- Thread-safe SQLite connections
- Indexed columns for fast queries
- Batch processing with progress display
- Rate limiting (respects NVD limits)
- Online fallback when database empty

---

#### 2. Settings Menu Updates (core/menu.py)

**New Settings Menu Structure:**
```
  Settings
  ──────────────────────────────────────────────────

  [1] LLM Settings
  [2] Metasploit Settings
  [3] CVE Database Settings       <- NEW
  [4] Custom APIs                 <- NEW
  [5] AUTARCH API                 <- NEW

  [6] View All Settings
  [7] Run Setup Wizard

  [0] Back
```

---

#### 3. CVE Database Settings Menu

```
  CVE Database Settings
  ──────────────────────────────────────────────────

  Database Path: /home/.../data/cve/cve.db
  Database Size: 150.5 MB
  Total CVEs: 245,000
  Last Sync: 2026-01-15

  Detected OS: Ubuntu 22.04.5 LTS
  CPE Prefix: cpe:2.3:o:canonical:ubuntu_linux

  NVD API Key: Configured

  [1] Sync Database (Recent - 120 days)
  [2] Sync Database (Full - all CVEs)
  [3] Set NVD API Key
  [4] Clear Database

  [0] Back
```

---

#### 4. Custom APIs Menu

Allows users to add and manage external API integrations:

```
  Custom APIs
  ──────────────────────────────────────────────────

  Configured APIs:
    [1] VirusTotal - Active
        https://www.virustotal.com/api/v3/...
    [2] Shodan - Active
        https://api.shodan.io/...

  [A] Add API
  [E] Edit API
  [D] Delete API
  [T] Toggle API

  [0] Back
```

**API Configuration Fields:**
- Name
- Base URL
- API Key
- Description
- Type (REST, GraphQL, SOAP, Other)
- Enabled/Disabled status

**Storage:** `custom_apis.json`

---

#### 5. AUTARCH API Menu (Placeholder)

Placeholder for future REST API implementation:

```
  AUTARCH API
  ──────────────────────────────────────────────────

  Status: Disabled
  Port: 8080
  API Key: Not set

  [!] API functionality coming in future version

  [1] Configure API Settings
  [2] Generate API Key
  [3] View API Documentation

  [0] Back
```

**Planned Endpoints:**
- `GET /api/v1/status` - Framework status
- `GET /api/v1/modules` - List modules
- `POST /api/v1/scan` - Run security scan
- `GET /api/v1/cve/search` - Search CVE database
- `POST /api/v1/agent/task` - Submit agent task

---

### Updated My System Module

Added CVE database sync options:

```
  My System - Security Audit
  ──────────────────────────────────────────────────
  Detected: ubuntu 22.04
  CVE Database: 245,000 CVEs (150.5 MB)
  Last Sync: 2026-01-15

  [1] Run Full System Audit
  [2] Run Audit (Skip CVE Check)

  [7] Sync CVE Database (Recent)   <- NEW
  [8] Sync CVE Database (Full)     <- NEW
  [9] CVE Database Info            <- NEW

  [0] Back
```

---

### Files Modified

| File | Changes |
|------|---------|
| core/cve.py | Complete rewrite - SQLite database (~870 lines) |
| core/menu.py | Added CVE, Custom APIs, AUTARCH API menus (~300 new lines) |
| modules/mysystem.py | Updated for SQLite, added sync options (~100 lines changed) |

---

### New Files

| File | Purpose |
|------|---------|
| data/cve/cve.db | SQLite CVE database |
| custom_apis.json | Custom API configurations |

---

### Database Sync Estimates

| Sync Type | CVEs | Time (no key) | Time (with key) | Size |
|-----------|------|---------------|-----------------|------|
| Recent (120 days) | ~5,000 | 10-15 min | 2-3 min | ~5 MB |
| Full (since 1999) | ~245,000 | 4-6 hours | 30-60 min | ~150-300 MB |

---

### Notes

- SQLite file located at `data/cve/cve.db`
- Get NVD API key for faster syncs: https://nvd.nist.gov/developers/request-an-api-key
- Database supports offline CVE lookups after initial sync
- Custom APIs stored in `custom_apis.json` in framework root
- AUTARCH API is placeholder - implementation in future version

---

---

## Session 2 (Continued) - Sites Database Expansion

### User Request
> now lets add more sites. Start crawling and scraping, do not exclude any kind of site. If you can create an account and post things add it. both nsfw and sfw

---

### Work Completed

#### 1. New Source Added: reveal-my-name

Added osint-liar/reveal-my-name as a new source (extended WhatsMyName fork with 2,140+ sites):
- URL: `https://raw.githubusercontent.com/osint-liar/reveal-my-name/main/wmn-data.json`
- Contains 628 parseable sites with improved detection patterns
- Handles XXXPORNXXX category for NSFW detection

**Parser Added:** `_parse_reveal_my_name()` in core/sites_db.py

---

#### 2. XenForo/vBulletin Forums Added

Added 43 major forums from XenForo's large forums list with multiple URL patterns:

| Posts | Forums Added |
|-------|--------------|
| 100M+ | IGN Boards |
| 50-99M | Disboards, Christian Forums, BigFooty |
| 20-49M | Sherdog, HFBoards, PurseForum, SpaceBattles, ADV Rider, Grasscity, etc. |
| 10-19M | Paradox, BladeForums, Smashboards, RedCafe, TalkBass, TheColi, Se7enSins, etc. |

Each forum added with both XenForo (`/members/{}.html`) and vBulletin (`/member.php?username={}`) patterns.

---

#### 3. Adult/NSFW Sites Added

**Cam Sites:**
- Chaturbate, StripChat, CamSoda, BongaCams, LiveJasmin, Cam4, MyFreeCams
- JerkMate, LivePrivates, Flirt4Free, Streamate

**Fan/Creator Platforms:**
- OnlyFans, Fansly, JustForFans, Fanvue, ManyVids
- LoyalFans, FanCentro, PocketStars, Unlockd, Alua, AdmireMe VIP

**Tube Sites:**
- Pornhub Models, xHamster Models, XVideos Models, ModelHub

**Adult Social/Dating:**
- FetLife, CollarSpace, SwingLifeStyle, Adult Friend Finder, Ashley Madison

**Gaming Adult:**
- F95zone, LoversLab, ULMF

**Hentai/Anime:**
- Hentai Foundry, Fakku, Gelbooru, Danbooru, Sankaku Complex

**Furry:**
- Fur Affinity, e621, SoFurry, Inkbunny

---

#### 4. Mainstream Sites Added

**Social/Messaging:**
- Discord, Telegram, Mastodon, Threads, Bluesky, Cohost, Nostr, Matrix

**Dating:**
- Tinder, Bumble, Hinge, OkCupid, Badoo, Grindr, Scruff, HER

**Crypto/Finance:**
- CoinMarketCap, CoinGecko, OpenSea, Rarible, Foundation, Mirror, Farcaster

**Streaming:**
- Twitch, Kick, TikTok, Trovo, DLive, Rumble, Odysee

**Creative:**
- ArtStation, Dribbble, Behance, DeviantArt, SoundCloud, Bandcamp

**Shopping:**
- Etsy, eBay, Depop, Poshmark, Grailed, Fiverr, Upwork

**Blogging:**
- Medium, Substack, Dev.to, Hashnode, Ghost

---

### Database Statistics

| Metric | Before | After |
|--------|--------|-------|
| Total Sites | 3,481 | 3,751 |
| NSFW Sites | 618 | 661 |
| Custom Sites | 400 | 672 |
| Sources | 7 | 8 |

**Sites by Source:**
| Source | Count |
|--------|-------|
| maigret | 1,682 |
| custom | 672 |
| social_analyzer | 469 |
| reveal_my_name | 312 |
| sherlock | 177 |
| cupidcr4wl | 142 |
| whatsmyname | 137 |
| detectdee | 126 |
| nexfil | 34 |

**Sites by Category:**
| Category | Count |
|----------|-------|
| other | 1,922 |
| adult | 647 |
| social | 258 |
| forum | 245 |
| gaming | 166 |
| tech | 152 |
| news | 69 |
| finance | 68 |
| dating | 38 |
| art | 37 |

---

### Files Modified

| File | Changes |
|------|---------|
| core/sites_db.py | Added reveal_my_name source URL, parser, and import support |
| data/sites/reveal_my_name.json | Downloaded 7,076 lines (628 parseable sites) |
| data/sites/sites.db | Updated with 270+ new sites |

---

### Notes

- reveal_my_name prioritized below maigret/sherlock but above whatsmyname
- XXXPORNXXX category auto-mapped to 'adult' with nsfw=1
- XenForo forums added with both XenForo and vBulletin URL patterns
- Many adult sites use simple status code detection (200 = exists)

---

---

## Session 2 (Continued) - Snoop Project Integration

### User Request
> i have it installed here... and the full database is BDfull

---

### Work Completed

#### 1. Snoop Database Decoding

The Snoop Project stores its database in a base32-encoded, reversed format. Decoded the full database:

**Decoding Process:**
```python
# 1. Read base32 encoded file
db = file.read()
# 2. Decode base32
db_bytes = base64.b32decode(db)
# 3. Reverse bytes
db_bytes = db_bytes[::-1]
# 4. Decode UTF-8
content = db_bytes.decode('utf-8', errors='replace')
# 5. Reverse string
content = content[::-1]
# 6. Parse JSON
data = json.loads(content)
```

**Results:**
- BDfull: 5,366 sites decoded
- Saved to: `/home/snake/dh_framework/data/sites/snoop_full.json` (1.95 MB)

---

#### 2. Snoop Parser Added

Added `_parse_snoop()` method to `core/sites_db.py`:

**Snoop Data Structure:**
```python
{
  "SiteName": {
    "country": "🇺🇸",           # Emoji flag
    "country_klas": "US",      # Country code
    "errorType": "status_code", # Detection method
    "url": "https://site.com/user/{}", # URL template
    "urlMain": "https://site.com/",    # Main URL
    "usernameON": "adam",      # Test username
    "errorMsg": "Not found",   # Error message
    "bad_site": ""             # Problem indicator
  }
}
```

**Parser Features:**
- Maps errorType to detection method (status_code → status, message → content)
- Extracts error patterns from errorMsg/errorMsg2
- Handles encoding issues in key names

---

### Updated Database Statistics

| Metric | Before | After |
|--------|--------|-------|
| Total Sites | 3,751 | 8,315 |
| NSFW Sites | 661 | 654 |
| Sources | 8 | 9 |

**Sites by Source:**
| Source | Count |
|--------|-------|
| snoop | 4,641 |
| maigret | 1,727 |
| custom | 604 |
| social_analyzer | 440 |
| reveal_my_name | 308 |
| sherlock | 169 |
| cupidcr4wl | 145 |
| whatsmyname | 134 |
| detectdee | 122 |
| nexfil | 25 |

---

### Files Modified/Added

| File | Changes |
|------|---------|
| core/sites_db.py | Added snoop source, `_parse_snoop()` method, updated priorities |
| data/sites/snoop_full.json | 5,366 sites (1.95 MB) |
| data/sites/sites.db | Updated with 8,315 total sites |

---

### Backup Created

- Path: `/home/snake/backups/dh_framework_backup_20260115_044001.tar.gz`
- Size: 1.5 MB

---

### Notes

- Snoop prioritized between maigret (highest) and sherlock
- Database now contains 8,315 sites for username enumeration (more than doubled)
- Many Snoop sites are Russian/Eastern European forums
- Snoop source stored locally (base32 encoded file required)

---

---

## Session 2 (Continued) - Snoop Decoder Module

### User Request
> now create a module to decrypt snoop databases and add it to OSINT menu

---

### Work Completed

#### 1. Created Snoop Decoder Module

**modules/snoop_decoder.py** - Full GUI module for decoding Snoop databases

**Features:**
- Decode any Snoop database file (BDdemo, BDfull, custom)
- View decoded data with statistics
- Import decoded sites to AUTARCH database
- Quick import from known locations
- View current sites database stats

**Menu Structure:**
```
  Snoop Database Decoder
  ──────────────────────────────────────────────────

  [1] Decode Snoop Database File
  [2] Decode & Import to AUTARCH
  [3] View Current Sites Database Stats

  [4] Quick Import (BDfull from snoop-master)
  [5] Quick Import (BDdemo from snoop-master)

  [0] Back to OSINT Menu
```

**SnoopDecoder Class Methods:**
| Method | Purpose |
|--------|---------|
| `decode_database()` | Decode base32 encoded database file |
| `save_decoded()` | Save decoded data to JSON |
| `import_to_database()` | Import sites to AUTARCH SQLite DB |
| `show_sample()` | Display sample sites from decoded data |
| `get_stats()` | Get statistics about decoded database |

---

#### 2. Added to OSINT Menu

**modules/recon.py** - Updated with new tools section

**New Menu Options:**
```
  Tools
    [S] Snoop Database Decoder
    [D] Sites Database Stats
```

**New Methods Added:**
| Method | Purpose |
|--------|---------|
| `run_snoop_decoder()` | Launch Snoop Decoder module |
| `show_sites_db_stats()` | Display sites DB statistics with visual bars |

---

### Files Created/Modified

| File | Lines | Purpose |
|------|-------|---------|
| modules/snoop_decoder.py | ~320 | New Snoop decoder module |
| modules/recon.py | +40 | Added tools section and handlers |

---

### Module Metadata

```python
NAME = "Snoop Decoder"
DESCRIPTION = "Decrypt and import Snoop Project databases"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"
```

---

### Usage

From AUTARCH main menu:
1. Select **OSINT** (option 5)
2. Press **S** for Snoop Database Decoder
3. Choose decode option (1-5)
4. Follow prompts to decode/import

Or run directly:
```bash
python autarch.py -m snoop_decoder
```

---

## Session - 2026-01-15 (Continued) - Snoop Features Integration

### User Request
> now lets add some snoops features to our app

---

### Work Completed

Added several Snoop-inspired features to AUTARCH, all translated to English and branded for AUTARCH:

#### 1. GEO IP/Domain Lookup Module (`modules/geoip.py`)

Full geolocation lookup for IPs, domains, and URLs. Features:
- Single IP/domain/URL lookup
- Your own IP lookup
- Bulk lookup from file
- Uses multiple API backends (ipwho.is, ipinfo.io)
- DNS resolution with IPv4/IPv6
- Map links (OpenStreetMap, Google Maps)

```python
NAME = "GEO IP Lookup"
DESCRIPTION = "Get geolocation for IPs, domains, and URLs"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"
```

#### 2. Yandex OSINT Module (`modules/yandex_osint.py`)

Gather intelligence from Yandex user accounts. Features:
- Lookup by login/email
- Extract user from Yandex.Disk public links
- Lookup by public ID (26-char hash)
- Returns: name, email, avatar, and profile links for:
  - Yandex Reviews
  - Yandex Market
  - Yandex Music
  - Yandex Dzen
  - Yandex Q&A

```python
NAME = "Yandex OSINT"
DESCRIPTION = "Gather intel from Yandex user accounts"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"
```

#### 3. Network Test Module (`modules/nettest.py`)

Network connectivity and speed testing. Features:
- Connectivity test (ping multiple sites)
- Full speed test (download/upload/ping)
- DNS resolution test
- Run all tests option
- Uses speedtest-cli library (optional)

```python
NAME = "Network Test"
DESCRIPTION = "Test network speed and connectivity"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "utility"
```

#### 4. HTML Report Generator (`core/report_generator.py`)

Generate professional HTML reports for scan results. Features:
- Dark theme with AUTARCH branding
- Username scan reports with:
  - Stats overview
  - Confidence scoring visualization
  - Category breakdown
  - Restricted access section
- GEO IP bulk lookup reports
- Responsive table design

#### 5. Updated OSINT Menu

New menu structure in `modules/recon.py`:

```
  Tools
    [G] GEO IP/Domain Lookup      <- NEW
    [Y] Yandex OSINT              <- NEW
    [N] Network Test              <- NEW
    [S] Snoop Database Decoder
    [D] Sites Database Stats
```

#### 6. Username Scanner Improvements

- Added scan time tracking
- HTML report generation option
- Save options: [1] JSON, [2] HTML, [3] Both, [n] No

---

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| modules/geoip.py | ~350 | GEO IP/Domain lookup |
| modules/yandex_osint.py | ~280 | Yandex user OSINT |
| modules/nettest.py | ~300 | Network speed/connectivity tests |
| core/report_generator.py | ~350 | HTML report generation |

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Added new modules to menu, HTML report support |
| (version bumped to 2.2) | |

---

### Directory Structure Update

```
dh_framework/
├── core/
│   ├── report_generator.py     # NEW - HTML reports
│   └── ...
├── modules/
│   ├── geoip.py                # NEW - GEO IP lookup
│   ├── yandex_osint.py         # NEW - Yandex OSINT
│   ├── nettest.py              # NEW - Network testing
│   └── ...
└── results/
    └── reports/                # NEW - HTML report output
```

---

### Usage Examples

**GEO IP Lookup:**
```
OSINT Menu > [G] GEO IP/Domain Lookup
> Enter: 8.8.8.8
> Shows: Country, Region, City, ISP, Map links
```

**Yandex OSINT:**
```
OSINT Menu > [Y] Yandex OSINT
> Enter Yandex login: username
> Shows: Name, Email, Avatar, Profile links
```

**Network Test:**
```
OSINT Menu > [N] Network Test
> [1] Test Connectivity
> [2] Full Speed Test
> [3] Test DNS
> [4] Run All Tests
```

**Username Scan with HTML Report:**
```
OSINT Menu > [3] Username Lookup
> Enter username: target_user
> Scan completes...
> Save results? [2] HTML
> Saved HTML report to results/reports/target_user_20260115_050000.html
```

---

### Notes

- All modules are in English (translated from Russian Snoop Project)
- All modules are branded as AUTARCH/darkHal Security Group
- Modules follow AUTARCH coding conventions
- HTML reports use a dark theme matching the terminal aesthetic

---

## Session 3 - OSINT Improvements

### Overview

This session focused on improving the OSINT username scanning functionality:
1. Adding configurable thread settings
2. Fixing malformed site names
3. Improving false positive detection
4. Cleaning up garbage sites from the database

---

### Part 1: OSINT Thread Settings

### User Request
> we need to add a threads setting for the OSINT search. For some reason it thinks my device has 50 threads. So lets add a option in the settings menu to adjust max threads and lets have the application default to 8

---

### Work Completed

#### 1. Added OSINT Configuration Section (core/config.py)

**New Default Config Section:**
```python
'osint': {
    'max_threads': '8',
    'timeout': '8',
    'include_nsfw': 'false',
}
```

**New Method:**
```python
def get_osint_settings(self) -> dict:
    """Get all OSINT settings as a dictionary."""
    return {
        'max_threads': self.get_int('osint', 'max_threads', 8),
        'timeout': self.get_int('osint', 'timeout', 8),
        'include_nsfw': self.get_bool('osint', 'include_nsfw', False),
    }
```

---

#### 2. Updated OSINT Modules to Use Config

**modules/recon.py:**
- Imports `get_config` from core.config
- Reads thread count from config instead of hardcoded 50
- Also uses config for timeout and NSFW settings

```python
def __init__(self):
    self.config = get_config()
    osint_settings = self.config.get_osint_settings()
    self.scan_config = {
        'max_sites': 200,
        'include_nsfw': osint_settings['include_nsfw'],
        'categories': None,
        'timeout': osint_settings['timeout'],
        'threads': osint_settings['max_threads'],  # Was hardcoded to 50
    }
```

**modules/adultscan.py:**
- Imports `get_config` from core.config
- Uses `self.max_threads` from config instead of hardcoded 10

```python
def __init__(self):
    self.config = get_config()
    osint_settings = self.config.get_osint_settings()
    self.timeout = osint_settings['timeout']
    self.max_threads = osint_settings['max_threads']  # Was hardcoded to 10
```

---

#### 3. Added OSINT Settings Menu (core/menu.py)

**Updated Settings Menu:**
```
  Settings
  ──────────────────────────────────────────────────

  [1] LLM Settings
  [2] Metasploit Settings
  [3] Database Management
  [4] Custom APIs
  [5] AUTARCH API
  [6] OSINT Settings          <- NEW

  [7] View All Settings
  [8] Run Setup Wizard

  [0] Back
```

**OSINT Settings Submenu:**
```
  OSINT Settings
  ──────────────────────────────────────────────────

    Max Threads:    8
    Timeout:        8 seconds
    Include NSFW:   No

  Thread setting controls parallel requests during
  username scanning. Lower values = slower but safer.

  [1] Set Max Threads
  [2] Set Timeout
  [3] Toggle NSFW Sites

  [0] Back
```

**New Methods Added:**
| Method | Purpose |
|--------|---------|
| `show_osint_settings()` | Display OSINT settings menu |
| `_set_osint_threads()` | Configure max threads (1-100) |
| `_set_osint_timeout()` | Configure timeout (1-60 seconds) |
| `_toggle_osint_nsfw()` | Toggle NSFW site inclusion |

---

#### 4. Updated "View All Settings"

Now includes OSINT configuration in the full settings view:
```
  OSINT Configuration:
    max_threads         : 8
    timeout             : 8
    include_nsfw        : False
```

---

### Files Modified

| File | Changes |
|------|---------|
| core/config.py | Added `[osint]` section defaults, `get_osint_settings()` method |
| core/menu.py | Added OSINT Settings menu (option 6), 3 new config methods |
| modules/recon.py | Import config, use `osint_settings['max_threads']` |
| modules/adultscan.py | Import config, use `self.max_threads` from config |

---

### Configuration File Format

New section in `autarch_settings.conf`:
```ini
[osint]
max_threads = 8
timeout = 8
include_nsfw = false
```

---

### Usage

**To adjust OSINT thread count:**
```
Main Menu → Settings (99) → OSINT Settings (6) → Set Max Threads (1)
```

**Recommended values:**
- Low-end devices: 4-8 threads
- Mid-range devices: 8-16 threads
- High-end devices: 16-32 threads

---

### Notes

- Default changed from 50 to 8 threads for safer scanning
- Setting persists in `autarch_settings.conf`
- Both `recon.py` and `adultscan.py` now use the same config
- Timeout and NSFW toggle also configurable from the same menu

---

### Part 2: Username Scan Improvements

**User Request:**
> we need improve the false positive detection on the username scan, as well as scan sites alphabetically. It also appears we have a naming issue. we have lots of sites that just say forum_name instead of the name of the sites. Also there are missing sites. Did you filter and remove sites like imgsrc.ru when you imported data?

---

### Investigation Results

1. **Malformed Names**: Found 3,409 sites with bad names:
   - `{username}.domain` style names (placeholder not replaced)
   - `Forum_sitename` patterns
   - `site_vb1`, `site_xf`, `site_phpbb` duplicates (forum software variants)

2. **imgsrc.ru**: NOT filtered - exists in database (2 entries)

3. **Sites ordered by rank, not alphabetically**

---

### Work Completed

#### 1. Database Cleanup (core/sites_db.py)

**Added `cleanup_names()` method:**
- Fixes `{username}` style names by extracting from URL domain
- Fixes `Forum_name` patterns by extracting actual name
- Removes duplicate forum software variants (`_vb1`, `_xf`, `_phpbb`, etc)
- Merges renamed entries if name already exists

**Cleanup Results:**
```
Renamed: 3,171
Merged:  84
Deleted: 407
Total removed: 3,662 malformed entries
Sites remaining: 7,824
```

---

#### 2. Alphabetical Sorting (core/sites_db.py)

**Updated `get_sites_for_scan()` method:**
- Added `sort_alphabetically` parameter (default: `True`)
- Sites now scanned A-Z by default instead of by rank
- Query excludes malformed names automatically

```python
def get_sites_for_scan(
    self,
    categories: List[str] = None,
    include_nsfw: bool = False,
    max_sites: int = 500,
    sort_alphabetically: bool = True  # NEW
) -> List[Dict]:
```

**SQL Filtering:**
```sql
AND name NOT LIKE '{%'
AND name NOT LIKE '%_vb1' AND name NOT LIKE '%_vb2'
AND name NOT LIKE '%_xf' AND name NOT LIKE '%_phpbb'
AND name NOT LIKE '%_mybb' AND name NOT LIKE '%_smf'
AND name NOT LIKE '%_ipb' AND name NOT LIKE '%_generic'
```

---

#### 3. Improved False Positive Detection (modules/recon.py)

**Expanded NOT_FOUND_PATTERNS (30 patterns):**
- Registration prompts ("this username is available")
- Soft 404 indicators ("oops", "sorry")
- Suspension/ban messages
- Generic error page patterns
- Title tag checks for 404/error

**Expanded FOUND_PATTERNS (23 patterns):**
- Account age/dates
- Activity statistics
- Activity timestamps
- Profile content indicators
- Verification badges
- Cam/streaming site patterns
- Social profile patterns
- E-commerce/creator patterns

**Added FALSE_POSITIVE_URLS list:**
```python
FALSE_POSITIVE_URLS = [
    '/login', '/signin', '/signup', '/register', '/join',
    '/404', '/error', '/not-found', '/notfound',
    '/search', '/home', '/index', '/welcome',
]
```

**Improved Detection Logic:**
- Username variation checking (underscores, hyphens, dots)
- Better handling of short usernames (extra validation required)
- Short page content checks for generic indicators
- API/JSON endpoint confidence reduction
- Search query parameter detection
- Confidence capping at 100%
- Higher minimum threshold (45% vs 40%)

---

### Files Modified

| File | Changes |
|------|---------|
| core/sites_db.py | `cleanup_names()` method, `sort_alphabetically` param, malformed name filtering |
| modules/recon.py | Expanded patterns, FALSE_POSITIVE_URLS, improved detection logic |

---

### Site Count After Cleanup

| Metric | Count |
|--------|-------|
| Total sites | 7,824 |
| Malformed names | 0 |
| imgsrc.ru entries | 2 (not filtered) |

---

### Notes

- No sites were filtered during import - imgsrc.ru and other adult sites are present
- Forum software variants were removed as duplicates (one entry per forum is sufficient)
- Alphabetical sorting makes progress easier to track during long scans
- False positive detection now more robust with 30+ NOT_FOUND patterns

---

### Part 3: Other Category Cleanup

**User Request:**
> its seems like their is alot of garbage sites in the other category

---

### Investigation

Found 6,462 sites (82%) in "other" category with many issues:
- Russian forum farms (ucoz, borda, at.ua, clan.su)
- Search URLs (not actual profile pages)
- Dead/closed sites
- Wiki user pages
- Invalid domains (google.com, gmail.com)
- Duplicate entries

---

### Work Completed

#### 1. Added `cleanup_garbage_sites()` Method

Disables low-quality sites:
```python
# Russian forum farms
ucoz.ru, ucoz.net, ucoz.com, at.ua, borda.ru, clan.su, forum24.ru, mybb.ru, do.am

# Search URLs (not profile pages)
search.php?author=, /search?, action=search, memberlist.php?mode=viewprofile

# uCoz profile pattern
/index/8-0-
```

Deletes garbage:
```python
# Dead sites
CLOSEDEAD, CLOSED, __DEAD, _DEAD

# Duplicate markers
__2, __3
```

#### 2. Added `auto_categorize()` Method

Auto-categorizes sites based on name/URL patterns:
- **tech**: github, stackoverflow, hackerone, etc.
- **gaming**: twitch, steam, xbox, playstation, etc.
- **art**: 500px, flickr, deviantart, etc.
- **forum**: sites with forum/forums in URL
- **adult**: pornhub, onlyfans, chaturbate, etc.
- **social**: mastodon, minds, mewe, etc.
- And more...

#### 3. Added `remove_duplicates()` Method

Removes sites with identical URL templates.

#### 4. Additional Cleanup

- Disabled wiki user pages (`/wiki/User:`)
- Disabled archive.org wayback URLs
- Deleted invalid domains (google.com, gmail.com)
- Disabled more search URL patterns

---

### Results

| Metric | Before | After | Change |
|--------|--------|-------|--------|
| Total sites | 7,824 | 7,119 | -705 |
| Enabled sites | 7,824 | 4,786 | -3,038 |
| "other" category | 6,462 (82%) | 2,011 (42%) | -4,451 |
| Disabled sites | 0 | 2,333 | +2,333 |

**Sites by Category (Enabled):**
```
other        2,011
forum        1,284
social         277
adult          243
tech           240
gaming         170
art             95
news            91
video           82
finance         80
music           63
professional    50
shopping        46
dating          45
hobby            8
images           1
```

---

### New Methods in sites_db.py

| Method | Purpose |
|--------|---------|
| `cleanup_garbage_sites()` | Disable Russian forums, search URLs, dead sites |
| `auto_categorize()` | Auto-categorize "other" sites by patterns |
| `remove_duplicates()` | Remove duplicate URL templates |
| `get_disabled_count()` | Get count of disabled sites |
| `enable_all_sites()` | Re-enable all disabled sites |

---

### Notes

- Sites are **disabled**, not deleted (can be re-enabled)
- "other" category now contains legitimate misc sites
- Quality over quantity - 4,786 enabled sites vs 7,824 total
- Use `db.enable_all_sites()` to restore all sites if needed

---

### Session 3 Summary

**Files Modified:**
| File | Changes |
|------|---------|
| `core/config.py` | Added `[osint]` section, `get_osint_settings()` |
| `core/menu.py` | Added OSINT Settings menu (option 6) |
| `core/sites_db.py` | Added `cleanup_garbage_sites()`, `auto_categorize()`, `remove_duplicates()`, `cleanup_names()`, alphabetical sorting |
| `modules/recon.py` | Expanded detection patterns, improved confidence logic |
| `modules/adultscan.py` | Added config support for threads |

**Database Changes:**
| Metric | Original | Final |
|--------|----------|-------|
| Total sites | 8,315+ | 7,119 |
| Enabled sites | 8,315+ | 4,786 |
| "other" category | 82% | 42% |
| Malformed names | 3,409 | 0 |

**Key Improvements:**
- Configurable OSINT thread count (default: 8)
- Sites scanned alphabetically for easier progress tracking
- 30+ NOT_FOUND patterns for false positive detection
- 23+ FOUND patterns for profile validation
- Auto-categorization of sites
- Garbage site filtering (Russian forum farms, search URLs, wiki pages)

---

---

## Session 3 (Continued) - Social-Analyzer Style Detection

### User Request
> the username search still needs some tweaks. take a look at how social analyzer does it /home/snake/Downloads/OSINT/social-analyzer-main.zip and make ours more like that

---

### Analysis of Social-Analyzer

Examined the social-analyzer codebase and identified key differences:

1. **Detection System**: Uses `return: true/false` pattern
   - `return: false` + string found = user does NOT exist
   - `return: true` + string found = user EXISTS

2. **Rate Calculation**: `rate = (detections_passed / detections_total) * 100`

3. **Status Categories**:
   - `good`: 100% rate
   - `maybe`: 50-100% rate
   - `bad`: <50% rate

4. **WAF/Captcha Detection**: Filters Cloudflare and captcha pages

5. **Random Delays**: `sleep(randint(1, 99) / 100)` to avoid rate limiting

6. **Retry Logic**: Retries failed sites up to 3 times

---

### Work Completed

#### 1. Rewrote Detection System (modules/recon.py)

**New WAF/Captcha Detection:**
```python
WAF_PATTERNS = re.compile(
    r'captcha-info|Please enable cookies|Completing the CAPTCHA|'
    r'checking your browser|just a moment|ddos protection|'
    r'access denied|blocked|security check|verify you are human',
    re.IGNORECASE
)

WAF_TITLE_PATTERNS = re.compile(
    r'not found|blocked|attention required|cloudflare|'
    r'access denied|security check|ddos|captcha',
    re.IGNORECASE
)
```

**New Shared Detections (like social-analyzer):**
```python
SHARED_DETECTIONS = {
    'mastodon': [
        {'return': False, 'string': "The page you are looking for isn"},
        {'return': True, 'string': 'profile:username'},
    ],
    'discourse': [...],
    'gitlab': [...],
    'phpbb': [...],
    'xenforo': [...],
    'vbulletin': [...],
}
```

**New Detection Logic:**
- Check NOT_FOUND_STRINGS (return: false patterns)
- Check FOUND_STRINGS (return: true patterns)
- Check if username in content/URL
- Calculate rate as percentage
- Determine status (good/maybe/bad)

#### 2. Updated `_check_site()` Method

**Key Changes:**
- Random delay: `time.sleep(randint(5, 50) / 100)`
- Cloudflare detection via `cf-ray` header
- WAF content pattern matching
- Title extraction and analysis
- Rate calculation: `rate = (passed / total) * 100`
- Status determination: good (100%), maybe (50-100%), bad (<50%)
- Retry logic for 5xx errors and connection failures (up to 2 retries)
- Returns `filtered` status for WAF-blocked pages

**Return Format:**
```python
{
    'name': site['name'],
    'url': url,
    'category': site.get('category', 'other'),
    'rate': '75.5%',      # Percentage
    'status': 'maybe',    # good/maybe/bad/restricted/filtered
    'title': 'Page Title',
    'is_tracker': False,
    'found': 5,           # Detections passed
    'total': 8,           # Total detections
}
```

#### 3. Updated Display Logic

**Real-time Output:**
```
  [+] SiteName                https://site.com/user [100.0%]  (good - green)
  [?] OtherSite               https://other.com/user [65.5%]  (maybe - yellow)
```

**Summary Categories:**
```
Results Breakdown (social-analyzer style):
  Detected (good):     15
  Unknown (maybe):     8
  Bad (low rate):      3
  Restricted (403):    12
  Filtered (WAF):      5
  Tracker sites:       2
```

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Complete rewrite of detection system, WAF detection, retry logic, rate calculation |

---

### Detection Patterns

**NOT_FOUND_STRINGS (return: false):**
- user not found, profile not found, page not found
- does not exist, no user, no such user
- account has been suspended/deleted/banned
- sign up, create an account, register now
- there's nothing here, this page is no longer available

**FOUND_STRINGS (return: true):**
- og:title, profile:username, user-profile
- member-header, profile-header, user-info
- followers, following, posts, joined
- member since, last seen, last active
- follow, subscribe, message

---

### Comparison with Social-Analyzer

| Feature | Before | After (social-analyzer style) |
|---------|--------|-------------------------------|
| Detection | Regex patterns | String matching with return true/false |
| Confidence | 0-100 score | Rate percentage |
| Status | High/Medium/Low | good/maybe/bad |
| WAF Detection | None | Cloudflare + captcha patterns |
| Delays | None | Random 50-500ms |
| Retries | None | Up to 2 retries |
| Filtering | None | Filtered status for WAF |

---

### Notes

- Detection system now mirrors social-analyzer's approach
- Rate calculation is more accurate than arbitrary confidence scores
- WAF detection prevents false positives from Cloudflare pages
- Random delays reduce rate limiting issues
- Retry logic handles temporary failures
- Filtered status clearly marks WAF-blocked results

---

---

## Session 3 (Continued) - Verbose Output & Blackbird Import

### User Request
> you turned off username scan verbose results, make sure it shows realtime the site being scanned. Also import the sites from this application /home/snake/blackbird

---

### Work Completed

#### 1. Real-Time Verbose Output (modules/recon.py)

Added real-time progress display during username scanning:

```python
# Show current site being checked (verbose)
print(f"\r{Colors.DIM}  [{checked}/{total_sites}] Checking: {site['name'][:30]:30}{Colors.RESET}", end='', flush=True)
```

**Features:**
- Shows current progress counter `[X/Y]`
- Displays site name being checked (truncated to 30 chars)
- Uses carriage return `\r` for in-place updates
- Dimmed color to distinguish from results
- Clears line before printing final results

---

#### 2. Blackbird Sites Import (core/sites_db.py)

Added `import_from_blackbird()` method to import sites from the blackbird OSINT tool.

**Blackbird Data Format** (`wmn-data.json`):
```json
{
  "SiteName": {
    "main": "https://example.com",
    "uri_check": "https://example.com/user/{account}",
    "e_string": "not found",
    "e_code": 404,
    "m_string": "",
    "m_code": 200,
    "cat": "social"
  }
}
```

**Import Method:**
```python
def import_from_blackbird(self, blackbird_path: str = '/home/snake/blackbird', verbose: bool = True) -> Dict[str, int]:
    """Import sites from blackbird application."""
    # Load wmn-data.json
    # Parse each site entry
    # Handle {account} placeholder -> {}
    # Handle name collisions by adding _bb suffix
    # Skip duplicate URLs
```

**Name Collision Handling:**
```python
# Check if name already exists - if so, append source suffix
cursor.execute("SELECT id FROM sites WHERE name = ?", (name,))
existing_name = cursor.fetchone()
if existing_name:
    name = f"{name}_bb"  # Add blackbird suffix
```

**Import Results:**
- First run: 77 new sites added, 573 skipped (URL duplicates)
- After name collision fix: 91 additional sites added
- **Total from blackbird: 168 new sites**

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Added real-time verbose output in `_check_site()` loop |
| core/sites_db.py | Added `import_from_blackbird()` method |

---

### Database Statistics Update

| Metric | Before | After |
|--------|--------|-------|
| Total sites | 7,119 | 7,287 |
| Sources | 9 | 10 |
| Blackbird sites | 0 | 168 |

---

### Notes

- Blackbird uses `{account}` as placeholder (converted to `{}`)
- Name collisions resolved with `_bb` suffix
- Most blackbird sites already existed in database (from other sources)
- Verbose output updates in-place without scrolling

---

---

## Session 4 - 2026-01-15 (Continued) - Dossier Manager & NSFW Fix

### User Request
> in the OSINT section, lets add a new menu named Dossier. In dossier the options are Start New and View. What this module does is lets users view saved information from the recon module and lets you associate information such as the results from an email search and username search

---

### Work Completed

#### 1. Dossier Manager Module (modules/dossier.py)

Created a comprehensive OSINT investigation management system:

**Menu Structure:**
```
  Dossier Manager
  ──────────────────────────────────────────────────
  Saved dossiers: X

  [1] Start New Dossier
  [2] View Dossiers

  [0] Back
```

**Dossier Features:**
- Create new dossiers with subject name, notes, and initial identifiers
- Store multiple identifier types:
  - Emails
  - Usernames
  - Phone numbers
  - Real names
  - Aliases
- Import search results from JSON files (username scan results)
- Manually add profiles
- Add investigation notes
- View all associated data grouped by category
- Export as JSON or text report

**Dossier Detail Menu:**
```
  View
    [1] View Identifiers
    [2] View Search Results
    [3] View Profiles
    [4] View Notes

  Add
    [5] Add Identifier
    [6] Import Search Results
    [7] Add Profile Manually
    [8] Add Note

  Manage
    [E] Edit Dossier Info
    [X] Export Dossier
    [D] Delete Dossier
```

**Storage:**
- Dossiers saved as JSON in `dossiers/` directory
- Auto-generated unique IDs with timestamps
- Supports importing `*_profiles.json` files from username scans

---

#### 2. Added Dossier to OSINT Menu (modules/recon.py)

**New Menu Section:**
```
  Dossier
    [R] Dossier Manager
```

**Methods Added:**
| Method | Purpose |
|--------|---------|
| `run_dossier_manager()` | Launch Dossier Manager module |

---

#### 3. Fixed NSFW Adult Site Detection

**Issue:** Adult sites like Chaturbate weren't appearing in results even with NSFW enabled.

**Root Causes Found:**
1. **Inconsistent NSFW flags**: 97 adult category sites had `nsfw=0`
2. **Config not used**: `include_nsfw` config setting wasn't being used as default

**Fixes Applied:**

**Database Fix:**
```sql
UPDATE sites SET nsfw = 1 WHERE category = 'adult'
-- Updated 179 adult category sites
```

**Code Fix (modules/recon.py):**
```python
# Before: hardcoded default
include_nsfw = False

# After: uses config setting
osint_settings = self.config.get_osint_settings()
include_nsfw = osint_settings['include_nsfw']
```

**Prompt Updated:**
- Now shows current config default (y/n)
- Press Enter keeps default instead of overriding to 'n'

---

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| modules/dossier.py | ~680 | Dossier Manager module |

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Added Dossier menu section, `run_dossier_manager()` method, fixed NSFW default |
| data/sites/sites.db | Fixed nsfw=1 for all adult category sites |

---

### New Directory

| Path | Purpose |
|------|---------|
| dossiers/ | Storage for dossier JSON files |

---

### Dossier JSON Structure

```json
{
  "meta": {
    "name": "Investigation Name",
    "subject": "Target identifier",
    "created": "2026-01-15T12:00:00",
    "modified": "2026-01-15T12:00:00",
    "notes": "Initial notes"
  },
  "identifiers": {
    "emails": ["user@example.com"],
    "usernames": ["username1", "username2"],
    "phones": ["+1234567890"],
    "real_names": ["John Doe"],
    "aliases": ["alias1"]
  },
  "results": {
    "email_searches": [],
    "username_searches": [
      {
        "username": "target",
        "date": "2026-01-15T12:00:00",
        "total_checked": 500,
        "found": [...]
      }
    ],
    "phone_searches": []
  },
  "profiles": [
    {
      "name": "SiteName",
      "url": "https://site.com/user",
      "category": "social",
      "status": "good",
      "rate": "100%"
    }
  ],
  "custom_notes": [
    {"date": "2026-01-15T12:00:00", "text": "Investigation note"}
  ]
}
```

---

### Notes

- Dossier Manager allows correlating data from multiple OSINT searches
- Import feature automatically adds username to identifiers list
- All adult category sites now properly flagged as NSFW
- Username scan now respects `include_nsfw` config setting as default
- Dossiers can be exported as JSON (full data) or text (readable report)

---

---

## Session 4 (Continued) - Site Additions & Adult Site Fixes

### User Requests
> chaturbate.com should have user url like this https://chaturbate.com/fudnucker/
> in the project directory add the sites from pred_site.txt
> also make sure imgsrc.ru is in the database
> chaturbate still isnt showing up. i think the issue is that a age confirmation appears

---

### Work Completed

#### 1. Fixed Chaturbate URL Format

**Issue:** Chaturbate URL was missing trailing slash.

**Fix:**
```sql
-- Deleted incorrect entry (no trailing slash)
DELETE FROM sites WHERE name = 'ChaturBate' AND url_template = 'https://chaturbate.com/{}'

-- Renamed correct entry
UPDATE sites SET name = 'Chaturbate' WHERE url_template = 'https://chaturbate.com/{}/'
```

**Result:** `https://chaturbate.com/fudnucker/` (correct format)

---

#### 2. Added Sites from pred_site.txt

Imported fanfiction and adult sites:

| Site | URL Pattern | Category | NSFW |
|------|-------------|----------|------|
| Fimfiction | `https://www.fimfiction.net/user/{}` | fanfiction | No |
| Inkbunny | `https://inkbunny.net/{}` | adult | Yes |
| ArchiveOfOurOwn | `https://archiveofourown.org/users/{}` | fanfiction | No |
| AdultFanfiction | `https://www2.adult-fanfiction.org/forum/search/?&q={}&type=core_members` | adult | Yes |
| FanfictionNet | `https://www.fanfiction.net/u/{}` | fanfiction | No |
| Kemono | `https://kemono.su/artists?q={}` | adult | Yes |

**Notes:**
- Inkbunny was already in database
- Created new "fanfiction" category
- AdultFanfiction and Kemono use search URLs (direct profiles require numeric IDs)

---

#### 3. Fixed imgsrc.ru Configuration

**Issue:** imgsrc.ru was categorized as "other" with `nsfw=0`.

**Fix:**
```sql
UPDATE sites SET category = 'adult', nsfw = 1 WHERE name LIKE '%imgsrc%'
```

**Result:**
| Site | URL Pattern | Category | NSFW |
|------|-------------|----------|------|
| imgsrc.ru | `https://imgsrc.ru/main/user.php?user={}` | adult | Yes |
| iMGSRC.RU | `https://imgsrc.ru/main/user.php?lang=ru&user={}` | adult | Yes |

---

#### 4. Added Age Verification Cookies

**Issue:** Adult sites like Chaturbate show age confirmation pages, causing scans to fail.

**Solution:** Added `SITE_COOKIES` dictionary with age verification cookies for 25+ adult sites.

**New Code (modules/recon.py):**
```python
SITE_COOKIES = {
    'chaturbate.com': 'agreeterms=1; age_verified=1',
    'stripchat.com': 'age_confirmed=true',
    'bongacams.com': 'bonga_age=true',
    'cam4.com': 'age_checked=true',
    'myfreecams.com': 'mfc_age_check=1',
    'camsoda.com': 'age_verified=1',
    'livejasmin.com': 'age_gate=true',
    'pornhub.com': 'age_verified=1; accessAgeDisclaimerPH=1',
    'xvideos.com': 'age_verified=1',
    'xhamster.com': 'age_check=1',
    'xnxx.com': 'age_verified=1',
    'redtube.com': 'age_verified=1',
    'youporn.com': 'age_verified=1',
    'spankbang.com': 'age_verified=1',
    'eporner.com': 'age_verified=1',
    'rule34.xxx': 'age_gate=1',
    'e621.net': 'age_check=1',
    'furaffinity.net': 'sfw=0',
    'inkbunny.net': 'age_check=1',
    'hentai-foundry.com': 'age_check=1',
    'f95zone.to': 'xf_logged_in=1',
    'imgsrc.ru': 'lang=en; over18=1',
    'fansly.com': 'age_verified=1',
    'onlyfans.com': 'age_verified=1',
    'fetlife.com': 'age_check=1',
}
```

**Implementation:**
```python
# In _check_site() method - add cookies based on domain
parsed_url = urlparse(url)
domain = parsed_url.netloc.lower()
for cookie_domain, cookies in self.SITE_COOKIES.items():
    if cookie_domain in domain:
        headers['Cookie'] = cookies
        break
```

---

#### 5. Fixed Overly Aggressive WAF Detection

**Issue:** Chaturbate (and other Cloudflare-served sites) were being marked as "filtered" even when returning valid content.

**Root Cause:** WAF detection triggered on ANY Cloudflare-served site:
```python
# OLD - Too aggressive
if resp_headers.get('server', '') == 'cloudflare':
    is_filtered = True
```

**Fix:** Only detect actual challenge/block pages:
```python
# NEW - Check for actual challenge page content
cf_challenge_patterns = [
    'just a moment', 'checking your browser', 'please wait',
    'ray id', 'cf-browser-verification', 'cf_chl_opt',
    'enable javascript and cookies', 'why do i have to complete a captcha',
]
if any(p in content_lower for p in cf_challenge_patterns):
    is_filtered = True

# Only flag WAF patterns on short pages (likely error pages)
if self.WAF_PATTERNS.search(content):
    if content_len < 5000:
        is_filtered = True
```

**Updated WAF Patterns:**
```python
# More specific - only actual challenge indicators
WAF_PATTERNS = re.compile(
    r'captcha-info|Completing the CAPTCHA|'
    r'cf-browser-verification|cf_chl_prog|'
    r'ddos protection by|verify you are human|'
    r'please turn javascript on|enable cookies to continue',
    re.IGNORECASE
)

WAF_TITLE_PATTERNS = re.compile(
    r'just a moment|attention required|'
    r'ddos-guard|security check required',
    re.IGNORECASE
)
```

---

### Test Results

**Username scan for `fudnucker` on adult sites:**

| Site | Status | Rate | URL |
|------|--------|------|-----|
| Chaturbate | maybe | 60% | https://chaturbate.com/fudnucker/ |
| AdultFanfiction | maybe | 66.7% | Search results |
| BDSMLR | maybe | 50% | https://fudnucker.bdsmlr.com |

Chaturbate now successfully detected after all fixes applied.

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Added SITE_COOKIES dict, cookie injection in requests, fixed WAF detection logic |
| data/sites/sites.db | Fixed Chaturbate URL, added fanfiction sites, fixed imgsrc.ru |

---

### Database Changes

| Change | Count |
|--------|-------|
| Chaturbate URL fixed | 1 |
| New fanfiction sites | 4 |
| imgsrc.ru category/nsfw fixed | 2 |
| ChaturbateRU category fixed | 1 |

---

### Notes

- Age verification cookies bypass consent popups without user interaction
- WAF detection now only triggers on actual challenge pages, not CDN-served content
- Fanfiction category created for fanfic sites (AO3, Fimfiction, FanFiction.net)
- Sites using numeric IDs in URLs use search endpoints instead

---

---

## Session 4 (Continued) - Agent Hal Module

### User Request
> Now lets work on the LLM integration and automation features. Lets first start by adding Agent Hal menu option. In this menu, lets focus on defense and pen-testing for now. Lets set it up to have a MITM detection module, and then options to run MSF modules automated by having the user tell the LLM what it wants

---

### Work Completed

#### 1. Created Agent Hal Module (`modules/agent_hal.py`)

AI-powered security automation module with two main features:

**Menu Structure:**
```
  Agent Hal
  AI-powered security automation
  ──────────────────────────────────────────────────
  LLM: Ready  |  MSF: Connected

  Defense
    [1] MITM Detection

  Offense
    [2] MSF Automation (AI)

  [0] Back
```

---

#### 2. MITM Detection System

**Submenu:**
```
  MITM Detection
  ──────────────────────────────────────────────────

  [1] Full MITM Scan (All Checks)
  [2] ARP Spoofing Detection
  [3] DNS Spoofing Detection
  [4] SSL/TLS Stripping Detection
  [5] Rogue DHCP Detection
  [6] Gateway Anomaly Check

  [7] Continuous Monitoring Mode

  [0] Back
```

**Detection Methods:**

| Check | Description | Severity |
|-------|-------------|----------|
| ARP Spoofing | Detects duplicate MACs in ARP table | HIGH |
| DNS Spoofing | Compares local DNS vs Google DNS resolution | HIGH |
| SSL Stripping | Tests HTTPS connections and certificates | MEDIUM |
| Rogue DHCP | Checks DHCP server legitimacy | HIGH |
| Gateway Anomaly | Verifies gateway MAC and connectivity | MEDIUM |

**Continuous Monitoring:**
- Captures baseline ARP table
- Monitors for MAC address changes every 5 seconds
- Alerts on new hosts joining network
- Alerts on MAC changes for known IPs (ARP spoofing indicator)

---

#### 3. LLM-Powered MSF Automation

**Submenu:**
```
  MSF Automation (AI-Powered)
  ──────────────────────────────────────────────────
  LLM: Loaded  |  MSF: Connected

  [1] Describe What You Want To Do
  [2] Quick Scan Target
  [3] Exploit Suggester
  [4] Post-Exploitation Helper

  [C] Connect to MSF
  [L] Load LLM Model

  [0] Back
```

**Natural Language MSF Control:**
- Users describe what they want in plain English
- LLM interprets request and recommends MSF modules
- Returns JSON with module path, options, and explanation
- User confirms before execution

**Example Workflow:**
```
User: "Scan 192.168.1.1 for open ports"

LLM Response:
{
    "module_type": "auxiliary",
    "module_path": "scanner/portscan/tcp",
    "options": {"RHOSTS": "192.168.1.1", "PORTS": "1-1000"},
    "explanation": "TCP port scanner to identify open ports"
}

Execute this module? (y/n): y
[*] Executing auxiliary/scanner/portscan/tcp...
[+] Module started as job 1
```

**Quick Scan Target:**
- Runs multiple scanners automatically:
  - TCP port scan (common ports)
  - SMB version scanner
  - SSH version scanner

**Exploit Suggester:**
- Input target information (OS, services, versions)
- LLM suggests relevant exploits with:
  - Module paths
  - CVE numbers
  - Success likelihood
  - Descriptions

**Post-Exploitation Helper:**
- Input current access level
- LLM provides structured plan:
  - Privilege escalation techniques
  - Persistence mechanisms
  - Credential harvesting
  - Lateral movement options
  - Relevant post modules

---

#### 4. Added Agent Hal to Main Menu

**Updated Main Menu:**
```
  Main Menu
  ──────────────────────────────────────────────────

  [1]  Defense      - Defensive security tools
  [2]  Offense      - Penetration testing
  [3]  Counter      - Counter-intelligence
  [4]  Analyze      - Analysis & forensics
  [5]  OSINT        - Open source intelligence
  [6]  Simulate     - Attack simulation

  [7]  Agent Hal    - AI-powered security automation

  [99] Settings
  [98] Exit
```

---

### Files Created

| File | Lines | Purpose |
|------|-------|---------|
| modules/agent_hal.py | ~650 | Agent Hal AI automation module |

---

### Files Modified

| File | Changes |
|------|---------|
| core/menu.py | Added Agent Hal to main menu (option 7), added `run_agent_hal()` method |

---

### Key Methods in agent_hal.py

**MITM Detection:**
| Method | Purpose |
|--------|---------|
| `full_mitm_scan()` | Run all MITM checks |
| `_check_arp_spoofing()` | Detect duplicate MACs |
| `_check_dns_spoofing()` | Compare DNS resolution |
| `_check_ssl_stripping()` | Test HTTPS connections |
| `_check_rogue_dhcp()` | Check DHCP servers |
| `_check_gateway()` | Verify gateway integrity |
| `continuous_monitoring()` | Real-time ARP monitoring |

**MSF Automation:**
| Method | Purpose |
|--------|---------|
| `natural_language_msf()` | Process NL requests via LLM |
| `_execute_msf_module()` | Execute MSF module from LLM recommendation |
| `quick_scan_target()` | Run common scanners on target |
| `exploit_suggester()` | LLM-powered exploit recommendations |
| `post_exploitation_helper()` | LLM-powered post-exploitation guidance |

---

### LLM System Prompts

**For MSF Module Selection:**
```
You are a Metasploit expert assistant. Your job is to translate
user requests into specific Metasploit module recommendations.

Format response as JSON:
{
    "module_type": "auxiliary|exploit|post",
    "module_path": "full/module/path",
    "options": {"RHOSTS": "value"},
    "explanation": "Brief description"
}
```

**For Exploit Suggestion:**
```
You are a penetration testing expert. Based on target information,
suggest relevant Metasploit exploits with:
- Module path
- CVE (if applicable)
- Success likelihood
- Brief description
```

---

### Notes

- Agent Hal integrates with existing LLM (`core/llm.py`) and MSF (`core/msf.py`) modules
- MITM detection works without external dependencies (uses standard Linux tools)
- MSF automation requires msfrpcd running and configured in settings
- LLM model must be loaded for AI features (loads automatically on first use)
- Continuous monitoring can be stopped with Ctrl+C

---

---

## Session 5 - 2026-01-19 - Username Scanner Improvements

### User Request
> we need to improve the username search. we are still getting a lot of false positives and missing alot of sites that should be a positive. Lets look at how a few differnt apps work, https://github.com/snooppr/snoop, https://github.com/OSINTI4L/cupidcr4wl

---

### Research Conducted

Analyzed detection methods from two OSINT tools:

**Snoop:**
- 4 error types: `message`, `status_code`, `response_url`, `redirection`
- Username validation (special chars, phone patterns, email extraction)
- Retry logic with alternate headers
- Exclusion regex patterns per site

**CupidCr4wl:**
- Dual pattern matching: `check_text` (user exists) + `not_found_text` (user doesn't exist)
- Three-state results: found (green), not found (red), possible (yellow)
- Detection logic:
  - If status 200 + check_text matches → Account found
  - If status 200 + not_found_text matches → No account
  - If status 200 + no matches → Possible account

---

### Work Completed

#### 1. CupidCr4wl-Style Detection Algorithm (modules/recon.py)

Rewrote `_check_site()` method with cleaner detection logic:

```python
# Detection priority:
# 1. If not_found_text matched → NOT FOUND (return None)
# 2. If check_text matched + username in content → FOUND (good)
# 3. If check_text matched only → POSSIBLE (maybe)
# 4. If username in content + status 200 → POSSIBLE (maybe)
# 5. Nothing matched → NOT FOUND (return None)
```

**Confidence Calculation:**
```python
if check_matched and (username_in_content or username_in_title):
    status = 'good'
    rate = min(100, 60 + (found_indicators * 10))
elif check_matched:
    status = 'maybe'
    rate = 50 + (found_indicators * 10)
```

---

#### 2. Username Validation

Added `validate_username()` method:

```python
@staticmethod
def validate_username(username: str) -> Tuple[bool, str]:
    # Checks:
    # - Not empty
    # - Min length 2, max length 100
    # - No invalid characters: <>{}[]|\^~`
    # - Email detection (offers to extract username part)
```

---

#### 3. Site-Specific Detection Patterns

Added `SITE_PATTERNS` dictionary with tailored patterns for 20+ platforms:

```python
SITE_PATTERNS = {
    'reddit.com': {
        'check_text': ['karma', 'cake day', 'trophy-case'],
        'not_found_text': ['sorry, nobody on reddit goes by that name'],
    },
    'github.com': {
        'check_text': ['contributions', 'repositories', 'gist-summary'],
        'not_found_text': ['not found'],
    },
    'chaturbate.com': {
        'check_text': ['broadcaster_gender', 'room_status', 'bio', 'following'],
        'not_found_text': ['http 404', 'page not found', 'bio page not available'],
    },
    # ... 20+ more platforms
}
```

**Categories Covered:**
- Social: Reddit, Twitter/X, Instagram, TikTok, Telegram, Tumblr
- Adult/Cam: Chaturbate, OnlyFans, Fansly, Pornhub, XVideos, Stripchat
- Art: DeviantArt, ArtStation, Fur Affinity, e621
- Gaming: Twitch, Steam
- Dating: FetLife
- Other: GitHub, YouTube, Wattpad

---

#### 4. User-Agent Rotation

Added 6 different User-Agents for rotation:

```python
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15 Version/17.2',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0',
]
```

---

#### 5. Fixed Gzip Encoding Bug

**Issue:** Responses were returning garbled binary data.

**Cause:** `Accept-Encoding: gzip, deflate` header caused servers to send compressed responses that urllib doesn't auto-decompress.

**Fix:** Removed the Accept-Encoding header:
```python
# Before (broken):
'Accept-Encoding': 'gzip, deflate',

# After (fixed):
# Header removed - get uncompressed content
```

---

#### 6. Database Pattern Updates

Updated detection patterns via SQL for major sites:

```sql
-- Reddit
UPDATE sites SET error_string = 'sorry, nobody on reddit goes by that name',
                 match_string = 'karma' WHERE url_template LIKE '%reddit.com/%';

-- Chaturbate
UPDATE sites SET error_string = 'HTTP 404 - Page Not Found',
                 match_string = 'live on Chaturbate!' WHERE url_template LIKE '%chaturbate.com/%';

-- GitHub, OnlyFans, XHamster, Pornhub, etc.
```

---

#### 7. Fixed Chaturbate "Offline" False Positive

**Issue:** Offline Chaturbate streamers were being marked as NOT FOUND.

**Cause:** `"offline"` was in the `not_found_text` patterns, but offline streamers still have valid profile pages.

**Fix:** Removed "offline" from not_found patterns:
```python
# Before (broken):
'not_found_text': ['offline', 'room is currently offline', 'bio page not available'],

# After (fixed):
'not_found_text': ['http 404', 'page not found', 'bio page not available'],
```

---

### Test Results

**Quick Scan (100 sites, username: `torvalds`):**
```
Sites checked:    100
Time elapsed:     20.4 seconds
Found (good):     6
Possible (maybe): 16
Restricted:       7
Filtered (WAF):   2
```

**Adult Sites Scan (50 sites, username: `admin`):**
```
Sites checked:    50
Time elapsed:     14.7 seconds
Found (good):     9
Possible (maybe): 8
```

**Chaturbate Verification:**
```
fudnucker                -> good (100%)  ✓ Correctly detected
totally_fake_user_xyz    -> NOT FOUND    ✓ Correctly rejected
```

**GitHub/Reddit Verification:**
```
torvalds (GitHub)        -> good (100%)  ✓ 3 patterns matched
spez (Reddit)            -> good (100%)  ✓ 3 patterns matched
```

---

### Files Modified

| File | Changes |
|------|---------|
| modules/recon.py | Rewrote detection algorithm, added username validation, site patterns, UA rotation, fixed gzip bug |
| data/sites/dh_sites.db | Updated detection patterns for major sites |

---

### Key Improvements Summary

| Feature | Before | After |
|---------|--------|-------|
| Detection method | Rate-based scoring | CupidCr4wl pattern matching |
| False positives | High | Significantly reduced |
| Chaturbate offline users | NOT FOUND | Correctly detected |
| Username validation | None | Length, chars, email detection |
| User-Agent | Single static | 6 rotating agents |
| Gzip handling | Broken (garbled) | Fixed (uncompressed) |

---

### Notes

- Detection now prioritizes `not_found_text` matches (if found, user definitely doesn't exist)
- Site-specific patterns override generic fallback patterns
- "offline" status on cam sites does NOT mean the profile doesn't exist
- Removed gzip Accept-Encoding to ensure readable responses
- Username validation prevents wasted requests on invalid inputs

---

---

## Session 9 - 2026-02-03: MSF Module Search Fix

### User Report

> The issue we are having now is the metasploit modules do not show up in the offense menu, which means they are probably broken everywhere since the metasploit interface should be handling everything

---

### Investigation

#### Initial Diagnosis

1. Verified Python module `modules/msf.py` loads correctly with `CATEGORY = "offense"`
2. Module appears in offense menu correctly
3. Issue was with actual Metasploit module searches returning empty or malformed results

#### Root Cause Discovery

Tested MSF interface search:

```python
results = msf.search_modules('smb')
print(results[:5])
```

Output showed dictionaries with **bytes keys**:
```python
{b'type': 'auxiliary', b'name': '...', b'fullname': 'auxiliary/admin/mssql/...'}
```

The code was trying to access `r.get('fullname')` but the actual key was `b'fullname'`, causing `None` returns.

---

### Work Completed

#### 1. Added Recursive Bytes Decoding (core/msf.py)

**Problem:** Previous fix only decoded top-level dict. MSF searches return list of dicts where inner dicts still had bytes keys.

**Solution:** Added `_decode_bytes()` method to `MetasploitRPC` class:

```python
def _decode_bytes(self, obj):
    """Recursively decode bytes to strings in msgpack responses.

    Args:
        obj: Object to decode (dict, list, bytes, or other).

    Returns:
        Decoded object with all bytes converted to strings.
    """
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif isinstance(obj, dict):
        return {
            self._decode_bytes(k): self._decode_bytes(v)
            for k, v in obj.items()
        }
    elif isinstance(obj, list):
        return [self._decode_bytes(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(self._decode_bytes(item) for item in obj)
    else:
        return obj
```

**Updated `_request()` method:**
```python
response_data = response.read()
result = msgpack.unpackb(response_data, raw=False, strict_map_key=False)

# Recursively normalize bytes to strings throughout the response
result = self._decode_bytes(result)
```

---

#### 2. Fixed list_modules() API Method (core/msf.py)

**Problem:** `list_modules()` was calling `module.list` which doesn't exist in MSF RPC API.

**Error observed:**
```
MSFError: MSF error: Unknown API Call: '"rpc_list"'
```

**Solution:** Changed to use correct API method names:

```python
def list_modules(self, module_type: str = None) -> List[str]:
    # Map module types to their API method names
    # The MSF RPC API uses module.exploits, module.auxiliary, etc.
    type_to_method = {
        "exploit": "module.exploits",
        "auxiliary": "module.auxiliary",
        "post": "module.post",
        "payload": "module.payloads",
        "encoder": "module.encoders",
        "nop": "module.nops",
    }

    if module_type:
        method = type_to_method.get(module_type)
        if not method:
            raise MSFError(f"Unknown module type: {module_type}")
        result = self._request(method)
        return result.get("modules", [])
    else:
        # Get all module types
        all_modules = []
        for mtype in ["exploit", "auxiliary", "post", "payload"]:
            try:
                method = type_to_method.get(mtype)
                result = self._request(method)
                modules = result.get("modules", [])
                all_modules.extend([f"{mtype}/{m}" for m in modules])
            except:
                pass
        return all_modules
```

---

#### 3. Updated Agent Hal to Use Centralized Interface (modules/agent_hal.py)

**Problem:** Agent Hal was bypassing `core/msf_interface.py` and creating its own `MetasploitRPC` instance directly:

```python
# OLD - Wrong approach
from core.msf import MetasploitRPC, get_msf_manager
manager = get_msf_manager()
self.msf = MetasploitRPC(
    host=manager.host,  # AttributeError: no such attribute
    ...
)
```

**Solution:** Updated to use the centralized interface:

```python
def _ensure_msf_connected(self) -> bool:
    """Ensure MSF RPC is connected via the centralized interface."""
    if self.msf is None:
        try:
            from core.msf_interface import get_msf_interface
            self.msf = get_msf_interface()
        except ImportError:
            self.print_status("MSF interface not available", "error")
            return False

    # Use the interface's connection management
    connected, msg = self.msf.ensure_connected(auto_prompt=False)
    if connected:
        self.msf_connected = True
        self.print_status("Connected to MSF RPC", "success")
        return True
    else:
        self.print_status(f"Failed to connect to MSF: {msg}", "error")
        return False
```

---

#### 4. Updated Agent Hal Module Execution Methods

**Problem:** Agent Hal was calling `execute_module(type, path, options)` which doesn't exist on `MSFInterface`.

**Solution:** Updated `_execute_msf_module()` to use `run_module()`:

```python
def _execute_msf_module(self, module_info: Dict):
    """Execute an MSF module based on LLM recommendation."""
    try:
        module_type = module_info.get('module_type', 'auxiliary')
        module_path = module_info.get('module_path', '')
        options = module_info.get('options', {})

        # Ensure full module path format (type/path)
        if not module_path.startswith(module_type + '/'):
            full_path = f"{module_type}/{module_path}"
        else:
            full_path = module_path

        print(f"\n{Colors.CYAN}[*] Executing {full_path}...{Colors.RESET}")

        # Use the interface's run_module method
        result = self.msf.run_module(full_path, options)

        if result.success:
            print(f"{Colors.GREEN}[+] Module executed successfully{Colors.RESET}")
            if result.findings:
                print(f"\n{Colors.CYAN}Findings:{Colors.RESET}")
                for finding in result.findings[:10]:
                    print(f"  {finding}")
        else:
            print(f"{Colors.YELLOW}[!] {result.get_summary()}{Colors.RESET}")

    except Exception as e:
        self.print_status(f"Execution failed: {e}", "error")
```

Updated `quick_scan_target()` similarly to use `run_module()`.

---

### Files Modified

| File | Lines Changed | Description |
|------|---------------|-------------|
| core/msf.py | +25, -8 | Added `_decode_bytes()`, fixed `list_modules()` |
| modules/agent_hal.py | +30, -25 | Switched to interface, updated method calls |

---

### Verification Results

**Module Search Test:**
```
Search (eternalblue): 5 results

[auxiliary] (2)
  auxiliary/admin/smb/ms17_010_command
  auxiliary/scanner/smb/smb_ms17_010

[exploit] (3)
  exploit/windows/smb/ms17_010_eternalblue
  exploit/windows/smb/ms17_010_psexec
  exploit/windows/smb/smb_doublepulsar_rce
```

**Module Listing Test:**
```
List exploits: 2604 modules
List auxiliary: 1322 modules
Module info (smb_version): SMB Version Detection ✓
Module options: 56 options ✓
```

**Full Application Test:**
```
Main Menu > [2] Offense > [1] msf > [1] Search Modules > eternalblue
Found 5 module(s) ✓
```

---

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface                          │
├─────────────────────────────────────────────────────────────┤
│  modules/msf.py    modules/agent_hal.py    modules/counter.py │
│         │                   │                     │          │
│         └───────────────────┼─────────────────────┘          │
│                             ▼                                │
│              ┌──────────────────────────┐                    │
│              │  core/msf_interface.py   │  ← Single point    │
│              │  get_msf_interface()     │    of contact      │
│              └──────────────────────────┘                    │
│                             │                                │
│                             ▼                                │
│              ┌──────────────────────────┐                    │
│              │     core/msf.py          │                    │
│              │  MetasploitRPC class     │  ← RPC protocol    │
│              │  MSFManager class        │    implementation  │
│              └──────────────────────────┘                    │
│                             │                                │
│                             ▼                                │
│              ┌──────────────────────────┐                    │
│              │       msfrpcd            │  ← External        │
│              │  (Metasploit Framework)  │    service         │
│              └──────────────────────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

All MSF operations now flow through `core/msf_interface.py`, ensuring fixes apply everywhere.

---

## Session 10 - 2026-02-03: Offense Menu Overhaul

### Overview

Complete rewrite of the MSF/Offense menu interface with new foundation libraries for option descriptions and module metadata. This session was split into two phases:

- **Phase 1a**: MSF Settings Term Bank (`core/msf_terms.py`)
- **Phase 1b**: MSF Module Library (`core/msf_modules.py`)
- **Phase 2**: Offense Menu Rewrite (`modules/msf.py` v2.0)

---

### Phase 1a: MSF Settings Term Bank

Created `core/msf_terms.py` - centralized definitions for all MSF options.

#### Structure

Each setting contains:
```python
'RHOSTS': {
    'description': 'The target host(s) to scan or exploit...',
    'input_type': 'host_range',  # ip, port, string, boolean, path, etc.
    'examples': ['192.168.1.1', '192.168.1.0/24'],
    'default': None,
    'aliases': ['RHOST', 'TARGET'],
    'category': 'target',
    'required': True,
    'notes': 'For single-target exploits, use RHOST...',
}
```

#### Categories (14 total)

| Category | Settings |
|----------|----------|
| target | RHOSTS, RHOST, RPORT, TARGETURI, VHOST, DOMAIN |
| local | LHOST, LPORT, SRVHOST, SRVPORT |
| auth | SMBUser, SMBPass, SMBDomain, HttpUsername, HttpPassword, SSH_USER, SSH_PASS, SSH_KEYFILE_B64 |
| payload | PAYLOAD, ENCODER, EXITFUNC, PrependMigrate, AutoLoadStdapi |
| connection | SSL, VHOST, Proxies, TIMEOUT, ConnectTimeout |
| scan | THREADS, PORTS, CONCURRENCY, ShowProgress |
| session | SESSION, TARGET |
| database | DATABASE, DB_ALL_CREDS, DB_ALL_HOSTS |
| output | OUTPUT, VERBOSE, LogLevel |
| smb | SMBUser, SMBPass, SMBDomain, SMBShare |
| http | TARGETURI, VHOST, HttpUsername, HttpPassword, SSL |
| ssh | SSH_USER, SSH_PASS, SSH_KEYFILE_B64 |
| execution | CMDSTAGER, WfsDelay, DisablePayloadHandler |
| file | FILENAME, RPATH, LPATH |

#### API Functions

```python
from core.msf_terms import (
    get_setting_info,       # Get full setting metadata
    get_setting_description, # Get just the description
    get_setting_prompt,     # Generate input prompt with default
    format_setting_help,    # Formatted help block for display
    get_settings_by_category, # Get all settings in a category
    get_common_settings,    # List of commonly used settings
    validate_setting_value, # Validate input value
    list_all_settings,      # List all setting names
    list_categories,        # List all categories
)
```

#### Validation Functions

```python
def validate_setting_value(name: str, value: str) -> tuple:
    """Returns (is_valid, message)"""
    # Validates based on input_type:
    # - host: IP address or hostname
    # - port: 1-65535
    # - host_range: IP, CIDR, or range
    # - boolean: true/false/yes/no
    # - path: file path exists
```

---

### Phase 1b: MSF Module Library

Created `core/msf_modules.py` - descriptions and metadata for common MSF modules.

#### Structure

Each module contains:
```python
'auxiliary/scanner/smb/smb_version': {
    'name': 'SMB Version Scanner',
    'description': 'Scans for SMB servers and identifies the operating system...',
    'author': ['hdm'],
    'cve': None,
    'platforms': ['windows'],
    'arch': None,
    'reliability': 'excellent',  # excellent/great/good/normal/average/low
    'options': [
        {'name': 'RHOSTS', 'required': True, 'desc': 'Target IP(s) or range'},
        {'name': 'THREADS', 'required': False, 'desc': 'Concurrent threads'},
    ],
    'tags': ['smb', 'scanner', 'enumeration', 'windows'],
    'notes': 'Safe to run - passive fingerprinting...',
}
```

#### Module Count by Type

| Type | Count | Examples |
|------|-------|----------|
| Scanners (auxiliary/scanner/*) | 25 | smb_version, ssh_version, portscan/tcp |
| Exploits | 12 | ms17_010_eternalblue, bluekeep, proftpd_backdoor |
| Post-exploitation | 4 | hashdump, local_exploit_suggester |
| Payloads | 4 | meterpreter/reverse_tcp, shell/reverse_tcp |

#### API Functions

```python
from core.msf_modules import (
    get_module_info,        # Get full module metadata
    get_module_description, # Get just the description
    search_modules,         # Search by name, description, tags
    get_modules_by_type,    # Get by type (exploit, auxiliary, etc.)
    get_modules_by_tag,     # Get by tag (smb, scanner, etc.)
    get_modules_by_platform, # Get by platform (windows, linux)
    get_module_options,     # Get module's key options
    format_module_help,     # Formatted help for display
    list_all_modules,       # List all module paths
    get_module_count,       # Count by type
)
```

---

### Phase 2: Offense Menu Rewrite

Completely rewrote `modules/msf.py` from v1.1 to v2.0.

#### New Features

**1. Global Target Settings**

Pre-configure target settings before browsing modules:
```python
self.global_settings = {
    'RHOSTS': '',   # Target IP/range
    'LHOST': '',    # Attacker IP (for reverse shells)
    'LPORT': '4444', # Listener port
}
```

Features:
- Settings persist across module selections
- Auto-filled when selecting modules
- Domain-to-IP resolution with confirmation
- Auto-detect LHOST from network interface

**2. Module Browser**

Category-based navigation:
```python
MODULE_CATEGORIES = {
    'scanners': {'types': ['auxiliary/scanner'], 'color': Colors.CYAN},
    'exploits': {'types': ['exploit'], 'color': Colors.RED},
    'post': {'types': ['post'], 'color': Colors.MAGENTA},
    'payloads': {'types': ['payload'], 'color': Colors.YELLOW},
    'auxiliary': {'types': ['auxiliary'], 'color': Colors.GREEN},
}
```

Features:
- Pagination (20 modules per page)
- Two-column display for compact viewing
- Combines library modules + live MSF modules
- Navigation: [N]ext, [P]revious, number to select

**3. Enhanced Module Details**

Shows rich information from module library:
- Full description with word wrapping
- Author, CVE, reliability rating
- Usage notes and warnings
- Option to fetch live info from MSF

**4. Streamlined Workflow**

```
Set Target → Browse/Search → Select Module → Configure → Run

[1] Set Target     → RHOSTS, LHOST, LPORT, domain resolution
[2] Module Browser → Category → Page → Select → Details → Use
[3] Search         → Query → Results → Select → Details → Use
[4] Current Module → View options, set values, run
[5] Run Module     → Confirm and execute
```

**5. Integration Points**

```python
# Uses term bank for help text
from core.msf_terms import get_setting_info, format_setting_help, validate_setting_value

# Uses module library for descriptions
from core.msf_modules import format_module_help, search_modules as library_search_modules, MSF_MODULES
```

#### Key Methods

| Method | Purpose |
|--------|---------|
| `show_target_settings()` | Configure RHOSTS, LHOST, LPORT |
| `_set_rhosts()` | Set target with domain resolution |
| `_auto_detect_lhost()` | Get local IP via socket |
| `_resolve_hostname()` | DNS lookup utility |
| `show_module_browser()` | Category selection menu |
| `_browse_category()` | Paginated module list |
| `_show_module_details()` | Module info display |
| `_select_module()` | Load module and apply global settings |
| `search_modules()` | Combined library + MSF search |
| `show_current_module()` | View/configure selected module |
| `_show_all_options()` | Full options list |
| `_set_specific_option()` | Set option with term bank help |

#### Auto-Fill Logic

When selecting a module:
```python
# Apply global settings to module options
if self.global_settings['RHOSTS'] and 'RHOSTS' in options:
    self.module_options['RHOSTS'] = self.global_settings['RHOSTS']
if self.global_settings['RHOSTS'] and 'RHOST' in options:
    self.module_options['RHOST'] = self.global_settings['RHOSTS']
if self.global_settings['LHOST'] and 'LHOST' in options:
    self.module_options['LHOST'] = self.global_settings['LHOST']
if self.global_settings['LPORT'] and 'LPORT' in options:
    self.module_options['LPORT'] = self.global_settings['LPORT']
```

#### Domain Resolution

```python
def resolve_hostname(self, hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        socket.inet_aton(hostname)  # Already an IP
        return hostname
    except socket.error:
        pass
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
```

---

### Files Created/Modified

| File | Action | Lines | Description |
|------|--------|-------|-------------|
| `core/msf_terms.py` | Created | 1,130 | MSF settings term bank |
| `core/msf_modules.py` | Created | 1,200 | MSF module library |
| `modules/msf.py` | Rewritten | 1,232 | Enhanced offense menu v2.0 |
| `devjournal.md` | Updated | +130 | Session 10 summary |
| `DEVLOG.md` | Updated | +250 | Technical details |

---

### Menu Screenshots

**Main Menu:**
```
Metasploit Framework
──────────────────────────────────────────
  Status: Connected
  Target: 192.168.1.100
  LHOST:  192.168.1.50
  Module: auxiliary/scanner/smb/smb_version

  [1] Set Target        - Configure target & listener settings
  [2] Module Browser    - Browse modules by category
  [3] Search Modules    - Search all modules

  [4] Current Module    - View/configure selected module
  [5] Run Module        - Execute current module

  [6] Sessions          - View and interact with sessions
  [7] Jobs              - View running background jobs

  [8] MSF Console       - Direct console access
  [9] Quick Scan        - Common scanners

  [0] Back to Main Menu
```

**Target Configuration:**
```
Target Configuration
  Set target and listener options before selecting modules
──────────────────────────────────────────

  [1] RHOSTS  = 192.168.1.100
      The target host(s) to scan or exploit. Can be a single IP...

  [2] LHOST   = (not set)
      Your IP address that the target will connect back to...

  [3] LPORT   = 4444
      The port your machine listens on for incoming connections...

  [A] Auto-detect LHOST
  [R] Resolve hostname to IP

  [0] Back
```

**Module Browser (Scanners):**
```
Scanners
  Page 1 of 2 (25 modules)
──────────────────────────────────────────

  [ 1] SMB Version Scanner      [ 2] SMB Share Enumeration
  [ 3] SMB User Enumeration     [ 4] MS17-010 Vulnerability...
  [ 5] TCP Port Scanner         [ 6] SSH Version Scanner
  [ 7] SSH Login Brute Force    [ 8] HTTP Version Scanner
  [ 9] HTTP Directory Scanner   [10] HTTP Title Scanner
  [11] FTP Version Scanner      [12] FTP Anonymous Login

  [N] Next page   [P] Previous   [0] Back
```

---

### Architecture Benefits

1. **Centralized Knowledge** - Option descriptions and module info in one place
2. **Offline Documentation** - Help text available without MSF connection
3. **Consistent UX** - Same descriptions everywhere in the app
4. **Extensible** - Easy to add new settings and modules
5. **AI-Friendly** - Structured data for LLM context injection
6. **Validation** - Input validation with helpful error messages
7. **Auto-Fill** - Global settings reduce repetitive input

---

### Future Integration Points

The term bank and module library can be used by:
- `modules/agent_hal.py` - AI can reference descriptions for better understanding
- `core/pentest_pipeline.py` - Pipeline can use module metadata for task generation
- Report generation - Include module details in reports
- LLM prompts - Inject relevant option descriptions into context

---

## Session 11 - 2026-02-14: Nmap Scanner & Scan Monitor

### Overview

Added two new tools to the AUTARCH framework:
1. **Nmap Scanner** integrated into the OSINT/Recon module
2. **Scan Monitor** in the Defense module for detecting incoming port scans and brute-force attempts

---

### 1. Nmap Scanner (`modules/recon.py`)

#### Menu Integration

Added `[X] Nmap Scanner` under the Tools section of the OSINT menu, with handler in `run()` and press-enter-to-continue support.

#### New Methods

**`_check_nmap() -> bool`**
- Validates nmap availability via `which nmap`

**`nmap_scanner()`**
- Submenu loop with 9 scan presets plus back option:

```
Nmap Scanner
──────────────────────────────────────────────────
  [1] Top 100 Ports       - Fastest common port scan
  [2] Quick Scan           - Default top 1000 ports
  [3] Full TCP Scan        - All 65535 ports (slow)
  [4] Stealth SYN Scan     - Half-open scan (needs root)
  [5] Service Detection    - Detect service versions (-sV)
  [6] OS Detection         - OS fingerprinting (needs root)
  [7] Vulnerability Scan   - NSE vuln scripts
  [8] UDP Scan             - Top 100 UDP ports (slow, needs root)
  [9] Custom Scan          - Enter your own nmap flags
  [0] Back
```

- Prompts for target IP/hostname per scan
- Custom scan option [9] allows user-provided nmap flags

**Nmap Flag Presets:**

| # | Flags | Description |
|---|-------|-------------|
| 1 | `--top-ports 100 -T4` | Top 100 ports |
| 2 | `-T4` | Quick scan (top 1000) |
| 3 | `-p- -T4` | Full TCP (all 65535) |
| 4 | `-sS -T4` | Stealth SYN |
| 5 | `-sV -T4` | Service detection |
| 6 | `-O -T4` | OS fingerprinting |
| 7 | `--script vuln -T4` | Vulnerability scan |
| 8 | `-sU --top-ports 100 -T4` | UDP scan |
| 9 | user-provided | Custom |

**`_run_nmap(target, flags, description, timeout=300)`**
- Validates non-empty target
- Builds command: `nmap {flags} {target}`
- Uses `subprocess.Popen` with `stdout=PIPE, stderr=STDOUT` for live streaming
- Color-coded output:
  - Green: lines containing "open" (open ports)
  - Dim: lines containing "closed" or "filtered"
  - Cyan bold: "Nmap scan report" header lines
- Prints summary of all open ports found after scan completes
- Offers to save full output to `{target}_nmap.txt`

#### Test Results

Tested Top 100 scan on `127.0.0.1`:
```
Scan: Top 100 Ports
Command: nmap --top-ports 100 -T4 127.0.0.1

Nmap scan report for localhost (127.0.0.1)
  22/tcp   open  ssh
  53/tcp   open  domain
  80/tcp   open  http
  139/tcp  open  netbios-ssn
  443/tcp  open  https
  445/tcp  open  microsoft-ds
  631/tcp  open  ipp
  8000/tcp open  http-alt
  8080/tcp open  http-proxy
  8888/tcp open  sun-answerbook

Open ports found: 10
```

Scan completed in 0.05 seconds. Color coding, summary, and save prompt all working correctly.

---

### 2. Scan Monitor (`modules/defender.py`)

#### Menu Integration

Added `[8] Scan Monitor - Detect & counter incoming scans` to the Defense menu, with handler in `run()` and press-enter-to-continue support.

#### New Imports

Added `re`, `time`, `threading`, `datetime` to the module imports.

#### New Methods

**`scan_monitor()`**
- Setup and launch method
- Checks tcpdump availability
- Prompts for:
  - Counter-scan enable (y/n, default y)
  - Whitelist IPs (comma-separated)
- Creates `results/` directory if missing
- Calls `_monitor_with_tcpdump()`

**`_monitor_with_tcpdump(counter_scan: bool, whitelist: list)`**
- Core monitoring loop using tcpdump
- Auto-detects local IPs to skip (127.0.0.1, hostname IP, all IPs from `hostname -I`)
- Uses `sudo tcpdump` when not running as root (tcpdump requires packet capture privileges)
- SYN-only filter: `tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0`
- Parses packets via regex: `IP (\d+\.\d+\.\d+\.\d+)\.\d+ > [\d.]+\.(\d+):`
- Per-IP tracking dict with:
  - `ports`: set of unique destination ports
  - `port_counts`: dict of connection counts per port
  - `first_seen` / `last_seen` timestamps
  - `alerted_scan`: bool (one-shot alert)
  - `alerted_brute`: set of ports already alerted
- Detection thresholds:
  - **Port scan**: 10+ unique ports within 30 seconds
  - **Brute force**: 15+ connections to single port within 60 seconds
- On detection:
  - Red alert for port scans, yellow for brute force
  - Appends to `results/scan_monitor.log`
  - Launches `_counter_scan()` in daemon thread if enabled
- Prunes stale tracker entries (>120s) every 5 seconds
- Ctrl+C handler: kills tcpdump, prints summary (total packets, threats, IPs logged)

**`_counter_scan(ip, log_file)`**
- Runs `nmap --top-ports 100 -T4 -sV {ip}` with 120s timeout
- Parses open ports from output
- Prints summary: `[+] Counter-scan {ip}: N open ports (port,port,...)`
- Appends full nmap output to log file

#### Display Format

```
  Scan Monitor Active  [Ctrl+C to stop]
  ──────────────────────────────────────────────────
  Counter-scan: Enabled | Log: results/scan_monitor.log
  Whitelisted: 192.168.1.1
  Local IPs: 127.0.0.1, 192.168.1.100
  Monitoring on all interfaces...

  14:23:05 [!] PORT SCAN detected from 192.168.1.50 (23 ports in 8s)
           [*] Counter-scanning 192.168.1.50...
  14:23:18 [+] Counter-scan 192.168.1.50: 5 open ports (22,80,443,3306,8080)
  14:25:33 [!] BRUTE FORCE detected from 10.0.0.99 (42 connections to port 22 in 30s)
           [*] Counter-scanning 10.0.0.99...
```

---

### Files Modified

| File | Changes |
|------|---------|
| `modules/recon.py` | Added `[X]` menu entry, handler, `_check_nmap()`, `nmap_scanner()`, `_run_nmap()` |
| `modules/defender.py` | Added imports (`re`, `time`, `threading`, `datetime`), `[8]` menu entry, handler, `scan_monitor()`, `_monitor_with_tcpdump()`, `_counter_scan()` |

---

## Session 15 - 2026-02-15: Phase 4.8 — WireGuard VPN + Remote ADB

### Initial Request

Integrate WireGuard VPN management from `/home/snake/wg_setec/` into AUTARCH. Two purposes:
1. VPN server management — create/manage WireGuard clients from AUTARCH dashboard
2. Remote ADB for Android — phone connects via WireGuard tunnel, AUTARCH runs ADB tools remotely

Two connection methods over WireGuard tunnel:
- **ADB TCP/IP** — native ADB over network (`adb connect 10.1.0.X:5555`)
- **USB/IP** — Linux kernel protocol that exports USB devices over TCP via `vhci-hcd` module

### Source Material

`/home/snake/wg_setec/` — working Flask app (1,647 lines) with:
- `config.py` — WG paths, subnet (10.1.0.0/24), keys, ports
- `wg_manager.py` — key gen, peer add/remove, config gen, QR codes, status parsing
- `app.py` — Flask routes (dashboard, clients CRUD, settings)

### Work Completed

---

#### 1. `core/wireguard.py` — WireGuardManager (~500 lines)

Singleton manager following `core/android_protect.py` pattern.

##### Constructor
```python
self._wg_bin = find_tool('wg')
self._wg_quick = find_tool('wg-quick')
self._usbip_bin = find_tool('usbip')
self._data_dir = get_data_dir() / 'wireguard'
self._clients_file = self._data_dir / 'clients.json'
```

Config loaded from `autarch_settings.conf [wireguard]` section:
- `config_path`, `interface`, `subnet`, `server_address`, `listen_port`, `default_dns`, `default_allowed_ips`

##### Subprocess Helpers
- `_run_wg(args)` — runs `wg` binary, returns `(stdout, stderr, rc)`
- `_run_wg_sudo(args)` — runs `sudo wg ...` for privileged commands
- `_run_cmd(cmd)` — arbitrary subprocess wrapper
- `_run_adb(args)` — runs adb binary via `find_tool('adb')`

##### Server Management
- `is_available()` — checks if `wg` binary exists
- `get_server_status()` — parses `wg show wg0` for interface info, peer count
- `start_interface()` / `stop_interface()` / `restart_interface()` — via `sudo wg-quick up/down`

##### Key Generation (adapted from wg_setec)
- `generate_keypair()` — `wg genkey` piped to `wg pubkey`, returns `(private, public)`
- `generate_preshared_key()` — `wg genpsk`

##### Client CRUD
- `get_next_ip()` — increments last octet tracked in `data/wireguard/last_ip`
- `create_client(name, dns, allowed_ips)` — generates keys, assigns IP, adds to live WG + config file + JSON store
- `delete_client(client_id)` — removes from live WG + config + JSON
- `toggle_client(client_id, enabled)` — enable/disable peer (add/remove from live WG)
- `get_all_clients()` / `get_client(id)` — JSON store lookups
- `get_peer_status()` — parses `wg show` for per-peer handshake, transfer, endpoint

##### Config File Manipulation
- `_add_peer_to_wg(pubkey, psk, ip)` — `sudo wg set` with preshared-key via `/dev/stdin`
- `_remove_peer_from_wg(pubkey)` — `sudo wg set ... remove`
- `_append_peer_to_config(...)` — appends `[Peer]` block via `sudo tee -a`
- `_remove_peer_from_config(pubkey)` — reads via `sudo cat`, removes block, writes via `sudo tee`
- `import_existing_peers()` — parses wg0.conf `[Peer]` blocks + `# Client:` comments, imports to JSON

##### Client Config Generation
- `generate_client_config(client)` — builds `.conf` with `[Interface]` + `[Peer]` sections
- `generate_qr_code(config_text)` — QR code PNG bytes via `qrcode` + `Pillow`

##### Remote ADB — TCP/IP
- `adb_connect(client_ip)` — `adb connect {ip}:5555`
- `adb_disconnect(client_ip)` — `adb disconnect {ip}:5555`
- `get_adb_remote_devices()` — filters `adb devices -l` for WG subnet IPs (10.1.0.*)
- `auto_connect_peers()` — scans active WG peers (handshake < 3min), tries ADB connect on each

##### Remote ADB — USB/IP
- `usbip_available()` — checks for `usbip` binary
- `check_usbip_modules()` — `lsmod | grep vhci_hcd`
- `load_usbip_modules()` — `sudo modprobe vhci-hcd`
- `usbip_list_remote(ip)` — `sudo usbip list -r {ip}`, parses bus IDs and descriptions
- `usbip_attach(ip, busid)` — `sudo usbip attach -r {ip} -b {busid}`
- `usbip_detach(port)` — `sudo usbip detach -p {port}`
- `usbip_port_status()` — `sudo usbip port`, parses attached virtual USB devices
- `get_usbip_status()` — combined: available + modules loaded + active imports + port list

##### UPnP Integration
- `refresh_upnp_mapping()` — reuses `core/upnp.get_upnp_manager()` to map port 51820/UDP

##### Singleton
```python
_manager = None
def get_wireguard_manager(config=None):
    # Loads config from autarch_settings.conf [wireguard] section
    # Falls back to sensible defaults if section missing
```

---

#### 2. `modules/wireguard_manager.py` — CLI Module (~330 lines)

Standard AUTARCH module: `CATEGORY = "defense"`, `run()` entry point.

Menu with 18 numbered actions across 5 groups:
- Server (1-4): status, start, stop, restart
- Clients (10-15): list, create, view detail, delete, toggle, import
- Remote ADB (20-23): TCP/IP connect/disconnect, auto-connect, list devices
- USB/IP (30-35): status, load modules, list remote, attach, detach, list ports
- Config (40-42): generate config, show QR (terminal ASCII), refresh UPnP

Helper methods:
- `_pick_client()` — numbered selection from client list
- `_pick_client_ip()` — input IP directly or select by number

---

#### 3. `web/routes/wireguard.py` — Flask Blueprint (~200 lines)

Blueprint: `wireguard_bp`, prefix `/wireguard/`, all routes `@login_required`.

25 routes across 6 groups:

| Group | Routes | Methods |
|-------|--------|---------|
| Page | `/` | GET → render wireguard.html |
| Server | `/server/status`, `start`, `stop`, `restart` | POST |
| Clients | `/clients/list`, `create`, `<id>`, `<id>/toggle`, `<id>/delete`, `<id>/config`, `<id>/download`, `<id>/qr`, `import` | POST/GET |
| ADB | `/adb/connect`, `disconnect`, `auto-connect`, `devices` | POST |
| USB/IP | `/usbip/status`, `load-modules`, `list-remote`, `attach`, `detach`, `ports` | POST |
| UPnP | `/upnp/refresh` | POST |

Notable: `/clients/<id>/download` returns `.conf` file as attachment, `/clients/<id>/qr` returns PNG image.

---

#### 4. `web/templates/wireguard.html` — Web UI (~470 lines)

4-tab layout matching `android_protect.html` patterns.

**Dashboard tab:**
- Status cards: interface running/stopped, endpoint, client count, USB/IP status
- Server controls: Start/Stop/Restart buttons
- Server info table: interface, status, public key, endpoint, listen port, peer count
- Peers table: name, IP, status dot (online/idle/offline), handshake, RX/TX

**Clients tab:**
- Create form: name, DNS (optional), allowed IPs (optional)
- Clients table: name, IP, status, handshake, transfer, action buttons (View/Toggle/Delete)
- Client detail section: full info table + Show Config/Download .conf/QR Code buttons
- Config display with copy-to-clipboard

**Remote ADB tab:**
- TCP/IP section: client IP dropdown, Connect/Disconnect/Auto-Connect buttons
- Connected ADB devices table: serial, state, model
- USB/IP section: module status cards, Load Modules button
- Remote USB devices: client IP dropdown + List Devices, results table with Attach buttons
- Attached ports table with Detach buttons

**Settings tab:**
- Binary availability table (wg, usbip, vhci-hcd)
- Import Existing Peers button
- Refresh UPnP Mapping button

JS functions (~25): `wgPost()` helper, then `wgServerStatus()`, `wgStartInterface()`, `wgRefreshPeers()`, `wgCreateClient()`, `wgViewClient()`, `wgDeleteClient()`, `wgAdbConnect()`, `wgUsbipAttach()`, etc.

---

#### 5. Integration Changes

**`web/app.py`:**
```python
from web.routes.wireguard import wireguard_bp
app.register_blueprint(wireguard_bp)
```

**`web/templates/base.html`:**
Added in System nav section after UPnP:
```html
<li><a href="{{ url_for('wireguard.index') }}" ...>WireGuard</a></li>
```

**`autarch_settings.conf`:**
```ini
[wireguard]
enabled = true
config_path = /etc/wireguard/wg0.conf
interface = wg0
subnet = 10.1.0.0/24
server_address = 10.1.0.1
listen_port = 51820
default_dns = 1.1.1.1, 8.8.8.8
default_allowed_ips = 0.0.0.0/0, ::/0
```

---

### Verification

```
$ py_compile core/wireguard.py              OK
$ py_compile modules/wireguard_manager.py   OK
$ py_compile web/routes/wireguard.py        OK
$ Flask URL map: 25 wireguard routes
$ WireGuardManager: wg=True, usbip=False, interface=wg0, subnet=10.1.0.0/24
```

### Files Created/Modified

| File | Action | Lines | Description |
|------|--------|-------|-------------|
| `core/wireguard.py` | Created | ~500 | WireGuardManager singleton |
| `modules/wireguard_manager.py` | Created | ~330 | CLI menu module (defense) |
| `web/routes/wireguard.py` | Created | ~200 | Flask blueprint, 25 routes |
| `web/templates/wireguard.html` | Created | ~470 | 4-tab web UI |
| `web/app.py` | Modified | +2 | Import + register wireguard_bp |
| `web/templates/base.html` | Modified | +1 | Nav link in System section |
| `autarch_settings.conf` | Modified | +9 | [wireguard] config section |
| `autarch_dev.md` | Updated | +10 | Phase 4.8, file counts |
| `devjournal.md` | Updated | +50 | Session 15 entry |

---

## Session 16 - 2026-02-15: Archon Android Companion App (Phase 4.9)

### Overview

Created the Archon Android companion app framework in `autarch_companion/`. This is the phone-side app that pairs with AUTARCH's WireGuard VPN + Remote ADB system (Phase 4.8).

**Name:** Archon — Greek ἄρχων (ruler/commander), etymological root of "autarch" (auto + archon = self-ruler)

### Architecture

```
autarch_companion/                     # 29 files total
├── build.gradle.kts                   # Root: AGP 8.2.2, Kotlin 1.9.22
├── settings.gradle.kts                # rootProject.name = "Archon"
├── gradle.properties                  # AndroidX, non-transitive R
├── gradle/wrapper/                    # Gradle 8.5
└── app/
    ├── build.gradle.kts               # com.darkhal.archon, minSdk 26, targetSdk 34
    └── src/main/
        ├── AndroidManifest.xml        # INTERNET, WIFI_STATE, NETWORK_STATE
        ├── kotlin/com/darkhal/archon/
        │   ├── MainActivity.kt        # NavHostFragment + BottomNavigationView
        │   ├── ui/
        │   │   ├── DashboardFragment.kt   # ADB/USB-IP controls, auto-restart watchdog
        │   │   ├── LinksFragment.kt       # 9-card grid → AUTARCH web UI
        │   │   ├── BbsFragment.kt         # WebView + @JavascriptInterface bridge
        │   │   └── SettingsFragment.kt    # Config form + connection test
        │   ├── service/
        │   │   ├── AdbManager.kt          # ADB TCP/IP, kill/restart, status
        │   │   └── UsbIpManager.kt        # usbipd control, device listing
        │   └── util/
        │       ├── PrefsManager.kt        # SharedPreferences wrapper
        │       └── ShellExecutor.kt       # Shell/root exec with timeout
        ├── res/
        │   ├── layout/                # 5 XMLs (activity + 4 fragments)
        │   ├── menu/bottom_nav.xml    # 4 nav items
        │   ├── navigation/nav_graph.xml
        │   ├── values/                # colors, strings, themes
        │   └── drawable/ic_archon.xml # Greek column vector icon
        └── assets/bbs/
            ├── index.html             # Terminal UI
            ├── terminal.css           # Green-on-black theme
            └── veilid-bridge.js       # VeilidBBS class + command system
```

### DashboardFragment — ADB & USB/IP Control

Key controls:
- **ADB TCP/IP toggle**: `setprop service.adb.tcp.port 5555 && stop adbd && start adbd`
- **USB/IP export toggle**: `usbipd -D` to start USB/IP daemon
- **Kill ADB**: `stop adbd`
- **Restart ADB**: `stop adbd && start adbd`
- **Auto-restart watchdog**: Handler posts every 5s, checks `pidof adbd`, restarts if dead
- **WireGuard status**: reads `ip addr show wg0` to check tunnel state

### BBS Terminal — Veilid Integration Strategy

No official Kotlin/Android SDK for Veilid exists. Chose **veilid-wasm in WebView**:

```
BbsFragment.kt
  └─ WebView
      ├─ loads file:///android_asset/bbs/index.html
      ├─ JS: VeilidBBS class (placeholder)
      ├─ JS: command system (help, connect, status, about, clear, version)
      └─ @JavascriptInterface: ArchonBridge
          ├─ getServerAddress() → prefs BBS address
          ├─ getAutarchUrl() → "http://10.1.0.1:8080"
          ├─ getVeilidConfig() → bootstrap JSON
          └─ log(msg) → Android logcat
```

When VPS BBS server is deployed:
1. Bundle `veilid-wasm` WASM module in assets
2. Load in WebView via ES module import
3. Initialize Veilid core with bootstrap config
4. Connect to BBS server via DHT key
5. Route messages through Veilid's onion-style network

### Theme

Dark hacker aesthetic matching AUTARCH web UI:
- Primary: `#00FF41` (terminal green)
- Background: `#0D0D0D`
- Surface: `#1A1A1A`
- All text: monospace font family
- Material Design 3 `Theme.Material3.Dark.NoActionBar`

### Verification

```
$ All 12 XML files: valid (Python xml.etree.ElementTree parse OK)
$ File count: 29 files
$ Directory structure: matches plan exactly
```

### Files Created

| File | Lines | Description |
|------|-------|-------------|
| `build.gradle.kts` (root) | 4 | AGP + Kotlin plugins |
| `settings.gradle.kts` | 12 | Project settings |
| `gradle.properties` | 4 | Gradle props |
| `gradle-wrapper.properties` | 5 | Gradle 8.5 wrapper |
| `app/build.gradle.kts` | 42 | App config + deps |
| `AndroidManifest.xml` | 22 | Permissions + activity |
| `MainActivity.kt` | 18 | Nav controller setup |
| `DashboardFragment.kt` | 185 | ADB/USB-IP/WG controls |
| `LinksFragment.kt` | 55 | AUTARCH link grid |
| `BbsFragment.kt` | 85 | WebView + JS bridge |
| `SettingsFragment.kt` | 120 | Config form + test |
| `AdbManager.kt` | 72 | ADB management |
| `UsbIpManager.kt` | 90 | USB/IP management |
| `PrefsManager.kt` | 80 | SharedPreferences |
| `ShellExecutor.kt` | 55 | Shell execution |
| `activity_main.xml` | 25 | Main layout |
| `fragment_dashboard.xml` | 230 | Dashboard UI |
| `fragment_links.xml` | 215 | Link grid UI |
| `fragment_bbs.xml` | 10 | WebView container |
| `fragment_settings.xml` | 180 | Settings form |
| `bottom_nav.xml` | 20 | Navigation menu |
| `nav_graph.xml` | 22 | Nav graph |
| `colors.xml` | 15 | Color palette |
| `strings.xml` | 45 | String resources |
| `themes.xml` | 15 | Material theme |
| `ic_archon.xml` | 35 | Vector icon |
| `index.html` | 25 | BBS terminal |
| `terminal.css` | 95 | Terminal theme |
| `veilid-bridge.js` | 175 | BBS + Veilid bridge |

### Network Discovery (added same session)

Added local network discovery so Archon can auto-find AUTARCH servers without manual IP configuration.

**Server side — `core/discovery.py`** (~280 lines):
- `DiscoveryManager` singleton with mDNS + Bluetooth advertising
- mDNS: uses `zeroconf` package to advertise `_autarch._tcp.local.` service with IP, port, hostname
- Bluetooth: uses `hciconfig`/`bluetoothctl` CLI tools — sets adapter name to "AUTARCH", enables discoverable + pairable
- BT security enforced: AUTH + ENCRYPT + SSP must be enabled before advertising starts
- BT only activates if physical adapter present (`hci0` in `hciconfig` output)
- 3 API routes: `/settings/discovery/status`, `/start`, `/stop`
- Auto-starts on Flask app startup if `[discovery] enabled = true`

**App side — `service/DiscoveryManager.kt`** (~320 lines):
- Three discovery methods, run in parallel:
  1. **NSD/mDNS** — `NsdManager.discoverServices("_autarch._tcp.")` → resolves to IP:port
  2. **Wi-Fi Direct** — `WifiP2pManager.discoverPeers()` → finds device named "AUTARCH" → connects → gets group owner IP
  3. **Bluetooth** — `BluetoothAdapter.startDiscovery()` → finds device named "AUTARCH"
- Listener callback pattern: `onServerFound`, `onDiscoveryStarted`, `onDiscoveryStopped`, `onDiscoveryError`
- Auto-timeout after 15 seconds
- Best server selection by method priority (MDNS > WIFI_DIRECT > BLUETOOTH)

**UI Integration:**
- Dashboard: new "Server Discovery" card at top — status dot, method text, SCAN button
- Auto-discovers on launch, auto-configures PrefsManager with found IP/port
- Settings: "AUTO-DETECT SERVER" button runs discovery and fills in IP/port fields

**Files created/modified:**

| File | Action | Description |
|------|--------|-------------|
| `core/discovery.py` | Created | DiscoveryManager (mDNS + BT) |
| `autarch_companion/.../DiscoveryManager.kt` | Created | NSD + Wi-Fi Direct + BT |
| `autarch_companion/.../DashboardFragment.kt` | Modified | Discovery card + auto-scan |
| `autarch_companion/.../SettingsFragment.kt` | Modified | Auto-detect button |
| `autarch_companion/.../fragment_dashboard.xml` | Modified | Discovery card layout |
| `autarch_companion/.../fragment_settings.xml` | Modified | Auto-detect button |
| `autarch_companion/.../AndroidManifest.xml` | Modified | BT + Wi-Fi Direct permissions |
| `autarch_companion/.../strings.xml` | Modified | Discovery string resources |
| `web/app.py` | Modified | Start discovery on Flask boot |
| `web/routes/settings.py` | Modified | 3 discovery API routes |
| `autarch_settings.conf` | Modified | `[discovery]` config section |

---

## Session 14 — 2026-02-28: MSF Web Runner, Agent Hal, Debug Console, LLM Settings Sub-Page

### Phase 4.12 — MSF Web Module Execution + Agent Hal + Global AI Chat

**Files Changed:**
- `core/agent.py` — added optional `step_callback` param to `Agent.run()`
- `web/routes/offense.py` — added `POST /offense/module/run` (SSE) + `POST /offense/module/stop`
- `web/templates/offense.html` — Run Module tabs (SSH/PortScan/OSDetect/Custom) + Agent Hal panel
- `web/routes/msf.py` (NEW) — MSF RPC console blueprint (`/msf/`)
- `web/templates/msf.html` (NEW) — terminal-style MSF console UI
- `web/routes/chat.py` (NEW) — `/api/chat` SSE, `/api/agent/run|stream|stop` endpoints
- `web/templates/base.html` — HAL global chat panel + MSF Console sidebar link
- `web/static/js/app.js` — HAL functions (halToggle/Send/Append/Scroll/Clear) + debug console functions
- `web/app.py` — registered msf_bp, chat_bp
- `web/static/css/style.css` — HAL panel CSS, debug panel CSS, stream utility classes

**Key technical details:**
- Module execution uses `MSFInterface.run_module()` → SSE streams output lines then `{done, findings, open_ports}`
- Agent runs in background thread; steps accumulated in shared list polled by SSE stream every 150ms
- HAL chat panel streams LLM tokens via ReadableStream pump (not EventSource — POST required)
- `Agent.run()` step_callback overrides `self.on_step` for incremental streaming
- MSF console uses `run_console_command(cmd)` → `(ok, output)` — not `console_exec()`
- `escapeHtml()` is the correct global (not `escHtml()`) — bug found and fixed in offense.html

### Phase 4.13 — Debug Console

**Files Changed:**
- `web/routes/settings.py` — `_DebugBufferHandler`, `_ensure_debug_handler()`, 4 debug routes
- `web/templates/settings.html` — Debug Console section with enable checkbox + test buttons
- `web/templates/base.html` — floating debug popup with 5 filter mode checkboxes
- `web/static/js/app.js` — full debug JS (toggle, stream, filter, format, drag)
- `web/static/css/style.css` — debug panel dark terminal aesthetic

**5 filter modes:** Warnings & Errors | Full Verbose | Full Debug + Symbols | Output Only | Show Everything

### Phase 4.14 — WebUSB "Already In Use" Fix

**File Changed:** `web/static/js/hardware-direct.js`
- `adbDisconnect()` now calls `await adbUsbDevice.close()` to release USB interface
- `adbConnect()` detects Windows "already in used/in use" errors, auto-retries once, shows actionable "run adb kill-server" message
- Separate Linux permission error path with udev rules hint

### Phase 4.15 — LLM Settings Sub-Page

**Files Changed:**
- `core/config.py` — added `get_openai_settings()` method (api_key, base_url, model, max_tokens, temperature, top_p, frequency_penalty, presence_penalty)
- `web/routes/settings.py` — added `GET /settings/llm`, `POST /settings/llm/scan-models`, updated `POST /settings/llm` for openai
- `web/templates/settings.html` — replaced LLM section with sub-menu card linking to `/settings/llm`
- `web/templates/llm_settings.html` (NEW) — 4-tab LLM config page

**Local tab features:**
- Folder picker + Scan button → server-side scan for .gguf/.ggml/.bin files and safetensors model dirs
- SafeTensors checkbox toggles between llama.cpp (full quantization/tokenizer params) and transformers backends
- llama.cpp: n_ctx, n_threads, n_gpu_layers, n_batch, temperature, top_p, top_k, repeat_penalty, max_tokens, seed, rope_scaling_type, mirostat (0/1/2), flash_attn
- Transformers: device, torch_dtype, load_in_8bit/4bit, trust_remote_code, use_fast_tokenizer, padding_side, do_sample, num_beams, temperature, top_p, top_k, repetition_penalty, max_new_tokens

**HuggingFace tab:** Token login + verify, model ID, provider selector (8 providers), custom endpoint, full generation params
**Claude tab:** API key + model dropdown (all Claude 4.x) + basic params
**OpenAI tab:** API key + base_url (custom endpoint support) + model + basic params

---

## Session 15 — 2026-03-01

### Phase 4.16 — Hash Toolkit Sub-Page

**Files Changed:**
- `web/routes/analyze.py` — added `import zlib`, `HASH_PATTERNS` list (~43 entries), `_identify_hash()` helper, 6 new routes
- `web/templates/hash_detection.html` (NEW) — 6-tab Hash Toolkit page
- `web/templates/base.html` — added Hash Toolkit sidebar sub-item under Analyze

**New routes:**
- `GET /analyze/hash-detection` → renders hash_detection.html
- `POST /analyze/hash-detection/identify` → regex-based hash algorithm identification (hashid-style)
- `POST /analyze/hash-detection/file` → compute CRC32/MD5/SHA1/SHA256/SHA512 for a file
- `POST /analyze/hash-detection/text` → hash text with selectable algorithm (supports "all")
- `POST /analyze/hash-detection/mutate` → append bytes to file copy, show before/after hashes
- `POST /analyze/hash-detection/generate` → create dummy test files with configurable content types

**HASH_PATTERNS coverage:** CRC16/32, MD2/4/5, NTLM, LM, MySQL 3.x/4.x+, SHA-1/224/256/384/512, SHA3-224/256/384/512, BLAKE2b/2s, Keccak-224/256/384/512, Whirlpool, Tiger-192, RIPEMD-160, bcrypt, Unix crypt ($1$/$5$/$6$), scrypt, Argon2, PBKDF2, Cisco Type 5/7/8/9, Django PBKDF2, WordPress/phpBB, Drupal, HMAC-MD5/SHA1/SHA256

**6 tabs in hash_detection.html:**
1. **Identify** — paste hash → regex match → algorithm candidates with hashcat modes + threat intel links (VirusTotal, Hybrid Analysis, MalwareBazaar, AlienVault OTX, Shodan)
2. **File Hash** — file path → CRC32/MD5/SHA1/SHA256/SHA512 digest output
3. **Text Hash** — textarea + algorithm dropdown → hash output (supports "all" for every digest)
4. **Mutate** — append random/null/custom bytes to file copy → before/after hash comparison
5. **Generate** — create dummy files with configurable content (random/zeros/ones/pattern/custom) → hash output
6. **Reference** — static table of hash types with lengths and hashcat modes

**Sidebar pattern:** sub-item under Analyze with `padding-left:1.5rem;font-size:0.85rem` and `└` prefix, matching Legendary Creator under Simulate

### Bugfix — `modules/analyze.py` magic import

**File Changed:** `modules/analyze.py`
- Changed bare `import magic` (line 13) to `try: import magic / except ImportError: magic = None`
- Usage at lines 91-99 was already in try/except fallback — this just prevented the module from failing to load entirely

### Bugfix — Debug Console server restart persistence

**File Changed:** `web/static/js/app.js`
- `_initDebug()` now POSTs to `/settings/debug/toggle` to re-enable backend capture when localStorage indicates debug is enabled
- Root cause: `_debug_enabled` in `settings.py` resets to `False` on server restart, but client-side localStorage persisted `autarch_debug=1` — so the SSE stream started but no messages were captured

### Bugfix — Android Protection Direct mode `'dict' object has no attribute 'strip'`

**File Changed:** `web/templates/android_protect.html`
- `apDirect()` line 504: `HWDirect.adbShell(cmd)` returns `{stdout, stderr, exitCode, output}` object, not a string
- Was passing whole object into `raw` dict → Python `/parse` route called `.strip()` on dict values
- Fix: extract `result.stdout || result.output || ''` before storing in `raw`

**Also hardened:** `web/routes/android_protect.py`
- `_serial()` now checks `request.form` (for FormData uploads like shield_install) and wraps in `str()` before `.strip()`

---

## Session 16 — 2026-03-01: Threat Monitor Enhancement, Hal Agent Mode, Windows Defense, LLM Trainer

### Phase 4.17 — Threat Monitor Enhancement (7-tab Threat Monitor)

Expanded the Threat Monitor from 4 tabs to 7, adding Network Intel, Packet Capture, and DDoS Mitigation capabilities.

**Files Changed:**
- `modules/defender_monitor.py` — Added ~15 new methods + singleton `get_threat_monitor()`
- `web/routes/defense.py` — Added ~25 new routes under `/defense/monitor/`
- `web/templates/defense_monitor.html` — 3 new tabs (7 total), drill-down popups

**New ThreatMonitor methods:**
- `get_bandwidth()` — bytes in/out per interface + deltas (PowerShell / `/proc/net/dev`)
- `check_arp_spoofing()` — multiple MACs per IP detection (`arp -a` / `ip neigh show`)
- `check_new_listening_ports()` — alert on new listeners since baseline
- `geoip_lookup(ip)` — country/ISP/ASN via ipwho.is API
- `get_connections_with_geoip()` — connection table enriched with geo data
- `get_connection_rate()` — connections/sec trending
- `detect_ddos()` — SYN flood / connection flood / bandwidth spike detection
- `get_top_talkers(limit)` — top IPs by connection count
- `apply_rate_limit(ip, rate)` / `remove_rate_limit(ip)` — per-IP rate limiting (netsh / iptables)
- `get_syn_protection_status()` / `enable_syn_protection()` — SYN cookies
- `get_ddos_config()` / `save_ddos_config()` — auto-mitigation config (data/ddos_config.json)
- `auto_mitigate()` — auto-block offenders if thresholds exceeded
- `get_mitigation_history()` / `log_mitigation()` — action log (data/mitigation_log.json)

**New routes (under `/defense/monitor/`):**
- Monitoring: `bandwidth`, `arp-check`, `new-ports`, `geoip`, `connections-geo`, `connection-rate`
- Packet Capture: `capture/interfaces`, `capture/start`, `capture/stop`, `capture/stats`, `capture/stream` (SSE), `capture/protocols`, `capture/conversations`
- DDoS: `ddos/detect`, `ddos/top-talkers`, `ddos/rate-limit`, `ddos/rate-limit/remove`, `ddos/syn-status`, `ddos/syn-enable`, `ddos/syn-disable`, `ddos/config` (GET/POST), `ddos/auto-mitigate`, `ddos/history`, `ddos/history/clear`

**7 tabs in defense_monitor.html:**
1. **Live Monitor** — enhanced with bandwidth cards, ARP/port/DDoS counters, drill-down popups
2. **Connections** — existing, with clickable rows for connection details
3. **Network Intel** — bandwidth table, ARP spoof check, listening port monitor, GeoIP lookup, connections+GeoIP
4. **Threats** — existing threat list with drill-down
5. **Packet Capture** — interface selector, BPF filter, duration, start/stop, live packet SSE stream, protocol distribution, top conversations
6. **DDoS Mitigation** — detection status, top talkers, SYN protection toggle, rate limiting per IP, auto-mitigation config, mitigation history
7. **Counter-Attack** — existing

**Drill-down popups (`.tmon-overlay` + `.tmon-popup`):**
- Click any stat in Live Monitor → modal popup with detailed data table
- Connections popup with clickable rows → individual connection detail card
- CSS added: `.tmon-overlay`, `.tmon-popup`, `.tmon-popup-header`, `.tmon-popup-body`, `.tmon-stat-clickable`, `.tmon-detail-card`, `.tmon-row-clickable`, `.tmon-back-btn`

### Phase 4.18 — Hal Agent Mode + Module Factory

Wired Hal chat to the Agent system so it can create new AUTARCH modules on demand.

**Files Changed:**
- `core/tools.py` — added `create_module` tool to ToolRegistry
- `web/routes/chat.py` — rewritten to use Agent system with system prompt; agent-mode SSE streaming
- `data/hal_system_prompt.txt` (NEW) — Hal's codebase knowledge (~2000 tokens)

**`create_module` tool:**
- Validates category (defense/offense/counter/analyze/osint/simulate)
- Validates code contains required module attributes (NAME, DESCRIPTION, VERSION, CATEGORY, def run())
- Prevents overwriting existing modules
- Writes to `modules/{name}.py`
- Attempts `importlib.util.spec_from_file_location` to verify valid Python
- If import fails, deletes the file and returns the error

**Chat route rewrite:**
- Loads system prompt from `data/hal_system_prompt.txt`
- Detects action requests → Agent mode vs simple chat
- Agent mode: creates `Agent(llm, tools)`, runs in background thread, streams steps via SSE
- SSE events: `thought`, `action`, `result`, `token`, `done`, `error`

### Phase 4.19 — Windows Defense Sub-Page

**Files Created:**
- `modules/defender_windows.py` — Windows security module with firewall, UAC, Defender AV, services, SSH, NTFS, event logs
- `web/templates/defense_windows.html` — multi-tab Windows defense UI

**Files Changed:**
- `web/routes/defense.py` — added `defense.windows_index` route + Windows-specific API routes
- `web/templates/base.html` — added Linux/Windows/Threat Monitor sub-items under Defense sidebar

### Phase 4.20 — LLM Trainer

**Files Created:**
- `modules/llm_trainer.py` — LLM fine-tuning module (dataset management, training config, adapter listing)
- `web/routes/llm_trainer.py` — Flask blueprint for LLM Trainer page
- `web/templates/llm_trainer.html` — LLM Trainer UI

**Features:**
- Dataset management (create, list, delete JSONL datasets)
- Training configuration (model, epochs, learning rate, batch size)
- Adapter listing (LoRA/QLoRA adapters)
- Training status monitoring

### Refresh Modules Button

**Files Changed:**
- `web/templates/base.html` — added "Refresh Modules" button in sidebar
- `web/static/js/app.js` — `reloadModules()` function POSTs to `/settings/reload-modules`
- `web/routes/settings.py` — `POST /settings/reload-modules` route calls `MenuSystem.reload_modules()`

---

## Session 17 — 2026-03-02: System Tray, Dual-Exe Build, Installer Scripts, v1.5 Release

### Phase 4.21 — System Tray Icon

**Files Created:**
- `core/tray.py` — `TrayManager` class using pystray + PIL

**Files Changed:**
- `autarch.py` — added `--no-tray` flag, tray integration in `--web` mode

**TrayManager features:**
- Auto-generates dark circle icon with cyan "A" using PIL
- Menu: status line, Start, Stop, Restart, Open Dashboard, Exit
- Dynamic menu state (Start disabled when running, Stop/Restart disabled when stopped)
- Uses `werkzeug.serving.make_server` for threaded Flask in background
- SSL context passthrough for HTTPS
- `TRAY_AVAILABLE` flag for graceful fallback on systems without pystray

### Phase 4.22 — Dual Executable Build + Frozen Path Support

**Files Created:**
- `autarch_web.py` — Windowless web launcher entry point (Win32GUI, no console window)

**Files Changed:**
- `core/paths.py` — Frozen build support with dual-directory pattern
- `core/menu.py` — Module loading scans both bundled and user module directories
- `web/app.py` — Template/static paths resolve correctly in frozen (PyInstaller) builds

**Frozen build architecture:**
- `_FROZEN = getattr(sys, 'frozen', False)` detection
- `_BUNDLE_DIR` = `Path(sys._MEIPASS)` when frozen (read-only assets)
- `_APP_DIR` = `Path(sys.executable).parent` when frozen (writable data)
- New: `is_frozen()`, `get_bundle_dir()`, `get_user_modules_dir()`
- `get_config_path()` copies bundled config to writable location on first run
- Module loading: scans both `get_modules_dir()` (bundle) and `get_user_modules_dir()` (user), user overrides bundled

### Phase 4.23 — Installer Scripts

**Files Created:**
- `installer.iss` — Inno Setup script (lzma2, no solid compression for large files)
- `installer.nsi` — NSIS script with MUI2, Start Menu, desktop shortcut, uninstaller

**Files Changed:**
- `autarch_public.spec` — Rewritten for dual-exe build with MERGE/COLLECT, existence-filtered data files
- `setup_msi.py` — Dual executables, LocalAppData install, model inclusion

**PyInstaller spec details:**
- Dual Analysis: `a_cli` (autarch.py, console=True) + `a_web` (autarch_web.py, console=False)
- `MERGE()` for shared library deduplication
- Single `COLLECT` combining both executables
- Existence filter: `added_files = [(str(src), dst) for src, dst in _candidate_files if src.exists()]`

**Inno Setup details:**
- GGUF model stored with `Flags: nocompression` to avoid OOM (3.9GB, barely compressible)
- `SolidCompression=no` prevents Inno from loading entire archive into memory
- Model excluded from main recursive glob with `Excludes: "_internal\models\Hal_v2.gguf"`
- GitHub release version excludes model (34 MB vs 3.9 GB)

### Phase 4.24 — WebUI FOUC Fix

**Files Changed:**
- `web/templates/base.html` — added inline critical CSS in `<head>`

**Fix:** Inlined dark theme colors, sidebar layout, and flex container styles directly in `<style>` tag before the external stylesheet `<link>`. Prevents flash of unstyled content (white background, unstyled sidebar) when the external CSS is delayed by self-signed cert negotiation or slow loading.

### v1.5 Release

**Release:** https://github.com/DigijEth/autarch/releases/tag/v1.5

**Assets:**
- `AUTARCH_Setup.exe` (34 MB) — Inno Setup installer, installs to `%LocalAppData%\AUTARCH`
- `AUTARCH_v1.5_Portable.zip` (39 MB) — Portable build with `autarch.exe` + `autarch_web.exe`

**Note:** Hal AI model (`Hal_v2.gguf`, 3.9 GB) excluded from both downloads due to GitHub's 2 GB per-asset limit.

**All 27+ pages tested** — inline CSS + external stylesheet present, layout/sidebar/content structure verified on every route.

---

## Session 18 - 2026-03-02

### Phase 4.25 — Hal Chat Fix (Chat/Agent Dual Mode)

**Problem:** All Hal chat messages were routed through the Agent system (`core/agent.py`), which expects structured `THOUGHT:/ACTION:/PARAMS:` responses. Local GGUF models return plain conversational text, causing `_parse_response()` to fail with `ValueError("No ACTION found")` on every message. The agent retried 20 times, exhausted max steps, and returned `Error: '"info"'`.

**Fix — Dual-mode routing:**

**Files Changed:**
- `web/routes/chat.py` — Split `/api/chat` into `_handle_direct_chat()` (streams tokens via `llm.chat(stream=True)`) and `_handle_agent_chat()` (existing Agent system). Mode selected by `mode` field in POST body (`'chat'` default, `'agent'` for tools).
- `web/templates/base.html` — Added toggle switch in Hal panel header (Chat ↔ Agent)
- `web/static/js/app.js` — Added `halAgentMode` flag, `halModeChanged()`, passes `mode` in fetch body
- `web/static/css/style.css` — Toggle switch CSS (`.hal-mode-switch`, `.hal-mode-slider`, `.hal-mode-label`)

### Phase 4.26 — Agent Graceful Degradation

**Problem:** In Agent mode, models that can't follow the structured format would loop 20 times and error out.

**Fix:**

**Files Changed:**
- `core/agent.py` — Added `parse_failures` counter. After 2 consecutive `ValueError` from `_parse_response()`, the agent cleans up the raw response (strips ChatML tokens) and returns it as a `task_complete` result instead of continuing to retry. First failure still gets one retry with format correction prompt.

### Phase 4.27 — Frozen Build LLM Fix

**Problem:** Compiled exe reported `llama-cpp-python not installed: No module named 'llama_cpp'` because `llama_cpp` and `llama_cpp_python` were in the PyInstaller excludes list.

**Fix:**

**Files Changed:**
- `autarch_public.spec` — Removed `llama_cpp`, `llama_cpp_python`, `anthropic` from `excludes` list
- `setup_msi.py` — Same removal from excludes

### Phase 4.28 — System Tray Icon

**Problem:** No `.ico` file existed — exe had no icon in Explorer/taskbar, and the tray icon relied on Pillow generating one programmatically at runtime.

**Fix:**

**Files Changed:**
- `autarch.ico` (NEW) — Multi-resolution .ico (16-256px) created from `icon.svg`
- `icon.svg` (NEW) — SVG source for the AUTARCH icon (anarchy-A in circle, cyberpunk neon style)
- `core/tray.py` — Added `_get_icon_path()` to find `.ico` in both source and frozen builds. `create_icon_image()` now loads from `.ico` first, falls back to programmatic generation.
- `autarch_public.spec` — Added `icon=str(SRC / 'autarch.ico')` for both exe targets, added `.ico` to data files
- `installer.iss` — Added `SetupIconFile=autarch.ico`, `UninstallDisplayIcon`, `IconFilename` on shortcuts

### v1.5.1 Release

**Release:** https://github.com/DigijEth/autarch/releases/tag/v1.5.1

**Assets:**
- `AUTARCH_Setup.exe` — Inno Setup installer with icon
- `AUTARCH_v1.5.1_Portable.zip` (51 MB) — Portable build

**Version bumped** in `installer.iss`, `installer.nsi`, `setup_msi.py`.

---

