# AUTARCH Development Journal
## Project: darkHal Security Group - Project AUTARCH

A condensed development journal covering all work on the AUTARCH framework.
For full implementation details, see `DEVLOG.md`.

---

## Session 1 - 2026-01-14: Framework Foundation

Built the entire AUTARCH framework from scratch in a single session.

### Core Framework

- **autarch.py** - Main entry point with full argparse CLI (--help, --module, --list, --setup, etc.)
- **core/banner.py** - ASCII art banner with ANSI color support
- **core/config.py** - Configuration handler for `autarch_settings.conf` with typed getters
- **core/menu.py** - Category-based main menu system (Defense/Offense/Counter/Analyze/OSINT/Simulate)
- **core/llm.py** - llama-cpp-python wrapper with ChatML format, streaming, chat history management
- **core/agent.py** - Autonomous agent loop with THOUGHT/ACTION/PARAMS structured response parsing
- **core/tools.py** - Tool registry with 12+ built-in tools (shell, file ops, MSF tools)
- **core/msf.py** - Metasploit RPC client (msgpack protocol) with module search/execution/session management
- **modules/setup.py** - First-run setup wizard for llama.cpp parameters
- **modules/chat.py** - Interactive LLM chat interface with slash commands
- **modules/agent.py** - Agent task interface
- **modules/msf.py** - Menu-driven MSF interface with quick scan presets

### Category Modules

- **modules/defender.py** (defense) - System hardening audit, firewall/SSH/permissions checks, security scoring
- **modules/counter.py** (counter) - Threat detection: suspicious processes, network analysis, rootkit checks
- **modules/analyze.py** (analyze) - File forensics: metadata, hashes, strings, hex dump, log analysis
- **modules/recon.py** (osint) - OSINT reconnaissance: email/username/phone/domain/IP lookup, social-analyzer integration
- **modules/simulate.py** (simulate) - Attack simulation: port scanner, password audit, payload generator
- **modules/adultscan.py** (osint) - Adult site username scanner (50+ sites) with custom site management, auto-detect URL patterns, bulk import from file

### CLI System

Full argparse with direct module execution (`-m`), quick commands (`osint <user>`, `scan <target>`), category listing, config display.

### Architecture Decisions

- Modules define NAME, DESCRIPTION, AUTHOR, VERSION, CATEGORY attributes with a `run()` entry point
- ChatML format (`<|im_start|>role\ncontent<|im_end|>`) for LLM compatibility
- Agent uses lower temperature (0.3) for tool selection accuracy
- MSF RPC requires msfrpcd running separately

---

## Session 2 - 2026-01-15: CVE Database & OSINT Expansion

### CVE Database System

- **core/cve.py** - Full NVD API v2.0 integration with SQLite storage
  - Auto OS detection with CPE mapping (15+ operating systems)
  - Thread-safe SQLite with indexed columns
  - Rate-limited API sync (respects NVD limits)
  - Online fallback when database empty
- **modules/mysystem.py** (defense) - "My System" comprehensive audit
  - 10 security checks (firewall, SSH, ports, users, permissions, services, updates, fail2ban, AV, CVEs)
  - Security score 0-100 with severity-based penalties
  - Per-issue remediation: manual instructions or LLM auto-fix
  - Persists audit results to `system.inf`

### Settings Menu Expansion

- CVE Database Settings (sync, API key, stats)
- Custom APIs management (add/edit/delete external API integrations)
- AUTARCH API placeholder (future REST API)

### OSINT Sites Database Expansion

- **core/sites_db.py** - SQLite-backed sites database
  - Added reveal-my-name source (628 sites)
  - Added 43 XenForo/vBulletin forums from large forums list
  - Added 60+ adult/NSFW sites (cam, creator, tube, dating, gaming, hentai, furry)
  - Added mainstream sites (social, dating, crypto, streaming, creative, shopping, blogging)
  - Decoded and imported Snoop Project database (base32-encoded, reversed format) - 4,641 sites
  - **Total: 8,315 sites across 9 sources**
- **modules/snoop_decoder.py** - Snoop database decoder module for OSINT menu

### New OSINT Modules (Snoop-inspired features)

- **modules/geoip.py** - GEO IP/domain lookup (ipwho.is, ipinfo.io backends)
- **modules/yandex_osint.py** - Yandex user account intelligence gathering
- **modules/nettest.py** - Network connectivity and speed testing
- **core/report_generator.py** - HTML report generator with dark theme AUTARCH branding

---

## Session 3 - 2026-01-15 (Continued): OSINT Quality Improvements

### Configurable OSINT Settings

- Added `[osint]` config section: `max_threads` (default 8), `timeout`, `include_nsfw`
- OSINT Settings submenu in Settings menu
- Both recon.py and adultscan.py use config instead of hardcoded values

### Database Cleanup

- Fixed 3,171 malformed site names (`{username}.domain` patterns, `Forum_name` patterns)
- Removed 407 duplicate forum software variants (`_vb1`, `_xf`, `_phpbb`)
- Added `cleanup_garbage_sites()` - disabled Russian forum farms (ucoz, borda, etc.), search URLs, dead sites
- Added `auto_categorize()` - pattern-based categorization reducing "other" from 82% to 42%
- Added `remove_duplicates()` - removed duplicate URL templates
- **Result: 7,119 total sites, 4,786 enabled (quality over quantity)**

### Detection System Rewrite (Social-Analyzer Style)

- Rewrote detection to mirror social-analyzer's approach:
  - `return: true/false` string matching patterns
  - Rate calculation: `(detections_passed / detections_total) * 100`
  - Status categories: good (100%), maybe (50-100%), bad (<50%)
- Added WAF/Cloudflare detection (actual challenge pages only, not all CDN-served content)
- Added random delays (50-500ms) to reduce rate limiting
- Added retry logic (up to 2 retries for 5xx/connection failures)
- Expanded to 30 NOT_FOUND patterns and 23 FOUND patterns

### Blackbird Import

- Added `import_from_blackbird()` to sites_db.py
- Imported 168 new sites from blackbird's wmn-data.json
- Name collision handling with `_bb` suffix
- **Final total: 7,287 sites across 10 sources**

---

## Session 4 - 2026-01-15 (Continued): Dossier Manager & Agent Hal

### Dossier Manager

- **modules/dossier.py** - OSINT investigation management
  - Create dossiers linking multiple identifiers (emails, usernames, phones, names, aliases)
  - Import username scan results from JSON
  - Manual profile addition, investigation notes
  - Export as JSON or text report
  - Storage in `dossiers/` directory

### NSFW / Adult Site Fixes

- Fixed Chaturbate URL format (added trailing slash)
- Added fanfiction sites from pred_site.txt (AO3, Fimfiction, FanFiction.net, Kemono)
- Fixed imgsrc.ru categorization (adult, nsfw=1)
- Added `SITE_COOKIES` dictionary with age verification cookies for 25+ adult sites
- Fixed overly aggressive WAF detection (Cloudflare-served != WAF-blocked)

### Agent Hal Module

- **modules/agent_hal.py** v1.0 - AI-powered security automation
  - **Defense: MITM Detection**
    - ARP spoofing, DNS spoofing, SSL stripping, rogue DHCP, gateway anomaly detection
    - Continuous monitoring mode (5-second interval ARP table comparison)
  - **Offense: MSF Automation (AI)**
    - Natural language MSF control (user describes intent, LLM recommends modules)
    - Quick scan target (multi-scanner automation)
    - Exploit suggester (LLM-powered, with CVE numbers and success likelihood)
    - Post-exploitation helper (privesc, persistence, credential harvesting guidance)
- Added to main menu as option [7] Agent Hal

---

## Session 5 - 2026-01-19: Username Scanner Refinement

### CupidCr4wl-Style Detection

- Rewrote detection algorithm based on CupidCr4wl's dual pattern matching:
  - `not_found_text` match = user definitely doesn't exist (highest priority)
  - `check_text` match + username in content = FOUND (good)
  - `check_text` match only = POSSIBLE (maybe)
  - Nothing matched = NOT FOUND

### Site-Specific Detection Patterns

- Added `SITE_PATTERNS` dictionary with tailored check_text/not_found_text for 20+ platforms:
  - Reddit, GitHub, Twitter/X, Instagram, TikTok, Telegram, Tumblr
  - Chaturbate, OnlyFans, Fansly, Pornhub, XVideos, Stripchat
  - DeviantArt, ArtStation, Fur Affinity, e621
  - Twitch, Steam, FetLife, YouTube, Wattpad

### Other Improvements

- Username validation (length, invalid chars, email detection)
- User-Agent rotation (6 agents)
- Fixed gzip encoding bug (removed Accept-Encoding header)
- Updated detection patterns in sites.db via SQL for major sites
- Fixed Chaturbate "offline" false positive ("offline" != "not found" for cam sites)

### Verification Results

- torvalds (GitHub): good 100% - correctly detected
- spez (Reddit): good 100% - correctly detected
- fudnucker (Chaturbate): good 100% - correctly detected
- totally_fake_user_xyz (Chaturbate): NOT FOUND - correctly rejected

---

## Session 6 - 2026-01-27: PentestGPT Methodology Integration

### Overview

Ported PentestGPT's three-module pipeline architecture (from the USENIX Security paper) into AUTARCH as native modules. This adds structured, AI-guided penetration testing capabilities to Agent Hal using the local LLM rather than external APIs.

### Research Phase

Studied PentestGPT's architecture:
- Three-module pipeline: Parsing, Reasoning, Generation
- Penetration Testing Tree (PTT) - hierarchical task tracker
- Session-based workflow with state persistence

Studied AUTARCH's existing systems:
- core/llm.py (ChatML, chat(), clear_history(), streaming)
- core/tools.py (ToolRegistry, MSF tools, shell)
- modules/agent_hal.py (MITM detection, MSF automation)

### Key Adaptation Decisions

1. **Fresh context per module call** - PentestGPT uses 100K+ token cloud models with rolling conversations. AUTARCH's local LLM has 4096 token context. Solution: `clear_history()` before each pipeline stage, inject only compact tree summary.
2. **PTT as Python object** - PentestGPT keeps the tree as in-context text. AUTARCH stores it as a proper data structure with `render_summary()` for minimal token injection.
3. **Regex-based LLM parsing** - Local 7B models don't produce reliable JSON. All parsers use regex with fallbacks, matching existing agent_hal.py patterns.
4. **Manual-first execution** - Commands displayed for user to run manually. `exec` command enables auto-execution with per-command Y/n/skip confirmation.

### New Files Created

#### core/pentest_tree.py - Penetration Testing Tree

The central PTT data structure from the USENIX paper.

- `NodeStatus` enum: TODO, IN_PROGRESS, COMPLETED, NOT_APPLICABLE
- `PTTNodeType` enum: RECONNAISSANCE, INITIAL_ACCESS, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, CREDENTIAL_ACCESS, PERSISTENCE, CUSTOM
- `PTTNode` dataclass with id, label, type, status, parent/children, details, tool_output, findings, priority
- `PentestTree` class:
  - Tree operations: add_node(), update_node(), delete_node()
  - Queries: get_next_todo() (highest priority TODO), get_all_by_status(), find_node_by_label()
  - `render_text()` - full tree for terminal display
  - `render_summary()` - compact format for LLM context injection (critical for 4096 token window, shows only TODO/IN_PROGRESS nodes and last 5 findings)
  - `initialize_standard_branches()` - creates MITRE ATT&CK-aligned top-level categories
  - Serialization: to_dict() / from_dict()

#### core/pentest_session.py - Session Management

Save/resume pentest sessions with full state persistence.

- `PentestSessionState` enum: IDLE, RUNNING, PAUSED, COMPLETED, ERROR
- `SessionEvent` dataclass for timeline logging
- `PentestSession` class:
  - Lifecycle: start(), pause(), resume(), complete(), set_error()
  - Persistence: save(), load_session(), list_sessions(), delete()
  - Logging: log_event(), log_pipeline_result(), add_finding()
  - export_report() - text summary report generation
  - JSON files stored in `data/pentest_sessions/`

#### core/pentest_pipeline.py - Three-Module Pipeline

Implements PentestGPT's core architecture using AUTARCH's LLM.chat().

- `SOURCE_PATTERNS` - regex auto-detection for tool output type (nmap, msf_scan, msf_exploit, web, shell, gobuster, nikto)
- **ParsingModule** - normalizes raw tool output into structured SUMMARY/FINDINGS/STATUS
  - Auto-detects source type via regex
  - Chunks output >2000 chars
  - Fresh clear_history() + chat() per call, temperature=0.2
  - Extracts [VULN] and [CRED] prefixed findings
- **ReasoningModule** - decides tree updates and selects next task
  - Injects PTT render_summary() + parsed findings
  - Produces TREE_UPDATES (ADD/COMPLETE/NOT_APPLICABLE) + NEXT_TASK + REASONING
  - `_apply_updates()` resolves node IDs by label if exact ID not found
  - Temperature=0.3
- **GenerationModule** - converts abstract task into concrete commands
  - Maps to AUTARCH tool names (msf_execute, msf_search, shell, etc.)
  - Produces COMMANDS (TOOL/ARGS/EXPECT format) + FALLBACK
  - Fallback detection for bare shell/MSF console commands
  - Temperature=0.2
- **PentestPipeline** - orchestrates all three modules
  - process_output() - full parse->reason->generate flow
  - get_initial_plan() - generates first tasks for new session
  - inject_information() - incorporate external research
  - discuss() - ad-hoc LLM questions without affecting tree

### Modified Files

#### core/config.py

Added `[pentest]` section to DEFAULT_CONFIG:
```
max_pipeline_steps = 50
output_chunk_size = 2000
auto_execute = false
save_raw_output = true
```
Added `get_pentest_settings()` method.

#### modules/agent_hal.py (v1.0 -> v2.0)

Major expansion adding Pentest Pipeline as [3] under Offense.

**New menu item:**
```
  Offense
    [2] MSF Automation (AI)
    [3] Pentest Pipeline (AI)    <- NEW
```

**Pentest Pipeline Submenu:**
```
  [1] New Session
  [2] Resume Session
  [3] List Sessions
  [4] Delete Session
  [5] Show Session Tree
```

**Interactive Loop Commands:**
- `next` - paste tool output, runs full pipeline (parse->reason->generate)
- `exec` - auto-execute next action via MSF/shell with per-command Y/n/skip confirmation
- `discuss` - ad-hoc LLM question (doesn't affect tree)
- `google` - inject external research into pipeline
- `tree` - display current PTT
- `status` - session stats and recent findings
- `pause` - save and return to menu
- `done` - complete session and generate report

**New methods:**
- pentest_pipeline_menu()
- _start_new_pentest_session(), _resume_pentest_session()
- _list_pentest_sessions(), _delete_pentest_session()
- _pentest_interactive_loop()
- _handle_next(), _handle_exec(), _handle_discuss(), _handle_google()
- _handle_status(), _handle_done()
- _execute_pipeline_action() - bridges pipeline output to shell/ToolRegistry

### Pipeline Data Flow

```
User pastes tool output (or exec returns output)
  -> ParsingModule: auto-detect source, chunk, LLM extracts SUMMARY/FINDINGS/STATUS
  -> ReasoningModule: inject PTT summary + findings, LLM returns TREE_UPDATES + NEXT_TASK
  -> GenerationModule: NEXT_TASK + target + tools -> LLM returns COMMANDS + FALLBACK
  -> Display to user / auto-execute with confirmation
  -> Session auto-saved after each cycle
```

### Verification

All imports and basic tests passed:
- pentest_tree: PTT initializes with 6 MITRE ATT&CK branches, serialization round-trip OK
- pentest_session: Session lifecycle and JSON persistence OK
- pentest_pipeline: All three modules instantiate correctly
- config: pentest settings load with correct types and defaults
- agent_hal: Menu renders with new [3] Pentest Pipeline option

---

## Current Project Structure

```
dh_framework/
├── autarch.py                    # Main entry point with CLI
├── autarch_settings.conf         # Configuration file
├── DEVLOG.md                     # Detailed development log
├── devjournal.md                 # This file
├── GUIDE.md                      # User guide
├── system.inf                    # System audit results
├── custom_adultsites.json        # Custom adult sites
├── custom_sites.inf              # Bulk import file
├── custom_apis.json              # Custom API configurations
│
├── core/
│   ├── __init__.py
│   ├── agent.py                  # Autonomous agent loop
│   ├── banner.py                 # ASCII banner
│   ├── config.py                 # Configuration handler
│   ├── cve.py                    # CVE database (NVD API + SQLite)
│   ├── llm.py                    # LLM wrapper (llama-cpp-python)
│   ├── menu.py                   # Main menu system
│   ├── msf.py                    # Metasploit RPC client
│   ├── pentest_pipeline.py       # PentestGPT three-module pipeline [NEW]
│   ├── pentest_session.py        # Pentest session management [NEW]
│   ├── pentest_tree.py           # Penetration Testing Tree [NEW]
│   ├── report_generator.py       # HTML report generator
│   ├── sites_db.py               # OSINT sites SQLite database
│   └── tools.py                  # Tool registry
│
├── modules/
│   ├── __init__.py
│   ├── adultscan.py              # Adult site username scanner (osint)
│   ├── agent.py                  # Agent task interface (core)
│   ├── agent_hal.py              # Agent Hal - AI automation (core) [UPDATED v2.0]
│   ├── analyze.py                # File forensics (analyze)
│   ├── chat.py                   # LLM chat interface (core)
│   ├── counter.py                # Threat detection (counter)
│   ├── defender.py               # System hardening (defense)
│   ├── dossier.py                # OSINT investigation manager (osint)
│   ├── geoip.py                  # GEO IP lookup (osint)
│   ├── msf.py                    # MSF interface (offense)
│   ├── mysystem.py               # System audit with CVE (defense)
│   ├── nettest.py                # Network testing (utility)
│   ├── recon.py                  # OSINT reconnaissance (osint)
│   ├── setup.py                  # First-run setup wizard
│   ├── simulate.py               # Attack simulation (simulate)
│   ├── snoop_decoder.py          # Snoop database decoder (osint)
│   └── yandex_osint.py           # Yandex OSINT (osint)
│
├── data/
│   ├── cve/
│   │   └── cve.db                # SQLite CVE database
│   ├── pentest_sessions/         # Pentest session JSON files [NEW]
│   └── sites/
│       ├── sites.db              # OSINT sites database (7,287 sites)
│       └── snoop_full.json       # Decoded Snoop database
│
├── dossiers/                     # Dossier JSON files
│
└── results/
    └── reports/                  # HTML reports and pentest reports
```

## Capability Summary

| Category | Modules | Key Features |
|----------|---------|--------------|
| Defense | defender, mysystem | System audit, CVE detection, auto-fix, security scoring |
| Offense | msf, agent_hal | MSF automation, pentest pipeline (AI), MITM detection |
| Counter | counter | Threat scan, rootkit detection, anomaly detection |
| Analyze | analyze | File forensics, hashes, strings, log analysis |
| OSINT | recon, adultscan, dossier, geoip, yandex_osint, snoop_decoder | Username scan (7K+ sites), dossier management, GEO IP, Yandex |
| Simulate | simulate | Port scan, password audit, payload generation |
| Core | agent, chat, agent_hal | Autonomous agent, LLM chat, AI-powered automation |
| Utility | nettest | Network speed and connectivity testing |

## Technology Stack

- **Language**: Python 3
- **LLM**: llama-cpp-python (local GGUF models), HuggingFace transformers (SafeTensors), Claude API
- **Databases**: SQLite (CVEs, sites), JSON (sessions, dossiers, configs)
- **Integrations**: Metasploit RPC (msgpack), NVD API v2.0, social-analyzer
- **OSINT Sources**: maigret, snoop, sherlock, blackbird, reveal-my-name, whatsmyname, detectdee, nexfil, cupidcr4wl, custom

---

## Session 7 - 2026-01-28: SafeTensors Model Support

### Overview

Added support for HuggingFace SafeTensors models alongside existing GGUF models. AUTARCH now supports three LLM backends:
1. **llama.cpp** - GGUF models (CPU-optimized, single file)
2. **transformers** - SafeTensors models (GPU-optimized, HuggingFace format)
3. **Claude API** - Anthropic's cloud API

### New Files

None - all changes were modifications to existing files.

### Modified Files

#### core/config.py
- Added `[transformers]` section to DEFAULT_CONFIG with settings:
  - `model_path`, `device`, `torch_dtype`
  - `load_in_8bit`, `load_in_4bit` (quantization options)
  - `trust_remote_code`
  - `max_tokens`, `temperature`, `top_p`, `top_k`, `repetition_penalty`
- Added `get_transformers_settings()` method

#### core/llm.py
- Added `TransformersLLM` class implementing same interface as `LLM`:
  - Uses HuggingFace `AutoModelForCausalLM` and `AutoTokenizer`
  - Supports automatic device detection (cuda/mps/cpu)
  - Supports 8-bit and 4-bit quantization via bitsandbytes
  - Supports streaming via `TextIteratorStreamer`
  - Uses tokenizer's `apply_chat_template` when available, falls back to ChatML
  - `_is_valid_model_dir()` validates SafeTensors directories
- Added `detect_model_type()` function to auto-detect model format:
  - Returns 'gguf' for GGUF files
  - Returns 'transformers' for SafeTensors directories
  - Returns 'unknown' for unrecognized formats
- Updated `get_llm()` to support 'transformers' backend

#### modules/setup.py
- Updated docstring to reflect multi-format support
- Rewrote `validate_model_path()` to return `(is_valid, model_type)` tuple
- Updated model path prompt to explain both formats
- Auto-detects model type and sets appropriate backend
- Added backend-specific configuration:
  - GGUF: Context size, threads, GPU layers
  - SafeTensors: Device selection, quantization options
- Updated summary display to show backend-specific settings

#### core/menu.py
- Updated `get_status_line()` to show model backend type
- Updated `show_llm_settings()` to display backend-specific settings
- Updated `_set_llm_model_path()` to auto-detect and switch backends
- Updated `_load_llm_model()` to handle both backends
- Added `_set_transformers_device()` for device configuration
- Added `_set_transformers_quantization()` for 8-bit/4-bit options
- Added `_switch_llm_backend()` to manually switch backends
- Updated `_set_llm_temperature()`, `_set_llm_sampling()`, `_set_llm_repeat_penalty()`, `_set_llm_max_tokens()` to work with both backends

### Configuration Format

New `autarch_settings.conf` section:
```ini
[transformers]
model_path = /path/to/model/directory
device = auto
torch_dtype = auto
load_in_8bit = false
load_in_4bit = false
trust_remote_code = false
max_tokens = 2048
temperature = 0.7
top_p = 0.9
top_k = 40
repetition_penalty = 1.1
```

### Usage

**Setup Wizard:**
```
Model path: /home/user/models/Lily-Cybersecurity-7B
SafeTensors model found: Lily-Cybersecurity-7B

Device Configuration (transformers)
Device [auto]: cuda
Quantization option [1]: 3  # 4-bit
```

**Settings Menu:**
- LLM Settings now shows backend-specific options
- [S] Switch Backend option to change between llama.cpp/transformers/Claude

### Dependencies

For SafeTensors support, users need:
```bash
pip install transformers torch
# Optional for quantization:
pip install bitsandbytes accelerate
```

### Notes

- Model type is auto-detected when path is provided
- Backend switches automatically when model path changes
- Quantization requires bitsandbytes package
- Device 'auto' uses CUDA if available, then MPS, then CPU
- SafeTensors models should be complete HuggingFace model directories with config.json

---

## Session 7b - 2026-01-28: Hardware Configuration Templates

### Overview

Added hardware-specific configuration templates and custom config save/load functionality to make LLM setup easier for different hardware configurations.

### New Files

#### .config/nvidia_4070_mobile.conf
Hardware template for NVIDIA GeForce RTX 4070 Mobile (8GB VRAM)
- n_gpu_layers = -1 (full GPU offload)
- n_ctx = 8192
- float16 dtype
- Suitable for 7B-13B models

#### .config/amd_rx6700xt.conf
Hardware template for AMD Radeon RX 6700 XT (12GB VRAM)
- Requires ROCm drivers and PyTorch ROCm build
- llama.cpp requires HIP/CLBlast build
- n_ctx = 8192
- Suitable for 7B-13B models at float16

#### .config/orangepi5plus_cpu.conf
Hardware template for Orange Pi 5 Plus (RK3588 SoC, CPU-only)
- n_threads = 4 (uses fast A76 cores only)
- n_gpu_layers = 0
- n_ctx = 2048 (conservative for RAM)
- Best with Q4_K_M quantized GGUF models

#### .config/orangepi5plus_mali.conf
**EXPERIMENTAL** template for Orange Pi 5 Plus with Mali-G610 GPU
- Attempts OpenCL acceleration via CLBlast
- n_gpu_layers = 8 (partial offload)
- Instructions for building llama.cpp with CLBlast
- May provide 20-30% speedup, but unstable

### Modified Files

#### core/config.py
- Added `get_templates_dir()` - returns `.config` directory path
- Added `get_custom_configs_dir()` - returns `.config/custom` directory path
- Added `list_hardware_templates()` - lists available hardware templates
- Added `list_custom_configs()` - lists user-saved custom configs
- Added `load_template(template_id)` - loads a hardware template
- Added `load_custom_config(filepath)` - loads a custom config file
- Added `_load_llm_settings_from_file()` - internal method to load llama/transformers sections
- Added `save_custom_config(name)` - saves current LLM settings to custom config
- Added `delete_custom_config(filepath)` - deletes a custom config file

#### core/menu.py
- Added `[T] Load Hardware Template` option in LLM Settings
- Added `[C] Load Custom Config` option in LLM Settings
- Added `[W] Save Current as Custom Config` option in LLM Settings
- Added `_load_hardware_template()` - UI for selecting hardware templates
- Added `_load_custom_config()` - UI for loading custom configs
- Added `_delete_custom_config()` - UI for deleting custom configs
- Added `_save_custom_config()` - UI for saving current settings

### Directory Structure

```
.config/
├── nvidia_4070_mobile.conf      # NVIDIA RTX 4070 Mobile template
├── amd_rx6700xt.conf            # AMD RX 6700 XT template
├── orangepi5plus_cpu.conf       # Orange Pi 5 Plus CPU template
├── orangepi5plus_mali.conf      # Orange Pi 5 Plus Mali (experimental)
└── custom/                      # User-saved custom configurations
    └── *.conf                   # Custom config files
```

### Usage

**Loading a Hardware Template:**
```
LLM Settings > [T] Load Hardware Template

Hardware Configuration Templates
Select a template optimized for your hardware

[1] NVIDIA RTX 4070 Mobile
    8GB VRAM, CUDA, optimal for 7B-13B models
[2] AMD Radeon RX 6700 XT
    12GB VRAM, ROCm, optimal for 7B-13B models
[3] Orange Pi 5 Plus (CPU)
    RK3588 ARM64, CPU-only, for quantized models
[4] Orange Pi 5 Plus (Mali GPU)
    EXPERIMENTAL - Mali-G610 OpenCL acceleration

Select template: 1
[+] Loaded template: NVIDIA RTX 4070 Mobile
    Note: Model path preserved from current config
```

**Saving Custom Configuration:**
```
LLM Settings > [W] Save Current as Custom Config

Save Custom Configuration
Save your current LLM settings for later use

Configuration name: My Gaming PC Settings
[+] Saved to: my_gaming_pc_settings.conf
    Full path: /home/snake/dh_framework/.config/custom/my_gaming_pc_settings.conf
```

**Loading Custom Configuration:**
```
LLM Settings > [C] Load Custom Config

Custom Configurations

[1] My Gaming Pc Settings
    my_gaming_pc_settings.conf

[D] Delete a custom config
[0] Cancel

Select config: 1
[+] Loaded config: My Gaming Pc Settings
```

### Template Details

| Template | GPU Layers | Context | Threads | Quantization | Target |
|----------|-----------|---------|---------|--------------|--------|
| NVIDIA 4070 Mobile | -1 (all) | 8192 | 8 | None/4-bit | 7B-13B |
| AMD RX 6700 XT | -1 (all) | 8192 | 8 | None/4-bit | 7B-13B |
| Orange Pi CPU | 0 | 2048 | 4 | Q4_K_M recommended | 7B Q4 |
| Orange Pi Mali | 8 | 2048 | 4 | 4-bit | 7B Q4 |

### Notes

- Templates preserve the current model path when loaded
- Custom configs are stored in `.config/custom/` directory
- Experimental templates show a warning before loading
- The Orange Pi Mali template requires additional setup (CLBlast, OpenCL drivers)
- AMD GPU support requires ROCm drivers and specially compiled PyTorch/llama.cpp

### Testing Notes

**Setup Wizard Test Run:**
- Successfully displays banner and welcome message
- Model format options (GGUF/SafeTensors) clearly explained
- Shows current configured model path as default
- Auto-detection of model type works when path is accessible

**Known Issue Found:**
- `PermissionError` when model path points to external drive that's not mounted or inaccessible
- The `validate_model_path()` function should handle permission errors gracefully
- Current behavior: crashes with traceback
- Suggested fix: wrap `path.exists()` in try/except for PermissionError

**Bug Location:** `modules/setup.py:119` - `validate_model_path()` method - **FIXED**

```python
# Fix applied - now handles permission errors gracefully:
try:
    if not path.exists():
        return False, None
except (PermissionError, OSError):
    return False, None
```

### Files Modified This Session

| File | Changes |
|------|---------|
| `core/config.py` | Added transformers section, template/custom config methods |
| `core/llm.py` | Added TransformersLLM class, detect_model_type() |
| `core/menu.py` | Updated LLM settings UI, added template/config options |
| `modules/setup.py` | Added SafeTensors support, auto-detection |
| `.config/*.conf` | Created 4 hardware templates |
| `devjournal.md` | Documented all changes |

### Additional Fixes Applied

**Path Resolution Enhancement:**
Added `resolve_model_path()` method to both `setup.py` and `menu.py` to handle various path formats:
- `/dh_framework/models/...` - common user mistake (missing /home/user)
- `models/ModelName` - relative to framework directory
- `ModelName` - just the model name (looks in models/ subdir)
- Full absolute paths

This makes model path entry more forgiving and user-friendly.

**Files Updated:**
- `modules/setup.py` - Added `resolve_model_path()` method
- `core/menu.py` - Added `_resolve_model_path()` method

### Git-LFS Model Files Note

The Lily-Cybersecurity-7B-v0.2 model in `models/` contains git-lfs pointer files, not actual model weights. Each `.safetensors` file is 135 bytes (pointer) instead of ~5GB (actual weights).

**Error when loading:**
```
Error while deserializing header: header too large
```

**Solution:**
```bash
cd models/Lily-Cybersecurity-7B-v0.2
git lfs pull
```

This will download the actual model files (~27GB total).

### Deprecation Warning

```
`torch_dtype` is deprecated! Use `dtype` instead!
```

This is a minor warning from newer transformers versions. The code still works correctly.

### HuggingFace Model ID Support

Added support for loading models by HuggingFace ID (e.g., `segolilylabs/Lily-Cybersecurity-7B-v0.2`) which loads from the HuggingFace cache (`~/.cache/huggingface/hub/`).

**Files Updated:**
- `core/llm.py` - TransformersLLM.load_model() now accepts HuggingFace model IDs
- `core/menu.py` - Added `_is_huggingface_id()` method, updated model path setting
- `modules/setup.py` - Added `_is_huggingface_id()` method, updated setup wizard

**Usage:**
```
Model path: segolilylabs/Lily-Cybersecurity-7B-v0.2
[+] HuggingFace model ID set: segolilylabs/Lily-Cybersecurity-7B-v0.2
    Model will be loaded from HuggingFace cache
```

### GGUF Tokenizer/Config Auto-Detection

Added automatic detection of tokenizer and config files when loading GGUF models. The loader now:
1. Searches for metadata files in the GGUF directory:
   - `tokenizer.json` - Full tokenizer definition
   - `tokenizer_config.json` - Tokenizer configuration and chat template
   - `special_tokens_map.json` - BOS, EOS, PAD, UNK token mappings
   - `config.json` - Model architecture config
2. If not found and GGUF is in a subdirectory like `guff/` or `gguf/`, checks parent directory
3. Detects chat format from tokenizer_config.json (chatml, llama-2, mistral-instruct, etc.)
4. Loads special tokens (bos_token, eos_token, pad_token, unk_token) for proper formatting
5. Passes detected chat_format to llama-cpp-python

**Files Updated:**
- `core/llm.py` - Added `_detect_chat_format()` method to LLM class
- LLM class now stores `_special_tokens`, `_chat_format`, `_metadata_dir`

**Supported Chat Formats:**
- `chatml` - ChatML format (Qwen, etc.)
- `llama-2` - Llama 2 format with [INST] tags
- `mistral-instruct` - Mistral instruction format
- `vicuna` - Vicuna format
- `alpaca` - Alpaca format
- `zephyr` - Zephyr format

**Special Tokens Loaded:**
- `bos_token` - Beginning of sequence (e.g., `<s>`)
- `eos_token` - End of sequence (e.g., `</s>`)
- `pad_token` - Padding token
- `unk_token` - Unknown token (e.g., `<unk>`)

**Example Output:**
```
[*] Loading model: model.Q4_K_M.gguf
    Context: 4096 | Threads: 4 | GPU Layers: 0
    Found model metadata in: Lily-Cybersecurity-7B-v0.2/
    Files: tokenizer.json, tokenizer_config.json, special_tokens_map.json, config.json
    Special tokens: bos_token=<s>, eos_token=</s>, pad_token=</s>, unk_token=<unk>
    Chat format: llama-2
[+] Model loaded successfully
```

### Next Steps

1. ~~Fix PermissionError handling in `validate_model_path()`~~ DONE
2. ~~Fix path resolution for relative/partial paths~~ DONE
3. ~~Add HuggingFace model ID support~~ DONE
4. ~~Add GGUF tokenizer/config auto-detection~~ DONE
5. Test hardware template loading via Settings menu
6. Test custom config save/load functionality
7. Download actual model files via `git lfs pull`
8. Verify SafeTensors model loading with actual model files
9. Test on Orange Pi 5 Plus hardware

---

## Session 8 - 2026-01-29: Metasploit Auto-Connect

### Overview

Added automatic Metasploit RPC server management on application startup. When AUTARCH starts, it now handles msfrpcd server lifecycle automatically.

### New Features

#### MSF Auto-Connect Flow

On startup, AUTARCH will:
1. **Scan** for existing msfrpcd server (socket + process detection)
2. **If found**: Kill the existing server, prompt for new credentials
3. **If not found**: Prompt for username/password
4. **Start** msfrpcd with the provided credentials
5. **Connect** to the new server

#### Command Line Options

```bash
# Skip autoconnect entirely
python autarch.py --no-msf

# Quick connect with credentials (non-interactive)
python autarch.py --msf-user msf --msf-pass secret
```

### Modified Files

#### core/msf.py

Added new imports: `socket`, `subprocess`, `time`, `os`, `signal`

**New MSFManager methods:**
- `detect_server() -> Tuple[bool, Optional[str]]` - Detect running msfrpcd via socket probe and process scan
- `_find_msfrpcd_pid() -> Optional[str]` - Find PID using pgrep or /proc scan
- `kill_server() -> bool` - Gracefully terminate msfrpcd (SIGTERM, then SIGKILL)
- `start_server(username, password, host, port, use_ssl) -> bool` - Launch msfrpcd and wait for port availability
- `autoconnect() -> bool` - Full interactive autoconnect flow with prompts
- `set_autoconnect(enabled: bool)` - Toggle autoconnect in config

**Updated methods:**
- `get_settings()` - Now includes `autoconnect` setting

**New standalone functions:**
- `msf_startup_autoconnect(skip_if_disabled)` - Entry point for startup autoconnect
- `msf_quick_connect(username, password, ...)` - Non-interactive server setup

#### autarch.py

**New command line arguments:**
- `--no-msf` - Skip Metasploit autoconnect on startup
- `--msf-user USER` - MSF RPC username for quick connect
- `--msf-pass PASS` - MSF RPC password for quick connect

**New function:**
- `msf_autoconnect(skip, username, password)` - Wrapper for MSF startup

**Modified:**
- `main()` - Now calls `msf_autoconnect()` after first-run check

**Updated epilog** with MSF autoconnect documentation.

#### core/menu.py

**Updated `show_msf_settings()`:**
- Shows server status (Running/Not Running with PID)
- Shows client connection status separately
- Shows autoconnect setting status
- New menu options:
  - `[4] Start Server` - Manually start msfrpcd
  - `[5] Stop Server` - Manually stop msfrpcd
  - `[6] Toggle Autoconnect` - Enable/disable autoconnect on startup

### Configuration

New setting in `autarch_settings.conf`:
```ini
[msf]
autoconnect = true
```

### Usage Examples

**Interactive startup (default):**
```
[*] Metasploit Auto-Connect
  ──────────────────────────────────────────

  Scanning for existing MSF RPC server...
  No existing server detected

  Configure MSF RPC Credentials
  These credentials will be used for the new server

    Username [msf]:
    Password (required): secret
    Host [127.0.0.1]:
    Port [55553]:
    Use SSL (y/n) [y]:

  Starting msfrpcd server...
  [+] Server started on 127.0.0.1:55553
  Connecting to server...
  [+] Connected to Metasploit 6.x.x
```

**With existing server:**
```
  Scanning for existing MSF RPC server...
  [!] Found existing msfrpcd server (PID: 12345)
  Stopping existing server...
  [+] Server stopped

  Configure MSF RPC Credentials
  ...
```

**Quick connect (scripting):**
```bash
python autarch.py --msf-user msf --msf-pass mypassword
```

### Technical Notes

- Server detection uses both socket probe (port check) and process scan (pgrep + /proc)
- Process termination uses SIGTERM first, falls back to SIGKILL after 1 second
- Server startup waits up to 30 seconds for port to become available
- SSL is enabled by default for msfrpcd connections
- Autoconnect can be disabled via settings menu or `--no-msf` flag

### Dependencies

- `msgpack` - Required for MSF RPC communication
- `msfrpcd` - Part of Metasploit Framework installation

### Bug Fix: msgpack Bytes vs Strings

**Issue:** Authentication was failing with "Authentication failed" even with correct credentials.

**Root Cause:** The `msgpack.unpackb()` function returns byte keys/values (e.g., `b'result'`) but the code was comparing against string keys (`"result"`).

**Fix:** Added normalization in `MetasploitRPC._request()` to decode byte keys/values to strings:
```python
result = msgpack.unpackb(response_data, raw=False, strict_map_key=False)
if isinstance(result, dict):
    result = {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in result.items()
    }
```

**Also improved:**
- Increased RPC initialization wait time from 2s to 5s
- Increased auth verification retries from 5 to 10
- Added helpful error message when auth fails suggesting to restart server

---

## Session 9 - 2026-02-03: MSF Module Search Fix

### Overview

Fixed critical bug where Metasploit modules were not appearing in searches or the Offense menu. The issue was caused by incomplete bytes-to-string decoding in the MSF RPC response handling.

### Root Cause

The `msgpack.unpackb()` function returns data with bytes keys/values. The previous fix only decoded the top-level dict, but MSF module searches return a **list of dicts**, where each inner dict still had bytes keys (e.g., `b'fullname'`, `b'type'`). This caused `dict.get('fullname')` to return `None` because the actual key was `b'fullname'`.

### Fixes Applied

#### 1. core/msf.py - Recursive Bytes Decoding

Added `_decode_bytes()` method that recursively decodes bytes throughout the entire response structure:

```python
def _decode_bytes(self, obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    elif isinstance(obj, dict):
        return {self._decode_bytes(k): self._decode_bytes(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [self._decode_bytes(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(self._decode_bytes(item) for item in obj)
    else:
        return obj
```

#### 2. core/msf.py - Fixed list_modules() API Method

The `list_modules()` method was calling `module.list` which doesn't exist. Changed to use correct MSF RPC API methods:

```python
type_to_method = {
    "exploit": "module.exploits",
    "auxiliary": "module.auxiliary",
    "post": "module.post",
    "payload": "module.payloads",
    "encoder": "module.encoders",
    "nop": "module.nops",
}
```

#### 3. modules/agent_hal.py - Use Centralized Interface

Agent Hal was bypassing `msf_interface.py` and creating its own `MetasploitRPC` instance. Updated to use `get_msf_interface()` so all MSF operations go through the centralized interface:

```python
def _ensure_msf_connected(self) -> bool:
    if self.msf is None:
        from core.msf_interface import get_msf_interface
        self.msf = get_msf_interface()
    connected, msg = self.msf.ensure_connected(auto_prompt=False)
    ...
```

Also updated `_execute_msf_module()` and `quick_scan_target()` to use `run_module()` instead of the non-existent `execute_module()`.

### Files Modified

| File | Changes |
|------|---------|
| core/msf.py | Added `_decode_bytes()`, fixed `list_modules()` API calls |
| modules/agent_hal.py | Switched to `get_msf_interface()`, updated method calls |

### Verification

```
=== MSF Interface Test ===
Search (eternalblue): 5 results
  - auxiliary/admin/smb/ms17_010_command
  - auxiliary/scanner/smb/smb_ms17_010
  - exploit/windows/smb/ms17_010_eternalblue
  - exploit/windows/smb/ms17_010_psexec
  - exploit/windows/smb/smb_doublepulsar_rce

List exploits: 2604 modules
Module info: SMB Version Detection ✓
```

### Architecture Note

All MSF operations now flow through `core/msf_interface.py`:
- `modules/msf.py` → uses `get_msf_interface()`
- `modules/agent_hal.py` → uses `get_msf_interface()`
- `modules/counter.py` → uses `get_msf_interface()`

This ensures any future fixes apply everywhere automatically.

---

## Session 10 - 2026-02-03: Offense Menu Overhaul

### Overview

Major overhaul of the MSF/Offense menu interface. Built foundation libraries for MSF option descriptions and module metadata, then completely rewrote the offense menu with improved UX.

### Phase 1a: MSF Settings Term Bank

Created `core/msf_terms.py` - centralized definitions for all MSF options.

**Features:**
- 54 MSF settings with full descriptions, examples, and notes
- 14 categories: target, local, auth, payload, connection, scan, session, database, output, smb, http, ssh, execution, file
- Validation functions for settings (IP validation, port validation, etc.)
- Prompt generation with defaults and help text

**API Functions:**
```python
from core.msf_terms import get_setting_info, get_setting_prompt, format_setting_help, validate_setting_value

info = get_setting_info('RHOSTS')  # Full setting metadata
prompt = get_setting_prompt('LPORT', default=4444)  # Input prompt with default
help_text = format_setting_help('PAYLOAD')  # Formatted help block
valid, msg = validate_setting_value('RHOSTS', '192.168.1.1')  # Validation
```

**Sample Settings:**
- RHOSTS, RHOST, RPORT, LHOST, LPORT, TARGETURI
- SMBUser, SMBPass, SMBDomain, HttpUsername, HttpPassword
- PAYLOAD, ENCODER, SESSION, DATABASE, OUTPUT

### Phase 1b: MSF Module Library

Created `core/msf_modules.py` - descriptions and metadata for common MSF modules.

**Features:**
- 45 modules documented: 25 scanners, 12 exploits, 4 post, 4 payloads
- Full metadata: name, description, author, CVE, platforms, arch, reliability
- Searchable by name, tags, type, platform
- Formatted help output for display

**API Functions:**
```python
from core.msf_modules import get_module_info, search_modules, get_modules_by_type, format_module_help

info = get_module_info('auxiliary/scanner/smb/smb_version')
results = search_modules('eternalblue')
scanners = get_modules_by_type('auxiliary')
help_text = format_module_help('exploit/windows/smb/ms17_010_eternalblue')
```

**Module Categories:**
- SMB scanners (smb_version, smb_enumshares, smb_ms17_010, etc.)
- SSH scanners (ssh_version, ssh_login)
- HTTP scanners (http_version, dir_scanner, etc.)
- FTP scanners and exploits
- Windows exploits (EternalBlue, BlueKeep, etc.)
- Post-exploitation modules
- Payload generators

### Phase 2: Offense Menu Rewrite

Completely rewrote `modules/msf.py` (v1.1 → v2.0) with new features:

**1. Global Target Settings**
- Pre-configure RHOSTS, LHOST, LPORT before browsing modules
- Settings persist across module selections
- Auto-filled when selecting modules
- Domain-to-IP resolution with confirmation
- Auto-detect LHOST from network interface

**2. Module Browser**
- Category-based navigation (Scanners, Exploits, Post, Payloads, Auxiliary)
- Pagination with 20 modules per page
- Two-column display for compact viewing
- Combines library modules + live MSF modules when connected

**3. Enhanced Module Details**
- Rich descriptions from module library
- CVE information, author, reliability rating
- Usage notes and warnings
- Option to fetch live info from MSF

**4. Streamlined Workflow**
```
Set Target [1] → Browse/Search [2/3] → Select Module → Configure → Run
```

**5. Quick Scan Improvements**
- Shows current target from global settings
- Uses pre-configured target automatically

### New Menu Structure

```
Metasploit Framework
──────────────────────────────────
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

### Target Configuration Screen

```
Target Configuration
  Set target and listener options before selecting modules
──────────────────────────────────

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

### Module Browser

```
Scanners
  Page 1 of 2 (25 modules)
──────────────────────────────────

  [ 1] SMB Version Scanner      [ 2] SMB Share Enumeration
  [ 3] SMB User Enumeration     [ 4] MS17-010 Vulnerability...
  [ 5] TCP Port Scanner         [ 6] SSH Version Scanner
  ...

  [N] Next page   [P] Previous   [0] Back
```

### Files Created/Modified

| File | Action | Description |
|------|--------|-------------|
| `core/msf_terms.py` | Created | MSF settings term bank (54 settings) |
| `core/msf_modules.py` | Created | MSF module library (45 modules) |
| `modules/msf.py` | Rewritten | Enhanced offense menu (v2.0) |

### Integration Points

The term bank and module library integrate with:
- `modules/msf.py` - Uses for help text and validation
- Future: `modules/agent_hal.py` - AI can reference descriptions
- Future: `core/pentest_pipeline.py` - Pipeline can use module metadata

### Architecture Benefits

1. **Centralized Knowledge** - Option descriptions and module info in one place
2. **Offline Documentation** - Help text available without MSF connection
3. **Consistent UX** - Same descriptions everywhere in the app
4. **Extensible** - Easy to add new settings and modules
5. **AI-Friendly** - Structured data for LLM context injection

---

## Session 11 - 2026-02-14: Nmap Scanner & Scan Monitor

Added two new tools: an Nmap scanner in the recon module and a real-time scan monitor in the defense module.

### Nmap Scanner (Recon)

- Menu entry `[X]` under Tools in OSINT menu
- Submenu with 9 scan types: Top 100, Quick, Full TCP, Stealth SYN, Service Detection, OS Detection, Vuln Scan, UDP, Custom
- Live-streaming output with color coding (green=open, dim=closed/filtered, cyan=scan headers)
- Open port summary after completion, optional save to file
- Tested on 127.0.0.1 - found 10 open ports in 0.05s

### Scan Monitor (Defense)

- Menu entry `[8]` in Defense module
- Uses `tcpdump` (with auto `sudo` elevation) to capture SYN-only packets in real-time
- Per-IP tracking with detection thresholds:
  - Port scan: 10+ unique ports in 30s
  - Brute force: 15+ connections to single port in 60s
- Counter-scan capability: auto-scans detected attacker IPs with nmap in daemon threads
- IP whitelisting and local IP auto-exclusion
- Logging to `results/scan_monitor.log`
- Stale entry pruning every 5s (120s TTL)
- Clean Ctrl+C shutdown with summary stats

### Files Modified

| File | Action | Description |
|------|--------|-------------|
| `modules/recon.py` | Modified | Added Nmap scanner (3 methods, menu entry, handler) |
| `modules/defender.py` | Modified | Added Scan Monitor (3 methods, 4 new imports, menu entry, handler) |

---

## Session 14 - 2026-02-15: Android Protection Shield (Phase 4.6)

### Overview

Built a comprehensive anti-stalkerware and anti-spyware module for Android devices. Uses the existing ADB infrastructure (`core/hardware.py`) to scan connected Android devices for surveillance threats — from commercial stalkerware (mSpy, FlexiSpy, Cocospy, etc.) to government-grade spyware (Pegasus, Predator, Hermit, FinSpy). Provides detection, analysis, and remediation capabilities.

### Architecture

The module follows AUTARCH's standard pattern: core singleton manager + CLI module + Flask blueprint + web template. All ADB operations delegate to `HardwareManager._run_adb()` to reuse existing device connectivity.

```
core/android_protect.py           # AndroidProtectManager singleton (~650 lines)
modules/android_protect.py        # CLI menu, CATEGORY=defense (~450 lines)
web/routes/android_protect.py     # Flask blueprint, 33 routes (~300 lines)
web/templates/android_protect.html # Web UI, 4 tabs (~500 lines)
data/stalkerware_signatures.json  # Threat signature database
```

### Threat Signature Database

`data/stalkerware_signatures.json` — JSON database with:
- **103 stalkerware families** with 275 package names (mSpy, FlexiSpy, Cocospy, XNSPY, Hoverwatch, KidsGuard Pro, Pegasus-adjacent RATs like SpyNote/DroidJack/AhMyth, APT spyware like VajraSpy/BadBazaar/GravityRAT, etc.)
- **10 government spyware families** with file, process, domain, and property indicators:
  - Pegasus (NSO Group), Predator (Cytrox/Intellexa), Hermit (RCS Lab), FinSpy (FinFisher), QuaDream REIGN, Candiru, Chrysaor, Exodus (eSurv), Phantom (Paragon), Dark Caracal
- **8 dangerous permission combos** (full_surveillance, communication_intercept, accessibility_spy, keylogger_behavior, call_intercept, etc.)
- **12 suspicious system package names** (packages mimicking Android system apps)
- **9 legitimate accessibility apps** (whitelist for TalkBack, Samsung, Google accessibility)
- Updatable from GitHub (AssoEchap/stalkerware-indicators community feed)

### Core Module: `core/android_protect.py`

`AndroidProtectManager` singleton with:

**Detection (11 scan types):**
- `scan_stalkerware()` — match installed packages against 275+ signatures
- `scan_hidden_apps()` — apps with no launcher icon (filtered from known system prefixes)
- `scan_device_admins()` — `dumpsys device_policy`, flag known-bad packages
- `scan_accessibility_services()` — enabled accessibility services, cross-ref whitelist
- `scan_notification_listeners()` — apps reading notifications, flag stalkerware
- `scan_usage_access()` — apps with usage stats permission
- `scan_spyware_indicators()` — government spyware file paths, processes, properties via ADB shell
- `scan_system_integrity()` — SELinux, verified boot, dm-verity, su binary, build fingerprint
- `scan_suspicious_processes()` — files in `/data/local/tmp/`, root processes from `/data/`
- `scan_certificates()` — user-installed CA certs in `/data/misc/user/0/cacerts-added/`
- `scan_network_config()` — HTTP proxy, DNS, private DNS, active VPN
- `scan_developer_options()` — USB debug, unknown sources, mock locations, OEM unlock

**Permission Analysis:**
- `analyze_app_permissions()` — full granted/denied breakdown from `dumpsys package`
- `find_dangerous_apps()` — match all non-system apps against 8 dangerous permission combos
- `permission_heatmap()` — matrix of 12 dangerous permissions across all apps

**Remediation:**
- `disable_threat()` — `pm disable-user`
- `uninstall_threat()` — `pm uninstall` (tries `--user 0` first, then without)
- `revoke_dangerous_perms()` — revokes 16 dangerous permissions
- `remove_device_admin()` — `dpm remove-active-admin` (auto-discovers component)
- `remove_ca_cert()` — removes user CA cert file
- `clear_proxy()` — clears HTTP proxy settings
- `disable_usb_debug()` — turns off ADB

**Composite Scans:**
- `quick_scan()` — stalkerware + device admins + accessibility (fast)
- `full_protection_scan()` — all 11 scans + permission analysis, returns comprehensive report
- `export_scan_report()` — saves JSON to `data/android_protect/<serial>/scans/`

**Shizuku/Shield Management:**
- Shizuku: install, start, stop, status (for privileged ops on non-rooted devices)
- Shield app: install, configure (broadcast intent), grant permissions, status query

### CLI Module: `modules/android_protect.py`

CATEGORY = "defense". Interactive menu with 30+ options organized in sections:
- Quick Actions (quick scan, full scan, export)
- Detection (11 individual scans)
- Permission Analysis (dangerous apps, per-app analysis, heatmap)
- Remediation (disable, uninstall, revoke, remove admin, remove cert, clear proxy)
- Shizuku & Shield (status, install, start, configure, permissions)
- Database (stats, update)
- Device selector with auto-pick for single device

### Web Blueprint: `web/routes/android_protect.py`

Blueprint `android_protect_bp` at `/android-protect/` with 33 routes:
- `GET /` — render template with status and signature stats
- `POST /scan/{quick,full,export,stalkerware,hidden,admins,accessibility,listeners,spyware,integrity,processes,certs,network,devopt}`
- `POST /perms/{dangerous,analyze,heatmap}`
- `POST /fix/{disable,uninstall,revoke,remove-admin,remove-cert,clear-proxy}`
- `POST /shizuku/{status,install,start}`
- `POST /shield/{status,install,configure,permissions}`
- `POST /db/{stats,update}`
- File upload support for Shizuku/Shield APK install routes

### Web Template: `web/templates/android_protect.html`

4-tab interface (Scan | Permissions | Remediate | Shizuku):
- **Scan tab**: Quick/Full scan buttons, 11 individual scan buttons, color-coded severity results (critical=red, high=orange, medium=yellow, low=green), severity badges, structured output for each scan type
- **Permissions tab**: Find Dangerous Apps, per-app analyzer (package name input), permission heatmap table with colored cells
- **Remediate tab**: Package input + disable/uninstall/revoke/remove-admin buttons, proxy clearing, CA cert list with per-cert remove buttons
- **Shizuku tab**: Shizuku status cards (installed/running/version), install APK (file upload), start service, Shield app status/install/permissions, signature DB stats and update

Device selector dropdown at top with refresh button, auto-populated from `/hardware/adb/devices`.

### Integration

- `web/app.py` — import + register `android_protect_bp` (15th blueprint)
- `web/templates/base.html` — "Shield" link added in Tools sidebar section (after iPhone Exploit)

### Files Created

| File | Lines | Description |
|------|-------|-------------|
| `data/stalkerware_signatures.json` | ~700 | 103 families, 275 packages, 10 govt spyware, 8 perm combos |
| `core/android_protect.py` | ~650 | AndroidProtectManager singleton |
| `modules/android_protect.py` | ~450 | CLI menu (defense category) |
| `web/routes/android_protect.py` | ~300 | Flask blueprint, 33 routes |
| `web/templates/android_protect.html` | ~500 | Web UI, 4 tabs |

### Files Modified

| File | Changes |
|------|---------|
| `web/app.py` | Import + register `android_protect_bp` |
| `web/templates/base.html` | Added "Shield" link in Tools sidebar |

### Verification

```
$ py_compile core/android_protect.py    ✓
$ py_compile modules/android_protect.py ✓
$ py_compile web/routes/android_protect.py ✓
$ Flask URL map: 33 routes under /android-protect/
$ autarch.py -l: [android_protect] listed under defense
$ Signature DB: 103 families, 275 packages, 10 govt spyware, 8 combos
```

---

## Session 11 - 2026-02-15: Tracking Honeypot

Added the Tracking Honeypot feature to the Android Protection Shield — feeds fake data to ad trackers (Google, Meta, Amazon, data brokers) while letting real apps function normally.

### Concept

3-tier protection system:
- **Tier 1 (ADB)**: Reset ad ID, opt out of tracking, ad-blocking DNS, disable WiFi/BT scanning
- **Tier 2 (Shizuku)**: Restrict tracker background data, revoke tracking perms, clear tracker data, force-stop trackers
- **Tier 3 (Root)**: Hosts file blocklist (2000+ domains), iptables redirect, fake GPS location, rotate device identity, fake device fingerprint

### Files Created

| File | Lines | Description |
|------|-------|-------------|
| `data/tracker_domains.json` | ~2500 | 2038 unique domains, 139 tracker packages, fake data templates |

### Files Extended

| File | Changes |
|------|---------|
| `core/android_protect.py` | +35 honeypot methods (helpers, status, detection, tier 1/2/3, composite, data mgmt) |
| `modules/android_protect.py` | +18 handler methods, menu items 70-87 in new "Tracking Honeypot" section |
| `web/routes/android_protect.py` | +28 routes under `/android-protect/honeypot/` |
| `web/templates/android_protect.html` | +5th "Honeypot" tab with 7 sections, ~20 JS functions |
| `autarch_dev.md` | Phase 4.7 status + feature documentation |

### Key Implementation Details

- Tracker DB: 5 categories (advertising, analytics, fingerprinting, social_tracking, data_brokers), 12 companies, 4 DNS providers
- Fake data templates: 35 locations (Eiffel Tower to Area 51), 42 absurd searches, 30 luxury purchases, 44 interests, 25 device models
- Per-device honeypot state persisted in `data/android_protect/<serial>/honeypot_config.json`
- Hosts blocklist uses same su/mount-remount pattern as android_exploit.py
- Composite activate/deactivate applies all protections for chosen tier and tracks state

### Verification

```
$ py_compile core/android_protect.py    OK
$ py_compile modules/android_protect.py OK
$ py_compile web/routes/android_protect.py OK
$ Flask URL map: 28 honeypot routes registered
$ Tracker stats: 2038 domains, 12 companies, 139 packages
$ Hosts generation: 2043 lines
```

---

## Session 15 - 2026-02-15: WireGuard VPN + Remote ADB (Phase 4.8)

Integrated WireGuard VPN management from `/home/snake/wg_setec/` into AUTARCH with added remote ADB support (TCP/IP and USB/IP over WireGuard tunnel).

### New Files

- **core/wireguard.py** - WireGuardManager singleton (~500 lines)
  - Server management: start/stop/restart via wg-quick, status via `wg show`
  - Key generation: `wg genkey`/`wg pubkey`/`wg genpsk`
  - Client CRUD: create/delete/toggle peers, JSON persistence in `data/wireguard/`
  - Config generation: client .conf files, QR codes via qrcode+Pillow
  - Remote ADB TCP/IP: connect/disconnect via WG tunnel IPs, auto-connect active peers
  - USB/IP: kernel module management, list/attach/detach remote USB devices
  - Import existing peers from wg0.conf
  - UPnP integration for port 51820/UDP

- **modules/wireguard_manager.py** - CLI menu (CATEGORY=defense, ~330 lines)
  - 18 menu actions: server, clients, ADB TCP/IP, USB/IP, config generation
  - Same interactive patterns as android_protect.py

- **web/routes/wireguard.py** - Flask blueprint, 25 routes (~200 lines)
  - `/wireguard/` prefix, all `@login_required`
  - Server, clients, ADB, USB/IP, UPnP route groups

- **web/templates/wireguard.html** - 4-tab web UI (~470 lines)
  - Dashboard: status cards, server controls, peer table
  - Clients: create form, client table with toggle/delete, detail view with config/QR
  - Remote ADB: TCP/IP connect/disconnect, USB/IP module management and device attach
  - Settings: import peers, refresh UPnP

### Modified Files

- **web/app.py** - Added `wireguard_bp` blueprint (16th blueprint)
- **web/templates/base.html** - Added WireGuard link in System nav section
- **autarch_settings.conf** - Added `[wireguard]` config section

### Architecture Decisions

- JSON storage (`data/wireguard/clients.json`) instead of SQLite — matches android_protect pattern
- Reuses AUTARCH auth (`@login_required`) instead of separate bcrypt auth from wg_setec
- `find_tool()` for binary lookup (wg, wg-quick, usbip, adb)
- Config from `autarch_settings.conf [wireguard]` section with sensible defaults
- USB/IP support: `vhci-hcd` kernel module + `usbip` CLI for importing remote USB devices over WG tunnel
- Peer config file modifications use `sudo tee` for permission handling

### Verification

```
$ py_compile core/wireguard.py              OK
$ py_compile modules/wireguard_manager.py   OK
$ py_compile web/routes/wireguard.py        OK
$ Flask URL map: 25 wireguard routes registered
$ WireGuardManager: wg=True, usbip=False, interface=wg0, subnet=10.1.0.0/24
```

---

## Session 16 - 2026-02-15: Archon Android Companion App (Phase 4.9)

Created the Android companion app framework "Archon" (Greek archon = ruler, root of "autarch").

### New: `autarch_companion/` — 29 files

- **com.darkhal.archon** — Kotlin Android app, Material Design 3, dark theme
- **Single Activity + Bottom Navigation** with 4 tabs:
  1. **Dashboard** — ADB TCP/IP toggle, USB/IP export, kill/restart ADB with auto-restart watchdog (5s interval), WireGuard tunnel status
  2. **Links** — 9-card grid linking to AUTARCH web UI sections via system browser
  3. **BBS** — Full-screen WebView loading local terminal HTML, Veilid-wasm placeholder, command system (help/connect/status/about/clear/version)
  4. **Settings** — Server IP, web/ADB/USB-IP ports, auto-restart toggle, BBS address, connection test (ping + TCP)

### Key Implementation Details

- **AdbManager.kt** — root shell commands: `setprop service.adb.tcp.port`, `stop adbd`, `start adbd`
- **UsbIpManager.kt** — `usbipd -D` daemon control, `usbip list -l` device listing
- **ShellExecutor.kt** — `Runtime.exec()` with timeout, root via `su -c`
- **PrefsManager.kt** — SharedPreferences wrapper for 6 config keys
- **BBS terminal** — HTML/CSS/JS with green-on-black monospace theme, command history (arrow keys), @JavascriptInterface bridge to native Android
- **Veilid strategy** — veilid-wasm in WebView (no official Kotlin SDK exists), placeholder until BBS VPS is deployed

### Architecture Decisions

- No third-party dependencies — only AndroidX + Material Design 3
- veilid-wasm in WebView chosen over JNI bindings (simpler, less maintenance)
- Root required for ADB/USB-IP control (standard for companion management apps)
- BBS has full local command system that works offline (help, about, version, status)
- Links open in system browser rather than embedded WebView (simpler, respects user browser choice)

### Build Config

- Gradle 8.5, AGP 8.2.2, Kotlin 1.9.22
- minSdk 26 (Android 8.0), targetSdk 34 (Android 14)
- Build requires Android Studio (no Android SDK on Orange Pi)

### Network Discovery (added same session)

Added auto-discovery so Archon finds AUTARCH servers without manual IP entry.

**Server (`core/discovery.py`):**
- mDNS: advertises `_autarch._tcp.local.` via Python `zeroconf` package
- Bluetooth: sets adapter name to "AUTARCH", enables discoverable, requires AUTH+ENCRYPT+SSP
- Auto-starts on Flask boot, 3 API routes for status/start/stop
- Config: `[discovery]` section in autarch_settings.conf

**App (`service/DiscoveryManager.kt`):**
- Scans via NSD (mDNS) + Wi-Fi Direct + Bluetooth in parallel
- Auto-configures server IP/port when found
- Dashboard: discovery card with SCAN button, auto-scans on launch
- Settings: AUTO-DETECT SERVER button fills in IP/port from scan

## Session 17 - 2026-02-15: HuggingFace Inference + MCP Server + Service Mode (Phase 4.10)

Continued from Session 16. Added 4 features: HuggingFace Inference API backend, MCP server, systemd service, and sideload companion app.

### HuggingFace Inference API
- `core/llm.py` — `HuggingFaceLLM` class using `huggingface_hub.InferenceClient`
- Text generation + chat completion with streaming support
- Config section `[huggingface]` in autarch_settings.conf
- `core/config.py` — `get_huggingface_settings()` method
- Web settings page + `/settings/llm` POST route for all 4 backends
- CLI menu: Switch Backend now shows 4 options (GGUF, SafeTensors, Claude, HuggingFace)
- Status line displays backend label for all 4 types

### MCP Server (Model Context Protocol)
- `core/mcp_server.py` — FastMCP server with 11 tools:
  nmap_scan, geoip_lookup, dns_lookup, whois_lookup, packet_capture,
  wireguard_status, upnp_status, system_info, llm_chat, android_devices, config_get
- Two transports: **stdio** (for Claude Desktop/Code) and **SSE** (for web clients)
- CLI: `python autarch.py --mcp [stdio|sse] --mcp-port 8081`
- Menu option [10]: Start/Stop SSE, Show Config Snippet, Run Stdio
- Web: 4 endpoints under `/settings/mcp/` (status, start, stop, config)
- Config snippet generator outputs JSON for Claude Desktop `mcpServers` config

### Systemd Service
- `scripts/autarch-web.service` — runs `autarch.py --web --no-banner`
- CLI: `python autarch.py --service [install|start|stop|restart|status|enable|disable]`
- Menu [8]: Full service management UI

### Sideload Companion App
- Menu [9]: Finds Archon APK in known locations, lists ADB devices, installs via `adb install -r`

### Web UI Overhaul (Settings Page)
- LLM section now shows all 4 backends with individual save+activate forms
- Each backend form has relevant settings fields
- MCP section with status/start/stop/config buttons and JSON output display

---

## Session 18 — 2026-02-15: Codebase Stub/Placeholder Audit

Full scan of all Python, Kotlin, JS, and HTML source for stubs, placeholders, and incomplete implementations.

### Genuine Stubs & Placeholders (TODO list)

#### 1. AUTARCH REST API (core/menu.py)
- **File:** `core/menu.py:2189-2314`
- **What:** `show_autarch_api()` — The API settings menu displays config (enable/disable, port, key) and lists endpoint documentation, but the endpoints themselves (`/api/v1/status`, `/api/v1/modules`, `/api/v1/scan`, `/api/v1/cve`, `/api/v1/agent/task`) are **not implemented** in the web routes. The docs page says "Endpoints (coming soon)" and "Full documentation will be available when the API is implemented in a future version."
- **Action needed:** Implement the REST API routes in `web/routes/` and connect them to core functionality. Alternatively, the MCP server may supersede this — decide whether both are needed.

#### 2. Veilid BBS — Archon Companion App (autarch_companion)
- **File:** `app/src/main/assets/bbs/veilid-bridge.js` (lines 28, 62, 85)
- **File:** `app/src/main/kotlin/com/darkhal/archon/ui/BbsFragment.kt` (line 72)
- **What:** The entire BBS tab is a placeholder framework. `VeilidBBS` class has stub `connect()`, `sendMessage()`, and `disconnect()` methods. The WebView loads a terminal UI but cannot actually connect to anything. The Kotlin side has a placeholder Veilid bootstrap config JSON.
- **Action needed:** Deploy an Autarch BBS server on a VPS, integrate `veilid-wasm` into the WebView assets, and wire up the connection protocol. This is blocked on the VPS/BBS server being built.

#### 3. Wi-Fi Direct Port Discovery (autarch_companion)
- **File:** `app/src/main/kotlin/com/darkhal/archon/service/DiscoveryManager.kt` (line 304)
- **What:** Wi-Fi Direct connection handler hardcodes port 8080 with comment "will be refined via mDNS or API call".
- **Action needed:** Minor — implement port discovery via mDNS `_autarch._tcp` service or a lightweight API handshake after Wi-Fi Direct connection is established.

### False Positives Excluded
- **HTML `placeholder=""` attributes** — Form input hints in web templates (normal HTML)
- **Pentest tree `NodeStatus.TODO`** — Legitimate pentest workflow status, not code stubs
- **`except: pass` blocks** — Normal exception swallowing in error handlers throughout codebase
- **`return []`/`return None`** — Normal error-path return values
- **"fake" references** — Legitimate anti-stalkerware/honeypot features (fake location, fake fingerprint)
- **`{username}` in osint.py** — URL template placeholder for OSINT site lookups
- **node_modules/ and build/ directories** — Third-party code, not ours

### Codebase Health Summary
The codebase is surprisingly clean. Only **3 genuine stub areas** found across ~50 source files:
1. REST API endpoints (menu config UI exists but no actual routes)
2. Veilid BBS (intentional — waiting on VPS server deployment)
3. Wi-Fi Direct port (minor hardcoded default)

---

## Session 15 - 2026-02-15: Archon Self-Contained Privilege Server & Module System

### Shizuku Replaced — Full Self-Containment

Removed all Shizuku dependencies. Archon now embeds its own privileged server process,
modeled after how Shizuku actually works internally (studied from their GitHub source).

**Thanks to Shizuku (RikkaApps/Shizuku)** — their open-source code was the guide for
understanding the `app_process` bootstrapping pattern. The technique of using
`CLASSPATH=<apk> /system/bin/app_process /system/bin <MainClass>` to run a Java class
at shell (UID 2000) privilege level is brilliant engineering. We studied their
`ServiceStarter.java`, `ShizukuService.java`, and `Starter.kt` to build our own
simplified version. Credit where credit is due.

### Architecture: Archon Privilege Server

```
App → ArchonClient (TCP socket) → ArchonServer (app_process, UID 2000)
```

- **ArchonServer.java** — Pure Java server, runs via `app_process` at shell level
  - TCP socket on localhost:17321, JSON protocol, token auth
  - Command blocklist for safety (rm -rf, mkfs, reboot, etc.)
  - Special commands: `__ping__`, `__shutdown__`, `__info__`
  - Logs to `/data/local/tmp/archon_server.log`

- **ArchonClient.kt** — App-side TCP client + bootstrap logic
  - Generates token, builds `app_process` command
  - Executes via LocalAdbClient (wireless debugging)
  - Manages server lifecycle (start/stop/ping)

- **Privilege chain:** ROOT → ARCHON_SERVER → LOCAL_ADB → SERVER_ADB → NONE

### Module System

Created a proper module system with interface + registry:

- **ArchonModule.kt** — Interface: id, name, actions, execute, status
- **ModuleManager.kt** — Singleton registry
- **ShieldModule.kt** — Anti-stalkerware/spyware (13 actions)
  - Package scanning against known stalkerware patterns
  - Permission auditing, device admin scanning, cert checking
  - Disable/uninstall/revoke actions through privilege chain
- **HoneypotModule.kt** — Anti-tracking (13 actions)
  - Tier 1 (ADB): reset ad ID, private DNS, disable scanning
  - Tier 2 (app-specific): restrict trackers, revoke perms
  - Tier 3 (root): hosts blocklist, iptables redirect, identity randomization

### UI Changes

- BBS tab → Modules tab (BBS was a placeholder for Veilid)
- Modules tab shows server status + Shield/Honeypot cards with action buttons
- Setup tab: removed Shizuku section, added Archon Server start/stop controls
- Flow: Wireless Debugging pair → Start Archon Server → Modules ready

### Files Changed
- New: `ArchonServer.java`, `ArchonClient.kt`, `ArchonModule.kt`, `ModuleManager.kt`,
  `ShieldModule.kt`, `HoneypotModule.kt`, `ModulesFragment.kt`, `fragment_modules.xml`
- Modified: `PrivilegeManager.kt`, `SetupFragment.kt`, `fragment_setup.xml`,
  `MainActivity.kt`, `build.gradle.kts`, `AndroidManifest.xml`, `bottom_nav.xml`,
  `nav_graph.xml`, `strings.xml`, `LocalAdbClient.kt`
- Deleted: `ShizukuManager.kt`, `BbsFragment.kt`, `fragment_bbs.xml`

### LocalAdbClient.kt Fix

Fixed pre-existing build errors with libadb-android v3.1.1 API:
- Replaced `sun.security.x509` cert generation (not available on Android)
  with pure DER/ASN.1 encoding — builds X.509 v3 certs from raw bytes
- Fixed `openStream()` → `openInputStream()` → `bufferedReader()` chain
- Created anonymous `AbsAdbConnectionManager` subclass with proper overrides

### Deep Dive: What Shell-Level (UID 2000) Can Actually Do

At UID 2000, we have access to a massive surface area that normal apps never touch.
This is the same privilege level as plugging in a USB cable and running `adb shell`.

#### System Commands Available at Shell Level

| Command | What It Does | Security Relevance |
|---------|-------------|-------------------|
| `pm` | Package manager — install, uninstall, disable, grant/revoke perms | Remove stalkerware, revoke spyware permissions |
| `am` | Activity manager — start activities, broadcast, force-stop | Kill malicious processes, trigger system actions |
| `settings` | Read/write system, secure, global settings | Change device identifiers, DNS, proxy, accessibility |
| `dumpsys` | Dump any system service state | Extract device policy, running processes, battery stats |
| `cmd` | Direct commands to system services | Control appops, jobscheduler, connectivity |
| `content` | Query/modify content providers | Read/write contacts, SMS, call log (for backup/wipe) |
| `service call` | Raw Binder IPC to system services | Clipboard access, service manipulation |
| `input` | Inject touch/key events | UI automation |
| `screencap` / `screenrecord` | Capture display | Evidence collection |
| `svc` | Control wifi, data, power, usb, nfc | USB lockdown, NFC control |
| `appops` | App operations management | Restrict background activity, sensors |
| `dpm` | Device policy manager | Remove device admins |
| `getprop` / `setprop` | System properties | Fingerprint spoofing, build info |
| `logcat` | System logs | Monitor for exploit indicators |
| `run-as` | Switch to debuggable app context | Access debuggable app data |
| `cmd wifi` | WiFi subsystem commands | List networks, saved passwords |

#### What Shell CANNOT Do (Root Required)

- Write to /system, /vendor, /product partitions
- `setenforce 0` (set SELinux permissive) — requires root/kernel
- Access other apps' /data/data/ directories directly
- Load/unload kernel modules
- iptables/nftables (requires CAP_NET_ADMIN)
- Mount/unmount filesystems
- Modify /dev nodes
- Write to /proc/sys/

---

### Exploitation Research: Creative Uses of Shell Access

#### 1. CVE-2024-0044 / CVE-2024-31317: Run-As Any UID (Android 12-14)

**This is the big one.** Disclosed by Meta security researchers.

The `run-as` command trusts package data from `/data/system/packages.list`. At shell
level, we can craft a malicious package entry that makes `run-as` switch to ANY UID,
including UID 0 (root) or UID 1000 (system). This effectively gives **temporary root**.

How it works:
1. Shell can write to `/data/local/tmp/`
2. Exploit the TOCTOU race in how `run-as` reads package info
3. `run-as` runs as UID 2000 but switches context to target UID
4. Patched in Android 14 QPR2 and Android 15, but many devices still vulnerable

**Impact:** Full root access on unpatched Android 12-14 devices.
**Archon action:** Add a detection module that checks if the device is vulnerable,
and if so, can use it for legitimate protection purposes (installing protective
system-level hooks that persist until reboot).

#### 2. Anti-Cellebrite / Anti-Forensic Module

Cellebrite UFED and similar forensic tools use several attack vectors:
- ADB exploitation (they need ADB enabled or exploit USB)
- Bootloader-level extraction
- Known CVE exploitation chains
- Content provider dumping

**What shell can do to defend:**

```
# USB Lockdown — disable all USB data modes
svc usb setFunctions charging
settings put global adb_enabled 0

# Monitor USB events in real-time
# (detect when forensic hardware connects)
cat /proc/bus/usb/devices  # USB device enumeration

# Detect Cellebrite-specific patterns:
# - Cellebrite identifies as specific USB vendor IDs
# - Known ADB command sequences (mass dumpsys, content query storms)
# - Rapid content provider enumeration

# Emergency data protection on forensic detection:
# - Revoke all app permissions
# - Clear clipboard
# - Force-stop sensitive apps
# - Disable USB debugging
# - Change lock to maximum security

# Feed disinformation via content providers:
# content insert --uri content://sms --bind address:s:fake --bind body:s:decoy
# (populate with convincing but fake data before surrendering device)
```

**Architecture for Archon:**
- Background monitoring thread watching USB events + logcat
- Known forensic tool USB vendor ID database
- Configurable responses: lockdown / alert / wipe sensitive / plant decoys
- "Duress PIN" concept: entering a specific PIN triggers data protection

#### 3. Anti-Pegasus / Anti-Zero-Click Module

NSO Group's Pegasus and similar state-level spyware use:
- Zero-click exploits via iMessage, WhatsApp, SMS
- Kernel exploits for persistence
- Memory-only implants (no files on disk)

**What shell can monitor:**

```
# Check for suspicious processes
dumpsys activity processes | grep -i "com.apple\|pegasus\|chrysaor"

# Monitor /proc for hidden processes
ls -la /proc/*/exe 2>/dev/null | grep -v "Permission denied"

# Check for unusual network connections
cat /proc/net/tcp6 | awk '{print $2}' # Active TCP6 connections
# Cross-reference with known Pegasus C2 IP ranges

# Check for memory-only implants
cat /proc/*/maps 2>/dev/null | grep -E "rwxp.*deleted"
# rwx+deleted mappings = code running from deleted files (classic implant pattern)

# Monitor for exploit indicators
logcat -d | grep -iE "exploit|overflow|heap|spray|jit|oat"

# Check for unauthorized root
ls -la /system/xbin/su /system/bin/su /sbin/su 2>/dev/null
getprop ro.debuggable
getprop ro.secure

# Check SELinux for permissive domains
cat /sys/fs/selinux/enforce  # 1=enforcing, 0=permissive

# Scan for known spyware artifacts
pm list packages | grep -iE "com\.network\.|com\.service\.|bridge|carrier"
# Pegasus uses innocuous-looking package names

# Check for certificate injection (MITM)
ls /data/misc/user/0/cacerts-added/ 2>/dev/null
# Spyware often installs CA certs for traffic interception
```

**Archon Shield integration:**
- Periodic background scans (configurable interval)
- Known C2 IP/domain database (updated from AUTARCH server)
- Process anomaly detection (unexpected UIDs, deleted exe links)
- Network connection monitoring against threat intel
- Alert system with severity levels

#### 4. Device Fingerprint Manipulation / Play Integrity

For making GrapheneOS appear as stock Android to Play Services:

```
# Android ID manipulation
settings put secure android_id $(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16)

# Build fingerprint spoofing (some writable via setprop)
setprop ro.build.fingerprint "google/raven/raven:14/UP1A.231005.007/10754064:user/release-keys"
setprop ro.product.model "Pixel 6 Pro"
setprop ro.product.manufacturer "Google"

# GSF (Google Services Framework) ID — stored in settings
settings put secure android_id <new_value>

# Keystore attestation is TEE-bound and cannot be spoofed at shell level
# BUT: Play Integrity has multiple levels:
#   - MEETS_BASIC_INTEGRITY: Can be satisfied with prop spoofing
#   - MEETS_DEVICE_INTEGRITY: Requires matching CTS profile
#   - MEETS_STRONG_INTEGRITY: Requires hardware attestation (impossible to fake)

# For BASIC integrity on GrapheneOS:
# Spoof enough props to pass CTS profile matching
# This is what Magisk's MagiskHide and Play Integrity Fix do

# Donor key approach: if we can obtain a valid attestation certificate chain
# from a donor device, we could theoretically replay it. BUT:
# - Keys are burned into TEE/SE at factory
# - Google revokes leaked keys quickly
# - This is legally/ethically complex

# More practical: use the "pretend to be old device" approach
# Older devices don't need hardware attestation
setprop ro.product.first_api_level 28  # Pretend we shipped with Android 9
```

#### 5. NFC on GrapheneOS

GrapheneOS restricts some NFC functionality for security:

```
# Enable NFC
svc nfc enable

# Set default HCE (Host Card Emulation) app
settings put secure nfc_payment_default_component com.darkhal.archon/.NfcPaymentService

# Check NFC adapter state
dumpsys nfc | grep -E "mState|mEnabled|mScreenState"

# The real issue: GrapheneOS blocks NFC in certain states
# At shell level we can:
# 1. Monitor NFC state changes
# 2. Re-enable NFC when GrapheneOS disables it
# 3. Set up a persistent watchdog that keeps NFC active

# For HCE apps that need to work on GrapheneOS:
# cmd nfc enable-reader-mode  # force reader mode
# settings put secure nfc_payment_foreground 1  # require foreground
```

#### 6. Temporary Root That Clears on Reboot

Multiple approaches possible at shell level:

**A. CVE exploitation (device-specific):**
- Scan for known unpatched vulns on the running kernel
- Exploit → get root → install temp hooks → hooks die on reboot
- Kernel version available via `uname -r`, match against CVE database

**B. Debuggable system app abuse:**
- `pm list packages -3` vs `pm list packages -s` — find system apps
- Check which are debuggable: `run-as <pkg> id`
- Debuggable system apps = system UID access via run-as

**C. Writable /data partition exploitation:**
- Shell owns /data/local/tmp/ fully
- Some init scripts read from /data/ locations
- On next boot, if we planted scripts, they could run at higher privilege
- BUT: SELinux contexts usually prevent this on modern Android

**D. `app_process` privilege chain:**
- Our ArchonServer already runs at shell level
- We can chain: ArchonServer → exploit → root process
- Root process creates a Unix socket
- ArchonServer proxies commands to root socket
- Root socket dies on reboot (no persistence)

#### 7. Key/Credential Extraction

```
# WiFi passwords (Android 10+)
cmd wifi list-networks  # List saved networks
# Full password extraction requires root on modern Android

# VPN credentials
dumpsys connectivity | grep -A5 "VPN"

# Account information
dumpsys account | grep -E "Account|name|type"

# Clipboard (potentially contains passwords)
service call clipboard 2 i32 1 i32 0  # getPrimaryClip (raw binder call)

# Accessibility service data (if any are running)
settings get secure enabled_accessibility_services
dumpsys accessibility

# Content provider queries (contacts, call log, SMS)
content query --uri content://call_log/calls --projection number:date:duration
content query --uri content://sms --projection address:body:date

# SharedPreferences of debuggable apps
for pkg in $(pm list packages -3 | cut -d: -f2); do
  run-as $pkg cat shared_prefs/*.xml 2>/dev/null && echo "=== $pkg ==="
done

# Bootloader state (informational, can't extract keys)
getprop ro.boot.verifiedbootstate  # green/yellow/orange/red
getprop ro.boot.flash.locked       # 1=locked, 0=unlocked
getprop ro.oem_unlock_supported    # OEM unlock availability
```

#### 8. SELinux Status and Manipulation

```
# Check current mode
getenforce  # Enforcing or Permissive

# List all SELinux domains
cat /sys/fs/selinux/policy | sesearch -A 2>/dev/null
# (sesearch not usually available, but we can pull the binary)

# Check for permissive domains (weak spots)
# On some ROMs, certain domains are permissive even when global is enforcing
cat /proc/1/attr/current  # init's SELinux context
cat /proc/self/attr/current  # our own context (u:r:shell:s0)

# SELinux audit log (shows what's being denied)
logcat -d -b events | grep avc
# These denials reveal what shell WOULD be able to do if SELinux were permissive

# On some kernels (esp. older or custom):
# setenforce 0  # Set permissive (requires root on stock, but some kernels allow shell)

# The most promising approach: find a domain transition
# If we can transition from shell context to a more permissive context,
# we gain capabilities without needing to disable SELinux globally
```

---

### New TODOs: On-Device AI Agent System

#### TODO 1: On-Device LLM with Agent/Tools (SmolChat + Koog)

**Goal:** Run a small LLM directly on the phone with tool-calling capabilities,
so the AI can autonomously execute security scans, manage trackers, and respond
to threats — completely offline, no cloud dependency.

**Research completed on two LLM engines:**

**SmolChat-Android** (https://github.com/shubham0204/SmolChat-Android)
- Apache 2.0, Kotlin + llama.cpp JNI
- Runs any GGUF model (huge ecosystem on HuggingFace)
- `smollm` module is an embeddable Android library — 2-class Kotlin API
- Auto-detects CPU SIMD (has ARMv8.4 SVE optimized builds)
- No tool-calling built in — we need to add that layer
- Streaming via Kotlin Flow, context tracking, chat templates from GGUF metadata
- **This is the inference engine to embed.**

**mllm** (https://github.com/UbiquitousLearning/mllm)
- MIT license, C++20 custom engine
- Supports multimodal (vision + text — Qwen2-VL, DeepSeek-OCR)
- Qualcomm QNN NPU acceleration (if device has Snapdragon)
- Custom `.mllm` format (must convert from HuggingFace, NOT GGUF)
- Much harder to integrate, but has NPU acceleration and vision
- **Consider for future multimodal features (OCR scanning, photo analysis).**

**Integration plan:**
1. Embed `smollm` module into Archon Companion
2. Bundle a small GGUF model (Qwen3-0.6B-Q4 or SmolLM3-3B-Q4)
3. Use Koog AI framework for the agent/tool layer (see TODO 3)
4. Define tools that map to our existing modules (ShieldModule, HoneypotModule)
5. LLM can autonomously: scan for threats, block trackers, respond to alerts
6. All processing stays on-device — zero network dependency

#### TODO 2: Copilot SDK for AUTARCH Server Agent (Research Bot)

**Goal:** Build a coding/research/chat agent for the AUTARCH server (Orange Pi)
that can use all 11 MCP tools, run security scans, and assist with analysis.

**Research completed on GitHub Copilot SDK** (https://github.com/github/copilot-sdk)
- MIT license (SDK), proprietary (CLI binary ~61MB)
- Python/TypeScript/Go/.NET SDKs
- BYOK mode: can use Ollama (local) — no GitHub subscription needed
- Has linux-arm64 binary — runs on Orange Pi directly
- MCP integration — can connect to our existing `core/mcp_server.py`
- Tool definitions, permission hooks, skills system
- Agent loop with planning and multi-step execution

**BUT:** The CLI binary is closed-source. We already have our own LLM backends
(local GGUF, transformers, claude, huggingface) and MCP server. The Copilot SDK
adds another orchestration layer on top of what we built.

**Alternative:** Build our own agent loop in Python using `core/llm.py` + `core/tools.py`.
We already have the infrastructure. Just need a better ReAct/planner loop.

**Decision:** Research further. The MCP integration is interesting but we may not
need the proprietary CLI binary. Our own agent system may be better.

#### TODO 3: Koog AI Agent Framework (For Archon Companion)

**Goal:** Use JetBrains' Koog framework to add a proper AI agent system to
the Archon Companion app — Kotlin-native, with tool-calling, memory, and
structured output.

**Research completed on Koog** (https://docs.koog.ai/)
- Apache 2.0, by JetBrains, pure Kotlin
- Kotlin Multiplatform — **officially supports Android**
- 9 LLM providers including Ollama (local) and cloud (OpenAI, Anthropic, etc.)
- First-class tool-calling with class-based tools (works on Android)
- Agent memory, persistence, checkpoints, history compression
- Structured output via kotlinx.serialization
- GOAP planner (A* search for action planning — game AI technique!)
- MCP integration (discover/use external tools)
- Multi-agent: agents-as-tools, agent-to-agent protocol
- Current version: 0.6.2

**Why Koog is the answer for Archon:**
- Native Kotlin — fits perfectly into our existing codebase
- `implementation("ai.koog:koog-agents:0.6.2")` — single Gradle dependency
- Class-based tools work on Android (no JVM reflection needed)
- Can point to Ollama on AUTARCH server for inference, or use cloud
- GOAP planner is perfect for security workflows:
  - Goal: "Protect device from tracking"
  - Actions: scan packages → identify trackers → restrict background → revoke perms
  - Planner finds optimal sequence automatically
- Memory system persists security scan results across sessions
- Structured output for scan reports, threat assessments

**Integration plan:**
1. Add Koog dependency to Archon Companion
2. Define security tools: ScanPackagesTool, RestrictTrackerTool, etc.
3. Wrap PrivilegeManager.execute() as the execution backend
4. Create "Security Guardian" agent with GOAP planner
5. Connect to AUTARCH server's Ollama for inference
6. Or embed SmolChat for fully offline operation
7. Agent can autonomously monitor and respond to threats

**Koog + SmolChat combo:**
- SmolChat provides the on-device inference engine (GGUF/llama.cpp)
- Koog provides the agent framework (tools, planning, memory, structured output)
- Together: fully autonomous, fully offline security AI agent on the phone

---

### SESSION SAVE — 2026-02-15 (end of session)

**What got done this session:**
- Phase 4.11 COMPLETE: Replaced Shizuku with self-contained ArchonServer
  - ArchonServer.java, ArchonClient.kt, module system, ShieldModule, HoneypotModule
  - BBS tab → Modules tab, Setup tab updated, all Shizuku refs removed
  - LocalAdbClient.kt fixed (DER/ASN.1 cert generation, libadb-android API fixes)
  - BUILD SUCCESSFUL
- Research completed: SmolChat, mllm, Koog AI, Copilot SDK, PhoneSploit-Pro, LinuxDroid
- Exploitation research written above (CVE-2024-0044, anti-Cellebrite, anti-Pegasus, etc.)

**What user wanted next (plan approved, code NOT started):**
1. Create `research.md` — consolidate ALL research findings
2. Reverse shell module (ArchonShell.java + ReverseShellModule.kt + AUTARCH listener)
3. `arish` — interactive shell like Shizuku's `rish`
4. Samsung S20/S21 section:
   - JTAG pinpoints and schematics
   - Bootloader weakness analysis
   - Secureboot partition dumping techniques
   - Donor key technique for NFC (user's own key, for GrapheneOS)
   - Hardening guides for S20/S21 specifically
   - Tool section for those phones
5. LLM suite addon (SmolChat + Koog, future phase)

**Plan file:** `/home/snake/.claude/plans/stateful-conjuring-moler.md`

**WHERE CLAUDE STOPPED CODING:**
- Was implementing Phase 4.11 (Shizuku replacement) — that part FINISHED and builds
- Then user asked for reverse shell module + research + Samsung guides
- Claude entered plan mode, wrote the plan, then GOT STUCK
- Kept looping on ExitPlanMode instead of coding
- Never started writing ANY code for Phase 5
- Never created research.md
- Never wrote ArchonShell.java, ReverseShellModule.kt, core/revshell.py, or any Phase 5 files
- The ONLY output was the plan file and the exploitation research notes above in devjournal
- All Phase 5 code is AT ZERO — nothing exists yet, start from scratch using the plan

**NOTE:** Claude malfunctioned — got stuck in plan mode loops, failed to respond
to multiple messages for extended periods (45+ min of nothing). User had to
repeatedly prompt. Claude also failed to acknowledge/respond to ~5 user messages
that came in while it was "processing". Do NOT repeat this behavior.

---

## Session 14 — 2026-02-28: MSF Web Runner, Agent Hal, Debug Console, LLM Settings Sub-Page

### Phase 4.12 — MSF Web Module Execution + Agent Hal + Global AI Chat

Wired Metasploit, the autonomous agent, and LLM chat into the web UI with live SSE streaming.

- **core/agent.py** — added `step_callback` param to `Agent.run()` for incremental SSE step streaming
- **web/routes/offense.py** — `POST /offense/module/run` streams MSF module output via SSE; `POST /offense/module/stop`
- **web/templates/offense.html** — Run Module tabs (SSH version/brute, TCP/SYN port scan, SMB OS detect, Custom) with live output + Stop; Agent Hal panel with SSE step stream
- **web/routes/msf.py** (NEW) — MSF RPC console at `/msf/` (connect, status, console/send)
- **web/templates/msf.html** (NEW) — dark terminal MSF console (status bar, terminal div, quick commands)
- **web/routes/chat.py** (NEW) — `/api/chat` SSE token stream, `/api/agent/run|stream|stop` background agent
- **web/templates/base.html** — global HAL chat panel (fixed bottom-right, 360×480), MSF Console sidebar link
- **web/static/js/app.js** — `halToggle/Send/Append/Scroll/Clear()`, full debug console JS
- **web/app.py** — registered msf_bp + chat_bp
- **web/static/css/style.css** — HAL panel + debug panel CSS + stream utility classes (.err/.success/.info/.warn/.dim)

### Phase 4.13 — Debug Console

Floating debug popup capturing all Python logging output, available on every page.

- `_DebugBufferHandler` captures root logger records into `collections.deque(maxlen=2000)`
- 4 server routes: toggle (enable/disable), stream (SSE), clear, test
- 5 client filter modes: Warnings & Errors | Full Verbose | Full Debug + Symbols | Output Only | Show Everything
- Draggable panel, level-colored output, pulsing live dot, localStorage persistence

### Phase 4.14 — WebUSB "Already In Use" Fix

- `adbDisconnect()` now releases USB interface (`await usbDev.close()`)
- `adbConnect()` detects Windows "already in use" errors, auto-retries once, shows "run adb kill-server" message

### Phase 4.15 — LLM Settings Sub-Page

Moved all LLM config to a dedicated sub-page at `/settings/llm`.

- 4 tabs: **Local** (llama.cpp GGUF + SafeTensors/Transformers), **Claude**, **OpenAI**, **HuggingFace**
- Local tab: folder browser → scan for model files → full parameter set (llama.cpp OR transformers depending on SafeTensors checkbox)
- HuggingFace tab: token login + verify, model ID, 8 provider options, custom endpoint, full generation params
- Added OpenAI backend support (`get_openai_settings()` in config.py)
- `POST /settings/llm/scan-models` → scans folder for .gguf/.ggml/.bin files and safetensors model directories

### Todos Added

- **System Tray** (pystray + PIL): icon in system tray with Server Menu (server options, default folder locations for tools/models, MSF RPC options — create/connect to msfrpcd)
- **Beta Release**: create `release/` folder, build EXE (PyInstaller) and MSI installer

---

## Session 15 — 2026-03-01: Hash Toolkit, Bugfixes

### Phase 4.16 — Hash Toolkit Sub-Page

Full Hash Toolkit added as a sub-page under Analyze (sidebar sub-item like Legendary Creator under Simulate).

- **43 hash pattern regexes** — pure Python hashid-style identification (no external deps)
- **6 tabs:** Identify (algorithm detection + threat intel links), File Hash (5 digests), Text Hash (all algorithms), Mutate (change file hash by appending bytes), Generate (create dummy files for testing), Reference (hash type table with hashcat modes)
- **Threat intel integration:** one-click lookups to VirusTotal, Hybrid Analysis, MalwareBazaar, AlienVault OTX, Shodan
- Routes added to existing `analyze_bp` — no new blueprint needed

### Bugfixes

- **`modules/analyze.py`** — wrapped `import magic` in try/except to prevent module load failure when python-magic not installed
- **Debug console** — `_initDebug()` now re-enables backend capture on page load (POST to `/settings/debug/toggle`) to survive server restarts
- **Android Protection Direct mode** — `apDirect()` was passing `HWDirect.adbShell()` result objects (dicts) into `raw` instead of extracting `.stdout` strings; Python `/parse` route then crashed calling `.strip()` on dicts. Fixed by extracting stdout before sending to server
- **`_serial()` hardened** — now checks `request.form` fallback and wraps in `str()` before `.strip()`

---

## Session 16 — 2026-03-01: Threat Monitor, Hal Agent, Windows Defense, LLM Trainer

### What got done this session:
- **7-tab Threat Monitor** — expanded from 4 tabs to 7 with Network Intel, Packet Capture, DDoS Mitigation
- **Drill-down popups** — click any stat in Live Monitor for detailed modal views
- **Hal Agent Mode** — Chat bubble now uses Agent system with `create_module` tool; can create modules on demand
- **System prompt** — `data/hal_system_prompt.txt` teaches Hal the codebase
- **Windows Defense** — `modules/defender_windows.py` + `defense_windows.html` (firewall, UAC, Defender AV, services, SSH, NTFS, event logs)
- **LLM Trainer** — `modules/llm_trainer.py` + `web/routes/llm_trainer.py` + `llm_trainer.html` (dataset management, training, adapters)
- **Refresh Modules** — sidebar button for hot-reloading modules without server restart

### Todos from session 14 resolved:
- System Tray → deferred to session 17
- Beta Release → deferred to session 17

---

## Session 17 — 2026-03-02: System Tray, Packaging, v1.5 Release

### What got done this session:
- **System tray** — `core/tray.py` with `TrayManager` (pystray + PIL): Start/Stop/Restart/Open Dashboard/Exit
- **Dual executables** — `autarch.exe` (CLI, console) + `autarch_web.exe` (Web, no console, tray icon)
- **PyInstaller frozen build fixes** — dual-directory pattern in `core/paths.py` (_BUNDLE_DIR vs _APP_DIR), module loading scans both bundled and user dirs
- **Installer scripts** — `installer.iss` (Inno Setup) + `installer.nsi` (NSIS)
- **Inno Setup OOM fix** — 3.9GB model stored uncompressed, `SolidCompression=no`
- **Inline critical CSS** — prevents white flash / FOUC on page load
- **All 27+ pages tested** — verified inline CSS, external stylesheet, layout structure
- **Version bumped to 1.5**
- **GitHub Release v1.5** — https://github.com/DigijEth/autarch/releases/tag/v1.5
  - `AUTARCH_Setup.exe` (34 MB) — installer without model
  - `AUTARCH_v1.5_Portable.zip` (39 MB) — portable without model

### SESSION SAVE — 2026-03-02 (end of session)

**Phase status:**
- Phases 0–4.24: DONE
- Phase 5 (Path portability): DONE (frozen build support complete)
- Phase 6 (Docker): NOT STARTED

**Key files created/modified this session:**
- `core/tray.py` (NEW) — TrayManager
- `autarch_web.py` (NEW) — Windowless web launcher
- `installer.iss` (NEW) — Inno Setup installer script
- `installer.nsi` (NEW) — NSIS installer script
- `core/paths.py` — Frozen build dual-directory pattern
- `core/menu.py` — Dual module directory scanning
- `web/app.py` — Frozen template/static path resolution
- `autarch.py` — --no-tray flag
- `autarch_public.spec` — Dual-exe MERGE/COLLECT
- `setup_msi.py` — Dual executables, v1.5
- `web/templates/base.html` — Inline critical CSS

**Todos from session 14 RESOLVED:**
- System Tray: DONE (core/tray.py)
- Beta Release: DONE (v1.5 on GitHub)

**Remaining work from master_plan.md:**
- Phase 6 (Docker): NOT STARTED
- Plan file (quizzical-toasting-mccarthy.md) — Threat Monitor + Hal Module Factory: DONE

