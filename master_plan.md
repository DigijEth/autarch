# AUTARCH Evolution Plan
## From CLI Framework to Full-Stack Security Platform

### Context

AUTARCH is currently a CLI-only Python security framework at `/home/snake/dh_framework/` with 20+ modules across 6 categories (Defense, Offense, Counter, Analyze, OSINT, Simulate), LLM integration (llama.cpp/transformers/Claude), Metasploit RPC integration, and an OSINT sites database with 7,200+ sites.

There is also a UPnP port forwarding script at `/home/snake/wg_setec/upnp-renew.sh` (using miniupnpc) that forwards ports 443/TCP, 51820/UDP, 8080/TCP but has **no cron job installed** despite being intended to run every 12 hours.

The goal is to evolve AUTARCH into a portable, cross-platform security platform with a web dashboard, advanced OSINT search engine, Wireshark integration, UPnP management, and Docker packaging -- while preserving the existing CLI interface.

---

## Phase 0: Backup & New Working Directory

**What:** Copy the codebase to `~/autarch`, excluding models (9GB).

**Steps:**
1. `mkdir ~/autarch`
2. `rsync -av --exclude='models/' --exclude='snoop/' --exclude='__pycache__/' /home/snake/dh_framework/ ~/autarch/`
3. Verify the copy: `ls ~/autarch/` and `du -sh ~/autarch/`
4. Switch working directory to `~/autarch`
5. `git init` in the new directory for version control going forward

**Files:** No code changes. Pure copy operation.

---

## Phase 1: UPnP Manager Integration

**What:** Integrate UPnP port forwarding management into AUTARCH with a config-driven approach and cron job management.

**New files:**
- `core/upnp.py` -- UPnP manager class wrapping `upnpc` (miniupnpc CLI)
- `modules/upnp_manager.py` -- CLI menu module (CATEGORY: defense)

**Changes to existing files:**
- `core/config.py` -- Add `[upnp]` config section with port mappings, internal IP, refresh interval
- `core/menu.py` -- No changes needed (module auto-discovered)

**`core/upnp.py` design:**
```python
class UPnPManager:
    def list_mappings()        # upnpc -l
    def add_mapping(internal_ip, internal_port, external_port, protocol, description)
    def remove_mapping(external_port, protocol)
    def refresh_all()          # Re-add all configured mappings
    def get_external_ip()      # upnpc -e
    def install_cron(interval_hours)   # Write crontab entry
    def uninstall_cron()       # Remove crontab entry
    def get_cron_status()      # Check if cron is active
    def load_mappings_from_config()
    def save_mappings_to_config()
```

**Config section:**
```ini
[upnp]
enabled = true
internal_ip = 10.0.0.26
refresh_hours = 12
mappings = 443:TCP,51820:UDP,8080:TCP
```

**CLI module menu:**
```
UPnP Port Manager
  [1] Show Current Mappings
  [2] Add Port Mapping
  [3] Remove Port Mapping
  [4] Refresh All Mappings
  [5] Show External IP
  [6] Cron Job Settings (currently: every 12h / not installed)
  [7] Edit Internal IP
  [0] Back
```

**Cron management:** Uses `subprocess` to read/write crontab via `crontab -l` and `crontab -` pipe. Adds entry like:
```
0 */12 * * * /usr/bin/python3 /home/snake/autarch/autarch.py --upnp-refresh > /dev/null 2>&1
```

**Also add to autarch.py:** `--upnp-refresh` CLI flag that calls `UPnPManager.refresh_all()` and exits (for cron use).

---

## Phase 2: Web UI Dashboard (Flask)

**What:** Add a Flask-based web dashboard running alongside the CLI. Reuse patterns from wg_setec (dark theme, session auth, template inheritance).

**New directory structure:**
```
~/autarch/
├── web/
│   ├── __init__.py
│   ├── app.py              # Flask app factory
│   ├── auth.py             # Login/session auth (from wg_setec pattern)
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── dashboard.py    # Main dashboard
│   │   ├── defense.py      # Defense tools page
│   │   ├── offense.py      # Offense tools page
│   │   ├── counter.py      # Counter-intel page
│   │   ├── analyze.py      # Analysis page
│   │   ├── osint.py        # OSINT search engine
│   │   ├── simulate.py     # Simulation page
│   │   ├── settings.py     # Settings management
│   │   ├── upnp.py         # UPnP management page
│   │   └── wireshark.py    # Wireshark page (Phase 4)
│   ├── templates/
│   │   ├── base.html       # Master template (dark theme, sidebar nav)
│   │   ├── login.html
│   │   ├── dashboard.html  # Overview with status cards
│   │   ├── defense.html
│   │   ├── offense.html
│   │   ├── counter.html
│   │   ├── analyze.html
│   │   ├── osint.html      # Advanced search UI
│   │   ├── simulate.html
│   │   ├── settings.html
│   │   ├── upnp.html
│   │   └── wireshark.html
│   └── static/
│       ├── css/style.css   # Dark theme (reuse wg_setec CSS variables)
│       └── js/app.js       # Vanilla JS for interactions
```

**Dashboard landing page shows:**
- System status cards (LLM loaded, MSF connected, UPnP active, services running)
- Quick action buttons for each category
- Recent activity/scan results
- Server info (hostname, IP, uptime)

**Each category page provides:**
- Module listing with descriptions
- Quick-launch buttons that trigger module functions via API
- Results display area
- Settings specific to that category

**Flask app startup:**
- Add `--web` flag to `autarch.py` to start web server
- Add `--web-port PORT` (default 8080)
- Web server runs in background thread or separate process
- Can run CLI and web simultaneously

**Authentication:**
- Session-based with bcrypt (same as wg_setec)
- Default admin/admin, forced password change on first login
- Config section `[web]` for port, host, secret_key

**Key reusable patterns from wg_setec:**
- CSS variables dark theme (`/home/snake/wg_setec/static/css/style.css`)
- Template inheritance (`/home/snake/wg_setec/templates/base.html`)
- Auth decorator (`/home/snake/wg_setec/auth.py`)
- Flash messages, status dots, data tables

---

## Phase 3: OSINT Search Engine (Web)

**What:** Build an advanced OSINT search interface in the web UI that surpasses the CLI capabilities.

**Route:** `web/routes/osint.py`
**Template:** `web/templates/osint.html`

**Search interface features:**
- Search box with type selector (username / email / phone / domain / IP)
- Category multi-select checkboxes (filter site categories)
- NSFW toggle
- Scan depth selector (Quick 100 / Standard 500 / Full 7000+)
- Advanced options panel:
  - Thread count slider
  - Timeout setting
  - User-agent selection
  - Proxy support field
  - Export format (JSON/HTML/CSV)

**Real-time results (Server-Sent Events):**
- `GET /osint/search/stream?username=X&...` -- SSE endpoint
- Progressive results as sites are checked
- Live progress bar (sites checked / total)
- Results appear in cards grouped by status (good/maybe/bad)
- Filter/sort results client-side

**Results display:**
- Card layout per found profile: site name, URL (clickable), confidence %, category badge
- Expandable detail: detection method, page title, response info
- Bulk actions: save to dossier, export, open all in new tabs
- Summary statistics bar chart

**Backend integration:**
- Reuses existing `modules/recon.py` scanning functions
- Reuses `core/sites_db.py` for site queries
- New `web/tasks.py` for async scan management (threading, not Celery -- keep it simple)

**Dossier management page:**
- List existing dossiers
- Create new dossier
- Link search results to dossier
- View/edit dossier details
- Export dossier as report

---

## Phase 4: Wireshark Module (tshark + pyshark)

**What:** Add packet capture and analysis capabilities using tshark CLI and pyshark Python library.

**New files:**
- `core/wireshark.py` -- tshark/pyshark wrapper class
- `modules/wireshark.py` -- CLI menu module (CATEGORY: analyze)
- `web/routes/wireshark.py` -- Web dashboard page

**`core/wireshark.py` design:**
```python
class WiresharkManager:
    def list_interfaces()          # tshark -D
    def start_capture(interface, filter, duration, output_file)
    def stop_capture()
    def get_capture_stats()
    def read_pcap(filepath)        # pyshark FileCapture
    def live_capture(interface, filter, callback)  # pyshark LiveCapture
    def get_protocol_hierarchy()   # Protocol distribution
    def extract_conversations()    # IP conversations
    def extract_dns_queries()      # DNS analysis
    def extract_http_requests()    # HTTP analysis
    def extract_credentials()      # Plain-text credential detection
    def apply_display_filter(capture, filter_string)
    def export_packets(capture, format)  # JSON/CSV export
```

**CLI module menu:**
```
Wireshark / Packet Analysis
  [1] List Interfaces
  [2] Start Live Capture
  [3] Open PCAP File
  [4] Protocol Analysis
  [5] Conversation Analysis
  [6] DNS Query Analysis
  [7] HTTP Traffic Analysis
  [8] Credential Detection
  [9] Export Results
  [0] Back
```

**Web UI features:**
- Interface selector dropdown
- Capture filter input (BPF syntax)
- Start/stop capture buttons
- Live packet stream (SSE)
- Protocol distribution pie chart
- Conversation table
- Packet detail view (expandable tree)
- PCAP file upload and analysis

**Dependencies:** `pyshark`, system `tshark` (part of Wireshark package)

---

## Phase 5: Path Portability & Windows Support

**What:** Make all paths relative/configurable, remove hardcoded paths, add Windows compatibility.

**Key changes:**

1. **Path resolution system** (`core/paths.py`):
```python
import platform, os
from pathlib import Path

def get_app_dir():
    """Returns the application root directory"""
    return Path(__file__).parent.parent

def get_data_dir():
    return get_app_dir() / 'data'

def get_config_path():
    return get_app_dir() / 'autarch_settings.conf'

def get_results_dir():
    return get_app_dir() / 'results'

def is_windows():
    return platform.system() == 'Windows'

def get_platform():
    return platform.system().lower()  # 'linux', 'windows', 'darwin'
```

2. **Audit all files for hardcoded paths:**
   - `core/config.py` -- WG paths, model paths
   - `core/msf.py` -- msfrpcd path
   - `core/upnp.py` -- upnpc path
   - `modules/*.py` -- any `/home/snake/` references
   - Replace all with `paths.get_*()` calls or config-driven paths

3. **Platform-specific tool detection:**
   - Check for `tshark`, `nmap`, `upnpc`, `wg`, `msfrpcd` availability
   - Graceful degradation when tools missing (disable features, show install instructions)
   - Windows: use `where` instead of `which`

4. **Cross-platform subprocess calls:**
   - Use `shutil.which()` for tool discovery
   - Use `pathlib.Path` everywhere instead of string concatenation
   - Handle Windows vs Unix shell differences

5. **Windows-specific considerations:**
   - `nmap` available on Windows (nmap.org installer)
   - `tshark` available on Windows (Wireshark installer)
   - `upnpc` available on Windows (miniupnpc builds)
   - Metasploit available via WSL or native Windows build
   - WireGuard available on Windows
   - No `sudo` -- use `ctypes.windll.shell32.IsUserAnAdmin()` check

---

## Phase 6: Docker Packaging

**What:** Create Docker configuration for portable deployment with all dependencies bundled.

**New files:**
```
~/autarch/
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
└── scripts/
    ├── entrypoint.sh      # Container startup script
    └── install-tools.sh   # Install nmap, tshark, upnpc, etc.
```

**Dockerfile approach:**
- Base: `python:3.11-slim`
- Install system tools: `nmap`, `tshark`, `miniupnpc`, `wireguard-tools`
- Install Python deps from `requirements.txt`
- Copy application code
- Expose ports: 8080 (web UI), 55553 (MSF RPC passthrough)
- Volume mounts: `/data` (persistent), `/models` (LLM models)
- Entrypoint: can start CLI, web, or both

**docker-compose.yml:**
```yaml
services:
  autarch:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/app/data
      - ./models:/app/models
      - ./results:/app/results
    environment:
      - AUTARCH_MODE=web  # or 'cli' or 'both'
    network_mode: host  # Needed for network scanning tools
```

**requirements.txt** (consolidated):
```
flask
bcrypt
pyshark
qrcode
Pillow
requests
llama-cpp-python  # optional
transformers      # optional
torch             # optional
anthropic         # optional
msgpack
```

---

## Execution Order

| Step | Phase | Effort | Description |
|------|-------|--------|-------------|
| 1 | Phase 0 | 5 min | Backup & create ~/autarch |
| 2 | Phase 1 | 1 session | UPnP manager + cron job management |
| 3 | Phase 2 | 2-3 sessions | Flask web dashboard skeleton + all pages |
| 4 | Phase 3 | 1-2 sessions | OSINT search engine with SSE streaming |
| 5 | Phase 4 | 1-2 sessions | Wireshark/tshark integration |
| 6 | Phase 5 | 1-2 sessions | Path portability + Windows support |
| 7 | Phase 6 | 1 session | Docker packaging |

**Each phase is self-contained and testable before moving to the next.**

---

## Verification Plan

After each phase:
1. **Phase 0:** `ls ~/autarch/` matches expected structure, `python3 ~/autarch/autarch.py --help` works
2. **Phase 1:** UPnP menu accessible, `upnpc -l` shows mappings, cron installs/uninstalls correctly
3. **Phase 2:** `python3 autarch.py --web` starts Flask on :8080, login works, all pages render, CLI still works independently
4. **Phase 3:** OSINT search returns results in web UI, SSE streaming shows live progress, results match CLI output
5. **Phase 4:** `tshark -D` lists interfaces from web UI, capture start/stop works, PCAP analysis shows results
6. **Phase 5:** No hardcoded paths remain (`grep -r '/home/snake' .` returns nothing), app runs from any directory
7. **Phase 6:** `docker-compose up` starts the app, web UI accessible, tools available inside container

---

## Critical Files Reference

| Existing File | Role | Reuse For |
|---|---|---|
| `/home/snake/wg_setec/static/css/style.css` | Dark theme CSS | Web UI base theme |
| `/home/snake/wg_setec/templates/base.html` | Template inheritance | Web UI base template |
| `/home/snake/wg_setec/auth.py` | bcrypt session auth | Web UI authentication |
| `/home/snake/wg_setec/upnp-renew.sh` | UPnP port script | Reference for port mappings |
| `core/config.py` | Config handler | Add [upnp], [web] sections |
| `core/sites_db.py` | Sites DB (7200+ sites) | OSINT search backend |
| `modules/recon.py` | OSINT scanner (2193 lines) | OSINT search engine backend |
| `core/menu.py` | Module discovery | Auto-discover new modules |
| `autarch.py` | Entry point | Add --web, --upnp-refresh flags |
