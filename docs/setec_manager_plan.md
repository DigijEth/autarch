# Setec App Manager — Architecture Plan

**A lightweight Plesk/cPanel replacement built in Go, designed to work with AUTARCH**

By darkHal Security Group & Setec Security Labs

---

## 1. What Is This?

Setec App Manager is a standalone Go application that turns a bare Debian 13 VPS into a fully managed web hosting platform. It provides:

- A **web dashboard** (its own HTTP server on port 9090) for managing the VPS
- **Multi-domain hosting** with Nginx reverse proxy management
- **Git-based deployment** (clone, pull, restart)
- **SSL/TLS automation** via Let's Encrypt (ACME)
- **AUTARCH-native integration** — first-class support for deploying and managing AUTARCH instances
- **System administration** — users, firewall, packages, monitoring, backups
- **Float Mode backend** — WebSocket bridge for AUTARCH Cloud Edition USB passthrough

It is NOT a general-purpose hosting panel. It is purpose-built for running AUTARCH and supporting web applications on a single VPS, with the lightest possible footprint.

---

## 2. Technology Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Go 1.22+ | Single binary, no runtime deps, fast |
| Web framework | `net/http` + `chi` router | Lightweight, stdlib-based |
| Templates | Go `html/template` | Built-in, secure, fast |
| Database | SQLite (via `modernc.org/sqlite`) | Zero-config, embedded, pure Go |
| Reverse proxy | Nginx (managed configs) | Battle-tested, performant |
| SSL | certbot / ACME (`golang.org/x/crypto/acme`) | Let's Encrypt automation |
| Auth | bcrypt + JWT sessions | Compatible with AUTARCH's credential format |
| Firewall | ufw / iptables (via exec) | Standard Debian tooling |
| Process mgmt | systemd (unit generation) | Native Debian service management |
| WebSocket | `gorilla/websocket` | For Float Mode USB bridge + live logs |

---

## 3. Directory Structure

```
/opt/setec-manager/
├── setec-manager              # Single Go binary
├── config.yaml                # Manager configuration
├── data/
│   ├── setec.db               # SQLite database (sites, users, logs, jobs)
│   ├── credentials.json       # Admin credentials (bcrypt)
│   └── acme/                  # Let's Encrypt account + certs
├── templates/                 # Embedded HTML templates (via embed.FS)
├── static/                    # Embedded CSS/JS assets
└── nginx/
    ├── sites-available/       # Generated per-domain configs
    └── snippets/              # Shared SSL/proxy snippets
```

**Managed directories on the VPS:**

```
/var/www/                      # Web applications root
├── autarch/                   # AUTARCH instance (cloned from git)
├── example.com/               # Static site or app
└── api.example.com/           # Another app
/etc/nginx/
├── sites-available/           # Setec-generated Nginx configs
├── sites-enabled/             # Symlinks to active sites
└── snippets/
    ├── ssl-params.conf        # Shared SSL settings
    └── proxy-params.conf      # Shared proxy headers
/etc/systemd/system/
├── setec-manager.service      # Manager itself
├── autarch-web.service        # AUTARCH web service
├── autarch-dns.service        # AUTARCH DNS service
└── app-*.service              # Per-app service units
```

---

## 4. Database Schema

```sql
-- Sites / domains managed by the panel
CREATE TABLE sites (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain        TEXT NOT NULL UNIQUE,
    aliases       TEXT DEFAULT '',              -- comma-separated alt domains
    app_type      TEXT NOT NULL DEFAULT 'static', -- 'static', 'reverse_proxy', 'autarch', 'python', 'node'
    app_root      TEXT NOT NULL,                -- /var/www/domain.com
    app_port      INTEGER DEFAULT 0,           -- backend port (for reverse proxy)
    app_entry     TEXT DEFAULT '',              -- entry point (e.g., autarch_web.py, server.js)
    git_repo      TEXT DEFAULT '',              -- git clone URL
    git_branch    TEXT DEFAULT 'main',
    ssl_enabled   BOOLEAN DEFAULT FALSE,
    ssl_cert_path TEXT DEFAULT '',
    ssl_key_path  TEXT DEFAULT '',
    ssl_auto      BOOLEAN DEFAULT TRUE,        -- auto Let's Encrypt
    enabled       BOOLEAN DEFAULT TRUE,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- System users (for SSH/SFTP access)
CREATE TABLE system_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    uid           INTEGER,
    home_dir      TEXT,
    shell         TEXT DEFAULT '/bin/bash',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Manager users (web panel login)
CREATE TABLE manager_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT DEFAULT 'admin',          -- 'admin', 'viewer'
    force_change  BOOLEAN DEFAULT FALSE,
    last_login    DATETIME,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Deployment history
CREATE TABLE deployments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER REFERENCES sites(id),
    action        TEXT NOT NULL,                 -- 'clone', 'pull', 'restart', 'ssl_renew'
    status        TEXT DEFAULT 'pending',        -- 'pending', 'running', 'success', 'failed'
    output        TEXT DEFAULT '',
    started_at    DATETIME,
    finished_at   DATETIME
);

-- Scheduled jobs (SSL renewal, backups, git pull)
CREATE TABLE cron_jobs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER REFERENCES sites(id),  -- NULL for system jobs
    job_type      TEXT NOT NULL,                 -- 'ssl_renew', 'backup', 'git_pull', 'restart'
    schedule      TEXT NOT NULL,                 -- cron expression
    enabled       BOOLEAN DEFAULT TRUE,
    last_run      DATETIME,
    next_run      DATETIME
);

-- Firewall rules
CREATE TABLE firewall_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    direction     TEXT DEFAULT 'in',             -- 'in', 'out'
    protocol      TEXT DEFAULT 'tcp',
    port          TEXT NOT NULL,                 -- '80', '443', '8181', '80,443', '1000:2000'
    source        TEXT DEFAULT 'any',
    action        TEXT DEFAULT 'allow',          -- 'allow', 'deny'
    comment       TEXT DEFAULT '',
    enabled       BOOLEAN DEFAULT TRUE
);

-- Float Mode sessions (AUTARCH Cloud Edition)
CREATE TABLE float_sessions (
    id            TEXT PRIMARY KEY,              -- UUID session token
    user_id       INTEGER REFERENCES manager_users(id),
    client_ip     TEXT,
    client_agent  TEXT,                          -- browser user-agent
    usb_bridge    BOOLEAN DEFAULT FALSE,         -- USB passthrough active
    connected_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_ping     DATETIME,
    expires_at    DATETIME
);

-- Backups
CREATE TABLE backups (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id       INTEGER REFERENCES sites(id),  -- NULL for full system backup
    backup_type   TEXT DEFAULT 'site',           -- 'site', 'database', 'full'
    file_path     TEXT NOT NULL,
    size_bytes    INTEGER DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

---

## 5. Web Dashboard Routes

### 5.1 Authentication
```
GET  /login                   → Login page
POST /login                   → Authenticate (returns JWT cookie)
POST /logout                  → Clear session
GET  /api/auth/status         → Current user info
```

### 5.2 Dashboard
```
GET  /                        → Dashboard overview (system stats, sites, services)
GET  /api/system/info         → CPU, RAM, disk, uptime, load
GET  /api/system/processes    → Top processes by resource usage
```

### 5.3 Site Management
```
GET  /sites                   → Site list page
GET  /sites/new               → New site form
POST /sites                   → Create site (clone repo, generate nginx config, enable)
GET  /sites/:id               → Site detail / edit
PUT  /sites/:id               → Update site config
DELETE /sites/:id             → Remove site (disable nginx, optionally delete files)
POST /sites/:id/deploy        → Git pull + restart
POST /sites/:id/restart       → Restart app service
POST /sites/:id/stop          → Stop app service
POST /sites/:id/start         → Start app service
GET  /sites/:id/logs          → View app logs (journalctl stream)
GET  /sites/:id/logs/stream   → SSE live log stream
```

### 5.4 AUTARCH Management
```
POST /autarch/install         → Clone from git, setup venv, install deps
POST /autarch/update          → Git pull + pip install + restart
GET  /autarch/status          → Service status, version, config
POST /autarch/start           → Start AUTARCH web + DNS
POST /autarch/stop            → Stop all AUTARCH services
POST /autarch/restart         → Restart all AUTARCH services
GET  /autarch/config          → Read autarch_settings.conf
PUT  /autarch/config          → Update autarch_settings.conf
POST /autarch/dns/build       → Build DNS server from source
```

### 5.5 SSL / Certificates
```
GET  /ssl                     → Certificate overview
POST /ssl/:domain/issue       → Issue Let's Encrypt cert (ACME)
POST /ssl/:domain/renew       → Renew cert
POST /ssl/:domain/upload      → Upload custom cert + key
DELETE /ssl/:domain           → Remove cert
GET  /api/ssl/status          → All cert statuses + expiry dates
```

### 5.6 Nginx Management
```
GET  /nginx/status            → Nginx service status + config test
POST /nginx/reload            → Reload nginx (graceful)
POST /nginx/restart           → Restart nginx
GET  /nginx/config/:domain    → View generated config
PUT  /nginx/config/:domain    → Edit config (with validation)
POST /nginx/test              → nginx -t (config syntax check)
```

### 5.7 Firewall
```
GET  /firewall                → Rule list + status
POST /firewall/rules          → Add rule
DELETE /firewall/rules/:id    → Remove rule
POST /firewall/enable         → Enable firewall (ufw enable)
POST /firewall/disable        → Disable firewall
GET  /api/firewall/status     → Current rules + status JSON
```

### 5.8 System Users
```
GET  /users                   → System user list
POST /users                   → Create system user (useradd)
DELETE /users/:id             → Remove system user
POST /users/:id/password      → Reset password
POST /users/:id/ssh-key       → Add SSH public key
```

### 5.9 Panel Users
```
GET  /panel/users             → Manager user list
POST /panel/users             → Create panel user
PUT  /panel/users/:id         → Update (role, password)
DELETE /panel/users/:id       → Remove
```

### 5.10 Backups
```
GET  /backups                 → Backup list
POST /backups/site/:id        → Backup specific site (tar.gz)
POST /backups/full            → Full system backup
POST /backups/:id/restore     → Restore from backup
DELETE /backups/:id           → Delete backup file
GET  /backups/:id/download    → Download backup archive
```

### 5.11 Monitoring
```
GET  /monitor                 → System monitoring page
GET  /api/monitor/cpu         → CPU usage (1s sample)
GET  /api/monitor/memory      → Memory usage
GET  /api/monitor/disk        → Disk usage per mount
GET  /api/monitor/network     → Network I/O stats
GET  /api/monitor/services    → Service status list
WS   /api/monitor/live        → WebSocket live stats stream (1s interval)
```

### 5.12 Float Mode Backend
```
POST /float/register          → Register Float client (returns session token)
WS   /float/bridge/:session   → WebSocket USB bridge (binary frames)
GET  /float/sessions          → Active Float sessions
DELETE /float/sessions/:id    → Disconnect Float session
POST /float/usb/enumerate     → List USB devices on connected client
POST /float/usb/open          → Open USB device on client
POST /float/usb/close         → Close USB device on client
POST /float/usb/transfer      → USB bulk/interrupt transfer via bridge
```

### 5.13 Logs
```
GET  /logs                    → Log viewer page
GET  /api/logs/system         → System logs (journalctl)
GET  /api/logs/nginx          → Nginx access + error logs
GET  /api/logs/setec          → Manager logs
GET  /api/logs/stream         → SSE live log stream (filterable)
```

---

## 6. Core Features Detail

### 6.1 Site Deployment Flow

When creating a new site:

```
1. User submits: domain, git_repo (optional), app_type, app_port
2. Manager:
   a. Creates /var/www/<domain>/
   b. If git_repo: git clone <repo> /var/www/<domain>
   c. If python app: creates venv, pip install -r requirements.txt
   d. If node app: npm install
   e. Generates Nginx config from template
   f. Writes to /etc/nginx/sites-available/<domain>
   g. Symlinks to sites-enabled/
   h. If ssl_auto: runs ACME cert issuance
   i. Generates systemd unit for the app
   j. Starts the app service
   k. Reloads nginx
   l. Records deployment in database
```

### 6.2 AUTARCH Install Flow

```
1. git clone https://github.com/DigijEth/autarch.git /var/www/autarch
2. chown -R autarch:autarch /var/www/autarch
3. python3 -m venv /var/www/autarch/venv
4. /var/www/autarch/venv/bin/pip install -r /var/www/autarch/requirements.txt
5. npm install (in /var/www/autarch for hardware JS bundles)
6. bash /var/www/autarch/scripts/build-hw-libs.sh
7. Copy default autarch_settings.conf → update web.host/port, web.secret_key
8. Generate systemd units (autarch-web, autarch-dns)
9. Generate Nginx reverse proxy config (domain → localhost:8181)
10. Issue SSL cert
11. Enable + start services
12. Record deployment
```

### 6.3 Nginx Config Templates

**Reverse Proxy (AUTARCH / Python / Node):**
```nginx
server {
    listen 80;
    server_name {{.Domain}} {{.Aliases}};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name {{.Domain}} {{.Aliases}};

    ssl_certificate     {{.SSLCertPath}};
    ssl_certificate_key {{.SSLKeyPath}};
    include snippets/ssl-params.conf;

    location / {
        proxy_pass https://127.0.0.1:{{.AppPort}};
        include snippets/proxy-params.conf;
    }

    # WebSocket support (for AUTARCH SSE/WebSocket)
    location /api/ {
        proxy_pass https://127.0.0.1:{{.AppPort}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
        include snippets/proxy-params.conf;
    }
}
```

**Static Site:**
```nginx
server {
    listen 443 ssl http2;
    server_name {{.Domain}};
    root {{.AppRoot}};
    index index.html;

    ssl_certificate     {{.SSLCertPath}};
    ssl_certificate_key {{.SSLKeyPath}};
    include snippets/ssl-params.conf;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

### 6.4 Firewall Default Rules

On first setup, Setec Manager installs these ufw rules:

```
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 80/tcp    comment "HTTP"
ufw allow 443/tcp   comment "HTTPS"
ufw allow 9090/tcp  comment "Setec Manager"
ufw allow 8181/tcp  comment "AUTARCH Web"
ufw allow 53        comment "AUTARCH DNS"
ufw enable
```

### 6.5 Float Mode USB Bridge

The Float Mode bridge is the backend half of AUTARCH Cloud Edition's USB passthrough. It works as follows:

```
┌──────────────────┐     WebSocket      ┌──────────────────┐
│  User's Browser  │◄──────────────────►│  Setec Manager   │
│  (AUTARCH CE)    │                    │  (VPS)           │
└────────┬─────────┘                    └────────┬─────────┘
         │                                       │
         │  Float Applet                         │  USB Commands
         │  (runs on user's PC)                  │  forwarded to
         │                                       │  AUTARCH modules
┌────────▼─────────┐                    ┌────────▼─────────┐
│  WebSocket Client │                    │  AUTARCH Backend │
│  + USB Access     │                    │  (hardware.py    │
│  (native app)     │                    │   equivalent)    │
└────────┬─────────┘                    └──────────────────┘
         │
    ┌────▼────┐
    │ USB Hub │ ← Physical devices (phones, ESP32, etc.)
    └─────────┘
```

**Protocol:**
1. Float applet on user's PC opens WebSocket to `wss://domain/float/bridge/<session>`
2. Manager authenticates session token
3. Binary WebSocket frames carry USB commands and data:
   - Frame type byte: `0x01` = enumerate, `0x02` = open, `0x03` = close, `0x04` = transfer
   - Payload: device descriptor, endpoint, data
4. Manager translates USB operations into AUTARCH hardware module calls
5. Results flow back over the same WebSocket

This is the **server side only**. The client applet is designed in `autarch_float.md`.

---

## 7. Go Package Structure

```
services/setec-manager/
├── cmd/
│   └── main.go                    # Entry point, flag parsing
├── internal/
│   ├── server/
│   │   ├── server.go              # HTTP server setup, middleware, router
│   │   ├── auth.go                # JWT auth, login/logout handlers
│   │   └── middleware.go          # Logging, auth check, CORS
│   ├── handlers/
│   │   ├── dashboard.go           # Dashboard + system info
│   │   ├── sites.go               # Site CRUD + deployment
│   │   ├── autarch.go             # AUTARCH-specific management
│   │   ├── ssl.go                 # Certificate management
│   │   ├── nginx.go               # Nginx config + control
│   │   ├── firewall.go            # ufw rule management
│   │   ├── users.go               # System + panel user management
│   │   ├── backups.go             # Backup/restore operations
│   │   ├── monitor.go             # System monitoring + WebSocket stream
│   │   ├── logs.go                # Log viewer + SSE stream
│   │   └── float.go               # Float Mode WebSocket bridge
│   ├── nginx/
│   │   ├── config.go              # Nginx config generation
│   │   ├── templates.go           # Go templates for nginx configs
│   │   └── control.go             # nginx reload/restart/test
│   ├── acme/
│   │   └── acme.go                # Let's Encrypt ACME client
│   ├── deploy/
│   │   ├── git.go                 # Git clone/pull operations
│   │   ├── python.go              # Python venv + pip setup
│   │   ├── node.go                # npm install
│   │   └── systemd.go             # Service unit generation + control
│   ├── system/
│   │   ├── info.go                # CPU, RAM, disk, network stats
│   │   ├── firewall.go            # ufw wrapper
│   │   ├── users.go               # useradd/userdel/passwd wrappers
│   │   └── packages.go            # apt wrapper
│   ├── db/
│   │   ├── db.go                  # SQLite connection + migrations
│   │   ├── sites.go               # Site queries
│   │   ├── users.go               # User queries
│   │   ├── deployments.go         # Deployment history queries
│   │   ├── backups.go             # Backup queries
│   │   └── float.go               # Float session queries
│   ├── float/
│   │   ├── bridge.go              # WebSocket USB bridge protocol
│   │   ├── session.go             # Session management
│   │   └── protocol.go            # Binary frame protocol definitions
│   └── config/
│       └── config.go              # YAML config loader
├── web/
│   ├── templates/                 # HTML templates (embedded)
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── dashboard.html
│   │   ├── sites.html
│   │   ├── site_detail.html
│   │   ├── site_new.html
│   │   ├── autarch.html
│   │   ├── ssl.html
│   │   ├── nginx.html
│   │   ├── firewall.html
│   │   ├── users.html
│   │   ├── backups.html
│   │   ├── monitor.html
│   │   ├── logs.html
│   │   └── float.html
│   └── static/                    # CSS/JS assets (embedded)
│       ├── css/style.css
│       └── js/app.js
├── build.sh                       # Build script
├── go.mod
├── config.yaml                    # Default config
└── README.md
```

---

## 8. Configuration (config.yaml)

```yaml
server:
  host: "0.0.0.0"
  port: 9090
  tls: true
  cert: "/opt/setec-manager/data/acme/manager.crt"
  key: "/opt/setec-manager/data/acme/manager.key"

database:
  path: "/opt/setec-manager/data/setec.db"

nginx:
  sites_available: "/etc/nginx/sites-available"
  sites_enabled: "/etc/nginx/sites-enabled"
  snippets: "/etc/nginx/snippets"
  webroot: "/var/www"
  certbot_webroot: "/var/www/certbot"

acme:
  email: ""                        # Let's Encrypt registration email
  staging: false                   # Use LE staging for testing
  account_dir: "/opt/setec-manager/data/acme"

autarch:
  install_dir: "/var/www/autarch"
  git_repo: "https://github.com/DigijEth/autarch.git"
  git_branch: "main"
  web_port: 8181
  dns_port: 53

float:
  enabled: false
  max_sessions: 10
  session_ttl: "24h"

backups:
  dir: "/opt/setec-manager/data/backups"
  max_age_days: 30
  max_count: 50

logging:
  level: "info"
  file: "/var/log/setec-manager.log"
  max_size_mb: 100
  max_backups: 3
```

---

## 9. Build Targets

```
Part 1:  Core server, auth, dashboard, site CRUD, Nginx config gen,
         AUTARCH install/deploy, systemd management
         (~4,000 lines)

Part 2:  SSL/ACME automation, firewall management, system users,
         backup/restore, system monitoring
         (~3,500 lines)

Part 3:  Float Mode WebSocket bridge, live log streaming,
         deployment history, scheduled jobs (cron), web UI polish
         (~3,500 lines)

Part 4:  Web UI templates + CSS + JS, full frontend for all features
         (~3,000 lines Go templates + 2,000 lines CSS/JS)

Total estimated: ~16,000 lines
```

---

## 10. Security Considerations

- Manager runs as root (required for nginx, systemd, useradd)
- Web panel protected by bcrypt + JWT with short-lived tokens
- All subprocess calls use `exec.Command()` with argument arrays (no shell injection)
- Nginx configs validated with `nginx -t` before reload
- ACME challenges served from dedicated webroot (no app interference)
- Float Mode sessions require authentication + have TTL
- USB bridge frames validated for protocol compliance
- SQLite database file permissions: 0600
- Credentials file permissions: 0600
- All user-supplied domains validated against DNS before cert issuance
- Rate limiting on login attempts (5 per minute per IP)

---

## 11. First-Run Bootstrap

When `setec-manager` is run for the first time on a fresh Debian 13 VPS:

```
1. Detect if first run (no config.yaml or empty database)
2. Interactive TUI setup:
   a. Set admin username + password
   b. Set manager domain (or IP)
   c. Set email for Let's Encrypt
   d. Configure AUTARCH auto-install (y/n)
3. System setup:
   a. apt update && apt install -y nginx certbot python3 python3-venv git ufw
   b. Generate Nginx base config + snippets
   c. Configure ufw default rules
   d. Enable ufw
4. If AUTARCH auto-install:
   a. Clone from git
   b. Full AUTARCH setup (venv, pip, npm, build)
   c. Generate + install systemd units
   d. Generate Nginx reverse proxy
   e. Issue SSL cert
   f. Start AUTARCH
5. Start Setec Manager web dashboard
6. Print access URL
```
