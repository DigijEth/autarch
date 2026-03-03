# AUTARCH Changelog

---

## v2.2.0 — 2026-03-03

### Full Arsenal Expansion — 16 New Modules

Phase 2 complete. 16 new security modules with full CLI, Flask routes, and web UI templates.

#### Offense
- **WiFi Auditing** (`/wifi/`) — aircrack-ng integration: monitor mode, AP scanning, deauth attacks, WPA handshake capture/crack, WPS Pixie-Dust, rogue AP detection, packet capture
- **API Fuzzer** (`/api-fuzzer/`) — OpenAPI/Swagger discovery, parameter fuzzing (SQLi/XSS/traversal/type confusion), auth bypass & IDOR testing, rate limit probing, GraphQL introspection attacks
- **Cloud Security Scanner** (`/cloud/`) — S3/GCS/Azure blob enumeration, exposed service scanning, IMDS metadata SSRF checks, cloud subdomain enumeration
- **C2 Framework** (`/c2/`) — multi-session agent management, Python/PowerShell/Bash payloads, HTTP/HTTPS/DNS beaconing, file transfer, SOCKS pivoting, listener management
- **Web Application Scanner** (`/webscan/`) — directory bruteforce, subdomain enum, SQLi/XSS detection, header analysis, tech fingerprinting, SSL/TLS audit, crawler

#### Defense
- **Threat Intel Feed** (`/threat-intel/`) — IOC management (IP/domain/hash/URL), STIX/CSV/JSON feed ingestion, VirusTotal & AbuseIPDB API lookups, network correlation, blocklist export (iptables/nginx/snort)
- **Log Correlator** (`/logs/`) — multi-format log parsing (syslog/Apache/JSON), 10 built-in detection rules (SSH brute force, SQLi, XSS, path traversal), threshold alerting, custom rules, timeline view

#### Counter
- **Steganography** (`/stego/`) — LSB image encoding (PNG/BMP), audio steganography (WAV), document whitespace encoding (zero-width chars), AES-256 pre-encryption, chi-square & RS statistical detection
- **Anti-Forensics** (`/anti-forensics/`) — multi-pass secure file/directory deletion, free space wiping, timestamp manipulation (set/clone/randomize), log clearing, shell history scrubbing, EXIF & PDF metadata stripping

#### Analyze
- **Password Toolkit** (`/passwords/`) — hash identification & cracking (hashcat/john integration), secure password generation, credential spray testing (SSH/FTP/SMB/HTTP), wordlist management, policy auditing
- **Network Topology Mapper** (`/netmap/`) — ARP/ICMP/TCP host discovery, service enumeration, OS fingerprinting, SVG topology visualization, subnet grouping, scan diffing
- **Reporting Engine** (`/reports/`) — structured pentest reports, CVSS-scored findings, auto-population from scans & dossiers, PDF/HTML/Markdown export, compliance mapping (OWASP/NIST/CIS)
- **BLE Scanner** (`/ble/`) — BLE advertisement scanning via bleak, service & characteristic enumeration, read/write operations, known vulnerability database, RSSI proximity tracking
- **Forensics Toolkit** (`/forensics/`) — disk imaging (dd + hash verification), file carving by magic bytes (15 types), EXIF metadata extraction, filesystem timeline builder, chain of custody logging
- **RFID/NFC Tools** (`/rfid/`) — Proxmark3 integration (LF/HF search, EM410x read/clone/sim, MIFARE dump/clone), libnfc NFC scanning, card database, default MIFARE keys
- **Malware Sandbox** (`/sandbox/`) — sample submission (file upload or path), static analysis (strings, PE/ELF parsing, YARA-like indicators, risk scoring), Docker-based dynamic analysis with behavior logging

### Build System
- All 16 modules wired into `web/app.py` (blueprint registration), `base.html` (sidebar navigation), `autarch_public.spec` and `setup_msi.py` (hidden imports)
- Sidebar organized by category: Defense, Offense, Counter, Analyze

---

## v2.1.0 — 2026-03-03

### DNS-over-TLS (DoT) & DNS-over-HTTPS (DoH)

- **Full DoT implementation** — encrypted DNS queries over TLS (port 853) with certificate validation
- **Full DoH implementation** — encrypted DNS queries over HTTPS (RFC 8484, wire-format POST)
- **Auto-detection** for known encrypted providers:
  - Google DNS (`8.8.8.8`, `8.8.4.4`) — DoT via `dns.google`, DoH via `https://dns.google/dns-query`
  - Cloudflare (`1.1.1.1`, `1.0.0.1`) — DoT via `one.one.one.one`, DoH via `https://cloudflare-dns.com/dns-query`
  - Quad9 (`9.9.9.9`, `149.112.112.112`) — DoT via `dns.quad9.net`, DoH via `https://dns.quad9.net/dns-query`
  - OpenDNS (`208.67.222.222`, `208.67.220.220`) — DoT/DoH via `dns.opendns.com`
  - AdGuard (`94.140.14.14`, `94.140.15.15`) — DoT/DoH via `dns.adguard-dns.com`
- **Priority chain**: DoH > DoT > Plain DNS — auto-fallback on failure
- **Encryption test tool** in the Nameserver UI — live test DoT/DoH/Plain against any server with latency reporting
- **Toggle controls** — enable/disable DoT and DoH independently via UI or API
- **API endpoints**: `GET/POST /api/encryption`, `POST /api/encryption/test`

### Hosts File Support

- **Hosts-file parser** — `/etc/hosts` style hostname resolution served via DNS
- **Resolution priority**: Hosts file entries checked before zones and cache for fastest local resolution
- **CRUD operations** — add, remove, search individual host entries via UI or API
- **Bulk import** — paste hosts-file format text or load from a file path (e.g., `/etc/hosts`, `C:\Windows\System32\drivers\etc\hosts`)
- **System hosts loader** — one-click button to load the OS hosts file
- **Export** — download current hosts database in standard hosts-file format
- **PTR reverse lookup** — hosts entries support reverse DNS (in-addr.arpa) queries
- **Alias support** — multiple hostnames per IP, matching on primary hostname or any alias
- **Hosts tab** in Nameserver UI — full management table with search, inline add, import/export
- **API endpoints**: `GET/POST/DELETE /api/hosts`, `POST /api/hosts/import`, `GET /api/hosts/export`

### EZ Intranet Domain (One-Click Local DNS)

- **One-click intranet domain creation** in the Nameserver UI
- **Auto network detection** — discovers local IP, hostname, gateway, subnet via socket/ARP
- **Host discovery** — scans ARP table for all devices on the network with reverse DNS lookup
- **Editable DNS names** — auto-suggests names for discovered hosts, fully editable before deployment
- **Custom hosts** — add arbitrary hosts not found by network scan
- **Deployment creates**:
  - Forward DNS zone with SOA + NS records
  - A records for server, hostname, and all selected/custom hosts
  - Hosts-file entries for instant resolution
  - Reverse DNS zone (PTR records) for reverse lookups
- **Client configuration** — shows copy-paste instructions for Windows (`netsh`) and Linux (`resolv.conf`/`systemd-resolved`)
- **Router DHCP hint** — advises setting the DNS server IP in router DHCP for automatic network-wide deployment
- **API endpoint**: `POST /dns/ez-intranet`

### Full Configuration UI

Expanded the Config tab from 5 fields to 18 fields across 5 categories:

- **Network** — DNS listen address, API listen address, upstream forwarder servers
- **Cache & Performance** — cache TTL, negative cache TTL (NXDOMAIN), SERVFAIL cache TTL, query log max entries, max UDP response size, rate limit (queries/sec/IP), prefetch toggle
- **Security** — query logging, refuse ANY queries (anti-amplification), minimal responses (hide server info), zone transfer ACL (AXFR/IXFR whitelist)
- **Encryption** — DoH enable/disable, DoT enable/disable with priority explanation
- **Hosts** — hosts file path, auto-load on startup toggle

All settings are live-editable from the dashboard and propagated to the running server without restart.

### Go DNS Server Changes

- **`server/resolver.go`** — added `QueryUpstreamDoT()`, `QueryUpstreamDoH()`, `queryUpstreamEncrypted()`, `GetEncryptionStatus()` with TLS 1.2+ minimum, HTTP/2 for DoH, proper SNI for DoT
- **`server/hosts.go`** — new file: `HostsStore` with `LoadFile()`, `LoadFromText()`, `Add()`, `Remove()`, `Lookup()`, `Export()`, PTR support
- **`server/dns.go`** — integrated hosts lookup before zone lookup in query handler; added `GetHosts()`, `GetEncryptionStatus()`, `SetEncryption()`, `GetResolver()`
- **`config/config.go`** — added `HostsFile`, `HostsAutoLoad`, `QueryLogMax`, `NegativeCacheTTL`, `PrefetchEnabled`, `ServFailCacheTTL`
- **`api/router.go`** — added 5 new endpoint groups: hosts CRUD, hosts import/export, encryption status/toggle, encryption test, full config expansion
- **`main.go`** — version bump to 2.1.0

### Web Dashboard Changes

- **`web/templates/dns_nameserver.html`** — added 3 new tabs: Encryption, Hosts, EZ Intranet (13 tabs total)
- **`web/templates/dns_service.html`** — expanded Config tab with all 18 settings in categorized layout
- **`web/routes/dns_service.py`** — added 8 new routes: hosts CRUD, hosts import/export, encryption status/toggle/test, EZ intranet deploy

---

## v2.0.0 — 2026-03-03

### Go DNS/Nameserver Service

- **Full recursive DNS resolver** from IANA root hints — no upstream dependency
- **13 root server** iterative resolution with delegation chain following
- **CNAME chain following** across zone boundaries
- **Authoritative zone hosting** with JSON-backed zone storage
- **Record types**: A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, SOA
- **DNSSEC toggle** per zone
- **DNS caching** with configurable TTL and automatic cleanup
- **Query logging** with ring buffer (configurable size)
- **Analytics**: top domains, query type distribution, per-client query counts
- **Blocklist**: exact match + wildcard parent domain matching, bulk import (hosts-file format)
- **Conditional forwarding**: zone-specific upstream server rules
- **Root health check**: concurrent ping of all 13 IANA root servers with latency measurement
- **Benchmark tool**: multi-domain latency testing with min/avg/max statistics
- **Zone import/export**: BIND zone file format support
- **Zone cloning**: duplicate zone with all records
- **Bulk record operations**: add multiple records in a single request
- **Mail record auto-setup**: one-click MX + SPF + DKIM + DMARC creation
- **Security hardening**: refuse ANY (anti-amplification), minimal responses, AXFR/IXFR blocking, rate limiting, max UDP size (1232 bytes for safe MTU)
- **REST API**: 30+ endpoints with token auth and CORS

### Nameserver Web UI (10 tabs)

- **Query** — DNS query tester against local NS or system resolver
- **Query Log** — auto-refreshing query history with filtering
- **Analytics** — top domains (bar charts), query type distribution, client stats, NS cache viewer
- **Cache** — searchable cache viewer with per-entry and full flush
- **Blocklist** — add/remove/search domains, bulk import in hosts-file format
- **Forwarding** — conditional forwarding rule management
- **Root Health** — concurrent check of all 13 root servers with latency bars
- **Benchmark** — multi-domain latency testing with visual results
- **Delegation** — NS delegation record generator with glue record instructions
- **Build** — Go binary compilation controls and instructions

### DNS Zone Manager Web UI (7 tabs)

- **Zones** — create/delete/clone zones
- **Records** — full CRUD with bulk add (JSON), filtering by type/search, column sorting
- **EZ-Local** — network auto-scan intranet domain setup with ARP host discovery
- **Reverse Proxy** — DDNS, nginx/Caddy/Apache config generation, UPnP port forwarding
- **Import/Export** — BIND zone file backup/restore with inline editor
- **Templates** — quick-setup for web server, mail server, PTR, subdomain delegation
- **Config** — full server configuration panel

### Gone Fishing Mail Server Enhancements

- **Landing pages** — 4 built-in phishing templates (Office 365, Google, Generic, VPN) + custom HTML editor
- **Credential capture** — form POST interception on unauthenticated endpoints with IP/UA/referer logging
- **DKIM signing** — OpenSSL RSA 2048-bit keypair generation and DNS record instructions
- **DNS auto-setup** — automatic MX/SPF/DKIM/DMARC record creation via DNS service integration
- **Email evasion** — Unicode homoglyphs (30% swap), zero-width character insertion (15%), HTML entity encoding (20%)
- **Header manipulation** — random X-Mailer, X-Priority, custom headers, spoofed Received chain generation
- **CSV import/export** — bulk target import and credential capture export
- **Campaign management** — per-campaign tracking, export, and capture association

### IP Capture & Redirect Service

- **Stealthy link tracking** — fast 302 redirect with IP/UA/headers capture
- **Realistic URL disguise** — article-style paths that look like real news URLs
- **GeoIP lookup** on captured IPs
- **Dossier integration** — add captures to existing OSINT dossiers
- **Management UI** — create/manage links, view captures with filtering, export

### SYN Flood Module

- **TCP SYN flood** attack tool with configurable parameters
- **Multi-threaded** packet generation
- **Port targeting** — single port, range, or random
- **Source IP spoofing** options
