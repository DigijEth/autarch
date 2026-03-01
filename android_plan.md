# AUTARCH Android Plan - Browser-Based Hardware Access
## darkHal Security Group
**Created:** 2026-02-14

---

## Problem Statement

The current hardware module (Phase 4.5) is **server-side only**: Flask routes call `adb`/`fastboot`/`esptool` as subprocess commands on the AUTARCH server. This works when devices are physically plugged into the server (e.g., Orange Pi), but does NOT allow a remote user to flash a device plugged into their own machine.

**Goal:** Add **browser-based direct USB/Serial access** using WebUSB and Web Serial APIs, so users can flash devices plugged into their local machine through the AUTARCH web interface. Keep the existing server-side mode as a fallback.

---

## Architecture: Dual-Mode Hardware Access

```
                    ┌─────────────────────────────────────┐
                    │        AUTARCH Web Dashboard         │
                    │         hardware.html                │
                    │                                      │
                    │   ┌─────────┐    ┌──────────────┐   │
                    │   │ SERVER  │    │   DIRECT      │   │
                    │   │  MODE   │    │    MODE       │   │
                    │   │         │    │               │   │
                    │   │ Flask   │    │ WebUSB /      │   │
                    │   │ API     │    │ Web Serial    │   │
                    │   │ calls   │    │ (browser JS)  │   │
                    │   └────┬────┘    └──────┬───────┘   │
                    └────────┼────────────────┼───────────┘
                             │                │
                    ┌────────▼────┐    ┌──────▼───────┐
                    │  AUTARCH    │    │  User's      │
                    │  Server     │    │  Browser     │
                    │  (Orange Pi)│    │  ↕ USB/Serial│
                    │  ↕ USB      │    │  ↕ Device    │
                    │  ↕ Device   │    └──────────────┘
                    └─────────────┘

 Server Mode: device ↔ server ↔ Flask API ↔ browser (existing)
 Direct Mode: device ↔ browser (WebUSB/Web Serial) ↔ JS libs (NEW)
```

**Server Mode** = Existing implementation. Device plugged into server. Flask calls adb/fastboot/esptool as subprocesses. Works in any browser.

**Direct Mode** = NEW. Device plugged into user's machine. Browser talks directly to device via WebUSB (ADB, Fastboot) or Web Serial (ESP32). Requires Chromium-based browser (Chrome, Edge, Brave, Opera).

---

## JavaScript Libraries

### 1. ADB — ya-webadb / Tango
- **npm:** `@yume-chan/adb`, `@yume-chan/adb-daemon-webusb`, `@yume-chan/stream-extra`
- **License:** MIT
- **API:** WebUSB → ADB protocol (shell, file sync, reboot, logcat, install, scrcpy)
- **Source:** https://github.com/yume-chan/ya-webadb
- **Key classes:**
  - `AdbDaemonWebUsbDeviceManager` — enumerate/request USB devices
  - `AdbDaemonWebUsbDevice` — wrap USB device for ADB transport
  - `AdbDaemonTransport` — handshake + auth
  - `Adb` — main interface (shell, sync, subprocess, reboot)
- **Usage pattern:**
  ```js
  const manager = new AdbDaemonWebUsbDeviceManager(navigator.usb);
  const device = await manager.requestDevice();  // USB permission prompt
  const connection = await device.connect();
  const transport = await AdbDaemonTransport.authenticate({connection, ...});
  const adb = new Adb(transport);
  const output = await adb.subprocess.spawnAndWait('ls /sdcard');
  ```

### 2. Fastboot — fastboot.js (kdrag0n)
- **npm:** `android-fastboot`
- **License:** MIT
- **API:** WebUSB → Fastboot protocol (getvar, flash, boot, reboot, OEM unlock)
- **Source:** https://github.com/niccolozy/fastboot.js (fork of kdrag0n), used by ArKT-7/nabu
- **Key classes:**
  - `FastbootDevice` — connect, getVariable, flashBlob, reboot, flashFactoryZip
- **Usage pattern:**
  ```js
  const device = new FastbootDevice();
  await device.connect();  // USB permission prompt
  const product = await device.getVariable('product');
  await device.flashBlob('boot', blob, (progress) => updateUI(progress));
  await device.reboot();
  ```

### 3. ESP32 — esptool-js (Espressif)
- **npm:** `esptool-js`
- **License:** Apache-2.0
- **API:** Web Serial → ESP32 ROM bootloader (chip detect, flash, erase, read MAC)
- **Source:** https://github.com/niccolozy/esptool-js (Espressif)
- **Key classes:**
  - `ESPLoader` — main class, connect/detectChip/writeFlash
  - `Transport` — Web Serial wrapper
- **Usage pattern:**
  ```js
  const port = await navigator.serial.requestPort();
  await port.open({ baudRate: 115200 });
  const transport = new Transport(port);
  const loader = new ESPLoader({ transport, baudrate: 115200 });
  await loader.main();  // connect + detect chip
  console.log('Chip:', loader.chipName);
  await loader.writeFlash({ fileArray: [{data: firmware, address: 0x0}],
                             flashSize: 'keep', progressCallback: fn });
  ```

---

## Build Strategy: Pre-bundled ESM

Since AUTARCH uses vanilla JS (no React/webpack/build system), we need browser-ready bundles of the npm libraries.

**Approach:** Use `esbuild` to create self-contained browser bundles, saved as static JS files.

```
web/static/js/
├── app.js                  # Existing (1,477 lines)
├── lib/
│   ├── adb-bundle.js       # ya-webadb bundled (ESM → IIFE)
│   ├── fastboot-bundle.js  # fastboot.js bundled
│   └── esptool-bundle.js   # esptool-js bundled
└── hardware-direct.js      # NEW: Direct-mode logic (~500 lines)
```

**Build script** (`scripts/build-hw-libs.sh`):
```bash
#!/bin/bash
# One-time build — output goes into web/static/js/lib/
# Only needed when updating library versions

npm install --save-dev esbuild
npm install @yume-chan/adb @yume-chan/adb-daemon-webusb @yume-chan/stream-extra android-fastboot esptool-js

# Bundle each library into browser-ready IIFE
npx esbuild src/adb-entry.js --bundle --format=iife --global-name=YumeAdb --outfile=web/static/js/lib/adb-bundle.js
npx esbuild src/fastboot-entry.js --bundle --format=iife --global-name=Fastboot --outfile=web/static/js/lib/fastboot-bundle.js
npx esbuild src/esptool-entry.js --bundle --format=iife --global-name=EspTool --outfile=web/static/js/lib/esptool-bundle.js
```

**Entry point files** (thin wrappers that re-export what we need):
```js
// src/adb-entry.js
export { AdbDaemonWebUsbDeviceManager, AdbDaemonWebUsbDevice } from '@yume-chan/adb-daemon-webusb';
export { AdbDaemonTransport, Adb, AdbSync } from '@yume-chan/adb';

// src/fastboot-entry.js
export { FastbootDevice, setDebugLevel } from 'android-fastboot';

// src/esptool-entry.js
export { ESPLoader, Transport } from 'esptool-js';
```

The pre-built bundles are committed to `web/static/js/lib/` so no npm/node is needed at runtime. The build script is only run when updating library versions.

---

## Implementation Phases

### Phase A: Build Infrastructure & Library Bundles
**Files:** `package.json`, `scripts/build-hw-libs.sh`, `src/*.js`, `web/static/js/lib/*.js`

1. Create `package.json` in project root (devDependencies only — not needed at runtime)
2. Create entry-point files in `src/` for each library
3. Create build script `scripts/build-hw-libs.sh`
4. Run build, verify bundles work in browser
5. Add `node_modules/` to `.gitignore` equivalent (cleanup notes)

**Deliverable:** Three bundled JS files in `web/static/js/lib/`

### Phase B: Direct-Mode JavaScript Module
**Files:** `web/static/js/hardware-direct.js` (~500 lines)

Core module providing a unified API that mirrors the existing server-mode functions:

```js
// hardware-direct.js — Browser-based device access

const HWDirect = {
    // State
    supported: { webusb: !!navigator.usb, webserial: !!navigator.serial },
    adbDevice: null,    // current ADB connection
    fbDevice: null,     // current Fastboot connection
    espLoader: null,    // current ESP32 connection
    espTransport: null,

    // ── ADB (WebUSB) ────────────────────────────────
    async adbRequestDevice() { ... },     // navigator.usb.requestDevice()
    async adbConnect(usbDevice) { ... },  // handshake + auth → Adb instance
    async adbShell(cmd) { ... },          // adb.subprocess.spawnAndWait
    async adbReboot(mode) { ... },        // adb.power.reboot / bootloader / recovery
    async adbInstall(blob) { ... },       // adb install APK
    async adbPush(blob, path) { ... },    // adb.sync().write()
    async adbPull(path) { ... },          // adb.sync().read() → Blob download
    async adbLogcat(lines) { ... },       // adb subprocess logcat
    async adbGetInfo() { ... },           // getprop queries
    async adbDisconnect() { ... },

    // ── Fastboot (WebUSB) ────────────────────────────
    async fbRequestDevice() { ... },      // FastbootDevice.connect()
    async fbGetInfo() { ... },            // getVariable queries
    async fbFlash(partition, blob, progressCb) { ... },
    async fbReboot(mode) { ... },
    async fbOemUnlock() { ... },
    async fbDisconnect() { ... },

    // ── ESP32 (Web Serial) ───────────────────────────
    async espRequestPort() { ... },       // navigator.serial.requestPort()
    async espConnect(port, baud) { ... }, // Transport + ESPLoader.main()
    async espDetectChip() { ... },        // loader.chipName
    async espFlash(fileArray, progressCb) { ... },
    async espMonitorStart(outputCb) { ... },
    async espMonitorSend(data) { ... },
    async espMonitorStop() { ... },
    async espDisconnect() { ... },

    // ── Factory Flash (PixelFlasher PoC) ─────────────
    async factoryFlash(zipBlob, options, progressCb) { ... },
};
```

### Phase C: UI Integration — Mode Switcher & Direct Controls
**Files:** `web/templates/hardware.html`, `web/static/js/app.js`

1. **Mode toggle** at top of hardware page:
   ```
   [Connection Mode]  ○ Server (device on AUTARCH host)  ● Direct (device on this PC)
   ```
   - Direct mode shows browser compatibility warning if WebUSB/Serial not supported
   - Direct mode shows "Pair Device" buttons (triggers USB/Serial permission prompts)

2. **Modify existing JS functions** to check mode:
   ```js
   // In app.js, each hw*() function checks the mode:
   async function hwRefreshAdbDevices() {
       if (hwConnectionMode === 'direct') {
           // Use HWDirect.adbRequestDevice() / enumerate
       } else {
           // Existing: fetchJSON('/hardware/adb/devices')
       }
   }
   ```

3. **New UI elements for direct mode:**
   - "Connect ADB Device" button (triggers WebUSB permission prompt)
   - "Connect Fastboot Device" button (triggers WebUSB permission prompt)
   - "Connect Serial Port" button (triggers Web Serial permission prompt)
   - File picker for firmware uploads (local files, no server upload needed)
   - Progress bars driven by JS callbacks instead of SSE streams

4. **Keep all existing server-mode UI** — just add the mode switch.

### Phase D: PixelFlasher Proof-of-Concept
**Files:** `web/static/js/hardware-direct.js` (factoryFlash section), `web/templates/hardware.html` (new tab/section)

Inspired by PixelFlasher's workflow, create a "Flash Factory Image" feature:

1. **Upload factory image ZIP** (via file input, read in browser — no server upload)
2. **Parse ZIP contents** (identify flash-all.sh/bat, partition images)
3. **Display flash plan** (list of partitions + images to flash, with sizes)
4. **Safety checks:**
   - Verify device product matches image (getVariable product vs ZIP name)
   - Check bootloader unlock status
   - Warn about data wipe partitions (userdata, metadata)
   - Show A/B slot info if applicable
5. **Options:**
   - [ ] Flash all partitions (default)
   - [ ] Skip userdata (preserve data)
   - [ ] Disable vbmeta verification (for custom ROMs)
   - [ ] Flash to inactive slot (A/B devices)
6. **Execute flash sequence:**
   - Reboot to bootloader if in ADB mode
   - Flash each partition with progress bar
   - Reboot to system
7. **Boot image patching** (future — Magisk/KernelSU integration)

### Phase E: Polish & Testing
1. Error handling for all WebUSB/Serial operations (device disconnected mid-flash, permission denied, etc.)
2. Browser compatibility detection and graceful degradation
3. Connection status indicators (connected device info in header)
4. Reconnection logic if USB device resets during flash
5. Update `autarch_dev.md` with completed phase notes

---

## File Changes Summary

### New Files
| File | Purpose | Est. Lines |
|------|---------|-----------|
| `package.json` | npm deps for build only | 20 |
| `scripts/build-hw-libs.sh` | esbuild bundler script | 25 |
| `src/adb-entry.js` | ya-webadb re-export | 5 |
| `src/fastboot-entry.js` | fastboot.js re-export | 3 |
| `src/esptool-entry.js` | esptool-js re-export | 3 |
| `web/static/js/lib/adb-bundle.js` | Built bundle | ~varies |
| `web/static/js/lib/fastboot-bundle.js` | Built bundle | ~varies |
| `web/static/js/lib/esptool-bundle.js` | Built bundle | ~varies |
| `web/static/js/hardware-direct.js` | Direct-mode logic | ~500 |

### Modified Files
| File | Changes |
|------|---------|
| `web/templates/hardware.html` | Add mode toggle, direct-mode connect buttons, factory flash section, script includes |
| `web/static/js/app.js` | Add mode switching to all hw*() functions |
| `web/static/css/style.css` | Styles for mode toggle, connect buttons, compatibility warnings |

### Unchanged
| File | Reason |
|------|--------|
| `core/hardware.py` | Server-mode backend stays as-is |
| `web/routes/hardware.py` | Server-mode routes stay as-is |
| `modules/hardware_local.py` | CLI module stays as-is |

---

## Browser Compatibility

| Feature | Chrome | Edge | Firefox | Safari |
|---------|--------|------|---------|--------|
| WebUSB (ADB/Fastboot) | 61+ | 79+ | No | No |
| Web Serial (ESP32) | 89+ | 89+ | No | No |

**Fallback:** Users with Firefox/Safari use Server Mode (device plugged into AUTARCH host). Direct Mode requires Chromium-based browser.

---

## Security Considerations

1. **WebUSB requires HTTPS** in production (or localhost). AUTARCH currently runs plain HTTP. For direct mode to work remotely, either:
   - Run behind a reverse proxy with TLS (nginx/caddy)
   - Use localhost (device and browser on same machine)
   - Use the server-mode fallback instead

2. **USB permission prompts** — The browser shows a native device picker. Users must explicitly select their device. No access without user gesture.

3. **Flash safety checks** — Same partition whitelist as server mode. Confirm dialogs before destructive operations. Product verification before factory flash.

---

## Implementation Order

```
Phase A  →  Phase B  →  Phase C  →  Phase D  →  Phase E
 (libs)     (JS API)    (UI)        (PoC)       (polish)

 ~1 session  ~1 session  ~1 session  ~1 session  ~1 session
```

Start with Phase A (build the library bundles) since everything else depends on having working JS libraries available in the browser.

---

## PixelFlasher Feature Mapping

| PixelFlasher Feature | AUTARCH Implementation | Phase |
|---------------------|----------------------|-------|
| Factory image flash | ZIP upload → parse → flash sequence | D |
| OTA sideload | ADB sideload (server) / adb.install (direct) | C |
| Boot image patching (Magisk) | Future — extract boot.img, patch, flash back | Future |
| Multi-device support | Device list + select (both modes already do this) | C |
| A/B slot management | fastboot getvar current-slot / set_active | D |
| Dry run mode | Parse + display flash plan without executing | D |
| Partition backup | fastboot fetch / adb pull partition | Future |
| Lock/unlock status | fastboot getvar unlocked | D |
| Device state display | Product, variant, bootloader version, secure, etc. | C |

---

## Notes

- All npm/node dependencies are **build-time only**. The built JS bundles are static files served by Flask. No Node.js runtime needed.
- The `src/` directory and `node_modules/` are build artifacts, not needed for deployment.
- Library bundles should be rebuilt when upgrading library versions. Pin versions in package.json.
- The server-side mode remains the primary mode for headless/remote AUTARCH deployments where devices are plugged into the server.
- Direct mode is an enhancement for users who want to flash devices plugged into their own workstation while using the AUTARCH web UI.
