# ESP32 WiFi Capture Probe — Design Document

**Project:** AUTARCH Hardware Probe
**Status:** Planned
**Author:** darkHal Security Group

---

## Problem

The Orange Pi 5 Plus built-in WiFi adapter (managed mode only) cannot:
- Enter monitor mode for raw 802.11 frame capture
- Detect deauthentication attacks (requires reading management frames)
- Do passive channel hopping while staying connected to a network
- Capture probe requests, beacon frames, or association traffic

USB WiFi adapters that support monitor mode (Alfa AWUS036ACH, etc.) work but are bulky, expensive, and require specific driver support.

## Solution

A small ESP32-based WiFi capture probe that runs custom firmware. The ESP32's WiFi chipset natively supports promiscuous mode and can capture raw 802.11 frames on both 2.4GHz and 5GHz (ESP32-S3/C6). The probe connects to AUTARCH over USB serial or TCP and streams captured frames in real time.

AUTARCH already has ESP32 flashing built into the Hardware page — users can flash the probe firmware directly from the web UI.

## Hardware

**Minimum:**
- ESP32 dev board (any variant) — ~$5
- USB cable

**Recommended:**
- ESP32-S3 or ESP32-C6 (dual-band 2.4/5GHz support)
- External antenna connector (IPEX/U.FL) for better range
- Small 3D-printed case
- Optional: LiPo battery + charging circuit for portable deployment

**Cost:** Under $10 for a complete probe

## Capabilities

### Capture Modes
1. **Promiscuous Mode** — capture all 802.11 frames on a channel (data, management, control)
2. **Channel Hopping** — cycle through channels 1-13 (2.4GHz) and 36-165 (5GHz on S3/C6)
3. **Targeted Capture** — lock to a specific channel and BSSID
4. **Beacon Monitor** — capture only beacon and probe frames (low bandwidth, good for SSID mapping)

### Detection
- Deauthentication frame detection (count, source MAC, target MAC, reason code)
- Evil twin detection (same SSID, different BSSID appearing)
- Probe request tracking (which devices are looking for which networks)
- Rogue AP detection (new BSSIDs appearing)
- Karma attack detection (AP responding to all probe requests)
- Association flood detection

### Output Formats
- Raw pcap over serial (AUTARCH reads with scapy)
- JSON event stream over serial (parsed on ESP32, lighter bandwidth)
- TCP stream over WiFi (ESP32 connects to AUTARCH's network in station mode on one radio, captures on the other — dual-radio ESP32 only)

## Firmware Architecture

```
esp32-capture-probe/
  main/
    main.c              Entry point, WiFi init, mode selection
    capture.c           Promiscuous mode callback, frame parsing
    channel_hop.c       Channel hopping logic with configurable dwell time
    serial_output.c     Frame/event output over USB serial (SLIP framing)
    tcp_output.c        Frame/event output over TCP socket
    detector.c          Deauth/evil twin/karma detection logic
    config.c            Runtime configuration via serial commands
    led.c               Status LED control (capturing, alert, idle)
  CMakeLists.txt
  sdkconfig             ESP-IDF configuration
```

### Frame Processing Pipeline

```
802.11 Frame (promiscuous callback)
  |
  +-- Parse header (type, subtype, addresses, sequence)
  |
  +-- Filter (by type, BSSID, channel)
  |
  +-- Detection engine
  |     +-- Deauth counter (threshold alert)
  |     +-- SSID/BSSID tracker (evil twin check)
  |     +-- Probe request log
  |
  +-- Output
        +-- JSON event (for alerts/detections)
        +-- Raw frame bytes (for pcap capture)
```

### Serial Protocol

Commands from AUTARCH to probe (newline-delimited JSON):
```json
{"cmd": "start", "mode": "promiscuous", "channel": 0}
{"cmd": "start", "mode": "beacon_only"}
{"cmd": "set_channel", "channel": 6}
{"cmd": "hop", "channels": [1,6,11], "dwell_ms": 200}
{"cmd": "stop"}
{"cmd": "status"}
{"cmd": "set_filter", "bssid": "aa:bb:cc:dd:ee:ff"}
{"cmd": "set_output", "format": "json"}
{"cmd": "set_output", "format": "pcap"}
```

Events from probe to AUTARCH:
```json
{"event": "deauth", "src": "aa:bb:cc:dd:ee:ff", "dst": "11:22:33:44:55:66", "reason": 7, "channel": 6, "rssi": -45, "count": 15}
{"event": "beacon", "ssid": "FreeWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 1, "rssi": -60, "security": "open"}
{"event": "evil_twin", "ssid": "HomeNetwork", "bssid_original": "aa:bb:cc:dd:ee:ff", "bssid_rogue": "11:22:33:44:55:66"}
{"event": "probe_req", "src": "aa:bb:cc:dd:ee:ff", "ssid": "MyPhone_Hotspot", "rssi": -70}
{"event": "karma", "ap_bssid": "aa:bb:cc:dd:ee:ff", "responded_to": ["Network1", "Network2", "Network3"]}
{"event": "frame", "hex": "80000000...", "channel": 6, "rssi": -55}
{"event": "status", "mode": "hopping", "channel": 6, "frames_captured": 1547, "alerts": 3, "uptime": 120}
```

## AUTARCH Integration

### Hardware Page
The probe appears as an ESP32 device on the Hardware page. Users can:
- Flash the capture firmware (one click from the ESP32 tab)
- Monitor probe status (connected, capturing, channel, frame count)
- Configure capture settings (mode, channels, filters)

### Network Security Page
New sub-features when a probe is connected:
- **Live 802.11 Monitor** — real-time frame stream with protocol breakdown
- **Deauth Alert** — instant notification when deauth frames detected (with source tracking)
- **Channel Survey** — signal strength and AP count per channel (helps pick the cleanest channel)
- **Hidden Network Discovery** — find SSIDs that don't broadcast beacons by watching probe responses
- **Client Tracker** — which devices (MACs) are associated to which APs

### Capture Agent Integration
The capture agent (`core/capture_agent.py`) gains a new action:
```json
{"action": "probe_start", "serial_port": "/dev/ttyUSB0", "mode": "promiscuous", "channels": [1,6,11]}
{"action": "probe_stop"}
{"action": "probe_status"}
```

The capture agent reads the serial stream, converts to pcap or forwards JSON events to Flask via its existing socket.

### WiFi Audit Integration
With the probe providing monitor mode:
- Deauth attacks actually work (raw frame injection)
- Handshake capture works (WPA 4-way handshake monitoring)
- Channel hopping during audit scans
- Passive reconnaissance without disconnecting from the network

## Implementation Phases

### Phase 1: Basic Capture (1-2 days)
- ESP-IDF project setup
- Promiscuous mode callback
- Serial output (JSON events)
- Channel hopping
- Flash from AUTARCH Hardware page

### Phase 2: Detection Engine (1-2 days)
- Deauth frame counter with threshold alerting
- Evil twin detection (SSID/BSSID tracking)
- Probe request logging
- AUTARCH integration (Network Security page reads probe events)

### Phase 3: Advanced Features (2-3 days)
- pcap output mode (raw frame bytes over serial)
- TCP streaming mode (dual-radio only)
- Karma attack detection
- Client association tracking
- Channel survey with signal heatmap data
- Hidden network discovery

### Phase 4: WiFi Audit Integration (1-2 days)
- Frame injection for deauth (if supported by ESP32 variant)
- Handshake capture and forwarding to aircrack-ng
- Automated WPA audit workflow

## Bill of Materials

| Component | Purpose | Price |
|-----------|---------|-------|
| ESP32-S3 DevKitC | Dual-band WiFi, USB-C | ~$8 |
| IPEX antenna | Better range | ~$2 |
| USB-C cable | Connection to AUTARCH host | ~$3 |
| 3D printed case | Protection (optional) | ~$1 |
| **Total** | | **~$14** |

For budget builds, any ESP32 board works ($3-5) but is limited to 2.4GHz only.

## Comparison to Alternatives

| Feature | ESP32 Probe | Alfa Adapter | HackRF | Built-in WiFi |
|---------|------------|-------------|--------|---------------|
| Cost | ~$14 | ~$40-70 | ~$300 | $0 |
| Monitor mode | Yes | Yes | N/A | Usually no |
| 5GHz | ESP32-S3/C6 | Model dependent | Yes | Model dependent |
| Portable | Very (tiny) | Medium | Large | N/A |
| Driver issues | None (serial) | Frequent | Complex | N/A |
| Frame injection | Limited | Yes | Yes | No |
| Power | USB powered | USB powered | USB powered | N/A |
| AUTARCH integration | Native | Requires airmon-ng | Complex | Limited |

The ESP32 probe fills the gap between "no monitor mode" and "expensive USB adapter with driver hell." It's cheap, reliable, driver-free (serial protocol), and integrates natively with AUTARCH.

---

*darkHal Security Group & Setec Security Labs*
*Planned for AUTARCH v2.5*
