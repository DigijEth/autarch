/**
 * AUTARCH Hardware Direct Mode
 * Browser-based device access via WebUSB (ADB/Fastboot) and Web Serial (ESP32)
 *
 * Dependencies (loaded before this file):
 *   - web/static/js/lib/adb-bundle.js      → window.YumeAdb
 *   - web/static/js/lib/fastboot-bundle.js  → window.Fastboot
 *   - web/static/js/lib/esptool-bundle.js   → window.EspTool
 */

var HWDirect = (function() {
    'use strict';

    // ── Browser Capability Detection ─────────────────────────────

    var supported = {
        webusb: typeof navigator !== 'undefined' && !!navigator.usb,
        webserial: typeof navigator !== 'undefined' && !!navigator.serial,
    };

    // ── State ────────────────────────────────────────────────────

    var adbDevice = null;       // Adb instance (ya-webadb)
    var adbTransport = null;    // AdbDaemonTransport
    var adbUsbDevice = null;    // AdbDaemonWebUsbDevice (for disconnect)
    var adbDeviceInfo = {};     // Cached device props

    var fbDevice = null;        // FastbootDevice instance

    var espLoader = null;       // ESPLoader instance
    var espTransport = null;    // Web Serial Transport
    var espPort = null;         // SerialPort reference
    var espMonitorReader = null;
    var espMonitorRunning = false;

    // ── ADB Credential Store (IndexedDB) ─────────────────────────
    // ADB requires RSA key authentication. Keys are stored in IndexedDB
    // so the user only needs to authorize once per browser.

    var DB_NAME = 'autarch_adb_keys';
    var STORE_NAME = 'keys';

    function _openKeyDB() {
        return new Promise(function(resolve, reject) {
            var req = indexedDB.open(DB_NAME, 1);
            req.onupgradeneeded = function(e) {
                e.target.result.createObjectStore(STORE_NAME, { keyPath: 'id' });
            };
            req.onsuccess = function(e) { resolve(e.target.result); };
            req.onerror = function(e) { reject(e.target.error); };
        });
    }

    function _saveKey(id, privateKey) {
        return _openKeyDB().then(function(db) {
            return new Promise(function(resolve, reject) {
                var tx = db.transaction(STORE_NAME, 'readwrite');
                tx.objectStore(STORE_NAME).put({ id: id, key: privateKey });
                tx.oncomplete = function() { resolve(); };
                tx.onerror = function(e) { reject(e.target.error); };
            });
        });
    }

    function _loadKeys() {
        return _openKeyDB().then(function(db) {
            return new Promise(function(resolve, reject) {
                var tx = db.transaction(STORE_NAME, 'readonly');
                var req = tx.objectStore(STORE_NAME).getAll();
                req.onsuccess = function() { resolve(req.result || []); };
                req.onerror = function(e) { reject(e.target.error); };
            });
        });
    }

    // Web Crypto RSA key generation for ADB authentication
    var credentialStore = {
        generateKey: async function() {
            var keyPair = await crypto.subtle.generateKey(
                { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048,
                  publicExponent: new Uint8Array([1, 0, 1]),
                  hash: 'SHA-1' },
                true, ['sign']
            );
            var exported = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
            var keyBuffer = new Uint8Array(exported);
            var keyId = 'adb_key_' + Date.now();
            await _saveKey(keyId, Array.from(keyBuffer));
            return { buffer: keyBuffer, name: 'autarch@browser' };
        },
        iterateKeys: async function*() {
            var keys = await _loadKeys();
            for (var i = 0; i < keys.length; i++) {
                yield { buffer: new Uint8Array(keys[i].key), name: 'autarch@browser' };
            }
        }
    };

    // ══════════════════════════════════════════════════════════════
    // ADB (WebUSB)
    // ══════════════════════════════════════════════════════════════

    /**
     * Get list of already-paired ADB devices (no permission prompt).
     * Returns array of {serial, name, raw}.
     */
    async function adbGetDevices() {
        if (!supported.webusb) return [];
        var manager = YumeAdb.AdbDaemonWebUsbDeviceManager.BROWSER;
        if (!manager) return [];
        try {
            var devices = await manager.getDevices();
            return devices.map(function(d) {
                return { serial: d.serial || '', name: d.name || '', raw: d };
            });
        } catch (e) {
            console.error('adbGetDevices:', e);
            return [];
        }
    }

    /**
     * Request user to select an ADB device (shows browser USB picker).
     * Returns {serial, name, raw} or null.
     */
    async function adbRequestDevice() {
        if (!supported.webusb) throw new Error('WebUSB not supported in this browser');
        var manager = YumeAdb.AdbDaemonWebUsbDeviceManager.BROWSER;
        if (!manager) throw new Error('WebUSB manager not available');
        var device = await manager.requestDevice();
        if (!device) return null;
        return { serial: device.serial || '', name: device.name || '', raw: device };
    }

    /**
     * Connect to an ADB device (from adbGetDevices or adbRequestDevice).
     * Performs USB connection + ADB authentication.
     * The device screen will show "Allow USB debugging?" on first connect.
     */
    async function adbConnect(deviceObj) {
        if (adbDevice) {
            await adbDisconnect();
        }
        var usbDev = deviceObj.raw;
        var connection;
        try {
            connection = await usbDev.connect();
        } catch (e) {
            var errMsg = e.message || String(e);
            var errLow = errMsg.toLowerCase();
            // Windows: USB driver conflict — ADB server or another app owns the device
            if (errLow.includes('already in used') || errLow.includes('already in use') ||
                errLow.includes('in use by another') || errLow.includes('access denied')) {
                // Try forcing a release and retrying once
                try { await usbDev.close(); } catch (_) {}
                try {
                    connection = await usbDev.connect();
                } catch (e2) {
                    throw new Error(
                        'USB device is claimed by another program (usually the ADB server).\n\n' +
                        'Fix: open a terminal and run:\n' +
                        '  adb kill-server\n\n' +
                        'Then close Android Studio, scrcpy, or any other ADB tool, and click Connect again.'
                    );
                }
            } else if (errLow.includes('permission') || errLow.includes('not allowed') ||
                       errLow.includes('failed to open')) {
                throw new Error(
                    'USB permission denied. On Linux, ensure udev rules are installed:\n' +
                    '  sudo bash -c "echo \'SUBSYSTEM==\"usb\", ATTR{idVendor}==\"18d1\", MODE=\"0666\"\' > /etc/udev/rules.d/99-android.rules"\n' +
                    '  sudo udevadm control --reload-rules'
                );
            } else {
                throw new Error(
                    'USB connect failed: ' + errMsg + '\n\n' +
                    'Make sure the device screen is unlocked and USB debugging is enabled in Developer Options.'
                );
            }
        }
        try {
            adbTransport = await YumeAdb.AdbDaemonTransport.authenticate({
                serial: deviceObj.serial,
                connection: connection,
                credentialStore: credentialStore,
            });
        } catch (e) {
            var msg = e.message || String(e);
            if (msg.toLowerCase().includes('auth') || msg.toLowerCase().includes('denied')) {
                throw new Error('ADB auth denied — tap "Allow USB Debugging?" on the device screen, then click Connect again.');
            }
            throw new Error('ADB authentication failed: ' + msg);
        }
        adbDevice = new YumeAdb.Adb(adbTransport);
        adbUsbDevice = usbDev;
        adbDeviceInfo = {};
        return true;
    }

    /**
     * Run a shell command on the connected ADB device.
     * Returns {stdout, stderr, exitCode} or {output} for legacy protocol.
     */
    async function adbShell(cmd) {
        if (!adbDevice) throw new Error('No ADB device connected');
        try {
            // Prefer shell v2 protocol (separate stdout/stderr + exit code)
            if (adbDevice.subprocess && adbDevice.subprocess.shellProtocol) {
                var result = await adbDevice.subprocess.shellProtocol.spawnWaitText(cmd);
                return {
                    stdout: result.stdout || '',
                    stderr: result.stderr || '',
                    exitCode: result.exitCode,
                    output: result.stdout || ''
                };
            }
            // Fallback: none protocol (mixed output)
            if (adbDevice.subprocess && adbDevice.subprocess.noneProtocol) {
                var output = await adbDevice.subprocess.noneProtocol.spawnWaitText(cmd);
                return { output: output, stdout: output, stderr: '', exitCode: 0 };
            }
            throw new Error('No subprocess protocol available');
        } catch (e) {
            return { output: '', stdout: '', stderr: e.message, exitCode: -1, error: e.message };
        }
    }

    /**
     * Get device info (model, brand, android version, etc.).
     * Returns object with property key-value pairs.
     */
    async function adbGetInfo() {
        if (!adbDevice) throw new Error('No ADB device connected');
        var props = [
            ['model', 'ro.product.model'],
            ['brand', 'ro.product.brand'],
            ['device', 'ro.product.device'],
            ['manufacturer', 'ro.product.manufacturer'],
            ['android_version', 'ro.build.version.release'],
            ['sdk', 'ro.build.version.sdk'],
            ['build', 'ro.build.display.id'],
            ['security_patch', 'ro.build.version.security_patch'],
            ['cpu_abi', 'ro.product.cpu.abi'],
            ['serialno', 'ro.serialno'],
        ];

        var info = {};
        for (var i = 0; i < props.length; i++) {
            try {
                var result = await adbShell('getprop ' + props[i][1]);
                info[props[i][0]] = (result.stdout || result.output || '').trim();
            } catch (e) {
                info[props[i][0]] = '';
            }
        }

        // Battery info
        try {
            var batt = await adbShell('dumpsys battery');
            var battOut = batt.stdout || batt.output || '';
            var levelMatch = battOut.match(/level:\s*(\d+)/);
            var statusMatch = battOut.match(/status:\s*(\d+)/);
            if (levelMatch) info.battery = levelMatch[1] + '%';
            if (statusMatch) {
                var statuses = {1:'Unknown', 2:'Charging', 3:'Discharging', 4:'Not charging', 5:'Full'};
                info.battery_status = statuses[statusMatch[1]] || 'Unknown';
            }
        } catch (e) {}

        // Storage info
        try {
            var df = await adbShell('df /data');
            var dfOut = df.stdout || df.output || '';
            var lines = dfOut.trim().split('\n');
            if (lines.length >= 2) {
                var parts = lines[1].trim().split(/\s+/);
                if (parts.length >= 4) {
                    info.storage_total = parts[1];
                    info.storage_used = parts[2];
                    info.storage_free = parts[3];
                }
            }
        } catch (e) {}

        adbDeviceInfo = info;
        return info;
    }

    /**
     * Reboot ADB device to specified mode.
     */
    async function adbReboot(mode) {
        if (!adbDevice) throw new Error('No ADB device connected');
        if (!adbDevice.power) throw new Error('Power commands not available');
        switch (mode) {
            case 'system':     await adbDevice.power.reboot(); break;
            case 'bootloader': await adbDevice.power.bootloader(); break;
            case 'recovery':   await adbDevice.power.recovery(); break;
            case 'fastboot':   await adbDevice.power.fastboot(); break;
            case 'sideload':   await adbDevice.power.sideload(); break;
            default:           await adbDevice.power.reboot(); break;
        }
        adbDevice = null;
        adbTransport = null;
        return { success: true };
    }

    /**
     * Install APK on connected device.
     * @param {Blob|File} blob - APK file
     */
    async function adbInstall(blob) {
        if (!adbDevice) throw new Error('No ADB device connected');
        // Push to temp location then pm install
        var tmpPath = '/data/local/tmp/autarch_install.apk';
        await adbPush(blob, tmpPath);
        var result = await adbShell('pm install -r ' + tmpPath);
        await adbShell('rm ' + tmpPath);
        return result;
    }

    /**
     * Push a file to the device.
     * @param {Blob|File|Uint8Array} data - File data
     * @param {string} remotePath - Destination path on device
     */
    async function adbPush(data, remotePath) {
        if (!adbDevice) throw new Error('No ADB device connected');
        var sync = await adbDevice.sync();
        try {
            var bytes;
            if (data instanceof Uint8Array) {
                bytes = data;
            } else if (data instanceof Blob) {
                var ab = await data.arrayBuffer();
                bytes = new Uint8Array(ab);
            } else {
                throw new Error('Unsupported data type');
            }
            var stream = new ReadableStream({
                start: function(controller) {
                    controller.enqueue(bytes);
                    controller.close();
                }
            });
            await sync.write({
                filename: remotePath,
                file: stream,
                permission: 0o644,
                mtime: Math.floor(Date.now() / 1000),
            });
            return { success: true };
        } finally {
            await sync.dispose();
        }
    }

    /**
     * Pull a file from the device.
     * Returns Blob.
     */
    async function adbPull(remotePath) {
        if (!adbDevice) throw new Error('No ADB device connected');
        var sync = await adbDevice.sync();
        try {
            var readable = sync.read(remotePath);
            var reader = readable.getReader();
            var chunks = [];
            while (true) {
                var result = await reader.read();
                if (result.done) break;
                chunks.push(result.value);
            }
            var totalLen = chunks.reduce(function(s, c) { return s + c.length; }, 0);
            var combined = new Uint8Array(totalLen);
            var offset = 0;
            for (var i = 0; i < chunks.length; i++) {
                combined.set(chunks[i], offset);
                offset += chunks[i].length;
            }
            return new Blob([combined]);
        } finally {
            await sync.dispose();
        }
    }

    /**
     * Get logcat output.
     */
    async function adbLogcat(lines) {
        lines = lines || 100;
        return await adbShell('logcat -d -t ' + lines);
    }

    /**
     * Disconnect from ADB device.
     */
    async function adbDisconnect() {
        if (adbDevice) {
            try { await adbDevice.close(); } catch (e) {}
        }
        if (adbUsbDevice) {
            // Release the USB interface so Windows won't block the next connect()
            try { await adbUsbDevice.close(); } catch (e) {}
        }
        adbDevice = null;
        adbTransport = null;
        adbUsbDevice = null;
        adbDeviceInfo = {};
    }

    /**
     * Check if ADB device is connected.
     */
    function adbIsConnected() {
        return adbDevice !== null;
    }

    /**
     * Get a human-readable label for the connected ADB device.
     * Returns "Model (serial)" or "Connected device" if info not yet fetched.
     */
    function adbGetDeviceLabel() {
        if (!adbDevice) return 'Not connected';
        var model = adbDeviceInfo.model || '';
        var serial = adbUsbDevice ? (adbUsbDevice.serial || '') : '';
        if (model && serial) return model + ' (' + serial + ')';
        if (model) return model;
        if (serial) return serial;
        return 'Connected device';
    }


    // ══════════════════════════════════════════════════════════════
    // FASTBOOT (WebUSB)
    // ══════════════════════════════════════════════════════════════

    /**
     * Connect to a fastboot device (shows browser USB picker).
     */
    async function fbConnect() {
        if (!supported.webusb) throw new Error('WebUSB not supported');
        if (fbDevice) await fbDisconnect();
        fbDevice = new Fastboot.FastbootDevice();
        await fbDevice.connect();
        return true;
    }

    /**
     * Get fastboot device info (getvar queries).
     */
    async function fbGetInfo() {
        if (!fbDevice) throw new Error('No fastboot device connected');
        var vars = ['product', 'variant', 'serialno', 'secure', 'unlocked',
                    'current-slot', 'max-download-size', 'battery-voltage',
                    'battery-soc-ok', 'hw-revision', 'version-bootloader',
                    'version-baseband', 'off-mode-charge'];
        var info = {};
        for (var i = 0; i < vars.length; i++) {
            try {
                info[vars[i]] = await fbDevice.getVariable(vars[i]);
            } catch (e) {
                info[vars[i]] = '';
            }
        }
        return info;
    }

    /**
     * Flash a partition.
     * @param {string} partition - Partition name (boot, recovery, system, etc.)
     * @param {Blob|File} blob - Firmware image
     * @param {function} progressCb - Called with (progress: 0-1)
     */
    async function fbFlash(partition, blob, progressCb) {
        if (!fbDevice) throw new Error('No fastboot device connected');
        var callback = progressCb || function() {};
        await fbDevice.flashBlob(partition, blob, function(progress) {
            callback(progress);
        });
        return { success: true };
    }

    /**
     * Reboot fastboot device.
     */
    async function fbReboot(mode) {
        if (!fbDevice) throw new Error('No fastboot device connected');
        switch (mode) {
            case 'bootloader': await fbDevice.reboot('bootloader'); break;
            case 'recovery':   await fbDevice.reboot('recovery'); break;
            default:           await fbDevice.reboot(); break;
        }
        fbDevice = null;
        return { success: true };
    }

    /**
     * OEM unlock the bootloader.
     */
    async function fbOemUnlock() {
        if (!fbDevice) throw new Error('No fastboot device connected');
        await fbDevice.runCommand('oem unlock');
        return { success: true };
    }

    /**
     * Flash a factory image ZIP (PixelFlasher-style).
     * Parses the ZIP, identifies partitions, flashes in sequence.
     * @param {Blob|File} zipBlob - Factory image ZIP file
     * @param {object} options - Flash options
     * @param {function} progressCb - Called with {stage, partition, progress, message}
     */
    async function fbFactoryFlash(zipBlob, options, progressCb) {
        if (!fbDevice) throw new Error('No fastboot device connected');
        options = options || {};
        var callback = progressCb || function() {};

        callback({ stage: 'init', message: 'Reading factory image ZIP...' });

        try {
            // Use fastboot.js built-in factory flash support
            await fbDevice.flashFactoryZip(zipBlob, !options.wipeData, function(action, item, progress) {
                if (action === 'unpack') {
                    callback({ stage: 'unpack', partition: item, progress: progress,
                               message: 'Unpacking: ' + item });
                } else if (action === 'flash') {
                    callback({ stage: 'flash', partition: item, progress: progress,
                               message: 'Flashing: ' + item + ' (' + Math.round(progress * 100) + '%)' });
                } else if (action === 'reboot') {
                    callback({ stage: 'reboot', message: 'Rebooting...' });
                }
            });

            callback({ stage: 'done', message: 'Factory flash complete' });
            return { success: true };
        } catch (e) {
            callback({ stage: 'error', message: 'Flash failed: ' + e.message });
            return { success: false, error: e.message };
        }
    }

    /**
     * Disconnect from fastboot device.
     */
    async function fbDisconnect() {
        if (fbDevice) {
            try { await fbDevice.disconnect(); } catch (e) {}
        }
        fbDevice = null;
    }

    function fbIsConnected() {
        return fbDevice !== null;
    }


    // ══════════════════════════════════════════════════════════════
    // ESP32 (Web Serial)
    // ══════════════════════════════════════════════════════════════

    /**
     * Request a serial port (shows browser serial picker).
     * Returns port reference for later use.
     */
    async function espRequestPort() {
        if (!supported.webserial) throw new Error('Web Serial not supported');
        espPort = await navigator.serial.requestPort({
            filters: [
                { usbVendorId: 0x10C4 }, // Silicon Labs CP210x
                { usbVendorId: 0x1A86 }, // QinHeng CH340
                { usbVendorId: 0x0403 }, // FTDI
                { usbVendorId: 0x303A }, // Espressif USB-JTAG
            ]
        });
        return espPort;
    }

    /**
     * Connect to ESP32 and detect chip.
     * @param {number} baud - Baud rate (default 115200)
     */
    async function espConnect(baud) {
        if (!espPort) throw new Error('No serial port selected. Call espRequestPort() first.');
        baud = baud || 115200;

        if (espTransport) await espDisconnect();

        await espPort.open({ baudRate: baud });
        espTransport = new EspTool.Transport(espPort);
        espLoader = new EspTool.ESPLoader({
            transport: espTransport,
            baudrate: baud,
            romBaudrate: 115200,
        });
        // Connect and detect chip
        await espLoader.main();
        return {
            success: true,
            chip: espLoader.chipName || 'Unknown',
        };
    }

    /**
     * Get detected chip info.
     */
    function espGetChipInfo() {
        if (!espLoader) return null;
        return {
            chip: espLoader.chipName || 'Unknown',
            features: espLoader.chipFeatures || [],
            mac: espLoader.macAddr || '',
        };
    }

    /**
     * Flash firmware to ESP32.
     * @param {Array} fileArray - [{data: Uint8Array|string, address: number}, ...]
     * @param {function} progressCb - Called with (fileIndex, written, total)
     */
    async function espFlash(fileArray, progressCb) {
        if (!espLoader) throw new Error('No ESP32 connected. Call espConnect() first.');
        var callback = progressCb || function() {};

        await espLoader.writeFlash({
            fileArray: fileArray,
            flashSize: 'keep',
            flashMode: 'keep',
            flashFreq: 'keep',
            eraseAll: false,
            compress: true,
            reportProgress: function(fileIndex, written, total) {
                callback(fileIndex, written, total);
            },
        });
        return { success: true };
    }

    /**
     * Start serial monitor on the connected port.
     * @param {number} baud - Baud rate (default 115200)
     * @param {function} outputCb - Called with each line of output
     */
    async function espMonitorStart(baud, outputCb) {
        if (!espPort) throw new Error('No serial port selected');
        baud = baud || 115200;

        // If loader is connected, disconnect it first but keep port open
        if (espLoader) {
            try { await espLoader.hardReset(); } catch (e) {}
            espLoader = null;
            espTransport = null;
        }

        // Close and reopen at monitor baud rate
        try { await espPort.close(); } catch (e) {}
        await espPort.open({ baudRate: baud });

        espMonitorRunning = true;
        var decoder = new TextDecoderStream();
        espPort.readable.pipeTo(decoder.writable).catch(function(e) {
            if (espMonitorRunning) console.error('espMonitor pipeTo:', e);
        });
        espMonitorReader = decoder.readable.getReader();

        (async function readLoop() {
            try {
                while (espMonitorRunning) {
                    var result = await espMonitorReader.read();
                    if (result.done) break;
                    if (result.value && outputCb) {
                        outputCb(result.value);
                    }
                }
            } catch (e) {
                if (espMonitorRunning) {
                    outputCb('[Monitor error: ' + e.message + ']');
                }
            }
        })();

        return { success: true };
    }

    /**
     * Send data to serial monitor.
     */
    async function espMonitorSend(data) {
        if (!espPort || !espPort.writable) throw new Error('No serial monitor active');
        var writer = espPort.writable.getWriter();
        try {
            var encoded = new TextEncoder().encode(data + '\n');
            await writer.write(encoded);
        } finally {
            writer.releaseLock();
        }
    }

    /**
     * Stop serial monitor.
     */
    async function espMonitorStop() {
        espMonitorRunning = false;
        if (espMonitorReader) {
            try { await espMonitorReader.cancel(); } catch (e) {}
            espMonitorReader = null;
        }
    }

    /**
     * Disconnect ESP32 and close serial port.
     */
    async function espDisconnect() {
        espMonitorRunning = false;
        if (espMonitorReader) {
            try { await espMonitorReader.cancel(); } catch (e) {}
            espMonitorReader = null;
        }
        espLoader = null;
        espTransport = null;
        if (espPort) {
            try { await espPort.close(); } catch (e) {}
            espPort = null;
        }
    }

    function espIsConnected() {
        return espLoader !== null || espMonitorRunning;
    }


    // ══════════════════════════════════════════════════════════════
    // Utility
    // ══════════════════════════════════════════════════════════════

    /**
     * Read a local file as Uint8Array (from <input type="file">).
     */
    function readFileAsBytes(file) {
        return new Promise(function(resolve, reject) {
            var reader = new FileReader();
            reader.onload = function() { resolve(new Uint8Array(reader.result)); };
            reader.onerror = function() { reject(reader.error); };
            reader.readAsArrayBuffer(file);
        });
    }

    /**
     * Read a local file as text.
     */
    function readFileAsText(file) {
        return new Promise(function(resolve, reject) {
            var reader = new FileReader();
            reader.onload = function() { resolve(reader.result); };
            reader.onerror = function() { reject(reader.error); };
            reader.readAsText(file);
        });
    }

    /**
     * Download data as a file to the user's machine.
     */
    function downloadBlob(blob, filename) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    // ── Public API ────────────────────────────────────────────────

    return {
        supported: supported,

        // ADB
        adbGetDevices: adbGetDevices,
        adbRequestDevice: adbRequestDevice,
        adbConnect: adbConnect,
        adbShell: adbShell,
        adbGetInfo: adbGetInfo,
        adbReboot: adbReboot,
        adbInstall: adbInstall,
        adbPush: adbPush,
        adbPull: adbPull,
        adbLogcat: adbLogcat,
        adbDisconnect: adbDisconnect,
        adbIsConnected: adbIsConnected,
        adbGetDeviceLabel: adbGetDeviceLabel,

        // Fastboot
        fbConnect: fbConnect,
        fbGetInfo: fbGetInfo,
        fbFlash: fbFlash,
        fbReboot: fbReboot,
        fbOemUnlock: fbOemUnlock,
        fbFactoryFlash: fbFactoryFlash,
        fbDisconnect: fbDisconnect,
        fbIsConnected: fbIsConnected,

        // ESP32
        espRequestPort: espRequestPort,
        espConnect: espConnect,
        espGetChipInfo: espGetChipInfo,
        espFlash: espFlash,
        espMonitorStart: espMonitorStart,
        espMonitorSend: espMonitorSend,
        espMonitorStop: espMonitorStop,
        espDisconnect: espDisconnect,
        espIsConnected: espIsConnected,

        // Utility
        readFileAsBytes: readFileAsBytes,
        readFileAsText: readFileAsText,
        downloadBlob: downloadBlob,
    };
})();
