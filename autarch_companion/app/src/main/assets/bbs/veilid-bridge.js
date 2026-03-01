/**
 * Autarch BBS — Veilid Bridge
 *
 * Handles the BBS terminal interface and will integrate with
 * veilid-wasm when the BBS server is deployed on the VPS.
 *
 * Native Android bridge: window.ArchonBridge
 */

const output = document.getElementById('output');
const cmdInput = document.getElementById('cmd-input');

// Terminal output helpers
function writeLine(text, className) {
    const div = document.createElement('div');
    div.className = 'line' + (className ? ' ' + className : '');
    div.textContent = text;
    output.appendChild(div);
    output.scrollTop = output.scrollHeight;
}

function writeSystem(text) { writeLine(text, 'system'); }
function writeError(text) { writeLine(text, 'error'); }
function writeInfo(text) { writeLine(text, 'info'); }
function writeSuccess(text) { writeLine(text, 'success'); }

/**
 * VeilidBBS — placeholder for Veilid WASM integration.
 *
 * When the BBS server is deployed, this class will:
 * 1. Load veilid-wasm from bundled assets
 * 2. Initialize a Veilid routing context
 * 3. Connect to the BBS server via DHT key
 * 4. Send/receive messages through the Veilid network
 */
class VeilidBBS {
    constructor() {
        this.connected = false;
        this.serverAddress = '';
    }

    async initialize() {
        // Get config from native bridge
        if (window.ArchonBridge) {
            this.serverAddress = window.ArchonBridge.getServerAddress();
            const configJson = window.ArchonBridge.getVeilidConfig();
            this.config = JSON.parse(configJson);
            this.log('Veilid config loaded');
        }
    }

    async connect() {
        if (!this.serverAddress) {
            writeError('No BBS server address configured.');
            writeSystem('Set the Veilid BBS address in Settings.');
            return false;
        }

        writeSystem('Connecting to Autarch BBS...');
        writeSystem('Server: ' + this.serverAddress);

        // Placeholder — actual Veilid connection will go here
        // Steps when implemented:
        // 1. await veilid.veilidCoreStartupJSON(config)
        // 2. await veilid.veilidCoreAttach()
        // 3. Create routing context
        // 4. Open route to BBS server DHT key
        // 5. Send/receive via app_message / app_call

        writeError('Veilid WASM not yet loaded.');
        writeSystem('BBS server deployment pending.');
        writeSystem('');
        writeInfo('The Autarch BBS will be available once the');
        writeInfo('VPS server is configured and the Veilid');
        writeInfo('WASM module is bundled into this app.');
        writeSystem('');
        return false;
    }

    async sendMessage(msg) {
        if (!this.connected) {
            writeError('Not connected to BBS.');
            return;
        }
        // Placeholder for sending messages via Veilid
        this.log('Send: ' + msg);
    }

    async disconnect() {
        this.connected = false;
        writeSystem('Disconnected from BBS.');
    }

    log(msg) {
        if (window.ArchonBridge) {
            window.ArchonBridge.log(msg);
        }
        console.log('[VeilidBBS] ' + msg);
    }
}

// Command handler
const bbs = new VeilidBBS();
const commandHistory = [];
let historyIndex = -1;

const commands = {
    help: function() {
        writeInfo('Available commands:');
        writeLine('  help       — Show this help');
        writeLine('  connect    — Connect to Autarch BBS');
        writeLine('  disconnect — Disconnect from BBS');
        writeLine('  status     — Show connection status');
        writeLine('  clear      — Clear terminal');
        writeLine('  about      — About Autarch BBS');
        writeLine('  version    — Show version info');
    },

    connect: async function() {
        await bbs.connect();
    },

    disconnect: async function() {
        await bbs.disconnect();
    },

    status: function() {
        writeInfo('Connection Status:');
        writeLine('  Connected: ' + (bbs.connected ? 'YES' : 'NO'));
        writeLine('  Server: ' + (bbs.serverAddress || 'not configured'));
        if (window.ArchonBridge) {
            writeLine('  Archon URL: ' + window.ArchonBridge.getAutarchUrl());
        }
    },

    clear: function() {
        output.innerHTML = '';
    },

    about: function() {
        writeInfo('╔════════════════════════════════════╗');
        writeInfo('║       AUTARCH BBS                  ║');
        writeInfo('╠════════════════════════════════════╣');
        writeLine('║ A decentralized bulletin board     ║');
        writeLine('║ system secured by the Veilid       ║');
        writeLine('║ protocol. All communications are   ║');
        writeLine('║ end-to-end encrypted and routed    ║');
        writeLine('║ through an onion-style network.    ║');
        writeInfo('╚════════════════════════════════════╝');
    },

    version: function() {
        let ver = '1.0.0';
        if (window.ArchonBridge) {
            ver = window.ArchonBridge.getAppVersion();
        }
        writeLine('Archon v' + ver);
        writeLine('Veilid WASM: not loaded (pending deployment)');
    }
};

function processCommand(input) {
    const trimmed = input.trim();
    if (!trimmed) return;

    writeLine('> ' + trimmed);
    commandHistory.push(trimmed);
    historyIndex = commandHistory.length;

    const parts = trimmed.split(/\s+/);
    const cmd = parts[0].toLowerCase();

    if (commands[cmd]) {
        commands[cmd](parts.slice(1));
    } else if (bbs.connected) {
        // If connected, send as BBS message
        bbs.sendMessage(trimmed);
    } else {
        writeError('Unknown command: ' + cmd);
        writeSystem('Type "help" for available commands.');
    }
}

// Input handling
cmdInput.addEventListener('keydown', function(e) {
    if (e.key === 'Enter') {
        processCommand(this.value);
        this.value = '';
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            this.value = commandHistory[historyIndex];
        }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++;
            this.value = commandHistory[historyIndex];
        } else {
            historyIndex = commandHistory.length;
            this.value = '';
        }
    }
});

// Keep input focused
document.addEventListener('click', function() {
    cmdInput.focus();
});

// Startup
(async function() {
    writeSuccess('AUTARCH BBS Terminal v1.0');
    writeSystem('Initializing...');
    writeSystem('');

    await bbs.initialize();

    writeSystem('Type "help" for commands.');
    writeSystem('Type "connect" to connect to the BBS.');
    writeSystem('');

    cmdInput.focus();
})();
