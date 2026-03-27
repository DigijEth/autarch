package com.darkhal.archon.server;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Archon Privileged Server — runs via app_process at shell (UID 2000) level.
 *
 * Started via ADB:
 *   CLASSPATH=/data/app/.../base.apk app_process /system/bin \
 *     --nice-name=archon_server com.darkhal.archon.server.ArchonServer <token> <port>
 *
 * Listens on localhost:<port> for JSON commands authenticated with a token.
 * Modeled after Shizuku's server architecture but uses TCP sockets instead of Binder IPC.
 *
 * Protocol (JSON over TCP, newline-delimited):
 *   Request:  {"token":"xxx","cmd":"pm list packages","timeout":30}
 *   Response: {"stdout":"...","stderr":"...","exit_code":0}
 *
 * Special commands:
 *   {"token":"xxx","cmd":"__ping__"}     → {"stdout":"pong","stderr":"","exit_code":0}
 *   {"token":"xxx","cmd":"__shutdown__"} → server exits gracefully
 *   {"token":"xxx","cmd":"__info__"}     → {"stdout":"uid=2000 pid=... uptime=...","stderr":"","exit_code":0}
 */
public class ArchonServer {

    private static final String TAG = "ArchonServer";
    private static final String LOG_FILE = "/data/local/tmp/archon_server.log";
    private static final int DEFAULT_TIMEOUT = 30;
    private static final int SOCKET_TIMEOUT = 0; // No timeout on accept (blocking)

    // Safety blocklist — commands that could brick the device
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

    private static String authToken;
    private static int listenPort;
    private static final AtomicBoolean running = new AtomicBoolean(true);
    private static ExecutorService executor;
    private static long startTime;

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: ArchonServer <token> <port>");
            System.exit(1);
        }

        authToken = args[0];
        listenPort = Integer.parseInt(args[1]);
        startTime = System.currentTimeMillis();

        log("Starting Archon Server on port " + listenPort);
        log("PID: " + android.os.Process.myPid() + " UID: " + android.os.Process.myUid());

        // Handle SIGTERM for graceful shutdown
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log("Shutdown hook triggered");
            running.set(false);
            if (executor != null) {
                executor.shutdownNow();
            }
        }));

        executor = Executors.newCachedThreadPool();

        try {
            // Bind to localhost only — not accessible from network
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            ServerSocket serverSocket = new ServerSocket(listenPort, 5, loopback);
            log("Listening on 127.0.0.1:" + listenPort);

            while (running.get()) {
                try {
                    Socket client = serverSocket.accept();
                    client.setSoTimeout(60000); // 60s read timeout per connection
                    executor.submit(() -> handleClient(client));
                } catch (SocketTimeoutException e) {
                    // Expected, loop continues
                } catch (IOException e) {
                    if (running.get()) {
                        log("Accept error: " + e.getMessage());
                    }
                }
            }

            serverSocket.close();
        } catch (IOException e) {
            log("Fatal: " + e.getMessage());
            System.exit(2);
        }

        log("Server stopped");
        if (executor != null) {
            executor.shutdown();
            try {
                executor.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
        }
        System.exit(0);
    }

    private static void handleClient(Socket client) {
        String clientAddr = client.getRemoteSocketAddress().toString();
        log("Client connected: " + clientAddr);

        try (
            BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream()));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(client.getOutputStream()), true)
        ) {
            String line;
            while ((line = reader.readLine()) != null) {
                String response = processRequest(line);
                writer.println(response);
                writer.flush();

                // Check if we should shut down after this request
                if (!running.get()) {
                    break;
                }
            }
        } catch (IOException e) {
            log("Client error: " + e.getMessage());
        } finally {
            try { client.close(); } catch (IOException ignored) {}
            log("Client disconnected: " + clientAddr);
        }
    }

    private static String processRequest(String json) {
        // Simple JSON parsing without dependencies
        String token = extractJsonString(json, "token");
        String cmd = extractJsonString(json, "cmd");
        int timeout = extractJsonInt(json, "timeout", DEFAULT_TIMEOUT);

        // No-auth alive check — allows any client to verify server is running
        if ("__alive__".equals(cmd)) {
            return jsonResponse("alive", "", 0);
        }

        // Verify auth token
        if (token == null || !token.equals(authToken)) {
            log("Auth failed from request");
            return jsonResponse("", "Authentication failed", -1);
        }

        if (cmd == null || cmd.isEmpty()) {
            return jsonResponse("", "No command specified", -1);
        }

        // Handle special commands
        switch (cmd) {
            case "__ping__":
                return jsonResponse("pong", "", 0);

            case "__shutdown__":
                log("Shutdown requested");
                running.set(false);
                return jsonResponse("Server shutting down", "", 0);

            case "__info__":
                long uptime = (System.currentTimeMillis() - startTime) / 1000;
                String info = "uid=" + android.os.Process.myUid() +
                    " pid=" + android.os.Process.myPid() +
                    " uptime=" + uptime + "s";
                return jsonResponse(info, "", 0);
        }

        // Safety check
        if (isBlocked(cmd)) {
            log("BLOCKED dangerous command: " + cmd);
            return jsonResponse("", "Command blocked by safety filter", -1);
        }

        // Execute the command
        return executeCommand(cmd, timeout);
    }

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

            // Read stdout and stderr in parallel to avoid deadlocks
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
                return jsonResponse(stdout.toString(), "Command timed out after " + timeoutSec + "s", -1);
            }

            stdoutThread.join(5000);
            stderrThread.join(5000);

            return jsonResponse(stdout.toString(), stderr.toString(), process.exitValue());

        } catch (Exception e) {
            return jsonResponse("", "Execution error: " + e.getMessage(), -1);
        }
    }

    // ── JSON helpers (no library dependencies) ──────────────────────

    private static String jsonResponse(String stdout, String stderr, int exitCode) {
        return "{\"stdout\":" + jsonEscape(stdout) +
            ",\"stderr\":" + jsonEscape(stderr) +
            ",\"exit_code\":" + exitCode + "}";
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
        // Pattern: "key":"value" or "key": "value"
        String search = "\"" + key + "\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;

        idx = json.indexOf(':', idx + search.length());
        if (idx < 0) return null;

        // Skip whitespace
        idx++;
        while (idx < json.length() && json.charAt(idx) == ' ') idx++;

        if (idx >= json.length() || json.charAt(idx) != '"') return null;
        idx++; // skip opening quote

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

    // ── Logging ─────────────────────────────────────────────────────

    private static void log(String msg) {
        String timestamp = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        String line = timestamp + " [" + TAG + "] " + msg;
        System.out.println(line);

        try {
            FileWriter fw = new FileWriter(LOG_FILE, true);
            fw.write(line + "\n");
            fw.close();
        } catch (IOException ignored) {
            // Can't write log file — not fatal
        }
    }
}
