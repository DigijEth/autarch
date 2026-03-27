package com.darkhal.archon.server;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;

/**
 * Archon Remote Interactive Shell (arish) — like Shizuku's "rish" but for Archon.
 *
 * Connects to the running ArchonServer on localhost and provides an interactive
 * shell at UID 2000 (shell privileges). This gives terminal users the same
 * elevated access that the Archon app modules use internally.
 *
 * Usage (from adb shell or terminal emulator):
 *   arish                          — interactive shell
 *   arish <command>                — execute single command
 *   arish -t <token>               — specify auth token
 *   arish -p <port>                — specify server port
 *   echo "pm list packages" | arish — pipe commands
 *
 * The "arish" shell script in assets/ sets up CLASSPATH and invokes this via app_process.
 *
 * Bootstrap:
 *   CLASSPATH='/data/app/.../base.apk' /system/bin/app_process /system/bin \
 *     --nice-name=arish com.darkhal.archon.server.ArchonRish [args...]
 */
public class ArchonRish {

    private static final String DEFAULT_TOKEN_FILE = "/data/local/tmp/.archon_token";
    private static final int DEFAULT_PORT = 17321;
    private static final int CONNECT_TIMEOUT = 3000;
    private static final int READ_TIMEOUT = 30000;

    public static void main(String[] args) {
        String token = null;
        int port = DEFAULT_PORT;
        String singleCmd = null;
        boolean showHelp = false;

        // Parse arguments
        int i = 0;
        while (i < args.length) {
            switch (args[i]) {
                case "-t":
                case "--token":
                    if (i + 1 < args.length) {
                        token = args[++i];
                    }
                    break;
                case "-p":
                case "--port":
                    if (i + 1 < args.length) {
                        port = Integer.parseInt(args[++i]);
                    }
                    break;
                case "-h":
                case "--help":
                    showHelp = true;
                    break;
                default:
                    // Everything else is a command to execute
                    StringBuilder sb = new StringBuilder();
                    for (int j = i; j < args.length; j++) {
                        if (j > i) sb.append(' ');
                        sb.append(args[j]);
                    }
                    singleCmd = sb.toString();
                    i = args.length; // break outer loop
                    break;
            }
            i++;
        }

        if (showHelp) {
            printHelp();
            return;
        }

        // Try to read token from file if not provided
        if (token == null) {
            token = readTokenFile();
        }
        if (token == null) {
            System.err.println("arish: no auth token. Use -t <token> or ensure ArchonServer wrote " + DEFAULT_TOKEN_FILE);
            System.exit(1);
        }

        // Check if stdin is a pipe (non-interactive)
        boolean isPiped = false;
        try {
            isPiped = System.in.available() > 0 || singleCmd != null;
        } catch (Exception e) {
            // Assume interactive
        }

        if (singleCmd != null) {
            // Single command mode
            int exitCode = executeRemote(token, port, singleCmd);
            System.exit(exitCode);
        } else if (isPiped) {
            // Pipe mode — read commands from stdin
            runPiped(token, port);
        } else {
            // Interactive mode
            runInteractive(token, port);
        }
    }

    private static void runInteractive(String token, int port) {
        System.out.println("arish — Archon Remote Interactive Shell (UID 2000)");
        System.out.println("Connected to ArchonServer on localhost:" + port);
        System.out.println("Type 'exit' to quit.\n");

        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));

        while (true) {
            System.out.print("arish$ ");
            System.out.flush();

            String line;
            try {
                line = stdin.readLine();
            } catch (Exception e) {
                break;
            }
            if (line == null) break; // EOF
            line = line.trim();
            if (line.isEmpty()) continue;
            if (line.equals("exit") || line.equals("quit")) break;

            executeRemote(token, port, line);
        }

        System.out.println("\narish: disconnected");
    }

    private static void runPiped(String token, int port) {
        BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        int lastExit = 0;
        try {
            String line;
            while ((line = stdin.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                lastExit = executeRemote(token, port, line);
            }
        } catch (Exception e) {
            System.err.println("arish: read error: " + e.getMessage());
        }
        System.exit(lastExit);
    }

    private static int executeRemote(String token, int port, String command) {
        try {
            InetAddress loopback = InetAddress.getByName("127.0.0.1");
            Socket sock = new Socket();
            sock.connect(new java.net.InetSocketAddress(loopback, port), CONNECT_TIMEOUT);
            sock.setSoTimeout(READ_TIMEOUT);

            PrintWriter writer = new PrintWriter(new OutputStreamWriter(sock.getOutputStream()), true);
            BufferedReader reader = new BufferedReader(new InputStreamReader(sock.getInputStream()));

            // Send command as JSON
            String json = "{\"token\":\"" + escapeJson(token) + "\","
                        + "\"cmd\":\"" + escapeJson(command) + "\","
                        + "\"timeout\":30}";
            writer.println(json);
            writer.flush();

            // Read response
            String response = reader.readLine();
            sock.close();

            if (response == null) {
                System.err.println("arish: no response from server");
                return -1;
            }

            // Parse JSON response (minimal hand-parsing, same as ArchonServer pattern)
            String stdout = extractJsonString(response, "stdout");
            String stderr = extractJsonString(response, "stderr");
            int exitCode = extractJsonInt(response, "exit_code", -1);

            if (stdout != null && !stdout.isEmpty()) {
                System.out.print(stdout);
                if (!stdout.endsWith("\n")) System.out.println();
            }
            if (stderr != null && !stderr.isEmpty()) {
                System.err.print(stderr);
                if (!stderr.endsWith("\n")) System.err.println();
            }

            return exitCode;

        } catch (java.net.ConnectException e) {
            System.err.println("arish: cannot connect to ArchonServer on localhost:" + port);
            System.err.println("arish: is the server running? Check Setup tab in Archon app.");
            return -1;
        } catch (Exception e) {
            System.err.println("arish: error: " + e.getMessage());
            return -1;
        }
    }

    // ── JSON Helpers (hand-rolled, no library dependencies) ──────

    private static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int j = 0; j < s.length(); j++) {
            char c = s.charAt(j);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:   sb.append(c); break;
            }
        }
        return sb.toString();
    }

    private static String extractJsonString(String json, String key) {
        String searchKey = "\"" + key + "\":\"";
        int start = json.indexOf(searchKey);
        if (start < 0) return "";
        start += searchKey.length();

        StringBuilder sb = new StringBuilder();
        boolean escape = false;
        for (int j = start; j < json.length(); j++) {
            char c = json.charAt(j);
            if (escape) {
                switch (c) {
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    default: sb.append(c); break;
                }
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                break;
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static int extractJsonInt(String json, String key, int defaultValue) {
        // Try "key":N pattern
        String searchKey = "\"" + key + "\":";
        int start = json.indexOf(searchKey);
        if (start < 0) return defaultValue;
        start += searchKey.length();

        StringBuilder sb = new StringBuilder();
        for (int j = start; j < json.length(); j++) {
            char c = json.charAt(j);
            if (c == '-' || (c >= '0' && c <= '9')) {
                sb.append(c);
            } else {
                break;
            }
        }
        try {
            return Integer.parseInt(sb.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private static String readTokenFile() {
        try {
            java.io.File f = new java.io.File(DEFAULT_TOKEN_FILE);
            if (!f.exists()) return null;
            BufferedReader br = new BufferedReader(new java.io.FileReader(f));
            String token = br.readLine();
            br.close();
            if (token != null) token = token.trim();
            return (token != null && !token.isEmpty()) ? token : null;
        } catch (Exception e) {
            return null;
        }
    }

    private static void printHelp() {
        System.out.println("arish — Archon Remote Interactive Shell");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  arish                    Interactive shell (UID 2000)");
        System.out.println("  arish <command>           Execute single command");
        System.out.println("  arish -t <token>          Specify auth token");
        System.out.println("  arish -p <port>           Specify server port (default: 17321)");
        System.out.println("  echo \"cmd\" | arish        Pipe commands");
        System.out.println();
        System.out.println("The ArchonServer must be running (start from the Archon app Setup tab).");
        System.out.println("Commands execute at UID 2000 (shell) — same as adb shell.");
        System.out.println();
        System.out.println("Token is read from " + DEFAULT_TOKEN_FILE + " if not specified.");
        System.out.println("The Archon app writes this file when the server starts.");
    }
}
