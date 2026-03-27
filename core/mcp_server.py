"""
AUTARCH MCP Server
Exposes AUTARCH tools via Model Context Protocol (MCP)
for use with Claude Desktop, Claude Code, and other MCP clients.
"""

import sys
import os
import json
import socket
import subprocess
import threading
from pathlib import Path
from typing import Optional

# Ensure core is importable
_app_dir = Path(__file__).resolve().parent.parent
if str(_app_dir) not in sys.path:
    sys.path.insert(0, str(_app_dir))

from core.config import get_config
from core.paths import find_tool, get_app_dir

# MCP server state
_server_process = None
_server_thread = None


def get_autarch_tools():
    """Build the list of AUTARCH tools to expose via MCP."""
    tools = []

    # ── Network Scanning ──
    tools.append({
        'name': 'nmap_scan',
        'description': 'Run an nmap scan against a target. Returns scan results.',
        'params': {
            'target': {'type': 'string', 'description': 'Target IP, hostname, or CIDR range', 'required': True},
            'ports': {'type': 'string', 'description': 'Port specification (e.g. "22,80,443" or "1-1024")', 'required': False},
            'scan_type': {'type': 'string', 'description': 'Scan type: quick, full, stealth, vuln', 'required': False},
        }
    })

    # ── GeoIP Lookup ──
    tools.append({
        'name': 'geoip_lookup',
        'description': 'Look up geographic and network information for an IP address.',
        'params': {
            'ip': {'type': 'string', 'description': 'IP address to look up', 'required': True},
        }
    })

    # ── DNS Lookup ──
    tools.append({
        'name': 'dns_lookup',
        'description': 'Perform DNS lookups for a domain.',
        'params': {
            'domain': {'type': 'string', 'description': 'Domain name to look up', 'required': True},
            'record_type': {'type': 'string', 'description': 'Record type: A, AAAA, MX, NS, TXT, CNAME, SOA', 'required': False},
        }
    })

    # ── WHOIS ──
    tools.append({
        'name': 'whois_lookup',
        'description': 'Perform WHOIS lookup for a domain or IP.',
        'params': {
            'target': {'type': 'string', 'description': 'Domain or IP to look up', 'required': True},
        }
    })

    # ── Packet Capture ──
    tools.append({
        'name': 'packet_capture',
        'description': 'Capture network packets using tcpdump. Returns captured packet summary.',
        'params': {
            'interface': {'type': 'string', 'description': 'Network interface (e.g. eth0, wlan0)', 'required': False},
            'count': {'type': 'integer', 'description': 'Number of packets to capture (default 10)', 'required': False},
            'filter': {'type': 'string', 'description': 'BPF filter expression', 'required': False},
        }
    })

    # ── WireGuard Status ──
    tools.append({
        'name': 'wireguard_status',
        'description': 'Get WireGuard VPN tunnel status and peer information.',
        'params': {}
    })

    # ── UPnP Status ──
    tools.append({
        'name': 'upnp_status',
        'description': 'Get UPnP port mapping status.',
        'params': {}
    })

    # ── System Info ──
    tools.append({
        'name': 'system_info',
        'description': 'Get AUTARCH system information: hostname, platform, uptime, tool availability.',
        'params': {}
    })

    # ── LLM Chat ──
    tools.append({
        'name': 'llm_chat',
        'description': 'Send a message to the currently configured LLM backend and get a response.',
        'params': {
            'message': {'type': 'string', 'description': 'Message to send to the LLM', 'required': True},
            'system_prompt': {'type': 'string', 'description': 'Optional system prompt', 'required': False},
        }
    })

    # ── Android Device Info ──
    tools.append({
        'name': 'android_devices',
        'description': 'List connected Android devices via ADB.',
        'params': {}
    })

    # ── Config Get/Set ──
    tools.append({
        'name': 'config_get',
        'description': 'Get an AUTARCH configuration value.',
        'params': {
            'section': {'type': 'string', 'description': 'Config section (e.g. autarch, llama, wireguard)', 'required': True},
            'key': {'type': 'string', 'description': 'Config key', 'required': True},
        }
    })

    return tools


def execute_tool(name: str, arguments: dict) -> str:
    """Execute an AUTARCH tool and return the result as a string."""
    config = get_config()

    if name == 'nmap_scan':
        return _run_nmap(arguments, config)
    elif name == 'geoip_lookup':
        return _run_geoip(arguments)
    elif name == 'dns_lookup':
        return _run_dns(arguments)
    elif name == 'whois_lookup':
        return _run_whois(arguments)
    elif name == 'packet_capture':
        return _run_tcpdump(arguments)
    elif name == 'wireguard_status':
        return _run_wg_status(config)
    elif name == 'upnp_status':
        return _run_upnp_status(config)
    elif name == 'system_info':
        return _run_system_info()
    elif name == 'llm_chat':
        return _run_llm_chat(arguments, config)
    elif name == 'android_devices':
        return _run_adb_devices()
    elif name == 'config_get':
        return _run_config_get(arguments, config)
    else:
        return json.dumps({'error': f'Unknown tool: {name}'})


def _run_nmap(args: dict, config) -> str:
    nmap = find_tool('nmap')
    if not nmap:
        return json.dumps({'error': 'nmap not found'})

    target = args.get('target', '')
    if not target:
        return json.dumps({'error': 'target is required'})

    cmd = [str(nmap)]
    scan_type = args.get('scan_type', 'quick')
    if scan_type == 'stealth':
        cmd.extend(['-sS', '-T2'])
    elif scan_type == 'full':
        cmd.extend(['-sV', '-sC', '-O'])
    elif scan_type == 'vuln':
        cmd.extend(['-sV', '--script=vuln'])
    else:
        cmd.extend(['-sV', '-T4'])

    ports = args.get('ports', '')
    if ports:
        cmd.extend(['-p', ports])

    cmd.append(target)

    try:
        nmap_timeout = config.get_int('mcp', 'nmap_timeout', 120)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=nmap_timeout)
        return json.dumps({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.returncode
        })
    except subprocess.TimeoutExpired:
        return json.dumps({'error': f'Scan timed out after {nmap_timeout} seconds'})
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_geoip(args: dict) -> str:
    ip = args.get('ip', '')
    if not ip:
        return json.dumps({'error': 'ip is required'})

    try:
        import urllib.request
        config = get_config()
        geoip_endpoint = config.get('mcp', 'geoip_endpoint', 'http://ip-api.com/json/')
        geoip_timeout = config.get_int('mcp', 'geoip_timeout', 10)
        url = f"{geoip_endpoint}{ip}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=geoip_timeout) as resp:
            return resp.read().decode()
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_dns(args: dict) -> str:
    domain = args.get('domain', '')
    if not domain:
        return json.dumps({'error': 'domain is required'})

    config = get_config()
    dns_timeout = config.get_int('mcp', 'dns_timeout', 10)
    record_type = args.get('record_type', 'A')
    try:
        result = subprocess.run(
            ['dig', '+short', domain, record_type],
            capture_output=True, text=True, timeout=dns_timeout
        )
        records = [r for r in result.stdout.strip().split('\n') if r]
        return json.dumps({'domain': domain, 'type': record_type, 'records': records})
    except FileNotFoundError:
        # Fallback to socket for A records
        try:
            ips = socket.getaddrinfo(domain, None)
            records = list(set(addr[4][0] for addr in ips))
            return json.dumps({'domain': domain, 'type': 'A', 'records': records})
        except Exception as e:
            return json.dumps({'error': str(e)})
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_whois(args: dict) -> str:
    target = args.get('target', '')
    if not target:
        return json.dumps({'error': 'target is required'})

    config = get_config()
    whois_timeout = config.get_int('mcp', 'whois_timeout', 15)
    try:
        result = subprocess.run(
            ['whois', target],
            capture_output=True, text=True, timeout=whois_timeout
        )
        return json.dumps({'target': target, 'output': result.stdout[:4000]})
    except FileNotFoundError:
        return json.dumps({'error': 'whois command not found'})
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_tcpdump(args: dict) -> str:
    tcpdump = find_tool('tcpdump')
    if not tcpdump:
        return json.dumps({'error': 'tcpdump not found'})

    cmd = [str(tcpdump), '-n']
    iface = args.get('interface', '')
    if iface:
        cmd.extend(['-i', iface])

    count = args.get('count', 10)
    cmd.extend(['-c', str(count)])

    bpf_filter = args.get('filter', '')
    if bpf_filter:
        cmd.append(bpf_filter)

    try:
        config = get_config()
        tcpdump_timeout = config.get_int('mcp', 'tcpdump_timeout', 30)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=tcpdump_timeout)
        return json.dumps({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.returncode
        })
    except subprocess.TimeoutExpired:
        return json.dumps({'error': 'Capture timed out'})
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_wg_status(config) -> str:
    wg = find_tool('wg')
    if not wg:
        return json.dumps({'error': 'wg not found'})

    iface = config.get('wireguard', 'interface', 'wg0')
    try:
        result = subprocess.run(
            [str(wg), 'show', iface],
            capture_output=True, text=True, timeout=10
        )
        return json.dumps({
            'interface': iface,
            'output': result.stdout,
            'active': result.returncode == 0
        })
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_upnp_status(config) -> str:
    upnpc = find_tool('upnpc')
    if not upnpc:
        return json.dumps({'error': 'upnpc not found'})

    try:
        result = subprocess.run(
            [str(upnpc), '-l'],
            capture_output=True, text=True, timeout=10
        )
        return json.dumps({
            'output': result.stdout,
            'exit_code': result.returncode
        })
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_system_info() -> str:
    import platform

    info = {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'arch': platform.machine(),
    }

    try:
        info['ip'] = socket.gethostbyname(socket.gethostname())
    except Exception:
        info['ip'] = '127.0.0.1'

    try:
        with open('/proc/uptime') as f:
            uptime_secs = float(f.read().split()[0])
        days = int(uptime_secs // 86400)
        hours = int((uptime_secs % 86400) // 3600)
        info['uptime'] = f"{days}d {hours}h"
    except Exception:
        info['uptime'] = 'N/A'

    # Tool availability
    tools = {}
    for tool in ['nmap', 'tshark', 'tcpdump', 'upnpc', 'wg', 'adb']:
        tools[tool] = find_tool(tool) is not None
    info['tools'] = tools

    config = get_config()
    info['llm_backend'] = config.get('autarch', 'llm_backend', 'local')

    return json.dumps(info)


def _run_llm_chat(args: dict, config) -> str:
    message = args.get('message', '')
    if not message:
        return json.dumps({'error': 'message is required'})

    try:
        from core.llm import get_llm, LLMError
        llm = get_llm()
        if not llm.is_loaded:
            llm.load_model()

        system_prompt = args.get('system_prompt', None)
        response = llm.chat(message, system_prompt=system_prompt)
        return json.dumps({
            'response': response,
            'model': llm.model_name,
            'backend': config.get('autarch', 'llm_backend', 'local')
        })
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_adb_devices() -> str:
    adb = find_tool('adb')
    if not adb:
        return json.dumps({'error': 'adb not found'})

    try:
        result = subprocess.run(
            [str(adb), 'devices', '-l'],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        devices = []
        for line in lines:
            if line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    dev = {'serial': parts[0], 'state': parts[1]}
                    # Parse extra info
                    for part in parts[2:]:
                        if ':' in part:
                            k, v = part.split(':', 1)
                            dev[k] = v
                    devices.append(dev)
        return json.dumps({'devices': devices})
    except Exception as e:
        return json.dumps({'error': str(e)})


def _run_config_get(args: dict, config) -> str:
    section = args.get('section', '')
    key = args.get('key', '')
    if not section or not key:
        return json.dumps({'error': 'section and key are required'})

    # Block sensitive keys
    if key.lower() in ('api_key', 'password', 'secret_key', 'token'):
        return json.dumps({'error': 'Cannot read sensitive configuration values'})

    value = config.get(section, key, fallback='(not set)')
    return json.dumps({'section': section, 'key': key, 'value': value})


def create_mcp_server():
    """Create and return the FastMCP server instance."""
    from mcp.server.fastmcp import FastMCP

    config = get_config()
    mcp_settings = config.get_mcp_settings()

    fastmcp_kwargs = {
        'instructions': mcp_settings['instructions'],
    }
    if mcp_settings['log_level']:
        fastmcp_kwargs['log_level'] = mcp_settings['log_level']
    if mcp_settings['mask_errors']:
        fastmcp_kwargs['mask_error_details'] = True
    if mcp_settings['rate_limit']:
        fastmcp_kwargs['rate_limit'] = mcp_settings['rate_limit']

    mcp = FastMCP("autarch", **fastmcp_kwargs)

    # Filter out disabled tools
    disabled = set(t.strip() for t in mcp_settings['disabled_tools'].split(',') if t.strip())

    # Register all tools
    tool_defs = get_autarch_tools()

    if 'nmap_scan' not in disabled:
        @mcp.tool()
        def nmap_scan(target: str, ports: str = "", scan_type: str = "quick") -> str:
            """Run an nmap network scan against a target. Returns scan results including open ports and services."""
            return execute_tool('nmap_scan', {'target': target, 'ports': ports, 'scan_type': scan_type})

    if 'geoip_lookup' not in disabled:
        @mcp.tool()
        def geoip_lookup(ip: str) -> str:
            """Look up geographic and network information for an IP address."""
            return execute_tool('geoip_lookup', {'ip': ip})

    if 'dns_lookup' not in disabled:
        @mcp.tool()
        def dns_lookup(domain: str, record_type: str = "A") -> str:
            """Perform DNS lookups for a domain. Supports A, AAAA, MX, NS, TXT, CNAME, SOA record types."""
            return execute_tool('dns_lookup', {'domain': domain, 'record_type': record_type})

    if 'whois_lookup' not in disabled:
        @mcp.tool()
        def whois_lookup(target: str) -> str:
            """Perform WHOIS lookup for a domain or IP address."""
            return execute_tool('whois_lookup', {'target': target})

    if 'packet_capture' not in disabled:
        @mcp.tool()
        def packet_capture(interface: str = "", count: int = 10, filter: str = "") -> str:
            """Capture network packets using tcpdump. Returns captured packet summary."""
            return execute_tool('packet_capture', {'interface': interface, 'count': count, 'filter': filter})

    if 'wireguard_status' not in disabled:
        @mcp.tool()
        def wireguard_status() -> str:
            """Get WireGuard VPN tunnel status and peer information."""
            return execute_tool('wireguard_status', {})

    if 'upnp_status' not in disabled:
        @mcp.tool()
        def upnp_status() -> str:
            """Get UPnP port mapping status."""
            return execute_tool('upnp_status', {})

    if 'system_info' not in disabled:
        @mcp.tool()
        def system_info() -> str:
            """Get AUTARCH system information: hostname, platform, uptime, tool availability."""
            return execute_tool('system_info', {})

    if 'llm_chat' not in disabled:
        @mcp.tool()
        def llm_chat(message: str, system_prompt: str = "") -> str:
            """Send a message to the currently configured LLM backend and get a response."""
            args = {'message': message}
            if system_prompt:
                args['system_prompt'] = system_prompt
            return execute_tool('llm_chat', args)

    if 'android_devices' not in disabled:
        @mcp.tool()
        def android_devices() -> str:
            """List connected Android devices via ADB."""
            return execute_tool('android_devices', {})

    if 'config_get' not in disabled:
        @mcp.tool()
        def config_get(section: str, key: str) -> str:
            """Get an AUTARCH configuration value. Sensitive keys (api_key, password) are blocked."""
            return execute_tool('config_get', {'section': section, 'key': key})

    return mcp


def run_stdio():
    """Run the MCP server in stdio mode (for Claude Desktop / Claude Code)."""
    mcp = create_mcp_server()
    mcp.run(transport='stdio')


def run_sse(host: str = '0.0.0.0', port: int = 8081):
    """Run the MCP server in SSE (Server-Sent Events) mode for web clients."""
    config = get_config()
    mcp_settings = config.get_mcp_settings()
    if host == '0.0.0.0':
        host = mcp_settings['host']
    if port == 8081:
        port = mcp_settings['port']
    mcp = create_mcp_server()
    mcp.run(transport='sse', host=host, port=port)


def get_mcp_config_snippet() -> str:
    """Generate the JSON config snippet for Claude Desktop / Claude Code."""
    app_dir = get_app_dir()
    python = sys.executable

    config = {
        "mcpServers": {
            "autarch": {
                "command": python,
                "args": [str(app_dir / "core" / "mcp_server.py"), "--stdio"],
                "env": {}
            }
        }
    }
    return json.dumps(config, indent=2)


def get_server_status() -> dict:
    """Check if the MCP server is running."""
    global _server_process
    if _server_process and _server_process.poll() is None:
        return {'running': True, 'pid': _server_process.pid, 'mode': 'sse'}
    return {'running': False}


def start_sse_server(host: str = '0.0.0.0', port: int = 8081) -> dict:
    """Start the MCP SSE server in the background."""
    global _server_process

    config = get_config()
    mcp_settings = config.get_mcp_settings()
    if host == '0.0.0.0':
        host = mcp_settings['host']
    if port == 8081:
        port = mcp_settings['port']

    status = get_server_status()
    if status['running']:
        return {'ok': False, 'error': f'Already running (PID {status["pid"]})'}

    python = sys.executable
    script = str(Path(__file__).resolve())

    _server_process = subprocess.Popen(
        [python, script, '--sse', '--host', host, '--port', str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    return {'ok': True, 'pid': _server_process.pid, 'host': host, 'port': port}


def stop_sse_server() -> dict:
    """Stop the MCP SSE server."""
    global _server_process

    status = get_server_status()
    if not status['running']:
        return {'ok': False, 'error': 'Not running'}

    _server_process.terminate()
    try:
        _server_process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _server_process.kill()
    _server_process = None
    return {'ok': True}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='AUTARCH MCP Server')
    parser.add_argument('--stdio', action='store_true', help='Run in stdio mode (for Claude Desktop/Code)')
    parser.add_argument('--sse', action='store_true', help='Run in SSE mode (for web clients)')
    parser.add_argument('--host', default='0.0.0.0', help='SSE host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8081, help='SSE port (default: 8081)')
    args = parser.parse_args()

    if args.sse:
        print(f"Starting AUTARCH MCP server (SSE) on {args.host}:{args.port}")
        run_sse(host=args.host, port=args.port)
    else:
        # Default to stdio
        run_stdio()
