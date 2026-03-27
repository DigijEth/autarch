"""
AUTARCH Metasploit Integration
Interface for Metasploit Framework via RPC
"""

import json
import http.client
import ssl
import socket
import subprocess
import time
import os
import signal
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass

# msgpack is optional - MSF features disabled without it
try:
    import msgpack
    MSGPACK_AVAILABLE = True
except ImportError:
    msgpack = None
    MSGPACK_AVAILABLE = False

from .config import get_config
from .banner import Colors
from core.daemon import root_exec


class MSFError(Exception):
    """Exception raised for Metasploit-related errors."""
    pass


def check_msgpack():
    """Check if msgpack is available, raise error if not."""
    if not MSGPACK_AVAILABLE:
        raise MSFError(
            "msgpack module not installed. Install with: pip install msgpack"
        )


@dataclass
class MSFModule:
    """Information about a Metasploit module."""
    type: str  # exploit, auxiliary, post, payload, encoder, nop
    name: str
    fullname: str
    description: str
    rank: str = ""
    author: List[str] = None
    references: List[str] = None


class MetasploitRPC:
    """Client for Metasploit RPC API."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 55553,
        username: str = "msf",
        password: str = None,
        ssl: bool = True
    ):
        """Initialize MSF RPC client.

        Args:
            host: MSF RPC host address.
            port: MSF RPC port (default 55553).
            username: RPC username.
            password: RPC password.
            ssl: Use SSL connection.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = ssl
        self.token: Optional[str] = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        """Check if connected to MSF RPC."""
        return self._connected and self.token is not None

    def _decode_bytes(self, obj):
        """Recursively decode bytes to strings in msgpack responses.

        Args:
            obj: Object to decode (dict, list, bytes, or other).

        Returns:
            Decoded object with all bytes converted to strings.
        """
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        elif isinstance(obj, dict):
            return {
                self._decode_bytes(k): self._decode_bytes(v)
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [self._decode_bytes(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._decode_bytes(item) for item in obj)
        else:
            return obj

    def _request(self, method: str, params: List = None) -> Dict[str, Any]:
        """Make an RPC request to Metasploit.

        Args:
            method: RPC method name.
            params: Method parameters.

        Returns:
            Response dictionary.

        Raises:
            MSFError: If request fails.
        """
        check_msgpack()  # Ensure msgpack is available

        params = params or []

        # Add token to authenticated requests
        if self.token and method != "auth.login":
            params = [self.token] + params

        # Build request
        request_data = msgpack.packb([method] + params)

        try:
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(
                    self.host, self.port, context=context, timeout=30
                )
            else:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=30)

            headers = {
                "Content-Type": "binary/message-pack",
                "Content-Length": str(len(request_data))
            }

            conn.request("POST", "/api/", request_data, headers)
            response = conn.getresponse()

            if response.status != 200:
                raise MSFError(f"HTTP error: {response.status} {response.reason}")

            response_data = response.read()
            result = msgpack.unpackb(response_data, raw=False, strict_map_key=False)

            # Recursively normalize bytes to strings throughout the response
            result = self._decode_bytes(result)

            if isinstance(result, dict) and result.get("error"):
                raise MSFError(f"MSF error: {result.get('error_message', 'Unknown error')}")

            return result

        except ConnectionRefusedError:
            raise MSFError(f"Connection refused to {self.host}:{self.port}. Is msfrpcd running?")
        except Exception as e:
            if isinstance(e, MSFError):
                raise
            raise MSFError(f"RPC request failed: {e}")
        finally:
            try:
                conn.close()
            except:
                pass

    def connect(self, password: str = None) -> bool:
        """Connect and authenticate to MSF RPC.

        Args:
            password: RPC password (uses stored password if not provided).

        Returns:
            True if connected successfully.

        Raises:
            MSFError: If connection fails.
        """
        password = password or self.password
        if not password:
            raise MSFError("No password provided for MSF RPC")

        try:
            result = self._request("auth.login", [self.username, password])

            if result.get("result") == "success":
                self.token = result.get("token")
                self._connected = True
                return True
            else:
                raise MSFError("Authentication failed")

        except MSFError:
            self._connected = False
            self.token = None
            raise

    def disconnect(self):
        """Disconnect from MSF RPC."""
        if self.token:
            try:
                self._request("auth.logout", [self.token])
            except:
                pass
        self.token = None
        self._connected = False

    def get_version(self) -> Dict[str, str]:
        """Get Metasploit version info.

        Returns:
            Dictionary with version information.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")
        return self._request("core.version")

    def list_modules(self, module_type: str = None) -> List[str]:
        """List available modules.

        Args:
            module_type: Filter by type (exploit, auxiliary, post, payload, encoder, nop).

        Returns:
            List of module names.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        # Map module types to their API method names
        # The MSF RPC API uses module.exploits, module.auxiliary, etc.
        type_to_method = {
            "exploit": "module.exploits",
            "auxiliary": "module.auxiliary",
            "post": "module.post",
            "payload": "module.payloads",
            "encoder": "module.encoders",
            "nop": "module.nops",
        }

        if module_type:
            method = type_to_method.get(module_type)
            if not method:
                raise MSFError(f"Unknown module type: {module_type}")
            result = self._request(method)
            return result.get("modules", [])
        else:
            # Get all module types
            all_modules = []
            for mtype in ["exploit", "auxiliary", "post", "payload"]:
                try:
                    method = type_to_method.get(mtype)
                    result = self._request(method)
                    modules = result.get("modules", [])
                    all_modules.extend([f"{mtype}/{m}" for m in modules])
                except:
                    pass
            return all_modules

    def search_modules(self, query: str) -> List[Dict[str, Any]]:
        """Search for modules matching a query.

        Args:
            query: Search query string.

        Returns:
            List of matching modules.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("module.search", [query])
        return result if isinstance(result, list) else []

    def get_module_info(self, module_type: str, module_name: str) -> MSFModule:
        """Get detailed information about a module.

        Args:
            module_type: Module type (exploit, auxiliary, etc.).
            module_name: Module name.

        Returns:
            MSFModule with module details.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("module.info", [module_type, module_name])

        return MSFModule(
            type=module_type,
            name=result.get("name", module_name),
            fullname=f"{module_type}/{module_name}",
            description=result.get("description", ""),
            rank=result.get("rank", ""),
            author=result.get("author", []),
            references=result.get("references", [])
        )

    def get_module_options(self, module_type: str, module_name: str) -> Dict[str, Any]:
        """Get available options for a module.

        Args:
            module_type: Module type.
            module_name: Module name.

        Returns:
            Dictionary of options and their details.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        return self._request("module.options", [module_type, module_name])

    def execute_module(
        self,
        module_type: str,
        module_name: str,
        options: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Execute a module with given options.

        Args:
            module_type: Module type.
            module_name: Module name.
            options: Module options dictionary.

        Returns:
            Execution result with job_id.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        options = options or {}
        return self._request("module.execute", [module_type, module_name, options])

    def list_jobs(self) -> Dict[str, Any]:
        """List running jobs.

        Returns:
            Dictionary of job IDs and info.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        return self._request("job.list")

    def get_job_info(self, job_id: str) -> Dict[str, Any]:
        """Get information about a job.

        Args:
            job_id: Job ID.

        Returns:
            Job information dictionary.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        return self._request("job.info", [job_id])

    def stop_job(self, job_id: str) -> bool:
        """Stop a running job.

        Args:
            job_id: Job ID to stop.

        Returns:
            True if stopped successfully.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("job.stop", [job_id])
        return result.get("result") == "success"

    def list_sessions(self) -> Dict[str, Any]:
        """List active sessions.

        Returns:
            Dictionary of session IDs and info.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        return self._request("session.list")

    def session_shell_read(self, session_id: str) -> str:
        """Read output from a shell session.

        Args:
            session_id: Session ID.

        Returns:
            Shell output string.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("session.shell_read", [session_id])
        return result.get("data", "")

    def session_shell_write(self, session_id: str, command: str) -> bool:
        """Write a command to a shell session.

        Args:
            session_id: Session ID.
            command: Command to execute.

        Returns:
            True if written successfully.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("session.shell_write", [session_id, command + "\n"])
        return result.get("write_count", 0) > 0

    def session_stop(self, session_id: str) -> bool:
        """Stop/kill a session.

        Args:
            session_id: Session ID to stop.

        Returns:
            True if stopped successfully.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        result = self._request("session.stop", [session_id])
        return result.get("result") == "success"

    def run_console_command(self, command: str) -> str:
        """Run a command in MSF console.

        Args:
            command: Console command to run.

        Returns:
            Command output.
        """
        if not self.is_connected:
            raise MSFError("Not connected to MSF RPC")

        # Create console
        console = self._request("console.create")
        console_id = console.get("id")

        try:
            # Write command
            self._request("console.write", [console_id, command + "\n"])

            # Read output (with retries for async commands)
            import time
            output = ""
            for _ in range(10):
                time.sleep(0.5)
                result = self._request("console.read", [console_id])
                output += result.get("data", "")
                if not result.get("busy", False):
                    break

            return output

        finally:
            # Destroy console
            try:
                self._request("console.destroy", [console_id])
            except:
                pass


class MSFManager:
    """High-level manager for Metasploit integration."""

    def __init__(self):
        self.config = get_config()
        self.rpc: Optional[MetasploitRPC] = None
        self._server_process: Optional[subprocess.Popen] = None

    def _ensure_config_section(self):
        """Ensure MSF config section exists."""
        if not self.config.config.has_section('msf'):
            self.config.config['msf'] = {
                'host': '127.0.0.1',
                'port': '55553',
                'username': 'msf',
                'password': '',
                'ssl': 'true',
                'autoconnect': 'true'
            }
            self.config.save()

    def detect_server(self) -> Tuple[bool, Optional[str]]:
        """Detect if msfrpcd is already running.

        Returns:
            Tuple of (is_running, pid or None)
        """
        settings = self.get_settings()
        host = settings['host']
        port = settings['port']

        # First try socket connection to check if port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()

            if result == 0:
                # Port is open, try to find the process
                pid = self._find_msfrpcd_pid()
                return True, pid
        except Exception:
            pass

        # Also check for running msfrpcd process even if port check failed
        pid = self._find_msfrpcd_pid()
        if pid:
            return True, pid

        return False, None

    def _find_msfrpcd_pid(self) -> Optional[str]:
        """Find the PID of running msfrpcd process.

        Works on both Linux (pgrep, /proc) and Windows (tasklist, wmic).

        Returns:
            PID as string, or None if not found
        """
        import sys
        is_win = sys.platform == 'win32'

        if is_win:
            # Windows: use tasklist to find ruby/msfrpcd processes
            for search_term in ['msfrpcd', 'thin', 'ruby']:
                try:
                    result = subprocess.run(
                        ['tasklist', '/FI', f'IMAGENAME eq {search_term}*',
                         '/FO', 'CSV', '/NH'],
                        capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for line in result.stdout.strip().split('\n'):
                            line = line.strip().strip('"')
                            if line and 'INFO:' not in line:
                                parts = line.split('","')
                                if len(parts) >= 2:
                                    return parts[1].strip('"')
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

            # Fallback: wmic for command-line matching
            try:
                result = subprocess.run(
                    ['wmic', 'process', 'where',
                     "commandline like '%msfrpcd%' or commandline like '%thin%msf%'",
                     'get', 'processid'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        line = line.strip()
                        if line.isdigit():
                            return line
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        else:
            # Linux: use pgrep
            try:
                result = subprocess.run(
                    ['pgrep', '-f', 'msfrpcd'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    pids = result.stdout.strip().split('\n')
                    return pids[0] if pids else None
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Fallback: check /proc on Linux
            try:
                for pid_dir in os.listdir('/proc'):
                    if pid_dir.isdigit():
                        try:
                            cmdline_path = f'/proc/{pid_dir}/cmdline'
                            with open(cmdline_path, 'r') as f:
                                cmdline = f.read()
                                if 'msfrpcd' in cmdline:
                                    return pid_dir
                        except (IOError, PermissionError):
                            continue
            except Exception:
                pass

        return None

    def kill_server(self, use_sudo: bool = True) -> bool:
        """Kill any running msfrpcd server.

        Args:
            use_sudo: Use sudo for killing (needed if server was started with sudo).
                      Ignored on Windows.

        Returns:
            True if server was killed or no server was running
        """
        import sys
        is_win = sys.platform == 'win32'

        is_running, pid = self.detect_server()

        if not is_running:
            return True

        # Disconnect our client first if connected
        if self.is_connected:
            self.disconnect()

        if is_win:
            # Windows: use taskkill
            if pid:
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/PID', str(pid)],
                        capture_output=True, timeout=10
                    )
                    time.sleep(1)
                    return True
                except Exception as e:
                    print(f"{Colors.RED}[X] Failed to kill msfrpcd (PID {pid}): {e}{Colors.RESET}")

            # Fallback: kill by image name
            for name in ['msfrpcd', 'ruby', 'thin']:
                try:
                    subprocess.run(
                        ['taskkill', '/F', '/IM', f'{name}.exe'],
                        capture_output=True, timeout=5
                    )
                except Exception:
                    pass
            time.sleep(1)
            return True
        else:
            # Linux: kill by PID or pkill
            if pid:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                    time.sleep(1)
                    try:
                        os.kill(int(pid), 0)
                        os.kill(int(pid), signal.SIGKILL)
                        time.sleep(0.5)
                    except ProcessLookupError:
                        pass
                    return True
                except PermissionError:
                    if use_sudo:
                        try:
                            root_exec(['kill', '-TERM', str(pid)], timeout=5)
                            time.sleep(1)
                            try:
                                os.kill(int(pid), 0)
                                root_exec(['kill', '-KILL', str(pid)], timeout=5)
                            except ProcessLookupError:
                                pass
                            return True
                        except Exception as e:
                            print(f"{Colors.RED}[X] Failed to kill msfrpcd with sudo (PID {pid}): {e}{Colors.RESET}")
                            return False
                    else:
                        print(f"{Colors.RED}[X] Failed to kill msfrpcd (PID {pid}): Permission denied{Colors.RESET}")
                        return False
                except ProcessLookupError:
                    return True

            # Try pkill as fallback
            try:
                if use_sudo:
                    root_exec(['pkill', '-f', 'msfrpcd'], timeout=5)
                else:
                    subprocess.run(['pkill', '-f', 'msfrpcd'], timeout=5)
                time.sleep(1)
                return True
            except Exception:
                pass

        return False

    def _find_msf_install(self) -> Optional[str]:
        """Find the Metasploit Framework installation directory.

        Returns:
            Path to the MSF install directory, or None if not found.
        """
        import sys
        is_win = sys.platform == 'win32'

        if is_win:
            # Common Windows Metasploit install paths
            candidates = [
                os.path.join(os.environ.get('ProgramFiles', r'C:\Program Files'), 'Metasploit'),
                os.path.join(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), 'Metasploit'),
                r'C:\metasploit-framework',
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Metasploit'),
                os.path.join(os.environ.get('ProgramFiles', ''), 'Rapid7', 'Metasploit'),
            ]
            for c in candidates:
                if c and os.path.isdir(c):
                    return c
                # Also check with -framework suffix
                cf = c + '-framework' if not c.endswith('-framework') else c
                if cf and os.path.isdir(cf):
                    return cf
        else:
            candidates = [
                '/opt/metasploit-framework',
                '/usr/share/metasploit-framework',
                '/opt/metasploit',
                os.path.expanduser('~/.msf4'),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    return c

        return None

    def start_server(self, username: str, password: str,
                     host: str = "127.0.0.1", port: int = 55553,
                     use_ssl: bool = True, use_sudo: bool = True) -> bool:
        """Start the msfrpcd server with given credentials.

        Works on both Linux and Windows.

        Args:
            username: RPC username
            password: RPC password
            host: Host to bind to
            port: Port to listen on
            use_ssl: Whether to use SSL
            use_sudo: Run msfrpcd with sudo (Linux only; ignored on Windows)

        Returns:
            True if server started successfully
        """
        import sys
        is_win = sys.platform == 'win32'

        # Find msfrpcd binary
        from core.paths import find_tool
        msfrpcd_bin = find_tool('msfrpcd')

        if not msfrpcd_bin and is_win:
            # Windows: look for msfrpcd.bat in common locations
            msf_dir = self._find_msf_install()
            if msf_dir:
                for candidate in [
                    os.path.join(msf_dir, 'bin', 'msfrpcd.bat'),
                    os.path.join(msf_dir, 'bin', 'msfrpcd'),
                    os.path.join(msf_dir, 'msfrpcd.bat'),
                    os.path.join(msf_dir, 'embedded', 'bin', 'ruby.exe'),
                ]:
                    if os.path.isfile(candidate):
                        msfrpcd_bin = candidate
                        break

            if not msfrpcd_bin:
                # Try PATH with .bat extension
                for ext in ['.bat', '.cmd', '.exe', '']:
                    for p in os.environ.get('PATH', '').split(os.pathsep):
                        candidate = os.path.join(p, f'msfrpcd{ext}')
                        if os.path.isfile(candidate):
                            msfrpcd_bin = candidate
                            break
                    if msfrpcd_bin:
                        break

        if not msfrpcd_bin:
            msfrpcd_bin = 'msfrpcd'  # Last resort: hope it's on PATH

        # Build command
        cmd = [
            msfrpcd_bin,
            '-U', username,
            '-P', password,
            '-a', host,
            '-p', str(port),
            '-f'  # Run in foreground (we'll background it ourselves)
        ]

        if not use_ssl:
            cmd.append('-S')  # Disable SSL

        # On Windows, if it's a .bat file, run through cmd
        if is_win and msfrpcd_bin.endswith('.bat'):
            cmd = ['cmd', '/c'] + cmd

        # Note: msfrpcd runs through the daemon if root is needed
        # For Popen-based background processes, we don't use the daemon socket
        if not is_win and use_sudo:
            cmd = ['sudo', '-n'] + cmd  # non-interactive sudo fallback

        try:
            # Start msfrpcd in background
            popen_kwargs = {
                'stdout': subprocess.DEVNULL,
                'stderr': subprocess.DEVNULL,
            }
            if is_win:
                popen_kwargs['creationflags'] = (
                    subprocess.CREATE_NEW_PROCESS_GROUP |
                    subprocess.CREATE_NO_WINDOW
                )
            else:
                popen_kwargs['start_new_session'] = True

            self._server_process = subprocess.Popen(cmd, **popen_kwargs)

            # Wait for server to start (check port becomes available)
            max_wait = 30
            start_time = time.time()
            port_open = False

            while time.time() - start_time < max_wait:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()

                    if result == 0:
                        port_open = True
                        break
                except Exception:
                    pass

                time.sleep(0.5)

            if not port_open:
                print(f"{Colors.YELLOW}[!] Server started but port not responding after {max_wait}s{Colors.RESET}")
                return False

            # Port is open, but server needs time to initialize RPC layer
            print(f"{Colors.DIM}  Waiting for RPC initialization...{Colors.RESET}")
            time.sleep(5)

            # Try a test connection to verify server is really ready
            for attempt in range(10):
                try:
                    test_rpc = MetasploitRPC(
                        host=host, port=port, username=username,
                        password=password, ssl=use_ssl
                    )
                    test_rpc.connect(password)
                    test_rpc.disconnect()
                    return True
                except MSFError:
                    if attempt < 9:
                        time.sleep(2)
                    continue
                except Exception:
                    if attempt < 9:
                        time.sleep(2)
                    continue

            print(f"{Colors.YELLOW}[!] Server running but authentication not ready - try connecting manually{Colors.RESET}")
            return True

        except FileNotFoundError:
            print(f"{Colors.RED}[X] msfrpcd not found. Is Metasploit installed?{Colors.RESET}")
            return False
        except Exception as e:
            print(f"{Colors.RED}[X] Failed to start msfrpcd: {e}{Colors.RESET}")
            return False

    def get_settings(self) -> Dict[str, Any]:
        """Get current MSF settings."""
        self._ensure_config_section()
        return {
            'host': self.config.get('msf', 'host', '127.0.0.1'),
            'port': self.config.get_int('msf', 'port', 55553),
            'username': self.config.get('msf', 'username', 'msf'),
            'password': self.config.get('msf', 'password', ''),
            'ssl': self.config.get_bool('msf', 'ssl', True),
            'autoconnect': self.config.get_bool('msf', 'autoconnect', True)
        }

    def save_settings(self, host: str, port: int, username: str, password: str, use_ssl: bool):
        """Save MSF settings."""
        self._ensure_config_section()
        self.config.set('msf', 'host', host)
        self.config.set('msf', 'port', port)
        self.config.set('msf', 'username', username)
        self.config.set('msf', 'password', password)
        self.config.set('msf', 'ssl', str(use_ssl).lower())
        self.config.save()

    def connect(self, password: str = None) -> MetasploitRPC:
        """Connect to Metasploit RPC.

        Args:
            password: RPC password (uses saved if not provided).

        Returns:
            Connected MetasploitRPC instance.
        """
        settings = self.get_settings()
        password = password or settings['password']

        self.rpc = MetasploitRPC(
            host=settings['host'],
            port=settings['port'],
            username=settings['username'],
            password=password,
            ssl=settings['ssl']
        )

        self.rpc.connect(password)
        return self.rpc

    def disconnect(self):
        """Disconnect from Metasploit RPC."""
        if self.rpc:
            self.rpc.disconnect()
            self.rpc = None

    @property
    def is_connected(self) -> bool:
        """Check if connected to MSF."""
        return self.rpc is not None and self.rpc.is_connected

    def autoconnect(self) -> bool:
        """Perform automatic MSF server detection and connection on startup.

        Flow:
        1. Scan for existing msfrpcd server
        2. If found: kill it, ask for new credentials, restart with new creds
        3. If not found: ask for credentials, start server
        4. Connect to the server

        Returns:
            True if successfully connected to MSF
        """
        settings = self.get_settings()

        print(f"\n{Colors.CYAN}[*] Metasploit Auto-Connect{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")

        # Step 1: Detect existing server
        print(f"\n{Colors.WHITE}  Scanning for existing MSF RPC server...{Colors.RESET}")
        is_running, pid = self.detect_server()

        if is_running:
            print(f"{Colors.YELLOW}  [!] Found existing msfrpcd server{Colors.RESET}", end="")
            if pid:
                print(f" (PID: {pid})")
            else:
                print()

            # Kill existing server (use sudo in case it was started with sudo)
            print(f"{Colors.WHITE}  Stopping existing server...{Colors.RESET}")
            if not self.kill_server(use_sudo=True):
                print(f"{Colors.RED}  [X] Failed to stop existing server{Colors.RESET}")
                print(f"{Colors.DIM}  You may need to manually run: sudo pkill -f msfrpcd{Colors.RESET}")
                return False
            print(f"{Colors.GREEN}  [+] Server stopped{Colors.RESET}")
        else:
            print(f"{Colors.DIM}  No existing server detected{Colors.RESET}")

        # Step 2: Ask for credentials
        print(f"\n{Colors.BOLD}  Configure MSF RPC Credentials{Colors.RESET}")
        print(f"{Colors.DIM}  These credentials will be used for the new server{Colors.RESET}\n")

        try:
            default_user = settings.get('username', 'msf')
            default_host = settings.get('host', '127.0.0.1')
            default_port = settings.get('port', 55553)

            username = input(f"    Username [{default_user}]: ").strip()
            if not username:
                username = default_user

            password = input(f"    Password (required): ").strip()
            if not password:
                print(f"{Colors.RED}  [X] Password is required{Colors.RESET}")
                return False

            host_input = input(f"    Host [{default_host}]: ").strip()
            host = host_input if host_input else default_host

            port_input = input(f"    Port [{default_port}]: ").strip()
            try:
                port = int(port_input) if port_input else default_port
            except ValueError:
                port = default_port

            ssl_input = input(f"    Use SSL (y/n) [y]: ").strip().lower()
            use_ssl = ssl_input != 'n'

            # Ask about sudo - default to yes for full module support
            print(f"\n{Colors.DIM}    Note: Running with sudo enables raw socket modules (SYN scan, etc.){Colors.RESET}")
            sudo_input = input(f"    Run with sudo (y/n) [y]: ").strip().lower()
            use_sudo = sudo_input != 'n'

        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}  [!] Setup cancelled{Colors.RESET}")
            return False

        # Save settings
        self.save_settings(host, port, username, password, use_ssl)

        # Step 3: Start server
        if use_sudo:
            print(f"\n{Colors.WHITE}  Starting msfrpcd server with sudo...{Colors.RESET}")
            print(f"{Colors.DIM}  (You may be prompted for your password){Colors.RESET}")
        else:
            print(f"\n{Colors.WHITE}  Starting msfrpcd server...{Colors.RESET}")

        if not self.start_server(username, password, host, port, use_ssl, use_sudo):
            print(f"{Colors.RED}  [X] Failed to start msfrpcd server{Colors.RESET}")
            return False

        print(f"{Colors.GREEN}  [+] Server started on {host}:{port}{Colors.RESET}")

        # Step 4: Connect
        print(f"{Colors.WHITE}  Connecting to server...{Colors.RESET}")
        try:
            self.connect(password)
            version = self.rpc.get_version()
            print(f"{Colors.GREEN}  [+] Connected to Metasploit {version.get('version', 'Unknown')}{Colors.RESET}")
            return True
        except MSFError as e:
            print(f"{Colors.RED}  [X] Connection failed: {e}{Colors.RESET}")
            return False

    def set_autoconnect(self, enabled: bool):
        """Enable or disable autoconnect on startup."""
        self._ensure_config_section()
        self.config.set('msf', 'autoconnect', str(enabled).lower())
        self.config.save()


# Global MSF manager instance
_msf_manager: Optional[MSFManager] = None


def get_msf_manager() -> MSFManager:
    """Get the global MSF manager instance."""
    global _msf_manager
    if _msf_manager is None:
        _msf_manager = MSFManager()
    return _msf_manager


def msf_startup_autoconnect(skip_if_disabled: bool = True) -> bool:
    """Perform MSF autoconnect during application startup.

    This is the main entry point for the autoconnect feature.
    Call this during application initialization.

    Args:
        skip_if_disabled: If True, skip autoconnect if disabled in config

    Returns:
        True if connected successfully, False otherwise
    """
    msf = get_msf_manager()
    settings = msf.get_settings()

    # Check if autoconnect is enabled
    if skip_if_disabled and not settings.get('autoconnect', True):
        print(f"{Colors.DIM}  MSF autoconnect disabled in settings{Colors.RESET}")
        return False

    # Check if msgpack is available
    if not MSGPACK_AVAILABLE:
        print(f"{Colors.YELLOW}[!] msgpack not installed - MSF features disabled{Colors.RESET}")
        print(f"{Colors.DIM}    Install with: pip install msgpack{Colors.RESET}")
        return False

    return msf.autoconnect()


def msf_quick_connect(username: str = None, password: str = None,
                      host: str = "127.0.0.1", port: int = 55553,
                      use_ssl: bool = True, kill_existing: bool = True,
                      use_sudo: bool = True) -> bool:
    """Quick non-interactive MSF server setup and connection.

    Useful for scripting or when credentials are already known.

    Args:
        username: RPC username (default: msf)
        password: RPC password (required)
        host: Host address
        port: RPC port
        use_ssl: Use SSL connection
        kill_existing: Kill any existing msfrpcd server first
        use_sudo: Run msfrpcd with sudo (required for raw socket modules)

    Returns:
        True if connected successfully
    """
    if not password:
        print(f"{Colors.RED}[X] Password required for msf_quick_connect{Colors.RESET}")
        return False

    if not MSGPACK_AVAILABLE:
        print(f"{Colors.RED}[X] msgpack not installed{Colors.RESET}")
        return False

    username = username or "msf"
    msf = get_msf_manager()

    # Kill existing if requested
    if kill_existing:
        is_running, _ = msf.detect_server()
        if is_running:
            print(f"{Colors.WHITE}[*] Stopping existing msfrpcd...{Colors.RESET}")
            msf.kill_server(use_sudo=use_sudo)

    # Save and start
    msf.save_settings(host, port, username, password, use_ssl)

    print(f"{Colors.WHITE}[*] Starting msfrpcd{' with sudo' if use_sudo else ''}...{Colors.RESET}")
    if not msf.start_server(username, password, host, port, use_ssl, use_sudo):
        return False

    print(f"{Colors.WHITE}[*] Connecting...{Colors.RESET}")
    try:
        msf.connect(password)
        print(f"{Colors.GREEN}[+] Connected to Metasploit{Colors.RESET}")
        return True
    except MSFError as e:
        print(f"{Colors.RED}[X] Connection failed: {e}{Colors.RESET}")
        return False
