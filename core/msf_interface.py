"""
AUTARCH Metasploit Interface
Centralized high-level interface for all Metasploit operations.

This module provides a clean API for executing MSF modules, handling
connection management, output parsing, and error recovery.

Usage:
    from core.msf_interface import get_msf_interface, MSFResult

    msf = get_msf_interface()
    result = msf.run_module('auxiliary/scanner/portscan/tcp', {'RHOSTS': '192.168.1.1'})

    if result.success:
        for finding in result.findings:
            print(finding)
"""

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum

# Import the low-level MSF components
from core.msf import get_msf_manager, MSFError, MSFManager
from core.banner import Colors


class MSFStatus(Enum):
    """Status of an MSF operation."""
    SUCCESS = "success"
    PARTIAL = "partial"  # Some results but also errors
    FAILED = "failed"
    AUTH_ERROR = "auth_error"
    CONNECTION_ERROR = "connection_error"
    TIMEOUT = "timeout"
    NOT_CONNECTED = "not_connected"


@dataclass
class MSFResult:
    """Result from an MSF module execution."""
    status: MSFStatus
    module: str
    target: str = ""

    # Raw and cleaned output
    raw_output: str = ""
    cleaned_output: str = ""

    # Parsed results
    findings: List[str] = field(default_factory=list)  # [+] lines
    info: List[str] = field(default_factory=list)      # [*] lines
    errors: List[str] = field(default_factory=list)    # [-] lines
    warnings: List[str] = field(default_factory=list)  # [!] lines

    # For scan results
    open_ports: List[Dict] = field(default_factory=list)  # [{port, service, state}]
    services: List[Dict] = field(default_factory=list)    # [{name, version, info}]

    # Metadata
    execution_time: float = 0.0
    error_count: int = 0

    @property
    def success(self) -> bool:
        return self.status in (MSFStatus.SUCCESS, MSFStatus.PARTIAL)

    def get_summary(self) -> str:
        """Get a brief summary of the result."""
        if self.status == MSFStatus.SUCCESS:
            return f"Success: {len(self.findings)} findings"
        elif self.status == MSFStatus.PARTIAL:
            return f"Partial: {len(self.findings)} findings, {self.error_count} errors"
        elif self.status == MSFStatus.AUTH_ERROR:
            return "Authentication token expired"
        elif self.status == MSFStatus.CONNECTION_ERROR:
            return "Connection to MSF failed"
        elif self.status == MSFStatus.TIMEOUT:
            return "Module execution timed out"
        else:
            return f"Failed: {self.errors[0] if self.errors else 'Unknown error'}"


class MSFInterface:
    """High-level interface for Metasploit operations."""

    # Patterns to filter from output (banner noise, Easter eggs, etc.)
    SKIP_PATTERNS = [
        'metasploit', '=[ ', '+ -- --=[', 'Documentation:',
        'Rapid7', 'Open Source', 'MAGIC WORD', 'PERMISSION DENIED',
        'access security', 'access:', 'Ready...', 'Alpha E',
        'Version 4.0', 'System Security Interface', 'Metasploit Park',
        'exploits -', 'auxiliary -', 'payloads', 'encoders -',
        'evasion', 'nops -', 'post -', 'msf6', 'msf5', 'msf >',
    ]

    # Patterns indicating specific result types
    PORT_PATTERN = re.compile(
        r'(\d{1,5})/(tcp|udp)\s+(open|closed|filtered)?\s*(\S+)?',
        re.IGNORECASE
    )
    SERVICE_PATTERN = re.compile(
        r'\[\+\].*?(\d+\.\d+\.\d+\.\d+):(\d+)\s*[-:]\s*(.+)',
        re.IGNORECASE
    )
    VERSION_PATTERN = re.compile(
        r'(?:version|running|server)[\s:]+([^\n\r]+)',
        re.IGNORECASE
    )

    def __init__(self):
        self._manager: Optional[MSFManager] = None
        self._last_error: Optional[str] = None

    @property
    def manager(self) -> MSFManager:
        """Get or create the MSF manager."""
        if self._manager is None:
            self._manager = get_msf_manager()
        return self._manager

    @property
    def is_connected(self) -> bool:
        """Check if connected to MSF RPC."""
        return self.manager.is_connected

    @property
    def last_error(self) -> Optional[str]:
        """Get the last error message."""
        return self._last_error

    def ensure_connected(self, password: str = None, auto_prompt: bool = True) -> Tuple[bool, str]:
        """Ensure we have a valid connection to MSF RPC.

        Args:
            password: Optional password to use for connection.
            auto_prompt: If True, prompt for password if needed.

        Returns:
            Tuple of (success, message).
        """
        # Check if already connected
        if self.is_connected:
            # Verify the connection is actually valid with a test request
            try:
                self.manager.rpc.get_version()
                return True, "Connected"
            except Exception as e:
                error_str = str(e)
                if 'Invalid Authentication Token' in error_str:
                    # Token expired, need to reconnect
                    pass
                else:
                    self._last_error = error_str
                    return False, f"Connection test failed: {error_str}"

        # Need to connect or reconnect
        try:
            # Disconnect existing stale connection
            if self.manager.rpc:
                try:
                    self.manager.rpc.disconnect()
                except:
                    pass

            # Get password from settings or parameter
            settings = self.manager.get_settings()
            connect_password = password or settings.get('password')

            if not connect_password and auto_prompt:
                print(f"{Colors.YELLOW}[!] MSF RPC password required{Colors.RESET}")
                connect_password = input(f"    Password: ").strip()

            if not connect_password:
                self._last_error = "No password provided"
                return False, "No password provided"

            # Connect
            self.manager.connect(connect_password)
            return True, "Connected successfully"

        except MSFError as e:
            self._last_error = str(e)
            return False, f"MSF Error: {e}"
        except Exception as e:
            self._last_error = str(e)
            return False, f"Connection failed: {e}"

    def _run_console_command(self, commands: str, timeout: int = 120) -> Tuple[str, Optional[str]]:
        """Execute commands via MSF console and capture output.

        Args:
            commands: Newline-separated commands to run.
            timeout: Maximum wait time in seconds.

        Returns:
            Tuple of (output, error_message).
        """
        try:
            # Create console
            console = self.manager.rpc._request("console.create")
            console_id = console.get("id")

            if not console_id:
                return "", "Failed to create console"

            try:
                # Wait for console to initialize and consume banner
                time.sleep(2)
                self.manager.rpc._request("console.read", [console_id])

                # Send commands one at a time
                for cmd in commands.strip().split('\n'):
                    cmd = cmd.strip()
                    if cmd:
                        self.manager.rpc._request("console.write", [console_id, cmd + "\n"])
                        time.sleep(0.3)

                # Collect output
                output = ""
                waited = 0
                idle_count = 0

                while waited < timeout:
                    time.sleep(1)
                    waited += 1

                    result = self.manager.rpc._request("console.read", [console_id])
                    new_data = result.get("data", "")

                    if new_data:
                        output += new_data
                        idle_count = 0
                    else:
                        idle_count += 1

                    # Stop if not busy and idle for 3+ seconds
                    if not result.get("busy", False) and idle_count >= 3:
                        break

                # Check for timeout
                if waited >= timeout:
                    return output, "Execution timed out"

                return output, None

            finally:
                # Clean up console
                try:
                    self.manager.rpc._request("console.destroy", [console_id])
                except:
                    pass

        except Exception as e:
            error_str = str(e)
            if 'Invalid Authentication Token' in error_str:
                return "", "AUTH_ERROR"
            return "", f"Console error: {e}"

    def _clean_output(self, raw_output: str) -> str:
        """Remove banner noise and clean up MSF output.

        Args:
            raw_output: Raw console output.

        Returns:
            Cleaned output string.
        """
        lines = []
        for line in raw_output.split('\n'):
            line_stripped = line.strip()

            # Skip empty lines
            if not line_stripped:
                continue

            # Skip banner/noise patterns
            skip = False
            for pattern in self.SKIP_PATTERNS:
                if pattern.lower() in line_stripped.lower():
                    skip = True
                    break

            if skip:
                continue

            # Skip prompt lines
            if line_stripped.startswith('>') and len(line_stripped) < 5:
                continue

            # Skip set confirmations (we already show these)
            if ' => ' in line_stripped and any(
                line_stripped.startswith(opt) for opt in
                ['RHOSTS', 'RHOST', 'PORTS', 'LHOST', 'LPORT', 'THREADS']
            ):
                continue

            lines.append(line)

        return '\n'.join(lines)

    def _parse_output(self, cleaned_output: str, module_path: str) -> Dict[str, Any]:
        """Parse cleaned output into structured data.

        Args:
            cleaned_output: Cleaned console output.
            module_path: The module that was run (for context).

        Returns:
            Dictionary with parsed results.
        """
        result = {
            'findings': [],
            'info': [],
            'errors': [],
            'warnings': [],
            'open_ports': [],
            'services': [],
            'error_count': 0,
        }

        is_scanner = 'scanner' in module_path.lower()
        is_portscan = 'portscan' in module_path.lower()

        for line in cleaned_output.split('\n'):
            line_stripped = line.strip()

            # Categorize by prefix
            if '[+]' in line:
                result['findings'].append(line_stripped)

                # Try to extract port/service info from scanner results
                if is_scanner:
                    # Look for IP:port patterns
                    service_match = self.SERVICE_PATTERN.search(line)
                    if service_match:
                        ip, port, info = service_match.groups()
                        result['services'].append({
                            'ip': ip,
                            'port': int(port),
                            'info': info.strip()
                        })

                    # Look for "open" port mentions
                    if is_portscan and 'open' in line.lower():
                        port_match = re.search(r':(\d+)\s', line)
                        if port_match:
                            result['open_ports'].append({
                                'port': int(port_match.group(1)),
                                'state': 'open'
                            })

            elif '[-]' in line or 'Error:' in line:
                # Count NoMethodError and similar spam but don't store each one
                if 'NoMethodError' in line or 'undefined method' in line:
                    result['error_count'] += 1
                else:
                    result['errors'].append(line_stripped)

            elif '[!]' in line:
                result['warnings'].append(line_stripped)

            elif '[*]' in line:
                result['info'].append(line_stripped)

        return result

    def run_module(
        self,
        module_path: str,
        options: Dict[str, Any] = None,
        timeout: int = 120,
        auto_reconnect: bool = True
    ) -> MSFResult:
        """Execute an MSF module and return parsed results.

        Args:
            module_path: Full module path (e.g., 'auxiliary/scanner/portscan/tcp').
            options: Module options dictionary.
            timeout: Maximum execution time in seconds.
            auto_reconnect: If True, attempt to reconnect on auth errors.

        Returns:
            MSFResult with parsed output.
        """
        options = options or {}
        target = options.get('RHOSTS', options.get('RHOST', ''))
        start_time = time.time()

        # Ensure connected
        connected, msg = self.ensure_connected()
        if not connected:
            return MSFResult(
                status=MSFStatus.NOT_CONNECTED,
                module=module_path,
                target=target,
                errors=[msg]
            )

        # Build console commands
        commands = f"use {module_path}\n"
        for key, value in options.items():
            commands += f"set {key} {value}\n"
        commands += "run"

        # Execute
        raw_output, error = self._run_console_command(commands, timeout)

        # Handle auth error with reconnect
        if error == "AUTH_ERROR" and auto_reconnect:
            connected, msg = self.ensure_connected()
            if connected:
                raw_output, error = self._run_console_command(commands, timeout)
            else:
                return MSFResult(
                    status=MSFStatus.AUTH_ERROR,
                    module=module_path,
                    target=target,
                    errors=["Session expired and reconnection failed"]
                )

        # Handle other errors
        if error and error != "AUTH_ERROR":
            if "timed out" in error.lower():
                status = MSFStatus.TIMEOUT
            else:
                status = MSFStatus.FAILED
            return MSFResult(
                status=status,
                module=module_path,
                target=target,
                raw_output=raw_output,
                errors=[error]
            )

        # Clean and parse output
        cleaned = self._clean_output(raw_output)
        parsed = self._parse_output(cleaned, module_path)

        execution_time = time.time() - start_time

        # Determine status
        if parsed['error_count'] > 0 and not parsed['findings']:
            status = MSFStatus.FAILED
        elif parsed['error_count'] > 0:
            status = MSFStatus.PARTIAL
        elif parsed['findings'] or parsed['info']:
            status = MSFStatus.SUCCESS
        else:
            status = MSFStatus.SUCCESS  # No output isn't necessarily an error

        return MSFResult(
            status=status,
            module=module_path,
            target=target,
            raw_output=raw_output,
            cleaned_output=cleaned,
            findings=parsed['findings'],
            info=parsed['info'],
            errors=parsed['errors'],
            warnings=parsed['warnings'],
            open_ports=parsed['open_ports'],
            services=parsed['services'],
            execution_time=execution_time,
            error_count=parsed['error_count']
        )

    def run_scanner(
        self,
        module_path: str,
        target: str,
        ports: str = None,
        options: Dict[str, Any] = None,
        timeout: int = 120
    ) -> MSFResult:
        """Convenience method for running scanner modules.

        Args:
            module_path: Scanner module path.
            target: Target IP or range (RHOSTS).
            ports: Port specification (optional).
            options: Additional options.
            timeout: Maximum execution time.

        Returns:
            MSFResult with scan results.
        """
        opts = {'RHOSTS': target}
        if ports:
            opts['PORTS'] = ports
        if options:
            opts.update(options)

        return self.run_module(module_path, opts, timeout)

    def get_module_info(self, module_path: str) -> Optional[Dict[str, Any]]:
        """Get information about a module.

        Args:
            module_path: Full module path.

        Returns:
            Module info dictionary or None.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return None

        try:
            # Determine module type from path
            parts = module_path.split('/')
            if len(parts) < 2:
                return None

            module_type = parts[0]
            module_name = '/'.join(parts[1:])

            info = self.manager.rpc.get_module_info(module_type, module_name)
            return {
                'name': info.name,
                'description': info.description,
                'author': info.author,
                'type': info.type,
                'rank': info.rank,
                'references': info.references
            }
        except Exception as e:
            self._last_error = str(e)
            return None

    def get_module_options(self, module_path: str) -> Optional[Dict[str, Any]]:
        """Get available options for a module.

        Args:
            module_path: Full module path.

        Returns:
            Options dictionary or None.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return None

        try:
            parts = module_path.split('/')
            if len(parts) < 2:
                return None

            module_type = parts[0]
            module_name = '/'.join(parts[1:])

            return self.manager.rpc.get_module_options(module_type, module_name)
        except Exception as e:
            self._last_error = str(e)
            return None

    def search_modules(self, query: str) -> List[str]:
        """Search for modules matching a query.

        Args:
            query: Search query.

        Returns:
            List of matching module paths.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return []

        try:
            results = self.manager.rpc.search_modules(query)
            # Results are typically dicts with 'fullname' key
            if isinstance(results, list):
                return [r.get('fullname', r) if isinstance(r, dict) else str(r) for r in results]
            return []
        except Exception as e:
            self._last_error = str(e)
            return []

    def list_modules(self, module_type: str = None) -> List[str]:
        """List available modules by type.

        Args:
            module_type: Filter by type (exploit, auxiliary, post, payload, encoder, nop).
                        If None, returns all modules.

        Returns:
            List of module paths.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return []

        try:
            return self.manager.rpc.list_modules(module_type)
        except Exception as e:
            self._last_error = str(e)
            return []

    def list_sessions(self) -> Dict[str, Any]:
        """List active MSF sessions.

        Returns:
            Dictionary of session IDs to session info.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return {}

        try:
            return self.manager.rpc.list_sessions()
        except Exception as e:
            self._last_error = str(e)
            return {}

    def list_jobs(self) -> Dict[str, Any]:
        """List running MSF jobs.

        Returns:
            Dictionary of job IDs to job info.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return {}

        try:
            return self.manager.rpc.list_jobs()
        except Exception as e:
            self._last_error = str(e)
            return {}

    def stop_job(self, job_id: str) -> bool:
        """Stop a running job.

        Args:
            job_id: Job ID to stop.

        Returns:
            True if stopped successfully.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return False

        try:
            return self.manager.rpc.stop_job(job_id)
        except Exception as e:
            self._last_error = str(e)
            return False

    def execute_module_job(
        self,
        module_path: str,
        options: Dict[str, Any] = None
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Execute a module as a background job (non-blocking).

        This is different from run_module() which uses console and captures output.
        Use this for exploits and long-running modules that should run in background.

        Args:
            module_path: Full module path.
            options: Module options.

        Returns:
            Tuple of (success, job_id, error_message).
        """
        connected, msg = self.ensure_connected()
        if not connected:
            return False, None, msg

        try:
            parts = module_path.split('/')
            if len(parts) < 2:
                return False, None, "Invalid module path"

            module_type = parts[0]
            module_name = '/'.join(parts[1:])

            result = self.manager.rpc.execute_module(module_type, module_name, options or {})

            job_id = result.get('job_id')
            if job_id is not None:
                return True, str(job_id), None
            else:
                # Check for error in result
                error = result.get('error_message') or result.get('error') or "Unknown error"
                return False, None, str(error)

        except Exception as e:
            self._last_error = str(e)
            return False, None, str(e)

    def session_read(self, session_id: str) -> Tuple[bool, str]:
        """Read from a session shell.

        Args:
            session_id: Session ID.

        Returns:
            Tuple of (success, output).
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return False, ""

        try:
            output = self.manager.rpc.session_shell_read(session_id)
            return True, output
        except Exception as e:
            self._last_error = str(e)
            return False, ""

    def session_write(self, session_id: str, command: str) -> bool:
        """Write a command to a session shell.

        Args:
            session_id: Session ID.
            command: Command to execute.

        Returns:
            True if written successfully.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return False

        try:
            return self.manager.rpc.session_shell_write(session_id, command)
        except Exception as e:
            self._last_error = str(e)
            return False

    def session_stop(self, session_id: str) -> bool:
        """Stop/kill a session.

        Args:
            session_id: Session ID.

        Returns:
            True if stopped successfully.
        """
        connected, _ = self.ensure_connected(auto_prompt=False)
        if not connected:
            return False

        try:
            return self.manager.rpc.session_stop(session_id)
        except Exception as e:
            self._last_error = str(e)
            return False

    def run_console_command(self, command: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run a raw console command and return output.

        This is a lower-level method for direct console access.

        Args:
            command: Console command to run.
            timeout: Timeout in seconds.

        Returns:
            Tuple of (success, output).
        """
        connected, msg = self.ensure_connected()
        if not connected:
            return False, msg

        try:
            output = self.manager.rpc.run_console_command(command, timeout=timeout)
            return True, output
        except Exception as e:
            self._last_error = str(e)
            return False, str(e)

    def print_result(self, result: MSFResult, verbose: bool = False):
        """Print a formatted result to the console.

        Args:
            result: MSFResult to print.
            verbose: If True, show all output including info lines.
        """
        print(f"\n{Colors.CYAN}Module Output:{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

        if result.status == MSFStatus.NOT_CONNECTED:
            print(f"  {Colors.RED}[X] Not connected to Metasploit{Colors.RESET}")
            if result.errors:
                print(f"      {result.errors[0]}")
        elif result.status == MSFStatus.AUTH_ERROR:
            print(f"  {Colors.RED}[X] Authentication failed{Colors.RESET}")
        elif result.status == MSFStatus.TIMEOUT:
            print(f"  {Colors.YELLOW}[!] Execution timed out{Colors.RESET}")
        else:
            # Print findings (green)
            for line in result.findings:
                print(f"  {Colors.GREEN}{line}{Colors.RESET}")

            # Print info (cyan) - only in verbose mode
            if verbose:
                for line in result.info:
                    print(f"  {Colors.CYAN}{line}{Colors.RESET}")

            # Print warnings (yellow)
            for line in result.warnings:
                print(f"  {Colors.YELLOW}{line}{Colors.RESET}")

            # Print errors (dim)
            for line in result.errors:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")

            # Summarize error count if high
            if result.error_count > 0:
                print(f"\n  {Colors.YELLOW}[!] {result.error_count} errors occurred during execution{Colors.RESET}")

        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

        # Print summary
        if result.execution_time > 0:
            print(f"  {Colors.DIM}Time: {result.execution_time:.1f}s{Colors.RESET}")
        print(f"  {Colors.DIM}Status: {result.get_summary()}{Colors.RESET}")

        # Print parsed port/service info if available
        if result.open_ports:
            print(f"\n  {Colors.GREEN}Open Ports:{Colors.RESET}")
            for port_info in result.open_ports:
                print(f"    {port_info['port']}/tcp - {port_info.get('state', 'open')}")

        if result.services:
            print(f"\n  {Colors.GREEN}Services Detected:{Colors.RESET}")
            for svc in result.services:
                print(f"    {svc['ip']}:{svc['port']} - {svc['info']}")


# Global instance
_msf_interface: Optional[MSFInterface] = None


def get_msf_interface() -> MSFInterface:
    """Get the global MSF interface instance."""
    global _msf_interface
    if _msf_interface is None:
        _msf_interface = MSFInterface()
    return _msf_interface
