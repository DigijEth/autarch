"""
AUTARCH RouterSploit High-Level Interface
Clean API for RSF operations, mirroring core/msf_interface.py patterns.
Wraps RSFManager with result parsing and formatted output.
"""

import re
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from .rsf import get_rsf_manager, RSFError, RSFModuleInfo
from .banner import Colors


class RSFStatus(Enum):
    """Status codes for RSF operations."""
    SUCCESS = "success"
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_AVAILABLE = "not_available"


@dataclass
class RSFResult:
    """Result of an RSF module execution."""
    status: RSFStatus
    module_path: str
    target: str = ""

    # Raw and cleaned output
    raw_output: str = ""
    cleaned_output: str = ""

    # Parsed results
    successes: List[str] = field(default_factory=list)  # [+] lines
    info: List[str] = field(default_factory=list)        # [*] lines
    errors: List[str] = field(default_factory=list)      # [-] lines

    # Credential results
    credentials: List[Dict[str, str]] = field(default_factory=list)

    # Check result (True/False/None)
    check_result: Optional[bool] = None

    # Execution metadata
    execution_time: float = 0.0


# ANSI escape code pattern
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\([a-zA-Z]')


class RSFInterface:
    """High-level interface for RouterSploit operations.

    Provides a clean API mirroring MSFInterface patterns:
    - Module listing and search
    - Module info and options
    - Check (safe vulnerability verification)
    - Run (full module execution)
    - Output parsing and result formatting
    """

    def __init__(self):
        self._manager = get_rsf_manager()

    def ensure_available(self) -> bool:
        """Check that RSF is importable and available.

        Returns:
            True if RSF is available

        Raises:
            RSFError: If RSF is not available
        """
        if not self._manager.is_available:
            raise RSFError(
                "RouterSploit is not available. "
                "Check install path in Settings > RouterSploit Settings."
            )
        return True

    @property
    def is_available(self) -> bool:
        """Check if RSF is available without raising."""
        return self._manager.is_available

    @property
    def module_count(self) -> int:
        """Get total number of available modules."""
        return self._manager.get_module_count()

    def list_modules(self, module_type: str = None) -> List[str]:
        """List available modules, optionally filtered by type.

        Combines live RSF index with curated library data.

        Args:
            module_type: Filter by type (exploits, creds, scanners, etc.)

        Returns:
            List of module paths
        """
        self.ensure_available()

        if module_type:
            return self._manager.get_modules_by_type(module_type)
        return self._manager.index_all_modules()

    def search_modules(self, query: str) -> List[str]:
        """Search modules by keyword.

        Searches both live RSF index and curated library.

        Args:
            query: Search string

        Returns:
            List of matching module paths
        """
        self.ensure_available()

        results = self._manager.search_modules(query)

        # Also search curated library for richer matches
        try:
            from .rsf_modules import search_modules as search_curated
            curated = search_curated(query)
            curated_paths = [m['path'] for m in curated if 'path' in m]
            # Merge without duplicates, curated first
            seen = set(results)
            for path in curated_paths:
                if path not in seen:
                    results.append(path)
                    seen.add(path)
        except ImportError:
            pass

        return results

    def get_module_info(self, path: str) -> RSFModuleInfo:
        """Get metadata for a module.

        Tries curated library first, falls back to live introspection.

        Args:
            path: Module path

        Returns:
            RSFModuleInfo with module metadata
        """
        # Try curated library first
        try:
            from .rsf_modules import get_module_info as get_curated_info
            curated = get_curated_info(path)
            if curated:
                parts = path.split('/')
                return RSFModuleInfo(
                    name=curated.get('name', path.split('/')[-1]),
                    path=path,
                    description=curated.get('description', ''),
                    authors=tuple(curated.get('authors', ())),
                    devices=tuple(curated.get('devices', ())),
                    references=tuple(curated.get('references', ())),
                    module_type=parts[0] if parts else "",
                )
        except ImportError:
            pass

        # Fall back to live introspection
        self.ensure_available()
        _, info = self._manager.load_module(path)
        return info

    def get_module_options(self, path: str) -> List[Dict[str, Any]]:
        """Get configurable options for a module.

        Args:
            path: Module path

        Returns:
            List of option dicts with name, type, default, description, current
        """
        self.ensure_available()
        instance, _ = self._manager.load_module(path)
        return self._manager.get_module_options(instance)

    def check_module(self, path: str, options: Dict[str, str] = None,
                     timeout: int = None) -> RSFResult:
        """Run check() on a module -- safe vulnerability verification.

        Args:
            path: Module path
            options: Dict of option_name -> value to set before running
            timeout: Execution timeout in seconds (default from config)

        Returns:
            RSFResult with check results
        """
        return self._execute_module(path, options, timeout, check_only=True)

    def run_module(self, path: str, options: Dict[str, str] = None,
                   timeout: int = None) -> RSFResult:
        """Run run() on a module -- full exploit execution.

        Args:
            path: Module path
            options: Dict of option_name -> value to set before running
            timeout: Execution timeout in seconds (default from config)

        Returns:
            RSFResult with execution results
        """
        return self._execute_module(path, options, timeout, check_only=False)

    def _execute_module(self, path: str, options: Dict[str, str] = None,
                        timeout: int = None, check_only: bool = False) -> RSFResult:
        """Internal method to execute a module (check or run).

        Args:
            path: Module path
            options: Option overrides
            timeout: Timeout in seconds
            check_only: If True, run check() instead of run()

        Returns:
            RSFResult
        """
        if not self._manager.is_available:
            return RSFResult(
                status=RSFStatus.NOT_AVAILABLE,
                module_path=path,
            )

        if timeout is None:
            from .config import get_config
            timeout = get_config().get_int('rsf', 'execution_timeout', 120)

        start_time = time.time()

        try:
            # Load and configure module
            instance, info = self._manager.load_module(path)

            target = ""
            if options:
                for name, value in options.items():
                    self._manager.set_module_option(instance, name, value)
                    if name == 'target':
                        target = value

            # Get target from instance if not in options
            if not target:
                target = str(getattr(instance, 'target', ''))

            # Execute
            if check_only:
                check_result, raw_output = self._manager.execute_check(instance, timeout)
            else:
                completed, raw_output = self._manager.execute_run(instance, timeout)
                check_result = None

            execution_time = time.time() - start_time
            cleaned = self._clean_output(raw_output)
            successes, info_lines, errors, credentials = self._parse_output(cleaned)

            # Determine status
            if check_only:
                if check_result is True:
                    status = RSFStatus.VULNERABLE
                elif check_result is False:
                    status = RSFStatus.NOT_VULNERABLE
                elif "[!]" in raw_output and "timed out" in raw_output.lower():
                    status = RSFStatus.TIMEOUT
                else:
                    status = RSFStatus.FAILED
            else:
                if "[!]" in raw_output and "timed out" in raw_output.lower():
                    status = RSFStatus.TIMEOUT
                elif errors and not successes:
                    status = RSFStatus.FAILED
                elif successes or credentials:
                    status = RSFStatus.SUCCESS
                elif completed:
                    status = RSFStatus.SUCCESS
                else:
                    status = RSFStatus.FAILED

            return RSFResult(
                status=status,
                module_path=path,
                target=target,
                raw_output=raw_output,
                cleaned_output=cleaned,
                successes=successes,
                info=info_lines,
                errors=errors,
                credentials=credentials,
                check_result=check_result,
                execution_time=execution_time,
            )

        except RSFError as e:
            return RSFResult(
                status=RSFStatus.FAILED,
                module_path=path,
                target=options.get('target', '') if options else '',
                raw_output=str(e),
                cleaned_output=str(e),
                errors=[str(e)],
                execution_time=time.time() - start_time,
            )

    def _clean_output(self, raw: str) -> str:
        """Strip ANSI escape codes from output.

        Args:
            raw: Raw output potentially containing ANSI codes

        Returns:
            Cleaned text
        """
        if not raw:
            return ""
        return _ANSI_RE.sub('', raw)

    def _parse_output(self, cleaned: str):
        """Parse cleaned output into categorized lines.

        Categorizes lines by RSF prefix:
        - [+] = success/finding
        - [*] = informational
        - [-] = error/failure

        Also extracts credentials from common patterns.

        Args:
            cleaned: ANSI-stripped output

        Returns:
            Tuple of (successes, info, errors, credentials)
        """
        successes = []
        info_lines = []
        errors = []
        credentials = []

        for line in cleaned.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            if stripped.startswith('[+]'):
                successes.append(stripped[3:].strip())
                # Check for credential patterns
                creds = self._extract_credentials(stripped)
                if creds:
                    credentials.append(creds)
            elif stripped.startswith('[*]'):
                info_lines.append(stripped[3:].strip())
            elif stripped.startswith('[-]'):
                errors.append(stripped[3:].strip())
            elif stripped.startswith('[!]'):
                errors.append(stripped[3:].strip())

        return successes, info_lines, errors, credentials

    def _extract_credentials(self, line: str) -> Optional[Dict[str, str]]:
        """Extract credentials from a success line.

        Common RSF credential output patterns:
        - [+] admin:password
        - [+] Found valid credentials: admin / password
        - [+] username:password on target:port

        Args:
            line: A [+] success line

        Returns:
            Dict with username/password keys, or None
        """
        # Pattern: username:password
        cred_match = re.search(
            r'(?:credentials?|found|valid).*?(\S+)\s*[:/]\s*(\S+)',
            line, re.IGNORECASE
        )
        if cred_match:
            return {
                'username': cred_match.group(1),
                'password': cred_match.group(2),
            }

        # Simple colon-separated on [+] lines
        content = line.replace('[+]', '').strip()
        if ':' in content and len(content.split(':')) == 2:
            parts = content.split(':')
            # Only if parts look like creds (not URLs or paths)
            if not any(x in parts[0].lower() for x in ['http', '/', '\\']):
                return {
                    'username': parts[0].strip(),
                    'password': parts[1].strip(),
                }

        return None

    def print_result(self, result: RSFResult, verbose: bool = False):
        """Print formatted execution result.

        Args:
            result: RSFResult to display
            verbose: Show raw output if True
        """
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Execution Result{Colors.RESET}")
        print(f"  {Colors.DIM}{'─' * 50}{Colors.RESET}")

        # Status with color
        status_colors = {
            RSFStatus.SUCCESS: Colors.GREEN,
            RSFStatus.VULNERABLE: Colors.RED,
            RSFStatus.NOT_VULNERABLE: Colors.GREEN,
            RSFStatus.FAILED: Colors.RED,
            RSFStatus.TIMEOUT: Colors.YELLOW,
            RSFStatus.NOT_AVAILABLE: Colors.YELLOW,
        }
        color = status_colors.get(result.status, Colors.WHITE)
        print(f"  {Colors.CYAN}Status:{Colors.RESET}  {color}{result.status.value}{Colors.RESET}")
        print(f"  {Colors.CYAN}Module:{Colors.RESET}  {result.module_path}")
        if result.target:
            print(f"  {Colors.CYAN}Target:{Colors.RESET}  {result.target}")
        print(f"  {Colors.CYAN}Time:{Colors.RESET}    {result.execution_time:.1f}s")
        print()

        # Successes
        if result.successes:
            for line in result.successes:
                print(f"  {Colors.GREEN}[+]{Colors.RESET} {line}")

        # Info
        if result.info:
            for line in result.info:
                print(f"  {Colors.CYAN}[*]{Colors.RESET} {line}")

        # Errors
        if result.errors:
            for line in result.errors:
                print(f"  {Colors.RED}[-]{Colors.RESET} {line}")

        # Credentials
        if result.credentials:
            print()
            print(f"  {Colors.GREEN}{Colors.BOLD}Credentials Found:{Colors.RESET}")
            for cred in result.credentials:
                print(f"    {Colors.GREEN}{cred.get('username', '?')}{Colors.RESET}:"
                      f"{Colors.YELLOW}{cred.get('password', '?')}{Colors.RESET}")

        # Verbose: raw output
        if verbose and result.cleaned_output:
            print()
            print(f"  {Colors.DIM}Raw Output:{Colors.RESET}")
            for line in result.cleaned_output.splitlines():
                print(f"    {Colors.DIM}{line}{Colors.RESET}")

        print()


# Singleton instance
_rsf_interface = None


def get_rsf_interface() -> RSFInterface:
    """Get the global RSFInterface singleton instance."""
    global _rsf_interface
    if _rsf_interface is None:
        _rsf_interface = RSFInterface()
    return _rsf_interface
