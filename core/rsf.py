"""
AUTARCH RouterSploit Framework Wrapper
Low-level interface for RouterSploit module discovery, import, and execution.
Direct Python import -- no RPC layer needed since RSF is pure Python.
"""

import sys
import os
import re
import threading
import importlib
from io import StringIO
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any
from contextlib import contextmanager

from .config import get_config


class RSFError(Exception):
    """Custom exception for RouterSploit operations."""
    pass


@dataclass
class RSFModuleInfo:
    """Metadata for a RouterSploit module."""
    name: str = ""
    path: str = ""
    description: str = ""
    authors: Tuple[str, ...] = ()
    devices: Tuple[str, ...] = ()
    references: Tuple[str, ...] = ()
    options: List[Dict[str, Any]] = field(default_factory=list)
    module_type: str = ""  # exploits, creds, scanners, payloads, encoders, generic


class RSFManager:
    """Manager for RouterSploit framework operations.

    Handles sys.path setup, module discovery, dynamic import,
    option introspection, stdout capture, and execution.
    """

    def __init__(self):
        self._available = None
        self._module_index = None
        self._path_added = False

    def _ensure_path(self):
        """Add RSF install path to sys.path if not already present."""
        if self._path_added:
            return

        config = get_config()
        install_path = config.get('rsf', 'install_path', '')

        if install_path and install_path not in sys.path:
            sys.path.insert(0, install_path)
            self._path_added = True

    @property
    def is_available(self) -> bool:
        """Check if RouterSploit is importable. Caches result."""
        if self._available is not None:
            return self._available

        try:
            self._ensure_path()
            import routersploit
            self._available = True
        except ImportError:
            self._available = False

        return self._available

    def reset_cache(self):
        """Reset cached state (availability, module index)."""
        self._available = None
        self._module_index = None
        self._path_added = False

    def index_all_modules(self) -> List[str]:
        """Discover all RSF modules. Returns list of dotted module paths.

        Uses routersploit.core.exploit.utils.index_modules() internally.
        Results are cached after first call.

        Returns:
            List of module paths like 'exploits/routers/dlink/some_module'
        """
        if self._module_index is not None:
            return self._module_index

        if not self.is_available:
            raise RSFError("RouterSploit is not available")

        try:
            self._ensure_path()
            from routersploit.core.exploit import utils

            modules_dir = os.path.join(
                os.path.dirname(utils.__file__),
                '..', '..', 'modules'
            )
            modules_dir = os.path.normpath(modules_dir)

            if not os.path.isdir(modules_dir):
                # Try from config path
                config = get_config()
                install_path = config.get('rsf', 'install_path', '')
                modules_dir = os.path.join(install_path, 'routersploit', 'modules')

            raw_index = utils.index_modules(modules_dir)

            # Convert dotted paths to slash paths for display
            self._module_index = []
            for mod_path in raw_index:
                # Remove 'routersploit.modules.' prefix if present
                clean = mod_path
                for prefix in ('routersploit.modules.', 'modules.'):
                    if clean.startswith(prefix):
                        clean = clean[len(prefix):]
                # Convert dots to slashes
                clean = clean.replace('.', '/')
                self._module_index.append(clean)

            return self._module_index

        except Exception as e:
            raise RSFError(f"Failed to index modules: {e}")

    def get_module_count(self) -> int:
        """Get total number of indexed modules."""
        try:
            return len(self.index_all_modules())
        except RSFError:
            return 0

    def get_modules_by_type(self, module_type: str) -> List[str]:
        """Filter modules by type (exploits, creds, scanners, payloads, encoders, generic).

        Args:
            module_type: One of 'exploits', 'creds', 'scanners', 'payloads', 'encoders', 'generic'

        Returns:
            List of matching module paths
        """
        all_modules = self.index_all_modules()
        return [m for m in all_modules if m.startswith(module_type + '/')]

    def search_modules(self, query: str) -> List[str]:
        """Search modules by substring match on path.

        Args:
            query: Search string (case-insensitive)

        Returns:
            List of matching module paths
        """
        all_modules = self.index_all_modules()
        query_lower = query.lower()
        return [m for m in all_modules if query_lower in m.lower()]

    def _dotted_path(self, slash_path: str) -> str:
        """Convert slash path to dotted import path.

        Args:
            slash_path: e.g. 'exploits/routers/dlink/some_module'

        Returns:
            Dotted path like 'routersploit.modules.exploits.routers.dlink.some_module'
        """
        clean = slash_path.strip('/')
        dotted = clean.replace('/', '.')
        return f"routersploit.modules.{dotted}"

    def load_module(self, path: str) -> Tuple[Any, RSFModuleInfo]:
        """Load a RouterSploit module by path.

        Converts slash path to dotted import path, imports using
        import_exploit(), instantiates, and extracts metadata.

        Args:
            path: Module path like 'exploits/routers/dlink/some_module'

        Returns:
            Tuple of (module_instance, RSFModuleInfo)

        Raises:
            RSFError: If module cannot be loaded
        """
        if not self.is_available:
            raise RSFError("RouterSploit is not available")

        try:
            self._ensure_path()
            from routersploit.core.exploit.utils import import_exploit

            dotted = self._dotted_path(path)
            module_class = import_exploit(dotted)
            instance = module_class()

            # Extract __info__ dict
            info_dict = {}
            # RSF metaclass renames __info__ to _ClassName__info__
            for attr in dir(instance):
                if attr.endswith('__info__') or attr == '__info__':
                    try:
                        info_dict = getattr(instance, attr)
                        if isinstance(info_dict, dict):
                            break
                    except AttributeError:
                        continue

            # If not found via mangled name, try class hierarchy
            if not info_dict:
                for klass in type(instance).__mro__:
                    mangled = f"_{klass.__name__}__info__"
                    if hasattr(klass, mangled):
                        info_dict = getattr(klass, mangled)
                        if isinstance(info_dict, dict):
                            break

            # Extract options
            options = self.get_module_options(instance)

            # Determine module type from path
            parts = path.split('/')
            module_type = parts[0] if parts else ""

            module_info = RSFModuleInfo(
                name=info_dict.get('name', path.split('/')[-1]),
                path=path,
                description=info_dict.get('description', ''),
                authors=info_dict.get('authors', ()),
                devices=info_dict.get('devices', ()),
                references=info_dict.get('references', ()),
                options=options,
                module_type=module_type,
            )

            return instance, module_info

        except Exception as e:
            raise RSFError(f"Failed to load module '{path}': {e}")

    def get_module_options(self, instance) -> List[Dict[str, Any]]:
        """Introspect Option descriptors on a module instance.

        Uses RSF's exploit_attributes metaclass aggregator to get
        option names, then reads descriptor properties for details.

        Args:
            instance: Instantiated RSF module

        Returns:
            List of dicts with keys: name, type, default, description, current, advanced
        """
        options = []

        # Try exploit_attributes first (set by metaclass)
        exploit_attrs = getattr(type(instance), 'exploit_attributes', {})

        if exploit_attrs:
            for name, attr_info in exploit_attrs.items():
                # attr_info is [display_value, description, advanced]
                display_value = attr_info[0] if len(attr_info) > 0 else ""
                description = attr_info[1] if len(attr_info) > 1 else ""
                advanced = attr_info[2] if len(attr_info) > 2 else False

                # Get current value from instance
                try:
                    current = getattr(instance, name, display_value)
                except Exception:
                    current = display_value

                # Determine option type from the descriptor class
                opt_type = "string"
                for klass in type(instance).__mro__:
                    if name in klass.__dict__:
                        descriptor = klass.__dict__[name]
                        opt_type = type(descriptor).__name__.lower()
                        # Clean up: optip -> ip, optport -> port, etc.
                        opt_type = opt_type.replace('opt', '')
                        break

                options.append({
                    'name': name,
                    'type': opt_type,
                    'default': display_value,
                    'description': description,
                    'current': str(current) if current is not None else "",
                    'advanced': advanced,
                })
        else:
            # Fallback: inspect instance options property
            opt_names = getattr(instance, 'options', [])
            for name in opt_names:
                try:
                    current = getattr(instance, name, "")
                    options.append({
                        'name': name,
                        'type': 'string',
                        'default': str(current),
                        'description': '',
                        'current': str(current) if current is not None else "",
                        'advanced': False,
                    })
                except Exception:
                    continue

        return options

    def set_module_option(self, instance, name: str, value: str) -> bool:
        """Set an option on a module instance.

        Args:
            instance: RSF module instance
            name: Option name
            value: Value to set (string, will be validated by descriptor)

        Returns:
            True if set successfully

        Raises:
            RSFError: If option cannot be set
        """
        try:
            setattr(instance, name, value)
            return True
        except Exception as e:
            raise RSFError(f"Failed to set option '{name}': {e}")

    @contextmanager
    def capture_output(self):
        """Context manager to capture stdout/stderr from RSF modules.

        RSF modules print directly via their printer system. This
        redirects stdout/stderr to StringIO for capturing output.

        Yields:
            StringIO object containing captured output
        """
        captured = StringIO()
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        try:
            sys.stdout = captured
            sys.stderr = captured
            yield captured
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def execute_check(self, instance, timeout: int = 60) -> Tuple[Optional[bool], str]:
        """Run check() on a module with stdout capture and timeout.

        check() is the safe vulnerability verification method.

        Args:
            instance: RSF module instance (already configured)
            timeout: Timeout in seconds

        Returns:
            Tuple of (result, output) where result is True/False/None
        """
        result = [None]
        output = [""]
        error = [None]

        def _run():
            try:
                with self.capture_output() as captured:
                    check_result = instance.check()
                    result[0] = check_result
                    output[0] = captured.getvalue()
            except Exception as e:
                error[0] = e
                try:
                    output[0] = captured.getvalue()
                except Exception:
                    pass

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            return None, output[0] + "\n[!] Module execution timed out"

        if error[0]:
            return None, output[0] + f"\n[-] Error: {error[0]}"

        return result[0], output[0]

    def execute_run(self, instance, timeout: int = 120) -> Tuple[bool, str]:
        """Run run() on a module with stdout capture and timeout.

        run() is the full exploit execution method.

        Args:
            instance: RSF module instance (already configured)
            timeout: Timeout in seconds

        Returns:
            Tuple of (completed, output) where completed indicates
            whether execution finished within timeout
        """
        completed = [False]
        output = [""]
        error = [None]

        def _run():
            try:
                with self.capture_output() as captured:
                    instance.run()
                    completed[0] = True
                    output[0] = captured.getvalue()
            except Exception as e:
                error[0] = e
                try:
                    output[0] = captured.getvalue()
                except Exception:
                    pass

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            return False, output[0] + "\n[!] Module execution timed out"

        if error[0]:
            return False, output[0] + f"\n[-] Error: {error[0]}"

        return completed[0], output[0]


# Singleton instance
_rsf_manager = None


def get_rsf_manager() -> RSFManager:
    """Get the global RSFManager singleton instance."""
    global _rsf_manager
    if _rsf_manager is None:
        _rsf_manager = RSFManager()
    return _rsf_manager
