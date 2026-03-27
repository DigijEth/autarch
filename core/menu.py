"""
AUTARCH Main Menu System
Handles the main interface, categories, and module loading
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Callable

from .banner import Colors, display_banner, clear_screen
from .config import get_config
from core.daemon import root_exec


# Module categories
CATEGORIES = {
    "defense": {
        "name": "Defense",
        "description": "Defensive security tools and monitoring",
        "color": Colors.BLUE
    },
    "offense": {
        "name": "Offense",
        "description": "Offensive security and penetration testing",
        "color": Colors.RED
    },
    "counter": {
        "name": "Counter",
        "description": "Counter-intelligence and threat response",
        "color": Colors.MAGENTA
    },
    "analyze": {
        "name": "Analyze",
        "description": "Analysis and forensics tools",
        "color": Colors.CYAN
    },
    "osint": {
        "name": "OSINT",
        "description": "Open source intelligence gathering",
        "color": Colors.GREEN
    },
    "simulate": {
        "name": "Simulate",
        "description": "Attack simulation and red team exercises",
        "color": Colors.YELLOW
    },
    "hardware": {
        "name": "Hardware",
        "description": "Physical device access and flashing",
        "color": Colors.YELLOW
    },
    "core": {
        "name": "Core",
        "description": "Core framework modules",
        "color": Colors.WHITE
    }
}


class ModuleInfo:
    """Information about a loaded module."""

    def __init__(self, name: str, path: Path, module):
        self.name = name
        self.path = path
        self.module = module
        self.description = getattr(module, 'DESCRIPTION', 'No description')
        self.author = getattr(module, 'AUTHOR', 'Unknown')
        self.version = getattr(module, 'VERSION', '1.0')
        self.category = getattr(module, 'CATEGORY', 'core').lower()


class MainMenu:
    """Main menu handler for AUTARCH."""

    def __init__(self):
        from core.paths import get_app_dir
        self._app_dir = get_app_dir()
        self.config = get_config()
        self.modules: Dict[str, ModuleInfo] = {}
        self.running = True

    def print_status(self, message: str, status: str = "info"):
        """Print a status message."""
        colors = {
            "info": Colors.CYAN,
            "success": Colors.GREEN,
            "warning": Colors.YELLOW,
            "error": Colors.RED
        }
        color = colors.get(status, Colors.WHITE)
        symbols = {
            "info": "*",
            "success": "+",
            "warning": "!",
            "error": "X"
        }
        symbol = symbols.get(status, "*")
        print(f"{color}[{symbol}] {message}{Colors.RESET}")

    def load_modules(self):
        """Load all available modules from the modules directory.

        In a frozen (PyInstaller) build, scans both the bundled modules inside
        _MEIPASS and the user modules directory next to the exe.  User modules
        override bundled modules with the same name.
        """
        from core.paths import get_modules_dir, get_user_modules_dir, is_frozen

        # Collect module files — bundled first, then user (user overrides)
        module_files: dict[str, Path] = {}

        bundled = get_modules_dir()
        if bundled.exists():
            for f in bundled.glob("*.py"):
                if not f.name.startswith("_") and f.stem != "setup":
                    module_files[f.stem] = f

        if is_frozen():
            user_dir = get_user_modules_dir()
            if user_dir.exists():
                for f in user_dir.glob("*.py"):
                    if not f.name.startswith("_") and f.stem != "setup":
                        module_files[f.stem] = f  # Override bundled

        for module_name, module_file in module_files.items():
            try:
                spec = importlib.util.spec_from_file_location(module_name, module_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, 'run'):
                    self.modules[module_name] = ModuleInfo(module_name, module_file, module)
                else:
                    self.print_status(f"Module '{module_name}' missing run() function", "warning")

            except Exception as e:
                self.print_status(f"Failed to load module '{module_name}': {e}", "error")

    def get_modules_by_category(self, category: str) -> Dict[str, ModuleInfo]:
        """Get all modules in a specific category."""
        return {
            name: info for name, info in self.modules.items()
            if info.category == category
        }

    def get_status_line(self) -> str:
        """Get the status line showing model and MSF status."""
        # Import version from main module
        try:
            from autarch import VERSION
        except ImportError:
            VERSION = "?"
        parts = [f"v{VERSION}"]

        # Model status - check based on backend
        backend = self.config.get('autarch', 'llm_backend', 'local')
        if backend == 'transformers':
            model_path = self.config.get('transformers', 'model_path', '')
            backend_label = "SafeTensors"
        elif backend == 'claude':
            model_path = self.config.get('claude', 'model', '')
            backend_label = "Claude"
        elif backend == 'huggingface':
            model_path = self.config.get('huggingface', 'model', '')
            backend_label = "HF Inference"
        else:
            model_path = self.config.get('llama', 'model_path', '')
            backend_label = "GGUF"

        if model_path:
            model_name = os.path.basename(model_path)
            parts.append(f"Model: {model_name} ({backend_label})")
        else:
            parts.append(f"{Colors.YELLOW}Model: Not configured{Colors.RESET}")

        # MSF status
        from .msf import get_msf_manager
        msf = get_msf_manager()
        if msf.is_connected:
            parts.append(f"{Colors.GREEN}MSF: Connected{Colors.RESET}")
        else:
            parts.append(f"{Colors.DIM}MSF: Disconnected{Colors.RESET}")

        # RSF status
        try:
            from .rsf import get_rsf_manager
            rsf = get_rsf_manager()
            if rsf.is_available:
                parts.append(f"{Colors.GREEN}RSF: Available{Colors.RESET}")
            else:
                parts.append(f"{Colors.DIM}RSF: Not Found{Colors.RESET}")
        except Exception:
            parts.append(f"{Colors.DIM}RSF: Not Found{Colors.RESET}")

        return f"{Colors.DIM} | {Colors.RESET}".join(parts)

    def _show_banner(self):
        """Display banner unless disabled in settings."""
        if not self.config.get_bool('autarch', 'no_banner', fallback=False):
            display_banner()

    def display_menu(self):
        """Display the main menu."""
        clear_screen()
        self._show_banner()

        # Status line
        print(f"{Colors.DIM}{self.get_status_line()}{Colors.RESET}")
        print()

        # Main menu options
        print(f"{Colors.BOLD}{Colors.WHITE}  Main Menu{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Category options
        print(f"  {Colors.BLUE}[1]{Colors.RESET}  Defense      {Colors.DIM}- Defensive security tools{Colors.RESET}")
        print(f"  {Colors.RED}[2]{Colors.RESET}  Offense      {Colors.DIM}- Penetration testing{Colors.RESET}")
        print(f"  {Colors.MAGENTA}[3]{Colors.RESET}  Counter      {Colors.DIM}- Counter-intelligence{Colors.RESET}")
        print(f"  {Colors.CYAN}[4]{Colors.RESET}  Analyze      {Colors.DIM}- Analysis & forensics{Colors.RESET}")
        print(f"  {Colors.GREEN}[5]{Colors.RESET}  OSINT        {Colors.DIM}- Open source intelligence{Colors.RESET}")
        print(f"  {Colors.YELLOW}[6]{Colors.RESET}  Simulate     {Colors.DIM}- Attack simulation{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[7]{Colors.RESET}  Agent Hal    {Colors.DIM}- AI-powered security automation{Colors.RESET}")
        print()
        print(f"  {Colors.GREEN}[8]{Colors.RESET}  Web Service  {Colors.DIM}- Start/stop web dashboard{Colors.RESET}")
        print(f"  {Colors.CYAN}[9]{Colors.RESET}  Sideload App {Colors.DIM}- Push Archon to Android device{Colors.RESET}")
        print(f"  {Colors.YELLOW}[10]{Colors.RESET} MCP Server   {Colors.DIM}- Model Context Protocol tools{Colors.RESET}")
        print(f"  {Colors.WHITE}[11]{Colors.RESET} User Manual  {Colors.DIM}- In-depth guide & documentation{Colors.RESET}")
        print(f"  {Colors.DIM}[12]{Colors.RESET} List Modules {Colors.DIM}- Show all loaded modules{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[99]{Colors.RESET} Settings")
        print(f"  {Colors.DIM}[98]{Colors.RESET} Exit")
        print()

    def display_category_menu(self, category: str):
        """Display the submenu for a category."""
        cat_info = CATEGORIES.get(category, CATEGORIES['core'])
        cat_modules = self.get_modules_by_category(category)

        clear_screen()
        self._show_banner()

        print(f"{cat_info['color']}{Colors.BOLD}  {cat_info['name']}{Colors.RESET}")
        print(f"{Colors.DIM}  {cat_info['description']}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        if not cat_modules:
            print(f"  {Colors.YELLOW}No modules in this category.{Colors.RESET}")
            print(f"  {Colors.DIM}Add modules with CATEGORY = '{category}'{Colors.RESET}")
        else:
            module_list = list(cat_modules.keys())
            for i, name in enumerate(module_list, 1):
                info = cat_modules[name]
                print(f"  {cat_info['color']}[{i}]{Colors.RESET} {name}")
                print(f"      {Colors.DIM}{info.description}{Colors.RESET}")

        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back to main menu")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

            if choice == "0" or not choice:
                return

            if cat_modules:
                module_list = list(cat_modules.keys())
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(module_list):
                        self.run_module(module_list[index])
                except ValueError:
                    if choice in cat_modules:
                        self.run_module(choice)

        except (EOFError, KeyboardInterrupt):
            print()

    def run_module(self, module_name: str):
        """Run a specific module."""
        if module_name not in self.modules:
            self.print_status(f"Module '{module_name}' not found", "error")
            return

        module_info = self.modules[module_name]

        clear_screen()
        self._show_banner()
        print(f"{Colors.GREEN}[+] Running module: {module_name}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        try:
            module_info.module.run()
        except Exception as e:
            self.print_status(f"Module error: {e}", "error")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_settings(self):
        """Display settings menu."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET}  LLM Settings")
            print(f"  {Colors.CYAN}[2]{Colors.RESET}  Metasploit Settings")
            print(f"  {Colors.CYAN}[3]{Colors.RESET}  Database Management")
            print(f"  {Colors.CYAN}[4]{Colors.RESET}  Custom APIs")
            print(f"  {Colors.CYAN}[5]{Colors.RESET}  AUTARCH API")
            print(f"  {Colors.CYAN}[6]{Colors.RESET}  OSINT Settings")
            print(f"  {Colors.CYAN}[7]{Colors.RESET}  RouterSploit Settings")
            print(f"  {Colors.CYAN}[8]{Colors.RESET}  UPnP Settings")
            print(f"  {Colors.CYAN}[9]{Colors.RESET}  Reverse Shell Settings")
            print(f"  {Colors.CYAN}[10]{Colors.RESET} Display Settings")
            print(f"  {Colors.CYAN}[11]{Colors.RESET} Load Config File")
            print()
            print(f"  {Colors.DIM}[12]{Colors.RESET} View All Settings")
            print(f"  {Colors.DIM}[13]{Colors.RESET} Run Setup Wizard")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self.show_llm_settings()
                elif choice == "2":
                    self.show_msf_settings()
                elif choice == "3":
                    self.show_database_management()
                elif choice == "4":
                    self.show_custom_apis()
                elif choice == "5":
                    self.show_autarch_api()
                elif choice == "6":
                    self.show_osint_settings()
                elif choice == "7":
                    self.show_rsf_settings()
                elif choice == "8":
                    self.show_upnp_settings()
                elif choice == "9":
                    self.show_revshell_settings()
                elif choice == "10":
                    self.show_display_settings()
                elif choice == "11":
                    self.load_config_file()
                elif choice == "12":
                    self.show_all_settings()
                elif choice == "13":
                    self.run_setup()

            except (EOFError, KeyboardInterrupt):
                break

    def show_llm_settings(self):
        """Display and configure LLM settings."""
        while True:
            clear_screen()
            self._show_banner()

            backend = self.config.get('autarch', 'llm_backend', 'local')

            print(f"{Colors.BOLD}{Colors.WHITE}  LLM Configuration{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Display backend-specific settings
            if backend == 'transformers':
                settings = self.config.get_transformers_settings()
                print(f"    {Colors.YELLOW}Backend: transformers (SafeTensors){Colors.RESET}")
                print()
                model_name = Path(settings['model_path']).name if settings['model_path'] else "(not set)"
                print(f"    {Colors.CYAN}Model:{Colors.RESET}             {model_name}")
                print(f"    {Colors.CYAN}Device:{Colors.RESET}            {settings['device']}")
                print(f"    {Colors.CYAN}Load in 8-bit:{Colors.RESET}     {settings['load_in_8bit']}")
                print(f"    {Colors.CYAN}Load in 4-bit:{Colors.RESET}     {settings['load_in_4bit']}")
                print(f"    {Colors.CYAN}Temperature:{Colors.RESET}       {settings['temperature']}")
                print(f"    {Colors.CYAN}Top P:{Colors.RESET}             {settings['top_p']}")
                print(f"    {Colors.CYAN}Top K:{Colors.RESET}             {settings['top_k']}")
                print(f"    {Colors.CYAN}Repetition Penalty:{Colors.RESET} {settings['repetition_penalty']}")
                print(f"    {Colors.CYAN}Max Tokens:{Colors.RESET}        {settings['max_tokens']}")
            elif backend == 'claude':
                settings = self.config.get_claude_settings()
                print(f"    {Colors.YELLOW}Backend: Claude API{Colors.RESET}")
                print()
                print(f"    {Colors.CYAN}Model:{Colors.RESET}          {settings['model']}")
                print(f"    {Colors.CYAN}API Key:{Colors.RESET}        {'***configured***' if settings['api_key'] else '(not set)'}")
                print(f"    {Colors.CYAN}Max Tokens:{Colors.RESET}     {settings['max_tokens']}")
                print(f"    {Colors.CYAN}Temperature:{Colors.RESET}    {settings['temperature']}")
            elif backend == 'huggingface':
                settings = self.config.get_huggingface_settings()
                print(f"    {Colors.YELLOW}Backend: HuggingFace Inference API{Colors.RESET}")
                print()
                print(f"    {Colors.CYAN}Model:{Colors.RESET}          {settings['model']}")
                print(f"    {Colors.CYAN}Endpoint:{Colors.RESET}       {settings['endpoint'] or '(HuggingFace Hub)'}")
                print(f"    {Colors.CYAN}API Key:{Colors.RESET}        {'***configured***' if settings['api_key'] else '(not set / free tier)'}")
                print(f"    {Colors.CYAN}Max Tokens:{Colors.RESET}     {settings['max_tokens']}")
                print(f"    {Colors.CYAN}Temperature:{Colors.RESET}    {settings['temperature']}")
                print(f"    {Colors.CYAN}Top P:{Colors.RESET}          {settings['top_p']}")
            else:  # llama.cpp / GGUF
                settings = self.config.get_llama_settings()
                print(f"    {Colors.YELLOW}Backend: llama.cpp (GGUF){Colors.RESET}")
                print()
                model_name = Path(settings['model_path']).name if settings['model_path'] else "(not set)"
                print(f"    {Colors.CYAN}Model:{Colors.RESET}          {model_name}")
                print(f"    {Colors.CYAN}Context Size:{Colors.RESET}   {settings['n_ctx']} tokens")
                print(f"    {Colors.CYAN}Threads:{Colors.RESET}        {settings['n_threads']}")
                print(f"    {Colors.CYAN}GPU Layers:{Colors.RESET}     {settings['n_gpu_layers']}")
                print(f"    {Colors.CYAN}Temperature:{Colors.RESET}    {settings['temperature']}")
                print(f"    {Colors.CYAN}Top P:{Colors.RESET}          {settings['top_p']}")
                print(f"    {Colors.CYAN}Top K:{Colors.RESET}          {settings['top_k']}")
                print(f"    {Colors.CYAN}Repeat Penalty:{Colors.RESET} {settings['repeat_penalty']}")
                print(f"    {Colors.CYAN}Max Tokens:{Colors.RESET}     {settings['max_tokens']}")
            print()

            # Check if model is loaded
            from .llm import get_llm
            llm = get_llm()
            if llm.is_loaded:
                print(f"    {Colors.GREEN}Status: Model loaded{Colors.RESET}")
            else:
                print(f"    {Colors.YELLOW}Status: Model not loaded{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Set Model Path")
            if backend != 'transformers':
                print(f"  {Colors.CYAN}[2]{Colors.RESET} Set Context Size")
                print(f"  {Colors.CYAN}[3]{Colors.RESET} Set Threads")
                print(f"  {Colors.CYAN}[4]{Colors.RESET} Set GPU Layers")
            else:
                print(f"  {Colors.CYAN}[2]{Colors.RESET} Set Device")
                print(f"  {Colors.CYAN}[3]{Colors.RESET} Set Quantization")
            print(f"  {Colors.CYAN}[5]{Colors.RESET} Set Temperature")
            print(f"  {Colors.CYAN}[6]{Colors.RESET} Set Top P / Top K")
            print(f"  {Colors.CYAN}[7]{Colors.RESET} Set Repeat Penalty")
            print(f"  {Colors.CYAN}[8]{Colors.RESET} Set Max Tokens")
            print()
            print(f"  {Colors.CYAN}[L]{Colors.RESET} Load/Reload Model")
            print(f"  {Colors.CYAN}[U]{Colors.RESET} Unload Model")
            print(f"  {Colors.CYAN}[S]{Colors.RESET} Switch Backend")
            print()
            print(f"  {Colors.GREEN}[T]{Colors.RESET} Load Hardware Template")
            print(f"  {Colors.GREEN}[C]{Colors.RESET} Load Custom Config")
            print(f"  {Colors.GREEN}[W]{Colors.RESET} Save Current as Custom Config")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self._set_llm_model_path()
                elif choice == "2":
                    if backend != 'transformers':
                        self._set_llm_context_size()
                    else:
                        self._set_transformers_device()
                elif choice == "3":
                    if backend != 'transformers':
                        self._set_llm_threads()
                    else:
                        self._set_transformers_quantization()
                elif choice == "4" and backend != 'transformers':
                    self._set_llm_gpu_layers()
                elif choice == "5":
                    self._set_llm_temperature()
                elif choice == "6":
                    self._set_llm_sampling()
                elif choice == "7":
                    self._set_llm_repeat_penalty()
                elif choice == "8":
                    self._set_llm_max_tokens()
                elif choice == "l":
                    self._load_llm_model()
                elif choice == "u":
                    self._unload_llm_model()
                elif choice == "s":
                    self._switch_llm_backend()
                elif choice == "t":
                    self._load_hardware_template()
                elif choice == "c":
                    self._load_custom_config()
                elif choice == "w":
                    self._save_custom_config()

            except (EOFError, KeyboardInterrupt):
                break

    def _set_llm_model_path(self):
        """Set LLM model path (GGUF file or SafeTensors directory)."""
        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')
        if backend == 'transformers':
            current = self.config.get('transformers', 'model_path', '')
        else:
            current = self.config.get('llama', 'model_path', '')

        if current:
            print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
        print(f"  {Colors.DIM}Enter path to GGUF file, SafeTensors directory, or HuggingFace model ID{Colors.RESET}")
        print(f"  {Colors.DIM}Examples: /path/to/model.gguf, models/MyModel, org/model-name{Colors.RESET}")
        print()

        try:
            path = input(f"  {Colors.WHITE}Model path: {Colors.RESET}").strip()
            if path:
                # Strip quotes from path
                path = path.strip('"').strip("'")
                path = os.path.expanduser(path)

                # Resolve the path - try multiple options
                resolved_path = self._resolve_model_path(path)

                if resolved_path:
                    # Detect model type
                    from .llm import detect_model_type
                    model_type = detect_model_type(resolved_path)

                    if model_type == 'gguf':
                        self.config.set('llama', 'model_path', resolved_path)
                        self.config.set('autarch', 'llm_backend', 'local')
                        self.config.save()
                        self.print_status(f"GGUF model set: {Path(resolved_path).name}", "success")
                        # Reset LLM instance to use new backend
                        from .llm import reset_llm
                        reset_llm()
                    elif model_type == 'transformers':
                        self.config.set('transformers', 'model_path', resolved_path)
                        self.config.set('autarch', 'llm_backend', 'transformers')
                        self.config.save()
                        self.print_status(f"SafeTensors model set: {Path(resolved_path).name}", "success")
                        # Reset LLM instance to use new backend
                        from .llm import reset_llm
                        reset_llm()
                    else:
                        self.print_status("Unrecognized model format. Expected .gguf file or model directory with .safetensors", "error")
                elif self._is_huggingface_id(path):
                    # HuggingFace model ID (e.g., 'org/model-name')
                    self.config.set('transformers', 'model_path', path)
                    self.config.set('autarch', 'llm_backend', 'transformers')
                    self.config.save()
                    self.print_status(f"HuggingFace model ID set: {path}", "success")
                    print(f"  {Colors.DIM}Model will be loaded from HuggingFace cache{Colors.RESET}")
                    # Reset LLM instance to use new backend
                    from .llm import reset_llm
                    reset_llm()
                else:
                    self.print_status("Path not found. Check the path and try again.", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _is_huggingface_id(self, path: str) -> bool:
        """Check if the path looks like a HuggingFace model ID.

        Args:
            path: The path/ID to check

        Returns:
            True if it looks like a HuggingFace model ID (org/model-name)
        """
        if not path:
            return False
        if path.startswith('/') or path.startswith('\\'):
            return False
        parts = path.split('/')
        if len(parts) == 2 and all(p and not p.startswith('.') for p in parts):
            return True
        return False

    def _resolve_model_path(self, path: str) -> str:
        """Resolve a model path, trying multiple variations.

        Args:
            path: User-provided path (may be relative or have variations)

        Returns:
            Resolved absolute path if found, None otherwise
        """
        framework_dir = self._app_dir

        # List of paths to try
        paths_to_try = [
            Path(path),  # As-is
            Path(path).expanduser(),  # Expand ~
            framework_dir / path.lstrip('/'),  # Relative to framework dir
            framework_dir / path,  # Relative without stripping /
        ]

        # Handle /dh_framework/... pattern (missing /home/user prefix)
        if path.startswith('/dh_framework'):
            paths_to_try.append(framework_dir / path[len('/dh_framework/'):])
        if path.startswith('dh_framework'):
            paths_to_try.append(framework_dir / path[len('dh_framework/'):])

        # Also try models/ subdirectory
        model_name = Path(path).name
        paths_to_try.append(framework_dir / 'models' / model_name)

        for p in paths_to_try:
            try:
                if p.exists():
                    return str(p.resolve())
            except (PermissionError, OSError):
                continue

        return None

    def _set_llm_context_size(self):
        """Set LLM context size."""
        print()
        current = self.config.get_int('llama', 'n_ctx', 4096)
        print(f"  {Colors.DIM}Current: {current} tokens{Colors.RESET}")
        print(f"  {Colors.DIM}Common values: 2048, 4096, 8192, 16384, 32768{Colors.RESET}")
        print()

        try:
            n_ctx = input(f"  {Colors.WHITE}Context size [{current}]: {Colors.RESET}").strip()
            if n_ctx:
                n_ctx = int(n_ctx)
                if 512 <= n_ctx <= 131072:
                    self.config.set('llama', 'n_ctx', str(n_ctx))
                    self.config.save()
                    self.print_status(f"Context size set to {n_ctx}", "success")
                else:
                    self.print_status("Value must be between 512 and 131072", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_llm_threads(self):
        """Set LLM CPU threads."""
        print()
        current = self.config.get_int('llama', 'n_threads', 4)
        cpu_count = os.cpu_count() or 4
        print(f"  {Colors.DIM}Current: {current} threads{Colors.RESET}")
        print(f"  {Colors.DIM}Your system has {cpu_count} CPU cores{Colors.RESET}")
        print()

        try:
            threads = input(f"  {Colors.WHITE}Threads [{current}]: {Colors.RESET}").strip()
            if threads:
                threads = int(threads)
                if 1 <= threads <= 256:
                    self.config.set('llama', 'n_threads', str(threads))
                    self.config.save()
                    self.print_status(f"Threads set to {threads}", "success")
                else:
                    self.print_status("Value must be between 1 and 256", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_llm_gpu_layers(self):
        """Set LLM GPU layers."""
        print()
        current = self.config.get_int('llama', 'n_gpu_layers', 0)
        print(f"  {Colors.DIM}Current: {current} layers{Colors.RESET}")
        print(f"  {Colors.DIM}Set to 0 for CPU only, higher for GPU acceleration{Colors.RESET}")
        print(f"  {Colors.DIM}Use -1 to offload all layers to GPU{Colors.RESET}")
        print()

        try:
            layers = input(f"  {Colors.WHITE}GPU layers [{current}]: {Colors.RESET}").strip()
            if layers:
                layers = int(layers)
                if layers >= -1:
                    self.config.set('llama', 'n_gpu_layers', str(layers))
                    self.config.save()
                    self.print_status(f"GPU layers set to {layers}", "success")
                else:
                    self.print_status("Value must be -1 or higher", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _get_llm_config_section(self):
        """Get the config section name for the current LLM backend."""
        backend = self.config.get('autarch', 'llm_backend', 'local')
        return {'transformers': 'transformers', 'claude': 'claude', 'huggingface': 'huggingface'}.get(backend, 'llama')

    def _set_llm_temperature(self):
        """Set LLM temperature."""
        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')
        section = self._get_llm_config_section()
        current = self.config.get_float(section, 'temperature', 0.7)
        print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
        print(f"  {Colors.DIM}Lower = more focused, Higher = more creative{Colors.RESET}")
        print(f"  {Colors.DIM}Typical range: 0.1 - 1.5{Colors.RESET}")
        print()

        try:
            temp = input(f"  {Colors.WHITE}Temperature [{current}]: {Colors.RESET}").strip()
            if temp:
                temp = float(temp)
                if 0.0 <= temp <= 2.0:
                    self.config.set(section, 'temperature', str(temp))
                    self.config.save()
                    self.print_status(f"Temperature set to {temp}", "success")
                else:
                    self.print_status("Value must be between 0.0 and 2.0", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_llm_sampling(self):
        """Set LLM Top P and Top K sampling parameters."""
        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')
        section = self._get_llm_config_section()
        current_p = self.config.get_float(section, 'top_p', 0.9)
        current_k = self.config.get_int(section, 'top_k', 40)
        print(f"  {Colors.DIM}Current Top P: {current_p} (nucleus sampling){Colors.RESET}")
        print(f"  {Colors.DIM}Current Top K: {current_k}{Colors.RESET}")
        print()

        try:
            # Top P
            top_p = input(f"  {Colors.WHITE}Top P (0.0-1.0) [{current_p}]: {Colors.RESET}").strip()
            if top_p:
                top_p = float(top_p)
                if 0.0 <= top_p <= 1.0:
                    self.config.set(section, 'top_p', str(top_p))
                    self.config.save()
                    self.print_status(f"Top P set to {top_p}", "success")
                else:
                    self.print_status("Top P must be between 0.0 and 1.0", "error")

            # Top K
            top_k = input(f"  {Colors.WHITE}Top K (0-1000) [{current_k}]: {Colors.RESET}").strip()
            if top_k:
                top_k = int(top_k)
                if 0 <= top_k <= 1000:
                    self.config.set(section, 'top_k', str(top_k))
                    self.config.save()
                    self.print_status(f"Top K set to {top_k}", "success")
                else:
                    self.print_status("Top K must be between 0 and 1000", "error")

        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_llm_repeat_penalty(self):
        """Set LLM repeat penalty."""
        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')
        section = self._get_llm_config_section()
        if backend == 'transformers':
            key = 'repetition_penalty'
        elif backend in ('claude', 'huggingface'):
            # These backends don't have repeat_penalty
            self.print_status("Repeat penalty not applicable for this backend", "info")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
            return
        else:
            key = 'repeat_penalty'
        current = self.config.get_float(section, key, 1.1)
        print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
        print(f"  {Colors.DIM}1.0 = no penalty, higher = less repetition{Colors.RESET}")
        print()

        try:
            penalty = input(f"  {Colors.WHITE}Repeat penalty [{current}]: {Colors.RESET}").strip()
            if penalty:
                penalty = float(penalty)
                if 0.0 <= penalty <= 2.0:
                    self.config.set(section, key, str(penalty))
                    self.config.save()
                    self.print_status(f"Repeat penalty set to {penalty}", "success")
                else:
                    self.print_status("Value must be between 0.0 and 2.0", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_llm_max_tokens(self):
        """Set LLM max tokens per response."""
        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')
        section = self._get_llm_config_section()
        current = self.config.get_int(section, 'max_tokens', 2048)
        print(f"  {Colors.DIM}Current: {current} tokens{Colors.RESET}")
        print(f"  {Colors.DIM}Maximum tokens generated per response{Colors.RESET}")
        print()

        try:
            tokens = input(f"  {Colors.WHITE}Max tokens [{current}]: {Colors.RESET}").strip()
            if tokens:
                tokens = int(tokens)
                if 1 <= tokens <= 32768:
                    self.config.set(section, 'max_tokens', str(tokens))
                    self.config.save()
                    self.print_status(f"Max tokens set to {tokens}", "success")
                else:
                    self.print_status("Value must be between 1 and 32768", "error")
        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _load_llm_model(self):
        """Load or reload the LLM model."""
        from .llm import get_llm, LLMError

        print()
        backend = self.config.get('autarch', 'llm_backend', 'local')

        if backend == 'transformers':
            model_path = self.config.get('transformers', 'model_path', '')
            is_valid = model_path and os.path.isdir(model_path)
        elif backend == 'claude':
            model_path = self.config.get('claude', 'model', '')
            is_valid = bool(model_path)  # Just needs model name
        elif backend == 'huggingface':
            model_path = self.config.get('huggingface', 'model', '')
            is_valid = bool(model_path)  # Just needs model ID
        else:
            model_path = self.config.get('llama', 'model_path', '')
            is_valid = model_path and os.path.isfile(model_path)

        if not model_path:
            self.print_status("No model path configured. Set model path first.", "error")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
            return

        if not is_valid:
            self.print_status(f"Model not found: {model_path}", "error")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
            return

        self.print_status(f"Loading model ({backend})...", "info")
        print(f"  {Colors.DIM}This may take a moment...{Colors.RESET}")
        print()

        try:
            llm = get_llm()
            if llm.is_loaded:
                llm.unload_model()
            llm.load_model(verbose=True)
            self.print_status("Model loaded successfully", "success")
        except LLMError as e:
            self.print_status(f"Failed to load model: {e}", "error")
        except Exception as e:
            self.print_status(f"Error: {e}", "error")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_transformers_device(self):
        """Set transformers device (cuda/cpu/mps/auto)."""
        print()
        current = self.config.get('transformers', 'device', 'auto')
        print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
        print(f"  {Colors.DIM}Options: auto, cuda, cpu, mps{Colors.RESET}")
        print()

        try:
            device = input(f"  {Colors.WHITE}Device [{current}]: {Colors.RESET}").strip()
            if device:
                if device in ['auto', 'cuda', 'cpu', 'mps']:
                    self.config.set('transformers', 'device', device)
                    self.config.save()
                    self.print_status(f"Device set to {device}", "success")
                else:
                    self.print_status("Invalid device. Use: auto, cuda, cpu, or mps", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_transformers_quantization(self):
        """Set transformers quantization settings."""
        print()
        load_8bit = self.config.get_bool('transformers', 'load_in_8bit', False)
        load_4bit = self.config.get_bool('transformers', 'load_in_4bit', False)

        if load_4bit:
            current = "4-bit"
        elif load_8bit:
            current = "8-bit"
        else:
            current = "None (full precision)"

        print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
        print(f"  {Colors.DIM}Quantization reduces memory but may affect quality{Colors.RESET}")
        print(f"  {Colors.DIM}Requires bitsandbytes package for 8-bit/4-bit{Colors.RESET}")
        print()
        print(f"  {Colors.GREEN}[1]{Colors.RESET} No quantization (full precision)")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} 8-bit quantization")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} 4-bit quantization")
        print()

        try:
            choice = input(f"  {Colors.WHITE}Select: {Colors.RESET}").strip()
            if choice == "1":
                self.config.set('transformers', 'load_in_8bit', 'false')
                self.config.set('transformers', 'load_in_4bit', 'false')
                self.config.save()
                self.print_status("Quantization disabled", "success")
            elif choice == "2":
                self.config.set('transformers', 'load_in_8bit', 'true')
                self.config.set('transformers', 'load_in_4bit', 'false')
                self.config.save()
                self.print_status("8-bit quantization enabled", "success")
            elif choice == "3":
                self.config.set('transformers', 'load_in_8bit', 'false')
                self.config.set('transformers', 'load_in_4bit', 'true')
                self.config.save()
                self.print_status("4-bit quantization enabled", "success")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _switch_llm_backend(self):
        """Switch between LLM backends."""
        from .llm import reset_llm

        print()
        current = self.config.get('autarch', 'llm_backend', 'local')
        print(f"  {Colors.DIM}Current backend: {current}{Colors.RESET}")
        print()
        print(f"  {Colors.GREEN}[1]{Colors.RESET} llama.cpp (GGUF models)")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} transformers (SafeTensors / PyTorch)")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Claude API")
        print(f"  {Colors.GREEN}[4]{Colors.RESET} HuggingFace Inference API")
        print()

        try:
            choice = input(f"  {Colors.WHITE}Select backend: {Colors.RESET}").strip()
            new_backend = None
            if choice == "1":
                new_backend = "local"
            elif choice == "2":
                new_backend = "transformers"
            elif choice == "3":
                new_backend = "claude"
            elif choice == "4":
                new_backend = "huggingface"

            if new_backend and new_backend != current:
                self.config.set('autarch', 'llm_backend', new_backend)
                self.config.save()
                reset_llm()  # Reset to pick up new backend
                self.print_status(f"Backend switched to {new_backend}", "success")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _load_hardware_template(self):
        """Load a hardware-specific configuration template."""
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Hardware Configuration Templates{Colors.RESET}")
        print(f"  {Colors.DIM}Select a template optimized for your hardware{Colors.RESET}")
        print()

        templates = self.config.list_hardware_templates()
        for i, (template_id, name, description, _) in enumerate(templates, 1):
            is_experimental = 'EXPERIMENTAL' in description
            color = Colors.YELLOW if is_experimental else Colors.GREEN
            print(f"  {color}[{i}]{Colors.RESET} {name}")
            print(f"      {Colors.DIM}{description}{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Cancel")
        print()

        try:
            choice = input(f"  {Colors.WHITE}Select template: {Colors.RESET}").strip()
            if choice and choice != "0":
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(templates):
                        template_id = templates[index][0]
                        template_name = templates[index][1]

                        # Confirm experimental templates
                        if 'EXPERIMENTAL' in templates[index][2]:
                            print()
                            print(f"  {Colors.YELLOW}WARNING: This template is experimental!{Colors.RESET}")
                            confirm = input(f"  {Colors.WHITE}Continue? (y/n): {Colors.RESET}").strip().lower()
                            if confirm != 'y':
                                self.print_status("Cancelled", "info")
                                input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                                return

                        if self.config.load_template(template_id):
                            self.print_status(f"Loaded template: {template_name}", "success")
                            print(f"  {Colors.DIM}Note: Model path preserved from current config{Colors.RESET}")
                        else:
                            self.print_status("Failed to load template", "error")
                    else:
                        self.print_status("Invalid selection", "error")
                except ValueError:
                    self.print_status("Invalid selection", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _load_custom_config(self):
        """Load a user-saved custom configuration."""
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Custom Configurations{Colors.RESET}")
        print()

        custom_configs = self.config.list_custom_configs()

        if not custom_configs:
            print(f"  {Colors.YELLOW}No custom configurations found.{Colors.RESET}")
            print(f"  {Colors.DIM}Use [W] Save Current as Custom Config to create one.{Colors.RESET}")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
            return

        for i, (name, filepath) in enumerate(custom_configs, 1):
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {name}")
            print(f"      {Colors.DIM}{filepath.name}{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[D]{Colors.RESET} Delete a custom config")
        print(f"  {Colors.DIM}[0]{Colors.RESET} Cancel")
        print()

        try:
            choice = input(f"  {Colors.WHITE}Select config: {Colors.RESET}").strip().lower()
            if choice == "d":
                self._delete_custom_config(custom_configs)
            elif choice and choice != "0":
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(custom_configs):
                        name, filepath = custom_configs[index]
                        if self.config.load_custom_config(filepath):
                            self.print_status(f"Loaded config: {name}", "success")
                            print(f"  {Colors.DIM}Note: Model path preserved from current config{Colors.RESET}")
                        else:
                            self.print_status("Failed to load config", "error")
                    else:
                        self.print_status("Invalid selection", "error")
                except ValueError:
                    self.print_status("Invalid selection", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _delete_custom_config(self, custom_configs: list):
        """Delete a custom configuration file."""
        print()
        print(f"  {Colors.RED}Delete Custom Configuration{Colors.RESET}")
        print()

        for i, (name, filepath) in enumerate(custom_configs, 1):
            print(f"  {Colors.RED}[{i}]{Colors.RESET} {name}")

        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Cancel")
        print()

        try:
            choice = input(f"  {Colors.WHITE}Select config to delete: {Colors.RESET}").strip()
            if choice and choice != "0":
                try:
                    index = int(choice) - 1
                    if 0 <= index < len(custom_configs):
                        name, filepath = custom_configs[index]
                        confirm = input(f"  {Colors.WHITE}Delete '{name}'? (y/n): {Colors.RESET}").strip().lower()
                        if confirm == 'y':
                            if self.config.delete_custom_config(filepath):
                                self.print_status(f"Deleted: {name}", "success")
                            else:
                                self.print_status("Failed to delete config", "error")
                        else:
                            self.print_status("Cancelled", "info")
                    else:
                        self.print_status("Invalid selection", "error")
                except ValueError:
                    self.print_status("Invalid selection", "error")
        except (EOFError, KeyboardInterrupt):
            print()

    def _save_custom_config(self):
        """Save current LLM settings as a custom configuration."""
        print()
        print(f"  {Colors.BOLD}{Colors.WHITE}Save Custom Configuration{Colors.RESET}")
        print(f"  {Colors.DIM}Save your current LLM settings for later use{Colors.RESET}")
        print()

        try:
            name = input(f"  {Colors.WHITE}Configuration name: {Colors.RESET}").strip()
            if name:
                filepath = self.config.save_custom_config(name)
                self.print_status(f"Saved to: {filepath.name}", "success")
                print(f"  {Colors.DIM}Full path: {filepath}{Colors.RESET}")
            else:
                self.print_status("No name provided, cancelled", "info")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _unload_llm_model(self):
        """Unload the current LLM model."""
        from .llm import get_llm

        print()
        llm = get_llm()

        if not llm.is_loaded:
            self.print_status("No model currently loaded", "info")
        else:
            llm.unload_model()
            self.print_status("Model unloaded", "success")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_osint_settings(self):
        """Display and configure OSINT settings."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  OSINT Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            settings = self.config.get_osint_settings()

            print(f"    {Colors.CYAN}Max Threads:{Colors.RESET}    {settings['max_threads']}")
            print(f"    {Colors.CYAN}Timeout:{Colors.RESET}        {settings['timeout']} seconds")
            print(f"    {Colors.CYAN}Include NSFW:{Colors.RESET}   {'Yes' if settings['include_nsfw'] else 'No'}")
            print()

            print(f"  {Colors.DIM}Thread setting controls parallel requests during{Colors.RESET}")
            print(f"  {Colors.DIM}username scanning. Lower values = slower but safer.{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Set Max Threads")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Set Timeout")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Toggle NSFW Sites")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self._set_osint_threads()
                elif choice == "2":
                    self._set_osint_timeout()
                elif choice == "3":
                    self._toggle_osint_nsfw()

            except (EOFError, KeyboardInterrupt):
                break

    def _set_osint_threads(self):
        """Set OSINT max threads."""
        print()
        current = self.config.get_int('osint', 'max_threads', 8)
        print(f"  {Colors.DIM}Current: {current} threads{Colors.RESET}")
        print(f"  {Colors.DIM}Recommended: 4-16 depending on your system{Colors.RESET}")
        print()

        try:
            threads = input(f"  {Colors.WHITE}Max threads (1-100) [{current}]: {Colors.RESET}").strip()

            if threads:
                threads = int(threads)
                if 1 <= threads <= 100:
                    self.config.set('osint', 'max_threads', str(threads))
                    self.config.save()
                    self.print_status(f"Max threads set to {threads}", "success")
                else:
                    self.print_status("Value must be between 1 and 100", "error")

        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_osint_timeout(self):
        """Set OSINT timeout."""
        print()
        current = self.config.get_int('osint', 'timeout', 8)
        print(f"  {Colors.DIM}Current: {current} seconds{Colors.RESET}")
        print()

        try:
            timeout = input(f"  {Colors.WHITE}Timeout in seconds (1-60) [{current}]: {Colors.RESET}").strip()

            if timeout:
                timeout = int(timeout)
                if 1 <= timeout <= 60:
                    self.config.set('osint', 'timeout', str(timeout))
                    self.config.save()
                    self.print_status(f"Timeout set to {timeout} seconds", "success")
                else:
                    self.print_status("Value must be between 1 and 60", "error")

        except ValueError:
            self.print_status("Invalid number", "error")
        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _toggle_osint_nsfw(self):
        """Toggle OSINT NSFW sites inclusion."""
        current = self.config.get_bool('osint', 'include_nsfw', False)
        new_value = not current
        self.config.set('osint', 'include_nsfw', str(new_value).lower())
        self.config.save()
        self.print_status(f"NSFW sites {'enabled' if new_value else 'disabled'}", "success")
        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_rsf_settings(self):
        """Display and configure RouterSploit settings."""
        from .rsf import get_rsf_manager

        rsf = get_rsf_manager()

        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  RouterSploit Configuration{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            settings = self.config.get_rsf_settings()

            print(f"    {Colors.CYAN}Install Path:{Colors.RESET}   {settings['install_path']}")

            # Status
            if rsf.is_available:
                count = rsf.get_module_count()
                print(f"    {Colors.CYAN}Status:{Colors.RESET}         {Colors.GREEN}Available ({count} modules){Colors.RESET}")
            else:
                print(f"    {Colors.CYAN}Status:{Colors.RESET}         {Colors.YELLOW}Not Found{Colors.RESET}")

            default_target = settings['default_target'] or '(not set)'
            print(f"    {Colors.CYAN}Default Target:{Colors.RESET} {default_target}")
            print(f"    {Colors.CYAN}Timeout:{Colors.RESET}        {settings['execution_timeout']}s")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Set Install Path")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Set Default Target")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Set Timeout")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Test Installation")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    print()
                    current = settings['install_path']
                    print(f"  {Colors.DIM}Current: {current}{Colors.RESET}")
                    path = input(f"  {Colors.WHITE}Install path: {Colors.RESET}").strip()
                    if path:
                        import os
                        path = os.path.expanduser(path)
                        if os.path.isdir(path):
                            self.config.set('rsf', 'install_path', path)
                            self.config.save()
                            rsf.reset_cache()
                            self.print_status(f"Install path set to: {path}", "success")
                        else:
                            self.print_status(f"Directory not found: {path}", "error")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

                elif choice == "2":
                    print()
                    current = settings['default_target']
                    prompt = f"Default target [{current}]: " if current else "Default target: "
                    target = input(f"  {Colors.WHITE}{prompt}{Colors.RESET}").strip()
                    if target:
                        self.config.set('rsf', 'default_target', target)
                        self.config.save()
                        self.print_status(f"Default target set to: {target}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

                elif choice == "3":
                    print()
                    current = settings['execution_timeout']
                    timeout_str = input(f"  {Colors.WHITE}Timeout in seconds [{current}]: {Colors.RESET}").strip()
                    if timeout_str:
                        try:
                            timeout = int(timeout_str)
                            if 10 <= timeout <= 600:
                                self.config.set('rsf', 'execution_timeout', str(timeout))
                                self.config.save()
                                self.print_status(f"Timeout set to {timeout}s", "success")
                            else:
                                self.print_status("Timeout must be between 10 and 600 seconds", "error")
                        except ValueError:
                            self.print_status("Invalid number", "error")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

                elif choice == "4":
                    print()
                    self.print_status("Testing RouterSploit installation...", "info")
                    rsf.reset_cache()
                    if rsf.is_available:
                        count = rsf.get_module_count()
                        self.print_status(f"RouterSploit is available! ({count} modules indexed)", "success")
                    else:
                        self.print_status("RouterSploit not found at configured path", "error")
                        print(f"  {Colors.DIM}Path: {settings['install_path']}{Colors.RESET}")
                        print(f"  {Colors.DIM}Make sure routersploit package is at this location{Colors.RESET}")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def show_msf_settings(self):
        """Display and configure Metasploit settings."""
        from .msf import get_msf_manager, MSFError

        msf = get_msf_manager()
        settings = msf.get_settings()

        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Metasploit Configuration{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Current settings
            print(f"    {Colors.CYAN}Host:{Colors.RESET}        {settings['host']}")
            print(f"    {Colors.CYAN}Port:{Colors.RESET}        {settings['port']}")
            print(f"    {Colors.CYAN}Username:{Colors.RESET}    {settings['username']}")
            print(f"    {Colors.CYAN}Password:{Colors.RESET}    {'*' * len(settings['password']) if settings['password'] else '(not set)'}")
            print(f"    {Colors.CYAN}SSL:{Colors.RESET}         {settings['ssl']}")
            print(f"    {Colors.CYAN}Autoconnect:{Colors.RESET} {Colors.GREEN if settings.get('autoconnect', True) else Colors.YELLOW}{'Enabled' if settings.get('autoconnect', True) else 'Disabled'}{Colors.RESET}")
            print()

            # Server status
            is_running, pid = msf.detect_server()
            if is_running:
                print(f"    {Colors.GREEN}Server: Running{Colors.RESET}", end="")
                if pid:
                    print(f" (PID: {pid})")
                else:
                    print()
            else:
                print(f"    {Colors.YELLOW}Server: Not Running{Colors.RESET}")

            # Connection status
            if msf.is_connected:
                print(f"    {Colors.GREEN}Client: Connected{Colors.RESET}")
                try:
                    version = msf.rpc.get_version()
                    print(f"    {Colors.DIM}Version: {version.get('version', 'Unknown')}{Colors.RESET}")
                except:
                    pass
            else:
                print(f"    {Colors.YELLOW}Client: Disconnected{Colors.RESET}")

            print()
            print(f"  {Colors.CYAN}[1]{Colors.RESET} Configure Connection")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Test Connection")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Disconnect")
            print()
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Start Server")
            print(f"  {Colors.CYAN}[5]{Colors.RESET} Stop Server")
            print(f"  {Colors.CYAN}[6]{Colors.RESET} Toggle Autoconnect")
            use_sudo = self.config.get_bool('msf', 'use_sudo', fallback=True)
            print(f"  {Colors.CYAN}[7]{Colors.RESET} Toggle Sudo    {Colors.DIM}(currently: {'on' if use_sudo else 'off'}){Colors.RESET}")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self.configure_msf()
                    settings = msf.get_settings()
                elif choice == "2":
                    print()
                    # Refresh settings before attempting connection
                    settings = msf.get_settings()
                    self.print_status("Testing connection...", "info")
                    try:
                        if not settings['password']:
                            password = input(f"    {Colors.WHITE}Enter MSF RPC password: {Colors.RESET}").strip()
                        else:
                            password = settings['password']
                        msf.connect(password)
                        self.print_status("Connected successfully!", "success")
                        version = msf.rpc.get_version()
                        print(f"    {Colors.DIM}Metasploit {version.get('version', 'Unknown')}{Colors.RESET}")
                    except MSFError as e:
                        self.print_status(f"Connection failed: {e}", "error")
                        if "Authentication failed" in str(e):
                            print(f"    {Colors.DIM}The server may be running with different credentials.{Colors.RESET}")
                            print(f"    {Colors.DIM}Try: [5] Stop Server, then [4] Start Server{Colors.RESET}")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                elif choice == "3":
                    msf.disconnect()
                    self.print_status("Disconnected", "info")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                elif choice == "4":
                    # Start server
                    print()
                    if is_running:
                        self.print_status("Server is already running", "warning")
                    else:
                        if not settings['password']:
                            password = input(f"    {Colors.WHITE}Enter MSF RPC password: {Colors.RESET}").strip()
                            if password:
                                msf.save_settings(
                                    settings['host'], settings['port'],
                                    settings['username'], password, settings['ssl']
                                )
                                settings = msf.get_settings()
                        else:
                            password = settings['password']

                        if password:
                            self.print_status("Starting server...", "info")
                            if msf.start_server(
                                settings['username'], password,
                                settings['host'], settings['port'], settings['ssl']
                            ):
                                self.print_status("Server started successfully", "success")
                            else:
                                self.print_status("Failed to start server", "error")
                        else:
                            self.print_status("Password required to start server", "error")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                elif choice == "5":
                    # Stop server
                    print()
                    if not is_running:
                        self.print_status("Server is not running", "warning")
                    else:
                        self.print_status("Stopping server...", "info")
                        if msf.kill_server():
                            self.print_status("Server stopped", "success")
                        else:
                            self.print_status("Failed to stop server", "error")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                elif choice == "6":
                    # Toggle autoconnect
                    new_value = not settings.get('autoconnect', True)
                    msf.set_autoconnect(new_value)
                    settings = msf.get_settings()
                    self.print_status(f"Autoconnect {'enabled' if new_value else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
                elif choice == "7":
                    # Toggle sudo for MSF server start
                    use_sudo = self.config.get_bool('msf', 'use_sudo', fallback=True)
                    new_value = not use_sudo
                    self.config.set('msf', 'use_sudo', str(new_value).lower())
                    self.config.save()
                    if new_value:
                        self.print_status("Sudo enabled — msfrpcd runs as root (full module support)", "success")
                    else:
                        self.print_status("Sudo disabled — msfrpcd runs as current user (some modules limited)", "warning")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def configure_msf(self):
        """Configure Metasploit connection settings."""
        from .msf import get_msf_manager

        msf = get_msf_manager()
        settings = msf.get_settings()

        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Configure Metasploit RPC{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print(f"\n  {Colors.DIM}Press Enter to keep current value{Colors.RESET}\n")

        try:
            host = input(f"    Host [{settings['host']}]: ").strip() or settings['host']
            port_str = input(f"    Port [{settings['port']}]: ").strip()
            port = int(port_str) if port_str else settings['port']
            username = input(f"    Username [{settings['username']}]: ").strip() or settings['username']
            password = input(f"    Password: ").strip() or settings['password']
            ssl_str = input(f"    Use SSL (y/n) [{'y' if settings['ssl'] else 'n'}]: ").strip().lower()
            use_ssl = ssl_str == 'y' if ssl_str else settings['ssl']

            msf.save_settings(host, port, username, password, use_ssl)
            self.print_status("Settings saved", "success")

        except (ValueError, EOFError, KeyboardInterrupt):
            print()
            self.print_status("Configuration cancelled", "warning")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_all_settings(self):
        """Display all current settings."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  All Settings{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # LLM Settings
        print(f"  {Colors.CYAN}LLM Configuration:{Colors.RESET}")
        settings = self.config.get_llama_settings()
        for key, value in settings.items():
            print(f"    {key:20}: {value}")

        # MSF Settings
        print()
        print(f"  {Colors.CYAN}Metasploit Configuration:{Colors.RESET}")
        from .msf import get_msf_manager
        msf_settings = get_msf_manager().get_settings()
        for key, value in msf_settings.items():
            if key == 'password':
                value = '*' * len(value) if value else '(not set)'
            print(f"    {key:20}: {value}")

        # OSINT Settings
        print()
        print(f"  {Colors.CYAN}OSINT Configuration:{Colors.RESET}")
        osint_settings = self.config.get_osint_settings()
        for key, value in osint_settings.items():
            print(f"    {key:20}: {value}")

        print()
        print(f"  {Colors.CYAN}Config file:{Colors.RESET} {self.config.config_path}")
        print()

        input(f"{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_database_management(self):
        """Display database management menu."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Database Management{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Get database info
            from .cve import get_cve_db
            cve_db = get_cve_db()
            cve_stats = cve_db.get_db_stats()

            # Custom APIs
            custom_apis = self._load_custom_apis()

            # System audit
            system_inf = self._app_dir / "system.inf"

            # Adult scanner custom sites
            adult_sites = self._app_dir / "custom_adultsites.json"

            # Calculate total storage
            total_size = 0

            print(f"  {Colors.CYAN}Databases:{Colors.RESET}")
            print()

            # CVE Database
            cve_size = cve_stats['db_size_mb']
            total_size += cve_size
            status = f"{Colors.GREEN}Active{Colors.RESET}" if cve_stats['total_cves'] > 0 else f"{Colors.YELLOW}Empty{Colors.RESET}"
            print(f"  {Colors.BLUE}[1]{Colors.RESET} CVE Database")
            print(f"      {Colors.DIM}Records: {cve_stats['total_cves']:,} | Size: {cve_size} MB | {status}{Colors.RESET}")

            # System Audit Results
            if system_inf.exists():
                sys_size = round(system_inf.stat().st_size / 1024 / 1024, 2)
                total_size += sys_size
                print(f"  {Colors.BLUE}[2]{Colors.RESET} System Audit Data")
                print(f"      {Colors.DIM}Size: {sys_size} MB | {Colors.GREEN}Active{Colors.RESET}")
            else:
                print(f"  {Colors.BLUE}[2]{Colors.RESET} System Audit Data")
                print(f"      {Colors.DIM}No data | {Colors.YELLOW}Empty{Colors.RESET}")

            # Custom Sites Database
            if adult_sites.exists():
                import json
                try:
                    with open(adult_sites) as f:
                        sites_data = json.load(f)
                    sites_count = len(sites_data.get('sites', []))
                    sites_size = round(adult_sites.stat().st_size / 1024, 2)
                    print(f"  {Colors.BLUE}[3]{Colors.RESET} Custom Sites Database")
                    print(f"      {Colors.DIM}Sites: {sites_count} | Size: {sites_size} KB{Colors.RESET}")
                except:
                    print(f"  {Colors.BLUE}[3]{Colors.RESET} Custom Sites Database")
                    print(f"      {Colors.DIM}Error reading | {Colors.RED}Corrupt{Colors.RESET}")
            else:
                print(f"  {Colors.BLUE}[3]{Colors.RESET} Custom Sites Database")
                print(f"      {Colors.DIM}No custom sites | {Colors.YELLOW}Empty{Colors.RESET}")

            # Custom APIs
            print(f"  {Colors.BLUE}[4]{Colors.RESET} Custom APIs")
            print(f"      {Colors.DIM}APIs: {len(custom_apis)}{Colors.RESET}")

            print()
            print(f"  {Colors.DIM}Total Storage: ~{round(total_size, 2)} MB{Colors.RESET}")
            print()

            print(f"  {Colors.GREEN}[S]{Colors.RESET} Sync All Databases")
            print(f"  {Colors.YELLOW}[B]{Colors.RESET} Backup All Databases")
            print(f"  {Colors.RED}[C]{Colors.RESET} Clear All Databases")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().upper()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self.show_cve_settings()
                elif choice == "2":
                    self._manage_system_audit_data()
                elif choice == "3":
                    self._manage_custom_sites()
                elif choice == "4":
                    self.show_custom_apis()
                elif choice == "S":
                    self._sync_all_databases()
                elif choice == "B":
                    self._backup_all_databases()
                elif choice == "C":
                    self._clear_all_databases()

            except (EOFError, KeyboardInterrupt):
                break

    def _manage_system_audit_data(self):
        """Manage system audit data."""
        system_inf = self._app_dir / "system.inf"

        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  System Audit Data{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        if system_inf.exists():
            import json
            try:
                with open(system_inf) as f:
                    data = json.load(f)

                print(f"  {Colors.CYAN}Audit Date:{Colors.RESET} {data.get('audit_date', 'Unknown')[:19]}")
                print(f"  {Colors.CYAN}Security Score:{Colors.RESET} {data.get('security_score', 'N/A')}/100")
                print(f"  {Colors.CYAN}Issues Found:{Colors.RESET} {len(data.get('issues', []))}")
                print(f"  {Colors.CYAN}System:{Colors.RESET} {data.get('system_info', {}).get('os_name', 'Unknown')}")
                print()

                print(f"  {Colors.RED}[D]{Colors.RESET} Delete Audit Data")
                print(f"  {Colors.CYAN}[V]{Colors.RESET} View Details")
            except Exception as e:
                print(f"  {Colors.RED}Error reading data: {e}{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}No audit data found.{Colors.RESET}")
            print(f"  {Colors.DIM}Run a system audit from My System module.{Colors.RESET}")

        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().upper()

            if choice == "D" and system_inf.exists():
                confirm = input(f"  {Colors.RED}Delete audit data? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    system_inf.unlink()
                    self.print_status("Audit data deleted", "success")
            elif choice == "V" and system_inf.exists():
                import json
                with open(system_inf) as f:
                    data = json.load(f)
                print(f"\n{Colors.DIM}{json.dumps(data, indent=2)[:2000]}...{Colors.RESET}")

        except (EOFError, KeyboardInterrupt):
            pass

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _manage_custom_sites(self):
        """Manage custom adult scanner sites."""
        sites_path = self._app_dir / "custom_adultsites.json"

        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Custom Sites Database{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        if sites_path.exists():
            import json
            try:
                with open(sites_path) as f:
                    data = json.load(f)

                sites = data.get('sites', [])
                print(f"  {Colors.CYAN}Total Sites:{Colors.RESET} {len(sites)}")
                print()

                if sites:
                    print(f"  {Colors.DIM}Sites:{Colors.RESET}")
                    for site in sites[:10]:
                        name = site[0] if isinstance(site, list) else site.get('name', 'Unknown')
                        print(f"    - {name}")
                    if len(sites) > 10:
                        print(f"    {Colors.DIM}... and {len(sites) - 10} more{Colors.RESET}")

                print()
                print(f"  {Colors.RED}[D]{Colors.RESET} Delete All Custom Sites")
                print(f"  {Colors.CYAN}[E]{Colors.RESET} Export Sites List")
            except Exception as e:
                print(f"  {Colors.RED}Error reading data: {e}{Colors.RESET}")
        else:
            print(f"  {Colors.YELLOW}No custom sites configured.{Colors.RESET}")
            print(f"  {Colors.DIM}Add sites from the Adult Scanner module.{Colors.RESET}")

        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        try:
            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().upper()

            if choice == "D" and sites_path.exists():
                confirm = input(f"  {Colors.RED}Delete all custom sites? (y/n): {Colors.RESET}").strip().lower()
                if confirm == 'y':
                    sites_path.unlink()
                    self.print_status("Custom sites deleted", "success")
            elif choice == "E" and sites_path.exists():
                export_path = self._app_dir / "custom_sites_export.txt"
                import json
                with open(sites_path) as f:
                    data = json.load(f)
                with open(export_path, 'w') as f:
                    for site in data.get('sites', []):
                        name = site[0] if isinstance(site, list) else site.get('name', '')
                        url = site[1] if isinstance(site, list) else site.get('url', '')
                        f.write(f"{name}: {url}\n")
                self.print_status(f"Exported to {export_path}", "success")

        except (EOFError, KeyboardInterrupt):
            pass

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _sync_all_databases(self):
        """Sync all databases."""
        print()
        print(f"{Colors.CYAN}[*] Syncing all databases...{Colors.RESET}")
        print()

        # Sync CVE database
        print(f"{Colors.CYAN}[*] Syncing CVE database (recent)...{Colors.RESET}")
        from .cve import get_cve_db
        cve_db = get_cve_db()
        stats = cve_db.sync_database(days_back=30, verbose=True)
        print(f"{Colors.GREEN}[+] CVE sync complete: {stats.get('cves_processed', 0):,} CVEs{Colors.RESET}")

        print()
        self.print_status("All databases synced", "success")
        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _backup_all_databases(self):
        """Backup all databases."""
        import shutil
        from datetime import datetime

        backup_dir = self._app_dir / "backups" / datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir.mkdir(parents=True, exist_ok=True)

        print()
        print(f"{Colors.CYAN}[*] Creating backup at {backup_dir}...{Colors.RESET}")
        print()

        files_to_backup = [
            ("data/cve/cve.db", "CVE Database"),
            ("system.inf", "System Audit Data"),
            ("custom_adultsites.json", "Custom Sites"),
            ("custom_apis.json", "Custom APIs"),
            ("autarch_settings.conf", "Settings"),
        ]

        backed_up = 0
        for filepath, name in files_to_backup:
            src = self._app_dir / filepath
            if src.exists():
                dst = backup_dir / src.name
                try:
                    shutil.copy2(src, dst)
                    print(f"  {Colors.GREEN}[+]{Colors.RESET} {name}")
                    backed_up += 1
                except Exception as e:
                    print(f"  {Colors.RED}[X]{Colors.RESET} {name}: {e}")
            else:
                print(f"  {Colors.DIM}[-]{Colors.RESET} {name} (not found)")

        print()
        self.print_status(f"Backed up {backed_up} files to {backup_dir}", "success")
        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _clear_all_databases(self):
        """Clear all databases."""
        print()
        print(f"{Colors.RED}[!] WARNING: This will delete ALL data:{Colors.RESET}")
        print(f"    - CVE Database")
        print(f"    - System Audit Data")
        print(f"    - Custom Sites")
        print(f"    - Custom APIs")
        print()

        confirm = input(f"{Colors.WHITE}Type 'DELETE ALL' to confirm: {Colors.RESET}").strip()

        if confirm == 'DELETE ALL':
            import os

            files_to_delete = [
                "data/cve/cve.db",
                "system.inf",
                "custom_adultsites.json",
                "custom_apis.json",
            ]

            for filepath in files_to_delete:
                path = self._app_dir / filepath
                if path.exists():
                    try:
                        os.remove(path)
                        print(f"  {Colors.GREEN}[+]{Colors.RESET} Deleted {path.name}")
                    except Exception as e:
                        print(f"  {Colors.RED}[X]{Colors.RESET} Failed to delete {path.name}: {e}")

            self.print_status("All databases cleared", "success")
        else:
            self.print_status("Operation cancelled", "info")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_cve_settings(self):
        """Display CVE database settings."""
        from .cve import get_cve_db

        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  CVE Database Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            cve_db = get_cve_db()
            stats = cve_db.get_db_stats()
            sys_info = cve_db.get_system_info()

            # Database info
            print(f"  {Colors.CYAN}Database Path:{Colors.RESET} {stats['db_path']}")
            print(f"  {Colors.CYAN}Database Size:{Colors.RESET} {stats['db_size_mb']} MB")
            print(f"  {Colors.CYAN}Total CVEs:{Colors.RESET} {stats['total_cves']:,}")
            print(f"  {Colors.CYAN}Last Sync:{Colors.RESET} {stats.get('last_sync', 'Never')[:19] if stats.get('last_sync') else 'Never'}")
            print()

            # System detection
            print(f"  {Colors.CYAN}Detected OS:{Colors.RESET} {sys_info.get('os_name', 'Unknown')}")
            print(f"  {Colors.CYAN}CPE Prefix:{Colors.RESET} {sys_info.get('cpe_prefix', 'Unknown')}")
            print()

            # NVD API Key status
            api_key = self.config.get('nvd', 'api_key', fallback='')
            if api_key:
                print(f"  {Colors.GREEN}NVD API Key:{Colors.RESET} Configured")
            else:
                print(f"  {Colors.YELLOW}NVD API Key:{Colors.RESET} Not set (slower sync)")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} Sync Database (Recent - 120 days)")
            print(f"  {Colors.YELLOW}[2]{Colors.RESET} Sync Database (Full - all CVEs)")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Set NVD API Key")
            print(f"  {Colors.RED}[4]{Colors.RESET} Clear Database")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self._sync_cve_database(days=120)
                elif choice == "2":
                    self._sync_cve_database(full=True)
                elif choice == "3":
                    self._set_nvd_api_key()
                elif choice == "4":
                    self._clear_cve_database()

            except (EOFError, KeyboardInterrupt):
                break

    def _sync_cve_database(self, days: int = 120, full: bool = False):
        """Sync CVE database."""
        from .cve import get_cve_db

        print()
        if full:
            print(f"{Colors.YELLOW}[!] Full sync will download 200,000+ CVEs{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] This may take 2-6 hours{Colors.RESET}")
            confirm = input(f"\n{Colors.WHITE}Continue? (y/n): {Colors.RESET}").strip().lower()
            if confirm != 'y':
                return
        else:
            print(f"{Colors.CYAN}[*] Syncing CVEs from last {days} days...{Colors.RESET}")

        print()
        cve_db = get_cve_db()
        stats = cve_db.sync_database(days_back=days, full_sync=full, verbose=True)

        print(f"\n{Colors.GREEN}[+] Sync complete: {stats.get('cves_processed', 0):,} CVEs{Colors.RESET}")
        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _set_nvd_api_key(self):
        """Set NVD API key."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  NVD API Key Configuration{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}Get your free API key at:{Colors.RESET}")
        print(f"  {Colors.CYAN}https://nvd.nist.gov/developers/request-an-api-key{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}Benefits: 50 requests/30s vs 5 requests/30s{Colors.RESET}")
        print()

        current = self.config.get('nvd', 'api_key', fallback='')
        if current:
            print(f"  {Colors.GREEN}Current: {current[:8]}...{Colors.RESET}")
        print()

        try:
            api_key = input(f"{Colors.WHITE}  Enter API key (or Enter to skip): {Colors.RESET}").strip()

            if api_key:
                self.config.set('nvd', 'api_key', api_key)
                self.config.save()
                self.print_status("API key saved", "success")
            else:
                self.print_status("No changes made", "info")

        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _clear_cve_database(self):
        """Clear CVE database."""
        from .cve import get_cve_db
        import os

        print()
        print(f"{Colors.RED}[!] This will delete all CVE data{Colors.RESET}")
        confirm = input(f"{Colors.WHITE}Type 'DELETE' to confirm: {Colors.RESET}").strip()

        if confirm == 'DELETE':
            cve_db = get_cve_db()
            db_path = cve_db.db_path
            cve_db.close()

            try:
                os.remove(db_path)
                self.print_status("Database cleared", "success")
            except Exception as e:
                self.print_status(f"Failed to clear: {e}", "error")
        else:
            self.print_status("Operation cancelled", "info")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_custom_apis(self):
        """Display custom APIs management menu."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Custom APIs{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Load existing APIs
            custom_apis = self._load_custom_apis()

            if custom_apis:
                print(f"  {Colors.CYAN}Configured APIs:{Colors.RESET}")
                for i, (name, api) in enumerate(custom_apis.items(), 1):
                    status = f"{Colors.GREEN}Active{Colors.RESET}" if api.get('enabled', True) else f"{Colors.RED}Disabled{Colors.RESET}"
                    print(f"    [{i}] {name} - {status}")
                    print(f"        {Colors.DIM}{api.get('url', 'No URL')[:50]}...{Colors.RESET}")
                print()
            else:
                print(f"  {Colors.DIM}No custom APIs configured{Colors.RESET}")
                print()

            print(f"  {Colors.GREEN}[A]{Colors.RESET} Add API")
            if custom_apis:
                print(f"  {Colors.CYAN}[E]{Colors.RESET} Edit API")
                print(f"  {Colors.RED}[D]{Colors.RESET} Delete API")
                print(f"  {Colors.YELLOW}[T]{Colors.RESET} Toggle API")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().upper()

                if choice == "0" or not choice:
                    break
                elif choice == "A":
                    self._add_custom_api()
                elif choice == "E" and custom_apis:
                    self._edit_custom_api(custom_apis)
                elif choice == "D" and custom_apis:
                    self._delete_custom_api(custom_apis)
                elif choice == "T" and custom_apis:
                    self._toggle_custom_api(custom_apis)

            except (EOFError, KeyboardInterrupt):
                break

    def _load_custom_apis(self) -> dict:
        """Load custom APIs from config."""
        import json
        apis_path = self._app_dir / "custom_apis.json"

        if apis_path.exists():
            try:
                with open(apis_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_custom_apis(self, apis: dict):
        """Save custom APIs to config."""
        import json
        apis_path = self._app_dir / "custom_apis.json"

        with open(apis_path, 'w') as f:
            json.dump(apis, f, indent=2)

    def _add_custom_api(self):
        """Add a new custom API."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Add Custom API{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        try:
            name = input(f"  {Colors.WHITE}API Name: {Colors.RESET}").strip()
            if not name:
                return

            url = input(f"  {Colors.WHITE}Base URL: {Colors.RESET}").strip()
            api_key = input(f"  {Colors.WHITE}API Key (optional): {Colors.RESET}").strip()
            description = input(f"  {Colors.WHITE}Description: {Colors.RESET}").strip()

            # API type
            print(f"\n  {Colors.DIM}API Types:{Colors.RESET}")
            print(f"    [1] REST API")
            print(f"    [2] GraphQL")
            print(f"    [3] SOAP")
            print(f"    [4] Other")
            api_type = input(f"  {Colors.WHITE}Type [1]: {Colors.RESET}").strip() or "1"
            type_map = {"1": "REST", "2": "GraphQL", "3": "SOAP", "4": "Other"}
            api_type = type_map.get(api_type, "REST")

            apis = self._load_custom_apis()
            apis[name] = {
                'url': url,
                'api_key': api_key,
                'description': description,
                'type': api_type,
                'enabled': True,
            }
            self._save_custom_apis(apis)

            self.print_status(f"API '{name}' added", "success")

        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _edit_custom_api(self, apis: dict):
        """Edit an existing custom API."""
        api_list = list(apis.keys())
        print()
        num = input(f"  {Colors.WHITE}Enter API number to edit: {Colors.RESET}").strip()

        try:
            idx = int(num) - 1
            if 0 <= idx < len(api_list):
                name = api_list[idx]
                api = apis[name]

                clear_screen()
                self._show_banner()
                print(f"{Colors.BOLD}{Colors.WHITE}  Edit API: {name}{Colors.RESET}")
                print(f"{Colors.DIM}  Press Enter to keep current value{Colors.RESET}")
                print()

                new_url = input(f"  URL [{api.get('url', '')}]: ").strip() or api.get('url', '')
                new_key = input(f"  API Key: ").strip() or api.get('api_key', '')
                new_desc = input(f"  Description [{api.get('description', '')}]: ").strip() or api.get('description', '')

                api['url'] = new_url
                api['api_key'] = new_key
                api['description'] = new_desc
                self._save_custom_apis(apis)

                self.print_status("API updated", "success")
        except (ValueError, IndexError):
            self.print_status("Invalid selection", "error")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _delete_custom_api(self, apis: dict):
        """Delete a custom API."""
        api_list = list(apis.keys())
        print()
        num = input(f"  {Colors.WHITE}Enter API number to delete: {Colors.RESET}").strip()

        try:
            idx = int(num) - 1
            if 0 <= idx < len(api_list):
                name = api_list[idx]
                confirm = input(f"  {Colors.RED}Delete '{name}'? (y/n): {Colors.RESET}").strip().lower()

                if confirm == 'y':
                    del apis[name]
                    self._save_custom_apis(apis)
                    self.print_status(f"API '{name}' deleted", "success")
                else:
                    self.print_status("Cancelled", "info")
        except (ValueError, IndexError):
            self.print_status("Invalid selection", "error")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _toggle_custom_api(self, apis: dict):
        """Toggle a custom API enabled/disabled."""
        api_list = list(apis.keys())
        print()
        num = input(f"  {Colors.WHITE}Enter API number to toggle: {Colors.RESET}").strip()

        try:
            idx = int(num) - 1
            if 0 <= idx < len(api_list):
                name = api_list[idx]
                apis[name]['enabled'] = not apis[name].get('enabled', True)
                self._save_custom_apis(apis)
                status = "enabled" if apis[name]['enabled'] else "disabled"
                self.print_status(f"API '{name}' {status}", "success")
        except (ValueError, IndexError):
            self.print_status("Invalid selection", "error")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def show_autarch_api(self):
        """Display AUTARCH API settings (placeholder for future implementation)."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  AUTARCH API{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Check if API is enabled
            api_enabled = self.config.get_bool('api', 'enabled', fallback=False)
            api_port = self.config.get_int('api', 'port', fallback=8080)
            api_key = self.config.get('api', 'key', fallback='')

            if api_enabled:
                print(f"  {Colors.GREEN}Status:{Colors.RESET} Enabled")
            else:
                print(f"  {Colors.YELLOW}Status:{Colors.RESET} Disabled")

            print(f"  {Colors.CYAN}Port:{Colors.RESET} {api_port}")
            print(f"  {Colors.CYAN}API Key:{Colors.RESET} {'Configured' if api_key else 'Not set'}")
            print()

            print(f"  {Colors.DIM}The AUTARCH API allows external tools to{Colors.RESET}")
            print(f"  {Colors.DIM}interact with the framework programmatically.{Colors.RESET}")
            print()

            print(f"  {Colors.YELLOW}[!] API functionality coming in future version{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Configure API Settings")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Generate API Key")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} View API Documentation")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    self._configure_autarch_api()
                elif choice == "2":
                    self._generate_api_key()
                elif choice == "3":
                    self._show_api_docs()

            except (EOFError, KeyboardInterrupt):
                break

    def _configure_autarch_api(self):
        """Configure AUTARCH API settings."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Configure AUTARCH API{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        try:
            enabled = input(f"  Enable API? (y/n) [{self.config.get_bool('api', 'enabled', fallback=False) and 'y' or 'n'}]: ").strip().lower()
            if enabled:
                self.config.set('api', 'enabled', 'true' if enabled == 'y' else 'false')

            port = input(f"  Port [{self.config.get_int('api', 'port', fallback=8080)}]: ").strip()
            if port.isdigit():
                self.config.set('api', 'port', port)

            self.config.save()
            self.print_status("API settings saved", "success")

        except (EOFError, KeyboardInterrupt):
            print()

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _generate_api_key(self):
        """Generate a new API key."""
        import secrets
        import string

        print()
        api_key = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

        self.config.set('api', 'key', api_key)
        self.config.save()

        print(f"  {Colors.GREEN}New API Key:{Colors.RESET} {api_key}")
        print(f"\n  {Colors.YELLOW}Store this key securely - it won't be shown again!{Colors.RESET}")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def _show_api_docs(self):
        """Show API documentation."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  AUTARCH API Documentation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        print(f"  {Colors.CYAN}Endpoints (coming soon):{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}GET  /api/v1/status{Colors.RESET}")
        print(f"       Get framework status")
        print()
        print(f"  {Colors.DIM}GET  /api/v1/modules{Colors.RESET}")
        print(f"       List available modules")
        print()
        print(f"  {Colors.DIM}POST /api/v1/scan{Colors.RESET}")
        print(f"       Run a security scan")
        print()
        print(f"  {Colors.DIM}GET  /api/v1/cve/search?q=<query>{Colors.RESET}")
        print(f"       Search CVE database")
        print()
        print(f"  {Colors.DIM}POST /api/v1/agent/task{Colors.RESET}")
        print(f"       Submit task to AI agent")
        print()

        print(f"  {Colors.YELLOW}Full documentation will be available when{Colors.RESET}")
        print(f"  {Colors.YELLOW}the API is implemented in a future version.{Colors.RESET}")

        input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def run_agent_hal(self):
        """Run the Agent Hal module."""
        try:
            from modules.agent_hal import run as run_hal
            run_hal()
        except ImportError as e:
            self.print_status(f"Failed to load Agent Hal: {e}", "error")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")
        except Exception as e:
            self.print_status(f"Error running Agent Hal: {e}", "error")
            input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def run_setup(self):
        """Run the setup wizard."""
        from modules.setup import run as run_setup
        run_setup()

    def show_web_service(self):
        """Web service management menu."""
        import subprocess

        SERVICE_NAME = "autarch-web"
        SERVICE_FILE = self._app_dir / "scripts" / "autarch-web.service"
        SYSTEMD_PATH = Path("/etc/systemd/system/autarch-web.service")

        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Web Dashboard Service{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Check status
            installed = SYSTEMD_PATH.exists()
            if installed:
                result = subprocess.run(
                    ['systemctl', 'is-active', SERVICE_NAME],
                    capture_output=True, text=True
                )
                is_active = result.stdout.strip()
                result2 = subprocess.run(
                    ['systemctl', 'is-enabled', SERVICE_NAME],
                    capture_output=True, text=True
                )
                is_enabled = result2.stdout.strip()
                color = Colors.GREEN if is_active == 'active' else Colors.RED
                print(f"    Service:  {color}{is_active}{Colors.RESET}")
                print(f"    Enabled:  {is_enabled}")
            else:
                print(f"    Service:  {Colors.YELLOW}Not installed{Colors.RESET}")

            host = self.config.get('web', 'host', fallback='0.0.0.0')
            port = self.config.get('web', 'port', fallback='8181')
            print(f"    Address:  http://{host}:{port}")
            print()

            if not installed:
                print(f"  {Colors.GREEN}[1]{Colors.RESET} Install Service")
            else:
                print(f"  {Colors.GREEN}[1]{Colors.RESET} Start Service")
                print(f"  {Colors.RED}[2]{Colors.RESET} Stop Service")
                print(f"  {Colors.YELLOW}[3]{Colors.RESET} Restart Service")
                print(f"  {Colors.CYAN}[4]{Colors.RESET} Enable (auto-start on boot)")
                print(f"  {Colors.CYAN}[5]{Colors.RESET} Disable (no auto-start)")
                print(f"  {Colors.DIM}[6]{Colors.RESET} View Logs")

            print(f"\n  {Colors.CYAN}[7]{Colors.RESET} Start Web UI (foreground, no service)")
            print(f"  {Colors.CYAN}[8]{Colors.RESET} Configure Host/Port")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1" and not installed:
                    try:
                        r = root_exec(['cp', str(SERVICE_FILE), str(SYSTEMD_PATH)])
                        if not r['ok']: raise subprocess.CalledProcessError(r['code'], 'cp')
                        r = root_exec(['systemctl', 'daemon-reload'])
                        if not r['ok']: raise subprocess.CalledProcessError(r['code'], 'systemctl')
                        self.print_status("Service installed", "success")
                    except Exception as e:
                        self.print_status(f"Install failed: {e}", "error")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "1" and installed:
                    root_exec(['systemctl', 'start', SERVICE_NAME])
                    self.print_status("Service started", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "2":
                    root_exec(['systemctl', 'stop', SERVICE_NAME])
                    self.print_status("Service stopped", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "3":
                    root_exec(['systemctl', 'restart', SERVICE_NAME])
                    self.print_status("Service restarted", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "4":
                    root_exec(['systemctl', 'enable', SERVICE_NAME])
                    self.print_status("Auto-start enabled", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "5":
                    root_exec(['systemctl', 'disable', SERVICE_NAME])
                    self.print_status("Auto-start disabled", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "6":
                    result = subprocess.run(
                        ['journalctl', '-u', SERVICE_NAME, '-n', '30', '--no-pager'],
                        capture_output=True, text=True
                    )
                    print(f"\n{Colors.DIM}{result.stdout}{Colors.RESET}")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "7":
                    from web.app import create_app
                    app = create_app()
                    print(f"\n{Colors.GREEN}[+] Starting web UI on {host}:{port}{Colors.RESET}")
                    print(f"{Colors.DIM}    Press Ctrl+C to stop{Colors.RESET}\n")
                    try:
                        app.run(host=host, port=int(port), debug=False)
                    except KeyboardInterrupt:
                        print(f"\n{Colors.CYAN}Web UI stopped.{Colors.RESET}")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "8":
                    print()
                    new_host = input(f"  {Colors.WHITE}Bind host [{host}]: {Colors.RESET}").strip()
                    new_port = input(f"  {Colors.WHITE}Port [{port}]: {Colors.RESET}").strip()
                    if new_host:
                        self.config.set('web', 'host', new_host)
                    if new_port:
                        try:
                            int(new_port)
                            self.config.set('web', 'port', new_port)
                        except ValueError:
                            self.print_status("Invalid port number", "error")
                            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                            continue
                    if new_host or new_port:
                        self.config.save()
                        self.print_status("Web settings saved", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def sideload_companion(self):
        """Sideload Archon companion APK to connected Android device."""
        from core.paths import find_tool, get_app_dir

        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Sideload Archon Companion App{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        adb = find_tool('adb')
        if not adb:
            self.print_status("ADB not found. Install Android SDK tools.", "error")
            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
            return

        # Check for APK
        app_dir = get_app_dir()
        apk_locations = [
            app_dir / "autarch_companion" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk",
            app_dir / "autarch_companion" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk",
            app_dir / "autarch_companion" / "archon.apk",
            app_dir / "archon.apk",
        ]

        apk_path = None
        for loc in apk_locations:
            if loc.exists():
                apk_path = loc
                break

        if not apk_path:
            self.print_status("Archon APK not found.", "warning")
            print(f"\n  {Colors.DIM}Expected locations:{Colors.RESET}")
            for loc in apk_locations:
                print(f"    {Colors.DIM}{loc}{Colors.RESET}")
            print(f"\n  {Colors.YELLOW}Build the APK in Android Studio first, or copy it to:{Colors.RESET}")
            print(f"    {app_dir / 'autarch_companion' / 'archon.apk'}")
            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
            return

        print(f"  APK: {Colors.GREEN}{apk_path.name}{Colors.RESET} ({apk_path.stat().st_size // 1024}KB)")
        print()

        # List connected devices
        import subprocess
        result = subprocess.run(
            [str(adb), 'devices'],
            capture_output=True, text=True, timeout=10
        )

        devices = []
        for line in result.stdout.strip().split('\n')[1:]:
            parts = line.split('\t')
            if len(parts) == 2 and parts[1].strip() in ('device', 'recovery'):
                devices.append(parts[0].strip())

        if not devices:
            self.print_status("No Android devices connected.", "warning")
            print(f"\n  {Colors.DIM}Connect via USB or enable ADB TCP/IP over WireGuard.{Colors.RESET}")
            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
            return

        print(f"  Connected devices:")
        for i, dev in enumerate(devices, 1):
            print(f"    {Colors.GREEN}[{i}]{Colors.RESET} {dev}")

        print()
        try:
            choice = input(f"  Select device (1-{len(devices)}, 0=cancel): ").strip()
            if choice == "0" or not choice:
                return

            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                target = devices[idx]
                print(f"\n  {Colors.CYAN}Installing Archon on {target}...{Colors.RESET}")

                result = subprocess.run(
                    [str(adb), '-s', target, 'install', '-r', str(apk_path)],
                    capture_output=True, text=True, timeout=120
                )

                if result.returncode == 0:
                    self.print_status(f"Archon installed on {target}", "success")
                else:
                    self.print_status(f"Install failed: {result.stderr.strip()}", "error")
            else:
                self.print_status("Invalid selection", "warning")

        except (ValueError, subprocess.TimeoutExpired) as e:
            self.print_status(f"Error: {e}", "error")

        input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

    def show_mcp_server(self):
        """Display MCP server management interface."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  MCP Server{Colors.RESET}")
            print(f"{Colors.DIM}  Model Context Protocol — expose AUTARCH tools to AI clients{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Check status
            try:
                from core.mcp_server import get_server_status, get_mcp_config_snippet, get_autarch_tools
                status = get_server_status()
                tools = get_autarch_tools()

                if status['running']:
                    print(f"    {Colors.GREEN}SSE Server: RUNNING (PID {status['pid']}){Colors.RESET}")
                else:
                    print(f"    {Colors.YELLOW}SSE Server: STOPPED{Colors.RESET}")

                print(f"    {Colors.CYAN}Available tools: {len(tools)}{Colors.RESET}")
                print()

                # List tools
                print(f"    {Colors.DIM}Tools:{Colors.RESET}")
                for t in tools:
                    print(f"      {Colors.GREEN}-{Colors.RESET} {t['name']}: {Colors.DIM}{t['description'][:60]}{Colors.RESET}")
                print()

            except ImportError:
                print(f"    {Colors.RED}MCP package not installed{Colors.RESET}")
                print(f"    {Colors.DIM}Install with: pip install mcp{Colors.RESET}")
                print()

            mcp_port = self.config.get('web', 'mcp_port', fallback='8081')
            print(f"    {Colors.CYAN}SSE Port: {mcp_port}{Colors.RESET}")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} Start SSE Server (port {mcp_port})")
            print(f"  {Colors.RED}[2]{Colors.RESET} Stop SSE Server")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Show Claude Desktop Config")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Run Stdio Mode (blocks)")
            print(f"  {Colors.CYAN}[5]{Colors.RESET} Configure Port")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    from core.mcp_server import start_sse_server
                    port = self.config.get('web', 'mcp_port', fallback='8081')
                    result = start_sse_server(port=int(port))
                    if result['ok']:
                        self.print_status(f"MCP SSE server started on port {port} (PID {result['pid']})", "success")
                    else:
                        self.print_status(result['error'], "error")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "2":
                    from core.mcp_server import stop_sse_server
                    result = stop_sse_server()
                    if result['ok']:
                        self.print_status("MCP server stopped", "success")
                    else:
                        self.print_status(result['error'], "warning")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "3":
                    from core.mcp_server import get_mcp_config_snippet
                    print()
                    print(f"  {Colors.CYAN}Add this to your Claude Desktop or Claude Code config:{Colors.RESET}")
                    print()
                    print(get_mcp_config_snippet())
                    print()
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "4":
                    print()
                    self.print_status("Starting MCP stdio server (Ctrl+C to stop)...", "info")
                    print(f"  {Colors.DIM}Connect with: claude --mcp autarch{Colors.RESET}")
                    print()
                    try:
                        from core.mcp_server import run_stdio
                        run_stdio()
                    except KeyboardInterrupt:
                        print()
                        self.print_status("MCP stdio server stopped", "info")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "5":
                    print()
                    new_port = input(f"  {Colors.WHITE}MCP SSE Port [{mcp_port}]: {Colors.RESET}").strip()
                    if new_port:
                        try:
                            int(new_port)
                            self.config.set('web', 'mcp_port', new_port)
                            self.config.save()
                            self.print_status(f"MCP port set to {new_port}", "success")
                        except ValueError:
                            self.print_status("Invalid port number", "error")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def show_upnp_settings(self):
        """Display and configure UPnP settings."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  UPnP Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            settings = self.config.get_upnp_settings()
            print(f"    {Colors.CYAN}Enabled:{Colors.RESET}      {Colors.GREEN if settings['enabled'] else Colors.YELLOW}{'Yes' if settings['enabled'] else 'No'}{Colors.RESET}")
            print(f"    {Colors.CYAN}Internal IP:{Colors.RESET}  {settings['internal_ip']}")
            print(f"    {Colors.CYAN}Refresh:{Colors.RESET}      Every {settings['refresh_hours']} hours")
            print(f"    {Colors.CYAN}Mappings:{Colors.RESET}     {settings['mappings'] or '(none)'}")
            print()

            print(f"  {Colors.GREEN}[1]{Colors.RESET} Refresh All Mappings Now")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Configure Internal IP")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Configure Refresh Interval")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Edit Port Mappings")
            print(f"  {Colors.CYAN}[5]{Colors.RESET} Toggle Enabled")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    from core.upnp import get_upnp_manager
                    upnp = get_upnp_manager(self.config)
                    if not upnp.is_available():
                        self.print_status("upnpc not found — install miniupnpc", "error")
                    else:
                        self.print_status("Refreshing UPnP mappings...", "info")
                        results = upnp.refresh_all()
                        for r in results:
                            status = "OK" if r['success'] else "FAIL"
                            color = Colors.GREEN if r['success'] else Colors.RED
                            print(f"    {color}{r['port']}/{r['protocol']}: {status}{Colors.RESET}")
                        self.print_status(f"Refreshed {len(results)} mappings", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "2":
                    new_ip = input(f"  {Colors.WHITE}Internal IP [{settings['internal_ip']}]: {Colors.RESET}").strip()
                    if new_ip:
                        self.config.set('upnp', 'internal_ip', new_ip)
                        self.config.save()
                        self.print_status(f"Internal IP set to {new_ip}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "3":
                    new_hrs = input(f"  {Colors.WHITE}Refresh hours [{settings['refresh_hours']}]: {Colors.RESET}").strip()
                    if new_hrs:
                        try:
                            int(new_hrs)
                            self.config.set('upnp', 'refresh_hours', new_hrs)
                            self.config.save()
                            self.print_status(f"Refresh interval set to {new_hrs} hours", "success")
                        except ValueError:
                            self.print_status("Invalid number", "error")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "4":
                    print(f"\n  {Colors.DIM}Format: port:protocol,port:protocol  (e.g. 443:TCP,51820:UDP,8080:TCP){Colors.RESET}")
                    new_maps = input(f"  {Colors.WHITE}Mappings [{settings['mappings']}]: {Colors.RESET}").strip()
                    if new_maps:
                        self.config.set('upnp', 'mappings', new_maps)
                        self.config.save()
                        self.print_status("Port mappings updated", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "5":
                    new_val = not settings['enabled']
                    self.config.set('upnp', 'enabled', str(new_val).lower())
                    self.config.save()
                    self.print_status(f"UPnP {'enabled' if new_val else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def show_revshell_settings(self):
        """Display and configure reverse shell settings."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Reverse Shell Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            settings = self.config.get_revshell_settings()
            print(f"    {Colors.CYAN}Enabled:{Colors.RESET}     {Colors.GREEN if settings['enabled'] else Colors.YELLOW}{'Yes' if settings['enabled'] else 'No'}{Colors.RESET}")
            print(f"    {Colors.CYAN}Listen Host:{Colors.RESET} {settings['host']}")
            print(f"    {Colors.CYAN}Listen Port:{Colors.RESET} {settings['port']}")
            print(f"    {Colors.CYAN}Auto-start:{Colors.RESET}  {Colors.GREEN if settings['auto_start'] else Colors.DIM}{'Yes' if settings['auto_start'] else 'No'}{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Configure Host")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Configure Port")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Toggle Enabled")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Toggle Auto-start")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    new_host = input(f"  {Colors.WHITE}Listen host [{settings['host']}]: {Colors.RESET}").strip()
                    if new_host:
                        self.config.set('revshell', 'host', new_host)
                        self.config.save()
                        self.print_status(f"Reverse shell host set to {new_host}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "2":
                    new_port = input(f"  {Colors.WHITE}Listen port [{settings['port']}]: {Colors.RESET}").strip()
                    if new_port:
                        try:
                            int(new_port)
                            self.config.set('revshell', 'port', new_port)
                            self.config.save()
                            self.print_status(f"Reverse shell port set to {new_port}", "success")
                        except ValueError:
                            self.print_status("Invalid port number", "error")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "3":
                    new_val = not settings['enabled']
                    self.config.set('revshell', 'enabled', str(new_val).lower())
                    self.config.save()
                    self.print_status(f"Reverse shell {'enabled' if new_val else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "4":
                    new_val = not settings['auto_start']
                    self.config.set('revshell', 'auto_start', str(new_val).lower())
                    self.config.save()
                    self.print_status(f"Auto-start {'enabled' if new_val else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def show_display_settings(self):
        """Display and configure display/output settings."""
        while True:
            clear_screen()
            self._show_banner()

            print(f"{Colors.BOLD}{Colors.WHITE}  Display Settings{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            verbose = self.config.get_bool('autarch', 'verbose', fallback=False)
            quiet = self.config.get_bool('autarch', 'quiet', fallback=False)
            no_banner = self.config.get_bool('autarch', 'no_banner', fallback=False)

            print(f"    {Colors.CYAN}Verbose:{Colors.RESET}    {Colors.GREEN if verbose else Colors.DIM}{'On' if verbose else 'Off'}{Colors.RESET}")
            print(f"    {Colors.CYAN}Quiet:{Colors.RESET}      {Colors.YELLOW if quiet else Colors.DIM}{'On' if quiet else 'Off'}{Colors.RESET}")
            print(f"    {Colors.CYAN}No Banner:{Colors.RESET}  {Colors.YELLOW if no_banner else Colors.DIM}{'On' if no_banner else 'Off'}{Colors.RESET}")
            print()

            print(f"  {Colors.CYAN}[1]{Colors.RESET} Toggle Verbose  {Colors.DIM}- Extra detail in output{Colors.RESET}")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Toggle Quiet    {Colors.DIM}- Minimal output{Colors.RESET}")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Toggle Banner   {Colors.DIM}- Show/hide ASCII banner{Colors.RESET}")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0" or not choice:
                    break
                elif choice == "1":
                    new_val = not verbose
                    self.config.set('autarch', 'verbose', str(new_val).lower())
                    if new_val:
                        self.config.set('autarch', 'quiet', 'false')
                    self.config.save()
                    self.print_status(f"Verbose {'enabled' if new_val else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "2":
                    new_val = not quiet
                    self.config.set('autarch', 'quiet', str(new_val).lower())
                    if new_val:
                        self.config.set('autarch', 'verbose', 'false')
                    self.config.save()
                    self.print_status(f"Quiet mode {'enabled' if new_val else 'disabled'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
                elif choice == "3":
                    new_val = not no_banner
                    self.config.set('autarch', 'no_banner', str(new_val).lower())
                    self.config.save()
                    self.print_status(f"Banner {'hidden' if new_val else 'shown'}", "success")
                    input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break

    def load_config_file(self):
        """Load settings from an alternate config file."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Load Configuration File{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}Current config: {self.config.config_path}{Colors.RESET}")
        print()

        path = input(f"  {Colors.WHITE}Path to config file (or Enter to cancel): {Colors.RESET}").strip()
        if not path:
            return

        config_path = Path(path).expanduser()
        if not config_path.exists():
            self.print_status(f"File not found: {config_path}", "error")
            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
            return

        try:
            from core.config import Config
            new_config = Config(str(config_path))
            self.config = new_config
            self.print_status(f"Loaded config from {config_path}", "success")
        except Exception as e:
            self.print_status(f"Failed to load config: {e}", "error")

        input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")

    def show_user_manual(self):
        """Display the user manual in a pager."""
        import shutil
        import subprocess

        manual_path = self._app_dir / 'user_manual.md'
        if not manual_path.exists():
            self.print_status("User manual not found", "error")
            input(f"\n{Colors.WHITE}  Press Enter...{Colors.RESET}")
            return

        pager = shutil.which('less') or shutil.which('more')
        if pager:
            subprocess.run([pager, str(manual_path)])
        else:
            # No pager — print page by page
            lines = manual_path.read_text().splitlines()
            page_size = 40
            for i in range(0, len(lines), page_size):
                for line in lines[i:i + page_size]:
                    print(line)
                if i + page_size < len(lines):
                    try:
                        resp = input(f"\n{Colors.DIM}  -- Press Enter for next page, q to quit -- {Colors.RESET}")
                        if resp.strip().lower() == 'q':
                            break
                    except (EOFError, KeyboardInterrupt):
                        break

    def list_all_modules(self):
        """List all loaded modules, optionally filtered by category."""
        clear_screen()
        self._show_banner()

        print(f"{Colors.BOLD}{Colors.WHITE}  Loaded Modules{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        if not self.modules:
            print(f"  {Colors.YELLOW}No modules loaded.{Colors.RESET}")
        else:
            # Group by category
            by_cat = {}
            for name, info in sorted(self.modules.items()):
                cat = info.category
                if cat not in by_cat:
                    by_cat[cat] = []
                by_cat[cat].append(info)

            for cat_key in sorted(by_cat.keys()):
                cat_info = CATEGORIES.get(cat_key, CATEGORIES.get('core', {'name': cat_key, 'color': Colors.WHITE}))
                print(f"  {cat_info['color']}{Colors.BOLD}{cat_info['name']}{Colors.RESET}")
                for info in by_cat[cat_key]:
                    print(f"    {Colors.GREEN}-{Colors.RESET} {info.name:20} {Colors.DIM}{info.description}{Colors.RESET}")
                print()

        print(f"  {Colors.DIM}Total: {len(self.modules)} modules{Colors.RESET}")
        print()
        input(f"{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

    def run(self):
        """Main menu loop."""
        self.load_modules()

        while self.running:
            self.display_menu()

            try:
                choice = input(f"{Colors.WHITE}  Select option: {Colors.RESET}").strip()

                if choice == "1":
                    self.display_category_menu("defense")
                elif choice == "2":
                    self.display_category_menu("offense")
                elif choice == "3":
                    self.display_category_menu("counter")
                elif choice == "4":
                    self.display_category_menu("analyze")
                elif choice == "5":
                    self.display_category_menu("osint")
                elif choice == "6":
                    self.display_category_menu("simulate")
                elif choice == "7":
                    self.run_agent_hal()
                elif choice == "8":
                    self.show_web_service()
                elif choice == "9":
                    self.sideload_companion()
                elif choice == "10":
                    self.show_mcp_server()
                elif choice == "11":
                    self.show_user_manual()
                elif choice == "12":
                    self.list_all_modules()
                elif choice == "99":
                    self.show_settings()
                elif choice == "98":
                    self.running = False
                    clear_screen()
                    print(f"\n{Colors.CYAN}Goodbye!{Colors.RESET}\n")
                else:
                    self.print_status("Invalid option", "warning")
                    input(f"\n{Colors.WHITE}  Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                print()
                self.running = False
                clear_screen()
                print(f"\n{Colors.CYAN}Goodbye!{Colors.RESET}\n")
