"""
AUTARCH Setup Module
First-time configuration wizard for LLM settings
Supports GGUF (llama.cpp) and SafeTensors (transformers) models
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import get_config
from core.banner import Colors, clear_screen, display_banner


class SetupWizard:
    """Interactive setup wizard for AUTARCH configuration."""

    def __init__(self):
        self.config = get_config()

    def print_header(self, text: str):
        """Print a formatted section header."""
        print(f"\n{Colors.CYAN}{Colors.BOLD}[*] {text}{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")

    def print_info(self, text: str):
        """Print info message."""
        print(f"{Colors.GREEN}    {text}{Colors.RESET}")

    def print_warning(self, text: str):
        """Print warning message."""
        print(f"{Colors.YELLOW}[!] {text}{Colors.RESET}")

    def print_error(self, text: str):
        """Print error message."""
        print(f"{Colors.RED}[X] {text}{Colors.RESET}")

    def get_input(self, prompt: str, default: str = None) -> str:
        """Get user input with optional default value.

        Args:
            prompt: The prompt to display
            default: Default value if user presses enter

        Returns:
            User input or default value
        """
        if default:
            prompt_text = f"{Colors.WHITE}    {prompt} [{Colors.YELLOW}{default}{Colors.WHITE}]: {Colors.RESET}"
        else:
            prompt_text = f"{Colors.WHITE}    {prompt}: {Colors.RESET}"

        try:
            value = input(prompt_text).strip()
            return value if value else default
        except (EOFError, KeyboardInterrupt):
            print()
            return default

    def get_int_input(self, prompt: str, default: int, min_val: int = None, max_val: int = None) -> int:
        """Get integer input with validation.

        Args:
            prompt: The prompt to display
            default: Default value
            min_val: Minimum allowed value
            max_val: Maximum allowed value

        Returns:
            Validated integer value
        """
        while True:
            value = self.get_input(prompt, str(default))
            try:
                int_val = int(value)
                if min_val is not None and int_val < min_val:
                    self.print_error(f"Value must be at least {min_val}")
                    continue
                if max_val is not None and int_val > max_val:
                    self.print_error(f"Value must be at most {max_val}")
                    continue
                return int_val
            except ValueError:
                self.print_error("Please enter a valid number")

    def get_float_input(self, prompt: str, default: float, min_val: float = None, max_val: float = None) -> float:
        """Get float input with validation."""
        while True:
            value = self.get_input(prompt, str(default))
            try:
                float_val = float(value)
                if min_val is not None and float_val < min_val:
                    self.print_error(f"Value must be at least {min_val}")
                    continue
                if max_val is not None and float_val > max_val:
                    self.print_error(f"Value must be at most {max_val}")
                    continue
                return float_val
            except ValueError:
                self.print_error("Please enter a valid number")

    def validate_model_path(self, path: str) -> tuple:
        """Validate that a model file or directory exists.

        Args:
            path: Path to the model file or directory

        Returns:
            Tuple of (is_valid, model_type) where model_type is 'gguf', 'transformers', or None
        """
        if not path:
            return False, None

        path = Path(os.path.expanduser(path))

        try:
            if not path.exists():
                return False, None
        except (PermissionError, OSError):
            return False, None

        # Check for GGUF file
        if path.is_file():
            if path.suffix.lower() == '.gguf':
                return True, 'gguf'
            # Check magic bytes for GGUF without extension
            try:
                with open(path, 'rb') as f:
                    magic = f.read(4)
                    if magic == b'GGUF':
                        return True, 'gguf'
            except Exception:
                pass
            # Could still be a valid file for llama.cpp
            return True, 'gguf'

        # Check for safetensors/transformers directory
        if path.is_dir():
            # Check for safetensors files
            safetensor_files = list(path.glob("*.safetensors"))
            index_file = path / "model.safetensors.index.json"
            config_file = path / "config.json"

            if safetensor_files or index_file.exists():
                return True, 'transformers'

            # Check for pytorch bin files (also transformers format)
            bin_files = list(path.glob("*.bin"))
            if config_file.exists() and (bin_files or (path / "pytorch_model.bin").exists()):
                return True, 'transformers'

            # Directory exists but no recognized model format
            if config_file.exists():
                return True, 'transformers'

        return False, None

    def validate_model_path_legacy(self, path: str) -> bool:
        """Legacy validation - just checks if file exists.

        Args:
            path: Path to the model file

        Returns:
            True if valid, False otherwise
        """
        if not path:
            return False
        path = os.path.expanduser(path)
        return os.path.isfile(path) or os.path.isdir(path)

    def _is_huggingface_id(self, path: str) -> bool:
        """Check if the path looks like a HuggingFace model ID.

        HuggingFace model IDs are in format 'org/model-name' or 'username/model-name'.

        Args:
            path: The path/ID to check

        Returns:
            True if it looks like a HuggingFace model ID
        """
        if not path:
            return False
        # Must contain exactly one '/' and not start with '/'
        # Also should not contain path separators like '\' or multiple '/'
        if path.startswith('/') or path.startswith('\\'):
            return False
        parts = path.split('/')
        if len(parts) == 2 and all(p and not p.startswith('.') for p in parts):
            # Looks like org/model-name format
            return True
        return False

    def resolve_model_path(self, path: str) -> str:
        """Resolve a model path, trying multiple variations.

        Args:
            path: User-provided path (may be relative or have variations)

        Returns:
            Resolved absolute path if found, None otherwise
        """
        from core.paths import get_app_dir
        framework_dir = get_app_dir()

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

    def skip_setup(self) -> bool:
        """Skip setup and mark as complete without LLM configuration.

        Returns:
            True always (setup skipped successfully)
        """
        clear_screen()
        display_banner()

        self.print_header("Setup Skipped")
        print(f"\n{Colors.WHITE}    AUTARCH will run without LLM features.{Colors.RESET}")
        print(f"{Colors.DIM}    The following modules will still work:{Colors.RESET}")
        print(f"{Colors.GREEN}      - defender    (Defense){Colors.RESET}")
        print(f"{Colors.GREEN}      - counter     (Counter){Colors.RESET}")
        print(f"{Colors.GREEN}      - analyze     (Analyze){Colors.RESET}")
        print(f"{Colors.GREEN}      - recon       (OSINT){Colors.RESET}")
        print(f"{Colors.GREEN}      - adultscan   (OSINT){Colors.RESET}")
        print(f"{Colors.GREEN}      - simulate    (Simulate){Colors.RESET}")
        print(f"{Colors.GREEN}      - msf         (Offense){Colors.RESET}")
        print()
        print(f"{Colors.YELLOW}    LLM-dependent modules (chat, agent) will not work{Colors.RESET}")
        print(f"{Colors.YELLOW}    until you configure a model with --setup{Colors.RESET}")
        print()

        self.config.mark_setup_complete()
        self.print_info(f"Configuration saved to: {self.config.config_path}")

        print(f"\n{Colors.WHITE}    Press Enter to continue...{Colors.RESET}")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass

        return True

    def run(self, allow_skip: bool = True) -> bool:
        """Run the setup wizard.

        Args:
            allow_skip: Whether to show the skip option

        Returns:
            True if setup completed successfully, False if cancelled
        """
        clear_screen()
        display_banner()

        self.print_header("AUTARCH First-Time Setup")
        print(f"\n{Colors.WHITE}    Welcome to AUTARCH! This wizard will help you configure")
        print(f"    the LLM settings for your system.{Colors.RESET}\n")

        # Offer skip option
        if allow_skip:
            print(f"{Colors.DIM}    Many modules work without an LLM (OSINT, forensics, etc.){Colors.RESET}")
            print()
            print(f"    {Colors.GREEN}[1]{Colors.RESET} Configure LLM (for chat & agent features)")
            print(f"    {Colors.YELLOW}[2]{Colors.RESET} Skip setup (use without LLM)")
            print()

            choice = self.get_input("Select option", "1")
            if choice == "2":
                return self.skip_setup()

        # Model Path Configuration
        self.print_header("Model Configuration")
        self.print_info("AUTARCH supports two model formats:")
        print(f"    {Colors.CYAN}GGUF{Colors.RESET} - Single file models for llama.cpp (recommended for CPU)")
        print(f"    {Colors.CYAN}SafeTensors{Colors.RESET} - HuggingFace models for transformers (GPU optimized)")
        print()
        self.print_info("Enter a local path OR a HuggingFace model ID.")
        self.print_info("Examples:")
        print(f"    {Colors.DIM}GGUF: /home/user/models/llama-7b.gguf{Colors.RESET}")
        print(f"    {Colors.DIM}SafeTensors: /home/user/models/Lily-Cybersecurity-7B{Colors.RESET}")
        print(f"    {Colors.DIM}HuggingFace ID: segolilylabs/Lily-Cybersecurity-7B-v0.2{Colors.RESET}")

        model_type = None
        while True:
            # Get current configured path for default
            current_gguf = self.config.get('llama', 'model_path', '')
            current_transformers = self.config.get('transformers', 'model_path', '')
            default_path = current_gguf or current_transformers or ''

            model_path = self.get_input("Model path", default_path if default_path else None)
            if model_path:
                # Strip quotes that users might accidentally include
                model_path = model_path.strip().strip('"').strip("'")
                model_path = os.path.expanduser(model_path)

                # Try to resolve the path (handles relative paths, /dh_framework/... etc.)
                resolved_path = self.resolve_model_path(model_path)
                if resolved_path:
                    model_path = resolved_path

                is_valid, detected_type = self.validate_model_path(model_path)
                if is_valid and detected_type:
                    model_type = detected_type
                    if model_type == 'gguf':
                        self.config.set('llama', 'model_path', model_path)
                        self.config.set('autarch', 'llm_backend', 'local')
                        self.print_info(f"GGUF model found: {os.path.basename(model_path)}")
                    else:  # transformers
                        self.config.set('transformers', 'model_path', model_path)
                        self.config.set('autarch', 'llm_backend', 'transformers')
                        self.print_info(f"SafeTensors model found: {os.path.basename(model_path)}")
                    break
                elif self._is_huggingface_id(model_path):
                    # Looks like a HuggingFace model ID (e.g., 'org/model-name')
                    model_type = 'transformers'
                    self.config.set('transformers', 'model_path', model_path)
                    self.config.set('autarch', 'llm_backend', 'transformers')
                    self.print_info(f"HuggingFace model ID: {model_path}")
                    self.print_info("Model will be downloaded/loaded from HuggingFace cache")
                    break
                else:
                    self.print_error("Model not found or unrecognized format.")
                    self.print_info("For GGUF: provide path to .gguf file")
                    self.print_info("For SafeTensors: provide path to model directory")
                    self.print_info("For HuggingFace: use format 'org/model-name'")
                    retry = self.get_input("Try again? (y/n)", "y")
                    if retry.lower() != 'y':
                        self.print_warning("Setup cancelled - no model configured")
                        return False
            else:
                self.print_warning("No model path provided")
                skip = self.get_input("Continue without model? (y/n)", "n")
                if skip.lower() == 'y':
                    break
                continue

        # Backend-specific configuration
        if model_type == 'gguf':
            # GGUF/llama.cpp specific settings
            self.print_header("Context Settings (llama.cpp)")
            self.print_info("Configure the context window and threading.")

            n_ctx = self.get_int_input(
                "Context size (tokens)",
                self.config.get_int('llama', 'n_ctx', 4096),
                min_val=512,
                max_val=131072
            )
            self.config.set('llama', 'n_ctx', n_ctx)

            n_threads = self.get_int_input(
                "Number of CPU threads",
                self.config.get_int('llama', 'n_threads', 4),
                min_val=1,
                max_val=256
            )
            self.config.set('llama', 'n_threads', n_threads)

            # GPU Configuration
            self.print_header("GPU Configuration")
            self.print_info("Set the number of layers to offload to GPU.")
            self.print_info("Set to 0 for CPU-only, or higher for GPU acceleration.")

            n_gpu_layers = self.get_int_input(
                "GPU layers (0 for CPU only)",
                self.config.get_int('llama', 'n_gpu_layers', 0),
                min_val=0
            )
            self.config.set('llama', 'n_gpu_layers', n_gpu_layers)

            # Generation Settings
            self.print_header("Generation Settings")
            self.print_info("Configure text generation parameters.")

            temperature = self.get_float_input(
                "Temperature (creativity)",
                self.config.get_float('llama', 'temperature', 0.7),
                min_val=0.0,
                max_val=2.0
            )
            self.config.set('llama', 'temperature', temperature)

            top_p = self.get_float_input(
                "Top P (nucleus sampling)",
                self.config.get_float('llama', 'top_p', 0.9),
                min_val=0.0,
                max_val=1.0
            )
            self.config.set('llama', 'top_p', top_p)

            top_k = self.get_int_input(
                "Top K",
                self.config.get_int('llama', 'top_k', 40),
                min_val=0
            )
            self.config.set('llama', 'top_k', top_k)

            repeat_penalty = self.get_float_input(
                "Repeat penalty",
                self.config.get_float('llama', 'repeat_penalty', 1.1),
                min_val=0.0,
                max_val=2.0
            )
            self.config.set('llama', 'repeat_penalty', repeat_penalty)

            max_tokens = self.get_int_input(
                "Max tokens per response",
                self.config.get_int('llama', 'max_tokens', 2048),
                min_val=1,
                max_val=32768
            )
            self.config.set('llama', 'max_tokens', max_tokens)

        elif model_type == 'transformers':
            # Transformers/SafeTensors specific settings
            self.print_header("Device Configuration (transformers)")
            self.print_info("Configure hardware settings for model loading.")

            print(f"    {Colors.DIM}Device options: auto, cuda, cpu, mps{Colors.RESET}")
            device = self.get_input(
                "Device",
                self.config.get('transformers', 'device', 'auto')
            )
            self.config.set('transformers', 'device', device)

            # Quantization options
            self.print_header("Quantization (Memory Optimization)")
            self.print_info("Quantization reduces memory usage at the cost of some quality.")
            print(f"    {Colors.DIM}Requires bitsandbytes package for 8-bit/4-bit{Colors.RESET}")

            print(f"\n    {Colors.GREEN}[1]{Colors.RESET} No quantization (full precision)")
            print(f"    {Colors.GREEN}[2]{Colors.RESET} 8-bit quantization (half memory)")
            print(f"    {Colors.GREEN}[3]{Colors.RESET} 4-bit quantization (quarter memory)")

            quant_choice = self.get_input("Quantization option", "1")
            if quant_choice == "2":
                self.config.set('transformers', 'load_in_8bit', 'true')
                self.config.set('transformers', 'load_in_4bit', 'false')
            elif quant_choice == "3":
                self.config.set('transformers', 'load_in_8bit', 'false')
                self.config.set('transformers', 'load_in_4bit', 'true')
            else:
                self.config.set('transformers', 'load_in_8bit', 'false')
                self.config.set('transformers', 'load_in_4bit', 'false')

            # Generation Settings
            self.print_header("Generation Settings")
            self.print_info("Configure text generation parameters.")

            temperature = self.get_float_input(
                "Temperature (creativity)",
                self.config.get_float('transformers', 'temperature', 0.7),
                min_val=0.0,
                max_val=2.0
            )
            self.config.set('transformers', 'temperature', temperature)

            top_p = self.get_float_input(
                "Top P (nucleus sampling)",
                self.config.get_float('transformers', 'top_p', 0.9),
                min_val=0.0,
                max_val=1.0
            )
            self.config.set('transformers', 'top_p', top_p)

            top_k = self.get_int_input(
                "Top K",
                self.config.get_int('transformers', 'top_k', 40),
                min_val=0
            )
            self.config.set('transformers', 'top_k', top_k)

            repeat_penalty = self.get_float_input(
                "Repetition penalty",
                self.config.get_float('transformers', 'repetition_penalty', 1.1),
                min_val=0.0,
                max_val=2.0
            )
            self.config.set('transformers', 'repetition_penalty', repeat_penalty)

            max_tokens = self.get_int_input(
                "Max tokens per response",
                self.config.get_int('transformers', 'max_tokens', 2048),
                min_val=1,
                max_val=32768
            )
            self.config.set('transformers', 'max_tokens', max_tokens)

        # Save configuration
        self.print_header("Saving Configuration")
        self.config.mark_setup_complete()
        self.print_info(f"Configuration saved to: {self.config.config_path}")

        # Summary
        self.print_header("Setup Complete")
        print(f"\n{Colors.GREEN}    AUTARCH has been configured with the following settings:{Colors.RESET}\n")

        if model_type == 'gguf':
            print(f"    {Colors.YELLOW}Backend: llama.cpp (GGUF){Colors.RESET}\n")
            settings = self.config.get_llama_settings()
        elif model_type == 'transformers':
            print(f"    {Colors.YELLOW}Backend: transformers (SafeTensors){Colors.RESET}\n")
            settings = self.config.get_transformers_settings()
        else:
            print(f"    {Colors.YELLOW}No model configured{Colors.RESET}\n")
            settings = {}

        for key, value in settings.items():
            if key == 'model_path' and value:
                value = os.path.basename(value)
            print(f"    {Colors.CYAN}{key:20}{Colors.RESET}: {value}")

        print(f"\n{Colors.WHITE}    Press Enter to continue to the main menu...{Colors.RESET}")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass

        return True


def run():
    """Module entry point."""
    wizard = SetupWizard()
    return wizard.run()


if __name__ == "__main__":
    run()
