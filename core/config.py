"""
AUTARCH Configuration Handler
Manages the autarch_settings.conf file for llama.cpp settings
"""

import os
import configparser
from pathlib import Path


class Config:
    """Configuration manager for AUTARCH settings."""

    DEFAULT_CONFIG = {
        'llama': {
            'model_path': '',
            'n_ctx': '4096',
            'n_threads': '4',
            'n_gpu_layers': '0',
            'gpu_backend': 'cpu',
            'temperature': '0.7',
            'top_p': '0.9',
            'top_k': '40',
            'repeat_penalty': '1.1',
            'max_tokens': '2048',
            'seed': '-1',
        },
        'autarch': {
            'first_run': 'true',
            'modules_path': 'modules',
            'verbose': 'false',
            'quiet': 'false',
            'no_banner': 'false',
            'llm_backend': 'local',
        },
        'claude': {
            'api_key': '',
            'model': 'claude-sonnet-4-20250514',
            'max_tokens': '4096',
            'temperature': '0.7',
        },
        'osint': {
            'max_threads': '8',
            'timeout': '8',
            'include_nsfw': 'false',
        },
        'pentest': {
            'max_pipeline_steps': '50',
            'output_chunk_size': '2000',
            'auto_execute': 'false',
            'save_raw_output': 'true',
        },
        'transformers': {
            'model_path': '',
            'device': 'auto',
            'torch_dtype': 'auto',
            'load_in_8bit': 'false',
            'load_in_4bit': 'false',
            'trust_remote_code': 'false',
            'max_tokens': '2048',
            'temperature': '0.7',
            'top_p': '0.9',
            'top_k': '40',
            'repetition_penalty': '1.1',
        },
        'rsf': {
            'install_path': '',
            'enabled': 'true',
            'default_target': '',
            'default_port': '80',
            'execution_timeout': '120',
        },
        'upnp': {
            'enabled': 'true',
            'internal_ip': '10.0.0.26',
            'refresh_hours': '12',
            'mappings': '443:TCP,51820:UDP,8181:TCP',
        },
        'web': {
            'host': '0.0.0.0',
            'port': '8181',
            'secret_key': '',
            'mcp_port': '8081',
        },
        'revshell': {
            'enabled': 'true',
            'host': '0.0.0.0',
            'port': '17322',
            'auto_start': 'false',
        },
        'slm': {
            'enabled': 'true',
            'backend': 'local',
            'model_path': '',
            'n_ctx': '512',
            'n_gpu_layers': '-1',
            'n_threads': '2',
        },
        'sam': {
            'enabled': 'true',
            'backend': 'local',
            'model_path': '',
            'n_ctx': '2048',
            'n_gpu_layers': '-1',
            'n_threads': '4',
        },
        'lam': {
            'enabled': 'true',
            'backend': 'local',
            'model_path': '',
            'n_ctx': '4096',
            'n_gpu_layers': '-1',
            'n_threads': '4',
        },
        'autonomy': {
            'enabled': 'false',
            'monitor_interval': '3',
            'rule_eval_interval': '5',
            'max_concurrent_agents': '3',
            'threat_threshold_auto_respond': '40',
            'log_max_entries': '1000',
        },
    }

    def __init__(self, config_path: str = None):
        """Initialize the configuration manager.

        Args:
            config_path: Path to the configuration file. Defaults to autarch_settings.conf
                        in the framework directory.
        """
        if config_path is None:
            from core.paths import get_config_path
            self.config_path = get_config_path()
        else:
            self.config_path = Path(config_path)

        self.config = configparser.ConfigParser()
        self._load_or_create()

    def _load_or_create(self):
        """Load existing config or create with defaults."""
        if self.config_path.exists():
            self.config.read(self.config_path)
            self._apply_missing_defaults()
        else:
            self._create_default_config()

    def _apply_missing_defaults(self):
        """Add any missing sections/keys from DEFAULT_CONFIG to the loaded config."""
        changed = False
        for section, options in self.DEFAULT_CONFIG.items():
            if section not in self.config:
                self.config[section] = options
                changed = True
            else:
                for key, value in options.items():
                    if key not in self.config[section]:
                        self.config[section][key] = value
                        changed = True
        if changed:
            self.save()

    def _create_default_config(self):
        """Create a default configuration file."""
        for section, options in self.DEFAULT_CONFIG.items():
            self.config[section] = options
        self.save()

    def save(self):
        """Save the current configuration to file."""
        with open(self.config_path, 'w') as f:
            self.config.write(f)

    def get(self, section: str, key: str, fallback=None):
        """Get a configuration value.

        Args:
            section: Configuration section name
            key: Configuration key name
            fallback: Default value if key doesn't exist

        Returns:
            The configuration value or fallback
        """
        value = self.config.get(section, key, fallback=fallback)
        # Strip quotes from values (handles paths with spaces that were quoted)
        if value and isinstance(value, str):
            value = value.strip().strip('"').strip("'")
        return value

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        """Get a configuration value as integer."""
        return self.config.getint(section, key, fallback=fallback)

    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        """Get a configuration value as float."""
        return self.config.getfloat(section, key, fallback=fallback)

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        """Get a configuration value as boolean."""
        return self.config.getboolean(section, key, fallback=fallback)

    def set(self, section: str, key: str, value):
        """Set a configuration value.

        Args:
            section: Configuration section name
            key: Configuration key name
            value: Value to set
        """
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = str(value)

    def is_first_run(self) -> bool:
        """Check if this is the first run of AUTARCH."""
        return self.get_bool('autarch', 'first_run', fallback=True)

    def mark_setup_complete(self):
        """Mark the first-time setup as complete."""
        self.set('autarch', 'first_run', 'false')
        self.save()

    def get_llama_settings(self) -> dict:
        """Get all llama.cpp settings as a dictionary.

        Returns:
            Dictionary with llama.cpp settings properly typed
        """
        return {
            'model_path': self.get('llama', 'model_path', ''),
            'n_ctx': self.get_int('llama', 'n_ctx', 4096),
            'n_threads': self.get_int('llama', 'n_threads', 4),
            'n_gpu_layers': self.get_int('llama', 'n_gpu_layers', 0),
            'gpu_backend': self.get('llama', 'gpu_backend', 'cpu'),
            'temperature': self.get_float('llama', 'temperature', 0.7),
            'top_p': self.get_float('llama', 'top_p', 0.9),
            'top_k': self.get_int('llama', 'top_k', 40),
            'repeat_penalty': self.get_float('llama', 'repeat_penalty', 1.1),
            'max_tokens': self.get_int('llama', 'max_tokens', 2048),
            'seed': self.get_int('llama', 'seed', -1),
        }

    def get_osint_settings(self) -> dict:
        """Get all OSINT settings as a dictionary.

        Returns:
            Dictionary with OSINT settings properly typed
        """
        return {
            'max_threads': self.get_int('osint', 'max_threads', 8),
            'timeout': self.get_int('osint', 'timeout', 8),
            'include_nsfw': self.get_bool('osint', 'include_nsfw', False),
        }

    def get_pentest_settings(self) -> dict:
        """Get all pentest pipeline settings as a dictionary.

        Returns:
            Dictionary with pentest settings properly typed
        """
        return {
            'max_pipeline_steps': self.get_int('pentest', 'max_pipeline_steps', 50),
            'output_chunk_size': self.get_int('pentest', 'output_chunk_size', 2000),
            'auto_execute': self.get_bool('pentest', 'auto_execute', False),
            'save_raw_output': self.get_bool('pentest', 'save_raw_output', True),
        }

    def get_claude_settings(self) -> dict:
        """Get all Claude API settings as a dictionary.

        Returns:
            Dictionary with Claude API settings properly typed
        """
        return {
            'api_key': self.get('claude', 'api_key', ''),
            'model': self.get('claude', 'model', 'claude-sonnet-4-20250514'),
            'max_tokens': self.get_int('claude', 'max_tokens', 4096),
            'temperature': self.get_float('claude', 'temperature', 0.7),
        }

    def get_transformers_settings(self) -> dict:
        """Get all transformers/safetensors settings as a dictionary.

        Returns:
            Dictionary with transformers settings properly typed
        """
        return {
            'model_path': self.get('transformers', 'model_path', ''),
            'device': self.get('transformers', 'device', 'auto'),
            'torch_dtype': self.get('transformers', 'torch_dtype', 'auto'),
            'load_in_8bit': self.get_bool('transformers', 'load_in_8bit', False),
            'load_in_4bit': self.get_bool('transformers', 'load_in_4bit', False),
            'llm_int8_enable_fp32_cpu_offload': self.get_bool('transformers', 'llm_int8_enable_fp32_cpu_offload', False),
            'device_map': self.get('transformers', 'device_map', 'auto'),
            'trust_remote_code': self.get_bool('transformers', 'trust_remote_code', False),
            'max_tokens': self.get_int('transformers', 'max_tokens', 2048),
            'temperature': self.get_float('transformers', 'temperature', 0.7),
            'top_p': self.get_float('transformers', 'top_p', 0.9),
            'top_k': self.get_int('transformers', 'top_k', 40),
            'repetition_penalty': self.get_float('transformers', 'repetition_penalty', 1.1),
        }

    def get_huggingface_settings(self) -> dict:
        """Get all HuggingFace Inference API settings as a dictionary."""
        return {
            'api_key': self.get('huggingface', 'api_key', ''),
            'model': self.get('huggingface', 'model', 'mistralai/Mistral-7B-Instruct-v0.3'),
            'endpoint': self.get('huggingface', 'endpoint', ''),
            'provider': self.get('huggingface', 'provider', 'auto'),
            'max_tokens': self.get_int('huggingface', 'max_tokens', 1024),
            'temperature': self.get_float('huggingface', 'temperature', 0.7),
            'top_p': self.get_float('huggingface', 'top_p', 0.9),
            'top_k': self.get_int('huggingface', 'top_k', 40),
            'repetition_penalty': self.get_float('huggingface', 'repetition_penalty', 1.1),
            'do_sample': self.get_bool('huggingface', 'do_sample', True),
            'seed': self.get_int('huggingface', 'seed', -1),
            'stop_sequences': self.get('huggingface', 'stop_sequences', ''),
        }

    def get_openai_settings(self) -> dict:
        """Get all OpenAI API settings as a dictionary."""
        return {
            'api_key': self.get('openai', 'api_key', ''),
            'base_url': self.get('openai', 'base_url', 'https://api.openai.com/v1'),
            'model': self.get('openai', 'model', 'gpt-4o'),
            'max_tokens': self.get_int('openai', 'max_tokens', 4096),
            'temperature': self.get_float('openai', 'temperature', 0.7),
            'top_p': self.get_float('openai', 'top_p', 1.0),
            'frequency_penalty': self.get_float('openai', 'frequency_penalty', 0.0),
            'presence_penalty': self.get_float('openai', 'presence_penalty', 0.0),
        }

    def get_rsf_settings(self) -> dict:
        """Get all RouterSploit settings as a dictionary.

        Returns:
            Dictionary with RSF settings properly typed
        """
        return {
            'install_path': self.get('rsf', 'install_path', ''),
            'enabled': self.get_bool('rsf', 'enabled', True),
            'default_target': self.get('rsf', 'default_target', ''),
            'default_port': self.get('rsf', 'default_port', '80'),
            'execution_timeout': self.get_int('rsf', 'execution_timeout', 120),
        }

    def get_upnp_settings(self) -> dict:
        """Get all UPnP settings as a dictionary."""
        return {
            'enabled': self.get_bool('upnp', 'enabled', True),
            'internal_ip': self.get('upnp', 'internal_ip', '10.0.0.26'),
            'refresh_hours': self.get_int('upnp', 'refresh_hours', 12),
            'mappings': self.get('upnp', 'mappings', ''),
        }

    def get_revshell_settings(self) -> dict:
        """Get all reverse shell settings as a dictionary."""
        return {
            'enabled': self.get_bool('revshell', 'enabled', True),
            'host': self.get('revshell', 'host', '0.0.0.0'),
            'port': self.get_int('revshell', 'port', 17322),
            'auto_start': self.get_bool('revshell', 'auto_start', False),
        }

    def get_tier_settings(self, tier: str) -> dict:
        """Get settings for a model tier (slm, sam, lam)."""
        return {
            'enabled': self.get_bool(tier, 'enabled', True),
            'backend': self.get(tier, 'backend', 'local'),
            'model_path': self.get(tier, 'model_path', ''),
            'n_ctx': self.get_int(tier, 'n_ctx', 2048),
            'n_gpu_layers': self.get_int(tier, 'n_gpu_layers', -1),
            'n_threads': self.get_int(tier, 'n_threads', 4),
        }

    def get_slm_settings(self) -> dict:
        """Get Small Language Model tier settings."""
        return self.get_tier_settings('slm')

    def get_sam_settings(self) -> dict:
        """Get Small Action Model tier settings."""
        return self.get_tier_settings('sam')

    def get_lam_settings(self) -> dict:
        """Get Large Action Model tier settings."""
        return self.get_tier_settings('lam')

    def get_autonomy_settings(self) -> dict:
        """Get autonomy daemon settings."""
        return {
            'enabled': self.get_bool('autonomy', 'enabled', False),
            'monitor_interval': self.get_int('autonomy', 'monitor_interval', 3),
            'rule_eval_interval': self.get_int('autonomy', 'rule_eval_interval', 5),
            'max_concurrent_agents': self.get_int('autonomy', 'max_concurrent_agents', 3),
            'threat_threshold_auto_respond': self.get_int('autonomy', 'threat_threshold_auto_respond', 40),
            'log_max_entries': self.get_int('autonomy', 'log_max_entries', 1000),
        }

    @staticmethod
    def get_templates_dir() -> Path:
        """Get the path to the configuration templates directory."""
        from core.paths import get_templates_dir
        return get_templates_dir()

    @staticmethod
    def get_custom_configs_dir() -> Path:
        """Get the path to the custom user configurations directory."""
        from core.paths import get_custom_configs_dir
        return get_custom_configs_dir()

    def list_hardware_templates(self) -> list:
        """List available hardware configuration templates.

        Returns:
            List of tuples: (template_id, display_name, description, filename)
        """
        templates = [
            ('nvidia_4070_mobile', 'NVIDIA RTX 4070 Mobile', '8GB VRAM, CUDA, optimal for 7B-13B models', 'nvidia_4070_mobile.conf'),
            ('amd_rx6700xt', 'AMD Radeon RX 6700 XT', '12GB VRAM, ROCm, optimal for 7B-13B models', 'amd_rx6700xt.conf'),
            ('orangepi5plus_cpu', 'Orange Pi 5 Plus (CPU)', 'RK3588 ARM64, CPU-only, for quantized models', 'orangepi5plus_cpu.conf'),
            ('orangepi5plus_mali', 'Orange Pi 5 Plus (Mali GPU)', 'EXPERIMENTAL - Mali-G610 OpenCL acceleration', 'orangepi5plus_mali.conf'),
        ]
        return templates

    def list_custom_configs(self) -> list:
        """List user-saved custom configurations.

        Returns:
            List of tuples: (name, filepath)
        """
        custom_dir = self.get_custom_configs_dir()
        configs = []
        for conf_file in custom_dir.glob('*.conf'):
            name = conf_file.stem.replace('_', ' ').title()
            configs.append((name, conf_file))
        return configs

    def load_template(self, template_id: str) -> bool:
        """Load a hardware template into the current configuration.

        Args:
            template_id: The template identifier (e.g., 'nvidia_4070_mobile')

        Returns:
            True if loaded successfully, False otherwise
        """
        templates = {t[0]: t[3] for t in self.list_hardware_templates()}
        if template_id not in templates:
            return False

        template_path = self.get_templates_dir() / templates[template_id]
        if not template_path.exists():
            return False

        return self._load_llm_settings_from_file(template_path)

    def load_custom_config(self, filepath: Path) -> bool:
        """Load a custom configuration file.

        Args:
            filepath: Path to the custom configuration file

        Returns:
            True if loaded successfully, False otherwise
        """
        if not filepath.exists():
            return False
        return self._load_llm_settings_from_file(filepath)

    def _load_llm_settings_from_file(self, filepath: Path) -> bool:
        """Load LLM settings (llama and transformers sections) from a file.

        Preserves model_path from current config (doesn't overwrite).

        Args:
            filepath: Path to the configuration file

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            template_config = configparser.ConfigParser()
            template_config.read(filepath)

            # Preserve current model paths
            current_llama_path = self.get('llama', 'model_path', '')
            current_transformers_path = self.get('transformers', 'model_path', '')

            # Load llama section
            if 'llama' in template_config:
                for key, value in template_config['llama'].items():
                    if key != 'model_path':  # Preserve current model path
                        self.set('llama', key, value)
                # Restore model path
                if current_llama_path:
                    self.set('llama', 'model_path', current_llama_path)

            # Load transformers section
            if 'transformers' in template_config:
                for key, value in template_config['transformers'].items():
                    if key != 'model_path':  # Preserve current model path
                        self.set('transformers', key, value)
                # Restore model path
                if current_transformers_path:
                    self.set('transformers', 'model_path', current_transformers_path)

            self.save()
            return True
        except Exception:
            return False

    def save_custom_config(self, name: str) -> Path:
        """Save current LLM settings to a custom configuration file.

        Args:
            name: Name for the custom configuration (will be sanitized)

        Returns:
            Path to the saved configuration file
        """
        # Sanitize name for filename
        safe_name = ''.join(c if c.isalnum() or c in '-_' else '_' for c in name.lower())
        safe_name = safe_name.strip('_')
        if not safe_name:
            safe_name = 'custom_config'

        custom_dir = self.get_custom_configs_dir()
        filepath = custom_dir / f'{safe_name}.conf'

        # Create config with just LLM settings
        custom_config = configparser.ConfigParser()

        # Save llama settings
        custom_config['llama'] = {}
        for key in self.DEFAULT_CONFIG['llama'].keys():
            value = self.get('llama', key, '')
            if value:
                custom_config['llama'][key] = str(value)

        # Save transformers settings
        custom_config['transformers'] = {}
        for key in self.DEFAULT_CONFIG['transformers'].keys():
            value = self.get('transformers', key, '')
            if value:
                custom_config['transformers'][key] = str(value)

        # Add header comment
        with open(filepath, 'w') as f:
            f.write(f'# AUTARCH Custom LLM Configuration\n')
            f.write(f'# Name: {name}\n')
            f.write(f'# Saved: {Path(self.config_path).name}\n')
            f.write('#\n\n')
            custom_config.write(f)

        return filepath

    def delete_custom_config(self, filepath: Path) -> bool:
        """Delete a custom configuration file.

        Args:
            filepath: Path to the custom configuration file

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            if filepath.exists() and filepath.parent == self.get_custom_configs_dir():
                filepath.unlink()
                return True
        except Exception:
            pass
        return False


# Global config instance
_config = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = Config()
    return _config
