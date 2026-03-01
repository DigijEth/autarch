"""
AUTARCH LLM Integration Module
Wrapper for llama-cpp-python to interface with llama.cpp models
"""

import logging
import sys
from typing import Optional, Generator, List, Dict, Any
from pathlib import Path

from .config import get_config
from .banner import Colors

_llm_logger = logging.getLogger('autarch.llm')


class LLMError(Exception):
    """Exception raised for LLM-related errors."""
    pass


class LLM:
    """Wrapper class for llama-cpp-python integration."""

    def __init__(self, config=None):
        """Initialize the LLM wrapper.

        Args:
            config: Optional Config instance. Uses global config if not provided.
        """
        self.config = config or get_config()
        self._model = None
        self._model_path = None
        self._metadata_dir = None
        self._special_tokens = {}
        self._chat_format = None
        self._chat_history: List[Dict[str, str]] = []

    @property
    def is_loaded(self) -> bool:
        """Check if a model is currently loaded."""
        return self._model is not None

    @property
    def model_name(self) -> str:
        """Get the name of the currently loaded model."""
        if self._model_path:
            return Path(self._model_path).name
        return "No model loaded"

    def load_model(self, model_path: str = None, verbose: bool = False) -> bool:
        """Load a GGUF model.

        Args:
            model_path: Path to the model file. Uses config if not provided.
            verbose: Whether to show loading progress.

        Returns:
            True if model loaded successfully.

        Raises:
            LLMError: If model loading fails.
        """
        try:
            from llama_cpp import Llama
        except ImportError as e:
            raise LLMError(f"llama-cpp-python not installed: {e}")

        # Get model path from config if not provided
        if model_path is None:
            model_path = self.config.get('llama', 'model_path', '')

        if not model_path:
            raise LLMError("No model path configured. Run setup first.")

        model_path = Path(model_path).expanduser()
        if not model_path.exists():
            raise LLMError(f"Model file not found: {model_path}")

        # Get settings from config
        settings = self.config.get_llama_settings()

        if verbose:
            print(f"{Colors.CYAN}[*] Loading model: {model_path.name}{Colors.RESET}")
            print(f"{Colors.DIM}    Context: {settings['n_ctx']} | Threads: {settings['n_threads']} | GPU Layers: {settings['n_gpu_layers']}{Colors.RESET}")

        # Look for tokenizer/config files in the model directory or parent
        model_dir = model_path.parent
        chat_format, metadata_dir, special_tokens = self._detect_chat_format(model_dir, verbose)

        # If not found in same dir, try parent directory
        if not metadata_dir and model_dir.name.lower() in ('gguf', 'guff', 'models'):
            chat_format, metadata_dir, special_tokens = self._detect_chat_format(model_dir.parent, verbose)

        try:
            llama_kwargs = {
                'model_path': str(model_path),
                'n_ctx': settings['n_ctx'],
                'n_threads': settings['n_threads'],
                'n_gpu_layers': settings['n_gpu_layers'],
                'seed': settings['seed'] if settings['seed'] != -1 else None,
                'verbose': verbose,
            }

            # Add chat format if detected
            if chat_format:
                llama_kwargs['chat_format'] = chat_format
                if verbose:
                    print(f"{Colors.DIM}    Chat format: {chat_format}{Colors.RESET}")

            self._model = Llama(**llama_kwargs)
            self._model_path = str(model_path)
            self._metadata_dir = metadata_dir
            self._special_tokens = special_tokens
            self._chat_format = chat_format

            if verbose:
                print(f"{Colors.GREEN}[+] Model loaded successfully{Colors.RESET}")

            return True

        except Exception as e:
            self._model = None
            self._model_path = None
            raise LLMError(f"Failed to load model: {e}")

    def _detect_chat_format(self, directory: Path, verbose: bool = False) -> tuple:
        """Detect chat format and special tokens from tokenizer config files.

        Args:
            directory: Directory to search for config files
            verbose: Whether to print status

        Returns:
            Tuple of (chat_format, metadata_dir, special_tokens) or (None, None, {})
        """
        import json

        if not directory.exists():
            return None, None, {}

        # Look for tokenizer_config.json
        tokenizer_config = directory / 'tokenizer_config.json'
        config_json = directory / 'config.json'
        special_tokens_file = directory / 'special_tokens_map.json'

        chat_format = None
        metadata_dir = None
        special_tokens = {}

        # Check for tokenizer files
        has_tokenizer = (directory / 'tokenizer.json').exists()
        has_tokenizer_config = tokenizer_config.exists()
        has_config = config_json.exists()
        has_special_tokens = special_tokens_file.exists()

        if has_tokenizer or has_tokenizer_config or has_config or has_special_tokens:
            metadata_dir = str(directory)
            if verbose:
                found_files = []
                if has_tokenizer:
                    found_files.append('tokenizer.json')
                if has_tokenizer_config:
                    found_files.append('tokenizer_config.json')
                if has_special_tokens:
                    found_files.append('special_tokens_map.json')
                if has_config:
                    found_files.append('config.json')
                print(f"{Colors.DIM}    Found model metadata in: {directory.name}/{Colors.RESET}")
                print(f"{Colors.DIM}    Files: {', '.join(found_files)}{Colors.RESET}")

        # Load special tokens
        if has_special_tokens:
            try:
                with open(special_tokens_file, 'r') as f:
                    st = json.load(f)
                # Extract token strings
                for key, value in st.items():
                    if isinstance(value, dict):
                        special_tokens[key] = value.get('content', '')
                    else:
                        special_tokens[key] = value
                if verbose and special_tokens:
                    tokens_str = ', '.join(f"{k}={v}" for k, v in special_tokens.items() if v)
                    print(f"{Colors.DIM}    Special tokens: {tokens_str}{Colors.RESET}")
            except (json.JSONDecodeError, IOError):
                pass

        # Try to detect chat format from tokenizer_config.json
        if has_tokenizer_config:
            try:
                with open(tokenizer_config, 'r') as f:
                    tc = json.load(f)

                # Check chat_template field
                chat_template = tc.get('chat_template', '')

                # Detect format from chat_template content
                if 'chatml' in chat_template.lower() or '<|im_start|>' in chat_template:
                    chat_format = 'chatml'
                elif 'llama-2' in chat_template.lower() or '[INST]' in chat_template:
                    chat_format = 'llama-2'
                elif 'mistral' in chat_template.lower():
                    chat_format = 'mistral-instruct'
                elif 'vicuna' in chat_template.lower():
                    chat_format = 'vicuna'
                elif 'alpaca' in chat_template.lower():
                    chat_format = 'alpaca'
                elif 'zephyr' in chat_template.lower():
                    chat_format = 'zephyr'

                # Also check model_type or other fields
                if not chat_format:
                    model_type = tc.get('model_type', '').lower()
                    if 'llama' in model_type:
                        chat_format = 'llama-2'
                    elif 'mistral' in model_type:
                        chat_format = 'mistral-instruct'

            except (json.JSONDecodeError, IOError):
                pass

        # If still no format, try config.json
        if not chat_format and has_config:
            try:
                with open(config_json, 'r') as f:
                    cfg = json.load(f)

                model_type = cfg.get('model_type', '').lower()
                architectures = cfg.get('architectures', [])

                # Detect from model_type or architectures
                arch_str = ' '.join(architectures).lower()

                if 'llama' in model_type or 'llama' in arch_str:
                    chat_format = 'llama-2'
                elif 'mistral' in model_type or 'mistral' in arch_str:
                    chat_format = 'mistral-instruct'
                elif 'qwen' in model_type or 'qwen' in arch_str:
                    chat_format = 'chatml'

            except (json.JSONDecodeError, IOError):
                pass

        return chat_format, metadata_dir, special_tokens

    def unload_model(self):
        """Unload the current model and free resources."""
        if self._model is not None:
            del self._model
            self._model = None
            self._model_path = None
            self._metadata_dir = None
            self._special_tokens = {}
            self._chat_format = None
            self._chat_history.clear()

    def generate(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = None,
        top_p: float = None,
        top_k: int = None,
        repeat_penalty: float = None,
        stop: List[str] = None,
        stream: bool = False
    ) -> str | Generator[str, None, None]:
        """Generate text completion.

        Args:
            prompt: The input prompt.
            max_tokens: Maximum tokens to generate. Uses config default if None.
            temperature: Sampling temperature. Uses config default if None.
            top_p: Nucleus sampling parameter. Uses config default if None.
            top_k: Top-k sampling parameter. Uses config default if None.
            repeat_penalty: Repetition penalty. Uses config default if None.
            stop: List of stop sequences.
            stream: If True, yields tokens as they're generated.

        Returns:
            Generated text string, or generator if stream=True.

        Raises:
            LLMError: If no model is loaded or generation fails.
        """
        if not self.is_loaded:
            raise LLMError("No model loaded. Call load_model() first.")

        # Get defaults from config
        settings = self.config.get_llama_settings()

        params = {
            'max_tokens': max_tokens or settings['max_tokens'],
            'temperature': temperature if temperature is not None else settings['temperature'],
            'top_p': top_p if top_p is not None else settings['top_p'],
            'top_k': top_k if top_k is not None else settings['top_k'],
            'repeat_penalty': repeat_penalty if repeat_penalty is not None else settings['repeat_penalty'],
            'stop': stop or [],
            'stream': stream,
        }

        try:
            if stream:
                return self._stream_generate(prompt, params)
            else:
                response = self._model(prompt, **params)
                return response['choices'][0]['text']

        except Exception as e:
            raise LLMError(f"Generation failed: {e}")

    def _stream_generate(self, prompt: str, params: dict) -> Generator[str, None, None]:
        """Internal streaming generation method.

        Args:
            prompt: The input prompt.
            params: Generation parameters.

        Yields:
            Token strings as they're generated.
        """
        try:
            for chunk in self._model(prompt, **params):
                token = chunk['choices'][0]['text']
                yield token
        except Exception as e:
            raise LLMError(f"Streaming generation failed: {e}")

    def chat(
        self,
        message: str,
        system_prompt: str = None,
        stream: bool = False,
        **kwargs
    ) -> str | Generator[str, None, None]:
        """Chat-style interaction with conversation history.

        Args:
            message: User message.
            system_prompt: Optional system prompt (used on first message).
            stream: If True, yields tokens as they're generated.
            **kwargs: Additional parameters passed to generate().

        Returns:
            Assistant response string, or generator if stream=True.
        """
        if not self.is_loaded:
            raise LLMError("No model loaded. Call load_model() first.")

        # Initialize with system prompt if provided and history is empty
        if system_prompt and not self._chat_history:
            self._chat_history.append({
                'role': 'system',
                'content': system_prompt
            })

        # Add user message to history
        self._chat_history.append({
            'role': 'user',
            'content': message
        })

        # Build prompt from history
        prompt = self._build_chat_prompt()

        # Generate response
        if stream:
            return self._stream_chat(prompt, kwargs)
        else:
            response = self.generate(prompt, stream=False, **kwargs)
            # Clean up response and add to history
            response = response.strip()
            self._chat_history.append({
                'role': 'assistant',
                'content': response
            })
            return response

    def _stream_chat(self, prompt: str, kwargs: dict) -> Generator[str, None, None]:
        """Internal streaming chat method.

        Args:
            prompt: The formatted prompt.
            kwargs: Generation parameters.

        Yields:
            Token strings as they're generated.
        """
        full_response = []
        for token in self.generate(prompt, stream=True, **kwargs):
            full_response.append(token)
            yield token

        # Add complete response to history
        response = ''.join(full_response).strip()
        self._chat_history.append({
            'role': 'assistant',
            'content': response
        })

    def _build_chat_prompt(self) -> str:
        """Build a chat prompt from conversation history.

        Returns:
            Formatted prompt string.
        """
        # ChatML-style format (works with many models)
        prompt_parts = []

        for msg in self._chat_history:
            role = msg['role']
            content = msg['content']

            if role == 'system':
                prompt_parts.append(f"<|im_start|>system\n{content}<|im_end|>")
            elif role == 'user':
                prompt_parts.append(f"<|im_start|>user\n{content}<|im_end|>")
            elif role == 'assistant':
                prompt_parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")

        # Add assistant prompt for generation
        prompt_parts.append("<|im_start|>assistant\n")

        return "\n".join(prompt_parts)

    def clear_history(self):
        """Clear the conversation history."""
        self._chat_history.clear()

    def get_history(self) -> List[Dict[str, str]]:
        """Get the current conversation history.

        Returns:
            List of message dictionaries with 'role' and 'content' keys.
        """
        return self._chat_history.copy()

    def set_history(self, history: List[Dict[str, str]]):
        """Set the conversation history.

        Args:
            history: List of message dictionaries.
        """
        self._chat_history = history.copy()

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model.

        Returns:
            Dictionary with model information.
        """
        if not self.is_loaded:
            return {'loaded': False}

        return {
            'loaded': True,
            'model_path': self._model_path,
            'model_name': self.model_name,
            'n_ctx': self._model.n_ctx(),
            'n_vocab': self._model.n_vocab(),
        }


class TransformersLLM:
    """HuggingFace Transformers backend for safetensors models."""

    def __init__(self, config=None):
        self.config = config or get_config()
        self._model = None
        self._tokenizer = None
        self._model_path = None
        self._device = None
        self._chat_history: List[Dict[str, str]] = []

    @property
    def is_loaded(self) -> bool:
        return self._model is not None and self._tokenizer is not None

    @property
    def model_name(self) -> str:
        if self._model_path:
            return Path(self._model_path).name
        return "No model loaded"

    def load_model(self, model_path: str = None, verbose: bool = False) -> bool:
        """Load a safetensors model using HuggingFace Transformers.

        Args:
            model_path: Path to model directory OR HuggingFace model ID
                       (e.g., 'segolilylabs/Lily-Cybersecurity-7B-v0.2').
                       Uses config if not provided.
            verbose: Whether to show loading progress.

        Returns:
            True if model loaded successfully.

        Raises:
            LLMError: If model loading fails.
        """
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as e:
            raise LLMError(f"transformers/torch not installed: {e}\nInstall with: pip install transformers torch")

        # Get model path from config if not provided
        if model_path is None:
            model_path = self.config.get('transformers', 'model_path', '')

        if not model_path:
            raise LLMError("No model path configured. Run setup first.")

        # Determine if this is a local path or HuggingFace model ID
        model_id = model_path  # For from_pretrained()
        is_local = False

        local_path = Path(model_path).expanduser()
        if local_path.exists():
            if self._is_valid_model_dir(local_path):
                is_local = True
                model_id = str(local_path)
            else:
                raise LLMError(f"Invalid model directory. Expected safetensors files in: {local_path}")
        elif '/' in model_path and not model_path.startswith('/'):
            # Looks like a HuggingFace model ID (e.g., 'org/model-name')
            is_local = False
            model_id = model_path
        else:
            raise LLMError(f"Model not found: {model_path}\nProvide a local path or HuggingFace model ID (e.g., 'segolilylabs/Lily-Cybersecurity-7B-v0.2')")

        settings = self.config.get_transformers_settings()

        if verbose:
            display_name = Path(model_id).name if is_local else model_id
            print(f"{Colors.CYAN}[*] Loading model: {display_name}{Colors.RESET}")
            if not is_local:
                print(f"{Colors.DIM}    (from HuggingFace Hub/cache){Colors.RESET}")

        try:
            # Determine device
            if settings['device'] == 'auto':
                if torch.cuda.is_available():
                    self._device = 'cuda'
                elif hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                    self._device = 'mps'
                else:
                    self._device = 'cpu'
            else:
                self._device = settings['device']

            if verbose:
                print(f"{Colors.DIM}    Device: {self._device}{Colors.RESET}")

            # Determine dtype
            if settings['torch_dtype'] == 'auto':
                torch_dtype = torch.float16 if self._device != 'cpu' else torch.float32
            elif settings['torch_dtype'] == 'float16':
                torch_dtype = torch.float16
            elif settings['torch_dtype'] == 'bfloat16':
                torch_dtype = torch.bfloat16
            else:
                torch_dtype = torch.float32

            # Load tokenizer
            if verbose:
                print(f"{Colors.DIM}    Loading tokenizer...{Colors.RESET}")
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_id,
                trust_remote_code=settings['trust_remote_code']
            )

            # Prepare model loading kwargs
            device_map_cfg = settings.get('device_map', 'auto') or 'auto'
            model_kwargs = {
                'torch_dtype': torch_dtype,
                'trust_remote_code': settings['trust_remote_code'],
                'device_map': device_map_cfg if self._device != 'cpu' else None,
            }

            # Handle quantization — requires bitsandbytes (Linux/CUDA only)
            _bnb_ok = False
            try:
                import bitsandbytes  # noqa: F401
                _bnb_ok = True
            except (ImportError, Exception):
                pass

            if settings['load_in_8bit'] or settings['load_in_4bit']:
                if _bnb_ok:
                    if settings['load_in_8bit']:
                        model_kwargs['load_in_8bit'] = True
                        # Enable FP32 CPU offload if requested — required when model layers
                        # are dispatched to CPU/disk during 8-bit quantization
                        if settings.get('llm_int8_enable_fp32_cpu_offload', False):
                            model_kwargs['llm_int8_enable_fp32_cpu_offload'] = True
                            _llm_logger.info("[LLM] llm_int8_enable_fp32_cpu_offload=True enabled")
                        if verbose:
                            print(f"{Colors.DIM}    Loading in 8-bit quantization...{Colors.RESET}")
                    elif settings['load_in_4bit']:
                        model_kwargs['load_in_4bit'] = True
                        if verbose:
                            print(f"{Colors.DIM}    Loading in 4-bit quantization...{Colors.RESET}")
                else:
                    _llm_logger.warning(
                        "[LLM] load_in_8bit/load_in_4bit requested but bitsandbytes is not installed "
                        "(Windows is not supported). Loading without quantization."
                    )

            # Load model
            if verbose:
                print(f"{Colors.DIM}    Loading model weights...{Colors.RESET}")
            self._model = AutoModelForCausalLM.from_pretrained(
                model_id,
                **model_kwargs
            )

            # Move to device if not using device_map
            if 'device_map' not in model_kwargs or model_kwargs['device_map'] is None:
                self._model = self._model.to(self._device)

            self._model.eval()
            self._model_path = model_id

            if verbose:
                print(f"{Colors.GREEN}[+] Model loaded successfully{Colors.RESET}")

            return True

        except Exception as e:
            self._model = None
            self._tokenizer = None
            self._model_path = None
            raise LLMError(f"Failed to load model: {e}")

    def _is_valid_model_dir(self, path: Path) -> bool:
        """Check if directory contains a valid safetensors model."""
        if not path.is_dir():
            return False

        # Check for safetensors files
        safetensor_files = list(path.glob("*.safetensors"))
        if safetensor_files:
            return True

        # Check for model index
        index_file = path / "model.safetensors.index.json"
        if index_file.exists():
            return True

        # Check for config.json (indicates HF model)
        config_file = path / "config.json"
        if config_file.exists():
            return True

        return False

    def unload_model(self):
        """Unload the current model and free resources."""
        if self._model is not None:
            del self._model
            self._model = None
        if self._tokenizer is not None:
            del self._tokenizer
            self._tokenizer = None
        self._model_path = None
        self._device = None
        self._chat_history.clear()

        # Clear GPU cache if available
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:
            pass

    def generate(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = None,
        top_p: float = None,
        top_k: int = None,
        repeat_penalty: float = None,
        stop: List[str] = None,
        stream: bool = False
    ) -> str | Generator[str, None, None]:
        """Generate text completion using transformers."""
        if not self.is_loaded:
            raise LLMError("No model loaded. Call load_model() first.")

        try:
            import torch
        except ImportError:
            raise LLMError("torch not installed")

        settings = self.config.get_transformers_settings()

        # Tokenize input
        inputs = self._tokenizer(prompt, return_tensors="pt")
        inputs = {k: v.to(self._device) for k, v in inputs.items()}

        # Generation parameters
        gen_kwargs = {
            'max_new_tokens': max_tokens or settings['max_tokens'],
            'temperature': temperature if temperature is not None else settings['temperature'],
            'top_p': top_p if top_p is not None else settings['top_p'],
            'top_k': top_k if top_k is not None else settings['top_k'],
            'repetition_penalty': repeat_penalty if repeat_penalty is not None else settings['repetition_penalty'],
            'do_sample': True,
            'pad_token_id': self._tokenizer.eos_token_id,
        }

        # Handle temperature=0
        if gen_kwargs['temperature'] == 0:
            gen_kwargs['do_sample'] = False
            del gen_kwargs['temperature']
            del gen_kwargs['top_p']
            del gen_kwargs['top_k']

        try:
            if stream:
                return self._stream_generate(inputs, gen_kwargs, stop)
            else:
                with torch.no_grad():
                    outputs = self._model.generate(**inputs, **gen_kwargs)
                # Decode only the new tokens
                response = self._tokenizer.decode(
                    outputs[0][inputs['input_ids'].shape[1]:],
                    skip_special_tokens=True
                )
                # Handle stop sequences
                if stop:
                    for stop_seq in stop:
                        if stop_seq in response:
                            response = response.split(stop_seq)[0]
                return response

        except Exception as e:
            raise LLMError(f"Generation failed: {e}")

    def _stream_generate(self, inputs: dict, gen_kwargs: dict, stop: List[str] = None) -> Generator[str, None, None]:
        """Internal streaming generation using TextIteratorStreamer."""
        try:
            import torch
            from transformers import TextIteratorStreamer
            from threading import Thread
        except ImportError as e:
            raise LLMError(f"Required packages not installed: {e}")

        streamer = TextIteratorStreamer(
            self._tokenizer,
            skip_prompt=True,
            skip_special_tokens=True
        )
        gen_kwargs['streamer'] = streamer

        # Run generation in background thread
        thread = Thread(target=lambda: self._model.generate(**inputs, **gen_kwargs))
        thread.start()

        # Yield tokens as they're generated
        full_text = ""
        for text in streamer:
            # Check for stop sequences
            if stop:
                for stop_seq in stop:
                    if stop_seq in text:
                        text = text.split(stop_seq)[0]
                        yield text
                        return
            full_text += text
            yield text

        thread.join()

    def chat(
        self,
        message: str,
        system_prompt: str = None,
        stream: bool = False,
        **kwargs
    ) -> str | Generator[str, None, None]:
        """Chat-style interaction with conversation history."""
        if not self.is_loaded:
            raise LLMError("No model loaded. Call load_model() first.")

        # Initialize with system prompt if provided and history is empty
        if system_prompt and not self._chat_history:
            self._chat_history.append({
                'role': 'system',
                'content': system_prompt
            })

        # Add user message to history
        self._chat_history.append({
            'role': 'user',
            'content': message
        })

        # Build prompt from history
        prompt = self._build_chat_prompt()

        # Generate response
        if stream:
            return self._stream_chat(prompt, kwargs)
        else:
            response = self.generate(prompt, stream=False, **kwargs)
            response = response.strip()
            self._chat_history.append({
                'role': 'assistant',
                'content': response
            })
            return response

    def _stream_chat(self, prompt: str, kwargs: dict) -> Generator[str, None, None]:
        """Internal streaming chat method."""
        full_response = []
        for token in self.generate(prompt, stream=True, **kwargs):
            full_response.append(token)
            yield token

        response = ''.join(full_response).strip()
        self._chat_history.append({
            'role': 'assistant',
            'content': response
        })

    def _build_chat_prompt(self) -> str:
        """Build a chat prompt from conversation history."""
        # Try to use the tokenizer's chat template if available
        if hasattr(self._tokenizer, 'apply_chat_template'):
            try:
                return self._tokenizer.apply_chat_template(
                    self._chat_history,
                    tokenize=False,
                    add_generation_prompt=True
                )
            except Exception:
                pass

        # Fallback to ChatML format
        prompt_parts = []
        for msg in self._chat_history:
            role = msg['role']
            content = msg['content']
            if role == 'system':
                prompt_parts.append(f"<|im_start|>system\n{content}<|im_end|>")
            elif role == 'user':
                prompt_parts.append(f"<|im_start|>user\n{content}<|im_end|>")
            elif role == 'assistant':
                prompt_parts.append(f"<|im_start|>assistant\n{content}<|im_end|>")

        prompt_parts.append("<|im_start|>assistant\n")
        return "\n".join(prompt_parts)

    def clear_history(self):
        """Clear the conversation history."""
        self._chat_history.clear()

    def get_history(self) -> List[Dict[str, str]]:
        """Get the current conversation history."""
        return self._chat_history.copy()

    def set_history(self, history: List[Dict[str, str]]):
        """Set the conversation history."""
        self._chat_history = history.copy()

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        if not self.is_loaded:
            return {'loaded': False}

        info = {
            'loaded': True,
            'model_path': self._model_path,
            'model_name': self.model_name,
            'device': self._device,
            'backend': 'transformers',
        }

        # Add vocab size if available
        if hasattr(self._tokenizer, 'vocab_size'):
            info['vocab_size'] = self._tokenizer.vocab_size

        return info


class ClaudeLLM:
    """Claude API backend implementing the same interface as LLM."""

    def __init__(self, config=None):
        self.config = config or get_config()
        self._client = None
        self._model = None
        self._chat_history: List[Dict[str, str]] = []

    @property
    def is_loaded(self) -> bool:
        return self._client is not None

    @property
    def model_name(self) -> str:
        if self._model:
            return self._model
        return "No model loaded"

    def load_model(self, model_path: str = None, verbose: bool = False) -> bool:
        """Initialize the Anthropic client.

        Args:
            model_path: Ignored for Claude (model set in config).
            verbose: Whether to show status messages.

        Returns:
            True if client initialized successfully.

        Raises:
            LLMError: If initialization fails.
        """
        try:
            import anthropic
        except ImportError as e:
            raise LLMError(f"anthropic package not installed: {e}")

        import os
        settings = self.config.get_claude_settings()
        api_key = settings['api_key'] or os.environ.get('ANTHROPIC_API_KEY', '')

        if not api_key:
            raise LLMError(
                "No Claude API key found. Set it in autarch_settings.conf [claude] section "
                "or export ANTHROPIC_API_KEY environment variable."
            )

        self._model = settings['model']

        if verbose:
            print(f"{Colors.CYAN}[*] Initializing Claude API: {self._model}{Colors.RESET}")

        try:
            self._client = anthropic.Anthropic(api_key=api_key)
            if verbose:
                print(f"{Colors.GREEN}[+] Claude API ready{Colors.RESET}")
            return True
        except Exception as e:
            self._client = None
            self._model = None
            raise LLMError(f"Failed to initialize Claude client: {e}")

    def unload_model(self):
        """Clear the client and history."""
        self._client = None
        self._model = None
        self._chat_history.clear()

    def generate(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = None,
        top_p: float = None,
        top_k: int = None,
        repeat_penalty: float = None,
        stop: List[str] = None,
        stream: bool = False
    ) -> str | Generator[str, None, None]:
        """Generate text from a prompt via Claude API.

        The prompt is sent as a single user message.
        """
        if not self.is_loaded:
            raise LLMError("Claude client not initialized. Call load_model() first.")

        settings = self.config.get_claude_settings()

        params = {
            'model': self._model,
            'max_tokens': max_tokens or settings['max_tokens'],
            'messages': [{'role': 'user', 'content': prompt}],
        }

        temp = temperature if temperature is not None else settings['temperature']
        if temp is not None:
            params['temperature'] = temp
        if top_p is not None:
            params['top_p'] = top_p
        if top_k is not None:
            params['top_k'] = top_k
        if stop:
            params['stop_sequences'] = stop

        try:
            if stream:
                return self._stream_generate(params)
            else:
                response = self._client.messages.create(**params)
                return response.content[0].text
        except Exception as e:
            raise LLMError(f"Claude generation failed: {e}")

    def _stream_generate(self, params: dict) -> Generator[str, None, None]:
        """Internal streaming generation."""
        try:
            with self._client.messages.stream(**params) as stream:
                for text in stream.text_stream:
                    yield text
        except Exception as e:
            raise LLMError(f"Claude streaming failed: {e}")

    def chat(
        self,
        message: str,
        system_prompt: str = None,
        stream: bool = False,
        **kwargs
    ) -> str | Generator[str, None, None]:
        """Chat-style interaction with conversation history via Claude API."""
        if not self.is_loaded:
            raise LLMError("Claude client not initialized. Call load_model() first.")

        # Store system prompt in history for tracking (same as LLM)
        if system_prompt and not self._chat_history:
            self._chat_history.append({
                'role': 'system',
                'content': system_prompt
            })

        # Add user message to history
        self._chat_history.append({
            'role': 'user',
            'content': message
        })

        # Build API call from history
        system_text = None
        messages = []
        for msg in self._chat_history:
            if msg['role'] == 'system':
                system_text = msg['content']
            else:
                messages.append({'role': msg['role'], 'content': msg['content']})

        settings = self.config.get_claude_settings()

        params = {
            'model': self._model,
            'max_tokens': kwargs.get('max_tokens', settings['max_tokens']),
            'messages': messages,
        }

        if system_text:
            params['system'] = system_text

        temp = kwargs.get('temperature', settings['temperature'])
        if temp is not None:
            params['temperature'] = temp
        if 'top_p' in kwargs:
            params['top_p'] = kwargs['top_p']
        if 'top_k' in kwargs:
            params['top_k'] = kwargs['top_k']
        if 'stop' in kwargs and kwargs['stop']:
            params['stop_sequences'] = kwargs['stop']

        try:
            if stream:
                return self._stream_chat(params)
            else:
                response = self._client.messages.create(**params)
                text = response.content[0].text.strip()
                self._chat_history.append({
                    'role': 'assistant',
                    'content': text
                })
                return text
        except Exception as e:
            raise LLMError(f"Claude chat failed: {e}")

    def _stream_chat(self, params: dict) -> Generator[str, None, None]:
        """Internal streaming chat method."""
        full_response = []
        try:
            with self._client.messages.stream(**params) as stream:
                for text in stream.text_stream:
                    full_response.append(text)
                    yield text
        except Exception as e:
            raise LLMError(f"Claude streaming chat failed: {e}")

        response = ''.join(full_response).strip()
        self._chat_history.append({
            'role': 'assistant',
            'content': response
        })

    def clear_history(self):
        """Clear the conversation history."""
        self._chat_history.clear()

    def get_history(self) -> List[Dict[str, str]]:
        """Get the current conversation history."""
        return self._chat_history.copy()

    def set_history(self, history: List[Dict[str, str]]):
        """Set the conversation history."""
        self._chat_history = history.copy()

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the Claude model."""
        if not self.is_loaded:
            return {'loaded': False}

        return {
            'loaded': True,
            'model_path': 'Claude API',
            'model_name': self.model_name,
            'backend': 'claude',
        }


class HuggingFaceLLM:
    """HuggingFace Inference API backend implementing the same interface as LLM.

    Uses the huggingface_hub InferenceClient to call HF-hosted models
    or any compatible text-generation-inference endpoint.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self._client = None
        self._model = None
        self._chat_history: List[Dict[str, str]] = []

    @property
    def is_loaded(self) -> bool:
        return self._client is not None

    @property
    def model_name(self) -> str:
        if self._model:
            return self._model
        return "No model loaded"

    def load_model(self, model_path: str = None, verbose: bool = False) -> bool:
        """Initialize the HuggingFace Inference client."""
        try:
            from huggingface_hub import InferenceClient
        except ImportError as e:
            raise LLMError(f"huggingface_hub package not installed: {e}")

        import os
        settings = self._get_settings()
        api_key = settings.get('api_key', '') or os.environ.get('HF_TOKEN', '') or os.environ.get('HUGGING_FACE_HUB_TOKEN', '')
        model = model_path or settings.get('model', 'mistralai/Mistral-7B-Instruct-v0.3')
        endpoint = settings.get('endpoint', '')

        self._model = model

        if verbose:
            print(f"{Colors.CYAN}[*] Initializing HuggingFace Inference: {self._model}{Colors.RESET}")
            if endpoint:
                print(f"{Colors.DIM}    Endpoint: {endpoint}{Colors.RESET}")

        try:
            kwargs = {}
            if api_key:
                kwargs['token'] = api_key
            if endpoint:
                kwargs['model'] = endpoint
            else:
                kwargs['model'] = model

            self._client = InferenceClient(**kwargs)

            if verbose:
                print(f"{Colors.GREEN}[+] HuggingFace Inference ready{Colors.RESET}")
            return True
        except Exception as e:
            self._client = None
            self._model = None
            raise LLMError(f"Failed to initialize HuggingFace client: {e}")

    def _get_settings(self) -> dict:
        """Get HuggingFace settings from config."""
        return {
            'api_key': self.config.get('huggingface', 'api_key', fallback=''),
            'model': self.config.get('huggingface', 'model', fallback='mistralai/Mistral-7B-Instruct-v0.3'),
            'endpoint': self.config.get('huggingface', 'endpoint', fallback=''),
            'max_tokens': int(self.config.get('huggingface', 'max_tokens', fallback='1024')),
            'temperature': float(self.config.get('huggingface', 'temperature', fallback='0.7')),
            'top_p': float(self.config.get('huggingface', 'top_p', fallback='0.9')),
        }

    def unload_model(self):
        """Clear the client and history."""
        self._client = None
        self._model = None
        self._chat_history.clear()

    def generate(
        self,
        prompt: str,
        max_tokens: int = None,
        temperature: float = None,
        top_p: float = None,
        top_k: int = None,
        repeat_penalty: float = None,
        stop: List[str] = None,
        stream: bool = False
    ) -> str | Generator[str, None, None]:
        """Generate text via HuggingFace Inference API."""
        if not self.is_loaded:
            raise LLMError("HuggingFace client not initialized. Call load_model() first.")

        settings = self._get_settings()

        params = {
            'max_new_tokens': max_tokens or settings['max_tokens'],
            'temperature': temperature if temperature is not None else settings['temperature'],
            'top_p': top_p if top_p is not None else settings['top_p'],
        }
        if top_k is not None:
            params['top_k'] = top_k
        if repeat_penalty is not None:
            params['repetition_penalty'] = repeat_penalty
        if stop:
            params['stop_sequences'] = stop

        try:
            if stream:
                return self._stream_generate(prompt, params)
            else:
                response = self._client.text_generation(
                    prompt,
                    **params
                )
                return response
        except Exception as e:
            raise LLMError(f"HuggingFace generation failed: {e}")

    def _stream_generate(self, prompt: str, params: dict) -> Generator[str, None, None]:
        """Internal streaming generation."""
        try:
            for token in self._client.text_generation(
                prompt,
                stream=True,
                **params
            ):
                yield token
        except Exception as e:
            raise LLMError(f"HuggingFace streaming failed: {e}")

    def chat(
        self,
        message: str,
        system_prompt: str = None,
        stream: bool = False,
        **kwargs
    ) -> str | Generator[str, None, None]:
        """Chat-style interaction via HuggingFace Inference API."""
        if not self.is_loaded:
            raise LLMError("HuggingFace client not initialized. Call load_model() first.")

        if system_prompt and not self._chat_history:
            self._chat_history.append({
                'role': 'system',
                'content': system_prompt
            })

        self._chat_history.append({
            'role': 'user',
            'content': message
        })

        # Build messages for chat completion
        messages = []
        for msg in self._chat_history:
            messages.append({'role': msg['role'], 'content': msg['content']})

        settings = self._get_settings()

        try:
            if stream:
                return self._stream_chat(messages, settings, kwargs)
            else:
                response = self._client.chat_completion(
                    messages=messages,
                    max_tokens=kwargs.get('max_tokens', settings['max_tokens']),
                    temperature=kwargs.get('temperature', settings['temperature']),
                )
                text = response.choices[0].message.content.strip()
                self._chat_history.append({
                    'role': 'assistant',
                    'content': text
                })
                return text
        except Exception as e:
            raise LLMError(f"HuggingFace chat failed: {e}")

    def _stream_chat(self, messages: list, settings: dict, kwargs: dict) -> Generator[str, None, None]:
        """Internal streaming chat."""
        full_response = []
        try:
            stream = self._client.chat_completion(
                messages=messages,
                max_tokens=kwargs.get('max_tokens', settings['max_tokens']),
                temperature=kwargs.get('temperature', settings['temperature']),
                stream=True,
            )
            for chunk in stream:
                if chunk.choices and chunk.choices[0].delta.content:
                    text = chunk.choices[0].delta.content
                    full_response.append(text)
                    yield text
        except Exception as e:
            raise LLMError(f"HuggingFace streaming chat failed: {e}")

        response = ''.join(full_response).strip()
        self._chat_history.append({
            'role': 'assistant',
            'content': response
        })

    def clear_history(self):
        self._chat_history.clear()

    def get_history(self) -> List[Dict[str, str]]:
        return self._chat_history.copy()

    def set_history(self, history: List[Dict[str, str]]):
        self._chat_history = history.copy()

    def get_model_info(self) -> Dict[str, Any]:
        if not self.is_loaded:
            return {'loaded': False}
        settings = self._get_settings()
        return {
            'loaded': True,
            'model_path': settings.get('endpoint', '') or 'HuggingFace Hub',
            'model_name': self.model_name,
            'backend': 'huggingface',
        }


# Global LLM instance
_llm_instance = None


def get_llm():
    """Get the global LLM instance, auto-loading the model if needed.

    Returns the appropriate backend (LLM, TransformersLLM, ClaudeLLM, or HuggingFaceLLM) based on config.
    """
    global _llm_instance
    if _llm_instance is None:
        config = get_config()
        backend = config.get('autarch', 'llm_backend', 'local')
        _llm_logger.info(f"[LLM] Initializing backend: {backend}")

        try:
            if backend == 'claude':
                settings = config.get_claude_settings()
                _llm_logger.info(f"[LLM] Claude model: {settings['model']} | API key set: {bool(settings['api_key'])}")
                _llm_instance = ClaudeLLM(config)
                _llm_instance.load_model()
                _llm_logger.info(f"[LLM] Claude client ready: {settings['model']}")

            elif backend == 'transformers':
                settings = config.get_transformers_settings()
                _llm_logger.info(f"[LLM] Transformers model: {settings['model_path']} | device: {settings['device']}")
                _llm_instance = TransformersLLM(config)
                if settings['model_path']:
                    _llm_instance.load_model()
                    _llm_logger.info(f"[LLM] Transformers model loaded: {settings['model_path']}")
                else:
                    _llm_logger.warning("[LLM] No transformers model path configured — set one in LLM Settings")

            elif backend == 'huggingface':
                hf = config.get_huggingface_settings()
                _llm_logger.info(f"[LLM] HuggingFace model: {hf['model']} | provider: {hf.get('provider','auto')} | API key set: {bool(hf['api_key'])}")
                _llm_instance = HuggingFaceLLM(config)
                _llm_instance.load_model()
                _llm_logger.info(f"[LLM] HuggingFace client ready: {hf['model']}")

            else:  # local / llama.cpp
                settings = config.get_llama_settings()
                _llm_logger.info(f"[LLM] llama.cpp model: {settings['model_path']} | n_ctx: {settings['n_ctx']} | n_gpu_layers: {settings['n_gpu_layers']} | threads: {settings['n_threads']}")
                _llm_instance = LLM(config)
                if settings['model_path']:
                    _llm_instance.load_model()
                    _llm_logger.info(f"[LLM] llama.cpp model loaded: {settings['model_path']}")
                else:
                    _llm_logger.warning("[LLM] No local model path configured — set one in LLM Settings")

        except Exception as exc:
            _llm_logger.error(f"[LLM] Failed to load backend '{backend}': {exc}", exc_info=True)
            _llm_instance = None
            raise

    return _llm_instance


def detect_model_type(path: str) -> str:
    """Detect the type of model at the given path.

    Args:
        path: Path to model file or directory

    Returns:
        'gguf' for GGUF files, 'transformers' for safetensors directories,
        'unknown' if cannot be determined
    """
    path = Path(path).expanduser()

    if not path.exists():
        return 'unknown'

    # Check for GGUF file
    if path.is_file():
        if path.suffix.lower() == '.gguf':
            return 'gguf'
        # Some GGUF files might not have .gguf extension
        # Check magic bytes
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
                if magic == b'GGUF':
                    return 'gguf'
        except Exception:
            pass

    # Check for transformers/safetensors directory
    if path.is_dir():
        # Check for safetensors files
        safetensor_files = list(path.glob("*.safetensors"))
        if safetensor_files:
            return 'transformers'

        # Check for model index
        index_file = path / "model.safetensors.index.json"
        if index_file.exists():
            return 'transformers'

        # Check for config.json (indicates HF model)
        config_file = path / "config.json"
        if config_file.exists():
            # Could be safetensors or pytorch
            if list(path.glob("*.safetensors")) or (path / "model.safetensors.index.json").exists():
                return 'transformers'
            # Check for pytorch files too
            if list(path.glob("*.bin")) or (path / "pytorch_model.bin").exists():
                return 'transformers'

    return 'unknown'


def reset_llm():
    """Reset the global LLM instance (used when switching backends)."""
    global _llm_instance
    if _llm_instance is not None:
        _llm_logger.info("[LLM] Unloading current model instance")
        _llm_instance.unload_model()
    _llm_instance = None
    _llm_logger.info("[LLM] Instance reset — next call to get_llm() will reload")
