"""
AUTARCH Model Router
Manages concurrent SLM/LAM/SAM model instances for autonomous operation.

Model Tiers:
  SLM (Small Language Model) — Fast classification, routing, yes/no decisions
  SAM (Small Action Model)   — Quick tool execution, simple automated responses
  LAM (Large Action Model)   — Complex multi-step agent tasks, strategic planning
"""

import json
import logging
import threading
from typing import Optional, Dict, Any
from enum import Enum

from .config import get_config

_logger = logging.getLogger('autarch.model_router')


class ModelTier(Enum):
    SLM = 'slm'
    SAM = 'sam'
    LAM = 'lam'


# Fallback chain: if a tier fails, try the next one
_FALLBACK = {
    ModelTier.SLM: [ModelTier.SAM, ModelTier.LAM],
    ModelTier.SAM: [ModelTier.LAM],
    ModelTier.LAM: [],
}


class _TierConfigProxy:
    """Proxies Config but overrides the backend section for a specific model tier.

    When a tier says backend=local with model_path=X, this proxy makes the LLM
    class (which reads [llama]) see the tier's model_path/n_ctx/etc instead.
    """

    def __init__(self, base_config, tier_name: str):
        self._base = base_config
        self._tier = tier_name
        self._overrides: Dict[str, Dict[str, str]] = {}
        self._build_overrides()

    def _build_overrides(self):
        backend = self._base.get(self._tier, 'backend', 'local')
        model_path = self._base.get(self._tier, 'model_path', '')
        n_ctx = self._base.get(self._tier, 'n_ctx', '2048')
        n_gpu_layers = self._base.get(self._tier, 'n_gpu_layers', '-1')
        n_threads = self._base.get(self._tier, 'n_threads', '4')

        if backend == 'local':
            self._overrides['llama'] = {
                'model_path': model_path,
                'n_ctx': n_ctx,
                'n_gpu_layers': n_gpu_layers,
                'n_threads': n_threads,
            }
        elif backend == 'transformers':
            self._overrides['transformers'] = {
                'model_path': model_path,
            }
        # claude and huggingface are API-based — no path override needed

    def get(self, section: str, key: str, fallback=None):
        overrides = self._overrides.get(section, {})
        if key in overrides:
            return overrides[key]
        return self._base.get(section, key, fallback)

    def get_int(self, section: str, key: str, fallback: int = 0) -> int:
        overrides = self._overrides.get(section, {})
        if key in overrides:
            try:
                return int(overrides[key])
            except (ValueError, TypeError):
                return fallback
        return self._base.get_int(section, key, fallback)

    def get_float(self, section: str, key: str, fallback: float = 0.0) -> float:
        overrides = self._overrides.get(section, {})
        if key in overrides:
            try:
                return float(overrides[key])
            except (ValueError, TypeError):
                return fallback
        return self._base.get_float(section, key, fallback)

    def get_bool(self, section: str, key: str, fallback: bool = False) -> bool:
        overrides = self._overrides.get(section, {})
        if key in overrides:
            val = str(overrides[key]).lower()
            return val in ('true', '1', 'yes', 'on')
        return self._base.get_bool(section, key, fallback)

    # Delegate all settings getters to base (they call self.get internally)
    def get_llama_settings(self) -> dict:
        from .config import Config
        return Config.get_llama_settings(self)

    def get_transformers_settings(self) -> dict:
        from .config import Config
        return Config.get_transformers_settings(self)

    def get_claude_settings(self) -> dict:
        return self._base.get_claude_settings()

    def get_huggingface_settings(self) -> dict:
        return self._base.get_huggingface_settings()


class ModelRouter:
    """Manages up to 3 concurrent LLM instances (SLM, SAM, LAM).

    Each tier can use a different backend (local GGUF, transformers, Claude API,
    HuggingFace). The router handles loading, unloading, fallback, and thread-safe
    access.
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self._instances: Dict[ModelTier, Any] = {}
        self._locks: Dict[ModelTier, threading.Lock] = {
            tier: threading.Lock() for tier in ModelTier
        }
        self._load_lock = threading.Lock()

    @property
    def status(self) -> Dict[str, dict]:
        """Return load status of all tiers."""
        result = {}
        for tier in ModelTier:
            inst = self._instances.get(tier)
            settings = self.config.get_tier_settings(tier.value)
            result[tier.value] = {
                'loaded': inst is not None and inst.is_loaded,
                'model_name': inst.model_name if inst and inst.is_loaded else None,
                'backend': settings['backend'],
                'enabled': settings['enabled'],
                'model_path': settings['model_path'],
            }
        return result

    def load_tier(self, tier: ModelTier, verbose: bool = False) -> bool:
        """Load a single tier's model. Thread-safe."""
        settings = self.config.get_tier_settings(tier.value)

        if not settings['enabled']:
            _logger.info(f"[Router] Tier {tier.value} is disabled, skipping")
            return False

        if not settings['model_path'] and settings['backend'] == 'local':
            _logger.warning(f"[Router] No model_path configured for {tier.value}")
            return False

        with self._load_lock:
            # Unload existing if any
            if tier in self._instances:
                self.unload_tier(tier)

            try:
                inst = self._create_instance(tier, verbose)
                self._instances[tier] = inst
                _logger.info(f"[Router] Loaded {tier.value}: {inst.model_name}")
                return True
            except Exception as e:
                _logger.error(f"[Router] Failed to load {tier.value}: {e}")
                return False

    def unload_tier(self, tier: ModelTier):
        """Unload a tier's model and free resources."""
        inst = self._instances.pop(tier, None)
        if inst:
            try:
                inst.unload_model()
                _logger.info(f"[Router] Unloaded {tier.value}")
            except Exception as e:
                _logger.error(f"[Router] Error unloading {tier.value}: {e}")

    def load_all(self, verbose: bool = False) -> Dict[str, bool]:
        """Load all enabled tiers. Returns {tier_name: success}."""
        results = {}
        for tier in ModelTier:
            results[tier.value] = self.load_tier(tier, verbose)
        return results

    def unload_all(self):
        """Unload all tiers."""
        for tier in list(self._instances.keys()):
            self.unload_tier(tier)

    def get_instance(self, tier: ModelTier):
        """Get the LLM instance for a tier (may be None if not loaded)."""
        return self._instances.get(tier)

    def is_tier_loaded(self, tier: ModelTier) -> bool:
        """Check if a tier has a loaded model."""
        inst = self._instances.get(tier)
        return inst is not None and inst.is_loaded

    def classify(self, text: str) -> Dict[str, Any]:
        """Use SLM to classify/triage an event or task.

        Returns: {'tier': 'sam'|'lam', 'category': str, 'urgency': str, 'reasoning': str}

        Falls back to SAM tier if SLM is not loaded.
        """
        classify_prompt = f"""Classify this event/task for autonomous handling.
Respond with ONLY a JSON object, no other text:
{{"tier": "sam" or "lam", "category": "defense|offense|counter|analyze|osint|simulate", "urgency": "high|medium|low", "reasoning": "brief explanation"}}

Event: {text}"""

        # Try SLM first, then fallback
        for tier in [ModelTier.SLM, ModelTier.SAM, ModelTier.LAM]:
            inst = self._instances.get(tier)
            if inst and inst.is_loaded:
                try:
                    with self._locks[tier]:
                        response = inst.generate(classify_prompt, max_tokens=200, temperature=0.1)
                    # Parse JSON from response
                    response = response.strip()
                    # Find JSON in response
                    start = response.find('{')
                    end = response.rfind('}')
                    if start >= 0 and end > start:
                        return json.loads(response[start:end + 1])
                except Exception as e:
                    _logger.warning(f"[Router] Classification failed on {tier.value}: {e}")
                    continue

        # Default if all tiers fail
        return {'tier': 'sam', 'category': 'defense', 'urgency': 'medium',
                'reasoning': 'Default classification (no model available)'}

    def generate(self, tier: ModelTier, prompt: str, **kwargs) -> str:
        """Generate with a specific tier, falling back to higher tiers on failure.

        Fallback chain: SLM -> SAM -> LAM, SAM -> LAM
        """
        chain = [tier] + _FALLBACK.get(tier, [])

        for t in chain:
            inst = self._instances.get(t)
            if inst and inst.is_loaded:
                try:
                    with self._locks[t]:
                        return inst.generate(prompt, **kwargs)
                except Exception as e:
                    _logger.warning(f"[Router] Generate failed on {t.value}: {e}")
                    continue

        from .llm import LLMError
        raise LLMError(f"All tiers exhausted for generation (started at {tier.value})")

    def _create_instance(self, tier: ModelTier, verbose: bool = False):
        """Create an LLM instance from tier config."""
        from .llm import LLM, TransformersLLM, ClaudeLLM, HuggingFaceLLM

        section = tier.value
        backend = self.config.get(section, 'backend', 'local')
        proxy = _TierConfigProxy(self.config, section)

        if verbose:
            model_path = self.config.get(section, 'model_path', '')
            _logger.info(f"[Router] Creating {tier.value} instance: backend={backend}, model={model_path}")

        if backend == 'local':
            inst = LLM(proxy)
        elif backend == 'transformers':
            inst = TransformersLLM(proxy)
        elif backend == 'claude':
            inst = ClaudeLLM(proxy)
        elif backend == 'huggingface':
            inst = HuggingFaceLLM(proxy)
        else:
            from .llm import LLMError
            raise LLMError(f"Unknown backend '{backend}' for tier {tier.value}")

        inst.load_model(verbose=verbose)
        return inst


# Singleton
_router_instance = None


def get_model_router() -> ModelRouter:
    """Get the global ModelRouter instance."""
    global _router_instance
    if _router_instance is None:
        _router_instance = ModelRouter()
    return _router_instance


def reset_model_router():
    """Reset the global ModelRouter (unloads all models)."""
    global _router_instance
    if _router_instance is not None:
        _router_instance.unload_all()
    _router_instance = None
