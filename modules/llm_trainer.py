"""
AUTARCH LLM Trainer Module
Fine-tune language models on the AUTARCH codebase and convert to GGUF.

Generates training datasets from source code, trains LoRA adapters,
merges weights, and quantizes to GGUF format for local inference.
"""

import os
import sys
import subprocess
import json
import re
import ast
import time
import platform
import shutil
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

# Module metadata
DESCRIPTION = "LLM fine-tuning & GGUF training pipeline"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

_is_win = platform.system() == 'Windows'
_PROJECT_ROOT = Path(__file__).parent.parent
_DATA_DIR = _PROJECT_ROOT / 'data'
_MODELS_DIR = _PROJECT_ROOT / 'models'
_TRAINING_DIR = _DATA_DIR / 'training'


class LLMTrainer:
    """Fine-tuning pipeline: dataset generation, LoRA training, GGUF conversion."""

    def __init__(self):
        self._training_dir = _TRAINING_DIR
        self._training_dir.mkdir(parents=True, exist_ok=True)
        self._models_dir = _MODELS_DIR
        self._project_root = _PROJECT_ROOT
        self._status = {
            'phase': 'idle',
            'progress': 0,
            'message': '',
            'log': [],
        }
        self._training_process = None

    def _log(self, msg, level='info'):
        entry = {'time': datetime.now().strftime('%H:%M:%S'), 'msg': msg, 'level': level}
        self._status['log'].append(entry)
        # Keep last 200 entries
        if len(self._status['log']) > 200:
            self._status['log'] = self._status['log'][-200:]

    def get_status(self):
        return dict(self._status)

    # ==================== DEPENDENCY CHECK ====================

    def check_dependencies(self):
        """Check what training dependencies are installed."""
        deps = {}
        checks = {
            'torch': 'import torch; print(torch.__version__)',
            'transformers': 'import transformers; print(transformers.__version__)',
            'peft': 'import peft; print(peft.__version__)',
            'datasets': 'import datasets; print(datasets.__version__)',
            'unsloth': 'import unsloth; print(unsloth.__version__)',
            'bitsandbytes': 'import bitsandbytes; print(bitsandbytes.__version__)',
            'trl': 'import trl; print(trl.__version__)',
            'accelerate': 'import accelerate; print(accelerate.__version__)',
        }
        for name, cmd in checks.items():
            try:
                result = subprocess.run(
                    [sys.executable, '-c', cmd],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0:
                    deps[name] = {'installed': True, 'version': result.stdout.strip()}
                else:
                    deps[name] = {'installed': False, 'version': None}
            except Exception:
                deps[name] = {'installed': False, 'version': None}

        # Check for llama.cpp convert script
        llama_cpp_paths = [
            _PROJECT_ROOT / 'tools' / 'llama.cpp',
            Path.home() / 'llama.cpp',
            Path('/usr/local/bin/llama-quantize'),
        ]
        deps['llama_cpp'] = {'installed': False, 'path': None}
        for p in llama_cpp_paths:
            if p.exists():
                deps['llama_cpp'] = {'installed': True, 'path': str(p)}
                break

        # Check GPU
        try:
            result = subprocess.run(
                [sys.executable, '-c',
                 'import torch; print(torch.cuda.is_available()); print(torch.cuda.get_device_name(0) if torch.cuda.is_available() else "none")'],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                deps['cuda'] = {
                    'available': lines[0].strip() == 'True',
                    'device': lines[1].strip() if len(lines) > 1 else 'none',
                }
            else:
                deps['cuda'] = {'available': False, 'device': 'none'}
        except Exception:
            deps['cuda'] = {'available': False, 'device': 'none'}

        # Check Intel XPU
        try:
            result = subprocess.run(
                [sys.executable, '-c',
                 'import torch; import intel_extension_for_pytorch; print(torch.xpu.is_available())'],
                capture_output=True, text=True, timeout=15
            )
            deps['xpu'] = {'available': result.returncode == 0 and 'True' in result.stdout}
        except Exception:
            deps['xpu'] = {'available': False}

        return deps

    def install_dependencies(self):
        """Install training dependencies via pip."""
        self._status['phase'] = 'installing'
        self._status['progress'] = 0
        self._log('Installing training dependencies...')

        packages = [
            'torch', 'transformers', 'peft', 'datasets',
            'trl', 'accelerate', 'bitsandbytes',
        ]
        results = []
        for i, pkg in enumerate(packages):
            self._status['progress'] = int((i / len(packages)) * 100)
            self._status['message'] = f'Installing {pkg}...'
            self._log(f'pip install {pkg}')
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                    capture_output=True, text=True, timeout=300
                )
                results.append({
                    'package': pkg,
                    'success': result.returncode == 0,
                    'output': result.stdout.strip() or result.stderr.strip(),
                })
            except Exception as e:
                results.append({'package': pkg, 'success': False, 'output': str(e)})

        self._status['phase'] = 'idle'
        self._status['progress'] = 100
        self._status['message'] = 'Dependencies installed'
        return results

    # ==================== CODEBASE SCANNING ====================

    def scan_codebase(self):
        """Scan the AUTARCH codebase and return file inventory."""
        inventory = {
            'modules': [],
            'core': [],
            'routes': [],
            'templates': [],
            'configs': [],
            'other': [],
        }

        scan_dirs = {
            'modules': self._project_root / 'modules',
            'core': self._project_root / 'core',
            'routes': self._project_root / 'web' / 'routes',
            'templates': self._project_root / 'web' / 'templates',
        }

        for category, scan_dir in scan_dirs.items():
            if not scan_dir.exists():
                continue
            for f in sorted(scan_dir.glob('*.py' if category != 'templates' else '*.html')):
                try:
                    size = f.stat().st_size
                    lines = f.read_text(encoding='utf-8', errors='replace').count('\n')
                    inventory[category].append({
                        'name': f.name,
                        'path': str(f.relative_to(self._project_root)),
                        'size': size,
                        'lines': lines,
                    })
                except Exception:
                    pass

        # Config files
        for pattern in ['*.conf', '*.json', '*.txt']:
            for f in self._project_root.glob(pattern):
                if f.name.startswith('.'):
                    continue
                try:
                    inventory['configs'].append({
                        'name': f.name,
                        'path': str(f.relative_to(self._project_root)),
                        'size': f.stat().st_size,
                        'lines': f.read_text(encoding='utf-8', errors='replace').count('\n'),
                    })
                except Exception:
                    pass
        for f in (_DATA_DIR).glob('*.txt'):
            try:
                inventory['configs'].append({
                    'name': f'data/{f.name}',
                    'path': str(f.relative_to(self._project_root)),
                    'size': f.stat().st_size,
                    'lines': f.read_text(encoding='utf-8', errors='replace').count('\n'),
                })
            except Exception:
                pass

        # Entry point
        entry = self._project_root / 'autarch.py'
        if entry.exists():
            inventory['other'].append({
                'name': 'autarch.py',
                'path': 'autarch.py',
                'size': entry.stat().st_size,
                'lines': entry.read_text(encoding='utf-8', errors='replace').count('\n'),
            })

        # JS
        js_dir = self._project_root / 'web' / 'static' / 'js'
        if js_dir.exists():
            for f in js_dir.glob('*.js'):
                try:
                    inventory['other'].append({
                        'name': f'static/js/{f.name}',
                        'path': str(f.relative_to(self._project_root)),
                        'size': f.stat().st_size,
                        'lines': f.read_text(encoding='utf-8', errors='replace').count('\n'),
                    })
                except Exception:
                    pass

        total_files = sum(len(v) for v in inventory.values())
        total_lines = sum(item['lines'] for v in inventory.values() for item in v)
        return {
            'inventory': inventory,
            'total_files': total_files,
            'total_lines': total_lines,
        }

    # ==================== PYTHON MODULE EXTRACTION ====================

    def _extract_module_info(self, filepath):
        """Extract structured info from a Python module file."""
        try:
            source = Path(filepath).read_text(encoding='utf-8', errors='replace')
        except Exception:
            return None

        info = {
            'file': str(Path(filepath).relative_to(self._project_root)),
            'source': source,
            'docstring': '',
            'classes': [],
            'functions': [],
            'metadata': {},
        }

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return info

        # Module docstring
        if (tree.body and isinstance(tree.body[0], ast.Expr)
                and isinstance(tree.body[0].value, (ast.Constant, ast.Str))):
            info['docstring'] = getattr(tree.body[0].value, 'value',
                                        getattr(tree.body[0].value, 's', ''))

        # Module-level assignments (DESCRIPTION, AUTHOR, etc.)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, (ast.Constant, ast.Str)):
                        val = getattr(node.value, 'value', getattr(node.value, 's', ''))
                        if target.id in ('DESCRIPTION', 'AUTHOR', 'VERSION', 'CATEGORY', 'NAME'):
                            info['metadata'][target.id] = val

        # Classes and methods
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                cls_info = {
                    'name': node.name,
                    'docstring': ast.get_docstring(node) or '',
                    'methods': [],
                }
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        args = [a.arg for a in item.args.args if a.arg != 'self']
                        cls_info['methods'].append({
                            'name': item.name,
                            'args': args,
                            'docstring': ast.get_docstring(item) or '',
                            'lineno': item.lineno,
                        })
                info['classes'].append(cls_info)

            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [a.arg for a in node.args.args if a.arg != 'self']
                info['functions'].append({
                    'name': node.name,
                    'args': args,
                    'docstring': ast.get_docstring(node) or '',
                    'lineno': node.lineno,
                })

        return info

    # ==================== DATASET GENERATION ====================

    def generate_dataset(self, format='sharegpt', include_source=True,
                         include_qa=True, include_module_creation=True):
        """Generate training dataset from the AUTARCH codebase.

        Args:
            format: 'sharegpt' (conversations) or 'instruction' (alpaca-style)
            include_source: Include code understanding pairs
            include_qa: Include Q&A about architecture
            include_module_creation: Include module creation examples

        Returns:
            Dict with dataset path, sample count, preview
        """
        self._status['phase'] = 'generating'
        self._status['progress'] = 0
        self._status['message'] = 'Scanning codebase...'
        self._log('Starting dataset generation...')

        samples = []
        scan = self.scan_codebase()
        all_files = []
        for category, files in scan['inventory'].items():
            for f in files:
                all_files.append((category, f))

        total = len(all_files)

        # ── Phase 1: Code understanding pairs ──
        if include_source:
            self._log(f'Generating code understanding pairs from {total} files...')
            for i, (category, finfo) in enumerate(all_files):
                self._status['progress'] = int((i / total) * 30)
                filepath = self._project_root / finfo['path']
                if not filepath.exists():
                    continue

                if filepath.suffix == '.py':
                    mod_info = self._extract_module_info(filepath)
                    if not mod_info:
                        continue

                    # "What does this file do?" pair
                    desc = mod_info.get('docstring') or mod_info['metadata'].get('DESCRIPTION', '')
                    if desc:
                        samples.append(self._make_sample(
                            f"What does the file `{finfo['path']}` do in AUTARCH?",
                            f"`{finfo['path']}` — {desc}\n\n"
                            f"Category: {mod_info['metadata'].get('CATEGORY', 'core')}\n"
                            f"It contains {len(mod_info['classes'])} class(es) and "
                            f"{len(mod_info['functions'])} top-level function(s).",
                            format
                        ))

                    # Class/method documentation
                    for cls in mod_info['classes']:
                        if cls['methods']:
                            method_list = ', '.join(m['name'] for m in cls['methods']
                                                     if not m['name'].startswith('_'))
                            samples.append(self._make_sample(
                                f"What methods does the `{cls['name']}` class in "
                                f"`{finfo['path']}` provide?",
                                f"The `{cls['name']}` class provides these methods: "
                                f"{method_list}\n\n"
                                + (f"Class description: {cls['docstring']}" if cls['docstring'] else ''),
                                format
                            ))

                        # Individual method docs
                        for method in cls['methods']:
                            if method['docstring'] and not method['name'].startswith('_'):
                                samples.append(self._make_sample(
                                    f"What does `{cls['name']}.{method['name']}()` do?",
                                    f"`{method['name']}({', '.join(method['args'])})` — "
                                    f"{method['docstring']}",
                                    format
                                ))

                elif filepath.suffix == '.html':
                    try:
                        content = filepath.read_text(encoding='utf-8', errors='replace')
                        # Extract template purpose from title block
                        title_match = re.search(r'{%\s*block\s+title\s*%}(.+?){%', content)
                        if title_match:
                            samples.append(self._make_sample(
                                f"What is the `{finfo['path']}` template for?",
                                f"The template `{finfo['path']}` renders the "
                                f"'{title_match.group(1).strip()}' page in the AUTARCH web dashboard.",
                                format
                            ))
                    except Exception:
                        pass

        # ── Phase 2: Architecture Q&A ──
        if include_qa:
            self._status['progress'] = 30
            self._status['message'] = 'Generating architecture Q&A...'
            self._log('Generating architecture Q&A pairs...')
            samples.extend(self._generate_architecture_qa(format, scan))

        # ── Phase 3: Module creation examples ──
        if include_module_creation:
            self._status['progress'] = 60
            self._status['message'] = 'Generating module creation examples...'
            self._log('Generating module creation training data...')
            samples.extend(self._generate_module_creation_samples(format))

        # ── Phase 4: System prompt and identity ──
        self._status['progress'] = 80
        self._status['message'] = 'Adding identity and system context...'
        samples.extend(self._generate_identity_samples(format))

        # ── Save dataset ──
        self._status['progress'] = 90
        self._status['message'] = 'Saving dataset...'

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        dataset_path = self._training_dir / f'autarch_dataset_{timestamp}.jsonl'

        with open(dataset_path, 'w', encoding='utf-8') as f:
            for sample in samples:
                f.write(json.dumps(sample, ensure_ascii=False) + '\n')

        self._status['phase'] = 'idle'
        self._status['progress'] = 100
        self._status['message'] = f'Dataset generated: {len(samples)} samples'
        self._log(f'Dataset saved to {dataset_path} ({len(samples)} samples)')

        return {
            'path': str(dataset_path),
            'filename': dataset_path.name,
            'sample_count': len(samples),
            'format': format,
            'preview': samples[:5],
            'size_bytes': dataset_path.stat().st_size,
        }

    def _make_sample(self, instruction, response, format='sharegpt'):
        """Create a training sample in the specified format."""
        if format == 'sharegpt':
            return {
                'conversations': [
                    {'from': 'human', 'value': instruction},
                    {'from': 'gpt', 'value': response},
                ]
            }
        else:  # alpaca/instruction format
            return {
                'instruction': instruction,
                'input': '',
                'output': response,
            }

    def _generate_architecture_qa(self, format, scan):
        """Generate Q&A pairs about AUTARCH architecture."""
        pairs = []

        # Project overview
        pairs.append(self._make_sample(
            "What is AUTARCH?",
            "AUTARCH (Autonomous Tactical Agent for Reconnaissance, Counterintelligence, "
            "and Hacking) is an autonomous security platform built by darkHal Security Group. "
            "It provides a web-based dashboard with modular tools for defense, offense, "
            "counter-intelligence, analysis, OSINT, and attack simulation. "
            "It features an AI agent (Hal) that can create new modules on demand.",
            format
        ))

        # Directory structure
        pairs.append(self._make_sample(
            "What is the directory structure of AUTARCH?",
            "AUTARCH has this structure:\n"
            "- `modules/` — Plugin modules (Python), each is a standalone tool\n"
            "- `core/` — Framework internals (llm.py, agent.py, tools.py, config.py, wireshark.py)\n"
            "- `web/` — Flask web dashboard (routes/, templates/, static/)\n"
            "- `data/` — Databases, configs, JSON files\n"
            "- `models/` — LLM model files (GGUF)\n"
            "- `autarch.py` — Main entry point\n"
            "- `autarch_settings.conf` — Configuration file",
            format
        ))

        # Module categories
        pairs.append(self._make_sample(
            "What module categories does AUTARCH support?",
            "AUTARCH supports 6 module categories:\n"
            "1. **defense** (Blue) — Security hardening, monitoring, firewalls\n"
            "2. **offense** (Red) — Penetration testing, exploitation\n"
            "3. **counter** (Purple) — Counter-intelligence, threat response\n"
            "4. **analyze** (Cyan) — Analysis, forensics, packet inspection\n"
            "5. **osint** (Green) — Open source intelligence gathering\n"
            "6. **simulate** (Yellow) — Attack simulation, red team exercises",
            format
        ))

        # Web architecture
        pairs.append(self._make_sample(
            "How does the AUTARCH web dashboard work?",
            "The web dashboard is built with Flask and uses Jinja2 templates with vanilla "
            "JavaScript. It runs on port 8181 with HTTPS. Routes are organized as Flask "
            "Blueprints in `web/routes/`. The frontend uses SSE (Server-Sent Events) for "
            "real-time streaming. The sidebar menu links to category pages (Defense, Offense, "
            "Analyze, etc.) which load their respective modules and tools.",
            format
        ))

        # LLM integration
        pairs.append(self._make_sample(
            "How does the LLM system work in AUTARCH?",
            "AUTARCH supports multiple LLM backends:\n"
            "1. **Local GGUF** — llama-cpp-python loads .gguf models from the models/ directory\n"
            "2. **HuggingFace Transformers** — loads full models with optional 4-bit quantization\n"
            "3. **Claude API** — Anthropic's API for cloud inference\n"
            "4. **HuggingFace API** — Inference API for cloud models\n\n"
            "The `core/llm.py` module wraps all backends with a unified interface. "
            "The AI agent (Hal) uses the local GGUF model with a tool-calling loop defined "
            "in `core/agent.py`. It can execute shell commands, read/write files, search code, "
            "and create new modules via the `create_module` tool in `core/tools.py`.",
            format
        ))

        # Config system
        pairs.append(self._make_sample(
            "How is AUTARCH configured?",
            "AUTARCH uses `autarch_settings.conf` (INI format) with sections for: "
            "[llama] (GGUF model settings), [autarch] (general), [msf] (Metasploit RPC), "
            "[osint] (OSINT settings), [transformers] (HuggingFace models), [claude] (API key), "
            "[web] (dashboard host/port/secret), [wireguard] (VPN), [upnp] (port forwarding), "
            "and more. The `core/config.py` module reads and writes this file.",
            format
        ))

        # Module stats
        mod_count = len(scan['inventory'].get('modules', []))
        core_count = len(scan['inventory'].get('core', []))
        pairs.append(self._make_sample(
            "How many modules and core files does AUTARCH have?",
            f"AUTARCH has {mod_count} plugin modules in `modules/` and {core_count} core "
            f"framework files in `core/`. Total codebase is {scan['total_files']} files "
            f"with {scan['total_lines']} lines of code.",
            format
        ))

        return pairs

    def _generate_module_creation_samples(self, format):
        """Generate training data for teaching the LLM how to create modules."""
        pairs = []

        # Module creation pattern
        pairs.append(self._make_sample(
            "How do I create a new AUTARCH module?",
            "Every AUTARCH module in `modules/` must have these elements:\n\n"
            "1. **Module-level metadata**: DESCRIPTION, AUTHOR, VERSION, CATEGORY\n"
            "2. **A `run()` function** — Entry point for CLI mode\n"
            "3. **Imports**: `from core.banner import Colors` for terminal colors\n\n"
            "```python\n"
            '"""\nModule description\n"""\n'
            "import os\nimport sys\nimport subprocess\nfrom pathlib import Path\n\n"
            "DESCRIPTION = \"What this module does\"\n"
            "AUTHOR = \"darkHal\"\nVERSION = \"1.0\"\n"
            "CATEGORY = \"defense\"  # defense/offense/counter/analyze/osint/simulate\n\n"
            "sys.path.insert(0, str(Path(__file__).parent.parent))\n"
            "from core.banner import Colors\n\n\n"
            "class MyModule:\n"
            "    def print_status(self, message, status=\"info\"):\n"
            "        colors = {\"info\": Colors.CYAN, \"success\": Colors.GREEN, "
            "\"warning\": Colors.YELLOW, \"error\": Colors.RED}\n"
            "        symbols = {\"info\": \"*\", \"success\": \"+\", \"warning\": \"!\", \"error\": \"X\"}\n"
            "        print(f\"{colors.get(status, Colors.WHITE)}"
            "[{symbols.get(status, '*')}] {message}{Colors.RESET}\")\n\n"
            "    def run_cmd(self, cmd, timeout=30):\n"
            "        try:\n"
            "            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)\n"
            "            return r.returncode == 0, r.stdout.strip()\n"
            "        except Exception as e:\n"
            "            return False, str(e)\n\n\n"
            "def run():\n"
            "    mod = MyModule()\n"
            "    # Interactive menu or direct execution\n"
            "```",
            format
        ))

        # Scan existing modules for real examples
        modules_dir = self._project_root / 'modules'
        if modules_dir.exists():
            for mod_file in sorted(modules_dir.glob('*.py')):
                if mod_file.name.startswith('__'):
                    continue
                info = self._extract_module_info(mod_file)
                if not info or not info['metadata'].get('DESCRIPTION'):
                    continue

                # "Create a module like X" example
                desc = info['metadata'].get('DESCRIPTION', '')
                cat = info['metadata'].get('CATEGORY', 'analyze')
                source = info['source']

                # Only use first 3000 chars to keep training samples reasonable
                if len(source) > 3000:
                    source = source[:3000] + '\n# ... (truncated for training)\n'

                pairs.append(self._make_sample(
                    f"Create an AUTARCH module for: {desc}",
                    f"Here's a {cat} module that {desc.lower()}:\n\n```python\n{source}\n```",
                    format
                ))

        # Specific module creation scenarios
        scenarios = [
            ("Create a defense module that monitors port 5555 for incoming connections",
             "port_monitor", "defense",
             "Monitors a specific port for incoming TCP connections and alerts on new connections."),
            ("Create an OSINT module that looks up domain WHOIS information",
             "whois_lookup", "osint",
             "Performs WHOIS lookups on domains to gather registration information."),
            ("Create an analyze module that checks for open S3 buckets",
             "s3_checker", "analyze",
             "Checks if AWS S3 buckets are publicly accessible."),
        ]
        for prompt, name, cat, desc in scenarios:
            pairs.append(self._make_sample(
                prompt,
                f"I'll create the `{name}.py` module in the `{cat}` category.\n\n"
                f"```python\n"
                f'"""\n{desc}\n"""\n'
                f"import os\nimport sys\nimport subprocess\nimport socket\n"
                f"from pathlib import Path\n\n"
                f"DESCRIPTION = \"{desc}\"\n"
                f"AUTHOR = \"darkHal\"\nVERSION = \"1.0\"\n"
                f"CATEGORY = \"{cat}\"\n\n"
                f"sys.path.insert(0, str(Path(__file__).parent.parent))\n"
                f"from core.banner import Colors\n\n\n"
                f"class {name.title().replace('_', '')}:\n"
                f"    def print_status(self, msg, status='info'):\n"
                f"        colors = {{'info': Colors.CYAN, 'success': Colors.GREEN, "
                f"'warning': Colors.YELLOW, 'error': Colors.RED}}\n"
                f"        symbols = {{'info': '*', 'success': '+', 'warning': '!', 'error': 'X'}}\n"
                f"        print(f\"{{colors.get(status, Colors.WHITE)}}"
                f"[{{symbols.get(status, '*')}}] {{msg}}{{Colors.RESET}}\")\n\n"
                f"    def run_cmd(self, cmd, timeout=30):\n"
                f"        try:\n"
                f"            r = subprocess.run(cmd, shell=True, capture_output=True, "
                f"text=True, timeout=timeout)\n"
                f"            return r.returncode == 0, r.stdout.strip()\n"
                f"        except Exception as e:\n"
                f"            return False, str(e)\n\n\n"
                f"def run():\n"
                f"    mod = {name.title().replace('_', '')}()\n"
                f"    mod.print_status('Starting {desc.lower()}')\n"
                f"```\n\n"
                f"This module is saved as `modules/{name}.py` and will appear in the "
                f"{cat} category on the dashboard.",
                format
            ))

        return pairs

    def _generate_identity_samples(self, format):
        """Generate identity and behavior training data."""
        pairs = []

        pairs.append(self._make_sample(
            "Who are you?",
            "I'm Hal, the AI agent powering Project AUTARCH — an autonomous security "
            "platform built by darkHal Security Group. I can create new tools and modules, "
            "analyze code, run system commands, and help with security operations.",
            format
        ))

        pairs.append(self._make_sample(
            "What can you do?",
            "I can:\n"
            "- Create new AUTARCH modules on demand (defense, offense, analyze, etc.)\n"
            "- Read and analyze source code files\n"
            "- Execute shell commands\n"
            "- Search the codebase for patterns and files\n"
            "- Help with security analysis and tool development\n"
            "- Explain how AUTARCH works\n"
            "- Write Python code following AUTARCH's module patterns",
            format
        ))

        pairs.append(self._make_sample(
            "What tools do you have access to?",
            "I have these tools:\n"
            "- `shell` — Execute system commands\n"
            "- `read_file` — Read file contents\n"
            "- `write_file` — Write files\n"
            "- `list_dir` — List directory contents\n"
            "- `search_files` — Search for files by name\n"
            "- `search_content` — Search file contents (grep)\n"
            "- `create_module` — Create a new AUTARCH module (validates and saves to modules/)\n\n"
            "When asked to create a module, I use the `create_module` tool which validates "
            "the code has the required metadata (DESCRIPTION, AUTHOR, VERSION, CATEGORY) and "
            "a `run()` function, then saves it to the `modules/` directory.",
            format
        ))

        return pairs

    # ==================== LIST DATASETS ====================

    def list_datasets(self):
        """List generated training datasets."""
        datasets = []
        if self._training_dir.exists():
            for f in sorted(self._training_dir.glob('*.jsonl'), reverse=True):
                try:
                    line_count = sum(1 for _ in open(f, encoding='utf-8'))
                    datasets.append({
                        'filename': f.name,
                        'path': str(f),
                        'size_bytes': f.stat().st_size,
                        'sample_count': line_count,
                        'created': datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                    })
                except Exception:
                    pass
        return datasets

    def preview_dataset(self, filename, limit=10):
        """Preview samples from a dataset file."""
        filepath = self._training_dir / filename
        if not filepath.exists():
            return {'error': 'Dataset not found'}

        samples = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for i, line in enumerate(f):
                    if i >= limit:
                        break
                    samples.append(json.loads(line))
        except Exception as e:
            return {'error': str(e)}

        return {'filename': filename, 'samples': samples, 'total': i + 1 if samples else 0}

    def delete_dataset(self, filename):
        """Delete a dataset file."""
        filepath = self._training_dir / filename
        if filepath.exists() and filepath.suffix == '.jsonl':
            filepath.unlink()
            return True
        return False

    # ==================== TRAINING ====================

    def get_training_config(self):
        """Get default training configuration."""
        return {
            'base_model': '',
            'dataset': '',
            'output_dir': str(self._training_dir / 'output'),
            'lora_r': 16,
            'lora_alpha': 32,
            'lora_dropout': 0.05,
            'num_epochs': 3,
            'batch_size': 4,
            'gradient_accumulation_steps': 4,
            'learning_rate': 2e-4,
            'max_seq_length': 2048,
            'warmup_ratio': 0.03,
            'use_4bit': True,
            'use_unsloth': False,
            'save_steps': 50,
            'logging_steps': 10,
        }

    def browse_models(self, directory=''):
        """Browse local directories for model files (HuggingFace format)."""
        if not directory:
            directory = str(self._models_dir)
        target = Path(directory)
        if not target.exists():
            return {'error': f'Directory not found: {directory}', 'entries': []}

        entries = []
        try:
            for item in sorted(target.iterdir()):
                if item.name.startswith('.'):
                    continue
                entry = {
                    'name': item.name,
                    'path': str(item).replace('\\', '/'),
                    'is_dir': item.is_dir(),
                }
                if item.is_dir():
                    # Check if it looks like a HuggingFace model directory
                    has_config = (item / 'config.json').exists()
                    has_model = any(item.glob('*.safetensors')) or any(item.glob('*.bin'))
                    entry['is_model'] = has_config and has_model
                elif item.suffix in ('.gguf', '.bin', '.safetensors'):
                    entry['size_gb'] = round(item.stat().st_size / (1024**3), 2)
                entries.append(entry)
        except PermissionError:
            return {'error': f'Permission denied: {directory}', 'entries': []}

        return {
            'current_dir': str(target).replace('\\', '/'),
            'parent_dir': str(target.parent).replace('\\', '/') if target.parent != target else None,
            'entries': entries,
        }

    def start_training(self, config):
        """Start LoRA fine-tuning in a background process."""
        if self._training_process and self._training_process.poll() is None:
            return {'error': 'Training already in progress'}

        # Check critical dependencies before starting
        deps = self.check_dependencies()
        missing = []
        for pkg in ['torch', 'transformers', 'peft', 'datasets', 'trl']:
            if not deps.get(pkg, {}).get('installed'):
                missing.append(pkg)
        if missing:
            return {'error': f'Missing required packages: {", ".join(missing)}. Go to the Dependencies tab to install them.'}

        self._status['phase'] = 'training'
        self._status['progress'] = 0
        self._status['message'] = 'Starting training...'
        self._log('Starting LoRA fine-tuning...')

        # Generate the training script
        script_path = self._training_dir / 'train_lora.py'
        output_dir = Path(config.get('output_dir', str(self._training_dir / 'output')))
        output_dir.mkdir(parents=True, exist_ok=True)
        config['output_dir'] = str(output_dir)

        script = self._generate_training_script(config)
        script_path.write_text(script, encoding='utf-8')
        self._log(f'Training script written to {script_path}')

        # Run in background
        log_path = self._training_dir / 'training.log'
        try:
            with open(log_path, 'w') as log_file:
                self._training_process = subprocess.Popen(
                    [sys.executable, str(script_path)],
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    cwd=str(self._project_root),
                )
            self._log(f'Training started (PID: {self._training_process.pid})')
            return {
                'success': True,
                'pid': self._training_process.pid,
                'log_path': str(log_path),
                'output_dir': str(output_dir),
            }
        except Exception as e:
            self._status['phase'] = 'idle'
            self._log(f'Failed to start training: {e}', 'error')
            return {'error': str(e)}

    def _generate_training_script(self, config):
        """Generate the LoRA training Python script."""
        # Use forward slashes for all paths to avoid Python escape sequence issues
        dataset_path = config.get('dataset', '').replace('\\', '/')
        base_model = config.get('base_model', '').replace('\\', '/')
        output_dir = config.get('output_dir', str(self._training_dir / 'output')).replace('\\', '/')

        use_unsloth = config.get('use_unsloth', False)

        if use_unsloth:
            return f'''#!/usr/bin/env python3
"""AUTARCH LoRA Training Script (Unsloth)"""
import json
from unsloth import FastLanguageModel
from datasets import Dataset
from trl import SFTTrainer
from transformers import TrainingArguments

# Load model
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="{base_model}",
    max_seq_length={config.get('max_seq_length', 2048)},
    load_in_4bit={config.get('use_4bit', True)},
)

# Add LoRA adapters
model = FastLanguageModel.get_peft_model(
    model,
    r={config.get('lora_r', 16)},
    lora_alpha={config.get('lora_alpha', 32)},
    lora_dropout={config.get('lora_dropout', 0.05)},
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                     "gate_proj", "up_proj", "down_proj"],
)

# Load dataset
samples = []
with open("{dataset_path}", "r") as f:
    for line in f:
        samples.append(json.loads(line))

def format_sample(sample):
    if "conversations" in sample:
        msgs = sample["conversations"]
        text = ""
        for msg in msgs:
            role = "user" if msg["from"] == "human" else "assistant"
            text += f"<|im_start|>{{role}}\\n{{msg['value']}}<|im_end|>\\n"
        return {{"text": text}}
    else:
        return {{"text": f"<|im_start|>user\\n{{sample['instruction']}}\\n{{sample.get('input','')}}<|im_end|>\\n<|im_start|>assistant\\n{{sample['output']}}<|im_end|>\\n"}}

dataset = Dataset.from_list([format_sample(s) for s in samples])

# Train
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length={config.get('max_seq_length', 2048)},
    args=TrainingArguments(
        output_dir="{output_dir}",
        num_train_epochs={config.get('num_epochs', 3)},
        per_device_train_batch_size={config.get('batch_size', 4)},
        gradient_accumulation_steps={config.get('gradient_accumulation_steps', 4)},
        learning_rate={config.get('learning_rate', 2e-4)},
        warmup_ratio={config.get('warmup_ratio', 0.03)},
        save_steps={config.get('save_steps', 50)},
        logging_steps={config.get('logging_steps', 10)},
        fp16=True,
        optim="adamw_8bit",
    ),
)

print("Starting training...")
trainer.train()
print("Training complete!")

# Save
model.save_pretrained("{output_dir}/lora_adapter")
tokenizer.save_pretrained("{output_dir}/lora_adapter")
print(f"LoRA adapter saved to {output_dir}/lora_adapter")
'''
        else:
            return f'''#!/usr/bin/env python3
"""AUTARCH LoRA Training Script (Transformers + PEFT)"""
import json
import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# Quantization config
bnb_config = BitsAndBytesConfig(
    load_in_4bit={config.get('use_4bit', True)},
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
) if {config.get('use_4bit', True)} else None

print("Loading base model: {base_model}")
model = AutoModelForCausalLM.from_pretrained(
    "{base_model}",
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=False,
)
tokenizer = AutoTokenizer.from_pretrained("{base_model}", trust_remote_code=False)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

if {config.get('use_4bit', True)}:
    model = prepare_model_for_kbit_training(model)

# LoRA config
lora_config = LoraConfig(
    r={config.get('lora_r', 16)},
    lora_alpha={config.get('lora_alpha', 32)},
    lora_dropout={config.get('lora_dropout', 0.05)},
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                     "gate_proj", "up_proj", "down_proj"],
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# Load dataset
samples = []
with open("{dataset_path}", "r") as f:
    for line in f:
        samples.append(json.loads(line))

def format_sample(sample):
    if "conversations" in sample:
        msgs = sample["conversations"]
        text = ""
        for msg in msgs:
            role = "user" if msg["from"] == "human" else "assistant"
            text += f"<|im_start|>{{role}}\\n{{msg['value']}}<|im_end|>\\n"
        return {{"text": text}}
    else:
        return {{"text": f"<|im_start|>user\\n{{sample['instruction']}}\\n{{sample.get('input','')}}<|im_end|>\\n<|im_start|>assistant\\n{{sample['output']}}<|im_end|>\\n"}}

dataset = Dataset.from_list([format_sample(s) for s in samples])
print(f"Dataset: {{len(dataset)}} samples")

# Train
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length={config.get('max_seq_length', 2048)},
    args=TrainingArguments(
        output_dir="{output_dir}",
        num_train_epochs={config.get('num_epochs', 3)},
        per_device_train_batch_size={config.get('batch_size', 4)},
        gradient_accumulation_steps={config.get('gradient_accumulation_steps', 4)},
        learning_rate={config.get('learning_rate', 2e-4)},
        warmup_ratio={config.get('warmup_ratio', 0.03)},
        save_steps={config.get('save_steps', 50)},
        logging_steps={config.get('logging_steps', 10)},
        fp16=True,
        optim="adamw_8bit",
        report_to="none",
    ),
)

print("Starting training...")
trainer.train()
print("Training complete!")

# Save
model.save_pretrained("{output_dir}/lora_adapter")
tokenizer.save_pretrained("{output_dir}/lora_adapter")
print(f"LoRA adapter saved to {output_dir}/lora_adapter")
'''

    def get_training_status(self):
        """Get current training status including log tail."""
        result = dict(self._status)

        if self._training_process:
            poll = self._training_process.poll()
            if poll is None:
                result['training_running'] = True
                result['pid'] = self._training_process.pid
            else:
                result['training_running'] = False
                result['exit_code'] = poll
                if self._status['phase'] == 'training':
                    self._status['phase'] = 'idle'
                    self._status['message'] = 'Training finished' if poll == 0 else f'Training failed (exit {poll})'
        else:
            result['training_running'] = False

        # Read training log tail
        log_path = self._training_dir / 'training.log'
        if log_path.exists():
            try:
                lines = log_path.read_text(encoding='utf-8', errors='replace').split('\n')
                result['training_log'] = '\n'.join(lines[-50:])
            except Exception:
                result['training_log'] = ''
        else:
            result['training_log'] = ''

        return result

    def stop_training(self):
        """Stop the running training process."""
        if self._training_process and self._training_process.poll() is None:
            self._training_process.terminate()
            self._training_process.wait(timeout=10)
            self._status['phase'] = 'idle'
            self._status['message'] = 'Training stopped by user'
            self._log('Training stopped by user', 'warning')
            return True
        return False

    # ==================== GGUF CONVERSION ====================

    def list_adapters(self):
        """List saved LoRA adapters."""
        adapters = []
        output_dir = self._training_dir / 'output'
        if output_dir.exists():
            for d in output_dir.iterdir():
                if d.is_dir():
                    config_path = d / 'adapter_config.json'
                    if config_path.exists():
                        try:
                            config = json.loads(config_path.read_text())
                            adapters.append({
                                'name': d.name,
                                'path': str(d),
                                'base_model': config.get('base_model_name_or_path', ''),
                                'r': config.get('r', 0),
                                'lora_alpha': config.get('lora_alpha', 0),
                            })
                        except Exception:
                            adapters.append({'name': d.name, 'path': str(d)})
        return adapters

    def merge_and_convert(self, adapter_path, output_name, quantization='Q5_K_M'):
        """Merge LoRA adapter with base model and convert to GGUF.

        This is a multi-step process:
        1. Load base model + LoRA adapter
        2. Merge weights
        3. Save merged model
        4. Convert to GGUF format
        5. Quantize
        """
        self._status['phase'] = 'converting'
        self._status['progress'] = 0
        self._status['message'] = 'Starting merge and conversion...'
        self._log(f'Starting merge: adapter={adapter_path}, quant={quantization}')

        merged_dir = self._training_dir / 'merged'
        merged_dir.mkdir(parents=True, exist_ok=True)
        output_path = self._models_dir / f'{output_name}.gguf'

        # Generate merge+convert script
        script = f'''#!/usr/bin/env python3
"""Merge LoRA adapter and convert to GGUF."""
import json, sys
from pathlib import Path

adapter_path = Path("{adapter_path}")
config_path = adapter_path / "adapter_config.json"
if not config_path.exists():
    print("ERROR: adapter_config.json not found")
    sys.exit(1)

config = json.loads(config_path.read_text())
base_model = config.get("base_model_name_or_path", "")
if not base_model:
    print("ERROR: No base_model_name_or_path in adapter config")
    sys.exit(1)

print(f"Base model: {{base_model}}")
print(f"Adapter: {{adapter_path}}")

# Step 1: Load and merge
print("Loading base model...")
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

model = AutoModelForCausalLM.from_pretrained(base_model, device_map="cpu")
tokenizer = AutoTokenizer.from_pretrained(base_model)

print("Loading LoRA adapter...")
model = PeftModel.from_pretrained(model, str(adapter_path))

print("Merging weights...")
model = model.merge_and_unload()

merged_path = "{merged_dir}"
print(f"Saving merged model to {{merged_path}}")
model.save_pretrained(merged_path)
tokenizer.save_pretrained(merged_path)
print("Merge complete!")
'''
        script_path = self._training_dir / 'merge_model.py'
        script_path.write_text(script, encoding='utf-8')

        # Run merge
        self._status['message'] = 'Merging LoRA adapter with base model...'
        self._status['progress'] = 10
        try:
            result = subprocess.run(
                [sys.executable, str(script_path)],
                capture_output=True, text=True, timeout=1800  # 30 min max
            )
            if result.returncode != 0:
                self._log(f'Merge failed: {result.stderr}', 'error')
                self._status['phase'] = 'idle'
                return {'error': f'Merge failed: {result.stderr[-500:]}'}
            self._log('Merge complete')
        except subprocess.TimeoutExpired:
            self._status['phase'] = 'idle'
            return {'error': 'Merge timed out (30 min limit)'}

        # Convert to GGUF using llama.cpp convert script
        self._status['message'] = 'Converting to GGUF format...'
        self._status['progress'] = 60

        # Try to find llama.cpp convert script
        convert_script = None
        search_paths = [
            self._project_root / 'tools' / 'llama.cpp' / 'convert_hf_to_gguf.py',
            Path.home() / 'llama.cpp' / 'convert_hf_to_gguf.py',
        ]
        for p in search_paths:
            if p.exists():
                convert_script = p
                break

        if not convert_script:
            # Try pip-installed llama-cpp-python convert
            self._log('llama.cpp convert script not found, trying pip package...', 'warning')
            try:
                result = subprocess.run(
                    [sys.executable, '-m', 'llama_cpp.convert',
                     str(merged_dir), '--outfile', str(output_path),
                     '--outtype', quantization.lower()],
                    capture_output=True, text=True, timeout=1800
                )
                if result.returncode == 0:
                    self._status['phase'] = 'idle'
                    self._status['progress'] = 100
                    self._log(f'GGUF saved to {output_path}')
                    return {
                        'success': True,
                        'output_path': str(output_path),
                        'size_bytes': output_path.stat().st_size if output_path.exists() else 0,
                    }
            except Exception:
                pass

            self._status['phase'] = 'idle'
            self._status['message'] = 'Merged model saved but GGUF conversion requires llama.cpp'
            return {
                'partial': True,
                'merged_path': str(merged_dir),
                'message': 'Model merged successfully. To convert to GGUF, install llama.cpp '
                           'and run: python convert_hf_to_gguf.py <merged_path> --outfile <output.gguf>',
            }

        # Run convert script
        try:
            result = subprocess.run(
                [sys.executable, str(convert_script),
                 str(merged_dir), '--outfile', str(output_path),
                 '--outtype', 'f16'],
                capture_output=True, text=True, timeout=1800
            )
            if result.returncode != 0:
                self._status['phase'] = 'idle'
                return {'error': f'GGUF conversion failed: {result.stderr[-500:]}'}
        except subprocess.TimeoutExpired:
            self._status['phase'] = 'idle'
            return {'error': 'GGUF conversion timed out'}

        # Quantize if not f16
        if quantization.upper() != 'F16':
            self._status['message'] = f'Quantizing to {quantization}...'
            self._status['progress'] = 80

            quantize_bin = None
            for p in [self._project_root / 'tools' / 'llama.cpp' / 'llama-quantize',
                       Path.home() / 'llama.cpp' / 'llama-quantize',
                       Path('/usr/local/bin/llama-quantize')]:
                if p.exists():
                    quantize_bin = p
                    break
                # Check .exe variant on Windows
                p_exe = p.with_suffix('.exe')
                if p_exe.exists():
                    quantize_bin = p_exe
                    break

            if quantize_bin:
                quant_output = output_path.with_stem(f'{output_name}_{quantization}')
                try:
                    result = subprocess.run(
                        [str(quantize_bin), str(output_path),
                         str(quant_output), quantization],
                        capture_output=True, text=True, timeout=1800
                    )
                    if result.returncode == 0:
                        # Replace f16 with quantized version
                        output_path.unlink()
                        shutil.move(str(quant_output), str(output_path))
                        self._log(f'Quantized to {quantization}')
                except Exception as e:
                    self._log(f'Quantization failed: {e}', 'warning')

        self._status['phase'] = 'idle'
        self._status['progress'] = 100
        self._status['message'] = f'GGUF model saved: {output_path.name}'
        self._log(f'GGUF model saved to {output_path}')

        return {
            'success': True,
            'output_path': str(output_path),
            'size_bytes': output_path.stat().st_size if output_path.exists() else 0,
        }

    def list_models(self):
        """List available GGUF models."""
        models = []
        if self._models_dir.exists():
            for f in sorted(self._models_dir.glob('*.gguf')):
                models.append({
                    'name': f.stem,
                    'filename': f.name,
                    'path': str(f),
                    'size_bytes': f.stat().st_size,
                    'size_gb': round(f.stat().st_size / (1024**3), 2),
                    'modified': datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                })
        return models

    # ==================== EVALUATION ====================

    def evaluate_model(self, model_path, test_prompts=None):
        """Quick evaluation of a GGUF model with test prompts."""
        if not test_prompts:
            test_prompts = [
                "What is AUTARCH?",
                "How do I create a new defense module?",
                "What module categories does AUTARCH support?",
                "Create a module that scans for open ports on localhost.",
            ]

        self._status['phase'] = 'evaluating'
        self._status['message'] = 'Loading model for evaluation...'
        self._log(f'Evaluating model: {model_path}')

        results = []
        try:
            from core.llm import LLM
            llm = LLM()
            llm.load_model(model_path)

            for i, prompt in enumerate(test_prompts):
                self._status['progress'] = int((i / len(test_prompts)) * 100)
                self._status['message'] = f'Testing prompt {i+1}/{len(test_prompts)}...'

                response = llm.generate(prompt, max_tokens=512)
                results.append({
                    'prompt': prompt,
                    'response': response,
                    'length': len(response),
                })

        except Exception as e:
            self._status['phase'] = 'idle'
            return {'error': str(e)}

        self._status['phase'] = 'idle'
        self._status['progress'] = 100
        self._status['message'] = 'Evaluation complete'
        return {'results': results, 'model': model_path}


# ==================== SINGLETON ====================

_trainer_instance = None


def get_trainer():
    """Get or create singleton LLMTrainer instance."""
    global _trainer_instance
    if _trainer_instance is None:
        _trainer_instance = LLMTrainer()
    return _trainer_instance


# ==================== CLI ====================

def run():
    """CLI entry point."""
    from core.banner import Colors, clear_screen, display_banner
    clear_screen()
    display_banner()
    print(f"\n{Colors.BOLD}{Colors.CYAN}LLM Trainer{Colors.RESET}\n")

    trainer = LLMTrainer()

    print(f"{Colors.CYAN}[*] Checking dependencies...{Colors.RESET}")
    deps = trainer.check_dependencies()
    for name, info in deps.items():
        if isinstance(info, dict) and 'installed' in info:
            status = f"{Colors.GREEN}v{info['version']}{Colors.RESET}" if info['installed'] else f"{Colors.RED}Not installed{Colors.RESET}"
            print(f"  {name}: {status}")

    print(f"\n{Colors.CYAN}[*] Scanning codebase...{Colors.RESET}")
    scan = trainer.scan_codebase()
    print(f"  Files: {scan['total_files']}")
    print(f"  Lines: {scan['total_lines']}")

    while True:
        print(f"\n{Colors.BOLD}Options:{Colors.RESET}")
        print("  1. Generate training dataset")
        print("  2. List datasets")
        print("  3. Check dependencies")
        print("  4. Install dependencies")
        print("  0. Exit")

        choice = input(f"\n{Colors.CYAN}Select: {Colors.RESET}").strip()
        if choice == '1':
            result = trainer.generate_dataset()
            print(f"\n{Colors.GREEN}[+] Generated {result['sample_count']} samples{Colors.RESET}")
            print(f"  File: {result['path']}")
        elif choice == '2':
            datasets = trainer.list_datasets()
            for d in datasets:
                print(f"  {d['filename']} — {d['sample_count']} samples, "
                      f"{d['size_bytes']//1024}KB")
        elif choice == '3':
            deps = trainer.check_dependencies()
            for name, info in deps.items():
                if isinstance(info, dict) and 'installed' in info:
                    status = f"{Colors.GREEN}v{info['version']}{Colors.RESET}" if info['installed'] else f"{Colors.RED}Missing{Colors.RESET}"
                    print(f"  {name}: {status}")
        elif choice == '4':
            results = trainer.install_dependencies()
            for r in results:
                status = f"{Colors.GREEN}OK{Colors.RESET}" if r['success'] else f"{Colors.RED}FAIL{Colors.RESET}"
                print(f"  {r['package']}: {status}")
        elif choice == '0':
            break

    input("\nPress Enter to continue...")
