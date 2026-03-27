"""LLM Trainer routes — dataset generation, fine-tuning, GGUF conversion."""

import json
from flask import Blueprint, render_template, request, jsonify, Response, stream_with_context
from web.auth import login_required

llm_trainer_bp = Blueprint('llm_trainer', __name__, url_prefix='/llm-trainer')


def _get_trainer():
    from modules.llm_trainer import get_trainer
    return get_trainer()


# ==================== PAGE ====================

@llm_trainer_bp.route('/')
@login_required
def index():
    return render_template('llm_trainer.html')


# ==================== DEPENDENCIES ====================

@llm_trainer_bp.route('/deps', methods=['POST'])
@login_required
def check_deps():
    """Check training dependencies."""
    return jsonify(_get_trainer().check_dependencies())


@llm_trainer_bp.route('/deps/install', methods=['POST'])
@login_required
def install_deps():
    """Install training dependencies."""
    results = _get_trainer().install_dependencies()
    return jsonify({'results': results})


# ==================== CODEBASE ====================

@llm_trainer_bp.route('/scan', methods=['POST'])
@login_required
def scan_codebase():
    """Scan the AUTARCH codebase."""
    return jsonify(_get_trainer().scan_codebase())


# ==================== DATASET ====================

@llm_trainer_bp.route('/dataset/generate', methods=['POST'])
@login_required
def generate_dataset():
    """Generate training dataset from codebase."""
    data = request.get_json(silent=True) or {}
    result = _get_trainer().generate_dataset(
        format=data.get('format', 'sharegpt'),
        include_source=data.get('include_source', True),
        include_qa=data.get('include_qa', True),
        include_module_creation=data.get('include_module_creation', True),
    )
    return jsonify(result)


@llm_trainer_bp.route('/dataset/list')
@login_required
def list_datasets():
    """List generated datasets."""
    return jsonify({'datasets': _get_trainer().list_datasets()})


@llm_trainer_bp.route('/dataset/preview', methods=['POST'])
@login_required
def preview_dataset():
    """Preview samples from a dataset."""
    data = request.get_json(silent=True) or {}
    filename = data.get('filename', '')
    limit = int(data.get('limit', 10))
    return jsonify(_get_trainer().preview_dataset(filename, limit))


@llm_trainer_bp.route('/dataset/delete', methods=['POST'])
@login_required
def delete_dataset():
    """Delete a dataset file."""
    data = request.get_json(silent=True) or {}
    filename = data.get('filename', '')
    success = _get_trainer().delete_dataset(filename)
    return jsonify({'success': success})


# ==================== MODEL BROWSER ====================

@llm_trainer_bp.route('/browse', methods=['POST'])
@login_required
def browse_models():
    """Browse local directories for model files."""
    data = request.get_json(silent=True) or {}
    directory = data.get('directory', '')
    return jsonify(_get_trainer().browse_models(directory))


# ==================== TRAINING ====================

@llm_trainer_bp.route('/train/config')
@login_required
def get_training_config():
    """Get default training configuration."""
    return jsonify(_get_trainer().get_training_config())


@llm_trainer_bp.route('/train/start', methods=['POST'])
@login_required
def start_training():
    """Start LoRA fine-tuning."""
    config = request.get_json(silent=True) or {}
    return jsonify(_get_trainer().start_training(config))


@llm_trainer_bp.route('/train/status')
@login_required
def training_status():
    """Get training status and log."""
    return jsonify(_get_trainer().get_training_status())


@llm_trainer_bp.route('/train/stop', methods=['POST'])
@login_required
def stop_training():
    """Stop training."""
    success = _get_trainer().stop_training()
    return jsonify({'success': success})


# ==================== CONVERSION ====================

@llm_trainer_bp.route('/adapters')
@login_required
def list_adapters():
    """List saved LoRA adapters."""
    return jsonify({'adapters': _get_trainer().list_adapters()})


@llm_trainer_bp.route('/convert', methods=['POST'])
@login_required
def merge_and_convert():
    """Merge LoRA adapter and convert to GGUF."""
    data = request.get_json(silent=True) or {}
    adapter_path = data.get('adapter_path', '')
    output_name = data.get('output_name', 'autarch_model')
    quantization = data.get('quantization', 'Q5_K_M')
    return jsonify(_get_trainer().merge_and_convert(adapter_path, output_name, quantization))


@llm_trainer_bp.route('/models')
@login_required
def list_models():
    """List GGUF models."""
    return jsonify({'models': _get_trainer().list_models()})


# ==================== EVALUATION ====================

@llm_trainer_bp.route('/evaluate', methods=['POST'])
@login_required
def evaluate_model():
    """Evaluate a GGUF model with test prompts."""
    data = request.get_json(silent=True) or {}
    model_path = data.get('model_path', '')
    prompts = data.get('prompts', None)
    return jsonify(_get_trainer().evaluate_model(model_path, prompts))


# ==================== STATUS ====================

@llm_trainer_bp.route('/status')
@login_required
def get_status():
    """Get trainer status."""
    return jsonify(_get_trainer().get_status())
