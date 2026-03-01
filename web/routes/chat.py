"""Chat and Agent API routes — LLM chat SSE stream + autonomous agent run/stream/stop."""

import json
import threading
import time
import uuid
from flask import Blueprint, request, jsonify, Response
from web.auth import login_required

chat_bp = Blueprint('chat', __name__, url_prefix='/api')

_agent_runs: dict = {}  # run_id -> {'steps': [], 'done': bool, 'stop': threading.Event}


@chat_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    """Stream LLM response token-by-token via SSE."""
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    if not message:
        return jsonify({'error': 'No message provided'})

    def generate():
        try:
            from core.llm import get_llm
            llm = get_llm()
            for token in llm.chat(message, stream=True):
                yield f"data: {json.dumps({'token': token})}\n\n"
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@chat_bp.route('/chat/reset', methods=['POST'])
@login_required
def chat_reset():
    """Clear LLM conversation history."""
    try:
        from core.llm import get_llm
        llm = get_llm()
        if hasattr(llm, 'reset'):
            llm.reset()
        elif hasattr(llm, 'conversation_history'):
            llm.conversation_history = []
    except Exception:
        pass
    return jsonify({'ok': True})


@chat_bp.route('/agent/run', methods=['POST'])
@login_required
def agent_run():
    """Start an autonomous agent run in a background thread. Returns run_id."""
    data = request.get_json(silent=True) or {}
    task = data.get('task', '').strip()
    if not task:
        return jsonify({'error': 'No task provided'})

    run_id = str(uuid.uuid4())
    stop_event = threading.Event()
    steps = []
    _agent_runs[run_id] = {'steps': steps, 'done': False, 'stop': stop_event}

    def worker():
        try:
            from core.agent import Agent
            from core.tools import get_tool_registry
            agent = Agent(tool_registry=get_tool_registry(), verbose=False)

            def on_step(step):
                steps.append({'type': 'thought', 'content': step.thought})
                if step.tool_name and step.tool_name not in ('task_complete', 'ask_user'):
                    steps.append({'type': 'action', 'content': f"{step.tool_name}({json.dumps(step.tool_args or {})})"})
                if step.tool_result:
                    steps.append({'type': 'result', 'content': step.tool_result[:600]})

            agent.run(task, step_callback=on_step)
        except Exception as e:
            steps.append({'type': 'error', 'content': str(e)})
        finally:
            _agent_runs[run_id]['done'] = True

    threading.Thread(target=worker, daemon=True).start()
    return jsonify({'run_id': run_id})


@chat_bp.route('/agent/stream/<run_id>')
@login_required
def agent_stream(run_id):
    """SSE stream of agent steps for a given run_id."""
    def generate():
        run = _agent_runs.get(run_id)
        if not run:
            yield f"data: {json.dumps({'error': 'Run not found'})}\n\n"
            return
        sent = 0
        while True:
            steps = run['steps']
            while sent < len(steps):
                yield f"data: {json.dumps(steps[sent])}\n\n"
                sent += 1
            if run['done']:
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
            time.sleep(0.15)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@chat_bp.route('/agent/stop/<run_id>', methods=['POST'])
@login_required
def agent_stop(run_id):
    """Signal a running agent to stop."""
    run = _agent_runs.get(run_id)
    if run:
        run['stop'].set()
        run['done'] = True
    return jsonify({'stopped': bool(run)})
