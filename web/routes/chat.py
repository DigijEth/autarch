"""Chat and Agent API routes — Hal chat with Agent system for module creation."""

import json
import os
import threading
import time
import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, Response
from web.auth import login_required

chat_bp = Blueprint('chat', __name__, url_prefix='/api')

_agent_runs: dict = {}  # run_id -> {'steps': [], 'done': bool, 'stop': threading.Event}
_system_prompt = None


def _get_system_prompt():
    """Load the Hal system prompt from data/hal_system_prompt.txt."""
    global _system_prompt
    if _system_prompt is None:
        prompt_path = Path(__file__).parent.parent.parent / 'data' / 'hal_system_prompt.txt'
        if prompt_path.exists():
            _system_prompt = prompt_path.read_text(encoding='utf-8')
        else:
            _system_prompt = (
                "You are Hal, the AI agent for AUTARCH. You can create new modules, "
                "run shell commands, read and write files. When asked to create a module, "
                "use the create_module tool."
            )
    return _system_prompt


def _ensure_model_loaded():
    """Load the LLM model if not already loaded. Returns (llm, error)."""
    from core.llm import get_llm, LLMError
    llm = get_llm()
    if not llm.is_loaded:
        try:
            llm.load_model(verbose=False)
        except LLMError as e:
            return None, str(e)
    return llm, None


@chat_bp.route('/chat', methods=['POST'])
@login_required
def chat():
    """Handle chat messages — direct chat or agent mode based on user toggle.
    Streams response via SSE."""
    data = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    mode = data.get('mode', 'chat')  # 'chat' (default) or 'agent'
    if not message:
        return jsonify({'error': 'No message provided'})

    # Store in HAL's encrypted memory
    try:
        from core.hal_memory import get_hal_memory
        mem = get_hal_memory()
        mem.add('user', message, metadata={'mode': mode})
    except Exception:
        pass

    if mode == 'agent':
        return _handle_agent_chat(message)
    else:
        return _handle_direct_chat(message)


def _handle_direct_chat(message):
    """Direct chat mode — streams tokens from the LLM without the Agent system."""
    def generate():
        from core.llm import get_llm, LLMError

        llm = get_llm()
        if not llm.is_loaded:
            yield f"data: {json.dumps({'type': 'status', 'content': 'Loading model...'})}\n\n"
            try:
                llm.load_model(verbose=False)
            except LLMError as e:
                yield f"data: {json.dumps({'type': 'error', 'content': f'Failed to load model: {e}'})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
                return

        system_prompt = _get_system_prompt()
        try:
            token_gen = llm.chat(message, system_prompt=system_prompt, stream=True)
            full_response = []
            for token in token_gen:
                full_response.append(token)
                yield f"data: {json.dumps({'token': token})}\n\n"
            # Store HAL's response in memory
            try:
                from core.hal_memory import get_hal_memory
                get_hal_memory().add('hal', ''.join(full_response))
            except Exception:
                pass
        except LLMError as e:
            yield f"data: {json.dumps({'type': 'error', 'content': str(e)})}\n\n"

        yield f"data: {json.dumps({'done': True})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


def _handle_agent_chat(message):
    """Agent mode — uses the Agent system with tools for complex tasks."""
    run_id = str(uuid.uuid4())
    stop_event = threading.Event()
    steps = []
    _agent_runs[run_id] = {'steps': steps, 'done': False, 'stop': stop_event}

    def worker():
        try:
            from core.agent import Agent
            from core.tools import get_tool_registry
            from core.llm import get_llm, LLMError

            llm = get_llm()
            if not llm.is_loaded:
                steps.append({'type': 'status', 'content': 'Loading model...'})
                try:
                    llm.load_model(verbose=False)
                except LLMError as e:
                    steps.append({'type': 'error', 'content': f'Failed to load model: {e}'})
                    return

            tools = get_tool_registry()
            agent = Agent(llm=llm, tools=tools, max_steps=20, verbose=False)

            # Inject system prompt — keep the THOUGHT/ACTION/PARAMS format from Agent,
            # prepend with our behavioral rules
            hal_prompt = _get_system_prompt()
            agent.SYSTEM_PROMPT = hal_prompt + """

FORMAT — you MUST use this exact format:

THOUGHT: your reasoning
ACTION: tool_name
PARAMS: {{"param": "value"}}

When done:  ACTION: task_complete  PARAMS: {{"summary": "what was done"}}
When you need input:  ACTION: ask_user  PARAMS: {{"question": "your question"}}

{tools_description}
"""

            def on_step(step):
                # Check stop signal
                if stop_event.is_set():
                    return
                if step.thought:
                    steps.append({'type': 'thought', 'content': step.thought})
                if step.tool_name and step.tool_name not in ('task_complete', 'ask_user'):
                    steps.append({'type': 'action', 'content': f"{step.tool_name}({json.dumps(step.tool_args or {})})"})
                if step.tool_result:
                    result = step.tool_result
                    if len(result) > 800:
                        result = result[:800] + '...'
                    steps.append({'type': 'result', 'content': result})

            result = agent.run(message, step_callback=on_step)

            if result.success:
                steps.append({'type': 'answer', 'content': result.summary})
            else:
                steps.append({'type': 'error', 'content': result.error or result.summary})

            # Store agent conversation in HAL memory
            try:
                from core.hal_memory import get_hal_memory
                mem = get_hal_memory()
                for step in result.steps:
                    if step.thought:
                        mem.add('hal_thought', step.thought)
                    if step.tool_name:
                        mem.add('hal_action', f'{step.tool_name}({json.dumps(step.tool_args or {})})')
                    if step.tool_result:
                        mem.add('hal_result', step.tool_result[:2000])
                mem.add('hal', result.summary if result.success else (result.error or result.summary))
                mem.save()
            except Exception:
                pass

        except Exception as e:
            steps.append({'type': 'error', 'content': str(e)})
        finally:
            _agent_runs[run_id]['done'] = True

    threading.Thread(target=worker, daemon=True).start()

    # Stream the agent steps as SSE
    def generate():
        run = _agent_runs.get(run_id)
        if not run:
            yield f"data: {json.dumps({'error': 'Run not found'})}\n\n"
            return
        sent = 0
        while True:
            current_steps = run['steps']
            while sent < len(current_steps):
                yield f"data: {json.dumps(current_steps[sent])}\n\n"
                sent += 1
            if run['done']:
                yield f"data: {json.dumps({'done': True})}\n\n"
                return
            time.sleep(0.15)

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@chat_bp.route('/chat/reset', methods=['POST'])
@login_required
def chat_reset():
    """Clear LLM conversation history."""
    try:
        from core.llm import get_llm
        llm = get_llm()
        if hasattr(llm, 'clear_history'):
            llm.clear_history()
        elif hasattr(llm, 'reset'):
            llm.reset()
        elif hasattr(llm, 'conversation_history'):
            llm.conversation_history = []
    except Exception:
        pass
    return jsonify({'ok': True})


@chat_bp.route('/hal/analyze', methods=['POST'])
@login_required
def hal_analyze():
    """Send tool output to HAL for AI analysis.

    Expects JSON: {tool_name, output, context?, category?}
    Returns JSON: {available, analysis, risk_level, has_fixes, tool_name}
    """
    data = request.get_json(silent=True) or {}
    tool_name = data.get('tool_name', 'unknown')
    output = data.get('output', '')
    context = data.get('context', '')
    category = data.get('category', 'default')

    if not output:
        return jsonify({'available': False, 'analysis': 'No output provided', 'tool_name': tool_name})

    from core.hal_analyst import analyze_output
    result = analyze_output(tool_name, output, context=context, category=category)
    return jsonify(result)


@chat_bp.route('/hal/fix', methods=['POST'])
@login_required
def hal_fix():
    """Execute a fix command suggested by HAL.

    Expects JSON: {command: str}
    Returns JSON: {ok, output, exit_code}
    """
    from core.daemon import root_exec
    import shlex
    import subprocess as _subprocess
    data = request.get_json(silent=True) or {}
    command = data.get('command', '').strip()

    if not command:
        return jsonify({'ok': False, 'error': 'No command provided'})

    # Safety: block obviously dangerous commands
    dangerous = ['rm -rf /', 'mkfs', 'dd if=', ':(){', 'format c:']
    for d in dangerous:
        if d in command.lower():
            return jsonify({'ok': False, 'error': f'Blocked dangerous command: {d}'})

    # Clean the command: strip sudo, shell redirections
    import re
    command = re.sub(r'\s*2>/dev/null\s*', ' ', command)
    command = re.sub(r'\s*>/dev/null\s*', ' ', command)
    command = re.sub(r'\s*2>&1\s*', ' ', command)
    command = command.strip()

    if command.startswith('sudo '):
        command = command[5:].strip()

    # Commands that should run as the normal user, not root
    USER_COMMANDS = {'adb', 'fastboot'}

    def _is_user_cmd(cmd_str):
        """Check if a command should run as normal user."""
        base = cmd_str.split()[0] if cmd_str.split() else ''
        return os.path.basename(base) in USER_COMMANDS

    def _run_user(cmd_parts, timeout=60):
        """Run a command as the normal user via subprocess."""
        try:
            result = _subprocess.run(
                cmd_parts, capture_output=True, text=True, timeout=timeout
            )
            return {
                'ok': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'code': result.returncode,
            }
        except _subprocess.TimeoutExpired:
            return {'ok': False, 'stdout': '', 'stderr': f'Timeout after {timeout}s', 'code': -2}
        except FileNotFoundError:
            return {'ok': False, 'stdout': '', 'stderr': f'Command not found: {cmd_parts[0]}', 'code': -3}
        except Exception as e:
            return {'ok': False, 'stdout': '', 'stderr': str(e), 'code': -4}

    def _exec(cmd_parts, timeout=60):
        """Route to user or root execution based on command."""
        if cmd_parts and os.path.basename(cmd_parts[0]) in USER_COMMANDS:
            return _run_user(cmd_parts, timeout=timeout)
        return root_exec(cmd_parts, timeout=timeout)

    # Handle pipes (cmd1 | cmd2) — run as shell command through bash
    if '|' in command:
        if _is_user_cmd(command):
            r = _run_user(['bash', '-c', command], timeout=60)
        else:
            r = root_exec(['bash', '-c', command], timeout=60)
        return jsonify({'ok': r['ok'], 'output': r['stdout'] + r['stderr'], 'exit_code': r['code']})

    # Handle chained commands (&&) by running them sequentially
    if '&&' in command:
        parts = [c.strip() for c in command.split('&&') if c.strip()]
        all_output = ''
        for part in parts:
            if part.startswith('sudo '):
                part = part[5:].strip()
            part = re.sub(r'\s*2>/dev/null\s*', ' ', part).strip()
            part = re.sub(r'\s*>/dev/null\s*', ' ', part).strip()
            try:
                cmd_parts = shlex.split(part)
            except ValueError:
                cmd_parts = part.split()
            r = _exec(cmd_parts, timeout=60)
            all_output += r['stdout'] + r['stderr']
            if not r['ok']:
                return jsonify({'ok': False, 'output': all_output, 'exit_code': r['code']})
        return jsonify({'ok': True, 'output': all_output, 'exit_code': 0})

    # Single command
    try:
        cmd_parts = shlex.split(command)
    except ValueError:
        cmd_parts = command.split()

    r = _exec(cmd_parts, timeout=60)
    return jsonify({
        'ok': r['ok'],
        'output': r['stdout'] + r['stderr'],
        'exit_code': r['code'],
    })


@chat_bp.route('/hal/available')
@login_required
def hal_available():
    """Quick check if HAL analysis is available (LLM loaded)."""
    from core.hal_analyst import is_llm_available
    return jsonify({'available': is_llm_available()})


@chat_bp.route('/chat/status')
@login_required
def chat_status():
    """Get LLM model status."""
    try:
        from core.llm import get_llm
        llm = get_llm()
        return jsonify({
            'loaded': llm.is_loaded,
            'model': llm.model_name if llm.is_loaded else None,
        })
    except Exception as e:
        return jsonify({'loaded': False, 'error': str(e)})


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
            from core.llm import get_llm, LLMError

            llm = get_llm()
            if not llm.is_loaded:
                try:
                    llm.load_model(verbose=False)
                except LLMError as e:
                    steps.append({'type': 'error', 'content': f'Failed to load model: {e}'})
                    return

            tools = get_tool_registry()
            agent = Agent(llm=llm, tools=tools, verbose=False)

            # Inject system prompt
            system_prompt = _get_system_prompt()
            agent.SYSTEM_PROMPT = system_prompt + "\n\n{tools_description}"

            def on_step(step):
                steps.append({'type': 'thought', 'content': step.thought})
                if step.tool_name and step.tool_name not in ('task_complete', 'ask_user'):
                    steps.append({'type': 'action', 'content': f"{step.tool_name}({json.dumps(step.tool_args or {})})"})
                if step.tool_result:
                    steps.append({'type': 'result', 'content': step.tool_result[:800]})

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
            current_steps = run['steps']
            while sent < len(current_steps):
                yield f"data: {json.dumps(current_steps[sent])}\n\n"
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
