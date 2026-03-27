"""
AUTARCH Autonomy Daemon
Background loop that monitors threats, evaluates rules, and dispatches
AI-driven responses across all categories (defense, offense, counter,
analyze, OSINT, simulate).

The daemon ties together:
  - ThreatMonitor (threat data gathering)
  - RulesEngine (condition-action evaluation)
  - ModelRouter (SLM/SAM/LAM model tiers)
  - Agent (autonomous task execution)
"""

import json
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Deque

from .config import get_config
from .rules import RulesEngine, Rule
from .model_router import get_model_router, ModelTier

_logger = logging.getLogger('autarch.autonomy')


@dataclass
class ActivityEntry:
    """Single entry in the autonomy activity log."""
    id: str
    timestamp: str
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    tier: Optional[str] = None
    action_type: str = ''
    action_detail: str = ''
    result: str = ''
    success: bool = True
    duration_ms: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)


class AutonomyDaemon:
    """Background daemon for autonomous threat response.

    Lifecycle: start() -> pause()/resume() -> stop()
    """

    LOG_PATH = Path(__file__).parent.parent / 'data' / 'autonomy_log.json'

    def __init__(self, config=None):
        self.config = config or get_config()
        self.rules_engine = RulesEngine()
        self._router = None   # Lazy — get_model_router() on start

        # State
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._paused = False
        self._stop_event = threading.Event()

        # Agent tracking
        self._active_agents: Dict[str, threading.Thread] = {}
        self._agent_lock = threading.Lock()

        # Activity log (ring buffer)
        settings = self.config.get_autonomy_settings()
        max_entries = settings.get('log_max_entries', 1000)
        self._activity: Deque[ActivityEntry] = deque(maxlen=max_entries)
        self._activity_lock = threading.Lock()

        # SSE subscribers
        self._subscribers: List = []
        self._sub_lock = threading.Lock()

        # Load persisted log
        self._load_log()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def status(self) -> dict:
        """Current daemon status."""
        settings = self.config.get_autonomy_settings()
        with self._agent_lock:
            active = len(self._active_agents)
        return {
            'running': self._running,
            'paused': self._paused,
            'enabled': settings['enabled'],
            'monitor_interval': settings['monitor_interval'],
            'rule_eval_interval': settings['rule_eval_interval'],
            'active_agents': active,
            'max_agents': settings['max_concurrent_agents'],
            'rules_count': len(self.rules_engine.get_all_rules()),
            'activity_count': len(self._activity),
        }

    def start(self) -> bool:
        """Start the autonomy daemon background thread."""
        if self._running:
            _logger.warning('[Autonomy] Already running')
            return False

        self._router = get_model_router()
        self._running = True
        self._paused = False
        self._stop_event.clear()

        self._thread = threading.Thread(
            target=self._run_loop,
            name='AutonomyDaemon',
            daemon=True,
        )
        self._thread.start()
        self._log_activity('system', 'Autonomy daemon started')
        _logger.info('[Autonomy] Daemon started')
        return True

    def stop(self):
        """Stop the daemon and wait for thread exit."""
        if not self._running:
            return
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)
        self._log_activity('system', 'Autonomy daemon stopped')
        _logger.info('[Autonomy] Daemon stopped')

    def pause(self):
        """Pause rule evaluation (monitoring continues)."""
        self._paused = True
        self._log_activity('system', 'Autonomy paused')
        _logger.info('[Autonomy] Paused')

    def resume(self):
        """Resume rule evaluation."""
        self._paused = False
        self._log_activity('system', 'Autonomy resumed')
        _logger.info('[Autonomy] Resumed')

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def _run_loop(self):
        """Background loop: gather context, evaluate rules, dispatch."""
        settings = self.config.get_autonomy_settings()
        monitor_interval = settings['monitor_interval']
        rule_eval_interval = settings['rule_eval_interval']
        last_rule_eval = 0

        while self._running and not self._stop_event.is_set():
            try:
                # Gather threat context every cycle
                context = self._gather_context()

                # Evaluate rules at a slower cadence
                now = time.time()
                if not self._paused and (now - last_rule_eval) >= rule_eval_interval:
                    last_rule_eval = now
                    self._evaluate_and_dispatch(context)

            except Exception as e:
                _logger.error(f'[Autonomy] Loop error: {e}')
                self._log_activity('error', f'Loop error: {e}', success=False)

            # Sleep in short increments so stop is responsive
            self._stop_event.wait(timeout=monitor_interval)

    def _gather_context(self) -> Dict[str, Any]:
        """Gather current threat context from ThreatMonitor."""
        try:
            from modules.defender_monitor import get_threat_monitor
            tm = get_threat_monitor()
        except ImportError:
            _logger.warning('[Autonomy] ThreatMonitor not available')
            return {'timestamp': datetime.now().isoformat()}

        context: Dict[str, Any] = {
            'timestamp': datetime.now().isoformat(),
        }

        try:
            context['connections'] = tm.get_connections()
            context['connection_count'] = len(context['connections'])
        except Exception:
            context['connections'] = []
            context['connection_count'] = 0

        try:
            context['bandwidth'] = {}
            bw = tm.get_bandwidth()
            if bw:
                total_rx = sum(iface.get('rx_delta', 0) for iface in bw)
                total_tx = sum(iface.get('tx_delta', 0) for iface in bw)
                context['bandwidth'] = {
                    'rx_mbps': (total_rx * 8) / 1_000_000,
                    'tx_mbps': (total_tx * 8) / 1_000_000,
                    'interfaces': bw,
                }
        except Exception:
            context['bandwidth'] = {'rx_mbps': 0, 'tx_mbps': 0}

        try:
            context['arp_alerts'] = tm.check_arp_spoofing()
        except Exception:
            context['arp_alerts'] = []

        try:
            context['new_ports'] = tm.check_new_listening_ports()
        except Exception:
            context['new_ports'] = []

        try:
            context['threat_score'] = tm.calculate_threat_score()
        except Exception:
            context['threat_score'] = {'score': 0, 'level': 'LOW', 'details': []}

        try:
            context['ddos'] = tm.detect_ddos()
        except Exception:
            context['ddos'] = {'under_attack': False}

        try:
            context['scan_indicators'] = tm.check_port_scan_indicators()
            if isinstance(context['scan_indicators'], list):
                context['scan_indicators'] = len(context['scan_indicators'])
        except Exception:
            context['scan_indicators'] = 0

        return context

    # ------------------------------------------------------------------
    # Rule evaluation and dispatch
    # ------------------------------------------------------------------

    def _evaluate_and_dispatch(self, context: Dict[str, Any]):
        """Evaluate rules and dispatch matching actions."""
        matches = self.rules_engine.evaluate(context)

        for rule, resolved_actions in matches:
            for action in resolved_actions:
                action_type = action.get('type', '')
                _logger.info(f'[Autonomy] Rule "{rule.name}" triggered -> {action_type}')

                if self._is_agent_action(action_type):
                    self._dispatch_agent(rule, action, context)
                else:
                    self._dispatch_direct(rule, action, context)

    def _is_agent_action(self, action_type: str) -> bool:
        """Check if an action requires an AI agent."""
        return action_type in ('run_module', 'counter_scan', 'escalate_to_lam')

    def _dispatch_direct(self, rule: Rule, action: dict, context: dict):
        """Execute a simple action directly (no LLM needed)."""
        action_type = action.get('type', '')
        start = time.time()
        success = True
        result = ''

        try:
            if action_type == 'block_ip':
                result = self._action_block_ip(action.get('ip', ''))

            elif action_type == 'unblock_ip':
                result = self._action_unblock_ip(action.get('ip', ''))

            elif action_type == 'rate_limit_ip':
                result = self._action_rate_limit(
                    action.get('ip', ''),
                    action.get('rate', '10/s'),
                )

            elif action_type == 'block_port':
                result = self._action_block_port(
                    action.get('port', ''),
                    action.get('direction', 'inbound'),
                )

            elif action_type == 'kill_process':
                result = self._action_kill_process(action.get('pid', ''))

            elif action_type in ('alert', 'log_event'):
                result = action.get('message', 'No message')

            elif action_type == 'run_shell':
                result = self._action_run_shell(action.get('command', ''))

            else:
                result = f'Unknown action type: {action_type}'
                success = False

        except Exception as e:
            result = f'Error: {e}'
            success = False

        duration = int((time.time() - start) * 1000)
        detail = action.get('ip', '') or action.get('port', '') or action.get('message', '')[:80]
        self._log_activity(
            action_type, detail,
            rule_id=rule.id, rule_name=rule.name,
            result=result, success=success, duration_ms=duration,
        )

    def _dispatch_agent(self, rule: Rule, action: dict, context: dict):
        """Spawn an AI agent to handle a complex action."""
        settings = self.config.get_autonomy_settings()
        max_agents = settings['max_concurrent_agents']

        # Clean finished agents
        with self._agent_lock:
            self._active_agents = {
                k: v for k, v in self._active_agents.items()
                if v.is_alive()
            }
            if len(self._active_agents) >= max_agents:
                _logger.warning('[Autonomy] Max agents reached, skipping')
                self._log_activity(
                    action.get('type', 'agent'), 'Skipped: max agents reached',
                    rule_id=rule.id, rule_name=rule.name,
                    success=False,
                )
                return

        agent_id = str(uuid.uuid4())[:8]
        action_type = action.get('type', '')

        # Determine tier
        if action_type == 'escalate_to_lam':
            tier = ModelTier.LAM
        else:
            tier = ModelTier.SAM

        t = threading.Thread(
            target=self._run_agent,
            args=(agent_id, tier, rule, action, context),
            name=f'Agent-{agent_id}',
            daemon=True,
        )

        with self._agent_lock:
            self._active_agents[agent_id] = t

        t.start()
        self._log_activity(
            action_type, f'Agent {agent_id} spawned ({tier.value})',
            rule_id=rule.id, rule_name=rule.name, tier=tier.value,
        )

    def _run_agent(self, agent_id: str, tier: ModelTier, rule: Rule,
                   action: dict, context: dict):
        """Execute an agent task in a background thread."""
        from .agent import Agent
        from .tools import get_tool_registry

        action_type = action.get('type', '')
        start = time.time()

        # Build task prompt
        if action_type == 'run_module':
            module = action.get('module', '')
            args = action.get('args', '')
            task = f'Run the AUTARCH module "{module}" with arguments: {args}'

        elif action_type == 'counter_scan':
            target = action.get('target', '')
            task = f'Perform a counter-scan against {target}. Gather reconnaissance and identify vulnerabilities.'

        elif action_type == 'escalate_to_lam':
            task = action.get('task', 'Analyze the current threat landscape and recommend actions.')

        else:
            task = f'Execute action: {action_type} with params: {json.dumps(action)}'

        # Get LLM instance for the tier
        router = self._router or get_model_router()
        llm_inst = router.get_instance(tier)

        if llm_inst is None or not llm_inst.is_loaded:
            # Try fallback
            for fallback in (ModelTier.SAM, ModelTier.LAM):
                llm_inst = router.get_instance(fallback)
                if llm_inst and llm_inst.is_loaded:
                    tier = fallback
                    break
            else:
                self._log_activity(
                    action_type, f'Agent {agent_id}: no model loaded',
                    rule_id=rule.id, rule_name=rule.name,
                    tier=tier.value, success=False,
                    result='No model available for agent execution',
                )
                return

        try:
            agent = Agent(
                llm=llm_inst,
                tools=get_tool_registry(),
                max_steps=15,
                verbose=False,
            )
            result = agent.run(task)
            duration = int((time.time() - start) * 1000)

            self._log_activity(
                action_type,
                f'Agent {agent_id}: {result.summary[:100]}',
                rule_id=rule.id, rule_name=rule.name,
                tier=tier.value, success=result.success,
                result=result.summary, duration_ms=duration,
            )

        except Exception as e:
            duration = int((time.time() - start) * 1000)
            _logger.error(f'[Autonomy] Agent {agent_id} failed: {e}')
            self._log_activity(
                action_type, f'Agent {agent_id} failed: {e}',
                rule_id=rule.id, rule_name=rule.name,
                tier=tier.value, success=False,
                result=str(e), duration_ms=duration,
            )

        finally:
            with self._agent_lock:
                self._active_agents.pop(agent_id, None)

    # ------------------------------------------------------------------
    # Direct action implementations
    # ------------------------------------------------------------------

    def _action_block_ip(self, ip: str) -> str:
        if not ip:
            return 'No IP specified'
        try:
            from modules.defender_monitor import get_threat_monitor
            tm = get_threat_monitor()
            tm.auto_block_ip(ip)
            return f'Blocked {ip}'
        except Exception as e:
            return f'Block failed: {e}'

    def _action_unblock_ip(self, ip: str) -> str:
        if not ip:
            return 'No IP specified'
        try:
            import subprocess, platform
            if platform.system() == 'Windows':
                cmd = f'netsh advfirewall firewall delete rule name="AUTARCH Block {ip}"'
            else:
                cmd = f'iptables -D INPUT -s {ip} -j DROP 2>/dev/null; iptables -D OUTPUT -d {ip} -j DROP 2>/dev/null'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return f'Unblocked {ip}'
        except Exception as e:
            return f'Unblock failed: {e}'

    def _action_rate_limit(self, ip: str, rate: str) -> str:
        if not ip:
            return 'No IP specified'
        try:
            from modules.defender_monitor import get_threat_monitor
            tm = get_threat_monitor()
            tm.apply_rate_limit(ip)
            return f'Rate limited {ip} at {rate}'
        except Exception as e:
            return f'Rate limit failed: {e}'

    def _action_block_port(self, port: str, direction: str) -> str:
        if not port:
            return 'No port specified'
        try:
            import subprocess, platform
            if platform.system() == 'Windows':
                d = 'in' if direction == 'inbound' else 'out'
                cmd = f'netsh advfirewall firewall add rule name="AUTARCH Block Port {port}" dir={d} action=block protocol=TCP localport={port}'
            else:
                chain = 'INPUT' if direction == 'inbound' else 'OUTPUT'
                cmd = f'iptables -A {chain} -p tcp --dport {port} -j DROP'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return f'Blocked port {port} ({direction})'
        except Exception as e:
            return f'Block port failed: {e}'

    def _action_kill_process(self, pid: str) -> str:
        if not pid:
            return 'No PID specified'
        try:
            import subprocess, platform
            if platform.system() == 'Windows':
                cmd = f'taskkill /F /PID {pid}'
            else:
                cmd = f'kill -9 {pid}'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=10)
            return f'Killed process {pid}'
        except Exception as e:
            return f'Kill failed: {e}'

    def _action_run_shell(self, command: str) -> str:
        if not command:
            return 'No command specified'
        try:
            import subprocess
            result = subprocess.run(
                command, shell=True, capture_output=True,
                text=True, timeout=30,
            )
            output = result.stdout[:500]
            if result.returncode != 0:
                output += f'\n[exit {result.returncode}]'
            return output.strip() or '[no output]'
        except Exception as e:
            return f'Shell failed: {e}'

    # ------------------------------------------------------------------
    # Activity log
    # ------------------------------------------------------------------

    def _log_activity(self, action_type: str, detail: str, *,
                      rule_id: str = None, rule_name: str = None,
                      tier: str = None, result: str = '',
                      success: bool = True, duration_ms: int = None):
        """Add an entry to the activity log and notify SSE subscribers."""
        entry = ActivityEntry(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            rule_id=rule_id,
            rule_name=rule_name,
            tier=tier,
            action_type=action_type,
            action_detail=detail,
            result=result,
            success=success,
            duration_ms=duration_ms,
        )

        with self._activity_lock:
            self._activity.append(entry)

        # Notify SSE subscribers
        self._notify_subscribers(entry)

        # Persist periodically (every 10 entries)
        if len(self._activity) % 10 == 0:
            self._save_log()

    def get_activity(self, limit: int = 50, offset: int = 0) -> List[dict]:
        """Get recent activity entries."""
        with self._activity_lock:
            entries = list(self._activity)
        entries.reverse()  # Newest first
        return [e.to_dict() for e in entries[offset:offset + limit]]

    def get_activity_count(self) -> int:
        return len(self._activity)

    # ------------------------------------------------------------------
    # SSE streaming
    # ------------------------------------------------------------------

    def subscribe(self):
        """Create an SSE subscriber queue."""
        import queue
        q = queue.Queue(maxsize=100)
        with self._sub_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        """Remove an SSE subscriber."""
        with self._sub_lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def _notify_subscribers(self, entry: ActivityEntry):
        """Push an activity entry to all SSE subscribers."""
        data = json.dumps(entry.to_dict())
        with self._sub_lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(data)
                except Exception:
                    dead.append(q)
            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save_log(self):
        """Persist activity log to JSON file."""
        try:
            self.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with self._activity_lock:
                entries = [e.to_dict() for e in self._activity]
            self.LOG_PATH.write_text(
                json.dumps({'entries': entries[-200:]}, indent=2),
                encoding='utf-8',
            )
        except Exception as e:
            _logger.error(f'[Autonomy] Failed to save log: {e}')

    def _load_log(self):
        """Load persisted activity log."""
        if not self.LOG_PATH.exists():
            return
        try:
            data = json.loads(self.LOG_PATH.read_text(encoding='utf-8'))
            for entry_dict in data.get('entries', []):
                entry = ActivityEntry(
                    id=entry_dict.get('id', str(uuid.uuid4())[:8]),
                    timestamp=entry_dict.get('timestamp', ''),
                    rule_id=entry_dict.get('rule_id'),
                    rule_name=entry_dict.get('rule_name'),
                    tier=entry_dict.get('tier'),
                    action_type=entry_dict.get('action_type', ''),
                    action_detail=entry_dict.get('action_detail', ''),
                    result=entry_dict.get('result', ''),
                    success=entry_dict.get('success', True),
                    duration_ms=entry_dict.get('duration_ms'),
                )
                self._activity.append(entry)
            _logger.info(f'[Autonomy] Loaded {len(self._activity)} log entries')
        except Exception as e:
            _logger.error(f'[Autonomy] Failed to load log: {e}')


# ------------------------------------------------------------------
# Singleton
# ------------------------------------------------------------------

_daemon_instance: Optional[AutonomyDaemon] = None


def get_autonomy_daemon() -> AutonomyDaemon:
    """Get the global AutonomyDaemon instance."""
    global _daemon_instance
    if _daemon_instance is None:
        _daemon_instance = AutonomyDaemon()
    return _daemon_instance


def reset_autonomy_daemon():
    """Stop and reset the global daemon."""
    global _daemon_instance
    if _daemon_instance is not None:
        _daemon_instance.stop()
    _daemon_instance = None
