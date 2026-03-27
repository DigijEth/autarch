"""
AUTARCH Automation Rules Engine
Condition-action rules for autonomous threat response.

Rules are JSON-serializable and stored in data/automation_rules.json.
The engine evaluates conditions against a threat context dict and returns
matching rules with resolved action parameters.
"""

import json
import logging
import re
import ipaddress
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict

_logger = logging.getLogger('autarch.rules')


@dataclass
class Rule:
    """A single automation rule."""
    id: str
    name: str
    enabled: bool = True
    priority: int = 50              # 0=highest, 100=lowest
    conditions: List[Dict] = field(default_factory=list)   # AND-combined
    actions: List[Dict] = field(default_factory=list)
    cooldown_seconds: int = 60
    last_triggered: Optional[str] = None   # ISO timestamp
    created: Optional[str] = None
    description: str = ''

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Rule':
        return cls(
            id=d.get('id', str(uuid.uuid4())[:8]),
            name=d.get('name', 'Untitled'),
            enabled=d.get('enabled', True),
            priority=d.get('priority', 50),
            conditions=d.get('conditions', []),
            actions=d.get('actions', []),
            cooldown_seconds=d.get('cooldown_seconds', 60),
            last_triggered=d.get('last_triggered'),
            created=d.get('created'),
            description=d.get('description', ''),
        )


class RulesEngine:
    """Evaluates automation rules against a threat context."""

    RULES_PATH = Path(__file__).parent.parent / 'data' / 'automation_rules.json'

    CONDITION_TYPES = {
        'threat_score_above', 'threat_score_below', 'threat_level_is',
        'port_scan_detected', 'ddos_detected', 'ddos_attack_type',
        'connection_from_ip', 'connection_count_above',
        'new_listening_port', 'bandwidth_rx_above_mbps',
        'arp_spoof_detected', 'schedule', 'always',
    }

    ACTION_TYPES = {
        'block_ip', 'unblock_ip', 'rate_limit_ip', 'block_port',
        'kill_process', 'alert', 'log_event', 'run_shell',
        'run_module', 'counter_scan', 'escalate_to_lam',
    }

    def __init__(self):
        self._rules: List[Rule] = []
        self._load()

    def _load(self):
        """Load rules from JSON file."""
        if not self.RULES_PATH.exists():
            self._rules = []
            return
        try:
            data = json.loads(self.RULES_PATH.read_text(encoding='utf-8'))
            self._rules = [Rule.from_dict(r) for r in data.get('rules', [])]
            _logger.info(f"[Rules] Loaded {len(self._rules)} rules")
        except Exception as e:
            _logger.error(f"[Rules] Failed to load rules: {e}")
            self._rules = []

    def save(self):
        """Save rules to JSON file."""
        self.RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'version': 1,
            'rules': [r.to_dict() for r in self._rules],
        }
        self.RULES_PATH.write_text(json.dumps(data, indent=2), encoding='utf-8')

    def add_rule(self, rule: Rule) -> Rule:
        if not rule.created:
            rule.created = datetime.now().isoformat()
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority)
        self.save()
        return rule

    def update_rule(self, rule_id: str, updates: dict) -> Optional[Rule]:
        for rule in self._rules:
            if rule.id == rule_id:
                for key, value in updates.items():
                    if hasattr(rule, key) and key != 'id':
                        setattr(rule, key, value)
                self._rules.sort(key=lambda r: r.priority)
                self.save()
                return rule
        return None

    def delete_rule(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        if len(self._rules) < before:
            self.save()
            return True
        return False

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        for rule in self._rules:
            if rule.id == rule_id:
                return rule
        return None

    def get_all_rules(self) -> List[Rule]:
        return list(self._rules)

    def evaluate(self, context: Dict[str, Any]) -> List[Tuple[Rule, List[Dict]]]:
        """Evaluate all enabled rules against a threat context.

        Args:
            context: Dict with keys from ThreatMonitor / AutonomyDaemon:
                - threat_score: {'score': int, 'level': str, 'details': [...]}
                - connection_count: int
                - connections: [...]
                - ddos: {'under_attack': bool, 'attack_type': str, ...}
                - new_ports: [{'port': int, 'process': str}, ...]
                - arp_alerts: [...]
                - bandwidth: {'rx_mbps': float, 'tx_mbps': float}
                - scan_indicators: int
                - timestamp: str

        Returns:
            List of (Rule, resolved_actions) for rules that match and aren't in cooldown.
        """
        matches = []
        now = datetime.now()

        for rule in self._rules:
            if not rule.enabled:
                continue

            # Check cooldown
            if rule.last_triggered:
                try:
                    last = datetime.fromisoformat(rule.last_triggered)
                    if (now - last).total_seconds() < rule.cooldown_seconds:
                        continue
                except (ValueError, TypeError):
                    pass

            # Evaluate all conditions (AND logic)
            if not rule.conditions:
                continue

            all_match = all(
                self._evaluate_condition(cond, context)
                for cond in rule.conditions
            )

            if all_match:
                # Resolve action variables
                resolved = [self._resolve_variables(a, context) for a in rule.actions]
                matches.append((rule, resolved))

                # Mark triggered
                rule.last_triggered = now.isoformat()

        # Save updated trigger times
        if matches:
            self.save()

        return matches

    def _evaluate_condition(self, condition: dict, context: dict) -> bool:
        """Evaluate a single condition against context."""
        ctype = condition.get('type', '')
        value = condition.get('value')

        if ctype == 'threat_score_above':
            return context.get('threat_score', {}).get('score', 0) > (value or 0)

        elif ctype == 'threat_score_below':
            return context.get('threat_score', {}).get('score', 0) < (value or 100)

        elif ctype == 'threat_level_is':
            return context.get('threat_score', {}).get('level', 'LOW') == (value or 'HIGH')

        elif ctype == 'port_scan_detected':
            return context.get('scan_indicators', 0) > 0

        elif ctype == 'ddos_detected':
            return context.get('ddos', {}).get('under_attack', False)

        elif ctype == 'ddos_attack_type':
            return context.get('ddos', {}).get('attack_type', '') == (value or '')

        elif ctype == 'connection_from_ip':
            return self._check_ip_match(value, context.get('connections', []))

        elif ctype == 'connection_count_above':
            return context.get('connection_count', 0) > (value or 0)

        elif ctype == 'new_listening_port':
            return len(context.get('new_ports', [])) > 0

        elif ctype == 'bandwidth_rx_above_mbps':
            return context.get('bandwidth', {}).get('rx_mbps', 0) > (value or 0)

        elif ctype == 'arp_spoof_detected':
            return len(context.get('arp_alerts', [])) > 0

        elif ctype == 'schedule':
            return self._check_cron(condition.get('cron', ''))

        elif ctype == 'always':
            return True

        _logger.warning(f"[Rules] Unknown condition type: {ctype}")
        return False

    def _check_ip_match(self, pattern: str, connections: list) -> bool:
        """Check if any connection's remote IP matches a pattern (IP or CIDR)."""
        if not pattern:
            return False
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            for conn in connections:
                remote = conn.get('remote_addr', '')
                if remote and remote not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                    try:
                        if ipaddress.ip_address(remote) in network:
                            return True
                    except ValueError:
                        continue
        except ValueError:
            # Not a valid IP/CIDR, try exact match
            return any(conn.get('remote_addr') == pattern for conn in connections)
        return False

    def _check_cron(self, cron_expr: str) -> bool:
        """Minimal 5-field cron matcher: minute hour day month weekday.

        Supports * and */N. Does not support ranges or lists.
        """
        if not cron_expr:
            return False

        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return False

        now = datetime.now()
        current = [now.minute, now.hour, now.day, now.month, now.isoweekday() % 7]

        for field_val, pattern in zip(current, parts):
            if pattern == '*':
                continue
            if pattern.startswith('*/'):
                try:
                    step = int(pattern[2:])
                    if step > 0 and field_val % step != 0:
                        return False
                except ValueError:
                    return False
            else:
                try:
                    if field_val != int(pattern):
                        return False
                except ValueError:
                    return False

        return True

    def _resolve_variables(self, action: dict, context: dict) -> dict:
        """Replace $variable placeholders in action parameters with context values."""
        resolved = {}

        # Build variable map from context
        variables = {
            '$threat_score': str(context.get('threat_score', {}).get('score', 0)),
            '$threat_level': context.get('threat_score', {}).get('level', 'LOW'),
        }

        # Source IP = top talker (most connections)
        connections = context.get('connections', [])
        if connections:
            ip_counts = {}
            for c in connections:
                rip = c.get('remote_addr', '')
                if rip and rip not in ('0.0.0.0', '::', '127.0.0.1', '::1', '*'):
                    ip_counts[rip] = ip_counts.get(rip, 0) + 1
            if ip_counts:
                variables['$source_ip'] = max(ip_counts, key=ip_counts.get)

        # New port
        new_ports = context.get('new_ports', [])
        if new_ports:
            variables['$new_port'] = str(new_ports[0].get('port', ''))
            variables['$suspicious_pid'] = str(new_ports[0].get('pid', ''))

        # DDoS attack type
        ddos = context.get('ddos', {})
        if ddos:
            variables['$attack_type'] = ddos.get('attack_type', 'unknown')

        # Resolve in all string values
        for key, val in action.items():
            if isinstance(val, str):
                for var_name, var_val in variables.items():
                    val = val.replace(var_name, var_val)
            resolved[key] = val

        return resolved
