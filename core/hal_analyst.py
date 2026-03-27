"""
AUTARCH HAL Analyst
Automatically analyzes tool output via the loaded LLM.

When a defensive/analysis tool produces output, this module sends it to
the active LLM backend for analysis. HAL identifies issues, explains
what the user is looking at, and optionally suggests fixes.

Usage:
    from core.hal_analyst import analyze_output
    result = analyze_output('log_analyzer', log_text, context='syslog')
"""

import json
import logging
import time
from typing import Optional

_log = logging.getLogger('autarch.hal_analyst')

# Categories that should NOT get auto-analysis (offensive tools)
EXCLUDED_BLUEPRINTS = {
    'offense', 'loadtest', 'phishmail', 'social_eng', 'hack_hijack',
    'c2_framework', 'deauth', 'pineapple', 'exploit_dev', 'sms_forge',
    'rcs_tools', 'starlink_hack', 'iphone_exploit',
}

# Prompts tailored per tool category
ANALYSIS_PROMPTS = {
    'default': (
        "You are HAL, the AUTARCH security analyst. Analyze the following tool output. "
        "Be concise but thorough. Structure your response as:\n"
        "1. **Summary**: One sentence about what this data shows\n"
        "2. **Findings**: List any issues, anomalies, or notable items\n"
        "3. **Risk Level**: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. **Recommendation**: What the user should do (if anything)\n\n"
        "Tool: {tool_name}\n"
        "Context: {context}\n\n"
        "--- OUTPUT ---\n{output}\n--- END ---"
    ),
    'log_analysis': (
        "You are HAL, the AUTARCH security analyst. Analyze these system logs for security issues. "
        "Look for: failed login attempts, privilege escalation, suspicious processes, "
        "unusual network connections, file permission changes, service failures, "
        "and any indicators of compromise.\n\n"
        "Be specific about line numbers or timestamps where issues appear.\n\n"
        "Structure your response as:\n"
        "1. **Summary**: What these logs show\n"
        "2. **Issues Found**: Specific problems with details\n"
        "3. **Risk Level**: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. **Fix**: Exact commands or steps to resolve each issue\n\n"
        "--- LOGS ---\n{output}\n--- END ---"
    ),
    'network': (
        "You are HAL, the AUTARCH network security analyst. Analyze this network data. "
        "Look for: suspicious connections, unusual ports, potential backdoors, "
        "ARP anomalies, rogue devices, and any signs of intrusion.\n\n"
        "Structure your response as:\n"
        "1. **Summary**: Network status overview\n"
        "2. **Findings**: Suspicious items with details\n"
        "3. **Risk Level**: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. **Action**: Commands to investigate or fix issues\n\n"
        "Tool: {tool_name}\n\n"
        "--- DATA ---\n{output}\n--- END ---"
    ),
    'defense': (
        "You are HAL, the AUTARCH defensive security analyst. "
        "Analyze ONLY the specific output provided below. Do NOT expand scope beyond what was tested. "
        "If this is a single check (firewall only, SSH only, etc.), only comment on that one check. "
        "Do NOT perform or suggest a full system audit unless the output contains multiple checks.\n\n"
        "Keep your response short and focused on the actual data shown.\n\n"
        "Structure:\n"
        "1. Summary (one sentence)\n"
        "2. Issues found (if any)\n"
        "3. Risk Level: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. Fix commands (only for issues found in THIS output)\n\n"
        "Tool: {tool_name}\nContext: {context}\n\n"
        "--- OUTPUT ---\n{output}\n--- END ---"
    ),
    'counter': (
        "You are HAL, the AUTARCH threat analyst. Analyze this threat detection output. "
        "Look for active compromises, persistent threats, backdoors, rootkits, "
        "and indicators of compromise.\n\n"
        "Be urgent and specific about any active threats found.\n\n"
        "Structure your response as:\n"
        "1. **Summary**: Threat landscape\n"
        "2. **Active Threats**: Any confirmed or suspected compromises\n"
        "3. **Risk Level**: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. **Immediate Action**: Steps to contain and remediate\n\n"
        "--- DATA ---\n{output}\n--- END ---"
    ),
    'android': (
        "You are HAL, the AUTARCH mobile security analyst. Analyze this Android device output. "
        "Look for: suspicious apps, dangerous permissions, stalkerware indicators, "
        "root detection, SELinux status, unusual processes, and security misconfigurations.\n\n"
        "Structure your response as:\n"
        "1. Summary: What this data shows\n"
        "2. Findings: Issues or notable items\n"
        "3. Risk Level: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. Fix: Exact adb or device commands to resolve issues\n\n"
        "Tool: {tool_name}\nContext: {context}\n\n"
        "--- OUTPUT ---\n{output}\n--- END ---"
    ),
    'analyze': (
        "You are HAL, the AUTARCH forensics analyst. Analyze this forensic data. "
        "Look for malware indicators, suspicious strings, anomalous file properties, "
        "and any signs of tampering or malicious content.\n\n"
        "Structure your response as:\n"
        "1. **Summary**: What this data represents\n"
        "2. **Findings**: Notable or suspicious items\n"
        "3. **Risk Level**: CLEAN / LOW / MEDIUM / HIGH / CRITICAL\n"
        "4. **Recommendation**: Further analysis or actions needed\n\n"
        "Tool: {tool_name}\n\n"
        "--- DATA ---\n{output}\n--- END ---"
    ),
}


def is_llm_available() -> bool:
    """Check if any LLM backend is loaded and ready."""
    try:
        from core.llm import get_llm
        llm = get_llm()
        return llm is not None and llm.is_loaded
    except Exception:
        return False


def analyze_output(
    tool_name: str,
    output: str,
    context: str = '',
    category: str = 'default',
    max_output_chars: int = 8000,
) -> dict:
    """Send tool output to the loaded LLM for analysis.

    Args:
        tool_name: Name of the tool that produced the output
        output: The raw output text to analyze
        context: Additional context (e.g., 'syslog', 'auth.log', 'ARP table')
        category: Analysis category for prompt selection
        max_output_chars: Truncate output to this length to fit context windows

    Returns:
        dict with keys:
            available (bool): Whether LLM was available
            analysis (str): The LLM's analysis text
            risk_level (str): Extracted risk level (CLEAN/LOW/MEDIUM/HIGH/CRITICAL)
            has_fixes (bool): Whether the analysis contains fix commands
            tool_name (str): Echo back the tool name
    """
    result = {
        'available': False,
        'analysis': '',
        'risk_level': 'unknown',
        'has_fixes': False,
        'tool_name': tool_name,
    }

    if not output or not output.strip():
        result['analysis'] = 'No output to analyze.'
        return result

    # Check LLM
    try:
        from core.llm import get_llm
        llm = get_llm()
        if not llm or not llm.is_loaded:
            result['analysis'] = 'No LLM loaded — enable a model in LLM Settings to get AI analysis.'
            return result
    except Exception as e:
        _log.debug(f"[HAL] LLM not available: {e}")
        result['analysis'] = f'LLM not available: {e}'
        return result

    result['available'] = True

    # Truncate output if too long
    if len(output) > max_output_chars:
        output = output[:max_output_chars] + f'\n\n... [truncated — {len(output)} chars total]'

    # Select prompt template
    prompt_template = ANALYSIS_PROMPTS.get(category, ANALYSIS_PROMPTS['default'])
    prompt = prompt_template.format(
        tool_name=tool_name,
        output=output,
        context=context or 'general',
    )

    # Detect current OS for context
    import platform as _plat
    _os_name = _plat.system()
    _os_detail = _plat.platform()

    # Send to LLM
    try:
        _log.info(f"[HAL] Analyzing output from {tool_name} ({len(output)} chars, category={category})")
        start = time.time()
        response = llm.chat(prompt, system_prompt=(
            "You are HAL, the AI security analyst for the AUTARCH platform. "
            f"This system is running {_os_name} ({_os_detail}). "
            "ONLY suggest commands for this operating system. "
            "If the tool output is from the WRONG platform (e.g. Windows scan results on a Linux host), "
            "immediately tell the user they ran the wrong scan and point them to the correct one. "
            "Do NOT use markdown formatting. Plain text only. No ** or ## or ``` or bullet points. "
            "Be specific, cite evidence from the data, and provide exact commands to fix issues."
        ))
        elapsed = time.time() - start
        _log.info(f"[HAL] Analysis complete in {elapsed:.1f}s ({len(response)} chars)")

        result['analysis'] = response

        # Extract risk level from response
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN']:
            if level in response.upper():
                result['risk_level'] = level.lower()
                break

        # Check if response contains fix commands
        result['has_fixes'] = any(x in response for x in [
            '```', 'sudo ', 'systemctl ', 'iptables ', 'chmod ', 'chown ',
            'apt ', 'ufw ', 'sshd_config', 'Fix:', 'fix:', 'Command:',
            'adb ', 'fastboot ', 'pm ', 'am ', 'dumpsys ', 'settings put ',
        ])

    except Exception as e:
        _log.error(f"[HAL] Analysis failed: {e}", exc_info=True)
        result['analysis'] = f'Analysis failed: {e}'

    return result


def extract_fix_commands(analysis: str) -> list:
    """Extract actionable commands from an analysis response.

    Looks for commands in code blocks or after 'Fix:' / 'Command:' markers.
    Returns a list of command strings.
    """
    commands = []
    in_code_block = False
    code_block = []

    for line in analysis.split('\n'):
        stripped = line.strip()

        # Code blocks
        if stripped.startswith('```'):
            if in_code_block:
                if code_block:
                    commands.extend(code_block)
                code_block = []
            in_code_block = not in_code_block
            continue

        if in_code_block:
            if stripped and not stripped.startswith('#'):
                code_block.append(stripped)
            continue

        # Inline commands after markers
        if stripped.startswith(('sudo ', '$ ', '# ')) and len(stripped) > 5:
            cmd = stripped.lstrip('$# ').strip()
            if cmd:
                commands.append(cmd)

    return commands
