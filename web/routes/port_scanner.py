"""Advanced Port Scanner — streaming SSE-based port scanner with nmap integration."""

import json
import queue
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, render_template, request, jsonify, Response
from web.auth import login_required

port_scanner_bp = Blueprint('port_scanner', __name__, url_prefix='/port-scanner')

# job_id -> {'q': Queue, 'result': dict|None, 'done': bool, 'cancel': bool}
_jobs: dict = {}

# ── Common port lists ──────────────────────────────────────────────────────────

QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888,
]

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514,
    515, 587, 593, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1521,
    1723, 1883, 2049, 2121, 2181, 2222, 2375, 2376, 2483, 2484, 3000, 3306,
    3389, 3690, 4000, 4040, 4333, 4444, 4567, 4899, 5000, 5432, 5601, 5672,
    5900, 5984, 6000, 6379, 6443, 6881, 7000, 7001, 7080, 7443, 7474, 8000,
    8001, 8008, 8080, 8081, 8082, 8083, 8088, 8089, 8161, 8333, 8443, 8444,
    8500, 8888, 8983, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418, 9999,
    10000, 11211, 15432, 15672, 27017, 27018, 27019, 28017, 50000, 54321,
]

SERVICE_MAP = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    88: 'Kerberos', 110: 'POP3', 111: 'RPC', 119: 'NNTP', 123: 'NTP',
    135: 'MS-RPC', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP', 194: 'IRC',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 500: 'IKE/ISAKMP',
    514: 'Syslog/RSH', 515: 'LPD', 587: 'SMTP-Submission', 631: 'IPP',
    636: 'LDAPS', 873: 'rsync', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle',
    1723: 'PPTP', 1883: 'MQTT', 2049: 'NFS', 2181: 'Zookeeper',
    2222: 'SSH-alt', 2375: 'Docker', 2376: 'Docker-TLS', 3000: 'Grafana',
    3306: 'MySQL', 3389: 'RDP', 3690: 'SVN', 4444: 'Meterpreter',
    5000: 'Flask/Dev', 5432: 'PostgreSQL', 5601: 'Kibana', 5672: 'AMQP/RabbitMQ',
    5900: 'VNC', 5984: 'CouchDB', 6379: 'Redis', 6443: 'Kubernetes-API',
    7474: 'Neo4j', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8500: 'Consul',
    8888: 'Jupyter/HTTP-Alt', 9000: 'SonarQube/PHP-FPM', 9001: 'Tor/Supervisor',
    9042: 'Cassandra', 9090: 'Prometheus/Cockpit', 9092: 'Kafka',
    9200: 'Elasticsearch', 9300: 'Elasticsearch-node', 9418: 'Git',
    10000: 'Webmin', 11211: 'Memcached', 15672: 'RabbitMQ-Mgmt',
    27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB', 50000: 'DB2',
}

PROBE_MAP = {
    21: b'',
    22: b'',
    23: b'',
    25: b'',
    80: b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
    110: b'',
    143: b'',
    443: b'',
    3306: b'',
    5432: b'',
    6379: b'INFO\r\n',
    8080: b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
    8443: b'',
    8888: b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
    9200: b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n',
    27017: b'',
}


def _push(q: queue.Queue, event_type: str, data: dict) -> None:
    data['type'] = event_type
    data['ts'] = time.time()
    q.put(data)


def _grab_banner(sock: socket.socket, port: int, timeout: float = 2.0) -> str:
    try:
        sock.settimeout(timeout)
        probe = PROBE_MAP.get(port, b'')
        if probe:
            sock.sendall(probe)
        raw = sock.recv(2048)
        return raw.decode('utf-8', errors='replace').strip()[:512]
    except Exception:
        return ''


def _identify_service(port: int, banner: str) -> str:
    bl = banner.lower()
    if 'ssh-' in bl:
        return 'SSH'
    if 'ftp' in bl or '220 ' in bl[:10]:
        return 'FTP'
    if 'smtp' in bl or ('220 ' in bl and 'mail' in bl):
        return 'SMTP'
    if 'http/' in bl or '<html' in bl or '<!doctype' in bl:
        return 'HTTP'
    if 'mysql' in bl:
        return 'MySQL'
    if 'redis' in bl:
        return 'Redis'
    if 'mongo' in bl:
        return 'MongoDB'
    if 'postgresql' in bl:
        return 'PostgreSQL'
    if 'rabbitmq' in bl:
        return 'RabbitMQ'
    if 'elastic' in bl:
        return 'Elasticsearch'
    return SERVICE_MAP.get(port, 'unknown')


def _scan_port(host: str, port: int, timeout: float) -> Optional[dict]:
    """TCP connect scan a single port. Returns port info dict or None if closed."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err = sock.connect_ex((host, port))
        if err == 0:
            banner = _grab_banner(sock, port)
            sock.close()
            service = _identify_service(port, banner)
            return {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': service,
                'banner': banner,
            }
        sock.close()
    except Exception:
        pass
    return None


def _run_nmap_scan(host: str, ports: list, options: dict, q: queue.Queue,
                   job: dict) -> Optional[list]:
    """Run nmap and parse output. Returns list of port dicts or None if nmap unavailable."""
    import shutil
    nmap = shutil.which('nmap')
    if not nmap:
        _push(q, 'warning', {'msg': 'nmap not found — falling back to TCP connect scan'})
        return None

    port_str = ','.join(str(p) for p in sorted(ports))
    cmd = [nmap, '-Pn', '--open', '-p', port_str]

    if options.get('service_detection'):
        cmd += ['-sV', '--version-intensity', '5']
    if options.get('os_detection'):
        cmd += ['-O', '--osscan-guess']
    if options.get('aggressive'):
        cmd += ['-A']
    if options.get('timing'):
        cmd += [f'-T{options["timing"]}']
    else:
        cmd += ['-T4']

    cmd += ['-oN', '-', '--host-timeout', '120s', host]

    _push(q, 'nmap_start', {'cmd': ' '.join(cmd[:-1] + ['<target>'])})

    open_ports = []
    os_guess = ''
    nmap_raw_lines = []

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        for line in proc.stdout:
            line = line.rstrip()
            if job.get('cancel'):
                proc.terminate()
                break
            nmap_raw_lines.append(line)
            _push(q, 'nmap_line', {'line': line})

            # Parse open port lines: "80/tcp   open  http    Apache httpd 2.4.54"
            stripped = line.strip()
            if '/tcp' in stripped or '/udp' in stripped:
                parts = stripped.split()
                if len(parts) >= 2 and parts[1] == 'open':
                    port_proto = parts[0].split('/')
                    port_num = int(port_proto[0])
                    proto = port_proto[1] if len(port_proto) > 1 else 'tcp'
                    service = parts[2] if len(parts) > 2 else SERVICE_MAP.get(port_num, 'unknown')
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    open_ports.append({
                        'port': port_num,
                        'protocol': proto,
                        'state': 'open',
                        'service': service,
                        'banner': version,
                    })
                    _push(q, 'port_open', {
                        'port': port_num, 'protocol': proto,
                        'service': service, 'banner': version,
                    })
            # OS detection line
            if 'OS details:' in line or 'Running:' in line:
                os_guess = line.split(':', 1)[-1].strip()

        proc.wait(timeout=10)
    except Exception as exc:
        _push(q, 'warning', {'msg': f'nmap error: {exc} — falling back to TCP connect scan'})
        return None

    return open_ports, os_guess, '\n'.join(nmap_raw_lines)


def _socket_scan(host: str, ports: list, timeout: float, concurrency: int,
                 q: queue.Queue, job: dict) -> list:
    """Concurrent TCP connect scan. Returns list of open port dicts."""
    open_ports = []
    lock = threading.Lock()
    scanned = [0]
    total = len(ports)
    start = time.time()

    def worker(port: int):
        if job.get('cancel'):
            return
        result = _scan_port(host, port, timeout)
        with lock:
            scanned[0] += 1
            done = scanned[0]
        if result:
            with lock:
                open_ports.append(result)
            _push(q, 'port_open', {
                'port': result['port'], 'protocol': result['protocol'],
                'service': result['service'], 'banner': result['banner'],
            })
        # Progress every 25 ports or on first/last
        if done == 1 or done % 25 == 0 or done == total:
            elapsed = time.time() - start
            rate = done / elapsed if elapsed > 0 else 0
            eta = int((total - done) / rate) if rate > 0 else 0
            _push(q, 'progress', {
                'current': done, 'total': total,
                'pct': round(done * 100 / total),
                'eta': f'{eta}s' if eta < 3600 else f'{eta//60}m',
                'port': port,
                'open_count': len(open_ports),
            })

    sem = threading.Semaphore(concurrency)
    threads = []

    for port in sorted(ports):
        if job.get('cancel'):
            break
        sem.acquire()
        def _run(p=port):
            try:
                worker(p)
            finally:
                sem.release()
        t = threading.Thread(target=_run, daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=timeout + 1)

    return sorted(open_ports, key=lambda x: x['port'])


def _do_scan(job_id: str, host: str, ports: list, options: dict) -> None:
    """Main scan worker — runs in a background thread."""
    job = _jobs[job_id]
    q = job['q']
    start = time.time()

    _push(q, 'start', {
        'target': host, 'total_ports': len(ports),
        'mode': options.get('mode', 'custom'),
    })

    # Resolve hostname
    ip = host
    try:
        ip = socket.gethostbyname(host)
        if ip != host:
            _push(q, 'info', {'msg': f'Resolved {host} → {ip}'})
    except Exception:
        _push(q, 'warning', {'msg': f'Could not resolve {host} — using as-is'})

    open_ports = []
    os_guess = ''
    nmap_raw = ''

    try:
        use_nmap = options.get('use_nmap', False)
        timeout = float(options.get('timeout', 1.0))
        concurrency = int(options.get('concurrency', 100))

        if use_nmap:
            nmap_result = _run_nmap_scan(ip, ports, options, q, job)
            if nmap_result is not None:
                open_ports, os_guess, nmap_raw = nmap_result
            else:
                # fallback
                _push(q, 'info', {'msg': 'Running TCP connect scan fallback...'})
                open_ports = _socket_scan(ip, ports, timeout, concurrency, q, job)
        else:
            _push(q, 'info', {'msg': f'Scanning {len(ports)} ports on {ip} '
                                     f'(concurrency={concurrency}, timeout={timeout}s)'})
            open_ports = _socket_scan(ip, ports, timeout, concurrency, q, job)

        duration = round(time.time() - start, 2)

        result = {
            'target': host,
            'ip': ip,
            'scan_time': datetime.now(timezone.utc).isoformat(),
            'duration': duration,
            'ports_scanned': len(ports),
            'open_ports': open_ports,
            'os_guess': os_guess,
            'nmap_raw': nmap_raw,
            'options': options,
        }
        job['result'] = result

        _push(q, 'done', {
            'open_count': len(open_ports),
            'ports_scanned': len(ports),
            'duration': duration,
            'os_guess': os_guess,
        })

    except Exception as exc:
        _push(q, 'error', {'msg': str(exc)})
    finally:
        job['done'] = True


# ── Routes ────────────────────────────────────────────────────────────────────

@port_scanner_bp.route('/')
@login_required
def index():
    return render_template('port_scanner.html')


@port_scanner_bp.route('/start', methods=['POST'])
@login_required
def start_scan():
    data = request.get_json(silent=True) or {}
    host = data.get('target', '').strip()
    if not host:
        return jsonify({'ok': False, 'error': 'Target required'})

    mode = data.get('mode', 'common')

    if mode == 'quick':
        ports = list(QUICK_PORTS)
    elif mode == 'common':
        ports = list(COMMON_PORTS)
    elif mode == 'full':
        ports = list(range(1, 65536))
    elif mode == 'custom':
        raw = data.get('ports', '').strip()
        ports = _parse_port_spec(raw)
        if not ports:
            return jsonify({'ok': False, 'error': 'No valid ports in custom range'})
    else:
        ports = list(COMMON_PORTS)

    options = {
        'mode': mode,
        'use_nmap': bool(data.get('use_nmap', False)),
        'service_detection': bool(data.get('service_detection', False)),
        'os_detection': bool(data.get('os_detection', False)),
        'aggressive': bool(data.get('aggressive', False)),
        'timing': data.get('timing', '4'),
        'timeout': float(data.get('timeout', 1.0)),
        'concurrency': min(int(data.get('concurrency', 200)), 500),
    }

    job_id = str(uuid.uuid4())[:8]
    job = {'q': queue.Queue(), 'result': None, 'done': False, 'cancel': False}
    _jobs[job_id] = job

    t = threading.Thread(target=_do_scan, args=(job_id, host, ports, options), daemon=True)
    t.start()

    return jsonify({'ok': True, 'job_id': job_id, 'port_count': len(ports)})


@port_scanner_bp.route('/stream/<job_id>')
@login_required
def stream(job_id):
    job = _jobs.get(job_id)
    if not job:
        def err_gen():
            yield f"data: {json.dumps({'type': 'error', 'msg': 'Job not found'})}\n\n"
        return Response(err_gen(), mimetype='text/event-stream')

    def generate():
        q = job['q']
        while True:
            try:
                item = q.get(timeout=0.5)
                yield f"data: {json.dumps(item)}\n\n"
                if item.get('type') in ('done', 'error'):
                    break
            except queue.Empty:
                if job['done']:
                    break
                yield ': keepalive\n\n'

    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@port_scanner_bp.route('/result/<job_id>')
@login_required
def get_result(job_id):
    job = _jobs.get(job_id)
    if not job:
        return jsonify({'ok': False, 'error': 'Job not found'})
    if not job['done']:
        return jsonify({'ok': True, 'done': False})
    return jsonify({'ok': True, 'done': True, 'result': job['result']})


@port_scanner_bp.route('/cancel/<job_id>', methods=['POST'])
@login_required
def cancel_scan(job_id):
    job = _jobs.get(job_id)
    if job:
        job['cancel'] = True
    return jsonify({'ok': True})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_port_spec(spec: str) -> list:
    """Parse port specification: '22,80,443', '1-1024', '22,80-100,443'."""
    ports = set()
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            try:
                lo, hi = part.split('-', 1)
                lo, hi = int(lo.strip()), int(hi.strip())
                if 1 <= lo <= hi <= 65535:
                    ports.update(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                pass
    return sorted(ports)
