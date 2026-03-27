"""
AUTARCH Reverse Shell Listener
Accepts incoming reverse shell connections from the Archon Android companion app.

Protocol: JSON over TCP, newline-delimited. Matches ArchonShell.java.

Auth handshake:
  Client → Server: {"type":"auth","token":"xxx","device":"model","android":"14","uid":2000}
  Server → Client: {"type":"auth_ok"} or {"type":"auth_fail","reason":"..."}

Command flow:
  Server → Client: {"type":"cmd","cmd":"ls","timeout":30,"id":"abc"}
  Client → Server: {"type":"result","id":"abc","stdout":"...","stderr":"...","exit_code":0}

Special commands: __sysinfo__, __packages__, __screenshot__, __download__, __upload__,
                  __processes__, __netstat__, __dumplog__, __disconnect__
"""

import base64
import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

from core.paths import get_data_dir

logger = logging.getLogger('autarch.revshell')


class RevShellSession:
    """Active reverse shell session with an Archon device."""

    def __init__(self, sock: socket.socket, device_info: dict, session_id: str):
        self.socket = sock
        self.device_info = device_info
        self.session_id = session_id
        self.connected_at = datetime.now()
        self.command_log: List[dict] = []
        self._lock = threading.Lock()
        self._reader = sock.makefile('r', encoding='utf-8', errors='replace')
        self._writer = sock.makefile('w', encoding='utf-8', errors='replace')
        self._alive = True
        self._cmd_counter = 0

    @property
    def alive(self) -> bool:
        return self._alive

    @property
    def device_name(self) -> str:
        return self.device_info.get('device', 'unknown')

    @property
    def android_version(self) -> str:
        return self.device_info.get('android', '?')

    @property
    def uid(self) -> int:
        return self.device_info.get('uid', -1)

    @property
    def uptime(self) -> float:
        return (datetime.now() - self.connected_at).total_seconds()

    def execute(self, command: str, timeout: int = 30) -> dict:
        """Send a command and wait for result. Returns {stdout, stderr, exit_code}."""
        with self._lock:
            if not self._alive:
                return {'stdout': '', 'stderr': 'Session disconnected', 'exit_code': -1}

            self._cmd_counter += 1
            cmd_id = f"cmd_{self._cmd_counter}"

            msg = json.dumps({
                'type': 'cmd',
                'cmd': command,
                'timeout': timeout,
                'id': cmd_id
            })

            try:
                self._writer.write(msg + '\n')
                self._writer.flush()

                # Read response (with extended timeout for command execution)
                self.socket.settimeout(timeout + 10)
                response_line = self._reader.readline()
                if not response_line:
                    self._alive = False
                    return {'stdout': '', 'stderr': 'Connection closed', 'exit_code': -1}

                result = json.loads(response_line)

                # Log command
                self.command_log.append({
                    'time': datetime.now().isoformat(),
                    'cmd': command,
                    'exit_code': result.get('exit_code', -1)
                })

                return {
                    'stdout': result.get('stdout', ''),
                    'stderr': result.get('stderr', ''),
                    'exit_code': result.get('exit_code', -1)
                }

            except (socket.timeout, OSError, json.JSONDecodeError) as e:
                logger.error(f"Session {self.session_id}: execute error: {e}")
                self._alive = False
                return {'stdout': '', 'stderr': f'Communication error: {e}', 'exit_code': -1}

    def execute_special(self, command: str, **kwargs) -> dict:
        """Execute a special command with extra parameters."""
        with self._lock:
            if not self._alive:
                return {'stdout': '', 'stderr': 'Session disconnected', 'exit_code': -1}

            self._cmd_counter += 1
            cmd_id = f"cmd_{self._cmd_counter}"

            msg = {'type': 'cmd', 'cmd': command, 'id': cmd_id, 'timeout': 60}
            msg.update(kwargs)

            try:
                self._writer.write(json.dumps(msg) + '\n')
                self._writer.flush()

                self.socket.settimeout(70)
                response_line = self._reader.readline()
                if not response_line:
                    self._alive = False
                    return {'stdout': '', 'stderr': 'Connection closed', 'exit_code': -1}

                return json.loads(response_line)

            except (socket.timeout, OSError, json.JSONDecodeError) as e:
                logger.error(f"Session {self.session_id}: special cmd error: {e}")
                self._alive = False
                return {'stdout': '', 'stderr': f'Communication error: {e}', 'exit_code': -1}

    def sysinfo(self) -> dict:
        """Get device system information."""
        return self.execute('__sysinfo__')

    def packages(self) -> dict:
        """List installed packages."""
        return self.execute('__packages__', timeout=30)

    def screenshot(self) -> Optional[bytes]:
        """Capture screenshot. Returns PNG bytes or None."""
        result = self.execute('__screenshot__', timeout=30)
        if result['exit_code'] != 0:
            return None
        try:
            return base64.b64decode(result['stdout'])
        except Exception:
            return None

    def download(self, remote_path: str) -> Optional[Tuple[bytes, str]]:
        """Download file from device. Returns (data, filename) or None."""
        result = self.execute_special('__download__', path=remote_path)
        if result.get('exit_code', -1) != 0:
            return None
        try:
            data = base64.b64decode(result.get('stdout', ''))
            filename = result.get('filename', os.path.basename(remote_path))
            return (data, filename)
        except Exception:
            return None

    def upload(self, local_path: str, remote_path: str) -> dict:
        """Upload file to device."""
        try:
            with open(local_path, 'rb') as f:
                data = base64.b64encode(f.read()).decode('ascii')
        except IOError as e:
            return {'stdout': '', 'stderr': f'Failed to read local file: {e}', 'exit_code': -1}

        return self.execute_special('__upload__', path=remote_path, data=data)

    def processes(self) -> dict:
        """List running processes."""
        return self.execute('__processes__', timeout=10)

    def netstat(self) -> dict:
        """Get network connections."""
        return self.execute('__netstat__', timeout=10)

    def dumplog(self, lines: int = 100) -> dict:
        """Get logcat output."""
        return self.execute_special('__dumplog__', lines=min(lines, 5000))

    def ping(self) -> bool:
        """Send keepalive ping."""
        with self._lock:
            if not self._alive:
                return False
            try:
                self._writer.write('{"type":"ping"}\n')
                self._writer.flush()
                self.socket.settimeout(10)
                response = self._reader.readline()
                if not response:
                    self._alive = False
                    return False
                result = json.loads(response)
                return result.get('type') == 'pong'
            except Exception:
                self._alive = False
                return False

    def disconnect(self):
        """Gracefully disconnect the session."""
        with self._lock:
            if not self._alive:
                return
            try:
                self._writer.write('{"type":"disconnect"}\n')
                self._writer.flush()
            except Exception:
                pass
            self._alive = False
            try:
                self.socket.close()
            except Exception:
                pass

    def to_dict(self) -> dict:
        """Serialize session info for API responses."""
        return {
            'session_id': self.session_id,
            'device': self.device_name,
            'android': self.android_version,
            'uid': self.uid,
            'connected_at': self.connected_at.isoformat(),
            'uptime': int(self.uptime),
            'commands_executed': len(self.command_log),
            'alive': self._alive,
        }


class RevShellListener:
    """TCP listener for incoming Archon reverse shell connections."""

    def __init__(self, host: str = '0.0.0.0', port: int = 17322, auth_token: str = None):
        self.host = host
        self.port = port
        self.auth_token = auth_token or uuid.uuid4().hex[:32]
        self.sessions: Dict[str, RevShellSession] = {}
        self._server_socket: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()

        # Data directory for screenshots, downloads, etc.
        self._data_dir = get_data_dir() / 'revshell'
        self._data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def running(self) -> bool:
        return self._running

    @property
    def active_sessions(self) -> List[RevShellSession]:
        return [s for s in self.sessions.values() if s.alive]

    def start(self) -> Tuple[bool, str]:
        """Start listening for incoming reverse shell connections."""
        if self._running:
            return (False, 'Listener already running')

        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.settimeout(2.0)  # Accept timeout for clean shutdown
            self._server_socket.bind((self.host, self.port))
            self._server_socket.listen(5)
        except OSError as e:
            return (False, f'Failed to bind {self.host}:{self.port}: {e}')

        self._running = True

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

        self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._keepalive_thread.start()

        logger.info(f"RevShell listener started on {self.host}:{self.port}")
        logger.info(f"Auth token: {self.auth_token}")
        return (True, f'Listening on {self.host}:{self.port}')

    def stop(self):
        """Stop listener and disconnect all sessions."""
        self._running = False

        # Disconnect all sessions
        for session in list(self.sessions.values()):
            try:
                session.disconnect()
            except Exception:
                pass

        # Close server socket
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass

        # Wait for threads
        if self._accept_thread:
            self._accept_thread.join(timeout=5)
        if self._keepalive_thread:
            self._keepalive_thread.join(timeout=5)

        logger.info("RevShell listener stopped")

    def get_session(self, session_id: str) -> Optional[RevShellSession]:
        """Get session by ID."""
        return self.sessions.get(session_id)

    def list_sessions(self) -> List[dict]:
        """List all sessions with their info."""
        return [s.to_dict() for s in self.sessions.values()]

    def remove_session(self, session_id: str):
        """Disconnect and remove a session."""
        session = self.sessions.pop(session_id, None)
        if session:
            session.disconnect()

    def save_screenshot(self, session_id: str) -> Optional[str]:
        """Capture and save screenshot. Returns file path or None."""
        session = self.get_session(session_id)
        if not session or not session.alive:
            return None

        png_data = session.screenshot()
        if not png_data:
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'screenshot_{session.device_name}_{timestamp}.png'
        filepath = self._data_dir / filename
        filepath.write_bytes(png_data)
        return str(filepath)

    def save_download(self, session_id: str, remote_path: str) -> Optional[str]:
        """Download file from device and save locally. Returns local path or None."""
        session = self.get_session(session_id)
        if not session or not session.alive:
            return None

        result = session.download(remote_path)
        if not result:
            return None

        data, filename = result
        filepath = self._data_dir / filename
        filepath.write_bytes(data)
        return str(filepath)

    # ── Internal ────────────────────────────────────────────────────

    def _accept_loop(self):
        """Accept incoming connections in background thread."""
        while self._running:
            try:
                client_sock, addr = self._server_socket.accept()
                client_sock.settimeout(30)
                logger.info(f"Connection from {addr[0]}:{addr[1]}")

                # Handle auth in a separate thread to not block accept
                threading.Thread(
                    target=self._handle_new_connection,
                    args=(client_sock, addr),
                    daemon=True
                ).start()

            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    logger.error("Accept error")
                break

    def _handle_new_connection(self, sock: socket.socket, addr: tuple):
        """Authenticate a new connection."""
        try:
            reader = sock.makefile('r', encoding='utf-8', errors='replace')
            writer = sock.makefile('w', encoding='utf-8', errors='replace')

            # Read auth message
            auth_line = reader.readline()
            if not auth_line:
                sock.close()
                return

            auth_msg = json.loads(auth_line)

            if auth_msg.get('type') != 'auth':
                writer.write('{"type":"auth_fail","reason":"Expected auth message"}\n')
                writer.flush()
                sock.close()
                return

            # Verify token
            if auth_msg.get('token') != self.auth_token:
                logger.warning(f"Auth failed from {addr[0]}:{addr[1]}")
                writer.write('{"type":"auth_fail","reason":"Invalid token"}\n')
                writer.flush()
                sock.close()
                return

            # Auth OK — create session
            writer.write('{"type":"auth_ok"}\n')
            writer.flush()

            session_id = uuid.uuid4().hex[:12]
            device_info = {
                'device': auth_msg.get('device', 'unknown'),
                'android': auth_msg.get('android', '?'),
                'uid': auth_msg.get('uid', -1),
                'remote_addr': f"{addr[0]}:{addr[1]}"
            }

            session = RevShellSession(sock, device_info, session_id)
            with self._lock:
                self.sessions[session_id] = session

            logger.info(f"Session {session_id}: {device_info['device']} "
                        f"(Android {device_info['android']}, UID {device_info['uid']})")

        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Auth error from {addr[0]}:{addr[1]}: {e}")
            try:
                sock.close()
            except Exception:
                pass

    def _keepalive_loop(self):
        """Periodically ping sessions and remove dead ones."""
        while self._running:
            time.sleep(30)
            dead = []
            for sid, session in list(self.sessions.items()):
                if not session.alive:
                    dead.append(sid)
                    continue
                # Ping to check liveness
                if not session.ping():
                    dead.append(sid)
                    logger.info(f"Session {sid} lost (keepalive failed)")

            for sid in dead:
                self.sessions.pop(sid, None)


# ── Singleton ───────────────────────────────────────────────────────

_listener: Optional[RevShellListener] = None


def get_listener() -> RevShellListener:
    """Get or create the global RevShellListener singleton."""
    global _listener
    if _listener is None:
        _listener = RevShellListener()
    return _listener


def start_listener(host: str = '0.0.0.0', port: int = 17322,
                   token: str = None) -> Tuple[bool, str]:
    """Start the global listener."""
    global _listener
    _listener = RevShellListener(host=host, port=port, auth_token=token)
    return _listener.start()


def stop_listener():
    """Stop the global listener."""
    global _listener
    if _listener:
        _listener.stop()
        _listener = None
