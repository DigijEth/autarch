"""AUTARCH Container Security

Docker auditing, Kubernetes assessment, container image scanning,
escape detection, Dockerfile linting, and runtime monitoring.
"""

DESCRIPTION = "Container security — Docker & Kubernetes auditing"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "defense"

import os
import re
import sys
import json
import subprocess
import platform
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    from core.paths import get_data_dir, find_tool
except ImportError:
    def get_data_dir():
        return str(Path(__file__).parent.parent / 'data')

    import shutil

    def find_tool(name):
        return shutil.which(name)

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        RED = YELLOW = GREEN = CYAN = WHITE = DIM = RESET = BOLD = ''

    def clear_screen():
        pass

    def display_banner():
        pass


# ── Dangerous Docker capabilities ───────────────────────────────────────────

DANGEROUS_CAPS = [
    'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_RAWIO',
    'DAC_OVERRIDE', 'FOWNER', 'NET_RAW', 'MKNOD', 'SYS_CHROOT',
    'AUDIT_WRITE', 'SETFCAP', 'MAC_OVERRIDE', 'MAC_ADMIN',
    'SYSLOG', 'DAC_READ_SEARCH', 'LINUX_IMMUTABLE', 'SYS_BOOT',
    'SYS_MODULE', 'SYS_TIME', 'KILL',
]

SENSITIVE_MOUNTS = [
    '/var/run/docker.sock', '/run/docker.sock',
    '/proc', '/sys', '/dev', '/etc/shadow', '/etc/passwd',
    '/root', '/home', '/var/log',
]

DEFAULT_SECCOMP_PROFILE = 'runtime/default'

# ── Dockerfile Lint Rules ───────────────────────────────────────────────────

DOCKERFILE_RULES = {
    'DL001': {'severity': 'high', 'title': 'FROM uses :latest tag',
              'desc': 'Pin image versions for reproducible builds.'},
    'DL002': {'severity': 'high', 'title': 'No USER directive',
              'desc': 'Container runs as root by default. Add a USER directive.'},
    'DL003': {'severity': 'medium', 'title': 'ADD used instead of COPY',
              'desc': 'Use COPY for local files. ADD auto-extracts and supports URLs.'},
    'DL004': {'severity': 'high', 'title': 'Secrets in ENV/ARG',
              'desc': 'Avoid passing secrets via ENV or ARG. Use build secrets.'},
    'DL005': {'severity': 'low', 'title': 'Missing HEALTHCHECK',
              'desc': 'Add HEALTHCHECK for container orchestration readiness.'},
    'DL006': {'severity': 'medium', 'title': 'apt-get without --no-install-recommends',
              'desc': 'Use --no-install-recommends to reduce image size.'},
    'DL007': {'severity': 'low', 'title': 'Missing cache cleanup',
              'desc': 'Run apt-get clean / rm -rf /var/lib/apt/lists/* after install.'},
    'DL008': {'severity': 'medium', 'title': 'EXPOSE all interfaces',
              'desc': 'Avoid EXPOSE with 0.0.0.0; bind to specific interfaces.'},
    'DL009': {'severity': 'high', 'title': 'COPY / ADD of sensitive files',
              'desc': 'Avoid copying .env, credentials, or private keys into image.'},
    'DL010': {'severity': 'medium', 'title': 'Using sudo in RUN',
              'desc': 'Avoid sudo in Dockerfiles. Use USER directive instead.'},
    'DL011': {'severity': 'low', 'title': 'Multiple consecutive RUN commands',
              'desc': 'Chain RUN commands with && to reduce layers.'},
}

SECRET_PATTERNS = re.compile(
    r'(password|secret|token|api_key|apikey|access_key|private_key|'
    r'aws_secret|db_pass|database_url|auth_token)',
    re.IGNORECASE
)

SENSITIVE_FILE_PATTERNS = re.compile(
    r'\.(pem|key|p12|pfx|env|credentials|htpasswd|pgpass)$',
    re.IGNORECASE
)


# ── ContainerSecurity Class ─────────────────────────────────────────────────

class ContainerSecurity:
    """Docker and Kubernetes security auditing engine."""

    _instance = None

    def __init__(self):
        data = Path(str(get_data_dir())) / 'container_sec'
        data.mkdir(parents=True, exist_ok=True)
        self._data_dir = data
        self._results_path = data / 'results.json'
        self._results = {
            'docker_host': [],
            'container_audits': {},
            'image_scans': {},
            'dockerfile_lints': [],
            'k8s_audits': {},
            'escape_checks': {},
            'timestamp': None,
        }
        self._is_win = platform.system() == 'Windows'

    # ── helpers ──────────────────────────────────────────────────────────────

    def _run(self, cmd: str, timeout: int = 30) -> tuple:
        """Run a shell command. Returns (success: bool, stdout: str)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    def _run_json(self, cmd: str, timeout: int = 30) -> tuple:
        """Run command expecting JSON output. Returns (success, parsed_data)."""
        ok, raw = self._run(cmd, timeout=timeout)
        if not ok:
            return False, raw
        try:
            return True, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return False, raw

    def _save_results(self):
        self._results['timestamp'] = datetime.utcnow().isoformat()
        try:
            with open(self._results_path, 'w') as f:
                json.dump(self._results, f, indent=2, default=str)
        except Exception:
            pass

    # ── tool checks ──────────────────────────────────────────────────────────

    def check_docker_installed(self) -> dict:
        """Check if Docker CLI is available."""
        docker = find_tool('docker')
        if not docker:
            return {'installed': False, 'path': None, 'version': None}
        ok, ver = self._run(f'"{docker}" --version')
        return {
            'installed': True,
            'path': docker,
            'version': ver if ok else 'unknown',
        }

    def check_kubectl_installed(self) -> dict:
        """Check if kubectl CLI is available."""
        kubectl = find_tool('kubectl')
        if not kubectl:
            return {'installed': False, 'path': None, 'version': None, 'context': None}
        ok, ver = self._run(f'"{kubectl}" version --client --short 2>/dev/null || "{kubectl}" version --client')
        ctx_ok, ctx = self._run(f'"{kubectl}" config current-context 2>/dev/null')
        return {
            'installed': True,
            'path': kubectl,
            'version': ver if ok else 'unknown',
            'context': ctx if ctx_ok else None,
        }

    # ── Docker Host Audit ────────────────────────────────────────────────────

    def audit_docker_host(self) -> list:
        """Comprehensive Docker host security audit."""
        findings = []
        docker = find_tool('docker')
        if not docker:
            return [{'check': 'Docker CLI', 'severity': 'critical',
                      'status': 'fail', 'detail': 'Docker not found on system'}]

        # 1. Daemon configuration
        daemon_cfg_path = '/etc/docker/daemon.json'
        if self._is_win:
            daemon_cfg_path = os.path.expandvars(r'%ProgramData%\docker\config\daemon.json')

        daemon_cfg = {}
        if os.path.isfile(daemon_cfg_path):
            try:
                with open(daemon_cfg_path) as f:
                    daemon_cfg = json.load(f)
                findings.append({
                    'check': 'Daemon Config',
                    'severity': 'info',
                    'status': 'pass',
                    'detail': f'Found {daemon_cfg_path}',
                })
            except Exception as e:
                findings.append({
                    'check': 'Daemon Config',
                    'severity': 'medium',
                    'status': 'warn',
                    'detail': f'Cannot parse {daemon_cfg_path}: {e}',
                })
        else:
            findings.append({
                'check': 'Daemon Config',
                'severity': 'medium',
                'status': 'warn',
                'detail': f'No daemon.json found at {daemon_cfg_path}',
            })

        # 2. Docker socket permissions (Linux only)
        if not self._is_win:
            sock = '/var/run/docker.sock'
            if os.path.exists(sock):
                try:
                    stat = os.stat(sock)
                    mode = oct(stat.st_mode)[-3:]
                    world_rw = mode[2] in ('6', '7', '2', '3')
                    if world_rw:
                        findings.append({
                            'check': 'Docker Socket Permissions',
                            'severity': 'high',
                            'status': 'fail',
                            'detail': f'{sock} is world-accessible (mode {mode}). Restrict to docker group.',
                        })
                    else:
                        findings.append({
                            'check': 'Docker Socket Permissions',
                            'severity': 'info',
                            'status': 'pass',
                            'detail': f'{sock} permissions: {mode}',
                        })
                except Exception:
                    findings.append({
                        'check': 'Docker Socket Permissions',
                        'severity': 'low',
                        'status': 'warn',
                        'detail': 'Cannot stat docker socket',
                    })

        # 3. TLS configuration
        tls_verify = daemon_cfg.get('tls', False) or daemon_cfg.get('tlsverify', False)
        if tls_verify:
            findings.append({
                'check': 'TLS Configuration',
                'severity': 'info',
                'status': 'pass',
                'detail': 'Docker daemon TLS is enabled',
            })
        else:
            findings.append({
                'check': 'TLS Configuration',
                'severity': 'medium',
                'status': 'warn',
                'detail': 'Docker daemon TLS is not configured in daemon.json',
            })

        # 4. User namespace remapping
        userns = daemon_cfg.get('userns-remap', '')
        if userns:
            findings.append({
                'check': 'User Namespace Remapping',
                'severity': 'info',
                'status': 'pass',
                'detail': f'Remapped to: {userns}',
            })
        else:
            findings.append({
                'check': 'User Namespace Remapping',
                'severity': 'medium',
                'status': 'warn',
                'detail': 'Not enabled. Containers run as host UID 0.',
            })

        # 5. Content trust
        content_trust = os.environ.get('DOCKER_CONTENT_TRUST', '0')
        if content_trust == '1':
            findings.append({
                'check': 'Content Trust (DCT)',
                'severity': 'info',
                'status': 'pass',
                'detail': 'DOCKER_CONTENT_TRUST=1 — signed images enforced',
            })
        else:
            findings.append({
                'check': 'Content Trust (DCT)',
                'severity': 'low',
                'status': 'warn',
                'detail': 'DOCKER_CONTENT_TRUST not set. Unsigned images accepted.',
            })

        # 6. Live restore
        live_restore = daemon_cfg.get('live-restore', False)
        if live_restore:
            findings.append({
                'check': 'Live Restore',
                'severity': 'info',
                'status': 'pass',
                'detail': 'Containers survive daemon restarts',
            })
        else:
            findings.append({
                'check': 'Live Restore',
                'severity': 'low',
                'status': 'warn',
                'detail': 'live-restore not enabled in daemon.json',
            })

        # 7. Logging driver
        log_driver = daemon_cfg.get('log-driver', 'json-file')
        log_opts = daemon_cfg.get('log-opts', {})
        max_size = log_opts.get('max-size', 'unlimited')
        findings.append({
            'check': 'Logging Driver',
            'severity': 'low' if log_driver == 'json-file' and max_size == 'unlimited' else 'info',
            'status': 'warn' if max_size == 'unlimited' else 'pass',
            'detail': f'Driver: {log_driver}, max-size: {max_size}',
        })

        # 8. Docker info — check swarm, runtimes
        ok, info_raw = self._run(f'"{docker}" info --format "{{{{json .}}}}"')
        if ok:
            try:
                info = json.loads(info_raw)
                # Check default runtime
                rt = info.get('DefaultRuntime', 'runc')
                findings.append({
                    'check': 'Default Runtime',
                    'severity': 'info',
                    'status': 'pass' if rt in ('runc', 'crun') else 'info',
                    'detail': f'Runtime: {rt}',
                })
                # Swarm mode
                swarm = info.get('Swarm', {})
                swarm_active = swarm.get('LocalNodeState', 'inactive') == 'active'
                if swarm_active:
                    findings.append({
                        'check': 'Swarm Mode',
                        'severity': 'info',
                        'status': 'info',
                        'detail': 'Swarm is active. Ensure manager auto-lock is enabled.',
                    })
            except (json.JSONDecodeError, ValueError):
                pass

        self._results['docker_host'] = findings
        self._save_results()
        return findings

    # ── Container Listing / Inspection ───────────────────────────────────────

    def list_containers(self, all: bool = True) -> list:
        """List Docker containers."""
        docker = find_tool('docker')
        if not docker:
            return []

        flag = '-a' if all else ''
        fmt = '{{json .}}'
        ok, raw = self._run(f'"{docker}" ps {flag} --format "{fmt}"')
        if not ok:
            return []

        containers = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                c = json.loads(line)
                containers.append({
                    'id': c.get('ID', ''),
                    'name': c.get('Names', ''),
                    'image': c.get('Image', ''),
                    'status': c.get('Status', ''),
                    'ports': c.get('Ports', ''),
                    'created': c.get('CreatedAt', ''),
                    'state': c.get('State', ''),
                })
            except (json.JSONDecodeError, ValueError):
                continue
        return containers

    def inspect_container(self, container_id: str) -> dict:
        """Inspect a container and extract security-relevant config."""
        docker = find_tool('docker')
        if not docker:
            return {'error': 'Docker not found'}

        ok, data = self._run_json(f'"{docker}" inspect {container_id}')
        if not ok or not isinstance(data, list) or len(data) == 0:
            return {'error': f'Cannot inspect container {container_id}'}

        info = data[0]
        host_cfg = info.get('HostConfig', {})
        cfg = info.get('Config', {})

        # Capabilities
        cap_add = host_cfg.get('CapAdd') or []
        cap_drop = host_cfg.get('CapDrop') or []

        # Mounts
        mounts = []
        for m in info.get('Mounts', []):
            mounts.append({
                'source': m.get('Source', ''),
                'destination': m.get('Destination', ''),
                'mode': m.get('Mode', ''),
                'rw': m.get('RW', True),
                'type': m.get('Type', ''),
            })

        # Security options
        sec_opts = host_cfg.get('SecurityOpt') or []

        return {
            'id': info.get('Id', '')[:12],
            'name': info.get('Name', '').lstrip('/'),
            'image': cfg.get('Image', ''),
            'privileged': host_cfg.get('Privileged', False),
            'cap_add': cap_add,
            'cap_drop': cap_drop,
            'mounts': mounts,
            'network_mode': host_cfg.get('NetworkMode', ''),
            'user': cfg.get('User', '') or 'root',
            'pid_mode': host_cfg.get('PidMode', ''),
            'ipc_mode': host_cfg.get('IpcMode', ''),
            'read_only_rootfs': host_cfg.get('ReadonlyRootfs', False),
            'security_opt': sec_opts,
            'memory_limit': host_cfg.get('Memory', 0),
            'cpu_shares': host_cfg.get('CpuShares', 0),
            'pids_limit': host_cfg.get('PidsLimit', 0),
            'restart_policy': host_cfg.get('RestartPolicy', {}).get('Name', ''),
            'env': cfg.get('Env', []),
        }

    # ── Container Security Audit ─────────────────────────────────────────────

    def audit_container(self, container_id: str) -> dict:
        """Full security audit of a running container."""
        info = self.inspect_container(container_id)
        if 'error' in info:
            return info

        findings = []
        passed = 0
        total = 0

        def check(name, ok, detail='', severity='medium'):
            nonlocal passed, total
            total += 1
            if ok:
                passed += 1
            findings.append({
                'check': name,
                'status': 'pass' if ok else 'fail',
                'severity': severity if not ok else 'info',
                'detail': detail,
            })

        # 1. Privileged mode
        check('Privileged Mode',
              not info['privileged'],
              'Container is running in privileged mode!' if info['privileged']
              else 'Not privileged',
              severity='critical')

        # 2. Dangerous capabilities
        dangerous_found = [c for c in info['cap_add'] if c in DANGEROUS_CAPS]
        check('Capabilities',
              len(dangerous_found) == 0,
              f'Dangerous capabilities added: {", ".join(dangerous_found)}' if dangerous_found
              else f'No dangerous capabilities ({len(info["cap_drop"])} dropped)',
              severity='high')

        # 3. Sensitive mounts
        sensitive_found = []
        for m in info['mounts']:
            for s in SENSITIVE_MOUNTS:
                if m['destination'].startswith(s) or m['source'].startswith(s):
                    sensitive_found.append(f'{m["source"]} -> {m["destination"]}')
                    break
        check('Sensitive Mounts',
              len(sensitive_found) == 0,
              f'Sensitive paths mounted: {"; ".join(sensitive_found)}' if sensitive_found
              else 'No sensitive host paths mounted',
              severity='high')

        # 4. Running as root
        check('User',
              info['user'] not in ('', 'root', '0'),
              f'Running as: {info["user"]}' if info['user'] not in ('', 'root', '0')
              else 'Running as root. Use USER directive.',
              severity='medium')

        # 5. Read-only root filesystem
        check('Read-only Rootfs',
              info['read_only_rootfs'],
              'Root filesystem is read-only' if info['read_only_rootfs']
              else 'Root filesystem is writable. Consider --read-only.',
              severity='low')

        # 6. Resource limits — memory
        check('Memory Limit',
              info['memory_limit'] > 0,
              f'Memory limit: {info["memory_limit"] // (1024*1024)}MB' if info['memory_limit'] > 0
              else 'No memory limit set. Container can exhaust host memory.',
              severity='medium')

        # 7. Resource limits — PID
        pids = info['pids_limit']
        has_pids = pids is not None and pids > 0 and pids != -1
        check('PID Limit',
              has_pids,
              f'PID limit: {pids}' if has_pids
              else 'No PID limit. Fork bomb possible.',
              severity='low')

        # 8. Seccomp profile
        seccomp_set = any('seccomp' in opt for opt in info['security_opt'])
        no_seccomp = any('seccomp=unconfined' in opt for opt in info['security_opt'])
        check('Seccomp Profile',
              seccomp_set and not no_seccomp,
              'Seccomp profile disabled (unconfined)!' if no_seccomp
              else ('Custom seccomp profile applied' if seccomp_set
                    else 'Default seccomp profile (OK for Docker default)'),
              severity='high' if no_seccomp else 'low')

        # 9. AppArmor profile
        apparmor_set = any('apparmor' in opt for opt in info['security_opt'])
        no_apparmor = any('apparmor=unconfined' in opt for opt in info['security_opt'])
        check('AppArmor Profile',
              not no_apparmor,
              'AppArmor disabled (unconfined)!' if no_apparmor
              else ('AppArmor profile applied' if apparmor_set
                    else 'No explicit AppArmor profile (using Docker default)'),
              severity='medium' if no_apparmor else 'low')

        # 10. Network mode
        check('Network Mode',
              info['network_mode'] not in ('host',),
              f'Network mode: {info["network_mode"]}',
              severity='high' if info['network_mode'] == 'host' else 'info')

        # 11. PID mode
        check('PID Mode',
              info['pid_mode'] != 'host',
              'PID namespace shared with host!' if info['pid_mode'] == 'host'
              else f'PID mode: {info["pid_mode"] or "container (isolated)"}',
              severity='high')

        # 12. Secrets in environment
        env_secrets = []
        for e in info.get('env', []):
            key = e.split('=', 1)[0] if '=' in e else e
            if SECRET_PATTERNS.search(key):
                env_secrets.append(key)
        check('Environment Secrets',
              len(env_secrets) == 0,
              f'Possible secrets in ENV: {", ".join(env_secrets)}' if env_secrets
              else 'No obvious secrets in environment variables',
              severity='medium')

        score = int((passed / total) * 100) if total > 0 else 0

        result = {
            'container_id': container_id,
            'name': info.get('name', ''),
            'image': info.get('image', ''),
            'score': score,
            'passed': passed,
            'total': total,
            'findings': findings,
        }

        self._results['container_audits'][container_id] = result
        self._save_results()
        return result

    # ── Image Operations ─────────────────────────────────────────────────────

    def list_images(self) -> list:
        """List local Docker images."""
        docker = find_tool('docker')
        if not docker:
            return []

        fmt = '{{json .}}'
        ok, raw = self._run(f'"{docker}" images --format "{fmt}"')
        if not ok:
            return []

        images = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                img = json.loads(line)
                images.append({
                    'id': img.get('ID', ''),
                    'repo': img.get('Repository', ''),
                    'tag': img.get('Tag', ''),
                    'size': img.get('Size', ''),
                    'created': img.get('CreatedAt', img.get('CreatedSince', '')),
                })
            except (json.JSONDecodeError, ValueError):
                continue
        return images

    def scan_image(self, image_name: str) -> dict:
        """Scan a container image for CVEs using trivy or grype."""
        # Try trivy first
        trivy = find_tool('trivy')
        if trivy:
            ok, raw = self._run(
                f'"{trivy}" image --format json --severity CRITICAL,HIGH,MEDIUM,LOW '
                f'--quiet "{image_name}"',
                timeout=120
            )
            if ok:
                return self._parse_trivy(raw, image_name)

        # Fallback to grype
        grype = find_tool('grype')
        if grype:
            ok, raw = self._run(
                f'"{grype}" "{image_name}" -o json --quiet',
                timeout=120
            )
            if ok:
                return self._parse_grype(raw, image_name)

        return {
            'image': image_name,
            'scanner': None,
            'error': 'No scanner available. Install trivy or grype.',
            'vulnerabilities': [],
            'summary': {},
        }

    def _parse_trivy(self, raw: str, image_name: str) -> dict:
        """Parse Trivy JSON output."""
        vulns = []
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        try:
            data = json.loads(raw)
            results = data.get('Results', [])
            for r in results:
                for v in r.get('Vulnerabilities', []):
                    sev = v.get('Severity', 'UNKNOWN').upper()
                    entry = {
                        'cve': v.get('VulnerabilityID', ''),
                        'severity': sev,
                        'package': v.get('PkgName', ''),
                        'installed_version': v.get('InstalledVersion', ''),
                        'fixed_version': v.get('FixedVersion', ''),
                        'title': v.get('Title', ''),
                    }
                    vulns.append(entry)
                    if sev in summary:
                        summary[sev] += 1
        except (json.JSONDecodeError, ValueError):
            return {'image': image_name, 'scanner': 'trivy',
                    'error': 'Failed to parse trivy output', 'vulnerabilities': [], 'summary': {}}

        result = {
            'image': image_name,
            'scanner': 'trivy',
            'vulnerabilities': vulns,
            'summary': summary,
            'total': len(vulns),
        }
        self._results['image_scans'][image_name] = result
        self._save_results()
        return result

    def _parse_grype(self, raw: str, image_name: str) -> dict:
        """Parse Grype JSON output."""
        vulns = []
        summary = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        try:
            data = json.loads(raw)
            for m in data.get('matches', []):
                v = m.get('vulnerability', {})
                sev = v.get('severity', 'Unknown').upper()
                pkg = m.get('artifact', {})
                fixed = ''
                fix_vers = v.get('fix', {}).get('versions', [])
                if fix_vers:
                    fixed = fix_vers[0]
                entry = {
                    'cve': v.get('id', ''),
                    'severity': sev,
                    'package': pkg.get('name', ''),
                    'installed_version': pkg.get('version', ''),
                    'fixed_version': fixed,
                    'title': v.get('description', '')[:120],
                }
                vulns.append(entry)
                if sev in summary:
                    summary[sev] += 1
        except (json.JSONDecodeError, ValueError):
            return {'image': image_name, 'scanner': 'grype',
                    'error': 'Failed to parse grype output', 'vulnerabilities': [], 'summary': {}}

        result = {
            'image': image_name,
            'scanner': 'grype',
            'vulnerabilities': vulns,
            'summary': summary,
            'total': len(vulns),
        }
        self._results['image_scans'][image_name] = result
        self._save_results()
        return result

    # ── Dockerfile Linting ───────────────────────────────────────────────────

    def lint_dockerfile(self, content: str) -> list:
        """Lint a Dockerfile for security issues."""
        findings = []
        lines = content.splitlines()
        has_user = False
        has_healthcheck = False
        consecutive_run = 0
        max_consecutive_run = 0

        for i, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                consecutive_run = 0
                continue

            upper = line.upper()

            # FROM :latest
            if upper.startswith('FROM '):
                img = line[5:].strip().split(' ')[0]
                if ':' not in img or img.endswith(':latest'):
                    findings.append({
                        'rule': 'DL001', 'line': i,
                        'severity': DOCKERFILE_RULES['DL001']['severity'],
                        'title': DOCKERFILE_RULES['DL001']['title'],
                        'detail': f'Image "{img}" — pin a specific version tag.',
                    })

            # USER directive
            if upper.startswith('USER '):
                has_user = True

            # HEALTHCHECK
            if upper.startswith('HEALTHCHECK '):
                has_healthcheck = True

            # ADD vs COPY
            if upper.startswith('ADD ') and not line.strip().startswith('ADD --from'):
                parts = line[4:].strip()
                # Skip if it's a URL (ADD has valid URL use)
                if not parts.startswith('http://') and not parts.startswith('https://'):
                    findings.append({
                        'rule': 'DL003', 'line': i,
                        'severity': DOCKERFILE_RULES['DL003']['severity'],
                        'title': DOCKERFILE_RULES['DL003']['title'],
                        'detail': f'Line {i}: prefer COPY over ADD for local files.',
                    })

            # Secrets in ENV/ARG
            if upper.startswith('ENV ') or upper.startswith('ARG '):
                key = line.split()[1] if len(line.split()) > 1 else ''
                key = key.split('=')[0]
                if SECRET_PATTERNS.search(key):
                    findings.append({
                        'rule': 'DL004', 'line': i,
                        'severity': DOCKERFILE_RULES['DL004']['severity'],
                        'title': DOCKERFILE_RULES['DL004']['title'],
                        'detail': f'Line {i}: "{key}" looks like a secret. Use --secret instead.',
                    })

            # apt-get without --no-install-recommends
            if 'apt-get install' in line and '--no-install-recommends' not in line:
                findings.append({
                    'rule': 'DL006', 'line': i,
                    'severity': DOCKERFILE_RULES['DL006']['severity'],
                    'title': DOCKERFILE_RULES['DL006']['title'],
                    'detail': f'Line {i}: add --no-install-recommends to reduce image size.',
                })

            # COPY/ADD of sensitive files
            if upper.startswith('COPY ') or upper.startswith('ADD '):
                if SENSITIVE_FILE_PATTERNS.search(line):
                    findings.append({
                        'rule': 'DL009', 'line': i,
                        'severity': DOCKERFILE_RULES['DL009']['severity'],
                        'title': DOCKERFILE_RULES['DL009']['title'],
                        'detail': f'Line {i}: copying potentially sensitive file into image.',
                    })

            # sudo in RUN
            if upper.startswith('RUN ') and 'sudo ' in line:
                findings.append({
                    'rule': 'DL010', 'line': i,
                    'severity': DOCKERFILE_RULES['DL010']['severity'],
                    'title': DOCKERFILE_RULES['DL010']['title'],
                    'detail': f'Line {i}: avoid sudo in Dockerfiles.',
                })

            # Consecutive RUN
            if upper.startswith('RUN '):
                consecutive_run += 1
                if consecutive_run > max_consecutive_run:
                    max_consecutive_run = consecutive_run
            else:
                consecutive_run = 0

        # Post-scan checks
        if not has_user:
            findings.append({
                'rule': 'DL002', 'line': 0,
                'severity': DOCKERFILE_RULES['DL002']['severity'],
                'title': DOCKERFILE_RULES['DL002']['title'],
                'detail': 'No USER directive found. Container will run as root.',
            })

        if not has_healthcheck:
            findings.append({
                'rule': 'DL005', 'line': 0,
                'severity': DOCKERFILE_RULES['DL005']['severity'],
                'title': DOCKERFILE_RULES['DL005']['title'],
                'detail': 'No HEALTHCHECK instruction. Add one for orchestration.',
            })

        if max_consecutive_run >= 3:
            findings.append({
                'rule': 'DL011', 'line': 0,
                'severity': DOCKERFILE_RULES['DL011']['severity'],
                'title': DOCKERFILE_RULES['DL011']['title'],
                'detail': f'{max_consecutive_run} consecutive RUN commands. Chain with && to reduce layers.',
            })

        # Check for missing cache cleanup
        if 'apt-get install' in content and 'rm -rf /var/lib/apt/lists' not in content:
            findings.append({
                'rule': 'DL007', 'line': 0,
                'severity': DOCKERFILE_RULES['DL007']['severity'],
                'title': DOCKERFILE_RULES['DL007']['title'],
                'detail': 'apt-get install used without cleaning /var/lib/apt/lists/*.',
            })

        self._results['dockerfile_lints'] = findings
        self._save_results()
        return findings

    # ── Container Escape Detection ───────────────────────────────────────────

    def check_escape_vectors(self, container_id: str) -> dict:
        """Check for container escape possibilities."""
        info = self.inspect_container(container_id)
        if 'error' in info:
            return info

        vectors = []

        def vec(name, risk, exploitable, detail):
            vectors.append({
                'vector': name,
                'risk': risk,
                'exploitable': exploitable,
                'detail': detail,
            })

        # 1. Privileged mode — full escape
        if info['privileged']:
            vec('Privileged Mode', 'critical', True,
                'Container has full access to host devices and kernel. '
                'Trivial escape via mounting host filesystem.')

        # 2. Docker socket mount
        sock_mounted = any(
            '/var/run/docker.sock' in m.get('source', '') or
            '/run/docker.sock' in m.get('source', '')
            for m in info['mounts']
        )
        if sock_mounted:
            vec('Docker Socket Mount', 'critical', True,
                'Docker socket mounted inside container. Attacker can spawn '
                'privileged containers on the host.')

        # 3. SYS_ADMIN capability
        if 'SYS_ADMIN' in info.get('cap_add', []):
            vec('SYS_ADMIN Capability', 'high', True,
                'SYS_ADMIN allows mounting filesystems, modifying cgroups. '
                'Combined with other misconfigs, can lead to escape.')

        # 4. SYS_PTRACE capability
        if 'SYS_PTRACE' in info.get('cap_add', []):
            vec('SYS_PTRACE Capability', 'high', True,
                'SYS_PTRACE allows process injection and debugging. '
                'Can be used to escape via process injection into host PID.')

        # 5. Host PID namespace
        if info.get('pid_mode') == 'host':
            vec('Host PID Namespace', 'high', True,
                'Container shares PID namespace with host. Processes visible '
                'and injectable from container.')

        # 6. Host network namespace
        if info.get('network_mode') == 'host':
            vec('Host Network Namespace', 'medium', False,
                'Container shares host network stack. Can sniff host traffic '
                'and access services on localhost.')

        # 7. /proc write access
        proc_mounted = any(
            m.get('destination', '').startswith('/proc') and m.get('rw', True)
            for m in info['mounts']
        )
        if proc_mounted:
            vec('/proc Write Access', 'high', True,
                'Writable /proc mount can enable kernel parameter modification '
                'and cgroup escape techniques.')

        # 8. Kernel version (check for known container escape CVEs)
        ok, uname = self._run('uname -r 2>/dev/null')
        if ok and uname:
            kernel = uname.strip()
            # Known vulnerable kernel ranges (simplified check)
            vec('Kernel Version', 'info', False,
                f'Host kernel: {kernel}. Check against CVE-2022-0185, '
                f'CVE-2022-0847 (DirtyPipe), CVE-2021-22555.')

        # 9. Cgroup escape
        if info['privileged'] or 'SYS_ADMIN' in info.get('cap_add', []):
            vec('Cgroup Escape', 'critical' if info['privileged'] else 'high', True,
                'Privileged + cgroup v1 release_agent technique enables full '
                'host command execution.')

        # 10. Seccomp disabled
        if any('seccomp=unconfined' in opt for opt in info.get('security_opt', [])):
            vec('Seccomp Disabled', 'medium', False,
                'No seccomp filter. All syscalls available including '
                'those needed for escape techniques.')

        # 11. AppArmor disabled
        if any('apparmor=unconfined' in opt for opt in info.get('security_opt', [])):
            vec('AppArmor Disabled', 'medium', False,
                'No AppArmor confinement. Reduced protection against '
                'filesystem and network abuse.')

        risk_score = 0
        for v in vectors:
            w = {'critical': 40, 'high': 25, 'medium': 10, 'low': 5, 'info': 0}
            risk_score += w.get(v['risk'], 0)
        risk_score = min(risk_score, 100)

        result = {
            'container_id': container_id,
            'name': info.get('name', ''),
            'vectors': vectors,
            'risk_score': risk_score,
            'total_vectors': len(vectors),
            'exploitable': sum(1 for v in vectors if v['exploitable']),
        }

        self._results['escape_checks'][container_id] = result
        self._save_results()
        return result

    # ── Kubernetes Operations ────────────────────────────────────────────────

    def _kubectl(self, args: str, timeout: int = 30) -> tuple:
        kubectl = find_tool('kubectl')
        if not kubectl:
            return False, 'kubectl not found'
        return self._run(f'"{kubectl}" {args}', timeout=timeout)

    def _kubectl_json(self, args: str, timeout: int = 30) -> tuple:
        kubectl = find_tool('kubectl')
        if not kubectl:
            return False, 'kubectl not found'
        return self._run_json(f'"{kubectl}" {args} -o json', timeout=timeout)

    def k8s_get_namespaces(self) -> list:
        """List Kubernetes namespaces."""
        ok, data = self._kubectl_json('get namespaces')
        if not ok:
            return []
        namespaces = []
        for item in data.get('items', []):
            meta = item.get('metadata', {})
            namespaces.append({
                'name': meta.get('name', ''),
                'status': item.get('status', {}).get('phase', ''),
                'age': meta.get('creationTimestamp', ''),
            })
        return namespaces

    def k8s_get_pods(self, namespace: str = 'default') -> list:
        """List pods in a namespace."""
        ok, data = self._kubectl_json(f'get pods -n {namespace}')
        if not ok:
            return []
        pods = []
        for item in data.get('items', []):
            meta = item.get('metadata', {})
            spec = item.get('spec', {})
            status = item.get('status', {})
            containers = [c.get('name', '') for c in spec.get('containers', [])]
            pod_status = status.get('phase', 'Unknown')
            conditions = status.get('conditions', [])
            ready = any(c.get('type') == 'Ready' and c.get('status') == 'True'
                        for c in conditions)
            pods.append({
                'name': meta.get('name', ''),
                'namespace': meta.get('namespace', namespace),
                'status': pod_status,
                'ready': ready,
                'containers': containers,
                'node': spec.get('nodeName', ''),
                'age': meta.get('creationTimestamp', ''),
                'restart_count': sum(
                    cs.get('restartCount', 0)
                    for cs in status.get('containerStatuses', [])
                ),
            })
        return pods

    def k8s_audit_rbac(self, namespace: Optional[str] = None) -> dict:
        """Audit RBAC for overly permissive bindings."""
        findings = []

        # Cluster role bindings
        ok, data = self._kubectl_json('get clusterrolebindings')
        if ok:
            for item in data.get('items', []):
                meta = item.get('metadata', {})
                role_ref = item.get('roleRef', {})
                subjects = item.get('subjects', [])

                if role_ref.get('name') == 'cluster-admin':
                    for subj in subjects:
                        findings.append({
                            'severity': 'critical',
                            'type': 'cluster-admin binding',
                            'binding': meta.get('name', ''),
                            'subject': f'{subj.get("kind", "")}/{subj.get("name", "")}',
                            'detail': 'cluster-admin grants full cluster access',
                        })

        # Check for wildcard permissions in cluster roles
        ok, data = self._kubectl_json('get clusterroles')
        if ok:
            for item in data.get('items', []):
                meta = item.get('metadata', {})
                role_name = meta.get('name', '')
                for rule in item.get('rules', []):
                    verbs = rule.get('verbs', [])
                    resources = rule.get('resources', [])
                    api_groups = rule.get('apiGroups', [])
                    if '*' in verbs and '*' in resources:
                        findings.append({
                            'severity': 'high',
                            'type': 'wildcard permissions',
                            'binding': role_name,
                            'subject': '',
                            'detail': f'Role "{role_name}" has wildcard verbs and resources '
                                      f'on apiGroups: {api_groups}',
                        })

        # Check service account token automount
        ns_flag = f'-n {namespace}' if namespace else '--all-namespaces'
        ok, data = self._kubectl_json(f'get serviceaccounts {ns_flag}')
        if ok:
            for item in data.get('items', []):
                meta = item.get('metadata', {})
                automount = item.get('automountServiceAccountToken', True)
                if automount and meta.get('name') != 'default':
                    findings.append({
                        'severity': 'low',
                        'type': 'token automount',
                        'binding': meta.get('name', ''),
                        'subject': f'namespace/{meta.get("namespace", "")}',
                        'detail': f'SA "{meta.get("name")}" has automountServiceAccountToken enabled',
                    })

        result = {'findings': findings, 'total': len(findings)}
        self._results['k8s_audits']['rbac'] = result
        self._save_results()
        return result

    def k8s_check_secrets(self, namespace: str = 'default') -> dict:
        """Check for exposed or unencrypted secrets."""
        findings = []

        ok, data = self._kubectl_json(f'get secrets -n {namespace}')
        if not ok:
            return {'error': 'Cannot list secrets', 'findings': []}

        for item in data.get('items', []):
            meta = item.get('metadata', {})
            secret_type = item.get('type', '')
            secret_name = meta.get('name', '')
            data_keys = list((item.get('data') or {}).keys())

            # Check for default token (legacy, pre-1.24)
            if secret_type == 'kubernetes.io/service-account-token':
                findings.append({
                    'severity': 'info',
                    'name': secret_name,
                    'type': secret_type,
                    'detail': f'SA token secret with keys: {", ".join(data_keys)}',
                })

            # Check for Opaque secrets with suspicious names
            if secret_type == 'Opaque':
                for key in data_keys:
                    if SECRET_PATTERNS.search(key):
                        findings.append({
                            'severity': 'medium',
                            'name': secret_name,
                            'type': secret_type,
                            'detail': f'Key "{key}" may contain credentials',
                        })

        # Check which pods mount secrets
        ok, pod_data = self._kubectl_json(f'get pods -n {namespace}')
        if ok:
            for pod in pod_data.get('items', []):
                pod_name = pod.get('metadata', {}).get('name', '')
                volumes = pod.get('spec', {}).get('volumes', [])
                for vol in volumes:
                    if vol.get('secret'):
                        findings.append({
                            'severity': 'info',
                            'name': vol['secret'].get('secretName', ''),
                            'type': 'mounted',
                            'detail': f'Secret mounted in pod "{pod_name}"',
                        })

        result = {'findings': findings, 'total': len(findings), 'namespace': namespace}
        self._results['k8s_audits']['secrets'] = result
        self._save_results()
        return result

    def k8s_check_network_policies(self, namespace: str = 'default') -> dict:
        """Check if network policies exist and find unprotected pods."""
        findings = []

        ok, data = self._kubectl_json(f'get networkpolicies -n {namespace}')
        policies = data.get('items', []) if ok else []

        if not policies:
            findings.append({
                'severity': 'high',
                'type': 'no_policies',
                'detail': f'No NetworkPolicies found in namespace "{namespace}". '
                          f'All pod-to-pod traffic is allowed.',
            })
            return {'findings': findings, 'total': 1, 'namespace': namespace,
                    'policy_count': 0, 'unprotected_pods': []}

        # Collect pod selectors covered by policies
        covered_labels = set()
        for pol in policies:
            spec = pol.get('spec', {})
            selector = spec.get('podSelector', {})
            match_labels = selector.get('matchLabels', {})
            if not match_labels:
                covered_labels.add('__all__')
            else:
                for k, v in match_labels.items():
                    covered_labels.add(f'{k}={v}')

        # Check pods without matching policies
        unprotected = []
        if '__all__' not in covered_labels:
            ok, pod_data = self._kubectl_json(f'get pods -n {namespace}')
            if ok:
                for pod in pod_data.get('items', []):
                    meta = pod.get('metadata', {})
                    labels = meta.get('labels', {})
                    pod_labels = {f'{k}={v}' for k, v in labels.items()}
                    if not pod_labels.intersection(covered_labels):
                        unprotected.append(meta.get('name', ''))

        if unprotected:
            findings.append({
                'severity': 'medium',
                'type': 'unprotected_pods',
                'detail': f'{len(unprotected)} pod(s) not covered by any NetworkPolicy',
            })

        result = {
            'findings': findings,
            'total': len(findings),
            'namespace': namespace,
            'policy_count': len(policies),
            'unprotected_pods': unprotected,
        }
        self._results['k8s_audits']['network_policies'] = result
        self._save_results()
        return result

    def k8s_audit_pod(self, pod_name: str, namespace: str = 'default') -> dict:
        """Security audit of a Kubernetes pod."""
        ok, data = self._kubectl_json(f'get pod {pod_name} -n {namespace}')
        if not ok:
            return {'error': f'Cannot get pod {pod_name}'}

        spec = data.get('spec', {})
        findings = []
        passed = 0
        total = 0

        def check(name, ok, detail='', severity='medium'):
            nonlocal passed, total
            total += 1
            if ok:
                passed += 1
            findings.append({
                'check': name,
                'status': 'pass' if ok else 'fail',
                'severity': severity if not ok else 'info',
                'detail': detail,
            })

        # Host namespaces
        check('Host Network',
              not spec.get('hostNetwork', False),
              'Pod uses host network namespace!' if spec.get('hostNetwork') else 'Isolated',
              severity='high')
        check('Host PID',
              not spec.get('hostPID', False),
              'Pod uses host PID namespace!' if spec.get('hostPID') else 'Isolated',
              severity='high')
        check('Host IPC',
              not spec.get('hostIPC', False),
              'Pod uses host IPC namespace!' if spec.get('hostIPC') else 'Isolated',
              severity='high')

        # Per-container checks
        for container in spec.get('containers', []):
            c_name = container.get('name', 'unknown')
            sec_ctx = container.get('securityContext', {})

            # Privileged
            priv = sec_ctx.get('privileged', False)
            check(f'{c_name}: Privileged',
                  not priv,
                  'Container is privileged!' if priv else 'Not privileged',
                  severity='critical')

            # Run as root
            run_as_user = sec_ctx.get('runAsUser')
            run_as_non_root = sec_ctx.get('runAsNonRoot', False)
            is_root = run_as_user == 0 or (run_as_user is None and not run_as_non_root)
            check(f'{c_name}: Root User',
                  not is_root,
                  f'Runs as UID {run_as_user}' if run_as_user and run_as_user != 0
                  else ('runAsNonRoot=true' if run_as_non_root else 'May run as root'),
                  severity='medium')

            # Read-only root filesystem
            ro = sec_ctx.get('readOnlyRootFilesystem', False)
            check(f'{c_name}: Read-only Rootfs',
                  ro,
                  'Root filesystem is read-only' if ro else 'Writable root filesystem',
                  severity='low')

            # Resource limits
            resources = container.get('resources', {})
            limits = resources.get('limits', {})
            has_limits = bool(limits.get('memory') or limits.get('cpu'))
            check(f'{c_name}: Resource Limits',
                  has_limits,
                  f'Limits: {limits}' if has_limits else 'No resource limits set',
                  severity='medium')

            # Capabilities
            caps = sec_ctx.get('capabilities', {})
            cap_add = caps.get('add', [])
            dangerous = [c for c in cap_add if c in DANGEROUS_CAPS]
            all_dropped = 'ALL' in caps.get('drop', [])
            check(f'{c_name}: Capabilities',
                  len(dangerous) == 0 and (all_dropped or not cap_add),
                  f'Dangerous caps: {", ".join(dangerous)}' if dangerous
                  else ('All capabilities dropped' if all_dropped else 'Default capabilities'),
                  severity='high' if dangerous else 'info')

            # Privilege escalation
            allow_escalation = sec_ctx.get('allowPrivilegeEscalation', True)
            check(f'{c_name}: Privilege Escalation',
                  not allow_escalation,
                  'allowPrivilegeEscalation=true' if allow_escalation
                  else 'Privilege escalation disabled',
                  severity='medium')

        # Service account
        sa = spec.get('serviceAccountName', 'default')
        automount = spec.get('automountServiceAccountToken', True)
        check('Service Account',
              sa != 'default' or not automount,
              f'SA: {sa}, automount: {automount}',
              severity='low')

        score = int((passed / total) * 100) if total > 0 else 0
        result = {
            'pod': pod_name,
            'namespace': namespace,
            'score': score,
            'passed': passed,
            'total': total,
            'findings': findings,
        }
        self._results['k8s_audits'][f'pod:{namespace}/{pod_name}'] = result
        self._save_results()
        return result

    # ── Export ────────────────────────────────────────────────────────────────

    def export_results(self, fmt: str = 'json') -> dict:
        """Export all audit results."""
        self._results['timestamp'] = datetime.utcnow().isoformat()
        if fmt == 'json':
            path = self._data_dir / f'container_sec_export_{int(time.time())}.json'
            with open(path, 'w') as f:
                json.dump(self._results, f, indent=2, default=str)
            return {'path': str(path), 'format': 'json', 'success': True}
        return {'error': f'Unsupported format: {fmt}'}


# ── Singleton ────────────────────────────────────────────────────────────────

_instance = None


def get_container_sec() -> ContainerSecurity:
    global _instance
    if _instance is None:
        _instance = ContainerSecurity()
    return _instance


# ── CLI Entry Point ──────────────────────────────────────────────────────────

def run():
    """CLI entry point for Container Security module."""
    cs = get_container_sec()

    while True:
        print(f"\n{'='*60}")
        print(f"  Container Security")
        print(f"{'='*60}")
        print()
        print("  1 — Audit Docker Host")
        print("  2 — List Containers")
        print("  3 — Audit Container")
        print("  4 — Scan Image")
        print("  5 — Lint Dockerfile")
        print("  6 — K8s Pods")
        print("  7 — K8s RBAC Audit")
        print("  0 — Back")
        print()

        choice = input("  > ").strip()

        if choice == '0':
            break

        elif choice == '1':
            print("\n  [*] Auditing Docker host...")
            findings = cs.audit_docker_host()
            if not findings:
                print("  [-] No findings.")
            for f in findings:
                sev = f.get('severity', 'info').upper()
                status = f.get('status', 'info').upper()
                color = {'CRITICAL': Colors.RED, 'HIGH': Colors.RED,
                         'MEDIUM': Colors.YELLOW, 'LOW': Colors.CYAN,
                         'INFO': Colors.GREEN}.get(sev, Colors.WHITE)
                print(f"  {color}[{sev}]{Colors.RESET} {f['check']}: {f['detail']}")

        elif choice == '2':
            containers = cs.list_containers(all=True)
            if not containers:
                print("  [-] No containers found.")
            else:
                print(f"\n  {'ID':<14} {'Name':<25} {'Image':<30} {'Status':<15}")
                print(f"  {'-'*14} {'-'*25} {'-'*30} {'-'*15}")
                for c in containers:
                    print(f"  {c['id']:<14} {c['name']:<25} {c['image']:<30} {c['status']:<15}")

        elif choice == '3':
            cid = input("  Container ID or name: ").strip()
            if cid:
                print(f"\n  [*] Auditing container {cid}...")
                result = cs.audit_container(cid)
                if 'error' in result:
                    print(f"  [!] {result['error']}")
                else:
                    print(f"\n  Security Score: {result['score']}% ({result['passed']}/{result['total']})")
                    for f in result['findings']:
                        sym = '+' if f['status'] == 'pass' else '!'
                        color = Colors.GREEN if f['status'] == 'pass' else Colors.YELLOW
                        print(f"  {color}[{sym}]{Colors.RESET} {f['check']}: {f['detail']}")

        elif choice == '4':
            img = input("  Image name (e.g., nginx:latest): ").strip()
            if img:
                print(f"\n  [*] Scanning {img} for vulnerabilities...")
                result = cs.scan_image(img)
                if result.get('error'):
                    print(f"  [!] {result['error']}")
                else:
                    s = result.get('summary', {})
                    print(f"  Scanner: {result.get('scanner', '?')}")
                    print(f"  Total: {result.get('total', 0)} vulnerabilities")
                    print(f"  Critical: {s.get('CRITICAL', 0)}  High: {s.get('HIGH', 0)}  "
                          f"Medium: {s.get('MEDIUM', 0)}  Low: {s.get('LOW', 0)}")
                    for v in result.get('vulnerabilities', [])[:20]:
                        print(f"    {v['severity']:<8} {v['cve']:<18} {v['package']:<20} "
                              f"{v['installed_version']} -> {v.get('fixed_version', 'n/a')}")

        elif choice == '5':
            path = input("  Path to Dockerfile: ").strip()
            if path and os.path.isfile(path):
                with open(path) as f:
                    content = f.read()
                findings = cs.lint_dockerfile(content)
                if not findings:
                    print("  [+] No issues found.")
                else:
                    print(f"\n  Found {len(findings)} issue(s):")
                    for f in findings:
                        sev = f.get('severity', 'info').upper()
                        line = f"line {f['line']}" if f.get('line') else 'general'
                        print(f"  [{sev}] {f['rule']}: {f['title']} ({line})")
                        print(f"         {f['detail']}")
            else:
                print("  [!] File not found.")

        elif choice == '6':
            ns = input("  Namespace (default): ").strip() or 'default'
            pods = cs.k8s_get_pods(namespace=ns)
            if not pods:
                print("  [-] No pods found.")
            else:
                print(f"\n  {'Name':<35} {'Status':<12} {'Node':<20} {'Restarts':<10}")
                print(f"  {'-'*35} {'-'*12} {'-'*20} {'-'*10}")
                for p in pods:
                    print(f"  {p['name']:<35} {p['status']:<12} {p['node']:<20} {p['restart_count']:<10}")

        elif choice == '7':
            ns = input("  Namespace (blank for all): ").strip() or None
            print("\n  [*] Auditing RBAC...")
            result = cs.k8s_audit_rbac(namespace=ns)
            if not result.get('findings'):
                print("  [+] No RBAC issues found.")
            else:
                print(f"  Found {result['total']} issue(s):")
                for f in result['findings']:
                    sev = f.get('severity', 'info').upper()
                    print(f"  [{sev}] {f['type']}: {f.get('binding', '')} — {f['detail']}")
