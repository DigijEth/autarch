"""DNS Service web routes — manage the Go-based DNS server from the dashboard."""

from flask import Blueprint, render_template, request, jsonify
from web.auth import login_required

dns_service_bp = Blueprint('dns_service', __name__, url_prefix='/dns')


def _mgr():
    from core.dns_service import get_dns_service
    return get_dns_service()


@dns_service_bp.route('/')
@login_required
def index():
    return render_template('dns_service.html')


@dns_service_bp.route('/nameserver')
@login_required
def nameserver():
    return render_template('dns_nameserver.html')


@dns_service_bp.route('/network-info')
@login_required
def network_info():
    """Auto-detect local network info for EZ-Local setup."""
    import socket
    import subprocess as sp
    info = {'ok': True}

    # Hostname
    info['hostname'] = socket.gethostname()
    try:
        info['fqdn'] = socket.getfqdn()
    except Exception:
        info['fqdn'] = info['hostname']

    # Local IPs
    local_ips = []
    try:
        # Connect to external to find default route IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        default_ip = s.getsockname()[0]
        s.close()
        info['default_ip'] = default_ip
    except Exception:
        info['default_ip'] = '127.0.0.1'

    # Gateway detection
    try:
        r = sp.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=5)
        if r.stdout:
            parts = r.stdout.split()
            if 'via' in parts:
                info['gateway'] = parts[parts.index('via') + 1]
    except Exception:
        pass
    if 'gateway' not in info:
        try:
            # Windows: parse ipconfig or route print
            r = sp.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == '0.0.0.0':
                    info['gateway'] = parts[2]
                    break
        except Exception:
            info['gateway'] = ''

    # Subnet guess from default IP
    ip = info.get('default_ip', '')
    if ip and ip != '127.0.0.1':
        parts = ip.split('.')
        if len(parts) == 4:
            info['subnet'] = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            info['network_prefix'] = f"{parts[0]}.{parts[1]}.{parts[2]}"

    # ARP table for existing hosts
    hosts = []
    try:
        r = sp.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
        for line in r.stdout.splitlines():
            # Parse arp output (Windows: "  192.168.1.1  00-aa-bb-cc-dd-ee  dynamic")
            parts = line.split()
            if len(parts) >= 2:
                candidate = parts[0].strip()
                if candidate.count('.') == 3 and not candidate.startswith('224.') and not candidate.startswith('255.'):
                    try:
                        socket.inet_aton(candidate)
                        mac = parts[1] if len(parts) >= 2 else ''
                        # Try reverse DNS
                        try:
                            name = socket.gethostbyaddr(candidate)[0]
                        except Exception:
                            name = ''
                        hosts.append({'ip': candidate, 'mac': mac, 'name': name})
                    except Exception:
                        pass
    except Exception:
        pass
    info['hosts'] = hosts[:50]  # Limit

    return jsonify(info)


@dns_service_bp.route('/nameserver/binary-info')
@login_required
def binary_info():
    """Get info about the Go nameserver binary."""
    mgr = _mgr()
    binary = mgr.find_binary()
    info = {
        'ok': True,
        'found': binary is not None,
        'path': binary,
        'running': mgr.is_running(),
        'pid': mgr._pid,
        'config_path': mgr._config_path,
        'listen_dns': mgr._config.get('listen_dns', ''),
        'listen_api': mgr._config.get('listen_api', ''),
        'upstream': mgr._config.get('upstream', []),
    }
    if binary:
        import subprocess as sp
        try:
            r = sp.run([binary, '-version'], capture_output=True, text=True, timeout=5)
            info['version'] = r.stdout.strip() or r.stderr.strip()
        except Exception:
            info['version'] = 'unknown'
    return jsonify(info)


@dns_service_bp.route('/nameserver/query', methods=['POST'])
@login_required
def query_test():
    """Resolve a DNS name using the running nameserver (or system resolver)."""
    import socket
    import subprocess as sp
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    qtype = data.get('type', 'A').upper()
    use_local = data.get('use_local', True)

    if not name:
        return jsonify({'ok': False, 'error': 'Name required'})

    mgr = _mgr()
    listen = mgr._config.get('listen_dns', '0.0.0.0:53')
    host, port = (listen.rsplit(':', 1) + ['53'])[:2]
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1'

    results = []

    # Try nslookup / dig
    try:
        if use_local and mgr.is_running():
            cmd = ['nslookup', '-type=' + qtype, name, host]
        else:
            cmd = ['nslookup', '-type=' + qtype, name]
        r = sp.run(cmd, capture_output=True, text=True, timeout=10)
        raw = r.stdout + r.stderr
        results.append({'method': 'nslookup', 'output': raw.strip(), 'cmd': ' '.join(cmd)})
    except FileNotFoundError:
        pass
    except Exception as e:
        results.append({'method': 'nslookup', 'output': str(e), 'cmd': ''})

    # Python socket fallback for A records
    if qtype == 'A':
        try:
            addrs = socket.getaddrinfo(name, None, socket.AF_INET)
            ips = list(set(a[4][0] for a in addrs))
            results.append({'method': 'socket', 'output': ', '.join(ips) if ips else 'No results', 'cmd': f'getaddrinfo({name})'})
        except socket.gaierror as e:
            results.append({'method': 'socket', 'output': str(e), 'cmd': f'getaddrinfo({name})'})

    return jsonify({'ok': True, 'name': name, 'type': qtype, 'results': results})


@dns_service_bp.route('/status')
@login_required
def status():
    return jsonify(_mgr().status())


@dns_service_bp.route('/start', methods=['POST'])
@login_required
def start():
    return jsonify(_mgr().start())


@dns_service_bp.route('/stop', methods=['POST'])
@login_required
def stop():
    return jsonify(_mgr().stop())


@dns_service_bp.route('/config', methods=['GET'])
@login_required
def get_config():
    return jsonify({'ok': True, 'config': _mgr().get_config()})


@dns_service_bp.route('/config', methods=['PUT'])
@login_required
def update_config():
    data = request.get_json(silent=True) or {}
    return jsonify(_mgr().update_config(data))


@dns_service_bp.route('/zones', methods=['GET'])
@login_required
def list_zones():
    try:
        zones = _mgr().list_zones()
        return jsonify({'ok': True, 'zones': zones})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones', methods=['POST'])
@login_required
def create_zone():
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain required'})
    try:
        return jsonify(_mgr().create_zone(domain))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>', methods=['GET'])
@login_required
def get_zone(domain):
    try:
        return jsonify(_mgr().get_zone(domain))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>', methods=['DELETE'])
@login_required
def delete_zone(domain):
    try:
        return jsonify(_mgr().delete_zone(domain))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/records', methods=['GET'])
@login_required
def list_records(domain):
    try:
        records = _mgr().list_records(domain)
        return jsonify({'ok': True, 'records': records})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/records', methods=['POST'])
@login_required
def add_record(domain):
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(_mgr().add_record(
            domain,
            rtype=data.get('type', 'A'),
            name=data.get('name', ''),
            value=data.get('value', ''),
            ttl=int(data.get('ttl', 300)),
            priority=int(data.get('priority', 0)),
        ))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/records/<record_id>', methods=['DELETE'])
@login_required
def delete_record(domain, record_id):
    try:
        return jsonify(_mgr().delete_record(domain, record_id))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/mail-setup', methods=['POST'])
@login_required
def mail_setup(domain):
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(_mgr().setup_mail_records(
            domain,
            mx_host=data.get('mx_host', ''),
            dkim_key=data.get('dkim_key', ''),
            spf_allow=data.get('spf_allow', ''),
        ))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/dnssec/enable', methods=['POST'])
@login_required
def dnssec_enable(domain):
    try:
        return jsonify(_mgr().enable_dnssec(domain))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zones/<domain>/dnssec/disable', methods=['POST'])
@login_required
def dnssec_disable(domain):
    try:
        return jsonify(_mgr().disable_dnssec(domain))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/metrics')
@login_required
def metrics():
    try:
        return jsonify({'ok': True, 'metrics': _mgr().get_metrics()})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


# ── New Go API proxies ────────────────────────────────────────────────

def _proxy_get(endpoint):
    try:
        return jsonify(_mgr()._api_get(endpoint))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


def _proxy_post(endpoint, data=None):
    try:
        return jsonify(_mgr()._api_post(endpoint, data))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


def _proxy_delete(endpoint):
    try:
        return jsonify(_mgr()._api_delete(endpoint))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/querylog')
@login_required
def querylog():
    limit = request.args.get('limit', '200')
    return _proxy_get(f'/api/querylog?limit={limit}')


@dns_service_bp.route('/querylog', methods=['DELETE'])
@login_required
def clear_querylog():
    return _proxy_delete('/api/querylog')


@dns_service_bp.route('/cache')
@login_required
def cache_list():
    return _proxy_get('/api/cache')


@dns_service_bp.route('/cache', methods=['DELETE'])
@login_required
def cache_flush():
    key = request.args.get('key', '')
    if key:
        return _proxy_delete(f'/api/cache?key={key}')
    return _proxy_delete('/api/cache')


@dns_service_bp.route('/blocklist')
@login_required
def blocklist_list():
    return _proxy_get('/api/blocklist')


@dns_service_bp.route('/blocklist', methods=['POST'])
@login_required
def blocklist_add():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/blocklist', data)


@dns_service_bp.route('/blocklist', methods=['DELETE'])
@login_required
def blocklist_remove():
    data = request.get_json(silent=True) or {}
    try:
        return jsonify(_mgr()._api_urllib('/api/blocklist', 'DELETE', data)
                       if not __import__('importlib').util.find_spec('requests')
                       else _mgr()._api_delete_with_body('/api/blocklist', data))
    except Exception:
        # Fallback: use POST with _method override or direct urllib
        import json as _json
        import urllib.request
        mgr = _mgr()
        url = f'{mgr.api_base}/api/blocklist'
        body = _json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method='DELETE',
                                     headers={'Authorization': f'Bearer {mgr.api_token}',
                                              'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return jsonify(_json.loads(resp.read()))
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/stats/top-domains')
@login_required
def top_domains():
    limit = request.args.get('limit', '50')
    return _proxy_get(f'/api/stats/top-domains?limit={limit}')


@dns_service_bp.route('/stats/query-types')
@login_required
def query_types():
    return _proxy_get('/api/stats/query-types')


@dns_service_bp.route('/stats/clients')
@login_required
def client_stats():
    return _proxy_get('/api/stats/clients')


@dns_service_bp.route('/resolver/ns-cache')
@login_required
def ns_cache():
    return _proxy_get('/api/resolver/ns-cache')


@dns_service_bp.route('/resolver/ns-cache', methods=['DELETE'])
@login_required
def flush_ns_cache():
    return _proxy_delete('/api/resolver/ns-cache')


@dns_service_bp.route('/rootcheck')
@login_required
def rootcheck():
    return _proxy_get('/api/rootcheck')


@dns_service_bp.route('/benchmark', methods=['POST'])
@login_required
def benchmark():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/benchmark', data)


@dns_service_bp.route('/forwarding')
@login_required
def forwarding_list():
    return _proxy_get('/api/forwarding')


@dns_service_bp.route('/forwarding', methods=['POST'])
@login_required
def forwarding_add():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/forwarding', data)


@dns_service_bp.route('/forwarding', methods=['DELETE'])
@login_required
def forwarding_remove():
    data = request.get_json(silent=True) or {}
    try:
        import json as _json, urllib.request
        mgr = _mgr()
        url = f'{mgr.api_base}/api/forwarding'
        body = _json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, method='DELETE',
                                     headers={'Authorization': f'Bearer {mgr.api_token}',
                                              'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return jsonify(_json.loads(resp.read()))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/zone-export/<domain>')
@login_required
def zone_export(domain):
    return _proxy_get(f'/api/zone-export/{domain}')


@dns_service_bp.route('/zone-import/<domain>', methods=['POST'])
@login_required
def zone_import(domain):
    data = request.get_json(silent=True) or {}
    return _proxy_post(f'/api/zone-import/{domain}', data)


@dns_service_bp.route('/zone-clone', methods=['POST'])
@login_required
def zone_clone():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/zone-clone', data)


@dns_service_bp.route('/zone-bulk-records/<domain>', methods=['POST'])
@login_required
def bulk_records(domain):
    data = request.get_json(silent=True) or {}
    return _proxy_post(f'/api/zone-bulk-records/{domain}', data)


# ── Hosts file management ────────────────────────────────────────────

@dns_service_bp.route('/hosts')
@login_required
def hosts_list():
    return _proxy_get('/api/hosts')


@dns_service_bp.route('/hosts', methods=['POST'])
@login_required
def hosts_add():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/hosts', data)


@dns_service_bp.route('/hosts', methods=['DELETE'])
@login_required
def hosts_remove():
    data = request.get_json(silent=True) or {}
    try:
        import json as _json, urllib.request
        mgr = _mgr()
        url = f'{mgr.api_base}/api/hosts'
        body = _json.dumps(data).encode()
        req_obj = urllib.request.Request(url, data=body, method='DELETE',
                                         headers={'Authorization': f'Bearer {mgr.api_token}',
                                                  'Content-Type': 'application/json'})
        with urllib.request.urlopen(req_obj, timeout=5) as resp:
            return jsonify(_json.loads(resp.read()))
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)})


@dns_service_bp.route('/hosts/import', methods=['POST'])
@login_required
def hosts_import():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/hosts/import', data)


@dns_service_bp.route('/hosts/export')
@login_required
def hosts_export():
    return _proxy_get('/api/hosts/export')


# ── Encryption (DoT / DoH) ──────────────────────────────────────────

@dns_service_bp.route('/encryption')
@login_required
def encryption_status():
    return _proxy_get('/api/encryption')


@dns_service_bp.route('/encryption', methods=['PUT', 'POST'])
@login_required
def encryption_update():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/encryption', data)


@dns_service_bp.route('/encryption/test', methods=['POST'])
@login_required
def encryption_test():
    data = request.get_json(silent=True) or {}
    return _proxy_post('/api/encryption/test', data)


# ── EZ Intranet Domain ──────────────────────────────────────────────

@dns_service_bp.route('/ez-intranet', methods=['POST'])
@login_required
def ez_intranet():
    """One-click intranet domain setup. Creates zone + host records + reverse zone."""
    import socket
    data = request.get_json(silent=True) or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'ok': False, 'error': 'Domain name required'})

    mgr = _mgr()
    results = {'ok': True, 'domain': domain, 'steps': []}

    # Detect local network info
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 53))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = '127.0.0.1'

    hostname = socket.gethostname()

    # Step 1: Create the zone
    try:
        r = mgr.create_zone(domain)
        results['steps'].append({'step': 'Create zone', 'ok': r.get('ok', False)})
    except Exception as e:
        results['steps'].append({'step': 'Create zone', 'ok': False, 'error': str(e)})

    # Step 2: Add server record (ns.domain -> local IP)
    records = [
        {'type': 'A', 'name': f'ns.{domain}.', 'value': local_ip, 'ttl': 3600},
        {'type': 'A', 'name': f'{domain}.', 'value': local_ip, 'ttl': 3600},
        {'type': 'A', 'name': f'{hostname}.{domain}.', 'value': local_ip, 'ttl': 3600},
    ]

    # Add custom hosts from request
    for host in data.get('hosts', []):
        ip = host.get('ip', '').strip()
        name = host.get('name', '').strip()
        if ip and name:
            if not name.endswith('.'):
                name = f'{name}.{domain}.'
            records.append({'type': 'A', 'name': name, 'value': ip, 'ttl': 3600})

    for rec in records:
        try:
            r = mgr.add_record(domain, rtype=rec['type'], name=rec['name'],
                               value=rec['value'], ttl=rec['ttl'])
            results['steps'].append({'step': f'Add {rec["name"]} -> {rec["value"]}', 'ok': r.get('ok', False)})
        except Exception as e:
            results['steps'].append({'step': f'Add {rec["name"]}', 'ok': False, 'error': str(e)})

    # Step 3: Add hosts file entries too for immediate local resolution
    try:
        import json as _json, urllib.request
        hosts_entries = [
            {'ip': local_ip, 'hostname': domain, 'aliases': [hostname + '.' + domain]},
        ]
        for host in data.get('hosts', []):
            ip = host.get('ip', '').strip()
            name = host.get('name', '').strip()
            if ip and name:
                hosts_entries.append({'ip': ip, 'hostname': name + '.' + domain if '.' not in name else name})

        for entry in hosts_entries:
            body = _json.dumps(entry).encode()
            url = f'{mgr.api_base}/api/hosts'
            req_obj = urllib.request.Request(url, data=body, method='POST',
                                             headers={'Authorization': f'Bearer {mgr.api_token}',
                                                      'Content-Type': 'application/json'})
            urllib.request.urlopen(req_obj, timeout=5)
        results['steps'].append({'step': 'Add hosts entries', 'ok': True})
    except Exception as e:
        results['steps'].append({'step': 'Add hosts entries', 'ok': False, 'error': str(e)})

    # Step 4: Create reverse zone if requested
    if data.get('reverse_zone', True):
        parts = local_ip.split('.')
        if len(parts) == 4:
            rev_zone = f'{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa'
            try:
                mgr.create_zone(rev_zone)
                # Add PTR for server
                mgr.add_record(rev_zone, rtype='PTR',
                               name=f'{parts[3]}.{rev_zone}.',
                               value=f'{hostname}.{domain}.', ttl=3600)
                results['steps'].append({'step': f'Create reverse zone {rev_zone}', 'ok': True})
            except Exception as e:
                results['steps'].append({'step': 'Create reverse zone', 'ok': False, 'error': str(e)})

    results['local_ip'] = local_ip
    results['hostname'] = hostname
    return jsonify(results)
