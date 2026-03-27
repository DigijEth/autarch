"""OSINT category route - advanced search engine with SSE, dossier management, export."""

import json
import os
import re
import time
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from random import randint
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Blueprint, render_template, request, Response, current_app, jsonify, stream_with_context
from web.auth import login_required

osint_bp = Blueprint('osint', __name__, url_prefix='/osint')

# Dossier storage directory
from core.paths import get_data_dir
DOSSIER_DIR = get_data_dir() / 'dossiers'
DOSSIER_DIR.mkdir(parents=True, exist_ok=True)

# User agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
]

# WAF / challenge page patterns
WAF_PATTERNS = re.compile(
    r'cloudflare|captcha|challenge|please wait|checking your browser|'
    r'access denied|blocked|rate limit|too many requests',
    re.IGNORECASE
)

# Not-found generic strings
NOT_FOUND_STRINGS = [
    'page not found', 'user not found', 'profile not found', 'account not found',
    'no user', 'does not exist', 'doesn\'t exist', '404', 'not exist',
    'could not be found', 'no results', 'this page is not available',
]

# Found generic strings (with {username} placeholder)
FOUND_STRINGS = [
    '{username}', '@{username}',
]


def _check_site(site, username, timeout=8, user_agent=None, proxy=None):
    """Check if username exists on a site using detection patterns.

    Returns result dict or None if not found.
    """
    try:
        time.sleep(randint(5, 50) / 1000)

        url = site['url'].replace('{}', username).replace('{username}', username).replace('{account}', username)

        headers = {
            'User-Agent': user_agent or USER_AGENTS[randint(0, len(USER_AGENTS) - 1)],
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }

        req = urllib.request.Request(url, headers=headers)

        # Proxy support
        opener = None
        if proxy:
            proxy_handler = urllib.request.ProxyHandler({'http': proxy, 'https': proxy})
            opener = urllib.request.build_opener(proxy_handler)

        error_type = site.get('error_type', 'status_code')
        error_code = site.get('error_code')
        error_string = (site.get('error_string') or '').strip() or None
        match_string = (site.get('match_string') or '').strip() or None

        try:
            if opener:
                response = opener.open(req, timeout=timeout)
            else:
                response = urllib.request.urlopen(req, timeout=timeout)

            status_code = response.getcode()
            final_url = response.geturl()
            raw_content = response.read()
            content = raw_content.decode('utf-8', errors='ignore')
            content_lower = content.lower()
            content_len = len(content)

            # Extract title
            title = ''
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).strip()

            response.close()

            # WAF/Challenge detection
            cf_patterns = ['just a moment', 'checking your browser', 'cf-browser-verification', 'cf_chl_opt']
            if any(p in content_lower for p in cf_patterns):
                return {
                    'name': site['name'], 'url': url, 'category': site.get('category', ''),
                    'status': 'filtered', 'rate': 0, 'title': 'filtered',
                }
            if WAF_PATTERNS.search(content) and content_len < 5000:
                return {
                    'name': site['name'], 'url': url, 'category': site.get('category', ''),
                    'status': 'filtered', 'rate': 0, 'title': 'filtered',
                }

            # Detection
            username_lower = username.lower()
            not_found_texts = []
            check_texts = []

            if error_string:
                not_found_texts.append(error_string.lower())
            if match_string:
                check_texts.append(
                    match_string.replace('{username}', username).replace('{account}', username).lower()
                )

            # Status code detection
            if error_type == 'status_code':
                if error_code and status_code == error_code:
                    return None
                if status_code >= 400:
                    return None

            # Redirect detection
            if error_type in ('response_url', 'redirection'):
                if final_url != url and username_lower not in final_url.lower():
                    parsed = urlparse(final_url)
                    if parsed.netloc.lower() != urlparse(url).netloc.lower():
                        return None
                    fp_paths = ['login', 'signup', 'register', 'error', '404', 'home']
                    if any(fp in final_url.lower() for fp in fp_paths):
                        return None

            # Pattern matching
            not_found_matched = any(nf in content_lower for nf in not_found_texts if nf)
            check_matched = any(ct in content_lower for ct in check_texts if ct)

            # Fallback generic patterns
            if not not_found_texts:
                not_found_matched = any(nf in content_lower for nf in NOT_FOUND_STRINGS)

            if not_found_matched:
                return None

            username_in_content = username_lower in content_lower
            username_in_title = username_lower in title.lower() if title else False

            # Calculate confidence
            if check_matched and (username_in_content or username_in_title):
                status = 'good'
                rate = min(100, 70 + (10 if username_in_title else 0) + (10 if username_in_content else 0))
            elif check_matched:
                status = 'maybe'
                rate = 55
            elif username_in_content and status_code == 200:
                status = 'maybe'
                rate = 45
            elif status_code == 200 and content_len > 1000:
                status = 'maybe'
                rate = 30
            else:
                return None

            if content_len < 500 and not check_matched and not username_in_content:
                return None
            if rate < 30:
                return None

            return {
                'name': site['name'],
                'url': url,
                'category': site.get('category', ''),
                'status': status,
                'rate': rate,
                'title': title[:100] if title else '',
                'http_code': status_code,
                'method': error_type or 'status',
            }

        except urllib.error.HTTPError as e:
            if error_code and e.code == error_code:
                return None
            if e.code == 404:
                return None
            if e.code in [403, 401]:
                return {
                    'name': site['name'], 'url': url, 'category': site.get('category', ''),
                    'status': 'restricted', 'rate': 0,
                }
            return None
        except (urllib.error.URLError, TimeoutError, OSError):
            return None
        except Exception:
            return None

    except Exception:
        return None


@osint_bp.route('/')
@login_required
def index():
    from core.menu import MainMenu
    menu = MainMenu()
    menu.load_modules()
    modules = {k: v for k, v in menu.modules.items() if v.category == 'osint'}

    categories = []
    db_stats = {}
    try:
        from core.sites_db import get_sites_db
        db = get_sites_db()
        categories = db.get_categories()
        db_stats = db.get_stats()
    except Exception:
        pass

    config = current_app.autarch_config
    osint_settings = config.get_osint_settings()

    return render_template('osint.html',
        modules=modules,
        categories=categories,
        osint_settings=osint_settings,
        db_stats=db_stats,
    )


@osint_bp.route('/categories')
@login_required
def get_categories():
    """Get site categories with counts."""
    try:
        from core.sites_db import get_sites_db
        db = get_sites_db()
        cats = db.get_categories()
        return jsonify({'categories': [{'name': c[0], 'count': c[1]} for c in cats]})
    except Exception as e:
        return jsonify({'error': str(e), 'categories': []})


@osint_bp.route('/stats')
@login_required
def db_stats():
    """Get sites database statistics."""
    try:
        from core.sites_db import get_sites_db
        db = get_sites_db()
        stats = db.get_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)})


@osint_bp.route('/search/stream')
@login_required
def search_stream():
    """SSE endpoint for real-time OSINT search with proper detection."""
    search_type = request.args.get('type', 'username')
    query = request.args.get('q', '').strip()
    max_sites = int(request.args.get('max', 500))
    include_nsfw = request.args.get('nsfw', 'false') == 'true'
    categories_str = request.args.get('categories', '')
    timeout = int(request.args.get('timeout', 8))
    threads = int(request.args.get('threads', 8))
    user_agent = request.args.get('ua', '') or None
    proxy = request.args.get('proxy', '') or None

    # Clamp values
    timeout = max(3, min(30, timeout))
    threads = max(1, min(20, threads))
    if max_sites == 0:
        max_sites = 10000  # "Full" mode

    if not query:
        return Response('data: {"error": "No query provided"}\n\n',
                       content_type='text/event-stream')

    def generate():
        try:
            from core.sites_db import get_sites_db
            db = get_sites_db()

            cat_filter = [c.strip() for c in categories_str.split(',') if c.strip()] if categories_str else None

            sites = db.get_sites_for_scan(
                categories=cat_filter,
                include_nsfw=include_nsfw,
                max_sites=max_sites,
            )

            total = len(sites)
            yield f'data: {json.dumps({"type": "start", "total": total})}\n\n'

            checked = 0
            found = 0
            maybe = 0
            filtered = 0
            results_list = []

            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_site = {}
                for site in sites:
                    future = executor.submit(
                        _check_site, site, query,
                        timeout=timeout,
                        user_agent=user_agent,
                        proxy=proxy,
                    )
                    future_to_site[future] = site

                for future in as_completed(future_to_site):
                    checked += 1
                    site = future_to_site[future]
                    result_data = {
                        'type': 'result',
                        'site': site['name'],
                        'category': site.get('category', ''),
                        'checked': checked,
                        'total': total,
                        'status': 'not_found',
                    }

                    try:
                        result = future.result()
                        if result:
                            result_data['status'] = result.get('status', 'not_found')
                            result_data['url'] = result.get('url', '')
                            result_data['rate'] = result.get('rate', 0)
                            result_data['title'] = result.get('title', '')
                            result_data['http_code'] = result.get('http_code', 0)
                            result_data['method'] = result.get('method', '')

                            if result['status'] == 'good':
                                found += 1
                                results_list.append(result)
                            elif result['status'] == 'maybe':
                                maybe += 1
                                results_list.append(result)
                            elif result['status'] == 'filtered':
                                filtered += 1
                    except Exception:
                        result_data['status'] = 'error'

                    yield f'data: {json.dumps(result_data)}\n\n'

            yield f'data: {json.dumps({"type": "done", "total": total, "checked": checked, "found": found, "maybe": maybe, "filtered": filtered})}\n\n'

        except Exception as e:
            yield f'data: {json.dumps({"type": "error", "message": str(e)})}\n\n'

    return Response(stream_with_context(generate()), content_type='text/event-stream')


# ==================== DOSSIER MANAGEMENT ====================

def _load_dossier(dossier_id):
    """Load a dossier from disk."""
    path = DOSSIER_DIR / f'{dossier_id}.json'
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _save_dossier(dossier):
    """Save a dossier to disk."""
    path = DOSSIER_DIR / f'{dossier["id"]}.json'
    with open(path, 'w') as f:
        json.dump(dossier, f, indent=2)


def _list_dossiers():
    """List all dossiers."""
    dossiers = []
    for f in sorted(DOSSIER_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(f) as fh:
                d = json.load(fh)
                dossiers.append({
                    'id': d['id'],
                    'name': d['name'],
                    'target': d.get('target', ''),
                    'created': d.get('created', ''),
                    'updated': d.get('updated', ''),
                    'result_count': len(d.get('results', [])),
                    'notes': d.get('notes', '')[:100],
                })
        except Exception:
            continue
    return dossiers


@osint_bp.route('/dossiers')
@login_required
def list_dossiers():
    """List all dossiers."""
    return jsonify({'dossiers': _list_dossiers()})


@osint_bp.route('/dossier', methods=['POST'])
@login_required
def create_dossier():
    """Create a new dossier."""
    data = request.get_json(silent=True) or {}
    name = data.get('name', '').strip()
    target = data.get('target', '').strip()

    if not name:
        return jsonify({'error': 'Dossier name required'})

    dossier_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    dossier = {
        'id': dossier_id,
        'name': name,
        'target': target,
        'created': datetime.now().isoformat(),
        'updated': datetime.now().isoformat(),
        'notes': '',
        'results': [],
    }
    _save_dossier(dossier)
    return jsonify({'success': True, 'dossier': dossier})


@osint_bp.route('/dossier/<dossier_id>')
@login_required
def get_dossier(dossier_id):
    """Get dossier details."""
    dossier = _load_dossier(dossier_id)
    if not dossier:
        return jsonify({'error': 'Dossier not found'})
    return jsonify({'dossier': dossier})


@osint_bp.route('/dossier/<dossier_id>', methods=['PUT'])
@login_required
def update_dossier(dossier_id):
    """Update dossier (notes, name)."""
    dossier = _load_dossier(dossier_id)
    if not dossier:
        return jsonify({'error': 'Dossier not found'})

    data = request.get_json(silent=True) or {}
    if 'name' in data:
        dossier['name'] = data['name']
    if 'notes' in data:
        dossier['notes'] = data['notes']
    dossier['updated'] = datetime.now().isoformat()
    _save_dossier(dossier)
    return jsonify({'success': True})


@osint_bp.route('/dossier/<dossier_id>', methods=['DELETE'])
@login_required
def delete_dossier(dossier_id):
    """Delete a dossier."""
    path = DOSSIER_DIR / f'{dossier_id}.json'
    if path.exists():
        path.unlink()
        return jsonify({'success': True})
    return jsonify({'error': 'Dossier not found'})


@osint_bp.route('/dossier/<dossier_id>/add', methods=['POST'])
@login_required
def add_to_dossier(dossier_id):
    """Add search results to a dossier."""
    dossier = _load_dossier(dossier_id)
    if not dossier:
        return jsonify({'error': 'Dossier not found'})

    data = request.get_json(silent=True) or {}
    results = data.get('results', [])

    if not results:
        return jsonify({'error': 'No results to add'})

    existing_urls = {r.get('url') for r in dossier['results']}
    added = 0
    for r in results:
        if r.get('url') and r['url'] not in existing_urls:
            dossier['results'].append({
                'name': r.get('name', ''),
                'url': r['url'],
                'category': r.get('category', ''),
                'status': r.get('status', ''),
                'rate': r.get('rate', 0),
                'added': datetime.now().isoformat(),
            })
            existing_urls.add(r['url'])
            added += 1

    dossier['updated'] = datetime.now().isoformat()
    _save_dossier(dossier)
    return jsonify({'success': True, 'added': added, 'total': len(dossier['results'])})


# ==================== EXPORT ====================

@osint_bp.route('/export', methods=['POST'])
@login_required
def export_results():
    """Export search results in various formats."""
    data = request.get_json(silent=True) or {}
    results = data.get('results', [])
    fmt = data.get('format', 'json')
    query = data.get('query', 'unknown')

    if not results:
        return jsonify({'error': 'No results to export'})

    export_dir = get_data_dir() / 'exports'
    export_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if fmt == 'csv':
        filename = f'osint_{query}_{timestamp}.csv'
        filepath = export_dir / filename
        lines = ['Site,URL,Category,Status,Confidence']
        for r in results:
            line = f'{r.get("name","")},{r.get("url","")},{r.get("category","")},{r.get("status","")},{r.get("rate",0)}'
            lines.append(line)
        filepath.write_text('\n'.join(lines))
    else:
        filename = f'osint_{query}_{timestamp}.json'
        filepath = export_dir / filename
        export_data = {
            'query': query,
            'exported': datetime.now().isoformat(),
            'total_results': len(results),
            'results': results,
        }
        filepath.write_text(json.dumps(export_data, indent=2))

    return jsonify({'success': True, 'filename': filename, 'path': str(filepath)})
