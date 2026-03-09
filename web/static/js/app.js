/* AUTARCH Web UI - Vanilla JS */

// Auto-dismiss flash messages after 5s
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.flash').forEach(function(el) {
        setTimeout(function() { el.style.opacity = '0'; setTimeout(function() { el.remove(); }, 300); }, 5000);
    });
});

// ==================== HELPERS ====================

function escapeHtml(str) {
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function fetchJSON(url, options) {
    options = options || {};
    options.headers = options.headers || {};
    options.headers['Accept'] = 'application/json';
    return fetch(url, options).then(function(resp) {
        if (resp.status === 401 || resp.status === 302) {
            window.location.href = '/auth/login';
            throw new Error('Unauthorized');
        }
        return resp.json();
    });
}

function postJSON(url, body) {
    return fetchJSON(url, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(body)
    });
}

function renderOutput(elementId, text) {
    var el = document.getElementById(elementId);
    if (el) el.textContent = text;
}

/* ── Refresh Modules ─────────────────────────────────────────── */
function reloadModules() {
    var btn = document.getElementById('btn-reload-modules');
    if (!btn) return;
    var origText = btn.innerHTML;
    btn.innerHTML = '&#x21BB; Reloading...';
    btn.disabled = true;
    btn.style.color = 'var(--accent)';

    postJSON('/api/modules/reload', {}).then(function(data) {
        var total = data.total || 0;
        btn.innerHTML = '&#x2713; ' + total + ' modules loaded';
        btn.style.color = 'var(--success)';

        // If on a category page, reload to reflect changes
        var path = window.location.pathname;
        var isCategoryPage = /^\/(defense|offense|counter|analyze|osint|simulate)\/?$/.test(path)
                          || path === '/';
        if (isCategoryPage) {
            setTimeout(function() { window.location.reload(); }, 800);
        } else {
            setTimeout(function() {
                btn.innerHTML = origText;
                btn.style.color = 'var(--text-secondary)';
                btn.disabled = false;
            }, 2000);
        }
    }).catch(function() {
        btn.innerHTML = '&#x2717; Reload failed';
        btn.style.color = 'var(--danger)';
        setTimeout(function() {
            btn.innerHTML = origText;
            btn.style.color = 'var(--text-secondary)';
            btn.disabled = false;
        }, 2000);
    });
}

function showTab(tabGroup, tabId) {
    document.querySelectorAll('[data-tab-group="' + tabGroup + '"].tab').forEach(function(t) {
        t.classList.toggle('active', t.dataset.tab === tabId);
    });
    document.querySelectorAll('[data-tab-group="' + tabGroup + '"].tab-content').forEach(function(c) {
        c.classList.toggle('active', c.dataset.tab === tabId);
    });
}

function setLoading(btn, loading) {
    if (loading) {
        btn.dataset.origText = btn.textContent;
        btn.textContent = 'Loading...';
        btn.disabled = true;
    } else {
        btn.textContent = btn.dataset.origText || btn.textContent;
        btn.disabled = false;
    }
}

// ==================== OSINT ====================

var osintEventSource = null;
var osintResults = [];
var currentDossierId = null;

function getSelectedCategories() {
    var boxes = document.querySelectorAll('.cat-checkbox');
    if (boxes.length === 0) return '';
    var allChecked = document.getElementById('cat-all');
    if (allChecked && allChecked.checked) return '';
    var selected = [];
    boxes.forEach(function(cb) { if (cb.checked) selected.push(cb.value); });
    return selected.join(',');
}

function toggleAllCategories(checked) {
    document.querySelectorAll('.cat-checkbox').forEach(function(cb) { cb.checked = checked; });
}

function toggleAdvanced() {
    var body = document.getElementById('advanced-body');
    var arrow = document.getElementById('adv-arrow');
    body.classList.toggle('visible');
    arrow.classList.toggle('open');
}

function stopOsintSearch() {
    if (osintEventSource) {
        osintEventSource.close();
        osintEventSource = null;
    }
    var searchBtn = document.getElementById('search-btn');
    var stopBtn = document.getElementById('stop-btn');
    searchBtn.disabled = false;
    searchBtn.textContent = 'Search';
    stopBtn.style.display = 'none';
    document.getElementById('progress-text').textContent = 'Search stopped.';
}

function startOsintSearch() {
    var query = document.getElementById('osint-query').value.trim();
    if (!query) return;

    var type = document.getElementById('osint-type').value;
    var maxSites = document.getElementById('osint-max').value;
    var nsfw = document.getElementById('osint-nsfw') && document.getElementById('osint-nsfw').checked;
    var categories = getSelectedCategories();

    // Advanced options
    var threads = document.getElementById('osint-threads') ? document.getElementById('osint-threads').value : '8';
    var timeout = document.getElementById('osint-timeout') ? document.getElementById('osint-timeout').value : '8';
    var ua = document.getElementById('osint-ua') ? document.getElementById('osint-ua').value : '';
    var proxy = document.getElementById('osint-proxy') ? document.getElementById('osint-proxy').value.trim() : '';

    var resultsDiv = document.getElementById('osint-results');
    var progressFill = document.getElementById('progress-fill');
    var progressText = document.getElementById('progress-text');

    resultsDiv.innerHTML = '';
    progressFill.style.width = '0%';
    progressText.textContent = 'Starting search...';
    osintResults = [];

    // Show/hide UI elements
    document.getElementById('results-section').style.display = 'block';
    document.getElementById('osint-summary').style.display = 'flex';
    document.getElementById('result-actions').style.display = 'none';
    document.getElementById('save-dossier-panel').style.display = 'none';
    document.getElementById('sum-checked').textContent = '0';
    document.getElementById('sum-found').textContent = '0';
    document.getElementById('sum-maybe').textContent = '0';
    document.getElementById('sum-filtered').textContent = '0';

    var searchBtn = document.getElementById('search-btn');
    var stopBtn = document.getElementById('stop-btn');
    searchBtn.disabled = true;
    searchBtn.textContent = 'Searching...';
    stopBtn.style.display = 'inline-block';

    var url = '/osint/search/stream?type=' + type + '&q=' + encodeURIComponent(query)
            + '&max=' + maxSites + '&nsfw=' + (nsfw ? 'true' : 'false')
            + '&categories=' + encodeURIComponent(categories)
            + '&threads=' + threads + '&timeout=' + timeout;
    if (ua) url += '&ua=' + encodeURIComponent(ua);
    if (proxy) url += '&proxy=' + encodeURIComponent(proxy);

    var source = new EventSource(url);
    osintEventSource = source;
    var foundCount = 0;
    var maybeCount = 0;
    var filteredCount = 0;

    source.onmessage = function(e) {
        var data = JSON.parse(e.data);

        if (data.type === 'start') {
            progressText.textContent = 'Checking ' + data.total + ' sites...';
        } else if (data.type === 'result') {
            var pct = ((data.checked / data.total) * 100).toFixed(1);
            progressFill.style.width = pct + '%';
            progressText.textContent = data.checked + ' / ' + data.total + ' checked';
            document.getElementById('sum-checked').textContent = data.checked;

            if (data.status === 'good') {
                foundCount++;
                document.getElementById('sum-found').textContent = foundCount;
                osintResults.push(data);
                var card = document.createElement('div');
                card.className = 'result-card found';
                card.dataset.status = 'good';
                card.onclick = function() { toggleResultDetail(card); };
                var conf = data.rate || 0;
                var confClass = conf >= 70 ? 'high' : conf >= 50 ? 'medium' : 'low';
                card.innerHTML = '<div style="flex:1"><strong>' + escapeHtml(data.site) + '</strong> '
                    + '<span class="badge badge-pass" style="margin-left:6px">' + conf + '%</span>'
                    + '<span class="confidence-bar"><span class="fill ' + confClass + '" style="width:' + conf + '%"></span></span>'
                    + '<span style="color:var(--text-muted);margin-left:8px;font-size:0.78rem">' + escapeHtml(data.category || '') + '</span>'
                    + '<div class="result-detail">'
                    + '<div>URL: <a href="' + escapeHtml(data.url || '') + '" target="_blank">' + escapeHtml(data.url || '') + '</a></div>'
                    + (data.title ? '<div>Title: ' + escapeHtml(data.title) + '</div>' : '')
                    + '<div>Method: ' + escapeHtml(data.method || '') + ' | HTTP ' + (data.http_code || '') + '</div>'
                    + '</div></div>'
                    + '<a href="' + escapeHtml(data.url || '') + '" target="_blank" class="btn btn-small btn-success" onclick="event.stopPropagation()">Open</a>';
                resultsDiv.prepend(card);
            } else if (data.status === 'maybe') {
                maybeCount++;
                document.getElementById('sum-maybe').textContent = maybeCount;
                osintResults.push(data);
                var card = document.createElement('div');
                card.className = 'result-card maybe';
                card.dataset.status = 'maybe';
                card.onclick = function() { toggleResultDetail(card); };
                var conf = data.rate || 0;
                var confClass = conf >= 50 ? 'medium' : 'low';
                card.innerHTML = '<div style="flex:1"><strong>' + escapeHtml(data.site) + '</strong> '
                    + '<span class="badge badge-medium" style="margin-left:6px">' + conf + '%</span>'
                    + '<span class="confidence-bar"><span class="fill ' + confClass + '" style="width:' + conf + '%"></span></span>'
                    + '<span style="color:var(--text-muted);margin-left:8px;font-size:0.78rem">' + escapeHtml(data.category || '') + '</span>'
                    + '<div class="result-detail">'
                    + '<div>URL: <a href="' + escapeHtml(data.url || '') + '" target="_blank">' + escapeHtml(data.url || '') + '</a></div>'
                    + (data.title ? '<div>Title: ' + escapeHtml(data.title) + '</div>' : '')
                    + '<div>Method: ' + escapeHtml(data.method || '') + ' | HTTP ' + (data.http_code || '') + '</div>'
                    + '</div></div>'
                    + '<a href="' + escapeHtml(data.url || '') + '" target="_blank" class="btn btn-small" onclick="event.stopPropagation()">Open</a>';
                resultsDiv.appendChild(card);
            } else if (data.status === 'filtered') {
                filteredCount++;
                document.getElementById('sum-filtered').textContent = filteredCount;
                var card = document.createElement('div');
                card.className = 'result-card filtered';
                card.dataset.status = 'filtered';
                card.innerHTML = '<span>' + escapeHtml(data.site) + '</span><span style="color:var(--text-muted);font-size:0.78rem">WAF/Filtered</span>';
                resultsDiv.appendChild(card);
            }
        } else if (data.type === 'done') {
            progressFill.style.width = '100%';
            progressText.textContent = 'Done: ' + data.checked + ' checked, ' + data.found + ' found, ' + (data.maybe || 0) + ' possible';
            source.close();
            osintEventSource = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            stopBtn.style.display = 'none';
            if (osintResults.length > 0) {
                document.getElementById('result-actions').style.display = 'flex';
            }
        } else if (data.type === 'error' || data.error) {
            progressText.textContent = 'Error: ' + (data.message || data.error);
            source.close();
            osintEventSource = null;
            searchBtn.disabled = false;
            searchBtn.textContent = 'Search';
            stopBtn.style.display = 'none';
        }
    };

    source.onerror = function() {
        source.close();
        osintEventSource = null;
        searchBtn.disabled = false;
        searchBtn.textContent = 'Search';
        stopBtn.style.display = 'none';
        progressText.textContent = 'Connection lost';
    };
}

function toggleResultDetail(card) {
    var detail = card.querySelector('.result-detail');
    if (detail) detail.classList.toggle('visible');
}

function filterResults(filter) {
    document.querySelectorAll('.result-filters .filter-btn').forEach(function(b) {
        b.classList.toggle('active', b.dataset.filter === filter);
    });
    document.querySelectorAll('#osint-results .result-card').forEach(function(card) {
        if (filter === 'all') {
            card.style.display = '';
        } else {
            card.style.display = card.dataset.status === filter ? '' : 'none';
        }
    });
}

function openAllFound() {
    osintResults.forEach(function(r) {
        if (r.status === 'good' && r.url) {
            window.open(r.url, '_blank');
        }
    });
}

function exportResults(fmt) {
    var query = document.getElementById('osint-query').value.trim();
    postJSON('/osint/export', {
        results: osintResults,
        format: fmt,
        query: query
    }).then(function(data) {
        if (data.error) { alert('Export error: ' + data.error); return; }
        alert('Exported to: ' + data.path);
    });
}

function showSaveToDossier() {
    var panel = document.getElementById('save-dossier-panel');
    panel.style.display = 'block';
    document.getElementById('dossier-save-status').textContent = '';
    // Load existing dossiers for selection
    fetchJSON('/osint/dossiers').then(function(data) {
        var list = document.getElementById('dossier-select-list');
        var dossiers = data.dossiers || [];
        if (dossiers.length === 0) {
            list.innerHTML = '<div style="font-size:0.82rem;color:var(--text-muted)">No existing dossiers. Create one below.</div>';
            return;
        }
        var html = '';
        dossiers.forEach(function(d) {
            html += '<button class="btn btn-small" style="margin:3px" onclick="saveToDossier(\'' + escapeHtml(d.id) + '\')">'
                + escapeHtml(d.name) + ' (' + d.result_count + ')</button>';
        });
        list.innerHTML = html;
    });
}

function saveToDossier(dossierId) {
    postJSON('/osint/dossier/' + dossierId + '/add', {results: osintResults}).then(function(data) {
        var status = document.getElementById('dossier-save-status');
        if (data.error) { status.textContent = 'Error: ' + data.error; return; }
        status.textContent = 'Added ' + data.added + ' results (total: ' + data.total + ')';
        status.style.color = 'var(--success)';
    });
}

function createAndSaveDossier() {
    var name = document.getElementById('new-dossier-name').value.trim();
    if (!name) return;
    var query = document.getElementById('osint-query').value.trim();
    postJSON('/osint/dossier', {name: name, target: query}).then(function(data) {
        if (data.error) { document.getElementById('dossier-save-status').textContent = 'Error: ' + data.error; return; }
        document.getElementById('new-dossier-name').value = '';
        saveToDossier(data.dossier.id);
    });
}

// ==================== DOSSIER MANAGEMENT ====================

function loadDossiers() {
    fetchJSON('/osint/dossiers').then(function(data) {
        var container = document.getElementById('dossier-list');
        var dossiers = data.dossiers || [];
        if (dossiers.length === 0) {
            container.innerHTML = '<div class="empty-state">No dossiers yet. Run a search and save results.</div>';
            return;
        }
        var html = '';
        dossiers.forEach(function(d) {
            html += '<div class="dossier-card" onclick="viewDossier(\'' + escapeHtml(d.id) + '\')">'
                + '<h4>' + escapeHtml(d.name) + '</h4>'
                + '<div class="dossier-meta">' + escapeHtml(d.target || '') + ' | ' + escapeHtml(d.created ? d.created.split('T')[0] : '') + '</div>'
                + '<div class="dossier-stats">' + d.result_count + ' results</div>'
                + '</div>';
        });
        container.innerHTML = html;
    });
}

function viewDossier(dossierId) {
    currentDossierId = dossierId;
    fetchJSON('/osint/dossier/' + dossierId).then(function(data) {
        if (data.error) { alert(data.error); return; }
        var d = data.dossier;
        document.getElementById('dossier-detail').style.display = 'block';
        document.getElementById('dossier-detail-name').textContent = d.name + (d.target ? ' - ' + d.target : '');
        document.getElementById('dossier-notes').value = d.notes || '';

        var results = d.results || [];
        var container = document.getElementById('dossier-results-list');
        if (results.length === 0) {
            container.innerHTML = '<div class="empty-state">No results in this dossier.</div>';
            return;
        }
        var html = '';
        results.forEach(function(r) {
            var badgeCls = r.status === 'good' ? 'badge-pass' : r.status === 'maybe' ? 'badge-medium' : 'badge-info';
            html += '<div class="result-card ' + (r.status || '') + '">'
                + '<div style="flex:1"><strong>' + escapeHtml(r.name) + '</strong> '
                + '<span class="badge ' + badgeCls + '">' + (r.rate || 0) + '%</span>'
                + '<span style="color:var(--text-muted);margin-left:8px;font-size:0.78rem">' + escapeHtml(r.category || '') + '</span></div>'
                + '<a href="' + escapeHtml(r.url || '') + '" target="_blank" class="btn btn-small btn-success">Open</a>'
                + '</div>';
        });
        container.innerHTML = html;
    });
}

function saveDossierNotes() {
    if (!currentDossierId) return;
    var notes = document.getElementById('dossier-notes').value;
    fetchJSON('/osint/dossier/' + currentDossierId, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({notes: notes})
    }).then(function(data) {
        if (data.success) alert('Notes saved.');
    });
}

function deleteDossier() {
    if (!currentDossierId || !confirm('Delete this dossier?')) return;
    fetchJSON('/osint/dossier/' + currentDossierId, {method: 'DELETE'}).then(function(data) {
        if (data.success) {
            closeDossierDetail();
            loadDossiers();
        }
    });
}

function closeDossierDetail() {
    document.getElementById('dossier-detail').style.display = 'none';
    currentDossierId = null;
}

function exportDossier(fmt) {
    if (!currentDossierId) return;
    fetchJSON('/osint/dossier/' + currentDossierId).then(function(data) {
        if (data.error) return;
        var d = data.dossier;
        postJSON('/osint/export', {
            results: d.results || [],
            format: fmt,
            query: d.target || d.name
        }).then(function(exp) {
            if (exp.error) { alert('Export error: ' + exp.error); return; }
            alert('Exported to: ' + exp.path);
        });
    });
}

// ==================== DEFENSE ====================

function runDefenseAudit() {
    var btn = document.getElementById('btn-audit');
    setLoading(btn, true);
    postJSON('/defense/audit', {}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('audit-output', 'Error: ' + data.error); return; }
        // Score
        var scoreEl = document.getElementById('audit-score');
        if (scoreEl) {
            scoreEl.textContent = data.score + '%';
            scoreEl.style.color = data.score >= 80 ? 'var(--success)' : data.score >= 50 ? 'var(--warning)' : 'var(--danger)';
        }
        // Checks table
        var html = '';
        (data.checks || []).forEach(function(c) {
            html += '<tr><td>' + escapeHtml(c.name) + '</td><td><span class="badge ' + (c.passed ? 'badge-pass' : 'badge-fail') + '">'
                + (c.passed ? 'PASS' : 'FAIL') + '</span></td><td>' + escapeHtml(c.details || '') + '</td></tr>';
        });
        document.getElementById('audit-results').innerHTML = html;
    }).catch(function() { setLoading(btn, false); });
}

function runDefenseCheck(name) {
    var resultEl = document.getElementById('check-result-' + name);
    if (resultEl) { resultEl.textContent = 'Running...'; resultEl.style.display = 'block'; }
    postJSON('/defense/check/' + name, {}).then(function(data) {
        if (data.error) { if (resultEl) resultEl.textContent = 'Error: ' + data.error; return; }
        var lines = (data.checks || []).map(function(c) {
            return (c.passed ? '[PASS] ' : '[FAIL] ') + c.name + (c.details ? ' - ' + c.details : '');
        });
        if (resultEl) resultEl.textContent = lines.join('\n') || 'No results';
    }).catch(function() { if (resultEl) resultEl.textContent = 'Request failed'; });
}

function loadFirewallRules() {
    fetchJSON('/defense/firewall/rules').then(function(data) {
        renderOutput('fw-rules', data.rules || 'Could not load rules');
    });
}

function blockIP() {
    var ip = document.getElementById('block-ip').value.trim();
    if (!ip) return;
    postJSON('/defense/firewall/block', {ip: ip}).then(function(data) {
        renderOutput('fw-result', data.message || data.error);
        if (data.success) { document.getElementById('block-ip').value = ''; loadFirewallRules(); }
    });
}

function unblockIP(ip) {
    postJSON('/defense/firewall/unblock', {ip: ip}).then(function(data) {
        renderOutput('fw-result', data.message || data.error);
        if (data.success) loadFirewallRules();
    });
}

function analyzeLogs() {
    var btn = document.getElementById('btn-logs');
    setLoading(btn, true);
    postJSON('/defense/logs/analyze', {}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('log-output', 'Error: ' + data.error); return; }
        var lines = [];
        if (data.auth_results && data.auth_results.length) {
            lines.push('=== Auth Log Analysis ===');
            data.auth_results.forEach(function(r) {
                lines.push(r.ip + ': ' + r.count + ' failures (' + (r.usernames||[]).join(', ') + ')');
            });
        }
        if (data.web_results && data.web_results.length) {
            lines.push('\n=== Web Log Findings ===');
            data.web_results.forEach(function(r) {
                lines.push('[' + r.severity + '] ' + r.type + ' from ' + r.ip + ' - ' + (r.detail||''));
            });
        }
        renderOutput('log-output', lines.join('\n') || 'No findings');
    }).catch(function() { setLoading(btn, false); });
}

// ==================== COUNTER ====================

function runCounterScan() {
    var btn = document.getElementById('btn-scan');
    setLoading(btn, true);
    postJSON('/counter/scan', {}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('scan-output', 'Error: ' + data.error); return; }
        var container = document.getElementById('scan-results');
        var html = '';
        var threats = data.threats || [];
        if (threats.length === 0) {
            html = '<div class="empty-state">No threats detected.</div>';
        } else {
            threats.forEach(function(t) {
                var cls = t.severity === 'high' ? 'badge-high' : t.severity === 'medium' ? 'badge-medium' : 'badge-low';
                html += '<div class="threat-item"><span class="badge ' + cls + '">' + escapeHtml(t.severity).toUpperCase()
                    + '</span><div><div class="threat-message">' + escapeHtml(t.message)
                    + '</div><div class="threat-category">' + escapeHtml(t.category) + '</div></div></div>';
            });
        }
        container.innerHTML = html;
        // Summary
        var sumEl = document.getElementById('scan-summary');
        if (sumEl && data.summary) sumEl.textContent = data.summary;
    }).catch(function() { setLoading(btn, false); });
}

function runCounterCheck(name) {
    var resultEl = document.getElementById('counter-result-' + name);
    if (resultEl) { resultEl.textContent = 'Running...'; resultEl.style.display = 'block'; }
    postJSON('/counter/check/' + name, {}).then(function(data) {
        if (data.error) { if (resultEl) resultEl.textContent = 'Error: ' + data.error; return; }
        var lines = (data.threats || []).map(function(t) {
            return '[' + t.severity.toUpperCase() + '] ' + t.category + ': ' + t.message;
        });
        if (resultEl) resultEl.textContent = lines.join('\n') || data.message || 'No threats found';
    }).catch(function() { if (resultEl) resultEl.textContent = 'Request failed'; });
}

function loadLogins() {
    var btn = document.getElementById('btn-logins');
    setLoading(btn, true);
    fetchJSON('/counter/logins').then(function(data) {
        setLoading(btn, false);
        var container = document.getElementById('login-results');
        if (data.error) { container.innerHTML = '<div class="empty-state">' + escapeHtml(data.error) + '</div>'; return; }
        var attempts = data.attempts || [];
        if (attempts.length === 0) {
            container.innerHTML = '<div class="empty-state">No failed login attempts found.</div>';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>IP</th><th>Attempts</th><th>Usernames</th><th>Country</th><th>ISP</th></tr></thead><tbody>';
        attempts.forEach(function(a) {
            html += '<tr><td>' + escapeHtml(a.ip) + '</td><td>' + a.count + '</td><td>' + escapeHtml((a.usernames||[]).join(', '))
                + '</td><td>' + escapeHtml(a.country||'-') + '</td><td>' + escapeHtml(a.isp||'-') + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    }).catch(function() { setLoading(btn, false); });
}

// ==================== ANALYZE ====================

function analyzeFile() {
    var filepath = document.getElementById('analyze-filepath').value.trim();
    if (!filepath) return;
    var btn = document.getElementById('btn-analyze-file');
    setLoading(btn, true);
    postJSON('/analyze/file', {filepath: filepath}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('file-output', 'Error: ' + data.error); return; }
        var lines = [];
        lines.push('Path:     ' + (data.path || ''));
        lines.push('Size:     ' + (data.size || 0) + ' bytes');
        lines.push('Modified: ' + (data.modified || ''));
        lines.push('MIME:     ' + (data.mime || ''));
        lines.push('Type:     ' + (data.type || ''));
        if (data.hashes) {
            lines.push('\nHashes:');
            lines.push('  MD5:    ' + (data.hashes.md5 || ''));
            lines.push('  SHA1:   ' + (data.hashes.sha1 || ''));
            lines.push('  SHA256: ' + (data.hashes.sha256 || ''));
        }
        renderOutput('file-output', lines.join('\n'));
    }).catch(function() { setLoading(btn, false); });
}

function extractStrings() {
    var filepath = document.getElementById('strings-filepath').value.trim();
    var minLen = document.getElementById('strings-minlen').value || '4';
    if (!filepath) return;
    var btn = document.getElementById('btn-strings');
    setLoading(btn, true);
    postJSON('/analyze/strings', {filepath: filepath, min_len: parseInt(minLen)}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('strings-output', 'Error: ' + data.error); return; }
        var lines = [];
        if (data.urls && data.urls.length) { lines.push('URLs (' + data.urls.length + '):'); data.urls.forEach(function(u){lines.push('  ' + u);}); lines.push(''); }
        if (data.ips && data.ips.length) { lines.push('IPs (' + data.ips.length + '):'); data.ips.forEach(function(i){lines.push('  ' + i);}); lines.push(''); }
        if (data.emails && data.emails.length) { lines.push('Emails (' + data.emails.length + '):'); data.emails.forEach(function(e){lines.push('  ' + e);}); lines.push(''); }
        if (data.paths && data.paths.length) { lines.push('Paths (' + data.paths.length + '):'); data.paths.forEach(function(p){lines.push('  ' + p);}); }
        renderOutput('strings-output', lines.join('\n') || 'No interesting strings found');
    }).catch(function() { setLoading(btn, false); });
}

function hashLookup() {
    var hash = document.getElementById('hash-input').value.trim();
    if (!hash) return;
    postJSON('/analyze/hash', {hash: hash}).then(function(data) {
        if (data.error) { renderOutput('hash-output', 'Error: ' + data.error); return; }
        var lines = ['Hash Type: ' + (data.hash_type || 'Unknown'), ''];
        (data.links || []).forEach(function(l) { lines.push(l.name + ': ' + l.url); });
        renderOutput('hash-output', lines.join('\n'));
    });
}

function analyzeLog() {
    var filepath = document.getElementById('log-filepath').value.trim();
    if (!filepath) return;
    var btn = document.getElementById('btn-analyze-log');
    setLoading(btn, true);
    postJSON('/analyze/log', {filepath: filepath}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('log-analyze-output', 'Error: ' + data.error); return; }
        var lines = ['Total lines: ' + (data.total_lines || 0), ''];
        if (data.ip_counts && data.ip_counts.length) {
            lines.push('Top IPs:');
            data.ip_counts.forEach(function(i) { lines.push('  ' + i[0] + ': ' + i[1] + ' occurrences'); });
            lines.push('');
        }
        lines.push('Errors: ' + (data.error_count || 0));
        if (data.time_range) { lines.push('Time Range: ' + data.time_range.first + ' - ' + data.time_range.last); }
        renderOutput('log-analyze-output', lines.join('\n'));
    }).catch(function() { setLoading(btn, false); });
}

function hexDump() {
    var filepath = document.getElementById('hex-filepath').value.trim();
    var offset = document.getElementById('hex-offset').value || '0';
    var length = document.getElementById('hex-length').value || '256';
    if (!filepath) return;
    var btn = document.getElementById('btn-hex');
    setLoading(btn, true);
    postJSON('/analyze/hex', {filepath: filepath, offset: parseInt(offset), length: parseInt(length)}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('hex-output', 'Error: ' + data.error); return; }
        renderOutput('hex-output', data.hex || 'No data');
    }).catch(function() { setLoading(btn, false); });
}

function compareFiles() {
    var file1 = document.getElementById('compare-file1').value.trim();
    var file2 = document.getElementById('compare-file2').value.trim();
    if (!file1 || !file2) return;
    var btn = document.getElementById('btn-compare');
    setLoading(btn, true);
    postJSON('/analyze/compare', {file1: file1, file2: file2}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('compare-output', 'Error: ' + data.error); return; }
        var lines = [];
        lines.push('File 1: ' + data.file1_size + ' bytes');
        lines.push('File 2: ' + data.file2_size + ' bytes');
        lines.push('Difference: ' + data.size_diff + ' bytes');
        lines.push('');
        lines.push('MD5:    ' + (data.md5_match ? 'MATCH' : 'DIFFERENT'));
        lines.push('SHA256: ' + (data.sha256_match ? 'MATCH' : 'DIFFERENT'));
        if (data.diff) { lines.push('\nDiff:\n' + data.diff); }
        renderOutput('compare-output', lines.join('\n'));
    }).catch(function() { setLoading(btn, false); });
}

// ==================== SIMULATE ====================

function auditPassword() {
    var pw = document.getElementById('sim-password').value;
    if (!pw) return;
    var btn = document.getElementById('btn-password');
    setLoading(btn, true);
    postJSON('/simulate/password', {password: pw}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('password-output', 'Error: ' + data.error); return; }
        // Score
        var scoreEl = document.getElementById('pw-score');
        if (scoreEl) {
            scoreEl.textContent = data.score + '/10';
            scoreEl.style.color = data.score >= 8 ? 'var(--success)' : data.score >= 5 ? 'var(--warning)' : 'var(--danger)';
        }
        var strengthEl = document.getElementById('pw-strength');
        if (strengthEl) strengthEl.textContent = data.strength || '';
        // Feedback
        var lines = (data.feedback || []).map(function(f) { return f; });
        if (data.hashes) {
            lines.push('');
            lines.push('MD5:    ' + data.hashes.md5);
            lines.push('SHA1:   ' + data.hashes.sha1);
            lines.push('SHA256: ' + data.hashes.sha256);
        }
        renderOutput('password-output', lines.join('\n'));
    }).catch(function() { setLoading(btn, false); });
}

function scanPorts() {
    var target = document.getElementById('scan-target').value.trim();
    var ports = document.getElementById('scan-ports').value.trim() || '1-1024';
    if (!target) return;
    var btn = document.getElementById('btn-portscan');
    setLoading(btn, true);
    document.getElementById('portscan-output').textContent = 'Scanning... this may take a while.';
    postJSON('/simulate/portscan', {target: target, ports: ports}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('portscan-output', 'Error: ' + data.error); return; }
        var lines = [];
        var ports = data.open_ports || [];
        if (ports.length) {
            lines.push('Open ports on ' + escapeHtml(target) + ':');
            lines.push('');
            ports.forEach(function(p) {
                lines.push('  ' + p.port + '/tcp    open    ' + (p.service || 'unknown'));
            });
        } else {
            lines.push('No open ports found');
        }
        lines.push('\nScanned: ' + (data.scanned || 0) + ' ports');
        renderOutput('portscan-output', lines.join('\n'));
    }).catch(function() { setLoading(btn, false); });
}

function grabBanner() {
    var target = document.getElementById('banner-target').value.trim();
    var port = document.getElementById('banner-port').value.trim() || '80';
    if (!target) return;
    var btn = document.getElementById('btn-banner');
    setLoading(btn, true);
    postJSON('/simulate/banner', {target: target, port: parseInt(port)}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('banner-output', 'Error: ' + data.error); return; }
        renderOutput('banner-output', data.banner || 'No banner received');
    }).catch(function() { setLoading(btn, false); });
}

function generatePayloads() {
    var type = document.getElementById('payload-type').value;
    var btn = document.getElementById('btn-payloads');
    setLoading(btn, true);
    postJSON('/simulate/payloads', {type: type}).then(function(data) {
        setLoading(btn, false);
        if (data.error) { renderOutput('payload-output', 'Error: ' + data.error); return; }
        var container = document.getElementById('payload-list');
        var html = '';
        (data.payloads || []).forEach(function(p) {
            html += '<div class="payload-item"><code>' + escapeHtml(p) + '</code><button class="btn btn-small" onclick="navigator.clipboard.writeText(this.previousElementSibling.textContent)">Copy</button></div>';
        });
        container.innerHTML = html;
    }).catch(function() { setLoading(btn, false); });
}

// ==================== OFFENSE ====================

function checkMSFStatus() {
    fetchJSON('/offense/status').then(function(data) {
        var el = document.getElementById('msf-status');
        if (!el) return;
        var dot = data.connected ? '<span class="status-dot active"></span>' : '<span class="status-dot inactive"></span>';
        var text = data.connected ? 'Connected' : 'Disconnected';
        el.innerHTML = dot + text;
        if (data.connected) {
            var info = document.getElementById('msf-info');
            if (info) info.textContent = (data.host || '') + ':' + (data.port || '') + (data.version ? ' (v' + data.version + ')' : '');
        }
    }).catch(function() {
        var el = document.getElementById('msf-status');
        if (el) el.innerHTML = '<span class="status-dot inactive"></span>Disconnected';
    });
}

function searchMSFModules() {
    var query = document.getElementById('msf-search').value.trim();
    if (!query) return;
    var btn = document.getElementById('btn-msf-search');
    setLoading(btn, true);
    postJSON('/offense/search', {query: query}).then(function(data) {
        setLoading(btn, false);
        var container = document.getElementById('msf-search-results');
        if (data.error) { container.innerHTML = '<div class="empty-state">' + escapeHtml(data.error) + '</div>'; return; }
        var modules = data.modules || [];
        if (modules.length === 0) { container.innerHTML = '<div class="empty-state">No modules found.</div>'; return; }
        var html = '';
        modules.forEach(function(m) {
            var typeBadge = 'badge-info';
            if (m.path && m.path.startsWith('exploit')) typeBadge = 'badge-high';
            else if (m.path && m.path.startsWith('auxiliary')) typeBadge = 'badge-medium';
            var type = m.path ? m.path.split('/')[0] : '';
            html += '<div class="result-card" style="border-left:2px solid var(--border)"><div style="flex:1"><strong>' + escapeHtml(m.name || m.path)
                + '</strong> <span class="badge ' + typeBadge + '">' + escapeHtml(type) + '</span>'
                + '<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:2px">' + escapeHtml(m.path || '')
                + '</div></div></div>';
        });
        container.innerHTML = html;
    }).catch(function() { setLoading(btn, false); });
}

function loadMSFSessions() {
    fetchJSON('/offense/sessions').then(function(data) {
        var container = document.getElementById('msf-sessions');
        if (data.error) { container.innerHTML = '<div class="empty-state">' + escapeHtml(data.error) + '</div>'; return; }
        var sessions = data.sessions || {};
        var keys = Object.keys(sessions);
        if (keys.length === 0) { container.innerHTML = '<div class="empty-state">No active sessions.</div>'; return; }
        var html = '<table class="data-table"><thead><tr><th>ID</th><th>Type</th><th>Target</th><th>Info</th></tr></thead><tbody>';
        keys.forEach(function(id) {
            var s = sessions[id];
            html += '<tr><td>' + escapeHtml(id) + '</td><td>' + escapeHtml(s.type || '') + '</td><td>'
                + escapeHtml(s.tunnel_peer || s.target_host || '') + '</td><td>' + escapeHtml(s.info || '') + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function browseMSFModules(type) {
    var page = parseInt(document.getElementById('msf-page-' + type)?.value || '1');
    fetchJSON('/offense/modules/' + type + '?page=' + page).then(function(data) {
        var container = document.getElementById('msf-modules-' + type);
        if (data.error) { container.innerHTML = '<div class="empty-state">' + escapeHtml(data.error) + '</div>'; return; }
        var modules = data.modules || [];
        if (modules.length === 0) { container.innerHTML = '<div class="empty-state">No modules in this category.</div>'; return; }
        var html = '';
        modules.forEach(function(m) {
            html += '<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:0.85rem">'
                + '<strong>' + escapeHtml(m.name || '') + '</strong>'
                + '<div style="color:var(--text-muted);font-size:0.78rem">' + escapeHtml(m.path || '') + '</div>'
                + '</div>';
        });
        if (data.has_more) {
            html += '<div style="margin-top:8px"><button class="btn btn-small" onclick="document.getElementById(\'msf-page-' + type + '\').value='
                + (page + 1) + ';browseMSFModules(\'' + type + '\')">Load More</button></div>';
        }
        container.innerHTML = html;
    });
}

// ==================== WIRESHARK ====================

var wsEventSource = null;

function wsLoadInterfaces() {
    var sel = document.getElementById('ws-interface');
    if (!sel) return;
    fetchJSON('/wireshark/interfaces').then(function(data) {
        var ifaces = data.interfaces || [];
        sel.innerHTML = '<option value="">Default</option>';
        ifaces.forEach(function(i) {
            var desc = i.description ? ' (' + i.description + ')' : '';
            sel.innerHTML += '<option value="' + escapeHtml(i.name) + '">' + escapeHtml(i.name) + desc + '</option>';
        });
    }).catch(function() {
        sel.innerHTML = '<option value="">Could not load interfaces</option>';
    });
}

function wsStartCapture() {
    var iface = document.getElementById('ws-interface').value;
    var filter = document.getElementById('ws-filter').value.trim();
    var duration = parseInt(document.getElementById('ws-duration').value) || 30;

    var btn = document.getElementById('btn-ws-start');
    var stopBtn = document.getElementById('btn-ws-stop');
    setLoading(btn, true);
    stopBtn.style.display = 'inline-block';

    postJSON('/wireshark/capture/start', {
        interface: iface, filter: filter, duration: duration
    }).then(function(data) {
        if (data.error) {
            setLoading(btn, false);
            stopBtn.style.display = 'none';
            document.getElementById('ws-progress').textContent = 'Error: ' + data.error;
            return;
        }
        document.getElementById('ws-progress').textContent = 'Capturing...';
        document.getElementById('ws-capture-status').innerHTML = '<span class="status-dot active"></span>Capturing';

        // Start SSE stream
        var liveDiv = document.getElementById('ws-live-packets');
        liveDiv.style.display = 'block';
        liveDiv.textContent = '';

        wsEventSource = new EventSource('/wireshark/capture/stream');
        var pktCount = 0;

        wsEventSource.onmessage = function(e) {
            var d = JSON.parse(e.data);
            if (d.type === 'packet') {
                pktCount++;
                var line = (d.src || '?') + ' -> ' + (d.dst || '?') + '  ' + (d.protocol || '') + '  ' + (d.info || '');
                liveDiv.textContent += line + '\n';
                liveDiv.scrollTop = liveDiv.scrollHeight;
                document.getElementById('ws-progress').textContent = pktCount + ' packets captured';
            } else if (d.type === 'done') {
                wsEventSource.close();
                wsEventSource = null;
                setLoading(btn, false);
                stopBtn.style.display = 'none';
                document.getElementById('ws-progress').textContent = 'Capture complete: ' + (d.packet_count || pktCount) + ' packets';
                document.getElementById('ws-capture-status').innerHTML = '<span class="status-dot inactive"></span>Idle';
                document.getElementById('ws-analysis-section').style.display = 'block';
                wsShowPacketsTable();
            }
        };

        wsEventSource.onerror = function() {
            wsEventSource.close();
            wsEventSource = null;
            setLoading(btn, false);
            stopBtn.style.display = 'none';
            document.getElementById('ws-capture-status').innerHTML = '<span class="status-dot inactive"></span>Idle';
        };
    }).catch(function() {
        setLoading(btn, false);
        stopBtn.style.display = 'none';
    });
}

function wsStopCapture() {
    postJSON('/wireshark/capture/stop', {}).then(function(data) {
        document.getElementById('ws-progress').textContent = 'Stopping...';
    });
    if (wsEventSource) {
        wsEventSource.close();
        wsEventSource = null;
    }
}

function wsAnalyzePcap() {
    var filepath = document.getElementById('ws-pcap-path').value.trim();
    if (!filepath) return;
    var btn = document.getElementById('btn-ws-pcap');
    setLoading(btn, true);
    document.getElementById('ws-pcap-info').textContent = 'Loading...';

    postJSON('/wireshark/pcap/analyze', {filepath: filepath}).then(function(data) {
        setLoading(btn, false);
        if (data.error) {
            document.getElementById('ws-pcap-info').textContent = 'Error: ' + data.error;
            return;
        }
        var info = data.total_packets + ' packets loaded';
        if (data.size) info += ' (' + Math.round(data.size/1024) + ' KB)';
        if (data.truncated) info += ' (showing first 500)';
        document.getElementById('ws-pcap-info').textContent = info;

        document.getElementById('ws-analysis-section').style.display = 'block';
        wsRenderPackets(data.packets || []);
    }).catch(function() { setLoading(btn, false); });
}

function wsShowPacketsTable() {
    fetchJSON('/wireshark/capture/stats').then(function(stats) {
        document.getElementById('ws-packets-table').textContent = stats.packet_count + ' packets captured. Use analysis tabs to explore.';
    });
}

function wsRenderPackets(packets) {
    var container = document.getElementById('ws-packets-table');
    if (!packets.length) {
        container.textContent = 'No packets to display.';
        return;
    }
    var lines = [];
    lines.push('No.   Source               Destination          Proto    Length  Info');
    lines.push('─'.repeat(90));
    packets.forEach(function(p, i) {
        var num = String(i+1).padEnd(6);
        var src = (p.src || '').padEnd(21);
        var dst = (p.dst || '').padEnd(21);
        var proto = (p.protocol || '').padEnd(9);
        var len = String(p.length || 0).padEnd(8);
        var info = (p.info || '').substring(0, 40);
        lines.push(num + src + dst + proto + len + info);
    });
    container.textContent = lines.join('\n');
}

function wsLoadProtocols() {
    var container = document.getElementById('ws-protocols');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    postJSON('/wireshark/analyze/protocols', {}).then(function(data) {
        var protocols = data.protocols || {};
        var keys = Object.keys(protocols);
        if (keys.length === 0) {
            container.innerHTML = '<div class="empty-state">No protocol data.</div>';
            return;
        }
        var html = '<div style="margin-bottom:8px;font-size:0.82rem;color:var(--text-secondary)">Total: ' + (data.total || 0) + ' packets</div>';
        keys.forEach(function(proto) {
            var d = protocols[proto];
            var barWidth = Math.max(2, d.percent);
            html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;font-size:0.82rem">'
                + '<span style="width:80px;text-align:right">' + escapeHtml(proto) + '</span>'
                + '<div style="flex:1;height:16px;background:var(--bg-input);border-radius:3px;overflow:hidden">'
                + '<div style="height:100%;width:' + barWidth + '%;background:var(--accent);border-radius:3px"></div></div>'
                + '<span style="width:60px;color:var(--text-secondary)">' + d.count + ' (' + d.percent + '%)</span>'
                + '</div>';
        });
        container.innerHTML = html;
    });
}

function wsLoadConversations() {
    var container = document.getElementById('ws-conversations');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    postJSON('/wireshark/analyze/conversations', {}).then(function(data) {
        var convos = data.conversations || [];
        if (convos.length === 0) {
            container.innerHTML = '<div class="empty-state">No conversations found.</div>';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>Source</th><th>Destination</th><th>Packets</th><th>Bytes</th><th>Protocols</th></tr></thead><tbody>';
        convos.forEach(function(c) {
            html += '<tr><td>' + escapeHtml(c.src) + '</td><td>' + escapeHtml(c.dst) + '</td><td>' + c.packets
                + '</td><td>' + c.bytes + '</td><td>' + escapeHtml((c.protocols||[]).join(', ')) + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function wsLoadDNS() {
    var container = document.getElementById('ws-dns');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    postJSON('/wireshark/analyze/dns', {}).then(function(data) {
        var queries = data.queries || [];
        if (queries.length === 0) {
            container.innerHTML = '<div class="empty-state">No DNS queries found.</div>';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>Query</th><th>Type</th><th>Count</th><th>Response</th><th>Source</th></tr></thead><tbody>';
        queries.forEach(function(q) {
            html += '<tr><td>' + escapeHtml(q.query) + '</td><td>' + escapeHtml(q.type) + '</td><td>' + q.count
                + '</td><td>' + escapeHtml(q.response || '') + '</td><td>' + escapeHtml(q.src || '') + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function wsLoadHTTP() {
    var container = document.getElementById('ws-http');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    postJSON('/wireshark/analyze/http', {}).then(function(data) {
        var reqs = data.requests || [];
        if (reqs.length === 0) {
            container.innerHTML = '<div class="empty-state">No HTTP requests found.</div>';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>Method</th><th>Host</th><th>Path</th><th>Source</th></tr></thead><tbody>';
        reqs.forEach(function(r) {
            var methodCls = r.method === 'GET' ? 'badge-pass' : r.method === 'POST' ? 'badge-medium' : 'badge-info';
            html += '<tr><td><span class="badge ' + methodCls + '">' + escapeHtml(r.method) + '</span></td>'
                + '<td>' + escapeHtml(r.host) + '</td><td>' + escapeHtml((r.path||'').substring(0,60)) + '</td>'
                + '<td>' + escapeHtml(r.src) + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function wsLoadCredentials() {
    var container = document.getElementById('ws-creds');
    container.innerHTML = '<div class="empty-state">Loading...</div>';
    postJSON('/wireshark/analyze/credentials', {}).then(function(data) {
        var creds = data.credentials || [];
        if (creds.length === 0) {
            container.innerHTML = '<div class="empty-state">No plaintext credentials detected.</div>';
            return;
        }
        var html = '<div style="margin-bottom:8px;font-size:0.82rem;color:var(--danger)">' + creds.length + ' credential artifact(s) found</div>';
        html += '<table class="data-table"><thead><tr><th>Protocol</th><th>Type</th><th>Value</th><th>Source</th><th>Destination</th></tr></thead><tbody>';
        creds.forEach(function(c) {
            html += '<tr><td><span class="badge badge-high">' + escapeHtml(c.protocol) + '</span></td>'
                + '<td>' + escapeHtml(c.type) + '</td><td><code>' + escapeHtml(c.value) + '</code></td>'
                + '<td>' + escapeHtml(c.src) + '</td><td>' + escapeHtml(c.dst) + '</td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function wsExport(fmt) {
    postJSON('/wireshark/export', {format: fmt}).then(function(data) {
        if (data.error) { alert('Export error: ' + data.error); return; }
        alert('Exported ' + data.count + ' packets to:\n' + data.filepath);
    });
}

// ==================== HARDWARE ====================

var hwSelectedAdb = '';
var hwSelectedFb = '';
var hwMonitorES = null;
var hwConnectionMode = 'server'; // 'server' or 'direct'

// ── Mode Switching ──

function hwSetMode(mode) {
    hwConnectionMode = mode;
    localStorage.setItem('hw_connection_mode', mode);

    // Toggle button states
    var serverBtn = document.getElementById('hw-mode-server');
    var directBtn = document.getElementById('hw-mode-direct');
    if (serverBtn) serverBtn.classList.toggle('active', mode === 'server');
    if (directBtn) directBtn.classList.toggle('active', mode === 'direct');

    // Toggle status cards
    var serverStatus = document.getElementById('hw-status-server');
    var directStatus = document.getElementById('hw-status-direct');
    if (serverStatus) serverStatus.style.display = mode === 'server' ? '' : 'none';
    if (directStatus) directStatus.style.display = mode === 'direct' ? '' : 'none';

    // Toggle server-only vs direct-only elements
    var serverEls = ['hw-adb-refresh-bar', 'hw-fb-refresh-bar', 'hw-serial-section',
                     'hw-sideload-server', 'hw-transfer-server', 'hw-fb-firmware-server',
                     'hw-esp-flash-server', 'hw-monitor-server'];
    var directEls = ['hw-direct-adb-connect', 'hw-direct-fb-connect', 'hw-direct-esp-connect',
                     'hw-sideload-direct', 'hw-transfer-direct', 'hw-fb-firmware-direct',
                     'hw-esp-flash-direct', 'hw-monitor-direct'];

    serverEls.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = mode === 'server' ? '' : 'none';
    });
    directEls.forEach(function(id) {
        var el = document.getElementById(id);
        if (el) el.style.display = mode === 'direct' ? '' : 'none';
    });

    // Direct mode: check browser capabilities
    if (mode === 'direct') {
        hwCheckDirectCapabilities();
        // Hide server device lists in direct mode
        var adbSection = document.getElementById('hw-adb-section');
        if (adbSection) adbSection.style.display = 'none';
        var fbSection = document.getElementById('hw-fastboot-section');
        if (fbSection) fbSection.style.display = 'none';
    } else {
        var adbSection = document.getElementById('hw-adb-section');
        if (adbSection) adbSection.style.display = '';
        var fbSection = document.getElementById('hw-fastboot-section');
        if (fbSection) fbSection.style.display = '';
        hwRefreshAdbDevices();
        hwRefreshFastbootDevices();
        hwRefreshSerialPorts();
    }

    // Factory flash tab: check mode
    var factoryWarning = document.getElementById('hw-factory-requires-direct');
    var factoryControls = document.getElementById('hw-factory-controls');
    if (factoryWarning && factoryControls) {
        factoryWarning.style.display = mode === 'direct' ? 'none' : 'block';
        factoryControls.style.display = mode === 'direct' ? '' : 'none';
    }

    // Warning message
    var warning = document.getElementById('hw-mode-warning');
    if (warning) {
        if (mode === 'direct' && typeof HWDirect !== 'undefined' && !HWDirect.supported.webusb) {
            warning.style.display = 'block';
            if (typeof window.isSecureContext !== 'undefined' && !window.isSecureContext) {
                warning.textContent = 'WebUSB requires a secure context (HTTPS). You are accessing over plain HTTP — set [web] https = true in autarch.conf or access via https://. Restart the server after changing config.';
            } else {
                warning.textContent = 'WebUSB is not supported in this browser. Direct mode requires Chrome, Edge, or another Chromium-based browser.';
            }
        } else {
            warning.style.display = 'none';
        }
    }
}

function hwCheckDirectCapabilities() {
    if (typeof HWDirect === 'undefined') return;
    var usbDot = document.getElementById('hw-cap-webusb');
    var usbText = document.getElementById('hw-cap-webusb-text');
    var serialDot = document.getElementById('hw-cap-webserial');
    var serialText = document.getElementById('hw-cap-webserial-text');
    if (usbDot) {
        usbDot.className = 'status-dot ' + (HWDirect.supported.webusb ? 'active' : 'inactive');
        if (usbText) usbText.textContent = HWDirect.supported.webusb ? 'Supported' : 'Not available';
    }
    if (serialDot) {
        serialDot.className = 'status-dot ' + (HWDirect.supported.webserial ? 'active' : 'inactive');
        if (serialText) serialText.textContent = HWDirect.supported.webserial ? 'Supported' : 'Not available';
    }
    hwUpdateDirectStatus();
}

function hwUpdateDirectStatus() {
    if (typeof HWDirect === 'undefined') return;
    var adbDot = document.getElementById('hw-direct-adb-status');
    var adbText = document.getElementById('hw-direct-adb-text');
    var fbDot = document.getElementById('hw-direct-fb-status');
    var fbText = document.getElementById('hw-direct-fb-text');
    if (adbDot) {
        adbDot.className = 'status-dot ' + (HWDirect.adbIsConnected() ? 'active' : 'inactive');
        if (adbText) adbText.textContent = HWDirect.adbIsConnected() ? 'Connected' : 'Not connected';
    }
    if (fbDot) {
        fbDot.className = 'status-dot ' + (HWDirect.fbIsConnected() ? 'active' : 'inactive');
        if (fbText) fbText.textContent = HWDirect.fbIsConnected() ? 'Connected' : 'Not connected';
    }
}

// ── Direct-mode ADB ──

async function hwDirectAdbConnect() {
    var msg = document.getElementById('hw-direct-adb-msg');
    msg.textContent = 'Requesting USB device...';
    try {
        var device = await HWDirect.adbRequestDevice();
        if (!device) { msg.textContent = 'Cancelled'; return; }
        msg.textContent = 'Connecting to ' + (device.name || device.serial) + '...';
        await HWDirect.adbConnect(device);
        msg.innerHTML = '<span style="color:var(--success)">Connected: ' + escapeHtml(device.serial || device.name) + '</span>';
        document.getElementById('hw-direct-adb-disconnect-btn').style.display = 'inline-block';
        hwUpdateDirectStatus();
        // Show device actions and load info
        hwSelectedAdb = device.serial || 'direct';
        document.getElementById('hw-selected-serial').textContent = device.serial || device.name;
        document.getElementById('hw-device-actions').style.display = 'block';
        hwDeviceInfo();
    } catch (e) {
        msg.innerHTML = '<span style="color:var(--danger)">' + escapeHtml(e.message) + '</span>';
    }
}

async function hwDirectAdbDisconnect() {
    await HWDirect.adbDisconnect();
    document.getElementById('hw-direct-adb-msg').textContent = 'Disconnected';
    document.getElementById('hw-direct-adb-disconnect-btn').style.display = 'none';
    document.getElementById('hw-device-actions').style.display = 'none';
    hwSelectedAdb = '';
    hwUpdateDirectStatus();
}

// ── Direct-mode Fastboot ──

async function hwDirectFbConnect() {
    var msg = document.getElementById('hw-direct-fb-msg');
    msg.textContent = 'Requesting USB device...';
    try {
        await HWDirect.fbConnect();
        msg.innerHTML = '<span style="color:var(--success)">Fastboot device connected</span>';
        document.getElementById('hw-direct-fb-disconnect-btn').style.display = 'inline-block';
        hwUpdateDirectStatus();
        hwSelectedFb = 'direct';
        document.getElementById('hw-fb-selected').textContent = 'Direct USB';
        document.getElementById('hw-fastboot-actions').style.display = 'block';
        hwFastbootInfo();
    } catch (e) {
        msg.innerHTML = '<span style="color:var(--danger)">' + escapeHtml(e.message) + '</span>';
    }
}

async function hwDirectFbDisconnect() {
    await HWDirect.fbDisconnect();
    document.getElementById('hw-direct-fb-msg').textContent = 'Disconnected';
    document.getElementById('hw-direct-fb-disconnect-btn').style.display = 'none';
    document.getElementById('hw-fastboot-actions').style.display = 'none';
    hwSelectedFb = '';
    hwUpdateDirectStatus();
}

// ── Direct-mode ESP32 ──

async function hwDirectEspConnect() {
    var msg = document.getElementById('hw-direct-esp-msg');
    msg.textContent = 'Select serial port...';
    try {
        await HWDirect.espRequestPort();
        msg.innerHTML = '<span style="color:var(--success)">Serial port selected</span>';
        document.getElementById('hw-direct-esp-disconnect-btn').style.display = 'inline-block';
    } catch (e) {
        msg.innerHTML = '<span style="color:var(--danger)">' + escapeHtml(e.message) + '</span>';
    }
}

async function hwDirectEspDisconnect() {
    await HWDirect.espDisconnect();
    document.getElementById('hw-direct-esp-msg').textContent = 'Disconnected';
    document.getElementById('hw-direct-esp-disconnect-btn').style.display = 'none';
}

// ── Archon Server Bootstrap ──

function hwArchonBootstrap() {
    var out = document.getElementById('hw-archon-output');
    if (!out) return;
    out.textContent = 'Discovering device and bootstrapping ArchonServer...';

    // Step 1: Find connected device
    fetchJSON('/hardware/adb/devices').then(function(data) {
        var devices = data.devices || [];
        if (devices.length === 0) {
            out.textContent = 'ERROR: No ADB devices connected. Connect phone via USB.';
            return;
        }
        var serial = devices[0].serial;
        out.textContent = 'Found device: ' + serial + '\nGetting APK path...';

        // Step 2: Get the Archon APK path
        fetchJSON('/hardware/adb/shell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({serial: serial, command: 'pm path com.darkhal.archon'})
        }).then(function(r) {
            var stdout = r.stdout || '';
            var apkPath = stdout.replace('package:', '').trim().split('\n')[0];
            if (!apkPath || !apkPath.startsWith('/data/app/')) {
                out.textContent += '\nERROR: Archon app not installed on device.\npm path output: ' + stdout;
                return;
            }
            out.textContent += '\nAPK: ' + apkPath;

            // Step 3: Generate token and bootstrap
            var token = '';
            for (var i = 0; i < 32; i++) {
                token += '0123456789abcdef'[Math.floor(Math.random() * 16)];
            }

            out.textContent += '\nToken: ' + token + '\nBootstrapping...';

            fetchJSON('/hardware/archon/bootstrap', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({apk_path: apkPath, token: token, port: 17321})
            }).then(function(result) {
                if (result.ok) {
                    out.textContent += '\nBootstrap command sent!';
                    out.textContent += '\nstdout: ' + (result.stdout || '');
                    if (result.stderr) out.textContent += '\nstderr: ' + result.stderr;
                    out.textContent += '\n\nWaiting for server to start...';

                    // Step 4: Check if server started (ping via device)
                    setTimeout(function() {
                        fetchJSON('/hardware/adb/shell', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({serial: serial, command: 'cat /data/local/tmp/archon_server.log'})
                        }).then(function(logResult) {
                            out.textContent += '\n\n── Server Log ──\n' + (logResult.stdout || logResult.stderr || 'empty');
                        });
                    }, 3000);
                } else {
                    out.textContent += '\nERROR: ' + (result.error || result.stderr || JSON.stringify(result));
                }
            });
        });
    });
}

function hwArchonStatus() {
    var out = document.getElementById('hw-archon-output');
    if (!out) return;
    out.textContent = 'Checking ArchonServer status...';

    fetchJSON('/hardware/adb/devices').then(function(data) {
        var devices = data.devices || [];
        if (devices.length === 0) {
            out.textContent = 'No ADB devices connected.';
            return;
        }
        var serial = devices[0].serial;

        fetchJSON('/hardware/adb/shell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({serial: serial, command: 'cat /data/local/tmp/archon_server.log 2>&1; echo "---"; ps -A | grep archon 2>/dev/null || echo "No archon process"'})
        }).then(function(r) {
            out.textContent = '── Server Log ──\n' + (r.stdout || 'No log file') + '\n' + (r.stderr || '');
        });
    });
}

function hwArchonStop() {
    var out = document.getElementById('hw-archon-output');
    if (!out) return;
    out.textContent = 'Stopping ArchonServer...';

    fetchJSON('/hardware/adb/devices').then(function(data) {
        var devices = data.devices || [];
        if (devices.length === 0) {
            out.textContent = 'No ADB devices connected.';
            return;
        }
        var serial = devices[0].serial;

        fetchJSON('/hardware/adb/shell', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({serial: serial, command: "pkill -f 'com.darkhal.archon.server.ArchonServer' 2>/dev/null && echo 'Killed' || echo 'Not running'"})
        }).then(function(r) {
            out.textContent = r.stdout || r.stderr || 'Done';
        });
    });
}

// ── ADB (mode-aware) ──

function hwRefreshAdbDevices() {
    if (hwConnectionMode === 'direct') return; // Direct mode uses connect buttons
    var container = document.getElementById('hw-adb-devices');
    if (!container) return;
    container.innerHTML = '<div class="progress-text">Scanning...</div>';
    fetchJSON('/hardware/adb/devices').then(function(data) {
        var devices = data.devices || [];
        if (devices.length === 0) {
            container.innerHTML = '<div class="empty-state">No ADB devices connected</div>';
            document.getElementById('hw-device-actions').style.display = 'none';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>Serial</th><th>State</th><th>Model</th><th>Product</th><th></th></tr></thead><tbody>';
        devices.forEach(function(d) {
            var sel = d.serial === hwSelectedAdb ? ' style="background:rgba(99,102,241,0.08)"' : '';
            html += '<tr' + sel + '><td><strong>' + escapeHtml(d.serial) + '</strong></td>'
                + '<td><span class="status-dot ' + (d.state === 'device' ? 'active' : 'warning') + '"></span>' + escapeHtml(d.state) + '</td>'
                + '<td>' + escapeHtml(d.model || '') + '</td>'
                + '<td>' + escapeHtml(d.product || '') + '</td>'
                + '<td><button class="btn btn-primary btn-small" onclick="hwSelectDevice(\'' + escapeHtml(d.serial) + '\')">Select</button></td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function hwSelectDevice(serial) {
    hwSelectedAdb = serial;
    document.getElementById('hw-selected-serial').textContent = serial;
    document.getElementById('hw-device-actions').style.display = 'block';
    hwDeviceInfo(serial);
    hwRefreshAdbDevices();
}

function hwDeviceInfo(serial) {
    var container = document.getElementById('hw-device-info');
    container.innerHTML = '<div class="progress-text">Loading...</div>';

    if (hwConnectionMode === 'direct') {
        HWDirect.adbGetInfo().then(function(data) {
            hwRenderDeviceInfo(container, data);
        }).catch(function(e) {
            container.innerHTML = '<div class="progress-text" style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
        });
    } else {
        postJSON('/hardware/adb/info', {serial: serial}).then(function(data) {
            if (data.error) { container.innerHTML = '<div class="progress-text" style="color:var(--danger)">' + escapeHtml(data.error) + '</div>'; return; }
            hwRenderDeviceInfo(container, data);
        });
    }
}

function hwRenderDeviceInfo(container, data) {
    var html = '';
    var keys = ['model', 'brand', 'android_version', 'sdk', 'build', 'security_patch', 'cpu_abi', 'battery', 'battery_status', 'storage_total', 'storage_used', 'storage_free', 'serialno'];
    keys.forEach(function(k) {
        if (data[k]) {
            var label = k.replace(/_/g, ' ').replace(/\b\w/g, function(c){return c.toUpperCase();});
            html += '<div class="info-item"><div class="info-label">' + label + '</div><div class="info-value">' + escapeHtml(data[k]) + '</div></div>';
        }
    });
    container.innerHTML = html || '<div class="progress-text">No properties available</div>';
}

function hwShell() {
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    var input = document.getElementById('hw-shell-cmd');
    var cmd = input.value.trim();
    if (!cmd) return;
    var output = document.getElementById('hw-shell-output');
    var existing = output.textContent;
    output.textContent = existing + (existing ? '\n' : '') + '$ ' + cmd + '\n...';

    var promise;
    if (hwConnectionMode === 'direct') {
        promise = HWDirect.adbShell(cmd).then(function(data) {
            return data.output || data.error || '';
        });
    } else {
        promise = postJSON('/hardware/adb/shell', {serial: hwSelectedAdb, command: cmd}).then(function(data) {
            return data.output || data.error || '';
        });
    }

    promise.then(function(result) {
        output.textContent = existing + (existing ? '\n' : '') + '$ ' + cmd + '\n' + result;
        output.scrollTop = output.scrollHeight;
    });
    input.value = '';
}

function hwReboot(mode) {
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    if (!confirm('Reboot device to ' + mode + '?')) return;

    if (hwConnectionMode === 'direct') {
        HWDirect.adbReboot(mode).then(function() {
            alert('Rebooting...');
            hwDirectAdbDisconnect();
        }).catch(function(e) { alert('Reboot failed: ' + e.message); });
    } else {
        postJSON('/hardware/adb/reboot', {serial: hwSelectedAdb, mode: mode}).then(function(data) {
            alert(data.output || (data.success ? 'Rebooting...' : 'Failed'));
            setTimeout(hwRefreshAdbDevices, 3000);
        });
    }
}

function hwSideload() {
    // Server mode only
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    var filepath = document.getElementById('hw-sideload-path').value.trim();
    if (!filepath) { alert('Enter file path'); return; }
    var progDiv = document.getElementById('hw-sideload-progress');
    progDiv.style.display = 'block';
    document.getElementById('hw-sideload-fill').style.width = '0%';
    document.getElementById('hw-sideload-pct').textContent = '0%';
    document.getElementById('hw-sideload-msg').textContent = 'Starting...';

    postJSON('/hardware/adb/sideload', {serial: hwSelectedAdb, filepath: filepath}).then(function(data) {
        if (!data.success) {
            document.getElementById('hw-sideload-msg').textContent = data.error || 'Failed';
            return;
        }
        hwTrackProgress(data.op_id, 'hw-sideload-fill', 'hw-sideload-pct', 'hw-sideload-msg');
    });
}

async function hwSideloadDirect() {
    // Direct mode: install APK from file picker
    if (!HWDirect.adbIsConnected()) { alert('No ADB device connected'); return; }
    var fileInput = document.getElementById('hw-sideload-file');
    if (!fileInput.files.length) { alert('Select an APK file'); return; }
    var file = fileInput.files[0];
    document.getElementById('hw-sideload-msg').textContent = 'Installing ' + file.name + '...';
    document.getElementById('hw-sideload-progress').style.display = 'block';
    try {
        var result = await HWDirect.adbInstall(file);
        document.getElementById('hw-sideload-msg').textContent = result.output || 'Done';
    } catch (e) {
        document.getElementById('hw-sideload-msg').textContent = 'Failed: ' + e.message;
    }
}

function hwTrackProgress(opId, fillId, pctId, msgId) {
    var es = new EventSource('/hardware/progress/stream?op_id=' + encodeURIComponent(opId));
    es.onmessage = function(e) {
        var data = JSON.parse(e.data);
        var fill = document.getElementById(fillId);
        var pct = document.getElementById(pctId);
        var msg = document.getElementById(msgId);
        if (fill) fill.style.width = data.progress + '%';
        if (pct) pct.textContent = data.progress + '%';
        if (msg) msg.textContent = data.message || '';
        if (data.status === 'done' || data.status === 'error' || data.status === 'unknown') {
            es.close();
        }
    };
    es.onerror = function() { es.close(); };
}

function hwPush() {
    // Server mode
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    var local = document.getElementById('hw-push-local').value.trim();
    var remote = document.getElementById('hw-push-remote').value.trim();
    if (!local || !remote) { alert('Enter both local and remote paths'); return; }
    var msg = document.getElementById('hw-transfer-msg');
    msg.textContent = 'Pushing...';
    postJSON('/hardware/adb/push', {serial: hwSelectedAdb, local: local, remote: remote}).then(function(data) {
        msg.textContent = data.output || data.error || (data.success ? 'Done' : 'Failed');
    });
}

async function hwPushDirect() {
    // Direct mode: push file from picker
    if (!HWDirect.adbIsConnected()) { alert('No ADB device connected'); return; }
    var fileInput = document.getElementById('hw-push-file');
    var remote = document.getElementById('hw-push-remote-direct').value.trim();
    if (!fileInput.files.length) { alert('Select a file'); return; }
    if (!remote) { alert('Enter remote path'); return; }
    var msg = document.getElementById('hw-transfer-msg');
    msg.textContent = 'Pushing...';
    try {
        await HWDirect.adbPush(fileInput.files[0], remote);
        msg.textContent = 'Push complete';
    } catch (e) {
        msg.textContent = 'Failed: ' + e.message;
    }
}

async function hwPullDirect() {
    // Direct mode: pull file and download
    if (!HWDirect.adbIsConnected()) { alert('No ADB device connected'); return; }
    var remote = document.getElementById('hw-push-remote-direct').value.trim();
    if (!remote) { alert('Enter remote path'); return; }
    var msg = document.getElementById('hw-transfer-msg');
    msg.textContent = 'Pulling...';
    try {
        var blob = await HWDirect.adbPull(remote);
        var filename = remote.split('/').pop() || 'pulled_file';
        HWDirect.downloadBlob(blob, filename);
        msg.textContent = 'Downloaded: ' + filename;
    } catch (e) {
        msg.textContent = 'Failed: ' + e.message;
    }
}

function hwPull() {
    // Server mode
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    var remote = document.getElementById('hw-push-remote').value.trim();
    if (!remote) { alert('Enter remote path'); return; }
    var msg = document.getElementById('hw-transfer-msg');
    msg.textContent = 'Pulling...';
    postJSON('/hardware/adb/pull', {serial: hwSelectedAdb, remote: remote}).then(function(data) {
        msg.textContent = data.output || data.error || (data.success ? 'Saved to: ' + data.local_path : 'Failed');
    });
}

function hwLogcat() {
    if (!hwSelectedAdb) { alert('No device selected'); return; }
    var lines = document.getElementById('hw-logcat-lines').value || 50;
    var output = document.getElementById('hw-logcat-output');
    output.style.display = 'block';
    output.textContent = 'Loading...';

    if (hwConnectionMode === 'direct') {
        HWDirect.adbLogcat(parseInt(lines)).then(function(data) {
            output.textContent = data.output || 'No output';
            output.scrollTop = output.scrollHeight;
        });
    } else {
        postJSON('/hardware/adb/logcat', {serial: hwSelectedAdb, lines: parseInt(lines)}).then(function(data) {
            output.textContent = data.output || 'No output';
            output.scrollTop = output.scrollHeight;
        });
    }
}

// ── Fastboot (mode-aware) ──

function hwRefreshFastbootDevices() {
    if (hwConnectionMode === 'direct') return;
    var container = document.getElementById('hw-fastboot-devices');
    if (!container) return;
    container.innerHTML = '<div class="progress-text">Scanning...</div>';
    fetchJSON('/hardware/fastboot/devices').then(function(data) {
        var devices = data.devices || [];
        if (devices.length === 0) {
            container.innerHTML = '<div class="empty-state">No Fastboot devices connected</div>';
            document.getElementById('hw-fastboot-actions').style.display = 'none';
            return;
        }
        var html = '<table class="data-table"><thead><tr><th>Serial</th><th>State</th><th></th></tr></thead><tbody>';
        devices.forEach(function(d) {
            html += '<tr><td><strong>' + escapeHtml(d.serial) + '</strong></td>'
                + '<td>' + escapeHtml(d.state) + '</td>'
                + '<td><button class="btn btn-primary btn-small" onclick="hwSelectFastboot(\'' + escapeHtml(d.serial) + '\')">Select</button></td></tr>';
        });
        html += '</tbody></table>';
        container.innerHTML = html;
    });
}

function hwSelectFastboot(serial) {
    hwSelectedFb = serial;
    document.getElementById('hw-fb-selected').textContent = serial;
    document.getElementById('hw-fastboot-actions').style.display = 'block';
    hwFastbootInfo(serial);
}

function hwFastbootInfo(serial) {
    var container = document.getElementById('hw-fastboot-info');
    container.innerHTML = '<div class="progress-text">Loading...</div>';

    if (hwConnectionMode === 'direct') {
        HWDirect.fbGetInfo().then(function(data) {
            hwRenderFastbootInfo(container, data);
        }).catch(function(e) {
            container.innerHTML = '<div class="progress-text" style="color:var(--danger)">' + escapeHtml(e.message) + '</div>';
        });
    } else {
        postJSON('/hardware/fastboot/info', {serial: serial}).then(function(data) {
            if (data.error) { container.innerHTML = '<div class="progress-text" style="color:var(--danger)">' + escapeHtml(data.error) + '</div>'; return; }
            hwRenderFastbootInfo(container, data);
        });
    }
}

function hwRenderFastbootInfo(container, data) {
    var html = '';
    Object.keys(data).forEach(function(k) {
        if (data[k]) {
            var label = k.replace(/[-_]/g, ' ').replace(/\b\w/g, function(c){return c.toUpperCase();});
            html += '<div class="info-item"><div class="info-label">' + label + '</div><div class="info-value">' + escapeHtml(data[k]) + '</div></div>';
        }
    });
    container.innerHTML = html || '<div class="progress-text">No info available</div>';
}

function hwFastbootFlash() {
    if (!hwSelectedFb) { alert('No fastboot device selected'); return; }
    var partition = document.getElementById('hw-fb-partition').value;

    if (hwConnectionMode === 'direct') {
        var fileInput = document.getElementById('hw-fb-firmware-file');
        if (!fileInput.files.length) { alert('Select firmware file'); return; }
        if (!confirm('Flash ' + partition + ' partition?')) return;
        var progDiv = document.getElementById('hw-fb-flash-progress');
        progDiv.style.display = 'block';
        document.getElementById('hw-fb-flash-fill').style.width = '0%';
        document.getElementById('hw-fb-flash-pct').textContent = '0%';
        document.getElementById('hw-fb-flash-msg').textContent = 'Flashing...';

        HWDirect.fbFlash(partition, fileInput.files[0], function(progress) {
            var pct = Math.round(progress * 100);
            document.getElementById('hw-fb-flash-fill').style.width = pct + '%';
            document.getElementById('hw-fb-flash-pct').textContent = pct + '%';
        }).then(function() {
            document.getElementById('hw-fb-flash-msg').textContent = 'Flash complete';
        }).catch(function(e) {
            document.getElementById('hw-fb-flash-msg').textContent = 'Failed: ' + e.message;
        });
    } else {
        var filepath = document.getElementById('hw-fb-firmware').value.trim();
        if (!filepath) { alert('Enter firmware file path'); return; }
        if (!confirm('Flash ' + partition + ' partition on ' + hwSelectedFb + '?')) return;
        var progDiv = document.getElementById('hw-fb-flash-progress');
        progDiv.style.display = 'block';
        document.getElementById('hw-fb-flash-fill').style.width = '0%';
        document.getElementById('hw-fb-flash-pct').textContent = '0%';
        document.getElementById('hw-fb-flash-msg').textContent = 'Starting...';

        postJSON('/hardware/fastboot/flash', {serial: hwSelectedFb, partition: partition, filepath: filepath}).then(function(data) {
            if (!data.success) {
                document.getElementById('hw-fb-flash-msg').textContent = data.error || 'Failed';
                return;
            }
            hwTrackProgress(data.op_id, 'hw-fb-flash-fill', 'hw-fb-flash-pct', 'hw-fb-flash-msg');
        });
    }
}

function hwFastbootReboot(mode) {
    if (!hwSelectedFb) { alert('No fastboot device selected'); return; }
    if (!confirm('Reboot fastboot device to ' + mode + '?')) return;

    if (hwConnectionMode === 'direct') {
        HWDirect.fbReboot(mode).then(function() {
            var msg = document.getElementById('hw-fb-msg');
            msg.textContent = 'Rebooting...';
            hwDirectFbDisconnect();
        }).catch(function(e) {
            document.getElementById('hw-fb-msg').textContent = 'Failed: ' + e.message;
        });
    } else {
        postJSON('/hardware/fastboot/reboot', {serial: hwSelectedFb, mode: mode}).then(function(data) {
            var msg = document.getElementById('hw-fb-msg');
            msg.textContent = data.output || (data.success ? 'Rebooting...' : 'Failed');
            setTimeout(function() { hwRefreshFastbootDevices(); hwRefreshAdbDevices(); }, 3000);
        });
    }
}

function hwFastbootUnlock() {
    document.getElementById('hw-fb-confirm').style.display = 'block';
}

function hwFastbootUnlockConfirm() {
    if (!hwSelectedFb) return;
    document.getElementById('hw-fb-confirm').style.display = 'none';
    var msg = document.getElementById('hw-fb-msg');
    msg.textContent = 'Sending OEM unlock...';

    if (hwConnectionMode === 'direct') {
        HWDirect.fbOemUnlock().then(function() {
            msg.textContent = 'OEM Unlock sent';
        }).catch(function(e) {
            msg.textContent = 'Failed: ' + e.message;
        });
    } else {
        postJSON('/hardware/fastboot/unlock', {serial: hwSelectedFb}).then(function(data) {
            msg.textContent = data.output || (data.success ? 'OEM Unlock sent' : 'Failed');
        });
    }
}

// ── Serial / ESP32 (mode-aware) ──

function hwRefreshSerialPorts() {
    if (hwConnectionMode === 'direct') return;
    fetchJSON('/hardware/serial/ports').then(function(data) {
        var ports = data.ports || [];
        var container = document.getElementById('hw-serial-ports');
        if (container) {
            if (ports.length === 0) {
                container.innerHTML = '<div class="empty-state">No serial ports detected</div>';
            } else {
                var html = '<table class="data-table"><thead><tr><th>Port</th><th>Description</th><th>VID:PID</th><th>Manufacturer</th></tr></thead><tbody>';
                ports.forEach(function(p) {
                    var vidpid = (p.vid && p.pid) ? p.vid + ':' + p.pid : '';
                    html += '<tr><td><strong>' + escapeHtml(p.port) + '</strong></td>'
                        + '<td>' + escapeHtml(p.desc) + '</td>'
                        + '<td>' + escapeHtml(vidpid) + '</td>'
                        + '<td>' + escapeHtml(p.manufacturer || '') + '</td></tr>';
                });
                html += '</tbody></table>';
                container.innerHTML = html;
            }
        }
        ['hw-detect-port', 'hw-flash-port', 'hw-monitor-port'].forEach(function(id) {
            var sel = document.getElementById(id);
            if (!sel) return;
            var val = sel.value;
            sel.innerHTML = '<option value="">Select port...</option>';
            ports.forEach(function(p) {
                var opt = document.createElement('option');
                opt.value = p.port;
                opt.textContent = p.port + ' - ' + p.desc;
                sel.appendChild(opt);
            });
            if (val) sel.value = val;
        });
    });
}

function hwDetectChip() {
    if (hwConnectionMode === 'direct') {
        var msg = document.getElementById('hw-detect-result');
        msg.textContent = 'Connecting to chip...';
        var baud = parseInt(document.getElementById('hw-detect-baud').value || '115200');
        HWDirect.espConnect(baud).then(function(result) {
            msg.innerHTML = '<span style="color:var(--success)">Chip: ' + escapeHtml(result.chip) + '</span>';
        }).catch(function(e) {
            msg.innerHTML = '<span style="color:var(--danger)">' + escapeHtml(e.message) + '</span>';
        });
        return;
    }
    var port = document.getElementById('hw-detect-port').value;
    var baud = document.getElementById('hw-detect-baud').value;
    if (!port) { alert('Select a port'); return; }
    var result = document.getElementById('hw-detect-result');
    result.textContent = 'Detecting...';
    postJSON('/hardware/serial/detect', {port: port, baud: parseInt(baud)}).then(function(data) {
        if (data.success) {
            result.innerHTML = '<span style="color:var(--success)">Chip: ' + escapeHtml(data.chip) + '</span>'
                + (data.chip_id ? '<br>Chip ID: ' + escapeHtml(data.chip_id) : '');
        } else {
            result.innerHTML = '<span style="color:var(--danger)">' + escapeHtml(data.error || 'Detection failed') + '</span>';
        }
    });
}

function hwFlashEsp() {
    if (hwConnectionMode === 'direct') {
        var fileInput = document.getElementById('hw-flash-firmware-file');
        if (!fileInput.files.length) { alert('Select firmware file'); return; }
        if (!confirm('Flash firmware?')) return;

        var progDiv = document.getElementById('hw-esp-flash-progress');
        progDiv.style.display = 'block';
        document.getElementById('hw-esp-flash-fill').style.width = '0%';
        document.getElementById('hw-esp-flash-pct').textContent = '0%';
        document.getElementById('hw-esp-flash-msg').textContent = 'Reading file...';

        var address = parseInt(document.getElementById('hw-flash-address').value || '0', 16);
        var baud = parseInt(document.getElementById('hw-flash-baud-direct').value || '460800');

        HWDirect.readFileAsBytes(fileInput.files[0]).then(function(bytes) {
            // Connect if not already connected
            var connectPromise = HWDirect.espIsConnected() ? Promise.resolve() : HWDirect.espConnect(baud);
            return connectPromise.then(function() {
                document.getElementById('hw-esp-flash-msg').textContent = 'Flashing...';
                return HWDirect.espFlash(
                    [{ data: bytes, address: address }],
                    function(fileIndex, written, total) {
                        var pct = total > 0 ? Math.round((written / total) * 100) : 0;
                        document.getElementById('hw-esp-flash-fill').style.width = pct + '%';
                        document.getElementById('hw-esp-flash-pct').textContent = pct + '%';
                    }
                );
            });
        }).then(function() {
            document.getElementById('hw-esp-flash-msg').textContent = 'Flash complete';
            document.getElementById('hw-esp-flash-fill').style.width = '100%';
            document.getElementById('hw-esp-flash-pct').textContent = '100%';
        }).catch(function(e) {
            document.getElementById('hw-esp-flash-msg').textContent = 'Failed: ' + e.message;
        });
        return;
    }

    // Server mode
    var port = document.getElementById('hw-flash-port').value;
    var baud = document.getElementById('hw-flash-baud').value;
    var firmware = document.getElementById('hw-flash-firmware').value.trim();
    if (!port) { alert('Select a port'); return; }
    if (!firmware) { alert('Enter firmware file path'); return; }
    if (!confirm('Flash firmware to ' + port + '?')) return;

    var progDiv = document.getElementById('hw-esp-flash-progress');
    progDiv.style.display = 'block';
    document.getElementById('hw-esp-flash-fill').style.width = '0%';
    document.getElementById('hw-esp-flash-pct').textContent = '0%';
    document.getElementById('hw-esp-flash-msg').textContent = 'Starting...';

    postJSON('/hardware/serial/flash', {port: port, filepath: firmware, baud: parseInt(baud)}).then(function(data) {
        if (!data.success) {
            document.getElementById('hw-esp-flash-msg').textContent = data.error || 'Failed';
            return;
        }
        hwTrackProgress(data.op_id, 'hw-esp-flash-fill', 'hw-esp-flash-pct', 'hw-esp-flash-msg');
    });
}

function hwMonitorStart() {
    if (hwConnectionMode === 'direct') {
        var baud = parseInt(document.getElementById('hw-monitor-baud-direct').value || '115200');
        var output = document.getElementById('hw-monitor-output');
        HWDirect.espMonitorStart(baud, function(text) {
            output.textContent += text;
            output.scrollTop = output.scrollHeight;
        }).then(function() {
            document.getElementById('hw-monitor-start-btn').style.display = 'none';
            document.getElementById('hw-monitor-stop-btn').style.display = 'inline-block';
        }).catch(function(e) {
            alert('Monitor failed: ' + e.message);
        });
        return;
    }

    // Server mode
    var port = document.getElementById('hw-monitor-port').value;
    var baud = document.getElementById('hw-monitor-baud').value;
    if (!port) { alert('Select a port'); return; }
    postJSON('/hardware/serial/monitor/start', {port: port, baud: parseInt(baud)}).then(function(data) {
        if (!data.success) { alert(data.error || 'Failed to start monitor'); return; }
        document.getElementById('hw-monitor-start-btn').style.display = 'none';
        document.getElementById('hw-monitor-stop-btn').style.display = 'inline-block';
        hwMonitorStream();
    });
}

function hwMonitorStop() {
    if (hwConnectionMode === 'direct') {
        HWDirect.espMonitorStop();
        document.getElementById('hw-monitor-start-btn').style.display = 'inline-block';
        document.getElementById('hw-monitor-stop-btn').style.display = 'none';
        return;
    }
    if (hwMonitorES) { hwMonitorES.close(); hwMonitorES = null; }
    postJSON('/hardware/serial/monitor/stop', {}).then(function() {
        document.getElementById('hw-monitor-start-btn').style.display = 'inline-block';
        document.getElementById('hw-monitor-stop-btn').style.display = 'none';
    });
}

function hwMonitorStream() {
    if (hwMonitorES) hwMonitorES.close();
    hwMonitorES = new EventSource('/hardware/serial/monitor/stream');
    var output = document.getElementById('hw-monitor-output');
    hwMonitorES.onmessage = function(e) {
        var data = JSON.parse(e.data);
        if (data.type === 'data') {
            output.textContent += data.line + '\n';
            output.scrollTop = output.scrollHeight;
        } else if (data.type === 'stopped') {
            hwMonitorES.close();
            hwMonitorES = null;
            document.getElementById('hw-monitor-start-btn').style.display = 'inline-block';
            document.getElementById('hw-monitor-stop-btn').style.display = 'none';
        }
    };
    hwMonitorES.onerror = function() {
        hwMonitorES.close();
        hwMonitorES = null;
    };
}

function hwMonitorSend() {
    var input = document.getElementById('hw-monitor-input');
    var data = input.value;
    if (!data) return;

    if (hwConnectionMode === 'direct') {
        HWDirect.espMonitorSend(data);
    } else {
        postJSON('/hardware/serial/monitor/send', {data: data});
    }
    input.value = '';
}

function hwMonitorClear() {
    var output = document.getElementById('hw-monitor-output');
    if (output) output.textContent = '';
}

// ── Factory Flash (Direct mode, PixelFlasher PoC) ──

var hwFactoryZipFile = null;

function hwFactoryZipSelected(input) {
    if (!input.files.length) return;
    hwFactoryZipFile = input.files[0];
    var planDiv = document.getElementById('hw-factory-plan');
    var detailsDiv = document.getElementById('hw-factory-plan-details');
    var checkDiv = document.getElementById('hw-factory-device-check');

    detailsDiv.innerHTML = '<div class="progress-text">Reading ZIP file: ' + escapeHtml(hwFactoryZipFile.name) + ' (' + (hwFactoryZipFile.size / 1024 / 1024).toFixed(1) + ' MB)</div>';
    planDiv.style.display = 'block';

    // Check if fastboot device is connected
    if (HWDirect.fbIsConnected()) {
        HWDirect.fbGetInfo().then(function(info) {
            checkDiv.innerHTML = '<span style="color:var(--success)">Fastboot device connected: ' +
                escapeHtml(info.product || 'Unknown') + ' (unlocked: ' + escapeHtml(info.unlocked || '?') + ')</span>';
        });
    } else {
        checkDiv.innerHTML = '<span style="color:var(--warning)">No fastboot device connected. Connect one before flashing.</span>';
    }
}

async function hwFactoryFlash() {
    if (!hwFactoryZipFile) { alert('Select a factory image ZIP'); return; }
    if (!HWDirect.fbIsConnected()) { alert('Connect a fastboot device first'); return; }
    if (!confirm('Flash factory image? This may erase device data.')) return;

    var progressDiv = document.getElementById('hw-factory-progress');
    var logDiv = document.getElementById('hw-factory-log');
    progressDiv.style.display = 'block';
    logDiv.textContent = '';

    var skipUserdata = document.getElementById('hw-factory-skip-userdata').checked;

    function logMsg(text) {
        logDiv.textContent += text + '\n';
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    try {
        await HWDirect.fbFactoryFlash(hwFactoryZipFile, { wipeData: !skipUserdata }, function(status) {
            document.getElementById('hw-factory-msg').textContent = status.message || '';
            if (status.progress !== undefined) {
                var pct = Math.round(status.progress * 100);
                document.getElementById('hw-factory-fill').style.width = pct + '%';
                document.getElementById('hw-factory-pct').textContent = pct + '%';
            }
            logMsg('[' + (status.stage || '') + '] ' + (status.message || ''));
        });
        document.getElementById('hw-factory-msg').textContent = 'Factory flash complete';
        document.getElementById('hw-factory-fill').style.width = '100%';
        document.getElementById('hw-factory-pct').textContent = '100%';
    } catch (e) {
        document.getElementById('hw-factory-msg').textContent = 'Failed: ' + e.message;
        logMsg('ERROR: ' + e.message);
    }
}

// ── Agent Hal Global Chat Panel ──────────────────────────────────────────────

var halAgentMode = false;  // false = direct chat, true = agent mode

function halModeChanged(checkbox) {
    halAgentMode = checkbox.checked;
    var label = document.getElementById('hal-mode-label');
    if (label) label.textContent = halAgentMode ? 'Agent' : 'Chat';
}

function halToggle() {
    var p = document.getElementById('hal-panel');
    if (!p) return;
    var visible = p.style.display !== 'none';
    p.style.display = visible ? 'none' : 'flex';
    if (!visible) {
        var inp = document.getElementById('hal-input');
        if (inp) inp.focus();
    }
}

function halSend() {
    var inp = document.getElementById('hal-input');
    if (!inp) return;
    var msg = inp.value.trim();
    if (!msg) return;
    inp.value = '';
    inp.disabled = true;
    halAppend('user', msg);
    var container = document.getElementById('hal-messages');

    fetch('/api/chat', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({message: msg, mode: halAgentMode ? 'agent' : 'chat'})
    }).then(function(res) {
        var reader = res.body.getReader();
        var dec = new TextDecoder();
        var buf = '';
        function pump() {
            reader.read().then(function(chunk) {
                if (chunk.done) { inp.disabled = false; inp.focus(); return; }
                buf += dec.decode(chunk.value, {stream: true});
                var parts = buf.split('\n\n');
                buf = parts.pop();
                parts.forEach(function(part) {
                    var line = part.replace(/^data:\s*/, '').trim();
                    if (!line) return;
                    try {
                        var d = JSON.parse(line);
                        if (d.type === 'thought') {
                            halAppendStyled('thought', d.content);
                        } else if (d.type === 'action') {
                            halAppendStyled('action', d.content);
                        } else if (d.type === 'result') {
                            halAppendStyled('result', d.content);
                        } else if (d.type === 'answer') {
                            halAppendStyled('bot', d.content);
                        } else if (d.type === 'status') {
                            halAppendStyled('status', d.content);
                        } else if (d.type === 'error') {
                            halAppendStyled('error', d.content);
                        } else if (d.token) {
                            // Legacy streaming token mode
                            var last = container.lastElementChild;
                            if (!last || !last.classList.contains('hal-msg-bot')) {
                                last = halAppend('bot', '');
                            }
                            last.textContent += d.token;
                            halScroll();
                        } else if (d.done) {
                            inp.disabled = false;
                            inp.focus();
                        }
                    } catch(e) {}
                });
                pump();
            });
        }
        pump();
    }).catch(function(e) {
        halAppendStyled('error', e.message);
        inp.disabled = false;
    });
}

function halAppendStyled(type, text) {
    var msgs = document.getElementById('hal-messages');
    if (!msgs) return;
    var div = document.createElement('div');
    div.className = 'hal-msg hal-msg-' + type;
    if (type === 'thought') {
        div.style.cssText = 'font-style:italic;color:var(--text-muted,#888);font-size:0.8rem';
        div.textContent = text;
    } else if (type === 'action') {
        div.style.cssText = 'font-family:monospace;color:var(--accent,#0af);font-size:0.78rem;background:rgba(0,170,255,0.08);padding:4px 8px;border-radius:4px';
        div.textContent = '> ' + text;
    } else if (type === 'result') {
        div.style.cssText = 'font-family:monospace;color:var(--text-secondary,#aaa);font-size:0.75rem;max-height:100px;overflow-y:auto;white-space:pre-wrap;background:rgba(255,255,255,0.03);padding:4px 8px;border-radius:4px';
        div.textContent = text;
    } else if (type === 'status') {
        div.style.cssText = 'color:var(--text-muted,#666);font-size:0.78rem;font-style:italic';
        div.textContent = text;
    } else if (type === 'error') {
        div.style.cssText = 'color:var(--danger,#f55);font-size:0.82rem';
        div.textContent = 'Error: ' + text;
    } else {
        div.textContent = text;
    }
    msgs.appendChild(div);
    halScroll();
}

function halAppend(role, text) {
    var msgs = document.getElementById('hal-messages');
    if (!msgs) return null;
    var div = document.createElement('div');
    div.className = 'hal-msg hal-msg-' + role;
    div.textContent = text;
    msgs.appendChild(div);
    halScroll();
    return div;
}

function halScroll() {
    var m = document.getElementById('hal-messages');
    if (m) m.scrollTop = m.scrollHeight;
}

function halClear() {
    var m = document.getElementById('hal-messages');
    if (m) m.innerHTML = '';
    fetch('/api/chat/reset', {method: 'POST'}).catch(function() {});
}

// ── Debug Console ─────────────────────────────────────────────────────────────

var _dbgEs = null;
var _dbgMode = 'warn';
var _dbgMessages = [];
var _dbgMsgCount = 0;

// Level → display config
var _DBG_LEVELS = {
    DEBUG:    { cls: 'dbg-debug', sym: '▶' },
    INFO:     { cls: 'dbg-info',  sym: 'ℹ' },
    WARNING:  { cls: 'dbg-warn',  sym: '⚠' },
    ERROR:    { cls: 'dbg-err',   sym: '✕' },
    CRITICAL: { cls: 'dbg-crit',  sym: '☠' },
    STDOUT:   { cls: 'dbg-info',  sym: '»' },
    STDERR:   { cls: 'dbg-warn',  sym: '»' },
};

// Output-tagged logger names (treated as operational output in "Output Only" mode)
var _OUTPUT_LOGGERS = ['msf', 'agent', 'autarch', 'output', 'scanner', 'tools', 'print'];

function debugToggle(enabled) {
    fetch('/settings/debug/toggle', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enabled: enabled})
    }).catch(function() {});

    var btn = document.getElementById('debug-toggle-btn');
    if (btn) btn.style.display = enabled ? '' : 'none';
    localStorage.setItem('autarch_debug', enabled ? '1' : '0');

    if (enabled) {
        _dbgStartStream();
    } else {
        _dbgStopStream();
    }
}

function debugOpen() {
    var p = document.getElementById('debug-panel');
    if (!p) return;
    p.style.display = 'flex';
    if (!_dbgEs) _dbgStartStream();
}

function debugClose() {
    var p = document.getElementById('debug-panel');
    if (p) p.style.display = 'none';
}

function _dbgStartStream() {
    if (_dbgEs) return;
    _dbgEs = new EventSource('/settings/debug/stream');
    var dot = document.getElementById('debug-live-dot');
    if (dot) dot.classList.add('debug-live-active');

    _dbgEs.onmessage = function(e) {
        try {
            var d = JSON.parse(e.data);
            _dbgMessages.push(d);
            if (_dbgMessages.length > 5000) _dbgMessages.shift();
            _dbgRenderOne(d);
        } catch(err) {}
    };

    _dbgEs.onerror = function() {
        if (dot) dot.classList.remove('debug-live-active');
    };
}

function _dbgStopStream() {
    if (_dbgEs) { _dbgEs.close(); _dbgEs = null; }
    var dot = document.getElementById('debug-live-dot');
    if (dot) dot.classList.remove('debug-live-active');
}

function _dbgShouldShow(entry) {
    var lvl = (entry.level || '').toUpperCase();
    switch (_dbgMode) {
        case 'all':     return true;
        case 'debug':   return true;  // all levels, with symbols
        case 'verbose': return lvl !== 'DEBUG' && lvl !== 'NOTSET';
        case 'warn':    return lvl === 'WARNING' || lvl === 'ERROR' || lvl === 'CRITICAL';
        case 'output':
            var lvlO = (entry.level || '').toUpperCase();
            if (lvlO === 'STDOUT' || lvlO === 'STDERR') return true;
            var name = (entry.name || '').toLowerCase();
            return _OUTPUT_LOGGERS.some(function(pfx) { return name.indexOf(pfx) >= 0; });
    }
    return true;
}

function _dbgFormat(entry) {
    var lvl  = (entry.level || 'INFO').toUpperCase();
    var cfg  = _DBG_LEVELS[lvl] || {cls: '', sym: '·'};
    var ts   = new Date(entry.ts * 1000).toISOString().substr(11, 12);
    var sym  = (_dbgMode === 'debug' || _dbgMode === 'all') ? cfg.sym + ' ' : '';
    var name = _dbgMode === 'all' ? '[' + (entry.name || '') + '] ' : '';
    var text = ts + ' ' + sym + '[' + lvl.substr(0,4) + '] ' + name + (entry.raw || '');
    var exc  = (_dbgMode === 'all' && entry.exc) ? '\n' + entry.exc : '';
    return { cls: cfg.cls, text: text + exc };
}

function _dbgRenderOne(entry) {
    if (!_dbgShouldShow(entry)) return;
    var out = document.getElementById('debug-output');
    if (!out) return;
    var f = _dbgFormat(entry);
    var line = document.createElement('div');
    line.className = 'debug-line ' + f.cls;
    line.textContent = f.text;
    out.appendChild(line);

    // Auto-scroll only if near bottom (within 80px)
    if (out.scrollHeight - out.scrollTop - out.clientHeight < 80) {
        out.scrollTop = out.scrollHeight;
    }

    _dbgMsgCount++;
    var cnt = document.getElementById('debug-msg-count');
    if (cnt) cnt.textContent = _dbgMsgCount + ' msgs';
}

function _dbgRerender() {
    var out = document.getElementById('debug-output');
    if (!out) return;
    out.innerHTML = '';
    _dbgMsgCount = 0;
    var cnt = document.getElementById('debug-msg-count');
    if (cnt) cnt.textContent = '0 msgs';
    _dbgMessages.forEach(_dbgRenderOne);
}

function debugSetMode(chk) {
    // Mutually exclusive — uncheck all others
    document.querySelectorAll('input[name="dbg-mode"]').forEach(function(c) {
        c.checked = false;
    });
    chk.checked = true;
    _dbgMode = chk.value;
    _dbgRerender();
}

function debugClear() {
    _dbgMessages = [];
    _dbgMsgCount = 0;
    var out = document.getElementById('debug-output');
    if (out) out.innerHTML = '';
    var cnt = document.getElementById('debug-msg-count');
    if (cnt) cnt.textContent = '0 msgs';
    fetch('/settings/debug/clear', {method: 'POST'}).catch(function() {});
}

// Init debug panel on page load
(function _initDebug() {
    document.addEventListener('DOMContentLoaded', function() {
        var enabled = localStorage.getItem('autarch_debug') === '1';
        var btn = document.getElementById('debug-toggle-btn');
        var chk = document.getElementById('debug-enable-chk');
        if (btn) btn.style.display = enabled ? '' : 'none';
        if (chk) chk.checked = enabled;
        if (enabled) {
            // Re-enable backend capture (survives server restarts)
            fetch('/settings/debug/toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enabled: true})
            }).catch(function() {});
            _dbgStartStream();
        }

        // Make debug panel draggable
        var handle = document.getElementById('debug-drag-handle');
        var panel  = document.getElementById('debug-panel');
        if (handle && panel) {
            var dragging = false, ox = 0, oy = 0;
            handle.addEventListener('mousedown', function(e) {
                dragging = true;
                ox = e.clientX - panel.offsetLeft;
                oy = e.clientY - panel.offsetTop;
                e.preventDefault();
            });
            document.addEventListener('mousemove', function(e) {
                if (!dragging) return;
                panel.style.left   = (e.clientX - ox) + 'px';
                panel.style.top    = (e.clientY - oy) + 'px';
                panel.style.right  = 'auto';
                panel.style.bottom = 'auto';
            });
            document.addEventListener('mouseup', function() { dragging = false; });
        }
    });
}());
