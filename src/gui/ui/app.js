let allFindings = [];
let totalFindings = 0;
let term = null;
let currentLogDir = "";
let sourceFilter = "all";   // all | emba | custom | both
let splitView = false;      // EMBA vs Grep side-by-side
const splitVerdict = { emba: 'all', grep: 'all' };  // per-column TP/FP filter

// CVE module (v1, no AI)
let cveFindings = [];
let moduleView = "creds";   // creds | cve  (results-area switch)
let cveShowHidden = false;
let cveSort = 'sev-desc';   // sev-desc (JSON default: high->low) | sev-asc
const cveFilter = { av: 'all', sev: 'all', exp: 'all', type: 'all' };
const _SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function sortCveRows(rows) {
    if (cveSort !== 'sev-asc') return rows;   // default = the file's order
    return rows.slice().sort((a, b) => {
        const r = (_SEV_RANK[b.severity] ?? 5) - (_SEV_RANK[a.severity] ?? 5);  // least severe first
        if (r) return r;
        return ((b.kev ? 1 : 0) - (a.kev ? 1 : 0))
            || ((b.has_exploit ? 1 : 0) - (a.has_exploit ? 1 : 0))
            || ((a.cvss_score || 0) - (b.cvss_score || 0));
    });
}
// which module tabs to show even before their data lands - driven by the
// Modules checkboxes / the modules a running scan was started with.
let credsModuleWanted = true;
let cveModuleWanted = false;

function deriveSource(finding) {
    if (finding.source) return finding.source;
    const mods = finding.found_by_modules || (finding.module ? [finding.module] : []);
    const custom = mods.filter(m => String(m).startsWith("CUSTOM:"));
    if (custom.length === 0) return "emba";
    if (custom.length === mods.length) return "custom";
    return "both";
}

window.addEventListener('pywebviewready', async () => {
    fetchData();
    setupEventListeners();
    checkStatus();
    setInterval(checkStatus, 3000);
    // Seed the main-screen "CVE" module checkbox from the saved default.
    try {
        if (window.pywebview && window.pywebview.api && window.pywebview.api.get_ai_config) {
            const cfg = await window.pywebview.api.get_ai_config();
            const modCve = document.getElementById('modCve');
            if (modCve) modCve.checked = String(cfg.CVE_SCAN_ENABLED) === '1';
        }
    } catch (e) { /* non-fatal */ }
    const mc = document.getElementById('modCreds'), mv = document.getElementById('modCve');
    credsModuleWanted = mc ? mc.checked : true;
    cveModuleWanted = mv ? mv.checked : false;
    updateModuleSwitch();
});

setTimeout(() => {
    if (!window.pywebview) {
        const grid = document.getElementById('findingsGrid');
        if (grid) grid.innerHTML = '<div class="loading-state"><p style="color: var(--danger)">PyWebView not detected. Please launch the UI with: bash scripts/start_linux.sh</p></div>';
    }
}, 2000);

async function fetchData() {
    try {
        if (!window.pywebview || !window.pywebview.api) {
            throw new Error('PyWebView API not available.');
        }
        
        // Only ever show results from a scan started in THIS session
        // (currentLogDir is set by start_scan). Merely selecting a log directory
        // must NOT surface a previous run's lava_out_* sibling - that is a
        // different scan even if the CVE side is deterministic.
        const logDir = currentLogDir;

        if (!logDir) {
            document.getElementById('findingsGrid').innerHTML =
                '<div class="loading-state"><p>Select an input and press <b>Start Scan</b> &mdash; or press <b>&#128194; Open Results</b> to load a previous scan\'s <code>lava_out_*</code> folder.</p></div>';
            allFindings = [];
            cveFindings = [];
            totalFindings = 0;
            updateSourceTabs();
            updateModuleSwitch();
            renderCve();
            updateStats();
            return;
        }

        const totalRes = await window.pywebview.api.get_total_findings(logDir);
        totalFindings = totalRes.total || 0;

        allFindings = await window.pywebview.api.get_verdicts(logDir);
        if (allFindings.error) {
            throw new Error(allFindings.error);
        }

        if (window.pywebview.api.get_cve_findings) {
            const cve = await window.pywebview.api.get_cve_findings(logDir);
            cveFindings = Array.isArray(cve) ? cve : [];
        }

        populateModuleFilter();
        updateSourceTabs();
        updateModuleSwitch();
        renderCve();
        updateStats();

        // Re-apply current filters instead of rendering all findings
        const activeFilterBtn = document.querySelector('.filter-btn.active');
        const verdictFilter = activeFilterBtn ? activeFilterBtn.dataset.filter : 'all';
        const searchInput = document.getElementById('searchInput');
        const searchTerm = searchInput ? searchInput.value : '';
        filterData(searchTerm, verdictFilter);
    } catch (error) {
        document.getElementById('findingsGrid').innerHTML = `
            <div class="loading-state">
                <p style="color: var(--danger)">Error loading verdicts.json. Make sure you launched the UI with: bash scripts/start_linux.sh</p>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function updateStats() {
    const elTotal = document.getElementById('stat-total');
    const elTp = document.getElementById('stat-tp');
    const elFp = document.getElementById('stat-fp');
    // right-hand stat card ("With Exploit" in CVE mode) hovers red, not green
    const statsC = document.querySelector('.stats-container');
    if (statsC) statsC.classList.toggle('cve-mode', moduleView === 'cve');
    const setLabels = (a, b, c) => {
        const L = document.querySelectorAll('.stat-card .stat-label');
        if (L[0]) L[0].textContent = a;
        if (L[1]) L[1].textContent = b;
        if (L[2]) L[2].textContent = c;
    };

    if (moduleView === 'cve') {
        const crit = cveFindings.filter(r => r.severity === 'critical' || r.severity === 'high').length;
        const exp = cveFindings.filter(r => r.has_exploit).length;
        setLabels('CVEs', 'High / Critical', 'With Exploit');
        if (elTotal) elTotal.querySelector('.stat-value').innerHTML = cveFindings.length;
        if (elTp) elTp.querySelector('.stat-value').innerHTML = crit;
        if (elFp) elFp.querySelector('.stat-value').innerHTML = exp;
        updateRawJsonView();
        return;
    }

    const total = allFindings.length;
    const tp = allFindings.filter(f => f.predicted_verdict === 'TP').length;
    const fp = allFindings.filter(f => f.predicted_verdict === 'FP').length;

    setLabels('Findings Processed', 'True Positives', 'False Positives');
    if (elTotal) {
        elTotal.querySelector('.stat-value').innerHTML =
            totalFindings > 0 ? `${total} / ${totalFindings}` : total;
    }
    if (elTp) elTp.querySelector('.stat-value').innerHTML = tp;
    if (elFp) elFp.querySelector('.stat-value').innerHTML = fp;

    // Also update raw JSON view if it's currently visible
    updateRawJsonView();
}

function populateModuleFilter() {
    const filter = document.getElementById('moduleFilter');
    if (!filter) return;

    filter.innerHTML = '<option value="all">All Modules</option>';

    const modules = new Set();
    allFindings.forEach(f => {
        const mods = (f.found_by_modules && Array.isArray(f.found_by_modules))
            ? f.found_by_modules : (f.module ? [f.module] : []);
        // The module sub-filter only makes sense for EMBA modules
        mods.filter(m => !String(m).startsWith("CUSTOM:")).forEach(m => modules.add(m));
    });

    Array.from(modules).sort().forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        filter.appendChild(opt);
    });
}

// A tab is a "seen by" SET, not a disjoint bucket:
//   EMBA    = found by an EMBA module (emba-only OR both)
//   Grep    = found by a custom rule  (custom-only OR both)
//   Overlap = found by both
function matchesSourceTab(f, tab) {
    if (tab === 'all') return true;
    const s = deriveSource(f);
    if (tab === 'emba')   return s === 'emba' || s === 'both';
    if (tab === 'custom') return s === 'custom' || s === 'both';
    if (tab === 'both')   return s === 'both';
    return true;
}

function updateSourceTabs() {
    const raw = { emba: 0, custom: 0, both: 0 };
    allFindings.forEach(f => { raw[deriveSource(f)] = (raw[deriveSource(f)] || 0) + 1; });
    const counts = {
        all: allFindings.length,
        emba: raw.emba + raw.both,
        custom: raw.custom + raw.both,
        both: raw.both,
    };

    const tabs = document.getElementById('sourceTabs');
    const hasCustom = raw.custom > 0 || raw.both > 0;
    if (tabs) tabs.classList.toggle('hidden', !hasCustom);
    if (!hasCustom && sourceFilter !== 'all') sourceFilter = 'all';

    // Split view only makes sense when there are two sources
    const splitToggle = document.getElementById('splitToggle');
    if (splitToggle) splitToggle.style.display = hasCustom ? '' : 'none';
    if (!hasCustom && splitView) { splitView = false; if (splitToggle) splitToggle.classList.remove('active'); }
    updateResultsVisibility();

    ['all', 'emba', 'custom', 'both'].forEach(s => {
        const el = document.getElementById('src-count-' + s);
        if (el) el.textContent = counts[s] || 0;
    });
    document.querySelectorAll('.source-tab').forEach(b => {
        b.classList.toggle('active', b.dataset.source === sourceFilter);
    });
    // Module sub-filter is only relevant for the EMBA view
    const modFilter = document.getElementById('moduleFilter');
    if (modFilter) modFilter.style.display = (sourceFilter === 'emba' || !hasCustom) ? '' : 'none';
}

function buildFindingCard(finding) {
    const isTP = finding.predicted_verdict === 'TP';
    const confPct = Math.round((finding.confidence || 0) * 100);

    const card = document.createElement('div');
    card.className = `finding-card verdict-${finding.predicted_verdict.toLowerCase()}`;

    const src = deriveSource(finding);
    const srcLabel = { emba: 'EMBA', custom: 'GREP', both: 'BOTH' }[src] || src;
    const category = (finding.category || '').trim();

    card.innerHTML = `
        <div class="card-top">
            <div class="card-titles">
                <div class="card-file">${escapeHtml(finding.file_path)}${finding.line_no ? ':' + finding.line_no : ''}</div>
                <div class="card-category">${escapeHtml(category)}</div>
            </div>
            <div class="card-chips">
                <span class="source-chip source-${src}">${srcLabel}</span>
                <span class="verdict-badge badge-${finding.predicted_verdict.toLowerCase()}">${finding.predicted_verdict}</span>
            </div>
        </div>
        <div class="snippet">${escapeHtml(finding.matched_content || '')}</div>
        <div class="card-footer">
            <span>Modules: ${(finding.found_by_modules || [finding.module || 'Unknown']).join(', ')}</span>
            <div class="confidence">
                <span>Conf: ${confPct}%</span>
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: ${confPct}%; background: ${isTP ? 'var(--danger)' : 'var(--success)'}"></div>
                </div>
            </div>
        </div>
    `;

    card.addEventListener('click', () => openModal(finding));
    return card;
}

function renderFindings(findings) {
    const grid = document.getElementById('findingsGrid');
    grid.innerHTML = '';
    findings.forEach(finding => grid.appendChild(buildFindingCard(finding)));
    if (findings.length === 0) {
        grid.innerHTML = '<div class="loading-state"><p>No findings match your criteria.</p></div>';
    }
}

// Split view: EMBA findings (emba + both) on the left, Grep findings (custom +
// both) on the right; global search applies, each column has its own TP/FP filter.
function renderSplitColumn(colKey, findings) {
    const body = document.getElementById(colKey === 'emba' ? 'splitBodyEmba' : 'splitBodyGrep');
    const countEl = document.getElementById(colKey === 'emba' ? 'split-count-emba' : 'split-count-grep');
    const want = colKey === 'emba' ? ['emba', 'both'] : ['custom', 'both'];
    const vf = splitVerdict[colKey];

    const rows = findings.filter(f => want.includes(deriveSource(f)))
                         .filter(f => vf === 'all' || f.predicted_verdict === vf);
    if (countEl) countEl.textContent = rows.length;

    body.innerHTML = '';
    rows.forEach(f => body.appendChild(buildFindingCard(f)));
    if (rows.length === 0) {
        body.innerHTML = '<div class="split-empty">No findings match.</div>';
    }
}

function renderSplit(searchFiltered) {
    renderSplitColumn('emba', searchFiltered);
    renderSplitColumn('grep', searchFiltered);
}

/* ============================== CVE module ============================== */
function updateModuleSwitch() {
    const sw = document.getElementById('moduleSwitch');
    // a view is "available" once its module has data OR is selected for this scan
    const showCve = cveFindings.length > 0 || cveModuleWanted;
    const showCreds = allFindings.length > 0 || credsModuleWanted;

    // the switch only makes sense when there are two views to switch between
    if (sw) sw.classList.toggle('hidden', !(showCve && showCreds));
    const msc = document.getElementById('ms-creds');
    const msv = document.getElementById('ms-cve');
    if (msc) msc.textContent = allFindings.length;
    if (msv) msv.textContent = cveFindings.length;

    if (!showCve && moduleView === 'cve') setModuleView('creds');
    if (!showCreds && showCve && moduleView === 'creds') setModuleView('cve');
}

function setModuleView(view) {
    moduleView = view;
    document.getElementById('credsView').classList.toggle('hidden', view !== 'creds');
    document.getElementById('cveView').classList.toggle('hidden', view !== 'cve');
    document.querySelectorAll('.mod-switch-btn').forEach(b =>
        b.classList.toggle('active', b.dataset.view === view));
    updateStats();
    if (view === 'cve') renderCve();
}

function cveMatches(r, term) {
    if (term && !((r.cve || '').toLowerCase().includes(term) ||
                  (r.component || '').toLowerCase().includes(term) ||
                  (r.description || '').toLowerCase().includes(term))) return false;
    if (!cveShowHidden && r.default_hidden) return false;
    if (cveFilter.av !== 'all' && r.av !== cveFilter.av) return false;
    if (cveFilter.sev !== 'all' && r.severity !== cveFilter.sev) return false;
    if (cveFilter.exp === 'exploit' && !r.has_exploit) return false;
    if (cveFilter.exp === 'kev' && !r.kev) return false;
    if (cveFilter.type === '__unclassified__' && (r.vuln_type || '') !== '') return false;
    if (cveFilter.type !== 'all' && cveFilter.type !== '__unclassified__' && r.vuln_type !== cveFilter.type) return false;
    return true;
}

function buildCveCard(r) {
    const card = document.createElement('div');
    card.className = `finding-card cve-card sev-${r.severity || 'unknown'}`;
    const chips = [];
    if (r.av && r.av !== 'Unknown') {
        chips.push(`<span class="cve-chip chip-av">${escapeHtml(r.av === 'Network' ? 'NET' : r.av.slice(0, 3).toUpperCase())}</span>`);
    }
    if (r.kev) chips.push('<span class="cve-chip chip-kev">KEV</span>');
    else if (r.has_exploit) chips.push('<span class="cve-chip chip-exploit">EXPLOIT</span>');
    if (r.verified) chips.push('<span class="cve-chip chip-verified">VERIFIED</span>');
    chips.push(`<span class="verdict-badge sev-badge sev-${r.severity || 'unknown'}">${escapeHtml((r.severity || '?').toUpperCase())}</span>`);
    const score = (r.cvss_score != null) ? r.cvss_score.toFixed(1) : '--';
    const vt = (r.vuln_type || '').trim();

    card.innerHTML = `
        <div class="card-top">
            <div class="card-titles">
                <div class="card-file">${escapeHtml(r.component)} ${escapeHtml(r.version || '')}</div>
                <div class="card-category">${escapeHtml(r.cve)}</div>
            </div>
            <div class="card-chips">${chips.join('')}</div>
        </div>
        ${vt ? `<div class="cve-type-line">${escapeHtml(vt)}</div>` : ''}
        <div class="snippet cve-desc">${escapeHtml(r.description || '(no description)')}</div>
        <div class="card-footer">
            <span>${escapeHtml(r.av || '?')} &middot; ${escapeHtml(r.cvss_vector || 'no vector')}</span>
            <span>CVSS ${score}</span>
        </div>
    `;
    card.addEventListener('click', () => openCveModal(r));
    return card;
}

function renderCve() {
    const grid = document.getElementById('cveGrid');
    if (!grid) return;
    const term = (document.getElementById('cveSearch')?.value || '').toLowerCase();
    const rows = sortCveRows(cveFindings.filter(r => cveMatches(r, term)));
    grid.innerHTML = '';
    rows.forEach(r => grid.appendChild(buildCveCard(r)));
    if (!rows.length) {
        const msg = cveFindings.length === 0
            ? 'CVE results will appear here once the scan reaches the CVE step (it runs before the AI classification).'
            : 'No CVEs match your criteria.';
        grid.innerHTML = `<div class="loading-state"><p>${msg}</p></div>`;
    }

    const hidden = cveFindings.filter(r => r.default_hidden).length;
    const note = document.getElementById('cveNote');
    if (note) {
        note.textContent = `${rows.length} shown` +
            ((!cveShowHidden && hidden) ? `  ·  ${hidden} lower-severity kernel CVEs hidden` : '');
    }
}

function openCveModal(r) {
    document.getElementById('modalTitle').textContent = r.cve;
    const im = r.impact || {};
    const badges = [
        `<span class="verdict-badge sev-badge sev-${r.severity || 'unknown'}">${escapeHtml((r.severity || '?').toUpperCase())}</span>`,
        `<span class="verdict-badge" style="border:1px solid var(--glass-border);color:var(--text-secondary)">CVSS ${r.cvss_score != null ? r.cvss_score : '--'} (v${escapeHtml(r.cvss_version || '?')})</span>`,
        `<span class="verdict-badge" style="border:1px solid var(--glass-border);color:var(--text-secondary)">${escapeHtml(r.component)} ${escapeHtml(r.version || '')}</span>`,
        `<span class="verdict-badge" style="border:1px solid var(--glass-border);color:var(--text-secondary)">${r.source_module === 'S26' ? 'kernel (S26)' : 'component (F17)'}</span>`,
    ];
    if (r.vuln_type) badges.push(`<span class="verdict-badge" style="border:1px solid var(--border-color);color:var(--text-secondary)">${escapeHtml(r.vuln_type)}</span>`);
    if (r.kev) badges.push('<span class="cve-chip chip-kev">KNOWN-EXPLOITED</span>');
    if (r.verified) badges.push(`<span class="cve-chip chip-verified">kernel-verified: ${escapeHtml(r.verified)}</span>`);
    document.getElementById('modalBadges').innerHTML = badges.join(' ');

    document.getElementById('modalCredsBody').classList.add('hidden');
    const body = document.getElementById('modalCveBody');
    body.classList.remove('hidden');
    const exploits = (r.exploit_sources && r.exploit_sources.length)
        ? escapeHtml(r.exploit_sources.join('\n'))
        : 'No exploit or PoC referenced by EMBA.';
    body.innerHTML = `
        <h3>Description</h3>
        <div class="reasoning-box">${escapeHtml(r.description || '(none)')}</div>
        <h3>CVSS vector</h3>
        <div class="cve-kv">
            <b>Attack vector</b><span>${escapeHtml(r.av || '?')}</span>
            <b>Attack complexity</b><span>${escapeHtml(r.ac || '?')}</span>
            <b>Privileges required</b><span>${escapeHtml(r.pr || 'n/a')}</span>
            <b>User interaction</b><span>${escapeHtml(r.ui || 'n/a')}</span>
            <b>Impact C/I/A</b><span>${escapeHtml(im.c || '?')} / ${escapeHtml(im.i || '?')} / ${escapeHtml(im.a || '?')}</span>
            <b>Raw</b><span>${escapeHtml(r.cvss_vector || '(none)')}</span>
        </div>
        <h3>Exploit / PoC</h3>
        <pre><code>${exploits}</code></pre>
        ${(r.cwe && r.cwe.length) ? '<h3>CWE</h3><pre><code>' + escapeHtml(r.cwe.map(c => 'CWE-' + c).join(', ')) + '</code></pre>' : ''}
    `;
    document.getElementById('modalOverlay').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function setupEventListeners() {
    // Scan Controls
    const startBtn = document.getElementById('startScanBtn');
    const stopBtn = document.getElementById('stopScanBtn');
    const browseBtn = document.getElementById('browseBtn');
    const exportBtn = document.getElementById('exportHtmlBtn');
    const showTerminalBtn = document.getElementById('showTerminalBtn');

    
    if (startBtn) startBtn.addEventListener('click', startScan);
    if (stopBtn) stopBtn.addEventListener('click', stopScan);
    if (browseBtn) browseBtn.addEventListener('click', browseFolder);
    if (exportBtn) exportBtn.addEventListener('click', exportHtml);
    const openResultsBtn = document.getElementById('openResultsBtn');
    if (openResultsBtn) openResultsBtn.addEventListener('click', openPastResults);
    


    // Settings Modal (left nav + panels)
    const settingsBtn = document.getElementById('settingsBtn');
    const settingsModal = document.getElementById('settingsModal');
    const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const aiProviderSelect = document.getElementById('aiProviderSelect');
    const geminiKeyContainer = document.getElementById('geminiKeyContainer');
    const geminiKeyInput = document.getElementById('geminiKeyInput');
    const customGrepEnabled = document.getElementById('customGrepEnabled');
    const scanProfileSelect = document.getElementById('scanProfileSelect');
    const grepProfileContainer = document.getElementById('grepProfileContainer');
    const s99ScanSelect = document.getElementById('s99ScanSelect');
    const mcpBatchSizeInput = document.getElementById('mcpBatchSizeInput');
    const embaScanProfileSelect = document.getElementById('embaScanProfileSelect');
    const embaPathInput = document.getElementById('embaPathInput');

    function updateProviderVisibility(value) {
        if (geminiKeyContainer) geminiKeyContainer.style.display = value === 'gemini' ? 'block' : 'none';
        const mcpInfo = document.getElementById('mcpInfo');
        if (mcpInfo) mcpInfo.style.display = (value && value.indexOf('mcp') === 0) ? 'block' : 'none';
    }
    function updateGrepVisibility() {
        if (grepProfileContainer)
            grepProfileContainer.style.opacity = customGrepEnabled && customGrepEnabled.checked ? '1' : '0.45';
    }

    if (settingsBtn) {
        settingsBtn.addEventListener('click', async () => {
            if (window.pywebview && window.pywebview.api.get_ai_config) {
                const config = await window.pywebview.api.get_ai_config();
                aiProviderSelect.value = config.AI_PROVIDER || 'local';
                geminiKeyInput.value = config.GEMINI_API_KEY || '';
                if (customGrepEnabled) customGrepEnabled.checked = String(config.CUSTOM_GREP_ENABLED) === '1';
                if (scanProfileSelect && window.pywebview.api.list_scan_profiles) {
                    const profiles = await window.pywebview.api.list_scan_profiles();
                    scanProfileSelect.innerHTML = '';
                    (profiles || ['iot-testing']).forEach(p => {
                        const o = document.createElement('option');
                        o.value = p; o.textContent = p;
                        scanProfileSelect.appendChild(o);
                    });
                    scanProfileSelect.value = config.SCAN_PROFILE || 'iot-testing';
                }
                if (s99ScanSelect) {
                    const aliases = { narrow: 'light', broad: 'light', strict: 'light', gated: 'light' };
                    s99ScanSelect.value = aliases[config.S99_SCAN] || config.S99_SCAN || 'raw';
                }
                if (mcpBatchSizeInput) mcpBatchSizeInput.value = (config.MCP_BATCH_SIZE ?? '40');
                if (embaScanProfileSelect) embaScanProfileSelect.value = config.EMBA_SCAN_PROFILE || 'auto';
                if (embaPathInput) embaPathInput.value = config.EMBA_PATH || '';
                updateProviderVisibility(aiProviderSelect.value);
                updateGrepVisibility();
            }
            settingsModal.classList.remove('hidden');
        });
    }

    document.querySelectorAll('.settings-nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.settings-nav-item').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.settings-panel').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const panel = document.getElementById('panel-' + btn.dataset.panel);
            if (panel) panel.classList.add('active');
        });
    });

    if (cancelSettingsBtn) {
        cancelSettingsBtn.addEventListener('click', () => settingsModal.classList.add('hidden'));
    }
    if (settingsModal) {
        settingsModal.addEventListener('click', (e) => {
            if (e.target.id === 'settingsModal') settingsModal.classList.add('hidden');
        });
    }
    if (aiProviderSelect) {
        aiProviderSelect.addEventListener('change', (e) => updateProviderVisibility(e.target.value));
    }
    if (customGrepEnabled) {
        customGrepEnabled.addEventListener('change', updateGrepVisibility);
    }

    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', async () => {
            if (window.pywebview && window.pywebview.api.save_ai_config) {
                await window.pywebview.api.save_ai_config({
                    "AI_PROVIDER": aiProviderSelect.value,
                    "GEMINI_API_KEY": geminiKeyInput.value,
                    "CUSTOM_GREP_ENABLED": (customGrepEnabled && customGrepEnabled.checked) ? "1" : "0",
                    "SCAN_PROFILE": scanProfileSelect ? scanProfileSelect.value : "iot-testing",
                    "S99_SCAN": s99ScanSelect ? s99ScanSelect.value : "raw",
                    "MCP_BATCH_SIZE": mcpBatchSizeInput ? String(parseInt(mcpBatchSizeInput.value, 10) || 0) : "40",
                    "EMBA_SCAN_PROFILE": embaScanProfileSelect ? embaScanProfileSelect.value : "auto",
                    "EMBA_PATH": embaPathInput ? embaPathInput.value.trim() : ""
                });
            }
            settingsModal.classList.add('hidden');
        });
    }

    // Source tabs (EMBA / Grep / overlap)
    document.querySelectorAll('.source-tab').forEach(btn => {
        btn.addEventListener('click', () => {
            sourceFilter = btn.dataset.source;
            document.querySelectorAll('.source-tab').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            const modFilter = document.getElementById('moduleFilter');
            if (modFilter) modFilter.style.display = sourceFilter === 'emba' ? '' : 'none';
            reapplyFilters();
        });
    });

    // Split view toggle
    const splitToggle = document.getElementById('splitToggle');
    if (splitToggle) splitToggle.addEventListener('click', () => setSplitView(!splitView));

    // Module chips: ticking one shows its results tab right away (even before a
    // scan), and the CVE choice persists to CVE_SCAN_ENABLED.
    const modCredsChip = document.getElementById('modCreds');
    const modCveChip = document.getElementById('modCve');
    if (modCredsChip) modCredsChip.addEventListener('change', () => {
        credsModuleWanted = modCredsChip.checked;
        updateModuleSwitch();
    });
    if (modCveChip) modCveChip.addEventListener('change', () => {
        cveModuleWanted = modCveChip.checked;
        updateModuleSwitch();
        if (window.pywebview && window.pywebview.api && window.pywebview.api.save_ai_config) {
            window.pywebview.api.save_ai_config({ "CVE_SCAN_ENABLED": modCveChip.checked ? "1" : "0" });
        }
    });

    // Module switch (Credentials / CVE)
    document.querySelectorAll('.mod-switch-btn').forEach(btn => {
        btn.addEventListener('click', () => setModuleView(btn.dataset.view));
    });
    const cveSearch = document.getElementById('cveSearch');
    if (cveSearch) cveSearch.addEventListener('input', renderCve);
    document.querySelectorAll('.cve-filter-btn[data-k]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll(`.cve-filter-btn[data-k="${btn.dataset.k}"]`)
                .forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            cveFilter[btn.dataset.k] = btn.dataset.v;
            renderCve();
        });
    });
    const cveTypeSelect = document.getElementById('cveTypeSelect');
    if (cveTypeSelect) cveTypeSelect.addEventListener('change', () => {
        cveFilter.type = cveTypeSelect.value; renderCve();
    });
    const cveSortSelect = document.getElementById('cveSortSelect');
    if (cveSortSelect) cveSortSelect.addEventListener('change', () => {
        cveSort = cveSortSelect.value; renderCve();
    });
    const cveShowAllBtn = document.getElementById('cveShowAll');
    if (cveShowAllBtn) cveShowAllBtn.addEventListener('click', () => {
        cveShowHidden = !cveShowHidden;
        cveShowAllBtn.classList.toggle('active', cveShowHidden);
        cveShowAllBtn.textContent = cveShowHidden ? 'Hide lower-severity kernel CVEs' : 'Show hidden kernel CVEs';
        renderCve();
    });
    const exportCveBtn = document.getElementById('exportHtmlBtnCve');
    if (exportCveBtn) exportCveBtn.addEventListener('click', exportHtml);

    // Per-column TP/FP filters inside the split view
    document.querySelectorAll('.split-mini-filters').forEach(group => {
        const col = group.dataset.col; // 'emba' | 'grep'
        group.querySelectorAll('.mini-filter').forEach(btn => {
            btn.addEventListener('click', () => {
                group.querySelectorAll('.mini-filter').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                splitVerdict[col] = btn.dataset.filter;
                reapplyFilters();
            });
        });
    });

    let logInterval = null;

    if (showTerminalBtn) {
        showTerminalBtn.addEventListener('click', async () => {
            const terminalView = document.getElementById('terminalView');
            if (terminalView) {
                if (terminalView.classList.contains('hidden')) {
                    terminalView.classList.remove('hidden');
                    
                    // Initialize Xterm if it doesn't exist
                    if (!term) {
                        const tc = document.getElementById('terminalContent');
                        term = new Terminal({
                            theme: { background: '#000000' },
                            fontFamily: "'Consolas', 'Courier New', monospace",
                            fontSize: 13,
                            convertEol: true,
                            scrollback: 9999
                        });
                        
                        const fitAddon = new FitAddon.FitAddon();
                        term.loadAddon(fitAddon);
                        term.open(tc);
                        fitAddon.fit();
                        
                        // Prevent scroll chaining explicitly for xterm.js
                        tc.addEventListener('wheel', (e) => {
                            const viewport = tc.querySelector('.xterm-viewport');
                            if (viewport) {
                                const atTop = viewport.scrollTop === 0;
                                // Math.ceil for fractional scrollTop issues on some displays
                                const atBottom = Math.ceil(viewport.scrollTop + viewport.clientHeight) >= viewport.scrollHeight;
                                
                                if ((atTop && e.deltaY < 0) || (atBottom && e.deltaY > 0)) {
                                    e.preventDefault();
                                }
                            }
                        }, { passive: false });
                        
                        // Resize handling
                        const resizePty = () => {
                            fitAddon.fit();
                            
                            // Keep the column width at a minimum of 160 for EMBA; show a horizontal scrollbar if it does not fit
                            const cols = Math.max(term.cols, 160);
                            term.resize(cols, term.rows);
                            
                            // Force xterm viewport to handle horizontal overflow
                            const viewport = tc.querySelector('.xterm-viewport');
                            if (viewport) {
                                viewport.style.overflowX = 'auto';
                            }
                            const screen = tc.querySelector('.xterm-screen');
                            if (screen) {
                                screen.style.width = '100%';
                            }
                            
                            console.log(`[xterm.js] Terminal resized: ${term.rows} rows, ${cols} cols`);
                            
                            if (window.pywebview && window.pywebview.api.resize_pty) {
                                window.pywebview.api.resize_pty(term.rows, cols);
                            }
                        };
                        
                        window.addEventListener('resize', () => {
                            if (!terminalView.classList.contains('hidden')) {
                                resizePty();
                            }
                        });
                        
                        setTimeout(resizePty, 200); 
                    }
                    
                    // Start fetching logs
                    if (!logInterval) {
                        logInterval = setInterval(async () => {
                            if (window.pywebview && window.pywebview.api.get_scan_logs) {
                                const res = await window.pywebview.api.get_scan_logs(lastLogOffset);
                                if (res && res.data) {
                                    const binary = atob(res.data);
                                    const bytes = new Uint8Array(binary.length);
                                    for (let i = 0; i < binary.length; i++) {
                                        bytes[i] = binary.charCodeAt(i);
                                    }
                                    term.write(bytes);
                                    lastLogOffset = res.offset;
                                } else if (res && res.offset < lastLogOffset) {
                                    // Log file was truncated/restarted
                                    term.clear();
                                    lastLogOffset = 0;
                                }
                            }
                        }, 500); // 500ms for smooth TUI updates
                    }
                } else {
                    terminalView.classList.add('hidden');
                    if (logInterval) {
                        clearInterval(logInterval);
                        logInterval = null;
                    }
                }
            }
        });
    }
    document.querySelectorAll('input[name="scanMode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const input = document.getElementById('logDirInput');
            if (e.target.value === 'firmware') {
                input.placeholder = "Enter Firmware File Path (e.g. firmware.bin)";
            } else {
                input.placeholder = "Enter EMBA Log Directory (e.g. emba_firmware_log)";
            }
            input.value = "";
        });
    });

    // Search
    document.getElementById('searchInput').addEventListener('input', (e) => {
        filterData(e.target.value, document.querySelector('.filter-btn.active').dataset.filter);
    });

    // Filters
    const modFilter = document.getElementById('moduleFilter');
    if (modFilter) {
        modFilter.addEventListener('change', () => {
            const verdictFilter = document.querySelector('.filter-btn.active').dataset.filter;
            filterData(document.getElementById('searchInput').value, verdictFilter);
        });
    }

    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            e.target.classList.add('active');
            filterData(document.getElementById('searchInput').value, e.target.dataset.filter);
        });
    });

    // Modal Close
    const closeBtn = document.getElementById('closeModal');
    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    
    const overlay = document.getElementById('modalOverlay');
    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target.id === 'modalOverlay') closeModal();
        });
    }
    
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });

    // View Toggles
    const toggleBtn = document.getElementById('toggleViewBtn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const rawView = document.getElementById('rawJsonView');
            const showRaw = rawView.classList.contains('hidden');
            rawView.classList.toggle('hidden', !showRaw);
            toggleBtn.textContent = showRaw ? '⊞ View Cards' : '{} View Raw JSON';
            if (showRaw) updateRawJsonView();
            updateResultsVisibility();
        });
    }
}

function updateRawJsonView() {
    const rawContent = document.getElementById('rawJsonContent');
    if (rawContent && !document.getElementById('rawJsonView').classList.contains('hidden')) {
        rawContent.textContent = JSON.stringify(allFindings, null, 4);
    }
}

function filterData(searchTerm, verdictFilter) {
    const term = (searchTerm || '').toLowerCase();
    const matchesSearch = f => (f.file_path || '').toLowerCase().includes(term) ||
                               (f.matched_content || '').toLowerCase().includes(term);

    if (splitView) {
        // Split mode: only the global search applies here; each column owns its
        // own TP/FP filter, and source/module filters are hidden.
        renderSplit(allFindings.filter(matchesSearch));
        return;
    }

    let modFilterVal = 'all';
    const modFilter = document.getElementById('moduleFilter');
    if (modFilter) {
        modFilterVal = modFilter.value;
    }

    const filtered = allFindings.filter(f => {
        const matchesVerdict = verdictFilter === 'all' || f.predicted_verdict === verdictFilter;

        const mods = f.found_by_modules || (f.module ? [f.module] : []);
        const matchesModule = modFilterVal === 'all' || mods.includes(modFilterVal);

        return matchesSearch(f) && matchesVerdict && matchesModule && matchesSourceTab(f, sourceFilter);
    });

    renderFindings(filtered);
}

function currentVerdictFilter() {
    const b = document.querySelector('.filter-btn.active');
    return b ? b.dataset.filter : 'all';
}

function reapplyFilters() {
    const s = document.getElementById('searchInput');
    filterData(s ? s.value : '', currentVerdictFilter());
}

// Show grid / split / raw depending on state. Raw JSON view wins when open.
function updateResultsVisibility() {
    const grid = document.getElementById('findingsGrid');
    const split = document.getElementById('splitView');
    const raw = document.getElementById('rawJsonView');
    const rawOpen = raw && !raw.classList.contains('hidden');

    if (grid) grid.classList.toggle('hidden', rawOpen || splitView);
    if (split) split.classList.toggle('hidden', rawOpen || !splitView);

    // In split mode the rail's global source/verdict filters are replaced by
    // the per-column filters living inside the split view.
    const rail = document.getElementById('credsRail');
    if (rail) rail.classList.toggle('split-mode', splitView);
}

function setSplitView(on) {
    splitView = on;
    const btn = document.getElementById('splitToggle');
    if (btn) btn.classList.toggle('active', on);
    updateResultsVisibility();
    reapplyFilters();
}

function openModal(finding) {
    // restore the credentials modal body (CVE modal reuses the same overlay)
    document.getElementById('modalCredsBody').classList.remove('hidden');
    document.getElementById('modalCveBody').classList.add('hidden');

    const category = (finding.category || '').trim();
    document.getElementById('modalTitle').textContent = category || finding.file_path;

    const isTP = finding.predicted_verdict === 'TP';
    const src = deriveSource(finding);
    const srcLabel = { emba: 'Source: EMBA', custom: 'Source: Custom grep', both: 'Source: EMBA + Custom grep' }[src] || src;
    const fileChip = `<span class="verdict-badge" style="border: 1px solid var(--glass-border); color: var(--text-secondary)">${escapeHtml(finding.file_path)}${finding.line_no ? ':' + finding.line_no : ''}</span>`;
    const badgesHtml = `
        <span class="verdict-badge badge-${finding.predicted_verdict.toLowerCase()}">${finding.predicted_verdict}</span>
        <span class="source-chip source-${src}">${srcLabel}</span>
        ${category ? fileChip : ''}
        <span class="verdict-badge" style="border: 1px solid var(--glass-border); color: var(--text-secondary)">Corroboration: ${finding.corroboration_count}</span>
    `;

    document.getElementById('modalBadges').innerHTML = badgesHtml;
    document.getElementById('modalContent').textContent = finding.matched_content || 'No content available';
    document.getElementById('modalReasoning').textContent = finding.model_reasoning || 'No reasoning provided by AI.';
    
    document.getElementById('modalOverlay').classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal() {
    document.getElementById('modalOverlay').classList.remove('active');
    document.body.style.overflow = 'auto';
}

// Helpers
function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}

// Enable/disable the scan-config inputs (module chips, mode segments) as a set.
function setScanConfigDisabled(disabled) {
    ['modCreds', 'modCve'].forEach(id => {
        const el = document.getElementById(id);
        if (el) { el.disabled = disabled; el.closest('.toggle-chip')?.classList.toggle('is-disabled', disabled); }
    });
    document.querySelectorAll('input[name="scanMode"]').forEach(r => {
        r.disabled = disabled;
        r.closest('.segment')?.classList.toggle('is-disabled', disabled);
    });
}

// Scan Control API Calls
async function checkStatus() {
    if (!window.pywebview || !window.pywebview.api) return;
    try {
        const data = await window.pywebview.api.get_status();
        const indicator = document.getElementById('scanStatusIndicator');
        const startBtn = document.getElementById('startScanBtn');
        const stopBtn = document.getElementById('stopScanBtn');
        const logInput = document.getElementById('logDirInput');

        if (!indicator) return;

        if (data.running) {
            indicator.textContent = 'RUNNING...';
            indicator.className = 'status-indicator status-running';
            startBtn.disabled = true;
            stopBtn.disabled = false;
            logInput.disabled = true;
            setScanConfigDisabled(true);
            ['browseBtn', 'openResultsBtn'].forEach(id => {
                const el = document.getElementById(id); if (el) el.disabled = true;
            });

            // Fetch live data while running
            fetchData();
        } else {
            // If it was running and now it's not, refresh one last time
            if (indicator.textContent === 'RUNNING...') {
                fetchData();
                if (data.exit_code === 0) {
                    alert("Scan completed successfully!");
                } else if (data.exit_code !== null && data.exit_code !== undefined && data.exit_code !== 143 && data.exit_code !== 130) { // 143=SIGTERM, 130=SIGINT on stop, mostly ignore
                    alert("Scan failed or was stopped (exit code: " + data.exit_code + "). Check ~/.cache/lava/last_scan.log or the Terminal view for details.");
                }
            }
            indicator.textContent = 'IDLE';
            indicator.className = 'status-indicator status-idle';
            startBtn.disabled = false;
            stopBtn.disabled = true;
            logInput.disabled = false;
            setScanConfigDisabled(false);
            ['browseBtn', 'openResultsBtn'].forEach(id => {
                const el = document.getElementById(id); if (el) el.disabled = false;
            });
        }
    } catch(e) {
        console.error("Status check failed", e);
    }
}

// Open a previous run's output folder (lava_out_* / lava_scan_*) in the
// dashboard, for reviewing a past scan without re-running or opening the HTML.
async function openPastResults() {
    if (!window.pywebview || !window.pywebview.api || !window.pywebview.api.load_results) {
        alert("Opening past results is only available in the LAVA desktop app.");
        return;
    }
    try {
        const folder = await window.pywebview.api.open_folder_dialog();
        if (!folder) return;
        const res = await window.pywebview.api.load_results(folder);
        if (res.status === 'error') { alert(res.message); return; }
        document.getElementById('logDirInput').value = folder;
        currentLogDir = folder;   // fetchData() targets this folder's outputs
        await fetchData();
        const grid = document.getElementById('findingsGrid');
        if (!allFindings.length && !cveFindings.length && grid) {
            grid.innerHTML = '<div class="loading-state"><p>That folder had no findings.</p></div>';
        }
    } catch (e) {
        alert("Could not open results: " + e.message);
    }
}

async function browseFolder() {
    if (window.pywebview && window.pywebview.api) {
        try {
            const mode = document.querySelector('input[name="scanMode"]:checked').value;
            let path = "";
            if (mode === 'firmware') {
                path = await window.pywebview.api.open_file_dialog();
            } else {
                path = await window.pywebview.api.open_folder_dialog();
            }
            if (path) {
                document.getElementById('logDirInput').value = path;
                currentLogDir = "";
                // Do NOT load anything yet - picking a path is not a scan.
                fetchData();   // clears the grid to the "press Start Scan" state
            }
        } catch (e) {
            console.error("Folder selection failed:", e);
        }
    } else {
        alert("Native file browser is only available in the LAVA Desktop App (bash scripts/start_linux.sh).");
    }
}

// Editing the path by hand is not a scan either - drop the session's scan
// binding and clear any results that are still on screen.
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('logDirInput');
    if (input) {
        input.addEventListener('input', () => {
            if (currentLogDir) { currentLogDir = ""; fetchData(); }
        });
    }
});

async function startScan() {
    const inputPath = document.getElementById('logDirInput').value.trim();
    const mode = document.querySelector('input[name="scanMode"]:checked').value;

    if (!inputPath) {
        alert("Please enter a path first.");
        return;
    }

    const modules = [];
    if (document.getElementById('modCreds')?.checked) modules.push('credentials');
    if (document.getElementById('modCve')?.checked) modules.push('cve');
    if (modules.length === 0) {
        alert("Select at least one module (Credentials / CVE).");
        return;
    }
    credsModuleWanted = modules.includes('credentials');
    cveModuleWanted = modules.includes('cve');

    if (!window.pywebview || !window.pywebview.api) {
        alert("Native API is not available.");
        return;
    }

    try {
        // pass modules as a plain comma string - the most reliable type across
        // pywebview versions (an array can arrive as None on some builds).
        const res = await window.pywebview.api.start_scan(inputPath, mode, modules.join(','));
        if (res.status === 'error') {
            alert("Failed to start scan: " + res.message);
        } else {
            if (term) term.clear();
            
            // Clear findings when new scan starts
            allFindings = [];
            cveFindings = [];
            if (typeof totalFindings !== 'undefined') totalFindings = 0;
            sourceFilter = "all";
            renderFindings([]);
            renderCve();
            updateSourceTabs();
            updateModuleSwitch();
            updateStats();
            const grid = document.getElementById('findingsGrid');
            if (grid) {
                grid.innerHTML = '<div class="loading-state"><p style="color: var(--accent);">[+] Scan initialized. Waiting for findings...</p></div>';
            }
            
            lastLogOffset = 0;
            if (res.log_dir) {
                currentLogDir = res.log_dir;
            }
            // Force indicator to RUNNING so immediate failures are caught and alerted
            const indicator = document.getElementById('scanStatusIndicator');
            if (indicator) indicator.textContent = 'RUNNING...';
            
            checkStatus();
        }
    } catch (e) {
        alert("Error starting scan: " + e.message);
    }
}

async function stopScan() {
    if (!window.pywebview || !window.pywebview.api) return;
    try {
        const res = await window.pywebview.api.stop_scan();
        if (res.status === 'error') {
            alert("Failed to stop scan: " + res.message);
        } else {
            checkStatus();
        }
    } catch (e) {
        alert("Error stopping scan: " + e.message);
    }
}

async function exportHtml() {
    // only the current session's scan output - never a previous run's sibling
    const logDir = currentLogDir;
    if (!logDir) {
        alert("Run a scan first - the report is built from this session's results.");
        return;
    }
    if (window.pywebview && window.pywebview.api) {
        try {
            const res = await window.pywebview.api.export_html(logDir);
            if (res.status === 'success') {
                alert("HTML Report generated successfully at:\n" + res.path);
            } else {
                alert("Failed to generate report: " + res.message);
            }
        } catch (e) {
            alert("Error exporting HTML: " + e.message);
        }
    }
}
