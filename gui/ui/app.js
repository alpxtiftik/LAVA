let allFindings = [];
let totalFindings = 0;

window.addEventListener('pywebviewready', () => {
    fetchData();
    setupEventListeners();
    checkStatus();
    setInterval(checkStatus, 3000);
});

setTimeout(() => {
    if (!window.pywebview) {
        const grid = document.getElementById('findingsGrid');
        if (grid) grid.innerHTML = '<div class="loading-state"><p style="color: var(--danger)">PyWebView not detected. Please run LAVA_UI.exe</p></div>';
    }
}, 2000);

async function fetchData() {
    try {
        if (!window.pywebview || !window.pywebview.api) {
            throw new Error('PyWebView API not available.');
        }
        const logDir = document.getElementById('logDirInput') ? document.getElementById('logDirInput').value.trim() : '';
        if (!logDir) {
            document.getElementById('findingsGrid').innerHTML = '<div class="loading-state"><p>Please select an EMBA Log Directory to view findings.</p></div>';
            return;
        }

        const totalRes = await window.pywebview.api.get_total_findings(logDir);
        totalFindings = totalRes.total || 0;

        allFindings = await window.pywebview.api.get_verdicts(logDir);
        if (allFindings.error) {
            throw new Error(allFindings.error);
        }
        
        populateModuleFilter();
        updateStats();
        renderFindings(allFindings);
    } catch (error) {
        document.getElementById('findingsGrid').innerHTML = `
            <div class="loading-state">
                <p style="color: var(--danger)">Error loading verdicts.json. Make sure you are running start_ui.py</p>
                <p>${error.message}</p>
            </div>
        `;
    }
}

function updateStats() {
    const total = allFindings.length;
    const tp = allFindings.filter(f => f.predicted_verdict === 'TP').length;
    const fp = allFindings.filter(f => f.predicted_verdict === 'FP').length;

    const elTotal = document.getElementById('stat-total');
    if (elTotal) {
        if (totalFindings > 0) {
            elTotal.querySelector('.stat-value').innerHTML = `${total} / ${totalFindings}`;
        } else {
            elTotal.querySelector('.stat-value').innerHTML = total;
        }
    }
    
    const elTp = document.getElementById('stat-tp');
    if (elTp) elTp.querySelector('.stat-value').innerHTML = tp;
    
    const elFp = document.getElementById('stat-fp');
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
        if (f.found_by_modules && Array.isArray(f.found_by_modules)) {
            f.found_by_modules.forEach(m => modules.add(m));
        } else if (f.module) {
            modules.add(f.module);
        }
    });
    
    Array.from(modules).sort().forEach(m => {
        const opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        filter.appendChild(opt);
    });
}

function renderFindings(findings) {
    const grid = document.getElementById('findingsGrid');
    grid.innerHTML = '';

    findings.forEach(finding => {
        const isTP = finding.predicted_verdict === 'TP';
        const confPct = Math.round((finding.confidence || 0) * 100);
        
        const card = document.createElement('div');
        card.className = `finding-card verdict-${finding.predicted_verdict.toLowerCase()}`;
        
        card.innerHTML = `
            <div class="card-header">
                <span class="file-path">${escapeHtml(finding.file_path)}</span>
                <span class="verdict-badge badge-${finding.predicted_verdict.toLowerCase()}">${finding.predicted_verdict}</span>
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
        grid.appendChild(card);
    });

    if (findings.length === 0) {
        grid.innerHTML = '<div class="loading-state"><p>No findings match your criteria.</p></div>';
    }
}

function setupEventListeners() {
    // Scan Controls
    const startBtn = document.getElementById('startScanBtn');
    const stopBtn = document.getElementById('stopScanBtn');
    const browseBtn = document.getElementById('browseBtn');
    const exportBtn = document.getElementById('exportHtmlBtn');
    
    if (startBtn) startBtn.addEventListener('click', startScan);
    if (stopBtn) stopBtn.addEventListener('click', stopScan);
    if (browseBtn) browseBtn.addEventListener('click', browseFolder);
    if (exportBtn) exportBtn.addEventListener('click', exportHtml);

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
            const gridView = document.getElementById('findingsGrid');
            const rawView = document.getElementById('rawJsonView');
            
            if (gridView.classList.contains('hidden')) {
                // Switch to Grid View
                gridView.classList.remove('hidden');
                rawView.classList.add('hidden');
                toggleBtn.textContent = '{} View Raw JSON';
            } else {
                // Switch to Raw View
                gridView.classList.add('hidden');
                rawView.classList.remove('hidden');
                toggleBtn.textContent = '⊞ View Cards';
                updateRawJsonView();
            }
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
    const term = searchTerm.toLowerCase();
    let modFilterVal = 'all';
    const modFilter = document.getElementById('moduleFilter');
    if (modFilter) {
        modFilterVal = modFilter.value;
    }
    
    const filtered = allFindings.filter(f => {
        const matchesSearch = (f.file_path || '').toLowerCase().includes(term) || 
                              (f.matched_content || '').toLowerCase().includes(term);
        const matchesVerdict = verdictFilter === 'all' || f.predicted_verdict === verdictFilter;
        
        const mods = f.found_by_modules || [f.module];
        const matchesModule = modFilterVal === 'all' || mods.includes(modFilterVal);
        
        return matchesSearch && matchesVerdict && matchesModule;
    });

    renderFindings(filtered);
}

function openModal(finding) {
    document.getElementById('modalTitle').textContent = finding.file_path;
    
    const isTP = finding.predicted_verdict === 'TP';
    const badgesHtml = `
        <span class="verdict-badge badge-${finding.predicted_verdict.toLowerCase()}">${finding.predicted_verdict}</span>
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
            if (document.getElementById('browseBtn')) document.getElementById('browseBtn').disabled = true;
            
            // Fetch live data while running
            fetchData();
        } else {
            // If it was running and now it's not, refresh one last time
            if (indicator.textContent === 'RUNNING...') {
                fetchData();
            }
            indicator.textContent = 'IDLE';
            indicator.className = 'status-indicator status-idle';
            startBtn.disabled = false;
            stopBtn.disabled = true;
            logInput.disabled = false;
            if (document.getElementById('browseBtn')) document.getElementById('browseBtn').disabled = false;
        }
    } catch(e) {
        console.error("Status check failed", e);
    }
}

async function browseFolder() {
    if (window.pywebview && window.pywebview.api) {
        try {
            const path = await window.pywebview.api.open_folder_dialog();
            if (path) {
                document.getElementById('logDirInput').value = path;
                fetchData();
            }
        } catch (e) {
            console.error("Folder selection failed:", e);
        }
    } else {
        alert("Native file browser is only available in the LAVA Desktop App (LAVA_UI.exe).");
    }
}

async function startScan() {
    const logDir = document.getElementById('logDirInput').value.trim();
    if (!logDir) {
        alert("Please enter an EMBA Log Directory (e.g. emba_example_log)");
        return;
    }
    
    if (!window.pywebview || !window.pywebview.api) {
        alert("Native API is not available.");
        return;
    }

    try {
        const res = await window.pywebview.api.start_scan(logDir);
        if (res.status === 'error') {
            alert("Failed to start scan: " + res.message);
        } else {
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
    const logDir = document.getElementById('logDirInput').value.trim();
    if (!logDir) {
        alert("Please select a Log Directory first.");
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
