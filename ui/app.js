let allFindings = [];

document.addEventListener('DOMContentLoaded', () => {
    fetchData();
    setupEventListeners();
    checkStatus();
    setInterval(checkStatus, 3000);
});

async function fetchData() {
    try {
        const response = await fetch('/verdicts.json');
        if (!response.ok) throw new Error('Network response was not ok');
        allFindings = await response.json();
        
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

    animateValue('stat-total', 0, total, 1000);
    animateValue('stat-tp', 0, tp, 1000);
    animateValue('stat-fp', 0, fp, 1000);
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
    
    if (startBtn) startBtn.addEventListener('click', startScan);
    if (stopBtn) stopBtn.addEventListener('click', stopScan);
    if (browseBtn) browseBtn.addEventListener('click', browseFolder);

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
    document.getElementById('closeModal').addEventListener('click', closeModal);
    document.getElementById('modalOverlay').addEventListener('click', (e) => {
        if (e.target.id === 'modalOverlay') closeModal();
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
    });
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

function animateValue(id, start, end, duration) {
    const obj = document.getElementById(id);
    if (!obj) return;
    const valueSpan = obj.querySelector('.stat-value');
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        valueSpan.innerHTML = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Scan Control API Calls
async function checkStatus() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
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
        } else {
            // If it was running and now it's not, we should refresh the data
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
        alert("Please enter an EMBA Log Directory (e.g. lava_tplinkad7200_log)");
        return;
    }
    
    try {
        const res = await fetch('/api/start', {
            method: 'POST',
            body: JSON.stringify({ logDir })
        });
        if (!res.ok) {
            const err = await res.text();
            alert("Failed to start scan: " + err);
        } else {
            checkStatus();
        }
    } catch (e) {
        alert("Error starting scan: " + e.message);
    }
}

async function stopScan() {
    try {
        const res = await fetch('/api/stop', { method: 'POST' });
        if (!res.ok) {
            const err = await res.text();
            alert("Failed to stop scan: " + err);
        } else {
            checkStatus();
        }
    } catch (e) {
        alert("Error stopping scan: " + e.message);
    }
}
