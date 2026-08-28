let allFindings = [];
let totalFindings = 0;
let term = null;
let currentLogDir = "";

window.addEventListener('pywebviewready', async () => {
    try {
        const platform = await window.pywebview.api.get_platform();
        if (platform === "win32") {
            const firmwareRadio = document.querySelector('input[value="firmware"]');
            if (firmwareRadio) {
                firmwareRadio.parentElement.style.display = 'none';
            }
        }
    } catch (e) {
        console.warn("Could not fetch platform", e);
    }
    
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
        
        // Use currentLogDir if set (from a scan), otherwise read from input box
        const inputVal = document.getElementById('logDirInput') ? document.getElementById('logDirInput').value.trim() : '';
        const logDir = currentLogDir || inputVal;
        
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
        
        // Re-apply current filters instead of rendering all findings
        const activeFilterBtn = document.querySelector('.filter-btn.active');
        const verdictFilter = activeFilterBtn ? activeFilterBtn.dataset.filter : 'all';
        const searchInput = document.getElementById('searchInput');
        const searchTerm = searchInput ? searchInput.value : '';
        filterData(searchTerm, verdictFilter);
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
    const showTerminalBtn = document.getElementById('showTerminalBtn');

    
    if (startBtn) startBtn.addEventListener('click', startScan);
    if (stopBtn) stopBtn.addEventListener('click', stopScan);
    if (browseBtn) browseBtn.addEventListener('click', browseFolder);
    if (exportBtn) exportBtn.addEventListener('click', exportHtml);
    


    // AI Settings Modal
    const aiSettingsBtn = document.getElementById('aiSettingsBtn');
    const aiSettingsModal = document.getElementById('aiSettingsModal');
    const cancelSettingsBtn = document.getElementById('cancelSettingsBtn');
    const saveSettingsBtn = document.getElementById('saveSettingsBtn');
    const aiProviderSelect = document.getElementById('aiProviderSelect');
    const geminiKeyContainer = document.getElementById('geminiKeyContainer');
    const geminiKeyInput = document.getElementById('geminiKeyInput');

    if (aiSettingsBtn) {
        aiSettingsBtn.addEventListener('click', async () => {
            if (window.pywebview && window.pywebview.api.get_ai_config) {
                const config = await window.pywebview.api.get_ai_config();
                aiProviderSelect.value = config.AI_PROVIDER || 'local';
                geminiKeyInput.value = config.GEMINI_API_KEY || '';
                updateProviderVisibility(aiProviderSelect.value);
            }
            aiSettingsModal.classList.remove('hidden');
        });
    }

    if (cancelSettingsBtn) {
        cancelSettingsBtn.addEventListener('click', () => {
            aiSettingsModal.classList.add('hidden');
        });
    }

    function updateProviderVisibility(value) {
        if (geminiKeyContainer) geminiKeyContainer.style.display = value === 'gemini' ? 'block' : 'none';
        const mcpInfo = document.getElementById('mcpInfo');
        if (mcpInfo) mcpInfo.style.display = (value && value.indexOf('mcp') === 0) ? 'block' : 'none';
    }

    if (aiProviderSelect) {
        aiProviderSelect.addEventListener('change', (e) => {
            updateProviderVisibility(e.target.value);
        });
    }

    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', async () => {
            if (window.pywebview && window.pywebview.api.save_ai_config) {
                await window.pywebview.api.save_ai_config({
                    "AI_PROVIDER": aiProviderSelect.value,
                    "GEMINI_API_KEY": geminiKeyInput.value
                });
            }
            aiSettingsModal.classList.add('hidden');
        });
    }

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
                            
                            // EMBA için sütun genişliğini minimum 160'ta tut, sığmazsa yatay scrollbar çıksın
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
                if (data.exit_code === 0) {
                    alert("Scan completed successfully!");
                } else if (data.exit_code !== null && data.exit_code !== undefined && data.exit_code !== 1) { // 1 is taskkill error on stop, mostly ignore
                    alert("Scan failed or was stopped (exit code: " + data.exit_code + "). Check lava_out/lava_scan.log for details.");
                }
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
                if (mode === 'log') {
                    fetchData();
                }
            }
        } catch (e) {
            console.error("Folder selection failed:", e);
        }
    } else {
        alert("Native file browser is only available in the LAVA Desktop App (LAVA_UI.exe).");
    }
}

// Clear currentLogDir when user manually edits the input
document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('logDirInput');
    if (input) {
        input.addEventListener('input', () => {
            currentLogDir = "";
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
    
    if (!window.pywebview || !window.pywebview.api) {
        alert("Native API is not available.");
        return;
    }

    try {
        const res = await window.pywebview.api.start_scan(inputPath, mode);
        if (res.status === 'error') {
            alert("Failed to start scan: " + res.message);
        } else {
            if (term) term.clear();
            
            // Clear findings when new scan starts
            allFindings = [];
            if (typeof totalFindings !== 'undefined') totalFindings = 0;
            renderFindings([]);
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
    const logDir = currentLogDir || document.getElementById('logDirInput').value.trim();
    if (!logDir) {
        alert("Please run a scan or select a Log Directory first.");
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
