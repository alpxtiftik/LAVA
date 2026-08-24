#!/usr/bin/env python3
import json
import argparse
import sys
import os

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LAVA - Vulnerability Report</title>
    <style>
        :root {
            --bg: #09090b; --surface: #18181b; --surface-hover: #27272a;
            --border: #3f3f46; --glass-border: rgba(255,255,255,0.1);
            --primary: #3b82f6; --primary-glow: rgba(59, 130, 246, 0.5);
            --danger: #ef4444; --danger-glow: rgba(239, 68, 68, 0.3);
            --success: #22c55e; --success-glow: rgba(34, 197, 94, 0.3);
            --text: #f4f4f5; --text-secondary: #a1a1aa;
        }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg); color: var(--text);
            margin: 0; padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--border); padding-bottom: 20px; flex-wrap: wrap; gap: 20px;}
        h1 { margin: 0; color: var(--text); font-size: 2rem; }
        .subtitle { color: var(--text-secondary); font-family: monospace; }
        .stats { display: flex; gap: 20px; }
        .stat-card {
            background: var(--surface); padding: 15px 25px; border-radius: 8px;
            border: 1px solid var(--glass-border); text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; display: block; }
        .stat-label { color: var(--text-secondary); font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
        .stat-tp { color: var(--danger); text-shadow: 0 0 10px var(--danger-glow); border-color: rgba(239, 68, 68, 0.3); }
        .stat-fp { color: var(--success); text-shadow: 0 0 10px var(--success-glow); border-color: rgba(34, 197, 94, 0.3); }
        
        .controls { display: flex; gap: 15px; margin-bottom: 20px; }
        .search-input { flex-grow: 1; padding: 10px 15px; background: #000; border: 1px solid var(--border); color: #fff; border-radius: 6px; font-size: 1rem; }
        .filter-btn { padding: 10px 20px; background: var(--surface); border: 1px solid var(--border); color: var(--text-secondary); border-radius: 6px; cursor: pointer; transition: all 0.2s; }
        .filter-btn:hover { background: var(--surface-hover); color: #fff; }
        .filter-btn.active { background: rgba(59, 130, 246, 0.1); border-color: var(--primary); color: var(--primary); }

        .finding-card {
            background: var(--surface); border: 1px solid var(--glass-border);
            border-radius: 8px; padding: 20px; margin-bottom: 20px;
        }
        .finding-card.hidden { display: none; }
        .verdict-tp { border-left: 4px solid var(--danger); box-shadow: 0 4px 20px rgba(239,68,68,0.05); }
        .verdict-fp { border-left: 4px solid var(--success); opacity: 0.8; }
        .card-header { display: flex; justify-content: space-between; margin-bottom: 15px; }
        .file-path { font-family: monospace; font-size: 1.1rem; color: var(--primary); word-break: break-all; }
        .badge { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9rem; }
        .badge-tp { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-fp { background: rgba(34, 197, 94, 0.1); color: var(--success); border: 1px solid rgba(34, 197, 94, 0.3); }
        
        pre { background: #000; padding: 15px; border-radius: 6px; overflow-x: auto; color: #0f0; border: 1px solid var(--border); font-size: 0.9rem; }
        .reasoning { margin-top: 15px; padding: 15px; background: rgba(255,255,255,0.02); border-left: 3px solid var(--primary); color: var(--text-secondary); line-height: 1.5; font-style: italic; }
        .meta { display: flex; gap: 15px; margin-top: 15px; font-size: 0.85rem; color: var(--text-secondary); flex-wrap: wrap; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>LAVA Report</h1>
                <span class="subtitle">Standalone Vulnerability Analysis</span>
            </div>
            <div class="stats">
                <div class="stat-card">
                    <span class="stat-value">[[TOTAL]]</span>
                    <span class="stat-label">Total Findings</span>
                </div>
                <div class="stat-card stat-tp">
                    <span class="stat-value">[[TP]]</span>
                    <span class="stat-label">True Positives</span>
                </div>
                <div class="stat-card stat-fp">
                    <span class="stat-value">[[FP]]</span>
                    <span class="stat-label">False Positives</span>
                </div>
            </div>
        </header>

        <div class="controls">
            <input type="text" id="searchInput" class="search-input" placeholder="Search in paths or contents...">
            <button class="filter-btn active" data-filter="all">All</button>
            <button class="filter-btn" data-filter="TP">True Positives</button>
            <button class="filter-btn" data-filter="FP">False Positives</button>
        </div>
        
        <main id="findingsList">
[[CARDS]]
        </main>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const filterBtns = document.querySelectorAll('.filter-btn');
        const cards = document.querySelectorAll('.finding-card');

        function filterCards() {
            const term = searchInput.value.toLowerCase();
            const activeFilter = document.querySelector('.filter-btn.active').dataset.filter;

            cards.forEach(card => {
                const text = card.textContent.toLowerCase();
                const isTP = card.classList.contains('verdict-tp');
                const isFP = card.classList.contains('verdict-fp');
                
                let matchesFilter = true;
                if (activeFilter === 'TP' && !isTP) matchesFilter = false;
                if (activeFilter === 'FP' && !isFP) matchesFilter = false;

                if (matchesFilter && text.includes(term)) {
                    card.classList.remove('hidden');
                } else {
                    card.classList.add('hidden');
                }
            });
        }

        searchInput.addEventListener('input', filterCards);

        filterBtns.forEach(btn => {
            btn.addEventListener('click', (e) => {
                filterBtns.forEach(b => b.classList.remove('active'));
                e.target.classList.add('active');
                filterCards();
            });
        });
    </script>
</body>
</html>
"""

def generate_report(verdicts_file: str, out_file: str):
    if not os.path.exists(verdicts_file):
        print(f"Error: {verdicts_file} not found.")
        sys.exit(1)
        
    with open(verdicts_file, "r", encoding="utf-8") as f:
        try:
            findings = json.load(f)
        except Exception as e:
            print(f"Error parsing JSON: {e}")
            sys.exit(1)
            
    if not isinstance(findings, list):
        findings = []

    def sort_key(f):
        v = str(f.get("predicted_verdict", "")).upper()
        if v == "TP": return 0
        if v == "FP": return 1
        return 2
        
    findings.sort(key=sort_key)
    
    tp_count = sum(1 for f in findings if f.get("predicted_verdict") == "TP")
    fp_count = sum(1 for f in findings if f.get("predicted_verdict") == "FP")
    
    cards = []
    for f in findings:
        v = str(f.get("predicted_verdict", "UNKNOWN")).upper()
        v_class = v.lower()
        
        path = str(f.get("file_path", "Unknown"))
        content = str(f.get("matched_content", "")).replace("\\n", "\n").replace("<", "&lt;").replace(">", "&gt;")
        reasoning = str(f.get("model_reasoning", "")).replace("\\n", "<br>")
        conf = f.get("confidence")
        conf_str = f"{int(conf*100)}%" if conf is not None else "N/A"
        modules = ", ".join(f.get("found_by_modules", [f.get("module", "Unknown")]))
        corrob = f.get("corroboration_count", 1)
        
        card = f'''
        <div class="finding-card verdict-{v_class}">
            <div class="card-header">
                <span class="file-path">{path}</span>
                <span class="badge badge-{v_class}">{v}</span>
            </div>
            <pre><code>{content}</code></pre>
            <div class="reasoning">
                <strong>AI Reasoning:</strong> {reasoning}
            </div>
            <div class="meta">
                <span><strong>Confidence:</strong> {conf_str}</span>
                <span><strong>Modules:</strong> {modules}</span>
                <span><strong>Corroboration:</strong> {corrob}</span>
            </div>
        </div>
        '''
        cards.append(card)
        
    html_content = HTML_TEMPLATE.replace("[[TOTAL]]", str(len(findings)))
    html_content = html_content.replace("[[TP]]", str(tp_count))
    html_content = html_content.replace("[[FP]]", str(fp_count))
    html_content = html_content.replace("[[CARDS]]", "\\n".join(cards))
    
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(html_content)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate LAVA HTML Report")
    parser.add_argument("--verdicts", required=True, help="Path to verdicts.json")
    parser.add_argument("--out", required=True, help="Path to output HTML file")
    args = parser.parse_args()
    
    generate_report(args.verdicts, args.out)
