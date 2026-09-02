#!/usr/bin/env python3
"""LAVA HTML report.

Self-contained single file whose look and interactions mirror the desktop GUI:
same card layout (bold file path + bold-larger AI category), the same
search / TP-FP filter, the EMBA / Grep / Overlap source tabs and the
side-by-side split view. verdicts.json is embedded as a JSON blob; no server,
no external assets.
"""
import argparse
import json
import os
import sys

_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LAVA report</title>
<style>
:root{
  --bg-primary:#000;--bg-secondary:#080808;--bg-tertiary:#121212;
  --text-primary:#e0e0e0;--text-secondary:#888;--accent:#00ffcc;
  --danger:#ff0044;--danger-dim:rgba(255,0,68,.15);
  --success:#00ffcc;--success-dim:rgba(0,255,204,.15);
  --border-color:#222;
}
*{box-sizing:border-box;margin:0;padding:0}
body{
  font-family:'Consolas','Courier New',monospace;background:var(--bg-primary);
  background-image:linear-gradient(rgba(0,255,204,.03) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,255,204,.03) 1px,transparent 1px);
  background-size:30px 30px;background-attachment:fixed;
  color:var(--text-primary);line-height:1.6;padding:24px;
}
.wrap{max-width:1600px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:flex-end;gap:20px;
  flex-wrap:wrap;border-bottom:1px solid var(--border-color);padding-bottom:16px;margin-bottom:20px}
h1{font-size:1.6rem;letter-spacing:2px;color:var(--accent);font-weight:700}
.sub{color:var(--text-secondary);font-size:.8rem}
.stats{display:flex;gap:12px}
.stat{border:1px solid var(--border-color);background:var(--bg-secondary);padding:10px 18px;text-align:center}
.stat .v{font-size:1.6rem;font-weight:700;display:block}
.stat .l{font-size:.65rem;letter-spacing:1px;color:var(--text-secondary);text-transform:uppercase}
.stat.tp .v{color:var(--danger)} .stat.fp .v{color:var(--success)}

.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.controls input[type=text]{flex:1;min-width:220px;padding:9px 12px;background:#000;
  border:1px solid var(--border-color);color:var(--text-primary);font-family:inherit;font-size:.85rem}
.btn{padding:8px 16px;background:var(--bg-tertiary);border:1px solid var(--border-color);
  color:var(--text-secondary);cursor:pointer;font-family:inherit;font-size:.8rem;transition:all .15s}
.btn:hover{color:var(--text-primary)}
.btn.active{background:var(--text-primary);color:#000;border-color:var(--text-primary)}
.controls.split-mode .filter-btn{display:none}

.source-tabs{display:flex;gap:4px;border-bottom:1px solid var(--border-color);margin-bottom:14px}
.source-tabs.hidden{display:none}
.source-tab{padding:8px 16px;border:0;background:transparent;color:var(--text-secondary);
  cursor:pointer;font-family:inherit;font-size:.8rem;border-bottom:2px solid transparent}
.source-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.source-tabs.split-mode .source-tab{display:none}
.count{display:inline-block;margin-left:6px;padding:0 6px;background:var(--bg-tertiary);
  border:1px solid var(--border-color);border-radius:10px;font-size:.7rem}
.split-toggle{margin-left:auto;align-self:center}

.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:1rem}
@media(max-width:820px){.grid{grid-template-columns:minmax(0,1fr)}}
@media(min-width:2200px){.grid{grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,1fr)}}
.grid.hidden,.split.hidden{display:none}

.card{background:var(--bg-secondary);border:1px solid var(--border-color);
  border-left:4px solid var(--border-color);padding:1.25rem;display:flex;flex-direction:column;
  gap:1rem;cursor:pointer;transition:background .2s,border-color .2s;min-width:0;overflow:hidden}
.card:hover{background:var(--bg-tertiary);border-color:var(--accent)}
.card.tp{border-left-color:var(--danger)} .card.fp{border-left-color:var(--success)}
.card-top{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}
.card-top>div:first-child{min-width:0}
.card-file{font-size:.9rem;font-weight:700;color:var(--text-primary);word-break:break-all;line-height:1.35}
.card-cat{margin-top:.35rem;font-size:1.15rem;font-weight:700;color:var(--accent);line-height:1.25}
.card-cat:empty{display:none}
.chips{display:flex;gap:6px;align-items:center;flex-shrink:0}
.badge{padding:.2rem .5rem;font-weight:700;font-size:.7rem;border:1px solid}
.badge.tp{background:var(--danger-dim);color:var(--danger);border-color:var(--danger)}
.badge.fp{background:var(--success-dim);color:var(--success);border-color:var(--success)}
.chip{font-size:.62rem;letter-spacing:1px;padding:2px 6px;border:1px solid #333;
  color:var(--text-secondary);text-transform:uppercase}
.chip.custom{color:var(--accent);border-color:var(--accent)}
.chip.both{color:#ffb000;border-color:#ffb000}
.snippet{background:#000;border:1px solid var(--border-color);padding:.7rem;font-size:.78rem;
  color:#a3a3a3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;min-width:0}
.foot{display:flex;justify-content:space-between;align-items:center;margin-top:auto;
  font-size:.72rem;color:var(--text-secondary);gap:10px}
.foot>span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.foot>span:last-child{flex-shrink:0}
.bar{width:60px;height:4px;background:var(--border-color)}
.bar>i{display:block;height:100%}
.empty{color:var(--text-secondary);font-size:.85rem;padding:24px;text-align:center}

.split{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:14px}
@media(max-width:1100px){.split{grid-template-columns:minmax(0,1fr)}}
.col{border:1px solid var(--border-color);display:flex;flex-direction:column;max-height:74vh;min-width:0}
.col-head{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:10px 12px;
  background:var(--bg-tertiary);border-bottom:1px solid var(--border-color)}
.col-title{font-size:.8rem;letter-spacing:1px}
.mini{display:flex;gap:4px}
.mini .btn{padding:3px 10px;font-size:.7rem}
.col-body{overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:12px;flex:1}
.col-body .card{padding:1rem}

.overlay{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;
  justify-content:center;padding:24px;z-index:50}
.overlay.on{display:flex}
.modal{background:var(--bg-secondary);border:1px solid var(--accent);max-width:820px;width:100%;
  max-height:86vh;overflow-y:auto;padding:24px}
.modal h2{color:var(--accent);font-size:1.2rem;margin-bottom:12px;word-break:break-all}
.modal h3{font-size:.8rem;color:var(--text-secondary);letter-spacing:1px;text-transform:uppercase;
  margin:16px 0 6px}
.modal pre{background:#000;border:1px solid var(--border-color);padding:12px;font-size:.8rem;
  white-space:pre-wrap;word-break:break-all;color:#a3a3a3}
.modal .reason{border-left:3px solid var(--accent);padding:10px 12px;background:rgba(0,255,204,.04);
  font-size:.85rem;line-height:1.5}
.modal .close{float:right;background:none;border:1px solid var(--border-color);color:var(--text-secondary);
  cursor:pointer;padding:2px 10px;font-family:inherit}
.badge-group{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>LAVA REPORT</h1><div class="sub" id="sub"></div></div>
    <div class="stats">
      <div class="stat"><span class="v" id="s-total">0</span><span class="l">findings</span></div>
      <div class="stat tp"><span class="v" id="s-tp">0</span><span class="l">true positive</span></div>
      <div class="stat fp"><span class="v" id="s-fp">0</span><span class="l">false positive</span></div>
    </div>
  </header>

  <div class="controls" id="controls">
    <input type="text" id="search" placeholder="Search files or content...">
    <button class="btn filter-btn active" data-filter="all">All</button>
    <button class="btn filter-btn" data-filter="TP">True Positives</button>
    <button class="btn filter-btn" data-filter="FP">False Positives</button>
  </div>

  <div class="source-tabs hidden" id="tabs">
    <button class="source-tab active" data-source="all">All <span class="count" id="c-all">0</span></button>
    <button class="source-tab" data-source="emba">EMBA <span class="count" id="c-emba">0</span></button>
    <button class="source-tab" data-source="custom">Grep <span class="count" id="c-custom">0</span></button>
    <button class="source-tab" data-source="both">Overlap <span class="count" id="c-both">0</span></button>
    <button class="btn split-toggle" id="splitToggle">&#8863; Split</button>
  </div>

  <div class="grid" id="grid"></div>

  <div class="split hidden" id="split">
    <div class="col"><div class="col-head"><span class="col-title">EMBA <span class="count" id="cs-emba">0</span></span>
      <div class="mini" data-col="emba"><button class="btn active" data-f="all">All</button>
        <button class="btn" data-f="TP">TP</button><button class="btn" data-f="FP">FP</button></div></div>
      <div class="col-body" id="body-emba"></div></div>
    <div class="col"><div class="col-head"><span class="col-title">Grep <span class="count" id="cs-grep">0</span></span>
      <div class="mini" data-col="grep"><button class="btn active" data-f="all">All</button>
        <button class="btn" data-f="TP">TP</button><button class="btn" data-f="FP">FP</button></div></div>
      <div class="col-body" id="body-grep"></div></div>
  </div>
</div>

<div class="overlay" id="overlay"><div class="modal" id="modal"></div></div>

<script id="lava-data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('lava-data').textContent);
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function srcOf(f){
  if(f.source) return f.source;
  const m=f.found_by_modules||(f.module?[f.module]:[]);
  const c=m.filter(x=>String(x).startsWith('CUSTOM:'));
  if(!c.length) return 'emba';
  return c.length===m.length?'custom':'both';
}
let verdictFilter='all', sourceFilter='all', splitView=false;
const splitVerdict={emba:'all',grep:'all'};

function card(f){
  const v=(f.predicted_verdict||'').toLowerCase(), src=srcOf(f);
  const conf=Math.round((f.confidence||0)*100);
  const cat=(f.category||'').trim();
  const srcLbl={emba:'EMBA',custom:'GREP',both:'BOTH'}[src]||src;
  const el=document.createElement('div');
  el.className='card '+v;
  el.innerHTML=`
    <div class="card-top">
      <div>
        <div class="card-file">${esc(f.file_path)}${f.line_no?':'+f.line_no:''}</div>
        <div class="card-cat">${esc(cat)}</div>
      </div>
      <div class="chips">
        <span class="chip ${src}">${srcLbl}</span>
        <span class="badge ${v}">${esc(f.predicted_verdict)}</span>
      </div>
    </div>
    <div class="snippet">${esc(f.matched_content||'')}</div>
    <div class="foot">
      <span>${esc((f.found_by_modules||[f.module||'?']).join(', '))}</span>
      <span style="display:flex;align-items:center;gap:6px">Conf ${conf}%
        <span class="bar"><i style="width:${conf}%;background:${v==='tp'?'var(--danger)':'var(--success)'}"></i></span>
      </span>
    </div>`;
  el.onclick=()=>openModal(f);
  return el;
}

function openModal(f){
  const src=srcOf(f), cat=(f.category||'').trim();
  const srcLbl={emba:'Source: EMBA',custom:'Source: Custom grep',both:'Source: EMBA + Custom grep'}[src]||src;
  document.getElementById('modal').innerHTML=`
    <button class="close" onclick="closeModal()">close</button>
    <h2>${esc(cat||f.file_path)}</h2>
    <div class="badge-group">
      <span class="badge ${(f.predicted_verdict||'').toLowerCase()}">${esc(f.predicted_verdict)}</span>
      <span class="chip ${src}">${srcLbl}</span>
      ${cat?`<span class="chip">${esc(f.file_path)}${f.line_no?':'+f.line_no:''}</span>`:''}
      <span class="chip">Corroboration: ${esc(f.corroboration_count)}</span>
      <span class="chip">Confidence: ${Math.round((f.confidence||0)*100)}%</span>
    </div>
    <h3>Matched content</h3>
    <pre>${esc(f.matched_content||'(none)')}</pre>
    <h3>AI reasoning</h3>
    <div class="reason">${esc(f.model_reasoning||f.reasoning||'(none)')}</div>
    <h3>Modules</h3>
    <pre>${esc((f.found_by_modules||[f.module]).join(', '))}</pre>`;
  document.getElementById('overlay').classList.add('on');
}
function closeModal(){document.getElementById('overlay').classList.remove('on');}
document.getElementById('overlay').onclick=e=>{if(e.target.id==='overlay')closeModal();};
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});

function counts(){
  const c={all:DATA.length,emba:0,custom:0,both:0};
  DATA.forEach(f=>c[srcOf(f)]++);
  return c;
}
function searchMatch(f,t){
  return (f.file_path||'').toLowerCase().includes(t) || (f.matched_content||'').toLowerCase().includes(t)
      || (f.category||'').toLowerCase().includes(t);
}

function render(){
  const t=document.getElementById('search').value.toLowerCase();
  const searched=DATA.filter(f=>searchMatch(f,t));
  if(splitView){
    [['emba',['emba','both'],'body-emba','cs-emba'],['grep',['custom','both'],'body-grep','cs-grep']].forEach(([k,want,bodyId,cntId])=>{
      const rows=searched.filter(f=>want.includes(srcOf(f)))
        .filter(f=>splitVerdict[k]==='all'||f.predicted_verdict===splitVerdict[k]);
      document.getElementById(cntId).textContent=rows.length;
      const b=document.getElementById(bodyId); b.innerHTML='';
      rows.forEach(f=>b.appendChild(card(f)));
      if(!rows.length) b.innerHTML='<div class="empty">No findings match.</div>';
    });
    return;
  }
  const rows=searched.filter(f=>{
    const okV=verdictFilter==='all'||f.predicted_verdict===verdictFilter;
    const okS=sourceFilter==='all'||srcOf(f)===sourceFilter;
    return okV&&okS;
  });
  const g=document.getElementById('grid'); g.innerHTML='';
  rows.forEach(f=>g.appendChild(card(f)));
  if(!rows.length) g.innerHTML='<div class="empty">No findings match your criteria.</div>';
}

function visibility(){
  document.getElementById('grid').classList.toggle('hidden',splitView);
  document.getElementById('split').classList.toggle('hidden',!splitView);
  document.getElementById('tabs').classList.toggle('split-mode',splitView);
  document.getElementById('controls').classList.toggle('split-mode',splitView);
}

// init
(function(){
  const tp=DATA.filter(f=>f.predicted_verdict==='TP').length;
  const fp=DATA.filter(f=>f.predicted_verdict==='FP').length;
  document.getElementById('s-total').textContent=DATA.length;
  document.getElementById('s-tp').textContent=tp;
  document.getElementById('s-fp').textContent=fp;
  document.getElementById('sub').textContent=new Date().toISOString().slice(0,16).replace('T',' ')+'  ·  verdicts.json';

  const c=counts();
  ['all','emba','custom','both'].forEach(s=>document.getElementById('c-'+s).textContent=c[s]);
  const hasCustom=c.custom>0||c.both>0;
  document.getElementById('tabs').classList.toggle('hidden',!hasCustom);

  document.getElementById('search').addEventListener('input',render);
  document.querySelectorAll('.filter-btn').forEach(b=>b.onclick=()=>{
    document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); verdictFilter=b.dataset.filter; render();
  });
  document.querySelectorAll('.source-tab').forEach(b=>b.onclick=()=>{
    document.querySelectorAll('.source-tab').forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); sourceFilter=b.dataset.source; render();
  });
  document.getElementById('splitToggle').onclick=function(){
    splitView=!splitView; this.classList.toggle('active',splitView); visibility(); render();
  };
  document.querySelectorAll('.mini').forEach(group=>{
    const col=group.dataset.col;
    group.querySelectorAll('.btn').forEach(b=>b.onclick=()=>{
      group.querySelectorAll('.btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active'); splitVerdict[col]=b.dataset.f; render();
    });
  });
  render();
})();
</script>
</body>
</html>
"""


def generate_report(verdicts_file: str, out_file: str) -> None:
    if not os.path.exists(verdicts_file):
        print(f"Error: {verdicts_file} not found.")
        sys.exit(1)
    try:
        with open(verdicts_file, "r", encoding="utf-8") as f:
            findings = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {verdicts_file}: {e}")
        sys.exit(1)
    if not isinstance(findings, list):
        findings = []

    rank = {"TP": 0, "FP": 1}
    findings.sort(key=lambda f: rank.get(str(f.get("predicted_verdict", "")).upper(), 2))

    blob = json.dumps(findings, ensure_ascii=False).replace("<", "\\u003c").replace("\u2028", " ").replace("\u2029", " ")
    page = _PAGE.replace("__DATA__", blob)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[OK] report -> {out_file} ({len(findings)} findings)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate the LAVA HTML report")
    ap.add_argument("--verdicts", required=True, help="Path to verdicts.json")
    ap.add_argument("--out", required=True, help="Output HTML file")
    args = ap.parse_args()
    generate_report(args.verdicts, args.out)
