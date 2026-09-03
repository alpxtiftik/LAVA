#!/usr/bin/env python3
"""LAVA HTML report.

Self-contained single file whose look and interactions mirror the desktop GUI.
It can carry either or both of LAVA's two modules:

  * credentials - EMBA hardcoded-credential findings + AI verdicts (verdicts.json):
    the card layout (bold file path + bold-larger AI category), search / TP-FP
    filter, EMBA / Grep / Overlap source tabs, side-by-side split view.
  * cve - EMBA's F17 / S26 CVE output structured by cve_scan.py (cve_findings.json):
    cards grouped by attack vector, filtered by severity / exploit availability.

When both are present a module switcher appears at the top. No server, no
external assets - the JSON blobs are embedded.
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
  --warn:#ffb000;--warn-dim:rgba(255,176,0,.15);
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
h1{font-size:2rem;letter-spacing:2px;color:var(--text-primary);font-weight:700}
h1::after{content:'_';color:var(--accent);animation:blink 1s step-end infinite}
@keyframes blink{50%{opacity:0}}
.sub{color:var(--text-secondary);font-size:.85rem;letter-spacing:1px;text-transform:uppercase;
  display:block;margin-top:.25rem}
.stats{display:flex;gap:12px}
.stat{border:1px solid var(--border-color);background:var(--bg-secondary);padding:10px 18px;text-align:center}
.stat .v{font-size:1.6rem;font-weight:700;display:block}
.stat .l{font-size:.65rem;letter-spacing:1px;color:var(--text-secondary);text-transform:uppercase}
.stat.tp .v{color:var(--danger)} .stat.fp .v{color:var(--success)}
.stat.warn .v{color:var(--warn)}

.module-nav{display:flex;gap:4px;margin-bottom:16px}
.module-nav.hidden{display:none}
.module-nav button{padding:10px 22px;border:1px solid var(--border-color);background:var(--bg-secondary);
  color:var(--text-secondary);cursor:pointer;font-family:inherit;font-size:.85rem;letter-spacing:1px;
  text-transform:uppercase}
.module-nav button.active{background:var(--text-primary);color:#000;border-color:var(--text-primary)}
.module.hidden{display:none}

.controls{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
.controls input[type=text]{flex:1;min-width:220px;padding:9px 12px;background:#000;
  border:1px solid var(--border-color);color:var(--text-primary);font-family:inherit;font-size:.85rem}
.btn{padding:8px 16px;background:var(--bg-tertiary);border:1px solid var(--border-color);
  color:var(--text-secondary);cursor:pointer;font-family:inherit;font-size:.8rem;transition:all .15s}
.btn:hover{color:var(--text-primary)}
.btn.active{background:var(--text-primary);color:#000;border-color:var(--text-primary)}
#cve-showall{margin-left:4px}
#cve-showall.active{background:rgba(0,255,204,.12);color:var(--accent);border-color:var(--accent)}
.controls.split-mode .filter-btn{display:none}
.fgroup{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.fgroup .lbl{font-size:.65rem;letter-spacing:1px;color:var(--text-secondary);text-transform:uppercase;margin-right:4px}
.fgroup select{padding:6px 10px;background:#000;border:1px solid var(--border-color);color:var(--text-primary);
  font-family:inherit;font-size:.78rem}
.cve-type-line{font-size:.72rem;letter-spacing:1px;text-transform:uppercase;color:var(--warn);font-weight:700}

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
.card.sev-critical{border-left-color:var(--danger)}
.card.sev-high{border-left-color:var(--warn)}
.card.sev-medium{border-left-color:#3a9}
.card.sev-low,.card.sev-unknown{border-left-color:var(--border-color)}
.card-top{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}
.card-top>div:first-child{min-width:0}
.card-file{font-size:.9rem;font-weight:700;color:var(--text-primary);word-break:break-all;line-height:1.35}
.card-cat{margin-top:.35rem;font-size:1.15rem;font-weight:700;color:var(--accent);line-height:1.25}
.card-cat:empty{display:none}
.chips{display:flex;gap:6px;align-items:center;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.badge{padding:.2rem .5rem;font-weight:700;font-size:.7rem;border:1px solid}
.badge.tp{background:var(--danger-dim);color:var(--danger);border-color:var(--danger)}
.badge.fp{background:var(--success-dim);color:var(--success);border-color:var(--success)}
.badge.sev-critical{background:var(--danger-dim);color:var(--danger);border-color:var(--danger)}
.badge.sev-high{background:var(--warn-dim);color:var(--warn);border-color:var(--warn)}
.badge.sev-medium{background:rgba(51,170,153,.15);color:#5cc;border-color:#3a9}
.badge.sev-low,.badge.sev-unknown{background:var(--bg-tertiary);color:var(--text-secondary);border-color:#333}
.chip{font-size:.62rem;letter-spacing:1px;padding:2px 6px;border:1px solid #333;
  color:var(--text-secondary);text-transform:uppercase}
.chip.custom{color:var(--accent);border-color:var(--accent)}
.chip.both{color:#ffb000;border-color:#ffb000}
.chip.exploit{color:var(--danger);border-color:var(--danger)}
.chip.kev{color:#fff;background:var(--danger);border-color:var(--danger)}
.chip.av-network{color:var(--danger);border-color:var(--danger)}
.chip.verified{color:var(--accent);border-color:var(--accent)}
.snippet{background:#000;border:1px solid var(--border-color);padding:.7rem;font-size:.78rem;
  color:#a3a3a3;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;min-width:0}
.snippet.wrap{white-space:normal;max-height:4.2rem;overflow:hidden}
.foot{display:flex;justify-content:space-between;align-items:center;margin-top:auto;
  font-size:.72rem;color:var(--text-secondary);gap:10px}
.foot>span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.foot>span:last-child{flex-shrink:0}
.bar{width:60px;height:4px;background:var(--border-color)}
.bar>i{display:block;height:100%}
.empty{color:var(--text-secondary);font-size:.85rem;padding:24px;text-align:center}
.note{color:var(--text-secondary);font-size:.75rem;margin:10px 0 14px}

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
.kv{display:grid;grid-template-columns:auto 1fr;gap:4px 14px;font-size:.82rem}
.kv b{color:var(--text-secondary);font-weight:400}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div><h1>LAVA</h1><span class="sub" id="sub">Local AI Vulnerability Auditor</span></div>
    <div class="stats" id="stats"></div>
  </header>

  <div class="module-nav hidden" id="moduleNav">
    <button data-module="creds" class="active">Credentials <span class="count" id="mn-creds">0</span></button>
    <button data-module="cve">CVE <span class="count" id="mn-cve">0</span></button>
  </div>

  <!-- ============================ CREDENTIALS ============================ -->
  <section class="module" id="mod-creds">
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
  </section>

  <!-- ================================ CVE =============================== -->
  <section class="module hidden" id="mod-cve">
    <div class="controls">
      <input type="text" id="cve-search" placeholder="Search CVE id, component or description...">
    </div>
    <div class="controls">
      <div class="fgroup"><span class="lbl">Attack vector</span>
        <button class="btn cve-f active" data-k="av" data-v="all">All</button>
        <button class="btn cve-f" data-k="av" data-v="Network">Network</button>
        <button class="btn cve-f" data-k="av" data-v="Adjacent">Adjacent</button>
        <button class="btn cve-f" data-k="av" data-v="Local">Local</button>
        <button class="btn cve-f" data-k="av" data-v="Physical">Physical</button>
      </div>
      <div class="fgroup"><span class="lbl">Type</span>
        <select id="cve-type">
          <option value="all">All types</option>
          <option value="Injection / RCE">Injection / RCE</option>
          <option value="Memory safety">Memory safety</option>
          <option value="Auth / access control">Auth / access control</option>
          <option value="Path traversal">Path traversal</option>
          <option value="Information disclosure">Information disclosure</option>
          <option value="Race condition">Race condition</option>
          <option value="Denial of service">Denial of service</option>
          <option value="Cryptographic issue">Cryptographic issue</option>
          <option value="Web (XSS / CSRF / SSRF)">Web (XSS / CSRF / SSRF)</option>
          <option value="__unclassified__">Unclassified</option>
        </select>
      </div>
    </div>
    <div class="controls">
      <div class="fgroup"><span class="lbl">Severity</span>
        <button class="btn cve-f active" data-k="sev" data-v="all">All</button>
        <button class="btn cve-f" data-k="sev" data-v="critical">Critical</button>
        <button class="btn cve-f" data-k="sev" data-v="high">High</button>
        <button class="btn cve-f" data-k="sev" data-v="medium">Medium</button>
        <button class="btn cve-f" data-k="sev" data-v="low">Low</button>
      </div>
      <div class="fgroup"><span class="lbl">Exploit</span>
        <button class="btn cve-f active" data-k="exp" data-v="all">All</button>
        <button class="btn cve-f" data-k="exp" data-v="exploit">Has exploit</button>
        <button class="btn cve-f" data-k="exp" data-v="kev">Known-exploited</button>
      </div>
      <button class="btn" id="cve-showall">Show hidden kernel CVEs</button>
    </div>
    <div class="note" id="cve-note"></div>
    <div class="grid" id="cve-grid"></div>
  </section>
</div>

<div class="overlay" id="overlay"><div class="modal" id="modal"></div></div>

<script id="lava-data" type="application/json">__CREDS_DATA__</script>
<script id="lava-cve-data" type="application/json">__CVE_DATA__</script>
<script>
const esc = s => String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const DATA    = JSON.parse(document.getElementById('lava-data').textContent) || [];
const CVEDATA = JSON.parse(document.getElementById('lava-cve-data').textContent) || [];
const hasCreds = Array.isArray(DATA) && DATA.length>0;
const hasCve   = Array.isArray(CVEDATA) && CVEDATA.length>0;

/* ---------------------------- shared modal ---------------------------- */
function closeModal(){document.getElementById('overlay').classList.remove('on');}
document.getElementById('overlay').onclick=e=>{if(e.target.id==='overlay')closeModal();};
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
function showModal(html){document.getElementById('modal').innerHTML=html;document.getElementById('overlay').classList.add('on');}

/* ========================== CREDENTIALS ========================== */
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
  showModal(`
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
    <pre>${esc((f.found_by_modules||[f.module]).join(', '))}</pre>`);
}

// a tab is a "seen by" SET: EMBA = emba-only OR both, Grep = custom-only OR both
function tabMatch(f,tab){
  if(tab==='all') return true;
  const s=srcOf(f);
  if(tab==='emba')   return s==='emba'||s==='both';
  if(tab==='custom') return s==='custom'||s==='both';
  if(tab==='both')   return s==='both';
  return true;
}
function rawCounts(){
  const r={emba:0,custom:0,both:0};
  DATA.forEach(f=>r[srcOf(f)]++);
  return r;
}
function searchMatch(f,t){
  return (f.file_path||'').toLowerCase().includes(t) || (f.matched_content||'').toLowerCase().includes(t)
      || (f.category||'').toLowerCase().includes(t);
}

function renderCreds(){
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
    return okV&&tabMatch(f,sourceFilter);
  });
  const g=document.getElementById('grid'); g.innerHTML='';
  rows.forEach(f=>g.appendChild(card(f)));
  if(!rows.length) g.innerHTML='<div class="empty">No findings match your criteria.</div>';
}

function credsVisibility(){
  document.getElementById('grid').classList.toggle('hidden',splitView);
  document.getElementById('split').classList.toggle('hidden',!splitView);
  document.getElementById('tabs').classList.toggle('split-mode',splitView);
  document.getElementById('controls').classList.toggle('split-mode',splitView);
}

function initCreds(){
  document.getElementById('search').addEventListener('input',renderCreds);
  document.querySelectorAll('.filter-btn').forEach(b=>b.onclick=()=>{
    document.querySelectorAll('.filter-btn').forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); verdictFilter=b.dataset.filter; renderCreds();
  });
  document.querySelectorAll('.source-tab').forEach(b=>b.onclick=()=>{
    document.querySelectorAll('.source-tab').forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); sourceFilter=b.dataset.source; renderCreds();
  });
  document.getElementById('splitToggle').onclick=function(){
    splitView=!splitView; this.classList.toggle('active',splitView); credsVisibility(); renderCreds();
  };
  document.querySelectorAll('.mini').forEach(group=>{
    const col=group.dataset.col;
    group.querySelectorAll('.btn').forEach(b=>b.onclick=()=>{
      group.querySelectorAll('.btn').forEach(x=>x.classList.remove('active'));
      b.classList.add('active'); splitVerdict[col]=b.dataset.f; renderCreds();
    });
  });
  const rc=rawCounts();
  const c={all:DATA.length,emba:rc.emba+rc.both,custom:rc.custom+rc.both,both:rc.both};
  ['all','emba','custom','both'].forEach(s=>document.getElementById('c-'+s).textContent=c[s]);
  const hasCustom=rc.custom>0||rc.both>0;
  document.getElementById('tabs').classList.toggle('hidden',!hasCustom);
  renderCreds();
}

/* ============================== CVE ============================== */
const cveFilter={av:'all',sev:'all',exp:'all',type:'all'};
let cveShowHidden=false;

function cveCard(r){
  const el=document.createElement('div');
  el.className='card sev-'+(r.severity||'unknown');
  const chips=[];
  if(r.av==='Network') chips.push('<span class="chip av-network">NET</span>');
  else if(r.av&&r.av!=='Unknown') chips.push('<span class="chip">'+esc(r.av.slice(0,3).toUpperCase())+'</span>');
  if(r.kev) chips.push('<span class="chip kev">KEV</span>');
  else if(r.has_exploit) chips.push('<span class="chip exploit">EXPLOIT</span>');
  if(r.verified) chips.push('<span class="chip verified">VERIFIED</span>');
  chips.push('<span class="badge sev-'+(r.severity||'unknown')+'">'+esc((r.severity||'?').toUpperCase())+'</span>');
  const score=(r.cvss_score!=null)?r.cvss_score.toFixed(1):'--';
  const vt=(r.vuln_type||'').trim();
  el.innerHTML=`
    <div class="card-top">
      <div>
        <div class="card-file">${esc(r.component)} ${esc(r.version||'')}</div>
        <div class="card-cat">${esc(r.cve)}</div>
      </div>
      <div class="chips">${chips.join('')}</div>
    </div>
    ${vt?`<div class="cve-type-line">${esc(vt)}</div>`:''}
    <div class="snippet wrap">${esc(r.description||'(no description)')}</div>
    <div class="foot">
      <span>${esc(r.av||'?')} &middot; ${esc(r.cvss_vector||'no vector')}</span>
      <span>CVSS ${score}</span>
    </div>`;
  el.onclick=()=>openCveModal(r);
  return el;
}

function openCveModal(r){
  const im=r.impact||{};
  showModal(`
    <button class="close" onclick="closeModal()">close</button>
    <h2>${esc(r.cve)}</h2>
    <div class="badge-group">
      <span class="badge sev-${r.severity||'unknown'}">${esc((r.severity||'?').toUpperCase())}</span>
      <span class="chip">CVSS ${r.cvss_score!=null?r.cvss_score:'--'} (v${esc(r.cvss_version||'?')})</span>
      <span class="chip">${esc(r.component)} ${esc(r.version||'')}</span>
      <span class="chip">${esc(r.source_module==='S26'?'kernel (S26)':'component (F17)')}</span>
      ${r.vuln_type?'<span class="chip">'+esc(r.vuln_type)+'</span>':''}
      ${r.kev?'<span class="chip kev">KNOWN-EXPLOITED</span>':''}
      ${r.verified?'<span class="chip verified">kernel-verified: '+esc(r.verified)+'</span>':''}
    </div>
    <h3>Description</h3>
    <div class="reason">${esc(r.description||'(none)')}</div>
    <h3>CVSS vector</h3>
    <div class="kv">
      <b>Attack vector</b><span>${esc(r.av||'?')}</span>
      <b>Attack complexity</b><span>${esc(r.ac||'?')}</span>
      <b>Privileges required</b><span>${esc(r.pr||'n/a')}</span>
      <b>User interaction</b><span>${esc(r.ui||'n/a')}</span>
      <b>Impact C/I/A</b><span>${esc(im.c||'?')} / ${esc(im.i||'?')} / ${esc(im.a||'?')}</span>
      <b>Raw</b><span>${esc(r.cvss_vector||'(none)')}</span>
    </div>
    <h3>Exploit / PoC</h3>
    <pre>${r.exploit_sources&&r.exploit_sources.length?esc(r.exploit_sources.join('\n')):'No exploit or PoC referenced by EMBA.'}</pre>
    ${r.cwe&&r.cwe.length?'<h3>CWE</h3><pre>'+esc(r.cwe.map(c=>'CWE-'+c).join(', '))+'</pre>':''}`);
}

function cveMatch(r,t){
  if(t && !((r.cve||'').toLowerCase().includes(t)||(r.component||'').toLowerCase().includes(t)
      ||(r.description||'').toLowerCase().includes(t))) return false;
  if(!cveShowHidden && r.default_hidden) return false;
  if(cveFilter.av!=='all' && r.av!==cveFilter.av) return false;
  if(cveFilter.sev!=='all' && r.severity!==cveFilter.sev) return false;
  if(cveFilter.exp==='exploit' && !r.has_exploit) return false;
  if(cveFilter.exp==='kev' && !r.kev) return false;
  if(cveFilter.type==='__unclassified__' && (r.vuln_type||'')!=='') return false;
  if(cveFilter.type!=='all' && cveFilter.type!=='__unclassified__' && r.vuln_type!==cveFilter.type) return false;
  return true;
}

function renderCve(){
  const t=document.getElementById('cve-search').value.toLowerCase();
  const rows=CVEDATA.filter(r=>cveMatch(r,t));
  const g=document.getElementById('cve-grid'); g.innerHTML='';
  rows.forEach(r=>g.appendChild(cveCard(r)));
  if(!rows.length) g.innerHTML='<div class="empty">No CVEs match your criteria.</div>';
  const hidden=CVEDATA.filter(r=>r.default_hidden).length;
  document.getElementById('cve-note').textContent=
    `${rows.length} shown${(!cveShowHidden&&hidden)?`  ·  ${hidden} lower-severity kernel CVEs hidden (click "Show hidden kernel CVEs")`:''}`;
}

function initCve(){
  document.getElementById('cve-search').addEventListener('input',renderCve);
  document.getElementById('cve-type').addEventListener('change',function(){cveFilter.type=this.value;renderCve();});
  document.querySelectorAll('.cve-f').forEach(b=>b.onclick=()=>{
    document.querySelectorAll(`.cve-f[data-k="${b.dataset.k}"]`).forEach(x=>x.classList.remove('active'));
    b.classList.add('active'); cveFilter[b.dataset.k]=b.dataset.v; renderCve();
  });
  document.getElementById('cve-showall').onclick=function(){
    cveShowHidden=!cveShowHidden; this.classList.toggle('active',cveShowHidden);
    this.textContent=cveShowHidden?'Hide lower-severity kernel CVEs':'Show hidden kernel CVEs';
    renderCve();
  };
  renderCve();
}

/* ========================= module switch ========================= */
function setStats(mod){
  const s=document.getElementById('stats');
  if(mod==='cve'){
    const crit=CVEDATA.filter(r=>r.severity==='critical'||r.severity==='high').length;
    const exp=CVEDATA.filter(r=>r.has_exploit).length;
    s.innerHTML=`<div class="stat"><span class="v">${CVEDATA.length}</span><span class="l">CVEs</span></div>
      <div class="stat warn"><span class="v">${crit}</span><span class="l">high / critical</span></div>
      <div class="stat tp"><span class="v">${exp}</span><span class="l">with exploit</span></div>`;
  }else{
    const tp=DATA.filter(f=>f.predicted_verdict==='TP').length;
    const fp=DATA.filter(f=>f.predicted_verdict==='FP').length;
    s.innerHTML=`<div class="stat"><span class="v">${DATA.length}</span><span class="l">findings</span></div>
      <div class="stat tp"><span class="v">${tp}</span><span class="l">true positive</span></div>
      <div class="stat fp"><span class="v">${fp}</span><span class="l">false positive</span></div>`;
  }
}
function setModule(mod){
  document.getElementById('mod-creds').classList.toggle('hidden',mod!=='creds');
  document.getElementById('mod-cve').classList.toggle('hidden',mod!=='cve');
  document.querySelectorAll('#moduleNav button').forEach(b=>b.classList.toggle('active',b.dataset.module===mod));
  setStats(mod);
}

(function(){
  document.getElementById('sub').textContent='Local AI Vulnerability Auditor  ·  '+new Date().toISOString().slice(0,16).replace('T',' ');
  document.getElementById('mn-creds').textContent=DATA.length;
  document.getElementById('mn-cve').textContent=CVEDATA.length;

  if(hasCreds) initCreds();
  if(hasCve)   initCve();

  const both=hasCreds&&hasCve;
  document.getElementById('moduleNav').classList.toggle('hidden',!both);
  if(both){
    document.querySelectorAll('#moduleNav button').forEach(b=>b.onclick=()=>setModule(b.dataset.module));
  }
  setModule(hasCreds?'creds':'cve');
})();
</script>
</body>
</html>
"""


def _load_list(path: str, label: str) -> list:
    if not path:
        return []
    if not os.path.exists(path):
        print(f"Error: {label} {path} not found.")
        sys.exit(1)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading {path}: {e}")
        sys.exit(1)
    return data if isinstance(data, list) else []


def _embed(data: list) -> str:
    return (json.dumps(data, ensure_ascii=False)
            .replace("<", "\\u003c").replace("\u2028", " ").replace("\u2029", " "))


def generate_report(verdicts_file: str, cve_file: str, out_file: str) -> None:
    findings = _load_list(verdicts_file, "verdicts")
    cve_findings = _load_list(cve_file, "cve-findings")

    if not verdicts_file and not cve_file:
        print("Error: give --verdicts and/or --cve-findings.")
        sys.exit(1)

    rank = {"TP": 0, "FP": 1}
    findings.sort(key=lambda f: rank.get(str(f.get("predicted_verdict", "")).upper(), 2))

    page = (_PAGE
            .replace("__CREDS_DATA__", _embed(findings))
            .replace("__CVE_DATA__", _embed(cve_findings)))
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(page)
    print(f"[OK] report -> {out_file} "
          f"({len(findings)} credential findings, {len(cve_findings)} CVEs)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate the LAVA HTML report")
    ap.add_argument("--verdicts", help="Path to verdicts.json (credentials module)")
    ap.add_argument("--cve-findings", dest="cve_findings", help="Path to cve_findings.json (CVE module)")
    ap.add_argument("--out", required=True, help="Output HTML file")
    args = ap.parse_args()
    if not args.verdicts and not args.cve_findings:
        ap.error("give --verdicts and/or --cve-findings")
    generate_report(args.verdicts, args.cve_findings, args.out)
