from __future__ import annotations

from . import __version__


def dashboard_html() -> bytes:
    html = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PSMatrix Operations</title>
<style>
:root{color-scheme:dark;--bg:#0c1117;--panel:#131a22;--line:#26313d;--text:#e6edf3;--muted:#9da9b5;--ok:#3fb950;--warn:#d29922;--bad:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}header{position:sticky;top:0;z-index:2;display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid var(--line);background:#0c1117e8;backdrop-filter:blur(10px)}h1{font-size:18px;margin:0}main{padding:18px;max-width:1600px;margin:auto}.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}.metric{font-size:28px;font-weight:700}.muted{color:var(--muted)}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}section{margin-top:18px}h2{font-size:15px;margin:0 0 10px}table{width:100%;border-collapse:collapse;display:block;overflow:auto;white-space:nowrap}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:600}.pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#253141}.controls{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}input,select,button{background:#0d141c;color:var(--text);border:1px solid var(--line);padding:7px 9px;border-radius:6px}button{cursor:pointer}button:hover{border-color:var(--accent)}pre{margin:0;overflow:auto;max-height:420px;font-size:12px}.alert{border-left:3px solid var(--warn);padding:8px 10px;margin:6px 0;background:#1b2025}.alert.critical{border-color:var(--bad)}footer{color:var(--muted);padding:20px;text-align:center}
</style>
</head>
<body>
<header><h1>PSMatrix Operations</h1><div><span id="version"></span> · <span id="updated" class="muted">loading</span></div></header>
<main>
<div id="summary" class="grid"></div>
<section class="grid"><div class="card"><h2>Alerts</h2><div id="alerts"></div></div><div class="card"><h2>Certificate expiry</h2><div id="certs"></div></div></section>
<section class="card"><h2>Workers</h2><table><thead><tr><th>Worker</th><th>Runtime</th><th>State</th><th>Failures</th><th>Last health</th></tr></thead><tbody id="workers"></tbody></table></section>
<section class="card"><h2>Validation and queue jobs</h2><table><thead><tr><th>ID</th><th>Type/runtime</th><th>State</th><th>Created</th><th>Error</th></tr></thead><tbody id="jobs"></tbody></table></section>
<section class="card"><h2>Sessions</h2><table><thead><tr><th>Session</th><th>State</th><th>Files</th><th>Bytes</th><th>Delivery</th><th>Audit</th><th>Expires</th></tr></thead><tbody id="sessions"></tbody></table></section>
<section class="card"><h2>Recent reports</h2><table><thead><tr><th>Name</th><th>Kind</th><th>Status</th><th>Size</th><th>Modified</th></tr></thead><tbody id="reports"></tbody></table></section>
<section class="card"><h2>Audit search</h2><div class="controls"><input id="auditQuery" placeholder="text or hash"><input id="auditAction" placeholder="action"><button id="auditButton">Search</button></div><pre id="auditOutput">No search run.</pre></section>
</main><footer>Read-only dashboard. It cannot run tests, alter workers, or bypass delivery gates.</footer>
<script>
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const bytes=n=>{n=Number(n||0);for(const u of ['B','KiB','MiB','GiB']){if(n<1024)return n.toFixed(n<10&&u!='B'?1:0)+' '+u;n/=1024}return n.toFixed(1)+' TiB'};
const state=v=>{v=String(v||'UNKNOWN');const c=/PASS|ACTIVE|COMPLETE|READY/.test(v)?'ok':/FAIL|REVOKED|QUARANTINED|INVALID/.test(v)?'bad':'warn';return `<span class="pill ${c}">${esc(v)}</span>`};
async function api(path){const r=await fetch(path,{headers:{Accept:'application/json'},cache:'no-store'});if(!r.ok)throw new Error(`${r.status} ${await r.text()}`);return r.json()}
function metric(label,value,detail=''){return `<div class="card"><div class="muted">${esc(label)}</div><div class="metric">${esc(value)}</div><div class="muted">${esc(detail)}</div></div>`}
async function refresh(){try{const d=await api('/api/v1/ops/snapshot');document.getElementById('version').textContent='v'+d.version;document.getElementById('updated').textContent=new Date(d.generated_at).toLocaleString();const s=d.summary;document.getElementById('summary').innerHTML=[metric('Active sessions',s.active_sessions,`${s.delivery_ready} delivery-ready`),metric('Active workers',s.active_workers,`${s.quarantined_workers} quarantined`),metric('Queue',s.queued_jobs,'queued jobs'),metric('Validation',s.running_validations,'running jobs'),metric('Runtimes',s.healthy_runtimes,'healthy'),metric('Mirror',s.mirror_packages,'packages'),metric('Alerts',s.alerts,'current')].join('');document.getElementById('alerts').innerHTML=d.alerts.length?d.alerts.map(a=>`<div class="alert ${a.severity}"><b>${esc(a.code)}</b> · ${esc(a.count)}</div>`).join(''):'<span class="ok">No active alerts</span>';document.getElementById('certs').innerHTML=d.certificates.items.length?d.certificates.items.slice(0,12).map(c=>`<div>${esc(c.name)} · <span class="${c.critical?'bad':c.warning?'warn':'ok'}">${esc(c.days_remaining)} days</span></div>`).join(''):'<span class="muted">No certificates discovered</span>';document.getElementById('workers').innerHTML=d.fleet.workers.map(w=>`<tr><td>${esc(w.worker_id)}</td><td>${esc(w.runtime_id)}</td><td>${state(w.state)}</td><td>${esc(w.consecutive_failures)}</td><td>${esc(w.health.checked_at||'-')}</td></tr>`).join('');const jobs=[...(d.validation_jobs.jobs||[]).map(j=>({...j,type:'validation'})),...(d.queue.jobs||[]).map(j=>({...j,type:j.runtime_id}))];document.getElementById('jobs').innerHTML=jobs.slice(0,100).map(j=>`<tr><td>${esc(j.job_id)}</td><td>${esc(j.type)}</td><td>${state(j.state||j.status)}</td><td>${esc(j.created_at||'-')}</td><td>${esc(j.last_error||j.error||'-')}</td></tr>`).join('');document.getElementById('sessions').innerHTML=d.sessions.items.map(x=>`<tr><td>${esc(x.session_id)}</td><td>${state(x.state)}</td><td>${esc(x.files||0)}</td><td>${bytes(x.bytes)}</td><td>${state(x.delivery?.ready?'READY':'BLOCKED')}</td><td>${state(x.audit?.valid?'VALID':'INVALID')}</td><td>${esc(x.expires_at||'-')}</td></tr>`).join('');document.getElementById('reports').innerHTML=d.reports.items.slice(0,100).map(r=>`<tr><td>${esc(r.name)}</td><td>${esc(r.kind||'-')}</td><td>${state(r.status||r.status_bucket)}</td><td>${bytes(r.size)}</td><td>${esc(r.modified_at)}</td></tr>`).join('')}catch(e){document.getElementById('alerts').innerHTML=`<div class="alert critical">${esc(e)}</div>`}}
document.getElementById('auditButton').onclick=async()=>{const q=encodeURIComponent(document.getElementById('auditQuery').value),a=encodeURIComponent(document.getElementById('auditAction').value);try{const d=await api(`/api/v1/ops/audit?query=${q}&action=${a}&limit=100`);document.getElementById('auditOutput').textContent=JSON.stringify(d,null,2)}catch(e){document.getElementById('auditOutput').textContent=String(e)}};
refresh();setInterval(refresh,10000);
</script>
</body></html>'''
    return html.replace("__VERSION__", __version__).encode("utf-8")
