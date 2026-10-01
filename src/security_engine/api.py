from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .aggregation import active_window_keys
from .config import settings
from .decision import LocalJevProvider, MockProvider
from .engine import analyze
from .models import SecurityEvent
from .parser import parse_line
from .storage import Store

store = Store(settings.database)
provider = LocalJevProvider(settings.local_jev_base_url, settings.local_jev_model, settings.decision_timeout) if settings.decision_provider == "local_jev" else MockProvider()

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="Security Decision Engine", version="0.1.0", lifespan=lifespan)

@app.get("/healthz")
def health():
    return {"status": "ok", "provider": settings.decision_provider, "mode": settings.mode}

@app.get("/api/stats")
def stats():
    return store.stats()

@app.get("/api/assessments")
def list_assessments(limit: int = 200):
    return [x.model_dump(mode="json") for x in store.assessments(max(1, min(limit, 1000)))]

@app.get("/api/assessments/{entity}")
def get_entity(entity: str):
    items = [x for x in store.assessments(2000) if x.entity == entity]
    if not items:
        raise HTTPException(404, "entity not found")
    return [x.model_dump(mode="json") for x in items]

@app.get("/api/events/{source_ip}")
def event_timeline(source_ip: str, limit: int = 100):
    events = store.timeline(source_ip, max(1, min(limit, 500)))
    return [{"timestamp": e.timestamp.isoformat(), "method": e.method, "path": e.path, "status": e.status,
             "request_time": e.request_time} for e in events]

@app.post("/api/ingest")
async def ingest_json(events: list[SecurityEvent]):
    if not events:
        return {"ingested": 0, "assessments": 0}
    known_sources = store.source_ips()
    active = active_window_keys(events)
    store.add_events(events)
    five_minute_starts = [start for _, _, window, start in active if window == "5m"]
    start = min(five_minute_starts) if five_minute_starts else min(e.timestamp for e in events)
    source = store.recent_events(start, {e.source_ip for e in events}, {e.session_hash for e in events if e.session_hash})
    results = await analyze(source, provider, settings.mode, known_sources=known_sources, active_windows=active)
    for result in results:
        store.add_assessment(result)
    return {"ingested": len(events), "assessments": len(results)}

@app.post("/api/analyze")
async def reanalyze():
    events = store.events()
    results = await analyze(events, provider, settings.mode)
    for result in results:
        store.add_assessment(result)
    return {"assessments": len(results)}

@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD)

DASHBOARD = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Security Decision Engine</title>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#121d30;--line:#25344b;--muted:#93a4ba;--cyan:#69d5d0;--red:#ff817e;--amber:#f1bd62;--green:#6bd49a}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#e9f1fc;font:15px Inter,system-ui,sans-serif}.wrap{max-width:1320px;margin:auto;padding:28px}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 16px}.pill{border:1px solid #315c5a;color:var(--cyan);border-radius:20px;padding:7px 12px;font-size:12px}.cards{display:grid;grid-template-columns:repeat(7,1fr);gap:12px;margin:20px 0}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px}.label{color:var(--muted);font-size:12px}.value{font-size:26px;font-weight:650;margin-top:9px}.layout{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}.panel{min-width:0}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-weight:500}.risk{font-weight:700}.HIGH_RISK{color:var(--red)}.SUSPICIOUS{color:var(--amber)}.UNCERTAIN{color:#c4a4ff}.BENIGN{color:var(--green)}button{background:#173344;color:var(--cyan);border:1px solid #315c5a;border-radius:7px;padding:8px 12px;cursor:pointer}.sub{color:var(--muted);font-size:12px}.detail{line-height:1.7;font-size:13px;max-height:520px;overflow:auto}.bar{height:8px;background:#26364c;border-radius:5px;overflow:hidden}.bar i{display:block;height:100%;background:var(--cyan)}pre{white-space:pre-wrap;color:#bfd0e6}@media(max-width:900px){.cards{grid-template-columns:repeat(3,1fr)}.layout{grid-template-columns:1fr}}@media(max-width:500px){.wrap{padding:14px}.cards{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main class="wrap"><header><div><h1>Security Decision Engine</h1><div class="sub">Behavior based detection · local triage · shadow mode</div></div><div class="pill">RULE　JEV　HYBRID</div></header>
<section class="cards" id="stats"></section><section class="layout"><div class="panel"><h2>Risk entities <button style="float:right" onclick="load()">Refresh</button></h2><div class="tablewrap"><table><thead><tr><th>Source</th><th>Risk</th><th>Result</th><th>Category</th><th>Confidence</th><th>Rule</th><th>Jev</th><th>Last seen</th></tr></thead><tbody id="rows"></tbody></table></div></div><div class="panel"><h2>Entity detail</h2><div id="detail" class="detail sub">Select an entity to inspect its features, rule evidence and Jev answers.</div></div></section>
<p class="sub">Local mode keeps event data in SQLite. This product only detects and triages; it never blocks traffic.</p></main><script>
function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function load(){let s=await(await fetch('/api/stats')).json();let keys=[['Total events','total_events'],['Entities','entities'],['Suspicious','suspicious'],['High risk','high_risk'],['Uncertain','uncertain'],['Alert reduction','alert_reduction'],['Jev latency','jev_latency_ms']];document.querySelector('#stats').innerHTML=keys.map(([n,k])=>`<div class="card"><div class="label">${n}</div><div class="value">${s[k]??(k==='alert_reduction'||k==='jev_latency_ms'?'—':0)}${k==='jev_latency_ms'&&s[k]!=null?' ms':''}</div></div>`).join('');let a=await(await fetch('/api/assessments?limit=300')).json();let seen=new Set;a=a.filter(x=>{let k=x.entity_type+':'+x.entity;if(seen.has(k))return false;seen.add(k);return true});document.querySelector('#rows').innerHTML=a.map(x=>`<tr onclick="detail('${encodeURIComponent(x.entity)}')"><td>${esc(x.entity)}</td><td class="risk ${x.disposition}">${x.hybrid_risk.toFixed(0)}</td><td class="${x.disposition}">${x.disposition}</td><td>${esc(x.category)}</td><td>${Math.round(x.confidence*100)}%</td><td>${x.rule_risk}</td><td>${x.jev_risk==null?'—':x.jev_risk.toFixed(0)}</td><td>${new Date(x.ended_at).toLocaleString()}</td></tr>`).join('')||'<tr><td colspan="8" class="sub">No data yet. Import sample data with the CLI.</td></tr>'}
async function detail(e){let a=await(await fetch('/api/assessments/'+e)).json();let first=a[0];let timeline=first.entity_type==='source_ip'?await(await fetch('/api/events/'+e)).json():[];document.querySelector('#detail').innerHTML=a.map(x=>`<h3>${esc(x.entity)} · ${x.window} · <span class="${x.disposition}">${x.disposition}</span></h3><div class="sub">${x.started_at} – ${x.ended_at} · ${x.request_count} requests</div><p>RULE risk <b>${x.rule_risk}</b>　JEV risk <b>${x.jev_risk?.toFixed(1)??'—'}</b>　HYBRID <b>${x.hybrid_risk}</b></p><div class="bar"><i style="width:${Math.min(100,x.hybrid_risk)}%"></i></div><p><b>Features</b></p><pre>${esc(JSON.stringify(x.features,null,2))}</pre><p><b>Rules</b></p><pre>${esc(JSON.stringify(x.rules,null,2))}</pre><p><b>Jev</b></p><pre>${esc(JSON.stringify(x.jev,null,2))}</pre>`).join('<hr>')+(timeline.length?`<hr><p><b>Timeline</b></p><pre>${esc(JSON.stringify(timeline,null,2))}</pre>`:'')}
load();setInterval(load,10000);
</script></body></html>'''
