from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .aggregation import active_window_keys
from .config import settings
from .decision import LocalJevProvider, MockProvider, PrefilterProvider
from .engine import analyze
from .models import SecurityEvent
from .parser import parse_line
from .storage import Store

store = Store(settings.database)
_base_provider = LocalJevProvider(settings.local_jev_base_url, settings.local_jev_model, settings.decision_timeout) if settings.decision_provider == "local_jev" else MockProvider()
provider = PrefilterProvider(_base_provider) if settings.jev_prefilter and settings.decision_provider == "local_jev" else _base_provider

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        yield
    finally:
        closeable = getattr(provider, "provider", provider)
        if hasattr(closeable, "aclose"):
            await closeable.aclose()

app = FastAPI(title="JevSec Security Decision Engine", version="0.2.0", lifespan=lifespan)

@app.middleware("http")
async def bind_auth_guard(request: Request, call_next):
    if settings.auth_required:
        import base64, hmac
        expected = (settings.auth_username, settings.auth_password)
        supplied = ("", "")
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                supplied = tuple(base64.b64decode(header[6:], validate=True).decode().split(":", 1))
            except (ValueError, UnicodeError):
                pass
        if (not settings.auth_username or not settings.auth_password or len(supplied) != 2 or
                not all(hmac.compare_digest(a, b) for a, b in zip(expected, supplied))):
            return JSONResponse({"detail": "authentication required"}, status_code=401, headers={"WWW-Authenticate": "Basic"})
    return await call_next(request)

@app.get("/healthz")
def health():
    return {"status": "ok", "provider": settings.decision_provider, "mode": settings.mode}

@app.get("/api/stats")
def stats():
    return store.stats()

@app.get("/api/provider")
def provider_status():
    return {"provider": settings.decision_provider, "model": settings.local_jev_model,
            "prefilter_enabled": settings.jev_prefilter,
            "metrics": provider.metrics() if hasattr(provider, "metrics") else {}}

@app.get("/api/assessments")
def list_assessments(limit: int = 200):
    return [x.model_dump(mode="json") for x in store.assessments(max(1, min(limit, 1000)))]

@app.get("/api/risk-history")
def risk_history(limit: int = 200):
    return [x.model_dump(mode="json") for x in store.risk_history(max(1, min(limit, 1000)))]

@app.get("/api/assessments/{entity}")
def get_entity(entity: str):
    items = [x for x in store.assessments(2000) if x.entity == entity]
    if not items:
        raise HTTPException(404, "entity not found")
    return [x.model_dump(mode="json") for x in items]

@app.get("/api/stories")
def list_stories(limit: int = 100):
    from .stories import build_attack_stories
    return build_attack_stories(store.events(), max(1, min(limit, 500)), store.assessments(1000))

@app.post("/api/feedback")
async def submit_feedback(payload: dict):
    allowed = {"entity", "entity_type", "window", "label"}
    if set(payload) != allowed or not all(isinstance(payload[k], str) for k in allowed):
        raise HTTPException(422, "expected entity, entity_type, window and label strings")
    if payload["entity_type"] not in {"source_ip", "session", "user"} or payload["label"] not in {"true_positive", "false_positive", "unsure"}:
        raise HTTPException(422, "invalid feedback entity type or label")
    store.feedback(payload["entity"], payload["entity_type"], payload["window"], payload["label"])
    return {"saved": True}

@app.get("/api/feedback")
def list_feedback(limit: int = 1000):
    return store.feedback_rows(max(1, min(limit, 1000)))

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
    baseline_events = store.context_history(events)
    active = active_window_keys(events)
    store.add_events(events)
    five_minute_starts = [start for _, _, window, start in active if window == "5m"]
    start = min(five_minute_starts) if five_minute_starts else min(e.timestamp for e in events)
    source = store.recent_events(start, {e.source_ip for e in events}, {e.session_hash for e in events if e.session_hash}, {e.user_id for e in events if e.user_id})
    results = await analyze(source, provider, settings.mode, known_sources=known_sources, active_windows=active, baseline_events=baseline_events)
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
:root{color-scheme:dark;--bg:#0b1220;--panel:#121d30;--line:#25344b;--muted:#93a4ba;--cyan:#69d5d0;--red:#ff817e;--amber:#f1bd62;--green:#6bd49a}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#e9f1fc;font:15px Inter,system-ui,sans-serif}.wrap{max-width:1320px;margin:auto;padding:28px}header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}h1{font-size:24px;margin:0}h2{font-size:16px;margin:0 0 16px}.pill{border:1px solid #315c5a;color:var(--cyan);border-radius:20px;padding:7px 12px;font-size:12px}.cards{display:grid;grid-template-columns:repeat(8,1fr);gap:12px;margin:20px 0}.card,.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:17px}.label{color:var(--muted);font-size:12px}.value{font-size:26px;font-weight:650;margin-top:9px}.layout{display:grid;grid-template-columns:1.4fr 1fr;gap:14px}.panel{min-width:0}.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);white-space:nowrap}th{color:var(--muted);font-weight:500}.risk{font-weight:700}.HIGH_RISK{color:var(--red)}.REVIEW,.SUSPICIOUS{color:var(--amber)}.UNCERTAIN{color:#c4a4ff}.BENIGN{color:var(--green)}button{background:#173344;color:var(--cyan);border:1px solid #315c5a;border-radius:7px;padding:8px 12px;cursor:pointer}.sub{color:var(--muted);font-size:12px}.detail{line-height:1.7;font-size:13px;max-height:520px;overflow:auto}.bar{height:8px;background:#26364c;border-radius:5px;overflow:hidden}.bar i{display:block;height:100%;background:var(--cyan)}pre{white-space:pre-wrap;color:#bfd0e6}@media(max-width:900px){.cards{grid-template-columns:repeat(3,1fr)}.layout{grid-template-columns:1fr}}@media(max-width:500px){.wrap{padding:14px}.cards{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main class="wrap"><header><div><h1>Security Decision Engine</h1><div class="sub">Behavior based detection · local triage · shadow mode</div></div><div class="pill">RULE　JEV　HYBRID</div></header>
<section class="cards" id="stats"></section><section class="layout"><div class="panel"><h2>Risk entities <label class="sub">View <select id="mode" onchange="renderRows()"><option value="hybrid">Hybrid</option><option value="rules">Rules</option><option value="jev">Jev</option></select></label><button style="float:right" onclick="load()">Refresh</button></h2><div class="tablewrap"><table><thead><tr><th>Entity</th><th>Risk</th><th>Result</th><th>Category</th><th>Confidence</th><th>Rule</th><th>Jev</th><th>Last seen</th></tr></thead><tbody id="rows"></tbody></table></div></div><div class="panel"><h2>Entity detail</h2><div id="detail" class="detail sub">Select an entity to inspect evidence and submit feedback.</div></div></section><section class="panel" style="margin-top:14px"><h2>Risk over time</h2><div id="risk-history" class="detail sub">Loading risk history…</div></section><section class="panel" style="margin-top:14px"><h2>Attack stories</h2><div id="stories" class="detail sub">Loading structured stories…</div></section>
<p class="sub">Local mode keeps event data in SQLite. This product only detects and triages; it never blocks traffic.</p></main><script>
function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
let assessments=[];function renderRows(){let mode=document.querySelector('#mode').value;document.querySelector('#rows').innerHTML=assessments.map(x=>{let value=mode==='rules'?x.rule_risk:mode==='jev'?(x.jev_risk??0):x.hybrid_risk;let threshold=mode==='rules'?55:(x.features.calibration_threshold??55);let disposition=mode==='hybrid'?x.disposition:(mode==='jev'&&x.confidence<.52?'UNCERTAIN':value>=78?'HIGH_RISK':value>=threshold?'REVIEW':'BENIGN');return `<tr onclick="detail('${encodeURIComponent(x.entity)}')"><td>${esc(x.entity)} <span class="sub">${esc(x.entity_type)}</span></td><td class="risk ${disposition}">${value.toFixed(0)}</td><td class="${disposition}">${disposition}</td><td>${esc(x.category)}</td><td>${Math.round(x.confidence*100)}%</td><td>${x.rule_risk}</td><td>${x.jev_risk==null?'—':x.jev_risk.toFixed(0)}</td><td>${new Date(x.ended_at).toLocaleString()}</td></tr>`}).join('')||'<tr><td colspan="8" class="sub">No data yet. Import sample data with the CLI.</td></tr>'}
async function load(){let s=await(await fetch('/api/stats')).json();let keys=[['Events','total_events'],['Entities','entities'],['Review','review'],['High risk','high_risk'],['Alert reduction','alert_reduction'],['Attack retention','attack_retention'],['Jev latency','jev_latency_ms'],['Feedback','feedback_count']];document.querySelector('#stats').innerHTML=keys.map(([n,k])=>`<div class="card"><div class="label">${n}</div><div class="value">${s[k]??'—'}${k==='jev_latency_ms'&&s[k]!=null?' ms':''}</div></div>`).join('');let a=await(await fetch('/api/assessments?limit=300')).json();let seen=new Set;assessments=a.filter(x=>{let k=x.entity_type+':'+x.entity;if(seen.has(k))return false;seen.add(k);return true});renderRows();let history=await(await fetch('/api/risk-history?limit=100')).json();document.querySelector('#risk-history').innerHTML=drawRisk(history);let stories=await(await fetch('/api/stories?limit=30')).json();document.querySelector('#stories').innerHTML=stories.map(st=>`<details><summary>${esc(st.entity_type)} ${esc(st.entity)} · risk ${st.risk} · ${st.stage_count} stages</summary>${st.stages.map(q=>`<p>${esc(q.time)} · ${esc(q.event)} · risk ${q.risk} (+${q.risk_delta}) · ${esc(q.jev_judgment)}</p><pre>${esc(JSON.stringify({rules:q.rule_hits,evidence:q.evidence},null,2))}</pre>`).join('')}</details>`).join('')||'No structured multi-stage story yet.'}
function drawRisk(rows){if(!rows.length)return 'No assessment history yet.';let w=780,h=170,p=18,n=rows.length;let y=v=>h-p-(Math.max(0,Math.min(100,v))/100)*(h-2*p);let x=i=>p+(n<2?0:i*(w-2*p)/(n-1));let line=key=>rows.map((r,i)=>`${x(i).toFixed(1)},${y(r[key]??0).toFixed(1)}`).join(' ');return `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Rules, Jev and Hybrid risk scores over time" style="width:100%;height:auto"><path d="M${p} ${y(0)}H${w-p} M${p} ${y(50)}H${w-p} M${p} ${y(100)}H${w-p}" stroke="#35465e" fill="none"/><polyline points="${line('rule_risk')}" fill="none" stroke="#69d5d0" stroke-width="2"/><polyline points="${line('jev_risk')}" fill="none" stroke="#c4a4ff" stroke-width="2"/><polyline points="${line('hybrid_risk')}" fill="none" stroke="#ff817e" stroke-width="2"/></svg><p>Rules <span style="color:#69d5d0">━</span>　Jev <span style="color:#c4a4ff">━</span>　Hybrid <span style="color:#ff817e">━</span>　<span class="sub">${esc(rows[0].ended_at)} → ${esc(rows[rows.length-1].ended_at)}</span></p>`}
async function detail(e){let a=await(await fetch('/api/assessments/'+e)).json();let first=a[0];let timeline=first.entity_type==='source_ip'?await(await fetch('/api/events/'+e)).json():[];document.querySelector('#detail').innerHTML=a.map(x=>`<h3>${esc(x.entity)} · ${x.window} · <span class="${x.disposition}">${x.disposition}</span></h3><div class="sub">${x.started_at} – ${x.ended_at} · ${x.request_count} requests</div><p>RULE <b>${x.rule_risk}</b>　JEV <b>${x.jev_risk?.toFixed(1)??'—'}</b>　HYBRID <b>${x.hybrid_risk}</b></p><div class="bar"><i style="width:${Math.min(100,x.hybrid_risk)}%"></i></div><p><button onclick="feedback('${esc(x.entity)}','${x.entity_type}','${x.window}','true_positive')">True Positive</button> <button onclick="feedback('${esc(x.entity)}','${x.entity_type}','${x.window}','false_positive')">False Positive</button> <button onclick="feedback('${esc(x.entity)}','${x.entity_type}','${x.window}','unsure')">Unsure</button></p><p><b>Features / rules / Jev evidence</b></p><pre>${esc(JSON.stringify({features:x.features,rules:x.rules,jev:x.jev},null,2))}</pre>`).join('<hr>')+(timeline.length?`<hr><p><b>Timeline</b></p><pre>${esc(JSON.stringify(timeline,null,2))}</pre>`:'')}
async function feedback(entity,entity_type,window,label){let r=await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({entity,entity_type,window,label})});if(r.ok){alert('Feedback saved locally.');load()}}
load();setInterval(load,10000);
</script></body></html>'''
