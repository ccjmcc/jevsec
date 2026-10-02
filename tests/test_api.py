from fastapi.testclient import TestClient
from dataclasses import replace
from security_engine import api
from security_engine.storage import Store

def test_api_health_and_dashboard(tmp_path,monkeypatch):
    monkeypatch.setattr(api,'store',Store(tmp_path/'api.db'))
    c=TestClient(api.app)
    assert c.get('/healthz').status_code==200
    assert 'RULE' in c.get('/').text
    r=c.post('/api/ingest',json=[{'source_ip':'192.0.2.9','status':200,'path':'/'}])
    assert r.status_code==200 and r.json()['ingested']==1
    assert c.get('/api/stats').json()['total_events']==1
    assert c.get('/api/events/192.0.2.9').json()[0]['path']=='/'
    assert c.get('/api/risk-history').status_code==200
    feedback=c.post('/api/feedback',json={'entity':'192.0.2.9','entity_type':'source_ip','window':'1m','label':'false_positive'})
    assert feedback.json()=={'saved':True}
    assert c.get('/api/feedback').json()[0]['label']=='false_positive'
    assert c.get('/api/stories').status_code==200
    assert c.get('/').text.index('Risk over time') < c.get('/').text.index('Attack stories')

def test_nonlocal_guard_requires_valid_basic_auth(tmp_path,monkeypatch):
    monkeypatch.setattr(api,'store',Store(tmp_path/'auth.db'))
    monkeypatch.setattr(api,'settings',replace(api.settings,auth_required=True,auth_username='ops',auth_password='correct-horse'))
    c=TestClient(api.app)
    assert c.get('/healthz').status_code==401
    assert c.get('/healthz',auth=('ops','wrong')).status_code==401
    import base64
    assert c.get('/healthz',headers={'Authorization':'Basic '+base64.b64encode(b'ops').decode()}).status_code==401
    assert c.get('/healthz',auth=('ops','correct-horse')).status_code==200
