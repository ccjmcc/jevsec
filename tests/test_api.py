from fastapi.testclient import TestClient
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
