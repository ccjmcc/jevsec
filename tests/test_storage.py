from datetime import datetime, timezone, timedelta
import pytest
from security_engine.aggregation import active_window_keys
from security_engine.engine import analyze
from security_engine.models import SecurityEvent
from security_engine.storage import Store

def test_pseudonymous_ids_are_stable_across_storage(tmp_path):
    db=Store(tmp_path/'s.db')
    e=SecurityEvent(source_ip='192.0.2.2',session_hash='raw-session-id',request_id='raw-request-id')
    db.add_events([e])
    loaded=db.events()[0]
    assert loaded.session_hash==e.session_hash
    assert loaded.request_id==e.request_id
    assert 'raw-session-id' not in loaded.model_dump_json()

@pytest.mark.asyncio
async def test_incremental_window_reads_prior_events_for_active_entities(tmp_path):
    db=Store(tmp_path/'recent.db')
    start=datetime(2026,10,1,10,10,10,tzinfo=timezone.utc)
    first=SecurityEvent(timestamp=start,source_ip='192.0.2.5',status=401,auth_result='failure',session_hash='s')
    latest=SecurityEvent(timestamp=start+timedelta(seconds=20),source_ip='192.0.2.5',path='/login',status=200,auth_result='success',session_hash='s')
    db.add_events([first])
    known=db.source_ips()
    db.add_events([latest])
    active=active_window_keys([latest])
    recent=db.recent_events(start.replace(second=0),{'192.0.2.5'},{latest.session_hash})
    results=await analyze(recent,mode='rules_only',known_sources=known,active_windows=active)
    source=next(x for x in results if x.entity_type=='source_ip' and x.window=='1m')
    assert source.request_count==2
    assert source.features['auth_failure_then_success'] is True
