from datetime import datetime, timezone, timedelta
from security_engine.aggregation import aggregate
from security_engine.models import SecurityEvent

def test_aggregate_auth_sequence_and_sensitive():
    now=datetime(2026,10,1,10,11,10,tzinfo=timezone.utc)
    es=[SecurityEvent(timestamp=now,source_ip='192.0.2.1',status=401,auth_result='failure'),
        SecurityEvent(timestamp=now+timedelta(seconds=1),source_ip='192.0.2.1',path='/admin',auth_result='success',session_hash='s')]
    groups=aggregate(es,1)
    ip=next(x for x in groups if x['entity_type']=='source_ip')
    assert ip['features']['auth_failure_then_success'] is True
    assert ip['features']['sensitive_path_count']==1
    assert ip['features']['sensitive_access_after_auth'] is True
    assert any(x['entity_type']=='session' for x in groups)

def test_burst_rate_uses_observed_span():
    now=datetime(2026,10,1,10,11,10,tzinfo=timezone.utc)
    es=[SecurityEvent(timestamp=now+timedelta(milliseconds=i*50),source_ip='192.0.2.2') for i in range(20)]
    g=next(x for x in aggregate(es,1) if x['entity_type']=='source_ip')
    assert g['features']['requests_per_second']>8

def test_user_entity_and_historical_baseline_deviation():
    now=datetime(2026,10,1,10,11,10,tzinfo=timezone.utc)
    history=[SecurityEvent(timestamp=now-timedelta(days=1)+timedelta(seconds=i),source_ip='192.0.2.30',path='/usual',user_agent='Client/1',user_id='user-1') for i in range(8)]
    current=SecurityEvent(timestamp=now,source_ip='192.0.2.30',path='/new',user_agent='Other/9',user_id='user-1')
    groups=aggregate([current],1,baseline_events=history)
    user=next(x for x in groups if x['entity_type']=='user')
    assert user['features']['first_seen'] is False
    assert user['features']['usual_paths']==1
    assert user['features']['new_user_agent'] is True
    assert user['features']['new_path_ratio']==1
