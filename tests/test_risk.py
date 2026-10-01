from datetime import datetime,timezone
from security_engine.models import JevDecision
from security_engine.risk import assess

def test_uncertainty_zone_abstains():
    now=datetime.now(timezone.utc)
    j=JevDecision(malicious_probability=.51,category='unknown_suspicious',severity=2,review_probability=.6,confidence=.4)
    a=assess(entity='x',entity_type='source_ip',window='1m',started_at=now,ended_at=now,request_count=1,features={},rules=[],rule_risk=0,jev=j)
    assert a.disposition=='UNCERTAIN'

def test_hybrid_has_all_components():
    now=datetime.now(timezone.utc)
    j=JevDecision(malicious_probability=.9,category='reconnaissance',severity=4,review_probability=.9,confidence=.9)
    a=assess(entity='x',entity_type='source_ip',window='1m',started_at=now,ended_at=now,request_count=1,features={},rules=[],rule_risk=70,jev=j)
    assert a.hybrid_risk>70
