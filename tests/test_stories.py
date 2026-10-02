from datetime import datetime, timedelta, timezone

from security_engine.models import SecurityEvent
from security_engine.stories import build_attack_stories


def test_story_explains_multistage_chain_with_increasing_risk():
    start = datetime(2026, 10, 1, 14, 1, tzinfo=timezone.utc)
    events = [SecurityEvent(timestamp=start + timedelta(minutes=i), source_ip="192.0.2.15",
        session_hash="story-session", path=f"/synthetic/{i}", status=404) for i in range(5)]
    events += [SecurityEvent(timestamp=start + timedelta(minutes=6), source_ip="192.0.2.15", session_hash="story-session", path="/login", status=401, auth_result="failure") for _ in range(3)]
    events += [SecurityEvent(timestamp=start + timedelta(minutes=7), source_ip="192.0.2.15", session_hash="story-session", path="/login", status=200, auth_result="success")]
    events += [SecurityEvent(timestamp=start + timedelta(minutes=8), source_ip="192.0.2.15", session_hash="story-session", path="/api/keys", status=200)]
    stories = build_attack_stories(events)
    assert len(stories) == 1
    assert [stage["event"] for stage in stories[0]["stages"]] == [
        "reconnaissance", "authentication_anomaly", "successful_authentication_after_failures", "sensitive_post_auth_access"]
    assert stories[0]["stages"][-1]["risk"] == 94
    assert all("evidence" in stage for stage in stories[0]["stages"])
