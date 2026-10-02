from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from statistics import mean, pstdev
from typing import Iterable

from .models import SecurityEvent

SENSITIVE = ("/admin", "/.env", "/wp-admin", "/api/keys", "/backup", "/config", "/actuator")


def _ratio(n: int, d: int) -> float:
    return n / d if d else 0.0


def _entities(e: SecurityEvent):
    for item in (("source_ip", e.source_ip), ("session", e.session_hash), ("user", e.user_id)):
        if item[1]:
            yield item


def active_window_keys(events: Iterable[SecurityEvent], windows=(1, 5)) -> set[tuple[str, str, str, datetime]]:
    active = set()
    for e in events:
        for entity_type, entity in _entities(e):
            for minutes in windows:
                start = e.timestamp.replace(second=0, microsecond=0)
                start = start.replace(minute=(start.minute // minutes) * minutes)
                active.add((entity_type, entity, f"{minutes}m", start))
    return active


def aggregate(events: Iterable[SecurityEvent], window_minutes: int = 1, now: datetime | None = None,
              known_sources: set[str] | None = None, baseline_events: Iterable[SecurityEvent] | None = None) -> list[dict]:
    rows = list(events)
    if not rows:
        return []
    by_entity: dict[tuple[str, str], list[SecurityEvent]] = {}
    for e in rows:
        for identity in _entities(e):
            by_entity.setdefault(identity, []).append(e)
    baselines: dict[tuple[str, str], list[SecurityEvent]] = {}
    for event in baseline_events or ():
        for identity in _entities(event):
            baselines.setdefault(identity, []).append(event)
    out = []
    for (entity_type, entity), entity_events in by_entity.items():
        entity_events.sort(key=lambda e: e.timestamp)
        windows: dict[datetime, list[SecurityEvent]] = {}
        for e in entity_events:
            start = e.timestamp.replace(second=0, microsecond=0)
            if window_minutes == 5:
                start = start.replace(minute=(start.minute // 5) * 5)
            else:
                start = start.replace(minute=(start.minute // window_minutes) * window_minutes)
            windows.setdefault(start, []).append(e)
        for start, subset in windows.items():
            statuses = Counter(e.status // 100 for e in subset)
            paths = [e.path for e in subset]
            path_counts = Counter(paths)
            allowed_methods = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
            methods = Counter(e.method if e.method in allowed_methods else "OTHER" for e in subset)
            uas = {e.user_agent for e in subset if e.user_agent}
            failures = sum(e.auth_result == "failure" for e in subset)
            successes = sum(e.auth_result == "success" for e in subset)
            ordered_auth = [e.auth_result for e in subset if e.auth_result != "unknown"]
            fail_then_success = any(a == "failure" and b == "success" for a, b in zip(ordered_auth, ordered_auth[1:]))
            unique_paths = len(set(paths))
            gaps = [(b.timestamp - a.timestamp).total_seconds() for a, b in zip(subset, subset[1:])]
            burstiness = (pstdev(gaps) / mean(gaps)) if len(gaps) > 1 and mean(gaps) else 0.0
            sensitive = sum(any(p.lower().startswith(s) for s in SENSITIVE) for p in paths)
            sensitive_paths = {p for p in paths if any(p.lower().startswith(s) for s in SENSITIVE)}
            auth_success_seen = False
            sensitive_after_auth = False
            for event in subset:
                if event.auth_result == "success":
                    auth_success_seen = True
                if auth_success_seen and any(event.path.lower().startswith(s) for s in SENSITIVE):
                    sensitive_after_auth = True
            status_total = sum(v for k, v in statuses.items() if k in (2, 3, 4, 5))
            observed_span_seconds = max(1.0, (subset[-1].timestamp - subset[0].timestamp).total_seconds())
            features = {
                "request_count": len(subset), "requests_per_second": len(subset) / observed_span_seconds,
                "unique_paths": unique_paths, "unique_methods": len(methods), "method_counts": dict(methods),
                "status_2xx": statuses[2], "status_3xx": statuses[3], "status_4xx": statuses[4], "status_5xx": statuses[5],
                "404_ratio": _ratio(sum(e.status == 404 for e in subset), len(subset)),
                "401_ratio": _ratio(sum(e.status == 401 for e in subset), len(subset)),
                "403_ratio": _ratio(sum(e.status == 403 for e in subset), len(subset)),
                "failed_auth_count": failures, "successful_auth_count": successes,
                "sensitive_path_count": sensitive, "sensitive_unique_path_count": len(sensitive_paths), "unique_user_agents": len(uas),
                "path_change_rate": _ratio(unique_paths - 1, max(1, len(subset) - 1)),
                "new_source": bool(known_sources is not None and entity_type == "source_ip" and entity not in known_sources), "request_burstiness": burstiness,
                "post_ratio": _ratio(methods["POST"], len(subset)),
                "error_then_success_pattern": fail_then_success,
                "auth_failure_then_success": fail_then_success,
                "sensitive_access_after_auth": sensitive_after_auth,
                "enumeration_like_behavior": bool(unique_paths >= 12 and statuses[4] >= 8),
                "window_minutes": window_minutes,
            }
            history = [e for e in baselines.get((entity_type, entity), ()) if e.timestamp < start]
            if history:
                known_paths = {e.path.lower() for e in history}
                known_uas = {e.user_agent for e in history if e.user_agent}
                hours = {e.timestamp.hour for e in history}
                elapsed_minutes = max(1.0, (history[-1].timestamp - history[0].timestamp).total_seconds() / 60)
                usual_rpm = len(history) / elapsed_minutes
                current_rpm = len(subset) / max(1.0, observed_span_seconds / 60)
                features.update({"first_seen": False, "usual_request_rate": usual_rpm,
                    "usual_paths": len(known_paths), "usual_hours": sorted(hours),
                    "usual_user_agents": len(known_uas),
                    "deviation_from_baseline": min(10.0, abs(current_rpm - usual_rpm) / max(usual_rpm, .1)),
                    "new_path_ratio": _ratio(sum(p.lower() not in known_paths for p in paths), len(paths)),
                    "new_user_agent": bool(uas - known_uas),
                    "unusual_hour": start.hour not in hours,
                    "usual_auth_pattern": {"failure_rate": _ratio(sum(e.auth_result == "failure" for e in history), len(history)),
                                           "success_rate": _ratio(sum(e.auth_result == "success" for e in history), len(history))},
                    "auth_pattern_deviation": abs(_ratio(failures, len(subset)) - _ratio(sum(e.auth_result == "failure" for e in history), len(history)))} )
            else:
                features.update({"first_seen": True, "usual_request_rate": 0.0, "usual_paths": 0,
                    "usual_hours": [], "usual_user_agents": 0, "deviation_from_baseline": 0.0,
                    "new_path_ratio": 0.0, "new_user_agent": False, "unusual_hour": False,
                    "usual_auth_pattern": {"failure_rate": 0.0, "success_rate": 0.0},
                    "auth_pattern_deviation": 0.0})
            out.append({"entity": entity, "entity_type": entity_type, "window": f"{window_minutes}m",
                        "started_at": start, "ended_at": start + timedelta(minutes=window_minutes),
                        "events": subset, "features": features})
    return out
