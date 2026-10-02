"""Deterministic behavior stories assembled from structured local events."""
from __future__ import annotations

from collections import defaultdict

from .aggregation import SENSITIVE
from .models import Assessment, SecurityEvent


def build_attack_stories(events: list[SecurityEvent], limit: int = 100, assessments: list[Assessment] | None = None) -> list[dict]:
    groups: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        if event.session_hash:
            key = ("session", event.session_hash)
        else:
            key = ("source_ip", event.source_ip)
        groups[key].append(event)
    stories = []
    for (kind, entity), rows in groups.items():
        rows.sort(key=lambda e: e.timestamp)
        paths: set[str] = set()
        failures = 0
        prior_failure = False
        authenticated = False
        stages = []
        phase_seen: set[str] = set()
        risk = 8
        phase_rules = {"reconnaissance": ["unique_path_enumeration", "many_404"],
            "authentication_anomaly": ["login_failure_burst", "many_401"],
            "successful_authentication_after_failures": ["failure_then_success"],
            "sensitive_post_auth_access": ["sensitive_access_after_auth"]}
        for event in rows:
            path = event.path.lower()
            paths.add(path)
            phase = None
            evidence = {"method": event.method, "path": event.path, "status": event.status}
            if event.status in {401, 403, 404} and len(paths) >= 5 and "reconnaissance" not in phase_seen:
                phase = "reconnaissance"; risk = max(risk, 23)
                evidence.update({"unique_paths_seen": len(paths), "error_status": event.status})
            if event.auth_result == "failure":
                failures += 1; prior_failure = True
                if failures >= 3 and "authentication_anomaly" not in phase_seen:
                    phase = "authentication_anomaly"; risk = max(risk, 47)
                    evidence.update({"failed_auth_count": failures})
            if event.auth_result == "success":
                authenticated = True
                if prior_failure and "successful_authentication_after_failures" not in phase_seen:
                    phase = "successful_authentication_after_failures"; risk = max(risk, 72)
                    evidence.update({"preceded_by_failed_auth": True, "failed_auth_count": failures})
            is_sensitive = any(path.startswith(prefix) for prefix in SENSITIVE)
            if authenticated and is_sensitive and "sensitive_post_auth_access" not in phase_seen:
                phase = "sensitive_post_auth_access"; risk = max(risk, 94)
                evidence.update({"authenticated_in_session": True, "sensitive_path": True})
            if phase:
                phase_seen.add(phase)
                stages.append({"time": event.timestamp.isoformat(), "event": phase,
                    "risk": risk, "risk_delta": risk - (stages[-1]["risk"] if stages else 0),
                    "rule_hits": phase_rules[phase], "jev_judgment": "No matching window assessment",
                    "evidence": evidence})
                if assessments:
                    related = {event.source_ip, event.session_hash, event.user_id} - {None}
                    candidates = [a for a in assessments if a.entity in related and
                                  abs((a.ended_at - event.timestamp).total_seconds()) <= 300]
                    if candidates:
                        match = min(candidates, key=lambda a: abs((a.ended_at - event.timestamp).total_seconds()))
                        stages[-1]["jev_judgment"] = ("Jev not called" if match.jev is None else
                            f"Jev {match.jev.category}: p={match.jev.malicious_probability:.2f}; final {match.disposition}")
        if stages:
            source_ips = sorted({event.source_ip for event in rows})
            users = sorted({event.user_id for event in rows if event.user_id})
            stories.append({"story_id": f"{kind}:{entity}", "entity": entity, "entity_type": kind,
                "source_ips": source_ips, "user_ids": users,
                "started_at": stages[0]["time"], "updated_at": stages[-1]["time"],
                "risk": risk, "stage_count": len(stages), "stages": stages})
    stories.sort(key=lambda story: (story["risk"], story["updated_at"]), reverse=True)
    return stories[:max(1, limit)]
