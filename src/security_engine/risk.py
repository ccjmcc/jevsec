from __future__ import annotations

from .config import settings
from .models import Assessment, JevDecision, RuleMatch


def assess(*, entity: str, entity_type: str, window: str, started_at, ended_at, request_count: int,
           features: dict, rules: list[RuleMatch], rule_risk: int, jev: JevDecision | None,
           mode: str = "hybrid", context_completeness: float = 1.0) -> Assessment:
    jev_risk = None if jev is None else 100 * (0.62 * jev.malicious_probability + 0.38 * jev.severity / 4)
    anomaly = min(100, max(rule_risk, 12 * sum((int(features.get(k, 0)) > 0) for k in ("failed_auth_count", "sensitive_path_count", "unique_paths"))))
    if mode == "rules_only":
        score = float(rule_risk)
        confidence = 1.0 if rules else .7
        category = "unknown_suspicious" if rules else "benign"
    elif mode == "jev_only":
        if jev is None:
            raise ValueError("jev_only mode requires a decision provider")
        score = float(jev_risk)
        confidence = jev.confidence * context_completeness
        category = jev.category
    else:
        if jev is None:
            score = float(rule_risk)
            confidence = .45
        else:
            score = .55 * rule_risk + .35 * float(jev_risk) + .10 * anomaly
            # Disagreement raises uncertainty and causes review rather than forced binary classification.
            confidence = max(0, min(1, jev.confidence * context_completeness - abs(rule_risk - float(jev_risk)) / 180))
        category = jev.category if jev and confidence >= settings.low_confidence_threshold else ("unknown_suspicious" if rules else "benign")
    if confidence < settings.low_confidence_threshold:
        disposition = "UNCERTAIN"
    elif score >= settings.high_risk_threshold:
        disposition = "HIGH_RISK"
    elif score >= settings.alert_threshold:
        disposition = "SUSPICIOUS"
    else:
        disposition = "BENIGN"
    return Assessment(entity=entity, entity_type=entity_type, window=window, started_at=started_at, ended_at=ended_at,
                      request_count=request_count, features=features, rules=rules, rule_risk=rule_risk, jev=jev,
                      jev_risk=jev_risk, hybrid_risk=round(score, 2), disposition=disposition, category=category,
                      confidence=round(confidence, 3), mode=mode)
