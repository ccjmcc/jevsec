from __future__ import annotations

from .aggregation import aggregate
from .decision import DecisionProvider
from .models import Assessment
from .risk import assess
from .rules import evaluate_rules


async def analyze(events, provider: DecisionProvider | None = None, mode: str = "hybrid", windows=(1, 5), known_sources=None, active_windows=None) -> list[Assessment]:
    output = []
    for minutes in windows:
        for group in aggregate(events, minutes, known_sources=known_sources):
            if active_windows is not None and (group["entity_type"], group["entity"], group["window"], group["started_at"]) not in active_windows:
                continue
            matches, rule_risk = evaluate_rules(group["features"])
            jev = await provider.decide(group["features"]) if provider and mode != "rules_only" else None
            output.append(assess(entity=group["entity"], entity_type=group["entity_type"], window=group["window"],
                                 started_at=group["started_at"], ended_at=group["ended_at"],
                                 request_count=len(group["events"]), features=group["features"], rules=matches,
                                 rule_risk=rule_risk, jev=jev, mode=mode))
    return output
