from __future__ import annotations

from .models import RuleMatch


def evaluate_rules(f: dict[str, object]) -> tuple[list[RuleMatch], int]:
    rules: list[RuleMatch] = []
    def add(rule_id: str, description: str, severity: str, score: int, **evidence: object) -> None:
        rules.append(RuleMatch(rule_id=rule_id, description=description, severity=severity,
                               score=score, evidence=evidence))
    rps = float(f.get("requests_per_second", 0))
    if rps >= 8:
        add("high_request_rate", "High request rate within the behavior window", "high", 45, requests_per_second=round(rps, 2))
    if float(f.get("404_ratio", 0)) >= .45 and int(f.get("status_4xx", 0)) >= 8:
        add("many_404", "Large share of requests returned 404", "medium", 18, ratio=round(float(f["404_ratio"]), 3), count=f.get("status_4xx"))
    if float(f.get("401_ratio", 0)) >= .35 and int(f.get("status_4xx", 0)) >= 5:
        add("many_401", "Repeated unauthorized responses", "high", 25, ratio=round(float(f["401_ratio"]), 3))
    if float(f.get("403_ratio", 0)) >= .30 and int(f.get("status_4xx", 0)) >= 5:
        add("many_403", "Repeated forbidden responses", "high", 22, ratio=round(float(f["403_ratio"]), 3))
    unique = int(f.get("unique_paths", 0))
    if unique >= 10:
        add("unique_path_enumeration", "Many distinct paths visited in one window", "high", 40, unique_paths=unique)
    failures = int(f.get("failed_auth_count", 0))
    if failures >= 5:
        add("login_failure_burst", "Unusually many failed authentication attempts", "high", 30, failures=failures)
    if bool(f.get("auth_failure_then_success")):
        add("failure_then_success", "Authentication failure followed by success", "high", 28)
    sensitive = int(f.get("sensitive_unique_path_count", f.get("sensitive_path_count", 0)))
    if sensitive >= 3:
        add("sensitive_path_sweep", "Several distinct sensitive paths accessed in one window", "high", 30, unique_sensitive_paths=sensitive)
    uas = int(f.get("unique_user_agents", 0))
    count = int(f.get("request_count", 0))
    if count >= 10 and uas <= 1 and rps >= 1:
        add("automated_client", "High-volume requests from one user-agent identity", "medium", 10, request_count=count)
    methods = f.get("method_counts", {})
    if isinstance(methods, dict) and count and sum(v for k, v in methods.items() if k not in {"GET", "POST", "HEAD", "OPTIONS"}) / count >= .25:
        add("unusual_method_mix", "Uncommon methods form a notable share of requests", "medium", 18, method_counts=methods)
    risk = min(100, sum(r.score for r in rules))
    return rules, risk
