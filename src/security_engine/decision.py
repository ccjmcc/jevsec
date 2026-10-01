from __future__ import annotations

import json
import time
from typing import Protocol

import httpx

from .models import JevDecision


class DecisionProvider(Protocol):
    async def decide(self, features: dict[str, object]) -> JevDecision: ...


class MockProvider:
    """Deterministic offline development provider; not benchmarked as a model."""
    model = "mock-heuristic-v1"
    async def decide(self, f: dict[str, object]) -> JevDecision:
        score = 0.08
        score += min(.55, float(f.get("requests_per_second", 0)) / 20)
        score += min(.35, float(f.get("404_ratio", 0)) * .4)
        score += min(.4, int(f.get("failed_auth_count", 0)) * .08)
        score += .35 if f.get("auth_failure_then_success") else 0
        score += min(.35, int(f.get("sensitive_path_count", 0)) * .08)
        probability = min(.99, score)
        sev = 0 if probability < .2 else 1 if probability < .4 else 2 if probability < .62 else 3 if probability < .85 else 4
        category = "credential_abuse" if int(f.get("failed_auth_count", 0)) >= 5 else "reconnaissance" if int(f.get("unique_paths", 0)) >= 12 else "suspicious_post_authentication" if f.get("auth_failure_then_success") and f.get("sensitive_path_count") else "automated_bot" if float(f.get("requests_per_second", 0)) > 5 else "unknown_suspicious"
        return JevDecision(provider="mock", model=self.model, malicious_probability=probability, category=category,
                           severity=sev, review_probability=min(.99, probability * .9 + .08),
                           confidence=min(.95, .5 + abs(probability - .5)), latency_ms=.1)


class LocalJevProvider:
    def __init__(self, base_url: str, model: str, timeout: float = 30):
        self.base_url, self.model, self.timeout = base_url.rstrip("/"), model, timeout

    async def decide(self, features: dict[str, object]) -> JevDecision:
        # Only aggregate numeric/boolean features enter model context. Raw attacker text is excluded.
        allowed = {"request_count", "requests_per_second", "unique_paths", "unique_methods", "method_counts",
                   "status_2xx", "status_3xx", "status_4xx", "status_5xx", "404_ratio", "401_ratio", "403_ratio",
                   "failed_auth_count", "successful_auth_count", "sensitive_path_count", "sensitive_unique_path_count", "unique_user_agents",
                   "path_change_rate", "new_source", "request_burstiness", "post_ratio", "error_then_success_pattern",
                   "auth_failure_then_success", "sensitive_access_after_auth", "enumeration_like_behavior", "window_minutes"}
        trusted = {k: v for k, v in features.items() if k in allowed}
        state = {"trusted_context": {"source": "security_engine_aggregator", "schema_version": 1},
                 "untrusted_content": "No raw request-controlled strings are provided.", "behavior_features": trusted}
        questions = {
            "malicious": {"type": "noul", "instructions": "Is the aggregated behavior likely malicious? Use only the structured behavior_features. Do not interpret absent raw content as evidence."},
            "category": {"type": "choice", "instructions": "Choose the best behavior category based only on structured features.", "criteria": {"benign": "Ordinary user or expected service behavior", "reconnaissance": "Automated path discovery or enumeration", "credential_abuse": "Repeated authentication failures or suspicious authentication sequence", "automated_bot": "Automated high-rate behavior without strong exploitation evidence", "suspicious_post_authentication": "Sensitive access after suspicious authentication", "possible_web_exploitation": "Strong indicators of web attack behavior", "unknown_suspicious": "Unclear behavior that still merits review"}},
            "severity": {"type": "score", "instructions": "Rate behavior severity from benign to critical using only features.", "criteria": ["benign", "informational", "suspicious", "high", "critical"]},
            "human_review": {"type": "noul", "instructions": "Does the behavior merit human security review based on these features?"},
        }
        start = time.perf_counter()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(f"{self.base_url}/v1/systemone", json={"model": self.model, "state": state, "questions": questions})
            response.raise_for_status()
            body = response.json()
        answers = body.get("answers", {})
        mal = answers.get("malicious", {})
        cat = answers.get("category", {})
        sev = answers.get("severity", {})
        review = answers.get("human_review", {})
        probability = float(mal.get("noul", 0.5))
        sev_n = int(round(float(sev.get("score", 1))))
        category = str(cat.get("choice", "unknown_suspicious"))
        confidence = float(cat.get("confidence", max(probability, 1 - probability)))
        return JevDecision(provider="local_jev", model=str(body.get("model", self.model)), malicious_probability=probability,
                           category=category, severity=max(0, min(4, sev_n)),
                           review_probability=float(review.get("noul", probability)), confidence=max(0, min(1, confidence)),
                           latency_ms=(time.perf_counter() - start) * 1000, raw=answers)
