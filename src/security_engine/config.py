from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    database: Path = Path(os.getenv("SDE_DATABASE", "data/security.db"))
    decision_provider: str = os.getenv("SDE_DECISION_PROVIDER", "mock")
    local_jev_base_url: str = os.getenv("LOCAL_JEV_BASE_URL", "http://127.0.0.1:8765")
    local_jev_model: str = os.getenv("LOCAL_JEV_MODEL", "llm-qwen3-4b")
    decision_timeout: float = float(os.getenv("SDE_DECISION_TIMEOUT", "30"))
    mode: str = os.getenv("SDE_MODE", "hybrid")
    alert_threshold: int = int(os.getenv("SDE_ALERT_THRESHOLD", "55"))
    high_risk_threshold: int = int(os.getenv("SDE_HIGH_RISK_THRESHOLD", "78"))
    low_confidence_threshold: float = float(os.getenv("SDE_LOW_CONFIDENCE_THRESHOLD", "0.52"))
    window_minutes: tuple[int, ...] = (1, 5)


settings = Settings()
