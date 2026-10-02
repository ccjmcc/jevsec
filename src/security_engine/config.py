from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_MODEL = "llm-qwen3-4b"
configured_model = os.getenv("LOCAL_JEV_MODEL", SUPPORTED_MODEL)
if configured_model != SUPPORTED_MODEL:
    raise ValueError(f"JevSec supports only {SUPPORTED_MODEL}; received {configured_model!r}")


@dataclass(frozen=True)
class Settings:
    database: Path = Path(os.getenv("SDE_DATABASE", "data/security.db"))
    decision_provider: str = os.getenv("SDE_DECISION_PROVIDER", "mock")
    local_jev_base_url: str = os.getenv("LOCAL_JEV_BASE_URL", "http://127.0.0.1:8765")
    local_jev_model: str = SUPPORTED_MODEL
    decision_timeout: float = float(os.getenv("SDE_DECISION_TIMEOUT", "180"))
    mode: str = os.getenv("SDE_MODE", "hybrid")
    alert_threshold: int = int(os.getenv("SDE_ALERT_THRESHOLD", "55"))
    high_risk_threshold: int = int(os.getenv("SDE_HIGH_RISK_THRESHOLD", "78"))
    low_confidence_threshold: float = float(os.getenv("SDE_LOW_CONFIDENCE_THRESHOLD", "0.52"))
    auth_required: bool = os.getenv("SDE_AUTH_REQUIRED", "0").lower() in {"1", "true", "yes"}
    auth_username: str = os.getenv("SDE_AUTH_USERNAME", "")
    auth_password: str = os.getenv("SDE_AUTH_PASSWORD", "")
    calibration_file: Path = Path(os.getenv("SDE_CALIBRATION_FILE", "config/calibration.json"))
    jev_prefilter: bool = os.getenv("SDE_JEV_PREFILTER", "1").lower() not in {"0", "false", "no"}
    window_minutes: tuple[int, ...] = (1, 5)


settings = Settings()
