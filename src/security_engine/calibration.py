"""Validation-only, explainable per-category operating point selection."""
from __future__ import annotations

from dataclasses import dataclass
import json
from functools import lru_cache
from pathlib import Path


MODEL_CATEGORY = {
    "automated_bot": "automation",
    "automation": "automation",
    "suspicious_post_authentication": "post_authentication_anomaly",
    "post_authentication_anomaly": "post_authentication_anomaly",
    "possible_web_exploitation": "web_exploitation",
}
CALIBRATION_CATEGORIES = (
    "reconnaissance", "credential_abuse", "automation",
    "post_authentication_anomaly", "web_exploitation", "unknown_suspicious", "benign",
)
DEFAULT_THRESHOLDS = {name: 55.0 for name in CALIBRATION_CATEGORIES}


def load_thresholds(path: str | Path | None = None, system: str = "hybrid") -> dict:
    if path is None:
        return dict(DEFAULT_THRESHOLDS)
    calibration_path = Path(path).resolve()
    try:
        modified_ns = calibration_path.stat().st_mtime_ns
    except FileNotFoundError:
        return dict(DEFAULT_THRESHOLDS)
    return _load_thresholds_cached(str(calibration_path), system, modified_ns)


@lru_cache(maxsize=16)
def _load_thresholds_cached(path: str, system: str, modified_ns: int) -> dict:
    payload = json.loads(Path(path).read_text())
    system_key = "jev_thresholds" if system == "jev_only" else "hybrid_thresholds"
    if system_key in payload:
        return dict(payload[system_key])
    return dict(payload.get("thresholds", DEFAULT_THRESHOLDS))


def normalize_category(category: str) -> str:
    return MODEL_CATEGORY.get(category, category)


def _rates(rows: list[dict], threshold: float) -> tuple[float, float, float, int]:
    tp = sum(bool(r["label"]) and float(r["score"]) >= threshold for r in rows)
    fp = sum(not bool(r["label"]) and float(r["score"]) >= threshold for r in rows)
    positives = sum(bool(r["label"]) for r in rows)
    negatives = len(rows) - positives
    recall = tp / positives if positives else 0.0
    fpr = fp / negatives if negatives else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    return precision, recall, fpr, tp + fp


def fit_category_thresholds(validation_rows: list[dict], max_fpr: float = .05) -> dict:
    """Fit on validation rows only. Maximize attack retention under an FPR cap.

    A row needs `score`, `label` and `predicted_category`. When `true_category` is
    present, each one-vs-rest threshold is fit on that validation label plus all
    validation benign rows. Ties select the higher threshold, then fewer reviews. Categories without validation observations use
    the conservative threshold 101 (never alert on a 0..100 scale).
    """
    if not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be within [0, 1]")
    result = {}
    for category in CALIBRATION_CATEGORIES:
        if category == "benign":
            result[category] = {"threshold": 101.0, "validation_n": 0, "precision": 0.0, "recall": 0.0,
                                "false_positive_rate": 0.0, "review_rate": 0.0}
            continue
        subset = [r for r in validation_rows if
                  (str(r.get("true_category", "")) == "benign" or normalize_category(str(r.get("true_category", r.get("predicted_category", "")))) == category)]
        if not subset:
            result[category] = {"threshold": 101.0, "validation_n": 0, "precision": 0.0, "recall": 0.0,
                                "false_positive_rate": 0.0, "review_rate": 0.0}
            continue
        candidates = sorted({0.0, 100.000001, *(float(r["score"]) for r in subset)})
        feasible = []
        for threshold in candidates:
            precision, recall, fpr, reviews = _rates(subset, threshold)
            if fpr <= max_fpr:
                feasible.append((recall, threshold, precision, fpr, reviews))
        if feasible:
            recall, threshold, precision, fpr, reviews = max(feasible, key=lambda x: (x[0], x[1], -x[4]))
        else:
            threshold = 101.0; precision, recall, fpr, reviews = _rates(subset, threshold)
        result[category] = {"threshold": round(threshold, 6), "validation_n": len(subset),
                            "precision": precision, "recall": recall,
                            "false_positive_rate": fpr, "review_rate": reviews / len(subset)}
    return result


def fit_min_review_thresholds(validation_rows: list[dict], target_recall: float = .95) -> dict:
    """Per-category highest threshold that retains the requested validation recall."""
    if not 0 < target_recall <= 1:
        raise ValueError("target_recall must be within (0, 1]")
    result = {}
    for category in CALIBRATION_CATEGORIES:
        if category == "benign":
            result[category] = {"threshold": 101.0, "validation_n": 0, "target_recall": target_recall,
                                "recall": 0.0, "review_rate": 0.0, "false_positive_rate": 0.0}
            continue
        subset = [r for r in validation_rows if str(r.get("true_category", "")) == "benign" or
                  normalize_category(str(r.get("true_category", r.get("predicted_category", "")))) == category]
        positives = sum(bool(r["label"]) for r in subset)
        candidates = sorted({0.0, 100.000001, *(float(r["score"]) for r in subset)})
        feasible = []
        for threshold in candidates:
            precision, recall, fpr, reviews = _rates(subset, threshold)
            if positives and recall >= target_recall:
                feasible.append((reviews, -threshold, recall, precision, fpr))
        if feasible:
            reviews, neg_threshold, recall, precision, fpr = min(feasible)
            threshold = -neg_threshold
        else:
            threshold = 101.0; precision, recall, fpr, reviews = _rates(subset, threshold)
        result[category] = {"threshold": round(threshold, 6), "validation_n": len(subset),
            "target_recall": target_recall, "recall": recall, "precision": precision,
            "false_positive_rate": fpr, "review_rate": reviews / len(subset) if subset else 0.0}
    return result


@dataclass(frozen=True)
class CalibratedDecision:
    disposition: str
    threshold: float
    review: bool


def calibrate(score: float, category: str, thresholds: dict | None = None, confidence: float = 1.0,
              low_confidence: float = .52, high_risk_threshold: float = 85.0) -> CalibratedDecision:
    """Convert a continuous score to four explicit human-facing outcomes."""
    thresholds = thresholds or DEFAULT_THRESHOLDS
    category = normalize_category(category)
    config = thresholds.get(category, thresholds.get("default", 55.0))
    threshold = float(config.get("threshold", config) if isinstance(config, dict) else config)
    if confidence < low_confidence:
        disposition = "UNCERTAIN"
    elif score < threshold:
        disposition = "BENIGN"
    elif score >= high_risk_threshold:
        disposition = "HIGH_RISK"
    else:
        disposition = "REVIEW"
    return CalibratedDecision(disposition, threshold, disposition != "BENIGN")
