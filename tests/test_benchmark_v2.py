import asyncio
import json

import pytest

from security_engine.dataset import generate_dataset
from security_engine.benchmark_v2 import evaluate


def test_v2_benchmark_keeps_validation_separate_and_all_test_windows(tmp_path):
    data = tmp_path / "data"
    reports = tmp_path / "reports"
    generate_dataset(data, entities=1000, seed=17, malicious_rate=.1)
    result = asyncio.run(evaluate(data, reports, "mock-heuristic-v1", "http://127.0.0.1:8765", provider_name="mock"))
    assert result["windows_evaluated"] == 200
    assert abs(result["test_malicious_prevalence"] - .1) < .06
    assert result["dataset_generator_version"] == 2
    assert len(result["dataset_fingerprint"]) == 64
    assert (reports / "thresholds.json").exists()
    assert (reports / "precision_recall_curve.csv").exists()


def test_public_benchmark_rejects_unverified_or_other_model_runs(tmp_path):
    data = tmp_path / "data"
    generate_dataset(data, entities=1000, seed=23, malicious_rate=.05)
    with pytest.raises(ValueError, match="supports only llm-qwen3-4b"):
        asyncio.run(evaluate(data, tmp_path / "report", "unsupported-model", "http://127.0.0.1:8765"))
    (data / "labels.csv").write_text((data / "labels.csv").read_text() + "tamper,benign,ordinary_browse,test\n")
    with pytest.raises(ValueError, match="integrity check failed"):
        asyncio.run(evaluate(data, tmp_path / "report", "llm-qwen3-4b", "http://127.0.0.1:8765", provider_name="mock"))
