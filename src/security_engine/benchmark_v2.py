from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import math
import platform
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from pathlib import Path

from .benchmark import _metrics, _splits
from .calibration import calibrate, fit_category_thresholds, fit_min_review_thresholds
from .decision import LocalJevProvider, MockProvider, PrefilterProvider
from .models import SecurityEvent
from .risk import assess
from .rules import evaluate_rules
from .aggregation import aggregate
from .config import SUPPORTED_MODEL


def _prevalence(labels: dict[str, tuple[str, str]]) -> float:
    return sum(category != "benign" for category, _ in labels.values()) / max(1, len(labels))


def _outcome_rows(rows: list[dict], field: str) -> list[dict]:
    return [{**row, "risk": row[field + "_risk"], "alert": row[field + "_review"]} for row in rows]


def _summary(rows: list[dict], field: str) -> dict:
    result = _metrics(_outcome_rows(rows, field))
    result["review_rate"] = sum(r[field + "_review"] for r in rows) / max(1, len(rows))
    result["alerts_or_reviews"] = sum(r[field + "_review"] for r in rows)
    result["attack_retention"] = result["recall"]
    rule_count = sum(r["rules_review"] for r in rows)
    result["rule_reviews"] = rule_count
    result["alert_reduction"] = (rule_count - result["alerts_or_reviews"]) / rule_count if rule_count else None
    return result


def _pr_curve(rows: list[dict], score_key: str, name: str) -> list[dict]:
    thresholds = sorted({0.0, 100.000001, *(float(r[score_key]) for r in rows)})
    out = []
    for threshold in thresholds:
        selected = [{**r, "risk": r[score_key], "alert": float(r[score_key]) >= threshold} for r in rows]
        m = _metrics(selected)
        out.append({"system": name, "threshold": threshold, "precision": m["precision"], "recall": m["recall"],
                    "false_positive_rate": m["false_positive_rate"], "review_rate": sum(x["alert"] for x in selected) / max(1, len(selected))})
    return out


async def evaluate(data_dir: Path, report_dir: Path, model: str, base_url: str, sample_limit: int | None = None,
                   provider_name: str = "local_jev") -> dict:
    """Run all selected 1m source-IP windows. Threshold fitting sees validation only."""
    if provider_name == "local_jev" and model != SUPPORTED_MODEL:
        raise ValueError(f"public benchmark supports only {SUPPORTED_MODEL}")
    manifest_path = data_dir / "dataset_manifest.json"
    if not manifest_path.is_file():
        raise ValueError("public benchmark requires dataset_manifest.json; regenerate with security-engine generate-dataset")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("generator_version") != 2:
        raise ValueError(f"unsupported dataset generator version: {manifest.get('generator_version')}")
    for filename, key in (("events.jsonl", "events_sha256"), ("labels.csv", "labels_sha256")):
        digest = hashlib.sha256((data_dir / filename).read_bytes()).hexdigest()
        if digest != manifest.get(key):
            raise ValueError(f"dataset integrity check failed for {filename}")
    dataset_fingerprint = hashlib.sha256(
        (manifest["events_sha256"] + manifest["labels_sha256"]).encode("ascii")
    ).hexdigest()
    labels = _splits(data_dir / "labels.csv")
    events = [SecurityEvent.model_validate_json(line) for line in (data_dir / "events.jsonl").open() if line.strip()]
    groups = [g for g in aggregate(events, 1)
              if g["entity_type"] == "source_ip" and g["entity"] in labels["test"] | labels["validation"]]
    if sample_limit and len(groups) > sample_limit:
        raise ValueError("sample_limit is not allowed in public v2 evaluation; use the complete split")
    labels_by_entity = {**labels["validation"], **labels["test"]}
    provider = LocalJevProvider(base_url, model, timeout=1200) if provider_name == "local_jev" else MockProvider()
    prefilter = PrefilterProvider(LocalJevProvider(base_url, model, timeout=1200)) if provider_name == "local_jev" else None
    rows = []
    uncached_latencies = []
    started = time.perf_counter()
    for group in groups:
        category, scenario = labels_by_entity[group["entity"]]
        truth = category != "benign"
        rule_matches, rule_score = evaluate_rules(group["features"])
        rule = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
                      ended_at=group["ended_at"], request_count=len(group["events"]), features=group["features"],
                      rules=rule_matches, rule_risk=rule_score, jev=None, mode="rules_only")
        jev = await provider.decide(group["features"])
        if jev.latency_ms:
            uncached_latencies.append(jev.latency_ms)
        jev_assessment = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
            ended_at=group["ended_at"], request_count=len(group["events"]), features=group["features"], rules=rule_matches,
            rule_risk=rule_score, jev=jev, mode="jev_only")
        hybrid = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
            ended_at=group["ended_at"], request_count=len(group["events"]), features=group["features"], rules=rule_matches,
            rule_risk=rule_score, jev=jev, mode="hybrid")
        pdecision = await prefilter.decide(group["features"]) if prefilter else jev
        pref_hybrid = assess(entity=group["entity"], entity_type="source_ip", window="1m", started_at=group["started_at"],
            ended_at=group["ended_at"], request_count=len(group["events"]), features=group["features"], rules=rule_matches,
            rule_risk=rule_score, jev=pdecision, mode="hybrid")
        rows.append({"entity": group["entity"], "split": "validation" if group["entity"] in labels["validation"] else "test",
            "category": category, "scenario": scenario, "label": truth, "predicted_category": jev.category,
            "confidence": jev.confidence, "rules_risk": rule.hybrid_risk,
            "rules_review": rule.disposition in {"REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"},
            "jev_risk": jev_assessment.hybrid_risk,
            "jev_review": jev_assessment.disposition in {"REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"},
            "hybrid_risk": hybrid.hybrid_risk,
            "hybrid_review": hybrid.disposition in {"REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"},
            "prefilter_hybrid_risk": pref_hybrid.hybrid_risk,
            "prefilter_hybrid_review": pref_hybrid.disposition in {"REVIEW", "SUSPICIOUS", "HIGH_RISK", "UNCERTAIN"},
            "jev_latency_ms": jev.latency_ms, "rule_ids": ";".join(x.rule_id for x in rule_matches),
            "prefilter_skipped": pdecision.provider == "prefilter"})
    elapsed = time.perf_counter() - started
    val = [r for r in rows if r["split"] == "validation"]
    test = [r for r in rows if r["split"] == "test"]
    jev_fit = fit_category_thresholds([{"score": r["jev_risk"], "label": r["label"], "predicted_category": r["predicted_category"], "true_category": r["category"]} for r in val])
    hybrid_fit = fit_category_thresholds([{"score": r["hybrid_risk"], "label": r["label"], "predicted_category": r["predicted_category"], "true_category": r["category"]} for r in val])
    jev_min_review = fit_min_review_thresholds([{"score": r["jev_risk"], "label": r["label"], "predicted_category": r["predicted_category"], "true_category": r["category"]} for r in val])
    hybrid_min_review = fit_min_review_thresholds([{"score": r["hybrid_risk"], "label": r["label"], "predicted_category": r["predicted_category"], "true_category": r["category"]} for r in val])
    for row in rows:
        if row["split"] != "test":
            continue
        jev_result = calibrate(row["jev_risk"], row["predicted_category"], jev_fit, row["confidence"])
        hybrid_result = calibrate(row["hybrid_risk"], row["predicted_category"], hybrid_fit, row["confidence"])
        row["calibrated_jev_review"] = jev_result.review
        row["calibrated_jev_disposition"] = jev_result.disposition
        row["calibrated_jev_threshold"] = jev_result.threshold
        row["calibrated_jev_risk"] = row["jev_risk"]
        row["calibrated_hybrid_review"] = hybrid_result.review
        row["calibrated_hybrid_disposition"] = hybrid_result.disposition
        row["calibrated_hybrid_threshold"] = hybrid_result.threshold
        row["calibrated_hybrid_risk"] = row["hybrid_risk"]
        row["jev_95_review"] = calibrate(row["jev_risk"], row["predicted_category"], jev_min_review, row["confidence"]).review
        row["jev_95_risk"] = row["jev_risk"]
        row["hybrid_95_review"] = calibrate(row["hybrid_risk"], row["predicted_category"], hybrid_min_review, row["confidence"]).review
        row["hybrid_95_risk"] = row["hybrid_risk"]
    test = [r for r in rows if r["split"] == "test"]
    systems = {name: _summary(test, name) for name in ("rules", "jev", "hybrid", "prefilter_hybrid", "calibrated_jev", "calibrated_hybrid", "jev_95", "hybrid_95")}
    report_dir.mkdir(parents=True, exist_ok=True)
    with (report_dir / "benchmark_results.csv").open("w", newline="", encoding="utf-8") as f:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader(); writer.writerows(rows)
    thresholds = {"model": model, "calibration_split": "validation", "maximum_validation_fpr": .05,
                  "jev_thresholds": jev_fit, "hybrid_thresholds": hybrid_fit,
                  "target_recall": .95, "jev_min_review_thresholds": jev_min_review,
                  "hybrid_min_review_thresholds": hybrid_min_review}
    (report_dir / "thresholds.json").write_text(json.dumps(thresholds, indent=2))
    curve = _pr_curve(test, "jev_risk", "Jev") + _pr_curve(test, "hybrid_risk", "Hybrid")
    with (report_dir / "precision_recall_curve.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=curve[0].keys(), lineterminator="\n"); writer.writeheader(); writer.writerows(curve)
    dataset_prevalence = _prevalence(labels["test"])
    composition = {split: {"windows": len(split_rows), "classes": dict(Counter(cat for cat, _ in split_rows.values())),
                           "scenarios": dict(Counter(scenario for _, scenario in split_rows.values()))}
                   for split, split_rows in labels.items()}
    hardware = platform.platform()
    try:
        hardware = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, timeout=2, check=True).stdout.strip()
    except Exception:
        pass
    jev_version = "unknown"
    try:
        import httpx
        response = httpx.get(base_url.rstrip("/") + "/healthz", timeout=3)
        response.raise_for_status()
        jev_version = response.json().get("version", "unknown")
    except Exception:
        pass
    model_versions = {SUPPORTED_MODEL: "Qwen3-4B-Instruct-2507; HF snapshot cdbee75f17c01a7cc42f958dc650907174af0554"}
    meta = {"model": model, "provider": provider_name, "machine": platform.platform(), "architecture": platform.machine(),
        "hardware_model": hardware, "python": platform.python_version(), "local_jev_version": jev_version,
        "model_version": model_versions.get(model, model), "dataset_composition": composition,
        "windows_evaluated": len(test), "validation_windows": len(val), "test_malicious_prevalence": dataset_prevalence,
        "event_count": len(events), "system_results": systems, "thresholds": thresholds,
        "provider_metrics": provider.metrics() if hasattr(provider, "metrics") else {},
        "prefilter_metrics": prefilter.metrics() if prefilter else {},
        "inference_latency_p50_ms": statistics.median(uncached_latencies) if uncached_latencies else 0,
        "inference_latency_p95_ms": sorted(uncached_latencies)[math.ceil(.95*len(uncached_latencies))-1] if uncached_latencies else 0,
        "uncached_inferences": len(uncached_latencies), "wall_seconds": elapsed,
        "effective_windows_per_second": len(groups) / elapsed if elapsed else 0,
        "context_bytes": provider.metrics().get("context_bytes", 0) if hasattr(provider, "metrics") else None,
        "token_count": None, "token_count_note": "local-jev System-One endpoint does not expose token usage",
        "dataset_generator_version": manifest["generator_version"], "dataset_fingerprint": dataset_fingerprint,
        "dataset_seed": manifest["seed"], "dataset_behavior_windows": manifest["behavior_windows"]}
    (report_dir / "benchmark_results.json").write_text(json.dumps(meta, indent=2))
    if hasattr(provider, "aclose"):
        await provider.aclose()
    if prefilter:
        await prefilter.provider.aclose()
    return meta


def render(meta: dict, out: Path):
    lines = ["# Public benchmark v2 run", "", f"- System: `{meta['hardware_model']}`; OS `{meta['machine']}` ({meta['architecture']}); Python {meta['python']}.",
        f"- Provider/model: `{meta['provider']}` / `{meta['model']}` ({meta['model_version']}); local-jev endpoint `{meta['local_jev_version']}`.",
        f"- Test windows: {meta['windows_evaluated']:,}; validation windows: {meta['validation_windows']:,}; test malicious prevalence: {meta['test_malicious_prevalence']:.2%}.",
        f"- Dataset generator v{meta['dataset_generator_version']}; requested windows: {meta['dataset_behavior_windows']:,}; seed: {meta['dataset_seed']}; fingerprint: `{meta['dataset_fingerprint']}`.",
        f"- Synthetic events: {meta['event_count']:,}; elapsed {meta['wall_seconds']:.1f}s; full-window throughput {meta['effective_windows_per_second']:.1f}/s.",
        f"- Uncached model calls: {meta['uncached_inferences']:,}; cache/provider stats `{json.dumps(meta['provider_metrics'], sort_keys=True)}`.",
        f"- Model inference latency for uncached calls: p50 {meta['inference_latency_p50_ms']:.1f} ms, p95 {meta['inference_latency_p95_ms']:.1f} ms. Context payload bytes: {meta['context_bytes']}; tokens: unavailable from endpoint.",
        "", "All 1-minute source-IP windows in the split are evaluated. Thresholds are fitted only on the disjoint validation split, separately by predicted behavior category, with a 5% maximum validation FPR objective; test labels are used only for final metric calculation.",
        "", "## Systems", "", "| System | Precision | Recall / retention | F1 | FPR | FNR | Review rate | Reviews | Alert reduction vs Rules |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, title in (("rules", "Rules"), ("jev", "Jev every window"), ("calibrated_jev", "Calibrated Jev"), ("hybrid", "Hybrid"),
                        ("calibrated_hybrid", "Calibrated Hybrid (≤5% val FPR)"),
                        ("prefilter_hybrid", "Prefilter → Jev Hybrid"), ("jev_95", "Calibrated Jev (≥95% val recall)"),
                        ("hybrid_95", "Calibrated Hybrid (≥95% val recall)")):
        s = meta["system_results"][name]
        reduction = "n/a" if s["alert_reduction"] is None else f"{s['alert_reduction']:+.1%}"
        lines.append(f"| {title} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {s['false_positive_rate']:.3f} | {s['false_negative_rate']:.3f} | {s['review_rate']:.2%} | {s['alerts_or_reviews']:,} | {reduction} |")
    lines += ["", "## Validation-fitted threshold table", "", "The detailed category thresholds and validation counts are in `thresholds.json`; no test split was consulted when choosing them.", "", "| Category | Jev threshold, max 5% FPR | Hybrid threshold, max 5% FPR | Jev threshold, 95% recall target | Hybrid threshold, 95% recall target |", "|---|---:|---:|---:|---:|"]
    for category, jev in meta["thresholds"]["jev_thresholds"].items():
        hybrid = meta["thresholds"]["hybrid_thresholds"][category]
        jev95 = meta["thresholds"]["jev_min_review_thresholds"][category]
        hybrid95 = meta["thresholds"]["hybrid_min_review_thresholds"][category]
        lines.append(f"| {category} | {jev['threshold']:.2f} (FPR {jev['false_positive_rate']:.2%}) | {hybrid['threshold']:.2f} (FPR {hybrid['false_positive_rate']:.2%}) | {jev95['threshold']:.2f} (recall {jev95['recall']:.2%}) | {hybrid95['threshold']:.2f} (recall {hybrid95['recall']:.2%}) |")
    lines += ["", "## Recommended operating points", "", "- **FPR-constrained:** per-category threshold maximizes validation recall subject to no more than 5% validation FPR.", "- **Review-budget oriented:** highest per-category threshold preserving at least 95% validation recall minimizes validation review volume at that retention target.", "- **Rules shadow baseline:** static configured threshold; no model call. Compare against the same held-out rows.", "", "## Reproduction", "", "Run `scripts/run_public_benchmark.sh`. Fixed seed, generator, model identifiers, split boundaries and all result files are retained under `reports/public_v2/`.", "", "This is a synthetic benchmark, not a production prevalence estimate. False positive rates and review rates depend on the included scenario mix."]
    out.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:8765")
    parser.add_argument("--provider", choices=["local_jev", "mock"], default="local_jev")
    args = parser.parse_args()
    meta = asyncio.run(evaluate(args.data, args.reports, args.model, args.base_url, provider_name=args.provider))
    render(meta, args.reports / "BENCHMARK.md")
    print(f"benchmark_v2 complete model={args.model} prevalence={meta['test_malicious_prevalence']:.2%} test_windows={meta['windows_evaluated']} uncached={meta['uncached_inferences']} report={args.reports / 'BENCHMARK.md'}")


if __name__ == "__main__":
    main()
