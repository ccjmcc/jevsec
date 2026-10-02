#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_MODEL = "llm-qwen3-4b"
SYSTEMS = (("rules", "Rules"), ("jev", "Jev every window"), ("calibrated_jev", "Calibrated Jev"),
          ("hybrid", "Hybrid"), ("calibrated_hybrid", "Calibrated Hybrid (≤5% val FPR)"),
          ("prefilter_hybrid", "Prefilter → Jev Hybrid"), ("jev_95", "Calibrated Jev (≥95% val recall)"),
          ("hybrid_95", "Calibrated Hybrid (≥95% val recall)"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT / "reports/public_v2")
    args = parser.parse_args()
    runs = []
    for result_path in sorted(args.root.glob("*/*/benchmark_results.json")):
        meta = json.loads(result_path.read_text())
        if meta.get("model") != SUPPORTED_MODEL:
            raise SystemExit(f"unsupported model in report tree: {meta.get('model')!r}")
        if meta.get("dataset_generator_version") != 2 or not meta.get("dataset_fingerprint"):
            raise SystemExit(f"stale or unverified dataset report: {result_path}")
        rows = list(csv.DictReader((result_path.parent / "benchmark_results.csv").open()))
        test = [r for r in rows if r["split"] == "test"]
        runs.append((result_path, result_path.parent.name, meta, test))
    if not runs:
        raise SystemExit("no benchmark v2 outputs found")
    summary_rows, threshold_rows, curve_rows = [], [], []
    fp, fn = Counter(), Counter()
    fp_examples, fn_examples = [], []
    for path, prevalence, meta, rows in runs:
        model = meta["model"]
        prefilter_metrics = meta.get("prefilter_metrics", {})
        for name, title in SYSTEMS:
            stats = meta["system_results"][name]
            if name == "rules":
                calls, cache_hits, skips, p50, p95 = 0, 0, 0, None, None
            elif name == "prefilter_hybrid":
                calls = prefilter_metrics.get("inference_count", 0)
                cache_hits = prefilter_metrics.get("cache_hits", 0)
                skips = prefilter_metrics.get("prefilter_skips", 0)
                p50, p95 = meta["inference_latency_p50_ms"], meta["inference_latency_p95_ms"]
            else:
                provider_metrics = meta.get("provider_metrics", {})
                calls = provider_metrics.get("inference_count", meta.get("uncached_inferences", 0))
                cache_hits = provider_metrics.get("cache_hits", 0)
                skips = 0
                p50, p95 = meta["inference_latency_p50_ms"], meta["inference_latency_p95_ms"]
            summary_rows.append({"model": model, "requested_prevalence": prevalence,
                "test_prevalence": meta["test_malicious_prevalence"], "windows": stats["n"], "system": title,
                "precision": stats["precision"], "recall": stats["recall"], "f1": stats["f1"],
                "fpr": stats["false_positive_rate"], "fnr": stats["false_negative_rate"],
                "review_rate": stats["review_rate"], "reviews": stats["alerts_or_reviews"],
                "alert_reduction": stats["alert_reduction"], "attack_retention": stats["attack_retention"],
                "p50_ms": p50, "p95_ms": p95,
                "model_calls": calls, "cache_hits": cache_hits, "prefilter_skips": skips,
                "payload_bytes": meta["context_bytes"], "seconds": meta["wall_seconds"],
                "windows_per_second": meta["effective_windows_per_second"]})
        for category, jev in meta["thresholds"]["jev_thresholds"].items():
            hybrid = meta["thresholds"]["hybrid_thresholds"][category]
            threshold_rows.append({"model": model, "prevalence": prevalence, "category": category,
                "jev_threshold": jev["threshold"], "jev_validation_n": jev["validation_n"], "jev_validation_fpr": jev["false_positive_rate"],
                "hybrid_threshold": hybrid["threshold"], "hybrid_validation_n": hybrid["validation_n"], "hybrid_validation_fpr": hybrid["false_positive_rate"],
                "jev_min_review_threshold": meta["thresholds"]["jev_min_review_thresholds"][category]["threshold"],
                "jev_target_recall": meta["thresholds"]["jev_min_review_thresholds"][category]["recall"],
                "hybrid_min_review_threshold": meta["thresholds"]["hybrid_min_review_thresholds"][category]["threshold"],
                "hybrid_target_recall": meta["thresholds"]["hybrid_min_review_thresholds"][category]["recall"]})
        for curve in csv.DictReader((path.parent / "precision_recall_curve.csv").open()):
            curve_rows.append({"model": model, "prevalence": prevalence, **curve})
        for row in rows:
            if row["split"] != "test":
                continue
            for name, _ in SYSTEMS:
                alert = str(row.get(name + "_review", "False")).lower() == "true"
                positive = str(row["label"]).lower() == "true"
                error = "FP" if alert and not positive else "FN" if positive and not alert else None
                if error:
                    key = (model, prevalence, name, row["category"], row["scenario"])
                    (fp if error == "FP" else fn)[key] += 1
                    sample = {"model": model, "prevalence": prevalence, "system": name, "error": error,
                        "category": row["category"], "scenario": row["scenario"], "score": row.get(name + "_risk"),
                        "predicted_category": row["predicted_category"], "rule_ids": row["rule_ids"]}
                    (fp_examples if error == "FP" else fn_examples).append(sample)
    args.root.mkdir(parents=True, exist_ok=True)
    def write_csv(path: Path, rows: list[dict]):
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
            writer.writeheader(); writer.writerows(rows)
    write_csv(ROOT / "reports/public_v2_summary.csv", summary_rows)
    write_csv(args.root / "threshold_table.csv", threshold_rows)
    write_csv(args.root / "precision_recall_curve.csv", curve_rows)
    # Ship a transparent runtime operating point selected from the 5% Qwen3
    # validation split. The benchmark artifact records its sample counts/FPR.
    calibration_run = next((meta for _, prevalence, meta, _ in runs
                            if prevalence == "5pct" and meta["model"] == "llm-qwen3-4b"), None)
    if calibration_run is not None:
        thresholds = calibration_run["thresholds"]
        runtime_calibration = {
            "schema_version": 1,
            "model": calibration_run["model"],
            "model_version": calibration_run["model_version"],
            "dataset_fingerprint": calibration_run["dataset_fingerprint"],
            "dataset_generator_version": calibration_run["dataset_generator_version"],
            "dataset_seed": calibration_run["dataset_seed"],
            "dataset_behavior_windows": calibration_run["dataset_behavior_windows"],
            "source": "reports/public_v2/llm-qwen3-4b/5pct/benchmark_results.json",
            "calibration_split": "validation",
            "maximum_validation_fpr": thresholds["maximum_validation_fpr"],
            "jev_thresholds": thresholds["jev_thresholds"],
            "hybrid_thresholds": thresholds["hybrid_thresholds"],
        }
        calibration_path = ROOT / "config/calibration.json"
        calibration_path.parent.mkdir(parents=True, exist_ok=True)
        calibration_path.write_text(json.dumps(runtime_calibration, indent=2, sort_keys=True) + "\n")
    report = ["# Public benchmark v2", "", "Reproducible synthetic benchmark for the single supported local model, Qwen3-4B. Every held-out test behavior window is scored. Threshold fitting sees validation rows only and uses per-category operating points constrained to at most 5% validation FPR.", "", "## Reproduce", "", "Run `scripts/run_public_benchmark.sh` with local-jev available. Defaults: 20,000 behavior windows per prevalence and seed 20261001. `SDE_PUBLIC_WINDOWS` can lower the count for a smoke run; test counts are recorded in each report.", "", "## Results", "", "Model calls, cache hits, and prefilter skips count validation plus test work; scores below use held-out test windows only. Project Rules has no model call. Latency shows measured uncached local-model requests; the prefilter changes the number of requests, not their measured latency.", "", "| Model | Test prevalence | System | n | Precision | Recall / attack retention | F1 | FPR | FNR | Review rate | Reviews | Alert reduction vs rules | p50/p95 model ms | Model calls/cache hits | Prefilter skips |", "|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in summary_rows:
        reduction = "n/a" if r["alert_reduction"] is None else f"{r['alert_reduction']:+.1%}"
        latency = "n/a" if r["p50_ms"] is None else f"{r['p50_ms']:.0f}/{r['p95_ms']:.0f}"
        report.append(f"| {r['model']} | {r['requested_prevalence']} ({r['test_prevalence']:.2%}) | {r['system']} | {r['windows']:,} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['fpr']:.3f} | {r['fnr']:.3f} | {r['review_rate']:.2%} | {r['reviews']:,} | {reduction} | {latency} | {r['model_calls']:,}/{r['cache_hits']:,} | {r['prefilter_skips']:,} |")
    report += ["", "## Dataset composition", "", "Each behavior window contains 12 synthetic requests using the RFC 2544 benchmarking range. The entity-disjoint splits are fixed at 60% calibration reserve, 20% validation, and 20% test. Threshold fitting reads validation rows only; test labels are used only for final metrics and PR curves.", "", "| Model | Requested rate | Split | Windows | Class distribution | Scenario distribution |", "|---|---|---|---:|---|---|"]
    composition = {(meta["model"], prevalence, split): meta["dataset_composition"][split]
                   for _, prevalence, meta, _ in runs for split in meta["dataset_composition"]}
    for (model, prevalence, split), part in sorted(composition.items()):
        report.append(f"| {model} | {prevalence} | {split} | {part['windows']:,} | `{json.dumps(part['classes'], sort_keys=True)}` | `{json.dumps(part['scenarios'], sort_keys=True)}` |")
    report += ["", "Attack classes include reconnaissance, credential abuse, automation, post-authentication anomaly, safe web errors, and unknown suspicious. Benign cases include crawlers/search bots, API polling, health checks, CDN, SPA 404, administrator batch work, development scans, monitoring, slow login failures, enterprise proxy, high-volume API, mobile retries and CI/CD.", "", "All three measured prevalences are retained. Per-category operating points are in `reports/public_v2/threshold_table.csv`; precision-recall curves are in `reports/public_v2/precision_recall_curve.csv`.", "", "## Model cost proxy", "", "The System-One endpoint does not expose token counts. Reports retain exact context payload bytes, uncached calls, cache hits, uncached inference p50/p95, full-window throughput and wall time. Prefilter results measure calls avoided against Jev every window.", "", "Synthetic results are not production estimates, WAF replacement claims, or evidence that unknown vulnerabilities will be detected."]
    (ROOT / "reports/BENCHMARK_V2.md").write_text("\n".join(report) + "\n")
    selected = {(r["system"], r["model"], r["requested_prevalence"]): r for r in summary_rows}
    failure = ["# Failure analysis", "", "Error counts come from each held-out test split and are grouped by model, prevalence, system, true class, and synthetic scenario. Examples contain only synthetic labels/features.", "", "## Top false positives", "", "| Model | Prevalence | System | Class | Scenario | Count |", "|---|---|---|---|---|---:|"]
    failure += [f"| {m} | {p} | {s} | {cat} | {scenario} | {n} |" for (m, p, s, cat, scenario), n in fp.most_common(40)] or ["| — | — | — | — | — | 0 |"]
    failure += ["", "## Top false negatives", "", "| Model | Prevalence | System | Class | Scenario | Count |", "|---|---|---|---|---|---:|"]
    failure += [f"| {m} | {p} | {s} | {cat} | {scenario} | {n} |" for (m, p, s, cat, scenario), n in fn.most_common(40)] or ["| — | — | — | — | — | 0 |"]
    failure += ["", "## Examples", "", "### False positives", "", "```json", json.dumps(fp_examples[:40], indent=2), "```", "", "### False negatives", "", "```json", json.dumps(fn_examples[:40], indent=2), "```", ""]
    (ROOT / "reports/FAILURE_ANALYSIS.md").write_text("\n".join(failure))
    print(f"compiled {len(runs)} runs to reports/BENCHMARK_V2.md")


if __name__ == "__main__":
    main()
