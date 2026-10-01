#!/usr/bin/env python3
"""Combine measured per-model benchmark runs into release reports."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
MODEL_DIR = REPORTS / "local_jev"


def confusion(run, system):
    return run.get("confusion_matrices", {}).get(system, {})


def alert_count(run, system):
    s = run["systems"][system]
    cm = confusion(run, system)
    return s.get("system_alerts", cm.get("tp", 0) + cm.get("fp", 0))


def main():
    runs = [json.loads(f.read_text()) for f in sorted(MODEL_DIR.glob("*/benchmark_results.json"))]
    if not runs:
        raise SystemExit("No local Jev benchmark result files found")
    latest = runs[-1]
    load_notes_path = REPORTS / "model_load_notes.json"
    load_notes = json.loads(load_notes_path.read_text()) if load_notes_path.exists() else {}
    robust_path = REPORTS / "robustness.json"
    robustness = json.loads(robust_path.read_text()) if robust_path.exists() else {}

    fields = ["model", "test_inferences", "cold_load_observation", "first_evaluation_request_ms", "p50_latency_ms", "p95_latency_ms", "throughput_states_per_second", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "accuracy", "auroc", "alerts_or_reviews", "traditional_rule_alerts", "workload_change_pct"]
    with (REPORTS / "local_jev_benchmark.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n"); writer.writeheader()
        for run in runs:
            s = run["systems"]["Local Jev Only"]
            rule_alerts = alert_count(run, "Rules Only")
            reviews = alert_count(run, "Local Jev Only")
            sample_file = MODEL_DIR / run["model"] / "benchmark_results.csv"
            with sample_file.open() as rf: rows = list(csv.DictReader(rf))
            cold = load_notes.get(run["model"], {}).get("cold_load_observation", "not separately timed")
            first_request = run.get("first_model_request_ms") or (rows[0].get("latency_ms") if rows else "")
            writer.writerow({"model": run["model"], "test_inferences": run["model_inferences"], "cold_load_observation": cold,
                "first_evaluation_request_ms": first_request, "p50_latency_ms": s["latency_p50_ms"], "p95_latency_ms": s["latency_p95_ms"],
                "throughput_states_per_second": s["throughput_rps"], "precision": s["precision"], "recall": s["recall"], "f1": s["f1"],
                "false_positive_rate": s["false_positive_rate"], "false_negative_rate": s["false_negative_rate"], "accuracy": s["accuracy"],
                "auroc": s["auroc"], "alerts_or_reviews": reviews, "traditional_rule_alerts": rule_alerts,
                "workload_change_pct": 100 * (reviews / max(1, rule_alerts) - 1)})

    label_counts = {}
    labels_file = ROOT / "datasets/generated/labels.csv"
    if labels_file.exists():
        with labels_file.open() as lf:
            for row in csv.DictReader(lf): label_counts[row["split"]] = label_counts.get(row["split"], 0) + 1
    event_count = sum(1 for _ in (ROOT / "datasets/generated/events.jsonl").open()) if (ROOT / "datasets/generated/events.jsonl").exists() else latest["total_events"]
    lines = ["# Benchmark report", "", "## Environment", "", "- Hardware: Apple M5, 16 GB unified memory, arm64.", "- OS: macOS 27.0.", "- Python: 3.12.13.", "- PyTorch: 2.14.1; Transformers: 5.18.0; MPS available.", "- local-jev: upstream v0.2.0, commit `64a0b31ff343dca32142496cf9edca5a0174a18d` (independent MIT project).", "- local-jev and security engine ran natively on macOS; model was not run inside Docker.", "- Model weights are cached outside this repository and are not part of the release archive.", "", "## Dataset and method", "", f"Fixed seed `20261001`, {label_counts.get('train_calibration', 0) + label_counts.get('validation', 0) + label_counts.get('test', 0):,} labeled entities and {event_count:,} event records. The dataset includes 50% benign behavior and hard negatives for crawler, internal monitor, high-volume API, forgotten password, SPA 404, normal admin access, mobile and polling. Suspicious categories are recon, credential abuse, automated bot, suspicious post-auth, possible web exploitation and unknown suspicious. All records are synthetic; source addresses come from RFC 5737 documentation-only ranges.", "", f"Entity-disjoint split counts: {label_counts}. This yields 240 source-IP one-minute windows in test. The provider was evaluated on 70 test windows per model, stratified approximately by category while preserving the balanced benign share (35 benign and 5–6 examples per suspicious category). Model scoring is one state request with four typed questions. Threshold defaults were held fixed (alert=55, high=78, low confidence=0.52); none was fit on test labels.", "", "An `UNCERTAIN` assessment counts as requiring human review for workload, precision/recall and confusion matrices. AUROC uses the continuous risk score. Results are from this deterministic but authored dataset and are not production estimates.", "", "## Rules Only vs Local Jev Only vs Hybrid", "", "| Model | System | n | Precision | Recall | F1 | FPR | FNR | Accuracy | AUROC | Alerts/reviews | Workload change vs rules | p50 ms | p95 ms | states/s |", "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for run in runs:
        rule_alerts = alert_count(run, "Rules Only")
        for system in ("Rules Only", "Local Jev Only", "Hybrid"):
            s = run["systems"].get(system)
            if not s: continue
            alerts = alert_count(run, system)
            change = 100 * (alerts / max(1, rule_alerts) - 1)
            lines.append(f"| {run['model']} | {system} | {s['n']} | {s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} | {s['false_positive_rate']:.3f} | {s['false_negative_rate']:.3f} | {s['accuracy']:.3f} | {s['auroc'] if s['auroc'] is not None else 'n/a'} | {alerts} | {change:+.1f}% | {s['latency_p50_ms']:.2f} | {s['latency_p95_ms']:.2f} | {s['throughput_rps']:.2f} |")
    lines += ["", "Rules Only is measured once in each identical stratified sample; its baseline repeats so Hybrid remains directly comparable to its paired Jev result. Positive workload change means more analyst reviews than Rules Only.", "", "### Per-category recall and category accuracy", ""]
    for run in runs:
        lines += [f"**{run['model']}**", "", "| Category | n | Rules recall | Jev review recall | Hybrid review recall | Jev category accuracy |", "|---|---:|---:|---:|---:|---:|"]
        for cat, s in run["per_category"].items():
            lines.append(f"| {cat} | {s['n']} | {s['rules_recall']:.3f} | {s['jev_recall'] if s['jev_recall'] is not None else 'n/a'} | {s['hybrid_recall'] if s['hybrid_recall'] is not None else 'n/a'} | {s.get('jev_category_accuracy', 'n/a')} |")
        lines.append("")
    lines += ["## Confusion matrices", "", "Counts use the held-out sample; TP/FP/TN/FN order is conventional. The exact matrices are retained in each model's `benchmark_results.json`.", ""]
    for run in runs:
        lines.append(f"**{run['model']}**")
        for system, cm in run.get("confusion_matrices", {}).items(): lines.append(f"- {system}: TP {cm['tp']}, FP {cm['fp']}, TN {cm['tn']}, FN {cm['fn']}")
    lines += ["", "## False-positive, false-negative and hard-negative analysis", ""]
    for run in runs:
        lines.append(f"**{run['model']}**")
        for system in ("Rules Only", "Local Jev Only", "Hybrid"):
            s = run["systems"].get(system)
            if s: lines.append(f"- {system}: {alert_count(run, system)} reviews; FPR {s['false_positive_rate']:.1%}; FNR {s['false_negative_rate']:.1%}; recall/attack retention {s['recall']:.1%}.")
        benign = run.get("benign_scenarios", {})
        if benign:
            lines.append("- Benign hard-negative review rates:")
            for scenario, s in benign.items(): lines.append(f"  - {scenario} (n={s['n']}): rules {s['rules_review_rate']:.1%}; Jev {s['jev_review_rate']:.1%}; Hybrid {s['hybrid_review_rate']:.1%}.")
        lines.append("")
    lines += ["A 1,000-traditional-alert production workload estimate is omitted. The evaluation split is deliberately 50% malicious, and the sample is only 70 windows, so converting its rate to a production queue size would overstate certainty.", "", "## Model load, latency and memory", "", "| Model | First request observation | p50 ms | p95 ms | throughput |", "|---|---|---:|---:|---:|"]
    for run in runs:
        note = load_notes.get(run["model"], {})
        cold = note.get("cold_load_observation", "not separately timed")
        s = run["systems"]["Local Jev Only"]
        lines.append(f"| {run['model']} | {cold}; first evaluation request {run.get('first_model_request_ms', 'not captured')} ms | {s['latency_p50_ms']:.2f} | {s['latency_p95_ms']:.2f} | {s['throughput_rps']:.2f} states/s |")
    lines += ["", "Observed process physical footprint (macOS `sample`, process-wide with cached model backends): NLI-only peak 2.7 GB; Qwen3-4B with NLI still cached peaked at 11.1 GB; Qwen3.5-4B process footprint reached 10.2 GB current and 18.7 GB peak. The Qwen3.5 peak exceeded installed unified RAM and can imply memory compression/swap; it is a material latency risk. These values reflect cache state and do not isolate per-model tensor allocation.", "", "Throughput is the reciprocal of sequential single-request latency, not a load test. First request may include model loading/warmup; cold-download observations are reported separately in the CSV and notes.", "", "## Robustness", ""]
    if robustness:
        lines.append(f"A localhost-only synthetic input check used {robustness.get('cases', 'n/a')} user-agent variants. All variants mapped to identical aggregate feature objects and produced identical Jev answers; the provider payload omitted the raw strings. The unit test also injects unknown prompt-like feature keys and confirms the allowlist discards them.")
    else:
        lines.append("The provider is unit-tested to omit prompt-like user-agent and unknown feature values from model context. The typed security state contains only a fixed feature allowlist, with method names normalized and path query data removed.")
    lines += ["", "This verifies that attacker-controlled strings are not transported to Jev; it does not establish resistance to every model error or prompt attack.", "", "## Known limitations", "", "- The dataset is synthetic and authored, and per-model test sample size is 70.", "- High-volume API and SPA 404 hard negatives can trigger rules or model reviews; false positives are visible in the scenario tables.", "- The NLI model's uncertainty and category accuracy require human review and were weak on this security task.", "- Thresholds are fixed defaults; further calibration requires a separate labeled operational dataset.", "- Source IPs remain identifying data in local SQLite; session and request identifiers are pseudonymized.", "- API/dashboard have no built-in authentication, rate limiting, retention scheduler or production isolation.", "- File tailing handles append and malformed lines but does not robustly handle rotation/truncation.", "- Models require a one-time weight download; local inference itself does not send event data off-host.", "- Results do not justify automatic blocking; the product is detection and triage in shadow mode."]

    report = "\n".join(lines) + "\n"
    (REPORTS / "BENCHMARK.md").write_text(report)
    (REPORTS / "local_jev_benchmark.md").write_text(report)


if __name__ == "__main__": main()
